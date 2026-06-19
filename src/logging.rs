//! Mutex-protected file logger with size-based rotation (one backup kept).
//! Levels: INFO, WARN, ERROR. Lines are written as
//! `YYYY-MM-DD HH:MM:SS.mmm [LEVEL] msg` using a UTC timestamp derived from
//! `SystemTime` via a small epoch-to-civil converter (no `chrono`).

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Default rotation threshold: 10 MiB, per `plan/01-logging-and-config.md`.
const DEFAULT_MAX_BYTES: u64 = 10 * 1024 * 1024;

/// Nanoseconds per millisecond, used to render the `HH:MM:SS.mmm` field.
const NANOS_PER_MILLI: u32 = 1_000_000;

/// Seconds per day, used by the epoch-to-civil-date converter.
const SECS_PER_DAY: i64 = 86_400;

/// Log severity. The proxy emits only these three levels; finer-grained
/// filtering is not needed for a single-stream service.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Level {
    Info,
    Warn,
    Error,
}

impl Level {
    /// Uppercase label printed inside the `[...]` prefix of each line.
    fn label(self) -> &'static str {
        match self {
            Level::Info => "INFO",
            Level::Warn => "WARN",
            Level::Error => "ERROR",
        }
    }
}

/// File logger that appends one line per call and rotates when the file
/// exceeds `max_bytes`. On rotation the current file is renamed to
/// `<path>.1` (overwriting any prior backup) and a fresh file is opened for
/// continued writes.
///
/// The open file is wrapped in `Mutex<Option<File>>` so rotation can close
/// the live handle before renaming it — this is required on Windows, where
/// an open file cannot be renamed, and is harmless on Unix.
pub struct Logger {
    path: PathBuf,
    max_bytes: u64,
    file: Mutex<Option<File>>,
}

impl Logger {
    /// Opens or creates a logger at `path` with the default 10 MiB rotation
    /// threshold.
    pub fn open(path: &Path) -> std::io::Result<Logger> {
        Self::open_with_max(path, DEFAULT_MAX_BYTES)
    }

    /// Opens or creates a logger at `path` with a caller-supplied rotation
    /// threshold. Tests use this with a small value to trigger rotation.
    pub fn open_with_max(path: &Path, max_bytes: u64) -> std::io::Result<Logger> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Logger {
            path: path.to_path_buf(),
            max_bytes,
            file: Mutex::new(Some(file)),
        })
    }

    /// Appends one formatted line `YYYY-MM-DD HH:MM:SS.mmm [LEVEL] msg`.
    /// Rotation is performed first if the live file size exceeds the
    /// threshold. I/O and lock-poisoning failures are silently dropped:
    /// logging must never crash the proxy.
    pub fn log(&self, level: Level, msg: &str) {
        let line = format_line(level, msg);
        let Ok(mut guard) = self.file.lock() else {
            return;
        };
        let needs_rotate = match &*guard {
            Some(f) => match f.metadata() {
                Ok(m) => m.len() > self.max_bytes,
                Err(_) => false,
            },
            None => false,
        };
        if needs_rotate {
            // Close the live handle before renaming so the move succeeds on
            // Windows as well as Unix.
            *guard = None;
            let _ = std::fs::rename(&self.path, backup_path(&self.path));
            match OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&self.path)
            {
                Ok(f) => *guard = Some(f),
                Err(_) => return,
            }
        }
        if let Some(f) = &mut *guard {
            let _ = writeln!(f, "{line}");
        }
    }
}

/// Builds the rotated-backup path `<path>.1` by appending `.1` to the file
/// name component, preserving any directory prefix.
fn backup_path(path: &Path) -> PathBuf {
    let mut p = path.to_path_buf();
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return p;
    };
    p.set_file_name(format!("{name}.1"));
    p
}

/// Formats a single log line, including the UTC timestamp derived from
/// `SystemTime` via the epoch-to-civil converter.
fn format_line(level: Level, msg: &str) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs() as i64;
    let nanos = now.subsec_nanos();
    let days = secs.div_euclid(SECS_PER_DAY);
    let day_secs = secs.rem_euclid(SECS_PER_DAY);
    let (year, month, day) = days_to_ymd(days);
    let hours = day_secs / 3600;
    let minutes = (day_secs % 3600) / 60;
    let seconds = day_secs % 60;
    let millis = nanos / NANOS_PER_MILLI;
    format!(
        "{year:04}-{month:02}-{day:02} {hours:02}:{minutes:02}:{seconds:02}.{millis:03} [{label}] {msg}",
        label = level.label(),
    )
}

/// Converts days since the Unix epoch (1970-01-01) to a `(year, month, day)`
/// civil triple. Implements the Howard Hinnant `civil_from_days` algorithm,
/// valid for any proleptic Gregorian day number.
fn days_to_ymd(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 {
        z / 146_097
    } else {
        (z - 146_097 + 1) / 146_097
    };
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    (year, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn days_to_ymd_epoch_origin_is_1970_01_01() {
        assert_eq!(days_to_ymd(0), (1970, 1, 1));
    }

    #[test]
    fn days_to_ymd_day_20089_is_2025_01_01() {
        // 2025-01-01 00:00:00 UTC = Unix timestamp 1_735_689_600 = day 20_089.
        assert_eq!(days_to_ymd(20_089), (2025, 1, 1));
    }

    #[test]
    fn days_to_ymd_day_20088_is_2024_12_31() {
        assert_eq!(days_to_ymd(20_088), (2024, 12, 31));
    }

    #[test]
    fn backup_path_appends_dot_one_to_file_name() {
        let p = Path::new("/tmp/flvproxy.log");
        assert_eq!(backup_path(p), PathBuf::from("/tmp/flvproxy.log.1"));
    }
}
