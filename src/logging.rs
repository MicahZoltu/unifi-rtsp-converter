//! Mutex-protected file logger with size-based rotation (one backup kept). Levels: INFO, WARN, ERROR. Lines are written as `YYYY-MM-DD HH:MM:SS.mmm [LEVEL] msg` using a UTC timestamp derived from `SystemTime` via a small epoch-to-civil converter (no `chrono`).
//!
//! Console mode (the default foreground path) opens the logger via `Logger::open_console`, which additionally tees every line to stdout so an operator watching a terminal sees live `camera connected` / `SPS received` / frame-counter lines without tailing the file. The tee shares the logger mutex with the file write, so multi-thread lines stay atomic on stdout too. The Windows service body (`--service`) uses the plain `Logger::open` (file only) — a headless service has no stdout worth writing to.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::calendar::civil_from_days;

/// Default rotation threshold: 10 MiB.
const DEFAULT_MAX_BYTES: u64 = 10 * 1024 * 1024;

/// Nanoseconds per millisecond, used to render the `HH:MM:SS.mmm` field.
const NANOS_PER_MILLI: u32 = 1_000_000;

/// Seconds per day, used to split a Unix epoch second count into a day number (fed to `calendar::civil_from_days`) and an intra-day second offset. The civil-from-days algorithm itself lives in `calendar` so it is shared with `protect_controller`'s ISO 8601 formatter.
const SECS_PER_DAY: i64 = 86_400;

/// Log severity. The proxy emits only these three levels; finer-grained filtering is not needed for a single-stream service.
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

/// File logger that appends one line per call and rotates when the file exceeds `max_bytes`. On rotation the current file is renamed to `<path>.1` (overwriting any prior backup) and a fresh file is opened for continued writes.
///
/// The open file is wrapped in `Mutex<Option<File>>` so rotation can close the live handle before renaming it — this is required on Windows, where an open file cannot be renamed, and is harmless on Unix.
pub struct Logger {
    path: PathBuf,
    max_bytes: u64,
    file: Mutex<Option<File>>,
    /// When `true`, `log` also writes each line to stdout (best-effort), used only by console mode (the default foreground path) so an operator sees live activity in the terminal. The shared mutex makes the file + stdout writes a single atomic critical section, so multi-thread lines do not interleave.
    tee_stdout: bool,
}

impl Logger {
    /// Opens or creates a logger at `path` with the default 10 MiB rotation threshold (file only — no stdout tee). Used by the service body and the unit tests.
    pub fn open(path: &Path) -> std::io::Result<Logger> {
        Self::open_with_max(path, DEFAULT_MAX_BYTES)
    }

    /// Opens or creates a logger at `path` with a caller-supplied rotation threshold. Tests use this with a small value to trigger rotation. No stdout tee.
    pub fn open_with_max(path: &Path, max_bytes: u64) -> std::io::Result<Logger> {
        Self::open_with(path, max_bytes, false)
    }

    /// Opens or creates a logger at `path` with the default rotation threshold and stdout tee enabled — the console-mode entry point (the default foreground path). The file is still written (it is the record the human-test pass criteria reference), but every line is also mirrored to stdout so the operator does not have to tail the file in a second window.
    pub fn open_console(path: &Path) -> std::io::Result<Logger> {
        Self::open_with(path, DEFAULT_MAX_BYTES, true)
    }

    /// Shared constructor: opens the file truncated (so each run starts a self-contained log rather than growing indefinitely across runs) and records the rotation threshold and stdout-tee flag. Within a single run, rotation still renames the live file to `<path>.1` and opens a fresh one once the threshold is exceeded.
    fn open_with(path: &Path, max_bytes: u64, tee_stdout: bool) -> std::io::Result<Logger> {
        let file = OpenOptions::new().create(true).write(true).truncate(true).open(path)?;
        Ok(Logger { path: path.to_path_buf(), max_bytes, file: Mutex::new(Some(file)), tee_stdout })
    }

    /// Returns whether this logger mirrors lines to stdout. Exposed for the console-path unit test; production code branches on it implicitly via `open` vs `open_console`.
    pub fn is_tee_enabled(&self) -> bool {
        self.tee_stdout
    }

    /// Appends one formatted line `YYYY-MM-DD HH:MM:SS.mmm [LEVEL] msg`. Rotation is performed first if the live file size exceeds the threshold. When `tee_stdout` is set the same line is also written to stdout inside the same mutex critical section, so an operator in console mode sees live activity and multi-thread lines stay ordered. I/O and lock-poisoning failures are silently dropped: logging must never crash the proxy.
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
            // Close the live handle before renaming so the move succeeds on Windows as well as Unix.
            *guard = None;
            let _ = std::fs::rename(&self.path, backup_path(&self.path));
            match OpenOptions::new().create(true).write(true).truncate(true).open(&self.path) {
                Ok(f) => *guard = Some(f),
                Err(_) => return,
            }
        }
        if let Some(f) = &mut *guard {
            let _ = writeln!(f, "{line}");
        }
        if self.tee_stdout {
            // Best-effort stdout mirror; stdout's own lock keeps the line atomic. Done inside the logger mutex so the file→stdout order is deterministic across threads.
            let _ = writeln!(std::io::stdout(), "{line}");
        }
    }
}

/// Builds the rotated-backup path `<path>.1` by appending `.1` to the file name component, preserving any directory prefix.
fn backup_path(path: &Path) -> PathBuf {
    let mut p = path.to_path_buf();
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return p;
    };
    p.set_file_name(format!("{name}.1"));
    p
}

/// Formats a single log line, including the UTC timestamp. The date triple comes from the shared `calendar::civil_from_days`; the sub-second milliseconds come from the `SystemTime` read here (the civil converter deals only in whole seconds).
fn format_line(level: Level, msg: &str) -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = now.as_secs() as i64;
    let nanos = now.subsec_nanos();
    let days = secs.div_euclid(SECS_PER_DAY);
    let day_secs = secs.rem_euclid(SECS_PER_DAY);
    let (year, month, day) = civil_from_days(days);
    let hours = day_secs / 3600;
    let minutes = (day_secs % 3600) / 60;
    let seconds = day_secs % 60;
    let millis = nanos / NANOS_PER_MILLI;
    format!("{year:04}-{month:02}-{day:02} {hours:02}:{minutes:02}:{seconds:02}.{millis:03} [{label}] {msg}", label = level.label(),)
}

/// Returns the current UTC civil time as `(year, month, day, hour, minute, second)`. Re-exported from `calendar` so `onvif_server::GetSystemDateAndTime` and the log-line formatter share one `SystemTime`-to-civil reduction and one civil-from-days implementation.
pub use crate::calendar::utc_now;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_path_appends_dot_one_to_file_name() {
        let p = Path::new("/tmp/flvproxy.log");
        assert_eq!(backup_path(p), PathBuf::from("/tmp/flvproxy.log.1"));
    }

    #[test]
    fn open_is_file_only_and_open_console_enables_tee() {
        let plain = std::env::temp_dir().join(format!("flvproxy-logger-plain-{}.log", std::process::id()));
        let console = std::env::temp_dir().join(format!("flvproxy-logger-console-{}.log", std::process::id()));
        let _ = std::fs::remove_file(&plain);
        let _ = std::fs::remove_file(&console);

        let l_plain = Logger::open(&plain).expect("open plain");
        let l_console = Logger::open_console(&console).expect("open console");
        assert!(!l_plain.is_tee_enabled(), "open() must not tee stdout");
        assert!(l_console.is_tee_enabled(), "open_console() must tee stdout");

        // Both must still write to their files.
        l_plain.log(Level::Info, "plain line");
        l_console.log(Level::Info, "console line");
        let plain_text = std::fs::read_to_string(&plain).expect("read plain");
        let console_text = std::fs::read_to_string(&console).expect("read console");
        assert!(plain_text.contains("plain line"));
        assert!(console_text.contains("console line"));

        let _ = std::fs::remove_file(&plain);
        let _ = std::fs::remove_file(&console);
    }
}
