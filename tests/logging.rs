//! Integration tests for `flvproxy::logging`. Writes against unique paths in the OS temp directory, then cleans up so repeated runs stay isolated.

use flvproxy::logging::{Level, Logger};
use std::fs;
use std::path::{Path, PathBuf};

/// Builds a unique temp path for the named test, namespaced by the process id.
fn test_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("flvproxy-logging-{name}-{}.log", std::process::id()))
}

/// Builds the rotated-backup path the same way the module does.
fn backup_path(path: &Path) -> PathBuf {
    let mut p = path.to_path_buf();
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return p;
    };
    p.set_file_name(format!("{name}.1"));
    p
}

/// Removes the active log and any rotated backup so a test starts clean.
fn clean(path: &Path) {
    let _ = fs::remove_file(path);
    let _ = fs::remove_file(backup_path(path));
}

/// Validates `YYYY-MM-DD HH:MM:SS.mmm [LEVEL] ` prefix structure without a regex crate, per the no-external-dependencies rule.
fn assert_prefix(line: &str, level: &str) {
    let mut parts = line.split(' ');
    let date = parts.next().expect("date token");
    let time = parts.next().expect("time token");
    let lvl = parts.next().expect("level token");

    let d = date.as_bytes();
    assert_eq!(d.len(), 10, "date must be YYYY-MM-DD");
    assert_eq!(d[4], b'-');
    assert_eq!(d[7], b'-');
    assert!(d[..4].iter().all(|c| c.is_ascii_digit()));
    assert!(d[5..7].iter().all(|c| c.is_ascii_digit()));
    assert!(d[8..10].iter().all(|c| c.is_ascii_digit()));

    let t = time.as_bytes();
    assert_eq!(t.len(), 12, "time must be HH:MM:SS.mmm");
    assert_eq!(t[2], b':');
    assert_eq!(t[5], b':');
    assert_eq!(t[8], b'.');
    assert!(t[..2].iter().all(|c| c.is_ascii_digit()));
    assert!(t[3..5].iter().all(|c| c.is_ascii_digit()));
    assert!(t[6..8].iter().all(|c| c.is_ascii_digit()));
    assert!(t[9..12].iter().all(|c| c.is_ascii_digit()));

    assert_eq!(lvl, &format!("[{level}]"));
}

#[test]
fn log_writes_lines_in_order() {
    let path = test_path("order");
    clean(&path);
    let logger = Logger::open(&path).expect("open logger");
    for i in 0..50 {
        logger.log(Level::Info, &format!("line {i}"));
    }
    let content = fs::read_to_string(&path).expect("read log");
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(lines.len(), 50, "expected 50 lines");
    for (i, line) in lines.iter().enumerate() {
        assert!(line.ends_with(&format!("line {i}")), "line {i} mismatch: {line}");
    }
    clean(&path);
}

#[test]
fn log_line_prefix_matches_timestamp_and_level_format() {
    let path = test_path("prefix");
    clean(&path);
    let logger = Logger::open(&path).expect("open logger");
    logger.log(Level::Info, "alpha");
    logger.log(Level::Warn, "beta");
    logger.log(Level::Error, "gamma");
    let content = fs::read_to_string(&path).expect("read log");
    let levels = ["INFO", "WARN", "ERROR"];
    for (line, level) in content.lines().zip(levels.iter()) {
        assert_prefix(line, level);
    }
    clean(&path);
}

#[test]
fn rotation_renames_to_backup_and_reopens_fresh() {
    let path = test_path("rotation");
    clean(&path);
    // Small threshold forces rotation after a few short lines.
    let logger = Logger::open_with_max(&path, 200).expect("open logger");
    let msg = "rotation test line with a fixed length message payload";
    // Stop the moment the backup appears so rotation happens exactly once; the active file then holds only the line that triggered the rotation.
    for _ in 0..100 {
        logger.log(Level::Info, msg);
        if fs::metadata(backup_path(&path)).is_ok() {
            break;
        }
    }
    let backup = backup_path(&path);
    assert!(fs::metadata(&backup).is_ok(), "rotated backup must exist");
    let backup_len = fs::metadata(&backup).map(|m| m.len()).expect("backup metadata");
    let active_len = fs::metadata(&path).map(|m| m.len()).expect("active metadata");
    assert!(backup_len > 200, "backup must exceed threshold, got {backup_len}");
    assert!(active_len < backup_len, "active must be smaller than backup: active={active_len} backup={backup_len}");
    clean(&path);
}
