//! Integration tests for `flvproxy::config`. Writes INI text to unique temp paths and checks parsing behavior.

use flvproxy::config::Config;
use std::fs;
use std::path::{Path, PathBuf};

/// Builds a unique temp path for the named test, namespaced by the process id.
fn test_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("flvproxy-config-{name}-{}.ini", std::process::id()))
}

/// Removes any prior file so a test starts clean.
fn clean(path: &Path) {
    let _ = fs::remove_file(path);
}

/// Writes `text` to `path`, panicking only on failure to set up the test.
fn write(path: &Path, text: &str) {
    fs::write(path, text).expect("write config fixture");
}

#[test]
fn parses_project_md_example_ini_with_inline_comments() {
    let path = test_path("projexample");
    clean(&path);
    write(
        &path,
        "[server]\n\
         listen_port = 7550          # Port the camera connects to\n\
         rtsp_port = 8554            # Port for RTSP clients\n\
         onvif_port = 8080           # Port for ONVIF device/media service\n\
         onvif_discovery = true      # Enable WS-Discovery",
    );
    let cfg = Config::from_file(&path).expect("parse");
    assert_eq!(cfg.listen_port, 7550);
    assert_eq!(cfg.rtsp_port, 8554);
    assert_eq!(cfg.onvif_port, Some(8080), "explicit onvif_port = 8080 in the INI must parse as Some(8080)");
    assert!(cfg.onvif_discovery);
    clean(&path);
}

#[test]
fn parses_overrides_with_blank_lines_and_unknown_key() {
    let path = test_path("overrides");
    clean(&path);
    write(
        &path,
        "# header comment\n\
         \n\
         [server]\n\
         listen_port = 700 # listen here\n\
         rtsp_port = 8000\n\
         unknown_key = ignored\n\
         onvif_port = 9000 # onvif here\n\
         onvif_discovery = false # disabled",
    );
    let cfg = Config::from_file(&path).expect("parse");
    assert_eq!(cfg, Config { listen_port: 700, rtsp_port: 8000, onvif_port: Some(9000), onvif_discovery: false, ..Config::default() });
    clean(&path);
}

#[test]
fn missing_server_header_keeps_defaults() {
    let path = test_path("noheader");
    clean(&path);
    write(&path, "listen_port = 700\nrtsp_port = 8000");
    let cfg = Config::from_file(&path).expect("parse");
    // Pairs outside the [server] section are not applied → all defaults.
    assert_eq!(cfg, Config::default());
    clean(&path);
}

#[test]
fn other_section_is_ignored() {
    let path = test_path("othersection");
    clean(&path);
    write(&path, "[other]\nlisten_port = 700\n[server]\nrtsp_port = 8000");
    let cfg = Config::from_file(&path).expect("parse");
    assert_eq!(cfg, Config { listen_port: 7550, rtsp_port: 8000, onvif_port: None, onvif_discovery: true, ..Config::default() });
    clean(&path);
}

#[test]
fn malformed_lines_keep_defaults_without_panicking() {
    let path = test_path("malformed");
    clean(&path);
    write(&path, "[server]\nthis is not a pair\nlisten_port = bad_port\nrtsp_port = 8000");
    let cfg = Config::from_file(&path).expect("parse");
    assert_eq!(cfg, Config { listen_port: 7550, rtsp_port: 8000, onvif_port: None, onvif_discovery: true, ..Config::default() });
    clean(&path);
}

#[test]
fn load_or_default_on_missing_path_returns_default() {
    let path = test_path("missing");
    clean(&path);
    let cfg = Config::load_or_default(&path);
    assert_eq!(cfg, Config::default());
    // Confirm no fixture was created by the call.
    assert!(!path.exists());
}

#[test]
fn bool_parsing_is_case_insensitive_true_and_false_only() {
    let path = test_path("bool");
    clean(&path);
    write(&path, "[server]\nonvif_discovery = True");
    assert!(Config::from_file(&path).expect("parse").onvif_discovery);
    clean(&path);
    write(&path, "[server]\nonvif_discovery = FALSE");
    assert!(!Config::from_file(&path).expect("parse").onvif_discovery);
    clean(&path);
    // `1`/`0` are rejected → the documented default (`true`) is retained.
    write(&path, "[server]\nonvif_discovery = 1");
    assert!(Config::from_file(&path).expect("parse").onvif_discovery);
    clean(&path);
}
