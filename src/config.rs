//! INI-style configuration parser for `flvproxy.ini`. Loads the listen/RTSP/
//! ONVIF ports and the WS-Discovery flag, falling back to the `PROJECT.md`
//! defaults when the file is absent or any field is missing or malformed.

use std::fs;
use std::io;
use std::path::Path;

/// Default camera push-listen port per `PROJECT.md` → "Configuration".
const DEFAULT_LISTEN_PORT: u16 = 7550;

/// Default RTSP client port per `PROJECT.md` → "Configuration".
const DEFAULT_RTSP_PORT: u16 = 8554;

/// Default ONVIF device/media SOAP port per `PROJECT.md` → "Configuration".
const DEFAULT_ONVIF_PORT: u16 = 8080;

/// Default WS-Discovery enable flag per `PROJECT.md` → "Configuration".
const DEFAULT_ONVIF_DISCOVERY: bool = true;

/// Name of the only INI section this parser applies; other sections ignored.
const SERVER_SECTION: &str = "server";

/// Parsed proxy configuration. All four fields originate from the `[server]`
/// section of `flvproxy.ini`; missing or malformed entries keep the
/// `PROJECT.md` defaults.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Config {
    pub listen_port: u16,
    pub rtsp_port: u16,
    pub onvif_port: u16,
    pub onvif_discovery: bool,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            listen_port: DEFAULT_LISTEN_PORT,
            rtsp_port: DEFAULT_RTSP_PORT,
            onvif_port: DEFAULT_ONVIF_PORT,
            onvif_discovery: DEFAULT_ONVIF_DISCOVERY,
        }
    }
}

impl Config {
    /// Parses `flvproxy.ini` from `path`. Defaults are retained for any
    /// missing or malformed entry, so a partial file never panics.
    pub fn from_file(path: &Path) -> io::Result<Config> {
        let text = fs::read_to_string(path)?;
        Ok(parse_ini(&text))
    }

    /// Returns the parsed config if the file exists and is readable,
    /// otherwise `Config::default()`. Used at startup so a missing file is
    /// not fatal.
    pub fn load_or_default(path: &Path) -> Config {
        Self::from_file(path).unwrap_or_default()
    }
}

/// Parses an INI-style string into a `Config`, applying only the `[server]`
/// section and keeping defaults for everything else.
fn parse_ini(text: &str) -> Config {
    let mut cfg = Config::default();
    let mut in_server = false;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            in_server = name.trim() == SERVER_SECTION;
            continue;
        }
        if !in_server {
            continue;
        }
        let (key, val) = match line_before_comment(line).split_once('=') {
            Some((k, v)) => (k.trim(), v.trim()),
            None => continue, // malformed: no `=` separator
        };
        if key.is_empty() || val.is_empty() {
            continue; // malformed: empty key or value
        }
        apply_pair(&mut cfg, key, val);
    }
    cfg
}

/// Strips an inline `#` comment from a line, returning the bound portion.
fn line_before_comment(line: &str) -> &str {
    match line.find('#') {
        Some(idx) => &line[..idx],
        None => line,
    }
}

/// Applies one `key=value` pair to `cfg`, ignoring unknown keys and malformed
/// values so a bad line never panics.
fn apply_pair(cfg: &mut Config, key: &str, val: &str) {
    match key {
        "listen_port" => {
            if let Ok(v) = val.parse::<u16>() {
                cfg.listen_port = v;
            }
        }
        "rtsp_port" => {
            if let Ok(v) = val.parse::<u16>() {
                cfg.rtsp_port = v;
            }
        }
        "onvif_port" => {
            if let Ok(v) = val.parse::<u16>() {
                cfg.onvif_port = v;
            }
        }
        "onvif_discovery" => {
            if let Ok(v) = parse_bool(val) {
                cfg.onvif_discovery = v;
            }
        }
        _ => {} // unknown key: ignored per spec
    }
}

/// Parses a boolean value case-insensitively. Only `true` and `false` are
/// accepted; `1`/`0`/`yes`/`no` are intentionally rejected so the config
/// stays a strict bool field.
fn parse_bool(val: &str) -> Result<bool, ()> {
    match val.to_ascii_lowercase() {
        s if s == "true" => Ok(true),
        s if s == "false" => Ok(false),
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_matches_project_md_values() {
        let d = Config::default();
        assert_eq!(
            d,
            Config {
                listen_port: 7550,
                rtsp_port: 8554,
                onvif_port: 8080,
                onvif_discovery: true
            }
        );
    }

    #[test]
    fn parse_bool_accepts_only_true_false_case_insensitively() {
        assert_eq!(parse_bool("true"), Ok(true));
        assert_eq!(parse_bool("TRUE"), Ok(true));
        assert_eq!(parse_bool("False"), Ok(false));
        assert_eq!(parse_bool("FALSE"), Ok(false));
        assert_eq!(parse_bool("1"), Err(()));
        assert_eq!(parse_bool("yes"), Err(()));
        assert_eq!(parse_bool(""), Err(()));
    }

    #[test]
    fn parse_ini_reads_all_four_fields() {
        let text = "[server]\nlisten_port = 700\nrtsp_port = 8000\nonvif_port = 9000\nonvif_discovery = false";
        assert_eq!(
            parse_ini(text),
            Config {
                listen_port: 700,
                rtsp_port: 8000,
                onvif_port: 9000,
                onvif_discovery: false
            }
        );
    }

    #[test]
    fn parse_ini_strips_inline_comments_and_keeps_values() {
        let text = "[server]\nlisten_port = 700 # camera port\nrtsp_port = 8000 # rtsp port";
        assert_eq!(
            parse_ini(text),
            Config {
                listen_port: 700,
                rtsp_port: 8000,
                onvif_port: 8080,
                onvif_discovery: true
            }
        );
    }

    #[test]
    fn parse_ini_ignores_non_server_sections() {
        let text = "[other]\nlisten_port = 700\n[server]\nrtsp_port = 8000";
        assert_eq!(
            parse_ini(text),
            Config {
                listen_port: 7550,
                rtsp_port: 8000,
                onvif_port: 8080,
                onvif_discovery: true
            }
        );
    }

    #[test]
    fn parse_ini_skips_malformed_lines_without_panic() {
        let text = "[server]\nthis is not a pair\nlisten_port = not_a_number\nrtsp_port = 8000";
        assert_eq!(
            parse_ini(text),
            Config {
                listen_port: 7550,
                rtsp_port: 8000,
                onvif_port: 8080,
                onvif_discovery: true
            }
        );
    }

    #[test]
    fn parse_ini_ignores_unknown_keys() {
        let text = "[server]\nmystery_key = 1234\nrtsp_port = 8000";
        assert_eq!(
            parse_ini(text),
            Config {
                listen_port: 7550,
                rtsp_port: 8000,
                onvif_port: 8080,
                onvif_discovery: true
            }
        );
    }

    #[test]
    fn parse_ini_without_server_header_keeps_all_defaults() {
        let text = "listen_port = 700\nrtsp_port = 8000";
        assert_eq!(parse_ini(text), Config::default());
    }
}
