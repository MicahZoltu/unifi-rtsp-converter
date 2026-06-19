//! Proxy configuration: an INI-style parser for `flvproxy.ini` plus the
//! advertised-server-IP resolution the SDP (step 09) and ONVIF (step 16)
//! layers consume. `local_ip_v4` detects the host's primary non-loopback
//! IPv4 with a zero-crates UDP "connect" trick; `Config::advertised_server_ip`
//! honours an explicit `server_ip` override from the INI and falls back to
//! detection, then loopback. The parser loads the listen/RTSP/ONVIF ports and
//! the WS-Discovery flag, retaining the `PROJECT.md` defaults when the file is
//! absent or any field is missing or malformed.

use std::fs;
use std::io;
use std::net::UdpSocket;
use std::path::Path;

/// Default camera push-listen port per `PROJECT.md` → "Configuration".
const DEFAULT_LISTEN_PORT: u16 = 7550;

/// Default RTSP client port per `PROJECT.md` → "Configuration".
const DEFAULT_RTSP_PORT: u16 = 8554;

/// Default ONVIF device/media SOAP port per `PROJECT.md` → "Configuration".
const DEFAULT_ONVIF_PORT: u16 = 8080;

/// Default WS-Discovery enable flag per `PROJECT.md` → "Configuration".
const DEFAULT_ONVIF_DISCOVERY: bool = true;

/// Public anycast address used only to resolve the default-route source IP.
/// `UdpSocket::connect` performs no I/O — it records the route the kernel
/// would use, letting `local_addr` report that route's source IPv4. Picking a
/// public target guarantees the kernel selects a non-loopback interface when
/// one exists. Zero-crates per the project constraint.
const ROUTE_PROBE_ADDR: &str = "8.8.8.8:80";

/// Loopback IPv4 used as the last-resort advertised address when detection
/// finds no non-loopback interface (e.g. an air-gapped host). Keeps the SDP
/// origin syntactically valid rather than empty.
const LOOPBACK_IPV4: &str = "127.0.0.1";

/// Name of the only INI section this parser applies; other sections ignored.
const SERVER_SECTION: &str = "server";

/// Parsed proxy configuration. The first four fields originate from the
/// `[server]` section of `flvproxy.ini`; missing or malformed entries keep
/// the `PROJECT.md` defaults. `server_ip` is the optional explicit override
/// of the address advertised in SDP origins / ONVIF stream URIs — `None`
/// means "auto-detect via `local_ip_v4`".
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Config {
    pub listen_port: u16,
    pub rtsp_port: u16,
    pub onvif_port: u16,
    pub onvif_discovery: bool,
    pub server_ip: Option<String>,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            listen_port: DEFAULT_LISTEN_PORT,
            rtsp_port: DEFAULT_RTSP_PORT,
            onvif_port: DEFAULT_ONVIF_PORT,
            onvif_discovery: DEFAULT_ONVIF_DISCOVERY,
            server_ip: None,
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

    /// Resolves the IPv4 address the proxy should advertise in SDP origins
    /// and ONVIF stream URIs. An explicit `server_ip` from `flvproxy.ini`
    /// wins (operators use this for multi-interface or NAT setups); otherwise
    /// `local_ip_v4` is tried; if that finds nothing, loopback is used so the
    /// address is always syntactically valid. Called by `console_main` (step
    /// 13) and, later, the service body (step 18).
    pub fn advertised_server_ip(&self) -> String {
        match &self.server_ip {
            Some(ip) => ip.clone(),
            None => local_ip_v4().unwrap_or_else(|| LOOPBACK_IPV4.to_string()),
        }
    }
}

/// Best-effort detection of the host's primary non-loopback IPv4 address by
/// opening a UDP socket and connecting to a public address — `connect` on a
/// UDP socket performs no I/O but resolves the route, letting `local_addr`
/// report the source IP that route would use. Returns `None` on any failure
/// or when the resolved address is loopback, so the caller can fall back to
/// `LOOPBACK_IPV4`. Zero-crates per the project constraint; robust
/// multi-interface selection is out of scope (an operator with multiple
/// interfaces sets `server_ip` in `flvproxy.ini`).
pub fn local_ip_v4() -> Option<String> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect(ROUTE_PROBE_ADDR).ok()?;
    match sock.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(v4) if !v4.is_loopback() => Some(v4.to_string()),
        _ => None,
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
        "server_ip" => cfg.server_ip = Some(val.to_string()),
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
                onvif_discovery: true,
                server_ip: None,
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
                onvif_discovery: false,
                server_ip: None,
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
                onvif_discovery: true,
                server_ip: None,
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
                onvif_discovery: true,
                server_ip: None,
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
                onvif_discovery: true,
                server_ip: None,
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
                onvif_discovery: true,
                server_ip: None,
            }
        );
    }

    #[test]
    fn parse_ini_without_server_header_keeps_all_defaults() {
        let text = "listen_port = 700\nrtsp_port = 8000";
        assert_eq!(parse_ini(text), Config::default());
    }

    #[test]
    fn parse_ini_reads_explicit_server_ip_override() {
        let text = "[server]\nrtsp_port = 8000\nserver_ip = 192.168.1.50";
        assert_eq!(
            parse_ini(text),
            Config {
                listen_port: 7550,
                rtsp_port: 8000,
                onvif_port: 8080,
                onvif_discovery: true,
                server_ip: Some("192.168.1.50".to_string()),
            }
        );
    }

    #[test]
    fn advertised_server_ip_honours_explicit_override_over_detection() {
        let cfg = Config {
            server_ip: Some("10.20.30.40".to_string()),
            ..Config::default()
        };
        assert_eq!(cfg.advertised_server_ip(), "10.20.30.40");
    }

    #[test]
    fn local_ip_v4_returns_non_loopback_or_none() {
        if let Some(addr) = local_ip_v4() {
            let ip: std::net::Ipv4Addr = addr
                .parse()
                .expect("local_ip_v4 must return a parseable IPv4");
            assert!(!ip.is_loopback(), "local_ip_v4 must be non-loopback: {ip}");
        }
        // `None` (no non-loopback interface, e.g. air-gapped CI) is tolerated.
    }
}
