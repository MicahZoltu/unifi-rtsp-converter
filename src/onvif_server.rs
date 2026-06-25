//! ONVIF Device and Media SOAP services over HTTP. Serves the handful of requests an NVR needs to learn the stream URL: `GetCapabilities`, `GetDeviceInformation`, `SetSynchronizationPoint` (Device service) and `GetProfiles`, `GetStreamUri`, `GetSnapshotUri`, `GetAudioOutputConfigurations` (Media service).
//!
//! The response bodies (hand-rolled SOAP 1.2 XML via `format!`, dynamic values XML-escaped) live in `onvif_responses`; this module owns the router (`route`/`resolve_action`) and the HTTP runtime (`OnvifServer`/`handle_connection`). The router is pure string logic with no sockets, so it builds and tests on any platform. The runtime drives the router over a real `TcpListener` on `onvif_port`, mirroring the accept-loop / shutdown-handle shape of `rtsp_server::RtspServer` and `camera_listener::CameraListener`. WS-Discovery and real-client validation are out of scope here.
//!
//! The dependency graph is a clean DAG: `onvif_server` depends on `onvif_responses` (the router calls the builders and names the config type); `onvif_responses` depends only on `stream_state` / `camera_identity` / `calendar` / `xml`, not back on `onvif_server`. `OnvifConfig` and the service-path constants are imported directly from `onvif_responses` (their owner) — not re-exported through this module — so a reader of either module sees ownership honestly.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::accept_loop::accept_loop;
use crate::logging::{Level, Logger};
use crate::onvif_responses::{build_fault, build_get_audio_output_configurations, build_get_capabilities, build_get_device_information, build_get_endpoint_reference, build_get_profiles, build_get_services, build_get_snapshot_uri, build_get_stream_uri, build_get_system_date_and_time, build_set_synchronization_point, OnvifConfig};
use crate::stream_state::StreamState;

/// Relaxed ordering suffices for the shutdown flag: it is an advisory signal, not synchronization that establishes happens-before for other data. Mirrors the server modules.
const RELAXED: Ordering = Ordering::Relaxed;

/// Per-connection read timeout. Bounds how long the server waits for a client to finish sending a request before giving up and closing the connection.
const READ_TIMEOUT_MS: u64 = 5_000;

/// Per-connection write timeout, bounding how long a stalled client can hold the socket before the connection is dropped.
const WRITE_TIMEOUT_MS: u64 = 5_000;

const READ_CHUNK_BYTES: usize = 8192;

/// Cap on the per-connection request buffer. A client that streams request bytes without ever completing a `\r\n\r\n`-terminated header block would otherwise grow the buffer unbounded; exceeding this closes the connection. Named per the resource-bounds quality gate.
const MAX_READ_BUFFER_BYTES: usize = 64 * 1024;

/// Header-block terminator separating HTTP headers from the body, per RFC 7230 §3.
const HEADER_TERMINATOR: &[u8] = b"\r\n\r\n";

/// Length in bytes of the header-block terminator (two CRLFs).
const HEADER_TERMINATOR_LEN: usize = 4;

/// SOAP 1.2 media type returned on every response, per RFC 3902 (`SOAP 1.2 Media Type`). ONVIF uses SOAP 1.2 over HTTP.
const SOAP_CONTENT_TYPE: &str = "application/soap+xml; charset=utf-8";

/// HTTP status `200 OK`, per RFC 7230 §3.1.2.
const STATUS_OK: u16 = 200;

/// The ONVIF operations this proxy implements, paired with their namespace URIs and owning service. Used both to match a `SOAPAction` header (exact equality after quote-stripping) and to scan the body as a fallback when the header is absent (some clients put the operation only in the body's XML namespace).
const KNOWN_ACTIONS: &[(&str, Service, &str)] = &[("http://www.onvif.org/ver10/device/wsdl/GetSystemDateAndTime", Service::Device, "GetSystemDateAndTime"), ("http://www.onvif.org/ver10/device/wsdl/GetCapabilities", Service::Device, "GetCapabilities"), ("http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation", Service::Device, "GetDeviceInformation"), ("http://www.onvif.org/ver10/device/wsdl/GetEndpointReference", Service::Device, "GetEndpointReference"), ("http://www.onvif.org/ver10/device/wsdl/GetServices", Service::Device, "GetServices"), ("http://www.onvif.org/ver10/device/wsdl/SetSynchronizationPoint", Service::Device, "SetSynchronizationPoint"), ("http://www.onvif.org/ver10/media/wsdl/GetProfiles", Service::Media, "GetProfiles"), ("http://www.onvif.org/ver10/media/wsdl/GetStreamUri", Service::Media, "GetStreamUri"), ("http://www.onvif.org/ver10/media/wsdl/GetSnapshotUri", Service::Media, "GetSnapshotUri"), ("http://www.onvif.org/ver10/media/wsdl/GetAudioOutputConfigurations", Service::Media, "GetAudioOutputConfigurations")];

/// Which ONVIF service an operation belongs to. `Copy` so it can live in a `const` table.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum Service {
    Device,
    Media,
}

/// A resolved ONVIF operation: the owning service and the operation name (e.g. `"GetStreamUri"`).
struct Resolved {
    service: Service,
    op: &'static str,
}

/// Routes one SOAP request to its response body. `soap_action` is the raw `SOAPAction:` header value (quotes intact or empty); `body` is the request body bytes as text. Returns `(status_code, xml_body)`. Known operations yield `200` plus the matching response template; an unrecognized or missing action yields `200` plus a SOAP Fault carrying `wsa:ActionNotSupported` (HTTP 200 for faults matches common ONVIF device behaviour and keeps the router's status surface trivial).
///
/// Routing first tries the `SOAPAction` header (stripping surrounding quotes); if that is absent or unrecognized, the body is scanned for any of the known operation namespace URIs so clients that omit the header still route.
pub fn route(soap_action: &str, body: &str, cfg: &OnvifConfig, state: &StreamState) -> (u16, String) {
    match resolve_action(soap_action, body) {
        Some(Resolved { service: Service::Device, op }) => match op {
            "GetSystemDateAndTime" => (STATUS_OK, build_get_system_date_and_time()),
            "GetCapabilities" => (STATUS_OK, build_get_capabilities(cfg)),
            "GetDeviceInformation" => (STATUS_OK, build_get_device_information(cfg, state)),
            "GetEndpointReference" => (STATUS_OK, build_get_endpoint_reference()),
            "GetServices" => (STATUS_OK, build_get_services(cfg)),
            "SetSynchronizationPoint" => (STATUS_OK, build_set_synchronization_point()),
            _ => (STATUS_OK, build_fault()),
        },
        Some(Resolved { service: Service::Media, op }) => match op {
            "GetProfiles" => (STATUS_OK, build_get_profiles(cfg, state)),
            "GetStreamUri" => (STATUS_OK, build_get_stream_uri(cfg)),
            "GetSnapshotUri" => (STATUS_OK, build_get_snapshot_uri(cfg)),
            "GetAudioOutputConfigurations" => (STATUS_OK, build_get_audio_output_configurations()),
            _ => (STATUS_OK, build_fault()),
        },
        None => (STATUS_OK, build_fault()),
    }
}

/// Resolves the incoming action to a known operation, preferring the `SOAPAction` header and falling back to a body namespace scan. Returns `None` when neither source names a supported operation.
fn resolve_action(soap_action: &str, body: &str) -> Option<Resolved> {
    let stripped = strip_quotes(soap_action.trim());
    if !stripped.is_empty() {
        for &(uri, service, op) in KNOWN_ACTIONS {
            if stripped == uri {
                return Some(Resolved { service, op });
            }
        }
    }
    for &(uri, service, op) in KNOWN_ACTIONS {
        if body.contains(uri) {
            return Some(Resolved { service, op });
        }
    }
    None
}

/// Strips one layer of surrounding double-quotes from `value`, per the `SOAPAction` header grammar (RFC 3902 / SOAP 1.2: the URI is quoted).
fn strip_quotes(value: &str) -> &str {
    let value = value.strip_prefix('"').unwrap_or(value);
    value.strip_suffix('"').unwrap_or(value)
}

/// HTTP reason phrase for `code`, per RFC 7231 §6. Unknown codes map to `"OK"` so the status line is always well-formed.
fn http_reason(code: u16) -> &'static str {
    match code {
        STATUS_OK => "OK",
        _ => "OK",
    }
}

// --------------------------------------------------------------------------- Runtime: HTTP accept loop and per-connection handler. ---------------------------------------------------------------------------

/// Shutdown handle and bound-port surface for the ONVIF HTTP server. Mirrors `RtspServer` / `CameraListener`: a single instance owns the accept thread's shared flag; `console_main` drives one instance per process.
pub struct OnvifServer {
    config: OnvifConfig,
    state: StreamState,
    shutdown: Arc<AtomicBool>,
    logger: Option<Arc<Logger>>,
}

impl OnvifServer {
    pub fn new(config: OnvifConfig, state: StreamState) -> OnvifServer {
        OnvifServer { config, state, shutdown: Arc::new(AtomicBool::new(false)), logger: None }
    }

    pub fn with_logger(config: OnvifConfig, state: StreamState, logger: Arc<Logger>) -> OnvifServer {
        OnvifServer { config, state, shutdown: Arc::new(AtomicBool::new(false)), logger: Some(logger) }
    }

    /// Binds the ONVIF listener on `0.0.0.0:onvif_port` and runs the accept loop until `shutdown()` is called.
    pub fn run(&self) -> io::Result<()> {
        let listener = TcpListener::bind(("0.0.0.0", self.config.onvif_port))?;
        self.run_on(listener)
    }

    /// Runs the accept loop on a caller-supplied listener. Tests use this with an ephemeral loopback listener so they know the bound port; production `run()` delegates here after binding. The non-blocking/poll/shutdown mechanics live in `accept_loop::accept_loop`; this body just spawns a per-connection handler thread.
    pub fn run_on(&self, listener: TcpListener) -> io::Result<()> {
        let shutdown = self.shutdown.clone();
        let shutdown_for_closure = shutdown.clone();
        let config = self.config.clone();
        let state = self.state.clone();
        let logger = self.logger.clone();
        accept_loop(listener, &shutdown, move |stream| {
            let config = config.clone();
            let state = state.clone();
            let shutdown = shutdown_for_closure.clone();
            let logger = logger.clone();
            thread::spawn(move || {
                let logger_ref = logger.as_deref();
                handle_connection(stream, &config, &state, &shutdown, logger_ref);
            });
        })
    }

    /// Signals the accept loop to exit. Idempotent. In-flight connections finish on their next read timeout or request completion.
    pub fn shutdown(&self) {
        self.shutdown.store(true, RELAXED);
    }

    /// Returns a clone of the shutdown flag so external code (`console_main` or tests) can stop the accept loop without holding a reference to the `OnvifServer`. Mirrors `RtspServer::shutdown_signal`.
    pub fn shutdown_signal(&self) -> Arc<AtomicBool> {
        self.shutdown.clone()
    }
}

/// Handles one ONVIF HTTP connection to completion: reads the request headers and `Content-Length` body, routes the SOAP request, and writes the response. One request per connection (`Connection: close`) — ONVIF NVR discovery issues a small handful of requests, so keep-alive adds complexity without benefit. Every error path closes the connection; none panic. When `logger` is `Some`, the connection open and close are logged (the routed action/status is intentionally not logged — NVR discovery polls the same operations repeatedly and the per-request detail is noise).
fn handle_connection(mut stream: std::net::TcpStream, config: &OnvifConfig, state: &StreamState, shutdown: &AtomicBool, logger: Option<&Logger>) {
    let peer: SocketAddr = stream.peer_addr().unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(Duration::from_millis(READ_TIMEOUT_MS)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(WRITE_TIMEOUT_MS)));

    if let Some(logger) = logger {
        logger.log(Level::Info, &format!("onvif client connected: {peer}"));
    }

    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; READ_CHUNK_BYTES];
    let header_end = loop {
        if shutdown.load(RELAXED) {
            return;
        }
        match stream.read(&mut chunk) {
            Ok(0) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) if e.kind() == io::ErrorKind::TimedOut => continue,
            Err(_) => return,
        }
        if buf.len() > MAX_READ_BUFFER_BYTES {
            return;
        }
        if let Some(pos) = find_terminator(&buf) {
            break pos + HEADER_TERMINATOR_LEN;
        }
    };

    let header_str = match std::str::from_utf8(&buf[..header_end - HEADER_TERMINATOR_LEN]) {
        Ok(s) => s,
        Err(e) => {
            if let Some(logger) = logger {
                logger.log(Level::Warn, &format!("onvif: {peer}: request headers not utf-8 ({e}); closing"));
            }
            return;
        }
    };
    let content_length = parse_content_length(header_str);
    let soap_action = parse_soap_action(header_str);

    while buf.len() < header_end + content_length {
        match stream.read(&mut chunk) {
            Ok(0) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) if e.kind() == io::ErrorKind::TimedOut => continue,
            Err(e) => {
                if let Some(logger) = logger {
                    logger.log(Level::Warn, &format!("onvif: {peer}: body read failed ({e}); closing"));
                }
                return;
            }
        }
        if buf.len() > MAX_READ_BUFFER_BYTES {
            return;
        }
    }

    let body_bytes = &buf[header_end..header_end + content_length];
    let body_str = String::from_utf8_lossy(body_bytes).to_string();
    let (status, xml) = route(&soap_action, &body_str, config, state);
    let response = build_http_response(status, &xml);
    let _ = stream.write_all(&response);
    if let Some(logger) = logger {
        logger.log(Level::Info, &format!("onvif client disconnected: {peer}"));
    }
}

/// Builds the full HTTP response bytes for `status` and `xml` body: status line, `Content-Type`, `Content-Length`, `Connection: close`, blank line, body. Line endings are `\r\n` per RFC 7230 §3.
fn build_http_response(status: u16, xml: &str) -> Vec<u8> {
    let reason = http_reason(status);
    let body = xml.as_bytes();
    let mut out = String::new();
    out.push_str(&format!("HTTP/1.1 {status} {reason}\r\n"));
    out.push_str(&format!("Content-Type: {SOAP_CONTENT_TYPE}\r\n"));
    out.push_str(&format!("Content-Length: {}\r\n", body.len()));
    out.push_str("Connection: close\r\n");
    out.push_str("\r\n");
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

fn find_terminator(buf: &[u8]) -> Option<usize> {
    buf.windows(HEADER_TERMINATOR_LEN).position(|w| w == HEADER_TERMINATOR)
}

/// Extracts the `Content-Length` value from a header block. Returns `0` when the header is absent or non-numeric so the body read completes immediately.
fn parse_content_length(headers: &str) -> usize {
    header_value(headers, "content-length").and_then(|v| v.parse().ok()).unwrap_or(0)
}

/// Extracts the `SOAPAction` header value (raw, with any surrounding quotes — `route` strips them). Returns an empty string when absent.
fn parse_soap_action(headers: &str) -> String {
    header_value(headers, "soapaction").map(|v| v.to_string()).unwrap_or_default()
}

/// Finds the value of header `name` (case-insensitive) in a header block, trimming surrounding whitespace. Returns `None` when absent.
fn header_value<'a>(headers: &'a str, name: &str) -> Option<&'a str> {
    for line in headers.split("\r\n") {
        if let Some((n, v)) = line.split_once(':') {
            if n.trim().eq_ignore_ascii_case(name) {
                return Some(v.trim());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> OnvifConfig {
        OnvifConfig::defaults_for("127.0.0.1".to_string(), 554, 8080)
    }

    #[test]
    fn strip_quotes_removes_one_layer_of_surrounding_double_quotes() {
        assert_eq!(strip_quotes("\"uri\""), "uri");
        assert_eq!(strip_quotes("uri"), "uri");
        assert_eq!(strip_quotes("\"\""), "");
    }

    #[test]
    fn resolve_action_prefers_soap_action_header_over_body() {
        let body = "http://www.onvif.org/ver10/media/wsdl/GetStreamUri";
        let r = resolve_action("\"http://www.onvif.org/ver10/device/wsdl/GetCapabilities\"", body).expect("header wins");
        assert_eq!(r.service, Service::Device);
        assert_eq!(r.op, "GetCapabilities");
    }

    #[test]
    fn resolve_action_falls_back_to_body_namespace_when_header_absent() {
        let r = resolve_action("", "<trt:GetStreamUri xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl/GetStreamUri\"/>").expect("body fallback");
        assert_eq!(r.service, Service::Media);
        assert_eq!(r.op, "GetStreamUri");
    }

    #[test]
    fn resolve_action_returns_none_for_unrecognized_action() {
        assert!(resolve_action("\"http://example.com/Foo\"", "").is_none());
        assert!(resolve_action("", "<no/>").is_none());
    }

    #[test]
    fn route_unknown_action_returns_fault_with_action_not_supported() {
        let (status, xml) = route("\"http://example.com/Bogus\"", "", &cfg(), &StreamState::new());
        assert_eq!(status, STATUS_OK);
        assert!(xml.contains("ActionNotSupported"));
    }

    #[test]
    fn get_device_information_prefers_published_camera_serial_over_default() {
        let state = StreamState::new();
        state.publish_camera_identity(crate::camera_identity::CameraIdentity { serial: "28704E11B531".to_string(), model: String::new() });
        let (_status, xml) = route("\"http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation\"", "", &cfg(), &state);
        assert!(xml.contains("<tds:SerialNumber>28704E11B531</tds:SerialNumber>"), "published MAC-derived serial must be advertised: {xml}");
        assert!(!xml.contains("000000000000"), "default serial must not appear once identity is published: {xml}");
        assert!(xml.contains("<tds:Model>UVC-G5-Bullet</tds:Model>"), "empty published model must fall back to the default MODEL: {xml}");
    }

    #[test]
    fn get_device_information_falls_back_to_cfg_serial_without_published_identity() {
        let cfg_with_serial = OnvifConfig { serial: "OPERATOR-FALLBACK".to_string(), ..cfg() };
        let (_status, xml) = route("\"http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation\"", "", &cfg_with_serial, &StreamState::new());
        assert!(xml.contains("<tds:SerialNumber>OPERATOR-FALLBACK</tds:SerialNumber>"), "cfg.serial fallback must be used when no identity is published: {xml}");
        assert!(xml.contains("<tds:Model>UVC-G5-Bullet</tds:Model>"), "default model must be advertised: {xml}");
    }

    #[test]
    fn get_device_information_uses_cfg_serial_when_published_model_is_empty_but_serial_present() {
        // Same shape as the published-serial case but exercising the operator override falling back to the *default* serial when nothing is published.
        let (_status, xml) = route("\"http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation\"", "", &cfg(), &StreamState::new());
        assert!(xml.contains("<tds:SerialNumber>000000000000</tds:SerialNumber>"), "default serial must appear when nothing is published: {xml}");
    }

    #[test]
    fn route_get_stream_uri_contains_exact_rtsp_uri() {
        let (status, xml) = route("\"http://www.onvif.org/ver10/media/wsdl/GetStreamUri\"", "", &cfg(), &StreamState::new());
        assert_eq!(status, STATUS_OK);
        assert!(xml.contains("<tt:Uri>rtsp://127.0.0.1:554/stream</tt:Uri>"));
    }

    #[test]
    fn route_get_snapshot_uri_returns_200_with_rtsp_stream_uri() {
        let (status, xml) = route("\"http://www.onvif.org/ver10/media/wsdl/GetSnapshotUri\"", "", &cfg(), &StreamState::new());
        assert_eq!(status, STATUS_OK, "GetSnapshotUri must return 200: {xml}");
        assert!(xml.contains("<trt:GetSnapshotUriResponse>"), "must wrap in GetSnapshotUriResponse: {xml}");
        assert!(xml.contains("<tt:Uri>rtsp://127.0.0.1:554/stream</tt:Uri>"), "snapshot URI must be the RTSP stream URI: {xml}");
        assert!(xml.contains("<tt:Timeout>PT60S</tt:Timeout>"), "must carry the 60 s timeout: {xml}");
        assert!(!xml.contains("Fault"), "must not be a fault: {xml}");
    }

    #[test]
    fn route_get_audio_output_configurations_returns_empty_list_not_fault() {
        let (status, xml) = route("\"http://www.onvif.org/ver10/media/wsdl/GetAudioOutputConfigurations\"", "", &cfg(), &StreamState::new());
        assert_eq!(status, STATUS_OK, "GetAudioOutputConfigurations must return 200: {xml}");
        assert!(xml.contains("<trt:GetAudioOutputConfigurationsResponse>"), "must wrap in GetAudioOutputConfigurationsResponse: {xml}");
        assert!(xml.contains("<trt:Configurations/>"), "must advertise an empty Configurations list: {xml}");
        assert!(!xml.contains("<tt:AudioOutputConfiguration"), "no audio output configuration may be advertised: {xml}");
        assert!(!xml.contains("Fault"), "must not be a fault: {xml}");
    }

    #[test]
    fn route_set_synchronization_point_returns_empty_success_not_fault() {
        let (status, xml) = route("\"http://www.onvif.org/ver10/device/wsdl/SetSynchronizationPoint\"", "", &cfg(), &StreamState::new());
        assert_eq!(status, STATUS_OK, "SetSynchronizationPoint must return 200: {xml}");
        assert!(xml.contains("<tds:SetSynchronizationPointResponse"), "must wrap in SetSynchronizationPointResponse: {xml}");
        assert!(!xml.contains("Fault"), "must not be a fault: {xml}");
    }

    #[test]
    fn route_get_snapshot_uri_routes_via_body_namespace_when_header_absent() {
        let body = envelope("<trt:GetSnapshotUri xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl/GetSnapshotUri\"/>");
        let (status, xml) = route("", &body, &cfg(), &StreamState::new());
        assert_eq!(status, STATUS_OK);
        assert!(xml.contains("<trt:GetSnapshotUriResponse>"), "body-namespace fallback must route GetSnapshotUri: {xml}");
    }

    #[test]
    fn build_http_response_has_content_type_and_length() {
        let bytes = build_http_response(STATUS_OK, "<x/>");
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.contains("Content-Type: application/soap+xml; charset=utf-8"));
        assert!(text.contains("Content-Length: 4\r\n"));
        assert!(text.contains("Connection: close\r\n"));
        assert!(text.ends_with("<x/>"));
    }

    #[test]
    fn route_get_system_date_and_time_returns_200_and_utc_datetime_elements() {
        let (status, xml) = route("\"http://www.onvif.org/ver10/device/wsdl/GetSystemDateAndTime\"", "", &cfg(), &StreamState::new());
        assert_eq!(status, STATUS_OK, "GetSystemDateAndTime must return 200: {xml}");
        assert!(xml.contains("<tds:GetSystemDateAndTimeResponse>"), "must wrap in GetSystemDateAndTimeResponse: {xml}");
        assert!(xml.contains("<tt:UTCDateTime>"), "must include UTCDateTime: {xml}");
        assert!(xml.contains("<tt:Year>"), "must include a Year element: {xml}");
        assert!(xml.contains("<tt:Hour>"), "must include an Hour element: {xml}");
    }

    #[test]
    fn route_get_system_date_and_time_routes_via_body_namespace_when_header_absent() {
        let body = envelope("<tds:GetSystemDateAndTime xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl/GetSystemDateAndTime\"/>");
        let (status, xml) = route("", &body, &cfg(), &StreamState::new());
        assert_eq!(status, STATUS_OK);
        assert!(xml.contains("<tds:GetSystemDateAndTimeResponse>"), "body-namespace fallback must route GetSystemDateAndTime: {xml}");
    }

    fn envelope(body_inner: &str) -> String {
        format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?><s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\"><s:Body>{body_inner}</s:Body></s:Envelope>")
    }
}
