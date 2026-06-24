//! Integration tests for `flvproxy::onvif_server` (step 22): the SOAP router (`route`) at the string level and the HTTP runtime (`OnvifServer`) over loopback TCP. Covers the cases enumerated in `plan/22-onvif-soap.md`: `GetCapabilities`, `GetDeviceInformation`, `GetProfiles`, `GetStreamUri`, the unknown-action SOAP Fault, XML-escaping of the server IP, the `SOAPAction`-header vs body-namespace routing fallback, and one end-to-end HTTP round-trip.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use flvproxy::onvif_server::{route, OnvifConfig, OnvifServer};
use flvproxy::stream_state::{CameraIdentity, CodecParams, StreamState};

/// Loopback server IP keeps XAddrs / stream URIs predictable across tests.
const SERVER_IP: &str = "127.0.0.1";

/// Realistic-ish SPS with NALU header `0x67` and profile/compat/level `4D 40 1F` (Main profile, level 3.1), matching the RTSP/SDP tests.
const SPS: &[u8] = &[0x67, 0x4D, 0x40, 0x1F, 0x96, 0x35, 0x40, 0x1E];

/// Realistic-ish PPS with NALU header `0x68`.
const PPS: &[u8] = &[0x68, 0xCE, 0x31, 0x12];

/// Upper bound for "within a short timeout" assertions against the loopback HTTP server.
const SETTLE_DEADLINE: Duration = Duration::from_secs(2);

/// Builds an `OnvifConfig` with loopback addressing and default ports.
fn cfg() -> OnvifConfig {
    OnvifConfig::defaults_for(SERVER_IP.to_string(), 8554, 8080)
}

/// Builds `CodecParams` carrying `SPS`/`PPS`, 1280x720, 25 fps, so the `GetProfiles` test asserts the metadata-derived values rather than the 1920x1080@30 fallback.
fn codec_with_metadata() -> CodecParams {
    CodecParams { sps: SPS.to_vec(), pps: PPS.to_vec(), profile_indication: SPS[1], profile_compat: SPS[2], level_indication: SPS[3], width: Some(1280), height: Some(720), fps: Some(25.0) }
}

/// Envelope wrapping an empty body for the given SOAP action, used so the router's body-namespace fallback has something to scan.
fn envelope(body_inner: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">\
         <s:Body>{body_inner}</s:Body></s:Envelope>"
    )
}

// --------------------------------------------------------------------------- Router-level tests ---------------------------------------------------------------------------

#[test]
fn get_capabilities_response_advertises_device_and_media_xaddrs() {
    let (_status, xml) = route("\"http://www.onvif.org/ver10/device/wsdl/GetCapabilities\"", "", &cfg(), &StreamState::new());
    assert!(xml.contains("<tt:Device><tt:XAddrs>http://127.0.0.1:8080/onvif/device_service</tt:XAddrs>"), "device XAddrs must point at the device service: {xml}");
    assert!(xml.contains("/onvif/media_service</tt:XAddrs>"), "media XAddrs must point at the media service: {xml}");
}

#[test]
fn get_device_information_response_carries_manufacturer_model_firmware_serial() {
    let (_status, xml) = route("\"http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation\"", "", &cfg(), &StreamState::new());
    assert!(xml.contains("<tds:Manufacturer>Ubiquiti</tds:Manufacturer>"));
    assert!(xml.contains("<tds:Model>UVC-G5-Bullet</tds:Model>"));
    let firmware = extract_element(&xml, "tds:FirmwareVersion");
    let serial = extract_element(&xml, "tds:SerialNumber");
    assert!(!firmware.is_empty(), "firmware must be non-empty: {xml}");
    assert!(!serial.is_empty(), "serial must be non-empty: {xml}");
}

#[test]
fn get_device_information_prefers_published_camera_mac_serial_over_default() {
    let state = StreamState::new();
    state.publish_camera_identity(CameraIdentity { serial: "28704E11B531".to_string(), model: String::new() });
    let (_status, xml) = route("\"http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation\"", "", &cfg(), &state);
    assert_eq!(extract_element(&xml, "tds:SerialNumber"), "28704E11B531", "published MAC-derived serial must win: {xml}");
    assert!(!xml.contains("000000000000"), "placeholder serial must not appear once identity is published: {xml}");
    assert_eq!(extract_element(&xml, "tds:Model"), "UVC-G5-Bullet", "empty published model must fall back to the default: {xml}");
}

#[test]
fn get_device_information_falls_back_to_configured_serial_without_identity() {
    let cfg = OnvifConfig { serial: "OPERATOR-FALLBACK".to_string(), ..cfg() };
    let (_status, xml) = route("\"http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation\"", "", &cfg, &StreamState::new());
    assert_eq!(extract_element(&xml, "tds:SerialNumber"), "OPERATOR-FALLBACK", "cfg.serial fallback must be used when no identity is published: {xml}");
}

#[test]
fn get_profiles_response_uses_published_metadata_width_height_fps() {
    let state = StreamState::new();
    state.publish_config(codec_with_metadata());
    let (_status, xml) = route("\"http://www.onvif.org/ver10/media/wsdl/GetProfiles\"", "", &cfg(), &state);
    assert!(xml.contains("trt:Profiles token=\"Profile_1\""));
    assert!(xml.contains("<tt:Encoding>H264</tt:Encoding>"));
    assert!(xml.contains("<tt:Width>1280</tt:Width>"));
    assert!(xml.contains("<tt:Height>720</tt:Height>"));
    assert!(xml.contains("<tt:FrameRateLimit>25</tt:FrameRateLimit>"));
}

#[test]
fn get_profiles_response_falls_back_to_1080p_30fps_without_metadata() {
    let (_status, xml) = route("\"http://www.onvif.org/ver10/media/wsdl/GetProfiles\"", "", &cfg(), &StreamState::new());
    assert!(xml.contains("<tt:Width>1920</tt:Width>"));
    assert!(xml.contains("<tt:Height>1080</tt:Height>"));
    assert!(xml.contains("<tt:FrameRateLimit>30</tt:FrameRateLimit>"));
}

#[test]
fn get_stream_uri_response_contains_exact_rtsp_uri() {
    let (_status, xml) = route("\"http://www.onvif.org/ver10/media/wsdl/GetStreamUri\"", "", &cfg(), &StreamState::new());
    assert!(xml.contains("<tt:Uri>rtsp://127.0.0.1:8554/stream</tt:Uri>"));
}

#[test]
fn unknown_soap_action_yields_action_not_supported_fault() {
    let (_status, xml) = route("\"http://example.com/Bogus\"", "", &cfg(), &StreamState::new());
    assert!(xml.contains("ActionNotSupported"), "unknown action must return a SOAP Fault: {xml}");
}

#[test]
fn missing_soap_action_routes_via_body_namespace_fallback() {
    let body = envelope("<trt:GetStreamUri xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl/GetStreamUri\"/>");
    let (_status, xml) = route("", &body, &cfg(), &StreamState::new());
    assert!(xml.contains("<tt:Uri>rtsp://127.0.0.1:8554/stream</tt:Uri>"), "body-namespace fallback must still route GetStreamUri: {xml}");
}

#[test]
fn server_ip_with_markup_is_xml_escaped_in_responses() {
    let cfg = OnvifConfig::defaults_for("10.0.0.1&<>\"'".to_string(), 8554, 8080);
    let injected = "10.0.0.1&<>\"'";
    let (_status, caps) = route("\"http://www.onvif.org/ver10/device/wsdl/GetCapabilities\"", "", &cfg, &StreamState::new());
    assert!(!caps.contains(injected), "raw injected IP must not appear unescaped: {caps}");
    assert!(caps.contains("10.0.0.1&amp;&lt;&gt;&quot;&apos;"), "injected IP must be escaped: {caps}");
    let (_status, uri) = route("\"http://www.onvif.org/ver10/media/wsdl/GetStreamUri\"", "", &cfg, &StreamState::new());
    assert!(!uri.contains(injected), "raw injected IP must not appear in stream URI: {uri}");
    assert!(uri.contains("rtsp://10.0.0.1&amp;&lt;&gt;&quot;&apos;:8554/stream"), "stream URI must escape injected IP: {uri}");
}

// --------------------------------------------------------------------------- HTTP-level (loopback) tests ---------------------------------------------------------------------------

/// Spins up an `OnvifServer` on an ephemeral loopback listener, returning the bound address and a shutdown flag. The server thread is detached; dropping the guard stops the accept loop.
struct Harness {
    addr: std::net::SocketAddr,
    stop: Arc<AtomicBool>,
}

impl Harness {
    fn start() -> Harness {
        Self::start_with(StreamState::new())
    }

    fn start_with(state: StreamState) -> Harness {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
        let addr = listener.local_addr().expect("local addr");
        let server = OnvifServer::new(cfg(), state);
        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_thread = stop.clone();
        thread::spawn(move || {
            let _ = server.run_on(listener);
            stop_for_thread.store(true, Ordering::SeqCst);
        });
        Harness { addr, stop }
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

/// Sends one SOAP request over a fresh TCP connection and returns the full HTTP response (status line + headers + body). `soap_action` is written verbatim into the `SOAPAction:` header; pass an empty string to omit it.
fn post_soap(addr: std::net::SocketAddr, soap_action: &str, body: &str) -> String {
    let mut stream = TcpStream::connect_timeout(&addr, SETTLE_DEADLINE).expect("connect");
    stream.set_read_timeout(Some(SETTLE_DEADLINE)).expect("set read timeout");
    let mut req = String::new();
    req.push_str("POST /onvif/device_service HTTP/1.1\r\n");
    req.push_str("Host: 127.0.0.1\r\n");
    req.push_str("Content-Type: application/soap+xml; charset=utf-8\r\n");
    req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    if !soap_action.is_empty() {
        req.push_str(&format!("SOAPAction: {soap_action}\r\n"));
    }
    req.push_str("\r\n");
    req.push_str(body);
    stream.write_all(req.as_bytes()).expect("write request");

    let mut resp = Vec::new();
    let mut chunk = [0u8; 4096];
    let deadline = Instant::now() + SETTLE_DEADLINE;
    while Instant::now() < deadline {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => resp.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
                if find_terminator(&resp).is_some() {
                    break;
                }
                continue;
            }
            Err(_) => break,
        }
        if find_terminator(&resp).is_some() && body_complete(&resp) {
            break;
        }
    }
    String::from_utf8_lossy(&resp).to_string()
}

/// Returns true once the response buffer holds a full header block AND its declared `Content-Length` body.
fn body_complete(resp: &[u8]) -> bool {
    let Some(header_end) = find_terminator(resp) else {
        return false;
    };
    let headers = std::str::from_utf8(&resp[..header_end]).unwrap_or("");
    let content_length = content_length(headers).unwrap_or(0);
    resp.len() >= header_end + 4 + content_length
}

/// Locates the first byte of the `\r\n\r\n` header terminator.
fn find_terminator(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Extracts the `Content-Length` value from a header block.
fn content_length(headers: &str) -> Option<usize> {
    for line in headers.split("\r\n") {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                return value.trim().parse().ok();
            }
        }
    }
    None
}

/// Extracts the inner text of the first `<prefix:Name>...</prefix:Name>` element.
fn extract_element(xml: &str, qualified_name: &str) -> String {
    let open = format!("<{qualified_name}>");
    let close = format!("</{qualified_name}>");
    let Some(start) = xml.find(&open) else {
        return String::new();
    };
    let rest = &xml[start + open.len()..];
    let Some(end) = rest.find(&close) else {
        return String::new();
    };
    rest[..end].to_string()
}

/// Status code parsed from the HTTP status line.
fn http_status(resp: &str) -> u16 {
    let line = resp.split("\r\n").next().expect("status line");
    let mut parts = line.split_whitespace();
    parts.next();
    parts.next().expect("status code").parse().expect("numeric")
}

#[test]
fn http_get_stream_uri_with_soap_action_header_returns_200_and_rtsp_uri() {
    let h = Harness::start();
    let body = envelope("<trt:GetStreamUri/>");
    let resp = post_soap(h.addr, "\"http://www.onvif.org/ver10/media/wsdl/GetStreamUri\"", &body);
    assert_eq!(http_status(&resp), 200, "status must be 200: {resp}");
    assert!(resp.contains("Content-Type: application/soap+xml"), "content type must be SOAP: {resp}");
    assert!(resp.contains("<tt:Uri>rtsp://127.0.0.1:8554/stream</tt:Uri>"), "body must contain the RTSP URI: {resp}");
}

#[test]
fn http_get_stream_uri_without_soap_action_routes_via_body_namespace() {
    let h = Harness::start();
    let body = envelope("<trt:GetStreamUri xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl/GetStreamUri\"/>");
    let resp = post_soap(h.addr, "", &body);
    assert_eq!(http_status(&resp), 200);
    assert!(resp.contains("<tt:Uri>rtsp://127.0.0.1:8554/stream</tt:Uri>"), "body-namespace fallback must still return the URI: {resp}");
}

#[test]
fn http_get_capabilities_returns_device_and_media_xaddrs() {
    let h = Harness::start();
    let body = envelope("<tds:GetCapabilities/>");
    let resp = post_soap(h.addr, "\"http://www.onvif.org/ver10/device/wsdl/GetCapabilities\"", &body);
    assert_eq!(http_status(&resp), 200);
    assert!(resp.contains("/onvif/device_service</tt:XAddrs>"));
    assert!(resp.contains("/onvif/media_service</tt:XAddrs>"));
}

#[test]
fn http_unknown_action_returns_soap_fault_body() {
    let h = Harness::start();
    let body = envelope("<x:Foo/>");
    let resp = post_soap(h.addr, "\"http://example.com/Bogus\"", &body);
    assert_eq!(http_status(&resp), 200);
    assert!(resp.contains("ActionNotSupported"));
}

#[test]
fn http_get_profiles_uses_published_metadata() {
    let state = StreamState::new();
    state.publish_config(codec_with_metadata());
    let h = Harness::start_with(state);
    let body = envelope("<trt:GetProfiles/>");
    let resp = post_soap(h.addr, "\"http://www.onvif.org/ver10/media/wsdl/GetProfiles\"", &body);
    assert_eq!(http_status(&resp), 200);
    assert!(resp.contains("trt:Profiles token=\"Profile_1\""));
    assert!(resp.contains("<tt:Width>1280</tt:Width>"));
    assert!(resp.contains("<tt:Height>720</tt:Height>"));
}
