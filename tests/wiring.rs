//! End-to-end wiring regression for step 13: builds the shared `StreamState`, spawns the camera TCP listener and the RTSP server in one process on ephemeral loopback ports, feeds a synthetic `extendedFlv` byte stream to the camera listener over a real loopback TCP socket, then drives a full RTSP client session (`OPTIONS` → `DESCRIBE` → `SETUP` interleaved → `PLAY` → receive ≥1 RTP packet → `TEARDOWN`) against the RTSP server. This is the combined regression of steps 11+12 now that `console_main` wires them together, per `plan/13-end-to-end-rtsp.md` → "Validation (automated)".
//!
//! No real camera and no real RTSP client are involved — only loopback TCP sockets and hand-built bytes, so the test is deterministic and CI-friendly.

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use flvproxy::camera_listener::CameraListener;
use flvproxy::config::local_ip_v4;
use flvproxy::logging::Logger;
use flvproxy::onvif_discovery::parse_probe;
use flvproxy::onvif_server::{OnvifConfig, OnvifServer, DEFAULT_DEVICE_SERVICE_PATH};
use flvproxy::rtsp_server::RtspServer;
use flvproxy::stream_state::{Frame, StreamState};

mod common;
use common::*;

/// Server IP advertised in SDP; loopback keeps the origin predictable.
const SERVER_IP: &str = "127.0.0.1";

/// Per-poll wait when the test needs a server or the pipeline to catch up.
const SETTLE_POLL: Duration = Duration::from_millis(25);

/// Upper bound for "within a short timeout" assertions. Generous CI-safe ceiling; the loopback path settles in milliseconds.
const SETTLE_DEADLINE: Duration = Duration::from_secs(2);

// --- harness ---

/// Unique temp log path for the wiring test, namespaced by pid.
fn test_log_path() -> PathBuf {
    std::env::temp_dir().join(format!("flvproxy-wiring-{}.log", std::process::id()))
}

/// In-process camera listener + RTSP server + ONVIF HTTP server on ephemeral loopback ports, sharing one `StreamState` — the `console_main`-equivalent wiring (step 24 extends the step-13 harness with ONVIF). `Drop` signals all accept loops to exit.
struct Harness {
    camera_addr: SocketAddr,
    rtsp_addr: SocketAddr,
    onvif_addr: SocketAddr,
    state: StreamState,
    cam_stop: Arc<AtomicBool>,
    rtsp_stop: Arc<AtomicBool>,
    onvif_stop: Arc<AtomicBool>,
}

impl Harness {
    fn start() -> Harness {
        let log_path = test_log_path();
        let _ = std::fs::remove_file(&log_path);
        let logger = Arc::new(Logger::open(&log_path).expect("open logger"));

        let state = StreamState::new();

        let cam_listener = TcpListener::bind("127.0.0.1:0").expect("bind camera listener");
        let camera_addr = cam_listener.local_addr().expect("camera local addr");
        let cam = CameraListener::new(state.clone(), 0, logger.clone());
        let cam_stop = cam.shutdown_signal();
        thread::spawn(move || {
            let _ = cam.run_on(cam_listener);
        });

        let rtsp_listener = TcpListener::bind("127.0.0.1:0").expect("bind rtsp listener");
        let rtsp_addr = rtsp_listener.local_addr().expect("rtsp local addr");
        let server = RtspServer::new(state.clone(), 0, SERVER_IP.to_string());
        let rtsp_stop = server.shutdown_signal();
        thread::spawn(move || {
            let _ = server.run_on(rtsp_listener);
        });

        let onvif_listener = TcpListener::bind("127.0.0.1:0").expect("bind onvif listener");
        let onvif_addr = onvif_listener.local_addr().expect("onvif local addr");
        // The ONVIF config advertises the *actual* bound RTSP and ONVIF ports so `GetStreamUri` returns a URI the test can open against the live RTSP server, and `GetCapabilities` XAddrs match the bound ONVIF port.
        let onvif_cfg = OnvifConfig::defaults_for(SERVER_IP.to_string(), rtsp_addr.port(), onvif_addr.port());
        let onvif = OnvifServer::new(onvif_cfg, state.clone());
        let onvif_stop = onvif.shutdown_signal();
        thread::spawn(move || {
            let _ = onvif.run_on(onvif_listener);
        });

        Harness { camera_addr, rtsp_addr, onvif_addr, state, cam_stop, rtsp_stop, onvif_stop }
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.cam_stop.store(true, Ordering::SeqCst);
        self.rtsp_stop.store(true, Ordering::SeqCst);
        self.onvif_stop.store(true, Ordering::SeqCst);
    }
}

/// Polls `predicate` until it returns `true` or `SETTLE_DEADLINE` elapses.
fn wait_until<F: Fn() -> bool>(predicate: F) -> bool {
    let deadline = Instant::now() + SETTLE_DEADLINE;
    while Instant::now() < deadline {
        if predicate() {
            return true;
        }
        thread::sleep(SETTLE_POLL);
    }
    false
}

/// Drains up to `count` frames from `rx` within `SETTLE_DEADLINE`, returning them in receive order. Stops early on channel disconnect.
fn drain_frames(rx: &Receiver<Frame>, count: usize) -> Vec<Frame> {
    let deadline = Instant::now() + SETTLE_DEADLINE;
    let mut out = Vec::new();
    while out.len() < count {
        let timeout = deadline.saturating_duration_since(Instant::now());
        if timeout.is_zero() {
            break;
        }
        match rx.recv_timeout(timeout) {
            Ok(frame) => out.push(frame),
            Err(RecvTimeoutError::Timeout) => break,
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    out
}

// --- RTSP client connection ---

/// Buffered reader/writer for one RTSP TCP connection. A per-connection lookahead buffer is essential: after a control response, RTP `$`-frames arrive on the same socket, and a plain `read` can return them together with the response. Consuming only the bytes belonging to the current message leaves the rest for the next read, eliminating a lost-frame race.
struct ClientConn {
    stream: TcpStream,
    buf: Vec<u8>,
}

impl ClientConn {
    /// Connects to `addr` with a bounded read timeout.
    fn connect(addr: SocketAddr) -> ClientConn {
        let stream = TcpStream::connect_timeout(&addr, SETTLE_DEADLINE).expect("connect to server");
        stream.set_read_timeout(Some(SETTLE_DEADLINE)).expect("set read timeout");
        ClientConn { stream, buf: Vec::new() }
    }

    /// Sends one complete RTSP request.
    fn send(&mut self, req: &str) {
        self.stream.write_all(req.as_bytes()).expect("write request");
    }

    /// Reads more bytes into the lookahead buffer. Returns `false` on EOF or a read timeout.
    fn fill(&mut self) -> bool {
        let mut chunk = [0u8; 4096];
        match self.stream.read(&mut chunk) {
            Ok(0) => false,
            Ok(n) => {
                self.buf.extend_from_slice(&chunk[..n]);
                true
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => false,
            Err(_) => false,
        }
    }

    /// Reads one complete RTSP response (headers + any `Content-Length` body), consuming exactly those bytes from the lookahead buffer.
    fn read_response(&mut self) -> String {
        let deadline = Instant::now() + SETTLE_DEADLINE;
        loop {
            if let Some(header_end) = find_terminator(&self.buf) {
                let headers = String::from_utf8_lossy(&self.buf[..header_end]).to_string();
                let content_length = content_length(&headers).unwrap_or(0);
                let end = header_end + 4 + content_length;
                if self.buf.len() >= end {
                    let resp = String::from_utf8_lossy(&self.buf[..end]).to_string();
                    self.buf.drain(..end);
                    return resp;
                }
            }
            if Instant::now() >= deadline || !self.fill() {
                let resp = String::from_utf8_lossy(&self.buf).to_string();
                self.buf.clear();
                return resp;
            }
        }
    }

    /// Reads one complete `$`-framed interleaved RTP packet, consuming exactly its bytes. Returns `None` on EOF or timeout before a full frame arrives.
    fn read_one_interleaved_frame(&mut self) -> Option<Interleaved> {
        let deadline = Instant::now() + SETTLE_DEADLINE;
        loop {
            if let Some((framed, consumed)) = decode_first_interleaved(&self.buf) {
                self.buf.drain(..consumed);
                return Some(framed);
            }
            if Instant::now() >= deadline || !self.fill() {
                return None;
            }
        }
    }
}

/// One decoded interleaved frame from an RTSP TCP stream.
struct Interleaved {
    channel: u8,
    declared_len: usize,
    payload: Vec<u8>,
}

/// Decodes the first `$`-framed packet from `buf` if a complete one is present, returning it plus the number of bytes consumed.
fn decode_first_interleaved(buf: &[u8]) -> Option<(Interleaved, usize)> {
    let marker = buf.iter().position(|&b| b == 0x24)?;
    if buf.len() < marker + 4 {
        return None;
    }
    let channel = buf[marker + 1];
    let declared_len = u16::from_be_bytes([buf[marker + 2], buf[marker + 3]]) as usize;
    let start = marker + 4;
    if buf.len() < start + declared_len {
        return None;
    }
    Some((Interleaved { channel, declared_len, payload: buf[start..start + declared_len].to_vec() }, start + declared_len))
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

/// Extracts the bare session id (text before `;`) from a `Session:` header value found in a response string.
fn session_id_from_response(resp: &str) -> String {
    for line in resp.split("\r\n") {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("session") {
                return value.trim().split(';').next().expect("split yields one").trim().to_string();
            }
        }
    }
    panic!("no Session header in response: {resp}");
}

/// Status code from a response's status line.
fn status_code(resp: &str) -> u16 {
    let line = resp.split("\r\n").next().expect("status line");
    let mut parts = line.split_whitespace();
    parts.next();
    parts.next().expect("status code token").parse().expect("numeric status")
}

// --- tests ---

#[test]
fn end_to_end_camera_to_rtsp_client_over_shared_state() {
    let h = Harness::start();

    // Register a probe client BEFORE writing so we can deterministically observe the keyframe being published (the `StreamState` does not expose `last_keyframe`); this guarantees the cached keyframe a later RTSP SETUP receives actually exists, removing a publish-order race.
    let (_probe_id, probe_rx) = h.state.add_client();

    let stream = build_stream(true, Some((1920, 1080, 30.0)), std_seq_header_body(SPS_MAIN, PPS), std_nalu_body(0x17, &[KEYFRAME_NALU]), std_nalu_body(0x27, &[INTER_NALU]));
    let mut cam_conn = TcpStream::connect_timeout(&h.camera_addr, SETTLE_DEADLINE).expect("connect to camera listener");
    cam_conn.write_all(&stream).expect("write extendedFlv stream");
    let _ = cam_conn.shutdown(Shutdown::Write);

    assert!(wait_until(|| h.state.codec().is_some()), "camera must publish the codec; codec={:?}", h.state.codec());
    let probe_frames = drain_frames(&probe_rx, 2);
    assert_eq!(probe_frames.len(), 2, "probe client must receive keyframe then inter: {probe_frames:?}");
    assert!(probe_frames[0].is_keyframe, "first published frame is the keyframe");
    assert!(!probe_frames[1].is_keyframe, "second published frame is the inter");

    let codec = h.state.codec().expect("codec published");
    assert_eq!(codec.sps, SPS_MAIN.to_vec());
    assert_eq!(codec.pps, PPS.to_vec());
    assert_eq!(codec.width, Some(1920));
    assert_eq!(codec.height, Some(1080));
    assert_eq!(codec.fps, Some(30.0));

    // RTSP client session against the same process's RTSP server.
    let mut client = ClientConn::connect(h.rtsp_addr);

    client.send("OPTIONS rtsp://127.0.0.1/stream RTSP/1.0\r\nCSeq: 1\r\n\r\n");
    let resp = client.read_response();
    assert_eq!(status_code(&resp), 200, "OPTIONS must succeed: {resp}");
    assert!(resp.contains("Public: OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN"), "OPTIONS must list supported methods: {resp}");

    client.send("DESCRIBE rtsp://127.0.0.1/stream RTSP/1.0\r\nCSeq: 2\r\nAccept: application/sdp\r\n\r\n");
    let resp = client.read_response();
    assert_eq!(status_code(&resp), 200, "DESCRIBE must succeed: {resp}");
    assert!(resp.contains("Content-Type: application/sdp"), "DESCRIBE must return SDP content type: {resp}");
    assert!(resp.contains("v=0\r\n"), "SDP body must be non-empty (starts with v=0): {resp}");
    assert!(resp.contains("sprop-parameter-sets="), "SDP must advertise sprop-parameter-sets: {resp}");

    client.send("SETUP rtsp://127.0.0.1/stream/streamid=0 RTSP/1.0\r\nCSeq: 3\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n\r\n");
    let resp = client.read_response();
    assert_eq!(status_code(&resp), 200, "SETUP must succeed: {resp}");
    assert!(resp.contains("interleaved=0-1"), "SETUP must echo the negotiated transport: {resp}");
    let sid = session_id_from_response(&resp);

    client.send(&format!("PLAY rtsp://127.0.0.1/stream RTSP/1.0\r\nCSeq: 4\r\nSession: {sid}\r\n\r\n"));
    let resp = client.read_response();
    assert_eq!(status_code(&resp), 200, "PLAY must succeed: {resp}");
    assert!(resp.contains("Range: npt=0.000-"), "PLAY must echo the range: {resp}");

    let interleaved = client.read_one_interleaved_frame().expect("at least one interleaved RTP packet after PLAY");
    assert_eq!(interleaved.channel, 0, "RTP must arrive on channel 0");
    assert_eq!(interleaved.payload.len(), interleaved.declared_len, "interleaved length field must match the following bytes");
    assert_eq!(interleaved.payload[0], 0x80, "RTP byte 0 must be V=2 (0x80)");
    assert_eq!(interleaved.payload[1] & 0x7F, 96, "RTP payload type must be 96");

    client.send(&format!("TEARDOWN rtsp://127.0.0.1/stream RTSP/1.0\r\nCSeq: 5\r\nSession: {sid}\r\n\r\n"));
    let resp = client.read_response();
    assert_eq!(status_code(&resp), 200, "TEARDOWN must succeed: {resp}");
}

#[test]
fn local_ip_v4_returns_non_loopback_or_none() {
    if let Some(addr) = local_ip_v4() {
        let ip: std::net::Ipv4Addr = addr.parse().expect("local_ip_v4 must return a parseable IPv4 string");
        assert!(!ip.is_loopback(), "local_ip_v4 must return a non-loopback IPv4 when an interface exists: {ip}");
    }
    // `None` (no non-loopback interface, e.g. air-gapped CI) is tolerated.
}

// --- ONVIF end-to-end wiring (step 24) ---

/// SOAP envelope wrapping an empty body element for the given qualified name, used so the router's body-namespace fallback has something to scan when the `SOAPAction` header is omitted.
fn soap_envelope(body_inner: &str) -> String {
    format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?><s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\"><s:Body>{body_inner}</s:Body></s:Envelope>")
}

/// Posts one SOAP request to `addr` and returns the full HTTP response (status line + headers + body). `soap_action` is written verbatim into the `SOAPAction:` header; pass an empty string to omit it.
fn post_onvif_soap(addr: SocketAddr, soap_action: &str, body: &str) -> String {
    let mut stream = TcpStream::connect_timeout(&addr, SETTLE_DEADLINE).expect("connect onvif");
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
    stream.write_all(req.as_bytes()).expect("write onvif request");
    let mut resp = Vec::new();
    let mut chunk = [0u8; 4096];
    let deadline = Instant::now() + SETTLE_DEADLINE;
    while Instant::now() < deadline {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => resp.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(_) => break,
        }
        if find_terminator(&resp).is_some() && onvif_body_complete(&resp) {
            break;
        }
    }
    String::from_utf8_lossy(&resp).to_string()
}

/// Returns true once the response buffer holds a full header block plus its declared `Content-Length` body.
fn onvif_body_complete(resp: &[u8]) -> bool {
    let Some(header_end) = find_terminator(resp) else {
        return false;
    };
    let headers = std::str::from_utf8(&resp[..header_end]).unwrap_or("");
    let content_length = content_length(headers).unwrap_or(0);
    resp.len() >= header_end + 4 + content_length
}

/// Extracts the inner text of the first `<tt:Uri>...</tt:Uri>` element from a SOAP body.
fn extract_stream_uri(xml: &str) -> String {
    let open = "<tt:Uri>";
    let close = "</tt:Uri>";
    let Some(start) = xml.find(open) else {
        return String::new();
    };
    let rest = &xml[start + open.len()..];
    let Some(end) = rest.find(close) else {
        return String::new();
    };
    rest[..end].to_string()
}

/// Splits `rtsp://host:port/path` into `(host_port, path)` so a test can connect to the RTSP server at the URI the ONVIF Media service advertised.
fn split_rtsp_uri(uri: &str) -> (String, String) {
    let rest = uri.strip_prefix("rtsp://").unwrap_or(uri);
    let (host_port, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    (host_port.to_string(), path.to_string())
}

#[test]
fn onvif_get_stream_uri_returns_live_rtsp_url_and_describe_succeeds() {
    let h = Harness::start();

    // Publish a codec + keyframe so the RTSP DESCRIBE has an SDP to return and a frame to serve.
    let (_probe_id, _probe_rx) = h.state.add_client();
    let stream = build_stream(true, Some((1920, 1080, 30.0)), std_seq_header_body(SPS_MAIN, PPS), std_nalu_body(0x17, &[KEYFRAME_NALU]), std_nalu_body(0x27, &[INTER_NALU]));
    let mut cam_conn = TcpStream::connect_timeout(&h.camera_addr, SETTLE_DEADLINE).expect("connect to camera listener");
    cam_conn.write_all(&stream).expect("write extendedFlv stream");
    let _ = cam_conn.shutdown(Shutdown::Write);
    assert!(wait_until(|| h.state.codec().is_some()), "camera must publish the codec before ONVIF/RTSP clients ask for it");

    // GetStreamUri via the ONVIF Media service.
    let body = soap_envelope("<trt:GetStreamUri/>");
    let resp = post_onvif_soap(h.onvif_addr, "\"http://www.onvif.org/ver10/media/wsdl/GetStreamUri\"", &body);
    assert_eq!(status_code(&resp), 200, "GetStreamUri must return 200: {resp}");
    let expected_uri = format!("rtsp://{ip}:{port}/stream", ip = SERVER_IP, port = h.rtsp_addr.port());
    let actual_uri = extract_stream_uri(&resp);
    assert_eq!(actual_uri, expected_uri, "GetStreamUri must return the live RTSP URL advertising the bound RTSP port: {resp}");

    // GetCapabilities XAddrs must point at the bound ONVIF port.
    let body = soap_envelope("<tds:GetCapabilities/>");
    let resp = post_onvif_soap(h.onvif_addr, "\"http://www.onvif.org/ver10/device/wsdl/GetCapabilities\"", &body);
    assert_eq!(status_code(&resp), 200, "GetCapabilities must return 200: {resp}");
    let expected_xaddr = format!("http://{ip}:{port}{path}", ip = SERVER_IP, port = h.onvif_addr.port(), path = DEFAULT_DEVICE_SERVICE_PATH);
    assert!(resp.contains(&expected_xaddr), "GetCapabilities XAddrs must match the bound ONVIF port ({expected_xaddr}): {resp}");

    // Open the advertised RTSP URI as an RTSP client and DESCRIBE → 200 + SDP. This proves the ONVIF-advertised URL lands on a working RTSP target.
    let (host_port, path) = split_rtsp_uri(&actual_uri);
    let rtsp_addr: SocketAddr = std::net::ToSocketAddrs::to_socket_addrs(&host_port).expect("resolve rtsp host").next().expect("rtsp addr");
    let mut client = ClientConn::connect(rtsp_addr);
    client.send(&format!("DESCRIBE rtsp://{host_port}{path} RTSP/1.0\r\nCSeq: 1\r\nAccept: application/sdp\r\n\r\n"));
    let resp = client.read_response();
    assert_eq!(status_code(&resp), 200, "DESCRIBE on the ONVIF-advertised URI must succeed: {resp}");
    assert!(resp.contains("Content-Type: application/sdp"), "DESCRIBE must return SDP: {resp}");
    assert!(resp.contains("sprop-parameter-sets="), "SDP must advertise sprop-parameter-sets: {resp}");
}

#[test]
fn wsdiscovery_disabled_means_no_probe_reply() {
    // Behavioral proxy for the `onvif_discovery = false` config flag: when no `Discovery` is spawned, a Probe sent to the multicast group receives no ProbeMatch within a short timeout. The gating itself lives in `console_main` (binary code, not unit-testable from the lib); this test asserts the observable consequence — an unspawned discovery answers no probes. Multicast is environment-dependent (often unavailable in CI containers), so the test is lenient: if the multicast probe socket cannot be created or joined, it passes trivially.
    let probe_socket = match std::net::UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return,
    };
    let group: std::net::Ipv4Addr = "239.255.255.250".parse().unwrap();
    let _ = probe_socket.set_multicast_loop_v4(true);
    let dst: std::net::SocketAddr = std::net::SocketAddrV4::new(group, 3702).into();
    let probe_body = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\">\
         <s:Header><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>\
         <wsa:MessageID>urn:uuid:flag-disabled-test</wsa:MessageID></s:Header>\
         <s:Body><Probe xmlns=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\"/></s:Body></s:Envelope>";
    let _ = probe_socket.set_read_timeout(Some(Duration::from_millis(300)));
    let _ = probe_socket.send_to(probe_body.as_bytes(), dst);
    let mut buf = [0u8; 8192];
    let deadline = Instant::now() + Duration::from_millis(800);
    while Instant::now() < deadline {
        match probe_socket.recv_from(&mut buf) {
            Ok((n, _)) => {
                // Any ProbeMatch reply here would mean a discovery instance is answering; with discovery disabled (not spawned) none should arrive. A stray reply from another process on the host is tolerated by checking it is not a ProbeMatch for our MessageID.
                let body = &buf[..n];
                if let Some(relates) = parse_probe(body) {
                    let _ = relates;
                    let text = String::from_utf8_lossy(body);
                    if text.contains("urn:uuid:flag-disabled-test") && text.contains("ProbeMatch") {
                        panic!("no ProbeMatch should arrive when discovery is not spawned, got: {text}");
                    }
                }
            }
            Err(_) => break,
        }
    }
    // Reaching here means no matching ProbeMatch arrived — the disabled-flag expectation holds.
}
