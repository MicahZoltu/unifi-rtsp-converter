//! Integration tests for `flvproxy::rtsp_server` runtime half: the `TcpListener` accept loop, per-session state, interleaved + UDP RTP transports, the `PacketSink` test seam, and client-cleanup semantics.
//!
//! The server's `StreamState` is fed by the test thread itself (a mock frame producer), so no real camera is involved. Loopback TCP/UDP sockets keep the tests fast, deterministic, and CI-friendly.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use flvproxy::rtp::{RtpPacketizer, RtpSessionConfig, MAX_PAYLOAD};
use flvproxy::rtsp_server::{pump_frame_into, RtspServer, VecSink};
use flvproxy::stream_state::{CodecParams, Frame, StreamState};

/// Server IP advertised in SDP; loopback keeps the origin predictable.
const SERVER_IP: &str = "127.0.0.1";

/// Per-poll wait when the test needs the server to catch up to an action (publish a frame, drain a dropped client). Long enough for a loopback round-trip and a pump poll cycle, short enough to fail fast.
const SETTLE_POLL: Duration = Duration::from_millis(25);

/// Upper bound for "within a short timeout" assertions.
const SETTLE_DEADLINE: Duration = Duration::from_secs(2);

/// Realistic-ish SPS with NALU header `0x67` and profile/compat/level `4D 40 1F` (Main profile, level 3.1), matching the SDP/RTSP-protocol tests.
const SPS: &[u8] = &[0x67, 0x4D, 0x40, 0x1F, 0x96, 0x35, 0x40, 0x1E];

/// Realistic-ish PPS with NALU header `0x68`.
const PPS: &[u8] = &[0x68, 0xCE, 0x31, 0x12];

/// Builds `CodecParams` carrying `SPS`/`PPS` and a 30 fps rate.
fn codec() -> CodecParams {
    CodecParams { sps: SPS.to_vec(), pps: PPS.to_vec(), profile_indication: SPS[1], profile_compat: SPS[2], level_indication: SPS[3], width: Some(1920), height: Some(1080), fps: Some(30.0) }
}

/// Builds a `Frame` with the given keyframe flag, timestamp, and NALU bytes.
fn frame(is_keyframe: bool, timestamp_ms: u32, nalus: &[&[u8]]) -> Frame {
    Frame { is_keyframe, timestamp_ms, nalus: nalus.iter().map(|n| n.to_vec()).collect() }
}

/// Spins up an `RtspServer` on an ephemeral loopback listener, returning the first client connection, the server address (for extra clients), and a shutdown handle. The server thread is detached; `stop` ends its accept loop.
struct Harness {
    conn: ClientConn,
    server_addr: std::net::SocketAddr,
    stop: Arc<AtomicBool>,
}

impl Harness {
    fn start(state: StreamState) -> Harness {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
        let addr = listener.local_addr().expect("local addr");
        let server = RtspServer::new(state, 0, SERVER_IP.to_string());
        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_thread = stop.clone();
        thread::spawn(move || {
            let _ = server.run_on(listener);
            stop_for_thread.store(true, Ordering::SeqCst);
        });
        Harness { conn: ClientConn::connect(addr), server_addr: addr, stop }
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

/// Buffered reader/writer for one RTSP TCP connection. Holding a per-connection lookahead buffer is essential: after a control response, RTP `$`-frames arrive on the same socket, and a plain `read` can return them together with the response. Consuming only the bytes belonging to the current message leaves the rest for the next read, eliminating a lost-frame race.
struct ClientConn {
    stream: TcpStream,
    buf: Vec<u8>,
}

impl ClientConn {
    /// Connects to `addr` with a bounded read timeout.
    fn connect(addr: std::net::SocketAddr) -> ClientConn {
        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).expect("connect to server");
        stream.set_read_timeout(Some(Duration::from_secs(2))).expect("set read timeout");
        ClientConn { stream, buf: Vec::new() }
    }

    /// Sends one complete RTSP request.
    fn send(&mut self, req: &str) {
        self.stream.write_all(req.as_bytes()).expect("write request");
    }

    /// Reads more bytes into the lookahead buffer. Returns `false` on EOF or a read timeout (used as a "no more data yet" signal by `read_one_interleaved_frame`).
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

/// Decodes the first `$`-framed packet from `buf` if a complete one is present, returning it plus the number of bytes consumed (marker scan + 4-byte framing header + payload).
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

#[test]
fn happy_path_tcp_interleaved_serves_rtp_after_play() {
    let state = StreamState::new();
    state.publish_config(codec());
    state.publish_frame(frame(true, 1000, &[&[0x65, 0xAA]]));

    let mut h = Harness::start(state);
    h.conn.send("OPTIONS rtsp://127.0.0.1/stream RTSP/1.0\r\nCSeq: 1\r\n\r\n");
    let resp = h.conn.read_response();
    assert_eq!(status_code(&resp), 200);
    assert!(resp.contains("CSeq: 1"));
    assert!(resp.contains("Public: OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN"));

    h.conn.send("DESCRIBE rtsp://127.0.0.1/stream RTSP/1.0\r\nCSeq: 2\r\nAccept: application/sdp\r\n\r\n");
    let resp = h.conn.read_response();
    assert_eq!(status_code(&resp), 200);
    assert!(resp.contains("Content-Type: application/sdp"));
    assert!(resp.contains("a=rtpmap:96 H264/90000"));
    assert!(resp.contains("sprop-parameter-sets="), "SDP must advertise sprop-parameter-sets: {resp}");

    h.conn.send("SETUP rtsp://127.0.0.1/stream/streamid=0 RTSP/1.0\r\nCSeq: 3\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n\r\n");
    let resp = h.conn.read_response();
    assert_eq!(status_code(&resp), 200);
    assert!(resp.contains("interleaved=0-1"));
    let sid = session_id_from_response(&resp);

    h.conn.send(&format!("PLAY rtsp://127.0.0.1/stream RTSP/1.0\r\nCSeq: 4\r\nSession: {sid}\r\n\r\n"));
    let resp = h.conn.read_response();
    assert_eq!(status_code(&resp), 200);
    assert!(resp.contains("Range: npt=0.000-"));

    let interleaved = h.conn.read_one_interleaved_frame().expect("an interleaved RTP frame");
    assert_eq!(interleaved.channel, 0, "RTP channel must be 0");
    assert_eq!(interleaved.payload.len(), interleaved.declared_len, "length field must match following bytes");
    assert_eq!(interleaved.payload[0], 0x80, "RTP byte 0 must be V=2 (0x80)");
    assert_eq!(interleaved.payload[1] & 0x7F, 96, "RTP payload type must be 96");

    h.conn.send(&format!("TEARDOWN rtsp://127.0.0.1/stream RTSP/1.0\r\nCSeq: 5\r\nSession: {sid}\r\n\r\n"));
    let resp = h.conn.read_response();
    assert_eq!(status_code(&resp), 200);
}

#[test]
fn udp_transport_delivers_rtp_datagram() {
    let state = StreamState::new();
    state.publish_config(codec());
    state.publish_frame(frame(true, 500, &[&[0x65, 0x11]]));

    let client = UdpSocket::bind("127.0.0.1:0").expect("bind client udp");
    let client_rtp = client.local_addr().expect("local addr").port();
    let client_rtcp = client_rtp + 1;
    client.set_read_timeout(Some(Duration::from_secs(2))).expect("set read timeout");

    let mut h = Harness::start(state);
    h.conn.send(&format!("SETUP rtsp://127.0.0.1/stream/streamid=0 RTSP/1.0\r\nCSeq: 1\r\nTransport: RTP/AVP;unicast;client_port={client_rtp}-{client_rtcp}\r\n\r\n"));
    let resp = h.conn.read_response();
    assert_eq!(status_code(&resp), 200, "SETUP must succeed: {resp}");
    let sid = session_id_from_response(&resp);

    h.conn.send(&format!("PLAY rtsp://127.0.0.1/stream RTSP/1.0\r\nCSeq: 2\r\nSession: {sid}\r\n\r\n"));
    let resp = h.conn.read_response();
    assert_eq!(status_code(&resp), 200);

    let mut buf = [0u8; 2048];
    let n = client.recv(&mut buf).expect("receive RTP datagram");
    assert!(n >= 12, "RTP datagram must include the 12-byte header");
    assert_eq!(buf[0], 0x80, "RTP byte 0 must be V=2 (0x80)");
    assert_eq!(buf[1] & 0x7F, 96, "RTP payload type must be 96");
}

#[test]
fn vec_sink_pump_emits_exact_packetizer_output_for_two_nalu_frame() {
    let mut sink = VecSink::new();
    let config = RtpSessionConfig { ssrc: 0x0102_0304, start_seq: 0x1234, start_ts_offset: 0 };
    let mut packetizer = RtpPacketizer::with_config(config);
    let two_nalu_frame = frame(true, 100, &[&[0x67, 0xAA], &[0x68, 0xBB]]);

    pump_frame_into(&mut sink, &mut packetizer, &two_nalu_frame).expect("pump sends without error");

    let expected = RtpPacketizer::with_config(config).packetize_frame(&two_nalu_frame);
    assert_eq!(sink.into_packets(), expected);
}

#[test]
fn vec_sink_pump_fu_a_fragments_match_packetizer_output() {
    let mut sink = VecSink::new();
    let config = RtpSessionConfig { ssrc: 0x0102_0304, start_seq: 0x1234, start_ts_offset: 0 };
    let mut packetizer = RtpPacketizer::with_config(config);
    let mut large = vec![0u8; MAX_PAYLOAD * 2];
    large[0] = 0x65;
    let f = frame(true, 0, &[&large[..]]);

    pump_frame_into(&mut sink, &mut packetizer, &f).expect("pump sends without error");
    assert!(sink.packets().len() > 1, "large NALU must fragment");

    let expected = RtpPacketizer::with_config(config).packetize_frame(&f);
    assert_eq!(sink.packets(), expected.as_slice());
}

#[test]
fn describe_before_codec_published_returns_503() {
    let state = StreamState::new();
    let mut h = Harness::start(state);
    h.conn.send("DESCRIBE rtsp://127.0.0.1/stream RTSP/1.0\r\nCSeq: 1\r\nAccept: application/sdp\r\n\r\n");
    let resp = h.conn.read_response();
    assert_eq!(status_code(&resp), 503);
}

#[test]
fn client_disconnect_shrinks_hub_client_count_to_baseline() {
    let state = StreamState::new();
    state.publish_config(codec());
    state.publish_frame(frame(true, 1000, &[&[0x65, 0xAA]]));

    let baseline = state.client_count();
    let mut h = Harness::start(state.clone());
    h.conn.send("SETUP rtsp://127.0.0.1/stream/streamid=0 RTSP/1.0\r\nCSeq: 1\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n\r\n");
    let _ = h.conn.read_response();

    assert!(wait_until(|| state.client_count() == baseline + 1), "SETUP must register one client; count={}", state.client_count());

    drop(h);

    assert!(wait_until(|| state.client_count() == baseline), "client count must return to baseline after disconnect; count={}", state.client_count());
}

#[test]
fn two_concurrent_clients_each_receive_interleaved_rtp() {
    let state = StreamState::new();
    state.publish_config(codec());
    state.publish_frame(frame(true, 1000, &[&[0x65, 0x01]]));

    let mut a = Harness::start(state.clone());
    a.conn.send("SETUP rtsp://127.0.0.1/stream/streamid=0 RTSP/1.0\r\nCSeq: 1\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n\r\n");
    let resp_a = a.conn.read_response();
    assert_eq!(status_code(&resp_a), 200);
    let sid_a = session_id_from_response(&resp_a);

    let mut b = ClientConn::connect(a.server_addr);
    b.send("SETUP rtsp://127.0.0.1/stream/streamid=0 RTSP/1.0\r\nCSeq: 1\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n\r\n");
    let resp_b = b.read_response();
    assert_eq!(status_code(&resp_b), 200);
    let sid_b = session_id_from_response(&resp_b);

    assert!(wait_until(|| state.client_count() == 2), "both clients must be registered; count={}", state.client_count());

    a.conn.send(&format!("PLAY rtsp://127.0.0.1/stream RTSP/1.0\r\nCSeq: 2\r\nSession: {sid_a}\r\n\r\n"));
    assert_eq!(status_code(&a.conn.read_response()), 200);
    b.send(&format!("PLAY rtsp://127.0.0.1/stream RTSP/1.0\r\nCSeq: 2\r\nSession: {sid_b}\r\n\r\n"));
    assert_eq!(status_code(&b.read_response()), 200);

    let frame_a = a.conn.read_one_interleaved_frame().expect("client A gets RTP");
    let frame_b = b.read_one_interleaved_frame().expect("client B gets RTP");
    assert_eq!(frame_a.channel, 0);
    assert_eq!(frame_b.channel, 0);
    assert_eq!(frame_a.payload[1] & 0x7F, 96);
    assert_eq!(frame_b.payload[1] & 0x7F, 96);
}

/// Regression for the interleaved-RTCP drain: a TCP-interleaved client (VLC, ffprobe) sends RTCP receiver reports as `$`-framed packets on channel 1. The control read loop must drain them rather than let them accumulate in the 64 KiB read buffer until the connection breaks. Sends one RTCP frame immediately followed by a TEARDOWN in a single write and asserts TEARDOWN still gets a `200` with the echoed `CSeq`.
#[test]
fn client_interleaved_rtcp_frame_does_not_break_following_control_request() {
    let state = StreamState::new();
    state.publish_config(codec());
    state.publish_frame(frame(true, 1000, &[&[0x65, 0xAA]]));

    let mut h = Harness::start(state);
    h.conn.send("SETUP rtsp://127.0.0.1/stream/streamid=0 RTSP/1.0\r\nCSeq: 1\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n\r\n");
    let setup_resp = h.conn.read_response();
    assert_eq!(status_code(&setup_resp), 200);
    let sid = session_id_from_response(&setup_resp);

    h.conn.send(&format!("PLAY rtsp://127.0.0.1/stream RTSP/1.0\r\nCSeq: 2\r\nSession: {sid}\r\n\r\n"));
    assert_eq!(status_code(&h.conn.read_response()), 200);
    // Consume the cached keyframe's RTP packet so the pump is in steady state.
    let _ = h.conn.read_one_interleaved_frame();

    // A minimal RTCP receiver report (V=2, PT=201, 1 SRC) on channel 1, immediately followed by a TEARDOWN, written in one TCP send so the server's read loop sees both together.
    let rtcp_body: [u8; 8] = [0x80, 0xC9, 0x00, 0x01, 0x01, 0x02, 0x03, 0x04];
    let mut combined: Vec<u8> = vec![0x24, 0x01];
    combined.extend_from_slice(&(rtcp_body.len() as u16).to_be_bytes());
    combined.extend_from_slice(&rtcp_body);
    let teardown = format!("TEARDOWN rtsp://127.0.0.1/stream RTSP/1.0\r\nCSeq: 3\r\nSession: {sid}\r\n\r\n");
    combined.extend_from_slice(teardown.as_bytes());
    h.conn.stream.write_all(&combined).expect("write rtcp + teardown");

    let resp = h.conn.read_response();
    assert_eq!(status_code(&resp), 200, "TEARDOWN following an RTCP frame must succeed: {resp}");
    assert!(resp.contains("CSeq: 3"), "response must echo the TEARDOWN CSeq: {resp}");
}
