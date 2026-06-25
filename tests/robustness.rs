//! Integration tests for `flvproxy`: the never-crash / resource-bounds / backpressure guarantees. Covers camera mid-tag disconnect returns to accept, oversized-tag resync keeps the connection alive, a saturated RTSP client cannot stall the camera thread, the max-clients cap rejects beyond with `503`, a malformed RTSP request yields `400`, and a partial-request-then-disconnect leaks no client. Loopback TCP only — no real camera, no real RTSP client.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use flvproxy::camera_listener::CameraListener;
use flvproxy::logging::Logger;
use flvproxy::rtsp_server::RtspServer;
use flvproxy::stream_state::{CodecParams, Frame, StreamState, CLIENT_CHANNEL_CAPACITY};

mod common;
use common::*;

/// Loopback server IP advertised in SDP; keeps origins predictable.
const SERVER_IP: &str = "127.0.0.1";

/// Per-poll wait when a test needs a server or pipeline to catch up.
const SETTLE_POLL: Duration = Duration::from_millis(25);

/// Upper bound for "within a short timeout" assertions. Generous CI-safe ceiling; loopback settles in milliseconds.
const SETTLE_DEADLINE: Duration = Duration::from_secs(2);

/// Bound for the backpressure timing assertion: each `publish_frame` of a tiny frame must complete well within this, proving a stalled client cannot block the camera thread.
const BACKPRESSURE_BOUND: Duration = Duration::from_millis(50);

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

/// Builds a `CodecParams` carrying `SPS_MAIN`/`PPS` and a 30 fps rate.
fn codec() -> CodecParams {
    CodecParams { sps: SPS_MAIN.to_vec(), pps: PPS.to_vec(), profile_indication: SPS_MAIN[1], profile_compat: SPS_MAIN[2], level_indication: SPS_MAIN[3], width: Some(1920), height: Some(1080), fps: Some(30.0) }
}

/// Builds a `Frame` with the given keyframe flag, timestamp, and NALU bytes.
fn frame(is_keyframe: bool, timestamp_ms: u32, nalus: &[&[u8]]) -> Frame {
    Frame { is_keyframe, timestamp_ms, nalus: nalus.iter().map(|n| n.to_vec()).collect() }
}

// ---------------------------------------------------------------------------
// Camera-listener harness (plain-TCP ingress).
// ---------------------------------------------------------------------------

/// Unique temp log path namespaced by pid + test name.
fn camera_log_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("flvproxy-robust-cam-{name}-{}.log", std::process::id()))
}

struct CameraHarness {
    state: StreamState,
    addr: std::net::SocketAddr,
    log_path: PathBuf,
    stop: Arc<AtomicBool>,
}

impl CameraHarness {
    fn start(name: &str) -> CameraHarness {
        let log_path = camera_log_path(name);
        let _ = std::fs::remove_file(&log_path);
        let logger = Arc::new(Logger::open(&log_path).expect("open logger"));
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
        let addr = listener.local_addr().expect("local addr");
        let state = StreamState::new();
        let cam = CameraListener::new(state.clone(), 0, logger);
        let stop = cam.shutdown_signal();
        thread::spawn(move || {
            let _ = cam.run_on(listener);
        });
        CameraHarness { state, addr, log_path, stop }
    }

    fn connect(&self) -> TcpStream {
        TcpStream::connect_timeout(&self.addr, SETTLE_DEADLINE).expect("connect to listener")
    }

    fn log_text(&self) -> String {
        std::fs::read_to_string(&self.log_path).unwrap_or_default()
    }
}

impl Drop for CameraHarness {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

// ---------------------------------------------------------------------------
// RTSP-server harness.
// ---------------------------------------------------------------------------

struct RtspHarness {
    addr: std::net::SocketAddr,
    active: Arc<std::sync::atomic::AtomicUsize>,
    stop: Arc<AtomicBool>,
}

impl RtspHarness {
    fn start(state: StreamState) -> RtspHarness {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
        let addr = listener.local_addr().expect("local addr");
        let server = RtspServer::new(state, 0, SERVER_IP.to_string());
        let active = server.active_clients_signal();
        let stop = server.shutdown_signal();
        thread::spawn(move || {
            let _ = server.run_on(listener);
        });
        RtspHarness { addr, active, stop }
    }
}

impl Drop for RtspHarness {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

/// Reads the first HTTP/RTSP response status line + headers from `stream`, returning the status code. Returns `0` on EOF/timeout with no data.
fn read_status(stream: &mut TcpStream) -> u16 {
    stream.set_read_timeout(Some(SETTLE_DEADLINE)).expect("set read timeout");
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    let deadline = Instant::now() + SETTLE_DEADLINE;
    while Instant::now() < deadline {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(_) => break,
        }
    }
    let text = String::from_utf8_lossy(&buf);
    text.split("\r\n").next().and_then(|line| line.split_whitespace().nth(1)).and_then(|t| t.parse().ok()).unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Camera-listener tests.
// ---------------------------------------------------------------------------

#[test]
fn camera_close_mid_tag_returns_to_accept_and_second_connection_works() {
    let h = CameraHarness::start("close_mid_tag");

    // Connection A: a valid header + config, then a video tag header whose declared body never arrives (the socket closes mid-tag). The listener must publish the config, hit EOF on the partial tag, log, and return to accept — no panic.
    let mut stream_a = Vec::new();
    stream_a.extend_from_slice(&FLV_HEADER);
    stream_a.extend_from_slice(&[0, 0, 0, 0]);
    push_tag(&mut stream_a, 0x09, 0, &std_seq_header_body(SPS_MAIN, PPS));
    // A bare video-tag header declaring a 6-byte body, but only 2 body bytes follow — then close.
    stream_a.push(0x09);
    stream_a.extend_from_slice(&[0, 0, 6]);
    stream_a.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0]);
    stream_a.extend_from_slice(&[0x65, 0xAA]);
    let mut conn_a = h.connect();
    conn_a.write_all(&stream_a).expect("write A");
    assert!(wait_until(|| h.state.codec().is_some()), "connection A must publish its config before closing mid-tag");
    let _ = conn_a.shutdown(std::net::Shutdown::Both);
    drop(conn_a);
    assert!(wait_until(|| h.log_text().contains("camera disconnected")), "connection A must log its disconnect: {}", h.log_text());

    // Connection B immediately works: a full stream publishes its config and frames.
    let (_id, rx) = h.state.add_client();
    let stream_b = build_stream(false, None, std_seq_header_body(SPS_MAIN, PPS), std_nalu_body(0x17, &[KEYFRAME_NALU]), std_nalu_body(0x27, &[INTER_NALU]));
    let mut conn_b = h.connect();
    conn_b.write_all(&stream_b).expect("write B");
    let _ = conn_b.shutdown(std::net::Shutdown::Write);
    assert!(wait_until(|| h.state.codec().map(|c| c.sps == SPS_MAIN).unwrap_or(false)), "connection B must publish its config");
    let frames: Vec<Frame> = rx.iter().take(2).collect();
    assert_eq!(frames.len(), 2, "connection B must deliver keyframe then inter");
    assert!(frames[0].is_keyframe);
}

#[test]
fn oversized_tag_triggers_resync_and_connection_continues() {
    let h = CameraHarness::start("oversized_resync");

    let mut conn = h.connect();

    // 1. Header + config first, in its own write so the config is published before the garbage (a single push that hits OversizedTag drops the events it had already collected).
    let mut head = Vec::new();
    head.extend_from_slice(&FLV_HEADER);
    head.extend_from_slice(&[0, 0, 0, 0]);
    push_tag(&mut head, 0x09, 0, &std_seq_header_body(SPS_MAIN, PPS));
    conn.write_all(&head).expect("write header+config");
    assert!(wait_until(|| h.state.codec().is_some()), "config published before the garbage");

    // 2. Oversized garbage header (12 MiB > 8 MiB cap, within u24) — forces OversizedTag; the framer enters Resyncing.
    let mut garbage = Vec::new();
    garbage.push(0x09);
    garbage.extend_from_slice(&[0xC0, 0x00, 0x00]);
    garbage.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0]);
    conn.write_all(&garbage).expect("write garbage");
    assert!(wait_until(|| h.log_text().contains("framing error")), "log must record the framing error: {}", h.log_text());

    // 3. Recovery: a fresh previous-tag-size + a valid keyframe on the SAME connection. The resync scan finds it and the connection continues.
    let (_id, rx) = h.state.add_client();
    let mut recovery = Vec::new();
    recovery.extend_from_slice(&[0, 0, 0, 0]);
    push_tag(&mut recovery, 0x09, 5000, &std_nalu_body(0x17, &[KEYFRAME_NALU]));
    conn.write_all(&recovery).expect("write recovery keyframe");
    let _ = conn.shutdown(std::net::Shutdown::Write);

    assert!(wait_until(|| h.log_text().contains("resync")), "log must record the resync: {}", h.log_text());
    let frames: Vec<Frame> = rx.iter().take(1).collect();
    assert_eq!(frames.len(), 1, "recovery keyframe must be published after resync");
    assert!(frames[0].is_keyframe);
    assert_eq!(frames[0].timestamp_ms, 5000);
    assert_eq!(frames[0].nalus, vec![KEYFRAME_NALU.to_vec()]);
}

// ---------------------------------------------------------------------------
// Backpressure (StreamState hub).
// ---------------------------------------------------------------------------

#[test]
fn backpressure_slow_client_does_not_stall_camera_thread() {
    let state = StreamState::new();
    let (_id, _rx) = state.add_client();

    let total = 5 * CLIENT_CHANNEL_CAPACITY;
    let start = Instant::now();
    let mut dropped = Vec::new();
    for i in 0..total {
        let outcome = state.publish_frame(frame(true, i as u32, &[&[0x65]]));
        dropped.extend(outcome.dropped_client_ids);
    }
    let elapsed = start.elapsed();
    assert!(elapsed < BACKPRESSURE_BOUND, "publishing {total} frames against a stalled client must be bounded, took {elapsed:?}");
    assert!(!dropped.is_empty(), "the stalled client must be dropped once its bounded channel fills (try_send → disconnect)");
}

// ---------------------------------------------------------------------------
// RTSP resource bounds.
// ---------------------------------------------------------------------------

#[test]
fn max_rtsp_clients_cap_rejects_beyond_with_503() {
    let state = StreamState::new();
    state.publish_config(codec());
    let h = RtspHarness::start(state.clone());

    // Hold MAX_RTSP_CLIENTS connections open (each blocks on a read, counting against the cap).
    let mut held: Vec<TcpStream> = Vec::new();
    for _ in 0..flvproxy::rtsp_server::MAX_RTSP_CLIENTS {
        held.push(TcpStream::connect_timeout(&h.addr, SETTLE_DEADLINE).expect("connect within cap"));
    }
    // Wait until the server has actually counted all of them, so the next connect is observed over the cap (connect returns before the accept loop fetches the stream, so this wait is what removes the race).
    assert!(wait_until(|| h.active.load(Ordering::SeqCst) == flvproxy::rtsp_server::MAX_RTSP_CLIENTS), "server must count all in-cap connections; counted={}", h.active.load(Ordering::SeqCst));

    // The next connection is rejected with 503.
    let mut over = TcpStream::connect_timeout(&h.addr, SETTLE_DEADLINE).expect("connect over cap");
    assert_eq!(read_status(&mut over), 503, "the connection beyond the cap must receive 503");

    // An earlier client is unaffected: a fresh OPTIONS on the first held connection succeeds.
    let mut first = held.remove(0);
    first.write_all(b"OPTIONS rtsp://127.0.0.1/stream RTSP/1.0\r\nCSeq: 1\r\n\r\n").expect("write OPTIONS");
    assert_eq!(read_status(&mut first), 200, "an in-cap client must still be served after a 503 rejection");
}

#[test]
fn malformed_rtsp_request_returns_400_and_next_connection_works() {
    let state = StreamState::new();
    state.publish_config(codec());
    let h = RtspHarness::start(state);

    let mut bad = TcpStream::connect_timeout(&h.addr, SETTLE_DEADLINE).expect("connect");
    bad.write_all(b"GARBAGE\r\n\r\n").expect("write garbage");
    assert_eq!(read_status(&mut bad), 400, "a malformed request must yield 400");

    // A new connection on the same server works normally.
    let mut good = TcpStream::connect_timeout(&h.addr, SETTLE_DEADLINE).expect("connect again");
    good.write_all(b"OPTIONS rtsp://127.0.0.1/stream RTSP/1.0\r\nCSeq: 1\r\n\r\n").expect("write OPTIONS");
    assert_eq!(read_status(&mut good), 200, "the server must serve a valid request after a 400");
}

#[test]
fn partial_rtsp_request_then_disconnect_returns_client_count_to_baseline() {
    let state = StreamState::new();
    state.publish_config(codec());
    let baseline = state.client_count();
    let h = RtspHarness::start(state.clone());

    // SETUP registers a StreamState client (count + 1); then a partial request (no \r\n\r\n terminator) followed by an abrupt disconnect leaves the handler to hit EOF, clean up, and decrement.
    let mut conn = TcpStream::connect_timeout(&h.addr, SETTLE_DEADLINE).expect("connect");
    conn.write_all(b"SETUP rtsp://127.0.0.1/stream/streamid=0 RTSP/1.0\r\nCSeq: 1\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n\r\n").expect("write SETUP");
    assert_eq!(read_status(&mut conn), 200, "SETUP must succeed and register a client");
    assert!(wait_until(|| state.client_count() == baseline + 1), "SETUP must register one client; count={}", state.client_count());

    // Partial request then disconnect.
    conn.write_all(b"PLAY rtsp://127.0.0.1/stream RTSP/1.0\r\nCSeq: 2\r\nSession: ").expect("write partial");
    let _ = conn.shutdown(std::net::Shutdown::Both);
    drop(conn);

    assert!(wait_until(|| state.client_count() == baseline), "client count must return to baseline after a partial-request disconnect; count={}", state.client_count());
}
