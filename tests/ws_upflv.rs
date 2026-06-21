//! Integration tests for `flvproxy::camera_listener` step 20: the 7550 production ingestion path. The step-20 interim recon (sub-steps 1–3) confirmed the real 7550 transport: **plain TCP, bare FLV** — no TLS, no WebSocket, no uPFLV prefix. The camera sends `FLV\x01\x07\x00\x00\x00\x09` (the standard FLV header) directly over a raw TCP socket. These tests drive the shared `run_connection` over a loopback `TcpStream` pair with a bare-FLV byte stream (no uPFLV prefix), proving `detect_and_strip_prefix` correctly handles the no-prefix case and the FLV pipeline publishes the same `codec()` and frame delivery as the step-14 uPFLV-prefix path.
//!
//! Cases:
//! - Single write carrying the whole bare-FLV stream → config + 2 frames.
//! - Multi-write stream (header+config, keyframe, inter) → all published in order.
//! - Close mid-stream → `run_connection` returns cleanly, no panic, the state stays usable for a reconnect.

mod common;

use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use flvproxy::camera_listener::{run_connection, CamByteSource, PlainTcpSource};
use flvproxy::logging::Logger;
use flvproxy::stream_state::{Frame, StreamState};

use common::*;

/// Poll interval for "wait until the pipeline catches up" assertions.
const SETTLE_POLL: Duration = Duration::from_millis(25);

/// Upper bound for settle assertions. The loopback pipeline publishes within milliseconds; two seconds is a generous CI-safe ceiling (mirrors `tests/camera_pipeline.rs`).
const SETTLE_DEADLINE: Duration = Duration::from_secs(2);

/// Builds a unique temp log path for the named test, namespaced by pid.
fn test_log_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("flvproxy-bareflv-{name}-{}.log", std::process::id()))
}

/// Removes any prior log so a test starts clean.
fn clean_log(path: &PathBuf) {
    let _ = std::fs::remove_file(path);
}

/// One bare-FLV test run: a loopback pair, a `PlainTcpSource` on the server side driven by `run_connection` on its own thread, and the client side handed back to the test for writing raw FLV bytes. `Drop` closes the client so `run_connection` observes EOF and exits.
struct BareFlvHarness {
    state: StreamState,
    client: TcpStream,
    log_path: PathBuf,
    shutdown: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<()>>,
}

impl BareFlvHarness {
    /// Connects a loopback pair, wraps the server end in a `PlainTcpSource`, and spawns `run_connection` on it. The client end is returned for the test to write raw FLV bytes into.
    fn start(name: &str) -> BareFlvHarness {
        let log_path = test_log_path(name);
        clean_log(&log_path);
        let logger = Arc::new(Logger::open(&log_path).expect("open logger"));
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let client = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).expect("connect");
        let (server, _) = listener.accept().expect("accept");
        let _ = client.set_nodelay(true);
        let _ = server.set_nodelay(true);

        let state = StreamState::new();
        let shutdown = Arc::new(AtomicBool::new(false));
        let source = PlainTcpSource::new(server);
        let run_state = state.clone();
        let run_logger = logger.clone();
        let run_shutdown = shutdown.clone();
        let join = thread::spawn(move || {
            run_connection(source, "bareflv-test".to_string(), run_state, run_logger, run_shutdown);
        });
        BareFlvHarness { state, client, log_path, shutdown, join: Some(join) }
    }

    /// Writes raw bytes to the client side.
    fn write_bytes(&mut self, data: &[u8]) {
        use std::io::Write;
        self.client.write_all(data).expect("write bytes");
    }

    /// Reads the log file produced so far (empty string if unreadable).
    fn log_text(&self) -> String {
        std::fs::read_to_string(&self.log_path).unwrap_or_default()
    }
}

impl Drop for BareFlvHarness {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        let _ = self.client.shutdown(std::net::Shutdown::Both);
        if let Some(handle) = self.join.take() {
            let _ = handle.join();
        }
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

/// Drains up to `count` frames from `rx` within `SETTLE_DEADLINE`, in receive order. Stops early on channel disconnect.
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
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => break,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    out
}

/// Builds a bare-FLV stream (no uPFLV prefix) — the real 7550 format confirmed by the step-20 interim recon.
fn bare_flv_stream(metadata: Option<(u32, u32, f64)>, seq_header: Vec<u8>, keyframe_body: Vec<u8>, inter_body: Vec<u8>) -> Vec<u8> {
    build_stream(false, metadata, seq_header, keyframe_body, inter_body)
}

#[test]
fn single_write_bare_flv_publishes_config_metadata_and_frames() {
    let mut h = BareFlvHarness::start("single_write");
    let stream = bare_flv_stream(Some((1920, 1080, 30.0)), std_seq_header_body(SPS_MAIN, PPS), std_nalu_body(0x17, &[KEYFRAME_NALU]), std_nalu_body(0x27, &[INTER_NALU]));

    let (_id, rx) = h.state.add_client();
    h.write_bytes(&stream);

    assert!(wait_until(|| h.state.codec().is_some()), "config must be published; codec={:?}", h.state.codec());

    let codec = h.state.codec().expect("codec published");
    assert_eq!(codec.sps, SPS_MAIN.to_vec());
    assert_eq!(codec.pps, PPS.to_vec());
    assert_eq!(codec.profile_indication, 0x4D);
    assert_eq!(codec.level_indication, 0x1F);
    assert_eq!(codec.width, Some(1920));
    assert_eq!(codec.height, Some(1080));
    assert_eq!(codec.fps, Some(30.0));

    let frames = drain_frames(&rx, 2);
    assert_eq!(frames.len(), 2, "client must receive keyframe then inter");
    assert!(frames[0].is_keyframe);
    assert_eq!(frames[0].timestamp_ms, 1000);
    assert_eq!(frames[0].nalus, vec![KEYFRAME_NALU.to_vec()]);
    assert!(!frames[1].is_keyframe);
    assert_eq!(frames[1].timestamp_ms, 1033);
    assert_eq!(frames[1].nalus, vec![INTER_NALU.to_vec()]);

    wait_until(|| h.log_text().contains("SPS received"));
    let log = h.log_text();
    assert!(log.contains("SPS received: profile=4D level=1F"), "log must mention SPS arrival: {log}");
}

#[test]
fn multi_write_bare_flv_publishes_config_then_frames_in_order() {
    let mut h = BareFlvHarness::start("multi_write");

    // Write 1: FLV header + leading prev-tag-size + onMetaData + AVC seq header.
    let mut msg1 = flv_prelude(false);
    push_tag(&mut msg1, 0x12, 0, &on_metadata_body(1920, 1080, 30.0));
    push_tag(&mut msg1, 0x09, 1000, &std_seq_header_body(SPS_MAIN, PPS));

    // Write 2: the keyframe tag.
    let mut msg2 = Vec::new();
    push_tag(&mut msg2, 0x09, 1000, &std_nalu_body(0x17, &[KEYFRAME_NALU]));

    // Write 3: the inter-frame tag.
    let mut msg3 = Vec::new();
    push_tag(&mut msg3, 0x09, 1033, &std_nalu_body(0x27, &[INTER_NALU]));

    let (_id, rx) = h.state.add_client();
    h.write_bytes(&msg1);
    assert!(wait_until(|| h.state.codec().is_some()), "config must be published from msg1; codec={:?}", h.state.codec());
    h.write_bytes(&msg2);
    h.write_bytes(&msg3);

    let codec = h.state.codec().expect("codec published");
    assert_eq!(codec.sps, SPS_MAIN.to_vec());
    assert_eq!(codec.pps, PPS.to_vec());
    assert_eq!(codec.width, Some(1920));
    assert_eq!(codec.height, Some(1080));
    assert_eq!(codec.fps, Some(30.0));

    let frames = drain_frames(&rx, 2);
    assert_eq!(frames.len(), 2, "keyframe then inter must both arrive");
    assert!(frames[0].is_keyframe);
    assert_eq!(frames[0].timestamp_ms, 1000);
    assert_eq!(frames[0].nalus, vec![KEYFRAME_NALU.to_vec()]);
    assert!(!frames[1].is_keyframe);
    assert_eq!(frames[1].timestamp_ms, 1033);
    assert_eq!(frames[1].nalus, vec![INTER_NALU.to_vec()]);
}

#[test]
fn close_midstream_drops_connection_without_panic_and_state_stays_usable() {
    let mut h = BareFlvHarness::start("close_midstream");

    // Feed header + config, wait for it to land, then close the client.
    let mut msg = flv_prelude(false);
    push_tag(&mut msg, 0x09, 0, &std_seq_header_body(SPS_MAIN, PPS));
    h.write_bytes(&msg);
    assert!(wait_until(|| h.state.codec().is_some()), "config must be published before the close; codec={:?}", h.state.codec());
    let codec_before = h.state.codec().expect("codec published");
    assert_eq!(codec_before.sps, SPS_MAIN.to_vec());

    // Close the client — run_connection observes EOF and returns.
    let _ = h.client.shutdown(std::net::Shutdown::Both);

    assert!(wait_until(|| h.log_text().contains("camera connection closed: bareflv-test")), "run_connection must log the close and return; log={}", h.log_text());

    // The state is still usable: a new client can register on the same StreamState, mirroring a reconnect on the same listener.
    let (_id2, _rx2) = h.state.add_client();
    assert_eq!(h.state.client_count(), 1);
    let codec_after = h.state.codec().expect("codec still published after close");
    assert_eq!(codec_after.sps, SPS_MAIN.to_vec());
}

/// Compile-time proof that `PlainTcpSource` is a `CamByteSource` (the production seam). The 7550 path uses `PlainTcpSource` directly — no TLS, no WS, no separate source type.
#[test]
fn plain_tcp_source_is_cam_byte_source() {
    fn assert_cam_byte_source<S: CamByteSource>(_source: &S) {}
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let client = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).expect("connect");
    let (server, _) = listener.accept().expect("accept");
    let source = PlainTcpSource::new(server);
    assert_cam_byte_source(&source);
    drop(client);
    drop(source);
}
