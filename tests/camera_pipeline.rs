//! Integration tests for `flvproxy::camera_listener` step 12: the camera TCP listener → FLV pipeline → stream state. Covers the cases enumerated in `plan/12-tcp-listener-and-flv-pipeline.md`, asserting byte-for-byte SPS/PPS and frame contents via a synthetic extendedFlv byte stream written over a real loopback TCP socket (no real camera).
//!
//! Stream construction mirrors the FLV/AVC/AMF layouts from `PROJECT.md`: uPFLV prefix + 9-byte FLV header + 4-byte leading previous-tag-size, then one `onMetaData` script tag, one video seq-header tag, one video keyframe NALU tag, and one video inter NALU tag.

use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use flvproxy::camera_listener::CameraListener;
use flvproxy::logging::Logger;
use flvproxy::stream_state::{Frame, StreamState};

mod common;
use common::*;

/// Poll interval for "wait until the pipeline catches up" assertions.
const SETTLE_POLL: Duration = Duration::from_millis(25);

/// Upper bound for settle assertions. The loopback pipeline publishes within milliseconds; two seconds is a generous CI-safe ceiling.
const SETTLE_DEADLINE: Duration = Duration::from_secs(2);

/// Alternate SPS (Baseline profile, level 3.0) used by the reconnect and malformed tests to distinguish connection B's config from connection A's.
const SPS_BASELINE: &[u8] = &[0x67, 0x42, 0xC0, 0x1E, 0x96, 0x35, 0x40, 0x1E];

// --- harness ---

/// Builds a unique temp log path for the named test, namespaced by pid.
fn test_log_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("flvproxy-camera-{name}-{}.log", std::process::id()))
}

/// Removes any prior log so a test starts clean.
fn clean_log(path: &PathBuf) {
    let _ = std::fs::remove_file(path);
}

/// In-process camera listener on an ephemeral loopback port, plus the shared `StreamState` and the log path the test asserts on. `Drop` signals the accept loop to exit.
struct Harness {
    state: StreamState,
    addr: std::net::SocketAddr,
    log_path: PathBuf,
    stop: Arc<AtomicBool>,
}

impl Harness {
    fn start(name: &str) -> Harness {
        let log_path = test_log_path(name);
        clean_log(&log_path);
        let logger = Arc::new(Logger::open(&log_path).expect("open logger"));
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
        let addr = listener.local_addr().expect("local addr");
        let state = StreamState::new();
        let cam = CameraListener::new(state.clone(), 0, logger);
        let stop = cam.shutdown_signal();
        thread::spawn(move || {
            let _ = cam.run_on(listener);
        });
        Harness { state, addr, log_path, stop }
    }

    /// Opens a TCP connection to the listener, returning the stream.
    fn connect(&self) -> TcpStream {
        TcpStream::connect_timeout(&self.addr, Duration::from_secs(2)).expect("connect to listener")
    }

    /// Reads the log file produced so far (empty string if unreadable).
    fn log_text(&self) -> String {
        std::fs::read_to_string(&self.log_path).unwrap_or_default()
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
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
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => break,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    out
}

/// Writes `bytes` to `conn` and shuts down the write half so the listener's handler observes EOF after consuming the buffered data.
fn write_stream(conn: &mut TcpStream, bytes: &[u8]) {
    conn.write_all(bytes).expect("write stream");
    let _ = conn.shutdown(std::net::Shutdown::Write);
}

// --- tests ---

#[test]
fn standard_stream_with_prefix_publishes_config_metadata_and_frames() {
    let h = Harness::start("std_prefix");
    let stream = build_stream(true, Some((1920, 1080, 30.0)), std_seq_header_body(SPS_MAIN, PPS), std_nalu_body(0x17, &[KEYFRAME_NALU]), std_nalu_body(0x27, &[INTER_NALU]));

    // Register a client BEFORE writing so it receives both frames in order (registering after would only deliver the cached keyframe).
    let (_id, rx) = h.state.add_client();

    let mut conn = h.connect();
    write_stream(&mut conn, &stream);

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

    // Wait for the handler to log SPS arrival and the connection.
    wait_until(|| h.log_text().contains("SPS received"));
    let log = h.log_text();
    assert!(log.contains("camera connected from"), "log must mention the connection: {log}");
    assert!(log.contains("SPS received: profile=4D level=1F"), "log must mention SPS arrival: {log}");
    assert!(log.contains("PPS received"), "log must mention PPS: {log}");
}

#[test]
fn standard_stream_without_prefix_publishes_config_metadata_and_frames() {
    let h = Harness::start("std_no_prefix");
    let stream = build_stream(false, Some((1280, 720, 25.0)), std_seq_header_body(SPS_MAIN, PPS), std_nalu_body(0x17, &[KEYFRAME_NALU]), std_nalu_body(0x27, &[INTER_NALU]));

    let (_id, rx) = h.state.add_client();
    let mut conn = h.connect();
    write_stream(&mut conn, &stream);

    assert!(wait_until(|| h.state.codec().is_some()));
    let codec = h.state.codec().expect("codec published");
    assert_eq!(codec.sps, SPS_MAIN.to_vec());
    assert_eq!(codec.pps, PPS.to_vec());
    assert_eq!(codec.width, Some(1280));
    assert_eq!(codec.height, Some(720));
    assert_eq!(codec.fps, Some(25.0));

    let frames = drain_frames(&rx, 2);
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0].nalus, vec![KEYFRAME_NALU.to_vec()]);
    assert_eq!(frames[1].nalus, vec![INTER_NALU.to_vec()]);
}

#[test]
fn extended_stream_publishes_config_metadata_and_frames() {
    let h = Harness::start("extended");
    let stream = build_stream(true, Some((1920, 1080, 30.0)), ext_seq_header_body(SPS_MAIN, PPS), ext_nalu_body(0x93, &[KEYFRAME_NALU]), ext_nalu_body(0xA3, &[INTER_NALU]));

    let (_id, rx) = h.state.add_client();
    let mut conn = h.connect();
    write_stream(&mut conn, &stream);

    assert!(wait_until(|| h.state.codec().is_some()));
    let codec = h.state.codec().expect("codec published");
    assert_eq!(codec.sps, SPS_MAIN.to_vec());
    assert_eq!(codec.pps, PPS.to_vec());
    assert_eq!(codec.width, Some(1920));
    assert_eq!(codec.height, Some(1080));
    assert_eq!(codec.fps, Some(30.0));

    let frames = drain_frames(&rx, 2);
    assert_eq!(frames.len(), 2);
    assert!(frames[0].is_keyframe);
    assert_eq!(frames[0].nalus, vec![KEYFRAME_NALU.to_vec()]);
    assert!(!frames[1].is_keyframe);
    assert_eq!(frames[1].nalus, vec![INTER_NALU.to_vec()]);
}

#[test]
fn reconnect_swaps_connections_and_publishes_new_config() {
    let h = Harness::start("reconnect");

    // Connection A: header + config with the Main-profile SPS, kept open.
    let stream_a = {
        let mut s = Vec::new();
        s.extend_from_slice(&FLV_HEADER);
        s.extend_from_slice(&[0, 0, 0, 0]);
        push_tag(&mut s, 0x09, 0, &std_seq_header_body(SPS_MAIN, PPS));
        s
    };
    let mut conn_a = h.connect();
    conn_a.write_all(&stream_a).expect("write A");
    assert!(wait_until(|| h.state.codec().map(|c| c.sps == SPS_MAIN).unwrap_or(false)), "connection A must publish its config");

    // Connection B (with A still open): a fresh header + config with the Baseline-profile SPS + a keyframe. The listener must force-close A and swap to B without crashing.
    let stream_b = build_stream(false, None, std_seq_header_body(SPS_BASELINE, PPS), std_nalu_body(0x17, &[KEYFRAME_NALU]), std_nalu_body(0x27, &[INTER_NALU]));
    let mut conn_b = h.connect();
    write_stream(&mut conn_b, &stream_b);
    drop(conn_a);

    assert!(wait_until(|| h.state.codec().map(|c| c.sps == SPS_BASELINE).unwrap_or(false)), "connection B's config must be live after the swap; codec={:?}", h.state.codec());
    let codec = h.state.codec().expect("codec published");
    assert_eq!(codec.sps, SPS_BASELINE.to_vec());
    assert_eq!(codec.profile_indication, 0x42);
}

#[test]
fn malformed_midstream_does_not_panic_and_listener_still_accepts() {
    let h = Harness::start("malformed");

    let mut conn = h.connect();

    // 1. Valid header + config. Wait until published so the config and the garbage below land in separate `FlvParser::push` calls (a single push that hits OversizedTag drops the events it had already collected).
    let mut stream = Vec::new();
    stream.extend_from_slice(&FLV_HEADER);
    stream.extend_from_slice(&[0, 0, 0, 0]);
    let cfg_body = std_seq_header_body(SPS_MAIN, PPS);
    push_tag(&mut stream, 0x09, 0, &cfg_body);
    conn.write_all(&stream).expect("write header+config");
    assert!(wait_until(|| h.state.codec().is_some()), "config published before the garbage");

    // 2. Garbage: a video tag header whose 3-byte data_size (0xC00000 ≈ 12 MiB) exceeds the 8 MiB framer cap but stays within the u24 range, forcing OversizedTag. The framer is in TagHeader state here (the config tag's trailing prev-size was already consumed), so this is a bare 11-byte header with no leading prev-size. The handler must log the framing error and keep the connection open (no panic).
    let mut garbage = Vec::new();
    garbage.push(0x09);
    garbage.extend_from_slice(&[0xC0, 0x00, 0x00]);
    garbage.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0]);
    conn.write_all(&garbage).expect("write garbage");
    assert!(wait_until(|| h.log_text().contains("framing error")), "log must record the parse/framing error: {}", h.log_text());

    // 3. Recovery: a fresh previous-tag-size + a valid keyframe NALU tag on the SAME connection. The framer reset to PrevTagSize after the OversizedTag, so it frames this tag cleanly — proving the connection stayed open and parsing resumed (best-effort; full resync is step 17).
    let (_id, rx) = h.state.add_client();
    let mut recovery = Vec::new();
    recovery.extend_from_slice(&[0, 0, 0, 0]);
    push_tag(&mut recovery, 0x09, 5000, &std_nalu_body(0x17, &[KEYFRAME_NALU]));
    conn.write_all(&recovery).expect("write recovery keyframe");
    let _ = conn.shutdown(std::net::Shutdown::Write);

    let frames = drain_frames(&rx, 1);
    assert_eq!(frames.len(), 1, "recovery keyframe must be published");
    assert!(frames[0].is_keyframe);
    assert_eq!(frames[0].timestamp_ms, 5000);
    assert_eq!(frames[0].nalus, vec![KEYFRAME_NALU.to_vec()]);
}

#[test]
fn metadata_arriving_after_config_republishes_with_merged_dimensions() {
    let h = Harness::start("meta_after_config");

    // Script tag arrives AFTER the config: header + config first, then an onMetaData script tag. The listener must merge the metadata into the already-published codec and republish.
    let mut stream = Vec::new();
    stream.extend_from_slice(&FLV_HEADER);
    stream.extend_from_slice(&[0, 0, 0, 0]);
    push_tag(&mut stream, 0x09, 0, &std_seq_header_body(SPS_MAIN, PPS));
    push_tag(&mut stream, 0x12, 0, &on_metadata_body(1920, 1080, 30.0));

    let mut conn = h.connect();
    write_stream(&mut conn, &stream);

    assert!(wait_until(|| h.state.codec().is_some()));
    assert!(wait_until(|| { h.state.codec().map(|c| c.width == Some(1920) && c.height == Some(1080) && c.fps == Some(30.0)).unwrap_or(false) }), "metadata must merge into the published codec; codec={:?}", h.state.codec());
    let codec = h.state.codec().expect("codec published");
    assert_eq!(codec.sps, SPS_MAIN.to_vec());
    assert_eq!(codec.width, Some(1920));
    assert_eq!(codec.height, Some(1080));
    assert_eq!(codec.fps, Some(30.0));
}
