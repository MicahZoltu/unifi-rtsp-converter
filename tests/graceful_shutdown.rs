//! Graceful-shutdown validation: spawns the camera listener, RTSP server, and ONVIF HTTP server in-process on ephemeral loopback ports (the same wiring `console_main` assembles), sets the shared shutdown flag, and asserts every worker thread returns within a 5s budget via a no-crates join-with-timeout helper. WS-Discovery (the fourth server) binds the host's multicast 3702, which is environment-dependent and often unavailable in CI, so it is not exercised here; its `Bye`-on-exit path is covered by `onvif_discovery.rs`'s unit tests.

use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use flvproxy::camera_listener::CameraListener;
use flvproxy::logging::Logger;
use flvproxy::onvif_server::{OnvifConfig, OnvifServer};
use flvproxy::rtsp_server::RtspServer;
use flvproxy::stream_state::StreamState;

mod common;

/// Per-worker join budget, matching the service's `STOP_PENDING_WAIT_HINT_MS`. Each accept loop polls its shutdown flag every ~50ms, so a healthy worker exits well inside this bound.
const JOIN_BUDGET: Duration = Duration::from_secs(5);

/// Poll granularity for the join-timeout helper.
const JOIN_POLL: Duration = Duration::from_millis(25);

fn test_log_path() -> PathBuf {
    std::env::temp_dir().join(format!("flvproxy-shutdown-{}.log", std::process::id()))
}

/// One spawned server: its shutdown flag (so the test can stop it) and the worker `JoinHandle` (so the test can assert it returns).
struct Worker {
    stop: Arc<AtomicBool>,
    handle: JoinHandle<()>,
}

/// Joins `handle`, polling `is_finished` until it returns or `budget` elapses, returning `true` iff the worker returned in time.
fn join_with_timeout(handle: JoinHandle<()>, budget: Duration) -> bool {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        if handle.is_finished() {
            let _ = handle.join();
            return true;
        }
        thread::sleep(JOIN_POLL);
    }
    false
}

#[test]
fn all_servers_exit_within_budget_after_shutdown_signal() {
    let log_path = test_log_path();
    let _ = std::fs::remove_file(&log_path);
    let logger = Arc::new(Logger::open(&log_path).expect("open logger"));
    let state = StreamState::new();

    let cam_listener = TcpListener::bind("127.0.0.1:0").expect("bind camera listener");
    let cam = CameraListener::new(state.clone(), 0, logger.clone());
    let cam_stop = cam.shutdown_signal();
    let cam_handle = thread::spawn(move || {
        let _ = cam.run_on(cam_listener);
    });

    let rtsp_listener = TcpListener::bind("127.0.0.1:0").expect("bind rtsp listener");
    let rtsp_addr = rtsp_listener.local_addr().expect("rtsp local addr");
    let server = RtspServer::new(state.clone(), 0, "127.0.0.1".to_string());
    let rtsp_stop = server.shutdown_signal();
    let rtsp_handle = thread::spawn(move || {
        let _ = server.run_on(rtsp_listener);
    });

    let onvif_listener = TcpListener::bind("127.0.0.1:0").expect("bind onvif listener");
    let onvif_addr = onvif_listener.local_addr().expect("onvif local addr");
    let onvif_cfg = OnvifConfig::defaults_for("127.0.0.1".to_string(), rtsp_addr.port(), onvif_addr.port());
    let onvif = OnvifServer::new(onvif_cfg, state.clone());
    let onvif_stop = onvif.shutdown_signal();
    let onvif_handle = thread::spawn(move || {
        let _ = onvif.run_on(onvif_listener);
    });

    let workers = [Worker { stop: cam_stop, handle: cam_handle }, Worker { stop: rtsp_stop, handle: rtsp_handle }, Worker { stop: onvif_stop, handle: onvif_handle }];

    // Give the accept loops a moment to enter their non-blocking accept polls before signalling shutdown, so the flag is observed on the first poll rather than racing a bind.
    thread::sleep(Duration::from_millis(150));

    for w in &workers {
        w.stop.store(true, Ordering::SeqCst);
    }

    for w in workers {
        let returned = join_with_timeout(w.handle, JOIN_BUDGET);
        assert!(returned, "a server worker did not exit within 5s of the shutdown signal");
    }

    let _ = std::fs::remove_file(&log_path);
}
