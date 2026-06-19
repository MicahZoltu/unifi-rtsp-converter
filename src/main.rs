//! Command-line entry point. Parses `--install`, `--uninstall`, and
//! `--console` arguments. `--console` runs the camera listener and RTSP
//! server in the foreground (step 12 human-test path); the Windows Service
//! Control Manager FFI lifecycle (`--install`/`--uninstall`/service mode)
//! lands in step 18.
//!
//! The logic modules live in the `flvproxy` library crate (`src/lib.rs`); the
//! binary imports them as needed.

use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

use flvproxy::camera_listener::CameraListener;
use flvproxy::config::Config;
use flvproxy::logging::{Level, Logger};
use flvproxy::rtsp_server::RtspServer;
use flvproxy::stream_state::StreamState;

/// Prints the startup banner identifying the proxy and its supported modes.
fn print_banner() {
    println!("flvproxy — UniFi Camera FLV-to-RTSP/ONVIF proxy");
    println!("usage: flvproxy [--install | --uninstall | --console]");
}

/// Handles a recognized CLI flag by dispatching to the matching mode. Returns
/// the process exit code to report to the operating system.
fn handle_flag(flag: &str) -> i32 {
    match flag {
        "--install" => {
            println!("--install: service installation not implemented yet");
            0
        }
        "--uninstall" => {
            println!("--uninstall: service removal not implemented yet");
            0
        }
        "--console" => console_main(),
        other => {
            eprintln!("flvproxy: unknown argument '{other}'");
            eprintln!("valid arguments: --install, --uninstall, --console");
            1
        }
    }
}

/// Foreground mode (step 12 human test): loads `flvproxy.ini` from the
/// executable's directory, opens `flvproxy.log` beside it, and spawns the
/// camera TCP listener plus the RTSP server on a shared `StreamState`. The
/// main thread then blocks until the process is killed (Ctrl+C), which is the
/// expected operator interaction for a quick smoke against a real camera.
fn console_main() -> i32 {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(std::path::Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."));
    let config = Config::load_or_default(&exe_dir.join("flvproxy.ini"));
    let log_path = exe_dir.join("flvproxy.log");
    let logger = match Logger::open(&log_path) {
        Ok(l) => Arc::new(l),
        Err(e) => {
            eprintln!("flvproxy: cannot open log {}: {e}", log_path.display());
            return 1;
        }
    };
    logger.log(
        Level::Info,
        &format!(
            "flvproxy console mode starting (listen={}, rtsp={})",
            config.listen_port, config.rtsp_port
        ),
    );

    let state = StreamState::new();
    let server_ip = detect_lan_ip().unwrap_or_else(|| "127.0.0.1".to_string());

    let cam = CameraListener::new(state.clone(), config.listen_port, logger.clone());
    thread::spawn(move || {
        if let Err(e) = cam.run() {
            eprintln!("flvproxy: camera listener failed: {e}");
        }
    });

    let server = RtspServer::new(state, config.rtsp_port, server_ip);
    thread::spawn(move || {
        if let Err(e) = server.run() {
            eprintln!("flvproxy: rtsp server failed: {e}");
        }
    });

    loop {
        thread::park();
    }
}

/// Best-effort detection of the host's primary LAN IPv4 address by opening a
/// UDP socket and connecting to a public address — `connect` on a UDP socket
/// performs no I/O but resolves the route, letting `local_addr` report the
/// source IP that route would use. Returns `None` on any failure so the
/// caller can fall back to loopback. Zero-crates per the project constraint;
/// robust multi-interface selection is out of scope for the console smoke
/// (proper SDP/ONVIF URL wiring lands in step 13/16).
fn detect_lan_ip() -> Option<String> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    Some(sock.local_addr().ok()?.ip().to_string())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        print_banner();
        return;
    }
    let code = handle_flag(&args[0]);
    std::process::exit(code);
}
