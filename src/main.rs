//! Command-line entry point. Parses `--install`, `--uninstall`, and `--console` arguments. `--console` runs the camera listener and RTSP server in the foreground on a shared `StreamState` and blocks on Ctrl+C (step 13 end-to-end wiring path); the Windows Service Control Manager FFI lifecycle (`--install`/`--uninstall`/service mode) lands in the Windows service step.
//!
//! The logic modules live in the `flvproxy` library crate (`src/lib.rs`); the binary imports them as needed.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use flvproxy::camera_listener::CameraListener;
use flvproxy::config::Config;
use flvproxy::logging::{Level, Logger};
use flvproxy::onvif_discovery::{Discovery, DiscoveryConfig};
use flvproxy::onvif_server::{OnvifConfig, OnvifServer, DEFAULT_DEVICE_SERVICE_PATH};
use flvproxy::rtsp_server::RtspServer;
use flvproxy::stream_state::StreamState;

#[cfg(windows)]
use flvproxy::config::DEFAULT_CERT_FILE;
#[cfg(windows)]
use flvproxy::protect_listener::{ProtectListener, PROTECT_AVCLIENT_PORT};
#[cfg(windows)]
use flvproxy::tls_schannel::TlsAcceptor;

/// Relaxed ordering suffices for the shutdown flag: it is an advisory signal, not synchronization that establishes happens-before for other data (the `StreamState` mutex carries that burden). Mirrors the server modules.
const RELAXED: Ordering = Ordering::Relaxed;

/// Main-thread sleep between polls of `CONSOLE_SHUTDOWN`. `park_timeout` is used instead of `park` so a missing Ctrl+C handler (FFI best-effort) still lets the loop re-check the flag rather than deadlocking.
const CONSOLE_SHUTDOWN_POLL_MS: u64 = 250;

/// Process-wide flag flipped by the installed Ctrl+C handler. The main thread polls it; on `true` it signals the spawned servers to stop and returns. A plain `AtomicBool` is safe to set from a signal / console control handler running on an arbitrary thread.
static CONSOLE_SHUTDOWN: AtomicBool = AtomicBool::new(false);

fn print_banner() {
    println!("flvproxy — UniFi Camera FLV-to-RTSP/ONVIF proxy");
    println!("usage: flvproxy [--install | --uninstall | --console]");
}

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

/// Foreground mode (step 13 + step 21): loads `flvproxy.ini` from the executable's directory, opens `flvproxy.log` beside it, constructs one shared `StreamState`, and spawns the camera listener plus the RTSP server on it — each on its own thread with a clone of the shared shutdown handle.
///
/// On Windows (step 21) the proxy additionally spawns the Protect-controller 7442 TLS+WSS+AVClient listener so the camera adopts over 7442 and pushes bare FLV over 7550 with no SSH into the camera. On Linux `console_main` retains the plain-TCP `CameraListener` so `cargo test` and dev runs still work (this is the test ingress, per step 21's debt note). The RTSP server runs on both.
///
/// The advertised server IP is resolved from the config (explicit `server_ip` override, else auto-detection, else loopback) so SDP origins and the future ONVIF stream URI point clients at a reachable address. The main thread blocks on Ctrl+C (which sets `CONSOLE_SHUTDOWN`), then signals all servers to stop and returns.
fn console_main() -> i32 {
    let exe_dir = std::env::current_exe().ok().and_then(|p| p.parent().map(std::path::Path::to_path_buf)).unwrap_or_else(|| PathBuf::from("."));
    let config = Config::load_or_default(&exe_dir.join("flvproxy.ini"));
    let log_path = exe_dir.join("flvproxy.log");
    let logger = match Logger::open_console(&log_path) {
        Ok(l) => Arc::new(l),
        Err(e) => {
            eprintln!("flvproxy: cannot open log {}: {e}", log_path.display());
            return 1;
        }
    };

    let state = StreamState::new();
    let server_ip = config.advertised_server_ip();

    // On Windows the proxy spawns the Protect-controller 7442 TLS+WSS+AVClient listener so the camera adopts over 7442 and pushes bare FLV over 7550 with no SSH into the camera. On Linux `console_main` retains the plain-TCP `CameraListener` so `cargo test` and dev runs still work (this is the test ingress, per step 21's debt note). The RTSP server and camera (7550) listener run on both.
    #[cfg(windows)]
    let protect_stop = {
        let cert_path = config.cert_path.as_ref().map(std::path::PathBuf::from).unwrap_or_else(|| exe_dir.join(DEFAULT_CERT_FILE));
        let pfx = match std::fs::read(&cert_path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("flvproxy: cannot read cert {}: {e}", cert_path.display());
                eprintln!("generate a self-signed PFX with openssl and place it beside the exe, or set cert_path / cert_password in flvproxy.ini");
                return 1;
            }
        };
        let password = config.cert_password.as_deref().filter(|p| !p.is_empty());
        let acceptor = match TlsAcceptor::from_pfx(&pfx, password) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("flvproxy: failed to load TLS cert from {}: {e}", cert_path.display());
                return 1;
            }
        };
        let protect = ProtectListener::new(PROTECT_AVCLIENT_PORT, server_ip.clone(), acceptor, logger.clone());
        let stop = protect.shutdown_signal();
        let protect_logger = logger.clone();
        thread::spawn(move || {
            if let Err(e) = protect.run() {
                protect_logger.log(Level::Error, &format!("protect listener failed: {e}"));
            }
        });
        Some(stop)
    };

    let cam = CameraListener::new(state.clone(), config.listen_port, logger.clone());
    let cam_stop = cam.shutdown_signal();
    let cam_logger = logger.clone();
    thread::spawn(move || {
        if let Err(e) = cam.run() {
            cam_logger.log(Level::Error, &format!("camera listener failed: {e}"));
        }
    });

    let server = RtspServer::with_logger(state.clone(), config.rtsp_port, server_ip.clone(), logger.clone());
    let server_stop = server.shutdown_signal();
    let rtsp_logger = logger.clone();
    thread::spawn(move || {
        if let Err(e) = server.run() {
            rtsp_logger.log(Level::Error, &format!("rtsp server failed: {e}"));
        }
    });

    let onvif_cfg = OnvifConfig::defaults_for(server_ip.clone(), config.rtsp_port, config.onvif_port);
    let onvif = OnvifServer::with_logger(onvif_cfg, state.clone(), logger.clone());
    let onvif_stop = onvif.shutdown_signal();
    let onvif_logger = logger.clone();
    thread::spawn(move || {
        if let Err(e) = onvif.run() {
            onvif_logger.log(Level::Error, &format!("onvif server failed: {e}"));
        }
    });

    // WS-Discovery is gated by the `onvif_discovery` config flag (step 01). When disabled the multicast recv loop is not started, so an operator running multiple proxies on one host (or one with no multicast route) can suppress the UDP 3702 listener. The device-service XAddr advertised in ProbeMatch/Hello points at the same ONVIF HTTP server spawned above. The multicast interface is pinned to the advertised `server_ip`'s NIC so the group membership and `Hello`/`ProbeMatch` egress land on the camera/NVR subnet rather than the OS default-route NIC (which on a multi-homed host is often a different interface).
    let discovery_stop = if config.onvif_discovery {
        let xaddr = format!("http://{ip}:{port}{path}", ip = server_ip.clone(), port = config.onvif_port, path = DEFAULT_DEVICE_SERVICE_PATH);
        let discovery = match server_ip.parse::<std::net::Ipv4Addr>() {
            Ok(iface) => Discovery::with_logger(DiscoveryConfig::with_iface(xaddr, iface), logger.clone()),
            Err(_) => {
                logger.log(Level::Warn, &format!("wsdiscovery: server_ip '{server_ip}' is not a literal IPv4; falling back to OS-default multicast interface"));
                Discovery::with_logger(DiscoveryConfig::new(xaddr), logger.clone())
            }
        };
        let stop = discovery.shutdown_signal();
        let discovery_logger = logger.clone();
        thread::spawn(move || {
            if let Err(e) = discovery.run() {
                discovery_logger.log(Level::Error, &format!("wsdiscovery failed: {e}"));
            }
        });
        Some(stop)
    } else {
        logger.log(Level::Info, "wsdiscovery: disabled by onvif_discovery=false");
        None
    };

    // One startup log line per endpoint (camera ingress, RTSP, ONVIF HTTP, WS-Discovery) plus the advertised IP, so an operator tailing `flvproxy.log` can scan the per-line status of each server. The camera ingress differs by platform: Windows runs the Protect 7442/7550 listener, Linux/non-Windows runs the plain-TCP `CameraListener` on `listen_port`.
    #[cfg(windows)]
    logger.log(Level::Info, "listening camera: 7550=upflv + 7442=avclient");
    #[cfg(not(windows))]
    logger.log(Level::Info, &format!("listening camera=:{} (plain tcp)", config.listen_port));
    logger.log(Level::Info, &format!("listening rtsp=rtsp://{ip}:{port}/stream", ip = server_ip, port = config.rtsp_port));
    logger.log(Level::Info, &format!("listening onvif=http://{ip}:{port}/onvif/device_service (+ /onvif/media_service)", ip = server_ip, port = config.onvif_port));
    logger.log(Level::Info, &format!("wsdiscovery={} (udp 239.255.255.250:3702)", if config.onvif_discovery { "on" } else { "off" }));
    logger.log(Level::Info, &format!("advertised ip={ip}", ip = server_ip));

    console_shutdown::install();
    while !CONSOLE_SHUTDOWN.load(RELAXED) {
        thread::park_timeout(Duration::from_millis(CONSOLE_SHUTDOWN_POLL_MS));
    }
    cam_stop.store(true, RELAXED);
    server_stop.store(true, RELAXED);
    onvif_stop.store(true, RELAXED);
    if let Some(stop) = discovery_stop {
        stop.store(true, RELAXED);
    }
    #[cfg(windows)]
    {
        if let Some(stop) = protect_stop {
            stop.store(true, RELAXED);
        }
    }
    0
}

/// Best-effort, zero-crates Ctrl+C → `CONSOLE_SHUTDOWN` wiring. Unix installs a `SIGINT` handler via the libc `signal` FFI; Windows registers a console control handler via `SetConsoleCtrlHandler` (kernel32). Both are best-effort: a failure leaves the OS default (terminate the process), so the operator's Ctrl+C still ends the process — only graceful per-thread shutdown is lost. The logic tests never exercise this (it is binary-only console behavior); the windows branch is `#[cfg(windows)]`-gated so the Linux build host compiles cleanly.
#[cfg(unix)]
mod console_shutdown {
    /// POSIX signal number for interactive interrupt (SIGINT), per `<signal.h>`. Installing a handler intercepts Ctrl+C instead of the default terminate action.
    const SIGINT: i32 = 2;

    /// SIGINT handler: flips `CONSOLE_SHUTDOWN`. Does no I/O and touches only async-signal-safe state (one `AtomicBool` store), matching the POSIX signal-safety constraint.
    extern "C" fn on_sigint(_sig: i32) {
        super::CONSOLE_SHUTDOWN.store(true, super::RELAXED);
    }

    type SigHandler = extern "C" fn(i32);

    extern "C" {
        /// libc `signal`: install `handler` for `signum`, returning the prior handler. The return value is ignored — best-effort installation.
        fn signal(signum: i32, handler: SigHandler) -> SigHandler;
    }

    pub fn install() {
        // SAFETY: `signal` is async-signal-safe to call at startup; the handler does only an `AtomicBool` store. Failure keeps the default terminate behavior, which still ends the process on Ctrl+C.
        unsafe {
            let _ = signal(SIGINT, on_sigint);
        }
    }
}

#[cfg(windows)]
mod console_shutdown {
    /// `CTRL_C_EVENT` control type passed by the console to the handler, per the Windows Console API (`SetConsoleCtrlHandler`).
    const CTRL_C_EVENT: u32 = 0;

    /// Console control handler: returns `TRUE` for Ctrl+C after flipping `CONSOLE_SHUTDOWN`, suppressing the default terminate action so the main thread can shut the servers down cleanly; returns `FALSE` for other events so they fall through to the next handler / default.
    unsafe extern "system" fn on_console_ctrl(ctrl: u32) -> i32 {
        if ctrl == CTRL_C_EVENT {
            super::CONSOLE_SHUTDOWN.store(true, super::RELAXED);
            1
        } else {
            0
        }
    }

    extern "system" {
        /// kernel32 `SetConsoleCtrlHandler`: register a console control handler (`add` = 1 to add). The return is ignored — best-effort.
        fn SetConsoleCtrlHandler(handler: Option<unsafe extern "system" fn(u32) -> i32>, add: i32) -> i32;
    }

    pub fn install() {
        // SAFETY: registering a handler is safe at startup; the handler does only an `AtomicBool` store. Failure leaves the default terminate behavior, which still ends the process on Ctrl+C.
        unsafe {
            let _ = SetConsoleCtrlHandler(Some(on_console_ctrl), 1);
        }
    }
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
