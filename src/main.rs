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
use flvproxy::onvif_server::{OnvifConfig, OnvifServer};
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
        thread::spawn(move || {
            if let Err(e) = protect.run() {
                eprintln!("flvproxy: protect listener failed: {e}");
            }
        });
        Some(stop)
    };

    #[cfg(windows)]
    logger.log(Level::Info, &format!("listening 7442=avclient 7550=upflv rtsp=:{} onvif=:{} ip={}", config.rtsp_port, config.onvif_port, server_ip));
    #[cfg(not(windows))]
    logger.log(Level::Info, &format!("listening camera=:{} rtsp=:{} onvif=:{} ip={}", config.listen_port, config.rtsp_port, config.onvif_port, server_ip));

    let cam = CameraListener::new(state.clone(), config.listen_port, logger.clone());
    let cam_stop = cam.shutdown_signal();
    thread::spawn(move || {
        if let Err(e) = cam.run() {
            eprintln!("flvproxy: camera listener failed: {e}");
        }
    });

    let server = RtspServer::new(state.clone(), config.rtsp_port, server_ip.clone());
    let server_stop = server.shutdown_signal();
    thread::spawn(move || {
        if let Err(e) = server.run() {
            eprintln!("flvproxy: rtsp server failed: {e}");
        }
    });

    let onvif_cfg = OnvifConfig::defaults_for(server_ip.clone(), config.rtsp_port, config.onvif_port);
    let onvif = OnvifServer::new(onvif_cfg, state.clone());
    let onvif_stop = onvif.shutdown_signal();
    thread::spawn(move || {
        if let Err(e) = onvif.run() {
            eprintln!("flvproxy: onvif server failed: {e}");
        }
    });

    console_shutdown::install();
    while !CONSOLE_SHUTDOWN.load(RELAXED) {
        thread::park_timeout(Duration::from_millis(CONSOLE_SHUTDOWN_POLL_MS));
    }
    cam_stop.store(true, RELAXED);
    server_stop.store(true, RELAXED);
    onvif_stop.store(true, RELAXED);
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
