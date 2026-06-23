//! Command-line entry point. Dispatches on the first argument via `app::parse_dispatch`: `--console` runs the camera/RTSP/ONVIF servers in the foreground (blocking on Ctrl+C); no argument runs under the Windows Service Control Manager (`service::run_as_service`); `--install`/`--uninstall` manage the SCM registration. The dispatch decision lives in the library (`app`) so it is unit-testable on Linux without spawning servers.
//!
//! The logic modules live in the `flvproxy` library crate (`src/lib.rs`); the binary imports them as needed.

use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use flvproxy::app::{self, Dispatch, EXIT_FAILURE, EXIT_OK, JOIN_TIMEOUT_SECS};
use flvproxy::service;

/// Relaxed ordering suffices for the shutdown flag: it is an advisory signal, not synchronization that establishes happens-before for other data (the `StreamState` mutex carries that burden). Mirrors the server modules.
const RELAXED: Ordering = Ordering::Relaxed;

/// Main-thread sleep between polls of `CONSOLE_SHUTDOWN`. `park_timeout` is used instead of `park` so a missing Ctrl+C handler (FFI best-effort) still lets the loop re-check the flag rather than deadlocking.
const CONSOLE_SHUTDOWN_POLL_MS: u64 = 250;

/// Process-wide flag flipped by the installed Ctrl+C handler. The main thread polls it; on `true` it signals the spawned servers to stop and returns. A plain `AtomicBool` is safe to set from a signal / console control handler running on an arbitrary thread.
static CONSOLE_SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Foreground mode (`--console`): bootstraps config/logger/state, spawns every server via `App::spawn`, installs a Ctrl+C handler, then blocks until Ctrl+C flips `CONSOLE_SHUTDOWN`, shuts the servers down, and returns. This is the dev / test ingress; the Windows service path runs the same `App::bootstrap` + `App::spawn` body under the SCM (see `service::run_as_service`).
fn console_main() -> i32 {
    let app = match app::App::bootstrap(true) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("flvproxy: {e}");
            return EXIT_FAILURE;
        }
    };
    let mut stops = app.spawn();
    console_shutdown::install();
    while !CONSOLE_SHUTDOWN.load(RELAXED) {
        thread::park_timeout(Duration::from_millis(CONSOLE_SHUTDOWN_POLL_MS));
    }
    stops.shutdown();
    stops.join_with_timeout(Duration::from_secs(JOIN_TIMEOUT_SECS));
    EXIT_OK
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
    let code = match app::parse_dispatch(&args) {
        Dispatch::Console => console_main(),
        Dispatch::Service => service::run_as_service(),
        Dispatch::Install => service::install(),
        Dispatch::Uninstall => service::uninstall(),
        Dispatch::Unknown(arg) => {
            eprintln!("flvproxy: unknown argument '{arg}'");
            eprintln!("valid arguments: --install, --uninstall, --console");
            EXIT_FAILURE
        }
    };
    std::process::exit(code);
}
