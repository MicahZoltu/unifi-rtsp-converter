//! Application orchestration shared by the `main.rs` entry point (no-arg console path) and the Windows Service entry point (`service::run_as_service`): config/logger bootstrap, the spawn-everything / shutdown-everything pair, and the CLI dispatch decision. The two entry points differ only in *what triggers shutdown* (Ctrl+C vs the SCM stop event) — what they spawn is identical, so it lives here once rather than being duplicated between the binary and the service module.

use std::net::TcpListener;
#[cfg(windows)]
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

#[cfg(windows)]
use std::io;

use crate::camera_listener::CameraListener;
use crate::config::Config;
use crate::logging::{Level, Logger};
use crate::onvif_discovery::{Discovery, DiscoveryConfig};
use crate::onvif_server::{OnvifConfig, OnvifServer, DEFAULT_DEVICE_SERVICE_PATH};
use crate::rtsp_server::RtspServer;
use crate::stream_state::StreamState;

#[cfg(windows)]
use crate::config::DEFAULT_CERT_FILE;
#[cfg(windows)]
use crate::protect_listener::{ProtectListener, PROTECT_AVCLIENT_PORT};
#[cfg(windows)]
use crate::tls_schannel::TlsAcceptor;

/// Relaxed ordering suffices for the per-server shutdown flags: they are advisory signals, not synchronization that establishes happens-before for other data (each server's internal `Arc<Mutex<…>>` state carries that burden). Mirrors the server modules.
const RELAXED: Ordering = Ordering::Relaxed;

/// Per-worker upper bound for `ServerStops::join_with_timeout` when shutting down. Each accept loop polls its shutdown flag every ~50ms, so a healthy worker exits well inside this bound; a worker that overshoots is detached (its thread keeps running but the process is leaving anyway). Public so the console entry point (`main.rs`) passes the same budget the service path uses.
pub const JOIN_TIMEOUT_SECS: u64 = 5;

/// Poll granularity for the no-crates join-timeout helper. `JoinHandle::is_finished` is polled at this cadence until the worker exits or the per-handle deadline elapses.
const JOIN_POLL_MS: u64 = 25;

/// Process exit code returned for every successful entry-path run (the console path completes, the service dispatcher returns, `--install`/`--uninstall` succeed). Mirrors `EXIT_SUCCESS` from `<stdlib.h>`.
pub const EXIT_OK: i32 = 0;

/// Process exit code returned for a generic entry-path failure (unknown argument, FFI call failed, bootstrap error in the console path). Mirrors `EXIT_FAILURE` from `<stdlib.h>`.
pub const EXIT_FAILURE: i32 = 1;

/// Process exit code returned when `service::run_as_service` / `install` / `uninstall` is invoked on a non-Windows target. Distinct from `EXIT_FAILURE` so a caller (or CI) can tell "wrong platform" apart from "the operation ran and failed" — the SCM/install/uninstall FFI does not exist on Linux, so the branch must not attempt any of it.
pub const EXIT_WINDOWS_ONLY: i32 = 2;

/// Which entry path `main` should run, decided purely from the first command-line argument. Separating the decision from the execution lets the dispatcher be unit-tested on Linux without spawning servers or touching Windows FFI.
#[derive(Debug, Eq, PartialEq)]
pub enum Dispatch {
    /// No argument (or a bare invocation): run the camera/RTSP/ONVIF servers in the foreground, blocking on Ctrl+C. This is the default so double-clicking the exe or running it bare runs the proxy and surfaces the `--install` hint; the SCM-launched service path uses the explicit `--service` flag instead.
    Console,
    /// `--service`: the process was launched by the SCM (or an operator reproducing that). Runs under the service control dispatcher.
    Service,
    /// `--install`: register the service with the SCM.
    Install,
    /// `--uninstall`: stop (if running) and delete the service.
    Uninstall,
    /// An unrecognized argument; the caller prints usage and returns `EXIT_FAILURE`.
    Unknown(String),
}

/// Maps the command-line arguments to the entry path. No argument selects `Console` (the default foreground path — double-clicking the exe or running it bare runs the proxy and prints the `--install` hint); `--service` is the SCM-launched service path, wired into the service's registered bin path so the SCM passes it; `--install`/`--uninstall` manage the SCM registration. Anything else is an error.
pub fn parse_dispatch(args: &[String]) -> Dispatch {
    match args.first().map(String::as_str) {
        None => Dispatch::Console,
        Some("--service") => Dispatch::Service,
        Some("--install") => Dispatch::Install,
        Some("--uninstall") => Dispatch::Uninstall,
        Some(other) => Dispatch::Unknown(other.to_string()),
    }
}

/// Fallible startup outcome of `App::bootstrap`. The logger-open failure has no logger to report through, so the entry point surfaces it via stderr (console path) or the SCM stop status (service); the Windows cert failures are logged by `bootstrap` itself (the logger is open by then) before being returned.
#[derive(Debug)]
pub enum BootstrapError {
    /// `Logger::open` / `Logger::open_console` failed — the log file beside the exe could not be created or truncated.
    LoggerOpen { path: PathBuf, source: std::io::Error },
    /// Reading the configured PFX cert file failed (Windows only).
    #[cfg(windows)]
    CertRead { path: PathBuf, source: std::io::Error },
    /// `TlsAcceptor::from_pfx` failed to build a server credential from the PFX (Windows only).
    #[cfg(windows)]
    CertLoad { path: PathBuf, source: std::io::Error },
}

impl std::fmt::Display for BootstrapError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::LoggerOpen { path, source } => write!(f, "cannot open log {}: {source}", path.display()),
            #[cfg(windows)]
            Self::CertRead { path, source } => write!(f, "cannot read cert {}: {source}; run `flvproxy --install` to auto-generate a self-signed PFX, or supply one via cert_path / cert_password in flvproxy.ini", path.display()),
            #[cfg(windows)]
            Self::CertLoad { path, source } => write!(f, "failed to load TLS cert from {}: {source}", path.display()),
        }
    }
}

/// The bootstrapped application: parsed config, open logger, shared stream state, advertised server IP, and (on Windows) the 7442 Protect TLS acceptor. `spawn` consumes nothing — it hands clones to each server thread — so the entry point may keep logging through `logger()` after spawning (the service path logs its running/stopping transitions this way).
pub struct App {
    config: Config,
    logger: Arc<Logger>,
    state: StreamState,
    server_ip: String,
    #[cfg(windows)]
    tls_acceptor: TlsAcceptor,
}

impl App {
    /// Loads `flvproxy.ini` from the executable's directory, opens `flvproxy.log` beside it (teed to stdout when `tee_stdout`, i.e. the console path), constructs the shared `StreamState`, resolves the advertised server IP, and (on Windows) builds the 7442 Protect TLS acceptor from the configured PFX. The cert load is a fallible startup step that belongs here rather than in `spawn` so a service-mode failure is reported before `SERVICE_RUNNING`.
    pub fn bootstrap(tee_stdout: bool) -> Result<App, BootstrapError> {
        let exe_dir = std::env::current_exe().ok().and_then(|p| p.parent().map(PathBuf::from)).unwrap_or_else(|| PathBuf::from("."));
        let config = Config::load_or_default(&exe_dir.join("flvproxy.ini"));
        let log_path = exe_dir.join("flvproxy.log");
        let logger = Arc::new(match if tee_stdout { Logger::open_console(&log_path) } else { Logger::open(&log_path) } {
            Ok(l) => l,
            Err(source) => return Err(BootstrapError::LoggerOpen { path: log_path, source }),
        });
        let state = StreamState::new();
        let server_ip = config.advertised_server_ip();
        #[cfg(windows)]
        let tls_acceptor = {
            let cert_path = config.cert_path.as_ref().map(PathBuf::from).unwrap_or_else(|| exe_dir.join(DEFAULT_CERT_FILE));
            let pfx = match std::fs::read(&cert_path) {
                Ok(b) => b,
                Err(source) => {
                    // Lazy self-signed PFX generation: when the configured PFX is absent (`NotFound`) and its parent directory is writable, generate one in place and re-read it so a console-mode run with no prior `--install` still starts. Any other read error, or a generation failure, falls through to the existing `CertRead` error. Windows-only — on Linux the 7442 Protect path is absent entirely so no cert is loaded.
                    if source.kind() == io::ErrorKind::NotFound && dir_is_writable(cert_path.parent().unwrap_or(Path::new("."))) {
                        match crate::cert_gen::generate_self_signed_pfx(&cert_path) {
                            Ok(()) => {
                                logger.log(Level::Info, &format!("generated self-signed PFX at {}", cert_path.display()));
                                match std::fs::read(&cert_path) {
                                    Ok(b) => b,
                                    Err(reread) => {
                                        logger.log(Level::Error, &format!("cannot read cert {} after generation: {reread}", cert_path.display()));
                                        return Err(BootstrapError::CertRead { path: cert_path, source: reread });
                                    }
                                }
                            }
                            Err(gen) => {
                                logger.log(Level::Error, &format!("cannot read cert {}: {source}; auto-generation failed: {gen}", cert_path.display()));
                                return Err(BootstrapError::CertRead { path: cert_path, source });
                            }
                        }
                    } else {
                        logger.log(Level::Error, &format!("cannot read cert {}: {source}", cert_path.display()));
                        return Err(BootstrapError::CertRead { path: cert_path, source });
                    }
                }
            };
            let password = config.cert_password.as_deref().filter(|p| !p.is_empty());
            match TlsAcceptor::from_pfx(&pfx, password) {
                Ok(a) => a,
                Err(source) => {
                    logger.log(Level::Error, &format!("failed to load TLS cert from {}: {source}", cert_path.display()));
                    return Err(BootstrapError::CertLoad { path: cert_path, source });
                }
            }
        };
        Ok(App {
            config,
            logger,
            state,
            server_ip,
            #[cfg(windows)]
            tls_acceptor,
        })
    }

    /// The open logger, so an entry point can log lifecycle transitions (service running/stopping) after `spawn`.
    pub fn logger(&self) -> &Arc<Logger> {
        &self.logger
    }

    /// Spawns the camera listener, RTSP server, ONVIF HTTP server, and (when enabled) WS-Discovery — each on its own thread with a clone of the shared logger — and logs one startup line per endpoint. On Windows the 7442 Protect AVClient TLS listener is spawned first so the camera adopts over 7442 and pushes bare FLV over 7550; on Linux the plain-TCP `CameraListener` runs (the test ingress). Returns the collected per-server shutdown flags so a single `ServerStops::shutdown` stops every accept loop.
    pub fn spawn(&self) -> ServerStops {
        let mut stops: Vec<Arc<AtomicBool>> = Vec::new();
        let mut handles: Vec<JoinHandle<()>> = Vec::new();

        #[cfg(windows)]
        {
            let protect = ProtectListener::new(PROTECT_AVCLIENT_PORT, self.server_ip.clone(), self.tls_acceptor.clone(), self.logger.clone()).with_controller_identity(self.config.controller_name.clone(), self.config.controller_uuid.clone(), self.config.controller_version.clone());
            let stop = protect.shutdown_signal();
            let logger = self.logger.clone();
            handles.push(thread::spawn(move || {
                if let Err(e) = protect.run() {
                    logger.log(Level::Error, &format!("protect listener failed: {e}"));
                }
            }));
            stops.push(stop);
        }

        let cam = CameraListener::new(self.state.clone(), self.config.listen_port, self.logger.clone());
        let cam_stop = cam.shutdown_signal();
        let cam_logger = self.logger.clone();
        handles.push(thread::spawn(move || {
            if let Err(e) = cam.run() {
                cam_logger.log(Level::Error, &format!("camera listener failed: {e}"));
            }
        }));
        stops.push(cam_stop);

        let server = RtspServer::with_logger(self.state.clone(), self.config.rtsp_port, self.server_ip.clone(), self.logger.clone());
        let server_stop = server.shutdown_signal();
        let rtsp_logger = self.logger.clone();
        handles.push(thread::spawn(move || {
            if let Err(e) = server.run() {
                rtsp_logger.log(Level::Error, &format!("rtsp server failed: {e}"));
            }
        }));
        stops.push(server_stop);

        // The ONVIF HTTP listener is bound eagerly here (not inside the server thread) so the actually-bound port is known before the WS-Discovery XAddr and the startup log line are built. When `onvif_port` is unset the bind port is 0, so the OS picks a free ephemeral port and `local_addr` reports it — the proxy never collides with a host service holding a fixed port. On bind failure the ONVIF server and WS-Discovery are both skipped: discovery advertises the ONVIF XAddr, so running it without a bound HTTP endpoint would point NVRs at a dead URL.
        let onvif_requested = self.config.onvif_bind_port();
        let onvif_actual: Option<u16> = match TcpListener::bind(("0.0.0.0", onvif_requested)) {
            Ok(listener) => {
                let port = listener.local_addr().map(|a| a.port()).unwrap_or(onvif_requested);
                let onvif_cfg = OnvifConfig { firmware: self.config.firmware.clone(), serial: self.config.serial.clone(), ..OnvifConfig::defaults_for(self.server_ip.clone(), self.config.rtsp_port, port) };
                let onvif = OnvifServer::with_logger(onvif_cfg, self.state.clone(), self.logger.clone());
                let onvif_stop = onvif.shutdown_signal();
                let onvif_logger = self.logger.clone();
                handles.push(thread::spawn(move || {
                    if let Err(e) = onvif.run_on(listener) {
                        onvif_logger.log(Level::Error, &format!("onvif server failed: {e}"));
                    }
                }));
                stops.push(onvif_stop);
                Some(port)
            }
            Err(e) => {
                self.logger.log(Level::Error, &format!("onvif server failed: {e}"));
                None
            }
        };

        let discovery_stop = if self.config.onvif_discovery {
            match onvif_actual {
                Some(port) => {
                    let xaddr = format!("http://{ip}:{port}{path}", ip = self.server_ip, port = port, path = DEFAULT_DEVICE_SERVICE_PATH);
                    let discovery = match self.server_ip.parse::<std::net::Ipv4Addr>() {
                        Ok(iface) => Discovery::with_logger(DiscoveryConfig::with_iface(xaddr, iface), self.logger.clone()),
                        Err(_) => {
                            self.logger.log(Level::Warn, &format!("wsdiscovery: server_ip '{}' is not a literal IPv4; falling back to OS-default multicast interface", self.server_ip));
                            Discovery::with_logger(DiscoveryConfig::new(xaddr), self.logger.clone())
                        }
                    };
                    let stop = discovery.shutdown_signal();
                    let discovery_logger = self.logger.clone();
                    handles.push(thread::spawn(move || {
                        if let Err(e) = discovery.run() {
                            discovery_logger.log(Level::Error, &format!("wsdiscovery failed: {e}"));
                        }
                    }));
                    Some(stop)
                }
                None => {
                    self.logger.log(Level::Warn, "wsdiscovery: disabled because the ONVIF HTTP server failed to bind (no port to advertise)");
                    None
                }
            }
        } else {
            self.logger.log(Level::Info, "wsdiscovery: disabled by onvif_discovery=false");
            None
        };
        stops.extend(discovery_stop);

        #[cfg(windows)]
        self.logger.log(Level::Info, "listening camera: 7550=upflv + 7442=avclient");
        #[cfg(not(windows))]
        self.logger.log(Level::Info, &format!("listening camera=:{} (plain tcp)", self.config.listen_port));
        self.logger.log(Level::Info, &format!("listening rtsp=rtsp://{ip}:{port}/stream", ip = self.server_ip, port = self.config.rtsp_port));
        match onvif_actual {
            Some(port) => self.logger.log(Level::Info, &format!("listening onvif=http://{ip}:{port}/onvif/device_service (+ /onvif/media_service)", ip = self.server_ip, port = port)),
            None => self.logger.log(Level::Info, "listening onvif=disabled (bind failed)"),
        }
        self.logger.log(Level::Info, &format!("wsdiscovery={} (udp 239.255.255.250:3702)", if self.config.onvif_discovery { "on" } else { "off" }));
        self.logger.log(Level::Info, &format!("advertised ip={ip}", ip = self.server_ip));

        ServerStops { stops, handles }
    }
}

/// Per-server shutdown flags and worker `JoinHandle`s collected by `App::spawn`. `shutdown` flips every flag so each accept loop exits on its next poll; `join_with_timeout` then waits for every worker to actually return, bounding process exit. The order of flags vs handles does not matter — the flags are independent advisory signals and each handle is joined with its own timeout budget.
pub struct ServerStops {
    stops: Vec<Arc<AtomicBool>>,
    handles: Vec<JoinHandle<()>>,
}

impl ServerStops {
    /// Signals every spawned server to stop. Idempotent — storing `true` into an already-`true` flag is a no-op, so calling this from both the shutdown path and `Drop` is safe.
    pub fn shutdown(&self) {
        for stop in &self.stops {
            stop.store(true, RELAXED);
        }
    }

    /// Waits for every spawned worker to return, bounding each join to `per_handle`. A worker that has not returned by its deadline is detached (its `JoinHandle` is dropped, so the thread continues but the process is leaving anyway). Implemented with a poll loop on `JoinHandle::is_finished` — no crate dependency.
    pub fn join_with_timeout(&mut self, per_handle: Duration) {
        for handle in self.handles.drain(..) {
            join_handle_with_timeout(handle, per_handle);
        }
    }
}

impl Drop for ServerStops {
    fn drop(&mut self) {
        // Best-effort: ensure the shutdown flags flip even if the owner forgot to call `shutdown` (e.g. a panic between spawn and the explicit shutdown). Idempotent with `shutdown`. Handles are not joined here — `drop` must not block.
        for stop in &self.stops {
            stop.store(true, RELAXED);
        }
    }
}

/// Joins `handle`, polling `is_finished` at `JOIN_POLL_MS` until it returns or `timeout` elapses, then detaches the handle. The standard no-crates join-with-timeout pattern: `JoinHandle::join` blocks with no timeout, so the only way to bound the wait is to poll for completion and drop the handle when the deadline passes.
fn join_handle_with_timeout(handle: JoinHandle<()>, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if handle.is_finished() {
            break;
        }
        thread::sleep(Duration::from_millis(JOIN_POLL_MS));
    }
    // If finished, `join` reaps the thread (and surfaces any panic); if not, dropping the handle detaches the thread so the process can continue exiting.
    if handle.is_finished() {
        let _ = handle.join();
    }
}

/// Returns `true` if a file can be created (and removed) in `dir`, used by the lazy-cert-generation path in `bootstrap` to decide whether auto-generating a PFX beside the exe is even possible before attempting it. Windows-only because that is the only caller; pure std so it is trivially correct, but gating avoids a dead-code warning on the Linux build host.
#[cfg(windows)]
fn dir_is_writable(dir: &Path) -> bool {
    let probe = dir.join(format!(".flvprobe_{}", std::process::id()));
    let ok = std::fs::File::create(&probe).is_ok();
    let _ = std::fs::remove_file(&probe);
    ok
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(x: &str) -> String {
        x.to_string()
    }

    #[test]
    fn parse_dispatch_no_args_selects_console() {
        assert_eq!(parse_dispatch(&[]), Dispatch::Console);
    }

    #[test]
    fn parse_dispatch_service_flag_selects_service() {
        assert_eq!(parse_dispatch(&[s("--service")]), Dispatch::Service);
    }

    #[test]
    fn parse_dispatch_install_flag_selects_install() {
        assert_eq!(parse_dispatch(&[s("--install")]), Dispatch::Install);
    }

    #[test]
    fn parse_dispatch_uninstall_flag_selects_uninstall() {
        assert_eq!(parse_dispatch(&[s("--uninstall")]), Dispatch::Uninstall);
    }

    #[test]
    fn parse_dispatch_unknown_flag_is_unknown() {
        assert_eq!(parse_dispatch(&[s("--frobnicate")]), Dispatch::Unknown("--frobnicate".to_string()));
    }

    #[test]
    fn parse_dispatch_ignores_extra_args_beyond_first() {
        // Only the first argument selects the dispatch branch; trailing args (e.g. a stray second token) are ignored by the dispatcher. The executor receives no arguments beyond the branch choice.
        assert_eq!(parse_dispatch(&[s("--service"), s("noise")]), Dispatch::Service);
    }

    #[test]
    fn join_with_timeout_reaps_a_promptly_returning_worker() {
        // A worker that exits immediately must be reaped well inside the budget; the helper returns (rather than panicking) once the handle is joined.
        let handle = thread::spawn(|| {});
        join_handle_with_timeout(handle, Duration::from_secs(2));
    }

    #[test]
    fn join_with_timeout_detaches_an_overrunning_worker_without_blocking() {
        // A worker that sleeps past the budget must NOT cause the helper to block: the handle is detached and the helper returns within the deadline. The worker thread continues to completion on its own.
        let handle = thread::spawn(|| {
            thread::sleep(Duration::from_secs(10));
        });
        let start = Instant::now();
        join_handle_with_timeout(handle, Duration::from_millis(200));
        assert!(start.elapsed() < Duration::from_secs(2), "join_with_timeout must not block past the deadline for an overrunning worker");
    }
}
