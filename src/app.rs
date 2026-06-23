//! Application orchestration shared by the `--console` entry point (`main.rs`) and the Windows Service entry point (`service::run_as_service`): config/logger bootstrap, the spawn-everything / shutdown-everything pair, and the CLI dispatch decision. The two entry points differ only in *what triggers shutdown* (Ctrl+C vs the SCM stop event) — what they spawn is identical, so it lives here once rather than being duplicated between the binary and the service module.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

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

/// Process exit code returned for every successful entry-path run (`--console` completes, the service dispatcher returns, `--install`/`--uninstall` succeed). Mirrors `EXIT_SUCCESS` from `<stdlib.h>`.
pub const EXIT_OK: i32 = 0;

/// Process exit code returned for a generic entry-path failure (unknown argument, FFI call failed, bootstrap error in `--console`). Mirrors `EXIT_FAILURE` from `<stdlib.h>`.
pub const EXIT_FAILURE: i32 = 1;

/// Process exit code returned when `service::run_as_service` / `install` / `uninstall` is invoked on a non-Windows target. Distinct from `EXIT_FAILURE` so a caller (or CI) can tell "wrong platform" apart from "the operation ran and failed" — the SCM/install/uninstall FFI does not exist on Linux, so the branch must not attempt any of it.
pub const EXIT_WINDOWS_ONLY: i32 = 2;

/// Which entry path `main` should run, decided purely from the first command-line argument. Separating the decision from the execution lets the dispatcher be unit-tested on Linux without spawning servers or touching Windows FFI.
#[derive(Debug, Eq, PartialEq)]
pub enum Dispatch {
    /// `--console`: run the camera/RTSP/ONVIF servers in the foreground, blocking on Ctrl+C.
    Console,
    /// No argument: the process was launched by the SCM (services start with no args). Runs under the service control dispatcher.
    Service,
    /// `--install`: register the service with the SCM.
    Install,
    /// `--uninstall`: stop (if running) and delete the service.
    Uninstall,
    /// An unrecognized argument; the caller prints usage and returns `EXIT_FAILURE`.
    Unknown(String),
}

/// Maps the command-line arguments to the entry path. SCM launches the service with no arguments, so the absence of any argument selects `Service`; `--console` is the operator's foreground/dev path; `--install`/`--uninstall` manage the SCM registration. Anything else is an error.
pub fn parse_dispatch(args: &[String]) -> Dispatch {
    match args.first().map(String::as_str) {
        None => Dispatch::Service,
        Some("--console") => Dispatch::Console,
        Some("--install") => Dispatch::Install,
        Some("--uninstall") => Dispatch::Uninstall,
        Some(other) => Dispatch::Unknown(other.to_string()),
    }
}

/// Fallible startup outcome of `App::bootstrap`. The logger-open failure has no logger to report through, so the entry point surfaces it via stderr (`--console`) or the SCM stop status (service); the Windows cert failures are logged by `bootstrap` itself (the logger is open by then) before being returned.
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
            Self::CertRead { path, source } => write!(f, "cannot read cert {}: {source}; generate a self-signed PFX with openssl and place it beside the exe, or set cert_path / cert_password in flvproxy.ini", path.display()),
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
    /// Loads `flvproxy.ini` from the executable's directory, opens `flvproxy.log` beside it (teed to stdout when `tee_stdout`, i.e. `--console`), constructs the shared `StreamState`, resolves the advertised server IP, and (on Windows) builds the 7442 Protect TLS acceptor from the configured PFX. The cert load is a fallible startup step that belongs here rather than in `spawn` so a service-mode failure is reported before `SERVICE_RUNNING`.
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
                    logger.log(Level::Error, &format!("cannot read cert {}: {source}", cert_path.display()));
                    return Err(BootstrapError::CertRead { path: cert_path, source });
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

        #[cfg(windows)]
        {
            let protect = ProtectListener::new(PROTECT_AVCLIENT_PORT, self.server_ip.clone(), self.tls_acceptor.clone(), self.logger.clone()).with_controller_identity(self.config.controller_name.clone(), self.config.controller_uuid.clone(), self.config.controller_version.clone());
            let stop = protect.shutdown_signal();
            let logger = self.logger.clone();
            thread::spawn(move || {
                if let Err(e) = protect.run() {
                    logger.log(Level::Error, &format!("protect listener failed: {e}"));
                }
            });
            stops.push(stop);
        }

        let cam = CameraListener::new(self.state.clone(), self.config.listen_port, self.logger.clone());
        let cam_stop = cam.shutdown_signal();
        let cam_logger = self.logger.clone();
        thread::spawn(move || {
            if let Err(e) = cam.run() {
                cam_logger.log(Level::Error, &format!("camera listener failed: {e}"));
            }
        });
        stops.push(cam_stop);

        let server = RtspServer::with_logger(self.state.clone(), self.config.rtsp_port, self.server_ip.clone(), self.logger.clone());
        let server_stop = server.shutdown_signal();
        let rtsp_logger = self.logger.clone();
        thread::spawn(move || {
            if let Err(e) = server.run() {
                rtsp_logger.log(Level::Error, &format!("rtsp server failed: {e}"));
            }
        });
        stops.push(server_stop);

        let onvif_cfg = OnvifConfig::defaults_for(self.server_ip.clone(), self.config.rtsp_port, self.config.onvif_port);
        let onvif = OnvifServer::with_logger(onvif_cfg, self.state.clone(), self.logger.clone());
        let onvif_stop = onvif.shutdown_signal();
        let onvif_logger = self.logger.clone();
        thread::spawn(move || {
            if let Err(e) = onvif.run() {
                onvif_logger.log(Level::Error, &format!("onvif server failed: {e}"));
            }
        });
        stops.push(onvif_stop);

        let discovery_stop = if self.config.onvif_discovery {
            let xaddr = format!("http://{ip}:{port}{path}", ip = self.server_ip, port = self.config.onvif_port, path = DEFAULT_DEVICE_SERVICE_PATH);
            let discovery = match self.server_ip.parse::<std::net::Ipv4Addr>() {
                Ok(iface) => Discovery::with_logger(DiscoveryConfig::with_iface(xaddr, iface), self.logger.clone()),
                Err(_) => {
                    self.logger.log(Level::Warn, &format!("wsdiscovery: server_ip '{}' is not a literal IPv4; falling back to OS-default multicast interface", self.server_ip));
                    Discovery::with_logger(DiscoveryConfig::new(xaddr), self.logger.clone())
                }
            };
            let stop = discovery.shutdown_signal();
            let discovery_logger = self.logger.clone();
            thread::spawn(move || {
                if let Err(e) = discovery.run() {
                    discovery_logger.log(Level::Error, &format!("wsdiscovery failed: {e}"));
                }
            });
            Some(stop)
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
        self.logger.log(Level::Info, &format!("listening onvif=http://{ip}:{port}/onvif/device_service (+ /onvif/media_service)", ip = self.server_ip, port = self.config.onvif_port));
        self.logger.log(Level::Info, &format!("wsdiscovery={} (udp 239.255.255.250:3702)", if self.config.onvif_discovery { "on" } else { "off" }));
        self.logger.log(Level::Info, &format!("advertised ip={ip}", ip = self.server_ip));

        ServerStops { stops }
    }
}

/// Per-server shutdown flags collected by `App::spawn`. `shutdown` flips every one so each accept loop exits on its next poll; the order does not matter because the flags are independent advisory signals.
pub struct ServerStops {
    stops: Vec<Arc<AtomicBool>>,
}

impl ServerStops {
    /// Signals every spawned server to stop. Idempotent — storing `true` into an already-`true` flag is a no-op, so calling this from both the shutdown path and `Drop` is safe.
    pub fn shutdown(&self) {
        for stop in &self.stops {
            stop.store(true, RELAXED);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(x: &str) -> String {
        x.to_string()
    }

    #[test]
    fn parse_dispatch_no_args_selects_service() {
        assert_eq!(parse_dispatch(&[]), Dispatch::Service);
    }

    #[test]
    fn parse_dispatch_console_flag_selects_console() {
        assert_eq!(parse_dispatch(&[s("--console")]), Dispatch::Console);
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
        assert_eq!(parse_dispatch(&[s("--console"), s("noise")]), Dispatch::Console);
    }
}
