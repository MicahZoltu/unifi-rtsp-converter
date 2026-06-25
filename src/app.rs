//! Application bootstrap: config/logger/cert load and the spawn-everything pair shared by the `main.rs` entry point (no-arg console path) and the Windows Service entry point (`service::run_as_service`). The two entry points differ only in *what triggers shutdown* (Ctrl+C vs the SCM stop event) — what they spawn is identical, so it lives here once rather than being duplicated between the binary and the service module. CLI dispatch and exit codes live in `cli`; the spawned-server join/shutdown machinery lives in `server_stops`.

use std::net::TcpListener;
#[cfg(windows)]
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

#[cfg(windows)]
use std::io;

use crate::camera_listener::CameraListener;
use crate::config::Config;
use crate::logging::{Level, Logger};
use crate::onvif_discovery::{Discovery, DiscoveryConfig};
use crate::onvif_server::{OnvifConfig, OnvifServer, DEFAULT_DEVICE_SERVICE_PATH};
use crate::rtsp_server::RtspServer;
use crate::server_stops::{ServerHandle, ServerStops};
use crate::stream_state::StreamState;

#[cfg(windows)]
use crate::config::DEFAULT_CERT_FILE;
#[cfg(windows)]
use crate::protect_listener::{ProtectListener, PROTECT_AVCLIENT_PORT};
#[cfg(windows)]
use crate::tls_schannel::TlsAcceptor;

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
        let mut handles: Vec<ServerHandle> = Vec::new();

        #[cfg(windows)]
        {
            let protect = ProtectListener::new(PROTECT_AVCLIENT_PORT, self.server_ip.clone(), self.tls_acceptor.clone(), self.logger.clone()).with_controller_identity(self.config.controller_name.clone(), self.config.controller_uuid.clone(), self.config.controller_version.clone());
            let stop = protect.shutdown_signal();
            let logger = self.logger.clone();
            let handle = thread::spawn(move || {
                if let Err(e) = protect.run() {
                    logger.log(Level::Error, &format!("protect listener failed: {e}"));
                }
            });
            handles.push(ServerHandle::new(stop, handle));
        }

        let cam = CameraListener::new(self.state.clone(), self.config.listen_port, self.logger.clone());
        let cam_stop = cam.shutdown_signal();
        let cam_logger = self.logger.clone();
        let cam_handle = thread::spawn(move || {
            if let Err(e) = cam.run() {
                cam_logger.log(Level::Error, &format!("camera listener failed: {e}"));
            }
        });
        handles.push(ServerHandle::new(cam_stop, cam_handle));

        let server = RtspServer::with_logger(self.state.clone(), self.config.rtsp_port, self.server_ip.clone(), self.logger.clone());
        let server_stop = server.shutdown_signal();
        let rtsp_logger = self.logger.clone();
        let rtsp_handle = thread::spawn(move || {
            if let Err(e) = server.run() {
                rtsp_logger.log(Level::Error, &format!("rtsp server failed: {e}"));
            }
        });
        handles.push(ServerHandle::new(server_stop, rtsp_handle));

        // The ONVIF HTTP listener is bound eagerly here (not inside the server thread) so the actually-bound port is known before the WS-Discovery XAddr and the startup log line are built. When `onvif_port` is unset the bind port is 0, so the OS picks a free ephemeral port and `local_addr` reports it — the proxy never collides with a host service holding a fixed port. On bind failure the ONVIF server and WS-Discovery are both skipped: discovery advertises the ONVIF XAddr, so running it without a bound HTTP endpoint would point NVRs at a dead URL.
        let onvif_requested = self.config.onvif_bind_port();
        let onvif_actual: Option<u16> = match TcpListener::bind(("0.0.0.0", onvif_requested)) {
            Ok(listener) => {
                let port = listener.local_addr().map(|a| a.port()).unwrap_or(onvif_requested);
                let onvif_cfg = OnvifConfig { firmware: self.config.firmware.clone(), serial: self.config.serial.clone(), ..OnvifConfig::defaults_for(self.server_ip.clone(), self.config.rtsp_port, port) };
                let onvif = OnvifServer::with_logger(onvif_cfg, self.state.clone(), self.logger.clone());
                let onvif_stop = onvif.shutdown_signal();
                let onvif_logger = self.logger.clone();
                let onvif_handle = thread::spawn(move || {
                    if let Err(e) = onvif.run_on(listener) {
                        onvif_logger.log(Level::Error, &format!("onvif server failed: {e}"));
                    }
                });
                handles.push(ServerHandle::new(onvif_stop, onvif_handle));
                Some(port)
            }
            Err(e) => {
                self.logger.log(Level::Error, &format!("onvif server failed: {e}"));
                None
            }
        };

        if self.config.onvif_discovery {
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
                    let handle = thread::spawn(move || {
                        if let Err(e) = discovery.run() {
                            discovery_logger.log(Level::Error, &format!("wsdiscovery failed: {e}"));
                        }
                    });
                    handles.push(ServerHandle::new(stop, handle));
                }
                None => self.logger.log(Level::Warn, "wsdiscovery: disabled because the ONVIF HTTP server failed to bind (no port to advertise)"),
            }
        } else {
            self.logger.log(Level::Info, "wsdiscovery: disabled by onvif_discovery=false");
        }

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

        ServerStops::new(handles)
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
