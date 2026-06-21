//! Implementation of the step-16 listen-only Protect recon capture tool.
//! See the parent binary's module doc for the operator-facing overview; this
//! module holds the Windows-only SChannel + minimal-RFC-6455 plumbing.
//!
//! TLS is provided by the hand-rolled `flvproxy::tls_schannel` module (step 17)
//! — not the throwaway `schannel` crate step 16 used. The raw-tap / WS-upgrade
//! / frame-capture logic is unchanged; only the TLS layer was swapped.
//!
//! Architecture: `run()` parses flags, loads the PFX, builds one shared
//! `TlsAcceptor` (clone-cheap, handed to every accepted connection), opens
//! the per-port capture logs, binds the 7442 (and optional 7550) listener,
//! and spawns one thread per listener. Each listener accepts inbound TLS
//! WebSocket connections and spawns a handler thread that completes the WS
//! upgrade best-effort and hex-dumps every inbound frame to stdout and the
//! port's capture file until the peer closes or the shutdown flag is set.
//! The main thread installs a Ctrl+C handler (the same `SetConsoleCtrlHandler`
//! pattern `src/main.rs` uses for `--console` mode) and polls the shutdown
//! flag, then signals every listener to stop.
//!
//! `--selftest` mode (step 17) bypasses the capture flow: it binds
//! `127.0.0.1:0`, accepts a single TLS connection, and echoes decrypted bytes
//! back so `tools/tls_selftest.ps1` can round-trip 1 B / 64 KiB / 1 MiB
//! buffers and a clean `close_notify` without needing the camera.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use flvproxy::protect_controller::AvClientSession;
use flvproxy::sdp::base64_encode;
use flvproxy::tls_schannel::{HandshakeError, TlsAcceptor, TlsStream};

/// Relaxed ordering suffices for the shutdown flag: it is an advisory signal,
/// not synchronization that establishes happens-before for other data. Mirrors
/// `camera_listener`/`rtsp_server`'s convention.
const RELAXED: Ordering = Ordering::Relaxed;

/// UniFi Protect AVClient handshake port (stage 3 of the 5-stage flow), per
/// `plan/16-protect-recon.md` → "Background". The recon tool always listens
/// here.
const PROTECT_AVCLIENT_PORT: u16 = 7442;

/// UniFi Protect uPFLV uplink port (stage 5), where the `UPFLV_PREFIX`-bearing
/// video stream lives. The recon tool listens here only when `--enable-7550`
/// is passed.
const PROTECT_UPFLV_PORT: u16 = 7550;

/// RFC 6455 §1.3 magic GUID appended to the client's `Sec-WebSocket-Key` before
/// SHA-1 hashing to derive the `Sec-WebSocket-Accept` value.
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// File name of the default self-signed PFX the tool loads, resolved beside
/// the exe. See the parent binary's "Cert generation" doc for how to produce
/// it.
const DEFAULT_CERT_FILE: &str = "protect_recon_cert.pfx";

/// Capture-log file name for the 7442 listener, written beside the exe.
const CAPTURE_FILE_7442: &str = "protect_recon_7442.log";

/// Capture-log file name for the 7550 listener, written beside the exe.
const CAPTURE_FILE_7550: &str = "protect_recon_7550.log";

/// Accept-loop poll interval (non-blocking `TcpListener`), so the shutdown
/// flag is checked promptly rather than blocking on the next connection.
/// Mirrors `camera_listener`'s `ACCEPT_POLL_MS`.
const ACCEPT_POLL_MS: u64 = 50;

/// Per-read timeout on an accepted (post-TLS) connection. The hand-rolled
/// `TlsStream` surfaces the underlying socket's `WSAEWOULDBLOCK`/timeout as
/// `WouldBlock`/`TimedOut`, which the capture loops tolerate (retrying) rather
/// than treating as fatal — see `CAPTURE_READ_DEADLINE_SECS` and
/// `RAW_RETRY_SLEEP_MS`.
const READ_TIMEOUT_MS: u64 = 1000;

/// Total deadline the raw-tap loop waits for the camera's **first** byte after
/// TLS completes. If nothing arrives in this window the connection is logged
/// `no data from camera within 30s` and closed — that outcome would mean the
/// controller must speak first, escalating the AVClient step's design. Once
/// the first byte arrives the deadline no longer applies; the tap keeps
/// reading until
/// the peer closes or shutdown is signalled.
const CAPTURE_READ_DEADLINE_SECS: u64 = 30;

/// Sleep between `WouldBlock`/`TimedOut` retries in the tolerant read loops.
/// Keeps the spin cheap while still polling well inside the
/// `CAPTURE_READ_DEADLINE_SECS` window and the per-read `READ_TIMEOUT_MS`.
const RAW_RETRY_SLEEP_MS: u64 = 20;

/// Scratch-buffer size for one raw-tap read. The recon tool hex-dumps each
/// chunk as it arrives, so this only bounds per-dump granularity, not the
/// total capture.
const RAW_READ_CHUNK_BYTES: usize = 4096;

/// Upper bound on a single WS frame payload we are willing to buffer. The
/// recon tool is best-effort: a frame claiming a larger length is logged and
/// the connection is dropped rather than risking a multi-GiB allocation from
/// a malformed/hostile peer.
const MAX_FRAME_PAYLOAD: usize = 16 * 1024 * 1024;

/// Cap on the buffered HTTP upgrade request (headers only — RFC 6455 §4.1
/// implementations must reject requests with absurdly long headers). 8 KiB
/// is well above any legitimate `Sec-WebSocket-*` header set.
const MAX_HANDSHAKE_HEADER_BYTES: usize = 8 * 1024;

/// RFC 6455 §5.2 opcode: continuation frame.
const OPCODE_CONTINUATION: u8 = 0x0;
/// RFC 6455 §5.2 opcode: text frame.
const OPCODE_TEXT: u8 = 0x1;
/// RFC 6455 §5.2 opcode: binary frame.
const OPCODE_BINARY: u8 = 0x2;
/// RFC 6455 §5.2 opcode: connection close.
const OPCODE_CLOSE: u8 = 0x8;
/// RFC 6455 §5.2 opcode: ping.
const OPCODE_PING: u8 = 0x9;
/// RFC 6455 §5.2 opcode: pong.
const OPCODE_PONG: u8 = 0xA;

/// Process-wide shutdown flag flipped by the Ctrl+C handler and polled by the
/// main thread, the accept loops, and each handler's read loop.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Camera 443 login username (set once at startup from `--camera-username`,
/// default `ubnt`). Read by `trigger_443_adoption` on the first unadopted
/// 7442 connection.
static CAMERA_USERNAME: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Camera 443 login password (set once at startup from `--camera-password`,
/// default `ubnt`). Read by `trigger_443_adoption` on the first unadopted
/// 7442 connection.
static CAMERA_PASSWORD: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// When true, the recon session is purely reactive (no 443 POST, no
/// paramAgreement/ChangeVideoSettings). Set from `--no-adopt` at startup.
static NO_ADOPT: AtomicBool = AtomicBool::new(false);

/// Parsed command-line configuration for the recon tool.
struct Config {
    /// Path to the PFX the tool loads as its TLS server identity.
    cert_path: PathBuf,
    /// Password decrypting the PFX (empty string = no password).
    password: String,
    /// Whether to also bind and capture on 7550 in addition to 7442.
    enable_7550: bool,
    /// Run the localhost TLS echo self-test (step 17) instead of the camera
    /// capture flow.
    selftest: bool,
    /// Disable the 443 adoption POST + 7442 paramAgreement/ChangeVideoSettings
    /// driver. The session becomes purely reactive (replies to timeSync only).
    /// Used to test whether the camera advances past TIME_SYNCING on its own.
    no_adopt: bool,
    /// Username for the camera's 443 `/api/1.2/login` adoption step.
    /// Defaults to `ubnt` (the UniFi factory default per redalert's discovery
    /// TLV `USERNAME = "ubnt"`). Override with `--camera-username`.
    camera_username: String,
    /// Password for the camera's 443 `/api/1.2/login` adoption step.
    /// Defaults to `ubnt`. Override with `--camera-password` when the camera
    /// has non-default credentials (the recon logs `401` if wrong).
    camera_password: String,
}

/// Entry point: parses flags, loads the cert, opens the capture logs, spawns
/// the listener(s), installs Ctrl+C, and blocks until shutdown. Returns the
/// process exit code.
pub fn run() -> i32 {
    let exe_dir = match std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(PathBuf::from))
    {
        Some(d) => d,
        None => {
            eprintln!("protect_recon: cannot locate own executable directory");
            return 1;
        }
    };
    let config = match parse_args(&exe_dir) {
        Ok(c) => c,
        Err(code) => return code,
    };

    let pfx = match std::fs::read(&config.cert_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!(
                "protect_recon: cannot read cert {}: {e}",
                config.cert_path.display()
            );
            eprintln!(
                "generate one with the openssl command in the tool's module doc, \
                 or pass --cert <path>"
            );
            return 1;
        }
    };
    let cred = match build_server_cred(&pfx, &config.password) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("protect_recon: failed to load server cert from PFX: {e}");
            return 1;
        }
    };

    if config.selftest {
        return run_selftest(cred);
    }

    // Publish camera 443 credentials for the adoption trigger (read on the
    // first unadopted 7442 connection). `OnceLock` makes them effectively
    // immutable for the rest of the process.
    let _ = CAMERA_USERNAME.set(config.camera_username.clone());
    let _ = CAMERA_PASSWORD.set(config.camera_password.clone());
    NO_ADOPT.store(config.no_adopt, RELAXED);

    let capture_7442 = match open_capture(&exe_dir.join(CAPTURE_FILE_7442)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("protect_recon: cannot open {CAPTURE_FILE_7442}: {e}");
            return 1;
        }
    };
    let capture_7550 = if config.enable_7550 {
        match open_capture(&exe_dir.join(CAPTURE_FILE_7550)) {
            Ok(c) => Some(c),
            Err(e) => {
                eprintln!("protect_recon: cannot open {CAPTURE_FILE_7550}: {e}");
                return 1;
            }
        }
    } else {
        None
    };

    println!(
        "protect_recon: listening on 0.0.0.0:{} (TLS WebSocket){} — Ctrl+C to stop",
        PROTECT_AVCLIENT_PORT,
        if config.enable_7550 {
            format!(" and 0.0.0.0:{}", PROTECT_UPFLV_PORT)
        } else {
            String::new()
        }
    );

    let mut handles = Vec::new();
    {
        let cred = cred.clone();
        let capture = capture_7442.clone();
        handles.push(thread::spawn(move || {
            listen(PROTECT_AVCLIENT_PORT, cred, capture);
        }));
    }
    if let Some(capture) = capture_7550.clone() {
        let cred = cred.clone();
        handles.push(thread::spawn(move || {
            listen(PROTECT_UPFLV_PORT, cred, capture);
        }));
    }

    install_ctrl_c();
    while !SHUTDOWN.load(RELAXED) {
        thread::park_timeout(Duration::from_millis(ACCEPT_POLL_MS));
    }
    for h in handles {
        let _ = h.join();
    }
    0
}

/// Parses `argv` into a `Config`. On error prints usage and returns the exit
/// code the caller should propagate. Recognized flags: `--cert <path>`,
/// `--password <pw>`, `--enable-7550`, `--selftest`, `--help`.
fn parse_args(exe_dir: &std::path::Path) -> Result<Config, i32> {
    let mut cert_path = exe_dir.join(DEFAULT_CERT_FILE);
    let mut password = String::new();
    let mut enable_7550 = false;
    let mut selftest = false;
    let mut camera_username = "ubnt".to_string();
    let mut camera_password = "ubnt".to_string();
    let mut no_adopt = false;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                print_usage();
                return Err(0);
            }
            "--cert" => match args.next() {
                Some(p) => cert_path = PathBuf::from(p),
                None => {
                    eprintln!("protect_recon: --cert requires a path argument");
                    return Err(1);
                }
            },
            "--password" => match args.next() {
                Some(p) => password = p,
                None => {
                    eprintln!("protect_recon: --password requires an argument");
                    return Err(1);
                }
            },
            "--enable-7550" => enable_7550 = true,
            "--selftest" => selftest = true,
            "--no-adopt" => no_adopt = true,
            "--camera-username" => match args.next() {
                Some(u) => camera_username = u,
                None => {
                    eprintln!("protect_recon: --camera-username requires an argument");
                    return Err(1);
                }
            },
            "--camera-password" => match args.next() {
                Some(p) => camera_password = p,
                None => {
                    eprintln!("protect_recon: --camera-password requires an argument");
                    return Err(1);
                }
            },
            other => {
                eprintln!("protect_recon: unknown argument '{other}'");
                print_usage();
                return Err(1);
            }
        }
    }
    Ok(Config {
        cert_path,
        password,
        enable_7550,
        selftest,
        no_adopt,
        camera_username,
        camera_password,
    })
}

/// Prints the tool's usage line to stderr.
fn print_usage() {
    eprintln!(
        "usage: protect_recon [--cert <path>] [--password <pw>] [--enable-7550] [--no-adopt] [--camera-username <user>] [--camera-password <pw>] [--selftest] [--help]"
    );
}

/// Imports the PFX and builds an inbound (server-side) `TlsAcceptor` holding
/// the first certificate in the archive. The returned acceptor is `Clone`
/// (Arc-wrapped credential handle) and is shared across every accepted
/// connection.
fn build_server_cred(pfx: &[u8], password: &str) -> io::Result<TlsAcceptor> {
    let pw = if password.is_empty() {
        None
    } else {
        Some(password)
    };
    TlsAcceptor::from_pfx(pfx, pw)
}

/// Opens `path` truncated (so each `protect_recon` run produces a self-
/// contained capture rather than an ever-growing append across runs) and
/// wraps it in a shared mutex so concurrent handler threads on the same port
/// write non-interleaved capture blocks. Concurrent appends within a single
/// run are still supported — only the across-run accumulation is dropped.
fn open_capture(path: &std::path::Path) -> io::Result<Arc<Mutex<File>>> {
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;
    Ok(Arc::new(Mutex::new(file)))
}

/// Read-timeout applied to self-test connections. The `.NET` `SslStream` client
/// sends promptly and echoes flow back continuously, so a healthy round-trip
/// never stalls; the timeout only bounds a stuck client so the echo loop can
/// re-check `SHUTDOWN` and exit on Ctrl+C rather than blocking forever.
const SELFTEST_READ_TIMEOUT_MS: u64 = 2000;

/// Scratch size for one self-test echo read. Bounds per-`EncryptMessage` record
/// granularity; the 1 MiB round-trip is reassembled across many reads.
const SELFTEST_ECHO_CHUNK: usize = 8192;

/// Step-17 localhost TLS self-test: binds `127.0.0.1:0`, prints the bound port,
/// and loops accepting connections. Each accepted connection completes the
/// SChannel handshake and echoes every decrypted byte straight back through
/// `EncryptMessage` until the peer closes, then drives a clean `close_notify`.
/// `tools/tls_selftest.ps1` connects and round-trips 1 B / 64 KiB / 1 MiB
/// buffers to exercise small-frame, typical-frame, and multi-record large-frame
/// encrypt/decrypt plus clean shutdown without needing the camera.
fn run_selftest(cred: TlsAcceptor) -> i32 {
    let listener = match TcpListener::bind(("127.0.0.1", 0)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("protect_recon: selftest bind 127.0.0.1:0 failed: {e}");
            return 1;
        }
    };
    let port = match listener.local_addr() {
        Ok(a) => a.port(),
        Err(_) => {
            eprintln!("protect_recon: selftest could not resolve local port");
            return 1;
        }
    };
    if listener.set_nonblocking(true).is_err() {
        eprintln!("protect_recon: selftest could not set listener non-blocking");
        return 1;
    }
    println!("selftest listening on 127.0.0.1:{port} — Ctrl+C to stop");
    install_ctrl_c();

    while !SHUTDOWN.load(RELAXED) {
        match listener.accept() {
            Ok((stream, _peer)) => {
                let cred = cred.clone();
                if let Err(e) = thread::spawn(move || selftest_handle(stream, cred)).join() {
                    eprintln!("selftest: handler thread panicked: {e:?}");
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(ACCEPT_POLL_MS));
            }
            Err(e) => {
                eprintln!("selftest: accept error: {e}");
                thread::sleep(Duration::from_millis(ACCEPT_POLL_MS));
            }
        }
    }
    0
}

/// Handles one self-test connection: completes the TLS handshake, echoes every
/// decrypted byte back, then shuts the TLS side down cleanly. Every error path
/// simply closes the connection so the accept loop keeps running for the next
/// round-trip.
fn selftest_handle(stream: TcpStream, cred: TlsAcceptor) {
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(Duration::from_millis(SELFTEST_READ_TIMEOUT_MS)));

    let mut tls = match cred.accept(stream) {
        Ok(t) => {
            println!("selftest: TLS handshake ok");
            t
        }
        Err(HandshakeError::PeerClosedBeforeData) => {
            println!("selftest: peer closed before any bytes (unexpected from .NET client)");
            return;
        }
        Err(e) => {
            eprintln!("selftest: {e}");
            return;
        }
    };

    let mut buf = [0u8; SELFTEST_ECHO_CHUNK];
    loop {
        if SHUTDOWN.load(RELAXED) {
            break;
        }
        match tls.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if let Err(e) = tls.write_all(&buf[..n]) {
                    eprintln!("selftest: echo write error: {e}");
                    break;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                if SHUTDOWN.load(RELAXED) {
                    break;
                }
                thread::sleep(Duration::from_millis(RAW_RETRY_SLEEP_MS));
                continue;
            }
            Err(e) => {
                eprintln!("selftest: echo read error: {e}");
                break;
            }
        }
    }

    match tls.shutdown() {
        Ok(()) => println!("selftest: clean shutdown (close_notify sent)"),
        Err(e) => eprintln!("selftest: shutdown error: {e}"),
    }
}

/// Binds `0.0.0.0:port`, runs the non-blocking accept loop, and spawns a
/// handler thread per accepted connection. Returns when `SHUTDOWN` is set.
fn listen(port: u16, cred: TlsAcceptor, capture: Arc<Mutex<File>>) {
    let listener = match TcpListener::bind(("0.0.0.0", port)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("protect_recon: bind 0.0.0.0:{port} failed: {e}");
            return;
        }
    };
    if listener.set_nonblocking(true).is_err() {
        eprintln!("protect_recon: could not set listener non-blocking on {port}");
        return;
    }
    println!("protect_recon: bound 0.0.0.0:{port}");
    for incoming in listener.incoming() {
        if SHUTDOWN.load(RELAXED) {
            break;
        }
        match incoming {
            Ok(stream) => {
                let cred = cred.clone();
                let capture = capture.clone();
                thread::spawn(move || handle_connection(stream, port, cred, capture));
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(ACCEPT_POLL_MS));
            }
            Err(_) => {
                thread::sleep(Duration::from_millis(ACCEPT_POLL_MS));
            }
        }
    }
}

/// Handles one accepted TCP connection to completion. On 7442, always wraps
/// in TLS then runs the WS-upgrade + AVClient session. On 7550, peeks the
/// first byte: if it's `0x16` (TLS ClientHello), wraps in TLS; otherwise
/// treats the connection as plain TCP (the `ChangeVideoSettings` destination
/// URI is `tcp://`, not `wss://`, so the camera may dial plain TCP). Either
/// way, the raw bytes are fed to `raw_tap_until_upgrade` / `capture_frames`
/// so the 7550 traffic is captured regardless of transport.
fn handle_connection(stream: TcpStream, port: u16, cred: TlsAcceptor, capture: Arc<Mutex<File>>) {
    let peer = stream
        .peer_addr()
        .map(|p| p.to_string())
        .unwrap_or_else(|_| "<unknown>".to_string());
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(Duration::from_millis(READ_TIMEOUT_MS)));

    log_line(&capture, &format!("[{port}] connection from {peer}"));

    // On 7550, peek the first byte to detect TLS vs plain TCP. The
    // `ChangeVideoSettings` destination URI is `tcp://` (not `wss://`), so
    // the camera may dial plain TCP. If the first byte is `0x16` (TLS
    // ContentType = Handshake = ClientHello), do TLS; otherwise, treat the
    // connection as raw TCP and capture the bytes directly.
    if port == PROTECT_UPFLV_PORT {
        let first_byte = match peek_first_byte(&stream) {
            Ok(b) => b,
            Err(HandshakeError::PeerClosedBeforeData) => {
                log_line(
                    &capture,
                    &format!(
                        "[{port}] peer TCP liveness probe (opened then closed, no bytes — normal)"
                    ),
                );
                return;
            }
            Err(e) => {
                log_line(&capture, &format!("[{port}] peek failed: {e}"));
                return;
            }
        };
        if first_byte == 0x16 {
            log_line(
                &capture,
                &format!("[{port}] first byte 0x16 — TLS ClientHello detected"),
            );
            handle_tls_connection(stream, port, cred, capture);
        } else {
            log_line(
                &capture,
                &format!("[{port}] first byte 0x{first_byte:02X} — plain TCP (not TLS); capturing raw bytes"),
            );
            handle_plain_connection(stream, port, capture);
        }
    } else {
        handle_tls_connection(stream, port, cred, capture);
    }
}

/// Peeks the first byte of `stream` without consuming it. Returns the byte,
/// or `PeerClosedBeforeData` if the peer sent zero bytes (the camera's
/// liveness probe).
fn peek_first_byte(stream: &TcpStream) -> Result<u8, HandshakeError> {
    let mut buf = [0u8; 1];
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    match stream.peek(&mut buf) {
        Ok(0) => Err(HandshakeError::PeerClosedBeforeData),
        Ok(_) => {
            let _ = stream.set_read_timeout(Some(Duration::from_millis(READ_TIMEOUT_MS)));
            Ok(buf[0])
        }
        Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
            Err(HandshakeError::PeerClosedBeforeData)
        }
        Err(e) => Err(HandshakeError::Failed(io::Error::other(format!(
            "peek: {e}"
        )))),
    }
}

/// Handles a plain-TCP (non-TLS) connection: hex-dumps every raw byte the
/// camera sends to the capture file. Used on 7550 when the first byte is not
/// a TLS ClientHello. The `ChangeVideoSettings` destination URI is `tcp://`
/// (not `wss://`), so the camera dials plain TCP and pushes uPFLV bytes
/// directly — no TLS, no WebSocket framing. The raw hex dump lets us identify
/// the actual framing (uPFLV prefix? FLV header? AMF metadata?) without
/// misinterpreting the bytes as WS frames.
fn handle_plain_connection(stream: TcpStream, port: u16, capture: Arc<Mutex<File>>) {
    let _ = stream.set_read_timeout(None);
    let mut reader = ChainedReader::new(Vec::new(), stream);
    let mut scratch = [0u8; RAW_READ_CHUNK_BYTES];
    let mut chunk_index: usize = 0;
    loop {
        if SHUTDOWN.load(RELAXED) {
            return;
        }
        match reader.read(&mut scratch) {
            Ok(0) => {
                log_line(&capture, &format!("[{port}] peer closed (raw tap)"));
                return;
            }
            Ok(n) => {
                chunk_index += 1;
                dump_raw(&capture, port, chunk_index, &scratch[..n]);
            }
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) => {
                log_line(&capture, &format!("[{port}] raw read error: {e}"));
                return;
            }
        }
    }
}

/// Handles a TLS connection: wraps in TLS, then runs the raw-tap capture
/// session. Used on 7442 (always) and 7550 (when the first byte is 0x16).
fn handle_tls_connection(
    stream: TcpStream,
    port: u16,
    cred: TlsAcceptor,
    capture: Arc<Mutex<File>>,
) {
    let mut tls = match cred.accept(stream) {
        Ok(t) => t,
        Err(HandshakeError::PeerClosedBeforeData) => {
            log_line(
                &capture,
                &format!(
                    "[{port}] peer TCP liveness probe (opened then closed, no bytes — normal)"
                ),
            );
            return;
        }
        Err(e) => {
            log_line(&capture, &format!("[{port}] {e}"));
            return;
        }
    };
    log_line(
        &capture,
        &format!("[{port}] TLS handshake ok — raw-tapping bytes"),
    );

    match raw_tap_until_upgrade(&mut tls, &capture, port) {
        RawTapOutcome::Upgraded { request, leftover } => {
            log_line(
                &capture,
                &format!("[{port}] WS upgrade ok — capturing decoded frames"),
            );
            if port == PROTECT_AVCLIENT_PORT {
                run_avclient_session(tls, leftover, &request, &capture, port);
            } else {
                let mut reader = ChainedReader::new(leftover, tls);
                capture_frames(&mut reader, &capture, port);
            }
        }
        RawTapOutcome::Closed => {
            log_line(&capture, &format!("[{port}] peer closed (raw tap)"));
        }
        RawTapOutcome::NoData => {
            log_line(
                &capture,
                &format!("[{port}] no data from camera within {CAPTURE_READ_DEADLINE_SECS}s"),
            );
        }
        RawTapOutcome::Error(e) => {
            log_line(&capture, &format!("[{port}] raw tap read error: {e}"));
        }
    }
}

/// Sub-step 1: drives the 7442 post-upgrade stream through step 19's
/// `AvClientSession` so the camera receives the correct `pong-<N>` /
/// `timeSync` / generic-ok replies and completes the handshake (the step-16
/// recon's generic replies caused the camera to forcibly close after frame 2,
/// so 7550 was never reached). With correct replies the camera proceeds to
/// open 7550 and stream, letting the separate 7550 listener capture the real
/// traffic. `request` is the buffered HTTP upgrade request; `Device-ID` is
/// parsed from it as the adoption context the controller would normally
/// record. `leftover` is any post-`\r\n\r\n` bytes the camera sent in the
/// same TLS record — fed into the session via `ChainedReader` so the first
/// AVClient frame is not lost.
fn run_avclient_session(
    tls: TlsStream<TcpStream>,
    leftover: Vec<u8>,
    request: &[u8],
    capture: &Arc<Mutex<File>>,
    port: u16,
) {
    let device_id =
        extract_header_value(request, "Device-ID").unwrap_or_else(|| "<unknown>".to_string());
    let adopted = extract_header_value(request, "Adopted")
        .unwrap_or_default()
        .eq_ignore_ascii_case("true");
    let controller_host =
        extract_header_value(request, "Host").unwrap_or_else(|| "<unknown>".to_string());
    let controller_ip = controller_host
        .rsplit_once(':')
        .map(|(ip, _)| ip)
        .unwrap_or(&controller_host);
    let camera_mac = extract_header_value(request, "Camera-MAC")
        .unwrap_or_default()
        .to_uppercase()
        .replace(':', "");
    let stream_name = if camera_mac.is_empty() {
        None
    } else {
        Some(format!("{camera_mac}_0"))
    };
    let stream_destination = format!("tcp://{controller_ip}:7550?retryInterval=1&connectTimeout=5");
    log_line(
        capture,
        &format!(
            "[{port}] AVClient handoff to step-19 session (Device-ID {device_id}, Adopted: {adopted}); \
             will send ChangeVideoSettings → {stream_destination} (streamName {stream_name:?}) after hello",
        ),
    );

    let inner = ChainedReader::new(leftover, tls);
    let mut retry = RetryReader::new(inner);
    let trace_capture = capture.clone();
    let trace_port = port;
    let mut session = AvClientSession::new(&mut retry, device_id.clone())
        .with_stream_destination(stream_destination, stream_name)
        .with_tracer(move |trace| {
            let dir = match trace.direction {
                flvproxy::protect_controller::FrameDirection::In => "IN ",
                flvproxy::protect_controller::FrameDirection::Out => "OUT",
            };
            let op = opcode_name(trace.opcode);
            // Render JSON / text payloads as UTF-8 for readability; hex-dump
            // non-UTF-8 binary.
            let body = match std::str::from_utf8(&trace.payload) {
                Ok(s) => s.to_string(),
                Err(_) => hex_dump_one_line(&trace.payload),
            };
            log_line(
                &trace_capture,
                &format!(
                    "[{trace_port}] AVClient {dir} {op} ({} bytes): {body}",
                    trace.payload.len()
                ),
            );
        });
    match session.run() {
        Ok(()) => log_line(
            capture,
            &format!(
                "[{port}] AVClient session ended cleanly (timeSync answered: {}, ChangeVideoSettings sent: {})",
                session.is_ready(),
                session.change_video_settings_sent(),
            ),
        ),
        Err(e) => log_line(
            capture,
            &format!(
                "[{port}] AVClient session ended: {e} (timeSync answered: {}, ChangeVideoSettings sent: {})",
                session.is_ready(),
                session.change_video_settings_sent(),
            ),
        ),
    }
}

fn opcode_name(op: flvproxy::ws::Opcode) -> &'static str {
    use flvproxy::ws::Opcode;
    match op {
        Opcode::Continuation => "Continuation",
        Opcode::Text => "Text",
        Opcode::Binary => "Binary",
        Opcode::Close => "Close",
        Opcode::Ping => "Ping",
        Opcode::Pong => "Pong",
    }
}

/// Renders `bytes` as a single-line hex string (`DE 19 16 ...`), used by the
/// AVClient frame tracer for non-UTF-8 payloads.
fn hex_dump_one_line(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        out.push_str(&format!("{b:02X}"));
    }
    out
}

/// "no complete TLS record yet" / timed-socket conditions) into a bounded
/// sleep+retry, so a caller that treats those as fatal — like step 19's
/// `AvClientSession::run` — sees only real data, real EOF, or real fatal
/// errors. Mirrors the retry discipline of `fill_exact` /
/// `raw_tap_until_upgrade`. Writes pass straight through. Stops retrying when
/// `SHUTDOWN` is set or the per-session deadline elapses.
struct RetryReader<S> {
    inner: S,
    deadline: Instant,
}

/// Upper bound on how long the AVClient session will keep retrying a
/// `WouldBlock`/`TimedOut` read before giving up. Matches
/// `CAPTURE_READ_DEADLINE_SECS`: if the camera has not sent the next AVClient
/// frame (or closed) within this window, the session is logged and ended so
/// the recon's accept loop can handle the camera's inevitable 7442 retry
/// rather than accumulating stuck handler threads. Ctrl+C still terminates
/// promptly — the retry loop checks `SHUTDOWN` every `AVCLIENT_RETRY_SLEEP_MS`.
const AVCLIENT_SESSION_DEADLINE_SECS: u64 = 30;

/// Sleep between `WouldBlock`/`TimedOut` retries in the AVClient read loop.
/// Matches `RAW_RETRY_SLEEP_MS` so the spin stays cheap.
const AVCLIENT_RETRY_SLEEP_MS: u64 = 20;

impl<S> RetryReader<S> {
    /// Wraps `inner` with a fresh session deadline.
    fn new(inner: S) -> RetryReader<S> {
        RetryReader {
            inner,
            deadline: Instant::now() + Duration::from_secs(AVCLIENT_SESSION_DEADLINE_SECS),
        }
    }
}

impl<S: Read> Read for RetryReader<S> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        loop {
            match self.inner.read(out) {
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    if SHUTDOWN.load(RELAXED) {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "shutdown signalled during AVClient read",
                        ));
                    }
                    if Instant::now() >= self.deadline {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!(
                                "AVClient read stalled beyond {AVCLIENT_SESSION_DEADLINE_SECS}s"
                            ),
                        ));
                    }
                    thread::sleep(Duration::from_millis(AVCLIENT_RETRY_SLEEP_MS));
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }
}

impl<S: Write> Write for RetryReader<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Extracts the value of HTTP header `name` (case-insensitive) from a textual
/// HTTP request, returning the trimmed value. Used by the 7442 handoff to
/// pull `Device-ID` from the buffered upgrade request as the adoption
/// context. Mirrors `extract_websocket_key`'s per-line split-and-skip.
fn extract_header_value(request: &[u8], name: &str) -> Option<String> {
    let text = std::str::from_utf8(request).ok()?;
    for line in text.split("\r\n") {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((hdr, value)) = line.split_once(':') else {
            continue;
        };
        if hdr.trim().eq_ignore_ascii_case(name) {
            return Some(value.trim().to_string());
        }
    }
    None
}

/// Outcome of the pre-upgrade raw-tap loop. `Upgraded` carries the full HTTP
/// upgrade request bytes (so the 7442 path can parse `Device-ID` for the
/// AVClient session) plus any bytes the camera sent after the `\r\n\r\n`
/// terminator (the start of the first WS frame); the post-upgrade handler
/// consumes the leftover via `ChainedReader` before reading fresh bytes off
/// the TLS stream.
enum RawTapOutcome {
    Upgraded { request: Vec<u8>, leftover: Vec<u8> },
    Closed,
    NoData,
    Error(io::Error),
}

/// Phase 1 capture: reads every byte the camera sends right after TLS
/// completes, hex-dumping each chunk to stdout and the capture file, and
/// opportunistically completes the RFC 6455 server handshake if the buffered
/// bytes form a valid HTTP Upgrade request. Tolerates the `WouldBlock`/
/// `TimedOut` errors the `TlsStream` surfaces from the timed socket (the bug
/// that aborted every connection in the first recon run): the first-byte wait is
/// bounded by `CAPTURE_READ_DEADLINE_SECS`; subsequent reads retry until the
/// peer closes, the upgrade completes, or shutdown is signalled.
fn raw_tap_until_upgrade(
    tls: &mut TlsStream<TcpStream>,
    capture: &Arc<Mutex<File>>,
    port: u16,
) -> RawTapOutcome {
    let deadline = Instant::now() + Duration::from_secs(CAPTURE_READ_DEADLINE_SECS);
    let mut buf: Vec<u8> = Vec::new();
    let mut scratch = [0u8; RAW_READ_CHUNK_BYTES];
    let mut chunk_index: usize = 0;
    let mut first_byte_seen = false;
    let mut stop_upgrade_check = false;

    loop {
        if SHUTDOWN.load(RELAXED) {
            return RawTapOutcome::Closed;
        }
        match tls.read(&mut scratch) {
            Ok(0) => return RawTapOutcome::Closed,
            Ok(n) => {
                first_byte_seen = true;
                chunk_index += 1;
                dump_raw(capture, port, chunk_index, &scratch[..n]);
                if !stop_upgrade_check {
                    buf.extend_from_slice(&scratch[..n]);
                    if let Some(outcome) = try_upgrade_from_buffer(tls, &buf, capture, port) {
                        return outcome;
                    }
                    if buf.len() > MAX_HANDSHAKE_HEADER_BYTES {
                        log_line(
                            capture,
                            &format!(
                                "[{port}] buffered {len} bytes with no \\r\\n\\r\\n; \
                                 not an HTTP upgrade — raw tap continues",
                                len = buf.len()
                            ),
                        );
                        stop_upgrade_check = true;
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                if !first_byte_seen && Instant::now() >= deadline {
                    return RawTapOutcome::NoData;
                }
                thread::sleep(Duration::from_millis(RAW_RETRY_SLEEP_MS));
            }
            Err(e) => return RawTapOutcome::Error(e),
        }
    }
}

/// Inspects the accumulated pre-upgrade buffer for a complete RFC 6455 §4.1
/// HTTP Upgrade request. When found and it carries a `Sec-WebSocket-Key`,
/// sends the `101` response and returns `Some(Upgraded { leftover })` where
/// `leftover` is any bytes the camera sent past the `\r\n\r\n` terminator.
/// Returns `None` when no complete header terminator is present yet (the
/// caller keeps reading). A complete-but-keyless request stops further
/// upgrade attempts and returns `None` (raw tap continues).
fn try_upgrade_from_buffer(
    tls: &mut TlsStream<TcpStream>,
    buf: &[u8],
    capture: &Arc<Mutex<File>>,
    port: u16,
) -> Option<RawTapOutcome> {
    let term = b"\r\n\r\n";
    let header_end = buf.windows(term.len()).position(|w| w == term)? + term.len();
    let request = match std::str::from_utf8(&buf[..header_end]) {
        Ok(s) => s,
        Err(_) => {
            log_line(
                capture,
                &format!("[{port}] non-UTF-8 in upgrade buffer; raw tap continues"),
            );
            return None;
        }
    };
    if extract_websocket_key(request).is_none() {
        log_line(
            capture,
            &format!("[{port}] HTTP-like request without Sec-WebSocket-Key; raw tap continues"),
        );
        return None;
    }
    if let Err(e) = send_ws_upgrade_response(tls, request) {
        return Some(RawTapOutcome::Error(e));
    }
    let leftover = buf[header_end..].to_vec();
    if !leftover.is_empty() {
        log_line(
            capture,
            &format!(
                "[{port}] {leftover} byte(s) followed the upgrade headers — \
                 fed to the frame reader",
                leftover = leftover.len()
            ),
        );
    }
    Some(RawTapOutcome::Upgraded {
        request: buf[..header_end].to_vec(),
        leftover,
    })
}

/// Phase 2 capture (after a successful WS upgrade): reads RFC 6455 frames
/// from `reader`, hex-dumps each decoded (unmasked) payload, and best-effort
/// replies to ping/close so the capture loop can keep running. `reader` is a
/// `ChainedReader` so any bytes the camera sent immediately after the upgrade
/// headers are consumed before fresh TLS reads.
fn capture_frames<R: Read + Write>(
    reader: &mut ChainedReader<R>,
    capture: &Arc<Mutex<File>>,
    port: u16,
) {
    let mut frame_index: usize = 0;
    loop {
        if SHUTDOWN.load(RELAXED) {
            break;
        }
        let frame = match read_frame(reader) {
            Ok(Some(f)) => f,
            Ok(None) => {
                log_line(capture, &format!("[{port}] peer closed connection"));
                break;
            }
            Err(e) => {
                log_line(capture, &format!("[{port}] frame read error: {e}"));
                break;
            }
        };
        frame_index += 1;
        dump_frame(capture, port, frame_index, &frame);
        match frame.opcode {
            OPCODE_PING => {
                if let Err(e) = write_frame(reader, OPCODE_PONG, false, &frame.payload) {
                    log_line(capture, &format!("[{port}] pong write error: {e}"));
                    break;
                }
            }
            OPCODE_CLOSE => {
                let _ = write_frame(reader, OPCODE_CLOSE, false, &frame.payload);
                log_line(capture, &format!("[{port}] received close frame, closing"));
                break;
            }
            OPCODE_CONTINUATION | OPCODE_TEXT | OPCODE_BINARY | OPCODE_PONG => {}
            _ => {}
        }
    }
}

/// Reader that drains a leftover byte buffer first, then delegates to an
/// inner `Read`. Used after the WS upgrade to feed any bytes the camera sent
/// past the `\r\n\r\n` terminator into `read_frame` before pulling fresh
/// bytes off the TLS stream. The inner stream may surface `WouldBlock`/
/// `TimedOut`, which the tolerant `fill_exact` retries.
struct ChainedReader<S: Read> {
    pre: std::io::Cursor<Vec<u8>>,
    stream: S,
}

impl<S: Read> ChainedReader<S> {
    /// Wraps `stream` so `leftover` is yielded first.
    fn new(leftover: Vec<u8>, stream: S) -> ChainedReader<S> {
        ChainedReader {
            pre: std::io::Cursor::new(leftover),
            stream,
        }
    }
}

impl<S: Read> Read for ChainedReader<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pre.position() < self.pre.get_ref().len() as u64 {
            self.pre.read(buf)
        } else {
            self.stream.read(buf)
        }
    }
}

impl<S: Read + Write> Write for ChainedReader<S> {
    /// Writes go straight to the inner stream — the leftover buffer is a
    /// read-only prefix, not a write buffer. Used only for best-effort
    /// pong/close replies during the frame-capture loop.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

/// One decoded RFC 6455 frame: the FIN bit, the 4-bit opcode, and the
/// (unmasked) payload.
struct Frame {
    fin: bool,
    opcode: u8,
    payload: Vec<u8>,
}

/// Reads exactly `buf.len()` bytes from `r` into `buf`. Returns `Ok(Some(()))`
/// on success and `Ok(None)` if the peer cleanly closed before any byte of
/// this read arrived (used to distinguish a clean close from a mid-frame EOF).
/// Tolerates `WouldBlock`/`TimedOut` (which the `TlsStream` surfaces
/// from the timed socket) by retrying after `RAW_RETRY_SLEEP_MS` until bytes
/// arrive, the peer closes, or shutdown is signalled — so post-upgrade frame
/// reads do not abort the capture when the camera pauses between frames.
fn fill_exact<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<Option<()>> {
    let n = buf.len();
    let mut filled = 0;
    while filled < n {
        match r.read(&mut buf[filled..]) {
            Ok(0) => {
                if filled == 0 {
                    return Ok(None);
                }
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "peer closed mid-frame",
                ));
            }
            Ok(k) => filled += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                if SHUTDOWN.load(RELAXED) {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "shutdown signalled during read",
                    ));
                }
                thread::sleep(Duration::from_millis(RAW_RETRY_SLEEP_MS));
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(Some(()))
}

/// Reads one RFC 6455 §5.2 frame from `r` (client→server, so the payload is
/// unmasked). Control frames are returned as-is; the caller decides what to
/// do with them. Returns `Ok(None)` on a clean peer close before the next
/// frame's first byte.
fn read_frame<R: Read>(r: &mut R) -> io::Result<Option<Frame>> {
    let mut header = [0u8; 2];
    if fill_exact(r, &mut header)?.is_none() {
        return Ok(None);
    }
    let fin = header[0] & 0x80 != 0;
    let opcode = header[0] & 0x0F;
    let masked = header[1] & 0x80 != 0;
    let mut len = (header[1] & 0x7F) as usize;
    if len == 126 {
        let mut ext = [0u8; 2];
        fill_exact(r, &mut ext)?
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "len126 eof"))?;
        len = u16::from_be_bytes(ext) as usize;
    } else if len == 127 {
        let mut ext = [0u8; 8];
        fill_exact(r, &mut ext)?
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "len127 eof"))?;
        len = u64::from_be_bytes(ext) as usize;
    }
    if len > MAX_FRAME_PAYLOAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame payload length {len} exceeds recon cap {MAX_FRAME_PAYLOAD}"),
        ));
    }
    let mut mask = [0u8; 4];
    if masked {
        fill_exact(r, &mut mask)?
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "mask eof"))?;
    }
    let mut payload = vec![0u8; len];
    if len > 0 {
        fill_exact(r, &mut payload)?
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "payload eof"))?;
    }
    if masked {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= mask[i & 3];
        }
    }
    Ok(Some(Frame {
        fin,
        opcode,
        payload,
    }))
}

/// Writes one RFC 6455 §5.2 frame from server→client (unmasked). Used only for
/// best-effort pong/close replies so the capture loop can keep reading.
fn write_frame<W: Write>(w: &mut W, opcode: u8, fin: bool, payload: &[u8]) -> io::Result<()> {
    let mut header = [0u8; 2];
    if fin {
        header[0] |= 0x80;
    }
    header[0] |= opcode & 0x0F;
    if payload.len() <= 125 {
        header[1] = payload.len() as u8;
        w.write_all(&header)?;
    } else if payload.len() <= u16::MAX as usize {
        header[1] = 126;
        w.write_all(&header)?;
        w.write_all(&(payload.len() as u16).to_be_bytes())?;
    } else {
        header[1] = 127;
        w.write_all(&header)?;
        w.write_all(&(payload.len() as u64).to_be_bytes())?;
    }
    w.write_all(payload)?;
    w.flush()?;
    Ok(())
}

/// Subprotocol the camera offers in its `Sec-WebSocket-Protocol` header
/// (`secure_transfer`), per the captured 7442 request. RFC 6455 §4.2.2
/// requires the server to echo the selected subprotocol in its `101`; the
/// camera may refuse the upgrade otherwise.
const WS_SUBPROTOCOL: &str = "secure_transfer";

/// Completes the RFC 6455 §4.1/§4.2.2 server-side opening handshake from an
/// already-buffered HTTP request: extracts `Sec-WebSocket-Key`, computes
/// `Sec-WebSocket-Accept = base64(sha1(key + GUID))`, echoes the
/// `secure_transfer` subprotocol the camera requested, and writes the `101`
/// response. The raw-tap loop calls this once it has accumulated a complete
/// header block.
fn send_ws_upgrade_response<S: Write>(stream: &mut S, request: &str) -> io::Result<()> {
    let key = extract_websocket_key(request)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing Sec-WebSocket-Key"))?;
    let accept = websocket_accept(&key);
    let protocol_line = if request_subprotocols(request)
        .iter()
        .any(|p| p == WS_SUBPROTOCOL)
    {
        format!("Sec-WebSocket-Protocol: {WS_SUBPROTOCOL}\r\n")
    } else {
        String::new()
    };
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {accept}\r\n\
         {protocol_line}\
         \r\n"
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()?;
    Ok(())
}

/// Extracts the comma-separated values of the request's
/// `Sec-WebSocket-Protocol` header (RFC 6455 §4.1), case-insensitively, as
/// trimmed lowercased tokens. Empty when the header is absent. Used to decide
/// whether to echo the `secure_transfer` subprotocol in the `101` response.
fn request_subprotocols(request: &str) -> Vec<String> {
    for line in request.split("\r\n") {
        let line = line.trim();
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("Sec-WebSocket-Protocol") {
            return value
                .split(',')
                .map(|t| t.trim().to_ascii_lowercase())
                .collect();
        }
    }
    Vec::new()
}

/// Extracts the `Sec-WebSocket-Key` header value (RFC 6455 §4.1), case-
/// insensitively, from the textual HTTP request. Returns `None` if absent.
/// Lines without a `:` (e.g. the request line `GET /path HTTP/1.1`) are
/// skipped rather than aborting the search — an earlier `?`-on-`split_once`
/// form returned `None` for the whole request whenever the colon-less first
/// line was reached, masking the key that was in fact present.
fn extract_websocket_key(request: &str) -> Option<String> {
    for line in request.split("\r\n") {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("Sec-WebSocket-Key") {
            return Some(value.trim().to_string());
        }
    }
    None
}

/// Computes the RFC 6455 §1.3 `Sec-WebSocket-Accept` value:
/// `base64(sha1(key + GUID))`.
fn websocket_accept(key: &str) -> String {
    let mut input = Vec::with_capacity(key.len() + WS_GUID.len());
    input.extend_from_slice(key.as_bytes());
    input.extend_from_slice(WS_GUID.as_bytes());
    let digest = sha1(&input);
    base64_encode(&digest)
}

/// Computes SHA-1 (FIPS 180-4) over `data`, returning the 20-byte digest.
/// Implemented by hand per the project's zero-crates constraint.
fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xEFCDAB89;
    let mut h2: u32 = 0x98BADCFE;
    let mut h3: u32 = 0x10325476;
    let mut h4: u32 = 0xC3D2E1F0;

    let bit_len: u64 = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 80];
        for (i, word) in chunk.chunks_exact(4).enumerate().take(16) {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
}

/// Formats one captured raw byte chunk as a header line plus hex+ASCII rows
/// and writes the block to both stdout and the port's capture file (under the
/// capture mutex so concurrent connections on the same port do not interleave).
/// Used by the pre-upgrade raw-tap loop, which must dump bytes before knowing
/// whether they form an HTTP upgrade or a raw WS frame.
fn dump_raw(capture: &Arc<Mutex<File>>, port: u16, index: usize, bytes: &[u8]) {
    let block = format_raw_block(port, index, bytes);
    print!("{block}");
    if let Ok(mut f) = capture.lock() {
        let _ = write!(f, "{block}");
    }
}

/// Builds the textual capture block for one raw chunk: a header line naming
/// the port, chunk index, and byte count, followed by canonical hex+ASCII rows
/// of 16 bytes each.
fn format_raw_block(port: u16, index: usize, bytes: &[u8]) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "[{port}] raw chunk {index}: {len} byte(s)\n",
        len = bytes.len()
    ));
    for chunk in bytes.chunks(16) {
        let mut hex_part = String::new();
        let mut ascii_part = String::new();
        for b in chunk {
            hex_part.push_str(&format!("{b:02X} "));
            ascii_part.push(if (0x20..0x7F).contains(b) {
                *b as char
            } else {
                '.'
            });
        }
        for _ in chunk.len()..16 {
            hex_part.push_str("   ");
        }
        s.push_str(&format!("  {hex_part} |{ascii_part}|\n"));
    }
    s
}

/// Formats one captured frame as a header line plus hex+ASCII rows and writes
/// the block to both stdout and the port's capture file (under the capture
/// mutex so concurrent connections on the same port do not interleave).
fn dump_frame(capture: &Arc<Mutex<File>>, port: u16, index: usize, frame: &Frame) {
    let block = format_frame_block(port, index, frame);
    println!("{block}");
    if let Ok(mut f) = capture.lock() {
        let _ = writeln!(f, "{block}");
    }
}

/// Builds the textual capture block for one frame: a header line naming the
/// port, frame index, opcode and FIN bit, followed by canonical hex+ASCII
/// rows of 16 bytes each.
fn format_frame_block(port: u16, index: usize, frame: &Frame) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "[{port}] frame {index}: opcode=0x{:02X} fin={} len={}\n",
        frame.opcode,
        frame.fin,
        frame.payload.len()
    ));
    for chunk in frame.payload.chunks(16) {
        let mut hex_part = String::new();
        let mut ascii_part = String::new();
        for b in chunk {
            hex_part.push_str(&format!("{b:02X} "));
            ascii_part.push(if (0x20..0x7F).contains(b) {
                *b as char
            } else {
                '.'
            });
        }
        for _ in chunk.len()..16 {
            hex_part.push_str("   ");
        }
        s.push_str(&format!("  {hex_part} |{ascii_part}|\n"));
    }
    s
}

/// Writes one capture line to both stdout and (under the mutex) the capture
/// file. Used for connection / handshake / close status lines.
fn log_line(capture: &Arc<Mutex<File>>, line: &str) {
    println!("{line}");
    if let Ok(mut f) = capture.lock() {
        let _ = writeln!(f, "{line}");
    }
}

/// Installs a Ctrl+C console-control handler (kernel32
/// `SetConsoleCtrlHandler`) that flips `SHUTDOWN`. Best-effort: on failure
/// the OS default (terminate) still ends the process on Ctrl+C — only
/// graceful per-thread shutdown is lost. Mirrors `src/main.rs`'s
/// `console_shutdown` Windows branch.
fn install_ctrl_c() {
    extern "system" {
        fn SetConsoleCtrlHandler(
            handler: Option<unsafe extern "system" fn(u32) -> i32>,
            add: i32,
        ) -> i32;
    }
    const CTRL_C_EVENT: u32 = 0;
    unsafe extern "system" fn on_ctrl(ctrl: u32) -> i32 {
        if ctrl == CTRL_C_EVENT {
            SHUTDOWN.store(true, RELAXED);
            1
        } else {
            0
        }
    }
    unsafe {
        let _ = SetConsoleCtrlHandler(Some(on_ctrl), 1);
    }
}
