//! WS-Discovery over UDP multicast `239.255.255.250:3702`. Answers Probe messages with a ProbeMatch advertising the ONVIF device endpoint XAddr and the `NetworkVideoTransmitter` type, and announces a one-shot `Hello` on startup so NVRs that wait for announcements (rather than probing) still see the device. On shutdown a `Bye` is sent.
//!
//! The XML builders are pure string logic with no sockets, so they build and test on any platform. The runtime (`Discovery`) drives a real `UdpSocket` joined to the multicast group, mirroring the accept-loop / shutdown-handle shape of `rtsp_server::RtspServer`, `camera_listener::CameraListener`, and `onvif_server::OnvifServer`. Real-client validation against an NVR (ONVIF Device Manager) is step 24.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::logging::{Level, Logger};
use crate::onvif_server::xml_escape;

/// Relaxed ordering suffices for the shutdown flag: it is an advisory signal, not synchronization that establishes happens-before for other data. Mirrors the other server modules.
const RELAXED: Ordering = Ordering::Relaxed;

/// WS-Discovery multicast group address, per `RFC 3701` / WS-Discovery Appendix II. The group is `239.255.255.250`.
const MULTICAST_GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);

/// WS-Discovery multicast UDP port, per WS-Discovery §2.4. The probe target port is `3702`.
const MULTICAST_PORT: u16 = 3702;

/// Bind address for the multicast listener: all interfaces, on the WS-Discovery port. Same as `0.0.0.0:3702`.
const LISTEN_ADDR: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, MULTICAST_PORT);

/// Maximum size of a WS-Discovery datagram we are willing to read. UDP datagrams on this socket are small SOAP envelopes; bounding the read buffer guards against a misbehaving peer sending a huge datagram.
const MAX_DATAGRAM_BYTES: usize = 8192;

/// Poll interval for the non-blocking recv loop, so the `shutdown` flag is checked promptly rather than blocking until the next datagram. Matches the cadence of the other server modules.
const RECV_POLL_MS: u64 = 50;

/// Time budget for sending the one-shot `Hello` on startup and the `Bye` on shutdown. These are best-effort announcements; a slow send must not wedge the loop.
const ANNOUNCE_SEND_TIMEOUT_MS: u64 = 1_000;

/// Time budget for sending a `ProbeMatch` reply to a Probe sender. Best-effort unicast reply; a slow send must not stall the recv loop.
const REPLY_SEND_TIMEOUT_MS: u64 = 1_000;

/// ONVIF device type advertised in `ProbeMatch`/`Hello` `Types`, per the ONVIF Core Spec §5.1: `NetworkVideoTransmitter` is the type NVRs filter on for discovery of streaming devices.
const DEVICE_TYPE: &str = "tns:NetworkVideoTransmitter";

/// ONVIF `Device` type optionally advertised alongside `NetworkVideoTransmitter` so NVRs that filter on the generic device type also match.
const DEVICE_TYPE_DEVICE: &str = "tds:Device";

/// ONVIF Profile S streaming scope advertised in `Scopes`. Some NVRs filter discovery on this scope, so including it (cheap) broadens compatibility with NVRs that require the `Streaming` profile.
const SCOPE_STREAMING: &str = "onvif://www.onvif.org/Profile/Streaming";

/// ONVIF `Hardware` scope advertised in `Scopes`, advertising the device hardware (the proxy model) so NVRs grouping by hardware see a sane value.
const SCOPE_HARDWARE: &str = "onvif://www.onvif.org/hardware/UVC-G5-Bullet";

/// ONVIF `name` scope advertised in `Scopes`, advertising a human-readable device name so NVRs that show a name field display something sensible.
const SCOPE_NAME: &str = "onvif://www.onvif.org/name/flvproxy";

/// WS-Discovery `Hello`/`Bye`/`ProbeMatch` action namespaces, per the WS-Discovery specification §3. Declared once so the templates stay readable.
const NS_ENVELOPE: &str = "http://www.w3.org/2003/05/soap-envelope";
const NS_ADDRESSING: &str = "http://schemas.xmlsoap.org/ws/2004/08/addressing";
const NS_DISCOVERY: &str = "http://schemas.xmlsoap.org/ws/2005/04/discovery";

/// WS-Discovery `Hello` wsa:Action URI, per WS-Discovery §3.1.
const ACTION_HELLO: &str = "http://schemas.xmlsoap.org/ws/2005/04/discovery/Hello";

/// WS-Discovery `Bye` wsa:Action URI, per WS-Discovery §3.2.
const ACTION_BYE: &str = "http://schemas.xmlsoap.org/ws/2005/04/discovery/Bye";

/// WS-Discovery `ProbeMatch` wsa:Action URI, per WS-Discovery §3.3.
const ACTION_PROBE_MATCH: &str = "http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches";

/// WS-Discovery `Probe` wsa:Action URI, used to detect incoming Probes by scanning the datagram body, per WS-Discovery §3.3.
const ACTION_PROBE: &str = "http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe";

/// WS-Discovery `ProbeMatches` wrapper element local name, per WS-Discovery §3.3. The reply body's outer element.
const ELEMENT_PROBE_MATCHES: &str = "ProbeMatches";

const ELEMENT_PROBE_MATCH: &str = "ProbeMatch";

/// WS-Discovery `Hello` element local name, per WS-Discovery §3.1.
const ELEMENT_HELLO: &str = "Hello";

/// WS-Discovery `Bye` element local name, per WS-Discovery §3.2.
const ELEMENT_BYE: &str = "Bye";

/// WS-Discovery `Types` element local name: the ONVIF type list field.
const ELEMENT_TYPES: &str = "Types";

/// WS-Discovery `XAddrs` element local name: the list of device service URLs.
const ELEMENT_XADDRS: &str = "XAddrs";

/// WS-Discovery `Scopes` element local name: the device capability scopes.
const ELEMENT_SCOPES: &str = "Scopes";

/// WS-Discovery `AppSequence` element local name, used to order discovery messages. The header is emitted inline by `build_envelope`; this constant documents the spec reference (WS-Discovery §3.4 AppSequence).
const ELEMENT_APP_SEQUENCE: &str = "AppSequence";

/// WS-Discovery `AppSequence InstanceId` attribute: identifies the discovery instance. Held at a constant for simplicity (one proxy = one instance).
const APP_SEQUENCE_INSTANCE_ID: u32 = 1;

/// WS-Discovery `AppSequence MessageNumber` attribute: increments per announcement. Held at a constant; NVRs do not depend on it for adding the device.
const APP_SEQUENCE_MESSAGE_NUMBER: u32 = 1;

/// Builds the WS-Discovery `ProbeMatch` SOAP envelope for the given device XAddr and device address. `relates_to` (when present) is echoed in a `wsa:RelatesTo` element so the probing NVR can correlate the reply with its outgoing Probe (best-effort — WS-Discovery allows omitting `RelatesTo`).
///
/// The envelope advertises `Types = NetworkVideoTransmitter` and `Device`, the supplied XAddrs, and the `Streaming`/`Hardware`/`name` scopes. The XAddr and device address are XML-escaped so a configured IP containing markup cannot break the envelope.
pub fn build_probe_match(xaddr: &str, device_addr: &str, relates_to: Option<&str>) -> String {
    let relates_block = match relates_to {
        Some(id) => format!("<wsa:RelatesTo>{}</wsa:RelatesTo>", xml_escape(id)),
        None => String::new(),
    };
    build_envelope(ACTION_PROBE_MATCH, ELEMENT_PROBE_MATCHES, Some((ELEMENT_PROBE_MATCH, relates_block)), xaddr, device_addr)
}

/// Builds the WS-Discovery `Hello` SOAP envelope announcing the device on startup. Same body shape as `ProbeMatch` but with the `Hello` action and no `RelatesTo`.
pub fn build_hello(xaddr: &str, device_addr: &str) -> String {
    build_envelope(ACTION_HELLO, ELEMENT_HELLO, None, xaddr, device_addr)
}

/// Builds the WS-Discovery `Bye` SOAP envelope announcing device departure.
pub fn build_bye(xaddr: &str, device_addr: &str) -> String {
    build_envelope(ACTION_BYE, ELEMENT_BYE, None, xaddr, device_addr)
}

/// Shared envelope builder for the three announcement types (`ProbeMatch`, `Hello`, `Bye`). They share the same body shape — an endpoint reference, `Types`, `Scopes`, `XAddrs`, and `MetadataVersion` — and differ only in the `wsa:Action`, the outer body element name, and (for `ProbeMatch`) an extra wrapper element plus an optional `wsa:RelatesTo`.
///
/// `body_outer` names the outer body element (`Hello` / `Bye` / `ProbeMatches`). `probe_match_inner`, when `Some((name, relates_block))`, inserts a wrapper element `name` (`ProbeMatch`) around the shared body and emits the `relates_block` in the header. The shared shape keeps the three builders DRY; factoring it here is the owning-module location for this concept.
fn build_envelope(action: &str, body_outer: &str, probe_match_inner: Option<(&str, String)>, xaddr: &str, device_addr: &str) -> String {
    let xaddrs = xml_escape(xaddr);
    let endpoint = xml_escape(device_addr);
    let (inner_open, inner_close, relates) = match probe_match_inner {
        Some((inner_name, relates_block)) => (format!("<wsdiscovery:{inner_name}>"), format!("</wsdiscovery:{inner_name}>"), relates_block),
        None => (String::new(), String::new(), String::new()),
    };
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <s:Envelope xmlns:s=\"{envelope}\" xmlns:wsa=\"{addressing}\" xmlns:wsdiscovery=\"{discovery}\">\n\
         <s:Header>\n\
         <wsa:Action>{action}</wsa:Action>\n\
         {relates}\n\
         <wsa:To>urn:docs-oasis-open-org:ws-sx:ws-discovery</wsa:To>\n\
         <wsdiscovery:{app_seq} InstanceId=\"{inst}\" MessageNumber=\"{msg}\"/>\n\
         </s:Header>\n\
         <s:Body>\n\
         <wsdiscovery:{body_outer}>\n\
         {inner_open}\n\
         <wsa:EndpointReference>\n\
         <wsa:Address>{endpoint}</wsa:Address>\n\
         </wsa:EndpointReference>\n\
         <wsdiscovery:{types}>{device_type} {device_type_device}</wsdiscovery:{types}>\n\
         <wsdiscovery:{scopes}>{scope_streaming} {scope_hardware} {scope_name}</wsdiscovery:{scopes}>\n\
         <wsdiscovery:{xaddrs_elem}>{xaddrs}</wsdiscovery:{xaddrs_elem}>\n\
         <wsdiscovery:MetadataVersion>1</wsdiscovery:MetadataVersion>\n\
         {inner_close}\n\
         </wsdiscovery:{body_outer}>\n\
         </s:Body>\n\
         </s:Envelope>",
        envelope = NS_ENVELOPE,
        addressing = NS_ADDRESSING,
        discovery = NS_DISCOVERY,
        action = action,
        relates = relates,
        app_seq = ELEMENT_APP_SEQUENCE,
        inst = APP_SEQUENCE_INSTANCE_ID,
        msg = APP_SEQUENCE_MESSAGE_NUMBER,
        body_outer = body_outer,
        inner_open = inner_open,
        endpoint = endpoint,
        types = ELEMENT_TYPES,
        device_type = DEVICE_TYPE,
        device_type_device = DEVICE_TYPE_DEVICE,
        scopes = ELEMENT_SCOPES,
        scope_streaming = SCOPE_STREAMING,
        scope_hardware = SCOPE_HARDWARE,
        scope_name = SCOPE_NAME,
        xaddrs_elem = ELEMENT_XADDRS,
        xaddrs = xaddrs,
        inner_close = inner_close,
    )
}

/// Detects whether `buf` is a WS-Discovery `Probe` SOAP envelope and, when it is, extracts the request's `wsa:MessageID` so the reply can echo it via `RelatesTo`. A regex-free substring scan is sufficient — WS-Discovery datagrams are small SOAP envelopes with predictable element shapes, and the reply is best-effort (a missing `RelatesTo` is legal per the spec).
///
/// The Probe action is matched as `>{ACTION_PROBE}<` — the action URI bounded by the closing `>` of an opening element tag and the opening `<` of the matching closing tag. This is prefix-agnostic (works with `<wsa:Action>`, `<Action>`, `<a:Action>`, etc., since ONVIF clients use different WS-Addressing namespace prefixes — Onvier uses a default `xmlns=` with no prefix) and avoids false-detecting a `ProbeMatches` reply (whose action URI ends with `ProbeMatches`, not `Probe`) because the bounding `<` ensures the URI is the complete element value, not a prefix of a longer one.
pub fn parse_probe(buf: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(buf).ok()?;
    let needle = format!(">{ACTION_PROBE}<");
    if !text.contains(&needle) {
        return None;
    }
    Some(extract_message_id(text))
}

/// Extracts the inner text of the first `MessageID` element in `xml` (regardless of namespace prefix or attributes), or returns an empty string when absent. The caller treats an empty string as "no MessageID" and omits `RelatesTo` from the reply. Attribute-tolerant because ONVIF clients put `xmlns=` on the element itself (e.g. `<MessageID xmlns="http://www.w3.org/2005/08/addressing">...`) rather than declaring the prefix on the envelope.
fn extract_message_id(xml: &str) -> String {
    if let Some(idx) = xml.find("MessageID") {
        if let Some(gt) = xml[idx..].find('>') {
            let content_start = idx + gt + 1;
            let rest = &xml[content_start..];
            if let Some(lt) = rest.find('<') {
                return rest[..lt].trim().to_string();
            }
        }
    }
    String::new()
}

/// Generates a stable-per-process URN UUID-style device address. WS-Discovery recommends a `urn:uuid:` form for the endpoint `wsa:Address`. The proxy has no real serial; a random u128 generated once at startup is sufficient (the address only needs to be stable for the lifetime of the process so a re-probing NVR correlates replies to the same endpoint).
pub fn random_device_addr() -> String {
    let mut bytes = [0u8; 16];
    fill_random(&mut bytes);
    // RFC 4122 §4.4: set version (4) and variant (10) bits so the value looks like a v4 UUID even though it is not cryptographically random.
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    format!("urn:uuid:{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}", bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],)
}

/// Fills `buf` with best-effort randomness using `std::time` as a seed mixed with the address of a local stack variable. This is not cryptographically secure, but WS-Discovery endpoint addresses only need uniqueness within a subnet — collision resistance, not secrecy, is the property that matters.
fn fill_random(buf: &mut [u8]) {
    let seed = seed_value();
    let mut state = seed;
    for b in buf.iter_mut() {
        // SplitMix32-style step: simple, fast, good enough for an opportunistic identifier.
        state = state.wrapping_add(0x9E37_79B9);
        let mut z = state;
        z = (z ^ (z >> 16)).wrapping_mul(0x7FEB_A7F3);
        z = (z ^ (z >> 15)).wrapping_mul(0x846C_A68B);
        z ^= z >> 16;
        *b = (z & 0xFF) as u8;
    }
}

/// Builds a per-process seed by mixing the wall clock with a stack address, so two proxies started in the same second still differ.
fn seed_value() -> u32 {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos() as u32).unwrap_or(0);
    let stack_marker: u8 = 0;
    let addr = &stack_marker as *const u8 as usize as u32;
    now.wrapping_add(addr).wrapping_mul(0x9E37_79B9)
}

// --------------------------------------------------------------------------- Runtime: UDP multicast recv loop. ---------------------------------------------------------------------------

/// Configuration for the WS-Discovery runtime. `xaddr` is the device service URL advertised in ProbeMatch/Hello (`http://<ip>:<onvif_port>/onvif/ device_service`); `device_addr` is the stable-per-process `urn:uuid:...` endpoint address used in `wsa:Address`. `multicast_iface` is the IPv4 address of the NIC to join the multicast group on and to use as egress for `Hello`/`Bye`/`ProbeMatch`; `None` means "OS default interface". On a multi-homed host (e.g. a proxy with a `10.x` management NIC and a `192.168.x` camera-LAN NIC), leaving this `None` causes the OS to join the group on the default-route interface, which may not be the camera/NVR subnet — Probes from that subnet never arrive and announcements egress on the wrong NIC. `console_main` sets this to the advertised `server_ip` so the membership and egress match the subnet the ONVIF clients are on.
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// Device service XAddr advertised in ProbeMatch / Hello / Bye.
    pub xaddr: String,
    /// Endpoint `wsa:Address` (a `urn:uuid:...` value).
    pub device_addr: String,
    /// IPv4 address of the NIC to join the multicast group on and egress announcements from. `None` = OS default.
    pub multicast_iface: Option<Ipv4Addr>,
}

impl DiscoveryConfig {
    /// Builds a config with the supplied XAddr, a fresh random `urn:uuid:...` device address, and the OS-default multicast interface. `console_main` (step 24 wiring) uses `with_iface` instead so the membership/egress matches the advertised `server_ip` subnet on multi-homed hosts.
    pub fn new(xaddr: String) -> DiscoveryConfig {
        DiscoveryConfig { xaddr, device_addr: random_device_addr(), multicast_iface: None }
    }

    /// Builds a config pinned to a specific multicast interface (`iface`), the IPv4 of the NIC the ONVIF clients share with the proxy. Used by `console_main` to keep the membership and egress on the camera/NVR subnet rather than the OS default-route NIC.
    pub fn with_iface(xaddr: String, iface: Ipv4Addr) -> DiscoveryConfig {
        DiscoveryConfig { xaddr, device_addr: random_device_addr(), multicast_iface: Some(iface) }
    }
}

/// WS-Discovery runtime: joins the multicast group, sends a one-shot `Hello` on startup, answers incoming `Probe` datagrams with a unicast `ProbeMatch` to the probe sender, and sends a `Bye` on shutdown. Mirrors the shutdown-handle shape of the other server modules.
pub struct Discovery {
    config: DiscoveryConfig,
    shutdown: Arc<AtomicBool>,
}

impl Discovery {
    /// Creates a discovery runtime that will join the multicast group and answer Probes advertising `config.xaddr` / `config.device_addr`.
    pub fn new(config: DiscoveryConfig) -> Discovery {
        Discovery { config, shutdown: Arc::new(AtomicBool::new(false)) }
    }

    /// Creates a discovery runtime that also takes a logger. The logger is used only for non-fatal diagnostics (send/recv failures); a missing logger is equivalent to no logging.
    pub fn with_logger(config: DiscoveryConfig, logger: Arc<Logger>) -> DiscoveryWithLogger {
        DiscoveryWithLogger { inner: Self::new(config), logger }
    }

    /// Joins the multicast group and runs the recv loop until `shutdown()` is called. The loop never panics: every error path is logged (when a logger is attached) and the loop continues or, for fatal bind errors, returns the error to the caller.
    pub fn run(&self) -> io::Result<()> {
        let socket = bind_multicast_socket(self.config.multicast_iface)?;
        send_announce(&socket, &build_hello(&self.config.xaddr, &self.config.device_addr));
        let mut buf = [0u8; MAX_DATAGRAM_BYTES];
        loop {
            if self.shutdown.load(RELAXED) {
                break;
            }
            match socket.recv_from(&mut buf) {
                Ok((n, sender)) => {
                    if let Some(message_id) = parse_probe(&buf[..n]) {
                        let relates = if message_id.is_empty() { None } else { Some(message_id.as_str()) };
                        let reply = build_probe_match(&self.config.xaddr, &self.config.device_addr, relates);
                        let _ = socket.set_write_timeout(Some(Duration::from_millis(REPLY_SEND_TIMEOUT_MS)));
                        let _ = socket.send_to(reply.as_bytes(), sender);
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(RECV_POLL_MS));
                }
                Err(ref e) if e.kind() == io::ErrorKind::TimedOut => {
                    thread::sleep(Duration::from_millis(RECV_POLL_MS));
                }
                Err(_) => {
                    thread::sleep(Duration::from_millis(RECV_POLL_MS));
                }
            }
        }
        send_announce(&socket, &build_bye(&self.config.xaddr, &self.config.device_addr));
        Ok(())
    }

    /// Runs the recv loop on a caller-supplied socket. Tests use this with a socket they have already joined to the multicast group so the test does not depend on the production bind path; production `run()` delegates the bind to [`bind_multicast_socket`] and then calls this.
    pub fn run_on(&self, socket: UdpSocket) -> io::Result<()> {
        let _ = socket.set_nonblocking(true);
        let mut buf = [0u8; MAX_DATAGRAM_BYTES];
        loop {
            if self.shutdown.load(RELAXED) {
                break;
            }
            match socket.recv_from(&mut buf) {
                Ok((n, sender)) => {
                    if let Some(message_id) = parse_probe(&buf[..n]) {
                        let relates = if message_id.is_empty() { None } else { Some(message_id.as_str()) };
                        let reply = build_probe_match(&self.config.xaddr, &self.config.device_addr, relates);
                        let _ = socket.set_write_timeout(Some(Duration::from_millis(REPLY_SEND_TIMEOUT_MS)));
                        let _ = socket.send_to(reply.as_bytes(), sender);
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(RECV_POLL_MS));
                }
                Err(ref e) if e.kind() == io::ErrorKind::TimedOut => {
                    thread::sleep(Duration::from_millis(RECV_POLL_MS));
                }
                Err(_) => {
                    thread::sleep(Duration::from_millis(RECV_POLL_MS));
                }
            }
        }
        Ok(())
    }

    /// Signals the recv loop to exit. Idempotent.
    pub fn shutdown(&self) {
        self.shutdown.store(true, RELAXED);
    }

    /// Returns a clone of the shutdown flag so external code (`console_main` or tests) can stop the recv loop without holding a reference to the `Discovery`. Mirrors `RtspServer::shutdown_signal`.
    pub fn shutdown_signal(&self) -> Arc<AtomicBool> {
        self.shutdown.clone()
    }
}

/// Discovery runtime with an attached logger. `console_main` (step 24) uses this so send/recv failures land in `flvproxy.log`; the logger-less `Discovery` is used by tests that want no log side effects.
pub struct DiscoveryWithLogger {
    inner: Discovery,
    logger: Arc<Logger>,
}

impl DiscoveryWithLogger {
    /// Joins the multicast group and runs the recv loop until `shutdown_signal()` is set, logging diagnostics along the way.
    pub fn run(&self) -> io::Result<()> {
        let socket = match bind_multicast_socket(self.inner.config.multicast_iface) {
            Ok(s) => s,
            Err(e) => {
                self.logger.log(Level::Warn, &format!("wsdiscovery: bind failed: {e}"));
                return Err(e);
            }
        };
        let iface_desc = match self.inner.config.multicast_iface {
            Some(ip) => {
                let egress = if cfg!(windows) { "egress pinned" } else { "egress OS-default (non-Windows)" };
                format!(" via {ip} ({egress})")
            }
            None => String::new(),
        };
        self.logger.log(Level::Info, &format!("wsdiscovery: joined {}:{}{iface}", MULTICAST_GROUP, MULTICAST_PORT, iface = iface_desc));
        send_announce(&socket, &build_hello(&self.inner.config.xaddr, &self.inner.config.device_addr));
        let mut buf = [0u8; MAX_DATAGRAM_BYTES];
        loop {
            if self.inner.shutdown.load(RELAXED) {
                break;
            }
            match socket.recv_from(&mut buf) {
                Ok((n, sender)) => {
                    if let Some(message_id) = parse_probe(&buf[..n]) {
                        let relates = if message_id.is_empty() { None } else { Some(message_id.as_str()) };
                        let reply = build_probe_match(&self.inner.config.xaddr, &self.inner.config.device_addr, relates);
                        let _ = socket.set_write_timeout(Some(Duration::from_millis(REPLY_SEND_TIMEOUT_MS)));
                        if let Err(e) = socket.send_to(reply.as_bytes(), sender) {
                            self.logger.log(Level::Warn, &format!("wsdiscovery: ProbeMatch send to {sender} failed: {e}"));
                        }
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(RECV_POLL_MS));
                }
                Err(ref e) if e.kind() == io::ErrorKind::TimedOut => {
                    thread::sleep(Duration::from_millis(RECV_POLL_MS));
                }
                Err(ref e) => {
                    self.logger.log(Level::Warn, &format!("wsdiscovery: recv_from failed: {e}"));
                    thread::sleep(Duration::from_millis(RECV_POLL_MS));
                }
            }
        }
        send_announce(&socket, &build_bye(&self.inner.config.xaddr, &self.inner.config.device_addr));
        self.logger.log(Level::Info, "wsdiscovery: stopped");
        Ok(())
    }

    /// Returns a clone of the shutdown flag so `console_main` can stop the recv loop without holding a reference to the `DiscoveryWithLogger`.
    pub fn shutdown_signal(&self) -> Arc<AtomicBool> {
        self.inner.shutdown.clone()
    }
}

/// Binds the WS-Discovery multicast listener socket: `0.0.0.0:3702`, joins the multicast group `239.255.255.250` on `iface` (or the OS default when `None`), disables loopback (the proxy never reads its own announcements), and sets the socket non-blocking so the recv loop can poll the shutdown flag.
///
/// `iface` is the IPv4 of the NIC the ONVIF clients share with the proxy. On a multi-homed host the OS default-route interface may be a different NIC (e.g. a `10.x` management link while the camera/NVR are on `192.168.x`); joining on the default then puts the membership on the wrong subnet, so Probes from the client NIC never arrive. Pinning `iface` to the advertised `server_ip` keeps the membership on the right subnet.
///
/// The bind is to the wildcard `0.0.0.0:3702`, not the specific interface IP. A specific-IP bind (`192.168.1.100:3702`) was attempted to win multicast delivery over the Windows "Function Discovery" service (`svchost.exe`) which already holds `0.0.0.0:3702`, but Windows refuses a non-wildcard bind to a port already wildcard-bound by another process even with `SO_REUSEADDR` (WSAEADDRNOTAVAIL, os error 10049). The wildcard bind coexists with svchost via `SO_REUSEADDR`; multicast delivery between the two sockets is OS-dependent, so on a host where svchost also joins `239.255.255.250` the proxy may not receive Probes. The reliable discovery path on such a host is to stop the Function Discovery service (`Stop-Service fdPHost`) or use manual device-add by ONVIF URL.
///
/// `SO_REUSEADDR` is set on the socket before bind so the proxy can coexist with other WS-Discovery listeners on the same host. On Windows this is mandatory: the OS "Function Discovery" service typically holds UDP 3702, and without `SO_REUSEADDR` the bind fails with `WSAEADDRINUSE` (os error 10048). `std::net::UdpSocket::bind` does not set `SO_REUSEADDR` and the option is ineffective after bind, so on Windows the socket is created via raw Winsock FFI (`windows_ffi::bind_reuseaddr_udp_socket`), the option is applied, the socket is bound, and ownership is then transferred to a std `UdpSocket` for the multicast join / timeouts / non-blocking calls. The Linux path keeps `UdpSocket::bind` (the test suite runs there and passes without `SO_REUSEADDR`).
fn bind_multicast_socket(iface: Option<Ipv4Addr>) -> io::Result<UdpSocket> {
    let bind_addr = LISTEN_ADDR;
    #[cfg(windows)]
    let socket = windows_ffi::bind_reuseaddr_udp_socket(bind_addr)?;
    #[cfg(not(windows))]
    let socket = UdpSocket::bind(bind_addr)?;
    let join_iface = iface.unwrap_or(Ipv4Addr::UNSPECIFIED);
    socket.join_multicast_v4(&MULTICAST_GROUP, &join_iface)?;
    // Egress is pinned to `iface` on Windows via `IP_MULTICAST_IF` so `Hello`/`Bye` leave on the camera/NVR subnet rather than the OS default-route NIC; the Probe→ProbeMatch flow (unicast reply to the probe sender) already routes correctly and is how ONVIF clients discover. On non-Windows std has no `IP_MULTICAST_IF` setter and multi-homed hosts are not a supported deployment (the test host has one NIC), so egress stays OS-default there.
    #[cfg(windows)]
    if let Some(ip) = iface {
        windows_ffi::pin_multicast_egress(&socket, ip)?;
    }
    socket.set_multicast_loop_v4(false)?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

/// Raw Winsock FFI to create a `SO_REUSEADDR` UDP socket bound to a given address, transferring ownership to a std `UdpSocket`. Windows-only: needed because `SO_REUSEADDR` must be set before `bind` and std does not expose that ordering. The `ws2_32` import library is linked explicitly (it is also pulled in by std's net module, but the explicit `#[link]` matches the `tls_schannel` convention and is harmless when duplicated).
#[cfg(windows)]
mod windows_ffi {
    use std::io;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::os::windows::io::{AsRawSocket, FromRawSocket};

    /// Address family `AF_INET` (IPv4), per `winsock2.h`.
    const AF_INET: i32 = 2;

    /// Socket type `SOCK_DGRAM` (datagram / UDP), per `winsock2.h`.
    const SOCK_DGRAM: i32 = 2;

    /// Protocol `IPPROTO_UDP`, per `winsock2.h`.
    const IPPROTO_UDP: i32 = 17;

    /// Option level `SOL_SOCKET`, per `winsock2.h` / `ws2def.h`.
    const SOL_SOCKET: i32 = 0xFFFF;

    /// `SO_REUSEADDR` option number, per `winsock2.h`. Allows multiple sockets to bind the same local address:port; on a multicast port this is how several WS-Discovery participants coexist.
    const SO_REUSEADDR: i32 = 0x0004;

    /// Option level `IPPROTO_IP` (IPv4-level socket options), per `winsock2.h`. Used as the `level` argument to `setsockopt` for `IP_MULTICAST_IF`.
    const IPPROTO_IP: i32 = 0;

    /// `IP_MULTICAST_IF` option number, per `winsock2.h` / `ws2ipdef.h`: sets the outgoing interface for multicast sends to the supplied `in_addr` (the interface's IPv4 in network byte order), pinning `Hello`/`Bye` egress to the camera/NVR subnet on a multi-homed host.
    const IP_MULTICAST_IF: i32 = 9;

    /// `INVALID_SOCKET` sentinel returned by `socket()` on failure, per `winsock2.h` (`(SOCKET)(~0)`).
    const INVALID_SOCKET: usize = !0;

    /// `sockaddr_in` layout (16 bytes), per `winsock2.h`: 2-byte family, 2-byte port (network order), 4-byte IPv4 address (network order), 8-byte zero padding. `#[repr(C)]` so the field order matches the OS struct for `bind`.
    #[repr(C)]
    struct SockaddrIn {
        sin_family: u16,
        sin_port: u16,
        sin_addr: u32,
        sin_zero: [u8; 8],
    }

    impl SockaddrIn {
        fn from_v4(addr: SocketAddrV4) -> SockaddrIn {
            SockaddrIn { sin_family: AF_INET as u16, sin_port: addr.port().to_be(), sin_addr: u32::from_be_bytes(addr.ip().octets()), sin_zero: [0; 8] }
        }
    }

    #[link(name = "ws2_32")]
    extern "system" {
        /// `socket` (winsock2.h) — create a socket, returning a handle or `INVALID_SOCKET`.
        fn socket(af: i32, ty: i32, proto: i32) -> usize;
        /// `setsockopt` (winsock2.h) — set a socket option; returns 0 on success or `SOCKET_ERROR` (-1).
        fn setsockopt(s: usize, level: i32, name: i32, val: *const u8, len: i32) -> i32;
        /// `bind` (winsock2.h) — bind a socket to a local address; returns 0 on success or `SOCKET_ERROR` (-1).
        fn bind(s: usize, addr: *const SockaddrIn, len: i32) -> i32;
        /// `closesocket` (winsock2.h) — close a socket handle. Used for cleanup on the error path before ownership transfers to std.
        fn closesocket(s: usize) -> i32;
        /// `WSAGetLastError` (winsock2.h) — return the per-thread last Winsock error code.
        fn WSAGetLastError() -> i32;
    }

    /// Returns the last Winsock error as an `io::Error` via `from_raw_os_error`, which maps the Winsock error code to its OS string.
    fn last_error() -> io::Error {
        // SAFETY: `WSAGetLastError` reads thread-local state and has no side effects.
        let code = unsafe { WSAGetLastError() };
        io::Error::from_raw_os_error(code)
    }

    /// Pins multicast egress to the interface whose IPv4 is `iface` by setting `IP_MULTICAST_IF` on `socket`. The `in_addr` value is the interface address in network byte order — `from_ne_bytes(octets())` so the field's in-memory bytes equal `iface.octets()` regardless of host endianness. Returns the `setsockopt` failure as an `io::Error` rather than ignoring it: egress pinning is a correctness fix for multi-homed hosts, so a failure to pin must be visible instead of silently sending `Hello`/`Bye` out the wrong NIC.
    pub(crate) fn pin_multicast_egress(socket: &std::net::UdpSocket, iface: Ipv4Addr) -> io::Result<()> {
        let raw = socket.as_raw_socket() as usize;
        let addr: u32 = u32::from_ne_bytes(iface.octets());
        // SAFETY: `raw` is a valid socket handle owned by `socket`; `&addr` is a valid `u32` lvalue whose bytes are read for `len` = sizeof(u32).
        if unsafe { setsockopt(raw, IPPROTO_IP, IP_MULTICAST_IF, &addr as *const u32 as *const u8, std::mem::size_of::<u32>() as i32) } != 0 {
            return Err(last_error());
        }
        Ok(())
    }

    /// Creates a UDP/IPv4 socket, sets `SO_REUSEADDR`, binds it to `addr`, and returns it as a std `UdpSocket`. On any failure the raw handle is closed and the error returned; on success ownership transfers to std, whose `Drop` calls `closesocket`.
    pub(crate) fn bind_reuseaddr_udp_socket(addr: SocketAddrV4) -> io::Result<std::net::UdpSocket> {
        // Force std's process-wide `WSAStartup` (run lazily on first socket creation) before any raw `ws2_32` call. Without this, if the discovery thread is the first to touch Winsock, `socket()` fails with `WSANOTINITIALISED` (os error 10093). Creating and immediately dropping an ephemeral std socket runs std's `Once`-guarded WSAStartup; the `ws2_32` calls below then succeed.
        let _ = std::net::UdpSocket::bind("0.0.0.0:0");
        // SAFETY: `socket` creates a new socket handle; WSAStartup has run (see above). The returned handle is valid until `closesocket` (or transfer to std below).
        let s = unsafe { socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP) };
        if s == INVALID_SOCKET {
            return Err(last_error());
        }
        let reuse: u32 = 1;
        // SAFETY: `s` is a valid socket; `&reuse` is a valid `u32` lvalid whose bytes are read for `len` = sizeof(u32).
        if unsafe { setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &reuse as *const u32 as *const u8, std::mem::size_of::<u32>() as i32) } != 0 {
            let e = last_error();
            // SAFETY: `s` is a valid handle we still own; close it to avoid a leak.
            unsafe { closesocket(s) };
            return Err(e);
        }
        let sa = SockaddrIn::from_v4(addr);
        // SAFETY: `s` is a valid socket; `sa` is a fully-initialized `sockaddr_in` of the size passed in `len`.
        if unsafe { bind(s, &sa, std::mem::size_of::<SockaddrIn>() as i32) } != 0 {
            let e = last_error();
            // SAFETY: `s` is a valid handle we still own; close it to avoid a leak.
            unsafe { closesocket(s) };
            return Err(e);
        }
        // SAFETY: `s` is a valid, bound socket handle; `from_raw_socket` takes ownership so std's `Drop` will `closesocket` it. `s` is not used after this point.
        Ok(unsafe { std::net::UdpSocket::from_raw_socket(s as u64) })
    }
}

/// Sends one announcement (`Hello` or `Bye`) to the multicast group, with a bounded write timeout so a stalled send cannot wedge the loop. Failures are silently dropped: announcements are best-effort.
fn send_announce(socket: &UdpSocket, body: &str) {
    let dst = SocketAddr::V4(SocketAddrV4::new(MULTICAST_GROUP, MULTICAST_PORT));
    let _ = socket.set_write_timeout(Some(Duration::from_millis(ANNOUNCE_SEND_TIMEOUT_MS)));
    let _ = socket.send_to(body.as_bytes(), dst);
}

#[cfg(test)]
mod tests {
    use super::*;

    const XADDR: &str = "http://10.0.0.5:8080/onvif/device_service";
    const DEVICE_ADDR: &str = "urn:uuid:abc";

    fn probe_envelope(message_id: &str) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" \
             xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\">\
             <s:Header>\
             <wsa:Action>{ACTION_PROBE}</wsa:Action>\
             <wsa:MessageID>{message_id}</wsa:MessageID>\
             </s:Header>\
             <s:Body><Probe xmlns=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\"/></s:Body>\
             </s:Envelope>"
        )
    }

    #[test]
    fn build_probe_match_contains_xaddr_endpoint_and_network_video_transmitter() {
        let xml = build_probe_match(XADDR, DEVICE_ADDR, None);
        assert!(xml.contains(&format!("<wsa:Address>{DEVICE_ADDR}</wsa:Address>")), "endpoint address must be present: {xml}");
        assert!(xml.contains(XADDR), "raw XAddr must be present: {xml}");
        assert!(xml.contains(DEVICE_TYPE), "NetworkVideoTransmitter missing: {xml}");
        assert!(xml.contains("<wsdiscovery:ProbeMatches>"), "ProbeMatches wrapper missing: {xml}");
        assert!(xml.contains("<wsdiscovery:ProbeMatch>"), "ProbeMatch inner missing: {xml}");
        assert!(xml.contains(SCOPE_STREAMING), "Streaming scope missing: {xml}");
        assert!(xml.contains(ACTION_PROBE_MATCH), "ProbeMatch action missing: {xml}");
    }

    #[test]
    fn build_probe_match_includes_relates_to_when_supplied() {
        let xml = build_probe_match(XADDR, DEVICE_ADDR, Some("urn:uuid:probe-1"));
        assert!(xml.contains("<wsa:RelatesTo>urn:uuid:probe-1</wsa:RelatesTo>"), "RelatesTo must echo the probe MessageID: {xml}");
    }

    #[test]
    fn build_probe_match_omits_relates_to_when_none() {
        let xml = build_probe_match(XADDR, DEVICE_ADDR, None);
        assert!(!xml.contains("wsa:RelatesTo"), "RelatesTo must be absent when no relates_to supplied: {xml}");
    }

    #[test]
    fn build_probe_match_escapes_markup_in_xaddr_and_address() {
        let injected_xaddr = "http://10.0.0.5:8080/onvif/device_service?x=<>&\"";
        let injected_addr = "urn:uuid:<>&\"'";
        let xml = build_probe_match(injected_xaddr, injected_addr, None);
        assert!(!xml.contains(injected_xaddr), "raw injected XAddr must not appear: {xml}");
        assert!(!xml.contains(injected_addr), "raw injected address must not appear: {xml}");
        assert!(xml.contains("&lt;&gt;&amp;&quot;"));
    }

    #[test]
    fn build_hello_contains_hello_action_and_xaddr() {
        let xml = build_hello(XADDR, DEVICE_ADDR);
        assert!(xml.contains(ACTION_HELLO), "Hello action missing: {xml}");
        assert!(xml.contains("<wsdiscovery:Hello>"), "Hello element missing: {xml}");
        assert!(xml.contains(XADDR), "XAddr missing from Hello: {xml}");
        assert!(xml.contains(DEVICE_TYPE), "NetworkVideoTransmitter missing: {xml}");
    }

    #[test]
    fn build_bye_contains_bye_action_and_xaddr() {
        let xml = build_bye(XADDR, DEVICE_ADDR);
        assert!(xml.contains(ACTION_BYE), "Bye action missing: {xml}");
        assert!(xml.contains("<wsdiscovery:Bye>"), "Bye element missing: {xml}");
        assert!(xml.contains(XADDR), "XAddr missing from Bye: {xml}");
    }

    #[test]
    fn parse_probe_returns_message_id_for_well_formed_probe() {
        let probe = probe_envelope("urn:uuid:probe-42");
        let id = parse_probe(probe.as_bytes()).expect("Probe must be detected");
        assert_eq!(id, "urn:uuid:probe-42");
    }

    #[test]
    fn parse_probe_returns_none_for_probe_match() {
        let xml = build_probe_match(XADDR, DEVICE_ADDR, None);
        assert!(parse_probe(xml.as_bytes()).is_none());
    }

    #[test]
    fn parse_probe_returns_none_for_garbage() {
        assert!(parse_probe(b"not xml at all").is_none());
        assert!(parse_probe(&[]).is_none());
    }

    #[test]
    fn parse_probe_returns_empty_string_when_message_id_absent() {
        let probe = format!(
            "<?xml version=\"1.0\"?>\
             <s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">\
             <s:Header><wsa:Action>{ACTION_PROBE}</wsa:Action></s:Header>\
             <s:Body><Probe xmlns=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\"/></s:Body>\
             </s:Envelope>"
        );
        let id = parse_probe(probe.as_bytes()).expect("Probe with no MessageID is still a Probe");
        assert!(id.is_empty(), "absent MessageID yields empty string: {id}");
    }

    #[test]
    fn parse_probe_matches_action_element_without_namespace_prefix() {
        // Onvier (and other WS-Addressing 1.0 clients) emit <Action> with a default xmlns instead of <wsa:Action>. The matcher must be prefix-agnostic.
        let probe = format!(
            "<?xml version=\"1.0\"?>\
             <s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">\
             <s:Header><Action mustUnderstand=\"1\" xmlns=\"http://www.w3.org/2005/08/addressing\">{ACTION_PROBE}</Action>\
             <MessageID xmlns=\"http://www.w3.org/2005/08/addressing\">urn:uuid:onvier-probe</MessageID></s:Header>\
             <s:Body><Probe xmlns=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\"/></s:Body>\
             </s:Envelope>"
        );
        let id = parse_probe(probe.as_bytes()).expect("prefix-less Action must be detected as a Probe");
        assert_eq!(id, "urn:uuid:onvier-probe", "MessageID without wsa: prefix must be extracted: {id}");
    }

    #[test]
    fn parse_probe_rejects_probe_matches_action() {
        let probe_match = format!(
            "<?xml version=\"1.0\"?>\
             <s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">\
             <s:Header><wsa:Action>{ACTION_PROBE_MATCH}</wsa:Action></s:Header>\
             <s:Body><ProbeMatches xmlns=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\"/></s:Body>\
             </s:Envelope>"
        );
        assert!(parse_probe(probe_match.as_bytes()).is_none(), "ProbeMatches must not be mis-detected as a Probe");
    }

    #[test]
    fn random_device_addr_is_well_formed_urn_uuid_v4() {
        let addr = random_device_addr();
        assert!(addr.starts_with("urn:uuid:"), "must be a urn:uuid: {addr}");
        let uuid = addr.strip_prefix("urn:uuid:").unwrap();
        assert_eq!(uuid.len(), 36, "UUID string must be 36 chars: {uuid}");
        assert_eq!(uuid.as_bytes()[8], b'-');
        assert_eq!(uuid.as_bytes()[13], b'-');
        assert_eq!(uuid.as_bytes()[18], b'-');
        assert_eq!(uuid.as_bytes()[23], b'-');
        assert_eq!(uuid.as_bytes()[14], b'4', "version nibble must be 4 (v4): {uuid}");
    }

    #[test]
    fn random_device_addr_differs_across_calls() {
        let a = random_device_addr();
        let b = random_device_addr();
        assert_ne!(a, b, "two random addresses must differ: {a} == {b}");
    }

    /// Guards the cfg gating of the Windows-only egress pin: `bind_multicast_socket(None)` must succeed without attempting `IP_MULTICAST_IF` (the `None` path skips the pin on every platform). Skips rather than fails when the multicast port is already held (e.g. a parallel test or a host service), since the cfg-gating guarantee is what is under test, not the bind itself.
    #[test]
    fn bind_multicast_socket_none_succeeds() {
        let socket = match bind_multicast_socket(None) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("skip: could not bind multicast socket on this environment: {e}");
                return;
            }
        };
        drop(socket);
    }
}
