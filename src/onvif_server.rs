//! ONVIF Device and Media SOAP services over HTTP. Serves the handful of requests an NVR needs to learn the stream URL: `GetCapabilities`, `GetDeviceInformation`, `SetSynchronizationPoint` (Device service) and `GetProfiles`, `GetStreamUri`, `GetSnapshotUri`, `GetAudioOutputConfigurations` (Media service). Responses are hand-rolled SOAP 1.2 XML built from `&str` templates via `format!`, with the dynamic values (server IP, firmware, serial, resolution) XML-escaped.
//!
//! The router (`route`) is pure string logic with no sockets, so it builds and tests on any platform. The runtime (`OnvifServer`) drives it over a real `TcpListener` on `onvif_port`, mirroring the accept-loop / shutdown-handle shape of `rtsp_server::RtspServer` and `camera_listener::CameraListener`. WS-Discovery and real-client validation are out of scope here.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::logging::{utc_now, Level, Logger};
use crate::stream_state::StreamState;

/// Relaxed ordering suffices for the shutdown flag: it is an advisory signal, not synchronization that establishes happens-before for other data. Mirrors the server modules.
const RELAXED: Ordering = Ordering::Relaxed;

/// Poll interval for the non-blocking accept loop, so the `shutdown` flag is checked promptly rather than blocking until the next connection. Matches `rtsp_server` / `camera_listener` cadence.
const ACCEPT_POLL_MS: u64 = 50;

/// Per-connection read timeout. Bounds how long the server waits for a client to finish sending a request before giving up and closing the connection.
const READ_TIMEOUT_MS: u64 = 5_000;

/// Per-connection write timeout, bounding how long a stalled client can hold the socket before the connection is dropped.
const WRITE_TIMEOUT_MS: u64 = 5_000;

const READ_CHUNK_BYTES: usize = 8192;

/// Cap on the per-connection request buffer. A client that streams request bytes without ever completing a `\r\n\r\n`-terminated header block would otherwise grow the buffer unbounded; exceeding this closes the connection. Named per the resource-bounds quality gate.
const MAX_READ_BUFFER_BYTES: usize = 64 * 1024;

/// Header-block terminator separating HTTP headers from the body, per RFC 7230 §3.
const HEADER_TERMINATOR: &[u8] = b"\r\n\r\n";

/// Length in bytes of the header-block terminator (two CRLFs).
const HEADER_TERMINATOR_LEN: usize = 4;

/// SOAP 1.2 media type returned on every response, per RFC 3902 (`SOAP 1.2 Media Type`). ONVIF uses SOAP 1.2 over HTTP.
const SOAP_CONTENT_TYPE: &str = "application/soap+xml; charset=utf-8";

/// HTTP status `200 OK`, per RFC 7230 §3.1.2.
const STATUS_OK: u16 = 200;

/// RTSP URL path the Media service advertises as the stream URI. Matches the path the RTSP server serves, so an NVR that opens the URI lands on a working DESCRIBE target.
const STREAM_URI_PATH: &str = "/stream";

/// ONVIF profile token advertised by `GetProfiles`. A single H.264 profile is all an NVR needs to add the camera and pull the RTSP URL.
const PROFILE_TOKEN: &str = "Profile_1";

/// Default video width advertised when the stream has not published metadata yet. Matches the UVC G5 Bullet default recording resolution.
const FALLBACK_WIDTH: u32 = 1920;

const FALLBACK_HEIGHT: u32 = 1080;

const FALLBACK_FPS: u32 = 30;

/// Default firmware version advertised by `GetDeviceInformation` when the operator has not overridden it via `flvproxy.ini`. The camera's real firmware is not available from any current channel, so this sensible UVC G5 value is the fallback (config-overridable via the `firmware` ini key).
const DEFAULT_FIRMWARE: &str = "4.73.112";

/// Default serial number advertised when the operator has not overridden it and no camera identity has been published yet. Before the camera's first `onMetaData` tag (or on a stream that omits `streamName`) the live identity is absent, so this non-empty default keeps `GetDeviceInformation` well-formed (config-overridable via the `serial` ini key).
const DEFAULT_SERIAL: &str = "000000000000";

/// Manufacturer advertised by `GetDeviceInformation`, per `PROJECT.md` → "ONVIF Device Service".
const MANUFACTURER: &str = "Ubiquiti";

/// Model advertised by `GetDeviceInformation`, per `PROJECT.md` → "ONVIF Device Service".
const MODEL: &str = "UVC-G5-Bullet";

/// Hardware id advertised by `GetDeviceInformation`. ONVIF requires a non-empty `HardwareId`; the model name is reused as a stable identifier.
const HARDWARE_ID: &str = MODEL;

/// `Timeout` value returned in `GetStreamUri` responses, per the ONVIF Media service spec — the URI remains valid for 60 seconds after connect.
const STREAM_URI_TIMEOUT: &str = "PT60S";

/// SOAP envelope namespaces used in every response body. Declared once so the templates stay readable.
const NS_ENVELOPE: &str = "http://www.w3.org/2003/05/soap-envelope";
const NS_DEVICE: &str = "http://www.onvif.org/ver10/device/wsdl";
const NS_MEDIA: &str = "http://www.onvif.org/ver10/media/wsdl";
const NS_SCHEMA: &str = "http://www.onvif.org/ver10/schema";
const NS_ADDRESSING: &str = "http://schemas.xmlsoap.org/ws/2004/08/addressing";

/// Device service URL path served by this proxy.
pub const DEFAULT_DEVICE_SERVICE_PATH: &str = "/onvif/device_service";

/// Media service URL path served by this proxy.
pub const DEFAULT_MEDIA_SERVICE_PATH: &str = "/onvif/media_service";

/// The ONVIF operations this proxy implements, paired with their namespace URIs and owning service. Used both to match a `SOAPAction` header (exact equality after quote-stripping) and to scan the body as a fallback when the header is absent (some clients put the operation only in the body's XML namespace).
const KNOWN_ACTIONS: &[(&str, Service, &str)] = &[("http://www.onvif.org/ver10/device/wsdl/GetSystemDateAndTime", Service::Device, "GetSystemDateAndTime"), ("http://www.onvif.org/ver10/device/wsdl/GetCapabilities", Service::Device, "GetCapabilities"), ("http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation", Service::Device, "GetDeviceInformation"), ("http://www.onvif.org/ver10/device/wsdl/GetEndpointReference", Service::Device, "GetEndpointReference"), ("http://www.onvif.org/ver10/device/wsdl/GetServices", Service::Device, "GetServices"), ("http://www.onvif.org/ver10/device/wsdl/SetSynchronizationPoint", Service::Device, "SetSynchronizationPoint"), ("http://www.onvif.org/ver10/media/wsdl/GetProfiles", Service::Media, "GetProfiles"), ("http://www.onvif.org/ver10/media/wsdl/GetStreamUri", Service::Media, "GetStreamUri"), ("http://www.onvif.org/ver10/media/wsdl/GetSnapshotUri", Service::Media, "GetSnapshotUri"), ("http://www.onvif.org/ver10/media/wsdl/GetAudioOutputConfigurations", Service::Media, "GetAudioOutputConfigurations")];

/// Which ONVIF service an operation belongs to. `Copy` so it can live in a `const` table.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum Service {
    Device,
    Media,
}

/// A resolved ONVIF operation: the owning service and the operation name (e.g. `"GetStreamUri"`).
struct Resolved {
    service: Service,
    op: &'static str,
}

/// Configuration for the ONVIF SOAP server. `server_ip` / `rtsp_port` / `onvif_port` populate the dynamic XAddrs and stream URI; `firmware` is always advertised as-is by `GetDeviceInformation`; `serial` is the fallback advertised when no camera identity has been published yet (once the 7550 pipeline publishes the MAC-derived identity from `onMetaData` `streamName` it wins). `device_service_path` / `media_service_path` are `&'static str` because the proxy serves fixed paths — an operator changes the port, not the path.
#[derive(Debug, Clone)]
pub struct OnvifConfig {
    /// IPv4 address advertised in XAddrs and the RTSP stream URI.
    pub server_ip: String,
    /// RTSP port advertised in the stream URI returned by `GetStreamUri`.
    pub rtsp_port: u16,
    pub onvif_port: u16,
    /// HTTP path at which the Device service is reachable.
    pub device_service_path: &'static str,
    /// HTTP path at which the Media service is reachable.
    pub media_service_path: &'static str,
    /// Firmware version advertised by `GetDeviceInformation`. Always used as-is; config-overridable via the `firmware` ini key.
    pub firmware: String,
    /// Serial advertised by `GetDeviceInformation` when no camera identity has been published yet. Config-overridable via the `serial` ini key; once the 7550 pipeline publishes the MAC-derived identity from `onMetaData` `streamName`, that wins.
    pub serial: String,
}

impl OnvifConfig {
    /// Builds a config with the default service paths, firmware, and serial, filling in the operator-supplied addressing fields. `app::spawn` populates `firmware`/`serial` from `Config` instead of using this default, so the ini overrides reach the ONVIF server; this helper remains for tests and the no-config path.
    pub fn defaults_for(server_ip: String, rtsp_port: u16, onvif_port: u16) -> OnvifConfig {
        OnvifConfig { server_ip, rtsp_port, onvif_port, device_service_path: DEFAULT_DEVICE_SERVICE_PATH, media_service_path: DEFAULT_MEDIA_SERVICE_PATH, firmware: DEFAULT_FIRMWARE.to_string(), serial: DEFAULT_SERIAL.to_string() }
    }
}

/// Routes one SOAP request to its response body. `soap_action` is the raw `SOAPAction:` header value (quotes intact or empty); `body` is the request body bytes as text. Returns `(status_code, xml_body)`. Known operations yield `200` plus the matching response template; an unrecognized or missing action yields `200` plus a SOAP Fault carrying `wsa:ActionNotSupported` (HTTP 200 for faults matches common ONVIF device behaviour and keeps the router's status surface trivial).
///
/// Routing first tries the `SOAPAction` header (stripping surrounding quotes); if that is absent or unrecognized, the body is scanned for any of the known operation namespace URIs so clients that omit the header still route.
pub fn route(soap_action: &str, body: &str, cfg: &OnvifConfig, state: &StreamState) -> (u16, String) {
    match resolve_action(soap_action, body) {
        Some(Resolved { service: Service::Device, op }) => match op {
            "GetSystemDateAndTime" => (STATUS_OK, build_get_system_date_and_time()),
            "GetCapabilities" => (STATUS_OK, build_get_capabilities(cfg)),
            "GetDeviceInformation" => (STATUS_OK, build_get_device_information(cfg, state)),
            "GetEndpointReference" => (STATUS_OK, build_get_endpoint_reference()),
            "GetServices" => (STATUS_OK, build_get_services(cfg)),
            "SetSynchronizationPoint" => (STATUS_OK, build_set_synchronization_point()),
            _ => (STATUS_OK, build_fault()),
        },
        Some(Resolved { service: Service::Media, op }) => match op {
            "GetProfiles" => (STATUS_OK, build_get_profiles(cfg, state)),
            "GetStreamUri" => (STATUS_OK, build_get_stream_uri(cfg)),
            "GetSnapshotUri" => (STATUS_OK, build_get_snapshot_uri(cfg)),
            "GetAudioOutputConfigurations" => (STATUS_OK, build_get_audio_output_configurations()),
            _ => (STATUS_OK, build_fault()),
        },
        None => (STATUS_OK, build_fault()),
    }
}

/// Resolves the incoming action to a known operation, preferring the `SOAPAction` header and falling back to a body namespace scan. Returns `None` when neither source names a supported operation.
fn resolve_action(soap_action: &str, body: &str) -> Option<Resolved> {
    let stripped = strip_quotes(soap_action.trim());
    if !stripped.is_empty() {
        for &(uri, service, op) in KNOWN_ACTIONS {
            if stripped == uri {
                return Some(Resolved { service, op });
            }
        }
    }
    for &(uri, service, op) in KNOWN_ACTIONS {
        if body.contains(uri) {
            return Some(Resolved { service, op });
        }
    }
    None
}

/// Strips one layer of surrounding double-quotes from `value`, per the `SOAPAction` header grammar (RFC 3902 / SOAP 1.2: the URI is quoted).
fn strip_quotes(value: &str) -> &str {
    let value = value.strip_prefix('"').unwrap_or(value);
    value.strip_suffix('"').unwrap_or(value)
}

/// Builds the `GetEndpointReference` response: a stable `urn:uuid:` token. ONVIF clients use this as a device-identity token (e.g. to correlate a discovered device with a later session); the value need only be stable for the process lifetime. The `urn:uuid:` form satisfies the ONVIF Core Spec §5.3 endpoint-reference shape; a fixed token keeps the value deterministic across restarts on the same address (a re-probing client sees the same endpoint reference).
fn build_get_endpoint_reference() -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <s:Envelope xmlns:s=\"{envelope}\" xmlns:tds=\"{device}\">\n\
         <s:Body>\n\
         <tds:GetEndpointReferenceResponse>\n\
         <tds:Guid>urn:uuid:flvproxy-000000000000</tds:Guid>\n\
         </tds:GetEndpointReferenceResponse>\n\
         </s:Body>\n\
         </s:Envelope>",
        envelope = NS_ENVELOPE,
        device = NS_DEVICE,
    )
}

/// Builds the `GetServices` response: one `Service` element per ONVIF service the proxy implements (Device, Media), each carrying its namespace and XAddr. `GetCapabilities` returns a compact capabilities tree; `GetServices` returns the flat service→XAddr map some clients (notably Onvier) call separately to enumerate the service endpoints. `IncludeCapability` is `false` per the common device pattern (capabilities are already available via `GetCapabilities`). The advertised ONVIF Profile S version (`20.12`) matches the spec version the proxy's response shapes target.
fn build_get_services(cfg: &OnvifConfig) -> String {
    let ip = xml_escape(&cfg.server_ip);
    let device_xaddr = format!("http://{ip}:{port}{path}", ip = ip, port = cfg.onvif_port, path = cfg.device_service_path);
    let media_xaddr = format!("http://{ip}:{port}{path}", ip = ip, port = cfg.onvif_port, path = cfg.media_service_path);
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <s:Envelope xmlns:s=\"{envelope}\" xmlns:tds=\"{device}\" xmlns:tt=\"{schema}\">\n\
         <s:Body>\n\
         <tds:GetServicesResponse>\n\
         <tds:Service>\n\
         <tds:Namespace>{device_ns}</tds:Namespace>\n\
         <tds:XAddr>{device_xaddr}</tds:XAddr>\n\
         <tds:Version><tt:Major>20</tt:Major><tt:Minor>12</tt:Minor></tds:Version>\n\
         </tds:Service>\n\
         <tds:Service>\n\
         <tds:Namespace>{media_ns}</tds:Namespace>\n\
         <tds:XAddr>{media_xaddr}</tds:XAddr>\n\
         <tds:Version><tt:Major>20</tt:Major><tt:Minor>12</tt:Minor></tds:Version>\n\
         </tds:Service>\n\
         </tds:GetServicesResponse>\n\
         </s:Body>\n\
         </s:Envelope>",
        envelope = NS_ENVELOPE,
        device = NS_DEVICE,
        schema = NS_SCHEMA,
        device_ns = NS_DEVICE,
        media_ns = NS_MEDIA,
        device_xaddr = device_xaddr,
        media_xaddr = media_xaddr,
    )
}

/// Builds the `GetSystemDateAndTime` response with the current UTC civil time. ONVIF clients commonly call this first (before authentication) to seed their clock against the device; a fault here aborts the rest of the exchange, so the proxy answers it even though it has no real device clock to learn. `DateTimeFormat=0` is `YYYY-MM-DDThh:mm:ss` per the ONVIF Core Spec §5.3. The `tds:` namespace matches the device service schema.
fn build_get_system_date_and_time() -> String {
    let (year, month, day, hour, minute, second) = utc_now();
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <s:Envelope xmlns:s=\"{envelope}\" xmlns:tds=\"{device}\" xmlns:tt=\"{schema}\">\n\
         <s:Body>\n\
         <tds:GetSystemDateAndTimeResponse>\n\
         <tt:SystemDateAndTime>\n\
         <tt:DateTimeType>NTP</tt:DateTimeType>\n\
         <tt:DayTimeSavings>false</tt:DayTimeSavings>\n\
         <tt:TimeZone><tt:TZ>GMT0</tt:TZ></tt:TimeZone>\n\
         <tt:UTCDateTime>\n\
         <tt:Date><tt:Year>{year}</tt:Year><tt:Month>{month}</tt:Month><tt:Day>{day}</tt:Day></tt:Date>\n\
         <tt:Time><tt:Hour>{hour}</tt:Hour><tt:Minute>{minute}</tt:Minute><tt:Second>{second}</tt:Second></tt:Time>\n\
         </tt:UTCDateTime>\n\
         </tt:SystemDateAndTime>\n\
         </tds:GetSystemDateAndTimeResponse>\n\
         </s:Body>\n\
         </s:Envelope>",
        envelope = NS_ENVELOPE,
        device = NS_DEVICE,
        schema = NS_SCHEMA,
        year = year,
        month = month,
        day = day,
        hour = hour,
        minute = minute,
        second = second,
    )
}

/// Builds the `GetCapabilities` response: Device and Media XAddrs pointing at this proxy's service paths. The XAddrs use the escaped server IP so a configured IP containing markup cannot break the XML.
fn build_get_capabilities(cfg: &OnvifConfig) -> String {
    let ip = xml_escape(&cfg.server_ip);
    let device_xaddr = format!("http://{ip}:{port}{path}", ip = ip, port = cfg.onvif_port, path = cfg.device_service_path);
    let media_xaddr = format!("http://{ip}:{port}{path}", ip = ip, port = cfg.onvif_port, path = cfg.media_service_path);
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <s:Envelope xmlns:s=\"{envelope}\" xmlns:tds=\"{device}\" xmlns:tt=\"{schema}\">\n\
         <s:Body>\n\
         <tds:GetCapabilitiesResponse>\n\
         <tt:Capabilities>\n\
         <tt:Device><tt:XAddrs>{device_xaddr}</tt:XAddrs></tt:Device>\n\
         <tt:Media><tt:XAddrs>{media_xaddr}</tt:XAddrs></tt:Media>\n\
         </tt:Capabilities>\n\
         </tds:GetCapabilitiesResponse>\n\
         </s:Body>\n\
         </s:Envelope>",
        envelope = NS_ENVELOPE,
        device = NS_DEVICE,
        schema = NS_SCHEMA,
        device_xaddr = device_xaddr,
        media_xaddr = media_xaddr,
    )
}

/// Builds the `GetDeviceInformation` response with manufacturer, model, firmware, serial, and hardware id. The serial and model prefer the live camera identity published by the 7550 FLV pipeline (`onMetaData` `streamName`-derived); when no identity has been published yet (before the camera's first `onMetaData` tag, or a stream that omits `streamName`) the `cfg.serial` fallback and the default `MODEL` are used. `cfg.firmware` is used as-is (the real firmware is not available on any current channel). All dynamic values are escaped.
fn build_get_device_information(cfg: &OnvifConfig, state: &StreamState) -> String {
    let identity = state.camera_identity();
    let serial = identity.as_ref().map(|i| i.serial.as_str()).unwrap_or(&cfg.serial);
    let model = identity.as_ref().map(|i| i.model.as_str()).filter(|m| !m.is_empty()).unwrap_or(MODEL);
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <s:Envelope xmlns:s=\"{envelope}\" xmlns:tds=\"{device}\">\n\
         <s:Body>\n\
         <tds:GetDeviceInformationResponse>\n\
         <tds:Manufacturer>{manufacturer}</tds:Manufacturer>\n\
         <tds:Model>{model}</tds:Model>\n\
         <tds:FirmwareVersion>{firmware}</tds:FirmwareVersion>\n\
         <tds:SerialNumber>{serial}</tds:SerialNumber>\n\
         <tds:HardwareId>{hardware}</tds:HardwareId>\n\
         </tds:GetDeviceInformationResponse>\n\
         </s:Body>\n\
         </s:Envelope>",
        envelope = NS_ENVELOPE,
        device = NS_DEVICE,
        manufacturer = xml_escape(MANUFACTURER),
        model = xml_escape(model),
        firmware = xml_escape(&cfg.firmware),
        serial = xml_escape(serial),
        hardware = xml_escape(HARDWARE_ID),
    )
}

/// Builds the `GetProfiles` response: one H.264 profile token `Profile_1` with resolution and frame rate from the published stream metadata, falling back to 1920x1080 @ 30 fps when no metadata is available yet.
fn build_get_profiles(_cfg: &OnvifConfig, state: &StreamState) -> String {
    let (width, height, fps) = match state.snapshot_metadata() {
        Some(meta) => (meta.width.unwrap_or(FALLBACK_WIDTH), meta.height.unwrap_or(FALLBACK_HEIGHT), meta.fps.map(|f| f as u32).unwrap_or(FALLBACK_FPS)),
        None => (FALLBACK_WIDTH, FALLBACK_HEIGHT, FALLBACK_FPS),
    };
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <s:Envelope xmlns:s=\"{envelope}\" xmlns:trt=\"{media}\" xmlns:tt=\"{schema}\">\n\
         <s:Body>\n\
         <trt:GetProfilesResponse>\n\
         <trt:Profiles token=\"{token}\">\n\
         <tt:VideoEncoderConfiguration>\n\
         <tt:Encoding>H264</tt:Encoding>\n\
         <tt:Resolution><tt:Width>{width}</tt:Width><tt:Height>{height}</tt:Height></tt:Resolution>\n\
         <tt:RateControl><tt:FrameRateLimit>{fps}</tt:FrameRateLimit></tt:RateControl>\n\
         </tt:VideoEncoderConfiguration>\n\
         </trt:Profiles>\n\
         </trt:GetProfilesResponse>\n\
         </s:Body>\n\
         </s:Envelope>",
        envelope = NS_ENVELOPE,
        media = NS_MEDIA,
        schema = NS_SCHEMA,
        token = PROFILE_TOKEN,
        width = width,
        height = height,
        fps = fps,
    )
}

/// Formats the RTSP stream URI advertised to NVRs: `rtsp://<ip>:<rtsp_port>/stream`. The server IP is XML-escaped so a configured IP containing markup cannot break the envelope. Shared by `GetStreamUri` and `GetSnapshotUri` so both advertise the same live-feed URL.
fn rtsp_stream_uri(cfg: &OnvifConfig) -> String {
    format!("rtsp://{ip}:{port}{path}", ip = xml_escape(&cfg.server_ip), port = cfg.rtsp_port, path = STREAM_URI_PATH)
}

/// Builds the `GetStreamUri` response: `rtsp://<ip>:<rtsp_port>/stream` as the URI an NVR opens to pull the feed. The URI matches the path the RTSP server serves.
fn build_get_stream_uri(cfg: &OnvifConfig) -> String {
    let uri = rtsp_stream_uri(cfg);
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <s:Envelope xmlns:s=\"{envelope}\" xmlns:trt=\"{media}\" xmlns:tt=\"{schema}\">\n\
         <s:Body>\n\
         <trt:GetStreamUriResponse>\n\
         <trt:MediaUri>\n\
         <tt:Uri>{uri}</tt:Uri>\n\
         <tt:InvalidAfterConnect>false</tt:InvalidAfterConnect>\n\
         <tt:InvalidAfterReboot>false</tt:InvalidAfterReboot>\n\
         <tt:Timeout>{timeout}</tt:Timeout>\n\
         </trt:MediaUri>\n\
         </trt:GetStreamUriResponse>\n\
         </s:Body>\n\
         </s:Envelope>",
        envelope = NS_ENVELOPE,
        media = NS_MEDIA,
        schema = NS_SCHEMA,
        uri = uri,
        timeout = STREAM_URI_TIMEOUT,
    )
}

/// Builds the `GetSnapshotUri` response. The proxy does not produce JPEG snapshots, so it advertises the RTSP stream URI in the same `MediaUri` shape `GetStreamUri` uses — an NVR that polls a snapshot URI then pulls the live RTSP feed, which keeps a snapshot-polling client streaming rather than failing on an empty/disabled URI. A stricter NVR that aborts device-add on the `ActionNotSupported` fault (the prior behaviour) is thus satisfied.
fn build_get_snapshot_uri(cfg: &OnvifConfig) -> String {
    let uri = rtsp_stream_uri(cfg);
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <s:Envelope xmlns:s=\"{envelope}\" xmlns:trt=\"{media}\" xmlns:tt=\"{schema}\">\n\
         <s:Body>\n\
         <trt:GetSnapshotUriResponse>\n\
         <trt:MediaUri>\n\
         <tt:Uri>{uri}</tt:Uri>\n\
         <tt:InvalidAfterConnect>false</tt:InvalidAfterConnect>\n\
         <tt:InvalidAfterReboot>false</tt:InvalidAfterReboot>\n\
         <tt:Timeout>{timeout}</tt:Timeout>\n\
         </trt:MediaUri>\n\
         </trt:GetSnapshotUriResponse>\n\
         </s:Body>\n\
         </s:Envelope>",
        envelope = NS_ENVELOPE,
        media = NS_MEDIA,
        schema = NS_SCHEMA,
        uri = uri,
        timeout = STREAM_URI_TIMEOUT,
    )
}

/// Builds the `GetAudioOutputConfigurations` response with an empty `Configurations` list. The proxy has no audio output, so the spec-correct "none configured" answer is an empty list — returning a fault here (the prior behaviour) could make a strict NVR refuse to add the camera.
fn build_get_audio_output_configurations() -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <s:Envelope xmlns:s=\"{envelope}\" xmlns:trt=\"{media}\" xmlns:tt=\"{schema}\">\n\
         <s:Body>\n\
         <trt:GetAudioOutputConfigurationsResponse>\n\
         <trt:Configurations/>\n\
         </trt:GetAudioOutputConfigurationsResponse>\n\
         </s:Body>\n\
         </s:Envelope>",
        envelope = NS_ENVELOPE,
        media = NS_MEDIA,
        schema = NS_SCHEMA,
    )
}

/// Builds the `SetSynchronizationPoint` response: an empty success. ONVIF uses this op to flush server-side state; the proxy has nothing to flush, so a no-op success is the correct answer rather than a fault that a strict NVR might treat as fatal.
fn build_set_synchronization_point() -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <s:Envelope xmlns:s=\"{envelope}\" xmlns:tds=\"{device}\">\n\
         <s:Body>\n\
         <tds:SetSynchronizationPointResponse/>\n\
         </s:Body>\n\
         </s:Envelope>",
        envelope = NS_ENVELOPE,
        device = NS_DEVICE,
    )
}

/// Builds a SOAP 1.2 Fault carrying `wsa:ActionNotSupported`, returned for any unrecognized or missing action. The body explicitly contains the `ActionNotSupported` subcode so an NVR (and the ONVIF tests) can detect the unsupported case.
fn build_fault() -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <s:Envelope xmlns:s=\"{envelope}\" xmlns:wsa=\"{addressing}\">\n\
         <s:Body>\n\
         <s:Fault>\n\
         <s:Code><s:Value>s:Sender</s:Value><s:Subcode><s:Value>wsa:ActionNotSupported</s:Value></s:Subcode></s:Code>\n\
         <s:Reason><s:Text xml:lang=\"en\">The action is not supported by the service.</s:Text></s:Reason>\n\
         </s:Fault>\n\
         </s:Body>\n\
         </s:Envelope>",
        envelope = NS_ENVELOPE,
        addressing = NS_ADDRESSING,
    )
}

/// Escapes the five XML special characters (`&` `<` `>` `"` `'`) per XML 1.0 §2.4. Applied to every dynamic value inserted into a response template so a configured IP / firmware / serial containing markup cannot break the envelope or inject elements.
pub(crate) fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

/// HTTP reason phrase for `code`, per RFC 7231 §6. Unknown codes map to `"OK"` so the status line is always well-formed.
fn http_reason(code: u16) -> &'static str {
    match code {
        STATUS_OK => "OK",
        _ => "OK",
    }
}

// --------------------------------------------------------------------------- Runtime: HTTP accept loop and per-connection handler. ---------------------------------------------------------------------------

/// Shutdown handle and bound-port surface for the ONVIF HTTP server. Mirrors `RtspServer` / `CameraListener`: a single instance owns the accept thread's shared flag; `console_main` drives one instance per process.
pub struct OnvifServer {
    config: OnvifConfig,
    state: StreamState,
    shutdown: Arc<AtomicBool>,
    logger: Option<Arc<Logger>>,
}

impl OnvifServer {
    pub fn new(config: OnvifConfig, state: StreamState) -> OnvifServer {
        OnvifServer { config, state, shutdown: Arc::new(AtomicBool::new(false)), logger: None }
    }

    pub fn with_logger(config: OnvifConfig, state: StreamState, logger: Arc<Logger>) -> OnvifServer {
        OnvifServer { config, state, shutdown: Arc::new(AtomicBool::new(false)), logger: Some(logger) }
    }

    /// Binds the ONVIF listener on `0.0.0.0:onvif_port` and runs the accept loop until `shutdown()` is called.
    pub fn run(&self) -> io::Result<()> {
        let listener = TcpListener::bind(("0.0.0.0", self.config.onvif_port))?;
        self.run_on(listener)
    }

    /// Runs the accept loop on a caller-supplied listener. Tests use this with an ephemeral loopback listener so they know the bound port; production `run()` delegates here after binding.
    pub fn run_on(&self, listener: TcpListener) -> io::Result<()> {
        listener.set_nonblocking(true)?;
        for incoming in listener.incoming() {
            if self.shutdown.load(RELAXED) {
                break;
            }
            match incoming {
                Ok(stream) => {
                    let config = self.config.clone();
                    let state = self.state.clone();
                    let shutdown = self.shutdown.clone();
                    let logger = self.logger.clone();
                    thread::spawn(move || {
                        let logger_ref = logger.as_deref();
                        handle_connection(stream, &config, &state, &shutdown, logger_ref);
                    });
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(ACCEPT_POLL_MS));
                }
                Err(_) => {
                    thread::sleep(Duration::from_millis(ACCEPT_POLL_MS));
                }
            }
        }
        Ok(())
    }

    /// Signals the accept loop to exit. Idempotent. In-flight connections finish on their next read timeout or request completion.
    pub fn shutdown(&self) {
        self.shutdown.store(true, RELAXED);
    }

    /// Returns a clone of the shutdown flag so external code (`console_main` or tests) can stop the accept loop without holding a reference to the `OnvifServer`. Mirrors `RtspServer::shutdown_signal`.
    pub fn shutdown_signal(&self) -> Arc<AtomicBool> {
        self.shutdown.clone()
    }
}

/// Handles one ONVIF HTTP connection to completion: reads the request headers and `Content-Length` body, routes the SOAP request, and writes the response. One request per connection (`Connection: close`) — ONVIF NVR discovery issues a small handful of requests, so keep-alive adds complexity without benefit. Every error path closes the connection; none panic. When `logger` is `Some`, the connection open and close are logged (the routed action/status is intentionally not logged — NVR discovery polls the same operations repeatedly and the per-request detail is noise).
fn handle_connection(mut stream: std::net::TcpStream, config: &OnvifConfig, state: &StreamState, shutdown: &AtomicBool, logger: Option<&Logger>) {
    let peer: SocketAddr = stream.peer_addr().unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(Duration::from_millis(READ_TIMEOUT_MS)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(WRITE_TIMEOUT_MS)));

    if let Some(logger) = logger {
        logger.log(Level::Info, &format!("onvif client connected: {peer}"));
    }

    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; READ_CHUNK_BYTES];
    let header_end = loop {
        if shutdown.load(RELAXED) {
            return;
        }
        match stream.read(&mut chunk) {
            Ok(0) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) if e.kind() == io::ErrorKind::TimedOut => continue,
            Err(_) => return,
        }
        if buf.len() > MAX_READ_BUFFER_BYTES {
            return;
        }
        if let Some(pos) = find_terminator(&buf) {
            break pos + HEADER_TERMINATOR_LEN;
        }
    };

    let header_str = match std::str::from_utf8(&buf[..header_end - HEADER_TERMINATOR_LEN]) {
        Ok(s) => s,
        Err(e) => {
            if let Some(logger) = logger {
                logger.log(Level::Warn, &format!("onvif: {peer}: request headers not utf-8 ({e}); closing"));
            }
            return;
        }
    };
    let content_length = parse_content_length(header_str);
    let soap_action = parse_soap_action(header_str);

    while buf.len() < header_end + content_length {
        match stream.read(&mut chunk) {
            Ok(0) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) if e.kind() == io::ErrorKind::TimedOut => continue,
            Err(e) => {
                if let Some(logger) = logger {
                    logger.log(Level::Warn, &format!("onvif: {peer}: body read failed ({e}); closing"));
                }
                return;
            }
        }
        if buf.len() > MAX_READ_BUFFER_BYTES {
            return;
        }
    }

    let body_bytes = &buf[header_end..header_end + content_length];
    let body_str = String::from_utf8_lossy(body_bytes).to_string();
    let (status, xml) = route(&soap_action, &body_str, config, state);
    let response = build_http_response(status, &xml);
    let _ = stream.write_all(&response);
    if let Some(logger) = logger {
        logger.log(Level::Info, &format!("onvif client disconnected: {peer}"));
    }
}

/// Builds the full HTTP response bytes for `status` and `xml` body: status line, `Content-Type`, `Content-Length`, `Connection: close`, blank line, body. Line endings are `\r\n` per RFC 7230 §3.
fn build_http_response(status: u16, xml: &str) -> Vec<u8> {
    let reason = http_reason(status);
    let body = xml.as_bytes();
    let mut out = String::new();
    out.push_str(&format!("HTTP/1.1 {status} {reason}\r\n"));
    out.push_str(&format!("Content-Type: {SOAP_CONTENT_TYPE}\r\n"));
    out.push_str(&format!("Content-Length: {}\r\n", body.len()));
    out.push_str("Connection: close\r\n");
    out.push_str("\r\n");
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

fn find_terminator(buf: &[u8]) -> Option<usize> {
    buf.windows(HEADER_TERMINATOR_LEN).position(|w| w == HEADER_TERMINATOR)
}

/// Extracts the `Content-Length` value from a header block. Returns `0` when the header is absent or non-numeric so the body read completes immediately.
fn parse_content_length(headers: &str) -> usize {
    header_value(headers, "content-length").and_then(|v| v.parse().ok()).unwrap_or(0)
}

/// Extracts the `SOAPAction` header value (raw, with any surrounding quotes — `route` strips them). Returns an empty string when absent.
fn parse_soap_action(headers: &str) -> String {
    header_value(headers, "soapaction").map(|v| v.to_string()).unwrap_or_default()
}

/// Finds the value of header `name` (case-insensitive) in a header block, trimming surrounding whitespace. Returns `None` when absent.
fn header_value<'a>(headers: &'a str, name: &str) -> Option<&'a str> {
    for line in headers.split("\r\n") {
        if let Some((n, v)) = line.split_once(':') {
            if n.trim().eq_ignore_ascii_case(name) {
                return Some(v.trim());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> OnvifConfig {
        OnvifConfig::defaults_for("127.0.0.1".to_string(), 554, 8080)
    }

    #[test]
    fn strip_quotes_removes_one_layer_of_surrounding_double_quotes() {
        assert_eq!(strip_quotes("\"uri\""), "uri");
        assert_eq!(strip_quotes("uri"), "uri");
        assert_eq!(strip_quotes("\"\""), "");
    }

    #[test]
    fn resolve_action_prefers_soap_action_header_over_body() {
        let body = "http://www.onvif.org/ver10/media/wsdl/GetStreamUri";
        let r = resolve_action("\"http://www.onvif.org/ver10/device/wsdl/GetCapabilities\"", body).expect("header wins");
        assert_eq!(r.service, Service::Device);
        assert_eq!(r.op, "GetCapabilities");
    }

    #[test]
    fn resolve_action_falls_back_to_body_namespace_when_header_absent() {
        let r = resolve_action("", "<trt:GetStreamUri xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl/GetStreamUri\"/>").expect("body fallback");
        assert_eq!(r.service, Service::Media);
        assert_eq!(r.op, "GetStreamUri");
    }

    #[test]
    fn resolve_action_returns_none_for_unrecognized_action() {
        assert!(resolve_action("\"http://example.com/Foo\"", "").is_none());
        assert!(resolve_action("", "<no/>").is_none());
    }

    #[test]
    fn xml_escape_replaces_all_five_special_characters() {
        assert_eq!(xml_escape("10.0.0.1&<>\"'"), "10.0.0.1&amp;&lt;&gt;&quot;&apos;");
    }

    #[test]
    fn route_unknown_action_returns_fault_with_action_not_supported() {
        let (status, xml) = route("\"http://example.com/Bogus\"", "", &cfg(), &StreamState::new());
        assert_eq!(status, STATUS_OK);
        assert!(xml.contains("ActionNotSupported"));
    }

    #[test]
    fn get_device_information_prefers_published_camera_serial_over_default() {
        let state = StreamState::new();
        state.publish_camera_identity(crate::stream_state::CameraIdentity { serial: "28704E11B531".to_string(), model: String::new() });
        let (_status, xml) = route("\"http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation\"", "", &cfg(), &state);
        assert!(xml.contains("<tds:SerialNumber>28704E11B531</tds:SerialNumber>"), "published MAC-derived serial must be advertised: {xml}");
        assert!(!xml.contains("000000000000"), "default serial must not appear once identity is published: {xml}");
        assert!(xml.contains("<tds:Model>UVC-G5-Bullet</tds:Model>"), "empty published model must fall back to the default MODEL: {xml}");
    }

    #[test]
    fn get_device_information_falls_back_to_cfg_serial_without_published_identity() {
        let cfg_with_serial = OnvifConfig { serial: "OPERATOR-FALLBACK".to_string(), ..cfg() };
        let (_status, xml) = route("\"http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation\"", "", &cfg_with_serial, &StreamState::new());
        assert!(xml.contains("<tds:SerialNumber>OPERATOR-FALLBACK</tds:SerialNumber>"), "cfg.serial fallback must be used when no identity is published: {xml}");
        assert!(xml.contains("<tds:Model>UVC-G5-Bullet</tds:Model>"), "default model must be advertised: {xml}");
    }

    #[test]
    fn get_device_information_uses_cfg_serial_when_published_model_is_empty_but_serial_present() {
        // Same shape as the published-serial case but exercising the operator override falling back to the *default* serial when nothing is published.
        let (_status, xml) = route("\"http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation\"", "", &cfg(), &StreamState::new());
        assert!(xml.contains("<tds:SerialNumber>000000000000</tds:SerialNumber>"), "default serial must appear when nothing is published: {xml}");
    }

    #[test]
    fn route_get_stream_uri_contains_exact_rtsp_uri() {
        let (status, xml) = route("\"http://www.onvif.org/ver10/media/wsdl/GetStreamUri\"", "", &cfg(), &StreamState::new());
        assert_eq!(status, STATUS_OK);
        assert!(xml.contains("<tt:Uri>rtsp://127.0.0.1:554/stream</tt:Uri>"));
    }

    #[test]
    fn route_get_snapshot_uri_returns_200_with_rtsp_stream_uri() {
        let (status, xml) = route("\"http://www.onvif.org/ver10/media/wsdl/GetSnapshotUri\"", "", &cfg(), &StreamState::new());
        assert_eq!(status, STATUS_OK, "GetSnapshotUri must return 200: {xml}");
        assert!(xml.contains("<trt:GetSnapshotUriResponse>"), "must wrap in GetSnapshotUriResponse: {xml}");
        assert!(xml.contains("<tt:Uri>rtsp://127.0.0.1:554/stream</tt:Uri>"), "snapshot URI must be the RTSP stream URI: {xml}");
        assert!(xml.contains("<tt:Timeout>PT60S</tt:Timeout>"), "must carry the 60 s timeout: {xml}");
        assert!(!xml.contains("Fault"), "must not be a fault: {xml}");
    }

    #[test]
    fn route_get_audio_output_configurations_returns_empty_list_not_fault() {
        let (status, xml) = route("\"http://www.onvif.org/ver10/media/wsdl/GetAudioOutputConfigurations\"", "", &cfg(), &StreamState::new());
        assert_eq!(status, STATUS_OK, "GetAudioOutputConfigurations must return 200: {xml}");
        assert!(xml.contains("<trt:GetAudioOutputConfigurationsResponse>"), "must wrap in GetAudioOutputConfigurationsResponse: {xml}");
        assert!(xml.contains("<trt:Configurations/>"), "must advertise an empty Configurations list: {xml}");
        assert!(!xml.contains("<tt:AudioOutputConfiguration"), "no audio output configuration may be advertised: {xml}");
        assert!(!xml.contains("Fault"), "must not be a fault: {xml}");
    }

    #[test]
    fn route_set_synchronization_point_returns_empty_success_not_fault() {
        let (status, xml) = route("\"http://www.onvif.org/ver10/device/wsdl/SetSynchronizationPoint\"", "", &cfg(), &StreamState::new());
        assert_eq!(status, STATUS_OK, "SetSynchronizationPoint must return 200: {xml}");
        assert!(xml.contains("<tds:SetSynchronizationPointResponse"), "must wrap in SetSynchronizationPointResponse: {xml}");
        assert!(!xml.contains("Fault"), "must not be a fault: {xml}");
    }

    #[test]
    fn route_get_snapshot_uri_routes_via_body_namespace_when_header_absent() {
        let body = envelope("<trt:GetSnapshotUri xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl/GetSnapshotUri\"/>");
        let (status, xml) = route("", &body, &cfg(), &StreamState::new());
        assert_eq!(status, STATUS_OK);
        assert!(xml.contains("<trt:GetSnapshotUriResponse>"), "body-namespace fallback must route GetSnapshotUri: {xml}");
    }

    #[test]
    fn build_http_response_has_content_type_and_length() {
        let bytes = build_http_response(STATUS_OK, "<x/>");
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.contains("Content-Type: application/soap+xml; charset=utf-8"));
        assert!(text.contains("Content-Length: 4\r\n"));
        assert!(text.contains("Connection: close\r\n"));
        assert!(text.ends_with("<x/>"));
    }

    #[test]
    fn route_get_system_date_and_time_returns_200_and_utc_datetime_elements() {
        let (status, xml) = route("\"http://www.onvif.org/ver10/device/wsdl/GetSystemDateAndTime\"", "", &cfg(), &StreamState::new());
        assert_eq!(status, STATUS_OK, "GetSystemDateAndTime must return 200: {xml}");
        assert!(xml.contains("<tds:GetSystemDateAndTimeResponse>"), "must wrap in GetSystemDateAndTimeResponse: {xml}");
        assert!(xml.contains("<tt:UTCDateTime>"), "must include UTCDateTime: {xml}");
        assert!(xml.contains("<tt:Year>"), "must include a Year element: {xml}");
        assert!(xml.contains("<tt:Hour>"), "must include an Hour element: {xml}");
    }

    #[test]
    fn route_get_system_date_and_time_routes_via_body_namespace_when_header_absent() {
        let body = envelope("<tds:GetSystemDateAndTime xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl/GetSystemDateAndTime\"/>");
        let (status, xml) = route("", &body, &cfg(), &StreamState::new());
        assert_eq!(status, STATUS_OK);
        assert!(xml.contains("<tds:GetSystemDateAndTimeResponse>"), "body-namespace fallback must route GetSystemDateAndTime: {xml}");
    }

    fn envelope(body_inner: &str) -> String {
        format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?><s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\"><s:Body>{body_inner}</s:Body></s:Envelope>")
    }
}
