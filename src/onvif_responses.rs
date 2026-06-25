//! ONVIF SOAP 1.2 response templates + the `OnvifConfig` they consume. Split out from `onvif_server` so the router (`route`/`resolve_action`) and the HTTP runtime (`OnvifServer`, `handle_connection`) — the surfaces an auditor reads first — fit in one screen, and the ~350 lines of `format!`-based SOAP bodies live in one auditable place.
//!
//! `OnvifConfig`, `DEFAULT_DEVICE_SERVICE_PATH`, and `DEFAULT_MEDIA_SERVICE_PATH` are re-exported by `onvif_server` (`pub use crate::onvif_responses::*`) so existing imports (`crate::onvif_server::{OnvifConfig, OnvifServer, DEFAULT_DEVICE_SERVICE_PATH}`) keep working. The dependency graph is a clean DAG: `onvif_server` depends on `onvif_responses` (the router calls the builders and names the config type); `onvif_responses` depends only on `stream_state` / `camera_identity` / `calendar` / `xml`, not back on `onvif_server`.

use crate::calendar::utc_now;
use crate::stream_state::StreamState;
use crate::xml::{xml_escape, NS_ADDRESSING, NS_ENVELOPE};

/// ONVIF profile token advertised by `GetProfiles`. A single H.264 profile is all an NVR needs to add the camera and pull the RTSP URL.
const PROFILE_TOKEN: &str = "Profile_1";

/// Default video width advertised when the stream has not published metadata yet. Matches the UVC G5 Bullet default recording resolution.
const FALLBACK_WIDTH: u32 = 1920;

const FALLBACK_HEIGHT: u32 = 1080;

const FALLBACK_FPS: u32 = 30;

/// Manufacturer advertised by `GetDeviceInformation`, per `PROJECT.md` → "ONVIF Device Service".
const MANUFACTURER: &str = "Ubiquiti";

/// Model advertised by `GetDeviceInformation`, per `PROJECT.md` → "ONVIF Device Service".
const MODEL: &str = "UVC-G5-Bullet";

/// Hardware id advertised by `GetDeviceInformation`. ONVIF requires a non-empty `HardwareId`; the model name is reused as a stable identifier.
const HARDWARE_ID: &str = MODEL;

/// `Timeout` value returned in `GetStreamUri` responses, per the ONVIF Media service spec — the URI remains valid for 60 seconds after connect.
const STREAM_URI_TIMEOUT: &str = "PT60S";

/// RTSP URL path the Media service advertises as the stream URI. Matches the path the RTSP server serves, so an NVR that opens the URI lands on a working DESCRIBE target.
const STREAM_URI_PATH: &str = "/stream";

/// ONVIF service namespaces (Device, Media, Schema) declared on this proxy's response bodies. Declared once so the templates stay readable; the SOAP envelope and WS-Addressing namespaces are shared with `onvif_discovery` and live in `crate::xml`.
const NS_DEVICE: &str = "http://www.onvif.org/ver10/device/wsdl";
const NS_MEDIA: &str = "http://www.onvif.org/ver10/media/wsdl";
const NS_SCHEMA: &str = "http://www.onvif.org/ver10/schema";

/// Device service URL path served by this proxy.
pub const DEFAULT_DEVICE_SERVICE_PATH: &str = "/onvif/device_service";

/// Media service URL path served by this proxy.
pub const DEFAULT_MEDIA_SERVICE_PATH: &str = "/onvif/media_service";

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
        OnvifConfig { server_ip, rtsp_port, onvif_port, device_service_path: DEFAULT_DEVICE_SERVICE_PATH, media_service_path: DEFAULT_MEDIA_SERVICE_PATH, firmware: crate::defaults::DEFAULT_FIRMWARE.to_string(), serial: crate::defaults::DEFAULT_SERIAL.to_string() }
    }
}

/// Builds the `GetEndpointReference` response: a stable `urn:uuid:` token. ONVIF clients use this as a device-identity token (e.g. to correlate a discovered device with a later session); the value need only be stable for the process lifetime. The `urn:uuid:` form satisfies the ONVIF Core Spec §5.3 endpoint-reference shape; a fixed token keeps the value deterministic across restarts on the same address (a re-probing client sees the same endpoint reference).
pub fn build_get_endpoint_reference() -> String {
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
pub fn build_get_services(cfg: &OnvifConfig) -> String {
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
pub fn build_get_system_date_and_time() -> String {
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
pub fn build_get_capabilities(cfg: &OnvifConfig) -> String {
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
pub fn build_get_device_information(cfg: &OnvifConfig, state: &StreamState) -> String {
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
pub fn build_get_profiles(_cfg: &OnvifConfig, state: &StreamState) -> String {
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
pub fn build_get_stream_uri(cfg: &OnvifConfig) -> String {
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
pub fn build_get_snapshot_uri(cfg: &OnvifConfig) -> String {
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
pub fn build_get_audio_output_configurations() -> String {
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
pub fn build_set_synchronization_point() -> String {
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
pub fn build_fault() -> String {
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
