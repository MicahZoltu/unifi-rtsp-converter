//! Per-camera identity the ONVIF Device service advertises in `GetDeviceInformation`. `serial` is the camera's MAC-derived identifier recovered from the 7550 `onMetaData` `streamName` field — UniFi cameras emit `streamName` as `<MAC>_0` (colon-stripped, uppercased MAC with a stream-index suffix), which is the camera's de-facto serial: the hardware serial is not exposed on any current channel. `model` is an optional model-string override a future capture may populate; left empty until one does, in which case `onvif_server` falls back to its own `MODEL` constant.
//!
//! Owned here (not on `stream_state`) so the dependency graph is honest: this is an ONVIF concern consumed by both the FLV pipeline (which publishes it via `stream_state::publish_camera_identity`) and the ONVIF Device service (which reads it back via `stream_state::camera_identity`). The hub remains the concurrency rendezvous — the publisher and reader are on different threads with no other shared state — but the *type* no longer lives in the hub module, mirroring how `CodecParams` is defined in `stream_state` only because no other module owns it; `CameraIdentity` has a clearer owner (the ONVIF identity domain).

use crate::amf::StreamMetadata;

/// Per-camera identity the ONVIF Device service prefers over the configured serial/model fallback when answering `GetDeviceInformation`.
#[derive(Debug, Clone, PartialEq)]
pub struct CameraIdentity {
    /// MAC-derived identifier (`<MAC>` from `onMetaData` `streamName = <MAC>_N`, suffix stripped).
    pub serial: String,
    /// Optional model-string override; empty means "use the ONVIF service's own `MODEL` constant".
    pub model: String,
}

/// Recovers the MAC-derived serial from an `onMetaData` `streamName` value. UniFi cameras set `streamName` to `<MAC>_N` where `<MAC>` is the colon-stripped uppercased MAC address and `N` is the stream index. Strips the last `_<…>` suffix when present; a value with no underscore is returned verbatim (the camera's identifier may be a bare MAC on some firmware). Returns `None` only when `stream_name` is absent, empty, or trims to empty — a malformed-but-non-empty value never overwrites a prior good publish with an empty serial.
pub fn serial_from_stream_name(stream_name: Option<&str>) -> Option<String> {
    let name = stream_name?.trim();
    let mac = name.rsplit_once('_').map(|(mac, _)| mac).unwrap_or(name);
    if mac.is_empty() {
        None
    } else {
        Some(mac.to_string())
    }
}

/// Convenience: derives the `CameraIdentity` (serial only; model left empty) from a parsed `onMetaData` `StreamMetadata`, or `None` when the stream omitted a usable `streamName`.
pub fn from_metadata(meta: &StreamMetadata) -> Option<CameraIdentity> {
    serial_from_stream_name(meta.stream_name.as_deref()).map(|serial| CameraIdentity { serial, model: String::new() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serial_from_typical_stream_name_strips_suffix() {
        assert_eq!(serial_from_stream_name(Some("28704E11B531_0")), Some("28704E11B531".to_string()));
    }

    #[test]
    fn serial_from_stream_name_handles_none_and_empty() {
        assert_eq!(serial_from_stream_name(None), None);
        assert_eq!(serial_from_stream_name(Some("")), None);
        assert_eq!(serial_from_stream_name(Some("   ")), None);
    }

    #[test]
    fn serial_from_stream_name_without_underscore_is_returned_verbatim() {
        assert_eq!(serial_from_stream_name(Some("nomac")), Some("nomac".to_string()));
    }

    #[test]
    fn serial_from_stream_name_rejects_empty_halves() {
        assert_eq!(serial_from_stream_name(Some("_0")), None);
        assert_eq!(serial_from_stream_name(Some("MAC_")), Some("MAC".to_string()));
    }
}
