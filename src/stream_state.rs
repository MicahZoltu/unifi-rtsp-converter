//! Shared stream-state hub. The camera pipeline publishes decoded H.264
//! frames and codec parameters here; RTSP clients register and receive
//! frames over a bounded `mpsc` channel. Pure concurrency logic —
//! `Arc<Mutex<_>>` + `mpsc` — with no networking and no I/O, so it builds
//! and tests on any platform.
//!
//! The hub keeps only the most recent keyframe (a "GOP of 1" bootstrap, so
//! a mid-stream joiner gets an instant decode point). Full GOP buffering is
//! out of scope. SPS/PPS travel out-of-band via the SDP
//! `sprop-parameter-sets` (step 09), so this module never duplicates them
//! onto the frame channel.
//!
//! The hub does not log directly: `publish_frame` returns the session ids it
//! disconnected so the camera pipeline can log them at the call site, keeping
//! this module free of I/O in line with the parser modules (`avc`, `amf`,
//! `flv_parser`).

use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex};

/// Capacity of the bounded per-client frame channel, per
/// `plan/07-stream-state.md`. Large enough that a briefly stalled RTSP
/// reader (a slow VLC over a congested LAN) absorbs a short frame burst
/// without being dropped, while keeping per-client memory bounded. A client
/// that falls a full window behind is disconnected rather than allowed to
/// stall the camera thread.
pub const CLIENT_CHANNEL_CAPACITY: usize = 64;

/// First session id handed out by `StreamState::add_client`. Starts above
/// zero so a sentinel `ClientId(0)` is never produced by the hub.
const FIRST_CLIENT_ID: u64 = 1;

/// One decoded H.264 frame ready for RTP packetization. Mirrors step 04's
/// `avc::NaluFrame` (keyframe flag + length-prefix-stripped NALUs) and adds
/// the 32-bit FLV tag timestamp the RTP layer needs for the 90 kHz clock.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Frame {
    /// True iff the originating FLV video tag's FrameType nibble was 1
    /// (keyframe). Set by the caller, which splits it from the tag's first
    /// byte.
    pub is_keyframe: bool,
    /// 32-bit FLV tag timestamp in milliseconds. RTP converts it to the
    /// 90 kHz clock as `timestamp_ms * 90`.
    pub timestamp_ms: u32,
    /// NALUs in this frame in stream order, each without its start code or
    /// length prefix — ready for RTP single-NALU / FU-A packetization.
    pub nalus: Vec<Vec<u8>>,
}

/// H.264 codec parameters the hub advertises to consumers. The
/// SPS/PPS/profile/level fields come from the AVCDecoderConfigurationRecord
/// (step 04); `width` / `height` / `fps` come from the `onMetaData` script
/// tag (step 06) and may all be `None`. The FLV pipeline (step 12) merges
/// the two sources before calling `StreamState::publish_config`.
#[derive(Debug, Clone, PartialEq)]
pub struct CodecParams {
    /// First SPS NALU bytes, without start code or length prefix.
    pub sps: Vec<u8>,
    /// First PPS NALU bytes, without start code or length prefix.
    pub pps: Vec<u8>,
    /// AVCProfileIndication (SPS byte 1), e.g. `0x4D` for Main profile.
    pub profile_indication: u8,
    /// profile_compatibility (SPS byte 2).
    pub profile_compat: u8,
    /// AVCLevelIndication (SPS byte 3), e.g. `0x1F` for level 3.1.
    pub level_indication: u8,
    /// `videoWidth` from `onMetaData`, if the stream declared one.
    pub width: Option<u32>,
    /// `videoHeight` from `onMetaData`, if the stream declared one.
    pub height: Option<u32>,
    /// `videoFps` from `onMetaData`, if the stream declared one.
    pub fps: Option<f32>,
}

/// Opaque, comparable session id assigned to each registered client. Cheap
/// to copy; used as the handle for `StreamState::remove_client`.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct ClientId(u64);

/// Read-only view of the stream's published metadata, used by the ONVIF
/// Media service (step 14) to answer `GetProfiles`. Returned only when a
/// codec has been published: until then no encodable profile exists.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct StreamSnapshot {
    /// Declared video width, if known.
    pub width: Option<u32>,
    /// Declared video height, if known.
    pub height: Option<u32>,
    /// Declared frame rate, if known.
    pub fps: Option<f32>,
}

/// Outcome of `StreamState::publish_frame`: the session ids of clients the
/// hub disconnected during this publish (their channel was full or already
/// closed). The camera pipeline logs these at the call site so the hub
/// itself stays free of I/O.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct PublishOutcome {
    /// Session ids disconnected because their channel was full or closed.
    pub dropped_client_ids: Vec<ClientId>,
}

/// One registered RTSP client: its session id and the sending half of its
/// bounded frame channel. Held inside the hub's lock; the matching
/// `Receiver` is returned to the client thread by `add_client`.
struct ClientHandle {
    id: ClientId,
    sender: SyncSender<Frame>,
}

/// Mutable hub state guarded by the `StreamState` mutex.
struct StreamStateInner {
    codec: Option<CodecParams>,
    last_keyframe: Option<Frame>,
    clients: Vec<ClientHandle>,
    next_client_id: u64,
}

/// Shared in-memory hub the camera pipeline writes to and RTSP clients read
/// from. Cloning a `StreamState` is cheap (one `Arc` bump) and yields another
/// handle to the same hub, so the camera thread and each RTSP session thread
/// can own a clone.
#[derive(Clone)]
pub struct StreamState {
    inner: Arc<Mutex<StreamStateInner>>,
}

impl StreamState {
    /// Creates an empty hub with no codec, no cached keyframe, and no
    /// registered clients.
    pub fn new() -> StreamState {
        StreamState {
            inner: Arc::new(Mutex::new(StreamStateInner {
                codec: None,
                last_keyframe: None,
                clients: Vec::new(),
                next_client_id: FIRST_CLIENT_ID,
            })),
        }
    }

    /// Replaces the stored codec parameters. Called by the FLV pipeline when
    /// an AVCDecoderConfigurationRecord (merged with the `onMetaData`
    /// width/height/fps) arrives. SDP generation (step 09) and ONVIF (step
    /// 14) read these back via `codec` / `snapshot_metadata`.
    pub fn publish_config(&self, config: CodecParams) {
        let mut guard = lock_hub(&self.inner);
        guard.codec = Some(config);
    }

    /// Publishes a decoded frame to every registered client. Keyframes are
    /// cached as `last_keyframe` so a client that registers later can begin
    /// decoding immediately. Each client's channel is fed with `try_send` so
    /// the camera thread is never blocked: a full or closed channel
    /// disconnects that client (it is removed from the registry) and its id
    /// is returned in the `PublishOutcome` for the caller to log.
    pub fn publish_frame(&self, frame: Frame) -> PublishOutcome {
        let mut guard = lock_hub(&self.inner);
        if frame.is_keyframe {
            guard.last_keyframe = Some(frame.clone());
        }
        let mut dropped: Vec<ClientId> = Vec::new();
        guard.clients.retain(|client| {
            if client.sender.try_send(frame.clone()).is_ok() {
                true
            } else {
                dropped.push(client.id);
                false
            }
        });
        PublishOutcome {
            dropped_client_ids: dropped,
        }
    }

    /// Registers a new client, returning its session id and the receiving
    /// half of a fresh bounded channel. If a keyframe is already cached, it
    /// is delivered to the new client immediately so the client has a decode
    /// point without waiting for the next keyframe. SPS/PPS are not sent
    /// here — the RTSP layer (step 11) ships them via the SDP
    /// `sprop-parameter-sets`, so duplicating them on the frame channel
    /// would be redundant.
    pub fn add_client(&self) -> (ClientId, Receiver<Frame>) {
        let mut guard = lock_hub(&self.inner);
        let id = ClientId(guard.next_client_id);
        guard.next_client_id = guard.next_client_id.wrapping_add(1);
        let (tx, rx) = mpsc::sync_channel(CLIENT_CHANNEL_CAPACITY);
        if let Some(keyframe) = &guard.last_keyframe {
            let _ = tx.try_send(keyframe.clone());
        }
        guard.clients.push(ClientHandle { id, sender: tx });
        (id, rx)
    }

    /// Removes the client with the given session id, if registered. No-op
    /// for an unknown id — e.g. a client already dropped by `publish_frame`
    /// or never registered. Returns `true` iff a client was actually
    /// removed.
    pub fn remove_client(&self, id: ClientId) -> bool {
        let mut guard = lock_hub(&self.inner);
        let before = guard.clients.len();
        guard.clients.retain(|c| c.id != id);
        guard.clients.len() != before
    }

    /// Returns a clone of the stored codec parameters, or `None` if no
    /// `publish_config` has occurred yet. SDP generation (step 09) uses this
    /// to read SPS/PPS/profile-level-id.
    pub fn codec(&self) -> Option<CodecParams> {
        let guard = lock_hub(&self.inner);
        guard.codec.clone()
    }

    /// Returns the width/height/fps declared by the stream, or `None` if no
    /// codec has been published yet (no encodable profile exists). The ONVIF
    /// Media service (step 14) uses this to answer `GetProfiles`.
    pub fn snapshot_metadata(&self) -> Option<StreamSnapshot> {
        let guard = lock_hub(&self.inner);
        guard.codec.as_ref().map(|c| StreamSnapshot {
            width: c.width,
            height: c.height,
            fps: c.fps,
        })
    }

    /// Number of clients currently registered. Intended for diagnostics and
    /// tests; not used in the hot path.
    pub fn client_count(&self) -> usize {
        let guard = lock_hub(&self.inner);
        guard.clients.len()
    }
}

impl Default for StreamState {
    fn default() -> StreamState {
        StreamState::new()
    }
}

/// Acquires the hub lock, recovering the guard even if a previous holder
/// panicked and poisoned the mutex. Poisoning does not invalidate the hub's
/// owned data — every field remains structurally sound — so serving
/// continues rather than propagating a poison panic to the camera or RTSP
/// threads. The hub's own operations never panic (no indexing, no unwrap),
/// so poisoning is only reachable if a future caller's `Drop` impl panics
/// while a guard is held.
fn lock_hub(inner: &Mutex<StreamStateInner>) -> std::sync::MutexGuard<'_, StreamStateInner> {
    inner
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_id_is_copy_and_comparable() {
        let a = ClientId(1);
        let b = a;
        assert_eq!(a, b);
        assert_ne!(a, ClientId(2));
    }
}
