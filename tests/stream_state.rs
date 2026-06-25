//! Integration tests for `flvproxy::stream_state`: the shared in-memory hub the camera pipeline publishes to and RTSP clients read from, asserting exact frame ordering, content, and client-drop semantics.

use std::sync::mpsc::Receiver;
use std::time::Instant;

use flvproxy::stream_state::{CameraIdentity, ClientId, CodecParams, Frame, PublishOutcome, StreamSnapshot, StreamState, CLIENT_CHANNEL_CAPACITY};

/// Builds a `Frame` with the given keyframe flag, timestamp, and NALU bytes.
fn frame(is_keyframe: bool, timestamp_ms: u32, nalus: &[&[u8]]) -> Frame {
    Frame { is_keyframe, timestamp_ms, nalus: nalus.iter().map(|n| n.to_vec()).collect() }
}

/// Builds `CodecParams` with fixed SPS/PPS/profile/level and the supplied `onMetaData`-derived dimensions/rate.
fn codec_params(width: Option<u32>, height: Option<u32>, fps: Option<f32>) -> CodecParams {
    CodecParams { sps: vec![0x67, 0xAB], pps: vec![0x68], profile_indication: 0x4D, profile_compat: 0x40, level_indication: 0x1F, width, height, fps }
}

/// Drains every currently-buffered frame from `rx` into a `Vec`, in receive order. Stops at the first `Empty` (channel open, no message) or `Disconnected` (all senders dropped) result.
fn drain(rx: &Receiver<Frame>) -> Vec<Frame> {
    let mut out = Vec::new();
    while let Ok(f) = rx.try_recv() {
        out.push(f);
    }
    out
}

#[test]
fn codec_is_none_until_publish_config_then_some() {
    let hub = StreamState::new();
    assert_eq!(hub.codec(), None);
    let cfg = codec_params(Some(1920), Some(1080), Some(30.0));
    hub.publish_config(cfg.clone());
    assert_eq!(hub.codec(), Some(cfg));
}

#[test]
fn late_client_receives_only_cached_keyframe() {
    let hub = StreamState::new();
    hub.publish_config(codec_params(Some(1920), Some(1080), Some(30.0)));
    let keyframe = frame(true, 1000, &[&[0x65, 0xAA]]);
    hub.publish_frame(keyframe.clone());
    hub.publish_frame(frame(false, 1066, &[&[0x61, 0xBB]]));
    hub.publish_frame(frame(false, 1133, &[&[0x61, 0xCC]]));
    hub.publish_frame(frame(false, 1200, &[&[0x61, 0xDD]]));

    let (_id, rx) = hub.add_client();
    assert_eq!(drain(&rx), vec![keyframe]);
}

#[test]
fn early_client_receives_frames_in_publish_order() {
    let hub = StreamState::new();
    let (_id, rx) = hub.add_client();
    let f1 = frame(true, 1000, &[&[0x65, 0x01]]);
    let f2 = frame(false, 1066, &[&[0x61, 0x02]]);
    let f3 = frame(false, 1133, &[&[0x61, 0x03]]);
    let f4 = frame(false, 1200, &[&[0x61, 0x04]]);
    hub.publish_frame(f1.clone());
    hub.publish_frame(f2.clone());
    hub.publish_frame(f3.clone());
    hub.publish_frame(f4.clone());

    assert_eq!(drain(&rx), vec![f1, f2, f3, f4]);
}

#[test]
fn two_clients_each_receive_all_frames_in_order() {
    let hub = StreamState::new();
    let (_id_a, rx_a) = hub.add_client();
    let (_id_b, rx_b) = hub.add_client();
    let frames: Vec<Frame> = (0..10).map(|i| frame(i == 0, 1000 + i * 33, &[&[0x61, i as u8]])).collect();
    for f in &frames {
        hub.publish_frame(f.clone());
    }
    assert_eq!(drain(&rx_a), frames);
    assert_eq!(drain(&rx_b), frames);
}

#[test]
fn slow_client_is_dropped_after_cap_and_never_blocks_publisher() {
    let hub = StreamState::new();
    let (id, rx) = hub.add_client();
    assert_eq!(hub.client_count(), 1);

    let total = CLIENT_CHANNEL_CAPACITY + 5;
    let start = Instant::now();
    let mut dropped_ids: Vec<ClientId> = Vec::new();
    for i in 0..total {
        let outcome = hub.publish_frame(frame(i == 0, 1000 + i as u32 * 33, &[&[0x61, i as u8]]));
        dropped_ids.extend(outcome.dropped_client_ids);
    }
    let elapsed = start.elapsed();

    assert!(elapsed.as_secs() < 1, "publish_frame blocked the caller: {elapsed:?}",);
    assert_eq!(hub.client_count(), 0);
    assert_eq!(dropped_ids, vec![id]);

    let received = drain(&rx);
    assert_eq!(received.len(), CLIENT_CHANNEL_CAPACITY);
    for (i, f) in received.iter().enumerate() {
        assert_eq!(f.timestamp_ms, 1000 + i as u32 * 33);
    }
}

#[test]
fn remove_client_cleans_up_and_stops_delivery() {
    let hub = StreamState::new();
    let (id, rx) = hub.add_client();
    assert_eq!(hub.client_count(), 1);
    assert!(hub.remove_client(id));
    assert_eq!(hub.client_count(), 0);
    assert!(!hub.remove_client(id));

    let outcome = hub.publish_frame(frame(true, 1000, &[&[0x65, 0xAA]]));
    assert!(outcome.dropped_client_ids.is_empty());
    assert_eq!(drain(&rx), Vec::<Frame>::new());
}

#[test]
fn last_keyframe_is_overwritten_not_appended() {
    let hub = StreamState::new();
    let keyframe_a = frame(true, 1000, &[&[0x65, 0xAA]]);
    let keyframe_b = frame(true, 2000, &[&[0x65, 0xBB]]);
    hub.publish_frame(keyframe_a);
    hub.publish_frame(keyframe_b.clone());

    let (_id, rx) = hub.add_client();
    assert_eq!(drain(&rx), vec![keyframe_b]);
}

#[test]
fn snapshot_metadata_is_none_until_codec_published() {
    let hub = StreamState::new();
    assert_eq!(hub.snapshot_metadata(), None);
    hub.publish_config(codec_params(Some(1920), Some(1080), Some(30.0)));
    assert_eq!(hub.snapshot_metadata(), Some(StreamSnapshot { width: Some(1920), height: Some(1080), fps: Some(30.0) }),);
}

#[test]
fn snapshot_metadata_reflects_partial_codec_params() {
    let hub = StreamState::new();
    hub.publish_config(codec_params(Some(1280), None, None));
    assert_eq!(hub.snapshot_metadata(), Some(StreamSnapshot { width: Some(1280), height: None, fps: None }),);
}

#[test]
fn publish_frame_with_no_clients_drops_none_but_caches_keyframe() {
    let hub = StreamState::new();
    let outcome = hub.publish_frame(frame(true, 1000, &[&[0x65, 0xAA]]));
    assert_eq!(outcome, PublishOutcome::default());
    assert_eq!(hub.client_count(), 0);

    let (_id, rx) = hub.add_client();
    assert_eq!(drain(&rx), vec![frame(true, 1000, &[&[0x65, 0xAA]])],);
}

#[test]
fn camera_identity_is_none_until_published_then_round_trips() {
    let hub = StreamState::new();
    assert_eq!(hub.camera_identity(), None);
    let id = CameraIdentity { serial: "28704E11B531".to_string(), model: String::new() };
    hub.publish_camera_identity(id.clone());
    assert_eq!(hub.camera_identity(), Some(id));
}

#[test]
fn publish_camera_identity_overwrites_prior_identity() {
    let hub = StreamState::new();
    hub.publish_camera_identity(CameraIdentity { serial: "AAAAA".to_string(), model: String::new() });
    hub.publish_camera_identity(CameraIdentity { serial: "BBBBB".to_string(), model: String::new() });
    assert_eq!(hub.camera_identity(), Some(CameraIdentity { serial: "BBBBB".to_string(), model: String::new() }));
}
