//! Integration tests for `flvproxy::rtp` step 08: RTP header layout, single-NALU packetization, and FU-A fragmentation per RFC 6184. Covers the exact cases enumerated in `plan/08-rtp-packetization.md`, asserting byte-for-byte packet contents.
//!
//! FU indicator derivation follows RFC 6184 §5.8: `(nalu_header & 0xE0) | 28`. For a header of `0x65` (IDR, nal_ref_idc=3) this is `0x60 | 0x1C = 0x7C` — the plan's validation prose wrote `0x60` (the masked portion alone, dropping the `| 28`); the RFC- and `PROJECT.md`-correct value `0x7C` is asserted here.

use flvproxy::rtp::{RtpPacketizer, RtpSessionConfig, MAX_PAYLOAD};
use flvproxy::stream_state::Frame;

/// Fixed SSRC used across tests so header bytes 8-11 are predictable.
const SSRC: u32 = 0x0102_0304;

/// Fixed start sequence number used across tests so header bytes 2-3 are predictable.
const START_SEQ: u16 = 0x1234;

/// Builds a `Frame` with the given keyframe flag, timestamp, and NALU bytes.
fn frame(is_keyframe: bool, timestamp_ms: u32, nalus: &[&[u8]]) -> Frame {
    Frame { is_keyframe, timestamp_ms, nalus: nalus.iter().map(|n| n.to_vec()).collect() }
}

/// Returns the RTP header (first 12 bytes) of `packet`.
fn header(packet: &[u8]) -> &[u8] {
    &packet[..12]
}

/// Returns the RTP payload (bytes after the 12-byte header) of `packet`.
fn payload(packet: &[u8]) -> &[u8] {
    &packet[12..]
}

#[test]
fn single_small_nalu_yields_one_packet_with_marker_and_exact_fields() {
    let mut pkt = RtpPacketizer::new(SSRC, START_SEQ);
    let packets = pkt.packetize_frame(&frame(true, 100, &[&[0x67, 0xAA]]));

    assert_eq!(packets.len(), 1);
    let p = &packets[0];
    // byte0 = 0x80 (v2, no pad/ext/CSRC); byte1 = 0xE0 (marker=1, PT=96).
    assert_eq!(header(p)[0], 0x80);
    assert_eq!(header(p)[1], 0xE0);
    // seq = start_seq (big-endian).
    assert_eq!(&header(p)[2..4], &START_SEQ.to_be_bytes());
    // ts = 100 ms * 90 = 9000 (big-endian).
    assert_eq!(&header(p)[4..8], &9000u32.to_be_bytes());
    // ssrc correct (big-endian).
    assert_eq!(&header(p)[8..12], &SSRC.to_be_bytes());
    // payload == the NALU verbatim.
    assert_eq!(payload(p), &[0x67, 0xAA]);
}

#[test]
fn two_small_nalus_share_timestamp_and_marker_only_on_second() {
    let mut pkt = RtpPacketizer::new(SSRC, START_SEQ);
    let packets = pkt.packetize_frame(&frame(true, 100, &[&[0x67, 0xAA], &[0x68, 0xBB]]));

    assert_eq!(packets.len(), 2);

    // First packet: marker=0, seq=start_seq.
    assert_eq!(header(&packets[0])[1], 0x60);
    assert_eq!(&header(&packets[0])[2..4], &START_SEQ.to_be_bytes());
    assert_eq!(&header(&packets[0])[4..8], &9000u32.to_be_bytes());
    assert_eq!(payload(&packets[0]), &[0x67, 0xAA]);

    // Second packet: marker=1, seq=start_seq+1, same timestamp.
    assert_eq!(header(&packets[1])[1], 0xE0);
    let next_seq = START_SEQ.wrapping_add(1);
    assert_eq!(&header(&packets[1])[2..4], &next_seq.to_be_bytes());
    assert_eq!(&header(&packets[1])[4..8], &9000u32.to_be_bytes());
    assert_eq!(payload(&packets[1]), &[0x68, 0xBB]);
}

#[test]
fn large_nalu_fragments_into_fu_a_with_correct_headers_and_marker() {
    let mut pkt = RtpPacketizer::new(SSRC, START_SEQ);
    // 3000-byte NALU: header 0x65 (IDR, nal_ref_idc=3) + 2999 body bytes.
    let mut nalu = vec![0u8; 3000];
    nalu[0] = 0x65;
    for (i, b) in nalu[1..].iter_mut().enumerate() {
        *b = (i & 0xFF) as u8;
    }
    let packets = pkt.packetize_frame(&frame(true, 0, &[&nalu[..]]));

    // body = 2999 bytes, chunk = MAX_PAYLOAD - 2 = 1398 → ceil = 3 packets.
    assert_eq!(packets.len(), 3);
    let chunk_size = MAX_PAYLOAD - 2;
    let body = &nalu[1..];

    // Packet 1: start fragment, marker=0.
    let p0 = &packets[0];
    assert_eq!(header(p0)[1], 0x60, "first fragment must not set marker");
    // FU indicator = (0x65 & 0xE0) | 28 = 0x7C.
    assert_eq!(payload(p0)[0], 0x7C);
    // FU header = start | type = 0x80 | 0x05 = 0x85.
    assert_eq!(payload(p0)[1], 0x85);
    assert_eq!(&payload(p0)[2..], &body[..chunk_size]);

    // Middle packet: no flags, marker=0.
    let p1 = &packets[1];
    assert_eq!(header(p1)[1], 0x60);
    assert_eq!(payload(p1)[0], 0x7C);
    assert_eq!(payload(p1)[1], 0x05);
    assert_eq!(&payload(p1)[2..], &body[chunk_size..2 * chunk_size]);

    // Last packet: end flag, marker=1 (only NALU in frame).
    let p2 = &packets[2];
    assert_eq!(header(p2)[1], 0xE0, "last fragment of last NALU sets marker");
    assert_eq!(payload(p2)[0], 0x7C);
    // FU header = end | type = 0x40 | 0x05 = 0x45.
    assert_eq!(payload(p2)[1], 0x45);
    assert_eq!(&payload(p2)[2..], &body[2 * chunk_size..]);

    // Sequence numbers increment per packet.
    assert_eq!(&header(p0)[2..4], &START_SEQ.to_be_bytes());
    assert_eq!(&header(p1)[2..4], &START_SEQ.wrapping_add(1).to_be_bytes());
    assert_eq!(&header(p2)[2..4], &START_SEQ.wrapping_add(2).to_be_bytes());
}

#[test]
fn fu_a_fragments_reassemble_to_original_nalu_body() {
    let mut pkt = RtpPacketizer::new(SSRC, START_SEQ);
    let mut nalu = vec![0u8; 3000];
    nalu[0] = 0x65;
    for (i, b) in nalu[1..].iter_mut().enumerate() {
        *b = (i & 0xFF) as u8;
    }
    let packets = pkt.packetize_frame(&frame(true, 0, &[&nalu[..]]));

    let mut reassembled = Vec::new();
    for p in &packets {
        // Each FU-A payload is [fu_indicator][fu_header][body chunk].
        reassembled.extend_from_slice(&payload(p)[2..]);
    }
    assert_eq!(reassembled.as_slice(), &nalu[1..]);
}

#[test]
fn large_nalu_followed_by_small_nalu_sets_marker_only_on_final_packet() {
    let mut pkt = RtpPacketizer::new(SSRC, START_SEQ);
    let mut large = vec![0u8; 3000];
    large[0] = 0x65;
    let small: [u8; 2] = [0x68, 0xBB];
    let packets = pkt.packetize_frame(&frame(true, 0, &[&large[..], &small[..]]));

    // 3 FU-A packets for the large NALU + 1 single packet for the small one.
    assert_eq!(packets.len(), 4);
    // Every FU-A fragment of the large NALU has marker=0.
    for p in &packets[..3] {
        assert_eq!(header(p)[1], 0x60, "non-final NALU must not set marker");
    }
    // The final single-NALU packet carries the marker.
    assert_eq!(header(&packets[3])[1], 0xE0);
    assert_eq!(payload(&packets[3]), &small);
}

#[test]
fn sequence_number_wraps_past_u16_max() {
    let mut pkt = RtpPacketizer::new(SSRC, 0xFFFE);
    let one_nalu_frame = frame(false, 10, &[&[0x61, 0xAA]]);

    let p0 = pkt.packetize_frame(&one_nalu_frame);
    let p1 = pkt.packetize_frame(&one_nalu_frame);
    let p2 = pkt.packetize_frame(&one_nalu_frame);
    let p3 = pkt.packetize_frame(&one_nalu_frame);

    let seq = |packets: &Vec<Vec<u8>>| u16::from_be_bytes([packets[0][2], packets[0][3]]);
    assert_eq!(seq(&p0), 0xFFFE);
    assert_eq!(seq(&p1), 0xFFFF);
    assert_eq!(seq(&p2), 0x0000, "seq must wrap to 0 past u16::MAX");
    assert_eq!(seq(&p3), 0x0001);
}

#[test]
fn empty_frame_yields_no_packets_without_panicking() {
    let mut pkt = RtpPacketizer::new(SSRC, START_SEQ);
    let packets = pkt.packetize_frame(&frame(true, 100, &[]));
    assert!(packets.is_empty());
}

#[test]
fn nalu_exactly_at_max_payload_is_single_packet_boundary() {
    let mut pkt = RtpPacketizer::new(SSRC, START_SEQ);
    // NALU of exactly MAX_PAYLOAD bytes: header 0x65 + (MAX_PAYLOAD-1) body.
    let mut nalu = vec![0u8; MAX_PAYLOAD];
    nalu[0] = 0x65;
    let packets = pkt.packetize_frame(&frame(true, 0, &[&nalu[..]]));

    assert_eq!(packets.len(), 1, "MAX_PAYLOAD-sized NALU must not fragment");
    // Single-NALU packet payload is the NALU verbatim — no FU indicator.
    assert_eq!(payload(&packets[0]), nalu.as_slice());
}

#[test]
fn start_ts_offset_is_added_to_every_packet_timestamp() {
    let config = RtpSessionConfig { ssrc: SSRC, start_seq: START_SEQ, start_ts_offset: 1_000_000 };
    let mut pkt = RtpPacketizer::with_config(config);
    // 100 ms * 90 = 9000, plus offset 1_000_000 = 1_009_000.
    let expected_ts = 1_000_000u32.wrapping_add(9000);
    let packets = pkt.packetize_frame(&frame(true, 100, &[&[0x67, 0xAA]]));
    assert_eq!(packets.len(), 1);
    assert_eq!(&header(&packets[0])[4..8], &expected_ts.to_be_bytes());
}

#[test]
fn timestamp_wraps_modulo_u32() {
    // offset near u32::MAX so adding 9000 wraps past 2^32.
    let config = RtpSessionConfig { ssrc: SSRC, start_seq: START_SEQ, start_ts_offset: u32::MAX };
    let mut pkt = RtpPacketizer::with_config(config);
    let expected_ts = u32::MAX.wrapping_add(9000);
    let packets = pkt.packetize_frame(&frame(true, 100, &[&[0x67, 0xAA]]));
    assert_eq!(&header(&packets[0])[4..8], &expected_ts.to_be_bytes());
}

#[test]
fn rtp_session_config_new_has_zero_timestamp_offset() {
    let config = RtpSessionConfig::new(SSRC, START_SEQ);
    assert_eq!(config.ssrc, SSRC);
    assert_eq!(config.start_seq, START_SEQ);
    assert_eq!(config.start_ts_offset, 0);
}
