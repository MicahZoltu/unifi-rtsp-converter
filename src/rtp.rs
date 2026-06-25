//! RTP packetization per RFC 6184. Builds the 12-byte RTP header and packetizes H.264 NALUs as single-NALU packets or FU-A fragments.
//!
//! Pure byte logic — no I/O, no networking, no logging — so it builds and tests on any platform. The packetizer consumes `stream_state::Frame` and emits complete RTP packets as `Vec<u8>`, leaving the actual wire send to the RTSP server.
//!
//! Timestamps derive from the frame's FLV tag milliseconds scaled onto the 90 kHz RTP clock (`timestamp_ms * 90`), per RFC 6184 §1 and the proxy's SDP `a=rtpmap:96 H264/90000`. A per-session timestamp offset (`RtpSessionConfig::start_ts_offset`) randomizes the session's initial timestamp, mirroring the sequence-number offset recommended by RFC 3550 §5.1; it wraps modulo 2^32 alongside the timestamp itself.

use crate::stream_state::Frame;

/// RTP version 2 with no padding, no header extension, and no CSRC contributors — the fixed first byte of every RTP header this proxy sends, per RFC 3550 §5.1 (`V=2`, `P=0`, `X=0`, `CC=0`).
const RTP_VERSION_BYTE: u8 = 0x80;

/// Dynamic payload type for H.264 over RTP, per RFC 6184 §1, registered as 96 in the proxy's SDP `a=rtpmap:96 H264/90000`. Stored on the packetizer so a future payload type can be introduced without an API change. Shared with `sdp` so the SDP `m=`/`a=rtpmap` lines and the packetizer's PT always agree.
pub const PAYLOAD_TYPE_H264: u8 = 96;

/// RTP marker bit position in the second header byte, per RFC 3550 §5.1.
const MARKER_BIT: u8 = 0x80;

/// Mask isolating the 7-bit payload-type field of the second header byte, per RFC 3550 §5.1.
const PAYLOAD_TYPE_MASK: u8 = 0x7F;

/// NAL unit type for FU-A fragmentation, per RFC 6184 §5.8 (Table 7).
const NAL_TYPE_FU_A: u8 = 28;

/// Mask preserving the forbidden-zero-bit and NAL-ref-idc (the top 3 bits) of a NALU header byte when constructing an FU indicator, per RFC 6184 §5.8.
const NAL_HEADER_TOP_MASK: u8 = 0xE0;

/// Mask isolating the 5-bit NAL unit type from a NALU header byte, per ITU-T H.264 §7.4.1.
const NAL_TYPE_MASK: u8 = 0x1F;

/// FU header start-bit, set on the first fragment of a fragmented NALU, per RFC 6184 §5.8.
const FU_START_BIT: u8 = 0x80;

/// FU header end-bit, set on the last fragment of a fragmented NALU, per RFC 6184 §5.8.
const FU_END_BIT: u8 = 0x40;

/// Bytes consumed by the FU indicator + FU header prefix of every FU-A packet, per RFC 6184 §5.8. Subtracted from `MAX_PAYLOAD` to size each fragment's body chunk.
const FU_A_HEADER_BYTES: usize = 2;

/// Size of the fixed RTP header, per RFC 3550 §5.1 (no CSRC, no extension).
const RTP_HEADER_BYTES: usize = 12;

/// Maximum RTP payload size before a NALU must be fragmented with FU-A. Matches the MTU-safe value discussed in RFC 6184 §5.8: small enough to clear a 1500-byte Ethernet MTU after the 12-byte RTP + 8-byte UDP + 20-byte IP headers, with headroom to spare. A NALU whose length is ≤ this value is sent as one single-NALU packet; a larger NALU is FU-A fragmented.
pub const MAX_PAYLOAD: usize = 1400;

/// RTP clock rate for H.264, fixed at 90_000 Hz by RFC 6184 §1 and advertised in the proxy's SDP `a=rtpmap:96 H264/90000`. Shared with `sdp` so the SDP rtpmap and the packetizer's timestamp scaling always agree.
pub const RTP_CLOCK_RATE_HZ: u32 = 90_000;

/// H.264 millisecond timestamps are scaled by this to land on the 90 kHz RTP clock (`RTP_CLOCK_RATE_HZ` / 1000 ms = 90 ticks per ms), per RFC 6184 §1.
const RTP_TICKS_PER_MS: u32 = RTP_CLOCK_RATE_HZ / 1000;

/// Per-session RTP seed values: the SSRC identifying the sender, the initial sequence number, and the initial timestamp offset. The caller seeds randomness (or tests pass deterministic values); the packetizer never draws randomness itself, so its output is reproducible from a config.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct RtpSessionConfig {
    /// 32-bit synchronization source identifying this RTP session, constant for the session lifetime, per RFC 3550 §3.
    pub ssrc: u32,
    /// Initial 16-bit RTP sequence number; increments per packet and wraps at `u16::MAX + 1`, per RFC 3550 §5.1.
    pub start_seq: u16,
    /// Random offset added to every emitted RTP timestamp so the session's initial timestamp is not zero, mirroring the sequence-number offset recommended by RFC 3550 §5.1. Wraps modulo 2^32 with the timestamp.
    pub start_ts_offset: u32,
}

impl RtpSessionConfig {
    /// Builds a config with a zero timestamp offset, for callers (and tests) that want the RTP timestamp to equal `timestamp_ms * 90` exactly.
    pub fn new(ssrc: u32, start_seq: u16) -> RtpSessionConfig {
        RtpSessionConfig { ssrc, start_seq, start_ts_offset: 0 }
    }
}

/// H.264 RTP packetizer per RFC 6184. Holds the running sequence number (which persists and wraps across `packetize_frame` calls) plus the session-constant SSRC, payload type, and timestamp offset. Each call emits one or more complete RTP packets as `Vec<u8>`; the timestamp is derived per frame, so the packetizer itself is stateless apart from the sequence number.
pub struct RtpPacketizer {
    ssrc: u32,
    seq: u16,
    payload_type: u8,
    start_ts_offset: u32,
}

impl RtpPacketizer {
    /// Creates a packetizer with the H.264 payload type (96), the given SSRC and initial sequence number, and a zero timestamp offset. Use `with_config` to supply a non-zero offset.
    pub fn new(ssrc: u32, start_seq: u16) -> RtpPacketizer {
        RtpPacketizer::with_config(RtpSessionConfig::new(ssrc, start_seq))
    }

    /// Creates a packetizer from a full `RtpSessionConfig`, honoring its timestamp offset and initial sequence number.
    pub fn with_config(config: RtpSessionConfig) -> RtpPacketizer {
        RtpPacketizer { ssrc: config.ssrc, seq: config.start_seq, payload_type: PAYLOAD_TYPE_H264, start_ts_offset: config.start_ts_offset }
    }

    /// Packetizes one H.264 frame into RTP packets per RFC 6184.
    ///
    /// Each NALU is sent as a single-NALU packet when it fits `MAX_PAYLOAD`, otherwise fragmented with FU-A. The RTP marker bit is set only on the final packet of the final NALU, signalling end-of-frame to the receiver (RFC 6184 §5.1). All packets in a frame share the frame's timestamp; the sequence number increments per packet and wraps u16. An empty frame (no NALUs) yields an empty `Vec` and never panics.
    pub fn packetize_frame(&mut self, frame: &Frame) -> Vec<Vec<u8>> {
        let timestamp = self.start_ts_offset.wrapping_add(frame.timestamp_ms.wrapping_mul(RTP_TICKS_PER_MS));
        let nalu_count = frame.nalus.len();
        let mut packets = Vec::new();
        for (nalu_index, nalu) in frame.nalus.iter().enumerate() {
            let is_last_nalu = nalu_index + 1 == nalu_count;
            if nalu.is_empty() {
                // A zero-length NALU carries no header byte to encode its type, so it cannot be packetized; skip it rather than emit a malformed packet. `avc::split_length_prefixed_nalus` already drops these, so this is a defensive guard against adversarially-constructed `Frame`s.
                continue;
            }
            if nalu.len() <= MAX_PAYLOAD {
                packets.push(self.build_single_nalu_packet(nalu, timestamp, is_last_nalu));
            } else {
                self.packetize_fu_a(nalu, timestamp, is_last_nalu, &mut packets);
            }
        }
        packets
    }

    /// Builds one single-NALU RTP packet (RFC 6184 §5.6) and advances the sequence number. The marker bit is set iff this is the last NALU of the frame (a single-NALU packet is always the last packet of its NALU).
    fn build_single_nalu_packet(&mut self, nalu: &[u8], timestamp: u32, is_last_nalu: bool) -> Vec<u8> {
        let mut packet = Vec::with_capacity(RTP_HEADER_BYTES + nalu.len());
        packet.extend_from_slice(&rtp_header(is_last_nalu, self.payload_type, self.seq, timestamp, self.ssrc));
        packet.extend_from_slice(nalu);
        self.seq = self.seq.wrapping_add(1);
        packet
    }

    /// Fragments `nalu` into FU-A packets (RFC 6184 §5.8) and appends them to `packets`. The original 1-byte NALU header is dropped from the payload (its type travels in the FU header); the body is sliced into `MAX_PAYLOAD - FU_A_HEADER_BYTES` chunks to leave room for the FU indicator and FU header. The marker bit is set only on the final fragment of the final NALU of the frame.
    fn packetize_fu_a(&mut self, nalu: &[u8], timestamp: u32, is_last_nalu: bool, packets: &mut Vec<Vec<u8>>) {
        let header = nalu[0];
        let fu_indicator = (header & NAL_HEADER_TOP_MASK) | NAL_TYPE_FU_A;
        let nalu_type = header & NAL_TYPE_MASK;
        let body = &nalu[1..];
        let chunk_size = MAX_PAYLOAD - FU_A_HEADER_BYTES;
        let chunk_count = body.len().div_ceil(chunk_size);
        for (i, chunk) in body.chunks(chunk_size).enumerate() {
            let is_first = i == 0;
            let is_last = i + 1 == chunk_count;
            let mut fu_header = nalu_type;
            if is_first {
                fu_header |= FU_START_BIT;
            }
            if is_last {
                fu_header |= FU_END_BIT;
            }
            let marker = is_last && is_last_nalu;
            let mut packet = Vec::with_capacity(RTP_HEADER_BYTES + FU_A_HEADER_BYTES + chunk.len());
            packet.extend_from_slice(&rtp_header(marker, self.payload_type, self.seq, timestamp, self.ssrc));
            packet.push(fu_indicator);
            packet.push(fu_header);
            packet.extend_from_slice(chunk);
            self.seq = self.seq.wrapping_add(1);
            packets.push(packet);
        }
    }
}

/// Builds the fixed 12-byte RTP header (RFC 3550 §5.1) for one packet: version 2 / no pad / no ext / no CSRC in byte 0, marker + payload type in byte 1, big-endian sequence number in bytes 2-3, big-endian timestamp in bytes 4-7, big-endian SSRC in bytes 8-11.
fn rtp_header(marker: bool, payload_type: u8, seq: u16, timestamp: u32, ssrc: u32) -> [u8; RTP_HEADER_BYTES] {
    let mut h = [0u8; RTP_HEADER_BYTES];
    h[0] = RTP_VERSION_BYTE;
    h[1] = (if marker { MARKER_BIT } else { 0 }) | (payload_type & PAYLOAD_TYPE_MASK);
    h[2..4].copy_from_slice(&seq.to_be_bytes());
    h[4..8].copy_from_slice(&timestamp.to_be_bytes());
    h[8..12].copy_from_slice(&ssrc.to_be_bytes());
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rtp_header_lays_out_fields_big_endian() {
        let h = rtp_header(false, 96, 0x1234, 0xAABBCCDD, 0x01020304);
        assert_eq!(h, [0x80, 0x60, 0x12, 0x34, 0xAA, 0xBB, 0xCC, 0xDD, 0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn rtp_header_sets_marker_bit_in_byte_one() {
        let no_marker = rtp_header(false, 96, 0, 0, 0);
        let marker = rtp_header(true, 96, 0, 0, 0);
        assert_eq!(no_marker[1], 0x60);
        assert_eq!(marker[1], 0xE0);
    }
}
