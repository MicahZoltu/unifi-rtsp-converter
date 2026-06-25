//! RTP-delivery half of the RTSP server: the `PacketSink` transport abstraction (TCP-interleaved + UDP + in-memory test sink), the per-session RTP pump (`run_pump`), and the keyframe pacing + per-session SSRC/sequence-number seeding. Split out from `rtsp_server` so the control-channel surface (request dispatch, session wiring, the accept loop) and the RTP-delivery surface each have one reason to change and one file to audit, mirroring the `rtsp_protocol`/`rtsp_server` split already established for the protocol layer.
//!
//! `pump_frame_into` and the sinks are `pub` and re-exported by `rtsp_server` so existing imports (`flvproxy::rtsp_server::{pump_frame_into, VecSink}`) keep working — the symbols move to a narrower home without churning the test-facing API.

use std::io;
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::logging::{Level, Logger};
use crate::rtp::RtpPacketizer;
use crate::stream_state::{ClientId, Frame, StreamState};

/// Relaxed ordering suffices for the shutdown flag and the session-seed counter: they are advisory signals / an opportunistic entropy mix, not synchronization that establishes happens-before for other data. Mirrors `rtsp_server`.
const RELAXED: Ordering = Ordering::Relaxed;

/// `$` byte prefixing an interleaved RTP/RTCP frame on the RTSP TCP connection, per RFC 2326 §12.39 and `PROJECT.md` → "TCP Interleaved RTP". `pub(crate)` so `rtsp_server::drain_client_interleaved_frames` (the control-channel side that discards client→server interleaved frames) shares the single source.
pub(crate) const INTERLEAVED_FRAME_MARKER: u8 = 0x24;

/// Number of framing bytes preceding an interleaved RTP packet: `[$][channel][len_hi][len_lo]`, per RFC 2326 §12.39. `pub(crate)` for the same reason as `INTERLEAVED_FRAME_MARKER`.
pub(crate) const INTERLEAVED_FRAMING_BYTES: usize = 4;

/// Pump channel poll interval, so the `shutdown` flag is checked promptly between frames rather than blocking indefinitely on `recv`.
const PUMP_POLL_TIMEOUT_MS: u64 = 200;

/// Frames larger than this are sent with inter-chunk pacing so the burst does not overflow a receiver's initial RTP reorder buffer. P-frames from the G5 Bullet are 20–50 KB; keyframes are ~1 MB. The threshold sits between the two so only keyframes are paced.
const PACING_FRAME_THRESHOLD_BYTES: usize = 64 * 1024;

/// Number of RTP packets sent before a pacing sleep. ~35 packets × ~1400 bytes ≈ 49 KB per chunk, small enough that the receiver's reorder buffer absorbs it without loss between sleeps.
const PACING_CHUNK_PACKETS: usize = 35;

/// Sleep between paced chunks. A 1.2 MB keyframe (889 packets / 25 chunks) paced at 5 ms/chunk spreads the send over ~125 ms instead of ~12 ms, giving live555 (VLC) time to grow its initial ~500 KB reorder buffer past the ~475 KB it would otherwise drop. On Windows the default timer resolution may round this up to ~15 ms, which yields ~375 ms total — still well under the 5 s keyframe interval and far better than the alternative (dropped keyframe → 5 s wait for the next one).
const PACING_CHUNK_SLEEP: Duration = Duration::from_millis(5);

/// Multiplier and increment of the tiny splitmix64-style mixer used to derive per-session SSRC / sequence-number seeds from wall-clock nanos and a process-wide counter, avoiding a crate dependency. Values from Knuth's MMIX constants.
const SPLITMIX_MULTIPLIER: u64 = 6_364_136_223_846_793_005;
const SPLITMIX_INCREMENT: u64 = 14_426_950_408_889_634_077;

/// 64-bit golden-ratio fractional constant (`(√5−1)/2`), used to mix the process counter into the session seed so successive sessions diverge even when wall-clock nanos collide.
const GOLDEN_RATIO_64: u64 = 0x9E37_79B9_7F4A_7C15;

/// Sink abstraction letting the pump send RTP packets to a real socket in production and an in-memory `Vec` in tests, sharing one code path. The `Send` bound is required so a boxed sink can move into the pump thread.
pub trait PacketSink {
    /// Sends one complete RTP packet. An error signals a broken transport (e.g. peer closed); the pump treats it as terminal.
    fn send(&mut self, pkt: &[u8]) -> io::Result<()>;
}

/// `PacketSink` writing RTP as `$`-framed interleaved data on the RTSP TCP connection, per RFC 2326 §12.39. Shares the connection's send mutex with control-response writes so bytes never interleave.
pub struct TcpInterleavedSink {
    writer: Arc<Mutex<TcpStream>>,
    rtp_ch: u8,
}

impl TcpInterleavedSink {
    pub fn new(writer: Arc<Mutex<TcpStream>>, rtp_ch: u8) -> TcpInterleavedSink {
        TcpInterleavedSink { writer, rtp_ch }
    }
}

impl PacketSink for TcpInterleavedSink {
    fn send(&mut self, pkt: &[u8]) -> io::Result<()> {
        let mut frame = Vec::with_capacity(INTERLEAVED_FRAMING_BYTES + pkt.len());
        frame.push(INTERLEAVED_FRAME_MARKER);
        frame.push(self.rtp_ch);
        let len = u16::try_from(pkt.len()).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "RTP packet exceeds 65535 bytes"))?;
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(pkt);
        let guard = self.writer.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        // On Windows, a TcpStream with a write timeout can return WSAEWOULDBLOCK (os error 10035) when the TCP send buffer is full (e.g. bursting ~900 RTP packets for a 1.2 MB keyframe). `write_all` treats that as fatal; retry on WouldBlock/TimedOut instead so the pump drains the buffer over multiple writes.
        crate::rtsp_server::write_all_retry(&guard, &frame)
    }
}

/// `PacketSink` sending RTP as UDP datagrams to the client's negotiated RTP port, per RFC 2326 §12.39 (`client_port`). The socket is bound to the server RTP port advertised in SETUP so the client can correlate source and advertised ports.
pub struct UdpSink {
    sock: UdpSocket,
    dst: SocketAddr,
}

impl UdpSink {
    pub fn new(sock: UdpSocket, dst: SocketAddr) -> UdpSink {
        UdpSink { sock, dst }
    }
}

impl PacketSink for UdpSink {
    fn send(&mut self, pkt: &[u8]) -> io::Result<()> {
        self.sock.send_to(pkt, self.dst).map(|_| ())
    }
}

/// In-memory `PacketSink` recording every packet for assertion in tests. Shares the exact pump code path with the production sinks.
pub struct VecSink {
    packets: Vec<Vec<u8>>,
}

impl VecSink {
    pub fn new() -> VecSink {
        VecSink { packets: Vec::new() }
    }

    pub fn packets(&self) -> &[Vec<u8>] {
        &self.packets
    }

    pub fn into_packets(self) -> Vec<Vec<u8>> {
        self.packets
    }
}

impl Default for VecSink {
    fn default() -> VecSink {
        VecSink::new()
    }
}

impl PacketSink for VecSink {
    fn send(&mut self, pkt: &[u8]) -> io::Result<()> {
        self.packets.push(pkt.to_vec());
        Ok(())
    }
}

/// Drives one frame through the pump core: packetizes `frame` and sends every resulting RTP packet via `sink`, advancing `packetizer`'s sequence number. This is the single shared send path — `run_pump` calls it for each live frame over a real `TcpInterleavedSink` / `UdpSink`, and tests call it over a `VecSink` to assert byte-for-byte parity with `RtpPacketizer::packetize_frame`. A send error (broken transport) propagates as `Err` so the caller can tear the session down.
pub fn pump_frame_into(sink: &mut dyn PacketSink, packetizer: &mut RtpPacketizer, frame: &Frame) -> io::Result<()> {
    for packet in packetizer.packetize_frame(frame) {
        sink.send(&packet)?;
    }
    Ok(())
}

/// Production send path used by `run_pump`: packetizes `frame` and sends every resulting RTP packet via `sink`, pacing large frames (keyframes) by sleeping `PACING_CHUNK_SLEEP` every `PACING_CHUNK_PACKETS` so the burst does not overflow a receiver's initial RTP reorder buffer. Small frames (P-frames) are sent without pacing — they arrive at 33 ms intervals and never approach the buffer's capacity. A send error propagates as `Err` so the caller can tear the session down. This mirrors `pump_frame_into` exactly for the unpaced case, so tests that assert byte-for-byte parity via `pump_frame_into` over a `VecSink` cover the same packetization.
fn pump_frame_into_paced(sink: &mut dyn PacketSink, packetizer: &mut RtpPacketizer, frame: &Frame) -> io::Result<()> {
    let frame_bytes: usize = frame.nalus.iter().map(|n| n.len()).sum();
    let packets = packetizer.packetize_frame(frame);
    let pacing = frame_bytes > PACING_FRAME_THRESHOLD_BYTES;
    for (i, packet) in packets.iter().enumerate() {
        sink.send(packet)?;
        if pacing && (i + 1) % PACING_CHUNK_PACKETS == 0 {
            thread::sleep(PACING_CHUNK_SLEEP);
        }
    }
    Ok(())
}

/// Per-session RTP pump: pulls `Frame`s from the session's `StreamState` receiver, packetizes each per RFC 6184, and sends every RTP packet through the sink. Large frames (keyframes) are paced so the burst does not overflow a receiver's initial RTP reorder buffer — a 1.2 MB keyframe packetized into ~900 RTP packets and sent in ~12 ms causes live555 (VLC) to drop ~475 KB and wait for the next keyframe. Pacing spreads the send over ~100 ms by sleeping between chunk boundaries, giving the receiver time to grow its buffer. Exits on channel disconnect (TEARDOWN / client gone), a sink write error (broken pipe), or the shutdown flag, then removes the client from the hub so the camera thread never blocks on a dead session. A sink write error is logged at WARN (when a logger is attached) so a vanished player is visible in `flvproxy.log`.
pub(crate) fn run_pump(receiver: Receiver<Frame>, mut sink: Box<dyn PacketSink + Send>, state: StreamState, client_id: ClientId, shutdown: Arc<std::sync::atomic::AtomicBool>, logger: Option<&Logger>, peer: SocketAddr) {
    let mut packetizer = RtpPacketizer::new(random_ssrc(), random_seq());
    while !shutdown.load(RELAXED) {
        match receiver.recv_timeout(Duration::from_millis(PUMP_POLL_TIMEOUT_MS)) {
            Ok(frame) => {
                if pump_frame_into_paced(&mut *sink, &mut packetizer, &frame).is_err() {
                    if let Some(logger) = &logger {
                        logger.log(Level::Warn, &format!("rtsp: pump write failed for {peer}; tearing down session"));
                    }
                    let _ = state.remove_client(client_id);
                    return;
                }
            }
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    let _ = state.remove_client(client_id);
}

/// Derives a per-session SSRC from wall-clock nanos xor'd with a process-wide counter, then mixed via splitmix64. Avoids a randomness crate; uniqueness across sessions is provided by the counter, not by cryptographic strength (RTP SSRCs need only be locally unique, per RFC 3550 §3).
fn random_ssrc() -> u32 {
    (splitmix64(session_seed()) >> 32) as u32
}

/// Derives a per-session initial RTP sequence number from the same seed, per RFC 3550 §5.1's recommendation to start at a random offset.
fn random_seq() -> u16 {
    (splitmix64(session_seed()) >> 16) as u16
}

/// Per-call entropy: wall-clock nanos since the Unix epoch xor'd with a monotonic process counter. `unwrap_or_default` keeps it panic-free if the clock is before the epoch.
fn session_seed() -> u64 {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos() as u64;
    let c = COUNTER.fetch_add(1, RELAXED) as u64;
    nanos ^ c.wrapping_mul(GOLDEN_RATIO_64)
}

/// One splitmix64 round (Knuth MMIX), used to diffuse `session_seed`'s raw entropy across the 32-bit SSRC and 16-bit sequence fields.
fn splitmix64(mut z: u64) -> u64 {
    z = z.wrapping_add(SPLITMIX_INCREMENT);
    let mut x = z;
    x ^= x >> 30;
    x = x.wrapping_mul(SPLITMIX_MULTIPLIER);
    x ^= x >> 27;
    x = x.wrapping_mul(SPLITMIX_MULTIPLIER);
    x ^= x >> 31;
    x
}
