# Step 09 — RTP Packetization (RFC 6184)

**Depends on:** Step 04 (NALU shape).

## Goal

Turn a `Frame` (list of NALUs) into a sequence of RTP packets (byte vectors)
following RFC 6184: single-NALU packets for small NALUs, FU-A fragmentation for
large ones, correct marker bit on the last packet of the frame, shared
timestamp per frame, incrementing sequence number.

## Tasks — `src/rtp.rs`

1. `struct RtpSessionConfig { ssrc: u32, start_seq: u16, start_ts_offset: u32 }`
   — caller seeds randomness (or tests pass deterministic values).
2. `struct RtpPacketizer { ssrc: u32, seq: u16, payload_type: u8 /* =96 */ }`.
   - `RtpPacketizer::new(ssrc, start_seq)`.
3. `const MAX_PAYLOAD: usize = 1400;` (NALU ≤ this → single packet; > → FU-A).
4. `fn packetize_frame(&mut self, frame: &Frame) -> Vec<Vec<u8>>`:
   - RTP timestamp = `frame.timestamp_ms * 90` (u32 wraparound is fine).
   - For each NALU (in order):
     - If NALU.len() ≤ MAX_PAYLOAD: build a single-NALU packet.
     - Else: FU-A fragment into ceil((len-1)/chunk) packets, chunk size =
       MAX_PAYLOAD - 2 (FU indicator + FU header). First chunk includes the
       start flag; last chunk includes the end flag; payload is NALU body
       **excluding** the original 1-byte NALU header (the type is carried in
       the FU header).
   - **Marker bit** = 1 only on the last packet of the **last NALU** of the
     frame; 0 otherwise.
   - Sequence number increments per packet (wraps u16).
5. RTP header builder (12 bytes):
   - byte 0 = `0x80` (v2, no pad, no ext, no CSRC)
   - byte 1 = `(marker << 7) | (pt & 0x7F)`
   - bytes 2-3 = seq (BE u16)
   - bytes 4-7 = timestamp (BE u32)
   - bytes 8-11 = ssrc (BE u32)
6. FU-A helpers per `PROJECT.md`:
   - FU indicator = `(nalu_header & 0xE0) | 28`
   - FU header = `(start<<7)|(end<<6)|(nalu_header & 0x1F)`

## Validation (automated) — `tests/rtp.rs`

- Single small NALU (`[0x67, 0xAA]`, an SPS-like 2 bytes), `is_keyframe=true`,
   timestamp 100 ms → exactly **1** packet. Assert:
   - header byte0 = `0x80`, byte1 = `0xE0` (marker=1, PT=96),
   - seq = start_seq, ts = `100*90 = 9000`, ssrc correct,
   - payload == `[0x67, 0xAA]`.
- Frame with 2 small NALUs → 2 packets; marker bit set only on the 2nd; both
   share the same timestamp; seq increments by 1.
- Large NALU of 3000 bytes (header `0x65`, IDR-like) → FU-A fragmentation:
   - Packet 1: FU indicator `0x65 & 0xE0 | 28 = 0x60`, FU header `0x80 | 0x05
     = 0x85`, payload = first 1398 body bytes, marker=0.
   - Middle packets: FU header `0x05`, marker=0.
   - Last packet: FU header `0x40 | 0x05 = 0x45`, marker=1 (if it's the only
     NALU in the frame).
   - Reassemble: concatenate body chunks across packets → equals the original
     2999 body bytes (NALU minus header). Assert exact equality.
- Large NALU as **first** of a 2-NALU frame → its last FU-A packet has
   marker=0; the final small NALU's packet has marker=1.
- Sequence number wraps: feed 70000 frames' worth of single packets (or
   construct a packetizer with start_seq near `0xFFFF`) → assert wrap to 0
   happens correctly.
- Empty frame (zero NALUs) → returns empty `Vec` (no packets), no panic.
- Exactly-MAX_PAYLOAD-sized NALU → single packet (boundary), not FU-A.

## Quality Gate (mandatory — step is not complete until this passes)

Run the **Standard Quality Gate** from `plan/README.md`. Then **step back and review the whole codebase**, not just the diff:

- Does this change respect the module boundaries in `PROJECT.md`, or did you bend them? If bent, refactor now.
- Did consuming this step reveal that an earlier module's API is awkward, mis-named, or leaky? Go back and fix that module — do not paper over it here.
- Any new duplication across modules? Extract a shared helper into the owning module.
- Are logging, error, and test styles consistent with the conventions established by earlier steps?
- Did you introduce a `// TODO` / `// FIXME` / `// HACK`, commented-out code, or a magic number? Remove it, name it as a constant, or log it in `DEBT.md`.

**Hard rules:**
- If the gate fails, you do **not** proceed to the next step.
- If passing it properly requires reworking an earlier step, do that rework now — **iterating or redoing is preferred over hacking to move on.**
- A step that "works but feels hacky" is a failed step. Reopen it.

## Debt notes

If anything was deferred (a workaround, a "good enough for now", an unclear decision), append a line to `DEBT.md` at the repo root (create the file if absent — see `plan/README.md` for the format):

`step NN | <file>:<area> | <what> | <FIX NOW | TRIGGER: ...>`

- `FIX NOW` items must be resolved before the next dedicated review (`07` / `13` / `24` / `27`).
- `TRIGGER:` items must name the concrete future event that forces revisiting them.
- No silent hacks: if you hacked it, log it. If you can fix it now, fix it now and don't log it.

## Do not

- Do not send packets over the network yet (that's RTSP server, step 12).
- Do not handle RTCP.
