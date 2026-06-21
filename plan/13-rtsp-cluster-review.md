# Step 13 — Quality Review: RTSP / RTP / SDP Cluster

**Depends on:** Step 12 (RTSP cluster complete: 08–12). **Type:** Dedicated quality review — adds no features.

## Goal

Before the cluster meets real camera bytes (step 14) and real RTSP clients (human test 2), step back and review the **overall** quality of the stream-state / RTP / SDP / RTSP cluster as a hostile reviewer. This layer is where protocol bugs are costliest to debug live; clean it now.

## Review procedure

Read end to end: `stream_state.rs`, `rtp.rs`, `sdp.rs`, `rtsp_server.rs` (both protocol and runtime halves). Re-read `PROJECT.md` §7 (RTSP), §8 (RTP), §9 (ONVIF — only the SDP/URL overlap), and the RTP/RTSP reference snippets.

Check, concretely:

1. **Protocol correctness vs spec.**
   - RTP header byte layout, marker-bit-on-last-packet-of-frame rule, FU-A indicator/header math, sequence/timestamp handling — re-derive each from `PROJECT.md` and confirm the code matches. Don't trust the tests; trust the spec, then confirm the tests cover it.
   - RTSP: CSeq echoed, Session header on SETUP/PLAY/TEARDOWN, transport echo semantics, `Content-Length` on DESCRIBE, status codes (200/400/454/ 461/503) used correctly.
   - SDP: `\r\n` line endings, `sprop-parameter-sets` = `b64(sps),b64(pps)`, `profile-level-id` from SPS bytes 1-3.
2. **Concurrency soundness (stream_state + RTSP server).**
   - Confirm the camera thread can **never** block on a client (bounded channels + `try_send` + drop-on-full). Re-verify, don't assume.
   - No `Mutex` held across a blocking call (channel recv, socket write, `thread::sleep`). Locks are short and leaf-scoped.
   - Client removal is race-free: a client dropped mid-publish doesn't panic.
3. **The `PacketSink` test seam.** Is it actually clean, or did production paths sneak around it? The `VecSink` test and the real `TcpInterleavedSink`/ `UdpSink` must share the exact same pump code path.
4. **Cross-module consistency.** Error types, logging style, naming (`RtpSessionConfig` vs `RtpPacketizer` vs `RtspSession` — sensible?). `Frame`/`CodecParams` defined once and reused, not redefined.
5. **Abstraction boundaries.** `rtp.rs` must not know about RTSP; `sdp.rs` must not know about sockets; `rtsp_server.rs` orchestrates but delegates packetization to `rtp.rs` and SDP to `sdp.rs`. Fix any leak.
6. **Magic numbers.** `1400`, `90000`, `96`, `0x80`, `0xE0`, `28`, channel `0`/`1`, the `$` byte — all named `const`s with a doc reference.
7. **Resource bounds.** Max clients, read-buffer cap, session timeouts — are they present and named, or did step 12 defer them to step 26? If deferred, confirm a `DEBT.md` `FIX NOW` entry exists (step 26 is after the next review boundary, so it must be tracked).
8. **Tests.** Re-read each test: does it assert exact bytes or just "got something"? Upgrade weak assertions. Are the loopback socket tests deterministic (no race-prone sleeps without assertions)?
9. **Run the full gate:** `cargo build` (no warnings), `cargo test` (green), `cargo clippy -- -D warnings` on the cluster.

## Reconcile `DEBT.md`

- Resolve every `FIX NOW` item from steps 08–12.
- Any `TRIGGER:` items: confirm triggers still concrete.
- Review-induced findings: fix now (preferred) or log.
- State outcome: "DEBT.md empty: confirmed" or list remainder.

## Validation (review pass)

This step passes when:

- Standard Quality Gate green across the whole cluster.
- The reviewer can hand-trace one full frame from `publish_frame` → RTP bytes on the wire (both single-NALU and FU-A paths) and confirm every byte against the spec — no "I think this is right" steps.
- The reviewer can confirm, by reading, that no client can block the camera thread and no lock is held across a blocking call.
- `DEBT.md` reconciled; clean `cargo test` from `cargo clean`.

If real issues surface, **do not proceed to step 14** (which brings in the real camera). Loop back to the offending step(s), fix, re-review.

## Do not

- No new features. No ONVIF. No real camera yet. Review and cleanup only.
- Don't rewrite working, spec-correct code for taste. Changes must address a concrete smell, correctness issue, or debt item.
