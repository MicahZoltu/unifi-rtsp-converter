# Step 19 — Protect Controller: 7550 WSS uPFLV Ingestion

**Depends on:** Step 17 (WS framing), Step 18 (AVClient handshake, which
instructs the camera to start streaming).
**Type:** Automated — TLS-agnostic ingestion logic on Linux; Windows TLS wrap
compile-checked.

## Goal

Convert the camera-ingestion half of the data path from the step-14
plain-TCP listener to the real Protect transport: a **TLS WebSocket on port
7550**. After the 7442 AVClient handshake (step 18) tells the camera to stream,
the camera opens a second WSS connection to the controller on 7550 and pushes
uPFLV (the `DE 19 16 15 47 17 DE 19 16 75 50` prefix + FLV header + tags) as
**WebSocket binary-message payloads**. This step de-frames those WS messages and
feeds the bytes into the **existing, unchanged** `FlvParser` (step 03) →
`stream_state` (step 08), reusing every line of FLV/AVC/AMF investment.

The `CameraListener` from step 14 is refactored so its byte source is a trait
(`CamByteSource: PlainTcp | WsOverTls`) rather than a raw `TcpStream`. The
plain-TCP path is retained for the synthetic tests; the WSS path is the
production Windows path.

## Tasks

1. **`src/ws.rs` TLS impl (Windows only).** Add `WsConnection<TlsStream>` where
   `TlsStream` wraps `schannel`'s server stream, implementing `Read + Write`.
   `#[cfg(windows)]`-gated. The trait seam from step 17 means the Linux tests
   keep using the `Plain` impl untouched.
2. **`src/camera_listener.rs` refactor.** Extract the read loop behind a
   `CamByteSource` trait (`fn read_chunk(&mut self) -> io::Result<&[u8]>`).
   - `PlainTcpSource` = the current `TcpStream` behavior (step 14, unchanged
     for tests).
   - `WssUpflvSource` = a `WsConnection<TlsStream>` that yields the
     accumulated binary-message payloads (WS frame de-framing happens in
     `ws.rs`; here we just consume the reassembled message bytes).
   - The `detect_and_strip_prefix` / `parse_header` / `FlvParser::push` /
     dispatch logic is **unchanged** — it operates on bytes regardless of
     source. This is the key reuse: step 14's parser pipeline is transport-
     agnostic by construction.
3. **7550 listener** (`#[cfg(windows)]`): bind `0.0.0.0:7550`, TLS-accept,
   WS-upgrade, hand the `WsConnection<TlsStream>` to a new `CameraListener`
   built over `WssUpflvSource`. Reuse the step-14 reconnect/swap logic (one
   active camera connection; new connection force-closes the old).
4. **Controller→camera downlink frames.** The 7550 channel also carries
   controller→camera binary frames prefixed `DE 19 16 75 50` (stream start/stop,
   heartbeats, clock-sync). Implement a minimal heartbeat/start acknowledgement
   so the camera keeps streaming; exact shape from step-16 recon. Log unknown
   downlink frames, never crash.
5. **`StreamState` plumbing unchanged.** `publish_config` / `publish_frame`
   are called exactly as in step 14.

## Validation (automated) — extend `tests/camera_pipeline.rs` + new `tests/ws_upflv.rs`

- **Existing step-14 tests still pass unchanged** (they use `PlainTcpSource`),
  proving the refactor didn't regress the parser pipeline.
- New `tests/ws_upflv.rs`: build the same synthetic extendedFlv byte stream as
  `tests/camera_pipeline.rs`, wrap it in a single WS `Binary` frame over a
  loopback `TcpStream` pair (plain WS, no TLS — Linux-testable), feed it to a
  `CameraListener` over `WssUpflvSource` (using the `Plain` WS impl), and
  assert the **same** `codec()` / `add_client()` frame delivery as the step-14
  tests. This proves the WS de-framing → FlvParser handoff is correct.
- Multi-message stream: header+config in one WS message, keyframe in the next,
  inter in the next → all published in order.
- A WS `Close` frame mid-stream → listener logs, drops the connection, stays
  bound for a reconnect (no panic).
- Windows compile-check: `cargo check --target x86_64-pc-windows-gnu` confirms
  the `schannel` `TlsStream` impl + 7550 listener type-check (the TLS path
  itself is exercised only in step 20's human test).

## Quality Gate (Standard)

- `cargo build` / `cargo test` / `cargo clippy -- -D warnings` clean on Linux
  (the `schannel` paths are `#[cfg(windows)]` and excluded from Linux clippy).
- `cargo check --target x86_64-pc-windows-gnu --all-targets` clean.
- No `unwrap`/`expect`/`panic!` in non-test code.
- The `CamByteSource` trait is the single seam; no FLV/AVC logic is duplicated
  between the plain and WSS paths (if it is, factor it — that's a gate failure).

## Debt notes

- The plain-TCP `CameraListener` path (step 14) is now test-only scaffolding.
  Log `TRIGGER: step 27 (polish) decides whether to remove the plain-TCP path
  or keep it as a debug ingress`. Do not remove it yet — it's the Linux-test
  surface.
- Downlink frame shapes not confirmed by step-16 recon are logged as
  `FIX NOW` until step 20's human test confirms the camera accepts them.

## Do not

- Do not modify `FlvParser`, `avc`, `amf`, or `stream_state` — they are reused
  as-is. If a change there is needed, that's a gate failure signaling the
  transport abstraction leaked; refactor, don't patch.
- Do not wire into `console_main` here — step 20.
