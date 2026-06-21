# Step 18 — Protect Controller: WebSocket Framing Layer (RFC 6455)

**Depends on:** Step 17 (hand-rolled SChannel TLS module, which the production WS layer wraps at the outermost socket boundary on Windows), Step 16 (recon confirms the camera speaks WebSocket on 7442). **Type:** Automated — pure-logic, TLS-agnostic, zero-crates, Linux-testable.

## Goal

Implement an RFC 6455 WebSocket **server** framing layer by hand (no crate): the opening handshake (HTTP `Upgrade` response with the `Sec-WebSocket-Accept` SHA-1/base64 of `Sec-WebSocket-Key` + the magic GUID) and the frame parser/encoder (opcodes, masking, payload-length encodings, fragmentation, control frames). The layer is TLS-agnostic: it operates over a `Read`/`Write` trait, so it is fully unit-testable on Linux over plain loopback TCP. The SChannel TLS wrap (the hand-rolled `tls_schannel` module from step 17) is applied only at the outermost socket boundary on Windows (step 20), keeping 100% of this code zero-crates and CI-green on Linux.

This step delivers the reusable substrate that step 19 (AVClient JSON over
7442) and step 20 (uPFLV binary over 7550) both build on.

## Tasks — `src/ws.rs` (new module)

1. **`const WS_MAGIC_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"`** (RFC 6455 §1.3). Document origin.
2. **SHA-1 + Base64 for the accept key.** Hand-roll SHA-1 (RFC 3174) and reuse the existing `sdp::base64_encode` (step 10) for the base64 step. SHA-1 is small (~80 lines) and the only use is the WS handshake; do not pull a crypto crate. Unit-test SHA-1 against the RFC 3174 test vectors and the accept-key against RFC 6455 §4.2.2's worked example.
3. **`fn accept_key(client_key: &str) -> String`** — `base64(SHA1(key + GUID))`. Unit-test with the RFC 6455 example (`dGhlIHNhbXBsZSBub25jZQ==` → `s3pPLMBiTxaQ9kYGzzhZRbK+xOo=`).
4. **`struct WsHandshake`** — parse the inbound `Upgrade` request headers (method, `Host`, `Sec-WebSocket-Key`, `Sec-WebSocket-Version`, optional `Sec-WebSocket-Protocol`), and build the `101 Switching Protocols` response. Tolerate extra headers. Error enum: `WsError::{ MalformedRequest, MissingKey, BadVersion }`.
5. **`struct WsFrame`** — `{ fin: bool, opcode: u8, payload: Vec<u8> }`. Parser reads the 2-byte base header, the extended length (16-bit or 64-bit per §5.2), the 4-byte mask key, and XOR-decodes the payload. Encoder writes server frames (unmasked, per §5.3 — servers MUST NOT mask).
6. **`enum Opcode { Continuation, Text, Binary, Close, Ping, Pong }`** with `from_u8`/`to_u8`. Constants `OPCODE_*`.
7. **`struct WsConnection<RW>`** over a `Read + Write` trait object, with `read_frame(&mut self) -> Result<Option<WsFrame>, WsError>` (returns `None` on clean close) and `write_frame(&mut self, frame) -> Result<(), WsError>`. Handles control frames inline (respond to `Ping` with `Pong`, surface `Close`). Reassembles fragmented messages across `Continuation` frames up to a documented max (constant `MAX_FRAGMENTED_MESSAGE_BYTES`).
8. **A `Plain` impl** over `TcpStream` for tests; step 20 adds a `Tls` impl on Windows (wrapping the step-17 `tls_schannel::TlsStream`). The trait boundary is the only seam.

## Validation (automated) — `tests/ws.rs`

- `accept_key` matches the RFC 6454 §4.2.2 worked example, byte-for-byte.
- SHA-1 of `"abc"`, `""`, and the long-string vector from RFC 3174.
- Handshake: feed a real `Upgrade` request bytes → get back the exact `101` response string (assert byte-for-byte, including headers).
- Handshake rejects: missing `Sec-WebSocket-Key` → `MissingKey`; version != 13 → `BadVersion`; garbage → `MalformedRequest`.
- Frame round-trip over a loopback `TcpStream` pair: write a `Binary` frame, read it back, assert payload equality. Cover the three length encodings (≤125, 126, 127) and a masked client frame (decoder must unmask correctly).
- Control frames: a `Ping` sent by one side yields a `Pong` reply; a `Close` yields `None` (clean close) to `read_frame`.
- Fragmentation: three `Continuation` frames reassemble into one message.
- Over-sized fragmented message → `WsError` (no unbounded allocation).

## Quality Gate (Standard)

- `cargo build` / `cargo test` / `cargo clippy -- -D warnings` clean on Linux (no TLS touched here — this is the TLS-agnostic layer).
- No `unwrap`/`expect`/`panic!` in non-test code.
- Every magic byte/opcode/length threshold is a named `const` with an RFC §ref.
- SHA-1 implementation is isolated and documented as WS-handshake-only (not a general crypto primitive) so no one is tempted to reuse it for security.

## Debt notes

If SHA-1-by-hand raises review concerns at step 25, the trigger is logged (`TRIGGER: step 25 ONVIF cluster review re-evaluates the hand-rolled SHA-1`). The alternative (SChannel's `CryptCreateHash`) is Windows-only and would break the Linux-testable invariant, so hand-roll is the deliberate choice.

## Do not

- Do not implement the AVClient JSON protocol here — step 19.
- Do not implement the 7550 uPFLV ingestion here — step 20.
- Do not touch the TLS layer here — it is step 17's `tls_schannel` module; the wrap is step 20's outer seam only.
