# Step 18 — Protect Controller: 7442 AVClient Protocol

**Depends on:** Step 17 (WebSocket framing layer), Step 16 (recon findings).
**Type:** Automated — pure-logic JSON protocol over the WS layer, TLS-agnostic,
Linux-testable.

## Goal

Implement the AVClient JSON message protocol the camera speaks over the 7442
WSS channel (stage 3–4 of the Protect flow). The camera authenticates with a
token, sends a `HELLO_FEATURES` document, and the controller replies to a series
of request/response messages (`paramAgreement`, `timeSync`, `getSystemStats`,
`updateFirmwareRequest`, …) framed with `messageId` / `inResponseTo` /
`timeStamp`. The reverse-engineered message shapes come from
`NorthernMan54/unifi-cam-proxy-redalert`'s `Unifi/wss_manager.py`, confirmed
against the step-16 recon capture.

When this step is done, a camera that completes the 7442 handshake considers
itself "adopted/connected" and is ready to open the 7550 streaming channel
(step 19). The TLS wrap is still not present here — the protocol is unit-tested
on Linux over the plain-WS layer from step 17.

## Tasks — `src/protect_controller.rs` (new module)

1. **`const HELLO_PROTOCOL_VERSION: u32 = 67`** and the `HELLO_FEATURES` map
   (accelerometer, adjustableIR, …) per redalert's `HELLO_FEATURES`. Each
   feature flag is a named `const bool` so nothing is a magic literal.
2. **`struct ControllerMessage`** — `{ message_id: u64, in_response_to:
   Option<u64>, function_name: String, payload: serde_json::Value, ... }`.
   **JSON without a crate:** hand-roll a minimal JSON parser/emitter covering
   only the shapes the AVClient protocol uses (objects, arrays, strings,
   numbers, bools, null). This is bounded — the protocol is not arbitrary JSON.
   If the surface proves too large, escalate to `DEBT.md` and reconsider, but
   do not silently pull `serde_json`.
3. **Message framing:** each WS `Text` frame is one JSON `ControllerMessage`.
   Parse inbound, dispatch by `function_name` to a handler, emit a reply (with
   `in_response_to` = request's `messageId`, fresh `messageId`, `statusCode`/
   `status` payload).
4. **Handlers** (implement just enough to satisfy the camera — exact set
   confirmed by step-16 recon, baseline from redalert):
   - `hello` / feature negotiation → reply with controller features.
   - `paramAgreement` → `_reply_ok` (`statusCode: 0, status: "ok", deviceID`).
   - `timeSync` → reply `{ t1, t2 }` (current millis).
   - `getSystemStats` → reply with nominal CPU/mem/temp stats.
   - `updateFirmwareRequest` → acknowledge, no actual upgrade.
   - `stopService` / `enableLogging` → acknowledge.
   - Unknown `function_name` → log + best-effort ok reply (never crash).
5. **`struct AvClientSession`** owning a `WsConnection`, a monotonic
   `message_id` counter, and a dispatch table. `run(&mut self)` loops
   `read_frame` → dispatch → `write_frame` until clean close.
6. **Token auth:** the camera's first frame carries a token from adoption
   (stage 2). If step-16 recon shows the camera reaches 7442 without 443
   adoption (device-default token), accept a configurable/empty token. If recon
   shows 443 adoption is required, this step's scope expands to a minimal HTTPS
   `/api/1.2/manage` endpoint (log that decision in `DEBT.md`).

## Validation (automated) — `tests/protect_controller.rs`

- Each handler: feed the documented request JSON (as WS `Text` bytes) → assert
  the exact reply JSON byte-for-byte (status code, `inResponseTo` echoes the
  request `messageId`, `deviceID` correct).
- `timeSync` reply's `t1`/`t2` are within a few ms of now (bounded assert).
- A multi-message sequence (hello → paramAgreement → timeSync →
  getSystemStats) over a loopback WS pair completes with the session reaching
  "ready" state.
- Unknown `function_name` → ok reply, no panic, session continues.
- Malformed JSON frame → logged, frame skipped, session continues (no crash).
- `HELLO_PROTOCOL_VERSION` and every feature flag asserted by name in a
  constants test (catches accidental magic-number drift).

## Quality Gate (Standard)

- `cargo build` / `cargo test` / `cargo clippy -- -D warnings` clean on Linux.
- The hand-rolled JSON subset is isolated in one module with a clear doc
  stating it covers **only** AVClient shapes, not general JSON.
- Every protocol constant/feature flag is a named `const` with a redalert-file
  or recon-capture reference.

## Debt notes

- If 443 adoption turns out to be required (per step 16), log the scope
  expansion as `FIX NOW` and implement the minimal `/api/1.2/manage` here.
- The hand-rolled JSON parser is a deliberate zero-crates choice; `TRIGGER:
  step 24 ONVIF cluster review` re-evaluates whether it should become a shared
  `src/json.rs` if ONVIF SOAP (step 21) also needs JSON-ish parsing.

## Do not

- Do not implement the 7550 uPFLV ingestion here — step 19.
- Do not wire into `console_main` here — step 20.
- Do not implement UDP 10001 discovery (deferred per project decision).
