# Step 16 — Protect Controller Emulation: Recon Capture Tool

**Depends on:** Step 15 (synthetic end-to-end RTSP path proven).
**Type:** Protocol discovery — produces no production code, only a throwaway
capture tool and a `DEBT.md`/`PROJECT.md` findings record.

## Goal

The camera does **not** push uPFLV to a plain TCP port on its own. Per the
UniFi Protect adoption model (reverse-engineered by
`NorthernMan54/unifi-cam-proxy-redalert`), the camera first opens a **TLS
WebSocket** to the controller on **port 7442** to perform an AVClient
handshake, and only afterward streams uPFLV over a **TLS WebSocket** on **port
7550**. Before we can implement either side we must confirm, against the *real*
camera, the exact first bytes it sends on 7442 and whether the HTTPS adoption
endpoint on 443 is required when an operator simply types the controller IP
into the camera's "UniFi Protect Server" box.

This step builds a **listen-only** recon tool: it accepts inbound TLS WebSocket
connections on 7442 (and optionally 7550), completes the WS upgrade
best-effort, and hex-dumps / logs every inbound frame. It makes **no outbound
connections** to the camera. The operator runs it on the proxy host, points the
camera at it, and pastes the captured output back so steps 18–20 can be
implemented against ground truth rather than guesswork.

## Background — the 5-stage Protect flow (from redalert's reverse-engineering)

| Stage | Direction | Port | Protocol | Purpose |
|-------|-----------|------|----------|---------|
| 1 | Controller → Camera | 10001 | UDP | Discovery broadcast (DEFERRED — manual IP entry suffices) |
| 2 | Controller → Camera | 443 | HTTPS | `POST /api/1.2/manage` adoption (token + controller hostnames) |
| 3 | Camera → Controller | 7442 | WSS (TLS WS) | AVClient handshake: token auth + `HELLO_FEATURES` + settings |
| 4 | Controller ↔ Camera | 7442 | WSS | Controller pushes settings/adoption details |
| 5 | Camera → Controller | 7550 | WSS (TLS WS) | uPFLV video/audio/metadata uplink (our `UPFLV_PREFIX` lives here) |

What the operator's camera log showed (`192.168.50.100:7442 is not reachable`)
is **stage 3**: the camera tried to open the 7442 WSS handshake and nothing
answered. The open questions this step resolves:

- Does typing the controller IP in the camera UI cause the camera to attempt
  7442 directly with a device-default token, or does it first require stage 2
  (HTTPS 443 `/api/1.2/manage` adoption)?
- What is the exact first WS frame the camera sends on 7442 (the `HELLO_FEATURES`
  document shape)?
- Which TLS cipher suites / SNI does the camera require?

## Tasks — `src/bin/protect_recon.rs` (throwaway, `[[bin]]` target)

1. **TLS via SChannel (throwaway stopgap).** Add the `schannel` crate to
   `Cargo.toml` as a Windows-only dependency (`[target.'cfg(windows)'.dependencies]`)
   **for this throwaway recon tool only**. This deliberately violates
   `PROJECT.md`'s zero-crates rule — the violation is tracked in `DEBT.md` and
   resolved by step 17, which replaces `schannel` with a hand-rolled
   `src/tls_schannel.rs` raw-FFI module that the production path (steps 18–21)
   reuses. First action of this step: verify `schannel` cross-compiles from the
   Linux build host:
   `cargo check --target x86_64-pc-windows-gnu --bin protect_recon`. **There is
   no fallback plan for the recon tool itself** — if SChannel cannot
   cross-compile, stop and reconsider before proceeding (per project decision:
   SChannel only, deal with problems when reached).
2. **Self-signed cert, generated offline.** Do NOT add a cert-generation crate.
   Generate a self-signed cert on the build host (openssl) or on Windows
   (`New-SelfSignedCertificate`) and ship the PFX/PEM beside the recon exe. The
   recon tool loads it at startup. Document the exact command in this file's
   "Cert generation" section once chosen.
3. **Listen-only 7442 (and optional 7550) WSS acceptor.** Bind
   `0.0.0.0:7442`, accept TLS, then best-effort complete the RFC 6455 WebSocket
   upgrade (a minimal handshake is fine for recon — full framing lands in step
   18). On any inbound frame, hex-dump it to stdout and to a capture file
   `protect_recon_7442.log`. Optionally do the same on 7550.
4. **No outbound connections.** The tool must never dial the camera. It only
   listens. (This is an operator trust constraint: capture tools must not reach
   into the camera.)
5. **Graceful Ctrl+C exit** (reuse the `console_shutdown` pattern from
   `main.rs`).

## Validation — 🛑 STOP AND HUMAN CAPTURE

This step has **no automated tests** (it is a throwaway Windows-only capture
tool against real hardware). It "passes" when the operator has run it and
returned the capture. Concretely:

1. Build: `cargo build --release --target x86_64-pc-windows-gnu --bin protect_recon`.
2. Operator runs `protect_recon.exe` on the proxy host (beside the shipped cert).
3. Operator enters the proxy IP in the camera's "UniFi Protect Server" box.
4. Operator observes + pastes back:
   - Whether the camera connected to 7442 at all (or whether it first tried
     443 and the tool saw nothing on 7442 — in which case stage 2 adoption is
     required, escalating scope to step 19's 443 endpoint).
   - The hex dump of the first WS frame(s) on 7442.
   - Any TLS negotiation details visible.

The findings are recorded as a `DEBT.md` `TRIGGER`-style note (or directly
folded into step 19's task list) so steps 18–20 implement against confirmed
byte shapes, not redalert's second-hand description.

## Quality Gate (Standard, scoped)

- `cargo build --target x86_64-pc-windows-gnu --bin protect_recon` is clean.
- `cargo clippy --target x86_64-pc-windows-gnu --bin protect_recon -- -D warnings`.
- The recon tool is gated so it does **not** break the Linux `cargo test` run
  (Windows-only binary; the throwaway `schannel` dependency is under
  `[target.'cfg(windows)'.dependencies]` so Linux builds stay zero-crates and
  green; it is removed by step 17).
- The throwaway nature is explicit: this binary is removed (or moved under a
  `tools/` path) once step 21 confirms the real path works.

## Debt notes

Log a `DEBT.md` entry capturing the recon findings (is 443 adoption required?
exact first 7442 frame shape?). This becomes the spec input for steps 18–20.
Also log the deliberate `schannel` zero-crates violation for this throwaway
tool, with `TRIGGER: step 17 replaces schannel with hand-rolled
src/tls_schannel.rs and deletes the dependency`.

## Do not

- Do not implement the full AVClient protocol here — that is step 19.
- Do not implement production WebSocket framing here — that is step 18. This
  tool only needs enough WS to capture frames.
- Do not make the recon tool dial the camera.
