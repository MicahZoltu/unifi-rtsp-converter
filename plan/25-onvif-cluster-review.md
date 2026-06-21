# Step 25 — Quality Review: ONVIF Cluster

**Depends on:** Step 24 (ONVIF cluster complete: 22–24, plus the wired 14–15).
**Type:** Dedicated quality review — adds no features.

## Goal

With ONVIF SOAP + WS-Discovery wired in and verified against a real NVR (human
test 3 passed), step back and review the **overall** quality of the ONVIF layer
and its integration with the rest of the system. This is the last review
before the Windows-service FFI and final hardening — clean ONVIF debt now so
the service wrapper wraps something solid.

## Review procedure

Read end to end: `onvif_server.rs`, `onvif_discovery.rs`, and the
`console_main` wiring in `main.rs`. Re-read `PROJECT.md` §9 and the ONVIF SOAP
example.

Check, concretely:

1. **Protocol correctness vs spec.**
   - SOAP 1.2 envelope structure, namespaces (`s:`, `tds:`, `trt:`, `tt:`,
     `wsa:`, `wsdiscovery:`), `SOAPAction`/namespace dual routing.
   - WS-Discovery: multicast addr `239.255.255.250:3702`, `Hello`/`Bye`/
     `ProbeMatch` shapes, `RelatesTo` echo, `d:Types` =
     `tns:NetworkVideoTransmitter`, the `onvif://www.onvif.org/Profile/Streaming`
     scope.
   - `GetStreamUri` returns the **same** RTSP URL the RTSP server actually
     serves (single source of truth for `server_ip`/`rtsp_port`).
2. **Single source of truth for endpoints.** `server_ip`, `rtsp_port`,
   `onvif_port` must come from one `Config`/shared struct and flow into SDP,
   ONVIF XAddrs, and `GetStreamUri` without re-derivation. Hunt for any place
   that hardcodes an IP/port and route it through the shared config.
3. **XML safety.** Every dynamic string inserted into SOAP XML goes through
   the escape helper. No `format!`-into-XML that bypasses it. Confirm with the
   escape test from step 22.
4. **Cross-module consistency.** Logging style, error handling, naming. The
   ONVIF HTTP server's request loop should look like the RTSP server's
   (similar structure, similar teardown) — diverge only where the protocol
   genuinely differs. Excessive divergence is a smell.
5. **Abstraction boundaries.** `onvif_server.rs` builds SOAP; it must not
   parse FLV or know RTP. It consumes `StreamState::snapshot_metadata()` only.
   `onvif_discovery.rs` is pure UDP + XML templates. Fix any leak.
6. **Robustness.** Malformed SOAP → SOAP Fault (not a panic, not a 500 with
   empty body). Unknown action → `ActionNotSupported`. Oversized POST body →
   rejected (cap, like the RTSP read buffer). HTTP client disconnects mid-body
   → no thread leak.
7. **Config flag.** `onvif_discovery = false` actually suppresses the
   discovery thread (and the `Hello`/`Bye`), not just the Probe responses.
8. **Tests.** Router tests assert exact XML substrings; the loopback HTTP test
   asserts status + content-type + body. Are there tests for the fault paths
   and the escape path? Add any missing.
9. **Run the full gate:** `cargo build` (no warnings), `cargo test` (green),
    `cargo clippy -- -D warnings`.

10. **`WsConnection` API decision (from step-19 DEBT, resolved here).** Decide
    whether `ws::WsConnection` should grow a "surface Pings / custom-pong"
    mode so the 7442 AVClient path can use the high-level connection type
    instead of calling `ws::parse_frame`/`ws::encode_frame` directly. The
    driver: the camera's UniFi keepalive is a WS **Ping** control frame
    (opcode 0x9) carrying `ping-<N>` that must be answered with a WS **Text**
    frame `pong-<N>` (not a WS Pong), and `WsConnection::read_frame`
    currently auto-replies with a Pong and swallows the Ping — both answering
    incorrectly and hiding the keepalive from the AVClient layer. If
    `WsConnection` gains the mode, switch `AvClientSession` to it; if not,
    accept the current direct-call as intentional and remove the open
    question.
11. **Camera-identity → ONVIF decision (from step-22 DEBT, resolved here).**
    Decide whether `OnvifConfig` should surface the real camera serial/firmware
    learned from the 7442 AVClient `paramAgreement`/`hello` exchange, via a
    shared `Arc<Mutex<CameraIdentity>>` populated by the Protect controller
    and read by `OnvifServer`. If not, keep the static defaults (`4.73.112` /
    `000000000000`) and document them as intentional in `onvif_server.rs`.
    Note: an NVR that keys device identity on the serial sees a placeholder
    until this is decided.

## Reconcile `DEBT.md`

- Resolve every `FIX NOW` item from steps 14–23.
- `TRIGGER:` items: confirm triggers still concrete.
- Review findings: fix now or log.
- State outcome: "DEBT.md empty: confirmed" or list remainder.

## Validation (review pass)

This step passes when:

- Standard Quality Gate green across the whole codebase (not just ONVIF — this
  is a full `cargo test`).
- The reviewer confirms there is exactly one source of truth for every
  endpoint/URL and can trace each from `Config` to its use site.
- The reviewer confirms no dynamic string enters SOAP XML unescaped.
- `DEBT.md` reconciled; clean `cargo test` from `cargo clean`.

If real issues surface, **do not proceed to step 26.** Loop back, fix, re-review.

## Do not

- No new features. No auth, no PTZ, no events service. Review and cleanup only.
- No rewriting spec-correct XML/SOAP for taste. Changes address a concrete
  smell, correctness issue, or debt item.
