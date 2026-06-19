# Step 22 — ONVIF WS-Discovery (UDP Multicast)

**Depends on:** Step 21.

## Goal

Make the proxy discoverable: listen on UDP multicast `239.255.255.250:3702`
for WS-Discovery `Probe` messages and reply with a `ProbeMatch` advertising the
device as a `NetworkVideoTransmitter` with the device service XAddrs. Also
optionally send a one-shot `Hello` on startup (some NVRs require it).

## Tasks — `src/onvif_discovery.rs`

1. Build the SOAP/XML for `ProbeMatch` and `Hello` as `&str` templates +
   `format!` with the device XAddr (`http://<ip>:<port>/onvif/device_service`)
   and a stable UUID-ish device address (derive from serial or a random u128
   at startup, formatted as `urn:uuid:...`).
2. `fn build_probe_match(xaddr: &str, device_addr: &str) -> String` — include
   `d:Types` = `tns:NetworkVideoTransmitter` (and optionally `tds:Device`).
3. `fn parse_probe(buf: &[u8]) -> Option<String>` — cheap detection: does this
   UDP datagram contain a WS-Discovery `Probe` element? If so, extract the
   `relates_to` MessageID so we can echo it in `RelatesTo` of the reply (best
   effort; if extraction fails, omit `RelatesTo`). A regex-free substring scan
   is acceptable.
4. `struct Discovery { xaddr: String, device_addr: String,
   shutdown: Arc<AtomicBool> }`.
5. `Discovery::run()`:
   - Join multicast group `239.255.255.250` on `0.0.0.0:3702` using
     `UdpSocket` + `join_multicast_v4`. Bind a **second** ephemeral socket for
     sending replies (or reuse the bound socket; pick what works on Windows).
   - Send a one-shot `Hello` to the multicast group on startup.
   - Loop `recv_from`; on `Probe`, unicast the `ProbeMatch` back to the
     sender's addr (per WS-Discovery: replies go to the *reply address*,
     usually the source of the Probe).
   - On shutdown flag, send a `Bye` and exit.
6. Cross-platform note: `join_multicast_v4` works on both Linux and Windows
   via `std::net`. Use `set_multicast_loop_v4(false)` for the sender.

## Validation (automated) — `tests/onvif_discovery.rs`

XML builders (no socket):
- `build_probe_match("http://10.0.0.5:8080/onvif/device_service",
  "urn:uuid:abc")` → string contains `<wsa:Address>http://10.0.0.5:8080/...
  </wsa:Address>`, `tns:NetworkVideoTransmitter`, the XAddrs, and well-formed
  SOAP envelope with `wsdiscovery:ProbeMatches`.
- `build_hello(...)` → contains `wsdiscovery:Hello` and the XAddrs.
- `build_bye(...)` → contains `wsdiscovery:Bye`.
- `parse_probe` on a synthetic `Probe` SOAP envelope with a known MessageID →
  returns `Some(message_id)`; on a `ProbeMatch` or garbage → `None`.

Loopback multicast (logic-level, no real NVR):
- Bind a `Discovery` instance on the real multicast address (this test joins
  the group from a *second* `UdpSocket` in the test and sends a synthetic
  `Probe`). Assert the test socket receives a `ProbeMatch` within 2 seconds
  that contains the configured XAddr and `NetworkVideoTransmitter`.
- Send a `Bye`-shaped or random datagram → no reply (no hang).
- **Caveat:** multicast loopback behavior differs by OS. If CI doesn't support
  it reliably, gate this test behind `#[cfg(not(ci))]` or skip on environments
  where `join_multicast_v4` errors; document the requirement. The XML-builder
  tests must always run.

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

- Don't implement `ProbeMatches` d:Scopes fully — a minimal/empty `d:Scopes`
   is fine; some NVRs filter on `onvif://www.onvif.org/Profile/Streaming`,
   add that scope string (cheap, helps discovery) — include it and test for it.
