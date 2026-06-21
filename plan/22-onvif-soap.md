# Step 22 — ONVIF Device + Media SOAP Services

**Depends on:** Step 08 (CodecParams/metadata), Step 10 (server_ip concept).

## Goal

A minimal HTTP/SOAP 1.2 server on `onvif_port` implementing the handful of ONVIF requests an NVR needs to discover the stream URL. Mostly static XML templates with a few dynamic values. No SOAP framework — hand-rolled request routing by `SOAPAction` header / body namespace, and string-built responses.

## Tasks — `src/onvif_server.rs`

1. `struct OnvifConfig { server_ip: String, rtsp_port: u16, onvif_port: u16, device_service_path: &'static str, media_service_path: &'static str, firmware: String, serial: String }` with sensible defaults (manufacturer "Ubiquiti", model "UVC-G5-Bullet").
2. `fn build_device_wsdl_template(cfg) -> String` and equivalents for media — **optional**: many NVRs don't fetch WSDL; only implement if a human test in step 24 needs it. Start without WSDL endpoints; add later if required.
3. SOAP request router — `fn route(soap_action: &str, body: &str, cfg, state) -> (u16, String)` returning `(status_code, xml_body)`:
   - **Device service** (`http://www.onvif.org/ver10/device/wsdl`):
     - `GetCapabilities` → return `Device`/`Media`/`System` XAddrs pointing to `http://<ip>:<port>/onvif/device_service` and `.../media_service`.
     - `GetDeviceInformation` → manufacturer/model/firmware/serial/hardwareId.
     - `GetHostname`, `GetScopes` → minimal stubs (return empty-ish valid responses) — add only if step 24 needs them.
   - **Media service** (`http://www.onvif.org/ver10/media/wsdl`):
     - `GetProfiles` → one `Profile` token `Profile_1`, with `VideoEncoderConfiguration` H264, resolution from `StreamState::snapshot_metadata()` (fallback 1920x1080 if unknown), fps from metadata (fallback 30).
     - `GetStreamUri` (with `Profile_1`) → `rtsp://<ip>:<rtsp_port>/stream` (see `PROJECT.md` example).
     - `GetVideoEncoderConfiguration` → optional, only if needed.
4. HTTP server thread: `TcpListener` on `onvif_port`; per request read headers (until `\r\n\r\n`), read `Content-Length` body, dispatch on `SOAPAction:` header (strip quotes), write `HTTP/1.1 200 OK\r\nContent-Type: application/soap+xml; charset=utf-8\r\nContent-Length: N\r\n\r\n<body>`.
5. All XML built via `format!` against static templates stored as `&str` constants. Escape dynamic strings (IP, model, serial) — minimal XML escape (`&` `<` `>` `"` `'`).
6. Unknown action → SOAP Fault with `wsa:ActionNotSupported`.

## Validation (automated) — `tests/onvif_soap.rs`

Test the **router** directly (no socket) with hand-built request bodies/headers. Also one end-to-end HTTP test via loopback.

Router-level:
- `GetCapabilities` request → response XML contains `<tds:Device><tt:XAddrs>http://127.0.0.1:8080/onvif/device_service</tt:XAddrs>` and a Media XAddrs with `/onvif/media_service`.
- `GetDeviceInformation` → contains `<tds:Manufacturer>Ubiquiti</tds:Manufacturer>`, `<tds:Model>UVC-G5-Bullet</tds:Model>`, non-empty firmware/serial.
- `GetProfiles` → contains `trt:Profiles token="Profile_1"`, `H264`, a `Width`/`Height` (from injected metadata when present, fallback otherwise).
- `GetStreamUri` → contains `<tt:Uri>rtsp://127.0.0.1:8554/stream</tt:Uri>` (exact).
- Unknown SOAPAction → SOAP Fault containing `ActionNotSupported`.
- XML-escape: server_ip set to `"10.0.0.1&<>"` (artificial) → response has escaped entities; no raw `&` from the injected value appears unescaped.

HTTP-level (loopback):
- Bind `OnvifServer` on ephemeral port; use `std::net::TcpStream` to POST a `GetStreamUri` SOAP envelope with `SOAPAction` header; assert `HTTP/1.1 200`, `Content-Type: application/soap+xml`, body parses as XML and contains the RTSP URI.
- `POST` with no `SOAPAction` header but body namespace `http://www.onvif.org/ver10/media/wsdl/GetStreamUri` → still routed correctly (namespace fallback). Verify both routing strategies work.

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

- No WS-Discovery yet (step 23). No real ONVIF client yet (step 24). No authentication (`onvif:User`/`wsse`).
- Don't implement the full ONVIF spec — only what an NVR needs to add the camera and pull the RTSP URL.
