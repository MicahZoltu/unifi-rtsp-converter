# Technical Debt Ledger

This file is the single source of truth for deferred work, known hacks, and
"good enough for now" decisions. It is maintained from build-plan step 00
onward. See `plan/README.md` → "Quality Bar & Anti-Debt Discipline" for the
rules.

## Format

One line per item:

```
step NN | <file>:<area> | <what is the debt> | <FIX NOW | TRIGGER: concrete future event>
```

- `FIX NOW` items **must** be resolved before the next dedicated review
  milestone (`06r`, `11r`, `16r`, `19`).
- `TRIGGER:` items name the exact future event that forces revisiting them.
- At each review, reconcile: every item is either resolved (delete the line)
  or re-justified with a fresh trigger. No item lives forever unchallenged.
- If this file is empty, that is the goal state — say so explicitly in each
  review ("DEBT.md empty: confirmed").

## Active items

step 00 | .cargo/config.toml:rustflags | Dropped `-static-libwinpthread` from the Windows GNU static-link rustflags: this build host's MinGW-w64 GCC 14 uses the win32 thread model, which rejects that flag (it is a posix-thread-model flag) and does not link winpthread at all, so the two remaining flags already yield a self-contained exe (verified via objdump). | TRIGGER: build host switches to a posix-thread-model MinGW (`x86_64-w64-mingw32-gcc -v` reports `--enable-default-msvcrt`/posix threads), at which point re-add static winpthread linking to keep the exe free of `libwinpthread-1.dll`.
step 03 | src/flv_parser.rs:OversizedTag path | On `OversizedTag` the framer clears its buffer and resets to the `PrevTagSize` state, dropping any bytes after the bad tag header. This is not a real resync scan; it merely stops the multi-MiB allocation and hands control back to the caller. | TRIGGER: step 17 (error-handling-and-resync) implements the resync scan — at that point replace the buffer-clear with byte-retention so the scanner can locate the next valid tag boundary.
step 11 | src/rtsp_server.rs:logging | The RTSP server runtime (accept loop, `handle_client`, RTP pump) handles every error path by closing the connection / removing the client but does not yet emit log lines: no module in the RTSP cluster wires the `logging::Logger`, and `RtspServer` has no logger field. Connection/parse/disconnect events are silently handled, not swallowed. | TRIGGER: step 19 (polish-and-hardening) wires structured logging across the server — at that point thread an `Arc<Logger>` (or equivalent) through `RtspServer`/`ConnectionCtx`/`run_pump` and log connection accept/disconnect, parse errors, pump write failures, and the 503/461 boundary responses.
step 11 | src/rtsp_server.rs:session idle timeout | `SESSION_TIMEOUT_SECS` (60) is advertised in SETUP `Session:` headers but never enforced: an idle RTSP TCP connection that never sends TEARDOWN is held open indefinitely (the non-blocking read loop has no idle deadline, and a streaming-but-silent PLAY session must not be killed by a read timeout, so the simple `set_read_timeout` approach is wrong). Max-clients and read-buffer caps are implemented; idle-session reaping is not. | TRIGGER: step 17 (error-handling-and-resync) implements client cleanup — at that point add a session-idle reaper (track last-activity per session, reap sessions idle past `SESSION_TIMEOUT_SECS` that are not in `playing` state) and a RTCP-based keepalive decision for playing sessions.
step 12 | src/main.rs:console_main LAN IP | `detect_lan_ip` uses the UDP connect-to-8.8.8.8 trick with a 127.0.0.1 fallback to populate the RTSP SDP origin / advertised IP. It selects one interface's IP heuristically and fails closed to loopback in air-gapped setups; multi-interface selection and config-driven advertised-IP are out of scope for the step-12 console smoke. | TRIGGER: step 13 (end-to-end RTSP) serves real RTSP clients — at that point replace `detect_lan_ip` with proper advertised-IP selection owned by the config/ONVIF layers (or read an explicit `server_ip` from `flvproxy.ini`).
