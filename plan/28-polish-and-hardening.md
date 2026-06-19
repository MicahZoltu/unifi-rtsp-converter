# Step 28 — Polish and Hardening (Final Pass)

**Depends on:** Step 27.

## Goal

Close the gaps: graceful shutdown across all threads, consistent log levels,
sensible defaults, a sample `flvproxy.ini.example`, and a short README of
operational usage. No new features — just making everything production-quiet.

## Tasks

1. **Graceful shutdown:** a single shared `Arc<AtomicBool>` `shutdown` passed
   to every server (camera listener, RTSP, ONVIF HTTP, ONVIF discovery).
   - Console mode: Ctrl+C / SIGINT handler sets the flag (on Windows use
     `SetConsoleCtrlHandler` via FFI; on Linux use a `signal_hook`-free approach
     — install a tiny `libc`-free SIGINT handler via `signal` FFI, or simply
     poll a flag set by a dedicated thread that blocks on stdin EOF). Pick the
     simplest cross-platform approach and document it.
   - Service mode: the step-18 `handler` sets the same flag on
     `SERVICE_CONTROL_STOP`.
   - Every server's accept loop polls `shutdown` (non-blocking accept + short
     sleep, or `shutdown()` the listener socket from the stop path) and exits.
   - ONVIF discovery sends a `Bye` before exit.
   - Main thread `join`s all worker threads with a 5s timeout each, then exits.
2. **Log hygiene:** ensure INFO-level cadence is sane (connection events, SPS/
   PPS, RTSP client connect/teardown, ONVIF discovery) and WARN/ERROR only for
   actual problems. Add a periodic stats line every 60s: `stats: fps=N
   clients=N uptime=HhMm`.
3. **Defaults & sample config:** ship `flvproxy.ini.example` mirroring
   `PROJECT.md` §2 with comments. `Config::load_or_default` already handles
   absence (step 01).
4. **README:** a concise top-level `README.md` covering build, install,
   console mode, camera setup link (point at `PROJECT.md` "Camera Setup"),
   RTSP URL, ONVIF discovery expectations, and log location. (Only create this
   because the user is shipping software — this is the one explicit exception
   to the "no docs unless requested" rule; the project is at completion.)
5. **Final lint pass:** `cargo build --release` clean, `cargo test` all green,
   no `unwrap()`/`expect()` in non-test, non-startup code paths (every parse/
   network error must be logged and recovered). `cargo clippy` if available
   with `-D warnings` on the logic modules (clippy is a tool, not a crate dep
   — acceptable; if not installed, skip).

## Validation (automated)

- Graceful shutdown test: start the full in-process wiring (camera mock + RTSP
  + ONVIF), set `shutdown`, assert all four server threads exit within 5s
  (assert via `JoinHandle::join().timeout(Duration::from_secs(5))` — implement
  the tiny timeout helper with a poll loop, no crate).
- Ctrl+C path on Linux (if implemented): send SIGINT to the process, assert it
  exits 0 within 5s and the log shows a "shutting down" line.
- No-panic regression: re-run the step-17 robustness suite; everything still
  green.
- `cargo test` full suite green from a clean `cargo clean`.
- `cargo build --release` (Linux host) and
  `cargo build --release --target x86_64-pc-windows-gnu` (Windows cross-build)
  both succeed, and the Windows `.exe` is self-contained (no MinGW-runtime DLL
  dependencies — re-verify the step-00 `objdump` check).

## Definition of Done

- All 0–27 step validations (automated + human tests 1–4) pass.
- `cargo test` green on Linux CI.
- Release binary runs as a Windows service, ingests the UniFi camera's
  extendedFlv stream, and serves it via RTSP and ONVIF to a third-party NVR.
- Log file rotates, never fills disk; service survives camera flapping and
  client abuse.

## Quality Gate (mandatory — step is not complete until this passes)

This step **is** the final review, so its Quality Gate is the most stringent:

Run the **Standard Quality Gate** from `plan/README.md` across the **entire
codebase** (every module, not just touched ones). Then do a full pass as a
hostile reviewer:

- Re-read `PROJECT.md` end to end and confirm every requirement in
  "Implementation Specification" §1–12 is met. List any gap → fix or log.
- Confirm the module layout matches "File Structure" exactly (or every
  deviation is justified in `DEBT.md`).
- Confirm there is exactly one source of truth for every config-derived value
  (ports, IP, paths) and trace each.
- Confirm no `unsafe` outside `service.rs`, and every `unsafe` block has a
  `// SAFETY:` note.
- Confirm `DEBT.md` is empty or every remaining item has a concrete `TRIGGER:`
  that is still plausible. State "DEBT.md empty: confirmed" or list remainder.

**Hard rules:**
- If the gate fails, you do **not** declare the project done.
- If passing it properly requires reworking an earlier step, do that rework now — **iterating or redoing is preferred over hacking to move on.**

## Debt notes

This is the final reconciliation. Resolve or re-justify every `DEBT.md` item.
The acceptable end state is: `DEBT.md` empty, OR a short list of items each
with a `TRIGGER:` tied to a genuinely out-of-scope future event (e.g. "audio
support", "second camera model") — and each such item is acceptable to the
human overseer. Surface the final `DEBT.md` contents to the overseer before
declaring done.

## Do not

- Don't add new protocol features. Don't add audio. Don't add HEVC. Don't add
  authentication. Scope is locked to `PROJECT.md`.
