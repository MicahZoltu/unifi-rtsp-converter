# Build Plan Index

This folder breaks the UniFi Camera FLV-to-RTSP/ONVIF Proxy (see `../PROJECT.md`) into bite-sized, sequentially-validatable steps.

## How to use this plan

- Work through steps **in order**. Each step lists what it **Depends on**.
- Every step has a **Validation** section and a mandatory **Quality Gate** (see below). Validation is either:
  - **Automated tests** — pure-logic unit/integration tests runnable on any platform (`cargo test`). Tests must exercise **logic only**, never real cameras or live RTSP/ONVIF clients.
  - **Human test** — a short, manual check against a real camera or a real RTSP/ONVIF client (VLC / ffprobe / ONVIF Device Manager). These are infrequent and called out explicitly with a 🛑 **STOP AND HUMAN TEST** banner. Do **not** proceed past one until the human confirms it passes.
- Do not move to the next step until the current step's validation **and** Quality Gate both pass.

---

## 🛑 Human-Action Alerting (MANDATORY for any step that needs a human)

Several steps require a human to perform an action the agent cannot do itself: running a binary on a Windows host, pointing a physical camera at the proxy, clicking through a dialog, cleaning up a persisted key, running a manual test in VLC, etc. **Human steps have been missed in the past because the agent assumed the human was closely following along and reading the plan themselves.** This is no longer acceptable. The convention below is mandatory for every agent implementing any step that has a human-action component.

### When a human action is needed, the agent MUST:

1. **Not silently "finish" the step.** A step is not complete while a human action is pending. The agent's final response for that turn must make the pending human action impossible to miss.

2. **End its turn with a clearly-marked human-action block** at the very top of its final response (before any optional technical summary), using this exact format:

   ```
   ## 🛑 HUMAN ACTION REQUIRED

   **You need to do this before we can continue.**

   ### What to do
   <one or more numbered steps the human can follow with zero context. Each
   step gives the exact command to run or UI action to take, on which machine,
   in which directory.>

   ### Why
   <one or two sentences: what this action unblocks and why the agent could
   not do it itself.>

   ### When you're done
   <what the human should paste back / report, or what "done" looks like, so
   the agent knows to proceed.>
   ```

3. **Use highly-visible markup** so the block stands out in a scrolling terminal: the `## 🛑 HUMAN ACTION REQUIRED` heading, bold lead-in, and emoji (🛑 / ✅) are mandatory. Plain prose buried mid-response does not count.

4. **Assume the human has zero context.** Spell out: which machine (Linux build host vs Windows target host), which directory, the exact one-liner command, and the expected output. Do not say "run the self-test" — say `protect_recon.exe --selftest --password recon` and quote the success line to look for.

5. **Give commands as single one-liners**, never multi-line backtick blocks that need copy-paste-fixup. If a command is long, use a single line; the human can wrap it in their shell.

6. **List every distinct human action** the step needs, even if some are optional cleanup (e.g. deleting a persisted key). Mark optional ones `### (optional) ...`.

7. **Cross-reference `DEBT.md`** if a human action is tracked there (e.g. cleanup with a `TRIGGER:`), so the human-action block and the debt ledger agree.

### What counts as a human action

- Running any cross-compiled binary on the Windows target host (the agent builds on Linux; it cannot run a `.exe`).
- Pointing the physical camera at the proxy / entering an IP in the camera UI.
- A manual test in VLC / ffprobe / ONVIF Device Manager.
- Installing/starting/stopping/uninstalling the Windows service.
- Any OS-level cleanup the agent cannot perform (deleting a persisted cert via `certmgr.msc`, removing a firewall rule, etc.).
- Any dialog or prompt the tool surfaces that requires a human click.

### What does NOT count (agent does it itself)

- Writing code, tests, docs, plan files, `DEBT.md` entries.
- Running `cargo build` / `cargo test` / `cargo clippy` on the Linux host.
- Cross-compiling the Windows binary.
- Generating a PFX with `openssl` on the Linux host (if the agent has shell access — it does).

If unsure whether something is a human action, treat it as one and surface it.

---

## ⚔️ Quality Bar & Anti-Debt Discipline (read this first — it governs every step)

The single most important property of this codebase is that it stays **clean and maintainable** as it grows. We minimize technical debt by addressing it **the moment it appears**, not later. The rules below are mandatory and override any "just get it working" pressure.

### Mindset

- **Iterate or redo work rather than hack.** If the clean way to make a step pass requires changing an earlier module, restructure it now. A hack that saves 20 minutes today costs hours later and is **not** acceptable.
- **Step back after every change.** Don't only ask "do my new tests pass?" Ask "is the *whole* codebase still clean after this change?" A change that works but degrades overall quality is a failed change.
- **Leave camp cleaner than you found it.** If you touch a module, fix any pre-existing smells you notice in it (naming, dead code, missing docs) — small inline cleanups don't need their own step.
- **No silent deferrals.** Anything you can't fix immediately goes into `DEBT.md` with a concrete trigger (see below). A hack that isn't logged doesn't exist for the next reviewer — that's how debt hides.

### Standard Quality Gate (applies to **every** step, run before marking complete)

1. `cargo build` is clean with **zero warnings**.
2. `cargo test` is fully green (run from a clean state if anything is flaky).
3. `cargo clippy -- -D warnings` on touched modules (clippy is a tool, not a crate dependency — acceptable; if unavailable, skip but note it in `DEBT.md`).
4. **No** `unwrap()` / `expect()` / `panic!()` / `todo!()` / `unimplemented!()` in non-test, non-startup code. Every fallible operation is handled and logged.
5. **No** dead code, unused imports, or commented-out code. `#![dead_code]` allowances are not permitted without a `DEBT.md` entry.
6. **No magic numbers.** Protocol constants, sizes, timeouts, ports → named `const`s with a brief doc of their origin (RFC section, spec line).
7. **No** `// TODO` / `// FIXME` / `// HACK` in committed code without a matching `DEBT.md` entry. (And remember: no comments at all unless explicitly requested — prefer self-describing names.)
8. **Public API** items (`pub fn`, `pub struct`, `pub enum` and their fields, `pub const`) have `///` rustdoc explaining intent, not re-stating the name.
9. **Naming** is consistent with the rest of the codebase (modules singular, types `UpperCamelCase`, functions/vars `snake_case`, constants `UPPER_SNAKE`).
10. **No duplicated logic.** If two modules need near-identical code, factor a shared helper into the module that owns that concept.
11. **Errors are meaningful and exhaustive.** Error enums cover the real failure modes; nothing is `Box<dyn Error>` or a stringly-typed catch-all. Errors are logged at the boundary, never silently swallowed.
12. **Tests assert exact values**, not `assert!(x.is_some())`. Byte-for-byte / string-for-string where feasible. Each test name says what it asserts.
13. **Diff sanity:** if a single step's diff grew unexpectedly large, either split the step or justify the size in the step's Debt notes. Large diffs hide debt.
14. **Whole-codebase scan:** re-read every module this step's change could have affected. Confirm module boundaries from `PROJECT.md` still hold and no earlier abstraction leaked.
15. **Comment and newline hygiene:** re-check touched modules against `AGENTS.md` → "Comments and line wrapping" before declaring done — delete reiterative comments, remove or track future-author markers, and rejoin mid-sentence prose wraps. These accumulate silently; sweeping them each change is mandatory, not optional. `cargo fmt --check` (driven by `rustfmt.toml`) is the mechanical formatting gate; comment/wrap quality is a review judgment, not an automated lint.

**Hard rule:** if any gate item fails, the step is **not complete**. You do not proceed. If fixing it properly means reworking an earlier step, you do that rework now.

### `DEBT.md` — the running technical-debt ledger

Maintained at the repo root from step 00 onward. One line per item:

```
step NN | <file>:<area> | <what is the debt> | <FIX NOW | TRIGGER: concrete future event>
```

- `FIX NOW` items **must** be resolved before the next dedicated review milestone (`07`, `13`, `25`, `28`).
- `TRIGGER:` items name the exact future event that forces revisiting them (e.g. `TRIGGER: when audio support is added`, `TRIGGER: when a second codec is needed`).
- Reviews reconcile the ledger: every item is either resolved (removed) or re-justified with a fresh trigger. No item lives forever unchallenged.
- If `DEBT.md` is empty, that's the goal state — say so explicitly in each review ("DEBT.md empty: confirmed").
- **`DEBT.md` is for uncertain or conditional deferrals** — a shortcut taken now whose resolution depends on something that may or may not happen (an environment change, a future review's taste call, a protocol edge case production may never surface). It is **not** a to-do list for work a future step will definitely do. If the work is concrete, knowable, and assigned to a specific future step, edit that step's plan file (`plan/N-*.md`) instead. A `DEBT.md` entry whose entire payload is "TRIGGER: step N will do X" — where X is already well-defined — is a smell: the forward assignment belongs in `plan/N-*.md`, and `DEBT.md` should record only *why the current code is a shortcut* if a hostile reviewer reading it today needs that context.

### Dedicated review milestones

Three deeper, holistic reviews are intermixed as their own numbered steps. They don't add features — they exist **only** to evaluate overall codebase quality across a whole cluster and pay down debt before it compounds:

- **`07`** — after the parser cluster (FLV/AVC/extended/AMF) is complete.
- **`13`** — after the RTSP cluster (state, RTP, SDP, protocol, server) is complete.
- **`25`** — after the ONVIF cluster (SOAP, discovery, wiring) is complete.
- **`28`** — final review (also serves as the project's Definition of Done review).

At each review: read **every** module in the cluster as a hostile reviewer, check cross-module consistency (error types, naming, logging, test style), verify the `PROJECT.md` module boundaries still make sense, run the full test suite, and reconcile `DEBT.md`. **A review that finds real issues does not proceed** — it loops back to the relevant step(s) and fixes them.

---

## Cross-cutting conventions (apply to every step)

1. **Zero external crates.** `Cargo.toml` has **no dependencies** on any platform — only `std` and direct Win32 FFI declarations (`extern "system"` blocks linked against `advapi32`/`kernel32`/`crypt32`/`secur32`). This applies to the Protect-controller TLS (steps 16–21) as well: TLS on the camera's 7442/7550 channels is provided by the Windows **SChannel** SSPI via a hand-rolled `#[cfg(windows)]` FFI module (`src/tls_schannel.rs`, added in step 17) — we vendor **no crypto source** and pull in **no crates** (not `schannel`, not `windows-sys`). The hand-rolled RFC 6455 WebSocket framing and the AVClient JSON protocol are TLS-agnostic and stay zero-crates, compiling and testing on Linux over plain loopback TCP. No fallback TLS implementation is planned.
> **History note:** step 16's throwaway recon tool temporarily used the `schannel` crate as a stopgap (a deliberate, `DEBT.md`-tracked policy violation). Step 17 replaced it with the hand-rolled `tls_schannel` module and deleted the dependency; after step 17 the tree is fully zero-crates on every target.
2. **Platform strategy.** Networking uses `std::net` (cross-platform). Only the Windows service FFI in `src/service.rs` and the Protect-controller TLS wrap in steps 16–21 are `#[cfg(windows)]`-gated. All *logic* (parsers, packetizers, SDP, RTSP framing, SOAP templates, config, WebSocket framing, AVClient protocol) must compile and run its tests on Linux so `cargo test` works in CI without a Windows host.

## Build prerequisites

The project builds on **Linux** (dev/CI) and cross-compiles to **Windows** without requiring any software installed on the target Windows host.

### Build host (Linux) — install once

1. **Rust toolchain** (stable), via <https://rustup.rs>:
   - `rustup toolchain install stable`
   - `rustup component add clippy rustfmt` (clippy is referenced by the Quality Gate)
2. **Windows cross-compile target** (GNU variant — lightest setup, produces a self-contained `.exe`):
   - `rustup target add x86_64-pc-windows-gnu`
   - MinGW-w64 linker/toolchain: on Debian/Ubuntu `apt install gcc-mingw-w64-x86-64`; on Fedora `dnf install mingw64-gcc`; on Arch `pacman -S mingw-w64-gcc`.
3. **No C dependencies, no build scripts, no system headers beyond MinGW.** `Cargo.toml` has zero external crates, so nothing else is fetched or built. (Step 16's throwaway recon tool temporarily pulled `schannel` for the Windows target only; step 17 removed it — see convention #1's history note.)

### Target host (Windows) — install nothing

The cross-compiled binary is fully self-contained. Step 00 adds a `.cargo/config.toml` that forces static linking of the MinGW runtime (`-static-libgcc -static-libstdc++ -static-libwinpthread`), so the resulting `flvproxy.exe` depends only on system DLLs that ship with Windows (`kernel32.dll`, `advapi32.dll`, etc.). No MinGW runtime, no Visual C++ redistributable, no .NET — nothing to install on the Windows machine beyond copying the `.exe` (and optionally `flvproxy.ini`).

### Commands

- Logic tests (run on the Linux build host): `cargo test`
- Host build (Linux, for dev): `cargo build --release`
- Windows release binary: `cargo build --release --target x86_64-pc-windows-gnu` → produces `target/x86_64-pc-windows-gnu/release/flvproxy.exe`
- Windows compile-check only (faster, no link): `cargo check --release --target x86_64-pc-windows-gnu`
3. **Test style.** Construct synthetic byte vectors / request strings by hand. No fixture files captured from a real camera are required for automated tests (but a captured sample may optionally be added later for a human smoke test). Tests assert exact bytes / exact strings.
4. **No comments** unless explicitly requested (prefer self-describing names; `///` doc-comments on public API are required, not optional). The full rule — comments explain *why*, never restate *what*; no future-author markers without a `DEBT.md`/plan reference; newlines carry semantic meaning only; `rustfmt` (`rustfmt.toml`, `max_width = 10000`) is the sole wrapping authority — lives in `AGENTS.md` → "Comments and line wrapping", with good/bad examples and a per-change definition-of-done checklist. That section refines (does not repeal) this bullet.
5. **Module layout** follows `PROJECT.md`'s "File Structure" section. New modules are added as the steps that own them are implemented. If a step discovers the layout is wrong, fix the layout — don't fight it.

## Step sequence

| # | File | Subject | Validation type |
|---|------|---------|-----------------|
| 00 | `00-scaffolding.md`            | Cargo project, module skeletons, CI build, `DEBT.md` | automated |
| 01 | `01-logging-and-config.md`     | File logger w/ rotation + INI config parser | automated |
| 02 | `02-flv-prefix-and-header.md`  | uPFLV magic prefix + FLV header parsing | automated |
| 03 | `03-flv-tag-state-machine.md`  | FLV tag framing state machine | automated |
| 04 | `04-avc-config-and-nalus.md`   | AVCDecoderConfigurationRecord + length-prefixed NALU extraction | automated |
| 05 | `05-extended-video-tags.md`    | ExVideoTagHeader (SequenceStart / CodedFrames / CodedFramesX) | automated |
| 06 | `06-script-metadata.md`        | AMF0 onMetaData → width/height/fps | automated |
| 07 | `07-parser-cluster-review.md`  | **Quality review: whole parser cluster + DEBT reconcile** | review |
| 08 | `08-stream-state.md`           | Shared state, SPS/PPS store, keyframe ring buffer, client registry | automated |
| 09 | `09-rtp-packetization.md`      | RTP header + single-NALU + FU-A fragmentation (RFC 6184) | automated |
| 10 | `10-sdp-generation.md`         | SDP builder, profile-level-id, sprop-parameter-sets, base64 | automated |
| 11 | `11-rtsp-protocol.md`          | RTSP request parser + response builder (OPTIONS/DESCRIBE/SETUP/PLAY/TEARDOWN, transport negotiation) | automated |
| 12 | `12-rtsp-server.md`            | RTSP accept loop, per-session state, interleaved+UDP transport, fed by a *mock* frame source | automated |
| 13 | `13-rtsp-cluster-review.md`    | **Quality review: whole RTSP/RTP/SDP cluster + DEBT reconcile** | review |
| 14 | `14-tcp-listener-and-flv-pipeline.md` | Camera TCP listener → FLV parser → stream state | automated + 🛑 HUMAN TEST 1 |
| 15 | `15-end-to-end-rtsp.md`        | Wire real camera frames into the RTSP server (synthetic path) | 🛑 HUMAN TEST 2 |
| 16 | `16-protect-recon.md`                 | Protect controller emulation — listen-only recon capture tool (7442 WSS) | 🛑 HUMAN CAPTURE |
| 17 | `17-tls-schannel-handrolled.md`       | Hand-rolled SChannel SSPI TLS module (zero-crates) + self-test; deletes step-16 `schannel` dep | 🛑 MANUAL (self-test + camera re-capture) |
| 18 | `18-protect-ws-framing.md`            | RFC 6455 WebSocket framing layer (hand-rolled, TLS-agnostic, zero-crates) | automated |
| 19 | `19-protect-avclient-7442.md`         | 7442 AVClient JSON protocol (hello/paramAgreement/timeSync/…) | automated |
| 20 | `20-protect-upflv-7550.md`            | 7550 WSS uPFLV ingestion → existing `FlvParser` | automated |
| 21 | `21-protect-human-test.md`            | Wire Protect controller into `console_main`; real camera (no SSH) end-to-end | ✅ complete |
| 22 | `22-onvif-soap.md`                    | ONVIF Device + Media SOAP services over HTTP | automated |
| 23 | `23-onvif-wsdiscovery.md`             | WS-Discovery Probe/ProbeMatch UDP multicast | automated |
| 24 | `24-onvif-end-to-end.md`              | Discovery + Media service + RTSP URL wired together | 🛑 HUMAN TEST 3 |
| 25 | `25-onvif-cluster-review.md`          | **Quality review: whole ONVIF cluster + DEBT reconcile** | review |
| 25b | `25b-camera-reconnect-investigation.md` | Investigate and resolve the ~7-10s camera reconnect cycle by reading the Protect Node.js source | 🛑 HUMAN TEST |
| 26 | `26-error-handling-and-resync.md`     | Resync scan, reconnect, client cleanup, never-crash guarantees | automated |
| 27 | `27-windows-service-ffi.md`           | SCM FFI lifecycle (`#[cfg(windows)]`) | compile-only + 🛑 HUMAN TEST 4 (install/start/stop/uninstall) |
| 28 | `28-polish-and-hardening.md`          | Final quality review + graceful shutdown, log levels, defaults, docs | automated + review |

## Human tests at a glance

> Every entry below is a 🛑 HUMAN ACTION. See "🛑 Human-Action Alerting" above for the mandatory format an agent must use when surfacing these to the human.

| # | When | What | Expected duration |
|---|------|------|-------------------|
| 1 | After step 14 | Point camera at proxy; tail log; confirm frames are parsed (SPS/PPS + NALUs logged) | ~5 min |
| 2 | After step 21 | Open `rtsp://<proxy>:8554/stream` in VLC / ffprobe against the **real camera** (no SSH) via the Protect controller emulator | ~10 min |
| 3 | After step 24 | Use ONVIF Device Manager to discover the proxy and open its stream | ~10 min |
| 4 | After step 27 | `--install`, `sc start`, `sc stop`, `--uninstall`; confirm clean lifecycle | ~5 min |

> **Note on human test 2:** step 15 delivers a synthetic end-to-end path (mock frame source → RTSP → client) validated by automated tests. The real camera, no-SSH path depends on the Protect controller emulator (steps 16–21); human test 2 against a real camera therefore lands at step 21. Step 16 additionally produces a one-off 🛑 HUMAN CAPTURE (pointing the camera at a listen-only recon tool) to confirm the 7442 protocol shape, and step 17 re-validates the hand-rolled TLS against the same camera.
