# Step 00 — Project Scaffolding

**Depends on:** nothing.

## Goal

Create the Cargo project, module skeletons, and confirm it builds and runs a
trivial test on both Linux (dev/CI) and Windows (release target).

## Tasks

1. `cargo init --name flvproxy` in the repo root.
2. `Cargo.toml`:
   - `name = "flvproxy"`
   - `edition = "2021"`
   - **No `[dependencies]`** (zero external crates — enforced).
   - `[package]` metadata; `[profile.release]` with `panic = "abort"` is fine.
3. Create empty module files (each just `// placeholder` or a tiny stub) so the
   tree matches `PROJECT.md` "File Structure":
   ```
   src/main.rs
   src/config.rs
   src/service.rs          // guarded with #[cfg(windows)] body, stub elsewhere
   src/flv_parser.rs
   src/avc.rs
   src/stream_state.rs
   src/rtsp_server.rs
   src/rtp.rs
   src/sdp.rs
   src/onvif_discovery.rs
   src/onvif_server.rs
   src/logging.rs
   ```
4. `main.rs`: parse argv for `--install`, `--uninstall`, `--console` (no-op stubs
   that print "not implemented yet") and a default branch that prints a banner.
   Keep it platform-agnostic; the real service FFI lands in step 26.
5. Add a `tests/smoke.rs` integration test asserting `2 + 2 == 4` just to prove
   the test harness works.
6. Add a root `.gitignore` (`/target`, `*.log`, `flvproxy.ini`).
7. Create `DEBT.md` at the repo root with the header/format from
   `plan/README.md` (the running technical-debt ledger). It starts empty.
8. Add `.cargo/config.toml` to force static linking of the MinGW runtime for
   the Windows GNU target, so the cross-compiled `.exe` is self-contained and
   needs nothing installed on the Windows host:
   ```toml
   [target.x86_64-pc-windows-gnu]
   rustflags = [
       "-C", "link-arg=-static-libgcc",
       "-C", "link-arg=-static-libstdc++",
       "-C", "link-arg=-static-libwinpthread",
   ]
   ```
   (See `plan/README.md` → "Build prerequisites".)

## Validation (automated)

- `cargo build` succeeds on Linux.
- `cargo test` passes (smoke test green).
- `cargo build --release --target x86_64-pc-windows-gnu` cross-compiles
  cleanly on Linux (requires `rustup target add x86_64-pc-windows-gnu` +
  MinGW-w64; see `plan/README.md` → "Build prerequisites"). If the toolchain
  isn't present in CI yet, defer this check — but it must pass before the
  first Windows-targeted human test (step 14).
- The produced `flvproxy.exe` is self-contained: running
  `x86_64-w64-mingw32-objdump -p <exe>` (or `ldd`-equivalent) shows **no**
  dependency on `libgcc_s_seh-1.dll`, `libstdc++-6.dll`, or
  `libwinpthread-1.dll` — only standard Windows system DLLs.

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

- Do not pull in any crate. Do not implement service FFI yet. Do not implement
  networking yet.
