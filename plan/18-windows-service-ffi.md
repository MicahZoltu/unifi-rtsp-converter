# Step 18 — Windows Service FFI Lifecycle

**Depends on:** Step 17 (full app must run as a console app first).

## Goal

Implement the SCM integration from `PROJECT.md` §1 using direct FFI to
`advapi32.dll`/`kernel32.dll` — no `windows-service`/`windows-sys` crates.
Wire it so the same `console_main()` body runs under SCM, with a stop event
gated on `SERVICE_CONTROL_STOP`.

## Tasks — `src/service.rs` (`#[cfg(windows)]`)

1. FFI declarations exactly as specified in `PROJECT.md`:
   - `advapi32`: `StartServiceCtrlDispatcherW`,
     `RegisterServiceCtrlHandlerExW`, `SetServiceStatus`,
     `OpenSCManagerW`, `CreateServiceW`, `DeleteService`, `OpenServiceW`,
     `CloseServiceHandle`, `StartServiceW`, `ControlService`.
   - `kernel32`: `CreateEventW`, `SetEvent`, `WaitForSingleObject`,
     `CloseHandle`.
   - `#[repr(C)]` structs: `ServiceTableEntryW`, `ServiceStatus`,
     `SERVICE_STATUS_HANDLE`, plus the `SERVICE_CONTROL_*` / `SERVICE_*`
     constants.
2. `extern "system" fn service_main(argc: u32, argv: *mut *mut u16)`:
   - Register control handler with `ServiceMain` name + a
     `extern "system" fn handler(ctrl: u32, ...) -> u32`.
   - Report `SERVICE_START_PENDING` (check_point increments, wait_hint ~3s).
   - Spawn the app body (camera + RTSP + ONVIF) on worker threads, passing a
     cloned `Arc<AtomicBool>` shutdown flag and the SCM status handle.
   - Report `SERVICE_RUNNING` with `SERVICE_ACCEPT_STOP`.
   - `WaitForSingleObject(stop_event, INFINITE)`.
   - Set shutdown flag (threads wind down), report `SERVICE_STOP_PENDING`,
     then `SERVICE_STOPPED`, return.
3. `handler(ctrl, ...)`: on `SERVICE_CONTROL_STOP` → `SetEvent(stop_event)`,
   return `NO_ERROR`. On `SERVICE_CONTROL_INTERROGATE` → return current
   status. Ignore others.
4. `fn run_as_service() -> i32`: build the `ServiceTableEntryW` (name =
   `flvproxy` as UTF-16), call `StartServiceCtrlDispatcherW`. Return its exit
   code.
5. `main.rs` dispatch:
   - `--console` → `console_main()` (the existing path; default for dev).
   - no args (launched by SCM) → `service::run_as_service()`.
   - `--install` / `--uninstall` → step 18b below (could be same step; keep
     here).
6. UTF-16 helpers: `fn to_wide(s: &str) -> Vec<u16>` with trailing NUL. Tiny,
   testable on any platform (put the helper outside `#[cfg(windows)]` or in a
   shared module so its test runs in CI).

## Tasks — install/uninstall (`#[cfg(windows)]`)

7. `fn install() -> i32`: `OpenSCManagerW(null, null, SC_MANAGER_CREATE_SERVICE)`
   → `CreateServiceW(name, display "UniFi FLV Proxy", SERVICE_WIN32_OWN_PROCESS,
   SERVICE_DEMAND_START, bin_path, ...)` → set description → close. Log result.
   - `bin_path` = current exe path + `" --run"` arg (or rely on no-arg =
     service mode). Decide and document.
8. `fn uninstall() -> i32`: `OpenSCManagerW` → `OpenServiceW(name, DELETE|
   SERVICE_STOP|SERVICE_QUERY_STATUS)` → if running, `ControlService(SERVICE_
   CONTROL_STOP)` (wait) → `DeleteService` → close. Log result.

## Validation

This step's logic cannot be unit-tested on Linux (FFI is Windows-only). Two
tiers:

**Automated (run anywhere):**
- `to_wide("abc")` → `vec!['a','b','c',0]`; `to_wide("")` → `vec![0]`;
   round-trip a string with a non-ASCII char.
- Argument parsing in `main.rs`: `--console` / `--install` / `--uninstall` /
   no-arg each select the right dispatch branch (test the dispatcher function,
   not `main` itself). On non-Windows, the service/install/uninstall branches
   return a clear "Windows-only" error code without calling FFI.
- `cargo check --target x86_64-pc-windows-gnu` (run on the Linux build host)
   → must compile cleanly (this is the real gate for the FFI code). It uses the
   same `.cargo/config.toml` static-link flags from step 00; the produced
   `flvproxy.exe` is self-contained and needs nothing installed on the Windows
   host.

**🛑 STOP AND HUMAN TEST 4 — Service install / start / stop / uninstall**

Requires the cross-compiled binary on a Windows host (built on Linux — no
software needs to be installed on the Windows machine).

1. On the Linux build host:
   `cargo build --release --target x86_64-pc-windows-gnu`, then copy
   `target/x86_64-pc-windows-gnu/release/flvproxy.exe` to the Windows machine.
2. From an admin shell:
   - `flvproxy.exe --install` → `sc query flvproxy` shows the service exists
     (STATE: STOPPED).
   - `sc start flvproxy` → `sc query flvproxy` shows `STATE: 4 RUNNING`
     within a few seconds; `flvproxy.log` shows the startup line with all
     endpoints.
   - With the camera pointed at it, VLC plays `rtsp://...:8554/stream` (re-run
     the essence of HUMAN TEST 2 while running as a service — quick sanity, no
     need to repeat ONVIF).
   - `sc stop flvproxy` → `sc query flvproxy` shows `STATE: 1 STOPPED`
     within ~5s; log shows a clean shutdown line (threads wound down, no
     abrupt termination).
   - `flvproxy.exe --uninstall` → `sc query flvproxy` reports "service does
     not exist".
3. Robustness: start the service **without** the camera connected → it stays
   RUNNING (listener bound, no crash); then point the camera at it → frames
   flow (re-uses HUMAN TEST 1 pass criteria, quick version).
4. Robustness: `sc stop` while an RTSP client is mid-stream → service stops
   cleanly within ~5s (clients dropped, no orphan threads — verify by checking
   Task Manager shows the process exit).

**Pass criteria:** all of the above succeed; no leftover process; service
re-installs cleanly after uninstall.

**Expected duration:** ~5 minutes.

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

Windows-FFI-specific: the `unsafe` blocks must be minimal and each `unsafe`
block must have a `// SAFETY:` justification (this is the **one** sanctioned
comment exception — FFI safety requires it). Raw pointer reads/writes are
guarded by length checks. No `unwrap` on FFI return values that can fail.

## Debt notes

If anything was deferred (a workaround, a "good enough for now", an unclear decision), append a line to `DEBT.md` at the repo root (create the file if absent — see `plan/README.md` for the format):

`step NN | <file>:<area> | <what> | <FIX NOW | TRIGGER: ...>`

- `FIX NOW` items must be resolved before the next dedicated review (`06r` / `11r` / `16r` / `19`).
- `TRIGGER:` items must name the concrete future event that forces revisiting them.
- No silent hacks: if you hacked it, log it. If you can fix it now, fix it now and don't log it.

## Do not

- No `windows-sys`, no `windows`, no `windows-service` crates. Direct FFI only.
- Don't run the service as `LocalSystem` unless required — `NT
  AUTHORITY\LocalService` is safer; but SCM-registered services default to
  LocalSystem. Pick LocalService in `CreateServiceW` if straightforward,
  otherwise LocalSystem and document.
