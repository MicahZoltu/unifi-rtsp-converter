# 07 — Service auto-start on install

## Goal

Make `--install` leave the proxy actually running and configured to start on boot, so an operator who runs `flvproxy --install` once is done: no `sc.exe start`, no reboot needed to bring it up after a future restart. Today the service is registered with `SERVICE_DEMAND_START` and the install message tells the operator to run `sc.exe start flvproxy` themselves — an unnecessary manual step that the install path can eliminate.

## Context

`service.rs:win::install` registers the service with `SERVICE_DEMAND_START` (`service.rs` `win` constants) and returns, printing `start with: sc.exe start flvproxy`. The cert generation (step 05) already runs pre-`CreateServiceW`, so by the time the service is registered the PFX is on disk and `service_main` can load it. Starting immediately after registration is therefore safe and matches user intent ("install it and walk away").

The service account stays `LocalSystem` for now; the switch to a least-privilege account is tracked separately as step 06. Auto-start is orthogonal to the account choice — `SERVICE_AUTO_START` + `StartServiceW` works identically under `LocalSystem` and the future `NT SERVICE\flvproxy` virtual account.

## Approach

1. Change the `CreateServiceW` `dwStartType` from `SERVICE_DEMAND_START` (0x3) to `SERVICE_AUTO_START` (0x2). Rename the constant to `SERVICE_AUTO_START` and rewrite its doc comment to explain the rationale (a streaming proxy is useful only when running; an install should leave it active; `service_main` fast-fails cleanly on a runtime error like a bound port).
2. Add an FFI declaration for `StartServiceW` (advapi32, `extern "system"`) to the existing `service::win` extern block. Call it after `ChangeServiceConfig2W` (description set) and before `CloseServiceHandle(svc)`, with `argc = 0` / `argv = NULL` (the SCM launches `flvproxy.exe` with no args; `app::parse_dispatch` routes no-arg to the service path).
3. Handle `StartServiceW` failure without aborting the install: the service is already registered with `SERVICE_AUTO_START`, so a start failure (port 7552 already bound, cert unreadable at runtime, service already running) is a runtime issue, not an install failure. Map `GetLastError` via `io::Error::last_os_error()` and:
   - `ERROR_SERVICE_ALREADY_RUNNING` (1056) → informational line ("already running").
   - Any other failure → stderr warning telling the operator the service is registered for boot but could not start now, and to run `sc.exe start flvproxy` after fixing the issue.
   - Success → print `installed and started (auto-starts on boot)`.
   In all three cases return `EXIT_OK` (the install itself succeeded).
4. Update the `install()` top-level doc comment (`service.rs`) from "demand-start" to "auto-start" and note the immediate start.

## Scope

In: `SERVICE_AUTO_START` constant; `StartServiceW` FFI + call in `win::install`; install message text; `install()` doc comment.

Out: the service account change (step 06); UAC elevation (step 08); any change to `service_main` / `run_as_service` / `SetServiceStatus` lifecycle; any change to the cert path or `App::bootstrap`.

## Test

- `cargo build --target x86_64-pc-windows-gnu` must compile the `StartServiceW` FFI and the new start-type constant.
- The start/failure-message logic is Windows-runtime-only (the SCM is not available on Linux); there is no Linux-visible unit test for `StartServiceW`. The existing top-level `service` tests (dispatch, message text) stay green.
- Manual Windows smoke test (acceptance): `sc.exe stop flvproxy` then `--uninstall` to clear prior state; run `flvproxy --install` and confirm (a) the message says `installed and started`, (b) `sc.exe query flvproxy` reports `RUNNING`, (c) `sc.exe qc flvproxy` reports `START_TYPE : 2  AUTO_START`. Then `sc.exe stop`, `sc.exe start`, confirm it comes back up; reboot (or restart the service) confirms boot auto-start.
- The "already running" branch: with the service already running, re-run `--install` — expect `CreateServiceW` to fail with `ERROR_SERVICE_EXISTS` (the existing `CreateService failed` path); that is pre-existing behavior, not changed by this step (this step only adds `StartServiceW` on the success path). If a future step wants idempotent `--install` (open-if-exists + ensure-auto-start), that is separate scope.

## Files

- `src/service.rs` — `SERVICE_AUTO_START` constant (replaces `SERVICE_DEMAND_START`); `StartServiceW` FFI decl; call + message logic in `win::install`; `install()` doc comment.

## Acceptance

- `sc.exe qc flvproxy` shows `START_TYPE : 2  AUTO_START` after `--install`.
- The service is `RUNNING` immediately after `--install` (no separate `sc.exe start`).
- A start failure does not make `--install` return non-zero or un-register the service.
- Host `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`, and `cargo build --target x86_64-pc-windows-gnu` green.

## Notes

- This step touches the same `win::install` function as steps 05 (cert) and 06 (account); coordinate so all three land cleanly. The cert generation runs first (pre-`CreateServiceW`), then `CreateServiceW` (this step's auto-start type), then `ChangeServiceConfig2W`, then this step's `StartServiceW` — order is fixed by the function's existing structure.
- `StartServiceW` blocks until `service_main` reports `SERVICE_RUNNING` (or fails) — the SCM serializes this. If `service_main` hangs the install would appear to hang; the existing `service_main` reports `SERVICE_RUNNING` promptly after `App::spawn`, so this is not a concern. A stuck `service_main` would be a separate bug.
