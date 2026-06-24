# 08 — UAC elevation prompt for install/uninstall only

## Goal

Let an operator run `flvproxy --install` / `flvproxy --uninstall` from a non-elevated prompt (or a desktop shortcut) and get a UAC elevation prompt automatically, instead of the current "must right-click → Run as administrator" or the cryptic `OpenSCManager failed: Access is denied. (os error 5)`. `--console` (the dev/test ingress) and the no-arg SCM service path must **not** prompt — elevation is only for the SCM-mutating operations.

## Context

Installing/uninstalling a Windows service calls the SCM (`OpenSCManagerW`/`CreateServiceW`/`DeleteService`/`StartServiceW`), which requires administrator privileges. This is true regardless of the account the service runs as — even after step 06 switches the run-as account to the least-privilege `NT SERVICE\flvproxy` virtual account, the *installation* still needs admin (it is the SCM, not the service runtime, that requires elevation). A non-elevated `--install` today fails at `OpenSCManagerW` with `Access is denied (os error 5)`, which the operator must interpret as "re-run as admin" — poor UX for a shortcut-based install.

The chosen design is **relaunch-on-demand**, not a blanket `requireAdministrator` manifest. A blanket manifest would prompt for *every* invocation, including `--console` (dev) and the SCM's own launch of the exe with no args (the service path) — neither needs elevation, and prompting there is wrong (the service path cannot show a UI). Relaunch-on-demand detects a non-elevated `--install`/`--uninstall` and re-spawns itself via `ShellExecuteW(... "runas" ...)`, which triggers exactly one UAC prompt for exactly those operations.

## Approach

1. Add an elevation check usable from `--install`/`--uninstall` before they touch the SCM: determine whether the process token is elevated. Zero-crates FFI: `OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &h)` → `GetTokenInformation(h, TokenElevation, &elev, sizeof, &len)` → read the `TOKEN_ELEVATION` `TokenIsElevated` bool. All advapi32/kernel32, matching the existing `service::win` FFI style. Provide a cross-platform stub (`#[cfg(not(windows))] fn is_elevated() -> bool { true }`) so Linux tests compile.
2. In `app::parse_dispatch` (or a thin wrapper in `main.rs` around the `Install`/`Uninstall` arms): if the operation is `Install`/`Uninstall` and `!is_elevated()`, relaunch the current exe elevated via `ShellExecuteW(NULL, "runas", <exe path wide>, <args wide>, NULL, SW_SHOWNORMAL)` and exit `EXIT_OK` (the elevated copy does the actual work; the non-elevated original is done). On `ShellExecuteW` failure (operator clicked "No" on the UAC prompt, returning a value ≤ 32), print a clear message ("elevation declined; run as administrator") and return `EXIT_FAILURE`.
3. The exe path: `std::env::current_exe()`. The args: re-encode `--install`/`--uninstall` as a wide string. If `current_exe()` fails, fall back to printing the "run as administrator" instruction and `EXIT_FAILURE` (do not attempt a blind relaunch).
4. Do **not** add a manifest. `asInvoker` (the default, no manifest needed) keeps `--console` and the no-arg service path prompt-free; only the explicit `--install`/`--uninstall` arms relaunch elevated.
5. Keep `--console` and the no-arg (service) path exactly as-is — they never call `is_elevated()` and never relaunch.

## Scope

In: an `is_elevated()` helper (Windows FFI + Linux stub) in a new small `src/elevate.rs` or folded into `service::win` (gated so the stub exists on Linux); the relaunch-on-demand logic around the `Install`/`Uninstall` dispatch arms in `main.rs`/`app.rs`; `ShellExecuteW` FFI (shell32).

Out: a `requireAdministrator` manifest (rejected — prompts `--console`/service path); a `build.rs`/windres manifest-embed step; changing `--console` or the service path; any change to the SCM FFI itself (it already works when elevated).

## Test

- `is_elevated()` cannot meaningfully run on Linux (no token API); the `#[cfg(not(windows))]` stub returns `true` so Linux `cargo test` is unaffected. Add a Linux test that the stub returns `true` (guards the cfg wiring).
- The relaunch path is Windows-runtime-only; verify `cargo build --target x86_64-pc-windows-gnu` compiles the `ShellExecuteW` + token FFI.
- Manual Windows smoke test (acceptance): from a **non-elevated** cmd/PowerShell, run `flvproxy --install` — expect a UAC prompt, and on "Yes" the install proceeds (cert generated, service registered auto-start + started). Click "No" → clear "elevation declined" message, non-zero exit. From an already-elevated prompt, `--install` runs directly (no double-prompt). `flvproxy --console` from a non-elevated prompt must **not** prompt and must run normally.

## Files

- `src/elevate.rs` (new) or `src/service.rs` — `is_elevated()` Windows FFI + Linux stub.
- `src/main.rs` — relaunch-on-demand around the `Install`/`Uninstall` arms; `ShellExecuteW` FFI (shell32); `current_exe()` + wide-arg encoding.
- `src/lib.rs` — `pub mod elevate;` if a new module.

## Acceptance

- Non-elevated `flvproxy --install` triggers exactly one UAC prompt and completes the install on "Yes".
- Non-elevated `flvproxy --uninstall` triggers exactly one UAC prompt and completes the uninstall on "Yes".
- `flvproxy --console` (non-elevated) runs with no prompt.
- The no-arg service path (SCM-launched) never prompts.
- Host `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`, and `cargo build --target x86_64-pc-windows-gnu` green.

## Notes

- This step is independent of step 06 (account): elevation is needed for the SCM-mutating *install* regardless of the run-as account, so even after step 06 lands this step remains necessary. The two compose: step 06 changes `CreateServiceW`'s `start_name`; step 08 ensures `--install` itself runs elevated.
- `ShellExecuteW` with `"runas"` is the documented "run as administrator" verb; it returns `HINSTANCE` > 32 on success (the launched process's pseudo-handle) and ≤ 32 on failure. The operator declining the prompt surfaces as a failure return, not an exception.
- A subtle correctness point: the elevated relaunch must pass the **same** `--install`/`--uninstall` arg and no others, so the elevated copy runs the same `app::parse_dispatch` path. Do not pass `--console` or other args through.
- If `current_exe()` returns a path with a UNC `\\?\` prefix, `ShellExecuteW` generally accepts it; if a Windows build rejects it, strip the prefix before wide-encoding. Verify in the smoke test.
