# Production-readiness cleanup plan

This plan covers the remaining work to take `flvproxy` from "feature-complete" to production-ready. It supersedes `DEBT.md`; once every step here is done, `DEBT.md` is deleted (step 08). The old `plan/` directory was removed earlier — these files are a fresh, self-contained plan that does not reference the old step numbers as authoritative (they survive only as historical citations inside source comments, swept clean by step 07).

## Origin

Each step here corresponds to one of the eight `DEBT.md` items, plus the self-signed-cert production concern that surfaced during review. Items that needed no code (DEBT 1, 2, 4, and the firmware half of 3) are pure deletions absorbed by step 08 — they have no dedicated step file. The implement items each get their own file.

## Steps (in recommended order)

| Step | Title | DEBT item | Depends on |
|------|-------|-----------|------------|
| 01 | FLV resync for extendedFlv `0x00` tags | 7 | none |
| 02 | ONVIF stub operations | 5 | none |
| 03 | Multicast egress pinning (`IP_MULTICAST_IF`) | 6 | none |
| 04 | Camera identity → ONVIF serial | 3 (serial half) | none |
| 05 | Self-signed PFX auto-generation | new (production) | none |
| 06 | Service account least-privilege | 8 | 05 (shared `--install` path) |
| 07 | Sweep `plan/…` references | cleanup | all code steps done first |
| 08 | Delete `DEBT.md`, finalize | all | 01–07 |

Steps 01–05 are independent and can be done in any order. Step 06 shares the `--install` entry point with step 05, so do 05 first (or coordinate). Step 07 (reference sweep) is mechanical but churn-heavy, so it goes last to avoid re-touching comments edited by earlier steps. Step 08 is the gate: nothing in `DEBT.md` may remain referenced, and the build must be green.

## Conventions (carry forward from AGENTS.md)

- Zero external crates. All Windows crypto/socket/SCM work is raw FFI matching the existing `tls_schannel` / `onvif_discovery::windows_ffi` / `service::win` style.
- `rustfmt.toml` (`max_width = 10000`) is the sole formatting authority. Do not hand-wrap. One paragraph per line in all prose and comments.
- Comments explain *why*, never restate *what*. No `TODO`/`FIXME`/`HACK` inline — this plan replaces `DEBT.md`, so there is no longer a ledger to point such markers at. If work is deferred, it does not get done; do not leave markers.
- Windows-only code is `#[cfg(windows)]` with a non-Windows stub returning `EXIT_WINDOWS_ONLY` / an error, so the Linux build host and `cargo test` stay green. Cross-platform helpers stay top-level so their tests run in CI.
- Every step must leave `cargo fmt --check`, `cargo clippy -- -D warnings`, and `cargo test` green on the host (`x86_64-unknown-linux-gnu`), and `cargo build --target x86_64-pc-windows-gnu` green for the cross-compile.

## Verification commands (run after every step)

```
cargo fmt
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --target x86_64-pc-windows-gnu
```

If a step cannot make a command pass (e.g. a Windows-only FFI path that cannot run on Linux), the step file says so explicitly and the stub is the verified surface.
