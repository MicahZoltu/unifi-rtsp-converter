# 08 — Delete `DEBT.md`, finalize

## Goal

Remove `DEBT.md` (the ledger is fully resolved by steps 01–06 and this step's deletions), confirm the codebase is clean and production-ready, and record the completion in `AGENTS.md`.

## Context

`DEBT.md`'s contract was "a line present here means the debt is still open; resolved items are deleted." With steps 01–07 done, every line is either implemented (3-serial, 5, 6, 7, 8) or deliberately dropped as no-longer-relevant (1, 2, 4, firmware-half of 3). The ledger has no remaining purpose and is deleted wholesale, exactly as `plan/` was deleted once its contents were completed. Steps 01–06 already removed all `DEBT.md` references from the code they touched; step 07 swept the rest. This step is the final gate.

## Scope

In: delete `DEBT.md`; final whole-repo verification; `AGENTS.md` History update.

Out: any code change. If verification fails, fix the offending step's work (do not paper over it here).

## Pure deletions absorbed here (no dedicated step file)

These DEBT items needed no code and are resolved by deleting the file:

- **DEBT 1** (step-00 winpthread static-link flag): the host MinGW is win32 thread-model, the flag is correctly absent, the exe is self-contained. No code change; the recorded build-environment fact is no longer needed in a ledger.
- **DEBT 2** (step-17 TLS schannel write/read hardening): speculative hardening for a failure mode no production trace surfaced; the never-crash guarantee for the Linux-testable path is covered by the FLV resync work. Ship the simpler code.
- **DEBT 4** (step-24 fdPHost coexistence): a Windows deployment-environment caveat, not code debt; the `SO_REUSEADDR` wildcard bind already coexists with `fdPHost`, and the "stop `fdPHost` if a host swallows Probes" fallback is operational guidance that belongs in `--install`'s printed message (or nowhere), not a code ledger.
- **DEBT 3 firmware half**: firmware stays as an overridable config default (step 04 added the `firmware` ini key); learning the real firmware needs a future AVClient capture that is out of scope. The serial half was implemented in step 04.

## Approach

1. Delete `DEBT.md`.
2. Run the full verification suite (below). If any check fails, stop and fix the responsible step — do not commit a red build.
3. Audit for stragglers: Grep the whole repo for `DEBT\.md`, `plan/`, `step \d`, `LocalSystem` (should only appear in historical `AGENTS.md` context or be gone), `000000000000` (should be gone from `GetDeviceInformation` runtime path, retained only as the config fallback constant), `TODO`/`FIXME`/`HACK`/`placeholder` (should be zero).
4. Update `AGENTS.md` History: add a final entry noting that `DEBT.md` and the old `plan/` directory were both removed, that the eight ledger items were resolved (implemented or deliberately dropped, enumerated), that step-number citations in source were swept, and that the self-signed-cert auto-generation and least-privilege service account were added as production hardening. Keep it factual and one-paragraph-per-line.
5. Optionally refresh `PROJECT.md`'s "Configuration" / production-deployment notes to reflect `--install` auto-generating the cert and the service running as `NT SERVICE\flvproxy`. Only if the existing text is now inaccurate.

## Verification

```
cargo fmt
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --target x86_64-pc-windows-gnu
```

All must be green. Additionally confirm via `git status` that `DEBT.md` is staged for deletion and no unintended files are touched.

## Files

- `DEBT.md` — deleted.
- `AGENTS.md` — History entry.
- `PROJECT.md` — optional accuracy refresh.

## Acceptance

- `DEBT.md` no longer exists.
- All verification commands green on host and cross-compile.
- No `DEBT.md`/`plan/`/`TODO`/`FIXME`/`placeholder` references remain in `src/` or the `.md` files (historical `AGENTS.md` History mentions excepted).
- `AGENTS.md` History reflects the production-readiness completion.
- The project is production-ready: an operator runs `flvproxy --install` on Windows, the cert is generated, the service starts as a least-privilege virtual account, ONVIF advertises the real camera serial, WS-Discovery egress is pinned, strict NVRs do not fault on the three stubbed ops, and a mid-stream FLV desync recovers instead of dropping the connection.
