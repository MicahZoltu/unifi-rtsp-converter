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
