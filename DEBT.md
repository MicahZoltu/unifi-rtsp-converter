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
  milestone (`07`, `13`, `25`, `28`).
- `TRIGGER:` items name the exact future event that forces revisiting them.
- At each review, reconcile: every item is either resolved (delete the line)
  or re-justified with a fresh trigger. No item lives forever unchallenged.
- If this file is empty, that is the goal state — say so explicitly in each
  review ("DEBT.md empty: confirmed").
- **Resolved items are deleted** (history lives in git), not annotated as
  "RESOLVED" and retained. A line present here means the debt is still open;
  "resolution records" are an anti-pattern that hides whether the ledger
  reflects real pending work.

## Active items

step 00 | .cargo/config.toml:rustflags | Dropped `-static-libwinpthread` from the Windows GNU static-link rustflags: this build host's MinGW-w64 GCC 14 uses the win32 thread model, which rejects that flag (it is a posix-thread-model flag) and does not link winpthread at all, so the two remaining flags already yield a self-contained exe (verified via objdump). | TRIGGER: build host switches to a posix-thread-model MinGW (`x86_64-w64-mingw32-gcc -v` reports `--enable-default-msvcrt`/posix threads), at which point re-add static winpthread linking to keep the exe free of `libwinpthread-1.dll`.
step 03 | src/flv_parser.rs:OversizedTag path | On `OversizedTag` the framer clears its buffer and resets to the `PrevTagSize` state, dropping any bytes after the bad tag header. This is not a real resync scan; it merely stops the multi-MiB allocation and hands control back to the caller. | TRIGGER: step 26 (error-handling-and-resync) implements the resync scan — at that point replace the buffer-clear with byte-retention so the scanner can locate the next valid tag boundary.
step 17 | src/tls_schannel.rs:edge cases + write/read hardening | The hand-rolled TLS is validated against exactly one camera (fw 4.73.112) and one .NET `SslStream` client. Edge cases (very large frames, rapid reconnects, partial records at unusual boundaries) are covered by the self-test's 1 B / 64 KiB / 1 MiB round-trips but not exhaustively. Two simplifications remain: (a) `TlsStream::write` sends each encrypted record with a single `stream.write_all` and propagates `WouldBlock`/`TimedOut` as a fatal connection error (the record may be half-sent) rather than buffering+resending like the `schannel` crate — acceptable because the recon/self-test sockets set no write timeout, but production (steps 18–21) may need resumable writes; (b) the streaming `Read` path propagates `WouldBlock`/`TimedOut` from the underlying socket (no internal retry/deadline) so the caller controls cadence, which is correct but means a malformed-record / peer-reset path is not yet hardened. | TRIGGER: step 26 (error-handling-and-resync) hardens the TLS read/write loops against the never-crash guarantees, exercising malformed-record and peer-reset paths and adding resumable write buffering if the production path needs it.
step 18 | src/ws.rs:hand-rolled SHA-1 for WebSocket handshake | RFC 6455 §1.3 requires `Sec-WebSocket-Accept = base64(SHA1(key + GUID))`. Per the project's zero-crates constraint, SHA-1 (FIPS 180-4 / RFC 3174) is implemented by hand in the private `ws::sha1` rather than pulling a crypto crate, and reused only via the public `ws::accept_key`. The implementation is isolated and documented as WS-handshake-only (not a general crypto primitive) so it is not reused for any security-sensitive path — production crypto goes through Windows SChannel (step 17). The alternative (`CryptCreateHash` via SChannel) is Windows-only and would break the Linux-testable invariant, so hand-roll is the deliberate choice. | TRIGGER: step 25 (ONVIF cluster review) re-evaluates the hand-rolled SHA-1 — if a reviewer prefers the SChannel hash path on Windows, `accept_key` gains a `#[cfg(windows)]` SChannel-backed variant while the Linux test path keeps the hand-rolled one.
step 18 | src/ws.rs:decoder mask policy is lenient | RFC 6455 §5.1 mandates that client→server frames be masked and that a server MUST fail the connection on an unmasked client frame. `ws::parse_frame` instead unmasks iff the mask bit is set and accepts unmasked frames otherwise. Strict rejection would break the loopback round-trip tests (the server encoder's own unmasked output is read back) and buys nothing on the production path, where the camera always masks; the server encoder (§5.3) never masks. | TRIGGER: step 25 (ONVIF cluster review) decides whether to add a strict-masked-only mode for the production read path (gated behind a parameter so tests keep the lenient path).
step 23 | src/onvif_discovery.rs:random_device_addr RNG | `random_device_addr` generates the `urn:uuid:...` endpoint address using a hand-rolled SplitMix32-style PRNG seeded from `SystemTime` nanos mixed with a stack address, rather than a cryptographically secure RNG. WS-Discovery endpoint addresses only need uniqueness within a subnet (collision resistance, not secrecy), so a non-CSPRNG is correct here; a `getrandom`/`BCryptGenRandom` path would either pull a crate (forbidden) or be Windows-only (breaking the Linux test invariant). The seed mixing is best-effort: two proxies started in the same nanosecond on the same host could collide, which is acceptable for the single-proxy-per-host deployment model. | TRIGGER: step 25 (ONVIF cluster review) re-evaluates whether to route through the SChannel SSPI `CryptGenRandom` on Windows (already linked for step 17 TLS) for a CSPRNG-backed v4 UUID while keeping the hand-rolled path for the Linux test build.
