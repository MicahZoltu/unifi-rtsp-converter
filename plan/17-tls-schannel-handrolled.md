# Step 17 — Hand-Rolled SChannel TLS Module + Self-Test

**Depends on:** Step 16 (recon capture confirmed the 7442 TLS+WS shape and
validated SChannel TLS against the real camera; the throwaway `schannel` crate
used there is replaced here).
**Type:** 🛑 MANUAL — Windows-only FFI module validated by a camera re-capture
**and** a localhost .NET `SslStream` self-test. Cannot run in Linux `cargo
test` (the module is `#[cfg(windows)]`); the rest of the codebase stays
Linux-testable.

## Goal

Replace the throwaway `schannel` crate (added in step 16 for the recon tool)
with a hand-rolled, zero-crates, `#[cfg(windows)]` SChannel SSPI FFI module —
`src/tls_schannel.rs` — that becomes the production TLS foundation for steps
18–21 (WS framing, AVClient 7442, uPFLV 7550, real-camera wiring). This
resolves the `PROJECT.md` zero-crates policy violation that step 16's
`schannel` dependency introduced.

The module implements only the bare-minimum server-side stream-mode SChannel
surface this one camera exercises: accept a TLS connection from a
self-signed-PFX-bearing server, then `EncryptMessage`/`DecryptMessage`
bidirectional byte streams. No client-cert authentication, no chain
validation, no client side — we implement *enough*, not all of Win32.

## Background — why hand-rolled, not `schannel`

`PROJECT.md` line 7 ("Zero external dependencies... No crates from crates.io")
and line 120 ("Do NOT use the `windows-sys` crate") forbid both `schannel` and
its transitive `windows-sys`/`windows-link` deps. The `schannel` crate is also
at `0.1.x` (not a stabilized API) and pulls in a broad `windows-sys` feature
set (cryptography, authentication, credentials, memory, system information) —
harder to audit than a minimal FFI block that declares only the ~12 SSPI
functions and ~8 structs we actually call. Hand-rolling also means we vendor
no crypto source: SChannel is the OS crypto Windows already ships; we only
declare the FFI to call it.

## Tasks — `src/tls_schannel.rs` (new module, `#[cfg(windows)]`)

1. **Raw FFI declarations.** `extern "system"` blocks linked against
   `crypt32.dll` and `secur32.dll` (`#[link(name = "crypt32")]` /
   `#[link(name = "secur32")]`). Hand-define only the structs/constants needed:
   `SCHANNEL_CRED` (+ `SCHANNEL_CRED_VERSION`, `SCH_USE_STRONG_CRYPTO`,
   `SCH_CRED_NO_DEFAULT_CREDS`), `SecBufferDesc`/`SecBuffer` (+ buffer types
   `SECBUFFER_VERSION`, `SECBUFFER_DATA`, `SECBUFFER_TOKEN`, `SECBUFFER_EXTRA`,
   `SECBUFFER_STREAM`, `SECBUFFER_EMPTY`), `SecHandle`, `TimeStamp`,
   `CRYPT_INTEGER_BLOB`, opaque `CERT_CONTEXT` (pointer), `SecPkgContext_StreamSizesW`,
   return codes (`SEC_I_CONTINUE_NEEDED`, `SEC_E_INCOMPLETE_MESSAGE`,
   `SEC_I_CONTEXT_EXPIRED`, `SEC_E_OK`), `ASC_REQ_*`/`SCH_*` flags,
   `UNISP_NAME`. Module-local `#![allow(non_snake_case, non_camel_case_types,
   non_upper_case_globals)]` for the Win32 naming (conventional for raw FFI;
   documented in-module).
2. **Minimal SSPI/crypt32 surface (server stream mode only):**
   - `crypt32`: `PFXImportCertStore`, `CertEnumCertificatesInStore`,
     `CertFreeCertificateContext`, `CertCloseStore`.
   - SSPI: `AcquireCredentialsHandleA` (inbound), `FreeCredentialsHandle`,
     `AcceptSecurityContext`, `DeleteSecurityContext`, `ApplyControlToken`,
     `EncryptMessage`, `DecryptMessage`, `FreeContextBuffer`,
     `QueryContextAttributesW` (for `SECPKG_ATTR_STREAM_SIZES`).
3. **`TlsAcceptor`** — built once from a PFX; `Clone` (Arc-wrapped cred handle)
   so listener threads share it.
   - `TlsAcceptor::from_pfx(pfx: &[u8], password: Option<&str>) -> io::Result<TlsAcceptor>`:
     `PFXImportCertStore` → `CertEnumCertificatesInStore` (first cert) →
     `AcquireCredentialsHandleA` with `SCHANNEL_CRED` (inbound).
   - `TlsAcceptor::accept<S: Read + Write>(&self, stream: S) -> io::Result<TlsStream<S>>`:
     drives `AcceptSecurityContext` to completion, handling
     `SEC_I_CONTINUE_NEEDED` (loop, feed token back) and
     `SEC_E_INCOMPLETE_MESSAGE` (partial TLS record — read more bytes).
4. **`TlsStream<S: Read + Write>: Read + Write`** — stream-mode TLS over an
   arbitrary byte stream.
   - `Read`: `DecryptMessage` with `SECBUFFER_STREAM` input; surface
     `SECBUFFER_DATA` to the caller; carry `SECBUFFER_EXTRA` into the next
     call (handles records spanning reads and multiple records per read).
   - `Write`: buffer to `SecPkgContext_StreamSizes` sizes, `EncryptMessage`,
     write the whole encrypted record.
   - `TlsStream::shutdown()`: `ApplyControlToken(SCHANNEL_SHUTDOWN)` + a final
     `AcceptSecurityContext` to send close_notify.
5. **Wire into the recon tool.** Refactor `src/protect_recon_impl.rs` off
   `schannel::*` onto `flvproxy::tls_schannel`; the raw-tap / WS-upgrade /
   frame-capture logic is untouched. Declare `pub mod tls_schannel;` in
   `lib.rs` under `#[cfg(windows)]`.
6. **Self-test mode.** Add a `--selftest` flag to `protect_recon` that runs
   `TlsAcceptor` on `127.0.0.1:0` and echoes decrypted bytes back via
   `EncryptMessage`. Stresses the encrypt/decrypt buffer state machine and
   clean shutdown without needing the camera.
7. **Throwaway self-test client script** `tools/tls_selftest.ps1`: uses .NET
   `TcpClient` + `SslStream` (validate callback ignores the self-signed cert)
   to connect to the `--selftest` listener and round-trip buffers at
   **1 B**, **64 KiB**, and **1 MiB** — exercising small-frame, typical-frame,
   and multi-record large-frame encrypt/decrypt paths plus clean shutdown.

## Validation — 🛑 MANUAL (two checks, both must pass)

### Check 1: localhost self-test (no camera)

1. Build: `cargo build --release --target x86_64-pc-windows-gnu --bin protect_recon`.
2. On the proxy host: `protect_recon.exe --selftest --password recon` (loads
   the same `protect_recon_cert.pfx` from step 16; prints the bound
   `127.0.0.1:<port>`).
3. From a PowerShell prompt: `./tools/tls_selftest.ps1 -Port <port>` (or the
   script auto-reads the printed port).
4. **Pass:** all three round-trips (1 B / 64 KiB / 1 MiB) echo back
   byte-identical; the listener log shows a clean `EncryptMessage`/
   `DecryptMessage` cycle and a clean `shutdown` (close_notify) with no
   `SEC_E_INCOMPLETE_MESSAGE`-style stalls or panics.

### Check 2: camera re-capture (real hardware)

1. Re-run `protect_recon.exe --password recon --enable-7550` (now using the
   hand-rolled `tls_schannel`, not `schannel`).
2. Re-enter the proxy IP in the camera's "UniFi Protect Server" box.
3. **Pass:** the log shows `TLS handshake ok` → `WS upgrade ok` → the same
   `timeSync` JSON frame (frame 1, opcode `0x2`) and `ping-0` frame (frame 2,
   opcode `0x9`) that the step-16 `schannel`-based capture produced — proving
   the hand-rolled module is behaviorally equivalent to `schannel` against the
   real camera.

### Final action on green

Delete the throwaway `schannel` dependency: remove the
`[target.'cfg(windows)'.dependencies]` block from `Cargo.toml`; regenerate
`Cargo.lock` (back to just `flvproxy`); confirm
`cargo build --target x86_64-pc-windows-gnu` is fully zero-crates. This closes
the `DEBT.md` policy-violation entry opened in step 16.

## Quality Gate (Standard, scoped to touched modules)

- `cargo build` / `cargo test` / `cargo clippy --lib --tests --bins -- -D
  warnings` clean on Linux (the `tls_schannel` module is `#[cfg(windows)]`;
  Linux is unaffected and stays zero-crates).
- `cargo build --target x86_64-pc-windows-gnu --bin protect_recon` clean, zero
  warnings.
- `cargo clippy --target x86_64-pc-windows-gnu --bin protect_recon -- -D
  warnings` clean (the raw-FFI block will need the module-local Win32-naming
  `allow`s; that is standard and documented).
- No `unwrap`/`expect`/`panic!` in the FFI module — every SSPI return code is
  matched and mapped to an `io::Error`; partial-record states are handled, not
  asserted away.
- After the final-action deletion: `Cargo.lock` contains only `flvproxy`; the
  Windows target is zero-crates, matching Linux.
- No `schannel`/`windows-sys`/`windows-link` references remain anywhere in the
  tree except the historical `plan/16` "throwaway stopgap" note and the
  `DEBT.md` resolution record.

## Debt notes

- The `--selftest` driver in `protect_recon` and `tools/tls_selftest.ps1` are
  throwaway validation scaffolding. `TRIGGER: step 21 (real-camera wiring)
  human test confirms the production path → delete the recon tool +
  `--selftest` mode + the `.ps1` script; the `tls_schannel` module itself stays
  as production.`
- The hand-rolled TLS is validated against exactly one camera (fw 4.73.112) and
  one .NET `SslStream` client. Edge cases (very large frames, rapid
  reconnects, partial records at unusual boundaries) are covered by the
  self-test's 1 B / 64 KiB / 1 MiB round-trips but not exhaustively. Log
  `TRIGGER: step 26 (error-handling-and-resync) hardens the TLS read/write
  loops against the never-crash guarantees, exercising malformed-record and
  peer-reset paths.`

## Do not

- Do not implement the WebSocket framing layer here — that is step 18. This
  step delivers only the TLS byte-stream (`Read + Write`).
- Do not implement client-side TLS — the proxy only ever *accepts* inbound TLS
  from the camera (7442/7550); it never dials out over TLS.
- Do not implement client-certificate authentication or chain validation — the
  camera does not present a client cert, and the server cert is self-signed.
  Keep the surface minimal.
- Do not add `schannel`/`windows-sys`/`windows-link` back under any
  circumstance — that is the policy violation this step exists to fix.
- Do not delete the recon tool or the self-test scaffolding yet — they are
  removed at step 21 once the production path is confirmed.
