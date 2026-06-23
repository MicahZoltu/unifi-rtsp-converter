# 05 — Self-signed PFX auto-generation

## Goal

Generate a fresh self-signed PFX automatically so an operator never has to run `openssl` by hand before the proxy starts. Generation fires in two places: proactively during `--install` (so the first `sc start` always finds a cert), and lazily during bootstrap if the configured PFX is absent and the exe directory is writable (a `--console` convenience). Each generation produces a unique random keypair; the camera does not validate the server cert, so rotation is free and no CA coordination is needed.

## Context

Today `App::bootstrap` (`app.rs:121-139`) hard-fails if the configured PFX is missing, telling the operator to run openssl — a real deployment blocker for a Windows service. The cert is the server-side TLS identity presented to the *camera* on port 7442 (`protect_listener` + `tls_schannel`), not an HTTPS cert for NVR clients; SChannel is configured for no chain validation (`tls_schannel.rs:3`), so any self-signed cert works. The project already FFI's SChannel/CryptoAPI from `crypt32`/`secur32`/`ws2_32`; CryptoAPI cert self-signing lives in the same DLL family. Zero crates.

## Scope

In: a new Windows-only `cert_gen` module that, given an output path, generates a self-signed RSA cert + key in a transient in-memory store and exports it as a no-password PFX to that path; wiring into `service::install` (proactive) and into `App::bootstrap` (lazy fallback when the PFX is missing and the dir is writable); a Linux stub returning a clear "Windows-only" error.

Out: changing `TlsAcceptor::from_pfx` or `tls_schannel` load path (the generated PFX is consumed identically to a hand-made one); supporting password-protected generated PFXs (generated PFXs use an empty password to keep the `cert_password = None` default path); client-cert or CA-chain work; any change to `cert_path`/`cert_password` config semantics (operator-supplied cert still wins).

## Approach

1. Create `src/cert_gen.rs`. Module doc explains: generates a self-signed cert valid for the machine's hostname/`server_ip` CN, 2048-bit RSA (CryptoAPI's `CRYPT_EXPORTABLE` key), SHA-256 signature, ~10-year validity, exported as PKCS#12 (PFX) with no password via `PFXExportCertStoreEx`. Zero crates.
2. FFI declarations (mirror `service::win` / `tls_schannel` style, `#[link(name="crypt32")]` and `#[link(name="advapi32")]` as needed): `CertOpenStore` (memory store), `CertCreateSelfSignCertificate` (with a `CRYPT_KEY_PROV_INFO` naming an in-memory RSA CSP container and `AT_KEYEXCHANGE`), `CertSetCertificateContextProperty` for `CERT_KEY_PROV_HANDLE_PROP_ID` so the key travels with the cert, `PFXExportCertStoreEx` (with an empty password, flags `REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY | EXPORT_PRIVATE_KEYS`), `CertCloseStore`, `CryptReleaseContext`. Define the needed `#[repr(C)]` structs (`CRYPT_KEY_PROV_INFO`, `CRYPT_DATA_BLOB`, a `SYSTEMTIME`-based validity or use `NotBefore`/`NotAfter` via `CertCreateSelfSignCertificate`'s `pStartTime`/`pEndTime`).
3. Public entry: `pub fn generate_self_signed_pfx(out_path: &Path) -> io::Result<()>`. Steps: open a memory cert store; create a self-signed cert with a CN built from the hostname (fall back to `"flvproxy"`); ensure the private key is exportable; export the store to a PFX blob; write the blob bytes to `out_path`; close the store. Return the io::Error from the first failing FFI call (use `io::Error::from_raw_os_error` after mapping via the last Win32 error; CryptoAPI does not use `WSAGetLastError` — use `GetLastError`/`std::io::Error::last_os_error`). Clean up handles on every error path.
4. Non-Windows: `#[cfg(not(windows))] pub fn generate_self_signed_pfx(_out_path: &Path) -> io::Result<()> { Err(io::Error::new(InvalidInput, "self-signed cert generation is only available on Windows")) }` so the module compiles and is unit-testable for its signature on Linux.
5. `service::install` (`service.rs`, Windows `win::install`): after `CreateServiceW` succeeds (or just before, once the bin path is known — either order works; doing it before lets a cert-load failure abort the install cleanly), resolve the default cert path (`<exe_dir>/flvproxy_cert.pfx`), and if it does not already exist, call `cert_gen::generate_self_signed_pfx(&path)`. Log/println the result. If generation fails, print a clear message pointing to manual openssl but still return success (the operator can supply `cert_path`); do not abort the install over cert generation.
6. `App::bootstrap` (`app.rs:121-139`): in the `CertRead` error branch, before returning the error, attempt `cert_gen::generate_self_signed_pfx(&cert_path)` when the error is `NotFound`-kind and the parent dir is writable. On success, re-read the PFX and continue; on failure, fall through to the existing `CertRead` error. Keep this Windows-only (`#[cfg(windows)]`); on Linux the 7442 path is absent entirely so no cert is loaded. Update the `BootstrapError::CertRead` Display message to mention `--install` as the fix (it now generates the cert).
7. Update `tls_schannel.rs:310`: remove the dangling sentence "The leftover `protect-recon` self-signed key is a `DEBT.md`-tracked cleanup item (see `DEBT.md` step 17)." — no leftover key exists in the tree (verified), and DEBT.md is being deleted. Leave the rest of the `PFXImportCertStore` flags=0 explanation intact; it remains accurate.
8. Update the example ini comment for `cert_path` to note that `--install` auto-generates the PFX if absent, so the openssl instruction is now optional.

## Test

- Linux host: assert the non-Windows stub returns the "Windows-only" error. Assert the function signature compiles. The FFI path is verified by cross-compile + a manual Windows smoke test (run `--install`, confirm `flvproxy_cert.pfx` appears beside the exe and `--console` loads it).
- If a pure-logic helper is factored out (e.g. building the CN string, or the validity timestamps), unit-test it on Linux.

## Files

- `src/cert_gen.rs` — new module, Windows FFI + Linux stub.
- `src/lib.rs` (or wherever modules are declared) — `pub mod cert_gen;`.
- `src/service.rs` — `win::install` proactive generation.
- `src/app.rs` — `bootstrap` lazy fallback; `BootstrapError::CertRead` message.
- `src/tls_schannel.rs` — remove the dangling DEBT.md sentence at line 310.
- `flvproxy.ini.example` — update the cert comment.

## Acceptance

- On Windows, `flvproxy --install` creates `flvproxy_cert.pfx` beside the exe if absent; `flvproxy --console` then starts and loads it without operator action.
- `flvproxy --console` with no PFX and no `--install` first still starts (lazy generation), provided the exe dir is writable.
- A pre-existing `cert_path` PFX is never overwritten.
- Linux host builds, clippy clean, tests pass; `cargo build --target x86_64-pc-windows-gnu` compiles the FFI.
- `tls_schannel.rs:310` no longer references DEBT.md.

## Notes

- Generated PFX uses an empty password to match the `cert_password = None` default; an operator who wants a password-protected cert supplies their own via `cert_path`.
- CryptoAPI's `CertCreateSelfSignCertificate` persists the key to a CSP container by default (same behaviour `tls_schannel.rs:310` documents for `PFXImportCertStore(flags=0)`); exporting to PFX and re-importing via the existing load path keeps the runtime behaviour identical to a hand-made cert.
- Security: the generated private key is written beside the exe. On a user-owned directory (the assumed deployment) that is acceptable; the file should be created with restrictive ACLs if practical, but do not over-engineer — CryptoAPI does not expose a simple ACL-on-file-write path, and the camera-cert key is low-value (camera doesn't validate it). Note this in the module doc.
