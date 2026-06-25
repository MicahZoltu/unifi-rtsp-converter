//! Self-signed PFX auto-generation. Generates a fresh self-signed RSA cert + key via raw CryptoAPI FFI and exports it as a no-password PKCS#12 (PFX) so an operator never has to run `openssl` by hand before the proxy starts. Generation fires in two places: proactively during `--install` (`service::win::install`) so the first `sc.exe start` always finds a cert, and lazily during `App::bootstrap` if the configured PFX is absent and the exe directory is writable (a console-mode convenience). Each generation produces a unique random keypair; the camera does not validate the server cert (SChannel is configured for no chain validation in `tls_schannel`), so rotation is free and no CA coordination is needed.
//!
//! The Windows implementation uses only the legacy CSP surface (`CryptAcquireContext`/`CryptGenKey`/`CertCreateSelfSignCertificate`/`PFXExportCertStoreEx`) — the same `crypt32`/`advapi32` DLL family the rest of the project already FFI's (`tls_schannel`, `service::win`). No `windows-sys`/`windows` crates. The non-Windows stub returns a clear "Windows-only" error so the module compiles and its signature is unit-testable on the Linux build host.
//!
//! The cert is the server-side TLS identity presented to the *camera* on port 7442, not an HTTPS cert for NVR clients; the generated private key is written beside the exe with no restrictive ACL (CryptoAPI does not expose a simple ACL-on-file-write path, and the camera-cert key is low-value because the camera does not validate it). The generated PFX uses an empty password to match the `cert_password = None` default; an operator who wants a password-protected cert supplies their own via `cert_path`.
//!
//! Implementation note: each generation creates a uniquely-named CryptoAPI key container in the user's CSP profile (transient RSA key material). The container is not deleted after export (CryptoAPI's `CRYPT_DELETEKEYSET` delete is best-effort and awkward to interleave with the still-open provider handle); because the container name embeds a nanosecond timestamp it never collides, and generation is a rare event (once per `--install`, or once on the first console-mode run after the PFX is removed), so the accumulation is negligible. The exported PFX is self-contained and does not depend on the container after export.

use std::io;
use std::path::Path;

/// Builds the `CN=<hostname>` X.500 subject string for the self-signed cert. Cross-platform so it is unit-testable on Linux; the Windows path reads `COMPUTERNAME` (falling back to `flvproxy`) and passes the result here. A bare `CN=` is sufficient because the camera does not validate the server cert — the subject only needs to parse into a valid certificate.
#[cfg(any(windows, test))]
fn subject_cn(hostname: &str) -> String {
    format!("CN={hostname}")
}

/// Generates a self-signed RSA cert (2048-bit, SHA-256, ~10-year validity, CN from the machine hostname) and writes it as a no-password PFX to `out_path`. A pre-existing file at `out_path` is **not** checked here — callers (`service::install`, `App::bootstrap`) guard existence so an operator-supplied cert is never overwritten. On non-Windows the operation does not exist (CryptoAPI is Windows-only), so a clear "Windows-only" error is returned without touching FFI.
pub fn generate_self_signed_pfx(out_path: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        win::generate_self_signed_pfx(out_path)
    }
    #[cfg(not(windows))]
    {
        let _ = out_path;
        Err(io::Error::new(io::ErrorKind::InvalidInput, "self-signed cert generation is only available on Windows"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subject_cn_wraps_hostname() {
        assert_eq!(subject_cn("cam1"), "CN=cam1");
        assert_eq!(subject_cn(""), "CN=");
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_stub_returns_windows_only_error() {
        let err = generate_self_signed_pfx(Path::new("/nonexistent/cert.pfx")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("Windows"), "stub message must explain it is Windows-only: {err}");
    }
}

#[cfg(windows)]
mod win {
    #![allow(non_snake_case, non_camel_case_types, non_upper_case_globals, clippy::upper_case_acronyms)]

    use std::ffi::c_void;
    use std::io;
    use std::path::Path;
    use std::ptr::{null, null_mut};

    use super::subject_cn;
    use crate::wide::to_wide;

    /// `X509_ASN_ENCODING` — the certificate-encoding type for `CertStrToNameW`/`CertCreateSelfSignCertificate`. wincrypt.h.
    const X509_ASN_ENCODING: u32 = 0x0000_0001;

    /// `CERT_X500_NAME_STR` — string-type flag for `CertStrToNameW` so an input like `CN=host` is parsed as an X.500 distinguished name. wincrypt.h.
    const CERT_X500_NAME_STR: u32 = 0x1000_0000;

    /// `CERT_STORE_PROV_MEMORY` — `CertOpenStore` provider selector for an in-memory store. wincrypt.h defines it as `((LPCSTR)2)`, so the "provider string" is the integer 2 cast to a pointer.
    const CERT_STORE_PROV_MEMORY: usize = 2;

    /// `CERT_STORE_ADD_REPLACE` — disposition for `CertAddCertificateContextToStore`: replace an existing cert with the same subject+issuer. wincrypt.h.
    const CERT_STORE_ADD_REPLACE: u32 = 3;

    /// `PROV_RSA_AES` — CryptoAPI provider type for the RSA AES provider, which supports the SHA-2 family (SHA-256/384/512) for signing. Used instead of `PROV_RSA_FULL` (type 1) because that legacy CSP only supports SHA-1/MD5 signatures and rejects `szOID_RSA_SHA256RSA` from `CertCreateSelfSignCertificate` with `ERROR_INVALID_PARAMETER` (87) — observed during Windows runtime testing. RSA key generation (`CryptGenKey` with `AT_KEYEXCHANGE`) and PFX export work identically under this provider. wincrypt.h.
    const PROV_RSA_AES: u32 = 24;

    /// `AT_KEYEXCHANGE` — key-spec selector for the key-exchange (encryption) key pair. Used so the self-signed cert is signed by and its private key is the exchange key, which `PFXExportCertStoreEx` exports. wincrypt.h.
    const AT_KEYEXCHANGE: u32 = 1;

    /// `CRYPT_NEWKEYSET` — `CryptAcquireContext` flag to create a new key container (with a fresh default keypair) if one does not exist. wincrypt.h.
    const CRYPT_NEWKEYSET: u32 = 0x0000_0008;

    /// `CRYPT_EXPORTABLE` — `CryptGenKey` flag marking the generated key as exportable, which is required for `PFXExportCertStoreEx` to write the private key into the PFX. wincrypt.h.
    const CRYPT_EXPORTABLE: u32 = 0x0000_0001;

    /// `EXPORT_PRIVATE_KEYS` — `PFXExportCertStoreEx` flag requesting the private key be included in the export. wincrypt.h value `0x00000004` (NOT `0x0001`, which is the import-side `PKCS12_NO_PERSIST_KEY` and is invalid on the export path, producing `ERROR_INVALID_PARAMETER` 87 — the bug that blocked the Windows runtime test until the correct value was set).
    const EXPORT_PRIVATE_KEYS: u32 = 0x0004;

    /// `REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY` — `PFXExportCertStoreEx` flag making the call fail (rather than silently emit a cert-only PFX) if a private key is present but non-exportable. wincrypt.h value `0x0002` (an earlier version of this constant used `0x4000`, which is not a valid PFX flag and caused every export to fail with `ERROR_INVALID_PARAMETER` 87 — one of the root causes that blocked the Windows runtime test).
    const REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY: u32 = 0x0002;

    /// `REPORT_NO_PRIVATE_KEY` — `PFXExportCertStoreEx` flag making the call fail (rather than silently emit a cert-only PFX) if a certificate has **no** associated private key. Without this flag, a cert with no key association produces a cert-only PFX that SChannel later rejects with `SEC_E_NO_CREDENTIALS` (0x8009030E) — the exact failure that Windows runtime testing surfaced after the export itself succeeded. Setting it makes the export fail loudly at generation time instead. wincrypt.h value `0x0001`.
    const REPORT_NO_PRIVATE_KEY: u32 = 0x0001;

    /// `CERT_KEY_CONTEXT_PROP_ID` (value 5) — cert property whose data is a `CERT_KEY_CONTEXT` (`cbSize` + `HCRYPTPROV` + `dwKeySpec`), the property `PFXExportCertStoreEx` consults to find the private key to serialize. The bare `CERT_KEY_PROV_HANDLE_PROP_ID` (value 1) is honored by `AcquireCredentialsHandle` but **not** by `PFXExportCertStoreEx`, which is why the first generated PFX was cert-only (914 bytes) and the service failed with `SEC_E_NO_CREDENTIALS` on `sc.exe start`. wincrypt.h.
    const CERT_KEY_CONTEXT_PROP_ID: u32 = 5;

    /// `CERT_KEY_PROV_INFO_PROP_ID` (value 2) — cert property set by `CertCreateSelfSignCertificate` (from the `pKeyProvInfo` we pass) naming the key container, and re-set by `PFXImportCertStore` when it persists an imported key. The post-export verification checks for its presence on the re-imported cert as proof the PFX actually carried a private key. wincrypt.h.
    const CERT_KEY_PROV_INFO_PROP_ID: u32 = 2;

    /// `CERT_STORE_NO_CRYPT_RELEASE_FLAG` — passed to `CertSetCertificateContextProperty` for the key-handle/key-context properties so the cert context does **not** take ownership of (and release on free) the `HCRYPTPROV` we attach; `ProvGuard` owns and releases the provider handle itself at the end of `generate_self_signed_pfx`. wincrypt.h value `0x00000001`.
    const CERT_STORE_NO_CRYPT_RELEASE_FLAG: u32 = 0x0000_0001;

    /// Validity span of the generated cert. ~10 years matches the design spec; long enough that the cert does not expire within a deployment's lifetime, short enough to stay conservative. The camera does not validate the cert, so the exact span is not security-critical.
    const VALIDITY_YEARS: u16 = 10;

    /// RSA key length generated for the cert. 2048 bits is the current baseline for a server identity; the legacy CSP supports up to 16384 bits.
    const RSA_KEY_BITS: u32 = 2048;

    /// `szOID_RSA_SHA256RSA` — OID for the sha256WithRSAEncryption signature algorithm, so the cert is signed with SHA-256 rather than the legacy SHA-1 default. wincrypt.h (ANSI, NUL-terminated).
    const SZOID_RSA_SHA256RSA: &[u8] = b"1.2.840.113549.1.1.11\0";

    /// CryptoAPI provider/key handles are `ULONG_PTR` (pointer-sized unsigned). `usize` matches the `extern "system"` ABI on x86_64.
    type HCRYPTPROV = usize;

    /// `HCRYPTKEY` — CryptoAPI key handle. Pointer-sized unsigned.
    type HCRYPTKEY = usize;

    /// `HCERTSTORE` — opaque cert-store handle. Pointer.
    type HCERTSTORE = *mut c_void;

    /// `PCCERT_CONTEXT` — opaque pointer to a `CERT_CONTEXT`. Pointer.
    type PCCERT_CONTEXT = *const CERT_CONTEXT;

    /// Win32 `BOOL`.
    type Bool = i32;

    /// `CRYPT_DATA_BLOB` / `CRYPT_INTEGER_BLOB` (wincrypt.h) — length + pointer, used for the encoded subject name and the exported PFX bytes. Same layout as the `CRYPT_INTEGER_BLOB` in `tls_schannel`.
    #[repr(C)]
    struct CRYPT_DATA_BLOB {
        cbData: u32,
        pbData: *mut u8,
    }

    /// `CRYPT_ALGORITHM_IDENTIFIER` (wincrypt.h) — the signature algorithm passed to `CertCreateSelfSignCertificate`. `pszObjId` is an ANSI OID string; `Parameters` is left empty (RSA signature carries no DER-encoded parameters here).
    #[repr(C)]
    struct CRYPT_ALGORITHM_IDENTIFIER {
        pszObjId: *const u8,
        Parameters: CRYPT_DATA_BLOB,
    }

    /// `CRYPT_KEY_PROV_INFO` (wincrypt.h) — names the key container/provider the cert's private key lives in, so `PFXExportCertStoreEx` can re-acquire the key for export. `CertCreateSelfSignCertificate` stores this as the cert's `CERT_KEY_PROV_INFO_PROP_ID` property. `cProvParam = 0` / `rgProvParam = null` means no provider parameters.
    #[repr(C)]
    struct CRYPT_KEY_PROV_INFO {
        pwszContainerName: *const u16,
        pwszProvName: *const u16,
        dwProvType: u32,
        dwFlags: u32,
        cProvParam: u32,
        rgProvParam: *mut c_void,
        dwKeySpec: u32,
    }

    /// `CERT_KEY_CONTEXT` (wincrypt.h) — value of the `CERT_KEY_CONTEXT_PROP_ID` cert property: the provider handle plus the key spec (`AT_KEYEXCHANGE`/`AT_SIGNATURE`). The `u` field is a `union { HCRYPTPROV hCryptProv; NCRYPT_KEY_HANDLE hNCryptKey; }`; for a legacy CSP we use the `hCryptProv` arm and Rust represents the union as the `HCRYPTPROV` (it is pointer-sized and the `NCRYPT_KEY_HANDLE` arm is the same width). `cbSize` must be `sizeof(CERT_KEY_CONTEXT)` or `CertSetCertificateContextProperty` rejects it with `E_INVALIDARG`.
    #[repr(C)]
    struct CERT_KEY_CONTEXT {
        cbSize: u32,
        hCryptProv: HCRYPTPROV,
        dwKeySpec: u32,
    }

    /// `SYSTEMTIME` (winbase.h) — 8 `WORD` fields, 16 bytes. `CertCreateSelfSignCertificate` takes validity as `const SYSTEMTIME*`.
    #[repr(C)]
    #[derive(Copy, Clone, Default)]
    struct SYSTEMTIME {
        wYear: u16,
        wMonth: u16,
        wDayOfWeek: u16,
        wDay: u16,
        wHour: u16,
        wMinute: u16,
        wSecond: u16,
        wMilliseconds: u16,
    }

    /// Opaque `CERT_CONTEXT` (wincrypt.h). We only ever hold/pass pointers to it, so the body is left undefined.
    #[repr(C)]
    struct CERT_CONTEXT {
        _opaque: [u8; 0],
    }

    #[link(name = "advapi32")]
    extern "system" {
        /// `CryptAcquireContextW` (wincrypt.h) — acquire a CSP handle for a key container. With `CRYPT_NEWKEYSET` it creates the container (and a default keypair) if absent. Returns TRUE on success.
        fn CryptAcquireContextW(phProv: *mut HCRYPTPROV, szContainer: *const u16, szProvider: *const u16, dwProvType: u32, dwFlags: u32) -> Bool;
        /// `CryptGenKey` (wincrypt.h) — generate a new key of `Algid` with `dwFlags`-controlled size/attributes into `*phKey`. The top 16 bits of `dwFlags` carry the RSA key length in bits.
        fn CryptGenKey(hProv: HCRYPTPROV, Algid: u32, dwFlags: u32, phKey: *mut HCRYPTKEY) -> Bool;
        /// `CryptDestroyKey` (wincrypt.h) — release a key handle. The key material persists in its container; only the handle is freed.
        fn CryptDestroyKey(hKey: HCRYPTKEY) -> Bool;
        /// `CryptReleaseContext` (wincrypt.h) — release a CSP handle.
        fn CryptReleaseContext(hProv: HCRYPTPROV, dwFlags: u32) -> Bool;
    }

    #[link(name = "crypt32")]
    extern "system" {
        /// `CertStrToNameW` (wincrypt.h) — encode an X.500 name string (e.g. `CN=host`) into a `CERT_NAME_BLOB`. Two-call: first with `pbEncoded = NULL` to learn `*pcbEncoded`, then with a buffer of that size.
        fn CertStrToNameW(dwCertEncodingType: u32, pszX500: *const u16, dwStrType: u32, pvReserved: *mut c_void, pbEncoded: *mut u8, pcbEncoded: *mut u32, ppszError: *mut *const u16) -> Bool;
        /// `CertCreateSelfSignCertificate` (wincrypt.h) — build a self-signed cert from a provider handle, subject name, key-provider info, signature algorithm, and validity window. Returns a `PCCERT_CONTEXT` (caller frees via `CertFreeCertificateContext`) or NULL on failure.
        fn CertCreateSelfSignCertificate(hCryptProv: HCRYPTPROV, pSubjectIssuerBlob: *const CRYPT_DATA_BLOB, dwFlags: u32, pKeyProvInfo: *const CRYPT_KEY_PROV_INFO, pSignatureAlgorithm: *const CRYPT_ALGORITHM_IDENTIFIER, pStartTime: *const SYSTEMTIME, pEndTime: *const SYSTEMTIME, pExtensions: *const c_void) -> PCCERT_CONTEXT;
        /// `CertOpenStore` (wincrypt.h) — open a cert store. `CERT_STORE_PROV_MEMORY` (passed as `lpszStoreProvider = (LPCSTR)2`) opens an in-memory store.
        fn CertOpenStore(lpszStoreProvider: *const u8, dwEncodingType: u32, hCryptProv: HCRYPTPROV, dwFlags: u32, pvPara: *const c_void) -> HCERTSTORE;
        /// `CertAddCertificateContextToStore` (wincrypt.h) — add a cert context to a store with the given disposition.
        fn CertAddCertificateContextToStore(hCertStore: HCERTSTORE, pCertContext: PCCERT_CONTEXT, dwAddDisposition: u32, ppStoreContext: *mut PCCERT_CONTEXT) -> Bool;
        /// `CertSetCertificateContextProperty` (wincrypt.h) — attach a property to a cert context. Here `CERT_KEY_CONTEXT_PROP_ID` (`CERT_KEY_CONTEXT`) so `PFXExportCertStoreEx` can serialize the private key.
        fn CertSetCertificateContextProperty(pCertContext: PCCERT_CONTEXT, dwPropId: u32, dwFlags: u32, pvData: *const c_void) -> Bool;
        /// `CertGetCertificateContextProperty` (wincrypt.h) — query a property's presence/size. The post-export verification uses it on `CERT_KEY_PROV_INFO_PROP_ID` to prove the re-imported cert carries a private key.
        fn CertGetCertificateContextProperty(pCertContext: PCCERT_CONTEXT, dwPropId: u32, pvData: *mut c_void, pcbData: *mut u32) -> Bool;
        /// `CertFreeCertificateContext` (wincrypt.h) — release one reference to a cert context.
        fn CertFreeCertificateContext(pCertContext: PCCERT_CONTEXT) -> Bool;
        /// `CertCloseStore` (wincrypt.h) — close a cert store. Flag 0 leaves outstanding cert-context references valid.
        fn CertCloseStore(hCertStore: HCERTSTORE, dwFlags: u32) -> Bool;
        /// `CertEnumCertificatesInStore` (wincrypt.h) — enumerate certs in a store; NULL `pPrev` yields the first, the prior context yields the next (prior is auto-freed). Returns NULL at end. Used by the post-export verification to fetch the re-imported cert.
        fn CertEnumCertificatesInStore(hCertStore: HCERTSTORE, pPrev: PCCERT_CONTEXT) -> PCCERT_CONTEXT;
        /// `PFXExportCertStoreEx` (wincrypt.h) — export a store (with private keys) as a PKCS#12 blob. Two-call: first to learn `pszblob->cbData`, then with an allocated buffer. An empty wide string password produces an unencrypted PFX that `tls_schannel::from_pfx` re-imports with its NULL-password path (the export side rejects a NULL password with `ERROR_INVALID_PARAMETER` 87 on modern Windows, so the two halves use different but compatible no-password representations).
        fn PFXExportCertStoreEx(hStore: HCERTSTORE, pszblob: *mut CRYPT_DATA_BLOB, szPassword: *const u16, pvReserved: *mut c_void, dwFlags: u32) -> Bool;
        /// `PFXImportCertStore` (wincrypt.h) — load a PFX into a transient store. Used by the post-export verification with flags = 0 (persist key to CSP container) to mirror `tls_schannel::from_pfx` exactly; a cert-only PFX imports a cert with no `CERT_KEY_PROV_INFO_PROP_ID`, which the verification detects.
        fn PFXImportCertStore(pPFX: *mut CRYPT_DATA_BLOB, szPassword: *const u16, dwFlags: u32) -> HCERTSTORE;
    }

    #[link(name = "kernel32")]
    extern "system" {
        /// `GetLocalTime` (winbase.h) — fill `*lpSystemTime` with the current local date/time.
        fn GetLocalTime(lpSystemTime: *mut SYSTEMTIME);
    }

    /// RAII guard for a CSP provider handle — releases it on drop so an early `?` return never leaks it.
    struct ProvGuard(HCRYPTPROV);
    impl Drop for ProvGuard {
        fn drop(&mut self) {
            if self.0 != 0 {
                // SAFETY: `self.0` is a valid `HCRYPTPROV` obtained from `CryptAcquireContextW`; `CryptReleaseContext` is the documented release.
                unsafe {
                    let _ = CryptReleaseContext(self.0, 0);
                }
            }
        }
    }

    /// RAII guard for a cert context — frees it on drop so an early `?` return never leaks it.
    struct CertGuard(PCCERT_CONTEXT);
    impl Drop for CertGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: `self.0` is a valid `PCCERT_CONTEXT` from `CertCreateSelfSignCertificate`; `CertFreeCertificateContext` is the documented release.
                unsafe {
                    let _ = CertFreeCertificateContext(self.0);
                }
            }
        }
    }

    /// RAII guard for a cert store — closes it on drop so an early `?` return never leaks it.
    struct StoreGuard(HCERTSTORE);
    impl Drop for StoreGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: `self.0` is a valid `HCERTSTORE` from `CertOpenStore`; flag 0 leaves any outstanding cert-context references valid.
                unsafe {
                    let _ = CertCloseStore(self.0, 0);
                }
            }
        }
    }

    /// Reads `COMPUTERNAME` (always set on Windows) for the cert CN, falling back to `flvproxy` if unset. Uses the env var rather than `GetComputerNameW` FFI to keep the FFI surface minimal and to let the CN helper stay cross-platform-testable.
    fn computer_name() -> String {
        std::env::var("COMPUTERNAME").unwrap_or_else(|_| "flvproxy".to_string())
    }

    /// Builds a unique key-container name so repeated generations never collide. Embeds the hostname and a nanosecond timestamp; the container is transient (the exported PFX is self-contained).
    fn container_name(hostname: &str) -> String {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
        format!("flvproxy_cert_{hostname}_{nanos}")
    }

    /// Wraps the last OS error with a call-site tag so a generation failure reports *which* FFI call failed. Without this every failure surfaces as bare `os error 87`, making the failing call impossible to identify from the message alone.
    fn ffi_err(tag: &str) -> io::Error {
        let e = io::Error::last_os_error();
        io::Error::other(format!("CertGen/{tag}: {e}"))
    }

    /// Windows implementation of `super::generate_self_signed_pfx`.
    pub(super) fn generate_self_signed_pfx(out_path: &Path) -> io::Result<()> {
        let hostname = computer_name();
        let cn = subject_cn(&hostname);
        let container = container_name(&hostname);
        let container_wide = to_wide(&container);
        let cn_wide = to_wide(&cn);

        // 1. Acquire a fresh CSP container (CRYPT_NEWKEYSET creates it; a unique name guarantees no collision).
        let mut hprov: HCRYPTPROV = 0;
        // SAFETY: `container_wide` is a valid NUL-terminated wide string; `&mut hprov` is a valid out-pointer; `szProvider = NULL` selects the default provider for PROV_RSA_AES.
        if unsafe { CryptAcquireContextW(&mut hprov, container_wide.as_ptr(), null(), PROV_RSA_AES, CRYPT_NEWKEYSET) } == 0 {
            return Err(ffi_err("CryptAcquireContextW"));
        }
        let prov = ProvGuard(hprov);

        // 2. Generate an exportable 2048-bit AT_KEYEXCHANGE key into the container. The top 16 bits of dwFlags carry the key length; CRYPT_EXPORTABLE is required for PFX private-key export. The returned key handle is freed immediately — the key material persists in the container and is re-acquired by name during export.
        let mut hkey: HCRYPTKEY = 0;
        let key_flags = (RSA_KEY_BITS << 16) | CRYPT_EXPORTABLE;
        // SAFETY: `hprov` is a valid provider handle; `&mut hkey` is a valid out-pointer.
        if unsafe { CryptGenKey(hprov, AT_KEYEXCHANGE, key_flags, &mut hkey) } == 0 {
            return Err(ffi_err("CryptGenKey"));
        }
        // SAFETY: `hkey` is the valid key handle just returned by `CryptGenKey`; freeing the handle does not destroy the key material in the container.
        unsafe {
            let _ = CryptDestroyKey(hkey);
        }

        // 3. Encode the subject CN into a CERT_NAME_BLOB via the two-call CertStrToNameW pattern.
        let mut name_cb: u32 = 0;
        // SAFETY: `cn_wide` is a valid NUL-terminated wide string; `pcbEncoded` is a valid out-pointer; `pbEncoded = NULL` requests the required size.
        if unsafe { CertStrToNameW(X509_ASN_ENCODING, cn_wide.as_ptr(), CERT_X500_NAME_STR, null_mut(), null_mut(), &mut name_cb, null_mut()) } == 0 {
            // Some Windows builds set the required size even on the sizing call; if `name_cb` is 0 the call genuinely failed.
            if name_cb == 0 {
                return Err(ffi_err("CertStrToNameW(size)"));
            }
        }
        let mut name_buf = vec![0u8; name_cb as usize];
        // SAFETY: `name_buf` is `name_cb` bytes; `pbEncoded`/`pcbEncoded` alias `name_buf`'s storage and the size field respectively.
        if unsafe { CertStrToNameW(X509_ASN_ENCODING, cn_wide.as_ptr(), CERT_X500_NAME_STR, null_mut(), name_buf.as_mut_ptr(), &mut name_cb, null_mut()) } == 0 {
            return Err(ffi_err("CertStrToNameW(encode)"));
        }
        name_buf.truncate(name_cb as usize);
        let name_blob = CRYPT_DATA_BLOB { cbData: name_buf.len() as u32, pbData: name_buf.as_mut_ptr() };

        // 4. Validity window: now .. now+10y. GetLocalTime fills the start; the end copies it and adds 10 to the year (day clamped to 28 so a Feb-29 start does not produce an invalid Feb-29 in a non-leap end year).
        let mut not_before = SYSTEMTIME::default();
        // SAFETY: `&mut not_before` is a valid out-pointer for a 16-byte SYSTEMTIME.
        unsafe { GetLocalTime(&mut not_before) };
        let mut not_after = not_before;
        not_after.wYear = not_after.wYear.saturating_add(VALIDITY_YEARS);
        if not_after.wDay > 28 {
            not_after.wDay = 28;
        }

        // 5. Key-provider info naming the container (so the cert's private key is locatable for PFX export) and the SHA-256-RSA signature algorithm.
        let kpi = CRYPT_KEY_PROV_INFO { pwszContainerName: container_wide.as_ptr(), pwszProvName: null(), dwProvType: PROV_RSA_AES, dwFlags: 0, cProvParam: 0, rgProvParam: null_mut(), dwKeySpec: AT_KEYEXCHANGE };
        let alg = CRYPT_ALGORITHM_IDENTIFIER { pszObjId: SZOID_RSA_SHA256RSA.as_ptr(), Parameters: CRYPT_DATA_BLOB { cbData: 0, pbData: null_mut() } };

        // 6. Create the self-signed cert context.
        // SAFETY: `hprov` is a valid provider handle; `name_blob` points into the valid `name_buf` allocation; `kpi` references the valid `container_wide`; `alg` references the static `SZOID_RSA_SHA256RSA`; `not_before`/`not_after` are fully initialized; `pExtensions = NULL` (no extensions).
        let pcert = unsafe { CertCreateSelfSignCertificate(hprov, &name_blob, 0, &kpi, &alg, &not_before, &not_after, null()) };
        if pcert.is_null() {
            return Err(ffi_err("CertCreateSelfSignCertificate"));
        }
        let cert = CertGuard(pcert);

        // 7. Open a memory store and add the cert. The store makes its OWN copy of the context, and per the `CertAddCertificateContextToStore` docs that copy does **not** inherit `CERT_KEY_CONTEXT_PROP_ID` (or `CERT_KEY_PROV_HANDLE_PROP_ID`) — handle-type properties are explicitly excluded from the copy. So we capture the store-owned copy via `ppStoreContext` (the `7b` block below) and attach the key context to *that* copy, which is the one `PFXExportCertStoreEx` reads. Setting the property on `pcert` (the pre-store context) does nothing for the export.
        // SAFETY: `CERT_STORE_PROV_MEMORY` as `(LPCSTR)2`; the remaining args are 0/NULL for an in-memory store.
        let hstore = unsafe { CertOpenStore(CERT_STORE_PROV_MEMORY as *const u8, 0, 0, 0, null()) };
        if hstore.is_null() {
            return Err(ffi_err("CertOpenStore"));
        }
        let store = StoreGuard(hstore);
        let mut store_cert: PCCERT_CONTEXT = null();
        // SAFETY: `hstore` is a valid store; `pcert` is a valid cert context; `&mut store_cert` receives the store-owned copy (freed below via `CertFreeCertificateContext`).
        if unsafe { CertAddCertificateContextToStore(hstore, pcert, CERT_STORE_ADD_REPLACE, &mut store_cert) } == 0 {
            return Err(ffi_err("CertAddCertificateContextToStore"));
        }
        let store_cert = CertGuard(store_cert);

        // 7b. Attach the open provider handle + key spec to the store-owned cert context as `CERT_KEY_CONTEXT_PROP_ID`. This is the property `PFXExportCertStoreEx` consults to serialize the private key; the bare `CERT_KEY_PROV_HANDLE_PROP_ID` is honored by `AcquireCredentialsHandle` but not by the export, which is why the first generated PFX was cert-only (914 bytes) and the service failed with `SEC_E_NO_CREDENTIALS` on `sc.exe start`. `CERT_STORE_NO_CRYPT_RELEASE_FLAG` keeps ownership of `hprov` with `prov` (released at the end of this fn) instead of transferring it to the cert context.
        let key_ctx = CERT_KEY_CONTEXT { cbSize: std::mem::size_of::<CERT_KEY_CONTEXT>() as u32, hCryptProv: hprov, dwKeySpec: AT_KEYEXCHANGE };
        // SAFETY: `store_cert.0` is the valid store-owned cert context; `&key_ctx` is a valid pointer to a fully-initialized `CERT_KEY_CONTEXT` whose `hCryptProv` is owned by `prov` and outlives the export.
        if unsafe { CertSetCertificateContextProperty(store_cert.0, CERT_KEY_CONTEXT_PROP_ID, CERT_STORE_NO_CRYPT_RELEASE_FLAG, &key_ctx as *const CERT_KEY_CONTEXT as *const c_void) } == 0 {
            return Err(ffi_err("CertSetCertificateContextProperty(KEY_CONTEXT)"));
        }

        // 8. Export the store (cert + private key) as a no-password PFX via the two-call pattern. `EXPORT_PRIVATE_KEYS` includes the key; `REPORT_NO_PRIVATE_KEY` + `REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY` make the call fail loudly (rather than silently emit a cert-only PFX) if the key is absent or non-exportable — the silent cert-only path was the runtime failure (the export "succeeded" with a 914-byte cert-only PFX that SChannel then rejected with `SEC_E_NO_CREDENTIALS`). An empty wide string password is passed because the export side rejects a NULL password with `ERROR_INVALID_PARAMETER` (87) on modern Windows; `tls_schannel::from_pfx` re-imports it with its NULL-password path (the two halves use different but compatible no-password representations).
        let export_flags = EXPORT_PRIVATE_KEYS | REPORT_NO_PRIVATE_KEY | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY;
        let empty_pw: [u16; 1] = [0];
        let mut pfx_blob = CRYPT_DATA_BLOB { cbData: 0, pbData: null_mut() };
        // SAFETY: `hstore` is a valid store; `&mut pfx_blob` is a valid out-pointer; `empty_pw` is a valid NUL-terminated empty wide string.
        if unsafe { PFXExportCertStoreEx(hstore, &mut pfx_blob, empty_pw.as_ptr(), null_mut(), export_flags) } == 0 {
            return Err(ffi_err("PFXExportCertStoreEx(size)"));
        }
        if pfx_blob.cbData == 0 {
            return Err(io::Error::other("PFXExportCertStoreEx reported zero-length PFX"));
        }
        let mut pfx_buf = vec![0u8; pfx_blob.cbData as usize];
        pfx_blob.pbData = pfx_buf.as_mut_ptr();
        // SAFETY: `pfx_buf` is `pfx_blob.cbData` bytes; `pbData` aliases `pfx_buf`'s storage.
        if unsafe { PFXExportCertStoreEx(hstore, &mut pfx_blob, empty_pw.as_ptr(), null_mut(), export_flags) } == 0 {
            return Err(ffi_err("PFXExportCertStoreEx(export)"));
        }
        let pfx_bytes = pfx_buf[..pfx_blob.cbData as usize].to_vec();

        // 9. Post-export verification: re-import the generated PFX (mirroring `tls_schannel::from_pfx` with flags = 0) and confirm the re-imported cert carries a `CERT_KEY_PROV_INFO_PROP_ID` — proof the PFX actually contains a private key. Without this, a future regression that silently produces a cert-only PFX would surface only at `sc.exe start` time as `SEC_E_NO_CREDENTIALS`; this check fails the generation loudly instead. The provider handle must stay open through this step (it is — `prov` is dropped below), so the re-import's persisted key resolves cleanly.
        let mut verify_blob = CRYPT_DATA_BLOB { cbData: pfx_bytes.len() as u32, pbData: pfx_bytes.as_ptr() as *mut u8 };
        // SAFETY: `verify_blob` aliases `pfx_bytes`'s storage for the duration of the call; `empty_pw` is a valid empty wide string; flags = 0 persists the key like `tls_schannel::from_pfx`.
        let verify_store = unsafe { PFXImportCertStore(&mut verify_blob, empty_pw.as_ptr(), 0) };
        if verify_store.is_null() {
            return Err(ffi_err("PFXImportCertStore(verify)"));
        }
        let verify_guard = StoreGuard(verify_store);
        // SAFETY: `verify_store` is a valid store; NULL `pPrev` yields the first (only) cert.
        let verify_cert = unsafe { CertEnumCertificatesInStore(verify_store, null()) };
        if verify_cert.is_null() {
            return Err(io::Error::other("PFX verification failed: re-imported PFX contains no certificate"));
        }
        let mut kpi_cb: u32 = 0;
        // SAFETY: `verify_cert` is the valid re-imported cert context; `pvData = NULL` queries presence/size only.
        let has_key = unsafe { CertGetCertificateContextProperty(verify_cert, CERT_KEY_PROV_INFO_PROP_ID, null_mut(), &mut kpi_cb) } != 0;
        // SAFETY: `verify_cert` is the valid context just enumerated; `CertEnumCertificatesInStore` auto-frees the prior context on the next call, but we free it explicitly here for clarity since we will not enumerate further.
        unsafe {
            let _ = CertFreeCertificateContext(verify_cert);
        }
        if !has_key {
            return Err(io::Error::other("PFX verification failed: the exported PFX is cert-only (no private key) — the cert's CERT_KEY_PROV_INFO_PROP_ID is absent after re-import, so SChannel would reject it with SEC_E_NO_CREDENTIALS"));
        }

        // Drop the CryptoAPI handles before touching the filesystem so a write failure cannot leave dangling provider/store/cert references in flight. `verify_guard`/`store_cert` are freed before `prov` so the provider handle is never used after its references are released; `cert` (the original self-signed context) and the store follow.
        drop(verify_guard);
        drop(store_cert);
        drop(store);
        drop(cert);
        drop(prov);

        std::fs::write(out_path, &pfx_bytes).map_err(|e| io::Error::other(format!("CertGen/write: {e}")))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn subject_cn_wraps_hostname() {
            assert_eq!(subject_cn("cam1"), "CN=cam1");
        }

        #[test]
        fn container_name_is_unique_and_prefixed() {
            let a = container_name("host");
            let b = container_name("host");
            assert!(a.starts_with("flvproxy_cert_host_"), "{a}");
            assert_ne!(a, b, "container names must be unique across calls");
        }

        #[test]
        fn systemtime_default_is_all_zero() {
            let st = SYSTEMTIME::default();
            assert_eq!(st.wYear, 0);
            assert_eq!(st.wMilliseconds, 0);
        }
    }
}
