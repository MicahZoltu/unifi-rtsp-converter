//! Hand-rolled, zero-crates, Windows-only SChannel SSPI TLS module (build-plan
//! step 17). Replaces the throwaway `schannel` crate used by the step-16 recon
//! tool and becomes the production TLS foundation for steps 18–21 (Protect
//! controller emulation: WS framing, AVClient 7442, uPFLV 7550).
//!
//! The module implements only the bare-minimum **server-side stream-mode**
//! SChannel surface this one camera exercises: accept a TLS connection backed
//! by a self-signed PFX, then `EncryptMessage`/`DecryptMessage` bidirectional
//! byte streams. No client side, no client-cert authentication, no chain
//! validation — the camera does not present a client cert and the server
//! cert is self-signed. We vendor no crypto source: SChannel is the OS crypto
//! Windows already ships; we only declare the FFI to call it.
//!
//! `PROJECT.md` lines 7 and 120 forbid both the `schannel` crate and its
//! transitive `windows-sys`/`windows-link` deps. This module declares only the
//! ~12 SSPI functions and ~8 structs actually called, which is far easier to
//! audit than the broad `windows-sys` feature set the crate pulls in.
//!
//! The whole module is `#[cfg(windows)]`: it links `crypt32.dll`/`secur32.dll`
//! and has no meaning on Linux. The rest of the crate stays Linux-testable; the
//! `protect_recon` binary is likewise Windows-only.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

use std::ffi::c_void;
use std::fmt;
use std::io::{self, Read, Write};
use std::os::raw::c_int;
use std::ptr::{null, null_mut};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Hard upper bound the accept loop waits for the TLS handshake to complete.
/// The camera sends the ClientHello promptly and each flight follows within a
/// network RTT, so a healthy handshake finishes in well under a second. The
/// deadline only guards against a silent peer (misrouted camera, dead socket)
/// so a stuck accept thread does not block the listener forever; the caller
/// logs "TLS handshake failed: timed out" and drops the connection. Mirrors
/// `protect_recon`'s `CAPTURE_READ_DEADLINE_SECS`.
const HANDSHAKE_DEADLINE_SECS: u64 = 30;

/// Sleep between `WouldBlock`/`TimedOut` retries in the handshake read loop.
/// Keeps the spin cheap while polling well inside the deadline.
const HANDSHAKE_RETRY_SLEEP_MS: u64 = 20;

/// Per-read scratch size for the handshake read loop. The handshake flights are
/// small (KiB-scale); this only bounds how much is buffered per stream read.
const HANDSHAKE_READ_CHUNK: usize = 8192;

/// Scratch-buffer size for the streaming `Read` path. Bounded per read; a
/// larger encrypted record is reassembled across multiple `read` calls.
const STREAM_READ_CHUNK: usize = 8192;

// ---------------------------------------------------------------------------
// SSPI return codes (SECURITY_STATUS is `LONG` = i32; compare via `as u32`).
// ---------------------------------------------------------------------------

/// `SEC_E_OK` — operation succeeded. sspi.h.
const SEC_E_OK: u32 = 0x0000_0000;

/// `SEC_I_CONTINUE_NEEDED` — more handshake flights needed; send the output
/// token and continue. sspi.h.
const SEC_I_CONTINUE_NEEDED: u32 = 0x0009_0312;

/// `SEC_I_CONTEXT_EXPIRED` — peer sent `close_notify`; the stream is at EOF.
/// sspi.h.
const SEC_I_CONTEXT_EXPIRED: u32 = 0x0009_0317;

/// `SEC_E_INCOMPLETE_MESSAGE` — the input does not contain a complete TLS
/// record; read more bytes and retry. sspi.h.
const SEC_E_INCOMPLETE_MESSAGE: u32 = 0x8009_0318;

// ---------------------------------------------------------------------------
// SChannel credential / context flags.
// ---------------------------------------------------------------------------

/// `SCHANNEL_CRED_VERSION` — version of the `SCHANNEL_CRED` struct. schannel.h.
const SCHANNEL_CRED_VERSION: u32 = 4;

/// `SCH_USE_STRONG_CRYPTO` — disable known-weak algorithms/cipher suites.
/// schannel.h.
const SCH_USE_STRONG_CRYPTO: u32 = 0x0040_0000;

/// `SCH_CRED_NO_DEFAULT_CREDS` — server side: do not supply default client
/// creds (irrelevant for inbound, but matches the schannel crate's setup).
/// schannel.h.
const SCH_CRED_NO_DEFAULT_CREDS: u32 = 0x0000_0010;

/// `SECPKG_CRED_INBOUND` — acquire the credential for accepting (server-side)
/// connections. sspi.h.
const SECPKG_CRED_INBOUND: u32 = 0x0000_0001;

/// `ASC_REQ_REPLAY_DETECT` — request replay detection. sspi.h.
const ASC_REQ_REPLAY_DETECT: u32 = 0x0000_0004;

/// `ASC_REQ_SEQUENCE_DETECT` — request sequence detection. sspi.h.
const ASC_REQ_SEQUENCE_DETECT: u32 = 0x0000_0008;

/// `ASC_REQ_CONFIDENTIALITY` — request encryption (confidentiality). sspi.h.
const ASC_REQ_CONFIDENTIALITY: u32 = 0x0000_0010;

/// `ASC_REQ_ALLOCATE_MEMORY` — let SSPI allocate output tokens (caller frees
/// via `FreeContextBuffer`). sspi.h. Value `0x00000100` (256) — *not* `0x200`
/// (512), which is `ASC_REQ_USE_DCE_STYLE`; passing DCE-style instead of
/// allocate-memory caused `SEC_E_INSUFFICIENT_MEMORY` (0x80090300) on the
/// first `AcceptSecurityContext` call (the bug that blocked the step-17
/// self-test before this fix).
const ASC_REQ_ALLOCATE_MEMORY: u32 = 0x0000_0100;

/// `ASC_REQ_STREAM` — operate in stream mode (raw TLS records), the mode this
/// module uses for `EncryptMessage`/`DecryptMessage`. sspi.h.
const ASC_REQ_STREAM: u32 = 0x0001_0000;

/// Composite `AcceptSecurityContext` request flags for a stream-mode,
/// confidential, replay/sequence-detected inbound context with SSPI-allocated
/// output tokens. Matches the schannel crate's `ACCEPT_REQUESTS`.
const ASC_REQ_FLAGS: u32 = ASC_REQ_REPLAY_DETECT
    | ASC_REQ_SEQUENCE_DETECT
    | ASC_REQ_CONFIDENTIALITY
    | ASC_REQ_ALLOCATE_MEMORY
    | ASC_REQ_STREAM;

/// `SECPKG_ATTR_STREAM_SIZES` — query the per-record header/trailer/max sizes.
/// sspi.h.
const SECPKG_ATTR_STREAM_SIZES: u32 = 4;

/// `SCHANNEL_SHUTDOWN` control-token value passed to `ApplyControlToken` to
/// initiate a clean `close_notify` shutdown. schannel.h.
const SCHANNEL_SHUTDOWN: u32 = 1;

// ---------------------------------------------------------------------------
// SecBuffer types. sspi.h.
// ---------------------------------------------------------------------------

/// `SECBUFFER_EMPTY` — unused slot SSPI may fill in. sspi.h.
const SECBUFFER_EMPTY: u32 = 0;

/// `SECBUFFER_DATA` — generic data buffer (used as the decrypt input). sspi.h.
const SECBUFFER_DATA: u32 = 1;

/// `SECBUFFER_TOKEN` — security token (handshake flight). sspi.h.
const SECBUFFER_TOKEN: u32 = 2;

/// `SECBUFFER_EXTRA` — leftover (unconsumed) bytes carried into the next call.
/// sspi.h.
const SECBUFFER_EXTRA: u32 = 5;

/// `SECBUFFER_ALERT` — output slot for an alert SChannel may emit during the
/// handshake (e.g. fatal alert on a protocol error). sspi.h. The `schannel`
/// crate passes `[TOKEN, ALERT, EMPTY]` as the handshake output buffers; we
/// match that layout so SChannel has a slot to write an alert into instead of
/// failing the call with `SEC_E_INSUFFICIENT_MEMORY` (0x80090300).
const SECBUFFER_ALERT: u32 = 17;

/// `SECBUFFER_STREAM_HEADER` — TLS record header slot for `EncryptMessage`.
/// sspi.h.
const SECBUFFER_STREAM_HEADER: u32 = 7;

/// `SECBUFFER_STREAM_TRAILER` — TLS record trailer (MAC) slot for
/// `EncryptMessage`. sspi.h.
const SECBUFFER_STREAM_TRAILER: u32 = 6;

/// `SECBUFFER_VERSION` — `SecBufferDesc.ulVersion` value. sspi.h.
const SECBUFFER_VERSION: u32 = 0;

/// `UNISP_NAME_A` — the SSPI package name for the Microsoft Unified Security
/// Protocol Provider (SChannel), ANSI form for `AcquireCredentialsHandleA`.
/// schannel.h.
const UNISP_NAME_A: &[u8] = b"Microsoft Unified Security Protocol Provider\0";

// ---------------------------------------------------------------------------
// Raw Win32 structs (only what we call).
// ---------------------------------------------------------------------------

/// `TimeStamp` (sspi.h) — expiry/out parameter; we pass null where unused, but
/// declare it for `AcquireCredentialsHandleA`. Two-DWORD form, 8 bytes, 4-byte
/// aligned — ABI-identical to the `i64` the headers sometimes typedef it to.
#[repr(C)]
#[derive(Copy, Clone)]
struct TimeStamp {
    dwLowDateTime: u32,
    dwHighDateTime: u32,
}

/// `SecHandle` (sspi.h) — opaque credential/context handle pair. Both members
/// are opaque pointers; we never dereference them.
#[repr(C)]
#[derive(Copy, Clone)]
struct SecHandle {
    dwLower: *mut c_void,
    dwUpper: *mut c_void,
}

impl SecHandle {
    /// All-zero handle (NULL), used as the "no context yet" sentinel.
    fn null() -> SecHandle {
        SecHandle {
            dwLower: null_mut(),
            dwUpper: null_mut(),
        }
    }
}

/// `SecBuffer` (sspi.h) — one buffer passed to/from an SSPI function.
#[repr(C)]
struct SecBuffer {
    cbBuffer: u32,
    BufferType: u32,
    pvBuffer: *mut c_void,
}

impl SecBuffer {
    /// Builds an empty (type `SECBUFFER_EMPTY`, zero-length) buffer.
    fn empty() -> SecBuffer {
        SecBuffer {
            cbBuffer: 0,
            BufferType: SECBUFFER_EMPTY,
            pvBuffer: null_mut(),
        }
    }
}

/// `SecBufferDesc` (sspi.h) — descriptor for an array of `SecBuffer`.
#[repr(C)]
struct SecBufferDesc {
    ulVersion: u32,
    cBuffers: u32,
    pBuffers: *mut SecBuffer,
}

/// `SCHANNEL_CRED` (schannel.h) — credential configuration. Layout matches the
/// Windows SDK `SCHANNEL_CRED` (version 4) on x86_64: `dwVersion`, `cCreds`,
/// `paCred` (ptr), `hRootStore` (ptr), `cMappers`, `aphMappers` (ptr),
/// `cSupportedAlgs`, `palgSupportedAlgs` (ptr), `grbitEnabledProtocols`,
/// minimum/maximum cipher strength, session lifespan, flags, cred format.
#[repr(C)]
struct SCHANNEL_CRED {
    dwVersion: u32,
    cCreds: u32,
    paCred: *mut *const CERT_CONTEXT,
    hRootStore: *mut c_void,
    cMappers: u32,
    aphMappers: *mut *mut c_void,
    cSupportedAlgs: u32,
    palgSupportedAlgs: *mut u32,
    grbitEnabledProtocols: u32,
    dwMinimumCipherStrength: u32,
    dwMaximumCipherStrength: u32,
    dwSessionLifespan: u32,
    dwFlags: u32,
    dwCredFormat: u32,
}

/// `CRYPT_INTEGER_BLOB` / `CRYPT_DATA_BLOB` (wincrypt.h) — length + pointer,
/// used for the PFX bytes and password passed to `PFXImportCertStore`.
#[repr(C)]
struct CRYPT_INTEGER_BLOB {
    cbData: u32,
    pbData: *mut u8,
}

/// `SecPkgContext_StreamSizesW` (sspi.h) — returned by
/// `QueryContextAttributesW(SECPKG_ATTR_STREAM_SIZES)`; sizes for stream-mode
/// record framing.
#[repr(C)]
struct SecPkgContext_StreamSizesW {
    cbHeader: u32,
    cbTrailer: u32,
    cbMaximumMessage: u32,
    cBuffers: u32,
    cbBlockSize: u32,
}

/// Opaque `CERT_CONTEXT` (wincrypt.h). We only ever hold/pass pointers to it,
/// so the body is left undefined.
#[repr(C)]
struct CERT_CONTEXT {
    _opaque: [u8; 0],
}

// ---------------------------------------------------------------------------
// FFI declarations. `extern "system"` matches the Win32 calling convention
// (stdcall on x86, the common convention on x86_64). `#[link]` pulls in the
// import libraries MinGW ships (`libcrypt32.a`, `libsecur32.a`).
// ---------------------------------------------------------------------------

#[link(name = "crypt32")]
extern "system" {
    /// `PFXImportCertStore` (wincrypt.h) — load a PFX into a transient cert
    /// store and return its handle, or NULL on failure (call `GetLastError`).
    fn PFXImportCertStore(
        pPFX: *mut CRYPT_INTEGER_BLOB,
        szPassword: *const u16,
        dwFlags: u32,
    ) -> *mut c_void;

    /// `CertEnumCertificatesInStore` (wincrypt.h) — enumerate certs in a store.
    /// Pass NULL for `pPrev` to get the first; pass the prior context to get
    /// the next (the prior is automatically freed). Returns NULL when done.
    fn CertEnumCertificatesInStore(
        hCertStore: *mut c_void,
        pPrev: *const CERT_CONTEXT,
    ) -> *const CERT_CONTEXT;

    /// `CertFreeCertificateContext` (wincrypt.h) — release one reference to a
    /// cert context. Returns TRUE on success.
    fn CertFreeCertificateContext(pCertContext: *const CERT_CONTEXT) -> c_int;

    /// `CertCloseStore` (wincrypt.h) — close a cert store. Outstanding cert
    /// context references (freed separately) remain valid with flag 0.
    fn CertCloseStore(hCertStore: *mut c_void, dwFlags: u32) -> c_int;
}

#[link(name = "secur32")]
extern "system" {
    /// `AcquireCredentialsHandleA` (sspi.h) — acquire an SSPI credential
    /// handle. For SChannel, `pszPackage` is `UNISP_NAME_A` and `pAuthData`
    /// points to a `SCHANNEL_CRED`.
    fn AcquireCredentialsHandleA(
        pszPrincipal: *const u8,
        pszPackage: *const u8,
        fCredentialUse: u32,
        pvLogonId: *const c_void,
        pAuthData: *const c_void,
        pGetKeyFn: *const c_void,
        pvGetKeyArgument: *const c_void,
        phCredential: *mut SecHandle,
        ptsExpiry: *mut TimeStamp,
    ) -> i32;

    /// `FreeCredentialsHandle` (sspi.h) — release a credential handle.
    fn FreeCredentialsHandle(phCredential: *mut SecHandle) -> i32;

    /// `AcceptSecurityContext` (sspi.h) — drive the server-side TLS handshake
    /// to completion, returning `SEC_E_OK`/`SEC_I_CONTINUE_NEEDED`/
    /// `SEC_E_INCOMPLETE_MESSAGE`/`SEC_I_CONTEXT_EXPIRED`.
    fn AcceptSecurityContext(
        phCredential: *const SecHandle,
        phContext: *const SecHandle,
        pInput: *mut SecBufferDesc,
        fContextReq: u32,
        TargetDataRep: u32,
        phNewContext: *mut SecHandle,
        pOutput: *mut SecBufferDesc,
        pfContextAttr: *mut u32,
        ptsExpiry: *mut TimeStamp,
    ) -> i32;

    /// `DeleteSecurityContext` (sspi.h) — release a security context.
    fn DeleteSecurityContext(phContext: *mut SecHandle) -> i32;

    /// `ApplyControlToken` (sspi.h) — apply a control token (e.g.
    /// `SCHANNEL_SHUTDOWN`) to a context before the next handshake call.
    fn ApplyControlToken(phContext: *const SecHandle, pInput: *mut SecBufferDesc) -> i32;

    /// `EncryptMessage` (sspi.h) — encrypt one plaintext into a stream-mode TLS
    /// record. The buffers' `cbBuffer` are updated on return.
    fn EncryptMessage(
        phContext: *const SecHandle,
        fQOP: u32,
        pMessage: *mut SecBufferDesc,
        MessageSeqNo: u32,
    ) -> i32;

    /// `DecryptMessage` (sspi.h) — decrypt one stream-mode TLS record. The
    /// first buffer (input) becomes consumed; a `SECBUFFER_DATA` buffer holds
    /// the plaintext and a `SECBUFFER_EXTRA` buffer holds leftover bytes.
    fn DecryptMessage(
        phContext: *const SecHandle,
        pMessage: *mut SecBufferDesc,
        MessageSeqNo: u32,
        pfQOP: *mut u32,
    ) -> i32;

    /// `FreeContextBuffer` (sspi.h) — release a buffer SSPI allocated (e.g. an
    /// output handshake token produced with `ASC_REQ_ALLOCATE_MEMORY`).
    fn FreeContextBuffer(pvContextBuffer: *mut c_void) -> i32;

    /// `QueryContextAttributesW` (sspi.h) — query a context attribute. Used here
    /// for `SECPKG_ATTR_STREAM_SIZES` to learn record framing sizes.
    fn QueryContextAttributesW(
        phContext: *const SecHandle,
        ulAttribute: u32,
        pBuffer: *mut c_void,
    ) -> i32;
}

// ---------------------------------------------------------------------------
// HandshakeError — distinguishes a benign peer preconnect/probe from a real
// TLS failure, so the caller can decide whether to log quietly or treat it as
// an error. Discovered during step-17 validation: the UVC G5 camera opens a
// TCP connection to 7442, completes the 3-way handshake, then sends FIN with
// zero application bytes (a TCP liveness probe) before opening the real TLS
// connection. `TlsAcceptor::accept` surfaces this as `PeerClosedBeforeData`
// so the production controller (steps 18–21) and the recon tool can recognize
// it as benign instead of logging a scary "TLS handshake failed".
// ---------------------------------------------------------------------------

/// Failure outcome of `TlsAcceptor::accept`.
#[derive(Debug)]
pub enum HandshakeError {
    /// The peer completed the TCP handshake but closed the connection before
    /// sending any application bytes — i.e. `read()` returned 0 on the very
    /// first read of the handshake, with no prior bytes received. Common for
    /// embedded clients: the UVC G5 camera performs this exact zero-byte TCP
    /// liveness probe on port 7442 before opening the real TLS connection.
    /// No TLS handshake was attempted (SChannel never received a `ClientHello`).
    /// Callers should treat this as benign — debug log, no error metric.
    PeerClosedBeforeData,
    /// The TLS handshake failed for a real reason: SChannel rejected the
    /// peer's bytes, the peer closed mid-handshake (after sending some bytes),
    /// the handshake timed out, or a write to the peer failed. Callers should
    /// log this at error level and count it.
    Failed(io::Error),
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HandshakeError::PeerClosedBeforeData => {
                f.write_str("peer closed before sending any bytes (TCP liveness probe)")
            }
            HandshakeError::Failed(e) => write!(f, "TLS handshake failed: {e}"),
        }
    }
}

impl std::error::Error for HandshakeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            HandshakeError::PeerClosedBeforeData => None,
            HandshakeError::Failed(e) => Some(e),
        }
    }
}

// ---------------------------------------------------------------------------
// TlsAcceptor — built once from a PFX; Clone (Arc-wrapped cred handle) so
// listener threads share it.
// ---------------------------------------------------------------------------

/// Server-side SChannel credential built from a PFX. `Clone` is cheap (one
/// `Arc` refcount) so a listener hands the same acceptor to every accepted
/// connection. Dropping the last clone frees the credential handle and the
/// loaded certificate context.
#[derive(Clone)]
pub struct TlsAcceptor {
    inner: Arc<RawAcceptor>,
}

struct RawAcceptor {
    cred: SecHandle,
    cert: *const CERT_CONTEXT,
}

/// SChannel credential handles are safe to share across threads for inbound
/// accepts (the package serializes internally; the handle is read-only during
/// `AcceptSecurityContext`). We hold the certificate context for the cred's
/// lifetime and never mutate either from Rust.
unsafe impl Send for RawAcceptor {}
unsafe impl Sync for RawAcceptor {}

impl Drop for RawAcceptor {
    fn drop(&mut self) {
        // Order: free the credential (which may still reference the cert)
        // before freeing the certificate context itself.
        unsafe {
            let _ = FreeCredentialsHandle(&mut self.cred);
            if !self.cert.is_null() {
                let _ = CertFreeCertificateContext(self.cert);
            }
        }
    }
}

impl TlsAcceptor {
    /// Imports `pfx` and acquires an inbound (server-side) SChannel credential
    /// over the first certificate in the archive. `password` decrypts the PFX;
    /// pass `None` for an unencrypted PFX.
    ///
    /// `PFXImportCertStore` is called with **flags = 0** — the same path the
    /// step-16 `schannel`-crate tool used successfully against the real camera.
    /// `PKCS12_NO_PERSIST_KEY` (0x8000) was tried and rejected: it leaves the
    /// private key as a non-persisted in-memory `NCRYPT_KEY_HANDLE` that
    /// `AcquireCredentialsHandleA` cannot resolve for a server credential,
    /// producing `SEC_E_NO_CREDENTIALS` (0x8009030E) on this Windows config.
    /// With flags = 0 the key is persisted to the user's CSP/KSP container for
    /// the process's lifetime (standard behavior for a Windows service
    /// identity — no UI prompt). The leftover `protect-recon` self-signed key
    /// is a `DEBT.md`-tracked cleanup item (see `DEBT.md` step 17).
    pub fn from_pfx(pfx: &[u8], password: Option<&str>) -> io::Result<TlsAcceptor> {
        unsafe {
            let mut pfx_blob = CRYPT_INTEGER_BLOB {
                cbData: pfx.len() as u32,
                pbData: pfx.as_ptr() as *mut u8,
            };
            let pw_wide: Vec<u16> = match password {
                Some(pw) => pw.encode_utf16().chain(std::iter::once(0u16)).collect(),
                None => Vec::new(),
            };
            let pw_ptr = if pw_wide.is_empty() {
                null::<u16>()
            } else {
                pw_wide.as_ptr()
            };
            // flags = 0: persist the key to the user's CSP/KSP container. See
            // the method doc for why PKCS12_NO_PERSIST_KEY is not used.
            let store = PFXImportCertStore(&mut pfx_blob, pw_ptr, 0);
            if store.is_null() {
                return Err(io::Error::last_os_error());
            }
            let cert = CertEnumCertificatesInStore(store, null::<CERT_CONTEXT>());
            let _ = CertCloseStore(store, 0);
            if cert.is_null() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "PFX contains no certificates",
                ));
            }

            let mut cred_data: SCHANNEL_CRED = std::mem::zeroed();
            cred_data.dwVersion = SCHANNEL_CRED_VERSION;
            cred_data.cCreds = 1;
            cred_data.paCred = &cert as *const *const CERT_CONTEXT as *mut *const CERT_CONTEXT;
            cred_data.hRootStore = null_mut();
            cred_data.cMappers = 0;
            cred_data.aphMappers = null_mut();
            cred_data.cSupportedAlgs = 0;
            cred_data.palgSupportedAlgs = null_mut();
            cred_data.grbitEnabledProtocols = 0;
            cred_data.dwMinimumCipherStrength = 0;
            cred_data.dwMaximumCipherStrength = 0;
            cred_data.dwSessionLifespan = 0;
            cred_data.dwFlags = SCH_USE_STRONG_CRYPTO | SCH_CRED_NO_DEFAULT_CREDS;
            cred_data.dwCredFormat = 0;

            let mut cred_handle = SecHandle::null();
            let ret = AcquireCredentialsHandleA(
                null(),
                UNISP_NAME_A.as_ptr(),
                SECPKG_CRED_INBOUND,
                null(),
                &cred_data as *const SCHANNEL_CRED as *const c_void,
                null(),
                null(),
                &mut cred_handle,
                null_mut(),
            );
            if ret as u32 != SEC_E_OK {
                let _ = CertFreeCertificateContext(cert);
                return Err(io::Error::other(format!(
                    "AcquireCredentialsHandleA failed: 0x{:08X}",
                    ret as u32
                )));
            }

            Ok(TlsAcceptor {
                inner: Arc::new(RawAcceptor {
                    cred: cred_handle,
                    cert,
                }),
            })
        }
    }

    /// Drives the server-side TLS handshake over `stream` to completion,
    /// returning a `TlsStream` that encrypts/decrypts application data over the
    /// same `stream`. Tolerates `WouldBlock`/`TimedOut` from a timed blocking
    /// socket (retries up to `HANDSHAKE_DEADLINE_SECS`), so the recon tool's
    /// read-timeout socket does not abort mid-handshake.
    ///
    /// On failure returns a [`HandshakeError`], which distinguishes a benign
    /// zero-byte TCP liveness probe (`PeerClosedBeforeData` — the peer closed
    /// before sending any bytes, e.g. the UVC G5's 7442 preconnect) from a
    /// real TLS failure (`Failed`).
    pub fn accept<S: Read + Write>(&self, stream: S) -> Result<TlsStream<S>, HandshakeError> {
        let mut stream = stream;
        // Single context handle, passed as both phContext (from the second call
        // on) and phNewContext on every call — the proven pattern the schannel
        // crate uses against this camera. SChannel fills it on the first call
        // and updates it in place thereafter.
        let mut context = SecHandle::null();
        // Whether the *next* `AcceptSecurityContext` call is the literal first
        // call (phContext must be NULL). Per the schannel crate's comment
        // (tls_stream.rs:541-555): Windows rejects a non-NULL phContext on a
        // call that follows an `SEC_E_INCOMPLETE_MESSAGE` result — the context
        // is only "live" once a call returns `CONTINUE_NEEDED` or `OK`. We
        // therefore flip this flag to `false` only inside those two arms, never
        // unconditionally after the call.
        let mut first_call = true;
        let mut input: Vec<u8> = Vec::new();
        // Whether the peer has sent us *any* bytes yet on this connection.
        // Distinguishes a zero-byte TCP liveness probe (EOF on the first read,
        // before any bytes) from a mid-handshake peer close (EOF after some
        // bytes). See `HandshakeError::PeerClosedBeforeData`.
        let mut received_any = false;
        let deadline = Instant::now() + Duration::from_secs(HANDSHAKE_DEADLINE_SECS);

        loop {
            // Read before the first call so SChannel is never handed an empty
            // token (which would also throw off the first_call/INCOMPLETE_MESSAGE
            // invariant). Subsequent iterations only read when the prior result
            // was CONTINUE_NEEDED with no leftover, or INCOMPLETE_MESSAGE.
            if input.is_empty() {
                if let Err(e) = read_more(&mut stream, &mut input, deadline) {
                    return Err(read_err_to_handshake(e, received_any));
                }
                // read_more only returns Ok after appending ≥1 byte.
                received_any = true;
            }

            let mut in_bufs = [
                SecBuffer {
                    cbBuffer: input.len() as u32,
                    BufferType: SECBUFFER_TOKEN,
                    pvBuffer: input.as_mut_ptr() as *mut c_void,
                },
                SecBuffer::empty(),
            ];
            let mut in_desc = SecBufferDesc {
                ulVersion: SECBUFFER_VERSION,
                cBuffers: in_bufs.len() as u32,
                pBuffers: in_bufs.as_mut_ptr(),
            };

            // Output buffers: [TOKEN, ALERT, EMPTY] — matches the schannel
            // crate's server-handshake layout. The ALERT slot gives SChannel a
            // place to write an alert without failing the call with
            // SEC_E_INSUFFICIENT_MEMORY (0x80090300).
            let mut out_bufs = [
                SecBuffer {
                    cbBuffer: 0,
                    BufferType: SECBUFFER_TOKEN,
                    pvBuffer: null_mut(),
                },
                SecBuffer {
                    cbBuffer: 0,
                    BufferType: SECBUFFER_ALERT,
                    pvBuffer: null_mut(),
                },
                SecBuffer::empty(),
            ];
            let mut out_desc = SecBufferDesc {
                ulVersion: SECBUFFER_VERSION,
                cBuffers: out_bufs.len() as u32,
                pBuffers: out_bufs.as_mut_ptr(),
            };

            // phContext is NULL on the very first call, then the live context
            // handle on every subsequent *valid* call. phNewContext always
            // aliases the same `context` slot (SChannel updates it in place).
            // Using raw pointers avoids overlapping a shared and mutable
            // borrow of `context` in the same FFI call.
            let ctx_ptr: *mut SecHandle = &mut context;
            let ph_context: *const SecHandle = if first_call {
                null::<SecHandle>()
            } else {
                ctx_ptr
            };
            let mut attrs: u32 = 0;

            let ret = unsafe {
                AcceptSecurityContext(
                    &self.inner.cred as *const SecHandle,
                    ph_context,
                    &mut in_desc,
                    ASC_REQ_FLAGS,
                    0,
                    ctx_ptr,
                    &mut out_desc,
                    &mut attrs,
                    null_mut(),
                )
            };
            let ret_u = ret as u32;

            // Send any output token (handshake flight / alert) the SSPI
            // produced back to the peer, then release every SSPI-allocated
            // output buffer (TOKEN at [0], ALERT at [1], any fill-in at [2]).
            // The schannel crate frees outbufs[1..]; we free all non-null
            // output buffers for the same reason — SSPI allocates them with
            // ASC_REQ_ALLOCATE_MEMORY and the caller owns their release.
            for (i, buf) in out_bufs.iter_mut().enumerate() {
                if !buf.pvBuffer.is_null() && buf.cbBuffer > 0 {
                    let token = unsafe {
                        std::slice::from_raw_parts(buf.pvBuffer as *const u8, buf.cbBuffer as usize)
                    };
                    if i == 0 {
                        // Only the TOKEN buffer is a handshake flight the peer
                        // expects to receive; an ALERT is SChannel-internal
                        // and already folded into the TOKEN flight when sent.
                        let write_res = stream.write_all(token);
                        unsafe { FreeContextBuffer(buf.pvBuffer) };
                        write_res.map_err(HandshakeError::Failed)?;
                    } else {
                        unsafe { FreeContextBuffer(buf.pvBuffer) };
                    }
                    buf.pvBuffer = null_mut();
                    buf.cbBuffer = 0;
                }
            }

            match ret_u {
                SEC_E_OK => {
                    let extra = extra_size(&in_bufs);
                    let leftover = if extra > 0 {
                        let consumed = input.len() - extra;
                        input[consumed..].to_vec()
                    } else {
                        Vec::new()
                    };
                    return TlsStream::new(stream, context, leftover, self.inner.clone())
                        .map_err(HandshakeError::Failed);
                }
                SEC_I_CONTINUE_NEEDED => {
                    first_call = false;
                    let extra = extra_size(&in_bufs);
                    let consumed = input.len().saturating_sub(extra);
                    if consumed > 0 {
                        input.drain(0..consumed);
                    }
                    continue;
                }
                SEC_E_INCOMPLETE_MESSAGE => {
                    // Do NOT flip first_call — the context is not yet live and
                    // the next call must still pass phContext = NULL. Just read
                    // more bytes and retry.
                    if let Err(e) = read_more(&mut stream, &mut input, deadline) {
                        return Err(read_err_to_handshake(e, received_any));
                    }
                    received_any = true;
                    continue;
                }
                SEC_I_CONTEXT_EXPIRED => {
                    return Err(HandshakeError::Failed(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "peer closed during TLS handshake",
                    )));
                }
                other => {
                    return Err(HandshakeError::Failed(io::Error::other(format!(
                        "AcceptSecurityContext failed: 0x{other:08X}"
                    ))));
                }
            }
        }
    }
}

/// Maps a `read_more` error to a [`HandshakeError`]: a peer EOF (`Ok(0)` from
/// `read`) when *no* bytes have ever been received on this connection is a
/// benign zero-byte TCP liveness probe (`PeerClosedBeforeData`); any other
/// error (EOF after some bytes, timeout, fatal read error) is a real failure.
fn read_err_to_handshake(e: io::Error, received_any: bool) -> HandshakeError {
    if !received_any && e.kind() == io::ErrorKind::UnexpectedEof {
        HandshakeError::PeerClosedBeforeData
    } else {
        HandshakeError::Failed(e)
    }
}

/// Returns the `cbBuffer` of the first `SECBUFFER_EXTRA` entry in `bufs`, or 0
/// if none. The EXTRA buffer holds input bytes SSPI did not consume (leftover
/// for the next call).
fn extra_size(bufs: &[SecBuffer]) -> usize {
    for b in bufs {
        if b.BufferType == SECBUFFER_EXTRA {
            return b.cbBuffer as usize;
        }
    }
    0
}

/// Reads more bytes from `stream` into `input`, retrying on `Interrupted` and
/// tolerating `WouldBlock`/`TimedOut` (sleep + retry) until `deadline` elapses.
/// Returns `Ok(())` after appending at least one byte, or an error on EOF /
/// timeout / fatal read error.
fn read_more<S: Read>(stream: &mut S, input: &mut Vec<u8>, deadline: Instant) -> io::Result<()> {
    let mut scratch = [0u8; HANDSHAKE_READ_CHUNK];
    loop {
        match stream.read(&mut scratch) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "peer closed during TLS handshake",
                ));
            }
            Ok(n) => {
                input.extend_from_slice(&scratch[..n]);
                return Ok(());
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "TLS handshake timed out",
                    ));
                }
                thread::sleep(Duration::from_millis(HANDSHAKE_RETRY_SLEEP_MS));
                continue;
            }
            Err(e) => return Err(e),
        }
    }
}

// ---------------------------------------------------------------------------
// TlsStream — stream-mode TLS Read + Write over an arbitrary byte stream.
// ---------------------------------------------------------------------------

/// A TLS stream wrapping an underlying `Read + Write` byte stream. Encrypts
/// outgoing writes into TLS records via `EncryptMessage` and decrypts incoming
/// reads via `DecryptMessage`, carrying leftover encrypted/decrypted bytes
/// across calls so records spanning reads and multiple records per read are
/// handled correctly.
pub struct TlsStream<S> {
    stream: S,
    context: SecHandle,
    /// The credential handle (Arc-shared with `TlsAcceptor`) — retained so the
    /// `shutdown()` path can pass it to `AcceptSecurityContext`, which SChannel
    /// requires even on the post-handshake shutdown call (passing NULL yields
    /// `SEC_E_INVALID_HANDLE` / 0x80090301). Matches the `schannel` crate's
    /// `TlsStream` which holds `cred: SchannelCred` for the same reason.
    cred: Arc<RawAcceptor>,
    sizes: SecPkgContext_StreamSizesW,
    /// Decrypted plaintext not yet handed to the caller (`dec_pos..len()`).
    dec_buf: Vec<u8>,
    dec_pos: usize,
    /// Encrypted bytes received but not yet consumed by `DecryptMessage`.
    enc_buf: Vec<u8>,
    /// True after `shutdown()` has driven the `close_notify` exchange.
    shutdown_done: bool,
}

/// A live security context owns raw SSPI handles but is used from a single
/// thread per connection (the recon tool moves it into one handler thread).
unsafe impl<S: Send> Send for TlsStream<S> {}

impl<S: Read + Write> TlsStream<S> {
    /// Finishes a completed handshake: stores the context, queries the
    /// stream-mode record sizes, and seeds `enc_buf` with any bytes the peer
    /// sent immediately after the final handshake flight (post-handshake app
    /// data that arrived in the same TCP segment).
    fn new(
        stream: S,
        context: SecHandle,
        leftover_enc: Vec<u8>,
        cred: Arc<RawAcceptor>,
    ) -> io::Result<TlsStream<S>> {
        let sizes = query_stream_sizes(&context)?;
        Ok(TlsStream {
            stream,
            context,
            cred,
            sizes,
            dec_buf: Vec::new(),
            dec_pos: 0,
            enc_buf: leftover_enc,
            shutdown_done: false,
        })
    }

    /// Returns a shared reference to the wrapped underlying stream.
    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    /// Returns a mutable reference to the wrapped underlying stream.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Drives a clean TLS `close_notify` shutdown: applies the
    /// `SCHANNEL_SHUTDOWN` control token, calls `AcceptSecurityContext` once
    /// more to produce the close_notify flight, sends it, and is then safe to
    /// drop. Idempotent — subsequent calls are no-ops.
    pub fn shutdown(&mut self) -> io::Result<()> {
        if self.shutdown_done {
            return Ok(());
        }
        unsafe {
            let mut token: u32 = SCHANNEL_SHUTDOWN;
            let token_ptr = &mut token as *mut u32 as *mut c_void;
            let mut shut_buf = SecBuffer {
                cbBuffer: std::mem::size_of::<u32>() as u32,
                BufferType: SECBUFFER_TOKEN,
                pvBuffer: token_ptr,
            };
            let mut shut_desc = SecBufferDesc {
                ulVersion: SECBUFFER_VERSION,
                cBuffers: 1,
                pBuffers: &mut shut_buf,
            };
            let ret = ApplyControlToken(&self.context, &mut shut_desc);
            if ret as u32 != SEC_E_OK {
                return Err(io::Error::other(format!(
                    "ApplyControlToken(shutdown) failed: 0x{:08X}",
                    ret as u32
                )));
            }

            // After ApplyControlToken, call AcceptSecurityContext once more to
            // produce the close_notify flight. This mirrors the schannel crate's
            // shutdown path (which re-enters step_initialize with shutting_down
            // = true): pass the credential handle (NOT NULL — SChannel returns
            // SEC_E_INVALID_HANDLE if phCredential is NULL here), the existing
            // context as both phContext and phNewContext, an input desc with
            // [SECBUFFER_TOKEN (0 bytes), SECBUFFER_EMPTY], and the same
            // [TOKEN, ALERT, EMPTY] output layout as the handshake.
            let mut in_bufs = [
                SecBuffer {
                    cbBuffer: 0,
                    BufferType: SECBUFFER_TOKEN,
                    pvBuffer: null_mut(),
                },
                SecBuffer::empty(),
            ];
            let mut in_desc = SecBufferDesc {
                ulVersion: SECBUFFER_VERSION,
                cBuffers: in_bufs.len() as u32,
                pBuffers: in_bufs.as_mut_ptr(),
            };
            let mut out_bufs = [
                SecBuffer {
                    cbBuffer: 0,
                    BufferType: SECBUFFER_TOKEN,
                    pvBuffer: null_mut(),
                },
                SecBuffer {
                    cbBuffer: 0,
                    BufferType: SECBUFFER_ALERT,
                    pvBuffer: null_mut(),
                },
                SecBuffer::empty(),
            ];
            let mut out_desc = SecBufferDesc {
                ulVersion: SECBUFFER_VERSION,
                cBuffers: out_bufs.len() as u32,
                pBuffers: out_bufs.as_mut_ptr(),
            };
            let mut attrs: u32 = 0;
            let ctx_ptr: *mut SecHandle = &mut self.context;
            let ret = AcceptSecurityContext(
                &self.cred.cred as *const SecHandle,
                ctx_ptr,
                &mut in_desc,
                ASC_REQ_FLAGS,
                0,
                ctx_ptr,
                &mut out_desc,
                &mut attrs,
                null_mut(),
            );
            if ret as u32 != SEC_E_OK && ret as u32 != SEC_I_CONTEXT_EXPIRED {
                return Err(io::Error::other(format!(
                    "AcceptSecurityContext(shutdown) failed: 0x{:08X}",
                    ret as u32
                )));
            }
            // Send the close_notify flight and free any SSPI-allocated output
            // buffers (TOKEN at [0], ALERT at [1], fill-in at [2]).
            for (i, buf) in out_bufs.iter_mut().enumerate() {
                if !buf.pvBuffer.is_null() && buf.cbBuffer > 0 {
                    if i == 0 {
                        let token = std::slice::from_raw_parts(
                            buf.pvBuffer as *const u8,
                            buf.cbBuffer as usize,
                        );
                        let write_res = self.stream.write_all(token);
                        FreeContextBuffer(buf.pvBuffer);
                        write_res?;
                    } else {
                        FreeContextBuffer(buf.pvBuffer);
                    }
                    buf.pvBuffer = null_mut();
                    buf.cbBuffer = 0;
                }
            }
        }
        self.shutdown_done = true;
        Ok(())
    }

    /// Encrypts one plaintext chunk (`<= cbMaximumMessage`) into a TLS record
    /// and writes the whole record (header + encrypted data + trailer) to the
    /// underlying stream. The record is fully sent before returning, so there
    /// is no half-sent-record state to recover from.
    fn encrypt_and_send(&mut self, plaintext: &[u8]) -> io::Result<()> {
        let header = self.sizes.cbHeader as usize;
        let trailer = self.sizes.cbTrailer as usize;
        let total = header + plaintext.len() + trailer;
        let mut record = vec![0u8; total];
        record[header..header + plaintext.len()].copy_from_slice(plaintext);

        let base = record.as_mut_ptr();
        // SAFETY: `base..base+total` is the valid allocation backing `record`;
        // `header` and `header+plaintext.len()` lie within it, so the offset
        // pointers are in-bounds. The pointers alias `record` only until
        // `EncryptMessage` returns; we do not reallocate or alias-uniquely
        // during the call.
        let (data_ptr, trailer_ptr) =
            unsafe { (base.add(header), base.add(header + plaintext.len())) };
        let mut bufs = [
            SecBuffer {
                cbBuffer: header as u32,
                BufferType: SECBUFFER_STREAM_HEADER,
                pvBuffer: base as *mut c_void,
            },
            SecBuffer {
                cbBuffer: plaintext.len() as u32,
                BufferType: SECBUFFER_DATA,
                pvBuffer: data_ptr as *mut c_void,
            },
            SecBuffer {
                cbBuffer: trailer as u32,
                BufferType: SECBUFFER_STREAM_TRAILER,
                pvBuffer: trailer_ptr as *mut c_void,
            },
            SecBuffer::empty(),
        ];
        let mut desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: bufs.len() as u32,
            pBuffers: bufs.as_mut_ptr(),
        };
        let ret = unsafe { EncryptMessage(&self.context, 0, &mut desc, 0) };
        if ret as u32 != SEC_E_OK {
            return Err(io::Error::other(format!(
                "EncryptMessage failed: 0x{:08X}",
                ret as u32
            )));
        }
        // After encryption the header/data/trailer cbBuffer reflect the actual
        // record framing (data may have grown with padding folded in). Send the
        // contiguous record = header + data + trailer.
        let send_len = (bufs[0].cbBuffer + bufs[1].cbBuffer + bufs[2].cbBuffer) as usize;
        self.stream.write_all(&record[..send_len])?;
        self.stream.flush()?;
        Ok(())
    }

    /// Attempts one `DecryptMessage` over `enc_buf`. On success copies the
    /// decrypted plaintext into `dec_buf`, retains any leftover encrypted bytes
    /// in `enc_buf`, resets the decrypt read position, and returns `Ok(true)`.
    /// Returns `Ok(false)` when more encrypted bytes are needed
    /// (`SEC_E_INCOMPLETE_MESSAGE`) so the caller reads more. Returns
    /// `Ok(Err(eof))` semantics via the special `CONTEXT_EXPIRED` variant.
    fn try_decrypt(&mut self) -> io::Result<DecryptOutcome> {
        let pos = self.enc_buf.len();
        let mut bufs = [
            SecBuffer {
                cbBuffer: pos as u32,
                BufferType: SECBUFFER_DATA,
                pvBuffer: self.enc_buf.as_mut_ptr() as *mut c_void,
            },
            SecBuffer::empty(),
            SecBuffer::empty(),
            SecBuffer::empty(),
        ];
        let mut desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: bufs.len() as u32,
            pBuffers: bufs.as_mut_ptr(),
        };
        let mut qop: u32 = 0;
        let ret = unsafe { DecryptMessage(&self.context, &mut desc, 0, &mut qop) };
        match ret as u32 {
            SEC_E_OK => {
                // Copy decrypted plaintext out before we touch enc_buf (the
                // DATA pointer aliases enc_buf's storage).
                self.dec_buf.clear();
                if !bufs[1].pvBuffer.is_null() && bufs[1].cbBuffer > 0 {
                    let data = unsafe {
                        std::slice::from_raw_parts(
                            bufs[1].pvBuffer as *const u8,
                            bufs[1].cbBuffer as usize,
                        )
                    };
                    self.dec_buf.extend_from_slice(data);
                }
                self.dec_pos = 0;
                let extra = if bufs[3].BufferType == SECBUFFER_EXTRA {
                    bufs[3].cbBuffer as usize
                } else {
                    0
                };
                let consumed = self.enc_buf.len() - extra;
                if extra > 0 {
                    let leftover: Vec<u8> = self.enc_buf[consumed..].to_vec();
                    self.enc_buf = leftover;
                } else {
                    self.enc_buf.clear();
                }
                Ok(DecryptOutcome::Decrypted)
            }
            SEC_E_INCOMPLETE_MESSAGE => Ok(DecryptOutcome::NeedMore),
            SEC_I_CONTEXT_EXPIRED => Ok(DecryptOutcome::Eof),
            other => Err(io::Error::other(format!(
                "DecryptMessage failed: 0x{other:08X}"
            ))),
        }
    }
}

impl<S> Drop for TlsStream<S> {
    fn drop(&mut self) {
        // Best-effort: do not attempt the close_notify exchange from Drop (the
        // peer may already be gone); just release the SSPI context.
        unsafe {
            let _ = DeleteSecurityContext(&mut self.context);
        }
    }
}

/// Result of one `try_decrypt` attempt.
enum DecryptOutcome {
    /// Plaintext is now available in `dec_buf`.
    Decrypted,
    /// More encrypted bytes are needed before a full record is present.
    NeedMore,
    /// Peer sent `close_notify`; the stream is at EOF.
    Eof,
}

impl<S: Read + Write> Read for TlsStream<S> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        // Serve any buffered plaintext first.
        if self.dec_pos < self.dec_buf.len() {
            let n = out.len().min(self.dec_buf.len() - self.dec_pos);
            out[..n].copy_from_slice(&self.dec_buf[self.dec_pos..self.dec_pos + n]);
            self.dec_pos += n;
            return Ok(n);
        }
        loop {
            if !self.enc_buf.is_empty() {
                match self.try_decrypt()? {
                    DecryptOutcome::Decrypted => {
                        if !self.dec_buf.is_empty() {
                            let n = out.len().min(self.dec_buf.len());
                            out[..n].copy_from_slice(&self.dec_buf[..n]);
                            self.dec_pos = n;
                            return Ok(n);
                        }
                        // Decryption produced no plaintext (e.g. a control
                        // record); loop to decrypt the next record or read more.
                        continue;
                    }
                    DecryptOutcome::Eof => return Ok(0),
                    DecryptOutcome::NeedMore => {}
                }
            }
            // Need more encrypted bytes from the underlying stream. Propagate
            // `WouldBlock`/`TimedOut` so a non-blocking / timed caller (the
            // recon tool's tolerant read loops) can retry on its own cadence.
            let mut scratch = [0u8; STREAM_READ_CHUNK];
            match self.stream.read(&mut scratch) {
                Ok(0) => return Ok(0),
                Ok(n) => self.enc_buf.extend_from_slice(&scratch[..n]),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
    }
}

impl<S: Read + Write> Write for TlsStream<S> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        let max_msg = self.sizes.cbMaximumMessage as usize;
        let n = data.len().min(max_msg);
        self.encrypt_and_send(&data[..n])?;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

/// Queries `SECPKG_ATTR_STREAM_SIZES` for the context, returning the record
/// framing sizes used by `encrypt_and_send`.
fn query_stream_sizes(context: &SecHandle) -> io::Result<SecPkgContext_StreamSizesW> {
    let mut sizes: SecPkgContext_StreamSizesW = SecPkgContext_StreamSizesW {
        cbHeader: 0,
        cbTrailer: 0,
        cbMaximumMessage: 0,
        cBuffers: 0,
        cbBlockSize: 0,
    };
    let ret = unsafe {
        QueryContextAttributesW(
            context as *const SecHandle,
            SECPKG_ATTR_STREAM_SIZES,
            &mut sizes as *mut SecPkgContext_StreamSizesW as *mut c_void,
        )
    };
    if ret as u32 == SEC_E_OK {
        Ok(sizes)
    } else {
        Err(io::Error::other(format!(
            "QueryContextAttributesW(STREAM_SIZES) failed: 0x{:08X}",
            ret as u32
        )))
    }
}
