//! Throwaway, Windows-only **listen-only** recon capture tool (build-plan
//! step 16). It exists to confirm, against a *real* UniFi Protect camera,
//! the exact first bytes the camera sends on the 7442 AVClient WebSocket and
//! whether the HTTPS adoption endpoint on 443 is required first — ground
//! truth that steps 17–19 (full WebSocket framing, the 7442 AVClient JSON
//! protocol, and the 7550 uPFLV ingestion) implement against, instead of
//! redalert's second-hand reverse-engineering description.
//!
//! What it does:
//! 1. Loads a self-signed PFX (generated offline — see "Cert generation"
//!    below) beside the exe.
//! 2. Binds `0.0.0.0:7442`, accepts a TLS (SChannel) connection, completes a
//!    best-effort RFC 6455 WebSocket upgrade, and hex-dumps every inbound
//!    frame to stdout **and** to `protect_recon_7442.log` beside the exe.
//! 3. Optionally does the same on 7550 when `--enable-7550` is passed.
//!
//! What it deliberately does **not** do:
//! - It never dials the camera (operator-trust constraint: capture tools must
//!   not reach into the camera).
//! - It does not implement the full AVClient protocol (the AVClient step) or
//!   production WebSocket framing (the WebSocket framing step) — only enough
//!   WS to capture frames.
//!
//! ## Cert generation
//!
//! Do NOT add a cert-generation crate. Generate a self-signed PFX on the
//! build/host with openssl and ship it beside `protect_recon.exe`:
//!
//! ```text
//! openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
//!   -keyout protect_recon_key.pem -out protect_recon_cert.pem \
//!   -subj "/CN=protect-recon" \
//!   -addext "subjectAltName=DNS:protect-recon,DNS:localhost"
//! openssl pkcs12 -export -in protect_recon_cert.pem \
//!   -inkey protect_recon_key.pem -out protect_recon_cert.pfx \
//!   -passout pass:recon
//! ```
//!
//! Then run `protect_recon.exe --password recon` (the default cert path is
//! `protect_recon_cert.pfx` beside the exe; override with `--cert <path>`).
//!
//! ## Validation
//!
//! This step has **no automated tests** (a throwaway Windows-only capture
//! tool against real hardware). It "passes" when the operator has run it,
//! pointed the camera at it, and pasted back the capture. See
//! `plan/16-protect-recon.md` → "Validation — 🛑 STOP AND HUMAN CAPTURE".

// The entire capture tool is Windows-only (SChannel TLS via the hand-rolled
// `flvproxy::tls_schannel` module from step 17). On every other target the
// binary is a stub that refuses to run, so Linux `cargo build` and `cargo
// test` stay green — the tree is fully zero-crates, with no `cfg`-gated
// dependencies on any target.

#[cfg(not(windows))]
fn main() {
    eprintln!(
        "protect_recon is a Windows-only throwaway capture tool; \
         build with --target x86_64-pc-windows-gnu"
    );
    std::process::exit(1);
}

// The implementation lives in `src/protect_recon_impl.rs` (outside `src/bin/`)
// so cargo's binary auto-discovery does not also try to build it as a
// standalone `recon` crate on Linux, where the `tls_schannel` module it
// depends on is absent. It is only pulled in here, under the `cfg(windows)`
// gate.
#[cfg(windows)]
#[path = "../protect_recon_impl.rs"]
mod recon;

#[cfg(windows)]
fn main() {
    std::process::exit(recon::run());
}
