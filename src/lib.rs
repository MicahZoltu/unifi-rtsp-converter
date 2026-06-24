//! Library crate exposing the proxy's logic modules for cross-platform unit and integration testing. The binary entry point lives in `src/main.rs` and consumes these modules via the `flvproxy` crate name.
//!
//! All networking uses `std::net` (cross-platform); only `service` is `#[cfg(windows)]`-gated. Logic modules compile and test on Linux so `cargo test` runs without a Windows host.

pub mod amf;
pub mod app;
pub mod avc;
pub mod camera_listener;
pub mod cert_gen;
pub mod config;
pub mod flv_parser;
pub mod logging;
pub mod onvif_discovery;
pub mod onvif_server;
pub mod protect_controller;
// Production Protect-controller 7442 TLS+WSS+AVClient listener (step 21). Windows-only: links the step-17 `tls_schannel` SSPI module. Gated here so the Linux build host and `cargo test` stay zero-crates and link-free; the Linux `console_main` path uses the plain-TCP `CameraListener` directly as the test ingress.
#[cfg(windows)]
pub mod protect_listener;
pub mod rtp;
pub mod rtsp_server;
pub mod sdp;
pub mod service;
pub mod stream_state;
pub mod ws;

// Hand-rolled SChannel SSPI TLS (step 17). Windows-only: links crypt32/secur32 via `extern "system"` and has no meaning on Linux. Gated here so the Linux build host and `cargo test` stay zero-crates and link-free.
#[cfg(windows)]
pub mod tls_schannel;
