//! Library crate exposing the proxy's logic modules for cross-platform unit
//! and integration testing. The binary entry point lives in `src/main.rs`
//! and consumes these modules via the `flvproxy` crate name.
//!
//! All networking uses `std::net` (cross-platform); only `service` is
//! `#[cfg(windows)]`-gated. Logic modules compile and test on Linux so
//! `cargo test` runs without a Windows host.

pub mod amf;
pub mod avc;
pub mod config;
pub mod flv_parser;
pub mod logging;
pub mod onvif_discovery;
pub mod onvif_server;
pub mod rtp;
pub mod rtsp_server;
pub mod sdp;
pub mod service;
pub mod stream_state;
