//! Windows Service Control Manager lifecycle. Body is `#[cfg(windows)]`-gated
//! and uses direct FFI to `advapi32`/`kernel32`; on non-Windows targets the
//! module is empty so logic tests compile on Linux.
