//! UAC elevation for the SCM-mutating `--install`/`--uninstall` operations only. A non-elevated `--install`/`--uninstall` would fail at `OpenSCManagerW` with `Access is denied (os error 5)` — poor UX for a shortcut-based install. The chosen design is **relaunch-on-demand**, not a blanket `requireAdministrator` manifest: a blanket manifest would prompt for *every* invocation, including the default console path (double-click / bare run) and the SCM's own `--service` launch of the exe, neither of which needs elevation (the service path runs under the SCM, which cannot show a UI). Relaunch-on-demand detects a non-elevated `--install`/`--uninstall` and re-spawns itself via `ShellExecuteW(... "runas" ...)`, which triggers exactly one UAC prompt for exactly those operations.
//!
//! All FFI is raw `advapi32`/`kernel32`/`shell32` matching the existing `service::win` / `tls_schannel` / `cert_gen::win` style — no `windows-sys`/`windows` crates. The non-Windows stubs (`is_elevated` returns `true`, `relaunch_elevated` returns an error) keep the Linux build host and `cargo test` link-free so the cross-platform dispatch tests stay green.

use std::path::Path;

/// Determines whether the current process is running with an elevated (administrator) token. The `--install`/`--uninstall` dispatch arms call this before touching the SCM: when `false`, the caller relaunches itself elevated via `relaunch_elevated` rather than failing at `OpenSCManagerW` with a cryptic access-denied error. On non-Windows there is no token API (and no SCM), so the stub returns `true` — the install/uninstall entry points return `EXIT_WINDOWS_ONLY` regardless, and this keeps the cross-platform dispatch tests link-free.
pub fn is_elevated() -> bool {
    #[cfg(windows)]
    {
        win::is_elevated()
    }
    #[cfg(not(windows))]
    {
        true
    }
}

/// Relaunches the current executable elevated with the single `arg` (`--install` or `--uninstall`) via `ShellExecuteW` with the `"runas"` verb, which triggers exactly one UAC prompt. On success (operator clicked "Yes") the caller exits `EXIT_OK` — the elevated copy does the actual SCM work. On failure (operator declined, or `ShellExecuteW` could not launch) the caller surfaces a clear "elevation declined; run as administrator" message and returns `EXIT_FAILURE`. `exe_path` is the path to relaunch (the caller passes `current_exe()`); on non-Windows the operation does not exist, so a clear "Windows-only" error is returned without touching FFI.
pub fn relaunch_elevated(exe_path: &Path, arg: &str) -> Result<(), std::io::Error> {
    #[cfg(windows)]
    {
        win::relaunch_elevated(exe_path, arg)
    }
    #[cfg(not(windows))]
    {
        let _ = (exe_path, arg);
        Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "UAC elevation is only available on Windows"))
    }
}

/// Encodes `s` as a NUL-terminated UTF-16 wide string, the form Win32 `*W` APIs expect. Mirrors `service::to_wide` so this module is self-contained without a cross-module dependency for a one-line helper; `cfg(any(windows, test))` (the `cert_gen::subject_cn` pattern) keeps it live where the `win` submodule and the tests reach it without a dead-code warning on the Linux build host.
#[cfg(any(windows, test))]
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
mod win {
    #![allow(non_snake_case, non_camel_case_types, non_upper_case_globals, clippy::upper_case_acronyms)]

    use std::ffi::c_void;
    use std::io;
    use std::path::Path;

    use super::to_wide;

    /// Win32 `BOOL`.
    type Bool = i32;

    /// `TOKEN_QUERY` — the only access right needed to call `GetTokenInformation(TokenElevation)`; the minimum-privilege open for an elevation check.
    const TOKEN_QUERY: u32 = 0x0008;

    /// `TokenElevation` value class for `GetTokenInformation`, selecting the `TOKEN_ELEVATION` out-struct (`DWORD` bool) that reports whether the process token has full admin privilege.
    const TokenElevation: u32 = 20;

    /// `GetCurrentProcess` returns a pseudo-handle (-1) for the current process; `OpenProcessToken` accepts it. No `CloseHandle` is needed for a pseudo-handle.
    const CURRENT_PROCESS: isize = -1;

    /// `SW_SHOWNORMAL` — show the elevated process's window normally. The relaunch is a console-style install/uninstall, so a normal window is the expected UX; the elevated copy inherits the operator's console only if UAC preserves the console (it does not — the elevated copy gets a fresh console), which is fine because `--install`/`--uninstall` print to stdout/stderr that the operator reads from the original prompt only on failure of the relaunch itself.
    const SW_SHOWNORMAL: i32 = 1;

    /// `TOKEN_ELEVATION` (winnt.h) — a single `DWORD` (`TokenIsElevated`): nonzero if the token is elevated. `#[repr(C)]` with one `u32` matches the documented single-DWORD layout that `GetTokenInformation(TokenElevation)` fills.
    #[repr(C)]
    #[derive(Default)]
    struct TOKEN_ELEVATION {
        token_is_elevated: u32,
    }

    #[link(name = "advapi32")]
    extern "system" {
        /// `OpenProcessToken` (advapi32) — open the process token for `process` with `desired_access`, returning the handle via `*token`. Returns TRUE on success.
        fn OpenProcessToken(process: isize, desired_access: u32, token: *mut isize) -> Bool;
        /// `GetTokenInformation` (advapi32) — query `token_class` from `token_handle` into `*token_info` (`len` bytes; `*return_len` receives the required size). Returns TRUE on success.
        fn GetTokenInformation(token_handle: isize, token_class: u32, token_info: *mut c_void, len: u32, return_len: *mut u32) -> Bool;
    }

    #[link(name = "kernel32")]
    extern "system" {
        /// `CloseHandle` (kernel32) — release the token handle opened by `OpenProcessToken`. Returns TRUE on success.
        fn CloseHandle(handle: isize) -> Bool;
    }

    #[link(name = "shell32")]
    extern "system" {
        /// `ShellExecuteW` (shell32) — launch `file` with `parameters` using the `verb` (the `"runas"` verb triggers the UAC prompt). Returns an `HINSTANCE` cast to `isize`: a value > 32 means success, ≤ 32 is a failure code (e.g. the operator declined elevation). The window `show` flag controls the launched process's first window.
        fn ShellExecuteW(hwnd: isize, verb: *const u16, file: *const u16, parameters: *const u16, directory: *const u16, show: i32) -> isize;
    }

    /// Windows implementation of `super::is_elevated`: opens the current process token with `TOKEN_QUERY`, queries `TokenElevation`, and reads the `TOKEN_ELEVATION.token_is_elevated` bool. Any FFI failure is treated as "not elevated" rather than panicking — a failed token query means the SCM install would fail anyway, so falling through to the relaunch path (which then surfaces the elevation prompt or its own failure) is the safe direction.
    pub(super) fn is_elevated() -> bool {
        let mut token: isize = 0;
        // SAFETY: `CURRENT_PROCESS` is the documented pseudo-handle for the calling process; `TOKEN_QUERY` is a valid access right; `token` is an out-param. The handle is closed below on success.
        if unsafe { OpenProcessToken(CURRENT_PROCESS, TOKEN_QUERY, &mut token) } == 0 {
            return false;
        }
        let mut elev = TOKEN_ELEVATION::default();
        let mut return_len: u32 = 0;
        // SAFETY: `token` is a valid token handle from `OpenProcessToken`; `TokenElevation` selects the `TOKEN_ELEVATION` class; `elev` is a `repr(C)` single-DWORD struct matching the expected out-size; `return_len` is an out-param.
        let ok = unsafe { GetTokenInformation(token, TokenElevation, &mut elev as *mut _ as *mut c_void, std::mem::size_of::<TOKEN_ELEVATION>() as u32, &mut return_len) };
        // SAFETY: `token` is a valid handle opened above; close it regardless of the query result.
        unsafe {
            let _ = CloseHandle(token);
        }
        ok != 0 && elev.token_is_elevated != 0
    }

    /// Windows implementation of `super::relaunch_elevated`: invokes `ShellExecuteW(NULL, "runas", <exe wide>, <arg wide>, NULL, SW_SHOWNORMAL)`. A return value > 32 means the elevated process was launched (the UAC prompt was accepted); ≤ 32 is a failure (the operator declined, or the launch could not start), mapped to an `io::Error` via `last_os_error` when available. The elevated copy runs the same `app::parse_dispatch` path with the single `arg`, so it performs the actual SCM work.
    pub(super) fn relaunch_elevated(exe_path: &Path, arg: &str) -> io::Result<()> {
        let verb = to_wide("runas");
        let file = to_wide(&exe_path.to_string_lossy());
        let params = to_wide(arg);
        // SAFETY: a NULL hwnd is the documented "no owner window" value; `verb`/`file`/`params` are NUL-terminated wide strings; a NULL directory inherits the caller's current directory; `SW_SHOWNORMAL` is the documented normal-show flag.
        let hinst = unsafe { ShellExecuteW(0, verb.as_ptr(), file.as_ptr(), params.as_ptr(), std::ptr::null(), SW_SHOWNORMAL) };
        if hinst > 32 {
            Ok(())
        } else {
            // `ShellExecuteW` returns a small error code (≤ 32) rather than setting `GetLastError` in the usual way, but `last_os_error` is still the best available message for the rare cases where the launch fails for an OS reason; for the common "operator declined" case the return code itself is the signal, so the message names that explicitly.
            Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("elevation declined or launch failed (ShellExecuteW returned {hinst}); run as administrator")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(windows))]
    #[test]
    fn non_windows_is_elevated_stub_returns_true() {
        assert!(is_elevated(), "non-Windows stub must report elevated so dispatch tests are unaffected");
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_relaunch_stub_returns_windows_only_error() {
        let err = relaunch_elevated(Path::new("/nonexistent/flvproxy.exe"), "--install").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("Windows"), "stub message must explain it is Windows-only: {err}");
    }

    #[test]
    fn to_wide_ascii_appends_nul() {
        assert_eq!(to_wide("runas"), vec![b'r' as u16, b'u' as u16, b'n' as u16, b'a' as u16, b's' as u16, 0]);
    }

    #[test]
    fn to_wide_empty_is_just_nul() {
        assert_eq!(to_wide(""), vec![0]);
    }
}
