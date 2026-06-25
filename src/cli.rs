//! Command-line dispatch: maps the first command-line argument to the entry path the binary should run, and defines the process exit codes shared by the console entry point (`main.rs`), the Windows Service entry point (`service`), and the install/uninstall elevation wrapper (`elevate`). Separating the decision from the execution lets the dispatcher be unit-tested on Linux without spawning servers or touching Windows FFI.

/// Process exit code returned for every successful entry-path run (the console path completes, the service dispatcher returns, `--install`/`--uninstall` succeed). Mirrors `EXIT_SUCCESS` from `<stdlib.h>`.
pub const EXIT_OK: i32 = 0;

/// Process exit code returned for a generic entry-path failure (unknown argument, FFI call failed, bootstrap error in the console path). Mirrors `EXIT_FAILURE` from `<stdlib.h>`.
pub const EXIT_FAILURE: i32 = 1;

/// Process exit code returned when `service::run_as_service` / `install` / `uninstall` is invoked on a non-Windows target. Distinct from `EXIT_FAILURE` so a caller (or CI) can tell "wrong platform" apart from "the operation ran and failed" — the SCM/install/uninstall FFI does not exist on Linux, so the branch must not attempt any of it.
pub const EXIT_WINDOWS_ONLY: i32 = 2;

/// Which entry path `main` should run, decided purely from the first command-line argument. Separating the decision from the execution lets the dispatcher be unit-tested on Linux without spawning servers or touching Windows FFI.
#[derive(Debug, Eq, PartialEq)]
pub enum Dispatch {
    /// No argument (or a bare invocation): run the camera/RTSP/ONVIF servers in the foreground, blocking on Ctrl+C. This is the default so double-clicking the exe or running it bare runs the proxy and surfaces the `--install` hint; the SCM-launched service path uses the explicit `--service` flag instead.
    Console,
    /// `--service`: the process was launched by the SCM (or an operator reproducing that). Runs under the service control dispatcher.
    Service,
    /// `--install`: register the service with the SCM.
    Install,
    /// `--uninstall`: stop (if running) and delete the service.
    Uninstall,
    /// An unrecognized argument; the caller prints usage and returns `EXIT_FAILURE`.
    Unknown(String),
}

/// Maps the command-line arguments to the entry path. No argument selects `Console` (the default foreground path — double-clicking the exe or running it bare runs the proxy and prints the `--install` hint); `--service` is the SCM-launched service path, wired into the service's registered bin path so the SCM passes it; `--install`/`--uninstall` manage the SCM registration. Anything else is an error.
pub fn parse_dispatch(args: &[String]) -> Dispatch {
    match args.first().map(String::as_str) {
        None => Dispatch::Console,
        Some("--service") => Dispatch::Service,
        Some("--install") => Dispatch::Install,
        Some("--uninstall") => Dispatch::Uninstall,
        Some(other) => Dispatch::Unknown(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(x: &str) -> String {
        x.to_string()
    }

    #[test]
    fn parse_dispatch_no_args_selects_console() {
        assert_eq!(parse_dispatch(&[]), Dispatch::Console);
    }

    #[test]
    fn parse_dispatch_service_flag_selects_service() {
        assert_eq!(parse_dispatch(&[s("--service")]), Dispatch::Service);
    }

    #[test]
    fn parse_dispatch_install_flag_selects_install() {
        assert_eq!(parse_dispatch(&[s("--install")]), Dispatch::Install);
    }

    #[test]
    fn parse_dispatch_uninstall_flag_selects_uninstall() {
        assert_eq!(parse_dispatch(&[s("--uninstall")]), Dispatch::Uninstall);
    }

    #[test]
    fn parse_dispatch_unknown_flag_is_unknown() {
        assert_eq!(parse_dispatch(&[s("--frobnicate")]), Dispatch::Unknown("--frobnicate".to_string()));
    }

    #[test]
    fn parse_dispatch_ignores_extra_args_beyond_first() {
        // Only the first argument selects the dispatch branch; trailing args (e.g. a stray second token) are ignored by the dispatcher. The executor receives no arguments beyond the branch choice.
        assert_eq!(parse_dispatch(&[s("--service"), s("noise")]), Dispatch::Service);
    }
}
