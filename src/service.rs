//! Windows Service Control Manager lifecycle. The SCM FFI, `service_main`/`handler` callbacks, and `install`/`uninstall` are `#[cfg(windows)]` (in the `win` submodule) and use direct FFI to `advapi32`/`kernel32` — no `windows-service`/`windows-sys` crates. On non-Windows targets the public entry fns return `EXIT_WINDOWS_ONLY` without touching FFI, so the Linux build host and `cargo test` stay link-free. The cross-platform `to_wide` UTF-16 helper is top-level so its tests run in CI.

/// SCM service name (the `lpServiceName` passed to `CreateServiceW` and matched by `OpenServiceW`). Short and stable so operators can `sc start flvproxy` / `sc stop flvproxy` without quoting. Referenced by both the Windows FFI paths and the non-Windows stub messages, so it is top-level and cross-platform.
pub const SERVICE_NAME: &str = "flvproxy";

/// Encodes `s` as a NUL-terminated UTF-16 wide string, the form Win32 `*W` APIs expect. Cross-platform so its tests run in CI; the Windows-only FFI paths call it to build service/bin/display names.
pub fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Runs the proxy under the Windows Service Control Manager: registers the control handler, reports start-pending, bootstraps and spawns the app body (`App::bootstrap` + `App::spawn`), reports running, blocks on the SCM stop event, then winds the servers down and reports stopped. Returns the process exit code. On non-Windows the SCM FFI does not exist, so this returns `EXIT_WINDOWS_ONLY` without touching FFI.
pub fn run_as_service() -> i32 {
    #[cfg(windows)]
    {
        win::run_as_service()
    }
    #[cfg(not(windows))]
    {
        eprintln!("flvproxy: service mode ('{SERVICE_NAME}') is only available on Windows");
        crate::app::EXIT_WINDOWS_ONLY
    }
}

/// Registers the service with the SCM (`OpenSCManagerW` → `CreateServiceW`, demand-start, `LocalSystem`). Returns `EXIT_OK` on success, `EXIT_FAILURE` on an FFI failure, or `EXIT_WINDOWS_ONLY` on non-Windows.
pub fn install() -> i32 {
    #[cfg(windows)]
    {
        win::install()
    }
    #[cfg(not(windows))]
    {
        eprintln!("flvproxy: --install ('{SERVICE_NAME}') is only available on Windows");
        crate::app::EXIT_WINDOWS_ONLY
    }
}

/// Stops the service if running (polling until `SERVICE_STOPPED`) then deletes it (`OpenServiceW` → `ControlService(STOP)` → `DeleteService`). Returns `EXIT_OK` on success, `EXIT_FAILURE` on an FFI failure, or `EXIT_WINDOWS_ONLY` on non-Windows.
pub fn uninstall() -> i32 {
    #[cfg(windows)]
    {
        win::uninstall()
    }
    #[cfg(not(windows))]
    {
        eprintln!("flvproxy: --uninstall ('{SERVICE_NAME}') is only available on Windows");
        crate::app::EXIT_WINDOWS_ONLY
    }
}
#[cfg(windows)]
mod win {
    use std::ffi::c_void;
    use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
    use std::sync::OnceLock;
    use std::time::{Duration, Instant};

    use crate::app::{App, EXIT_FAILURE, EXIT_OK};
    use crate::logging::Level;

    use super::SERVICE_NAME;

    /// Human-readable display name shown in `services.msc`.
    const SERVICE_DISPLAY_NAME: &str = "UniFi FLV Proxy";

    /// Longer description shown beneath the display name in `services.msc`, set via `ChangeServiceConfig2W(SERVICE_CONFIG_DESCRIPTION)`.
    const SERVICE_DESCRIPTION: &str = "UniFi Camera FLV-to-RTSP/ONVIF proxy";

    /// Relaxed ordering suffices for the SCM-shared handles and state: they are advisory control-plane values, not synchronization that establishes happens-before for the spawned servers (each server's own state mutex carries that burden).
    const RELAXED: Ordering = Ordering::Relaxed;

    /// `service_specific_exit_code` reported with `SERVICE_STOPPED` when `App::bootstrap` fails under SCM (cert unreadable / logger unopenable). Arbitrary app-defined value; the SCM surfaces it via `sc query`'s service-specific code field.
    const SERVICE_SPECIFIC_BOOTSTRAP: u32 = 1;

    /// `check_point` reported with `SERVICE_START_PENDING` so the SCM sees progress during the (fast) bootstrap. The check point must change between pending reports; a single start-pending report uses this fixed value.
    const START_PENDING_CHECKPOINT: u32 = 1;

    /// `check_point` reported with `SERVICE_STOP_PENDING` while the spawned servers wind down.
    const STOP_PENDING_CHECKPOINT: u32 = 2;

    /// `wait_hint` (ms) reported with `SERVICE_START_PENDING` — the SCM will not mark the service failed before this elapses without further status updates. ~3s covers config/logger/cert load on a cold disk.
    const START_PENDING_WAIT_HINT_MS: u32 = 3000;

    /// `wait_hint` (ms) reported with `SERVICE_STOP_PENDING` — bounds how long the SCM waits before forcing the process to stop. ~5s matches the step-27 human-test "stops cleanly within ~5s" pass criterion; the accept loops poll every ~50ms so they exit well inside it.
    const STOP_PENDING_WAIT_HINT_MS: u32 = 5000;

    /// Poll interval (ms) when waiting for the service to reach `SERVICE_STOPPED` during `uninstall`, so `DeleteService` does not race a still-running service (`ERROR_SERVICE_MARKED_FOR_DELETE`).
    const STOP_POLL_MS: u64 = 100;

    /// Upper bound (ms) for the uninstall stop-wait. Generous relative to the service's own `STOP_PENDING_WAIT_HINT_MS` so a healthy service always stops inside it.
    const STOP_WAIT_MAX_MS: u64 = 6000;

    /// Win32 `HANDLE` / `SC_HANDLE` / `SERVICE_STATUS_HANDLE` are all opaque pointer types; `isize` matches the `extern "system"` ABI on x86_64.
    type Handle = isize;

    /// Win32 `BOOL`.
    type Bool = i32;

    const TRUE: Bool = 1;
    const FALSE: Bool = 0;

    /// `INFINITE` — wait without a timeout.
    const INFINITE: u32 = 0xFFFF_FFFF;

    /// `SC_MANAGER_CONNECT` (connect to the SCM) — the minimum access `OpenSCManagerW` needs for `OpenServiceW`/`DeleteService`.
    const SC_MANAGER_CONNECT: u32 = 0x0001;

    /// `SC_MANAGER_CREATE_SERVICE` — required by `CreateServiceW`.
    const SC_MANAGER_CREATE_SERVICE: u32 = 0x0002;

    /// `SERVICE_ALL_ACCESS` — full access to the service handle for `CreateServiceW`.
    const SERVICE_ALL_ACCESS: u32 = 0xF01FF;

    /// `SERVICE_WIN32_OWN_PROCESS` — the service runs in its own process (not shared).
    const SERVICE_WIN32_OWN_PROCESS: u32 = 0x00000010;

    /// `SERVICE_DEMAND_START` — the service is started on demand by `sc start` / `StartService`, not auto-started at boot. A streaming proxy should not start before the network stack / camera is up; demand-start lets the operator control timing.
    const SERVICE_DEMAND_START: u32 = 0x00000003;

    /// `SERVICE_ERROR_NORMAL` — the SCM logs errors and continues (no system boot impact).
    const SERVICE_ERROR_NORMAL: u32 = 0x00000001;

    /// `DELETE` access right — required by `DeleteService`.
    const DELETE: u32 = 0x0001_0000;

    /// `SERVICE_STOP` access right — required to send `SERVICE_CONTROL_STOP` via `ControlService`.
    const SERVICE_STOP: u32 = 0x0020;

    /// `SERVICE_QUERY_STATUS` access right — paired with stop so the uninstall poll can observe `SERVICE_STOPPED`.
    const SERVICE_QUERY_STATUS: u32 = 0x0004;

    const SERVICE_CONTROL_STOP: u32 = 0x00000001;
    const SERVICE_CONTROL_INTERROGATE: u32 = 0x00000004;
    const SERVICE_ACCEPT_STOP: u32 = 0x00000001;
    const SERVICE_STOPPED: u32 = 0x00000001;
    const SERVICE_START_PENDING: u32 = 0x00000002;
    const SERVICE_STOP_PENDING: u32 = 0x00000003;
    const SERVICE_RUNNING: u32 = 0x00000004;

    /// `ERROR_SUCCESS`.
    const ERROR_SUCCESS: u32 = 0;

    /// `ERROR_SERVICE_SPECIFIC_ERROR` (1066) — set as `win32_exit_code` so the SCM reports the `service_specific_exit_code` field.
    const ERROR_SERVICE_SPECIFIC_ERROR: u32 = 1066;

    /// `ERROR_SERVICE_NOT_ACTIVE` (1062) — `ControlService(STOP)` returns this when the service is not running, which `uninstall` treats as "already stopped, proceed to delete".
    const ERROR_SERVICE_NOT_ACTIVE: u32 = 1062;

    /// `SERVICE_CONFIG_DESCRIPTION` info level for `ChangeServiceConfig2W` (sets the `services.msc` description).
    const SERVICE_CONFIG_DESCRIPTION: u32 = 0x00000003;

    #[repr(C)]
    struct ServiceTableEntryW {
        name: *const u16,
        service_main: Option<unsafe extern "system" fn(u32, *mut *mut u16)>,
    }

    #[repr(C)]
    #[derive(Default)]
    struct ServiceStatus {
        service_type: u32,
        current_state: u32,
        controls_accepted: u32,
        win32_exit_code: u32,
        service_specific_exit_code: u32,
        check_point: u32,
        wait_hint: u32,
    }

    /// Win32 `SERVICE_DESCRIPTIONW` — a single `LPWSTR` field — passed to `ChangeServiceConfig2W`.
    #[repr(C)]
    struct ServiceDescriptionW {
        description: *const u16,
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn StartServiceCtrlDispatcherW(table: *const ServiceTableEntryW) -> Bool;
        fn RegisterServiceCtrlHandlerExW(name: *const u16, handler: Option<unsafe extern "system" fn(u32, u32, *mut c_void, *mut c_void) -> u32>, context: *mut c_void) -> Handle;
        fn SetServiceStatus(handle: Handle, status: *const ServiceStatus) -> Bool;
        fn OpenSCManagerW(machinename: *const u16, databasename: *const u16, access: u32) -> Handle;
        fn CreateServiceW(scm: Handle, name: *const u16, display: *const u16, access: u32, service_type: u32, start_type: u32, error_control: u32, bin_path: *const u16, load_order_group: *const u16, tag_id: *mut u32, dependencies: *const u16, start_name: *const u16, password: *const u16) -> Handle;
        fn DeleteService(service: Handle) -> Bool;
        fn OpenServiceW(scm: Handle, name: *const u16, access: u32) -> Handle;
        fn CloseServiceHandle(handle: Handle) -> Bool;
        fn ControlService(service: Handle, control: u32, status: *mut ServiceStatus) -> Bool;
        fn ChangeServiceConfig2W(service: Handle, info_level: u32, info: *mut c_void) -> Bool;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateEventW(attrs: *mut c_void, manual_reset: Bool, initial_state: Bool, name: *const u16) -> Handle;
        fn SetEvent(handle: Handle) -> Bool;
        fn WaitForSingleObject(handle: Handle, ms: u32) -> u32;
        fn CloseHandle(handle: Handle) -> Bool;
    }

    static STOP_EVENT: AtomicUsize = AtomicUsize::new(0);
    static STATUS_HANDLE: AtomicUsize = AtomicUsize::new(0);
    static CURRENT_STATE: AtomicU32 = AtomicU32::new(0);

    static SERVICE_NAME_WIDE: OnceLock<Vec<u16>> = OnceLock::new();

    /// The NUL-terminated UTF-16 service name, initialized once and reused by `run_as_service`/`install`/`uninstall`. `OnceLock` is required because `super::to_wide` is not `const`.
    fn service_name_wide() -> &'static [u16] {
        SERVICE_NAME_WIDE.get_or_init(|| super::to_wide(SERVICE_NAME)).as_slice()
    }

    fn report_status(handle: Handle, state: u32, controls: u32, checkpoint: u32, wait_hint: u32) -> bool {
        CURRENT_STATE.store(state, RELAXED);
        let status = ServiceStatus { service_type: SERVICE_WIN32_OWN_PROCESS, current_state: state, controls_accepted: controls, win32_exit_code: ERROR_SUCCESS, service_specific_exit_code: 0, check_point: checkpoint, wait_hint };
        // SAFETY: `handle` is a valid `SERVICE_STATUS_HANDLE` obtained from `RegisterServiceCtrlHandlerExW`; `status` is fully initialized and `repr(C)` matching the Win32 `SERVICE_STATUS` layout.
        unsafe { SetServiceStatus(handle, &status) != 0 }
    }

    fn report_stopped_error(handle: Handle, specific: u32) -> bool {
        CURRENT_STATE.store(SERVICE_STOPPED, RELAXED);
        let status = ServiceStatus { service_type: SERVICE_WIN32_OWN_PROCESS, current_state: SERVICE_STOPPED, controls_accepted: 0, win32_exit_code: ERROR_SERVICE_SPECIFIC_ERROR, service_specific_exit_code: specific, check_point: 0, wait_hint: 0 };
        // SAFETY: as above; `handle` is a valid status handle, `status` fully initialized.
        unsafe { SetServiceStatus(handle, &status) != 0 }
    }

    unsafe extern "system" fn handler(ctrl: u32, _event_type: u32, _event_data: *mut c_void, _context: *mut c_void) -> u32 {
        match ctrl {
            SERVICE_CONTROL_STOP => {
                let raw = STOP_EVENT.load(RELAXED);
                if raw != 0 {
                    // SAFETY: `raw` was stored from a valid `CreateEventW` handle in `service_main`; the event outlives the handler (it is closed only after `WaitForSingleObject` returns).
                    SetEvent(raw as Handle);
                }
                ERROR_SUCCESS
            }
            SERVICE_CONTROL_INTERROGATE => {
                let raw = STATUS_HANDLE.load(RELAXED);
                if raw != 0 {
                    let state = CURRENT_STATE.load(RELAXED);
                    let controls = if state == SERVICE_RUNNING { SERVICE_ACCEPT_STOP } else { 0 };
                    let _ = report_status(raw as Handle, state, controls, 0, 0);
                }
                ERROR_SUCCESS
            }
            _ => ERROR_SUCCESS,
        }
    }

    unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
        let raw_handle = RegisterServiceCtrlHandlerExW(service_name_wide().as_ptr(), Some(handler), std::ptr::null_mut());
        if raw_handle == 0 {
            // Without a status handle the SCM cannot be told anything; it will time out the start. Nothing else can be done.
            return;
        }
        STATUS_HANDLE.store(raw_handle as usize, RELAXED);

        let stop_event = CreateEventW(std::ptr::null_mut(), TRUE, FALSE, std::ptr::null());
        if stop_event == 0 {
            let _ = report_stopped_error(raw_handle, SERVICE_SPECIFIC_BOOTSTRAP);
            return;
        }
        STOP_EVENT.store(stop_event as usize, RELAXED);

        if !report_status(raw_handle, SERVICE_START_PENDING, 0, START_PENDING_CHECKPOINT, START_PENDING_WAIT_HINT_MS) {
            STOP_EVENT.store(0, RELAXED);
            // SAFETY: `stop_event` is a valid event handle just created by `CreateEventW` and not yet closed.
            let _ = CloseHandle(stop_event);
            let _ = report_status(raw_handle, SERVICE_STOPPED, 0, 0, 0);
            return;
        }

        let app = match App::bootstrap(false) {
            Ok(a) => a,
            Err(_) => {
                // `App::bootstrap` logs cert failures through the logger it opened before returning; a logger-open failure has no channel (the SCM-specific exit code is the only signal in that rare case), so the error value is intentionally discarded here.
                let _ = report_stopped_error(raw_handle, SERVICE_SPECIFIC_BOOTSTRAP);
                STOP_EVENT.store(0, RELAXED);
                // SAFETY: as above.
                let _ = CloseHandle(stop_event);
                return;
            }
        };
        let logger = app.logger().clone();
        let stops = app.spawn();
        logger.log(Level::Info, "service: started");

        if !report_status(raw_handle, SERVICE_RUNNING, SERVICE_ACCEPT_STOP, 0, 0) {
            logger.log(Level::Error, "service: SetServiceStatus(RUNNING) failed; shutting down");
            stops.shutdown();
            let _ = report_status(raw_handle, SERVICE_STOPPED, 0, 0, 0);
            STOP_EVENT.store(0, RELAXED);
            // SAFETY: as above.
            let _ = CloseHandle(stop_event);
            return;
        }

        // SAFETY: `stop_event` is a valid manual-reset event; `INFINITE` blocks until `SetEvent` is called from `handler` on `SERVICE_CONTROL_STOP`.
        WaitForSingleObject(stop_event, INFINITE);

        logger.log(Level::Info, "service: stop received; shutting down");
        let _ = report_status(raw_handle, SERVICE_STOP_PENDING, 0, STOP_PENDING_CHECKPOINT, STOP_PENDING_WAIT_HINT_MS);
        stops.shutdown();
        logger.log(Level::Info, "service: stopped");
        let _ = report_status(raw_handle, SERVICE_STOPPED, 0, 0, 0);
        STOP_EVENT.store(0, RELAXED);
        // SAFETY: as above; the event is no longer referenced after this.
        let _ = CloseHandle(stop_event);
    }

    fn current_exe_path_string() -> Option<String> {
        std::env::current_exe().ok().and_then(|p| p.to_str().map(std::string::ToString::to_string))
    }

    fn wait_for_stopped(svc: Handle) {
        let deadline = Instant::now() + Duration::from_millis(STOP_WAIT_MAX_MS);
        while Instant::now() < deadline {
            let mut status = ServiceStatus::default();
            // SAFETY: `svc` is a valid service handle from `OpenServiceW` with `SERVICE_QUERY_STATUS`; `ControlService` with `INTERROGATE` only fills `status` and does not change service state.
            let interrogated = unsafe { ControlService(svc, SERVICE_CONTROL_INTERROGATE, &mut status) };
            if interrogated != 0 && status.current_state == SERVICE_STOPPED {
                return;
            }
            std::thread::sleep(Duration::from_millis(STOP_POLL_MS));
        }
    }

    /// Windows implementation of `super::run_as_service`.
    pub(super) fn run_as_service() -> i32 {
        let table = [ServiceTableEntryW { name: service_name_wide().as_ptr(), service_main: Some(service_main) }, ServiceTableEntryW { name: std::ptr::null(), service_main: None }];
        // SAFETY: `table` is a two-element array terminated by the SCM-required sentinel (null name + null fn); the dispatcher reads it for the duration of the call and invokes `service_main` on the SCM thread. `service_main` is `unsafe extern "system" fn` matching `LPSERVICE_MAIN_FUNCTIONW`.
        let rc = unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) };
        if rc != 0 {
            EXIT_OK
        } else {
            let err = std::io::Error::last_os_error();
            eprintln!("flvproxy: not running under the service control manager (StartServiceCtrlDispatcher failed): {err}");
            eprintln!("flvproxy: use --console for foreground, or --install then `sc start {SERVICE_NAME}`");
            EXIT_FAILURE
        }
    }

    /// Windows implementation of `super::install`.
    pub(super) fn install() -> i32 {
        // SAFETY: null machine/db names connect to the local SCM; `SC_MANAGER_CREATE_SERVICE` is the documented access for `CreateServiceW`.
        let scm = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CREATE_SERVICE) };
        if scm == 0 {
            eprintln!("flvproxy: OpenSCManager failed: {}", std::io::Error::last_os_error());
            return EXIT_FAILURE;
        }
        let bin_path = match current_exe_path_string() {
            Some(s) => s,
            None => {
                eprintln!("flvproxy: cannot resolve current exe path");
                // SAFETY: `scm` is a valid SC handle just opened.
                unsafe {
                    let _ = CloseServiceHandle(scm);
                }
                return EXIT_FAILURE;
            }
        };
        // `bin_path` carries no arguments: the SCM launches the service with no args, and `app::parse_dispatch` routes no-arg to `Service` (i.e. `run_as_service`). A dedicated `--run` flag is therefore unnecessary.
        let bin_wide = super::to_wide(&bin_path);
        let display_wide = super::to_wide(SERVICE_DISPLAY_NAME);
        // `start_name = null` selects `LocalSystem` (the SCM default). `LocalSystem` is used over `LocalService` because the logger writes `flvproxy.log` beside the exe, which is typically in a directory `LocalService` cannot write to (e.g. under `Program Files`). See `DEBT.md` for the trigger to revisit once the log path moves to a `LocalService`-writable location.
        let svc = unsafe { CreateServiceW(scm, service_name_wide().as_ptr(), display_wide.as_ptr(), SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, bin_wide.as_ptr(), std::ptr::null(), std::ptr::null_mut(), std::ptr::null(), std::ptr::null(), std::ptr::null()) };
        if svc == 0 {
            let err = std::io::Error::last_os_error();
            eprintln!("flvproxy: CreateService failed: {err}");
            // SAFETY: `scm` is a valid SC handle.
            unsafe {
                let _ = CloseServiceHandle(scm);
            }
            return EXIT_FAILURE;
        }
        let desc_wide = super::to_wide(SERVICE_DESCRIPTION);
        let mut desc = ServiceDescriptionW { description: desc_wide.as_ptr() };
        // SAFETY: `svc` is a valid service handle from `CreateServiceW`; `SERVICE_CONFIG_DESCRIPTION` is the documented info level; `desc` points to a `SERVICE_DESCRIPTIONW` whose `lpDescription` is a valid NUL-terminated wide string. The return is ignored — a failed description set leaves the service registered with no description, not a failure of the install.
        let _ = unsafe { ChangeServiceConfig2W(svc, SERVICE_CONFIG_DESCRIPTION, &mut desc as *mut _ as *mut c_void) };
        // SAFETY: `svc` and `scm` are valid handles.
        unsafe {
            let _ = CloseServiceHandle(svc);
            let _ = CloseServiceHandle(scm);
        }
        println!("flvproxy: service '{SERVICE_NAME}' installed (start with: sc start {SERVICE_NAME})");
        EXIT_OK
    }

    /// Windows implementation of `super::uninstall`.
    pub(super) fn uninstall() -> i32 {
        // SAFETY: null machine/db names connect to the local SCM; `SC_MANAGER_CONNECT` suffices for open/stop/delete.
        let scm = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
        if scm == 0 {
            eprintln!("flvproxy: OpenSCManager failed: {}", std::io::Error::last_os_error());
            return EXIT_FAILURE;
        }
        // SAFETY: `scm` is a valid SC handle; `DELETE | SERVICE_STOP | SERVICE_QUERY_STATUS` covers stop-then-delete.
        let svc = unsafe { OpenServiceW(scm, service_name_wide().as_ptr(), DELETE | SERVICE_STOP | SERVICE_QUERY_STATUS) };
        if svc == 0 {
            let err = std::io::Error::last_os_error();
            eprintln!("flvproxy: OpenService failed (is the service installed?): {err}");
            // SAFETY: `scm` is a valid SC handle.
            unsafe {
                let _ = CloseServiceHandle(scm);
            }
            return EXIT_FAILURE;
        }
        let mut status = ServiceStatus::default();
        // SAFETY: `svc` is a valid service handle with `SERVICE_STOP`; `ControlService(STOP)` signals the handler and fills `status`.
        let stop_rc = unsafe { ControlService(svc, SERVICE_CONTROL_STOP, &mut status) };
        if stop_rc != 0 {
            wait_for_stopped(svc);
        } else {
            // `ERROR_SERVICE_NOT_ACTIVE` means it was already stopped — proceed to delete. Any other failure is reported on stderr but the delete is still attempted so a half-stopped service is removed.
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(ERROR_SERVICE_NOT_ACTIVE as i32) {
                eprintln!("flvproxy: ControlService(STOP) failed: {err}");
            }
        }
        // SAFETY: `svc` is a valid service handle with `DELETE`.
        let deleted = unsafe { DeleteService(svc) };
        // SAFETY: `svc` and `scm` are valid handles.
        unsafe {
            let _ = CloseServiceHandle(svc);
            let _ = CloseServiceHandle(scm);
        }
        if deleted != 0 {
            println!("flvproxy: service '{SERVICE_NAME}' uninstalled");
            EXIT_OK
        } else {
            eprintln!("flvproxy: DeleteService failed: {}", std::io::Error::last_os_error());
            EXIT_FAILURE
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn service_name_wide_is_nul_terminated_and_matches_name() {
            let wide = service_name_wide();
            assert_eq!(*wide.last().unwrap(), 0, "service name must be NUL-terminated");
            let without_nul = &wide[..wide.len() - 1];
            assert_eq!(String::from_utf16_lossy(without_nul), SERVICE_NAME);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_wide_ascii_appends_nul() {
        assert_eq!(to_wide("abc"), vec![b'a' as u16, b'b' as u16, b'c' as u16, 0]);
    }

    #[test]
    fn to_wide_empty_is_just_nul() {
        assert_eq!(to_wide(""), vec![0]);
    }

    #[test]
    fn to_wide_non_ascii_round_trips() {
        let s = "héllo€";
        let wide = to_wide(s);
        assert_eq!(*wide.last().unwrap(), 0, "must be NUL-terminated");
        let without_nul = &wide[..wide.len() - 1];
        assert_eq!(String::from_utf16_lossy(without_nul), s, "round-trip must preserve non-ASCII");
    }

    #[test]
    fn service_name_is_flvproxy() {
        assert_eq!(SERVICE_NAME, "flvproxy");
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_entry_fns_return_windows_only_without_ffi() {
        assert_eq!(run_as_service(), crate::app::EXIT_WINDOWS_ONLY);
        assert_eq!(install(), crate::app::EXIT_WINDOWS_ONLY);
        assert_eq!(uninstall(), crate::app::EXIT_WINDOWS_ONLY);
    }
}
