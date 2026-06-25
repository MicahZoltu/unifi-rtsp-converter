//! Windows Service Control Manager lifecycle. The SCM FFI, `service_main`/`handler` callbacks, and `install`/`uninstall` are `#[cfg(windows)]` (in the `win` submodule) and use direct FFI to `advapi32`/`kernel32` — no `windows-service`/`windows-sys` crates. On non-Windows targets the public entry fns return `EXIT_WINDOWS_ONLY` without touching FFI, so the Linux build host and `cargo test` stay link-free. The UTF-16 wide-string helpers live in `crate::wide` and are re-exported here so the legacy `flvproxy::service::to_wide` / `flvproxy::service::wide_to_string` paths keep resolving for the `win` submodule and any external caller.

/// SCM service name (the `lpServiceName` passed to `CreateServiceW` and matched by `OpenServiceW`). Short and stable so operators can `sc.exe start flvproxy` / `sc.exe stop flvproxy` without quoting. Referenced by both the Windows FFI paths and the non-Windows stub messages, so it is top-level and cross-platform.
pub const SERVICE_NAME: &str = "flvproxy";

pub use crate::wide::{to_wide, wide_to_string};

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

/// Registers the service with the SCM (`OpenSCManagerW` → `CreateServiceW`, auto-start, `NT SERVICE\flvproxy` virtual account, with an ACL grant on the exe directory) and starts it immediately. Returns `EXIT_OK` on success, `EXIT_FAILURE` on an FFI failure, or `EXIT_WINDOWS_ONLY` on non-Windows.
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
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
    use std::sync::OnceLock;
    use std::time::{Duration, Instant};

    use crate::app::{App, EXIT_FAILURE, EXIT_OK};
    use crate::cert_gen;
    use crate::config::{Config, DEFAULT_CERT_FILE};
    use crate::logging::Level;

    use super::SERVICE_NAME;

    /// Human-readable display name shown in `services.msc`.
    const SERVICE_DISPLAY_NAME: &str = "UniFi FLV Proxy";

    /// Longer description shown beneath the display name in `services.msc`, set via `ChangeServiceConfig2W(SERVICE_CONFIG_DESCRIPTION)`.
    const SERVICE_DESCRIPTION: &str = "UniFi Camera FLV-to-RTSP/ONVIF proxy";

    /// Relaxed ordering suffices for the SCM-shared handles and state: they are advisory control-plane values, not synchronization that establishes happens-before for the spawned servers (each server's own state mutex carries that burden).
    const RELAXED: Ordering = Ordering::Relaxed;

    /// `service_specific_exit_code` reported with `SERVICE_STOPPED` when `App::bootstrap` fails under SCM (cert unreadable / logger unopenable). Arbitrary app-defined value; the SCM surfaces it via `sc.exe query`'s service-specific code field.
    const SERVICE_SPECIFIC_BOOTSTRAP: u32 = 1;

    /// `check_point` reported with `SERVICE_START_PENDING` so the SCM sees progress during the (fast) bootstrap. The check point must change between pending reports; a single start-pending report uses this fixed value.
    const START_PENDING_CHECKPOINT: u32 = 1;

    /// `check_point` reported with `SERVICE_STOP_PENDING` while the spawned servers wind down.
    const STOP_PENDING_CHECKPOINT: u32 = 2;

    /// `wait_hint` (ms) reported with `SERVICE_START_PENDING` — the SCM will not mark the service failed before this elapses without further status updates. ~3s covers config/logger/cert load on a cold disk.
    const START_PENDING_WAIT_HINT_MS: u32 = 3000;

    /// `wait_hint` (ms) reported with `SERVICE_STOP_PENDING` — bounds how long the SCM waits before forcing the process to stop. ~5s matches the real-camera "stops cleanly within ~5s" pass criterion; the accept loops poll every ~50ms so they exit well inside it.
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

    /// `SERVICE_AUTO_START` — the service starts automatically during boot (started by the SCM, not on demand). A streaming proxy is useful only when running, and an operator installing it expects it to be active without a manual `sc.exe start`; auto-start means a reboot or service-restart after install brings the proxy up unattended. The service still stops cleanly on Ctrl+C / `sc.exe stop`, and a fast-fail during `service_main` (e.g. port already bound) reports to the SCM without crashing.
    const SERVICE_AUTO_START: u32 = 0x00000002;

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

    /// `SE_FILE_OBJECT` (the `SE_OBJECT_TYPE` for a file/directory path) — passed to `GetNamedSecurityInfoW`/`SetNamedSecurityInfoW` so they treat `pObjectName` as a filesystem path.
    const SE_FILE_OBJECT: u32 = 1;

    /// `DACL_SECURITY_INFORMATION` — operate on the discretionary ACL (the `*pDacl` parameters of the named-security-info calls), leaving owner/group/SACL untouched.
    const DACL_SECURITY_INFORMATION: u32 = 0x00000004;

    /// `GRANT_ACCESS` (`ACCESS_MODE`) — `SetEntriesInAclW` adds the entry as an access-allowed ACE without clearing the existing ACEs, so the operator's and inherited permissions on the exe dir are preserved.
    const GRANT_ACCESS: u32 = 1;

    /// `TRUSTEE_IS_NAME` (`TRUSTEE_FORM`) — the trustee is identified by an account-name string (`ptstrName`), not a SID; this is what `BuildTrusteeWithNameW` would set, filled by hand to avoid that extra FFI call.
    const TRUSTEE_IS_NAME: u32 = 1;

    /// `CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE` (`INHERIT_FLAGS`) — the ACE applies to the directory itself, its subdirectories (containers), and the files within them (objects), so the service can write the log/PFX anywhere beside the exe.
    const SUB_CONTAINERS_AND_OBJECTS_INHERIT: u32 = 0x3;

    /// `FILE_GENERIC_READ` (winnt.h) = `STANDARD_RIGHTS_READ | FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | SYNCHRONIZE` = 0x120089. Lets the service enumerate the exe directory and read files in it.
    const FILE_GENERIC_READ: u32 = 0x0012_0089;

    /// `FILE_GENERIC_WRITE` (winnt.h) = `STANDARD_RIGHTS_WRITE | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | SYNCHRONIZE` = 0x120116. Lets the service create/overwrite `flvproxy.log` and the lazily-generated PFX beside the exe.
    const FILE_GENERIC_WRITE: u32 = 0x0012_0116;

    /// `FILE_LIST_DIRECTORY` (= `FILE_READ_DATA` for a directory) — explicit list permission; `FILE_GENERIC_READ` already carries it, named explicitly for unambiguity.
    const FILE_LIST_DIRECTORY: u32 = 0x0001;

    /// `FILE_TRAVERSE` (= `FILE_EXECUTE` for a directory) — descend into the directory; not part of `FILE_GENERIC_READ`/`FILE_GENERIC_WRITE`, so granted explicitly so the service can reach files nested under the exe dir.
    const FILE_TRAVERSE: u32 = 0x0020;

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

    /// Win32 `TRUSTEE_W` (accctrl.h) — identifies a trustee (account) for `SetEntriesInAclW`. Filled by hand with `TrusteeForm = TRUSTEE_IS_NAME` and the account name in `ptstrName`, matching what `BuildTrusteeWithNameW` would produce. Field names mirror the Win32 names (PascalCase/camelCase) so they map 1:1 to the documented struct layout.
    #[repr(C)]
    #[derive(Default)]
    #[allow(non_snake_case)]
    struct TRUSTEE_W {
        pMultipleTrustee: *mut TRUSTEE_W,
        MultipleTrusteeOperation: u32,
        TrusteeForm: u32,
        TrusteeType: u32,
        ptstrName: *const u16,
    }

    /// Win32 `EXPLICIT_ACCESS_W` (accctrl.h) — one access-control entry merged into a DACL via `SetEntriesInAclW`. Field declaration order matches the Win32 struct exactly (`grfAccessPermissions`, `grfAccessMode`, `grfInheritance`, `Trustee`) because `#[repr(C)]` lays fields out in declaration order — swapping permissions and access mode puts a permission bitmask where the `ACCESS_MODE` enum belongs and `SetEntriesInAclW` rejects it with `ERROR_INVALID_PARAMETER` (87).
    #[repr(C)]
    #[allow(non_snake_case)]
    struct EXPLICIT_ACCESS_W {
        grfAccessPermissions: u32,
        grfAccessMode: u32,
        grfInheritance: u32,
        Trustee: TRUSTEE_W,
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn StartServiceCtrlDispatcherW(table: *const ServiceTableEntryW) -> Bool;
        fn RegisterServiceCtrlHandlerExW(name: *const u16, handler: Option<unsafe extern "system" fn(u32, u32, *mut c_void, *mut c_void) -> u32>, context: *mut c_void) -> Handle;
        fn SetServiceStatus(handle: Handle, status: *const ServiceStatus) -> Bool;
        fn OpenSCManagerW(machinename: *const u16, databasename: *const u16, access: u32) -> Handle;
        fn CreateServiceW(scm: Handle, name: *const u16, display: *const u16, access: u32, service_type: u32, start_type: u32, error_control: u32, bin_path: *const u16, load_order_group: *const u16, tag_id: *mut u32, dependencies: *const u16, start_name: *const u16, password: *const u16) -> Handle;
        /// `StartServiceW` (winsvc.h) — start a registered service now (the SCM dispatches it through `ServiceMain`). Returns TRUE on success; a failure here (e.g. port 7552 already bound, or the service already running) returns FALSE and `GetLastError` is inspected by the caller.
        fn StartServiceW(service: Handle, argc: u32, argv: *const *const u16) -> Bool;
        fn DeleteService(service: Handle) -> Bool;
        fn OpenServiceW(scm: Handle, name: *const u16, access: u32) -> Handle;
        fn CloseServiceHandle(handle: Handle) -> Bool;
        fn ControlService(service: Handle, control: u32, status: *mut ServiceStatus) -> Bool;
        fn ChangeServiceConfig2W(service: Handle, info_level: u32, info: *mut c_void) -> Bool;
        /// `GetNamedSecurityInfoW` (aclapi.h) — retrieve a security descriptor for a named object. `DACL_SECURITY_INFORMATION` fetches the existing DACL into `*ppDacl` and the full SD into `*ppSecurityDescriptor` (freed with `LocalFree`). Returns `ERROR_SUCCESS` (0) on success.
        fn GetNamedSecurityInfoW(pObjectName: *const u16, ObjectType: u32, SecurityInfo: u32, ppsidOwner: *mut *mut c_void, ppsidGroup: *mut *mut c_void, ppDacl: *mut *mut c_void, ppSacl: *mut *mut c_void, ppSecurityDescriptor: *mut *mut c_void) -> u32;
        /// `SetEntriesInAclW` (aclapi.h) — merge `cCountExplicitEntries` new ACEs into `pOldAcl` (which may be NULL for an object with no DACL), producing a new ACL in `*ppNewAcl` (freed with `LocalFree`). Returns `ERROR_SUCCESS` (0) on success.
        fn SetEntriesInAclW(cCountExplicitEntries: u32, pListOfExplicitEntries: *const EXPLICIT_ACCESS_W, pOldAcl: *mut c_void, ppNewAcl: *mut *mut c_void) -> u32;
        /// `SetNamedSecurityInfoW` (aclapi.h) — write a security descriptor's DACL back to the named object. The ACL is copied, not taken. Returns `ERROR_SUCCESS` (0) on success.
        fn SetNamedSecurityInfoW(pObjectName: *mut u16, ObjectType: u32, SecurityInfo: u32, psidOwner: *mut c_void, psidGroup: *mut c_void, pDacl: *mut c_void, pSacl: *mut c_void) -> u32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateEventW(attrs: *mut c_void, manual_reset: Bool, initial_state: Bool, name: *const u16) -> Handle;
        fn SetEvent(handle: Handle) -> Bool;
        fn WaitForSingleObject(handle: Handle, ms: u32) -> u32;
        fn CloseHandle(handle: Handle) -> Bool;
        /// `LocalFree` (winbase.h) — free memory allocated by `GetNamedSecurityInfoW` (`ppSecurityDescriptor`) and `SetEntriesInAclW` (`ppNewAcl`). Returns NULL on success.
        fn LocalFree(hMem: *mut c_void) -> *mut c_void;
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
        let mut stops = app.spawn();
        logger.log(Level::Info, "service: started");

        if !report_status(raw_handle, SERVICE_RUNNING, SERVICE_ACCEPT_STOP, 0, 0) {
            logger.log(Level::Error, "service: SetServiceStatus(RUNNING) failed; shutting down");
            stops.shutdown();
            stops.join_with_timeout(Duration::from_millis(STOP_PENDING_WAIT_HINT_MS as u64));
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
        stops.join_with_timeout(Duration::from_millis(STOP_PENDING_WAIT_HINT_MS as u64));
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
            eprintln!("flvproxy: run bare (no arguments) for foreground, or `--install` (as administrator) to register and start the service");
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
        // `bin_path` carries `--service`: the SCM launches the registered bin path verbatim, and `app::parse_dispatch` routes `--service` to `Service` (i.e. `run_as_service`). The default (no-arg) console path is no longer the SCM path, so an explicit `--service` arg is required in the registered bin path; this also means double-clicking the exe outside the SCM runs the console path rather than failing `StartServiceCtrlDispatcherW` with error 1063.
        let bin_path_with_arg = format!("{bin_path} --service");
        let bin_wide = super::to_wide(&bin_path_with_arg);
        let display_wide = super::to_wide(SERVICE_DISPLAY_NAME);
        // The exe directory is resolved once and reused for both proactive cert generation and the per-service-SID ACL grant so the service — running as `NT SERVICE\flvproxy` — can write the log/PFX beside the exe.
        let exe_dir = std::env::current_exe().ok().and_then(|p| p.parent().map(PathBuf::from));
        // Proactive self-signed PFX generation: if the cert the service will load is absent, generate it now so the first `sc.exe start` finds a cert without operator action. The cert path is resolved the same way `App::bootstrap` resolves it (honouring a `cert_path` override in `flvproxy.ini`, else `<exe_dir>/flvproxy_cert.pfx`). A generation failure is reported on stderr but does **not** abort the install — the operator may supply their own cert via `cert_path`.
        if let Some(exe_dir) = exe_dir.as_ref() {
            let cfg = Config::load_or_default(&exe_dir.join("flvproxy.ini"));
            let cert_path = cfg.cert_path.as_ref().map(PathBuf::from).unwrap_or_else(|| exe_dir.join(DEFAULT_CERT_FILE));
            if !cert_path.exists() {
                match cert_gen::generate_self_signed_pfx(&cert_path) {
                    Ok(()) => println!("flvproxy: generated self-signed PFX at {}", cert_path.display()),
                    Err(e) => eprintln!("flvproxy: could not auto-generate self-signed PFX at {} ({e}); generate one with openssl, or set cert_path / cert_password in flvproxy.ini", cert_path.display()),
                }
            }
        }
        // Run the service under the `NT SERVICE\flvproxy` per-service virtual account. A virtual account is least-privilege by default (no admin token, no network credential), needs no password (`CreateServiceW` with `password = null` — the SCM grants `SeServiceLogonRight` and creates the account on first start), and is a dedicated per-service SID distinct from the shared `LocalService`, so it can be granted ACLs on exactly the resources this service needs. The exe-dir ACL grant below gives it write access for the log and the lazily-generated PFX.
        let account = format!("NT SERVICE\\{SERVICE_NAME}");
        let account_wide = super::to_wide(&account);
        let svc = unsafe { CreateServiceW(scm, service_name_wide().as_ptr(), display_wide.as_ptr(), SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, bin_wide.as_ptr(), std::ptr::null(), std::ptr::null_mut(), std::ptr::null(), account_wide.as_ptr(), std::ptr::null()) };
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
        // Grant the per-service virtual account read/write/traverse access on the exe directory before starting the service, so its first `service_main` can open `flvproxy.log`. A failure is reported but does not abort the install — the service is already registered, and the operator can fix the dir ACL manually.
        if let Some(exe_dir) = exe_dir.as_ref() {
            grant_exe_dir_write_access(exe_dir, &account_wide);
        }
        // Start the service immediately so `--install` leaves the proxy running (not just registered for the next boot). This pairs with `SERVICE_AUTO_START`: the operator neither reboots nor runs `sc.exe start`. A failure here (e.g. port 7552 already bound, or the cert path is unreadable at runtime) does **not** abort the install — the service is registered with `SERVICE_AUTO_START`, so the operator can fix the runtime issue and reboot/restart; reporting the start failure and returning success is correct.
        // SAFETY: `svc` is a valid service handle from `CreateServiceW`; argc = 0 and argv = NULL pass no override arguments, so the SCM launches the registered bin path (`<exe> --service`) unchanged, which `app::parse_dispatch` routes to the service path.
        if unsafe { StartServiceW(svc, 0, std::ptr::null()) } == 0 {
            let err = std::io::Error::last_os_error();
            // `ERROR_SERVICE_ALREADY_RUNNING` (1056) is benign — the service was already up; report it as info, not an error.
            if err.raw_os_error() == Some(1056) {
                println!("flvproxy: service '{SERVICE_NAME}' already running (registered with auto-start on boot)");
            } else {
                eprintln!("flvproxy: service '{SERVICE_NAME}' registered with auto-start on boot, but could not start it now ({err}); run `sc.exe start {SERVICE_NAME}` after fixing the issue");
            }
        } else {
            println!("flvproxy: service '{SERVICE_NAME}' installed and started (auto-starts on boot)");
        }
        // SAFETY: `svc` and `scm` are valid handles.
        unsafe {
            let _ = CloseServiceHandle(svc);
            let _ = CloseServiceHandle(scm);
        }
        EXIT_OK
    }

    /// Grants `FILE_GENERIC_WRITE | FILE_GENERIC_READ | FILE_LIST_DIRECTORY | FILE_TRAVERSE` (inherited by children) to `account_wide` on `dir`, so the service running as that per-service virtual account can write `flvproxy.log` and the lazily-generated PFX beside the exe. The existing DACL is read (so the operator's and inherited ACEs are preserved), merged with the new ACE via `SetEntriesInAclW`, and written back via `SetNamedSecurityInfoW`. Failures are reported on stderr but never panic — the service is already registered, and a missing ACL grant surfaces as a write failure at runtime that the operator can fix with `icacls`.
    fn grant_exe_dir_write_access(dir: &PathBuf, account_wide: &[u16]) {
        let dir_wide = super::to_wide(&dir.to_string_lossy());
        let account_str = super::wide_to_string(account_wide);
        let mut existing_dacl: *mut c_void = std::ptr::null_mut();
        let mut p_sd: *mut c_void = std::ptr::null_mut();
        // SAFETY: `dir_wide` is a NUL-terminated wide path; `SE_FILE_OBJECT` + `DACL_SECURITY_INFORMATION` fetch only the DACL. `existing_dacl`/`p_sd` are out-params zeroed above; on success `p_sd` points to an SD the caller frees via `LocalFree`, and `existing_dacl` points *into* that SD (not independently freed).
        let rc = unsafe { GetNamedSecurityInfoW(dir_wide.as_ptr(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, std::ptr::null_mut(), std::ptr::null_mut(), &mut existing_dacl, std::ptr::null_mut(), &mut p_sd) };
        if rc != ERROR_SUCCESS {
            eprintln!("flvproxy: GetNamedSecurityInfo failed for {}: os error {rc}", dir.display());
            return;
        }
        // RAII: free the SD (and the DACL it contains) on scope exit.
        struct SdGuard(*mut c_void);
        impl Drop for SdGuard {
            fn drop(&mut self) {
                if !self.0.is_null() {
                    // SAFETY: `self.0` is a valid `PSECURITY_DESCRIPTOR` from `GetNamedSecurityInfoW`; `LocalFree` is the documented release.
                    unsafe {
                        let _ = LocalFree(self.0);
                    }
                }
            }
        }
        let _sd_guard = SdGuard(p_sd);
        let entry = EXPLICIT_ACCESS_W { grfAccessPermissions: FILE_GENERIC_WRITE | FILE_GENERIC_READ | FILE_LIST_DIRECTORY | FILE_TRAVERSE, grfAccessMode: GRANT_ACCESS, grfInheritance: SUB_CONTAINERS_AND_OBJECTS_INHERIT, Trustee: TRUSTEE_W { pMultipleTrustee: std::ptr::null_mut(), MultipleTrusteeOperation: 0, TrusteeForm: TRUSTEE_IS_NAME, TrusteeType: 0, ptstrName: account_wide.as_ptr() } };
        let mut p_new_acl: *mut c_void = std::ptr::null_mut();
        // SAFETY: `entry` is fully initialized with `TRUSTEE_IS_NAME` form and a NUL-terminated wide account name; `existing_dacl` is a valid DACL pointer into `p_sd` (or null if the object had no DACL, which `SetEntriesInAclW` accepts as a fresh ACL). `p_new_acl` is an out-param zeroed above; on success it points to a freshly allocated ACL the caller frees via `LocalFree`.
        let rc = unsafe { SetEntriesInAclW(1, &entry, existing_dacl, &mut p_new_acl) };
        if rc != ERROR_SUCCESS {
            eprintln!("flvproxy: SetEntriesInAcl failed for {} (account {account_str}): os error {rc}", dir.display());
            return;
        }
        // RAII: free the merged ACL on scope exit (it is copied by `SetNamedSecurityInfoW`, so freeing here is correct).
        struct AclGuard(*mut c_void);
        impl Drop for AclGuard {
            fn drop(&mut self) {
                if !self.0.is_null() {
                    // SAFETY: `self.0` is a valid `PACL` from `SetEntriesInAclW`; `LocalFree` is the documented release.
                    unsafe {
                        let _ = LocalFree(self.0);
                    }
                }
            }
        }
        let _acl_guard = AclGuard(p_new_acl);
        // SAFETY: `dir_wide` is a NUL-terminated wide path; `SE_FILE_OBJECT` + `DACL_SECURITY_INFORMATION` write only the DACL; `p_new_acl` is a valid merged ACL from `SetEntriesInAclW`. The other SID pointers are null (no owner/group/SACL change). `SetNamedSecurityInfoW` takes a `LPWSTR` (mutable) but does not mutate the path string; casting the const pointer is sound under that read-only contract.
        let rc = unsafe { SetNamedSecurityInfoW(dir_wide.as_ptr() as *mut u16, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, std::ptr::null_mut(), std::ptr::null_mut(), p_new_acl, std::ptr::null_mut()) };
        if rc != ERROR_SUCCESS {
            eprintln!("flvproxy: SetNamedSecurityInfo failed for {} (account {account_str}): os error {rc}", dir.display());
            return;
        }
        println!("flvproxy: granted {account_str} write access on {}", dir.display());
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
    fn service_name_is_flvproxy() {
        assert_eq!(SERVICE_NAME, "flvproxy");
    }

    /// Guards the `NT SERVICE\<SERVICE_NAME>` account-name formatting used by `win::install` — the SCM resolves the per-service virtual account from this exact string on first start, so a formatting change here would break the ACL grant and the service logon identity silently.
    #[test]
    fn service_account_name_is_nt_service_virtual_account() {
        assert_eq!(format!("NT SERVICE\\{SERVICE_NAME}"), "NT SERVICE\\flvproxy");
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_entry_fns_return_windows_only_without_ffi() {
        assert_eq!(run_as_service(), crate::app::EXIT_WINDOWS_ONLY);
        assert_eq!(install(), crate::app::EXIT_WINDOWS_ONLY);
        assert_eq!(uninstall(), crate::app::EXIT_WINDOWS_ONLY);
    }
}
