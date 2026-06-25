//! The shared non-blocking TCP accept loop used by every server in the proxy. One implementation of the "set non-blocking, iterate `incoming()`, poll the shutdown flag, sleep on `WouldBlock`/error, hand each accepted stream to a closure" shape that `camera_listener`, `rtsp_server`, `onvif_server`, and (on Windows) `protect_listener` all need. Extracting it makes the invariant "every server checks shutdown on the same cadence and never aborts on a transient accept error" visible in one place instead of copied across four files, and keeps each server's `run_on`/`run` body down to just its per-connection handler.

use std::io;
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

/// Relaxed ordering suffices for the shutdown flag: it is an advisory signal, not synchronization that establishes happens-before for other data (each server's own state mutex carries that burden).
const RELAXED: Ordering = Ordering::Relaxed;

/// Poll interval for the non-blocking accept loop, so the `shutdown` flag is checked promptly rather than blocking until the next connection. Matches the cadence every server module used when each inlined its own copy.
const ACCEPT_POLL_MS: u64 = 50;

/// Runs a non-blocking accept loop over `listener` until `shutdown` is set. Sets the listener non-blocking, polls `incoming()` with `ACCEPT_POLL_MS` sleeps so `shutdown` is checked promptly, hands each accepted `TcpStream` to `on_accept`, and sleeps (rather than aborts) on any accept error so a transient failure never kills the listener. The caller binds the listener (so tests can pick an ephemeral port); this fn owns only the loop mechanics.
pub fn accept_loop<F: FnMut(TcpStream)>(listener: TcpListener, shutdown: &AtomicBool, mut on_accept: F) -> io::Result<()> {
    listener.set_nonblocking(true)?;
    for incoming in listener.incoming() {
        if shutdown.load(RELAXED) {
            break;
        }
        match incoming {
            Ok(stream) => on_accept(stream),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(ACCEPT_POLL_MS));
            }
            Err(_) => {
                thread::sleep(Duration::from_millis(ACCEPT_POLL_MS));
            }
        }
    }
    Ok(())
}
