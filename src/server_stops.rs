//! Spawned-server lifecycle: collects the per-server shutdown flags and worker `JoinHandle`s produced by `App::spawn` and provides a no-crates join-with-timeout so process exit is bounded even if a worker overshoots. The accept loops poll their shutdown flag every ~50ms, so a healthy worker exits well inside the budget; an overrunning worker is detached (its thread keeps running but the process is leaving anyway).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// Relaxed ordering suffices for the per-server shutdown flags: they are advisory signals, not synchronization that establishes happens-before for other data (each server's internal `Arc<Mutex<…>>` state carries that burden). Mirrors the server modules.
const RELAXED: Ordering = Ordering::Relaxed;

/// Per-worker upper bound for `ServerStops::join_with_timeout` when shutting down. Each accept loop polls its shutdown flag every ~50ms, so a healthy worker exits well inside this bound; a worker that overshoots is detached (its thread keeps running but the process is leaving anyway). Public so the console entry point (`main.rs`) passes the same budget the service path uses.
pub const JOIN_TIMEOUT_SECS: u64 = 5;

/// Poll granularity for the no-crates join-timeout helper. `JoinHandle::is_finished` is polled at this cadence until the worker exits or the per-handle deadline elapses.
const JOIN_POLL_MS: u64 = 25;

/// Per-server shutdown flags and worker `JoinHandle`s collected by `App::spawn`. `shutdown` flips every flag so each accept loop exits on its next poll; `join_with_timeout` then waits for every worker to actually return, bounding process exit. The order of flags vs handles does not matter — the flags are independent advisory signals and each handle is joined with its own timeout budget.
pub struct ServerStops {
    stops: Vec<Arc<AtomicBool>>,
    handles: Vec<JoinHandle<()>>,
}

impl ServerStops {
    pub(crate) fn new(stops: Vec<Arc<AtomicBool>>, handles: Vec<JoinHandle<()>>) -> ServerStops {
        ServerStops { stops, handles }
    }

    /// Signals every spawned server to stop. Idempotent — storing `true` into an already-`true` flag is a no-op, so calling this from both the shutdown path and `Drop` is safe.
    pub fn shutdown(&self) {
        for stop in &self.stops {
            stop.store(true, RELAXED);
        }
    }

    /// Waits for every spawned worker to return, bounding each join to `per_handle`. A worker that has not returned by its deadline is detached (its `JoinHandle` is dropped, so the thread continues but the process is leaving anyway). Implemented with a poll loop on `JoinHandle::is_finished` — no crate dependency.
    pub fn join_with_timeout(&mut self, per_handle: Duration) {
        for handle in self.handles.drain(..) {
            join_handle_with_timeout(handle, per_handle);
        }
    }
}

impl Drop for ServerStops {
    fn drop(&mut self) {
        // Best-effort: ensure the shutdown flags flip even if the owner forgot to call `shutdown` (e.g. a panic between spawn and the explicit shutdown). Idempotent with `shutdown`. Handles are not joined here — `drop` must not block.
        for stop in &self.stops {
            stop.store(true, RELAXED);
        }
    }
}

/// Joins `handle`, polling `is_finished` at `JOIN_POLL_MS` until it returns or `timeout` elapses, then detaches the handle. The standard no-crates join-with-timeout pattern: `JoinHandle::join` blocks with no timeout, so the only way to bound the wait is to poll for completion and drop the handle when the deadline passes.
fn join_handle_with_timeout(handle: JoinHandle<()>, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if handle.is_finished() {
            break;
        }
        thread::sleep(Duration::from_millis(JOIN_POLL_MS));
    }
    // If finished, `join` reaps the thread (and surfaces any panic); if not, dropping the handle detaches the thread so the process can continue exiting.
    if handle.is_finished() {
        let _ = handle.join();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_with_timeout_reaps_a_promptly_returning_worker() {
        // A worker that exits immediately must be reaped well inside the budget; the helper returns (rather than panicking) once the handle is joined.
        let handle = thread::spawn(|| {});
        join_handle_with_timeout(handle, Duration::from_secs(2));
    }

    #[test]
    fn join_with_timeout_detaches_an_overrunning_worker_without_blocking() {
        // A worker that sleeps past the budget must NOT cause the helper to block: the handle is detached and the helper returns within the deadline. The worker thread continues to completion on its own.
        let handle = thread::spawn(|| {
            thread::sleep(Duration::from_secs(10));
        });
        let start = Instant::now();
        join_handle_with_timeout(handle, Duration::from_millis(200));
        assert!(start.elapsed() < Duration::from_secs(2), "join_with_timeout must not block past the deadline for an overrunning worker");
    }
}
