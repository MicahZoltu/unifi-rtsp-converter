//! Holds the raw socket of the currently-active connection for a single-active-connection listener, so a newly-accepted connection can force-close the prior one (one active camera at a time, per `PROJECT.md` → "TCP Listener"). Shared by `camera_listener` (the 7550 plain-TCP path) and `protect_listener` (the Windows 7442 TLS+WSS path); extracting it consolidates the "swap force-closes the old, force_close drops the active" invariant in one place rather than two identical copies, mirroring the `accept_loop` consolidation of the shared non-blocking accept mechanics.
//!
//! Storing the raw `TcpStream` (not the wrapped source) means a `shutdown(Both)` on the clone interrupts the active handler's blocked read on the original. `Clone` is a cheap `Arc` clone so the accept loop and a handler thread each hold one.

use std::net::{Shutdown, TcpStream};
use std::sync::{Arc, Mutex};

/// Holds the currently-active `TcpStream` behind an `Arc<Mutex<Option<_>>>` so a new connection can replace and force-close the prior one. A clone shares the same slot.
#[derive(Clone)]
pub struct ConnectionSlot {
    current: Arc<Mutex<Option<TcpStream>>>,
}

impl ConnectionSlot {
    pub fn new() -> ConnectionSlot {
        ConnectionSlot { current: Arc::new(Mutex::new(None)) }
    }

    /// Stores `clone` as the active connection, force-closing (TCP shutdown both directions) whatever connection was active before, so its blocked read returns promptly. The stored `TcpStream` is a `try_clone` of the accepted socket, so closing it does not close the handler's own copy.
    pub fn swap(&self, clone: TcpStream) {
        let old = {
            let mut guard = self.current.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            guard.replace(clone)
        };
        if let Some(old) = old {
            let _ = old.shutdown(Shutdown::Both);
        }
    }

    /// Force-closes and drops the active connection, if any. Used on listener shutdown so the active handler's blocked read returns promptly.
    pub fn force_close(&self) {
        let old = {
            let mut guard = self.current.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            guard.take()
        };
        if let Some(old) = old {
            let _ = old.shutdown(Shutdown::Both);
        }
    }
}

impl Default for ConnectionSlot {
    fn default() -> ConnectionSlot {
        ConnectionSlot::new()
    }
}
