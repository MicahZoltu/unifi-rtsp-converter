# Step 12 — RTSP Server (Sockets + Sessions + RTP Pump)

**Depends on:** Steps 08, 09, 10, 11.

## Goal

A real `std::net::TcpListener`-based RTSP server that:
- Accepts client connections, one thread per client.
- Drives the protocol from step 11 over the socket.
- On `PLAY`, spawns an RTP pump that pulls `Frame`s from the client's `StreamState` receiver (step 08) and pushes RTP packets via the packetizer (step 09).
- Supports **both** TCP interleaved (write `$`-framed packets on the RTSP socket) and UDP (send datagrams to `client_rtp` port).
- Cleans up on disconnect / `TEARDOWN`.

Importantly: this step is testable **without a camera** by injecting a `StreamState` that is fed by a **mock frame producer** (a test thread pushing synthetic frames). That keeps tests logic-only.

## Tasks — `src/rtsp_server.rs` (runtime half)

1. `struct RtspServer { state: Arc<Mutex<StreamStateInner>>, rtsp_port: u16, server_ip: String, shutdown: Arc<AtomicBool> }`.
2. `RtspServer::run()` — bind `TcpListener` on `0.0.0.0:rtsp_port`, `accept` loop spawning `thread::spawn` per connection → `handle_client(stream, ...)`.
3. `handle_client`:
   - Read loop into a growable buffer; after each read, call `parse_request` repeatedly, draining complete requests.
   - Dispatch to the step-10 handlers. Maintain a `HashMap<session_id, RtspSession>` plus per-session `mpsc::Receiver<Frame>` (obtained from `StreamState::add_client` at SETUP time).
   - On `PLAY`, spawn the RTP pump thread for that session (or drive it inline via a select-ish poll between socket reads and channel recv — simplest: separate thread).
4. RTP pump (per session):
   - `RtpPacketizer` per session (random ssrc, random start seq).
   - Loop: `receiver.recv_frame()` → `packetizer.packetize_frame(&frame)` → send each packet:
     - `Transport::Interleaved { rtp_ch }`: write `[0x24, rtp_ch, len_hi, len_lo, ...packet]` on the RTSP `TcpStream` (guarded by a per-connection send mutex so control + data don't interleave corruptly).
     - `Transport::Udp { client_rtp, .. }`: `UdpSocket::send_to` to `client_addr:client_rtp`.
   - On channel disconnect or shutdown flag → exit, remove client from `StreamState`.
5. **Test seam:** factor the pump's "send one packet" behind a trait so tests can supply an in-memory sink (`Vec<Vec<u8>>`) instead of a real socket.
   ```rust
   trait PacketSink { fn send(&mut self, pkt: &[u8]) -> io::Result<()>; }
   ```
   Provide `TcpInterleavedSink` and `UdpSink` for production, `VecSink` for tests.
6. Graceful handling of broken pipes: a write error ends the session and removes the client (camera thread must never be blocked).

## Validation (automated) — `tests/rtsp_server.rs`

Use `TcpListener::bind("127.0.0.1:0")` ephemeral ports. Tests act as the RTSP client using `std::net::TcpStream` and raw byte writes/reads. The server's `StreamState` is fed by a test thread producing synthetic frames (a fake SPS/ PPS `Config` + a repeating keyframe/inter-frame sequence).

- Full happy path over **TCP interleaved**:
  1. Connect, send `OPTIONS` → assert `200` + `Public:` + echoed CSeq.
  2. `DESCRIBE` → assert `200`, `Content-Type: application/sdp`, body contains `a=rtpmap:96 H264/90000` and a non-empty `sprop-parameter-sets`.
  3. `SETUP` with `interleaved=0-1` → assert `200`, `Session:` returned, echoed transport.
  4. `PLAY` → assert `200`, `Range:`.
  5. Read bytes from the socket; assert at least one `$` (0x24) interleaved frame arrives, channel byte == 0, length field matches following bytes, and the RTP header PT == 96.
  6. `TEARDOWN` → `200`. Server closes the session.
- **UDP** path: `SETUP` with `client_port=X-Y`, then bind a `UdpSocket` on `127.0.0.1:X`, `PLAY`, assert a UDP datagram arrives with a valid RTP header.
- **VecSink unit test** (no socket): feed a 2-NALU frame into a pump wired to a `VecSink`, assert the exact sequence of packet bytes matches `RtpPacketizer::packetize_frame` output (cross-check against step 09 tests).
- DESCRIBE before mock camera publishes a `Config` → `503`.
- Client disconnects mid-stream (drop the `TcpStream`) → server's client list shrinks; no panic, no thread leak (best-effort: assert `StreamState` `clients.len()` returns to baseline within a short timeout).
- Two concurrent clients each get their own session and their own RTP stream.

## Quality Gate (mandatory — step is not complete until this passes)

Run the **Standard Quality Gate** from `plan/README.md`. Then **step back and review the whole codebase**, not just the diff:

- Does this change respect the module boundaries in `PROJECT.md`, or did you bend them? If bent, refactor now.
- Did consuming this step reveal that an earlier module's API is awkward, mis-named, or leaky? Go back and fix that module — do not paper over it here.
- Any new duplication across modules? Extract a shared helper into the owning module.
- Are logging, error, and test styles consistent with the conventions established by earlier steps?
- Did you introduce a `// TODO` / `// FIXME` / `// HACK`, commented-out code, or a magic number? Remove it, name it as a constant, or log it in `DEBT.md`.

**Hard rules:**
- If the gate fails, you do **not** proceed to the next step.
- If passing it properly requires reworking an earlier step, do that rework now — **iterating or redoing is preferred over hacking to move on.**
- A step that "works but feels hacky" is a failed step. Reopen it.

This step ends the RTSP cluster — after it passes, run the **step 13 cluster review** before moving to step 14.

## Debt notes

If anything was deferred (a workaround, a "good enough for now", an unclear decision), append a line to `DEBT.md` at the repo root (create the file if absent — see `plan/README.md` for the format):

`step NN | <file>:<area> | <what> | <FIX NOW | TRIGGER: ...>`

- `FIX NOW` items must be resolved before the next dedicated review (`07` / `13` / `24` / `27`).
- `TRIGGER:` items must name the concrete future event that forces revisiting them.
- No silent hacks: if you hacked it, log it. If you can fix it now, fix it now and don't log it.

## Do not

- Do not yet attach a real camera (that's step 14). The mock producer stands in for the camera. No RTCP. No authentication.

## Note

This step's tests spin up real loopback TCP/UDP sockets, but they exercise **our own** server logic against a synthetic in-process producer — not a real camera or a real RTSP client library. That keeps them fast, deterministic, and CI-friendly.
