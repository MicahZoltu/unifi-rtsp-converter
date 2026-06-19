# Step 21 — Protect Controller: Wire-In + Real-Camera End-to-End

**Depends on:** Step 19 (AVClient 7442), Step 20 (7550 WSS uPFLV ingest), Step
15 (RTSP server side already proven on the synthetic path).
**Type:** 🛑 STOP AND HUMAN TEST 2 (real camera, no SSH) — the capstone of the
Protect-controller track.

## Goal

Wire the 7442 AVClient controller and the 7550 WSS uPFLV listener into
`console_main` (and later the step-27 service body) on the Windows target, so
that the proxy acts as a complete UniFi Protect controller: the camera is
adopted over 7442, streams uPFLV over 7550 WSS, and RTSP clients (VLC/ffprobe)
consume the re-published stream — **with no SSH into the camera**. This is the
real-camera half of the end-to-end goal that step 15 could only prove
synthetically.

## Tasks

1. **`console_main` (Windows path):** replace the plain-TCP `CameraListener`
   spawn with:
   - A 7442 WSS listener running an `AvClientSession` accept loop (step 19).
   - A 7550 WSS listener running the `WssUpflvSource` `CameraListener` (step
     20), sharing the same `StreamState` as the RTSP server (step 12).
   - The existing RTSP server (step 12) on 8554, unchanged.
   - The startup log line now reports all four ports: `listening 7442=avclient
     7550=upflv 8554=rtsp onvif=... ip=...`.
2. **Cert loading:** `console_main` loads the self-signed cert (generated in
   step 16) from beside the exe; its path is configurable via `flvproxy.ini`
   (`cert_path` / `cert_password`). Document the field in `src/config.rs`.
3. **Linux `console_main` path:** the Protect listeners are `#[cfg(windows)]`;
   on Linux `console_main` retains the plain-TCP `CameraListener` so `cargo
   test` and dev runs still work (this is the test ingress, per step 20's debt
   note). The RTSP server runs on both.
4. **Shutdown:** Ctrl+C (the existing `console_shutdown` from step 15) signals
   all listeners + the RTSP server to stop.
5. **Remove/retire the step-16 recon tool and the step-17 TLS self-test
   harness** (or move them under `tools/`) once the real path works — they have
   served their purpose. The `tls_schannel` module stays as production.

## Validation — 🛑 STOP AND HUMAN TEST 2 (real camera, no SSH)

Build: `cargo build --release --target x86_64-pc-windows-gnu`.

**Setup:**
1. Ship `flvproxy.exe` + the self-signed cert + (optional) `flvproxy.ini` to
   the Windows proxy host.
2. Run `flvproxy.exe --console`. Confirm the startup line lists 7442/7550/8554.
3. In the camera's web UI, enter the proxy IP in the "UniFi Protect Server"
   box. (No SSH. No editing of `ubnt_streamer_sysid_a591.json`.)

**Pass criteria (all must be true):**
- Within ~10 s the log shows a 7442 AVClient connection + the handshake
  completing (`hello`, `paramAgreement`, `timeSync` acknowledged).
- The camera then opens 7550; the log shows `camera connected from <ip>` and,
  within ~5 s, `SPS received: profile=... level=...` + `PPS received` + frame
  counters incrementing at roughly the camera's FPS (the Human Test 1
  criteria, now satisfied over the real WSS path).
- From another machine, **VLC** opens `rtsp://<proxy_ip>:8554/stream` → live
  moving video within ~5 s.
- `ffprobe -rtsp_transport tcp rtsp://<proxy_ip>:8554/stream` AND
  `ffprobe -rtsp_transport udp rtsp://<proxy_ip>:8554/stream` both report
  `h264`, sane resolution/fps, incrementing `packets`/`duration`.
- Reconnect VLC mid-stream → new client gets a keyframe quickly and resumes.
- 60 s soak: no panic, no crash, no error floods in the log.

**If it fails:** the recon capture (step 16) + the step-19/20 logs pinpoint
whether the fault is the AVClient handshake (7442), the uPFLV de-framing
(7550), or the RTSP/RTP path (already proven in step 15, so unlikely). Capture
the failing stage's bytes and harden the matching step; do not paper over.

## Quality Gate (Standard, scoped to touched modules)

- `cargo build` / `cargo test` / `cargo clippy -- -D warnings` clean on Linux.
- `cargo build --release --target x86_64-pc-windows-gnu` clean.
- `cargo clippy --target x86_64-pc-windows-gnu -- -D warnings` clean.
- `console_main` has no `unwrap`/`expect`/`panic!` outside startup.
- The four-listener startup line is logged exactly once, before blocking.

## Debt notes

- Any step-16/19/20 assumptions that the real camera contradicted are logged
  here as `FIX NOW` and resolved before this step is marked complete.
- The plain-TCP `CameraListener` test ingress (step 14/20) is kept; its
  retirement is deferred to step 28 per step 20's note.

## After this step

The real-camera → RTSP-client path works end-to-end without SSH. The project
resumes the planned sequence at step 22 (ONVIF SOAP), with the Protect
controller emulator as a permanent part of the proxy.

## Do not

- Do not implement ONVIF here — step 22+.
- Do not remove the Linux plain-TCP test ingress — it's the `cargo test`
  surface for the parser pipeline.
