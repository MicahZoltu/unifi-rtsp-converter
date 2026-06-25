# flvproxy — UniFi Camera FLV-to-RTSP/ONVIF Proxy

A Windows service (also runnable as a console app on any platform) that receives a live video stream from a Ubiquiti UVC G5 Bullet camera, pushed in UniFi's proprietary `extendedFlv` format over TCP, and re-serves it as standard **RTSP** and **ONVIF**, so third-party NVR software (VLC, ffprobe, Onvier, Blue Iris, …) can consume the feed.

Zero external crates: only the Rust standard library and direct Win32 FFI.

## Build

The project builds on **Linux** (dev/CI) and cross-compiles to **Windows** with no dev tooling or runtimes needed on the target host.

```sh
# one-time toolchain setup
rustup toolchain install stable
rustup component add clippy rustfmt
rustup target add x86_64-pc-windows-gnu
# Debian/Ubuntu: apt install gcc-mingw-w64-x86-64

# Linux host build (dev)
cargo build --release

# Windows release binary → target/x86_64-pc-windows-gnu/release/flvproxy.exe
cargo build --release --target x86_64-pc-windows-gnu

# logic tests (run on the Linux build host)
cargo test
```

The cross-compiled `flvproxy.exe` is self-contained: static-linked MinGW runtime (`.cargo/config.toml`), depends only on system DLLs that ship with Windows. Copy just the `.exe` (and optionally `flvproxy.ini`) to the target.

## Configuration

All settings are optional; defaults come from `PROJECT.md` §2. Copy [`flvproxy.ini.example`](flvproxy.ini.example) to `flvproxy.ini` beside the binary and edit:

```ini
[server]
listen_port = 7550          # camera pushes extendedFlv here
rtsp_port = 554            # NVRs connect over RTSP here
onvif_discovery = true      # WS-Discovery (UDP 239.255.255.250:3702)
# onvif_port = 8080         # ONVIF Device + Media SOAP over HTTP; auto-select when missing
# server_ip = 192.168.1.10  # advertised IP; auto-detected when missing
```

Windows-only fields (`cert_path`, `cert_password`, `controller_name/uuid/version`) configure the 7442 Protect AVClient TLS identity; see the sample file.

## Run

**Console / foreground** (the default — dev, or Linux test ingress — Ctrl+C exits cleanly):

```sh
flvproxy.exe
```

**Windows service:**

```sh
flvproxy.exe --install
sc.exe start flvproxy
sc.exe stop flvproxy
flvproxy.exe --uninstall
```

## Camera setup

Login to the camera's web portal (http://<camera-ip>) and under Configure -> UniFi Protect Server put in the IP address of the host that the service is installed on.

## Consuming the stream

- **RTSP:** `rtsp://<proxy_ip>:554/stream` (open in VLC / ffprobe / your NVR).
- **ONVIF:** WS-Discovery advertises the device on UDP `239.255.255.250:3702`; the Device + Media SOAP services live at `http://<proxy_ip>:8080/onvif/device_service` and `/onvif/media_service`. `GetStreamUri` returns the RTSP URL above.

## Logs

`flvproxy.log` is written beside the executable and rotates at 10 MiB (one backup, `flvproxy.log.1`). In console mode (the default) every line is also teed to stdout.
