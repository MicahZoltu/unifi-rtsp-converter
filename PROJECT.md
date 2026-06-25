# UniFi Camera FLV-to-RTSP/ONVIF Proxy — Build Plan

## Project Overview

Build a Windows service in Rust that receives a live video stream from a Ubiquiti UVC G5 Bullet camera (using Ubiquiti's proprietary `extendedFlv` format over TCP) and re-serves it as standard RTSP and ONVIF, allowing third-party NVR software to consume the feed.

**Zero external dependencies.** The entire project uses only the Rust standard library and direct Win32 FFI declarations. No crates from crates.io.

> **🛑 Human-action convention:** several build-plan steps require a human to run a binary on Windows, point a physical camera at the proxy, run a manual test in VLC/ONVIF Device Manager, or clean up an OS artifact. When an agent implementing a step reaches such an action, it **must** surface it very visibly in its final response — not assume the human is reading along. See `plan/README.md` → "🛑 Human-Action Alerting" for the mandatory format.

---

## Background: How the Camera Streams

UniFi Protect cameras do not serve RTSP or ONVIF natively. Instead, they **push** a video stream to a destination specified in their internal streamer configuration. The stream uses a proprietary format called `extendedFlv` sent over a raw TCP connection.

### The Stream Format

The stream consists of three layers:

#### Layer 1: uPFLV Magic Prefix (11 bytes)
Before the FLV data begins, there is a UniFi-specific magic prefix:
```
DE 19 16 15 47 17 DE 19 16 75 50
```
This must be detected and stripped before parsing FLV data. If the first 11 bytes do not match this pattern, assume no prefix is present and parse from byte 0.

#### Layer 2: Standard FLV Container
After the uPFLV prefix (if present), the stream is a standard FLV (Flash Video) stream:
- **FLV Header** (9 bytes): `46 4C 56` ("FLV"), version byte (0x01), flags byte (0x07 = audio+video), header size (0x00000009), prev tag size 0 (0x00000000)
- **FLV Tags**: Repeating sequence of:
  - Tag type (1 byte): `0x08` = audio, `0x09` = video, `0x12` = script data
  - Data size (3 bytes, big-endian)
  - Timestamp (3 bytes) + timestamp extended (1 byte) = 32-bit timestamp in ms
  - Stream ID (3 bytes, always 0)
  - Tag payload (data size bytes)
  - Previous tag size (4 bytes, big-endian) = 11 + data size

#### Layer 3: Extended FLV Video Tags
Video tags (`0x09`) in `extendedFlv` format use the **ExVideoTagHeader** (defined in the Enhanced RTMP specification by Veovera Software Organization). The first byte of the video tag payload is parsed as follows:

The first byte contains two nibbles. The **high nibble** (bits 7-4) contains `IsExHeader` (bit 7) and `FrameType` (bits 6-4). The **low nibble** (bits 3-0) contains either `CodecID` (standard) or `PacketType` (extended).

```
byte0 = first byte of video tag payload

is_ex_header = (byte0 & 0x80) != 0

if NOT extended (is_ex_header == false):
    frame_type = (byte0 >> 4) & 0x0F   // 1=keyframe, 2=inter frame
    codec_id   = byte0 & 0x0F           // 7=AVC/H.264

if extended (is_ex_header == true):
    frame_type  = (byte0 >> 4) & 0x07   // bits 6-4: 1=keyframe, 2=inter
    packet_type = byte0 & 0x0F          // bits 3-0: see below
    fourcc      = read 4 bytes (e.g. "hvc1", "av01")
```

**PacketType values (extended mode):**
- 0 = SequenceStart (codec config record follows)
- 1 = CodedFrames (composition time SI24 + NALUs)
- 2 = SequenceEnd
- 3 = CodedFramesX (NALUs, no composition time)
- 4 = Metadata (skip)

**The implementation should handle BOTH standard and extended paths.** Based on captured real-world streams from UniFi cameras, the video tags may use standard FLV video tag framing (not ExVideoTagHeader). The H.264 NALU data is the same standard H.264 bitstream either way.

### Script Data Tags (type 0x12)
The stream includes AMF0-encoded script tags:
- **onMetaData**: Stream descriptors (videoWidth, videoHeight, videoFps, videoBandwidth, hasAudio, hasVideo, extendedFormat, streamName, etc.)
- **onMpma**: Per-module bitrate statistics
- **onClockSync**: Timing information (streamClock, streamClockBase, wallClock)

These can be parsed to extract stream metadata (resolution, FPS) but are not required for video extraction. The implementation should skip unneeded script tags.

### Audio Tags (type 0x08)
Audio tags may contain AAC or Opus audio. For this implementation, **audio will be ignored** — only video (H.264) will be extracted and served via RTSP/ONVIF.

---

## Architecture

```
Camera (ubnt_streamer)
    │
    │ TCP connection (camera initiates)
    │ Pushes extendedFlv stream
    ▼
[Proxy Server - Windows Service]
    │
    ├── TCP Listener (port 7550 or configurable)
    │     └── Reads uPFLV prefix → FLV stream
    │
    ├── FLV Parser
    │     └── Parses FLV header + tags
    │     └── Extracts H.264 SPS/PPS (from AVC sequence headers)
    │     └── Extracts H.264 NALUs (from AVC NALU tags)
    │
    ├── H.264 Stream State
    │     └── Stores current SPS/PPS
    │     └── Buffers recent frames for new RTSP clients
    │
    ├── RTSP Server (port 8554 or configurable)
    │     └── DESCRIBE → returns SDP with H.264 capabilities
    │     └── SETUP → allocates RTP transport (UDP or TCP interleaved)
    │     └── PLAY → starts sending RTP packets to client
    │     └── TEARDOWN → stops streaming to client
    │
    └── ONVIF Server (port 3702 discovery + port 8080 or configurable)
          └── WS-Discovery (UDP multicast 239.255.255.250:3702)
          └── ONVIF Device Service (GetCapabilities, GetDeviceInformation)
          └── ONVIF Media Service (GetProfiles, GetStreamUri)
          └── Returns RTSP URL as the stream URI
```

---

## Implementation Specification

### 1. Windows Service Integration (Direct FFI, No Crates)

Implement the Windows Service using direct FFI to `advapi32.dll` and `kernel32.dll`. Do NOT use the `windows-service` crate or `windows-sys` crate.

**Required FFI declarations:**

```rust
// From advapi32.dll:
// - StartServiceCtrlDispatcherW(ServiceTableEntryW*) -> i32
// - RegisterServiceCtrlHandlerExW(name, handler, context) -> isize (status handle)
// - SetServiceStatus(handle, ServiceStatus*) -> i32

// From kernel32.dll:
// - CreateEventW(attrs, manual_reset, initial_state, name) -> *mut void
// - SetEvent(handle) -> i32
// - WaitForSingleObject(handle, ms) -> u32
// - CloseHandle(handle) -> i32
```

**Required types:**
```rust
#[repr(C)]
struct ServiceTableEntryW {
    name: *const u16,           // UTF-16 service name
    service_main: extern "system" fn(u32, *mut *mut u16),
}

#[repr(C)]
struct ServiceStatus {
    service_type: u32,          // SERVICE_WIN32_OWN_PROCESS = 0x10
    current_state: u32,         // SERVICE_START_PENDING=2, SERVICE_RUNNING=4, SERVICE_STOP_PENDING=3, SERVICE_STOPPED=1
    controls_accepted: u32,     // SERVICE_ACCEPT_STOP = 0x01
    win32_exit_code: u32,       // 0 = ERROR_SUCCESS
    service_specific_exit_code: u32, // 0
    check_point: u32,           // increment during long starts
    wait_hint: u32,             // ms expected for pending operations
}
```

**Service lifecycle:**
1. `main()` calls `StartServiceCtrlDispatcherW` with a single-entry service table
2. Windows calls `service_main()` callback
3. `service_main()` registers control handler, reports START_PENDING
4. Spawns a thread for the proxy server
5. Reports RUNNING
6. Waits on stop event (set by control handler when SCM sends SERVICE_CONTROL_STOP)
7. Reports STOPPED and returns

**Service installation:** Provide a separate `install` subcommand (when run with `--install` argument) that uses `OpenSCManagerW` / `CreateServiceW` to register the service. Provide `--uninstall` to remove it.

### 2. Configuration

Parse a simple INI or TOML-like config file (`flvproxy.ini`) from the same directory as the executable:

```ini
[server]
listen_port = 7550          # Port the camera connects to
rtsp_port = 8554            # Port for RTSP clients
onvif_port = 8080           # Port for ONVIF device/media service (omit to auto-select a free port)
onvif_discovery = true      # Enable WS-Discovery
```

If the config file doesn't exist, use these defaults.

### 3. TCP Listener (Camera Input)

- Listen on `0.0.0.0:listen_port` (default 7550)
- Accept one connection at a time (the camera maintains a persistent connection)
- If a new connection arrives while one is active, close the old one
- Read bytes from the connection in a loop

**uPFLV prefix detection:**
- Read the first 11 bytes
- If they match `DE 19 16 15 47 17 DE 19 16 75 50`, skip them
- If they don't match, treat the data as starting from byte 0 (the camera might not send the prefix in some configurations)
- Pass remaining bytes to the FLV parser

### 4. FLV Parser

Parse the FLV stream byte-by-byte. The parser should be a state machine that processes a byte buffer and emits events:

**States:**
1. `ReadingHeader` — Read 9 bytes, validate "FLV" signature, read version and flags
2. `ReadingPrevTagSize` — Read 4 bytes (ignore)
3. `ReadingTagHeader` — Read 11 bytes: tag type (1), data size (3), timestamp (3+1), stream ID (3)
4. `ReadingTagBody` — Read `data_size` bytes of tag payload
5. Go to state 2

**Tag handling:**
- **`0x12` (script data)**: Skip. Optionally parse `onMetaData` to extract `videoWidth`, `videoHeight`, `videoFps` for SDP.
- **`0x08` (audio)**: Skip. (Audio is not supported in this version.)
- **`0x09` (video)**: Parse as video tag (see below).

**Video tag parsing (standard path — is_ex_header == false):**

```
byte0: [FrameType:4][CodecID:4]  (e.g. 0x17 = keyframe+AVC, 0x27 = inter+AVC)

if codec_id == 7 (AVC):
    byte1:     AVCPacketType (0=seq header, 1=NALU, 2=end)
    bytes 2-4: Composition time (big-endian SI24)
    rest:      H.264 data

    if AVCPacketType == 0:
        Parse as AVCDecoderConfigurationRecord → extract SPS and PPS
        Store in stream state
    if AVCPacketType == 1:
        Parse as length-prefixed NALUs (4-byte big-endian length + NALU data, repeated)
        Emit frame event with: frame_type, timestamp, Vec<NALU>
```

**Video tag parsing (extended path — is_ex_header == true):**

```
byte0: [1][FrameType:3][PacketType:4]
bytes 1-4: FourCC (4 ASCII bytes, e.g. "hvc1")

if PacketType == 0 (SequenceStart):
    rest: Codec configuration record (AVCDecoderConfigurationRecord for H.264)
    Parse to extract SPS and PPS
if PacketType == 1 (CodedFrames):
    bytes 5-7: Composition time (SI24)
    rest: H.264 NALUs (4-byte length-prefixed)
    Emit frame event
if PacketType == 3 (CodedFramesX):
    rest: H.264 NALUs (4-byte length-prefixed, no composition time)
    Emit frame event
if PacketType == 4 (Metadata):
    Skip
```

### 5. H.264 Stream State

Maintain a shared state object:
```rust
struct StreamState {
    sps: Option<Vec<u8>>,       // SPS NALU (without start code)
    pps: Option<Vec<u8>>,       // PPS NALU (without start code)
    width: u32,                 // Video width (optional, from onMetaData)
    height: u32,                // Video height (optional, from onMetaData)
    fps: f32,                   // Frame rate (optional, from onMetaData)
    latest_clients: Vec<ClientHandle>,  // Connected RTSP clients
}
```

When SPS/PPS are received (from AVC sequence header), store them. When a new RTSP client connects, send SPS/PPS first, then continue with live frames.

### 6. Frame Distribution

When a video frame is received from the FLV parser:
1. Store the frame in a small ring buffer (for clients that connect mid-stream to get the last keyframe)
2. For each connected RTSP client, push the frame into their send queue

Frame structure:
```rust
struct Frame {
    is_keyframe: bool,
    timestamp_ms: u32,    // From FLV tag timestamp
    nalus: Vec<Vec<u8>>,  // Each NALU without start code or length prefix
}
```

### 7. RTSP Server

Implement a minimal RTSP server per RFC 2326. Support these methods only:
- **OPTIONS**: Return supported methods
- **DESCRIBE**: Return SDP describing the H.264 stream
- **SETUP**: Allocate a transport (UDP or TCP interleaved)
- **PLAY**: Start streaming RTP packets
- **TEARDOWN**: Stop streaming

**RTSP protocol notes:**
- RTSP is text-based, similar to HTTP
- Each request has headers and an optional body
- Responses have status code, headers, and body
- The `CSeq` header must be echoed in responses
- Sessions use a `Session:` header with a generated session ID

**SDP for DESCRIBE:**
```
v=0
o=- 0 0 IN IP4 0.0.0.0
s=UniFi Camera Stream
t=0 0
m=video 0 RTP/AVP 96
a=control:streamid=0
a=rtpmap:96 H264/90000
a=fmtp:96 packetization-mode=1;profile-level-id=<from SPS>;sprop-parameter-sets=<base64(SPS)>,<base64(PPS)>
a=framerate:<fps>
```

The `profile-level-id` is derived from SPS bytes 1-3 (AVCProfileIndication, profile_compatibility, AVCLevelIndication), formatted as 6 hex digits.

The `sprop-parameter-sets` is the base64 encoding of SPS and PPS NALUs, comma-separated.

**Transport modes:**
- **TCP interleaved**: RTP packets are sent over the RTSP TCP connection, prefixed with a `$` byte, channel byte, and 2-byte length. Use when `Transport:` header contains `interleaved=N-M`.
- **UDP**: RTP packets are sent to the client's IP and specified port. Use when `Transport:` header contains `client_port=N-M`.

### 8. RTP Packetization (RFC 6184)

- RTP payload type: 96 (dynamic)
- RTP timestamp: Frame timestamp in 90kHz clock (convert from ms: `timestamp_ms * 90`)
- RTP SSRC: Random 32-bit value per session
- Sequence number: Starts at random value, increments per packet

**NALU packetization modes:**
- **Single NALU Packet** (NALU ≤ 1400 bytes): One NALU per RTP packet. The RTP payload is just the NALU (with its 1-byte NALU header).
- **FU-A Fragmentation** (NALU > 1400 bytes): Split large NALUs across multiple RTP packets using FU-A fragmentation:
  - FU indicator byte: `(original_nalu_header & 0xE0) | 28` (preserve forbidden+priority bits, set type to 28=FU-A)
  - FU header byte: `[Start:1][End:1][Reserved:1][NALU type:5]` where type is `original_nalu_header & 0x1F`
  - For first packet: Start=1, End=0
  - For middle packets: Start=0, End=0
  - For last packet: Start=0, End=1
  - Payload: chunk of NALU data (excluding the original NALU header byte)

**Multiple NALUs per frame:**
- If a frame contains multiple NALUs (e.g., SPS + PPS + IDR), send each as separate RTP packets
- All NALUs in the same frame share the same RTP timestamp
- Set the RTP marker bit to 1 on the last packet of the last NALU in a frame

### 9. ONVIF Server

Implement minimal ONVIF support so that NVR software can discover the device and get the RTSP URL.

**WS-Discovery (UDP multicast):**
- Listen on UDP multicast `239.255.255.250:3702`
- Respond to `Probe` messages with a `ProbeMatch` containing the device endpoint
- The device type should include `tns:NetworkVideoTransmitter`

**ONVIF Device Service (HTTP/SOAP on `onvif_port`):**
- `GetCapabilities`: Return capabilities pointing to the media service URL
- `GetDeviceInformation`: Return manufacturer="Ubiquiti", model="UVC-G5-Bullet", firmware version, serial number

**ONVIF Media Service (HTTP/SOAP on `onvif_port`):**
- `GetProfiles`: Return one profile with H.264 video encoding
- `GetStreamUri`: Return `rtsp://<server_ip>:<rtsp_port>/stream` as the RTSP URI

**SOAP format:** ONVIF uses SOAP 1.2 over HTTP. Responses are XML. The implementation needs to:
1. Parse incoming SOAP XML requests (extract the action from the `SOAPAction` header or the body's XML namespace)
2. Generate appropriate SOAP XML responses

This is verbose but straightforward — the XML responses are mostly static templates with a few dynamic values (IP addresses, URLs).

### 10. Logging

Implement simple logging to a log file:
- Log level: INFO (connection events), WARN (parse errors), ERROR (fatal errors)
- Log to a file in the same directory as the executable: `flvproxy.log`
- Rotate when the file exceeds 10MB (keep one backup)
- Use a simple mutex-protected file writer

### 11. Error Handling and Reconnection

- If the camera disconnects, log it and wait for a new connection
- If a parse error occurs, log it and attempt to resync by scanning for the next FLV tag (read until you find a valid tag type byte at the expected position)
- If an RTSP client disconnects, clean up its resources
- Never crash — all errors should be caught and logged

### 12. Thread Architecture

```
Main thread → Service Control (SCM) → waits for stop event
    │
    ├── TCP listener thread (accepts camera connections)
    │     └── FLV parser (runs in the same thread, reads from TCP)
    │           └── Frame distributor (updates shared state, notifies client threads)
    │
    ├── RTSP server thread (accepts RTSP client connections)
    │     └── Per-client threads (one per RTSP client, sends RTP packets)
    │
    ├── ONVIF HTTP server thread (handles SOAP requests)
    │
    └── ONVIF WS-Discovery thread (UDP multicast listener)
```

Use `Arc<Mutex<>>` for shared state (StreamState, client list). Use channels (`std::sync::mpsc`) for communicating new frames to client threads.

---

## File Structure

```
src/
  main.rs              — Entry point, Windows service FFI, arg parsing (--install, --uninstall, --service; no arg = console foreground)
  config.rs            — Config file parsing
  service.rs           — Windows service lifecycle (SCM integration)
  flv_parser.rs        — FLV header + tag parsing, uPFLV prefix detection
  avc.rs               — AVCDecoderConfigurationRecord parsing, NALU extraction
  stream_state.rs      — Shared stream state (SPS/PPS, frame buffer, client list)
  rtsp_server.rs       — RTSP protocol implementation (OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN)
  rtp.rs               — RTP packetization (RFC 6184, FU-A fragmentation)
  sdp.rs               — SDP generation
  onvif_discovery.rs   — WS-Discovery (UDP multicast Probe/ProbeMatch)
  onvif_server.rs      — ONVIF Device Service + Media Service (SOAP over HTTP)
  logging.rs           — Simple file logger with rotation
```

---

## Key Specifications Reference

### FLV Tag Structure (11-byte header + payload + 4-byte prev tag size)
```
Byte 0:     Tag type (0x08=audio, 0x09=video, 0x12=script)
Bytes 1-3:  Data size (big-endian u24) — size of payload only
Bytes 4-6:  Timestamp low 24 bits (big-endian u24)
Byte 7:     Timestamp high 8 bits
Bytes 8-10: Stream ID (always 0x000000)
--- payload (data_size bytes) ---
Bytes 0-3:  Previous tag size (big-endian u32) = 11 + data_size
```

### Standard FLV Video Tag (CodecID=7, AVC)
```
Byte 0:     [FrameType:4][CodecID:4]  (0x17=keyframe+AVC, 0x27=inter+AVC)
Byte 1:     AVCPacketType (0=seq header, 1=NALU, 2=end)
Bytes 2-4:  Composition time (big-endian SI24)
Rest:       H.264 data
  - If AVCPacketType=0: AVCDecoderConfigurationRecord
  - If AVCPacketType=1: NALUs (4-byte big-endian length prefix + NALU data, repeated)
```

### Extended FLV Video Tag (IsExHeader=1)
```
Byte 0:     [1][FrameType:3][PacketType:4]
  (bit 7 = 1, bits 6-4 = FrameType, bits 3-0 = PacketType)
Bytes 1-4:  FourCC (4 ASCII bytes, e.g. "hvc1")
If PacketType=0 (SequenceStart):
  Rest:     Codec configuration record (AVCDecoderConfigurationRecord for H.264)
If PacketType=1 (CodedFrames):
  Bytes 5-7: Composition time (SI24)
  Rest:     H.264 NALUs (4-byte length-prefixed)
If PacketType=3 (CodedFramesX):
  Rest:     H.264 NALUs (4-byte length-prefixed, no composition time)
```

### AVCDecoderConfigurationRecord
```
Byte 0:       configurationVersion (1)
Byte 1:       AVCProfileIndication (e.g. 0x4D for Main profile)
Byte 2:       profile_compatibility
Byte 3:       AVCLevelIndication (e.g. 0x1F for level 3.1)
Byte 4:       0xFF (reserved 6 bits + lengthSizeMinusOne=3 → 4-byte NALU length prefix)
Byte 5:       0xE1 (reserved 3 bits + numSPS=1)
Bytes 6-7:    SPS length (big-endian u16)
Bytes 8..:    SPS NALU data (without start code)
Next byte:    numPPS (1)
Next 2 bytes: PPS length (big-endian u16)
Next bytes:   PPS NALU data (without start code)
```

### RTP Packet Structure (12-byte header + payload)
```
Byte 0:      [V:2][P:1][X:1][CC:4] = 0x80 (version 2, no padding, no extension, no CSRC)
Byte 1:      [M:1][PT:7] = 0x60 (marker=0, PT=96) or 0xE0 (marker=1, PT=96)
Bytes 2-3:   Sequence number (big-endian u16, increments per packet)
Bytes 4-7:   Timestamp (big-endian u32, 90kHz clock)
Bytes 8-11:  SSRC (random u32, constant per session)
--- payload ---
For single NALU: The NALU bytes (1-byte NALU header + data)
For FU-A: [FU indicator:1][FU header:1][fragment data]
```

### FU-A Fragmentation
```
Original NALU header byte: [forbidden:1][priority:2][type:5]
  e.g. 0x67 = forbidden=0, priority=3, type=7 (SPS)

FU indicator: (original_nalu_header & 0xE0) | 28
  = preserve forbidden+priority bits from original, set type to 28 (FU-A)

FU header: (start<<7) | (end<<6) | (original_nalu_header & 0x1F)
  = start/end flags + original NALU type

First packet:  start=1, end=0
Middle packets: start=0, end=0
Last packet:   start=0, end=1

Payload: chunk of NALU data (excluding the original NALU header byte)
```

### RTSP Protocol (Minimal)

**Request format (client → server):**
```
METHOD url RTSP/1.0\r\n
CSeq: <number>\r\n
[Session: <session_id>\r\n]
[Transport: <transport_spec>\r\n]
[other headers]\r\n
\r\n
[body]
```

**Response format (server to client):**
```
RTSP/1.0 <status_code> <status_text>\r\n
CSeq: <number>\r\n
[Session: <session_id>\r\n]
[Content-Length: <length>\r\n]
[Content-Type: <type>\r\n]
[other headers]\r\n
\r\n
[body]
```

**OPTIONS:**
```
Request: OPTIONS rtsp://server:port/stream RTSP/1.0
Response: 200 OK, Public: OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN
```

**DESCRIBE:**
```
Request: DESCRIBE rtsp://server:port/stream RTSP/1.0
Response: 200 OK, Content-Type: application/sdp, Content-Length: N
Body: <SDP>
```

**SETUP:**
```
Request: SETUP rtsp://server:port/stream/streamid=0 RTSP/1.0
         Transport: RTP/AVP;unicast;client_port=4588-4589 (UDP)
   OR   Transport: RTP/AVP/TCP;unicast;interleaved=0-1 (TCP)
Response: 200 OK, Session: <id>, Transport: <chosen transport>
```

**PLAY:**
```
Request: PLAY rtsp://server:port/stream RTSP/1.0
         Session: <id>
Response: 200 OK, Session: <id>, Range: npt=0.000-
```
(Server begins sending RTP packets)

**TEARDOWN:**
```
Request: TEARDOWN rtsp://server:port/stream RTSP/1.0
         Session: <id>
Response: 200 OK
```

### TCP Interleaved RTP
When using TCP interleaved transport, RTP packets are sent over the RTSP TCP connection:
```
Byte 0: '$' (0x24)
Byte 1: Channel (0 for video RTP, 1 for RTCP)
Bytes 2-3: RTP packet length (big-endian u16)
Bytes 4+: RTP packet data
```

### ONVIF SOAP Example (GetStreamUri response)
```xml
<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <trt:GetStreamUriResponse xmlns:trt="http://www.onvif.org/ver10/media/wsdl">
      <trt:MediaUri>
        <tt:Uri xmlns:tt="http://www.onvif.org/ver10/schema">rtsp://192.168.1.100:8554/stream</tt:Uri>
        <tt:InvalidAfterConnect>false</tt:InvalidAfterConnect>
        <tt:InvalidAfterReboot>false</tt:InvalidAfterReboot>
        <tt:Timeout>PT60S</tt:Timeout>
      </trt:MediaUri>
    </trt:GetStreamUriResponse>
  </s:Body>
</s:Envelope>
```

---

## Build and Test

### Build
```
cargo build --release --target x86_64-pc-windows-msvc
```

### Install as Windows Service
```
flvproxy.exe --install
```

### Uninstall
```
flvproxy.exe --uninstall
```

### Run as console app (for debugging)
```
flvproxy.exe
```

### Test with VLC
```
rtsp://<server_ip>:8554/stream
```

### Test RTSP with ffprobe
```
ffprobe rtsp://<server_ip>:8554/stream
```

---

## Camera Setup (Manual, Separate from the Proxy)

After the proxy is running, configure the camera to stream to it:

1. SSH into the camera: `ssh admin@<camera_ip>` (password: whatever you set)
2. View the streamer config: `cat /usr/etc/ubnt_streamer_sysid_a591.json`
3. Copy to a writable location and modify the `destinations` to point to the proxy:
   ```json
   "destinations": ["tcp://<proxy_ip>:7550"]
   ```
4. Restart the streamer: `killall ubnt_streamer`
5. The watchdog will restart it, and it will connect to the proxy

**Note:** The config modification approach may need refinement based on the camera's firmware. The config files in `/usr/etc/` are read-only, so you may need to:
- Copy to `/var/etc/` or `/tmp/` and create a symlink
- Or use a startup script to apply the changes on boot

This is a manual operational step, not part of the proxy software.
