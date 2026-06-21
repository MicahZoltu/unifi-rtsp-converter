//! Integration tests for `flvproxy::protect_controller` (build-plan step 19):
//! the AVClient JSON protocol over a loopback RFC 6455 WebSocket pair. Covers
//! the cases listed in `plan/19-protect-avclient-7442.md` Validation:
//! - Each handler: feed the documented request JSON → assert the exact reply
//!   JSON byte-for-byte (`inResponseTo` echoes the request `messageId`).
//! - `timeSync` reply's `t1`/`t2` are within a few ms of now (bounded assert
//!   against the real clock).
//! - A multi-message sequence reaches the `ready` state.
//! - Unknown `functionName` → ok reply, no panic, session continues.
//! - Malformed JSON frame → frame skipped, session continues (no crash).
//! - `ping-<N>` keepalive answered with a `pong-<N>` text frame (both the WS
//!   Ping control frame shape and the Text-frame shape the camera may use).
//! - `HELLO_PROTOCOL_VERSION` and every feature flag asserted by name.
//!
//! The test harness plays the camera side: it performs the WS opening handshake
//! on a loopback `TcpStream` pair, then sends AVClient JSON as binary WS frames
//! (and `ping-<N>` as Ping/Text frames) and reads the controller's replies. The
//! server side hands the post-handshake stream to `AvClientSession::run`. TLS
//! is not exercised here (the protocol is TLS-agnostic); the WS handshake uses
//! `ws::WsHandshake` from step 18.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use flvproxy::protect_controller::{
    AvClientSession, FEATURE_ACCELEROMETER, FEATURE_ADJUSTABLE_IR, FEATURE_HDR,
    FEATURE_MOTION_ZONES, HELLO_PROTOCOL_VERSION,
};
use flvproxy::ws::{encode_frame, Opcode, WsFrame, WsHandshake};

/// Device-ID captured by the step-16 recon (`40941af9-...`); reused so the
/// generic ok reply's `deviceID` is a realistic value.
const DEVICE_ID: &str = "40941af9-a767-5d-662-b57a-deacddd4354d";

/// Pinned clock value: 2025-01-01T00:00:00.000+00:00 = 1_735_689_600_000 ms,
/// verified by hand (55*365 + 14 leap days = 20089 days since epoch).
const FIXED_NOW_MS: u64 = 1_735_689_600_000;

/// The ISO 8601 string `format_iso8601_utc(FIXED_NOW_MS)` must produce.
const ISO_FIXED: &str = "2025-01-01T00:00:00.000+00:00";

/// `Sec-WebSocket-Key` used by every test's client upgrade (the value from the
/// RFC 6455 §4.2.2 worked example; its accept key is known and asserted in
/// `tests/ws.rs`).
const WS_KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";

/// Returns a connected loopback `(client, server)` pair.
fn loopback_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local_addr");
    let client = TcpStream::connect(addr).expect("connect");
    let (server, _) = listener.accept().expect("accept");
    (client, server)
}

/// Server side of the WS opening handshake: read the request, send the `101`.
fn server_handshake(stream: &mut TcpStream) {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        stream.read_exact(&mut byte).expect("read request byte");
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let handshake = WsHandshake::parse(&buf).expect("parse upgrade");
    stream.write_all(&handshake.response()).expect("write 101");
}

/// Client side of the WS opening handshake: send the upgrade, read the `101`.
fn client_handshake(stream: &mut TcpStream) {
    let request = format!(
        "GET /camera/1.0/ws HTTP/1.1\r\n\
         Host: 127.0.0.1\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {WS_KEY}\r\n\
         Sec-WebSocket-Protocol: secure_transfer\r\n\
         Sec-WebSocket-Version: 13\r\n\
         \r\n"
    );
    stream.write_all(request.as_bytes()).expect("write request");
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        stream.read_exact(&mut byte).expect("read 101 byte");
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
    }
}

/// Writes one raw WS frame straight onto `stream` (optionally masked). Used to
/// feed the controller frames the high-level server encoder cannot produce
/// (masked client binary frames, or Ping/Text keepalives).
fn write_raw_frame(
    stream: &mut TcpStream,
    opcode: u8,
    fin: bool,
    payload: &[u8],
    mask: Option<[u8; 4]>,
) {
    let mut b0 = opcode & 0x0F;
    if fin {
        b0 |= 0x80;
    }
    let mut out = Vec::with_capacity(payload.len() + 14);
    out.push(b0);
    let len = payload.len();
    let masked = mask.is_some();
    let mut b1 = if len <= 125 {
        len as u8
    } else if len <= u16::MAX as usize {
        126
    } else {
        127
    };
    if masked {
        b1 |= 0x80;
    }
    out.push(b1);
    if len > 125 && len <= u16::MAX as usize {
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else if len > u16::MAX as usize {
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    let mask_key = mask.unwrap_or([0u8; 4]);
    if masked {
        out.extend_from_slice(&mask_key);
    }
    if masked {
        for (i, &byte) in payload.iter().enumerate() {
            out.push(byte ^ mask_key[i & 3]);
        }
    } else {
        out.extend_from_slice(payload);
    }
    stream.write_all(&out).expect("write raw frame");
}

/// Reads one raw WS frame from `stream`, unmasking if needed, and returns its
/// `(fin, opcode, payload)`.
fn read_raw_frame(stream: &mut TcpStream) -> (bool, u8, Vec<u8>) {
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).expect("read header");
    let fin = header[0] & 0x80 != 0;
    let opcode = header[0] & 0x0F;
    let masked = header[1] & 0x80 != 0;
    let mut len = (header[1] & 0x7F) as usize;
    if len == 126 {
        let mut ext = [0u8; 2];
        stream.read_exact(&mut ext).expect("read len16");
        len = u16::from_be_bytes(ext) as usize;
    } else if len == 127 {
        let mut ext = [0u8; 8];
        stream.read_exact(&mut ext).expect("read len64");
        len = u64::from_be_bytes(ext) as usize;
    }
    let mut mask_key = [0u8; 4];
    if masked {
        stream.read_exact(&mut mask_key).expect("read mask");
    }
    let mut payload = vec![0u8; len];
    if len > 0 {
        stream.read_exact(&mut payload).expect("read payload");
    }
    if masked {
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask_key[i & 3];
        }
    }
    (fin, opcode, payload)
}

/// Runs `AvClientSession` on the server side after completing the WS handshake.
/// Returns whether the session reached `ready` before a clean close.
fn run_server_session(mut stream: TcpStream) -> bool {
    server_handshake(&mut stream);
    let mut session = AvClientSession::with_start_and_clock(
        stream,
        DEVICE_ID.to_string(),
        1,
        Box::new(|| FIXED_NOW_MS),
    );
    let outcome = session.run();
    assert!(outcome.is_ok(), "session should close cleanly: {outcome:?}");
    session.is_ready()
}

/// The exact bytes of a `timeSync` request the camera sends (step-16 recon).
fn timesync_request(message_id: u64) -> Vec<u8> {
    format!(
        r#"{{"from":"ubnt_avclient","functionName":"ubnt_avclient_timeSync","inResponseTo":0,"messageId":{message_id},"payload":{{"timeDelta":0}},"responseExpected":true,"timeStamp":"2026-06-19T15:52:59.817+00:00","to":"UniFiVideo"}}"#
    )
    .into_bytes()
}

/// The exact `timeSync` reply the controller must emit (pinned clock).
fn expected_timesync_reply(message_id: u64, controller_message_id: u64) -> String {
    format!(
        r#"{{"from":"UniFiVideo","functionName":"ubnt_avclient_timeSync","inResponseTo":{message_id},"messageId":{controller_message_id},"payload":{{"t1":1735689600000,"t2":1735689600000}},"responseExpected":false,"timeStamp":"{ISO_FIXED}","to":"ubnt_avclient"}}"#
    )
}

/// The exact generic ok reply the controller must emit for `function_name`
/// (pinned clock, `messageId` starting at 1).
fn expected_ok_reply(function_name: &str, message_id: u64, controller_message_id: u64) -> String {
    format!(
        r#"{{"from":"UniFiVideo","functionName":"{function_name}","inResponseTo":{message_id},"messageId":{controller_message_id},"payload":{{"statusCode":0,"status":"ok","deviceID":"{DEVICE_ID}"}},"responseExpected":false,"timeStamp":"{ISO_FIXED}","to":"ubnt_avclient"}}"#
    )
}

#[test]
fn timesync_reply_is_byte_exact_and_echoes_request_message_id() {
    let (mut client, server) = loopback_pair();
    let handle = thread::spawn(move || run_server_session(server));

    client_handshake(&mut client);
    let request = timesync_request(79_364_096);
    write_raw_frame(&mut client, 0x2, true, &request, None);

    let (fin, opcode, payload) = read_raw_frame(&mut client);
    assert!(fin);
    assert_eq!(opcode, 0x2, "JSON replies travel as Binary frames");
    assert_eq!(
        String::from_utf8(payload).expect("utf8"),
        expected_timesync_reply(79_364_096, 1)
    );

    drop(client);
    assert!(handle.join().expect("server thread"));
}

#[test]
fn paramagreement_reply_is_byte_exact_generic_ok() {
    let (mut client, server) = loopback_pair();
    let handle = thread::spawn(move || run_server_session(server));

    client_handshake(&mut client);
    let request = r#"{"from":"ubnt_avclient","functionName":"ubnt_avclient_paramAgreement","inResponseTo":0,"messageId":42,"payload":{},"responseExpected":true,"timeStamp":"2026-06-19T15:53:00.000+00:00","to":"UniFiVideo"}"#;
    write_raw_frame(&mut client, 0x2, true, request.as_bytes(), None);

    let (_, opcode, payload) = read_raw_frame(&mut client);
    assert_eq!(opcode, 0x2);
    assert_eq!(
        String::from_utf8(payload).expect("utf8"),
        expected_ok_reply("ubnt_avclient_paramAgreement", 42, 1)
    );

    drop(client);
    let _ = handle.join().expect("server thread");
}

#[test]
fn unknown_function_name_yields_ok_reply_and_continues() {
    let (mut client, server) = loopback_pair();
    let handle = thread::spawn(move || run_server_session(server));

    client_handshake(&mut client);
    let request = r#"{"from":"ubnt_avclient","functionName":"ubnt_avclient_totallyUnknown","inResponseTo":0,"messageId":7,"payload":{},"responseExpected":true,"timeStamp":"2026-06-19T15:53:00.000+00:00","to":"UniFiVideo"}"#;
    write_raw_frame(&mut client, 0x2, true, request.as_bytes(), None);

    let (_, opcode, payload) = read_raw_frame(&mut client);
    assert_eq!(opcode, 0x2);
    assert_eq!(
        String::from_utf8(payload).expect("utf8"),
        expected_ok_reply("ubnt_avclient_totallyUnknown", 7, 1)
    );

    // Session must still be alive: a follow-up timeSync gets a normal reply.
    write_raw_frame(&mut client, 0x2, true, &timesync_request(99), None);
    let (_, opcode, payload) = read_raw_frame(&mut client);
    assert_eq!(opcode, 0x2);
    assert_eq!(
        String::from_utf8(payload).expect("utf8"),
        expected_timesync_reply(99, 2)
    );

    drop(client);
    assert!(handle.join().expect("server thread"));
}

#[test]
fn malformed_json_frame_is_skipped_without_crashing() {
    let (mut client, server) = loopback_pair();
    let handle = thread::spawn(move || run_server_session(server));

    client_handshake(&mut client);
    // Garbage that is not valid JSON: no reply must be sent for this frame.
    write_raw_frame(&mut client, 0x2, true, b"{not json at all", None);
    // A valid frame immediately after must still be answered (session continued).
    write_raw_frame(&mut client, 0x2, true, &timesync_request(5), None);

    let (_, opcode, payload) = read_raw_frame(&mut client);
    assert_eq!(opcode, 0x2);
    assert_eq!(
        String::from_utf8(payload).expect("utf8"),
        expected_timesync_reply(5, 1)
    );

    drop(client);
    assert!(handle.join().expect("server thread"));
}

#[test]
fn multi_message_sequence_reaches_ready_state() {
    let (mut client, server) = loopback_pair();
    let handle = thread::spawn(move || run_server_session(server));

    client_handshake(&mut client);
    for function_name in [
        "ubnt_avclient_hello",
        "ubnt_avclient_paramAgreement",
        "ubnt_avclient_timeSync",
        "ubnt_avclient_getSystemStats",
    ] {
        let request = format!(
            r#"{{"from":"ubnt_avclient","functionName":"{function_name}","inResponseTo":0,"messageId":{mid},"payload":{{}},"responseExpected":true,"timeStamp":"2026-06-19T15:53:00.000+00:00","to":"UniFiVideo"}}"#,
            mid = function_name.len() // arbitrary distinct message ids
        );
        write_raw_frame(&mut client, 0x2, true, request.as_bytes(), None);
        let (_, opcode, _payload) = read_raw_frame(&mut client);
        assert_eq!(opcode, 0x2, "each message gets a reply");
    }

    drop(client);
    assert!(
        handle.join().expect("server thread"),
        "session must be ready after the sequence"
    );
}

#[test]
fn ws_ping_carrying_ping_zero_is_answered_with_text_pong_zero() {
    let (mut client, server) = loopback_pair();
    let handle = thread::spawn(move || run_server_session(server));

    client_handshake(&mut client);
    // opcode 0x9 (WS Ping control frame) with UniFi text payload "ping-0".
    write_raw_frame(&mut client, 0x9, true, b"ping-0", None);
    let (fin, opcode, payload) = read_raw_frame(&mut client);
    assert!(fin);
    assert_eq!(
        opcode, 0x1,
        "UniFi keepalive must be answered with a Text frame"
    );
    assert_eq!(payload, b"pong-0");

    // Session continues: a following timeSync gets `messageId` 1 (the keepalive
    // does not consume a controller messageId).
    write_raw_frame(&mut client, 0x2, true, &timesync_request(1), None);
    let (_, _, payload) = read_raw_frame(&mut client);
    assert_eq!(
        String::from_utf8(payload).expect("utf8"),
        expected_timesync_reply(1, 1)
    );

    drop(client);
    assert!(handle.join().expect("server thread"));
}

#[test]
fn text_frame_carrying_ping_n_is_answered_with_text_pong_n() {
    let (mut client, server) = loopback_pair();
    let handle = thread::spawn(move || run_server_session(server));

    client_handshake(&mut client);
    // The "text ping" shape `DEBT.md`'s summary also describes: opcode 0x1
    // (Text) with payload "ping-7".
    write_raw_frame(&mut client, 0x1, true, b"ping-7", None);
    let (_, opcode, payload) = read_raw_frame(&mut client);
    assert_eq!(opcode, 0x1);
    assert_eq!(payload, b"pong-7");

    drop(client);
    let _ = handle.join().expect("server thread");
}

#[test]
fn standard_ws_ping_without_ping_prefix_is_answered_with_standard_pong() {
    let (mut client, server) = loopback_pair();
    let handle = thread::spawn(move || run_server_session(server));

    client_handshake(&mut client);
    // A non-UniFi Ping (no "ping" prefix) must fall back to RFC 6455 §5.5: echo
    // with a WS Pong control frame.
    write_raw_frame(&mut client, 0x9, true, b"keepalive", None);
    let (_, opcode, payload) = read_raw_frame(&mut client);
    assert_eq!(opcode, 0xA, "standard Ping -> standard Pong");
    assert_eq!(payload, b"keepalive");

    drop(client);
    let _ = handle.join().expect("server thread");
}

#[test]
fn timesync_reply_t1_t2_are_within_a_few_ms_of_now_with_real_clock() {
    let (mut client, mut server) = loopback_pair();
    // Real-clock session (not pinned).
    let handle = thread::spawn(move || {
        server_handshake(&mut server);
        let mut session = AvClientSession::new(server, DEVICE_ID.to_string());
        let _ = session.run();
    });

    client_handshake(&mut client);
    write_raw_frame(&mut client, 0x2, true, &timesync_request(1), None);
    let (_, _, payload) = read_raw_frame(&mut client);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("post-epoch")
        .as_millis() as u64;
    let reply = String::from_utf8(payload).expect("utf8");
    // Extract the t1/t2 integers from the compact reply without a JSON dep.
    let t1 = extract_u64_after(&reply, "\"t1\":").expect("t1 present");
    let t2 = extract_u64_after(&reply, "\"t2\":").expect("t2 present");
    let tolerance = 5_000;
    assert!(
        t1.abs_diff(now) <= tolerance,
        "t1 {t1} not within {tolerance} ms of now {now}"
    );
    assert!(
        t2.abs_diff(now) <= tolerance,
        "t2 {t2} not within {tolerance} ms of now {now}"
    );

    drop(client);
    handle.join().expect("server thread");
}

#[test]
fn hello_reply_carries_protocol_version_and_features() {
    let (mut client, server) = loopback_pair();
    let handle = thread::spawn(move || run_server_session(server));

    client_handshake(&mut client);
    let request = r#"{"from":"ubnt_avclient","functionName":"ubnt_avclient_hello","inResponseTo":0,"messageId":3,"payload":{},"responseExpected":true,"timeStamp":"2026-06-19T15:53:00.000+00:00","to":"UniFiVideo"}"#;
    write_raw_frame(&mut client, 0x2, true, request.as_bytes(), None);
    let (_, _, payload) = read_raw_frame(&mut client);
    let reply = String::from_utf8(payload).expect("utf8");

    let expected = format!(
        r#"{{"from":"UniFiVideo","functionName":"ubnt_avclient_hello","inResponseTo":3,"messageId":1,"payload":{{"protocolVersion":{HELLO_PROTOCOL_VERSION},"features":{{"accelerometer":{FEATURE_ACCELEROMETER},"adjustableIR":{FEATURE_ADJUSTABLE_IR},"hdr":{FEATURE_HDR},"motionZones":{FEATURE_MOTION_ZONES}}}}},"responseExpected":false,"timeStamp":"{ISO_FIXED}","to":"ubnt_avclient"}}"#
    );
    assert_eq!(reply, expected);

    drop(client);
    let _ = handle.join().expect("server thread");
}

#[test]
fn constants_have_their_declared_baseline_values() {
    assert_eq!(HELLO_PROTOCOL_VERSION, 67);
    const { assert!(FEATURE_ACCELEROMETER) };
    const { assert!(FEATURE_ADJUSTABLE_IR) };
    const { assert!(!FEATURE_HDR) };
    const { assert!(FEATURE_MOTION_ZONES) };
}

/// Finds `needle` in `haystack` and parses the unsigned integer that follows
/// it (up to the next non-digit). Used to extract `t1`/`t2` from a reply
/// without depending on the private JSON module.
fn extract_u64_after(haystack: &str, needle: &str) -> Option<u64> {
    let start = haystack.find(needle)? + needle.len();
    let digits: String = haystack[start..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse().ok()
}

/// Ensure the `WsFrame` re-exports used by the test harness still compile
/// against the public surface (a cheap guard against accidental removal).
#[test]
fn ws_frame_public_surface_is_usable() {
    let frame = WsFrame {
        fin: true,
        opcode: Opcode::Binary,
        payload: vec![1, 2, 3],
    };
    let mut sink: Vec<u8> = Vec::new();
    encode_frame(&mut sink, &frame).expect("encode");
    assert!(!sink.is_empty());
}

/// Runs `AvClientSession` with a configured 7550 stream destination (so it
/// sends a controller-initiated `ChangeVideoSettings` after `timeSync`).
/// Returns whether the session reached `ready`.
fn run_server_session_with_stream(mut stream: TcpStream) -> bool {
    server_handshake(&mut stream);
    let mut session = AvClientSession::with_start_and_clock(
        stream,
        DEVICE_ID.to_string(),
        1,
        Box::new(|| FIXED_NOW_MS),
    )
    .with_stream_destination(
        "tcp://192.168.0.1:7550?retryInterval=1&connectTimeout=5".to_string(),
        Some("F09FC2A1B2C3_0".to_string()),
    );
    let outcome = session.run();
    assert!(outcome.is_ok(), "session should close cleanly: {outcome:?}");
    assert!(
        session.change_video_settings_sent(),
        "ChangeVideoSettings must have been sent after hello"
    );
    session.is_ready()
}

/// A minimal `hello` request the camera sends after completing timeSync.
/// Only the fields the controller's dispatch matches on (`functionName`,
/// `messageId`) are needed for the test.
fn hello_request(message_id: u64) -> Vec<u8> {
    format!(
        r#"{{"from":"ubnt_avclient","functionName":"ubnt_avclient_hello","inResponseTo":0,"messageId":{message_id},"payload":{{}},"responseExpected":false,"timeStamp":"2026-06-20T19:08:17.446+00:00","to":"UniFiVideo"}}"#
    )
    .into_bytes()
}

/// After the camera sends `hello` (the post-timeSync handshake advancement),
/// the controller sends the adoption sequence — `paramAgreement` then
/// `ChangeVideoSettings` — pointing one `extendedFlv` stream at the configured
/// 7550 destination. Real-camera testing (step-20 interim recon) proved the
/// sequence: sending the adoption commands before `hello` caused the camera to
/// reset; after `hello`, the camera is ready. Pinned byte-exact.
#[test]
fn paramagreement_then_change_video_settings_sent_after_hello() {
    let (mut client, server) = loopback_pair();
    let handle = thread::spawn(move || run_server_session_with_stream(server));

    client_handshake(&mut client);
    // Camera sends timeSync → controller replies (no adoption driver yet).
    write_raw_frame(&mut client, 0x2, true, &timesync_request(79_364_096), None);

    // Frame 1: the timeSync reply (messageId 1). No adoption frames follow
    // because hello hasn't been received yet.
    let (_, op1, payload1) = read_raw_frame(&mut client);
    assert_eq!(op1, 0x2, "timeSync reply is a Binary frame");
    assert_eq!(
        String::from_utf8(payload1).expect("utf8"),
        expected_timesync_reply(79_364_096, 1)
    );

    // Camera sends hello → controller replies, then sends the adoption
    // sequence (paramAgreement messageId 2, ChangeVideoSettings messageId 3).
    write_raw_frame(&mut client, 0x2, true, &hello_request(79_364_100), None);

    // Frame 2: the hello reply (messageId 2).
    let (_, op2, payload2) = read_raw_frame(&mut client);
    assert_eq!(op2, 0x2, "hello reply is a Binary frame");
    assert!(String::from_utf8(payload2)
        .expect("utf8")
        .contains("ubnt_avclient_hello"));

    // Frame 3: the unsolicited paramAgreement command (messageId 3).
    let (_, op3, payload3) = read_raw_frame(&mut client);
    assert_eq!(op3, 0x2, "paramAgreement is a Binary frame");
    let pa = String::from_utf8(payload3).expect("utf8");
    let expected_pa = format!(
        r#"{{"from":"UniFiVideo","functionName":"ubnt_avclient_paramAgreement","inResponseTo":0,"messageId":3,"payload":{{"enableStatusCodes":true,"useHeartbeats":false,"heartbeatsTimeoutMs":10000}},"responseExpected":true,"timeStamp":"{ISO_FIXED}","to":"ubnt_avclient"}}"#
    );
    assert_eq!(pa, expected_pa, "paramAgreement payload must match");

    // Frame 4: the unsolicited ChangeVideoSettings command (messageId 4).
    let (_, op4, payload4) = read_raw_frame(&mut client);
    assert_eq!(op4, 0x2, "ChangeVideoSettings is a Binary frame");
    let cmd = String::from_utf8(payload4).expect("utf8");
    let expected_cv = format!(
        r#"{{"from":"UniFiVideo","functionName":"ChangeVideoSettings","inResponseTo":0,"messageId":4,"payload":{{"video":{{"video1":{{"avSerializer":{{"destinations":["tcp://192.168.0.1:7550?retryInterval=1&connectTimeout=5"],"parameters":{{"streamName":"F09FC2A1B2C3_0","withTalkback":false}},"type":"extendedFlv"}}}}}}}},"responseExpected":true,"timeStamp":"{ISO_FIXED}","to":"ubnt_avclient"}}"#
    );
    assert_eq!(cmd, expected_cv, "ChangeVideoSettings payload must match");

    drop(client);
    assert!(handle.join().expect("server thread reached ready"));
}

/// With no stream destination configured, the session stays purely reactive
/// and never sends `ChangeVideoSettings` (the step-19 test behavior).
#[test]
fn without_stream_destination_no_change_video_settings_is_sent() {
    let (mut client, server) = loopback_pair();
    let handle = thread::spawn(move || {
        let mut stream = server;
        server_handshake(&mut stream);
        let mut session = AvClientSession::with_start_and_clock(
            stream,
            DEVICE_ID.to_string(),
            1,
            Box::new(|| FIXED_NOW_MS),
        );
        let outcome = session.run();
        assert!(outcome.is_ok());
        assert!(!session.change_video_settings_sent());
        session.is_ready()
    });

    client_handshake(&mut client);
    write_raw_frame(&mut client, 0x2, true, &timesync_request(79_364_096), None);

    // Only the timeSync reply arrives — no second (ChangeVideoSettings) frame.
    let (_, op, payload) = read_raw_frame(&mut client);
    assert_eq!(op, 0x2);
    assert_eq!(
        String::from_utf8(payload).expect("utf8"),
        expected_timesync_reply(79_364_096, 1)
    );

    drop(client);
    let _ = handle.join().expect("server thread");
}
