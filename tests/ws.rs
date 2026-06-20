//! Integration tests for `flvproxy::ws` (build-plan step 18): RFC 6455
//! WebSocket framing over a loopback `TcpStream` pair. Covers the cases listed
//! in `plan/18-protect-ws-framing.md` Validation:
//! - `accept_key` matches the RFC 6455 §4.2.2 worked example.
//! - Handshake: a real `Upgrade` request → exact `101` response bytes; rejects
//!   missing key / bad version / garbage.
//! - Frame round-trip over loopback for the three length encodings (≤125, 126,
//!   127) and a masked client frame the decoder must unmask.
//! - Control frames: `Ping` yields a `Pong` reply; `Close` yields `None`.
//! - Fragmentation: three `Continuation` frames reassemble into one message.
//! - Over-sized fragmented message → `WsError::MessageTooLarge`.
//!
//! SHA-1's RFC 3174 vectors and the byte-exact handshake responses are also
//! unit-tested inside `src/ws.rs`; this file focuses on the socket-level
//! behavior that needs a real `Read + Write` stream.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

use flvproxy::ws::{accept_key, parse_frame, Opcode, WsConnection, WsError, WsFrame, WsHandshake};

/// Returns a connected loopback `(client, server)` pair. `client` is the
/// caller's side; `server` is the side `WsConnection` wraps.
fn loopback_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local_addr");
    let client = TcpStream::connect(addr).expect("connect");
    let (server, _) = listener.accept().expect("accept");
    (client, server)
}

/// Writes one raw WebSocket frame straight onto `stream` (no `WsConnection`),
/// optionally masked. Used to feed the decoder frames the server encoder cannot
/// produce (masked client frames, or control frames with a chosen opcode).
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
        for (i, &b) in payload.iter().enumerate() {
            out.push(b ^ mask_key[i & 3]);
        }
    } else {
        out.extend_from_slice(payload);
    }
    stream.write_all(&out).expect("write raw frame");
}

/// Reads one raw frame from `stream` (no `WsConnection`) and returns its
/// `(fin, opcode, payload)`; unmasking the payload if the mask bit was set.
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
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= mask_key[i & 3];
        }
    }
    (fin, opcode, payload)
}

#[test]
fn accept_key_matches_rfc6455_section_4_2_2_example() {
    assert_eq!(
        accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
        "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
    );
}

#[test]
fn handshake_upgrade_request_yields_exact_101_response_bytes() {
    let request = b"GET /camera/1.0/ws HTTP/1.1\r\n\
                    Host: 192.168.1.20:7442\r\n\
                    Origin: http://ws_camera_proto_secure_transfer\r\n\
                    Upgrade: websocket\r\n\
                    Connection: close, Upgrade\r\n\
                    Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                    Sec-WebSocket-Protocol: secure_transfer\r\n\
                    Sec-WebSocket-Version: 13\r\n\
                    Camera-MAC: 28704E11B531\r\n\
                    Camera-Model: UVC-G5-Bullet\r\n\
                    \r\n\r\n";
    let hs = WsHandshake::parse(request).expect("valid handshake");
    let resp = hs.response();
    let expected = b"HTTP/1.1 101 Switching Protocols\r\n\
                     Upgrade: websocket\r\n\
                     Connection: Upgrade\r\n\
                     Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\
                     Sec-WebSocket-Protocol: secure_transfer\r\n\
                     \r\n";
    assert_eq!(resp, expected);
}

#[test]
fn handshake_rejects_missing_key_bad_version_and_garbage() {
    let no_key = b"GET /s HTTP/1.1\r\nSec-WebSocket-Version: 13\r\n\r\n\r\n";
    assert_eq!(WsHandshake::parse(no_key), Err(WsError::MissingKey));

    let bad_version =
        b"GET /s HTTP/1.1\r\nSec-WebSocket-Key: k\r\nSec-WebSocket-Version: 12\r\n\r\n\r\n";
    assert_eq!(WsHandshake::parse(bad_version), Err(WsError::BadVersion));

    assert_eq!(
        WsHandshake::parse(b"totally not http\r\n\r\n"),
        Err(WsError::MalformedRequest)
    );
}

#[test]
fn frame_round_trip_inline_length_over_loopback() {
    let (client, server) = loopback_pair();
    let mut reader = WsConnection::new(server);
    let mut writer = WsConnection::new(client);

    let payload = vec![0xABu8; 125];
    writer
        .write_frame(&WsFrame {
            fin: true,
            opcode: Opcode::Binary,
            payload: payload.clone(),
        })
        .expect("write");
    let frame = reader.read_frame().expect("read").expect("frame");
    assert!(frame.fin);
    assert_eq!(frame.opcode, Opcode::Binary);
    assert_eq!(frame.payload, payload);
}

#[test]
fn frame_round_trip_16_bit_length_over_loopback() {
    let (client, server) = loopback_pair();
    let mut reader = WsConnection::new(server);
    let mut writer = WsConnection::new(client);

    let payload = vec![0x11u8; 200];
    writer
        .write_frame(&WsFrame {
            fin: true,
            opcode: Opcode::Binary,
            payload: payload.clone(),
        })
        .expect("write");
    let frame = reader.read_frame().expect("read").expect("frame");
    assert_eq!(frame.payload.len(), 200);
    assert_eq!(frame.payload, payload);
}

#[test]
fn frame_round_trip_64_bit_length_over_loopback() {
    let (client, server) = loopback_pair();
    let mut reader = WsConnection::new(server);
    let mut writer = WsConnection::new(client);

    let payload = vec![0x77u8; 70_000];
    writer
        .write_frame(&WsFrame {
            fin: true,
            opcode: Opcode::Binary,
            payload: payload.clone(),
        })
        .expect("write");
    let frame = reader.read_frame().expect("read").expect("frame");
    assert_eq!(frame.payload.len(), 70_000);
    assert_eq!(frame.payload, payload);
}

#[test]
fn decoder_unmasks_a_masked_client_frame() {
    let (mut client, server) = loopback_pair();
    let mut reader = WsConnection::new(server);
    let payload = b"hello masked world".to_vec();
    write_raw_frame(
        &mut client,
        0x2,
        true,
        &payload,
        Some([0x01, 0x02, 0x03, 0x04]),
    );

    let frame = reader.read_frame().expect("read").expect("frame");
    assert!(frame.fin);
    assert_eq!(frame.opcode, Opcode::Binary);
    assert_eq!(frame.payload, payload);
}

#[test]
fn ping_is_answered_with_a_pong_of_matching_payload() {
    let (mut client, server) = loopback_pair();
    let mut conn = WsConnection::new(server);

    let handle = thread::spawn(move || conn.read_frame());

    write_raw_frame(&mut client, 0x9, true, b"keepalive", None);
    let (fin, opcode, payload) = read_raw_frame(&mut client);
    assert!(fin);
    assert_eq!(opcode, 0xA);
    assert_eq!(payload, b"keepalive");

    write_raw_frame(&mut client, 0x2, true, b"after-pong", None);
    let outcome = handle
        .join()
        .expect("thread")
        .expect("read")
        .expect("frame");
    assert_eq!(outcome.opcode, Opcode::Binary);
    assert_eq!(outcome.payload, b"after-pong");
}

#[test]
fn close_frame_yields_clean_none() {
    let (mut client, server) = loopback_pair();
    let mut conn = WsConnection::new(server);

    let handle = thread::spawn(move || conn.read_frame());

    write_raw_frame(&mut client, 0x8, true, &[], None);
    let outcome = handle.join().expect("thread").expect("read ok");
    assert!(
        outcome.is_none(),
        "Close must surface as None, got {outcome:?}"
    );
}

#[test]
fn fragmented_message_reassembles_across_continuation_frames() {
    let (mut client, server) = loopback_pair();
    let mut conn = WsConnection::new(server);

    let handle = thread::spawn(move || conn.read_frame());

    write_raw_frame(&mut client, 0x2, false, b"part1-", None);
    write_raw_frame(&mut client, 0x0, false, b"part2-", None);
    write_raw_frame(&mut client, 0x0, true, b"part3", None);

    let frame = handle
        .join()
        .expect("thread")
        .expect("read ok")
        .expect("frame");
    assert!(frame.fin);
    assert_eq!(frame.opcode, Opcode::Binary);
    assert_eq!(frame.payload, b"part1-part2-part3");
}

#[test]
fn oversized_fragmented_message_is_rejected_without_unbounded_allocation() {
    let (mut client, server) = loopback_pair();
    let mut conn = WsConnection::new(server);

    let handle = thread::spawn(move || conn.read_frame());

    let half = vec![0u8; 32 * 1024];
    write_raw_frame(&mut client, 0x2, false, &half, None);
    write_raw_frame(&mut client, 0x0, false, &half, None);
    write_raw_frame(&mut client, 0x0, true, b"overflow", None);

    let outcome = handle.join().expect("thread");
    assert_eq!(outcome, Err(WsError::MessageTooLarge));
}

#[test]
fn parse_frame_returns_none_on_clean_close_before_first_byte() {
    let (client, server) = loopback_pair();
    drop(client);
    let mut server = server;
    assert_eq!(parse_frame(&mut server).expect("read"), None);
}
