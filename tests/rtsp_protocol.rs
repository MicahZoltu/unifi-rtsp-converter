//! Integration tests for `flvproxy::rtsp_server`: RTSP request parsing, response serialization, the five method handlers, and transport negotiation, asserting exact status codes, header values, session-state transitions, and byte-for-byte response wire format.

use flvproxy::rtsp_server::{handle_describe, handle_options, handle_play, handle_setup, handle_teardown, parse_request, Method, RtspRequest, RtspResponse, RtspSessions, Transport};
use flvproxy::stream_state::CodecParams;

/// Server IP passed to DESCRIBE so the SDP origin line is predictable.
const SERVER_IP: &str = "192.168.1.100";

/// Realistic-ish SPS with NALU header `0x67` and profile/compat/level `4D 40 1F` (Main profile, level 3.1), matching the SDP tests.
const SPS: &[u8] = &[0x67, 0x4D, 0x40, 0x1F, 0x96, 0x35, 0x40, 0x1E];

/// Realistic-ish PPS with NALU header `0x68`.
const PPS: &[u8] = &[0x68, 0xCE, 0x31, 0x12];

/// Builds `CodecParams` carrying `SPS`/`PPS` and a 30 fps rate.
fn codec() -> CodecParams {
    CodecParams { sps: SPS.to_vec(), pps: PPS.to_vec(), profile_indication: SPS[1], profile_compat: SPS[2], level_indication: SPS[3], width: Some(1920), height: Some(1080), fps: Some(30.0) }
}

/// Parses a complete request from a UTF-8 string, asserting the buffer was fully consumed and no error occurred.
fn parse_full(text: &str) -> RtspRequest {
    let (req, consumed) = parse_request(text.as_bytes()).expect("parsing should not error").expect("request should be complete");
    assert_eq!(consumed, text.len(), "parser must consume the whole buffer");
    req
}

/// Returns the value of the first header named `name` (case-insensitive) in `resp.headers`, or `None`. Note the `Session` header lives on `resp.session`; use `session_header` for it.
fn header_value<'a>(resp: &'a RtspResponse, name: &str) -> Option<&'a str> {
    resp.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

/// Returns the `Session:` header value (from the dedicated field), if any.
fn session_header(resp: &RtspResponse) -> Option<&str> {
    resp.session.as_deref()
}

/// Extracts the bare session id (text before any `;`) from a `Session:` header value.
fn session_id(value: &str) -> &str {
    value.split(';').next().expect("split always yields one").trim()
}

#[test]
fn parse_complete_options_request_fills_method_cseq_uri_and_consumes_all() {
    let req = parse_full("OPTIONS rtsp://server:554/stream RTSP/1.0\r\nCSeq: 7\r\n\r\n");
    assert_eq!(req.method, Method::Options);
    assert_eq!(req.uri, "rtsp://server:554/stream");
    assert_eq!(req.cseq, Some(7));
    assert!(req.body.is_empty());
}

#[test]
fn parse_request_without_terminator_returns_none_needing_more_data() {
    let result = parse_request(b"OPTIONS rtsp://server:554/stream RTSP/1.0\r\nCSeq: 7\r\n").expect("no error");
    assert!(result.is_none(), "incomplete request must yield Ok(None)");
}

#[test]
fn parse_describe_captures_accept_header() {
    let req = parse_full("DESCRIBE rtsp://server:554/stream RTSP/1.0\r\nCSeq: 1\r\nAccept: application/sdp\r\n\r\n");
    assert_eq!(req.method, Method::Describe);
    assert_eq!(req.accept.as_deref(), Some("application/sdp"));
}

#[test]
fn parse_setup_captures_transport_header_case_insensitively() {
    let req = parse_full("SETUP rtsp://server:554/stream/streamid=0 RTSP/1.0\r\nCSeq: 2\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n\r\n");
    assert_eq!(req.method, Method::Setup);
    assert_eq!(req.transport.as_deref(), Some("RTP/AVP/TCP;unicast;interleaved=0-1"));
}

#[test]
fn handle_options_returns_supported_methods() {
    let req = parse_full("OPTIONS rtsp://server:554/stream RTSP/1.0\r\nCSeq: 1\r\n\r\n");
    let resp = handle_options(&req);
    assert_eq!(resp.status, 200);
    assert_eq!(resp.cseq, Some(1));
    assert_eq!(header_value(&resp, "Public"), Some("OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN"));
}

#[test]
fn handle_setup_tcp_interleaved_echoes_transport_and_stores_interleaved_session() {
    let req = parse_full("SETUP rtsp://server:554/stream/streamid=0 RTSP/1.0\r\nCSeq: 2\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n\r\n");
    let mut sessions = RtspSessions::new();
    let resp = handle_setup(&req, &mut sessions);

    assert_eq!(resp.status, 200);
    assert_eq!(resp.cseq, Some(2));
    let session_header = session_header(&resp).expect("Session header present");
    let id = session_id(session_header);
    assert!(session_header.contains(";timeout=60"), "Session header must advertise the timeout: {session_header}",);
    let transport = header_value(&resp, "Transport").expect("Transport header present");
    assert!(transport.contains("interleaved=0-1"), "echoed Transport must contain interleaved=0-1: {transport}",);

    let stored = sessions.get(id).expect("session was registered");
    assert_eq!(stored.transport, Transport::Interleaved { rtp_ch: 0, rtcp_ch: 1 });
    assert!(!stored.playing);
}

#[test]
fn handle_setup_udp_echoes_client_and_server_ports() {
    let req = parse_full("SETUP rtsp://server:554/stream/streamid=0 RTSP/1.0\r\nCSeq: 3\r\nTransport: RTP/AVP;unicast;client_port=4588-4589\r\n\r\n");
    let mut sessions = RtspSessions::new();
    let resp = handle_setup(&req, &mut sessions);

    assert_eq!(resp.status, 200);
    let transport = header_value(&resp, "Transport").expect("Transport header present");
    assert!(transport.contains("client_port=4588-4589"), "echoed Transport must contain client_port=4588-4589: {transport}",);
    assert!(transport.contains("server_port="), "echoed Transport must contain a server_port pair: {transport}",);

    let session_header = session_header(&resp).expect("Session header present");
    let stored = sessions.get(session_id(session_header)).expect("session registered");
    match stored.transport.clone() {
        Transport::Udp { client_rtp, client_rtcp, server_rtp, server_rtcp } => {
            assert_eq!((client_rtp, client_rtcp), (4588, 4589));
            assert_eq!(server_rtcp, server_rtp + 1);
        }
        other => panic!("expected Udp transport, got {other:?}"),
    }
}

#[test]
fn handle_setup_bogus_transport_returns_461() {
    let req = parse_full("SETUP rtsp://server:554/stream/streamid=0 RTSP/1.0\r\nCSeq: 4\r\nTransport: RTP/AVP;unicast;mode=RECORD\r\n\r\n");
    let mut sessions = RtspSessions::new();
    let resp = handle_setup(&req, &mut sessions);
    assert_eq!(resp.status, 461);
    assert_eq!(resp.cseq, Some(4));
    assert!(sessions.get("anything").is_none(), "no session should be allocated");
}

#[test]
fn handle_play_on_known_session_returns_200_with_range_and_marks_playing() {
    let setup_req = parse_full("SETUP rtsp://server:554/stream/streamid=0 RTSP/1.0\r\nCSeq: 1\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n\r\n");
    let mut sessions = RtspSessions::new();
    let setup_resp = handle_setup(&setup_req, &mut sessions);
    let id = session_id(session_header(&setup_resp).expect("Session header"));

    let play_req = parse_full(&format!("PLAY rtsp://server:554/stream RTSP/1.0\r\nCSeq: 2\r\nSession: {id}\r\n\r\n"));
    let resp = handle_play(&play_req, &mut sessions);
    assert_eq!(resp.status, 200);
    assert_eq!(resp.cseq, Some(2));
    assert_eq!(header_value(&resp, "Range"), Some("npt=0.000-"));
    assert_eq!(session_id(session_header(&resp).expect("Session header")), id);
    assert!(sessions.get(id).expect("session still present").playing);
}

#[test]
fn handle_play_with_missing_session_returns_454() {
    let req = parse_full("PLAY rtsp://server:554/stream RTSP/1.0\r\nCSeq: 1\r\n\r\n");
    let mut sessions = RtspSessions::new();
    let resp = handle_play(&req, &mut sessions);
    assert_eq!(resp.status, 454);
    assert_eq!(resp.cseq, Some(1));
}

#[test]
fn handle_play_with_unknown_session_returns_454() {
    let req = parse_full("PLAY rtsp://server:554/stream RTSP/1.0\r\nCSeq: 1\r\nSession: DEADBEEF\r\n\r\n");
    let mut sessions = RtspSessions::new();
    let resp = handle_play(&req, &mut sessions);
    assert_eq!(resp.status, 454);
}

#[test]
fn handle_teardown_then_play_returns_200_then_454() {
    let setup_req = parse_full("SETUP rtsp://server:554/stream/streamid=0 RTSP/1.0\r\nCSeq: 1\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n\r\n");
    let mut sessions = RtspSessions::new();
    let setup_resp = handle_setup(&setup_req, &mut sessions);
    let id = session_id(session_header(&setup_resp).expect("Session header")).to_string();

    let teardown_req = parse_full(&format!("TEARDOWN rtsp://server:554/stream RTSP/1.0\r\nCSeq: 2\r\nSession: {id}\r\n\r\n"));
    let resp = handle_teardown(&teardown_req, &mut sessions);
    assert_eq!(resp.status, 200);
    assert_eq!(resp.cseq, Some(2));
    assert!(sessions.get(&id).is_none(), "session must be removed by TEARDOWN");

    let play_req = parse_full(&format!("PLAY rtsp://server:554/stream RTSP/1.0\r\nCSeq: 3\r\nSession: {id}\r\n\r\n"));
    let resp = handle_play(&play_req, &mut sessions);
    assert_eq!(resp.status, 454);
}

#[test]
fn handle_describe_before_codec_returns_503() {
    let req = parse_full("DESCRIBE rtsp://server:554/stream RTSP/1.0\r\nCSeq: 1\r\nAccept: application/sdp\r\n\r\n");
    let resp = handle_describe(&req, SERVER_IP, None);
    assert_eq!(resp.status, 503);
    assert_eq!(resp.cseq, Some(1));
    assert!(resp.body.is_empty());
}

#[test]
fn handle_describe_with_codec_returns_sdp_body() {
    let req = parse_full("DESCRIBE rtsp://server:554/stream RTSP/1.0\r\nCSeq: 1\r\nAccept: application/sdp\r\n\r\n");
    let codec = codec();
    let resp = handle_describe(&req, SERVER_IP, Some(&codec));
    assert_eq!(resp.status, 200);
    assert_eq!(header_value(&resp, "Content-Type"), Some("application/sdp"));
    let body = String::from_utf8(resp.body.clone()).expect("SDP is UTF-8");
    assert!(body.starts_with("v=0\r\n"), "SDP body must start with v=0: {body}");
    assert!(body.contains(&format!("o=- 0 0 IN IP4 {SERVER_IP}")));
    assert!(body.contains("a=rtpmap:96 H264/90000"));
}

#[test]
fn response_to_bytes_serializes_canonical_wire_format_without_body() {
    let resp = RtspResponse { status: 200, status_text: "OK".to_string(), cseq: Some(5), session: Some("DEADBEEF;timeout=60".to_string()), headers: vec![("Public".to_string(), "OPTIONS, DESCRIBE".to_string())], body: Vec::new() };
    let expected = b"RTSP/1.0 200 OK\r\n\
                     CSeq: 5\r\n\
                     Session: DEADBEEF;timeout=60\r\n\
                     Public: OPTIONS, DESCRIBE\r\n\
                     \r\n"
        .to_vec();
    assert_eq!(resp.to_bytes(), expected);
}

#[test]
fn response_to_bytes_appends_content_length_and_body_when_body_present() {
    let resp = RtspResponse { status: 200, status_text: "OK".to_string(), cseq: Some(1), session: None, headers: vec![("Content-Type".to_string(), "application/sdp".to_string())], body: b"v=0\r\n".to_vec() };
    let expected = b"RTSP/1.0 200 OK\r\n\
                     CSeq: 1\r\n\
                     Content-Type: application/sdp\r\n\
                     Content-Length: 5\r\n\
                     \r\n\
                     v=0\r\n"
        .to_vec();
    assert_eq!(resp.to_bytes(), expected);
}

#[test]
fn response_to_bytes_omits_content_length_when_body_empty() {
    let resp = RtspResponse { status: 461, status_text: "Unsupported transport".to_string(), cseq: Some(9), session: None, headers: Vec::new(), body: Vec::new() };
    let expected = b"RTSP/1.0 461 Unsupported transport\r\nCSeq: 9\r\n\r\n".to_vec();
    assert_eq!(resp.to_bytes(), expected);
}

#[test]
fn parse_request_consumes_body_and_not_just_headers() {
    let body = b"hello body";
    let mut buf = b"OPTIONS rtsp://x RTSP/1.0\r\nCSeq: 1\r\nContent-Length: 10\r\n\r\n".to_vec();
    buf.extend_from_slice(body);
    let (req, consumed) = parse_request(&buf).expect("ok").expect("complete");
    assert_eq!(consumed, buf.len());
    assert_eq!(req.body, body);
}

#[test]
fn parse_request_with_partial_body_returns_none() {
    let mut buf = b"OPTIONS rtsp://x RTSP/1.0\r\nCSeq: 1\r\nContent-Length: 10\r\n\r\n".to_vec();
    buf.extend_from_slice(b"short");
    assert!(parse_request(&buf).expect("ok").is_none());
}

#[test]
fn parse_request_header_names_match_case_insensitively() {
    let req = parse_full("DESCRIBE rtsp://x RTSP/1.0\r\ncseq: 42\r\nACCEPT: application/sdp\r\n\r\n");
    assert_eq!(req.cseq, Some(42));
    assert_eq!(req.accept.as_deref(), Some("application/sdp"));
}

#[test]
fn parse_request_with_unrecognized_method_yields_other() {
    let req = parse_full("GET_PARAMETER rtsp://x RTSP/1.0\r\nCSeq: 1\r\n\r\n");
    assert_eq!(req.method, Method::Other("GET_PARAMETER".to_string()));
}

#[test]
fn handle_request_without_cseq_returns_400() {
    let req = parse_full("OPTIONS rtsp://x RTSP/1.0\r\n\r\n");
    let mut sessions = RtspSessions::new();
    let resp = flvproxy::rtsp_server::handle_request(&req, &mut sessions, SERVER_IP, None);
    assert_eq!(resp.status, 400);
    assert!(resp.cseq.is_none());
}

#[test]
fn handle_request_with_unknown_method_returns_501() {
    let req = parse_full("GET_PARAMETER rtsp://x RTSP/1.0\r\nCSeq: 1\r\n\r\n");
    let mut sessions = RtspSessions::new();
    let resp = flvproxy::rtsp_server::handle_request(&req, &mut sessions, SERVER_IP, None);
    assert_eq!(resp.status, 501);
    assert_eq!(resp.cseq, Some(1));
}

#[test]
fn handle_request_routes_describe_to_sdp_body() {
    let req = parse_full("DESCRIBE rtsp://x RTSP/1.0\r\nCSeq: 1\r\nAccept: application/sdp\r\n\r\n");
    let codec = codec();
    let mut sessions = RtspSessions::new();
    let resp = flvproxy::rtsp_server::handle_request(&req, &mut sessions, SERVER_IP, Some(&codec));
    assert_eq!(resp.status, 200);
    assert!(!resp.body.is_empty());
}
