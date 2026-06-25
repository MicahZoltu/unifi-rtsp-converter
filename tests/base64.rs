//! Integration tests for the shared `flvproxy::base64` encoder against the RFC 4648 §4 worked vectors plus an arbitrary 3-byte vector, asserting exact output.

use flvproxy::base64::base64_encode;

#[test]
fn base64_rfc4648_empty_is_empty() {
    assert_eq!(base64_encode(b""), "");
}

#[test]
fn base64_rfc4648_single_byte_f() {
    assert_eq!(base64_encode(b"f"), "Zg==");
}

#[test]
fn base64_rfc4648_two_bytes_fo() {
    assert_eq!(base64_encode(b"fo"), "Zm8=");
}

#[test]
fn base64_rfc4648_three_bytes_foo() {
    assert_eq!(base64_encode(b"foo"), "Zm9v");
}

#[test]
fn base64_rfc4648_four_bytes_foob() {
    assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
}

#[test]
fn base64_rfc4648_five_bytes_fooba() {
    assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
}

#[test]
fn base64_rfc4648_six_bytes_foobar() {
    assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
}

#[test]
fn base64_three_byte_vector_deadbe() {
    assert_eq!(base64_encode(&[0xDE, 0xAD, 0xBE]), "3q2+");
}
