//! Standard Base64 (RFC 4648 §4) encoder with `=` padding. Shared by `sdp` (the `sprop-parameter-sets` SDP field) and `ws` (the RFC 6455 §1.3 `Sec-WebSocket-Accept` derivation), so a reader of either need not follow a dependency on the other. Mirrors `calendar`'s precedent: a shared encoding concern gets its own module so the two consumers depend downward on it without one knowing about the other, instead of `ws` reaching into `sdp` for a generic encoder that is not an SDP concept.

/// Standard Base64 alphabet, per RFC 4648 §4.
const BASE64_ALPHABET: [u8; 64] = *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Base64 padding character, per RFC 4648 §4.
const BASE64_PAD: u8 = b'=';

/// Encodes `input` as standard Base64 (RFC 4648 §4) with `=` padding.
///
/// Implemented by hand per the project's zero-crates constraint. Output is the shortest correct encoding; an empty input yields an empty string.
pub fn base64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 3 <= input.len() {
        let triplet = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8) | input[i + 2] as u32;
        push_base64_quartet(&mut out, triplet);
        i += 3;
    }
    let remainder = input.len() - i;
    if remainder == 1 {
        let triplet = (input[i] as u32) << 16;
        out.push(char_from_alphabet((triplet >> 18) & 0x3F));
        out.push(char_from_alphabet((triplet >> 12) & 0x3F));
        out.push(BASE64_PAD as char);
        out.push(BASE64_PAD as char);
    } else if remainder == 2 {
        let triplet = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8);
        out.push(char_from_alphabet((triplet >> 18) & 0x3F));
        out.push(char_from_alphabet((triplet >> 12) & 0x3F));
        out.push(char_from_alphabet((triplet >> 6) & 0x3F));
        out.push(BASE64_PAD as char);
    }
    out
}

/// Appends one 24-bit triplet as four Base64 characters to `out`.
fn push_base64_quartet(out: &mut String, triplet: u32) {
    out.push(char_from_alphabet((triplet >> 18) & 0x3F));
    out.push(char_from_alphabet((triplet >> 12) & 0x3F));
    out.push(char_from_alphabet((triplet >> 6) & 0x3F));
    out.push(char_from_alphabet(triplet & 0x3F));
}

fn char_from_alphabet(value: u32) -> char {
    BASE64_ALPHABET[value as usize] as char
}
