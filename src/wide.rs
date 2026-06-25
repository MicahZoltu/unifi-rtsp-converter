//! UTF-16 wide-string helpers for Win32 `*W` APIs. Two operations, each used by every Windows FFI module in the tree: `to_wide` encodes a Rust string as a NUL-terminated UTF-16 `Vec<u16>` (the form `*W` functions expect), and `wide_to_string` decodes a NUL-terminated UTF-16 slice back to a lossy `String` for diagnostics. Cross-platform so the unit tests run in CI; the Windows-only FFI paths (`service::win`, `elevate::win`, `cert_gen::win`) are the only callers. Deduplicating the three prior copies (`service::to_wide`, `elevate::to_wide`, `cert_gen::win::wide_nul`) keeps one NUL-termination invariant in one place — a missing trailing NUL in any one copy was the kind of bug that would surface as a silent Win32 buffer-overrun, not a compile error.

/// Encodes `s` as a NUL-terminated UTF-16 wide string, the form Win32 `*W` APIs expect: each `u16` is one UTF-16 unit, and a trailing `0` terminator is appended so the buffer can be passed wherever a `PCWSTR` / `LPCWSTR` is required.
pub fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Decodes a NUL-terminated UTF-16 slice (as produced by `to_wide`) back to a `String` for display in log/error messages, dropping any trailing NULs. Lossy so a malformed wide string never panics on a diagnostic path. Cross-platform so its test runs in CI.
pub fn wide_to_string(wide: &[u16]) -> String {
    let end = wide.len().saturating_sub(wide.iter().rev().take_while(|&&c| c == 0).count());
    String::from_utf16_lossy(&wide[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_wide_ascii_appends_nul() {
        assert_eq!(to_wide("abc"), vec![b'a' as u16, b'b' as u16, b'c' as u16, 0]);
    }

    #[test]
    fn to_wide_empty_is_just_nul() {
        assert_eq!(to_wide(""), vec![0]);
    }

    #[test]
    fn to_wide_non_ascii_round_trips() {
        let s = "héllo€";
        let wide = to_wide(s);
        assert_eq!(*wide.last().unwrap(), 0, "must be NUL-terminated");
        let without_nul = &wide[..wide.len() - 1];
        assert_eq!(String::from_utf16_lossy(without_nul), s, "round-trip must preserve non-ASCII");
    }

    #[test]
    fn wide_to_string_strips_trailing_nul() {
        assert_eq!(wide_to_string(&to_wide("NT SERVICE\\flvproxy")), "NT SERVICE\\flvproxy");
        assert_eq!(wide_to_string(&to_wide("")), "");
        assert_eq!(wide_to_string(&[0u16]), "");
        assert_eq!(wide_to_string(&[]), "");
    }
}
