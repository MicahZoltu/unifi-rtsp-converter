//! XML helpers shared by the ONVIF SOAP services (`onvif_server`) and the WS-Discovery announcer (`onvif_discovery`). Both speak SOAP 1.2 over XML and both need (a) the five-character XML escape applied to every dynamic value inserted into a response/announcement template so a configured IP / firmware / serial containing markup cannot break the envelope or inject elements, and (b) the SOAP envelope and WS-Addressing namespace URIs that every envelope they emit declares. Owning these in one place keeps the dependency graph honest: both ONVIF modules depend on `xml`, neither depends on the other, and `xml_escape` is no longer a `pub(crate)` escape hatch borrowed across the module boundary. Pure string logic — no I/O, no networking — so it builds and tests on any platform.

/// SOAP 1.2 envelope namespace, declared on every `<s:Envelope>` the proxy emits (ONVIF responses and WS-Discovery announcements alike), per RFC 3902 / `http://www.w3.org/2003/05/soap-envelope`.
pub const NS_ENVELOPE: &str = "http://www.w3.org/2003/05/soap-envelope";

/// WS-Addressing (August 2004) namespace, declared on every envelope carrying `wsa:Action` / `wsa:Address` / `wsa:RelatesTo` elements — both the ONVIF Fault's `wsa:ActionNotSupported` subcode and the WS-Discovery `Hello`/`Bye`/`ProbeMatch` headers. Per `http://schemas.xmlsoap.org/ws/2004/08/addressing`.
pub const NS_ADDRESSING: &str = "http://schemas.xmlsoap.org/ws/2004/08/addressing";

/// Escapes the five XML special characters (`&` `<` `>` `"` `'`) per XML 1.0 §2.4. Applied to every dynamic value inserted into a response/announcement template so a configured IP / firmware / serial containing markup cannot break the envelope or inject elements.
pub fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xml_escape_replaces_all_five_special_characters() {
        assert_eq!(xml_escape("10.0.0.1&<>\"'"), "10.0.0.1&amp;&lt;&gt;&quot;&apos;");
    }

    #[test]
    fn xml_escape_leaves_plain_text_unchanged() {
        assert_eq!(xml_escape("192.168.1.10"), "192.168.1.10");
    }
}
