//! Minimal hand-rolled JSON parser/emitter covering only the shapes the UniFi Protect AVClient protocol uses: objects, arrays, strings, integers, floats, bools, null. Zero-crates per the project constraint — no `serde_json`. The subset is bounded to the AVClient envelope shapes and is not silently expanded by pulling a crate.
//!
//! Not a general-purpose JSON library: it parses a single value with no trailing tokens, emits compact JSON preserving object key insertion order, and rejects unescaped control bytes in strings. The single caller is `protect_controller`; the ONVIF cluster speaks SOAP/XML, not JSON. Promoting it from a private submodule of `protect_controller` to its own module isolates the parser for audit and unit testing rather than for reuse — the AVClient session logic that remains in `protect_controller` is what an auditor of that module actually wants to read, and the parser's edge cases (surrogate pairs, big-integer precision, trailing-token rejection) are exercised here in isolation.

/// A JSON number, kept as the narrowest exact integer/float kind so `messageId`/`inResponseTo`/`t1`/`t2` round-trip without f64 precision loss.
#[derive(Debug, Clone, PartialEq)]
pub enum JsonNumber {
    /// A non-negative integer lexeme (the common case for AVClient numbers).
    UInt(u64),
    /// A negative integer lexeme.
    Int(i64),
    /// A lexeme containing `.` or an exponent.
    Float(f64),
}

/// A decoded JSON value. Object key order is preserved as-inserted so the emitter produces deterministic, byte-exact output for tests.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Num(JsonNumber),
    Str(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

/// Parser failure modes. Kept `Debug + PartialEq` so unit tests can assert the exact variant.
#[derive(Debug, Clone, PartialEq)]
pub enum JsonError {
    /// Input ended before a complete value.
    Eof,
    /// An unexpected byte was encountered (carries the byte).
    UnexpectedByte(u8),
    /// A number lexeme did not parse.
    InvalidNumber,
    /// An invalid `\uXXXX` / surrogate pair / escape sequence.
    InvalidEscape,
    /// A string contained invalid UTF-8 (cannot happen for well-formed escapes, but `String::from_utf8` is the final authority).
    InvalidUtf8String,
}

impl Json {
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// Coerces a number value to `u64` (truncating floats); `None` for non-numbers.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Json::Num(JsonNumber::UInt(n)) => Some(*n),
            Json::Num(JsonNumber::Int(n)) => u64::try_from(*n).ok(),
            Json::Num(JsonNumber::Float(f)) => Some(*f as u64),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }
}

/// Parses `input` as exactly one JSON value (with optional surrounding whitespace). Trailing non-whitespace bytes are an error.
pub fn parse(input: &[u8]) -> Result<Json, JsonError> {
    let mut parser = Parser { bytes: input, pos: 0 };
    parser.skip_ws();
    let value = parser.value()?;
    parser.skip_ws();
    if parser.pos != parser.bytes.len() {
        return Err(JsonError::UnexpectedByte(parser.bytes[parser.pos]));
    }
    Ok(value)
}

/// Emits `value` as compact JSON (no whitespace), preserving object key insertion order.
pub fn emit(value: &Json) -> String {
    let mut out = String::new();
    emit_into(value, &mut out);
    out
}

pub fn obj(pairs: &[(&str, Json)]) -> Json {
    Json::Object(pairs.iter().map(|(key, value)| ((*key).to_string(), value.clone())).collect())
}

pub fn uint(n: u64) -> Json {
    Json::Num(JsonNumber::UInt(n))
}

pub fn str_v(s: &str) -> Json {
    Json::Str(s.to_string())
}

pub fn bool_v(b: bool) -> Json {
    Json::Bool(b)
}

/// Builds a `Json::Array` from the given items in order.
pub fn array(items: Vec<Json>) -> Json {
    Json::Array(items)
}

fn emit_into(value: &Json, out: &mut String) {
    match value {
        Json::Null => out.push_str("null"),
        Json::Bool(true) => out.push_str("true"),
        Json::Bool(false) => out.push_str("false"),
        Json::Num(JsonNumber::UInt(n)) => out.push_str(&n.to_string()),
        Json::Num(JsonNumber::Int(n)) => out.push_str(&n.to_string()),
        Json::Num(JsonNumber::Float(n)) => out.push_str(&n.to_string()),
        Json::Str(s) => emit_str(s, out),
        Json::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                emit_into(item, out);
            }
            out.push(']');
        }
        Json::Object(entries) => {
            out.push('{');
            for (i, (key, value)) in entries.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                emit_str(key, out);
                out.push(':');
                emit_into(value, out);
            }
            out.push('}');
        }
    }
}

/// Emits a JSON string with mandatory escaping of `"`, `\`, the short escapes, and any control byte `< 0x20` as `\uXXXX`.
fn emit_str(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Recursive-descent parser cursor over the input byte slice.
struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let byte = self.peek();
        if byte.is_some() {
            self.pos += 1;
        }
        byte
    }

    fn skip_ws(&mut self) {
        while let Some(byte) = self.peek() {
            if matches!(byte, b' ' | b'\n' | b'\r' | b'\t') {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn value(&mut self) -> Result<Json, JsonError> {
        self.skip_ws();
        match self.peek() {
            None => Err(JsonError::Eof),
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => self.string().map(Json::Str),
            Some(b't') => self.literal(b"true", Json::Bool(true)),
            Some(b'f') => self.literal(b"false", Json::Bool(false)),
            Some(b'n') => self.literal(b"null", Json::Null),
            Some(byte) if byte == b'-' || byte.is_ascii_digit() => self.number(),
            Some(byte) => Err(JsonError::UnexpectedByte(byte)),
        }
    }

    fn literal(&mut self, lit: &[u8], value: Json) -> Result<Json, JsonError> {
        if self.bytes.get(self.pos..self.pos + lit.len()) == Some(lit) {
            self.pos += lit.len();
            Ok(value)
        } else {
            Err(JsonError::UnexpectedByte(self.peek().unwrap_or(0)))
        }
    }

    fn number(&mut self) -> Result<Json, JsonError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        while let Some(byte) = self.peek() {
            if byte.is_ascii_digit() {
                self.pos += 1;
            } else {
                break;
            }
        }
        let mut is_float = false;
        if self.peek() == Some(b'.') {
            is_float = true;
            self.pos += 1;
            while let Some(byte) = self.peek() {
                if byte.is_ascii_digit() {
                    self.pos += 1;
                } else {
                    break;
                }
            }
        }
        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            is_float = true;
            self.pos += 1;
            if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                self.pos += 1;
            }
            while let Some(byte) = self.peek() {
                if byte.is_ascii_digit() {
                    self.pos += 1;
                } else {
                    break;
                }
            }
        }
        let lexeme = std::str::from_utf8(&self.bytes[start..self.pos]).map_err(|_| JsonError::InvalidNumber)?;
        if is_float {
            let parsed: f64 = lexeme.parse().map_err(|_| JsonError::InvalidNumber)?;
            Ok(Json::Num(JsonNumber::Float(parsed)))
        } else if let Some(digits) = lexeme.strip_prefix('-') {
            let magnitude: u64 = digits.parse().map_err(|_| JsonError::InvalidNumber)?;
            let signed = i64::try_from(magnitude).ok().and_then(|m| m.checked_neg()).ok_or(JsonError::InvalidNumber)?;
            Ok(Json::Num(JsonNumber::Int(signed)))
        } else {
            let parsed: u64 = lexeme.parse().map_err(|_| JsonError::InvalidNumber)?;
            Ok(Json::Num(JsonNumber::UInt(parsed)))
        }
    }

    fn string(&mut self) -> Result<String, JsonError> {
        self.pos += 1; // opening quote
        let mut out: Vec<u8> = Vec::new();
        loop {
            let byte = self.bump().ok_or(JsonError::Eof)?;
            match byte {
                b'"' => return String::from_utf8(out).map_err(|_| JsonError::InvalidUtf8String),
                b'\\' => {
                    let escape = self.bump().ok_or(JsonError::Eof)?;
                    match escape {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'/' => out.push(b'/'),
                        b'n' => out.push(b'\n'),
                        b't' => out.push(b'\t'),
                        b'r' => out.push(b'\r'),
                        b'b' => out.push(0x08),
                        b'f' => out.push(0x0C),
                        b'u' => {
                            let code = self.read_hex4()?;
                            if (0xD800..=0xDBFF).contains(&code) {
                                if self.bump() != Some(b'\\') || self.bump() != Some(b'u') {
                                    return Err(JsonError::InvalidEscape);
                                }
                                let low = self.read_hex4()?;
                                if !(0xDC00..=0xDFFF).contains(&low) {
                                    return Err(JsonError::InvalidEscape);
                                }
                                let combined = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00);
                                push_codepoint(&mut out, combined)?;
                            } else {
                                push_codepoint(&mut out, code)?;
                            }
                        }
                        _ => return Err(JsonError::InvalidEscape),
                    }
                }
                byte if byte < 0x20 => return Err(JsonError::UnexpectedByte(byte)),
                byte => out.push(byte),
            }
        }
    }

    fn read_hex4(&mut self) -> Result<u32, JsonError> {
        let mut code = 0u32;
        for _ in 0..4 {
            let hex = self.bump().ok_or(JsonError::Eof)?;
            let digit = (hex as char).to_digit(16).ok_or(JsonError::InvalidEscape)?;
            code = code * 16 + digit;
        }
        Ok(code)
    }

    fn object(&mut self) -> Result<Json, JsonError> {
        self.pos += 1; // '{'
        let mut entries = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Json::Object(entries));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(JsonError::UnexpectedByte(self.peek().unwrap_or(0)));
            }
            let key = self.string()?;
            self.skip_ws();
            if self.peek() != Some(b':') {
                return Err(JsonError::UnexpectedByte(self.peek().unwrap_or(0)));
            }
            self.pos += 1;
            let value = self.value()?;
            entries.push((key, value));
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Json::Object(entries));
                }
                _ => return Err(JsonError::UnexpectedByte(self.peek().unwrap_or(0))),
            }
        }
    }

    fn array(&mut self) -> Result<Json, JsonError> {
        self.pos += 1; // '['
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Json::Array(items));
        }
        loop {
            let value = self.value()?;
            items.push(value);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Json::Array(items));
                }
                _ => return Err(JsonError::UnexpectedByte(self.peek().unwrap_or(0))),
            }
        }
    }
}

/// UTF-8 encodes `code` into `out`. Returns `InvalidEscape` for code points that are not valid scalar values (lone surrogates reaching here).
fn push_codepoint(out: &mut Vec<u8>, code: u32) -> Result<(), JsonError> {
    let mut buf = [0u8; 4];
    let c = char::from_u32(code).ok_or(JsonError::InvalidEscape)?;
    out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_round_trips_avclient_envelope() {
        let input = br#"{"from":"ubnt_avclient","functionName":"ubnt_avclient_timeSync","inResponseTo":0,"messageId":79364096,"payload":{"timeDelta":0},"responseExpected":true,"timeStamp":"2026-06-19T15:52:59.817+00:00","to":"UniFiVideo"}"#;
        let value = parse(input).expect("valid JSON");
        let emitted = emit(&value);
        assert_eq!(emitted.as_bytes(), input);
    }

    #[test]
    fn json_parses_uint_without_precision_loss() {
        let value = parse(b"9007199254740993").expect("big uint"); // 2^53 + 1
        assert_eq!(value.as_u64(), Some(9_007_199_254_740_993));
    }

    #[test]
    fn json_rejects_trailing_garbage() {
        // After `{}` the parser skips the space, then fails on the `t`.
        assert_eq!(parse(b"{} trailing"), Err(JsonError::UnexpectedByte(b't')));
    }
}
