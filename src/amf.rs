//! Minimal AMF0 (ActionScript Message Format 0) reader, sufficient to extract `videoWidth`, `videoHeight`, `videoFps` from an `onMetaData` FLV script-tag body (FLV tag type `0x12`). Other script tags (`onMpma`, `onClockSync`) are skipped without parsing. Robustness over completeness: every marker the real camera emits in those fields is decoded, anything unknown is skipped safely. Pure byte logic — no I/O, no logging — so it builds and tests on any platform.
//!
//! Read-only: this module never serializes AMF0. The reader is a private recursive-descent cursor over `&[u8]`; only `StreamMetadata`, `parse_on_metadata`, and `is_metadata_tag` are exposed.

/// AMF0 type marker for the `Number` value (8-byte big-endian IEEE 754 f64), per the AMF0 spec (Adobe `amf0_spec.pdf`, section "Number").
const MARKER_NUMBER: u8 = 0x00;
/// AMF0 type marker for the `Boolean` value (1 payload byte), per the AMF0 spec section "Boolean".
const MARKER_BOOLEAN: u8 = 0x01;
/// AMF0 type marker for the `String` value (u16 BE length + UTF-8 bytes), per the AMF0 spec section "String".
const MARKER_STRING: u8 = 0x02;
/// AMF0 type marker for the `Object` value (key/value pairs until the end marker), per the AMF0 spec section "Object".
const MARKER_OBJECT: u8 = 0x03;
/// AMF0 type marker for the `ECMA Array` value (u32 count hint then object-style pairs until the end marker), per the AMF0 spec section "ECMA Array".
const MARKER_ECMA_ARRAY: u8 = 0x08;
/// AMF0 end marker: terminates an `Object` or `ECMA Array` after an empty (zero-length) key. Per the AMF0 spec section "Object End Marker".
const MARKER_OBJECT_END: u8 = 0x09;
/// AMF0 type marker for the `StrictArray` value (u32 count + that many values), per the AMF0 spec section "Strict Array".
const MARKER_STRICT_ARRAY: u8 = 0x0A;
/// AMF0 type marker for the `Date` value (f64 timestamp + i16 timezone offset), per the AMF0 spec section "Date".
const MARKER_DATE: u8 = 0x0B;
/// AMF0 type marker for the `LongString` value (u32 length + UTF-8 bytes), per the AMF0 spec section "Long String".
const MARKER_LONG_STRING: u8 = 0x0C;

/// Size of the IEEE 754 double payload that follows a `MARKER_NUMBER` or the timestamp portion of a `MARKER_DATE`, in bytes.
const F64_PAYLOAD_BYTES: usize = 8;

/// Size of the i16 timezone offset that follows the f64 timestamp in a `MARKER_DATE`, in bytes.
const DATE_TZ_BYTES: usize = 2;

/// Script-tag name string carried as the first AMF0 value of an `onMetaData` body, per `PROJECT.md` → "Script Data Tags". 10 ASCII bytes; the AMF0 string-length field that precedes it is therefore `10`.
const ON_METADATA_NAME: &str = "onMetaData";

/// Decoded AMF0 value. The reader produces one `AmfValue` per cursor advance. Not exposed publicly: only the three `onMetaData`-derived fields are surfaced, via `StreamMetadata`.
#[derive(Debug, Clone, PartialEq)]
enum AmfValue {
    Number(f64),
    /// One payload byte interpreted as true iff non-zero.
    Boolean(bool),
    /// u16-length-prefixed UTF-8 string (lossy).
    String(String),
    /// Key/value pairs until the end marker.
    Object(Vec<(String, AmfValue)>),
    /// u32 count hint (ignored) then key/value pairs until the end marker.
    EcmaArray(Vec<(String, AmfValue)>),
    /// u32 count then that many values (no end marker).
    StrictArray(Vec<AmfValue>),
    /// f64 timestamp + i16 timezone; payload discarded.
    Date,
    /// u32-length-prefixed UTF-8 string (lossy).
    LongString(String),
    /// Standalone end marker encountered outside an object/array context.
    ObjectEnd,
    /// A marker this reader does not decode. Carries the offending byte. The cursor stops immediately after the marker — its value body length is unknown, so a containing object/array walk terminates here, returning the pairs it had already collected.
    Unknown(u8),
}

/// Stream metadata extracted from an `onMetaData` script tag. The width/height/fps fields are optional: a stream may omit any of them; they are consumed by stream state and SDP generation. `stream_name` carries the `streamName` property UniFi cameras set to `<MAC>_0` — the MAC-derived identifier the ONVIF Device service uses as the serial; `None` when the stream omits the property.
#[derive(Debug, Clone, PartialEq)]
pub struct StreamMetadata {
    /// `videoWidth` as a `u32`; negatives clamp to 0 via saturating cast.
    pub width: Option<u32>,
    /// `videoHeight` as a `u32`; negatives clamp to 0 via saturating cast.
    pub height: Option<u32>,
    /// `videoFps` as an `f32` (narrowed from the AMF0 f64).
    pub fps: Option<f32>,
    /// `streamName` verbatim from the `onMetaData` object (e.g. `"28704E11B531_0"`); the camera pipeline strips the `_N` stream-index suffix to recover the MAC-derived serial.
    pub stream_name: Option<String>,
}

/// Cheap peek answering "does this script-tag body begin with the AMF0 string marker for `onMetaData`?". Used by the FLV pipeline to decide whether to parse the body or skip it without touching the cursor. False on truncation or any preamble mismatch; never panics.
pub fn is_metadata_tag(body: &[u8]) -> bool {
    let name = ON_METADATA_NAME.as_bytes();
    let need = 1 + 2 + name.len();
    if body.len() < need {
        return false;
    }
    body[0] == MARKER_STRING && body[1] == 0 && body[2] == name.len() as u8 && body[3..need] == *name
}

/// Parses an `onMetaData` script-tag body into a `StreamMetadata` if, and only if, the first AMF0 value is the string `"onMetaData"` and the second is an ECMA array (or object) of properties. Walks the pairs, capturing `videoWidth` / `videoHeight` (Number → u32, negatives clamped to 0), `videoFps` (Number → f32), and `streamName` (String → verbatim); every other property is ignored.
///
/// Returns `None` when the first value is not the `"onMetaData"` string, the second value is not an ECMA array or object, or the body is malformed or truncated at any point the reader must consume. An unknown AMF0 marker encountered as a property value terminates the walk safely and returns the fields already read rather than `None`. Never panics.
pub fn parse_on_metadata(body: &[u8]) -> Option<StreamMetadata> {
    let mut reader = Reader::new(body);
    match reader.read_value()? {
        AmfValue::String(name) if name == ON_METADATA_NAME => {}
        _ => return None,
    }
    let pairs = match reader.read_value()? {
        AmfValue::EcmaArray(pairs) | AmfValue::Object(pairs) => pairs,
        _ => return None,
    };
    let mut meta = StreamMetadata { width: None, height: None, fps: None, stream_name: None };
    for (key, value) in pairs {
        match (key.as_str(), value) {
            ("videoWidth", AmfValue::Number(n)) => meta.width = Some(saturating_f64_to_u32(n)),
            ("videoHeight", AmfValue::Number(n)) => meta.height = Some(saturating_f64_to_u32(n)),
            ("videoFps", AmfValue::Number(n)) => meta.fps = Some(n as f32),
            ("streamName", AmfValue::String(s)) => meta.stream_name = Some(s),
            ("streamName", AmfValue::LongString(s)) => meta.stream_name = Some(s),
            _ => {}
        }
    }
    Some(meta)
}

/// Converts an AMF0 Number to a `u32` using Rust's saturating `as` cast: NaN maps to 0, negatives map to 0, and values above `u32::MAX` map to `u32::MAX`. This is robust against hostile or malformed numbers without an explicit clamp branch.
fn saturating_f64_to_u32(n: f64) -> u32 {
    n as u32
}

/// Push-based, recursive-descent cursor over a borrowed AMF0 byte buffer. Each `read_*` method returns `None` on truncation or malformed structure; the caller propagates `None` rather than panicking. The cursor never allocates beyond the slice it was given.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Reader<'a> {
        Reader { buf, pos: 0 }
    }

    fn read_u8(&mut self) -> Option<u8> {
        let b = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    fn read_u16(&mut self) -> Option<u16> {
        let bytes = self.read_bytes(2)?;
        Some(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32(&mut self) -> Option<u32> {
        let bytes = self.read_bytes(4)?;
        Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Borrows `n` contiguous bytes at the cursor and advances by `n`. `None` if the cursor cannot supply that many (truncation).
    fn read_bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        if end > self.buf.len() {
            return None;
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Some(slice)
    }

    /// Reads `len` bytes and decodes them as UTF-8 with the lossy replacement policy, returning a `String`. AMF0 strings are not guaranteed valid UTF-8 over the wire; lossy decoding never panics.
    fn read_lossy_string(&mut self, len: usize) -> Option<String> {
        let bytes = self.read_bytes(len)?;
        Some(String::from_utf8_lossy(bytes).into_owned())
    }

    /// Reads one AMF0 value at the cursor, advancing past its full encoding for every decoded marker. Returns `Some(AmfValue::Unknown(marker))` for any unrecognized marker, leaving the cursor just after that marker byte (its body length is unknowable). `None` on truncation.
    fn read_value(&mut self) -> Option<AmfValue> {
        let marker = self.read_u8()?;
        match marker {
            MARKER_NUMBER => {
                let bytes = self.read_bytes(F64_PAYLOAD_BYTES)?;
                let fixed: [u8; F64_PAYLOAD_BYTES] = bytes.try_into().ok()?;
                Some(AmfValue::Number(f64::from_be_bytes(fixed)))
            }
            MARKER_BOOLEAN => {
                let b = self.read_u8()?;
                Some(AmfValue::Boolean(b != 0))
            }
            MARKER_STRING => {
                let len = self.read_u16()? as usize;
                let s = self.read_lossy_string(len)?;
                Some(AmfValue::String(s))
            }
            MARKER_OBJECT => {
                let pairs = self.read_object_pairs()?;
                Some(AmfValue::Object(pairs))
            }
            MARKER_ECMA_ARRAY => {
                let _hint = self.read_u32()?;
                let pairs = self.read_object_pairs()?;
                Some(AmfValue::EcmaArray(pairs))
            }
            MARKER_OBJECT_END => Some(AmfValue::ObjectEnd),
            MARKER_STRICT_ARRAY => {
                let count = self.read_u32()?;
                let mut values = Vec::new();
                for _ in 0..count {
                    let v = self.read_value()?;
                    let unknown = matches!(v, AmfValue::Unknown(_));
                    values.push(v);
                    if unknown {
                        break;
                    }
                }
                Some(AmfValue::StrictArray(values))
            }
            MARKER_DATE => {
                let _timestamp = self.read_bytes(F64_PAYLOAD_BYTES)?;
                let _tz = self.read_bytes(DATE_TZ_BYTES)?;
                Some(AmfValue::Date)
            }
            MARKER_LONG_STRING => {
                let len = self.read_u32()? as usize;
                let s = self.read_lossy_string(len)?;
                Some(AmfValue::LongString(s))
            }
            other => Some(AmfValue::Unknown(other)),
        }
    }

    /// Reads AMF0 object/ECMA-array pairs: a repeating sequence of (u16-length-prefixed UTF-8 key, AMF0 value) terminated by an empty key (u16 length 0) followed by `MARKER_OBJECT_END`. Returns the pairs collected so far if an `Unknown` value is encountered — the cursor cannot locate the next key, so the walk stops cleanly with what was already decoded. `None` on truncation or an end-of-object byte that is not `MARKER_OBJECT_END`.
    fn read_object_pairs(&mut self) -> Option<Vec<(String, AmfValue)>> {
        let mut pairs = Vec::new();
        loop {
            let key_len = self.read_u16()?;
            if key_len == 0 {
                let end = self.read_u8()?;
                if end != MARKER_OBJECT_END {
                    return None;
                }
                return Some(pairs);
            }
            let key = self.read_lossy_string(key_len as usize)?;
            let value = self.read_value()?;
            let unknown = matches!(value, AmfValue::Unknown(_));
            pairs.push((key, value));
            if unknown {
                return Some(pairs);
            }
        }
    }
}
