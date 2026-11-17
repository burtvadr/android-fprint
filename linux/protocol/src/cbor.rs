//! Canonical CBOR (CTAP2 profile) restricted to the subset allowed by
//! `PROTOCOL.md` §8.5.
//!
//! Two properties matter for security here:
//!
//! 1. **Canonical-form enforcement on decode.** A decoder rejects any input that
//!    is not already the unique shortest, sorted, definite-length encoding of the
//!    value it denotes. Without this, "sign the encoding" would not be equivalent
//!    to "sign the request": two byte strings could denote the same logical
//!    request and be signed interchangeably.
//! 2. **Deterministic re-encoding.** `encode(&decode(x)) == x` for every `x` the
//!    decoder accepts. This is asserted by the unit tests.
//!
//! Major types 0, 1, 2, 3, 4, 5 plus the simple values `false` and `true` are
//! permitted. Tags, floats, `undefined`, indefinite lengths and non-shortest
//! integers are all rejected.

use std::fmt;

/// Maximum nesting depth. Guards the recursive decoder against stack exhaustion
/// from hostile input.
pub const MAX_DEPTH: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// Major type 0.
    Uint(u64),
    /// Major type 1. Represents the integer `-1 - n`.
    Nint(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    /// Map entries in canonical order (keys sorted by encoded bytes, unique).
    Map(Vec<(Value, Value)>),
    Bool(bool),
}

impl Value {
    pub fn text(s: impl Into<String>) -> Value {
        Value::Text(s.into())
    }

    pub fn bytes(b: impl Into<Vec<u8>>) -> Value {
        Value::Bytes(b.into())
    }

    /// Builds a map from key/value pairs. Entries are sorted into canonical order
    /// at construction time so that callers cannot accidentally produce an
    /// unsorted map.
    pub fn map<I, K>(entries: I) -> Value
    where
        I: IntoIterator<Item = (K, Value)>,
        K: Into<String>,
    {
        let mut pairs: Vec<(Value, Value)> = entries
            .into_iter()
            .map(|(k, v)| (Value::Text(k.into()), v))
            .collect();
        pairs.sort_by(|a, b| cmp_encoded(&a.0, &b.0));
        Value::Map(pairs)
    }

    /// Looks up a text key in a map. Returns `None` for non-maps or absent keys.
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Map(pairs) => pairs
                .iter()
                .find(|(k, _)| matches!(k, Value::Text(t) if t == key))
                .map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(t) => Some(t),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    pub fn as_uint(&self) -> Option<u64> {
        match self {
            Value::Uint(u) => Some(*u),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Enforces that the value contains only the types permitted by §8.5.
    pub fn is_allowed_type(&self) -> bool {
        match self {
            Value::Uint(_) | Value::Nint(_) | Value::Bytes(_) | Value::Text(_) | Value::Bool(_) => {
                true
            }
            Value::Array(items) => items.iter().all(|v| v.is_allowed_type()),
            Value::Map(pairs) => pairs
                .iter()
                .all(|(k, v)| k.is_allowed_type() && v.is_allowed_type()),
        }
    }

    /// Enforces R5 (unique keys) and R4 (sorted keys) for a map built by hand.
    pub fn is_canonically_ordered(&self) -> bool {
        match self {
            Value::Map(pairs) => {
                for w in pairs.windows(2) {
                    match cmp_encoded(&w[0].0, &w[1].0) {
                        std::cmp::Ordering::Less => {}
                        // Equal keys means a duplicate, which is forbidden.
                        _ => return false,
                    }
                }
                pairs
                    .iter()
                    .all(|(k, v)| k.is_canonically_ordered() && v.is_canonically_ordered())
            }
            Value::Array(items) => items.iter().all(|v| v.is_canonically_ordered()),
            _ => true,
        }
    }
}

/// Bytewise comparison of two encoded CBOR values: shorter-is-smaller on a
/// prefix, otherwise lexicographic. This is the CTAP2 canonical map key order.
fn cmp_encoded(a: &Value, b: &Value) -> std::cmp::Ordering {
    let ea = encode(a);
    let eb = encode(b);
    ea.as_slice().cmp(eb.as_slice())
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodeError(pub String);

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cbor encode error: {}", self.0)
    }
}

impl std::error::Error for EncodeError {}

fn write_head(out: &mut Vec<u8>, major: u8, arg: u64) {
    let m = major << 5;
    if arg < 24 {
        out.push(m | arg as u8);
    } else if arg <= u8::MAX as u64 {
        out.push(m | 24);
        out.push(arg as u8);
    } else if arg <= u16::MAX as u64 {
        out.push(m | 25);
        out.extend_from_slice(&(arg as u16).to_be_bytes());
    } else if arg <= u32::MAX as u64 {
        out.push(m | 26);
        out.extend_from_slice(&(arg as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&arg.to_be_bytes());
    }
}

pub fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(value, &mut out);
    out
}

fn encode_into(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Uint(u) => write_head(out, 0, *u),
        Value::Nint(n) => write_head(out, 1, *n),
        Value::Bytes(b) => {
            write_head(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        Value::Text(t) => {
            write_head(out, 3, t.len() as u64);
            out.extend_from_slice(t.as_bytes());
        }
        Value::Array(items) => {
            write_head(out, 4, items.len() as u64);
            for item in items {
                encode_into(item, out);
            }
        }
        Value::Map(pairs) => {
            write_head(out, 5, pairs.len() as u64);
            for (k, v) in pairs {
                encode_into(k, out);
                encode_into(v, out);
            }
        }
        Value::Bool(false) => out.push(0xf4),
        Value::Bool(true) => out.push(0xf5),
    }
}

// ---------------------------------------------------------------------------
// Strict decoding
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Ran out of input.
    Truncated,
    /// A byte outside the permitted major types / a forbidden simple value.
    ForbiddenType(u8),
    /// Major type 6 (tags).
    Tag,
    /// Indefinite-length item (additional information 31).
    IndefiniteLength,
    /// An argument that was not encoded in its shortest form.
    NonCanonicalInteger,
    /// Map keys not in canonical order, or a duplicate key.
    UnsortedOrDuplicateKeys,
    /// Invalid UTF-8, a surrogate, or an overlong encoding.
    InvalidText,
    /// Valid CBOR but structurally invalid for this protocol.
    Canonical,
    /// Nesting deeper than `MAX_DEPTH`.
    TooDeep,
    /// Trailing bytes after the top-level item.
    TrailingBytes,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::Truncated => write!(f, "cbor: truncated input"),
            DecodeError::ForbiddenType(b) => write!(f, "cbor: forbidden type byte 0x{b:02x}"),
            DecodeError::Tag => write!(f, "cbor: tags are forbidden"),
            DecodeError::IndefiniteLength => write!(f, "cbor: indefinite lengths are forbidden"),
            DecodeError::NonCanonicalInteger => write!(f, "cbor: integer not in shortest form"),
            DecodeError::UnsortedOrDuplicateKeys => {
                write!(f, "cbor: map keys unsorted or duplicated")
            }
            DecodeError::InvalidText => write!(f, "cbor: text string is not canonical UTF-8"),
            DecodeError::Canonical => write!(f, "cbor: non-canonical encoding"),
            DecodeError::TooDeep => write!(f, "cbor: nesting too deep"),
            DecodeError::TrailingBytes => write!(f, "cbor: trailing bytes after top-level item"),
        }
    }
}

impl std::error::Error for DecodeError {}

struct Decoder<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    fn new(input: &'a [u8]) -> Self {
        Decoder { input, pos: 0 }
    }

    fn byte(&mut self) -> Result<u8, DecodeError> {
        let b = *self.input.get(self.pos).ok_or(DecodeError::Truncated)?;
        self.pos += 1;
        Ok(b)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let end = self.pos.checked_add(n).ok_or(DecodeError::Truncated)?;
        if end > self.input.len() {
            return Err(DecodeError::Truncated);
        }
        let s = &self.input[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    /// Reads the initial byte and returns `(major, additional_information)`.
    fn head(&mut self) -> Result<(u8, u8), DecodeError> {
        let b = self.byte()?;
        Ok((b >> 5, b & 0x1f))
    }

    /// Reads the argument, enforcing R2/R3 (shortest form).
    fn argument(&mut self, ai: u8) -> Result<u64, DecodeError> {
        Ok(match ai {
            0..=23 => ai as u64,
            24 => {
                let v = self.byte()? as u64;
                if v < 24 {
                    return Err(DecodeError::NonCanonicalInteger);
                }
                v
            }
            25 => {
                let b = self.take(2)?;
                let v = u16::from_be_bytes([b[0], b[1]]) as u64;
                if v <= u8::MAX as u64 {
                    return Err(DecodeError::NonCanonicalInteger);
                }
                v
            }
            26 => {
                let b = self.take(4)?;
                let v = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64;
                if v <= u16::MAX as u64 {
                    return Err(DecodeError::NonCanonicalInteger);
                }
                v
            }
            27 => {
                let b = self.take(8)?;
                let v = u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
                if v <= u32::MAX as u64 {
                    return Err(DecodeError::NonCanonicalInteger);
                }
                v
            }
            28..=30 => return Err(DecodeError::ForbiddenType(ai)),
            31 => return Err(DecodeError::IndefiniteLength),
            _ => unreachable!(),
        })
    }

    fn value(&mut self, depth: usize) -> Result<Value, DecodeError> {
        if depth > MAX_DEPTH {
            return Err(DecodeError::TooDeep);
        }
        let (major, ai) = self.head()?;
        match major {
            0 => Ok(Value::Uint(self.argument(ai)?)),
            1 => Ok(Value::Nint(self.argument(ai)?)),
            2 => {
                let n = self.argument(ai)? as usize;
                Ok(Value::Bytes(self.take(n)?.to_vec()))
            }
            3 => {
                let n = self.argument(ai)? as usize;
                let raw = self.take(n)?;
                // `String::from_utf8` rejects overlong encodings, surrogate code
                // points and values above U+10FFFF, which is exactly R8/§8.6.
                match std::str::from_utf8(raw) {
                    Ok(s) => Ok(Value::Text(s.to_owned())),
                    Err(_) => Err(DecodeError::InvalidText),
                }
            }
            4 => {
                let n = self.argument(ai)? as usize;
                // Guard against a hostile length claiming a huge array before
                // any elements have been read.
                if n > self.remaining_items(1) {
                    return Err(DecodeError::Truncated);
                }
                let mut items = Vec::with_capacity(n.min(64));
                for _ in 0..n {
                    items.push(self.value(depth + 1)?);
                }
                Ok(Value::Array(items))
            }
            5 => {
                let n = self.argument(ai)? as usize;
                if n > self.remaining_items(2) {
                    return Err(DecodeError::Truncated);
                }
                let mut pairs: Vec<(Value, Value)> = Vec::with_capacity(n.min(64));
                for _ in 0..n {
                    let k = self.value(depth + 1)?;
                    let v = self.value(depth + 1)?;
                    pairs.push((k, v));
                }
                // R4 + R5: canonical order, no duplicates.
                for w in pairs.windows(2) {
                    if cmp_encoded(&w[0].0, &w[1].0) != std::cmp::Ordering::Less {
                        return Err(DecodeError::UnsortedOrDuplicateKeys);
                    }
                }
                Ok(Value::Map(pairs))
            }
            6 => Err(DecodeError::Tag),
            7 => match ai {
                20 => Ok(Value::Bool(false)),
                21 => Ok(Value::Bool(true)),
                31 => Err(DecodeError::IndefiniteLength),
                _ => Err(DecodeError::ForbiddenType(ai)),
            },
            _ => unreachable!(),
        }
    }

    /// Conservative lower bound on how many further items can possibly be read,
    /// used to reject absurd declared lengths before allocating.
    fn remaining_items(&self, per_entry: usize) -> usize {
        self.input.len().saturating_sub(self.pos) / per_entry
    }
}

/// Decodes exactly one canonical CBOR value from `input`, rejecting trailing
/// bytes and every non-canonical form described in §8.5.
pub fn decode(input: &[u8]) -> Result<Value, DecodeError> {
    let mut d = Decoder::new(input);
    let v = d.value(0)?;
    if d.pos != input.len() {
        return Err(DecodeError::TrailingBytes);
    }
    Ok(v)
}

/// Decodes and additionally asserts the canonical-order invariant that the
/// recursive decoder already enforces. Exposed for tests and for validating
/// hand-built values.
pub fn decode_canonical(input: &[u8]) -> Result<Value, DecodeError> {
    let v = decode(input)?;
    if !v.is_allowed_type() || !v.is_canonically_ordered() {
        return Err(DecodeError::Canonical);
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hexs(b: &[u8]) -> String {
        hex::encode(b)
    }

    #[test]
    fn integers_use_shortest_form() {
        assert_eq!(hexs(&encode(&Value::Uint(0))), "00");
        assert_eq!(hexs(&encode(&Value::Uint(23))), "17");
        assert_eq!(hexs(&encode(&Value::Uint(24))), "1818");
        assert_eq!(hexs(&encode(&Value::Uint(255))), "18ff");
        assert_eq!(hexs(&encode(&Value::Uint(256))), "190100");
        assert_eq!(hexs(&encode(&Value::Uint(65536))), "1a00010000");
        assert_eq!(
            hexs(&encode(&Value::Uint(4294967296))),
            "1b0000000100000000"
        );
    }

    #[test]
    fn negative_integers_encode_as_minus_one_minus_n() {
        assert_eq!(hexs(&encode(&Value::Nint(0))), "20"); // -1
        assert_eq!(hexs(&encode(&Value::Nint(22))), "36"); // -23
                                                           // -24 is still encodable in one byte (argument 23), so 0x37 is correct.
        assert_eq!(hexs(&encode(&Value::Nint(23))), "37");
        assert_eq!(hexs(&encode(&Value::Nint(24))), "3818"); // -25
    }

    #[test]
    fn roundtrip_simple_values() {
        for v in [
            Value::Uint(0),
            Value::Uint(u64::MAX),
            Value::Nint(u64::MAX),
            Value::Bytes(vec![]),
            Value::Bytes(vec![1, 2, 3]),
            Value::Text("alice".into()),
            Value::Bool(true),
            Value::Bool(false),
            Value::Array(vec![Value::Uint(1), Value::Text("x".into())]),
            Value::map([("b", Value::Uint(2)), ("a", Value::Uint(1))]),
        ] {
            let enc = encode(&v);
            let dec = decode(&enc).expect("decode");
            assert_eq!(dec, v, "roundtrip failed for {v:?}");
            // R2 idempotence: re-encoding is byte-identical.
            assert_eq!(encode(&dec), enc, "re-encode differs for {v:?}");
        }
    }

    #[test]
    fn map_keys_are_sorted_shorter_first() {
        // Canonical order is by *encoded* key bytes, not by string length:
        // "b" encodes as 61 62 and "aa" as 62 61 61, so "b" sorts first.
        let v = Value::map([("b", Value::Uint(1)), ("aa", Value::Uint(2))]);
        // a2 | 61 62 (b) 01 | 62 61 61 (aa) 02
        assert_eq!(hexs(&encode(&v)), "a261620162616102");
    }

    #[test]
    fn rejects_non_canonical_integers() {
        // 0x18 0x00 == 0, must be rejected (R2)
        assert_eq!(decode(&[0x18, 0x00]), Err(DecodeError::NonCanonicalInteger));
        // 0x19 0x00 0x18 == 24, must be rejected
        assert_eq!(
            decode(&[0x19, 0x00, 0x18]),
            Err(DecodeError::NonCanonicalInteger)
        );
        // 0x1a with a u16-sized value
        assert_eq!(
            decode(&[0x1a, 0x00, 0x00, 0x00, 0x18]),
            Err(DecodeError::NonCanonicalInteger)
        );
    }

    #[test]
    fn rejects_indefinite_length() {
        // 0x5f == indefinite-length byte string
        assert_eq!(decode(&[0x5f]), Err(DecodeError::IndefiniteLength));
        // 0x9f == indefinite-length array
        assert_eq!(decode(&[0x9f]), Err(DecodeError::IndefiniteLength));
        // 0xbf == indefinite-length map
        assert_eq!(decode(&[0xbf]), Err(DecodeError::IndefiniteLength));
    }

    #[test]
    fn rejects_tags_and_floats() {
        assert_eq!(decode(&[0xc0, 0x00]), Err(DecodeError::Tag));
        // float64
        assert_eq!(
            decode(&[0xfb, 0, 0, 0, 0, 0, 0, 0, 0]),
            Err(DecodeError::ForbiddenType(27))
        );
        // undefined
        assert_eq!(decode(&[0xf7]), Err(DecodeError::ForbiddenType(23)));
        // simple value 16
        assert_eq!(decode(&[0xf0]), Err(DecodeError::ForbiddenType(16)));
    }

    #[test]
    fn rejects_unsorted_map_keys() {
        // {"b":1,"a":2} -- not in canonical order
        let mut v = Vec::new();
        v.push(0xa2);
        v.extend_from_slice(&encode(&Value::Text("b".into())));
        v.extend_from_slice(&encode(&Value::Uint(1)));
        v.extend_from_slice(&encode(&Value::Text("a".into())));
        v.extend_from_slice(&encode(&Value::Uint(2)));
        assert_eq!(decode(&v), Err(DecodeError::UnsortedOrDuplicateKeys));
    }

    #[test]
    fn rejects_duplicate_map_keys() {
        let mut v = Vec::new();
        v.push(0xa2);
        v.extend_from_slice(&encode(&Value::Text("a".into())));
        v.extend_from_slice(&encode(&Value::Uint(1)));
        v.extend_from_slice(&encode(&Value::Text("a".into())));
        v.extend_from_slice(&encode(&Value::Uint(2)));
        assert_eq!(decode(&v), Err(DecodeError::UnsortedOrDuplicateKeys));
    }

    #[test]
    fn rejects_trailing_bytes() {
        assert_eq!(decode(&[0x01, 0x02]), Err(DecodeError::TrailingBytes));
    }

    #[test]
    fn rejects_truncated_input() {
        assert_eq!(decode(&[0x43, 0x01, 0x02]), Err(DecodeError::Truncated));
    }

    #[test]
    fn rejects_overlong_utf8_and_surrogates() {
        // 0x62 c0 af -- overlong encoding of '/'
        assert_eq!(decode(&[0x62, 0xc0, 0xaf]), Err(DecodeError::InvalidText));
        // 0x63 ed a0 80 -- U+D800 surrogate
        assert_eq!(
            decode(&[0x63, 0xed, 0xa0, 0x80]),
            Err(DecodeError::InvalidText)
        );
        // 0x64 f4 90 80 80 -- above U+10FFFF
        assert_eq!(
            decode(&[0x64, 0xf4, 0x90, 0x80, 0x80]),
            Err(DecodeError::InvalidText)
        );
    }

    #[test]
    fn rejects_excessive_nesting() {
        let mut v = vec![0x81; MAX_DEPTH + 2]; // array(1) ...
        v.push(0x00);
        assert_eq!(decode(&v), Err(DecodeError::TooDeep));
    }

    #[test]
    fn accepts_allowed_nesting_depth() {
        let mut v = vec![0x81; MAX_DEPTH]; // array(1) ...
        v.push(0x00);
        assert!(decode(&v).is_ok());
    }

    #[test]
    fn absurd_declared_length_is_rejected_without_allocating() {
        // array claiming 2^32-1 elements but with no payload
        assert_eq!(
            decode(&[0x9a, 0xff, 0xff, 0xff, 0xff]),
            Err(DecodeError::Truncated)
        );
    }

    #[test]
    fn nested_maps_are_canonically_checked() {
        let mut inner = Vec::new();
        inner.push(0xa2);
        inner.extend_from_slice(&encode(&Value::Text("z".into())));
        inner.extend_from_slice(&encode(&Value::Uint(1)));
        inner.extend_from_slice(&encode(&Value::Text("a".into())));
        inner.extend_from_slice(&encode(&Value::Uint(2)));

        let mut outer = Vec::new();
        outer.push(0x81); // array(1)
        outer.extend_from_slice(&inner);
        assert_eq!(decode(&outer), Err(DecodeError::UnsortedOrDuplicateKeys));
    }
}
