//! JSON text at the engine's boundary: how a language SDK hands the JSON
//! index a document, and how it gets one back.
//!
//! A binding has no `serde_json::Value` to pass. It sends the document as
//! UTF-8 JSON text, and the engine parses it here, once, by one set of
//! rules, so every language seals the same document for the same text:
//!
//! - **Numbers** are signed or unsigned 64-bit integers, or binary64
//!   floats. An integer literal (no fraction, no exponent) outside
//!   `i64::MIN ..= u64::MAX` is refused ([`JsonTextError::IntegerRange`])
//!   rather than read as the nearest `f64`, which would seal a different
//!   number than the text names. A literal with a fraction or an exponent
//!   is the nearest binary64 (serde_json's `float_roundtrip` parser), so
//!   `1e400` is refused as not JSON this engine reads, and `0.1` is the
//!   double nearest to it.
//! - **An object names each member once.** A repeated key is refused
//!   ([`JsonTextError::DuplicateKey`]) rather than resolved, since two JSON
//!   parsers keep different ones (Go's `encoding/json` the last, others the
//!   first) and the sealed document would depend on which ran.
//! - **Text is valid Unicode**: invalid UTF-8 and an unpaired surrogate
//!   escape (`"\ud800"`) are refused as not JSON.
//! - **Nesting** is limited by the parser (128 levels) and by the index
//!   ([`TermError::JsonTooDeep`](crate::sem::TermError::JsonTooDeep)).
//!
//! What comes back out ([`to_text`]) is JSON text serde_json writes:
//! numbers in their shortest round-tripping form, members in the order the
//! document holds them. Key order, whitespace and the spelling of a number
//! (`1.0`, `1e0`) are not promised to survive: the document is sealed as
//! values, not as text.
//!
//! Every error names a class and, for a syntax error, a line and column,
//! and never a byte of the text.

use std::fmt;

use serde::de::{DeserializeSeed, Deserializer, Error as _, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

/// Why JSON text was refused at the boundary. Each says what kind of
/// mistake it was and where, never what the text held.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum JsonTextError {
    /// Not JSON text: a syntax error, text that is not UTF-8, an unpaired
    /// surrogate, a float out of range, nesting past the parser's limit, or
    /// anything after the value.
    #[error("not JSON text (line {line}, column {column})")]
    Syntax {
        /// The line of the first byte refused, from 1.
        line: usize,
        /// Its column, from 1.
        column: usize,
    },
    /// An object names one member twice.
    #[error("an object names a member twice (line {line}, column {column})")]
    DuplicateKey {
        /// The line of the second name, from 1.
        line: usize,
        /// Its column, from 1.
        column: usize,
    },
    /// An integer literal outside the signed and unsigned 64-bit range.
    #[error("an integer literal is outside the 64-bit range")]
    IntegerRange,
}

impl JsonTextError {
    /// The error's machine-readable code: `json_syntax`,
    /// `json_duplicate_key` or `json_integer_range`.
    pub fn code(&self) -> &'static str {
        match self {
            JsonTextError::Syntax { .. } => "json_syntax",
            JsonTextError::DuplicateKey { .. } => "json_duplicate_key",
            JsonTextError::IntegerRange => "json_integer_range",
        }
    }
}

/// The marker a duplicate key is raised with inside the parse, told apart
/// from serde_json's own errors by its text, which nothing else writes.
const DUPLICATE: &str = "\u{0}stack-encrypt: duplicate member";

/// Parse a document from UTF-8 JSON text by the rules in the module docs.
///
/// # Errors
///
/// [`JsonTextError`]: the text is not JSON, an object repeats a member,
/// or an integer literal is out of range.
///
/// ```
/// use stack_encrypt::json::{parse_text, JsonTextError};
///
/// let value = parse_text(br#"{"name": "Alice", "age": 34}"#)?;
/// assert_eq!(value["age"], 34);
/// assert!(matches!(parse_text(br#"{"a": 1, "a": 2}"#), Err(JsonTextError::DuplicateKey { .. })));
/// assert_eq!(parse_text(b"18446744073709551616"), Err(JsonTextError::IntegerRange));
/// # Ok::<(), JsonTextError>(())
/// ```
pub fn parse_text(text: &[u8]) -> Result<Value, JsonTextError> {
    check_integers(text)?;
    let mut de = serde_json::Deserializer::from_slice(text);
    let value = Strict.deserialize(&mut de).map_err(classify)?;
    de.end().map_err(classify)?;
    Ok(value)
}

/// The document as JSON text: what opening returns to a binding.
///
/// # Errors
///
/// None in practice: every `Value` serializes. The `Result` is serde_json's.
pub fn to_text(value: &Value) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(value)
}

fn classify(error: serde_json::Error) -> JsonTextError {
    let (line, column) = (error.line(), error.column());
    if error.to_string().starts_with(DUPLICATE) {
        JsonTextError::DuplicateKey { line, column }
    } else {
        JsonTextError::Syntax { line, column }
    }
}

/// Refuse an integer literal serde_json would read as the nearest `f64`:
/// one outside `i64::MIN ..= u64::MAX`. A lexical scan, outside strings,
/// of each number token with no fraction or exponent. Syntax errors are
/// left to the parser.
fn check_integers(text: &[u8]) -> Result<(), JsonTextError> {
    let mut i = 0;
    while i < text.len() {
        match text[i] {
            b'"' => {
                i += 1;
                while i < text.len() && text[i] != b'"' {
                    // An escape takes the next byte with it, so `\"` does
                    // not end the string.
                    i += if text[i] == b'\\' { 2 } else { 1 };
                }
                i += 1;
            }
            b'-' | b'0'..=b'9' => {
                let start = i;
                i += 1;
                while i < text.len()
                    && matches!(text[i], b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-')
                {
                    i += 1;
                }
                let token = &text[start..i];
                if token.iter().any(|b| matches!(b, b'.' | b'e' | b'E')) {
                    continue;
                }
                // ASCII by construction; a malformed token is the parser's.
                let Ok(token) = std::str::from_utf8(token) else {
                    continue;
                };
                let digits = token.strip_prefix('-').unwrap_or(token);
                if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
                    continue;
                }
                let fits = if token.starts_with('-') {
                    token.parse::<i64>().is_ok()
                } else {
                    token.parse::<u64>().is_ok()
                };
                if !fits {
                    return Err(JsonTextError::IntegerRange);
                }
            }
            _ => i += 1,
        }
    }
    Ok(())
}

/// A `Value`, refusing an object that names a member twice.
struct Strict;

impl<'de> DeserializeSeed<'de> for Strict {
    type Value = Value;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        d.deserialize_any(StrictVisitor)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }

    fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Value, E> {
        Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| E::custom("a number that is not finite"))
    }

    fn visit_str<E>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }

    fn visit_string<E>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_none<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        Strict.deserialize(d)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element_seed(Strict)? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut members = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if members.contains_key(&key) {
                return Err(A::Error::custom(DUPLICATE));
            }
            let value = map.next_value_seed(Strict)?;
            let _ = members.insert(key, value);
        }
        Ok(Value::Object(members))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn reads_every_kind_of_value() {
        let value = parse_text(
            br#"{"s": "x", "n": -3, "u": 18446744073709551615, "f": 1.5, "b": true, "z": null, "a": [1, {}]}"#,
        )
        .unwrap();
        assert_eq!(
            value,
            json!({"s": "x", "n": -3, "u": 18446744073709551615u64, "f": 1.5, "b": true, "z": null, "a": [1, {}]})
        );
        assert_eq!(parse_text(b" null ").unwrap(), Value::Null);
        assert_eq!(parse_text(b"\"text\"").unwrap(), json!("text"));
    }

    #[test]
    fn the_64_bit_bounds_are_integers_and_one_past_is_refused() {
        assert_eq!(
            parse_text(b"-9223372036854775808").unwrap(),
            json!(i64::MIN)
        );
        assert_eq!(
            parse_text(b"18446744073709551615").unwrap(),
            json!(u64::MAX)
        );
        for text in [
            &b"-9223372036854775809"[..],
            b"18446744073709551616",
            br#"{"a": [1, 99999999999999999999]}"#,
        ] {
            assert_eq!(parse_text(text), Err(JsonTextError::IntegerRange));
        }
        // With a fraction or an exponent it is a float, by the documented
        // binary64 rule.
        assert_eq!(parse_text(b"1e20").unwrap(), json!(1e20));
        assert_eq!(
            parse_text(b"18446744073709551616.0").unwrap(),
            json!(1.8446744073709552e19)
        );
    }

    #[test]
    fn a_number_inside_a_string_is_text() {
        assert_eq!(
            parse_text(br#"{"k": "99999999999999999999", "e": "a\"99999999999999999999"}"#)
                .unwrap()["k"],
            json!("99999999999999999999")
        );
    }

    #[test]
    fn a_repeated_member_is_refused_with_its_place() {
        assert_eq!(
            parse_text(b"{\"a\": 1,\n \"a\": 2}"),
            Err(JsonTextError::DuplicateKey { line: 2, column: 4 })
        );
        assert!(matches!(
            parse_text(br#"[{"x": {"y": 1, "y": 1}}]"#),
            Err(JsonTextError::DuplicateKey { .. })
        ));
        // The same name in two objects is two members.
        assert!(parse_text(br#"[{"a": 1}, {"a": 2}]"#).is_ok());
    }

    #[test]
    fn text_that_is_not_json_is_refused_without_quoting_it() {
        for text in [
            &b""[..],
            b"{",
            b"{\"secret-4242\"}",
            b"[1] [2]",
            b"\"\\ud800\"",
            b"\"\xff\"",
            b"1e400",
            b"NaN",
        ] {
            let error = parse_text(text).unwrap_err();
            assert!(matches!(error, JsonTextError::Syntax { .. }), "{error:?}");
            assert!(!error.to_string().contains("4242"));
            assert_eq!(error.code(), "json_syntax");
        }
    }

    #[test]
    fn text_round_trips_by_value() {
        let value = parse_text(br#"{"b": 1.0, "a": [0.1, -0.0]}"#).unwrap();
        let text = to_text(&value).unwrap();
        assert_eq!(parse_text(&text).unwrap(), value);
    }
}
