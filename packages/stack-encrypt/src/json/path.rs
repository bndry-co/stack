//! JSON paths: how a caller names a node of a document.
//!
//! A [`JsonPath`] is parsed from the JSONPath subset the JSON index
//! addresses: `$`, object members (`.name` or `["name"]`), array elements
//! by position (`[2]`) and every element of an array (`[*]`). Nothing else:
//! no filters, no recursive descent, no slices.
//!
//! The index derives two things from a path, and they differ on arrays:
//!
//! - A **selector** names a path with every array position replaced by the
//!   wildcard, because every element of an array shares one selector
//!   ([`JsonPath::selector_bytes`]). `$.a[2].x` and `$.a[*].x` have the same
//!   selector.
//! - A **token** names a path positionally ([`JsonPath::token_bytes`]), so a
//!   path with a wildcard has none: the token chain addresses one node.
use std::fmt;
use std::str::FromStr;

/// One step of a [`JsonPath`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Segment {
    /// An object member, by key.
    Key(String),
    /// One array element, by position.
    Index(u64),
    /// Every element of an array.
    Wildcard,
}

/// A path into a JSON document, from the root (`$`) down.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub struct JsonPath {
    segments: Vec<Segment>,
}

/// Why text is not a [`JsonPath`]. The message names the position of the
/// first character the parser refused and nothing else of the text: a path
/// can name a key that is customer data.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error, miette::Diagnostic)]
#[error("not a JSON path: {reason} at byte {at}")]
#[diagnostic(
    code(stack_encrypt::json_path),
    help("A path starts with `$` and continues with `.name`, `[\"name\"]`, `[2]` or `[*]` steps, as in `$.address.city` or `$.tags[*]`.")
)]
pub struct JsonPathError {
    /// What was expected, or what was found.
    pub reason: &'static str,
    /// The byte offset in the text the parser stopped at.
    pub at: usize,
}

impl crate::ErrorPayload for JsonPathError {
    fn payload(&self) -> serde_json::Map<String, serde_json::Value> {
        crate::diagnostic::payload([
            ("reason", self.reason.into()),
            ("at", (self.at as u64).into()),
        ])
    }
}

/// The tag byte of an object step in a path's canonical bytes.
const KEY_STEP: u8 = 0x01;
/// The tag byte of an array step (positional or wildcard) in a path's
/// canonical bytes.
const ARRAY_STEP: u8 = 0x02;

impl JsonPath {
    /// The root, `$`.
    pub fn root() -> Self {
        Self::default()
    }

    /// Parse the JSONPath subset the index addresses: `$`, `.name`,
    /// `["name"]`, `[2]` and `[*]` steps.
    ///
    /// # Errors
    ///
    /// [`JsonPathError`] for text that is not one.
    pub fn parse(text: &str) -> Result<Self, JsonPathError> {
        let bytes = text.as_bytes();
        let refuse = |reason, at| Err(JsonPathError { reason, at });
        if bytes.first() != Some(&b'$') {
            return refuse("expected `$`", 0);
        }
        let mut segments = Vec::new();
        let mut at = 1;
        while at < bytes.len() {
            match bytes[at] {
                b'.' => {
                    let start = at + 1;
                    let mut end = start;
                    while end < bytes.len() && bytes[end] != b'.' && bytes[end] != b'[' {
                        end += 1;
                    }
                    if end == start {
                        return refuse("expected a member name after `.`", start);
                    }
                    // `end` is at an ASCII delimiter or the end of the text,
                    // so the slice ends on a character boundary.
                    segments.push(Segment::Key(text[start..end].to_owned()));
                    at = end;
                }
                b'[' => {
                    let start = at + 1;
                    match bytes.get(start) {
                        Some(b'*') => {
                            if bytes.get(start + 1) != Some(&b']') {
                                return refuse("expected `]` after `*`", start + 1);
                            }
                            segments.push(Segment::Wildcard);
                            at = start + 2;
                        }
                        Some(b'"') => {
                            let (key, next) = quoted(text, start)?;
                            if bytes.get(next) != Some(&b']') {
                                return refuse("expected `]` after the quoted name", next);
                            }
                            segments.push(Segment::Key(key));
                            at = next + 1;
                        }
                        Some(b'0'..=b'9') => {
                            let mut end = start;
                            while end < bytes.len() && bytes[end].is_ascii_digit() {
                                end += 1;
                            }
                            if bytes.get(end) != Some(&b']') {
                                return refuse("expected `]` after the position", end);
                            }
                            let Ok(index) = text[start..end].parse::<u64>() else {
                                return refuse("the position does not fit 64 bits", start);
                            };
                            segments.push(Segment::Index(index));
                            at = end + 1;
                        }
                        _ => {
                            return refuse(
                                "expected `*`, a quoted name or a position after `[`",
                                start,
                            )
                        }
                    }
                }
                _ => return refuse("expected `.` or `[`", at),
            }
        }
        Ok(Self { segments })
    }

    /// The steps, from the root down. Empty for the root itself.
    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }

    /// Whether this path names one node: no step is the wildcard.
    pub fn is_positional(&self) -> bool {
        !self.segments.iter().any(|s| matches!(s, Segment::Wildcard))
    }

    /// This path with one more step.
    pub(crate) fn then(&self, segment: Segment) -> Self {
        let mut segments = Vec::with_capacity(self.segments.len() + 1);
        segments.extend_from_slice(&self.segments);
        segments.push(segment);
        Self { segments }
    }

    /// The longest prefix with no wildcard, and whether anything was cut.
    pub(crate) fn anchor(&self) -> (Self, bool) {
        let end = self
            .segments
            .iter()
            .position(|s| matches!(s, Segment::Wildcard))
            .unwrap_or(self.segments.len());
        (
            Self {
                segments: self.segments[..end].to_vec(),
            },
            end < self.segments.len(),
        )
    }

    /// The canonical bytes a selector is derived over: every array step,
    /// positional or wildcard, is the one array tag, so every element of an
    /// array shares its parent's selector. A key is length-prefixed, so two
    /// paths cannot encode to one byte string.
    pub(crate) fn selector_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for segment in &self.segments {
            match segment {
                Segment::Key(key) => push_key(&mut out, key),
                Segment::Index(_) | Segment::Wildcard => out.push(ARRAY_STEP),
            }
        }
        out
    }

    /// The canonical bytes a token is derived over: an array step carries
    /// its position. `None` for a path with a wildcard, which names no one
    /// node.
    pub(crate) fn token_bytes(&self) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        for segment in &self.segments {
            match segment {
                Segment::Key(key) => push_key(&mut out, key),
                Segment::Index(index) => {
                    out.push(ARRAY_STEP);
                    out.extend_from_slice(&index.to_le_bytes());
                }
                Segment::Wildcard => return None,
            }
        }
        Some(out)
    }

    /// The document that holds `value` at this path and nothing else:
    /// `$.a[*].x` with `1` is `{"a": [{"x": 1}]}`. A positional array step
    /// places the value at element zero, since the needle's selectors do not
    /// tell positions apart.
    pub(crate) fn needle(&self, value: serde_json::Value) -> serde_json::Value {
        self.segments
            .iter()
            .rev()
            .fold(value, |inner, segment| match segment {
                Segment::Key(key) => {
                    let mut map = serde_json::Map::new();
                    let _ = map.insert(key.clone(), inner);
                    serde_json::Value::Object(map)
                }
                Segment::Index(_) | Segment::Wildcard => serde_json::Value::Array(vec![inner]),
            })
    }
}

/// A key step: the tag, the key's length and the key.
fn push_key(out: &mut Vec<u8>, key: &str) {
    out.push(KEY_STEP);
    out.extend_from_slice(&(key.len() as u32).to_le_bytes());
    out.extend_from_slice(key.as_bytes());
}

/// A JSON string starting at the quote at `start`: its value and the offset
/// after its closing quote. The escapes are JSON's.
fn quoted(text: &str, start: usize) -> Result<(String, usize), JsonPathError> {
    let bytes = text.as_bytes();
    let mut end = start + 1;
    while end < bytes.len() {
        match bytes[end] {
            b'\\' => end += 2,
            b'"' => {
                let literal = &text[start..=end];
                let key: String = serde_json::from_str(literal).map_err(|_| JsonPathError {
                    reason: "the quoted name is not a JSON string",
                    at: start,
                })?;
                return Ok((key, end + 1));
            }
            _ => end += 1,
        }
    }
    Err(JsonPathError {
        reason: "unterminated quoted name",
        at: start,
    })
}

impl FromStr for JsonPath {
    type Err = JsonPathError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

/// Renders the path as it parses: a plain key as `.key`, any other as
/// `["…"]`, a position as `[2]`, the wildcard as `[*]`.
impl fmt::Display for JsonPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("$")?;
        for segment in &self.segments {
            match segment {
                Segment::Key(key) if !key.is_empty() && !key.contains(['.', '[', ']', '"']) => {
                    write!(f, ".{key}")?;
                }
                Segment::Key(key) => {
                    write!(f, "[{}]", serde_json::Value::String(key.clone()))?;
                }
                Segment::Index(index) => write!(f, "[{index}]")?,
                Segment::Wildcard => f.write_str("[*]")?,
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(k: &str) -> Segment {
        Segment::Key(k.to_owned())
    }

    #[test]
    fn parses_the_subset_the_index_addresses() {
        let path = JsonPath::parse("$.a[2].b[*][\"c.d\"]").unwrap();
        assert_eq!(
            path.segments(),
            &[
                key("a"),
                Segment::Index(2),
                key("b"),
                Segment::Wildcard,
                key("c.d")
            ]
        );
        assert_eq!(path.to_string(), "$.a[2].b[*][\"c.d\"]");
        assert_eq!(JsonPath::parse("$").unwrap(), JsonPath::root());
        assert_eq!(JsonPath::parse("$").unwrap().to_string(), "$");
        assert!(!path.is_positional());
        assert!(JsonPath::parse("$.a[2]").unwrap().is_positional());
    }

    #[test]
    fn refuses_what_it_does_not_address() {
        for (text, at) in [
            ("", 0),
            ("a.b", 0),
            ("$.", 2),
            ("$..a", 2),
            ("$[", 2),
            ("$[1", 3),
            ("$[-1]", 2),
            ("$[\"a]", 2),
            ("$.a[x]", 4),
        ] {
            let error = JsonPath::parse(text).unwrap_err();
            assert_eq!(error.at, at, "{text:?}: {error}");
        }
        // A plain key runs to the next `.` or `[`, so it may hold a space.
        assert_eq!(JsonPath::parse("$.a b").unwrap().segments(), &[key("a b")]);
    }

    #[test]
    fn a_selector_folds_positions_into_the_wildcard_and_a_token_keeps_them() {
        let positional = JsonPath::parse("$.a[2].x").unwrap();
        let wild = JsonPath::parse("$.a[*].x").unwrap();
        assert_eq!(positional.selector_bytes(), wild.selector_bytes());
        assert!(positional.token_bytes().is_some());
        assert!(wild.token_bytes().is_none());
        assert_ne!(
            JsonPath::parse("$.a[1]").unwrap().token_bytes(),
            JsonPath::parse("$.a[2]").unwrap().token_bytes()
        );
        // Length-prefixed keys: `("ab", "c")` and `("a", "bc")` differ.
        assert_ne!(
            JsonPath::parse("$.ab.c").unwrap().selector_bytes(),
            JsonPath::parse("$.a.bc").unwrap().selector_bytes()
        );
    }

    #[test]
    fn the_anchor_is_the_prefix_before_the_first_wildcard() {
        let (anchor, cut) = JsonPath::parse("$.a[*].x").unwrap().anchor();
        assert_eq!(anchor, JsonPath::parse("$.a").unwrap());
        assert!(cut);
        let (anchor, cut) = JsonPath::parse("$.a[1].x").unwrap().anchor();
        assert_eq!(anchor.to_string(), "$.a[1].x");
        assert!(!cut);
    }

    #[test]
    fn a_needle_holds_the_value_at_the_path() {
        let needle = JsonPath::parse("$.a[*].x")
            .unwrap()
            .needle(serde_json::json!(1));
        assert_eq!(needle, serde_json::json!({"a": [{"x": 1}]}));
        let needle = JsonPath::root().needle(serde_json::json!("v"));
        assert_eq!(needle, serde_json::json!("v"));
    }
}
