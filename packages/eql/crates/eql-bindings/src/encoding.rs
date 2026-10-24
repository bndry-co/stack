//! Text encodings a wire field is written in.
//!
//! A payload field that carries bytes carries them as text, and the
//! encoding is part of the field's contract: SQL decodes base64 with
//! `decode(x, 'base64')`, and decodes no base85 at all. These newtypes name
//! the encoding in the type, so a field's type says how its text is to be
//! read. Each serializes as the string itself (`#[serde(transparent)]`), and
//! renders as `string` in TypeScript and JSON Schema.
//!
//! Deserializing checks that the value is a string and nothing else. The
//! engine that produced the bytes decodes them, and refuses text that is not
//! its encoding there.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// Padded standard base64 (RFC 4648 §4), as PostgreSQL's
/// `encode(x, 'base64')` writes it and `decode(x, 'base64')` reads it.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, TS, JsonSchema)]
#[serde(transparent)]
pub struct Base64Text(pub String);

/// RFC 1924 base85, the alphabet `base85-simd` writes. No SQL function
/// decodes it, so a field in it is opaque to the database.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, TS, JsonSchema)]
#[serde(transparent)]
pub struct Base85Text(pub String);

impl Base64Text {
    /// The text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Base85Text {
    /// The text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_encodings_are_the_bare_string_on_the_wire() {
        let b64 = Base64Text("AAAAAAAAAAAAAAAAAAAAAA==".to_owned());
        let b85 = Base85Text("0rr91".to_owned());
        assert_eq!(
            serde_json::to_value(&b64).unwrap(),
            serde_json::json!(b64.as_str())
        );
        assert_eq!(
            serde_json::to_value(&b85).unwrap(),
            serde_json::json!(b85.as_str())
        );
        assert_eq!(
            serde_json::from_value::<Base64Text>(serde_json::json!(b64.0)).unwrap(),
            b64
        );
        assert!(serde_json::from_value::<Base85Text>(serde_json::json!(1)).is_err());
        assert_eq!(Base64Text::name(), "Base64Text");
        assert_eq!(Base64Text::inline(), "string");
        assert_eq!(
            serde_json::to_value(schemars::schema_for!(Base85Text)).unwrap()["type"],
            "string"
        );
    }
}
