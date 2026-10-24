//! The `json_tree` family: an encrypted JSON document stored as one entry
//! per node, with node-local ciphertexts, a token chain and exact
//! containment. HAND-WRITTEN, like the v3 SteVec structs and for the same
//! reason: the bodies are not derivable from the catalog. The SQL is
//! `src/v3/json_tree/`, confined to EQL v4; the family is not in the
//! catalog yet, so it is not in [`super::all`] nor in the target table.
//!
//! Stack Encrypt's [`Json`](stack_encrypt::target::Json) index produces the
//! document ([`stack_encrypt::json::JsonDocument`], whose wire form is the
//! `h` and `sv` here) and the query operands; these types are the SQL
//! contract around them, with the `v` and `i` envelope, and the
//! [`EncryptFrom`] / [`DecryptInto`] impls that let a Rust program name
//! [`JsonTreeDocument`] as a target: `encrypt_as::<JsonTreeDocument>` under
//! an [`Identifier`]. A query derives through the engine's own document
//! target under the same context as a label, `Plan::value::<Value>()
//! .context("users/profile").encrypt_into::<JsonDocument>()`, and converts
//! into the operand types here; the identifier and the two-segment label
//! are one context, so the selectors agree (see [`crate::encryption`]). The
//! design is `docs/plans/2026-10-17-json-tree-index.md` at
//! the repository root.

use schemars::{schema_for, JsonSchema, Schema};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use stack_encrypt::json::{JsonDocument, JsonLeafQuery, JsonNode, JsonQuery, JsonSubtree};
use stack_encrypt::target::{AeadContext, ExpectedContext, IndexSpec};
use stack_encrypt::{
    DecryptField, DecryptInto, Decryptable, Decryption, EncryptFrom, Encryption, Error, NonEmpty,
};
use ts_rs::TS;

use crate::v3::terms::{EntryCiphertext, KeyHeader, OpeCllw, Selector};
use crate::v4::{DomainType, SchemaVersion};
use crate::Identifier;

/// A sixteen-byte chain tag, hex: a parent tag `p`, a wrapped token `w`,
/// a group tag `n` or `g`. Per document, salted by the document's `iv`, so
/// unlinkable across rows at rest.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, TS, JsonSchema)]
pub struct JsonTreeTag(pub String);

/// `public.eql_v4_json_tree`: a JSON tree document, `{v, i, h, sv:
/// [entry]}`. Strict. `h` is the document's key header, stored once (every
/// entry is sealed under the document's one data key); `sv` holds one
/// entry per node in depth-first order, the root first.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JsonTreeDocument {
    pub v: SchemaVersion,
    pub i: Identifier,
    pub h: KeyHeader,
    pub sv: Vec<JsonTreeEntry>,
}

/// `public.eql_v4_json_tree_entry`: one node. `s` and `vs` are the path
/// and value selectors, `c` the node's own ciphertext; `o`, `p` and `w`
/// the chain fields below the heads; `n` and `g` the group tags of
/// container array elements and what sits inside them; `op` the leaf
/// ordering term. `h`, `j`, `d`, `v` and `i` are what the extractors graft
/// onto an entry they return, so it opens on its own.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JsonTreeEntry {
    pub s: Selector,
    pub vs: Selector,
    pub c: EntryCiphertext,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub o: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub p: Option<JsonTreeTag>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub w: Option<JsonTreeTag>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub n: Option<JsonTreeTag>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub g: Option<JsonTreeTag>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub op: Option<OpeCllw>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub h: Option<KeyHeader>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub j: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub d: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub v: Option<SchemaVersion>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub i: Option<Identifier>,
}

/// One selector pair of a containment needle.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JsonTreeQueryPair {
    pub s: Selector,
    pub vs: Selector,
}

/// One group of a containment needle: the pairs that sit directly in it,
/// and one nested group per array element that is a container.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JsonTreeQueryGroup {
    pub sv: Vec<JsonTreeQueryPair>,
    pub el: Vec<JsonTreeQueryGroup>,
}

/// `eql_v4.query_json_tree`: a containment needle, the element-nested
/// projection of the needle document's selectors, with the alternative
/// projection a root scalar carries. Strict. What
/// [`stack_encrypt::json::JsonQuery`] serializes to; [`TryFrom`] converts
/// one.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JsonTreeQuery {
    pub sv: Vec<JsonTreeQueryPair>,
    pub el: Vec<JsonTreeQueryGroup>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub alt: Option<JsonTreeQueryGroup>,
}

/// `eql_v4.query_json_tree_leaf`: an ordering operand at a path, the path's
/// selector and the leaf ordering term. What
/// [`stack_encrypt::json::JsonLeafQuery`] serializes to.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JsonTreeLeafQuery {
    pub s: Selector,
    pub op: OpeCllw,
}

/// The rows a subtree walk returned (`eql_v4.json_tree_subtree` or
/// `json_tree_subtree_at`), collected: opens to the value under the
/// walked node, or to the list of complete subtrees the rows hold.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct JsonTreeSubtree(pub Vec<JsonTreeEntry>);

macro_rules! json_tree_domain_type {
    ($ty:ident, $sql:literal) => {
        impl DomainType for $ty {
            fn sql_domain_static() -> &'static str {
                $sql
            }
            fn sql_domain(&self) -> &'static str {
                Self::sql_domain_static()
            }
            // `term_json_keys` keeps the trait default (`None`): the terms
            // live per entry, not as flat payload keys.
            fn parse_value(&self, value: &serde_json::Value) -> Result<(), serde_json::Error> {
                <$ty as Deserialize>::deserialize(value).map(|_| ())
            }
            fn schema(&self) -> Schema {
                schema_for!($ty)
            }
            fn schema_id_base_static() -> &'static str {
                super::SCHEMA_ID_BASE
            }
            fn schema_id(&self) -> String {
                format!("{}{}.json", super::SCHEMA_ID_BASE, self.domain())
            }
        }
    };
}

json_tree_domain_type!(JsonTreeDocument, "public.eql_v4_json_tree");
json_tree_domain_type!(JsonTreeEntry, "public.eql_v4_json_tree_entry");
json_tree_domain_type!(JsonTreeQuery, "eql_v4.query_json_tree");
json_tree_domain_type!(JsonTreeLeafQuery, "eql_v4.query_json_tree_leaf");

// =============================================================================
// Conversions to and from the engine's types, through their one wire form
// =============================================================================

fn codec(error: impl std::error::Error + Send + Sync + 'static) -> Error {
    Error::Other(Box::new(error))
}

/// Re-read one serializable value as another type sharing its wire form.
fn transcode<T: Serialize, U: serde::de::DeserializeOwned>(value: &T) -> Result<U, Error> {
    serde_json::from_value(serde_json::to_value(value).map_err(codec)?).map_err(codec)
}

impl JsonTreeDocument {
    /// The envelope around an engine document: `v = 4`, the column, and
    /// the document's header and entries.
    fn envelope(i: Identifier, document: &JsonDocument) -> Result<Self, Error> {
        let mut value = serde_json::to_value(document).map_err(codec)?;
        let object = value
            .as_object_mut()
            .ok_or_else(|| Error::Other("a JSON document serializes to an object".into()))?;
        let _ = object.insert("v".into(), serde_json::json!(4));
        let _ = object.insert("i".into(), serde_json::to_value(i).map_err(codec)?);
        serde_json::from_value(value).map_err(codec)
    }

    /// The engine's document: the header and entries without the envelope.
    fn document(&self) -> Result<JsonDocument, Error> {
        serde_json::from_value(serde_json::json!({ "h": self.h, "sv": self.sv })).map_err(codec)
    }
}

impl TryFrom<JsonQuery> for JsonTreeQuery {
    type Error = Error;
    fn try_from(query: JsonQuery) -> Result<Self, Error> {
        transcode(&query)
    }
}

impl TryFrom<&JsonQuery> for JsonTreeQuery {
    type Error = Error;
    fn try_from(query: &JsonQuery) -> Result<Self, Error> {
        transcode(query)
    }
}

impl TryFrom<&JsonLeafQuery> for JsonTreeLeafQuery {
    type Error = Error;
    fn try_from(query: &JsonLeafQuery) -> Result<Self, Error> {
        transcode(query)
    }
}

impl JsonTreeEntry {
    /// The entry as an extracted node the engine opens: it must carry the
    /// grafted `h` and `j`, which every extractor adds.
    fn node(&self) -> Result<JsonNode, Error> {
        if self.h.is_none() || self.j.is_none() {
            return Err(Error::Other(
                "a JSON tree entry opens only as an extractor returned it, with `h` and `j`".into(),
            ));
        }
        transcode(self)
    }
}

// =============================================================================
// Stack Encrypt targets
// =============================================================================

/// A document seals as the JSON index lays it out, under the column it is
/// stored in: the [`Identifier`] is the context the data key is minted
/// under and every selector derives under, and is written to `i`.
impl EncryptFrom<Value> for JsonTreeDocument {
    type Context = NonEmpty<Identifier>;
    fn encryption<'s, K: 'static>() -> Encryption<'s, Value, Self, K, Self::Context> {
        <JsonDocument as EncryptFrom<Value>>::encryption()
            .accepting::<NonEmpty<Identifier>>()
            .map_with_context(|document, i: NonEmpty<Identifier>| (i, document))
            .try_map(|(i, document)| Self::envelope(i.into_inner(), &document))
    }
    fn indexes() -> Vec<IndexSpec> {
        <JsonDocument as EncryptFrom<Value>>::indexes()
    }
}

/// Opens to the plaintext document, under the stored identifier, which an
/// [`ExpectedContext`] may require to be the column the caller expects.
impl DecryptInto<Value> for JsonTreeDocument {
    type Context = ExpectedContext<Identifier>;
    fn decryption<K: 'static>(self, context: Self::Context) -> Decryption<Value, K> {
        let column = match context.validate(self.i.clone()) {
            Ok(column) => column,
            Err(error) => return Decryption::failed(error),
        };
        match self.document() {
            Ok(document) => document.decryption(AeadContext::from(column)),
            Err(error) => Decryption::failed(error),
        }
    }
}

impl Decryptable for JsonTreeDocument {
    const DECRYPTABLE: bool = true;
}
impl<P, Ctx> DecryptField<P, Ctx> for JsonTreeDocument
where
    Self: DecryptInto<P>,
    Ctx: Into<<Self as DecryptInto<P>>::Context>,
{
    fn decryption_field<K: 'static>(self, context: Ctx) -> Option<Decryption<P, K>> {
        Some(self.decryption(context.into()))
    }
}

/// An extracted entry opens to the scalar it holds, or to the whole
/// document for a sealed root, under the column it was extracted from. A
/// container node holds no value of its own; its subtree opens through
/// [`JsonTreeSubtree`].
impl DecryptInto<Value> for JsonTreeEntry {
    type Context = NonEmpty<Identifier>;
    fn decryption<K: 'static>(self, context: Self::Context) -> Decryption<Value, K> {
        match self.node() {
            Ok(node) => node.decryption(AeadContext::from(context)),
            Err(error) => Decryption::failed(error),
        }
    }
}

/// The rows of `json_tree_subtree(doc, token)` open to the value under the
/// walked node.
impl DecryptInto<Value> for JsonTreeSubtree {
    type Context = NonEmpty<Identifier>;
    fn decryption<K: 'static>(self, context: Self::Context) -> Decryption<Value, K> {
        match self.subtree() {
            Ok(subtree) => subtree.decryption(AeadContext::from(context)),
            Err(error) => Decryption::failed(error),
        }
    }
}

/// The rows of a walk open to the complete subtrees they hold, in order:
/// one per node whose selector `json_tree_subtree_at` matched.
impl DecryptInto<Vec<Value>> for JsonTreeSubtree {
    type Context = NonEmpty<Identifier>;
    fn decryption<K: 'static>(self, context: Self::Context) -> Decryption<Vec<Value>, K> {
        match self.subtree() {
            Ok(subtree) => subtree.decryption(AeadContext::from(context)),
            Err(error) => Decryption::failed(error),
        }
    }
}

impl JsonTreeSubtree {
    fn subtree(&self) -> Result<JsonSubtree, Error> {
        Ok(JsonSubtree::new(
            self.0
                .iter()
                .map(JsonTreeEntry::node)
                .collect::<Result<_, _>>()?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_domains_are_the_v4_json_tree_family() {
        assert_eq!(
            JsonTreeDocument::sql_domain_static(),
            "public.eql_v4_json_tree"
        );
        assert_eq!(
            JsonTreeEntry::sql_domain_static(),
            "public.eql_v4_json_tree_entry"
        );
        assert_eq!(JsonTreeQuery::sql_domain_static(), "eql_v4.query_json_tree");
        assert_eq!(
            JsonTreeLeafQuery::sql_domain_static(),
            "eql_v4.query_json_tree_leaf"
        );
    }

    #[test]
    fn a_query_needs_sv_and_el_and_takes_an_alt() {
        let query: JsonTreeQuery = serde_json::from_value(serde_json::json!({
            "sv": [{"s": "aa", "vs": "bb"}],
            "el": [{"sv": [], "el": []}],
            "alt": {"sv": [{"s": "cc", "vs": "dd"}], "el": []},
        }))
        .unwrap();
        assert_eq!(query.el.len(), 1);
        assert!(query.alt.is_some());
        assert!(serde_json::from_value::<JsonTreeQuery>(serde_json::json!({"sv": []})).is_err());
        assert!(serde_json::from_value::<JsonTreeQuery>(serde_json::json!({
            "sv": [], "el": [], "grp": []
        }))
        .is_err());
    }

    #[test]
    fn an_entry_without_the_grafted_fields_does_not_open() {
        let entry: JsonTreeEntry = serde_json::from_value(serde_json::json!({
            "s": "00", "vs": "00", "c": "AA=="
        }))
        .unwrap();
        assert!(entry.node().is_err());
    }
}
