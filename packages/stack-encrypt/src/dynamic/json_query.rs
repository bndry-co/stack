//! The JSON operators of a document field, for a binding: queries named by
//! operator, and reads opened against the request that prepared them.
//!
//! A field that names a target storing a document (`EncryptedJson`) runs
//! under the JSON index's options its plan resolved
//! ([`TargetOptions::Json`](super::TargetOptions::Json)). Each operator
//! takes an object of named inputs and gives a tagged operand
//! ([`Operand`]):
//!
//! | operator | input | operand |
//! |---|---|---|
//! | `contains`, `contained_by` | `{"json"}`: a JSON needle | EQL: the needle's projection (`eql_v4.query_json_tree`) |
//! | `eq_at` | `{"path", "json"}`: a scalar at a path | EQL: the needle holding the scalar there |
//! | `lt_at`, `lte_at`, `gt_at`, `gte_at` | `{"path", "json"}`: a number or string at an ordered path | EQL: the path's selector and the leaf's ordering term (`eql_v4.query_json_tree_leaf`) |
//! | `between_at` | `{"path", "low", "high"}` | EQL, two of them: the low bound's then the high's |
//! | `selector` | `{"path"}` | text: the selector `->` takes |
//! | `subtree` | `{"path", "wildcard_bound"?}` | text array: the tokens `json_tree_subtree` takes |
//! | `children`, `child_count` | `{"path"}`: a path with no wildcard | text: the node's token |
//!
//! Every JSON value in an input is UTF-8 JSON text, parsed by
//! [`parse_text`](crate::json::parse_text)'s rules. A path is JSONPath text
//! ([`JsonPath::parse`]). A position in a path (`[2]`) is refused for the
//! operators whose operand is a selector (`eq_at`, the orderings,
//! `selector`): a selector reads every position as the wildcard, so the
//! query would compare whichever element the database found first. A
//! positional read is a `subtree` read. Equality at a wildcard path matches
//! when any element matches; an ordering or `->` through one compares the
//! first. Two `eq_at` predicates on one row need not hold of the same
//! array element; one containment needle holding both does.
//!
//! # Reads
//!
//! [`json_open`] opens the rows a read returned, against the request that
//! prepared the read: the operator, the path and the bound. The engine
//! derives the selector or the read key again from that request, the
//! field's definition and the keyset, and checks every row against it with
//! the index's own checks ([`JsonSelector::open`],
//! [`JsonSubtreeKey::open`](crate::json::JsonSubtreeKey::open)). The rows
//! never say which path they are for. Each group of rows is one database
//! row's, and opens on its own: entries of two documents are never one walk.
//!
//! What opening proves is limited, as the index documents: a row of the
//! column other than the one asked for can answer, an element under one
//! array element can stand for the same field under another, and the
//! database can leave whole nodes out. Opening does not prove the result is
//! complete.

use serde::de::{self, Deserializer, Visitor};
use serde::Deserialize;
use serde_json::Value;
use vitaminc_protected::Protected;
use zeroize::Zeroizing;

use super::query::{OpSpec, Operand};
use super::{Error, Reason, Scope, ValueFrame};
use crate::json::{
    parse_text, wipe_value, JsonExtracted, JsonLeafQuery, JsonNode, JsonOptions, JsonPath,
    JsonQuery, JsonSubtree, JsonSubtreeKey,
};
use crate::sem::TermError;
use crate::target::{AeadContext, DeclaredContext, Index, Json, Owned};
use crate::{KeysetCipher, Label, NonEmpty, Pending};

/// The SQL type a JSON operand binds as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Binds {
    /// The target's needle domain (`eql_v4.query_json_tree`).
    Needle,
    /// The target's leaf operand domain (`eql_v4.query_json_tree_leaf`).
    Leaf,
    /// `text`.
    Text,
    /// `text[]`.
    TextArray,
}

/// What a JSON operator's operand binds as.
pub(super) fn binds(op: OpSpec) -> Binds {
    match op {
        OpSpec::LtAt | OpSpec::LteAt | OpSpec::GtAt | OpSpec::GteAt | OpSpec::BetweenAt => {
            Binds::Leaf
        }
        OpSpec::Selector | OpSpec::Children | OpSpec::ChildCount => Binds::Text,
        OpSpec::Subtree => Binds::TextArray,
        _ => Binds::Needle,
    }
}

/// UTF-8 JSON text in an input: a text or bytes leaf, held in a buffer
/// wiped on drop.
struct JsonText(Zeroizing<Vec<u8>>);

impl<'de> Deserialize<'de> for JsonText {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl Visitor<'_> for V {
            type Value = JsonText;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("JSON text, as text or bytes")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<JsonText, E> {
                Ok(JsonText(Zeroizing::new(v.as_bytes().to_vec())))
            }
            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<JsonText, E> {
                Ok(JsonText(Zeroizing::new(v.to_vec())))
            }
        }
        d.deserialize_any(V)
    }
}

/// A document parsed from an input, wiped when it drops.
struct Parsed(Value);

impl Drop for Parsed {
    fn drop(&mut self) {
        wipe_value(&mut self.0);
    }
}

impl JsonText {
    fn parse(&self) -> Result<Parsed, Error> {
        parse_text(&self.0)
            .map(Parsed)
            .map_err(|error| Error::Source {
                field: None,
                reason: json_reason(error.code()),
            })
    }
}

/// The reason a JSON text refusal is reported with, from its code.
fn json_reason(code: &str) -> Reason {
    match code {
        "json_duplicate_key" => Reason::JsonDuplicateKey,
        "json_integer_range" => Reason::JsonIntegerRange,
        _ => Reason::JsonSyntax,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NeedleInput {
    json: JsonText,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AtInput {
    path: String,
    json: JsonText,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BetweenInput {
    path: String,
    low: JsonText,
    high: JsonText,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PathInput {
    path: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadInput {
    path: String,
    #[serde(default)]
    wildcard_bound: Option<u32>,
}

/// An operator's input, read from its frame and checked: everything
/// [`derive`] would refuse before it derives anything.
enum Input {
    Needle(Parsed),
    At(JsonPath, Parsed),
    Between(JsonPath, Parsed, Parsed),
    Path(JsonPath),
    Read(JsonPath, u32),
}

fn read_frame<T: for<'de> Deserialize<'de>>(input: &ValueFrame) -> Result<T, Error> {
    vitaminc_aead_frame::serde::from_slice(input.risky_ref()).map_err(|_| Error::Source {
        field: None,
        reason: Reason::JsonInput,
    })
}

fn path(text: &str) -> Result<JsonPath, Error> {
    JsonPath::parse(text).map_err(|error| Error::Cipher(TermError::JsonPath(error).into()))
}

/// A path whose operand is a selector, which reads a position as the
/// wildcard.
fn selector_path(text: &str) -> Result<JsonPath, Error> {
    let path = path(text)?;
    if path.names_a_position() {
        return Err(Error::bad_source(Reason::JsonPathPosition));
    }
    Ok(path)
}

/// A path that names one node: no wildcard.
fn node_path(text: &str) -> Result<JsonPath, Error> {
    let path = path(text)?;
    if path.is_positional() {
        Ok(path)
    } else {
        Err(Error::bad_source(Reason::JsonPathWildcard))
    }
}

fn term(error: TermError) -> Error {
    Error::Cipher(error.into())
}

/// Read and check an operator's input against the field's options.
fn read_input(op: OpSpec, options: &JsonOptions, input: &ValueFrame) -> Result<Input, Error> {
    match op {
        OpSpec::Contains | OpSpec::ContainedBy => Ok(Input::Needle(
            read_frame::<NeedleInput>(input)?.json.parse()?,
        )),
        OpSpec::EqAt => read_eq_at(input),
        OpSpec::LtAt | OpSpec::LteAt | OpSpec::GtAt | OpSpec::GteAt => {
            read_ordering(options, input)
        }
        OpSpec::BetweenAt => read_between(options, input),
        OpSpec::Selector => Ok(Input::Path(selector_path(
            &read_frame::<PathInput>(input)?.path,
        )?)),
        OpSpec::Children | OpSpec::ChildCount => Ok(Input::Path(node_path(
            &read_frame::<PathInput>(input)?.path,
        )?)),
        OpSpec::Subtree => {
            let read: ReadInput = read_frame(input)?;
            Ok(Input::Read(
                path(&read.path)?,
                read.wildcard_bound.unwrap_or(JsonSubtreeKey::DEFAULT_BOUND),
            ))
        }
        _ => Err(Error::Internal),
    }
}

/// `eq_at`'s input: a scalar at a path read through a selector.
fn read_eq_at(input: &ValueFrame) -> Result<Input, Error> {
    let at: AtInput = read_frame(input)?;
    let path = selector_path(&at.path)?;
    let value = at.json.parse()?;
    if matches!(value.0, Value::Object(_) | Value::Array(_)) {
        return Err(term(TermError::JsonValueNotScalar));
    }
    Ok(Input::At(path, value))
}

/// An ordering's input: a leaf the index orders at an ordered path.
fn read_ordering(options: &JsonOptions, input: &ValueFrame) -> Result<Input, Error> {
    let at: AtInput = read_frame(input)?;
    let path = ordered_path(options, &at.path)?;
    let value = at.json.parse()?;
    leaf(&value.0)?;
    Ok(Input::At(path, value))
}

/// `between_at`'s input: two leaves the index orders at an ordered path.
fn read_between(options: &JsonOptions, input: &ValueFrame) -> Result<Input, Error> {
    let between: BetweenInput = read_frame(input)?;
    let path = ordered_path(options, &between.path)?;
    let (low, high) = (between.low.parse()?, between.high.parse()?);
    leaf(&low.0)?;
    leaf(&high.0)?;
    Ok(Input::Between(path, low, high))
}

/// A path the index orders, which names no position.
fn ordered_path(options: &JsonOptions, text: &str) -> Result<JsonPath, Error> {
    let path = path(text)?;
    if path.names_a_position() {
        Err(term(TermError::JsonOrderingAtPosition))
    } else if options.orders(&path) {
        Ok(path)
    } else {
        Err(term(TermError::JsonPathNotOrdered))
    }
}

/// A leaf the index orders: a number or a string.
fn leaf(value: &Value) -> Result<(), Error> {
    match value {
        Value::Number(_) | Value::String(_) => Ok(()),
        _ => Err(term(TermError::JsonLeafNotOrdered)),
    }
}

/// Check a JSON operator's input without a cipher: what [`derive`]
/// refuses before it derives anything.
pub(super) fn check(op: OpSpec, options: &JsonOptions, input: &ValueFrame) -> Result<(), Error> {
    read_input(op, options, input).map(drop)
}

/// The JSON index's terms of `value` under the column, as the stored
/// document's were derived.
fn terms<'a, K: 'static>(
    keyset: &'a KeysetCipher<'_, K>,
    options: &JsonOptions,
    label: &Label,
    value: Value,
) -> Pending<'a, crate::json::JsonTerms, K> {
    keyset.run(
        Index::<Value>::operation::<K, Owned>(&Json::new(options.clone()))
            .under(NonEmpty::from(label.clone())),
        value,
        DeclaredContext::default(),
    )
}

fn eql<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, crate::Error> {
    serde_json::to_vec(value).map_err(|error| crate::Error::Other(Box::new(error)))
}

/// Derive a JSON operator's operand for one input, under the field's
/// column and options. Derived locally: the pending carries no request.
pub(super) fn derive<'a, K: 'static>(
    keyset: &'a KeysetCipher<'_, K>,
    label: &Label,
    options: &JsonOptions,
    op: OpSpec,
    input: &ValueFrame,
) -> Result<Pending<'a, Operand, K>, Error> {
    let column = || NonEmpty::from(label.clone());
    Ok(match read_input(op, options, input)? {
        Input::Needle(needle) => terms(keyset, options, label, needle.0.clone())
            .try_map(|terms| eql(&JsonQuery::of_terms(&terms)).map(Operand::One)),
        Input::At(path, value) if op == OpSpec::EqAt => {
            terms(keyset, options, label, path.needle(value.0.clone()))
                .try_map(|terms| eql(&JsonQuery::at_path(&terms)).map(Operand::One))
        }
        Input::At(path, value) => terms(keyset, options, label, path.needle(value.0.clone()))
            .try_map(|terms| eql(&JsonLeafQuery::of_leaf(&terms)).map(Operand::One)),
        Input::Between(path, low, high) => {
            terms(keyset, options, label, path.needle(low.0.clone()))
                .zip(terms(keyset, options, label, path.needle(high.0.clone())))
                .try_map(|(lo, hi)| {
                    Ok(Operand::Range {
                        lo: eql(&JsonLeafQuery::of_leaf(&lo))?,
                        hi: eql(&JsonLeafQuery::of_leaf(&hi))?,
                    })
                })
        }
        Input::Path(path) if op == OpSpec::Selector => {
            let selector = keyset.json_selector_now(&path, column())?;
            Pending::ready(keyset, Ok(Operand::Text(selector.to_string())))
        }
        Input::Path(path) => {
            // A path with no wildcard names one node: its key holds the
            // one token, and nothing that covers a node above it.
            let key = keyset.json_subtree_key_now(
                &path,
                options,
                JsonSubtreeKey::DEFAULT_BOUND,
                column(),
            )?;
            let [token]: [String; 1] = key.tokens().try_into().map_err(|_| Error::Internal)?;
            Pending::ready(keyset, Ok(Operand::Text(token)))
        }
        Input::Read(path, bound) => {
            let key = keyset.json_subtree_key_now(&path, options, bound, column())?;
            Pending::ready(keyset, Ok(Operand::TextList(key.tokens())))
        }
    })
}

/// A read to open, as the request that prepared it names it: the
/// operator, the path and, for a subtree read, the wildcard bound. What a
/// binding keeps from preparing the read and hands back with its rows; the
/// engine derives the selector or the key again from it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadRequest {
    operation: String,
    path: String,
    #[serde(default)]
    wildcard_bound: Option<u32>,
}

/// The groups of rows a read returned: one list of entries per database
/// row, each entry the `public.eql_v4_json_tree_entry` JSON the SQL
/// returned, as text or bytes.
#[derive(Deserialize)]
#[serde(transparent)]
struct Groups(Vec<Vec<JsonText>>);

/// A read as its request names it, checked.
enum Read {
    Selector(JsonPath),
    Subtree(JsonPath, u32),
}

/// Read and check a read's request and its rows: everything [`open`]
/// refuses before it derives anything. A selector's group holds one entry
/// or none.
fn read_open(request: &ValueFrame, rows: &ValueFrame) -> Result<(Read, Vec<Vec<JsonNode>>), Error> {
    let request: ReadRequest = read_frame(request)?;
    let read = match OpSpec::parse(&request.operation) {
        Some(OpSpec::Selector) if request.wildcard_bound.is_none() => {
            Read::Selector(selector_path(&request.path)?)
        }
        Some(OpSpec::Subtree) => Read::Subtree(
            path(&request.path)?,
            request
                .wildcard_bound
                .unwrap_or(JsonSubtreeKey::DEFAULT_BOUND),
        ),
        _ => return Err(Error::bad_source(Reason::JsonInput)),
    };
    let groups: Groups = read_frame(rows)?;
    let groups = groups
        .0
        .into_iter()
        .map(|group| {
            group
                .iter()
                .map(|row| serde_json::from_slice::<JsonNode>(&row.0))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| Error::bad_source(Reason::JsonInput))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if matches!(read, Read::Selector(_)) && groups.iter().any(|group| group.len() > 1) {
        return Err(Error::bad_source(Reason::JsonInput));
    }
    Ok((read, groups))
}

/// Check a read's request and rows without a cipher: what [`open`] refuses
/// before it derives anything.
pub(super) fn check_open(request: &ValueFrame, rows: &ValueFrame) -> Result<(), Error> {
    read_open(request, rows).map(drop)
}

/// What a read opens with: the selector or the subtree key, derived again
/// from the request.
enum Opener {
    Selector(crate::json::JsonSelector),
    Subtree(JsonSubtreeKey),
}

/// Open the rows a read returned against the request that prepared it,
/// under the field's column and options and through `keyset`, the keyset
/// whose index key derived the read; the rows open through `scope`. Each
/// group of rows is one database row's: for `selector`, the entry `->`
/// returned or none (SQL `NULL`); for `subtree`, the rows
/// `json_tree_subtree` returned. Every group opens to a list of JSON
/// texts: for `selector`, the scalar or none, and for `subtree`, one value
/// per concrete path the read named that the row has, in document order.
/// One key request for every group.
///
/// # Errors
///
/// [`Error::Source`] for a request or rows that do not parse
/// ([`Reason::JsonInput`]), an operator that is not a read
/// ([`Reason::OperatorNotAnswered`]), or a selector group of more than one
/// entry; [`Error::Cipher`] for the read's own refusals (a path that does
/// not parse, a wildcard that expands too far). A row that is not the one
/// the read asked for fails the pending
/// ([`crate::Error::JsonWrongEntry`]), as does a wildcard read of an array
/// longer than the bound ([`crate::Error::JsonWildcardTruncated`]).
pub(super) fn open<'a, K: 'static>(
    keyset: &'a KeysetCipher<'_, K>,
    scope: Scope<'a, K>,
    label: &Label,
    options: &JsonOptions,
    request: &ValueFrame,
    rows: &ValueFrame,
) -> Result<Pending<'a, ValueFrame, K>, Error> {
    let (read, groups) = read_open(request, rows)?;
    let column = || NonEmpty::from(label.clone());
    let opener = match read {
        Read::Selector(path) => Opener::Selector(keyset.json_selector_now(&path, column())?),
        Read::Subtree(path, bound) => {
            Opener::Subtree(keyset.json_subtree_key_now(&path, options, bound, column())?)
        }
    };
    let context = || AeadContext::from(NonEmpty::from(label.clone()));
    // Opened through the client, confined to the scope's keyset when it is
    // one, as a record's leaves are: a document sealed under another
    // keyset is refused before any key is retrieved.
    let (opener_cipher, confine) = match &scope {
        Scope::Client(cipher) => (*cipher, None),
        Scope::Keyset(keyset) => (keyset.cipher(), Some(keyset.keyset_id())),
    };
    let confined = |pending: Pending<'a, Vec<Value>, K>| match confine {
        Some(keyset) => pending.scoped_to(keyset),
        None => pending,
    };
    let mut pendings: Vec<Pending<'a, Vec<Value>, K>> = Vec::with_capacity(groups.len());
    for nodes in groups {
        pendings.push(match &opener {
            Opener::Selector(selector) => match <[JsonNode; 1]>::try_from(nodes) {
                Ok([node]) => confined(
                    opener_cipher
                        .decrypt_as::<Value, JsonExtracted>(selector.open(node), context())
                        .map(|value| vec![value]),
                ),
                // `read_open` allows a selector group one entry or none.
                Err(_) => Pending::ready(keyset, Ok(Vec::new())),
            },
            Opener::Subtree(key) => confined(
                opener_cipher.decrypt_as::<Vec<Value>, JsonSubtree>(key.open(nodes), context()),
            ),
        });
    }
    Ok(Pending::all(keyset, pendings).try_map(opened_frame))
}

/// The opened groups as a frame: a list per group of each value's JSON
/// text, as bytes. Each value is wiped once its text is written, and each
/// text once the frame holds it.
fn opened_frame(mut groups: Vec<Vec<Value>>) -> Result<ValueFrame, crate::Error> {
    let texts: Result<Vec<Vec<Protected<Vec<u8>>>>, crate::Error> = groups
        .iter()
        .map(|group| {
            group
                .iter()
                .map(|value| {
                    crate::json::to_text(value)
                        .map(Protected::new)
                        .map_err(|error| crate::Error::Other(Box::new(error)))
                })
                .collect()
        })
        .collect();
    groups.iter_mut().flatten().for_each(wipe_value);
    ValueFrame::of(&texts?).map_err(|error| crate::Error::Other(Box::new(error)))
}
