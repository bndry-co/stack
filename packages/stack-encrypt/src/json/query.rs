//! The query terms of the JSON index, and how the operators reach it.
//!
//! A containment needle is the **element-nested projection** of the
//! needle's terms: the selector pairs `{s, vs}` of every node, grouped by
//! the array element they sit in. The server projects a stored document the
//! same way from its group tags, and native `jsonb @>` over the two
//! projections is exact containment: each needle element has to fit inside
//! one stored element, which is PostgreSQL's own rule for arrays. The
//! design's "The preferred form" records why no re-check is needed.
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::derive::{JsonTerms, TermNode};
use super::path::JsonPath;
use super::{hex, JsonDocument, JsonEntry, JsonOptions, Tag};
use crate::op::{
    Answers, AtPath, Between, ContainedBy, Contains, DefaultIndex, Eq, Gt, Gte, Input, Lt, Lte,
    One, Pair, Pathed, QueryTerm, QueryToken, Supports,
};
use crate::sem::{RangeQuery, TermError};
use crate::target::{DeclaredContext, Index, Json, Owned, Pending};
use crate::{Error, KeysetCipher, Label, NonEmpty};

/// One selector pair of a projection.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Pair16 {
    s: Tag,
    vs: Tag,
}

/// The element-nested projection of a document: the selector pairs that
/// sit outside any array element, and one nested projection per array
/// element that is a container. What the server computes from a stored
/// document's group tags (`json_tree_query`), and what a containment
/// needle is.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct JsonProjection {
    sv: Vec<Pair16>,
    el: Vec<JsonProjection>,
}

impl JsonProjection {
    /// `jsonb @>` over two projections: every needle pair is some pair of
    /// this projection, and every needle element fits inside some element
    /// of it, recursively. What the server computes natively over the two
    /// projections; here so a caller can decide containment over documents
    /// it holds, with no database.
    pub fn contains(&self, needle: &JsonProjection) -> bool {
        needle.sv.iter().all(|pair| self.sv.contains(pair))
            && needle
                .el
                .iter()
                .all(|group| self.el.iter().any(|mine| mine.contains(group)))
    }
}

/// The query term of [`Contains`], [`ContainedBy`] and `AtPath<Eq>`: the
/// element-nested projection of the needle's selectors, and, for a needle
/// whose root is a scalar, the alternative projection that matches a
/// stored root array holding it. Serializes to the `query_json_tree`
/// operand: `{"sv": [{"s": "…", "vs": "…"}, …], "el": [{"sv": …, "el": …},
/// …], "alt": {…}}`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JsonQuery {
    group: JsonProjection,
    alt: Option<JsonProjection>,
}

impl JsonQuery {
    pub(crate) fn of_terms(terms: &JsonTerms) -> Self {
        let alt = terms.alt().map(|(s, vs)| JsonProjection {
            sv: vec![Pair16 { s, vs }],
            el: Vec::new(),
        });
        Self {
            group: group_of(terms.nodes(), None),
            alt,
        }
    }

    /// The needle's projection: what `<@` compares a stored document's
    /// projection against.
    pub fn projection(&self) -> &JsonProjection {
        &self.group
    }

    /// Whether a stored document's projection contains this needle, as the
    /// server decides `@>`: containment of the needle's projection, or of
    /// its alternative for a root scalar against a root array.
    pub fn matches(&self, stored: &JsonProjection) -> bool {
        stored.contains(&self.group) || self.alt.as_ref().is_some_and(|alt| stored.contains(alt))
    }
}

/// The group of the nodes that sit directly in `parent` (`None` is the top
/// level), with the container elements in it nested as groups.
fn group_of(nodes: &[TermNode], parent: Option<usize>) -> JsonProjection {
    let belongs = |index: usize, node: &TermNode| {
        if node.container_element {
            Some(index)
        } else {
            node.element
        }
    };
    JsonProjection {
        sv: nodes
            .iter()
            .enumerate()
            .filter(|(i, n)| belongs(*i, n) == parent)
            .map(|(_, n)| Pair16 { s: n.s, vs: n.vs })
            .collect(),
        el: nodes
            .iter()
            .enumerate()
            .filter(|(_, n)| n.container_element && n.element == parent)
            .map(|(i, _)| group_of(nodes, Some(i)))
            .collect(),
    }
}

impl JsonDocument {
    /// The stored document's projection, from its group tags, as the SQL's
    /// `json_tree_query` computes it: what a [`JsonQuery`] is matched
    /// against.
    pub fn projection(&self) -> JsonProjection {
        fn belongs(e: &JsonEntry) -> Option<&Tag> {
            e.n.as_ref().or(e.g.as_ref())
        }
        fn group(entries: &[JsonEntry], parent: Option<&Tag>) -> JsonProjection {
            JsonProjection {
                sv: entries
                    .iter()
                    .filter(|e| belongs(e) == parent)
                    .map(|e| Pair16 { s: e.s, vs: e.vs })
                    .collect(),
                el: entries
                    .iter()
                    .filter(|e| e.n.is_some() && e.g.as_ref() == parent)
                    .map(|e| group(entries, e.n.as_ref()))
                    .collect(),
            }
        }
        group(&self.entries, None)
    }
}

#[derive(Serialize, Deserialize)]
struct PairWire {
    s: String,
    vs: String,
}

#[derive(Serialize, Deserialize)]
struct GroupWire {
    sv: Vec<PairWire>,
    el: Vec<GroupWire>,
}

#[derive(Serialize, Deserialize)]
struct QueryWire {
    #[serde(flatten)]
    group: GroupWire,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    alt: Option<GroupWire>,
}

impl From<&JsonProjection> for GroupWire {
    fn from(group: &JsonProjection) -> Self {
        Self {
            sv: group
                .sv
                .iter()
                .map(|p| PairWire {
                    s: hex(&p.s),
                    vs: hex(&p.vs),
                })
                .collect(),
            el: group.el.iter().map(GroupWire::from).collect(),
        }
    }
}

impl TryFrom<GroupWire> for JsonProjection {
    type Error = super::WireError;
    fn try_from(w: GroupWire) -> Result<Self, Self::Error> {
        let tag = |text: &str| {
            Tag::try_from(super::unhex(text)?).map_err(|_| super::WireError("not 16 bytes"))
        };
        Ok(Self {
            sv: w
                .sv
                .iter()
                .map(|p| {
                    Ok(Pair16 {
                        s: tag(&p.s)?,
                        vs: tag(&p.vs)?,
                    })
                })
                .collect::<Result<_, super::WireError>>()?,
            el: w
                .el
                .into_iter()
                .map(JsonProjection::try_from)
                .collect::<Result<_, _>>()?,
        })
    }
}

impl Serialize for JsonQuery {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        QueryWire {
            group: GroupWire::from(&self.group),
            alt: self.alt.as_ref().map(GroupWire::from),
        }
        .serialize(s)
    }
}

impl<'de> Deserialize<'de> for JsonQuery {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let wire = QueryWire::deserialize(d)?;
        Ok(Self {
            group: JsonProjection::try_from(wire.group).map_err(serde::de::Error::custom)?,
            alt: wire
                .alt
                .map(JsonProjection::try_from)
                .transpose()
                .map_err(serde::de::Error::custom)?,
        })
    }
}

/// The query term of `AtPath<Lt | Lte | Gt | Gte>`: the selector of the
/// path and the leaf ordering term of the value, which the SQL compares
/// against the stored leaf's: `col -> $1 >= $2`. Serializes to the
/// `query_json_tree_leaf` operand, `{"s": "…", "op": "…"}`. `Between`
/// sends two as one [`RangeQuery`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JsonLeafQuery {
    s: Tag,
    op: Vec<u8>,
}

impl JsonLeafQuery {
    fn of_leaf(terms: &JsonTerms) -> Self {
        // `check` admitted only a number or a string, both of which carry a
        // term; an empty term here would be a leaf that cannot be.
        let leaf = terms.leaf();
        Self {
            s: leaf.map(|n| n.s).unwrap_or_default(),
            op: leaf.and_then(|n| n.op.clone()).unwrap_or_default(),
        }
    }

    /// The path's selector, for `->`.
    pub fn selector(&self) -> JsonSelector {
        JsonSelector(self.s)
    }

    /// The leaf's ordering term, as the `op` of a stored leaf is.
    pub fn ordering_term(&self) -> &[u8] {
        &self.op
    }
}

#[derive(Serialize, Deserialize)]
struct LeafWire {
    s: String,
    op: String,
}

impl Serialize for JsonLeafQuery {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        LeafWire {
            s: hex(&self.s),
            op: hex(&self.op),
        }
        .serialize(s)
    }
}

impl<'de> Deserialize<'de> for JsonLeafQuery {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let wire = LeafWire::deserialize(d)?;
        let s = super::unhex(&wire.s)
            .ok()
            .and_then(|b| Tag::try_from(b).ok())
            .ok_or_else(|| serde::de::Error::custom("not a selector"))?;
        let op = super::unhex(&wire.op).map_err(serde::de::Error::custom)?;
        Ok(Self { s, op })
    }
}

/// A path selector: what `->` and the path functions take. Prints and
/// serializes as the hex the stored entry carries in `s`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct JsonSelector(pub(crate) Tag);

impl JsonSelector {
    /// The sixteen bytes.
    pub fn as_bytes(&self) -> &Tag {
        &self.0
    }
}

impl fmt::Display for JsonSelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex(&self.0))
    }
}

impl fmt::Debug for JsonSelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "JsonSelector({})", hex(&self.0))
    }
}

impl Serialize for JsonSelector {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex(&self.0))
    }
}

/// The key of a subtree walk: the token of a positional node, and, when
/// the walked path continues with a wildcard below it, the selector of the
/// whole path the walk gates on. Serializes as `{"t": "…", "s": "…"}`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct JsonSubtreeKey {
    pub(crate) token: Tag,
    pub(crate) selector: Option<Tag>,
}

impl JsonSubtreeKey {
    /// The token, as the hex the walk takes.
    pub fn token(&self) -> String {
        hex(&self.token)
    }

    /// The token's bytes. A token is a capability over the structure of
    /// one subtree in every row of the column, for as long as the column
    /// lives: send it to the server for a query, and nowhere else.
    pub fn token_bytes(&self) -> &Tag {
        &self.token
    }

    /// The selector the walk gates on, when the path has a wildcard below
    /// the token's node.
    pub fn selector(&self) -> Option<JsonSelector> {
        self.selector.map(JsonSelector)
    }
}

/// The token is a capability: it prints as the key's shape, not its bytes.
impl fmt::Debug for JsonSubtreeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JsonSubtreeKey")
            .field("gated", &self.selector.is_some())
            .finish_non_exhaustive()
    }
}

impl Serialize for JsonSubtreeKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Wire {
            t: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            s: Option<String>,
        }
        Wire {
            t: hex(&self.token),
            s: self.selector.as_ref().map(|t| hex(t)),
        }
        .serialize(s)
    }
}

/// The terms of an accessor's input: the path it was asked at, and the
/// index's terms of the needle that holds the value there. What
/// [`Input<Pathed<A>>`](Input) derives, and what the JSON index's
/// [`Supports`] impls build an accessor's query from.
#[derive(Clone, Debug)]
pub struct AtPathTerms<T> {
    path: JsonPath,
    terms: T,
}

impl<T> AtPathTerms<T> {
    /// The path the query was asked at.
    pub fn path(&self) -> &JsonPath {
        &self.path
    }

    /// The terms of the needle, or of both needles for a pair of bounds.
    pub fn terms(&self) -> &T {
        &self.terms
    }
}

impl QueryTerm for JsonQuery {}
impl QueryTerm for JsonLeafQuery {}

// =============================================================================
// Inputs: a path and a value, or a path and a pair of bounds
// =============================================================================

fn parse_path(text: &str) -> Result<JsonPath, Error> {
    JsonPath::parse(text).map_err(|e| Error::Term(TermError::JsonPath(e)))
}

/// A path and a value: the input of `AtPath<Eq>` and the single-bound
/// orderings. The index is declared over the document, so the plaintext
/// is a [`Value`], and the term is derived over the needle that holds the
/// value at the path.
impl<P, V> Input<Pathed<One>> for (P, V)
where
    P: AsRef<str> + 'static,
    V: Into<Value> + 'static,
{
    type Plaintext = Value;
    type Terms<T: 'static> = AtPathTerms<T>;

    fn derive<'a, 'p, I, K>(
        self,
        index: &I,
        keyset: &'p KeysetCipher<'a, K>,
        label: Label,
        extend: DeclaredContext,
    ) -> Pending<'p, AtPathTerms<I::Term>, K>
    where
        I: Index<Value>,
        K: 'static,
    {
        let (path, value) = self;
        let path = match parse_path(path.as_ref()) {
            Ok(path) => path,
            Err(error) => return Pending::failed(keyset, error),
        };
        let needle = path.needle(value.into());
        keyset
            .run(
                index.operation::<K, Owned>().under(NonEmpty::from(label)),
                needle,
                extend,
            )
            .map(move |terms| AtPathTerms { path, terms })
    }
}

/// A path and a pair of bounds: the input of `AtPath<Between>`. Both
/// needles derive under the one label, settled together.
impl<P, V> Input<Pathed<Pair>> for (P, (V, V))
where
    P: AsRef<str> + 'static,
    V: Into<Value> + 'static,
{
    type Plaintext = Value;
    type Terms<T: 'static> = AtPathTerms<(T, T)>;

    fn derive<'a, 'p, I, K>(
        self,
        index: &I,
        keyset: &'p KeysetCipher<'a, K>,
        label: Label,
        extend: DeclaredContext,
    ) -> Pending<'p, AtPathTerms<(I::Term, I::Term)>, K>
    where
        I: Index<Value>,
        K: 'static,
    {
        let (path, (lo, hi)) = self;
        let path = match parse_path(path.as_ref()) {
            Ok(path) => path,
            Err(error) => return Pending::failed(keyset, error),
        };
        let lo = keyset.run(
            index
                .operation::<K, Owned>()
                .under(NonEmpty::from(label.clone())),
            path.needle(lo.into()),
            extend.clone(),
        );
        let hi = keyset.run(
            index.operation::<K, Owned>().under(NonEmpty::from(label)),
            path.needle(hi.into()),
            extend,
        );
        lo.zip(hi).map(move |terms| AtPathTerms { path, terms })
    }
}

// =============================================================================
// What the index answers
// =============================================================================

/// Containment, both ways: the needle's projection, which the SQL compares
/// against the stored projection in the direction the operator says.
macro_rules! containment {
    ($($op:ident),+ $(,)?) => {$(
        impl Supports<$op, Value> for Json {
            type Query = JsonQuery;
            type Verifier = ();
            fn check(&self, _: &Value) -> Result<(), Error> {
                Ok(())
            }
            fn verifier(&self, _: &Value) {}
            fn query((): (), terms: JsonTerms, _: QueryToken) -> JsonQuery {
                JsonQuery::of_terms(&terms)
            }
        }
        impl Answers<$op, Value> for JsonDocument {
            type Via = Json;
        }
        impl DefaultIndex<Value> for $op {
            type Via = Json;
        }
    )+};
}
containment!(Contains, ContainedBy);

/// Equality at a path: the needle that holds the value at the path,
/// projected, which containment answers exactly. A position in the path
/// reads as the wildcard, since selectors do not tell positions apart.
impl<P, V> Supports<AtPath<Eq>, (P, V)> for Json
where
    P: AsRef<str> + 'static,
    V: Into<Value> + 'static,
{
    type Query = JsonQuery;
    type Verifier = ();
    fn check(&self, (path, _): &(P, V)) -> Result<(), Error> {
        parse_path(path.as_ref()).map(drop)
    }
    fn verifier(&self, _: &(P, V)) {}
    fn query((): (), terms: AtPathTerms<JsonTerms>, _: QueryToken) -> JsonQuery {
        JsonQuery::of_terms(&terms.terms)
    }
}
impl<P, V> Answers<AtPath<Eq>, (P, V)> for JsonDocument
where
    P: AsRef<str> + 'static,
    V: Into<Value> + 'static,
{
    type Via = Json;
}
impl<P, V> DefaultIndex<(P, V)> for AtPath<Eq>
where
    P: AsRef<str> + 'static,
    V: Into<Value> + 'static,
{
    type Via = Json;
}

/// Whether `value` is a leaf the index orders: a number or a string.
fn ordered(value: &Value) -> Result<(), Error> {
    match value {
        Value::Number(_) | Value::String(_) => Ok(()),
        _ => Err(TermError::JsonLeafNotOrdered.into()),
    }
}

/// The orderings at a path: the path's selector and the value's leaf
/// ordering term. Refused, when the query is awaited, for a value that is
/// neither a number nor a string.
macro_rules! orderings {
    ($($op:ident),+ $(,)?) => {$(
        impl<P, V> Supports<AtPath<$op>, (P, V)> for Json
        where
            P: AsRef<str> + 'static,
            V: Into<Value> + Clone + 'static,
        {
            type Query = JsonLeafQuery;
            type Verifier = ();
            fn check(&self, (path, value): &(P, V)) -> Result<(), Error> {
                let _ = parse_path(path.as_ref())?;
                ordered(&value.clone().into())
            }
            fn verifier(&self, _: &(P, V)) {}
            fn query((): (), terms: AtPathTerms<JsonTerms>, _: QueryToken) -> JsonLeafQuery {
                JsonLeafQuery::of_leaf(&terms.terms)
            }
        }
        impl<P, V> Answers<AtPath<$op>, (P, V)> for JsonDocument
        where
            P: AsRef<str> + 'static,
            V: Into<Value> + Clone + 'static,
        {
            type Via = Json;
        }
        impl<P, V> DefaultIndex<(P, V)> for AtPath<$op>
        where
            P: AsRef<str> + 'static,
            V: Into<Value> + Clone + 'static,
        {
            type Via = Json;
        }
    )+};
}
orderings!(Lt, Lte, Gt, Gte);

impl<P, V> Supports<AtPath<Between>, (P, (V, V))> for Json
where
    P: AsRef<str> + 'static,
    V: Into<Value> + Clone + 'static,
{
    type Query = RangeQuery<JsonLeafQuery>;
    type Verifier = ();
    fn check(&self, (path, (lo, hi)): &(P, (V, V))) -> Result<(), Error> {
        let _ = parse_path(path.as_ref())?;
        ordered(&lo.clone().into())?;
        ordered(&hi.clone().into())
    }
    fn verifier(&self, _: &(P, (V, V))) {}
    fn query(
        (): (),
        terms: AtPathTerms<(JsonTerms, JsonTerms)>,
        _: QueryToken,
    ) -> RangeQuery<JsonLeafQuery> {
        let (lo, hi) = &terms.terms;
        RangeQuery::new(JsonLeafQuery::of_leaf(lo), JsonLeafQuery::of_leaf(hi))
    }
}
impl<P, V> Answers<AtPath<Between>, (P, (V, V))> for JsonDocument
where
    P: AsRef<str> + 'static,
    V: Into<Value> + Clone + 'static,
{
    type Via = Json;
}
impl<P, V> DefaultIndex<(P, (V, V))> for AtPath<Between>
where
    P: AsRef<str> + 'static,
    V: Into<Value> + Clone + 'static,
{
    type Via = Json;
}

/// The options a query derives under must be the stored document's; a
/// plan that declares the index carries them, and a query through it takes
/// them from there.
impl Json {
    /// The index's layout options.
    pub fn options(&self) -> JsonOptions {
        self.options
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_query_serializes_as_the_needle_operand() {
        let pair = |b: u8| Pair16 {
            s: [b; 16],
            vs: [b + 1; 16],
        };
        let query = JsonQuery {
            group: JsonProjection {
                sv: vec![pair(1)],
                el: vec![JsonProjection {
                    sv: vec![pair(3)],
                    el: vec![],
                }],
            },
            alt: None,
        };
        let json = serde_json::to_value(&query).unwrap();
        assert_eq!(
            json,
            json!({
                "sv": [{"s": "01".repeat(16), "vs": "02".repeat(16)}],
                "el": [{"sv": [{"s": "03".repeat(16), "vs": "04".repeat(16)}], "el": []}],
            })
        );
        let back: JsonQuery = serde_json::from_value(json).unwrap();
        assert_eq!(back, query);
    }

    #[test]
    fn group_containment_is_jsonbs_rule() {
        let pair = |b: u8| Pair16 {
            s: [b; 16],
            vs: [b; 16],
        };
        let element = |pairs: &[u8]| JsonProjection {
            sv: pairs.iter().map(|&b| pair(b)).collect(),
            el: vec![],
        };
        let stored = JsonProjection {
            sv: vec![pair(0)],
            el: vec![element(&[1, 5]), element(&[7, 2])],
        };
        // The issue's example: 1 and 2 sit in different elements.
        assert!(!stored.contains(&JsonProjection {
            sv: vec![],
            el: vec![element(&[1, 2])],
        }));
        assert!(stored.contains(&JsonProjection {
            sv: vec![],
            el: vec![element(&[1, 5])],
        }));
        assert!(stored.contains(&JsonProjection {
            sv: vec![pair(0)],
            el: vec![element(&[1]), element(&[2])],
        }));
        assert!(!stored.contains(&JsonProjection {
            sv: vec![pair(9)],
            el: vec![],
        }));
    }
}
