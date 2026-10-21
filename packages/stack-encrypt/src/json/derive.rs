//! The derivations: flattening a document into its terms, sealing the
//! entries under one data key, and opening them again.
//!
//! One walk ([`walk`]) serves both the index's term operation and the
//! sealing operation, so a query derives exactly the selectors a stored
//! document carries. The walk is depth-first, pre-order, siblings in key
//! order for an object and in position order for an array; every entry's
//! ordinal `j` is its place in that order, and the AAD of its ciphertext
//! binds it there.
use std::collections::BTreeMap;

use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use vitaminc_aead::{Cipher, Context, IntoAad, IntoContext, LocalCipherText};
use vitaminc_encrypt::{Aes256Cipher, Key as AesKey};
use vitaminc_hmac::HmacSha256Prf;
use vitaminc_prf::{BlockVisitor, IntoPrfContext, PrfValue};
use vitaminc_protected::{Controlled, Protected};

use super::path::{JsonPath, Segment};
use super::query::{JsonSelector, JsonSubtreeKey};
use super::{JsonDocument, JsonEntry, JsonHeader, JsonNode, JsonOptions, JsonSubtree, Tag};
use crate::sem::TermError;
use crate::target::{AeadContext, CallerContext, Decryption, Pending, Request};
use crate::{DecryptInto, Descriptor, Error, KeysetCipher, NonEmpty, StackCipher};

/// PAE domain of the path selector `s`.
const SELECTOR_DOMAIN: &[u8] = b"stack-encrypt/json/selector/v1";
/// PAE domain of the value selector `vs`.
const VALUE_DOMAIN: &[u8] = b"stack-encrypt/json/value/v1";
/// PAE domain of a chain head's token: the root's, or a top-level field's
/// under the sealed root.
const TOKEN_DOMAIN: &[u8] = b"stack-encrypt/json/token/v1";
/// PAE domain of an entry's AAD.
const ENTRY_AAD_DOMAIN: &[u8] = b"stack-encrypt/json/entry/v1";

/// Deeper than this is refused rather than walked: the walk recurses, and a
/// document built in memory can nest deeper than any parser admits.
const MAX_DEPTH: usize = 512;

/// The byte that leads a sealed root's plaintext: the whole document, not a
/// node.
const SEALED_ROOT: u8 = 0xff;

/// A node's kind: what its value selector says it is, and what its
/// ciphertext's first byte records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Null,
    Bool,
    Number,
    String,
    Object,
    Array,
}

impl Kind {
    fn of(value: &Value) -> Self {
        match value {
            Value::Null => Kind::Null,
            Value::Bool(_) => Kind::Bool,
            Value::Number(_) => Kind::Number,
            Value::String(_) => Kind::String,
            Value::Object(_) => Kind::Object,
            Value::Array(_) => Kind::Array,
        }
    }

    pub(crate) fn is_container(self) -> bool {
        matches!(self, Kind::Object | Kind::Array)
    }

    fn byte(self) -> u8 {
        match self {
            Kind::Null => 0,
            Kind::Bool => 1,
            Kind::Number => 2,
            Kind::String => 3,
            Kind::Object => 4,
            Kind::Array => 5,
        }
    }

    fn from_byte(byte: u8) -> Option<Self> {
        Some(match byte {
            0 => Kind::Null,
            1 => Kind::Bool,
            2 => Kind::Number,
            3 => Kind::String,
            4 => Kind::Object,
            5 => Kind::Array,
            _ => return None,
        })
    }

    /// The tag the value selector binds: a container contributes its tag
    /// alone, so every object has one value selector at a path and every
    /// array another.
    fn tag(self) -> &'static [u8] {
        match self {
            Kind::Null => b"NULL",
            Kind::Bool => b"BOOL",
            Kind::Number => b"NUM",
            Kind::String => b"STR",
            Kind::Object => b"MAP0{}",
            Kind::Array => b"ARRY[]",
        }
    }
}

/// A node's label under its parent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Label {
    Root,
    Key(String),
    Index(u64),
}

/// One node's one-way terms: what a query is built from, and what sealing
/// adds the ciphertext and chain fields to.
#[derive(Clone, Debug)]
pub(crate) struct TermNode {
    /// The node's positional path.
    pub(crate) positional: JsonPath,
    pub(crate) s: Tag,
    pub(crate) vs: Tag,
    /// The node's token: every node has one except the sealed root.
    pub(crate) token: Option<Tag>,
    /// The leaf ordering term, on a number or string.
    pub(crate) op: Option<Vec<u8>>,
    pub(crate) parent: Option<usize>,
    /// The node's ordinal under its parent, when the parent has a token.
    pub(crate) ordinal: Option<u32>,
    /// The nearest enclosing array element that is a container.
    pub(crate) element: Option<usize>,
    /// Whether this node is an array element that is a container.
    pub(crate) container_element: bool,
}

/// One node's plaintext, as its ciphertext encodes it.
struct NodePlain {
    label: Label,
    kind: Kind,
    scalar: Option<Value>,
    children: u32,
}

/// The one-way terms of a document: one term node per node, in the
/// walk's order, with the root first. The term of the
/// [`Json`](struct@crate::target::Json) index, and what every query term is built
/// from; it holds no plaintext and no key.
#[derive(Clone, Debug)]
pub struct JsonTerms {
    nodes: Vec<TermNode>,
    /// For a document whose root is a scalar: the selector pair the same
    /// scalar has as an element of a root array, so a containment needle
    /// can match a stored `["a"]` as `jsonb @>` does.
    alt: Option<(Tag, Tag)>,
}

impl JsonTerms {
    /// The path selector of the node at `path`, which names the node
    /// positionally, or `None` when the document has no node there.
    pub fn selector(&self, path: &JsonPath) -> Option<JsonSelector> {
        self.nodes
            .iter()
            .find(|n| &n.positional == path)
            .map(|n| JsonSelector(n.s))
    }

    /// How many nodes the document has.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether the document has no nodes. It never has: a document has a
    /// root.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    pub(crate) fn nodes(&self) -> &[TermNode] {
        &self.nodes
    }

    pub(crate) fn alt(&self) -> Option<(Tag, Tag)> {
        self.alt
    }

    /// The last node of the walk: in a needle built from one path, the
    /// leaf the path names.
    pub(crate) fn leaf(&self) -> Option<&TermNode> {
        self.nodes.last()
    }
}

// =============================================================================
// Primitives
// =============================================================================

fn truncate(block: &[u8]) -> Tag {
    let mut tag = [0; 16];
    tag.copy_from_slice(&block[..16]);
    tag
}

/// The first sixteen bytes of the PRF of `input` under `domain` and the
/// column's context.
fn prf16(
    prf: &HmacSha256Prf,
    domain: &[u8],
    context: &Context<'_>,
    input: &[u8],
) -> Result<Tag, TermError> {
    let block: [u8; 32] = input
        .prf_visit_with_context(
            prf,
            Context::pae(&[domain, context.as_bytes()]),
            BlockVisitor,
        )
        .into_result()
        .map_err(TermError::from_prf)?;
    Ok(truncate(&block))
}

/// The first sixteen bytes of SHA-256 over the concatenation of `parts`.
/// Plain SHA-256 by design: the design's "Why plain SHA-256 is enough here"
/// records why length extension does not apply.
fn h16(parts: &[&[u8]]) -> Tag {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    truncate(&hasher.finalize())
}

/// `H("t" ‖ t(parent) ‖ 0x01 ‖ key)` or `H("t" ‖ t(parent) ‖ 0x02 ‖ LE64(index))`.
fn child_token(parent: &Tag, label: &Label) -> Tag {
    match label {
        Label::Key(key) => h16(&[b"t", parent, &[0x01], key.as_bytes()]),
        Label::Index(index) => h16(&[b"t", parent, &[0x02], &index.to_le_bytes()]),
        Label::Root => *parent,
    }
}

/// `H("p" ‖ iv ‖ t(parent) ‖ LE32(ordinal))`: position-keyed, so siblings
/// are unlinkable at rest.
pub(super) fn parent_tag(iv: &[u8], parent: &Tag, ordinal: u32) -> Tag {
    h16(&[b"p", iv, parent, &ordinal.to_le_bytes()])
}

/// `H("w" ‖ iv ‖ t(parent) ‖ c)`: the mask a child's token is wrapped under.
pub(super) fn mask(iv: &[u8], parent: &Tag, c: &[u8]) -> Tag {
    h16(&[b"w", iv, parent, c])
}

/// `H("g" ‖ iv ‖ t(element))`: an array element's group tag.
fn group_tag(iv: &[u8], token: &Tag) -> Tag {
    h16(&[b"g", iv, token])
}

/// `H("o" ‖ t(parent) ‖ key)`: what an object's members are ranked by for
/// their ordinals, so an ordinal does not rank key names.
fn rank(parent: &Tag, key: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"o");
    hasher.update(parent);
    hasher.update(key.as_bytes());
    hasher.finalize().into()
}

pub(super) fn xor(a: &Tag, b: &Tag) -> Tag {
    let mut out = [0; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = a[i] ^ b[i];
    }
    out
}

/// A number's canonical bytes for its value selector: an integral value,
/// whichever JSON spelling it had, is its `i128`; anything else is its
/// `f64`. So `2` and `2.0` are one value, as `jsonb` compares them, and
/// `-0.0` is `0`.
fn canonical_number(number: &Number) -> Vec<u8> {
    fn int(i: i128) -> Vec<u8> {
        let mut out = Vec::with_capacity(17);
        out.push(b'i');
        out.extend_from_slice(&i.to_le_bytes());
        out
    }
    if let Some(i) = number.as_i64() {
        return int(i128::from(i));
    }
    if let Some(u) = number.as_u64() {
        return int(i128::from(u));
    }
    let f = number.as_f64().unwrap_or(0.0);
    if f.fract() == 0.0 && f.abs() < 1e38 {
        return int(f as i128);
    }
    let mut out = Vec::with_capacity(9);
    out.push(b'f');
    out.extend_from_slice(&f.to_le_bytes());
    out
}

/// A scalar's canonical bytes; a container contributes nothing beyond its
/// kind's tag.
fn canonical(value: &Value) -> Vec<u8> {
    match value {
        Value::Null | Value::Object(_) | Value::Array(_) => Vec::new(),
        Value::Bool(b) => vec![u8::from(*b)],
        Value::Number(n) => canonical_number(n),
        Value::String(s) => s.as_bytes().to_vec(),
    }
}

/// The value selector: the PRF of the kind's tag, the path selector and
/// the canonical value, PAE-framed.
fn value_selector(
    prf: &HmacSha256Prf,
    context: &Context<'_>,
    s: &Tag,
    value: &Value,
) -> Result<Tag, TermError> {
    let framed = Context::pae(&[Kind::of(value).tag(), s, &canonical(value)]);
    prf16(prf, VALUE_DOMAIN, context, framed.as_bytes())
}

/// The leaf ordering term: the OPE term of a number as an `f64` or of a
/// string, under the column's context, as the scalar `Ope` index derives
/// it. Nothing for any other kind. An integer wider than 53 bits orders by
/// the `f64` it rounds to.
fn leaf_op(
    prf: &HmacSha256Prf,
    context: &Context<'_>,
    value: &Value,
) -> Result<Option<Vec<u8>>, TermError> {
    Ok(match value {
        Value::Number(n) => Some(
            crate::sem::ope(prf, n.as_f64().unwrap_or(0.0), context.clone())?
                .into_inner()
                .as_ref()
                .to_vec(),
        ),
        Value::String(s) => Some(
            crate::sem::ope(prf, s.clone(), context.clone())?
                .into_inner()
                .as_ref()
                .to_vec(),
        ),
        _ => None,
    })
}

// =============================================================================
// The walk
// =============================================================================

struct Walked {
    terms: JsonTerms,
    plain: Vec<NodePlain>,
}

struct Walker<'p> {
    prf: &'p HmacSha256Prf,
    context: &'p Context<'p>,
    options: JsonOptions,
    nodes: Vec<TermNode>,
    plain: Vec<NodePlain>,
}

/// Flatten `value` into its terms and its nodes' plaintexts.
fn walk(
    value: &Value,
    options: JsonOptions,
    prf: &HmacSha256Prf,
    context: &Context<'_>,
) -> Result<Walked, TermError> {
    let mut walker = Walker {
        prf,
        context,
        options,
        nodes: Vec::new(),
        plain: Vec::new(),
    };
    let _ = walker.visit(
        value,
        &JsonPath::root(),
        &JsonPath::root(),
        Label::Root,
        None,
        None,
        None,
        None,
        0,
    )?;
    let alt = if Kind::of(value).is_container() {
        None
    } else {
        let wild = JsonPath::root().then(Segment::Wildcard);
        let s = prf16(prf, SELECTOR_DOMAIN, context, &wild.selector_bytes())?;
        let vs = value_selector(prf, context, &s, value)?;
        Some((s, vs))
    };
    Ok(Walked {
        terms: JsonTerms {
            nodes: walker.nodes,
            alt,
        },
        plain: walker.plain,
    })
}

impl Walker<'_> {
    #[allow(clippy::too_many_arguments)]
    fn visit(
        &mut self,
        value: &Value,
        positional: &JsonPath,
        wild: &JsonPath,
        label: Label,
        parent: Option<usize>,
        parent_token: Option<Tag>,
        ordinal: Option<u32>,
        element: Option<usize>,
        depth: usize,
    ) -> Result<usize, TermError> {
        if depth > MAX_DEPTH {
            return Err(TermError::JsonTooDeep);
        }
        let kind = Kind::of(value);
        let s = prf16(
            self.prf,
            SELECTOR_DOMAIN,
            self.context,
            &wild.selector_bytes(),
        )?;
        let vs = value_selector(self.prf, self.context, &s, value)?;
        let token = match (depth, self.options.sealed_root) {
            (0, true) => None,
            (0, false) | (1, true) => Some(prf16(
                self.prf,
                TOKEN_DOMAIN,
                self.context,
                &positional.token_bytes().unwrap_or_default(),
            )?),
            _ => parent_token.map(|p| child_token(&p, &label)),
        };
        let op = leaf_op(self.prf, self.context, value)?;
        let container_element = matches!(label, Label::Index(_)) && kind.is_container();
        let index = self.nodes.len();
        self.nodes.push(TermNode {
            positional: positional.clone(),
            s,
            vs,
            token,
            op,
            parent,
            ordinal,
            element,
            container_element,
        });
        self.plain.push(NodePlain {
            label,
            kind,
            scalar: (!kind.is_container()).then(|| value.clone()),
            children: 0,
        });
        let child_element = if container_element {
            Some(index)
        } else {
            element
        };
        let mut count: u32 = 0;
        match value {
            Value::Object(map) => {
                let ordinals: Option<BTreeMap<String, u32>> =
                    token.map(|t| shuffled_ordinals(&t, map));
                for (key, child) in map {
                    let ordinal = ordinals.as_ref().and_then(|o| o.get(key).copied());
                    let _ = self.visit(
                        child,
                        &positional.then(Segment::Key(key.clone())),
                        &wild.then(Segment::Key(key.clone())),
                        Label::Key(key.clone()),
                        Some(index),
                        token,
                        ordinal,
                        child_element,
                        depth + 1,
                    )?;
                    count += 1;
                }
            }
            Value::Array(items) => {
                for (i, child) in items.iter().enumerate() {
                    let i = u64::try_from(i).map_err(|_| TermError::JsonTooWide)?;
                    let ordinal = token
                        .map(|_| u32::try_from(i))
                        .transpose()
                        .map_err(|_| TermError::JsonTooWide)?;
                    let _ = self.visit(
                        child,
                        &positional.then(Segment::Index(i)),
                        &wild.then(Segment::Wildcard),
                        Label::Index(i),
                        Some(index),
                        token,
                        ordinal,
                        child_element,
                        depth + 1,
                    )?;
                    count += 1;
                }
            }
            _ => {}
        }
        self.plain[index].children = count;
        Ok(index)
    }
}

/// An object's members' ordinals: their positions in the order of their
/// ranks under the parent's token, so the ordinals rank nothing a reader
/// without the token can see.
fn shuffled_ordinals(parent: &Tag, map: &Map<String, Value>) -> BTreeMap<String, u32> {
    let mut ranked: Vec<([u8; 32], &String)> = map.keys().map(|k| (rank(parent, k), k)).collect();
    ranked.sort();
    ranked
        .into_iter()
        .enumerate()
        .map(|(o, (_, key))| (key.clone(), o as u32))
        .collect()
}

// =============================================================================
// Sealing
// =============================================================================

/// The one-way terms of `value` under `context`, as the index's operation
/// derives them: no key is requested.
pub(crate) fn terms_pending<'a, K>(
    value: &Value,
    options: JsonOptions,
    cipher: &'a KeysetCipher<'_, K>,
    context: NonEmpty<CallerContext>,
) -> Pending<'a, JsonTerms, K> {
    let context = context.into_prf_context().into_owned();
    let terms = walk(value, options, cipher.prf(), &context)
        .map(|w| w.terms)
        .map_err(Error::from);
    Pending::ready(cipher, terms)
}

/// Seal `value` into a [`JsonDocument`] under `context`: one data key for
/// the document, requested under the context's descriptor, and every entry
/// sealed under it with the AAD that binds the entry to the document, the
/// column and its ordinal.
pub(crate) fn seal_pending<'a, K: 'static>(
    value: Value,
    options: JsonOptions,
    cipher: &'a KeysetCipher<'_, K>,
    context: NonEmpty<CallerContext>,
) -> Pending<'a, JsonDocument, K> {
    let piece = context.into_context();
    let descriptor = Descriptor::from_piece(&piece);
    if let Err(error) = descriptor.check() {
        return Pending::failed(cipher, error);
    }
    let prf_context = piece.clone().into_prf_context().into_owned();
    let aad = piece.into_aad().into_owned();
    let walked = match walk(&value, options, cipher.prf(), &prf_context) {
        Ok(walked) => walked,
        Err(error) => return Pending::failed(cipher, error.into()),
    };
    let whole = if options.sealed_root {
        match serde_json::to_vec(&value) {
            Ok(bytes) => Some(bytes),
            Err(error) => return Pending::failed(cipher, Error::Other(Box::new(error))),
        }
    } else {
        None
    };
    let keyset_id = cipher.keyset_id();
    Pending::request(
        cipher,
        vec![Request::generate_under(descriptor)],
        move |responses| {
            let key = responses.next_generated_key()?;
            seal(walked, whole, keyset_id, key, &aad, options)
        },
    )
}

/// An entry's AAD: the domain, the keyset, the column's AAD, the key tag,
/// the entry's selector and its ordinal.
fn entry_aad(keyset_id: Uuid, aad: &Context<'_>, tag: &[u8], s: &Tag, j: u64) -> Context<'static> {
    Context::pae(&[
        ENTRY_AAD_DOMAIN,
        keyset_id.as_bytes(),
        aad.as_bytes(),
        tag,
        s,
        &j.to_le_bytes(),
    ])
}

fn leaf_cipher(key: &stack_kms::DataKey) -> Result<Aes256Cipher, Error> {
    Aes256Cipher::new(&AesKey::from(*key.key())).map_err(|_| Error::Aead)
}

/// A node's plaintext: its kind, its child count, its label and, for a
/// scalar, its value.
fn encode_node(plain: &NodePlain) -> Vec<u8> {
    let mut out = vec![plain.kind.byte()];
    out.extend_from_slice(&plain.children.to_le_bytes());
    match &plain.label {
        Label::Root => out.push(0x00),
        Label::Key(key) => {
            out.push(0x01);
            out.extend_from_slice(&(key.len() as u32).to_le_bytes());
            out.extend_from_slice(key.as_bytes());
        }
        Label::Index(index) => {
            out.push(0x02);
            out.extend_from_slice(&index.to_le_bytes());
        }
    }
    match &plain.scalar {
        Some(Value::String(s)) => out.extend_from_slice(s.as_bytes()),
        Some(Value::Number(n)) => out.extend_from_slice(n.to_string().as_bytes()),
        Some(Value::Bool(b)) => out.push(u8::from(*b)),
        _ => {}
    }
    out
}

fn seal(
    walked: Walked,
    whole: Option<Vec<u8>>,
    keyset_id: Uuid,
    key: stack_kms::DataKeyWithTag,
    aad: &Context<'_>,
    options: JsonOptions,
) -> Result<JsonDocument, Error> {
    if key.tag.len() > usize::from(u16::MAX) {
        return Err(Error::Other(
            "the data key's tag does not fit the JSON header".into(),
        ));
    }
    let cipher = leaf_cipher(&key.key)?;
    let iv = key.key.iv;
    let tag = key.tag;
    let nodes = &walked.terms.nodes;
    let mut entries = Vec::with_capacity(nodes.len());
    for (j, (node, plain)) in nodes.iter().zip(&walked.plain).enumerate() {
        let plaintext = match (&whole, j) {
            (Some(whole), 0) => {
                let mut out = Vec::with_capacity(whole.len() + 1);
                out.push(SEALED_ROOT);
                out.extend_from_slice(whole);
                out
            }
            _ => encode_node(plain),
        };
        let c = cipher
            .seal(
                Protected::new(plaintext),
                &entry_aad(keyset_id, aad, &tag, &node.s, j as u64),
            )
            .map_err(|_| Error::Aead)?;
        let c = c.as_ref().to_vec();
        let parent_token = node.parent.and_then(|p| nodes[p].token);
        let (o, p, w) = match (parent_token, node.ordinal, node.token) {
            (Some(parent), Some(o), Some(token)) => (
                Some(o),
                Some(parent_tag(&iv, &parent, o)),
                Some(xor(&token, &mask(&iv, &parent, &c))),
            ),
            _ => (None, None, None),
        };
        let n = if node.container_element {
            node.token.map(|t| group_tag(&iv, &t))
        } else {
            None
        };
        let g = node
            .element
            .and_then(|e| nodes[e].token)
            .map(|t| group_tag(&iv, &t));
        entries.push(JsonEntry {
            s: node.s,
            vs: node.vs,
            c,
            o,
            p,
            w,
            n,
            g,
            op: node.op.clone(),
        });
    }
    Ok(JsonDocument::new(
        JsonHeader::new(keyset_id, iv, tag, options.sealed_root),
        entries,
    ))
}

// =============================================================================
// Opening
// =============================================================================

/// An opened node.
struct Opened {
    label: Label,
    kind: Kind,
    scalar: Option<Value>,
    children: u32,
    /// The whole document, from a sealed root.
    whole: Option<Value>,
}

fn shape(expected: &'static str) -> Error {
    Error::OpenedType { expected }
}

fn decode_node(bytes: &[u8]) -> Result<Opened, Error> {
    let refused = || shape("a JSON index node");
    let (&first, rest) = bytes.split_first().ok_or_else(refused)?;
    if first == SEALED_ROOT {
        let whole: Value = serde_json::from_slice(rest).map_err(|_| refused())?;
        return Ok(Opened {
            label: Label::Root,
            kind: Kind::of(&whole),
            scalar: None,
            children: 0,
            whole: Some(whole),
        });
    }
    let kind = Kind::from_byte(first).ok_or_else(refused)?;
    if rest.len() < 5 {
        return Err(refused());
    }
    let (count, rest) = rest.split_at(4);
    let children = u32::from_le_bytes([count[0], count[1], count[2], count[3]]);
    let (&label_tag, rest) = rest.split_first().ok_or_else(refused)?;
    let (label, rest) = match label_tag {
        0x00 => (Label::Root, rest),
        0x01 => {
            if rest.len() < 4 {
                return Err(refused());
            }
            let (len, rest) = rest.split_at(4);
            let len = u32::from_le_bytes([len[0], len[1], len[2], len[3]]) as usize;
            if rest.len() < len {
                return Err(refused());
            }
            let (key, rest) = rest.split_at(len);
            let key = std::str::from_utf8(key).map_err(|_| refused())?;
            (Label::Key(key.to_owned()), rest)
        }
        0x02 => {
            if rest.len() < 8 {
                return Err(refused());
            }
            let (index, rest) = rest.split_at(8);
            let mut bytes = [0; 8];
            bytes.copy_from_slice(index);
            (Label::Index(u64::from_le_bytes(bytes)), rest)
        }
        _ => return Err(refused()),
    };
    let scalar = match kind {
        Kind::Null => Some(Value::Null),
        Kind::Bool => Some(Value::Bool(rest.first().is_some_and(|&b| b != 0))),
        Kind::Number => {
            let text = std::str::from_utf8(rest).map_err(|_| refused())?;
            Some(Value::Number(text.parse().map_err(|_| refused())?))
        }
        Kind::String => Some(Value::String(
            std::str::from_utf8(rest).map_err(|_| refused())?.to_owned(),
        )),
        Kind::Object | Kind::Array => None,
    };
    Ok(Opened {
        label,
        kind,
        scalar,
        children,
        whole: None,
    })
}

fn open_entry(
    cipher: &Aes256Cipher,
    header: &JsonHeader,
    aad: &Context<'_>,
    entry: &JsonEntry,
    j: u64,
) -> Result<Opened, Error> {
    let plaintext = cipher
        .open(
            LocalCipherText::from(entry.c.clone()),
            &entry_aad(header.keyset_id, aad, &header.tag, &entry.s, j),
        )
        .map_err(|_| Error::Aead)?;
    decode_node(&plaintext.risky_unwrap())
}

/// Rebuild the value of `node`, taking its descendants from `rest`, the
/// pre-order sequence after it. Every child is taken with `next`, so each
/// step consumes an entry and the rebuild ends on any sequence.
fn rebuild<'a>(
    node: &'a Opened,
    rest: &mut impl Iterator<Item = &'a Opened>,
) -> Result<Value, Error> {
    if let Some(whole) = &node.whole {
        return Ok(whole.clone());
    }
    match node.kind {
        Kind::Object => {
            let mut map = Map::new();
            for _ in 0..node.children {
                let member = next_child(rest)?;
                let Label::Key(key) = &member.label else {
                    return Err(shape("an object member"));
                };
                let value = rebuild(member, rest)?;
                let _ = map.insert(key.clone(), value);
            }
            Ok(Value::Object(map))
        }
        Kind::Array => {
            let mut items = Vec::with_capacity(node.children as usize);
            for i in 0..node.children {
                let element = next_child(rest)?;
                if element.label != Label::Index(u64::from(i)) {
                    return Err(shape("an array element in order"));
                }
                items.push(rebuild(element, rest)?);
            }
            Ok(Value::Array(items))
        }
        _ => node.scalar.clone().ok_or_else(|| shape("a JSON scalar")),
    }
}

fn next_child<'a>(rest: &mut impl Iterator<Item = &'a Opened>) -> Result<&'a Opened, Error> {
    rest.next().ok_or_else(|| shape("a complete JSON subtree"))
}

/// The retrieve request for a document's one data key, and the AAD its
/// entries open under.
fn retrieval(
    header: &JsonHeader,
    context: AeadContext,
) -> Result<(Request, Context<'static>), Error> {
    let piece = context.into_context();
    let descriptor = Descriptor::from_piece(&piece);
    descriptor.check()?;
    Ok((
        Request::retrieve_under(header.iv, header.tag.clone(), descriptor, header.keyset_id),
        piece.into_aad().into_owned(),
    ))
}

/// Open the document: one key retrieval, then the sealed root alone, or
/// every entry rebuilt into the value.
fn open_document<'a, K>(
    doc: JsonDocument,
    cipher: &'a StackCipher<K>,
    context: AeadContext,
) -> Pending<'a, Value, K> {
    let (request, aad) = match retrieval(&doc.header, context) {
        Ok(parts) => parts,
        Err(error) => return Pending::failed(cipher, error),
    };
    Pending::request(cipher, vec![request], move |responses| {
        let key = responses.next_retrieved_key()?;
        let aes = leaf_cipher(&key)?;
        if doc.header.sealed_root {
            let root = doc
                .entries
                .first()
                .ok_or_else(|| shape("a document with a root entry"))?;
            return open_entry(&aes, &doc.header, &aad, root, 0)?
                .whole
                .ok_or_else(|| shape("a sealed root"));
        }
        let opened = doc
            .entries
            .iter()
            .enumerate()
            .map(|(j, entry)| open_entry(&aes, &doc.header, &aad, entry, j as u64))
            .collect::<Result<Vec<_>, _>>()?;
        let mut rest = opened.iter();
        let root = rest
            .next()
            .ok_or_else(|| shape("a document with a root entry"))?;
        let value = rebuild(root, &mut rest)?;
        if rest.next().is_some() {
            return Err(shape("a document with no entries past its root"));
        }
        Ok(value)
    })
}

impl DecryptInto<Value> for JsonDocument {
    type Context = AeadContext;
    fn decryption<K: 'static>(self, context: Self::Context) -> Decryption<Value, K> {
        Decryption::from_open(move |cipher| open_document(self, cipher, context))
    }
}

/// Open one extracted node: the scalar it holds, or the whole document for
/// a sealed root. A container node holds no value of its own and is
/// refused with [`Error::OpenedType`]; its subtree opens through
/// [`JsonSubtree`].
impl DecryptInto<Value> for JsonNode {
    type Context = AeadContext;
    fn decryption<K: 'static>(self, context: Self::Context) -> Decryption<Value, K> {
        Decryption::from_open(move |cipher| {
            let (request, aad) = match retrieval(&self.header, context) {
                Ok(parts) => parts,
                Err(error) => return Pending::failed(cipher, error),
            };
            Pending::request(cipher, vec![request], move |responses| {
                let key = responses.next_retrieved_key()?;
                let aes = leaf_cipher(&key)?;
                let opened = open_entry(&aes, &self.header, &aad, &self.entry, self.j)?;
                opened
                    .whole
                    .or(opened.scalar)
                    .ok_or_else(|| shape("a JSON scalar, or a sealed root"))
            })
        })
    }
}

/// Open the rows of a walk: each complete subtree the rows hold, as a
/// value, in order. What `json_tree_subtree_at` returns is one subtree per
/// node whose selector matched; what `json_tree_subtree` returns is the
/// children of one node, which [`DecryptInto<Value>`] assembles into that
/// node's value. The sealed root a walk fell back to opens whole, and the
/// path attached with [`JsonSubtree::at`] selects over it: one value per
/// node the path reaches.
impl DecryptInto<Vec<Value>> for JsonSubtree {
    type Context = AeadContext;
    fn decryption<K: 'static>(self, context: Self::Context) -> Decryption<Vec<Value>, K> {
        Decryption::from_open(move |cipher| {
            if self.is_sealed_root() {
                return open_fallback(self, cipher, context)
                    .map(|(path, whole)| path.select(&whole).into_iter().cloned().collect());
            }
            open_subtree(self, cipher, context)
                .map(|forest| forest.into_iter().map(|(_, v)| v).collect())
        })
    }
}

/// Open the rows of `json_tree_subtree(doc, token)` into the value under
/// that token: an array when the rows are elements, an object when they are
/// members. No rows is no value ([`Error::OpenedType`]): an empty container
/// and a scalar both have no descendants, and `->` on the node's selector
/// returns the node itself. The sealed root a walk fell back to opens
/// whole, and the path attached with [`JsonSubtree::at`] selects the one
/// value under it; a path that reaches no node, or more than one, is
/// [`Error::OpenedType`].
impl DecryptInto<Value> for JsonSubtree {
    type Context = AeadContext;
    fn decryption<K: 'static>(self, context: Self::Context) -> Decryption<Value, K> {
        Decryption::from_open(move |cipher| {
            if self.is_sealed_root() {
                return open_fallback(self, cipher, context).try_map(|(path, whole)| {
                    let mut found = path.select(&whole);
                    match found.len() {
                        1 => Ok(found.remove(0).clone()),
                        0 => Err(shape("a node at the walked path")),
                        _ => Err(shape("one node at the walked path")),
                    }
                });
            }
            open_subtree(self, cipher, context).try_map(|forest| {
                let mut members = Map::new();
                let mut elements: Vec<(u64, Value)> = Vec::new();
                for (label, value) in forest {
                    match label {
                        Label::Key(key) => {
                            let _ = members.insert(key, value);
                        }
                        Label::Index(i) => elements.push((i, value)),
                        Label::Root => return Err(shape("a subtree below the root")),
                    }
                }
                match (members.is_empty(), elements.is_empty()) {
                    (false, true) => Ok(Value::Object(members)),
                    (true, false) => {
                        elements.sort_by_key(|(i, _)| *i);
                        Ok(Value::Array(elements.into_iter().map(|(_, v)| v).collect()))
                    }
                    (true, true) => Err(shape("a node with children")),
                    (false, false) => Err(shape("the children of one node")),
                }
            })
        })
    }
}

/// Open every row and rebuild each complete subtree, labelled.
fn open_subtree<'a, K>(
    subtree: JsonSubtree,
    cipher: &'a StackCipher<K>,
    context: AeadContext,
) -> Pending<'a, Vec<(Label, Value)>, K> {
    let mut nodes = subtree.nodes;
    nodes.sort_by_key(|n| n.j);
    let Some(first) = nodes.first() else {
        return Pending::ready(cipher, Ok(Vec::new()));
    };
    let header = first.header.clone();
    if nodes.iter().any(|n| n.header != header) {
        return Pending::failed(cipher, shape("rows of one document"));
    }
    let (request, aad) = match retrieval(&header, context) {
        Ok(parts) => parts,
        Err(error) => return Pending::failed(cipher, error),
    };
    Pending::request(cipher, vec![request], move |responses| {
        let key = responses.next_retrieved_key()?;
        let aes = leaf_cipher(&key)?;
        let opened = nodes
            .iter()
            .map(|n| open_entry(&aes, &header, &aad, &n.entry, n.j))
            .collect::<Result<Vec<_>, _>>()?;
        let mut forest = Vec::new();
        let mut rest = opened.iter();
        while let Some(top) = rest.next() {
            let value = rebuild(top, &mut rest)?;
            forest.push((top.label.clone(), value));
        }
        Ok(forest)
    })
}

/// Open the sealed root a walk fell back to: the whole document, with the
/// path the rows were keyed from, which the caller selects over. Refused
/// without the path, since nothing in the rows records it.
fn open_fallback<'a, K>(
    subtree: JsonSubtree,
    cipher: &'a StackCipher<K>,
    context: AeadContext,
) -> Pending<'a, (JsonPath, Value), K> {
    let Some(path) = subtree.path().cloned() else {
        return Pending::failed(
            cipher,
            shape("the walked path, attached with JsonSubtree::at, to select over the sealed root the walk returned"),
        );
    };
    let Some(root) = subtree.nodes().first().cloned() else {
        return Pending::failed(cipher, shape("the sealed root"));
    };
    let (request, aad) = match retrieval(&root.header, context) {
        Ok(parts) => parts,
        Err(error) => return Pending::failed(cipher, error),
    };
    Pending::request(cipher, vec![request], move |responses| {
        let key = responses.next_retrieved_key()?;
        let aes = leaf_cipher(&key)?;
        let opened = open_entry(&aes, &root.header, &aad, &root.entry, root.j)?;
        let whole = opened.whole.ok_or_else(|| shape("a sealed root"))?;
        Ok((path, whole))
    })
}

// =============================================================================
// Extraction keys, on the keyset cipher
// =============================================================================

/// The token of the node at `path`, which must be positional: a chain head
/// by PRF, then one hash per step below it.
fn token_for(
    prf: &HmacSha256Prf,
    context: &Context<'_>,
    options: JsonOptions,
    path: &JsonPath,
) -> Result<Tag, TermError> {
    let segments = path.segments();
    let (head, rest) = if options.sealed_root {
        let Some((first, rest)) = segments.split_first() else {
            return Err(TermError::JsonSealedRoot);
        };
        let head = JsonPath::root().then(first.clone());
        (head, rest)
    } else {
        (JsonPath::root(), segments)
    };
    let mut token = prf16(
        prf,
        TOKEN_DOMAIN,
        context,
        &head.token_bytes().ok_or(TermError::JsonSealedRoot)?,
    )?;
    for segment in rest {
        let label = match segment {
            Segment::Key(key) => Label::Key(key.clone()),
            Segment::Index(index) => Label::Index(*index),
            // `anchor` cut the path before any wildcard.
            Segment::Wildcard => return Err(TermError::JsonSealedRoot),
        };
        token = child_token(&token, &label);
    }
    Ok(token)
}

impl<K> KeysetCipher<'_, K> {
    /// The selector of `path`, under the field `descriptor`: what `->` and
    /// the path functions take. Every element of an array shares its
    /// parent's selector, so a position in `path` reads as the wildcard.
    /// Derived locally; the pending carries no request.
    pub fn json_selector<'c>(
        &self,
        path: &JsonPath,
        descriptor: NonEmpty<impl IntoPrfContext<'c>>,
    ) -> Pending<'_, JsonSelector, K> {
        let context = descriptor.into_prf_context().into_owned();
        let selector = prf16(
            self.prf(),
            SELECTOR_DOMAIN,
            &context,
            &path.selector_bytes(),
        )
        .map(JsonSelector)
        .map_err(Error::from);
        Pending::ready(self, selector)
    }

    /// The key that walks the subtree under `path`, under the field
    /// `descriptor` and the index's `options`: the token of the deepest
    /// positional node on the path, and, when the path continues with a
    /// wildcard below it, the selector of the whole path, which the walk
    /// gates on. What `json_tree_subtree` and `json_tree_subtree_at` take.
    ///
    /// # Errors
    ///
    /// [`TermError::JsonSealedRoot`] for the root, or for a path whose
    /// first step is a wildcard, under the sealed root: no token exists for
    /// the root, and the document opens whole instead.
    pub fn json_subtree_key<'c>(
        &self,
        path: &JsonPath,
        options: JsonOptions,
        descriptor: NonEmpty<impl IntoPrfContext<'c>>,
    ) -> Pending<'_, JsonSubtreeKey, K> {
        let context = descriptor.into_prf_context().into_owned();
        let (anchor, cut) = path.anchor();
        let key = token_for(self.prf(), &context, options, &anchor).and_then(|token| {
            let selector = cut
                .then(|| {
                    prf16(
                        self.prf(),
                        SELECTOR_DOMAIN,
                        &context,
                        &path.selector_bytes(),
                    )
                })
                .transpose()?;
            Ok(JsonSubtreeKey { token, selector })
        });
        Pending::ready(self, key.map_err(Error::from))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use vitaminc_prf::PrfKeyInit;

    fn prf() -> HmacSha256Prf {
        HmacSha256Prf::new(Protected::new([7; 32]))
    }

    fn terms(value: &Value, options: JsonOptions) -> JsonTerms {
        walk(
            value,
            options,
            &prf(),
            &Context::from_encoded(b"users/profile"),
        )
        .unwrap()
        .terms
    }

    #[test]
    fn numbers_canonicalise_by_value() {
        let n = |text: &str| -> Number { text.parse().unwrap() };
        assert_eq!(canonical_number(&n("2")), canonical_number(&n("2.0")));
        assert_eq!(canonical_number(&n("0")), canonical_number(&n("-0.0")));
        assert_ne!(canonical_number(&n("2")), canonical_number(&n("2.5")));
        assert_ne!(canonical_number(&n("1")), canonical_number(&n("-1")));
        assert_eq!(
            canonical_number(&n("18446744073709551615")),
            canonical_number(&n("18446744073709551615"))
        );
        // A value selector is stored, so where an integral float stops
        // reading as an integer is part of the stored form: below 1e38 it
        // is the `i128`, from 1e38 up the `f64`.
        assert_eq!(canonical_number(&n("9.9e37"))[0], b'i');
        assert_eq!(canonical_number(&n("1e38"))[0], b'f');
        assert_eq!(canonical_number(&n("-1e38"))[0], b'f');
    }

    #[test]
    fn the_terms_name_a_node_by_its_path() {
        let t = terms(&json!({"a": [1, {"b": 2}]}), JsonOptions::default());
        // $, $.a, $.a[0], $.a[1], $.a[1].b
        assert_eq!(t.len(), 5);
        assert!(!t.is_empty());
        let at = |path: &str| t.selector(&JsonPath::parse(path).unwrap());
        assert_eq!(at("$.a[1].b"), Some(JsonSelector(t.nodes()[4].s)));
        assert_eq!(at("$.a"), Some(JsonSelector(t.nodes()[1].s)));
        assert_eq!(at("$.a[0]"), at("$.a[1]"), "every element shares one");
        assert_eq!(at("$.c"), None, "no node there");
        assert_eq!(at("$.a[2]"), None, "no third element");
    }

    #[test]
    fn every_element_of_an_array_shares_a_selector_and_values_do_not() {
        let t = terms(&json!({"a": [1, 2, 1]}), JsonOptions::default());
        let nodes = t.nodes();
        assert_eq!(nodes.len(), 5);
        assert_eq!(nodes[2].s, nodes[3].s);
        assert_eq!(nodes[2].s, nodes[4].s);
        assert_eq!(nodes[2].vs, nodes[4].vs, "equal values at one path");
        assert_ne!(nodes[2].vs, nodes[3].vs);
    }

    #[test]
    fn the_sealed_root_has_no_token_and_its_fields_are_heads() {
        let sealed = terms(&json!({"a": {"b": 1}}), JsonOptions::default());
        assert!(sealed.nodes()[0].token.is_none());
        assert!(sealed.nodes()[1].token.is_some());
        assert!(sealed.nodes()[1].ordinal.is_none(), "a head has no ordinal");
        assert!(sealed.nodes()[2].ordinal.is_some());
        let open = terms(&json!({"a": {"b": 1}}), JsonOptions { sealed_root: false });
        assert!(open.nodes()[0].token.is_some());
        assert!(open.nodes()[1].ordinal.is_some());
        // The chain below a head is the same hash chain either way, but
        // the heads differ: one is a PRF of the path, the other a hash
        // under the root's token.
        assert_ne!(sealed.nodes()[1].token, open.nodes()[1].token);
    }

    #[test]
    fn a_head_token_is_what_the_subtree_key_derives() {
        let context = Context::from_encoded(b"users/profile");
        let value = json!({"a": {"b": [1, {"c": 2}]}});
        for options in [JsonOptions::default(), JsonOptions { sealed_root: false }] {
            let t = terms(&value, options);
            for node in t.nodes().iter().filter(|n| n.token.is_some()) {
                let derived = token_for(&prf(), &context, options, &node.positional).unwrap();
                assert_eq!(Some(derived), node.token, "{}", node.positional);
            }
        }
        assert!(matches!(
            token_for(&prf(), &context, JsonOptions::default(), &JsonPath::root()),
            Err(TermError::JsonSealedRoot)
        ));
        assert!(token_for(
            &prf(),
            &context,
            JsonOptions { sealed_root: false },
            &JsonPath::root()
        )
        .is_ok());
    }

    #[test]
    fn a_root_scalar_carries_its_element_selectors_as_alt() {
        let scalar = terms(&json!("a"), JsonOptions::default());
        let array = terms(&json!(["a"]), JsonOptions::default());
        assert_eq!(
            scalar.alt(),
            Some((array.nodes()[1].s, array.nodes()[1].vs)),
            "the alt pair is the stored array element's"
        );
        assert!(terms(&json!({}), JsonOptions::default()).alt().is_none());
    }

    #[test]
    fn container_elements_group_what_sits_inside_them() {
        let t = terms(&json!({"a": [{"x": 1}, 2, [3]]}), JsonOptions::default());
        let nodes = t.nodes();
        // $, $.a, $.a[0], $.a[0].x, $.a[1], $.a[2], $.a[2][0]
        assert!(nodes[2].container_element);
        assert_eq!(nodes[3].element, Some(2));
        assert!(
            !nodes[4].container_element,
            "a scalar element groups nothing"
        );
        assert_eq!(nodes[4].element, None);
        assert!(nodes[5].container_element);
        assert_eq!(nodes[6].element, Some(5));
    }

    #[test]
    fn object_ordinals_are_a_permutation_that_does_not_rank_keys() {
        let map: Map<String, Value> = ["a", "b", "c", "d"]
            .iter()
            .map(|k| (k.to_string(), json!(1)))
            .collect();
        let ordinals = shuffled_ordinals(&[1; 16], &map);
        let mut seen: Vec<u32> = ordinals.values().copied().collect();
        seen.sort_unstable();
        assert_eq!(seen, [0, 1, 2, 3]);
        let other = shuffled_ordinals(&[2; 16], &map);
        assert_ne!(
            ordinals, other,
            "a different token shuffles differently (with overwhelming probability)"
        );
    }

    #[test]
    fn a_node_encodes_and_decodes() {
        for (label, scalar, kind) in [
            (Label::Root, None, Kind::Object),
            (Label::Key("k".into()), Some(json!("v")), Kind::String),
            (Label::Index(3), Some(json!(1.5)), Kind::Number),
            (Label::Index(0), Some(json!(true)), Kind::Bool),
            (Label::Key("n".into()), Some(Value::Null), Kind::Null),
            (Label::Key("a".into()), None, Kind::Array),
        ] {
            let plain = NodePlain {
                label: label.clone(),
                kind,
                scalar: scalar.clone(),
                children: 2,
            };
            let opened = decode_node(&encode_node(&plain)).unwrap();
            assert_eq!(opened.label, label);
            assert_eq!(opened.kind, kind);
            assert_eq!(opened.scalar, scalar);
            assert_eq!(opened.children, 2);
        }
        assert!(decode_node(&[]).is_err());
        assert!(decode_node(&[9, 0, 0, 0, 0, 0]).is_err());

        // The empty key is a key: its label is the tag and a zero length,
        // and nothing after it.
        let empty_key = NodePlain {
            label: Label::Key(String::new()),
            kind: Kind::Object,
            scalar: None,
            children: 0,
        };
        let encoded = encode_node(&empty_key);
        assert_eq!(encoded.len(), 1 + 4 + 1 + 4);
        assert_eq!(
            decode_node(&encoded).unwrap().label,
            Label::Key(String::new())
        );
        // Every truncation of a labelled node is refused, not read past.
        let keyed = encode_node(&NodePlain {
            label: Label::Key("key".into()),
            kind: Kind::Array,
            scalar: None,
            children: 1,
        });
        let indexed = encode_node(&NodePlain {
            label: Label::Index(7),
            kind: Kind::Object,
            scalar: None,
            children: 1,
        });
        for bytes in [&keyed, &indexed, &encoded] {
            for len in 0..bytes.len() {
                assert!(decode_node(&bytes[..len]).is_err(), "{len} of {bytes:?}");
            }
        }
    }

    #[test]
    fn a_key_tag_must_fit_the_header() {
        let value = json!({"a": 1});
        let context = Context::from_encoded(b"users/profile");
        let sealed = |tag_len: usize| {
            let walked = walk(&value, JsonOptions::default(), &prf(), &context).unwrap();
            let key = stack_kms::DataKeyWithTag {
                key: stack_kms::DataKey {
                    iv: [1; 16],
                    key: [2; 32],
                },
                tag: vec![3; tag_len],
                decryption_policy: None,
            };
            seal(
                walked,
                Some(serde_json::to_vec(&value).unwrap()),
                Uuid::from_u128(1),
                key,
                &context,
                JsonOptions::default(),
            )
        };
        let longest = usize::from(u16::MAX);
        let doc = sealed(longest).unwrap();
        assert_eq!(doc.header().tag().len(), longest);
        assert_eq!(
            &JsonHeader::from_bytes(&doc.header().to_bytes()).unwrap(),
            doc.header(),
            "the longest tag the field holds round-trips"
        );
        assert!(matches!(sealed(longest + 1), Err(Error::Other(_))));
    }

    #[test]
    fn too_deep_a_document_is_refused() {
        // The innermost scalar of `n` nested arrays sits at depth `n`.
        let nested = |n: usize| {
            let mut value = json!(1);
            for _ in 0..n {
                value = json!([value]);
            }
            value
        };
        assert!(walk(
            &nested(MAX_DEPTH),
            JsonOptions::default(),
            &prf(),
            &Context::empty()
        )
        .is_ok());
        assert!(matches!(
            walk(
                &nested(MAX_DEPTH + 1),
                JsonOptions::default(),
                &prf(),
                &Context::empty()
            ),
            Err(TermError::JsonTooDeep)
        ));
    }
}
