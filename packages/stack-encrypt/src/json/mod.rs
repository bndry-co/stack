//! The JSON index: a document stored as one searchable value, with
//! node-local ciphertexts, a token chain and exact containment.
//!
//! `docs/plans/2026-10-17-json-tree-index.md` is the design
//! this module implements, and the authority on why. In short, a document
//! is flattened into one entry per node. Each entry carries:
//!
//! - a **selector** `s`, a PRF of the node's path with every array position
//!   folded into the wildcard, so every element of an array shares one;
//! - a **value selector** `vs`, a PRF of the node's kind and, for a scalar,
//!   its canonical value, bound to `s`; containment is a set comparison
//!   over these two;
//! - the node's own **ciphertext** `c`, sealed under one ZeroKMS data key
//!   per document: the node's label, its kind and, for a scalar, its
//!   value, and for a container its child count. Nothing beneath a node is
//!   encrypted in that node's entry, so a document's ciphertext is linear
//!   in its size;
//! - the **token chain** fields `p` and `w`, which let the server walk the
//!   subtree under a node from one client-derived token and nothing else,
//!   and the **group tags** `n` and `g`, which tell the server which
//!   entries sit inside the same array element, so containment agrees with
//!   PostgreSQL's own `jsonb @>` across elements;
//! - a leaf ordering term `op` on number and string leaves, the same OPE
//!   term the scalar [`Ope`](crate::target::Ope) index derives, keyed by
//!   the column.
//!
//! By default the root is **sealed** ([`JsonOptions::sealed_root`]): the root
//! entry's ciphertext is the whole document, the top-level fields are the
//! heads of the chain, and no token exists for the root, so no query can
//! hand the server a token that unlocks the shape of every row in the
//! column.
//!
//! # What the types are
//!
//! [`Json`](struct@crate::target::Json) is the index, an [`Index<Value>`](crate::target::Index)
//! whose term is a [`JsonTerms`]: the one-way terms of a document (its
//! selectors, tokens and grouping), which a query is built from. Sealing is
//! a separate operation, [`json_document`](crate::target::json_document),
//! whose output is the stored [`JsonDocument`]; `JsonDocument` is itself an
//! [`EncryptFrom<Value>`](crate::EncryptFrom) target, so a plan or a record
//! names it by type. The query terms are [`JsonQuery`] (containment and
//! `AtPath<Eq>`), [`JsonLeafQuery`] (ordering at a path), and the two
//! extraction keys a caller derives through the keyset cipher,
//! [`JsonSelector`] and [`JsonSubtreeKey`]. What the server returns for an
//! extraction opens through [`JsonNode`] (one entry) and [`JsonSubtree`]
//! (the entries under a token).
//!
//! # Where this deviates from the design
//!
//! Two deliberate deviations, recorded here so the plan can be read against
//! the code:
//!
//! - **Nonces are random, not derived.** The design derives each entry's
//!   AES-GCM nonce from its selector and ordinal. This module seals every
//!   entry through the engine's one AEAD path (`vitaminc-encrypt`'s
//!   `Aes256Cipher`, a fresh random 96-bit nonce per seal, carried in the
//!   ciphertext), so there is one leaf cipher in the crate and no second
//!   AES-GCM call site. Uniqueness under one document key is probabilistic
//!   rather than structural: at `N` entries the collision probability is
//!   `N² / 2^97`, negligible for any document. The ordinal still binds the
//!   entry to its place through the AAD, so a moved or reordered entry fails
//!   to open as the design requires. The cost is twelve bytes per entry.
//! - **The ordinal field is `o`, not `i`**, because `i` is the EQL
//!   envelope's identifier, which the SQL grafts onto an extracted entry.
//!
//! # Byte encodings
//!
//! The document's wire form is JSON, as the EQL domain stores it:
//! sixteen-byte fields (`s`, `vs`, `p`, `w`, `n`, `g`) and the OPE term `op`
//! in lowercase hex, the ciphertext `c` and the header `h` in standard
//! base64. The header's bytes are a frozen layout, [`JsonHeader`]. The
//! derivations are versioned by their PAE domain labels, as every other
//! term kind's are ([`sem`](crate::sem)): a change to any of them is a new
//! version, never an edit in place.
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vitaminc_protected::OpaqueDebug;

use crate::target::{DecryptField, DecryptInto, Decryptable, Decryption};

mod derive;
mod path;
mod query;

pub use derive::JsonTerms;
pub use path::{JsonPath, JsonPathError, Segment};
pub use query::{
    AtPathTerms, JsonLeafQuery, JsonProjection, JsonQuery, JsonSelector, JsonSubtreeKey,
};

pub(crate) use derive::{seal_pending, terms_pending};

/// A sixteen-byte tag: a selector, a token, a parent tag or a group tag.
pub type Tag = [u8; 16];

/// How a JSON index lays a document out. Part of the index's identity: a
/// stored document and the query probing it must agree on it, so it rides
/// in the data plan beside the index and is recorded in every document's
/// header.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct JsonOptions {
    /// Seal the root: the root entry's ciphertext is the whole document and
    /// the top-level fields are the heads of the token chain, so no token
    /// for the root exists and no query can hand the server one. On by
    /// default. Off, the chain starts at the root and a query may walk the
    /// whole document from the root's token.
    pub sealed_root: bool,
}

impl Default for JsonOptions {
    fn default() -> Self {
        Self { sealed_root: true }
    }
}

/// The document's key header, stored once in `h`: what retrieving the
/// document's data key needs, and which shape the root has.
///
/// # Frozen byte encoding
///
/// | offset | field | size | value |
/// |---|---|---|---|
/// | 0 | header version | 1 | [`FORMAT_VERSION`](Self::FORMAT_VERSION) (`0x01`) |
/// | 1 | flags | 1 | bit 0: the root is sealed |
/// | 2 | epoch | 4 | `u32` little-endian; reserved, always `0` |
/// | 6 | keyset id | 16 | the keyset the data key was minted under, raw UUID bytes |
/// | 22 | ZeroKMS `iv` | 16 | identifies the data key for retrieval; also the per-document salt of the chain tags |
/// | 38 | `tag_len` | 2 | `u16` little-endian |
/// | 40 | ZeroKMS key `tag` | `tag_len` | required to retrieve the key |
///
/// The SQL reads the `iv` at offset 22 to compute parent and group tags; it
/// parses nothing else. The epoch is reserved for bounding a revealed token
/// in time (the design's "Epochs"); writing it now keeps that a new value
/// rather than a new layout.
///
/// `Debug` ([`OpaqueDebug`]) prints the keyset and the layout, which say
/// what a header is for, and masks the ZeroKMS `iv` and `tag`, which
/// retrieve the data key.
#[derive(Clone, PartialEq, Eq, OpaqueDebug)]
pub struct JsonHeader {
    #[non_sensitive]
    keyset_id: Uuid,
    iv: stack_kms::Iv,
    tag: Vec<u8>,
    #[non_sensitive]
    sealed_root: bool,
    #[non_sensitive]
    epoch: u32,
}

/// The [`JsonHeader`] bytes are not the frozen layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error, miette::Diagnostic)]
#[non_exhaustive]
pub enum JsonHeaderError {
    /// The leading version byte is not one this build parses.
    #[error("unknown JSON header version {0}")]
    #[diagnostic(code(stack_encrypt::json_header_version))]
    UnknownVersion(u8),
    /// The bytes end before the fixed fields, or before the tag promised.
    #[error("JSON header bytes are truncated")]
    #[diagnostic(code(stack_encrypt::json_header_truncated))]
    Truncated,
}

impl JsonHeader {
    /// The version byte of the frozen layout.
    pub const FORMAT_VERSION: u8 = 1;
    const FLAG_SEALED_ROOT: u8 = 0b1;
    const FIXED_LEN: usize = 1 + 1 + 4 + 16 + 16 + 2;

    /// The keyset the document's data key was minted under.
    pub fn keyset_id(&self) -> Uuid {
        self.keyset_id
    }

    /// The ZeroKMS IV of the document's data key: its identifier, and the
    /// per-document salt of every chain tag.
    pub fn iv(&self) -> &stack_kms::Iv {
        &self.iv
    }

    /// The ZeroKMS key tag.
    pub fn tag(&self) -> &[u8] {
        &self.tag
    }

    /// Whether the root is sealed: see [`JsonOptions::sealed_root`].
    pub fn sealed_root(&self) -> bool {
        self.sealed_root
    }

    /// The layout this document was laid out under.
    pub fn options(&self) -> JsonOptions {
        JsonOptions {
            sealed_root: self.sealed_root,
        }
    }

    /// The frozen byte layout; see the type docs.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::FIXED_LEN + self.tag.len());
        out.push(Self::FORMAT_VERSION);
        out.push(if self.sealed_root {
            Self::FLAG_SEALED_ROOT
        } else {
            0
        });
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(self.keyset_id.as_bytes());
        out.extend_from_slice(&self.iv);
        // `seal_pending` refuses a tag longer than the field, so the
        // saturation is unreachable; it is a bound, not a case.
        out.extend_from_slice(
            &u16::try_from(self.tag.len())
                .unwrap_or(u16::MAX)
                .to_le_bytes(),
        );
        out.extend_from_slice(&self.tag);
        out
    }

    /// Parse the frozen byte layout. Structural only: nothing here is
    /// trusted until an entry opens under the key it names.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, JsonHeaderError> {
        let (&version, rest) = bytes.split_first().ok_or(JsonHeaderError::Truncated)?;
        if version != Self::FORMAT_VERSION {
            return Err(JsonHeaderError::UnknownVersion(version));
        }
        if rest.len() < Self::FIXED_LEN - 1 {
            return Err(JsonHeaderError::Truncated);
        }
        let (flags, rest) = rest.split_at(1);
        let (epoch, rest) = rest.split_at(4);
        let (keyset, rest) = rest.split_at(16);
        let (iv, rest) = rest.split_at(16);
        let (tag_len, rest) = rest.split_at(2);
        let tag_len = usize::from(u16::from_le_bytes([tag_len[0], tag_len[1]]));
        if rest.len() < tag_len {
            return Err(JsonHeaderError::Truncated);
        }
        let mut iv_bytes: stack_kms::Iv = [0; 16];
        iv_bytes.copy_from_slice(iv);
        Ok(Self {
            keyset_id: Uuid::from_slice(keyset).map_err(|_| JsonHeaderError::Truncated)?,
            iv: iv_bytes,
            tag: rest[..tag_len].to_vec(),
            sealed_root: flags[0] & Self::FLAG_SEALED_ROOT != 0,
            epoch: u32::from_le_bytes([epoch[0], epoch[1], epoch[2], epoch[3]]),
        })
    }

    pub(crate) fn new(keyset_id: Uuid, iv: stack_kms::Iv, tag: Vec<u8>, sealed_root: bool) -> Self {
        Self {
            keyset_id,
            iv,
            tag,
            sealed_root,
            epoch: 0,
        }
    }
}

/// One entry of a stored document: one JSON node.
///
/// Every field but `s`, `vs` and `c` is optional, and which are present
/// says what the node is: `p`, `w` and `o` on a node whose parent has a
/// token (everything below the chain's heads); `n` on an array element
/// that is a container; `g` on every entry inside such an element; `op` on
/// a number or string leaf.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JsonEntry {
    s: Tag,
    vs: Tag,
    c: Vec<u8>,
    o: Option<u32>,
    p: Option<Tag>,
    w: Option<Tag>,
    n: Option<Tag>,
    g: Option<Tag>,
    op: Option<Vec<u8>>,
}

impl JsonEntry {
    /// The path selector.
    pub fn selector(&self) -> &Tag {
        &self.s
    }
    /// The value selector.
    pub fn value_selector(&self) -> &Tag {
        &self.vs
    }
    /// The node's ciphertext, as sealed.
    pub fn ciphertext(&self) -> &[u8] {
        &self.c
    }
    /// The node's ordinal under its parent, when its parent has a token.
    pub fn ordinal(&self) -> Option<u32> {
        self.o
    }
    /// The parent tag, when the parent has a token.
    pub fn parent_tag(&self) -> Option<&Tag> {
        self.p.as_ref()
    }
    /// The wrapped token, when the parent has a token.
    pub fn wrapped_token(&self) -> Option<&Tag> {
        self.w.as_ref()
    }
    /// This node's group tag, when it is an array element that is a
    /// container.
    pub fn group_tag(&self) -> Option<&Tag> {
        self.n.as_ref()
    }
    /// The enclosing array element's group tag, when this node sits inside
    /// an element that is a container.
    pub fn enclosing_group_tag(&self) -> Option<&Tag> {
        self.g.as_ref()
    }
    /// The leaf ordering term, on a number or string leaf.
    pub fn ordering_term(&self) -> Option<&[u8]> {
        self.op.as_deref()
    }
}

/// A stored JSON document: its [`JsonHeader`] and its entries, one per
/// node, in depth-first pre-order with the root first. What
/// [`json_document`](crate::target::json_document) produces and
/// [`DecryptInto<Value>`](crate::DecryptInto) opens.
///
/// Serializes to the wire form the EQL domain stores: `{"h": "…", "sv":
/// [{"s": "…", "vs": "…", "c": "…", …}, …], "q": {"sv": [{"s", "vs"}, …],
/// "el": […]}}`, where `q` is the document's own containment
/// [projection](Self::projection), written once so the server never
/// rebuilds it; see the [module docs](self#byte-encodings).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "DocumentWire", into = "DocumentWire")]
pub struct JsonDocument {
    header: JsonHeader,
    entries: Vec<JsonEntry>,
}

impl JsonDocument {
    /// The document's header.
    pub fn header(&self) -> &JsonHeader {
        &self.header
    }

    /// The entries, in depth-first pre-order; the root is first.
    pub fn entries(&self) -> &[JsonEntry] {
        &self.entries
    }

    /// The children of the node whose token is `token`, as the server
    /// finds them: every entry whose parent tag is the tag of `token` at
    /// the entry's own ordinal, with its own token unwrapped, in ordinal
    /// order. The SQL walk finds the same entries by trying the ordinals
    /// `0..F`, where `F` is one more than the largest ordinal in the
    /// document; checking each entry at its own ordinal gives the same
    /// answer without a loop whose length a stored document chooses. A
    /// token that names no node yields nothing.
    ///
    /// What a `jsonb_array_elements(doc, token)` returns; one level of the
    /// walk [`subtree`](Self::subtree) runs to the bottom.
    pub fn children(&self, token: &Tag) -> Vec<(usize, &JsonEntry, Tag)> {
        let iv = &self.header.iv;
        let mut out: Vec<(usize, &JsonEntry, Tag)> = self
            .entries
            .iter()
            .enumerate()
            .filter_map(|(j, e)| {
                let (p, w, o) = (e.p.as_ref()?, e.w.as_ref()?, e.o?);
                (derive::parent_tag(iv, token, o) == *p).then(|| {
                    let child = derive::xor(w, &derive::mask(iv, token, &e.c));
                    (j, e, child)
                })
            })
            .collect();
        out.sort_by_key(|(_, e, _)| e.o);
        out
    }

    /// Every entry under the node whose token is `token`, with its depth
    /// below that node, as the server's recursive walk finds them: the node
    /// itself is not included, since the walk addresses nodes by their
    /// parent. In depth-first order, siblings by ordinal.
    ///
    /// A stored document is untrusted, and its tags need not form a tree:
    /// whoever holds a token can write a chain deeper than any document the
    /// index seals, or a cycle. The walk stops descending below the deepest
    /// level a sealed document has, and stops once it has returned as many
    /// entries as the document holds, which a tree never exceeds, so it
    /// ends, and in bounded stack, on any document.
    pub fn subtree(&self, token: &Tag) -> Vec<(usize, &JsonEntry, u32)> {
        let mut out = Vec::new();
        self.walk(token, 1, &mut out);
        out
    }

    fn walk<'a>(&'a self, token: &Tag, depth: u32, out: &mut Vec<(usize, &'a JsonEntry, u32)>) {
        if depth as usize > derive::MAX_DEPTH {
            return;
        }
        for (j, entry, child) in self.children(token) {
            if out.len() >= self.entries.len() {
                return;
            }
            out.push((j, entry, depth));
            self.walk(&child, depth + 1, out);
        }
    }

    /// The node at ordinal `j` as an extraction returns it: the entry with
    /// the header beside it, which opens on its own.
    pub fn node(&self, j: usize) -> Option<JsonNode> {
        self.entries.get(j).map(|entry| JsonNode {
            entry: entry.clone(),
            header: self.header.clone(),
            j: j as u64,
            depth: None,
        })
    }

    pub(crate) fn new(header: JsonHeader, entries: Vec<JsonEntry>) -> Self {
        Self { header, entries }
    }
}

impl Decryptable for JsonDocument {
    const DECRYPTABLE: bool = true;
}
impl<P: 'static, Ctx> DecryptField<P, Ctx> for JsonDocument
where
    Self: crate::DecryptInto<P>,
    Ctx: Into<<Self as crate::DecryptInto<P>>::Context>,
{
    fn decryption_field<K: 'static>(self, context: Ctx) -> Option<Decryption<P, K>> {
        Some(self.decryption(context.into()))
    }
}

/// One entry as an extraction returns it: the entry, the document's header
/// grafted beside it, and the entry's ordinal `j` in the document, which
/// its ciphertext is bound to. What `->` and the walk return per row, and
/// what [`DecryptInto<Value>`](crate::DecryptInto) opens to the node's
/// scalar, or to the whole document for a sealed root.
///
/// Deserializes from the entry's wire fields plus `h` and `j`, and tolerates
/// the envelope fields the SQL grafts beside them (`i`, `v`, `d`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "NodeWire", into = "NodeWire")]
pub struct JsonNode {
    entry: JsonEntry,
    header: JsonHeader,
    j: u64,
    depth: Option<u32>,
}

impl JsonNode {
    /// The entry.
    pub fn entry(&self) -> &JsonEntry {
        &self.entry
    }
    /// The document's header.
    pub fn header(&self) -> &JsonHeader {
        &self.header
    }
    /// The entry's ordinal in the document.
    pub fn ordinal(&self) -> u64 {
        self.j
    }
    /// The entry's depth below the walk's start, when the walk reported one.
    pub fn depth(&self) -> Option<u32> {
        self.depth
    }
}

impl Decryptable for JsonNode {
    const DECRYPTABLE: bool = true;
}
impl<P: 'static, Ctx> DecryptField<P, Ctx> for JsonNode
where
    Self: crate::DecryptInto<P>,
    Ctx: Into<<Self as crate::DecryptInto<P>>::Context>,
{
    fn decryption_field<K: 'static>(self, context: Ctx) -> Option<Decryption<P, K>> {
        Some(self.decryption(context.into()))
    }
}

/// The entries the server's walk returned for one token: what
/// `json_tree_subtree(doc, token)` yields, collected, and what
/// [`DecryptInto<Value>`](crate::DecryptInto) reassembles into the value
/// under that node.
///
/// The walk returns the node's descendants and not the node itself, so the
/// node's kind is read from its children's labels: elements make an array,
/// members an object. A node with no descendants, an empty container or a
/// scalar, yields no rows and so no value; `->` on its selector returns the
/// node itself.
///
/// Past its budget, a walk over a document with a sealed root returns the
/// root entry alone, at depth `0`, instead of a subtree it would be
/// cheaper to open whole: the client opens the document and takes the
/// walked path over it. Opening such rows needs that path, attached with
/// [`at`](Self::at); without it the opening fails with
/// [`Error::OpenedType`](crate::Error::OpenedType).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct JsonSubtree {
    nodes: Vec<JsonNode>,
    #[serde(skip)]
    path: Option<JsonPath>,
}

impl JsonSubtree {
    /// The rows, as returned.
    pub fn new(nodes: Vec<JsonNode>) -> Self {
        Self { nodes, path: None }
    }

    /// The rows with the path the walk was keyed from: what the opening
    /// takes over the whole document when the rows are the sealed root
    /// the server fell back to. A positional path opens to one value; a
    /// path with a wildcard, as `json_tree_subtree_at` walks, to one value
    /// per node it reaches.
    pub fn at(self, path: JsonPath) -> Self {
        Self {
            path: Some(path),
            ..self
        }
    }

    /// The rows.
    pub fn nodes(&self) -> &[JsonNode] {
        &self.nodes
    }

    /// The path attached with [`at`](Self::at), if any.
    pub fn path(&self) -> Option<&JsonPath> {
        self.path.as_ref()
    }

    /// Whether the rows are the sealed root the server returned in place
    /// of a subtree past its budget: one row, the root, at depth `0`.
    pub fn is_sealed_root(&self) -> bool {
        matches!(
            self.nodes.as_slice(),
            [node] if node.j == 0 && node.depth == Some(0) && node.header.sealed_root()
        )
    }
}

impl Decryptable for JsonSubtree {
    const DECRYPTABLE: bool = true;
}
impl<P: 'static, Ctx> DecryptField<P, Ctx> for JsonSubtree
where
    Self: crate::DecryptInto<P>,
    Ctx: Into<<Self as crate::DecryptInto<P>>::Context>,
{
    fn decryption_field<K: 'static>(self, context: Ctx) -> Option<Decryption<P, K>> {
        Some(self.decryption(context.into()))
    }
}

// =============================================================================
// Wire form
// =============================================================================

/// Lowercase hex, as the SQL decodes with `decode(x, 'hex')`.
pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(DIGITS[usize::from(b >> 4)] as char);
        out.push(DIGITS[usize::from(b & 0xf)] as char);
    }
    out
}

/// The inverse of [`hex`]; either case.
pub(crate) fn unhex(text: &str) -> Result<Vec<u8>, WireError> {
    fn nibble(c: u8) -> Result<u8, WireError> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(WireError("not hex")),
        }
    }
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(WireError("odd hex length"));
    }
    bytes
        .chunks_exact(2)
        .map(|pair| Ok(nibble(pair[0])? << 4 | nibble(pair[1])?))
        .collect()
}

fn unhex16(text: &str) -> Result<Tag, WireError> {
    Tag::try_from(unhex(text)?).map_err(|_| WireError("not 16 bytes"))
}

fn base64(bytes: &[u8]) -> String {
    use base64ct::{Base64, Encoding};
    Base64::encode_string(bytes)
}

fn unbase64(text: &str) -> Result<Vec<u8>, WireError> {
    use base64ct::{Base64, Encoding};
    Base64::decode_vec(text).map_err(|_| WireError("not base64"))
}

/// A wire field that does not decode. Names the field's fault and never its
/// text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a JSON index wire field does not decode: {0}")]
pub struct WireError(&'static str);

/// `h`, `sv` and `q`, as stored. `q` is written from the entries and not
/// read back: a document deserialized from the wire derives its projection
/// from `sv` again, so the field is accepted and ignored on the way in.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DocumentWire {
    h: String,
    sv: Vec<EntryWire>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    q: Option<query::GroupWire>,
}

/// One entry, as stored: tags in hex, the ciphertext in base64.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EntryWire {
    s: String,
    vs: String,
    c: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    o: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    p: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    w: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    n: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    g: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    op: Option<String>,
}

impl From<&JsonEntry> for EntryWire {
    fn from(e: &JsonEntry) -> Self {
        Self {
            s: hex(&e.s),
            vs: hex(&e.vs),
            c: base64(&e.c),
            o: e.o,
            p: e.p.as_ref().map(|t| hex(t)),
            w: e.w.as_ref().map(|t| hex(t)),
            n: e.n.as_ref().map(|t| hex(t)),
            g: e.g.as_ref().map(|t| hex(t)),
            op: e.op.as_deref().map(hex),
        }
    }
}

impl TryFrom<EntryWire> for JsonEntry {
    type Error = WireError;

    fn try_from(w: EntryWire) -> Result<Self, WireError> {
        Ok(Self {
            s: unhex16(&w.s)?,
            vs: unhex16(&w.vs)?,
            c: unbase64(&w.c)?,
            o: w.o,
            p: w.p.as_deref().map(unhex16).transpose()?,
            w: w.w.as_deref().map(unhex16).transpose()?,
            n: w.n.as_deref().map(unhex16).transpose()?,
            g: w.g.as_deref().map(unhex16).transpose()?,
            op: w.op.as_deref().map(unhex).transpose()?,
        })
    }
}

impl From<JsonDocument> for DocumentWire {
    fn from(doc: JsonDocument) -> Self {
        Self {
            h: base64(&doc.header.to_bytes()),
            sv: doc.entries.iter().map(EntryWire::from).collect(),
            q: Some(query::GroupWire::from(&doc.projection())),
        }
    }
}

impl TryFrom<DocumentWire> for JsonDocument {
    type Error = WireError;

    fn try_from(w: DocumentWire) -> Result<Self, WireError> {
        let header =
            JsonHeader::from_bytes(&unbase64(&w.h)?).map_err(|_| WireError("not a header"))?;
        let entries =
            w.sv.into_iter()
                .map(JsonEntry::try_from)
                .collect::<Result<_, _>>()?;
        Ok(Self { header, entries })
    }
}

/// An extracted entry: the entry's fields, the grafted header and ordinal,
/// and whatever else the SQL grafted (`i`, `v`), which is ignored.
#[derive(Clone, Serialize, Deserialize)]
struct NodeWire {
    #[serde(flatten)]
    entry: EntryWire,
    h: String,
    j: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    d: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    i: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    v: Option<serde_json::Value>,
}

impl From<JsonNode> for NodeWire {
    fn from(node: JsonNode) -> Self {
        Self {
            entry: EntryWire::from(&node.entry),
            h: base64(&node.header.to_bytes()),
            j: node.j,
            d: node.depth,
            i: None,
            v: None,
        }
    }
}

impl TryFrom<NodeWire> for JsonNode {
    type Error = WireError;

    fn try_from(w: NodeWire) -> Result<Self, WireError> {
        Ok(Self {
            entry: JsonEntry::try_from(w.entry)?,
            header: JsonHeader::from_bytes(&unbase64(&w.h)?)
                .map_err(|_| WireError("not a header"))?,
            j: w.j,
            depth: w.d,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_header_round_trips_its_frozen_layout() {
        let header = JsonHeader::new(Uuid::from_u128(7), [9; 16], vec![1, 2, 3], true);
        let bytes = header.to_bytes();
        assert_eq!(bytes[0], JsonHeader::FORMAT_VERSION);
        assert_eq!(bytes[1], 1, "the sealed-root flag");
        assert_eq!(&bytes[2..6], &[0; 4], "the epoch is reserved at zero");
        assert_eq!(
            &bytes[22..38],
            &[9; 16],
            "the iv sits at offset 22, where the SQL reads it"
        );
        assert_eq!(JsonHeader::from_bytes(&bytes).unwrap(), header);
        let open = JsonHeader::new(Uuid::from_u128(7), [9; 16], vec![], false);
        assert_eq!(JsonHeader::from_bytes(&open.to_bytes()).unwrap(), open);
        assert!(!JsonHeader::from_bytes(&open.to_bytes())
            .unwrap()
            .sealed_root());
        assert!(matches!(
            JsonHeader::from_bytes(&bytes[..10]),
            Err(JsonHeaderError::Truncated)
        ));
        assert!(matches!(
            JsonHeader::from_bytes(&[2]),
            Err(JsonHeaderError::UnknownVersion(2))
        ));
    }

    #[test]
    fn a_header_reads_back_what_it_was_made_with() {
        let header = JsonHeader::new(Uuid::from_u128(7), [9; 16], vec![1, 2, 3], false);
        assert_eq!(header.keyset_id(), Uuid::from_u128(7));
        assert_eq!(header.iv(), &[9; 16]);
        assert_eq!(header.tag(), &[1, 2, 3]);
        assert!(!header.sealed_root());
        assert_eq!(header.options(), JsonOptions { sealed_root: false });
        let sealed = JsonHeader::new(Uuid::from_u128(7), [9; 16], vec![], true);
        assert_eq!(sealed.options(), JsonOptions { sealed_root: true });
    }

    #[test]
    fn every_truncation_of_a_header_is_refused() {
        let header = JsonHeader::new(Uuid::from_u128(7), [9; 16], vec![1, 2, 3], true);
        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), 40 + 3, "the fixed fields, then the tag");
        // Short of the fixed fields, and short of the tag `tag_len` promises.
        for len in 0..bytes.len() {
            assert_eq!(
                JsonHeader::from_bytes(&bytes[..len]),
                Err(JsonHeaderError::Truncated),
                "{len} bytes"
            );
        }
        let bare = JsonHeader::new(Uuid::from_u128(7), [9; 16], vec![], true);
        assert_eq!(
            JsonHeader::from_bytes(&bare.to_bytes()),
            Ok(bare),
            "the fixed fields alone are a header with an empty tag"
        );
    }

    #[test]
    fn a_header_prints_its_keyset_and_layout_and_masks_the_key_identifiers() {
        let header = JsonHeader::new(Uuid::from_u128(7), [9; 16], vec![1, 2, 3], true);
        assert_eq!(
            format!("{header:?}"),
            format!(
                "stack_encrypt::json::JsonHeader {{ keyset_id: {:?}, iv: \"***\", tag: \"***\", sealed_root: true, epoch: 0 }}",
                Uuid::from_u128(7)
            )
        );
    }

    /// A chained entry that unwraps to `child` under `parent` at ordinal `o`,
    /// as whoever holds `parent` can write one.
    fn chained(iv: &[u8], parent: &Tag, o: u32, child: &Tag, c: Vec<u8>) -> JsonEntry {
        JsonEntry {
            s: [0; 16],
            vs: [0; 16],
            o: Some(o),
            p: Some(derive::parent_tag(iv, parent, o)),
            w: Some(derive::xor(child, &derive::mask(iv, parent, &c))),
            n: None,
            g: None,
            op: None,
            c,
        }
    }

    fn root() -> JsonEntry {
        JsonEntry {
            s: [0; 16],
            vs: [0; 16],
            c: vec![0],
            o: None,
            p: None,
            w: None,
            n: None,
            g: None,
            op: None,
        }
    }

    fn document(entries: Vec<JsonEntry>) -> JsonDocument {
        JsonDocument::new(
            JsonHeader::new(Uuid::from_u128(7), [9; 16], vec![], true),
            entries,
        )
    }

    #[test]
    fn an_ordinal_at_the_top_of_its_range_is_an_entry_like_any_other() {
        let token = [1; 16];
        let mut entry = chained(&[9; 16], &token, u32::MAX, &[2; 16], vec![3; 20]);
        let doc = document(vec![root(), entry.clone()]);
        let children = doc.children(&token);
        assert_eq!(children.len(), 1, "found at its own ordinal, no fan-out");
        assert_eq!(children[0].2, [2; 16]);
        assert!(doc.children(&[7; 16]).is_empty());
        entry.p = Some([0; 16]);
        assert!(document(vec![root(), entry]).children(&token).is_empty());
    }

    #[test]
    fn a_walk_ends_on_tags_that_do_not_form_a_tree() {
        let iv = [9; 16];
        let token = [1; 16];
        // Two children of the token that each unwrap to the token itself:
        // a cycle that doubles at every level.
        let cycle = document(vec![
            root(),
            chained(&iv, &token, 0, &token, vec![4; 20]),
            chained(&iv, &token, 1, &token, vec![5; 20]),
        ]);
        assert_eq!(
            cycle.subtree(&token).len(),
            cycle.entries().len(),
            "no more entries than the document holds"
        );

        // A chain longer than any document the index seals.
        let mut entries = vec![root()];
        let mut parent = token;
        for i in 0..1000u32 {
            let mut child = [0; 16];
            child[..4].copy_from_slice(&i.to_le_bytes());
            child[15] = 0xee;
            entries.push(chained(&iv, &parent, 0, &child, i.to_le_bytes().to_vec()));
            parent = child;
        }
        let chain = document(entries);
        let walked = chain.subtree(&token);
        assert_eq!(walked.len(), derive::MAX_DEPTH, "cut at the deepest level");
        assert_eq!(
            walked.last().map(|(_, _, depth)| *depth as usize),
            Some(derive::MAX_DEPTH)
        );
    }

    #[test]
    fn hex_round_trips_and_refuses_what_is_not_hex() {
        assert_eq!(hex(&[0, 15, 255]), "000fff");
        assert_eq!(unhex("000FfF").unwrap(), vec![0, 15, 255]);
        assert!(unhex("abc").is_err());
        assert!(unhex("zz").is_err());
    }
}
