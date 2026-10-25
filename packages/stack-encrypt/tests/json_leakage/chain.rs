//! The token chain's public hash functions, written out from the design
//! rather than imported, because both sides of the harness need them on
//! bytes they observe: the database's half of the walk recomputes them over
//! a stored row's `iv`, a token it was sent and the selectors it holds, and
//! the simulator programs its random tags with them.
//!
//! These are the only functions of the real scheme the harness evaluates.
//! Everything keyed (selectors, value selectors, head tokens, member ranks)
//! stays on the client and is replaced by randomness in the simulator.
//! `chain_is_the_crates_chain` (in `calibration.rs`) holds them to the
//! crate's own walk, `JsonDocument::subtree`.

use sha2::{Digest, Sha256};

/// A sixteen-byte tag: a selector, a value selector or a token.
pub type Tag16 = [u8; 16];

/// An eight-byte tag: a parent tag `p` or a self tag `x`.
pub type Tag8 = [u8; 8];

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    let mut out = [0; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

fn first<const N: usize>(full: [u8; 32]) -> [u8; N] {
    let mut tag = [0; N];
    tag.copy_from_slice(&full[..N]);
    tag
}

/// `H8("p" ‖ iv ‖ t(parent) ‖ LE32(o))`: the parent tag of the child at
/// ordinal `o` under the node whose token is `parent`.
pub fn parent_tag(iv: &Tag16, parent: &Tag16, ordinal: u32) -> Tag8 {
    first(sha256(&[b"p", iv, parent, &ordinal.to_le_bytes()]))
}

/// `H8("x" ‖ iv ‖ t(self))`: the self tag of the node whose token is
/// `token`, by which the database finds that node in a row.
pub fn self_tag(iv: &Tag16, token: &Tag16) -> Tag8 {
    first(sha256(&[b"x", iv, token]))
}

/// `H16("t" ‖ t(parent) ‖ s(member))`: an object member's token. No
/// ordinal, so the client derives it from the path alone.
pub fn member_token(parent: &Tag16, selector: &Tag16) -> Tag16 {
    first(sha256(&[b"t", parent, selector]))
}

/// `H16("t" ‖ t(array) ‖ s(element) ‖ LE32(i))`: an array element's token,
/// `i` its index. This is the pre-#1363 chain's rule for every child, kept
/// for elements, whose ordinal was always their index.
pub fn element_token(array: &Tag16, selector: &Tag16, index: u32) -> Tag16 {
    first(sha256(&[b"t", array, selector, &index.to_le_bytes()]))
}

/// Which rule a hit's self tag matched, as the database tests them: the
/// member rule first, then the element rule with the hit's ordinal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Rule {
    Member,
    Element,
}

/// The token the database derives for a hit found at `ordinal` under the
/// node whose token is `parent`, and the rule that gave it: the member
/// rule's if the hit's self tag `x` is that token's, else the element
/// rule's if it is that one's, else none
/// (`eql_v4_internal.json_tree_hit_token`).
pub fn hit_token(
    iv: &Tag16,
    parent: &Tag16,
    selector: &Tag16,
    x: Option<&Tag8>,
    ordinal: u32,
) -> Option<(Tag16, Rule)> {
    let x = x?;
    let member = member_token(parent, selector);
    if self_tag(iv, &member) == *x {
        return Some((member, Rule::Member));
    }
    let element = element_token(parent, selector, ordinal);
    (self_tag(iv, &element) == *x).then_some((element, Rule::Element))
}

/// The simulator's stand-in for the keyed member rank: any keyed function of
/// the parent's token and the member's selector will do, since the real one
/// is a PRF under a key the database never sees. The simulator samples its
/// own `key`.
pub fn simulated_rank(key: &[u8; 32], parent: &Tag16, selector: &Tag16) -> Tag16 {
    first(sha256(&[b"rank", key, parent, selector]))
}
