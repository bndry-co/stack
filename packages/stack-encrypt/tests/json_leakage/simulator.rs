//! The simulator: a wire-shaped world built from a [`Leakage`] and
//! randomness, with no plaintext and no key.
//!
//! Every keyed value is a fresh random string per opaque name (a selector
//! per [`SelId`](super::profile::SelId), a value selector per
//! [`ValueId`](super::profile::ValueId), a head token per
//! [`HeadId`](super::profile::HeadId), a self tag per
//! [`SelfTagId`](super::profile::SelfTagId)), so equality patterns are
//! exactly the profile's. Ciphertexts are random bytes of the stated length
//! behind the frame's public version byte. Ordering terms are random bytes
//! laid out so that byte order is the profile's rank order.
//!
//! The chain is the one place the simulator evaluates the real scheme's
//! public functions ([`super::chain`]): a token the database is sent has to
//! find the node the profile says it names, by that node's self tag, and
//! link the entries the profile says it reaches, by their parent tags and
//! self tags, with the real hash, or the database would notice. So the
//! simulator derives each token a query sends from its random head and the
//! steps the profile names (the member rule or the element rule, as the
//! client does), writes the self tag of that token on each entry the token
//! names, and below it chains every entry the token reaches: its parent tag
//! from its parent's token and its ordinal (an element's position, or a
//! member's rank under a keyed function the simulator samples itself), its
//! self tag from its own token, by the rule the profile states for it.
//! Every other parent and self tag is random bytes, as a tag under a token
//! the database never sees is to it.

use std::collections::HashMap;

use base64ct::{Base64, Encoding};
use proptest::prelude::RngCore;
use proptest::test_runner::TestRng;
use serde_json::{json, Value};

use super::chain::{
    element_token, member_token, parent_tag, self_tag, simulated_rank, Rule, Tag16, Tag8,
};
use super::observe::QueryKind;
use super::profile::{GroupLeakage, Leakage, QueryLeakage, RowLeakage, Step, TokenName, TokenStep};

/// The version byte `vitaminc-encrypt` writes at the front of every
/// ciphertext: public framing, not leakage.
pub const CIPHERTEXT_FRAME: u8 = 2;

/// A fixed-size random value per name, drawn on first use.
struct Names<const N: usize> {
    bytes: HashMap<usize, [u8; N]>,
}

impl<const N: usize> Names<N> {
    fn new() -> Self {
        Self {
            bytes: HashMap::new(),
        }
    }

    fn get(&mut self, id: usize, rng: &mut TestRng) -> [u8; N] {
        *self.bytes.entry(id).or_insert_with(|| random(rng))
    }
}

fn random<const N: usize>(rng: &mut TestRng) -> [u8; N] {
    let mut out = [0; N];
    rng.fill_bytes(&mut out);
    out
}

fn random_vec(rng: &mut TestRng, len: usize) -> Vec<u8> {
    let mut out = vec![0; len];
    rng.fill_bytes(&mut out);
    out
}

fn b64(bytes: &[u8]) -> String {
    Base64::encode_string(bytes)
}

/// The tags a row's entries carry where some query's token links them.
#[derive(Default)]
struct Linked {
    x: HashMap<usize, Tag8>,
    p: HashMap<usize, Tag8>,
}

struct Simulator<'a> {
    leakage: &'a Leakage,
    rng: &'a mut TestRng,
    selectors: Names<16>,
    values: Names<16>,
    heads: Names<16>,
    keysets: Names<16>,
    ivs: Names<16>,
    self_tags: Names<8>,
    tags: HashMap<usize, Vec<u8>>,
    ordering: HashMap<usize, Vec<u8>>,
    rank_key: [u8; 32],
}

/// Build the rows' wire JSON and the queries' wire JSON from `leakage` and
/// `rng` alone.
pub fn simulate(leakage: &Leakage, rng: &mut TestRng) -> (Vec<Value>, Vec<(QueryKind, Value)>) {
    let rank_key = random(rng);
    let mut sim = Simulator {
        leakage,
        rng,
        selectors: Names::new(),
        values: Names::new(),
        heads: Names::new(),
        keysets: Names::new(),
        ivs: Names::new(),
        self_tags: Names::new(),
        tags: HashMap::new(),
        ordering: HashMap::new(),
        rank_key,
    };
    let linked = sim.link();
    let rows = leakage
        .rows
        .iter()
        .zip(linked)
        .map(|(row, linked)| sim.row(row, &linked))
        .collect();
    let queries = leakage.queries.iter().map(|q| sim.query(q)).collect();
    (rows, queries)
}

impl Simulator<'_> {
    fn selector(&mut self, id: usize) -> Tag16 {
        self.selectors.get(id, self.rng)
    }

    fn iv(&mut self, row: &RowLeakage) -> Tag16 {
        self.ivs.get(row.data_key, self.rng)
    }

    /// The token the client derives for `name`: its head's random token,
    /// then each step by its rule.
    fn token(&mut self, name: &TokenName) -> Tag16 {
        let mut t = self.heads.get(name.head, self.rng);
        for step in &name.steps {
            t = match *step {
                TokenStep::Member(s) => member_token(&t, &self.selector(s)),
                TokenStep::Element(s, i) => element_token(
                    &t,
                    &self.selector(s),
                    u32::try_from(i).expect("a small position"),
                ),
            };
        }
        t
    }

    /// An ordering term of `len` bytes for class `class`: a zero byte, the
    /// class's rank big-endian, then random bytes, so byte order is rank
    /// order and equal classes are equal terms.
    fn ordering(&mut self, class: usize, len: usize) -> Vec<u8> {
        if let Some(bytes) = self.ordering.get(&class) {
            assert_eq!(bytes.len(), len, "one class, one length");
            return bytes.clone();
        }
        assert!(len >= 5, "a term is long enough to carry its rank");
        let rank = u32::try_from(self.leakage.ordering_ranks[class]).expect("a small world");
        let mut bytes = vec![0];
        bytes.extend_from_slice(&rank.to_be_bytes());
        bytes.extend(random_vec(self.rng, len - 5));
        let _ = self.ordering.insert(class, bytes.clone());
        bytes
    }

    fn group(&mut self, group: &GroupLeakage) -> Value {
        let pairs: Vec<Value> = group
            .pairs
            .iter()
            .map(|&(s, vs)| {
                let s = self.selector(s);
                let vs = self.values.get(vs, self.rng);
                json!({"s": b64(&s), "vs": b64(&vs)})
            })
            .collect();
        let elements: Vec<Value> = group.elements.iter().map(|g| self.group(g)).collect();
        json!({"sv": pairs, "el": elements})
    }

    /// Entry `i`'s ordinal under its parent, whose token is `parent`: an
    /// element's position, or a member's rank among its sibling members
    /// under the simulator's own keyed rank.
    fn ordinal(&mut self, row: &RowLeakage, i: usize, parent: &Tag16) -> u32 {
        let entry = &row.entries[i];
        match entry.step {
            Step::Element(n) => u32::try_from(n).expect("a small array"),
            Step::Member => {
                let mine = self.selector(entry.selector);
                let my_rank = simulated_rank(&self.rank_key, parent, &mine);
                let siblings: Vec<usize> = (0..row.entries.len())
                    .filter(|&j| {
                        row.entries[j].parent == entry.parent && row.entries[j].step == Step::Member
                    })
                    .collect();
                let below = siblings
                    .into_iter()
                    .filter(|&j| {
                        let theirs = self.selector(row.entries[j].selector);
                        simulated_rank(&self.rank_key, parent, &theirs) < my_rank
                    })
                    .count();
                u32::try_from(below).expect("a small object")
            }
            Step::Root => 0,
        }
    }

    /// The self and parent tags every query's tokens link, row by row:
    /// each token's self tag on the entry it names, and below it the chain
    /// over the entries it reaches.
    ///
    /// Shallower named nodes first, so that where two reads link one entry
    /// the one that names it last sets its tags, and every chain below it
    /// is derived from that. Under the full profile the two always agree;
    /// under a profile that states other rules than the code's (the page as
    /// #1363 published it), this is what keeps the world consistent: a
    /// node a read names keeps the token the read sends, as the database's
    /// test of the member rule first then finds it.
    fn link(&mut self) -> Vec<Linked> {
        let mut linked: Vec<Linked> = self
            .leakage
            .rows
            .iter()
            .map(|_| Linked::default())
            .collect();
        let leakage = self.leakage;
        let depth = |row: &RowLeakage, mut at: usize| {
            let mut d = 0;
            while let Some(p) = row.entries[at].parent {
                d += 1;
                at = p;
            }
            d
        };
        let mut work = Vec::new();
        for query in &leakage.queries {
            let QueryLeakage::Subtree { reads, .. } = query else {
                continue;
            };
            for read in reads {
                let t = self.token(&read.token);
                for (r, row) in leakage.rows.iter().enumerate() {
                    let named = read.hits[r].map_or(0, |h| depth(row, h));
                    work.push((named, work.len(), r, t, read));
                }
            }
        }
        work.sort_by_key(|&(named, order, ..)| (named, order));
        for (_, _, r, t, read) in work {
            let row = &leakage.rows[r];
            let iv = self.iv(row);
            let mut tokens: HashMap<usize, Tag16> = HashMap::new();
            if let Some(h) = read.hits[r] {
                let _ = linked[r].x.insert(h, self_tag(&iv, &t));
                let _ = tokens.insert(h, t);
            }
            // Parents before children: the stored order puts them first,
            // but a mutant may not, so by depth.
            let mut reach = read.reach[r].clone();
            reach.sort_by_key(|&i| (depth(row, i), i));
            for c in reach {
                let entry = &row.entries[c];
                let Some(pt) = entry.parent.and_then(|p| tokens.get(&p).copied()) else {
                    continue;
                };
                let o = self.ordinal(row, c, &pt);
                let s = self.selector(entry.selector);
                let ct = match entry.rule {
                    Some(Rule::Member) => member_token(&pt, &s),
                    Some(Rule::Element) => element_token(&pt, &s, o),
                    None => continue,
                };
                // A node a read names keeps that read's token, as the
                // database's member-rule-first test then finds it.
                let ct = match linked[r].x.get(&c) {
                    Some(x) if *x == self_tag(&iv, &member_token(&pt, &s)) => member_token(&pt, &s),
                    _ => {
                        let _ = linked[r].x.insert(c, self_tag(&iv, &ct));
                        ct
                    }
                };
                if entry.has_parent_tag {
                    let _ = linked[r].p.insert(c, parent_tag(&iv, &pt, o));
                }
                let _ = tokens.insert(c, ct);
            }
        }
        linked
    }

    fn row(&mut self, row: &RowLeakage, linked: &Linked) -> Value {
        let iv = self.iv(row);
        let tag = self
            .tags
            .entry(row.data_key)
            .or_insert_with(|| random_vec(self.rng, self.leakage.key_tag_len))
            .clone();
        let keyset: [u8; 16] = self.keysets.get(row.keyset, self.rng);
        let mut header = vec![1, u8::from(row.sealed_root), 0, 0, 0, 0];
        header.extend_from_slice(&keyset);
        header.extend_from_slice(&iv);
        header.extend_from_slice(&u16::try_from(tag.len()).expect("a short tag").to_le_bytes());
        header.extend_from_slice(&tag);

        let entries: Vec<Value> = row
            .entries
            .iter()
            .enumerate()
            .map(|(i, entry)| {
                let s = self.selector(entry.selector);
                let mut c = vec![CIPHERTEXT_FRAME];
                c.extend(random_vec(self.rng, entry.ciphertext_len - 1));
                let mut wire = json!({"s": b64(&s), "c": base85_simd::encode(&c)});
                if let Some(id) = entry.self_tag {
                    let x = match linked.x.get(&i) {
                        Some(x) => *x,
                        None => self.self_tags.get(id, self.rng),
                    };
                    wire["x"] = json!(b64(&x));
                }
                if entry.has_parent_tag {
                    let p: Tag8 = match linked.p.get(&i) {
                        Some(p) => *p,
                        None => random(self.rng),
                    };
                    wire["p"] = json!(b64(&p));
                }
                if let Some(op) = entry.ordering {
                    wire["op"] = json!(b64(&self.ordering(op.class, op.len)));
                }
                wire
            })
            .collect();
        let q = self.group(&row.projection);
        json!({"h": b64(&header), "sv": entries, "q": q})
    }

    fn query(&mut self, query: &QueryLeakage) -> (QueryKind, Value) {
        match query {
            QueryLeakage::Extract { selector } => {
                (QueryKind::Extract, json!(b64(&self.selector(*selector))))
            }
            QueryLeakage::Subtree { reads, budget } => {
                let tokens: Vec<String> = reads
                    .iter()
                    .map(|read| b64(&self.token(&read.token)))
                    .collect();
                (QueryKind::Subtree, json!({"t": tokens, "budget": budget}))
            }
            QueryLeakage::Contains { needle, alt } => {
                let mut wire = self.group(needle);
                if let Some(alt) = alt {
                    wire["alt"] = self.group(alt);
                }
                (QueryKind::Contains, wire)
            }
            QueryLeakage::Equals { needle } => (QueryKind::Equals, self.group(needle)),
            QueryLeakage::Order { selector, bound } => {
                let s = self.selector(*selector);
                let op = self.ordering(bound.class, bound.len);
                (QueryKind::Order, json!({"s": b64(&s), "op": b64(&op)}))
            }
        }
    }
}
