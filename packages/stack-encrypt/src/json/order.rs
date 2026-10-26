//! The stored order: where a document's entries sit in `sv`, and the order
//! of its containment projection `q`.
//!
//! A document's entries are stored in a uniformly random order, drawn
//! afresh for each document when it is sealed and then thrown away, with
//! the root at slot `0`, where the sealed-root fallback finds it. Every
//! document has a root, so its slot says nothing. The pairs of each group of
//! `q`, and the element groups of each list, are shuffled the same way.
//!
//! Nothing needs the permutation afterwards. The server finds entries by
//! their self and parent tags and reads `q` as sets (`jsonb @>`), and the
//! client places a read's rows by the chain and verifies them by the cascade
//! ([`cascade`](super::cascade)); the AAD binds each entry's slot, so an
//! entry cannot be moved between slots, but nothing reads a slot as a
//! position in the document. So the permutation is not derived from
//! anything, keyed or not: whatever it were derived from would have to be
//! kept from the database, and nothing is gained by being able to derive
//! it.
//!
//! What the depth-first order used to show and this one does not: each
//! row's tree (the parent of every node), the size of every subtree, and
//! which of two sibling key names sorts first. What any order leaves
//! visible is listed on the leakage page
//! (`packages/eql/docs/reference/json-tree-leakage.md`).
//!
//! The generator is `vitaminc`'s [`SafeRand`] (ChaCha20, seeded from the
//! operating system) and each draw is [`SafeRand::next_below`] (Lemire's
//! reduction: one 64-bit draw per call, bias at most `n / 2⁶⁴`, negligible
//! for any document). Which generator draws the permutation is not part of
//! the format, since nothing stored depends on it, and it can be replaced
//! without a version change.

use std::sync::Mutex;

use vitaminc::random::{Rng, SafeRand};
use vitaminc_protected::{Controlled, Protected};

use crate::Error;

/// Where a cipher draws the stored orders of the documents it seals from.
pub(crate) enum OrderSource {
    /// A fresh generator per document, seeded from the operating system:
    /// the only source outside tests.
    Entropy,
    /// A generator per document seeded from one stream that starts at a
    /// fixed seed, so a run that seals the same documents in the same order
    /// stores them in the same orders. Test support only
    /// ([`StackCipherBuilder::json_order_seed`](crate::StackCipherBuilder)).
    Controlled(Box<Mutex<SafeRand>>),
}

impl OrderSource {
    /// The source a fixed `seed` starts.
    pub(crate) fn controlled(seed: Protected<[u8; 32]>) -> Self {
        Self::Controlled(Box::new(Mutex::new(SafeRand::from_controlled_seed(seed))))
    }

    /// The generator one document's order is drawn from.
    pub(crate) fn document(&self) -> Result<SafeRand, Error> {
        match self {
            Self::Entropy => SafeRand::from_entropy()
                .map_err(|_| Error::Other("no entropy for a JSON document's stored order".into())),
            Self::Controlled(stream) => {
                // The stream holds no invariant a panic could break.
                let mut stream = stream
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let seed = Protected::generate(|| {
                    let mut seed = [0u8; 32];
                    stream.fill_bytes(&mut seed);
                    seed
                });
                Ok(SafeRand::from_controlled_seed(seed))
            }
        }
    }
}

/// A uniform shuffle of `items` (Fisher–Yates), each swap index drawn with
/// [`SafeRand::next_below`].
pub(crate) fn shuffle<T>(items: &mut [T], rng: &mut SafeRand) {
    for i in (1..items.len()).rev() {
        // `items` is a document's entries, or a group of its projection:
        // never more than `u32::MAX` of them, since an ordinal past
        // PostgreSQL's integer is refused when the document is walked.
        let bound = u32::try_from(i + 1).unwrap_or(u32::MAX);
        let j = rng.next_below(bound) as usize;
        items.swap(i, j);
    }
}

/// The slot each of `n` nodes is stored at, by its index in the walk: the
/// root (index `0`) at slot `0`, and the other nodes at a uniformly random
/// permutation of the slots `1..n`.
pub(crate) fn slots(n: usize, rng: &mut SafeRand) -> Vec<usize> {
    let mut slots: Vec<usize> = (0..n).collect();
    if let Some(rest) = slots.get_mut(1..) {
        shuffle(rest, rng);
    }
    slots
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seeded(byte: u8) -> SafeRand {
        SafeRand::from_controlled_seed(Protected::new([byte; 32]))
    }

    #[test]
    fn the_slots_are_a_permutation_with_the_root_first() {
        for n in [0, 1, 2, 3, 17, 200] {
            let slots = slots(n, &mut seeded(1));
            let mut sorted = slots.clone();
            sorted.sort_unstable();
            assert_eq!(sorted, (0..n).collect::<Vec<_>>(), "{n}: a permutation");
            if n > 0 {
                assert_eq!(slots[0], 0, "{n}: the root at slot 0");
            }
        }
        assert_ne!(
            slots(50, &mut seeded(1)),
            (0..50).collect::<Vec<_>>(),
            "not the identity (with overwhelming probability)"
        );
    }

    /// Every arrangement of three items comes up, each about a sixth of the
    /// time: the shuffle reaches every permutation and favours none.
    #[test]
    fn the_shuffle_is_uniform_over_small_permutations() {
        let mut rng = seeded(2);
        let mut counts = std::collections::BTreeMap::new();
        let runs = 60_000;
        for _ in 0..runs {
            let mut items = [0, 1, 2];
            shuffle(&mut items, &mut rng);
            *counts.entry(items).or_insert(0usize) += 1;
        }
        assert_eq!(counts.len(), 6, "every permutation of three");
        for (perm, count) in counts {
            assert!(
                (9_000..11_000).contains(&count),
                "{perm:?} came up {count} times in {runs}"
            );
        }
    }

    #[test]
    fn a_controlled_source_repeats_and_entropy_does_not() {
        let order = |source: &OrderSource| {
            let mut a = source.document().unwrap();
            let mut b = source.document().unwrap();
            (slots(30, &mut a), slots(30, &mut b))
        };
        let one = order(&OrderSource::controlled(Protected::new([3; 32])));
        let two = order(&OrderSource::controlled(Protected::new([3; 32])));
        assert_eq!(one, two, "the same seed, the same orders");
        assert_ne!(one.0, one.1, "each document draws its own order");
        let other = order(&OrderSource::controlled(Protected::new([4; 32])));
        assert_ne!(one, other, "another seed, other orders");
        let fresh = order(&OrderSource::Entropy);
        assert_ne!(fresh.0, fresh.1, "entropy draws a new order per document");
    }
}
