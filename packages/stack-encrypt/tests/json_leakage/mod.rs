//! An executable leakage profile for the JSON index, EQL v4's `json_tree`.
//!
//! `packages/eql/docs/reference/json-tree-leakage.md` says, in prose, what a
//! database holding a `json_tree` column learns from the stored rows and
//! from each query. This module turns that page into a checked claim. If the
//! real scheme reveals anything the claim leaves out, a test here fails and
//! names the observation that gave it away.
//!
//! It models the format of #1363: every entry `{s, c, x, p?, op?}` with a
//! self tag `x`; a member's token derived without an ordinal and an
//! element's with its index, so the client derives any node's token from
//! its path; and a subtree read, `json_tree_subtree(doc, tokens, budget)`,
//! that sends the tokens of exactly the nodes it names, wildcards expanded
//! on the client to a bound `N` with a probe per expanded array. It was
//! first written against the format before (one head token and plaintext
//! gates per read, member tokens carrying their ordinal, no self tag) and
//! ported; `docs/plans/2026-10-25-json-tree-leakage-before-and-after.md`
//! compares the two profiles clause by clause.
//!
//! # The pieces
//!
//! ```text
//!  documents, queries ──► profile::leak ──► Leakage ──► simulator::simulate ──► wire JSON ─┐
//!   (plaintext)              (L: no key)                 (+ seeded randomness)            │
//!                                                                                         ├─► observe ──► ObservedWorld ──► distinguishers
//!  documents, queries ──► real::world ─────────────────────────────────────────► wire JSON ─┘
//!                          (the crate, under the fake key source)
//! ```
//!
//! - [`profile`] is `L`, the claim: [`profile::l_store`] (what the stored
//!   rows reveal) and [`profile::l_query`] (what one query reveals), both
//!   functions of the plaintext alone. Every keyed value is an opaque integer
//!   that is equal exactly where the real values are equal. Each field of the
//!   leakage types is one clause, and its doc comment quotes the sentence of
//!   the page it encodes. The two take a shared [`profile::Ids`] beside the
//!   documents, so that a query's selector and a stored selector get the same
//!   name when the real bytes are equal.
//! - [`simulator`] builds a world in the wire form from a
//!   [`profile::Leakage`] and randomness, with no plaintext and no key:
//!   random bytes for every name, random ciphertexts of the stated length,
//!   ordering terms with CLLW's layout under a key of its own, over codes
//!   that have the stated order, lengths and shared prefixes and nothing
//!   else of the values, and the chain programmed
//!   with the real hash where the profile says a query's token links it:
//!   the self tag `x` of each node a token names, and below it every parent
//!   tag and self tag the token reaches.
//! - [`real`] seals the same documents and derives the same query terms
//!   through the crate's public API, and serializes them.
//! - [`observe`] parses either world's wire JSON into one
//!   [`observe::ObservedWorld`].
//! - [`distinguishers`] are pure functions of an observed world: what an
//!   observer holding the column and the query terms could compute. Each
//!   feature is exact (byte strings renamed to integers in order of first
//!   appearance), so a real and a simulated world are compared for equality,
//!   with no statistics. One feature needs a probability bound and carries it
//!   in its doc comment ([`distinguishers::member_ordinals_follow_key_order`]).
//! - [`mutants`] are profiles with one clause dropped or coarsened.
//! - [`corpus`] holds the handcrafted columns and a proptest generator of
//!   random ones over a shared key vocabulary.
//! - [`chain`] is the token chain's public hash functions (the parent tag,
//!   the self tag, the member and element rules, and the database's test of
//!   a hit against the two rules), the only part of the real scheme the
//!   harness evaluates itself.
//!
//! # The checks ([`calibration`])
//!
//! - **The positive control.** The simulator, run from the full profile, is
//!   told from the real scheme by no distinguisher, on the handcrafted
//!   columns and on 256 random ones. If this fails, the real scheme reveals
//!   something `L` does not state: that is a finding against the page (or
//!   against the code), and the failure names the distinguisher and prints
//!   both features.
//! - **The page as #1363 published it.** `L` carries one clause the page
//!   did not state when #1363 published it, marked **added to the page by
//!   #1362** in [`profile::Clauses`], and this branch adds the sentence.
//!   [`profile::Clauses::as_published_in_1363`] turns it off, and a test
//!   holds that the result is then told from the real scheme, by the
//!   distinguisher that names it and the three its absence breaks.
//! - **Two readings.** The page states the key order (UTF-8 byte order)
//!   and that strings order folded; a profile read the other way on either
//!   is told from the real scheme, so both sentences are load-bearing.
//! - **The calibration.** Each mutant profile drops one clause. The test
//!   expects some distinguisher to tell each mutant's world from the real
//!   one, and prints a table of which (run with `--no-capture`). A mutant
//!   nothing notices goes in its `UNNOTICED` list with the reason; there is
//!   none today. This is what shows the distinguishers can see what the
//!   clauses describe, so that the positive control passing means something.
//! - **The harness itself.** The chain functions agree with the crate's own
//!   walk (`JsonDocument::subtree`) for reads through members, positions,
//!   wildcards and `$`; the order-only attack in
//!   [`distinguishers::depth_recovery`] recovers every row's depth sequence
//!   on a column whose rows vary, which is the page's claim that the stored
//!   order reveals each row's shape; and on the real scheme a wildcard
//!   read's token list gives its bound and its probes away
//!   (`a_read_gives_away_its_bound_and_its_probes`). Two features no mutant
//!   can reach are shown to fire: `cross_kind_equalities` on a world whose
//!   token is a stored selector, and `token_derivability` on a read of a
//!   position past every row's array.
//!
//! # What the profile found
//!
//! Against the page as #1363 published it:
//!
//! 1. **A walk tells members from elements.** Nothing stored says whether a
//!    node is an object member or an array element (the design's decision
//!    2, "no kind bit"), but to derive a reached node's token the database
//!    tests its self tag against the member rule and then the element rule
//!    (`json_tree_hit_token`), so under any token it sends, it learns which
//!    each node is, and so whether each parent is an object or an array.
//!    Where selectors show it anyway (an array with two elements in some
//!    row) this adds nothing; for a node that is an only child in every
//!    row, it does. The page said a token's holder can "see how the nodes
//!    beneath it nest, link each one to its parent". This branch adds the
//!    sentence, and `the_hit_rule_separates_it_from_the_real_scheme` holds
//!    it: without it, `hit_rules` separates the worlds, and no world
//!    consistent with the tokens a client sends can hide the rule.
//!
//! Against the SQL's own comment, not the page:
//!
//! 2. **A probe is told from the other tokens.** `json_tree_subtree`'s
//!    comment said "the server cannot tell a probe from any other token".
//!    It cannot from the token's bytes, but the probe is the last token at
//!    its level, the count gives the bound away (65 tokens is one level at
//!    `N = 64` and nothing else), and a probe that finds something finds
//!    the element, whose selector differs from the leaf the path's other
//!    tokens find. `a_read_gives_away_its_bound_and_its_probes`. #1363
//!    corrected the comment, which now says the server "can pick it out".
//!
//! The three findings against the page as it stood before #1363 (an
//! ordering term's length, equal values at two ordered paths, UTF-8 byte
//! order of keys) are on the page now. Their clauses stay, each with a
//! mutant or a reading the calibration catches. The profile itself was
//! wrong in one place the old corpus could not show: it ordered strings by
//! their bytes, where the code (and the page) fold case and accents; the
//! corpus now holds folded names, and the reading test holds the sentence.
//!
//! The profile also left out, until review, a disclosure the page states:
//! the ordering terms' shared prefixes. A CLLW OPE term spends a byte per
//! plaintext bit, so two terms agree to within one up to the first bit their
//! values' encodings differ in, and the database reads that bit off the
//! stored terms exactly; for numbers it is their signs and binary exponents.
//! The profile had called it "not an exact function of the plaintexts"
//! (true of the byte prefix, which carries move, and not of the bit), and
//! its simulator drew terms with no prefix structure, so nothing could see
//! the omission. It is a clause now ([`profile::Leakage::ordering_prefixes`],
//! [`distinguishers::ordering_term_prefixes`], the mutant
//! `ordering_prefixes_hidden`), and the page says bits, not bytes.
//!
//! Where the page is vague and `L` is as precise as the code forces, the
//! clause says so: a member's ordinal under a token (its keyed rank), the
//! needle's `alt` ([`profile::QueryLeakage::Contains`]), and the fixed
//! parts of a ciphertext's length ([`profile::ciphertext_len`]).
//!
//! The two issues the profile was first built to check: the stored order
//! still reveals each row's shape (#1357; the order clause is load-bearing
//! and the depth attack works), and a subtree read no longer hands over
//! its top-level field (#1360): the mutant that sends the head's token as
//! the read before #1363 did (`ancestor_token_sent`) is told apart by
//! `ancestor_links`, `token_reach` and the token counts.
//!
//! # When the format changes
//!
//! `L` and the real-side adapter are expected to change with the format,
//! and with the leakage page; the distinguishers mostly should not (the
//! port to #1363 kept 26 of the 27 the profile had, renamed one and added
//! eight). To add or change a clause:
//!
//! 1. Change the page first, or at least decide what it will say.
//! 2. Change [`profile`]: a field on the leakage type, with the page's
//!    sentence quoted in its doc comment, computed from the plaintext.
//! 3. Make the [`simulator`] produce it from that field and randomness only.
//! 4. Teach [`observe`] the new wire field, and [`real`] any new API.
//! 5. Add a distinguisher if no existing one would see the clause, and a
//!    mutant that drops the clause, and check the calibration catches it.
//!
//! # Reading a failure
//!
//! - **Positive control fails.** The real scheme shows something the profile
//!   does not state, or states differently. The message names each
//!   distinguisher that separated the worlds, with the real and the
//!   simulated feature. Decide whether the page or the code is wrong. Never
//!   widen `L` silently to make it pass: a clause the page does not state
//!   goes in marked as such in [`profile::Clauses`], with a test like the
//!   one for the hit rule, so the gap stays visible until the page closes
//!   it.
//! - **Calibration fails for a mutant nothing noticed.** Either the clause
//!   is not load-bearing on the calibration columns (add a column that
//!   exercises it, as the wide-objects column does for member ranks and
//!   for a probe's reach), or no distinguisher can see it (write one). If
//!   neither is possible, list the mutant in `UNNOTICED` with the reason.
//!   Do not delete the clause.
//! - **Calibration fails for a listed mutant that is now noticed.** Remove it
//!   from the list: something got sharper.
//! - **Every mutant is caught and the positive control fails.** The
//!   calibration means nothing until the positive control passes: a profile
//!   the real scheme is already told from makes every mutant "caught".
//!   That is what happened when this module first ran against #1363's
//!   format.
//!
//! # A tension this module states and does not resolve
//!
//! PR #1358's read check (`JsonSubtreeKey::open`) refuses a walk's rows
//! unless each subtree's rows sit at consecutive positions `j` in `sv`, which
//! is what a subtree is in a depth-first stored order, and `j` is bound into
//! every ciphertext's AAD. #1363 keeps it (its decision 8: "each deeper row
//! must sit at the next consecutive `j` within its subtree"). That
//! consecutiveness is exactly the property #1357 wants gone: a stored order
//! independent of the shape (a keyed permutation of `sv`, say) would
//! scatter a subtree's rows. The check and "order independent of shape"
//! cannot both hold as written: one of them has to give, and which is the
//! owner's decision.
//!
//! # Out of reach
//!
//! - **The carries inside an ordering term.** A CLLW OPE term's bytes before
//!   the first bit two values differ in agree to within one, a carry from
//!   the right that depends on the key. Where the terms part is exact and
//!   is in the profile ([`profile::Leakage::ordering_prefixes`],
//!   [`distinguishers::ordering_term_prefixes`]); which shared bytes differ
//!   by one is not a function of the plaintexts, and no distinguisher reads
//!   it.
//! - **A near-tie between the two kinds' keys.** At a path ordered over
//!   numbers and strings both, the profile states where the column's key
//!   puts the strings' terms among the numbers' ([`profile::Placement`]):
//!   as one block, below, between the negative and non-negative numbers, or
//!   above. That holds because each kind's terms begin with that kind's
//!   key's constant byte (plus 128 for a first bit of 1, with a carry). For
//!   about one pair of keys in forty, the two kinds' front bytes tie to
//!   within a carry, and then a few pairs of a number and a string compare
//!   by their later, keyed bytes. No clause states that case; the simulator
//!   refuses such keys, and the test key is not one. Since the real key
//!   picked one placement and the simulator cannot know which, the
//!   calibration simulates each and counts two worlds as told apart only
//!   when none agrees, which is also why one world cannot tell "the key
//!   chose numbers first" from jsonb's fixed order: the mutant that states
//!   jsonb's (`mixed_kinds_jsonb_order`) is caught because the test key put
//!   the strings below the numbers.
//! - **The keyed member rank as a permutation.** Under a token, a member's
//!   ordinal is a keyed rank. Its relation to the stored (key) order is a
//!   random permutation, decidable exactly only where enough wide objects sit
//!   under the tokens sent; elsewhere the feature reports nothing.
//! - **The primitives.** Ciphertexts beyond their length, selectors, value
//!   selectors, head tokens and unlinked self tags beyond their equality
//!   patterns: the profile assumes AES-GCM, the PRFs and the hash do their
//!   job, and the simulator draws random bytes for them.
//! - **The database's side channels.** Timing, which rows a query touches
//!   beyond its result, and the `i` and `v` envelope fields the SQL adds.
//!   The budget fallback is modelled (`distinguishers::subtree_results`);
//!   the database computes it from the walk it already sees. One column at a
//!   time; no cross-column linkage is modelled.
//! - **`json_tree_children` and `json_tree_child_count`.** Each takes one
//!   token, the token a read of the same path sends, and probes one level
//!   below it, which the read's walk already does; they are not modelled as
//!   queries of their own.
//! - **The key service.** The fake key source mints 32-byte tags; ZeroKMS's
//!   tag length is its own, and a column constant either way.
//!
//! # Determinism
//!
//! Every simulation and every mutant draws from one seeded generator, and
//! the random columns come from a seeded proptest runner. The real side
//! draws data keys and nonces from the operating system; those reach a
//! feature only through equality patterns, which change only on a collision
//! of random bytes, below `n² / 2^64` for `n` eight-byte tags in a column
//! (about `10^-13` here). The fake key source's index key is fixed, so the
//! real member ranks are too.
//!
//! The profile sorts members itself rather than trusting `serde_json`'s
//! iteration order, so a build that unified serde_json's `preserve_order`
//! feature on (which would store the application's field order, #1357) fails
//! the positive control on the handcrafted rows whose keys are written out
//! of order.

pub mod calibration;
pub mod chain;
pub mod corpus;
pub mod distinguishers;
pub mod mutants;
pub mod observe;
pub mod profile;
pub mod real;
pub mod simulator;
