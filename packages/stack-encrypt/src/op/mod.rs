//! Operators: what a query asks of the server, as a type.
//!
//! A query names an *operator* ([`Eq`](struct@Eq), [`Matches`](struct@Matches)), and the plan it
//! runs on finds the index that answers it. The operator is a unit type
//! passed by value, as an index is (`.via(Ore)`):
//!
//! ```
//! # async fn example() -> Result<(), stack_encrypt::Error> {
//! use stack_encrypt::kms::FakeDataKeySource;
//! use stack_encrypt::{op, Equality, Match, Plan, StackCipher};
//!
//! let cipher = StackCipher::builder().kms(FakeDataKeySource::new()).init().await?;
//! let email_plan = Plan::context("users/email")
//!     .with::<String, _>((Equality, Match))
//!     .build()?;
//!
//! let exact = cipher.query(op::Eq, "bob@example.com").on(&email_plan).await?;
//! let search = cipher.query(op::Matches, "bob").on(&email_plan).await?;
//! # let _ = (exact, search);
//! # Ok(())
//! # }
//! # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(example()).unwrap();
//! ```
//!
//! Three traits connect an operator to an index, and ADR-0009 records why:
//!
//! - [`Supports<Op, S>`] is on an index, for each operator it can answer
//!   over plaintexts `S`, and names the [`QueryTerm`] it sends. That term is
//!   not the stored term: an equality index sends the same HMAC it stores,
//!   but a match index sends a filter over the query's value
//!   ([`MatchQuery`]), where it stores a filter over the stored value
//!   ([`MatchTerms`]).
//! - [`Answers<Op, S>`] is on a target type, a domain type such as an EQL
//!   type, and names the index that answers `Op` for it. It is written by
//!   hand per type, because the choice decides what the query term reveals.
//! - [`DefaultIndex<S>`] is on an operator, and names the index a plan that
//!   declares its indexes, rather than a target type, answers it with.
//!
//! What the types can see is checked at compile time: a match query on an
//! integer, an operator a target type does not answer, and, on a one-value
//! plan, an index the plan does not hold or a case-sensitive match against
//! a case-folding index. A field of a fields plan is data, so there an
//! index the field does not declare, or declares with other options, is
//! refused when the query is awaited, as with
//! [`query_index`](crate::StackCipher::query_index), before any key is
//! requested.
//! So is a match configuration whose [`MatchCase`] disagrees with its
//! options.
//!
//! The module is meant to be used by path (`op::Eq`): an imported `Eq`
//! would shadow the prelude's `Eq` trait.
//!
//! [`MatchQuery`]: crate::sem::MatchQuery
//! [`MatchTerms`]: crate::sem::MatchTerms
use std::fmt;
use std::marker::PhantomData;

use stack_kms::MaybeSend;

pub(crate) mod stats;
pub use stats::{Limit, Stats, DEFAULT_CONFIDENCE, MAX_ROWS};

use crate::sem::{DefaultMatch, EqualityTerm, MatchConfig, MatchQuery, MatchTerms, QueryTokens};
use crate::target::{Equality, Index, Match};
use crate::PlanError;

/// A query operator: a unit type naming what a query asks of the server.
///
/// The trait is open, as [`Index`] is: an operator defined in another crate
/// is answered by the indexes that implement [`Supports`] for it.
pub trait Operator: Copy + 'static {}

/// Equality: rows whose value equals the query's.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Eq;

impl Operator for Eq {}

/// Text search: rows whose text contains the query's tokens, under the
/// match index's tokenizer. Not containment: a Bloom match is order- and
/// multiplicity-insensitive.
///
/// `C` is the case the query is asked in, [`CaseInsensitive`] unless named
/// otherwise. A match index answers only the case its configuration fixes
/// ([`MatchCase`]), so asking a case-folding index for a case-sensitive
/// match is a compile error rather than a query that quietly folds case.
///
/// The value [`Matches`](constant@Matches) is the case-insensitive operator,
/// as `PhantomData` is a value of its type; [`case_sensitive`](Matches::case_sensitive)
/// is the other.
pub struct Matches<C = CaseInsensitive> {
    case: PhantomData<fn() -> C>,
}

/// The case-insensitive text search operator, as a value:
/// `cipher.query(op::Matches, "ali")`.
#[allow(non_upper_case_globals)]
pub const Matches: Matches = Matches::new();

impl<C> Matches<C> {
    /// The operator in the case `C`: `Matches::<CaseSensitive>::new()`.
    pub const fn new() -> Self {
        Self { case: PhantomData }
    }
}

impl Matches {
    /// The case-sensitive text search operator:
    /// `cipher.query(op::Matches.case_sensitive(), "Ali")`. Only a match
    /// index whose configuration does not fold case answers it.
    pub const fn case_sensitive(self) -> Matches<CaseSensitive> {
        Matches::new()
    }
}

// By hand, so `C` (a marker type) need not implement them.
impl<C> Clone for Matches<C> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<C> Copy for Matches<C> {}
impl<C> Default for Matches<C> {
    fn default() -> Self {
        Self::new()
    }
}
impl<C> PartialEq for Matches<C> {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}
impl<C> std::cmp::Eq for Matches<C> {}
impl<C> std::hash::Hash for Matches<C> {
    fn hash<H: std::hash::Hasher>(&self, _: &mut H) {}
}
impl<C: Case> fmt::Debug for Matches<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Matches<{}>", C::NAME)
    }
}

impl<C: Case> Operator for Matches<C> {}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::CaseInsensitive {}
    impl Sealed for super::CaseSensitive {}
}

/// The case a text operator is asked in: [`CaseInsensitive`] or
/// [`CaseSensitive`]. Sealed: there are exactly two.
pub trait Case: sealed::Sealed + 'static {
    /// Whether text is lower-cased before it is tokenised.
    const FOLDS: bool;
    /// The case's name, for `Debug`.
    const NAME: &'static str;
}

/// Case-insensitive: text is lower-cased before it is tokenised.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct CaseInsensitive;

/// Case-sensitive: text is tokenised as written.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct CaseSensitive;

impl Case for CaseInsensitive {
    const FOLDS: bool = true;
    const NAME: &'static str = "CaseInsensitive";
}
impl Case for CaseSensitive {
    const FOLDS: bool = false;
    const NAME: &'static str = "CaseSensitive";
}

/// The case a match configuration fixes, as a type, so the operators its
/// index answers are known at compile time.
///
/// `Case::FOLDS` must equal the configuration's
/// [`MatchOptions::downcase`](crate::sem::MatchOptions::downcase): the type
/// cannot see the options, so a query through a configuration whose two
/// disagree is refused when it is awaited, with
/// [`PlanError::MatchCase`]. A configuration
/// that does not implement this can still store match terms and query them
/// by index; it cannot be queried by [`Matches`](struct@Matches).
pub trait MatchCase: MatchConfig {
    /// The case the configuration's index answers.
    type Case: Case;
}

impl MatchCase for DefaultMatch {
    type Case = CaseInsensitive;
}

/// A value a query sends to the server to compare against stored terms.
///
/// This trait says only that a value is a query term. How far the server's
/// answer can be trusted is said by the traits that refine it: a term that
/// can return false positives says how a row is checked (ADR-0009,
/// decision 4), and one that refines nothing is exact.
pub trait QueryTerm {}

impl QueryTerm for EqualityTerm {}
impl<O> QueryTerm for MatchQuery<O> {}

/// A query term whose answer can hold **false positives and no false
/// negatives**: a row the server returns may not match, and a row that
/// matches is always returned.
///
/// [`verify`](Self::verify) is the operator's own meaning, run on a
/// decrypted value: it decides whether a row the server returned is a real
/// match. The library never runs a query, so it cannot drop the false
/// positives itself; a caller filters the decrypted rows with `verify`.
///
/// An exact term does not implement this, so `verify` on one is a compile
/// error rather than a method that is always `true`.
pub trait Probabilistic: QueryTerm {
    /// The decrypted value `verify` reads: the plaintext the index was
    /// declared over, which is not always the value the user wrote.
    type Plaintext: ?Sized;

    /// Whether `value`, a row's decrypted value, really matches the query.
    ///
    /// Infallible: it runs on a value already decrypted and already the type
    /// the index was declared over, so every outcome other than a match is
    /// `false`, never an error.
    fn verify(&self, value: &Self::Plaintext) -> bool;

    /// How many candidate rows to fetch so that, at the confidence `stats`
    /// names, `want` of them [`verify`](Self::verify), when the table holds
    /// that many matches.
    ///
    /// A probabilistic bound, not a guarantee: at 99% confidence one query
    /// in a hundred draws more false positives than it allows for, and the
    /// model assumes a non-matching row shares no token with the query,
    /// which natural text does not honour, so the confidence is nominal.
    /// The candidate count says which case a fetch is in. If the server
    /// returned fewer rows than the limit, the predicate is exhausted, and
    /// fewer than `want` verified rows means fewer than `want` matches. If
    /// it returned exactly the limit and fewer than `want` verified, the
    /// result is a page: carry on from its last row with a cursor.
    fn target_limit(&self, want: u64, stats: &Stats) -> Limit;
}

/// The query terms that may answer the operator `Op`: what
/// [`Supports::Query`] must be.
///
/// Most operators take any [`QueryTerm`]. One whose answer is inherently
/// approximate requires more: a term that answers [`Matches`](struct@Matches) must be
/// [`Probabilistic`], so none of this crate's indexes can claim a text
/// match without saying how its answer is checked.
///
/// The rule binds this crate's terms, through the blanket impls below. A
/// term defined in another crate can implement this for an operator by
/// hand, and coherence lets it; the bound is a guide there, not a proof. An
/// operator defined in another crate states its requirement the same way,
/// one term type at a time.
#[diagnostic::on_unimplemented(
    message = "`{Self}` cannot answer `{Op}`",
    label = "this query term does not meet the operator's requirement",
    note = "a term that answers `op::Matches` must implement `op::Probabilistic`"
)]
pub trait TermFor<Op: Operator>: QueryTerm {}

impl<T: QueryTerm> TermFor<Eq> for T {}
impl<C: Case, T: Probabilistic> TermFor<Matches<C>> for T {}

/// An index that answers the operator `Op` over plaintexts `S`, and the
/// query term it sends for it.
///
/// [`Index::Term`] is what the index derives; [`query`](Self::query) makes
/// the query term from it and from the query's [`Verifier`](Self::Verifier).
/// For an equality index the two are the same HMAC and there is nothing to
/// verify. For a match index they are not: the query is a filter over the
/// query's value, which matches some rows that do not hold the value, so
/// the query keeps that value's tokens to
/// [`verify`](Probabilistic::verify) each decrypted row.
#[diagnostic::on_unimplemented(
    message = "`{Self}` does not answer `{Op}` over `{S}`",
    label = "this index cannot answer the operator",
    note = "an equality index answers `op::Eq`; a match index answers `op::Matches` over text, in the case its configuration fixes"
)]
pub trait Supports<Op: Operator, S>: Index<S> {
    /// What this index sends for `Op`.
    type Query: TermFor<Op>;
    /// What the query term keeps of the query's plaintext so that it can
    /// later check a decrypted row, taken before the plaintext is consumed.
    ///
    /// An exact term checks nothing, so its verifier is `()`. A match
    /// query's is [`crate::sem::QueryTokens`]: `Supports<Matches,
    /// String> for Match` cuts `"alice"` into `ali`, `lic`, `ice`, and
    /// [`MatchQuery::verify`](Probabilistic::verify) passes a row only if
    /// its own text holds all three. The filter cannot give the tokens back,
    /// so without the verifier a Bloom false positive would reach the caller.
    type Verifier: MaybeSend + 'static;
    /// Why this index cannot answer `Op` as configured, if it cannot: a
    /// match index whose [`MatchCase`] disagrees with its options.
    fn check(&self) -> Result<(), PlanError>;
    /// The verifier of the query's plaintext `value`.
    fn verifier(&self, value: &S) -> Self::Verifier;
    /// The query term, from the verifier and the term the index derived for
    /// the query's value. Only a query chain calls this: `QueryToken`
    /// cannot be made outside this crate, so no caller can pair one query's tokens
    /// with another value's filter, or pass a stored term off as a query.
    fn query(verifier: Self::Verifier, term: Self::Term, token: QueryToken) -> Self::Query;
}

/// Proof that [`Supports::query`] is called by a query chain. Only this
/// crate can make one, so an index in another crate can implement
/// [`Supports`] but no caller can turn a term into a query term by hand.
#[derive(Debug)]
pub struct QueryToken(());

impl QueryToken {
    pub(crate) fn new() -> Self {
        Self(())
    }
}

impl<S: vitaminc_prf::PrfValue> Supports<Eq, S> for Equality {
    type Query = EqualityTerm;
    type Verifier = ();
    fn check(&self) -> Result<(), PlanError> {
        Ok(())
    }
    fn verifier(&self, _: &S) {}
    fn query((): (), term: EqualityTerm, _: QueryToken) -> EqualityTerm {
        term
    }
}

impl<S, O> Supports<Matches<O::Case>, S> for Match<O>
where
    S: AsRef<str>,
    O: MatchCase,
{
    type Query = MatchQuery<O>;
    type Verifier = QueryTokens;
    fn check(&self) -> Result<(), PlanError> {
        let folds = O::options().downcase;
        if folds == O::Case::FOLDS {
            Ok(())
        } else {
            Err(PlanError::MatchCase {
                declared: O::Case::NAME,
                folds,
            })
        }
    }
    fn verifier(&self, value: &S) -> QueryTokens {
        QueryTokens::of::<O>(value.as_ref())
    }
    fn query(tokens: QueryTokens, term: MatchTerms<O>, _: QueryToken) -> MatchQuery<O> {
        MatchQuery::new(term, tokens)
    }
}

/// A target type that answers the operator `Op` over plaintexts `S`, and
/// the index it answers it with.
///
/// Written by hand per type: a type with two indexes that both answer an
/// operator chooses the cheaper or the more private, as the indexes in play
/// dictate, and that choice decides what the query term reveals. A type
/// that does not answer an operator has no impl, and the query does not
/// compile.
#[diagnostic::on_unimplemented(
    message = "`{Self}` does not answer `{Op}` over `{S}`",
    label = "this target type does not answer the operator",
    note = "a target answers the operators its type implements `Answers` for; `.via(index)` names an index the target declares"
)]
pub trait Answers<Op: Operator, S> {
    /// The index that answers `Op` for this type. An index is a unit type,
    /// so its `Default` is the index.
    type Via: Supports<Op, S> + Default;
}

impl<S: vitaminc_prf::PrfValue> Answers<Eq, S> for EqualityTerm {
    type Via = Equality;
}

impl<S, O> Answers<Matches<O::Case>, S> for MatchTerms<O>
where
    S: AsRef<str>,
    O: MatchCase,
{
    type Via = Match<O>;
}

/// A ciphertext with one term beside it, the shape of a `plaintext = ..`
/// record without the struct, answers what its term answers.
impl<Op: Operator, S, T: Answers<Op, S>> Answers<Op, S> for (crate::StackCipherText, T) {
    type Via = T::Via;
}

/// A ciphertext with one term, as [`indexed`](crate::target::indexed)
/// produces it, answers what its term answers. One with several terms
/// names the index with `.via(index)`.
impl<Op: Operator, S, T: Answers<Op, S>> Answers<Op, S> for crate::target::Encrypted<T> {
    type Via = T::Via;
}

/// The index a plan that declares its indexes answers an operator with:
/// a field of a fields plan, or a one-value plan built `with` indexes.
///
/// A plan that declares a different index for the operator, such as a
/// match index with its own configuration, names it with `.via(index)`.
/// So does a typed field of a fields plan (`encrypt_into::<T, _>(name)`):
/// the field's type is not known where the query is written, so its
/// [`Answers`] impl is not consulted, and a field whose type answers
/// through another index needs `via`.
#[diagnostic::on_unimplemented(
    message = "`{Self}` has no default index over `{S}`",
    label = "no default index answers this operator here",
    note = "`op::Eq` defaults to `Equality`; `op::Matches` defaults to `Match` with the default configuration, which is case-insensitive and over text only; name another index with `.via(index)`"
)]
pub trait DefaultIndex<S>: Operator {
    /// The index. An index is a unit type, so its `Default` is the index.
    type Via: Supports<Self, S> + Default;
}

impl<S: vitaminc_prf::PrfValue> DefaultIndex<S> for Eq {
    type Via = Equality;
}

impl<S: AsRef<str>> DefaultIndex<S> for Matches<<DefaultMatch as MatchCase>::Case> {
    type Via = Match;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_match_configuration_folds_case_as_its_type_says() {
        assert_eq!(
            <DefaultMatch as MatchCase>::Case::FOLDS,
            DefaultMatch::options().downcase
        );
    }

    #[test]
    fn an_operator_is_equal_to_itself() {
        assert_eq!(Matches::<CaseInsensitive>::new(), Matches);
        assert_eq!(Eq, Eq);
    }

    #[test]
    fn an_operator_debugs_with_its_case() {
        assert_eq!(
            format!("{:?}", Matches.case_sensitive()),
            "Matches<CaseSensitive>"
        );
        assert_eq!(format!("{:?}", Eq), "Eq");
    }
}
