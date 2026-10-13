//! Operators: what a query asks of the server, as a type.
//!
//! A query names an *operator* ([`Eq`](struct@Eq), [`Matches`]), and the plan it runs
//! through finds the index that answers it. The operator is a unit type
//! passed by value, as an index is (`.index(Ore)`):
//!
//! ```
//! # async fn example() -> Result<(), stack_encrypt::Error> {
//! use stack_encrypt::kms::FakeDataKeySource;
//! use stack_encrypt::{op, Equality, Match, Plan, StackCipher};
//!
//! let cipher = StackCipher::builder().kms(FakeDataKeySource::new()).init().await?;
//! let email_plan = Plan::context("users/email")
//!     .with::<String, _>((Equality, Match::default()))
//!     .build()?;
//!
//! let exact = cipher.query("bob@example.com").using(&email_plan).op(op::Eq).await?;
//! let search = cipher.query("bob").using(&email_plan).op(op::Matches::new()).await?;
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
//!   but a match index sends a filter over the needle ([`MatchQuery`]),
//!   where it stores a filter over the whole value ([`MatchTerms`]).
//! - [`Answers<Op, S>`] is on a target type, a domain type such as an EQL
//!   type, and names the index that answers `Op` for it. It is written by
//!   hand per type, because the choice decides what the query term reveals.
//! - [`DefaultIndex<S>`] is on an operator, and names the index a plan that
//!   declares its indexes, rather than a target type, answers it with.
//!
//! An operator a plan cannot answer is a compile error: a match query on an
//! integer, a case-sensitive match against a case-folding index, or an
//! operator a target type does not answer. An index the plan does not
//! declare is refused when the query is awaited, as with
//! [`index`](crate::plan::QueryUsing::index), before any key is requested.
//!
//! The module is meant to be used by path (`op::Eq`): an imported `Eq`
//! would shadow the prelude's `Eq` trait.
//!
//! [`MatchQuery`]: crate::sem::MatchQuery
//! [`MatchTerms`]: crate::sem::MatchTerms
use std::fmt;
use std::marker::PhantomData;

use crate::sem::{DefaultMatch, EqualityTerm, MatchConfig, MatchQuery, MatchTerms};
use crate::target::{Equality, Index, Match};

/// A query operator: a unit type naming what a query asks of the server.
///
/// The trait is open, as [`Index`] is: an operator defined in another crate
/// is answered by the indexes that implement [`Supports`] for it.
pub trait Operator: Copy + 'static {
    /// The operator's name, as a binding or an error message spells it.
    const NAME: &'static str;
}

/// Equality: rows whose value equals the query's.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Eq;

impl Operator for Eq {
    const NAME: &'static str = "eq";
}

/// Text search: rows whose text contains the needle's tokens, under the
/// match index's tokenizer. Not containment: a Bloom match is order- and
/// multiplicity-insensitive.
///
/// `C` is the case the query is asked in, [`Insensitive`] unless named
/// otherwise. A match index answers only the case its configuration fixes
/// ([`MatchCase`]), so asking a case-folding index for a case-sensitive
/// match is a compile error rather than a query that quietly folds case.
pub struct Matches<C = Insensitive>(PhantomData<fn() -> C>);

impl<C> Matches<C> {
    /// The operator. `Matches::new()` takes its case from the index it is
    /// asked of; `Matches::<Sensitive>::new()` names it.
    pub const fn new() -> Self {
        Self(PhantomData)
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
impl<C: Case> fmt::Debug for Matches<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Matches<{}>", C::NAME)
    }
}

impl<C: Case> Operator for Matches<C> {
    const NAME: &'static str = "matches";
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Insensitive {}
    impl Sealed for super::Sensitive {}
}

/// The case a text operator is asked in: [`Insensitive`] or [`Sensitive`].
/// Sealed: there are exactly two.
pub trait Case: sealed::Sealed + 'static {
    /// Whether text is lower-cased before it is tokenised.
    const FOLDS: bool;
    /// The case's name, for `Debug`.
    const NAME: &'static str;
}

/// Case-insensitive: text is lower-cased before it is tokenised.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Insensitive;

/// Case-sensitive: text is tokenised as written.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Sensitive;

impl Case for Insensitive {
    const FOLDS: bool = true;
    const NAME: &'static str = "Insensitive";
}
impl Case for Sensitive {
    const FOLDS: bool = false;
    const NAME: &'static str = "Sensitive";
}

/// The case a match configuration fixes, as a type, so the operators its
/// index answers are known at compile time.
///
/// `Case::FOLDS` must equal the configuration's
/// [`MatchOptions::downcase`](crate::sem::MatchOptions::downcase). A
/// configuration that does not implement this can still store and query
/// match terms; it cannot be queried by [`Matches`].
pub trait MatchCase: MatchConfig {
    /// The case the configuration's index answers.
    type Case: Case;
}

impl MatchCase for DefaultMatch {
    type Case = Insensitive;
}

/// A value a query sends to the server to compare against stored terms.
///
/// A term that implements this and nothing more is *exact*: the server's
/// answer is the answer.
pub trait QueryTerm {}

impl QueryTerm for EqualityTerm {}
impl<O> QueryTerm for MatchQuery<O> {}

/// An index that answers the operator `Op` over plaintexts `S`, and the
/// query term it sends for it.
///
/// [`Index::Term`] is what the index derives; [`query`](Self::query) makes
/// the query term from it. For an equality index the two are the same
/// HMAC. For a match index they are not: the query is a filter over the
/// needle, and its type says so.
#[diagnostic::on_unimplemented(
    message = "`{Self}` does not answer `{Op}` over `{S}`",
    label = "this index cannot answer the operator",
    note = "an equality index answers `op::Eq`; a match index answers `op::Matches` over text, in the case its configuration fixes"
)]
pub trait Supports<Op: Operator, S>: Index<S> {
    /// What this index sends for `Op`.
    type Query: QueryTerm;
    /// The query term, from the term the index derived for the query's
    /// value.
    fn query(term: Self::Term) -> Self::Query;
}

impl<S: vitaminc_prf::PrfValue> Supports<Eq, S> for Equality {
    type Query = EqualityTerm;
    fn query(term: EqualityTerm) -> EqualityTerm {
        term
    }
}

impl<S, O> Supports<Matches<O::Case>, S> for Match<O>
where
    S: AsRef<str>,
    O: MatchCase,
{
    type Query = MatchQuery<O>;
    fn query(term: MatchTerms<O>) -> MatchQuery<O> {
        MatchQuery::from_terms(term)
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
    note = "a target answers the operators its type implements `Answers` for; `.op_via(op, index)` names an index the target declares"
)]
pub trait Answers<Op: Operator, S> {
    /// The index that answers `Op` for this type.
    type Via: Supports<Op, S>;
    /// That index, as a value.
    fn via() -> Self::Via;
}

impl<S: vitaminc_prf::PrfValue> Answers<Eq, S> for EqualityTerm {
    type Via = Equality;
    fn via() -> Equality {
        Equality
    }
}

impl<S, O> Answers<Matches<O::Case>, S> for MatchTerms<O>
where
    S: AsRef<str>,
    O: MatchCase,
{
    type Via = Match<O>;
    fn via() -> Match<O> {
        Match::new()
    }
}

/// A ciphertext with one term beside it, the shape of a `plaintext = ..`
/// record without the struct, answers what its term answers.
impl<Op: Operator, S, T: Answers<Op, S>> Answers<Op, S> for (crate::StackCipherText, T) {
    type Via = T::Via;
    fn via() -> T::Via {
        T::via()
    }
}

/// A ciphertext with one term, as [`indexed`](crate::target::indexed)
/// produces it, answers what its term answers. One with several terms
/// names the index with `.op_via(op, index)`.
impl<Op: Operator, S, T: Answers<Op, S>> Answers<Op, S> for crate::target::Encrypted<T> {
    type Via = T::Via;
    fn via() -> T::Via {
        T::via()
    }
}

/// The index a plan that declares its indexes answers an operator with:
/// a field of a fields plan, or a one-value plan built `with` indexes.
///
/// A plan that declares a different index for the operator, such as a
/// match index with its own configuration, names it with
/// `.op_via(op, index)`.
#[diagnostic::on_unimplemented(
    message = "`{Self}` has no default index over `{S}`",
    label = "no default index answers this operator here",
    note = "`op::Eq` defaults to `Equality`; `op::Matches` defaults to `Match` with the default configuration, which is case-insensitive and over text only; name another index with `.op_via(op, index)`"
)]
pub trait DefaultIndex<S>: Operator {
    /// The index.
    type Via: Supports<Self, S>;
    /// That index, as a value.
    fn via() -> Self::Via;
}

impl<S: vitaminc_prf::PrfValue> DefaultIndex<S> for Eq {
    type Via = Equality;
    fn via() -> Equality {
        Equality
    }
}

impl<S: AsRef<str>> DefaultIndex<S> for Matches<<DefaultMatch as MatchCase>::Case> {
    type Via = Match;
    fn via() -> Match {
        Match::default()
    }
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
        assert_eq!(Matches::<Insensitive>::new(), Matches::default());
        assert_eq!(Eq, Eq);
    }

    #[test]
    fn an_operator_debugs_with_its_case() {
        assert_eq!(
            format!("{:?}", Matches::<Sensitive>::new()),
            "Matches<Sensitive>"
        );
        assert_eq!(format!("{:?}", Eq), "Eq");
    }
}
