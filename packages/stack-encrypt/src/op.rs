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
//! What the types can see is checked at compile time: a match query on an
//! integer, an operator a target type does not answer, and, on a one-value
//! plan, an index the plan does not hold or a case-sensitive match against
//! a case-folding index. A field of a fields plan is data, so there an
//! index the field does not declare, or declares with other options, is
//! refused when the query is awaited, as with
//! [`index`](crate::plan::QueryUsing::index), before any key is requested.
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

use crate::sem::{DefaultMatch, EqualityTerm, MatchConfig, MatchQuery, MatchTerms};
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
/// [`MatchOptions::downcase`](crate::sem::MatchOptions::downcase): the type
/// cannot see the options, so a query through a configuration whose two
/// disagree is refused when it is awaited, with
/// [`PlanError::MatchCase`]. A configuration
/// that does not implement this can still store match terms and query them
/// by index; it cannot be queried by [`Matches`].
pub trait MatchCase: MatchConfig {
    /// The case the configuration's index answers.
    type Case: Case;
}

impl MatchCase for DefaultMatch {
    type Case = Insensitive;
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
    /// Why this index cannot answer `Op` as configured, if it cannot: a
    /// match index whose [`MatchCase`] disagrees with its options.
    fn check(&self) -> Result<(), PlanError>;
    /// The query term, from the term the index derived for the query's
    /// value. Only a query chain calls this: `QueryToken` cannot be made
    /// outside this crate, so a stored term cannot be passed off as a
    /// query.
    fn query(term: Self::Term, token: QueryToken) -> Self::Query;
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
    fn check(&self) -> Result<(), PlanError> {
        Ok(())
    }
    fn query(term: EqualityTerm, _: QueryToken) -> EqualityTerm {
        term
    }
}

impl<S, O> Supports<Matches<O::Case>, S> for Match<O>
where
    S: AsRef<str>,
    O: MatchCase,
{
    type Query = MatchQuery<O>;
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
    fn query(term: MatchTerms<O>, _: QueryToken) -> MatchQuery<O> {
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
/// `.op_via(op, index)`. So does a typed field of a fields plan
/// (`encrypt_into::<T, _>(name)`): the field's type is not known where the
/// query is written, so its [`Answers`] impl is not consulted, and a field
/// whose type answers through another index needs `op_via`.
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
        assert_eq!(Matches::<Insensitive>::new(), Matches::new());
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
