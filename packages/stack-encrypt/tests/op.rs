//! Operator-typed queries (`stack_encrypt::op`, ADR-0009): a query names an
//! operator, the plan finds the index that answers it, and the term that
//! comes back is the query term for that operator, which for a match index
//! is not the stored term.
mod common;

use common::{loads_counting_cipher, stack_cipher};
use stack_encrypt::kms::FakeDataKeySource;
use stack_encrypt::op::{self, Limit, MatchCase, Probabilistic, Stats};
use stack_encrypt::plan::{Field, FieldSchema, Fields, PlanError};
use stack_encrypt::sem::{EqualityTerm, MatchConfig, MatchOptions, MatchQuery, MatchTerms};
use stack_encrypt::target::{Encrypted, IndexSpec};
use stack_encrypt::{Equality, Error, Match, Plan};

/// A match configuration that keeps case, so its index answers only a
/// case-sensitive `Matches`.
struct Exact;
impl MatchConfig for Exact {
    fn options() -> MatchOptions {
        MatchOptions {
            downcase: false,
            ..Default::default()
        }
    }
}
impl MatchCase for Exact {
    type Case = op::CaseSensitive;
}

#[derive(Clone)]
struct Person {
    email: String,
    name: String,
}

impl Fields for Person {
    fn field_names(&self) -> Vec<&str> {
        vec!["email", "name"]
    }
    fn schema() -> Option<Vec<FieldSchema>> {
        Some(vec![
            FieldSchema::of::<String>("email"),
            FieldSchema::of::<String>("name"),
        ])
    }
}
impl Field<String> for Person {
    fn field(&self, name: &str) -> Option<&String> {
        match name {
            "email" => Some(&self.email),
            "name" => Some(&self.name),
            _ => None,
        }
    }
}

fn person() -> Person {
    Person {
        email: "bob@example.com".into(),
        name: "Alice Nguyen".into(),
    }
}

fn people_plan() -> Plan<Person, FakeDataKeySource> {
    Plan::context("people")
        .fields()
        .encrypt_index::<String>("email", (Equality, Match))
        .encrypt_index::<String>("name", Match::<Exact>::new())
        .build()
        .expect("a valid plan")
}

fn plan_error<T>(result: Result<T, Error>) -> PlanError {
    match result {
        Err(Error::Plan(error)) => error,
        Err(other) => panic!("expected a plan error, got {other:?}"),
        Ok(_) => panic!("expected a plan error, got a value"),
    }
}

#[tokio::test]
async fn an_eq_query_is_the_stored_equality_term() {
    let cipher = stack_cipher().await;
    let plan = people_plan();
    let mut row = cipher.encrypt(&person()).using(&plan).await.unwrap();
    let email: Encrypted<(EqualityTerm, MatchTerms)> = row.take("email").unwrap();

    let query: EqualityTerm = cipher
        .query(op::Eq, "bob@example.com")
        .on(&plan.field("email").unwrap())
        .await
        .unwrap();
    assert_eq!(query, email.terms.0, "HMAC equality sends what it stores");
}

#[tokio::test]
async fn a_matches_query_is_a_filter_over_the_query_value_that_the_stored_filter_holds() {
    let cipher = stack_cipher().await;
    let plan = people_plan();
    let mut row = cipher.encrypt(&person()).using(&plan).await.unwrap();
    let email: Encrypted<(EqualityTerm, MatchTerms)> = row.take("email").unwrap();
    let stored = email.terms.1;
    let email_plan = plan.field("email").unwrap();

    let query: MatchQuery = cipher
        .query(op::Matches, "BOB")
        .on(&email_plan)
        .await
        .unwrap();
    assert!(stored.matches(&query), "a case-folding index matches BOB");
    assert!(
        query.positions().len() < stored.positions().len(),
        "the query is the query value's filter, not the stored value's"
    );

    // The operator derives the filter the index writes, under the same
    // label: the query for BOB is the stored filter of bob.
    let bob = Person {
        email: "bob".into(),
        ..person()
    };
    let mut bob_row = cipher.encrypt(&bob).using(&plan).await.unwrap();
    let bob_email: Encrypted<(EqualityTerm, MatchTerms)> = bob_row.take("email").unwrap();
    assert_eq!(query.to_bytes(), bob_email.terms.1.to_bytes());
    assert_eq!(query.positions(), bob_email.terms.1.positions());
    assert_eq!(query.clone(), query);

    let elsewhere: MatchQuery = cipher
        .query(op::Matches, "zzz")
        .on(&email_plan)
        .await
        .unwrap();
    assert!(!stored.matches(&elsewhere));
    assert_ne!(elsewhere, query);
}

#[tokio::test]
async fn a_match_index_with_its_own_configuration_is_named_with_via() {
    let cipher = stack_cipher().await;
    let plan = people_plan();
    let mut row = cipher.encrypt(&person()).using(&plan).await.unwrap();
    let name: Encrypted<MatchTerms<Exact>> = row.take("name").unwrap();
    let name_plan = plan.field("name").unwrap();

    let exact = |value: &'static str| {
        cipher
            .query(op::Matches.case_sensitive(), value)
            .via(Match::<Exact>::new())
            .on(&name_plan)
    };
    let hit: MatchQuery<Exact> = exact("Nguyen").await.unwrap();
    assert!(name.terms.matches(&hit));
    let miss: MatchQuery<Exact> = exact("nguyen").await.unwrap();
    assert!(
        !name.terms.matches(&miss),
        "a case-sensitive index does not fold the query"
    );

    // The operator's default index is the default configuration, which
    // this field does not declare.
    assert_eq!(
        plan_error(cipher.query(op::Matches, "Nguyen").on(&name_plan).await),
        PlanError::IndexOptions {
            field: "name".into(),
            declared: IndexSpec::Match(Exact::options()),
            asked: IndexSpec::Match(MatchOptions::default()),
        }
    );
}

#[tokio::test]
async fn an_operator_the_field_has_no_index_for_is_refused_when_awaited() {
    let cipher = stack_cipher().await;
    let plan = people_plan();
    assert_eq!(
        plan_error(
            cipher
                .query(op::Eq, "Alice")
                .on(&plan.field("name").unwrap())
                .await
        ),
        PlanError::IndexNotDeclared {
            field: "name".into(),
            index: "eq"
        }
    );
}

#[tokio::test]
async fn a_one_value_plan_answers_from_its_indexes_by_type() {
    let cipher = stack_cipher().await;
    let plan = Plan::context("users/email")
        .with::<String, _>((Equality, Match))
        .build()
        .unwrap();
    let stored: Encrypted<(EqualityTerm, MatchTerms)> = cipher
        .encrypt(&"bob@example.com".to_owned())
        .using(&plan)
        .await
        .unwrap();

    let eq = cipher
        .query(op::Eq, "bob@example.com")
        .on(&plan)
        .await
        .unwrap();
    assert_eq!(eq, stored.terms.0);
    let matches = cipher
        .query(op::Matches, "example")
        .on(&plan)
        .await
        .unwrap();
    assert!(stored.terms.1.matches(&matches));

    let exact_plan = Plan::context("users/name")
        .with::<String, _>(Match::<Exact>::new())
        .build()
        .unwrap();
    let name: Encrypted<MatchTerms<Exact>> = cipher
        .encrypt(&"Alice".to_owned())
        .using(&exact_plan)
        .await
        .unwrap();
    let query = cipher
        .query(op::Matches.case_sensitive(), "Ali")
        .via(Match::<Exact>::new())
        .on(&exact_plan)
        .await
        .unwrap();
    assert!(name.terms.matches(&query));
}

#[tokio::test]
async fn a_target_answers_an_operator_through_the_index_it_names() {
    let cipher = stack_cipher().await;
    let eq_plan = Plan::value::<String>()
        .context("users/email")
        .encrypt_into::<EqualityTerm>()
        .build()
        .unwrap();
    let stored: EqualityTerm = cipher
        .encrypt(&"bob@example.com".to_owned())
        .using(&eq_plan)
        .await
        .unwrap();
    let query = cipher
        .query(op::Eq, "bob@example.com")
        .on(&eq_plan)
        .await
        .unwrap();
    assert_eq!(query, stored);

    let match_plan = Plan::value::<String>()
        .context("users/email")
        .encrypt_into::<MatchTerms>()
        .build()
        .unwrap();
    let stored: MatchTerms = cipher
        .encrypt(&"bob@example.com".to_owned())
        .using(&match_plan)
        .await
        .unwrap();
    let query = cipher
        .query(op::Matches, "bob")
        .on(&match_plan)
        .await
        .unwrap();
    assert!(stored.matches(&query));
}

#[tokio::test]
async fn a_target_with_several_terms_names_the_index_with_via() {
    let cipher = stack_cipher().await;
    let plan = Plan::value::<String>()
        .context("users/email")
        .encrypt_into::<Encrypted<(EqualityTerm, MatchTerms)>>()
        .build()
        .unwrap();
    let stored = cipher
        .encrypt(&"bob@example.com".to_owned())
        .using(&plan)
        .await
        .unwrap();
    let eq = cipher
        .query(op::Eq, "bob@example.com")
        .via(Equality)
        .on(&plan)
        .await
        .unwrap();
    assert_eq!(eq, stored.terms.0);
    let matches = cipher
        .query(op::Matches, "bob")
        .via(Match)
        .on(&plan)
        .await
        .unwrap();
    assert!(stored.terms.1.matches(&matches));

    // An index the target does not declare is refused when awaited.
    let one_term = Plan::value::<String>()
        .context("users/email")
        .encrypt_into::<Encrypted<EqualityTerm>>()
        .build()
        .unwrap();
    assert_eq!(
        plan_error(
            cipher
                .query(op::Matches, "bob")
                .via(Match)
                .on(&one_term)
                .await
        ),
        PlanError::IndexNotDeclared {
            field: "the value".into(),
            index: "match"
        }
    );
    let eq = cipher.query(op::Eq, "bob").on(&one_term).await;
    assert!(eq.is_ok(), "one term answers what the term answers");
}

#[tokio::test]
async fn operator_queries_settle_together_and_extend_like_the_write() {
    let cipher = stack_cipher().await;
    let plan = people_plan();
    let mut row = cipher
        .encrypt(&person())
        .using(&plan)
        .extend(7u64)
        .await
        .unwrap();
    let email: Encrypted<(EqualityTerm, MatchTerms)> = row.take("email").unwrap();
    let email_plan = plan.field("email").unwrap();

    let (eq, matches) = stack_encrypt::all((
        cipher
            .query(op::Eq, "bob@example.com")
            .on(&email_plan)
            .extend(7u64),
        cipher
            .query(op::Matches, "bob")
            .on(&email_plan)
            .extend(7u64),
    ))
    .await
    .unwrap();
    assert_eq!(eq, email.terms.0);
    assert!(email.terms.1.matches(&matches));

    let unextended = cipher
        .query(op::Eq, "bob@example.com")
        .on(&email_plan)
        .await
        .unwrap();
    assert_ne!(
        unextended, email.terms.0,
        "the query is derived under the extended label"
    );
}

#[tokio::test]
async fn a_query_chain_debugs_without_its_value() {
    let cipher = stack_cipher().await;
    let plan = people_plan();
    let email_plan = plan.field("email").unwrap();
    let secret = "bob@example.com";
    let shown = format!("{:?}", cipher.query(op::Eq, secret).on(&email_plan));
    assert_eq!(shown, "QueryOp { .. }");
}

/// A configuration whose `MatchCase` says it folds case while its options
/// keep it: the type cannot see the options, so the query is refused.
struct Mislabelled;
impl MatchConfig for Mislabelled {
    fn options() -> MatchOptions {
        MatchOptions {
            downcase: false,
            ..Default::default()
        }
    }
}
impl MatchCase for Mislabelled {
    type Case = op::CaseInsensitive;
}

#[tokio::test]
async fn a_match_case_that_disagrees_with_its_options_is_refused() {
    let cipher = stack_cipher().await;
    let plan = Plan::context("users/name")
        .with::<String, _>(Match::<Mislabelled>::new())
        .build()
        .unwrap();
    let refused = plan_error(
        cipher
            .query(op::Matches, "Bob")
            .via(Match::<Mislabelled>::new())
            .on(&plan)
            .await,
    );
    assert_eq!(
        refused,
        PlanError::MatchCase {
            declared: "CaseInsensitive",
            folds: false
        }
    );
    assert_eq!(
        refused.to_string(),
        "a match configuration declares the case CaseInsensitive but its options keep case"
    );
}

#[tokio::test]
async fn an_undeclared_index_is_refused_before_its_case_is_checked() {
    let cipher = stack_cipher().await;
    let plan = people_plan();
    let refused = plan_error(
        cipher
            .query(op::Matches, "Bob")
            .via(Match::<Mislabelled>::new())
            .on(&plan.field("email").unwrap())
            .await,
    );
    assert!(
        matches!(refused, PlanError::IndexOptions { ref field, .. } if field == "email"),
        "the plan's refusal comes first, not the case: {refused:?}"
    );

    let no_context: Plan<Person, FakeDataKeySource> = Plan::fields()
        .encrypt::<String>("email")
        .encrypt_index::<String>("name", Match::<Mislabelled>::new())
        .build()
        .unwrap();
    let refused = plan_error(
        cipher
            .query(op::Matches, "Bob")
            .via(Match::<Mislabelled>::new())
            .on(&no_context.field("name").unwrap())
            .await,
    );
    assert_eq!(refused, PlanError::NoContext);
}

#[tokio::test]
async fn a_query_names_its_context_before_or_after_the_index() {
    let cipher = stack_cipher().await;
    let plan: Plan<Person, FakeDataKeySource> = Plan::fields()
        .encrypt_index::<String>("email", Match)
        .encrypt::<String>("name")
        .build()
        .unwrap();
    let email_plan = plan.field("email").unwrap();
    let before = cipher
        .query(op::Matches, "bob")
        .context("people")
        .via(Match)
        .on(&email_plan)
        .await
        .unwrap();
    let after = cipher
        .query(op::Matches, "bob")
        .via(Match)
        .context("people")
        .on(&email_plan)
        .await
        .unwrap();
    assert_eq!(before, after);
}

/// A configuration with an n-gram length of zero, which `MatchOptions`
/// refuses when a term is derived.
struct ZeroGram;
impl MatchConfig for ZeroGram {
    fn options() -> MatchOptions {
        MatchOptions {
            tokenizer: stack_encrypt::sem::Tokenizer::Ngram { length: 0 },
            ..Default::default()
        }
    }
}
impl MatchCase for ZeroGram {
    type Case = op::CaseInsensitive;
}

#[tokio::test]
async fn a_match_query_under_invalid_options_is_refused_not_a_panic() {
    let cipher = stack_cipher().await;
    let plan = Plan::context("users/name")
        .with::<String, _>(Match::<ZeroGram>::new())
        .build()
        .unwrap();
    let refused = cipher
        .query(op::Matches, "Bob")
        .via(Match::<ZeroGram>::new())
        .on(&plan)
        .await;
    assert!(
        matches!(
            refused,
            Err(Error::Term(stack_encrypt::sem::TermError::InvalidOptions(
                _
            )))
        ),
        "{refused:?}"
    );
}

#[tokio::test]
async fn a_refused_operator_query_loads_no_keyset() {
    let (cipher, loads) = loads_counting_cipher().await;
    let plan: Plan<Person, common::CountingSource> = Plan::context("people")
        .fields()
        .encrypt::<String>("email")
        .encrypt_index::<String>("name", Match::<Exact>::new())
        .build()
        .unwrap();
    let refused = cipher
        .query(op::Eq, "Alice")
        .on(&plan.field("name").unwrap())
        .keyset("tenant")
        .await;
    assert_eq!(
        plan_error(refused),
        PlanError::IndexNotDeclared {
            field: "name".into(),
            index: "eq"
        }
    );
    assert_eq!(
        loads.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "refused before the named keyset is loaded"
    );
}

#[tokio::test]
async fn an_operator_query_runs_under_the_keyset_it_names() {
    let cipher = stack_cipher().await;
    let plan = Plan::context("users/email")
        .with::<String, _>(Equality)
        .build()
        .unwrap();
    let stored: Encrypted<EqualityTerm> = cipher
        .encrypt(&"bob@example.com".to_owned())
        .using(&plan)
        .keyset("tenant")
        .await
        .unwrap();
    let under_tenant = cipher
        .query(op::Eq, "bob@example.com")
        .on(&plan)
        .keyset("tenant")
        .await
        .unwrap();
    assert_eq!(under_tenant, stored.terms);
    let under_default = cipher
        .query(op::Eq, "bob@example.com")
        .on(&plan)
        .await
        .unwrap();
    assert_ne!(under_default, stored.terms, "another keyset, another key");
}

/// A match configuration with the smallest filter allowed, so a long value
/// sets nearly every bit and false positives are easy to find.
struct Tiny;
impl MatchConfig for Tiny {
    fn options() -> MatchOptions {
        MatchOptions {
            m: 32,
            ..Default::default()
        }
    }
}
impl MatchCase for Tiny {
    type Case = op::CaseInsensitive;
}

#[tokio::test]
async fn verify_keeps_every_real_match_and_folds_case_as_the_index_does() {
    let cipher = stack_cipher().await;
    let plan = people_plan();
    let email_plan = plan.field("email").unwrap();
    let name_plan = plan.field("name").unwrap();

    let query = cipher
        .query(op::Matches, "BOB@Example")
        .on(&email_plan)
        .await
        .unwrap();
    assert!(query.verify("bob@example.com"));
    assert!(query.verify(&String::from("say hi to Bob@example.org")));
    assert!(!query.verify("alice@example.com"));
    assert!(query.clone().verify("bob@example.com"));

    let exact = cipher
        .query(op::Matches.case_sensitive(), "Nguyen")
        .via(Match::<Exact>::new())
        .on(&name_plan)
        .await
        .unwrap();
    assert!(exact.verify("Alice Nguyen"));
    assert!(
        !exact.verify("alice nguyen"),
        "a case-sensitive index keeps case"
    );
}

#[tokio::test]
async fn verify_drops_a_row_the_filter_matched_by_chance() {
    let cipher = stack_cipher().await;
    let plan = Plan::context("notes/body")
        .with::<String, _>(Match::<Tiny>::new())
        .build()
        .unwrap();
    let value = "the quick brown fox jumps over the lazy dog and keeps running";
    let stored: Encrypted<MatchTerms<Tiny>> = cipher
        .encrypt(&value.to_owned())
        .using(&plan)
        .await
        .unwrap();

    let real = cipher
        .query(op::Matches, "lazy dog")
        .via(Match::<Tiny>::new())
        .on(&plan)
        .await
        .unwrap();
    assert!(stored.terms.matches(&real) && real.verify(value));

    // The value holds no digit, so no query with one is in it; a 32-bit
    // filter this full holds some of their filters anyway.
    let mut false_positive = None;
    for i in 0..1000 {
        let digits = format!("{i:04}");
        let query = cipher
            .query(op::Matches, &digits)
            .via(Match::<Tiny>::new())
            .on(&plan)
            .await
            .unwrap();
        if stored.terms.matches(&query) {
            false_positive = Some(query);
            break;
        }
    }
    let query = false_positive.expect("a 32-bit filter this full matches some query by chance");
    assert!(
        !query.verify(value),
        "the server would return this row; verify does not keep it"
    );
}

#[tokio::test]
async fn a_match_query_debugs_without_its_tokens() {
    let cipher = stack_cipher().await;
    let plan = people_plan();
    let query = cipher
        .query(op::Matches, "needle")
        .on(&plan.field("email").unwrap())
        .await
        .unwrap();
    let shown = format!("{query:?}");
    assert_eq!(
        shown,
        format!("MatchQuery {{ positions: {:?}, .. }}", query.positions())
    );
    for token in ["nee", "eed", "edl", "dle", "needle"] {
        assert!(!shown.contains(token), "{shown}");
    }
}

/// Whole words, as the v1 match indexer's standard tokenizer splits them.
struct Words;
impl MatchConfig for Words {
    fn options() -> MatchOptions {
        MatchOptions {
            tokenizer: stack_encrypt::sem::Tokenizer::Standard,
            ..Default::default()
        }
    }
}
impl MatchCase for Words {
    type Case = op::CaseInsensitive;
}

/// A Bloom match asks for the query's tokens, in any order and anywhere;
/// it is not a substring test, and `verify` must not become one, or it
/// would drop rows the index rightly returned.
#[tokio::test]
async fn verify_is_a_token_test_not_a_substring_test() {
    let cipher = stack_cipher().await;
    let plan = people_plan();
    let query = cipher
        .query(op::Matches, "abcd")
        .on(&plan.field("email").unwrap())
        .await
        .unwrap();
    assert!(query.verify("abc bcd"), "both 3-grams, never adjacent");
    assert!(!query.verify("abc"), "one 3-gram of two");

    let words = Plan::context("notes/body")
        .with::<String, _>(Match::<Words>::new())
        .build()
        .unwrap();
    let stored: Encrypted<MatchTerms<Words>> = cipher
        .encrypt(&"Hello, big World!".to_owned())
        .using(&words)
        .await
        .unwrap();
    let query = cipher
        .query(op::Matches, "world hello")
        .via(Match::<Words>::new())
        .on(&words)
        .await
        .unwrap();
    assert!(stored.terms.matches(&query));
    assert!(query.verify("Hello, big World!"));
    assert!(
        !query.verify("worldly hello"),
        "a word is a token, not a prefix"
    );
}

/// EQL v4's match parameters, with a notes column's prior.
struct Notes;
impl MatchConfig for Notes {
    fn options() -> MatchOptions {
        MatchOptions {
            k: 6,
            m: 2048,
            ..Default::default()
        }
    }
    fn expected_tokens() -> Option<u32> {
        Some(200)
    }
}
impl MatchCase for Notes {
    type Case = op::CaseInsensitive;
}

#[tokio::test]
async fn target_limit_sizes_the_fetch_from_the_query_and_the_prior() {
    let cipher = stack_cipher().await;
    let plan = Plan::context("notes/body")
        .with::<String, _>(Match::<Notes>::new())
        .build()
        .unwrap();
    let query = |text: &'static str| {
        cipher
            .query(op::Matches, text)
            .via(Match::<Notes>::new())
            .on(&plan)
    };
    let stats = Stats::declared(1_000_000);

    let short = query("ali").await.unwrap();
    let long = query("alice nguyen").await.unwrap();
    let (Limit::Rows(short_rows), Limit::Rows(long_rows)) = (
        short.target_limit(10, &stats),
        long.target_limit(10, &stats),
    ) else {
        panic!("a declared prior gives a finite fetch");
    };
    assert!(
        short_rows > 1_000,
        "three letters against long text match thousands of rows by chance: {short_rows}"
    );
    assert!(long_rows < 20, "a long query sets enough bits: {long_rows}");
    assert!(long_rows >= 10, "never fewer than `want`");

    // A tighter confidence asks for more.
    let strict = short.target_limit(10, &stats.clone().with_confidence(0.9999));
    assert!(strict.rows().unwrap() > short_rows);
}

#[tokio::test]
async fn target_limit_without_a_prior_needs_a_measured_column() {
    let cipher = stack_cipher().await;
    let plan = people_plan();
    let email_plan = plan.field("email").unwrap();
    let query = cipher
        .query(op::Matches, "bob")
        .on(&email_plan)
        .await
        .unwrap();

    // The default configuration declares no prior.
    assert_eq!(
        query.target_limit(10, &Stats::declared(1_000)),
        Limit::Unbounded
    );

    // Measure the column: the set-bit count of each stored filter.
    let mut histogram = std::collections::BTreeMap::<u32, u64>::new();
    for email in [
        "bob@example.com",
        "alice@example.org",
        "carol.smith@example.net",
    ] {
        let mut row = cipher
            .encrypt(&Person {
                email: email.into(),
                name: "x".repeat(4),
            })
            .using(&plan)
            .await
            .unwrap();
        let stored: Encrypted<(EqualityTerm, MatchTerms)> = row.take("email").unwrap();
        *histogram
            .entry(stored.terms.1.positions().len() as u32)
            .or_default() += 1;
    }
    // The pass rate the histogram gives this query, over a large table.
    let bits = query.positions().len() as i32;
    let rows_seen: u64 = histogram.values().sum();
    let p = histogram
        .iter()
        .map(|(&set, &n)| n as f64 * (f64::from(set) / 256.0).powi(bits))
        .sum::<f64>()
        / rows_seen as f64;
    let lambda = p * 1_000_000.0;
    let stats = Stats::measured(1_000_000, histogram);
    let Limit::Rows(rows) = query.target_limit(10, &stats) else {
        panic!("a measured column gives a finite fetch");
    };
    let extra = (rows - 10) as f64;
    assert!(
        extra >= lambda && extra <= lambda + 4.0 * lambda.sqrt() + 3.0,
        "10 wanted, λ = {lambda}: {rows}"
    );
}
