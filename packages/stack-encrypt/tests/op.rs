//! Operator-typed queries (`stack_encrypt::op`, ADR-0009): a query names an
//! operator, the plan finds the index that answers it, and the term that
//! comes back is the query term for that operator, which for a match index
//! is not the stored term.
mod common;

use common::{loads_counting_cipher, stack_cipher};
use stack_encrypt::kms::FakeDataKeySource;
use stack_encrypt::op::{self, MatchCase};
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
    type Case = op::Sensitive;
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
        .encrypt_index::<String>("email", (Equality, Match::default()))
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
        .query("bob@example.com")
        .using(&plan.field("email").unwrap())
        .op(op::Eq)
        .await
        .unwrap();
    assert_eq!(query, email.terms.0, "HMAC equality sends what it stores");
}

#[tokio::test]
async fn a_matches_query_is_a_filter_over_the_needle_that_the_stored_filter_holds() {
    let cipher = stack_cipher().await;
    let plan = people_plan();
    let mut row = cipher.encrypt(&person()).using(&plan).await.unwrap();
    let email: Encrypted<(EqualityTerm, MatchTerms)> = row.take("email").unwrap();
    let stored = email.terms.1;
    let email_plan = plan.field("email").unwrap();

    let query: MatchQuery = cipher
        .query("BOB")
        .using(&email_plan)
        .op(op::Matches::new())
        .await
        .unwrap();
    assert!(stored.matches(&query), "a case-folding index matches BOB");
    assert!(
        query.positions().len() < stored.positions().len(),
        "the query is the needle's filter, not the value's"
    );

    // The operator derives the term the index does, under the same label.
    let by_index: MatchTerms = cipher
        .query("BOB")
        .using(&email_plan)
        .index(Match::default())
        .await
        .unwrap();
    assert_eq!(query.to_bytes(), by_index.to_bytes());
    assert_eq!(query.positions(), by_index.positions());
    assert_eq!(query.clone(), query);

    let elsewhere: MatchQuery = cipher
        .query("zzz")
        .using(&email_plan)
        .op(op::Matches::new())
        .await
        .unwrap();
    assert!(!stored.matches(&elsewhere));
    assert_ne!(elsewhere, query);
}

#[tokio::test]
async fn a_match_index_with_its_own_configuration_is_named_with_op_via() {
    let cipher = stack_cipher().await;
    let plan = people_plan();
    let mut row = cipher.encrypt(&person()).using(&plan).await.unwrap();
    let name: Encrypted<MatchTerms<Exact>> = row.take("name").unwrap();
    let name_plan = plan.field("name").unwrap();

    let exact = |needle: &'static str| {
        cipher
            .query(needle)
            .using(&name_plan)
            .op_via(op::Matches::<op::Sensitive>::new(), Match::<Exact>::new())
    };
    let hit: MatchQuery<Exact> = exact("Nguyen").await.unwrap();
    assert!(name.terms.matches(&hit));
    let miss: MatchQuery<Exact> = exact("nguyen").await.unwrap();
    assert!(
        !name.terms.matches(&miss),
        "a case-sensitive index does not fold the needle"
    );

    // The operator's default index is the default configuration, which
    // this field does not declare.
    assert_eq!(
        plan_error(
            cipher
                .query("Nguyen")
                .using(&name_plan)
                .op(op::Matches::new())
                .await
        ),
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
                .query("Alice")
                .using(&plan.field("name").unwrap())
                .op(op::Eq)
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
        .with::<String, _>((Equality, Match::default()))
        .build()
        .unwrap();
    let stored: Encrypted<(EqualityTerm, MatchTerms)> = cipher
        .encrypt(&"bob@example.com".to_owned())
        .using(&plan)
        .await
        .unwrap();

    let eq = cipher
        .query("bob@example.com")
        .using(&plan)
        .op(op::Eq)
        .await
        .unwrap();
    assert_eq!(eq, stored.terms.0);
    let matches = cipher
        .query("example")
        .using(&plan)
        .op(op::Matches::new())
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
        .query("Ali")
        .using(&exact_plan)
        .op_via(op::Matches::<op::Sensitive>::new(), Match::<Exact>::new())
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
        .query("bob@example.com")
        .using(&eq_plan)
        .op(op::Eq)
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
        .query("bob")
        .using(&match_plan)
        .op(op::Matches::new())
        .await
        .unwrap();
    assert!(stored.matches(&query));
}

#[tokio::test]
async fn a_target_with_several_terms_names_the_index_with_op_via() {
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
        .query("bob@example.com")
        .using(&plan)
        .op_via(op::Eq, Equality)
        .await
        .unwrap();
    assert_eq!(eq, stored.terms.0);
    let matches = cipher
        .query("bob")
        .using(&plan)
        .op_via(op::Matches::new(), Match::default())
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
                .query("bob")
                .using(&one_term)
                .op_via(op::Matches::new(), Match::default())
                .await
        ),
        PlanError::IndexNotDeclared {
            field: "the value".into(),
            index: "match"
        }
    );
    let eq = cipher.query("bob").using(&one_term).op(op::Eq).await;
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
            .query("bob@example.com")
            .using(&email_plan)
            .op(op::Eq)
            .extend(7u64),
        cipher
            .query("bob")
            .using(&email_plan)
            .op(op::Matches::new())
            .extend(7u64),
    ))
    .await
    .unwrap();
    assert_eq!(eq, email.terms.0);
    assert!(email.terms.1.matches(&matches));

    let unextended = cipher
        .query("bob@example.com")
        .using(&email_plan)
        .op(op::Eq)
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
    let shown = format!("{:?}", cipher.query(secret).using(&email_plan).op(op::Eq));
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
    type Case = op::Insensitive;
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
            .query("Bob")
            .using(&plan)
            .op_via(op::Matches::new(), Match::<Mislabelled>::new())
            .await,
    );
    assert_eq!(
        refused,
        PlanError::MatchCase {
            declared: "Insensitive",
            folds: false
        }
    );
    assert_eq!(
        refused.to_string(),
        "a match configuration declares the case Insensitive but its options keep case"
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
        .query("Alice")
        .using(&plan.field("name").unwrap())
        .op(op::Eq)
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
async fn a_match_query_debugs_as_its_positions() {
    let cipher = stack_cipher().await;
    let plan = people_plan();
    let query = cipher
        .query("bob")
        .using(&plan.field("email").unwrap())
        .op(op::Matches::new())
        .await
        .unwrap();
    assert_eq!(
        format!("{query:?}"),
        format!("MatchQuery {{ positions: {:?} }}", query.positions())
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
        .query("bob@example.com")
        .using(&plan)
        .op(op::Eq)
        .keyset("tenant")
        .await
        .unwrap();
    assert_eq!(under_tenant, stored.terms);
    let under_default = cipher
        .query("bob@example.com")
        .using(&plan)
        .op(op::Eq)
        .await
        .unwrap();
    assert_ne!(under_default, stored.terms, "another keyset, another key");
}
