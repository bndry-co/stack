//! The SteVec selector pin.
//!
//! A SteVec document stores one entry per JSON node, each tagged with a
//! selector `s`: a keyed MAC over the workspace index key, the column's
//! SteVec prefix and the node's path (and, for a value entry, its value).
//! A query finds an entry by recomputing its selector, so a document a
//! customer has already stored stays queryable only while that computation
//! stays the same. Nothing else in the repository notices it changing: the
//! live SQLx suite generates its fixtures and its queries with the same
//! code, under a live workspace key, so a changed computation changes both
//! sides at once and every assertion still passes.
//!
//! This pins the selectors under a key that never changes:
//! `FakeDataKeySource`'s index key (keyset nil), the one every test in the
//! repository derives terms under. No network, no credentials, and the CI
//! workspace does not enter into it.
//!
//! The computation lives in cipherstash-client's `JsonIndexer` (stack-encrypt
//! has no JSON index yet). The indexer is built the way production builds it:
//! `JsonIndexer::try_init` over an `IndexType::SteVec` deserialized from the
//! exact `ste_vec` index config `@cipherstash/stack` sends for an EQL v3
//! searchable JSON column (`eql/v3/columns.ts`): prefix `table/column`,
//! `array_index_mode` item + wildcard without position, mode `compat`
//! (CLLW-OPE `op` terms). `ScopedCipher` hands the indexer the keyset's index
//! key unchanged, so only the key is swapped. The document covers every JSON
//! shape the indexer branches on: numbers (integer and float), a string, a
//! bool, null, a nested object and an array.
//!
//! What it pins is the cipherstash-client version this EQL workspace resolves.
//! protect-ffi, which writes customers' documents, resolves cipherstash-client
//! from its own workspace and lockfile, so a bump there is not covered until
//! this workspace moves to the same version.
//!
//! Regenerate with `EQL_UPDATE_STE_VEC_SELECTORS=1`, deliberately not the
//! crate's routine `EQL_UPDATE_FIXTURES` switch, and read the failure message
//! below before doing so.

use std::borrow::Cow;
use std::path::PathBuf;

use cipherstash_client::ejsonpath::Selector;
use cipherstash_client::encryption::{IndexerInit, JsonIndexer, SteVec, TokenizedSelector};
use cipherstash_client::schema::column::IndexType;
use cipherstash_client::zerokms;
use serde_json::{json, Value};
use stack_kms::{DataKeySource, FakeDataKeySource, GenerateKeyPayload, IndexKeySource};

const TABLE: &str = "users";
const COLUMN: &str = "profile";

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/ste_vec_selectors.json")
}

fn prefix() -> String {
    format!("{TABLE}/{COLUMN}")
}

fn document() -> Value {
    json!({
        "field": 1,
        "hello": "world",
        "ratio": 1.5,
        "active": true,
        "missing": null,
        "nested": {"deep": "value"},
        "roles": ["admin", "user"],
    })
}

/// The `ste_vec` index config `@cipherstash/stack` sends for an EQL v3
/// searchable JSON column, with its `prefix: 'enabled'` sentinel already
/// rewritten to `table/column` as the table's `build()` does.
fn index_config() -> Value {
    json!({
        "kind": "ste-vec",
        "prefix": prefix(),
        "array_index_mode": {"item": true, "wildcard": true, "position": false},
        "mode": "compat",
    })
}

fn indexer() -> JsonIndexer {
    let index_type: IndexType = serde_json::from_value(index_config()).unwrap();
    JsonIndexer::try_init(&index_type).unwrap()
}

/// `FakeDataKeySource`'s index key for the default (nil) keyset, as the key
/// type cipherstash-client's indexer takes.
async fn index_key() -> zerokms::IndexKey {
    let (keyset, key) = FakeDataKeySource::new().load_index_key(None).await.unwrap();
    assert!(keyset.is_nil(), "the default keyset is nil");
    zerokms::IndexKey::from(*key.key())
}

/// A data key from `FakeDataKeySource` for the document's ciphertexts. They
/// are not pinned (the IV is random); the key exists so the test encrypts a
/// real stored document rather than stopping at the index.
async fn data_key(descriptor: &str) -> zerokms::DataKeyWithTag {
    let mut keys = FakeDataKeySource::new()
        .generate_keys(
            vec![GenerateKeyPayload::new(descriptor, Cow::Owned(vec![]))],
            None,
            None,
        )
        .await
        .unwrap();
    let key = keys.pop().unwrap();
    zerokms::DataKeyWithTag {
        key: zerokms::DataKey {
            iv: key.key.iv,
            key: key.key.key,
        },
        tag: key.tag.clone(),
        decryption_policy: None,
    }
}

fn hex(selector: &TokenizedSelector<16>) -> String {
    selector
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

const DRIFT: &str = "\
The SteVec selectors (or their CLLW-OPE op terms) derived under \
FakeDataKeySource's index key no longer match fixtures/ste_vec_selectors.json. \
A selector is how a query finds an entry in a stored SteVec document, so a \
changed selector breaks queries over every SteVec document customers have \
ALREADY STORED: they stop matching, silently, with no error raised. A changed \
op breaks their range queries the same way. This is a breaking change to stored data, not \
a fixture refresh. Do not regenerate the fixture to make this pass unless the \
break is intended; if it is, regenerate with EQL_UPDATE_STE_VEC_SELECTORS=1 and \
add a changeset on the packages that ship the computation to customers \
(@cipherstash/protect-ffi, and @cipherstash/stack above it) explaining the \
break and how stored documents are re-encrypted.";

#[tokio::test]
async fn ste_vec_selectors_are_pinned_under_the_fake_index_key() {
    let key = index_key().await;
    let indexer = indexer();
    let descriptor = prefix();

    // The stored document: index, then encrypt every entry.
    let pending = indexer.index(document(), &key).unwrap();
    let stored: SteVec<16> = pending
        .encrypt(data_key(&descriptor).await, &descriptor, None)
        .unwrap();

    // The query side: the path selectors a `->` / `jsonb_path_query` query
    // derives, and the value selectors an exact-match query derives.
    let path = |p: &str| hex(&indexer.generate_selector(Selector::parse(p).unwrap(), &key));
    let value = |p: &str, v: Value| {
        hex(&indexer
            .generate_value_selector(Selector::parse(p).unwrap(), &v, &key)
            .unwrap())
    };
    let labels: Vec<(String, String)> = vec![
        ("path $".into(), path("$")),
        ("path $.field".into(), path("$.field")),
        ("path $.hello".into(), path("$.hello")),
        ("path $.ratio".into(), path("$.ratio")),
        ("path $.active".into(), path("$.active")),
        ("path $.missing".into(), path("$.missing")),
        ("path $.nested".into(), path("$.nested")),
        ("path $.nested.deep".into(), path("$.nested.deep")),
        ("path $.roles".into(), path("$.roles")),
        ("path $.roles[*]".into(), path("$.roles[*]")),
        ("value $.field == 1".into(), value("$.field", json!(1))),
        (
            "value $.hello == \"world\"".into(),
            value("$.hello", json!("world")),
        ),
        ("value $.ratio == 1.5".into(), value("$.ratio", json!(1.5))),
        (
            "value $.active == true".into(),
            value("$.active", json!(true)),
        ),
        (
            "value $.nested.deep == \"value\"".into(),
            value("$.nested.deep", json!("value")),
        ),
    ];

    let entries: Vec<Value> = stored
        .entries()
        .iter()
        .map(|entry| {
            let s = hex(&entry.tokenized_selector);
            let label = labels
                .iter()
                .find(|(_, selector)| *selector == s)
                .map(|(label, _)| label.as_str());
            // The orderable term, as the entry serializes it: `op` (CLLW-OPE,
            // Compat mode) on number and string path entries, absent elsewhere.
            let term = serde_json::to_value(entry).unwrap();
            json!({
                "s": s,
                "query": label,
                "op": term.get("op").cloned().unwrap_or(Value::Null),
            })
        })
        .collect();

    // Every selector the query side derives is one the stored document
    // carries: storage and query agree, so the pin below covers both.
    for (label, selector) in &labels {
        assert!(
            entries.iter().any(|e| e["s"] == *selector),
            "the stored document carries the `{label}` selector {selector}"
        );
    }
    // The scalar leaves' path entries carry the orderable `op` term that
    // range queries compare; the pin below records exactly which entries do.
    for leaf in ["path $.field", "path $.hello"] {
        assert!(
            entries
                .iter()
                .any(|e| e["query"] == leaf && !e["op"].is_null()),
            "the `{leaf}` entry carries an `op` term"
        );
    }

    let fixture = json!({
        "_comment": "The SteVec selectors and op terms cipherstash-client's JsonIndexer derives for the document under FakeDataKeySource's index key (keyset nil), with the ste_vec index config @cipherstash/stack sends. A change here breaks queries over SteVec documents customers have already stored: it is a breaking change, not a refresh. Regenerate with EQL_UPDATE_STE_VEC_SELECTORS=1 only alongside a changeset on @cipherstash/protect-ffi explaining the break; do not edit by hand.",
        "index_config": index_config(),
        "prefix": descriptor,
        "document": document(),
        "selectors": labels
            .iter()
            .map(|(label, s)| (label.clone(), Value::String(s.clone())))
            .collect::<serde_json::Map<String, Value>>(),
        "entries": entries,
    });
    let rendered = serde_json::to_string_pretty(&fixture).unwrap() + "\n";
    if std::env::var_os("EQL_UPDATE_STE_VEC_SELECTORS").is_some() {
        std::fs::write(fixture_path(), &rendered).unwrap();
    }
    let committed = std::fs::read_to_string(fixture_path()).expect(
        "fixtures/ste_vec_selectors.json is committed; EQL_UPDATE_STE_VEC_SELECTORS=1 writes it",
    );
    assert_eq!(committed, rendered, "{DRIFT}");
}
