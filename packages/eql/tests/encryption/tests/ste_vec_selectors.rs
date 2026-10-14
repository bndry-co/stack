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
//! has no JSON index yet); `ScopedCipher` hands it the keyset's index key
//! unchanged, so passing it the fake index key is the production path with
//! the key swapped. The prefix is `table/column`, which is how
//! `@cipherstash/stack` builds every JSON column's `ste_vec` index, and the
//! mode is `Compat` (CLLW-OPE `op` terms), the only mode EQL v3 stores.
//!
//! Regenerate with `EQL_UPDATE_FIXTURES=1` — and read the failure message
//! below before doing so.

use std::borrow::Cow;
use std::path::PathBuf;

use cipherstash_client::ejsonpath::Selector;
use cipherstash_client::encryption::{JsonIndexer, JsonIndexerOptions, SteVec, TokenizedSelector};
use cipherstash_client::schema::column::{ArrayIndexMode, SteVecMode};
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
    json!({"field": 1, "hello": "world"})
}

fn indexer() -> JsonIndexer {
    JsonIndexer::new(JsonIndexerOptions {
        prefix: prefix(),
        term_filters: Vec::new(),
        array_index_mode: ArrayIndexMode::default(),
        mode: SteVecMode::Compat,
    })
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
break is intended; if it is, regenerate with EQL_UPDATE_FIXTURES=1 and add a \
changeset that explains the break and how stored documents are re-encrypted.";

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
        ("value $.field == 1".into(), value("$.field", json!(1))),
        (
            "value $.hello == \"world\"".into(),
            value("$.hello", json!("world")),
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
    // Six entries, and the only one no query names is the root's own value
    // entry: value selectors take scalars only, so no query builds it.
    let unlabelled: Vec<usize> = entries
        .iter()
        .enumerate()
        .filter(|(_, e)| e["query"].is_null())
        .map(|(i, _)| i)
        .collect();
    assert_eq!(entries.len(), 6, "the document has six SteVec entries");
    assert_eq!(unlabelled, [3], "only the root value entry is unlabelled");
    // The op-carrying entries are exactly the two scalar leaves' path entries.
    let with_op: Vec<&Value> = entries.iter().filter(|e| !e["op"].is_null()).collect();
    assert_eq!(
        with_op
            .iter()
            .map(|e| e["query"].as_str().unwrap_or("?"))
            .collect::<Vec<_>>(),
        ["path $.field", "path $.hello"],
        "the op-carrying entries are the $.field and $.hello path entries"
    );

    let fixture = json!({
        "_comment": "The SteVec selectors cipherstash-client's JsonIndexer derives for the document under FakeDataKeySource's index key (keyset nil). A change here breaks queries over SteVec documents customers have already stored: it is a breaking change, not a refresh. Regenerate with EQL_UPDATE_FIXTURES=1 only alongside a changeset explaining the break; do not edit by hand.",
        "prefix": descriptor,
        "mode": "Compat",
        "document": document(),
        "selectors": labels
            .iter()
            .map(|(label, s)| (label.clone(), Value::String(s.clone())))
            .collect::<serde_json::Map<String, Value>>(),
        "entries": entries,
    });
    let rendered = serde_json::to_string_pretty(&fixture).unwrap() + "\n";
    if std::env::var_os("EQL_UPDATE_FIXTURES").is_some() {
        std::fs::write(fixture_path(), &rendered).unwrap();
    }
    let committed = std::fs::read_to_string(fixture_path())
        .expect("fixtures/ste_vec_selectors.json is committed; EQL_UPDATE_FIXTURES=1 writes it");
    assert_eq!(committed, rendered, "{DRIFT}");
}
