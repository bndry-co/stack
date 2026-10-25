//! An encrypted JSON document through a data plan: the path a language SDK
//! takes (the Go guest installs the same resolver), against the typed Rust
//! path it must agree with.
//!
//! A data-plan field names the target `EncryptedJson`, declares the `json`
//! type, and hands its document over as JSON text. The engine parses it by
//! one set of rules, lays it out with the JSON index under the field's
//! options, and stores the `public.eql_v4_json_tree` value; opening gives
//! the document's text back. Here:
//!
//! - a batch of documents seals in one key request and opens to the same
//!   values, scalar roots, arrays and a JSON `null` included;
//! - the data plan and `JsonTree::new(options)` write the same search terms
//!   (selectors, ordering terms, the containment projection) for the same
//!   document under the same column, and each opens what the other sealed;
//! - text that is not a document is refused before any key is requested,
//!   naming the field and a code, never a byte of the text.

mod common;

use std::collections::BTreeMap;

use eql_bindings::encryption::targets::{self as eql_targets, Target};
use eql_bindings::v4::json_tree::{JsonTree, JsonTreeDocument};
use eql_bindings::Identifier;
use serde_json::{json, Value};
use stack_encrypt::dynamic::{
    self, record, Scope, TargetDescriptor, TargetError, TargetResolver, ValueFrame,
};
use stack_encrypt::json::JsonOptions;
use stack_encrypt::target::{ExpectedContext, Layout};
use stack_encrypt::{CipherText, Encrypt, KeysetCipher, Label, NonEmpty, Pending, StackCipher};

/// eql-bindings' table as the engine's resolver, as the Go guest installs
/// it (`languages/golang/encrypt/guest/src/targets.rs`).
struct Eql;

fn describe(target: &Target) -> TargetDescriptor {
    TargetDescriptor::new(
        target.name,
        target.family,
        target.suffix,
        target.plaintext_kind(),
        target.sql_domain,
        target.indexes.iter().map(|key| (*key).to_owned()).collect(),
        target.query.map(str::to_owned),
        target.query_sql_domain.map(str::to_owned),
        target.producible,
        target.reason.map(str::to_owned),
    )
}

/// As the guest converts: a document refusal keeps its code.
fn convert(error: eql_targets::TargetError) -> TargetError {
    match error {
        eql_targets::TargetError::Json { target, source } => TargetError::Json {
            name: String::new(),
            target: target.to_owned(),
            reason: source.code(),
        },
        other => TargetError::Other(Box::new(other)),
    }
}

impl TargetResolver for Eql {
    fn targets(&self) -> Vec<TargetDescriptor> {
        eql_targets::targets().iter().map(describe).collect()
    }
    fn encrypt<'a, K: 'static>(
        &self,
        name: &str,
        options: Option<&dynamic::TargetOptions>,
        keyset: &'a KeysetCipher<'_, K>,
        label: &Label,
        plaintext: ValueFrame,
    ) -> Result<Pending<'a, Vec<u8>, K>, TargetError> {
        eql_targets::encrypt_with(name, options, keyset, label, plaintext).map_err(convert)
    }
    fn decrypt<'a, K: 'static>(
        &self,
        name: &str,
        cipher: &'a StackCipher<K>,
        label: &Label,
        stored: &[u8],
    ) -> Result<Pending<'a, ValueFrame, K>, TargetError> {
        eql_targets::decrypt(name, cipher, label, stored).map_err(convert)
    }
    fn query<'a, K: 'static>(
        &self,
        name: &str,
        index: &stack_encrypt::target::IndexSpec,
        keyset: &'a KeysetCipher<'_, K>,
        label: &Label,
        plaintext: ValueFrame,
    ) -> Result<Pending<'a, Vec<u8>, K>, TargetError> {
        eql_targets::query(name, index, keyset, label, plaintext).map_err(convert)
    }
}

/// The options the documents are sealed under on both paths.
fn options() -> JsonOptions {
    JsonOptions::default()
        .ordering(["$.age", "$.visits[*].at"])
        .unwrap()
}

/// A plan with one `json` field, `profile`, under `users/profile`, naming
/// `EncryptedJson` with [`options`], as a binding writes it.
fn plan() -> record::Plan {
    let wire = json!({
        "profile": {
            "context": ["users", "profile"],
            "type": "json",
            "null": "sql",
            "target": {
                "name": "EncryptedJson",
                "options": {"ordered": ["$.age", "$.visits[*].at"]}
            }
        }
    });
    record::plan_with(&dynamic::frame::serde::to_vec(&wire).unwrap(), &Eql).unwrap()
}

fn frame<T: Encrypt>(value: T) -> ValueFrame {
    ValueFrame::of(value).unwrap()
}

/// The documents a batch carries, as values.
fn documents() -> Vec<Value> {
    vec![
        json!({"name": "Alice", "age": 34, "visits": [{"at": 3, "where": "x"}, {"at": 1}], "tags": ["a", "b"]}),
        json!({"name": "Bob", "age": 7.5, "nested": {"deep": [[1, 2], {}]}, "none": null}),
        json!([1, "two", {"three": 3}]),
        json!("a scalar root"),
        json!(18446744073709551615u64),
        json!(-9223372036854775808i64),
        json!(-926_809.505_100_808_3),
        Value::Null,
        json!({}),
        json!([]),
    ]
}

/// The EQL value a sealed row stores for `profile`, parsed.
fn stored(row: &stack_encrypt::StackCipherText) -> JsonTreeDocument {
    let CipherText::Map(fields) = row else {
        panic!("a row is a map")
    };
    let (_, CipherText::Map(outputs)) = fields
        .iter()
        .find(|(name, _)| name == "profile")
        .expect("profile is stored")
    else {
        panic!("profile is a map of outputs");
    };
    let Some((_, CipherText::Passthrough(payload))) = outputs.iter().find(|(key, _)| key == "eql")
    else {
        panic!("profile's EQL value is a passthrough");
    };
    let bytes: Vec<u8> =
        match dynamic::frame::serde::from_slice::<serde_bytes_like::Bytes>(&payload.0) {
            Ok(bytes) => bytes.0,
            Err(_) => panic!("the EQL value is bytes"),
        };
    serde_json::from_slice(&bytes).expect("the EQL value is a json_tree document")
}

/// A byte string read out of a frame.
mod serde_bytes_like {
    pub struct Bytes(pub Vec<u8>);
    impl<'de> serde::Deserialize<'de> for Bytes {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct V;
            impl serde::de::Visitor<'_> for V {
                type Value = Bytes;
                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("bytes")
                }
                fn visit_bytes<E>(self, v: &[u8]) -> Result<Bytes, E> {
                    Ok(Bytes(v.to_vec()))
                }
                fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Bytes, E> {
                    Ok(Bytes(v))
                }
            }
            d.deserialize_bytes(V)
        }
    }
}

fn column() -> NonEmpty<Identifier> {
    Identifier::for_column("users", "profile").unwrap()
}

/// Every document of a batch, as JSON text, seals in one key request and
/// opens to the same value: the text is not promised back byte for byte,
/// the value is.
#[tokio::test]
async fn a_batch_of_documents_round_trips_in_one_request() {
    let (cipher, calls) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let plan = plan();
    let texts: Vec<String> = documents().iter().map(Value::to_string).collect();
    let source: Vec<BTreeMap<&str, &str>> = texts
        .iter()
        .map(|text| BTreeMap::from([("profile", text.as_str())]))
        .collect();
    let sealed = record::encrypt_with(&keyset, frame(&source), &plan, &Eql)
        .unwrap()
        .await
        .unwrap();
    assert_eq!(
        calls.lock().unwrap().generate.len(),
        1,
        "every document's key in one request"
    );
    let opened = record::decrypt_with(Scope::Client(&cipher), sealed, &plan, None, &Eql)
        .unwrap()
        .await
        .unwrap();
    assert_eq!(calls.lock().unwrap().retrieve.len(), 1, "and one to open");
    let rows: Vec<BTreeMap<String, serde_bytes_like::Bytes>> =
        dynamic::frame::serde::from_slice(opened.risky_ref()).unwrap();
    let back: Vec<Value> = rows
        .iter()
        .map(|row| serde_json::from_slice(&row["profile"].0).unwrap())
        .collect();
    assert_eq!(back, documents());
}

/// The data plan and the typed layout write the same search terms for the
/// same document under the same column: every entry's selector, self and
/// parent tags' places and ordering term, and the containment projection.
/// Only the ciphertexts, the data key and the tags salted by it differ.
/// And each opens what the other sealed.
#[tokio::test]
async fn the_data_plan_and_the_typed_layout_agree() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let plan = plan();
    for document in documents() {
        let text = document.to_string();
        let source = BTreeMap::from([("profile", text.as_str())]);
        let sealed = record::encrypt_with(&keyset, frame(&source), &plan, &Eql)
            .unwrap()
            .await
            .unwrap();
        let data = stored(&sealed);
        let typed: JsonTreeDocument = keyset
            .run(
                Layout::<Value>::encryption::<common::Observed>(&JsonTree::new(options())),
                &document,
                column(),
            )
            .await
            .unwrap();
        assert_eq!(data.i, typed.i, "{text}: the column");
        assert_eq!(data.q, typed.q, "{text}: the containment projection");
        assert_eq!(data.sv.len(), typed.sv.len(), "{text}: one entry per node");
        for (a, b) in data.sv.iter().zip(&typed.sv) {
            assert_eq!(a.s, b.s, "{text}: an entry's selector");
            assert_eq!(a.op, b.op, "{text}: an entry's ordering term");
            assert_eq!(a.p.is_some(), b.p.is_some(), "{text}: a parent tag's place");
        }

        // The typed path opens the data plan's document...
        let opened: Value = cipher
            .decrypt_as::<Value, JsonTreeDocument>(data, ExpectedContext::from(column()))
            .await
            .unwrap();
        assert_eq!(opened, document);
        // ...and the data plan opens the typed path's.
        let record = CipherText::Map(vec![(
            "profile".to_owned(),
            CipherText::Map(vec![(
                "eql".to_owned(),
                CipherText::Passthrough(stack_encrypt::PassthroughFrame(
                    frame(stack_encrypt::Protected::new(
                        serde_json::to_vec(&typed).unwrap(),
                    ))
                    .risky_ref()
                    .to_vec(),
                )),
            )]),
        )]);
        let opened = record::decrypt_with(Scope::Client(&cipher), record, &plan, None, &Eql)
            .unwrap()
            .await
            .unwrap();
        let row: BTreeMap<String, serde_bytes_like::Bytes> =
            dynamic::frame::serde::from_slice(opened.risky_ref()).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&row["profile"].0).unwrap(),
            document
        );
    }
}

/// Text that is not a document is refused when the record is read, before
/// any key is requested, naming the field and what was wrong by its code.
/// A frame null is not a JSON null: under `"null": "sql"` it stores
/// nothing.
#[tokio::test]
async fn text_that_is_not_a_document_is_refused_before_any_key() {
    let (cipher, calls) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let plan = plan();
    for (text, code) in [
        (r#"{"secret": 1, "secret": 2}"#, "json_duplicate_key"),
        ("99999999999999999999", "json_integer_range"),
        (r#"{"secret": "#, "json_syntax"),
        ("", "json_syntax"),
    ] {
        let source = BTreeMap::from([("profile", text)]);
        let error = match record::encrypt_with(&keyset, frame(&source), &plan, &Eql) {
            Err(error) => error,
            Ok(_) => panic!("{text:?} was accepted"),
        };
        let shown = format!("{error} {:?}", stack_encrypt::ErrorPayload::payload(&error));
        assert!(
            matches!(&error, dynamic::Error::Target(TargetError::Json { name, reason, .. }) if name == "profile" && *reason == code),
            "{text:?}: {error:?}"
        );
        assert!(
            !shown.contains("secret") && !shown.contains("9999"),
            "{shown}"
        );
    }
    // A value of another kind is not a document either.
    let source = BTreeMap::from([("profile", 7u32)]);
    assert!(record::encrypt_with(&keyset, frame(&source), &plan, &Eql).is_err());
    assert!(
        calls.lock().unwrap().generate.is_empty(),
        "no key was requested"
    );
}

/// A document is queried by a JSON operator, which the engine derives
/// from named inputs; eql-bindings' one-plaintext query refuses it by
/// name rather than falling through its generated dispatch.
#[tokio::test]
async fn a_document_has_no_one_plaintext_query() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let label: Label = "users/profile".parse().unwrap();
    let error = eql_targets::query(
        "EncryptedJson",
        &stack_encrypt::target::IndexSpec::Json(JsonOptions::default()),
        &keyset,
        &label,
        frame("{}"),
    )
    .err()
    .expect("refused");
    assert!(
        matches!(
            error,
            eql_targets::TargetError::DocumentQuery {
                name: "EncryptedJson"
            }
        ),
        "{error}"
    );
}

/// Which targets take the JSON index's options is decided twice: the
/// engine gives them to a target whose descriptor carries the `json`
/// index, and eql-bindings seals a target of a document family with them
/// and refuses them on any other. The two must name the same producible
/// targets, or a write the engine configures is one eql-bindings refuses.
#[tokio::test]
async fn the_engine_and_the_table_agree_on_which_targets_take_json_options() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let label: Label = "users/profile".parse().unwrap();
    let options = dynamic::TargetOptions::Json(JsonOptions::default());
    for target in eql_targets::targets().iter().filter(|t| t.producible) {
        let engine = target.indexes.contains(&"json");
        let refused = matches!(
            eql_targets::encrypt_with(target.name, Some(&options), &keyset, &label, frame(true)),
            Err(eql_targets::TargetError::Options { .. })
        );
        assert_eq!(engine, !refused, "{}", target.name);
    }
}
