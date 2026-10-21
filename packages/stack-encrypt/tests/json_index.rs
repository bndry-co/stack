//! The JSON index end to end, with no database: a document seals into one
//! entry per node under one data key and opens again; the token chain
//! reaches every child from its parent's token and ordinal, and nothing
//! from any other token;
//! a moved, reordered or regrafted entry fails to open; and containment
//! over the element-nested projection agrees with PostgreSQL's `jsonb @>`
//! on the design's corpus and on random documents, through a Rust model
//! of `jsonb @>` written here from the rules PostgreSQL documents.

mod common;

use common::stack_cipher;
use serde_json::{json, Map, Value};
use stack_encrypt::json::{
    JsonDocument, JsonNode, JsonOptions, JsonPath, JsonQuery, JsonSubtree, JsonSubtreeKey,
};
use stack_encrypt::op;
use stack_encrypt::sem::TermError;
use stack_encrypt::target::{
    AeadContext, CallerContext, DecryptField, Decryption, IndexSpec, Json,
};
use stack_encrypt::{nonempty, Error, Plan, PlanError, StackCipher};
use stack_kms::FakeDataKeySource;

fn context() -> CallerContext {
    CallerContext::from(nonempty!("users").with("profile"))
}

fn aead() -> AeadContext {
    AeadContext::from(nonempty!("users").with("profile"))
}

async fn seal(cipher: &StackCipher<FakeDataKeySource>, value: &Value) -> JsonDocument {
    cipher
        .default_keyset()
        .encrypt_as::<Value, JsonDocument>(value, context())
        .await
        .expect("seals")
}

async fn seal_with(
    cipher: &StackCipher<FakeDataKeySource>,
    value: &Value,
    options: JsonOptions,
) -> JsonDocument {
    cipher
        .default_keyset()
        .run(
            stack_encrypt::target::json_document::<_, stack_encrypt::target::Borrowed>(options),
            value,
            context(),
        )
        .await
        .expect("seals")
}

async fn open(cipher: &StackCipher<FakeDataKeySource>, doc: JsonDocument) -> Result<Value, Error> {
    cipher.decrypt_as::<Value, JsonDocument>(doc, aead()).await
}

/// The design's fixture document.
fn fixture() -> Value {
    json!({"hello": "world-1", "nested": {"deep": "constant", "list": [{"x": 1}, {"x": 2}]}, "number": 1})
}

/// How many nodes a value has.
fn nodes(value: &Value) -> usize {
    1 + match value {
        Value::Object(map) => map.values().map(nodes).sum(),
        Value::Array(items) => items.iter().map(nodes).sum(),
        _ => 0,
    }
}

// =============================================================================
// Round trips
// =============================================================================

#[tokio::test]
async fn a_document_seals_one_entry_per_node_and_opens_again() {
    let cipher = stack_cipher().await;
    for value in [
        fixture(),
        json!({}),
        json!([]),
        json!("a"),
        json!(2.5),
        json!(null),
        json!(true),
        json!([[1, 2], [3, [4, {"a": null}]]]),
        json!({"a": {"b": {"c": {"d": [1, "x", false]}}}}),
        json!({"a": "b", "a b": 1, "é": [], "0": {}}),
        json!({"n": 18446744073709551615u64, "m": -9223372036854775808i64, "f": 1e300}),
    ] {
        for options in [JsonOptions::default(), JsonOptions { sealed_root: false }] {
            let doc = seal_with(&cipher, &value, options).await;
            assert_eq!(
                doc.entries().len(),
                nodes(&value),
                "{value}: one entry per node"
            );
            assert_eq!(doc.header().sealed_root(), options.sealed_root);
            let back = open(&cipher, doc).await.unwrap();
            assert_eq!(back, value, "{value} under {options:?}");
        }
    }
}

#[tokio::test]
async fn the_wire_form_is_what_the_sql_domain_stores() {
    let cipher = stack_cipher().await;
    let doc = seal(&cipher, &fixture()).await;
    let wire = serde_json::to_value(&doc).unwrap();
    let keys: Vec<&str> = wire
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys, ["h", "q", "sv"]);
    // `q` is the document's own projection, written once: the needle a
    // `Contains` of the whole document derives has the same pairs in the
    // same groups, and nothing else.
    let needle = cipher
        .query(op::Contains, &fixture())
        .on(&plan())
        .await
        .unwrap();
    assert_eq!(wire["q"], serde_json::to_value(&needle).unwrap());
    assert!(
        serde_json::from_value::<JsonDocument>(json!({"h": wire["h"], "sv": wire["sv"]})).is_err(),
        "a document without `q` is not a document: the projection is the only place the value selectors live"
    );
    let back: JsonDocument = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(
        serde_json::to_value(&back).unwrap(),
        wire,
        "`q` round-trips as stored"
    );
    assert_eq!(
        serde_json::to_value(back.projection()).unwrap(),
        wire["q"],
        "the projection read back is the stored one"
    );
    for (j, entry) in wire["sv"].as_array().unwrap().iter().enumerate() {
        let entry = entry.as_object().unwrap();
        for key in entry.keys() {
            assert!(
                ["s", "c", "p", "op"].contains(&key.as_str()),
                "entry {j} carries an unknown key {key}"
            );
        }
        for tag in ["s", "p"] {
            if let Some(hex) = entry.get(tag) {
                assert_eq!(
                    hex.as_str().unwrap().len(),
                    32,
                    "entry {j}'s {tag} is 16 bytes of hex"
                );
            }
        }
    }
    let back: JsonDocument = serde_json::from_value(wire).unwrap();
    assert_eq!(back, doc);
}

#[tokio::test]
async fn the_chain_fields_sit_where_the_design_says() {
    let cipher = stack_cipher().await;
    let doc = seal(&cipher, &fixture()).await;
    let entries = doc.entries();
    // $, $.hello, $.nested, $.nested.deep, $.nested.list, [0], [0].x, [1], [1].x, $.number
    assert_eq!(entries.len(), 10);
    let root = &entries[0];
    assert!(root.parent_tag().is_none());
    for head in [&entries[1], &entries[2], &entries[9]] {
        assert!(
            head.parent_tag().is_none(),
            "a head has no parent tag under the sealed root"
        );
    }
    for below in &entries[3..9] {
        assert!(below.parent_tag().is_some());
    }
    // Every parent tag is distinct: siblings are not linkable at rest.
    let tags: std::collections::HashSet<_> = entries[3..9]
        .iter()
        .map(|e| *e.parent_tag().unwrap())
        .collect();
    assert_eq!(tags.len(), 6);
    // The projection groups the two list elements: each is a nested group
    // holding its own pair and its `x`.
    let q = serde_json::to_value(doc.projection()).unwrap();
    assert_eq!(q["el"].as_array().unwrap().len(), 2);
    assert_eq!(q["el"][0]["sv"].as_array().unwrap().len(), 2);
    assert_eq!(
        q["sv"].as_array().unwrap().len(),
        6,
        "$, hello, nested, deep, list, number"
    );
    // Ordering terms on the string and number leaves only.
    assert!(entries[1].ordering_term().is_some() && entries[9].ordering_term().is_some());
    assert!(entries[2].ordering_term().is_none() && entries[4].ordering_term().is_none());
    // Equal values at one path share selectors but not ciphertexts; the
    // value selectors, in the projection, tell equal values from different.
    let pair = |doc: &JsonDocument, i: usize| -> (String, String) {
        let q = serde_json::to_value(doc.projection()).unwrap();
        (
            q["sv"][i]["s"].as_str().unwrap().to_owned(),
            q["sv"][i]["vs"].as_str().unwrap().to_owned(),
        )
    };
    let doc2 = seal(&cipher, &json!([1, 1])).await;
    let (a, b) = (&doc2.entries()[1], &doc2.entries()[2]);
    assert_eq!(a.selector(), b.selector());
    assert_eq!(pair(&doc2, 1), pair(&doc2, 2));
    assert_ne!(a.ciphertext(), b.ciphertext());
    let doc3 = seal(&cipher, &json!([1, 2])).await;
    let (one, two) = (&doc3.entries()[1], &doc3.entries()[2]);
    assert_eq!(one.selector(), two.selector(), "one path");
    assert_ne!(
        pair(&doc3, 1),
        pair(&doc3, 2),
        "different values at one path have different value selectors"
    );
    assert_eq!(
        pair(&doc3, 1),
        pair(&doc2, 1),
        "the value selector names the value at its path, in any document"
    );

    // Without the sealed root, the top-level fields chain from the root.
    let open_doc = seal_with(&cipher, &fixture(), JsonOptions { sealed_root: false }).await;
    assert!(open_doc.entries()[1].parent_tag().is_some());
}

// =============================================================================
// The token chain
// =============================================================================

async fn subtree_key(
    cipher: &StackCipher<FakeDataKeySource>,
    path: &str,
    options: JsonOptions,
) -> Result<JsonSubtreeKey, Error> {
    cipher
        .default_keyset()
        .json_subtree_key(
            &JsonPath::parse(path).unwrap(),
            options,
            nonempty!("users").with("profile"),
        )
        .await
}

#[tokio::test]
async fn a_token_derived_from_the_path_alone_unlocks_exactly_its_subtree() {
    let cipher = stack_cipher().await;
    let doc = seal(&cipher, &fixture()).await;
    let key = subtree_key(&cipher, "$.nested", JsonOptions::default())
        .await
        .unwrap();
    assert!(
        key.gates().is_empty(),
        "a chain head's token is derived, nothing to gate"
    );
    let under = doc.subtree(key.token_bytes());
    let found: Vec<usize> = under.iter().map(|(j, _, _)| *j).collect();
    assert_eq!(
        found,
        [3, 4, 5, 6, 7, 8],
        "deep, list, both elements, both leaves"
    );
    let depths: Vec<u32> = under.iter().map(|(_, _, d)| *d).collect();
    assert_eq!(depths, [1, 1, 2, 3, 2, 3]);

    let garbage = doc.subtree(&[7; 16]);
    assert!(garbage.is_empty(), "a wrong token unlocks nothing");

    // Below a head the client derives nothing but array positions: a key
    // step becomes a gate, and the walk from the head takes it.
    let deeper = subtree_key(&cipher, "$.nested.list[1]", JsonOptions::default())
        .await
        .unwrap();
    assert_eq!(
        deeper.token_bytes(),
        key.token_bytes(),
        "anchored at the head"
    );
    assert_eq!(deeper.gates().len(), 2, "list, then [1]");
    assert_eq!(deeper.gates()[1], "#1");
    let list_token = doc
        .children(key.token_bytes())
        .into_iter()
        .find(|(j, _, _)| *j == 4)
        .map(|(_, _, t)| t)
        .expect("the list is a child of nested");
    let second = doc
        .children(&list_token)
        .into_iter()
        .find(|(j, _, _)| *j == 7)
        .map(|(_, _, t)| t)
        .expect("the second element");
    let found: Vec<usize> = doc.subtree(&second).iter().map(|(j, _, _)| *j).collect();
    assert_eq!(found, [8], "the second element's x");

    // The children of a node, by ordinal: the list's two elements.
    let children: Vec<usize> = doc
        .children(&list_token)
        .iter()
        .map(|(j, _, _)| *j)
        .collect();
    assert_eq!(children, [5, 7]);
    // An array element's token is derivable from the path once the array
    // itself is reached by token: under an open root every node is.

    // The sealed root has no token; the open root's unlocks every node.
    assert!(matches!(
        subtree_key(&cipher, "$", JsonOptions::default()).await,
        Err(Error::Term(TermError::JsonSealedRoot))
    ));
    assert!(matches!(
        subtree_key(&cipher, "$[*].x", JsonOptions::default()).await,
        Err(Error::Term(TermError::JsonSealedRoot))
    ));
    let open_doc = seal_with(&cipher, &fixture(), JsonOptions { sealed_root: false }).await;
    let root = subtree_key(&cipher, "$", JsonOptions { sealed_root: false })
        .await
        .unwrap();
    assert_eq!(
        open_doc.subtree(root.token_bytes()).len(),
        9,
        "every entry but the root"
    );

    // A wildcard path anchors at the head and gates on each step's
    // selector: the list's, then every element's (the wildcard's), then x's.
    let gated = subtree_key(&cipher, "$.nested.list[*].x", JsonOptions::default())
        .await
        .unwrap();
    assert_eq!(gated.token_bytes(), key.token_bytes());
    assert_eq!(
        gated.gates(),
        [
            hex(doc.entries()[4].selector()),
            hex(doc.entries()[5].selector()),
            hex(doc.entries()[6].selector()),
        ]
    );
    // Under an open root the whole chain is derivable down to the first
    // key step: `$[0]` would be a position, `$.nested` is a gate.
    let open_key = subtree_key(
        &cipher,
        "$.nested.list[1]",
        JsonOptions { sealed_root: false },
    )
    .await
    .unwrap();
    assert_eq!(open_key.token_bytes(), root.token_bytes());
    assert_eq!(open_key.gates().len(), 3);
    let array_doc = seal_with(
        &cipher,
        &json!([[1, 2], [3]]),
        JsonOptions { sealed_root: false },
    )
    .await;
    let second_row = subtree_key(&cipher, "$[1]", JsonOptions { sealed_root: false })
        .await
        .unwrap();
    assert!(second_row.gates().is_empty(), "positions derive");
    let found: Vec<usize> = array_doc
        .subtree(second_row.token_bytes())
        .iter()
        .map(|(j, _, _)| *j)
        .collect();
    assert_eq!(found, [5], "$, [0], [0][0], [0][1], [1], [1][0]");
}

#[tokio::test]
async fn a_selector_is_the_stored_one_and_folds_positions_into_the_wildcard() {
    let cipher = stack_cipher().await;
    let doc = seal(&cipher, &fixture()).await;
    let keyset = cipher.default_keyset();
    let selector = |path: &str| {
        let path = JsonPath::parse(path).unwrap();
        keyset.json_selector(&path, nonempty!("users").with("profile"))
    };
    assert_eq!(
        selector("$.nested.deep").await.unwrap().as_bytes(),
        doc.entries()[3].selector()
    );
    assert_eq!(
        selector("$.nested.list[*].x").await.unwrap().as_bytes(),
        doc.entries()[6].selector()
    );
    assert_eq!(
        selector("$.nested.list[1].x").await.unwrap().as_bytes(),
        doc.entries()[8].selector()
    );
    assert_eq!(
        selector("$").await.unwrap().as_bytes(),
        doc.entries()[0].selector()
    );
    assert_ne!(
        selector("$.hello").await.unwrap().as_bytes(),
        keyset
            .json_selector(
                &JsonPath::parse("$.hello").unwrap(),
                nonempty!("users").with("bio")
            )
            .await
            .unwrap()
            .as_bytes(),
        "a selector is bound to its column"
    );
}

// =============================================================================
// Extraction
// =============================================================================

#[tokio::test]
async fn an_extracted_node_opens_to_its_scalar_and_a_subtree_to_its_value() {
    let cipher = stack_cipher().await;
    let doc = seal(&cipher, &fixture()).await;
    let node = |j: usize| doc.node(j).unwrap();
    let scalar = |j: usize| cipher.decrypt_as::<Value, JsonNode>(node(j), aead());
    assert_eq!(scalar(1).await.unwrap(), json!("world-1"));
    assert_eq!(scalar(6).await.unwrap(), json!(1));
    assert_eq!(
        scalar(0).await.unwrap(),
        fixture(),
        "the sealed root is the document"
    );
    assert!(
        matches!(scalar(2).await, Err(Error::OpenedType { .. })),
        "a container node holds no value of its own"
    );

    let key = subtree_key(&cipher, "$.nested", JsonOptions::default())
        .await
        .unwrap();
    let rows: Vec<JsonNode> = doc
        .subtree(key.token_bytes())
        .iter()
        .map(|(j, _, _)| node(*j))
        .collect();
    let nested = cipher
        .decrypt_as::<Value, JsonSubtree>(JsonSubtree::new(rows.clone()), aead())
        .await
        .unwrap();
    assert_eq!(nested, fixture()["nested"]);
    let forest = cipher
        .decrypt_as::<Vec<Value>, JsonSubtree>(JsonSubtree::new(rows), aead())
        .await
        .unwrap();
    assert_eq!(forest, vec![json!("constant"), json!([{"x": 1}, {"x": 2}])]);

    // The list's token is the server's to derive, one level under nested.
    let list = doc
        .children(key.token_bytes())
        .into_iter()
        .find(|(j, _, _)| *j == 4)
        .map(|(_, _, t)| t)
        .unwrap();
    let rows: Vec<JsonNode> = doc
        .subtree(&list)
        .iter()
        .map(|(j, _, _)| node(*j))
        .collect();
    let elements = cipher
        .decrypt_as::<Value, JsonSubtree>(JsonSubtree::new(rows), aead())
        .await
        .unwrap();
    assert_eq!(elements, json!([{"x": 1}, {"x": 2}]));

    // An extracted node round-trips through its wire form with the
    // envelope fields the SQL grafts beside it.
    let mut wire = serde_json::to_value(node(6)).unwrap();
    wire["i"] = json!({"t": "users", "c": "profile"});
    wire["v"] = json!(4);
    let back: JsonNode = serde_json::from_value(wire).unwrap();
    assert_eq!(back.ordinal(), 6);
    assert_eq!(
        cipher
            .decrypt_as::<Value, JsonNode>(back, aead())
            .await
            .unwrap(),
        json!(1)
    );
}

// =============================================================================
// Tamper evidence
// =============================================================================

#[tokio::test]
async fn a_moved_reordered_or_regrafted_entry_fails_to_open() {
    let cipher = stack_cipher().await;
    let value = json!({"a": "x", "b": "y"});
    let doc = seal_with(&cipher, &value, JsonOptions { sealed_root: false }).await;
    let other = seal_with(&cipher, &value, JsonOptions { sealed_root: false }).await;
    let tamper = |mut wire: Value, f: &dyn Fn(&mut Vec<Value>)| {
        let sv = wire["sv"].as_array_mut().unwrap();
        f(sv);
        serde_json::from_value::<JsonDocument>(wire).unwrap()
    };
    let wire = serde_json::to_value(&doc).unwrap();
    let other_wire = serde_json::to_value(&other).unwrap();

    let reordered = tamper(wire.clone(), &|sv| sv.swap(1, 2));
    assert!(
        matches!(open(&cipher, reordered).await, Err(Error::Aead)),
        "reordered"
    );

    let regrafted = tamper(wire.clone(), &|sv| sv[1] = other_wire["sv"][1].clone());
    assert!(
        matches!(open(&cipher, regrafted).await, Err(Error::Aead)),
        "regrafted from another document"
    );

    let truncated = tamper(wire.clone(), &|sv| {
        let _ = sv.pop();
    });
    assert!(
        matches!(
            open(&cipher, truncated).await,
            Err(Error::OpenedType { .. })
        ),
        "truncated"
    );

    let flipped = tamper(wire.clone(), &|sv| {
        let c = sv[1]["c"].as_str().unwrap().to_owned();
        let mut bytes = c.into_bytes();
        bytes[3] = if bytes[3] == b'A' { b'B' } else { b'A' };
        sv[1]["c"] = Value::String(String::from_utf8(bytes).unwrap());
    });
    assert!(
        matches!(open(&cipher, flipped).await, Err(Error::Aead)),
        "a changed byte"
    );

    let wrong_context = cipher
        .decrypt_as::<Value, JsonDocument>(doc, AeadContext::from(nonempty!("users").with("bio")))
        .await;
    assert!(matches!(wrong_context, Err(Error::Aead)), "another column");

    // A node lifted out of its document fails under another ordinal.
    let sealed = seal(&cipher, &value).await;
    let mut lifted = serde_json::to_value(sealed.node(1).unwrap()).unwrap();
    lifted["j"] = json!(2);
    let lifted: JsonNode = serde_json::from_value(lifted).unwrap();
    assert!(matches!(
        cipher.decrypt_as::<Value, JsonNode>(lifted, aead()).await,
        Err(Error::Aead)
    ));
}

// =============================================================================
// Queries
// =============================================================================

type JsonPlan = stack_encrypt::plan::ValuePlan<Value, stack_encrypt::plan::Typed<JsonDocument>>;

fn plan() -> JsonPlan {
    Plan::value::<Value>()
        .context("users/profile")
        .encrypt_into::<JsonDocument>()
        .build()
        .unwrap()
}

/// PostgreSQL's `jsonb @>`, from its documented rules: an object contains
/// another when it has every key with a containing value; an array
/// contains another when every needle element is contained by some stored
/// element; a top-level array contains a scalar that is one of its
/// elements; scalars contain equal scalars, numbers by value.
fn pg_contains(stored: &Value, needle: &Value, top: bool) -> bool {
    match (stored, needle) {
        (Value::Object(a), Value::Object(b)) => b
            .iter()
            .all(|(k, vb)| a.get(k).is_some_and(|va| pg_contains(va, vb, false))),
        (Value::Array(a), Value::Array(b)) => b
            .iter()
            .all(|vb| a.iter().any(|va| pg_contains(va, vb, false))),
        (Value::Array(a), scalar) if top && !scalar.is_object() && !scalar.is_array() => {
            a.iter().any(|va| pg_contains(va, scalar, false))
        }
        (Value::Number(a), Value::Number(b)) => a.as_f64() == b.as_f64(),
        (Value::Object(_) | Value::Array(_), _) | (_, Value::Object(_) | Value::Array(_)) => false,
        (a, b) => a == b,
    }
}

/// The design's two corpora: `jsonb-semantics.sql` and
/// `containment-oracle.sql`, as `(stored, needle)` pairs.
fn corpus() -> Vec<(Value, Value)> {
    [
        (r#"["a"]"#, r#""a""#),
        (r#""a""#, r#"["a"]"#),
        (r#"{"a":[1]}"#, r#"{"a":1}"#),
        (r#"{"a":1}"#, r#"{"a":[1]}"#),
        (r#"[1,[2]]"#, r#"[2]"#),
        (r#"[1,[2]]"#, r#"[[2]]"#),
        (r#"{"a":{"b":1}}"#, r#"{"a":{}}"#),
        (r#"{"a":{}}"#, r#"{"a":{"b":1}}"#),
        (r#"{"a":[1,2]}"#, r#"{"a":[]}"#),
        (r#"{"a":1}"#, r#"{}"#),
        (r#"[1]"#, r#"{}"#),
        (r#"[1]"#, r#"[]"#),
        (r#"[1,2]"#, r#"[1,1,1]"#),
        (
            r#"{"a":[{"x":1,"y":5},{"x":7,"y":2}]}"#,
            r#"{"a":[{"x":1,"y":2}]}"#,
        ),
        (r#"{"a":[{"x":1,"y":2,"z":3}]}"#, r#"{"a":[{"x":1,"y":2}]}"#),
        (r#"{"a":[{"x":1}]}"#, r#"{"a":[{"x":1},{"x":1}]}"#),
        (
            r#"{"a":[{"b":[{"x":1},{"y":2}]}]}"#,
            r#"{"a":[{"b":[{"x":1,"y":2}]}]}"#,
        ),
        (
            r#"{"a":[{"b":[{"x":1,"y":2}]}]}"#,
            r#"{"a":[{"b":[{"x":1,"y":2}]}]}"#,
        ),
        (r#"{"a":[["x"]]}"#, r#"{"a":["x"]}"#),
        (r#""a""#, r#""a""#),
        (r#"2"#, r#"2.0"#),
        (r#"{"a":null}"#, r#"{"a":null}"#),
        (r#"[["a"]]"#, r#""a""#),
        (
            r#"{"a":[{"b":[{"x":1,"y":2}],"c":3},{"b":[{"x":1,"y":9}],"c":4}]}"#,
            r#"{"a":[{"b":[{"x":1,"y":2}],"c":4}]}"#,
        ),
        (
            r#"{"a":[{"b":[{"x":1,"y":2}],"c":3},{"b":[{"x":1,"y":9}],"c":4}]}"#,
            r#"{"a":[{"b":[{"x":1,"y":2}],"c":3}]}"#,
        ),
        (
            r#"{"a":[{"b":{"c":1,"d":2}},{"b":{"c":3,"d":2}}]}"#,
            r#"{"a":[{"b":{"c":1,"d":2}}]}"#,
        ),
        (
            r#"{"a":[{"b":{"c":1,"d":5}},{"b":{"c":3,"d":2}}]}"#,
            r#"{"a":[{"b":{"c":1,"d":2}}]}"#,
        ),
        (r#"{"a":[[1,2],[3,4]]}"#, r#"{"a":[[1,4]]}"#),
        (r#"{"a":[[1,2],[3,4]]}"#, r#"{"a":[[1,2]]}"#),
        (r#"{"a":[[1,2],[3,4]]}"#, r#"{"a":[[1],[4]]}"#),
        (r#"{"a":"2"}"#, r#"{"a":2}"#),
        (r#"{"a":2}"#, r#"{"a":2.0}"#),
        (r#"{"a":[{"x":1}]}"#, r#"{"a":[{}]}"#),
        (r#"{"a":[1]}"#, r#"{"a":[{}]}"#),
        (
            r#"{"a":[{"t":[{"u":1,"v":2}]},{"t":[{"u":1},{"v":2}]}]}"#,
            r#"{"a":[{"t":[{"u":1,"v":2}]}]}"#,
        ),
        (
            r#"{"a":[{"t":[{"u":1},{"v":2}]}]}"#,
            r#"{"a":[{"t":[{"u":1,"v":2}]}]}"#,
        ),
        (r#"{"a":[{}]}"#, r#"{"a":[{}]}"#),
        (r#"{"a":[[]]}"#, r#"{"a":[[]]}"#),
        (r#"{"a":[[]]}"#, r#"{"a":[{}]}"#),
        (r#"[{"a":1},{"b":2}]"#, r#"[{"a":1,"b":2}]"#),
        (r#"[{"a":1,"b":2}]"#, r#"[{"a":1},{"b":2}]"#),
        (r#"{"a":[true,false,null]}"#, r#"{"a":[null,true]}"#),
        (r#"{"a":[true]}"#, r#"{"a":[false]}"#),
        (r#"{"a":[{"x":[1,2]},{"x":[3]}]}"#, r#"{"a":[{"x":[2,3]}]}"#),
        (r#"{"a":[{"x":[1,2]},{"x":[3]}]}"#, r#"{"a":[{"x":[1,2]}]}"#),
    ]
    .iter()
    .map(|(a, b)| {
        (
            serde_json::from_str(a).unwrap(),
            serde_json::from_str(b).unwrap(),
        )
    })
    .collect()
}

/// The pinned answers of `jsonb-semantics.sql`, so the model above is held
/// to PostgreSQL and not only to itself.
#[test]
fn the_containment_model_gives_postgresqls_answers() {
    let expect = [
        (r#"["a"]"#, r#""a""#, true),
        (r#""a""#, r#"["a"]"#, false),
        (r#"{"a":[1]}"#, r#"{"a":1}"#, false),
        (r#"{"a":1}"#, r#"{"a":[1]}"#, false),
        (r#"[1,[2]]"#, r#"[2]"#, false),
        (r#"[1,[2]]"#, r#"[[2]]"#, true),
        (r#"{"a":{"b":1}}"#, r#"{"a":{}}"#, true),
        (r#"{"a":{}}"#, r#"{"a":{"b":1}}"#, false),
        (r#"{"a":[1,2]}"#, r#"{"a":[]}"#, true),
        (r#"{"a":1}"#, r#"{}"#, true),
        (r#"[1]"#, r#"{}"#, false),
        (r#"[1]"#, r#"[]"#, true),
        (r#"[1,2]"#, r#"[1,1,1]"#, true),
        (
            r#"{"a":[{"x":1,"y":5},{"x":7,"y":2}]}"#,
            r#"{"a":[{"x":1,"y":2}]}"#,
            false,
        ),
        (
            r#"{"a":[{"x":1,"y":2,"z":3}]}"#,
            r#"{"a":[{"x":1,"y":2}]}"#,
            true,
        ),
        (r#"{"a":[{"x":1}]}"#, r#"{"a":[{"x":1},{"x":1}]}"#, true),
        (
            r#"{"a":[{"b":[{"x":1},{"y":2}]}]}"#,
            r#"{"a":[{"b":[{"x":1,"y":2}]}]}"#,
            false,
        ),
        (
            r#"{"a":[{"b":[{"x":1,"y":2}]}]}"#,
            r#"{"a":[{"b":[{"x":1,"y":2}]}]}"#,
            true,
        ),
        (r#"{"a":[["x"]]}"#, r#"{"a":["x"]}"#, false),
        (r#""a""#, r#""a""#, true),
        (r#"2"#, r#"2.0"#, true),
        (r#"{"a":null}"#, r#"{"a":null}"#, true),
        (r#"[["a"]]"#, r#""a""#, false),
    ];
    for (stored, needle, answer) in expect {
        let (a, b): (Value, Value) = (
            serde_json::from_str(stored).unwrap(),
            serde_json::from_str(needle).unwrap(),
        );
        assert_eq!(pg_contains(&a, &b, true), answer, "{stored} @> {needle}");
    }
}

/// A small deterministic generator of documents over a few keys and
/// values, so needles drawn from it overlap stored documents often.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn value(&mut self, depth: u32) -> Value {
        match self.below(if depth == 0 { 4 } else { 6 }) {
            0 => json!(self.below(3)),
            1 => json!(["x", "y", "z"][self.below(3) as usize]),
            2 => json!(self.below(2) == 0),
            3 => Value::Null,
            4 => Value::Array((0..self.below(4)).map(|_| self.value(depth - 1)).collect()),
            _ => {
                let mut map = Map::new();
                for _ in 0..self.below(4) {
                    let key = ["a", "b", "c"][self.below(3) as usize].to_owned();
                    let _ = map.insert(key, self.value(depth - 1));
                }
                Value::Object(map)
            }
        }
    }
}

#[tokio::test]
async fn containment_over_the_projection_is_postgresqls_containment() {
    let cipher = stack_cipher().await;
    let plan = plan();
    let mut cases = corpus();
    let mut rng = Lcg(42);
    for _ in 0..150 {
        let stored = rng.value(3);
        let needle = rng.value(2);
        cases.push((stored.clone(), needle));
        // A needle taken from the stored document itself is always contained.
        cases.push((stored.clone(), stored));
    }
    for (stored, needle) in cases {
        let doc = cipher.encrypt(&stored).using(&plan).await.unwrap();
        let projection = doc.projection();
        let query: JsonQuery = cipher.query(op::Contains, &needle).on(&plan).await.unwrap();
        assert_eq!(
            query.matches(projection),
            pg_contains(&stored, &needle, true),
            "{stored} @> {needle}"
        );
        // `<@` compares the same two projections the other way round. The
        // one case it cannot answer is a stored root scalar inside a needle
        // root array: a stored document carries no alternative pair, so the
        // SQL answers false where `jsonb` answers true, as the design's
        // leakage table records for v3's `@>`.
        let reverse: JsonQuery = cipher
            .query(op::ContainedBy, &needle)
            .on(&plan)
            .await
            .unwrap();
        let scalar_in_array = !stored.is_object() && !stored.is_array() && needle.is_array();
        assert_eq!(
            reverse.projection().contains(projection),
            pg_contains(&needle, &stored, true) && !scalar_in_array,
            "{stored} <@ {needle}"
        );
    }
}

#[tokio::test]
async fn a_query_term_serializes_as_the_needle_operand_and_derives_no_key() {
    let (cipher, generates, _) = common::counting_cipher().await;
    let plan = plan();
    let query = cipher
        .query(op::Contains, &json!({"a": [{"x": 1}]}))
        .on(&plan)
        .await
        .unwrap();
    let wire = serde_json::to_value(&query).unwrap();
    assert_eq!(
        wire["sv"].as_array().unwrap().len(),
        2,
        "$ and $.a sit outside the element"
    );
    assert_eq!(wire["el"].as_array().unwrap().len(), 1);
    assert_eq!(
        wire["el"][0]["sv"].as_array().unwrap().len(),
        2,
        "the element and its x"
    );
    assert!(wire.get("alt").is_none());
    assert_eq!(
        generates.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "a query mints no key"
    );

    let scalar = cipher
        .query(op::Contains, &json!("a"))
        .on(&plan)
        .await
        .unwrap();
    let wire = serde_json::to_value(&scalar).unwrap();
    assert!(
        wire.get("alt").is_some(),
        "a root scalar carries its root-array alternative"
    );
}

#[tokio::test]
async fn an_accessor_asks_at_a_path() {
    let cipher = stack_cipher().await;
    let plan = plan();
    let doc = cipher.encrypt(&fixture()).using(&plan).await.unwrap();
    let projection = doc.projection();

    let hit: JsonQuery = cipher
        .query(op::AtPath(op::Eq), &("$.nested.list[*].x", 2))
        .on(&plan)
        .await
        .unwrap();
    assert!(hit.matches(projection));
    let miss: JsonQuery = cipher
        .query(op::AtPath(op::Eq), &("$.nested.list[*].x", 3))
        .on(&plan)
        .await
        .unwrap();
    assert!(!miss.matches(projection));
    let deep: JsonQuery = cipher
        .query(op::AtPath(op::Eq), &("$.nested.deep", "constant"))
        .on(&plan)
        .await
        .unwrap();
    assert!(deep.matches(projection));
    let wrong_kind: JsonQuery = cipher
        .query(op::AtPath(op::Eq), &("$.number", "1"))
        .on(&plan)
        .await
        .unwrap();
    assert!(
        !wrong_kind.matches(projection),
        "a string is not the number"
    );

    // An ordering at a path: the path's selector and a leaf term that
    // orders as the stored leaf's does, under native byte comparison.
    let bound = cipher
        .query(op::AtPath(op::Gte), &("$.number", 0))
        .on(&plan)
        .await
        .unwrap();
    assert_eq!(bound.selector().as_bytes(), doc.entries()[9].selector());
    assert!(
        bound.ordering_term() < doc.entries()[9].ordering_term().unwrap(),
        "0 < 1"
    );
    let above = cipher
        .query(op::AtPath(op::Lt), &("$.number", 5))
        .on(&plan)
        .await
        .unwrap();
    assert!(
        above.ordering_term() > doc.entries()[9].ordering_term().unwrap(),
        "5 > 1"
    );
    let text = cipher
        .query(op::AtPath(op::Gt), &("$.hello", "world-0"))
        .on(&plan)
        .await
        .unwrap();
    assert!(text.ordering_term() < doc.entries()[1].ordering_term().unwrap());
    let range = cipher
        .query(op::AtPath(op::Between), &("$.number", (0, 5)))
        .on(&plan)
        .await
        .unwrap();
    assert!(range.lo().ordering_term() < range.hi().ordering_term());
    assert_eq!(
        range.lo().selector().as_bytes(),
        doc.entries()[9].selector()
    );
    let wire = serde_json::to_value(range.lo()).unwrap();
    assert_eq!(
        wire.as_object().unwrap().keys().collect::<Vec<_>>(),
        ["op", "s"]
    );

    // Refusals, before any term is derived.
    let bad_path = cipher
        .query(op::AtPath(op::Eq), &("address.city", "Sydney"))
        .on(&plan)
        .await;
    assert!(matches!(bad_path, Err(Error::Term(TermError::JsonPath(_)))));
    let unordered = cipher
        .query(op::AtPath(op::Gte), &("$.flag", true))
        .on(&plan)
        .await;
    assert!(matches!(
        unordered,
        Err(Error::Term(TermError::JsonLeafNotOrdered))
    ));
}

#[tokio::test]
async fn a_query_under_other_options_is_refused_by_the_plan() {
    let cipher = stack_cipher().await;
    let plan = plan();
    let refused = cipher
        .query(op::Contains, &json!({}))
        .via(Json::new(JsonOptions { sealed_root: false }))
        .on(&plan)
        .await;
    assert!(
        matches!(refused, Err(Error::Plan(PlanError::IndexOptions { .. }))),
        "{refused:?}"
    );
    assert_eq!(
        <JsonDocument as stack_encrypt::EncryptFrom<Value>>::indexes(),
        [IndexSpec::Json(JsonOptions::default())]
    );
    assert_eq!(Json, Json::default(), "the value is the default index");
}

#[tokio::test]
async fn opening_through_the_plan_is_the_typed_open() {
    let cipher = stack_cipher().await;
    let plan = plan();
    let doc = cipher.encrypt(&fixture()).using(&plan).await.unwrap();
    let back: Value = cipher.open(doc).using(&plan).await.unwrap();
    assert_eq!(back, fixture());
}

#[cfg(feature = "dynamic")]
#[test]
fn the_json_index_has_a_wire_form() {
    use stack_encrypt::dynamic::{not_admitted, Reason, ValueKind};
    assert_eq!(
        IndexSpec::parse("json"),
        Some(IndexSpec::Json(JsonOptions::default()))
    );
    assert_eq!(IndexSpec::Json(JsonOptions::default()).key(), "json");
    assert_eq!(
        serde_json::to_value(IndexSpec::Json(JsonOptions::default())).unwrap(),
        json!("json")
    );
    assert_eq!(
        serde_json::to_value(IndexSpec::Json(JsonOptions { sealed_root: false })).unwrap(),
        json!({"json": {"sealed_root": false}})
    );
    let frame =
        vitaminc_aead_frame::serde::to_vec(&json!({"json": {"sealed_root": false}})).unwrap();
    assert_eq!(
        IndexSpec::from_frame(&frame).unwrap(),
        IndexSpec::Json(JsonOptions { sealed_root: false })
    );
    let frame = vitaminc_aead_frame::serde::to_vec(&json!({"json": {"nope": true}})).unwrap();
    assert!(IndexSpec::from_frame(&frame).is_err());
    assert_eq!(
        not_admitted(ValueKind::Object, &IndexSpec::Json(JsonOptions::default())),
        Some(Reason::JsonIndexPending)
    );
}

// =============================================================================
// What the suite pins beyond the round trips
// =============================================================================

/// No token is stored: an entry below a head carries only the parent tag,
/// and no tag in the document is a token, or a parent's hash of one
/// without the document's salt.
#[tokio::test]
async fn no_stored_tag_is_a_token() {
    let cipher = stack_cipher().await;
    let doc = seal(&cipher, &fixture()).await;
    let nested = subtree_key(&cipher, "$.nested", JsonOptions::default())
        .await
        .unwrap();
    let mut tokens = vec![*nested.token_bytes()];
    let mut frontier = vec![*nested.token_bytes()];
    while let Some(token) = frontier.pop() {
        assert!(
            tokens.len() <= doc.entries().len(),
            "the chain is a tree: no token is reached twice"
        );
        for (_, _, child) in doc.children(&token) {
            tokens.push(child);
            frontier.push(child);
        }
    }
    assert_eq!(tokens.len(), 7, "nested and its six descendants");
    for entry in doc.entries() {
        if let Some(p) = entry.parent_tag() {
            assert!(!tokens.contains(p), "a parent tag is not a token");
        }
        assert!(!tokens.contains(entry.selector()));
    }
    assert_eq!(nested.token(), hex(nested.token_bytes()));
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A document, an extracted node and a walked subtree are each the one
/// recoverable field of a derived record: each opens through
/// `DecryptField`, as a record holding one would.
/// The rows of a gated walk carry the node the gates reached at depth 0
/// and its descendants beneath. Opened as a value, they are that node's
/// value; two reached nodes open as a list, or refuse to be one value.
#[tokio::test]
async fn gated_walk_rows_open_to_the_reached_nodes_value() {
    let cipher = stack_cipher().await;
    let doc = seal(&cipher, &fixture()).await;
    let nested = subtree_key(&cipher, "$.nested", JsonOptions::default())
        .await
        .unwrap();
    let list = doc
        .children(nested.token_bytes())
        .into_iter()
        .find(|(j, _, _)| *j == 4)
        .map(|(_, _, t)| t)
        .unwrap();
    // What `json_tree_subtree_at(doc, t(nested), [s(list), #1])` returns:
    // the second element at d = 0, its x at d = 1.
    let rows_at = |reached: &[usize], below: &[(usize, u32)]| -> Vec<JsonNode> {
        reached
            .iter()
            .map(|j| (*j, 0u32))
            .chain(below.iter().copied())
            .map(|(j, d)| {
                let mut wire = serde_json::to_value(doc.node(j).unwrap()).unwrap();
                wire["d"] = json!(d);
                serde_json::from_value(wire).unwrap()
            })
            .collect()
    };
    let second = JsonSubtree::new(rows_at(&[7], &[(8, 1)]));
    assert!(
        !second.is_sealed_root(),
        "a reached node is not the fallback"
    );
    let value = cipher
        .decrypt_as::<Value, JsonSubtree>(second.clone(), aead())
        .await
        .unwrap();
    assert_eq!(value, json!({"x": 2}), "the reached node's own value");
    let values = cipher
        .decrypt_as::<Vec<Value>, JsonSubtree>(second, aead())
        .await
        .unwrap();
    assert_eq!(values, vec![json!({"x": 2})]);
    // A scalar reached by a gate opens to the scalar, where the ungated
    // walk of a scalar yields no rows and no value.
    let x = cipher
        .decrypt_as::<Value, JsonSubtree>(JsonSubtree::new(rows_at(&[8], &[])), aead())
        .await
        .unwrap();
    assert_eq!(x, json!(2));
    // Two reached nodes (a wildcard): a list, never one value.
    let both = JsonSubtree::new(rows_at(&[6, 8], &[]));
    let values = cipher
        .decrypt_as::<Vec<Value>, JsonSubtree>(both.clone(), aead())
        .await
        .unwrap();
    assert_eq!(values, vec![json!(1), json!(2)]);
    match cipher.decrypt_as::<Value, JsonSubtree>(both, aead()).await {
        Err(Error::OpenedType { expected }) => {
            assert_eq!(expected, "one node at the walked path")
        }
        other => panic!("{other:?}"),
    }
    // Without a d = 0 row the same entries are the children of one node and
    // assemble into it.
    let rows: Vec<JsonNode> = doc
        .subtree(&list)
        .iter()
        .map(|(j, _, _)| doc.node(*j).unwrap())
        .collect();
    let elements = cipher
        .decrypt_as::<Value, JsonSubtree>(JsonSubtree::new(rows), aead())
        .await
        .unwrap();
    assert_eq!(elements, json!([{"x": 1}, {"x": 2}]));
}

#[tokio::test]
async fn each_stored_form_opens_as_a_record_field() {
    let cipher = stack_cipher().await;
    let doc = seal(&cipher, &fixture()).await;
    let node = doc.node(1).unwrap();
    let key = subtree_key(&cipher, "$.nested", JsonOptions::default())
        .await
        .unwrap();
    let list = doc
        .children(key.token_bytes())
        .into_iter()
        .find(|(j, _, _)| *j == 4)
        .map(|(_, _, t)| t)
        .unwrap();
    let rows: Vec<JsonNode> = doc
        .subtree(&list)
        .iter()
        .map(|(j, _, _)| doc.node(*j).unwrap())
        .collect();
    let subtree = JsonSubtree::new(rows.clone());
    assert_eq!(subtree.nodes(), rows.as_slice());
    assert_eq!(subtree.nodes().len(), 4, "both elements and both leaves");

    let opening: Option<Decryption<Value, FakeDataKeySource>> = doc.decryption_field(aead());
    let opened = cipher
        .run_decryption(opening.expect("a document opens"))
        .await
        .unwrap();
    assert_eq!(opened, fixture());
    let opening: Option<Decryption<Value, FakeDataKeySource>> = node.decryption_field(aead());
    let opened = cipher
        .run_decryption(opening.expect("a node opens"))
        .await
        .unwrap();
    assert_eq!(opened, json!("world-1"));
    let opening: Option<Decryption<Value, FakeDataKeySource>> = subtree.decryption_field(aead());
    let opened = cipher
        .run_decryption(opening.expect("a subtree opens"))
        .await
        .unwrap();
    assert_eq!(opened, json!([{"x": 1}, {"x": 2}]));
}

/// Past its budget the server returns the sealed root alone, at depth 0,
/// in place of the subtree: the rows open to the whole document and the
/// path attached with `at` selects over it. Without the path, or with one
/// that reaches nothing, the opening is refused; a root at depth 0 under
/// an unsealed document is not the fallback.
#[tokio::test]
async fn the_sealed_root_a_walk_fell_back_to_opens_at_the_path() {
    let cipher = stack_cipher().await;
    let doc = seal(&cipher, &fixture()).await;
    let fallback = |doc: &JsonDocument| -> JsonNode {
        let mut wire = serde_json::to_value(doc.node(0).unwrap()).unwrap();
        wire["d"] = json!(0);
        serde_json::from_value(wire).unwrap()
    };
    let root = fallback(&doc);
    let rows = JsonSubtree::new(vec![root.clone()]);
    assert!(rows.is_sealed_root());
    assert!(rows.path().is_none());

    let nested = cipher
        .decrypt_as::<Value, JsonSubtree>(
            rows.clone().at(JsonPath::parse("$.nested").unwrap()),
            aead(),
        )
        .await
        .unwrap();
    assert_eq!(nested, fixture()["nested"]);
    let xs = cipher
        .decrypt_as::<Vec<Value>, JsonSubtree>(
            rows.clone()
                .at(JsonPath::parse("$.nested.list[*].x").unwrap()),
            aead(),
        )
        .await
        .unwrap();
    assert_eq!(xs, vec![json!(1), json!(2)]);
    let none = cipher
        .decrypt_as::<Vec<Value>, JsonSubtree>(
            rows.clone().at(JsonPath::parse("$.missing[*]").unwrap()),
            aead(),
        )
        .await
        .unwrap();
    assert!(none.is_empty(), "a path that reaches nothing is no subtree");

    // Each refusal names what it expected: nothing at the path, or one node
    // where a wildcard reached two.
    for (path, expected) in [
        ("$.missing", "a node at the walked path"),
        ("$.nested.list[*].x", "one node at the walked path"),
    ] {
        let refused = cipher
            .decrypt_as::<Value, JsonSubtree>(
                rows.clone().at(JsonPath::parse(path).unwrap()),
                aead(),
            )
            .await;
        match refused {
            Err(Error::OpenedType { expected: got }) => assert_eq!(got, expected, "{path}"),
            other => panic!("{path}: {other:?}"),
        }
    }
    let unattached = cipher
        .decrypt_as::<Value, JsonSubtree>(rows.clone(), aead())
        .await;
    assert!(
        matches!(unattached, Err(Error::OpenedType { .. })),
        "the fallback needs the path: {unattached:?}"
    );

    // The same root at depth 1, or at depth 0 under an unsealed document,
    // is a walk's row and not the fallback; neither assembles.
    let mut as_walked = serde_json::to_value(doc.node(0).unwrap()).unwrap();
    as_walked["d"] = json!(1);
    let as_walked: JsonNode = serde_json::from_value(as_walked).unwrap();
    assert!(!JsonSubtree::new(vec![as_walked.clone()]).is_sealed_root());
    let refused = cipher
        .decrypt_as::<Value, JsonSubtree>(
            JsonSubtree::new(vec![as_walked]).at(JsonPath::parse("$.nested").unwrap()),
            aead(),
        )
        .await;
    assert!(matches!(refused, Err(Error::OpenedType { .. })));
    let open_doc = seal_with(&cipher, &fixture(), JsonOptions { sealed_root: false }).await;
    assert!(!JsonSubtree::new(vec![fallback(&open_doc)]).is_sealed_root());
    assert!(!JsonSubtree::new(vec![]).is_sealed_root());
    assert!(!JsonSubtree::new(vec![root.clone(), root]).is_sealed_root());
}

/// The walk reports each row's depth below where it started, in `d`; an
/// extracted node carries none.
#[tokio::test]
async fn a_walked_row_carries_its_depth() {
    let cipher = stack_cipher().await;
    let doc = seal(&cipher, &fixture()).await;
    assert_eq!(doc.node(6).unwrap().depth(), None);
    let mut wire = serde_json::to_value(doc.node(6).unwrap()).unwrap();
    assert!(wire.get("d").is_none());
    wire["d"] = json!(3);
    let walked: JsonNode = serde_json::from_value(wire).unwrap();
    assert_eq!(walked.depth(), Some(3));
    assert_eq!(serde_json::to_value(&walked).unwrap()["d"], json!(3));
}

/// A document sealed without the sealed root keeps the root as an ordinary
/// node, and opens from its entries.
#[tokio::test]
async fn a_document_without_the_sealed_root_opens_from_its_entries() {
    let cipher = stack_cipher().await;
    for value in [fixture(), json!({"": {}}), json!([[], {}, ""]), json!("a")] {
        let doc = seal_with(&cipher, &value, JsonOptions { sealed_root: false }).await;
        assert!(!doc.header().sealed_root());
        assert_eq!(doc.entries().len(), nodes(&value));
        assert_eq!(open(&cipher, doc).await.unwrap(), value);
    }
}

/// An accessor whose path or bounds the index refuses is refused when the
/// query is awaited, before the keyset it names is loaded.
#[tokio::test]
async fn an_accessor_is_refused_before_its_keyset_loads() {
    let (cipher, loads) = common::loads_counting_cipher().await;
    let plan = plan();
    let eq = cipher
        .query(op::AtPath(op::Eq), &("address.city", "Sydney"))
        .on(&plan)
        .keyset("tenant")
        .await;
    assert!(
        matches!(eq, Err(Error::Term(TermError::JsonPath(_)))),
        "{eq:?}"
    );
    let between = cipher
        .query(op::AtPath(op::Between), &("address.age", (1, 2)))
        .on(&plan)
        .keyset("tenant")
        .await;
    assert!(
        matches!(between, Err(Error::Term(TermError::JsonPath(_)))),
        "{between:?}"
    );
    let unordered = cipher
        .query(op::AtPath(op::Between), &("$.flag", (false, true)))
        .on(&plan)
        .keyset("tenant")
        .await;
    assert!(
        matches!(unordered, Err(Error::Term(TermError::JsonLeafNotOrdered))),
        "{unordered:?}"
    );
    assert_eq!(
        loads.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "no keyset was loaded for a refused query"
    );
    // The same query with a path the index takes does load it.
    let _ = cipher
        .query(op::AtPath(op::Eq), &("$.address.city", "Sydney"))
        .on(&plan)
        .keyset("tenant")
        .await
        .unwrap();
    assert_eq!(loads.load(std::sync::atomic::Ordering::SeqCst), 1);
}
