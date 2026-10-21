//! The JSON tree family end to end: a document sealed by Stack Encrypt's
//! JSON index into `public.eql_v4_json_tree`, queried with the v4 SQL, and
//! opened again. The unit tests need no database; the PostgreSQL test
//! installs nothing itself (`mise run test:encryption:postgres` installs the
//! v4 bundle built from the tree) and is the oracle the design asks for:
//! `@>` and `<@` over the encrypted column against PostgreSQL's own
//! `jsonb @>` over the plaintexts, for the design's corpus and random
//! documents, with a GIN index on the projection that the planner is shown
//! to use.

mod common;

use eql_bindings::v4::json_tree::{
    JsonTreeDocument, JsonTreeEntry, JsonTreeLeafQuery, JsonTreeQuery, JsonTreeSubtree,
};
use eql_bindings::Identifier;
use serde_json::{json, Map, Value};
use stack_encrypt::json::{JsonDocument, JsonOptions, JsonPath};
use stack_encrypt::plan::{Typed, ValuePlan};
use stack_encrypt::{op, NonEmpty, Plan};

fn column() -> NonEmpty<Identifier> {
    Identifier::for_column("users", "profile").unwrap()
}

fn fixture() -> Value {
    json!({"hello": "world-1", "nested": {"deep": "constant", "list": [{"x": 1}, {"x": 2}]}, "number": 1})
}

type Cipher = stack_encrypt::StackCipher<common::Observed>;

async fn seal(cipher: &Cipher, value: &Value) -> JsonTreeDocument {
    cipher
        .default_keyset()
        .encrypt_as::<Value, JsonTreeDocument>(value, column())
        .await
        .unwrap()
}

/// The plan a query derives through: the engine's own document target
/// under the label `users/profile`, which is the same context as the
/// identifier the EQL target stores (the same two parts, rendered
/// `users/profile`), so its selectors are the stored document's. An EQL
/// type takes its context as an identifier and runs through `encrypt_as`,
/// not through the chain.
fn plan() -> ValuePlan<Value, Typed<JsonDocument>> {
    Plan::value::<Value>()
        .context("users/profile")
        .encrypt_into::<JsonDocument>()
        .build()
        .unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[tokio::test]
async fn a_document_round_trips_through_the_typed_target() {
    let (cipher, calls) = common::cipher().await;
    let stored = seal(&cipher, &fixture()).await;
    assert_eq!(stored.sv.len(), 10, "one entry per node");
    assert_eq!(
        calls.lock().unwrap().generate,
        vec![vec!["users/profile".to_string()]],
        "one data key for the document, under the column's descriptor"
    );

    let wire = serde_json::to_value(&stored).unwrap();
    assert_eq!(wire["v"], 4);
    assert_eq!(wire["i"], json!({"t": "users", "c": "profile"}));
    assert!(wire["h"].is_string());
    let keys: Vec<&str> = wire
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys, ["h", "i", "sv", "v"]);

    let opened: Value = cipher
        .decrypt_as(stored.clone(), Default::default())
        .await
        .unwrap();
    assert_eq!(opened, fixture());
    let opened: Value = cipher
        .decrypt_as(stored.clone(), column().into())
        .await
        .unwrap();
    assert_eq!(opened, fixture());

    let wrong = Identifier::for_column("users", "bio").unwrap();
    let refused = cipher
        .decrypt_as::<Value, _>(stored.clone(), wrong.into())
        .await;
    assert!(
        matches!(refused, Err(stack_encrypt::Error::ContextMismatch { .. })),
        "{refused:?}"
    );
    assert_eq!(
        calls.lock().unwrap().retrieve.len(),
        2,
        "the refused open retrieved no key"
    );

    // An entry lifted from the stored document, with the header and its
    // ordinal grafted as `->` grafts them, opens to its scalar.
    let mut entry = stored.sv[1].clone();
    entry.h = Some(stored.h.clone());
    entry.j = Some(1);
    entry.i = Some(stored.i.clone());
    entry.v = Some(stored.v);
    let scalar: Value = cipher.decrypt_as(entry, column()).await.unwrap();
    assert_eq!(scalar, json!("world-1"));
    let bare = stored.sv[1].clone();
    assert!(cipher.decrypt_as::<Value, _>(bare, column()).await.is_err());
}

#[tokio::test]
async fn the_query_operands_are_the_engines_terms_in_the_sql_contract() {
    let (cipher, _) = common::cipher().await;
    let plan = plan();
    let query = cipher
        .query(op::Contains, &json!({"nested": {"list": [{"x": 2}]}}))
        .on(&plan)
        .await
        .unwrap();
    let operand = JsonTreeQuery::try_from(&query).unwrap();
    assert_eq!(
        serde_json::to_value(&operand).unwrap(),
        serde_json::to_value(&query).unwrap()
    );
    assert_eq!(operand.el.len(), 1);

    let bound = cipher
        .query(op::AtPath(op::Gte), &("$.number", 1))
        .on(&plan)
        .await
        .unwrap();
    let leaf = JsonTreeLeafQuery::try_from(&bound).unwrap();
    assert_eq!(
        serde_json::to_value(&leaf).unwrap(),
        serde_json::to_value(&bound).unwrap()
    );
    assert_eq!(leaf.s.0, bound.selector().to_string());

    // The engine's document under the label and the EQL document under the
    // identifier carry the same selectors: one context, two spellings.
    let engine = cipher.encrypt(&fixture()).using(&plan).await.unwrap();
    let typed = seal(&cipher, &fixture()).await;
    assert_eq!(engine.entries().len(), typed.sv.len());
    for (a, b) in engine.entries().iter().zip(&typed.sv) {
        assert_eq!(hex(a.selector()), b.s.0);
        assert_eq!(hex(a.value_selector()), b.vs.0);
    }
    let opened: Value = cipher.open(engine).using(&plan).await.unwrap();
    assert_eq!(opened, fixture());
}

// =============================================================================
// PostgreSQL
// =============================================================================

/// Settle a chain or a pending on the test's runtime: both are
/// `IntoFuture`, not `Future`.
fn wait<F: std::future::IntoFuture>(runtime: &tokio::runtime::Runtime, f: F) -> F::Output {
    runtime.block_on(f.into_future())
}

fn connect() -> postgres::Client {
    postgres::Client::connect(
        &std::env::var("EQL_TEST_DATABASE_URL").expect("EQL_TEST_DATABASE_URL"),
        postgres::NoTls,
    )
    .unwrap()
}

/// A small deterministic generator over a few keys and values, so needles
/// drawn from it overlap stored documents often.
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

/// The design's corpus (`containment-oracle.sql`), the cross-element cases
/// included, plus random documents.
fn corpus() -> Vec<Value> {
    let mut docs: Vec<Value> = [
        r#"{"a":[{"x":1,"y":5},{"x":7,"y":2}]}"#,
        r#"{"a":[{"x":1,"y":2,"z":3}]}"#,
        r#"{"a":[{"x":1}]}"#,
        r#"{"a":[{"b":[{"x":1},{"y":2}]}]}"#,
        r#"{"a":[{"b":[{"x":1,"y":2}]}]}"#,
        r#"{"a":[{"b":[{"x":1,"y":2}],"c":3},{"b":[{"x":1,"y":9}],"c":4}]}"#,
        r#"{"a":[{"b":{"c":1,"d":2}},{"b":{"c":3,"d":2}}]}"#,
        r#"{"a":[{"b":{"c":1,"d":5}},{"b":{"c":3,"d":2}}]}"#,
        r#"{"a":[[1,2],[3,4]]}"#,
        r#"{"a":[1,2]}"#,
        r#"{"a":{"b":1}}"#,
        r#"{"a":{}}"#,
        r#"{"a":[1]}"#,
        r#"{"a":1}"#,
        r#"[1,[2]]"#,
        r#"[1,2]"#,
        r#"[1]"#,
        r#"{"a":null}"#,
        r#"{"a":"2"}"#,
        r#"{"a":2}"#,
        r#"["a"]"#,
        r#""a""#,
        r#"[["a"]]"#,
        r#"{"a":[{"t":[{"u":1,"v":2}]},{"t":[{"u":1},{"v":2}]}]}"#,
        r#"{"a":[{"t":[{"u":1},{"v":2}]}]}"#,
        r#"{"a":[{}]}"#,
        r#"{"a":[[]]}"#,
        r#"{}"#,
        r#"[]"#,
        r#"2"#,
        r#"true"#,
        r#"null"#,
    ]
    .iter()
    .map(|text| serde_json::from_str(text).unwrap())
    .collect();
    let mut rng = Lcg(7);
    for _ in 0..40 {
        docs.push(rng.value(3));
    }
    docs
}

/// The needles: the corpus's own documents, plus the design's needles that
/// are not themselves stored.
fn needles() -> Vec<Value> {
    let mut needles = corpus();
    needles.extend(
        [
            r#"{"a":[{"x":1,"y":2}]}"#,
            r#"{"a":[{"x":1},{"x":1}]}"#,
            r#"{"a":[{"b":[{"x":1,"y":2}]}]}"#,
            r#"{"a":[{"b":[{"x":1,"y":2}],"c":4}]}"#,
            r#"{"a":[{"b":[{"x":1,"y":2}],"c":3}]}"#,
            r#"{"a":[{"b":{"c":1,"d":2}}]}"#,
            r#"{"a":[[1,4]]}"#,
            r#"{"a":[[1,2]]}"#,
            r#"{"a":[[1],[4]]}"#,
            r#"{"a":[]}"#,
            r#"[2]"#,
            r#"[[2]]"#,
            r#"[1,1,1]"#,
            r#"{"a":2.0}"#,
            r#"2.0"#,
            r#"{"a":[{"t":[{"u":1,"v":2}]}]}"#,
            r#"{"a":["x"]}"#,
        ]
        .iter()
        .map(|text| serde_json::from_str::<Value>(text).unwrap()),
    );
    let mut rng = Lcg(11);
    for _ in 0..40 {
        needles.push(rng.value(2));
    }
    needles
}

/// Needs an EQL v4 installation. Every document of the corpus is stored
/// encrypted beside its plaintext; for every needle, the rows `@>` and `<@`
/// select over the encrypted column are the rows PostgreSQL's own `jsonb`
/// operators select over the plaintext column.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_containment_over_the_encrypted_column_is_jsonb_containment() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (cipher, _) = wait(&runtime, common::cipher());
    let plan = plan();
    let mut db = connect();
    db.batch_execute(
        "CREATE TEMP TABLE json_tree_docs (id int PRIMARY KEY, plain jsonb NOT NULL, doc public.eql_v4_json_tree NOT NULL);
         CREATE INDEX json_tree_docs_doc ON json_tree_docs USING gin ((eql_v4.json_tree_query(doc)) jsonb_path_ops);",
    )
    .unwrap();

    let docs = corpus();
    for (id, plain) in docs.iter().enumerate() {
        let stored = wait(&runtime, seal(&cipher, plain));
        let stored = serde_json::to_string(&stored).unwrap();
        db.execute(
            "INSERT INTO json_tree_docs VALUES ($1, $2::text::jsonb, $3::text::jsonb::public.eql_v4_json_tree)",
            &[&(id as i32), &plain.to_string(), &stored],
        )
        .unwrap();
    }

    let ids = |db: &mut postgres::Client, sql: &str, param: &str| -> Vec<i32> {
        db.query(sql, &[&param])
            .unwrap_or_else(|e| panic!("{sql}: {e}"))
            .iter()
            .map(|r| r.get(0))
            .collect()
    };
    let mut checked = 0;
    for needle in needles() {
        let query = wait(&runtime, cipher.query(op::Contains, &needle).on(&plan)).unwrap();
        let operand = serde_json::to_string(&JsonTreeQuery::try_from(&query).unwrap()).unwrap();
        let plain = needle.to_string();
        let expected = ids(
            &mut db,
            "SELECT id FROM json_tree_docs WHERE plain @> $1::text::jsonb ORDER BY id",
            &plain,
        );
        let encrypted = ids(
            &mut db,
            "SELECT id FROM json_tree_docs WHERE doc @> $1::text::jsonb::eql_v4.query_json_tree ORDER BY id",
            &operand,
        );
        assert_eq!(encrypted, expected, "@> {needle}");
        let function_form = ids(
            &mut db,
            "SELECT id FROM json_tree_docs WHERE eql_v4.json_tree_contains(doc, $1::text::jsonb::eql_v4.query_json_tree) ORDER BY id",
            &operand,
        );
        assert_eq!(function_form, expected, "json_tree_contains {needle}");

        // `<@`: a stored root scalar inside a needle root array is the one
        // case the SQL cannot answer (a stored document carries no `alt`).
        let reverse = wait(&runtime, cipher.query(op::ContainedBy, &needle).on(&plan)).unwrap();
        let reverse = serde_json::to_string(&JsonTreeQuery::try_from(&reverse).unwrap()).unwrap();
        let mut expected = ids(
            &mut db,
            "SELECT id FROM json_tree_docs WHERE plain <@ $1::text::jsonb ORDER BY id",
            &plain,
        );
        if needle.is_array() {
            expected.retain(|id| {
                let stored = &docs[*id as usize];
                stored.is_object() || stored.is_array()
            });
        }
        let encrypted = ids(
            &mut db,
            "SELECT id FROM json_tree_docs WHERE doc <@ $1::text::jsonb::eql_v4.query_json_tree ORDER BY id",
            &reverse,
        );
        assert_eq!(encrypted, expected, "<@ {needle}");
        checked += 1;
    }
    assert!(
        checked > 80,
        "the corpus should hold many needles: {checked}"
    );

    // The GIN index serves `@>`: with sequential scans discouraged, the
    // plan is a bitmap scan over the index.
    db.batch_execute("SET enable_seqscan = off").unwrap();
    let needle = wait(
        &runtime,
        cipher
            .query(op::Contains, &json!({"a": [{"x": 1}]}))
            .on(&plan),
    )
    .unwrap();
    let operand = serde_json::to_string(&JsonTreeQuery::try_from(&needle).unwrap()).unwrap();
    let explain: Vec<String> = db
        .query(
            "EXPLAIN SELECT id FROM json_tree_docs WHERE doc @> $1::text::jsonb::eql_v4.query_json_tree",
            &[&operand],
        )
        .unwrap()
        .iter()
        .map(|r| r.get::<_, String>(0))
        .collect();
    let text = explain.join("\n");
    assert!(
        text.contains("Bitmap Index Scan on json_tree_docs_doc"),
        "the GIN index should serve containment:\n{text}"
    );
    db.batch_execute("SET enable_seqscan = on").unwrap();

    // Not STRICT, so inlinable; a NULL on either side is still NULL.
    let nulls = db
        .query_one(
            "SELECT (NULL::public.eql_v4_json_tree @> $1::text::jsonb::eql_v4.query_json_tree) IS NULL
                AND ((SELECT doc FROM json_tree_docs WHERE id = 0) @> NULL::eql_v4.query_json_tree) IS NULL",
            &[&operand],
        )
        .unwrap();
    assert!(nulls.get::<_, bool>(0));
}

/// Needs an EQL v4 installation. Extraction by selector opens to the leaf;
/// the subtree walk by a client-derived token returns exactly the nodes
/// under it and reassembles; the array functions count and list elements;
/// the orderings at a path select the rows the plaintexts say.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_extracts_walks_and_orders_by_path() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (cipher, _) = wait(&runtime, common::cipher());
    let keyset = cipher.default_keyset();
    let plan = plan();
    let mut db = connect();
    db.batch_execute(
        "CREATE TEMP TABLE json_tree_rows (id int PRIMARY KEY, doc public.eql_v4_json_tree NOT NULL)",
    )
    .unwrap();
    let rows = [
        (1, fixture()),
        (
            2,
            json!({"hello": "world-2", "nested": {"deep": "other", "list": []}, "number": 7}),
        ),
        (3, json!({"hello": "aaa", "number": -3, "tags": ["x", "y"]})),
    ];
    for (id, plain) in &rows {
        let stored = wait(&runtime, seal(&cipher, plain));
        let stored = serde_json::to_string(&stored).unwrap();
        db.execute(
            "INSERT INTO json_tree_rows VALUES ($1, $2::text::jsonb::public.eql_v4_json_tree)",
            &[id, &stored],
        )
        .unwrap();
    }
    let selector = |path: &str| {
        wait(
            &runtime,
            keyset.json_selector(&JsonPath::parse(path).unwrap(), column()),
        )
        .unwrap()
        .to_string()
    };
    let subtree_key = |path: &str| {
        wait(
            &runtime,
            keyset.json_subtree_key(
                &JsonPath::parse(path).unwrap(),
                JsonOptions::default(),
                column(),
            ),
        )
        .unwrap()
    };
    let entry = |row: &postgres::Row| -> JsonTreeEntry {
        serde_json::from_str(&row.get::<_, String>(0)).unwrap()
    };
    let open =
        |e: JsonTreeEntry| -> Value { wait(&runtime, cipher.decrypt_as(e, column())).unwrap() };

    // `->` by selector opens to the leaf; a missing path is NULL.
    let hello = selector("$.hello");
    let row = db
        .query_one(
            "SELECT (doc -> $1::text)::jsonb::text FROM json_tree_rows WHERE id = 2",
            &[&hello],
        )
        .unwrap();
    assert_eq!(open(entry(&row)), json!("world-2"));
    let missing = db
        .query_one(
            "SELECT (doc -> $1::text)::jsonb::text FROM json_tree_rows WHERE id = 3",
            &[&selector("$.nested.deep")],
        )
        .unwrap();
    assert!(missing.get::<_, Option<String>>(0).is_none());
    let exists: Vec<i32> = db
        .query(
            "SELECT id FROM json_tree_rows WHERE eql_v4.json_tree_path_exists(doc::jsonb, $1::text) ORDER BY id",
            &[&selector("$.nested.deep")],
        )
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    assert_eq!(exists, [1, 2]);

    // Every element of an array shares its selector: the path query returns
    // one row per element, each opening to its value.
    let tags: Vec<Value> = db
        .query(
            "SELECT e::jsonb::text FROM json_tree_rows, eql_v4.json_tree_path_query(doc::jsonb, $1::text) e WHERE id = 3",
            &[&selector("$.tags[*]")],
        )
        .unwrap()
        .iter()
        .map(|r| open(entry(r)))
        .collect();
    assert_eq!(tags, vec![json!("x"), json!("y")]);

    // The subtree under `$.nested`, from a token derived on the client from
    // the path alone: six entries in row 1, reassembling the sub-document;
    // two in row 2.
    let nested = subtree_key("$.nested");
    for (id, expected) in [
        (1, fixture()["nested"].clone()),
        (2, rows[1].1["nested"].clone()),
    ] {
        let walked: Vec<JsonTreeEntry> = db
            .query(
                "SELECT e::jsonb::text FROM json_tree_rows, eql_v4.json_tree_subtree(doc, $1::text) e WHERE id = $2",
                &[&nested.token(), &id],
            )
            .unwrap()
            .iter()
            .map(entry)
            .collect();
        assert_eq!(walked.len(), if id == 1 { 6 } else { 2 });
        assert!(walked
            .iter()
            .all(|e| e.d.is_some() && e.j.is_some() && e.h.is_some()));
        let value: Value = wait(
            &runtime,
            cipher.decrypt_as(JsonTreeSubtree::new(walked), column()),
        )
        .unwrap();
        assert_eq!(value, expected, "row {id}");
    }
    let garbage: i64 = db
        .query_one(
            "SELECT count(*) FROM json_tree_rows, eql_v4.json_tree_subtree(doc, $1::text) e",
            &[&"00".repeat(16)],
        )
        .unwrap()
        .get(0);
    assert_eq!(garbage, 0, "a wrong token unlocks nothing in any row");

    // The budget: past it the walk returns the sealed root alone, at depth
    // 0, and the rows open to the value at the walked path; at it, or
    // with the budget off, the walk is complete; a wrong token still
    // yields nothing under any budget.
    let walked = |db: &mut postgres::Client, budget: i32| -> Vec<JsonTreeEntry> {
        db.query(
            "SELECT e::jsonb::text FROM json_tree_rows, eql_v4.json_tree_subtree(doc, $1::text, $2::int) e WHERE id = 1",
            &[&nested.token(), &budget],
        )
        .unwrap()
        .iter()
        .map(entry)
        .collect()
    };
    assert_eq!(walked(&mut db, 6).len(), 6, "at the budget, the subtree");
    assert_eq!(walked(&mut db, 0).len(), 6, "budget 0 never falls back");
    let root = walked(&mut db, 5);
    assert_eq!(root.len(), 1, "past the budget, the root alone");
    assert_eq!((root[0].j, root[0].d), (Some(0), Some(0)));
    let refused = wait(
        &runtime,
        cipher.decrypt_as::<Value, _>(JsonTreeSubtree::new(root.clone()), column()),
    );
    assert!(refused.is_err(), "the fallback needs the walked path");
    let value: Value = wait(
        &runtime,
        cipher.decrypt_as(
            JsonTreeSubtree::new(root).at(JsonPath::parse("$.nested").unwrap()),
            column(),
        ),
    )
    .unwrap();
    assert_eq!(value, fixture()["nested"]);
    let garbage: i64 = db
        .query_one(
            "SELECT count(*) FROM json_tree_rows, eql_v4.json_tree_subtree(doc, $1::text, 1) e",
            &[&"00".repeat(16)],
        )
        .unwrap()
        .get(0);
    assert_eq!(garbage, 0);

    // A wildcard below the anchor: every element's `x`, each a complete
    // subtree, from the list's token gated on the whole path's selector.
    let xs = subtree_key("$.nested.list[*].x");
    let walked: Vec<JsonTreeEntry> = db
        .query(
            "SELECT e::jsonb::text FROM json_tree_rows, eql_v4.json_tree_subtree_at(doc, $1::text, $2::text) e WHERE id = 1",
            &[&xs.token(), &xs.selector().unwrap().to_string()],
        )
        .unwrap()
        .iter()
        .map(entry)
        .collect();
    let values: Vec<Value> = wait(
        &runtime,
        cipher.decrypt_as(JsonTreeSubtree::new(walked), column()),
    )
    .unwrap();
    assert_eq!(values, vec![json!(1), json!(2)]);
    // Past the budget, the gated walk falls back the same way, and the
    // wildcard path selects every subtree over the whole document.
    let root: Vec<JsonTreeEntry> = db
        .query(
            "SELECT e::jsonb::text FROM json_tree_rows, eql_v4.json_tree_subtree_at(doc, $1::text, $2::text, 1) e WHERE id = 1",
            &[&xs.token(), &xs.selector().unwrap().to_string()],
        )
        .unwrap()
        .iter()
        .map(entry)
        .collect();
    assert_eq!(root.len(), 1);
    assert_eq!(root[0].d, Some(0));
    let values: Vec<Value> = wait(
        &runtime,
        cipher.decrypt_as(
            JsonTreeSubtree::new(root).at(JsonPath::parse("$.nested.list[*].x").unwrap()),
            column(),
        ),
    )
    .unwrap();
    assert_eq!(values, vec![json!(1), json!(2)]);

    // The array functions, by the list's token.
    let list = subtree_key("$.nested.list");
    let counts: Vec<(i32, i32)> = db
        .query(
            "SELECT id, eql_v4.json_tree_child_count(doc, $1::text) FROM json_tree_rows ORDER BY id",
            &[&list.token()],
        )
        .unwrap()
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect();
    assert_eq!(counts, [(1, 2), (2, 0), (3, 0)]);
    let elements: Vec<JsonTreeEntry> = db
        .query(
            "SELECT e::jsonb::text FROM json_tree_rows, eql_v4.json_tree_children(doc, $1::text) e WHERE id = 1",
            &[&list.token()],
        )
        .unwrap()
        .iter()
        .map(entry)
        .collect();
    assert_eq!(elements.len(), 2);
    assert_eq!(
        elements.iter().map(|e| e.o).collect::<Vec<_>>(),
        [Some(0), Some(1)]
    );

    // Orderings at a path: the rows whose `$.number` is in range, and
    // sorted by the leaf's term.
    let at_least_one = wait(
        &runtime,
        cipher
            .query(op::AtPath(op::Gte), &("$.number", 1))
            .on(&plan),
    )
    .unwrap();
    let at_least_one =
        serde_json::to_string(&JsonTreeLeafQuery::try_from(&at_least_one).unwrap()).unwrap();
    let number = selector("$.number");
    let ids: Vec<i32> = db
        .query(
            "SELECT id FROM json_tree_rows WHERE (doc -> $1::text) >= $2::text::jsonb::eql_v4.query_json_tree_leaf ORDER BY id",
            &[&number, &at_least_one],
        )
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    assert_eq!(ids, [1, 2]);
    let ids: Vec<i32> = db
        .query(
            "SELECT id FROM json_tree_rows WHERE (doc -> $1::text) < $2::text::jsonb::eql_v4.query_json_tree_leaf ORDER BY id",
            &[&number, &at_least_one],
        )
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    assert_eq!(ids, [3]);
    let sorted: Vec<i32> = db
        .query(
            "SELECT id FROM json_tree_rows ORDER BY eql_v4.ord_term(doc -> $1::text), id",
            &[&number],
        )
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    assert_eq!(sorted, [3, 1, 2], "-3, 1, 7");
    let text = selector("$.hello");
    let sorted: Vec<i32> = db
        .query(
            "SELECT id FROM json_tree_rows ORDER BY eql_v4.ord_term(doc -> $1::text), id",
            &[&text],
        )
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    assert_eq!(sorted, [3, 1, 2], "aaa, world-1, world-2");

    // The native jsonb operators are blocked on the column. The operand is
    // typed, as every EQL jsonb domain requires: an untyped literal resolves
    // to the native operator on the base type.
    match db.query("SELECT doc ? 'hello'::text FROM json_tree_rows", &[]) {
        Ok(rows) => panic!(
            "native `?` must be blocked, but returned {} rows",
            rows.len()
        ),
        Err(error) => {
            let message = error
                .as_db_error()
                .map(|e| e.message().to_owned())
                .unwrap_or_else(|| error.to_string());
            assert!(
                message.contains("operator ? is not supported for public.eql_v4_json_tree"),
                "native `?` must be blocked: {message}"
            );
        }
    }
}
