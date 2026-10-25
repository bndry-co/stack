//! The worlds the harness compares: handcrafted columns that exercise every
//! clause, and a proptest generator of random columns over a small, shared
//! key vocabulary, so that rows have paths and values in common and the
//! equality patterns are rich.

use proptest::prelude::*;
use serde_json::{json, Map, Value};
use stack_encrypt::json::JsonPath;

use super::profile::{Column, Query};

/// A column, its rows and the queries sent to it.
#[derive(Clone, Debug)]
pub struct World {
    pub name: &'static str,
    pub column: Column,
    pub docs: Vec<Value>,
    pub queries: Vec<Query>,
}

fn ordered(paths: &[&str]) -> Vec<JsonPath> {
    paths.iter().map(|p| JsonPath::parse(p).unwrap()).collect()
}

/// The design's fixture document, with the shapes of `json_index.rs` around
/// it and rows that vary it, so that each clause has something to show.
fn shapes() -> Vec<Value> {
    vec![
        json!({"hello": "world-1", "nested": {"deep": "constant", "list": [{"x": 1}, {"x": 2}]}, "number": 1}),
        json!({"hello": "world-2", "nested": {"deep": "constant", "list": [{"x": 2}]}, "number": 5}),
        json!({"hello": "world-1", "nested": {"list": [{"x": 1, "y": [true, null]}, 3, [4, {"x": 1}]]}, "number": -2}),
        json!({"number": 3, "nested": {"deep": "other", "list": []}, "zeta": {"k": "v", "a": 1}}),
        json!({"a": "b", "a b": 1, "é": [], "0": {}}),
        json!({"a": {"b": {"c": {"d": [1, "x", false]}}}}),
        json!({"n": 18446744073709551615u64, "m": -9223372036854775808i64, "f": 1e300, "g": 2.5}),
        json!([[1, 2], [3, [4, {"a": null}]]]),
        json!([{"x": 1}, {"y": 2}]),
        json!({}),
        json!([]),
        json!("a"),
        json!(2.5),
        json!(null),
        json!(true),
    ]
}

fn shape_queries(sealed_root: bool) -> Vec<Query> {
    // Reads below a key step (`$.nested.deep`), through positions, and
    // through one and two wildcard levels, at the default bound (65 tokens)
    // and at bounds the rows overflow, so that probes find elements and the
    // database walks them. `$.nested` is read under a budget its rows
    // overflow, so the sealed root falls back. `$.zeta` is read twice, for
    // determinism. `$` is a read under either root.
    let mut queries = vec![
        Query::subtree("$.nested.list"),
        Query::subtree("$.nested.list[1]"),
        Query::subtree("$.nested.list[*].x"),
        Query::subtree_with("$.nested.list[*].x", 1, 64),
        Query::subtree("$.nested.deep"),
        Query::subtree_with("$.nested.list[*].y[*]", 2, 64),
        Query::subtree_with("$.nested", 64, 3),
        Query::subtree("$.zeta"),
        Query::subtree("$[1]"),
        Query::subtree("$[1][1]"),
        Query::subtree_with("$[*].x", 3, 64),
        Query::subtree("$"),
        Query::subtree("$.zeta"),
        Query::Extract("$.nested.list[0].x".into()),
        Query::Extract("$.nested.list[1].x".into()),
        Query::Extract("$.hello".into()),
        Query::Extract("$".into()),
        Query::Contains(json!({"nested": {"list": [{"x": 1}]}})),
        Query::Contains(json!("a")),
        Query::Contains(json!({"hello": "world-1"})),
        Query::Contains(json!([{"x": 1}])),
        Query::Equals("$.hello".into(), json!("world-1")),
        Query::Equals("$.nested.list[*].x".into(), json!(2)),
        Query::Order("$.number".into(), json!(0)),
        Query::Order("$.nested.list[*].x".into(), json!(2)),
        Query::Order("$.number".into(), json!(5)),
        Query::Order("$.number".into(), json!(0)),
    ];
    if !sealed_root {
        queries.extend([
            Query::subtree("$.a.b"),
            Query::subtree_with("$[*][*]", 2, 64),
        ]);
    }
    queries
}

/// A column that orders strings, so the string half of the ordering clause
/// has something to compare (a world orders one kind of leaf; see
/// [`super::profile::Ids::ordering_ranks`]). `"Carol"` and `"carol"`, and
/// `"ál"` and `"al"`, fold to one value, so their terms are equal and
/// `"ál"`'s length is that of the two bytes it folds to.
fn names() -> World {
    World {
        name: "ordered strings",
        column: Column {
            sealed_root: true,
            ordered: ordered(&["$.name", "$.tags[*]"]),
        },
        docs: vec![
            json!({"name": "carol", "tags": ["b", "aa"]}),
            json!({"name": "al", "tags": ["aa"]}),
            json!({"name": "carol", "age": 3}),
            json!({"name": "bob", "tags": []}),
            json!({"tags": ["zzzzzzzz", "b"]}),
            json!({"name": "Carol", "tags": ["B", "aa", "Ab"]}),
            json!({"name": "ál"}),
        ],
        queries: vec![
            Query::Order("$.name".into(), json!("b")),
            Query::Order("$.tags[*]".into(), json!("aa")),
            Query::Order("$.name".into(), json!("AL")),
            Query::subtree("$.tags"),
            Query::subtree("$.tags[1]"),
            Query::subtree_with("$.tags[*]", 2, 64),
        ],
    }
}

/// A column with three wide top-level objects, each read whole, so that
/// whether members' ordinals follow their keys' order is decidable rather
/// than a coin toss (see `distinguishers::member_ordinals_follow_key_order`).
fn wide() -> World {
    let object = |prefix: &str, n: usize| {
        Value::Object(
            (0..n)
                .map(|i| (format!("{prefix}{i}"), Value::from(i as u64)))
                .collect(),
        )
    };
    World {
        name: "wide objects",
        column: Column {
            sealed_root: true,
            ordered: Vec::new(),
        },
        docs: vec![
            json!({"w1": object("a", 8), "w2": object("b", 8), "w3": object("c", 8),
                   "arr": [{"k": 1}, {"k": {"z": 2}, "m": [3]}]}),
            json!({"w1": object("a", 5), "w3": object("c", 8), "arr": [{"k": 4}]}),
        ],
        // `$.arr[*].k` at a bound of one: the probe `$.arr[1]` finds the
        // first row's second element, and no other read names anything in
        // it, so only the probe links its subtree.
        queries: vec![
            Query::subtree("$.w1"),
            Query::subtree("$.w2"),
            Query::subtree("$.w3"),
            Query::subtree_with("$.arr[*].k", 1, 64),
        ],
    }
}

/// The handcrafted worlds: the shapes under each root option, and a column
/// of ordered strings.
pub fn handcrafted() -> Vec<World> {
    vec![
        World {
            name: "shapes, sealed root",
            column: Column {
                sealed_root: true,
                ordered: ordered(&["$.number", "$.nested.list[*].x"]),
            },
            docs: shapes(),
            queries: shape_queries(true),
        },
        World {
            name: "shapes, open root",
            column: Column {
                sealed_root: false,
                ordered: ordered(&["$.number", "$.nested.list[*].x"]),
            },
            docs: shapes(),
            queries: shape_queries(false),
        },
        names(),
        wide(),
    ]
}

// =============================================================================
// Random columns
// =============================================================================

const KEYS: &[&str] = &["a", "b", "c", "list", "n", "name", "tags", "zz"];

fn leaf() -> impl Strategy<Value = Value> {
    prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        (-3i64..6).prop_map(Value::from),
        prop::sample::select(vec!["x", "yy", "x", "zzz", "ab", ""]).prop_map(Value::from),
    ]
}

fn object(
    inner: impl Strategy<Value = Value>,
    size: std::ops::Range<usize>,
) -> impl Strategy<Value = Value> {
    prop::collection::btree_map(prop::sample::select(KEYS), inner, size).prop_map(|members| {
        Value::Object(
            members
                .into_iter()
                .map(|(k, v)| (k.to_owned(), v))
                .collect::<Map<String, Value>>(),
        )
    })
}

fn value() -> impl Strategy<Value = Value> {
    leaf().prop_recursive(3, 24, 4, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..4).prop_map(Value::Array),
            object(inner, 0..4),
        ]
    })
}

/// Every value under the key `n` made a number, since the random columns
/// order `$.n` and `$.list[*].n` and a world orders one kind of leaf.
fn numberize(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(k, v)| {
                    let v = if k == "n" && !v.is_number() {
                        Value::from(i64::try_from(v.to_string().len() % 7).unwrap())
                    } else {
                        numberize(v)
                    };
                    (k, v)
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.into_iter().map(numberize).collect()),
        other => other,
    }
}

fn document() -> impl Strategy<Value = Value> {
    prop_oneof![
        8 => object(value(), 0..5),
        1 => prop::collection::vec(value(), 0..3).prop_map(Value::Array),
        1 => leaf(),
    ]
    .prop_map(numberize)
}

fn query() -> impl Strategy<Value = Query> {
    let subtree = vec![
        "$",
        "$.a",
        "$.list",
        "$.list[0]",
        "$.list[1]",
        "$.list[1].n",
        "$.a.b",
        "$.list[*].a",
        "$.tags[0].a",
        "$.a.list[2]",
        "$[0]",
        "$[1].a",
        "$[0][1]",
        "$.a.tags[*]",
        "$[*].a",
        "$.list[*]",
        "$.list[*].tags[*]",
    ];
    prop_oneof![
        3 => (
            prop::sample::select(subtree),
            prop::sample::select(vec![1u32, 2, 3, 64]),
            prop::sample::select(vec![0u32, 2, 64]),
        )
            // Two wildcard levels at the default bound send 4,161 tokens;
            // the harness keeps them small, and `a_read_gives_away_its_bound`
            // sends the full count once.
            .prop_map(|(p, bound, budget)| {
                let bound = if p.matches("[*]").count() > 1 { bound.min(3) } else { bound };
                Query::subtree_with(p, bound, budget)
            }),
        2 => prop::sample::select(vec!["$", "$.a", "$.a.b", "$.list[0].n", "$.list[3].n", "$.tags[*]"])
            .prop_map(|p| Query::Extract(p.into())),
        2 => prop_oneof![
            leaf(),
            object(leaf(), 1..3),
            prop::collection::vec(leaf(), 1..3).prop_map(Value::Array),
            object(prop::collection::vec(object(leaf(), 1..2), 1..2).prop_map(Value::Array), 1..2),
        ]
        .prop_map(|v| Query::Contains(numberize(v))),
        1 => (prop::sample::select(vec!["$.a", "$.tags[0]", "$.list[*].b"]),
              prop_oneof![(-3i64..6).prop_map(Value::from), prop::sample::select(vec!["x", "ab"]).prop_map(Value::from)])
            .prop_map(|(p, v)| Query::Equals(p.into(), v)),
        1 => (prop::sample::select(vec!["$.n", "$.list[*].n"]), -3i64..6)
            .prop_map(|(p, v)| Query::Order(p.into(), Value::from(v))),
    ]
}

/// A random column: a root option, two to six documents, and four to ten
/// queries, some of which repeat.
pub fn random_world() -> impl Strategy<Value = World> {
    any::<bool>().prop_flat_map(|sealed_root| {
        (
            prop::collection::vec(document(), 2..7),
            prop::collection::vec(query(), 4..11),
        )
            .prop_map(move |(docs, queries)| World {
                name: "random",
                column: Column {
                    sealed_root,
                    ordered: ordered(&["$.n", "$.list[*].n"]),
                },
                docs,
                queries,
            })
    })
}
