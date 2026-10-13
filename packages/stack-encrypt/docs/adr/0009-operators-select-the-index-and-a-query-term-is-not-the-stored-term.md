---
status: proposed
date: 2026-10-13
supersedes: ADR-0004 (decision 5)
extends: ADR-0003, ADR-0007
---

# Operators select the index, and a query term is not the stored term

[ADR-0004](0004-one-context-per-target-threaded-through-the-declaration-tree.md)
decision 5 kept the standalone term methods as the query path on the grounds
that "a probe and a stored term are the same bytes, and the term methods
cannot tell which they are producing". That premise is wrong, and the API
built on it has the caller name an *index* when what they mean is an
*operator*.

This ADR records the query-side model for the Rust Stack Encrypt library:
what a caller asks for, how the library chooses the index that answers it,
what it hands back, and how far that answer can be trusted. It is a design
record. No code changes with it.

Scope is the Rust library only. The TypeScript bindings and the ProtectJS FFI
are not covered; ADR-0007 governs how a binding reaches this surface.

## The problem

### A probe and a stored term are not the same bytes

Decision 5 of ADR-0004 assumed they were. They are not, for any index except
HMAC equality:

| index | stored term | query term |
| --- | --- | --- |
| HMAC | the HMAC | the same HMAC |
| ORE | left and right ciphertext (right only, in future) | the left ciphertext only |
| OPE | the OPE value | the same OPE value |
| Bloom match | one filter over every n-gram of the value | a filter over the n-grams of the needle: a subset, or bits the stored filter lacks |
| Bloom prefix (planned) | an HMAC per edge n-gram | one HMAC |
| JSON path | a selector and, per leaf, that leaf's term | a selector, or a selector plus a leaf query term |
| similarity (research preview) | `[u64; BANDS]` tokens per row | a probe set of `BANDS × PROBES` tokens |

The term is a function of the index *and the operator*, not of the index
alone. An ORE index answers `=`, `<` and `BETWEEN` with different query shapes;
a Bloom index answers `Matches` and (if used for ranked search) `Nearest` with
the same stored filter and different queries.

### The caller names an index, not what they want

Today the query chain is
`cipher.query(value).using(&plan).index(Match(..))`: the caller picks the
index, and the operator is implied. That has three costs.

- A domain type with two indexes that both answer an operator leaves the choice
  to the caller, who has to know that HMAC is the better equality than ORE.
  The original CipherStash client made the choice for them, by operator — and
  took the *first* index after an alphabetical sort, so `Eq` went to ORE when
  both were present.
- An operator an index cannot answer is not a compile error. Nothing in the
  types says which operators `Match(..)` supports.
- There is no place to put operator-specific input. `Between` takes two
  values; `Nearest` takes an embedding and a fetch size; a JSON path operator
  takes a path.

### The server's answer is sometimes approximate, and the library says nothing

A Bloom filter is probabilistic. A row whose filter happens to contain every
bit of the query passes `@@` without containing the needle. The lossy
`orderise` transform behind text ordering collapses case and punctuation, so
`<` on text returns false positives at the boundary. A similarity index returns
candidates by construction.

The library has never said which terms are exact. A caller who wants ten real
matches has no way to know how many rows to fetch, and no help deciding, after
decrypting, which rows to keep. "We have never implemented client-side
filtering for Bloom filters" is a gap the API should at least leave room for.

### What the library is

Stack Encrypt is not a query interface. It produces query terms that a caller
binds into SQL through sqlx, Diesel or (through the bindings) Drizzle and
Prisma, and it decrypts what comes back. It never runs a query. Every decision
below respects that line: the library can tell you how many rows to ask for
and whether a decrypted row is a real match, but the SQL, the `LIMIT` and the
loop are yours.

## Decision

### 1. The caller names an operator; the operator is a type

```rust
let term = cipher.query::<Eq>("bob@example.com").on(&users::email)?;
let term = cipher.query::<Lt>(40).on(&users::age)?;
let term = cipher.query::<Between>((18, 65)).on(&users::age)?;
let term = cipher.query::<Matches>("ali").on(&users::name)?;
let term = cipher.query::<AtPath<Eq>>(("$.address.city", "Sydney")).on(&users::profile)?;
```

Operators are unit types, as in the original client, not a runtime enum. An
operator carries its own input type: `Eq` takes one value, `Between` a pair,
`Nearest` an embedding, `AtPath<Op>` a path and `Op`'s input.

Operators come in three kinds. A **predicate** (`Eq`, `Lt`, `Lte`, `Gt`,
`Gte`, `Between`, `Matches`, `StartsWith`, JSON `Contains`, `ContainedBy`)
filters rows. An **accessor** (`AtPath<Op>`) applies another operator at a
JSON path. A **ranking** (`Nearest`) orders rows and takes a fetch size
rather than filtering.

Two naming points, so they are not re-litigated. `Contains` and `ContainedBy`
are JSON containment (`@>` / `<@`); text search is `Matches`, because a Bloom
match is not a containment. The accessor is `AtPath`, not `At`, because `At`
alone does not say what it is at.

Case is a parameter of the text operators, defaulting to the common case:
`Matches<C = Insensitive>`, `StartsWith<C = Insensitive>`. A Bloom index
implements the variant its configuration fixes (`downcase` on or off), so a
case-sensitive query against a case-folding index is a type error, not an
empty result.

### 2. An index declares the operators it supports, and the query term for each

```rust
trait Index { type Stored; }

trait Supports<Op>: Index {
    type Input;            // what the operator takes: T, (T, T), an embedding …
    type Query: Term;      // what this index sends for this operator
}
```

`Query` is the query term, and decision 3 says what it must be. It is not
`Stored`. An ORE index's `Supports<Lt>::Query` is the left ciphertext; its
`Stored` is left and right. A Bloom index's `Supports<Matches>::Query` is a
filter over the needle; its `Stored` is a filter over the value.

The bound tightens per operator. `Supports<Matches>` requires
`Query: Verifiable`; `Supports<Nearest>` requires `Query: Ranked`. An index
cannot claim an inexact operator without saying how its answer is checked.

### 3. The domain type chooses the best index for an operator

```rust
trait Answers<Op> { type Via: Supports<Op>; }

impl Answers<Eq>      for TextSearch { type Via = Hmac; }
impl Answers<Lt>      for TextSearch { type Via = Ore;  }
impl Answers<Matches> for TextSearch { type Via = Bloom<EqlMatch>; }
```

"Best" is defined per domain type, by hand, and means the most efficient or
the most secure index that answers the operator, as the index types in play
dictate. A domain with both HMAC and ORE answers `Eq` with HMAC: cheaper to
compare, and the ORE term reveals order. This is the decision the original
client made by accident (first after a sort) and this ADR makes on purpose.

A domain that does not answer an operator has no `Answers<Op>` impl, and the
query is a compile error.

### 4. A query term is one of three things, and the trait it implements is its fidelity

```rust
pub trait Term: Serialize { type Plaintext; }

pub trait Verifiable: Term {
    fn verify(&self, value: &Self::Plaintext) -> bool;
    fn target_limit(&self, want: u64, stats: &Stats) -> Limit;
}

pub trait Ranked: Term {
    fn score(&self, value: &Self::Plaintext) -> Score;
    fn fetch_for(&self, want: u64) -> u64;
}
```

- A term that implements `Term` only is **exact**. The server's answer is the
  answer. HMAC `Eq`, ORE and OPE on numbers (`Lt`, `Between`), JSON
  `AtPath<Eq>`.
- A `Verifiable` term can return **false positives and no false negatives**.
  `verify` is the operator's own meaning, run on a decrypted value: it
  decides whether a row the server returned is a real match. Bloom `Matches`
  and `StartsWith`, and `Lt` on text through the lossy `orderise` (the ties).
- A `Ranked` term returns **candidates in approximate order**. `score` is the
  exact score on a decrypted value, for re-ranking. `Nearest` over a
  similarity index, and `Nearest` over a Bloom index if used for ranked text
  search.

There is no `Fidelity` enum and no `verify` on exact terms. A caller cannot
write `term.verify(..)` for an HMAC term, because there is nothing to verify,
and the compiler says so.

`AtPath<Op>` inherits the fidelity of the leaf: `AtPath<Lt>` on a text leaf is
`Verifiable`, as `Lt` on a text column is.

### 5. Verification is the caller's, after decrypt; the library supplies the predicate and the bound

The library never runs a query, so it cannot filter the result. What it gives
a caller of a `Verifiable` term is two things.

`verify` is the predicate. For `Matches<Insensitive>`, it folds case,
tokenises both sides with the index's own tokenizer and checks that the
needle's n-grams occur in the value. It lives on the term because the term
already carries the operator's input and the index's configuration, so it
cannot disagree with what was stored.

`target_limit` is how many rows to ask for to expect `want` real matches.
For a Bloom filter it is computable from what the client knows, plus one
number the client cannot know:

- `m` bits and `k` hashes: the index configuration.
- `b`: the distinct bits set in the *query* filter. The client built it, so
  this is exact, not `k × n-grams`.
- `f`: the fill of a *stored* filter, `1 − e^(−k·n/m)` for `n` stored tokens.
  The client cannot see `n` per row; it takes either a declared estimate or a
  measured fill.
- `N`: the rows the predicate scans.

A non-matching row passes when every one of the `b` query bits is set in its
filter: `p ≈ f^b`. False positives are then `Poisson(λ = p·N)`, and the
worst case that still satisfies the caller is exactly `want` true matches, so

```
target_limit(want, N) = want + Poisson_quantile(λ = p·N, confidence)
```

If fewer than `want` verified rows come back, there were fewer than `want`
matches and the caller has them all.

With the EQL v4 defaults (3-grams, `k = 6`, `m = 2048`), a million rows and 99%
confidence:

| stored tokens | needle | `b` | `p` | `λ` | `LIMIT` |
| --- | --- | --- | --- | --- | --- |
| 20 (a name) | `ali` | 6 | 3.4e-8 | 0.03 | `want + 1` |
| 200 (a paragraph) | `ali` | 6 | 7.3e-3 | 7300 | `want + ~7500` |
| 200 | `alice` | 18 | 3.8e-7 | 0.4 | `want + 2` |

The bad case is a short needle against long stored text, and the library can
say so before the query runs. `λ` is also the number of decrypts that will be
wasted, which is a better signal for tuning `m` and `k` than anything the
library reports today.

`N` and `f` come from the server, always. The library takes them as numbers in
`Stats` and does not care where they came from. The documented sources are:

- `SELECT reltuples FROM pg_class WHERE oid = 'users'::regclass` — a catalog
  read, approximate, cached at startup. Staleness only moves the confidence;
  `verify` keeps the result correct.
- `SELECT count(*) FROM users WHERE name @@ $1` — the candidate count
  `C = T + FP`, index-only. `C` is the true minimum: fetch `C` rows and every
  real match is among them. `p·N` then says how much of `C` is noise.
- `SELECT avg(cardinality(bf)) FROM users` — `bf` stores set-bit positions,
  so this is the mean fill directly, and removes the token estimate.

`Lt` on text has no `p`: the false positives are the rows that collapse onto
the boundary key, which depends on the data. Its `target_limit` is
`Limit::Unbounded`, and the caller uses the loop below. A `Ranked` term has no
`target_limit`; `fetch_for` applies the index's configured recall factor.

### 6. The loop is a documented pattern, not a library helper

A `Verifiable` term composes with the caller's query library like this. One
shot, with a bound:

```rust
let term  = cipher.query::<Matches>("ali").on(&users::name)?;
let fetch = term.target_limit(10, &stats).fetch();

let rows: Vec<UserRow> = sqlx::query_as(
    "SELECT id, name FROM users WHERE name @@ $1 ORDER BY id LIMIT $2",
)
.bind(sqlx::types::Json(&term))
.bind(fetch as i64)
.fetch_all(&pool).await?;

let users = cipher.decrypt_all(rows).await?;
let hits: Vec<User> = users.into_iter().filter(|u| term.verify(&u.name)).take(10).collect();
```

Keyset paging, which needs no `Stats` and works for `Limit::Unbounded`:

```rust
let term = cipher.query::<Matches>("ali").on(&users::name)?;
let (mut hits, mut after, page) = (Vec::new(), 0_i64, 50_i64);

while hits.len() < 10 {
    let rows: Vec<UserRow> = sqlx::query_as(
        "SELECT id, name FROM users WHERE name @@ $1 AND id > $2 ORDER BY id LIMIT $3",
    )
    .bind(sqlx::types::Json(&term)).bind(after).bind(page)
    .fetch_all(&pool).await?;
    if rows.is_empty() { break; }
    after = rows.last().unwrap().id;
    hits.extend(cipher.decrypt_all(rows).await?.into_iter().filter(|u| term.verify(&u.name)));
}
hits.truncate(10);
```

The library ships `verify` and `target_limit`. It does not ship the loop,
because the loop runs queries. That may change when Stack Similarity lands and
the ranked loop is worth packaging; it is deferred, not refused.

### 7. `Between` is one query

`cipher.query::<Between>((lo, hi))` produces one term carrying both ORE left
ciphertexts, inclusive at both ends, and the client refuses `lo > hi`. It is
one operand in SQL. Two `Gte`/`Lte` terms would be two round trips through
the term path and two operands the planner cannot see as a range.

### 8. One query operand domain per (family, term) in EQL v4

The EQL v4 side carries one query domain per (type family, term), such as
`eql_v4.query_text_match` and `eql_v4.query_integer_range`, rather than one per
operator or one per stored domain. This is the "option B" of the design
discussion and is recorded here so the Rust side's `Supports<Op>::Query` has a
fixed target: the query term for an (index, operator) serialises to exactly
one of those domains.

## Considered options

**Keep the index as the thing the caller names** (status quo). Rejected for
the three costs in the problem statement. It is also what the review of
#1164 ran into: storing short `TextMatch` text needs the stored term and the
query term for a Bloom filter to differ, and the API had no place to say so.

**Operators as a runtime enum**, as `cipherstash-client` did. Rejected: an
unsupported operator becomes a runtime error, and operator-specific input has
to be a tagged union. Rust can carry both in the type.

**First index that supports the operator**, as `cipherstash-client` did.
Rejected: the choice is per domain type and must be deliberate, because it
decides what the query term reveals.

**A `Fidelity` enum on every term, and `verify` that returns `true` for exact
terms**. Considered and dropped: a method that is a no-op on most terms is
noise, and a runtime enum says at runtime what the trait says at compile
time.

**The library returns candidates and verifies them itself**
(`cipher.query(..).fetch(&pool)`). Rejected: the library would run queries,
own `LIMIT` and paging, and need a driver. That is a query interface, which
this library is not.

**Two `Gte` and `Lte` terms for a range.** Rejected, decision 7.

## Consequences

ADR-0004 decision 5 is superseded. Its rule — a stored term goes through a
target, a probe comes from the query path — stands, but its justification was
wrong and is replaced: the two are different bytes for every index but HMAC,
and the query path is `cipher.query::<Op>(..)`, which produces a term the
stored side never would.

A caller who wants a real-match count or offset paging on a `Verifiable` term
cannot have either from the server. `COUNT(*)` is an upper bound, and
`OFFSET` shifts with the false positives. Keyset paging only. This is the most
visible change for users and is the reason to settle it now.

Only the inexact terms in a `WHERE` need verifying. `age > $2 AND name @@ $1`
verifies `name` and not `age`.

Verification costs decrypts, not database work, and tells the server nothing
it does not already know. The cost is `λ` ZeroKMS calls per query, so the
Bloom parameters now have a number to be tuned against.

A verified row needs its ciphertext. EQL v4 values carry `c` beside their
terms. A similarity index stores its vector separately, so a `Nearest` query
must select it too.

The lossy text-order case falls out without a special case: EQL's ADR-0002
(the value model, #1139) already refuses equality through `orderise`, and `Lt`
on text is now simply a `Verifiable` term.

It is a breaking change to the query chain. `QueryUsing::index(..)` goes;
`QueryUsing::equality()` becomes `query::<Eq>`. The write side (`encrypt`,
targets, plans) does not change.

## Deferred

- The SQL spelling of `Between`: `age <@ $1` through an operator on the range
  domain, or `eql_v4.between(age, $1)`. Either must stay inlinable.
- Whether `Nearest` is `cipher.query::<Nearest>(..)` or a separate
  `cipher.nearest(..)` entry, and whether a ranked query can carry further
  predicates. The latter is possible only when the server can join candidates
  to rows (the `ByRow` similarity mode), not in the per-band pseudonymous mode.
- Whether a match index declares `expected_tokens` so `target_limit` has a
  default fill without a stats query.
- `ORDER BY cardinality(bf)` on the EQL side, so low-fill rows — the least
  likely false positives — come first. It reveals nothing `bf` does not.
- Whether `Nearest` over Bloom scores by bit overlap or needs token-level
  terms. An index-design question, not an API one.
- Packaging the keyset and ranked loops once Stack Similarity exists.
