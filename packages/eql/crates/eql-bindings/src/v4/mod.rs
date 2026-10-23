//! # `eql_v4` domain payload types
//!
//! EQL v4 is the v3 SQL installed under a second name (ADR-0002): `eql_v3`
//! holds terms written by cipherstash-client, `eql_v4` holds terms written by
//! Stack Encrypt. The structs here are generated from the same catalog as
//! [`crate::v3`], with `eql_v4_*` domain names and a `v` of `4`.
//!
//! **Only these structs derive Stack Encrypt's traits** (`EncryptFrom`,
//! `DecryptInto`). Only Stack Encrypt produces a v4 value, so this module
//! exists only with the `stack-encrypt` feature. Stack Encrypt's output
//! is not byte-for-byte compatible with cipherstash-client's, so no `eql_v3`
//! struct claims it. Which v4 types derive them is
//! `eql-codegen`'s `ENCRYPTION_DOMAINS`; the rest say why in
//! `crate::encryption::targets`.
//!
//! Beyond v3's types, every ordered family has a range query operand per
//! order term (`IntegerRangeOreQuery`, `IntegerRangeOpeQuery`, …, listed by
//! [`all_range_query`]): both bounds of one `BETWEEN`, each the single-bound
//! domain's `ob` or `op` value, in a `{v, i, lo, hi}` envelope, and the one
//! operand of `eql_v4.between(column, range)`. EQL v3 has no range domains.
//!
//! v4 has no SteVec bindings, payload enums, TypeScript export or
//! published JSON Schema yet; those follow in `@cipherstash/eql` 4.0. The
//! term newtypes and the [`DomainType`] trait are shared with v3: a v4
//! `Ciphertext` or `Hmac256` is v3's type, so a change to a term's validation
//! in `v3::terms` changes v4 too. The one v4 term v3 has no use for is
//! [`terms::SearchBloomFilter`], the stored filter of a search domain. What
//! separates the two on the wire is the envelope's [`SchemaVersion`], which
//! refuses the other generation's `v`.

/// Generated: the `op::Answers` impls through which Stack Encrypt's typed
/// query chain queries a producible type, each type's
/// `op::LabelledTarget` impl and its query twin's assembly
/// ([`crate::encryption::query`]). Needs only the `stack-encrypt` feature.
pub mod answers;
pub mod bigint;
pub mod boolean;
pub mod date;
pub mod double;
pub mod integer;
pub mod inventory;
/// Generated bindings for the `json` family's bare scalar storage domain
/// (`public.eql_v4_json`, the `Json` struct).
pub mod json;
pub mod numeric;
// The Rust plaintexts of the `date`, `timestamp` and `numeric` families. A
// plain comment: an outer doc comment here would resolve the module's own
// links from this scope.
pub mod plaintext;
pub mod real;
pub mod smallint;
/// Generated: the table of EQL types a Stack Encrypt data plan may name as
/// a field target (`TARGETS`) and the by-name dispatch that runs a
/// producible type's own plan. The descriptor type, the errors and the
/// public entry points are hand-written in [`crate::encryption::targets`].
/// `targets` feature only.
#[cfg(feature = "targets")]
pub mod targets;
pub mod text;
pub mod timestamp;

pub use crate::v3::domain_type::{DomainType, SQL_SCHEMA};
pub use inventory::{all, all_query, all_range_query};

/// The wire-field newtypes of the v4 payloads: v3's, shared, and
/// [`SearchBloomFilter`](terms::SearchBloomFilter).
pub mod terms {
    pub use crate::v3::terms::*;

    use schemars::JsonSchema;
    use serde::{Deserialize, Serialize};
    use ts_rs::TS;

    /// The `bf` term of a stored search value (`TextSearch`,
    /// `TextSearchOre`): a [`BloomFilter`] that may be empty.
    ///
    /// Text too short to cut a 3-gram (empty, separator-only, or shorter than
    /// three characters) has no match tokens. A search column stores it with
    /// the empty filter, Stack Encrypt's answer for a stored value, so `=`
    /// and `<` still find it through its `hm` and `op`, and no `@@` query
    /// does: EQL's `matches` finds a stored filter only when it contains the
    /// query's, and an EQL v4 search query's filter is never empty (the
    /// match projection refuses such text, and the SQL refuses `"bf": []`).
    ///
    /// [`BloomFilter`], the filter of `TextMatch` and of every query, still
    /// refuses such text: `TextMatch` has no other term to find it by. The
    /// JSON is [`BloomFilter`]'s, and so is the JSON Schema; only what Stack
    /// Encrypt derives into it differs.
    #[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
    #[serde(transparent)]
    pub struct SearchBloomFilter(pub BloomFilter);

    /// [`BloomFilter`]'s schema, under its name: the wire format is one.
    impl JsonSchema for SearchBloomFilter {
        fn schema_name() -> std::borrow::Cow<'static, str> {
            BloomFilter::schema_name()
        }

        fn schema_id() -> std::borrow::Cow<'static, str> {
            BloomFilter::schema_id()
        }

        fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
            BloomFilter::json_schema(generator)
        }
    }

    impl From<SearchBloomFilter> for BloomFilter {
        fn from(filter: SearchBloomFilter) -> Self {
            filter.0
        }
    }
}

/// The PostgreSQL typname prefix every `public` v4 domain carries.
pub const PUBLIC_TYPNAME_PREFIX: &str = "eql_v4_";

/// Base URL for the canonical `$id` of a v4 domain's JSON Schema.
pub const SCHEMA_ID_BASE: &str = "https://schemas.cipherstash.com/eql/v4/";

/// EQL v4 wire-format version: the `v` every v4 payload carries, and what the
/// `eql_v4_*` domain CHECKs assert.
pub const EQL_SCHEMA_VERSION: u16 = 4;

/// The envelope version field (`v`) of a v4 payload — always exactly
/// [`EQL_SCHEMA_VERSION`] on the wire.
///
/// Deserialization rejects any other value, so a v3 payload fails at the type
/// boundary instead of at INSERT. The same type as v3's, at version `4`: see
/// [`crate::SchemaVersion`].
pub type SchemaVersion = crate::SchemaVersion<EQL_SCHEMA_VERSION>;
