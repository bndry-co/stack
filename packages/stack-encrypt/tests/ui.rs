//! Compile-fail tests for the derive diagnostics: every `tests/ui/*.rs` must
//! fail to compile with exactly the `.stderr` beside it. Regenerate the
//! expectations after a deliberate message change with `TRYBUILD=overwrite`.
//!
//! The expectations are recorded with every feature on, as `test:unit` and
//! CI run them (`--all-features`), and this test is only built with the
//! `dynamic` feature (`required-features` in `Cargo.toml`): rustc lists a
//! trait's other implementors in its help, that feature adds implementors
//! (`ValueFrame`) that can join such a list, and one recording cannot be
//! relied on to hold under both feature sets.

#[test]
fn derive_diagnostics() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/*.rs");
    // These cases' diagnostics name where vitaminc's `Encrypt` trait is
    // defined, beside the older vitaminc that cts-common pulls in. trybuild
    // writes a crates.io path as `$CARGO/<crate>-$VERSION`, and a git
    // checkout's as the absolute path under the machine's CARGO_HOME, which
    // no recording can match on every machine. So they run only while the
    // workspace takes vitaminc from crates.io; while the root Cargo.toml's
    // temporary `[patch.crates-io]` block points it at a git revision, they
    // are skipped, and they run again the day that block is removed.
    if vitaminc_from_crates_io() {
        t.compile_fail("tests/ui/registry_vitaminc/*.rs");
    } else {
        eprintln!(
            "skipping tests/ui/registry_vitaminc: the workspace takes vitaminc from a git revision"
        );
    }
    // And the shapes that must compile, so a diagnostic never grows to
    // cover a valid call.
    t.pass("tests/ui/pass/*.rs");
}

/// Whether the workspace lock resolves `vitaminc-aead` from crates.io, as
/// it does with no `[patch]` pointing it at a git revision.
fn vitaminc_from_crates_io() -> bool {
    let lock = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.lock");
    let lock = std::fs::read_to_string(lock).expect("the workspace Cargo.lock");
    !lock.contains("git+https://github.com/cipherstash/vitaminc")
}
