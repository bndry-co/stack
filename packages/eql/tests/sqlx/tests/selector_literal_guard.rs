//! Guard: no workspace-keyed SteVec selector is written into this crate.
//!
//! A SteVec selector is a keyed MAC over (workspace keyset, prefix, JSON path),
//! so a selector copied out of a fixture is a fact about one CipherStash
//! workspace. Pinned in source, it breaks the whole suite the next time CI's
//! `CS_WORKSPACE_CRN` changes, which happened twice (issue #1200). Tests read
//! selectors from the loaded fixture instead (`fixtures::ste_vec_selector`).
//!
//! The scan flags any standalone run of exactly 32 lowercase hex characters (a
//! 16-byte selector) AND looks random, wherever it sits on the line: a bare
//! `"…"` literal, inside a SQL string (`payload -> '…'::text`, the shape the
//! removed pins were used in), or inside escaped JSON (`{\"s\":\"…\"}`).
//! "Standalone" means no ASCII letter, digit or `_` directly before or after,
//! so a longer hash or identifier never matches part-way. A match must also look random: at least [`MIN_DISTINCT_DIGITS`]
//! distinct hex digits. A real selector is MAC output, uniformly random, and has
//! fewer than 8 distinct digits in 32 with probability about 4e-8. Forged
//! selectors in literal-payload tests are written low-entropy
//! (`"00000000000000000000000000000001"`, `"ffff…"`, `"deadbeef…"`), so they read
//! as fake and pass. Needs no database.

use std::path::{Path, PathBuf};

/// Selector hex length: 16 bytes.
const SELECTOR_HEX_LEN: usize = 32;

/// A literal with at least this many distinct hex digits is treated as real.
const MIN_DISTINCT_DIGITS: usize = 8;

/// Whether `content` (a string literal's body) looks like a real selector.
fn looks_like_real_selector(content: &str) -> bool {
    if content.len() != SELECTOR_HEX_LEN
        || !content
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return false;
    }
    let mut seen = [false; 256];
    for b in content.bytes() {
        seen[b as usize] = true;
    }
    seen.iter().filter(|s| **s).count() >= MIN_DISTINCT_DIGITS
}

/// Every standalone 32-hex run on `line` that looks like a real selector.
fn selector_literals(line: &str) -> Vec<&str> {
    let bytes = line.as_bytes();
    let is_word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let is_hex = |b: u8| b.is_ascii_digit() || (b'a'..=b'f').contains(&b);
    let mut found = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if !is_hex(bytes[i]) || (i > 0 && is_word(bytes[i - 1])) {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && is_hex(bytes[i]) {
            i += 1;
        }
        let bounded = i == bytes.len() || !is_word(bytes[i]);
        let run = &line[start..i];
        if bounded && looks_like_real_selector(run) {
            found.push(run);
        }
    }
    found
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn no_workspace_keyed_selector_literals() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    for dir in ["src", "tests"] {
        rust_files(&root.join(dir), &mut files);
    }
    files.sort();
    assert!(
        files.len() > 10,
        "the scan found only {} .rs files under {}; is it reading the right crate?",
        files.len(),
        root.display(),
    );

    let mut hits = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file)
            .unwrap_or_else(|e| panic!("read {}: {e}", file.display()));
        for (n, line) in text.lines().enumerate() {
            for literal in selector_literals(line) {
                let rel = file.strip_prefix(root).unwrap_or(file);
                hits.push(format!("  {}:{}: \"{literal}\"", rel.display(), n + 1));
            }
        }
    }

    assert!(
        hits.is_empty(),
        "selector-shaped hex literals found (32 lowercase hex chars, >= {MIN_DISTINCT_DIGITS} \
         distinct digits):\n{}\n\
         A SteVec selector is keyed by the CipherStash workspace, so a pinned one breaks \
         when CI's workspace changes. Read it from the loaded fixture \
         (`fixtures::v3_doc_integer::field_op_selector`, \
         `fixtures::v3_ste_vec::hello_op_selector`). If the value is forged for a \
         literal-payload test, make it visibly fake, e.g. all zeros ending in 1.",
        hits.join("\n"),
    );
}

#[cfg(test)]
mod classifier {
    use super::*;

    /// A random-looking 32-hex string built at runtime, so this file carries no
    /// literal the guard would flag.
    fn random_looking() -> String {
        let digits = b"0123456789abcdef";
        (0..SELECTOR_HEX_LEN)
            .map(|i| digits[(i * 7 + 3) % 16] as char)
            .collect()
    }

    #[test]
    fn flags_a_random_looking_selector() {
        assert!(looks_like_real_selector(&random_looking()));
        let line = format!(r#"    {{"s":"{}","c":"ct"}}"#, random_looking());
        assert_eq!(selector_literals(&line), vec![random_looking().as_str()]);
    }

    #[test]
    fn flags_a_selector_inside_sql_or_escaped_json() {
        let r = random_looking();
        let sql = format!("    \"SELECT 1 WHERE (payload -> '{r}'::text) IS NOT NULL\"");
        assert_eq!(selector_literals(&sql), vec![r.as_str()]);
        let escaped = format!(r#"    "{{\"s\":\"{r}\"}}""#);
        assert_eq!(selector_literals(&escaped), vec![r.as_str()]);
    }

    #[test]
    fn ignores_a_run_inside_a_longer_word() {
        let r = random_looking();
        for line in [
            format!("x{r}"),
            format!("{r}0"),
            format!("{r}_"),
            format!("0{r}"),
        ] {
            assert!(selector_literals(&line).is_empty(), "{line}");
        }
    }

    #[test]
    fn passes_visibly_forged_values() {
        for forged in [
            "0".repeat(31) + "1",
            "f".repeat(32),
            "deadbeef".repeat(4),
            "ab".repeat(16),
        ] {
            assert!(!looks_like_real_selector(&forged), "{forged}");
        }
    }

    #[test]
    fn ignores_other_lengths_and_cases() {
        let r = random_looking();
        assert!(!looks_like_real_selector(&r[..31]));
        assert!(!looks_like_real_selector(&format!("{r}0")));
        assert!(!looks_like_real_selector(&r.to_uppercase()));
        assert!(!looks_like_real_selector("placeholder"));
    }
}
