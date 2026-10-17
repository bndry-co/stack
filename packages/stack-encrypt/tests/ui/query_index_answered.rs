//! An operator answers `Match`, so `query_index` cannot derive its term: a
//! match query is `cipher.query(op::Matches, v)`, whose term is a query,
//! never the stored filter `query_index` would hand back.
use stack_encrypt::kms::FakeDataKeySource;
use stack_encrypt::{Match, StackCipher};

fn query(cipher: &StackCipher<FakeDataKeySource>) {
    let _ = cipher.query_index(Match, "bob");
}

fn main() {}
