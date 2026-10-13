//! The default match index folds case, so it answers only a
//! case-insensitive `Matches`: asking it for a case-sensitive one does not
//! compile, rather than quietly folding the needle.
use stack_encrypt::kms::FakeDataKeySource;
use stack_encrypt::{op, Match, Plan, StackCipher};

async fn query(cipher: &StackCipher<FakeDataKeySource>) {
    let name_plan = Plan::context("users/name")
        .with::<String, _>(Match::default())
        .build()
        .unwrap();
    let _ = cipher
        .query("Ali")
        .using(&name_plan)
        .op_via(op::Matches::<op::Sensitive>::new(), Match::default());
}

fn main() {}
