---
"@cipherstash/eql": patch
---

EQL v4 `json_tree` (unreleased): the reference docs gain "What an encrypted JSON tree reveals" (`docs/reference/json-tree-leakage.md`), one page on what a stored row shows the database at rest, what each query type hands it, what is authenticated, and the side-by-side with v3 `ste_vec`. The encryption test suite now holds the planner to the GIN and btree indexes with every setting at its default, on inline and TOASTed documents, and CI runs that suite once per supported PostgreSQL version.
