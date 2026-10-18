---
'@cipherstash/eql': minor
---

**An EQL v4 text search query carries only the terms its operator reads.** `eql_v4.query_text_search` and `eql_v4.query_text_search_ore` now require at least one of their terms (`hm`, `op` or `ob`, `bf`) instead of all of them, so `col = $1` and `col < $1` work on text too short to cut a 3-gram, which has no match term. Each extractor over such a query raises (`invalid_parameter_value`) when the query lacks the term it reads, naming the domain, the term and the operators that compare it: `=` without `hm`, `<` without `op`, `@@` without `bf`. A missing term never matches no row silently, nor every row. Stored `eql_v4_text_search` values still carry every term. The `eql_v3` domains are unchanged: the v3 bundle is byte for byte what it was.
