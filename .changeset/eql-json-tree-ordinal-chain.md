---
"@cipherstash/eql": minor
---

EQL v4 `json_tree` (unreleased): the token chain is derived by ordinal and the walk probes to the first miss.

A stored entry now carries four fields, `s`, `c`, `p` and `op`. The value selector `vs` lives only in the document's projection `q`, which the engine now reads back as the projection instead of rebuilding it from the entries; the group tags `n` and `g` are gone with it, since nothing read them once `q` was stored. The wrapped token `w` and the ordinal `o` are gone too: a child's token is `H("t" ‖ t(parent) ‖ LE32(o))`, which the server derives as it walks, and the ordinals under a node are dense from zero, so the walk probes them in turn and stops at the first miss. A subtree of `N` nodes costs about `2N` hashes whatever the document's width, where it cost the document's widest node times every node visited.

The client can derive a token only for a chain head and the array positions under it, since an object member's ordinal is a rank among its siblings' keys. `JsonSubtreeKey::gates()` gives the rest of a path as one gate per step, a selector or `#n` for an array position, and `eql_v4.json_tree_subtree_at(doc, token, gates text[], budget)` walks them; `json_tree_children` and `json_tree_child_count` take the same optional `gates`. A gated walk returns the node the gates reach with `d = 0` and its descendants beneath it; `json_tree_subtree(doc, token)` still returns the descendants of the token's node from `d = 1`. The entry validator accepts the four fields only. `eql_v4_internal.json_tree_unwrap`, `json_tree_xor16` and `json_tree_fanout` are removed; `json_tree_child_token` is added.
