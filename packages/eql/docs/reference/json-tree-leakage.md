# What an encrypted JSON tree reveals

`public.eql_v4_json_tree` (EQL v4) stores a JSON document so that PostgreSQL can answer containment, path extraction, ordering at chosen paths and subtree reads without the key. Every value, key name and container sits inside an AES-256-GCM ciphertext under the document's data key, and nothing on this page reveals one. What the database can see is a bounded amount of **structure**, and it is deliberate: each item below is what one query capability costs. Read this before you put a column on it, and decide the two options at the end with it in mind.

## On this page

- [What a stored row shows](#what-a-stored-row-shows)
- [What a query shows](#what-a-query-shows)
- [What is authenticated](#what-is-authenticated)
- [Compared with EQL v3 (`public.eql_v3_json_search`)](#compared-with-eql-v3-publiceql_v3_json_search)
- [The two options that change the picture](#the-two-options-that-change-the-picture)

## What a stored row shows

Someone who holds the column and no key, such as a database administrator, a backup, or an attacker with a copy of the table, learns the following from each row. "Across rows" means a comparison between rows of the same column; nothing links a column to another column or another keyset.

| field | what it reveals |
|---|---|
| `s`, the path selector on every node | **Which paths the row has.** A selector is a keyed hash of the path, the same in every row of the column, so two rows with a selector in common hold the same path. Key names are inside the hash and not readable. Array elements share their array's selector, so `$.tags[0]` and `$.tags[1]` look alike. |
| `q`, the containment projection: one `{s, vs}` pair per node, nested by array element | **Whether two rows hold the same value at the same path**, through the value selector `vs`, a keyed hash of the path and the value. Not the value itself, and not whether two different paths hold the same value. **Which nodes sit inside the same array element**, through the nesting. That grouping is what makes containment exact for arrays of objects, and it is the one thing this format reveals that v3 did not. |
| the number of entries, and each ciphertext's length | **The node count**, and for each scalar the length of its value plus its key name, to within the AEAD's fixed overhead. A row's total size is the usual size signal any encrypted column gives. |
| `p`, the parent tag below the chain's heads | Nothing on its own. It is salted by the document's `iv`, so the same position in two rows is unrelated bytes. It shows **how many nodes are direct members of the root** (they carry no `p`); not which node is any other node's parent, not an array's length, and not whether two rows have the same shape. |
| `op`, the ordering term, only on leaves at the paths the index orders | **The order of that leaf's value among every row that holds one.** The term is order-preserving encryption under one key per column, so leaves at two ordered paths compare with each other too. An order-preserving term is not a random value: values that sort near each other get terms that share leading bytes. By default no path is ordered; see the options below. |

Not revealed at rest: any value, any key name, which node is whose parent, how long an array is, and whether two rows have the same shape.

## What a query shows

A query hands the database a term derived from the plaintext it asks about, and the database's answer is visible to it. Each query type reveals the following, in addition to the rows it returns.

- **Containment (`@>`, `<@`).** The needle's own projection: the selectors of its paths, the value selectors of its leaves, and its element grouping. So the database learns which paths and which (path, value) pairs you asked about, and which rows hold them.
- **Path extraction (`->`, `->>`, `json_tree_path_query`).** The selector of the path asked. The entry returned is a ciphertext.
- **Ordering at a path (`<`, `<=`, `>`, `>=`, `ORDER BY ord_term(…)`).** The bound's own ordering term, so roughly where the bound sits in the order of the stored values at that path.
- **A subtree read (`json_tree_subtree`, `json_tree_subtree_at`, `json_tree_children`, `json_tree_child_count`).** A **token** for the node, and one gate (a selector or an array position) per step below it. A token is a capability over the structure of that subtree in *every row of the column*: whoever holds it can count the nodes under that path in any row, see how they nest and in what order, and derive the tokens of the nodes beneath. It still opens no value. Tokens are column-wide and do not expire, so a token sent once is useful to the database for as long as the column lives. Send a token to the database in a query and nowhere else. With the sealed root on (the default) the broadest token a query can send covers one top-level field's subtree; no query can walk a whole column.

## What is authenticated

Only the ciphertext `c`. Opening an entry verifies that it was sealed under this keyset, for this column, under this data key, at this path (`s`) and at this position in the document (`j`); a moved, swapped or re-labelled entry fails to open. The selectors, the projection, the parent tags, the ordering terms, and which entries a row holds are not authenticated, by the same rule every EQL stored value follows (ADR 0010 in `packages/stack-encrypt/docs/adr`). The consequence to design around: tampering with those fields changes **which rows a query returns or where a walk stops**, never what a value decrypts to. A query's result set is not integrity-protected; a decrypted value is.

## Compared with EQL v3 (`public.eql_v3_json_search`)

| observer sees | v3 (`ste_vec`) | v4 (`json_tree`) |
|---|---|---|
| which paths a row has | yes | yes |
| which (path, value) pairs a row has | yes | yes |
| node count | yes, two entries per node | yes, one entry per node |
| size of every subtree | yes: each path entry's ciphertext is the subtree under it | no: only each scalar's length |
| parent and child relation | inferable from subtree sizes and co-occurrence across rows | hidden at rest; linkable only with a token the query supplies |
| whether two rows have the same shape | yes, selectors are column-deterministic | no, until a token is supplied |
| which leaves sit in the same array element | no | yes, through the projection's nesting: the one new disclosure, required for exact containment, bounded to array elements |
| equal values in sibling elements | ciphertexts equal | ciphertexts differ |
| ordering terms | on scalar leaves, with no per-path choice | only at the paths the index orders; none by default |
| a subtree read | reveals the selector asked | reveals the token asked, and with it the subtree's shape in every row for the life of the column |

## The two options that change the picture

- **`sealed_root`** (default on). The root entry's ciphertext is the whole document, so a full read is one decryption and the broadest token a query can send is one top-level field's. The cost is that the root entry's length reveals the document's size, and the row is larger.
- **`ordered`** (default none). Each path listed carries an ordering term and takes on the `op` row above; a path not listed cannot be range-queried or sorted, and a query that tries is refused by the client before any key loads. Order only the paths your queries sort or range over.

To report a concern with any of this, see `SECURITY.md` at the repository root.
