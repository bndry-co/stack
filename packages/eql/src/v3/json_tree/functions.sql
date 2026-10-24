-- ONLY EQL VERSION: 4
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/json_tree/types.sql
-- REQUIRE: src/v3/sem/ope_cllw/types.sql
-- REQUIRE: src/v3/sem/ope_cllw/functions.sql

--! @file v3/json_tree/functions.sql
--! @brief The JSON tree surface's functions: the chain primitives, the
--!        containment projection, extraction by selector, the subtree walk
--!        by token, and the ordering extractors.
--!
--! Everything here is core PostgreSQL: `sha256(bytea)`, `get_byte` /
--! `set_byte`, `decode` / `encode`, recursive CTEs and `jsonb` operators. No
--! extension, no superuser, so the surface installs wherever the rest of
--! {{prefix}} does.
--!
--! `selector` parameters are *encrypted-side* selectors, the hex the index
--! emits in `s`; `token` parameters are the hex of a chain token the client
--! derived from a path. Plaintext paths are never accepted.

------------------------------------------------------------------------------
-- Chain primitives ({{prefix}}_internal)
------------------------------------------------------------------------------

--! @brief The first sixteen bytes of SHA-256 over `x`.
--! @internal
--! @param x bytea The bytes to hash.
--! @return bytea Sixteen bytes.
CREATE FUNCTION {{prefix}}_internal.json_tree_h16(x bytea)
  RETURNS bytea
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT substr(sha256(x), 1, 16)
$$;

--! @brief XOR of two sixteen-byte strings.
--! @internal
--! @param a bytea Sixteen bytes.
--! @param b bytea Sixteen bytes.
--! @return bytea `a XOR b`, byte by byte.
CREATE FUNCTION {{prefix}}_internal.json_tree_xor16(a bytea, b bytea)
  RETURNS bytea
  LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
AS $$
DECLARE
  r bytea := a;
  i int;
BEGIN
  FOR i IN 0..15 LOOP
    r := set_byte(r, i, get_byte(a, i) # get_byte(b, i));
  END LOOP;
  RETURN r;
END;
$$;

--! @brief A 32-bit integer as four little-endian bytes.
--! @internal
--! @param n integer The integer, non-negative.
--! @return bytea Four bytes, least significant first.
CREATE FUNCTION {{prefix}}_internal.json_tree_le32(n integer)
  RETURNS bytea
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT set_byte(set_byte(set_byte(set_byte('\x00000000'::bytea,
    0, n & 255), 1, (n >> 8) & 255), 2, (n >> 16) & 255), 3, (n >> 24) & 255)
$$;

--! @brief The document's ZeroKMS `iv` from its header: the per-document salt
--!        of every chain tag.
--! @internal
--! @param h text The document's header, base64.
--! @return bytea Sixteen bytes, at byte offset 22 of the header's frozen
--!         layout (version, flags, epoch, keyset id, iv, tag).
CREATE FUNCTION {{prefix}}_internal.json_tree_iv(h text)
  RETURNS bytea
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT substr(decode(h, 'base64'), 23, 16)
$$;

--! @brief The parent tag a child at ordinal `o` under the node with token
--!        `token` carries: `H("p" ‖ iv ‖ token ‖ LE32(o))`.
--! @internal
--! @param iv bytea The document's iv.
--! @param token bytea The parent's token, sixteen bytes.
--! @param o integer The child's ordinal.
--! @return text The tag, hex, as the entry's `p` spells it.
CREATE FUNCTION {{prefix}}_internal.json_tree_parent_tag(iv bytea, token bytea, o integer)
  RETURNS text
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT encode({{prefix}}_internal.json_tree_h16('p'::bytea || iv || token || {{prefix}}_internal.json_tree_le32(o)), 'hex')
$$;

--! @brief Unwrap a child's token from its entry, given its parent's token:
--!        `w XOR H("w" ‖ iv ‖ token ‖ c)`.
--! @internal
--! @param iv bytea The document's iv.
--! @param token bytea The parent's token.
--! @param entry jsonb The child's entry, carrying `w` and `c`.
--! @return bytea The child's token, sixteen bytes.
CREATE FUNCTION {{prefix}}_internal.json_tree_unwrap(iv bytea, token bytea, entry jsonb)
  RETURNS bytea
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT {{prefix}}_internal.json_tree_xor16(
    decode(entry ->> 'w', 'hex'),
    {{prefix}}_internal.json_tree_h16('w'::bytea || iv || token || decode(entry ->> 'c', 'base64'))
  )
$$;

--! @brief How many ordinals a walk tries under each node: one more than the
--!        largest ordinal any entry of the document carries, and never more
--!        than the document has entries.
--!
--! A node's children sit at ordinals below its child count, which is below
--! the document's entry count, so the cap changes nothing for a sealed
--! document. It is there for a stored one: `o` is not authenticated, and
--! without the cap one entry carrying `o = 2147483646` would make every
--! level of every walk hash two billion candidate tags.
--!
--! @internal
--! @param val jsonb The document.
--! @return integer The fan-out bound; `0` for a document with no chained
--!         entry.
CREATE FUNCTION {{prefix}}_internal.json_tree_fanout(val jsonb)
  RETURNS integer
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT LEAST(COALESCE(MAX((elem ->> 'o')::integer), -1) + 1, count(*)::integer)
  FROM jsonb_array_elements(val -> 'sv') AS elem
$$;

--! @brief Whether the document's root is sealed: its header's sealed-root
--!        flag, bit 0 of the flags byte at offset 1 of the frozen layout.
--!        A sealed root's `c` is the whole document, so a walk may return
--!        the root in place of a subtree it would be cheaper to open whole.
--! @internal
--! @param h text The document's header, base64.
--! @return boolean True when the root is sealed.
CREATE FUNCTION {{prefix}}_internal.json_tree_sealed_root(h text)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT (get_byte(decode(h, 'base64'), 1) & 1) = 1
$$;

--! @brief The chained entries of a document keyed by parent tag: one object
--!        whose keys are each entry's `p` and whose values are the entry
--!        with its ordinal `j` in `sv` added. A walk looks a child up by
--!        the tag it computes, `map -> tag`, instead of scanning `sv` for
--!        it, so the document is read once per walk and a level costs its
--!        fan-out in hashes, not its fan-out times the document's size.
--! @internal
--! @param val jsonb The document.
--! @return jsonb The map; `{}` for a document with no chained entry.
CREATE FUNCTION {{prefix}}_internal.json_tree_by_parent(val jsonb)
  RETURNS jsonb
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT COALESCE(
    jsonb_object_agg(elem ->> 'p', elem || jsonb_build_object('j', ord - 1)),
    '{}'::jsonb)
  FROM jsonb_array_elements(val -> 'sv') WITH ORDINALITY AS t(elem, ord)
  WHERE elem ? 'p'
$$;

------------------------------------------------------------------------------
-- Envelope helpers
------------------------------------------------------------------------------

--! @brief The envelope metadata an extracted entry carries: `i`, `v`, `h`.
--! @param val jsonb The document.
--! @return jsonb `{i, v, h}`, with absent keys dropped.
CREATE FUNCTION {{prefix}}.json_tree_meta(val jsonb)
  RETURNS jsonb
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT jsonb_strip_nulls(
    jsonb_build_object('i', val -> 'i', 'v', val -> 'v', 'h', val -> 'h')
  )
$$;

COMMENT ON FUNCTION {{prefix}}.json_tree_meta(jsonb) IS
  'eql-inline-critical: raw-jsonb envelope helper used by the JSON tree extractors; must stay inlinable (unpinned search_path)';

--! @brief The entry at ordinal `j` of the document, with the metadata grafted:
--!        what every extractor returns per node.
--! @internal
--! @param val jsonb The document.
--! @param elem jsonb The entry, as it sits in `sv`.
--! @param j integer The entry's ordinal in `sv`, from zero.
--! @return public.{{prefix}}_json_tree_entry The entry with `i`, `v`, `h` and `j`.
CREATE FUNCTION {{prefix}}_internal.json_tree_graft(val jsonb, elem jsonb, j integer)
  RETURNS public.{{prefix}}_json_tree_entry
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT ({{prefix}}.json_tree_meta(val) || elem || jsonb_build_object('j', j))::public.{{prefix}}_json_tree_entry
$$;

------------------------------------------------------------------------------
-- Extraction by selector
------------------------------------------------------------------------------

--! @brief Every entry whose path selector is `selector`, as rows.
--!
--! Every element of an array shares its parent's selector, so a wildcard
--! path (`$.tags[*]`) returns one row per element. Each row opens on its
--! own: it carries the document's header `h` and its own ordinal `j`.
--!
--! @param val jsonb The document.
--! @param selector text The path selector, hex.
--! @return SETOF public.{{prefix}}_json_tree_entry The matching entries, in
--!         document order.
CREATE FUNCTION {{prefix}}.json_tree_path_query(val jsonb, selector text)
  RETURNS SETOF public.{{prefix}}_json_tree_entry
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT {{prefix}}_internal.json_tree_graft(val, elem, (ord - 1)::integer)
  FROM jsonb_array_elements(val -> 'sv') WITH ORDINALITY AS t(elem, ord)
  WHERE elem ->> 's' = selector
  ORDER BY ord
$$;

COMMENT ON FUNCTION {{prefix}}.json_tree_path_query(jsonb, text) IS
  'eql-inline-critical: raw-jsonb path query helper; must stay inlinable (unpinned search_path)';

--! @brief The first entry whose path selector is `selector`, or NULL: what
--!        `->` returns, and what the ordering comparisons extract.
--!
--! Costed at 1000 (ten times the default): the body scans `sv`, and its
--! cost is what decides whether a comparison on it, `(col -> sel) > $1`,
--! takes the functional btree on `{{prefix}}.ord_term(col -> sel)` or filters
--! a sequential scan. Under a prepared statement's generic plan, where the
--! operand's selectivity is a guess, the default cost chose the scan.
--!
--! @param val jsonb The document.
--! @param selector text The path selector, hex.
--! @return public.{{prefix}}_json_tree_entry The entry, or NULL when the document
--!         has no node at that path.
CREATE FUNCTION {{prefix}}.json_tree_path_query_first(val jsonb, selector text)
  RETURNS public.{{prefix}}_json_tree_entry
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
  COST 1000
AS $$
  SELECT {{prefix}}_internal.json_tree_graft(val, elem, (ord - 1)::integer)
  FROM jsonb_array_elements(val -> 'sv') WITH ORDINALITY AS t(elem, ord)
  WHERE elem ->> 's' = selector
  ORDER BY ord
  LIMIT 1
$$;

COMMENT ON FUNCTION {{prefix}}.json_tree_path_query_first(jsonb, text) IS
  'eql-inline-critical: raw-jsonb path first helper; must stay inlinable (unpinned search_path)';

--! @brief Whether the document has a node at the path `selector` names.
--! @param val jsonb The document.
--! @param selector text The path selector, hex.
--! @return boolean True when some entry carries the selector.
CREATE FUNCTION {{prefix}}.json_tree_path_exists(val jsonb, selector text)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT EXISTS (
    SELECT 1 FROM jsonb_array_elements(val -> 'sv') AS elem
    WHERE elem ->> 's' = selector
  )
$$;

COMMENT ON FUNCTION {{prefix}}.json_tree_path_exists(jsonb, text) IS
  'eql-inline-critical: raw-jsonb path exists helper; must stay inlinable (unpinned search_path)';

------------------------------------------------------------------------------
-- Containment: the element-nested projection
------------------------------------------------------------------------------

--! @brief The stored document's containment projection: the needle shape
--!        `{{prefix}}.query_json_tree` holds, as the client wrote it in `q`.
--!
--! The projection is the document's `{s, vs}` pairs nested by array
--! element, `{"sv": [{"s", "vs"}, …], "el": [group, …]}`: the pairs outside
--! any array element at the top, and one nested group per array element
--! that is a container, so that `jsonb @>` over a stored projection and a
--! needle is PostgreSQL's own containment rule, each needle element inside
--! one stored element. The client derives it from the document it seals
--! and stores it beside `sv`; the server reads it and never rebuilds it,
--! so a containment recheck costs a field read, not a pass over `sv`.
--!
--! This is the GIN index expression for containment:
--!   `CREATE INDEX … USING gin (({{prefix}}.json_tree_query(col)) jsonb_path_ops);`
--! The typed `@>` inlines to native `jsonb @>` over the same expression, so
--! the index engages; GIN is lossy and the executor rechecks the real
--! operator on the heap tuple, which is the exact containment.
--!
--! @param e public.{{prefix}}_json_tree The stored document.
--! @return jsonb Its projection, the shape of `{{prefix}}.query_json_tree`.
--! @note Returns raw jsonb rather than the needle domain: a domain cast
--!       runs the needle's recursive CHECK, and the recheck would pay it
--!       once per candidate row. The document's own CHECK validated `q`
--!       when the row was written.
--! @note plpgsql, deliberately, and costed at 1000: a SQL body this simple
--!       would be inlined to `value -> 'q'`, which the planner costs as one
--!       operator, and a column of large documents is TOASTed out of the
--!       heap, so a sequential scan over it looks almost free on paper and
--!       is chosen over the GIN index. It is not free: every row is
--!       decompressed to read `q`. Un-inlined, the call keeps its cost, the
--!       index expression still matches it, and the planner takes the
--!       index. The call itself is a few microseconds per recheck row.
CREATE FUNCTION {{prefix}}.json_tree_query(e public.{{prefix}}_json_tree)
  RETURNS jsonb
  LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
  COST 1000
AS $$
BEGIN
  RETURN e::jsonb -> 'q';
END;
$$;

--! @brief Does the stored document `a` contain the needle `b`?
--!
--! Native `jsonb @>` over the projections, plus the needle's `alt` projection
--! when it carries one (a root scalar against a stored root array). Both
--! probes are over `{{prefix}}.json_tree_query(a)`, so a GIN index on that
--! expression serves them as one bitmap OR.
--!
--! @param a public.{{prefix}}_json_tree The stored document.
--! @param b {{prefix}}.query_json_tree The needle.
--! @return boolean True when `a` contains `b` as `jsonb @>` would contain the
--!         plaintexts; NULL when either is NULL.
--! @note Deliberately not STRICT. The planner inlines a STRICT SQL function
--!       only when it can prove the body is NULL for a NULL argument, and
--!       `x OR y` is not provably NULL. Un-inlined, the call is an opaque
--!       filter and the GIN index never engages. The body returns NULL for
--!       a NULL argument on its own: a NULL side of `@>` is NULL, and NULL
--!       OR NULL is NULL.
CREATE FUNCTION {{prefix}}.json_tree_contains(a public.{{prefix}}_json_tree, b {{prefix}}.query_json_tree)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$
  SELECT {{prefix}}.json_tree_query(a) @> (b::jsonb - 'alt')
      OR ((b::jsonb ? 'alt') AND {{prefix}}.json_tree_query(a) @> (b::jsonb -> 'alt'))
$$;

--! @brief Is the stored document `a` contained by the needle `b`?
--!
--! The projections the other way round. A stored document carries no `alt`,
--! so a stored root scalar inside a needle root array is the one case this
--! answers false where `jsonb <@` answers true.
--!
--! @param a public.{{prefix}}_json_tree The stored document.
--! @param b {{prefix}}.query_json_tree The needle.
--! @return boolean True when `b` contains `a`.
CREATE FUNCTION {{prefix}}.json_tree_contained_by(a public.{{prefix}}_json_tree, b {{prefix}}.query_json_tree)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT (b::jsonb - 'alt') @> {{prefix}}.json_tree_query(a)
$$;

--! @brief Does the stored document `a` contain the stored document `b`?
--! @param a public.{{prefix}}_json_tree The container.
--! @param b public.{{prefix}}_json_tree The contained document.
--! @return boolean True when `a`'s projection contains `b`'s.
CREATE FUNCTION {{prefix}}.json_tree_document_contains(a public.{{prefix}}_json_tree, b public.{{prefix}}_json_tree)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT {{prefix}}.json_tree_query(a) @> {{prefix}}.json_tree_query(b)
$$;

------------------------------------------------------------------------------
-- The token chain: children and subtrees by token
------------------------------------------------------------------------------

--! The walk, in every function below: for the node in hand, compute the
--! parent tag a child at each ordinal under the document's fan-out would
--! carry, and look each tag up in the document's parent map
--! ({{prefix}}_internal.json_tree_by_parent). A hit is a child; its token
--! unwraps under the parent's and the walk recurses. The map and the
--! document's header fields are computed once per call, so a level costs
--! its fan-out in SHA-256 evaluations and one lookup each, and the
--! document is never scanned per node.

--! @brief The children of the node whose token is `token`, as rows.
--!
--! What `jsonb_array_elements` is for an encrypted array: one row per
--! element, in ordinal order, each opening on its own. Each child's token
--! is unwrapped on the way, though not returned.
--!
--! @param e public.{{prefix}}_json_tree The stored document.
--! @param token text The parent's token, hex: derived by the client from the
--!        path alone, and never stored.
--! @return SETOF public.{{prefix}}_json_tree_entry The children, each with `d = 1`.
CREATE FUNCTION {{prefix}}.json_tree_children(e public.{{prefix}}_json_tree, token text)
  RETURNS SETOF public.{{prefix}}_json_tree_entry
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  WITH
    doc AS MATERIALIZED (
      SELECT {{prefix}}_internal.json_tree_iv(e::jsonb ->> 'h') AS iv,
             {{prefix}}_internal.json_tree_fanout(e::jsonb) AS fanout,
             {{prefix}}_internal.json_tree_by_parent(e::jsonb) AS map,
             {{prefix}}.json_tree_meta(e::jsonb) AS meta
    )
  SELECT (doc.meta || c.entry || '{"d": 1}'::jsonb)::public.{{prefix}}_json_tree_entry
  FROM doc
  CROSS JOIN generate_series(0, doc.fanout - 1) AS o
  CROSS JOIN LATERAL (
    SELECT doc.map -> {{prefix}}_internal.json_tree_parent_tag(doc.iv, decode(token, 'hex'), o) AS entry
  ) AS c
  WHERE c.entry IS NOT NULL
  ORDER BY o
$$;

--! @brief How many children the node whose token is `token` has: the length
--!        of an encrypted array, or the member count of an object.
--! @param e public.{{prefix}}_json_tree The stored document.
--! @param token text The node's token, hex.
--! @return integer The count; `0` for a node with no children, a token that
--!         names no node included.
CREATE FUNCTION {{prefix}}.json_tree_child_count(e public.{{prefix}}_json_tree, token text)
  RETURNS integer
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT count(*)::integer FROM {{prefix}}.json_tree_children(e, token)
$$;

--! @brief Every entry under the node whose token is `token`, as rows: the
--!        recursive walk of the chain, in core SQL.
--!
--! Starting from the token, each level finds its children by parent tag,
--! unwraps their tokens, and recurses. A token that names no node yields no
--! row, and nothing in a row is linkable to anything without the token. The
--! node itself is not returned: the walk addresses nodes by their parent,
--! and the client reads the node's kind from its children's labels, or
--! fetches the node by its selector.
--! The walk descends at most 127 levels, the deepest a sealed document
--! nests, and returns at most as many rows as the document has entries,
--! which a tree never exceeds. A stored document whose tags form a longer
--! chain or a loop therefore still ends it, after at most its entry count
--! times its fan-out in hashes.
--!
--! **The budget.** A walk costs the fan-out in hashes per node it visits,
--! and returns about four hundred characters per entry, where a sealed root
--! holds the whole document in one ciphertext of about the plaintext's
--! size. So when the root is sealed and the subtree has more than `budget`
--! entries, the walk stops and returns the root entry alone, with `d = 0`:
--! the client opens it to the whole document and takes the path itself,
--! which is cheaper on both sides than the walk past that point. The
--! default of 64 is past the crossover by bytes (about a dozen entries) by
--! a margin that keeps a small subtree arriving as the entries it is. A
--! `budget` of `0` never falls back. A token that names no node yields no
--! row under any budget, and a document whose root is not sealed is always
--! walked in full, since its root holds no document to return.
--!
--! @param e public.{{prefix}}_json_tree The stored document.
--! @param token text The subtree's token, hex.
--! @param budget integer The most entries to return before falling back to
--!        the sealed root; `0` to always walk the subtree out. Default 64.
--! @return SETOF public.{{prefix}}_json_tree_entry The descendants, each with its
--!         depth `d` below the node, in depth-first order; or the root
--!         entry alone, with `d = 0`, past the budget.
CREATE FUNCTION {{prefix}}.json_tree_subtree(e public.{{prefix}}_json_tree, token text, budget integer DEFAULT 64)
  RETURNS SETOF public.{{prefix}}_json_tree_entry
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  WITH RECURSIVE
    doc AS MATERIALIZED (
      SELECT {{prefix}}_internal.json_tree_iv(e::jsonb ->> 'h') AS iv,
             {{prefix}}_internal.json_tree_fanout(e::jsonb) AS fanout,
             {{prefix}}_internal.json_tree_by_parent(e::jsonb) AS map,
             {{prefix}}.json_tree_meta(e::jsonb) AS meta,
             e::jsonb -> 'sv' -> 0 AS root,
             jsonb_array_length(e::jsonb -> 'sv') AS entries,
             budget > 0 AND {{prefix}}_internal.json_tree_sealed_root(e::jsonb ->> 'h') AS capped
    ),
    walk(depth, t, entry) AS (
        SELECT 0, decode(token, 'hex'), NULL::jsonb
      UNION ALL
        SELECT w.depth + 1,
               {{prefix}}_internal.json_tree_unwrap(doc.iv, w.t, c.entry),
               c.entry
        FROM walk AS w
        CROSS JOIN doc
        CROSS JOIN generate_series(0, doc.fanout - 1) AS o
        CROSS JOIN LATERAL (
          SELECT doc.map -> {{prefix}}_internal.json_tree_parent_tag(doc.iv, w.t, o) AS entry
        ) AS c
        -- No sealed document nests deeper than 127 levels. A stored one
        -- whose tags form a longer chain, which whoever holds a token can
        -- write, stops here. A cycle that branches is stopped by `visited`.
        WHERE c.entry IS NOT NULL AND w.depth < 127
    ),
    -- A walk of a sealed document reaches each entry at most once, so it
    -- has at most as many rows as the document has entries, the seed row
    -- standing in for the root. A stored document can loop instead: `w`
    -- is not authenticated, so whoever holds a token can wrap a child's
    -- token to its parent's, and two such children double the rows at
    -- every level the depth bound allows. PostgreSQL computes a recursive
    -- query only as far as its reader pulls rows, so this limit stops the
    -- recursion, and not only the output.
    visited AS MATERIALIZED (
      SELECT w.* FROM walk AS w LIMIT (SELECT doc.entries FROM doc)
    ),
    -- One row past the budget is enough to know the walk went over; a walk
    -- under it is the subtree complete. Uncapped, the limit is NULL: all.
    found AS MATERIALIZED (
      SELECT w.depth, w.entry
      FROM visited AS w
      WHERE w.entry IS NOT NULL
      LIMIT (SELECT CASE WHEN doc.capped THEN budget + 1 END FROM doc)
    ),
    over AS MATERIALIZED (
      SELECT doc.capped AND (SELECT count(*) FROM found) > budget AS fallback FROM doc
    )
  SELECT rows.entry
  FROM (
    SELECT 0 AS j,
           (doc.meta || doc.root || '{"j": 0, "d": 0}'::jsonb)::public.{{prefix}}_json_tree_entry AS entry
    FROM doc, over
    WHERE over.fallback
    UNION ALL
    SELECT (f.entry ->> 'j')::integer,
           (doc.meta || f.entry || jsonb_build_object('d', f.depth))::public.{{prefix}}_json_tree_entry
    FROM found AS f, doc, over
    WHERE NOT over.fallback
  ) AS rows
  ORDER BY rows.j
$$;

--! @brief The subtrees under the node whose token is `token` whose path
--!        continues through a node with selector `selector`: how a path
--!        with a wildcard below its last positional step is walked.
--!
--! The walk starts at the token and emits an entry once it has passed
--! through, or reached, an entry carrying the selector: for
--! `$.orders[*].items` it starts at `$.orders` and returns every element's
--! `items` subtree, each complete. The budget is `json_tree_subtree`'s,
--! counted over the entries emitted: past it, the sealed root alone, with
--! `d = 0`, and the client takes the wildcard path over the whole document.
--!
--! @param e public.{{prefix}}_json_tree The stored document.
--! @param token text The anchor's token, hex.
--! @param selector text The whole path's selector, hex.
--! @param budget integer The most entries to return before falling back to
--!        the sealed root; `0` to always walk out. Default 64.
--! @return SETOF public.{{prefix}}_json_tree_entry The matching subtrees' entries,
--!         each with its depth `d` below the anchor, in depth-first order;
--!         or the root entry alone, with `d = 0`, past the budget.
CREATE FUNCTION {{prefix}}.json_tree_subtree_at(e public.{{prefix}}_json_tree, token text, selector text, budget integer DEFAULT 64)
  RETURNS SETOF public.{{prefix}}_json_tree_entry
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  WITH RECURSIVE
    doc AS MATERIALIZED (
      SELECT {{prefix}}_internal.json_tree_iv(e::jsonb ->> 'h') AS iv,
             {{prefix}}_internal.json_tree_fanout(e::jsonb) AS fanout,
             {{prefix}}_internal.json_tree_by_parent(e::jsonb) AS map,
             {{prefix}}.json_tree_meta(e::jsonb) AS meta,
             e::jsonb -> 'sv' -> 0 AS root,
             jsonb_array_length(e::jsonb -> 'sv') AS entries,
             budget > 0 AND {{prefix}}_internal.json_tree_sealed_root(e::jsonb ->> 'h') AS capped
    ),
    walk(depth, t, entry, hit) AS (
        SELECT 0, decode(token, 'hex'), NULL::jsonb, false
      UNION ALL
        SELECT w.depth + 1,
               {{prefix}}_internal.json_tree_unwrap(doc.iv, w.t, c.entry),
               c.entry,
               w.hit OR c.entry ->> 's' = selector
        FROM walk AS w
        CROSS JOIN doc
        CROSS JOIN generate_series(0, doc.fanout - 1) AS o
        CROSS JOIN LATERAL (
          SELECT doc.map -> {{prefix}}_internal.json_tree_parent_tag(doc.iv, w.t, o) AS entry
        ) AS c
        -- No sealed document nests deeper than 127 levels. A stored one
        -- whose tags form a longer chain, which whoever holds a token can
        -- write, stops here. A cycle that branches is stopped by `visited`.
        WHERE c.entry IS NOT NULL AND w.depth < 127
    ),
    -- A walk of a sealed document reaches each entry at most once, so it
    -- has at most as many rows as the document has entries, the seed row
    -- standing in for the root. A stored document can loop instead: `w`
    -- is not authenticated, so whoever holds a token can wrap a child's
    -- token to its parent's, and two such children double the rows at
    -- every level the depth bound allows. PostgreSQL computes a recursive
    -- query only as far as its reader pulls rows, so this limit stops the
    -- recursion, and not only the output.
    visited AS MATERIALIZED (
      SELECT w.* FROM walk AS w LIMIT (SELECT doc.entries FROM doc)
    ),
    found AS MATERIALIZED (
      SELECT w.depth, w.entry
      FROM visited AS w
      WHERE w.entry IS NOT NULL AND w.hit
      LIMIT (SELECT CASE WHEN doc.capped THEN budget + 1 END FROM doc)
    ),
    over AS MATERIALIZED (
      SELECT doc.capped AND (SELECT count(*) FROM found) > budget AS fallback FROM doc
    )
  SELECT rows.entry
  FROM (
    SELECT 0 AS j,
           (doc.meta || doc.root || '{"j": 0, "d": 0}'::jsonb)::public.{{prefix}}_json_tree_entry AS entry
    FROM doc, over
    WHERE over.fallback
    UNION ALL
    SELECT (f.entry ->> 'j')::integer,
           (doc.meta || f.entry || jsonb_build_object('d', f.depth))::public.{{prefix}}_json_tree_entry
    FROM found AS f, doc, over
    WHERE NOT over.fallback
  ) AS rows
  ORDER BY rows.j
$$;

------------------------------------------------------------------------------
-- Ordering at a path
------------------------------------------------------------------------------

--! @brief The path selector of an entry.
--! @param entry public.{{prefix}}_json_tree_entry The entry.
--! @return text Its `s`, hex.
CREATE FUNCTION {{prefix}}.selector(entry public.{{prefix}}_json_tree_entry)
  RETURNS text
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT entry ->> 's'
$$;

--! @brief The leaf ordering term of an entry, for ordered comparison.
--!
--! The CLLW OPE term the index derived for a number or string leaf, keyed by
--! the column, hex-decoded to the bytea-backed `{{prefix}}_internal.ope_cllw`
--! domain: native byte order is plaintext order, so a functional btree on
--! `{{prefix}}.ord_term(col -> 'selector')` engages with the DEFAULT opclass. NULL
--! for an entry with no term (a container, a boolean, a null), which btree's
--! NULL handling drops from range queries.
--!
--! Order rows by this, `ORDER BY {{prefix}}.ord_term(col -> 'sel')`, never by
--! the entry itself: `ORDER BY col -> 'sel'` uses jsonb's default ordering of
--! the entry object, which sorts by ciphertext, and an operator class that
--! would redirect it needs a superuser to install.
--!
--! @param entry public.{{prefix}}_json_tree_entry The entry.
--! @return {{prefix}}_internal.ope_cllw The term, or NULL.
CREATE FUNCTION {{prefix}}.ord_term(entry public.{{prefix}}_json_tree_entry)
  RETURNS {{prefix}}_internal.ope_cllw
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT {{prefix}}_internal.ope_cllw(entry::jsonb)
$$;

--! @brief The leaf ordering term of an ordering operand.
--! @param q {{prefix}}.query_json_tree_leaf The operand.
--! @return {{prefix}}_internal.ope_cllw Its `op`, hex-decoded.
CREATE FUNCTION {{prefix}}.ord_term(q {{prefix}}.query_json_tree_leaf)
  RETURNS {{prefix}}_internal.ope_cllw
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT {{prefix}}_internal.ope_cllw(q::jsonb)
$$;

--! @brief The path selector of an ordering operand: what `->` takes to reach
--!        the leaf the operand compares against.
--! @param q {{prefix}}.query_json_tree_leaf The operand.
--! @return text Its `s`, hex.
CREATE FUNCTION {{prefix}}.selector(q {{prefix}}.query_json_tree_leaf)
  RETURNS text
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT q ->> 's'
$$;
