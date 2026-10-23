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
--!        largest ordinal any entry of the document carries.
--! @internal
--! @param val jsonb The document.
--! @return integer The fan-out bound; `0` for a document with no chained
--!         entry.
CREATE FUNCTION {{prefix}}_internal.json_tree_fanout(val jsonb)
  RETURNS integer
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT COALESCE(MAX((elem ->> 'o')::integer), -1) + 1
  FROM jsonb_array_elements(val -> 'sv') AS elem
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

--! @brief The first entry whose path selector is `selector`, or NULL.
--! @param val jsonb The document.
--! @param selector text The path selector, hex.
--! @return public.{{prefix}}_json_tree_entry The entry, or NULL when the document
--!         has no node at that path.
CREATE FUNCTION {{prefix}}.json_tree_path_query_first(val jsonb, selector text)
  RETURNS public.{{prefix}}_json_tree_entry
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
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

--! @brief One group of a stored document's projection, from its group tags.
--! @internal
--!
--! An entry belongs to the group of its own tag `n` when it is an array
--! element that is a container, else to the group of its enclosing element's
--! tag `g`, else to the top level. A group's `el` holds one nested group per
--! container element whose `g` is the group's tag. The needle is projected
--! the same way by the client, from its structure, so `jsonb @>` over the two
--! is PostgreSQL's own containment rule: each needle element has to fit
--! inside one stored element.
--!
--! @param sv jsonb The document's `sv` array.
--! @param parent text The group's tag, hex, or NULL for the top level.
--! @return jsonb `{"sv": [{"s", "vs"}, …], "el": [group, …]}`.
--! @note plpgsql: recursive. IMMUTABLE and deterministic (document order), so
--!       `{{prefix}}.json_tree_query` over it serves an expression index.
CREATE FUNCTION {{prefix}}_internal.json_tree_group(sv jsonb, parent text)
  RETURNS jsonb
  LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE
AS $$
DECLARE
  pairs jsonb;
  groups jsonb;
BEGIN
  SELECT COALESCE(jsonb_agg(jsonb_build_object('s', elem -> 's', 'vs', elem -> 'vs') ORDER BY ord), '[]'::jsonb)
    INTO pairs
    FROM jsonb_array_elements(sv) WITH ORDINALITY AS t(elem, ord)
   WHERE COALESCE(elem ->> 'n', elem ->> 'g') IS NOT DISTINCT FROM parent;
  SELECT COALESCE(jsonb_agg({{prefix}}_internal.json_tree_group(sv, elem ->> 'n') ORDER BY ord), '[]'::jsonb)
    INTO groups
    FROM jsonb_array_elements(sv) WITH ORDINALITY AS t(elem, ord)
   WHERE elem ? 'n' AND (elem ->> 'g') IS NOT DISTINCT FROM parent;
  RETURN jsonb_build_object('sv', pairs, 'el', groups);
END;
$$;

--! @brief Project a stored document into its containment shape: the needle
--!        shape `{{prefix}}.query_json_tree` holds, from the document's group
--!        tags.
--!
--! This is the GIN index expression for containment:
--!   `CREATE INDEX … USING gin (({{prefix}}.json_tree_query(col)::jsonb) jsonb_path_ops);`
--! The typed `@>` inlines to native `jsonb @>` over the same expression, so
--! the index engages; GIN is lossy and the executor rechecks the real
--! operator on the heap tuple, which is the exact containment.
--!
--! @param e public.{{prefix}}_json_tree The stored document.
--! @return {{prefix}}.query_json_tree Its projection.
CREATE FUNCTION {{prefix}}.json_tree_query(e public.{{prefix}}_json_tree)
  RETURNS {{prefix}}.query_json_tree
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT {{prefix}}_internal.json_tree_group(e::jsonb -> 'sv', NULL)::{{prefix}}.query_json_tree
$$;

--! @brief Does the stored document `a` contain the needle `b`?
--!
--! Native `jsonb @>` over the projections, plus the needle's `alt` projection
--! when it carries one (a root scalar against a stored root array). Both
--! probes are over `{{prefix}}.json_tree_query(a)::jsonb`, so a GIN index on
--! that expression serves them as one bitmap OR.
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
  SELECT {{prefix}}.json_tree_query(a)::jsonb @> (b::jsonb - 'alt')
      OR ((b::jsonb ? 'alt') AND {{prefix}}.json_tree_query(a)::jsonb @> (b::jsonb -> 'alt'))
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
  SELECT (b::jsonb - 'alt') @> {{prefix}}.json_tree_query(a)::jsonb
$$;

--! @brief Does the stored document `a` contain the stored document `b`?
--! @param a public.{{prefix}}_json_tree The container.
--! @param b public.{{prefix}}_json_tree The contained document.
--! @return boolean True when `a`'s projection contains `b`'s.
CREATE FUNCTION {{prefix}}.json_tree_document_contains(a public.{{prefix}}_json_tree, b public.{{prefix}}_json_tree)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT {{prefix}}.json_tree_query(a)::jsonb @> {{prefix}}.json_tree_query(b)::jsonb
$$;

------------------------------------------------------------------------------
-- The token chain: children and subtrees by token
------------------------------------------------------------------------------

--! @brief The children of the node whose token is `token`, as rows.
--!
--! For every ordinal under the document's fan-out, the parent tag the child
--! at that ordinal would carry; the entries carrying one are the children,
--! and each row's token is unwrapped on the way, though not returned. What
--! `jsonb_array_elements` is for an encrypted array: one row per element, in
--! ordinal order, each opening on its own.
--!
--! @param e public.{{prefix}}_json_tree The stored document.
--! @param token text The parent's token, hex: derived by the client from the
--!        path alone, and never stored.
--! @return SETOF public.{{prefix}}_json_tree_entry The children, each with `d = 1`.
CREATE FUNCTION {{prefix}}.json_tree_children(e public.{{prefix}}_json_tree, token text)
  RETURNS SETOF public.{{prefix}}_json_tree_entry
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT ({{prefix}}_internal.json_tree_graft(e::jsonb, c.elem, (c.ord - 1)::integer)::jsonb || '{"d": 1}'::jsonb)::public.{{prefix}}_json_tree_entry
  FROM generate_series(0, {{prefix}}_internal.json_tree_fanout(e::jsonb) - 1) AS o
  JOIN LATERAL (
    SELECT elem, ord
    FROM jsonb_array_elements(e::jsonb -> 'sv') WITH ORDINALITY AS t(elem, ord)
    WHERE elem ->> 'p' = {{prefix}}_internal.json_tree_parent_tag(
      {{prefix}}_internal.json_tree_iv(e::jsonb ->> 'h'), decode(token, 'hex'), o)
  ) AS c ON true
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
--! nests, so a stored document whose tags do not form a tree still ends it.
--!
--! @param e public.{{prefix}}_json_tree The stored document.
--! @param token text The subtree's token, hex.
--! @return SETOF public.{{prefix}}_json_tree_entry The descendants, each with its
--!         depth `d` below the node, in depth-first order.
CREATE FUNCTION {{prefix}}.json_tree_subtree(e public.{{prefix}}_json_tree, token text)
  RETURNS SETOF public.{{prefix}}_json_tree_entry
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  WITH RECURSIVE
    doc AS (
      SELECT e::jsonb AS val,
             {{prefix}}_internal.json_tree_iv(e::jsonb ->> 'h') AS iv,
             {{prefix}}_internal.json_tree_fanout(e::jsonb) AS fanout
    ),
    walk(depth, t, j, entry, path) AS (
        SELECT 0, decode(token, 'hex'), NULL::integer, NULL::jsonb, ARRAY[]::integer[]
      UNION ALL
        SELECT w.depth + 1,
               {{prefix}}_internal.json_tree_unwrap(doc.iv, w.t, c.elem),
               (c.ord - 1)::integer,
               c.elem,
               w.path || (c.ord - 1)::integer
        FROM walk AS w
        CROSS JOIN doc
        JOIN LATERAL (
          SELECT elem, ord
          FROM generate_series(0, doc.fanout - 1) AS o
          JOIN LATERAL (
            SELECT elem, ord
            FROM jsonb_array_elements(doc.val -> 'sv') WITH ORDINALITY AS t(elem, ord)
            WHERE elem ->> 'p' = {{prefix}}_internal.json_tree_parent_tag(doc.iv, w.t, o)
          ) AS hit ON true
        ) AS c ON true
        -- No sealed document nests deeper than 127 levels. A stored one
        -- whose tags form a cycle or a longer chain, which whoever holds a
        -- token can write, stops here instead of recursing without end.
        WHERE w.depth < 127
    )
  SELECT ({{prefix}}_internal.json_tree_graft(doc.val, w.entry, w.j)::jsonb || jsonb_build_object('d', w.depth))::public.{{prefix}}_json_tree_entry
  FROM walk AS w CROSS JOIN doc
  WHERE w.entry IS NOT NULL
  ORDER BY w.path
$$;

--! @brief The subtrees under the node whose token is `token` whose path
--!        continues through a node with selector `selector`: how a path
--!        with a wildcard below its last positional step is walked.
--!
--! The walk starts at the token and emits an entry once it has passed
--! through, or reached, an entry carrying the selector: for
--! `$.orders[*].items` it starts at `$.orders` and returns every element's
--! `items` subtree, each complete.
--!
--! @param e public.{{prefix}}_json_tree The stored document.
--! @param token text The anchor's token, hex.
--! @param selector text The whole path's selector, hex.
--! @return SETOF public.{{prefix}}_json_tree_entry The matching subtrees' entries,
--!         each with its depth `d` below the anchor, in depth-first order.
CREATE FUNCTION {{prefix}}.json_tree_subtree_at(e public.{{prefix}}_json_tree, token text, selector text)
  RETURNS SETOF public.{{prefix}}_json_tree_entry
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  WITH RECURSIVE
    doc AS (
      SELECT e::jsonb AS val,
             {{prefix}}_internal.json_tree_iv(e::jsonb ->> 'h') AS iv,
             {{prefix}}_internal.json_tree_fanout(e::jsonb) AS fanout
    ),
    walk(depth, t, j, entry, path, hit) AS (
        SELECT 0, decode(token, 'hex'), NULL::integer, NULL::jsonb, ARRAY[]::integer[], false
      UNION ALL
        SELECT w.depth + 1,
               {{prefix}}_internal.json_tree_unwrap(doc.iv, w.t, c.elem),
               (c.ord - 1)::integer,
               c.elem,
               w.path || (c.ord - 1)::integer,
               w.hit OR c.elem ->> 's' = selector
        FROM walk AS w
        CROSS JOIN doc
        JOIN LATERAL (
          SELECT elem, ord
          FROM generate_series(0, doc.fanout - 1) AS o
          JOIN LATERAL (
            SELECT elem, ord
            FROM jsonb_array_elements(doc.val -> 'sv') WITH ORDINALITY AS t(elem, ord)
            WHERE elem ->> 'p' = {{prefix}}_internal.json_tree_parent_tag(doc.iv, w.t, o)
          ) AS hit ON true
        ) AS c ON true
        -- No sealed document nests deeper than 127 levels. A stored one
        -- whose tags form a cycle or a longer chain, which whoever holds a
        -- token can write, stops here instead of recursing without end.
        WHERE w.depth < 127
    )
  SELECT ({{prefix}}_internal.json_tree_graft(doc.val, w.entry, w.j)::jsonb || jsonb_build_object('d', w.depth))::public.{{prefix}}_json_tree_entry
  FROM walk AS w CROSS JOIN doc
  WHERE w.entry IS NOT NULL AND w.hit
  ORDER BY w.path
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
