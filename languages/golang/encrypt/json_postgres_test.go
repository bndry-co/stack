package encrypt_test

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"slices"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/eql"
	"github.com/cipherstash/stack/languages/golang/encrypt/internal/testusers"
)

// Encrypted JSON documents (JsonSearch, public.eql_v4_json_search) the Go
// SDK stores, found by the queries its generated methods derive and read by
// its selections and reads, inside PostgreSQL with EQL v4 installed. Each
// query's rows are the ones the plaintexts say. Skipped unless DATABASE_URL
// is set, as eql_postgres_test.go is.

var jsonCustomers = []testusers.Customer{
	{ID: 1, Profile: json.RawMessage(`{"name":"Alice","age":34,"visits":[{"at":3},{"at":1}],"tags":["a"]}`), Prefs: rawPtr(`{"theme":"dark"}`)},
	{ID: 2, Profile: json.RawMessage(`{"name":"Bob","age":7,"visits":[{"at":5}]}`)},
	{ID: 3, Profile: json.RawMessage(`{"name":"Carol","age":61,"visits":[]}`), Prefs: rawPtr(`null`)},
	{ID: 4, Profile: json.RawMessage(`{"name":"Dan"}`)},
}

func TestJSONDocumentsQueryAndReadInPostgres(t *testing.T) {
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL is not set")
	}
	ctx := context.Background()
	c := deterministicEQLClient(t)
	cipher := c.DefaultKeyset()
	conn := eqlPostgresConn(t, ctx, url)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := conn.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	exec(`CREATE TEMP TABLE customers (id bigint PRIMARY KEY, profile public.eql_v4_json_search NOT NULL, prefs public.eql_v4_json_search)`)
	t.Cleanup(func() { _, _ = conn.ExecContext(context.Background(), `DROP TABLE IF EXISTS customers`) })
	encrypted, err := testusers.EncryptCustomer(ctx, cipher, jsonCustomers)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range encrypted {
		// Each value binds through its driver.Valuer; a nil Prefs is NULL.
		exec(`INSERT INTO customers VALUES ($1, $2, $3)`, e.ID, e.Profile, e.Prefs)
	}
	ids := func(q string, args ...any) []int64 {
		t.Helper()
		rows, err := conn.QueryContext(ctx, q, args...)
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		defer rows.Close()
		var out []int64
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				t.Fatal(err)
			}
			out = append(out, id)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	want := func(name string, got []int64, want ...int64) {
		t.Helper()
		if !slices.Equal(got, want) {
			t.Errorf("%s: rows %v, want %v", name, got, want)
		}
	}
	f := testusers.CustomerFields.Profile
	must := func(v []byte, err error) []byte {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return v
	}

	// Stored values read back, re-serialised by PostgreSQL, open as they were.
	rows, err := conn.QueryContext(ctx, `SELECT id, profile, prefs FROM customers ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	var stored []testusers.EncryptedCustomer
	for rows.Next() {
		var e testusers.EncryptedCustomer
		if err := rows.Scan(&e.ID, &e.Profile, &e.Prefs); err != nil {
			t.Fatal(err)
		}
		stored = append(stored, e)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	_ = rows.Close()
	back, err := testusers.DecryptCustomer(ctx, c, stored)
	if err != nil {
		t.Fatal(err)
	}
	for i := range jsonCustomers {
		if !sameJSON(t, back[i].Profile, jsonCustomers[i].Profile) || (back[i].Prefs == nil) != (jsonCustomers[i].Prefs == nil) {
			t.Fatalf("row %d read back as %s %v", i, back[i].Profile, back[i].Prefs)
		}
	}

	// Containment, both ways.
	q := eql.JSONSearchQuery(must(f.Contains(ctx, cipher, json.RawMessage(`{"name":"Alice"}`))))
	want("contains name", ids(`SELECT id FROM customers WHERE profile @> $1::eql_v4.query_json ORDER BY id`, q), 1)
	q = eql.JSONSearchQuery(must(f.Contains(ctx, cipher, json.RawMessage(`{"visits":[{"at":5}]}`))))
	want("contains an element", ids(`SELECT id FROM customers WHERE profile @> $1::eql_v4.query_json ORDER BY id`, q), 2)
	q = eql.JSONSearchQuery(must(f.ContainedBy(ctx, cipher, json.RawMessage(`{"name":"Dan","x":1}`))))
	want("contained by", ids(`SELECT id FROM customers WHERE profile <@ $1::eql_v4.query_json ORDER BY id`, q), 4)
	// Equality at a wildcard path matches any element.
	q = eql.JSONSearchQuery(must(f.EqAt(ctx, cipher, "$.visits[*].at", json.RawMessage(`1`))))
	want("eq_at", ids(`SELECT id FROM customers WHERE profile @> $1::eql_v4.query_json ORDER BY id`, q), 1)
	// Containment on the optional column: SQL NULL rows match nothing.
	pq, err := testusers.CustomerFields.Prefs.Contains(ctx, cipher, json.RawMessage(`{"theme":"dark"}`))
	if err != nil {
		t.Fatal(err)
	}
	want("prefs contains", ids(`SELECT id FROM customers WHERE prefs @> $1::eql_v4.query_json ORDER BY id`, pq), 1)

	// Orderings at an ordered path compare the leaf `->` extracts there,
	// selected by the accessor's own Selector, so the path is named once.
	age, err := f.At.Age.Selector(ctx, cipher)
	if err != nil {
		t.Fatal(err)
	}
	lt, err := f.At.Age.Lt(ctx, cipher, json.RawMessage(`40`))
	if err != nil {
		t.Fatal(err)
	}
	want("age < 40", ids(`SELECT id FROM customers WHERE (profile -> $1::text) < $2::eql_v4.query_json_leaf ORDER BY id`, age.Selector(), lt), 1, 2)
	rng, err := f.At.Age.Between(ctx, cipher, json.RawMessage(`30`), json.RawMessage(`70`))
	if err != nil {
		t.Fatal(err)
	}
	want("age between", ids(`SELECT id FROM customers WHERE (profile -> $1::text) >= $2::eql_v4.query_json_leaf AND (profile -> $1::text) <= $3::eql_v4.query_json_leaf ORDER BY id`, age.Selector(), rng.Low, rng.High), 1, 3)
	at, err := f.At.VisitsAt.Selector(ctx, cipher)
	if err != nil {
		t.Fatal(err)
	}
	gt, err := f.At.VisitsAt.Gt(ctx, cipher, json.RawMessage(`2`))
	if err != nil {
		t.Fatal(err)
	}
	want("first visit > 2", ids(`SELECT id FROM customers WHERE (profile -> $1::text) > $2::eql_v4.query_json_leaf ORDER BY id`, at.Selector(), gt), 1, 2)

	// `->` opened against the selection that asked for it: each row's
	// value, and no value where the row has none.
	selected := func(sel encrypt.JSONSelection[eql.JSONEntry]) []encrypt.JSONValue {
		t.Helper()
		rows, err := conn.QueryContext(ctx, `SELECT profile -> $1::text FROM customers ORDER BY id`, sel.Selector())
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var entries []*eql.JSONEntry
		for rows.Next() {
			var e *eql.JSONEntry
			if err := rows.Scan(&e); err != nil {
				t.Fatal(err)
			}
			entries = append(entries, e)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		values, err := sel.Open(ctx, entries)
		if err != nil {
			t.Fatal(err)
		}
		return values
	}
	name, err := f.Selector(ctx, cipher, "$.name")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, v := range selected(name) {
		names = append(names, string(v.JSON))
	}
	if !slices.Equal(names, []string{`"Alice"`, `"Bob"`, `"Carol"`, `"Dan"`}) {
		t.Errorf("->: %v", names)
	}
	ages := selected(age)
	if !ages[0].Found || string(ages[0].JSON) != "34" || ages[3].Found {
		t.Errorf("-> $.age: %+v", ages)
	}

	// A subtree read: per row, every visit's `at`, in document order, with
	// the walk and with the sealed-root fallback a budget of 1 forces.
	read, err := f.Subtree(ctx, cipher, "$.visits[*].at", encrypt.JSONReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	walk := func(budget int) [][]json.RawMessage {
		t.Helper()
		groups := make([][]eql.JSONEntry, len(jsonCustomers))
		for i, cust := range jsonCustomers {
			rows, err := conn.QueryContext(ctx, `SELECT e FROM customers, eql_v4.json_tree_subtree(profile, $2::text[], $3) AS e WHERE id = $1`, cust.ID, read.Tokens(), budget)
			if err != nil {
				t.Fatal(err)
			}
			for rows.Next() {
				var e eql.JSONEntry
				if err := rows.Scan(&e); err != nil {
					t.Fatal(err)
				}
				groups[i] = append(groups[i], e)
			}
			if err := rows.Err(); err != nil {
				t.Fatal(err)
			}
			_ = rows.Close()
		}
		opened, err := read.Open(ctx, groups)
		if err != nil {
			t.Fatal(err)
		}
		return opened
	}
	text := func(groups [][]json.RawMessage) [][]string {
		out := make([][]string, len(groups))
		for i, g := range groups {
			out[i] = []string{}
			for _, v := range g {
				out[i] = append(out[i], string(v))
			}
		}
		return out
	}
	wantAts := [][]string{{"3", "1"}, {"5"}, {}, {}}
	for _, budget := range []int{64, 1} {
		if got := text(walk(budget)); !slicesEqual2(got, wantAts) {
			t.Errorf("subtree with budget %d: %v, want %v", budget, got, wantAts)
		}
	}

	// A concrete read of a container, opened to one value or none.
	visits, err := f.Subtree(ctx, cipher, "$.visits", encrypt.JSONReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var entries []eql.JSONEntry
	rs, err := conn.QueryContext(ctx, `SELECT e FROM customers, eql_v4.json_tree_subtree(profile, $1::text[]) AS e WHERE id = 1`, visits.Tokens())
	if err != nil {
		t.Fatal(err)
	}
	for rs.Next() {
		var e eql.JSONEntry
		if err := rs.Scan(&e); err != nil {
			t.Fatal(err)
		}
		entries = append(entries, e)
	}
	if err := rs.Err(); err != nil {
		t.Fatal(err)
	}
	_ = rs.Close()
	one, err := visits.OpenOne(ctx, entries)
	if err != nil || !one.Found || !sameJSON(t, one.JSON, []byte(`[{"at":3},{"at":1}]`)) {
		t.Errorf("OpenOne $.visits: %+v %v", one, err)
	}

	// Child counts: two visits, one, an empty array, and none.
	token, err := f.ChildCount(ctx, cipher, "$.visits")
	if err != nil {
		t.Fatal(err)
	}
	cr, err := conn.QueryContext(ctx, `SELECT eql_v4.json_tree_child_count(profile, $1::text) FROM customers ORDER BY id`, token)
	if err != nil {
		t.Fatal(err)
	}
	var counts []string
	for cr.Next() {
		var n sql.NullInt64
		if err := cr.Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n.Valid {
			counts = append(counts, string(rune('0'+n.Int64)))
		} else {
			counts = append(counts, "NULL")
		}
	}
	if err := cr.Err(); err != nil {
		t.Fatal(err)
	}
	_ = cr.Close()
	if !slices.Equal(counts, []string{"2", "1", "0", "NULL"}) {
		t.Errorf("child counts: %v", counts)
	}
	children, err := f.Children(ctx, cipher, "$.visits")
	if err != nil {
		t.Fatal(err)
	}
	want("children rows", ids(`SELECT id FROM customers, eql_v4.json_tree_children(profile, $1::text) AS e ORDER BY id`, children), 1, 1, 2)

	// Sorting by an ordered path, in the form EQL documents:
	// ORDER BY eql_v4.ord_term(col -> sel). Ordering by the entry itself
	// would sort by its ciphertext. Two more rows give each path a tie,
	// broken by id, and Eve's visits (first 2, last 9) tell the first match
	// `->` takes at the wildcard path from the least or greatest element.
	more := []testusers.Customer{
		{ID: 5, Profile: json.RawMessage(`{"name":"Eve","age":34,"visits":[{"at":2},{"at":9}]}`)},
		{ID: 6, Profile: json.RawMessage(`{"name":"Fay","age":7,"visits":[{"at":3}]}`)},
	}
	extra, err := testusers.EncryptCustomer(ctx, cipher, more)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range extra {
		exec(`INSERT INTO customers VALUES ($1, $2, $3)`, e.ID, e.Profile, e.Prefs)
	}
	type plain struct {
		Age    *float64 `json:"age"`
		Visits []struct {
			At *float64 `json:"at"`
		} `json:"visits"`
	}
	ageOf := func(p plain) *float64 { return p.Age }
	firstAtOf := func(p plain) *float64 {
		for _, v := range p.Visits {
			if v.At != nil {
				return v.At
			}
		}
		return nil
	}
	// The ids in the order PostgreSQL's defaults put the plaintexts in: a
	// row with no value at the path has a NULL term, which sorts as the
	// greatest value, so last ascending and first descending; ties by id.
	plaintextOrder := func(key func(plain) *float64, desc bool) []int64 {
		type row struct {
			id int64
			v  *float64
		}
		var rows []row
		for _, cust := range append(slices.Clone(jsonCustomers), more...) {
			var p plain
			if err := json.Unmarshal(cust.Profile, &p); err != nil {
				t.Fatal(err)
			}
			rows = append(rows, row{cust.ID, key(p)})
		}
		slices.SortFunc(rows, func(a, b row) int {
			var c int
			switch {
			case a.v == nil && b.v == nil:
			case a.v == nil:
				c = 1
			case b.v == nil:
				c = -1
			default:
				c = cmp.Compare(*a.v, *b.v)
			}
			if desc {
				c = -c
			}
			if c == 0 {
				c = cmp.Compare(a.id, b.id)
			}
			return c
		})
		out := make([]int64, len(rows))
		for i, r := range rows {
			out[i] = r.id
		}
		return out
	}
	for _, tc := range []struct {
		name      string
		selector  encrypt.JSONSelector
		key       func(plain) *float64
		asc, desc []int64 // what plaintextOrder gives, written out
	}{
		// Bob and Fay tie at 7, Alice and Eve at 34; Dan has no age.
		{"$.age", age.Selector(), ageOf, []int64{2, 6, 1, 5, 3, 4}, []int64{4, 3, 1, 5, 2, 6}},
		// First visits: Eve 2, Alice and Fay 3, Bob 5; Carol's visits are
		// empty and Dan has none.
		{"$.visits[*].at", at.Selector(), firstAtOf, []int64{5, 1, 6, 2, 3, 4}, []int64{3, 4, 2, 1, 6, 5}},
	} {
		asc, desc := plaintextOrder(tc.key, false), plaintextOrder(tc.key, true)
		want("plaintext order by "+tc.name, asc, tc.asc...)
		want("plaintext order by "+tc.name+" DESC", desc, tc.desc...)
		want("ORDER BY "+tc.name, ids(`SELECT id FROM customers ORDER BY eql_v4.ord_term(profile -> $1::text), id`, tc.selector), asc...)
		want("ORDER BY "+tc.name+" DESC", ids(`SELECT id FROM customers ORDER BY eql_v4.ord_term(profile -> $1::text) DESC, id`, tc.selector), desc...)
	}
}

func slicesEqual2(a, b [][]string) bool {
	return slices.EqualFunc(a, b, func(x, y []string) bool { return slices.Equal(x, y) })
}
