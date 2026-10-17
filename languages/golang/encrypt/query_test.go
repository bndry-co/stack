package encrypt_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/internal/record"
	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// The query fixture holds the guest's query exports to the Rust results:
// packages/stack-encrypt/tests/fixtures/query_operators.json records, for one
// declaration, the term each query by operator derives (each equal to the
// typed Rust query chain's), a page of verified values and a few fetch
// limits. These tests derive, verify and size the same queries through the
// deterministic test build of the guest and compare. Skipped when that build
// is absent.

type queryFixture struct {
	KeySource struct {
		Seed string `json:"seed"`
	} `json:"key_source"`
	Plan    json.RawMessage `json:"plan"`
	Queries []struct {
		Field    string          `json:"field"`
		Operator string          `json:"operator"`
		Input    json.RawMessage `json:"input"`
		Term     struct {
			Operator string          `json:"operator"`
			Fidelity string          `json:"fidelity"`
			Index    string          `json:"index"`
			Domain   *string         `json:"domain"`
			Term     json.RawMessage `json:"term"`
		} `json:"term"`
	} `json:"queries"`
	Verify struct {
		Field    string    `json:"field"`
		Operator string    `json:"operator"`
		Input    string    `json:"input"`
		Values   []*string `json:"values"`
		Verified []bool    `json:"verified"`
	} `json:"verify"`
	TargetLimit []struct {
		Field    string `json:"field"`
		Operator string `json:"operator"`
		Term     string `json:"term"`
		Want     uint64 `json:"want"`
		Stats    struct {
			Rows       uint64      `json:"rows"`
			Histogram  [][2]uint64 `json:"histogram"`
			Confidence float64     `json:"confidence"`
		} `json:"stats"`
		Limit *uint64 `json:"limit"`
	} `json:"target_limit"`
}

func readQueryFixture(t *testing.T) queryFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "packages", "stack-encrypt", "tests", "fixtures", "query_operators.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f queryFixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	// The terms are derived under queryPlan: a fixture recorded under any
	// other plan fails here, by name, rather than as mismatched bytes.
	var recorded any
	if err := json.Unmarshal(f.Plan, &recorded); err != nil {
		t.Fatal(err)
	}
	if want := wireJSON(queryPlan.Wire()); !reflect.DeepEqual(recorded, want) {
		t.Fatalf("the fixture's plan is not queryPlan; update queryPlan to match it:\nfixture:   %v\nqueryPlan: %v", recorded, want)
	}
	return f
}

// wireJSON is a plan's wire form as encoding/json decodes the same JSON:
// objects as maps, lists as []any.
func wireJSON(v any) any {
	switch v := v.(type) {
	case vcvalue.Object:
		out := make(map[string]any, len(v))
		for _, f := range v {
			out[f.Key] = wireJSON(f.Value)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = wireJSON(item)
		}
		return out
	}
	return v
}

// queryPlan is the fixture's declaration: an email with equality, an age
// with equality and ORE, a name with match, all under users.
var queryPlan = &record.Plan{Context: []string{"users"}, Fields: []record.Field{
	{Name: "email", Kind: record.String, Outputs: []record.Output{record.Ciphertext, record.Equality}},
	{Name: "age", Kind: record.Uint32, Outputs: []record.Output{record.Ciphertext, record.Equality, record.Ore}},
	{Name: "name", Kind: record.String, Outputs: []record.Output{record.Ciphertext, record.Match}},
}}

func queryFixtureClient(t *testing.T, f queryFixture) *encrypt.Client {
	t.Helper()
	seed, err := hex.DecodeString(f.KeySource.Seed)
	if err != nil || len(seed) != 32 {
		t.Fatalf("seed: %v (%d bytes)", err, len(seed))
	}
	c, err := encrypt.NewDeterministicClient(context.Background(), [32]byte(seed))
	if errors.Is(err, encrypt.ErrDeterministicGuestNotBuilt) || errors.Is(err, encrypt.ErrGuestNotBuilt) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// goInput is a fixture input as Go code passes it: text as a string, an
// age as the field's uint32, a range as two of them.
func goInput(t *testing.T, field string, raw json.RawMessage) any {
	t.Helper()
	if field != "age" {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	var n uint32
	if err := json.Unmarshal(raw, &n); err == nil {
		return n
	}
	var pair [2]uint32
	if err := json.Unmarshal(raw, &pair); err != nil {
		t.Fatal(err)
	}
	return []any{pair[0], pair[1]}
}

func fixtureTerms(t *testing.T, raw json.RawMessage) [][]byte {
	t.Helper()
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		b, err := hex.DecodeString(one)
		if err != nil {
			t.Fatal(err)
		}
		return [][]byte{b}
	}
	var pair []string
	if err := json.Unmarshal(raw, &pair); err != nil {
		t.Fatal(err)
	}
	out := make([][]byte, len(pair))
	for i, s := range pair {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		out[i] = b
	}
	return out
}

func TestQueryTermsAreTheRustFixtures(t *testing.T) {
	f := readQueryFixture(t)
	c := queryFixtureClient(t, f)
	ctx := context.Background()
	cipher := c.DefaultKeyset()
	if len(f.Queries) == 0 {
		t.Fatal("the fixture holds no query")
	}
	for _, q := range f.Queries {
		got, err := cipher.QueryTerm(ctx, queryPlan, q.Field, q.Operator, goInput(t, q.Field, q.Input))
		if err != nil {
			t.Fatalf("%s on %s: %v", q.Operator, q.Field, err)
		}
		want := encrypt.QueryTerm{
			Operator: q.Term.Operator,
			Fidelity: record.Fidelity(q.Term.Fidelity),
			Index:    record.Output(q.Term.Index),
			Terms:    fixtureTerms(t, q.Term.Term),
		}
		if q.Term.Domain != nil {
			want.Domain = *q.Term.Domain
		}
		if got.Operator != want.Operator || got.Fidelity != want.Fidelity || got.Index != want.Index || got.Domain != want.Domain || len(got.Terms) != len(want.Terms) {
			t.Fatalf("%s on %s: %+v, want %+v", q.Operator, q.Field, got, want)
		}
		for i := range want.Terms {
			if hex.EncodeToString(got.Terms[i]) != hex.EncodeToString(want.Terms[i]) {
				t.Fatalf("%s on %s: term %d = %x, want %x", q.Operator, q.Field, i, got.Terms[i], want.Terms[i])
			}
		}
	}

	// The engine reads the input as the field's type: a Go int queries a
	// uint32 field as the uint32 it stored.
	asUint32, err := cipher.QueryTerm(ctx, queryPlan, "age", "lt", uint32(40))
	if err != nil {
		t.Fatal(err)
	}
	asInt, err := cipher.QueryTerm(ctx, queryPlan, "age", "lt", 40)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(asInt.Terms[0]) != hex.EncodeToString(asUint32.Terms[0]) {
		t.Fatal("an int input derived another term than the field's uint32")
	}
}

func TestVerifyIsTheRustFixtures(t *testing.T) {
	f := readQueryFixture(t)
	c := queryFixtureClient(t, f)
	values := make([]any, len(f.Verify.Values))
	for i, v := range f.Verify.Values {
		if v != nil {
			values[i] = *v
		}
	}
	verified, err := c.DefaultKeyset().Verify(context.Background(), queryPlan, f.Verify.Field, f.Verify.Operator, f.Verify.Input, values)
	if err != nil {
		t.Fatal(err)
	}
	if len(verified) != len(f.Verify.Verified) {
		t.Fatalf("Verify = %v, want %v", verified, f.Verify.Verified)
	}
	for i := range verified {
		if verified[i] != f.Verify.Verified[i] {
			t.Fatalf("Verify = %v, want %v", verified, f.Verify.Verified)
		}
	}
	empty, err := c.DefaultKeyset().Verify(context.Background(), queryPlan, "name", "matches", "alice", nil)
	if err != nil || len(empty) != 0 {
		t.Fatalf("an empty page: %v %v", empty, err)
	}
}

func TestTargetLimitIsTheRustFixtures(t *testing.T) {
	f := readQueryFixture(t)
	c := queryFixtureClient(t, f)
	if len(f.TargetLimit) == 0 {
		t.Fatal("the fixture holds no limit")
	}
	for i, l := range f.TargetLimit {
		term, err := hex.DecodeString(l.Term)
		if err != nil {
			t.Fatal(err)
		}
		stats := encrypt.Stats{Rows: l.Stats.Rows, Confidence: l.Stats.Confidence}
		for _, b := range l.Stats.Histogram {
			stats.Histogram = append(stats.Histogram, encrypt.Bucket{Bits: uint32(b[0]), Rows: b[1]})
		}
		got, err := c.DefaultKeyset().TargetLimit(context.Background(), queryPlan, l.Field, l.Operator, term, l.Want, stats)
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		rows, bounded := got.Rows()
		switch {
		case l.Limit == nil && bounded:
			t.Fatalf("case %d: %d rows, want unbounded", i, rows)
		case l.Limit != nil && (!bounded || rows != *l.Limit):
			t.Fatalf("case %d: %d (bounded %v), want %d", i, rows, bounded, *l.Limit)
		}
		if l.Limit == nil && got.FetchOr(50) != 50 {
			t.Fatalf("case %d: an unbounded limit fetches the page", i)
		}
	}
}

// A query the field does not answer is refused as a mistyped value is: an
// encoding error that names the field and the rule. The typed path's own
// refusals are term errors.
func TestAQueryTheFieldDoesNotAnswerIsRefused(t *testing.T) {
	f := readQueryFixture(t)
	c := queryFixtureClient(t, f)
	ctx := context.Background()
	cipher := c.DefaultKeyset()
	for _, tc := range []struct {
		field, operator string
		input           any
		reason          string
	}{
		{"age", "matches", "ali", "operator_not_answered"},
		{"name", "lt", "ali", "operator_not_answered"},
		{"age", "like", uint32(1), "unknown_operator"},
		{"age", "between", uint32(1), "not_a_range"},
		{"age", "eq", "34", "field_type"},
	} {
		_, err := cipher.QueryTerm(ctx, queryPlan, tc.field, tc.operator, tc.input)
		if !errors.Is(err, encrypt.ErrEncoding) {
			t.Fatalf("%s on %s: %v, want ErrEncoding", tc.operator, tc.field, err)
		}
		var d *encrypt.Diagnostic
		if !errors.As(err, &d) || d.Field() != tc.field || d.Reason() != tc.reason {
			t.Fatalf("%s on %s: %v, want field %q and reason %q", tc.operator, tc.field, err, tc.field, tc.reason)
		}
	}
	if _, err := cipher.QueryTerm(ctx, queryPlan, "age", "between", []any{uint32(65), uint32(18)}); !errors.Is(err, encrypt.ErrTerm) {
		t.Fatalf("an inverted range: %v, want ErrTerm", err)
	}
	if _, err := cipher.QueryTerm(ctx, queryPlan, "name", "matches", "al"); !errors.Is(err, encrypt.ErrTerm) {
		t.Fatalf("text that cuts no token: %v, want ErrTerm", err)
	}

	_, err := cipher.Verify(ctx, queryPlan, "email", "eq", "bob@example.com", []any{"bob@example.com"})
	var d *encrypt.Diagnostic
	if !errors.Is(err, encrypt.ErrEncoding) || !errors.As(err, &d) || d.Reason() != "exact_operator" {
		t.Fatalf("Verify on an exact operator: %v", err)
	}
	_, err = cipher.TargetLimit(ctx, queryPlan, "age", "lt", []byte{1, 0}, 10, encrypt.Stats{Rows: 1})
	if !errors.Is(err, encrypt.ErrEncoding) || !errors.As(err, &d) || d.Reason() != "exact_operator" {
		t.Fatalf("TargetLimit on an exact operator: %v", err)
	}
	_, err = cipher.TargetLimit(ctx, queryPlan, "name", "matches", []byte{1}, 10, encrypt.Stats{Rows: 1})
	if !errors.Is(err, encrypt.ErrEncoding) || !errors.As(err, &d) || d.Reason() != "not_a_query_term" {
		t.Fatalf("TargetLimit on half a position: %v", err)
	}
}

// Verifying and sizing use no key, so a guest never given one answers them,
// as it answers the generator's questions.
func TestVerifyAndTargetLimitNeedNoCipher(t *testing.T) {
	wasm, err := encrypt.EmbeddedGuest()
	if errors.Is(err, encrypt.ErrGuestNotBuilt) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	c := encrypt.RawClient(t, wasm)
	ctx := context.Background()
	cipher := c.DefaultKeyset()
	verified, err := cipher.Verify(ctx, queryPlan, "name", "matches", "alice", []any{"Alice Smith", "Bob"})
	if err != nil || len(verified) != 2 || !verified[0] || verified[1] {
		t.Fatalf("Verify = %v, %v", verified, err)
	}
	limit, err := cipher.TargetLimit(ctx, queryPlan, "name", "matches", []byte{1, 0, 2, 0}, 10, encrypt.Stats{Rows: 100, Histogram: []encrypt.Bucket{{Bits: 10, Rows: 100}}})
	if rows, ok := limit.Rows(); err != nil || !ok || rows < 10 {
		t.Fatalf("TargetLimit = %d %v, %v", rows, ok, err)
	}
	if _, err := cipher.QueryTerm(ctx, queryPlan, "age", "eq", uint32(1)); !errors.Is(err, encrypt.ErrState) {
		t.Fatalf("a query term needs the cipher: %v, want ErrState", err)
	}
}

// The catalog reports, per EQL type, the operators the engine answers:
// TextEq answers eq, exactly, through its equality index.
func TestTheCatalogListsEachTypesOperators(t *testing.T) {
	wasm, err := encrypt.EmbeddedGuest()
	if errors.Is(err, encrypt.ErrGuestNotBuilt) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	checker, err := encrypt.NewCheckerOver(ctx, wasm)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = checker.Close() }()
	targets, err := checker.Targets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) == 0 {
		t.Skip("this build holds no EQL types: import encrypt/eql")
	}
	for _, target := range targets {
		switch {
		case target.Name == "TextEq":
			want := []record.TargetOperator{{Name: "eq", Fidelity: record.Exact, Index: record.Equality}}
			if len(target.Operators) != 1 || target.Operators[0] != want[0] {
				t.Fatalf("TextEq answers %+v, want %+v", target.Operators, want)
			}
		case target.Name == "TextMatch":
			want := record.TargetOperator{Name: "matches", Fidelity: record.Probabilistic, Index: record.Match}
			if len(target.Operators) != 1 || target.Operators[0] != want {
				t.Fatalf("TextMatch answers %+v, want %+v", target.Operators, want)
			}
		case len(target.Operators) != 0:
			// Every other type is storage-only or not produced.
			t.Fatalf("%s (producible %v) answers %+v, want none", target.Name, target.Producible, target.Operators)
		}
	}
}
