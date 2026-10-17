package encrypt

import (
	"context"
	"fmt"

	"github.com/cipherstash/stack/languages/golang/internal/record"
	"github.com/cipherstash/vitaminc/bindings/go/vcffi"
	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// Queries named by operator (ADR-0009; ADR-0007, amended 2026-10-16): the
// guest's se_query_term, se_verify and se_target_limit exports, for
// generated code. A query names a field of a declaration and an operator,
// and the engine picks the index that answers it, or refuses an operator
// the field does not answer as it refuses a mistyped value.

// QueryTerm is the query term the engine derives for one field, an operator
// and its input.
type QueryTerm struct {
	// Operator is the operator the term answers: eq, lt, lte, gt, gte,
	// between or matches.
	Operator string
	// Fidelity is how far the server's answer can be trusted. A
	// [record.Probabilistic] term's rows are checked with [Cipher.Verify]
	// after decrypt, and its fetch sized with [Cipher.TargetLimit].
	Fidelity record.Fidelity
	// Index is the field's index that answers the operator.
	Index record.Output
	// Domain is the PostgreSQL domain the term is cast to, for a field
	// that names an EQL type; "" for a field with indexes, whose terms are
	// bytes.
	Domain string
	// Terms is the term: one, or for between two, the low bound's then the
	// high's. For a field that names an EQL type it is the query value's
	// JSON.
	Terms [][]byte
}

// Bucket is one bar of a histogram of the stored match filters' set-bit
// counts: Rows rows whose filter sets Bits bits.
type Bucket struct {
	Bits uint32
	Rows uint64
}

// Stats is what [Cipher.TargetLimit] knows of the table: how many rows the
// query scans, how full their stored filters are, and the confidence to
// size the fetch at. None of it is secret: the server holds the filters and
// the catalog holds the row count.
type Stats struct {
	// Rows is the rows the query scans, such as greatest(reltuples, 0)
	// from pg_class.
	Rows uint64
	// Histogram is a measured histogram of the stored filters' set-bit
	// counts. With none, the engine uses the index's declared prior, and
	// a field declared as data has none, so the limit is unbounded.
	Histogram []Bucket
	// Confidence is the probability that the fetch holds the rows wanted
	// when the table has that many; 0 is the engine's default, 99%.
	Confidence float64
}

// wire is the statistics as se_target_limit reads them.
func (s Stats) wire() vcvalue.Object {
	out := vcvalue.Object{{Key: "rows", Value: s.Rows}}
	if s.Histogram != nil {
		buckets := make([]any, len(s.Histogram))
		for i, b := range s.Histogram {
			buckets[i] = []any{b.Bits, b.Rows}
		}
		out = append(out, vcvalue.Field{Key: "histogram", Value: buckets})
	}
	if s.Confidence != 0 {
		out = append(out, vcvalue.Field{Key: "confidence", Value: s.Confidence})
	}
	return out
}

// Limit is how many rows a probabilistic query should fetch: a number, or
// unbounded when the statistics say nothing of the stored filters or the
// confidence is not below 1, in which case a caller pages with a cursor.
type Limit struct {
	rows    uint64
	bounded bool
}

// Rows is the rows to fetch, and false when no finite fetch can be
// promised.
func (l Limit) Rows() (uint64, bool) { return l.rows, l.bounded }

// FetchOr is the rows to fetch, or page when no finite fetch can be
// promised, for a caller that pages either way.
func (l Limit) FetchOr(page uint64) uint64 {
	if l.bounded {
		return l.rows
	}
	return page
}

// QueryTerm derives the query term for one field of the plan, an operator
// and its input under this cipher's keyset: one value for every operator
// but between, whose input is a two-element slice, low then high. The
// engine reads the input as the field's declared type, finds the index
// that answers the operator, and derives that index's term under the
// field's context; for a field that names an EQL type it runs the type's
// query. An operator the field does not answer, or one the engine does not
// know, is [ErrEncoding] naming the field, as a mistyped value is; a range
// the wrong way round, and match text that cuts no token, are [ErrTerm].
// No data key is minted. For generated code.
func (cph *Cipher) QueryTerm(ctx context.Context, plan *record.Plan, field, operator string, input any) (QueryTerm, error) {
	p, err := cph.queryPlan(plan, field)
	if err != nil {
		return QueryTerm{}, err
	}
	encodedInput, err := vcffi.Marshal(input)
	if err != nil {
		return QueryTerm{}, fmt.Errorf("%w: %v", ErrEncoding, err)
	}
	// The input is plaintext: its transport copy is wiped once it is in the
	// guest.
	defer wipe(encodedInput)
	encodedPlan, err := vcffi.Marshal(p.Wire())
	if err != nil {
		return QueryTerm{}, fmt.Errorf("%w: %v", ErrEncoding, err)
	}
	opts, err := vcffi.Marshal(options(cph.keyset, ""))
	if err != nil {
		return QueryTerm{}, err
	}
	out, err := cph.client.call(ctx, func(inst *instance) ([]byte, error) {
		return inst.call(ctx, inst.queryTerm, buf(encodedInput), buf(encodedPlan), buf([]byte(field)), buf([]byte(operator)), buf(opts))
	})
	if err != nil {
		return QueryTerm{}, err
	}
	decoded, err := vcffi.Unmarshal(out)
	if err != nil {
		return QueryTerm{}, fmt.Errorf("%w: %v", ErrInternal, err)
	}
	term, err := parseQueryTerm(decoded)
	if err != nil {
		return QueryTerm{}, fmt.Errorf("%w: se_query_term: %v", ErrInternal, err)
	}
	return term, nil
}

// parseQueryTerm reads se_query_term's object: exactly the keys operator,
// fidelity, index, domain (a string or null) and term (bytes, or a list of
// two for between). The operator, fidelity and index take only the values
// the engine writes, as the catalog reader's do.
func parseQueryTerm(decoded any) (QueryTerm, error) {
	obj, ok := decoded.(vcvalue.Object)
	if !ok {
		return QueryTerm{}, fmt.Errorf("came back as %T, not an object", decoded)
	}
	var t QueryTerm
	seen := map[string]bool{}
	for _, f := range obj {
		if seen[f.Key] {
			return QueryTerm{}, fmt.Errorf("key %q twice", f.Key)
		}
		seen[f.Key] = true
		var err error
		switch f.Key {
		case "operator":
			var s string
			if s, err = targetString(f); err == nil {
				t.Operator, err = parseOperatorName(s)
			}
		case "fidelity":
			var s string
			if s, err = targetString(f); err == nil {
				t.Fidelity, err = parseFidelity(s)
			}
		case "index":
			var s string
			if s, err = targetString(f); err == nil {
				t.Index, err = parseOperatorIndex(s)
			}
		case "domain":
			t.Domain, err = targetOptionalString(f)
		case "term":
			switch v := f.Value.(type) {
			case []byte:
				t.Terms = [][]byte{v}
			case []any:
				if len(v) != 2 {
					return QueryTerm{}, fmt.Errorf("a range of %d terms", len(v))
				}
				for _, bound := range v {
					b, ok := bound.([]byte)
					if !ok {
						return QueryTerm{}, fmt.Errorf("a bound is %T, not bytes", bound)
					}
					t.Terms = append(t.Terms, b)
				}
			default:
				return QueryTerm{}, fmt.Errorf("term is %T", f.Value)
			}
		default:
			return QueryTerm{}, fmt.Errorf("unknown key %q", f.Key)
		}
		if err != nil {
			return QueryTerm{}, err
		}
	}
	if len(seen) != 5 {
		return QueryTerm{}, fmt.Errorf("%d keys, not 5", len(seen))
	}
	return t, nil
}

// Verify reports, for each of a page of decrypted values, whether it really
// matches a probabilistic query: one call into the guest for the page. The
// query is named as it was derived, by the field, the operator and the
// input; the engine cuts the input's tokens again with the field's own
// tokenizer, so nothing here holds a copy of it. A nil value is false. An
// exact operator has nothing to verify and is [ErrEncoding]. Uses no key.
// For generated code.
func (cph *Cipher) Verify(ctx context.Context, plan *record.Plan, field, operator string, input any, values []any) ([]bool, error) {
	p, err := cph.plan(plan)
	if err != nil {
		return nil, err
	}
	encodedInput, err := vcffi.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncoding, err)
	}
	defer wipe(encodedInput)
	if values == nil {
		values = []any{}
	}
	encodedValues, err := vcffi.Marshal(values)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncoding, err)
	}
	// The values are decrypted plaintext: wiped once they are in the guest.
	defer wipe(encodedValues)
	encodedPlan, err := vcffi.Marshal(p.Wire())
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncoding, err)
	}
	out, err := cph.client.call(ctx, func(inst *instance) ([]byte, error) {
		return inst.call(ctx, inst.verify, buf(encodedInput), buf(encodedValues), buf(encodedPlan), buf([]byte(field)), buf([]byte(operator)))
	})
	if err != nil {
		return nil, err
	}
	decoded, err := vcffi.Unmarshal(out)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInternal, err)
	}
	list, ok := decoded.([]any)
	if !ok || len(list) != len(values) {
		return nil, fmt.Errorf("%w: se_verify returned %T for %d values", ErrInternal, decoded, len(values))
	}
	verified := make([]bool, len(list))
	for i, v := range list {
		b, ok := v.(bool)
		if !ok {
			return nil, fmt.Errorf("%w: se_verify returned %T for value %d", ErrInternal, v, i)
		}
		verified[i] = b
	}
	return verified, nil
}

// TargetLimit is how many rows to fetch so that, at the confidence stats
// names, want of them verify: term is the probabilistic term's bytes as
// [Cipher.QueryTerm] returned them. An exact operator has no fetch to size
// and is [ErrEncoding], as are bytes the field's index would not derive.
// Uses no key. For generated code.
func (cph *Cipher) TargetLimit(ctx context.Context, plan *record.Plan, field, operator string, term []byte, want uint64, stats Stats) (Limit, error) {
	p, err := cph.plan(plan)
	if err != nil {
		return Limit{}, err
	}
	encodedStats, err := vcffi.Marshal(stats.wire())
	if err != nil {
		return Limit{}, fmt.Errorf("%w: %v", ErrEncoding, err)
	}
	encodedPlan, err := vcffi.Marshal(p.Wire())
	if err != nil {
		return Limit{}, fmt.Errorf("%w: %v", ErrEncoding, err)
	}
	out, err := cph.client.call(ctx, func(inst *instance) ([]byte, error) {
		return inst.call(ctx, inst.limit, buf(term), buf(encodedStats), buf(encodedPlan), buf([]byte(field)), buf([]byte(operator)), scalar(want))
	})
	if err != nil {
		return Limit{}, err
	}
	decoded, err := vcffi.Unmarshal(out)
	if err != nil {
		return Limit{}, fmt.Errorf("%w: %v", ErrInternal, err)
	}
	switch v := decoded.(type) {
	case nil:
		return Limit{}, nil
	case uint64:
		return Limit{rows: v, bounded: true}, nil
	default:
		return Limit{}, fmt.Errorf("%w: se_target_limit returned %T", ErrInternal, decoded)
	}
}
