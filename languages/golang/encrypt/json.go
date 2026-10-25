package encrypt

import (
	"context"
	"fmt"

	"github.com/cipherstash/stack/languages/golang/internal/record"
	"github.com/cipherstash/vitaminc/bindings/go/vcffi"
	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// JSONOpen opens the rows a read of a field that stores a JSON document
// returned (the guest's se_json_open), against the request that prepared
// the read: {"operation": "selector" | "subtree", "path", "wildcard_bound"}.
// rows holds one group per database row: for selector, the entry col ->
// selector returned, or none for SQL NULL; for subtree, the rows
// eql_v4.json_tree_subtree returned. Each entry is the
// public.eql_v4_json_tree_entry JSON the database sent.
//
// The engine derives the selector or the read's key again from the request,
// the field's declaration and this cipher's keyset, and checks every row
// against it; the rows never say which path they are for. A row that is not
// one the read asked for is [ErrEncoding]; a wildcard read of an array
// longer than its bound is too. What comes back is, per group, the JSON
// text of each value the read reached, in document order: plaintext, which
// the caller owns. One ZeroKMS request for every group. For generated code.
//
// Opening does not prove the database returned every row the read asked
// for, or rows of the database row the caller meant: see the EQL json_tree
// leakage reference.
func (cph *Cipher) JSONOpen(ctx context.Context, plan *record.Plan, field string, request vcvalue.Object, rows [][][]byte) ([][][]byte, error) {
	p, err := cph.queryPlan(plan, field)
	if err != nil {
		return nil, err
	}
	groups := make([]any, len(rows))
	for i, group := range rows {
		entries := make([]any, len(group))
		for j, entry := range group {
			entries[j] = entry
		}
		groups[i] = entries
	}
	encodedRows, err := vcffi.Marshal(groups)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncoding, err)
	}
	encodedRequest, err := vcffi.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncoding, err)
	}
	encodedPlan, err := vcffi.Marshal(p.Wire())
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncoding, err)
	}
	opts, err := vcffi.Marshal(options(cph.keyset, ""))
	if err != nil {
		return nil, err
	}
	out, err := cph.client.callKMS(ctx, func(ctx context.Context, inst *instance) ([]byte, error) {
		return inst.call(ctx, inst.jsonOpen, buf(encodedRows), buf(encodedPlan), buf([]byte(field)), buf(encodedRequest), buf(opts))
	})
	if err != nil {
		return nil, err
	}
	// The output is plaintext: wiped once it is decoded into the caller's
	// slices.
	defer wipe(out)
	decoded, err := vcffi.Unmarshal(out)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInternal, err)
	}
	list, ok := decoded.([]any)
	if !ok || len(list) != len(rows) {
		return nil, fmt.Errorf("%w: se_json_open returned %T for %d groups", ErrInternal, decoded, len(rows))
	}
	opened := make([][][]byte, len(list))
	for i, item := range list {
		values, ok := item.([]any)
		if !ok {
			return nil, fmt.Errorf("%w: se_json_open group %d is %T", ErrInternal, i, item)
		}
		opened[i] = make([][]byte, len(values))
		for j, v := range values {
			text, ok := v.([]byte)
			if !ok {
				return nil, fmt.Errorf("%w: se_json_open value %d.%d is %T", ErrInternal, i, j, v)
			}
			opened[i][j] = text
		}
	}
	return opened, nil
}
