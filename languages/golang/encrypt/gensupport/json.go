package gensupport

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/internal/record"
	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// The operators of a field stored as a JSONSearch document, for the
// generated methods of its Fields entry. Each sends the operator's named
// inputs, JSON values as their JSON text ([]byte of the json.RawMessage),
// and checks the engine answered in the encoding and with the number of
// parts the method returns.

// jsonTerm derives one JSON operator's term on the field: an exact term in
// encoding, of parts byte strings ("eql") or texts ("text"); parts 0 takes
// any number of texts ("text_array").
func (f Field[T]) jsonTerm(ctx context.Context, c *encrypt.Cipher, operator, encoding string, parts int, input vcvalue.Object) (encrypt.QueryTerm, error) {
	if f.err != nil {
		return encrypt.QueryTerm{}, f.err
	}
	if c == nil {
		return encrypt.QueryTerm{}, fmt.Errorf("%w: gensupport: %s: a query needs a cipher", encrypt.ErrEncoding, f.name)
	}
	term, err := c.QueryTerm(ctx, f.plan, f.name, operator, input)
	if err != nil {
		return encrypt.QueryTerm{}, err
	}
	got := len(term.Terms)
	if encoding == "text" || encoding == "text_array" {
		got = len(term.Text)
	}
	if term.Encoding != encoding || term.Fidelity != record.Exact || (parts != 0 && got != parts) {
		return encrypt.QueryTerm{}, fmt.Errorf("gensupport: %s: %s came back as a %s %s term of %d parts, not an exact %s one of %d", f.name, operator, term.Fidelity, term.Encoding, got, encoding, parts)
	}
	return term, nil
}

// JSONQuery derives a containment operator's query on a JSON field
// (contains, contained_by): the needle's projection, Q.
func JSONQuery[Q ~[]byte, T any](ctx context.Context, f Field[T], c *encrypt.Cipher, operator string, needle json.RawMessage) (Q, error) {
	term, err := f.jsonTerm(ctx, c, operator, "eql", 1, vcvalue.Object{{Key: "json", Value: []byte(needle)}})
	if err != nil {
		return nil, err
	}
	return Q(term.Terms[0]), nil
}

// JSONQueryAt derives an operator at a path on a JSON field (eq_at, lt_at,
// lte_at, gt_at, gte_at): Q is the needle for eq_at and the leaf operand
// for the orderings.
func JSONQueryAt[Q ~[]byte, T any](ctx context.Context, f Field[T], c *encrypt.Cipher, operator, path string, v json.RawMessage) (Q, error) {
	term, err := f.jsonTerm(ctx, c, operator, "eql", 1, vcvalue.Object{{Key: "path", Value: path}, {Key: "json", Value: []byte(v)}})
	if err != nil {
		return nil, err
	}
	return Q(term.Terms[0]), nil
}

// JSONBetweenAt derives between_at on a JSON field: the two leaf operands,
// low then high, inclusive.
func JSONBetweenAt[Q ~[]byte, T any](ctx context.Context, f Field[T], c *encrypt.Cipher, path string, lo, hi json.RawMessage) (encrypt.JSONRange[Q], error) {
	term, err := f.jsonTerm(ctx, c, "between_at", "eql", 2, vcvalue.Object{{Key: "path", Value: path}, {Key: "low", Value: []byte(lo)}, {Key: "high", Value: []byte(hi)}})
	if err != nil {
		return encrypt.JSONRange[Q]{}, err
	}
	return encrypt.JSONRange[Q]{Low: Q(term.Terms[0]), High: Q(term.Terms[1])}, nil
}

// JSONSelect prepares `->` at a path on a JSON field: the selector to
// bind, and what opens the entries it returns. E is the field's entry type.
func JSONSelect[E ~[]byte, T any](ctx context.Context, f Field[T], c *encrypt.Cipher, path string) (encrypt.JSONSelection[E], error) {
	term, err := f.jsonTerm(ctx, c, "selector", "text", 1, vcvalue.Object{{Key: "path", Value: path}})
	if err != nil {
		return encrypt.JSONSelection[E]{}, err
	}
	return encrypt.NewJSONSelection[E](c, f.plan, f.name, path, term.Text[0]), nil
}

// JSONSubtree prepares a subtree read at a path on a JSON field: the
// tokens to bind, and what opens the rows they return. The request is
// built once, here, and the read keeps it: opening sends the engine the
// same request the tokens were derived from.
func JSONSubtree[E ~[]byte, T any](ctx context.Context, f Field[T], c *encrypt.Cipher, path string, opts encrypt.JSONReadOptions) (encrypt.JSONRead[E], error) {
	input := vcvalue.Object{{Key: "path", Value: path}}
	if opts.WildcardBound != 0 {
		input = append(input, vcvalue.Field{Key: "wildcard_bound", Value: opts.WildcardBound})
	}
	term, err := f.jsonTerm(ctx, c, "subtree", "text_array", 0, input)
	if err != nil {
		return encrypt.JSONRead[E]{}, err
	}
	return encrypt.NewJSONRead[E](c, f.plan, f.name, path, input, term.Text), nil
}

// JSONNodeToken derives the token of the node at a path with no wildcard
// (children, child_count), which json_tree_children and
// json_tree_child_count take.
func JSONNodeToken[T any](ctx context.Context, f Field[T], c *encrypt.Cipher, operator, path string) (encrypt.JSONToken, error) {
	term, err := f.jsonTerm(ctx, c, operator, "text", 1, vcvalue.Object{{Key: "path", Value: path}})
	if err != nil {
		return "", err
	}
	return encrypt.JSONToken(term.Text[0]), nil
}
