package gensupport

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// The operators of a field stored as an EncryptedJSON document, for the
// generated methods of its Fields entry. Each sends the operator's named
// inputs, JSON values as their JSON text, and checks the engine answered
// in the encoding the method returns.

// jsonTerm derives one JSON operator's term on the field.
func (f Field[T]) jsonTerm(ctx context.Context, c *encrypt.Cipher, operator, encoding string, input vcvalue.Object) (encrypt.QueryTerm, error) {
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
	if term.Encoding != encoding || term.Fidelity != "exact" {
		return encrypt.QueryTerm{}, fmt.Errorf("gensupport: %s: %s came back as a %s %s term, not an exact %s one", f.name, operator, term.Fidelity, term.Encoding, encoding)
	}
	return term, nil
}

// jsonText is a JSON value as an input carries it: its text, as bytes.
func jsonText(v json.RawMessage) []byte { return []byte(v) }

// JSONQuery derives a containment operator's query on a JSON field
// (contains, contained_by): the needle's projection, Q.
func JSONQuery[Q ~[]byte, T any](ctx context.Context, f Field[T], c *encrypt.Cipher, operator string, needle json.RawMessage) (Q, error) {
	term, err := f.jsonTerm(ctx, c, operator, "eql", vcvalue.Object{{Key: "json", Value: jsonText(needle)}})
	if err != nil || len(term.Terms) != 1 {
		return nil, oneTermErr(f.name, operator, err)
	}
	return Q(term.Terms[0]), nil
}

// JSONQueryAt derives an operator at a path on a JSON field (eq_at, lt_at,
// lte_at, gt_at, gte_at): Q is the needle for eq_at and the leaf operand
// for the orderings.
func JSONQueryAt[Q ~[]byte, T any](ctx context.Context, f Field[T], c *encrypt.Cipher, operator, path string, v json.RawMessage) (Q, error) {
	term, err := f.jsonTerm(ctx, c, operator, "eql", vcvalue.Object{{Key: "path", Value: path}, {Key: "json", Value: jsonText(v)}})
	if err != nil || len(term.Terms) != 1 {
		return nil, oneTermErr(f.name, operator, err)
	}
	return Q(term.Terms[0]), nil
}

// JSONBetweenAt derives between_at on a JSON field: the two leaf operands,
// low then high, inclusive.
func JSONBetweenAt[Q ~[]byte, T any](ctx context.Context, f Field[T], c *encrypt.Cipher, path string, lo, hi json.RawMessage) (encrypt.JSONRange[Q], error) {
	term, err := f.jsonTerm(ctx, c, "between_at", "eql", vcvalue.Object{{Key: "path", Value: path}, {Key: "low", Value: jsonText(lo)}, {Key: "high", Value: jsonText(hi)}})
	if err != nil {
		return encrypt.JSONRange[Q]{}, err
	}
	if len(term.Terms) != 2 {
		return encrypt.JSONRange[Q]{}, fmt.Errorf("gensupport: %s: between_at came back as %d terms, not 2", f.name, len(term.Terms))
	}
	return encrypt.JSONRange[Q]{Low: Q(term.Terms[0]), High: Q(term.Terms[1])}, nil
}

// JSONSelect prepares `->` at a path on a JSON field: the selector to
// bind, and what opens the entries it returns. E is the field's entry type.
func JSONSelect[E ~[]byte, T any](ctx context.Context, f Field[T], c *encrypt.Cipher, path string) (encrypt.JSONSelection[E], error) {
	term, err := f.jsonTerm(ctx, c, "selector", "text", vcvalue.Object{{Key: "path", Value: path}})
	if err == nil && len(term.Text) != 1 {
		err = fmt.Errorf("gensupport: %s: selector came back as %d texts, not 1", f.name, len(term.Text))
	}
	if err != nil {
		return encrypt.JSONSelection[E]{}, err
	}
	return encrypt.NewJSONSelection[E](c, f.plan, f.name, path, term.Text[0]), nil
}

// JSONSubtree prepares a subtree read at a path on a JSON field: the
// tokens to bind, and what opens the rows they return.
func JSONSubtree[E ~[]byte, T any](ctx context.Context, f Field[T], c *encrypt.Cipher, path string, opts encrypt.JSONReadOptions) (encrypt.JSONRead[E], error) {
	input := vcvalue.Object{{Key: "path", Value: path}}
	if opts.WildcardBound != 0 {
		input = append(input, vcvalue.Field{Key: "wildcard_bound", Value: opts.WildcardBound})
	}
	term, err := f.jsonTerm(ctx, c, "subtree", "text_array", input)
	if err != nil {
		return encrypt.JSONRead[E]{}, err
	}
	return encrypt.NewJSONRead[E](c, f.plan, f.name, path, opts.WildcardBound, term.Text), nil
}

// JSONNodeToken derives the token of the node at a path with no wildcard
// (children, child_count), which json_tree_children and
// json_tree_child_count take.
func JSONNodeToken[T any](ctx context.Context, f Field[T], c *encrypt.Cipher, operator, path string) (encrypt.JSONToken, error) {
	term, err := f.jsonTerm(ctx, c, operator, "text", vcvalue.Object{{Key: "path", Value: path}})
	if err == nil && len(term.Text) != 1 {
		err = fmt.Errorf("gensupport: %s: %s came back as %d texts, not 1", f.name, operator, len(term.Text))
	}
	if err != nil {
		return "", err
	}
	return encrypt.JSONToken(term.Text[0]), nil
}

func oneTermErr(field, operator string, err error) error {
	if err != nil {
		return err
	}
	return fmt.Errorf("gensupport: %s: %s came back as other than one term", field, operator)
}
