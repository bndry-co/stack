package encrypt

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"strings"

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

// JSONSelector is a JSON path's selector: what `->`, `->>` and the path
// functions of an EncryptedJSON column take. It binds as SQL text; cast it,
// `col -> $1::text`, so PostgreSQL picks EQL's operator and not jsonb's.
// It is column-wide: the same path has the same selector in every row.
type JSONSelector string

// Value binds the selector as text.
func (s JSONSelector) Value() (driver.Value, error) { return string(s), nil }

// JSONToken is one node's token: what eql_v4.json_tree_children and
// eql_v4.json_tree_child_count take. It binds as SQL text. A token is a
// capability over the node's subtree in every row of the column: send it
// to the database for a query, and do not log it.
type JSONToken string

// Value binds the token as text.
func (t JSONToken) Value() (driver.Value, error) { return string(t), nil }

// JSONTokens are a subtree read's tokens: what eql_v4.json_tree_subtree
// takes. They bind as a PostgreSQL text[] literal; cast the parameter,
// `$2::text[]`. Like a [JSONToken], each is a capability: do not log them.
type JSONTokens []string

// Value binds the tokens as a text[] literal. A token is base64, so it
// needs no escape inside the quotes.
func (t JSONTokens) Value() (driver.Value, error) {
	var b strings.Builder
	b.WriteByte('{')
	for i, token := range t {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteByte('"')
		b.WriteString(token)
		b.WriteByte('"')
	}
	b.WriteByte('}')
	return b.String(), nil
}

// JSONValue is one value a read reached, or none. Found is false for no
// value at the path (the row has no node there, or SQL NULL); a JSON null
// that is there is Found, with JSON "null". JSON is the value's JSON text:
// plaintext, which the caller owns.
type JSONValue struct {
	Found bool
	JSON  json.RawMessage
}

// JSONReadOptions are a subtree read's options.
type JSONReadOptions struct {
	// WildcardBound is how many elements each [*] in the path is expanded
	// to; 0 is the engine's default, 64. A read of an array longer than the
	// bound fails rather than open to part of it ([ErrEncoding], with the
	// diagnostic code stack_encrypt::json_wildcard_truncated). Two wildcard
	// levels send bound² + bound + 1 tokens, and the engine refuses a read
	// past 8,192.
	WildcardBound uint32
}

// JSONRange is both bounds of a between at a path, each an ordering
// operand Q, low then high, inclusive.
type JSONRange[Q ~[]byte] struct {
	Low  Q
	High Q
}

// JSONSelection is a prepared `->` on an EncryptedJSON field: the selector
// to bind, and what opens the entries the database returns for it. It keeps
// the request it was prepared from (the field's declaration, the path and
// the cipher's keyset), so the entries open only as answers to it: the
// engine derives the selector again and refuses an entry that does not
// carry it. E is the column's entry type, eql.EncryptedJSONEntry.
type JSONSelection[E ~[]byte] struct {
	cipher   *Cipher
	plan     *record.Plan
	field    string
	path     string
	selector JSONSelector
}

// NewJSONSelection is a selection prepared by [Cipher.QueryTerm]'s
// selector operator. For generated code.
func NewJSONSelection[E ~[]byte](c *Cipher, plan *record.Plan, field, path, selector string) JSONSelection[E] {
	return JSONSelection[E]{cipher: c, plan: plan, field: field, path: path, selector: JSONSelector(selector)}
}

// Selector is the selector to bind: `col -> $1::text`.
func (s JSONSelection[E]) Selector() JSONSelector { return s.selector }

// Open opens the entries `col -> selector` returned, one per database row,
// nil for a row where it returned SQL NULL, with one ZeroKMS request. Each
// opens to the scalar it holds (Found), or for the sealed root at "$" the
// whole document; a nil opens to no value. A container's entry is refused:
// read a container with a subtree read. An entry that is not the selector's
// is [ErrEncoding].
func (s JSONSelection[E]) Open(ctx context.Context, rows []*E) ([]JSONValue, error) {
	if s.cipher == nil {
		return nil, fmt.Errorf("%w: a zero JSONSelection has no request to open against", ErrEncoding)
	}
	groups := make([][][]byte, len(rows))
	for i, row := range rows {
		if row != nil {
			groups[i] = [][]byte{[]byte(*row)}
		}
	}
	opened, err := s.cipher.JSONOpen(ctx, s.plan, s.field, vcvalue.Object{{Key: "operation", Value: "selector"}, {Key: "path", Value: s.path}}, groups)
	if err != nil {
		return nil, err
	}
	out := make([]JSONValue, len(opened))
	for i, values := range opened {
		if len(values) == 1 {
			out[i] = JSONValue{Found: true, JSON: values[0]}
		}
	}
	return out, nil
}

// JSONRead is a prepared subtree read of an EncryptedJSON field: the tokens
// to bind, and what opens the rows eql_v4.json_tree_subtree returns for
// them. It keeps the request it was prepared from (the field's declaration,
// the path, the bound and the cipher's keyset); the engine derives the read
// again from it, and checks every row against it. E is the column's entry
// type, eql.EncryptedJSONEntry.
type JSONRead[E ~[]byte] struct {
	cipher *Cipher
	plan   *record.Plan
	field  string
	path   string
	bound  uint32
	tokens JSONTokens
}

// NewJSONRead is a read prepared by [Cipher.QueryTerm]'s subtree operator.
// For generated code.
func NewJSONRead[E ~[]byte](c *Cipher, plan *record.Plan, field, path string, bound uint32, tokens []string) JSONRead[E] {
	return JSONRead[E]{cipher: c, plan: plan, field: field, path: path, bound: bound, tokens: JSONTokens(tokens)}
}

// Tokens are the tokens to bind:
// `eql_v4.json_tree_subtree(col, $1::text[], 64)`.
func (r JSONRead[E]) Tokens() JSONTokens { return r.tokens }

// Open opens the rows the read returned, one group per database row, with
// one ZeroKMS request: per row, the value at each concrete path the read
// named that the row has, in document order. A row with no node there
// opens to no value. Past its walk budget the database returns the sealed
// root instead, and the read's paths are evaluated over the whole document
// to the same values; only those values come back. A row that is not one
// the read asked for, or a wildcard read of an array longer than the bound,
// is [ErrEncoding].
//
// Opening checks each row against the read, not that the database
// returned every row it should have, nor that the rows came from the row
// the caller meant.
func (r JSONRead[E]) Open(ctx context.Context, rows [][]E) ([][]json.RawMessage, error) {
	if r.cipher == nil {
		return nil, fmt.Errorf("%w: a zero JSONRead has no request to open against", ErrEncoding)
	}
	groups := make([][][]byte, len(rows))
	for i, row := range rows {
		groups[i] = make([][]byte, len(row))
		for j, entry := range row {
			groups[i][j] = []byte(entry)
		}
	}
	request := vcvalue.Object{{Key: "operation", Value: "subtree"}, {Key: "path", Value: r.path}}
	if r.bound != 0 {
		request = append(request, vcvalue.Field{Key: "wildcard_bound", Value: r.bound})
	}
	opened, err := r.cipher.JSONOpen(ctx, r.plan, r.field, request, groups)
	if err != nil {
		return nil, err
	}
	out := make([][]json.RawMessage, len(opened))
	for i, values := range opened {
		out[i] = make([]json.RawMessage, len(values))
		for j, v := range values {
			out[i][j] = v
		}
	}
	return out, nil
}

// OpenOne opens one row's rows to the one value at the read's path: Found
// with its JSON, or not Found where the row has no node there. A read that
// reaches more than one value (a wildcard) is [ErrEncoding]; open it with
// [JSONRead.Open].
func (r JSONRead[E]) OpenOne(ctx context.Context, rows []E) (JSONValue, error) {
	opened, err := r.Open(ctx, [][]E{rows})
	if err != nil {
		return JSONValue{}, err
	}
	switch values := opened[0]; len(values) {
	case 0:
		return JSONValue{}, nil
	case 1:
		return JSONValue{Found: true, JSON: values[0]}, nil
	default:
		return JSONValue{}, fmt.Errorf("%w: the read reached %d values, not one; open it with Open", ErrEncoding, len(values))
	}
}
