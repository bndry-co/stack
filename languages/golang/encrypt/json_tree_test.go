package encrypt_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/eql"
	"github.com/cipherstash/stack/languages/golang/internal/record"
)

// An encrypted JSON document (the EQL type JsonSearch) through the guest
// that holds the EQL types: a field of kind json names the target with the
// JSON index's options, crosses as its JSON text, and opens back to it.

func jsonPlan() *record.Plan {
	return &record.Plan{Context: []string{"users"}, Fields: []record.Field{{
		Name: "profile", Kind: record.JSON, Target: "JsonSearch", Null: record.SQLNull,
		TargetOptions: &record.TargetOptions{Ordered: []string{"$.age"}},
	}}}
}

var jsonDocuments = []string{
	`{"name":"Alice","age":34,"visits":[{"at":3},{"at":1}]}`,
	`[1,"two",{"three":3}]`,
	`"a scalar root"`,
	`null`,
	`18446744073709551615`,
	`{}`,
}

func TestJSONDocumentsRoundTripThroughTheGuest(t *testing.T) {
	c := deterministicEQLClient(t)
	ctx := context.Background()
	rows := make([]record.Source, len(jsonDocuments))
	for i, doc := range jsonDocuments {
		rows[i] = record.Source{"profile": []byte(doc)}
	}
	sealed, err := c.DefaultKeyset().Seal(ctx, jsonPlan(), rows)
	if err != nil {
		t.Fatal(err)
	}
	for i, s := range sealed {
		var stored struct {
			V  int               `json:"v"`
			I  map[string]string `json:"i"`
			H  string            `json:"h"`
			SV []json.RawMessage `json:"sv"`
		}
		if err := json.Unmarshal(s["profile"].EQL, &stored); err != nil {
			t.Fatalf("row %d: %v", i, err)
		}
		if stored.V != 4 || stored.I["t"] != "users" || stored.I["c"] != "profile" || stored.H == "" || len(stored.SV) == 0 {
			t.Fatalf("row %d: stored %+v", i, stored)
		}
		// The value scans and binds as the generated EQL type.
		var col eql.JSONSearch
		if err := col.Scan(s["profile"].EQL); err != nil {
			t.Fatalf("row %d: Scan: %v", i, err)
		}
	}
	opened, err := c.Open(ctx, jsonPlan(), sealed)
	if err != nil {
		t.Fatal(err)
	}
	for i, row := range opened {
		text, ok := row["profile"].([]byte)
		if !ok {
			t.Fatalf("row %d opened as %T, not bytes", i, row["profile"])
		}
		// Numbers are compared as their text (UseNumber), so an integer
		// past 2^53 that came back as the nearest float would differ.
		got, err := decodeNumbers(text)
		if err != nil {
			t.Fatalf("row %d: %v", i, err)
		}
		want, _ := decodeNumbers([]byte(jsonDocuments[i]))
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("row %d: opened %s, want %s", i, text, jsonDocuments[i])
		}
	}
}

// Text that is not a document is refused before anything is sealed, with
// the engine's code and without the text.
func TestJSONTextThatIsNotADocumentIsErrEncoding(t *testing.T) {
	c := deterministicEQLClient(t)
	for text, code := range map[string]string{
		`{"secret":1,"secret":2}`: "json_duplicate_key",
		`99999999999999999999`:    "json_integer_range",
		`{"secret":`:              "json_syntax",
	} {
		_, err := c.DefaultKeyset().Seal(context.Background(), jsonPlan(), []record.Source{{"profile": []byte(text)}})
		if !errors.Is(err, encrypt.ErrEncoding) {
			t.Fatalf("%s: %v, want ErrEncoding", text, err)
		}
		var d *encrypt.Diagnostic
		if !errors.As(err, &d) || d.Code != "stack_encrypt::target_json" || d.Reason() != code || d.Field() != "profile" {
			t.Fatalf("%s: diagnostic %+v", text, d)
		}
		if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "9999") {
			t.Fatalf("%s: the error holds the text: %v", text, err)
		}
	}
}

// decodeNumbers decodes JSON text with each number kept as its text.
func decodeNumbers(text []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(text))
	dec.UseNumber()
	var v any
	err := dec.Decode(&v)
	return v, err
}
