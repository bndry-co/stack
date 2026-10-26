package gensupport

import (
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
)

// numbers holds the values a float64 would round: the 64-bit integer
// extremes and a float that needs 17 significant digits.
type numbers struct {
	Min   int64   `json:"min"`
	Max   int64   `json:"max"`
	UMax  uint64  `json:"umax"`
	Float float64 `json:"float"`
}

var extremes = numbers{Min: math.MinInt64, Max: math.MaxInt64, UMax: math.MaxUint64, Float: 0.30000000000000004} // the float64 after 0.3: 17 digits

// failingMarshaler's MarshalJSON fails with an error that holds a value.
type failingMarshaler struct{}

func (failingMarshaler) MarshalJSON() ([]byte, error) { return nil, errors.New("secret-value") }

func TestJSONTextWritesExactNumbersAndRefusesWhatIsNotJSON(t *testing.T) {
	text, err := JSONText(extremes)
	if err != nil {
		t.Fatal(err)
	}
	// encoding/json writes integers as their digits and a float64 as the
	// shortest text that reads back to it: 0.30000000000000004, 17 digits.
	want := `{"min":-9223372036854775808,"max":9223372036854775807,"umax":18446744073709551615,"float":0.30000000000000004}`
	if string(text) != want {
		t.Fatalf("JSONText = %s, want %s", text, want)
	}
	// A json.RawMessage is JSON text already: it crosses unchanged, spacing
	// and all, so a RawMessage needle sends what it sent before.
	raw := json.RawMessage(`{ "a" : 1 }`)
	if text, err := JSONText(raw); err != nil || string(text) != string(raw) {
		t.Fatalf("a RawMessage: %s %v", text, err)
	}
	// Scalars for the path operators, and nil for JSON null.
	for v, want := range map[any]string{"Alice": `"Alice"`, int64(40): `40`, true: `true`, nil: `null`} {
		if text, err := JSONText(v); err != nil || string(text) != want {
			t.Errorf("JSONText(%v) = %s %v, want %s", v, text, err, want)
		}
	}
	for name, v := range map[string]any{
		"[]byte":      []byte(`{"secret-value":1}`),
		"NaN":         math.NaN(),
		"infinity":    map[string]float64{"x": math.Inf(1)},
		"channel":     make(chan int),
		"MarshalJSON": failingMarshaler{},
	} {
		_, err := JSONText(v)
		if !errors.Is(err, encrypt.ErrEncoding) {
			t.Errorf("%s: %v, want ErrEncoding", name, err)
			continue
		}
		// The error names a type, never the value: encoding/json's own
		// text would say "unsupported value: NaN" or "+Inf".
		if msg := err.Error(); strings.Contains(msg, "secret-value") || strings.Contains(msg, "unsupported value") || strings.Contains(msg, "+Inf") {
			t.Errorf("%s: the error shows the value: %s", name, msg)
		}
	}
}

func TestGetDocumentReadsTheDeclaredType(t *testing.T) {
	text, err := JSONText(extremes)
	if err != nil {
		t.Fatal(err)
	}
	vals := Values{"doc": text, "none": nil, "wrong": "text"}
	got, err := GetDocument[numbers](vals, "doc")
	if err != nil || got != extremes {
		t.Fatalf("GetDocument = %+v %v, want %+v", got, err, extremes)
	}
	ptr, err := GetDocumentPtr[numbers](vals, "doc")
	if err != nil || ptr == nil || *ptr != extremes {
		t.Fatalf("GetDocumentPtr = %v %v", ptr, err)
	}
	// A null=sql field that was nil opened as nil, and reads as nil.
	if ptr, err := GetDocumentPtr[numbers](vals, "none"); err != nil || ptr != nil {
		t.Fatalf("a nil document: %v %v", ptr, err)
	}
	if _, err := GetDocument[numbers](vals, "missing"); err == nil {
		t.Fatal("a field the opened value lacks reads")
	}
	if _, err := GetDocument[numbers](vals, "wrong"); !errors.Is(err, encrypt.ErrEncoding) {
		t.Fatalf("a document that opened as a string: %v", err)
	}
	// A document that does not fit the type is refused, naming the type
	// and the field, not the value.
	vals["doc"] = []byte(`{"max":"secret-value"}`)
	_, err = GetDocument[numbers](vals, "doc")
	if !errors.Is(err, encrypt.ErrEncoding) || strings.Contains(err.Error(), "secret-value") || !strings.Contains(err.Error(), `"doc"`) {
		t.Fatalf("a mismatched document: %v", err)
	}
}
