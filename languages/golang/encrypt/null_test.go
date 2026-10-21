package encrypt_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/eql"
	"github.com/cipherstash/stack/languages/golang/encrypt/internal/testusers"
)

// Optional fields, declared over pointers (#1298), through generated code
// over the deterministic guest build with the EQL types. A sealed null is as
// long as a value and the stored field never shows it; a SQL null stores
// nothing. Both decrypt to nil.

func ptr[T any](v T) *T { return &v }

// cOf is the length of the `c` an EQL value stores.
func cOf(t *testing.T, value []byte) int {
	t.Helper()
	var envelope struct {
		C string `json:"c"`
	}
	if err := json.Unmarshal(value, &envelope); err != nil {
		t.Fatalf("the EQL value is not JSON: %v", err)
	}
	if envelope.C == "" {
		t.Fatalf("the EQL value has no c: %s", value)
	}
	return len(envelope.C)
}

func TestOptionalFieldsStoreNilAsTheirTagsSay(t *testing.T) {
	c := deterministicEQLClient(t)
	ctx := context.Background()
	cipher := c.DefaultKeyset()
	dob, born := encrypt.Date{Year: 1990, Month: 5, Day: 17}, encrypt.Date{Year: 1991, Month: 6, Day: 1}
	people := []testusers.Person{
		{ID: 1, DOB: &dob, Born: &born, Age: ptr(int32(34)), Score: ptr(int64(7)), Nick: ptr("al")},
		{ID: 2},
	}
	sealed, err := testusers.EncryptPerson(ctx, cipher, people)
	if err != nil {
		t.Fatal(err)
	}
	present, absent := sealed[0], sealed[1]

	// A sealed null: a value whose ciphertext is as long as a date's, or
	// an int32's, so the column does not show which rows are absent.
	if len(absent.DOB) == 0 || cOf(t, absent.DOB) != cOf(t, present.DOB) {
		t.Fatalf("a nil DOB is sealed as long as a date: %s, beside %s", absent.DOB, present.DOB)
	}
	if len(absent.Age.Ciphertext) != len(present.Age.Ciphertext) {
		t.Fatalf("a nil Age is sealed as long as an int32: %d bytes, beside %d", len(absent.Age.Ciphertext), len(present.Age.Ciphertext))
	}
	// A SQL null: nothing stored, so the column holds NULL.
	if absent.Born != nil || absent.Score != nil || absent.Nick != nil {
		t.Fatalf("a nil null=sql field stores nothing: %+v", absent)
	}
	if present.Born == nil || present.Score == nil || present.Nick == nil {
		t.Fatalf("a present null=sql field is stored: %+v", present)
	}
	var stored eql.Date
	if err := stored.Scan([]byte(absent.DOB)); err != nil {
		t.Fatalf("a sealed null is a value the column scans: %v", err)
	}

	opened, err := testusers.DecryptPerson(ctx, cipher, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if got := opened[1]; got.ID != 2 || got.DOB != nil || got.Born != nil || got.Age != nil || got.Score != nil || got.Nick != nil {
		t.Fatalf("every nil decrypts to nil: %+v", got)
	}
	got := opened[0]
	if got.DOB == nil || *got.DOB != dob || got.Born == nil || *got.Born != born || got.Age == nil || *got.Age != 34 ||
		got.Score == nil || *got.Score != 7 || got.Nick == nil || *got.Nick != "al" {
		t.Fatalf("every value decrypts as it was: %+v", got)
	}

	// A field that is not a pointer has no nil to give: the stored null is
	// a decrypt error, not a zero date.
	_, err = testusers.DecryptBirthday(ctx, cipher, []testusers.EncryptedBirthday{{DOB: absent.DOB}})
	if err == nil {
		t.Fatal("a sealed null decrypted into encrypt.Date, which has no nil")
	}
	birthdays, err := testusers.DecryptBirthday(ctx, cipher, []testusers.EncryptedBirthday{{DOB: present.DOB}})
	if err != nil || birthdays[0].DOB != dob {
		t.Fatalf("a present date reads into either: %v, %+v", err, birthdays)
	}
}
