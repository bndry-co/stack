package testusers

import "encoding/json"

//go:generate go run github.com/cipherstash/stack/languages/golang/cmd/stashgen -type Customer -name Customer

// Customer holds two encrypted JSON documents (the EQL type EncryptedJson,
// stored in public.eql_v4_json_tree): a profile whose $.age and every
// visit's $.at order, and optional preferences, stored as SQL NULL when nil.
type Customer struct {
	_       struct{}         `stash:"context=customers"`
	ID      int64            `stash:"id,passthrough"`
	Profile json.RawMessage  `stash:"profile,encrypt_into=EncryptedJson(ordered=$.age;$.visits[*].at)"`
	Prefs   *json.RawMessage `stash:"prefs,encrypt_into=EncryptedJson,null=sql"`
}
