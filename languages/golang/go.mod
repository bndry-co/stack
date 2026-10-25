module github.com/cipherstash/stack/languages/golang

go 1.26.10

// TEMPORARY: vcffi and vcvalue at cipherstash/vitaminc#526 (head c226edf),
// unreleased, for the storage profile (vcffi.MarshalStorage). Only Go writes
// and reads that profile; the guests stay on vitaminc 0.8.0 from crates.io,
// whose transport is the one this commit writes. Replace with the release.
require (
	github.com/cipherstash/vitaminc/bindings/go/vcffi v0.0.0-20261025114513-c226edfeaf43
	github.com/cipherstash/vitaminc/bindings/go/vcvalue v0.0.0-20261025114513-c226edfeaf43
	github.com/tetratelabs/wazero v1.12.0
	golang.org/x/oauth2 v0.37.0
)

require (
	github.com/jackc/pgx/v5 v5.11.0 // test only: encrypt/postgres_test.go, encrypt/eql_postgres_test.go
	golang.org/x/sys v0.49.0
	golang.org/x/tools v0.51.0
	google.golang.org/protobuf v1.36.12
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.3 // indirect
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/text v0.43.0 // indirect
)
