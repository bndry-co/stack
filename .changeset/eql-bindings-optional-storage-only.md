---
"@cipherstash/eql": patch
---

`eql-bindings` (the Rust crate released with this package): a storage-only EQL v4 type (`Date`, `Integer`, `Text`, and the other types with no term) now also implements `EncryptFrom` and `DecryptInto` for an `Option` of its plaintext. A `None` seals as a typed null as long as a value (vitaminc 0.8), so an optional column does not show which rows are absent, and opens as `None`. A value seals exactly as before. The by-name dispatch (`encryption::targets`) reads and opens these types through the `Option`, so a null frame encrypts and a stored null decrypts to a null; a type with a term still refuses a null. eql-bindings' own `Date`, `Timestamp` and `Decimal` plaintexts declare their fixed width to vitaminc, so their `None` is padded too. The SQL bundle and the TypeScript types do not change.
