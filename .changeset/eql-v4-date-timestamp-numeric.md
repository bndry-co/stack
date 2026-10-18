---
'@cipherstash/eql': minor
---

**Stack Encrypt produces the EQL v4 date, timestamp and numeric types `Date`, `DateEq`, `Timestamp`, `TimestampEq`, `Numeric` and `NumericEq`** (`eql-bindings`, `stack-encrypt` feature). Their Rust plaintexts are the crate's own `v4::plaintext::Date`, `Timestamp` and `Decimal`, which hold the integers the engine stores (days since 1970-01-01; Unix seconds and nanoseconds; a mantissa and a scale), are range checked when built and are wiped when dropped. The `chrono` and `rust_decimal` features convert to and from those crates' types. `=` on `NumericEq` normalises the scale (`1.5 = 1.50`) and on `TimestampEq` compares to the microsecond, truncating (never rounding) the nanoseconds below it; each value decrypts as it was stored. The ordered types of these families stay unproducible until the engine derives their order terms. The Go SDK's `encrypt/eql` table marks the six producible, from `encrypt.Date`, `time.Time` and `encrypt.Decimal`.
