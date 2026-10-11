# x402-BCH cross-language conformance

The protocol contract is defined in `spec/` and deterministic fixtures in
`spec/conformance/`. Every language implementation must consume the same
fixtures and produce the same canonical JSON, transaction bytes, txid, and
validation verdict.

| Language   | Package path          | Status                   |
| ---------- | --------------------- | ------------------------ |
| TypeScript | repository root       | reference implementation |
| Rust       | `rust/x402-chain-bch` | SDK implementation       |
| Go         | `packages/go`         | conformance scaffold     |
| Java       | `packages/java`       | conformance scaffold     |
| Python     | `packages/python`     | conformance scaffold     |
| C++        | `packages/cpp`        | conformance scaffold     |

The non-TypeScript packages begin with wire-level conformance. They must not
claim transaction-signing or BCH VM support until their implementation passes
the corresponding vectors.

Parity rules:

1. JSON field names and omission rules are defined by the fixtures.
2. BCH amounts, token amounts, txids, hashes, and byte strings are represented
   as decimal or lowercase hexadecimal strings at language boundaries.
3. A transaction is valid only after source outputs, BCH value, CashToken state,
   scripts, and request binding are checked.
4. Chain state is authoritative; local settlement stores are caches and replay
   controls only.
5. A fixture change is a protocol change and must update every language test.

Run `npm run parity:check` for the repository-level fixture check.
