# x402-BCH cross-language conformance

Each language package contains its own copy of the protocol fixture under
`spec/conformance/v1`. Every package can build and test without importing code
or files from another language package. The root parity tool compares those
fixtures and runs the package-local conformance commands.

| Language   | Package path                   | Status                       |
| ---------- | ------------------------------ | ---------------------------- |
| TypeScript | `packages/typescript`          | complete SDK implementation  |
| Rust       | `packages/rust/x402-chain-bch` | SDK implementation           |
| Go         | `packages/go`                  | protocol-core implementation |
| Java       | `packages/java`                | protocol-core implementation |
| Python     | `packages/python`              | protocol-core implementation |
| C++        | `packages/cpp`                 | protocol-core implementation |

Every package exposes the same wallet-agnostic protocol-core behaviors:
requirements validation, x402 v2 payment-payload binding, non-empty base64
transaction-envelope validation, and SHA-256 request commitments. The Rust and
TypeScript packages additionally include transaction construction/validation,
wallet boundaries, provider integration, and settlement behavior. Signing,
BCH VM execution, and provider transport remain explicit language-specific
adapters for the other packages rather than silently divergent implementations.

Parity rules:

1. JSON field names and omission rules are defined by the fixtures.
2. BCH amounts, token amounts, txids, hashes, and byte strings are represented
   as decimal or lowercase hexadecimal strings at language boundaries.
3. A transaction is valid only after source outputs, BCH value, CashToken state,
   scripts, and request binding are checked.
4. Chain state is authoritative; local settlement stores are caches and replay
   controls only.
5. A fixture change is a protocol change and must update every language test.

Run `node tools/check-parity.mjs` from the repository root for the repository-level
fixture and package parity check. The root `tools/check-parity.mjs` is an
aggregate developer tool; it is not a runtime dependency of any package.
