# x402-BCH cross-language conformance

Each language package contains its own copy of the protocol fixture under
`spec/conformance/v1`. Every package can build and test without importing code
or files from another language package. The root parity tool compares those
fixtures and runs the package-local conformance commands.

This gate does not claim equal feature depth. Full portable SDK parity is
implemented as capability gates: a capability is complete only after shared
positive and negative vectors pass in every language. Browser/WASM,
WalletConnect, HTTP, Fulcrum, and BCHN integrations are adapters over that
portable surface, not literal APIs required in every language. See
[`PARITY_PLAN.md`](PARITY_PLAN.md) for the scope and sequence of those gates.

| Language   | Package path                   | Status                       |
| ---------- | ------------------------------ | ---------------------------- |
| TypeScript | `packages/typescript`          | portable SDK reference       |
| Rust       | `packages/rust`                | portable SDK reference       |
| Go         | `packages/go`                  | protocol-core implementation |
| Java       | `packages/java`                | protocol-core implementation |
| Python     | `packages/python`              | protocol-core implementation |
| C++        | `packages/cpp`                 | protocol-core implementation |

Every package exposes the same wallet-agnostic protocol-core behaviors:
requirements validation, x402 v2 payment-payload binding, non-empty base64
transaction-envelope validation, SHA-256 request commitments, conventional
BCH txid derivation, and the pure BCH settlement-acceptance policy. The Rust
and TypeScript packages additionally include
transaction construction/validation, wallet boundaries, provider integration,
and settlement behavior. Shared P2PKH signature verification is now a
protocol-core gate; arbitrary BCH VM execution, signing, and provider
transport remain explicit language-specific adapters rather than silently
divergent implementations.

Current capability matrix:

| Capability gate | TypeScript | Rust | Go | Java | Python | C++ |
| --- | --- | --- | --- | --- | --- | --- |
| Requirements and payload binding | pass | pass | pass | pass | pass | pass |
| Envelope shape and txid fixture | pass | pass | pass | pass | pass | pass |
| Request-hash OP_RETURN commitment | pass | pass | pass | pass | pass | pass |
| BCH transaction parsing/serialization | pass | pass | pass | pass | pass | pass |
| Native BCH value/output policy | pass | pass | pass | pass | pass | pass |
| CashAddr and standard script encoding | pass | pass | pass | pass | pass | pass |
| BCH script/VM signature validation | pass | P2PKH only | P2PKH | P2PKH | P2PKH | P2PKH |
| Bounded BCH VM stack/equality/HASH160 profile | pass | pass | pass | pass | pass | pass |
| P2SH20/P2SH32 redeem-script commitment | pass | pass | pass | pass | pass | pass |
| Settlement acceptance policy | pass | pass | pass | pass | pass | pass |
| Provider raw-transaction/txid reconciliation | pass | pass | pass | pass | pass | pass |
| Settlement outcome normalization | pass | pass | pass | pass | pass | pass |
| Deterministic settlement retry/orchestration | pass | pass | pass | pass | pass | pass |
| Provider-fact settlement projection | pass | pass | pass | pass | pass | pass |
| Provider source-output projection | pass | pass | pass | pass | pass | pass |
| CashToken prefix and fungible conservation | pass | pass | pass | pass | pass | pass |
| CashToken NFT/capability conservation | pass | pass | pass | pass | pass | pass |
| Provider/facilitator transport and source-output settlement | pass | pass | adapter boundary | adapter boundary | adapter boundary | adapter boundary |

The shared signed P2PKH fixture covers BCH ForkID ECDSA, payer-key binding, and mutated-signature
rejection across all six executable packages. The shared NFT fixture covers
zero-amount NFTs with the shared 40-byte portable x402 policy
cap and exact conservation for `none`, `mutable`, and `minting` capabilities.
The request-hash fixture requires a matching zero-value `OP_RETURN 0x20 <32-byte
hash>` commitment and rejects mismatched or missing commitments.
The P2SH fixture covers P2SH20/P2SH32 redeem-script hashing and rejects
non-push unlocking scripts or a mismatched redeem-script commitment. It does
not claim arbitrary redeem-script VM execution.
The `bch-bounded-v1` VM fixture covers BCH push operations, small integers,
`DUP`, `HASH160`, equality/verification, `OP_RETURN`, clean-stack, and stable
failure categories in all six languages. It intentionally excludes
transaction-dependent operations such as `CHECKSIG`, `CHECKDATASIG`, covenant
introspection, and CashToken introspection; those remain full-VM/provider
adapter responsibilities.
The settlement-policy fixture covers mempool acceptance, confirmation-depth
calculation, double-spend-proof rejection, and not-found/unknown/conflicted
states. It is pure policy over provider-observed facts; it does not provide a
provider transport or claim live-chain evidence.
The provider-observation fixture requires recomputing the txid from provider
returned raw bytes and rejects invalid candidates, mismatched txids, and a
missing observation.
The settlement-outcome fixture combines candidate validity, provider-byte
identity, transaction status, confirmation policy, and conflict state into the
same `accepted`, `pending`, or `rejected` result in every language. It is a
pure normalization gate; it does not replace provider transport or chain
observation.
The settlement-integration fixture adds deterministic replay binding, claim
conflict, lost-broadcast retry, and no-second-broadcast decisions. It preserves
the original transaction ID in pending responses and is also pure; it does not
claim that a broadcast or confirmation occurred.
The settlement-provider fixture composes raw provider bytes with normalized
status facts. It produces `match` only after recomputing the candidate txid from
those bytes; missing bytes remain `missing`, and malformed or different bytes
become `mismatch`. It is a provider-fact contract, not a transport or
source-output lookup implementation.
The provider-source-output fixture additionally proves `(txid, vout)` lookup
against provider bytes and distinguishes missing, mismatched, and out-of-range
outputs. It remains transport-neutral; it does not perform RPC calls.
BCHN's post-upgrade consensus path permits up to 128 bytes; the wider
41–128-byte range and its policy/dust vectors remain intentionally outside the
portable x402 policy cap for now. The shared negative fixture covers the
reserved-bit, invalid-capability, over-cap commitment, and fungible
non-conservation failures; broader negative coverage is a follow-up. Rust's
signature gate is intentionally P2PKH-only; non-P2PKH script checks are
delegated to an optional BCHN provider call. These protocol-core rows do not
claim full in-process BCH VM parity.

The remaining work is adapter and release work, not a missing shared verdict:

1. add provider/source-output fake adapters for Go, Java, Python, and C++ when
   those packages have consumers that need them;
2. add a separate full transaction-dependent VM/covenant vector set only when
   every language can support the same semantics and resource limits;
3. decide whether the wider BCHN 41–128-byte commitment policy belongs in the
   portable x402 policy, then add its policy and dust vectors if so;
4. run the no-skip CI gate on every release and keep live provider, mempool,
   broadcast, and confirmation evidence separate from offline conformance.

Each gate must compare stable normalized fields (`case_id`, acceptance,
`error_code`, `transaction_id`, `normalized_outputs`, and settlement state),
not language-specific exception text.

Parity roadmap:

| Phase | Exit criteria | Current state |
| --- | --- | --- |
| 0. Package boundaries | Independent manifests, tests, local fixtures, and a single root runner | complete |
| 1. Wire core | Requirements/payload binding, canonical amounts, transaction envelope, txids, request-hash commitments | complete |
| 2. BCH transaction core | Lossless parsing/serialization, native value policy, standard CashAddr/script forms | complete* |
| 3. CashToken core | Prefix codec, fungible conservation, NFT conservation, mutable/minting vectors, then negative cases | positive and initial negative coverage complete; broader negatives and 41–128-byte range next |
| 4. Script authorization | Shared signed P2PKH, P2SH20/P2SH32 commitment, and bounded VM vectors | P2PKH, P2SH commitment, and `bch-bounded-v1` VM profile complete; transaction-dependent VM spending remains an explicit follow-up |
| 5. Integration behavior | Source-output lookup, provider truth, facilitator settlement, replay/pending outcomes | Deterministic retry/orchestration contract complete in all six; provider/source-output/facilitator adapters remain TypeScript/Rust only for now |
| 6. Release gate | CI executes every package, no skipped language, identical normalized verdicts | CI configured; later capability phases remain |

“Complete*” for phase 2 means the protocol-core surface is covered; it does
not mean every language executes arbitrary BCH VM or CashScript. Phase 4's
P2PKH gate proves standard BCH ForkID authorization only; it does not prove
arbitrary VM, P2SH20, or P2SH32 spending.

Parity rules:

1. JSON field names and omission rules are defined by the fixtures.
2. BCH amounts, token amounts, txids, hashes, and byte strings are represented
   as decimal or lowercase hexadecimal strings at language boundaries.
3. The accepted payment requirements must match the server offer, including the
   complete `extra` object; `requestHash` is therefore negotiated data as well
   as a transaction-level OP_RETURN commitment.
4. A transaction is valid only after source outputs, BCH value, CashToken state,
   scripts, and request binding are checked.
5. Chain state is authoritative; local settlement stores are caches and replay
   controls only.
6. A fixture change is a protocol change and must update every language test.

Run `node tools/check-parity.mjs` from the repository root for the repository-level
fixture and package parity check. The root `tools/check-parity.mjs` is an
aggregate developer tool; it is not a runtime dependency of any package.
