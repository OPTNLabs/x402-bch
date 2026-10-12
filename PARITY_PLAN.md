# Cross-language parity plan

## Goal

Provide one wallet-agnostic x402-BCH protocol contract implemented in
TypeScript, Rust, Go, Java, Python, and C++. “Parity” means the same normalized
accept/reject result and the same settlement meaning for the same BCH bytes and
provider facts. It does not mean that every language must expose the same
wallet, HTTP, provider, or framework adapter.

The TypeScript and Rust packages currently contain the deeper SDK and provider
integration. Go, Java, Python, and C++ are being brought up as protocol-core
implementations first. This keeps the common contract small enough to verify
and avoids copying account-model or wallet-specific assumptions into BCH UTXO
code.

## Source of truth

The protocol contract is represented by versioned fixtures under
`packages/*/spec/conformance/v1/`. Every package owns a byte-for-byte local
copy. `tools/check-parity.mjs` compares those copies before it runs the local
tests, so a language cannot silently test a different protocol.

Each conformance fixture must expose stable semantic fields (the JSON field
names may vary by vector family, but the normalized meaning is fixed):

```text
case id, accepted/rejected result, stable error category,
transaction identity, normalized outputs, settlement state
```

Exception text, class names, provider SDK types, and language-specific
serialization are not parity requirements.

## Capability tiers

| Tier | Shared contract | Exit evidence | Status |
| --- | --- | --- | --- |
| 1. Wire | x402 v2 requirements/payload binding, canonical amounts, base64 envelope, request hash, BCH txid | shared positive and negative fixtures in all six packages | complete |
| 2. BCH transaction core | lossless transaction parsing/serialization, CashAddr, native BCH value/fee/dust policy, CashToken state | identical raw bytes, txids, normalized outputs, and rejection cases | complete for current portable policy |
| 3. Authorization boundary | BCH ForkID P2PKH signatures; P2SH20/P2SH32 redeem-script commitment and push-only unlocking boundary | signed and mutated-signature fixtures plus P2SH commitment fixtures | complete for the declared boundary |
| 4. Settlement policy | mempool, confirmation depth, double-spend-proof, not-found, unknown, and conflicted decisions | one pure settlement-policy fixture exercised in all six languages | complete |
| 5. Provider identity, facts, and outcome | provider-returned raw transaction recomputes to the submitted txid; normalized settlement state is accepted, pending, or rejected | provider-observation, settlement-outcome, and provider-fact fixtures exercised in all six languages | complete |
| 6. VM authorization | common BCH VM vectors for the supported opcode/policy surface | the same `bch-bounded-v1` input/output/error vectors in all six languages | bounded profile complete; full transaction-dependent VM remains pending |
| 7. Integration | provider-fact projection, source-output lookup, chain truth, broadcast reconciliation, replay binding, pending response, idempotent settlement | provider-fact, provider-source-output, and settlement-integration fixtures in all six; provider-specific transports and live boundaries | shared projections/orchestration complete; provider transports and full facilitator adapters TypeScript/Rust only today |
| 8. Release | CI installs every toolchain and runs all gates without skipped languages | clean CI run and package-local commands | configured; release owner review still required |

Tier 5 is deliberately separate from P2SH destination support. A P2SH or
P2SH32 locking output can be paid without the x402 package executing the later
contract spend. Contract execution is only a parity claim after every language
passes the same VM vectors.

## Implementation sequence

### 1. Freeze the protocol fixtures

Add or change a fixture before adding language code. Validate field names,
omission rules, numeric ranges, txids, and expected error categories in the
root runner. Copy the exact bytes into all six package directories.

Current shared gates are:

- payment requirements and payload binding;
- transaction serialization and txid derivation;
- CashAddr and standard script forms;
- native BCH output and fee policy;
- fungible CashTokens and NFT capabilities;
- BCH ForkID P2PKH signatures;
- request-hash `OP_RETURN` commitments;
- P2SH20/P2SH32 redeem-script commitments;
- settlement acceptance policy;
- provider raw-transaction/txid reconciliation.
- provider-fact projection: `missing` without provider bytes, `match` only
  after recomputing the candidate txid from provider bytes, and `mismatch` for
  malformed or different bytes;
- normalized provider observations must never be inferred from a local txid
  without provider-returned bytes.
- normalized settlement outcomes (`accepted`, `pending`, `rejected`) from
  candidate validity, provider identity, status, confirmation policy, and
  conflict state.
- authoritative source-output projection keyed by `(txid, vout)` only after
  provider txid reconciliation; missing, mismatched, and out-of-range outputs
  have distinct normalized observations.
- bounded BCH VM stack/equality/HASH160 execution with clean-stack and stable
  error categories.
- deterministic settlement retry/orchestration decisions for replay binding,
  claim conflicts, lost broadcast responses, pending txid preservation, and
  no-second-broadcast behavior.

### 2. Implement pure protocol functions

Implement the fixture as a side-effect-free function in each language. Keep
provider calls, wallet calls, HTTP, and local persistence out of these
functions. This gives all six languages one deterministic unit to compare.

For BCH transaction checks, preserve these invariants:

- UTXOs are explicit inputs, not account balances or nonces.
- BCH value and CashToken state are checked independently.
- Merchant output, token category/amount/NFT state, change, dust, fee, and
  request commitment are all validated.
- A signed transaction is never rewritten by a facilitator.
- Chain/provider state is authoritative; local settlement state is only a
  replay and idempotency control.

### 3. Add negative vectors with every positive feature

Every new capability requires at least one rejection vector for malformed
encoding, stale/mismatched state, unauthorized output, and duplicate or
conflicting settlement. Do not use a language's exception text as the shared
result.

The bounded `bch-bounded-v1` authorization gate is specified against BCHN and
Libauth primitive semantics and is implemented in all six languages. It is not
full script parity: transaction-dependent operations (`CHECKSIG`,
`CHECKDATASIG`, locktime/sequence checks, covenant introspection, and
CashToken introspection) still require a separate vector set or an explicit
full-VM adapter boundary. A TypeScript-only VM path must not silently elevate
the other five packages to “full script support.”

### 4. Build integration adapters around the core

The integration layer can differ by language, but it must preserve the same
state machine:

```text
intent -> build -> sign -> broadcast -> mempool -> confirmed -> finalized
```

The provider-fact projection, source-output projection, retry state machine,
and deterministic fake-chain evidence boundary are now shared across all six
languages. TypeScript and Rust adapters still cover more of the actual provider
path. Network transports and full facilitator adapters are consumer-driven
extensions over this boundary, not additional protocol verdicts. Any such
extension should preserve:

- authoritative source-output retrieval;
- txid matching against provider-returned raw bytes;
- provider status and tip-height handling;
- normalized accepted/pending/rejected outcomes from those provider facts;
- replay binding and claim-conflict handling;
- broadcast response loss and retry;
- settlement claim conflict/idempotency;
- `settlement_pending` with a non-empty transaction ID;
- no second payment request when the original valid transaction is already
  observed on-chain.

Live Chipnet/mainnet, signing, and broadcast remain operator-owned tests and
are not release evidence for protocol parity.

### 5. Keep language scope explicit

TypeScript and Rust may expose wallet, HTTP, Fulcrum, BCHN, WASM, and framework
adapters. The other languages should only add those adapters when there is a
real consumer and a deterministic test boundary. Their protocol-core packages
must remain usable without importing another package or requiring a wallet key,
mnemonic, provider credential, or network connection.

## Required checks for each change

Run the smallest package test first, then the aggregate gate:

```bash
cd packages/typescript && npm run check
cd ../..
node tools/check-parity.mjs
git diff --check
```

The aggregate runner must report the fixture counts and each package result.
Ignored live-provider tests are expected to remain clearly labelled and do not
turn into a pass by absence of an endpoint.

## Definition of done

Parity is complete for a capability only when:

1. the capability has a versioned fixture and negative cases;
2. all six packages contain the exact fixture bytes;
3. all six package-local tests execute it;
4. the root runner checks both fixture identity and test execution;
5. documentation states whether the result is protocol-core, VM-backed,
   provider-backed, mempool-observed, confirmed, or still unverified.

The project is ready to call the common protocol surface stable when Tiers 1–4
are green and Tier 5 is either green or explicitly excluded from the supported
contract. Full SDK parity requires Tier 6 in every language and separate
review of wallet/provider security boundaries.
