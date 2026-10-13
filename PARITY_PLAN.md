# Cross-language parity plan

## Goal

Provide one wallet-agnostic x402-BCH SDK contract implemented in TypeScript,
Rust, Go, Java, Python, and C++. “Parity” means the same normalized
accept/reject result and the same settlement meaning for the same BCH bytes and
provider facts, plus matching role boundaries for server, client, wallet,
provider, facilitator, and settlement storage. HTTP/framework adapters may
remain idiomatic per language, but payment and settlement responsibilities must
not disappear from a package.

The TypeScript and Rust packages remain reference implementations for the
widest framework and transport integrations. Go, Java, Python, and C++ also
provide concrete HD derivation/signing, Fulcrum and BCHN transport/provider
adapters, deterministic mocknet UTXO providers, signer-backed and
external-wallet clients, builders, and facilitator/source-output lifecycles
behind the same wallet-agnostic role contract. The machine-readable feature
inventory is the strict gate; this document explains its scope.

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

## Strict gate and current blockers

The strict gate is intentionally machine-enforced:

```bash
X402_STRICT_PARITY=1 node tools/check-feature-manifest.mjs
node tools/check-api-inventory.mjs
node tools/check-parity.mjs
```

The first command is expected to pass for the declared portable SDK contract.
The remaining environment-sensitive evidence is executed by the aggregate
runner when the corresponding toolchain is available:

| Runtime check | Current evidence | Closure condition |
| --- | --- | --- |
| `provider.fulcrum-native:cpp` | C++ direct newline-delimited Fulcrum TCP transport, failover, provider mapping, and the same injected transport boundary; TLS/WSS remains caller-owned | no additional portable SDK obligation; add a TLS implementation only as an explicitly scoped adapter |
| `runtime.browser-wasm:rust` | WASM bindings exist in source and the release workflow installs the target before checking them; local hosts may not have the target | keep the CI target install and `X402_REQUIRE_WASM=1` aggregate check green |

These are environment-sensitive checks, not protocol-fixture gaps. The
portable feature manifest is complete for its declared contract; strict
release readiness still requires the CI workflow to execute the Rust WASM
check and the normal package security review.

## Capability tiers

| Tier | Shared contract | Exit evidence | Status |
| --- | --- | --- | --- |
| 1. Wire | x402 v2 requirements/payload binding, canonical amounts, base64 envelope, request hash, BCH txid | shared positive and negative fixtures in all six packages | complete |
| 2. BCH transaction core | lossless transaction parsing/serialization, CashAddr, native BCH value/fee/dust policy, CashToken state | identical raw bytes, txids, normalized outputs, and rejection cases | complete for current portable policy |
| 3. Authorization boundary | BCH ForkID P2PKH signatures; P2SH20/P2SH32 redeem-script commitment and push-only unlocking boundary | signed and mutated-signature fixtures plus P2SH commitment fixtures | complete for the declared boundary |
| 4. Settlement policy | mempool, confirmation depth, double-spend-proof, not-found, unknown, and conflicted decisions | one pure settlement-policy fixture exercised in all six languages | complete |
| 5. Provider identity, facts, and outcome | provider-returned raw transaction recomputes to the submitted txid; normalized settlement state is accepted, pending, or rejected | provider-observation, settlement-outcome, and provider-fact fixtures exercised in all six languages | complete |
| 6. VM authorization | common BCH VM vectors for the supported opcode/policy surface | the same `bch-bounded-v1` input/output/error vectors in all six languages | bounded profile complete; full transaction-dependent VM remains pending |
| 7. SDK roles | server requirement construction, wallet-to-payload client boundary, provider/facilitator/store interfaces, injected verification and settlement, transport failover | role API, lifecycle, and failover vectors in all six | role boundaries, lifecycle execution, and injected transport failover present in all six |
| 8. Concrete adapters | HD signing/discovery, provider transports, full facilitator/source-output lifecycle, browser/WASM where applicable | language-native adapters, deterministic fake evidence, and install/package checks | complete for native SDKs; browser/WASM remains language-specific |
| 9. Release | CI installs every toolchain and runs all gates without skipped languages | clean CI run and package-local commands | configured; release owner review still required |

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
- direct BCHN JSON-RPC `testmempoolaccept` mapping with stable allowed/reject
  results;
- deterministic mocknet UTXO transitions, authoritative source-output lookup,
  replay idempotency, and conflicting-spend rejection.

The role implementations additionally share these behavioral requirements:

- an external wallet's returned transaction is parsed and verified against
  provider source outputs before becoming an x402 payload;
- signer-backed clients perform provider UTXO selection and use the same
  explicit builder boundary;
- an optional request hash is encoded as the canonical zero-value OP_RETURN
  output and verified before the payload is returned or settled;
- a provider-observed transaction is reconciled by recomputing its txid and is
  accepted on retry without a second broadcast when the configured settlement
  policy accepts it.

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
and deterministic mocknet-chain evidence boundary are now shared across all
six languages. Native BCHN and Fulcrum transport boundaries are available in
all six. C++ bundles plain TCP for Fulcrum; Rust and C++ BCHN transports are
plain HTTP. TLS/WSS remains an explicit caller-owned transport extension where
the package does not bundle that runtime adapter.
Network transports and full facilitator adapters are extensions over this
boundary, not additional protocol verdicts. Any such extension should preserve:

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

### 5. Verify the strict runtime gates

Do not mark a runtime-specific capability complete because its source files
exist. For each remaining row, require:

1. a package-local executable smoke test;
2. a root-runner invocation of that smoke test;
3. an environment declaration for required native/runtime dependencies;
4. a negative-path test for unavailable endpoints, malformed responses, and
   timeout/transport failure;
5. a manifest update only after the evidence is reproducible.

For C++, any future TLS transport must be optional, clearly named, and have a
documented dependency boundary. Do not shell out to `openssl`, silently
downgrade `tls://` to plaintext, or convert a caller-owned secure transport
into a misleading package-level “native TLS” claim.

For Rust, keep the existing `JsFulcrumTransport` and browser client boundary;
the missing item is target/toolchain evidence, not a redesign of wallet or
provider ownership. The WASM check must remain free of private keys,
mnemonics, and live broadcast.

### 6. Keep language scope explicit

All six packages now expose wallet, Fulcrum, BCHN, and mocknet boundaries. The
HTTP, browser/WASM, and framework portions remain runtime-specific and must be
tracked as explicit capabilities rather than inferred from the protocol core.
Every package must remain usable without a wallet key, mnemonic, provider
credential, or network connection for its deterministic tests.

## Required checks for each change

Run the smallest package test first, then the aggregate gate:

```bash
cd packages/typescript && npm run check
cd ../..
node tools/check-parity.mjs
git diff --check
```

The aggregate runner must report the fixture counts and each package result.
It runs the complete TypeScript reference suite, not only the portable
fixture subset; TypeScript-specific provider, scheme, signer, settlement-store,
and wallet-shape tests are intentionally allowed to make that suite the most
comprehensive. Every other language must still execute every portable fixture
gate and cover its corresponding native SDK role boundaries.
Ignored live-provider tests are expected to remain clearly labelled and do not
turn into a pass by absence of an endpoint.

The native role-boundary minimum is the same across languages: settlement
claim/replay behavior, provider-observed retry without a second broadcast,
request-hash transaction construction, CashToken payment construction with an
ordinary BCH fee input, and injected provider transport/token-state mapping.
The exact test harness may be idiomatic per language, but a package is not
covered by compilation or fixture identity alone. TypeScript remains the
widest reference suite; extra wallet-shape, offline-vector, and provider cases
do not need to be duplicated when the portable gate and native minimum are
already exercised.

## Definition of done

Parity is complete for a capability only when:

1. the capability has a versioned fixture and negative cases;
2. all six packages contain the exact fixture bytes;
3. all six package-local tests execute it;
4. the root runner checks both fixture identity and test execution;
5. documentation states whether the result is protocol-core, VM-backed,
   provider-backed, mempool-observed, confirmed, or still unverified.

The project is ready to call the common protocol surface stable when Tiers 1–5
are green and Tier 7 plus native Tier 8 are green. Full SDK parity additionally
requires separate review of wallet/provider security boundaries and does not
claim full transaction-dependent VM/covenant execution.
