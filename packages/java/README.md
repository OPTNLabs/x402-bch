# x402-BCH Java

`X402BchSdk.ExactBchClient` delegates construction to an application-owned
wallet, while `X402BchSdk.ExactBchSignerClient` performs explicit provider
UTXO selection through the caller-owned signer. Both paths validate source
outputs and request-hash commitments. Grouped entrypoints are available under
`x402bch.protocol`, `x402bch.transaction`, `x402bch.vm`,
`x402bch.settlement`, `x402bch.wallet`, `x402bch.server`,
`x402bch.builder`, `x402bch.client`, `x402bch.provider`, and
`x402bch.facilitator`.

Java implementation of the wallet-agnostic x402-BCH protocol core, including
requirements and payment-payload binding, BCH transaction parsing/serialization,
native value/output policy, request commitments, BCH txid derivation, standard
CashAddr/script encoding, and CashToken prefix plus fungible/NFT conservation.
Standard BCH ForkID ECDSA P2PKH inputs and x402 request-hash OP_RETURN
commitments plus P2SH20/P2SH32 redeem-script commitments are verified
in-process. The bounded `bch-bounded-v1` VM profile covers stack, equality,
HASH160, and clean-stack behavior; transaction-dependent VM execution,
signing, and provider transport remain explicit adapter boundaries. Its local
fixture under `spec/conformance/v1` defines the wire behavior checked by this
package; the repository parity tool compares it with the other languages. The
pure BCH settlement acceptance policy is covered by the shared fixture, while
provider transport and facilitator orchestration are exercised through injected
adapter tests. `X402BchSdk`
exposes `Wallet`, `Signer`, `Utxo`, `Provider`, `ExactBchClient`, `ExactBchSignerClient`, `ExactBchFacilitator`, and
`SettlementStore` role boundaries matching the TypeScript/Rust SDK. Keys, UTXO
selection, and provider transport remain caller-owned adapters.
New code can import the grouped `x402bch.server.Server`,
`x402bch.client.Client`, `x402bch.builder.Builders`,
`x402bch.provider.Provider`, or `x402bch.facilitator.Facilitator` entrypoints;
`X402Bch` and `X402BchSdk` remain compatibility facades.
`FailoverFulcrumTransport` provides sequential retry across caller-supplied
Electrum Cash transports. `FulcrumProvider` maps transport-backed transaction,
broadcast, status, tip, and double-spend-proof calls into the provider role;
outpoint status returns `unknown` unless the caller supplies an indexer that
can prove it.
`buildAndSignNativePayment` provides the explicit-UTXO native BCH builder with
deterministic fee/change convergence, ForkID signing through the injected
signer, and post-build policy validation.
`providerTransactionMatches` provides the shared raw-byte-to-txid identity
check without assuming a network transport. The shared deterministic
settlement-integration fixture covers replay binding, pending txid preservation,
and same-transaction retry decisions without network I/O.
The settlement-provider fixture additionally covers raw provider-byte
observation before retry decisions. The provider-source-output fixture covers
authoritative `(txid, vout)` projection without RPC transport.

```bash
make test
```

`make test` runs the portable conformance program, grouped-module checks, and
the native SDK adapter checks for settlement claims, provider-observed retry,
request-hash construction, CashToken fee inputs, Fulcrum token mapping, and
transport failover.
