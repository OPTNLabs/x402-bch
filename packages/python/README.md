# x402-BCH Python

Python implementation of the wallet-agnostic x402-BCH protocol core,
including lossless requirements, payment-payload binding, strict BCH transaction
parsing/serialization, native value/output policy, request commitments, BCH
txid derivation, standard CashAddr/script encoding, and CashToken prefix plus
fungible/NFT conservation. BCH and CashToken quantities remain decimal strings.
Standard BCH ForkID ECDSA P2PKH inputs and x402 request-hash OP_RETURN
commitments plus P2SH20/P2SH32 redeem-script commitments are verified
in-process. The bounded `bch-bounded-v1` VM profile covers stack, equality,
HASH160, and clean-stack behavior; transaction-dependent VM execution,
signing, and provider transport remain explicit adapter boundaries. The
conformance fixtures are local to this package.
The pure BCH settlement acceptance policy is covered by the shared fixture.
The package exposes `BchWallet`, `BchSigner`, `BchUtxo`, `BchProvider`, `ExactBchClient`,
`ExactBchSignerClient`, `ExactBchFacilitator`, and `BchSettlementStore` role boundaries matching the
TypeScript/Rust SDK. Wallet keys, UTXO selection, and provider transport remain
caller-owned adapters.
Use the grouped `x402_bch.server`, `x402_bch.client`, `x402_bch.builders`,
`x402_bch.provider`, or `x402_bch.facilitator` modules when importing by role;
the `core` and `sdk` modules remain compatibility facades.
`FulcrumProvider` now maps the transport-backed Electrum Cash methods used by
the SDK (transaction retrieval, broadcast, status, tip, and double-spend-proof
lookups); outpoint spend status fails closed as `unknown` unless the caller
provides an indexer that can answer the source-script query. The provider does
not select or trust public endpoints. `FailoverFulcrumTransport` provides
sequential retry across caller-supplied transports.
`build_and_sign_native_payment` provides the corresponding explicit-UTXO
native BCH builder: fees, change, BCH ForkID signing, and post-build policy
validation are deterministic while keys remain in the injected signer.
`provider_transaction_matches` performs the shared raw-byte-to-txid identity
check without assuming a network transport. The shared deterministic
settlement-integration fixture covers replay binding, pending txid preservation,
and same-transaction retry decisions without network I/O.
The settlement-provider fixture additionally derives provider observation from
raw bytes before retry decisions. The provider-source-output fixture covers
authoritative `(txid, vout)` projection without RPC transport.

```bash
python3 tests/run_conformance.py
```

Run `PYTHONPATH=src:tests python3 tests/run_sdk.py` for the native SDK tests.
They cover settlement claims, provider-observed retry without rebroadcast,
request-hash construction, CashToken payments with an ordinary BCH fee UTXO,
and Fulcrum CashToken UTXO mapping.
