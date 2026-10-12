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
The pure BCH settlement acceptance policy is covered by the shared fixture;
provider transport and facilitator orchestration remain adapter boundaries.
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
