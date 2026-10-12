# x402-BCH C++

C++ implementation of the wallet-agnostic x402-BCH protocol core, including
requirements, payment-payload binding, strict BCH transaction
parsing/serialization, native value/output policy, BCH txid derivation,
standard CashAddr/script encoding, and CashToken prefix plus fungible/NFT
conservation. Standard BCH ForkID ECDSA P2PKH inputs and x402 request-hash
OP_RETURN commitments plus P2SH20/P2SH32 redeem-script commitments are
verified in-process. The bounded `bch-bounded-v1` VM profile covers stack,
equality, HASH160, and clean-stack behavior; transaction-dependent VM
execution, signing, and provider transport remain explicit adapter boundaries.
The P2PKH verifier uses GMP big integers, so install
`libgmp-dev` when building locally. Do not use floating-point values for BCH or
CashToken amounts; the local fixtures define the wire contract checked by this
package. Its settlement policy helper is covered by the shared provider-status
fixture; provider transport and facilitator orchestration remain adapter
boundaries. `provider_transaction_matches` covers the shared raw-byte-to-txid
identity check without assuming a network transport. The deterministic
settlement-integration fixture covers replay binding, pending txid preservation,
and same-transaction retry decisions without network I/O.
The settlement-provider fixture additionally derives provider observation from
raw bytes before retry decisions. The provider-source-output fixture covers
authoritative `(txid, vout)` projection without RPC transport.

```bash
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```
