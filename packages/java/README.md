# x402-BCH Java

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
pure BCH settlement acceptance policy is covered by the shared fixture; provider
transport and facilitator orchestration remain adapter boundaries.
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
