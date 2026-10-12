# x402-BCH Go

Go implementation of the wallet-agnostic x402-BCH protocol core. It validates
requirements and payment payloads, binds a submitted transaction envelope to
the accepted request, parses and serializes BCH transactions, checks native BCH
value/output policy, computes request commitments, derives BCH txids from raw
transaction bytes, handles standard CashAddr/script encoding, and checks
CashToken prefix plus fungible/NFT state conservation. It also verifies
standard BCH ForkID ECDSA P2PKH inputs and x402 request-hash OP_RETURN
commitments plus P2SH20/P2SH32 redeem-script commitments. The bounded
`bch-bounded-v1` BCH VM profile covers stack, equality, HASH160, and clean-stack
behavior; transaction-dependent VM execution, signing, and provider transport
remain explicit adapter boundaries. The pure settlement
acceptance policy is also covered by the shared mempool, confirmation-depth,
double-spend-proof, and provider-status fixture.
Provider-returned raw transactions can be checked against a candidate txid
with `ProviderTransactionMatches`; this is an identity check, not a provider
transport or confirmation claim. The deterministic settlement-integration
fixture covers replay binding, pending txid preservation, and same-transaction
retry decisions without network I/O. `ObserveBchProviderTransaction` and
`ResolveBchSettlementFromProvider` derive settlement facts from provider bytes
before applying that state machine. `GetBchProviderSourceOutput` projects a
source `(txid, vout)` only after the same byte identity check.

The package is standalone and keeps its conformance fixture under
`spec/conformance/v1`.

```bash
go test ./...
```
