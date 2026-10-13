# x402-BCH C++

C++ implementation of the wallet-agnostic x402-BCH protocol core. The public
headers cover requirements and payment-payload binding, strict BCH
transaction parsing/serialization, native value/output policy, CashAddr and
CashToken state, request commitments, txids, P2PKH/P2SH boundaries, and the
bounded `bch-bounded-v1` VM profile.

Public headers are grouped under `include/x402_bch/` (`types.hpp`,
`protocol.hpp`, `address.hpp`, `transaction.hpp`, `vm.hpp`, `crypto.hpp`, and
`payment.hpp`). The root `x402_bch.hpp` remains a compatibility umbrella.

The compiled `src/` layer exposes `Wallet`, `Signer`, `Utxo`, `Provider`, `ExactBchClient`,
`ExactBchSignerClient`, `ExactBchFacilitator`, and `SettlementStore` role boundaries matching the
TypeScript and Rust SDKs. Wallet keys, UTXO selection, and network transport
remain caller-owned adapters; the facilitator verifies provider-supplied
source outputs and broadcasts the unchanged transaction.
Include `x402_bch/client.hpp`, `builder.hpp`, `provider.hpp`,
`facilitator.hpp`, `server.hpp`, or `wallet.hpp` for a role-specific public
surface; `x402_bch.hpp` remains the compatibility umbrella.
`FailoverFulcrumTransport` provides sequential retry across caller-supplied
Electrum Cash transports; endpoint selection and chain consistency remain
application responsibilities.
`FulcrumProvider` maps the transport-backed transaction, broadcast, status,
tip, and double-spend-proof calls into the provider role. It returns
`unknown` for outpoint spend status unless an upstream indexer can prove it;
the adapter never infers spend state from confirmation height.

The P2PKH verifier uses GMP big integers, so install `libgmp-dev` locally.

```bash
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

CTest runs separate portable-conformance and SDK-adapter targets. The adapter
target covers settlement claims, provider-observed retry, request-hash
construction, CashToken fee inputs, Fulcrum token mapping, and transport
failover.
