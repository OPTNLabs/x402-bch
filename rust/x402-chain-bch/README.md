# x402-chain-bch

Bitcoin Cash exact payment support for x402 v2.

The BCH chain IDs exposed by this crate are:

| Network | Chain ID          |
| ------- | ----------------- |
| Mainnet | `bch:bitcoincash` |
| Chipnet | `bch:bchtest`     |

The references are the CashAddr network prefixes used by BCH integrations.
They are not derived from the Bitcoin/BCH genesis block or fork height.

The client submits a complete signed BCH transaction. The facilitator fetches
authoritative source outputs, validates the BCH transition, and broadcasts the
same transaction. BCH `SIGHASH_ALL | SIGHASH_FORKID` (`0x41`) is used for the
standard P2PKH path. The implementation supports native BCH, fungible and NFT
CashTokens, and P2PKH/P2SH20/P2SH32 payment outputs. CashScript is supported as
an output/locking-script destination: x402 does not execute arbitrary
CashScript spending conditions or act as a covenant engine.

The wallet is responsible for selecting and reserving UTXOs, adding BCH and
token change, deriving change addresses, signing every input, and returning a
finalized raw transaction. The facilitator must not append inputs or mutate a
signed transaction. BCH amounts are satoshis; token amounts are atomic units.
Both are conserved independently.

`payTo` may be a CashAddr or, for a native BCH payment, a legacy Base58Check
P2PKH or P2SH20 address. P2PKH inputs may be signed with ECDSA or BCH Schnorr.

The facilitator requires exactly one output that matches the merchant script,
value, and token state, and no second output to the merchant script. A wallet
may add other outputs up to `BchPolicy::max_outputs` (16 by default), including
OP_RETURN data, and may spend inputs from more than one P2PKH key. Every
CashToken category and NFT must leave the transaction unchanged, so minting,
burning, and NFT capability changes are rejected. These are the same rules as
`@optnlabs/x402-bch`.

P2PKH inputs are verified here, signature included. Other inputs, such as
P2SH20 and P2SH32 contracts, are checked for a push-only unlocking script and,
for P2SH, the redeem script their source output commits to. This crate has no
BCH script VM, so the network runs those scripts when the facilitator
broadcasts the transaction, and settlement fails if one is invalid. The
TypeScript package runs them in the Libauth VM before broadcast. Both accept
the same valid payments.

To run those scripts during verification instead, give the provider a BCH
node: `FulcrumProvider::new(transport, network).with_node(node)`, where `node`
implements `BchNodeRpc` with one JSON-RPC call, for example over HTTP to the
Bitcoin Cash Node behind a Fulcrum server. Payments with non-P2PKH inputs then
go through the node's `testmempoolaccept` before verification succeeds. If the
node does not answer, the scripts are left to the network as before.

The wallet-facing request uses `mainnet` or `chipnet`. The x402 wire network
identities remain `bch:bitcoincash` and `bch:bchtest`.

`FulcrumProvider` implements the Electrum Cash JSON-RPC boundary used by
Fulcrum. The crate includes `FulcrumTcpTransport` for plain TCP and, with the
`websocket` feature, `FulcrumWebSocketTransport` for `ws://` and `wss://`
servers such as public Fulcrum endpoints on port 50004. Applications may also
supply their own transport through the `FulcrumTransport` trait, and should
inject a shared `BchSettlementStore` for multi-process facilitator
deployments.

The adapter accounts for Fulcrum's two amount encodings: verbose transaction
outputs are BCH decimal values, while blockchain.scripthash.listunspent returns
integer satoshis.

The crate test suite includes `test/fixtures/bch-exact-p2pkh.json`, a
deterministic native-BCH P2PKH payment fixture shared with the TypeScript
package [`@optnlabs/x402-bch`](https://www.npmjs.com/package/@optnlabs/x402-bch).
It covers the serialized transaction, source output, merchant amount, payer,
transaction ID, and fee so integrations can compare results across both SDKs.
`test/fixtures/bch-exact-offline-vectors.json` and
`test/fixtures/bch-exact-wallet-shape-vectors.json` are written by this crate's
tests and checked by the TypeScript package. The tests fail if the generated
vectors stop matching the committed copies.

## Related packages and pull requests

This crate is the Rust half of [`@optnlabs/x402-bch`](https://www.npmjs.com/package/@optnlabs/x402-bch).
Both live in [OPTNLabs/x402-bch](https://github.com/OPTNLabs/x402-bch).
Protocol message types come from published [`x402-types` 2.0.2](https://crates.io/crates/x402-types).
This crate is not on crates.io yet.

```toml
x402-chain-bch = { git = "https://github.com/OPTNLabs/x402-bch" }
```

Until that lands on `main`, use the stacked branch:

```toml
x402-chain-bch = { git = "https://github.com/CyberAshven/x402-bch", branch = "feat/rust-sdk" }
```

TypeScript installs the same package with `npm install @optnlabs/x402-bch`.
Both SDKs use `extra.value` for CashToken merchant satoshis. This crate still
accepts `tokenOutputValue` when reading an older message. The wallet request
has the same shape in both SDKs: `recipient.address`, the merchant satoshis in
`value`, and an optional `token`.

- npm package: https://www.npmjs.com/package/@optnlabs/x402-bch
- TypeScript pull request: https://github.com/OPTNLabs/x402-bch/pull/1
- Rust SDK pull request: https://github.com/OPTNLabs/x402-bch/pull/2
- Upstream Rust contribution: https://github.com/lightswarm124/x402-rs/pull/1
- Upstream BCH pull request: https://github.com/x402-rs/x402-rs/pull/129
- Closed earlier upstream request: https://github.com/x402-rs/x402-rs/pull/128

Chipnet payments from these branches:

- setup transaction: https://chipnet.chaingraph.cash/tx/210f4659913fa77500ce547d7103f2e163bc39b1ecb287dfb7b0748fdb8627a3
- TypeScript exact NFT payment: https://chipnet.chaingraph.cash/tx/7c46af9c142e092a82f1cfafe87212bbd9d4b15b9b6a52f10e6bf1b28331baef
- Rust exact native payment: https://chipnet.chaingraph.cash/tx/57b434f19d901960802ef93f601358ed7d5996b73f94e6f689c2be8b18943c09

## Transaction lifecycle

```text
requirements -> wallet UTXO selection -> build outputs/change -> sign
             -> x402 payload -> facilitator source-output validation
             -> broadcast -> mempool/confirmation reconciliation
```

Inputs contain outpoints, not the previous output value or locking script.
Consequently, the facilitator provider is authoritative for source outputs;
client-supplied source data cannot replace that lookup. A transport failure
after broadcast is indeterminate and must be reconciled by TXID. It must not
be treated as permission to build a second spend.

`BchFacilitatorConfig::settlement_strategy` defaults to one confirmation.
x402-axum settles the `upfront` flow before the handler runs, so a server
answers within the request only with `Mempool` or `NoDoubleSpendProof`. With a
confirmation count, settlement returns `settlement_pending:<txid>` until the
transaction confirms, and retrying the same payment does not broadcast it
again.

## CashTokens and P2SH32

Native requirements use `asset: "BCH"` and
`extra.assetTransferMethod: "native"`. CashToken requirements use
`extra.assetTransferMethod: "cashtoken"`, a token category and atomic amount,
and optional NFT capability/commitment data. Fungible token amounts, NFT
commitments/capabilities, BCH output values, and token change are validated as
separate UTXO invariants.

When a CashToken price omits `value`, the merchant output value
defaults to the greater of 1,000 satoshis, the configured policy dust
threshold, and the standard relay dust of that output. NFT commitments may be
empty or up to 128 bytes under the current consensus rule
([CHIP-2024-12](https://github.com/bitjson/bch-p2s)). A 128-byte commitment
can make the relay dust larger than 1,000 satoshis. The older 828-satoshi
figure is the relay dust of a 40-byte commitment on the largest locking
script this crate pays; it is not the maximum for a 128-byte commitment. An
explicit `value` is preserved and must still pass the size-based
dust check. A 129-byte commitment is rejected. Native BCH outputs keep the
546-satoshi dust floor.

P2SH32 is a valid payment destination for compiled CashScript contracts. The
facilitator verifies that the requested output pays the requested locking
script, but it does not prove the contract's future successor transaction.
Consensus validity, covenant topology, token provenance, wallet
authorization, and x402 payment settlement are separate concerns.

## Electrum endpoint redundancy

`FulcrumProvider` accepts an injected `FulcrumTransport`; the crate does not
silently select or trust a public server. For live deployments, applications
should configure a failover transport with more than one endpoint and prefer
TLS (port `50002`) or WSS (port `50004`) where available. The following set is
the BCH Electrum set referenced by CashScript's network-provider sources and
migration notes:

| Network | Endpoints                                                      |
| ------- | -------------------------------------------------------------- |
| Mainnet | `bch.imaginary.cash`, `blackie.c3-soft.com`, `electroncash.dk` |
| Chipnet | `chipnet.bch.ninja`                                            |

`FailoverFulcrumTransport` provides the minimum sequential failover behavior:
pass it caller-created transports in the desired order. It retries all
requests, including broadcasts; if a broadcast response is lost after the
server accepts a transaction, applications must reconcile the result by
checking transaction status rather than assuming the broadcast failed.

```rust,ignore
let transport = FailoverFulcrumTransport::new(vec![primary, secondary])?;
let provider = FulcrumProvider::new(transport, BchChainReference::MAINNET);
```

The bundled `FulcrumTcpTransport` is a native TCP building block and is not
compiled for `wasm32-unknown-unknown`. Browser callers use `JsFulcrumTransport`
and `BchBrowserClient` in `src/wasm.rs`, which call the same client,
transaction, and verifier code. The browser function returns the JSON-RPC
result as a string. Applications that need TLS or WSS on native should provide
a transport that performs certificate validation. Availability redundancy is
not chain verification: applications should compare chain tip/header data
across independent servers when making operational decisions.

See `examples/bch-browser` for a working page. Wasm builds need Clang.
`.cargo/config.toml` allows the implicit `memmove` declaration in the bundled
libsecp256k1 wasm sources.

Endpoint availability and chain consistency are deployment concerns and should
be revalidated by each operator. Do not disable certificate validation for a
failover endpoint.

```rust,ignore
use x402_chain_bch::{BchChainReference, FulcrumProvider, FulcrumTcpTransport, V2BchExact};
use x402_types::scheme::X402SchemeFacilitatorBuilder;

let transport = FulcrumTcpTransport::connect("127.0.0.1:50002").await?;
let provider = FulcrumProvider::new(transport, BchChainReference::CHIPNET);
let facilitator = V2BchExact.build(provider, None)?;
```
