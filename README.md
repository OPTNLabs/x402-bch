# `@optnlabs/x402-bch`

This package is distributed as ESM because its Libauth dependency is ESM-only.
Use `import` or dynamic `import()` from Node.js and bundlers; CommonJS
`require()` is not supported.

Bitcoin Cash support for x402 v2 `exact` payments. BCH payments carry a
complete, client-signed transaction rather than an account authorization.

The public x402 network identifiers are `bch:bitcoincash` (mainnet) and
`bch:bchtest` (Chipnet). The wallet-facing transaction request uses the
corresponding network names `mainnet` and `chipnet`.

The package supports native BCH and CashTokens, including fungible tokens and
NFTs, with P2PKH, P2SH20, and P2SH32 payment outputs. Libauth is used for BCH
transaction parsing, serialization, signing serialization, CashToken data, and
address/script handling. Merchant and provider address boundaries accept
CashAddr and legacy Base58Check P2PKH/P2SH20 addresses; CashToken merchant
payments require a token-aware CashAddr. CashScript contracts are represented by their
compiled locking bytecode; x402 pays the contract output but does not execute
or validate the contract's later spending conditions.

## Rust

The same BCH exact rules are implemented for Rust in the `x402-chain-bch` crate.
It is not on crates.io yet. Until that crate is merged upstream, depend on the
open branch:

```toml
x402-chain-bch = { git = "https://github.com/CyberAshven/x402-rs", branch = "feat/bch-x402-rs-integration" }
```

- npm package: https://www.npmjs.com/package/@optnlabs/x402-bch
- TypeScript pull request: https://github.com/OPTNLabs/x402-bch/pull/1
- Rust pull request: https://github.com/lightswarm124/x402-rs/pull/1
- Upstream BCH pull request: https://github.com/x402-rs/x402-rs/pull/129
- Closed earlier upstream request: https://github.com/x402-rs/x402-rs/pull/128

Chipnet payments from these branches:

- setup transaction: https://chipnet.chaingraph.cash/tx/210f4659913fa77500ce547d7103f2e163bc39b1ecb287dfb7b0748fdb8627a3
- TypeScript exact NFT payment: https://chipnet.chaingraph.cash/tx/7c46af9c142e092a82f1cfafe87212bbd9d4b15b9b6a52f10e6bf1b28331baef
- Rust exact native payment: https://chipnet.chaingraph.cash/tx/57b434f19d901960802ef93f601358ed7d5996b73f94e6f689c2be8b18943c09

## BCH transaction model

Unlike account-based networks, BCH does not have a balance, nonce, or
facilitator-side transfer call. A wallet must construct a state transition:

```text
consume selected UTXOs
  -> required merchant output (BCH and optional CashToken state)
  -> one or more BCH/token change or application outputs
  -> optional OP_RETURN metadata
  -> miner fee
```

The wallet owns UTXO discovery, selection and reservation, fee calculation,
change-address selection, signing, and broadcast. The x402 client owns the
payment protocol and validates the wallet's returned transaction before
placing it in the payment payload. Mnemonics and private keys remain inside
the wallet adapter and are not part of the x402 client API.

The facilitator fetches authoritative source outputs from its provider and
checks input/output value, complete CashToken state conservation, signatures,
network, payment output, fee/dust policy, and transaction identity before
broadcasting the same raw transaction. It does not add inputs, rewrite
outputs, or create BCH change after signing.

The exact-payment validator requires exactly one matching merchant output, but
it may carry additional wallet or application outputs up to the configured
policy limit. Additional outputs may use P2PKH, P2SH20, P2SH32, other valid BCH
locking bytecode, or OP_RETURN metadata. CashToken state is conserved across
all inputs and outputs, including unrelated token categories selected by a
wallet. Token genesis, minting, burning, and unrelated NFT capability changes
are not implicitly authorized by an exact payment.

## Client

```ts
import type { BchWallet } from '@optnlabs/x402-bch';
import { ExactBchScheme } from '@optnlabs/x402-bch/exact/client';

client.register('bch:*', new ExactBchScheme(signer, provider));
```

For a low-level integration, `BchSigner` signs BCH sighash digests and
`BchProvider` supplies UTXOs and authoritative source outputs. For a normal
wallet integration, implement `BchWallet.createPayment(request)` and let the
wallet perform the complete transaction construction and signing:

```ts
const wallet: BchWallet = {
  async createPayment(request) {
    // Select and reserve UTXOs, add BCH/token change, and sign locally.
    return walletBackend.createSignedBchTransaction(request);
  },
};

const clientScheme = new ExactBchScheme(wallet, provider);
client.register('bch:*', clientScheme);
```

`BchTransactionRequest` contains `network`, `recipient.address`, and
`value`, the BCH satoshis assigned to the merchant output. For a fungible
CashToken, `token.amount` contains the token quantity and `token.category`
contains the category. For an NFT it additionally contains
`nft.capability` (`none`, `mutable`, or `minting`) and a commitment of 0 to
128 bytes. When a CashToken price omits `value`, the server and client fill a
size-aware default: the greater of 1,000 satoshis, the policy dust threshold,
and that output's standard relay dust. A 128-byte commitment can make the
relay dust larger than 1,000 satoshis. An explicit `value` is preserved and
rejected when it is below the output's dust threshold. Native BCH outputs keep
the 546-satoshi dust floor.

`BchSigner` is retained for integrations that already own UTXO selection and
transaction construction. `FulcrumProvider` implements the Electrum Cash
JSON-RPC boundary. Facilitators should inject a shared `BchSettlementStore`
when running more than one process.

The adapter accounts for Fulcrum's two amount encodings: verbose transaction
outputs are BCH decimal values, while blockchain.scripthash.listunspent returns
integer satoshis.

The package test suite includes deterministic local fixtures such as
`test/fixtures/bch-exact-p2pkh.json`. They cover the serialized transaction,
source output, merchant value, payer, transaction ID, and fee without requiring
another repository or external service.

## Electrum endpoint redundancy

The `FulcrumProvider` accepts an injected `FulcrumTransport`; it does not
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

```ts
const transport = new FailoverFulcrumTransport([primaryTransport, secondaryTransport]);
const provider = new FulcrumProvider('bch:bitcoincash', transport);
```

Availability redundancy is not chain verification. A failover transport may
retry a request against another server, but applications should compare chain
tip/header data across independent servers when making operational decisions.

Endpoint availability and chain consistency are deployment concerns and should
be revalidated by each operator. Do not disable certificate validation for a
failover endpoint.

## Facilitator

```ts
import { ExactBchFacilitatorScheme } from '@optnlabs/x402-bch/exact/facilitator';

facilitator.register(
  'bch:*',
  new ExactBchFacilitatorScheme(provider, {
    settlementStrategy: { kind: 'confirmations', count: 1 },
  }),
);
```

Mempool/0-conf mode is opt-in. The `noDoubleSpendProof` strategy accepts an
unconfirmed transaction only while the provider reports no BCH double-spend
proof; a proof is conflict evidence, not confirmation.

## Server

```ts
import { ExactBchServerScheme } from '@optnlabs/x402-bch/exact/server';

server.register('bch:*', new ExactBchServerScheme());
```

Use `{ amount: '1000', asset: 'BCH' }` for a 1,000-satoshi native BCH price.
CashToken requirements use the token category as `asset` and describe the
fungible/NFT state in `extra.token` with
`extra.assetTransferMethod: 'cashtoken'`. Amounts are decimal strings in the
x402 wire objects; wallet-facing amounts are converted to `bigint`. NFT-only
requirements use a token amount of `0` plus the NFT capability and commitment.

## Network and settlement notes

`bch:bitcoincash` and `bch:bchtest` are distinct networks. A mainnet address,
UTXO, provider, or transaction must never be reused for Chipnet. `maxTimeoutSeconds`
is an HTTP/resource acceptance window; it is not a BCH transaction expiry.

The facilitator can use mempool, no-double-spend-proof, or confirmation-count
settlement strategies. Mempool/0-conf acceptance is an explicit deployment
choice, not a confirmation. A broadcast whose status is temporarily unknown
must be reconciled by transaction ID rather than blindly rebuilt, because BCH
inputs are discrete outpoints and a retry can conflict with the original
transaction.

## Scope boundary

This package supports exact upfront payments. It does not turn x402 into a
general CashScript compiler or contract protocol, provide facilitator fee
sponsorship, or implement account-style `upto` debits. Libauth validates
P2SH20/P2SH32 input programs when the provider supplies their source outputs;
application-specific covenant successor rules remain an explicit extension.
PSBT, hardware-wallet transport,
WalletConnect, address discovery, UTXO reservation, and recovery from wallet
storage remain wallet/application responsibilities; the finalized raw
transaction is the x402 settlement object.

## Examples

The `examples/` directory keeps each integration concern in a separate file and
uses `common.ts` for shared network, wallet, and provider helpers:

| Example                                        | Covers                                                   |
| ---------------------------------------------- | -------------------------------------------------------- |
| `client.ts`                                    | Wallet-agnostic x402 client integration                  |
| `native-signer-client.ts`                      | Low-level signer-backed client and HD mnemonic boundary  |
| `cashtoken-client.ts`                          | Fungible and NFT CashToken requests                      |
| `payment-request-shapes.ts`                    | Native, fungible-token, and NFT wallet requests          |
| `cashscript-p2sh32.ts`                         | CashScript/P2SH32 payment destinations                   |
| `address-formats.ts`                           | CashAddr, token-aware, P2SH, and legacy address handling |
| `transaction-primitives.ts`                    | Libauth transaction serialization and signing hashes     |
| `payment-validation.ts`                        | Provider-backed VM and payment validation                |
| `script-toolkit.ts`                            | Script classification and P2PKH input verification       |
| `settlement-store.ts`                          | Idempotent settlement claims and conflicts               |
| `hd-discovery.ts`                              | Gap-limited receive/change address discovery             |
| `walletconnect-adapter.ts`                     | WalletConnect-style fully signed transaction adapter     |
| `networks-and-hd-wallet.ts`                    | Mainnet/Chipnet and BIP44 receive/change derivation      |
| `provider-failover.ts`                         | Multiple Fulcrum transport endpoints                     |
| `server.ts` and `server-pricing.ts`            | Resource server registration and BCH/token pricing       |
| `facilitator.ts` and `facilitator-policies.ts` | Confirmation, mempool, and double-spend-aware settlement |
| `utxo-wallet-lifecycle.ts`                     | Reservation, broadcast, and failure recovery             |
| `http-payment-flow.ts`                         | Framework-neutral 402 retry boundary                     |

Typecheck them with:

```bash
npm run typecheck:examples
```
