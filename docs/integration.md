# x402-BCH integration guide

This guide is an executable integration map for `@optnlabs/x402-bch`.
The TypeScript files in `packages/typescript/examples/` are the smallest typechecked examples;
the snippets below show how they fit into an HTTP application.

## What this package supports

The package implements x402 v2's `exact` scheme for two BCH networks:

| Capability        | Supported behavior                                                                                       |
| ----------------- | -------------------------------------------------------------------------------------------------------- |
| Native BCH        | Atomic amounts in satoshis, `asset: "BCH"`                                                               |
| CashTokens        | Fungible quantities and NFT state (`capability`, `commitment`)                                           |
| Payment flow      | `upfront` only                                                                                           |
| Merchant outputs  | P2PKH, P2SH20, and P2SH32; CashToken outputs require a token-aware CashAddr                              |
| Wallet boundary   | A complete, signed raw transaction returned by `BchWallet`                                               |
| Low-level signing | `BchSigner`, Libauth serialization and BCH sighash handling                                              |
| Validation        | Source-output lookup, BCH VM/script validity, value/fee/dust policy, and complete CashToken conservation |
| Settlement policy | Mempool, no-double-spend-proof, or confirmation count                                                    |
| Provider          | Fulcrum/Electrum Cash with caller-supplied transport and optional failover                               |
| Replay safety     | Provider-backed outpoint checks plus an injected/shared `BchSettlementStore`                             |

The package does not implement `upto`, facilitator fee sponsorship, PSBT or
hardware-wallet transport, address discovery, wallet persistence, CashScript
compilation, or application-specific covenant successor policies. Those are
wallet or application responsibilities.

## Server: resource pricing and 402 handling

The resource server advertises BCH requirements through x402 core. A framework
adapter should keep the application handler unaware of transaction details:

```ts
import { x402ResourceServer } from '@x402/core/server';
import { ExactBchServerScheme } from '@optnlabs/x402-bch/exact/server';

const server = new x402ResourceServer(facilitator).register('bch:*', new ExactBchServerScheme());
await server.initialize();

const requirements = await server.buildPaymentRequirements({
  scheme: 'exact',
  network: 'bch:bitcoincash',
  payTo: merchantCashAddr,
  price: { amount: '1000', asset: 'BCH' }, // satoshis
  maxTimeoutSeconds: 60,
});

const paymentRequired = await server.createPaymentRequiredResponse(requirements, {
  url: 'https://api.example.com/weather',
  description: 'Weather data',
});

// The HTTP adapter normally performs this 402/verify/settle lifecycle.
// Framework code returns `paymentRequired` on 402, calls
// `server.verifyPayment(...)` for the received payload, runs the handler, then
// calls `server.settlePayment(...)` and returns the settlement response.
```

`facilitator` above is an `HTTPFacilitatorClient` or another x402 core
`FacilitatorClient`; it is not the BCH scheme object itself. For an in-process
merchant deployment, register the `ExactBchFacilitatorScheme` with an x402
facilitator client, or call its `verify` and `settle` methods from the
application-owned adapter described below.

For a CashToken price, use the category as `asset` and put the token state in
`extra`:

```ts
const tokenPrice = {
  amount: '25',
  asset: tokenCategoryHex,
  extra: {
    assetTransferMethod: 'cashtoken',
    paymentFlow: 'upfront',
    value: '687', // BCH satoshis assigned to the token-bearing merchant output
    token: { category: tokenCategoryHex, amount: '25' },
  },
};

const nftPrice = {
  ...tokenPrice,
  amount: '0',
  extra: {
    ...tokenPrice.extra,
    token: {
      category: tokenCategoryHex,
      amount: '0',
      nft: { capability: 'none', commitment: 'deadbeef' },
    },
  },
};
```

For human-readable prices, register a `MoneyParser`; the built-in parser is
deliberately strict and accepts atomic satoshi strings. See
`packages/typescript/examples/server-pricing.ts`.

## Client: 402, wallet, and retry

The x402 client receives requirements, asks the wallet for a complete signed
transaction, and retries the request with the encoded payment payload:

```ts
import { x402Client } from '@x402/core/client';
import { x402HTTPClient } from '@x402/core/http';
import { ExactBchScheme } from '@optnlabs/x402-bch/exact/client';

const coreClient = new x402Client().register(
  'bch:*',
  new ExactBchScheme(
    {
      async createPayment(request) {
        // The wallet owns UTXO selection, reservation, change, fee, and keys.
        return wallet.createSignedTransaction(request);
      },
    },
    provider,
  ),
);
const client = new x402HTTPClient(coreClient);

const first = await fetch(resourceUrl);
if (first.status === 402) {
  const requirements = client.getPaymentRequiredResponse(
    (name) => first.headers.get(name),
    await first.json(),
  );
  const payload = await client.createPaymentPayload(requirements);
  const paid = await fetch(resourceUrl, {
    headers: client.encodePaymentSignatureHeader(payload),
  });
}
```

For applications that own the selection and signer, pass a `BchSigner` instead
of a wallet and use `buildAndSignTransaction`. The low-level path still needs
the provider for UTXO discovery and source-output validation. The signer path
does not export mnemonic or private-key material through x402.

## Provider-backed facilitator settlement

In this package, “facilitator” means an x402 role, not a BCH signing
authority. It has no signer and does not rewrite the transaction:

```ts
import { ExactBchFacilitatorScheme } from '@optnlabs/x402-bch/exact/facilitator';

const facilitator = new ExactBchFacilitatorScheme(provider, {
  settlementStrategy: { kind: 'confirmations', count: 1 },
  settlementStore: sharedStore, // required when the service has multiple processes
});

// `facilitator.verify(payload, requirements)` validates without broadcasting.
// `facilitator.settle(payload, requirements)` validates, broadcasts the same
// raw transaction, and applies the selected settlement policy.
```

`mempool` is an explicit 0-conf choice. `noDoubleSpendProof` is still not a
confirmation. If a broadcast response is lost, reconcile the transaction by
TXID before retrying; rebuilding can consume the same discrete outpoints and
create a conflict.

## Are facilitators necessary on BCH?

Not as a cryptographic signer or transfer constructor. A merchant can replace
the hosted facilitator with an application-owned settlement service that:

1. decodes the payment transaction;
2. obtains authoritative source outputs and current outpoint status;
3. runs `verifyPayment` / BCH VM and CashToken conservation checks;
4. broadcasts the unchanged transaction; and
5. records TXID, resource binding, and settlement state.

That service is functionally the facilitator role even if it is deployed inside
the merchant. Covenants do not remove these operational steps. BCH opcodes and
CashScript can enforce authorization and successor-output invariants for UTXOs
that are actually locked by the covenant, but they cannot establish provider
reachability, current unspentness, transaction relay, confirmation policy, or
HTTP request replay identity. This repository currently treats CashScript/P2SH32
as a payment destination and validates the input program when source outputs
are supplied; it does not compile contracts or enforce application-specific
successor rules.

## BCH-specific user experience

Compared with an account-based chain, the user authorizes a concrete state
transition rather than an amount/nonce authorization:

```text
select UTXOs -> reserve them -> create merchant output and change
-> calculate fee -> sign every input -> submit one raw transaction
-> reconcile mempool/confirmation status by TXID
```

This means wallets must handle input selection, concurrent reservation, change
addresses, token change, dust thresholds, fee convergence, and recovery after a
lost broadcast response. A token payment also carries BCH satoshis for the
token-bearing output, while token quantities are conserved independently of
BCH value. A covenant may constrain the next spend, but it does not turn these
UTXO lifecycle concerns into an account balance.

The complete examples are indexed in `packages/typescript/examples/README.md`, including native,
fungible-token, NFT, P2SH32/CashScript, address, HD discovery, WalletConnect,
provider failover, validation, reservation, and settlement-store flows.
