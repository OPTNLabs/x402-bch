# BCH x402 examples

These examples are intentionally framework-neutral. They show the boundary
between x402 and the BCH wallet/provider/application that owns UTXOs, change,
signing, and broadcast.

See [`../../../docs/integration.md`](../../../docs/integration.md) for the end-to-end
client/server flow and an explanation of why a BCH deployment may embed the
facilitator role in the merchant while still needing provider-backed
verification, broadcast, and settlement tracking.

## Check the examples

From the repository root:

```bash
cd packages/typescript
npm run typecheck:examples
```

The examples do not contain mnemonics, private keys, network credentials, or
automatic broadcasts. Functions that need a wallet or provider accept one as
an argument.

## Example map

| File                        | Demonstrates                                                      |
| --------------------------- | ----------------------------------------------------------------- |
| `client.ts`                 | x402 client registration with a wallet adapter                    |
| `http-payment-flow.ts`      | 402 response, payment payload, and retry boundary                 |
| `server.ts`                 | BCH resource-server registration                                  |
| `server-pricing.ts`         | Native BCH and fungible CashToken pricing                         |
| `cashtoken-client.ts`       | Fungible and NFT wallet requests                                  |
| `payment-request-shapes.ts` | Native, fungible-token, and NFT request conversion                |
| `cashscript-p2sh32.ts`      | CashScript P2SH32 destination validation                          |
| `address-formats.ts`        | CashAddr, token-aware addresses, and legacy Base58Check           |
| `script-toolkit.ts`         | P2PKH/P2SH script classification and P2PKH verification           |
| `transaction-primitives.ts` | BCH transaction serialization, IDs, signing hashes, and OP_RETURN |
| `payment-validation.ts`     | Source-output and full payment validation                         |
| `native-signer-client.ts`   | Mnemonic-backed signer boundary                                   |
| `networks-and-hd-wallet.ts` | Mainnet/Chipnet BIP44 derivation                                  |
| `hd-discovery.ts`           | Receive/change address discovery with a gap limit                 |
| `walletconnect-adapter.ts`  | WalletConnect-style signed transaction boundary                   |
| `provider-failover.ts`      | Failover Fulcrum transport                                        |
| `facilitator.ts`            | Confirmation-based facilitator setup                              |
| `facilitator-policies.ts`   | Mempool, double-spend-aware, and confirmation policies            |
| `settlement-store.ts`       | Idempotent settlement claims and conflicts                        |
| `utxo-wallet-lifecycle.ts`  | Reservation, signing, broadcast, and rollback                     |
| `common.ts`                 | Shared requirements and wallet/provider helpers                   |

## Integration rules shown by the examples

- BCH `value` is measured in satoshis.
- CashToken `amount` is the token quantity; `category` identifies the token.
- NFT state uses `capability` and `commitment`.
- Mainnet uses `bch:bitcoincash` and BIP44 coin type `145`.
- Chipnet uses `bch:bchtest` and BIP44 coin type `1`.
- Wallets select and reserve UTXOs, calculate fees, create change, sign, and
  broadcast. The x402 payload contains the resulting complete transaction.
- Facilitators obtain authoritative source outputs from their provider before
  validating or broadcasting a payment.
- CashScript compilation and covenant-specific successor rules remain the
  responsibility of the application that owns the contract.
