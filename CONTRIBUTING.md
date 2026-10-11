# Contributing to `@optnlabs/x402-bch`

## Before you start

Please open an issue for substantial protocol, API, or architectural changes.
Small fixes, tests, documentation improvements, and example updates can usually
be submitted directly as a pull request.

## Development setup

Requirements:

- Node.js 20 or newer
- npm 9 or newer

```bash
cd packages/typescript
npm ci
npm test
npm run typecheck
npm run typecheck:examples
npm run build
npm run lint:check
npm run format:check
```

The TypeScript package is the npm workspace for these commands. From the
repository root, the equivalent cross-language parity command is:

```bash
npm --prefix packages/typescript run parity:check
```

The package uses Libauth for BCH primitives. Do not copy low-level BCH
transaction, CashToken, or signing logic from another implementation when a
Libauth primitive is available.

## Repository structure

```text
packages/typescript/src/
  crypto.ts                 BCH parsing, serialization, scripts, and validation
  provider.ts               Fulcrum/provider boundary
  signer.ts                 signer and HD derivation helpers
  types.ts                  wallet, provider, and x402 BCH types
  settlementStore.ts        settlement idempotency boundary
  exact/
    client/                 transaction creation and wallet integration
    server/                 BCH pricing and payment requirements
    facilitator/            verification, broadcast, and settlement policy
packages/typescript/examples/ focused client, server, wallet, and provider examples
packages/typescript/test/     deterministic fixtures and unit tests
packages/rust/                Cargo workspace and Rust SDK
packages/go/                  Go protocol-core package
packages/java/                Java protocol-core package
packages/python/              Python protocol-core package
packages/cpp/                 C++ protocol-core package
spec/                         shared protocol and conformance fixtures
tools/check-parity.mjs        repository-level cross-language parity runner
```

## BCH implementation rules

BCH is UTXO-based. Treat every payment as a state transition:

```text
selected inputs -> merchant output + token state + change outputs + fee
```

Changes must preserve these invariants:

- BCH values and CashToken amounts are validated separately.
- Every input outpoint is explicit and checked for stale or spent state.
- Token category, amount, NFT capability, and commitment are conserved.
- Change outputs are deterministic and satisfy BCH dust and standardness rules.
- Fees are paid by transaction inputs; the facilitator must not rewrite a
  signed transaction.
- P2PKH, P2SH20, and P2SH32 destinations remain distinguishable.
- CashScript/P2SH32 support validates and pays the compiled locking output; it
  does not execute or prove the later contract spend.
- Chain state is authoritative. Provider, mempool, and local wallet state are
  not equivalent evidence.

Keep these stages separate:

```text
intent -> build -> sign -> broadcast -> mempool -> confirmed -> finalized
```

## Wallet and key boundaries

The x402 client API must not require a mnemonic or private key. Wallets own HD
derivation, address discovery, UTXO selection and reservation, change-address
selection, signing, hardware-wallet interaction, and persistence/recovery.

The x402 client receives either a signer abstraction or a wallet adapter that
returns a complete signed transaction. WalletConnect, hardware wallets, and
browser extensions belong at that adapter boundary.

## Tests and fixtures

Add deterministic tests for changes to validation, serialization, transaction
construction, CashTokens, scripts, settlement, or network handling. Prefer
small fixtures with explicit source outputs, expected outputs, transaction IDs,
and fee values.

Live Chipnet tests must be opt-in and must never require secrets in the
repository. Clearly distinguish offline fixtures, Libauth/VM validation,
provider or mempool acceptance, broadcast, and confirmation evidence. Do not
label a unit-test result as live-chain or production evidence.

## Examples and documentation

Examples should be runnable or typecheckable and should use shared helpers where
appropriate. Keep distinct integration patterns in separate files. When
changing the public API, update the README and relevant examples, including an
explanation of how BCH differs from account-based networks.

## Pull requests

Pull requests should:

1. Describe the user-visible behavior and BCH-specific invariants.
2. Keep unrelated refactors out of the change.
3. Include tests or explain why tests are not applicable.
4. Include documentation/examples for new public behavior.
5. Report exact validation commands and results.
6. Call out live-network, provider, or wallet assumptions.

Before requesting review, confirm that the working tree contains no secrets,
generated artifacts, or unrelated changes. Signed commits are preferred.

## Reporting security issues

Do not publish private keys, mnemonics, exploitable transaction material, or
provider credentials in a public issue. Report security-sensitive issues
privately to the repository maintainers with sensitive material removed.
