# x402-BCH TypeScript

The complete TypeScript x402-BCH SDK lives in this package. It includes the
server, client, facilitator, provider, transaction, CashToken, request-hash,
and settlement components. Provider-returned raw transactions are reconciled
against their recomputed txids before retry settlement is recognized. Its
conformance fixture is local to this package;
the repository parity tool compares it with the equivalent fixture in each
other language package. The shared `bch-bounded-v1` VM, settlement-integration,
and settlement-provider fixtures cover the portable authorization, provider
byte identity, and retry contract; wallet keys, provider transport, and
source-output access remain explicit application boundaries.

## Standalone commands

Run these commands from this directory or use `npm --prefix packages/typescript`
from the repository root:

```bash
npm ci
npm test
npm run test:conformance
npm run check
```
