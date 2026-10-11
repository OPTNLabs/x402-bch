# x402-BCH TypeScript

The complete TypeScript x402-BCH SDK lives in this package. It includes the
server, client, facilitator, provider, transaction, CashToken, request-hash,
and settlement components. Its conformance fixture is local to this package;
the repository parity tool compares it with the equivalent fixture in each
other language package. Wallet keys and provider access remain explicit
application boundaries.

## Standalone commands

Run these commands from this directory or use `npm --prefix packages/typescript`
from the repository root:

```bash
npm ci
npm test
npm run test:conformance
npm run check
```
