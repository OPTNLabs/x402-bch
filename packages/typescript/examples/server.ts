import { x402ResourceServer } from '@x402/core/server';
import { ExactBchServerScheme } from '../src/exact/server/index.js';

/** Register BCH pricing with an x402 resource server. */
export function createBchResourceServer(
  facilitator: ConstructorParameters<typeof x402ResourceServer>[0],
) {
  return new x402ResourceServer(facilitator).register('bch:*', new ExactBchServerScheme());
}

// Connect the returned server to your HTTP framework. The framework adapter
// should pass 402 requests through x402 core and keep application handlers
// independent from BCH transaction details.
