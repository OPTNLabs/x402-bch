import { ExactBchFacilitatorScheme } from '../src/exact/facilitator/index.js';
import type { BchProvider } from '../src/index.js';
import { assertBchNetwork } from './common.js';

/** Construct the BCH facilitator scheme with explicit settlement policy. */
export function createBchFacilitator(provider: BchProvider) {
  assertBchNetwork(provider);
  return new ExactBchFacilitatorScheme(provider, {
    settlementStrategy: { kind: 'confirmations', count: 1 },
  });
}

// Register this scheme with an x402 facilitator service. The provider must
// fetch authoritative source outputs and transaction status from BCH infra.
