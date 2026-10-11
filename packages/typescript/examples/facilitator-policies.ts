import { ExactBchFacilitatorScheme } from '../src/exact/facilitator/index.js';
import type { BchProvider } from '../src/index.js';

export function mempoolFacilitator(provider: BchProvider) {
  return new ExactBchFacilitatorScheme(provider, {
    settlementStrategy: { kind: 'mempool' },
  });
}

export function doubleSpendAwareFacilitator(provider: BchProvider) {
  return new ExactBchFacilitatorScheme(provider, {
    settlementStrategy: { kind: 'noDoubleSpendProof' },
  });
}

export function confirmedFacilitator(provider: BchProvider, confirmations = 1) {
  if (!Number.isInteger(confirmations) || confirmations < 1) {
    throw new Error('confirmations must be a positive integer');
  }
  return new ExactBchFacilitatorScheme(provider, {
    settlementStrategy: { kind: 'confirmations', count: confirmations },
  });
}
