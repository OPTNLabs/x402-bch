import {
  verifyPayment,
  verifyTransactionInputs,
  type BchPaymentTarget,
  type BchTransaction,
  type BchPolicy,
} from '../src/crypto.js';
import type { BchNetwork, BchSourceOutput } from '../src/index.js';

/**
 * Validate a fully signed wallet transaction before broadcasting or settling.
 * The source outputs must come from authoritative BCH provider data.
 */
export function validateSignedPayment(
  transaction: BchTransaction,
  sources: BchSourceOutput[],
  network: BchNetwork,
  merchantScript: Uint8Array,
  target: BchPaymentTarget,
  policy?: BchPolicy,
) {
  const inputIdentities = verifyTransactionInputs(transaction, sources);
  const payment = verifyPayment(transaction, sources, network, merchantScript, target, policy);
  return { inputIdentities, payment };
}
