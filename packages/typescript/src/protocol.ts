import type { PaymentPayload } from '@x402/core/types';
import { sha256 } from '@noble/hashes/sha256';
import { base64ToBytes, bytesToHex } from './crypto';
import type { ExactBchPaymentPayload, ExactBchRequirements } from './types';

/** Validate the shared wallet-agnostic BCH exact requirements contract. */
export function validateRequirements(requirements: ExactBchRequirements): void {
  const version = (requirements as ExactBchRequirements & { x402Version?: unknown }).x402Version;
  if ((version !== undefined && version !== 2) || requirements.scheme !== 'exact') {
    throw new Error('unsupported x402 BCH requirements');
  }
  if (requirements.network !== 'bch:bitcoincash' && requirements.network !== 'bch:bchtest') {
    throw new Error('unsupported BCH network');
  }
  if (!/^\d+$/.test(requirements.amount))
    throw new Error('amount must be an unsigned decimal string');
  if (!requirements.asset || !requirements.payTo) throw new Error('asset and payTo are required');
  if (requirements.extra.paymentFlow !== 'upfront') {
    throw new Error('BCH exact requires upfront payment');
  }
  if (
    requirements.extra.requestHash !== undefined &&
    !/^[0-9a-fA-F]{64}$/.test(requirements.extra.requestHash)
  ) {
    throw new Error('requestHash must be 32-byte hexadecimal');
  }
}

/** Validate a complete x402 payment payload against the server offer. */
export function validatePaymentPayload(
  payload: ExactBchPaymentPayload,
  expected: ExactBchRequirements,
): void {
  validateRequirements(expected);
  if (payload.x402Version !== 2) throw new Error('unsupported x402 payment payload version');
  const accepted = payload.accepted as ExactBchRequirements;
  for (const field of ['scheme', 'network', 'asset', 'amount', 'payTo'] as const) {
    if (accepted[field] !== expected[field])
      throw new Error(`accepted requirements mismatch: ${field}`);
  }
  const transaction = payload.payload?.transaction;
  if (typeof transaction !== 'string') throw new Error('transaction is required');
  if (
    transaction.length === 0 ||
    transaction.length % 4 !== 0 ||
    !/^[A-Za-z0-9+/]+={0,2}$/.test(transaction)
  ) {
    throw new Error('transaction must be non-empty base64');
  }
  if (base64ToBytes(transaction).length === 0) throw new Error('transaction must not be empty');
}

/** SHA-256 of the canonical request bytes supplied by the server. */
export function requestHash(canonicalRequest: string): string {
  if (canonicalRequest.length === 0) throw new Error('canonical request must not be empty');
  return bytesToHex(sha256(new TextEncoder().encode(canonicalRequest)));
}

/** Type helper for adapters that construct the x402 payload incrementally. */
export type BchPaymentPayload = PaymentPayload & ExactBchPaymentPayload;
