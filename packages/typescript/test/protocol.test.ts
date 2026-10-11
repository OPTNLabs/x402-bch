import { describe, expect, it } from 'vitest';
import { requestHash, validatePaymentPayload, validateRequirements } from '../src/protocol';
import type { ExactBchPaymentPayload, ExactBchRequirements } from '../src/types';

const requirements = {
  x402Version: 2,
  scheme: 'exact',
  network: 'bch:bchtest',
  asset: 'BCH',
  amount: '1000',
  payTo: 'bchtest:merchant',
  maxTimeoutSeconds: 300,
  extra: { assetTransferMethod: 'native', paymentFlow: 'upfront' },
} as ExactBchRequirements;

describe('shared x402 BCH protocol core', () => {
  it('validates requirements and the actual x402 payload shape', () => {
    validateRequirements(requirements);
    const payload = {
      x402Version: 2,
      accepted: requirements,
      payload: { transaction: 'AQID' },
    } as ExactBchPaymentPayload;
    validatePaymentPayload(payload, requirements);
    expect(() =>
      validatePaymentPayload({ ...payload, payload: { transaction: '!!!!' } }, requirements),
    ).toThrow();
  });

  it('shares the canonical request commitment', () => {
    expect(requestHash('{"url":"https://example.test/resource"}')).toBe(
      '1f3a0cf475878c9cd4664f6812ac05722e1de2a0d00d341b9ae72cbc48e9a675',
    );
  });
});
