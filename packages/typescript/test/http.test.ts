import { describe, expect, it } from 'vitest';
import {
  BCH_PAYMENT_REQUIRED_HEADER,
  createBchPaymentRequiredResponse,
  decodeBchHttpHeader,
} from '../src/http';

describe('portable HTTP x402 boundary', () => {
  it('emits a 402 response and decodes the payment-required header', () => {
    const response = createBchPaymentRequiredResponse('{"x402Version":2}');
    expect(response.status).toBe(402);
    expect(decodeBchHttpHeader(response.headers[BCH_PAYMENT_REQUIRED_HEADER])).toBe(
      '{"x402Version":2}',
    );
  });
});
