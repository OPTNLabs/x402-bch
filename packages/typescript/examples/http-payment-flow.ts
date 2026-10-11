import type { PaymentPayload, PaymentRequired } from '@x402/core/types';
import { x402Client } from '@x402/core/client';

/** Framework-neutral retry loop for a 402 response. */
export async function requestWithBchPayment(
  request: () => Promise<Response>,
  retryWithPayment: (paymentHeader: string) => Promise<Response>,
  client: x402Client,
  encodePayment: (payload: PaymentPayload) => string,
): Promise<Response> {
  const first = await request();
  if (first.status !== 402) return first;
  const paymentRequired = (await first.json()) as PaymentRequired;
  const paymentPayload = await client.createPaymentPayload(paymentRequired);
  return retryWithPayment(encodePayment(paymentPayload));
}
