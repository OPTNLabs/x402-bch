import { base64ToBytes, bytesToBase64 } from './crypto';

export const BCH_PAYMENT_REQUIRED_HEADER = 'PAYMENT-REQUIRED';
export const BCH_PAYMENT_SIGNATURE_HEADER = 'PAYMENT-SIGNATURE';
export const BCH_PAYMENT_RESPONSE_HEADER = 'PAYMENT-RESPONSE';

export type BchHttpResponse = { status: number; headers: Record<string, string>; body?: string };

export function createBchPaymentRequiredResponse(requirementsJson: string): BchHttpResponse {
  return {
    status: 402,
    headers: { [BCH_PAYMENT_REQUIRED_HEADER]: encodeBchHttpHeader(requirementsJson) },
    body: 'Payment required',
  };
}

export function createBchPaymentSignatureHeader(payloadJson: string): Record<string, string> {
  return { [BCH_PAYMENT_SIGNATURE_HEADER]: encodeBchHttpHeader(payloadJson) };
}

export function createBchPaymentResponse(resultJson: string): Record<string, string> {
  return { [BCH_PAYMENT_RESPONSE_HEADER]: encodeBchHttpHeader(resultJson) };
}

export function encodeBchHttpHeader(json: string): string {
  if (!json) throw new Error('HTTP x402 header JSON must not be empty');
  return bytesToBase64(new TextEncoder().encode(json));
}

export function decodeBchHttpHeader(header: string): string {
  const decoded = new TextDecoder().decode(base64ToBytes(header));
  if (!decoded) throw new Error('HTTP x402 header JSON must not be empty');
  return decoded;
}
