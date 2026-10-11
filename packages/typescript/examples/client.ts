import { x402Client } from '@x402/core/client';
import { ExactBchScheme } from '../src/exact/client/index.js';
import type { BchProvider, BchTransactionRequest } from '../src/index.js';
import { assertBchNetwork, createWalletAdapter } from './common.js';

/**
 * Browser/server application client example.
 *
 * No mnemonic or private key crosses this API. `walletBackend` can be a native
 * wallet, hardware wallet, browser extension, or WalletConnect adapter.
 */
export function createBchClient(
  provider: BchProvider,
  walletBackend: {
    createSignedTransaction(request: BchTransactionRequest): Promise<Uint8Array>;
  },
) {
  assertBchNetwork(provider);
  const wallet = createWalletAdapter((request) => walletBackend.createSignedTransaction(request));
  const client = new x402Client().register('bch:*', new ExactBchScheme(wallet, provider));
  return client;
}

// The HTTP client/interceptor is application-specific: on a 402 response,
// decode the payment requirements, ask this x402 client for a payload, encode
// the payload in the standard payment header, and retry the request.
