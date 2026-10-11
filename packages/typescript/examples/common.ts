import type { BchProvider, BchWallet, ExactBchRequirements } from '../src/index.js';

export const BCH_NETWORK = 'bch:bchtest' as const;
// Deterministic valid Chipnet P2PKH address for examples; use your merchant's
// own address in an application.
export const MERCHANT_ADDRESS = 'bchtest:qqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zye3kwllue' as const;

/** Shared route pricing used by the client and server examples. */
export const nativeBchRequirements: ExactBchRequirements = {
  scheme: 'exact',
  network: BCH_NETWORK,
  asset: 'BCH',
  amount: '1000',
  payTo: MERCHANT_ADDRESS,
  maxTimeoutSeconds: 60,
  extra: { assetTransferMethod: 'native', paymentFlow: 'upfront' },
};

/**
 * The x402 client only needs this wallet boundary. The wallet owns UTXO
 * discovery, reservation, change-address selection, signing, and key custody.
 */
export function createWalletAdapter(
  createSignedTransaction: BchWallet['createPayment'],
): BchWallet {
  return { createPayment: createSignedTransaction };
}

/** Minimal transport shape for an application-provided Fulcrum adapter. */
export function createFulcrumTransport(
  request: (method: string, params: unknown[]) => Promise<unknown>,
) {
  return { request };
}

export function assertBchNetwork(provider: BchProvider): void {
  if (provider.network !== BCH_NETWORK) {
    throw new Error(`Example expects ${BCH_NETWORK}, got ${provider.network}`);
  }
}
