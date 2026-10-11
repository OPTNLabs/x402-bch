import { ExactBchScheme } from '../src/exact/client/index.js';
import { createSecp256k1BchSignerFromMnemonic } from '../src/signer.js';
import type { BchProvider } from '../src/index.js';

/**
 * Low-level client for applications that already own UTXO selection.
 * In production, read the mnemonic inside the wallet process only; never put
 * it in a browser bundle or x402 payment payload.
 */
export function createSignerBackedClient(provider: BchProvider, mnemonic: string) {
  const signer = createSecp256k1BchSignerFromMnemonic(mnemonic, {
    coinType: provider.network === 'bch:bchtest' ? 1 : 145,
  });
  return new ExactBchScheme(signer, provider);
}
