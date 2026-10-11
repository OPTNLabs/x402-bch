import type { BchProvider, BchTransactionRequest } from '../src/index.js';
import { encodeCashAddrScript, p2pkhScript } from '../src/crypto.js';
import { createWalletAdapter } from './common.js';

const TOKEN_CATEGORY = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const TOKEN_MERCHANT_ADDRESS = encodeCashAddrScript(
  p2pkhScript(new Uint8Array(20).fill(0x44)),
  'bch:bchtest',
  true,
);

/** Wallet request for a fungible CashToken payment. */
export const fungibleTokenRequest: BchTransactionRequest = {
  network: 'chipnet',
  recipient: { address: TOKEN_MERCHANT_ADDRESS },
  value: 687n,
  token: { category: TOKEN_CATEGORY, amount: 25n },
};

/** Wallet request for an NFT CashToken payment. */
export const nftRequest: BchTransactionRequest = {
  network: 'chipnet',
  recipient: { address: TOKEN_MERCHANT_ADDRESS },
  value: 687n,
  token: {
    category: TOKEN_CATEGORY,
    amount: 0n,
    nft: { capability: 'none', commitment: 'deadbeef' },
  },
};

export function createTokenWallet(
  provider: BchProvider,
  createSignedTransaction: (request: BchTransactionRequest) => Promise<Uint8Array>,
) {
  return createWalletAdapter(async (request) => {
    if (request.network !== (provider.network === 'bch:bchtest' ? 'chipnet' : 'mainnet')) {
      throw new Error('wallet network and provider network do not match');
    }
    // The wallet owns token UTXO selection, BCH/token change, and signing.
    return createSignedTransaction(request);
  });
}
