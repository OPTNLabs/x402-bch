import type { BchTransactionRequest, BchWallet } from '../src/index.js';

/**
 * WalletConnect-style boundary.
 *
 * WalletConnect transports a request to a wallet; it does not define BCH
 * UTXO selection or transaction serialization. The connected wallet must
 * return the fully signed raw transaction bytes.
 */
export interface BchWalletConnectSession {
  request(args: {
    method: 'bch_signTransaction';
    params: [BchTransactionRequest];
  }): Promise<string>;
}

export function createWalletConnectBchWallet(
  session: BchWalletConnectSession,
  decodeRawTransaction: (encoded: string) => Uint8Array,
): BchWallet {
  return {
    async createPayment(request) {
      const signed = await session.request({
        method: 'bch_signTransaction',
        params: [request],
      });
      return decodeRawTransaction(signed);
    },
  };
}
