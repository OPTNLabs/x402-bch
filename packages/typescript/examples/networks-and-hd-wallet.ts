import {
  CHIPNET_BIP44_COIN_TYPE,
  BCH_MAINNET_BIP44_COIN_TYPE,
  deriveBchWalletAddress,
} from '../src/signer.js';
import type { BchNetwork } from '../src/index.js';

export function deriveReceiveAndChangeAddresses(mnemonic: string, network: BchNetwork) {
  const coinType =
    network === 'bch:bchtest' ? CHIPNET_BIP44_COIN_TYPE : BCH_MAINNET_BIP44_COIN_TYPE;
  return {
    receive: deriveBchWalletAddress(mnemonic, network, 0, 0, { coinType }),
    change: deriveBchWalletAddress(mnemonic, network, 1, 0, { coinType }),
  };
}

// Chipnet uses m/44'/1'/0'/change/index in this integration.
// Mainnet uses m/44'/145'/0'/change/index.
