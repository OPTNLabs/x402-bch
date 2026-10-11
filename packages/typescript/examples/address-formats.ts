import { encodeBase58Address } from '@bitauth/libauth';
import {
  decodeBchAddressScript,
  encodeCashAddrScript,
  p2pkhScript,
  p2sh20Script,
  p2sh32Script,
} from '../src/crypto.js';
import type { BchNetwork } from '../src/index.js';

const MAINNET: BchNetwork = 'bch:bitcoincash';
const CHIPNET: BchNetwork = 'bch:bchtest';

/** Normalize CashAddr and legacy Base58Check addresses to locking bytecode. */
export function inspectAddress(address: string, network: BchNetwork) {
  return decodeBchAddressScript(address, network);
}

const publicKeyHash = new Uint8Array(20).fill(0x11);
const scriptHash20 = new Uint8Array(20).fill(0x22);
const scriptHash32 = new Uint8Array(32).fill(0x33);

export const addressExamples = {
  cashAddrP2pkh: encodeCashAddrScript(p2pkhScript(publicKeyHash), MAINNET),
  cashAddrP2sh20: encodeCashAddrScript(p2sh20Script(scriptHash20), MAINNET),
  cashAddrP2sh32: encodeCashAddrScript(p2sh32Script(scriptHash32), CHIPNET),
  tokenAwareP2sh32: encodeCashAddrScript(p2sh32Script(scriptHash32), CHIPNET, true),
  legacyP2pkh: encodeBase58Address('p2pkh', publicKeyHash),
};

// Legacy addresses can be decoded for UTXO lookup, but CashToken payments
// still require a token-aware CashAddr merchant destination.
export const inspectedAddresses = Object.entries(addressExamples).map(([kind, address]) => ({
  kind,
  address,
  decoded:
    kind === 'cashAddrP2sh32' || kind === 'tokenAwareP2sh32'
      ? inspectAddress(address, CHIPNET)
      : inspectAddress(address, MAINNET),
}));
