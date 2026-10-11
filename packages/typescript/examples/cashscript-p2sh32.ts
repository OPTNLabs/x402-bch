import { decodeCashAddrScript } from '../src/crypto.js';
import type { BchNetwork } from '../src/index.js';

/**
 * CashScript compiles to locking bytecode. x402 treats the resulting P2SH32
 * address as a payment destination; contract execution belongs to the wallet,
 * covenant, or later-spend application flow.
 */
export function validateCashScriptDestination(network: BchNetwork, address: string) {
  const decoded = decodeCashAddrScript(address, network);
  if (decoded.scriptPubKey[0] !== 0xaa) {
    throw new Error('expected a P2SH32 CashScript destination');
  }
  return decoded.scriptPubKey;
}
