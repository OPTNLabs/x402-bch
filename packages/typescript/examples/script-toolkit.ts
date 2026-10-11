import {
  bytesToHex,
  hash160,
  isP2pkhScript,
  isP2sh20Script,
  isP2sh32Script,
  isSupportedMerchantScript,
  p2pkhScript,
  p2sh20Script,
  p2sh32Script,
  verifyP2pkhInput,
  type BchTransaction,
} from '../src/crypto.js';
import type { BchSourceOutput } from '../src/index.js';

/** Inspect standard BCH locking scripts before passing them to a wallet. */
export function classifyLockingScript(script: Uint8Array) {
  return {
    hex: bytesToHex(script),
    p2pkh: isP2pkhScript(script),
    p2sh20: isP2sh20Script(script),
    p2sh32: isP2sh32Script(script),
    supportedMerchantScript: isSupportedMerchantScript(script),
  };
}

/**
 * Verify a P2PKH input and recover its public-key-hash identity.
 * The transaction and source output must come from the wallet/provider flow;
 * this function does not accept or expose private key material.
 */
export function verifyPayerInput(
  transaction: BchTransaction,
  inputIndex: number,
  source: BchSourceOutput,
  allSources: BchSourceOutput[] = [source],
) {
  return verifyP2pkhInput(transaction, inputIndex, source, allSources);
}

export const scriptExamples = [
  classifyLockingScript(p2pkhScript(new Uint8Array(20).fill(0x11))),
  classifyLockingScript(p2sh20Script(new Uint8Array(20).fill(0x22))),
  classifyLockingScript(p2sh32Script(new Uint8Array(32).fill(0x33))),
];

// Hashing a public key is the normal P2PKH identity derivation step.
export function publicKeyHash(publicKey: Uint8Array): Uint8Array {
  return hash160(publicKey);
}
