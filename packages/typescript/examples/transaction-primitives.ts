import {
  base64ToBytes,
  bytesToBase64,
  bytesToHex,
  doubleSha256,
  hexToBytes,
  p2pkhScript,
  p2sh20Script,
  p2sh32Script,
  parseTransaction,
  pushData,
  serializeTransaction,
  signingHash,
  transactionId,
  type BchTransaction,
} from '../src/crypto.js';

const payerScript = p2pkhScript(new Uint8Array(20).fill(0x11));
const merchantScript = p2sh32Script(new Uint8Array(32).fill(0x22));

/** Construct and round-trip a raw BCH transaction using Libauth serialization. */
export function serializeAndIdentifyTransaction() {
  const transaction: BchTransaction = {
    version: 2,
    inputs: [
      {
        outpoint: { txid: '11'.repeat(32), vout: 0 },
        scriptSig: new Uint8Array(),
        sequence: 0xffffffff,
      },
    ],
    outputs: [
      { value: 1_000n, scriptPubKey: merchantScript },
      { value: 546n, scriptPubKey: payerScript },
      { value: 0n, scriptPubKey: Uint8Array.from([0x6a, ...pushData(hexToBytes('bch'))]) },
    ],
    lockTime: 0,
  };
  const raw = serializeTransaction(transaction);
  const parsed = parseTransaction(raw);
  const source = { value: 2_000n, scriptPubKey: payerScript };
  return {
    raw,
    parsed,
    txid: transactionId(parsed),
    signingHash: signingHash(parsed, 0, source, [source]),
    rawHex: bytesToHex(raw),
    rawBase64: bytesToBase64(raw),
    decodedBase64: base64ToBytes(bytesToBase64(raw)),
    txidDoubleHashExample: doubleSha256(raw),
    p2sh20Example: p2sh20Script(new Uint8Array(20).fill(0x33)),
  };
}
