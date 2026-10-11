import type { BchTransactionRequest, BchUtxo } from '../src/index.js';

/** Application-owned lifecycle boundary for concurrent BCH requests. */
export interface UtxoReservationStore {
  reserve(utxos: readonly BchUtxo[], request: BchTransactionRequest): Promise<void>;
  release(utxos: readonly BchUtxo[]): Promise<void>;
  markBroadcast(utxos: readonly BchUtxo[], txid: string): Promise<void>;
}

export async function createPaymentWithReservation(
  store: UtxoReservationStore,
  inputs: readonly BchUtxo[],
  request: BchTransactionRequest,
  sign: () => Promise<Uint8Array>,
  broadcast: (raw: Uint8Array) => Promise<string>,
) {
  await store.reserve(inputs, request);
  try {
    const raw = await sign();
    const txid = await broadcast(raw);
    await store.markBroadcast(inputs, txid);
    return txid;
  } catch (error) {
    await store.release(inputs);
    throw error;
  }
}
