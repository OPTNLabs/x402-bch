import { decodeBchAddressScript, bytesToHex } from './crypto';
import type {
  BchNetwork,
  BchOutPoint,
  BchProvider,
  BchSourceOutput,
  BchTransactionStatus,
  BchUtxo,
} from './types';

export type MocknetTransaction = {
  txid: string;
  rawTransaction: Uint8Array;
  inputs: BchOutPoint[];
  outputs: BchSourceOutput[];
};

/** Deterministic in-memory UTXO chain for SDK and server integration tests. */
export class MocknetProvider implements BchProvider {
  readonly network: BchNetwork;
  private readonly tipHeight: number;
  private readonly unspent = new Map<string, BchUtxo>();
  private readonly outputs = new Map<string, BchSourceOutput>();
  private readonly transactions = new Map<string, Uint8Array>();
  private readonly registered = new Map<string, MocknetTransaction>();
  private readonly statuses = new Map<string, BchTransactionStatus>();

  constructor(network: BchNetwork, initialUtxos: BchUtxo[], tipHeight = 0) {
    this.network = network;
    this.tipHeight = tipHeight;
    for (const utxo of initialUtxos) {
      const key = outpointKey(utxo);
      if (this.unspent.has(key)) throw new Error(`duplicate mocknet outpoint ${key}`);
      this.unspent.set(key, copyUtxo(utxo));
      this.outputs.set(key, sourceFromUtxo(utxo));
    }
  }

  registerTransaction(transaction: MocknetTransaction): void {
    if (!/^[0-9a-f]{64}$/i.test(transaction.txid))
      throw new Error('mocknet txid must be 32-byte hexadecimal');
    this.registered.set(bytesToHex(transaction.rawTransaction), copyTransaction(transaction));
  }

  async listUtxos(address: string): Promise<BchUtxo[]> {
    const script = decodeBchAddressScript(address, this.network).scriptPubKey;
    return [...this.unspent.values()]
      .filter((utxo) => bytesToHex(utxo.scriptPubKey) === bytesToHex(script))
      .map(copyUtxo);
  }

  async getSourceOutput(outpoint: BchOutPoint): Promise<BchSourceOutput> {
    const output = this.outputs.get(outpointKey(outpoint));
    if (!output) throw new Error('mocknet source output was not found');
    return copySource(output);
  }

  async getOutpointStatus(outpoint: BchOutPoint): Promise<'unspent' | 'spent' | 'unknown'> {
    const key = outpointKey(outpoint);
    if (this.unspent.has(key)) return 'unspent';
    return this.outputs.has(key) ? 'spent' : 'unknown';
  }

  async broadcast(rawTransaction: Uint8Array): Promise<string> {
    const registered = this.registered.get(bytesToHex(rawTransaction));
    if (!registered) throw new Error('mocknet transaction is not registered');
    const knownStatus = this.statuses.get(registered.txid);
    if (knownStatus && knownStatus.kind !== 'conflicted') return registered.txid;
    for (const input of registered.inputs) {
      if (!this.unspent.has(outpointKey(input))) throw new Error('mocknet input is already spent');
    }
    for (const input of registered.inputs) this.unspent.delete(outpointKey(input));
    registered.outputs.forEach((output, vout) => {
      const outpoint = { txid: registered.txid, vout };
      const source = copySource(output);
      this.outputs.set(outpointKey(outpoint), source);
      this.unspent.set(outpointKey(outpoint), {
        ...outpoint,
        value: source.value,
        scriptPubKey: new Uint8Array(source.scriptPubKey),
        ...(source.token ? { token: copyToken(source.token) } : {}),
      });
    });
    this.transactions.set(registered.txid, new Uint8Array(registered.rawTransaction));
    this.statuses.set(registered.txid, { kind: 'mempool' });
    return registered.txid;
  }

  async getTransactionStatus(txid: string): Promise<BchTransactionStatus> {
    return this.statuses.get(txid) ?? { kind: 'notFound' };
  }

  async getTransaction(txid: string): Promise<Uint8Array | undefined> {
    const transaction = this.transactions.get(txid);
    return transaction ? new Uint8Array(transaction) : undefined;
  }

  async getTipHeight(): Promise<number> {
    return this.tipHeight;
  }

  async hasDoubleSpendProof(_txid: string): Promise<boolean> {
    return false;
  }

  confirm(txid: string, height = this.tipHeight): void {
    if (!this.transactions.has(txid)) throw new Error('mocknet transaction is not known');
    this.statuses.set(txid, { kind: 'confirmed', height });
    for (const [key, utxo] of this.unspent) {
      if (utxo.txid === txid) this.unspent.set(key, { ...utxo, height });
    }
  }
}

function outpointKey(outpoint: BchOutPoint): string {
  return `${outpoint.txid.toLowerCase()}:${outpoint.vout}`;
}
function sourceFromUtxo(utxo: BchUtxo): BchSourceOutput {
  return {
    value: utxo.value,
    scriptPubKey: new Uint8Array(utxo.scriptPubKey),
    ...(utxo.token ? { token: copyToken(utxo.token) } : {}),
  };
}
function copyUtxo(utxo: BchUtxo): BchUtxo {
  return {
    ...utxo,
    scriptPubKey: new Uint8Array(utxo.scriptPubKey),
    ...(utxo.token ? { token: copyToken(utxo.token) } : {}),
  };
}
function copySource(source: BchSourceOutput): BchSourceOutput {
  return {
    value: source.value,
    scriptPubKey: new Uint8Array(source.scriptPubKey),
    ...(source.token ? { token: copyToken(source.token) } : {}),
  };
}
function copyToken(
  token: NonNullable<BchSourceOutput['token']>,
): NonNullable<BchSourceOutput['token']> {
  return {
    category: token.category,
    amount: token.amount,
    ...(token.nft
      ? {
          nft: {
            capability: token.nft.capability,
            commitment: new Uint8Array(token.nft.commitment),
          },
        }
      : {}),
  };
}
function copyTransaction(transaction: MocknetTransaction): MocknetTransaction {
  return {
    txid: transaction.txid.toLowerCase(),
    rawTransaction: new Uint8Array(transaction.rawTransaction),
    inputs: transaction.inputs.map((input) => ({ ...input })),
    outputs: transaction.outputs.map(copySource),
  };
}
