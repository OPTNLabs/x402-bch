import { sha256 } from '@noble/hashes/sha256';
import {
  MAX_TOKEN_COMMITMENT_LENGTH,
  decodeBchAddressScript,
  hexToBytes,
  bytesToHex,
  type CashToken,
} from './crypto';
import { MAX_CASH_TOKEN_AMOUNT, MAX_U64 } from './constants';
import type {
  BchNetwork,
  BchOutPoint,
  BchOutpointStatus,
  BchProvider,
  BchSourceOutput,
  BchTransactionStatus,
  BchUtxo,
} from './types';

export interface FulcrumTransport {
  /** Execute one Electrum Cash JSON-RPC method. */
  request(method: string, params: unknown[]): Promise<unknown>;
}

/**
 * Sequentially retries Fulcrum requests across caller-provided transports.
 *
 * Endpoint construction, TLS certificate validation, and endpoint ordering
 * remain application responsibilities. This helper only provides availability
 * failover; it does not validate chain consistency or SPV proofs.
 */
export class FailoverFulcrumTransport implements FulcrumTransport {
  constructor(private readonly transports: readonly FulcrumTransport[]) {
    if (transports.length === 0) throw new Error('at least one Fulcrum transport is required');
  }

  async request(method: string, params: unknown[]): Promise<unknown> {
    const errors: string[] = [];
    for (const transport of this.transports) {
      try {
        return await transport.request(method, params);
      } catch (error) {
        errors.push(String(error));
      }
    }
    throw new Error(`all Fulcrum transports failed: ${errors.join('; ')}`);
  }
}

/**
 * Fulcrum Electrum Cash provider adapter.
 *
 * The transport is injected so Node TCP/TLS, browser WebSocket, and hosted
 * JSON-RPC adapters can share the same BCH provider behavior. The reference
 * implementation is `/home/lightswarm/projects/fulcrum`.
 */
export class FulcrumProvider implements BchProvider {
  constructor(
    public readonly network: BchNetwork,
    private readonly transport: FulcrumTransport,
  ) {}

  /** Fetch and parse one authoritative transaction output. */
  async getSourceOutput(outpoint: BchOutPoint): Promise<BchSourceOutput> {
    const transaction = await this.transport.request('blockchain.transaction.get', [
      outpoint.txid,
      true,
    ]);
    const outputs = getObject(transaction).vout;
    if (!Array.isArray(outputs)) throw new Error('Fulcrum transaction response has no vout array');
    const output = outputs.find((value) => getNumber(getObject(value).n) === outpoint.vout);
    if (!output) throw new Error('source output was not found');
    const outputObject = getObject(output);
    const token = parseTokenData(outputObject.tokenData ?? outputObject.token_data);
    const script = getObject(outputObject.scriptPubKey);
    if (typeof script.hex !== 'string') throw new Error('source output has no script hex');
    return {
      value: parseBchAmount(outputObject.value),
      scriptPubKey: hexToBytes(script.hex),
      ...(token === undefined ? {} : { token }),
    };
  }

  /** Query Fulcrum for unspent outputs belonging to an address/script. */
  async listUtxos(address: string): Promise<BchUtxo[]> {
    const { scriptPubKey: script } = decodeBchAddressScript(address, this.network);
    const scriptHash = sha256(script).slice().reverse();
    const result = await this.transport.request('blockchain.scripthash.listunspent', [
      bytesToHex(scriptHash),
      'include_tokens',
    ]);
    if (!Array.isArray(result)) throw new Error('Fulcrum listunspent response is not an array');
    return result.map((value) => {
      const entry = getObject(value);
      const txid = String(entry.tx_hash ?? entry.txid ?? '');
      const vout = getNumber(entry.tx_pos ?? entry.vout);
      if (!/^[0-9a-fA-F]{64}$/.test(txid) || !Number.isInteger(vout) || vout < 0) {
        throw new Error('invalid Fulcrum UTXO outpoint');
      }
      const height = getNumber(entry.height);
      const token = parseTokenData(entry.tokenData ?? entry.token_data);
      return {
        txid,
        vout,
        value: parseSatoshiAmount(entry.value),
        scriptPubKey: script,
        ...(token === undefined ? {} : { token }),
        ...(height > 0 ? { height } : {}),
      };
    });
  }

  /** Determine whether the specified source outpoint remains unspent. */
  async getOutpointStatus(
    outpoint: BchOutPoint,
    source: BchSourceOutput,
  ): Promise<BchOutpointStatus> {
    const scriptHash = sha256(source.scriptPubKey).slice().reverse();
    const result = await this.transport.request('blockchain.scripthash.listunspent', [
      bytesToHex(scriptHash),
      'include_tokens',
    ]);
    if (!Array.isArray(result)) throw new Error('Fulcrum listunspent response is not an array');
    const unspent = result.some((value) => {
      const entry = getObject(value);
      return (
        String(entry.tx_hash ?? entry.txid ?? '').toLowerCase() === outpoint.txid.toLowerCase() &&
        getNumber(entry.tx_pos ?? entry.vout) === outpoint.vout
      );
    });
    return unspent ? 'unspent' : 'spent';
  }

  /** Broadcast raw transaction bytes through Fulcrum. */
  async broadcast(rawTransaction: Uint8Array): Promise<string> {
    const result = await this.transport.request('blockchain.transaction.broadcast', [
      bytesToHex(rawTransaction),
    ]);
    if (typeof result !== 'string' || !/^[0-9a-fA-F]{64}$/.test(result)) {
      throw new Error('Fulcrum broadcast did not return a transaction ID');
    }
    return result.toLowerCase();
  }

  /** Map Fulcrum height state to the package transaction status model. */
  async getTransactionStatus(txid: string): Promise<BchTransactionStatus> {
    try {
      const result = await this.transport.request('blockchain.transaction.get_height', [txid]);
      const height = getNumber(result);
      if (height > 0) return { kind: 'confirmed', height };
      if (height === 0 || height === -1) return { kind: 'mempool' };
      return { kind: 'notFound' };
    } catch (error) {
      const message = String(error).toLowerCase();
      if (
        message.includes('not found') ||
        message.includes('no such') ||
        message.includes('no transaction matching')
      ) {
        return { kind: 'notFound' };
      }
      throw error;
    }
  }

  /** Return the current Fulcrum chain tip height. */
  async getTipHeight(): Promise<number> {
    const result = await this.transport.request('blockchain.headers.subscribe', []);
    const height = getNumber(getObject(result).height);
    if (!Number.isInteger(height) || height < 0) throw new Error('invalid Fulcrum chain tip');
    return height;
  }

  /** Check Fulcrum for a double-spend proof for an unconfirmed transaction. */
  async hasDoubleSpendProof(txid: string): Promise<boolean> {
    const result = await this.transport.request('blockchain.transaction.dsproof.get', [txid]);
    return result !== null && result !== undefined && result !== '';
  }
}

function parseBchAmount(value: unknown): bigint {
  const text = typeof value === 'number' || typeof value === 'string' ? String(value) : '';
  const match = /^(\d+)(?:\.(\d+))?(?:e([+-]?\d+))?$/i.exec(text);
  if (!match) throw new Error('invalid BCH amount');

  const digits = `${match[1]}${match[2] ?? ''}`;
  const exponent = Number(match[3] ?? 0);
  if (!Number.isSafeInteger(exponent) || Math.abs(exponent) > 100) {
    throw new Error('invalid BCH amount exponent');
  }

  const decimalPlaces = (match[2]?.length ?? 0) - exponent;
  let amount: bigint;
  if (decimalPlaces <= 8) {
    amount = BigInt(digits) * 10n ** BigInt(8 - decimalPlaces);
  } else {
    const divisor = 10n ** BigInt(decimalPlaces - 8);
    const unscaled = BigInt(digits);
    if (unscaled % divisor !== 0n) throw new Error('BCH amount has more than 8 decimals');
    amount = unscaled / divisor;
  }
  if (amount > MAX_U64) throw new Error('BCH amount exceeds u64');
  return amount;
}

function parseSatoshiAmount(value: unknown): bigint {
  const text = typeof value === 'number' || typeof value === 'string' ? String(value) : '';
  if (!/^(0|[1-9][0-9]*)$/.test(text)) throw new Error('invalid BCH satoshi amount');
  const amount = BigInt(text);
  if (amount > MAX_U64) throw new Error('BCH satoshi amount exceeds u64');
  return amount;
}

function parseTokenData(value: unknown): CashToken | undefined {
  if (value === undefined || value === null) return undefined;
  const object = getObject(value);
  const category = String(object.category ?? '');
  if (!/^[0-9a-fA-F]{64}$/.test(category)) throw new Error('invalid CashToken category');
  const amount = object.amount === undefined ? 0n : parseTokenAmount(object.amount);
  const rawNft = object.nft;
  let nft: CashToken['nft'];
  if (rawNft !== undefined && rawNft !== null) {
    const nftObject = getObject(rawNft);
    const capability = String(nftObject.capability ?? 'none');
    if (capability !== 'none' && capability !== 'mutable' && capability !== 'minting') {
      throw new Error('invalid CashToken NFT capability');
    }
    const commitmentValue = nftObject.commitmentHex ?? nftObject.commitment ?? '';
    if (typeof commitmentValue !== 'string' || !/^(?:[0-9a-fA-F]{2})*$/.test(commitmentValue)) {
      throw new Error('CashToken NFT commitment must be hex');
    }
    const commitment = hexToBytes(commitmentValue);
    if (commitment.length > MAX_TOKEN_COMMITMENT_LENGTH) {
      throw new Error('CashToken commitment is too large');
    }
    nft = { capability, commitment };
  }
  if (amount === 0n && nft === undefined) throw new Error('CashToken output has no token data');
  return { category: category.toLowerCase(), amount, ...(nft === undefined ? {} : { nft }) };
}

function parseTokenAmount(value: unknown): bigint {
  const text = typeof value === 'number' || typeof value === 'string' ? String(value) : '';
  if (!/^(0|[1-9][0-9]*)$/.test(text)) throw new Error('invalid CashToken amount');
  const amount = BigInt(text);
  if (amount > MAX_CASH_TOKEN_AMOUNT) throw new Error('CashToken amount exceeds BCH limits');
  return amount;
}

function getObject(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('invalid Fulcrum response object');
  }
  return value as Record<string, unknown>;
}

function getNumber(value: unknown): number {
  const number = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(number)) throw new Error('invalid Fulcrum numeric value');
  return number;
}
