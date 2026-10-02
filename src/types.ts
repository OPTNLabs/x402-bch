/** Public type and request model for the BCH x402 exact scheme. */
import type { PaymentPayload, PaymentRequirements, ResourceInfo } from '@x402/core/types';

/** x402 network identifiers supported by this package. */
export type BchNetwork = 'bch:bitcoincash' | 'bch:bchtest';
/** Wallet-facing network names used in transaction requests. */
export type BchTransactionNetwork = 'mainnet' | 'chipnet';

/** CashToken NFT capability as defined by the BCH token protocol. */
export type TokenCapability = 'none' | 'mutable' | 'minting';

/** CashToken NFT state, matching Libauth terminology. */
export type CashTokenNft = {
  /** Whether the NFT carries no, mutable, or minting authority. */
  capability: TokenCapability;
  /** NFT commitment encoded as lowercase or mixed-case hexadecimal text. */
  commitment: string;
};

export type CashTokenRequest = {
  /** 32-byte CashToken category, represented as hexadecimal text. */
  category: string;
  /** Fungible token quantity; use zero for an NFT-only transfer. */
  amount: bigint;
  /** Optional NFT state transferred with the fungible quantity. */
  nft?: CashTokenNft;
};

export type BchTransactionRequest = {
  /** BCH network on which the wallet must construct the transaction. */
  network: BchTransactionNetwork;
  /** Merchant destination. The wallet may use another address for change. */
  recipient: { address: string };
  /** BCH satoshis assigned to the merchant output, independent of token amount. */
  value: bigint;
  token?: CashTokenRequest;
};

export type BchWalletAddress = {
  /** Derived CashAddr. */
  address: string;
  /** BIP44 derivation path used to derive the address. */
  path: string;
  /** `0` for receive and `1` for change. */
  change: 0 | 1;
  /** Address index within the branch. */
  index: number;
  /** Optional provider-discovered UTXOs for this address. */
  utxos?: BchUtxo[];
};

/** Limits used by gap-limited HD address discovery. */
export type BchHdDiscoveryOptions = {
  /** Account number in the BIP44 path. Defaults to zero. */
  accountIndex?: number;
  /** Consecutive unused addresses before a branch is considered complete. */
  gapLimit?: number;
  /** Hard upper bound on addresses scanned per branch. */
  maxAddresses?: number;
};

/** Wallet boundary used by the x402 client; key material remains wallet-owned. */
export interface BchWallet {
  /** Build and return a fully signed raw BCH transaction. */
  createPayment(request: BchTransactionRequest): Promise<Uint8Array>;
}

/**
 * Convert an x402 BCH network identifier to the wallet-facing transaction name.
 *
 * @param network x402 network identifier.
 * @returns The network name used by wallet transaction builders.
 * @throws If the network is not supported by this package.
 */
export function toBchTransactionNetwork(network: BchNetwork): BchTransactionNetwork {
  if (network === 'bch:bitcoincash') return 'mainnet';
  if (network === 'bch:bchtest') return 'chipnet';
  throw new Error(`Unsupported BCH network: ${network}`);
}

/**
 * Convert x402 payment requirements into a wallet-owned BCH transaction request.
 *
 * @param requirements Validated BCH exact-payment requirements.
 * @returns Recipient, BCH value, network, and optional CashToken state.
 * @throws If the requirements contain an unsupported network or invalid numeric values.
 */
export function toBchTransactionRequest(
  requirements: Pick<ExactBchRequirements, 'network' | 'payTo' | 'amount' | 'asset' | 'extra'>,
): BchTransactionRequest {
  const extra = requirements.extra;
  const isCashToken = extra.assetTransferMethod === 'cashtoken';
  const value = isCashToken ? BigInt(extra.value ?? '1000') : BigInt(requirements.amount);
  return {
    network: toBchTransactionNetwork(requirements.network),
    recipient: { address: requirements.payTo },
    value,
    ...(isCashToken
      ? {
          token: {
            category: requirements.asset.toLowerCase(),
            amount: BigInt(requirements.amount),
            ...(extra.token?.nft === undefined ? {} : { nft: extra.token.nft }),
          },
        }
      : {}),
  };
}

export type BchNativeExtra = {
  /** Identifies a BCH value transfer. */
  assetTransferMethod: 'native';
  /** x402 flow supported by BCH exact payments. */
  paymentFlow: 'upfront';
};

export type BchCashTokenExtra = {
  /** Identifies a CashToken transfer. */
  assetTransferMethod: 'cashtoken';
  /** x402 flow supported by BCH exact payments. */
  paymentFlow: 'upfront';
  /** BCH value assigned to the merchant's token-bearing output. */
  value?: string;
  token?: {
    category: string;
    amount: string;
    nft?: CashTokenRequest['nft'];
  };
};

export type BchExtra = BchNativeExtra | BchCashTokenExtra;

/** x402 payload body carrying a signed BCH transaction. */
export type ExactBchPayload = {
  /** Base64-encoded, fully signed BCH transaction. */
  transaction: string;
};

/** x402 payment payload narrowed to the BCH exact transaction body. */
export type ExactBchPaymentPayload = PaymentPayload & {
  payload: ExactBchPayload;
};

/** x402 payment requirements narrowed to BCH network and transfer metadata. */
export type ExactBchRequirements = PaymentRequirements & {
  network: BchNetwork;
  asset: string;
  extra: BchExtra;
};

export type BchOutPoint = {
  /** Transaction ID in display-order hexadecimal. */
  txid: string;
  /** Output index consumed by an input. */
  vout: number;
};

export type BchSourceOutput = {
  /** Satoshis locked by the source output. */
  value: bigint;
  /** Locking bytecode from authoritative chain data. */
  scriptPubKey: Uint8Array;
  /** Optional CashToken state attached to the output. */
  token?: import('./crypto').CashToken;
};

export type BchUtxo = BchOutPoint & {
  /** Satoshis in this spendable output. */
  value: bigint;
  /** Locking bytecode associated with the outpoint. */
  scriptPubKey: Uint8Array;
  /** Optional token state associated with the outpoint. */
  token?: import('./crypto').CashToken;
  /** Confirmation height, when known and confirmed. */
  height?: number;
};

/** Normalized provider transaction state. */
export type BchTransactionStatus =
  | { kind: 'notFound' }
  | { kind: 'mempool' }
  | { kind: 'confirmed'; height: number }
  | { kind: 'unknown' };

/** Normalized provider outpoint spend state. */
export type BchOutpointStatus = 'unspent' | 'spent' | 'unknown';

export interface BchProvider {
  /** Network served by this provider; must match the x402 request. */
  readonly network: BchNetwork;
  /** Retrieve the complete source output for an outpoint. */
  getSourceOutput(outpoint: BchOutPoint): Promise<BchSourceOutput>;
  /** Determine whether an outpoint is still spendable. */
  getOutpointStatus(outpoint: BchOutPoint, source: BchSourceOutput): Promise<BchOutpointStatus>;
  /** List spendable UTXOs for an address or script. */
  listUtxos(address: string): Promise<BchUtxo[]>;
  /** Broadcast raw transaction bytes and return the transaction ID. */
  broadcast(rawTransaction: Uint8Array): Promise<string>;
  /** Return mempool, confirmation, or not-found state for a transaction. */
  getTransactionStatus(txid: string): Promise<BchTransactionStatus>;
  /** Return the current chain tip height. */
  getTipHeight(): Promise<number>;
  /** Check whether the provider knows a double-spend proof for a transaction. */
  hasDoubleSpendProof(txid: string): Promise<boolean>;
}

export interface BchSigner {
  /** Return the compressed public key used for P2PKH inputs. */
  getPublicKey(): Uint8Array;
  /** Sign a BCH signing digest and return a DER signature without sighash byte. */
  signDigest(digest: Uint8Array): Promise<Uint8Array>;
  /** Return the signer’s CashAddr on the requested network. */
  getAddress(network: BchNetwork): string;
}

export interface BchFacilitatorConfig {
  /** Settlement acceptance policy; defaults to one confirmation. */
  settlementStrategy?: BchConfirmationStrategy;
  /** Shared replay-protection store for multi-process facilitators. */
  settlementStore?: import('./settlementStore').BchSettlementStore;
  /** Minimum fee rate accepted and used by the transaction builder. */
  feeRateSatPerByte?: bigint;
  /** Native BCH output dust threshold. */
  dustThreshold?: bigint;
  /** Token-bearing output dust threshold. */
  cashTokenDustThreshold?: bigint;
  /** Maximum serialized transaction size accepted. */
  maxTransactionSize?: number;
  /** Maximum input count accepted. */
  maxInputs?: number;
  /** Maximum output count accepted. */
  maxOutputs?: number;
}

/** Rules controlling when a facilitator considers a BCH transaction settled. */
export type BchConfirmationStrategy =
  | { kind: 'mempool' }
  | { kind: 'noDoubleSpendProof' }
  | { kind: 'confirmations'; count: number };

/** Price forms accepted by the BCH server scheme. */
export type BchPrice =
  | string
  | number
  | {
      amount: string;
      asset: string;
      extra?: Record<string, unknown>;
    };

/** Optional x402 resource context used for settlement replay binding. */
export type BchPaymentPayloadContext = {
  resource?: ResourceInfo;
};
