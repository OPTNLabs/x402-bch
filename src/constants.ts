import type { BchNetwork } from './types';

/** x402 asset identifier for native BCH. */
export const BCH_ASSET = 'BCH';

/** BCH network prefixes used by CashAddr encoding and decoding. */
export const NETWORK_PREFIX: Record<BchNetwork, 'bitcoincash' | 'bchtest'> = {
  'bch:bitcoincash': 'bitcoincash',
  'bch:bchtest': 'bchtest',
};

/** BCH `SIGHASH_ALL | FORKID`, used by the exact payment signer. */
export const SIGHASH_ALL_FORKID = 0x41;

/** Maximum unsigned BCH value representable in a transaction output. */
export const MAX_U64 = 0xffffffffffffffffn;

/** Maximum fungible CashToken quantity accepted by BCH consensus. */
export const MAX_CASH_TOKEN_AMOUNT = 0x7fffffffffffffffn;

/** Standard dust threshold for a native BCH output. */
export const BCH_DUST_THRESHOLD = 546n;

/**
 * Flat standardness floor for a short token-bearing P2PKH output.
 * Omitted merchant values use the size-aware rule in `crypto.ts`, which is
 * at least 1,000 satoshis and can be higher for a long NFT commitment.
 */
export const CASH_TOKEN_DUST_THRESHOLD = 687n;

/** SLIP-0044 coin type used by BCH Chipnet wallets. */
export const CHIPNET_BIP44_COIN_TYPE = 1;

/** SLIP-0044 coin type used by BCH mainnet wallets. */
export const BCH_MAINNET_BIP44_COIN_TYPE = 145;
