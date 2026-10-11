import {
  decodeBip39Mnemonic,
  deriveHdPath,
  deriveHdPrivateNodeFromBip39Mnemonic,
  secp256k1,
} from '@bitauth/libauth';
import { encodeCashAddr, hash160 } from './crypto';
import { BCH_MAINNET_BIP44_COIN_TYPE, CHIPNET_BIP44_COIN_TYPE } from './constants';
import type {
  BchHdDiscoveryOptions,
  BchNetwork,
  BchProvider,
  BchSigner,
  BchWalletAddress,
} from './types';

/** Create the default compressed-key BCH signer around one private key. */
function createSecp256k1BchSigner(privateKey: Uint8Array): BchSigner {
  const publicKey = secp256k1.derivePublicKeyCompressed(privateKey);
  if (typeof publicKey === 'string') throw new Error(publicKey);
  return {
    getPublicKey: () => publicKey.slice(),
    signDigest: (digest) => {
      const signature = secp256k1.signMessageHashDER(privateKey, digest);
      if (typeof signature === 'string') throw new Error(signature);
      return Promise.resolve(signature);
    },
    getAddress: (network) => encodeCashAddr(hash160(publicKey), network),
  };
}

export { BCH_MAINNET_BIP44_COIN_TYPE, CHIPNET_BIP44_COIN_TYPE } from './constants';

/** Options for mnemonic-based BIP44 signer derivation. */
export type BchMnemonicSignerOptions = {
  /** BIP39 passphrase, if the wallet uses one. */
  passphrase?: string;
  /** BIP44 coin type; defaults to chipnet (1). */
  coinType?: number;
  accountIndex?: number;
  changeIndex?: number;
  addressIndex?: number;
};

const MAX_HARDENED_INDEX = 0x7fffffff;
const MAX_BIP32_INDEX = 0xffffffff;

function validateDerivationIndex(name: string, value: number, maximum: number): void {
  if (!Number.isInteger(value) || value < 0 || value > maximum) {
    throw new Error(`${name} must be an integer between 0 and ${maximum}`);
  }
}

/**
 * Create a BCH signer from a validated BIP39 mnemonic.
 *
 * The default path is BIP44 chipnet `m/44'/1'/0'/0/0`. Pass coin type 145
 * when deriving a mainnet BCH account.
 */
export function createSecp256k1BchSignerFromMnemonic(
  mnemonic: string,
  options: BchMnemonicSignerOptions = {},
): BchSigner {
  const decoded = decodeBip39Mnemonic(mnemonic);
  if (typeof decoded === 'string') {
    throw new Error(`Invalid BIP39 mnemonic: ${decoded}`);
  }

  const coinType = options.coinType ?? CHIPNET_BIP44_COIN_TYPE;
  const accountIndex = options.accountIndex ?? 0;
  const changeIndex = options.changeIndex ?? 0;
  const addressIndex = options.addressIndex ?? 0;
  validateDerivationIndex('coinType', coinType, MAX_HARDENED_INDEX);
  validateDerivationIndex('accountIndex', accountIndex, MAX_HARDENED_INDEX);
  validateDerivationIndex('changeIndex', changeIndex, MAX_BIP32_INDEX);
  validateDerivationIndex('addressIndex', addressIndex, MAX_BIP32_INDEX);

  const root = deriveHdPrivateNodeFromBip39Mnemonic(mnemonic, {
    passphrase: options.passphrase,
  });
  const derived = deriveHdPath(
    root,
    `m/44'/${coinType}'/${accountIndex}'/${changeIndex}/${addressIndex}`,
  );
  return createSecp256k1BchSigner(derived.privateKey);
}

/**
 * Derive one BCH wallet address without exposing the derived key material.
 * This is intended for wallet adapters and discovery, not the x402 scheme API.
 *
 * @param mnemonic BIP39 mnemonic held by the wallet process.
 * @param network BCH network used to encode the resulting CashAddr.
 * @param change BIP44 branch (`0` receive, `1` change).
 * @param index Address index within the branch.
 * @returns Address and derivation metadata; private key material is discarded.
 */
export function deriveBchWalletAddress(
  mnemonic: string,
  network: BchNetwork,
  change: 0 | 1,
  index: number,
  options: Pick<BchMnemonicSignerOptions, 'passphrase' | 'coinType' | 'accountIndex'> = {},
): BchWalletAddress {
  const accountIndex = options.accountIndex ?? 0;
  const coinType =
    options.coinType ??
    (network === 'bch:bchtest' ? CHIPNET_BIP44_COIN_TYPE : BCH_MAINNET_BIP44_COIN_TYPE);
  validateDerivationIndex('index', index, MAX_BIP32_INDEX);
  const signer = createSecp256k1BchSignerFromMnemonic(mnemonic, {
    ...options,
    coinType,
    accountIndex,
    changeIndex: change,
    addressIndex: index,
  });
  return {
    address: signer.getAddress(network),
    path: `m/44'/${coinType}'/${accountIndex}'/${change}/${index}`,
    change,
    index,
  };
}

/**
 * Discover used and gap-limit-bounded BCH addresses on both BIP44 branches.
 * The provider is queried for each derived address; no wallet state is written.
 */
export async function discoverBchHdWalletAddresses(
  mnemonic: string,
  network: BchNetwork,
  provider: BchProvider,
  options: BchHdDiscoveryOptions = {},
): Promise<BchWalletAddress[]> {
  const gapLimit = options.gapLimit ?? 20;
  const maxAddresses = options.maxAddresses ?? 1000;
  if (!Number.isInteger(gapLimit) || gapLimit < 1) throw new Error('gapLimit must be positive');
  if (!Number.isInteger(maxAddresses) || maxAddresses < gapLimit) {
    throw new Error('maxAddresses must be at least gapLimit');
  }
  const discovered: BchWalletAddress[] = [];
  for (const change of [0, 1] as const) {
    let unused = 0;
    for (let index = 0; index < maxAddresses && unused < gapLimit; index += 1) {
      const address = deriveBchWalletAddress(mnemonic, network, change, index, options);
      const utxos = await provider.listUtxos(address.address);
      discovered.push({ ...address, utxos });
      if (utxos.length === 0) unused += 1;
      else unused = 0;
    }
  }
  return discovered;
}
