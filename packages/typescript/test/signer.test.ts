import { describe, expect, it } from 'vitest';
import {
  BCH_MAINNET_BIP44_COIN_TYPE,
  CHIPNET_BIP44_COIN_TYPE,
  createSecp256k1BchSignerFromMnemonic,
  deriveBchWalletAddress,
} from '../src/signer';

const MNEMONIC = 'legal winner thank year wave sausage worth useful legal winner thank yellow';

describe('BCH signer and HD derivation', () => {
  it('derives deterministic Chipnet and mainnet addresses without exposing keys', () => {
    const signer = createSecp256k1BchSignerFromMnemonic(MNEMONIC, {
      coinType: CHIPNET_BIP44_COIN_TYPE,
    });
    const chipnet = signer.getAddress('bch:bchtest');
    const mainnet = createSecp256k1BchSignerFromMnemonic(MNEMONIC, {
      coinType: BCH_MAINNET_BIP44_COIN_TYPE,
    }).getAddress('bch:bitcoincash');

    expect(chipnet).toMatch(/^bchtest:/);
    expect(mainnet).toMatch(/^bitcoincash:/);
    expect(signer.getPublicKey()).toHaveLength(33);
    expect('privateKey' in signer).toBe(false);
  });

  it('reports the BIP44 path for receive and change addresses', () => {
    expect(deriveBchWalletAddress(MNEMONIC, 'bch:bchtest', 0, 2)).toMatchObject({
      path: "m/44'/1'/0'/0/2",
      change: 0,
      index: 2,
    });
    expect(
      deriveBchWalletAddress(MNEMONIC, 'bch:bitcoincash', 1, 3, {
        accountIndex: 1,
      }),
    ).toMatchObject({
      path: "m/44'/145'/1'/1/3",
      change: 1,
      index: 3,
    });
  });

  it('rejects invalid mnemonics and derivation indexes', () => {
    expect(() => createSecp256k1BchSignerFromMnemonic('not a mnemonic')).toThrow(
      'Invalid BIP39 mnemonic',
    );
    expect(() => deriveBchWalletAddress(MNEMONIC, 'bch:bchtest', 0, -1)).toThrow(
      'index must be an integer',
    );
  });
});
