import { describe, expect, it } from 'vitest';
import { toBchTransactionRequest, toBchTransactionNetwork } from '../src/types';

const merchant = 'bchtest:qqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zye3kwllue';

describe('BCH x402 request mapping', () => {
  it('maps network identifiers and native BCH value', () => {
    expect(toBchTransactionNetwork('bch:bchtest')).toBe('chipnet');
    expect(toBchTransactionNetwork('bch:bitcoincash')).toBe('mainnet');
    expect(
      toBchTransactionRequest({
        network: 'bch:bchtest',
        payTo: merchant,
        amount: '1000',
        asset: 'BCH',
        extra: { assetTransferMethod: 'native', paymentFlow: 'upfront' },
      }),
    ).toEqual({ network: 'chipnet', recipient: { address: merchant }, value: 1000n });
  });

  it('maps fungible and NFT CashToken quantities separately from BCH value', () => {
    const category = 'AB'.repeat(32);
    const fungible = toBchTransactionRequest({
      network: 'bch:bchtest',
      payTo: merchant,
      amount: '25',
      asset: category,
      extra: {
        assetTransferMethod: 'cashtoken',
        paymentFlow: 'upfront',
        value: '687',
        token: { category, amount: '25' },
      },
    });
    expect(fungible).toEqual({
      network: 'chipnet',
      recipient: { address: merchant },
      value: 687n,
      token: { category: category.toLowerCase(), amount: 25n },
    });

    const nft = toBchTransactionRequest({
      network: 'bch:bchtest',
      payTo: merchant,
      amount: '0',
      asset: category,
      extra: {
        assetTransferMethod: 'cashtoken',
        paymentFlow: 'upfront',
        value: '687',
        token: { category, amount: '0', nft: { capability: 'mutable', commitment: '' } },
      },
    });
    expect(nft.token).toEqual({
      category: category.toLowerCase(),
      amount: 0n,
      nft: { capability: 'mutable', commitment: '' },
    });
  });
});
