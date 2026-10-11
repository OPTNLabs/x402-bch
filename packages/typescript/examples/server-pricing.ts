import { ExactBchServerScheme } from '../src/exact/server/index.js';

const TOKEN_CATEGORY = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

export const nativePrice = { amount: '1000', asset: 'BCH' } as const;

export const fungibleTokenPrice = {
  amount: '25',
  asset: TOKEN_CATEGORY,
  extra: { value: '1000' },
} as const;

export function createServerScheme() {
  const scheme = new ExactBchServerScheme();
  scheme.registerMoneyParser(async (price) => {
    if (price === '0.00001 BCH') return nativePrice;
    return null;
  });
  return scheme;
}
