import { toBchTransactionRequest, type ExactBchRequirements } from '../src/index.js';

const TOKEN_CATEGORY = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const merchant = 'bchtest:qqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zye3kwllue';

const base = {
  scheme: 'exact',
  network: 'bch:bchtest' as const,
  payTo: merchant,
  maxTimeoutSeconds: 60,
};

export const nativeRequirements: ExactBchRequirements = {
  ...base,
  asset: 'BCH',
  amount: '1000',
  extra: { assetTransferMethod: 'native', paymentFlow: 'upfront' },
};

export const fungibleTokenRequirements: ExactBchRequirements = {
  ...base,
  asset: TOKEN_CATEGORY,
  amount: '25',
  extra: {
    assetTransferMethod: 'cashtoken',
    paymentFlow: 'upfront',
    value: '687',
    token: { category: TOKEN_CATEGORY, amount: '25' },
  },
};

export const nftRequirements: ExactBchRequirements = {
  ...base,
  asset: TOKEN_CATEGORY,
  amount: '0',
  extra: {
    assetTransferMethod: 'cashtoken',
    paymentFlow: 'upfront',
    value: '687',
    token: {
      category: TOKEN_CATEGORY,
      amount: '0',
      nft: { capability: 'none', commitment: 'deadbeef' },
    },
  },
};

export const walletRequests = [
  toBchTransactionRequest(nativeRequirements),
  toBchTransactionRequest(fungibleTokenRequirements),
  toBchTransactionRequest(nftRequirements),
];
