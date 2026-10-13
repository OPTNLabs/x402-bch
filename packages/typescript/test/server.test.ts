import { describe, expect, it } from 'vitest';
import { ExactBchServerScheme } from '../src/exact/server';
import fixture from '../spec/conformance/v1/server-requirements.json';

describe('server requirement construction fixture', () => {
  it.each(fixture.cases)('$id', async (testCase) => {
    const input = testCase.input as {
      kind: 'native' | 'cashtoken';
      network: 'bch:bitcoincash' | 'bch:bchtest';
      payTo: string;
      amount: string;
      category?: string;
      value?: string;
      requestHash?: string;
      nft?: { capability: 'none' | 'mutable' | 'minting'; commitment: string };
    };
    const price =
      input.kind === 'native'
        ? {
            amount: input.amount,
            asset: 'BCH',
            ...(input.requestHash ? { extra: { requestHash: input.requestHash } } : {}),
          }
        : {
            amount: input.amount,
            asset: input.category as string,
            extra: {
              value: input.value,
              token: {
                category: input.category,
                amount: input.amount,
                ...(input.nft ? { nft: input.nft } : {}),
              },
              ...(input.requestHash ? { requestHash: input.requestHash } : {}),
            },
          };
    const actual = await new ExactBchServerScheme().parsePrice(price, input.network);
    expect({
      x402Version: 2,
      scheme: 'exact',
      network: input.network,
      amount: actual.amount,
      asset: actual.asset,
      payTo: input.payTo,
      maxTimeoutSeconds: 300,
      extra: actual.extra,
    }).toEqual(testCase.expected);
  });
});
