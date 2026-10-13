import { describe, expect, it } from 'vitest';
import fixture from '../spec/conformance/v1/sdk-lifecycle.json';
import { base64ToBytes, parseTransaction } from '../src/crypto';
import { toBchTransactionRequest, type ExactBchRequirements } from '../src/types';

describe('cross-language SDK lifecycle contract', () => {
  it('normalizes the shared wallet request and accepts the canonical transaction', () => {
    const requirements = fixture.requirements as ExactBchRequirements;
    const request = toBchTransactionRequest(requirements);
    expect(request).toMatchObject({
      network: fixture.walletRequest.network,
      recipient: { address: fixture.walletRequest.payTo },
      value: BigInt(fixture.walletRequest.value),
    });
    expect(request.value).toBe(BigInt(fixture.walletRequest.value));
    expect(parseTransaction(base64ToBytes(fixture.transaction.base64))).toBeDefined();
    expect(fixture.settlement.accepted).toBe(true);
    expect(fixture.settlement.replayAccepted).toBe(false);
  });
});
