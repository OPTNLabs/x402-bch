import { describe, expect, it } from 'vitest';
import fixture from '../spec/conformance/v1/settlement-policy.json';
import observationFixture from '../spec/conformance/v1/provider-observation.json';
import { assertProviderTransactionId } from '../src/crypto';
import { acceptsBchSettlement, resolveBchSettlementOutcome } from '../src/settlementPolicy';
import outcomeFixture from '../spec/conformance/v1/settlement-outcome.json';

describe('shared settlement policy fixture', () => {
  for (const testCase of fixture.cases) {
    it(testCase.id, () => {
      const strategy =
        testCase.strategy === 'confirmations'
          ? { kind: 'confirmations' as const, count: testCase.confirmations }
          : { kind: testCase.strategy as 'mempool' | 'noDoubleSpendProof' };
      const status =
        testCase.status === 'confirmed'
          ? { kind: 'confirmed' as const, height: testCase.height }
          : { kind: testCase.status as 'notFound' | 'mempool' | 'unknown' | 'conflicted' };
      expect(
        acceptsBchSettlement(strategy, status, testCase.tipHeight, testCase.doubleSpendProof),
      ).toBe(testCase.expectedAccepted);
    });
  }
});

describe('provider observation identity fixture', () => {
  for (const testCase of observationFixture.cases) {
    it(testCase.id, () => {
      const verify = () =>
        testCase.rawTransaction === null
          ? assertProviderTransactionId(testCase.candidateTxid, new Uint8Array())
          : assertProviderTransactionId(
              testCase.candidateTxid,
              Uint8Array.from(Buffer.from(testCase.rawTransaction, 'hex')),
            );
      if (testCase.expected) expect(verify).not.toThrow();
      else expect(verify).toThrow();
    });
  }
});

describe('settlement outcome fixture', () => {
  for (const testCase of outcomeFixture.cases) {
    it(testCase.id, () => {
      const strategy =
        testCase.strategy === 'confirmations'
          ? { kind: 'confirmations' as const, count: testCase.confirmations }
          : { kind: testCase.strategy as 'mempool' | 'noDoubleSpendProof' };
      const status =
        testCase.status === 'confirmed'
          ? { kind: 'confirmed' as const, height: testCase.height }
          : { kind: testCase.status as 'notFound' | 'mempool' | 'unknown' | 'conflicted' };
      expect(
        resolveBchSettlementOutcome(
          testCase.candidateValid,
          testCase.providerObservation,
          strategy,
          status,
          testCase.tipHeight,
          testCase.doubleSpendProof,
        ),
      ).toBe(testCase.expectedOutcome);
    });
  }
});
