import { describe, expect, it } from 'vitest';
import fixture from '../spec/conformance/v1/settlement-integration.json';
import providerFixture from '../spec/conformance/v1/provider-observation.json';
import settlementProviderFixture from '../spec/conformance/v1/settlement-provider.json';
import { hexToBytes } from '../src/crypto';
import {
  observeBchProviderTransaction,
  resolveBchSettlementFromProvider,
  resolveBchSettlementIntegration,
} from '../src/settlementPolicy';

describe('deterministic settlement integration fixture', () => {
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
        resolveBchSettlementIntegration(
          testCase.candidateTxid,
          testCase.candidateValid,
          testCase.bindingMatches,
          testCase.existingClaim,
          testCase.providerObservation,
          strategy,
          status,
          testCase.tipHeight,
          testCase.doubleSpendProof ?? false,
          testCase.broadcastAttempt,
        ),
      ).toEqual({
        state: testCase.expectedState,
        transactionId: testCase.expectedTransactionId,
        nextAction: testCase.expectedAction,
      });
    });
  }
});

describe('provider-fact settlement fixture', () => {
  const providerCases = new Map(providerFixture.cases.map((testCase) => [testCase.id, testCase]));
  for (const testCase of settlementProviderFixture.cases) {
    it(testCase.id, () => {
      const source = providerCases.get(testCase.providerCase);
      expect(source).toBeDefined();
      const strategy =
        testCase.strategy === 'confirmations'
          ? { kind: 'confirmations' as const, count: testCase.confirmations }
          : { kind: testCase.strategy as 'mempool' | 'noDoubleSpendProof' };
      const status =
        testCase.status === 'confirmed'
          ? { kind: 'confirmed' as const, height: testCase.height }
          : { kind: testCase.status as 'notFound' | 'mempool' | 'unknown' | 'conflicted' };
      const rawTransaction =
        source?.rawTransaction === null ? undefined : hexToBytes(source?.rawTransaction ?? '');
      const result = resolveBchSettlementFromProvider({
        candidateTxid: testCase.candidateTxid,
        candidateValid: testCase.candidateValid,
        bindingMatches: testCase.bindingMatches,
        existingClaim: testCase.existingClaim,
        strategy,
        status,
        tipHeight: testCase.tipHeight,
        broadcastAttempt: testCase.broadcastAttempt,
        rawTransaction,
      });
      expect(result).toEqual({
        state: testCase.expectedState,
        transactionId: testCase.expectedTransactionId,
        nextAction: testCase.expectedAction,
      });
      expect(observeBchProviderTransaction(testCase.candidateTxid, rawTransaction)).toBe(
        testCase.expectedObservation,
      );
    });
  }
});
