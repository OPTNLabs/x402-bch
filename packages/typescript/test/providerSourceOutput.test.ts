import { describe, expect, it } from 'vitest';
import providerFixture from '../spec/conformance/v1/provider-observation.json';
import fixture from '../spec/conformance/v1/provider-source-output.json';
import { bytesToHex, hexToBytes } from '../src/crypto';
import { getBchProviderSourceOutput } from '../src/settlementPolicy';

describe('provider source-output fixture', () => {
  const providerCases = new Map(providerFixture.cases.map((testCase) => [testCase.id, testCase]));
  for (const testCase of fixture.cases) {
    it(testCase.id, () => {
      const source = providerCases.get(testCase.providerCase);
      expect(source).toBeDefined();
      const rawTransaction =
        source?.rawTransaction === null ? undefined : hexToBytes(source?.rawTransaction ?? '');
      const result = getBchProviderSourceOutput(testCase.sourceTxid, testCase.vout, rawTransaction);
      expect(result.observation).toBe(testCase.expectedObservation);
      if (testCase.expectedValue === null || testCase.expectedScriptPubKey === null) {
        expect(result.sourceOutput).toBeUndefined();
      } else {
        expect(result.sourceOutput?.value.toString()).toBe(testCase.expectedValue);
        expect(bytesToHex(result.sourceOutput?.scriptPubKey ?? new Uint8Array())).toBe(
          testCase.expectedScriptPubKey,
        );
      }
    });
  }
});
