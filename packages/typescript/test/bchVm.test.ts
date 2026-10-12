import { describe, expect, it } from 'vitest';
import fixture from '../spec/conformance/v1/bch-vm.json';
import { evaluateBchVm } from '../src/bchVm';
import { hexToBytes } from '../src/crypto';

describe('bounded BCH VM fixture', () => {
  for (const testCase of fixture.cases) {
    it(testCase.id, () => {
      const result = evaluateBchVm(
        hexToBytes(testCase.unlockingScript),
        hexToBytes(testCase.lockingScript),
      );
      expect(result.accepted).toBe(testCase.expectedAccepted);
      expect(result.errorCode ?? null).toBe(testCase.expectedError);
    });
  }
});
