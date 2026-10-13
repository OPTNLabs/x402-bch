import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  validateCovenantTransition,
  type CovenantProfile,
  type CovenantTransition,
} from '../src/covenant';

const fixture = JSON.parse(
  readFileSync(resolve(process.cwd(), 'spec/conformance/v1/covenant-profiles.json'), 'utf8'),
) as { profile: CovenantProfile; cases: Array<Record<string, unknown>> };

describe('registered covenant profiles', () => {
  for (const testCase of fixture.cases) {
    it(testCase.id as string, () => {
      const result = validateCovenantTransition(
        fixture.profile,
        testCase as unknown as CovenantTransition,
      );
      if (testCase.expected === 'accept') {
        expect(result).toEqual({ accepted: true });
      } else {
        expect(result).toEqual({ accepted: false, errorCode: testCase.errorCode });
      }
    });
  }
});
