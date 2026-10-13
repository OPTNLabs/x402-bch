import { describe, expect, it } from 'vitest';
import { createBchDiagnostic, DIAGNOSTIC_REDACTED } from '../src/diagnostics';

describe('structured diagnostics', () => {
  it('keeps stable fields and redacts sensitive context', () => {
    expect(
      createBchDiagnostic('provider', 'transaction_identity_mismatch', 'provider mismatch', {
        txid: 'a'.repeat(64),
        rawTransaction: 'deadbeef',
        mnemonic: 'secret',
        vout: 0,
      }),
    ).toEqual({
      stage: 'provider',
      code: 'transaction_identity_mismatch',
      message: 'provider mismatch',
      context: {
        txid: 'a'.repeat(64),
        rawTransaction: DIAGNOSTIC_REDACTED,
        mnemonic: DIAGNOSTIC_REDACTED,
        vout: 0,
      },
    });
  });
});
