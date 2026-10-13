export const DIAGNOSTIC_REDACTED = '[redacted]';

export type BchDiagnostic = {
  stage: string;
  code: string;
  message: string;
  context: Record<string, string | number | boolean | null>;
};

const sensitiveKey =
  /^(mnemonic|privateKey|seed|secret|authorization|transaction|rawTransaction|signedTransaction)$/i;

/** Create a stable, log-safe diagnostic without exposing payment or key material. */
export function createBchDiagnostic(
  stage: string,
  code: string,
  message: string,
  context: Record<string, unknown> = {},
): BchDiagnostic {
  const safeContext: Record<string, string | number | boolean | null> = {};
  for (const [key, value] of Object.entries(context)) {
    if (sensitiveKey.test(key)) safeContext[key] = DIAGNOSTIC_REDACTED;
    else if (
      value === null ||
      typeof value === 'string' ||
      typeof value === 'number' ||
      typeof value === 'boolean'
    )
      safeContext[key] = value;
  }
  return { stage, code, message, context: safeContext };
}
