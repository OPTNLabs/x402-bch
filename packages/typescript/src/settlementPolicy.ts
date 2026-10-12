import type { BchConfirmationStrategy, BchSourceOutput, BchTransactionStatus } from './types';
import { assertProviderTransactionId, parseTransaction } from './crypto';

export type BchProviderObservation = 'missing' | 'match' | 'mismatch';
export type BchSettlementOutcome = 'accepted' | 'pending' | 'rejected';
export type BchSettlementClaim = 'none' | 'same' | 'different';
export type BchBroadcastAttempt = 'none' | 'accepted' | 'lost';
export type BchSettlementAction = 'broadcast' | 'retry' | 'retain' | 'skip' | 'reject' | 'conflict';

export interface BchSettlementIntegrationResult {
  state: BchSettlementOutcome;
  transactionId: string;
  nextAction: BchSettlementAction;
}

export interface BchProviderSettlementInput {
  candidateTxid: string;
  candidateValid: boolean;
  bindingMatches: boolean;
  existingClaim: BchSettlementClaim;
  strategy: BchConfirmationStrategy;
  status: BchTransactionStatus;
  tipHeight?: number;
  hasDoubleSpendProof?: boolean;
  broadcastAttempt: BchBroadcastAttempt;
  /** Raw bytes returned by the provider, or undefined when not observed. */
  rawTransaction?: Uint8Array;
}

export type BchProviderSourceOutputObservation = 'missing' | 'mismatch' | 'notFound' | 'match';

export interface BchProviderSourceOutputResult {
  observation: BchProviderSourceOutputObservation;
  sourceOutput?: BchSourceOutput;
}

/** Normalize provider bytes into chain evidence before settlement decisions. */
export function observeBchProviderTransaction(
  candidateTxid: string,
  rawTransaction?: Uint8Array,
): BchProviderObservation {
  if (rawTransaction === undefined) return 'missing';
  try {
    assertProviderTransactionId(candidateTxid, rawTransaction);
    return 'match';
  } catch {
    return 'mismatch';
  }
}

/**
 * Project one authoritative source output from provider-returned transaction
 * bytes. The provider txid must match before a vout can be trusted.
 */
export function getBchProviderSourceOutput(
  sourceTxid: string,
  vout: number,
  rawTransaction?: Uint8Array,
): BchProviderSourceOutputResult {
  const observation = observeBchProviderTransaction(sourceTxid, rawTransaction);
  if (observation === 'missing' || observation === 'mismatch') return { observation };
  if (!Number.isInteger(vout) || vout < 0) return { observation: 'notFound' };
  try {
    const output = parseTransaction(rawTransaction!).outputs[vout];
    if (output === undefined) return { observation: 'notFound' };
    return {
      observation: 'match',
      sourceOutput: {
        value: output.value,
        scriptPubKey: output.scriptPubKey,
        ...(output.token === undefined ? {} : { token: output.token }),
      },
    };
  } catch {
    return { observation: 'mismatch' };
  }
}

/**
 * Apply the wallet-agnostic BCH settlement rule to provider-observed state.
 *
 * This function is deliberately pure. Provider calls for tip height and
 * double-spend proofs belong to the facilitator adapter; once those facts are
 * available, every implementation must make this same decision.
 */
export function acceptsBchSettlement(
  strategy: BchConfirmationStrategy,
  status: BchTransactionStatus,
  tipHeight?: number,
  hasDoubleSpendProof = false,
): boolean {
  if (strategy.kind === 'mempool') {
    return status.kind === 'mempool' || status.kind === 'confirmed';
  }
  if (strategy.kind === 'noDoubleSpendProof') {
    return status.kind === 'confirmed' || (status.kind === 'mempool' && !hasDoubleSpendProof);
  }
  if (strategy.count < 1 || status.kind !== 'confirmed' || tipHeight === undefined) return false;
  if (
    !Number.isInteger(status.height) ||
    !Number.isInteger(tipHeight) ||
    tipHeight < status.height
  ) {
    return false;
  }
  return tipHeight - status.height + 1 >= strategy.count;
}

/**
 * Normalize provider observations and policy facts into a retry-safe outcome.
 * Missing provider bytes remain pending; mismatched bytes are rejected because
 * a locally computed txid is not chain evidence.
 */
export function resolveBchSettlementOutcome(
  candidateValid: boolean,
  providerObservation: BchProviderObservation,
  strategy: BchConfirmationStrategy,
  status: BchTransactionStatus,
  tipHeight?: number,
  hasDoubleSpendProof = false,
): BchSettlementOutcome {
  if (!candidateValid || providerObservation === 'mismatch' || status.kind === 'conflicted') {
    return 'rejected';
  }
  if (providerObservation === 'missing') return 'pending';
  return acceptsBchSettlement(strategy, status, tipHeight, hasDoubleSpendProof)
    ? 'accepted'
    : 'pending';
}

/**
 * Resolve a deterministic facilitator retry decision from provider facts and
 * replay-claim state. This models orchestration only; it does not broadcast or
 * persist anything and it never creates a replacement transaction.
 */
export function resolveBchSettlementIntegration(
  candidateTxid: string,
  candidateValid: boolean,
  bindingMatches: boolean,
  existingClaim: BchSettlementClaim,
  providerObservation: BchProviderObservation,
  strategy: BchConfirmationStrategy,
  status: BchTransactionStatus,
  tipHeight: number | undefined,
  hasDoubleSpendProof: boolean,
  broadcastAttempt: BchBroadcastAttempt,
): BchSettlementIntegrationResult {
  const transactionId = candidateValid ? candidateTxid : '';
  if (!candidateValid || !bindingMatches || providerObservation === 'mismatch') {
    return {
      state: 'rejected',
      transactionId,
      nextAction: 'reject',
    };
  }
  if (existingClaim === 'different') {
    return {
      state: 'rejected',
      transactionId,
      nextAction: 'conflict',
    };
  }
  const state = resolveBchSettlementOutcome(
    true,
    providerObservation,
    strategy,
    status,
    tipHeight,
    hasDoubleSpendProof,
  );
  if (state !== 'pending') {
    return {
      state,
      transactionId,
      nextAction: state === 'accepted' ? 'skip' : 'reject',
    };
  }
  if (
    providerObservation === 'missing' &&
    existingClaim === 'none' &&
    broadcastAttempt === 'none'
  ) {
    return { state, transactionId, nextAction: 'broadcast' };
  }
  if (providerObservation === 'missing' && broadcastAttempt === 'lost') {
    return { state, transactionId, nextAction: 'retry' };
  }
  return { state, transactionId, nextAction: 'retain' };
}

/**
 * Derive the provider observation from provider-returned bytes before applying
 * settlement policy. A local txid alone is never treated as chain evidence.
 */
export function resolveBchSettlementFromProvider(
  input: BchProviderSettlementInput,
): BchSettlementIntegrationResult {
  const providerObservation = observeBchProviderTransaction(
    input.candidateTxid,
    input.rawTransaction,
  );
  return resolveBchSettlementIntegration(
    input.candidateTxid,
    input.candidateValid,
    input.bindingMatches,
    input.existingClaim,
    providerObservation,
    input.strategy,
    input.status,
    input.tipHeight,
    input.hasDoubleSpendProof ?? false,
    input.broadcastAttempt,
  );
}
