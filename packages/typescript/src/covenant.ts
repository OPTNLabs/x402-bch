import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from './crypto';
import type { BchNetwork } from './types';

export type CovenantTokenState = {
  category: string;
  amount: string;
  nft: { capability: 'none' | 'mutable' | 'minting'; commitment: string } | null;
} | null;

export type CovenantProfile = {
  id: string;
  family: string;
  profileVersion: number;
  network: BchNetwork;
  constructorParameters: Record<string, string>;
  successorPolicy: {
    lockingBytecode: string;
    maxFee: string;
    outputIndex: number;
    stateTransition: 'epoch-plus-one';
    token: 'preserve';
    value: 'preserve-minus-fee';
  };
  descriptorHash: string;
  lockingBytecodeHash: string;
  successorPolicyHash: string;
};

export type CovenantState = {
  lockingBytecode: string;
  value: string;
  epoch: string;
  requestHash: string;
  token: CovenantTokenState;
};

export type CovenantTransition = {
  requestHash: string;
  successorOutputIndex: number;
  fee: string;
  source: CovenantState;
  successor: CovenantState;
};

export type CovenantErrorCode =
  | 'profile-identity-mismatch'
  | 'locking-bytecode-mismatch'
  | 'successor-output-index-mismatch'
  | 'request-hash-mismatch'
  | 'state-transition-invalid'
  | 'fee-exceeds-limit'
  | 'token-state-mismatch';

export type CovenantValidation =
  | { accepted: true }
  | { accepted: false; errorCode: CovenantErrorCode };

/** Validate a registered profile and one deterministic successor transition. */
export function validateCovenantTransition(
  profile: CovenantProfile,
  transition: CovenantTransition,
): CovenantValidation {
  if (!profileHashesMatch(profile))
    return { accepted: false, errorCode: 'profile-identity-mismatch' };
  if (
    transition.source.lockingBytecode !== profile.successorPolicy.lockingBytecode ||
    transition.successor.lockingBytecode !== profile.successorPolicy.lockingBytecode
  ) {
    return { accepted: false, errorCode: 'locking-bytecode-mismatch' };
  }
  if (transition.successorOutputIndex !== profile.successorPolicy.outputIndex) {
    return { accepted: false, errorCode: 'successor-output-index-mismatch' };
  }
  if (
    transition.requestHash !== transition.source.requestHash ||
    transition.requestHash !== transition.successor.requestHash
  ) {
    return { accepted: false, errorCode: 'request-hash-mismatch' };
  }
  if (profile.successorPolicy.stateTransition === 'epoch-plus-one') {
    if (BigInt(transition.successor.epoch) !== BigInt(transition.source.epoch) + 1n) {
      return { accepted: false, errorCode: 'state-transition-invalid' };
    }
  }
  const fee = BigInt(transition.fee);
  if (fee > BigInt(profile.successorPolicy.maxFee)) {
    return { accepted: false, errorCode: 'fee-exceeds-limit' };
  }
  if (profile.successorPolicy.value === 'preserve-minus-fee') {
    if (BigInt(transition.source.value) - BigInt(transition.successor.value) !== fee) {
      return { accepted: false, errorCode: 'state-transition-invalid' };
    }
  }
  if (
    profile.successorPolicy.token === 'preserve' &&
    canonicalJson(transition.source.token) !== canonicalJson(transition.successor.token)
  ) {
    return { accepted: false, errorCode: 'token-state-mismatch' };
  }
  return { accepted: true };
}

/** Verify descriptor, locking-bytecode, and successor-policy identity. */
export function profileHashesMatch(profile: CovenantProfile): boolean {
  const descriptor = {
    id: profile.id,
    family: profile.family,
    profileVersion: profile.profileVersion,
    network: profile.network,
    constructorParameters: profile.constructorParameters,
    successorPolicy: profile.successorPolicy,
  };
  return (
    sha256Hex(canonicalJson(descriptor)) === profile.descriptorHash &&
    sha256Hex(hexToBytes(profile.successorPolicy.lockingBytecode)) ===
      profile.lockingBytecodeHash &&
    sha256Hex(canonicalJson(profile.successorPolicy)) === profile.successorPolicyHash
  );
}

function sha256Hex(value: string | Uint8Array): string {
  return bytesToHex(sha256(typeof value === 'string' ? new TextEncoder().encode(value) : value));
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => `${JSON.stringify(key)}:${canonicalJson(entry)}`)
      .join(',')}}`;
  }
  return JSON.stringify(value) ?? 'null';
}
