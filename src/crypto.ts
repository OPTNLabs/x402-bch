import {
  decodeCashAddress as decodeLibauthCashAddress,
  decodeBase58Address,
  cashAddressToLockingBytecode,
  decodeTransactionBCH,
  decodeAuthenticationInstructions,
  authenticationInstructionsAreMalformed,
  authenticationInstructionsArePushInstructions,
  decodeBitcoinSignature,
  encodeDataPush,
  encodeCashAddress as encodeLibauthCashAddress,
  encodeLockingBytecodeP2pkh,
  encodeLockingBytecodeP2sh20,
  encodeLockingBytecodeP2sh32,
  encodeTransactionBCH,
  generateSigningSerializationBCH,
  hash160 as libauthHash160,
  hash256 as libauthHash256,
  binToBase64,
  base64ToBin,
  binToHex,
  hexToBin,
  hashTransaction,
  isPayToPublicKeyHash,
  isPayToScriptHash20,
  isPayToScriptHash32,
  binsAreEqual,
  isHex,
  createVirtualMachineBch2026,
  getDustThreshold,
  verifyTransactionTokens,
} from '@bitauth/libauth';
import { ConsensusBch2026 } from '@bitauth/libauth/build/lib/vm/instruction-sets/bch/2026/bch-2026-consensus.js';
import type { BchNetwork, BchOutPoint, BchSourceOutput, TokenCapability } from './types';
import {
  BCH_ASSET,
  BCH_DUST_THRESHOLD,
  CASH_TOKEN_DUST_THRESHOLD,
  MAX_CASH_TOKEN_AMOUNT,
  MAX_U64,
  NETWORK_PREFIX,
  SIGHASH_ALL_FORKID,
} from './constants';
export { BCH_ASSET, SIGHASH_ALL_FORKID } from './constants';

/** Display-order hexadecimal BCH transaction identifier. */
export type TxId = string;

/** CashToken state attached to one BCH transaction output. */
export type CashToken = {
  /** 32-byte token category in canonical hexadecimal form. */
  category: string;
  /** Fungible token amount; zero is valid when an NFT is present. */
  amount: bigint;
  /** Optional NFT capability and commitment. */
  nft?: {
    capability: TokenCapability;
    commitment: Uint8Array;
  };
};

/** Exact merchant output required by an x402 payment. */
export type BchPaymentTarget =
  | { kind: 'native'; amount: bigint; merchantValue: bigint }
  | {
      kind: 'cashtoken';
      category: string;
      amount: bigint;
      merchantValue: bigint;
      nft?: CashToken['nft'];
    };

/** Parsed BCH transaction input. */
export type BchTxInput = {
  outpoint: BchOutPoint;
  scriptSig: Uint8Array;
  sequence: number;
};

/** Parsed BCH transaction output, including optional CashToken state. */
export type BchTxOutput = {
  value: bigint;
  scriptPubKey: Uint8Array;
  token?: CashToken;
};

/** Minimal Libauth-compatible BCH transaction model used by this package. */
export type BchTransaction = {
  version: number;
  inputs: BchTxInput[];
  outputs: BchTxOutput[];
  lockTime: number;
};

/** Consensus/standardness and resource limits applied by builders and validators. */
export type BchPolicy = {
  feeRateSatPerByte: bigint;
  dustThreshold: bigint;
  /** Conservative standard minimum for a token-bearing P2PKH output. */
  cashTokenDustThreshold: bigint;
  maxTransactionSize: number;
  maxInputs: number;
  maxOutputs: number;
};

/** Floor for an omitted CashToken `value`. The value actually used is this floor, the policy dust threshold, or the output's standard relay dust, whichever is greatest. */
export const CASHTOKEN_OUTPUT_DUST = 1000n;

/** Current BCH consensus maximum, from the resolved Libauth 2026 VM settings. */
export const MAX_TOKEN_COMMITMENT_LENGTH = ConsensusBch2026.maximumTokenCommitmentLength;

/** Conservative default policy for exact BCH payments. */
export const DEFAULT_BCH_POLICY: BchPolicy = {
  feeRateSatPerByte: 1n,
  dustThreshold: BCH_DUST_THRESHOLD,
  cashTokenDustThreshold: CASH_TOKEN_DUST_THRESHOLD,
  maxTransactionSize: 100_000,
  maxInputs: 100,
  maxOutputs: 16,
};

/**
 * Parse x402 wire requirements into a validated merchant output target.
 *
 * Native BCH uses `amount` and assigns the same value to the merchant output.
 * CashToken payments use `amount` for token quantity and `extra.value` for
 * the BCH satoshis carried by the merchant token output. An omitted `value`
 * uses the size-aware dust floor. An explicit `value` is preserved.
 *
 * @throws If the asset, amount, category, NFT state, or BCH output value is
 * invalid or outside BCH/ CashToken limits.
 */
export function createBchPaymentTarget(
  asset: string,
  amount: string,
  extra: {
    assetTransferMethod?: string;
    value?: string;
    token?: {
      category?: string;
      amount?: string;
      nft?: { capability: TokenCapability; commitment: string };
    };
  },
  policy: BchPolicy = DEFAULT_BCH_POLICY,
  merchantScript?: Uint8Array,
): BchPaymentTarget {
  if (!/^(0|[1-9][0-9]*)$/.test(amount)) {
    throw new Error('BCH amount must be canonical unsigned units');
  }
  const parsedAmount = BigInt(amount);
  if (parsedAmount > MAX_U64) throw new Error('BCH amount exceeds u64');
  if (asset === BCH_ASSET) {
    if (extra.assetTransferMethod !== 'native') throw new Error('BCH requires native transfer');
    return {
      kind: 'native',
      amount: parsedAmount,
      merchantValue: parsedAmount,
    };
  }
  if (extra.assetTransferMethod !== 'cashtoken' || !isCashTokenCategory(asset)) {
    throw new Error('BCH asset must be BCH or a CashToken category');
  }
  const category = asset.toLowerCase();
  if (extra.token?.category !== undefined && extra.token.category.toLowerCase() !== category) {
    throw new Error('CashToken token category must match the asset');
  }
  const tokenAmount = extra.token?.amount ?? amount;
  if (tokenAmount !== amount) throw new Error('CashToken token amount must match amount');
  if (extra.token?.nft !== undefined) {
    if (!['none', 'mutable', 'minting'].includes(extra.token.nft.capability)) {
      throw new Error('CashToken NFT capability is invalid');
    }
    if (!/^(?:[0-9a-fA-F]{2})*$/.test(extra.token.nft.commitment)) {
      throw new Error('CashToken NFT commitment must be even-length hex');
    }
    if (extra.token.nft.commitment.length / 2 > MAX_TOKEN_COMMITMENT_LENGTH) {
      throw new Error('CashToken commitment is too large');
    }
  }
  if (
    (parsedAmount === 0n && extra.token?.nft === undefined) ||
    parsedAmount > MAX_CASH_TOKEN_AMOUNT
  ) {
    throw new Error('CashToken amount is outside the BCH token range');
  }
  const nft =
    extra.token?.nft === undefined
      ? undefined
      : {
          capability: extra.token.nft.capability,
          commitment: hexToBytes(extra.token.nft.commitment),
        };
  const merchantValue =
    extra.value ??
    omittedTokenOutputValue(merchantScript, category, parsedAmount, nft, policy).toString();
  if (!/^(0|[1-9][0-9]*)$/.test(merchantValue)) {
    throw new Error('CashToken output value must be canonical satoshis');
  }
  const parsedMerchantValue = BigInt(merchantValue);
  if (parsedMerchantValue > MAX_U64) {
    throw new Error('CashToken output value exceeds u64');
  }
  return {
    kind: 'cashtoken',
    category,
    amount: parsedAmount,
    merchantValue: parsedMerchantValue,
    ...(nft === undefined ? {} : { nft }),
  };
}

/**
 * Satoshis to advertise when a CashToken price omits `value`.
 * Explicit quotes must not be passed here.
 */
export function omittedTokenOutputValue(
  lockingScript: Uint8Array | undefined,
  category: string,
  amount: bigint,
  nft: CashToken['nft'] | undefined,
  policy: BchPolicy,
): bigint {
  if (nft !== undefined && nft.commitment.length > MAX_TOKEN_COMMITMENT_LENGTH) {
    throw new Error('CashToken commitment is too large');
  }
  const token: CashToken = { category, amount, ...(nft === undefined ? {} : { nft }) };
  const standard =
    lockingScript !== undefined && isSupportedMerchantScript(lockingScript)
      ? dustMinimum(lockingScript, token, policy)
      : policy.dustThreshold;
  const floor =
    policy.dustThreshold > CASHTOKEN_OUTPUT_DUST ? policy.dustThreshold : CASHTOKEN_OUTPUT_DUST;
  return standard > floor ? standard : floor;
}

/** Encode bytes as lowercase hexadecimal. */
export function bytesToHex(bytes: Uint8Array): string {
  return binToHex(bytes);
}

/** Decode strict hexadecimal text into bytes. */
export function hexToBytes(value: string): Uint8Array {
  const result = hexToBin(value);
  if (typeof result === 'string') throw new Error(result);
  return result;
}

/** Encode bytes as base64 for the x402 transaction payload. */
export function bytesToBase64(bytes: Uint8Array): string {
  return binToBase64(bytes);
}

/** Decode a base64 x402 transaction payload. */
export function base64ToBytes(value: string): Uint8Array {
  const result = base64ToBin(value);
  if (typeof result === 'string') throw new Error(result);
  return result;
}

/** Compute RIPEMD160(SHA256(value)), used by BCH address scripts. */
export function hash160(value: Uint8Array): Uint8Array {
  return libauthHash160(value);
}

/** Compute BCH’s double-SHA256 hash. */
export function doubleSha256(value: Uint8Array): Uint8Array {
  return libauthHash256(value);
}

/** Build a standard P2PKH locking script from a 20-byte public-key hash. */
export function p2pkhScript(hash: Uint8Array): Uint8Array {
  if (hash.length !== 20) throw new Error('P2PKH hash must be 20 bytes');
  return encodeLockingBytecodeP2pkh(hash);
}

/** Build a standard P2SH20 locking script from a 20-byte script hash. */
export function p2sh20Script(hash: Uint8Array): Uint8Array {
  if (hash.length !== 20) throw new Error('P2SH20 hash must be 20 bytes');
  return encodeLockingBytecodeP2sh20(hash);
}

/** Build a BCH P2SH32 locking script from a 32-byte script hash. */
export function p2sh32Script(hash: Uint8Array): Uint8Array {
  if (hash.length !== 32) throw new Error('P2SH32 hash must be 32 bytes');
  return encodeLockingBytecodeP2sh32(hash);
}

/** Return whether bytecode is a standard P2PKH locking script. */
export function isP2pkhScript(script: Uint8Array): boolean {
  return isPayToPublicKeyHash(script);
}

/** Return whether bytecode is a standard P2SH20 locking script. */
export function isP2sh20Script(script: Uint8Array): boolean {
  return isPayToScriptHash20(script);
}

/** Return whether bytecode is a standard P2SH32 locking script. */
export function isP2sh32Script(script: Uint8Array): boolean {
  return isPayToScriptHash32(script);
}

/** Return whether a script is an accepted exact-payment merchant script. */
export function isSupportedMerchantScript(script: Uint8Array): boolean {
  return isP2pkhScript(script) || isP2sh20Script(script) || isP2sh32Script(script);
}

/** Return whether text is a 32-byte hexadecimal CashToken category. */
export function isCashTokenCategory(value: string): boolean {
  return value.length === 64 && isHex(value);
}

/** Decode a network-bound CashAddr into locking bytecode and token support. */
export function decodeCashAddrScript(
  value: string,
  network: BchNetwork,
): { scriptPubKey: Uint8Array; tokenSupport: boolean } {
  if (value !== value.toLowerCase()) throw new Error('CashAddr must be lowercase');
  const decoded = cashAddressToLockingBytecode(value);
  if (typeof decoded === 'string') throw new Error(decoded);
  if (decoded.prefix !== NETWORK_PREFIX[network]) throw new Error('CashAddr network mismatch');
  if (!isSupportedMerchantScript(decoded.bytecode)) throw new Error('unsupported CashAddr type');
  return { scriptPubKey: decoded.bytecode, tokenSupport: decoded.tokenSupport };
}

/**
 * Decode CashAddr or legacy Base58Check into network-bound locking bytecode.
 * Legacy addresses have no network prefix, so their version byte is checked
 * against the requested BCH network before producing locking bytecode.
 *
 * @param value CashAddr or legacy Base58Check address.
 * @param network Expected BCH network.
 * @returns Locking bytecode and whether the address encodes token support.
 * @throws If the address is malformed, belongs to another network, or uses an unsupported type.
 */
export function decodeBchAddressScript(
  value: string,
  network: BchNetwork,
): { scriptPubKey: Uint8Array; tokenSupport: boolean } {
  if (value.includes(':') || value === value.toLowerCase()) {
    try {
      return decodeCashAddrScript(value, network);
    } catch (cashAddrError) {
      if (value.includes(':')) throw cashAddrError;
    }
  }

  const decoded = decodeBase58Address(value);
  if (typeof decoded === 'string') throw new Error(decoded);
  const mainnetVersions = new Set([0, 5, 28, 40]);
  const testnetVersions = new Set([111, 196]);
  const validVersions = network === 'bch:bitcoincash' ? mainnetVersions : testnetVersions;
  if (!validVersions.has(decoded.version)) throw new Error('address network mismatch');
  if (decoded.version === 0 || decoded.version === 111 || decoded.version === 28) {
    return { scriptPubKey: p2pkhScript(decoded.payload), tokenSupport: false };
  }
  return { scriptPubKey: p2sh20Script(decoded.payload), tokenSupport: false };
}

/** Decode a P2PKH CashAddr and return its 20-byte hash payload. */
export function decodeCashAddr(value: string, network: BchNetwork): Uint8Array {
  if (value !== value.toLowerCase()) throw new Error('CashAddr must be lowercase');
  const decoded = decodeLibauthCashAddress(value);
  if (typeof decoded === 'string') throw new Error(decoded);
  if (decoded.prefix !== NETWORK_PREFIX[network]) throw new Error('CashAddr network mismatch');
  if (decoded.type !== 'p2pkh' && decoded.type !== 'p2pkhWithTokens') {
    throw new Error('CashAddr type mismatch');
  }
  return decoded.payload;
}

/** Encode a 20-byte P2PKH hash as a BCH CashAddr. */
export function encodeCashAddr(hash: Uint8Array, network: BchNetwork): string {
  if (hash.length !== 20) throw new Error('P2PKH hash must be 20 bytes');
  const encoded = encodeLibauthCashAddress({
    payload: hash,
    prefix: NETWORK_PREFIX[network],
    type: 'p2pkh',
  });
  if (typeof encoded === 'string') throw new Error(encoded);
  return encoded.address;
}

/** Encode a P2PKH, P2SH20, or P2SH32 script as a BCH CashAddr. */
export function encodeCashAddrScript(
  script: Uint8Array,
  network: BchNetwork,
  tokenSupport = false,
): string {
  const type = isP2pkhScript(script)
    ? tokenSupport
      ? 'p2pkhWithTokens'
      : 'p2pkh'
    : isP2sh20Script(script) || isP2sh32Script(script)
      ? tokenSupport
        ? 'p2shWithTokens'
        : 'p2sh'
      : undefined;
  if (type === undefined) throw new Error('unsupported script for CashAddr encoding');
  const payload = isP2pkhScript(script) ? script.slice(3, 23) : script.slice(2, -1);
  const encoded = encodeLibauthCashAddress({
    payload,
    prefix: NETWORK_PREFIX[network],
    type,
  });
  if (typeof encoded === 'string') throw new Error(encoded);
  return encoded.address;
}

function toLibauthTransaction(transaction: BchTransaction) {
  return {
    version: transaction.version,
    inputs: transaction.inputs.map((input) => ({
      outpointIndex: input.outpoint.vout,
      outpointTransactionHash: hexToBytes(input.outpoint.txid),
      sequenceNumber: input.sequence,
      unlockingBytecode: input.scriptSig,
    })),
    outputs: transaction.outputs.map((output) => ({
      valueSatoshis: output.value,
      lockingBytecode: output.scriptPubKey,
      ...(output.token === undefined ? {} : { token: toLibauthToken(output.token) }),
    })),
    locktime: transaction.lockTime,
  };
}

function toLibauthSourceOutput(source: BchSourceOutput) {
  return {
    valueSatoshis: source.value,
    lockingBytecode: source.scriptPubKey,
    ...(source.token === undefined ? {} : { token: toLibauthToken(source.token) }),
  };
}

function fromLibauthTransaction(transaction: {
  version: number;
  inputs: Array<{
    outpointIndex: number;
    outpointTransactionHash: Uint8Array;
    sequenceNumber: number;
    unlockingBytecode: Uint8Array;
  }>;
  outputs: Array<{
    valueSatoshis: bigint;
    lockingBytecode: Uint8Array;
    token?: {
      amount: bigint;
      category: Uint8Array;
      nft?: { capability: TokenCapability; commitment: Uint8Array };
    };
  }>;
  locktime: number;
}): BchTransaction {
  return {
    version: transaction.version,
    inputs: transaction.inputs.map((input) => ({
      outpoint: {
        txid: bytesToHex(input.outpointTransactionHash),
        vout: input.outpointIndex,
      },
      scriptSig: input.unlockingBytecode,
      sequence: input.sequenceNumber,
    })),
    outputs: transaction.outputs.map((output) => ({
      value: output.valueSatoshis,
      scriptPubKey: output.lockingBytecode,
      ...(output.token === undefined ? {} : { token: fromLibauthToken(output.token) }),
    })),
    lockTime: transaction.locktime,
  };
}

function toLibauthToken(token: CashToken) {
  assertToken(token);
  return {
    amount: token.amount,
    category: hexToBytes(token.category),
    ...(token.nft === undefined
      ? {}
      : { nft: { capability: token.nft.capability, commitment: token.nft.commitment } }),
  };
}

function fromLibauthToken(token: {
  amount: bigint;
  category: Uint8Array;
  nft?: { capability: TokenCapability; commitment: Uint8Array };
}): CashToken {
  const result: CashToken = {
    amount: token.amount,
    category: bytesToHex(token.category),
  };
  if (token.nft !== undefined) result.nft = token.nft;
  assertToken(result);
  return result;
}

function assertToken(token: CashToken): void {
  if (!isCashTokenCategory(token.category))
    throw new Error('CashToken category must be 32-byte hex');
  if (token.amount < 0n || token.amount > MAX_CASH_TOKEN_AMOUNT) {
    throw new Error('CashToken amount exceeds the BCH consensus range');
  }
  if (token.nft === undefined && token.amount === 0n) {
    throw new Error('CashToken output must contain a fungible amount or NFT');
  }
  if (token.nft !== undefined) {
    if (!['none', 'mutable', 'minting'].includes(token.nft.capability)) {
      throw new Error('invalid CashToken NFT capability');
    }
    if (token.nft.commitment.length > MAX_TOKEN_COMMITMENT_LENGTH) {
      throw new Error('CashToken commitment is too large');
    }
  }
}

/** Parse strict BCH transaction bytes into the package transaction model. */
export function parseTransaction(raw: Uint8Array): BchTransaction {
  const decoded = decodeTransactionBCH(raw);
  if (typeof decoded === 'string') {
    if (decoded.includes('unexpected bytes')) throw new Error('trailing transaction bytes');
    throw new Error(decoded);
  }
  return fromLibauthTransaction(decoded);
}

/** Serialize a transaction using Libauth BCH encoding. */
export function serializeTransaction(transaction: BchTransaction): Uint8Array {
  return encodeTransactionBCH(toLibauthTransaction(transaction));
}

/** Calculate the transaction ID from its serialized transaction bytes. */
export function transactionId(transaction: BchTransaction): string {
  return hashTransaction(serializeTransaction(transaction));
}

/**
 * Generate the BCH ForkID signing digest for one input.
 * The caller supplies authoritative source outputs because BCH signatures
 * commit to input value and script data.
 */
export function signingHash(
  transaction: BchTransaction,
  inputIndex: number,
  source: BchSourceOutput,
  sourceOutputs: BchSourceOutput[] = [source],
): Uint8Array {
  if (inputIndex < 0 || inputIndex >= transaction.inputs.length)
    throw new Error('invalid input index');
  const serialization = generateSigningSerializationBCH(
    {
      inputIndex,
      sourceOutputs: sourceOutputs.map(toLibauthSourceOutput),
      transaction: toLibauthTransaction(transaction),
    },
    {
      coveredBytecode: source.scriptPubKey,
      signingSerializationType: Uint8Array.of(SIGHASH_ALL_FORKID),
    },
  );
  return libauthHash256(serialization);
}

/** Verify one P2PKH input with the BCH VM and return its public-key hash. */
export function verifyP2pkhInput(
  transaction: BchTransaction,
  inputIndex: number,
  source: BchSourceOutput,
  sourceOutputs: BchSourceOutput[] = [source],
): Uint8Array {
  if (!isP2pkhScript(source.scriptPubKey)) throw new Error('source output is not P2PKH');
  verifyTransactionScripts(transaction, sourceOutputs);
  return extractP2pkhIdentity(transaction, inputIndex, source);
}

/**
 * Verify every input with the BCH VM and return identities for recognizable
 * P2PKH inputs. P2SH20/P2SH32 and covenant inputs are valid without having a
 * single P2PKH payer identity.
 */
/** Verify every input with Libauth’s BCH VM and recover P2PKH identities. */
export function verifyTransactionInputs(
  transaction: BchTransaction,
  sources: BchSourceOutput[],
): Array<Uint8Array | undefined> {
  verifyTransactionScripts(transaction, sources);
  return sources.map((source, index) =>
    isP2pkhScript(source.scriptPubKey)
      ? extractP2pkhIdentity(transaction, index, source)
      : undefined,
  );
}

function verifyTransactionScripts(transaction: BchTransaction, sources: BchSourceOutput[]): void {
  const vmResult = createVirtualMachineBch2026().verify({
    transaction: toLibauthTransaction(transaction),
    sourceOutputs: sources.map(toLibauthSourceOutput),
  });
  if (vmResult !== true) throw new Error(vmResult);
}

function extractP2pkhIdentity(
  transaction: BchTransaction,
  inputIndex: number,
  source: BchSourceOutput,
): Uint8Array {
  const decoded = decodeAuthenticationInstructions(
    transaction.inputs[inputIndex]?.scriptSig ?? new Uint8Array(),
  );
  if (authenticationInstructionsAreMalformed(decoded)) {
    throw new Error('invalid P2PKH scriptSig');
  }
  if (!authenticationInstructionsArePushInstructions(decoded)) {
    throw new Error('P2PKH scriptSig contains a non-push operation');
  }
  const pushes = decoded.map((instruction) => instruction.data);
  if (pushes.length !== 2 || pushes[0].length < 2) throw new Error('invalid P2PKH scriptSig');
  const signature = pushes[0];
  if (signature[signature.length - 1] !== SIGHASH_ALL_FORKID) {
    throw new Error('unsupported BCH sighash type');
  }
  decodeBitcoinSignature(signature.slice(0, -1));
  const publicKey = pushes[1];
  const publicKeyHash = hash160(publicKey);
  if (!equalBytes(publicKeyHash, source.scriptPubKey.slice(3, 23))) {
    throw new Error('P2PKH public key does not match source output');
  }
  return publicKeyHash;
}

/**
 * Validate an exact BCH payment against authoritative source outputs.
 *
 * This checks transaction resource limits, BCH VM validity, CashToken
 * conservation, merchant output uniqueness, dust, fee rate, and payer
 * identity. It does not broadcast or query chain state.
 *
 * @returns Transaction ID, payer identity, and calculated miner fee.
 */
export function verifyPayment(
  transaction: BchTransaction,
  sources: BchSourceOutput[],
  network: BchNetwork,
  merchantScript: Uint8Array,
  merchantAmountOrTarget: bigint | BchPaymentTarget,
  policy: BchPolicy = DEFAULT_BCH_POLICY,
): { txid: string; payer: string; fee: bigint } {
  const target: BchPaymentTarget =
    typeof merchantAmountOrTarget === 'bigint'
      ? { kind: 'native', amount: merchantAmountOrTarget, merchantValue: merchantAmountOrTarget }
      : merchantAmountOrTarget;
  assertPaymentTarget(target);
  const serialized = serializeTransaction(transaction);
  if (serialized.length > policy.maxTransactionSize)
    throw new Error('transaction exceeds maximum size');
  if (transaction.inputs.length === 0 || transaction.inputs.length > policy.maxInputs) {
    throw new Error('invalid input count');
  }
  if (transaction.lockTime !== 0) throw new Error('non-zero locktime is unsupported');
  const merchantToken =
    target.kind === 'cashtoken'
      ? {
          category: target.category,
          amount: target.amount,
          ...(target.nft === undefined ? {} : { nft: target.nft }),
        }
      : undefined;
  if (target.merchantValue < dustMinimum(merchantScript, merchantToken, policy)) {
    throw new Error('merchant output is dust');
  }
  if (sources.length !== transaction.inputs.length) throw new Error('source output count mismatch');
  const tokenValidation = verifyTransactionTokens(
    toLibauthTransaction(transaction),
    sources.map(toLibauthSourceOutput),
    { maximumTokenCommitmentLength: MAX_TOKEN_COMMITMENT_LENGTH },
  );
  if (tokenValidation !== true) throw new Error(tokenValidation);
  const inputPayerHashes = verifyTransactionInputs(transaction, sources);
  if (transaction.outputs.length < 1 || transaction.outputs.length > policy.maxOutputs) {
    throw new Error('transaction output count exceeds BCH payment policy');
  }
  let inputValue = 0n;
  let payerHash: Uint8Array | undefined;
  const sourceTokenLedger = createTokenLedger();
  for (let index = 0; index < sources.length; index += 1) {
    inputValue = addU64(inputValue, sources[index].value, 'BCH input value');
    const inputPayerHash = inputPayerHashes[index];
    if (inputPayerHash !== undefined) {
      payerHash ??= inputPayerHash;
    }
    const token = sources[index].token;
    if (token !== undefined) addTokenToLedger(sourceTokenLedger, token);
  }
  const outputTokenLedger = createTokenLedger();
  if (
    target.kind === 'cashtoken' &&
    target.nft !== undefined &&
    !sources.some((source) => sameNft(source.token?.nft, target.nft))
  ) {
    throw new Error('CashToken inputs do not contain the requested NFT');
  }
  const sourceTargetTokenAmount =
    sourceTokenLedger.fungible.get(target.kind === 'cashtoken' ? target.category : '') ?? 0n;
  if (target.kind === 'cashtoken' && sourceTargetTokenAmount < target.amount) {
    throw new Error('CashToken inputs do not cover the requested amount');
  }
  const merchantMatches = transaction.outputs.filter(
    (output) =>
      output.value === target.merchantValue &&
      equalBytes(output.scriptPubKey, merchantScript) &&
      matchesMerchantToken(output.token, target),
  ).length;
  if (merchantMatches !== 1) throw new Error('merchant output must match exactly once');
  let outputValue = 0n;
  for (const output of transaction.outputs) {
    if (output.token !== undefined) {
      assertToken(output.token);
      addTokenToLedger(outputTokenLedger, output.token);
    }
    if (
      !isOpReturnScript(output.scriptPubKey) &&
      output.value < dustMinimum(output.scriptPubKey, output.token, policy)
    ) {
      throw new Error('transaction output is dust');
    }
    outputValue = addU64(outputValue, output.value, 'BCH output value');
  }
  if (!equalTokenLedgers(sourceTokenLedger, outputTokenLedger)) {
    throw new Error('CashToken state is not conserved');
  }
  const fee = inputValue - outputValue;
  if (fee < BigInt(serialized.length) * policy.feeRateSatPerByte) {
    throw new Error('transaction fee is below the required BCH fee rate');
  }
  const duplicateMerchant = transaction.outputs.some(
    (output) =>
      !(
        output.value === target.merchantValue &&
        equalBytes(output.scriptPubKey, merchantScript) &&
        matchesMerchantToken(output.token, target)
      ) && equalBytes(output.scriptPubKey, merchantScript),
  );
  if (duplicateMerchant) {
    throw new Error('duplicate merchant output');
  }
  const payer =
    payerHash === undefined
      ? payerIdentity(sources[0], network)
      : encodeCashAddr(payerHash, network);
  return { txid: transactionId(transaction), payer, fee };
}

export function dustMinimum(
  scriptPubKey: Uint8Array,
  token: CashToken | undefined,
  policy: BchPolicy,
): bigint {
  if (isOpReturnScript(scriptPubKey)) return 0n;
  const standard = getDustThreshold({
    lockingBytecode: scriptPubKey,
    valueSatoshis: 0n,
    ...(token === undefined ? {} : { token: toLibauthToken(token) }),
  });
  return standard > policy.dustThreshold ? standard : policy.dustThreshold;
}

function matchesMerchantToken(token: CashToken | undefined, target: BchPaymentTarget): boolean {
  if (target.kind === 'native') return token === undefined;
  return (
    token !== undefined &&
    token.category === target.category &&
    token.amount === target.amount &&
    sameNft(token.nft, target.nft)
  );
}

type TokenLedger = {
  fungible: Map<string, bigint>;
  nfts: Map<string, number>;
};

function createTokenLedger(): TokenLedger {
  return { fungible: new Map(), nfts: new Map() };
}

function addTokenToLedger(ledger: TokenLedger, token: CashToken): void {
  const fungible = ledger.fungible.get(token.category) ?? 0n;
  ledger.fungible.set(token.category, fungible + token.amount);
  if (token.nft !== undefined) {
    const key = `${token.category}:${token.nft.capability}:${bytesToHex(token.nft.commitment)}`;
    ledger.nfts.set(key, (ledger.nfts.get(key) ?? 0) + 1);
  }
}

function equalTokenLedgers(left: TokenLedger, right: TokenLedger): boolean {
  return equalBigIntMaps(left.fungible, right.fungible) && equalNumberMaps(left.nfts, right.nfts);
}

function equalBigIntMaps(left: Map<string, bigint>, right: Map<string, bigint>): boolean {
  if (left.size !== right.size) return false;
  return [...left].every(([key, value]) => right.get(key) === value);
}

function equalNumberMaps(left: Map<string, number>, right: Map<string, number>): boolean {
  if (left.size !== right.size) return false;
  return [...left].every(([key, value]) => right.get(key) === value);
}

function isOpReturnScript(script: Uint8Array): boolean {
  return script[0] === 0x6a;
}

function payerIdentity(source: BchSourceOutput, network: BchNetwork): string {
  try {
    return encodeCashAddrScript(source.scriptPubKey, network, source.token !== undefined);
  } catch {
    return `bch:script:${bytesToHex(source.scriptPubKey)}`;
  }
}

function sameNft(left: CashToken['nft'] | undefined, right: CashToken['nft'] | undefined): boolean {
  return (
    left?.capability === right?.capability &&
    (left === undefined || (right !== undefined && equalBytes(left.commitment, right.commitment)))
  );
}

function assertPaymentTarget(target: BchPaymentTarget): void {
  if (
    target.amount < 0n ||
    target.merchantValue < 0n ||
    target.amount > MAX_U64 ||
    target.merchantValue > MAX_U64
  ) {
    throw new Error('invalid BCH payment target');
  }
  if (target.kind === 'cashtoken') {
    if (!isCashTokenCategory(target.category)) {
      throw new Error('CashToken category must be 32-byte hex');
    }
    if (
      (target.amount === 0n && target.nft === undefined) ||
      target.amount > MAX_CASH_TOKEN_AMOUNT
    ) {
      throw new Error('CashToken amount is outside the BCH token range');
    }
  }
}

function addU64(left: bigint, right: bigint, label: string): bigint {
  const result = left + right;
  if (right < 0n || result > MAX_U64) throw new Error(`${label} exceeds u64`);
  return result;
}

/** Encode a byte vector as the minimal BCH Script push operation. */
export function pushData(value: Uint8Array): Uint8Array {
  return encodeDataPush(value);
}

/** Compare two byte vectors for exact equality. */
export function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return binsAreEqual(left, right);
}
