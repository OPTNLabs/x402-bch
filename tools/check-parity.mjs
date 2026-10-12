import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const fixtureRelativePath = 'spec/conformance/v1/payment-requirements.json';
const transactionFixtureRelativePath = 'spec/conformance/v1/transaction.json';
const addressFixtureRelativePath = 'spec/conformance/v1/addresses.json';
const cashTokenFixtureRelativePath = 'spec/conformance/v1/cashtoken.json';
const cashTokenNftFixtureRelativePath = 'spec/conformance/v1/cashtoken-nft.json';
const cashTokenCapabilitiesFixtureRelativePath = 'spec/conformance/v1/cashtoken-capabilities.json';
const cashTokenNegativeFixtureRelativePath = 'spec/conformance/v1/cashtoken-negative.json';
const p2pkhSignatureFixtureRelativePath = 'spec/conformance/v1/p2pkh-signature.json';
const requestHashFixtureRelativePath = 'spec/conformance/v1/request-hash.json';
const p2shCommitmentFixtureRelativePath = 'spec/conformance/v1/p2sh-commitment.json';
const settlementPolicyFixtureRelativePath = 'spec/conformance/v1/settlement-policy.json';
const providerObservationFixtureRelativePath = 'spec/conformance/v1/provider-observation.json';
const settlementOutcomeFixtureRelativePath = 'spec/conformance/v1/settlement-outcome.json';
const bchVmFixtureRelativePath = 'spec/conformance/v1/bch-vm.json';
const settlementIntegrationFixtureRelativePath = 'spec/conformance/v1/settlement-integration.json';
const settlementProviderFixtureRelativePath = 'spec/conformance/v1/settlement-provider.json';
const providerSourceOutputFixtureRelativePath = 'spec/conformance/v1/provider-source-output.json';
const packageFixtures = [
  ['TypeScript', 'packages/typescript'],
  ['Rust', 'packages/rust'],
  ['Go', 'packages/go'],
  ['Java', 'packages/java'],
  ['Python', 'packages/python'],
  ['C++', 'packages/cpp'],
];

const canonicalPath = join(root, packageFixtures[0][1], fixtureRelativePath);
const canonicalText = await readFile(canonicalPath, 'utf8');
const fixture = JSON.parse(canonicalText);
const canonicalTransactionPath = join(root, packageFixtures[0][1], transactionFixtureRelativePath);
const canonicalTransactionText = await readFile(canonicalTransactionPath, 'utf8');
const transactionFixture = JSON.parse(canonicalTransactionText);
const canonicalAddressPath = join(root, packageFixtures[0][1], addressFixtureRelativePath);
const canonicalAddressText = await readFile(canonicalAddressPath, 'utf8');
const addressFixture = JSON.parse(canonicalAddressText);
const canonicalCashTokenPath = join(root, packageFixtures[0][1], cashTokenFixtureRelativePath);
const canonicalCashTokenText = await readFile(canonicalCashTokenPath, 'utf8');
const cashTokenFixture = JSON.parse(canonicalCashTokenText);
const canonicalCashTokenNftPath = join(root, packageFixtures[0][1], cashTokenNftFixtureRelativePath);
const canonicalCashTokenNftText = await readFile(canonicalCashTokenNftPath, 'utf8');
const cashTokenNftFixture = JSON.parse(canonicalCashTokenNftText);
const canonicalCashTokenCapabilitiesPath = join(root, packageFixtures[0][1], cashTokenCapabilitiesFixtureRelativePath);
const canonicalCashTokenCapabilitiesText = await readFile(canonicalCashTokenCapabilitiesPath, 'utf8');
const cashTokenCapabilitiesFixture = JSON.parse(canonicalCashTokenCapabilitiesText);
const canonicalCashTokenNegativePath = join(root, packageFixtures[0][1], cashTokenNegativeFixtureRelativePath);
const canonicalCashTokenNegativeText = await readFile(canonicalCashTokenNegativePath, 'utf8');
const cashTokenNegativeFixture = JSON.parse(canonicalCashTokenNegativeText);
const canonicalP2pkhSignaturePath = join(root, packageFixtures[0][1], p2pkhSignatureFixtureRelativePath);
const canonicalP2pkhSignatureText = await readFile(canonicalP2pkhSignaturePath, 'utf8');
const p2pkhSignatureFixture = JSON.parse(canonicalP2pkhSignatureText);
const canonicalRequestHashPath = join(root, packageFixtures[0][1], requestHashFixtureRelativePath);
const canonicalRequestHashText = await readFile(canonicalRequestHashPath, 'utf8');
const requestHashFixture = JSON.parse(canonicalRequestHashText);
const canonicalP2shCommitmentPath = join(root, packageFixtures[0][1], p2shCommitmentFixtureRelativePath);
const canonicalP2shCommitmentText = await readFile(canonicalP2shCommitmentPath, 'utf8');
const p2shCommitmentFixture = JSON.parse(canonicalP2shCommitmentText);
const canonicalSettlementPolicyPath = join(root, packageFixtures[0][1], settlementPolicyFixtureRelativePath);
const canonicalSettlementPolicyText = await readFile(canonicalSettlementPolicyPath, 'utf8');
const settlementPolicyFixture = JSON.parse(canonicalSettlementPolicyText);
const canonicalProviderObservationPath = join(root, packageFixtures[0][1], providerObservationFixtureRelativePath);
const canonicalProviderObservationText = await readFile(canonicalProviderObservationPath, 'utf8');
const providerObservationFixture = JSON.parse(canonicalProviderObservationText);
const canonicalSettlementOutcomePath = join(root, packageFixtures[0][1], settlementOutcomeFixtureRelativePath);
const canonicalSettlementOutcomeText = await readFile(canonicalSettlementOutcomePath, 'utf8');
const settlementOutcomeFixture = JSON.parse(canonicalSettlementOutcomeText);
const canonicalBchVmPath = join(root, packageFixtures[0][1], bchVmFixtureRelativePath);
const canonicalBchVmText = await readFile(canonicalBchVmPath, 'utf8');
const bchVmFixture = JSON.parse(canonicalBchVmText);
const canonicalSettlementIntegrationPath = join(root, packageFixtures[0][1], settlementIntegrationFixtureRelativePath);
const canonicalSettlementIntegrationText = await readFile(canonicalSettlementIntegrationPath, 'utf8');
const settlementIntegrationFixture = JSON.parse(canonicalSettlementIntegrationText);
const canonicalSettlementProviderPath = join(root, packageFixtures[0][1], settlementProviderFixtureRelativePath);
const canonicalSettlementProviderText = await readFile(canonicalSettlementProviderPath, 'utf8');
const settlementProviderFixture = JSON.parse(canonicalSettlementProviderText);
const canonicalProviderSourceOutputPath = join(root, packageFixtures[0][1], providerSourceOutputFixtureRelativePath);
const canonicalProviderSourceOutputText = await readFile(canonicalProviderSourceOutputPath, 'utf8');
const providerSourceOutputFixture = JSON.parse(canonicalProviderSourceOutputText);

if (fixture.version !== 1 || !Array.isArray(fixture.cases) || fixture.cases.length < 1) {
  throw new Error('invalid conformance fixture');
}
if (
  !/^[0-9a-f]+$/.test(transactionFixture.rawTransaction) ||
  transactionFixture.rawTransaction.length % 2 !== 0 ||
  !/^[0-9a-f]{64}$/.test(transactionFixture.txid) ||
  !/^(0|[1-9][0-9]*)$/.test(transactionFixture.sourceValue) ||
  !/^(0|[1-9][0-9]*)$/.test(transactionFixture.merchantValue) ||
  !/^[0-9a-f]+$/.test(transactionFixture.sourceScriptPubKey) ||
  !/^[0-9a-f]+$/.test(transactionFixture.merchantScriptPubKey) ||
  !Number.isInteger(transactionFixture.serializedSize) ||
  !/^(0|[1-9][0-9]*)$/.test(transactionFixture.fee) ||
  transactionFixture.serializedSize !== transactionFixture.rawTransaction.length / 2
) {
  throw new Error('invalid transaction fixture');
}
const transactionHash = createHash('sha256')
  .update(createHash('sha256').update(Buffer.from(transactionFixture.rawTransaction, 'hex')).digest())
  .digest()
  .reverse()
  .toString('hex');
if (transactionHash !== transactionFixture.txid) throw new Error('transaction fixture txid mismatch');
if (addressFixture.version !== 1 || !Array.isArray(addressFixture.cases) || addressFixture.cases.length !== 5) {
  throw new Error('invalid address fixture');
}
for (const addressCase of addressFixture.cases) {
  if (!['bch:bitcoincash', 'bch:bchtest'].includes(addressCase.network)) {
    throw new Error(`${addressCase.id}: address network`);
  }
  if (!/^(bitcoincash|bchtest):[qpzry9x8gf2tvdw0s3jn54khce6mua7l]+$/.test(addressCase.address)) {
    throw new Error(`${addressCase.id}: address encoding`);
  }
  if (!/^[0-9a-f]+$/.test(addressCase.scriptPubKey)) {
    throw new Error(`${addressCase.id}: script encoding`);
  }
}
if (
  !/^[0-9a-f]+$/.test(cashTokenFixture.rawTransaction) ||
  !/^[0-9a-f]{64}$/.test(cashTokenFixture.txid) ||
  !/^[0-9a-f]{64}$/.test(cashTokenFixture.asset) ||
  !/^(0|[1-9][0-9]*)$/.test(cashTokenFixture.amount) ||
  !/^(0|[1-9][0-9]*)$/.test(cashTokenFixture.value) ||
  !Number.isInteger(cashTokenFixture.serializedSize)
) {
  throw new Error('invalid CashToken fixture');
}
const cashTokenHash = createHash('sha256')
  .update(createHash('sha256').update(Buffer.from(cashTokenFixture.rawTransaction, 'hex')).digest())
  .digest()
  .reverse()
  .toString('hex');
if (cashTokenHash !== cashTokenFixture.txid || cashTokenFixture.serializedSize !== cashTokenFixture.rawTransaction.length / 2) {
  throw new Error('CashToken fixture txid or size mismatch');
}
if (
  !/^[0-9a-f]+$/.test(cashTokenNftFixture.rawTransaction) ||
  !/^[0-9a-f]{64}$/.test(cashTokenNftFixture.txid) ||
  !/^[0-9a-f]{64}$/.test(cashTokenNftFixture.asset) ||
  cashTokenNftFixture.amount !== '0' ||
  !cashTokenNftFixture.sourceToken?.nft ||
  cashTokenNftFixture.sourceToken.nft.capability !== 'none' ||
  !/^[0-9a-f]{2,80}$/.test(cashTokenNftFixture.sourceToken.nft.commitment) ||
  cashTokenNftFixture.sourceToken.nft.commitment.length % 2 !== 0 ||
  cashTokenNftFixture.serializedSize !== cashTokenNftFixture.rawTransaction.length / 2
) {
  throw new Error('invalid CashToken NFT fixture');
}
const cashTokenNftHash = createHash('sha256')
  .update(createHash('sha256').update(Buffer.from(cashTokenNftFixture.rawTransaction, 'hex')).digest())
  .digest()
  .reverse()
  .toString('hex');
if (cashTokenNftHash !== cashTokenNftFixture.txid) {
  throw new Error('CashToken NFT fixture txid mismatch');
}
if (
  cashTokenCapabilitiesFixture.version !== 1 ||
  !Array.isArray(cashTokenCapabilitiesFixture.cases) ||
  cashTokenCapabilitiesFixture.cases.length !== 2
) {
  throw new Error('invalid CashToken capability fixture');
}
for (const capabilityCase of cashTokenCapabilitiesFixture.cases) {
  if (!['mutable', 'minting'].includes(capabilityCase.capability)) {
    throw new Error(`${capabilityCase.id}: invalid CashToken capability`);
  }
  if (
    capabilityCase.sourceToken?.nft?.capability !== capabilityCase.capability ||
    capabilityCase.sourceToken.nft.commitment.length !== 80 ||
    !/^[0-9a-f]+$/.test(capabilityCase.rawTransaction) ||
    !/^[0-9a-f]{64}$/.test(capabilityCase.txid) ||
    capabilityCase.serializedSize !== capabilityCase.rawTransaction.length / 2
  ) {
    throw new Error(`${capabilityCase.id}: invalid CashToken capability case`);
  }
  const capabilityHash = createHash('sha256')
    .update(createHash('sha256').update(Buffer.from(capabilityCase.rawTransaction, 'hex')).digest())
    .digest()
    .reverse()
    .toString('hex');
  if (capabilityHash !== capabilityCase.txid) {
    throw new Error(`${capabilityCase.id}: CashToken capability txid mismatch`);
  }
}
if (
  cashTokenNegativeFixture.version !== 1 ||
  !Array.isArray(cashTokenNegativeFixture.cases) ||
  cashTokenNegativeFixture.cases.length !== 4
) {
  throw new Error('invalid CashToken negative fixture');
}
for (const negativeCase of cashTokenNegativeFixture.cases) {
  if (
    !['parse', 'verify'].includes(negativeCase.kind) ||
    !/^[0-9a-f]+$/.test(negativeCase.rawTransaction) ||
    negativeCase.rawTransaction.length % 2 !== 0 ||
    !negativeCase.errorCode
  ) {
    throw new Error(`${negativeCase.id}: invalid CashToken negative case`);
  }
  if (
    negativeCase.kind === 'verify' &&
    (!negativeCase.network ||
      !negativeCase.sourceScriptPubKey ||
      !negativeCase.sourceToken ||
      !negativeCase.merchantScriptPubKey ||
      !negativeCase.asset ||
      !negativeCase.amount)
  ) {
    throw new Error(`${negativeCase.id}: invalid verification negative case`);
  }
}
if (
  p2pkhSignatureFixture.version !== 1 ||
  !Array.isArray(p2pkhSignatureFixture.cases) ||
  p2pkhSignatureFixture.cases.length !== 2
) {
  throw new Error('invalid P2PKH signature fixture');
}
for (const signatureCase of p2pkhSignatureFixture.cases) {
  if (
    !signatureCase.id ||
    !['accept', 'reject'].includes(signatureCase.expected) ||
    signatureCase.inputIndex !== 0 ||
    !/^(0|[1-9][0-9]*)$/.test(signatureCase.sourceValue) ||
    !/^[0-9a-f]+$/.test(signatureCase.sourceScriptPubKey) ||
    !/^[0-9a-f]+$/.test(signatureCase.rawTransaction) ||
    signatureCase.rawTransaction.length % 2 !== 0 ||
    signatureCase.sighashType !== '41' ||
    !/^[0-9a-f]{64}$/.test(signatureCase.expectedSighash) ||
    !/^[0-9a-f]{40}$/.test(signatureCase.expectedPayerHash)
  ) {
    throw new Error(`${signatureCase.id}: invalid P2PKH signature case`);
  }
  if (signatureCase.expected === 'reject' && signatureCase.errorCode !== 'invalid-signature') {
    throw new Error(`${signatureCase.id}: invalid P2PKH rejection code`);
  }
}
if (
  requestHashFixture.version !== 1 ||
  !Array.isArray(requestHashFixture.cases) ||
  requestHashFixture.cases.length !== 3
) {
  throw new Error('invalid request-hash fixture');
}
for (const requestHashCase of requestHashFixture.cases) {
  if (
    !requestHashCase.id ||
    !/^[0-9a-f]{64}$/.test(requestHashCase.requestHash) ||
    !/^[0-9a-f]+$/.test(requestHashCase.rawTransaction) ||
    requestHashCase.rawTransaction.length % 2 !== 0 ||
    !['accept', 'reject'].includes(requestHashCase.expected) ||
    (requestHashCase.expected === 'reject' &&
      !['request-hash-mismatch', 'request-hash-missing'].includes(requestHashCase.errorCode))
  ) {
    throw new Error(`${requestHashCase.id}: invalid request-hash case`);
  }
}
if (
  p2shCommitmentFixture.version !== 1 ||
  !Array.isArray(p2shCommitmentFixture.cases) ||
  p2shCommitmentFixture.cases.length !== 4
) {
  throw new Error('invalid P2SH commitment fixture');
}
for (const p2shCase of p2shCommitmentFixture.cases) {
  if (
    !p2shCase.id ||
    p2shCase.inputIndex !== 0 ||
    !/^(0|[1-9][0-9]*)$/.test(p2shCase.sourceValue) ||
    !/^[0-9a-f]+$/.test(p2shCase.sourceScriptPubKey) ||
    !/^[0-9a-f]+$/.test(p2shCase.redeemScript) ||
    !/^[0-9a-f]+$/.test(p2shCase.rawTransaction) ||
    p2shCase.rawTransaction.length % 2 !== 0 ||
    !/^[0-9a-f]{64}$/.test(p2shCase.txid) ||
    p2shCase.serializedSize !== p2shCase.rawTransaction.length / 2 ||
    !['accept', 'reject'].includes(p2shCase.expected) ||
    (p2shCase.expected === 'reject' && !p2shCase.errorCode)
  ) {
    throw new Error(`${p2shCase.id}: invalid P2SH commitment case`);
  }
  const p2shHash = createHash('sha256')
    .update(createHash('sha256').update(Buffer.from(p2shCase.rawTransaction, 'hex')).digest())
    .digest()
    .reverse()
    .toString('hex');
  if (p2shHash !== p2shCase.txid) throw new Error(`${p2shCase.id}: P2SH fixture txid mismatch`);
}
if (
  settlementPolicyFixture.version !== 1 ||
  !Array.isArray(settlementPolicyFixture.cases) ||
  settlementPolicyFixture.cases.length !== 13
) {
  throw new Error('invalid settlement policy fixture');
}
for (const settlementCase of settlementPolicyFixture.cases) {
  if (
    !settlementCase.id ||
    !['mempool', 'noDoubleSpendProof', 'confirmations'].includes(settlementCase.strategy) ||
    !['notFound', 'mempool', 'confirmed', 'unknown', 'conflicted'].includes(settlementCase.status) ||
    typeof settlementCase.expectedAccepted !== 'boolean'
  ) {
    throw new Error(`${settlementCase.id}: invalid settlement policy case`);
  }
  if (settlementCase.strategy === 'confirmations' && (!Number.isInteger(settlementCase.confirmations) || settlementCase.confirmations < 1)) {
    throw new Error(`${settlementCase.id}: invalid confirmation count`);
  }
  if (settlementCase.status === 'confirmed' && (!Number.isInteger(settlementCase.height) || !Number.isInteger(settlementCase.tipHeight))) {
    throw new Error(`${settlementCase.id}: confirmed case requires heights`);
  }
}
if (
  providerObservationFixture.version !== 1 ||
  !Array.isArray(providerObservationFixture.cases) ||
  providerObservationFixture.cases.length !== 5
) {
  throw new Error('invalid provider observation fixture');
}
for (const observationCase of providerObservationFixture.cases) {
  const candidateValid = /^[0-9a-f]{64}$/i.test(observationCase.candidateTxid);
  const rawValid =
    observationCase.rawTransaction === null ||
    (/^[0-9a-f]+$/i.test(observationCase.rawTransaction) && observationCase.rawTransaction.length % 2 === 0);
  if (
    !observationCase.id ||
    (!candidateValid && observationCase.expected) ||
    !rawValid ||
    typeof observationCase.expected !== 'boolean'
  ) {
    throw new Error(`${observationCase.id}: invalid provider observation case`);
  }
  if (observationCase.rawTransaction !== null) {
    const observedHash = createHash('sha256')
      .update(createHash('sha256').update(Buffer.from(observationCase.rawTransaction, 'hex')).digest())
      .digest()
      .reverse()
      .toString('hex');
    if (observationCase.expected && observedHash !== observationCase.candidateTxid.toLowerCase()) {
      throw new Error(`${observationCase.id}: expected provider txid match is invalid`);
    }
    if (!observationCase.expected && observedHash === observationCase.candidateTxid.toLowerCase()) {
      throw new Error(`${observationCase.id}: expected provider txid mismatch is invalid`);
    }
  }
}
if (
  settlementOutcomeFixture.version !== 1 ||
  !Array.isArray(settlementOutcomeFixture.cases) ||
  settlementOutcomeFixture.cases.length !== 8
) {
  throw new Error('invalid settlement outcome fixture');
}
for (const outcomeCase of settlementOutcomeFixture.cases) {
  if (
    !outcomeCase.id ||
    typeof outcomeCase.candidateValid !== 'boolean' ||
    !['missing', 'match', 'mismatch'].includes(outcomeCase.providerObservation) ||
    !['mempool', 'noDoubleSpendProof', 'confirmations'].includes(outcomeCase.strategy) ||
    !['notFound', 'mempool', 'confirmed', 'unknown', 'conflicted'].includes(outcomeCase.status) ||
    !['accepted', 'pending', 'rejected'].includes(outcomeCase.expectedOutcome)
  ) {
    throw new Error(`${outcomeCase.id}: invalid settlement outcome case`);
  }
}
if (
  bchVmFixture.version !== 1 ||
  bchVmFixture.profile !== 'bch-bounded-v1' ||
  !Array.isArray(bchVmFixture.cases) ||
  bchVmFixture.cases.length !== 12
) {
  throw new Error('invalid BCH VM fixture');
}
for (const vmCase of bchVmFixture.cases) {
  if (
    !vmCase.id ||
    !/^[0-9a-f]*$/i.test(vmCase.unlockingScript) ||
    !/^[0-9a-f]*$/i.test(vmCase.lockingScript) ||
    vmCase.unlockingScript.length % 2 !== 0 ||
    vmCase.lockingScript.length % 2 !== 0 ||
    typeof vmCase.expectedAccepted !== 'boolean' ||
    (vmCase.expectedAccepted && vmCase.expectedError !== null) ||
    (!vmCase.expectedAccepted && typeof vmCase.expectedError !== 'string')
  ) {
    throw new Error(`${vmCase.id}: invalid BCH VM case`);
  }
}
if (
  settlementIntegrationFixture.version !== 1 ||
  !Array.isArray(settlementIntegrationFixture.cases) ||
  settlementIntegrationFixture.cases.length !== 11
) {
  throw new Error('invalid settlement integration fixture');
}
for (const integrationCase of settlementIntegrationFixture.cases) {
  if (
    !integrationCase.id ||
    (integrationCase.candidateValid && !/^[0-9a-f]{64}$/i.test(integrationCase.candidateTxid)) ||
    (!integrationCase.candidateValid && integrationCase.candidateTxid !== '') ||
    typeof integrationCase.bindingMatches !== 'boolean' ||
    !['none', 'same', 'different'].includes(integrationCase.existingClaim) ||
    !['missing', 'match', 'mismatch'].includes(integrationCase.providerObservation) ||
    !['none', 'accepted', 'lost'].includes(integrationCase.broadcastAttempt) ||
    !['accepted', 'pending', 'rejected'].includes(integrationCase.expectedState) ||
    !['broadcast', 'retry', 'retain', 'skip', 'reject', 'conflict'].includes(integrationCase.expectedAction) ||
    (integrationCase.expectedState !== 'rejected' && !/^[0-9a-f]{64}$/i.test(integrationCase.expectedTransactionId))
  ) {
    throw new Error(`${integrationCase.id}: invalid settlement integration case`);
  }
}
if (
  settlementProviderFixture.version !== 1 ||
  settlementProviderFixture.sourceFixture !== 'provider-observation.json' ||
  !Array.isArray(settlementProviderFixture.cases) ||
  settlementProviderFixture.cases.length !== 7
) {
  throw new Error('invalid settlement provider fixture');
}
for (const providerCase of settlementProviderFixture.cases) {
  if (
    !providerCase.id ||
    !providerCase.providerCase ||
    typeof providerCase.candidateValid !== 'boolean' ||
    typeof providerCase.bindingMatches !== 'boolean' ||
    !['none', 'same', 'different'].includes(providerCase.existingClaim) ||
    !['confirmations', 'mempool', 'noDoubleSpendProof'].includes(providerCase.strategy) ||
    !['notFound', 'mempool', 'confirmed', 'unknown', 'conflicted'].includes(providerCase.status) ||
    !['missing', 'match', 'mismatch'].includes(providerCase.expectedObservation) ||
    !['accepted', 'pending', 'rejected'].includes(providerCase.expectedState) ||
    !['broadcast', 'retry', 'retain', 'skip', 'reject', 'conflict'].includes(providerCase.expectedAction) ||
    (providerCase.expectedState !== 'rejected' && !/^[0-9a-f]{64}$/i.test(providerCase.expectedTransactionId))
  ) {
    throw new Error(`${providerCase.id}: invalid settlement provider case`);
  }
}
if (
  providerSourceOutputFixture.version !== 1 ||
  providerSourceOutputFixture.sourceFixture !== 'provider-observation.json' ||
  !Array.isArray(providerSourceOutputFixture.cases) ||
  providerSourceOutputFixture.cases.length !== 6
) {
  throw new Error('invalid provider source-output fixture');
}
for (const sourceCase of providerSourceOutputFixture.cases) {
  if (
    !sourceCase.id ||
    !sourceCase.providerCase ||
    !/^[0-9a-f]{64}$/i.test(sourceCase.sourceTxid) && sourceCase.expectedObservation !== 'mismatch' ||
    !Number.isInteger(sourceCase.vout) ||
    !['missing', 'mismatch', 'notFound', 'match'].includes(sourceCase.expectedObservation) ||
    (sourceCase.expectedObservation === 'match' &&
      (!/^(0|[1-9][0-9]*)$/.test(sourceCase.expectedValue) || !/^[0-9a-f]+$/i.test(sourceCase.expectedScriptPubKey)))
  ) {
    throw new Error(`${sourceCase.id}: invalid provider source-output case`);
  }
}
for (const testCase of fixture.cases) {
  const { requirements, expected } = testCase;
  if (requirements.x402Version !== 2) throw new Error(`${testCase.name}: x402 version`);
  if (requirements.scheme !== 'exact') throw new Error(`${testCase.name}: scheme`);
  if (!/^\d+$/.test(requirements.amount)) throw new Error(`${testCase.name}: amount`);
  if (
    requirements.extra?.requestHash !== undefined &&
    !/^[0-9a-f]{64}$/.test(requirements.extra.requestHash)
  ) {
    throw new Error(`${testCase.name}: requestHash`);
  }
  if (expected.requestHashBytes !== undefined && expected.requestHashBytes !== 32) {
    throw new Error(`${testCase.name}: requestHashBytes`);
  }
}

for (const [language, packagePath] of packageFixtures.slice(1)) {
  const packageFixturePath = join(root, packagePath, fixtureRelativePath);
  const packageText = await readFile(packageFixturePath, 'utf8');
  if (packageText !== canonicalText) {
    throw new Error(`${language} fixture differs from the TypeScript fixture`);
  }
  const transactionPath = join(root, packagePath, transactionFixtureRelativePath);
  const packageTransactionText = await readFile(transactionPath, 'utf8');
  if (packageTransactionText !== canonicalTransactionText) {
    throw new Error(`${language} transaction fixture differs from the TypeScript fixture`);
  }
  const addressPath = join(root, packagePath, addressFixtureRelativePath);
  const packageAddressText = await readFile(addressPath, 'utf8');
  if (packageAddressText !== canonicalAddressText) {
    throw new Error(`${language} address fixture differs from the TypeScript fixture`);
  }
  const cashTokenPath = join(root, packagePath, cashTokenFixtureRelativePath);
  const packageCashTokenText = await readFile(cashTokenPath, 'utf8');
  if (packageCashTokenText !== canonicalCashTokenText) {
    throw new Error(`${language} CashToken fixture differs from the TypeScript fixture`);
  }
  const cashTokenNftPath = join(root, packagePath, cashTokenNftFixtureRelativePath);
  const packageCashTokenNftText = await readFile(cashTokenNftPath, 'utf8');
  if (packageCashTokenNftText !== canonicalCashTokenNftText) {
    throw new Error(`${language} CashToken NFT fixture differs from the TypeScript fixture`);
  }
  const cashTokenCapabilitiesPath = join(root, packagePath, cashTokenCapabilitiesFixtureRelativePath);
  const packageCashTokenCapabilitiesText = await readFile(cashTokenCapabilitiesPath, 'utf8');
  if (packageCashTokenCapabilitiesText !== canonicalCashTokenCapabilitiesText) {
    throw new Error(`${language} CashToken capability fixture differs from the TypeScript fixture`);
  }
  const cashTokenNegativePath = join(root, packagePath, cashTokenNegativeFixtureRelativePath);
  const packageCashTokenNegativeText = await readFile(cashTokenNegativePath, 'utf8');
  if (packageCashTokenNegativeText !== canonicalCashTokenNegativeText) {
    throw new Error(`${language} CashToken negative fixture differs from the TypeScript fixture`);
  }
  const p2pkhSignaturePath = join(root, packagePath, p2pkhSignatureFixtureRelativePath);
  const packageP2pkhSignatureText = await readFile(p2pkhSignaturePath, 'utf8');
  if (packageP2pkhSignatureText !== canonicalP2pkhSignatureText) {
    throw new Error(`${language} P2PKH signature fixture differs from the TypeScript fixture`);
  }
  const requestHashPath = join(root, packagePath, requestHashFixtureRelativePath);
  const packageRequestHashText = await readFile(requestHashPath, 'utf8');
  if (packageRequestHashText !== canonicalRequestHashText) {
    throw new Error(`${language} request-hash fixture differs from the TypeScript fixture`);
  }
  const p2shCommitmentPath = join(root, packagePath, p2shCommitmentFixtureRelativePath);
  const packageP2shCommitmentText = await readFile(p2shCommitmentPath, 'utf8');
  if (packageP2shCommitmentText !== canonicalP2shCommitmentText) {
    throw new Error(`${language} P2SH commitment fixture differs from the TypeScript fixture`);
  }
  const settlementPolicyPath = join(root, packagePath, settlementPolicyFixtureRelativePath);
  const packageSettlementPolicyText = await readFile(settlementPolicyPath, 'utf8');
  if (packageSettlementPolicyText !== canonicalSettlementPolicyText) {
    throw new Error(`${language} settlement policy fixture differs from the TypeScript fixture`);
  }
  const providerObservationPath = join(root, packagePath, providerObservationFixtureRelativePath);
  const packageProviderObservationText = await readFile(providerObservationPath, 'utf8');
  if (packageProviderObservationText !== canonicalProviderObservationText) {
    throw new Error(`${language} provider observation fixture differs from the TypeScript fixture`);
  }
  const settlementOutcomePath = join(root, packagePath, settlementOutcomeFixtureRelativePath);
  const packageSettlementOutcomeText = await readFile(settlementOutcomePath, 'utf8');
  if (packageSettlementOutcomeText !== canonicalSettlementOutcomeText) {
    throw new Error(`${language} settlement outcome fixture differs from the TypeScript fixture`);
  }
  const bchVmPath = join(root, packagePath, bchVmFixtureRelativePath);
  const packageBchVmText = await readFile(bchVmPath, 'utf8');
  if (packageBchVmText !== canonicalBchVmText) {
    throw new Error(`${language} BCH VM fixture differs from the TypeScript fixture`);
  }
  const settlementIntegrationPath = join(root, packagePath, settlementIntegrationFixtureRelativePath);
  const packageSettlementIntegrationText = await readFile(settlementIntegrationPath, 'utf8');
  if (packageSettlementIntegrationText !== canonicalSettlementIntegrationText) {
    throw new Error(`${language} settlement integration fixture differs from the TypeScript fixture`);
  }
  const settlementProviderPath = join(root, packagePath, settlementProviderFixtureRelativePath);
  const packageSettlementProviderText = await readFile(settlementProviderPath, 'utf8');
  if (packageSettlementProviderText !== canonicalSettlementProviderText) {
    throw new Error(`${language} settlement provider fixture differs from the TypeScript fixture`);
  }
  const providerSourceOutputPath = join(root, packagePath, providerSourceOutputFixtureRelativePath);
  const packageProviderSourceOutputText = await readFile(providerSourceOutputPath, 'utf8');
  if (packageProviderSourceOutputText !== canonicalProviderSourceOutputText) {
    throw new Error(`${language} provider source-output fixture differs from the TypeScript fixture`);
  }
}
console.log(
  `conformance fixtures: ${fixture.cases.length} wire cases + ${cashTokenNegativeFixture.cases.length} negative CashToken cases + ${p2pkhSignatureFixture.cases.length} P2PKH signature cases + ${requestHashFixture.cases.length} request-hash cases + ${p2shCommitmentFixture.cases.length} P2SH commitment cases + ${settlementPolicyFixture.cases.length} settlement-policy cases + ${providerObservationFixture.cases.length} provider-observation cases + ${settlementOutcomeFixture.cases.length} settlement-outcome cases + ${bchVmFixture.cases.length} BCH VM cases + ${settlementIntegrationFixture.cases.length} settlement-integration cases + ${settlementProviderFixture.cases.length} provider-fact settlement cases + ${providerSourceOutputFixture.cases.length} provider source-output cases validated across ${packageFixtures.length} packages`,
);

function resolveCommand(command) {
  try {
    const resolved = execFileSync('which', [command], { encoding: 'utf8' }).trim();
    if (resolved) return resolved;
  } catch {
    // Try known toolchain locations below.
  }
  const fallbackPaths = command === 'go' ? ['/usr/local/go/bin/go'] : [];
  return fallbackPaths.find((candidate) => existsSync(candidate)) ?? null;
}

function run(command, args, cwd) {
  execFileSync(command, args, { cwd, stdio: 'inherit' });
}

run('npm', ['run', 'test:conformance'], join(root, 'packages/typescript'));
run('python3', ['tests/run_conformance.py'], join(root, 'packages/python'));
run('make', ['test'], join(root, 'packages/java'));

const cppBuild = mkdtempSync(join(tmpdir(), 'x402-bch-cpp-'));
try {
  run('cmake', ['-S', join(root, 'packages/cpp'), '-B', cppBuild], root);
  run('cmake', ['--build', cppBuild], root);
  run('ctest', ['--test-dir', cppBuild, '--output-on-failure'], root);
} finally {
  rmSync(cppBuild, { recursive: true, force: true });
}

const goCommand = resolveCommand('go');
if (goCommand) {
  run(goCommand, ['test', './...'], join(root, 'packages/go'));
} else {
  if (process.env.CI === 'true' || process.env.X402_REQUIRE_GO === '1') {
    throw new Error('go toolchain is required for the cross-language release gate');
  }
  console.warn('go toolchain unavailable; Go conformance test not run locally');
}

const cargoCommand = resolveCommand('cargo');
if (cargoCommand) {
  run(cargoCommand, ['fmt', '--manifest-path', 'Cargo.toml', '--', '--check'], join(root, 'packages/rust'));
  run(
    cargoCommand,
    ['test', '--manifest-path', 'Cargo.toml', '--locked', '--all-features', '--lib'],
    join(root, 'packages/rust'),
  );
} else {
  console.warn('cargo toolchain unavailable; Rust conformance test not run');
}
