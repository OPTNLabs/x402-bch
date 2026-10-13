import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
await import('./check-feature-manifest.mjs');
await import('./check-api-inventory.mjs');
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
const serverRequirementsFixtureRelativePath = 'spec/conformance/v1/server-requirements.json';
const sdkLifecycleFixtureRelativePath = 'spec/conformance/v1/sdk-lifecycle.json';
const hdWalletFixtureRelativePath = 'spec/conformance/v1/hd-wallet.json';
const covenantProfilesFixtureRelativePath = 'spec/conformance/v1/covenant-profiles.json';
const providerTransportFixtureRelativePath = 'spec/conformance/v1/provider-transport.json';
const bchnRpcFixtureRelativePath = 'spec/conformance/v1/bchn-rpc.json';
const mocknetFixtureRelativePath = 'spec/conformance/v1/mocknet.json';
const diagnosticsFixtureRelativePath = 'spec/conformance/v1/diagnostics.json';
const httpFlowFixtureRelativePath = 'spec/conformance/v1/http-flow.json';
const bip39WordListRelativePath = 'spec/conformance/v1/bip39-english.txt';
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
const canonicalServerRequirementsPath = join(root, packageFixtures[0][1], serverRequirementsFixtureRelativePath);
const canonicalServerRequirementsText = await readFile(canonicalServerRequirementsPath, 'utf8');
const serverRequirementsFixture = JSON.parse(canonicalServerRequirementsText);
const canonicalSdkLifecyclePath = join(root, packageFixtures[0][1], sdkLifecycleFixtureRelativePath);
const canonicalSdkLifecycleText = await readFile(canonicalSdkLifecyclePath, 'utf8');
const sdkLifecycleFixture = JSON.parse(canonicalSdkLifecycleText);
const canonicalHdWalletPath = join(root, packageFixtures[0][1], hdWalletFixtureRelativePath);
const canonicalHdWalletText = await readFile(canonicalHdWalletPath, 'utf8');
const hdWalletFixture = JSON.parse(canonicalHdWalletText);
const canonicalCovenantProfilesPath = join(root, packageFixtures[0][1], covenantProfilesFixtureRelativePath);
const canonicalCovenantProfilesText = await readFile(canonicalCovenantProfilesPath, 'utf8');
const covenantProfilesFixture = JSON.parse(canonicalCovenantProfilesText);
const canonicalProviderTransportPath = join(root, packageFixtures[0][1], providerTransportFixtureRelativePath);
const canonicalProviderTransportText = await readFile(canonicalProviderTransportPath, 'utf8');
const providerTransportFixture = JSON.parse(canonicalProviderTransportText);
const canonicalBchnRpcPath = join(root, packageFixtures[0][1], bchnRpcFixtureRelativePath);
const canonicalBchnRpcText = await readFile(canonicalBchnRpcPath, 'utf8');
const bchnRpcFixture = JSON.parse(canonicalBchnRpcText);
const canonicalMocknetPath = join(root, packageFixtures[0][1], mocknetFixtureRelativePath);
const canonicalMocknetText = await readFile(canonicalMocknetPath, 'utf8');
const mocknetFixture = JSON.parse(canonicalMocknetText);
const canonicalDiagnosticsPath = join(root, packageFixtures[0][1], diagnosticsFixtureRelativePath);
const canonicalDiagnosticsText = await readFile(canonicalDiagnosticsPath, 'utf8');
const diagnosticsFixture = JSON.parse(canonicalDiagnosticsText);
const canonicalHttpFlowPath = join(root, packageFixtures[0][1], httpFlowFixtureRelativePath);
const canonicalHttpFlowText = await readFile(canonicalHttpFlowPath, 'utf8');
const httpFlowFixture = JSON.parse(canonicalHttpFlowText);
const canonicalBip39Path = join(root, packageFixtures[0][1], bip39WordListRelativePath);
const canonicalBip39Text = await readFile(canonicalBip39Path, 'utf8');
if (canonicalBip39Text.trimEnd().split('\n').length !== 2048) throw new Error('invalid BIP39 English wordlist');

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
if (
  serverRequirementsFixture.version !== 1 ||
  !Array.isArray(serverRequirementsFixture.cases) ||
  serverRequirementsFixture.cases.length !== 4
) {
  throw new Error('invalid server requirements fixture');
}
for (const serverCase of serverRequirementsFixture.cases) {
  if (
    !serverCase.id ||
    !['native', 'cashtoken'].includes(serverCase.input?.kind) ||
    !['bch:bitcoincash', 'bch:bchtest'].includes(serverCase.input?.network) ||
    typeof serverCase.input?.payTo !== 'string' ||
    !/^(0|[1-9][0-9]*)$/.test(serverCase.input?.amount ?? '') ||
    serverCase.expected?.x402Version !== 2 ||
    serverCase.expected?.scheme !== 'exact' ||
    serverCase.expected?.maxTimeoutSeconds !== 300
  ) {
    throw new Error(`${serverCase.id}: invalid server requirements case`);
  }
}
if (
  sdkLifecycleFixture.version !== 1 ||
  sdkLifecycleFixture.requirements?.x402Version !== 2 ||
  sdkLifecycleFixture.requirements?.scheme !== 'exact' ||
  sdkLifecycleFixture.requirements?.extra?.paymentFlow !== 'upfront' ||
  sdkLifecycleFixture.walletRequest?.network !== 'mainnet' ||
  sdkLifecycleFixture.walletRequest?.value !== '1000' ||
  !/^[A-Za-z0-9+/]+={0,2}$/.test(sdkLifecycleFixture.transaction?.base64 ?? '') ||
  sdkLifecycleFixture.settlement?.accepted !== true ||
  sdkLifecycleFixture.settlement?.replayAccepted !== false
) {
  throw new Error('invalid SDK lifecycle fixture');
}
if (
  hdWalletFixture.version !== 1 ||
  typeof hdWalletFixture.mnemonic !== 'string' ||
  !Array.isArray(hdWalletFixture.vectors) ||
  hdWalletFixture.vectors.length !== 4 ||
  hdWalletFixture.vectors.some((vector) =>
    !['bch:bitcoincash', 'bch:bchtest'].includes(vector.network) ||
    !Number.isInteger(vector.coinType) ||
    ![0, 1].includes(vector.change) ||
    !Number.isInteger(vector.index) ||
    !/^m\/44'\/[0-9]+'\/0'\/[01]\/[0-9]+$/.test(vector.path) ||
    !/^(bitcoincash|bchtest):[qpzry9x8gf2tvdw0s3jn54khce6mua7l]+$/.test(vector.address) ||
    !/^[0-9a-f]{66}$/.test(vector.publicKey),
  )
) {
  throw new Error('invalid HD wallet fixture');
}
if (
  covenantProfilesFixture.version !== 1 ||
  !covenantProfilesFixture.profile ||
  !Array.isArray(covenantProfilesFixture.cases) ||
  covenantProfilesFixture.cases.length !== 6
) {
  throw new Error('invalid covenant profile fixture');
}
const covenantProfile = covenantProfilesFixture.profile;
if (
  covenantProfile.id !== 'x402-bch/recursive-ticket' ||
  covenantProfile.family !== 'recursive-state' ||
  covenantProfile.profileVersion !== 1 ||
  covenantProfile.network !== 'bch:bchtest' ||
  covenantProfile.successorPolicy?.lockingBytecode !== '51' ||
  covenantProfile.successorPolicy?.outputIndex !== 0 ||
  covenantProfile.successorPolicy?.stateTransition !== 'epoch-plus-one' ||
  covenantProfile.successorPolicy?.token !== 'preserve' ||
  covenantProfile.successorPolicy?.value !== 'preserve-minus-fee'
) {
  throw new Error('invalid covenant profile identity');
}
const canonicalJson = (value) => {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(',')}}`;
  }
  return JSON.stringify(value);
};
const sha256Hex = (value) => createHash('sha256').update(value).digest('hex');
const descriptor = {
  id: covenantProfile.id,
  family: covenantProfile.family,
  profileVersion: covenantProfile.profileVersion,
  network: covenantProfile.network,
  constructorParameters: covenantProfile.constructorParameters,
  successorPolicy: covenantProfile.successorPolicy,
};
if (sha256Hex(canonicalJson(descriptor)) !== covenantProfile.descriptorHash) {
  throw new Error('covenant descriptor hash mismatch');
}
if (
  sha256Hex(Buffer.from(covenantProfile.successorPolicy.lockingBytecode, 'hex')) !==
  covenantProfile.lockingBytecodeHash
) {
  throw new Error('covenant locking bytecode hash mismatch');
}
if (sha256Hex(canonicalJson(covenantProfile.successorPolicy)) !== covenantProfile.successorPolicyHash) {
  throw new Error('covenant successor policy hash mismatch');
}
for (const covenantCase of covenantProfilesFixture.cases) {
  if (
    !covenantCase.id ||
    !['accept', 'reject'].includes(covenantCase.expected) ||
    !/^[0-9a-f]{64}$/.test(covenantCase.requestHash) ||
    covenantCase.successorOutputIndex !== 0 ||
    !/^(0|[1-9][0-9]*)$/.test(covenantCase.fee) ||
    !covenantCase.source ||
    !covenantCase.successor ||
    !/^[0-9a-f]+$/.test(covenantCase.source.lockingBytecode) ||
    !/^[0-9a-f]+$/.test(covenantCase.successor.lockingBytecode) ||
    !/^(0|[1-9][0-9]*)$/.test(covenantCase.source.value) ||
    !/^(0|[1-9][0-9]*)$/.test(covenantCase.successor.value) ||
    !/^(0|[1-9][0-9]*)$/.test(covenantCase.source.epoch) ||
    !/^(0|[1-9][0-9]*)$/.test(covenantCase.successor.epoch)
  ) {
    throw new Error(`${covenantCase.id}: invalid covenant transition case`);
  }
  if (covenantCase.expected === 'reject' && typeof covenantCase.errorCode !== 'string') {
    throw new Error(`${covenantCase.id}: rejection error code is required`);
  }
}
if (
  providerTransportFixture.version !== 1 ||
  providerTransportFixture.protocol !== 'electrum-cash-json-rpc' ||
  providerTransportFixture.framing !== 'newline-delimited-json' ||
  !Array.isArray(providerTransportFixture.cases) ||
  providerTransportFixture.cases.length !== 3
) {
  throw new Error('invalid provider transport fixture');
}
for (const providerCase of providerTransportFixture.cases) {
  if (!providerCase.id || typeof providerCase.method !== 'string' || !Array.isArray(providerCase.params) || !providerCase.response) {
    throw new Error(`${providerCase.id ?? 'provider-case'}: invalid provider transport case`);
  }
  if (providerCase.response.id !== 1 || (!('result' in providerCase.response) && !('error' in providerCase.response))) {
    throw new Error(`${providerCase.id}: invalid provider response envelope`);
  }
}
if (
  bchnRpcFixture.version !== 1 ||
  bchnRpcFixture.protocol !== 'bchn-json-rpc' ||
  bchnRpcFixture.transport !== 'http-json-rpc' ||
  !Array.isArray(bchnRpcFixture.cases) ||
  bchnRpcFixture.cases.length !== 3
) {
  throw new Error('invalid BCHN RPC fixture');
}
for (const bchnCase of bchnRpcFixture.cases) {
  if (
    !bchnCase.id ||
    typeof bchnCase.method !== 'string' ||
    !Array.isArray(bchnCase.params) ||
    !bchnCase.response ||
    bchnCase.response.id !== 1 ||
    (!('result' in bchnCase.response) && !('error' in bchnCase.response)) ||
    !bchnCase.expected
  ) {
    throw new Error(`${bchnCase.id ?? 'bchn-case'}: invalid BCHN RPC case`);
  }
  if (bchnCase.method === 'testmempoolaccept' && typeof bchnCase.expected.allowed !== 'boolean') {
    throw new Error(`${bchnCase.id}: invalid testmempoolaccept expectation`);
  }
  if ('errorCode' in bchnCase.expected && !Number.isInteger(bchnCase.expected.errorCode)) {
    throw new Error(`${bchnCase.id}: invalid BCHN RPC error expectation`);
  }
}
if (
  mocknetFixture.version !== 1 ||
  mocknetFixture.network !== 'bch:bchtest' ||
  !Number.isInteger(mocknetFixture.tipHeight) ||
  !/^bchtest:/.test(mocknetFixture.address) ||
  !/^[0-9a-f]+$/.test(mocknetFixture.payerScriptPubKey) ||
  !/^[0-9a-f]+$/.test(mocknetFixture.merchantScriptPubKey) ||
  !Array.isArray(mocknetFixture.initialUtxos) ||
  mocknetFixture.initialUtxos.length !== 2 ||
  !mocknetFixture.spend ||
  !mocknetFixture.conflict
) {
  throw new Error('invalid mocknet fixture');
}
for (const utxo of mocknetFixture.initialUtxos) {
  if (!/^[0-9a-f]{64}$/.test(utxo.txid) || !Number.isInteger(utxo.vout) || !/^(0|[1-9][0-9]*)$/.test(utxo.value) || !/^[0-9a-f]+$/.test(utxo.scriptPubKey)) {
    throw new Error('invalid mocknet initial UTXO');
  }
}
for (const transaction of [mocknetFixture.spend, mocknetFixture.conflict]) {
  if (!/^[0-9a-f]{64}$/.test(transaction.txid) || !/^[0-9a-f]+$/.test(transaction.rawTransaction) || !Array.isArray(transaction.inputs) || !Array.isArray(transaction.outputs)) {
    throw new Error('invalid mocknet transaction');
  }
}
if (
  diagnosticsFixture.version !== 1 ||
  diagnosticsFixture.redactedValue !== '[redacted]' ||
  !Array.isArray(diagnosticsFixture.cases) ||
  diagnosticsFixture.cases.length !== 2
) {
  throw new Error('invalid diagnostics fixture');
}
for (const diagnosticCase of diagnosticsFixture.cases) {
  if (!diagnosticCase.id || !diagnosticCase.stage || !diagnosticCase.code || !diagnosticCase.message || !diagnosticCase.input || !diagnosticCase.expectedContext) {
    throw new Error(`${diagnosticCase.id ?? 'diagnostic-case'}: invalid diagnostics case`);
  }
  for (const [key, value] of Object.entries(diagnosticCase.expectedContext)) {
    if (['transaction', 'rawTransaction', 'mnemonic'].includes(key) && value !== '[redacted]') {
      throw new Error(`${diagnosticCase.id}: sensitive diagnostic context is not redacted`);
    }
  }
}
if (
  httpFlowFixture.version !== 1 ||
  httpFlowFixture.headers?.paymentRequired !== 'PAYMENT-REQUIRED' ||
  httpFlowFixture.headers?.paymentSignature !== 'PAYMENT-SIGNATURE' ||
  httpFlowFixture.headers?.paymentResponse !== 'PAYMENT-RESPONSE' ||
  !/^[A-Za-z0-9+/]+={0,2}$/.test(httpFlowFixture.paymentRequired) ||
  !/^[A-Za-z0-9+/]+={0,2}$/.test(httpFlowFixture.paymentSignature) ||
  !Array.isArray(httpFlowFixture.flow) ||
  httpFlowFixture.flow.length !== 2 ||
  httpFlowFixture.flow[0].status !== 402 ||
  httpFlowFixture.flow[1].status !== 200
) {
  throw new Error('invalid HTTP flow fixture');
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
  const serverRequirementsPath = join(root, packagePath, serverRequirementsFixtureRelativePath);
  const packageServerRequirementsText = await readFile(serverRequirementsPath, 'utf8');
  if (packageServerRequirementsText !== canonicalServerRequirementsText) {
    throw new Error(`${language} server requirements fixture differs from the TypeScript fixture`);
  }
  const packageSdkLifecyclePath = join(root, packagePath, sdkLifecycleFixtureRelativePath);
  const packageSdkLifecycleText = await readFile(packageSdkLifecyclePath, 'utf8');
  if (packageSdkLifecycleText !== canonicalSdkLifecycleText) {
    throw new Error(`${language} SDK lifecycle fixture differs from the TypeScript fixture`);
  }
  const packageHdWalletPath = join(root, packagePath, hdWalletFixtureRelativePath);
  const packageHdWalletText = await readFile(packageHdWalletPath, 'utf8');
  if (packageHdWalletText !== canonicalHdWalletText) {
    throw new Error(`${language} HD wallet fixture differs from the TypeScript fixture`);
  }
  const packageCovenantProfilesPath = join(root, packagePath, covenantProfilesFixtureRelativePath);
  const packageCovenantProfilesText = await readFile(packageCovenantProfilesPath, 'utf8');
  if (packageCovenantProfilesText !== canonicalCovenantProfilesText) {
    throw new Error(`${language} covenant profile fixture differs from the TypeScript fixture`);
  }
  const packageProviderTransportPath = join(root, packagePath, providerTransportFixtureRelativePath);
  const packageProviderTransportText = await readFile(packageProviderTransportPath, 'utf8');
  if (packageProviderTransportText !== canonicalProviderTransportText) {
    throw new Error(`${language} provider transport fixture differs from the TypeScript fixture`);
  }
  const packageBchnRpcPath = join(root, packagePath, bchnRpcFixtureRelativePath);
  const packageBchnRpcText = await readFile(packageBchnRpcPath, 'utf8');
  if (packageBchnRpcText !== canonicalBchnRpcText) {
    throw new Error(`${language} BCHN RPC fixture differs from the TypeScript fixture`);
  }
  const packageMocknetPath = join(root, packagePath, mocknetFixtureRelativePath);
  const packageMocknetText = await readFile(packageMocknetPath, 'utf8');
  if (packageMocknetText !== canonicalMocknetText) {
    throw new Error(`${language} mocknet fixture differs from the TypeScript fixture`);
  }
  const packageDiagnosticsPath = join(root, packagePath, diagnosticsFixtureRelativePath);
  const packageDiagnosticsText = await readFile(packageDiagnosticsPath, 'utf8');
  if (packageDiagnosticsText !== canonicalDiagnosticsText) {
    throw new Error(`${language} diagnostics fixture differs from the TypeScript fixture`);
  }
  const packageHttpFlowPath = join(root, packagePath, httpFlowFixtureRelativePath);
  const packageHttpFlowText = await readFile(packageHttpFlowPath, 'utf8');
  if (packageHttpFlowText !== canonicalHttpFlowText) {
    throw new Error(`${language} HTTP flow fixture differs from the TypeScript fixture`);
  }
  const packageBip39Path = join(root, packagePath, bip39WordListRelativePath);
  const packageBip39Text = await readFile(packageBip39Path, 'utf8');
  if (packageBip39Text !== canonicalBip39Text) throw new Error(`${language} BIP39 wordlist differs from the TypeScript fixture`);
}
console.log(
  `conformance fixtures: ${fixture.cases.length} wire cases + ${cashTokenNegativeFixture.cases.length} negative CashToken cases + ${p2pkhSignatureFixture.cases.length} P2PKH signature cases + ${requestHashFixture.cases.length} request-hash cases + ${p2shCommitmentFixture.cases.length} P2SH commitment cases + ${settlementPolicyFixture.cases.length} settlement-policy cases + ${providerObservationFixture.cases.length} provider-observation cases + ${settlementOutcomeFixture.cases.length} settlement-outcome cases + ${bchVmFixture.cases.length} BCH VM cases + ${settlementIntegrationFixture.cases.length} settlement-integration cases + ${settlementProviderFixture.cases.length} provider-fact settlement cases + ${providerSourceOutputFixture.cases.length} provider source-output cases + ${serverRequirementsFixture.cases.length} server-requirement cases + 1 SDK lifecycle case + ${hdWalletFixture.vectors.length} HD wallet vectors + ${covenantProfilesFixture.cases.length} covenant-profile cases + ${providerTransportFixture.cases.length} provider-transport cases + ${bchnRpcFixture.cases.length} BCHN RPC cases + 1 deterministic mocknet ledger case + ${diagnosticsFixture.cases.length} diagnostics cases + 1 HTTP flow case validated across ${packageFixtures.length} packages`,
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

// TypeScript is the most comprehensive reference suite. Run every test file;
// the conformance cases are included in that full run.
run('npm', ['test'], join(root, 'packages/typescript'));
run('python3', ['tests/run_conformance.py'], join(root, 'packages/python'));
run('python3', ['tests/run_sdk.py'], join(root, 'packages/python'));
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
  if (process.env.X402_REQUIRE_WASM === '1' || process.env.CI === 'true') {
    run(
      cargoCommand,
      ['check', '--manifest-path', 'Cargo.toml', '--locked', '--all-features', '--target', 'wasm32-unknown-unknown'],
      join(root, 'packages/rust'),
    );
  } else {
    console.warn('Rust WASM target check not run locally; set X402_REQUIRE_WASM=1 when the target is installed');
  }
} else {
  console.warn('cargo toolchain unavailable; Rust conformance test not run');
}
