import { describe, expect, it } from 'vitest';
import { requestHash, validatePaymentPayload, validateRequirements } from '../src/protocol';
import {
  decodeCashAddrScript,
  assertRequestHashCommitment,
  bytesToHex,
  hexToBytes,
  parseTransaction,
  serializeTransaction,
  signingHash,
  verifyP2shRedeemScript,
  verifyP2pkhInput,
  verifyPayment,
} from '../src/crypto';
import type { ExactBchPaymentPayload, ExactBchRequirements } from '../src/types';
import capabilityFixture from '../spec/conformance/v1/cashtoken-capabilities.json';
import negativeFixture from '../spec/conformance/v1/cashtoken-negative.json';
import nftFixture from '../spec/conformance/v1/cashtoken-nft.json';
import signatureFixture from '../spec/conformance/v1/p2pkh-signature.json';
import requestHashFixture from '../spec/conformance/v1/request-hash.json';
import p2shCommitmentFixture from '../spec/conformance/v1/p2sh-commitment.json';

const requirements = {
  x402Version: 2,
  scheme: 'exact',
  network: 'bch:bchtest',
  asset: 'BCH',
  amount: '1000',
  payTo: 'bchtest:merchant',
  maxTimeoutSeconds: 300,
  extra: {
    assetTransferMethod: 'native',
    paymentFlow: 'upfront',
    requestHash: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  },
} as ExactBchRequirements;

describe('shared x402 BCH protocol core', () => {
  it('validates requirements and the actual x402 payload shape', () => {
    validateRequirements(requirements);
    const payload = {
      x402Version: 2,
      accepted: requirements,
      payload: { transaction: 'AQID' },
    } as ExactBchPaymentPayload;
    validatePaymentPayload(payload, requirements);
    expect(() =>
      validatePaymentPayload(
        {
          ...payload,
          accepted: {
            ...requirements,
            extra: {
              ...requirements.extra,
              requestHash: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            },
          },
        },
        requirements,
      ),
    ).toThrow('accepted requirements mismatch: extra');
    expect(() =>
      validatePaymentPayload({ ...payload, payload: { transaction: '!!!!' } }, requirements),
    ).toThrow();
  });

  it('shares the canonical request commitment', () => {
    expect(requestHash('{"url":"https://example.test/resource"}')).toBe(
      '1f3a0cf475878c9cd4664f6812ac05722e1de2a0d00d341b9ae72cbc48e9a675',
    );
  });

  it('verifies the shared CashToken NFT transaction fixture', () => {
    const transaction = parseTransaction(hexToBytes(nftFixture.rawTransaction));
    const merchant = decodeCashAddrScript(nftFixture.payTo, nftFixture.network);
    const commitment = hexToBytes(nftFixture.sourceToken.nft.commitment);
    const target = {
      kind: 'cashtoken' as const,
      category: nftFixture.asset,
      amount: 0n,
      merchantValue: BigInt(nftFixture.value),
      nft: { capability: 'none' as const, commitment },
    };
    const result = verifyPayment(
      transaction,
      [
        {
          value: BigInt(nftFixture.sourceValue),
          scriptPubKey: hexToBytes(nftFixture.sourceScriptPubKey),
          token: { category: nftFixture.asset, amount: 0n, nft: target.nft },
        },
      ],
      nftFixture.network,
      merchant.scriptPubKey,
      target,
    );
    expect(merchant.tokenSupport).toBe(true);
    expect(result.txid).toBe(nftFixture.txid);
    expect(result.fee).toBe(BigInt(nftFixture.fee));
    expect(serializeTransaction(transaction).length).toBe(nftFixture.serializedSize);
  });

  for (const fixture of capabilityFixture.cases) {
    it(`verifies the shared ${fixture.capability} NFT capability fixture`, () => {
      const transaction = parseTransaction(hexToBytes(fixture.rawTransaction));
      const merchant = decodeCashAddrScript(fixture.payTo, fixture.network);
      const commitment = hexToBytes(fixture.sourceToken.nft.commitment);
      const capability = fixture.capability as 'mutable' | 'minting';
      const target = {
        kind: 'cashtoken' as const,
        category: fixture.asset,
        amount: 0n,
        merchantValue: BigInt(fixture.value),
        nft: { capability, commitment },
      };
      const result = verifyPayment(
        transaction,
        [
          {
            value: BigInt(fixture.sourceValue),
            scriptPubKey: hexToBytes(fixture.sourceScriptPubKey),
            token: { category: fixture.asset, amount: 0n, nft: target.nft },
          },
        ],
        fixture.network,
        merchant.scriptPubKey,
        target,
      );
      expect(merchant.tokenSupport).toBe(true);
      expect(result.txid).toBe(fixture.txid);
      expect(result.fee).toBe(BigInt(fixture.fee));
      expect(serializeTransaction(transaction).length).toBe(fixture.serializedSize);
    });
  }
  for (const fixture of negativeFixture.cases) {
    it(`rejects the shared negative case ${fixture.id}`, () => {
      if (fixture.kind === 'parse') {
        expect(() => parseTransaction(hexToBytes(fixture.rawTransaction))).toThrow();
        return;
      }
      const transaction = parseTransaction(hexToBytes(fixture.rawTransaction));
      const target = {
        kind: 'cashtoken' as const,
        category: fixture.asset,
        amount: BigInt(fixture.amount),
        merchantValue: BigInt(fixture.merchantValue),
      };
      expect(() =>
        verifyPayment(
          transaction,
          [
            {
              value: BigInt(fixture.sourceValue),
              scriptPubKey: hexToBytes(fixture.sourceScriptPubKey),
              token: { category: fixture.asset, amount: BigInt(fixture.sourceToken.amount) },
            },
          ],
          fixture.network,
          hexToBytes(fixture.merchantScriptPubKey),
          target,
        ),
      ).toThrow();
    });
  }
  for (const fixture of signatureFixture.cases) {
    it(`${fixture.expected === 'accept' ? 'verifies' : 'rejects'} the shared P2PKH signature case ${fixture.id}`, () => {
      const transaction = parseTransaction(hexToBytes(fixture.rawTransaction));
      const source = {
        value: BigInt(fixture.sourceValue),
        scriptPubKey: hexToBytes(fixture.sourceScriptPubKey),
      };
      expect(bytesToHex(signingHash(transaction, fixture.inputIndex, source))).toBe(
        fixture.expectedSighash,
      );
      const verify = () => verifyP2pkhInput(transaction, fixture.inputIndex, source);
      if (fixture.expected === 'accept') {
        expect(bytesToHex(verify())).toBe(fixture.expectedPayerHash);
      } else {
        expect(verify).toThrow();
      }
    });
  }
  for (const fixture of requestHashFixture.cases) {
    it(`${fixture.expected === 'accept' ? 'accepts' : 'rejects'} the shared request-hash case ${fixture.id}`, () => {
      const transaction = parseTransaction(hexToBytes(fixture.rawTransaction));
      const assertCommitment = () => assertRequestHashCommitment(transaction, fixture.requestHash);
      if (fixture.expected === 'accept') expect(assertCommitment).not.toThrow();
      else expect(assertCommitment).toThrow();
    });
  }
  for (const fixture of p2shCommitmentFixture.cases) {
    it(`${fixture.expected === 'accept' ? 'accepts' : 'rejects'} the shared P2SH commitment case ${fixture.id}`, () => {
      const transaction = parseTransaction(hexToBytes(fixture.rawTransaction));
      const verify = () =>
        verifyP2shRedeemScript(transaction, fixture.inputIndex, {
          value: BigInt(fixture.sourceValue),
          scriptPubKey: hexToBytes(fixture.sourceScriptPubKey),
        });
      if (fixture.expected === 'accept') expect(verify).not.toThrow();
      else expect(verify).toThrow();
    });
  }
});
