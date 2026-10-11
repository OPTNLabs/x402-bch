import { describe, expect, it, vi } from 'vitest';
import { ExactBchScheme } from '../src/exact/client';
import { ExactBchFacilitatorScheme } from '../src/exact/facilitator';
import { ExactBchServerScheme } from '../src/exact/server';
import { hash160, parseTransaction, p2pkhScript, transactionId } from '../src/crypto';
import { createSecp256k1BchSignerFromMnemonic } from '../src/signer';
import type { BchSettlementStore } from '../src/settlementStore';
import type { BchNetwork, BchProvider } from '../src/types';

const NETWORK: BchNetwork = 'bch:bitcoincash';
const BIP39_VECTOR_MNEMONIC =
  'legal winner thank year wave sausage worth useful legal winner thank yellow';
const MERCHANT_ADDRESS = 'bitcoincash:qqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zye3kwllue';
const REQUIREMENTS = {
  scheme: 'exact' as const,
  network: NETWORK,
  asset: 'BCH' as const,
  amount: '1000',
  payTo: MERCHANT_ADDRESS,
  maxTimeoutSeconds: 300,
  extra: { assetTransferMethod: 'native' as const, paymentFlow: 'upfront' as const },
};

function makeProvider(): BchProvider {
  const signer = createSecp256k1BchSignerFromMnemonic(BIP39_VECTOR_MNEMONIC);
  const scriptPubKey = p2pkhScript(hash160(signer.getPublicKey()));
  const utxo = {
    txid: '00'.repeat(32),
    vout: 0,
    value: 100_000n,
    scriptPubKey,
  };
  return {
    network: NETWORK,
    listUtxos: vi.fn(async () => [utxo]),
    getSourceOutput: vi.fn(async () => ({ value: utxo.value, scriptPubKey })),
    getOutpointStatus: vi.fn(async () => 'unspent' as const),
    broadcast: vi.fn(async (raw) => transactionId(parseTransaction(raw))),
    getTransactionStatus: vi.fn(async () => ({ kind: 'confirmed' as const, height: 100 })),
    getTipHeight: vi.fn(async () => 100),
    hasDoubleSpendProof: vi.fn(async () => false),
  };
}

describe('BCH x402 v2 exact scheme', () => {
  it('creates, verifies, and settles a payment through the core scheme interfaces', async () => {
    const provider = makeProvider();
    const signer = createSecp256k1BchSignerFromMnemonic(BIP39_VECTOR_MNEMONIC);
    const client = new ExactBchScheme(signer, provider);
    const facilitator = new ExactBchFacilitatorScheme(provider);

    const created = await client.createPaymentPayload(2, REQUIREMENTS);
    const payload = { ...created, accepted: REQUIREMENTS };
    const verified = await facilitator.verify(payload, REQUIREMENTS);
    const settled = await facilitator.settle(payload, REQUIREMENTS);

    expect(verified).toMatchObject({ isValid: true, payer: signer.getAddress(NETWORK) });
    expect(settled).toMatchObject({
      success: true,
      network: NETWORK,
      payer: signer.getAddress(NETWORK),
    });
    expect(provider.broadcast).toHaveBeenCalledOnce();

    const retried = await facilitator.settle(payload, REQUIREMENTS);
    expect(retried).toMatchObject({
      success: true,
      transaction: settled.transaction,
      payer: signer.getAddress(NETWORK),
    });
    expect(provider.broadcast).toHaveBeenCalledOnce();
  });

  it('declares BCH native upfront pricing and rejects unsupported price assets', async () => {
    const server = new ExactBchServerScheme();

    await expect(server.parsePrice({ amount: '1000', asset: 'BCH' }, NETWORK)).resolves.toEqual({
      amount: '1000',
      asset: 'BCH',
      extra: { assetTransferMethod: 'native', paymentFlow: 'upfront' },
    });
    await expect(
      server.parsePrice({ amount: '1000', asset: 'USD' } as never, NETWORK),
    ).rejects.toThrow('BCH asset must be BCH or a 32-byte CashToken category');

    await expect(
      server.parsePrice(
        {
          amount: '0',
          asset: '11'.repeat(32),
          extra: {
            value: '1000',
            token: { nft: { capability: 'none', commitment: '' } },
          },
        },
        NETWORK,
      ),
    ).resolves.toMatchObject({
      amount: '0',
      asset: '11'.repeat(32),
      extra: { assetTransferMethod: 'cashtoken', value: '1000' },
    });
  });

  it('uses a stable settlement binding across retries', async () => {
    const provider = makeProvider();
    const signer = createSecp256k1BchSignerFromMnemonic(BIP39_VECTOR_MNEMONIC);
    const bindings: string[] = [];
    const settlementStore: BchSettlementStore = {
      claim: vi.fn(async (_txid, binding) => {
        bindings.push(binding);
        return bindings.length === 1 ? 'acquired' : 'same';
      }),
      markAccepted: vi.fn(async () => undefined),
      release: vi.fn(async () => undefined),
    };
    const client = new ExactBchScheme(signer, provider);
    const facilitator = new ExactBchFacilitatorScheme(provider, { settlementStore });
    const created = await client.createPaymentPayload(2, REQUIREMENTS);
    const payload = { ...created, accepted: REQUIREMENTS };

    await facilitator.settle(payload, REQUIREMENTS);
    await facilitator.settle(payload, REQUIREMENTS);

    expect(bindings).toHaveLength(2);
    expect(bindings[0]).toBe(
      '{"accepted":{"amount":"1000","asset":"BCH","extra":{"assetTransferMethod":"native","paymentFlow":"upfront"},"maxTimeoutSeconds":300,"network":"bch:bitcoincash","payTo":"bitcoincash:qqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zye3kwllue","scheme":"exact"},"resource":null}',
    );
    expect(bindings[1]).toBe(bindings[0]);
  });

  it('treats a double-spend proof as conflict evidence in no-double-spend-proof mode', async () => {
    const provider = makeProvider();
    const signer = createSecp256k1BchSignerFromMnemonic(BIP39_VECTOR_MNEMONIC);
    const client = new ExactBchScheme(signer, provider);
    const facilitator = new ExactBchFacilitatorScheme(provider, {
      settlementStrategy: { kind: 'noDoubleSpendProof' },
    });
    const created = await client.createPaymentPayload(2, REQUIREMENTS);
    const payload = { ...created, accepted: REQUIREMENTS };
    vi.mocked(provider.getTransactionStatus).mockResolvedValue({ kind: 'mempool' });
    vi.mocked(provider.hasDoubleSpendProof).mockResolvedValue(true);

    const settled = await facilitator.settle(payload, REQUIREMENTS);

    expect(settled).toMatchObject({ success: false });
    expect(settled.errorReason).toBe('settlement_pending');
  });

  it('recognizes an observed chain transaction after local settlement state is lost', async () => {
    const provider = makeProvider();
    const signer = createSecp256k1BchSignerFromMnemonic(BIP39_VECTOR_MNEMONIC);
    const client = new ExactBchScheme(signer, provider);
    const created = await client.createPaymentPayload(2, REQUIREMENTS);
    const payload = { ...created, accepted: REQUIREMENTS };
    const raw = Buffer.from(payload.payload.transaction, 'base64');

    vi.mocked(provider.getOutpointStatus).mockResolvedValue('spent');
    provider.getTransaction = vi.fn(async () => Uint8Array.from(raw));
    vi.mocked(provider.getTransactionStatus).mockResolvedValue({ kind: 'confirmed', height: 100 });

    const recovered = await new ExactBchFacilitatorScheme(provider).settle(payload, REQUIREMENTS);

    expect(recovered).toMatchObject({
      success: true,
      transaction: transactionId(parseTransaction(raw)),
      payer: signer.getAddress(NETWORK),
    });
    expect(provider.broadcast).not.toHaveBeenCalled();
  });

  it('commits the advertised request hash inside the signed BCH transaction', async () => {
    const provider = makeProvider();
    const signer = createSecp256k1BchSignerFromMnemonic(BIP39_VECTOR_MNEMONIC);
    const requestHash = 'ab'.repeat(32);
    const requirements = {
      ...REQUIREMENTS,
      extra: { ...REQUIREMENTS.extra, requestHash },
    };
    const payload = {
      ...(await new ExactBchScheme(signer, provider).createPaymentPayload(2, requirements)),
      accepted: requirements,
    };
    const facilitator = new ExactBchFacilitatorScheme(provider);

    expect(await facilitator.verify(payload, requirements)).toMatchObject({ isValid: true });
    const tamperedRequirements = {
      ...requirements,
      extra: { ...requirements.extra, requestHash: 'cd'.repeat(32) },
    };
    expect(await facilitator.verify(payload, tamperedRequirements)).toMatchObject({
      isValid: false,
    });
    const transaction = parseTransaction(Buffer.from(payload.payload.transaction, 'base64'));
    expect(
      transaction.outputs.some((output) =>
        Buffer.from(output.scriptPubKey).equals(
          Buffer.from([0x6a, 0x20, ...Buffer.from(requestHash, 'hex')]),
        ),
      ),
    ).toBe(true);
  });
});
