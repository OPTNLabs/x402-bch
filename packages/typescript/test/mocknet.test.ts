import { describe, expect, it } from 'vitest';
import { MocknetProvider } from '../src/mocknet';

const payerScript = Uint8Array.from(
  Buffer.from('76a914111111111111111111111111111111111111111188ac', 'hex'),
);
const merchantScript = Uint8Array.from(
  Buffer.from('76a914333333333333333333333333333333333333333388ac', 'hex'),
);
const address = 'bchtest:qqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyarjfagm9';
const input = { txid: '1'.repeat(64), vout: 0, value: 5000n, scriptPubKey: payerScript };

describe('deterministic mocknet provider', () => {
  it('tracks UTXOs, authoritative outputs, and duplicate-spend rejection', async () => {
    const provider = new MocknetProvider('bch:bchtest', [input], 200);
    provider.registerTransaction({
      txid: '3'.repeat(64),
      rawTransaction: Uint8Array.from([1, 2, 3]),
      inputs: [{ txid: input.txid, vout: input.vout }],
      outputs: [
        { value: 1000n, scriptPubKey: merchantScript },
        { value: 3700n, scriptPubKey: payerScript },
      ],
    });
    await expect(provider.listUtxos(address)).resolves.toHaveLength(1);
    await expect(provider.broadcast(Uint8Array.from([1, 2, 3]))).resolves.toBe('3'.repeat(64));
    await expect(provider.getOutpointStatus(input)).resolves.toBe('spent');
    await expect(
      provider.getSourceOutput({ txid: '3'.repeat(64), vout: 0 }),
    ).resolves.toMatchObject({ value: 1000n });
    await expect(provider.broadcast(Uint8Array.from([1, 2, 3]))).resolves.toBe('3'.repeat(64));
    await expect(provider.broadcast(Uint8Array.from([4, 5, 6]))).rejects.toThrow('not registered');
  });
});
