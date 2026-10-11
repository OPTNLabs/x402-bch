import { describe, expect, it } from 'vitest';
import { InMemoryBchSettlementStore } from '../src/settlementStore';

describe('in-memory settlement store', () => {
  it('supports first claim, same-request retry, and conflicting request rejection', async () => {
    const store = new InMemoryBchSettlementStore();
    const txid = 'aa'.repeat(32);

    await expect(store.claim(txid, 'request-a')).resolves.toBe('acquired');
    await expect(store.claim(txid, 'request-a')).resolves.toBe('same');
    await expect(store.claim(txid, 'request-b')).resolves.toBe('conflict');
  });

  it('releases an unaccepted claim but retains an accepted claim', async () => {
    const store = new InMemoryBchSettlementStore();
    const firstTxid = 'bb'.repeat(32);
    const secondTxid = 'cc'.repeat(32);

    await store.claim(firstTxid, 'request-a');
    await store.release(firstTxid);
    await expect(store.claim(firstTxid, 'request-b')).resolves.toBe('acquired');

    await store.claim(secondTxid, 'request-a');
    await store.markAccepted(secondTxid);
    await store.release(secondTxid);
    await expect(store.claim(secondTxid, 'request-b')).resolves.toBe('conflict');
  });
});
