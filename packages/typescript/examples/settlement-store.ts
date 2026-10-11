import { InMemoryBchSettlementStore } from '../src/settlementStore.js';

/** Demonstrate idempotent settlement claims and conflicting request bindings. */
export async function settlementClaimLifecycle() {
  const store = new InMemoryBchSettlementStore();
  const txid = 'aa'.repeat(32);
  const first = await store.claim(txid, 'resource:/weather|request:1');
  const retry = await store.claim(txid, 'resource:/weather|request:1');
  const conflict = await store.claim(txid, 'resource:/other|request:2');
  await store.markAccepted(txid);
  return { first, retry, conflict };
}
