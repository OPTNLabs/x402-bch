import dotenv from 'dotenv';
import {
  ExactBchFacilitatorScheme,
  ExactBchScheme,
  FulcrumProvider,
  createSecp256k1BchSignerFromMnemonic,
  deriveBchWalletAddress,
  parseTransaction,
  transactionId,
} from '../dist/esm/index.js';

dotenv.config({ path: '.env.local' });

const network = 'bch:bchtest';
const endpoint = process.env.BCH_CHIPNET_FULCRUM_WSS ?? 'wss://electrum-chipnet.optnlabs.com';
const mnemonic = process.env.BCH_CHIPNET_MNEMONIC;

if (typeof mnemonic !== 'string' || mnemonic.trim().length === 0) {
  throw new Error('BCH_CHIPNET_MNEMONIC is required in .env.local');
}

class WebSocketFulcrumTransport {
  nextId = 1;

  constructor(url) {
    this.url = url;
  }

  request(method, params) {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const socket = new WebSocket(this.url);
      const timeout = setTimeout(() => {
        socket.close();
        reject(new Error(`Fulcrum request timed out: ${method}`));
      }, 30_000);
      socket.addEventListener('open', () => {
        socket.send(JSON.stringify({ jsonrpc: '2.0', id, method, params }));
      });
      socket.addEventListener('message', (event) => {
        let response;
        try {
          response = JSON.parse(String(event.data));
        } catch {
          return;
        }
        if (response.id !== id) return;
        clearTimeout(timeout);
        socket.close();
        if (response.error) reject(new Error(JSON.stringify(response.error)));
        else resolve(response.result);
      });
      socket.addEventListener('error', () => {
        clearTimeout(timeout);
        reject(new Error(`Fulcrum WebSocket error during ${method}`));
      });
    });
  }
}

const transport = new WebSocketFulcrumTransport(endpoint);
const provider = new FulcrumProvider(network, transport);
const receive = deriveBchWalletAddress(mnemonic, network, 0, 0, { coinType: 1 });
const change = deriveBchWalletAddress(mnemonic, network, 1, 0, { coinType: 1 });
const signer = createSecp256k1BchSignerFromMnemonic(mnemonic, {
  coinType: 1,
  changeIndex: 0,
  addressIndex: 0,
});

if (receive.path !== "m/44'/1'/0'/0/0") throw new Error('unexpected receive derivation path');
if (change.path !== "m/44'/1'/0'/1/0") throw new Error('unexpected change derivation path');

const before = await provider.listUtxos(receive.address);
if (before.length === 0) throw new Error(`no Chipnet UTXOs available at ${receive.address}`);

const nativeUtxos = before
  .filter((utxo) => utxo.token === undefined)
  .sort((left, right) => (left.value < right.value ? -1 : left.value > right.value ? 1 : 0));
if (nativeUtxos.length === 0) throw new Error('no native BCH Chipnet UTXO available');

const requirements = {
  scheme: 'exact',
  network,
  amount: '546',
  asset: 'BCH',
  payTo: change.address,
  maxTimeoutSeconds: 300,
  extra: { assetTransferMethod: 'native', paymentFlow: 'upfront' },
};
const client = new ExactBchScheme(signer, provider);
const payload = {
  ...(await client.createPaymentPayload(2, requirements)),
  accepted: requirements,
};
const raw = Buffer.from(payload.payload.transaction, 'base64');
const transaction = parseTransaction(raw);
const txidBeforeBroadcast = transactionId(transaction);
const input = transaction.inputs.find((candidate) =>
  nativeUtxos.some(
    (utxo) => candidate.outpoint.txid === utxo.txid && candidate.outpoint.vout === utxo.vout,
  ),
);
if (input === undefined) throw new Error('client did not select a discovered native BCH UTXO');
const source = nativeUtxos.find(
  (utxo) => input.outpoint.txid === utxo.txid && input.outpoint.vout === utxo.vout,
);
if (source === undefined) throw new Error('selected source UTXO disappeared during test setup');

const facilitator = new ExactBchFacilitatorScheme(provider, {
  settlementStrategy: { kind: 'confirmations', count: 1 },
});
const result = await facilitator.settle(payload, requirements);
if (!result.success && !result.errorReason?.startsWith('settlement_pending:')) {
  throw new Error(`Chipnet settlement failed: ${result.errorReason}`);
}
const txid = result.success
  ? result.transaction
  : result.errorReason.slice('settlement_pending:'.length);
if (txid !== txidBeforeBroadcast) {
  throw new Error('facilitator returned a transaction ID different from the signed transaction');
}

const status = await provider.getTransactionStatus(txid);
const spent = await provider.getOutpointStatus(source, await provider.getSourceOutput(source));
if (status.kind !== 'mempool' && status.kind !== 'confirmed') {
  throw new Error(`broadcast transaction was not found: ${status.kind}`);
}
if (spent !== 'spent') throw new Error(`source UTXO was not marked spent: ${spent}`);

console.log(
  JSON.stringify({
    network,
    derivation: { receive: receive.path, change: change.path },
    source: `${source.txid}:${source.vout}`,
    txid,
    status,
    sourceStatus: spent,
  }),
);
