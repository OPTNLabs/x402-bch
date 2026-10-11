import dotenv from 'dotenv';
import { FulcrumProvider, parseTransaction } from '../dist/esm/index.js';

dotenv.config({ path: '.env.local' });

const txid = process.env.BCH_CHIPNET_TXID;
const endpoint = process.env.BCH_CHIPNET_FULCRUM_WSS ?? 'wss://electrum-chipnet.optnlabs.com';
if (!txid) throw new Error('BCH_CHIPNET_TXID is required');

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
const provider = new FulcrumProvider('bch:bchtest', transport);
const status = await provider.getTransactionStatus(txid);
if (status.kind === 'notFound') throw new Error('broadcast transaction was not found');
const raw = await transport.request('blockchain.transaction.get', [txid, false]);
if (typeof raw !== 'string') throw new Error('Fulcrum did not return raw transaction bytes');
const transaction = parseTransaction(Uint8Array.from(Buffer.from(raw, 'hex')));
const inputs = [];
for (const input of transaction.inputs) {
  const source = await provider.getSourceOutput(input.outpoint);
  const sourceStatus = await provider.getOutpointStatus(input.outpoint, source);
  inputs.push({ outpoint: `${input.outpoint.txid}:${input.outpoint.vout}`, status: sourceStatus });
  if (sourceStatus !== 'spent') throw new Error(`input was not spent: ${sourceStatus}`);
}
console.log(JSON.stringify({ txid, status, inputs }));
