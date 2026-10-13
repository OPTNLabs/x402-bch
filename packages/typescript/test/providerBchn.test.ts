import { createServer } from 'node:http';
import { describe, expect, it } from 'vitest';
import { BchnRpcTransport, testMempoolAccept } from '../src/provider/bchn';

describe('BCHN JSON-RPC transport', () => {
  it('maps testmempoolaccept through a local HTTP node', async () => {
    const server = createServer(async (request, response) => {
      let body = '';
      for await (const chunk of request) body += chunk;
      const parsed = JSON.parse(body) as { method: string };
      expect(parsed.method).toBe('testmempoolaccept');
      response.setHeader('content-type', 'application/json');
      response.end(
        JSON.stringify({
          result: [{ txid: 'A'.repeat(64), allowed: false, 'reject-reason': 'script-failed' }],
        }),
      );
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('missing test server address');
    try {
      const rpc = new BchnRpcTransport({ url: `http://127.0.0.1:${address.port}/` });
      await expect(testMempoolAccept(rpc, new Uint8Array([1, 2, 3]))).resolves.toEqual({
        allowed: false,
        reason: 'script-failed',
        txid: 'a'.repeat(64),
      });
    } finally {
      await new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
    }
  });
});
