import { createServer } from 'node:net';
import { describe, expect, it } from 'vitest';
import { FulcrumSocketTransport } from '../src/provider/node';

describe('Node Fulcrum transport', () => {
  it('round-trips a newline-delimited JSON-RPC request', async () => {
    const server = createServer((socket) => {
      socket.once('data', (data) => {
        expect(data.toString()).toContain('"method":"server.version"');
        socket.end('{"id":1,"result":["fulcrum-test","1.0"]}\n');
      });
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    try {
      const address = server.address();
      if (!address || typeof address === 'string') throw new Error('server did not expose a port');
      const result = await new FulcrumSocketTransport({
        host: '127.0.0.1',
        port: address.port,
      }).request('server.version', ['x402-bch', '1.0']);
      expect(result).toEqual(['fulcrum-test', '1.0']);
    } finally {
      await new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
    }
  });
});
