import { FailoverFulcrumTransport, FulcrumProvider } from '../src/provider.js';

export function createChipnetProvider(
  primary: (method: string, params: unknown[]) => Promise<unknown>,
  secondary: (method: string, params: unknown[]) => Promise<unknown>,
) {
  const transport = new FailoverFulcrumTransport([{ request: primary }, { request: secondary }]);
  return new FulcrumProvider('bch:bchtest', transport);
}

// Failover is availability handling only. Applications should still compare
// independent chain state before making high-value settlement decisions.
