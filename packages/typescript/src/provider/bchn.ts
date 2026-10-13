export interface BchNodeRpc {
  request(method: string, params: unknown[]): Promise<unknown>;
}

export type BchnRpcTransportOptions = {
  url: string;
  timeoutMs?: number;
  headers?: Record<string, string>;
};

/** Direct BCHN JSON-RPC over HTTP(S). Credentials and endpoint policy remain caller-owned. */
export class BchnRpcTransport implements BchNodeRpc {
  private readonly url: string;
  private readonly timeoutMs: number;
  private readonly headers: Record<string, string>;

  constructor(options: BchnRpcTransportOptions) {
    if (!options.url.startsWith('http://') && !options.url.startsWith('https://')) {
      throw new Error('BCHN RPC URL must use http:// or https://');
    }
    if (options.timeoutMs !== undefined && options.timeoutMs <= 0) {
      throw new Error('BCHN RPC timeout must be positive');
    }
    this.url = options.url;
    this.timeoutMs = options.timeoutMs ?? 10_000;
    this.headers = { 'content-type': 'application/json', ...options.headers };
  }

  async request(method: string, params: unknown[]): Promise<unknown> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await fetch(this.url, {
        method: 'POST',
        headers: this.headers,
        body: JSON.stringify({ jsonrpc: '1.0', id: 1, method, params }),
        signal: controller.signal,
      });
      const body = (await response.json()) as {
        result?: unknown;
        error?: { code?: number; message?: string } | null;
      };
      if (!response.ok) throw new Error(`BCHN RPC HTTP status ${response.status}`);
      if (body.error !== undefined && body.error !== null) {
        throw new Error(
          `BCHN RPC error (${body.error.code ?? -1}): ${body.error.message ?? 'unknown error'}`,
        );
      }
      if (!('result' in body)) throw new Error('BCHN RPC response is missing result');
      return body.result;
    } finally {
      clearTimeout(timeout);
    }
  }
}

export type BchnMempoolResult = { allowed: boolean; reason: string | null; txid?: string };

/** Normalize BCHN's testmempoolaccept result for facilitator script validation. */
export async function testMempoolAccept(
  rpc: BchNodeRpc,
  rawTransaction: Uint8Array,
): Promise<BchnMempoolResult> {
  const result = await rpc.request('testmempoolaccept', [[bytesToHex(rawTransaction)]]);
  if (
    !Array.isArray(result) ||
    result.length !== 1 ||
    !result[0] ||
    typeof result[0] !== 'object'
  ) {
    throw new Error('BCHN testmempoolaccept response is malformed');
  }
  const entry = result[0] as { allowed?: unknown; ['reject-reason']?: unknown; txid?: unknown };
  if (typeof entry.allowed !== 'boolean')
    throw new Error('BCHN testmempoolaccept result has no allowed flag');
  return {
    allowed: entry.allowed,
    reason: typeof entry['reject-reason'] === 'string' ? entry['reject-reason'] : null,
    ...(typeof entry.txid === 'string' ? { txid: entry.txid.toLowerCase() } : {}),
  };
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('');
}
