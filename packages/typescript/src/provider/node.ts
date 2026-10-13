import { createConnection, type Socket } from 'node:net';
import { connect as connectTls, type TLSSocket } from 'node:tls';
import type { FulcrumTransport } from '../provider';

export type FulcrumSocketOptions = {
  host: string;
  port: number;
  timeoutMs?: number;
  tls?: boolean;
  servername?: string;
};

type SocketLike = Socket | TLSSocket;

/** Concrete one-request-per-connection Electrum Cash JSON-RPC transport for Node. */
export class FulcrumSocketTransport implements FulcrumTransport {
  private readonly options: Required<Omit<FulcrumSocketOptions, 'servername'>> & {
    servername?: string;
  };

  constructor(options: FulcrumSocketOptions) {
    if (
      !options.host ||
      !Number.isInteger(options.port) ||
      options.port < 1 ||
      options.port > 65535
    ) {
      throw new Error('Fulcrum host and port are required');
    }
    this.options = {
      host: options.host,
      port: options.port,
      timeoutMs: options.timeoutMs ?? 10_000,
      tls: options.tls ?? false,
      servername: options.servername,
    };
    if (this.options.timeoutMs <= 0) throw new Error('Fulcrum timeout must be positive');
  }

  request(method: string, params: unknown[]): Promise<unknown> {
    return new Promise((resolve, reject) => {
      let settled = false;
      let buffer = '';
      const finish = (error?: Error, value?: unknown) => {
        if (settled) return;
        settled = true;
        if (error) reject(error);
        else resolve(value);
      };
      const onConnect = (socket: SocketLike) => {
        socket.setTimeout(this.options.timeoutMs, () => {
          socket.destroy();
          finish(new Error('Fulcrum request timed out'));
        });
        socket.on('error', (error) => finish(error));
        socket.on('data', (chunk: Buffer | string) => {
          buffer += chunk.toString();
          const newline = buffer.indexOf('\n');
          if (newline < 0) return;
          const line = buffer.slice(0, newline).trim();
          try {
            const response = JSON.parse(line) as {
              result?: unknown;
              error?: { code?: number; message?: string } | null;
            };
            if (response.error !== undefined && response.error !== null) {
              finish(
                new Error(
                  `Fulcrum RPC error (${response.error.code ?? -1}): ${response.error.message ?? 'unknown error'}`,
                ),
              );
            } else {
              finish(undefined, response.result);
            }
          } catch (error) {
            finish(error instanceof Error ? error : new Error(String(error)));
          } finally {
            socket.end();
          }
        });
        socket.write(`${JSON.stringify({ id: 1, method, params })}\n`);
      };
      let socket: SocketLike;
      socket = this.options.tls
        ? connectTls(
            {
              host: this.options.host,
              port: this.options.port,
              servername: this.options.servername ?? this.options.host,
            },
            function onTlsConnect() {
              onConnect(socket);
            },
          )
        : createConnection(
            { host: this.options.host, port: this.options.port },
            function onTcpConnect() {
              onConnect(socket);
            },
          );
      socket.on('error', (error) => finish(error));
    });
  }
}
