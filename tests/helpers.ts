import http from "node:http";
import type { AddressInfo } from "node:net";

export type TestServer = {
  port: number;
  origin: string;
  close: () => Promise<void>;
};

/** Levanta un servidor HTTP local en un puerto libre. */
export function startServer(
  handler: http.RequestListener,
): Promise<TestServer> {
  return new Promise((resolve) => {
    const server = http.createServer(handler);

    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address() as AddressInfo;

      resolve({
        port,
        origin: `http://127.0.0.1:${port}`,
        close: () =>
          new Promise((done) => {
            server.closeAllConnections();
            server.close(() => done());
          }),
      });
    });
  });
}

/** Política para tests: permite solo el loopback 127.0.0.1. */
export const loopbackOnly = (address: string) => address === "127.0.0.1";
