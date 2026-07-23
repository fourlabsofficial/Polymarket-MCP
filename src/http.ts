/**
 * HTTP transport with OAuth 2.0 + Dynamic Client Registration.
 * Serves MCP endpoint + OAuth endpoints.
 */

import { createServer, IncomingMessage, ServerResponse } from "node:http";
import { parse as parseUrl } from "node:url";
import { randomUUID } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { OauthServer } from "./oauth.js";

const SESSION_ID_HEADER = "mcp-session-id";
const PROTOCOL_VERSION = "2025-03-26";

export type HttpOptions = {
  port: number;
  host?: string;
  path?: string;
  oauth: OauthServer;
};

export async function startHttp(buildServerFn: () => Promise<McpServer>, opts: HttpOptions): Promise<{ close: () => Promise<void> }> {
  const host = opts.host ?? "127.0.0.1";
  const mcpPath = opts.path ?? "/mcp";
  const transports = new Map<string, StreamableHTTPServerTransport>();

  const httpServer = createServer(async (req, res) => {
    if (req.method === "OPTIONS") {
      res.writeHead(204, {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": `Content-Type, ${SESSION_ID_HEADER}, Authorization`,
        "Access-Control-Max-Age": "86400",
      });
      res.end();
      return;
    }
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Expose-Headers", SESSION_ID_HEADER);

    const url = req.url || "";

    if (url === "/health") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({
        status: "ok",
        protocol: PROTOCOL_VERSION,
        sessions: transports.size,
        oauth: opts.oauth.isReady(),
      }));
      return;
    }

    if (url === "/.well-known/oauth-authorization-server") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(opts.oauth.metadata()));
      return;
    }

    if (url.startsWith("/oauth/")) {
      try {
        if (url === "/oauth/register") await opts.oauth.handleRegister(req, res);
        else if (url.startsWith("/oauth/authorize")) await opts.oauth.handleAuthorize(req, res);
        else if (url === "/oauth/token") await opts.oauth.handleToken(req, res);
        else if (url === "/oauth/revoke") await opts.oauth.handleRevoke(req, res);
        else if (url === "/oauth/polymarket-callback") {
          // Handle Polymarket's redirect back to us with their code
          res.writeHead(200, { "Content-Type": "text/html" });
          res.end("<h1>Polymarket login received</h1><p>Processing...</p>");
        }
        else { res.writeHead(404); res.end(); }
      } catch (e: any) {
        if (!res.headersSent) res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "internal", message: e?.message }));
      }
      return;
    }

    if (url === "/" || url === "/setup") {
      res.writeHead(200, { "Content-Type": "text/html" });
      res.end(`<!doctype html><html><body style="font-family:system-ui;max-width:600px;margin:2rem auto;padding:0 1rem">
<h1>Polymarket MCP</h1>
<p>One-click setup. In your MCP client (Claude, Cursor, Hermes, etc.), add this server:</p>
<pre>URL: http://${host}:${opts.port}/mcp</pre>
<p>It will use OAuth 2.0 + PKCE to authenticate you via Polymarket.com. Your private key never leaves Polymarket.</p>
</body></html>`);
      return;
    }

    if (url.startsWith(mcpPath)) {
      // Verify Bearer token
      const authz = req.headers.authorization || "";
      const m = authz.match(/^Bearer\s+(.+)$/i);
      if (!m) {
        res.writeHead(401, {
          "Content-Type": "application/json",
          "WWW-Authenticate": `Bearer realm="polymarket-mcp", resource_metadata="http://${host}:${opts.port}/.well-known/oauth-authorization-server"`,
        });
        res.end(JSON.stringify({ error: "unauthorized", hint: "OAuth required — see /.well-known/oauth-authorization-server" }));
        return;
      }
      const claims = opts.oauth.verifyAccessToken(m[1]);
      if (!claims) {
        res.writeHead(401, { "Content-Type": "application/json", "WWW-Authenticate": `Bearer error="invalid_token"` });
        res.end(JSON.stringify({ error: "invalid_token" }));
        return;
      }

      const sessionId = req.headers[SESSION_ID_HEADER.toLowerCase()] as string | undefined;
      let transport: StreamableHTTPServerTransport | undefined;

      if (sessionId && transports.has(sessionId)) {
        transport = transports.get(sessionId)!;
      } else if (req.method === "POST" && !sessionId) {
        transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
          onsessioninitialized: (id) => {
            transports.set(id, transport!);
            res.setHeader(SESSION_ID_HEADER, id);
          },
        });
        transport.onclose = () => { if (transport?.sessionId) transports.delete(transport.sessionId); };
        const sessionServer = await buildServerFn();
        await sessionServer.connect(transport);
      } else {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "missing_session_id" }));
        return;
      }

      try {
        const body = req.method === "POST" ? await readBodyJson(req) : undefined;
        await transport.handleRequest(req as IncomingMessage, res as ServerResponse, body);
      } catch (err: any) {
        if (!res.headersSent) res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "internal", message: err?.message }));
      }
      return;
    }

    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "not_found" }));
  });

  await new Promise<void>((r) => httpServer.listen(opts.port, host, r));
  console.error(`[polymarket-mcp] http://${host}:${opts.port}${mcpPath}`);
  console.error(`[polymarket-mcp] OAuth: /.well-known/oauth-authorization-server`);
  return {
    async close() {
      await new Promise<void>((r) => httpServer.close(() => r()));
      for (const t of transports.values()) await t.close();
      transports.clear();
    },
  };
}

function readBodyJson(req: IncomingMessage): Promise<unknown> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c as Buffer));
    req.on("end", () => {
      if (chunks.length === 0) return resolve(undefined);
      try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf8"))); } catch { resolve(undefined); }
    });
    req.on("error", () => resolve(undefined));
  });
}