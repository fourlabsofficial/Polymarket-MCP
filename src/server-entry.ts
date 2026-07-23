/**
 * Main entry. Wires HTTP server, OAuth, WebSocket, MCP server.
 *
 * Usage:
 *   npx polymarket-mcp start          # Start HTTP server on :7842
 *   npx polymarket-mcp serve --stdio  # Start stdio server (for direct MCP)
 */

import { startHttp } from "./http.js";
import { buildServer } from "./server.js";
import { PolymarketWsManager } from "./ws-manager.js";
import { OauthServer } from "./oauth.js";
import { credentialsMeta, hasCredentials } from "./credentials.js";

async function main() {
  const args = process.argv.slice(2);
  const cmd = args[0] || "start";

  if (cmd === "setup") {
    const { runSetup } = await import("./cli.js");
    await runSetup();
    return;
  }
  if (cmd === "install" || cmd === "uninstall" || cmd === "status") {
    const { installClient, uninstallClient, showStatus } = await import("./cli.js");
    if (cmd === "status") { await showStatus(); return; }
    const client = args[1] || "all";
    if (cmd === "install") {
      const result = await installClient(client as any);
      console.log(result.ok ? `✓ ${result.message}` : `✗ ${result.message}`);
      if (result.path && result.path !== "multiple") console.log(`  ${result.path}`);
    } else {
      const result = await uninstallClient(client as any);
      console.log(result.ok ? `✓ ${result.message}` : `✗ ${result.message}`);
    }
    return;
  }

  if (cmd === "serve") {
  // Stdio mode for direct MCP
  const { StdioServerTransport } = await import("@modelcontextprotocol/sdk/server/stdio.js");
  const ws = new PolymarketWsManager();
  await ws.start();
  const oauth = new OauthServer({ host: "127.0.0.1", port: 0 });
  const server = await buildServer(ws, { host: "127.0.0.1", port: 0, oauth });
  const transport = new StdioServerTransport();
  await server.connect(transport);
    console.error("[polymarket-mcp] stdio ready");
    process.on("SIGINT", async () => { await ws.stop(); process.exit(0); });
    return;
  }

  if (cmd === "start" || cmd === "serve-http") {
    const port = Number(args.find((a) => a.startsWith("--port="))?.split("=")[1] ?? 7842);
    const host = "127.0.0.1";
    const oauth = new OauthServer({ host, port });
    const ws = new PolymarketWsManager();
    await ws.start().catch((e) => console.error("[ws] error:", e?.message));
    await startHttp(async () => buildServer(ws, { host, port, oauth }), { port, host, oauth });
    const meta = credentialsMeta();
    console.error(`[polymarket-mcp] credentials: ${hasCredentials() ? "configured" : "not configured (run install + open browser to set up)"}`);
    if (meta.configured) console.error(`[polymarket-mcp] user: ${meta.userId?.slice(0, 10) ?? "?"}`);
    console.error(`[polymarket-mcp] ready. install command examples:`);
    console.error(`  npx polymarket-mcp install claude`);
    console.error(`  npx polymarket-mcp install cursor`);
    console.error(`  npx polymarket-mcp install hermes`);
    process.on("SIGINT", async () => { await ws.stop(); process.exit(0); });
    return;
  }

  console.log(`polymarket-mcp commands:
  install <client>     Add to Claude/Cursor/Hermes/etc (claude, cursor, hermes, openai, cline, all)
  uninstall <client>   Remove
  status               Show install status
  setup                One-time browser-based OAuth setup
  start                Start HTTP server on :7842
  serve --stdio        Stdio server
`);
}

main().catch((e) => { console.error("[polymarket-mcp] fatal:", e); process.exit(1); });