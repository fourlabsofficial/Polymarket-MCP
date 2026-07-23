/**
 * CLI installer — one-click setup for various MCP clients.
 *
 * Usage:
 *   npx polymarket-mcp install claude       # Adds to Claude Desktop config
 *   npx polymarket-mcp install cursor       # Adds to Cursor config
 *   npx polymarket-mcp install openai       # Adds to OpenAI / Codex config
 *   npx polymarket-mcp install hermes       # Adds to Hermes Agent (mcporter)
 *   npx polymarket-mcp install cline        # Adds to Cline config
 *   npx polymarket-mcp install all          # All of the above
 *   npx polymarket-mcp uninstall <client>   # Remove
 *   npx polymarket-mcp setup                # Browser OAuth flow
 *   npx polymarket-mcp status               # Show install status
 */

import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { exec, spawn } from "node:child_process";
import { promisify } from "node:util";
import os from "node:os";
import http from "node:http";

const execAsync = promisify(exec);

type Client = "claude" | "claude-code" | "cursor" | "openai" | "hermes" | "cline" | "all";

const PATHS: Record<Client, string> = {
  claude: process.platform === "win32"
    ? resolve(os.homedir(), "AppData", "Roaming", "Claude", "claude_desktop_config.json")
    : process.platform === "darwin"
    ? resolve(os.homedir(), "Library", "Application Support", "Claude", "claude_desktop_config.json")
    : resolve(os.homedir(), ".config", "Claude", "claude_desktop_config.json"),
  "claude-code": process.platform === "win32"
    ? resolve(os.homedir(), ".claude.json")
    : resolve(os.homedir(), ".claude.json"),
  cursor: process.platform === "win32"
    ? resolve(os.homedir(), "AppData", "Roaming", "Cursor", "User", "mcp.json")
    : process.platform === "darwin"
    ? resolve(os.homedir(), "Library", "Application Support", "Cursor", "User", "mcp.json")
    : resolve(os.homedir(), ".config", "Cursor", "User", "mcp.json"),
  openai: process.platform === "win32"
    ? resolve(os.homedir(), ".codex", "config.toml")
    : resolve(os.homedir(), ".codex", "config.toml"),
  hermes: process.platform === "win32"
    ? resolve(os.homedir(), ".mcporter", "mcporter.json")
    : resolve(os.homedir(), ".mcporter", "mcporter.json"),
  cline: process.platform === "win32"
    ? resolve(os.homedir(), "AppData", "Roaming", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json")
    : process.platform === "darwin"
    ? resolve(os.homedir(), "Library", "Application Support", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json")
    : resolve(os.homedir(), ".config", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"),
  all: "",
};

type McpConfig = { mcpServers: Record<string, any> };
type CodexConfig = { mcp_servers?: Record<string, any> };

function readJson<T>(path: string, fallback: T): T {
  if (!existsSync(path)) return fallback;
  try { return JSON.parse(readFileSync(path, "utf8")); } catch { return fallback; }
}

function writeJson(path: string, data: any) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(data, null, 2), { mode: 0o644 });
}

function buildPolymarketConfig(): any {
  return {
    type: "http",
    url: "http://127.0.0.1:7842/mcp",
    description: "Polymarket MCP — OAuth 2.0, 43 tools, 6 auto-trading strategies. No private key handling.",
  };
}

function buildPolymarketStdioConfig(): any {
  // For clients that don't support HTTP transport, use stdio with wrapper
  return {
    command: "npx",
    args: ["-y", "polymarket-mcp", "serve", "--stdio"],
    env: {},
    description: "Polymarket MCP — auto-installs via npx, no private key handling.",
  };
}

export async function installClient(client: Client): Promise<{ ok: boolean; path: string; message: string }> {
  if (client === "all") {
    const results: any[] = [];
    for (const c of ["claude", "claude-code", "cursor", "openai", "hermes", "cline"] as Client[]) {
      results.push({ client: c, ...(await installClient(c)) });
    }
    const allOk = results.every((r) => r.ok);
    return { ok: allOk, path: "multiple", message: results.map((r) => `${r.client}: ${r.ok ? "✓" : "✗ " + r.message}`).join("\n") };
  }

  const path = PATHS[client];
  if (!path) return { ok: false, path: "?", message: "unknown client" };

  try {
    if (client === "openai") {
      // TOML format
      const cfg = readJson<CodexConfig>(path, {} as any) || ({} as any);
      // For TOML we write a simpler entry — just point at npm package
      const tomlLine = `
[mcp_servers.polymarket]
url = "http://127.0.0.1:7842/mcp"
`;
      const existing = existsSync(path) ? readFileSync(path, "utf8") : "";
      if (existing.includes("[mcp_servers.polymarket]")) {
        return { ok: true, path, message: "already configured" };
      }
      mkdirSync(dirname(path), { recursive: true });
      writeFileSync(path, existing + tomlLine);
      return { ok: true, path, message: "added [mcp_servers.polymarket] entry" };
    }

    if (client === "hermes") {
      // mcporter uses HTTP baseUrl
      const cfg = readJson<any>(path, { mcpServers: {} });
      cfg.mcpServers = cfg.mcpServers || {};
      cfg.mcpServers.polymarket = buildPolymarketConfig();
      writeJson(path, cfg);
      return { ok: true, path, message: "added polymarket entry" };
    }

    if (client === "cline") {
      // Cline uses mcpServers at root
      const cfg = readJson<McpConfig>(path, { mcpServers: {} });
      cfg.mcpServers = cfg.mcpServers || {};
      cfg.mcpServers.polymarket = buildPolymarketConfig();
      writeJson(path, cfg);
      return { ok: true, path, message: "added polymarket entry" };
    }

    // claude, claude-code, cursor — all use { mcpServers: { name: { type, url/command+args }}}
    const cfg = readJson<McpConfig>(path, { mcpServers: {} });
    cfg.mcpServers = cfg.mcpServers || {};
    cfg.mcpServers.polymarket = buildPolymarketConfig();
    writeJson(path, cfg);
    return { ok: true, path, message: `added polymarket entry` };
  } catch (e: any) {
    return { ok: false, path, message: e?.message ?? "write failed" };
  }
}

export async function uninstallClient(client: Client): Promise<{ ok: boolean; path: string; message: string }> {
  if (client === "all") {
    const results: any[] = [];
    for (const c of ["claude", "claude-code", "cursor", "openai", "hermes", "cline"] as Client[]) {
      results.push({ client: c, ...(await uninstallClient(c)) });
    }
    return { ok: true, path: "multiple", message: results.map((r) => `${r.client}: ${r.ok ? "removed" : "not found"}`).join("\n") };
  }

  const path = PATHS[client];
  if (!path || !existsSync(path)) return { ok: true, path, message: "config not present (nothing to remove)" };

  try {
    if (client === "openai") {
      const content = readFileSync(path, "utf8");
      // Remove [mcp_servers.polymarket] block
      const cleaned = content.replace(/\[mcp_servers\.polymarket\][^[]*?(?=\[|$)/s, "").trim() + "\n";
      writeFileSync(path, cleaned);
      return { ok: true, path, message: "removed entry" };
    }
    const cfg = readJson<McpConfig>(path, { mcpServers: {} });
    if (cfg.mcpServers?.polymarket) {
      delete cfg.mcpServers.polymarket;
      writeJson(path, cfg);
      return { ok: true, path, message: "removed polymarket entry" };
    }
    return { ok: true, path, message: "polymarket not present" };
  } catch (e: any) {
    return { ok: false, path, message: e?.message ?? "remove failed" };
  }
}

export async function showStatus(): Promise<void> {
  console.log("Polymarket MCP install status:\n");
  for (const client of ["claude", "claude-code", "cursor", "openai", "hermes", "cline"] as Client[]) {
    const path = PATHS[client];
    const exists = existsSync(path);
    let installed = false;
    if (exists) {
      try {
        if (client === "openai") {
          installed = readFileSync(path, "utf8").includes("[mcp_servers.polymarket]");
        } else {
          const cfg = readJson<any>(path, {});
          installed = !!cfg?.mcpServers?.polymarket;
        }
      } catch {}
    }
    const status = installed ? "✓ installed" : (exists ? "✗ not in config" : "(no config file)");
    console.log(`  ${client.padEnd(15)} ${status.padEnd(20)} ${path}`);
  }
  console.log("\nServer config:");
  console.log(`  URL:   http://127.0.0.1:7842/mcp`);
  console.log(`  Auth:  OAuth 2.0 + PKCE at /oauth/authorize`);
  console.log(`  Start: npx polymarket-mcp start`);
}

export async function runSetup(): Promise<void> {
  console.log("Polymarket MCP — One-time setup");
  console.log("===================================\n");
  console.log("This will:");
  console.log("  1. Start the MCP server (if not running)");
  console.log("  2. Open your browser to Polymarket.com");
  console.log("  3. You sign in normally (private key never leaves Polymarket)");
  console.log("  4. Polymarket issues API credentials, auto-saved encrypted to your machine");
  console.log("  5. The server uses these to trade on your behalf (no withdrawals possible)\n");

  // Check if server is already running
  const health = await checkHealth();
  if (!health.ok) {
    console.log("Starting server...");
    const child = spawn(process.execPath, ["dist/server.js", "--transport=http", "--port=7842"], {
      detached: true, stdio: "ignore", cwd: process.cwd(),
    });
    child.unref();
    await new Promise((r) => setTimeout(r, 2000));
  } else {
    console.log("Server already running on :7842");
  }

  // Wait for health
  for (let i = 0; i < 10; i++) {
    const h = await checkHealth();
    if (h.ok) break;
    await new Promise((r) => setTimeout(r, 500));
  }

  // Open browser to start OAuth flow
  const setupUrl = "http://127.0.0.1:7842/setup";
  console.log(`\nOpening browser to ${setupUrl}...`);
  try {
    if (process.platform === "win32") await execAsync(`start "" "${setupUrl}"`);
    else if (process.platform === "darwin") await execAsync(`open "${setupUrl}"`);
    else await execAsync(`xdg-open "${setupUrl}"`);
  } catch {
    console.log(`\nCould not auto-open browser. Please visit:\n  ${setupUrl}\n`);
  }
}

async function checkHealth(): Promise<{ ok: boolean }> {
  return new Promise((resolve) => {
    const req = http.get("http://127.0.0.1:7842/health", (res) => {
      resolve({ ok: res.statusCode === 200 });
    });
    req.on("error", () => resolve({ ok: false }));
    req.setTimeout(1000, () => { req.destroy(); resolve({ ok: false }); });
  });
}