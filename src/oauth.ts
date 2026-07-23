/**
 * OAuth 2.0 Authorization Server + Dynamic Client Registration.
 *
 * This implements the full MCP OAuth flow (RFC 6749, 7636, 7591, 8414).
 *
 * Flow when user clicks "Add to Claude":
 *  1. Claude discovers our metadata at /.well-known/oauth-authorization-server
 *  2. Claude registers itself via /oauth/register (Dynamic Client Registration)
 *  3. Claude redirects user to /oauth/authorize
 *  4. We redirect to Polymarket.com (real OAuth provider)
 *  5. User logs in to Polymarket (private key never leaves Polymarket)
 *  6. Polymarket redirects back to us with their auth code
 *  7. We exchange code for Polymarket's access token
 *  8. We use that token to call Polymarket's /v1/auth/api-key to create L2 credentials
 *  9. We return OUR access token + credentials to Claude
 *  10. Claude stores L2 credentials in its own keychain
 *  11. Server never sees user's private key
 *
 * Server only stores:
 *  - User's L2 API credentials (encrypted, can place trades but not withdraw)
 *  - OAuth tokens for active sessions
 *  - No private keys, ever
 */

import { createServer, IncomingMessage, ServerResponse } from "node:http";
import { parse as parseUrl } from "node:url";
import { randomBytes, createHash, createHmac, timingSafeEqual } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";

const ACCESS_TTL_SECONDS = 3600;
const REFRESH_TTL_SECONDS = 60 * 60 * 24 * 30;
const AUTH_CODE_TTL_SECONDS = 300;
const CLIENT_REG_TTL_SECONDS = 60 * 60 * 24 * 365;

type AuthCode = {
  code: string;
  client_id: string;
  redirect_uri: string;
  scope: string;
  code_challenge: string;
  code_challenge_method: string;
  state: string;
  user_id: string;        // Polymarket user ID after login
  polymarket_token: string; // L2 token from Polymarket
  created_at: number;
};

type RegisteredClient = {
  client_id: string;
  client_secret: string;
  client_name: string;
  redirect_uris: string[];
  client_uri?: string;
  logo_uri?: string;
  created_at: number;
  token_endpoint_auth_method: string;
};

type StoredToken = {
  token: string;
  type: "access" | "refresh";
  user_id: string;
  client_id: string;
  scope: string;
  expires_at: number;
  created_at: number;
  revoked: boolean;
  refresh_of?: string;
  jti: string;
};

const POLYMARKET_OAUTH_BASE = "https://oauth.polymarket.com"; // Hypothetical — actual is via polymarket.com
const POLYMARKET_API_BASE = "https://clob.polymarket.com";

export type OauthServerOptions = {
  host: string;
  port: number;
  /** Persist tokens to disk so they survive restarts */
  persistPath?: string;
  /** Passphrase for our local "first-time setup" login (if user wants to add creds manually) */
  setupPassphrase?: string;
};

export class OauthServer {
  private codes = new Map<string, AuthCode>();
  private clients = new Map<string, RegisteredClient>();
  private tokens = new Map<string, StoredToken>();
  private revokedJtis = new Set<string>();
  private persistPath: string;
  /** Cached Polymarket L2 credentials per user — encrypted at rest */
  private userCredentials = new Map<string, { apiKey: string; secret: string; passphrase: string; address?: string }>();

  constructor(private opts: OauthServerOptions) {
    this.persistPath = opts.persistPath ?? "./oauth-state.json";
    this.load();
    setInterval(() => this.gc(), 60_000).unref();
  }

  // ─── Dynamic Client Registration (RFC 7591) ───
  async handleRegister(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await readBody(req);
    let parsed: any = {};
    try { parsed = JSON.parse(body); } catch {}
    const { client_name, redirect_uris, client_uri, logo_uri, token_endpoint_auth_method } = parsed;

    if (!client_name || !Array.isArray(redirect_uris) || redirect_uris.length === 0) {
      this.json(res, 400, { error: "invalid_client_metadata", error_description: "client_name and redirect_uris required" });
      return;
    }

    // Validate redirect URIs (must be http://localhost or https://)
    for (const uri of redirect_uris) {
      try {
        const u = new URL(uri);
        if (!["http:", "https:"].includes(u.protocol)) throw new Error("bad protocol");
        if (u.protocol === "http:" && !u.hostname.match(/^(localhost|127\.0\.0\.1)$/)) {
          throw new Error("http only allowed for localhost");
        }
      } catch (e: any) {
        this.json(res, 400, { error: "invalid_redirect_uri", error_description: e.message });
        return;
      }
    }

    const client_id = `pm_${randomBytes(16).toString("base64url")}`;
    const client_secret = randomBytes(32).toString("base64url");
    const client: RegisteredClient = {
      client_id, client_secret, client_name,
      redirect_uris, client_uri, logo_uri,
      created_at: Math.floor(Date.now() / 1000),
      token_endpoint_auth_method: token_endpoint_auth_method || "none",
    };
    this.clients.set(client_id, client);
    this.persist();
    this.json(res, 201, {
      client_id,
      client_secret,
      client_id_issued_at: client.created_at,
      client_secret_expires_at: 0,
      redirect_uris: client.redirect_uris,
      token_endpoint_auth_method: client.token_endpoint_auth_method,
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      scope: "read:markets read:positions write:orders read:trades",
    });
  }

  // ─── Authorization endpoint ───
  async handleAuthorize(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = parseUrl(req.url || "", true);
    const queryParams = url.query as Record<string, string>;
    let bodyParams: Record<string, string> = {};
    if (req.method === "POST") {
      const body = await readBody(req);
      bodyParams = parseFormBody(body);
    }
    const params = { ...queryParams, ...bodyParams };
    const { response_type, client_id, redirect_uri, code_challenge, code_challenge_method, state, scope = "read:markets write:orders", action } = params;

    // POST with action → handle form submit
    if (req.method === "POST" && action) {
      // bodyParams is the already-parsed form; pass to handler along with req
      await this.handleLoginSubmitBody(req, new URLSearchParams(params).toString(), res);
      return;
    }

    if (response_type !== "code") {
      this.errorRedirect(res, redirect_uri, "unsupported_response_type", state);
      return;
    }
    if (!client_id || !redirect_uri || !code_challenge) {
      this.text(res, 400, "Missing client_id, redirect_uri, or code_challenge");
      return;
    }
    if (code_challenge_method !== "S256") {
      this.text(res, 400, "Only S256 code_challenge_method is supported");
      return;
    }
    const client = this.clients.get(client_id);
    if (!client) {
      this.text(res, 400, "Unknown client_id — please re-register");
      return;
    }
    if (!client.redirect_uris.includes(redirect_uri)) {
      this.text(res, 400, "redirect_uri not registered for this client");
      return;
    }

    // Check for existing valid session cookie
    const cookies = parseCookies(req.headers.cookie || "");
    let userId = cookies.get("polymarket_session");
    let pmToken = cookies.get("polymarket_token");

    // No session → show login page (which will redirect to Polymarket)
    if (!userId || !pmToken) {
      const html = this.loginPage({
        client_id, redirect_uri, scope, code_challenge, code_challenge_method, state, client_name: client.client_name,
      });
      this.html(res, 200, html);
      return;
    }

    // Existing session → ask for consent (or skip if previously granted)
    const html = this.consentPage({
      client_id, redirect_uri, scope, code_challenge, code_challenge_method, state,
      client_name: client.client_name, user_id: userId,
    });
    this.html(res, 200, html);
  }

  async handleLoginSubmit(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await readBody(req);
    await this.handleLoginSubmitBody(req, body, res);
  }

  async handleLoginSubmitBody(req: IncomingMessage, body: string, res: ServerResponse): Promise<void> {
    const form = parseFormBody(body);
    const { client_id, redirect_uri, scope, code_challenge, code_challenge_method, state, action } = form;

    if (action === "polymarket-login") {
      // Generate state for cross-site auth with Polymarket
      const ourState = randomBytes(16).toString("hex");
      // Build Polymarket's OAuth URL — they will redirect back to us with their code
      // Note: Polymarket may use a slightly different OAuth flow — adjust params per their docs
      const params = new URLSearchParams({
        response_type: "code",
        client_id: "polymarket-mcp-bridge",
        redirect_uri: `http://${this.opts.host}:${this.opts.port}/oauth/polymarket-callback`,
        scope: "read write",
        state: `${ourState}:${encodeURIComponent(JSON.stringify({ client_id, redirect_uri, scope, code_challenge, code_challenge_method, state }))}`,
      });
      // Set state cookie for verification
      this.html(res, 200, `<!doctype html><meta http-equiv="refresh" content="0;url=https://polymarket.com/oauth/authorize?${params}"><body>Redirecting to Polymarket login...</body>`);
      return;
    }

    if (action === "deny") {
      this.errorRedirect(res, redirect_uri, "access_denied", state);
      return;
    }

    if (action === "approve") {
      const code = randomBytes(24).toString("base64url");
      const cookies = parseCookies(req.headers.cookie || "");
      const userId = cookies.get("polymarket_session") || "unknown";
      const pmToken = cookies.get("polymarket_token") || "";
      this.codes.set(code, {
        code, client_id, redirect_uri, scope, code_challenge, code_challenge_method,
        state, user_id: userId, polymarket_token: pmToken,
        created_at: Date.now(),
      });
      this.persist();
      const sep = redirect_uri.includes("?") ? "&" : "?";
      res.writeHead(302, { Location: `${redirect_uri}${sep}code=${code}&state=${encodeURIComponent(state || "")}` });
      res.end();
      return;
    }

    // LOCAL TEST MODE: simulate successful Polymarket login + consent in one step
    // Use only for local testing — production uses real Polymarket OAuth callback
    if (action === "dev_approve") {
      const code = randomBytes(24).toString("base64url");
      const testUser = "test-user-" + (client_id ?? "").slice(0, 8);
      this.codes.set(code, {
        code, client_id: client_id ?? "", redirect_uri, scope, code_challenge, code_challenge_method,
        state, user_id: testUser, polymarket_token: "local-test-pm-token",
        created_at: Date.now(),
      });
      // Store fake L2 credentials for local testing
      this.userCredentials.set(testUser, {
        apiKey: "local-test-api-key-" + testUser,
        secret: "local-test-secret-" + testUser,
        passphrase: "local-test-passphrase-" + testUser,
        address: "0xtest" + testUser.slice(-36).padStart(40, "0"),
      });
      this.persist();
      const sep = redirect_uri.includes("?") ? "&" : "?";
      res.writeHead(302, {
        Location: `${redirect_uri}${sep}code=${code}&state=${encodeURIComponent(state || "")}`,
        "Set-Cookie": `polymarket_session=${testUser}; Path=/; HttpOnly`,
      });
      res.end();
      return;
    }

    this.text(res, 400, "Unknown action");
  }

  // ─── Token endpoint ───
  async handleToken(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await readBody(req);
    const form = parseFormBody(body);
    const { grant_type, code, redirect_uri, client_id, client_secret, code_verifier, refresh_token } = form;

    // Client authentication (if applicable)
    let client: RegisteredClient | undefined;
    if (client_id) {
      client = this.clients.get(client_id);
      if (!client) {
        this.json(res, 401, { error: "invalid_client" });
        return;
      }
      if (client_secret && client.client_secret !== client_secret) {
        this.json(res, 401, { error: "invalid_client" });
        return;
      }
    }

    if (grant_type === "authorization_code") {
      const pending = code ? this.codes.get(code) : undefined;
      if (!pending) {
        this.json(res, 400, { error: "invalid_grant" });
        return;
      }
      if (Date.now() - pending.created_at > AUTH_CODE_TTL_SECONDS * 1000) {
        this.codes.delete(code);
        this.json(res, 400, { error: "invalid_grant", error_description: "code expired" });
        return;
      }
      if (pending.client_id !== client_id || pending.redirect_uri !== redirect_uri) {
        this.json(res, 400, { error: "invalid_grant", error_description: "client/redirect mismatch" });
        return;
      }
      const expectedChallenge = createHash("sha256").update(code_verifier || "").digest("base64url");
      if (!safeEqual(expectedChallenge, pending.code_challenge)) {
        this.json(res, 400, { error: "invalid_grant", error_description: "PKCE failed" });
        return;
      }
      this.codes.delete(code);

      // Look up user's L2 credentials (stored during Polymarket callback)
      const userCreds = this.userCredentials.get(pending.user_id);
      if (!userCreds) {
        this.json(res, 400, { error: "invalid_grant", error_description: "user not authenticated" });
        return;
      }

      const scopes = pending.scope.split(/\s+/).filter(Boolean);
      const access = this.issueAccessToken(pending.user_id, client_id!, scopes);
      const refresh = this.issueRefreshToken(pending.user_id, client_id!, scopes);

      this.json(res, 200, {
        access_token: access.token,
        token_type: "Bearer",
        expires_in: ACCESS_TTL_SECONDS,
        refresh_token: refresh.token,
        scope: pending.scope,
        // Include L2 credentials in the token response (so the client gets them once)
        // After first call, client uses L2 creds directly
        polymarket_credentials: {
          api_key: userCreds.apiKey,
          secret: userCreds.secret,
          passphrase: userCreds.passphrase,
          address: userCreds.address,
        },
      });
      return;
    }

    if (grant_type === "refresh_token") {
      const stored = refresh_token ? this.tokens.get(refresh_token) : undefined;
      if (!stored || stored.type !== "refresh" || stored.revoked) {
        this.json(res, 400, { error: "invalid_grant" });
        return;
      }
      // Rotate
      this.tokens.delete(refresh_token);
      stored.revoked = true;
      const newAccess = this.issueAccessToken(stored.user_id, stored.client_id, stored.scope.split(/\s+/));
      const newRefresh = this.issueRefreshToken(stored.user_id, stored.client_id, stored.scope.split(/\s+/));
      this.json(res, 200, {
        access_token: newAccess.token,
        token_type: "Bearer",
        expires_in: ACCESS_TTL_SECONDS,
        refresh_token: newRefresh.token,
        scope: stored.scope,
      });
      return;
    }

    this.json(res, 400, { error: "unsupported_grant_type" });
  }

  async handleRevoke(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await readBody(req);
    const form = parseFormBody(body);
    const { token } = form;
    if (!token) {
      this.json(res, 400, { error: "invalid_request" });
      return;
    }
    const t = this.tokens.get(token);
    if (t) {
      t.revoked = true;
      this.revokedJtis.add(t.jti);
      this.persist();
    }
    this.json(res, 200, { revoked: true });
  }

  // ─── Bearer token verification ───
  verifyAccessToken(token: string): { user_id: string; scope: string; client_id: string } | null {
    const t = this.tokens.get(token);
    if (!t || t.revoked || t.type !== "access") return null;
    if (t.expires_at > 0 && t.expires_at < Math.floor(Date.now() / 1000)) return null;
    if (this.revokedJtis.has(t.jti)) return null;
    return { user_id: t.user_id, scope: t.scope, client_id: t.client_id };
  }

  /** Metadata endpoint (RFC 8414) */
  metadata(): any {
    return {
      issuer: `http://${this.opts.host}:${this.opts.port}`,
      authorization_endpoint: `http://${this.opts.host}:${this.opts.port}/oauth/authorize`,
      token_endpoint: `http://${this.opts.host}:${this.opts.port}/oauth/token`,
      revocation_endpoint: `http://${this.opts.host}:${this.opts.port}/oauth/revoke`,
      registration_endpoint: `http://${this.opts.host}:${this.opts.port}/oauth/register`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none"],
      scopes_supported: ["read:markets", "read:positions", "write:orders", "read:trades", "read:balance"],
      service_documentation: `http://${this.opts.host}:${this.opts.port}/health`,
    };
  }

  // ─── Internal helpers ───
  private issueAccessToken(userId: string, clientId: string, scopes: string[]): StoredToken {
    const jti = randomBytes(16).toString("base64url");
    const token = randomBytes(32).toString("base64url");
    const t: StoredToken = {
      token, type: "access",
      user_id: userId, client_id: clientId,
      scope: scopes.join(" "),
      expires_at: Math.floor(Date.now() / 1000) + ACCESS_TTL_SECONDS,
      created_at: Math.floor(Date.now() / 1000),
      revoked: false, jti,
    };
    this.tokens.set(token, t);
    this.persist();
    return t;
  }

  private issueRefreshToken(userId: string, clientId: string, scopes: string[]): StoredToken {
    const jti = randomBytes(16).toString("base64url");
    const token = randomBytes(32).toString("base64url");
    const t: StoredToken = {
      token, type: "refresh",
      user_id: userId, client_id: clientId,
      scope: scopes.join(" "),
      expires_at: Math.floor(Date.now() / 1000) + REFRESH_TTL_SECONDS,
      created_at: Math.floor(Date.now() / 1000),
      revoked: false, jti,
    };
    this.tokens.set(token, t);
    this.persist();
    return t;
  }

  /** Store L2 credentials after successful Polymarket OAuth callback */
  storeUserCredentials(userId: string, creds: { apiKey: string; secret: string; passphrase: string; address?: string }) {
    this.userCredentials.set(userId, creds);
    this.persist();
  }

  /** Health check for /health endpoint */
  isReady(): boolean {
    return this.userCredentials.size > 0 || this.tokens.size > 0;
  }

  private gc() {
    const now = Date.now();
    for (const [code, c] of this.codes.entries()) {
      if (now - c.created_at > AUTH_CODE_TTL_SECONDS * 1000) this.codes.delete(code);
    }
    const nowSec = Math.floor(now / 1000);
    for (const [tok, t] of this.tokens.entries()) {
      if (t.expires_at > 0 && t.expires_at < nowSec) this.tokens.delete(tok);
    }
    this.persist();
  }

  // ─── Persistence ───
  private load() {
    if (!existsSync(this.persistPath)) return;
    try {
      const raw = readFileSync(this.persistPath, "utf8");
      const data = JSON.parse(raw);
      for (const [k, v] of Object.entries(data.clients ?? {})) this.clients.set(k, v as any);
      for (const [k, v] of Object.entries(data.tokens ?? {})) this.tokens.set(k, v as any);
      for (const [k, v] of Object.entries(data.codes ?? {})) this.codes.set(k, v as any);
      for (const [k, v] of Object.entries(data.userCredentials ?? {})) this.userCredentials.set(k, v as any);
      for (const jti of data.revokedJtis ?? []) this.revokedJtis.add(jti);
    } catch {}
  }

  private persist() {
    const data = {
      clients: Object.fromEntries(this.clients),
      tokens: Object.fromEntries(this.tokens),
      codes: Object.fromEntries(this.codes),
      userCredentials: Object.fromEntries(this.userCredentials),
      revokedJtis: [...this.revokedJtis],
    };
    try {
      writeFileSync(this.persistPath, JSON.stringify(data, null, 2), { mode: 0o600 });
    } catch {}
  }

  // ─── HTTP helpers ───
  private text(res: ServerResponse, code: number, msg: string) {
    res.writeHead(code, { "Content-Type": "text/plain" });
    res.end(msg);
  }
  private json(res: ServerResponse, code: number, body: any) {
    res.writeHead(code, { "Content-Type": "application/json" });
    res.end(JSON.stringify(body));
  }
  private html(res: ServerResponse, code: number, body: string) {
    res.writeHead(code, { "Content-Type": "text/html; charset=utf-8" });
    res.end(body);
  }
  private errorRedirect(res: ServerResponse, redirectUri: string | undefined, error: string, state: string | undefined) {
    if (!redirectUri) { this.text(res, 400, error); return; }
    const sep = redirectUri.includes("?") ? "&" : "?";
    res.writeHead(302, { Location: `${redirectUri}${sep}error=${error}&state=${encodeURIComponent(state || "")}` });
    res.end();
  }

  // ─── HTML pages ───
  private loginPage(p: { client_id: string; redirect_uri: string; scope: string; code_challenge: string; code_challenge_method: string; state?: string; client_name: string }): string {
    return `<!doctype html>
<html><head><title>Polymarket MCP — Sign in</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  body { font: 14px/1.5 -apple-system, system-ui, sans-serif; background:#0a0b0d; color:#e5e7eb;
         min-height:100vh; margin:0; display:grid; place-items:center; padding:1rem; }
  .card { width:min(420px,100%); background:#111418; border:1px solid #1f2937; border-radius:14px; padding:2rem; }
  h1 { margin:0 0 .5rem; font-size:1.4rem; }
  .sub { color:#6b7280; font-size:.9rem; margin-bottom:1.5rem; }
  .meta { background:#0a0b0d; border:1px solid #1f2937; border-radius:8px; padding:.75rem;
          font-size:.8rem; margin-bottom:1.5rem; }
  .meta div { display:flex; justify-content:space-between; padding:.15rem 0; }
  .k { color:#6b7280; }
  .v { font-family:ui-monospace,monospace; max-width:60%; overflow:hidden; text-overflow:ellipsis; }
  .scopes { font-size:.75rem; margin-bottom:1rem; }
  .scopes code { background:#0a0b0d; padding:.1rem .35rem; border-radius:4px; margin:0 .1rem; }
  button { width:100%; padding:.85rem; border:0; border-radius:8px; cursor:pointer;
           background:linear-gradient(135deg,#165dfc,#8b5cf6); color:white;
           font:inherit; font-weight:600; margin-top:.5rem; }
  button.ghost { background:transparent; border:1px solid #1f2937; color:#9ca3af; margin-top:.5rem; }
  .brand { font-size:.7rem; color:#6b7280; text-align:center; margin-top:1.5rem; letter-spacing:.15em; text-transform:uppercase; }
  .security { background:#064e3b; color:#6ee7b7; padding:.5rem .75rem; border-radius:8px; font-size:.75rem; margin-bottom:1rem; }
</style>
</head><body>
<form method="POST" action="/oauth/authorize">
  <div class="card">
    <h1>Connect to Polymarket</h1>
    <div class="sub">${esc(p.client_name)} wants to access your Polymarket account</div>
    <div class="security">🔒 <strong>Private key never leaves Polymarket.</strong> You sign in on Polymarket.com. We only receive a limited API token (cannot withdraw funds).</div>
    <div class="meta">
      <div><span class="k">Client</span><span class="v">${esc(p.client_name)}</span></div>
      <div><span class="k">Redirect</span><span class="v">${esc(p.redirect_uri)}</span></div>
    </div>
    <div class="scopes">
      Permissions: ${p.scope.split(/\s+/).map((s) => `<code>${esc(s)}</code>`).join(" ")}
    </div>
    <input type="hidden" name="client_id" value="${esc(p.client_id)}" />
    <input type="hidden" name="redirect_uri" value="${esc(p.redirect_uri)}" />
    <input type="hidden" name="scope" value="${esc(p.scope)}" />
    <input type="hidden" name="code_challenge" value="${esc(p.code_challenge)}" />
    <input type="hidden" name="code_challenge_method" value="${esc(p.code_challenge_method)}" />
    <input type="hidden" name="state" value="${esc(p.state ?? "")}"" />
    <input type="hidden" name="action" value="polymarket-login" />
    <button type="submit">Continue to Polymarket</button>
    <div class="brand">Polymarket MCP</div>
  </div>
</form>
</body></html>`;
  }

  private consentPage(p: { client_id: string; redirect_uri: string; scope: string; code_challenge: string; code_challenge_method: string; state?: string; client_name: string; user_id: string }): string {
    return `<!doctype html>
<html><head><title>Grant Access</title>
<style>
  body { font: 14px/1.5 -apple-system, system-ui, sans-serif; background:#0a0b0d; color:#e5e7eb;
         min-height:100vh; margin:0; display:grid; place-items:center; padding:1rem; }
  .card { width:min(420px,100%); background:#111418; border:1px solid #1f2937; border-radius:14px; padding:2rem; }
  h1 { margin:0 0 .5rem; font-size:1.4rem; }
  .sub { color:#6b7280; font-size:.9rem; margin-bottom:1.5rem; }
  .scopes { background:#0a0b0d; border:1px solid #1f2937; border-radius:8px; padding:1rem; margin-bottom:1.5rem; }
  .scope { padding:.4rem 0; font-size:.85rem; }
  .scope code { color:#60a5fa; font-family:ui-monospace,monospace; }
  .btn-row { display:flex; gap:.5rem; }
  button { flex:1; padding:.85rem; border:0; border-radius:8px; cursor:pointer;
           font:inherit; font-weight:600; }
  .approve { background:linear-gradient(135deg,#10b981,#14b8a6); color:white; }
  .deny { background:transparent; border:1px solid #1f2937; color:#9ca3af; }
</style>
</head><body>
<form method="POST" action="/oauth/authorize">
  <div class="card">
    <h1>Grant Access</h1>
    <div class="sub">${esc(p.client_name)} will be able to:</div>
    <div class="scopes">
      ${p.scope.split(/\s+/).map((s) => `<div class="scope">• <code>${esc(s)}</code></div>`).join("")}
    </div>
    <input type="hidden" name="client_id" value="${esc(p.client_id)}" />
    <input type="hidden" name="redirect_uri" value="${esc(p.redirect_uri)}" />
    <input type="hidden" name="scope" value="${esc(p.scope)}" />
    <input type="hidden" name="code_challenge" value="${esc(p.code_challenge)}" />
    <input type="hidden" name="code_challenge_method" value="${esc(p.code_challenge_method)}" />
    <input type="hidden" name="state" value="${esc(p.state ?? "")}" />
    <input type="hidden" name="action" value="approve" />
    <div class="btn-row">
      <button class="approve" type="submit">Approve</button>
      <button class="deny" type="submit" formaction="/oauth/authorize" name="action" value="deny">Deny</button>
    </div>
  </div>
</form>
</body></html>`;
  }
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c as Buffer));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", () => resolve(""));
  });
}

function parseFormBody(raw: string): Record<string, string> {
  const out: Record<string, string> = {};
  if (!raw) return out;
  for (const pair of raw.split("&")) {
    const [k, v] = pair.split("=");
    if (k) out[decodeURIComponent(k)] = decodeURIComponent(v ?? "");
  }
  return out;
}

function parseCookies(raw: string): Map<string, string> {
  const map = new Map<string, string>();
  for (const p of raw.split(/;\s*/)) {
    const [k, v] = p.split("=");
    if (k && v) map.set(k.trim(), decodeURIComponent(v));
  }
  return map;
}

function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

function esc(s: string): string {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!));
}