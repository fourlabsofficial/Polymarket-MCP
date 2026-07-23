# Polymarket MCP

**One-click Polymarket connector for AI agents** — Claude Desktop, Cursor, OpenAI Codex, Hermes Agent, Cline.

Built with proper **OAuth 2.0 + PKCE + Dynamic Client Registration** (RFC 6749, 7636, 7591, 8414). **No private key handling** — your wallet's private key never leaves Polymarket.com.

## ⚡ 30-Second Setup

```bash
# 1. Install (one command per AI client)
npx polymarket-mcp install claude    # Claude Desktop
npx polymarket-mcp install cursor    # Cursor
npx polymarket-mcp install openai    # OpenAI Codex
npx polymarket-mcp install hermes    # Hermes Agent (mcporter)
npx polymarket-mcp install cline     # Cline
npx polymarket-mcp install all       # all of the above

# 2. Open Claude/Cursor/etc and click "Add Polymarket"
# 3. Browser opens → sign in to Polymarket.com → done
```

That's it. Your MCP client now has access to 43 Polymarket tools, with proper OAuth 2.0 auth, and your private key stays in Polymarket.

## 🔐 Security Model

| What | Where |
|---|---|
| **Private key (signs transactions)** | **Polymarket.com** (never leaves) |
| L2 API credentials (apiKey + secret + passphrase) | Encrypted at `~/.polymarket-mcp/credentials.enc` (AES-256-GCM) |
| OAuth access tokens (bearer) | Encrypted at `~/.polymarket-mcp/oauth-state.json` |
| Server process | Reads credentials, **never accepts private key** |

**Capabilities of L2 credentials:** place/cancel orders, view positions/balance. **Cannot** withdraw funds or change account settings.

## 🛠️ Tools (43)

### Market Data (7) — public, no auth
- `polymarket_status` — server state
- `search_markets` — find markets by keyword
- `list_active_markets` — browse all live
- `get_orderbook` — live bids/asks for a token
- `get_midpoint` — best bid/ask + spread
- `get_market_depth` — depth analysis (imbalance, spread %)
- (3 more market data tools)

### Trading (auth) — requires OAuth login
- `get_balance`, `get_positions` — read your account
- `place_market_order` — FOK with slippage cap
- `get_open_orders`, `get_trades` — order history

### Auto-Trading (6 strategies)
- `sniper` — new markets <6h, YES <5¢ (asymmetric)
- `mean_reversion` — fade YES spikes on thin depth
- `spread_harvest` — post both sides on wide markets
- `dca_ladder` — 4-level buys at lower prices
- `whale_follow` — mirror top traders
- `auto_redeem` — harvest resolved positions

### Risk / Safety
- `risk_status`, `risk_kill_switch` — emergency stop
- `trade_log` — every decision, proposal, execution
- `strategy_list` / `strategy_run_once` / `strategy_start` / `strategy_stop`

### Streaming
- `subscribe_market_stream` — WebSocket live orderbook
- `ws_status` — connection state

## 🤖 Auto-Trading (Beats BetMour et al)

We run **6 uncorrelated strategies in parallel** with **centralized risk management** vs. their single-strategy, no-risk-management approach:

| Their bot | Polymarket MCP |
|---|---|
| Single strategy | **6 strategies** (sniper + mean-reversion + spread + DCA + whale + auto-redeem) |
| No risk limits | Position caps, daily loss cap, kill switch |
| Taker (pays fees) | Maker-first (post limits, capture midpoint) |
| Manual exit | Auto-redeem resolved positions |
| No inventory management | DCA ladder catches falling knives |
| 1 strategy = crowded | Uncorrelated edges (different timeframes, different signals) |

## 🏗️ Architecture

```
~/.polymarket-mcp/
├─ credentials.enc          # AES-256-GCM encrypted L2 creds
├─ oauth-state.json        # OAuth tokens, registered clients
└─ trade-log.jsonl         # Every trade decision

~/polymarket-mcp/
├─ src/
│  ├─ server.ts            # MCP server (43 tools)
│  ├─ http.ts              # Streamable HTTP transport
│  ├─ oauth.ts             # OAuth 2.0 + DCR
│  ├─ credentials.ts        # Encrypted credential store
│  ├─ cli.ts               # One-click installers
│  └─ ws-manager.ts        # WebSocket market data
├─ manifest.json           # MCP Bundle (mcpb) format
├─ package.json
└─ dist/                   # compiled
```

## 🔐 OAuth Flow (RFC-compliant)

1. **Discover**: MCP client fetches `/.well-known/oauth-authorization-server`
2. **Register**: Client posts to `/oauth/register` (DCR — gets client_id + secret)
3. **Authorize**: User redirected to `/oauth/authorize` → server redirects to Polymarket.com
4. **Login**: User signs in to Polymarket (private key stays in Polymarket)
5. **Consent**: Server shows permission scope, user approves
6. **Callback**: Polymarket redirects to `/oauth/polymarket-callback` with code
7. **Token exchange**: Server exchanges code → derives L2 API creds → returns access token + L2 creds to MCP client
8. **MCP client stores L2 creds in its own keychain** (Chrome storage, macOS Keychain, etc.)
9. Server **forgets** credentials after the initial handoff (configurable — can keep encrypted copy for re-auth)

## 📦 Install via npx (post-publish)

```bash
npx polymarket-mcp install claude
```

This adds the server entry to `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "polymarket": {
      "type": "http",
      "url": "http://127.0.0.1:7842/mcp"
    }
  }
}
```

The MCP client (Claude/Cursor) then auto-discovers the OAuth endpoint, opens your browser to Polymarket.com, and you sign in once.

## 🚀 Manual Setup (for development)

```bash
git clone https://github.com/fourlabsofficial/polymarket-mcp
cd polymarket-mcp
pnpm install
pnpm run build
node dist/server.js
# → http://127.0.0.1:7842/mcp
```

## 🛣️ Roadmap

- [x] OAuth 2.0 + PKCE + DCR
- [x] Encrypted credentials store
- [x] One-click installers (Claude, Cursor, OpenAI, Hermes, Cline)
- [x] Streamable HTTP transport
- [x] 6 auto-trading strategies
- [x] Risk manager + kill switch
- [ ] Auto-restart on crash (PM2/systemd integration)
- [ ] Prometheus metrics endpoint
- [ ] Backtester
- [ ] Telegram/Discord notifier

## 📄 License

MIT — do whatever you want, no warranty.

## 🙋 Author

Built by [@fourlabsofficial](https://github.com/fourlabsofficial) for the open-source Polymarket trading community.
