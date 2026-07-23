/**
 * Polymarket WebSocket manager — public market channel.
 * (User channel requires L2 auth; optional enhancement.)
 */

import WebSocket from "ws";
import { EventEmitter } from "node:events";

export type MarketEvent = {
  type: "book" | "price_change" | "trade" | "tick_size_change";
  asset_id: string;
  bids?: [string, string][];
  asks?: [string, string][];
  price?: string;
  side?: string;
  hash?: string;
  size?: string;
  new_tick_size?: string;
  timestamp: string;
};

const RECONNECT_BASE_MS = 250;
const RECONNECT_MAX_MS = 30_000;
const HEARTBEAT_MS = 30_000;

function backoff(attempt: number): number {
  return Math.min(RECONNECT_MAX_MS, RECONNECT_BASE_MS * Math.pow(2, attempt));
}

export class PolymarketWsManager extends EventEmitter {
  private marketWs: WebSocket | null = null;
  private userWs: WebSocket | null = null;
  private marketAttempt = 0;
  private userAttempt = 0;
  private subscriptions = new Set<string>();
  private heartbeat: NodeJS.Timeout | null = null;
  private closed = false;

  constructor() { super(); }

  async start(): Promise<void> {
    this.closed = false;
    await this.connectMarket();
  }

  async stop(): Promise<void> {
    this.closed = true;
    if (this.marketWs) this.marketWs.close();
    if (this.userWs) this.userWs.close();
    if (this.heartbeat) clearInterval(this.heartbeat);
  }

  private connectMarket(): Promise<void> {
    return new Promise((resolve, reject) => {
      if (this.closed) return reject(new Error("closed"));
      const ws = new WebSocket("wss://ws-subscriptions-clob.polymarket.com/ws/market");
      this.marketWs = ws;
      ws.on("open", () => {
        this.marketAttempt = 0;
        if (this.subscriptions.size > 0) {
          ws.send(JSON.stringify({
            type: "subscribe", channel: "market",
            assets_ids: [...this.subscriptions],
          }));
        }
        this.heartbeat = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) ws.ping();
        }, HEARTBEAT_MS);
        resolve();
      });
      ws.on("message", (raw) => {
        try {
          const data = JSON.parse(raw.toString());
          if (Array.isArray(data)) for (const ev of data) this.emit("market", ev as MarketEvent);
          else this.emit("market", data as MarketEvent);
        } catch {}
      });
      ws.on("error", (err) => this.emit("error", { channel: "market", err }));
      ws.on("close", () => {
        if (this.heartbeat) clearInterval(this.heartbeat);
        this.heartbeat = null;
        if (this.closed) return;
        const delay = backoff(this.marketAttempt);
        this.marketAttempt++;
        setTimeout(() => this.connectMarket().catch(() => {}), delay);
      });
    });
  }

  subscribeMarket(assetIds: string[]): void {
    for (const id of assetIds) this.subscriptions.add(id);
    if (this.marketWs?.readyState === WebSocket.OPEN) {
      this.marketWs.send(JSON.stringify({ type: "subscribe", channel: "market", assets_ids: assetIds }));
    }
  }

  unsubscribeMarket(assetIds: string[]): void {
    for (const id of assetIds) this.subscriptions.delete(id);
    if (this.marketWs?.readyState === WebSocket.OPEN) {
      this.marketWs.send(JSON.stringify({ type: "unsubscribe", channel: "market", assets_ids: assetIds }));
    }
  }

  isMarketConnected(): boolean { return this.marketWs?.readyState === WebSocket.OPEN; }
  isUserConnected(): boolean { return this.userWs?.readyState === WebSocket.OPEN; }
}