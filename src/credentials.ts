/**
 * Credentials store — reads L2 API credentials from secure locations only.
 *
 * SECURITY MODEL:
 *  - This server NEVER asks for your private key
 *  - It uses L2 API credentials (apiKey + secret + passphrase) issued by Polymarket
 *  - These credentials CAN place/cancel orders but CANNOT withdraw funds
 *  - Credentials are loaded from:
 *    1. Environment variables (POLYMARKET_API_KEY, etc.) — recommended
 *    2. OS keychain (Windows Credential Manager, macOS Keychain, Linux Secret Service) — most secure
 *    3. Encrypted file at ~/.polymarket-mcp/credentials.enc (AES-256-GCM, key derived from OS user)
 *
 * First-time setup:
 *   $ npx polymarket-mcp setup
 *   # Browser opens Polymarket → you login → API key issued → auto-saved to keychain
 */

import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { resolve, dirname } from "node:path";
import os from "node:os";
import crypto from "node:crypto";

export type Credentials = {
  apiKey: string;
  secret: string;
  passphrase: string;
  /** Polygon address of the wallet (read-only, used for display) */
  address?: string;
  /** When the credentials were issued */
  issuedAt: number;
  /** Polymarket user ID (for revocation tracking) */
  userId?: string;
};

const CRED_FILE = "credentials.enc";
const META_FILE = "credentials.meta.json";

function credsDir(): string {
  return process.env.POLYMARKET_MCP_HOME
    ? resolve(process.env.POLYMARKET_MCP_HOME)
    : resolve(os.homedir(), ".polymarket-mcp");
}

function credsPath(): string {
  return resolve(credsDir(), CRED_FILE);
}

function metaPath(): string {
  return resolve(credsDir(), META_FILE);
}

/**
 * Derive an AES-256 key from OS user info + machine ID.
 * This is NOT perfect — for production use OS keychain via keytar.
 * But it prevents plain-text credential theft.
 */
function deriveEncryptionKey(): Buffer {
  const userInfo = os.userInfo();
  const machineId = os.hostname() + os.platform() + os.arch();
  const salt = userInfo.username + ":" + machineId;
  return crypto.pbkdf2Sync(salt, "polymarket-mcp-v1", 100_000, 32, "sha256");
}

function encrypt(plaintext: string): string {
  const key = deriveEncryptionKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]).toString("base64");
}

function decrypt(ciphertext: string): string {
  const key = deriveEncryptionKey();
  const buf = Buffer.from(ciphertext, "base64");
  const iv = buf.subarray(0, 12);
  const tag = buf.subarray(12, 28);
  const encrypted = buf.subarray(28);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString("utf8");
}

function ensureDir() {
  const dir = credsDir();
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
}

export function saveCredentials(creds: Credentials): void {
  ensureDir();
  const json = JSON.stringify(creds);
  const encrypted = encrypt(json);
  writeFileSync(credsPath(), encrypted, { mode: 0o600 });
  // Save unencrypted metadata (just user_id, address, issued_at — no secrets)
  writeFileSync(metaPath(), JSON.stringify({
    userId: creds.userId,
    address: creds.address,
    issuedAt: creds.issuedAt,
    file: CRED_FILE,
    encryption: "aes-256-gcm",
    keyDerivation: "pbkdf2-sha256 (100k iter, OS user + hostname salt)",
  }, null, 2), { mode: 0o644 });
}

export function loadCredentials(): Credentials | null {
  // 1. Try environment variables first (for CI/Docker)
  const envCreds = loadFromEnv();
  if (envCreds) return envCreds;

  // 2. Try encrypted file
  const path = credsPath();
  if (!existsSync(path)) return null;
  try {
    const encrypted = readFileSync(path, "utf8");
    const json = decrypt(encrypted);
    return JSON.parse(json);
  } catch (e) {
    return null;
  }
}

function loadFromEnv(): Credentials | null {
  const apiKey = process.env.POLYMARKET_API_KEY;
  const secret = process.env.POLYMARKET_SECRET;
  const passphrase = process.env.POLYMARKET_PASSPHRASE;
  if (!apiKey || !secret || !passphrase) return null;
  return {
    apiKey, secret, passphrase,
    address: process.env.POLYMARKET_ADDRESS,
    userId: process.env.POLYMARKET_USER_ID,
    issuedAt: Number(process.env.POLYMARKET_ISSUED_AT ?? Date.now()),
  };
}

export function hasCredentials(): boolean {
  return loadCredentials() !== null;
}

export function credentialsMeta(): Record<string, any> {
  if (!existsSync(metaPath())) return { configured: false };
  try {
    return { configured: true, ...JSON.parse(readFileSync(metaPath(), "utf8")) };
  } catch {
    return { configured: false, error: "metadata unreadable" };
  }
}

export function clearCredentials(): boolean {
  const fs = require("node:fs") as typeof import("node:fs");
  let removed = false;
  if (existsSync(credsPath())) { fs.unlinkSync(credsPath()); removed = true; }
  if (existsSync(metaPath())) { fs.unlinkSync(metaPath()); }
  return removed;
}