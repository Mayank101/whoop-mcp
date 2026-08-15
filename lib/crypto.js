// ─────────────────────────────────────────────────────
// Security primitives. Two jobs:
//   1. Encrypt Whoop client secrets + tokens at rest (AES-256-GCM).
//   2. Hash user passwords (scrypt).
// The master key comes from APP_ENCRYPTION_KEY (64 hex chars = 32 bytes).
// In production this MUST live in a real secrets manager, not a plain env file.
// ─────────────────────────────────────────────────────
import { randomBytes, createCipheriv, createDecipheriv, scryptSync, timingSafeEqual } from "crypto";

function masterKey() {
  const hex = process.env.APP_ENCRYPTION_KEY || "";
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error("APP_ENCRYPTION_KEY must be 64 hex chars (32 bytes). Generate one with: openssl rand -hex 32");
  }
  return Buffer.from(hex, "hex");
}

// Encrypt a string -> compact "v1:<iv>:<tag>:<ciphertext>" (all base64url).
export function encrypt(plaintext) {
  if (plaintext == null) return null;
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", masterKey(), iv);
  const ct = Buffer.concat([cipher.update(String(plaintext), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `v1:${iv.toString("base64url")}:${tag.toString("base64url")}:${ct.toString("base64url")}`;
}

export function decrypt(blob) {
  if (blob == null) return null;
  const [v, ivB, tagB, ctB] = String(blob).split(":");
  if (v !== "v1" || !ivB || !tagB || !ctB) throw new Error("bad ciphertext format");
  const decipher = createDecipheriv("aes-256-gcm", masterKey(), Buffer.from(ivB, "base64url"));
  decipher.setAuthTag(Buffer.from(tagB, "base64url"));
  return Buffer.concat([decipher.update(Buffer.from(ctB, "base64url")), decipher.final()]).toString("utf8");
}

// ── Passwords (scrypt) ──────────────────────────────
export function hashPassword(password) {
  const salt = randomBytes(16);
  const hash = scryptSync(String(password), salt, 64);
  return `scrypt:${salt.toString("base64url")}:${hash.toString("base64url")}`;
}

export function verifyPassword(password, stored) {
  try {
    const [algo, saltB, hashB] = String(stored).split(":");
    if (algo !== "scrypt") return false;
    const salt = Buffer.from(saltB, "base64url");
    const expected = Buffer.from(hashB, "base64url");
    const actual = scryptSync(String(password), salt, expected.length);
    return expected.length === actual.length && timingSafeEqual(expected, actual);
  } catch { return false; }
}

// ── Opaque tokens (session ids, per-user MCP tokens) ──
export function newToken(bytes = 32) {
  return randomBytes(bytes).toString("base64url");
}
