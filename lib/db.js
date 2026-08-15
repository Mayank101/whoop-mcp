// ─────────────────────────────────────────────────────
// Postgres data layer (Neon-ready). Async. Whoop credentials + tokens stored
// ENCRYPTED (crypto.js) — the DB never holds plaintext secrets.
// Set DATABASE_URL to your Neon connection string (use the POOLED one).
// A test can inject a pg-mem pool via setPool().
// ─────────────────────────────────────────────────────
import pg from "pg";
import { encrypt, decrypt, newToken } from "./crypto.js";

let pool;
function needSSL(url) { return !!url && !/localhost|127\.0\.0\.1/.test(url); }
export function setPool(p) { pool = p; }              // for tests (pg-mem)
function getPool() {
  if (!pool) {
    const url = process.env.DATABASE_URL;
    if (!url) throw new Error("DATABASE_URL is not set (your Neon connection string).");
    pool = new pg.Pool({ connectionString: url, ssl: needSSL(url) ? { rejectUnauthorized: false } : false, max: 8 });
  }
  return pool;
}
const q = (text, params) => getPool().query(text, params);

// ── Schema ──────────────────────────────────────────
export async function initDb() {
  await q(`CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    mcp_token TEXT UNIQUE NOT NULL,
    created_at TEXT NOT NULL)`);
  await q(`CREATE TABLE IF NOT EXISTS whoop (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    client_id TEXT, client_secret TEXT, access_token TEXT, refresh_token TEXT,
    expires_at BIGINT, scope TEXT, connected_at TEXT)`);
  await q(`CREATE TABLE IF NOT EXISTS user_data (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    targets_json TEXT, food_json TEXT, notes_json TEXT)`);
  await q(`CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL)`);
}

// ── Users ───────────────────────────────────────────
export async function createUser(email, passwordHash) {
  const mcp = newToken(24);
  const { rows } = await q(
    "INSERT INTO users (email, password_hash, mcp_token, created_at) VALUES ($1,$2,$3,$4) RETURNING *",
    [email.toLowerCase().trim(), passwordHash, mcp, new Date().toISOString()]
  );
  const user = rows[0];
  await q("INSERT INTO user_data (user_id, targets_json, food_json, notes_json) VALUES ($1,$2,$3,$4)",
    [user.id, "{}", "{}", "{}"]);
  return user;
}
export async function getUserByEmail(email) {
  const { rows } = await q("SELECT * FROM users WHERE email=$1", [String(email).toLowerCase().trim()]);
  return rows[0] || null;
}
export async function getUserById(id) { const { rows } = await q("SELECT * FROM users WHERE id=$1", [id]); return rows[0] || null; }
export async function getUserByMcpToken(t) { const { rows } = await q("SELECT * FROM users WHERE mcp_token=$1", [t]); return rows[0] || null; }
export async function rotateMcpToken(userId) { const t = newToken(24); await q("UPDATE users SET mcp_token=$1 WHERE id=$2", [t, userId]); return t; }
export async function deleteUser(userId) { await q("DELETE FROM users WHERE id=$1", [userId]); }

// ── Sessions ────────────────────────────────────────
export async function createSession(userId) {
  const token = newToken(32);
  await q("INSERT INTO sessions (token, user_id, created_at) VALUES ($1,$2,$3)", [token, userId, new Date().toISOString()]);
  return token;
}
export async function getSessionUser(token) {
  if (!token) return null;
  const { rows } = await q("SELECT user_id FROM sessions WHERE token=$1", [token]);
  return rows[0] ? getUserById(rows[0].user_id) : null;
}
export async function destroySession(token) { await q("DELETE FROM sessions WHERE token=$1", [token]); }

// ── Whoop creds/tokens (encrypted) ──────────────────
export async function saveWhoopCreds(userId, { client_id, client_secret }) {
  await q(`INSERT INTO whoop (user_id, client_id, client_secret) VALUES ($1,$2,$3)
    ON CONFLICT (user_id) DO UPDATE SET client_id=$2, client_secret=$3`,
    [userId, encrypt(client_id), encrypt(client_secret)]);
}
export async function saveWhoopTokens(userId, { access_token, refresh_token, expires_at, scope }) {
  await q(`UPDATE whoop SET access_token=$2, refresh_token=$3, expires_at=$4, scope=$5,
      connected_at=COALESCE(connected_at,$6) WHERE user_id=$1`,
    [userId, encrypt(access_token), encrypt(refresh_token), expires_at, scope, new Date().toISOString()]);
}
export async function getWhoop(userId) {
  const { rows } = await q("SELECT * FROM whoop WHERE user_id=$1", [userId]);
  const r = rows[0];
  if (!r) return null;
  return {
    client_id: r.client_id ? decrypt(r.client_id) : null,
    client_secret: r.client_secret ? decrypt(r.client_secret) : null,
    access_token: r.access_token ? decrypt(r.access_token) : null,
    refresh_token: r.refresh_token ? decrypt(r.refresh_token) : null,
    expires_at: Number(r.expires_at) || 0,
    scope: r.scope || null,
    connected_at: r.connected_at || null,
  };
}
export async function isConnected(userId) {
  const { rows } = await q("SELECT refresh_token FROM whoop WHERE user_id=$1", [userId]);
  return !!(rows[0] && rows[0].refresh_token);
}

// ── Per-user app data ───────────────────────────────
export async function getUserData(userId) {
  const { rows } = await q("SELECT * FROM user_data WHERE user_id=$1", [userId]);
  const r = rows[0] || {};
  return {
    targets: JSON.parse(r.targets_json || "{}"),
    food_history: JSON.parse(r.food_json || "{}"),
    notes: JSON.parse(r.notes_json || "{}"),
  };
}
export async function saveUserData(userId, data) {
  await q(`INSERT INTO user_data (user_id, targets_json, food_json, notes_json) VALUES ($1,$2,$3,$4)
    ON CONFLICT (user_id) DO UPDATE SET targets_json=$2, food_json=$3, notes_json=$4`,
    [userId, JSON.stringify(data.targets || {}), JSON.stringify(data.food_history || {}), JSON.stringify(data.notes || {})]);
}
