// ─────────────────────────────────────────────────────
// Per-user Whoop API client. Same auto-refresh + rotation logic as the local
// server, but scoped to one user_id, reading/writing ENCRYPTED tokens via db.js.
// A per-user in-flight refresh promise prevents concurrent tool calls (e.g. the
// daily brief's parallel fetches) from spending the same refresh token twice.
// ─────────────────────────────────────────────────────
import { getWhoop, saveWhoopTokens } from "./db.js";

const BASE = process.env.WHOOP_API_BASE || "https://api.prod.whoop.com/developer";
const TOKEN_URL = process.env.WHOOP_TOKEN_URL || "https://api.prod.whoop.com/oauth/oauth2/token";
const EXPIRY_BUFFER_MS = 90_000;

const refreshLocks = new Map(); // userId -> Promise

async function refreshFor(userId) {
  if (refreshLocks.has(userId)) return refreshLocks.get(userId);
  const p = (async () => {
    const w = await getWhoop(userId);
    if (!w?.refresh_token) throw new Error("This account isn't connected to Whoop yet.");
    if (!w.client_id || !w.client_secret) throw new Error("Missing Whoop client credentials for this account.");

    const res = await fetch(TOKEN_URL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        client_id: w.client_id,
        client_secret: w.client_secret,
        scope: "offline",
        refresh_token: w.refresh_token,
      }),
    });
    if (!res.ok) {
      const t = await res.text().catch(() => "");
      throw new Error(`Whoop token refresh failed (${res.status}). The connection may have been revoked — reconnect on the website. ${t}`.trim());
    }
    const d = await res.json();
    await saveWhoopTokens(userId, {
      access_token: d.access_token,
      refresh_token: d.refresh_token || w.refresh_token, // rotate
      expires_at: Date.now() + (Number(d.expires_in) || 3600) * 1000,
      scope: d.scope || w.scope,
    });
    return d.access_token;
  })().finally(() => refreshLocks.delete(userId));
  refreshLocks.set(userId, p);
  return p;
}

async function accessTokenFor(userId) {
  const w = await getWhoop(userId);
  if (!w) throw new Error("This account isn't connected to Whoop yet.");
  if (w.access_token && w.expires_at && w.expires_at - EXPIRY_BUFFER_MS > Date.now()) return w.access_token;
  return refreshFor(userId);
}

// Build an api() bound to a single user. Returns null on 404 (no data).
export function whoopClientFor(userId) {
  async function api(path, params = {}, _retried = false) {
    const token = await accessTokenFor(userId);
    const url = new URL(`${BASE}${path}`);
    Object.entries(params).forEach(([k, v]) => v != null && url.searchParams.set(k, String(v)));

    let res;
    try {
      res = await fetch(url.toString(), { headers: { Authorization: `Bearer ${token}`, Accept: "application/json" } });
    } catch (e) { throw new Error(`Network error reaching Whoop: ${e.message}`); }

    if (res.status === 401 && !_retried) { await refreshFor(userId); return api(path, params, true); }
    if (res.status === 401) throw new Error("Whoop rejected the token even after refresh — reconnect on the website.");
    if (res.status === 429) throw new Error(`Whoop rate limit hit. Retry in ~${res.headers.get("x-ratelimit-reset") || "60"}s.`);
    if (res.status === 404) return null;
    if (!res.ok) { const t = await res.text().catch(() => ""); throw new Error(`Whoop API error ${res.status} on ${path}: ${t}`.trim()); }
    return res.json();
  }
  return { api };
}

// Used by the website's OAuth callback to do the initial code->token exchange.
export async function exchangeAuthCode({ client_id, client_secret, code, redirect_uri }) {
  const res = await fetch(TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "authorization_code", code, client_id, client_secret, redirect_uri }),
  });
  if (!res.ok) { const t = await res.text().catch(() => ""); throw new Error(`Token exchange failed (${res.status}): ${t}`.trim()); }
  return res.json(); // { access_token, refresh_token, expires_in, scope }
}
