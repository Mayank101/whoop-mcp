import express from "express";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { CallToolRequestSchema, ListToolsRequestSchema, ListPromptsRequestSchema, GetPromptRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { hashPassword, verifyPassword, newToken } from "./lib/crypto.js";
import {
  initDb, createUser, getUserByEmail, getUserByMcpToken, rotateMcpToken, deleteUser,
  createSession, getSessionUser, destroySession,
  saveWhoopCreds, saveWhoopTokens, getWhoop, isConnected,
  getUserData, saveUserData,
} from "./lib/db.js";
import { whoopClientFor, exchangeAuthCode } from "./lib/whoop.js";
import { TOOLS, runTool, PROMPTS, getPrompt } from "./lib/tools.js";

const PORT = Number(process.env.PORT || 3000);
const PUBLIC_URL = (process.env.PUBLIC_URL || `http://localhost:${PORT}`).replace(/\/$/, "");
const REDIRECT_URI = `${PUBLIC_URL}/whoop/callback`;
const SCOPES = "offline read:recovery read:sleep read:cycles read:workout read:profile read:body_measurement";
const WHOOP_AUTH_URL = process.env.WHOOP_AUTH_URL || "https://api.prod.whoop.com/oauth/oauth2/auth";
const DEFAULT_TZ = process.env.DEFAULT_TZ || "UTC";

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

function cookies(req) {
  return Object.fromEntries((req.headers.cookie || "").split(";").map((c) => c.trim().split("=").map(decodeURIComponent)).filter((p) => p[0]));
}
async function currentUser(req) { return getSessionUser(cookies(req).sid); }
async function requireUser(req, res, next) {
  const u = await currentUser(req);
  if (!u) return res.redirect("/login");
  req.user = u; next();
}
const oauthStates = new Map();
const cookieOpts = () => `HttpOnly; Path=/; SameSite=Lax; Max-Age=2592000${PUBLIC_URL.startsWith("https") ? "; Secure" : ""}`;

const page = (title, body) => `<!doctype html><html><head><meta charset="utf8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title>
<style>body{font-family:system-ui;max-width:720px;margin:40px auto;padding:0 16px;background:#0b0b0f;color:#e8e8ea;line-height:1.5}
a{color:#8ab4ff}input{width:100%;padding:10px;margin:6px 0 14px;background:#16161c;border:1px solid #2a2a35;border-radius:8px;color:#fff;box-sizing:border-box}
button,.btn{background:#5b8cff;color:#fff;border:0;padding:11px 18px;border-radius:8px;font-size:15px;cursor:pointer;text-decoration:none;display:inline-block}
code,pre{background:#16161c;border:1px solid #2a2a35;border-radius:8px;padding:2px 6px;font-size:13px}pre{padding:14px;overflow:auto;white-space:pre-wrap;word-break:break-all}
.card{background:#101017;border:1px solid #23232e;border-radius:12px;padding:20px;margin:16px 0}.ok{color:#5fd08a}.warn{color:#ffcf6b}.muted{color:#9a9aa6;font-size:14px}</style></head>
<body>${body}</body></html>`;

app.get("/", async (req, res) => {
  if (await currentUser(req)) return res.redirect("/dashboard");
  res.send(page("Whoop Coach", `<h1>Whoop Coach for Claude</h1>
  <p class="muted">Connect your Whoop to Claude — recovery, sleep, strain, food & notes, with weekly coaching. Already pay for Claude? No extra subscription for the assistant.</p>
  <p><a class="btn" href="/signup">Get started</a> &nbsp; <a href="/login">Log in</a></p>`));
});

app.get("/signup", (req, res) => res.send(page("Sign up", `<h1>Create account</h1>
  <form method="post" action="/signup"><label>Email</label><input name="email" type="email" required>
  <label>Password</label><input name="password" type="password" minlength="8" required>
  <button>Create account</button></form><p class="muted">Have one? <a href="/login">Log in</a></p>`)));

app.post("/signup", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password || password.length < 8) return res.send(page("Sign up", `<p class="warn">Email + 8-char password required.</p><a href="/signup">Back</a>`));
  if (await getUserByEmail(email)) return res.send(page("Sign up", `<p class="warn">That email is already registered.</p><a href="/login">Log in</a>`));
  const user = await createUser(email, hashPassword(password));
  const sid = await createSession(user.id);
  res.setHeader("Set-Cookie", `sid=${sid}; ${cookieOpts()}`);
  res.redirect("/dashboard");
});

app.get("/login", (req, res) => res.send(page("Log in", `<h1>Log in</h1>
  <form method="post" action="/login"><label>Email</label><input name="email" type="email" required>
  <label>Password</label><input name="password" type="password" required>
  <button>Log in</button></form><p class="muted">New? <a href="/signup">Sign up</a></p>`)));

app.post("/login", async (req, res) => {
  const user = await getUserByEmail(req.body.email || "");
  if (!user || !verifyPassword(req.body.password || "", user.password_hash))
    return res.send(page("Log in", `<p class="warn">Wrong email or password.</p><a href="/login">Try again</a>`));
  const sid = await createSession(user.id);
  res.setHeader("Set-Cookie", `sid=${sid}; ${cookieOpts()}`);
  res.redirect("/dashboard");
});

app.post("/logout", requireUser, async (req, res) => { await destroySession(cookies(req).sid); res.setHeader("Set-Cookie", "sid=; Path=/; Max-Age=0"); res.redirect("/"); });

app.get("/dashboard", requireUser, async (req, res) => {
  const u = req.user;
  const connected = await isConnected(u.id);
  const mcpUrl = `${PUBLIC_URL}/mcp/${u.mcp_token}`;
  const w = connected ? await getWhoop(u.id) : null;
  const tz = (await getUserData(u.id)).targets.tz || "UTC";

  const block = connected
    ? `<div class="card"><p class="ok">✅ Whoop connected${w?.connected_at ? ` since ${new Date(w.connected_at).toLocaleDateString()}` : ""}.</p>
       <p class="muted">Your private Claude link (treat like a password):</p><pre>${mcpUrl}</pre>
       <p class="muted">In Claude → Settings → Connectors → Add custom connector → paste the URL above.</p>
       <form method="post" action="/mcp-token/rotate"><button>Rotate link</button></form></div>`
    : `<div class="card"><p class="warn">Whoop not connected yet.</p>
       <p class="muted">First create your own app at <a href="https://developer.whoop.com" target="_blank">developer.whoop.com</a> with scopes<br><code>${SCOPES}</code><br>and redirect URL:</p><pre>${REDIRECT_URI}</pre>
       <form method="post" action="/whoop/connect">
       <label>Whoop Client ID</label><input name="client_id" required>
       <label>Whoop Client Secret</label><input name="client_secret" type="password" required>
       <label>Your timezone (IANA, e.g. Asia/Kolkata)</label><input name="tz" value="${tz}">
       <button>Connect Whoop</button></form></div>`;

  res.send(page("Dashboard", `<h1>Dashboard</h1><p class="muted">${u.email} · <form style="display:inline" method="post" action="/logout"><button style="background:#333">Log out</button></form></p>${block}`));
});

app.post("/whoop/connect", requireUser, async (req, res) => {
  const { client_id, client_secret, tz } = req.body;
  if (!client_id || !client_secret) return res.redirect("/dashboard");
  await saveWhoopCreds(req.user.id, { client_id: client_id.trim(), client_secret: client_secret.trim() });
  if (tz) { const d = await getUserData(req.user.id); d.targets = { ...d.targets, tz: tz.trim() }; await saveUserData(req.user.id, d); }
  const state = newToken(16);
  oauthStates.set(state, { userId: req.user.id, exp: Date.now() + 600000 });
  res.redirect(`${WHOOP_AUTH_URL}?${new URLSearchParams({ response_type: "code", client_id: client_id.trim(), redirect_uri: REDIRECT_URI, scope: SCOPES, state })}`);
});

app.get("/whoop/callback", async (req, res) => {
  const { code, state, error } = req.query;
  const s = oauthStates.get(state); oauthStates.delete(state);
  if (error) return res.send(page("Error", `<p class="warn">Whoop authorization failed: ${error}</p><a href="/dashboard">Back</a>`));
  if (!s || s.exp < Date.now()) return res.send(page("Error", `<p class="warn">Login session expired. Try connecting again.</p><a href="/dashboard">Back</a>`));
  try {
    const w = await getWhoop(s.userId);
    const tok = await exchangeAuthCode({ client_id: w.client_id, client_secret: w.client_secret, code, redirect_uri: REDIRECT_URI });
    if (!tok.refresh_token) throw new Error("No refresh token returned — ensure the `offline` scope is enabled on your Whoop app.");
    await saveWhoopTokens(s.userId, { access_token: tok.access_token, refresh_token: tok.refresh_token, expires_at: Date.now() + (Number(tok.expires_in) || 3600) * 1000, scope: tok.scope || SCOPES });
    res.redirect("/dashboard");
  } catch (e) { res.send(page("Error", `<p class="warn">Connection failed: ${e.message}</p><a href="/dashboard">Back</a>`)); }
});

app.post("/mcp-token/rotate", requireUser, async (req, res) => { await rotateMcpToken(req.user.id); res.redirect("/dashboard"); });

// ── PER-USER MCP ENDPOINT ───────────────────────────
app.post("/mcp/:token", async (req, res) => {
  const user = await getUserByMcpToken(req.params.token);
  if (!user) { res.status(401).json({ error: "invalid_mcp_token" }); return; }
  if (!(await isConnected(user.id))) { res.status(409).json({ error: "whoop_not_connected" }); return; }

  const server = new Server({ name: "whoop-health-mcp", version: "3.1.0" }, { capabilities: { tools: {}, prompts: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));
  server.setRequestHandler(ListPromptsRequestSchema, async () => ({ prompts: PROMPTS }));
  server.setRequestHandler(GetPromptRequestSchema, async (r) => getPrompt(r.params.name));
  server.setRequestHandler(CallToolRequestSchema, async (r) => {
    // load this user's data once (async), run the tool with sync accessors, flush once if changed
    let data = await getUserData(user.id);
    let dirty = false;
    const ctx = { api: whoopClientFor(user.id).api, load: () => data, save: (d) => { data = d; dirty = true; }, tz: data.targets?.tz || DEFAULT_TZ };
    const result = await runTool(ctx, r.params.name, r.params.arguments || {});
    if (dirty) await saveUserData(user.id, data);
    return result;
  });

  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
  res.on("close", () => { try { transport.close?.(); server.close?.(); } catch {} });
  try { await server.connect(transport); await transport.handleRequest(req, res, req.body); }
  catch (e) { if (!res.headersSent) res.status(500).json({ error: String(e?.message || e) }); }
});
app.get("/mcp/:token", (req, res) => res.status(405).json({ error: "use_POST" }));
app.get("/health", (req, res) => res.json({ ok: true }));

initDb().then(() => {
  app.listen(PORT, () => console.log(`Whoop Coach SaaS on ${PUBLIC_URL}  (MCP at /mcp/<token>)`));
}).catch((e) => { console.error("DB init failed:", e.message); process.exit(1); });
