# Whoop Coach — Hosted (Postgres/Neon)

Multi-tenant service: users sign up, connect their own Whoop app, get a private
MCP URL for Claude. Data in Postgres (Neon); secrets encrypted at rest.

## Deploy: Neon + Render (free)

### 1. Database — Neon
1. neon.tech → sign up → create a project.
2. Copy the **pooled** connection string (the host with `-pooler`). It looks like:
   `postgresql://user:pass@ep-xxx-pooler.region.aws.neon.tech/neondb?sslmode=require`

### 2. Push to GitHub
```bash
cd whoop-saas
git init && git add . && git status   # confirm no .env is listed
git commit -m "Whoop Coach SaaS (Postgres)"
git remote add origin https://github.com/YOU/whoop-coach.git
git push -u origin main
```

### 3. Deploy — Render
1. render.com → New → **Web Service** → connect your repo (or New → Blueprint to use `render.yaml`).
2. Runtime Node · Build `npm install` · Start `node server.js` · Plan Free.
3. Environment variables:
   - `DATABASE_URL` = your Neon pooled string
   - `APP_ENCRYPTION_KEY` = output of `npm run keygen` (save a copy!)
   - `PUBLIC_URL` = `https://<your-app>.onrender.com`
   - `DEFAULT_TZ` = `Asia/Kolkata`
4. Deploy. Tables auto-create on first boot (`initDb`).

### 4. Connect yourself
- Add `https://<your-app>.onrender.com/whoop/callback` as a redirect URL in your Whoop app.
- Sign up on your live site → paste Whoop client ID/secret → authorize.
- Copy your `/mcp/<token>` link → Claude → Settings → Connectors → Add custom connector.

## Free-tier caveats (Render)
- Free web services **sleep after ~15 min idle** and are slow to wake. The first
  Claude call after a nap will lag or time out. Options: a cron pinging `/health`
  every 10 min, or upgrade to the cheapest paid instance (always-on).
- Neon free tier also auto-suspends idle databases (fast to resume).
- For a truly always-on live product, use Fly.io (~$2/mo) or a paid Render instance.

## Before real strangers
- [ ] Privacy policy + terms (you store health data).
- [ ] Back up `APP_ENCRYPTION_KEY` (losing it = everyone must reconnect).
- [ ] Rate-limit /signup, /login, /mcp/:token.
- [ ] Email verification + password reset.

## Files
- `lib/db.js` — Postgres data layer (encrypted secrets)
- `lib/crypto.js` — AES-256-GCM + scrypt
- `lib/whoop.js` — per-user Whoop client (refresh + rotation)
- `lib/tools.js` — 14 tools + 3 prompts, per-user via AsyncLocalStorage
- `server.js` — web app + per-user MCP endpoint
- `render.yaml` — Render blueprint · `Dockerfile` — for Fly/others
