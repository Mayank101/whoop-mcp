// ─────────────────────────────────────────────────────
// Whoop MCP — shared core (tools, handlers, auth, Whoop API).
// Imported by index.js (stdio) and server-remote.js (HTTP) so the two
// transports never drift. No transport code lives here.
// ─────────────────────────────────────────────────────
import { readFileSync, writeFileSync, existsSync } from "fs";
import { join } from "path";
import { homedir } from "os";

// ─────────────────────────────────────────────────────
// CONFIG — all from env
// ─────────────────────────────────────────────────────
// Easiest setup: run `npm run connect` once. It writes client credentials +
// tokens into the store file, so the Claude Desktop config needs NO secrets.
// Alternatively, env vars also work:
//   WHOOP_CLIENT_ID + WHOOP_CLIENT_SECRET + WHOOP_REFRESH_TOKEN  (auto-refresh)
//   WHOOP_ACCESS_TOKEN  (quick test, ~1 hour)
const ENV_REFRESH = process.env.WHOOP_REFRESH_TOKEN;
const ENV_ACCESS = process.env.WHOOP_ACCESS_TOKEN;

const BASE = process.env.WHOOP_API_BASE || "https://api.prod.whoop.com/developer";
const TOKEN_URL = process.env.WHOOP_TOKEN_URL || "https://api.prod.whoop.com/oauth/oauth2/token";
const STORE = process.env.WHOOP_STORE || join(homedir(), ".whoop-mcp-data.json");

// Client credentials come from env first, else from the store file that
// `npm run connect` writes. Passing the auth object avoids a re-read.
function resolveClientCreds(auth) {
  return {
    id: process.env.WHOOP_CLIENT_ID || auth?.client_id || null,
    secret: process.env.WHOOP_CLIENT_SECRET || auth?.client_secret || null,
  };
}

// Refresh this many ms before the access token actually expires.
const EXPIRY_BUFFER_MS = 90_000;

// ─────────────────────────────────────────────────────
// LOCAL STORE — food log + targets + auth tokens
// One JSON file. All writes are read-modify-write of the whole object,
// so auth + food never clobber each other within this single process.
// ─────────────────────────────────────────────────────
function load() {
  try { return existsSync(STORE) ? JSON.parse(readFileSync(STORE, "utf8")) : {}; }
  catch { return {}; }
}
function save(data) {
  writeFileSync(STORE, JSON.stringify(data, null, 2));
}

// ─────────────────────────────────────────────────────
// DATES — everything in the user's LOCAL timezone.
// `new Date().toISOString()` is UTC and silently shifts the day boundary
// (e.g. anything logged after ~6:30pm in IST lands on "tomorrow"). We key
// food and match Whoop timestamps by local calendar date instead.
// ─────────────────────────────────────────────────────
function localDate(d = new Date()) {
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, "0");
  const day = String(d.getDate()).padStart(2, "0");
  return `${y}-${m}-${day}`;
}
function today() { return localDate(); }
function dateAgo(n) { const d = new Date(); d.setDate(d.getDate() - n); return localDate(d); }
function isoToLocalDate(iso) { return iso ? localDate(new Date(iso)) : null; }
function prevLocalDate(dateStr) {
  if (!dateStr) return null;
  const d = new Date(`${dateStr}T12:00:00`); // noon avoids DST edge weirdness
  d.setDate(d.getDate() - 1);
  return localDate(d);
}

// ─────────────────────────────────────────────────────
// AUTH — automatic access-token refresh with rotation handling.
// Whoop rotates refresh tokens: every refresh returns a NEW refresh token
// and invalidates the old one, so we persist it each time. A single
// in-flight refresh promise prevents parallel calls (the daily brief)
// from refreshing at once and spending the same refresh token twice.
// ─────────────────────────────────────────────────────
let refreshPromise = null;

function loadAuth() {
  const store = load();
  return store._auth || null;
}
function saveAuth(auth) {
  const store = load();          // fresh read so we don't clobber food data
  store._auth = auth;
  save(store);
}
function seedAuthFromEnv() {
  const auth = {};
  if (ENV_REFRESH) auth.refresh_token = ENV_REFRESH;
  if (ENV_ACCESS) { auth.access_token = ENV_ACCESS; auth.expires_at = 0; } // unknown expiry
  return Object.keys(auth).length ? auth : null;
}
function canRefresh(auth) {
  const { id, secret } = resolveClientCreds(auth);
  return Boolean(auth?.refresh_token && id && secret);
}

function configError() {
  return new Error(
    "Whoop is not connected yet.\n\n" +
    "EASIEST: run `npm run connect` once in the project folder. It opens your\n" +
    "browser, you authorize, and it saves your credentials locally — after that\n" +
    "the Claude Desktop config only needs the path to index.js (no secrets).\n\n" +
    "First create an app at developer.whoop.com with these scopes:\n" +
    "offline read:recovery read:sleep read:cycles read:workout read:profile read:body_measurement\n\n" +
    "ALTERNATIVE (env vars in the Claude config): WHOOP_CLIENT_ID + WHOOP_CLIENT_SECRET\n" +
    "+ WHOOP_REFRESH_TOKEN, or WHOOP_ACCESS_TOKEN for a ~1-hour quick test."
  );
}

async function getAccessToken() {
  const auth = loadAuth() || seedAuthFromEnv();
  if (!auth) throw configError();

  const now = Date.now();
  const valid = auth.access_token && auth.expires_at && (auth.expires_at - EXPIRY_BUFFER_MS) > now;
  if (valid) return auth.access_token;

  if (canRefresh(auth)) return refreshAccessToken();

  // No refresh capability. If we have a (possibly unknown-expiry) access token, try it;
  // the 401 path will explain clearly if it has expired.
  if (auth.access_token) return auth.access_token;
  throw configError();
}

function refreshAccessToken() {
  if (refreshPromise) return refreshPromise;      // coalesce concurrent refreshes
  refreshPromise = doRefresh().finally(() => { refreshPromise = null; });
  return refreshPromise;
}

async function doRefresh() {
  const auth = loadAuth() || seedAuthFromEnv();
  if (!auth?.refresh_token) throw configError();
  const { id, secret } = resolveClientCreds(auth);
  if (!id || !secret) throw new Error("Missing Whoop client ID/secret. Run `npm run connect`, or set WHOOP_CLIENT_ID and WHOOP_CLIENT_SECRET.");

  const body = new URLSearchParams({
    grant_type: "refresh_token",
    client_id: id,
    client_secret: secret,
    scope: "offline",
    refresh_token: auth.refresh_token,
  });

  let res;
  try {
    res = await fetch(TOKEN_URL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
    });
  } catch (e) {
    throw new Error(`Network error contacting Whoop to refresh token: ${e.message}`);
  }

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(
      `Token refresh failed (${res.status}). Your refresh token is likely expired or revoked — ` +
      `re-authorize at developer.whoop.com and update WHOOP_REFRESH_TOKEN. ${text}`.trim()
    );
  }

  const data = await res.json();
  const next = {
    ...auth,                                                  // keep client_id/secret + anything else
    access_token: data.access_token,
    refresh_token: data.refresh_token || auth.refresh_token,  // rotate (fallback just in case)
    expires_at: Date.now() + (Number(data.expires_in) || 3600) * 1000,
    scope: data.scope || auth.scope,
    refreshed_at: new Date().toISOString(),
  };
  saveAuth(next);
  return next.access_token;
}

// ─────────────────────────────────────────────────────
// WHOOP API — v2 endpoints. Auto-attaches a fresh token, refreshes on 401
// once, returns null on 404 (caller decides what "no data" means).
// ─────────────────────────────────────────────────────
async function api(path, params = {}, _retried = false) {
  const token = await getAccessToken();

  const url = new URL(`${BASE}${path}`);
  Object.entries(params).forEach(([k, v]) => v != null && url.searchParams.set(k, String(v)));

  let res;
  try {
    res = await fetch(url.toString(), {
      headers: { Authorization: `Bearer ${token}`, Accept: "application/json" },
    });
  } catch (e) {
    throw new Error(`Network error reaching Whoop (${path}): ${e.message}`);
  }

  if (res.status === 401 && !_retried && canRefresh(loadAuth())) {
    await refreshAccessToken();            // token expired early or was rotated; refresh + retry once
    return api(path, params, true);
  }
  if (res.status === 401) {
    throw new Error(
      canRefresh(loadAuth())
        ? "Whoop rejected the token even after refresh (401). The refresh token is likely revoked — re-authorize and update WHOOP_REFRESH_TOKEN."
        : "Whoop access token expired (401). Tokens last ~1 hour. Add WHOOP_CLIENT_ID, WHOOP_CLIENT_SECRET and WHOOP_REFRESH_TOKEN for automatic refresh."
    );
  }
  if (res.status === 429) {
    const reset = res.headers.get("x-ratelimit-reset");
    throw new Error(`Whoop rate limit hit. Retry in ~${reset || "60"}s.`);
  }
  if (res.status === 404) return null;     // no such resource — not an error, just no data
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`Whoop API error ${res.status} on ${path}: ${text}`.trim());
  }
  return res.json();
}

const recordsOf = (res) => (res && Array.isArray(res.records)) ? res.records : [];

// Return a record's score object ONLY if it is fully scored.
// Whoop score_state ∈ { SCORED, PENDING_SCORE, UNSCORABLE }. Reading .score
// while PENDING/UNSCORABLE is how the old code crashed on normal mornings.
function scored(record) {
  if (!record) return null;
  if (record.score_state && record.score_state !== "SCORED") return null;
  return record.score || null;
}
function stateNote(record, label) {
  const st = record?.score_state || "NO_DATA";
  if (st === "PENDING_SCORE") return `${label} is still being scored (PENDING_SCORE) — normal shortly after waking, check back soon.`;
  if (st === "UNSCORABLE") return `${label} could not be scored by Whoop (UNSCORABLE) — usually means the strap wasn't worn.`;
  return `${label} not available yet (no synced data).`;
}

// ─────────────────────────────────────────────────────
// FORMATTERS
// ─────────────────────────────────────────────────────
const n = (x) => (x == null ? null : Math.round(x));
const ms2h = (ms) => {
  if (!ms) return null;
  const h = Math.floor(ms / 3600000), m = Math.round((ms % 3600000) / 60000);
  return h ? `${h}h ${m}m` : `${m}m`;
};
const pct = (v, t) => (t ? Math.round((v / t) * 100) : 0);
const rvZone = (s) => s >= 67 ? "🟢 Green — Optimal" : s >= 34 ? "🟡 Yellow — Moderate" : "🔴 Red — Rest";
const strainDesc = (s) => { const v = parseFloat(s); return v < 8 ? "Light" : v < 14 ? "Moderate" : v < 18 ? "Hard" : "All out"; };
const proteinNeeded = (strain, weight_kg) => {
  const base = weight_kg ? weight_kg * 1.6 : 120;
  const v = parseFloat(strain);
  const mult = v < 8 ? 0.9 : v < 14 ? 1.0 : v < 18 ? 1.15 : 1.3;
  return Math.round(base * mult);
};

// ─────────────────────────────────────────────────────
// SPORT NAMES
// ─────────────────────────────────────────────────────
const SPORTS = {
  0:"Activity",1:"Running",16:"Baseball",17:"Basketball",18:"Rowing",
  21:"Football",22:"Golf",24:"Ice Hockey",25:"Lacrosse",27:"Rugby",
  28:"Sailing",30:"Soccer",33:"Swimming",34:"Tennis",36:"Volleyball",
  39:"Boxing",42:"Dance",43:"Pilates",44:"Walking",45:"Strength Training",
  47:"Cycling",48:"Triathlon",49:"CrossFit",50:"Functional Fitness",
  53:"Hiking",56:"Martial Arts",57:"Mountain Biking",60:"Racquetball",
  61:"Rock Climbing",65:"Snowboarding",66:"Spinning",67:"Stairmaster",
  68:"Surfing",71:"HIIT",73:"Weightlifting",74:"Yoga",76:"Elliptical",
  82:"Meditation",91:"Yoga",92:"Bouldering",97:"Jump Rope",
  98:"Obstacle Course Racing",113:"Pickleball",126:"Cycling",
};

// ─────────────────────────────────────────────────────
// COACHING FRAMEWORK
// Honest framing: real, well-supported principles only. Associations are
// presented as patterns to notice, never as precise causal numbers, because
// recovery is driven primarily by HRV/RHR/sleep and a handful of daily food
// logs cannot establish causation. No invented "Xg costs Yms HRV" figures.
// ─────────────────────────────────────────────────────
const COACH = `
You are a knowledgeable, careful health coach with a background in HRV, sleep,
exercise science, and nutrition. You have access to the user's real Whoop data
plus any food they have logged. You are a supportive guide, not a doctor.

REASONING FRAMEWORK:
1. NUMBERS FIRST — cite the user's actual data points, never vague statements.
2. MECHANISM, HONESTLY — explain plausible "why" using established physiology,
   but flag when something is a general principle vs. a confirmed cause for THIS user.
3. PERSONALISED — use their real strain, weight, targets; avoid generic ranges.
4. ONE ACTION — end with exactly one specific, doable thing for today.
5. TOMORROW — say what to watch for, framed as a hypothesis to check, not a promise.

HONESTY RULES (important):
- Recovery score is computed by Whoop mainly from HRV, resting HR, and sleep — NOT food.
  Nutrition can influence those inputs, but treat food→recovery as an association to
  watch, not a proven lever. Never state a specific "Xg protein = Yms HRV" figure;
  there is no such established constant.
- With fewer than ~10-14 logged days, call correlations "early patterns, not proof."
- Don't predict tomorrow's numbers with false confidence. Use "tends to" / "often."
- If something looks medically off (e.g. sustained high RHR, low SpO2, fever-range
  skin temp), gently suggest checking with a clinician rather than diagnosing.

WELL-SUPPORTED PRINCIPLES YOU MAY USE:
- Adequate protein supports muscle repair and adaptation, especially after hard training;
  spreading it across the day is sensible. Roughly 1.6–2.2 g/kg/day suits most active people.
- Deep (slow-wave) sleep is when most physical repair happens; consistently very low deep
  sleep alongside high strain is worth flagging.
- REM supports cognitive recovery. Alcohol and late heavy meals tend to fragment sleep.
- A meaningful HRV drop from a personal baseline often coincides with stress, illness,
  under-recovery, alcohol, or poor sleep — investigate rather than assume one cause.
- Caffeine late in the day and late large meals are common, checkable culprits for poor sleep.

RESPONSE FORMAT (use these sections):
⚡ SCORE & STATUS — what it is, one-line verdict
📊 YOUR NUMBERS — the key metrics, clean
🔗 WHAT MIGHT BE BEHIND IT — mechanism, hedged honestly
🌙 SLEEP — what the sleep data shows
🎯 TODAY'S ACTION — one specific thing, with amounts
📈 WHAT TO WATCH — a hypothesis to check tomorrow (not a guarantee)
`;

// ─────────────────────────────────────────────────────
// MCP SERVER

export const TOOLS = [
    { name: "get_recovery", description: "Get today's Whoop recovery score, HRV (RMSSD), resting heart rate, SpO2, and skin temperature, plus a 3-day HRV baseline and the previous day's strain that drove today's recovery.", inputSchema: { type: "object", properties: {} } },
    { name: "get_sleep", description: "Get last night's complete sleep data — performance %, efficiency %, all stages (deep/REM/light/awake), disturbances, latency, respiratory rate, cycles, and sleep need vs actual.", inputSchema: { type: "object", properties: { include_naps: { type: "boolean", description: "Include naps as well as main sleep (default: false)" } } } },
    { name: "get_strain", description: "Get today's strain, calories, heart rate, and all workouts with HR zones, distance, and intensity.", inputSchema: { type: "object", properties: {} } },
    { name: "get_weekly_trend", description: "Get the last 7-14 days of recovery, HRV, strain, and sleep, joined by calendar date and cross-referenced with the food log where available. Use to spot patterns.", inputSchema: { type: "object", properties: { days: { type: "number", description: "Days to look back, 1-14 (default: 7)" } } } },
    { name: "get_profile", description: "Get the user's name, email, height, weight, and max heart rate, plus weight-based protein targets.", inputSchema: { type: "object", properties: {} } },
    { name: "log_food", description: "Log a food item to today's nutrition log. From a photo: identify the item and ESTIMATE calories/macros yourself, and set estimated=true. If the user adds a comment with a quantity or detail (e.g. '2 rotis', 'big bowl', 'extra ghee'), use that to override your estimate; leave the rest estimated. If the user gives exact macros, set estimated=false.", inputSchema: { type: "object", required: ["name", "quantity", "unit", "meal"], properties: { name: { type: "string" }, quantity: { type: "number" }, unit: { type: "string", enum: ["g","ml","cup","piece","bowl","plate","tbsp","scoop"] }, meal: { type: "string", enum: ["Breakfast","Lunch","Dinner","Snack","Pre-workout","Post-workout"] }, calories: { type: "number" }, protein: { type: "number" }, carbs: { type: "number" }, fat: { type: "number" }, fiber: { type: "number" }, estimated: { type: "boolean", description: "true if calories/macros are your visual estimate (e.g. from a photo), false if user-provided exact values. Default true." }, note: { type: "string", description: "Optional user comment about the item (portion, prep, corrections)." } } } },
    { name: "log_water", description: "Log water intake for the day. Accumulates across the day. Accept ml or litres; convert to ml. e.g. 'drank 500ml' or '2L at EOD'.", inputSchema: { type: "object", required: ["amount_ml"], properties: { amount_ml: { type: "number", description: "Amount in millilitres (convert litres → ml before calling: 2L = 2000)." }, date: { type: "string", description: "YYYY-MM-DD (default: today, local)" } } } },
    { name: "get_nutrition", description: "Get a day's food log with macro totals, progress vs targets, protein gap, water intake, and repair-window status. Marks whether totals include estimated (photo) items.", inputSchema: { type: "object", properties: { date: { type: "string", description: "Date YYYY-MM-DD (default: today, local time)" } } } },
    { name: "set_targets", description: "Set daily nutrition targets — calories, protein, carbs, fat, fiber, water (ml) — and bodyweight for strain-adjusted protein.", inputSchema: { type: "object", properties: { calories: { type: "number" }, protein: { type: "number" }, carbs: { type: "number" }, fat: { type: "number" }, fiber: { type: "number" }, water_ml: { type: "number" }, weight_kg: { type: "number" } } } },
    { name: "get_daily_brief", description: "THE FLAGSHIP TOOL — pulls all Whoop data + nutrition in one call and returns a structured dataset for Claude to generate a personalised morning brief. Handles not-yet-scored mornings gracefully.", inputSchema: { type: "object", properties: {} } },
    { name: "get_correlation", description: "Show how nutrition (protein, calories) tracks against next-day recovery and HRV over recent days. Presented as patterns, not proof — needs enough logged days to be meaningful.", inputSchema: { type: "object", properties: {} } },
    { name: "ask_coach", description: "Ask a specific health question; Claude pulls the relevant Whoop data and answers with the coaching framework. e.g. 'Should I train hard today?', 'Why is my HRV low?'", inputSchema: { type: "object", required: ["question"], properties: { question: { type: "string" } } } },
    { name: "log_note", description: "Save a short free-text note capturing how you feel or context Whoop can't measure (e.g. 'felt wrecked today', 'started creatine', 'stressful week at work', 'slept badly — noisy neighbours', 'travelled, jet-lagged'). Stored verbatim with the date so it can be reviewed against your biometrics later. Just pass the user's words.", inputSchema: { type: "object", required: ["note"], properties: { note: { type: "string", description: "The note in plain language" }, date: { type: "string", description: "YYYY-MM-DD (default: today, local time)" } } } },
    { name: "get_day_report", description: "END-OF-DAY REPORT — pulls today's strain, workouts, last night's sleep, everything logged (food + notes) and targets into one structured wrap-up, so Claude can tell the user how the day actually went, whether they hit their targets, and what to do tonight. Use for 'how was my day', 'end of day report', 'wrap up my day'.", inputSchema: { type: "object", properties: { date: { type: "string", description: "YYYY-MM-DD (default: today, local time)" } } } },
    { name: "get_week_review", description: "THE COACH-WITH-MEMORY TOOL — assembles the last 7-14 days of Whoop biometrics (recovery, HRV, RHR, sleep, strain) together with logged food and personal notes into one structured review, so Claude can answer 'how was my week and what can I improve'. Works from any fresh chat because the history lives in the store, not the conversation.", inputSchema: { type: "object", properties: { days: { type: "number", description: "Days to review, 1-14 (default: 7)" } } } },
];

function respond(data) {
  return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
}
function notReady(message, extra = {}) {
  return respond({ data_ready: false, status: message, ...extra });
}
// food totals
const sumMacro = (arr, key) => arr.reduce((a, f) => a + (f[key] || 0), 0);
function macroTotals(log) {
  return {
    calories: sumMacro(log, "calories"),
    protein: sumMacro(log, "protein"),
    carbs: sumMacro(log, "carbs"),
    fat: sumMacro(log, "fat"),
    fiber: sumMacro(log, "fiber"),
  };
}
const DEFAULT_TARGETS = { calories: 2400, protein: 140, carbs: 280, fat: 75, fiber: 35 };

export async function handleTool(name, args = {}) {
  try {
    // ── GET RECOVERY ────────────────────────────────
    if (name === "get_recovery") {
      const [recRes, cycleRes] = await Promise.all([
        api("/v2/recovery", { limit: 3 }),
        api("/v2/cycle", { limit: 2 }),
      ]);

      const recs = recordsOf(recRes);
      const latest = recs[0];
      if (!latest) return notReady("No recovery records returned. Your Whoop may not have synced, or you have no cycles yet.");

      const sc = scored(latest);
      if (!sc) return notReady(stateNote(latest, "Recovery"), { score_state: latest.score_state || null });

      // baseline from SCORED recoveries only
      const scoredHrv = recs.map(scored).filter(Boolean).map((s) => n(s.hrv_rmssd_milli)).filter(Boolean);
      const hrv = n(sc.hrv_rmssd_milli);
      const baselineHrv = scoredHrv.length ? Math.round(scoredHrv.reduce((a, b) => a + b, 0) / scoredHrv.length) : hrv;
      const prevHrv = scoredHrv[1] ?? null;
      const rv = n(sc.recovery_score);
      const prevCycleSc = scored(recordsOf(cycleRes)[1]);
      const prevStrain = prevCycleSc?.strain;

      return respond({
        coach_context: COACH,
        recovery: {
          score_pct: rv,
          zone: rvZone(rv),
          hrv_ms: hrv,
          hrv_vs_yesterday_ms: prevHrv != null ? hrv - prevHrv : null,
          hrv_vs_3day_baseline_ms: hrv - baselineHrv,
          baseline_hrv_ms: baselineHrv,
          resting_hr_bpm: n(sc.resting_heart_rate),
          spo2_pct: sc.spo2_percentage != null ? sc.spo2_percentage.toFixed(1) : null,
          skin_temp_celsius: sc.skin_temp_celsius != null ? sc.skin_temp_celsius.toFixed(1) : null,
          previous_day_strain: prevStrain != null ? prevStrain.toFixed(1) : null,
          previous_day_strain_level: prevStrain != null ? strainDesc(prevStrain) : null,
          user_calibrating: sc.user_calibrating ?? null,
        },
        coaching_note:
          `Recovery ${rv}% (${rvZone(rv)}). HRV ${hrv}ms (${hrv - baselineHrv >= 0 ? "+" : ""}${hrv - baselineHrv}ms vs 3-day baseline ${baselineHrv}ms). ` +
          `Prev-day strain: ${prevStrain != null ? prevStrain.toFixed(1) : "unknown"}. ` +
          `Treat any food link as a pattern to explore, not a proven cause.`,
      });
    }

    // ── GET SLEEP ───────────────────────────────────
    if (name === "get_sleep") {
      const sleepRes = await api("/v2/activity/sleep", { limit: args.include_naps ? 3 : 2 });
      const all = recordsOf(sleepRes);
      const candidates = args.include_naps ? all : all.filter((s) => !s.nap);
      const s = candidates[0];
      if (!s) return notReady("No sleep records found. Has your Whoop synced today?");

      const sc = scored(s);
      if (!sc) return notReady(stateNote(s, "Sleep"), { score_state: s.score_state || null });

      const stages = sc.stage_summary || {};
      const need = sc.sleep_needed || {};
      const deepMs = stages.total_slow_wave_sleep_time_milli || 0;
      const remMs = stages.total_rem_sleep_time_milli || 0;
      const lightMs = stages.total_light_sleep_time_milli || 0;
      const totalSleep = deepMs + remMs + lightMs;
      const debt = need.baseline_milli ? need.baseline_milli - totalSleep : null;
      const disturbances = stages.disturbance_count ?? null;

      return respond({
        coach_context: COACH,
        sleep: {
          date: isoToLocalDate(s.end || s.start),
          is_nap: Boolean(s.nap),
          performance_pct: n(sc.sleep_performance_percentage),
          efficiency_pct: n(sc.sleep_efficiency_percentage),
          consistency_pct: sc.sleep_consistency_percentage != null ? n(sc.sleep_consistency_percentage) : null,
          total_sleep: ms2h(totalSleep),
          in_bed: ms2h(stages.total_in_bed_time_milli),
          sleep_need: ms2h(need.baseline_milli),
          sleep_debt: debt != null ? (debt > 0 ? `-${ms2h(debt)}` : "✓ Fully rested") : null,
          extra_need_from_strain: ms2h(need.need_from_recent_strain_milli),
          extra_need_from_debt: ms2h(need.need_from_sleep_debt_milli),
          stages: {
            deep_sws: ms2h(deepMs),
            deep_pct: totalSleep ? Math.round((deepMs / totalSleep) * 100) : null,
            deep_adequate: deepMs >= 5400000,
            rem: ms2h(remMs),
            rem_pct: totalSleep ? Math.round((remMs / totalSleep) * 100) : null,
            light: ms2h(lightMs),
            awake: ms2h(stages.total_awake_time_milli),
            sleep_cycles: stages.sleep_cycle_count ?? null,
            disturbances,
          },
          respiratory_rate_rpm: sc.respiratory_rate != null ? sc.respiratory_rate.toFixed(2) : null,
          sleep_start: s.start,
          sleep_end: s.end,
        },
        coaching_note:
          `Sleep ${n(sc.sleep_performance_percentage)}% performance. ` +
          `Deep SWS ${ms2h(deepMs)} (${deepMs >= 5400000 ? "✓ adequate" : "⚠ below ~90min — physical repair may be incomplete"}). ` +
          (disturbances != null
            ? (disturbances > 4
                ? `⚠ ${disturbances} disturbances — worth checking late meals, alcohol, room temp, stress. `
                : `${disturbances} disturbances (normal). `)
            : "") +
          `${stages.sleep_cycle_count ?? "?"} sleep cycles.`,
      });
    }

    // ── GET STRAIN ──────────────────────────────────
    if (name === "get_strain") {
      const [cycleRes, workoutRes] = await Promise.all([
        api("/v2/cycle", { limit: 1 }),
        api("/v2/activity/workout", { limit: 10, start: new Date(Date.now() - 86400000).toISOString() }),
      ]);

      const cycle = recordsOf(cycleRes)[0];
      const sc = scored(cycle);
      const strain = sc?.strain != null ? sc.strain.toFixed(1) : null;
      const kcal = sc?.kilojoule != null ? Math.round(sc.kilojoule * 0.239) : null;

      const todayStr = today();
      const workouts = recordsOf(workoutRes)
        .filter((w) => isoToLocalDate(w.start) === todayStr)
        .map((w) => {
          const ws = scored(w) || {};
          const zones = ws.zone_durations || {};
          return {
            sport: w.sport_name || SPORTS[w.sport_id] || `Sport ${w.sport_id}`,
            start: w.start, end: w.end,
            scored: Boolean(scored(w)),
            strain: ws.strain != null ? ws.strain.toFixed(1) : null,
            zone: ws.strain != null ? strainDesc(ws.strain) : null,
            kcal: ws.kilojoule != null ? Math.round(ws.kilojoule * 0.239) : null,
            avg_hr: ws.average_heart_rate ?? null,
            max_hr: ws.max_heart_rate ?? null,
            distance_km: ws.distance_meter != null ? (ws.distance_meter / 1000).toFixed(2) : null,
            altitude_gain_m: ws.altitude_gain_meter != null ? Math.round(ws.altitude_gain_meter) : null,
            heart_rate_zones: {
              zone1_easy: ms2h(zones.zone_zero_milli ?? zones.zone_one_milli),
              zone2_aerobic: ms2h(zones.zone_two_milli),
              zone3_threshold: ms2h(zones.zone_three_milli),
              zone4_hard: ms2h(zones.zone_four_milli),
              zone5_max: ms2h(zones.zone_five_milli),
            },
          };
        });

      const weight = load().targets?.weight_kg;

      return respond({
        coach_context: COACH,
        strain: {
          day_strain: strain,
          level: strain != null ? strainDesc(strain) : "Still accumulating / not yet scored",
          score_state: cycle?.score_state || null,
          calories_burned: kcal,
          avg_hr_bpm: sc?.average_heart_rate ?? null,
          max_hr_bpm: sc?.max_heart_rate ?? null,
          kilojoules: sc?.kilojoule ?? null,
          workouts,
          workouts_today: workouts.length,
        },
        protein_target_for_this_strain: strain != null && weight ? proteinNeeded(strain, weight) : null,
        coaching_note:
          `Day strain ${strain ?? "still accumulating"}${strain != null ? ` (${strainDesc(strain)})` : ""}. ` +
          (weight
            ? `Heuristic protein target for this strain: ~${proteinNeeded(strain ?? 0, weight)}g. `
            : "Set weight via set_targets for strain-adjusted protein. ") +
          `${workouts.length} workout(s) today.`,
      });
    }

    // ── GET WEEKLY TREND ────────────────────────────
    if (name === "get_weekly_trend") {
      const days = Math.min(Math.max(args.days || 7, 1), 14);
      const fetchN = days + 2; // headroom for naps / gaps

      const [recRes, cycleRes, sleepRes] = await Promise.all([
        api("/v2/recovery", { limit: fetchN }),
        api("/v2/cycle", { limit: fetchN }),
        api("/v2/activity/sleep", { limit: fetchN + 2 }),
      ]);

      // Join by LOCAL calendar date instead of by list index.
      const recByDate = {};
      for (const r of recordsOf(recRes)) { const d = isoToLocalDate(r.created_at); if (d && !(d in recByDate)) recByDate[d] = r; }
      const cycleByDate = {};
      for (const c of recordsOf(cycleRes)) { const d = isoToLocalDate(c.start); if (d && !(d in cycleByDate)) cycleByDate[d] = c; }
      const sleepByDate = {};
      for (const s of recordsOf(sleepRes)) { if (s.nap) continue; const d = isoToLocalDate(s.end || s.start); if (d && !(d in sleepByDate)) sleepByDate[d] = s; }

      const store = load();
      const foodHistory = store.food_history || {};
      const targets = store.targets || DEFAULT_TARGETS;

      const trend = [];
      for (let i = 0; i < days; i++) {
        const date = dateAgo(i);
        const recSc = scored(recByDate[date]);
        const cySc = scored(cycleByDate[date]);
        const slSc = scored(sleepByDate[date]);
        // nutrition that PRECEDED this morning's recovery = previous calendar day's food
        const food = foodHistory[prevLocalDate(date)] || [];
        const protein = sumMacro(food, "protein");
        const calories = sumMacro(food, "calories");

        trend.push({
          date,
          recovery_pct: recSc ? n(recSc.recovery_score) : null,
          hrv_ms: recSc ? n(recSc.hrv_rmssd_milli) : null,
          rhr_bpm: recSc ? n(recSc.resting_heart_rate) : null,
          strain: cySc?.strain != null ? cySc.strain.toFixed(1) : null,
          sleep_pct: slSc ? n(slSc.sleep_performance_percentage) : null,
          deep_sleep: slSc ? ms2h(slSc.stage_summary?.total_slow_wave_sleep_time_milli) : null,
          disturbances: slSc?.stage_summary?.disturbance_count ?? null,
          prev_day_protein_g: food.length ? protein : null,
          prev_day_calories: food.length ? calories : null,
          prev_day_protein_pct_of_target: food.length && targets.protein ? pct(protein, targets.protein) : null,
        });
      }

      const recvVals = trend.map((d) => d.recovery_pct).filter((v) => v != null);
      const hrvVals = trend.map((d) => d.hrv_ms).filter((v) => v != null);
      const avg = (a) => (a.length ? Math.round(a.reduce((x, y) => x + y, 0) / a.length) : null);
      const scoredDays = trend.filter((d) => d.recovery_pct != null);
      const best = scoredDays.length ? [...scoredDays].sort((a, b) => b.recovery_pct - a.recovery_pct)[0] : null;
      const worst = scoredDays.length ? [...scoredDays].sort((a, b) => a.recovery_pct - b.recovery_pct)[0] : null;
      const foodDays = trend.filter((d) => d.prev_day_protein_g != null).length;

      return respond({
        coach_context: COACH,
        weekly_trend: {
          period: `Last ${days} days`,
          averages: { recovery_pct: avg(recvVals), hrv_ms: avg(hrvVals) },
          best_day: best,
          worst_day: worst,
          days: trend,
          days_with_recovery: scoredDays.length,
          days_with_food_data: foodDays,
        },
        coaching_note:
          `${days}-day avg: ${avg(recvVals) ?? "—"}% recovery, ${avg(hrvVals) ?? "—"}ms HRV across ${scoredDays.length} scored day(s). ` +
          (best && worst ? `Best ${best.date} (${best.recovery_pct}%), worst ${worst.date} (${worst.recovery_pct}%). ` : "") +
          `Food data for ${foodDays}/${days} days. ` +
          (foodDays < 4 ? "Too few logged days to read a nutrition pattern yet." : "Enough to look for early patterns — present as patterns, not proof."),
      });
    }

    // ── GET PROFILE ─────────────────────────────────
    if (name === "get_profile") {
      const [profile, body] = await Promise.all([
        api("/v2/user/profile/basic"),
        api("/v2/user/measurement/body"),
      ]);
      if (!profile && !body) return notReady("Could not load profile/body data from Whoop.");

      const weight = body?.weight_kilogram ?? null;
      // Auto-save weight if user hasn't set one (re-load AFTER awaits so we keep fresh auth tokens)
      if (weight) {
        const stored = load();
        if (!stored.targets?.weight_kg) { stored.targets = { ...stored.targets, weight_kg: weight }; save(stored); }
      }

      return respond({
        profile: {
          name: profile ? `${profile.first_name ?? ""} ${profile.last_name ?? ""}`.trim() : null,
          email: profile?.email ?? null,
          user_id: profile?.user_id ?? null,
          height_m: body?.height_meter ?? null,
          weight_kg: weight,
          max_hr_bpm: body?.max_heart_rate ?? null,
        },
        personalised_targets: {
          protein_base_g: weight ? Math.round(weight * 1.6) : null,
          protein_hard_day_g: weight ? Math.round(weight * 2.0) : null,
          note: "Heuristic: ~1.6 g/kg baseline, ~2.0 g/kg on hard training days (strain 14+).",
        },
      });
    }

    // ── LOG FOOD ────────────────────────────────────
    if (name === "log_food") {
      const store = load();
      const key = today();
      store.food_history = store.food_history || {};
      store.food_history[key] = store.food_history[key] || [];

      const entry = {
        id: Date.now(),
        timestamp: new Date().toISOString(),
        name: args.name, quantity: args.quantity, unit: args.unit, meal: args.meal,
        calories: args.calories ?? null, protein: args.protein ?? null,
        carbs: args.carbs ?? null, fat: args.fat ?? null, fiber: args.fiber ?? null,
        estimated: args.estimated !== false,   // default: treat as an estimate unless told exact
        note: args.note || null,
      };
      store.food_history[key].push(entry);
      save(store);

      const log = store.food_history[key];
      const totals = macroTotals(log);
      const targets = store.targets || DEFAULT_TARGETS;
      const proteinGap = Math.max(0, (targets.protein || 0) - totals.protein);
      const repairHours = Math.max(0, 22 - new Date().getHours());
      const anyEstimated = log.some((f) => f.estimated);

      return respond({
        logged: entry,
        today_totals: totals,
        targets,
        protein_gap_g: proteinGap,
        calories_remaining: Math.max(0, (targets.calories || 0) - totals.calories),
        protein_pct_of_target: pct(totals.protein, targets.protein),
        repair_window_hours: repairHours,
        items_logged_today: log.length,
        totals_include_estimates: anyEstimated,
        status:
          `✓ ${args.quantity}${args.unit} ${args.name}${entry.estimated ? " (est.)" : ""} logged${entry.note ? ` — "${entry.note}"` : ""}. ` +
          `Running total${anyEstimated ? " (~ incl. estimates)" : ""}: ${totals.protein}g protein (${pct(totals.protein, targets.protein)}% of ${targets.protein}g), ${totals.calories} kcal.` +
          (proteinGap > 0 ? ` ${proteinGap}g protein to go.` : " ✓ Protein target hit."),
      });
    }

    // ── LOG WATER ───────────────────────────────────
    if (name === "log_water") {
      const ml = Math.round(Number(args.amount_ml) || 0);
      if (ml <= 0) throw new Error("Provide a positive amount in ml (e.g. 500, or 2000 for 2L).");
      const store = load();
      const key = args.date || today();
      store.water = store.water || {};
      store.water[key] = (store.water[key] || 0) + ml;
      save(store);
      const total = store.water[key];
      const targetMl = store.targets?.water_ml || null;
      return respond({
        status: `✓ ${ml >= 1000 ? (ml/1000).toFixed(2) + "L" : ml + "ml"} logged. ` +
          `Today: ${(total/1000).toFixed(2)}L` + (targetMl ? ` of ${(targetMl/1000).toFixed(1)}L (${pct(total, targetMl)}%).` : "."),
        date: key,
        water_ml_today: total,
        water_ml_target: targetMl,
        water_pct: targetMl ? pct(total, targetMl) : null,
      });
    }

    // ── GET NUTRITION ───────────────────────────────
    if (name === "get_nutrition") {
      const store = load();
      const key = args.date || today();
      const log = (store.food_history || {})[key] || [];
      const targets = store.targets || DEFAULT_TARGETS;
      const totals = macroTotals(log);
      const gaps = {
        protein: Math.max(0, (targets.protein || 0) - totals.protein),
        calories: Math.max(0, (targets.calories || 0) - totals.calories),
        carbs: Math.max(0, (targets.carbs || 0) - totals.carbs),
        fat: Math.max(0, (targets.fat || 0) - totals.fat),
      };
      const repairHours = Math.max(0, 22 - new Date().getHours());
      const proteinPct = pct(totals.protein, targets.protein);
      const anyEstimated = log.some((f) => f.estimated);
      const waterMl = (store.water || {})[key] || 0;
      const waterTarget = targets.water_ml || null;

      return respond({
        coach_context: COACH,
        nutrition: {
          date: key,
          items_logged: log.length,
          totals, targets, gaps,
          totals_include_estimates: anyEstimated,
          protein_pct: proteinPct,
          calories_pct: pct(totals.calories, targets.calories),
          water_ml: waterMl,
          water_l: +(waterMl / 1000).toFixed(2),
          water_target_ml: waterTarget,
          water_pct: waterTarget ? pct(waterMl, waterTarget) : null,
          repair_window_hours: repairHours,
          repair_window_status: repairHours > 4 ? "✓ Open" : repairHours > 0 ? "⚠ Closing" : "✗ Closed",
          food_log: log.map((f) => ({
            time: f.timestamp?.split("T")[1]?.substring(0, 5),
            meal: f.meal, name: f.name, qty: `${f.quantity}${f.unit}`,
            protein: f.protein, calories: f.calories,
            estimated: f.estimated || false, note: f.note || null,
          })),
        },
        coaching_note:
          `${key === today() ? "Today" : key}: ${totals.protein}g protein (${proteinPct}% of ${targets.protein}g), ${totals.calories} kcal` +
          (anyEstimated ? " (~ includes photo estimates)" : "") + ". " +
          (waterMl ? `Water ${(waterMl/1000).toFixed(2)}L${waterTarget ? ` of ${(waterTarget/1000).toFixed(1)}L` : ""}. ` : "") +
          (gaps.protein > 0 ? `${gaps.protein}g protein to go. ` : "✓ Protein target hit. ") +
          `Repair window: ${repairHours > 0 ? `${repairHours}h left` : "closed"}.` +
          (proteinPct < 60 ? " Note: protein is running low today — a common (not guaranteed) factor in feeling under-recovered." : ""),
      });
    }

    // ── SET TARGETS ─────────────────────────────────
    if (name === "set_targets") {
      const store = load();
      store.targets = { ...store.targets };
      ["calories", "protein", "carbs", "fat", "fiber", "water_ml", "weight_kg"].forEach((k) => {
        if (args[k] != null) store.targets[k] = args[k];
      });
      save(store);
      return respond({
        status: "✓ Targets saved.",
        targets: store.targets,
        note: store.targets.weight_kg
          ? `At ${store.targets.weight_kg}kg: ~${Math.round(store.targets.weight_kg * 1.6)}g base / ~${Math.round(store.targets.weight_kg * 2.0)}g hard-day protein (heuristic).`
          : "Add weight_kg for strain-adjusted protein targets.",
      });
    }

    // ── DAILY BRIEF ─────────────────────────────────
    if (name === "get_daily_brief") {
      const [recRes, sleepRes, cycleRes, workoutRes] = await Promise.all([
        api("/v2/recovery", { limit: 4 }),
        api("/v2/activity/sleep", { limit: 3 }),
        api("/v2/cycle", { limit: 2 }),
        api("/v2/activity/workout", { limit: 10, start: new Date(Date.now() - 86400000).toISOString() }),
      ]);

      const recs = recordsOf(recRes);
      const latest = recs[0];
      const recSc = scored(latest);

      // Recovery may not be scored yet — still return sleep/nutrition so the brief is useful.
      const recovery_pending = latest && !recSc ? (latest.score_state || "PENDING") : (!latest ? "NO_DATA" : null);

      const scoredHrv = recs.map(scored).filter(Boolean).map((s) => n(s.hrv_rmssd_milli)).filter(Boolean);
      const baselineHrv = scoredHrv.length ? Math.round(scoredHrv.reduce((a, b) => a + b, 0) / scoredHrv.length) : null;

      const sleep = recordsOf(sleepRes).find((s) => !s.nap);
      const sleepSc = scored(sleep);
      const stages = sleepSc?.stage_summary || {};
      const deepMs = stages.total_slow_wave_sleep_time_milli || 0;
      const remMs = stages.total_rem_sleep_time_milli || 0;
      const totalSleepMs = deepMs + remMs + (stages.total_light_sleep_time_milli || 0);

      const prevCycleSc = scored(recordsOf(cycleRes)[1]);
      const prevStrain = prevCycleSc?.strain;

      const store = load();
      const targets = store.targets || DEFAULT_TARGETS;
      const weight = store.targets?.weight_kg;
      const todayFood = (store.food_history || {})[today()] || [];
      const yesterdayFood = (store.food_history || {})[dateAgo(1)] || [];
      const yProtein = sumMacro(yesterdayFood, "protein");
      const yCalories = sumMacro(yesterdayFood, "calories");
      const tProtein = sumMacro(todayFood, "protein");
      const tCalories = sumMacro(todayFood, "calories");
      const proteinDeficit = Math.max(0, (targets.protein || 0) - yProtein);
      const strainAdjProtein = prevStrain != null && weight ? proteinNeeded(prevStrain, weight) : targets.protein;
      const repairHours = Math.max(0, 22 - new Date().getHours());

      const todayWorkouts = recordsOf(workoutRes)
        .filter((w) => isoToLocalDate(w.start) === today())
        .map((w) => { const ws = scored(w) || {}; return {
          sport: w.sport_name || SPORTS[w.sport_id] || "Workout",
          strain: ws.strain != null ? ws.strain.toFixed(1) : null,
          kcal: ws.kilojoule != null ? Math.round(ws.kilojoule * 0.239) : null,
        }; });

      const hrv = recSc ? n(recSc.hrv_rmssd_milli) : null;

      return respond({
        system_prompt: COACH,
        recovery_status: recovery_pending
          ? (recovery_pending === "NO_DATA"
              ? "No recovery synced yet — open the Whoop app to sync, then ask again."
              : `Recovery not scored yet (${recovery_pending}) — normal early morning. Sleep & nutrition below are still usable.`)
          : "scored",
        todays_whoop: recSc ? {
          recovery_score: n(recSc.recovery_score),
          zone: rvZone(n(recSc.recovery_score)),
          hrv_ms: hrv,
          hrv_vs_baseline: baselineHrv != null ? hrv - baselineHrv : null,
          baseline_hrv_ms: baselineHrv,
          resting_hr_bpm: n(recSc.resting_heart_rate),
          spo2_pct: recSc.spo2_percentage != null ? recSc.spo2_percentage.toFixed(1) : null,
          skin_temp_c: recSc.skin_temp_celsius != null ? recSc.skin_temp_celsius.toFixed(1) : null,
          previous_day_strain: prevStrain != null ? prevStrain.toFixed(1) : null,
          previous_day_strain_level: prevStrain != null ? strainDesc(prevStrain) : null,
        } : null,
        last_nights_sleep: sleepSc ? {
          performance_pct: n(sleepSc.sleep_performance_percentage),
          efficiency_pct: n(sleepSc.sleep_efficiency_percentage),
          total_sleep: ms2h(totalSleepMs),
          deep_sws: ms2h(deepMs),
          deep_adequate: deepMs >= 5400000,
          rem: ms2h(remMs),
          disturbances: stages.disturbance_count ?? null,
          sleep_cycles: stages.sleep_cycle_count ?? null,
          respiratory_rate: sleepSc.respiratory_rate != null ? sleepSc.respiratory_rate.toFixed(1) : null,
          start: sleep?.start, end: sleep?.end,
        } : (sleep ? { status: stateNote(sleep, "Sleep") } : null),
        yesterdays_nutrition: {
          data_available: yesterdayFood.length > 0,
          protein_g: yesterdayFood.length ? yProtein : null,
          calories: yesterdayFood.length ? yCalories : null,
          protein_target_g: targets.protein,
          strain_adjusted_protein_target_g: strainAdjProtein,
          protein_deficit_g: yesterdayFood.length ? proteinDeficit : null,
          protein_pct_of_target: yesterdayFood.length ? pct(yProtein, targets.protein) : null,
        },
        todays_nutrition_so_far: {
          protein_g: tProtein, calories: tCalories, items_logged: todayFood.length,
          protein_gap_g: Math.max(0, (targets.protein || 0) - tProtein),
          repair_window_hours: repairHours,
          repair_window_status: repairHours > 4 ? "Open" : repairHours > 0 ? "Closing" : "Closed",
        },
        todays_workouts: todayWorkouts,
        user_profile: { weight_kg: weight ?? null, targets },
        instruction_for_claude:
          `Using the system_prompt framework, write the morning brief with the exact sections ` +
          `(⚡ SCORE & STATUS → 📊 YOUR NUMBERS → 🔗 WHAT MIGHT BE BEHIND IT → 🌙 SLEEP → 🎯 TODAY'S ACTION → 📈 WHAT TO WATCH). ` +
          `Use the real numbers above. ` +
          (recovery_pending ? `Recovery isn't scored yet — lead with sleep + today's plan and tell them to re-run once recovery posts. ` : "") +
          (yesterdayFood.length === 0
            ? `No food logged yesterday — note this limits the nutrition angle and invite them to log meals. `
            : `Yesterday's nutrition is available — relate protein_pct_of_target to recovery as a PATTERN to watch, never a proven cause. `) +
          `If HRV is well below baseline, flag it as the key signal worth investigating (sleep, alcohol, stress, illness — not just food).`,
      });
    }

    // ── CORRELATION ─────────────────────────────────
    if (name === "get_correlation") {
      const store = load();
      const targets = store.targets || { protein: 140 };
      const foodHistory = store.food_history || {};
      const recRes = await api("/v2/recovery", { limit: 14 });

      const points = recordsOf(recRes).slice(0, 14).map((rec) => {
        const sc = scored(rec);
        const date = isoToLocalDate(rec.created_at);
        const prevFood = foodHistory[prevLocalDate(date)] || [];
        const protein = sumMacro(prevFood, "protein");
        const calories = sumMacro(prevFood, "calories");
        return {
          date,
          recovery_pct: sc ? n(sc.recovery_score) : null,
          hrv_ms: sc ? n(sc.hrv_rmssd_milli) : null,
          prev_day_protein_g: prevFood.length ? protein : null,
          prev_day_calories: prevFood.length ? calories : null,
          protein_pct_of_target: prevFood.length ? pct(protein, targets.protein) : null,
          usable: Boolean(sc && prevFood.length),
        };
      });

      const usable = points.filter((p) => p.usable);
      const highP = usable.filter((p) => p.prev_day_protein_g >= targets.protein * 0.85);
      const lowP = usable.filter((p) => p.prev_day_protein_g < targets.protein * 0.7);
      const avg = (arr, key) => (arr.length ? Math.round(arr.reduce((a, b) => a + (b[key] || 0), 0) / arr.length) : null);
      const enough = usable.length >= 5 && highP.length >= 2 && lowP.length >= 2;

      return respond({
        coach_context: COACH,
        correlation: {
          usable_day_pairs: usable.length,
          enough_data: enough,
          data_points: points,
          high_protein_days: { threshold: `≥ ${Math.round(targets.protein * 0.85)}g`, count: highP.length, avg_recovery_pct: avg(highP, "recovery_pct"), avg_hrv_ms: avg(highP, "hrv_ms") },
          low_protein_days: { threshold: `< ${Math.round(targets.protein * 0.7)}g`, count: lowP.length, avg_recovery_pct: avg(lowP, "recovery_pct"), avg_hrv_ms: avg(lowP, "hrv_ms") },
          recovery_difference_pct: enough ? avg(highP, "recovery_pct") - avg(lowP, "recovery_pct") : null,
          hrv_difference_ms: enough ? avg(highP, "hrv_ms") - avg(lowP, "hrv_ms") : null,
        },
        instruction_for_claude:
          enough
            ? `Describe the association between protein and next-day recovery/HRV using the averages above. ` +
              `Frame it explicitly as an early pattern from a small sample, NOT proof and NOT a per-gram constant. ` +
              `Mention confounders (sleep, alcohol, stress, training load) that could explain the gap.`
            : `There isn't enough data yet (need ≥5 usable day-pairs with ≥2 high- and ≥2 low-protein days). ` +
              `Tell the user what's missing and encourage consistent logging — do NOT manufacture a correlation from the few points available.`,
      });
    }

    // ── ASK COACH ───────────────────────────────────
    if (name === "ask_coach") {
      const q = (args.question || "").toLowerCase();
      const wantsSleep = /sleep|tired|rest|nap/.test(q);
      const wantsStrain = /train|workout|strain|exercise|run|lift|ride/.test(q);
      const wantsNutrition = /eat|protein|food|nutrition|meal|carb|calorie/.test(q);

      const pulls = [api("/v2/recovery", { limit: 2 })];
      if (wantsSleep) pulls.push(api("/v2/activity/sleep", { limit: 2 }));
      if (wantsStrain) pulls.push(api("/v2/cycle", { limit: 1 }));
      const results = await Promise.allSettled(pulls);

      const context = {};
      let idx = 0;
      const rRec = results[idx++];
      if (rRec.status === "fulfilled") {
        const sc = scored(recordsOf(rRec.value)[0]);
        const raw = recordsOf(rRec.value)[0];
        if (sc) context.recovery = { score: n(sc.recovery_score), hrv: n(sc.hrv_rmssd_milli), rhr: n(sc.resting_heart_rate) };
        else if (raw) context.recovery = { status: stateNote(raw, "Recovery") };
      }
      if (wantsSleep) {
        const r = results[idx++];
        if (r.status === "fulfilled") {
          const sl = recordsOf(r.value).find((s) => !s.nap);
          const sc = scored(sl);
          if (sc) context.sleep = { performance: n(sc.sleep_performance_percentage), deep: ms2h(sc.stage_summary?.total_slow_wave_sleep_time_milli), disturbances: sc.stage_summary?.disturbance_count ?? null };
          else if (sl) context.sleep = { status: stateNote(sl, "Sleep") };
        }
      }
      if (wantsStrain) {
        const r = results[idx++];
        if (r.status === "fulfilled") {
          const sc = scored(recordsOf(r.value)[0]);
          if (sc) context.strain = { score: sc.strain != null ? sc.strain.toFixed(1) : null };
        }
      }

      const store = load();
      const todayFood = (store.food_history || {})[today()] || [];
      const targets = store.targets || {};
      if (wantsNutrition && todayFood.length) {
        context.nutrition = { protein: sumMacro(todayFood, "protein"), calories: sumMacro(todayFood, "calories"), target_protein: targets.protein ?? null, items: todayFood.length };
      }

      return respond({
        system_prompt: COACH,
        question: args.question,
        whoop_context: context,
        nutrition_context: todayFood.length ? context.nutrition : "No food logged today",
        user_targets: targets,
        instruction: `Answer "${args.question}" using the data above and the coaching framework. Cite real numbers, give one clear action, and keep food→recovery talk as patterns, not proven causation.`,
      });
    }

    // ── LOG NOTE ────────────────────────────────────
    if (name === "log_note") {
      const text = String(args.note || "").trim();
      if (!text) throw new Error("Note text is empty — pass the note in plain language.");
      const store = load();
      const key = args.date || today();
      store.notes = store.notes || {};
      store.notes[key] = store.notes[key] || [];
      const entry = { id: Date.now(), timestamp: new Date().toISOString(), text };
      store.notes[key].push(entry);
      save(store);
      return respond({
        status: `✓ Note saved for ${key}.`,
        date: key,
        note: text,
        notes_on_this_day: store.notes[key].length,
      });
    }

    // ── DAY REPORT (end of day) ─────────────────────
    if (name === "get_day_report") {
      const dateKey = args.date || today();
      const isToday = dateKey === today();

      const [cycleRes, sleepRes, workoutRes, recRes] = await Promise.all([
        api("/v2/cycle", { limit: 3 }),
        api("/v2/activity/sleep", { limit: 4 }),
        api("/v2/activity/workout", { limit: 15, start: new Date(Date.now() - 2 * 86400000).toISOString() }),
        api("/v2/recovery", { limit: 2 }),
      ]);

      // Cycle covering this date (Whoop cycles roll at wake, not midnight)
      const cycles = recordsOf(cycleRes);
      const cycle = cycles.find((c) => isoToLocalDate(c.start) === dateKey) || (isToday ? cycles[0] : null);
      const cySc = scored(cycle);
      const strain = cySc?.strain != null ? cySc.strain.toFixed(1) : null;

      // Sleep that ENDED on this date = last night's sleep
      const sleep = recordsOf(sleepRes).find((s) => !s.nap && isoToLocalDate(s.end || s.start) === dateKey);
      const slSc = scored(sleep);
      const st = slSc?.stage_summary || {};
      const deepMs = st.total_slow_wave_sleep_time_milli || 0;
      const totalSleepMs = deepMs + (st.total_rem_sleep_time_milli || 0) + (st.total_light_sleep_time_milli || 0);

      const recSc = scored(recordsOf(recRes)[0]);

      const workouts = recordsOf(workoutRes)
        .filter((w) => isoToLocalDate(w.start) === dateKey)
        .map((w) => { const ws = scored(w) || {}; return {
          sport: w.sport_name || SPORTS[w.sport_id] || "Workout",
          strain: ws.strain != null ? ws.strain.toFixed(1) : null,
          kcal: ws.kilojoule != null ? Math.round(ws.kilojoule * 0.239) : null,
          avg_hr: ws.average_heart_rate ?? null,
          max_hr: ws.max_heart_rate ?? null,
          distance_km: ws.distance_meter != null ? (ws.distance_meter / 1000).toFixed(2) : null,
        }; });

      const store = load();
      const targets = store.targets || DEFAULT_TARGETS;
      const weight = store.targets?.weight_kg;
      const food = (store.food_history || {})[dateKey] || [];
      const notes = ((store.notes || {})[dateKey] || []).map((x) => x.text);
      const totals = macroTotals(food);

      const hour = new Date().getHours();
      const repairHours = Math.max(0, 22 - hour);
      const strainAdjProtein = strain != null && weight ? proteinNeeded(strain, weight) : (targets.protein ?? null);

      return respond({
        coach_context: COACH,
        day_report: {
          date: dateKey,
          is_today: isToday,
          strain: {
            day_strain: strain,
            level: strain != null ? strainDesc(strain) : "not scored yet",
            score_state: cycle?.score_state || null,
            calories_burned: cySc?.kilojoule != null ? Math.round(cySc.kilojoule * 0.239) : null,
            avg_hr_bpm: cySc?.average_heart_rate ?? null,
            max_hr_bpm: cySc?.max_heart_rate ?? null,
            note: "Whoop cycles roll over at wake, not midnight — a cycle can span parts of two calendar days.",
          },
          workouts,
          workouts_logged: workouts.length,
          last_nights_sleep: slSc ? {
            performance_pct: n(slSc.sleep_performance_percentage),
            total_sleep: ms2h(totalSleepMs),
            deep_sws: ms2h(deepMs),
            deep_adequate: deepMs >= 5400000,
            rem: ms2h(st.total_rem_sleep_time_milli),
            disturbances: st.disturbance_count ?? null,
            sleep_need: ms2h(slSc.sleep_needed?.baseline_milli),
          } : null,
          this_mornings_recovery: recSc ? {
            score_pct: n(recSc.recovery_score),
            hrv_ms: n(recSc.hrv_rmssd_milli),
            rhr_bpm: n(recSc.resting_heart_rate),
          } : null,
          nutrition: {
            items_logged: food.length,
            totals,
            targets,
            protein_gap_g: Math.max(0, (targets.protein || 0) - totals.protein),
            calories_gap: Math.max(0, (targets.calories || 0) - totals.calories),
            protein_pct_of_target: pct(totals.protein, targets.protein),
            calories_pct_of_target: pct(totals.calories, targets.calories),
            strain_adjusted_protein_target_g: strainAdjProtein,
            repair_window_hours: isToday ? repairHours : null,
            repair_window_status: !isToday ? "n/a" : repairHours > 4 ? "Open" : repairHours > 0 ? "Closing" : "Closed",
            meals: food.map((f) => ({ meal: f.meal, name: f.name, qty: `${f.quantity}${f.unit}`, protein: f.protein, calories: f.calories })),
          },
          notes,
        },
        instruction_for_claude:
          `Write the end-of-day wrap-up for ${dateKey}. Structure: ` +
          `(1) one-line verdict on the day; ` +
          `(2) 📊 what the body did — strain, workouts, calories, and this morning's recovery for context; ` +
          `(3) 🍽 how nutrition landed vs targets — call out the protein gap plainly and, if the repair window is still open, suggest a concrete way to close it tonight; ` +
          `(4) 🌙 tonight — given today's strain and last night's sleep, what sleep to aim for; ` +
          `(5) one specific thing to carry into tomorrow. ` +
          `Weave in any notes the user logged. ` +
          `If items_logged is 0, say the nutrition side is blank and invite them to log — do NOT invent food. ` +
          `Keep food/recovery links as patterns worth watching, never proven causes. Cite the real numbers above.`,
      });
    }

    // ── WEEK REVIEW ─────────────────────────────────
    if (name === "get_week_review") {
      const days = Math.min(Math.max(args.days || 7, 1), 14);
      const fetchN = days + 2;

      const [recRes, cycleRes, sleepRes] = await Promise.all([
        api("/v2/recovery", { limit: fetchN }),
        api("/v2/cycle", { limit: fetchN }),
        api("/v2/activity/sleep", { limit: fetchN + 2 }),
      ]);

      const recByDate = {};
      for (const r of recordsOf(recRes)) { const d = isoToLocalDate(r.created_at); if (d && !(d in recByDate)) recByDate[d] = r; }
      const cycleByDate = {};
      for (const c of recordsOf(cycleRes)) { const d = isoToLocalDate(c.start); if (d && !(d in cycleByDate)) cycleByDate[d] = c; }
      const sleepByDate = {};
      for (const s of recordsOf(sleepRes)) { if (s.nap) continue; const d = isoToLocalDate(s.end || s.start); if (d && !(d in sleepByDate)) sleepByDate[d] = s; }

      const store = load();
      const foodHistory = store.food_history || {};
      const noteHistory = store.notes || {};
      const targets = store.targets || DEFAULT_TARGETS;

      const daysArr = [];
      for (let i = 0; i < days; i++) {
        const date = dateAgo(i);
        const recSc = scored(recByDate[date]);
        const cySc = scored(cycleByDate[date]);
        const slSc = scored(sleepByDate[date]);
        const st = slSc?.stage_summary || {};
        const totalSleepMs = (st.total_slow_wave_sleep_time_milli || 0) + (st.total_rem_sleep_time_milli || 0) + (st.total_light_sleep_time_milli || 0);
        const food = foodHistory[date] || [];
        const totals = macroTotals(food);
        const dayNotes = (noteHistory[date] || []).map((x) => x.text);
        daysArr.push({
          date,
          recovery_pct: recSc ? n(recSc.recovery_score) : null,
          hrv_ms: recSc ? n(recSc.hrv_rmssd_milli) : null,
          rhr_bpm: recSc ? n(recSc.resting_heart_rate) : null,
          strain: cySc?.strain != null ? cySc.strain.toFixed(1) : null,
          sleep_pct: slSc ? n(slSc.sleep_performance_percentage) : null,
          total_sleep: slSc ? ms2h(totalSleepMs) : null,
          deep_sleep: slSc ? ms2h(st.total_slow_wave_sleep_time_milli) : null,
          disturbances: st.disturbance_count ?? null,
          protein_g: food.length ? totals.protein : null,
          calories: food.length ? totals.calories : null,
          protein_pct_of_target: food.length && targets.protein ? pct(totals.protein, targets.protein) : null,
          notes: dayNotes,
        });
      }

      const nums = (arr) => arr.map(Number).filter((v) => !isNaN(v));
      const vals = (k) => daysArr.map((d) => d[k]).filter((v) => v != null);
      const avg = (arr) => { const a = nums(arr); return a.length ? Math.round(a.reduce((x, y) => x + y, 0) / a.length) : null; };
      const avg1 = (arr) => { const a = nums(arr); return a.length ? (a.reduce((x, y) => x + y, 0) / a.length).toFixed(1) : null; };

      const scoredDays = daysArr.filter((d) => d.recovery_pct != null);
      const best = scoredDays.length ? [...scoredDays].sort((a, b) => b.recovery_pct - a.recovery_pct)[0] : null;
      const worst = scoredDays.length ? [...scoredDays].sort((a, b) => a.recovery_pct - b.recovery_pct)[0] : null;

      // trend: chronological, compare first half vs second half of the window
      const chrono = [...scoredDays].sort((a, b) => (a.date < b.date ? -1 : 1));
      const mid = Math.ceil(chrono.length / 2);
      const firstHalf = chrono.slice(0, mid).map((d) => d.recovery_pct);
      const secondHalf = chrono.slice(mid).map((d) => d.recovery_pct);
      const trendPts = (firstHalf.length && secondHalf.length) ? avg(secondHalf) - avg(firstHalf) : null;

      return respond({
        coach_context: COACH,
        week_review: {
          period: `Last ${days} days`,
          days: daysArr, // newest first
          averages: {
            recovery_pct: avg(vals("recovery_pct")),
            hrv_ms: avg(vals("hrv_ms")),
            rhr_bpm: avg(vals("rhr_bpm")),
            sleep_pct: avg(vals("sleep_pct")),
            strain: avg1(vals("strain")),
            protein_g: avg(vals("protein_g")),
          },
          best_day: best,
          worst_day: worst,
          recovery_trend_pts: trendPts, // +ve = recovery improved across the window
          days_with_recovery: scoredDays.length,
          days_with_food: daysArr.filter((d) => d.protein_g != null).length,
          days_with_notes: daysArr.filter((d) => d.notes.length).length,
        },
        instruction_for_claude:
          `Write the weekly review the user asked for ("how was my week / what can I improve"). Structure: ` +
          `(1) a one-line headline verdict; ` +
          `(2) the arc — did recovery/HRV/sleep trend up or down over the window (use recovery_trend_pts); ` +
          `(3) standouts — the best and worst day, and what co-occurred that day (strain, sleep, food, notes); ` +
          `(4) tie the personal notes to the numbers where they line up, explicitly as PATTERNS to consider, never as proven cause; ` +
          `(5) exactly 1-2 specific, doable things to improve next week. ` +
          `Cite the real numbers above. If days_with_food or days_with_notes is low, say the picture is limited and nudge them to log more — do NOT invent data. ` +
          `Recovery is driven mainly by HRV, resting HR, and sleep; treat food and notes as context worth exploring, not levers proven for this user.`,
      });
    }

    throw new Error(`Unknown tool: ${name}`);
  } catch (err) {
    return { content: [{ type: "text", text: `❌ Error: ${err.message}` }], isError: true };
  }
}

// ─────────────────────────────────────────────────────
// PREDEFINED PROMPTS (MCP prompts capability)
// These surface in Claude as pickable commands. Each one tells Claude which
// tool to call and how to render the result as a premium visual dashboard
// artifact — so "the dashboard" is a prompt, not a separate app.
// ─────────────────────────────────────────────────────
const DASHBOARD_BRIEF = `
Respond DIRECTLY in the conversation as a clean, scannable chat message. Do NOT create an artifact, HTML, or a
downloadable file — keep it in the chat. Make it easy to read at a glance with this shape:

**<one-line verdict — what to do today and why, in bold>**

<zone emoji 🟢/🟡/🔴> Recovery <n>% · <Green/Yellow/Red>
HRV <n>ms (<+/- vs baseline>) · RHR <n> · Sleep <Xh Ym> (deep <Xh Ym>) · Strain <n> yesterday

<If food/notes logged: ONE line tying them to the numbers as a pattern to watch — not proof. Skip if nothing logged.>

**→ Today:** <one specific action>

Keep it tight — a glanceable card in words, not paragraphs. Use only the real values the tool returned. If recovery
isn't scored yet or no food is logged, say so in one line instead of inventing anything (never fabricate numbers or a
protein→HRV constant). Only build a visual artifact if the user explicitly asks for the dashboard.
`;

// Full generic training dashboard, rendered inline via the Visualizer widget.
// Race/goals appear ONLY if the user mentioned them earlier in the chat.
const TRAINING_DASHBOARD = `
Build my training dashboard as an INLINE VISUAL using the Visualizer widget. Do NOT create an artifact, an HTML file,
or output any code — render it inline in the chat with the Visualizer only.

STEP 1 — Fetch from my Whoop MCP tools:
- Latest recovery: score %, HRV (ms), resting HR
- Latest sleep: total sleep, time in bed, bedtime, deep/SWS minutes, sleep need
- Resting HR and HRV for the last 14 days (for trend sparklines)
- All workouts in the last 14 days with sport = running: date, distance, duration, avg HR, max HR, HR-zone durations
- Today's strain and calories if available
- Today's nutrition (get_nutrition): calories + protein totals (note if they include estimates), and water intake (ml/L, and % of target)

STEP 2 — Compute from the run data only:
- Pace per km for each run (duration ÷ distance), formatted m'ss"
- Longest run (km), fastest pace, and best pace among runs with avg HR ≤ 143
- Do NOT invent, estimate, or fill in any value. If a field isn't returned by the MCP, show "—" in that slot.
- Whoop metrics are MEASURED; food calories may be photo ESTIMATES — mark estimated values with "~" and keep them visually distinct from measured data.

STEP 3 — Race & goals (ONLY if I mentioned them earlier in THIS chat):
- If I named a race/event or goals, show a race header (name + date + days remaining from today) and a goals section
  (each goal a card: target, a progress bar from the relevant Whoop metric, and a "current" sub-line).
- If I did NOT mention any race or goals, OMIT the race header and the goals section entirely. Never invent a race,
  a date, or goals.

LAYOUT (mobile width, dark-mode safe, max 2 cards per row):
1. Header: today's date + a live clock (add race name/date + days-remaining ONLY if provided in STEP 3).
2. Three rings: recovery %, sleep as hours-of-need, and WATER (of target — real, from get_nutrition) — each with a one-line sub (HRV/RHR, bedtime/deep, litres so far). If I gave a step count, you may swap steps in; otherwise water.
3. Fuel: calories + protein vs target for today, with "~" if the totals include photo estimates. Goals cards only if goals were provided; otherwise skip.
4. Engine: RHR and HRV as stacked rows — value, 14-day sparkline, delta vs 14-day baseline. Skip VO2 max and HR recovery unless the MCP returns them.
5. Running: a strip of longest / fastest / best@≤143, then a line chart of pace per run with avg HR under each point and dates on the x-axis.

After rendering, list in one short line which fields came from Whoop (measured), which were your estimates (~), and which were "—".
`;

export const PROMPTS = [
  { name: "dashboard",    description: "Your Whoop training dashboard as an inline visual — recovery, sleep, RHR/HRV trends, running. Mention a race or goals in chat first to see goal progress." },
  { name: "morning_read", description: "Your morning read — recovery, sleep & strain as a quick text brief with one clear action." },
  { name: "evening_wrap", description: "End-of-day wrap-up — how today went vs your targets, and what to do tonight." },
  { name: "week_review",  description: "Your weekly review — the arc of the week, standout days, and one thing to improve." },
];

const PROMPT_MAP = {
  morning_read: { tool: "get_daily_brief", title: "Morning Read",
    lead: "Call get_daily_brief, then build my morning read." },
  evening_wrap: { tool: "get_day_report", title: "Evening Wrap",
    lead: "Call get_day_report, then build my end-of-day wrap-up." },
  week_review: { tool: "get_week_review", title: "Week Review",
    lead: "Call get_week_review, then build my weekly review with the week's arc and standout days." },
};

export function getPrompt(name) {
  if (name === "dashboard") {
    return {
      description: "Render my training dashboard as an inline visual",
      messages: [{ role: "user", content: { type: "text", text: TRAINING_DASHBOARD } }],
    };
  }
  const p = PROMPT_MAP[name];
  if (!p) throw new Error(`Unknown prompt: ${name}`);
  return {
    description: `Render "${p.title}"`,
    messages: [{ role: "user", content: { type: "text", text: `${p.lead}\n${DASHBOARD_BRIEF}` } }],
  };
}
