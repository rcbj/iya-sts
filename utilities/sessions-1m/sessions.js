// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
// sessions.js — sign in people 1..COUNT through sessions-1m-rp's
// authorization code flow, keep every token set they are issued, refresh each
// before it expires, sign each person in again before their sign-on session
// reaches its 30-day limit, and say once when everybody is signed in and
// nothing is overdue. Then it goes on doing that until it is stopped.
//
//   ./run-sessions.sh                 everything, defaults below
//   COUNT=20 ./run-sessions.sh        twenty people (the smoke test)
//
// Ctrl-C stops it cleanly; run it again and it resumes from sessions.db.
//
// THE PACE IS DECIDED BY THE SERVICE, NOT BY THIS SCRIPT. Logins run
// LOGIN_CONCURRENCY at a time and at most LOGIN_RATE a second; refreshes run
// REFRESH_CONCURRENCY at a time and are always taken first. Logins pause
// whenever the container's memory passes MEM_CEILING_GB or refreshes fall
// behind, and they never pass the person set-passwords.js has reached.
"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { DatabaseSync } = require("node:sqlite");
const c = require("./common");

const env = process.env;
const COUNT = c.cfg.COUNT;
const FIRST = Math.max(1, Number(env.FIRST || 1));
const LOGIN_CONCURRENCY = Math.max(1, Number(env.LOGIN_CONCURRENCY || 8));
const LOGIN_RATE = Math.max(0.1, Number(env.LOGIN_RATE || 40));
const REFRESH_CONCURRENCY = Math.max(1, Number(env.REFRESH_CONCURRENCY || 8));
// Refresh at this fraction of the access token's life, with +-JITTER of it.
const REFRESH_AT = Number(env.REFRESH_AT || 0.8);
const JITTER = Number(env.JITTER || 0.05);
// The sign-on session lasts authn.sessionLifetimeS (30 days, set by
// setup.js); a person is signed in again this long before it ends.
const SESSION_LIFETIME_S = Number(env.SESSION_LIFETIME_S || 2592000);
const RELOGIN_MARGIN_S = Number(env.RELOGIN_MARGIN_S || 86400);
const REFRESH_TTL_S = Number(env.REFRESH_TTL_S || 172800);
const MEM_CEILING = Number(env.MEM_CEILING_GB || 24) * 1024 ** 3;
const PASSWORD_GATE = env.PASSWORD_GATE !== "off";
const STATUS_EVERY_MS = Number(env.STATUS_EVERY_S || 60) * 1000;
const REQUEST_TIMEOUT_MS = Number(env.REQUEST_TIMEOUT_S || 60) * 1000;
const DB_FILE = env.DB_FILE || path.join(c.HERE, "sessions.db");
const STATUS_FILE = path.join(c.HERE, "status.json");
const PW_STATE = path.join(c.HERE, "set-passwords.state.json");

const CLIENT_ID = c.cfg.APP_ID;
const CLIENT_SECRET = c.readSecret(c.cfg.CLIENT_SECRET_FILE);
const BASIC = "Basic " + Buffer.from(encodeURIComponent(CLIENT_ID) + ":" +
  encodeURIComponent(CLIENT_SECRET)).toString("base64");
const PASSWORD = c.peoplePassword();
const ORIGIN = new URL(c.cfg.STS_URL).origin;

// ---- the store --------------------------------------------------------------

// The database holds every person's live tokens: only this user may read it,
// and so the -wal and -shm files SQLite makes beside it (umask covers those).
process.umask(0o077);
const db = new DatabaseSync(DB_FILE);
require("fs").chmodSync(DB_FILE, 0o600);
db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA synchronous = NORMAL;
  CREATE TABLE IF NOT EXISTS people (
    n INTEGER PRIMARY KEY,
    state TEXT NOT NULL,            -- active | failed
    access_token TEXT, id_token TEXT, refresh_token TEXT,
    access_exp INTEGER, id_exp INTEGER, refresh_exp INTEGER,
    signed_in_at INTEGER,           -- this sign-on session's start, ms
    refresh_due INTEGER,            -- ms
    relogin_due INTEGER,            -- ms
    logins INTEGER DEFAULT 0, refreshes INTEGER DEFAULT 0,
    failures INTEGER DEFAULT 0, last_error TEXT, updated_at INTEGER
  );
  CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
`);
const qMeta = db.prepare("SELECT v FROM meta WHERE k = ?");
const qSetMeta = db.prepare(
  "INSERT INTO meta (k, v) VALUES (:k, :v) ON CONFLICT(k) DO UPDATE SET v = excluded.v");
const qUpsert = db.prepare(`
  INSERT INTO people (n, state, access_token, id_token, refresh_token,
    access_exp, id_exp, refresh_exp, signed_in_at, refresh_due, relogin_due,
    logins, refreshes, failures, last_error, updated_at)
  VALUES (:n, 'active', :access_token, :id_token, :refresh_token,
    :access_exp, :id_exp, :refresh_exp, :signed_in_at, :refresh_due,
    :relogin_due, 1, 0, 0, NULL, :now)
  ON CONFLICT(n) DO UPDATE SET state = 'active',
    access_token = excluded.access_token, id_token = excluded.id_token,
    refresh_token = excluded.refresh_token, access_exp = excluded.access_exp,
    id_exp = excluded.id_exp, refresh_exp = excluded.refresh_exp,
    signed_in_at = excluded.signed_in_at, refresh_due = excluded.refresh_due,
    relogin_due = excluded.relogin_due, logins = people.logins + 1,
    last_error = NULL, updated_at = excluded.updated_at`);
const qRefreshed = db.prepare(`
  UPDATE people SET access_token = :access_token,
    id_token = COALESCE(:id_token, id_token),
    refresh_token = COALESCE(:refresh_token, refresh_token),
    access_exp = :access_exp, id_exp = COALESCE(:id_exp, id_exp),
    refresh_exp = COALESCE(:refresh_exp, refresh_exp),
    refresh_due = :refresh_due, refreshes = refreshes + 1,
    last_error = NULL, updated_at = :now WHERE n = :n`);
const qFailed = db.prepare(`
  UPDATE people SET failures = failures + 1, last_error = :err,
    updated_at = :now WHERE n = :n`);
const qInsertFailed = db.prepare(`
  INSERT INTO people (n, state, failures, last_error, updated_at)
  VALUES (:n, 'failed', 1, :err, :now)
  ON CONFLICT(n) DO UPDATE SET failures = people.failures + 1,
    last_error = excluded.last_error, updated_at = excluded.updated_at`);
const qRefreshToken = db.prepare(
  "SELECT refresh_token FROM people WHERE n = ?");

function meta(k, dflt) {
  const row = qMeta.get(k);
  return row ? row.v : dflt;
}

// Writes are batched into one transaction a second.
let inTx = false;
function write(stmt, args) {
  if (!inTx) { db.exec("BEGIN"); inTx = true; }
  stmt.run(args);
}
function commit() {
  if (inTx) { db.exec("COMMIT"); inTx = false; }
}

// ---- a min-heap of (due, n, kind) in typed arrays ---------------------------
// kind 0 = refresh, 1 = sign in again. A person's due times live in the
// heap; an entry whose time no longer matches the person's is stale and
// skipped when it surfaces.

class Heap {
  constructor(cap) {
    this.due = new Float64Array(cap);
    this.n = new Int32Array(cap);
    this.kind = new Uint8Array(cap);
    this.size = 0;
  }
  grow() {
    const cap = this.due.length * 2;
    const d = new Float64Array(cap); d.set(this.due); this.due = d;
    const n = new Int32Array(cap); n.set(this.n); this.n = n;
    const k = new Uint8Array(cap); k.set(this.kind); this.kind = k;
  }
  swap(i, j) {
    const d = this.due[i]; this.due[i] = this.due[j]; this.due[j] = d;
    const n = this.n[i]; this.n[i] = this.n[j]; this.n[j] = n;
    const k = this.kind[i]; this.kind[i] = this.kind[j]; this.kind[j] = k;
  }
  push(due, n, kind) {
    if (this.size === this.due.length) this.grow();
    let i = this.size++;
    this.due[i] = due; this.n[i] = n; this.kind[i] = kind;
    while (i > 0) {
      const p = (i - 1) >> 1;
      if (this.due[p] <= this.due[i]) break;
      this.swap(i, p); i = p;
    }
  }
  peekDue() { return this.size ? this.due[0] : Infinity; }
  pop() {
    const top = { due: this.due[0], n: this.n[0], kind: this.kind[0] };
    this.size -= 1;
    if (this.size > 0) {
      this.due[0] = this.due[this.size];
      this.n[0] = this.n[this.size];
      this.kind[0] = this.kind[this.size];
      let i = 0;
      for (;;) {
        const l = 2 * i + 1, r = l + 1;
        let m = i;
        if (l < this.size && this.due[l] < this.due[m]) m = l;
        if (r < this.size && this.due[r] < this.due[m]) m = r;
        if (m === i) break;
        this.swap(i, m); i = m;
      }
    }
    return top;
  }
}

// What each person's current due times are, so a stale heap entry is known.
const refreshDue = new Float64Array(COUNT + 2);
const reloginDue = new Float64Array(COUNT + 2);
const active = new Uint8Array(COUNT + 2);
const heap = new Heap(1 << 16);

// ---- counters ---------------------------------------------------------------

const stats = {
  logins: 0, loginFailures: 0, gaveUp: 0, refreshes: 0, refreshFailures: 0,
  relogins: 0, outages: 0, reasons: new Map(),
  latency: { login: [], refresh: [] }
};
function noteReason(r) {
  stats.reasons.set(r, (stats.reasons.get(r) || 0) + 1);
}
function noteLatency(kind, ms) {
  const a = stats.latency[kind];
  a.push(ms);
  if (a.length > 2000) a.splice(0, a.length - 2000);
}
function pct(a, p) {
  if (!a.length) return 0;
  const s = Array.from(a).sort((x, y) => x - y);
  return s[Math.min(s.length - 1, Math.floor(p * s.length))];
}

// ---- HTTP -------------------------------------------------------------------

// 8081 is redeployed by other work while this runs. A refused connection or
// a 502/503/504 (the store refusing commits while the service shuts down)
// says the SERVICE is away, not that this person failed: it throws an
// outage, which pauses everything and puts the person back, uncounted.
async function http(url, opts, jar) {
  const headers = Object.assign({ "user-agent": c.USER_AGENT }, opts.headers);
  if (jar && jar.cookies.size) headers.cookie = jar.header();
  let res;
  try {
    res = await fetch(url, {
      method: opts.method || "GET", headers, body: opts.body,
      redirect: "manual", signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS)
    });
  } catch (e) {
    const err = new FlowError("unreachable",
      String((e.cause && e.cause.code) || e.message));
    err.outage = true;
    throw err;
  }
  if (res.status === 502 || res.status === 503 || res.status === 504) {
    const text = await res.text().catch(() => "");
    const err = new FlowError("unavailable", res.status + " " +
                              text.slice(0, 160));
    err.outage = true;
    throw err;
  }
  if (jar) jar.take(res);
  return res;
}

function absolute(loc) {
  return new URL(loc, c.cfg.STS_URL).toString();
}

class FlowError extends Error {
  constructor(reason, detail) {
    super(reason + (detail ? ": " + detail : ""));
    this.reason = reason;
  }
}

function dueFromTtl(now, ttlS) {
  const base = ttlS * 1000 * REFRESH_AT;
  const jitter = ttlS * 1000 * JITTER * (Math.random() * 2 - 1);
  return now + Math.max(30000, base + jitter);
}

function tokenRow(n, tok, now, signedInAt) {
  const ttl = Number(tok.expires_in || 3600);
  const idc = tok.id_token ? c.jwtClaims(tok.id_token) : {};
  return {
    n, now,
    access_token: tok.access_token || null,
    id_token: tok.id_token || null,
    refresh_token: tok.refresh_token || null,
    access_exp: now + ttl * 1000,
    id_exp: idc.exp ? idc.exp * 1000 : null,
    refresh_exp: tok.refresh_token ? now + REFRESH_TTL_S * 1000 : null,
    signed_in_at: signedInAt,
    refresh_due: dueFromTtl(now, ttl),
    relogin_due: signedInAt + (SESSION_LIFETIME_S - RELOGIN_MARGIN_S) * 1000
  };
}

// One person through the authorization code flow, as a browser would.
async function signIn(n) {
  const jar = new c.CookieJar();
  const verifier = c.b64url(crypto.randomBytes(32));
  const challenge = c.b64url(crypto.createHash("sha256").update(verifier)
    .digest());
  const state = c.b64url(crypto.randomBytes(16));
  const nonce = c.b64url(crypto.randomBytes(16));
  const q = new URLSearchParams({
    response_type: "code", client_id: CLIENT_ID,
    redirect_uri: c.cfg.REDIRECT_URI,
    scope: "openid profile offline_access", state, nonce,
    code_challenge: challenge, code_challenge_method: "S256"
  });
  let res = await http(c.cfg.STS_URL + "/oauth2/authorize?" + q, {}, jar);
  let loc = res.headers.get("location") || "";
  await res.arrayBuffer().catch(() => null);
  const m = /[?&]authn=([^&]+)/.exec(loc);
  if (res.status !== 302 || !m) {
    throw new FlowError("authorize", res.status + " " + loc.slice(0, 120));
  }
  const id = decodeURIComponent(m[1]);

  res = await http(c.cfg.STS_URL + "/authn-api/pending/" +
                   encodeURIComponent(id),
                   { headers: { accept: "application/json" } }, jar);
  const pending = await res.json().catch(() => ({}));
  if (res.status !== 200 || !pending.csrf) {
    throw new FlowError("pending", String(res.status));
  }

  const signedInAt = Date.now();
  res = await http(c.cfg.STS_URL + "/authn-api/pending/" +
                   encodeURIComponent(id) + "/password", {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json",
               origin: ORIGIN, "x-csrf-token": pending.csrf },
    body: JSON.stringify({ username: c.uidOf(n), password: PASSWORD })
  }, jar);
  const answer = await res.json().catch(() => ({}));
  if (res.status === 429) throw new FlowError("rate-limited");
  if (res.status !== 200 || answer.next !== "redirect" || !answer.location) {
    throw new FlowError("password",
      res.status + " next=" + (answer.next || "") + " " +
      String(answer.message || answer.error || "").slice(0, 160));
  }

  res = await http(absolute(answer.location), {}, jar);
  loc = res.headers.get("location") || "";
  await res.arrayBuffer().catch(() => null);
  if (res.status !== 302 || !loc.startsWith(c.cfg.REDIRECT_URI)) {
    throw new FlowError("code", res.status + " " + loc.slice(0, 160));
  }
  const back = new URL(loc).searchParams;
  if (back.get("error")) {
    throw new FlowError("code-error", back.get("error") + " " +
                        String(back.get("error_description") || "").slice(0, 160));
  }
  if (back.get("state") !== state || !back.get("code")) {
    throw new FlowError("code-state");
  }

  res = await http(c.cfg.STS_URL + "/oauth2/token", {
    method: "POST",
    headers: { authorization: BASIC,
               "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "authorization_code",
      code: back.get("code"), redirect_uri: c.cfg.REDIRECT_URI,
      code_verifier: verifier }).toString()
  });
  const tok = await res.json().catch(() => ({}));
  if (res.status !== 200 || !tok.access_token) {
    throw new FlowError("token", res.status + " " + (tok.error || "") + " " +
                        String(tok.error_description || "").slice(0, 160));
  }
  if (!tok.refresh_token) throw new FlowError("no-refresh-token");
  const idc = tok.id_token ? c.jwtClaims(tok.id_token) : {};
  if (tok.id_token && idc.nonce !== nonce) throw new FlowError("nonce");
  return tokenRow(n, tok, Date.now(), signedInAt);
}

async function refresh(n) {
  const row = qRefreshToken.get(n);
  if (!row || !row.refresh_token) throw new FlowError("no-refresh-token");
  const res = await http(c.cfg.STS_URL + "/oauth2/token", {
    method: "POST",
    headers: { authorization: BASIC,
               "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "refresh_token",
      refresh_token: row.refresh_token }).toString()
  });
  const tok = await res.json().catch(() => ({}));
  if (res.status !== 200 || !tok.access_token) {
    const fatal = res.status === 400 || res.status === 401;
    const e = new FlowError(fatal ? "refresh-refused" : "refresh",
      res.status + " " + (tok.error || "") + " " +
      String(tok.error_description || "").slice(0, 160));
    e.fatal = fatal;
    throw e;
  }
  const now = Date.now();
  const ttl = Number(tok.expires_in || 3600);
  const idc = tok.id_token ? c.jwtClaims(tok.id_token) : {};
  return {
    n, now,
    access_token: tok.access_token,
    id_token: tok.id_token || null,
    refresh_token: tok.refresh_token || null,
    access_exp: now + ttl * 1000,
    id_exp: idc.exp ? idc.exp * 1000 : null,
    refresh_exp: tok.refresh_token ? now + REFRESH_TTL_S * 1000 : null,
    refresh_due: dueFromTtl(now, ttl)
  };
}

// ---- the work ---------------------------------------------------------------

let stopping = false;
let loginCursor = Number(meta("loginCursor", String(FIRST)));
let passwordsThrough = Infinity;
let memory = null;
let memoryPaused = false;
let inflightLogins = 0;
// While 8081 is away nothing is sent: back off 2 s, doubling to 30 s.
let outageUntil = 0;
let outageBackoff = 0;
let outageSince = 0;
function noteOutage(e) {
  const now = Date.now();
  stats.outages += 1;
  if (!outageBackoff) {
    outageSince = now;
    c.log("8081 is not answering (" + e.message + "): pausing");
  }
  if (now >= outageUntil) {
    outageBackoff = Math.min(Math.max(2000, outageBackoff * 2), 30000);
    outageUntil = now + outageBackoff;
  }
}
function noteHealthy() {
  if (!outageBackoff) return;
  c.log("8081 answering again after " +
        Math.round((Date.now() - outageSince) / 1000) + " s: resuming");
  outageBackoff = 0;
  outageUntil = 0;
}
function outage() {
  return Date.now() < outageUntil;
}
let inflightRefreshes = 0;
let steadyAnnounced = meta("steadyAt", "") !== "";
const startedAt = Date.now();

function readPasswordMark() {
  if (!PASSWORD_GATE) { passwordsThrough = Infinity; return; }
  const s = c.readJson(PW_STATE, null);
  passwordsThrough = s && Number.isFinite(s.done) ? s.done : 0;
}

function schedule(n, row) {
  refreshDue[n] = row.refresh_due;
  heap.push(row.refresh_due, n, 0);
  if (row.relogin_due) {
    reloginDue[n] = row.relogin_due;
    heap.push(row.relogin_due, n, 1);
  }
}

function overdue(now) {
  // Due work that is more than a minute late says refreshes are behind.
  return heap.peekDue() < now - 60000;
}

// Logins: a fixed number of workers, paced to LOGIN_RATE.
let nextLoginSlot = Date.now();
async function loginWorker() {
  while (!stopping) {
    const now = Date.now();
    const backlog = overdue(now);
    const gateOpen = loginCursor <= COUNT && loginCursor <= passwordsThrough;
    if (!gateOpen || memoryPaused || backlog || outage()) {
      await sleep(1000);
      continue;
    }
    // Pace: one login per 1/LOGIN_RATE seconds across all workers.
    if (now < nextLoginSlot) { await sleep(nextLoginSlot - now); continue; }
    nextLoginSlot = Math.max(nextLoginSlot, now) + 1000 / LOGIN_RATE;
    const n = loginCursor++;
    if (active[n]) continue;   // signed in in an earlier run
    await doLogin(n);
  }
}

async function doLogin(n) {
  inflightLogins += 1;
  const t0 = Date.now();
  const wasActive = active[n];
  try {
    const row = await signIn(n);
    noteHealthy();
    noteLatency("login", Date.now() - t0);
    write(qUpsert, row);
    active[n] = 1;
    schedule(n, row);
    if (wasActive) stats.relogins += 1; else stats.logins += 1;
  } catch (e) {
    if (e.outage) {
      noteOutage(e);
      // Not this person's failure: try them again once 8081 is back.
      reloginDue[n] = outageUntil + 1000;
      heap.push(reloginDue[n], n, 1);
      return;
    }
    stats.loginFailures += 1;
    noteReason("login:" + (e.reason || "error"));
    const now = Date.now();
    if (active[n]) {
      write(qFailed, { n, err: String(e.message).slice(0, 300), now });
      // Try again later rather than drop a person already signed in.
      reloginDue[n] = now + 300000;
      heap.push(reloginDue[n], n, 1);
    } else {
      write(qInsertFailed, { n, err: String(e.message).slice(0, 300), now });
      // A FIRST SIGN-IN IS TRIED AT MOST MAX_LOGIN_ATTEMPTS TIMES PER RUN
      // (2026-10-21). Two people with no password were retried every minute
      // for an hour, and each refusal is a refused password from the docker
      // gateway: 20 of them in an hour put risk's network-failures on every
      // sign-in from it. The service answers a missing password and a wrong
      // one alike, so the cap is on attempts, not on a reason. The next run
      // tries each failed person again, once.
      attempts[n] = (attempts[n] || 0) + 1;
      if (attempts[n] < MAX_LOGIN_ATTEMPTS) {
        retryLater.push({ n, at: now + RETRY_AFTER_MS });
      } else {
        stats.gaveUp += 1;
        c.log("giving up on " + c.uidOf(n) + " for this run after " +
              attempts[n] + " refused sign-ins: " + e.message);
      }
    }
    if (stats.loginFailures <= 20 || stats.loginFailures % 1000 === 0) {
      c.log("sign-in failed for " + c.uidOf(n) + ": " + e.message);
    }
  } finally {
    inflightLogins -= 1;
  }
}

// People whose first sign-in failed, tried again a minute later (in order,
// at most five a second), not after the cursor is through everybody.
const retryLater = [];
const RETRY_AFTER_MS = 60000;
// First sign-ins refused this run, per person; see the catch in login().
const attempts = {};
const MAX_LOGIN_ATTEMPTS = Math.max(1,
  Number(process.env.MAX_LOGIN_ATTEMPTS || 3));

// Refreshes and sign-ins-again, from the heap, always ahead of first logins.
async function refreshWorker() {
  while (!stopping) {
    if (outage()) { await sleep(500); continue; }
    const now = Date.now();
    if (heap.peekDue() > now) {
      await sleep(Math.min(1000, heap.peekDue() - now));
      continue;
    }
    const job = heap.pop();
    if (job.kind === 0) {
      if (job.due !== refreshDue[job.n]) continue;   // stale
      await doRefresh(job.n);
    } else {
      if (job.due !== reloginDue[job.n]) continue;   // stale
      reloginDue[job.n] = 0;
      await doLogin(job.n);
    }
  }
}

async function doRefresh(n) {
  inflightRefreshes += 1;
  const t0 = Date.now();
  try {
    const row = await refresh(n);
    noteHealthy();
    noteLatency("refresh", Date.now() - t0);
    write(qRefreshed, row);
    refreshDue[n] = row.refresh_due;
    heap.push(row.refresh_due, n, 0);
    stats.refreshes += 1;
  } catch (e) {
    if (e.outage) {
      noteOutage(e);
      refreshDue[n] = outageUntil + 1000;
      heap.push(refreshDue[n], n, 0);
      return;
    }
    stats.refreshFailures += 1;
    noteReason("refresh:" + (e.reason || "error"));
    const now = Date.now();
    write(qFailed, { n, err: String(e.message).slice(0, 300), now });
    if (e.fatal) {
      // The grant is gone: sign the person in again.
      refreshDue[n] = 0;
      reloginDue[n] = now;
      heap.push(now, n, 1);
    } else {
      refreshDue[n] = now + 30000;
      heap.push(refreshDue[n], n, 0);
    }
    if (stats.refreshFailures <= 20 || stats.refreshFailures % 1000 === 0) {
      c.log("refresh failed for " + c.uidOf(n) + ": " + e.message);
    }
  } finally {
    inflightRefreshes -= 1;
  }
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, Math.max(1, ms)));
}

function activeCount() {
  let k = 0;
  for (let n = FIRST; n <= COUNT; n++) k += active[n];
  return k;
}

// The counts at the last status line, for the rate over the interval since:
// an average since the start trails the real pace for hours after an outage.
let lastReport = null;

function report() {
  const now = Date.now();
  const total = COUNT - FIRST + 1;
  const signedIn = activeCount();
  const secs = Math.max(1, (now - startedAt) / 1000);
  const overdueBy = heap.size && heap.peekDue() < now
    ? Math.round((now - heap.peekDue()) / 1000) : 0;
  const s = {
    at: new Date(now).toISOString(),
    signedIn, total,
    loginCursor, passwordsThrough: Number.isFinite(passwordsThrough)
      ? passwordsThrough : null,
    thisRun: { logins: stats.logins, relogins: stats.relogins,
               refreshes: stats.refreshes, loginFailures: stats.loginFailures,
               refreshFailures: stats.refreshFailures,
               unreachable: stats.outages, retryQueue: retryLater.length,
               loginsPerS: +(stats.logins / secs).toFixed(2),
               refreshesPerS: +(stats.refreshes / secs).toFixed(2) },
    latencyMs: { loginP50: pct(stats.latency.login, 0.5),
                 loginP95: pct(stats.latency.login, 0.95),
                 refreshP50: pct(stats.latency.refresh, 0.5),
                 refreshP95: pct(stats.latency.refresh, 0.95) },
    lastInterval: null,
    inflight: { logins: inflightLogins, refreshes: inflightRefreshes },
    scheduled: heap.size, oldestOverdueS: overdueBy,
    containerMemoryGiB: memory == null ? null : +(memory / 1024 ** 3).toFixed(2),
    memoryPaused,
    failureReasons: Object.fromEntries(stats.reasons),
    steadyAt: meta("steadyAt", null)
  };
  const signIns = stats.logins + stats.relogins;
  let recent = "";
  if (lastReport) {
    const span = Math.max(1, (now - lastReport.at) / 1000);
    const loginsPerS = +((signIns - lastReport.signIns) / span).toFixed(2);
    const refreshesPerS =
      +((stats.refreshes - lastReport.refreshes) / span).toFixed(2);
    s.lastInterval = { seconds: Math.round(span), signInsPerS: loginsPerS,
                       refreshesPerS: refreshesPerS };
    recent = "last " + Math.round(span) + " s: " + loginsPerS +
      " sign-ins/s, " + refreshesPerS + " refreshes/s | ";
  }
  lastReport = { at: now, signIns: signIns, refreshes: stats.refreshes };
  c.writeJson(STATUS_FILE, s);
  c.log(recent + "signed in " + signedIn + "/" + total + " | cursor " +
        loginCursor +
        " pw-through " + (s.passwordsThrough == null ? "-" : s.passwordsThrough) +
        " | logins " + stats.logins + " (" + s.thisRun.loginsPerS + "/s, p95 " +
        s.latencyMs.loginP95 + " ms) relogins " + stats.relogins +
        " refreshes " + stats.refreshes + " (" + s.thisRun.refreshesPerS +
        "/s, p95 " + s.latencyMs.refreshP95 + " ms) | failures " +
        stats.loginFailures + "/" + stats.refreshFailures + " (retry queue " +
        retryLater.length + ", given up " + stats.gaveUp + ", unreachable " + stats.outages + ")" +
        " | overdue " + overdueBy + " s | mem " +
        (s.containerMemoryGiB == null ? "?" : s.containerMemoryGiB + " GiB") +
        (memoryPaused ? " PAUSED" : "") + (outage() ? " 8081-AWAY" : ""));
  if (!steadyAnnounced && signedIn === total && overdueBy < 60) {
    steadyAnnounced = true;
    write(qSetMeta, { k: "steadyAt", v: s.at });
    commit();
    c.log("==== STEADY STATE REACHED: all " + total + " people signed in, " +
          "every token set current, refreshes on schedule. Carrying on. ====");
  }
}

function load() {
  let k = 0;
  const seen = new Uint8Array(COUNT + 2);
  const now = Date.now();
  for (const row of db.prepare(`SELECT n, state, refresh_due, relogin_due
                                FROM people`).iterate()) {
    if (row.n < FIRST || row.n > COUNT) continue;
    if (row.state === "active") {
      active[row.n] = 1;
      schedule(row.n, { refresh_due: Math.max(row.refresh_due || now, now),
                        relogin_due: row.relogin_due });
      k += 1;
    } else {
      retryLater.push({ n: row.n, at: now });
    }
    seen[row.n] = 1;
  }
  // A sign-in in flight when the last run stopped left no row: the cursor
  // passed it. Try those again too.
  for (let n = FIRST; n < Math.min(loginCursor, COUNT + 1); n++) {
    if (!seen[n]) retryLater.push({ n, at: now });
  }
  return k;
}

async function main() {
  c.log("sessions against " + c.cfg.STS_URL + " as " + CLIENT_ID + ": people " +
        FIRST + ".." + COUNT + ", " + LOGIN_CONCURRENCY + " sign-ins at most " +
        LOGIN_RATE + "/s, " + REFRESH_CONCURRENCY + " refreshers");
  const resumed = load();
  if (resumed) c.log("resumed " + resumed + " people from " + DB_FILE);
  readPasswordMark();

  process.on("SIGINT", () => { stopping = true; c.log("stopping…"); });
  process.on("SIGTERM", () => { stopping = true; });

  const tickers = [
    setInterval(() => { try { commit(); qSetMeta.run({ k: "loginCursor",
      v: String(loginCursor) }); } catch (e) { c.log("commit: " + e.message); } },
      1000),
    setInterval(readPasswordMark, 30000),
    setInterval(() => {
      memory = c.containerMemory();
      const was = memoryPaused;
      memoryPaused = memory != null && memory > MEM_CEILING;
      if (memoryPaused !== was) {
        c.log(memoryPaused ? "container memory " + (memory / 1024 ** 3)
          .toFixed(1) + " GiB over the ceiling: sign-ins paused"
          : "container memory back under the ceiling: sign-ins resume");
      }
    }, 30000),
    setInterval(() => {
      // First-time failures, each a minute after it failed.
      const now = Date.now();
      if (retryLater.length && retryLater[0].at <= now && !memoryPaused &&
          !outage()) {
        const { n } = retryLater.shift();
        if (!active[n] && !reloginDue[n]) {
          reloginDue[n] = now;
          heap.push(now, n, 1);
        }
      }
    }, 200),
    setInterval(report, STATUS_EVERY_MS)
  ];
  memory = c.containerMemory();

  const workers = [];
  for (let i = 0; i < REFRESH_CONCURRENCY; i++) workers.push(refreshWorker());
  for (let i = 0; i < LOGIN_CONCURRENCY; i++) workers.push(loginWorker());
  await Promise.all(workers);

  for (const t of tickers) clearInterval(t);
  commit();
  qSetMeta.run({ k: "loginCursor", v: String(loginCursor) });
  report();
  db.close();
  c.log("stopped");
}

main().catch((e) => {
  c.log("sessions FAILED: " + (e && e.stack || e));
  try { commit(); } catch (x) { /* closing */ }
  process.exit(1);
});
