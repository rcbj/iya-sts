// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
// common.js — what setup.js, set-passwords.js, sessions.js and teardown.js
// share: the settings, the management API, logging, the people, a cookie jar.
//
// Nothing here is a test of the service. These scripts drive 8081 the way a
// population of browsers and one confidential web application would.
"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { execFileSync } = require("child_process");

const HERE = __dirname;
const PARENT = path.join(HERE, "..");
const env = process.env;

const cfg = {
  STS_URL: (env.STS_URL || "https://localhost:8081").replace(/\/+$/, ""),
  // The people: load-26cb84b3-1 .. load-26cb84b3-<COUNT>, which load-users.js
  // created (ten million of them). The first COUNT are used.
  STAMP: env.STAMP || "26cb84b3",
  PREFIX: env.PREFIX || "load",
  COUNT: Number(env.COUNT || 1000000),
  BASE_DN: env.BASE_DN || "ou=users,dc=example,dc=com",
  // The management API client load-users.js already uses.
  ADMIN_CLIENT_ID: env.ADMIN_CLIENT_ID || "claude-293-runner",
  ADMIN_SECRET_FILE: env.ADMIN_SECRET_FILE || path.join(PARENT, "app.secret"),
  CA_FILE: env.CA_FILE || path.join(PARENT, "ca.pem"),
  // The relying party this test creates.
  APP_ID: env.APP_ID || "sessions-1m-rp",
  REDIRECT_URI: env.REDIRECT_URI || "https://127.0.0.1:9/sessions-1m/cb",
  CLIENT_SECRET_FILE: env.CLIENT_SECRET_FILE || path.join(HERE, "client.secret"),
  PEOPLE_SECRET_FILE: env.PEOPLE_SECRET_FILE || path.join(HERE, "people.secret"),
  // LDAPS, for the password phase.
  LDAPS_PORT: Number(env.LDAPS_PORT || 636),
  TLS_NAME: env.TLS_NAME || "localhost",
  LDAPJS: env.LDAPJS || path.join(PARENT, "..", "iya-sts", "node-ldapjs"),
  BINDER_STATE: path.join(PARENT, "load-users.state.json"),
  // The container whose memory the login ramp watches.
  CONTAINER: env.STS_CONTAINER || "sts"
};

// A real browser's User-Agent. Node's fetch says "node", which the risk
// evaluator scores as an automated client (x10, HIGH) and product mode
// refuses at a first sign-in.
const USER_AGENT = env.USER_AGENT ||
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) " +
  "Chrome/128.0.0.0 Safari/537.36";

if (!env.NODE_EXTRA_CA_CERTS) {
  console.error("Set NODE_EXTRA_CA_CERTS=" + cfg.CA_FILE +
                " (the run-*.sh wrappers do).");
  process.exit(2);
}

function log(msg) {
  console.log(new Date().toISOString().replace("T", " ").slice(0, 19) + " " +
              msg);
}

function uidOf(n) {
  return cfg.PREFIX + "-" + cfg.STAMP + "-" + n;
}

function dnOf(n) {
  return "uid=" + uidOf(n) + "," + cfg.BASE_DN;
}

function readSecret(file) {
  return fs.readFileSync(file, "utf8").trim();
}

// A file only this user may read. Secrets never go to stdout.
function writeSecret(file, value) {
  fs.writeFileSync(file, value + "\n", { mode: 0o600 });
  fs.chmodSync(file, 0o600);
}

function readJson(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (e) {
    return fallback;
  }
}

function writeJson(file, value) {
  const tmp = file + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(value, null, 2));
  fs.renameSync(tmp, file);
}

// The one password every chosen person is given. Long, random, and holding
// every class the password policy asks for, so the policy and the breach
// screen both pass it. Made once and kept in people.secret.
function peoplePassword() {
  if (fs.existsSync(cfg.PEOPLE_SECRET_FILE)) {
    return readSecret(cfg.PEOPLE_SECRET_FILE);
  }
  const pw = "S1m-" + crypto.randomBytes(24).toString("base64url") + "!Q7z";
  writeSecret(cfg.PEOPLE_SECRET_FILE, pw);
  return pw;
}

// ---- the management API -----------------------------------------------------

let adminToken = "";
let adminTokenExp = 0;

async function mintAdminToken() {
  const secret = readSecret(cfg.ADMIN_SECRET_FILE);
  const body = new URLSearchParams({
    grant_type: "client_credentials", scope: "admin:read admin:write",
    resource: cfg.STS_URL + "/admin-api"
  });
  const r = await fetch(cfg.STS_URL + "/oauth2/token", {
    method: "POST", body,
    headers: {
      "user-agent": USER_AGENT,
      authorization: "Basic " +
        Buffer.from(cfg.ADMIN_CLIENT_ID + ":" + secret).toString("base64")
    },
    signal: AbortSignal.timeout(60000)
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.access_token) {
    throw new Error("admin token request answered " + r.status + " " +
                    JSON.stringify(j).slice(0, 300));
  }
  adminToken = j.access_token;
  adminTokenExp = Date.now() + (Number(j.expires_in || 600) - 60) * 1000;
}

async function api(method, p, body, timeoutMs) {
  if (!adminToken || Date.now() > adminTokenExp) await mintAdminToken();
  const r = await fetch(cfg.STS_URL + "/admin-api" + p, {
    method,
    headers: Object.assign({ authorization: "Bearer " + adminToken,
                             "user-agent": USER_AGENT },
      body ? { "content-type": "application/json" } : {}),
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(timeoutMs || 60000)
  });
  const text = await r.text();
  let json = null;
  try { json = JSON.parse(text); } catch (e) { json = null; }
  return { status: r.status, json, text };
}

// Every setting the service reports, flattened to key -> row.
async function readSettings() {
  const r = await api("GET", "/config");
  if (r.status !== 200 || !r.json) {
    throw new Error("GET /admin-api/config answered " + r.status);
  }
  const rows = {};
  // The top-level `groups` is every setting; `settings.groups` is only the
  // ones the Server configuration page itself draws.
  const groups = r.json.groups ||
    (r.json.settings && r.json.settings.groups) || [];
  for (const g of groups) {
    for (const s of g.settings || []) rows[s.key] = s;
  }
  return rows;
}

async function setSetting(key, value) {
  const r = await api("POST", "/config/set", { key, value: String(value) });
  if (r.status !== 200) {
    throw new Error("setting " + key + " answered " + r.status + " " +
                    r.text.slice(0, 300));
  }
}

async function resetSetting(key) {
  const r = await api("POST", "/config/reset", { key });
  if (r.status !== 200) {
    throw new Error("resetting " + key + " answered " + r.status + " " +
                    r.text.slice(0, 300));
  }
}

// ---- the container ----------------------------------------------------------

function containerIp() {
  if (env.LDAPS_HOST) return env.LDAPS_HOST;
  try {
    const ip = execFileSync("docker", ["inspect", cfg.CONTAINER, "--format",
      "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}"],
      { encoding: "utf8" }).trim().split(/\s+/)[0];
    if (ip) return ip;
  } catch (e) {
    log("docker inspect " + cfg.CONTAINER + " failed; using localhost");
  }
  return "localhost";
}

// The container's memory in bytes, or null when docker cannot say.
function containerMemory() {
  try {
    const out = execFileSync("docker", ["stats", "--no-stream", "--format",
      "{{.MemUsage}}", cfg.CONTAINER], { encoding: "utf8", timeout: 20000 })
      .trim();
    const m = /^([\d.]+)\s*([KMGT]?i?B)/.exec(out);
    if (!m) return null;
    const unit = { B: 1, KiB: 1024, MiB: 1024 ** 2, GiB: 1024 ** 3,
                   TiB: 1024 ** 4, kB: 1e3, KB: 1e3, MB: 1e6, GB: 1e9,
                   TB: 1e12 }[m[2]] || 1;
    return Math.round(Number(m[1]) * unit);
  } catch (e) {
    return null;
  }
}

// ---- a browser's cookies ----------------------------------------------------

// One jar per person. Cookies are kept by name; the service sets few, all on
// one host, so path and domain matching are not needed.
class CookieJar {
  constructor() { this.cookies = new Map(); }
  take(res) {
    const list = typeof res.headers.getSetCookie === "function"
      ? res.headers.getSetCookie() : [];
    for (const c of list) {
      const first = c.split(";")[0];
      const eq = first.indexOf("=");
      if (eq < 1) continue;
      const name = first.slice(0, eq).trim();
      const value = first.slice(eq + 1).trim();
      if (!value || /max-age=0/i.test(c) ||
          /expires=Thu, 01 Jan 1970/i.test(c)) {
        this.cookies.delete(name);
      } else {
        this.cookies.set(name, value);
      }
    }
  }
  header() {
    return Array.from(this.cookies, ([k, v]) => k + "=" + v).join("; ");
  }
}

function b64url(buf) {
  return Buffer.from(buf).toString("base64url");
}

function jwtClaims(jwt) {
  try {
    return JSON.parse(Buffer.from(String(jwt).split(".")[1], "base64url")
      .toString("utf8"));
  } catch (e) {
    return {};
  }
}

module.exports = {
  cfg, USER_AGENT, log, uidOf, dnOf, readSecret, writeSecret, readJson,
  writeJson, peoplePassword, mintAdminToken, api, readSettings, setSetting,
  resetSetting, containerIp, containerMemory, CookieJar, b64url, jwtClaims,
  HERE, PARENT
};
