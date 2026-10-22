#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
// load-users.js — bulk-load people into an IYA STS realm's directory over LDAPS.
//
// Resumable, parallel, and gentle on the service: it uses only management-API
// calls that stay fast at a million entries (it never lists the directory), and
// adds people over several LDAPS connections at once.
//
// What it does, in order:
//   1. mints an /admin-api token (client_credentials, admin:read admin:write)
//   2. raises ldap.maxEntries so the directory may hold what is about to be added
//   3. creates a bind identity with a password and grants it Admin Write
//      (a product-mode directory refuses an LDAP add from anybody else)
//   4. adds COUNT people as inetOrgPerson entries, CONCURRENCY at a time
//   5. takes Admin Write back from the bind identity (on success, failure or Ctrl-C)
//
// Every name is <PREFIX>-<STAMP>-<n>. STAMP is chosen on the first run and kept in
// the state file, so running again continues where the last run stopped; an entry
// that already exists counts as done.
//
// Settings (environment variables):
//   STS_URL          https://localhost:8081
//   COUNT            1000000             people to add in total (across resumed runs)
//   CONCURRENCY      8                   parallel LDAPS connections
//   PREFIX           load                first part of every username
//   LDAPS_HOST       the `sts` container's IP (docker inspect), else localhost
//   LDAPS_PORT       636
//   TLS_NAME         localhost           name checked on the LDAPS certificate
//   CA_FILE          ./ca.pem            the service Root (verifies HTTPS and LDAPS)
//   CLIENT_ID        claude-293-runner   /admin-api client (client_credentials)
//   CLIENT_SECRET_FILE ./app.secret
//   USERS_DN         asked of /admin-api/groups (e.g. ou=users,dc=example,dc=com)
//   STATE_FILE       ./load-users.state.json
//   LDAPJS           path to the ldapjs package (default: the iya-sts checkout's)
"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { execFileSync } = require("child_process");

const HERE = __dirname;
const env = process.env;
const STS_URL = (env.STS_URL || "https://localhost:8081").replace(/\/+$/, "");
const COUNT = Number(env.COUNT || 1000000);
const CONCURRENCY = Math.max(1, Number(env.CONCURRENCY || 8));
const PREFIX = env.PREFIX || "load";
const LDAPS_PORT = Number(env.LDAPS_PORT || 636);
const TLS_NAME = env.TLS_NAME || "localhost";
const CA_FILE = env.CA_FILE || path.join(HERE, "ca.pem");
const CLIENT_ID = env.CLIENT_ID || "claude-293-runner";
const SECRET_FILE = env.CLIENT_SECRET_FILE || path.join(HERE, "app.secret");
const STATE_FILE = env.STATE_FILE || path.join(HERE, "load-users.state.json");
const LDAPJS = env.LDAPJS || path.join(HERE, "..", "node-ldapjs");

const ldapjs = require(LDAPJS);
const CA = fs.readFileSync(CA_FILE, "utf8");
// Node's fetch trusts only its own store; the service's Root is added for HTTPS.
if (!env.NODE_EXTRA_CA_CERTS) {
  console.error("Set NODE_EXTRA_CA_CERTS=" + CA_FILE + " (see the instructions).");
  process.exit(2);
}

function log(msg) {
  console.log(new Date().toISOString().slice(11, 19) + " " + msg);
}

function ldapsHost() {
  if (env.LDAPS_HOST) return env.LDAPS_HOST;
  try {
    const ip = execFileSync("docker", ["inspect", "sts", "--format",
      "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}"],
      { encoding: "utf8" }).trim().split(/\s+/)[0];
    if (ip) return ip;
  } catch (e) {
    log("docker inspect sts failed (" + e.message.split("\n")[0] +
        "); using localhost — set LDAPS_HOST if 636 is not published.");
  }
  return "localhost";
}

// ---- the management API -----------------------------------------------------

let token = "";

async function mintToken() {
  const secret = fs.readFileSync(SECRET_FILE, "utf8").trim();
  const body = new URLSearchParams({
    grant_type: "client_credentials", scope: "admin:read admin:write",
    resource: STS_URL + "/admin-api"
  });
  const r = await fetch(STS_URL + "/oauth2/token", {
    method: "POST", body,
    headers: { authorization: "Basic " +
      Buffer.from(CLIENT_ID + ":" + secret).toString("base64") }
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.access_token) {
    throw new Error("token request answered " + r.status + " " +
                    JSON.stringify(j).slice(0, 300));
  }
  token = j.access_token;
}

async function api(method, p, body, timeoutMs) {
  const r = await fetch(STS_URL + "/admin-api" + p, {
    method,
    headers: Object.assign({ authorization: "Bearer " + token },
      body ? { "content-type": "application/json" } : {}),
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(timeoutMs || 60000)
  });
  const text = await r.text();
  let json = null;
  try { json = JSON.parse(text); } catch (e) { json = null; }
  return { status: r.status, json, text };
}

// ---- state ------------------------------------------------------------------

function loadState() {
  try {
    return JSON.parse(fs.readFileSync(STATE_FILE, "utf8"));
  } catch (e) {
    return null;
  }
}

function saveState(state) {
  const tmp = STATE_FILE + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(state, null, 2));
  fs.renameSync(tmp, STATE_FILE);
}

// ---- LDAP -------------------------------------------------------------------

function connect(host) {
  return new Promise((resolve, reject) => {
    const client = ldapjs.createClient({
      url: "ldaps://" + host + ":" + LDAPS_PORT,
      reconnect: false, timeout: 60000, connectTimeout: 15000,
      tlsOptions: { ca: [CA], servername: TLS_NAME, rejectUnauthorized: true }
    });
    client.on("error", () => {});   // reported by the operation in flight
    client.once("connect", () => resolve(client));
    client.once("connectError", reject);
    client.once("setupError", reject);
  });
}

function bind(client, dn, password) {
  return new Promise((resolve, reject) => {
    client.bind(dn, password, (e) => (e ? reject(e) : resolve()));
  });
}

function add(client, dn, attributes) {
  return new Promise((resolve) => {
    client.add(dn, attributes, (e) => resolve(e || null));
  });
}

function personAt(stamp, n) {
  const uid = PREFIX + "-" + stamp + "-" + n;
  return {
    uid,
    attributes: {
      objectClass: ["top", "person", "organizationalPerson", "inetOrgPerson"],
      uid, cn: "Load User " + n, sn: "User " + n, givenName: "Load",
      displayName: "Load User " + n, mail: uid + "@load.example"
    }
  };
}

// ---- main -------------------------------------------------------------------

async function main() {
  let state = loadState();
  if (!state) {
    state = {
      stamp: crypto.randomBytes(4).toString("hex"),
      count: COUNT, done: 0, existed: 0, failed: 0,
      bindUser: "", bindPassword: "", bindDn: ""
    };
  }
  if (state.count !== COUNT) {
    log("NOTE: the state file was started with COUNT=" + state.count +
        "; continuing with COUNT=" + COUNT + ".");
    state.count = COUNT;
  }
  log("STS " + STS_URL + ", " + COUNT + " people as " + PREFIX + "-" +
      state.stamp + "-<n>, " + CONCURRENCY + " connections; " + state.done +
      " already done.");

  await mintToken();

  // Where people go.
  let usersDn = env.USERS_DN || "";
  if (!usersDn) {
    const g = await api("GET", "/groups?per=1", null, 120000);
    usersDn = g.json && g.json.usersDn;
    if (!usersDn) throw new Error("set USERS_DN: /admin-api/groups answered " +
                                  g.status);
  }
  log("Adding under " + usersDn);

  // Room in the directory. ldap.maxEntries counts every realm; never lowered.
  const svc = await api("GET", "/ldap/service", null, 180000);
  const limits = (svc.json && svc.json.limits) || {};
  const held = Number(limits.currentEntriesEverywhere || 0);
  const max = Number(limits.maxEntries || 0);
  const wanted = Math.max(max, held + (COUNT - state.done) + 50000);
  if (!held) log("could not read the entry count (" + svc.status +
                 "); setting the ceiling from COUNT alone.");
  if (wanted > max) {
    const set = await api("POST", "/config/set",
                          { key: "ldap.maxEntries", value: wanted });
    if (set.status !== 200) throw new Error("raising ldap.maxEntries: " +
                                            set.status + " " + set.text.slice(0, 300));
    log("ldap.maxEntries " + max + " -> " + wanted);
  }

  // The bind identity.
  if (!state.bindUser) {
    state.bindUser = PREFIX + "-" + state.stamp + "-binder";
    state.bindPassword = "Load-" + crypto.randomBytes(12).toString("base64url") + "!9a";
    const made = await api("POST", "/users/create", {
      username: state.bindUser, invent: false,
      attributes: { cn: "Load binder", givenName: "Load", sn: "Binder",
                    displayName: "Load binder",
                    mail: state.bindUser + "@load.example" },
      credential: "password", password: state.bindPassword
    });
    if (made.status !== 200 || !made.json || !made.json.ok) {
      throw new Error("creating the bind identity: " + made.status + " " +
                      made.text.slice(0, 300));
    }
    state.bindDn = made.json.dn || ("uid=" + state.bindUser + "," + usersDn);
    saveState(state);
  }
  const grant = await api("POST", "/rbac/grant",
                          { username: state.bindUser, role: "write" });
  if (grant.status !== 200) throw new Error("granting Admin Write: " +
                                            grant.status + " " + grant.text.slice(0, 300));
  log("Bind identity " + state.bindDn + " holds Admin Write for the run.");

  let stopping = false;
  let revoked = false;
  async function revoke() {
    if (revoked) return;
    revoked = true;
    try {
      await mintToken();
      const r = await api("POST", "/rbac/revoke",
                          { username: state.bindUser, role: "write" });
      log("Admin Write taken back from " + state.bindUser + ": " + r.status);
    } catch (e) {
      log("COULD NOT take Admin Write back from " + state.bindUser + ": " +
          e.message + " — do it on the console (Admin roles).");
    }
  }
  process.on("SIGINT", () => {
    if (stopping) process.exit(130);
    stopping = true;
    log("Stopping after the adds in flight (Ctrl-C again to quit at once)...");
  });

  // The adds. `next` hands out indexes; `doneSet` keeps finished indexes above
  // the contiguous mark so the state file only ever records a safe resume point.
  const host = ldapsHost();
  log("LDAPS " + host + ":" + LDAPS_PORT + " (certificate checked as " +
      TLS_NAME + ")");
  let next = state.done + 1;
  let mark = state.done;
  const doneSet = new Set();
  const errors = new Map();
  const started = Date.now();
  const startDone = state.done;

  function finish(n, kind) {
    if (kind === "added") state.done++; else if (kind === "existed") {
      state.done++; state.existed++;
    }
    doneSet.add(n);
    while (doneSet.has(mark + 1)) { doneSet.delete(mark + 1); mark++; }
  }

  async function worker(id) {
    let client = null;
    let attempts = 0;
    while (!stopping) {
      if (!client) {
        try {
          client = await connect(host);
          await bind(client, state.bindDn, state.bindPassword);
          attempts = 0;
        } catch (e) {
          client = null;
          attempts++;
          const wait = Math.min(30000, 1000 * 2 ** attempts);
          log("connection " + id + ": " + e.message + "; retrying in " +
              wait / 1000 + "s");
          await new Promise((r) => setTimeout(r, wait));
          continue;
        }
      }
      if (next > COUNT) break;
      const n = next++;
      const person = personAt(state.stamp, n);
      let tries = 0;
      for (;;) {
        const e = await add(client, "uid=" + person.uid + "," + usersDn,
                            person.attributes);
        if (!e) { finish(n, "added"); break; }
        if (e.name === "EntryAlreadyExistsError") { finish(n, "existed"); break; }
        const key = e.name || "Error";
        errors.set(key, (errors.get(key) || 0) + 1);
        if (++tries >= 3) {
          state.failed++;
          log("gave up on " + person.uid + ": " + (e.message || key));
          doneSet.add(n);
          while (doneSet.has(mark + 1)) { doneSet.delete(mark + 1); mark++; }
          break;
        }
        // A broken connection: start a new one and try this person again.
        try { client.unbind(() => {}); } catch (x) { /* already gone */ }
        try {
          client = await connect(host);
          await bind(client, state.bindDn, state.bindPassword);
        } catch (x) {
          await new Promise((r) => setTimeout(r, 2000));
        }
      }
    }
    if (client) {
      try { client.unbind(() => {}); } catch (x) { /* already gone */ }
    }
  }

  const ticker = setInterval(() => {
    const secs = (Date.now() - started) / 1000;
    const rate = (state.done - startDone) / Math.max(secs, 1);
    const left = COUNT - state.done;
    const eta = rate > 0 ? Math.round(left / rate) : 0;
    const errs = [...errors].map(([k, v]) => k + "=" + v).join(" ") || "none";
    log(state.done + "/" + COUNT + " done (" + state.existed + " existed, " +
        state.failed + " failed), " + rate.toFixed(1) + "/s, ETA " +
        Math.floor(eta / 3600) + "h" + Math.floor((eta % 3600) / 60) +
        "m; retried errors: " + errs);
    saveState(Object.assign({}, state, { done: mark }));
  }, 10000);

  try {
    await Promise.all(Array.from({ length: CONCURRENCY }, (_, i) => worker(i + 1)));
  } finally {
    clearInterval(ticker);
    saveState(Object.assign({}, state, { done: mark }));
    await revoke();
  }
  const secs = Math.round((Date.now() - started) / 1000);
  log((stopping ? "STOPPED" : "DONE") + ": " + mark + "/" + COUNT +
      " (resume point saved in " + STATE_FILE + "), " + state.failed +
      " failed, in " + secs + "s.");
}

main().catch((e) => {
  log("FAILED: " + (e && e.stack || e));
  process.exit(1);
});
