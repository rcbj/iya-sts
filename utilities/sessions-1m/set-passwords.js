// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
// set-passwords.js — give people 1..COUNT one shared password, over LDAPS.
//
// The people load-users.js made have no userPassword, and product mode checks
// passwords, so nobody can sign in until they have one. Each write is an LDAP
// modify bound as load-users.js's binder, which is given Admin Write for the
// run and has it taken away at the end (or on Ctrl-C).
//
// THE COST IS THE SERVICE'S, NOT THIS SCRIPT'S. A product-mode password write
// goes through credentials.preparePassword(): the policy, the breach screen
// (cached per hash prefix, so one lookup for one password), and ONE
// SYNCHRONOUS scrypt hash (about 70 ms) on the process that answers the
// modify. With the default two request workers that is roughly 25-30 writes
// a second at most, so 1,000,000 takes on the order of ten hours, and every
// write holds a worker's event loop while it hashes. CONCURRENCY (default 2)
// keeps one write per worker in flight; raising it buys little and costs
// latency for everything else the service answers.
//
// Resumable: set-passwords.state.json holds the contiguous high-water mark.
// sessions.js reads it and never signs in a person beyond it.
"use strict";

const path = require("path");
const c = require("./common");

const ldapjs = require(c.cfg.LDAPJS);
const CA = require("fs").readFileSync(c.cfg.CA_FILE, "utf8");

const STATE = process.env.PW_STATE || path.join(c.HERE, "set-passwords.state.json");
const CONCURRENCY = Math.max(1, Number(process.env.CONCURRENCY || 2));
const FIRST = Math.max(1, Number(process.env.FIRST || 1));
const LAST = Number(process.env.LAST || c.cfg.COUNT);
// A modify with no answer this long is treated as a lost connection: a
// connection that died mid-operation can leave ldapjs's callback uncalled,
// and one such write once held the contiguous mark still for good.
const MODIFY_TIMEOUT_MS = Number(process.env.MODIFY_TIMEOUT_MS || 60000);

function connect(host) {
  return new Promise((resolve, reject) => {
    const client = ldapjs.createClient({
      url: "ldaps://" + host + ":" + c.cfg.LDAPS_PORT,
      reconnect: false, timeout: 120000, connectTimeout: 15000,
      tlsOptions: { ca: [CA], servername: c.cfg.TLS_NAME,
                    rejectUnauthorized: true }
    });
    client.on("error", () => {});
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

function setPassword(client, dn, password) {
  const change = new ldapjs.Change({
    operation: "replace",
    modification: new ldapjs.Attribute({ type: "userPassword",
                                         values: [password] })
  });
  return new Promise((resolve) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      const e = new Error("no answer in " + MODIFY_TIMEOUT_MS + " ms");
      e.code = "MODIFY_TIMEOUT";
      resolve(e);
    }, MODIFY_TIMEOUT_MS);
    client.modify(dn, change, (e) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(e || null);
    });
  });
}

async function main() {
  const binder = c.readJson(c.cfg.BINDER_STATE, null);
  if (!binder || !binder.bindDn || !binder.bindPassword) {
    throw new Error("no binder in " + c.cfg.BINDER_STATE);
  }
  const password = c.peoplePassword();
  const state = c.readJson(STATE, { done: FIRST - 1, failed: [] });
  if (state.done < FIRST - 1) state.done = FIRST - 1;
  // Written above the mark in an earlier run, kept so a restart does not
  // write them again; and earlier failures, tried again first.
  const finishedBefore = Array.isArray(state.above) ? state.above : [];
  const redo = (state.failed || []).map((f) => f.n)
    .filter((n) => Number.isFinite(n) && n >= FIRST && n <= LAST);
  state.failed = [];
  if (state.done >= LAST) {
    c.log("already done through " + state.done);
    return;
  }
  const host = c.containerIp();
  c.log("setting passwords " + (state.done + 1) + ".." + LAST + " over ldaps://" +
        host + ":" + c.cfg.LDAPS_PORT + ", " + CONCURRENCY + " connection(s)");

  const grant = await c.api("POST", "/rbac/grant",
                            { username: binder.bindUser, role: "write" });
  if (grant.status !== 200) {
    throw new Error("granting Admin Write: " + grant.status + " " +
                    grant.text.slice(0, 300));
  }
  let revoked = false;
  async function revoke() {
    if (revoked) return;
    revoked = true;
    // Up to ten minutes, so a redeploy at the end does not leave the role held.
    for (let attempt = 0; attempt < 40; attempt++) {
      try {
        const r = await c.api("POST", "/rbac/revoke",
                              { username: binder.bindUser, role: "write" });
        if (r.status === 200) {
          c.log("Admin Write taken back from " + binder.bindUser);
          return;
        }
        c.log("revoking Admin Write answered " + r.status + "; retrying");
      } catch (e) {
        c.log("revoking Admin Write failed (" + e.message + "); retrying");
      }
      await new Promise((r) => setTimeout(r, 15000));
    }
    c.log("COULD NOT take Admin Write back from " + binder.bindUser +
          " — revoke it on /admin/rbac");
  }

  let stopping = false;
  process.on("SIGINT", () => { stopping = true; c.log("stopping…"); });
  process.on("SIGTERM", () => { stopping = true; });

  let next = state.done + 1;
  const finished = new Set(finishedBefore);   // completed above the mark
  while (finished.has(state.done + 1)) {
    finished.delete(state.done + 1);
    state.done += 1;
  }
  next = state.done + 1;
  // The next person to write: a redo first, then the cursor, skipping
  // whoever an earlier run already finished.
  function take() {
    if (redo.length) return redo.shift();
    while (next <= LAST && finished.has(next)) next++;
    if (next > LAST) return null;
    return next++;
  }
  let wrote = 0;
  const started = Date.now();
  let lastSave = 0;

  function complete(n) {
    finished.add(n);
    while (finished.has(state.done + 1)) {
      finished.delete(state.done + 1);
      state.done += 1;
    }
    if (Date.now() - lastSave > 2000) {
      lastSave = Date.now();
      save();
    }
  }
  function save() {
    state.above = Array.from(finished).sort((a, b) => a - b);
    c.writeJson(STATE, state);
  }

  // 8081 is redeployed by other work while this runs, so a lost connection
  // is waited out rather than counted: connect() retries with back-off until
  // the service answers again, and the person whose write was interrupted is
  // written once it does. Only an answer FROM the server (a refusal) counts
  // as a failure.
  async function connected() {
    let wait = 2000;
    while (!stopping) {
      try {
        const client = await connect(host);
        await bind(client, binder.bindDn, binder.bindPassword);
        return client;
      } catch (e) {
        c.log("connect/bind failed (" + e.message + "); retrying in " +
              wait / 1000 + " s");
        await new Promise((r) => setTimeout(r, wait));
        wait = Math.min(wait * 2, 30000);
      }
    }
    return null;
  }

  // The service away or going away: a dropped connection, a modify with
  // no answer, or LDAP busy (51) / unavailable (52), which a draining or
  // restarting 8081 answers. Waited out and retried, never counted.
  function lostConnection(err) {
    if (err && (err.code === 51 || err.code === 52)) return true;
    return /closed|ECONNRESET|ECONNREFUSED|EPIPE|socket|timeout|connection|MODIFY_TIMEOUT|Unavailable|Busy/i
      .test(String(err && (err.code || "") + " " + err.name + " " +
                   err.message));
  }

  async function worker(id) {
    let client = null;
    while (!stopping) {
      const n = take();
      if (n === null) break;
      let err = null;
      let refusals = 0;
      while (!stopping) {
        if (!client) client = await connected();
        if (!client) break;
        err = await setPassword(client, c.dnOf(n), password);
        if (!err) break;
        if (lostConnection(err)) {
          try { client.unbind(); } catch (e) { /* gone */ }
          try { client.destroy(); } catch (e) { /* gone */ }
          client = null;
          await new Promise((r) => setTimeout(r, 1000));
          continue;
        }
        // ALREADY SET: the password rules refuse the current password (and
        // the five before it) as a new one, and every person gets the same
        // one here — so a Constraint Violation on this write means an
        // earlier run set it and stopped before recording that. Done, not
        // failed: retrying it at every start only repeats the refusal.
        if (/constraint violation/i.test(String(err && err.message))) {
          err = null;
          break;
        }
        if (++refusals >= 4) break;
        await new Promise((r) => setTimeout(r, 1000 * refusals));
      }
      if (stopping && (err || !client)) {
        // Interrupted mid-person: the next run tries it again.
        state.failed.push({ n, error: "interrupted" });
        break;
      }
      if (err) {
        state.failed.push({ n, error: String(err.message).slice(0, 200) });
        c.log("person " + n + " failed: " + err.message);
        if (state.failed.length > 1000) {
          stopping = true;
          c.log("over 1000 failures; stopping");
        }
      } else {
        wrote += 1;
      }
      complete(n);
    }
    if (client) { try { client.unbind(); } catch (e) { /* gone */ } }
  }

  // Once a minute (STATUS_EVERY_S): how many people have a password now.
  const statusEvery = Math.max(5, Number(process.env.STATUS_EVERY_S || 60));
  // The rate over the interval since the last line, beside the average
  // since the start, which trails the real pace for hours after an outage.
  let lastTick = { at: started, wrote: 0 };
  const ticker = setInterval(() => {
    const now = Date.now();
    const secs = (now - started) / 1000;
    const rate = wrote / Math.max(1, secs);
    const span = Math.max(1, (now - lastTick.at) / 1000);
    const recent = (wrote - lastTick.wrote) / span;
    lastTick = { at: now, wrote: wrote };
    const left = LAST - state.done;
    const pct = (100 * state.done / LAST).toFixed(2);
    c.log("last " + Math.round(span) + " s: " + recent.toFixed(1) +
          " writes/s | users with a password: " +
          state.done.toLocaleString("en-US") +
          " of " + LAST.toLocaleString("en-US") + " (" + pct + "%) | " +
          wrote + " this run, " + rate.toFixed(1) + "/s on average | " +
          state.failed.length + " failed | ETA " +
          (recent > 0 ? (left / recent / 3600).toFixed(1) + " h" : "?") +
          " at the last interval's rate");
  }, statusEvery * 1000);

  try {
    await Promise.all(Array.from({ length: CONCURRENCY }, (_, i) => worker(i)));
  } finally {
    clearInterval(ticker);
    save();
    await revoke();
  }
  c.log("finished: done through " + state.done + ", " + state.failed.length +
        " failed");
}

main().catch((e) => {
  c.log("set-passwords FAILED: " + (e && e.stack || e));
  process.exit(1);
});
