// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// ===========================================================================
// tests/tools/realm-ledger.js — THE REALMS A JOB CREATED, AND THEIR REMOVAL
// ONCE IT HAS PASSED (rcbj, 2026-11-18: "Delete realms as we go").
//
// **WHY.** A trust realm is a logical copy of the service, and every process
// of every node holds it: in the cluster mode of GitHub Actions run #468 the
// suite had left 252 realms by the end, in five isolates on each of two
// nodes, and the runner ran six gigabytes into swap. Until this file no job
// removed one (tests/CLAUDE.md, *A passing job removes its realms*), for a
// reason that still holds for a FAILED job: its realm is the record of what
// it did. So the rule is split on the verdict — a job that PASSED has its
// realms removed, and a job that FAILED, timed out or declined keeps them.
//
// **TWO HALVES, ONE FILE.**
//
//   * PRELOADED into every protocol job (`run-report.js`, beside
//     `attach-admin-token.js`, whose reason for being a preload is this
//     one's: two hundred and seventy-five jobs create realms and no two share
//     an HTTP client). It watches `fetch()` and `http(s).request()` for a POST
//     to `/admin-api/realms/create` that the service ANSWERED 2xx, and
//     appends `{ id, base }` — the realm and the origin it was made at — to
//     the file `STS_TEST_REALM_LEDGER` names. Only an accepted create is
//     written, so a job refused "already defined" for somebody else's realm
//     can never put that realm on its list.
//   * REQUIRED by the runner, whose `removeRecorded()` reads the ledger after
//     a job PASSED and removes each realm through `/admin-api/realms/remove`,
//     one at a time, each call bounded. A realm the job removed itself is
//     answered "no such realm" and is not a failure. Nothing here can fail a
//     job: what could not be removed is said in the runner's log, and the
//     realm stays, which is what the suite did before this file.
//
// **WHAT IT DOES NOT SEE.** A realm created by a BROWSER through the
// console's own `/admin-api` calls is made by Chrome, not by this process,
// and stays. So does every realm `STS_TEST_KEEP_REALM_IDS` names (the
// launchers name the remote PEP containers' realms there: those containers
// poll their realm for the rest of the run) and every realm of a run started
// with `STS_TEST_KEEP_REALMS=1`.
// ===========================================================================

'use strict';

const fs = require('fs');
const http = require('http');
const https = require('https');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for.
const log = require('bunyan').createLogger({ name: 'realm-ledger',
  level: process.env.LOG_LEVEL || 'info' });

// A create in the default realm's management API, which is the only place a
// realm is created; any query string is allowed.
const CREATE = /^\/admin-api\/realms\/create(?:\?.*)?$/;

/**
 * The realm id a create's JSON body names, or '' when it names none.
 *
 * @param {string} body - the request body as sent
 * @returns {string} the id
 */
function idOfBody(body) {
  log.debug('Entering idOfBody().');
  try {
    const parsed = JSON.parse(String(body || ''));
    log.debug('Leaving idOfBody().');
    return parsed && typeof parsed.id === 'string' ? parsed.id.trim() : '';
  } catch (e) {
    log.debug('Caught in idOfBody(): ' + ((e && e.message) || e));
    log.debug('Leaving idOfBody(). Not JSON.');
    return '';
  }
}

/**
 * Appends one accepted create to the ledger. Synchronous on purpose: a job
 * may exit the line after its last create, and an asynchronous append would
 * be lost with it.
 *
 * @param {string} file - the ledger
 * @param {string} id - the realm
 * @param {string} base - the origin it was created at
 */
function note(file, id, base) {
  log.debug('Entering note().');
  if (!file || !id) {
    log.debug('Leaving note(). Nothing to note.');
    return;
  }
  try {
    fs.appendFileSync(file, JSON.stringify({ id: id, base: base }) + '\n');
  } catch (e) {
    // NOT FATAL: an unwritten line only means the realm stays, which is the
    // suite's behaviour before this file.
    log.debug('Caught in note(): ' + ((e && e.message) || e));
  }
  log.debug('Leaving note().');
}

/**
 * Installs the watch on `fetch()` and `http(s).request()`. Called once, at
 * preload, when the runner named a ledger.
 *
 * @param {string} file - the ledger
 */
function install(file) {
  log.debug('Entering install().');
  if (typeof globalThis.fetch === 'function') {
    const realFetch = globalThis.fetch;
    globalThis.fetch = function (input, init) {
      log.debug('Entering fetch().');
      const url = typeof input === 'string' ? input
        : (input && input.url) || String(input);
      let parsed = null;
      try {
        parsed = new URL(url);
      } catch (e) {
        log.debug('Caught in fetch(): ' + ((e && e.message) || e));
        parsed = null;
      }
      const method = String((init && init.method) ||
                            (input && typeof input === 'object' &&
                             input.method) || 'GET').toUpperCase();
      const sent = realFetch.apply(this, arguments);
      if (!parsed || method !== 'POST' ||
          !CREATE.test(parsed.pathname + parsed.search) ||
          !init || typeof init.body !== 'string') {
        log.debug('Leaving fetch().');
        return sent;
      }
      const id = idOfBody(init.body);
      log.debug('Leaving fetch(). A realm create.');
      return sent.then(function (res) {
        if (res && res.status >= 200 && res.status < 300) {
          note(file, id, parsed.origin);
        }
        return res;
      });
    };
  }
  [http, https].forEach(function (mod) {
    const real = mod.request;
    mod.request = function (a, b, c) {
      log.debug('Entering request().');
      const req = real.apply(this, arguments);
      let options = null;
      let parsed = null;
      try {
        if (typeof a === 'string' || a instanceof URL) {
          parsed = new URL(String(a));
          options = (b && typeof b === 'object') ? b : {};
        } else if (a && typeof a === 'object') {
          options = a;
          const scheme = mod === https ? 'https:' : 'http:';
          parsed = new URL(scheme + '//' + (options.hostname ||
            options.host || 'localhost') + (options.port ? ':' +
            options.port : '') + (options.path || '/'));
        }
      } catch (e) {
        log.debug('Caught in request(): ' + ((e && e.message) || e));
        parsed = null;
      }
      const method = String((options && options.method) || 'GET')
        .toUpperCase();
      if (!parsed || method !== 'POST' ||
          !CREATE.test(parsed.pathname + parsed.search)) {
        log.debug('Leaving request().');
        return req;
      }
      // The body is what the job writes; kept until the answer arrives.
      const chunks = [];
      const write = req.write;
      const end = req.end;
      req.write = function (chunk) {
        log.debug('Entering write().');
        if (chunk && typeof chunk !== 'function') {
          chunks.push(Buffer.from(chunk));
        }
        log.debug('Leaving write().');
        return write.apply(this, arguments);
      };
      req.end = function (chunk) {
        log.debug('Entering end().');
        if (chunk && typeof chunk !== 'function') {
          chunks.push(Buffer.from(chunk));
        }
        log.debug('Leaving end().');
        return end.apply(this, arguments);
      };
      req.on('response', function (res) {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          note(file, idOfBody(Buffer.concat(chunks).toString('utf8')),
               parsed.origin);
        }
      });
      log.debug('Leaving request(). A realm create.');
      return req;
    };
  });
  log.debug('Leaving install().');
}

/**
 * The realms a ledger names, each once, in the order they were created.
 *
 * @param {string} file - the ledger
 * @returns {Array<{id: string, base: string}>} the realms
 */
function readLedger(file) {
  log.debug('Entering readLedger().');
  let text = '';
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch (e) {
    // No ledger is a job that created no realm.
    log.debug('Caught in readLedger(): ' + ((e && e.message) || e));
    log.debug('Leaving readLedger(). None.');
    return [];
  }
  const seen = new Set();
  const out = [];
  text.split('\n').forEach(function (line) {
    if (!line.trim()) {
      return;
    }
    try {
      const row = JSON.parse(line);
      if (row && row.id && !seen.has(row.id)) {
        seen.add(row.id);
        out.push({ id: String(row.id), base: String(row.base || '') });
      }
    } catch (e) {
      // A torn line from a job killed mid-append: that realm stays.
      log.debug('Caught in readLedger(): ' + ((e && e.message) || e));
    }
  });
  log.debug('Leaving readLedger(). ' + out.length + ' realm(s).');
  return out;
}

/**
 * One bounded JSON POST. The service's certificate is the run's own, as
 * `admin-api-token.js` argues for the same call.
 *
 * @param {string} url - where
 * @param {string} token - the bearer token
 * @param {object} body - the JSON body
 * @param {number} timeoutMs - the bound
 * @returns {Promise<{status: number, text: string}>} the answer
 */
function post(url, token, body, timeoutMs) {
  log.debug('Entering post().');
  return new Promise(function (resolve, reject) {
    const u = new URL(url);
    const mod = u.protocol === 'http:' ? http : https;
    const data = JSON.stringify(body);
    const req = mod.request({
      hostname: u.hostname, port: u.port, path: u.pathname + u.search,
      method: 'POST', rejectUnauthorized: false, timeout: timeoutMs,
      headers: { 'content-type': 'application/json',
                 'content-length': Buffer.byteLength(data),
                 authorization: 'Bearer ' + token }
    }, function (res) {
      let text = '';
      res.on('data', function (c) {
        text += c;
      });
      res.on('end', function () {
        log.debug('Leaving post().');
        resolve({ status: res.statusCode, text: text });
      });
    });
    req.on('timeout', function () {
      req.destroy(new Error('no answer within ' + timeoutMs + 'ms'));
    });
    req.on('error', function (e) {
      log.debug('Caught in post(): ' + ((e && e.message) || e));
      reject(e);
    });
    req.end(data);
  });
}

/**
 * Removes every realm a PASSED job's ledger names, except those `keep`
 * names. Never throws: answers what was removed and what was not.
 *
 * @param {object} args - `{ file, tokenFor(base), keep: Set, timeoutMs,
 *   logger }`
 * @returns {Promise<{removed: string[], failed: string[]}>} the outcome
 */
async function removeRecorded(args) {
  log.debug('Entering removeRecorded().');
  const out = { removed: [], failed: [] };
  const keep = args.keep || new Set();
  const rows = readLedger(args.file).filter(function (row) {
    return !keep.has(row.id);
  });
  const tokens = new Map();
  for (const row of rows) {
    try {
      if (!tokens.has(row.base)) {
        tokens.set(row.base, await args.tokenFor(row.base));
      }
      const r = await post(row.base + '/admin-api/realms/remove',
                           tokens.get(row.base), { id: row.id },
                           args.timeoutMs || 60000);
      // 400 with "no realm called" is a realm the job removed itself.
      if (r.status === 200 || /No realm called/.test(r.text)) {
        out.removed.push(row.id);
      } else {
        out.failed.push(row.id + ' (' + r.status + ' ' +
                        r.text.slice(0, 160) + ')');
      }
    } catch (e) {
      log.debug('Caught in removeRecorded(): ' + ((e && e.message) || e));
      out.failed.push(row.id + ' (' + ((e && e.message) || e) + ')');
    }
  }
  log.debug('Leaving removeRecorded(). ' + out.removed.length + ' removed, ' +
            out.failed.length + ' not.');
  return out;
}

// ---------------------------------------------------------------------------
// THE QUEUE THE RUNNER REMOVES REALMS THROUGH, AND THE HOLD AN EXCLUSIVE JOB
// TAKES ON IT (2026-11-18, GitHub Actions run #493).
//
// The removals run one at a time beside the jobs, so a lane does not wait
// out a realm's retirement. That made them run beside EXCLUSIVE jobs too,
// which exist because nothing else may change the service under them:
// `sts_realm_count_limit` failed in every mode, "the realm count moved while
// the cap was being set (5 -> 4)", because a passed job's realm was removed
// halfway through it. So a job that must have the service to itself — and
// a cluster restart — `hold()`s the queue: the hold waits for every removal
// already queued to land, and a removal queued during the hold does not
// start until it is released. `drain()` waits for everything queued.
// tests/realm_removal_queue.js holds both.
// ---------------------------------------------------------------------------
class RemovalQueue {
  constructor() {
    log.debug('Entering RemovalQueue.constructor().');
    this.tail = Promise.resolve();
    this.gate = Promise.resolve();
    log.debug('Leaving RemovalQueue.constructor().');
  }

  /**
   * Queues `fn` after every removal already queued and after any hold.
   *
   * @param {Function} fn - the removal, answering a promise
   * @returns {Promise} when it has run; never rejects
   */
  enqueue(fn) {
    log.debug('Entering RemovalQueue.enqueue().');
    // The gate as it is NOW: a removal queued before a hold runs (and is
    // what the hold drains); one queued during a hold waits for its release.
    const gate = this.gate;
    this.tail = this.tail.then(function () {
      return gate;
    }).then(function () {
      return fn();
    }).then(function () {
      return null;
    }, function (e) {
      log.debug('Caught in RemovalQueue.enqueue(): ' +
                ((e && e.message) || e));
      return null;
    });
    log.debug('Leaving RemovalQueue.enqueue().');
    return this.tail;
  }

  /**
   * Waits for every queued removal to land.
   *
   * @returns {Promise} when the queue is empty as of the call
   */
  drain() {
    log.debug('Entering RemovalQueue.drain().');
    log.debug('Leaving RemovalQueue.drain().');
    return this.tail;
  }

  /**
   * Drains the queue and holds it: nothing queued from now on starts until
   * the answered release is called.
   *
   * @returns {Promise<Function>} the release
   */
  async hold() {
    log.debug('Entering RemovalQueue.hold().');
    let release = null;
    const held = new Promise(function (resolve) {
      release = resolve;
    });
    const before = this.gate;
    this.gate = before.then(function () {
      return held;
    });
    await this.drain();
    log.debug('Leaving RemovalQueue.hold().');
    return function () {
      log.debug('Entering the hold\'s release.');
      release();
      log.debug('Leaving the hold\'s release.');
    };
  }
}

if (process.env.STS_TEST_REALM_LEDGER) {
  install(process.env.STS_TEST_REALM_LEDGER);
}

module.exports = { idOfBody, readLedger, removeRecorded, CREATE,
                   RemovalQueue };
