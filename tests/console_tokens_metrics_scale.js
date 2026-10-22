// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: console_tokens_metrics_scale.js
//
// ===========================================================================
// MONITORING → TOKENS, METRICS AND VERIFIABLE CREDENTIALS SCALE WITH THE
// STORE, NOT WITH THE POPULATION (2026-10-22, #820).
//
// On 8081 the three pages were each a walk of everything: Tokens listed what
// the answering worker happened to hold, Metrics and the dashboard built a
// row per person (about 470,000) to report four numbers, and the credential
// status monitor built and sorted a row for every live status-list entry to
// show one page.
//
//   Q. the store's two new statements, `minted.newest` and `minted.count`,
//      are built and shaped, and the newest is capped;
//   H. held whole, `issuedSetsAsync()` and `tokensViewAsync()` answer what
//      the synchronous functions answer;
//   U. `userCountsAsync()` gives the counts the rows gave, with no row;
//   D. on demand, the list is the store's newest, labelled as a window, the
//      total is the store's count, a session is read through `sid:`, a set
//      through `set:` (the index key added for this), and a store that
//      cannot be read falls back to what is held and says so;
//   M. Monitoring → Metrics and the dashboard ask `userCountsAsync()` and
//      never `userRowsAsync()`, and report the counts the rows gave;
//   V. the status monitor's counts and page come from the status list's
//      index and equal a walk of every entry, through status changes,
//      attachments and revocations in the issued register — and neither
//      walks the entries.
//
// In a child process: it installs a stand-in for the store's on-demand
// reader and records tokens of its own.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'console_tokens_metrics_scale',
  level: process.env.LOG_LEVEL || 'info' });

// Runs in the child. Stringified, so it may use nothing from this file's scope.
function child() {
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };
  const OUT = process.env.CTM_OUT;
  const ROOT = process.env.CTM_ROOT;
  (async function () {
    const queries = require(ROOT + '/persistence/minted_queries');
    const realms = require(ROOT + '/common/realms');
    const stats = require(ROOT + '/common/admin_stats');
    const views = require(ROOT + '/admin-core/admin_views');
    const vcStatus = require(ROOT + '/oid4vc/vc_status');

    // ---------------------------------------------------------------- Q
    const newest = queries.build('minted.newest',
                                 ['admin_stats.tokens', 'r', 5, 50000]);
    const count = queries.build('minted.count', ['admin_stats.tokens', 'r', 5]);
    const rows = queries.answerOf('minted.newest',
      [{ key: 'k1', key_sealed: null, body: 'b1' }]);
    // Newest by the register's `n:` index keys since the same day (#820):
    // ordering `sts_minted` by `written_at` was a sort of the store.
    note(/ORDER BY i\.index_key DESC, i\.key DESC LIMIT \$5/
           .test(newest.text) &&
         newest.values[4] === queries.NEWEST_LIMIT &&
         newest.values[3] === 5 && /count\(\*\)/.test(count.text) &&
         count.values.length === 4 &&
         queries.answerOf('minted.count', [{ n: '7' }]) === 7 &&
         queries.answerOf('minted.count', []) === 0 &&
         rows.length === 1 && rows[0].key === 'k1',
         'Q. the store answers the newest rows, capped, and a count',
         JSON.stringify({ newest: newest.values, count: count.values,
                          rows: rows }));

    // ---------------------------------------------------------------- H
    const now = Math.floor(Date.now() / 1000);
    const record = function (jti, kind, ctx, extra) {
      stats.recordJwt(Object.assign({ jti: jti, sub: 'urn:uuid:' + jti,
                                      username: 'alice', client_id: 'web',
                                      iat: now, exp: now + 3600 },
                                    extra || {}),
                      '', Object.assign({ kind: kind }, ctx || {}));
    };
    record('at-1', 'access_token', { setId: 'S1', sessionId: 'sess-1' });
    record('id-1', 'id_token', { setId: 'S1', sessionId: 'sess-1' });
    record('rt-1', 'refresh_token', { setId: 'S1', sessionId: 'sess-1' });
    record('at-2', 'access_token', { grant: 'client_credentials' },
           { username: '', sub: 'svc-1', client_id: 'svc-1' });
    stats.recordAuthentication({ protocol: 'OAuth 2.0 / OIDC',
                                 presented: 'alice', method: 'password' });
    stats.recordAuthentication({ protocol: 'OAuth 2.0 / OIDC',
                                 presented: 'bob', method: 'password' });

    const heldRead = await stats.issuedSetsAsync({});
    const plain = views.tokensView({});
    const viaAsync = await views.tokensViewAsync({});
    const strip = function (json) {
      const copy = JSON.parse(JSON.stringify(json));
      delete copy.at;
      return copy;
    };
    note(heldRead.coverage.source === 'held' &&
         heldRead.coverage.complete === true &&
         heldRead.tokenCount === 4 &&
         heldRead.sets.length === stats.issuedSets().length &&
         JSON.stringify(strip(plain.json)) ===
           JSON.stringify(strip(viaAsync.json)) &&
         viaAsync.json.coverage.source === 'held',
         'H. held whole, the store-backed list answers what the held one does',
         JSON.stringify({ coverage: heldRead.coverage,
                          tokenCount: heldRead.tokenCount,
                          sets: heldRead.sets.length }));

    // ---------------------------------------------------------------- U
    const fromRows = stats.snapshot().users;
    const counted = await stats.userCountsAsync();
    const fromCounts = stats.snapshot({ userCounts: counted }).users;
    note(JSON.stringify(fromRows) === JSON.stringify(fromCounts) &&
         counted.known >= 3 && counted.clients >= 1,
         'U. the user counts equal the rows\' counts, with no row built',
         JSON.stringify({ rows: fromRows, counts: fromCounts }));

    // ---------------------------------------------------------------- D
    const storeRow = function (jti, setId, sessionId) {
      return { key: jti, value: {
        key: jti, jti: jti, kind: 'access_token', typ: 'Bearer',
        revocable: true, sub: 'urn:uuid:' + jti, iss: '', username: 'zed',
        client_id: 'far', audience: '', scope: '', jkt: '', x5t: '',
        x5tSpki: '', iat: now, nbf: 0, exp: now + 3600,
        sessionId: sessionId || '', sessionAuthenticated: true,
        setId: setId || '', grant: 'authorization_code' } };
    };
    const asked = { newest: [], index: [], count: 0, syncWalks: 0 };
    let failNewest = false;
    const reader = {
      active: function (handle) {
        return handle === 'admin_stats.tokens';
      },
      read: function () {
        return { present: false };
      },
      journalled: function () {
        return false;
      },
      byIndex: function () {
        asked.syncWalks++;
        return [];
      },
      page: function () {
        asked.syncWalks++;
        return { rows: [], after: '' };
      },
      readMany: function () {
        asked.syncWalks++;
        return [];
      },
      byIndexAsync: function (handle, realmId, indexKey) {
        asked.index.push(indexKey);
        if (indexKey === 'set:S9') {
          return Promise.resolve([storeRow('far-1', 'S9'),
                                  storeRow('far-2', 'S9')]);
        }
        if (indexKey === 'sid:sess-9') {
          return Promise.resolve([storeRow('far-3', '', 'sess-9')]);
        }
        return Promise.resolve([]);
      },
      newestAsync: function (handle, realmId, limit) {
        asked.newest.push(limit);
        if (failNewest) {
          return Promise.reject(new Error('the read pool is down'));
        }
        return Promise.resolve([storeRow('far-1', 'S9'),
                                storeRow('far-2', 'S9'),
                                storeRow('far-4')]);
      },
      countAsync: function () {
        asked.count++;
        return Promise.resolve(12345);
      }
    };
    realms.setOnDemandReader(reader);
    try {
      const window = await stats.issuedSetsAsync({});
      const view = await views.tokensViewAsync({});
      const tokenFamily = view.json.heldByFamily.token;
      note(window.coverage.source === 'store' &&
           window.coverage.complete === false &&
           window.coverage.newest === stats.ISSUED_NEWEST &&
           window.tokenCount === 12345 &&
           asked.newest[0] === stats.ISSUED_NEWEST &&
           window.sets.length === 2 &&
           view.json.coverage.source === 'store' &&
           tokenFamily === 12345 && view.json.held >= 12345 &&
           asked.syncWalks === 0,
           'D1. on demand the list is the store\'s newest, labelled, and ' +
           'the total is the store\'s count',
           JSON.stringify({ coverage: window.coverage, sets:
             window.sets.length, held: view.json.held, token: tokenFamily,
             asked: asked }));

      const one = await stats.issuedSetsAsync({ session: 'sess-9' });
      note(one.coverage.session === 'sess-9' && one.coverage.complete &&
           one.sets.length === 1 && asked.index.indexOf('sid:sess-9') >= 0,
           'D2. a session\'s tokens are read through its `sid:` index',
           JSON.stringify({ coverage: one.coverage, index: asked.index }));

      const far = await stats.issuedSetByKeyAsync('set:S9');
      const mine = await stats.issuedSetByKeyAsync('set:S1');
      const setView = await views.tokenSetViewAsync({ id: 'set:S9' });
      note(far && far.size === 2 && mine && mine.size === 3 &&
           setView.set && setView.set.size === 2,
           'D3. a set is found by its `set:` index, in the store and here',
           JSON.stringify({ far: far && far.size, mine: mine && mine.size,
                            index: asked.index }));

      failNewest = true;
      const fallen = await stats.issuedSetsAsync({});
      note(fallen.coverage.source === 'held' &&
           fallen.coverage.unread === true &&
           fallen.coverage.complete === false &&
           fallen.tokenCount === 12345 &&
           fallen.sets.length === stats.issuedSets().length,
           'D4. a store that cannot be read falls back to what is held, ' +
           'and says so',
           JSON.stringify(fallen.coverage));
      failNewest = false;

      const demand = stats.snapshot({
        userCounts: await stats.userCountsAsync() }).users;
      note(demand.clients >= 1 && demand.known >= 3,
           'D5. on demand the user counts read the holders and their ' +
           '`client` index',
           JSON.stringify(demand));
    } finally {
      realms.setOnDemandReader(null);
    }

    // ---------------------------------------------------------------- M
    const authn = require(ROOT + '/authn/authn');
    const admin = require(ROOT + '/admin-ui/admin');
    const calls = { rows: 0, counts: 0, snapshots: [] };
    const realRows = stats.userRowsAsync;
    const realCounts = stats.userCountsAsync;
    const realSnapshot = stats.snapshot;
    const realLivePage = authn.liveSessionPageAsync;
    const expected = realSnapshot.call(stats).users;
    stats.userRowsAsync = function () {
      calls.rows++;
      return realRows.apply(stats, arguments);
    };
    stats.userCountsAsync = function () {
      calls.counts++;
      return realCounts.apply(stats, arguments);
    };
    stats.snapshot = function (opts) {
      calls.snapshots.push(Object.keys(opts || {}).join(','));
      return realSnapshot.apply(stats, arguments);
    };
    authn.liveSessionPageAsync = function () {
      return Promise.resolve({ authenticated: 1, unauthenticated: 0,
                               total: 1, sessions: [] });
    };
    try {
      const metrics = await views.metricsJsonAsync();
      note(calls.rows === 0 && calls.counts === 1 &&
           calls.snapshots.indexOf('userCounts') >= 0 &&
           JSON.stringify(metrics.users) === JSON.stringify(expected),
           'M1. Metrics counts the users without building a row per person',
           JSON.stringify({ calls: calls, users: metrics.users,
                            expected: expected }));
      const req = { headers: { host: 'localhost:8081' }, query: {},
                    path: '/admin', originalUrl: '/admin',
                    url: '/admin', protocol: 'https', cookies: {},
                    socket: {}, connection: {},
                    get: function (name) {
                      return String(name).toLowerCase() === 'host'
                        ? 'localhost:8081' : undefined;
                    },
                    header: function (name) {
                      return this.get(name);
                    } };
      const dash = await admin.dashboardJsonAsync(req);
      note(calls.rows === 0 && calls.counts === 2 &&
           dash.usersAuthenticatedHere === expected.authenticatedHere,
           'M2. the dashboard counts the users without building a row ' +
           'per person',
           JSON.stringify({ calls: calls,
                            here: dash.usersAuthenticatedHere }));
    } finally {
      stats.userRowsAsync = realRows;
      stats.userCountsAsync = realCounts;
      stats.snapshot = realSnapshot;
      authn.liveSessionPageAsync = realLivePage;
    }

    // ---------------------------------------------------------------- V
    const DAY = 86400000;
    let clock = Date.now() - 5 * DAY;
    const revoked = [];
    const real = vcStatus.VcStatus.defaultDeps();
    // The entries, with every whole walk of them counted.
    let walks = 0;
    const WALKS = ['forEach', 'scan', 'scanAsync', 'values', 'entries',
                   'keys'];
    const countedEntries = new Proxy(real.entries, {
      get: function (target, prop) {
        const value = target[prop];
        if (WALKS.indexOf(prop) >= 0 && typeof value === 'function') {
          return function () {
            walks++;
            return value.apply(target, arguments);
          };
        }
        return typeof value === 'function' ? value.bind(target) : value;
      }
    });
    const vc = new vcStatus.VcStatus(Object.assign({}, real, {
      entries: countedEntries,
      now: function () {
        return clock;
      },
      revokedArtifactKeys: function () {
        return revoked.slice();
      },
      artifactRevokedByKey: function (key) {
        return revoked.indexOf(key) >= 0;
      },
      baseUrlOf: function () {
        return 'https://sts.test';
      }
    }));
    const made = [];
    for (let i = 0; i < 40; i++) {
      clock += Math.floor(DAY / 8) + i;
      // Every fifth one expires one day after today, so it is live; every
      // seventh expired yesterday, within the index's look-back.
      const expiresAt = i % 7 === 0 ? Date.now() - DAY
        : Date.now() + 365 * DAY;
      const out = await vc.allocate({ base: 'https://sts.test',
                                      format: 'dc+sd-jwt', configId: 'c',
                                      expiresAt: expiresAt });
      made.push(out.key);
    }
    clock = Date.now();
    vc.attach(made[1], 'art-1');
    vc.attach(made[2], 'art-2');
    vc.attach(made[3], 'art-3');
    revoked.push('art-1', 'art-3');
    vc.setStatus(made[3], vcStatus.SUSPENDED, 'test');
    vc.setStatus(made[4], vcStatus.SUSPENDED, 'test');
    vc.setStatus(made[5], vcStatus.SUSPENDED, 'test');
    vc.setStatus(made[5], vcStatus.VALID, 'test');
    vc.setStatus(made[6], vcStatus.INVALID, 'test');
    vc.setStatus(made[8], vcStatus.INVALID, 'test');
    const walked = vc.rows();
    const tally = { allocated: walked.length, valid: 0, invalid: 0,
                    suspended: 0 };
    walked.forEach(function (row) {
      if (row.status === 'VALID') {
        tally.valid++;
      } else if (row.status === 'INVALID') {
        tally.invalid++;
      } else if (row.status === 'SUSPENDED') {
        tally.suspended++;
      }
    });
    const walksBefore = walks;
    const fromIndex = vc.counts();
    const countWalks = walks - walksBefore;
    note(countWalks === 0 &&
         JSON.stringify(fromIndex) === JSON.stringify(tally) &&
         tally.suspended === 2 && tally.invalid === 3,
         'V1. the status counts come from the index and equal a walk',
         JSON.stringify({ index: fromIndex, walk: tally,
                          walks: countWalks }));

    const pages = [[0, 5], [5, 5], [3, 10], [20, 25], [0, 100], [33, 4]];
    const mismatched = pages.filter(function (p) {
      const want = walked.slice(p[0], p[0] + p[1]);
      return JSON.stringify(vc.newestRows(p[0], p[1])) !==
             JSON.stringify(want);
    });
    const pageWalksBefore = walks;
    const summary = vc.summary({}, { offset: 5, limit: 5 });
    const pageWalks = walks - pageWalksBefore;
    note(mismatched.length === 0 && pageWalks === 0 &&
         JSON.stringify(summary.rows) === JSON.stringify(walked.slice(5, 10)) &&
         summary.allocated === tally.allocated &&
         summary.suspended === tally.suspended,
         'V2. a page of entries is the walk\'s page, newest first',
         JSON.stringify({ mismatched: mismatched, walks: pageWalks,
                          rows: summary.rows.map(function (r) {
                            return r.idx;
                          }) }));
  })().catch(function (e) {
    note(false, 'the child threw', (e && e.stack) || e);
  }).then(function () {
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function run(t) {
  log.debug("Entering run().");
  const root = path.join(__dirname, '..');
  const out = path.join(os.tmpdir(), 'sts-ctm-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|CONFIG_FILE$)/.test(key)) {
      env[key] = process.env[key];
    }
  });
  Object.assign(env, { CTM_OUT: out, CTM_ROOT: root, LOG_LEVEL: 'fatal',
                       STS_LOG_LEVEL: 'fatal' });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + child.toString() + ')()'], {
      cwd: root, env: env, encoding: 'utf8', timeout: 120000 });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.rmSync(out, { force: true });
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (t.check(Array.isArray(findings),
              'the child process reported its findings',
              'status=' + result.status + ' ' +
              String(result.stderr || '').slice(-2000))) {
    findings.forEach(function (one) {
      t.check(one.ok, one.what, one.detail);
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'console_tokens_metrics_scale',
  describe: 'Monitoring → Tokens, Metrics and Verifiable Credentials read ' +
            'counts and pages from the store and the index, not every row ' +
            '(#820)',
  run: run
};
