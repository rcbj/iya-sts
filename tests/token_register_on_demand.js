// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: token_register_on_demand.js
//
// ===========================================================================
// THE TOKEN REGISTER ON DEMAND (#820 part 3, rcbj's hybrid).
//
// `admin_stats.tokens` is not held whole: a process holds the recent records
// it was asked about, and what has to find EVERY token of a session, a
// person or a key asks the register's index; an administrator's revoke-all
// walks the store a page at a time. The console's lists and counts are of
// what is held, and say so.
//
//   R1. a sign-out's revokeWhere() with the session's index key revokes the
//       session's tokens the process does not hold, asks the index and not
//       the whole store, and leaves another session's alone;
//   R2. a revokeWhere() with no candidates (revoke-all) walks the store a
//       page at a time and revokes what is not held;
//   R3. tokenList(person) answers that person's records through the index,
//       and nobody else's;
//   R4. the snapshot says its count is of what is held (`heldOnly`);
//   R5. revokeWhereAsync() — /admin-api's revoke-all — walks the store a
//       page at a time with the event loop given back between, and
//       revokes what is not held;
//   R6. every token holder is listed (`admin_stats.tokenHolders`), held
//       tokens or not, and one person's row counts their tokens through the
//       index; a JWT recorded notes its holder once, not once per token;
//   R7. the one-time backfill notes the holders of tokens already issued.
//
// In a child process: it installs a stand-in reader in `common/realms.js`.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'token_register_on_demand',
  level: process.env.LOG_LEVEL || 'info' });

// Runs in the child. Stringified, so it may use nothing from this file's scope.
function child() {
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };
  const OUT = process.env.TRD_OUT;
  const ROOT = process.env.TRD_ROOT;
  (async function () {
    const realms = require(ROOT + '/common/realms');
    const stats = require(ROOT + '/common/admin_stats');
    const HANDLE = 'admin_stats.tokens';
    const future = Math.floor(Date.now() / 1000) + 3600;
    const record = function (jti, over) {
      return Object.assign({ key: jti, jti: jti, kind: 'refresh_token',
                             typ: 'Refresh', revocable: true, sub: '',
                             username: 'alice', client_id: 'app',
                             sessionId: 'sid-a', iat: 1, exp: future,
                             issuedAt: Date.now() }, over || {});
    };
    // The store: what `sts_minted` would hold, filed by the register's own
    // `indexBy` values.
    const stored = new Map();
    [record('t-a1'), record('t-a2'),
     record('t-b1', { sessionId: 'sid-b', username: 'bob' }),
     record('t-c1', { sessionId: 'sid-c', username: 'carol' })]
      .forEach(function (one) {
        stored.set(one.jti, one);
      });
    const declared = realms.handleFor(HANDLE);
    const asked = [];
    realms.setOnDemandReader({
      active: function (handle) {
        return handle === HANDLE;
      },
      read: function (handle, realmId, key) {
        asked.push('read:' + key);
        return stored.has(key) ? { present: true, value: stored.get(key) }
          : { present: false };
      },
      byIndex: function (handle, realmId, indexKey) {
        asked.push('index:' + indexKey);
        const out = [];
        stored.forEach(function (value, key) {
          if ((declared.lookupsOf(value, key) || []).indexOf(indexKey) >= 0) {
            out.push({ key: key, value: value });
          }
        });
        return out;
      },
      page: function (handle, realmId, after) {
        asked.push('page:' + after);
        const rows = [];
        stored.forEach(function (value, key) {
          rows.push({ key: key, value: value });
        });
        return { rows: after ? [] : rows, next: '' };
      },
      journalled: function () {
        return false;
      }
    });
    const tokens = function () {
      return realms.handleFor(HANDLE);
    };
    note(tokens() && stats.snapshot().tokens.heldOnly === true,
         'R4. the snapshot says its count is of what is held',
         JSON.stringify(stats.snapshot().tokens));

    asked.length = 0;
    const ended = stats.revokeWhere(function (one) {
      return one.sessionId === 'sid-a' && one.typ === 'Refresh';
    }, 'a sign-out', {}, ['sid:sid-a']);
    note(ended === 2 && stats.isRevoked('t-a1') && stats.isRevoked('t-a2') &&
         !stats.isRevoked('t-b1') &&
         asked.indexOf('index:sid:sid-a') >= 0 &&
         asked.filter(function (a) {
           return a.indexOf('page:') === 0;
         }).length === 0,
         'R1. a sign-out revokes its session\'s tokens through the index, ' +
         'unheld, and nothing else', JSON.stringify({ ended: ended,
           asked: asked }));

    const people = stats.tokenList('bob').map(function (one) {
      return one.jti;
    });
    note(people.join(',') === 't-b1',
         'R3. tokenList(person) answers that person\'s records alone',
         JSON.stringify(people));

    asked.length = 0;
    const all = stats.revokeWhere(function () {
      return true;
    }, 'the admin console (everything)', {});
    note(all === 2 && stats.isRevoked('t-b1') && stats.isRevoked('t-c1') &&
         asked.indexOf('page:') >= 0,
         'R2. a revoke-all with no candidates walks the store a page at a ' +
         'time', JSON.stringify({ all: all, asked: asked }));

    stored.set('t-d1', record('t-d1', { sessionId: 'sid-d',
                                        username: 'dave' }));
    asked.length = 0;
    let turned = false;
    setImmediate(function () {
      turned = true;
    });
    const later = await stats.revokeWhereAsync(function () {
      return true;
    }, 'the admin console (everything)', {});
    note(later === 1 && stats.isRevoked('t-d1') && turned &&
         asked.indexOf('page:') >= 0,
         'R5. revokeWhereAsync() walks the store a page at a time, giving ' +
         'the event loop back, and revokes what is not held',
         JSON.stringify({ later: later, turned: turned, asked: asked }));

    const holders = realms.handleFor('admin_stats.tokenHolders');
    holders.restore('default', 'erin', { firstAt: 1,
                                         lastExp: future + 7200 });
    const keys = Array.from(stats.userKeys());
    const listed = stats.userRows().map(function (row) {
      return row.key;
    });
    const bob = stats.userRow('bob');
    note(keys.indexOf('erin') >= 0 && listed.indexOf('erin') >= 0 &&
         bob && bob.tokens && bob.tokens.issued === 1,
         'R6. every token holder is listed, and one person\'s row counts ' +
         'their tokens through the index',
         JSON.stringify({ erin: listed.indexOf('erin') >= 0,
                          bob: bob && bob.tokens }));
    const before = holders.dump('default').length;
    const recordOne = function (jti) {
      stats.recordJwt({ jti: jti, sub: '', username: 'frank', iat: 1,
                        exp: Math.floor(future / 1000), typ: 'Bearer' },
                      'x.y.z', { kind: 'access_token' });
    };
    recordOne('f-1');
    const once = holders.dump('default').length;
    let writes = 0;
    realms.setPersistObserver(function (handle) {
      if (handle === 'admin_stats.tokenHolders') {
        writes++;
      }
    });
    recordOne('f-2');
    note(once === before + 1 && writes === 0,
         'R6. a recorded JWT notes its holder once, not once per token',
         JSON.stringify({ before: before, once: once, writes: writes }));

    // R7: the backfill notes the holders of tokens already issued — carol's
    // and dave's are in the store, not held — and marks the realm done.
    const ran = await stats.backfillTokenHolders();
    const after = holders.dump('default').map(function (row) {
      return row.key;
    });
    const again = await stats.backfillTokenHolders();
    note(ran.realms === 1 && after.indexOf('carol') >= 0 &&
         after.indexOf('dave') >= 0 && again.realms === 0 &&
         stats.userRows().every(function (row) {
           return row.key !== '$backfilled$';
         }),
         'R7. the backfill notes every holder in the store once per realm, ' +
         'and its mark is no row of the list',
         JSON.stringify({ ran: ran, again: again, after: after }));
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
  const out = path.join(os.tmpdir(), 'sts-trd-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|CONFIG_FILE$)/.test(key)) {
      env[key] = process.env[key];
    }
  });
  Object.assign(env, { TRD_OUT: out, TRD_ROOT: root, LOG_LEVEL: 'fatal',
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
  name: 'token_register_on_demand',
  describe: 'the token register on demand: correctness paths through the ' +
            'index, revoke-all through a paged walk (#820)',
  run: run
};
