// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: console_known_keys.js
//
// ===========================================================================
// A CONSOLE PAGE ASKS ABOUT THE NAMES IT DRAWS, NOT EVERY NAME (2026-10-22,
// #820).
//
// A token's lineage (Monitoring → Tokens), the audit log and the delegation
// pictures asked `knownUserKeys()` to decide which names to draw as links,
// and on 8081 that built every key — about 940,000 user records and token
// holders — synchronously, per page.
//
//   K1. while the register is on demand, `userKeyTest()` answers one key
//       from the user records, the token holders and the artifacts;
//   K2. `knownUserKeys()` asks only the names read, once each, and never
//       builds every key; `allUserKeys()` still does, for the roles page;
//   K3. while the register is held whole, there is no test and the whole
//       set is the answer, as before;
//   K4. a snapshot asked `withoutUsers` builds no user rows (the token
//       lifetimes and SAML assertions pages).
//
// In a child process: it installs a stand-in on-demand reader.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'console_known_keys',
  level: process.env.LOG_LEVEL || 'info' });

// Runs in the child. Stringified, so it may use nothing from this file's scope.
function child() {
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };
  const OUT = process.env.CKK_OUT;
  const ROOT = process.env.CKK_ROOT;
  (async function () {
    const realms = require(ROOT + '/common/realms');
    const stats = require(ROOT + '/common/admin_stats');
    const views = require(ROOT + '/admin-core/admin_views');
    const now = Math.floor(Date.now() / 1000);
    const inRealm = function (fn) {
      return realms.run(realms.get(realms.currentId()), fn);
    };

    const heldWhole = inRealm(function () {
      return stats.userKeyTest();
    });

    let live = true;
    realms.setOnDemandReader({
      active: function () {
        return live;
      },
      read: function () {
        return { present: false };
      },
      byIndex: function () {
        return [];
      },
      digestOf: function (handle, realmId, key) {
        return 'd:' + key;
      },
      journalled: function () {
        return false;
      }
    });
    inRealm(function () {
      stats.recordJwt({ jti: 'ckk-1', sub: 'urn:uuid:1', username: 'alice',
                        iat: now, exp: now + 3600, typ: 'Bearer' },
                      'signed', { kind: 'access_token' });
      const test = stats.userKeyTest();
      note(heldWhole === null && typeof test === 'function' &&
           test('alice') === true && test('nobody-at-all') === false,
           'K1/K3. on demand, one key is answered from the holders; held ' +
           'whole, there is no test', JSON.stringify({
             heldWhole: heldWhole, alice: test && test('alice') }));
    });

    const realUserKeys = stats.userKeys;
    let built = 0;
    stats.userKeys = function () {
      built++;
      return realUserKeys.apply(this, arguments);
    };
    try {
      inRealm(function () {
        const known = views.knownUserKeys();
        const a = known.alice;
        const b = known.nobody;
        const again = known.alice;
        note(built === 0 && a === true && b === undefined && again === true,
             'K2. knownUserKeys() asks the names read and builds no key set',
             JSON.stringify({ built: built, a: a, b: b }));
        const all = views.allUserKeys();
        note(built === 1 && all.alice === true,
             'K2. allUserKeys() still builds every key, for the roles page',
             JSON.stringify({ built: built, keys: Object.keys(all) }));
      });
    } finally {
      stats.userKeys = realUserKeys;
    }

    const realRows = stats.userRows;
    inRealm(function () {
      const without = stats.snapshot({ withoutUsers: true });
      const whole = stats.snapshot();
      note(without.users.known === 0 && whole.users.known >= 1,
           'K4. a snapshot asked withoutUsers builds no user rows',
           JSON.stringify({ without: without.users.known,
                            whole: whole.users.known }));
    });
    stats.userRows = realRows;
    live = false;
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
  const out = path.join(os.tmpdir(), 'sts-ckk-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|CONFIG_FILE$)/.test(key)) {
      env[key] = process.env[key];
    }
  });
  Object.assign(env, { CKK_OUT: out, CKK_ROOT: root, LOG_LEVEL: 'fatal',
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
  name: 'console_known_keys',
  describe: 'console pages ask about the names they draw, not every name, ' +
            'and snapshots that read no user counts build no user rows (#820)',
  run: run
};
