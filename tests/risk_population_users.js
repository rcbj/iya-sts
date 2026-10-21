// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: risk_population_users.js
//
// ===========================================================================
// A SIGN-IN DOES NOT COUNT EVERY PERSON WHO HAS EVER SIGNED IN (#779).
//
// `RiskEngine.historyOf()` asked the store for the realm's user count — a
// `count(*)` over one row per person — at every sign-in: postgres's busiest
// statement on 8081, and slower with every new person. It is kept per realm
// for `risk.populationUsersCacheS` now.
//
//   U1. fifty assessments in a row ask the store for the count once;
//   U2. fifty asked AT ONCE while it is due ask once, and all get the count;
//   U3. that is past risk.populationUsersCacheS, so it is the NEW number;
//   U4. 0 asks the store every time, as before;
//   U5. a count that failed is not kept: the next one asks again;
//   U6. each realm has its own count, and /admin/caches describes them;
//   U7. a realm of fewer than 1,000 people is counted every time.
//
// In a child process: it replaces the store's distinctValues and changes a
// setting.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'risk_population_users',
  level: process.env.LOG_LEVEL || 'info' });

// Runs in the child. Stringified, so it may use nothing from this file's scope.
function child() {
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };
  const OUT = process.env.RPU_OUT;
  const ROOT = process.env.RPU_ROOT;
  const finish = function () {
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  };
  (async function () {
    const config = require(ROOT + '/common/config');
    const engineModule = require(ROOT + '/risk/risk_engine');
    const cacheRegistry = require(ROOT + '/common/cache_registry');
    let users = 5000;
    let asked = 0;
    let failNext = false;
    const store = { distinctValues: function (realm, subject, feature) {
      if (feature === 'user') {
        asked++;
        if (failNext) {
          failNext = false;
          return Promise.reject(new Error('the store is away'));
        }
        return new Promise(function (resolve) {
          setTimeout(function () {
            resolve(users + (realm === 'other' ? 1000 : 0));
          }, 20);
        });
      }
      return Promise.resolve(0);
    } };
    const deps = Object.assign(engineModule.RiskEngine.defaultDeps(),
                               { store: store });
    const engine = new engineModule.RiskEngine(deps);
    const count = function (realm) {
      return engine.populationUserCount(realm, '*', true);
    };
    config.setOverride('risk.populationUsersCacheS', '60');

    const serial = [];
    for (let i = 0; i < 50; i++) {
      serial.push(await count('r1'));
    }
    note(asked === 1 && serial.every(function (n) {
      return n === 5000;
    }), 'U1. fifty sign-ins in a row ask the store for the count once',
         'asked ' + asked);

    // Due again: the held count made old by hand.
    const realNow = Date.now;
    Date.now = function () {
      return realNow() + 61000;
    };
    users = 5001;
    asked = 0;
    const together = await Promise.all(Array.from({ length: 50 },
      function () {
        return count('r1');
      }));
    note(asked === 1 && together.every(function (n) {
      return n === 5001;
    }), 'U2/U3. past risk.populationUsersCacheS it is counted again — ' +
         'fifty asked at once ask once, and all get the NEW count',
         'asked ' + asked);
    Date.now = realNow;

    config.setOverride('risk.populationUsersCacheS', '0');
    asked = 0;
    for (let i = 0; i < 5; i++) {
      await count('r1');
    }
    note(asked === 5, 'U4. 0 asks the store at every sign-in, as before',
         'asked ' + asked);
    config.setOverride('risk.populationUsersCacheS', '60');
    const small = users;
    users = 10;
    asked = 0;
    for (let i = 0; i < 5; i++) {
      await count('r-small');
    }
    note(asked === 5, 'U7. a realm of fewer than 1,000 people is counted at ' +
         'every sign-in: its count is a few rows and moves fast',
         'asked ' + asked);
    users = small;

    config.setOverride('risk.populationUsersCacheS', '60');
    asked = 0;
    failNext = true;
    let failed = false;
    try {
      await count('r-fail');
    } catch (e) {
      failed = /away/.test(e.message);
    }
    const after = await count('r-fail');
    note(failed && after === 5001 && asked === 2,
         'U5. a count that failed is not kept: the next sign-in asks again',
         'asked ' + asked);

    asked = 0;
    const other = await count('other');
    const again = await count('r1');
    note(other === 6001 && again === 5001 && asked === 1,
         'U6. each realm has its own count', JSON.stringify([other, again]));
    const described = cacheRegistry.detail('risk.population-users');
    note(described && described.rows.length >= 3,
         'U6. and /admin/caches describes them, one row per realm',
         JSON.stringify(described && described.rows.length));
    finish();
  })().catch(function (e) {
    note(false, 'the child threw', (e && e.stack) || e);
    finish();
  });
}

function run(t) {
  log.debug("Entering run().");
  const root = path.join(__dirname, '..');
  const out = path.join(os.tmpdir(), 'sts-rpu-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|CONFIG_FILE$)/.test(key)) {
      env[key] = process.env[key];
    }
  });
  Object.assign(env, { RPU_OUT: out, RPU_ROOT: root, LOG_LEVEL: 'fatal',
                       STS_LOG_LEVEL: 'fatal' });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + child.toString() + ')()'], {
      cwd: root, env: env, encoding: 'utf8', timeout: 180000,
      maxBuffer: 64 * 1024 * 1024 });
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
  name: 'risk_population_users',
  describe: 'a sign-in does not count every person who has ever signed in ' +
            '(#779): the realm\'s user count kept for ' +
            'risk.populationUsersCacheS, one count in flight per realm',
  run: run
};
