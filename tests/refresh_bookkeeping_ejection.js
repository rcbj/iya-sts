// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: refresh_bookkeeping_ejection.js
//
// ===========================================================================
// AN ISSUANCE DOES NOT WALK THE REFRESH-TOKEN FAMILIES; THE EJECTION JOB
// DROPS WHAT HAS EXPIRED, AND THE CAP IS STILL KEPT AT THE INSERT (#761).
//
// `noteRefreshIssued()` and `noteGrantTokens()` swept every record of the
// realm on every issuance to drop the expired ones — a cost that grew with
// the population under a sign-in load (the cap is a million). The expiry is
// `caches.eject-expired`'s now (the root CLAUDE.md's rule for periodic
// work), through the bookkeeping's descriptor on `/admin/caches`.
//
//   R1. the bookkeeping is described to /admin/caches, with an ejector;
//   R2. an issuance below the cap leaves an expired record where it is (it
//       no longer sweeps) — and the ejector run at that instant drops it,
//       and only it;
//   R3. past `oauth2.maxRefreshTokenFamilies` the insert still keeps the
//       realm at the cap.
//
// In a child process: it changes settings and the module-wide stores.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'refresh_bookkeeping_ejection',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

/**
 * The child process: drives the bookkeeping and reports what it found.
 *
 * @returns {void}
 */
function childMain() {
  const ROOT_DIR = process.env.RB_ROOT;
  const OUT = process.env.RB_OUT;
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  try {
    const config = require(ROOT_DIR + '/common/config');
    const bcp = require(ROOT_DIR + '/oauth-oidc/oauth2_bcp');
    const cacheRegistry = require(ROOT_DIR + '/common/cache_registry');
    config.setOverride('oauth2.refreshTokenRotation', 'true');
    const NAME = 'oauth2.refresh-token-bookkeeping';
    const tokens = function () {
      const d = cacheRegistry.detail(NAME);
      const row = d && d.rows.filter(function (r) {
        return r.realm === 'default' || r.realm === '';
      })[0];
      const m = row ? /^(\d+) token/.exec(row.key) : null;
      return m ? Number(m[1]) : 0;
    };
    note(cacheRegistry.has(NAME), 'R1. the bookkeeping is described to ' +
         '/admin/caches');

    // An expired record: issued with the clock an hour and a window back.
    const realNow = Date.now;
    const past = realNow() - 10 * 365 * 24 * 3600 * 1000;
    Date.now = function () {
      return past;
    };
    bcp.noteRefreshIssued('rb-expired', '', 'rb-client', '');
    Date.now = realNow;
    const withExpired = tokens();
    bcp.noteRefreshIssued('rb-live', '', 'rb-client', '');
    note(tokens() === withExpired + 1,
         'R2a. an issuance below the cap leaves the expired record where ' +
         'it is', withExpired + ' then ' + tokens());
    const ejected = cacheRegistry.ejectExpired(realNow());
    note(tokens() === withExpired,
         'R2b. the ejection job drops the expired record',
         JSON.stringify(ejected && ejected.byStore && ejected.byStore[NAME]));
    bcp.noteRefreshIssued('rb-live-2', '', 'rb-client', '');
    cacheRegistry.ejectExpired(realNow());
    note(tokens() === withExpired + 1,
         'R2c. and leaves the live ones', String(tokens()));

    // The setting's minimum is 100.
    config.setOverride('oauth2.maxRefreshTokenFamilies', '100');
    for (let i = 0; i < 120; i++) {
      bcp.noteRefreshIssued('rb-cap-' + i, '', 'rb-client', '');
    }
    note(tokens() <= 100, 'R3. past oauth2.maxRefreshTokenFamilies the ' +
         'insert still keeps the realm at the cap', String(tokens()));
  } catch (e) {
    note(false, 'the child threw', (e && e.stack) || e);
  }
  fs.writeFileSync(OUT, JSON.stringify(findings));
  process.exit(0);
}

function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'rb-' + process.pid + '-' + Date.now() +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OAUTH2_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal',
                                  RB_ROOT: ROOT, RB_OUT: out }),
      encoding: 'utf8', timeout: 120000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings),
               'the child process reported its findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-800))) {
    log.debug("Leaving run().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'refresh_bookkeeping_ejection',
  describe: 'an issuance does not walk the refresh-token families (#761): ' +
            'the ejection job drops what has expired, and the cap is still ' +
            'kept at the insert',
  run: run
};
