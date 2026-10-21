// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: access_token_status_on_demand.js
//
// ===========================================================================
// THE ACCESS-TOKEN STATUS LIST ON DEMAND (#820 part 3).
//
// `access_token_status.entries` is key-resident and filed by jti; the list
// is built from `access_token_status.invalid`, the bits that are revoked,
// which the marker `admin_stats` calls keeps.
//
//   S1. revoking a token with an entry the process does not hold writes its
//       bit, found through the index; un-revoking it clears the bit;
//   S2. revoking a refresh token does not ask the index;
//   S3. counts() takes the live entries from the digests and the INVALID
//       ones from the bits, not from a walk of the entries;
//   S4. fillInvalid() writes the bit of every held entry already revoked.
//
// In a child process: it installs a stand-in reader in `common/realms.js`.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'access_token_status_on_demand',
  level: process.env.LOG_LEVEL || 'info' });

// Runs in the child. Stringified, so it may use nothing from this file's scope.
function child() {
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };
  const OUT = process.env.ATS_OUT;
  const ROOT = process.env.ATS_ROOT;
  try {
    const realms = require(ROOT + '/common/realms');
    const stats = require(ROOT + '/common/admin_stats');
    const status = require(ROOT + '/oauth-oidc/access_token_status');
    const HANDLE = 'access_token_status.entries';
    const future = Date.now() + 3600 * 1000;
    const stored = new Map([
      ['17', { jti: 'at-1', kind: 'oauth', expiresAt: future, allocatedAt: 1 }],
      ['42', { jti: 'at-2', kind: 'oauth', expiresAt: future, allocatedAt: 1 }]
    ]);
    const asked = [];
    let live = true;
    realms.setOnDemandReader({
      active: function (handle) {
        return live && handle === HANDLE;
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
          if ('j:' + value.jti === indexKey) {
            out.push({ key: key, value: value });
          }
        });
        return out;
      },
      digestOf: function (handle, realmId, key) {
        return 'd:' + key;
      },
      journalled: function () {
        return false;
      }
    });
    const declared = realms.handleFor(HANDLE);
    declared.residentAdd('default', 'd:17');
    declared.residentAdd('default', 'd:42');
    const invalid = function () {
      const out = [];
      realms.handleFor('access_token_status.invalid').dump('default')
        .forEach(function (row) {
          out.push(row.key);
        });
      return out.sort().join(',');
    };
    const list = new status.AccessTokenStatus(
      status.AccessTokenStatus.defaultDeps());

    stats.revoke('at-1', 'a test');
    const afterRevoke = invalid();
    stats.restore('at-1');
    note(afterRevoke === '17' && invalid() === '' &&
         asked.indexOf('index:j:at-1') >= 0,
         'S1. a revocation writes the bit of an unheld entry through the ' +
         'index, and un-revoking clears it',
         JSON.stringify({ afterRevoke: afterRevoke, asked: asked }));

    asked.length = 0;
    realms.handleFor('admin_stats.tokens').restore('default', 'rt-1',
      { key: 'rt-1', jti: 'rt-1', kind: 'refresh_token', typ: 'Refresh',
        revocable: true });
    stats.revoke('rt-1', 'a test');
    note(!asked.some(function (one) {
      return one.indexOf('index:') === 0;
    }), 'S2. a refresh token\'s revocation does not ask the index',
         JSON.stringify(asked));

    stats.revoke('at-2', 'a test');
    asked.length = 0;
    const counted = list.counts();
    note(counted.live === 2 && counted.invalid === 1 &&
         !asked.some(function (one) {
           return one.indexOf('read:') === 0;
         }),
         'S3. counts() takes live from the digests and INVALID from the bits',
         JSON.stringify({ counted: counted, asked: asked }));

    live = false;
    realms.handleFor('access_token_status.invalid').remove('default', '42');
    stored.forEach(function (value, key) {
      declared.restore('default', key, value);
    });
    status.AccessTokenStatus.fillInvalid();
    note(invalid() === '42',
         'S4. fillInvalid() writes the bit of every held entry revoked',
         invalid());
  } catch (e) {
    note(false, 'the child threw', (e && e.stack) || e);
  }
  require('fs').writeFileSync(OUT, JSON.stringify(findings));
  process.exit(0);
}

function run(t) {
  log.debug("Entering run().");
  const root = path.join(__dirname, '..');
  const out = path.join(os.tmpdir(), 'sts-ats-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|CONFIG_FILE$)/.test(key)) {
      env[key] = process.env[key];
    }
  });
  Object.assign(env, { ATS_OUT: out, ATS_ROOT: root, LOG_LEVEL: 'fatal',
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
  name: 'access_token_status_on_demand',
  describe: 'the access-token status list on demand: revoked bits kept by ' +
            'the revocation marker (#820)',
  run: run
};
