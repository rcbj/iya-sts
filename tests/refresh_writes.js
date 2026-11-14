// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: refresh_writes.js
//
// ===========================================================================
// FEWER WRITES PER REFRESH (2026-10-22, #820).
//
// On 8081 a refresh made 13.6 store writes, each a sealed row, a change-log
// row every process applies, and index rows; postgres's WAL flush was the
// ceiling. Four of them carried nothing another write did not:
//
//   R1. a successful client authentication deletes a rate-limit bucket only
//       when one exists; a delete is journalled whether or not anything was
//       there;
//   R2. a token holder's row is written a day past its token, so a person
//       refreshing every few hours rewrites it about once a day, not each
//       time; a token that outlives it still writes it;
//   R3. a refresh token superseded on use is not written back to the
//       register — `revokedJtis` holds it and is what enforces it — and the
//       console still sees it revoked; any other revocation still writes
//       the record;
//   R4. with rotation on, what a grant issued is kept on the refresh token's
//       own row and `grantTokens` is not written; `grantMembersOf()` still
//       finds the access token; with rotation off, `grantTokens` is written
//       as before.
//
// In a child process: it counts journalled writes with a persist observer.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'refresh_writes',
  level: process.env.LOG_LEVEL || 'info' });

// Runs in the child. Stringified, so it may use nothing from this file's scope.
function child() {
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };
  const OUT = process.env.RW_OUT;
  const ROOT = process.env.RW_ROOT;
  (async function () {
    const realms = require(ROOT + '/common/realms');
    const config = require(ROOT + '/common/config');
    const websecurity = require(ROOT + '/common/websecurity');
    const stats = require(ROOT + '/common/admin_stats');
    const bcp = require(ROOT + '/oauth-oidc/oauth2_bcp');
    const written = [];
    realms.setPersistObserver(function (handle, realmId, key) {
      written.push(handle + ' ' + key);
    });
    const of = function (handle) {
      return written.filter(function (one) {
        return one.indexOf(handle + ' ') === 0;
      }).length;
    };
    const inRealm = function (fn) {
      return realms.run(realms.get(realms.currentId()), fn);
    };

    const req = { headers: {}, ip: '192.0.2.9',
                  socket: { remoteAddress: '192.0.2.9' } };
    written.length = 0;
    websecurity.succeeded('rw-door', req, 'nobody-failed');
    const quiet = of('security.rateLimitBuckets');
    websecurity.attempt('rw-door', req, 'someone', { max: 5, windowS: 60 });
    written.length = 0;
    websecurity.succeeded('rw-door', req, 'someone');
    const cleared = of('security.rateLimitBuckets');
    note(quiet === 0 && cleared === 2,
         'R1. a success deletes a rate-limit bucket only when one exists',
         JSON.stringify({ absent: quiet, present: cleared }));

    const now = Math.floor(Date.now() / 1000);
    let n = 0;
    const record = function (exp, kind) {
      n++;
      stats.recordJwt({ jti: 'rw-' + n, sub: 'rw-person', iat: now,
                        username: 'rw-person',
                        exp: exp, typ: kind === 'refresh_token' ? 'Refresh'
                          : 'Bearer' },
                      'signed-' + n, { kind: kind || 'access_token',
                                       username: 'rw-person' });
    };
    inRealm(function () {
      written.length = 0;
      record(now + 3600);
      const first = of('admin_stats.tokenHolders');
      record(now + 3600 + 9 * 3600);
      record(now + 3600 + 18 * 3600);
      const within = of('admin_stats.tokenHolders') - first;
      record(now + 3600 + 30 * 3600);
      const beyond = of('admin_stats.tokenHolders') - first - within;
      note(first === 1 && within === 0 && beyond === 1,
           'R2. a holder\'s row is written a day past its token, and again ' +
           'only once a token outlives it',
           JSON.stringify({ first: first, within: within, beyond: beyond }));
    });

    inRealm(function () {
      record(now + 7200, 'refresh_token');
      const jti = 'rw-' + n;
      written.length = 0;
      stats.revoke(jti, 'RFC 9700 section 2.2.2: rotated on use',
                   { superseded: true }, now + 7200);
      const rotatedWrites = { register: of('admin_stats.tokens'),
                              revoked: of('admin_stats.revokedJtis') };
      const listed = stats.tokenList().filter(function (one) {
        return one.jti === jti;
      })[0];
      record(now + 7200, 'refresh_token');
      const other = 'rw-' + n;
      written.length = 0;
      stats.revoke(other, 'an operator', null, now + 7200);
      const operatorWrites = of('admin_stats.tokens');
      note(rotatedWrites.register === 0 && rotatedWrites.revoked === 1 &&
           listed && listed.revoked === true && listed.state === 'revoked' &&
           stats.isRevoked(jti) && operatorWrites === 1,
           'R3. a superseded token is not written back to the register, the ' +
           'console still sees it revoked, and other revocations still write',
           JSON.stringify({ rotated: rotatedWrites, listed: listed &&
             { revoked: listed.revoked, state: listed.state },
             operator: operatorWrites }));
    });

    inRealm(function () {
      config.setOverride('oauth2.refreshTokenRotation', true);
      written.length = 0;
      bcp.noteRefreshIssued('rw-rt-1', '', 'rw-client', '',
                            { access: 'rw-at-1', expSec: now + 7200 });
      bcp.noteGrantTokens('rw-rt-1', 'rw-rt-1', 'rw-at-1', 'rw-client',
                          now + 7200);
      const on = { refresh: of('oauth2_bcp.refreshTokens'),
                   grants: of('oauth2_bcp.grantTokens') };
      const members = bcp.grantMembersOf('rw-rt-1', '');
      config.setOverride('oauth2.refreshTokenRotation', false);
      written.length = 0;
      bcp.noteGrantTokens('rw-fam-2', 'rw-rt-2', 'rw-at-2', 'rw-client',
                          now + 7200);
      const off = of('oauth2_bcp.grantTokens');
      const offMembers = bcp.grantMembersOf('rw-fam-2', '');
      note(on.refresh === 1 && on.grants === 0 &&
           members.indexOf('rw-at-1') >= 0 && members.indexOf('rw-rt-1') >= 0 &&
           off === 1 && offMembers.indexOf('rw-at-2') >= 0,
           'R4. with rotation on, the grant is kept on the refresh token\'s ' +
           'row and found from there; off, grantTokens is written as before',
           JSON.stringify({ on: on, members: members, off: off,
                            offMembers: offMembers }));
    });
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
  const out = path.join(os.tmpdir(), 'sts-rw-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|CONFIG_FILE$)/.test(key)) {
      env[key] = process.env[key];
    }
  });
  Object.assign(env, { RW_OUT: out, RW_ROOT: root, LOG_LEVEL: 'fatal',
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
  name: 'refresh_writes',
  describe: 'a refresh writes fewer rows: no absent rate-limit deletes, ' +
            'holder rows with headroom, no register rewrite for a superseded ' +
            'token, and the grant on the refresh token\'s row (#820)',
  run: run
};
