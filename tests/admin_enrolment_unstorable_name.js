// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: admin_enrolment_unstorable_name.js
//
// ===========================================================================
// AN ADMINISTRATOR'S PASSKEY ENROLMENT FOR A NAME NO PERSON CAN HAVE.
//
// The fuzz run on 7fc43a1de (2026-11-12) posted `finish-passkey-enrolment`
// with a `user` holding U+0000. The finish spends the pending record before
// anything else, and the record is keyed by the administrator and the person
// joined with a newline, so the delete was journalled under a key holding a
// NUL: `credentials.pendingAdminKeys` logged STS-STORE-0063 and kept the row
// in memory only. This file holds both halves of the fix:
//
//   A. both doors refuse such a name, STS-AUTHN-0556, quoting nothing;
//   B. `abandonAdminKeyEnrolment()` reports no write for one, and still
//      reports one for an ordinary name (so the observer is really there).
//
// WHY IN A CHILD: B installs `realms.setPersistObserver()`, which has no
// getter, and in the shared process it would replace persistence's own.
// ===========================================================================

delete process.env.CONFIG_FILE;

const path = require('path');
const os = require('os');
const fs = require('fs');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'admin_enrolment_unstorable_name',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.AEU_ROOT;
  const OUT = process.env.AEU_OUT;
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  try {
    const realms = require(ROOT + '/common/realms');
    const errorCodes = require(ROOT + '/common/error_codes');
    require(ROOT + '/ldap/ldap_server');
    const credentials = require(ROOT + '/common/credentials');
    const actions = require(ROOT + '/admin-core/admin_actions');
    const writes = [];
    realms.setPersistObserver(function (handle, realmId, key) {
      if (handle === 'credentials.pendingAdminKeys') {
        writes.push(String(key));
      }
    });
    const context = { via: 'api', actor: 'tester', base: 'https://sts.test',
                      admin: { username: 'tester', sub: 'urn:uuid:t' } };
    const names = { nul: 'a\u0000b', newline: 'tester\nalice',
                    lone: 'a\ud800b', bell: 'a\u0007b' };
    Object.keys(names).forEach(function (kind) {
      ['begin-passkey-enrolment', 'finish-passkey-enrolment']
        .forEach(function (action) {
          writes.length = 0;
          // NO `credential`, as the fuzzer sent it: the finish then spends
          // the pending record at once (STS-AUTHN-0448's path), which is
          // the delete that was journalled under a NUL.
          const out = actions.usersAction({ action: action,
            user: names[kind] }, context);
          const text = JSON.stringify(out && out.errors || []);
          note(out && out.ok === false &&
               errorCodes.codeOf(out) === 'STS-AUTHN-0556',
               'A. ' + action + ' refuses a ' + kind + ' in the name as ' +
               'STS-AUTHN-0556', errorCodes.codeOf(out) + ' ' + text);
          note(text.indexOf(names[kind]) < 0,
               'A. and the refusal does not quote the name');
          note(writes.length === 0,
               'A. and nothing was written to the pending store',
               JSON.stringify(writes));
        });
    });
    writes.length = 0;
    credentials.abandonAdminKeyEnrolment('tester', 'a\u0000b');
    note(writes.length === 0,
         'B. abandoning under a NUL name reports no write',
         JSON.stringify(writes));
    credentials.abandonAdminKeyEnrolment('tester', 'alice');
    note(writes.length === 1 && writes[0].indexOf('\u0000') < 0,
         'B. abandoning under an ordinary name still reports one',
         JSON.stringify(writes));
  } catch (e) {
    note(false, 'the child ran to the end', (e && e.stack) || e);
  }
  require('fs').writeFileSync(OUT, JSON.stringify(findings));
  process.exit(0);
}

function inAChild(t) {
  log.debug("Entering inAChild().");
  const out = path.join(os.tmpdir(), 'aeu-' + process.pid + '-' +
                        require('crypto').randomBytes(8).toString('hex') +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|ADMIN_|CONFIG_FILE$)/
        .test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', AEU_ROOT: ROOT,
                                  AEU_OUT: out }),
      encoding: 'utf8', timeout: 240000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
    // No report: the child died before writing one. Reported below with its
    // exit status and stderr, which is where the reason is.
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written, which the read above has already reported.
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings), 'the child process reported its ' +
                                        'findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-800))) {
    log.debug("Leaving inAChild().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving inAChild().");
}

async function run(t) {
  log.debug("Entering run().");
  inAChild(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'admin_enrolment_unstorable_name',
  describe: 'an administrator\'s passkey enrolment refuses a person\'s name ' +
            'holding a NUL, a control character or a lone surrogate before ' +
            'the pending record is touched (STS-AUTHN-0556), so nothing ' +
            'PostgreSQL cannot store is journalled',
  run: run
};
