// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';

// ===========================================================================
// tests/console_role_needs_person.js — A CONSOLE ROLE IS GRANTED ONLY TO A
// PERSON WHO EXISTS (rcbj, 2026-11-11).
//
// `admin-ui/admin_rbac.ts`'s grant() used to write a name with no entry as
// the uid DN where they would go, a membership that dangled until somebody
// of that name arrived. #1624 made the directory refuse a group member that
// names no stored entry (STS-LDAP-0212, `danglingMember`), so the old grant
// became a refusal worded as a DN; and #1613's rule is that a person created
// later under an old name inherits nothing. The grant now asks first and
// refuses under STS-ADMIN-0920, in a sentence naming the person.
//
// The claims:
//
//   1. A grant to a name with no entry is refused with STS-ADMIN-0920 and
//      `reason: 'noSuchPerson'`, its sentence names the person, and nothing
//      is written: the roster's count does not move and the name holds no
//      role group — in a trust realm and in the default realm.
//   2. A grant to a person who exists still works, and the membership
//      resolves to their entry.
//   3. THE /admin-api DOOR ANSWERS THE SAME: 400 with the same reason and
//      sentence for the absent name, and the code itself is NOT in the
//      answer (it is recorded, never sent); 200 for a person who exists.
//
// In a CHILD PROCESS, for `admin_api_actor.js`'s reason: it loads the whole
// protocol stack and writes to the default realm's roster, which every other
// file in `run.js`'s one process shares.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'console_role_needs_person',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.CR_ROOT;
  const OUT = process.env.CR_OUT;
  const http = require('http');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  function call(port, urlPath, body) {
    return new Promise(function (resolve, reject) {
      const text = JSON.stringify(body);
      const req = http.request({ host: '127.0.0.1', port: port,
                                 path: urlPath, method: 'POST',
                                 headers: {
                                   accept: 'application/json',
                                   'content-type': 'application/json',
                                   'content-length': Buffer.byteLength(text)
                                 } }, function (res) {
        let raw = '';
        res.on('data', function (d) { raw += d; });
        res.on('end', function () {
          let json = null;
          try {
            json = JSON.parse(raw);
          } catch (e) {
            // Not JSON; the finding reports the text.
            json = null;
          }
          resolve({ status: res.statusCode, text: raw, json: json || {} });
        });
      });
      req.on('error', reject);
      req.end(text);
    });
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    const config = require(ROOT_DIR + '/common/config');
    const realms = require(ROOT_DIR + '/common/realms');
    const rbac = require(ROOT_DIR + '/admin-ui/admin_rbac');
    const ldap = require(ROOT_DIR + '/ldap/ldap_server');
    const errorCodes = require(ROOT_DIR + '/common/error_codes');

    const stamp = String(process.pid);
    const R = 'cr' + stamp;
    const GHOST = 'cr-ghost-' + stamp;
    const PERSON = 'cr-person-' + stamp;
    const GHOST_API = 'cr-ghost-api-' + stamp;
    const PERSON_API = 'cr-person-api-' + stamp;
    realms.create({ id: R, name: 'A role needs a person' });
    const inR = function (fn) {
      return realms.run(realms.get(R), fn);
    };

    // -------------------------------------------------------------------
    // 1. THE ABSENT NAME IS REFUSED, AND NOTHING IS WRITTEN.
    // -------------------------------------------------------------------
    const absent = function (where, realmId) {
      const before = rbac.describe(realmId).grantCount;
      const refused = rbac.grant(GHOST, 'write',
                                 { via: 'test', realm: realmId });
      const said = (refused.errors || []).join(' ');
      note(refused.ok === false &&
           errorCodes.codeOf(refused) === 'STS-ADMIN-0920' &&
           refused.reason === 'noSuchPerson',
           '1a. ' + where + ': a grant to a name with no entry is refused ' +
           'with STS-ADMIN-0920, reason noSuchPerson',
           JSON.stringify([errorCodes.codeOf(refused), refused]));
      note(said.indexOf('"' + GHOST + '"') >= 0 &&
           /create the person first/i.test(said) &&
           said.indexOf('danglingMember') < 0,
           '1b. ' + where + ': and the sentence names the person and says ' +
           'to create them, rather than quoting the directory\'s refusal',
           said);
      note(rbac.describe(realmId).grantCount === before &&
           rbac.rolesOf(GHOST, realmId).groups.length === 0,
           '1c. ' + where + ': and nothing is written — the roster does ' +
           'not move and the name holds no role group',
           JSON.stringify([before, rbac.describe(realmId).grantCount,
                           rbac.rolesOf(GHOST, realmId).groups]));
    };
    absent('in a trust realm', R);
    absent('in the default realm', realms.DEFAULT_ID);

    // -------------------------------------------------------------------
    // 2. A PERSON WHO EXISTS IS GRANTED THE ROLE.
    // -------------------------------------------------------------------
    const made = inR(function () {
      return ldap.createUser(PERSON, { invent: false });
    });
    const granted = rbac.grant(PERSON, 'write', { via: 'test', realm: R });
    note(made.ok && granted.ok === true && granted.changed === true &&
         granted.resolves === true &&
         String(granted.member) === String(made.dn) &&
         rbac.rolesOf(PERSON, R).groups.length === 1,
         '2. a grant to a person who exists still works, and the ' +
         'membership is their own entry',
         JSON.stringify([made.dn, granted]));

    // -------------------------------------------------------------------
    // 3. THE /admin-api DOOR. Development's open API (no token) is enough:
    // what is asserted is the grant's answer, not the gate in front of it.
    // -------------------------------------------------------------------
    config.setOverride('adminApi.authRequired', false);
    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const before = rbac.describe(R).grantCount;
    let r = await call(port, '/realm/' + R + '/admin-api/rbac/grant',
                       { username: GHOST_API, role: 'read' });
    const said = (r.json.errors || []).join(' ');
    note(r.status === 400 && r.json.ok === false &&
         r.json.reason === 'noSuchPerson' &&
         said.indexOf('"' + GHOST_API + '"') >= 0,
         '3a. POST /admin-api/rbac/grant for a name with no entry answers ' +
         '400, reason noSuchPerson, naming them',
         r.status + ' ' + r.text.slice(0, 400));
    note(r.text.indexOf('STS-ADMIN-0920') < 0,
         '3b. and the error code is recorded, never sent',
         r.text.slice(0, 400));
    note(rbac.describe(R).grantCount === before &&
         rbac.rolesOf(GHOST_API, R).groups.length === 0,
         '3c. and nothing is written through that door either',
         before + ' -> ' + rbac.describe(R).grantCount);
    inR(function () {
      return ldap.createUser(PERSON_API, { invent: false });
    });
    r = await call(port, '/realm/' + R + '/admin-api/rbac/grant',
                   { username: PERSON_API, role: 'read' });
    note(r.status === 200 && r.json.ok === true && r.json.changed === true &&
         rbac.rolesOf(PERSON_API, R).groups.length === 1,
         '3d. and the same door grants the role to a person who exists',
         r.status + ' ' + r.text.slice(0, 400));
    config.clearOverride('adminApi.authRequired');

    server.close();
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    note(false, 'the child process ran to the end', e && e.stack);
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

async function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'cr-' + process.pid + '-' + Date.now() +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$|ADMIN_API_)/
        .test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal',
                                  CR_ROOT: ROOT, CR_OUT: out }),
      encoding: 'utf8', timeout: 180000, cwd: ROOT
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
  name: 'console_role_needs_person',
  describe: 'a console role is granted only to a person who exists: a name ' +
            'with no entry is refused STS-ADMIN-0920 and nothing is ' +
            'written, at the module and at /admin-api (2026-11-11)',
  run: run
};
