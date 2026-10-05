// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/console_claim_at_issuance.js
// ===========================================================================
// THE BOOTSTRAP ADMINISTRATOR CLAIMS THE CONSOLE AT ISSUANCE (#446,
// 2026-10-05).
//
// The bootstrap administrator holds its console roles only once it has
// claimed the console (#103): signed in to it — in product, with a password
// this service verified. The server-rendered console made the claim from its
// own callback. A console that is a static client of `/admin-api` has no
// callback on the server, and until the claim is made the authorization
// endpoint narrows `admin:read` and `admin:write` off the token the console
// needs. So the claim is made where the console's own client is issued a
// gated permission: `common/role_permissions.ts`'s `noteConsoleSignIn()`,
// which the authorization endpoint calls before it narrows.
//
// In a CHILD PROCESS, in a realm of its own switched to product, with that
// realm's bootstrap administrator seeded and unclaimed:
//
//   1. before the claim the account is pending, and both admin scopes are
//      narrowed off a request made in its name;
//   2. ANOTHER client asking on a local password sign-in claims nothing;
//   3. the console's client on a FEDERATED sign-in claims nothing, nor on a
//      Kerberos one, nor for an application as the subject, nor for
//      somebody who is not the bootstrap administrator;
//   4. the console's client on a local password sign-in claims it: the
//      account is no longer pending, the claim is recorded, and both admin
//      scopes are issued;
//   5. and the default realm's own window is exactly as it was.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'console_claim_at_issuance',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.AG_ROOT;
  const OUT = process.env.AG_OUT;
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const config = require(ROOT_DIR + '/common/config');
    const realms = require(ROOT_DIR + '/common/realms');
    const rbac = require(ROOT_DIR + '/admin-ui/admin_rbac');
    const rolePermissions = require(ROOT_DIR + '/common/role_permissions');

    const T = 'cc' + process.pid;
    const CONSOLE = rolePermissions.CONSOLE_CLIENT_ID;
    const SCOPE = 'openid admin:read admin:write';
    realms.create({ id: T, name: 'The claim at issuance' });
    const inT = function (fn) {
      return realms.run(realms.get(T), fn);
    };
    const seeded = rbac.seedBootstrapAdministrator(T);
    const ADMIN = String(config.value('admin.bootstrapUsername') || 'admin');
    const person = { kind: 'user', name: ADMIN, authenticated: true };
    const defaultBefore = JSON.stringify(rbac.bootstrapState());
    const switched = inT(function () {
      return config.setOverride('global.mode', 'product');
    });
    note(seeded && seeded.ran && seeded.created &&
         (!switched || switched.ok !== false),
         'precondition: a realm in product mode with its bootstrap ' +
         'administrator seeded', JSON.stringify({ seeded: seeded,
                                                  switched: switched }));
    const pending = function () {
      return rbac.rolesOf(ADMIN, T).claimPending === true;
    };
    const narrow = function () {
      return inT(function () {
        return rolePermissions.narrowScope(SCOPE, person,
          { clientId: CONSOLE, grant: 'authorization_code' });
      });
    };
    const claim = function (subject, signIn) {
      return inT(function () {
        return rolePermissions.noteConsoleSignIn(subject, signIn);
      });
    };
    const has = function (scope, value) {
      return String(scope || '').split(/\s+/).indexOf(value) >= 0;
    };

    // --- 1. before the claim ------------------------------------------------
    let narrowed = narrow();
    note(pending() && !has(narrowed.scope, 'admin:read') &&
         !has(narrowed.scope, 'admin:write') && has(narrowed.scope, 'openid'),
         '1. before the claim the account is pending, and both admin scopes ' +
         'are narrowed off', pending() + ' ' + JSON.stringify(narrowed));

    // --- 2. another client ---------------------------------------------------
    note(claim(person, { clientId: 'some-other-client', amr: ['pwd'],
                         signInAuthority: 'local' }) === false && pending(),
         '2. another client asking on a local password sign-in claims ' +
         'nothing', String(pending()));

    // --- 3. sign-ins that are not a password verified here -------------------
    note(claim(person, { clientId: CONSOLE, amr: ['pwd', 'federated'],
                         signInAuthority: 'federation' }) === false &&
         pending(),
         '3a. the console\'s client on a federated sign-in claims nothing',
         String(pending()));
    note(claim(person, { clientId: CONSOLE, amr: ['pwd'],
                         signInAuthority: 'kerberos' }) === false && pending(),
         '3b. nor on a Kerberos one, whose amr also says pwd',
         String(pending()));
    note(claim(person, { clientId: CONSOLE, amr: ['hwk'],
                         signInAuthority: 'local' }) === false && pending(),
         '3c. nor on a security key with no password', String(pending()));
    note(claim({ kind: 'application', name: ADMIN, authenticated: true },
               { clientId: CONSOLE, amr: ['pwd'],
                 signInAuthority: 'local' }) === false && pending(),
         '3d. nor for an application as the subject', String(pending()));
    note(claim({ kind: 'user', name: 'cc-somebody-else', authenticated: true },
               { clientId: CONSOLE, amr: ['pwd'],
                 signInAuthority: 'local' }) === false && pending(),
         '3e. nor for somebody who is not the bootstrap administrator',
         String(pending()));
    narrowed = narrow();
    note(!has(narrowed.scope, 'admin:write'),
         '3f. and after all of them the admin scopes are still narrowed off',
         JSON.stringify(narrowed));

    // --- 4. the claim --------------------------------------------------------
    const claimed = claim(person, { clientId: CONSOLE, amr: ['pwd'],
                                    signInAuthority: 'local' });
    narrowed = narrow();
    note(claimed === true && !pending() &&
         !!rbac.bootstrapState(T).claimedAt,
         '4a. the console\'s client on a local password sign-in claims the ' +
         'console: no longer pending, and the claim is recorded',
         claimed + ' ' + pending() + ' ' +
         JSON.stringify(rbac.bootstrapState(T)));
    note(has(narrowed.scope, 'admin:read') && has(narrowed.scope,
                                                  'admin:write'),
         '4b. and both admin scopes are issued', JSON.stringify(narrowed));

    // --- 5. the default realm ------------------------------------------------
    note(JSON.stringify(rbac.bootstrapState()) === defaultBefore,
         '5. the default realm\'s own window is exactly as it was',
         JSON.stringify(rbac.bootstrapState()) + ' against ' + defaultBefore);

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
  const out = path.join(os.tmpdir(), 'cc-' + process.pid + '-' + Date.now() +
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
                                  AG_ROOT: ROOT, AG_OUT: out }),
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
  name: 'console_claim_at_issuance',
  describe: 'the bootstrap administrator claims the console when the ' +
            'console\'s own client is issued a gated permission, by the ' +
            'rule the console\'s callback applied (#446)',
  run: run
};
