// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: own_password_helper.js
//
// ===========================================================================
// THE PROTOCOL JOBS' HELPER THAT MAKES A TYPED PASSWORD THE PERSON'S OWN
// (#2160), DRIVEN OVER HTTP.
//
// `tests/protocol/own_password.js` is what the shared kits (console_signin,
// sts_applications' ensurePerson, cells_kit, passkey_wire_kit and the rest)
// call since a password an administrator types is temporary in product. No
// protocol job can show it works without a product stack, so this test
// does. In a CHILD PROCESS with the whole stack on an ephemeral port and an
// administrator door of `POST /admin-api/users/set-password` with a program's
// token:
//
//   A. PRODUCT: `ownPassword()` leaves the person holding the password with
//      no change owed. A door that cannot ask for a new one accepts it (its
//      only answer is the realm's second-factor rule, which comes after the
//      password verified).
//   B. DEVELOPMENT: the password is set directly, and nobody signs in.
//   C. PRODUCT, a SERVICE ACCOUNT: set directly too, since its password is
//      not temporary.
//   D. PRODUCT, a password the policy refuses: the helper fails, naming the
//      change step's refusal, rather than leaving a temporary password.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'own_password_helper',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.OPH_ROOT;
  const OUT = process.env.OPH_OUT;
  const http = require('http');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    const config = require(ROOT_DIR + '/common/config');
    const realms = require(ROOT_DIR + '/common/realms');
    const oauth2 = require(ROOT_DIR + '/oauth-oidc/oauth2');
    const credentials = require(ROOT_DIR + '/common/credentials');
    const applications = require(ROOT_DIR + '/common/applications');
    const serviceAccounts = require(ROOT_DIR + '/common/service_accounts');
    const ldap = require(ROOT_DIR + '/ldap/ldap_server');
    const ownPassword = require(ROOT_DIR + '/tests/protocol/own_password');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const base = 'http://127.0.0.1:' + port;
    config.setOverride('oauth2.consentRequired', false);
    // THE CONSOLE'S CALLBACK, REGISTERED: a product stack has it from
    // STS_PUBLIC_BASE_URL at start, and the helper signs in through it.
    realms.run(realms.DEFAULT_REALM, function () {
      return applications.updateApplication('sts-admin-console', {
        attribute: 'oauthRedirectUri', mode: 'add',
        value: base + '/admin/callback', actor: 'the test' });
    });
    const token = await realms.run(realms.DEFAULT_REALM, function () {
      return oauth2.accessTokenAsync(base, { audience: base + '/admin-api',
        scope: 'admin:read admin:write', client_id: 'sts-api-client',
        sub: 'sts-api-client' });
    });
    const setPassword = async function (who, value) {
      const r = await fetch(base + '/admin-api/users/set-password', {
        method: 'POST',
        headers: { 'content-type': 'application/json',
                   authorization: 'Bearer ' + token },
        body: JSON.stringify({ user: who, password: value }) });
      return { status: r.status, json: await r.json().catch(function () {
        return null;
      }) };
    };
    let calls = 0;
    const counted = function (who, value) {
      calls += 1;
      return setPassword(who, value);
    };
    const stamp = String(process.pid);
    const PW = 'Job-Own-Passw0rd!' + stamp;
    const person = function (name) {
      ldap.createUser(name, { invent: false,
        attributes: { givenName: 'Oph', sn: name,
                      mail: name + '@example.test' } });
      return ldap.objectFor(name).entry.dn;
    };
    // The password is right and no change is owed. Product requires a
    // second factor of everybody by default, which a door with nowhere to
    // ask for one answers AFTER the password verified.
    const ownsIt = function (name, password) {
      const checked = credentials.verify(name, password,
                                         { via: 'the test', door: 'ldap' });
      return !!checked && (checked.ok === true ||
                           checked.reason === 'second-factor-required') &&
             !credentials.passwordResetRequired(name);
    };

    // --- B. development ------------------------------------------------
    const DEV = 'oph-dev-' + stamp;
    person(DEV);
    calls = 0;
    await ownPassword.ownPassword(base, DEV, PW, counted);
    note(ownsIt(DEV, PW) && calls === 2,
         'B. development: the temporary password, then the job\'s, both set ' +
         'directly, with no sign-in', 'calls ' + calls);

    config.setOverride('global.mode', 'product');
    try {
      // --- A. product ------------------------------------------------
      const PROD = 'oph-prod-' + stamp;
      person(PROD);
      calls = 0;
      await ownPassword.ownPassword(base, PROD, PW, counted);
      note(ownsIt(PROD, PW) && calls === 1,
           'A. product: the person chose the job\'s password at the change ' +
           'step and owes no change',
           JSON.stringify({ calls: calls,
             reset: credentials.passwordResetRequired(PROD) }));

      // --- C. a service account ----------------------------------------
      const SVC = 'oph-svc-' + stamp;
      const ownerDn = person('oph-owner-' + stamp);
      person(SVC);
      serviceAccounts.set(SVC, { serviceAccount: true, owners: [ownerDn] });
      calls = 0;
      await ownPassword.ownPassword(base, SVC, PW, counted);
      note(calls === 2 && !credentials.passwordResetRequired(SVC),
           'C. product: a service account\'s password is set directly',
           'calls ' + calls);

      // --- D. a password the policy refuses -----------------------------
      const WEAK = 'oph-weak-' + stamp;
      person(WEAK);
      let thrown = '';
      try {
        await ownPassword.ownPassword(base, WEAK, 'Sh0rt!', setPassword);
      } catch (e) {
        thrown = String((e && e.message) || e);
      }
      note(/change step answered 400/.test(thrown),
           'D. product: a password the policy refuses fails the helper at ' +
           'the change step', thrown.slice(0, 300));
    } finally {
      config.clearOverride('global.mode');
    }

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
  const out = path.join(os.tmpdir(), 'oph-' + process.pid + '-' +
                        Date.now() + '.json');
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
                                  OPH_ROOT: ROOT, OPH_OUT: out }),
      encoding: 'utf8', timeout: 240000, cwd: ROOT
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
  name: 'own_password_helper',
  describe: 'tests/protocol/own_password.js makes a typed password the ' +
            'person\'s own: chosen at the change step in product, set ' +
            'directly in development and for a service account (#2160)',
  run: run
};
