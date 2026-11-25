// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: admin_typed_password_temporary.js
//
// ===========================================================================
// A PASSWORD AN ADMINISTRATOR TYPED IS TEMPORARY (#2160, ASVS 5.0.0 6.4.6;
// rcbj, 2026-11-24).
//
// The administrator knows it, so where passwords are verified (product
// mode) the person must choose their own at the next sign-in (`pwdReset`),
// as they already must after a generated one (#1446). Typed passwords are
// still accepted. In a CHILD PROCESS with the whole stack:
//
//   A. DEVELOPMENT: a typed `set-password` sets no `pwdReset`, since no
//      door checks a password there.
//   B. PRODUCT, `set-password`: a typed password is set, `pwdReset` goes on,
//      the answer says it is temporary and echoes no password, and the
//      audit row says `mustChange`.
//   C. PRODUCT, `create` with a typed password: `pwdReset` is on.
//   D. PRODUCT, a SERVICE ACCOUNT (common/CLAUDE.md 3cd): a typed password
//      sets no `pwdReset`; its password is a program's.
//   E. PRODUCT, LDAP: an administrator's modify of somebody else's
//      `userPassword` sets `pwdReset` in the same write; an administrator's
//      add of a person with one does too; a person's modify of their OWN
//      password does not.
//   F. DEVELOPMENT, LDAP: an administrator's modify sets no `pwdReset`.
//   G. PRODUCT, `set-service-account` on a person who owes a change (#2236,
//      rcbj, 2026-11-25): the change is cleared, the audit row says
//      `passwordResetCleared`, and the password works at a door that cannot
//      ask for a new one; for one who owes none, nothing is said.
//
// The keytab reset's half (#2160: it neither sets nor clears the flag, and
// product refuses it while a change is owed, STS-ADMIN-0969) is in
// `tests/kerberos_person_keytab.js`, which already drives that door.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'admin_typed_password_temporary',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.ATP_ROOT;
  const OUT = process.env.ATP_OUT;
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const config = require(ROOT_DIR + '/common/config');
    const audit = require(ROOT_DIR + '/common/audit');
    const credentials = require(ROOT_DIR + '/common/credentials');
    const serviceAccounts = require(ROOT_DIR + '/common/service_accounts');
    const ldap = require(ROOT_DIR + '/ldap/ldap_server');
    const rbac = require(ROOT_DIR + '/admin-ui/admin_rbac');
    const actions = require(ROOT_DIR + '/admin-core/admin_actions');

    const stamp = String(process.pid);
    const context = { via: 'api', actor: 'atp-tester' };
    const PW = 'Typed-Temporary-Passw0rd!' + stamp;
    const person = function (name) {
      ldap.createUser(name, { invent: false,
        attributes: { givenName: 'Typed', sn: name,
                      mail: name + '@example.test' } });
      return ldap.objectFor(name).entry.dn;
    };
    const flagOf = function (name) {
      const view = ldap.objectFor(name);
      const attributes = (view && view.entry && view.entry.attributes) || {};
      const key = Object.keys(attributes).filter(function (one) {
        return one.toLowerCase() === 'pwdreset';
      })[0];
      return key ? [].concat(attributes[key]).map(String).join() : '';
    };
    const modify = function (boundDn, dn, type, value) {
      return Promise.resolve(ldap.performOperation('modify', {
        dn: dn, boundDn: boundDn, channel: 'ldaps',
        changes: [{ operation: 'replace',
                    modification: { type: type, values: [value] } }] }));
    };

    // --- A. development --------------------------------------------------
    const DEV = 'atp-dev-' + stamp;
    person(DEV);
    const devSet = actions.usersAction({ action: 'set-password', user: DEV,
                                         password: PW }, context);
    note(devSet.ok === true && !credentials.passwordResetRequired(DEV) &&
         !/temporary/.test(String(devSet.message)),
         'A. development: a typed set-password is not temporary',
         JSON.stringify(devSet));

    // An administrator, for the LDAP half.
    const ADMIN = 'atp-admin-' + stamp;
    const adminDn = person(ADMIN);
    rbac.grant(ADMIN, 'write', { via: 'test' });

    // --- F. development, LDAP -------------------------------------------
    const DEVLDAP = 'atp-devldap-' + stamp;
    const devLdapDn = person(DEVLDAP);
    const devModify = await modify(adminDn, devLdapDn, 'userPassword', PW);
    note(devModify.ok === true && flagOf(DEVLDAP) === '',
         'F. development: an administrator\'s LDAP modify of a password ' +
         'sets no pwdReset', JSON.stringify(devModify) + ' ' +
         flagOf(DEVLDAP));

    config.setOverride('global.mode', 'product');
    try {
      // --- B. set-password ---------------------------------------------
      const TYPED = 'atp-typed-' + stamp;
      person(TYPED);
      const set = actions.usersAction({ action: 'set-password', user: TYPED,
                                        password: PW, passwordConfirm: PW },
                                      context);
      const row = audit.list().filter(function (one) {
        return one.action === 'password.set' && one.target === TYPED;
      })[0];
      note(set.ok === true && set.generated === false &&
           set.password === undefined &&
           credentials.passwordResetRequired(TYPED) === true &&
           /temporary password: they must choose their own/
             .test(String(set.message)) &&
           !!row && row.detail && row.detail.mustChange === true,
           'B. product: a typed set-password is accepted, must be changed ' +
           'at the next sign-in, is said to be temporary, is not echoed, ' +
           'and the audit row says mustChange',
           JSON.stringify({ set: set, detail: row && row.detail }));
      const signIn = credentials.verify(TYPED, PW, { via: 'the test',
                                                     door: 'ldap' });
      note(!!signIn && signIn.ok === false &&
           signIn.reason === 'password-reset-required',
           'B2. and a door that cannot ask for a new one refuses it ' +
           '(STS-AUTHN-0142)', JSON.stringify(signIn));

      // --- C. create -----------------------------------------------------
      const MADE = 'atp-made-' + stamp;
      const made = actions.usersAction({ action: 'create', username: MADE,
        invent: false, credential: 'password', password: PW,
        attributes: { cn: 'atp', givenName: 'atp', sn: 'made',
                      mail: MADE + '@example.test' } }, context);
      note(made.ok === true && made.passwordSet === true &&
           made.password === undefined &&
           credentials.passwordResetRequired(MADE) === true,
           'C. product: a person created with a typed password must change ' +
           'it at the next sign-in', JSON.stringify(made).slice(0, 400));

      // --- D. a service account ---------------------------------------
      const SVC = 'atp-svc-' + stamp;
      person(SVC);
      const flagged = serviceAccounts.set(SVC, { serviceAccount: true,
                                                 owners: [adminDn] });
      const svcSet = actions.usersAction({ action: 'set-password', user: SVC,
                                           password: PW }, context);
      note(flagged && flagged.ok !== false && svcSet.ok === true &&
           credentials.passwordResetRequired(SVC) === false,
           'D. product: a service account\'s typed password is not ' +
           'temporary (its password is a program\'s)',
           JSON.stringify({ flagged: flagged && flagged.ok, set: svcSet }));

      // --- G. a person who BECOMES a service account (#2236) -----------
      const LATER = 'atp-later-' + stamp;
      person(LATER);
      const laterSet = actions.usersAction({ action: 'set-password',
        user: LATER, password: PW, passwordConfirm: PW }, context);
      const owedBefore = credentials.passwordResetRequired(LATER);
      const became = actions.usersAction({ action: 'set-service-account',
        user: LATER, owners: [adminDn] }, context);
      const becameRow = audit.list().filter(function (one) {
        return one.action === 'admin.service-account.set' &&
               one.target === LATER;
      })[0];
      note(laterSet.ok === true && owedBefore === true &&
           became.ok === true && became.serviceAccount === true &&
           credentials.passwordResetRequired(LATER) === false &&
           !!becameRow && becameRow.detail &&
           becameRow.detail.passwordResetCleared === true,
           'G. product: set-service-account clears the pwdReset a typed ' +
           'password left, and its audit row says passwordResetCleared',
           JSON.stringify({ set: laterSet.ok, owedBefore: owedBefore,
                            became: became, detail: becameRow &&
                              becameRow.detail }).slice(0, 600));
      const laterVerify = credentials.verify(LATER, PW, { via: 'the test',
                                                          door: 'ldap' });
      note(!!laterVerify && laterVerify.ok === true,
           'G2. and a door that cannot ask for a new password takes it',
           JSON.stringify(laterVerify));
      const OWES = 'atp-owes-' + stamp;
      person(OWES);
      const plain = actions.usersAction({ action: 'set-service-account',
        user: OWES, owners: [adminDn] }, context);
      const plainRow = audit.list().filter(function (one) {
        return one.action === 'admin.service-account.set' &&
               one.target === OWES;
      })[0];
      note(plain.ok === true && !!plainRow && plainRow.detail &&
           plainRow.detail.passwordResetCleared === undefined,
           'G3. an account that owed no change: its audit row says nothing ' +
           'was cleared', JSON.stringify(plainRow && plainRow.detail));

      // --- E. LDAP ---------------------------------------------------------
      const OTHER = 'atp-other-' + stamp;
      const otherDn = person(OTHER);
      const byAdmin = await modify(adminDn, otherDn, 'userPassword', PW);
      note(byAdmin.ok === true && flagOf(OTHER) === 'TRUE',
           'E1. product: an administrator\'s LDAP modify of somebody else\'s ' +
           'password sets pwdReset in the same write',
           JSON.stringify(byAdmin) + ' ' + flagOf(OTHER));
      const NEW = 'atp-new-' + stamp;
      const newDn = 'uid=' + NEW + ',' + ldap.usersDn();
      const added = await Promise.resolve(ldap.performOperation('add', {
        dn: newDn, boundDn: adminDn, channel: 'ldaps',
        attributes: [
          { type: 'objectClass', values: ['top', 'person',
                                          'inetOrgPerson'] },
          { type: 'uid', values: [NEW] }, { type: 'cn', values: [NEW] },
          { type: 'sn', values: [NEW] }, { type: 'givenName', values: ['x'] },
          { type: 'mail', values: [NEW + '@example.test'] },
          { type: 'userPassword', values: [PW] }] }));
      note(added.ok === true && flagOf(NEW) === 'TRUE',
           'E2. product: a person an administrator adds over LDAP with a ' +
           'password must change it', JSON.stringify(added) + ' ' +
           flagOf(NEW));
      const SELF = 'atp-self-' + stamp;
      const selfDn = person(SELF);
      config.setOverride('ldap.selfWritableAttributes', 'userPassword');
      const bySelf = await modify(selfDn, selfDn, 'userPassword', PW);
      config.clearOverride('ldap.selfWritableAttributes');
      note(bySelf.ok === true && flagOf(SELF) === '',
           'E3. product: a person\'s own LDAP password change is not ' +
           'temporary', JSON.stringify(bySelf) + ' ' + flagOf(SELF));
    } finally {
      config.clearOverride('global.mode');
    }

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
  const out = path.join(os.tmpdir(), 'atp-' + process.pid + '-' +
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
                                  ATP_ROOT: ROOT, ATP_OUT: out }),
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
  name: 'admin_typed_password_temporary',
  describe: 'a password an administrator typed (set-password, create, an ' +
            'LDAP write of somebody else\'s userPassword) must be changed ' +
            'at the next sign-in in product mode, except a service ' +
            'account\'s (#2160, ASVS 5.0.0 6.4.6)',
  run: run
};
