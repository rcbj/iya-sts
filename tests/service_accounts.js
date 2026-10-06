// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: service_accounts.js
//
// ===========================================================================
// SERVICE ACCOUNTS (#221), in process: a person entry with a flag, and the
// third policy kind that governs it.
//
// `common/service_accounts.ts` and `common/service_account_policy.ts` argue
// the design. What is held here, each in a throwaway realm:
//
//   A. THE FLAG: `isServiceAccount()` on every shape an entry is handed
//      around in; `set()` refuses nobody, an application-shaped name, a
//      missing owner (requireOwner), an owner who is nobody, the account as
//      its own owner and half a destination; a person or a GROUP owns one;
//      the auxiliary class follows the flag; clearing takes every attribute
//      away.
//   B. THE POLICY: every default the more secure one; a save carries every
//      field; a rotated password shorter than the password policy is
//      refused; a realm inherits the default realm's profile; requireOwner
//      off lets an account have none.
//   C. THE DOORS, in both modes: each password door refuses the account's
//      RIGHT password where the policy closes it (STS-SVCACCT-0011) and
//      accepts it where open; a browser is refused by default
//      (STS-SVCACCT-0010); a door that declares nothing is refused; the KDC's
//      question says the same.
//   D. THE SECOND FACTOR: an account a second factor is required of is
//      needed one at the password-only doors until the realm exempts service
//      accounts, and then it is not.
//   E. THE SESSION FUNNEL: `authn.startSession()` refuses a service account a
//      browser session, and starts a KEYED one.
//   F. THE CONSOLE AND THE API: `set-service-account`, a create that refuses
//      a bad owner BEFORE anybody exists, and `/admin/users?kind=`.
//   G. AN LDAP MODIFY meets the same rules: no owner while one is required,
//      and the auxiliary class kept beside the flag.
//   H. ROTATION (P4), against a fake destination: refused for a person and
//      for an account with no destination; a failed push changes NOTHING
//      and is counted, an alarm at the threshold; a push that succeeded is
//      committed with the previous password accepted for the overlap, and
//      not after it; the clean-up clears it; and while rotation is on a
//      password cannot be set by hand.
// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
const realms = require('../common/realms');
const errorCodes = require('../common/error_codes');
const credentials = require('../common/credentials');
const serviceAccounts = require('../common/service_accounts');
const policy = require('../common/service_account_policy');
const passwordPolicy = require('../common/password_policy');
const ldap = require('../ldap/ldap_server');
const authn = require('../authn/authn');
const adminActions = require('../admin-core/admin_actions');
const adminViews = require('../admin-core/admin_views');
const policyKinds = require('../admin-core/policy_kinds');
const rotationModule = require('../common/service_account_rotation');

const log = require('bunyan').createLogger({ name: 'service_accounts',
  level: process.env.LOG_LEVEL || 'info' });

const PASSWORD = 'Sv1c-Acc0unt-Pa55word!x';

function realmId(stem) {
  log.debug('Entering realmId().');
  log.debug('Leaving realmId().');
  return stem + '-' + require('crypto').randomBytes(3).toString('hex');
}

async function withRealm(t, stem, fn) {
  log.debug('Entering withRealm(). ' + stem);
  const id = realmId(stem);
  const made = realms.create({ id: id, name: id,
                               description: 'Created by ' + __filename,
                               overrides: {} });
  if (!made.ok) {
    t.bad('could not create the realm "' + id + '"',
          (made.errors || []).join(' '));
    log.debug('Leaving withRealm(). Not created.');
    return undefined;
  }
  try {
    log.debug('Leaving withRealm().');
    return await realms.run(made.realm, function () {
      return fn(made.realm);
    });
  } finally {
    // Every other file in the run asserts only the default realm is left.
    realms.remove(id);
  }
}

async function withSettings(pairs, fn) {
  log.debug('Entering withSettings().');
  const keys = Object.keys(pairs);
  try {
    keys.forEach(function (key) {
      config.setOverride(key, String(pairs[key]));
    });
    log.debug('Leaving withSettings().');
    return await fn();
  } finally {
    keys.forEach(function (key) {
      config.clearOverride(key);
    });
  }
}

function person(name) {
  log.debug('Entering person().');
  ldap.createUser(name, { invent: false });
  const set = credentials.setPassword(name, PASSWORD);
  log.debug('Leaving person().');
  return set;
}

function savePolicy(fields) {
  log.debug('Entering savePolicy().');
  const saved = policy.save('default', Object.assign({}, policy.DEFAULTS,
                                                     fields || {}));
  if (!saved.ok) {
    throw new Error('the service-account policy was not saved: ' +
                    JSON.stringify(saved.errors));
  }
  log.debug('Leaving savePolicy().');
  return saved;
}

function stored(name) {
  log.debug('Entering stored().');
  const entry = ldap.existingUserEntry(name);
  log.debug('Leaving stored().');
  return entry ? { dn: entry.dn, attributes: entry.attributes } : null;
}

async function flag(t) {
  log.debug('Entering flag().');
  t.check(serviceAccounts.isServiceAccount({
            attributes: { stsserviceaccount: ['TRUE'] } }) &&
          serviceAccounts.isServiceAccount({
            attributes: { stsServiceAccount: ['true'] } }) &&
          serviceAccounts.isServiceAccount({ stsServiceAccount: 'TRUE' }) &&
          !serviceAccounts.isServiceAccount({ attributes: {} }) &&
          !serviceAccounts.isServiceAccount(null),
          'A1. isServiceAccount() reads a stored entry, an entryObject and ' +
          'a flat map, and nothing else is one');
  await withRealm(t, 'svc-flag', function () {
    person('svc-a');
    person('svc-owner');
    const nobody = serviceAccounts.set('svc-nobody', { serviceAccount: true,
                                                       owner: 'svc-owner' });
    t.equal(errorCodes.codeOf(nobody), 'STS-SVCACCT-0021',
            'A2. nobody by that name is refused');
    const noOwner = serviceAccounts.set('svc-a', { serviceAccount: true });
    t.equal(errorCodes.codeOf(noOwner), 'STS-SVCACCT-0023',
            'A3. requireOwner is ON by default, so no owner is refused');
    const badOwner = serviceAccounts.set('svc-a', { serviceAccount: true,
                                                    owner: 'nobody-here' });
    t.equal(errorCodes.codeOf(badOwner), 'STS-SVCACCT-0024',
            'A4. an owner who is neither a person nor a group is refused');
    const self = serviceAccounts.set('svc-a', { serviceAccount: true,
                                                owner: 'svc-a' });
    t.equal(errorCodes.codeOf(self), 'STS-SVCACCT-0025',
            'A5. an account cannot own itself');
    const half = serviceAccounts.set('svc-a', { serviceAccount: true,
                                                owner: 'svc-owner',
                                                secretName: 'x' });
    t.equal(errorCodes.codeOf(half), 'STS-SVCACCT-0026',
            'A6. a secret name without a destination is refused');
    const made = serviceAccounts.set('svc-a', { serviceAccount: true,
                                                owner: 'svc-owner' });
    t.check(made.ok && made.changed && made.account &&
            made.account.ownerKind === 'person',
            'A7. a person owns a service account', JSON.stringify(made));
    t.check(serviceAccounts.isServiceAccountName('svc-a') &&
            !serviceAccounts.isServiceAccountName('svc-owner') &&
            serviceAccounts.names().indexOf('svc-a') >= 0,
            'A8. the predicate and the listing find it, and only it');
    const object = stored('svc-a');
    if (object) {
      const classes = (object.attributes.objectClass ||
                       object.attributes.objectclass || []).map(String);
      t.check(classes.indexOf('stsServiceAccount') >= 0,
              'A9. the auxiliary class stsServiceAccount is on the entry',
              JSON.stringify(classes));
    }
    const groupOwned = serviceAccounts.set('svc-a', {
      serviceAccount: true, owner: 'cn=admin-read,' +
        'ou=groups,' + ldap.baseDn() });
    t.check(groupOwned.ok || errorCodes.codeOf(groupOwned) ===
            'STS-SVCACCT-0024',
            'A10. a group DN is resolved as a group (or refused where this ' +
            'realm has no such group)', JSON.stringify(groupOwned));
    const cleared = serviceAccounts.set('svc-a', { serviceAccount: false });
    t.check(cleared.ok && !serviceAccounts.isServiceAccountName('svc-a') &&
            serviceAccounts.of('svc-a') === null,
            'A11. clearing makes them an ordinary person again');
    const after = stored('svc-a');
    if (after) {
      const keys = Object.keys(after.attributes).map(function (k) {
        return k.toLowerCase();
      });
      t.check(keys.indexOf('stsserviceaccountowner') < 0 &&
              (after.attributes.objectClass || after.attributes.objectclass ||
               []).map(String).indexOf('stsServiceAccount') < 0,
              'A12. and the owner and the class went with the flag');
    }
  });
  log.debug('Leaving flag().');
}

async function policies(t) {
  log.debug('Entering policies().');
  const p = policy.read('default');
  t.check(p.exemptFromSecondFactor === false &&
          p.allowBrowserSignIn === false && p.rotationEnabled === false &&
          p.requireOwner === true && p.generatedLength === 32 &&
          policy.allowedDoors(p).length === policy.DOORS.length,
          'B1. every default is the more secure one, and every password ' +
          'door is open', JSON.stringify(p));
  t.check(policyKinds.byId('serviceAccount') !== null &&
          policyKinds.actions().indexOf('save-serviceAccount-policy') >= 0,
          'B2. it is the third kind on Directory → Policies');
  await withRealm(t, 'svc-policy', function () {
    const partial = policy.validate({ allowBrowserSignIn: true });
    t.check(partial.problems.some(function (one) {
      return /`requireOwner`.*required/.test(one);
    }), 'B3. a save that leaves a field out is refused by name');
    const minimum = Number(passwordPolicy.read().minLength) || 0;
    if (minimum > 16) {
      const short = policy.save('default', Object.assign({}, policy.DEFAULTS,
        { generatedLength: 16 }));
      t.equal(errorCodes.codeOf(short), 'STS-SVCACCT-0002',
              'B4. a rotated password shorter than the password policy ' +
              'allows is refused');
    }
    let destinationsLoaded = false;
    try {
      destinationsLoaded = typeof require('../common/secret_destinations')
        .list === 'function';
    } catch (e) {
      log.debug('Caught in policies(): ' + e.message);
      destinationsLoaded = false;
    }
    if (destinationsLoaded) {
      const rotating = policy.save('default', Object.assign({},
        policy.DEFAULTS, { rotationEnabled: true }));
      t.equal(errorCodes.codeOf(rotating), 'STS-SVCACCT-0002',
              'B5. rotation is refused in a realm with no push destination');
    }
    realms.run(realms.DEFAULT_REALM, function () {
      savePolicy({ allowBrowserSignIn: true });
    });
    try {
      const inherited = policy.read('default');
      t.check(inherited.inherited && inherited.allowBrowserSignIn === true,
              'B6. a realm with no profile of its own inherits the default ' +
              'realm\'s');
      savePolicy({ requireOwner: false });
      const own = policy.read('default');
      t.check(own.stored && own.allowBrowserSignIn === false,
              'B7. its own profile wins');
      person('svc-unowned');
      t.check(serviceAccounts.set('svc-unowned',
                                  { serviceAccount: true }).ok,
              'B8. with requireOwner off a service account may have none');
      policy.reset('default');
    } finally {
      realms.run(realms.DEFAULT_REALM, function () {
        policy.reset('default');
      });
    }
  });
  log.debug('Leaving policies().');
}

async function doors(t) {
  log.debug('Entering doors().');
  await withRealm(t, 'svc-doors', async function () {
    person('svc-d');
    person('svc-d-owner');
    serviceAccounts.set('svc-d', { serviceAccount: true,
                                   owner: 'svc-d-owner' });
    for (const mode of ['development', 'product']) {
      await withSettings({ 'global.mode': mode }, async function () {
        const open = credentials.verify('svc-d', PASSWORD,
                                        { via: 'test', door: 'ldap' });
        t.check(open.ok, 'C1 (' + mode + '). an open door accepts the ' +
                'service account', JSON.stringify(open));
        const browser = credentials.verify('svc-d', PASSWORD,
          { via: 'test', secondFactor: 'asked-next' });
        t.check(!browser.ok && errorCodes.codeOf(browser) ===
                'STS-SVCACCT-0010',
                'C2 (' + mode + '). the sign-in screen refuses it by default',
                JSON.stringify(browser));
        const unstated = credentials.verify('svc-d', PASSWORD,
                                            { via: 'test' });
        t.equal(errorCodes.codeOf(unstated), 'STS-SVCACCT-0011',
                'C3 (' + mode + '). a door that declares nothing is refused');
        savePolicy({ allowLdapBind: false, allowBrowserSignIn: true });
        try {
          const closed = credentials.verify('svc-d', PASSWORD,
                                            { via: 'test', door: 'ldap' });
          t.check(!closed.ok && closed.reason === 'service-account-door' &&
                  errorCodes.codeOf(closed) === 'STS-SVCACCT-0011',
                  'C4 (' + mode + '). a closed door refuses its right ' +
                  'password, as a wrong one is');
          const asyncClosed = await credentials.verifyAsync('svc-d',
            PASSWORD, { via: 'test', door: 'ldap' });
          t.check(!asyncClosed.ok,
                  'C5 (' + mode + '). and so does the asynchronous path');
          t.check(credentials.verify('svc-d', PASSWORD,
                    { via: 'test', secondFactor: 'asked-next' }).ok,
                  'C6 (' + mode + '). allowBrowserSignIn lets it sign in');
        } finally {
          policy.reset('default');
        }
        t.check(credentials.verify('svc-d-owner', PASSWORD,
                  { via: 'test', secondFactor: 'asked-next' }).ok,
                'C7 (' + mode + '). an ordinary person is asked nothing new');
      });
    }
    t.check(!credentials.serviceAccountRefusesDoor('svc-d', 'kerberos'),
            'C8. the Kerberos door is open by default');
    savePolicy({ allowKerberos: false });
    try {
      t.check(credentials.serviceAccountRefusesDoor('svc-d', 'kerberos') &&
              !credentials.serviceAccountRefusesDoor('svc-d-owner',
                                                     'kerberos'),
              'C9. closed, the KDC\'s question refuses the account and only ' +
              'the account');
    } finally {
      policy.reset('default');
    }
  });
  log.debug('Leaving doors().');
}

async function secondFactor(t) {
  log.debug('Entering secondFactor().');
  await withRealm(t, 'svc-mfa', async function () {
    person('svc-m');
    person('svc-m-owner');
    serviceAccounts.set('svc-m', { serviceAccount: true,
                                   owner: 'svc-m-owner' });
    credentials.setMfaRequired('svc-m', true);
    t.check(credentials.secondFactorDemand('svc-m').needed === true,
            'D1. a service account a second factor is required of needs one');
    await withSettings({ 'global.mode': 'product' }, function () {
      const refused = credentials.verify('svc-m', PASSWORD,
                                         { via: 'test', door: 'ldap' });
      t.equal(errorCodes.codeOf(refused), 'STS-AUTHN-0213',
              'D2. so its password alone is refused at a password-only door');
      savePolicy({ exemptFromSecondFactor: true });
      try {
        t.check(credentials.secondFactorDemand('svc-m').needed === false &&
                credentials.mfaRequirementFor('svc-m').required === false &&
                credentials.mfaRequirementFor('svc-m').exemptServiceAccount,
                'D3. an exempting realm asks it for none');
        t.check(credentials.verify('svc-m', PASSWORD,
                                   { via: 'test', door: 'ldap' }).ok,
                'D4. and the password-only door accepts its password');
        t.check(credentials.mfaRequirementFor('svc-m-owner')
                  .exemptServiceAccount === false,
                'D5. an ordinary person is not exempted with it');
      } finally {
        policy.reset('default');
      }
    });
  });
  log.debug('Leaving secondFactor().');
}

function noBrowser() {
  log.debug('Entering noBrowser().');
  log.debug('Leaving noBrowser().');
  return { set: function () {}, req: null };
}

async function sessions(t) {
  log.debug('Entering sessions().');
  await withRealm(t, 'svc-session', function () {
    person('svc-s');
    person('svc-s-owner');
    serviceAccounts.set('svc-s', { serviceAccount: true,
                                   owner: 'svc-s-owner' });
    const detail = {};
    const browser = authn.startSession(noBrowser(), 'svc-s', ['pwd'], '1',
                                       'a test', detail);
    t.check(browser === null && detail.refusedWith === 'STS-SVCACCT-0010',
            'E1. startSession() refuses a service account a browser session',
            JSON.stringify(detail));
    const keyed = authn.startSession(noBrowser(), 'svc-s', ['pwd'], '1',
                                     'SCIM', { key: 'svc-s-key',
                                               cookie: false });
    t.check(!!keyed, 'E2. and starts a KEYED session, a program\'s record');
    const plain = authn.startSession(noBrowser(), 'svc-s-owner', ['pwd'],
                                     '1', 'a test', {});
    t.check(!!plain, 'E3. an ordinary person is unaffected');
  });
  log.debug('Leaving sessions().');
}

async function consoleAndApi(t) {
  log.debug('Entering consoleAndApi().');
  await withRealm(t, 'svc-console', function () {
    person('svc-c-owner');
    const refused = adminActions.usersAction({
      action: 'create', username: 'svc-c-refused', credential: 'none',
      invent: 'no', serviceAccount: 'true', owner: 'nobody-at-all' },
      { via: 'test', actor: 'tester' });
    t.check(refused.ok === false &&
            errorCodes.codeOf(refused) === 'STS-SVCACCT-0024' &&
            !stored('svc-c-refused'),
            'F1. a create with a bad owner is refused BEFORE anybody exists',
            JSON.stringify(refused));
    const created = adminActions.usersAction({
      action: 'create', username: 'svc-c', credential: 'none', invent: 'no',
      serviceAccount: 'true', owner: 'svc-c-owner' },
      { via: 'test', actor: 'tester' });
    t.check(created.ok && created.serviceAccount === true &&
            serviceAccounts.isServiceAccountName('svc-c'),
            'F2. a create with a good owner makes a service account',
            JSON.stringify(created));
    const listed = adminViews.usersListJson({ query: { kind: 'service' } })
      .json;
    t.check(listed.users.every(function (row) {
      return row.serviceAccount;
    }) && listed.users.some(function (row) {
      return row.key === 'svc-c';
    }) && listed.serviceAccounts >= 1,
            'F3. /admin/users?kind=service lists service accounts, tagged',
            JSON.stringify(listed.users.map(function (r) {
              return r.key;
            })));
    const people = adminViews.usersListJson({ query: { kind: 'person' } })
      .json;
    t.check(!people.users.some(function (row) {
      return row.key === 'svc-c';
    }), 'F4. and ?kind=person leaves them out');
    const detail = adminViews.serviceAccountJson('svc-c');
    t.check(detail && detail.owner && detail.policy &&
            detail.policy.allowBrowserSignIn === false,
            'F5. the person page describes the account and its policy');
    const cleared = adminActions.usersAction({
      action: 'set-service-account', user: 'svc-c', serviceAccount: 'false' },
      { via: 'test', actor: 'tester' });
    t.check(cleared.ok && !serviceAccounts.isServiceAccountName('svc-c'),
            'F6. set-service-account false makes them a person again');
    const again = adminActions.usersAction({
      action: 'set-service-account', user: 'svc-c', owner: 'svc-c-owner' },
      { via: 'test', actor: 'tester' });
    t.check(again.ok && again.serviceAccount === true,
            'F7. set-service-account (true by default) makes one again',
            JSON.stringify(again));
  });
  log.debug('Leaving consoleAndApi().');
}

async function ldapModify(t) {
  log.debug('Entering ldapModify().');
  await withRealm(t, 'svc-ldap', async function () {
    person('svc-l');
    const dn = stored('svc-l').dn;
    const modify = function (changes) {
      log.debug('Entering modify().');
      log.debug('Leaving modify().');
      return Promise.resolve(ldap.performOperation('modify', {
        dn: dn, boundDn: '', channel: 'ldaps', changes: changes }));
    };
    const noOwner = await modify([{ operation: 'replace',
      modification: { type: 'stsServiceAccount', values: ['TRUE'] } }]);
    t.check(noOwner.ok === false &&
            !serviceAccounts.isServiceAccountName('svc-l'),
            'G1. an LDAP modify making a service account with no owner is ' +
            'refused while one is required', JSON.stringify(noOwner));
    person('svc-l-owner');
    const ownerDn = stored('svc-l-owner').dn;
    const owned = await modify([
      { operation: 'replace',
        modification: { type: 'stsServiceAccount', values: ['TRUE'] } },
      { operation: 'replace',
        modification: { type: 'stsServiceAccountOwner',
                        values: [ownerDn] } }]);
    t.check(owned.ok !== false &&
            serviceAccounts.isServiceAccountName('svc-l'),
            'G2. with an owner it is accepted', JSON.stringify(owned));
    const object = stored('svc-l');
    t.check((object.attributes.objectClass || object.attributes.objectclass ||
             []).map(String).indexOf('stsServiceAccount') >= 0,
            'G3. and the auxiliary class is kept beside the flag');
  });
  log.debug('Leaving ldapModify().');
}

// A destination that records what was pushed, or refuses.
function fakeDestinations(answer) {
  log.debug('Entering fakeDestinations().');
  const pushed = [];
  log.debug('Leaving fakeDestinations().');
  return {
    pushed: pushed,
    push: function (id, name, value) {
      pushed.push({ id: id, name: name, value: value });
      return Promise.resolve(answer.ok
        ? { ok: true, version: 'v' + pushed.length }
        : { ok: false, code: 'STS-SVCACCT-0044', error: 'refused' });
    }
  };
}

function rotationWith(destinations) {
  log.debug('Entering rotationWith().');
  const deps = rotationModule.ServiceAccountRotation.defaultDeps();
  deps.destinations = function () {
    return destinations;
  };
  log.debug('Leaving rotationWith().');
  return new rotationModule.ServiceAccountRotation(deps);
}

async function rotation(t) {
  log.debug('Entering rotation().');
  await withRealm(t, 'svc-rotate', async function () {
    await withSettings({ 'global.mode': 'product' }, async function () {
      person('svc-r');
      person('svc-r-owner');
      serviceAccounts.set('svc-r', { serviceAccount: true,
                                     owner: 'svc-r-owner' });
      const failing = fakeDestinations({ ok: false });
      const rotator = rotationWith(failing);
      const notOne = await rotator.rotateOne('svc-r-owner');
      t.equal(errorCodes.codeOf(notOne), 'STS-SVCACCT-0040',
              'H1. a person who is not a service account is not rotated');
      const noDest = await rotator.rotateOne('svc-r');
      t.equal(errorCodes.codeOf(noDest), 'STS-SVCACCT-0041',
              'H2. nor is an account that names no destination');
      // The destination register is P3's; the hook writes it directly.
      const dn = stored('svc-r').dn;
      serviceAccounts.directoryInstalled().writeServiceAccount(dn,
        { stsSecretDestination: 'cn=fake,ou=applications,' + ldap.baseDn(),
          stsSecretName: 'iya/svc-r' });
      savePolicy({ rotationEnabled: true, rotationAlarmFailures: 2,
                   rotationOverlapMinutes: 60 });
      try {
        const refusedPush = await rotator.rotateOne('svc-r');
        t.check(!refusedPush.ok && refusedPush.failures === 1 &&
                !refusedPush.alarm && failing.pushed.length === 1 &&
                credentials.verify('svc-r', PASSWORD,
                                   { via: 'test', door: 'ldap' }).ok,
                'H3. a failed push changes NOTHING — the old password ' +
                'still works — and is counted', JSON.stringify(refusedPush));
        const again = await rotator.rotateOne('svc-r');
        t.check(again.alarm === true && again.failures === 2,
                'H4. at the policy\'s threshold it is an alarm');
        const set = credentials.setPassword('svc-r', 'Hand-Set-Pa55word!x');
        t.equal(errorCodes.codeOf(set), 'STS-SVCACCT-0013',
                'H5. while rotation is on, a password cannot be set by hand');
        const good = fakeDestinations({ ok: true });
        const done = await rotationWith(good).rotateOne('svc-r');
        const fresh = good.pushed.length === 1
          ? good.pushed[0].value.password : '';
        t.check(done.ok && fresh.length >= 32 &&
                good.pushed[0].name === 'iya/svc-r' &&
                good.pushed[0].value.username === 'svc-r',
                'H6. a successful push carries the account, a generated ' +
                'password of the policy\'s length, to the named secret',
                JSON.stringify(done));
        t.check(credentials.verify('svc-r', fresh,
                                   { via: 'test', door: 'ldap' }).ok,
                'H7. and is committed: the new password is accepted');
        t.check(credentials.verify('svc-r', PASSWORD,
                                   { via: 'test', door: 'ldap' }).ok &&
                (await credentials.verifyAsync('svc-r', PASSWORD,
                  { via: 'test', door: 'ldap' })).ok,
                'H8. the previous password is accepted during the overlap');
        const facts = serviceAccounts.of('svc-r');
        t.check(facts.rotatedAt && facts.rotation.failures === 0 &&
                facts.previousPasswordExpires > Date.now(),
                'H9. the rotation is recorded and the failures reset');
        t.check(!credentials.verify('svc-r', 'not-it-at-all-x1!',
                                    { via: 'test', door: 'ldap' }).ok,
                'H10. a wrong password is still wrong');
        const later = Date.now() + 2 * 60 * 60 * 1000;
        t.check(serviceAccounts.previousPassword('svc-r', later) === null,
                'H11. after the overlap the previous password is not ' +
                'accepted — checked where it is read');
        t.check(rotator.cleanup(realms.currentId(),
                                { nowMs: function () {
                                  return later;
                                } }).cleared === 1 &&
                !credentials.verify('svc-r', PASSWORD,
                                    { via: 'test', door: 'ldap' }).ok,
                'H12. the clean-up job clears it, and then it is refused');
        t.check(rotator.offReason(realms.currentId()) === '',
                'H13. the hourly job is on where the policy rotates');
      } finally {
        policy.reset('default');
      }
      t.check(rotationWith(null).offReason(realms.currentId()) !== '',
              'H14. and off where it does not (the default)');
    });
  });
  log.debug('Leaving rotation().');
}

module.exports = {
  name: 'service accounts',
  describe: 'Service accounts (#221): the flag on a person entry and its ' +
            'one predicate, the service-account policy (the third kind), ' +
            'the doors it closes in both modes, the second-factor ' +
            'exemption, the session funnel, the console and API, and an ' +
            'LDAP modify',
  run: async function (t) {
    log.debug('Entering run().');
    await flag(t);
    await policies(t);
    await doors(t);
    await secondFactor(t);
    await sessions(t);
    await consoleAndApi(t);
    await ldapModify(t);
    await rotation(t);
    log.debug('Leaving run().');
  }
};
