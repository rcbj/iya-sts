// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/service_account_policy_selection.js
//
// ===========================================================================
// NAMED SERVICE-ACCOUNT POLICIES, NAMED BY THE ACCOUNT (#1240, rule 3cx).
//
// rcbj's decisions on #1234: the service-account policy holds named
// profiles beside `default`, each the realm's own, and a service account
// names its profile in `stsServiceAccountPolicy` on its own entry.
// `common/service_account_policy.ts`'s header argues the design. What is
// held here, each in a throwaway realm:
//
//   A. THE PROFILES: a named profile is saved with every field and a
//      precedence, listed after `default`, refused a malformed name
//      (STS-SVCACCT-0001) or precedence, and never inherited by another
//      realm; the kind is drawn tabbed and its named rows say who names
//      each one.
//   B. THE REFERENCE AT EVERY DOOR: the person editor draws it on the
//      Policies tab, writes a held profile for a service account, refuses
//      one for a person who is not a service account (STS-SVCACCT-0048)
//      and a name the realm does not hold (STS-LDAP-0106); an LDAP modify
//      refuses both (STS-SVCACCT-0048, STS-SVCACCT-0050); a create refuses
//      it without the flag; clearing the flag clears it.
//   C. THE READERS, each through the account's own profile: a door, the
//      browser and the second-factor exemption
//      (`credentials.serviceAccountRefusesDoor()`, `mfaRequirementFor()`),
//      and `requireOwner` at edit and at create.
//   D. A REFERENCE THE REALM DOES NOT HOLD gets `default` and is logged
//      (STS-SVCACCT-0047).
//   E. A NAMED PROFILE AN ACCOUNT NAMES IS NOT DELETED (STS-SVCACCT-0049),
//      and is once nothing names it.
//   F. THE ROTATION JOB ON A SELECTED PROFILE: with `default` not rotating,
//      the hourly run is on because a named profile rotates; it rotates the
//      account naming that profile and skips the one naming none; the
//      pushed password has the named profile's length, the previous one
//      the named profile's overlap; the named profile's interval decides
//      when it is due again; and a failure alarms at the named profile's
//      threshold.
// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
const realms = require('../common/realms');
const errorCodes = require('../common/error_codes');
const credentials = require('../common/credentials');
const serviceAccounts = require('../common/service_accounts');
const policy = require('../common/service_account_policy');
const ldap = require('../ldap/ldap_server');
const personEditor = require('../ldap/person_editor');
const adminActions = require('../admin-core/admin_actions');
const adminViews = require('../admin-core/admin_views');
const policyKinds = require('../admin-core/policy_kinds');
const rotationModule = require('../common/service_account_rotation');

const log = require('bunyan').createLogger({
  name: 'service_account_policy_selection',
  level: process.env.LOG_LEVEL || 'info' });

const PASSWORD = 'Sv1c-Acc0unt-Pa55word!x';
const DAY_MS = 24 * 60 * 60 * 1000;

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
  // The attribute policy (#396) requires these of every person in product
  // mode, and F makes its people in product.
  ldap.createUser(name, { invent: false,
                          attributes: { givenName: 'Service', sn: name,
                                        mail: name + '@example.test' } });
  const set = credentials.setPassword(name, PASSWORD);
  log.debug('Leaving person().');
  return set;
}

function account(name, owner) {
  log.debug('Entering account().');
  person(name);
  const made = serviceAccounts.set(name, { serviceAccount: true,
                                           owners: [owner] });
  if (!made.ok) {
    throw new Error('could not make ' + name + ' a service account: ' +
                    JSON.stringify(made.errors));
  }
  log.debug('Leaving account().');
  return made;
}

function saveNamed(name, fields, precedence) {
  log.debug('Entering saveNamed().');
  const saved = policy.save(name, Object.assign({}, policy.DEFAULTS,
    fields || {}, { precedence: precedence === undefined ? 50
                                                         : precedence }));
  if (!saved.ok) {
    throw new Error('the named profile ' + name + ' was not saved: ' +
                    JSON.stringify(saved.errors));
  }
  log.debug('Leaving saveNamed().');
  return saved;
}

function name(who, value) {
  log.debug('Entering name().');
  log.debug('Leaving name().');
  return personEditor.update(who, { attribute: 'stsServiceAccountPolicy',
                                    mode: 'set', value: value },
                             { actor: 'tester', via: 'test' });
}

function stored(who) {
  log.debug('Entering stored().');
  const entry = ldap.existingUserEntry(who);
  log.debug('Leaving stored().');
  return entry ? { dn: entry.dn, attributes: entry.attributes } : null;
}

function modify(who, changes) {
  log.debug('Entering modify().');
  log.debug('Leaving modify().');
  return Promise.resolve(ldap.performOperation('modify', {
    dn: stored(who).dn, boundDn: '', channel: 'ldaps', changes: changes }));
}

async function profiles(t) {
  log.debug('Entering profiles().');
  t.check(policyKinds.byId('serviceAccount').tabbed === true &&
          JSON.stringify(policy.REFERENCES) ===
            '{"person":"stsServiceAccountPolicy"}' &&
          policy.SELECTORS.length === 1 &&
          policy.SELECTORS[0].attribute === 'stsServiceAccountPrecedence',
          'A1. the kind is tabbed, named by the person\'s ' +
          'stsServiceAccountPolicy, and its one selector is the precedence');
  let other = '';
  await withRealm(t, 'svcsel-a', function (realm) {
    other = realm.id;
    const bad = policy.save('Not A Name', Object.assign({}, policy.DEFAULTS));
    const high = policy.save('weekly', Object.assign({}, policy.DEFAULTS,
                                                     { precedence: 1001 }));
    t.check(errorCodes.codeOf(bad) === 'STS-SVCACCT-0001' && !high.ok,
            'A2. a malformed name and a precedence out of 1..1000 are ' +
            'refused', JSON.stringify([bad.errors, high.errors]));
    const saved = saveNamed('weekly', { rotationIntervalDays: 7,
                                        allowLdapBind: false }, 20);
    const read = policy.read('weekly');
    t.check(saved.ok && read.stored && read.precedence === 20 &&
            read.rotationIntervalDays === 7 && read.allowLdapBind === false &&
            /^cn=weekly,/i.test(read.dn),
            'A3. a named profile is saved whole with its precedence',
            JSON.stringify(read));
    saveNamed('alpha', {}, 90);
    const names = policy.list().map(function (one) {
      return one.name;
    });
    t.check(JSON.stringify(names) === '["default","weekly","alpha"]',
            'A4. listed after default, by precedence', JSON.stringify(names));
    const view = adminViews.policiesView({});
    const row = ((view.serviceAccount || {}).named || [])
      .filter(function (one) {
        return one.name === 'weekly';
      })[0];
    t.check(!!row && row.precedence === 20 && !!row.namedBy &&
            Array.isArray(row.namedBy.people) &&
            view.kinds.some(function (kind) {
              return kind.id === 'serviceAccount' && kind.tabbed === true;
            }),
            'A5. the console and the API list it, tabbed, with who names it',
            JSON.stringify(row && row.namedBy));
    // B and onwards run in their own realms; this one's profiles go with it.
  });
  await withRealm(t, 'svcsel-a2', function () {
    t.check(policy.read('weekly').stored === false &&
            policy.read('weekly').from === 'built-in' &&
            policy.list().length === 1,
            'A6. a named profile is the realm\'s own: another realm does ' +
            'not hold it', other);
  });
  log.debug('Leaving profiles().');
}

async function reference(t) {
  log.debug('Entering reference().');
  await withRealm(t, 'svcsel-b', async function () {
    person('svcb-owner');
    person('svcb-person');
    account('svcb-acct', 'svcb-owner');
    saveNamed('narrow', { allowLdapBind: false });
    const editor = personEditor.editorFor('svcb-acct');
    const row = editor.attributes.filter(function (one) {
      return one.name === 'stsServiceAccountPolicy';
    })[0];
    t.check(!!row && row.group === 'policies' && row.multi === false &&
            JSON.stringify(row.choices) === '["default","narrow"]',
            'B1. the person editor draws the reference on the Policies ' +
            'tab, one value from default and the realm\'s profiles',
            JSON.stringify(row));
    const notOne = name('svcb-person', 'narrow');
    t.equal(errorCodes.codeOf(notOne), 'STS-SVCACCT-0048',
            'B2. a person who is not a service account is refused it');
    const unknown = name('svcb-acct', 'nowhere');
    t.equal(errorCodes.codeOf(unknown), 'STS-LDAP-0106',
            'B3. a name the realm does not hold is refused');
    const set = name('svcb-acct', 'narrow');
    t.check(set.ok && serviceAccounts.policyReference('svcb-acct') ===
              'narrow' &&
            serviceAccounts.of('svcb-acct').policy === 'narrow',
            'B4. a service account names a held profile, read with the ' +
            'account', JSON.stringify(set.errors));
    const ldapNotOne = await modify('svcb-person', [{ operation: 'replace',
      modification: { type: 'stsServiceAccountPolicy',
                      values: ['narrow'] } }]);
    const ldapUnknown = await modify('svcb-acct', [{ operation: 'replace',
      modification: { type: 'stsServiceAccountPolicy',
                      values: ['nowhere'] } }]);
    t.check(ldapNotOne.ok === false &&
            /SERVICE ACCOUNT/.test(ldapNotOne.error) &&
            ldapUnknown.ok === false &&
            /stsServiceAccountPolicy/.test(ldapUnknown.error) &&
            serviceAccounts.policyReference('svcb-acct') === 'narrow',
            'B5. an LDAP modify meets the same two rules',
            JSON.stringify([ldapNotOne, ldapUnknown]));
    const created = adminActions.usersAction({
      action: 'create', username: 'svcb-new', invent: 'no',
      credential: 'none', 'field.givenName': 'New', 'field.sn': 'Person',
      'field.mail': 'svcb-new@example.test',
      'field.stsServiceAccountPolicy': 'narrow' },
    { via: 'test', actor: 'tester' });
    t.check(errorCodes.codeOf(created) === 'STS-SVCACCT-0048' &&
            !stored('svcb-new'),
            'B6. a create naming it without the flag is refused before ' +
            'anybody exists', JSON.stringify(created.errors));
    const cleared = serviceAccounts.set('svcb-acct',
                                        { serviceAccount: false });
    const after = stored('svcb-acct');
    t.check(cleared.ok && !Object.keys(after.attributes).some(function (k) {
      return k.toLowerCase() === 'stsserviceaccountpolicy';
    }), 'B7. making the account a person again clears the reference');
  });
  log.debug('Leaving reference().');
}

async function readers(t) {
  log.debug('Entering readers().');
  await withRealm(t, 'svcsel-c', function () {
    person('svcc-owner');
    account('svcc-named', 'svcc-owner');
    account('svcc-plain', 'svcc-owner');
    saveNamed('loose', { allowLdapBind: false, allowBrowserSignIn: true,
                         exemptFromSecondFactor: true,
                         requireOwner: false });
    name('svcc-named', 'loose');
    t.check(policy.profileFor('svcc-named').name === 'loose' &&
            policy.profileFor('svcc-plain').name === 'default' &&
            policy.profileFor('svcc-owner').name === 'default',
            'C1. each account is governed by the profile it names, else ' +
            'default');
    t.check(credentials.serviceAccountRefusesDoor('svcc-named', 'ldap') &&
            !credentials.serviceAccountRefusesDoor('svcc-plain', 'ldap') &&
            !credentials.serviceAccountRefusesDoor('svcc-named',
                                                   'browser') &&
            credentials.serviceAccountRefusesDoor('svcc-plain', 'browser'),
            'C2. a door and the browser follow each account\'s own profile');
    t.check(credentials.mfaRequirementFor('svcc-named')
              .exemptServiceAccount === true &&
            !credentials.mfaRequirementFor('svcc-plain')
              .exemptServiceAccount,
            'C3. so does the second-factor exemption');
    const noOwner = serviceAccounts.set('svcc-named',
                                        { serviceAccount: true });
    const plainNoOwner = serviceAccounts.set('svcc-plain',
                                             { serviceAccount: true });
    t.check(noOwner.ok &&
            errorCodes.codeOf(plainNoOwner) === 'STS-SVCACCT-0023',
            'C4. requireOwner at edit is the account\'s own profile\'s',
            JSON.stringify([noOwner.errors, plainNoOwner.errors]));
    const base = { action: 'create', invent: 'no', credential: 'none',
                   serviceAccount: 'true', 'field.givenName': 'New',
                   'field.sn': 'Account' };
    const createdLoose = adminActions.usersAction(Object.assign({}, base, {
      username: 'svcc-new1', 'field.mail': 'svcc-new1@example.test',
      'field.stsServiceAccountPolicy': 'loose' }),
    { via: 'test', actor: 'tester' });
    const createdPlain = adminActions.usersAction(Object.assign({}, base, {
      username: 'svcc-new2', 'field.mail': 'svcc-new2@example.test' }),
    { via: 'test', actor: 'tester' });
    t.check(createdLoose.ok && createdLoose.serviceAccount === true &&
            serviceAccounts.policyReference('svcc-new1') === 'loose' &&
            errorCodes.codeOf(createdPlain) === 'STS-SVCACCT-0023',
            'C5. and at create: the profile the create names needs no ' +
            'owner, default does', JSON.stringify([createdLoose.errors,
                                                   createdPlain.errors]));
  });
  log.debug('Leaving readers().');
}

async function missingAndDelete(t) {
  log.debug('Entering missingAndDelete().');
  await withRealm(t, 'svcsel-d', function () {
    person('svcd-owner');
    account('svcd-acct', 'svcd-owner');
    saveNamed('kept', { allowLdapBind: false });
    name('svcd-acct', 'kept');
    const held = policy.reset('kept');
    t.check(errorCodes.codeOf(held) === 'STS-SVCACCT-0049' &&
            /svcd-acct/.test((held.errors || []).join(' ')) &&
            policy.read('kept').stored,
            'E1. a named profile an account names is not deleted',
            JSON.stringify(held.errors));
    t.check(JSON.stringify(policy.namedBy('kept').people) ===
              '["svcd-acct"]',
            'E2. who names it comes from the service-account index');
    // A REFERENCE NO PROFILE ANSWERS, written past every door (as a restore
    // or a copied entry would), on a policy whose log is watched.
    serviceAccounts.directoryInstalled().writeServiceAccount(
      stored('svcd-acct').dn, { stsServiceAccountPolicy: 'gone' });
    const warned = [];
    const deps = policy.ServiceAccountPolicy.defaultDeps();
    const quiet = deps.log;
    deps.log = {
      debug: function () {
        return quiet.debug.apply(quiet, arguments);
      },
      info: function () {
        return quiet.info.apply(quiet, arguments);
      },
      error: function () {
        return quiet.error.apply(quiet, arguments);
      },
      warn: function (message) {
        warned.push(String(message));
      }
    };
    const watched = new policy.ServiceAccountPolicy(deps);
    watched.setDirectory(policy.directoryInstalled());
    const got = watched.profileFor('svcd-acct');
    t.check(got.name === 'default' && warned.some(function (line) {
      return line.indexOf('STS-SVCACCT-0047') >= 0 &&
             line.indexOf('"gone"') >= 0;
    }) && !credentials.serviceAccountRefusesDoor('svcd-acct', 'ldap'),
            'D1. a reference the realm does not hold gets default, and is ' +
            'logged', JSON.stringify(warned));
    const freed = policy.reset('kept');
    t.check(freed.ok && freed.removed && !policy.read('kept').stored,
            'E3. once nothing names it, it is deleted',
            JSON.stringify(freed.errors));
  });
  log.debug('Leaving missingAndDelete().');
}

// A destination that records what was pushed, or refuses.
function fakeDestinations(answer) {
  log.debug('Entering fakeDestinations().');
  const pushed = [];
  log.debug('Leaving fakeDestinations().');
  return {
    pushed: pushed,
    push: function (id, secret, value) {
      pushed.push({ id: id, name: secret, value: value });
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
  const fs = require('fs');
  const os = require('os');
  const path = require('path');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'svc1240-'));
  await withRealm(t, 'svcsel-f', async function () {
    // A DESTINATION IN THE REALM, so a profile may turn rotation on; the
    // pushes go to a fake the rotation is built with.
    const registered = await require('../common/secret_destinations').act(
      { action: 'add-destination', identifier: 'svcsel-file',
        provider: 'file', directory: dir },
      { actor: 'tester', via: 'test' });
    t.check(registered.ok, 'F0. the realm has a push destination',
            JSON.stringify(registered));
    await withSettings({ 'global.mode': 'product' }, async function () {
      person('svcf-owner');
      account('svcf-weekly', 'svcf-owner');
      account('svcf-plain', 'svcf-owner');
      ['svcf-weekly', 'svcf-plain'].forEach(function (who) {
        serviceAccounts.directoryInstalled().writeServiceAccount(
          stored(who).dn,
          { stsSecretDestination: 'cn=fake,ou=applications,' + ldap.baseDn(),
            stsSecretName: 'iya/' + who });
      });
      saveNamed('weekly', { rotationEnabled: true, rotationIntervalDays: 7,
                            rotationOverlapMinutes: 5, generatedLength: 48,
                            rotationAlarmFailures: 1 });
      const named = name('svcf-weekly', 'weekly');
      t.check(named.ok, 'F1. the account names the rotating profile',
              JSON.stringify(named.errors));
      const realm = realms.currentId();
      const good = fakeDestinations({ ok: true });
      const rotator = rotationWith(good);
      t.check(policy.read('default').rotationEnabled === false &&
              rotator.offReason(realm) === '',
              'F2. default does not rotate, and the hourly job is on all ' +
              'the same, because a named profile does');
      const start = Date.now();
      const run = await rotator.rotateDue(realm, { nowMs: function () {
        return start;
      } });
      const pushed = good.pushed.map(function (one) {
        return one.value.username;
      });
      t.check(run.rotated === 1 && run.skipped === 1 &&
              JSON.stringify(pushed) === '["svcf-weekly"]',
              'F3. the run rotates the account naming the rotating profile ' +
              'and skips the one on default', JSON.stringify(run));
      const fresh = good.pushed.length ? good.pushed[0].value.password : '';
      t.check(fresh.length === 48 &&
              credentials.verify('svcf-weekly', fresh,
                                 { via: 'test', door: 'ldap' }).ok,
              'F4. the pushed password has the named profile\'s length, and ' +
              'is committed', String(fresh.length));
      const facts = serviceAccounts.of('svcf-weekly');
      const overlap = facts.previousPasswordExpires - Date.now();
      t.check(overlap > 0 && overlap <= 5 * 60 * 1000 + 1000,
              'F5. the previous password is kept for the named profile\'s ' +
              'overlap (5 minutes, not default\'s 60)', String(overlap));
      const notYet = await rotator.rotateDue(realm, { nowMs: function () {
        return start + 2 * DAY_MS;
      } });
      const due = await rotator.rotateDue(realm, { nowMs: function () {
        return start + 8 * DAY_MS;
      } });
      t.check(notYet.rotated === 0 && due.rotated === 1,
              'F6. it is due again after the named profile\'s 7 days, ' +
              'where default\'s 30 would not be',
              JSON.stringify([notYet, due]));
      const failing = await rotationWith(fakeDestinations({ ok: false }))
        .rotateOne('svcf-weekly');
      t.check(failing.ok === false && failing.failures === 1 &&
              failing.alarm === true,
              'F7. a failure alarms at the named profile\'s threshold (1)',
              JSON.stringify(failing));
      name('svcf-weekly', '');
      policy.reset('weekly');
    });
  });
  fs.rmSync(dir, { recursive: true, force: true });
  log.debug('Leaving rotation().');
}

module.exports = {
  name: 'service-account policy selection',
  describe: 'Named service-account policies (#1240): a service account ' +
            'names its profile in stsServiceAccountPolicy, held only by a ' +
            'service account, checked at every door; every reader and the ' +
            'rotation job follow the account\'s own profile',
  run: async function (t) {
    log.debug('Entering run().');
    await profiles(t);
    await reference(t);
    await readers(t);
    await missingAndDelete(t);
    await rotation(t);
    log.debug('Leaving run().');
  }
};
