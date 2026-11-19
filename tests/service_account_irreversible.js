// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: service_account_irreversible.js
//
// ===========================================================================
// A SERVICE ACCOUNT IS FOR GOOD (rcbj, 2026-11-15), in process.
//
// rcbj: "Once a user is established as a service account, do not allow this
// to be undone. Do not allow all owners to be deleted. Do not allow an owner
// to delete themselves as an owner. Add a warning when a user clicks the
// button to convert a user object to a service account stating this cannot
// be undone." `common/service_accounts.ts` (its header and
// `ownerChangeRefusal()`) and `common/CLAUDE.md` 3cd argue the rules. Held
// here, each in a throwaway realm, each refusal by its own code:
//
//   A. THE MANAGEMENT API (and so the console, whose every act is one of
//      its operations), through `usersAction()` with the context the API
//      passes — the token's person as `admin`:
//        A1 `serviceAccount` false on a service account (STS-SVCACCT-0060),
//           and nothing on the entry changes;
//        A2 `serviceAccount` true on one still changes its owners;
//        A3 false on an ordinary person changes nothing and is not refused;
//        A4 the last owner's Remove (0061), and `owners: []` (0061 ahead of
//           requireOwner's 0023);
//        A5 with requireOwner off: still 0061 for both; an account MADE with
//           no owner may be edited with none;
//        A6 an owner taking off their own DN, by Remove and by a set that
//           leaves them out (0062);
//        A7 an owner taking off the group that is their only way of owning
//           it (0063), and a group they are in while they still own it
//           another way taken off freely;
//        A8 another administrator taking an owner off while one remains;
//        A9 deleting the entry is allowed, and a person made again at the
//           name is an ordinary person;
//        A10 the person editor's set-attribute and update-fields do not
//           reach the flag or the owners.
//   B. AN LDAP MODIFY, with the bound DN as the caller:
//        B1 delete of the flag, B2 a replace of it with FALSE (0064);
//        B3 delete of the last owner (0065);
//        B4 the bound DN deleting itself (0066);
//        B5 the bound DN deleting the group that is its only way (0067);
//        B6 another bound DN deleting an owner while one remains.
//   C. THE CONSOLE: no "Make them an ordinary person" button and the
//      permanent note in its place; the Make carries the unfolded warning
//      and a REQUIRED, unnamed checkbox ahead of it, which every other
//      button of the form passes over (`formnovalidate`); the new-user
//      screen warns beside its box; and every base catalog has the new
//      strings and none of the old.
// ===========================================================================

delete process.env.CONFIG_FILE;

const i18n = require('../common/i18n');
const fs = require('fs');
const path = require('path');
const realms = require('../common/realms');
const errorCodes = require('../common/error_codes');
const credentials = require('../common/credentials');
const audit = require('../common/audit');
const serviceAccounts = require('../common/service_accounts');
const policy = require('../common/service_account_policy');
const ldap = require('../ldap/ldap_server');
const adminActions = require('../admin-core/admin_actions');
const adminViews = require('../admin-core/admin_views');
const UsersPage = require('../admin-ui/web_users');
const kit = require('../admin-ui/web_kit');

const log = require('bunyan').createLogger({
  name: 'service_account_irreversible',
  level: process.env.LOG_LEVEL || 'info' });

const PASSWORD = 'Sv1c-F0r-G00d-Pa55word!x';

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

function person(name) {
  log.debug('Entering person().');
  ldap.createUser(name, { invent: false });
  const set = credentials.setPassword(name, PASSWORD);
  log.debug('Leaving person().');
  return set;
}

function dnOf(name) {
  log.debug('Entering dnOf().');
  const entry = ldap.existingUserEntry(name);
  log.debug('Leaving dnOf().');
  return entry ? entry.dn : '';
}

function ownerDns(name) {
  log.debug('Entering ownerDns().');
  const facts = serviceAccounts.of(name);
  log.debug('Leaving ownerDns().');
  return facts ? facts.owners.map(function (one) {
    return one.dn.toLowerCase();
  }) : [];
}

// The API's context for a person signed in to it: `admin` is what
// `callerPersonOf()` answers for the verified token.
function as(username) {
  log.debug('Entering as().');
  log.debug('Leaving as().');
  return { via: 'api', actor: username,
           admin: username ? { username: username, sub: '' } : null };
}

function act(body, ctx) {
  log.debug('Entering act().');
  log.debug('Leaving act().');
  return adminActions.usersAction(body, ctx || as(''));
}

// How many audit rows carry `code` now.
function rowsWith(code) {
  log.debug('Entering rowsWith().');
  const out = audit.list().filter(function (row) {
    return row.errorCode === code;
  }).length;
  log.debug('Leaving rowsWith().');
  return out;
}

// An LDAP modify through the operation a worker runs, bound as `boundDn`.
async function modify(dn, boundDn, changes) {
  log.debug('Entering modify().');
  const out = await Promise.resolve(ldap.performOperation('modify', {
    dn: dn, boundDn: boundDn || '', channel: 'ldaps',
    changes: changes.map(function (one) {
      return { operation: one[0],
               modification: { type: one[1], values: one.slice(2) } };
    }) }));
  log.debug('Leaving modify().');
  return out;
}

// A modify that must be refused with `code` and change nothing.
async function refusedOverLdap(t, label, code, dn, boundDn, changes,
                               unchanged) {
  log.debug('Entering refusedOverLdap(). ' + code);
  const before = rowsWith(code);
  const got = await modify(dn, boundDn, changes);
  t.check(got.ok === false && /ConstraintViolation/.test(got.errorName) &&
          rowsWith(code) === before + 1 && unchanged(),
          label + ' (' + code + ')', JSON.stringify(got));
  log.debug('Leaving refusedOverLdap().');
}

async function theApi(t) {
  log.debug('Entering theApi().');
  await withRealm(t, 'svc-good-api', function () {
    ['svcg', 'svcg-ann', 'svcg-bo', 'svcg-cy', 'svcg-plain']
      .forEach(person);
    const ops = ldap.createGroup('svcg-ops', { members: ['svcg-cy'] });
    t.check(ops && ops.ok, 'A0. a group with a member', JSON.stringify(ops));
    const ann = dnOf('svcg-ann');
    const bo = dnOf('svcg-bo');
    const made = act({ action: 'set-service-account', user: 'svcg',
                       owners: ['svcg-ann', 'svcg-bo'] }, as('svcg-ann'));
    t.check(made.ok && ownerDns('svcg').length === 2,
            'A0. a service account with two owners', JSON.stringify(made));

    const cleared = act({ action: 'set-service-account', user: 'svcg',
                          serviceAccount: 'false' }, as('svcg-bo'));
    t.check(cleared.ok === false &&
            errorCodes.codeOf(cleared) === 'STS-SVCACCT-0060' &&
            serviceAccounts.isServiceAccountName('svcg') &&
            ownerDns('svcg').length === 2,
            'A1. serviceAccount false on a service account is refused ' +
            '(STS-SVCACCT-0060) and nothing changes', JSON.stringify(cleared));
    const kept = act({ action: 'set-service-account', user: 'svcg',
                       owners: ['svcg-ann', 'svcg-bo', 'svcg-ops'] },
                     as('svcg-bo'));
    t.check(kept.ok && kept.serviceAccount === true &&
            ownerDns('svcg').length === 3,
            'A2. serviceAccount true on one still changes its owners',
            JSON.stringify(kept));
    const plain = act({ action: 'set-service-account', user: 'svcg-plain',
                        serviceAccount: false }, as('svcg-bo'));
    t.check(plain.ok && !serviceAccounts.isServiceAccountName('svcg-plain'),
            'A3. false on an ordinary person changes nothing and is not ' +
            'refused', JSON.stringify(plain));

    // A6: an owner's own DN, by Remove and by a set leaving them out.
    const selfRemove = act({ action: 'remove-service-account-owner',
                             user: 'svcg', owner: ann }, as('svcg-ann'));
    const selfSet = act({ action: 'set-service-account', user: 'svcg',
                          owners: ['svcg-bo', 'svcg-ops'] }, as('svcg-ann'));
    t.check(errorCodes.codeOf(selfRemove) === 'STS-SVCACCT-0062' &&
            errorCodes.codeOf(selfSet) === 'STS-SVCACCT-0062' &&
            ownerDns('svcg').indexOf(ann.toLowerCase()) >= 0,
            'A6. an owner cannot take off their own DN, by Remove or by a ' +
            'set that leaves them out (STS-SVCACCT-0062)',
            JSON.stringify([selfRemove.errors, selfSet.errors]));

    // A7: cy owns it only through svcg-ops.
    const opsDn = ops.dn;
    const groupSelf = act({ action: 'remove-service-account-owner',
                            user: 'svcg', owner: opsDn }, as('svcg-cy'));
    t.check(errorCodes.codeOf(groupSelf) === 'STS-SVCACCT-0063' &&
            ownerDns('svcg').indexOf(opsDn.toLowerCase()) >= 0,
            'A7. an owner cannot take off the group that is their only ' +
            'way of owning it (STS-SVCACCT-0063)',
            JSON.stringify(groupSelf.errors));
    ldap.addGroupMember('svcg-ops', 'svcg-bo');
    const groupNotSelf = act({ action: 'remove-service-account-owner',
                               user: 'svcg', owner: opsDn }, as('svcg-bo'));
    t.check(groupNotSelf.ok &&
            ownerDns('svcg').indexOf(opsDn.toLowerCase()) < 0,
            'A7b. a group the caller is in goes while they still own it ' +
            'another way', JSON.stringify(groupNotSelf.errors));

    // A8: bo takes ann off; bo remains.
    const byAnother = act({ action: 'remove-service-account-owner',
                            user: 'svcg', owner: ann }, as('svcg-bo'));
    t.check(byAnother.ok && ownerDns('svcg').length === 1 &&
            ownerDns('svcg')[0] === bo.toLowerCase(),
            'A8. another administrator takes an owner off while one ' +
            'remains', JSON.stringify(byAnother.errors));

    // A4: bo is the last; nobody named (a client's token), so only rule 2.
    const last = act({ action: 'remove-service-account-owner', user: 'svcg',
                       owner: bo }, as(''));
    const emptied = act({ action: 'set-service-account', user: 'svcg',
                          owners: [] }, as(''));
    t.check(errorCodes.codeOf(last) === 'STS-SVCACCT-0061' &&
            errorCodes.codeOf(emptied) === 'STS-SVCACCT-0061' &&
            ownerDns('svcg').length === 1,
            'A4. the last owner\'s Remove and owners [] are refused ' +
            '(STS-SVCACCT-0061)', JSON.stringify([last.errors,
                                                   emptied.errors]));

    // A5: requireOwner off changes neither, and an account made with none
    // may be edited with none.
    policy.save('default', Object.assign({}, policy.DEFAULTS,
                                         { requireOwner: false }));
    try {
      const looseLast = act({ action: 'remove-service-account-owner',
                              user: 'svcg', owner: bo }, as(''));
      const looseEmpty = act({ action: 'set-service-account', user: 'svcg',
                               owners: '' }, as(''));
      t.check(errorCodes.codeOf(looseLast) === 'STS-SVCACCT-0061' &&
              errorCodes.codeOf(looseEmpty) === 'STS-SVCACCT-0061' &&
              ownerDns('svcg').length === 1,
              'A5. with requireOwner off the last owner still stays');
      person('svcg-bare');
      const bare = act({ action: 'set-service-account', user: 'svcg-bare' },
                       as(''));
      const bareAgain = act({ action: 'set-service-account-destination',
                              user: 'svcg-bare', destination: '',
                              secretName: '' }, as(''));
      t.check(bare.ok && bareAgain.ok && ownerDns('svcg-bare').length === 0,
              'A5b. an account made with no owner under requireOwner off ' +
              'is edited with none', JSON.stringify([bare.errors,
                                                     bareAgain.errors]));
    } finally {
      policy.reset('default');
    }

    // A10: the person editor's two writes do not reach the flag or the
    // owners: neither is an attribute it offers.
    const byAttribute = act({ action: 'set-attribute', user: 'svcg',
                              attribute: 'stsServiceAccount', value: '' },
                            as('svcg-bo'));
    const ownersByAttribute = act({ action: 'set-attribute', user: 'svcg',
                                    attribute: 'stsServiceAccountOwner',
                                    value: '' }, as('svcg-bo'));
    const byFields = act({ action: 'update-fields', user: 'svcg',
                           'field.stsServiceAccount': '',
                           'field.stsServiceAccountOwner': '' },
                         as('svcg-bo'));
    t.check(byAttribute.ok === false && ownersByAttribute.ok === false &&
            serviceAccounts.isServiceAccountName('svcg') &&
            ownerDns('svcg').length === 1,
            'A10. the person editor cannot clear the flag or the owners',
            JSON.stringify([byAttribute.errors, ownersByAttribute.errors,
                            byFields.ok, byFields.errors]));

    // A9: deletion is not conversion.
    const gone = ldap.deletePerson(dnOf('svcg'));
    t.check(gone && gone.ok !== false &&
            !serviceAccounts.isServiceAccountName('svcg'),
            'A9. deleting the entry is still allowed', JSON.stringify(gone));
    person('svcg');
    t.check(!serviceAccounts.isServiceAccountName('svcg') &&
            serviceAccounts.of('svcg') === null,
            'A9b. a person made again at the name is an ordinary person');
  });
  log.debug('Leaving theApi().');
}

async function theLdapModify(t) {
  log.debug('Entering theLdapModify().');
  await withRealm(t, 'svc-good-ldap', async function () {
    ['svcl', 'svcl-ann', 'svcl-bo', 'svcl-cy'].forEach(person);
    const ops = ldap.createGroup('svcl-ops', { members: ['svcl-cy'] });
    const dn = dnOf('svcl');
    const ann = dnOf('svcl-ann');
    const bo = dnOf('svcl-bo');
    const cy = dnOf('svcl-cy');
    const made = await modify(dn, bo, [
      ['replace', 'stsServiceAccount', 'TRUE'],
      ['replace', 'stsServiceAccountOwner', ann, bo, ops.dn]]);
    t.check(made.ok !== false && ownerDns('svcl').length === 3,
            'B0. an LDAP modify makes a service account with three owners',
            JSON.stringify(made));
    const stillOne = function () {
      return serviceAccounts.isServiceAccountName('svcl');
    };
    await refusedOverLdap(t, 'B1. a delete of the flag is refused',
      'STS-SVCACCT-0064', dn, bo, [['delete', 'stsServiceAccount']],
      stillOne);
    await refusedOverLdap(t, 'B2. and so is a replace of it with FALSE',
      'STS-SVCACCT-0064', dn, bo,
      [['replace', 'stsServiceAccount', 'FALSE']], stillOne);
    const three = function () {
      return ownerDns('svcl').length === 3;
    };
    await refusedOverLdap(t, 'B4. the bound DN deleting itself is refused',
      'STS-SVCACCT-0066', dn, ann,
      [['delete', 'stsServiceAccountOwner', ann]], three);
    await refusedOverLdap(t, 'B5. and so is it deleting the group that is ' +
      'its only way of owning the account', 'STS-SVCACCT-0067', dn, cy,
      [['delete', 'stsServiceAccountOwner', ops.dn]], three);
    const byAnother = await modify(dn, bo, [
      ['delete', 'stsServiceAccountOwner', ann, ops.dn]]);
    t.check(byAnother.ok !== false && ownerDns('svcl').length === 1,
            'B6. another bound DN deletes owners while one remains',
            JSON.stringify(byAnother));
    await refusedOverLdap(t, 'B3. a delete of the last owner is refused',
      'STS-SVCACCT-0065', dn, ann, [['delete', 'stsServiceAccountOwner']],
      function () {
        return ownerDns('svcl').length === 1;
      });
  });
  log.debug('Leaving theLdapModify().');
}

function theConsole(t) {
  log.debug('Entering theConsole().');
  const tr = kit.context().t;
  const account = {
    owners: [{ dn: 'uid=ann,ou=users,dc=x', kind: 'person', name: 'ann' }],
    destination: null, secretName: null, rotatedAt: null,
    rotation: { rotates: false, enabled: false, failures: 0 },
    policy: { exemptFromSecondFactor: false, allowBrowserSignIn: false,
              doors: ['ldap'], requiresOwner: true }
  };
  const rules = { requiresOwner: true, maxOwners: 25,
                  dn: 'uid=svc,ou=users,dc=x' };
  const held = UsersPage.serviceAccountSection(tr, 'svc', account,
    { write: true }, '/admin/users', rules, {});
  t.check(held.indexOf('name="serviceAccount" value="false"') < 0 &&
          held.indexOf('Make them an ordinary person') < 0 &&
          held.indexOf(tr.html('consoleUsers.serviceAccountSection.' +
                               'permanentNote')) >= 0,
          'C1. a service account\'s tab has no way back, and says so');
  const ordinary = UsersPage.serviceAccountSection(tr, 'svc', null,
    { write: true }, '/admin/users', rules, {});
  const makeForm = (ordinary.match(/<form[^>]*class="sa-form"[\s\S]*?<\/form>/) ||
                    [''])[0];
  const box = makeForm.indexOf('id="service-account-irreversible"');
  const warning = makeForm.indexOf('<div class="warn" ' +
                                   'id="service-account-warning">');
  const visible = makeForm.lastIndexOf('<div class="formrow"><button title=');
  const boxTag = (makeForm.match(
    /<input type="checkbox" id="service-account-irreversible"[^>]*>/) ||
    [''])[0];
  t.check(box > 0 && warning > 0 && warning < box && box < visible &&
          / required>?/.test(boxTag) && !/ name=/.test(boxTag) &&
          makeForm.indexOf(tr.html('consoleUsers.serviceAccountSection.' +
            'irreversibleWarning', { key: 'svc' })) >= 0 &&
          makeForm.indexOf(tr.html('consoleUsers.serviceAccountSection.' +
            'irreversibleConfirm', { key: 'svc' })) >= 0,
          'C2. the Make carries the unfolded warning and a required, ' +
          'unnamed checkbox ahead of its button', boxTag);
  const buttons = makeForm.match(/<button[^>]*>/g) || [];
  const validated = buttons.filter(function (one) {
    return one.indexOf('formnovalidate') < 0;
  });
  t.check(validated.length === 2 && validated.every(function (one) {
    return !/ name="(drop|fgsearch|fgadd)"/.test(one);
  }), 'C3. only the Make and its default button wait for the box; every ' +
      'other button passes over it (formnovalidate)',
  JSON.stringify(validated));
  const view = adminViews.newUserJson({ query: {} });
  const create = UsersPage.newUserBody(kit.context(), view);
  t.check(view.directory === true &&
          String(create).indexOf('<div class="warn">' +
    tr.html('consoleUsers.serviceAccountSection.permanentNote')) >= 0,
          'C4. the new-user screen warns beside its Service account box');
  const dir = path.join(__dirname, '..', 'common', 'locales',
                        'consoleUsers');
  // Base catalogs from catalogs.json. A regional overlay is not a second
  // language, and a language added to the index is checked here.
  const locales = i18n.catalogs().filter(function (c) {
    return !c.base;
  }).map(function (c) {
    return c.tag;
  });
  const wanted = ['irreversibleWarning', 'irreversibleConfirm',
                  'permanentNote'];
  const problems = [];
  locales.forEach(function (locale) {
    const catalog = JSON.parse(fs.readFileSync(path.join(dir, locale +
                                                         '.json'), 'utf8'));
    wanted.forEach(function (key) {
      const value = catalog['serviceAccountSection.' + key];
      if (!value || (key !== 'permanentNote' &&
                     value.indexOf('{key}') < 0)) {
        problems.push(locale + ' ' + key);
      }
    });
    ['ordinaryButton', 'ordinaryTitle'].forEach(function (key) {
      if (catalog['serviceAccountSection.' + key] !== undefined) {
        problems.push(locale + ' still has ' + key);
      }
    });
  });
  t.check(problems.length === 0,
          'C5. every base catalog has the three new strings and neither ' +
          'old one', problems.join('; '));
  log.debug('Leaving theConsole().');
}

module.exports = {
  name: 'service account irreversible',
  describe: 'A service account is for good (rcbj, 2026-11-15): never made a ' +
            'person again, never left with no owner once it has one, and an ' +
            'owner never removes themselves — at the management API, over ' +
            'LDAP, and on the console, which warns before the Make',
  run: async function (t) {
    log.debug('Entering run().');
    await theApi(t);
    await theLdapModify(t);
    theConsole(t);
    log.debug('Leaving run().');
  }
};
