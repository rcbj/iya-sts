// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: locale_policy.js
//
// ===========================================================================
// THE LOCALE POLICY AND THE LANGUAGE OF A PAGE (#539, 2026-10-09).
//
// rcbj: "add a policy default per realm that automatically populates user
// locale parameter", and "create multiple locale policies per realm an assign
// them to application objects" — named since #1238 by an application
// (`appLocalePolicy`) or a group (`stsLocalePolicy`), ranked by precedence
// (rule 3cx). In a realm this test creates, so it starts from nothing it did
// not make:
//
//   A. `cn=default` is saved whole; a tag that is not BCP 47 and a profile
//      name that is not one are refused under their codes.
//   B. A named profile carries a precedence and lists nothing. An
//      application names one (a name the realm does not hold is refused,
//      STS-REG-0203), and so does a group; with the person known, the
//      lowest precedence of the application's and their groups' wins, at
//      the page translator and a static surface's shell; with nobody known
//      the application alone chooses. A reference to a profile the realm
//      does not hold selects nothing (STS-I18N-0013) — `default` where
//      nothing else names one. A profile something names is not deleted
//      (STS-I18N-0014).
//   C. A person CREATED without a preferredLanguage is given the default
//      profile's tag, or the tag of the profile the application that caused
//      the create names; one created with a value keeps it; a profile with
//      population off gives none; an UPDATE never adds one.
//   D. Named profiles are the realm's own: another realm does not see them.
//   E. A page's language: ui_locales, then the person's preferredLanguage,
//      then the chooser's cookie, then Accept-Language, then the policy's
//      default for the application — a POPULATED preferredLanguage ranking
//      after Accept-Language until somebody changes it; and the chooser's
//      return is held to a local path.
// ===========================================================================

delete process.env.CONFIG_FILE;

const realms = require('../common/realms');
const errorCodes = require('../common/error_codes');
const localePolicy = require('../common/locale_policy');
const PageLocale = require('../common/page_locale');
const ldap = require('../ldap/ldap_server');

const log = require('bunyan').createLogger({ name: 'locale_policy',
  level: process.env.LOG_LEVEL || 'info' });

function save(name, fields, precedence) {
  log.debug('Entering save().');
  log.debug('Leaving save().');
  return localePolicy.save(name, Object.assign({}, localePolicy.DEFAULTS,
    fields || {}, precedence === undefined ? {}
      : { precedence: precedence }));
}

// Names a locale profile from an application, through the console's act.
function point(identifier, value) {
  log.debug('Entering point().');
  log.debug('Leaving point().');
  return require('../admin-core/admin_actions').applicationsAction({
    action: 'set', application: identifier, attribute: 'appLocalePolicy',
    value: value }, [], {});
}

// The locale register as installed, so `hide()` can be undone.
let installed = null;

// Makes the register stop answering one profile, as a delete made past the
// console leaves a reference to it.
function hide(name) {
  log.debug('Entering hide().');
  installed = localePolicy.directoryInstalled();
  localePolicy.setDirectory(Object.assign({}, installed, {
    allLocalePolicies: function () {
      return installed.allLocalePolicies().filter(function (one) {
        return String(one.name).toLowerCase() !== name;
      });
    }
  }));
  log.debug('Leaving hide().');
}

function unhide() {
  log.debug('Entering unhide().');
  if (installed) {
    localePolicy.setDirectory(installed);
    installed = null;
  }
  log.debug('Leaving unhide().');
}

function inRealm(realm, fn) {
  log.debug('Entering inRealm().');
  log.debug('Leaving inRealm().');
  return realms.run(realm, fn);
}

async function run(t) {
  log.debug('Entering run().');
  const tag = require('crypto').randomBytes(3).toString('hex');
  const app = 'loc-app-' + tag;
  const made = realms.create({ id: 'loc-' + tag, name: 'loc-' + tag,
                               description: 'Created by ' + __filename });
  const other = realms.create({ id: 'loc2-' + tag, name: 'loc2-' + tag,
                                description: 'Created by ' + __filename });
  // THE TWO REALMS GO IN A finally, as config_realm_layer's withRealm()
  // does: this file shares one process with every other in-process test,
  // and a realm left behind is a realm the next file finds — realm_isolation
  // counted three where it made one, and saw the realm layer active with
  // none of its own defined.
  try {
    checks(t, made, other, app, tag);
  } finally {
    unhide();
    realms.remove(made.realm ? made.realm.id : 'loc-' + tag);
    realms.remove(other.realm ? other.realm.id : 'loc2-' + tag);
  }
  log.debug('Leaving run().');
}

// B: what names a profile, and what applies (#1238). Leaves `mobile` (sv,
// precedence 50) named by the application, which C reads.
function references(t, app, tag) {
  log.debug('Entering references().');
  const adminActions = require('../admin-core/admin_actions');
  const PageLocale = require('../common/page_locale');
  const group = 'loc-group-' + tag;
  const member = 'loc-member-' + tag;
  const outsider = 'loc-outsider-' + tag;
  const mobile = save('mobile', { defaultLocale: 'sv' }, 50);
  const teams = save('teams', { defaultLocale: 'es-MX' }, 10);
  const badRank = save('ranked', { defaultLocale: 'sv' }, 0);
  t.check(mobile.ok && mobile.profile.precedence === 50 &&
          teams.ok && teams.profile.precedence === 10 &&
          mobile.profile.selectApplications === undefined,
          'B. named profiles are saved with a precedence and no list',
          JSON.stringify([mobile.errors, teams.errors]));
  t.check(!badRank.ok && errorCodes.codeOf(badRank) === 'STS-I18N-0004',
          'B. a precedence outside 1 to 1000 is refused',
          JSON.stringify(badRank.errors));
  t.check(JSON.stringify(localePolicy.list().map(function (one) {
    return one.name;
  })) === '["default","teams","mobile"]',
          'B. the profiles list default first, then by precedence');
  const created = adminActions.applicationsAction({ action: 'create',
                                                    identifier: app }, []);
  const named = point(app, 'mobile');
  const ghost = point(app, 'nowhere');
  t.check(created && created.ok && named.ok && !ghost.ok &&
          errorCodes.codeOf(ghost) === 'STS-REG-0203',
          'B. an application names a profile the realm holds in ' +
          'appLocalePolicy, and is refused one it does not',
          JSON.stringify([created && created.errors, named.errors,
                          ghost.errors]));
  ldap.createUser(member, { invent: false });
  ldap.createUser(outsider, { invent: false });
  // NEITHER NAMES A LANGUAGE, so a page falls through to the policy: the
  // one population gave them (fr-CA) would rank above it.
  [member, outsider].forEach(function (who) {
    require('../ldap/person_editor').update(who,
      { attribute: 'preferredLanguage', mode: 'remove', value: 'fr-CA' },
      { actor: 'locale_policy test', via: 'test' });
  });
  ldap.createGroup(group);
  ldap.addGroupMember(group, member);
  const grouped = ldap.setGroupPolicy(group, 'stsLocalePolicy', 'teams');
  const badGroup = ldap.setGroupPolicy(group, 'stsLocalePolicy', 'nowhere');
  t.check(grouped.ok && !badGroup.ok &&
          errorCodes.codeOf(badGroup) === 'STS-LDAP-0195',
          'B. a group names a profile in stsLocalePolicy, and is refused ' +
          'one the realm does not hold',
          JSON.stringify([grouped.errors, badGroup.errors]));
  t.check(localePolicy.profileNameFor(app) === 'mobile' &&
          localePolicy.profileNameFor(app, outsider) === 'mobile' &&
          localePolicy.profileNameFor(app, member) === 'teams' &&
          localePolicy.profileNameFor('', member) === 'teams' &&
          localePolicy.profileNameFor('nobody-' + tag) === 'default' &&
          localePolicy.profileNameFor('') === 'default',
          'B. with nobody known the application chooses; for a member the ' +
          'group\'s profile outranks it by precedence; else default');
  const lang = function (page) {
    log.debug('Entering lang().');
    log.debug('Leaving lang().');
    return PageLocale.translatorFor({ headers: {} }, page).locale;
  };
  const shellDefault = function (person) {
    log.debug('Entering shellDefault().');
    log.debug('Leaving shellDefault().');
    return PageLocale.shellAttributes({ headers: {} }, app, person)
      .filter(function (one) {
        return one[0] === 'data-sts-locale-default';
      })[0][1];
  };
  t.check(lang({ application: app }) === 'sv' &&
          lang({ application: app, username: outsider }) === 'sv' &&
          lang({ application: app, username: member }) === 'es-MX' &&
          shellDefault('') === 'sv' && shellDefault(member) === 'es-MX',
          'B. the page translator and a static surface\'s shell fall back ' +
          'to the profile for the application and the person',
          JSON.stringify([lang({ application: app, username: member }),
                          shellDefault(member)]));
  const by = localePolicy.namedBy('teams');
  const appBy = localePolicy.namedBy('mobile');
  t.check(by.groups.indexOf(group) >= 0 &&
          appBy.applications.indexOf(app) >= 0,
          'B. namedBy() answers the groups and applications naming a ' +
          'profile', JSON.stringify([by, appBy]));
  const keptByGroup = localePolicy.reset('teams');
  const keptByApp = localePolicy.reset('mobile');
  t.check(!keptByGroup.ok &&
          errorCodes.codeOf(keptByGroup) === 'STS-I18N-0014' &&
          !keptByApp.ok && errorCodes.codeOf(keptByApp) === 'STS-I18N-0014',
          'B. a profile an application or a group names is not deleted',
          JSON.stringify([keptByGroup.errors, keptByApp.errors]));
  // A REFERENCE TO A PROFILE THE REALM DOES NOT HOLD selects nothing:
  // `default` with nothing else named, the group's where it names one.
  hide('mobile');
  t.check(localePolicy.profileNameFor(app) === 'default' &&
          localePolicy.defaultLocaleFor(app) === 'fr-CA' &&
          localePolicy.profileNameFor(app, member) === 'teams',
          'B. a missing reference selects nothing and does not fail closed');
  unhide();
  ldap.setGroupPolicy(group, 'stsLocalePolicy', '');
  const gone = localePolicy.reset('teams');
  t.check(gone.ok && gone.removed === true &&
          localePolicy.profileNameFor(app, member) === 'mobile',
          'B. once nothing names it the profile is deleted',
          JSON.stringify(gone.errors));
  log.debug('Leaving references().');
}

// Everything run() asks of the two realms it made, apart so that run() can
// remove them whatever happens here.
function checks(t, made, other, app, tag) {
  log.debug('Entering checks().');
  t.check(made.ok !== false && other.ok !== false, 'two realms were made',
          JSON.stringify([made.errors, other.errors]));

  inRealm(made.realm, function () {
    log.debug('Entering run() in the realm.');
    // A.
    const saved = save('default', { defaultLocale: 'fr-ca' });
    t.check(saved.ok && saved.profile.defaultLocale === 'fr-CA' &&
            saved.profile.populatePreferredLanguage === true &&
            saved.profile.from === 'realm',
            'A. the default profile is saved, its tag canonicalised',
            JSON.stringify(saved.errors || saved.profile));
    const badTag = save('default', { defaultLocale: 'not a tag!' });
    const badName = save('Mobile!', {}, 10);
    t.check(!badTag.ok && errorCodes.codeOf(badTag) === 'STS-I18N-0004' &&
            !badName.ok && errorCodes.codeOf(badName) === 'STS-I18N-0003',
            'A. a malformed tag and a malformed name are refused under ' +
            'their codes', JSON.stringify([badTag.errors, badName.errors]));
    const missing = localePolicy.save('default', { defaultLocale: 'sv' });
    t.check(!missing.ok && errorCodes.codeOf(missing) === 'STS-I18N-0004',
            'A. a save that leaves a field out is refused by name',
            JSON.stringify(missing.errors));

    // B.
    references(t, app, tag);

    // C.
    ldap.createUser('loc-plain-' + tag, { invent: false });
    ldap.createUser('loc-app-user-' + tag, { invent: false,
                                             application: app });
    ldap.createUser('loc-own-' + tag, { invent: false,
                                        attributes: {
                                          preferredLanguage: 'es-PA' } });
    t.check(localePolicy.preferredLanguageOf('loc-plain-' + tag) ===
              'fr-CA',
            'C. a person created with no application is given the default ' +
            'profile\'s tag',
            localePolicy.preferredLanguageOf('loc-plain-' + tag));
    t.check(localePolicy.preferredLanguageOf('loc-app-user-' + tag) === 'sv',
            'C. one an application caused is given the tag of the profile ' +
            'it names',
            localePolicy.preferredLanguageOf('loc-app-user-' + tag));
    t.check(localePolicy.preferredLanguageOf('loc-own-' + tag) === 'es-PA',
            'C. one created with a language keeps it',
            localePolicy.preferredLanguageOf('loc-own-' + tag));
    save('mobile', { defaultLocale: 'sv', populatePreferredLanguage: false },
         50);
    ldap.createUser('loc-none-' + tag, { invent: false, application: app });
    t.check(localePolicy.preferredLanguageOf('loc-none-' + tag) === '',
            'C. a profile with population off gives none',
            localePolicy.preferredLanguageOf('loc-none-' + tag));
    const editor = require('../ldap/person_editor');
    editor.update('loc-plain-' + tag, { attribute: 'preferredLanguage',
                                       mode: 'remove', value: 'fr-CA' },
                  { actor: 'locale_policy test', via: 'test' });
    editor.update('loc-plain-' + tag, { attribute: 'description',
                                       mode: 'set', value: 'touched' },
                  { actor: 'locale_policy test', via: 'test' });
    t.check(localePolicy.preferredLanguageOf('loc-plain-' + tag) === '',
            'C. a removed language stays removed when the entry is ' +
            'written again',
            localePolicy.preferredLanguageOf('loc-plain-' + tag));

    // E.
    const req = function (headers) {
      log.debug('Entering req().');
      log.debug('Leaving req().');
      return { headers: headers || {} };
    };
    const lang = function (r, page) {
      log.debug('Entering lang().');
      log.debug('Leaving lang().');
      return PageLocale.translatorFor(r, page).locale;
    };
    t.check(lang(req(), {}) === 'fr-CA' && lang(req(), { application: app })
              === 'sv',
            'E. with nothing asked, the policy\'s default for the ' +
            'application');
    t.check(lang(req({ 'accept-language': 'zh-TW, en;q=0.5' }), {}) ===
              'zh-TW',
            'E. Accept-Language comes before the policy');
    t.check(lang(req({ 'accept-language': 'zh-TW',
                       cookie: 'a=b; sts_lang=es-MX' }), {}) === 'es-MX',
            'E. the chooser\'s cookie comes before Accept-Language');
    t.check(lang(req({ cookie: 'sts_lang=es-MX' }),
                 { username: 'loc-own-' + tag }) === 'es-PA',
            'E. the person\'s preferredLanguage comes before the cookie');
    t.check(lang(req({ cookie: 'sts_lang=es-MX' }),
                 { username: 'loc-own-' + tag, uiLocales: 'de fil' }) ===
              'fil',
            'E. ui_locales comes first, passing over a tag no catalog ' +
            'answers');
    t.check(lang(req({ 'accept-language': 'de-CH' }), {}) === 'fr-CA',
            'E. a language no catalog answers falls through to the policy');
    // A POPULATED language is the policy's, and ranks below the browser
    // (rcbj on #539); a chosen one ranks above it.
    ldap.createUser('loc-pop-' + tag, { invent: false });
    t.check(localePolicy.languageOf('loc-pop-' + tag).populated === true &&
            localePolicy.languageOf('loc-own-' + tag).populated === false,
            'E. population is told apart from a language the person has');
    t.check(lang(req({ 'accept-language': 'sv' }),
                 { username: 'loc-pop-' + tag }) === 'sv' &&
            lang(req(), { username: 'loc-pop-' + tag }) === 'fr-CA',
            'E. a populated language ranks below the browser, and still ' +
            'answers when the browser says nothing');
    require('../ldap/person_editor').update('loc-pop-' + tag,
      { attribute: 'preferredLanguage', mode: 'set', value: 'zh-TW' },
      { actor: 'locale_policy test', via: 'test' });
    t.check(localePolicy.languageOf('loc-pop-' + tag).populated === false &&
            lang(req({ 'accept-language': 'sv' }),
                 { username: 'loc-pop-' + tag }) === 'zh-TW',
            'E. once set to another language it is the person\'s, and ' +
            'outranks the browser');
    log.debug('Leaving run() in the realm.');
  });

  // D.
  inRealm(other.realm, function () {
    log.debug('Entering run() in the other realm.');
    t.check(localePolicy.profileNameFor(app) === 'default' &&
            localePolicy.list().every(function (one) {
              return one.name === 'default';
            }),
            'D. another realm does not see the first realm\'s named ' +
            'profiles');
    log.debug('Leaving run() in the other realm.');
  });

  t.check(PageLocale.safeReturn('/authn/login?authn=x') ===
            '/authn/login?authn=x' &&
          PageLocale.safeReturn('//evil.example/') === '/' &&
          PageLocale.safeReturn('https://evil.example/') === '/' &&
          PageLocale.safeReturn('/\\evil') === '/' &&
          PageLocale.safeReturn('/x\ny') === '/' &&
          PageLocale.safeReturn('') === '/',
          'E. the chooser returns only to a local path');
  log.debug('Leaving checks().');
}

module.exports = {
  name: 'locale_policy',
  describe: 'the locale policy: the default and named profiles an ' +
            'application or a group names, ranked by precedence, a new ' +
            'person given a language, and the order a page\'s language is ' +
            'chosen in (#539, #1238)',
  run: run
};
