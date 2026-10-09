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
// them to application objects". In a realm this test creates, so it starts
// from nothing it did not make:
//
//   A. `cn=default` is saved whole; a tag that is not BCP 47 and a profile
//      name that is not one are refused under their codes.
//   B. A named profile needs an application, and an application is on one
//      named profile at most (STS-I18N-0007); the profile for an
//      application is its named one, and `default` otherwise.
//   C. A person CREATED without a preferredLanguage is given the default
//      profile's tag, or the tag of the profile of the application that
//      caused the create; one created with a value keeps it; a profile with
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

function save(name, fields, applications) {
  log.debug('Entering save().');
  log.debug('Leaving save().');
  return localePolicy.save(name, Object.assign({}, localePolicy.DEFAULTS,
    fields || {}, applications === undefined ? {}
      : { selectApplications: applications }));
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
    const badName = save('Mobile!', {}, app);
    t.check(!badTag.ok && errorCodes.codeOf(badTag) === 'STS-I18N-0004' &&
            !badName.ok && errorCodes.codeOf(badName) === 'STS-I18N-0003',
            'A. a malformed tag and a malformed name are refused under ' +
            'their codes', JSON.stringify([badTag.errors, badName.errors]));
    const missing = localePolicy.save('default', { defaultLocale: 'sv' });
    t.check(!missing.ok && errorCodes.codeOf(missing) === 'STS-I18N-0004',
            'A. a save that leaves a field out is refused by name',
            JSON.stringify(missing.errors));

    // B.
    const mobile = save('mobile', { defaultLocale: 'sv' }, app);
    const noApp = save('lonely', { defaultLocale: 'sv' }, '');
    const twice = save('second', { defaultLocale: 'es-MX' }, app);
    t.check(mobile.ok && mobile.profile.name === 'mobile' &&
            JSON.stringify(mobile.profile.selectApplications) ===
              JSON.stringify([app]),
            'B. a named profile is saved with its application',
            JSON.stringify(mobile.errors));
    t.check(!noApp.ok && errorCodes.codeOf(noApp) === 'STS-I18N-0004',
            'B. a named profile naming no application is refused',
            JSON.stringify(noApp.errors));
    t.check(!twice.ok && errorCodes.codeOf(twice) === 'STS-I18N-0007',
            'B. an application already on a named profile cannot be put on ' +
            'a second', JSON.stringify(twice.errors));
    t.check(localePolicy.profileNameFor(app) === 'mobile' &&
            localePolicy.profileNameFor('nobody-' + tag) === 'default' &&
            localePolicy.defaultLocaleFor(app) === 'sv' &&
            localePolicy.defaultLocaleFor('') === 'fr-CA',
            'B. an application reads its named profile, anything else the ' +
            'default');

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
            'C. one an application caused is given its profile\'s tag',
            localePolicy.preferredLanguageOf('loc-app-user-' + tag));
    t.check(localePolicy.preferredLanguageOf('loc-own-' + tag) === 'es-PA',
            'C. one created with a language keeps it',
            localePolicy.preferredLanguageOf('loc-own-' + tag));
    save('mobile', { defaultLocale: 'sv', populatePreferredLanguage: false },
         app);
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
  log.debug('Leaving run().');
}

module.exports = {
  name: 'locale_policy',
  describe: 'the locale policy: the default and named profiles chosen by ' +
            'application, a new person given a language, and the order a ' +
            'page\'s language is chosen in (#539)',
  run: run
};
