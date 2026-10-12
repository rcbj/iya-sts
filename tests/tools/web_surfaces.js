// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/tools/web_surfaces.js
// ===========================================================================
// EVERY STATIC SURFACE, IN ONE TABLE (#570, 2026-10-12).
//
// One bundle per surface (rcbj's decision 2 on #570), each built by
// `build-typescript.sh`'s `bundle_surface` and each held to the round trip
// (`tests/tools/web_round_trip.js`). `tests/web_surfaces.js` reads this table
// and asks of every row:
//
//   * the build made the renderers' bundle and the runtime, with the
//     runtime's brotli and gzip beside it, and `build-typescript.sh` names
//     the row's files in a `bundle_surface` line;
//   * the renderers' bundle runs with no `require`, `process`, `module` or
//     `Buffer`, and answers a page table whose every row has a path and a
//     renderer;
//   * and where the row has `cases`, every case drawn by the bundle from its
//     view after the wire is, to the byte, what this process's compiled
//     module draws.
//
// A ROW: `{ name, pages, global, bundle, runtime, heldBy?, cases? }` — the
// page table's source, the bundle's global, the two built files, and either
// the test that already draws every page of the surface from its API's
// answers (`heldBy`, the console's and the portal's, which need the whole
// stack and a signed-in person) or `cases(ROOT)`, which answers
// `[{ label, view, ctx, path }]` for pages drawable from a view alone.
//
// The front door (#579) is the first row with `cases`: its one page is drawn
// from a view alone, in English and in French, in both modes, with and
// without the image, and with a console on another listener.
//
// The sign-in screen (#571) draws three pages from views alone: the screen
// in the states its view can name, the federation chooser and the forced
// password change.
//
// A NEW SURFACE ADDS ITS ROW HERE in the same commit that adds its
// `bundle_surface` line (`common/CLAUDE.md`, *Static public surfaces*).
// ===========================================================================

const fs = require('fs');
const path = require('path');
const log = require('bunyan').createLogger({ name: 'web_surfaces_table',
  level: process.env.STS_LOG_LEVEL || 'info' });

/**
 * A translator over one namespace's catalogs on disk, built the way the
 * browser's `WebI18n` builds it (`ns.key` → message, along a chain).
 *
 * @param {string} root - the repository root
 * @param {string|string[]} ns - the namespace, or several (#573: the
 *   sign-in surface draws `authn` and `emailFactor`)
 * @param {string[]} chain - the catalogs, most preferred first
 * @returns {object} the translator
 */
function translatorFor(root, ns, chain) {
  log.debug("Entering translatorFor(). " + ns + " " + chain.join(','));
  const messages = require(path.join(root, 'common', 'web_messages'));
  const catalogs = {};
  chain.forEach(function (tag) {
    const flat = {};
    [].concat(ns).forEach(function (one) {
      const own = JSON.parse(fs.readFileSync(path.join(root, 'common',
        'locales', one, tag + '.json'), 'utf8'));
      Object.keys(own).forEach(function (key) {
        flat[one + '.' + key] = own[key];
      });
    });
    catalogs[tag] = flat;
  });
  log.debug("Leaving translatorFor().");
  return messages.WebTranslator.fromData({ catalogs: catalogs,
    negotiated: { locale: chain[0], chain: chain, catalog: chain[0],
                  direction: 'ltr', matched: true } });
}

/**
 * The front door's cases (#579): the view in both modes, with and without
 * the image, a console on another listener, in English and in French.
 *
 * @param {string} root - the repository root
 * @returns {object[]} `[{ label, view, ctx, path }]`
 */
function homeCases(root) {
  log.debug("Entering homeCases().");
  const links = function (consoleHref) {
    log.debug("Entering links().");
    log.debug("Leaving links().");
    return [
      { id: 'repo', href: 'https://github.com/rcbj/iya-sts',
        external: true },
      { id: 'issues', href: 'https://github.com/rcbj/iya-sts/issues',
        external: true },
      { id: 'docs', href: 'https://rcbj.github.io/iya-sts/',
        external: true },
      { id: 'console', href: consoleHref, external: false },
      { id: 'portal', href: '/portal', external: false }
    ];
  };
  const development = { name: 'IYA STS', version: '0.9.20261012',
    build: 'built 2026-10-12T00:00:00Z from "abc" & <def>',
    mode: { verifiesCredentials: false, gatesConsole: true },
    logo: { src: '/logo.png', width: 906, height: 269 },
    links: links('/admin') };
  const product = Object.assign({}, development, {
    mode: { verifiesCredentials: true, gatesConsole: true }, logo: null,
    links: links('https://admin.example:9443/realm/a/admin?x=1&y="2"') });
  const en = { t: translatorFor(root, 'home', ['en']), query: {},
               prefix: '', origin: 'https://sts.example', here: '/' };
  const fr = Object.assign({}, en,
    { t: translatorFor(root, 'home', ['fr', 'en']) });
  log.debug("Leaving homeCases().");
  return [
    { label: 'the front page, development, in English', path: '/',
      view: development, ctx: en },
    { label: 'the front page, product, a console elsewhere, no image',
      path: '/', view: product, ctx: en },
    { label: 'the front page, development, in French', path: '/',
      view: development, ctx: fr },
    { label: 'an ungated console (the arm no mode reaches today)',
      path: '/', ctx: en, view: Object.assign({}, development,
        { mode: { verifiesCredentials: false, gatesConsole: false } }) }
  ];
}

/**
 * The sign-in screen's cases (#571): the screen with every door offered, in
 * English and in French; the screen in product, locked to a person, with
 * every demand on and a refusal over it; a screen the application allows
 * nothing on; the federation chooser; and the forced password change.
 *
 * @param {string} root - the repository root
 * @returns {object[]} `[{ label, view, ctx, path }]`
 */
function authnCases(root) {
  log.debug("Entering authnCases().");
  const en = { t: translatorFor(root, ['authn', 'emailFactor'], ['en']),
               query: {},
               prefix: '', origin: 'https://sts.example',
               here: '/authn/login?authn=abc', error: '', autofill: true };
  const fr = Object.assign({}, en,
    { t: translatorFor(root, ['authn', 'emailFactor'], ['fr', 'en']) });
  const partner = { id: 'acme-saml', label: 'Acme <SAML> & co',
    protocolLabel: 'SAML 2.0', peer: 'https://idp.acme.example',
    href: '/federation/login/acme-saml?returnTo=%2Foauth2%2Fauthorize' };
  const details = [{ label: 'client_id', value: 'demo "client"',
                     note: '' },
                   { label: 'issuer_state', value: '',
                     note: 'from a Credential Offer' }];
  const everything = { id: 'abc', base: 'https://sts.example',
    protocol: 'OAuth 2.0', application: 'demo', error: '', locked: '',
    hint: 'alice', screen: true, password: true,
    keys: { enabled: true, mfaAllowed: true, primaryAllowed: true },
    demands: { mfa: false, key: false, passwordless: false, via: '' },
    remember: true, anonymous: true, passkey: true,
    email: { code: true, link: true }, forgot: '/portal/forgot-password',
    partners: { kind: 'any', options: [partner] },
    kerberos: { state: 'offered', href: '/authn/spnego?authn=abc' },
    wallet: { state: 'offered', mfaNote: false,
              href: '/authn/wallet?authn=abc',
              siop: '/authn/wallet?authn=abc&siop=1' },
    verifiesCredentials: false, fingerprint: true, details: details };
  const demanding = Object.assign({}, everything, {
    error: 'The application names a disabled partner.',
    locked: 'bob', hint: 'bob', password: true,
    keys: { enabled: true, mfaAllowed: true, primaryAllowed: false },
    demands: { mfa: true, key: true, passwordless: true,
               via: 'partner-x' },
    remember: false, anonymous: false, passkey: false,
    email: { code: false, link: false }, forgot: '',
    partners: { kind: 'own-many', options: [partner, partner] },
    kerberos: { state: 'withheld-mfa', href: '' },
    wallet: { state: 'withheld', mfaNote: false, href: '', siop: '' },
    verifiesCredentials: true, fingerprint: false, details: [] });
  const keysOff = Object.assign({}, everything, {
    keys: { enabled: false, mfaAllowed: false, primaryAllowed: false },
    partners: { kind: 'own-one', options: [partner] },
    kerberos: { state: 'withheld-key', href: '' },
    wallet: { state: 'offered', mfaNote: true, href: '/authn/wallet',
              siop: '' } });
  const nothing = Object.assign({}, everything, { screen: false,
    partners: null, kerberos: null, wallet: null });
  log.debug("Leaving authnCases().");
  return [
    { label: 'the sign-in screen, every door, in English',
      path: '/authn/login', view: everything, ctx: en },
    { label: 'the sign-in screen, every door, in French',
      path: '/authn/login', view: everything, ctx: fr },
    { label: 'the screen in product, locked, every demand, refused',
      path: '/authn/login', view: demanding,
      ctx: Object.assign({}, en, { error: 'Authentication failed for bob.',
                                   autofill: false }) },
    { label: 'the screen with passkeys off and a refused passkey',
      path: '/authn/login', view: keysOff,
      ctx: Object.assign({}, en, { autofill: false }) },
    { label: 'the screen an application allows nothing on',
      path: '/authn/login', view: nothing, ctx: en },
    { label: 'the federation chooser', path: '/authn/select-idp',
      view: { id: 'abc', base: 'https://sts.example', protocol: 'SAML 2.0',
              application: 'urn:sp:<one>', partners: [partner, partner],
              problems: ['The relationship "gone" is disabled.'],
              details: details }, ctx: fr },
    { label: 'the forced password change, after a breach',
      path: '/authn/password-change',
      view: { id: 'def', username: 'carol & co',
              notice: 'The password you signed in with has appeared in a ' +
                      'data breach.' },
      ctx: Object.assign({}, en, { error: 'The two passwords are not the ' +
                                          'same.' }) }
  ].concat(stepCases(en, fr));
}

/**
 * The steps after the screen (#572, #573): every second-factor page, the
 * set-up step's choice and its authenticator app's secret (the QR code
 * drawn from the `otpauth:` URI), and every state of the emailed factor's
 * pages, in English and in French, with refusals and notices over them.
 *
 * @param {object} en - the English context
 * @param {object} fr - the French context
 * @returns {object[]} `[{ label, view, ctx, path }]`
 */
function stepCases(en, fr) {
  log.debug("Entering stepCases().");
  const links = { totp: true, webauthn: false, wallet: true, password: true,
                  email: 'link', backup: true };
  const none = { totp: false, webauthn: false, wallet: false,
                 password: false, email: '', backup: false };
  const step = { id: 'mfa1', username: 'dana <d>', passwordless: false };
  const refused = Object.assign({}, en, { error: 'That code is not right.' });
  const others = { totp: true, webauthn: true, password: true,
                   backup: true };
  const email = { kind: 'code', id: 'mfa2', primary: false,
                  username: 'erin', address: 'e***@example.org',
                  minutes: 10, seconds: 4, notice: '', others: others };
  log.debug("Leaving stepCases().");
  return [
    { label: 'the one-time code, every way round, refused',
      path: '/authn/totp', ctx: refused,
      view: Object.assign({ page: 'totp', links: Object.assign({}, links,
        { totp: false, webauthn: true }),
        totp: { digits: 8, period: 60 } }, step) },
    { label: 'the passkey step: an assertion, in French',
      path: '/authn/webauthn', ctx: fr,
      view: Object.assign({ page: 'webauthn', links: links,
        webauthn: { mode: 'get', passwordless: false, choices: [],
          chosen: { id: 'AAAA', name: 'Key <one>' }, problem: '',
          rpId: 'sts.example', widened: true, challenge: 'Q2hhbA',
          attestation: 'direct', algorithms: ['-7', '-257'],
          userVerification: 'required', residentKey: 'preferred',
          attachment: 'any' } }, step) },
    { label: 'the passkey step: a registration, passwordless, RP refused',
      path: '/authn/webauthn', ctx: en,
      view: Object.assign({ page: 'webauthn', links: none,
        webauthn: { mode: 'create', passwordless: true, choices: [],
          chosen: null, problem: 'The RP ID does not fit.',
          rpId: 'sts.example', widened: false, challenge: 'Q2hhbA',
          attestation: 'none', algorithms: ['-7'],
          userVerification: 'preferred', residentKey: 'required',
          attachment: 'platform' } }, step, { passwordless: true }) },
    { label: 'the passkey step: choosing one of several',
      path: '/authn/webauthn', ctx: en,
      view: Object.assign({ page: 'webauthn', links: none,
        webauthn: { mode: 'get', passwordless: false,
          choices: [{ id: 'AAAA', name: 'Phone' },
                    { id: 'BBBB', name: 'Desk & key' }],
          chosen: null, problem: '', rpId: 'sts.example', widened: false,
          challenge: 'Q2hhbA', attestation: 'direct', algorithms: ['-7'],
          userVerification: 'preferred', residentKey: 'discouraged',
          attachment: 'any' } }, step) },
    { label: 'the recovery code, three left',
      path: '/authn/backup-code', ctx: fr,
      view: Object.assign({ page: 'backup-code', links: none,
        backup: { factor: 'passkey', back: 'webauthn', remaining: 3,
                  total: 10, low: true } }, step) },
    { label: 'the password after a wallet',
      path: '/authn/password-factor', ctx: refused,
      view: Object.assign({ page: 'password', amr: ['pop', 'pwd'],
        links: Object.assign({}, none, { totp: true }) }, step) },
    { label: 'the set-up step, offered, every factor',
      path: '/authn/mfa-setup', ctx: en,
      view: Object.assign({ page: 'setup', links: none,
        setup: { state: 'choose', offered: { totp: true, webauthn: true },
                 optional: true, proved: false, totp: null } }, step) },
    { label: 'the set-up step\'s authenticator app, in French',
      path: '/authn/mfa-setup', ctx: fr,
      view: Object.assign({ page: 'setup', links: none,
        setup: { state: 'totp', offered: { totp: true, webauthn: false },
          optional: false, proved: false,
          totp: { uri: 'otpauth://totp/IYA%20STS:dana?secret=JBSWY3DPEHPK3' +
                       'PXP&issuer=IYA%20STS&algorithm=SHA1&digits=6&' +
                       'period=30',
                  secret: 'JBSW Y3DP EHPK 3PXP', algorithm: 'HMAC-SHA-1',
                  digits: 6, period: 30 } } }, step) },
    { label: 'the emailed factor: asked before anything is mailed',
      path: '/authn/email-code', ctx: en,
      view: Object.assign({}, email, { state: 'ask' }) },
    { label: 'the emailed code, sent again, in French',
      path: '/authn/email-code', ctx: Object.assign({}, fr,
                                                    { notice: 'resent' }),
      view: Object.assign({}, email, { state: 'code' }) },
    { label: 'the emailed code as a first factor, refused',
      path: '/authn/email-code', ctx: refused,
      view: Object.assign({}, email, { state: 'code', primary: true,
        address: '', others: { totp: false, webauthn: false,
                               password: false, backup: false } }) },
    { label: 'the mailed link\'s waiting page',
      path: '/authn/email-link', ctx: en,
      view: Object.assign({}, email, { kind: 'link', state: 'wait',
        notice: 'The message could not be sent just now.' }) },
    { label: 'the waiting tab after the link was opened',
      path: '/authn/email-link', ctx: fr, view: { state: 'elsewhere' } },
    { label: 'where the mailed link lands',
      path: '/authn/email-link/open', ctx: en,
      view: { state: 'open', id: 'mfa2', username: 'erin' } },
    { label: 'an emailed factor\'s end page',
      path: '/authn/email-link/open', ctx: en,
      view: { state: 'end', title: 'Open it where you started',
              sentence: 'This link works only in the browser where you ' +
                        'started signing in.' } }
  ];
}

module.exports = [
  { name: 'the admin console',
    pages: 'admin-ui/web_pages.ts', global: 'StsConsole',
    bundle: 'admin-ui/console.bundle.js', runtime: 'admin-ui/console.js',
    heldBy: 'tests/console_web_bundle.js' },
  { name: 'the user portal',
    pages: 'portal/web_portal_pages.ts', global: 'StsPortal',
    bundle: 'portal/portal.bundle.js', runtime: 'portal/portal-spa.js',
    heldBy: 'tests/account_api.js' },
  { name: 'the front door',
    pages: 'home/web_home_pages.ts', global: 'StsHome',
    bundle: 'home/home.bundle.js', runtime: 'home/home-spa.js',
    cases: homeCases },
  { name: 'the sign-in screen',
    pages: 'authn/web_authn_pages.ts', global: 'StsAuthn',
    bundle: 'authn/authn.bundle.js', runtime: 'authn/authn-spa.js',
    cases: authnCases }
];
