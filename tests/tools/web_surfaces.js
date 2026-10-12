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
// password change; the SPNEGO sign-in's three bodies (#575), from the
// state their shell carries; and the wallet's start and wait pages (#574),
// the QR code and a refusal.
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
 * @param {string} ns - the namespace
 * @param {string[]} chain - the catalogs, most preferred first
 * @returns {object} the translator
 */
function translatorFor(root, ns, chain) {
  log.debug("Entering translatorFor(). " + ns + " " + chain.join(','));
  const messages = require(path.join(root, 'common', 'web_messages'));
  const catalogs = {};
  chain.forEach(function (tag) {
    const flat = {};
    const own = JSON.parse(fs.readFileSync(path.join(root, 'common',
      'locales', ns, tag + '.json'), 'utf8'));
    Object.keys(own).forEach(function (key) {
      flat[ns + '.' + key] = own[key];
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
  const en = { t: translatorFor(root, 'authn', ['en']), query: {},
               prefix: '', origin: 'https://sts.example',
               here: '/authn/login?authn=abc', error: '', autofill: true };
  const fr = Object.assign({}, en,
    { t: translatorFor(root, 'authn', ['fr', 'en']) });
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
  const spnegoEn = { t: translatorFor(root, 'spnego', ['en']), query: {},
                     prefix: '', origin: 'https://sts.example',
                     here: '/authn/spnego' };
  const spnegoFr = Object.assign({}, spnegoEn,
    { t: translatorFor(root, 'spnego', ['fr', 'en']) });
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
                                          'same.' }) },
    // THE SPNEGO SIGN-IN'S BODIES (#575), drawn from the state the shell
    // carries: the first 401, the 403 when off, the signed-in page.
    { label: 'the SPNEGO challenge, for a waiting request, in French',
      path: '/authn/spnego',
      view: { door: 'spnego', kind: 'challenge',
              pending: { id: 'abc', protocol: 'OIDC <code>',
                         application: 'urn:app:<one>' },
              spn: 'HTTP/sts.example', realm: 'EXAMPLE.COM',
              hosts: ['sts.example', 'other.example'], checks: null },
      ctx: Object.assign({}, spnegoFr, { here: '/authn/spnego?authn=abc' }) },
    { label: 'the SPNEGO challenge, reached directly',
      path: '/authn/spnego',
      view: { door: 'spnego', kind: 'challenge', pending: null,
              spn: 'HTTP/sts.example', realm: 'EXAMPLE.COM', hosts: [],
              checks: [{ name: 'a check', ok: false, detail: '<x>' }] },
      ctx: spnegoEn },
    { label: 'the SPNEGO door off, with the demonstration',
      path: '/authn/spnego',
      view: { door: 'spnego', kind: 'off',
              setting: 'krb5.spnegoAuthentication',
              demoPath: '/spnego/protected',
              pending: { id: 'abc', protocol: 'SAML 2.0', application: '' } },
      ctx: spnegoEn },
    { label: 'signed in with a Kerberos ticket, two factors',
      path: '/authn/spnego',
      view: { door: 'spnego', kind: 'signed-in', username: 'alice & co',
              principal: 'alice@EXAMPLE.COM', session: 's1',
              subject: 'urn:uuid:1', flags: ['pre-authent'],
              indicators: ['otp'], amr: ['pwd', 'otp'], acr: 'mfa',
              mechanism: 'Kerberos 5', bare: false, mic: true,
              checks: [{ name: 'the ticket decrypts', ok: true,
                         detail: 'yes' }] },
      ctx: spnegoEn },
    { label: 'signed in with a bare ticket claiming nothing, in French',
      path: '/authn/spnego',
      view: { door: 'spnego', kind: 'signed-in', username: 'bob',
              principal: 'bob@PARTNER.COM', session: 's2',
              subject: 'urn:uuid:2', flags: [], indicators: [], amr: [],
              acr: '0', mechanism: 'Kerberos 5', bare: true, mic: false,
              checks: null },
      ctx: spnegoFr }
  ];
}

/**
 * The wallet sign-in's cases (#574): the start page; the wait page with the
 * Digital Credentials API button and a QR code offered, in English and in
 * French, as a second factor and as an enrolment; the QR page itself; and
 * a refusal with the presentation's checks, and one back to the portal.
 *
 * @param {string} root - the repository root
 * @returns {object[]} `[{ label, view, ctx, path }]`
 */
function walletCases(root) {
  log.debug("Entering walletCases().");
  const en = { t: translatorFor(root, 'wallet', ['en']), query: {},
               prefix: '', origin: 'https://sts.example',
               here: '/authn/wallet/wait?authn=abc&state=s1' };
  const fr = Object.assign({}, en,
    { t: translatorFor(root, 'wallet', ['fr', 'en']) });
  const wait = {
    wallet: 'wait', state: 's1', kind: 'wallet', secondFactor: false,
    authn: 'abc', mfa: '', enrol: false,
    dcRequest: { protocol: 'openid4vp-v1-signed',
                 data: { request: 'eyJ.<a&b>.sig' } },
    sameDevice: 'https://wallet.example/present?client_id=x&request_uri=' +
                'https%3A%2F%2Fsts.example%2Foid4vp%2Frequest%2Fs1',
    qr: 'openid4vp://?client_id=x&request_uri=https%3A%2F%2Fsts.example' +
        '%2Foid4vp%2Frequest%2Fs1',
    expiresIn: 297, pollSeconds: 3, protocol: 'OAuth 2.0 <authorize>',
    verifier: 'x509_san_dns:sts.example', back: '/authn/login?authn=abc',
    backKind: 'screen' };
  log.debug("Leaving walletCases().");
  return [
    { label: 'the wallet start page', path: '/authn/wallet',
      view: { wallet: 'start', kind: 'wallet', secondFactor: true },
      ctx: en },
    { label: 'the wallet wait page, every door, in English',
      path: '/authn/wallet/wait', view: wait, ctx: en },
    { label: 'the wallet wait page, every door, in French',
      path: '/authn/wallet/wait', view: wait, ctx: fr },
    { label: 'the wallet wait page, an enrolment with no QR code',
      path: '/authn/wallet/wait', ctx: en,
      view: Object.assign({}, wait, { kind: 'enrol', enrol: true,
        qr: '', dcRequest: null, back: '/portal/self-issued',
        backKind: 'portal' }) },
    { label: 'the wallet QR page', path: '/authn/wallet/wait', view: wait,
      ctx: Object.assign({}, en, { query: { qr: '1' } }) },
    { label: 'a wallet refusal with the presentation\'s checks',
      path: '/authn/wallet/wait', ctx: en,
      view: { wallet: 'refused', heading: 'Nobody was signed in',
              retry: '/authn/wallet?authn=abc',
              verdict: 'presentation.verified',
              checks: [{ ok: true, name: 'Signature', detail: 'ES256 <ok>' },
                       { ok: false, name: 'Register', detail: 'not issued' }],
              back: '/authn/login?authn=abc', backKind: 'screen' } },
    { label: 'a wallet refusal with nothing to go back to',
      path: '/authn/wallet', ctx: fr,
      view: { wallet: 'refused', heading: 'Nothing is waiting for this ' +
              'sign-in', retry: '', verdict: '', checks: [], back: '',
              backKind: 'none' } }
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
    cases: function (root) {
      log.debug("Entering the sign-in screen's cases.");
      log.debug("Leaving the sign-in screen's cases.");
      return authnCases(root).concat(walletCases(root));
    } }
];
