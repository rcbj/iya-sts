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
// the QR code and a refusal. The OAuth consent screen (#576) is a page of
// the same surface, and its cases are drawn from views alone too.
//
// GNAP's interaction pages (#578) draw every page from a view alone: the
// user code page, the approval page in the states its view can name, what
// is said after a decision, and a refusal.
// The sign-out (#577) draws its one page from views alone: the inventory,
// the result drawn in place, and the two refusals' pages.
// The federation pages (#580) draw every page from a view alone, as each
// shell carries it: the landing page, the linking step's outcome, a
// refusal of the login or linking endpoint, and the two pages not there.
// The OpenID4VC demonstration (#582) draws all five of its pages from views
// alone, the QR codes among them.
// The description pages (#584) draw each of the six families' pages from a
// view alone, in the states that change what is drawn.
// The TLS diagnostic pages and the SPNEGO demonstration pages (#583) draw
// every page from a view alone, as each shell carries it, and the TLS
// page's acts' outcomes from what the acts answered.
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

/**
 * The OAuth consent screen's cases (#576): every part of the page — the
 * application by name with its client_id, a scope with a permission and
 * one without, an RFC 9396 detail member by member, every kind of limit as
 * a control, the fold of what was already agreed (by the person, at a
 * time, and for everybody) and the request's own parameters — in English
 * and in French; a refused answer over it; and the plainest page there is.
 *
 * @param {string} root - the repository root
 * @returns {object[]} `[{ label, view, ctx, path }]`
 */
function consentCases(root) {
  log.debug("Entering consentCases().");
  const en = { t: translatorFor(root, 'consent', ['en']), query: {},
               prefix: '', origin: 'https://sts.example',
               here: '/oauth2/consent?consent=c1', error: '' };
  const fr = Object.assign({}, en,
    { t: translatorFor(root, 'consent', ['fr', 'en']) });
  const limits = { amount: '100.00', currency: 'EUR', count: 5,
                   receiver: ['DE89 <one>', 'FR76 & two'],
                   interval: 'R5/2026-10-01T00:00:00Z/P1M',
                   window: { notBefore: '2026-10-01', notAfter: '2026-12-31' },
                   vendor: { x: 1 } };
  const rows = [
    { member: 'amount', label: 'At most', value: '100.00 EUR' },
    { member: 'currency', label: 'In', value: 'EUR' },
    { member: 'count', label: 'At most', value: '5 operations' },
    { member: 'receiver', label: 'Only to', value: 'DE89 <one>, FR76 & two' },
    { member: 'interval', label: 'Resetting every',
      value: 'R5/2026-10-01T00:00:00Z/P1M' },
    { member: 'window', label: 'Only',
      value: 'from 2026-10-01 until 2026-12-31' },
    { member: 'vendor', label: 'vendor', value: '{"x":1}' }];
  const everything = { consent: true, username: 'alice <a>',
    base: 'https://sts.example',
    client: { id: 'demo "client"', name: 'Demo <App> & co' },
    scopes: [{ scope: 'read', permission: null },
             { scope: 'https://api.example/write', permission: {
               description: 'Write <things>', name: 'write',
               identifier: 'https://api.example/write',
               baseUri: 'https://api.example' } },
             { scope: 'https://api.example/admin', permission: {
               description: '', name: 'admin & more',
               identifier: 'https://api.example/admin',
               baseUri: 'https://api.example' } }],
    authorizationDetails: [{ type: 'payment_initiation',
      description: 'Initiate a <payment>', resource: 'Bank & co',
      audience: 'https://pay.example',
      members: [{ name: 'instructedAmount', value: '{"amount":"100.00"}' },
                { name: 'creditorName', value: 'Merchant <A>' }] },
      { type: 'account_information', description: '',
        resource: 'r96-bank', audience: 'https://acct.example',
        members: [] }],
    already: [{ scope: 'openid', global: false, at: '' },
              { scope: 'email', global: false,
                at: '2026-10-12T09:00:00Z' },
              { scope: 'profile', global: true, at: '' }],
    limits: [{ r: 0, type: 'payment_initiation', limits: limits,
               rows: rows }],
    attribute: 'oauthConsent', protocol: 'OAuth 2.0 / OIDC',
    details: [{ label: 'client_id', value: 'demo "client"', note: '' },
              { label: 'scope', value: 'openid read', note: '' },
              { label: 'request', value: 'signed request object (ES256)',
                note: 'verified <ok>' }] };
  const plain = { consent: true, username: 'bob', base: 'https://sts.example',
    client: { id: 'plain', name: 'plain' },
    scopes: [{ scope: 'openid', permission: null }],
    authorizationDetails: [], already: [], limits: [],
    attribute: 'oauthConsent', protocol: 'OAuth 2.0 / OIDC', details: [] };
  log.debug("Leaving consentCases().");
  return [
    { label: 'the consent screen, every part, in English',
      path: '/oauth2/consent', view: everything, ctx: en },
    { label: 'the consent screen, every part, in French',
      path: '/oauth2/consent', view: everything, ctx: fr },
    { label: 'the consent screen with a raised limit refused',
      path: '/oauth2/consent', view: everything,
      ctx: Object.assign({}, en, { error: 'The limits of ' +
        '"payment_initiation" may only be lowered here: amount.' }) },
    { label: 'the plainest consent screen',
      path: '/oauth2/consent', view: plain, ctx: fr }
  ];
}

/**
 * GNAP's interaction pages' cases (#578): the user code page; the approval
 * page with everything it can draw — a registered data: logo, a name and a
 * home page the client declared, a self-declared class, two labelled
 * tokens one of them a bearer, a registered and an unregistered reference,
 * a right with every dimension and an identifier, every kind of limit
 * as a control, what the policy narrowed, the subject asked for, a redirect
 * finish — in English and in French; a bare approval with a push finish and
 * none; each thing said after a decision; the request sent to its owner;
 * and a refusal carrying markup.
 *
 * @param {string} root - the repository root
 * @returns {object[]} `[{ label, view, ctx, path }]`
 */
function gnapCases(root) {
  log.debug("Entering gnapCases().");
  const en = { t: translatorFor(root, 'gnap', ['en']), query: {},
               prefix: '', origin: 'https://sts.example',
               here: '/gnap/approve/h1' };
  const fr = Object.assign({}, en,
    { t: translatorFor(root, 'gnap', ['fr', 'en']) });
  const approve = {
    kind: 'approve', id: 'h1<x>', username: 'alice & "co"',
    client: { identifier: 'gnap-client-<1>', name: 'Acme <App>',
              nameDeclared: true, uri: 'https://acme.example/?a=1&b="2"',
              uriDeclared: true,
              logo: 'data:image/png;base64,iVBORw0KGgo=',
              proof: 'httpsig', classId: 'urn:class:<x>',
              classIdDeclared: true },
    tokens: [
      { label: 'read <only>', number: 1, bearer: true, heading: true,
        rights: [
          { field: 't0r0', token: 0, index: 0, limits: null, limitRows: [],
            right: { reference: 'ref-<1>',
                     registered: { rs: 'rs.example', access: ['a', 'b&c'] } } },
          { field: 't0r1', token: 0, index: 1, limits: null, limitRows: [],
            right: { reference: 'ref-2', registered: null } }] },
      { label: '', number: 2, bearer: false, heading: true,
        rights: [
          { field: 't1r0', token: 1, index: 0,
            limits: { amount: '50', currency: 'EUR<', count: 3,
                      receiver: ['acct:<a>', 'acct:b'],
                      interval: 'R/2026-10-01T00:00:00Z/P1M',
                      window: { notBefore: '2026-10-01T00:00:00Z' },
                      region: 'eu' },
            limitRows: [
              { member: 'amount', label: 'at most', value: '50 EUR<' },
              { member: 'currency', label: 'currency', value: 'EUR<' },
              { member: 'count', label: 'at most', value: '3' },
              { member: 'receiver', label: 'only to', value: 'acct:<a>' },
              { member: 'interval', label: 'resetting',
                value: 'R/2026-10-01T00:00:00Z/P1M' },
              { member: 'window', label: 'between', value: '…' },
              { member: 'region', label: 'region', value: 'eu' }],
            right: { type: 'payment<x>', identifier: 'acct&1',
                     dimensions: [
                       { name: 'actions', values: ['read', 'pay'] },
                       { name: 'locations', values: ['https://x/<y>'] }] } },
          { field: 't1r1', token: 1, index: 1, limits: null, limitRows: [],
            right: { type: 'photo', identifier: '', dimensions: [] } }] }],
    narrowed: [
      { type: 'payment<x>', changes: [
        { how: 'removed', dimension: 'actions', values: ['refund', 'void'] },
        { how: 'limited', dimension: 'locations',
          values: ['https://x/<y>'] }] },
      { type: 'other', changes: [] }],
    subject: { ids: ['email', 'iss_sub'], assertions: [] },
    finish: { method: 'redirect', uri: 'https://client.example/cb?x=<1>' },
    grantEndpoint: 'https://sts.example/gnap' };
  const bare = Object.assign({}, approve, {
    client: Object.assign({}, approve.client, { nameDeclared: false,
      uri: '', uriDeclared: false, logo: '', classId: '' }),
    tokens: [{ label: '', number: 1, bearer: false, heading: false,
               rights: [] }],
    narrowed: [], subject: null, finish: null });
  const pushed = Object.assign({}, bare, {
    finish: { method: 'push', uri: 'https://client.example/push' } });
  const done = { kind: 'done', approved: true, pushed: true,
                 name: 'Acme <App> & co' };
  log.debug("Leaving gnapCases().");
  return [
    { label: 'the user code page, in English', path: '/gnap/code',
      view: { kind: 'code' }, ctx: Object.assign({}, en,
        { here: '/gnap/code' }) },
    { label: 'the user code page, in French', path: '/gnap/code',
      view: { kind: 'code' }, ctx: Object.assign({}, fr,
        { here: '/gnap/code' }) },
    { label: 'the approval page, everything drawn, in English',
      path: '/gnap/approve/h1', view: approve, ctx: en },
    { label: 'the approval page, everything drawn, in French',
      path: '/gnap/approve/h1', view: approve, ctx: fr },
    { label: 'the approval page, nothing asked and no finish',
      path: '/gnap/approve/h1', view: bare, ctx: en },
    { label: 'the approval page, a push finish', path: '/gnap/approve/h1',
      view: pushed, ctx: en },
    { label: 'approved, the client told', path: '/gnap/approve/h1',
      view: done, ctx: en },
    { label: 'approved, the client not told, in French',
      path: '/gnap/approve/h1', ctx: fr,
      view: Object.assign({}, done, { pushed: false }) },
    { label: 'not approved, return to the client',
      path: '/gnap/approve/h1', ctx: en,
      view: Object.assign({}, done, { approved: false, pushed: null }) },
    { label: 'sent to the person it names', path: '/gnap/approve/h1',
      view: { kind: 'sent' }, ctx: fr },
    { label: 'a refused start link', path: '/gnap/interact/h2', ctx: en,
      view: { kind: 'problem', heading: 'This link is <not> active',
              detail: 'It may have "expired" & gone.' } }
  ];
}

/**
 * The sign-out's cases (#577): the inventory with every kind of family row —
 * terminable, not, a failure, nothing live, a capped list — in English and
 * in French, under each of the three naming notes; the result drawn in
 * place, with something still live and with nothing left; and the two
 * refusals' pages.
 *
 * @param {string} root - the repository root
 * @returns {object[]} `[{ label, view, ctx, path }]`
 */
function signoutCases(root) {
  log.debug("Entering signoutCases().");
  const en = { t: translatorFor(root, 'logout', ['en']), query: {},
               prefix: '', origin: 'https://sts.example', here: '/logout' };
  const fr = Object.assign({}, en,
    { t: translatorFor(root, 'logout', ['fr', 'en']) });
  const families = [
    { id: 'session', label: 'Browser sign-on <sessions>', protocol: 'HTTP',
      spec: 'this service & its cookie', what: 'One sentence about it.',
      terminable: true, held: 2, notListed: 0, failure: '',
      rows: [{ id: 'session:abc"1', label: 'sid <abc>', detail: 'via "x"',
               kind: 'Browser session', startedAt: 1760227200000,
               expiresAt: 0, terminable: true, why: '' },
             { id: 'session:def', label: 'sid def', detail: '',
               kind: 'Browser session', startedAt: 0,
               expiresAt: 1760230800000, terminable: false,
               why: 'it is <held> elsewhere' }] },
    { id: 'issued', label: 'Already issued', protocol: 'SAML & co',
      spec: 'none', what: 'A long explanation of why nothing that was ' +
        'already issued can be recalled by anybody, which runs to well ' +
        'over one line so that the console\'s fold collapses it into a ' +
        'summary and a body.',
      terminable: false, held: 0, notListed: 0, failure: '', rows: [] },
    { id: 'ldap', label: 'Directory connections', protocol: 'LDAP',
      spec: 'RFC 4511', what: 'Bound connections.', terminable: true,
      held: 0, notListed: 0, failure: 'the <directory> is down', rows: [] },
    { id: 'token', label: 'Tokens', protocol: 'OAuth 2.0', spec: 'RFC 7009',
      what: 'Tokens.', terminable: true, held: 300, notListed: 299,
      failure: '',
      rows: [{ id: 'token:t1', label: 'jti t1', detail: 'access token',
               kind: 'Access token', startedAt: 1760227200000,
               expiresAt: 1760230800000, terminable: true, why: '' }] }
  ];
  const inventory = function (naming, username) {
    log.debug("Entering inventory().");
    log.debug("Leaving inventory().");
    return { state: 'inventory', username: username, key: username,
             named: false, naming: naming, total: 302, listed: 3,
             notListed: 299, maxRows: 3, families: families };
  };
  const result = { state: 'result', scope: 'global', key: 'alice & co',
    message: 'Global logout for alice: 2 item(s) ended, 1 that could not ' +
             'be.',
    terminated: [{ id: 'session:abc', label: 'sid <abc>',
                   message: 'ended "now"' },
                 { id: 'code:1', label: '', message: 'dropped' }],
    skipped: [{ id: 'issued:x', label: 'assertion x',
                message: 'cannot be <recalled>' }],
    remaining: 1 };
  log.debug("Leaving signoutCases().");
  return [
    { label: 'the inventory, naming open, in English', path: '/logout',
      view: inventory('open', 'alice <a> & "co"'), ctx: en },
    { label: 'the inventory, naming off, in French', path: '/logout',
      view: inventory('off', 'bob'), ctx: fr },
    { label: 'the inventory in product mode, nothing held', path: '/logout',
      ctx: en, view: { state: 'inventory', username: 'carol', key: 'carol',
        naming: 'product', total: 0, families: [families[1]] } },
    { label: 'a global result with something still live', path: '/logout',
      view: result, ctx: en },
    { label: 'a selective result with nothing left, in French',
      path: '/logout', ctx: fr,
      view: Object.assign({}, result, { scope: 'selected', skipped: [],
                                        terminated: [], remaining: 0 }) },
    { label: 'a name that may not be used, product', path: '/logout',
      ctx: en, view: { state: 'refused', verifiesCredentials: true } },
    { label: 'a name that may not be used, development', path: '/logout',
      ctx: fr, view: { state: 'refused', verifiesCredentials: false } },
    { label: 'nobody to sign out', path: '/logout', ctx: en,
      view: { state: 'nobody' } }
  ];
}

/**
 * The federation pages' cases (#580): the landing page with relationships
 * in every state and with none, in English and in French; the linking
 * step's outcome with attributes mapped and thrown away, and with none; a
 * refusal of the login and linking endpoints with and without a
 * relationship; the two pages that are not there; a view the page does not
 * know. Every value a partner or an administrator chose carries markup, so
 * the escaping is held too.
 *
 * @param {string} root - the repository root
 * @returns {object[]} `[{ label, view, ctx, path }]`
 */
function federationCases(root) {
  log.debug("Entering federationCases().");
  const ns = ['federationPages', 'handoff'];
  const en = { t: translatorFor(root, ns, ['en']), query: {}, prefix: '',
               origin: 'https://sts.example', here: '/federation' };
  const fr = Object.assign({}, en, { t: translatorFor(root, ns,
                                                      ['fr', 'en']) });
  const zh = Object.assign({}, en, { t: translatorFor(root, ns,
                                                      ['zh-Hans', 'en']) });
  const paths = { login: '/federation/login', acs: '/federation/acs',
                  metadata: '/federation/metadata', slo: '/federation/slo',
                  backchannel: '/federation/backchannel-logout',
                  frontchannel: '/federation/frontchannel-logout' };
  const index = { kind: 'index', base: 'https://sts.example/realm/a&b',
    loginButtons: true, paths: paths,
    consuming: [
      { id: 'idp<1>', protocol: 'SAML 2.0', peer: 'https://idp.example/"x"',
        state: 'ready', missing: [], metadata: true },
      { id: 'half', protocol: 'OpenID Connect', peer: '',
        state: 'incomplete', missing: ['fedClientId', 'fedSsoUrl'],
        metadata: false },
      { id: 'off one', protocol: 'WS-Federation 1.2', peer: 'urn:x',
        state: 'disabled', missing: ['fedSigningCertificate'],
        metadata: false }],
    asserting: [
      { id: 'sp1', protocol: 'SAML 1.1', application: 'urn:sp:<1>',
        release: ['mail', 'cn'] },
      { id: 'sp2', protocol: 'OpenID Connect', application: '',
        release: [] }] };
  const signedIn = { kind: 'signedIn', relationship: 'idp<1>',
    partner: 'The <Partner>', peer: 'https://idp.example',
    protocol: 'SAML 2.0', subject: 'urn:uuid:"abc"',
    username: 'alice&co', usernamePrefixed: true,
    usernameFrom: 'NameID <persistent>', session: 's<1>',
    autocreate: true, updates: false,
    mapped: [{ incoming: 'email', ldap: 'mail',
               values: ['a@example', '<b>@example'], where: 'layer 2' }],
    unmapped: [{ incoming: 'shoe<size>', values: ['9', '10'] }] };
  log.debug("Leaving federationCases().");
  return [
    { label: 'the landing page, relationships in every state, in English',
      path: '/federation', view: index, ctx: en },
    { label: 'the landing page, relationships in every state, in French',
      path: '/federation', view: index, ctx: fr },
    { label: 'the landing page with nothing configured and no buttons',
      path: '/federation', ctx: en,
      view: Object.assign({}, index, { consuming: [], asserting: [],
                                       loginButtons: false }) },
    { label: 'the linking step signed in, attributes mapped and thrown away',
      path: '/federation/link/fed-abc', view: signedIn, ctx: en },
    { label: 'the linking step signed in, no attributes, in Chinese',
      path: '/federation/link/fed-abc', ctx: zh,
      view: Object.assign({}, signedIn, { mapped: [], unmapped: [],
        peer: '', subject: '', usernamePrefixed: false, autocreate: false,
        updates: true }) },
    { label: 'a linking step refused, recorded on the relationship',
      path: '/federation/link/fed-abc', ctx: fr,
      view: { kind: 'refused', what: 'The account was not linked',
              why: 'This linking step was started in a <different> ' +
                   'browser & "so" on.', relationship: 'idp<1>' } },
    { label: 'a sign-in the login endpoint would not start, no relationship',
      path: '/federation/login/x', ctx: en,
      view: { kind: 'refused', what: 'That relationship goes the other way',
              why: '"x" is an identity-provider-side relationship.',
              relationship: '' } },
    { label: 'federation turned off', path: '/federation/login/x', ctx: en,
      view: { kind: 'off' } },
    { label: 'no such relationship', path: '/federation/login/x', ctx: fr,
      view: { kind: 'noRelationship', id: '<script>alert(1)</script>' } },
    { label: 'a view the page does not know', path: '/federation',
      ctx: en, view: { kind: 'other<1>' } }
  ];
}

/**
 * The description pages' cases (#584): each of the six families' pages
 * drawn from a view alone — the view each shell carries, its document
 * written here with the values that make escaping matter — in English and
 * in another language, and in the states that change what is drawn: the
 * demonstrations served (development) and not (product, #585), a family
 * turned off, XACML's gate enforced and not, SCIM's credential verified
 * and not, SPIFFE's authority not ready and its socket unattested.
 *
 * @param {string} root - the repository root
 * @returns {object[]} `[{ label, view, ctx, path }]`
 */
function descriptionCases(root) {
  log.debug("Entering descriptionCases().");
  const ctxFor = function (ns, chain, here) {
    log.debug("Entering ctxFor(). " + ns);
    log.debug("Leaving ctxFor().");
    return { t: translatorFor(root, ns, chain), query: {}, prefix: '',
             origin: 'https://sts.example', here: here };
  };
  const saml2 = { kind: 'saml2', idpEntityId: 'https://sts.example/"a"&b',
    base: 'https://sts.example/realm/<r>',
    paths: { sso: '/saml2/sso', ars: '/saml2/ars', slo: '/saml2/slo',
             unsolicited: '/saml2/unsolicited', aa: '/saml2/aa',
             metadata: '/saml2/metadata' },
    generic: { sso: 'https://sts.example/saml2/sso?x=<1>',
               slo: 'https://sts.example/saml2/slo',
               ars: 'https://sts.example/saml2/ars' } };
  const saml11 = { kind: 'saml11',
    paths: { sso: '/saml11/sso', responder: '/saml11/responder',
             metadata: '/saml11/metadata' },
    metadata: 'https://sts.example/saml11/metadata?a=1&b="2"' };
  const xacmlDoc = { enabled: true,
    repository: { policies: 3, enabledPolicies: 2, root: 'root<"set">' },
    pep: { embeddedAt: 'https://sts.example/xacml/protected',
           bias: 'deny-biased' },
    remotePeps: { enabled: true, registered: 2, syncToken: 'tok&<1>' },
    endpoints: [
      { method: 'GET', path: '/xacml', what: 'this document',
        requires: 'XACML_USER' },
      { method: 'POST', path: '/xacml/pip',
        what: 'the PIP: <PIPRequest> in', requires: 'REMOTE_PEPS' }],
    access: { enforced: true, xacmlUserGroup: 'cn=xacml-users,"x"',
              remotePepGroup: '' },
    notYetHere: ['AttributeSelector & <XPath>'] };
  const ssfDoc = { enabled: false, issuer: 'https://sts.example/"i"',
    metadataUrl: 'https://sts.example/.well-known/ssf-configuration',
    signingAlgorithm: 'ML-DSA-65',
    endpoints: [{ method: 'POST', path: '/ssf/stream',
                  what: 'Create a stream <with> "quotes"' }],
    eventTypes: [
      { name: 'Verification', uri: 'https://schemas.openid.net/x&y',
        offered: true, what: 'the pipe' },
      { name: 'Stream updated', uri: 'urn:x', offered: false, what: '' }],
    subjectFormats: [{ format: 'email', members: ['email'],
                       what: 'an <address>' }],
    complexSubjectMembers: [{ name: 'user' }, { name: 'session<1>' }],
    criticalSubjectMembers: [],
    authentication: { required: true, note: 'Bearer & <mTLS>',
      schemes: [{ name: 'OAuth', spec_urn: 'urn:ietf:rfc:6749',
                  what: 'a token' }] },
    streams: [{ stream_id: 's<1>', status: 'enabled', delivery: 'urn:push',
                subjects: 2, queued: 0,
                counters: { delivered: 5, failed: 1 } }],
    doesNotDo: ['It sends nothing when TIGHTENED <x>'],
    reachableNegatives: [{ what: 'POST junk', answer: '400 <bad>' }] };
  const scimDoc = { enabled: true, baseUrl: 'https://sts.example/scim/v2',
    store: { what: 'The directory & <more>', users: 'ou=people,dc=x',
             userCount: 4, groups: 'ou=groups,dc=x', groupCount: 1,
             entryCount: 9, maxEntries: 5000 },
    identifiers: { why: 'Because <DN>', example: 'uid=a,ou=people' },
    authentication: { required: true, realm: 'iya "sts"',
      discoveryOpen: true, digestAlgorithms: ['SHA-256', 'MD5'],
      hobaRegistration: '/.well-known/hoba/register',
      scopes: { read: 'scim:read', write: 'scim:write' },
      policy: ['Read needs scim:read <or> Basic'],
      schemes: [
        { name: 'OAuth Bearer', primary: true, type: 'oauthbearertoken',
          canonical: true, enabled: true, setting: 'scim.authBearer',
          scoped: true, spec: 'RFC 6750', description: 'a token & <x>' },
        { name: 'HOBA', primary: false, type: 'hoba', canonical: false,
          enabled: false, setting: 'scim.authHoba', scoped: false,
          spec: 'RFC 7486', description: '' }] },
    endpoints: [{ method: 'GET', path: '/scim/v2/Users', what: 'list <all>' }],
    doesNotDo: ['No ETags'],
    reachableNegatives: [{ what: 'a bad filter', answer: '400 invalidFilter' }],
    mapping: { user: [{ scim: 'userName', ldap: 'uid', kind: 'direct',
                        readOnly: true }] } };
  const spiffeDoc = { enabled: true, trustDomainId: 'spiffe://example.org',
    workloadAttestation: { nativeModule: false, problem: 'not <built>',
                           tcp: { state: 'served (development)' } },
    authentication: { enforced: false, what: 'Who <may>',
      bootstrapping: 'b', identityNote: 'i', credentialStatusNote: '',
      adminIds: [], entities: [{ id: 'local', what: 'the socket' }],
      policy: [{ method: 'ListEntries', allow: ['admin', 'local'] }] },
    bundle: { url: 'https://sts.example/spiffe/bundle?x=1&y=2', sequence: 7,
              refreshHint: 300, schemeNote: 'over <HTTPS>' },
    authorities: { source: 'pki', note: 'from the PKI',
      x509: [{ id: 'x<1>', keyType: 'EC P-256', active: true,
               notAfter: '2027-01-01' },
             { id: 'x2', keyType: 'RSA', active: false,
               notAfter: '2026-01-01' }],
      jwt: [{ kid: 'k&1', keyType: 'EC', alg: 'ES256', active: true }],
      chainSubjects: ['CN=Issuing', 'CN=Intermediate<2>'],
      trustAnchors: [{ id: 'root', subject: 'CN=Root', notAfter: '2030' }] },
    workloadApi: { listeners: [{ realm: '', address: '/tmp/x.sock',
      listening: true, tls: false, authentication: 'none' },
      { realm: 'a', address: '127.0.0.1:8092', listening: false,
        error: 'EADDRINUSE <x>', tls: true, authentication: 'mTLS' }],
      securityHeader: 'workload.spiffe.io', securityHeaderRequired: true,
      methods: [{ name: 'FetchX509SVID', streaming: true, implemented: true,
                  what: 'SVIDs' },
                { name: 'ValidateJWTSVID', streaming: false,
                  implemented: false, what: '' }] },
    serverApi: { listeners: [], services: [{ name: 'Entry', what: 'entries',
      methods: [{ name: 'ListEntries', implemented: true, what: 'list' }] }] },
    brokerApi: { listeners: [], securityHeader: 'broker.spiffe.io',
      brokers: [{ id: 'spiffe://example.org/broker', types: ['pid'] },
                { id: 'x', problem: 'not <a> SPIFFE ID' }] },
    notChecked: ['no revocation'], refused: ['a <bad> CSR'],
    registry: { entries: 3, agents: 1, note: 'in the directory' },
    links: { 'the console': '/admin/spiffe', 'bundle': '/spiffe/bundle' } };
  const tag = function (ns, chain) {
    log.debug("Entering tag(). " + ns);
    log.debug("Leaving tag().");
    return ctxFor(ns, chain, '/');
  };
  log.debug("Leaving descriptionCases().");
  return [
    { label: 'SAML 2.0, in English', path: '/saml2',
      view: saml2, ctx: tag('describeSaml2', ['en']) },
    { label: 'SAML 2.0, in French', path: '/saml2',
      view: saml2, ctx: tag('describeSaml2', ['fr', 'en']) },
    { label: 'SAML 1.1, in English', path: '/saml11',
      view: saml11, ctx: tag('describeSaml11', ['en']) },
    { label: 'SAML 1.1, in Simplified Chinese', path: '/saml11',
      view: saml11, ctx: tag('describeSaml11', ['zh-Hans', 'en']) },
    { label: 'XACML, enforced, development, in English', path: '/xacml',
      ctx: tag('describeXacml', ['en']),
      view: { kind: 'xacml', document: xacmlDoc,
              trustAnchorDoor: 'POST /admin-api/tls/trust "x"' } },
    { label: 'XACML, off, unenforced, no root, product, in Swedish',
      path: '/xacml', ctx: tag('describeXacml', ['sv', 'en']),
      view: { kind: 'xacml', trustAnchorDoor: 'door',
        document: Object.assign({}, xacmlDoc, { enabled: false, pep: null,
          repository: { policies: 0, enabledPolicies: 0, root: null },
          remotePeps: { enabled: false },
          access: { enforced: false } }) } },
    { label: 'Shared Signals, off, in English', path: '/ssf',
      ctx: tag('describeSsf', ['en']),
      view: { kind: 'ssf', document: ssfDoc,
              deliveryNames: { 'urn:push': 'push <RFC 8935>' } } },
    { label: 'Shared Signals, on, no streams, in Spanish', path: '/ssf',
      ctx: tag('describeSsf', ['es', 'en']),
      view: { kind: 'ssf', deliveryNames: {},
        document: Object.assign({}, ssfDoc, { enabled: true, streams: [],
          criticalSubjectMembers: ['user', 'session'],
          authentication: Object.assign({}, ssfDoc.authentication,
                                        { required: false }) }) } },
    { label: 'SCIM, product (verified), in English', path: '/scim',
      ctx: tag('describeScim', ['en']),
      view: { kind: 'scim', document: scimDoc, verifiesCredentials: true,
              base: '/scim/v2' } },
    { label: 'SCIM, development, off, discovery closed, in Filipino',
      path: '/scim', ctx: tag('describeScim', ['fil', 'en']),
      view: { kind: 'scim', verifiesCredentials: false, base: '/scim/v2',
        document: Object.assign({}, scimDoc, { enabled: false,
          authentication: Object.assign({}, scimDoc.authentication,
            { required: false, discoveryOpen: false }) }) } },
    { label: 'SPIFFE, unattested, authority failed, in English',
      path: '/spiffe', ctx: tag('describeSpiffe', ['en']),
      view: { kind: 'spiffe', document: spiffeDoc,
              authority: { ready: false, error: 'no <key>' },
              https: false } },
    { label: 'SPIFFE, attested, enforced, administrators, in Traditional ' +
      'Chinese', path: '/spiffe', ctx: tag('describeSpiffe',
                                           ['zh-Hant', 'en']),
      view: { kind: 'spiffe', authority: { ready: true, error: '' },
        https: true,
        document: Object.assign({}, spiffeDoc, { enabled: false,
          workloadAttestation: { nativeModule: true,
                                 tcp: { state: 'not served' } },
          authentication: Object.assign({}, spiffeDoc.authentication,
            { enforced: true, adminIds: ['spiffe://x/admin', 'a<b>'] }),
          authorities: Object.assign({}, spiffeDoc.authorities,
            { source: 'self', chainSubjects: [] }),
          brokerApi: Object.assign({}, spiffeDoc.brokerApi,
                                   { brokers: [] }) }) } },
    { label: 'SPIFFE, authority still being generated', path: '/spiffe',
      ctx: tag('describeSpiffe', ['en']),
      view: { kind: 'spiffe', document: spiffeDoc,
              authority: { ready: false, error: '' }, https: true } }
  ];
}

/**
 * The SPNEGO demonstration pages' cases (#583): the advertisement with the
 * sign-in on and off, in English and in Swedish; the body of every kind of
 * answer `/spnego/protected` gives — the bare challenge, a wrong scheme, an
 * empty token, an undecodable one, no common mechanism (with and without
 * `?mech=none`), a pessimistic token, a non-Kerberos mechanism, a refused
 * ticket, both wordings of a bad mechListMIC, a required MIC,
 * `request-mic`, an unmatched continuation, a continuation without the MIC,
 * a code no page knows, and the protected content (negotiated or bare,
 * mutual or `?mutual=off`).
 *
 * @param {string} root - the repository root
 * @returns {object[]} `[{ label, view, ctx, path }]`
 */
function spnegoCases(root) {
  log.debug("Entering spnegoCases().");
  const ns = ['spnegoPages'];
  const en = { t: translatorFor(root, ns, ['en']), query: {}, prefix: '',
               origin: 'https://sts.example', here: '/spnego' };
  const sv = Object.assign({}, en, { t: translatorFor(root, ns,
                                                      ['sv', 'en']) });
  const es = Object.assign({}, en, { t: translatorFor(root, ns,
                                                      ['es', 'en']) });
  const advert = { kind: 'advert', realm: 'EXAMPLE.COM<1>',
    protectedResource: '/spnego/protected', signInResource: '/authn/spnego',
    signInEnabled: true,
    servicePrincipalName: 'HTTP/sts.example@EXAMPLE.COM',
    mechanisms: [{ oid: '1.2.840.113554.1.2.2', name: 'Kerberos <5>' },
                 { oid: '1.2.840.48018.1.2.2', name: 'Kerberos (MS)' }],
    scheme: 'Negotiate' };
  const checks = [{ name: 'the ticket <decrypts>', ok: true,
                    detail: 'under the service key' },
                  { name: 'the authenticator', ok: false,
                    detail: 'skew & "late"' }];
  const verdict = function (extra) {
    return Object.assign({ kind: 'verdict', ok: false, code: '',
      spn: 'HTTP/sts.example', reason: 'Because <of> & this.', scheme: '',
      client: '', selected: '', selectedName: '', offered: [],
      offeredNames: [], supported: [], continuation: false,
      rawKerberos: false, micVerified: false, requirementReason: '',
      mutual: false, mutualOff: false, micNote: '', checks: null }, extra);
  };
  const accepted = verdict({ ok: true, code: 'accepted',
    client: 'alice@EXAMPLE.COM<1>', selected: '1.2.840.113554.1.2.2',
    selectedName: 'Kerberos 5', micVerified: true, mutual: true,
    checks: checks });
  log.debug("Leaving spnegoCases().");
  return [
    { label: 'the advertisement, the sign-in on, in English',
      path: '/spnego', ctx: en, view: advert },
    { label: 'the advertisement, the sign-in off, in Swedish',
      path: '/spnego', ctx: sv,
      view: Object.assign({}, advert, { signInEnabled: false }) },
    { label: 'the bare challenge', path: '/spnego/protected', ctx: en,
      view: verdict({ code: 'no-authorization' }) },
    { label: 'a wrong scheme, in Spanish', path: '/spnego/protected',
      ctx: es, view: verdict({ code: 'wrong-scheme', scheme: 'Basic<x>' }) },
    { label: 'an empty token', path: '/spnego/protected', ctx: en,
      view: verdict({ code: 'empty-token' }) },
    { label: 'an undecodable token', path: '/spnego/protected', ctx: sv,
      view: verdict({ code: 'undecodable', checks: [] }) },
    { label: 'no common mechanism', path: '/spnego/protected', ctx: en,
      view: verdict({ code: 'no-common-mechanism',
        offered: ['1.3.6.1.5.5.2<x>', '1.2.3'],
        offeredNames: ['SPNEGO', ''],
        supported: ['1.2.840.113554.1.2.2'] }) },
    { label: 'no common mechanism, ?mech=none, in Spanish',
      path: '/spnego/protected', ctx: es,
      view: verdict({ code: 'no-common-mechanism', offered: ['1.2.3'],
                      offeredNames: ['x'], supported: [] }) },
    { label: 'a pessimistic token', path: '/spnego/protected', ctx: en,
      view: verdict({ code: 'no-mech-token',
                      selected: '1.2.840.113554.1.2.2',
                      selectedName: 'Kerberos <5>' }) },
    { label: 'a non-Kerberos mechanism', path: '/spnego/protected', ctx: en,
      view: verdict({ code: 'non-kerberos-mechanism',
                      selected: '1.3.6.1.4.1.311.2.2.10<x>' }) },
    { label: 'a refused ticket, with the checks', path: '/spnego/protected',
      ctx: sv, view: verdict({ code: 'ticket-refused', checks: checks }) },
    { label: 'a bad mechListMIC on the first token',
      path: '/spnego/protected', ctx: en,
      view: verdict({ code: 'bad-mech-list-mic' }) },
    { label: 'a bad mechListMIC on the continuation, in Spanish',
      path: '/spnego/protected', ctx: es,
      view: verdict({ code: 'bad-mech-list-mic', continuation: true }) },
    { label: 'a required MIC', path: '/spnego/protected', ctx: en,
      view: verdict({ code: 'mic-required',
                      requirementReason: 'section 5 <requires> it' }) },
    { label: 'request-mic', path: '/spnego/protected', ctx: sv,
      view: verdict({ code: 'request-mic', checks: checks }) },
    { label: 'an unmatched continuation', path: '/spnego/protected',
      ctx: en, view: verdict({ code: 'no-pending-continuation' }) },
    { label: 'a continuation without the MIC', path: '/spnego/protected',
      ctx: en, view: verdict({ code: 'continuation-no-mic' }) },
    { label: 'a code no page knows is a reject', path: '/spnego/protected',
      ctx: en, view: verdict({ code: 'acceptor-threw' }) },
    { label: 'the protected content, negotiated and mutual',
      path: '/spnego/protected', ctx: en, view: accepted },
    { label: 'the protected content, bare, ?mutual=off, in Swedish',
      path: '/spnego/protected', ctx: sv,
      view: Object.assign({}, accepted, { rawKerberos: true,
        micVerified: false, requirementReason: 'no list <to protect>',
        mutual: false, mutualOff: true, micNote: 'a note & "more"',
        client: '' }) },
    { label: 'the protected content, no AP-REP, in Spanish',
      path: '/spnego/protected', ctx: es,
      view: Object.assign({}, accepted, { mutual: false, checks: null }) },
    { label: 'a view the page does not know', path: '/spnego', ctx: en,
      view: { kind: 'other<1>' } }
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
      return authnCases(root).concat(walletCases(root),
                                     consentCases(root));
    } },
  { name: 'GNAP\'s interaction pages',
    pages: 'gnap/web_gnap_interact_pages.ts', global: 'StsGnapInteract',
    bundle: 'gnap/gnap-interaction.bundle.js',
    runtime: 'gnap/gnap-interaction-spa.js', cases: gnapCases },
  { name: 'the sign-out',
    pages: 'logout/web_signout_pages.ts', global: 'StsSignout',
    bundle: 'logout/signout.bundle.js', runtime: 'logout/signout-spa.js',
    cases: signoutCases },
  { name: 'the federation pages',
    pages: 'federation/web_federation_pages.ts', global: 'StsFederation',
    bundle: 'federation/federation-pages.bundle.js',
    runtime: 'federation/federation-pages-spa.js', cases: federationCases },
  { name: 'the description pages',
    pages: 'common/web_description_pages.ts', global: 'StsDescriptions',
    bundle: 'common/description-pages.bundle.js',
    runtime: 'common/description-pages-spa.js', cases: descriptionCases },
  { name: 'the SPNEGO demonstration pages',
    pages: 'kerberos/web_spnego_pages.ts', global: 'StsSpnegoPages',
    bundle: 'kerberos/spnego-pages.bundle.js',
    runtime: 'kerberos/spnego-pages-spa.js', cases: spnegoCases }
];
