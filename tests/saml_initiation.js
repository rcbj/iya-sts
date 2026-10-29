// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: saml_initiation.js
//
// ===========================================================================
// WHO MAY START A SAML SIGN-IN, AND WHAT A SIGN-IN STARTED HERE RUNS (#711).
//
// #426 gave each browser profile two switches, a realm default and a
// per-application override: may this identity provider START a sign-in
// (identity-provider-initiated, OFF until an application opts in) and may
// the service provider. #711 makes the SAML endpoints obey them, and makes
// an identity-provider-initiated issuance step up on risk instead of
// refusing, once. This file is the contract, over HTTP, against the whole
// stack:
//
//   A. SAML 2.0, /saml2/unsolicited: refused by default (403, STS-SAML-0091)
//      and with no sign-in screen; answered for a service provider whose
//      entry sets saml2IdpInitiatedSso TRUE, with a Response carrying no
//      InResponseTo; and the session then names that service provider in
//      saml2ServiceProviders, which /logout and back-channel logout read.
//   B. SAML 2.0, an AuthnRequest from a service provider whose entry sets
//      saml2SpInitiatedSso FALSE: a RequestDenied Response naming the
//      request (STS-SAML-0111), before any sign-in screen; another service
//      provider's request is still answered.
//   C. SAML 1.1, /saml11/sso/{rp}: a link with only a TARGET is refused by
//      default (403, STS-SAML-0113) and answered with saml11IdpInitiatedSso
//      TRUE; a request carrying shire is answered by default and refused
//      with saml11SpInitiatedSso FALSE (403, STS-SAML-0114).
//   D. RISK, on both identity-provider-initiated paths, with
//      risk.enforceInDevelopment on and a session held at MEDIUM: a step-up
//      to the sign-in screen with a second factor demanded (STS-RISK-0017)
//      instead of a refusal; back from that ONE trip still unmet, refused
//      (STS-SAML-0112 as a RequestDenied Response, STS-SAML-0115 as a page)
//      rather than sent round again; and back from it with the factor, the
//      launch is answered. THEN AGAIN IN PRODUCT MODE (#715), "D1
//      (product)" to "D7 (product)": `global.mode` overridden to product,
//      no risk.enforceInDevelopment, service providers made in product, and
//      a person with a real password who signs in with it at the screen
//      (and is refused with a wrong one). Only D runs twice: A, B, C and E
//      run in product over the wire, in
//      tests/protocol/sts_idp_initiated_saml.js, and a session's risk is
//      the one thing here HTTP cannot set up.
//   E. THE MECHANISM RE-PROMPT ON /saml2/unsolicited (#457) makes the same
//      one trip: back from it still on a mechanism the service provider
//      does not allow, RequestDenied (STS-SAML-0100).
//
// The error code is read off the response object the server sent, through a
// wrapper around the express app: it is recorded and never sent, so a client
// could not read it.
//
// WHY A CHILD PROCESS: it serves the whole protocol stack on a loopback port
// and changes settings the rest of the in-process suite must not see.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const log = require('bunyan').createLogger({ name: 'saml_initiation',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.SI_ROOT;
  const OUT = process.env.SI_OUT;
  const http = require('http');
  const zlib = require('zlib');
  const nodeCrypto = require('crypto');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const realms = require(ROOT + '/common/realms');
    const config = require(ROOT + '/common/config');
    const errorCodes = require(ROOT + '/common/error_codes');
    const applications = require(ROOT + '/common/applications');
    const authn = require(ROOT + '/authn/authn');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const kit = require(ROOT + '/tests/tools/saml_signing_kit');
    const credentials = require(ROOT + '/common/credentials');
    const screen = require(ROOT + '/tests/tools/authn_screen');

    // The code the last response was marked with, off the server's own
    // response object.
    let lastCode = '';
    // A browser's User-Agent, sent on every request while it is set: the
    // product pass of D sets it (#715).
    let userAgent = '';
    const server = http.createServer(function (req, res) {
      res.on('finish', function () {
        lastCode = errorCodes.codeOf(res);
      });
      app(req, res);
    });
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const base = 'http://127.0.0.1:' + port;

    function request(method, target, cookie) {
      const url = new URL(target, base);
      lastCode = '';
      return new Promise(function (resolve) {
        const headers = cookie ? { cookie: cookie } : {};
        if (userAgent) {
          headers['user-agent'] = userAgent;
        }
        const req = http.request({ host: '127.0.0.1', port: port,
          path: url.pathname + url.search, method: method, headers: headers },
        function (res) {
          let text = '';
          res.on('data', function (c) { text += c; });
          res.on('end', function () {
            // `finish` on the server side has fired by now; a tick more is
            // cheap insurance.
            setImmediate(function () {
              resolve({ status: res.statusCode,
                        location: String(res.headers.location || ''),
                        text: text, code: lastCode });
            });
          });
        });
        req.end();
      });
    }

    const stamp = String(Date.now());
    // The product pass's (#715): its person's password, and the User-Agent
    // every request then carries, as a browser's would.
    const PASSWORD = 'si-Initiation-Passw0rd!-' + stamp.slice(-6);
    const BROWSER_UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 ' +
                       '(KHTML, like Gecko) Chrome/124.0 Safari/537.36';
    const created = [];
    function party(name, kind, fields) {
      const identifier = 'https://' + name + '-' + stamp + '.init.test/sp';
      const made = applications.createApplication({
        identifier: identifier, kind: kind,
        protocol: kind === 'saml11-relying-party' ? 'SAML 1.1' : 'SAML 2.0',
        protocols: [kind === 'saml11-relying-party' ? 'saml11' : 'saml2'],
        fields: Object.assign({
          samlEntityId: identifier,
          samlAssertionConsumerService: 'https://' + name + '-' + stamp +
                                        '.init.test/acs' }, fields || {}) });
      note(made.ok, 'created ' + name, JSON.stringify(made.errors || ''));
      created.push(identifier);
      return identifier;
    }
    function acsOf(identifier) {
      return identifier.replace(/\/sp$/, '/acs');
    }
    // A signed-in session for `who`, its cookie and the store's copy.
    function sessionFor(who) {
      ldap.createUser(who, { invent: false });
      const res = kit.fakeRes();
      const session = authn.startSession(res, who, ['pwd'], '1', 'a test',
                                         {});
      const cookie = [].concat(res.headers['set-cookie'] || [])
        .map(function (line) {
          return String(line).split(';')[0];
        }).filter(function (pair) {
          return /^sts_session=/.test(pair);
        })[0] || '';
      return { cookie: cookie, id: session.id,
                held: function () {
                  return authn.sessionById(session.id);
                } };
    }
    function samlResponseOf(r) {
      const m = /name="SAMLResponse" value="([^"]+)"/.exec(r.text);
      return m ? Buffer.from(m[1].replace(/&#x2B;|&#43;/g, '+'), 'base64')
        .toString('utf8') : '';
    }
    function pendingOf(location) {
      const m = /[?&]authn=([^&]+)/.exec(location || '');
      if (!m) {
        return null;
      }
      return realms.run(realms.DEFAULT_REALM, function () {
        return authn.pendingFor(decodeURIComponent(m[1]));
      });
    }
    function authnRequest(issuer, acs) {
      const id = '_si' + nodeCrypto.randomBytes(10).toString('hex');
      const xml = '<samlp:AuthnRequest ' +
        'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' +
        'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ' +
        'ID="' + id + '" Version="2.0" IssueInstant="' +
        new Date().toISOString() + '" AssertionConsumerServiceURL="' + acs +
        '"><saml:Issuer>' + issuer + '</saml:Issuer></samlp:AuthnRequest>';
      return { id: id, path: '/saml2/sso?SAMLRequest=' + encodeURIComponent(
        zlib.deflateRawSync(Buffer.from(xml)).toString('base64')) };
    }
    function unsolicited(sp, extra) {
      return '/saml2/unsolicited?' + new URLSearchParams(Object.assign({
        providerId: sp, target: 'rs-' + stamp }, extra || {})).toString();
    }
    function sso11(rp, extra) {
      return '/saml11/sso/' + encodeURIComponent(rp) + '?' +
        new URLSearchParams(Object.assign({
          TARGET: 'https://app.init.test/' + stamp }, extra || {}))
          .toString();
    }

    // D, a step-up on risk on both identity-provider-initiated paths, for
    // `risky` (`{ cookie, held }`) against `sp` and `rp`, each opted in. Run
    // twice (#715): in development with risk.enforceInDevelopment, and in
    // product, where the policy's risk Deny is kept with no setting at all.
    // `tag` tells the two passes' checks apart.
    async function riskSection(tag, risky, sp, rp) {
      // The sign-in's own risk assessment finishes after the session starts
      // and writes the session's risk; a level put in place before it lands
      // is overwritten. So wait for it, and put the level in place again
      // before each step that depends on it.
      await new Promise(function (r) { setTimeout(r, 1000); });
      const atMedium = function () {
        const s = risky.held();
        s.risk = { level: 'MEDIUM', score: 2, signals: ['tor-exit'],
                   assessmentId: 'si-' + stamp };
        s.acr = '1';
        s.amr = ['pwd'];
        authn.noteSessionChanged(s);
      };
      const steppedUp = function () {
        const s = risky.held();
        s.acr = 'mfa';
        s.amr = ['pwd', 'otp'];
        authn.noteSessionChanged(s);
      };
      atMedium();
      let r = await request('GET', unsolicited(sp), risky.cookie);
      let pending = pendingOf(r.location);
      const returnTo = pending ? String(pending.returnTo || '') : '';
      note(r.status === 303 && r.code === 'STS-RISK-0017' && !!pending &&
           !!pending.forceMfa && /[?&]reprompted=1$/.test(returnTo) &&
           returnTo.indexOf('target=rs-' + stamp) >= 0,
           'D1' + tag + '. SAML 2.0: a session at MEDIUM is STEPPED UP — to ' +
           'the sign-in screen with a second factor demanded ' +
           '(STS-RISK-0017), back to the same link marked as its one trip ' +
           '— not refused', r.status + ' ' + r.code + ' ' + returnTo);
      atMedium();
      r = await request('GET', returnTo || unsolicited(sp,
                                                       { reprompted: '1' }),
                        risky.cookie);
      let xml = samlResponseOf(r);
      note(r.status === 200 && r.code === 'STS-SAML-0112' &&
           /status:RequestDenied"/.test(xml) && !/InResponseTo=/.test(xml),
           'D2' + tag + '. back from that trip still unmet: RequestDenied, ' +
           'STS-SAML-0112, and not sent round again',
           r.status + ' ' + r.code + ' ' + r.location + ' ' +
           xml.slice(0, 200));
      steppedUp();
      r = await request('GET', returnTo || unsolicited(sp,
                                                       { reprompted: '1' }),
                        risky.cookie);
      xml = samlResponseOf(r);
      note(r.status === 200 && /StatusCode Value="[^"]*:Success"/.test(xml),
           'D3' + tag + '. back from it WITH the second factor: the launch ' +
           'is answered', r.status + ' ' + r.code + ' ' + xml.slice(0, 200));

      atMedium();
      r = await request('GET', sso11(rp), risky.cookie);
      pending = pendingOf(r.location);
      const return11 = pending ? String(pending.returnTo || '') : '';
      note(r.status === 303 && r.code === 'STS-RISK-0017' && !!pending &&
           !!pending.forceMfa && /[?&]fid=/.test(return11),
           'D4' + tag + '. SAML 1.1: a session at MEDIUM is stepped up too, ' +
           'back to the held flow', r.status + ' ' + r.code + ' ' + return11);
      atMedium();
      r = await request('GET', return11 || sso11(rp), risky.cookie);
      note(r.status === 403 && r.code === 'STS-SAML-0115' &&
           !/name="SAMLResponse"/.test(r.text),
           'D5' + tag + '. back from that trip still unmet: refused on a ' +
           'page, STS-SAML-0115, not sent round again', r.status + ' ' +
           r.code + ' ' + r.location);
      r = await request('GET', sso11(rp), risky.cookie);
      pending = pendingOf(r.location);
      const again11 = pending ? String(pending.returnTo || '') : '';
      steppedUp();
      r = await request('GET', again11 || sso11(rp), risky.cookie);
      note(!!again11 && r.status === 200 &&
           /name="SAMLResponse"/.test(r.text),
           'D6' + tag + '. a fresh link stepped up, back with the second ' +
           'factor: answered', r.status + ' ' + r.code + ' ' + again11);
    }

    // A PERSON WHO SIGNS IN THE WAY PRODUCT REQUIRES (#715): created with
    // the attributes the realm's attribute policy asks of everybody in
    // product (#396), given a real password through the same
    // `credentials.setPassword()` the management API's create calls, and
    // signed in at the sign-in screen over `/authn-api` with it — where
    // product verifies it — by following `sp`'s own unsolicited link, which
    // sends a browser with no session there. Answers `{ cookie, held }`
    // as sessionFor() does, from the cookie the screen set.
    async function signedInWithPassword(who, password, sp) {
      const made = ldap.createUser(who, { invent: false, attributes: {
        givenName: 'Initiation', sn: who, mail: who + '@init.test' } });
      note(made && made.ok, 'D0 (product). the person ' + who + ' is ' +
           'created with the attributes product requires',
           JSON.stringify((made && made.errors) || ''));
      const set = credentials.setPassword(who, password);
      note(set && set.ok, 'D0 (product). and given a password',
           JSON.stringify((set && set.errors) || ''));
      const jar = {};
      const started = await request('GET', unsolicited(sp));
      const answer = await screen.submit({ port: port, jar: jar,
        userAgent: userAgent, at: started.location,
        fields: { username: who, password: password } });
      const cookie = Object.keys(jar).map(function (k) {
        return k + '=' + jar[k];
      }).join('; ');
      const sid = String(jar.sts_session || '').split('.')[0];
      note(started.status === 303 && answer.next === 'redirect' && !!sid,
           'D0 (product). and signs in at the sign-in screen with that ' +
           'password', started.status + ' ' + answer.status + ' ' +
           answer.next + ' ' + JSON.stringify(answer.errors || ''));
      const back = await request('GET', answer.location || unsolicited(sp),
                                 cookie);
      note(back.status === 200 &&
           /StatusCode Value="[^"]*:Success"/.test(samlResponseOf(back)),
           'D0 (product). back from the screen, the link it started from is ' +
           'answered', back.status + ' ' + back.code);
      return { cookie: cookie, id: sid,
               held: function () {
                 return authn.sessionById(sid);
               } };
    }

    try {
      // --- A. SAML 2.0, identity-provider-initiated ------------------------
      const spOff = party('idp-off', 'saml2-service-provider');
      const spOn = party('idp-on', 'saml2-service-provider',
                         { saml2IdpInitiatedSso: 'TRUE' });
      const alice = sessionFor('si-alice-' + stamp);
      let r = await request('GET', unsolicited(spOff));
      note(r.status === 403 && r.code === 'STS-SAML-0091' && !r.location,
           'A1. /saml2/unsolicited for a service provider that did not opt ' +
           'in is REFUSED by default — 403, STS-SAML-0091, and no sign-in ' +
           'screen first', r.status + ' ' + r.code + ' ' + r.location);
      r = await request('GET', unsolicited(spOff), alice.cookie);
      note(r.status === 403 && r.code === 'STS-SAML-0091',
           'A2. and with a session too', r.status + ' ' + r.code);
      r = await request('GET', unsolicited(spOn));
      note(r.status === 303 && /\/authn\//.test(r.location),
           'A3. for one whose entry sets saml2IdpInitiatedSso TRUE, with no ' +
           'session: to the sign-in screen', r.status + ' ' + r.location);
      r = await request('GET', unsolicited(spOn), alice.cookie);
      let xml = samlResponseOf(r);
      note(r.status === 200 && /<samlp:Response\b/.test(xml) &&
           /StatusCode Value="[^"]*:Success"/.test(xml) &&
           !/InResponseTo=/.test(xml) &&
           xml.indexOf('Destination="' + acsOf(spOn) + '"') >= 0,
           'A4. with a session: an UNSOLICITED Response — Success, no ' +
           'InResponseTo on the Response or the assertion — at the ' +
           'registered ACS', r.status + ' ' + r.code + ' ' +
           xml.slice(0, 300));
      const heldA = alice.held();
      const inventory = (heldA && heldA.saml2ServiceProviders) || {};
      note(!!inventory[spOn] && !inventory[spOff],
           'A5. and the session names that service provider in ' +
           'saml2ServiceProviders — what /logout and back-channel logout ' +
           'read — and not the refused one', JSON.stringify(
             Object.keys(inventory)));
      const realmOn = await kit.withSettings(config,
        { 'saml2.idpInitiatedSso': true }, function () {
          return request('GET', unsolicited(spOff), alice.cookie);
        });
      note(realmOn.status === 200 && /SAMLResponse/.test(realmOn.text),
           'A6. the realm setting on answers a service provider whose entry ' +
           'says nothing', realmOn.status + ' ' + realmOn.code);

      // --- B. SAML 2.0, service-provider-initiated --------------------------
      const spClosed = party('sp-off', 'saml2-service-provider',
                             { saml2SpInitiatedSso: 'FALSE' });
      const closed = authnRequest(spClosed, acsOf(spClosed));
      r = await request('GET', closed.path);
      xml = samlResponseOf(r);
      note(r.status === 200 && r.code === 'STS-SAML-0111' &&
           /status:RequestDenied"/.test(xml) &&
           xml.indexOf('InResponseTo="' + closed.id + '"') >= 0 &&
           !/\/authn\//.test(r.location),
           'B1. an AuthnRequest from a service provider whose entry sets ' +
           'saml2SpInitiatedSso FALSE is answered RequestDenied, ' +
           'STS-SAML-0111, naming the request — with no sign-in screen',
           r.status + ' ' + r.code + ' ' + xml.slice(0, 300));
      const open = authnRequest(spOn, acsOf(spOn));
      r = await request('GET', open.path, alice.cookie);
      xml = samlResponseOf(r);
      note(r.status === 200 && /StatusCode Value="[^"]*:Success"/.test(xml) &&
           xml.indexOf('InResponseTo="' + open.id + '"') >= 0,
           'B2. another service provider\'s request is answered — ' +
           'service-provider-initiated is on by default',
           r.status + ' ' + r.code + ' ' + xml.slice(0, 200));

      // --- C. SAML 1.1 ------------------------------------------------------
      const rpOff = party('rp11-off', 'saml11-relying-party');
      const rpOn = party('rp11-on', 'saml11-relying-party',
                         { saml11IdpInitiatedSso: 'TRUE' });
      const rpClosed = party('rp11-sp-off', 'saml11-relying-party',
                             { saml11SpInitiatedSso: 'FALSE' });
      r = await request('GET', sso11(rpOff));
      note(r.status === 403 && r.code === 'STS-SAML-0113' && !r.location,
           'C1. a SAML 1.1 link with only a TARGET, for a relying party that ' +
           'did not opt in, is REFUSED by default — 403, STS-SAML-0113, no ' +
           'sign-in screen', r.status + ' ' + r.code + ' ' + r.location);
      r = await request('GET', sso11(rpOn), alice.cookie);
      note(r.status === 200 && /name="SAMLResponse"/.test(r.text) &&
           /name="TARGET"/.test(r.text),
           'C2. answered for one whose entry sets saml11IdpInitiatedSso TRUE',
           r.status + ' ' + r.code);
      const heldC = alice.held();
      note(!!(heldC && heldC.saml11RelyingParties &&
              heldC.saml11RelyingParties[rpOn]),
           'C3. and the session records the relying party, as for any SAML ' +
           '1.1 sign-in', JSON.stringify(Object.keys(
             (heldC && heldC.saml11RelyingParties) || {})));
      r = await request('GET', sso11(rpOff, { shire: acsOf(rpOff) }),
                        alice.cookie);
      note(r.status === 200 && /name="SAMLResponse"/.test(r.text),
           'C4. a request carrying shire — the relying party\'s own start — ' +
           'is answered by default, whatever the other switch says',
           r.status + ' ' + r.code);
      r = await request('GET', sso11(rpClosed, { shire: acsOf(rpClosed) }),
                        alice.cookie);
      note(r.status === 403 && r.code === 'STS-SAML-0114' &&
           !/name="SAMLResponse"/.test(r.text),
           'C5. and REFUSED for one whose entry sets saml11SpInitiatedSso ' +
           'FALSE — 403, STS-SAML-0114', r.status + ' ' + r.code);

      // --- D. a step-up on risk -------------------------------------------
      config.setOverride('risk.enforceInDevelopment', true);
      await riskSection('', sessionFor('si-bob-' + stamp), spOn, rpOn);
      config.clearOverride('risk.enforceInDevelopment');

      // --- D (product). the same, in product mode (#715) ------------------
      // The over-the-wire job, tests/protocol/sts_idp_initiated_saml.js,
      // runs A, B, C and E in product (`single-node`, `cluster`); D cannot
      // be set up over HTTP, because a session's risk comes from datasets
      // the suite does not load, so it runs here a second time with the
      // mode switched. What product changes for it: the risk Deny is kept
      // with no setting (risk.enforceInDevelopment is not set), the
      // service providers are registered ones made in product, and the
      // person has a real password and signs in with it at the screen,
      // where product checks it — not through startSession(), which checks
      // nothing. A browser's User-Agent is sent meanwhile: product scores
      // an automated client's sign-in as risky (`isbot`), which would make
      // the sign-in itself the step-up.
      config.setOverride('global.mode', 'product');
      userAgent = BROWSER_UA;
      try {
        const spProduct = party('idp-on-p', 'saml2-service-provider',
                                { saml2IdpInitiatedSso: 'TRUE' });
        const rpProduct = party('rp11-on-p', 'saml11-relying-party',
                                { saml11IdpInitiatedSso: 'TRUE' });
        const carolName = 'si-carol-' + stamp;
        const carol = await signedInWithPassword(carolName, PASSWORD,
                                                 spProduct);
        await riskSection(' (product)', carol, spProduct, rpProduct);
        // LAST, so nothing above stands on a session a failed attempt may
        // have made riskier: the wrong password is refused at the screen.
        const wrongJar = {};
        const startedWrong = await request('GET', unsolicited(spProduct));
        const wrong = await screen.submit({ port: port, jar: wrongJar,
          userAgent: userAgent, at: startedWrong.location,
          fields: { username: carolName, password: PASSWORD + '-wrong' } });
        note(startedWrong.status === 303 && wrong.next !== 'redirect' &&
             !(wrong.json && wrong.json.ok),
             'D7 (product). the same person with a WRONG password is ' +
             'refused at the screen — product checks it',
             startedWrong.status + ' ' + wrong.status + ' ' + wrong.next);
      } finally {
        userAgent = '';
        config.clearOverride('global.mode');
      }

      // --- E. the mechanism re-prompt, once ---------------------------------
      // The mechanisms are a named authentication policy's (#1148).
      require(ROOT + '/common/authn_policy').saveNamed('si-wallet-only',
        { mechanisms: ['wallet'] });
      const spMech = party('mech', 'saml2-service-provider',
                           { saml2IdpInitiatedSso: 'TRUE',
                             appAuthnPolicy: 'si-wallet-only' });
      r = await request('GET', unsolicited(spMech), alice.cookie);
      note(r.status === 303 && r.code === 'STS-SAML-0099',
           'E1. a session on a mechanism the service provider does not ' +
           'allow is sent to sign in again (STS-SAML-0099)',
           r.status + ' ' + r.code + ' ' + r.location);
      r = await request('GET', unsolicited(spMech, { reprompted: '1' }),
                        alice.cookie);
      xml = samlResponseOf(r);
      note(r.status === 200 && r.code === 'STS-SAML-0100' &&
           /status:RequestDenied"/.test(xml),
           'E2. back from that one trip still on it: RequestDenied, ' +
           'STS-SAML-0100, not another trip', r.status + ' ' + r.code + ' ' +
           r.location);
    } finally {
      config.clearOverride('risk.enforceInDevelopment');
      config.clearOverride('global.mode');
      created.forEach(function (identifier) {
        if (applications.get(identifier)) {
          applications.deleteApplication(identifier);
        }
      });
    }

    server.close();
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child ran to the end',
                    detail: e && e.stack });
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'saml-initiation-' + process.pid + '-' +
                        require('crypto').randomBytes(8).toString('hex') +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|SAML|CONFIG_FILE$)/
        .test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', SI_ROOT: ROOT, SI_OUT: out }),
      encoding: 'utf8', timeout: 180000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    // No report: the child died before writing one, which the check below
    // reports with its exit status and stderr.
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written, which the read above has already reported.
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (t.check(Array.isArray(findings), 'the child process reported',
              'exit ' + result.status + ' ' +
              String(result.stderr || '').slice(-800))) {
    findings.forEach(function (one) {
      t.check(one.ok, one.what, one.detail);
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'saml_initiation',
  describe: 'who may start a SAML sign-in (#711): SAML 2.0\'s unsolicited ' +
            'Response and SAML 1.1\'s TARGET-only link off until an ' +
            'application opts in, the service provider\'s own start ' +
            'refused per application, a step-up on risk instead of a ' +
            'refusal, and one trip to the sign-in screen per link',
  run: run
};
