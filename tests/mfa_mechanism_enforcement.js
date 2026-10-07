// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/mfa_mechanism_enforcement.js
//
// ---------------------------------------------------------------------------
// `appMfaMechanism` IS THE LIST OF SECOND FACTORS AN APPLICATION ALLOWS
// (#475), `appAuthnMechanism`'s companion (#457).
//
// rcbj's decisions (2026-10-07): it only NARROWS the realm's authentication
// policy; it says WHICH second factors, never WHETHER one is needed; a
// session that gave a second factor the application does not allow is
// RE-PROMPTED, as #457's are; and a person who holds none the application
// allows is offered one to set up — after PROVING the one they hold, if they
// hold one. This file holds every piece of it:
//
//   A. `common/mfa_mechanisms.ts`: which second factor each kind of
//      authentication event gave, the union over a session, and its ids
//      held to the authentication policy's second-factor mechanisms.
//   B. The field: a list with a checkbox per second factor, a value that is
//      not one refused at the write.
//   C. The policy, through `issuance_gate.check()`: a browser issuance on a
//      session whose second factor is not allowed is denied with the ones to
//      re-prompt for; one that gave an allowed one is permitted; a session
//      on ONE factor is not this rule's to deny; `browser: false` is not
//      asked.
//   D. The sign-in: a person who holds only an authenticator app, signing
//      in to an application that allows only a security key, is asked for
//      the app's code FIRST and then offered a passkey to set up — no
//      session in between, and the set-up screen lets them through although
//      they hold a factor.
//   E. Enrolment narrowed: a second factor required of somebody who holds
//      none is offered only what the application allows.
//   F. OAuth: a session on an authenticator app, for a client allowing only
//      a security key, is sent to sign in again (STS-OAUTH-0952);
//      prompt=none is login_required (STS-OAUTH-0953). A session on a
//      password alone is issued to (options only).
//   G. WS-Federation: re-prompted once (STS-WSFED-0022), and refused when it
//      comes back still unmet (STS-WSFED-0023).
//
// In a child process, on `tests/wallet_kit.js`'s in-process server, for
// `tests/authn_mechanism_enforcement.js`'s reason.
// ---------------------------------------------------------------------------

const kit = require('./wallet_kit');

const log = require('bunyan').createLogger({
  name: 'mfa_mechanism_enforcement',
  level: process.env.LOG_LEVEL || 'info' });

function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.WSI_ROOT;
  const OUT = process.env.WSI_OUT;
  const walletKit = require(ROOT + '/tests/wallet_kit');

  walletKit.boot().then(async function (w) {
    try {
      await sections(w, w.note, w.m);
    } catch (e) {
      w.note(false, 'the child ran to the end', e && (e.stack || e.message));
    }
    await w.finish(OUT);
    process.exit(0);
  }).catch(function (e) {
    require('fs').writeFileSync(OUT, JSON.stringify([
      { ok: false, what: 'the child booted', detail: e && e.stack }]));
    process.exit(0);
  });

  async function sections(w, note, m) {
    const factors = require(ROOT + '/common/mfa_mechanisms');
    const authnPolicy = require(ROOT + '/common/authn_policy');
    const credentials = require(ROOT + '/common/credentials');
    const totp = require(ROOT + '/common/totp');
    const adminActions = require(ROOT + '/admin-core/admin_actions');

    // --- A. The library ---------------------------------------------------
    const local = function (amr, acr, kind) {
      return { amr: amr, acr: acr, authenticated: true,
               authority: { kind: 'local' },
               context: { credential: { kind: kind } } };
    };
    const onApp = local(['pwd', 'otp'], 'mfa', 'totp');
    const onKey = local(['pwd', 'hwk'], 'mfa', 'webauthn');
    const onPassword = local(['pwd'], '1', 'password');
    const cases = [
      [onPassword, [], 'a password alone'],
      [onApp, ['totp'], 'a password and an authenticator app'],
      [onKey, ['securityKey'], 'a password and a security key'],
      [local(['hwk'], '1', 'webauthn'), [],
       'a passkey alone, which is a first factor'],
      [local(['pwd', 'otp'], 'mfa', 'backup-code'), ['recoveryCode'],
       'a password and a recovery code'],
      [local(['pwd', 'otp'], 'mfa', 'email-code'), ['emailCode'],
       'a password and an emailed code'],
      [local(['otp'], '1', 'email-code'), [], 'an emailed FIRST factor'],
      [local(['pwd', 'pop'], 'mfa', 'wallet'), ['wallet'],
       'a password and a wallet'],
      [local(['pop', 'pwd'], 'mfa', 'password'), ['password'],
       'a wallet and a password'],
      [{ amr: ['federated', 'otp'], acr: 'mfa', authenticated: true,
         authority: { kind: 'federation', id: 'p' } }, [],
       'a federation partner\'s second factor, which is not this service\'s']
    ];
    cases.forEach(function (one) {
      const got = factors.ofEvent(one[0]);
      note(JSON.stringify(got) === JSON.stringify(one[1]),
           'A. ' + one[2] + ' gave ' + (one[1].join(', ') || 'no second ' +
           'factor'), JSON.stringify(got));
    });
    const both = factors.satisfiedBy({ events: [onApp, onKey] });
    note(JSON.stringify(both) === '["totp","securityKey"]',
         'A. a session gave every second factor any of its events did — a ' +
         're-prompt appends an event', JSON.stringify(both));
    const capable = authnPolicy.MECHANISMS.filter(function (one) {
      return one.secondFactor !== null;
    }).map(function (one) {
      return one.id;
    });
    note(JSON.stringify(capable.slice(0).sort()) ===
         JSON.stringify(factors.IDS.slice(0).sort()),
         'A. the ids are exactly the authentication policy\'s second-factor ' +
         'mechanisms', JSON.stringify({ policy: capable, ids: factors.IDS }));

    // --- B. The field -----------------------------------------------------
    const fields = await w.inRealm(function () {
      return m.applications.applicationFields();
    });
    const row = fields.filter(function (one) {
      return one.attribute === 'appMfaMechanism';
    })[0];
    note(row && row.type === 'array' && row.editable === 'multi' &&
         JSON.stringify(row.choices) === JSON.stringify(factors.IDS),
         'B. appMfaMechanism is a list with a checkbox per second factor',
         JSON.stringify(row && { type: row.type, editable: row.editable,
                                 choices: row.choices }));
    const make = function (id, extra) {
      return w.inRealm(function () {
        return adminActions.applicationsAction(Object.assign({
          action: 'create', identifier: id }, extra || {}), [], {});
      });
    };
    const add = function (id, value) {
      return w.inRealm(function () {
        return adminActions.applicationsAction({ action: 'add',
          application: id, attribute: 'appMfaMechanism', value: value },
          [], {});
      });
    };
    await make('mfa-gate');
    const bad = await add('mfa-gate', 'carrier-pigeon');
    note(bad && bad.ok === false &&
         /carrier-pigeon/.test((bad.errors || []).join(' ')),
         'B. a value that is not a second factor is refused at the write',
         JSON.stringify(bad && bad.errors));

    // --- C. The policy ----------------------------------------------------
    const ask = function (session, extra) {
      return w.inRealm(function () {
        return m.gate.check(Object.assign({
          application: 'mfa-gate', kind: m.gate.ISSUANCE.SAML_ASSERTION,
          protocolFamilies: ['saml2'],
          subject: { kind: 'user', name: 'mfa-alice', authenticated: true },
          claims: null, session: session }, extra || {}));
      });
    };
    const sessionOn = function () {
      return { events: [].slice.call(arguments), authenticated: true };
    };
    const open = await ask(sessionOn(onApp));
    note(open.allowed === true && !open.mechanism,
         'C. an application that lists no second factor leaves the realm\'s',
         JSON.stringify({ allowed: open.allowed, why: open.why }));
    await add('mfa-gate', 'securityKey');
    const denied = await ask(sessionOn(onApp));
    note(denied.allowed === false && denied.mechanism &&
         denied.mechanism.secondFactor === true &&
         JSON.stringify(denied.mechanism.allowed) === '["securityKey"]',
         'C. a session on an authenticator app is denied for an application ' +
         'allowing only a security key, naming it to re-prompt for',
         JSON.stringify({ allowed: denied.allowed, why: denied.why,
                          mechanism: denied.mechanism }));
    const met = await ask(sessionOn(onApp, onKey));
    note(met.allowed === true,
         'C. and permitted once the session has a security key event too',
         JSON.stringify({ allowed: met.allowed, why: met.why }));
    const oneFactor = await ask(sessionOn(onPassword));
    note(oneFactor.allowed === true,
         'C. a session on ONE factor is not denied: the list says which ' +
         'second factors, never whether one is needed',
         JSON.stringify({ allowed: oneFactor.allowed, why: oneFactor.why }));
    const backChannel = await ask(sessionOn(onApp), { browser: false });
    note(backChannel.allowed === true,
         'C. a caller that is not a browser sign-in is not asked',
         JSON.stringify({ allowed: backChannel.allowed,
                          why: backChannel.why }));
    const atDoor = await w.inRealm(function () {
      return m.gate.check({
        application: 'mfa-gate', kind: m.gate.ISSUANCE.SESSION,
        subject: { kind: 'user', name: 'mfa-alice', authenticated: true },
        claims: null, authenticationEvent: onApp });
    });
    note(atDoor.allowed === false && !!atDoor.mechanism &&
         atDoor.mechanism.secondFactor === true,
         'C. a session about to be started on an authenticator app is ' +
         'denied too', JSON.stringify({ allowed: atDoor.allowed,
                                        why: atDoor.why }));

    // --- D. The sign-in: prove, then enrol --------------------------------
    // One person per authenticator app: a code is spent once (RFC 6238
    // section 5.2), and `totp.window` reaches a step either side.
    const withApp = function (username) {
      return w.inRealm(function () {
        m.ldap.createUser(username, { invent: false });
        const begun = credentials.beginTotpEnrolment(username,
                                                     { base: w.base });
        const done = credentials.confirmTotpEnrolment(username,
          totp.codeAt(begun.secret, Date.now(), begun));
        return done.ok ? begun : null;
      });
    };
    const nextCode = function (enrolled) {
      return w.inRealm(function () {
        return totp.codeAt(enrolled.secret,
                           Date.now() + (enrolled.period || 30) * 1000,
                           enrolled);
      });
    };
    const passwordStep = async function (who, username, application) {
      const id = w.pendingSignIn({ begin: { application: application } });
      return w.request('POST', '/authn/login', {
        browser: who,
        form: { authn_id: id, username: username, password: 'anything',
                action: 'login' } });
    };
    const dana = await withApp('mfa-dana');
    await make('mfa-keys-only');
    await add('mfa-keys-only', 'securityKey');
    const danaWho = w.browser();
    const asked = await passwordStep(danaWho, 'mfa-dana', 'mfa-keys-only');
    const danaStep = /name="mfa_id" value="([^"]+)"/.exec(asked.text);
    note(!!dana && asked.status === 200 &&
         /id="totp-submit"/.test(asked.text) && !!danaStep &&
         !w.sessionOf(danaWho),
         'D. somebody who holds only an authenticator app is asked for ITS ' +
         'code first, though the application does not allow it — the proof ' +
         'before any enrolment', asked.status);
    const proved = await w.request('POST', '/authn/totp', {
      browser: danaWho,
      form: { mfa_id: danaStep ? danaStep[1] : '',
              code: await nextCode(dana) } });
    const setupId = /name="mfa_id" value="([^"]+)"/.exec(proved.text);
    note(proved.status === 200 && /id="mfa-setup-webauthn"/.test(proved.text) &&
         !/id="mfa-setup-totp"/.test(proved.text) &&
         /does not accept the second factor you just gave/.test(proved.text) &&
         !w.sessionOf(danaWho),
         'D. and then offered a passkey to set up — only what the ' +
         'application allows, and still no session', proved.status);
    const chosen = await w.request('POST', '/authn/mfa-setup', {
      browser: danaWho,
      form: { mfa_id: setupId ? setupId[1] : '', action: 'webauthn' } });
    note(chosen.status === 200 && chosen.code !== 'STS-AUTHN-0175' &&
         /Create a passkey/.test(chosen.text),
         'D. the set-up screen lets the proved person through to the ' +
         'passkey registration, though they hold a factor',
         chosen.status + ' ' + chosen.code);

    // --- E. Enrolment narrowed --------------------------------------------
    await w.inRealm(function () {
      authnPolicy.save('default', Object.assign({}, authnPolicy.DEFAULTS,
        { requireSecondFactor: 'always' }));
      m.ldap.createUser('mfa-erin', { invent: false });
    });
    await make('mfa-apps-only');
    await add('mfa-apps-only', 'totp');
    const erinWho = w.browser();
    const enrol = await passwordStep(erinWho, 'mfa-erin', 'mfa-apps-only');
    note(enrol.status === 200 && /id="mfa-setup-totp"/.test(enrol.text) &&
         !/id="mfa-setup-webauthn"/.test(enrol.text),
         'E. a second factor required of somebody who holds none offers ' +
         'only what the application allows: an authenticator app, no ' +
         'passkey', enrol.status);
    await w.inRealm(function () {
      authnPolicy.reset('default');
    });

    // --- F. OAuth ---------------------------------------------------------
    // A browser holding a session on a password and an authenticator app,
    // for no application in particular.
    const fay = await withApp('mfa-fay');
    const fayWho = w.browser();
    const fayAsked = await passwordStep(fayWho, 'mfa-fay', '');
    const fayStep = /name="mfa_id" value="([^"]+)"/.exec(fayAsked.text);
    await w.request('POST', '/authn/totp', {
      browser: fayWho,
      form: { mfa_id: fayStep ? fayStep[1] : '', code: await nextCode(fay) } });
    const faySession = w.sessionOf(fayWho);
    note(!!faySession && faySession.acr === 'mfa',
         'F0. mfa-fay signs in with a password and an authenticator app',
         faySession ? JSON.stringify(faySession.amr) : 'no session');
    await w.inRealm(function () {
      m.config.setOverride('oauth2.consentRequired', 'false');
    });
    await make('mfa-oauth', { 'field.oauthClientId': 'mfa-oauth',
      'field.oauthRedirectUri': 'https://rp.mfa.example/cb' });
    await add('mfa-oauth', 'securityKey');
    const authorize = '/oauth2/authorize?response_type=code' +
      '&client_id=mfa-oauth&scope=openid&state=s1&nonce=n1' +
      '&redirect_uri=' + encodeURIComponent('https://rp.mfa.example/cb');
    const reprompt = await w.request('GET', authorize, { browser: fayWho });
    note(reprompt.status === 302 &&
         /\/authn\/login\?authn=/.test(String(reprompt.headers.location)) &&
         reprompt.code === 'STS-OAUTH-0952',
         'F. an authorization request on an authenticator-app session, for ' +
         'a client allowing only a security key, is sent to sign in again',
         reprompt.status + ' ' + reprompt.headers.location + ' ' +
         reprompt.code);
    const passive = await w.request('GET', authorize + '&prompt=none',
                                    { browser: fayWho });
    note(passive.status === 302 &&
         /^https:\/\/rp\.mfa\.example\/cb\?.*error=login_required/
           .test(String(passive.headers.location)) &&
         passive.code === 'STS-OAUTH-0953',
         'F. with prompt=none it is login_required at the client instead',
         passive.status + ' ' + passive.headers.location);
    await w.inRealm(function () {
      m.ldap.createUser('mfa-gus', { invent: false });
    });
    const gusWho = w.browser();
    await passwordStep(gusWho, 'mfa-gus', '');
    const oneFactorCode = await w.request('GET', authorize,
                                          { browser: gusWho });
    note(oneFactorCode.status === 302 &&
         /^https:\/\/rp\.mfa\.example\/cb\?.*code=/
           .test(String(oneFactorCode.headers.location)),
         'F. a session on a password alone is issued to: the list says ' +
         'which second factors, never whether one is needed',
         oneFactorCode.status + ' ' + oneFactorCode.headers.location);

    // --- G. WS-Federation -------------------------------------------------
    await make('urn:mfa:wsfed', {
      'field.wsfedReplyUrl': 'https://rp.mfa.example/wsfed' });
    await add('urn:mfa:wsfed', 'securityKey');
    const signIn = '/wsfed?wa=wsignin1.0' +
      '&wtrealm=' + encodeURIComponent('urn:mfa:wsfed') +
      '&wreply=' + encodeURIComponent('https://rp.mfa.example/wsfed');
    const wsfed = await w.request('GET', signIn, { browser: fayWho });
    note(wsfed.status === 303 &&
         /\/authn\/login\?authn=/.test(String(wsfed.headers.location)) &&
         wsfed.code === 'STS-WSFED-0022',
         'G. a WS-Federation sign-in on an authenticator-app session is sent ' +
         'to sign in again', wsfed.status + ' ' + wsfed.headers.location +
         ' ' + wsfed.code);
    const back = await w.request('GET', signIn + '&sts_mechanism_retry=1',
                                 { browser: fayWho });
    note(back.status === 403 && back.code === 'STS-WSFED-0023',
         'G. and refused when it comes back from that trip still unmet',
         back.status + ' ' + back.code);

    await w.inRealm(function () {
      m.config.clearOverride('oauth2.consentRequired');
    });
  }
}

async function run(t) {
  log.debug("Entering run().");
  kit.inAChild(t, childMain, 'mfa-mechanism-enforcement');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'mfa mechanism enforcement',
  describe: 'appMfaMechanism as a list of the second factors an ' +
            'application allows: narrowing the realm\'s, proved then ' +
            'enrolled, and re-prompted for by the issuance policy (#475)',
  run: run
};
