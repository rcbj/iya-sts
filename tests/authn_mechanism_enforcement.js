// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/authn_mechanism_enforcement.js
//
// ---------------------------------------------------------------------------
// `appAuthnMechanism` IS A LIST OF THE SIGN-IN MECHANISMS AN APPLICATION
// ALLOWS, AND IT IS ENFORCED AT EVERY BROWSER SIGN-IN (#457).
//
// rcbj's decisions: several mechanisms; enforced at run time in both modes;
// browser-based authentication only; a session on the wrong mechanism is
// RE-PROMPTED for an allowed one rather than refused; none ticked allows
// every one. The issuance policy decides (its `authn-mechanism` rule); this
// file holds every piece of it:
//
//   A. `common/authn_mechanisms.ts`: which mechanism each kind of
//      authentication event satisfies, and the union over a session.
//   B. The field: a list with a checkbox per mechanism, a value that is not
//      one refused at the write.
//   C. The policy, through `issuance_gate.check()`: a browser issuance on a
//      session that satisfies none of the allowed mechanisms is denied with
//      the mechanisms to re-prompt for; one that satisfies one is permitted;
//      an application allowing every one, and a `browser: false` caller, are
//      not asked.
//   D. Where the sign-in goes: one usable mechanism routes as the one value
//      did; several draw the screen with only those offered.
//   E. The sign-in door: a sign-in made with a mechanism the application does
//      not allow is refused (STS-AUTHN-0298), the screen drawn again.
//   F. OAuth: a session on the wrong mechanism is sent to sign in again
//      (STS-OAUTH-0945); prompt=none is login_required (STS-OAUTH-0946).
//   G. WS-Federation: re-prompted once (STS-WSFED-0017), and refused when
//      it comes back still unmet (STS-WSFED-0018).
//
// SAML 2.0 and SAML 1.1 take G's shape (a held request and a recorded
// trip); their HTTP drivers are the protocol suite's, which is where a
// signed AuthnRequest is built.
//
// In a child process, on `tests/wallet_kit.js`'s in-process server: the
// whole protocol stack is loaded and one module-level store would leak into
// every file after this one.
// ---------------------------------------------------------------------------

const kit = require('./wallet_kit');

const log = require('bunyan').createLogger({
  name: 'authn_mechanism_enforcement',
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
    const mech = require(ROOT + '/common/authn_mechanisms');
    const adminActions = require(ROOT + '/admin-core/admin_actions');

    // --- A. The library ---------------------------------------------------
    const local = function (amr, acr, kind) {
      return { amr: amr, acr: acr, authenticated: true,
               authority: { kind: 'local' },
               context: { credential: { kind: kind } } };
    };
    const cases = [
      [local(['pwd'], '1', 'password'), ['password'], 'a password'],
      [local(['pwd', 'otp'], 'mfa', 'totp'), ['password', 'password-mfa'],
       'a password and an authenticator app'],
      [local(['hwk'], '1', 'webauthn'), ['webauthn'], 'a passwordless key'],
      [local(['pop', 'hwk'], '1', 'wallet'), ['wallet'],
       'a hardware-backed wallet, which is not a security key'],
      [{ amr: ['federated', 'pwd'], acr: '1', authenticated: true,
         authority: { kind: 'federation', id: 'p' } }, ['federation'],
       'a federation partner, whose own pwd is not this service\'s'],
      [{ amr: ['pwd'], acr: '1', authenticated: true,
         authority: { kind: 'kerberos', principal: 'a@R' } }, ['spnego'],
       'a Kerberos ticket'],
      [local(['otp'], '1', 'email-code'), [], 'an emailed first factor'],
      [{ amr: [], acr: '0', authenticated: false,
         authority: { kind: 'local' } }, [], 'nobody']
    ];
    cases.forEach(function (one) {
      const got = mech.ofEvent(one[0]);
      note(JSON.stringify(got) === JSON.stringify(one[1]),
           'A. ' + one[2] + ' satisfies ' + (one[1].join(', ') || 'nothing'),
           JSON.stringify(got));
    });
    const both = mech.satisfiedBy({ events: [cases[0][0], cases[3][0]] });
    note(JSON.stringify(both) === '["password","wallet"]',
         'A. a session satisfies every mechanism any of its events did — a ' +
         're-prompt appends an event', JSON.stringify(both));

    // --- B. The field -----------------------------------------------------
    const fields = await w.inRealm(function () {
      return m.applications.applicationFields();
    });
    const row = fields.filter(function (one) {
      return one.attribute === 'appAuthnMechanism';
    })[0];
    note(row && row.type === 'array' && row.editable === 'multi' &&
         JSON.stringify(row.choices) === JSON.stringify(
           require(ROOT + '/federation/federation').MECHANISM_IDS),
         'B. appAuthnMechanism is a list with a checkbox per mechanism',
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
          application: id, attribute: 'appAuthnMechanism', value: value },
          [], {});
      });
    };
    await make('mech-gate');
    const bad = await add('mech-gate', 'smoke-signals');
    note(bad && bad.ok === false &&
         /smoke-signals/.test((bad.errors || []).join(' ')),
         'B. a value that is not a mechanism is refused at the write',
         JSON.stringify(bad && bad.errors));

    // --- C. The policy ----------------------------------------------------
    const ask = function (session, extra) {
      return w.inRealm(function () {
        return m.gate.check(Object.assign({
          application: 'mech-gate', kind: m.gate.ISSUANCE.SAML_ASSERTION,
          protocolFamilies: ['saml2'],
          subject: { kind: 'user', name: 'mech-alice', authenticated: true },
          claims: null, session: session }, extra || {}));
      });
    };
    const onPassword = { events: [cases[0][0]], authenticated: true };
    const open = await ask(onPassword);
    note(open.allowed === true && !open.mechanism,
         'C. an application that allows every mechanism is not asked about ' +
         'one', JSON.stringify({ allowed: open.allowed, why: open.why }));
    await add('mech-gate', 'wallet');
    await add('mech-gate', 'spnego');
    const denied = await ask(onPassword);
    note(denied.allowed === false && denied.mechanism &&
         JSON.stringify(denied.mechanism.allowed) === '["wallet","spnego"]',
         'C. a session on a password is denied for an application allowing ' +
         'wallet and spnego, naming them to re-prompt for',
         JSON.stringify({ allowed: denied.allowed, why: denied.why,
                          mechanism: denied.mechanism }));
    const met = await ask({ events: [cases[0][0], cases[3][0]],
                            authenticated: true });
    note(met.allowed === true,
         'C. and permitted once the session has a wallet event as well',
         JSON.stringify({ allowed: met.allowed, why: met.why }));
    const backChannel = await ask(onPassword, { browser: false });
    note(backChannel.allowed === true,
         'C. a caller that is not a browser sign-in is not asked',
         JSON.stringify({ allowed: backChannel.allowed,
                          why: backChannel.why }));
    const atDoor = await w.inRealm(function () {
      return m.gate.check({
        application: 'mech-gate', kind: m.gate.ISSUANCE.SESSION,
        subject: { kind: 'user', name: 'mech-alice', authenticated: true },
        claims: null, authenticationEvent: cases[0][0] });
    });
    note(atDoor.allowed === false && !!atDoor.mechanism,
         'C. a session about to be started on a password is denied too',
         JSON.stringify({ allowed: atDoor.allowed, why: atDoor.why }));

    // --- D. Where the sign-in goes ---------------------------------------
    await w.inRealm(function () {
      m.config.setOverride('krb5.spnegoAuthentication', 'true');
      m.config.setOverride('oid4vp.signIn', 'true');
    });
    await make('mech-spnego');
    await add('mech-spnego', 'spnego');
    const straight = await w.inRealm(function () {
      return m.authn.beginAuthentication({ returnTo: '/mech/after',
        protocol: 'mech-probe', application: 'mech-spnego' });
    });
    note(/^\/authn\/spnego\?authn=/.test(straight),
         'D. one mechanism allowed routes as the one value did — spnego ' +
         'straight to /authn/spnego', straight);
    await make('mech-door');
    await add('mech-door', 'webauthn');
    await add('mech-door', 'wallet');
    const screenAt = await w.inRealm(function () {
      return m.authn.beginAuthentication({ returnTo: '/mech/after',
        protocol: 'mech-probe', application: 'mech-door' });
    });
    const who = w.browser();
    const screen = await w.request('GET', screenAt, { browser: who });
    note(/^\/authn\/login\?authn=/.test(screenAt) && screen.status === 200 &&
         !/id="password"/.test(screen.text) &&
         !/kc-email-code|kc-email-link/.test(screen.text) &&
         !/\/authn\/spnego\?/.test(screen.text) &&
         /\/authn\/wallet/.test(screen.text) &&
         /webauthn_only/.test(screen.text),
         'D. several allowed draw the screen with only those: a key and the ' +
         'wallet, no password, no emailed code, no Kerberos',
         screenAt + ' ' + screen.status);

    // --- E. The sign-in door ---------------------------------------------
    // With a key allowed the screen forces a passwordless key, so a posted
    // password is never read; with nothing on the screen allowed it draws no
    // form at all, and a password posted ANYWAY is what the door refuses.
    await w.inRealm(function () {
      m.ldap.createUser('mech-alice', { invent: false });
    });
    await make('mech-elsewhere');
    await add('mech-elsewhere', 'wallet');
    await add('mech-elsewhere', 'spnego');
    const elsewhereAt = await w.inRealm(function () {
      return m.authn.beginAuthentication({ returnTo: '/mech/after',
        protocol: 'mech-probe', application: 'mech-elsewhere' });
    });
    const other = w.browser();
    const bare = await w.request('GET', elsewhereAt, { browser: other });
    note(bare.status === 200 && !/id="username"/.test(bare.text) &&
         /not signed in to on this screen/.test(bare.text) &&
         /\/authn\/wallet/.test(bare.text),
         'E. nothing on the screen allowed: no username or password, only ' +
         'the doors it allows', elsewhereAt + ' ' + bare.status);
    const authnId = (/name="authn_id" value="([^"]+)"/.exec(bare.text) ||
                     [])[1];
    const refused = await w.request('POST', '/authn/login', {
      browser: other,
      form: { authn_id: authnId, username: 'mech-alice',
              password: 'anything', action: 'login' } });
    note(refused.code === 'STS-AUTHN-0298' && !w.sessionOf(other) &&
         /requires signing in with/.test(refused.text),
         'E. a password posted anyway is refused at the door, the screen ' +
         'drawn again saying what it allows',
         refused.status + ' ' + refused.code);

    // A browser holding an ordinary password session, for F and G.
    const signedIn = w.browser();
    const plainAt = await w.inRealm(function () {
      return m.authn.beginAuthentication({ returnTo: '/mech/after',
        protocol: 'mech-probe' });
    });
    const plain = await w.request('GET', plainAt, { browser: signedIn });
    const plainId = (/name="authn_id" value="([^"]+)"/.exec(plain.text) ||
                     [])[1];
    await w.request('POST', '/authn/login', {
      browser: signedIn,
      form: { authn_id: plainId, username: 'mech-alice',
              password: 'anything', action: 'login' } });
    note(!!w.sessionOf(signedIn),
         'F0. mech-alice signs in with a password for no application in ' +
         'particular');

    // --- F. OAuth ---------------------------------------------------------
    await w.inRealm(function () {
      m.config.setOverride('oauth2.consentRequired', 'false');
    });
    await make('mech-oauth', { 'field.oauthClientId': 'mech-oauth',
      'field.oauthRedirectUri': 'https://rp.mech.example/cb' });
    await add('mech-oauth', 'webauthn');
    await add('mech-oauth', 'wallet');
    const authorize = '/oauth2/authorize?response_type=code' +
      '&client_id=mech-oauth&scope=openid&state=s1&nonce=n1' +
      '&redirect_uri=' + encodeURIComponent('https://rp.mech.example/cb');
    const reprompt = await w.request('GET', authorize,
                                     { browser: signedIn });
    note(reprompt.status === 302 &&
         /\/authn\/login\?authn=/.test(String(reprompt.headers.location)) &&
         reprompt.code === 'STS-OAUTH-0945',
         'F. an authorization request on a password session, for a client ' +
         'allowing a key or a wallet, is sent to sign in again',
         reprompt.status + ' ' + reprompt.headers.location + ' ' +
         reprompt.code);
    const passive = await w.request('GET', authorize + '&prompt=none',
                                    { browser: signedIn });
    note(passive.status === 302 &&
         /^https:\/\/rp\.mech\.example\/cb\?.*error=login_required/
           .test(String(passive.headers.location)) &&
         passive.code === 'STS-OAUTH-0946',
         'F. with prompt=none it is login_required at the client instead',
         passive.status + ' ' + passive.headers.location);

    // --- G. WS-Federation -------------------------------------------------
    await make('urn:mech:wsfed', {
      'field.wsfedReplyUrl': 'https://rp.mech.example/wsfed' });
    await add('urn:mech:wsfed', 'webauthn');
    await add('urn:mech:wsfed', 'wallet');
    const signIn = '/wsfed?wa=wsignin1.0' +
      '&wtrealm=' + encodeURIComponent('urn:mech:wsfed') +
      '&wreply=' + encodeURIComponent('https://rp.mech.example/wsfed');
    const wsfed = await w.request('GET', signIn, { browser: signedIn });
    note(wsfed.status === 303 &&
         /\/authn\/login\?authn=/.test(String(wsfed.headers.location)) &&
         wsfed.code === 'STS-WSFED-0017',
         'G. a WS-Federation sign-in on a password session is sent to sign ' +
         'in again', wsfed.status + ' ' + wsfed.headers.location + ' ' +
         wsfed.code);
    const back = await w.request('GET', signIn + '&sts_mechanism_retry=1',
                                 { browser: signedIn });
    note(back.status === 403 && back.code === 'STS-WSFED-0018',
         'G. and refused when it comes back from that trip still unmet',
         back.status + ' ' + back.code);

    await w.inRealm(function () {
      m.config.clearOverride('krb5.spnegoAuthentication');
      m.config.clearOverride('oid4vp.signIn');
      m.config.clearOverride('oauth2.consentRequired');
    });
  }
}

async function run(t) {
  log.debug("Entering run().");
  kit.inAChild(t, childMain, 'authn-mechanism-enforcement');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'authn mechanism enforcement',
  describe: 'appAuthnMechanism as a list of allowed sign-in mechanisms, ' +
            'enforced at every browser sign-in by the issuance policy and ' +
            're-prompted for (#457)',
  run: run
};
