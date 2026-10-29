// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: wsfed_wauth_step_up.js
//
// ===========================================================================
// WS-FEDERATION `wauth` AS A STEP-UP (2026-09-17, #36).
//
// A `wauth` demanding a hardware token or multi-factor authentication, on a
// session that does not have it, was refused 400 (STS-WSFED-0009 / 0010).
// It is a step-up now, through the same two pieces RFC 9470 uses at the
// authorization endpoint — `beginAuthentication({ forceMfa })` and the
// `step_up_honoured` marker on the return — and the two refusals remain only
// for a demand still unmet after that one attempt. `ws-federation/wsfed.ts`
// argues it. Held here, in a child process on an ephemeral loopback port:
//
//   a. a password `wauth` on a one-factor session is answered at once;
//   b. a MULTI-FACTOR `wauth` on a one-factor session is sent to sign in
//      again — not refused — with the second factor demanded on the screen
//      and the marker on the return; a one-time code there yields an
//      assertion whose AuthenticationMethod is multipleauthn;
//   c. a HARDWARE `wauth` on that two-factor session (a one-time code, no
//      key) is sent to sign in again too — and since 2026-09-17 the screen
//      DEMANDS THE KEY (`forceKey`): the one-time code door refuses
//      (STS-AUTHN-0204), a person who holds a second factor and no key is
//      told so, and a demand still unmet on the way back is STS-WSFED-0009;
//   g. a real WebAuthn ceremony — a software authenticator built here, as
//      `tests/webauthn_session.js` does — meets the demand BOTH ways: a
//      passwordless key alone, and a key as the second factor after a
//      password. `step_up.screenDemandFor()` is the same mechanism the
//      authorization endpoint's key aliases use;
//   d. a forged marker on a first request gets the refusal (0010), not a pass
//      and not a loop;
//   e. with no session at all the demand still requires the second factor
//      and carries the marker;
//   f. an unknown `wauth` is refused as before (0006);
//   h. a one-time code posted at the second-factor door under the demand is
//      refused; i. `step_up.screenDemandFor()` is what both protocols read.
//   j. a passkey enrolled passwordless answers a key demand after a
//      password (#1135: a key has no role), as an assertion — never the
//      ceremony that would enrol one (#898).
//   k. a phr wauth on a one-factor session is one step-up (forceKey,
//      phishingClass empty) and a return that did not earn the class is
//      refused (STS-WSFED-0030), the code recorded and not sent. Two
//      class URIs in one wauth stay the unknown-method refusal;
//   l. a phrh wauth sets phishingClass phrh, and the same one-trip refusal;
//   m. a password wauth, a multi-factor wauth and a request with no wauth
//      still issue the class they issued before #737;
//   n. a passkey registration under phr earns nothing (0030); an assertion
//      with that key carries the phr URI on both token types, and a later
//      request that does not ask does not.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'wsfed_wauth_step_up',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.WA_ROOT;
  const OUT = process.env.WA_OUT;
  const http = require('http');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  const sleep = function (ms) {
    return new Promise(function (r) { setTimeout(r, ms); });
  };

  function browser(port) {
    const jar = {};
    const go = function (method, urlPath, opts) {
      const o = opts || {};
      return new Promise(function (resolve) {
        const body = o.form ? new URLSearchParams(o.form).toString() : '';
        const headers = Object.assign({}, o.headers || {});
        if (Object.keys(jar).length) {
          headers.cookie = Object.keys(jar).map(function (k) {
            return k + '=' + jar[k];
          }).join('; ');
        }
        if (method !== 'GET') {
          headers['content-type'] = 'application/x-www-form-urlencoded';
          headers['content-length'] = Buffer.byteLength(body);
        }
        const req = http.request({ host: '127.0.0.1', port: port,
                                   path: String(urlPath).replace(
                                     /^https?:\/\/[^/]+/, ''),
                                   method: method, headers: headers },
                                 function (res) {
          let text = '';
          (res.headers['set-cookie'] || []).forEach(function (line) {
            const pair = line.split(';')[0];
            const eq = pair.indexOf('=');
            jar[pair.slice(0, eq)] = pair.slice(eq + 1);
          });
          res.on('data', function (c) { text += c; });
          res.on('end', function () {
            resolve({ status: res.statusCode, headers: res.headers,
                      text: text });
          });
        });
        req.end(body);
      });
    };
    return { go: go, jar: jar };
  }
  // ---------------------------------------------------------------------
  // A SOFTWARE AUTHENTICATOR, `tests/webauthn_session.js`'s, built here for
  // the same reason it is built there: what is under test is the SERVER's
  // half of the ceremony, and producing the bytes a real authenticator
  // produces is the honest way to reach it. Enough CBOR for one attestation
  // object and a P-256 signature.
  // ---------------------------------------------------------------------
  const nodeCrypto = require('crypto');
  const sha256 = function (buf) {
    return nodeCrypto.createHash('sha256').update(buf).digest();
  };
  const cborBytes = function (buf) {
    const head = buf.length < 24 ? Buffer.from([0x40 + buf.length])
      : Buffer.concat([Buffer.from([0x58]), Buffer.from([buf.length])]);
    return Buffer.concat([head, buf]);
  };
  const cborText = function (text) {
    const body = Buffer.from(text, 'utf8');
    return Buffer.concat([Buffer.from([0x60 + body.length]), body]);
  };
  const cborMapHeader = function (n) {
    return Buffer.from([0xa0 + n]);
  };
  const cborInt = function (n) {
    return Buffer.from([n]);
  };
  const cborNegInt = function (n) {
    return Buffer.from([0x20 + (Math.abs(n) - 1)]);
  };
  const coseKey = function (jwk) {
    return Buffer.concat([
      cborMapHeader(5),
      cborInt(0x01), cborInt(0x02),
      cborInt(0x03), cborNegInt(-7),
      cborNegInt(-1), cborInt(0x01),
      cborNegInt(-2), cborBytes(Buffer.from(jwk.x, 'base64url')),
      cborNegInt(-3), cborBytes(Buffer.from(jwk.y, 'base64url'))
    ]);
  };
  const makeAuthenticator = function (rpId, origin) {
    const pair = nodeCrypto.generateKeyPairSync('ec',
                                                { namedCurve: 'prime256v1' });
    const jwk = pair.publicKey.export({ format: 'jwk' });
    const credentialId = nodeCrypto.randomBytes(32);
    let signCount = 0;
    const authData = function (opts) {
      const count = Buffer.alloc(4);
      count.writeUInt32BE(opts.signCount >>> 0, 0);
      const parts = [sha256(Buffer.from(rpId, 'utf8')),
                     Buffer.from([opts.flags]), count];
      if (opts.attested) {
        const idLen = Buffer.alloc(2);
        idLen.writeUInt16BE(credentialId.length, 0);
        parts.push(Buffer.alloc(16), idLen, credentialId, coseKey(jwk));
      }
      return Buffer.concat(parts);
    };
    const clientData = function (type, challenge) {
      return Buffer.from(JSON.stringify({ type: type, challenge: challenge,
                                          origin: origin,
                                          crossOrigin: false }), 'utf8');
    };
    return {
      credentialId: credentialId.toString('base64url'),
      register: function (challenge) {
        const data = authData({ flags: 0x45, signCount: signCount,
                                attested: true });
        const length = Buffer.alloc(2);
        length.writeUInt16BE(data.length, 0);
        const attestationObject = Buffer.concat([
          cborMapHeader(3),
          cborText('fmt'), cborText('none'),
          cborText('attStmt'), cborMapHeader(0),
          cborText('authData'),
          Buffer.concat([Buffer.from([0x59]), length, data])
        ]);
        return { id: credentialId.toString('base64url'),
                 rawId: credentialId.toString('base64url'),
                 type: 'public-key',
                 response: {
                   attestationObject: attestationObject.toString('base64url'),
                   clientDataJSON: clientData('webauthn.create', challenge)
                     .toString('base64url') } };
      },
      assert: function (challenge) {
        signCount += 1;
        const data = authData({ flags: 0x05, signCount: signCount });
        const cdj = clientData('webauthn.get', challenge);
        const signature = nodeCrypto.sign(
          'sha256', Buffer.concat([data, sha256(cdj)]), pair.privateKey);
        return { id: credentialId.toString('base64url'),
                 rawId: credentialId.toString('base64url'),
                 type: 'public-key',
                 response: {
                   authenticatorData: data.toString('base64url'),
                   clientDataJSON: cdj.toString('base64url'),
                   signature: signature.toString('base64url') } };
      }
    };
  };


  (async function () {
    require(ROOT + '/common/protocol_stack');
    // The sign-in screen over `/authn-api` since #571.
    const authnScreen = require(ROOT + '/tests/tools/authn_screen');
    const app = require(ROOT + '/common/app');
    const audit = require(ROOT + '/common/audit');
    const credentials = require(ROOT + '/common/credentials');
    const totp = require(ROOT + '/common/totp');
    const authn = require(ROOT + '/authn/authn');
    const realms = require(ROOT + '/common/realms');

    const config = require(ROOT + '/common/config');
    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    // Three one-time codes are spent below, each for a LATER 30-second step
    // than the last — a code for an earlier step than one already spent is a
    // replay — and two steps of skew keeps all three inside the window.
    config.setOverride('totp.window', 2);

    const REALM = 'urn:wauth-step-up:rp';
    const MFA = 'http://schemas.microsoft.com/claims/multipleauthn';
    const KEY = 'urn:oasis:names:tc:SAML:1.0:am:HardwareToken';
    const PASSWORD = 'urn:oasis:names:tc:SAML:1.0:am:password';
    const signInUrl = function (extra) {
      return '/wsfed?' + new URLSearchParams(Object.assign({
        // A stand-in reply address nothing answers at: the response is read
        // off the page. With none, and none registered, the sign-in is
        // refused since #592 deleted the mock relying party it went to.
        wa: 'wsignin1.0', wtrealm: REALM, wctx: 'ctx-1',
        wreply: 'https://rp.wauth-step-up.example/wsfed' },
        extra || {})).toString();
    };
    const toSignIn = function (r) {
      return (r.status === 302 || r.status === 303) &&
             /\/authn\/login/.test(String(r.headers.location || ''));
    };
    // The screen as a person uses it, answering every hop. `code` is the
    // one-time code for the second-factor screen, when it is shown.
    const signIn = async function (b, first, username, code) {
      // A STATIC PAGE SINCE #571: its view, and the act, whose step's page
      // is opened as the screen's page opens it.
      const page = await authnScreen.open({ port: port, jar: b.jar,
        at: String(first.headers.location) });
      let posted = await authnScreen.follow({ port: port, jar: b.jar,
        opened: page, fields: { action: 'login', username: username,
                                password: 'anything' } });
      let totpPage = null;
      // THE CODE PAGE IS THE SIGN-IN SURFACE'S (#572): its view, and the
      // code sent to its act.
      if (code && posted.view && posted.view.page === 'totp') {
        totpPage = posted;
        posted = await authnScreen.stepAct({ port: port, jar: b.jar,
          opened: posted, op: 'totp', body: { code: code } });
      }
      const back = String((posted.headers || {}).location || '')
        .replace(/^https?:\/\/[^/]+/, '');
      const final = back ? await b.go('GET', back) : posted;
      return { page: page, posted: posted, totpPage: totpPage, back: back,
               final: final };
    };
    const assertionSays = function (r, method) {
      return r.status === 200 && /wresult/.test(r.text) &&
             r.text.indexOf(method) >= 0;
    };
    const refusedWith = async function (code) {
      await sleep(50);
      return audit.list().some(function (row) {
        return row.errorCode === code;
      });
    };
    const codeCount = async function (code) {
      await sleep(50);
      return audit.list().filter(function (row) {
        return row.errorCode === code;
      }).length;
    };
    const pendingOf = function (location) {
      const found = /[?&]authn=([^&]+)/.exec(String(location || ''));
      if (!found) {
        return null;
      }
      return realms.run(realms.DEFAULT_REALM, function () {
        return authn.pendingFor(decodeURIComponent(found[1]));
      });
    };
    // The sign-in page xml-escapes the assertion into the form, so the
    // class is read back out of that escaping. A 200 page does not echo
    // wauth; a 400 refusal that quotes it does, and is not read this way.
    const classRefOf = function (text) {
      const found = /AuthnContextClassRef&gt;([^&]*)&lt;/.exec(String(text));
      return found ? found[1] : '';
    };
    const methodOf = function (text) {
      const found = /AuthenticationMethod=&quot;([^&]*)&quot;/.exec(
        String(text));
      return found ? found[1] : '';
    };

    // --- a. a one-factor session, and a password demand ----------------------
    const alice = browser(port);
    let first = await alice.go('GET', signInUrl());
    note(toSignIn(first), 'a0. (no session: to the sign-in screen)',
         first.status + ' ' + first.headers.location);
    let done = await signIn(alice, first, 'wa-alice');
    note(done.final.status === 200 && /wresult/.test(done.final.text),
         'a0b. (a password sign-in answers the relying party)',
         done.final.status);
    let r = await alice.go('GET', signInUrl({ wauth: PASSWORD }));
    note(assertionSays(r, PASSWORD),
         'a1. a password wauth on a one-factor session is answered at once',
         r.status + ' ' + r.text.slice(0, 120));

    // --- b. multi-factor: a step-up, not a refusal ---------------------------
    const began = credentials.beginTotpEnrolment('wa-alice');
    const t0 = Date.now();
    const confirmed = began.ok
      ? credentials.confirmTotpEnrolment('wa-alice',
                                         totp.codeAt(began.secret, t0))
      : began;
    note(began.ok && confirmed.ok, 'b0. (wa-alice enrols an authenticator ' +
         'app)', JSON.stringify(confirmed).slice(0, 200));
    first = await alice.go('GET', signInUrl({ wauth: MFA }));
    note(toSignIn(first),
         'b1. a MULTI-FACTOR wauth on a one-factor session is SENT TO SIGN ' +
         'IN AGAIN, not refused 400',
         first.status + ' ' + (first.headers.location || first.text
                                                                .slice(0, 200)));
    done = await signIn(alice, first, 'wa-alice',
                        totp.codeAt(began.secret, t0 + 30000));
    note(/step_up_honoured=1/.test(done.back),
         'b2. the return address carries the one-attempt marker', done.back);
    note(done.page.view && done.page.view.demands.mfa === true,
         'b3. the sign-in screen demands the second factor (its view: the ' +
         'passkey box checked and disabled)', '');
    note(done.totpPage !== null, 'b4. and asks for the one-time code',
         done.posted.status);
    note(assertionSays(done.final, MFA),
         'b5. the stepped-up sign-in answers the relying party with ' +
         'AuthenticationMethod multipleauthn — what actually happened',
         done.final.status + ' ' + done.final.text.slice(0, 200));
    r = await alice.go('GET', signInUrl({ wauth: MFA }));
    note(assertionSays(r, MFA),
         'b6. the same demand on the two-factor session is now met at once',
         r.status);

    // --- c. hardware: the screen demands the KEY -----------------------------
    first = await alice.go('GET', signInUrl({ wauth: KEY }));
    note(toSignIn(first),
         'c1. a HARDWARE wauth on a session that used a code and no key is ' +
         'sent to sign in again', first.status + ' ' + first.headers.location);
    const keyScreen = await authnScreen.open({ port: port, jar: alice.jar,
      at: String(first.headers.location) });
    const kv = keyScreen.view || { demands: {}, keys: {} };
    note(kv.demands.key === true && kv.demands.mfa === false &&
         kv.keys.mfaAllowed === true && kv.keys.primaryAllowed === true &&
         !kv.locked,
         'c2. and the screen offers EXACTLY the two choices that meet it — ' +
         'the key alone (passwordless, not disabled) or the key after a ' +
         'password (checked and disabled) — and says so (its view: the ' +
         'key demanded, two factors not, both boxes allowed)',
         JSON.stringify({ demands: kv.demands, keys: kv.keys }));
    const refusedNoKey = await authnScreen.submit({ port: port,
      jar: alice.jar, opened: keyScreen,
      fields: { action: 'login', username: 'wa-alice',
                password: 'anything' } });
    note(refusedNoKey.apiStatus === 400 &&
         /This request needs a passkey/.test(refusedNoKey.text),
         'c3. a person who holds a SECOND FACTOR and no key is told so ' +
         'rather than walked through a ceremony that would enrol one — the ' +
         'bypass that would be', refusedNoKey.status + ' ' +
         ((refusedNoKey.text.match(/class="err[^>]*>[^<]*/) || [''])[0]));
    note(await refusedWith('STS-AUTHN-0204'),
         'c4. with STS-AUTHN-0204');
    const forgedKey = await alice.go('GET', signInUrl({
      wauth: KEY, step_up_honoured: '1' }));
    note(forgedKey.status === 400 &&
         /No security key was used/.test(forgedKey.text),
         'c5. and a session that comes back with the marker and still no ' +
         'key is refused — one attempt, then the refusal',
         forgedKey.status + ' ' +
         ((forgedKey.text.match(/<title>[^<]*/) || [''])[0]));
    note(await refusedWith('STS-WSFED-0009'),
         'c6. with STS-WSFED-0009');

    // --- d. a forged marker ---------------------------------------------------
    const bob = browser(port);
    first = await bob.go('GET', signInUrl());
    await signIn(bob, first, 'wa-bob');
    r = await bob.go('GET', signInUrl({ wauth: MFA, step_up_honoured: '1' }));
    note(r.status === 400 && /Still one factor/.test(r.text),
         'd1. a marker forged onto a first request buys a refusal, not a ' +
         'pass and not a loop', r.status + ' ' + r.text.slice(0, 160));
    note(await refusedWith('STS-WSFED-0010'),
         'd2. and it carries STS-WSFED-0010');

    // --- e. no session ---------------------------------------------------------
    const carol = browser(port);
    first = await carol.go('GET', signInUrl({ wauth: MFA }));
    note(toSignIn(first),
         'e1. with no session the demand goes to the sign-in screen',
         first.headers.location);
    const page = await authnScreen.open({ port: port, jar: carol.jar,
      at: String(first.headers.location) });
    note(page.view && page.view.demands.mfa === true,
         'e2. and the screen demands the second factor from the start');

    // --- f. an unknown method ---------------------------------------------------
    r = await bob.go('GET', signInUrl({ wauth: 'urn:example:retina' }));
    note(r.status === 400 && /not available/.test(r.text) &&
         r.text.indexOf(KEY) >= 0,
         'f1. an unknown wauth is still refused, and the list of what is ' +
         'accepted now names the hardware token too', r.status);
    note(await refusedWith('STS-WSFED-0006'), 'f2. with STS-WSFED-0006');

    // --- g. a REAL ceremony meets the demand, both ways ----------------------
    // The screen's own data attributes carry what a browser would be given;
    // the authenticator below produces what one would produce.
    const withKey = async function (username, passwordless) {
      const b = browser(port);
      const start = await b.go('GET', signInUrl({ wauth: KEY }));
      const screen = await authnScreen.open({ port: port, jar: b.jar,
        at: String(start.headers.location) });
      const step = await authnScreen.follow({ port: port, jar: b.jar,
        opened: screen, fields: { action: 'login', username: username,
          password: passwordless ? '' : 'anything',
          webauthn_only: passwordless ? '1' : '' } });
      // THE CEREMONY IS ARMED AND ANSWERED OVER `/authn-api` (#572): what
      // the page's data attributes carried is `webauthn/options`' answer.
      let mode = '';
      const ran = await authnScreen.passkeyStep({ port: port, jar: b.jar,
        opened: step }, function (c) {
        mode = c.mode;
        const authenticator = makeAuthenticator(c.rpId,
                                                'http://127.0.0.1:' + port);
        return c.mode === 'create' ? authenticator.register(c.challenge)
                                   : authenticator.assert(c.challenge);
      });
      const done = ran.answer;
      const backTo = String(done.headers.location || '')
        .replace(/^https?:\/\/[^/]+/, '');
      const answer = backTo ? await b.go('GET', backTo) : done;
      return { screen: screen, step: step, mode: mode, done: done,
               answer: answer, browser: b };
    };
    const passwordlessKey = await withKey('wa-passkey', true);
    note(passwordlessKey.mode === 'create' &&
         (passwordlessKey.done.status === 302 ||
          passwordlessKey.done.status === 303) &&
         assertionSays(passwordlessKey.answer, KEY),
         'g1. a PASSWORDLESS security key — one factor, amr ["hwk"] — meets ' +
         'a hardware wauth, and the assertion says HardwareToken',
         passwordlessKey.done.status + ' ' +
         passwordlessKey.answer.status + ' ' +
         passwordlessKey.answer.text.slice(0, 160));
    const secondFactorKey = await withKey('wa-keypair', false);
    note(secondFactorKey.mode === 'create' &&
         assertionSays(secondFactorKey.answer, MFA),
         'g2. and so does a password AND a key — two factors, so the ' +
         'assertion says multipleauthn, which is what happened',
         secondFactorKey.answer.status + ' ' +
         secondFactorKey.answer.text.slice(0, 160));
    const again = await secondFactorKey.browser.go('GET',
      signInUrl({ wauth: KEY }));
    note(assertionSays(again, MFA),
         'g3. and the demand is met at once on that session afterwards',
         again.status);

    // --- h. the code door is shut while a key is demanded ---------------------
    const codeAttempt = await (async function () {
      const b = browser(port);
      const start = await b.go('GET', signInUrl({ wauth: KEY }));
      // Somebody who holds NO second factor: the demand takes them to the
      // key ceremony, which is the step a code is posted at below.
      const step = await authnScreen.follow({ port: port, jar: b.jar,
        at: String(start.headers.location),
        fields: { action: 'login', username: 'wa-codeless',
                  password: 'anything' } });
      // The code is sent to the step's code act (#572), as a hand-made
      // request would: the step is the key ceremony's.
      return authnScreen.stepAct({ port: port, jar: b.jar,
        opened: { prefix: '', id: step.id || 'none', csrf: step.csrf },
        op: 'totp',
        body: { code: totp.codeAt(began.secret, Date.now() + 90000) } });
    })();
    note(codeAttempt.status === 400 &&
         /demands a passkey/.test(codeAttempt.text),
         'h1. a ONE-TIME CODE posted at the second-factor door while a key ' +
         'is demanded is refused — the link is not drawn, and a link that ' +
         'is not drawn is still a URL',
         codeAttempt.status + ' ' + codeAttempt.text.slice(0, 200));

    // --- j. ANY passkey answers the demand (#898, #1135) --------------------
    // Until #1135 the key step offered mfa-role keys only, so a person
    // holding a second factor and a primary passkey but no mfa key was
    // handed the ENROLLING ceremony after a password alone — the bypass c3
    // refuses — and #898 refused them instead. A key has no role now: the
    // passkey they hold answers the demand, so the password sign-in goes on
    // to an ASSERTION of it, and still never to an enrolment.
    const primaryOnly = await withKey('wa-primary', true);
    const beganPrimary = credentials.beginTotpEnrolment('wa-primary');
    const confirmedPrimary = beganPrimary.ok
      ? credentials.confirmTotpEnrolment('wa-primary',
        totp.codeAt(beganPrimary.secret, Date.now()))
      : beganPrimary;
    note(primaryOnly.mode === 'create' && confirmedPrimary.ok,
         'j0. (wa-primary holds a passkey made passwordless and an ' +
         'authenticator app)',
         primaryOnly.mode + ' ' + JSON.stringify(confirmedPrimary)
           .slice(0, 160));
    const dave = browser(port);
    first = await dave.go('GET', signInUrl({ wauth: KEY }));
    const daveScreen = await authnScreen.open({ port: port, jar: dave.jar,
      at: String(first.headers.location) });
    const toKey = await authnScreen.submit({ port: port,
      jar: dave.jar, opened: daveScreen,
      fields: { action: 'login', username: 'wa-primary',
                password: 'anything' } });
    const keyPage = toKey.next === 'mfa'
      ? await authnScreen.openStep({ port: port, jar: dave.jar,
                                    at: toKey.location })
      : {};
    const keyView = (keyPage.view || {}).webauthn || {};
    note(toKey.next === 'mfa' && toKey.step === 'webauthn' &&
         keyView.mode === 'get',
         'j1. a password sign-in by somebody holding a second factor and a ' +
         'passkey enrolled passwordless goes on, under a key demand, to an ' +
         'ASSERTION of that passkey — any key answers either step since ' +
         '#1135 — and never to a ceremony that would enrol one (#898)',
         (toKey.next || toKey.apiStatus) + ' ' + toKey.step + ' ' +
         keyView.mode + ' ' + String(toKey.text || '').slice(0, 200));

    // --- i. one mechanism, named in step_up.ts --------------------------------
    const stepUp = require(ROOT + '/oauth-oidc/step_up');
    note(JSON.stringify(stepUp.screenDemandFor(['hwk'])) ===
           JSON.stringify({ forceMfa: true, forceKey: true }) &&
         JSON.stringify(stepUp.screenDemandFor(['mfa'])) ===
           JSON.stringify({ forceMfa: true, forceKey: false }) &&
         JSON.stringify(stepUp.screenDemandFor(['mfa', '1'])) ===
           JSON.stringify({ forceMfa: false, forceKey: false }) &&
         JSON.stringify(stepUp.screenDemand('key')) ===
           JSON.stringify({ forceMfa: false, forceKey: true }),
         'i1. the same mechanism answers for the authorization endpoint: ' +
         'acr_values naming only RFC 8176 key aliases forces the key too, ' +
         'while `mfa` forces a second factor and `mfa 1` forces nothing',
         JSON.stringify([stepUp.screenDemandFor(['hwk']),
                         stepUp.screenDemandFor(['mfa', '1'])]));

    // --- k–n. the EAP class URIs (#737) ------------------------------------
    // The same two URIs acr_values=phr / phrh name. wauth is one of them.
    const PHR = 'http://schemas.openid.net/pape/policies/2007/06/' +
      'phishing-resistant';
    const PHRH = 'http://schemas.openid.net/acr/2016/07/' +
      'phishing-resistant-hardware';
    const PPT = 'urn:oasis:names:tc:SAML:2.0:ac:classes:' +
      'PasswordProtectedTransport';
    const UNSPECIFIED = 'urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified';
    const beforeBoth = await codeCount('STS-WSFED-0006');
    r = await bob.go('GET', signInUrl({ wauth: PHR + ' ' + PHRH }));
    note(r.status === 400 && /not available/.test(r.text) &&
         await codeCount('STS-WSFED-0006') === beforeBoth + 1,
         'k0. two EAP URIs in one wauth are still one unknown value ' +
         '(STS-WSFED-0006): wauth is a single URI',
         r.status + ' ' + r.text.slice(0, 120));
    const beforePhr = await codeCount('STS-WSFED-0030');
    first = await bob.go('GET', signInUrl({ wauth: PHR }));
    const phrPending = pendingOf(first.headers.location);
    note(toSignIn(first) && !!phrPending && phrPending.forceKey === true &&
         phrPending.phishingClass === '' &&
         /step_up_honoured=1/.test(String(phrPending.returnTo || '')),
         'k1. a phr wauth on a one-factor session is one step-up: ' +
         'forceKey, phishingClass empty, the marker on the return',
         JSON.stringify({ status: first.status,
           forceKey: phrPending && phrPending.forceKey,
           phishingClass: phrPending && phrPending.phishingClass,
           returnTo: phrPending && phrPending.returnTo }));
    const phrBack = phrPending
      ? await bob.go('GET', String(phrPending.returnTo || '/'))
      : { status: 0, text: '', headers: {} };
    note(phrBack.status === 400 &&
         /The class was not earned/.test(phrBack.text) &&
         phrBack.text.indexOf('hardware-protected') < 0 &&
         phrBack.text.indexOf('STS-WSFED-0030') < 0 &&
         phrBack.text.indexOf(PHR) >= 0 && !toSignIn(phrBack),
         'k2. coming back without earning the class is the refusal page, ' +
         'once, and the code is not in the body',
         phrBack.status + ' ' +
         ((phrBack.text.match(/<title>[^<]*/) || [''])[0]));
    note(await codeCount('STS-WSFED-0030') === beforePhr + 1,
         'k3. and STS-WSFED-0030 is recorded');

    const beforePhrh = await codeCount('STS-WSFED-0030');
    first = await bob.go('GET', signInUrl({ wauth: PHRH }));
    const phrhPending = pendingOf(first.headers.location);
    note(toSignIn(first) && !!phrhPending &&
         phrhPending.forceKey === true &&
         phrhPending.phishingClass === 'phrh',
         'l1. a phrh wauth forces a key and sets phishingClass phrh',
         JSON.stringify({
           forceKey: phrhPending && phrhPending.forceKey,
           phishingClass: phrhPending && phrhPending.phishingClass }));
    const phrhBack = phrhPending
      ? await bob.go('GET', String(phrhPending.returnTo || '/'))
      : { status: 0, text: '' };
    note(phrhBack.status === 400 &&
         /The class was not earned/.test(phrhBack.text) &&
         /hardware-protected/.test(phrhBack.text) &&
         phrhBack.text.indexOf('STS-WSFED-0030') < 0 &&
         !toSignIn(phrhBack) &&
         await codeCount('STS-WSFED-0030') === beforePhrh + 1,
         'l2. still unmet after the one trip is the same refusal, and ' +
         'STS-WSFED-0030 is recorded again',
         phrhBack.status + ' ' + String(phrhBack.text || '').slice(0, 180));

    r = await bob.go('GET', signInUrl({ wauth: PASSWORD,
                                        tokenType: 'saml2' }));
    note(r.status === 200 && classRefOf(r.text) === PPT &&
         r.text.indexOf(PHR) < 0 && r.text.indexOf(PHRH) < 0,
         'm1. a password wauth still issues PasswordProtectedTransport, ' +
         'with neither EAP URI',
         r.status + ' ' + classRefOf(r.text));
    r = await bob.go('GET', signInUrl({ tokenType: 'saml2' }));
    note(r.status === 200 && classRefOf(r.text) === PPT &&
         r.text.indexOf(PHR) < 0 && r.text.indexOf(PHRH) < 0,
         'm2. a request with no wauth is unchanged',
         classRefOf(r.text));
    r = await alice.go('GET', signInUrl({ wauth: MFA, tokenType: 'saml2' }));
    note(r.status === 200 && classRefOf(r.text) === MFA &&
         r.text.indexOf(PHR) < 0 && r.text.indexOf(PHRH) < 0,
         'm3. a multi-factor wauth still issues multipleauthn',
         classRefOf(r.text));
    r = await bob.go('GET', signInUrl({ wauth: PASSWORD }));
    note(r.status === 200 && methodOf(r.text) === PASSWORD &&
         r.text.indexOf(PHR) < 0 && r.text.indexOf(PHRH) < 0,
         'm4. the default SAML 1.1 token keeps am:password',
         methodOf(r.text));

    // A registration earns nothing, so the first passwordless sign-in
    // under phr comes back to the refusal. The same key asserted in a
    // new browser earns phr and not phrh (fmt none, no trusted attestation).
    let phrKey = null;
    const usePhrKey = function (c) {
      if (!phrKey) {
        phrKey = makeAuthenticator(c.rpId, 'http://127.0.0.1:' + port);
      }
      return c.mode === 'create' ? phrKey.register(c.challenge)
                                 : phrKey.assert(c.challenge);
    };
    const passkeyAnswer = async function (username, wauth, extra) {
      const b = browser(port);
      const start = await b.go('GET', signInUrl(Object.assign(
        { wauth: wauth }, extra || {})));
      if (!toSignIn(start)) {
        return { start: start, mode: '', answer: start, browser: b,
                 pending: pendingOf(start.headers.location) };
      }
      // takePending() drops the record once the passkey step is minted,
      // so the class this request armed is read before the ceremony.
      const pending = pendingOf(start.headers.location);
      const screen = await authnScreen.open({ port: port, jar: b.jar,
        at: String(start.headers.location) });
      const step = await authnScreen.follow({ port: port, jar: b.jar,
        opened: screen, fields: { action: 'login', username: username,
          password: '', webauthn_only: '1' } });
      let mode = '';
      const ran = await authnScreen.passkeyStep({ port: port, jar: b.jar,
        opened: step }, function (c) {
        mode = c.mode;
        return usePhrKey(c);
      });
      const done = ran.answer || {};
      const backTo = String((done.headers && done.headers.location) ||
                            '')
        .replace(/^https?:\/\/[^/]+/, '');
      const answer = backTo ? await b.go('GET', backTo) : done;
      return { start: start, mode: mode, answer: answer, browser: b,
               pending: pending };
    };
    const beforeN = await codeCount('STS-WSFED-0030');
    const n1 = await passkeyAnswer('wa-phr', PHR);
    note(n1.mode === 'create' && n1.pending &&
         n1.pending.forceKey === true && n1.pending.phishingClass === '' &&
         n1.answer.status === 400 &&
         /The class was not earned/.test(n1.answer.text) &&
         n1.answer.text.indexOf('STS-WSFED-0030') < 0 &&
         await codeCount('STS-WSFED-0030') === beforeN + 1,
         'n1. a registration under phr earns nothing: one trip, then the ' +
         'class was not earned (STS-WSFED-0030)',
         n1.mode + ' ' + n1.answer.status + ' ' +
         String(n1.answer.text || '').slice(0, 160));
    const n2 = await passkeyAnswer('wa-phr', PHR, { tokenType: 'saml2' });
    note(n2.mode === 'get' && n2.answer.status === 200 &&
         classRefOf(n2.answer.text) === PHR &&
         n2.answer.text.indexOf(PHRH) < 0,
         'n2. an assertion with the same key earns phr, and the SAML 2.0 ' +
         'class ref is that URI',
         n2.mode + ' ' + n2.answer.status + ' ' +
         classRefOf(n2.answer.text));
    const n3 = await n2.browser.go('GET', signInUrl({ wauth: PHR }));
    note(n3.status === 200 && methodOf(n3.text) === PHR && !toSignIn(n3),
         'n3. the same session meets phr at once, and the SAML 1.1 ' +
         'AuthenticationMethod is that URI',
         n3.status + ' ' + methodOf(n3.text));
    const n4 = await n2.browser.go('GET', signInUrl({ tokenType: 'saml2' }));
    note(n4.status === 200 && classRefOf(n4.text) === UNSPECIFIED &&
         n4.text.indexOf(PHR) < 0 && n4.text.indexOf(PHRH) < 0,
         'n4. a request that does not ask keeps unspecified, even though ' +
         'the session earned phr',
         classRefOf(n4.text));

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

function inAChild(t) {
  log.debug("Entering inAChild().");
  const out = path.join(os.tmpdir(), 'wauth-' + process.pid + '-' +
                        require('crypto').randomBytes(8).toString('hex') +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', WA_ROOT: ROOT, WA_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
    // No report: the child died before writing one. Reported below with its
    // exit status and stderr, which is where the reason is.
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written, which the read above has already reported.
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings), 'the child process reported its ' +
                                        'findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-800))) {
    log.debug("Leaving inAChild().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving inAChild().");
}

async function run(t) {
  log.debug("Entering run().");
  inAChild(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'wsfed_wauth_step_up',
  describe: 'WS-Federation wauth: a hardware, multi-factor or EAP-class ' +
            'demand the session cannot meet is one step-up through the ' +
            'sign-in, the assertion reports what happened, and a demand ' +
            'still unmet after that attempt is refused with its code',
  run: run
};
