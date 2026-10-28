// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/passkey_post_quantum_fallback.js
//
// ===========================================================================
// WHEN AN ML-DSA REGISTRATION FAILS (#944), AND LIST-AND-REFUSE WHERE A
// POST-QUANTUM PASSKEY IS REQUIRED (#946).
//
// Asserted with REAL ceremonies from a software authenticator that signs
// ES256 and ML-DSA (`webauthn_attestation_kit.js`'s keys), in a CHILD
// PROCESS serving the stack on a loopback port —
// `passkey_post_quantum_required.js`'s harness, whose design this extends:
//
//   A. THE RETRY'S RULE (`webauthn_policy.ts`): allowed by default, its list
//      the configured one less ML-DSA; refused (STS-AUTHN-0420) under
//      `webauthn.pqcOnly` and under `registration-and-sign-in`, and at the
//      sign-in step under `sign-in` too; the flag IGNORED where refused, so
//      nothing classical is asked for; the classical lane while both lanes
//      are on.
//   B. `/portal/keys`: the view's `fallback` facts; a retry begun with
//      `classicalOnly` registers an ES256 key, and an ML-DSA credential
//      answering it is refused as not offered (STS-AUTHN-0228); a retry
//      refused under `pqcOnly`; the page draws the hidden guidance — the
//      retry form where allowed, the "cannot make" sentence where not.
//   C. THE SIGN-IN STEP: a person setting up a passkey at sign-in arms the
//      classical retry through `POST /authn-api/mfa/{id}/webauthn/options`
//      (`algorithms: classical`), registers an ES256 key and is signed in;
//      under a profile requiring a post-quantum passkey at sign-in the same
//      request is refused (400, STS-AUTHN-0420) and the page offers none.
//   D. #946: `narrow` (the default) names only the post-quantum key;
//      `webauthn.postQuantumAllowCredentials: list-and-refuse` names both, a
//      classical assertion is refused after the ceremony (STS-AUTHN-0356, a
//      `session.refuse` row, NO `session.start` row) and the screen's view
//      carries the panel's link (registration; #939's upgrade link went with
//      the portal's Upgrade button, #1100), and the
//      post-quantum key signs in; the profile's row
//      overrides the realm's setting both ways; the question carries the
//      resolved value; a person holding only classical keys is still told
//      before the ceremony, with the panel.
//   E. THE BROWSER'S HALF, with stand-ins: `failureKind()`,
//      `offerFallback()` showing the right parts (the hybrid line only
//      where `getClientCapabilities()` reports `hybridTransport`), reporting
//      every failure to `reportCeremonyFailure()` (the #943 hook) and
//      leaving the page alone for an error it is not for; the renderers'
//      markup. Since #961 a portal create whose guidance is shown reports
//      the finish without submitting `#wa-form`, and the account API leaves
//      that enrolment; an error the guidance does not handle still submits
//      and abandons it. That submit carries only the error name. The quiet
//      report still carries the platform's capabilities. The same report
//      while the retry is not offered is still abandoned.
// ===========================================================================

delete process.env.CONFIG_FILE;

const path = require('path');
const os = require('os');
const fs = require('fs');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'passkey_post_quantum_fallback',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// Runs in the child. Stringified, so it may use nothing from this file's
// scope, and — code in a `node -e` child — is exempt from the Entering/Leaving
// rule (root CLAUDE.md, *Code style*).
function childMain() {
  const ROOT = process.env.PQF_ROOT;
  const OUT = process.env.PQF_OUT;
  const http = require('http');
  const nodeCrypto = require('crypto');
  const kit = require(ROOT + '/tests/webauthn_attestation_kit');
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };

  function browser(port) {
    const jar = {};
    const go = function (method, urlPath) {
      return new Promise(function (resolve) {
        const headers = {};
        if (Object.keys(jar).length) {
          headers.cookie = Object.keys(jar).map(function (k) {
            return k + '=' + jar[k];
          }).join('; ');
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
        req.end();
      });
    };
    return { go: go, jar: jar };
  }

  // A SOFTWARE AUTHENTICATOR OVER THE KIT'S KEYS, the required test's.
  const sha256 = function (buf) {
    return nodeCrypto.createHash('sha256').update(buf).digest();
  };
  const makeAuthenticator = async function (alg, rpId, origin) {
    const cred = await kit.credential(alg);
    let signCount = 0;
    let userHandle = '';
    const clientData = function (type, challenge) {
      return Buffer.from(JSON.stringify({ type: type, challenge: challenge,
                                          origin: origin,
                                          crossOrigin: false }), 'utf8');
    };
    const id = cred.id.toString('base64url');
    return {
      credentialId: id,
      register: function (challenge, handle) {
        userHandle = handle;
        const count = Buffer.alloc(4);
        const idLen = Buffer.alloc(2);
        idLen.writeUInt16BE(cred.id.length, 0);
        const data = Buffer.concat([sha256(Buffer.from(rpId, 'utf8')),
          Buffer.from([0x45]), count, Buffer.alloc(16), idLen, cred.id,
          kit.cbor(cred.cose)]);
        const attestationObject = kit.cbor(new Map([['fmt', 'none'],
          ['attStmt', new Map()], ['authData', data]]));
        return { id: id, rawId: id, type: 'public-key',
                 authenticatorAttachment: 'platform',
                 clientExtensionResults: { credProps: { rk: true } },
                 response: {
                   attestationObject: attestationObject.toString('base64url'),
                   clientDataJSON: clientData('webauthn.create', challenge)
                     .toString('base64url') } };
      },
      assert: function (challenge) {
        signCount += 1;
        const count = Buffer.alloc(4);
        count.writeUInt32BE(signCount, 0);
        const data = Buffer.concat([sha256(Buffer.from(rpId, 'utf8')),
                                    Buffer.from([0x05]), count]);
        const cdj = clientData('webauthn.get', challenge);
        const signature = cred.sign(Buffer.concat([data, sha256(cdj)]));
        return { id: id, rawId: id, type: 'public-key',
                 response: {
                   authenticatorData: data.toString('base64url'),
                   clientDataJSON: cdj.toString('base64url'),
                   signature: Buffer.from(signature).toString('base64url'),
                   userHandle: userHandle || null } };
      }
    };
  };

  // A translator that names its keys, so drawn markup shows which catalog
  // message it chose.
  const T = {
    html: function (key) {
      return '[' + key + ']';
    },
    text: function (key) {
      return key;
    }
  };

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const config = require(ROOT + '/common/config');
    const passkeyPolicy = require(ROOT + '/common/passkey_policy');
    const authnPolicy = require(ROOT + '/common/authn_policy');
    const applications = require(ROOT + '/common/applications');
    const credentials = require(ROOT + '/common/credentials');
    const webauthnPolicy = require(ROOT + '/authn/webauthn_policy');
    const errorCodes = require(ROOT + '/common/error_codes');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const audit = require(ROOT + '/common/audit');
    const accountKeys = require(ROOT + '/portal/account_keys');
    const keysPages = require(ROOT + '/portal/web_keys');
    const authnScreen = require(ROOT + '/tests/tools/authn_screen');
    const WebWebAuthn = require(ROOT + '/common/web_webauthn');
    const PortalWebAuthn = require(ROOT + '/portal/web_portal_webauthn');
    const PortalRuntime = require(ROOT + '/portal/web_portal_runtime');
    const WebAuthnLogin = require(ROOT + '/authn/web_authn_login');
    const WebAuthnMfa = require(ROOT + '/authn/web_authn_mfa');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const ORIGIN = 'http://127.0.0.1:' + port;
    const RPID = '127.0.0.1';
    const REDIRECT = 'https://rp.pqf.example/cb';
    const PASSWORD = 'correct-horse-battery-staple-pqf-7!';
    const CLIENT = 'pqf-app';
    const PQ_IDS = [-48, -49, -50];
    config.setOverride('oauth2.consentRequired', false);

    applications.createApplication({ identifier: CLIENT,
      protocols: ['oauth2'],
      fields: { oauthClientId: CLIENT, oauthClientSecret: '',
                oauthRedirectUri: [REDIRECT],
                oauthTokenEndpointAuthMethod: 'none',
                oauthGrantType: ['authorization_code'] } });
    ['pqf-ann', 'pqf-ben', 'pqf-cat', 'pqf-dan', 'pqf-eve', 'pqf-fay']
      .forEach(function (name) {
        ldap.createUser(name, { invent: false });
        credentials.setPassword(name, PASSWORD);
      });

    const withDefaults = function (fields) {
      return Object.assign({}, passkeyPolicy.DEFAULTS,
                           { allowUsernameless: true }, fields || {});
    };
    const rows = function (action, name, code) {
      return audit.list().filter(function (row) {
        return row.action === action && String(row.actor) === name &&
               (!code || row.errorCode === code);
      }).length;
    };
    const noPq = function (ids) {
      return (ids || []).length > 0 && (ids || []).every(function (id) {
        return PQ_IDS.indexOf(Number(id)) < 0;
      });
    };
    const screenFor = async function () {
      const b = browser(port);
      const verifier = nodeCrypto.randomBytes(32).toString('base64url');
      const start = await b.go('GET', '/oauth2/authorize?' +
        new URLSearchParams({ client_id: CLIENT, response_type: 'code',
          redirect_uri: REDIRECT, scope: 'openid', state: 's',
          nonce: 'n-' + nodeCrypto.randomBytes(8).toString('hex'),
          code_challenge: nodeCrypto.createHash('sha256').update(verifier)
            .digest('base64url'),
          code_challenge_method: 'S256' }).toString());
      const opened = await authnScreen.open({ port: port, jar: b.jar,
        at: String(start.headers.location || '') });
      return { b: b, opened: opened };
    };
    const firstStep = async function (name, passwordless) {
      const s = await screenFor();
      const step = await authnScreen.follow({ port: port, jar: s.b.jar,
        opened: s.opened, fields: { action: 'login', username: name,
          password: passwordless ? '' : PASSWORD,
          webauthn_only: passwordless ? '1' : '' } });
      return { s: s, step: step };
    };
    const enrol = async function (name, opts, make) {
      const begun = credentials.beginKeyEnrolment(name, opts);
      if (!begun.ok) {
        return { begun: begun, done: begun };
      }
      const done = await credentials.confirmKeyEnrolment(name,
        begun.enrolmentId, make(begun), { origin: ORIGIN, rpId: RPID });
      if (!done.ok) {
        credentials.abandonKeyEnrolment(name);
      }
      return { begun: begun, done: done };
    };
    const keysView = function (name) {
      const keys = new accountKeys.AccountKeys(
        accountKeys.AccountKeys.defaultDeps());
      return passkeyPolicy.withSelection(name, '', function () {
        return keys.view({ username: name,
                           session: { user: { name: name } } }, ORIGIN);
      });
    };

    // ======================================================================
    // A. The retry's rule.
    // ======================================================================
    passkeyPolicy.save('default', withDefaults());
    const plain = webauthnPolicy.classicalRetryRefusal();
    const retryList = webauthnPolicy.algorithmsOffered('', true);
    const retryOptions = webauthnPolicy.creationOptions(RPID, 'passkey',
                                                        'classical', true);
    note(plain.ok && webauthnPolicy.classicalFallbackOffered('classical') &&
         retryList.length > 0 && retryList.every(function (name) {
           return !/^ML-DSA/.test(name);
         }) && noPq(retryOptions.algorithms) &&
         webauthnPolicy.asksPostQuantum('classical') &&
         !webauthnPolicy.asksPostQuantum('classical', true),
         'A1. by default the classical retry is allowed and offered, and ' +
         'its list is the configured one less ML-DSA',
         JSON.stringify([retryList, retryOptions.algorithms]));
    config.setOverride('webauthn.pqcOnly', true);
    const onlyRefused = webauthnPolicy.classicalRetryRefusal();
    const onlyList = webauthnPolicy.algorithmsOffered('', true);
    note(!onlyRefused.ok &&
         errorCodes.codeOf(onlyRefused) === 'STS-AUTHN-0420' &&
         onlyList.length > 0 && onlyList.every(function (name) {
           return /^ML-DSA/.test(name);
         }) && !webauthnPolicy.classicalFallbackOffered('classical'),
         'A2. under webauthn.pqcOnly it is refused (STS-AUTHN-0420), not ' +
         'offered, and the flag is ignored: only ML-DSA is asked for',
         JSON.stringify([onlyRefused, onlyList]));
    config.clearOverride('webauthn.pqcOnly');
    passkeyPolicy.save('default', withDefaults({
      postQuantumRequired: 'registration-and-sign-in' }));
    const regRefused = webauthnPolicy.classicalRetryRefusal();
    passkeyPolicy.save('default', withDefaults({
      postQuantumRequired: 'sign-in' }));
    const signInPortal = webauthnPolicy.classicalRetryRefusal();
    const signInStep = webauthnPolicy.classicalRetryRefusal('sign-in');
    note(!regRefused.ok &&
         errorCodes.codeOf(regRefused) === 'STS-AUTHN-0420' &&
         signInPortal.ok && !signInStep.ok &&
         errorCodes.codeOf(signInStep) === 'STS-AUTHN-0420' &&
         webauthnPolicy.classicalFallbackOffered('classical') &&
         !webauthnPolicy.classicalFallbackOffered('classical', 'sign-in'),
         'A3. registration-and-sign-in refuses it everywhere; sign-in ' +
         'refuses it at the sign-in step only, whose key would sign nobody ' +
         'in', JSON.stringify([regRefused, signInPortal, signInStep]));
    passkeyPolicy.save('default', withDefaults());
    config.setOverride('webauthn.pqcAlongsideClassical', true);
    const laneOn = webauthnPolicy.classicalRetryLane('pqc');
    // #939's upgrade is offered by the realm (no switch since #1100, the
    // post-login policy decides who is asked), including while the two
    // lanes run alongside. Alongside decides where the new key is written.
    const offeredAlongside = webauthnPolicy.postQuantumUpgradeOffered();
    config.clearOverride('webauthn.pqcAlongsideClassical');
    const offered = webauthnPolicy.postQuantumUpgradeOffered();
    note(laneOn === 'classical' &&
         webauthnPolicy.classicalRetryLane('classical') === 'classical' &&
         offeredAlongside === true && offered === true,
         'A4. with both lanes on the retry is made in the classical lane, ' +
         'and #939\'s upgrade stays offered',
         JSON.stringify({ lane: laneOn, offeredAlongside: offeredAlongside,
                          offered: offered }));

    // ======================================================================
    // B. /portal/keys.
    // ======================================================================
    credentials.beginKeyEnrolment('pqf-ann', { role: 'primary',
                                              kind: 'passkey' });
    const firstView = (keysView('pqf-ann').enrol || {}).pending || {};
    const firstDrawn = keysPages.enrolBlock(keysView('pqf-ann'), T);
    credentials.abandonKeyEnrolment('pqf-ann');
    note(JSON.stringify(firstView.fallback) ===
           JSON.stringify({ asksPostQuantum: true, classical: true,
                            retrying: false }) &&
         firstDrawn.indexOf('id="wa-fallback" hidden') >= 0 &&
         firstDrawn.indexOf('[portal.key.retryClassical]') >= 0 &&
         firstDrawn.indexOf('name="algorithms" value="classical"') >= 0 &&
         firstDrawn.indexOf('[portal.key.cannotMake]') < 0,
         'B1. a waiting registration carries the fallback facts, and the ' +
         'page draws the hidden guidance with the retry form',
         JSON.stringify(firstView.fallback) + ' ' + firstDrawn.length);
    const annKey = await makeAuthenticator(-7, RPID, ORIGIN);
    let viewDuring = null;
    const retried = await enrol('pqf-ann', { role: 'primary',
                                             kind: 'passkey',
                                             classicalOnly: true },
      function (b) {
        viewDuring = (keysView('pqf-ann').enrol || {}).pending || {};
        return annKey.register(b.challenge, b.userHandle);
      });
    note(retried.begun.ok && retried.begun.classicalOnly === true &&
         retried.done.ok &&
         viewDuring && viewDuring.fallback &&
         viewDuring.fallback.retrying === true &&
         viewDuring.fallback.classical === false &&
         noPq((viewDuring.options || {}).algorithms) &&
         keysPages.fallback(viewDuring, T) === '',
         'B2. a retry begun with the classical algorithms only asks for no ' +
         'ML-DSA, draws no guidance of its own, and registers an ES256 key',
         JSON.stringify([retried.begun.ok, retried.done.ok,
                         viewDuring && viewDuring.fallback]));
    const annPq = await makeAuthenticator(-49, RPID, ORIGIN);
    const wrong = await enrol('pqf-ann', { role: 'primary', kind: 'passkey',
                                           classicalOnly: true },
      function (b) {
        return annPq.register(b.challenge, b.userHandle);
      });
    note(!wrong.done.ok && errorCodes.codeOf(wrong.done) === 'STS-AUTHN-0228',
         'B3. an ML-DSA credential answering the classical retry is refused ' +
         'as an algorithm not offered (STS-AUTHN-0228)',
         JSON.stringify(wrong.done));
    config.setOverride('webauthn.pqcOnly', true);
    const refusedBegin = credentials.beginKeyEnrolment('pqf-ann',
      { role: 'primary', classicalOnly: true });
    credentials.beginKeyEnrolment('pqf-ann', { role: 'primary' });
    const onlyDrawn = keysPages.enrolBlock(keysView('pqf-ann'), T);
    credentials.abandonKeyEnrolment('pqf-ann');
    config.clearOverride('webauthn.pqcOnly');
    note(!refusedBegin.ok &&
         errorCodes.codeOf(refusedBegin) === 'STS-AUTHN-0420' &&
         refusedBegin.reason === 'algorithms' &&
         onlyDrawn.indexOf('[portal.key.cannotMake]') >= 0 &&
         onlyDrawn.indexOf('[portal.key.retryClassical]') < 0,
         'B4. under webauthn.pqcOnly the retry is refused at the begin ' +
         '(STS-AUTHN-0420), and the page says this device cannot make the ' +
         'required key instead of offering it',
         JSON.stringify(refusedBegin) + ' ' + onlyDrawn.length);

    // ======================================================================
    // C. The sign-in step.
    // ======================================================================
    authnPolicy.save('default', Object.assign({}, authnPolicy.DEFAULTS,
      { requireSecondFactor: 'always' }));
    const setupFor = async function (name) {
      const f = await firstStep(name, false);
      const chosen = await authnScreen.stepAct({ port: port, jar: f.s.b.jar,
        opened: f.step, op: 'setup/webauthn', body: {} });
      const page = chosen.next === 'mfa'
        ? await authnScreen.openStep({ port: port, jar: f.s.b.jar,
                                       at: chosen.location })
        : null;
      return { f: f, chosen: chosen, page: page,
               w: (page && page.view && page.view.webauthn) || {} };
    };
    const ben = await setupFor('pqf-ben');
    const benKey = await makeAuthenticator(-7, RPID, ORIGIN);
    const armed = ben.page ? await authnScreen.stepAct({ port: port,
      jar: ben.f.s.b.jar, opened: ben.page, op: 'webauthn/options',
      body: { algorithms: 'classical' } }) : { json: null };
    const c = armed.json || {};
    const finished = c.ok ? await authnScreen.stepAct({ port: port,
      jar: ben.f.s.b.jar, opened: ben.page, op: 'webauthn',
      body: { credential: JSON.stringify(benKey.register(c.challenge,
        (c.user || {}).id)) } }) : { next: '' };
    note(ben.w.mode === 'create' && ben.w.fallback &&
         ben.w.fallback.classical === true &&
         c.ok && c.fallback && c.fallback.retrying === true &&
         noPq((c.options || {}).algorithms) &&
         finished.next === 'redirect' &&
         credentials.keysOf('pqf-ben').some(function (one) {
           return one.credentialId === benKey.credentialId;
         }),
         'C1. at the sign-in step the classical retry is armed through the ' +
         'API, asks for no ML-DSA, registers an ES256 key and signs them in',
         JSON.stringify([ben.w.mode, ben.w.fallback, c.fallback,
                         (c.options || {}).algorithms, finished.next]));
    passkeyPolicy.save('default', withDefaults({
      postQuantumRequired: 'sign-in' }));
    const dan = await setupFor('pqf-dan');
    const danArmed = dan.page ? await authnScreen.stepAct({ port: port,
      jar: dan.f.s.b.jar, opened: dan.page, op: 'webauthn/options',
      body: { algorithms: 'classical' } }) : { apiStatus: 0, text: '' };
    const danDrawn = WebAuthnMfa.fallback(dan.w.fallback, T);
    note(dan.w.mode === 'create' && dan.w.fallback &&
         dan.w.fallback.classical === false &&
         danArmed.apiStatus === 400 &&
         /would not sign you in/.test(danArmed.text) &&
         danDrawn.indexOf('[authn.webauthn.cannotMake]') >= 0 &&
         danDrawn.indexOf('wa-retry-classical') < 0,
         'C2. under a profile requiring a post-quantum passkey at sign-in ' +
         'the step offers no retry, and one asked for anyway is refused ' +
         '(400, STS-AUTHN-0420)', JSON.stringify(dan.w.fallback) + ' ' +
         danArmed.apiStatus + ' ' + String(danArmed.text).slice(0, 200));
    authnPolicy.reset('default');
    passkeyPolicy.save('default', withDefaults());

    // ======================================================================
    // D. #946: narrow, list-and-refuse.
    // ======================================================================
    const catClassical = await makeAuthenticator(-7, RPID, ORIGIN);
    const catPq = await makeAuthenticator(-48, RPID, ORIGIN);
    const eveKey = await makeAuthenticator(-7, RPID, ORIGIN);
    await enrol('pqf-cat', { role: 'primary' }, function (b) {
      return catClassical.register(b.challenge, b.userHandle);
    });
    await enrol('pqf-cat', { role: 'primary' }, function (b) {
      return catPq.register(b.challenge, b.userHandle);
    });
    await enrol('pqf-eve', { role: 'primary' }, function (b) {
      return eveKey.register(b.challenge, b.userHandle);
    });
    const allowOf = async function (name) {
      const f = await firstStep(name, true);
      const armedHere = await authnScreen.stepAct({ port: port,
        jar: f.s.b.jar, opened: f.step, op: 'webauthn/options', body: {} });
      return { f: f, armed: armedHere,
               allow: ((armedHere.json || {}).allow || []).slice().sort() };
    };
    passkeyPolicy.save('default', withDefaults({
      postQuantumRequired: 'sign-in' }));
    const narrowed = await allowOf('pqf-cat');
    note(JSON.stringify(narrowed.allow) ===
           JSON.stringify([catPq.credentialId]) &&
         passkeyPolicy.postQuantumAllowCredentials() === 'narrow',
         'D1. narrow, the default: the step names only the post-quantum key',
         JSON.stringify(narrowed.allow));
    config.setOverride('webauthn.postQuantumAllowCredentials',
                       'list-and-refuse');
    const listed = await allowOf('pqf-cat');
    const refusedBefore = rows('session.refuse', 'pqf-cat', 'STS-AUTHN-0356');
    const startsBefore = rows('session.start', 'pqf-cat');
    const classicalAnswer = listed.armed.json && listed.armed.json.ok
      ? await authnScreen.stepAct({ port: port, jar: listed.f.s.b.jar,
          opened: listed.f.step, op: 'webauthn',
          body: { credential: JSON.stringify(catClassical.assert(
            listed.armed.json.challenge)) } })
      : { next: '', location: '' };
    const screen = classicalAnswer.location
      ? await authnScreen.open({ port: port, jar: listed.f.s.b.jar,
                                 at: classicalAnswer.location })
      : { view: {} };
    const panel = (screen.view || {}).postQuantumRequired;
    note(listed.allow.length === 2 &&
         classicalAnswer.next === 'refused' &&
         rows('session.refuse', 'pqf-cat', 'STS-AUTHN-0356') ===
           refusedBefore + 1 &&
         rows('session.start', 'pqf-cat') === startsBefore &&
         panel && panel.register === '/portal/keys' &&
         panel.upgrade === undefined,
         'D2. list-and-refuse names both keys; the classical assertion is ' +
         'refused after the ceremony (STS-AUTHN-0356) with no session.start ' +
         'row, and the screen carries the panel: registration, and no ' +
         'upgrade link (#1100)',
         JSON.stringify([listed.allow.length, classicalAnswer.next, panel]));
    const again = await allowOf('pqf-cat');
    const pqAnswer = again.armed.json && again.armed.json.ok
      ? await authnScreen.stepAct({ port: port, jar: again.f.s.b.jar,
          opened: again.f.step, op: 'webauthn',
          body: { credential: JSON.stringify(catPq.assert(
            again.armed.json.challenge)) } })
      : { next: '' };
    note(pqAnswer.next === 'redirect' &&
         rows('session.start', 'pqf-cat') === startsBefore + 1,
         'D3. and the post-quantum key, picked from the same list, signs in',
         pqAnswer.next);
    passkeyPolicy.save('default', withDefaults({
      postQuantumRequired: 'sign-in', postQuantumAllowCredentials: 'narrow' }));
    const rowNarrow = await allowOf('pqf-cat');
    config.clearOverride('webauthn.postQuantumAllowCredentials');
    passkeyPolicy.save('default', withDefaults({
      postQuantumRequired: 'sign-in',
      postQuantumAllowCredentials: 'list-and-refuse' }));
    const rowList = await allowOf('pqf-cat');
    const asked = passkeyPolicy.question('sign-in',
      { username: 'pqf-cat', algorithm: 'ES256' });
    note(rowNarrow.allow.length === 1 && rowList.allow.length === 2 &&
         (asked.policy || {}).postQuantumAllowCredentials ===
           'list-and-refuse',
         'D4. the profile\'s row overrides the realm\'s setting both ways, ' +
         'and the question carries the resolved value as a policy fact',
         JSON.stringify([rowNarrow.allow.length, rowList.allow.length,
                         asked.policy]));
    const eve = await firstStep('pqf-eve', true);
    const eveView = (eve.step.view || {}).webauthn || {};
    const eveArmed = await authnScreen.stepAct({ port: port,
      jar: eve.s.b.jar, opened: eve.step, op: 'webauthn/options', body: {} });
    note(/requires a post-quantum passkey/.test(String(eveView.problem)) &&
         eveView.postQuantumHelp &&
         eveView.postQuantumHelp.register === '/portal/keys' &&
         eveView.postQuantumAllowCredentials === 'list-and-refuse' &&
         eveArmed.apiStatus === 400,
         'D5. under list-and-refuse a person holding only a classical key ' +
         'is still told before the ceremony, with the panel\'s links',
         JSON.stringify(eveView).slice(0, 300) + ' ' + eveArmed.apiStatus);
    passkeyPolicy.save('default', withDefaults());

    // ======================================================================
    // E. The browser's half.
    // ======================================================================
    const element = function () {
      return { hidden: true };
    };
    const page = function () {
      const els = { 'wa-fallback': element(),
                    'wa-fallback-unsupported': element(),
                    'wa-fallback-uncertain': element(),
                    'wa-fallback-hybrid': element() };
      return { els: els, getElementById: function (id) {
        return els[id] || null;
      } };
    };
    const reports = [];
    const realReport = WebWebAuthn.reportCeremonyFailure;
    WebWebAuthn.reportCeremonyFailure = function (report) {
      reports.push(report);
    };
    const hybridWindow = { PublicKeyCredential: {
      getClientCapabilities: function () {
        return Promise.resolve({ hybridTransport: true });
      } } };
    const said = { surface: 'test', fallback: { asksPostQuantum: true } };
    const p1 = page();
    const shown1 = await WebWebAuthn.offerFallback(p1, hybridWindow,
      { name: 'NotSupportedError', message: 'm' }, said);
    const p2 = page();
    const shown2 = await WebWebAuthn.offerFallback(p2, {},
      { name: 'NotAllowedError' }, said);
    const p3 = page();
    const shown3 = await WebWebAuthn.offerFallback(p3, hybridWindow,
      { name: 'SecurityError' }, said);
    const shown4 = await WebWebAuthn.offerFallback({ getElementById:
      function () {
        return null;
      } }, {}, { name: 'NotSupportedError' }, said);
    WebWebAuthn.reportCeremonyFailure = realReport;
    let sentFailure = null;
    WebWebAuthn.reportCeremonyFailure({ error: 'NotAllowedError',
      message: 'must not be sent', capabilities: {
        hybridTransport: true, privateField: 'must not be sent' } },
      function (error, caps) {
        sentFailure = { error: error, capabilities: caps };
      });
    note(sentFailure && sentFailure.error === 'NotAllowedError' &&
         sentFailure.capabilities.hybridTransport === true &&
         !sentFailure.capabilities.privateField,
         'E2. the reporter forwards only an allowlisted error name and ' +
         'boolean capabilities, never free text', JSON.stringify(sentFailure));
    note(WebWebAuthn.failureKind('NotSupportedError') === 'unsupported' &&
         WebWebAuthn.failureKind('UnknownError') === 'uncertain' &&
         WebWebAuthn.failureKind('InvalidStateError') === '' &&
         shown1 && !p1.els['wa-fallback'].hidden &&
         !p1.els['wa-fallback-unsupported'].hidden &&
         p1.els['wa-fallback-uncertain'].hidden &&
         !p1.els['wa-fallback-hybrid'].hidden &&
         shown2 && !p2.els['wa-fallback-uncertain'].hidden &&
         p2.els['wa-fallback-hybrid'].hidden &&
         !shown3 && p3.els['wa-fallback'].hidden && !shown4 &&
         reports.length === 4 &&
         reports[0].capabilities && reports[0].capabilities.hybridTransport &&
         reports[1].capabilities === null &&
         reports[0].offered === 'post-quantum-first',
         'E1. offerFallback() shows the part the error is for, the hybrid ' +
         'line only where getClientCapabilities() reports it, nothing for ' +
         'another error or a page with no guidance, and reports every ' +
         'failure to the #943 hook', JSON.stringify(reports));
    const drawnPanel = WebAuthnLogin.postQuantumPanel(
      { register: '/portal/keys' }, T);
    const drawnFallback = WebAuthnMfa.fallback({ asksPostQuantum: true,
      classical: true, retrying: false }, T);
    note(drawnPanel.indexOf('[authn.pqRequired.heading]') >= 0 &&
         drawnPanel.indexOf('href="/portal/keys"') >= 0 &&
         drawnPanel.indexOf('authn-post-quantum-upgrade') < 0 &&
         WebAuthnLogin.postQuantumPanel(null, T) === '' &&
         drawnFallback.indexOf('value="webauthn-classical"') >= 0 &&
         WebAuthnMfa.fallback({ asksPostQuantum: false }, T) === '',
         'E3. the panel links registration and no upgrade; the step\'s ' +
         'guidance carries the retry button, and nothing where no ML-DSA ' +
         'is asked for', drawnPanel.length + ' ' + drawnFallback.length);

    // A portal create, driven the way the page wires it (#961). The click
    // listener does not return its promise: create()'s rejection, the
    // capability question and offerFallback()'s report are microtasks, so
    // one timer lets them finish before the assertion reads them.
    const drivePortalCreate = async function (rejectName) {
      const submitted = [];
      const reported = [];
      const credential = { value: '' };
      const form = {
        getAttribute: function (name) {
          return name === 'action' ? '/portal/keys' : null;
        }
      };
      const fallback = { hidden: true };
      const data = {
        getAttribute: function (name) {
          const attrs = {
            'data-mode': 'create',
            'data-challenge': '',
            'data-rpid': '127.0.0.1',
            'data-user': 'pqf-fay',
            'data-userid': '',
            'data-display': 'pqf-fay',
            'data-allow': '',
            'data-exclude': '',
            'data-options': '{}',
            'data-fallback': JSON.stringify({ asksPostQuantum: true,
              classical: true, retrying: false })
          };
          return Object.prototype.hasOwnProperty.call(attrs, name)
            ? attrs[name] : null;
        }
      };
      const listeners = [];
      const go = {
        addEventListener: function (type, fn) {
          if (type === 'click') {
            listeners.push(fn);
          }
        }
      };
      const els = {
        'wa-data': data, 'wa-go': go, 'wa-credential': credential,
        'wa-form': form, 'wa-fallback': fallback,
        'wa-fallback-unsupported': { hidden: true },
        'wa-fallback-uncertain': { hidden: true },
        'wa-fallback-hybrid': { hidden: true }
      };
      const doc = {
        getElementById: function (id) {
          return els[id] || null;
        }
      };
      const win = {
        navigator: { credentials: { create: function () {
          return Promise.reject({ name: rejectName });
        } } },
        PublicKeyCredential: { getClientCapabilities: function () {
          return Promise.resolve({ hybridTransport: true });
        } }
      };
      PortalWebAuthn.wire(doc, win, function (posted) {
        submitted.push(posted);
      }, function (posted, body) {
        reported.push({ form: posted, body: body });
      });
      listeners[0]({});
      await new Promise(function (resolve) {
        setTimeout(resolve, 0);
      });
      return { submitted: submitted, reported: reported,
               credential: credential, fallback: fallback };
    };
    const parseReport = function (raw) {
      try {
        return JSON.parse(String(raw || ''));
      } catch (e) {
        // The child writes findings, not a log. A body that is not JSON is
        // the assertion's detail.
        return { parseError: String((e && e.message) || e) };
      }
    };
    const kept = await drivePortalCreate('NotSupportedError');
    const keptBody = kept.reported[0] && kept.reported[0].body;
    const keptCredential = parseReport(keptBody && keptBody.credential);
    note(kept.submitted.length === 0 && kept.reported.length === 1 &&
         keptCredential.error === 'NotSupportedError' &&
         Object.prototype.hasOwnProperty.call(keptCredential,
                                               'capabilities') &&
         keptCredential.capabilities &&
         keptCredential.capabilities.hybridTransport === true &&
         kept.fallback.hidden === false && kept.credential.value === '',
         'E4. a NotSupportedError during a portal create that has ' +
         '#wa-fallback reports the ceremony and does not submit the ' +
         'finish form',
         JSON.stringify({ submitted: kept.submitted.length,
           reported: kept.reported.length,
           credential: keptBody && keptBody.credential,
           hidden: kept.fallback.hidden, field: kept.credential.value }));
    const dropped = await drivePortalCreate('SecurityError');
    const droppedField = parseReport(dropped.credential.value);
    const droppedReport = dropped.reported[0] && dropped.reported[0].body;
    const droppedQuiet = parseReport(droppedReport &&
                                     droppedReport.credential);
    note(dropped.submitted.length === 1 && dropped.reported.length === 1 &&
         droppedField.error === 'SecurityError' &&
         !Object.prototype.hasOwnProperty.call(droppedField,
                                                'capabilities') &&
         droppedQuiet.capabilities &&
         droppedQuiet.capabilities.hybridTransport === true &&
         dropped.fallback.hidden === true,
         'E5. an error the guidance does not handle still submits the ' +
         'finish form, with no capabilities on the field, and the quiet ' +
         'report carries hybridTransport',
         JSON.stringify({ submitted: dropped.submitted.length,
           reported: dropped.reported.length,
           field: dropped.credential.value,
           quiet: droppedReport && droppedReport.credential,
           hidden: dropped.fallback.hidden }));

    // The runtime's quiet post is not submit(): an answer that carries a
    // view must not be drawn, and the form's other fields still go.
    const runtimeEnv = {
      location: { href: 'http://127.0.0.1/portal/keys',
                  pathname: '/portal/keys', origin: 'http://127.0.0.1',
                  search: '', hash: '' },
      document: { documentElement: null },
      history: { pushState: function () { return undefined; },
                 replaceState: function () { return undefined; } },
      sessionStorage: { getItem: function () { return null; },
                        setItem: function () { return undefined; },
                        removeItem: function () { return undefined; } },
      formDataOf: function () {
        return { forEach: function (fn) {
          fn('finish', 'action');
          fn('enr-1', 'enrolment_id');
          fn('', 'credential');
        } };
      }
    };
    const runtime = new PortalRuntime(runtimeEnv);
    const seen = [];
    runtime.submit = function (form) {
      seen.push({ kind: 'submit', form: form });
      return Promise.resolve();
    };
    runtime.reportForm = function (form, body) {
      seen.push({ kind: 'report', form: form, body: body });
      return Promise.resolve();
    };
    const realPortalWire = PortalWebAuthn.wire;
    let passedQuiet = null;
    PortalWebAuthn.wire = function (doc, win, submit, quiet) {
      passedQuiet = quiet;
      seen.push({ kind: 'wired', submit: typeof submit });
    };
    try {
      runtime.wire();
    } catch (e) {
      // wire() throwing is the assertion's detail. The real wire is put
      // back below either way.
      seen.push({ kind: 'wire-threw',
                  error: String((e && e.message) || e) });
    } finally {
      PortalWebAuthn.wire = realPortalWire;
    }
    if (typeof passedQuiet === 'function') {
      passedQuiet({ id: 'finish-form' }, { credential:
        '{"error":"NotSupportedError","capabilities":null}' });
    }
    await new Promise(function (resolve) {
      setTimeout(resolve, 0);
    });
    let drew = false;
    let postedFinish = null;
    runtime.answered = function () {
      drew = true;
      return Promise.resolve();
    };
    runtime.apiJson = function (method, path, body) {
      postedFinish = { method: method, path: path, body: body };
      return Promise.resolve({ status: 400, json: { ok: false,
        errors: ['NotSupportedError: '], view: { enrol: { pending: {} } } } });
    };
    runtime.publicJson = function () {
      drew = true;
      return Promise.resolve({ status: 500, json: {} });
    };
    runtime.formTable = { 'POST /portal/keys': { access: 'person',
      path: '/account-api/keys' } };
    runtime.ensureFormTable = function () {
      return Promise.resolve(true);
    };
    const finishForm = {
      getAttribute: function (name) {
        return name === 'action' ? '/portal/keys' : null;
      }
    };
    await PortalRuntime.prototype.reportForm.call(runtime, finishForm, {
      credential: JSON.stringify({ error: 'NotSupportedError',
                                  capabilities: null }) });
    const postedBody = (postedFinish && postedFinish.body) || {};
    const postedCredential = parseReport(postedBody.credential);
    note(seen.some(function (one) { return one.kind === 'report'; }) &&
         !seen.some(function (one) { return one.kind === 'submit'; }) &&
         !drew && runtime.flash === null && runtime.view === null &&
         postedFinish && postedFinish.method === 'POST' &&
         postedFinish.path === '/account-api/keys' &&
         postedBody.action === 'finish' &&
         postedBody.enrolment_id === 'enr-1' &&
         postedCredential.error === 'NotSupportedError' &&
         Object.prototype.hasOwnProperty.call(postedCredential,
                                               'capabilities') &&
         postedCredential.capabilities === null,
         'E5b. the runtime reports the finish through the account API and ' +
         'does not draw an answer that carries a view',
         JSON.stringify({ seen: seen.map(function (one) {
           return one.kind;
         }), drew: drew, posted: postedFinish && {
           method: postedFinish.method, path: postedFinish.path,
           action: postedBody.action, id: postedBody.enrolment_id,
           credential: postedBody.credential } }));

    // The account API, called as the finish operation is.
    const finishKey = async function (credential) {
      const keys = new accountKeys.AccountKeys(
        accountKeys.AccountKeys.defaultDeps());
      const sent = {};
      const res = {};
      const ctx = {
        audit: audit,
        websecurity: { addressOf: function () { return '127.0.0.1'; } },
        errorCodes: errorCodes,
        baseUrlOf: function () { return ORIGIN; },
        translatorFor: function () {
          return { text: function (key) { return key; } };
        },
        PORTAL: '/portal',
        BASE: '/account-api',
        refuse: function (response, status, code, why, extra) {
          errorCodes.mark(response, code);
          const body = Object.assign({ ok: false, errors: [String(why)] },
                                      extra || {});
          sent.status = status;
          sent.body = body;
          return body;
        },
        json: function (response, status, body) {
          sent.status = status;
          sent.body = body;
          return body;
        }
      };
      const held = credentials.pendingKeyEnrolmentFor('pqf-fay');
      await keys.enrol(ctx, { headers: {} }, res, {
        username: 'pqf-fay', session: { user: { name: 'pqf-fay' } }
      }, {
        action: 'finish',
        enrolment_id: held ? held.id : '',
        credential: JSON.stringify(credential)
      });
      return { sent: sent,
               pending: credentials.pendingKeyEnrolmentFor('pqf-fay') };
    };
    const fayBefore = rows('portal.key.refused', 'pqf-fay');
    const fayBegun = credentials.beginKeyEnrolment('pqf-fay',
      { role: 'primary', kind: 'passkey' });
    const fayKept = await finishKey({ error: 'NotSupportedError',
                                      capabilities: null });
    const keptAnswer = fayKept.sent.body || {};
    note(fayBegun.ok && fayKept.pending &&
         fayKept.pending.id === fayBegun.enrolmentId &&
         fayKept.sent.status === 400 && keptAnswer.ok === false &&
         !Object.prototype.hasOwnProperty.call(keptAnswer, 'view') &&
         rows('portal.key.refused', 'pqf-fay') === fayBefore + 1,
         'E6. a finish carrying the browser error with its own capabilities ' +
         'property, while the classical retry is offered, leaves the ' +
         'enrolment pending and answers no view',
         JSON.stringify({ begun: fayBegun.enrolmentId,
           pending: fayKept.pending && fayKept.pending.id,
           status: fayKept.sent.status, ok: keptAnswer.ok,
           hasView: Object.prototype.hasOwnProperty.call(keptAnswer, 'view'),
           refused: rows('portal.key.refused', 'pqf-fay') }));
    const fayAgain = credentials.beginKeyEnrolment('pqf-fay',
      { role: 'primary', kind: 'passkey' });
    const fayDropped = await finishKey({ error: 'SecurityError' });
    const droppedAnswer = fayDropped.sent.body || {};
    note(fayAgain.ok && !fayDropped.pending &&
         Object.prototype.hasOwnProperty.call(droppedAnswer, 'view') &&
         !((droppedAnswer.view || {}).enrol || {}).pending,
         'E7. a finish the guidance does not handle still abandons the ' +
         'enrolment and redraws the page',
         JSON.stringify({ begun: fayAgain.ok, pending: !!fayDropped.pending,
           hasView: Object.prototype.hasOwnProperty.call(droppedAnswer,
                                                         'view') }));
    config.setOverride('webauthn.pqcOnly', true);
    let fayOnly = { pending: true, sent: { body: {} },
                    begun: { ok: false } };
    try {
      const onlyBegun = credentials.beginKeyEnrolment('pqf-fay',
        { role: 'primary', kind: 'passkey' });
      fayOnly = await finishKey({ error: 'NotSupportedError',
                                 capabilities: null });
      fayOnly.begun = onlyBegun;
    } catch (e) {
      // The override is cleared below even when the finish throws. The
      // child writes findings; the message is the assertion's detail.
      fayOnly = { threw: String((e && e.message) || e), pending: true,
                  sent: { body: {} }, begun: { ok: false } };
    } finally {
      config.clearOverride('webauthn.pqcOnly');
    }
    const onlyAnswer = (fayOnly.sent && fayOnly.sent.body) || {};
    note(fayOnly.begun && fayOnly.begun.ok && !fayOnly.pending &&
         Object.prototype.hasOwnProperty.call(onlyAnswer, 'view'),
         'E8. the same report while the classical retry is not offered ' +
         'still abandons the enrolment',
         JSON.stringify({ ok: fayOnly.begun && fayOnly.begun.ok,
           pending: !!fayOnly.pending,
           hasView: Object.prototype.hasOwnProperty.call(onlyAnswer, 'view'),
           threw: fayOnly.threw || '' }));
    server.close();
  })().catch(function (e) {
    note(false, 'the child ran to the end', e && e.stack);
  }).then(function () {
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'sts-pqf-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = Object.assign({}, process.env, { PQF_OUT: out, PQF_ROOT: ROOT,
    STS_HTTPS: 'false' });
  delete env.CONFIG_FILE;
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      cwd: ROOT, env: env, encoding: 'utf8', timeout: 180000,
      maxBuffer: 256 * 1024 * 1024 });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    // The child died before writing a report; said below with its status.
    findings = null;
  }
  try {
    fs.rmSync(out, { force: true });
  } catch (e) {
    // A temporary file left behind is not a failed assertion.
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (t.check(Array.isArray(findings),
              'the child process reported its findings',
              'status=' + result.status + ' ' +
              String(result.stderr || '').slice(-2000))) {
    findings.forEach(function (one) {
      t.check(one.ok, one.what, one.detail);
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'passkey_post_quantum_fallback',
  describe: 'the classical retry of an ML-DSA registration that failed on ' +
            'the device (#944) and list-and-refuse where a post-quantum ' +
            'passkey is required (#946): the rule at both doors, the ' +
            'fallback facts and markup, the panel, and the browser\'s half ' +
            '(#961: a shown guidance is reported, not submitted)',
  run: run
};
