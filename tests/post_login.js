// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/post_login.js
//
// ===========================================================================
// POST-LOGIN ACTIVITIES: THE POST-QUANTUM PASSKEY MIGRATION (#1096, #1100-
// #1105).
//
// rcbj: a "post login activity", targeted at groups, configurable and
// enabled per realm; the first one asks a person holding a classical
// passkey to register a post-quantum one, skippable for a number of days,
// with a grace period after which the sign-in is held. In a CHILD PROCESS
// serving the stack on a loopback port (`passkey_dual_lane.js`'s harness),
// with REAL ceremonies from a software authenticator over
// `webauthn_attestation_kit.js`'s ES256 and ML-DSA keys:
//
//   A. The policy: off by default; a bad profile name, a missing field and
//      a named profile with no group are refused under their codes.
//   B. On: a person holding a classical passkey is due a post-quantum one,
//      asked of every key at once and in no role (#1135; until then a
//      passkey was due per role, `primary` first); a person with no passkey
//      only as `noPasskey` says; one lane makes `automatic` an UPGRADE
//      (#1100).
//   C. Exclusion by group.
//   D. Over HTTP: a password sign-in starts NO session and lands on
//      `/authn/post-login`; another step's act on its id is refused; Skip
//      starts the held session and puts it off.
//   E. The UPGRADE (#1100): Register proves the classical passkey (an
//      assertion naming only it), then registers ML-DSA only with it left out
//      of the exclude list; the ML-DSA passkey REPLACES it in place — one
//      row — and the held session starts. A classical retry is refused.
//   F. ALONGSIDE in one lane (#1100): a second passkey, made on another
//      authenticator (the classical one is excluded), and the page says so.
//   G. Required: Skip refused (0474); a door that cannot ask refused (0473);
//      a keyed caller never asked.
//   H. A device that cannot make it (#1105): the browser's error goes back
//      to the step's page with guidance, and an audit row with the platform.
//   I. A post-quantum attestation required (#1102): an ML-DSA passkey whose
//      attestation is not recorded post-quantum does not count.
//   J. The classical fallback for a person with no passkey (#1103).
//   K. A row a later registration may have replaced (#1101): marked, shown,
//      not counted by the removal guard, cleared by a use.
//   L. Two lanes per population (#1104).
//   M. The portal's Upgrade is gone (#1100), and so is webauthn.pqcUpgrade.
// ===========================================================================

delete process.env.CONFIG_FILE;

const path = require('path');
const os = require('os');
const fs = require('fs');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'post_login',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// Runs in the child. Stringified, so it may use nothing from this file's
// scope, and — code in a `node -e` child — is exempt from the Entering/Leaving
// rule (root CLAUDE.md, *Code style*).
function childMain() {
  const ROOT = process.env.PLA_ROOT;
  const OUT = process.env.PLA_OUT;
  const http = require('http');
  const nodeCrypto = require('crypto');
  const kit = require(ROOT + '/tests/webauthn_attestation_kit');
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };
  const DAY = 24 * 60 * 60 * 1000;

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

  // A SOFTWARE AUTHENTICATOR, `passkey_dual_lane.js`'s, with an AAGUID of
  // its own so #1101's comparison has something to compare.
  const sha256 = function (buf) {
    return nodeCrypto.createHash('sha256').update(buf).digest();
  };
  const makeAuthenticator = async function (alg, rpId, origin, aaguid) {
    const cred = await kit.credential(alg);
    const id = cred.id.toString('base64url');
    let signCount = 0;
    let userHandle = '';
    const clientData = function (type, challenge) {
      return Buffer.from(JSON.stringify({ type: type, challenge: challenge,
                                          origin: origin,
                                          crossOrigin: false }), 'utf8');
    };
    return {
      credentialId: id,
      register: function (challenge, handle) {
        userHandle = handle || '';
        const count = Buffer.alloc(4);
        const idLen = Buffer.alloc(2);
        idLen.writeUInt16BE(cred.id.length, 0);
        const data = Buffer.concat([sha256(Buffer.from(rpId, 'utf8')),
          Buffer.from([0x45]), count,
          aaguid ? Buffer.from(aaguid, 'hex') : Buffer.alloc(16), idLen,
          cred.id, kit.cbor(cred.cose)]);
        const attestationObject = kit.cbor(new Map([['fmt', 'none'],
          ['attStmt', new Map()], ['authData', data]]));
        return { id: id, rawId: id, type: 'public-key',
                 authenticatorAttachment: 'cross-platform',
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

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const config = require(ROOT + '/common/config');
    const applications = require(ROOT + '/common/applications');
    const credentials = require(ROOT + '/common/credentials');
    const errorCodes = require(ROOT + '/common/error_codes');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const audit = require(ROOT + '/common/audit');
    const authn = require(ROOT + '/authn/authn');
    const policy = require(ROOT + '/common/post_login_policy');
    const postLogin = require(ROOT + '/common/post_login');
    const passkeyPolicy = require(ROOT + '/common/passkey_policy');
    const webauthnPolicy = require(ROOT + '/authn/webauthn_policy');
    const accountKeys = require(ROOT + '/portal/account_keys');
    const authnScreen = require(ROOT + '/tests/tools/authn_screen');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const ORIGIN = 'http://127.0.0.1:' + port;
    const RPID = '127.0.0.1';
    const REDIRECT = 'https://rp.pla.example/cb';
    const PASSWORD = 'correct-horse-battery-staple-pla-7!';
    const EC = { kty: 'EC', crv: 'P-256', x: 'AA', y: 'AA' };
    const MODEL = '0102030405060708090a0b0c0d0e0f10';
    config.setOverride('oauth2.consentRequired', false);
    applications.createApplication({ identifier: 'pla-public',
      protocols: ['oauth2'],
      fields: { oauthClientId: 'pla-public', oauthClientSecret: '',
                oauthRedirectUri: [REDIRECT],
                oauthTokenEndpointAuthMethod: 'none',
                oauthGrantType: ['authorization_code'] } });
    // pla-gus has no password: the passkeys are the only way in (K).
    ['pla-ann', 'pla-bob', 'pla-cat', 'pla-dan', 'pla-eve', 'pla-fay',
     'pla-gus', 'pla-hal', 'pla-ivy'].forEach(function (name) {
      ldap.createUser(name, { invent: false });
      if (name !== 'pla-gus') {
        credentials.setPassword(name, PASSWORD);
      }
    });
    // REAL classical passkeys where a ceremony will prove them; eve's and
    // cat's are rows only.
    const enrol = async function (name, authenticator) {
      const begun = credentials.beginKeyEnrolment(name,
        { kind: 'passkey', lane: 'classical' });
      const done = await credentials.confirmKeyEnrolment(name,
        begun.enrolmentId,
        authenticator.register(begun.challenge, begun.userHandle),
        { origin: ORIGIN, rpId: RPID });
      return done;
    };
    const annOld = await makeAuthenticator(-7, RPID, ORIGIN, MODEL);
    const fayOld = await makeAuthenticator(-7, RPID, ORIGIN, MODEL);
    const gusOld = await makeAuthenticator(-7, RPID, ORIGIN, MODEL);
    const annSeed = await enrol('pla-ann', annOld);
    const faySeed = await enrol('pla-fay', fayOld);
    const gusSeed = await enrol('pla-gus', gusOld);
    // dan's is a REAL passkey since #1135: it answers the second step of
    // his password sign-in (G), where until then a `primary` row did not
    // have to.
    const danOld = await makeAuthenticator(-7, RPID, ORIGIN, MODEL);
    const danSeed = await enrol('pla-dan', danOld);
    credentials.addKey('pla-eve', { credentialId: 'pla-eve-ec',
                                    publicKeyJwk: EC });
    credentials.addKey('pla-cat', { credentialId: 'pla-cat-ec',
                                    publicKeyJwk: EC });
    ldap.createGroup('pla-excluded', { members: [] });
    ldap.addGroupMember('pla-excluded', 'pla-eve');

    const fields = function (over) {
      return Object.assign({}, policy.DEFAULTS, over || {});
    };
    const codeRecorded = function (code) {
      return audit.list().some(function (row) {
        return row.errorCode === code;
      });
    };
    const rows = function (action, actor) {
      return audit.list().filter(function (row) {
        return row.action === action && row.actor === actor;
      });
    };
    const screenFor = async function () {
      const b = browser(port);
      const verifier = nodeCrypto.randomBytes(32).toString('base64url');
      const start = await b.go('GET', '/oauth2/authorize?' +
        new URLSearchParams({ client_id: 'pla-public', response_type: 'code',
          redirect_uri: REDIRECT, scope: 'openid', state: 's',
          nonce: 'n-' + nodeCrypto.randomBytes(8).toString('hex'),
          code_challenge: nodeCrypto.createHash('sha256').update(verifier)
            .digest('base64url'),
          code_challenge_method: 'S256' }).toString());
      const opened = await authnScreen.open({ port: port, jar: b.jar,
        at: String(start.headers.location || '') });
      return { b: b, opened: opened };
    };
    // THE PASSWORD, AND THE PASSKEY AS THE SECOND STEP (#1135). Until then
    // these people's keys were `primary` and a password sign-in asked for
    // nothing more; a key has no role now, so where the realm accepts a
    // passkey as a second factor (its default, and this realm's), a person
    // holding a password and any passkey is asked for it next, and the
    // post-login step comes after both. `key` is the authenticator that
    // answers it.
    const signIn = async function (name, key) {
      const s = await screenFor();
      let answer = await authnScreen.submit({ port: port, jar: s.b.jar,
        opened: s.opened, fields: { action: 'login', username: name,
                                    password: PASSWORD } });
      if (key && answer.next === 'mfa' && answer.step === 'webauthn') {
        const page = await openStep(s.b, answer);
        const second = await authnScreen.passkeyStep({ port: port,
          jar: s.b.jar, opened: page }, function (armed) {
          return key.assert(armed.challenge);
        });
        answer = second.answer;
      }
      return { b: s.b, answer: answer };
    };
    const openStep = function (b, answer) {
      return authnScreen.openStep({ port: port, jar: b.jar,
                                    at: answer.location });
    };
    const stepAct = function (b, opened, op, body) {
      return authnScreen.stepAct({ port: port, jar: b.jar, opened: opened,
                                   op: op, body: body || {} });
    };
    const startsSession = function (a) {
      return a.next === 'redirect' && !/\/authn\//.test(String(a.location));
    };
    const fakeRes = { set: function () { return fakeRes; },
                      append: function () { return fakeRes; },
                      status: function () { return fakeRes; },
                      cookie: function () { return fakeRes; },
                      req: null };

    // A. Off by default, and the refusals.
    note(policy.read().enabled === false &&
         postLogin.dueFor('pla-ann') === null,
         'A1. off by default: nobody is due anything',
         JSON.stringify(policy.read()));
    const badName = policy.save('Pilot!', fields());
    const missing = policy.save('default', { enabled: true });
    const badRank = policy.save('pilot', fields({ precedence: 0 }));
    note(!badName.ok && errorCodes.codeOf(badName) === 'STS-AUTHN-0470' &&
         !missing.ok && errorCodes.codeOf(missing) === 'STS-AUTHN-0471' &&
         !badRank.ok && errorCodes.codeOf(badRank) === 'STS-AUTHN-0471',
         'A2. a bad name, a missing field and a named profile\'s ' +
         'precedence out of range are refused under their codes',
         JSON.stringify([badName.errors, missing.errors, badRank.errors]));

    // B. On.
    const on = policy.save('default', fields({ enabled: true,
                                               snoozeDays: 3 }));
    const ann = postLogin.dueFor('pla-ann');
    const cat = postLogin.dueFor('pla-cat');
    const bobLeft = postLogin.dueFor('pla-bob');
    policy.save('default', fields({ enabled: true, snoozeDays: 3,
                                    noPasskey: 'invite' }));
    const bobInvited = postLogin.dueFor('pla-bob');
    note(annSeed.ok && faySeed.ok && gusSeed.ok && danSeed.ok && on.ok &&
         ann &&
         ann.role === undefined && ann.reason === 'classical' &&
         ann.required === false && ann.method === 'upgrade' &&
         cat && cat.reason === 'classical' && cat.role === undefined &&
         bobLeft === null && bobInvited &&
         bobInvited.reason === 'none' && bobInvited.role === undefined &&
         bobInvited.method === 'register' &&
         bobInvited.enforceable === false,
         'B. on: every holder of a classical passkey is due a post-quantum ' +
         'one, in no role (#1135), by an upgrade in one lane; one with none ' +
         'only as noPasskey says',
         JSON.stringify([annSeed.errors, on.errors, ann, cat, bobLeft,
                         bobInvited]));
    policy.save('default', fields({ enabled: true, snoozeDays: 3 }));

    // C. Exclusion by group: the group names the profile (#1239).
    const excluded = policy.save('pla-excluded', fields({ enabled: false,
      precedence: 10 }));
    const pointed = ldap.setGroupPolicy('pla-excluded', 'stsPostLoginPolicy',
                                        'pla-excluded');
    note(excluded.ok && pointed.ok &&
         policy.profileNameFor('pla-eve') === 'pla-excluded' &&
         policy.profileNameFor('pla-ann') === 'default' &&
         postLogin.dueFor('pla-eve') === null,
         'C. a disabled named profile a group names reaches its members, ' +
         'who are due nothing',
         JSON.stringify([excluded.errors, pointed.errors]));

    // D. Over HTTP: held, a way round refused, Skip.
    let s = await signIn('pla-ann', annOld);
    const startsBefore = rows('session.start', 'pla-ann').length;
    note(s.answer.next === 'mfa' && s.answer.step === 'post-login' &&
         /\/authn\/post-login\?mfa=/.test(s.answer.location) &&
         rows('session.start', 'pla-ann').length === startsBefore &&
         rows('authn.post-login.asked', 'pla-ann').length === 1,
         'D1. the password and passkey sign-in starts no session and ' +
         'lands on the post-login step', JSON.stringify(s.answer.json));
    let opened = await openStep(s.b, s.answer);
    const v = (opened.view || {}).postLogin || {};
    note(opened.status === 200 && v.role === undefined &&
         v.reason === 'classical' && v.canSkip === true &&
         v.snoozeDays === 3 && v.method === 'upgrade',
         'D2. its view names the reason, the method and Skip, and no role ' +
         '(#1135)',
         JSON.stringify(opened.view));
    const roundAbout = await stepAct(s.b, opened, 'totp',
                                     { code: '000000' });
    note(roundAbout.apiStatus === 400 &&
         rows('session.start', 'pla-ann').length === startsBefore,
         'D3. another step\'s act on the post-login step is refused and ' +
         'starts nothing', roundAbout.apiStatus + ' ' + roundAbout.next);
    const skipped = await stepAct(s.b, opened, 'post-login/skip');
    const snoozed = postLogin.stateOf('pla-ann');
    note(startsSession(skipped) &&
         rows('session.start', 'pla-ann').length === startsBefore + 1 &&
         snoozed.snoozedUntil > Date.now() + 2 * DAY &&
         rows('authn.post-login.skipped', 'pla-ann').length === 1,
         'D4. Skip starts the held session and puts it off for snoozeDays',
         JSON.stringify([skipped.json, snoozed]));
    s = await signIn('pla-ann', annOld);
    note(startsSession(s.answer),
         'D5. while it is put off, the next sign-in is not asked',
         JSON.stringify(s.answer.json));

    // E. The upgrade (#1100).
    postLogin.forget('pla-ann');
    s = await signIn('pla-ann', annOld);
    opened = await openStep(s.b, s.answer);
    const toProof = await stepAct(s.b, opened, 'post-login/register');
    const proofPage = toProof.next === 'mfa'
      ? await openStep(s.b, toProof) : {};
    const pw = (proofPage.view || {}).webauthn || {};
    const retry = await stepAct(s.b, proofPage, 'webauthn/options',
                                { algorithms: 'classical' });
    const proved = await authnScreen.passkeyStep({ port: port, jar: s.b.jar,
      opened: proofPage }, function (armed) {
      return annOld.assert(armed.challenge);
    });
    note(toProof.step === 'webauthn' && pw.mode === 'get' &&
         pw.postLogin && pw.postLogin.upgrade &&
         pw.postLogin.upgrade.phase === 'proof' &&
         proved.armed.json && proved.armed.json.allow &&
         proved.armed.json.allow.join(',') === annOld.credentialId &&
         retry.apiStatus === 400 &&
         proved.answer.next === 'mfa' && proved.answer.step === 'webauthn',
         'E1. Register asks first for the classical passkey alone (the ' +
         'proof), and a classical retry is refused',
         JSON.stringify([toProof.json, pw.mode, proved.armed.json &&
                         proved.armed.json.allow, retry.apiStatus,
                         proved.answer.json]));
    const createPage = await openStep(s.b, proved.answer);
    const cw = (createPage.view || {}).webauthn || {};
    const pq = await makeAuthenticator(-49, RPID, ORIGIN, MODEL);
    const made = await authnScreen.passkeyStep({ port: port, jar: s.b.jar,
      opened: createPage }, function (armed) {
      return pq.register(armed.challenge, armed.user && armed.user.id);
    });
    const annKeys = credentials.keysOf('pla-ann');
    note(cw.mode === 'create' && (cw.algorithms || []).length > 0 &&
         cw.algorithms.every(function (one) {
           return /^ML-DSA-/.test(one);
         }) && made.armed.json &&
         (made.armed.json.exclude || []).indexOf(annOld.credentialId) < 0 &&
         startsSession(made.answer) && annKeys.length === 1 &&
         credentials.keyAlgorithm(annKeys[0]).postQuantum &&
         annKeys[0].role === undefined &&
         annKeys[0].previousCredentialId === annOld.credentialId &&
         postLogin.dueFor('pla-ann') === null &&
         rows('authn.post-login.done', 'pla-ann').length === 1,
         'E2. the registration is ML-DSA only with the classical passkey ' +
         'left out of the exclude list; the ML-DSA passkey replaces it in ' +
         'place (one row) and the held session starts',
         JSON.stringify([cw.algorithms, made.armed.json &&
                         made.armed.json.exclude, made.answer.json,
                         annKeys.map(function (one) {
                           return [credentials.keyAlgorithm(one).name,
                                   one.previousCredentialId];
                         })]));

    // F. Alongside, in one lane: another authenticator.
    policy.save('default', fields({ enabled: true, snoozeDays: 3,
                                    method: 'alongside' }));
    s = await signIn('pla-fay', fayOld);
    opened = await openStep(s.b, s.answer);
    const fv = (opened.view || {}).postLogin || {};
    const toCreate = await stepAct(s.b, opened, 'post-login/register');
    const fayPage = toCreate.next === 'mfa'
      ? await openStep(s.b, toCreate) : {};
    const fayPq = await makeAuthenticator(-48, RPID, ORIGIN);
    const fayMade = await authnScreen.passkeyStep({ port: port,
      jar: s.b.jar, opened: fayPage }, function (armed) {
      return fayPq.register(armed.challenge, armed.user && armed.user.id);
    });
    note(fv.method === 'alongside' && fv.separate === true &&
         ((fayPage.view || {}).webauthn || {}).mode === 'create' &&
         fayMade.armed.json &&
         (fayMade.armed.json.exclude || []).indexOf(fayOld.credentialId) >=
           0 && startsSession(fayMade.answer) &&
         credentials.keysOf('pla-fay').length === 2,
         'F. alongside in one lane: the page says another authenticator, ' +
         'the classical passkey is excluded, and both passkeys are kept',
         JSON.stringify([fv, fayMade.armed.json &&
                         fayMade.armed.json.exclude, fayMade.answer.json]));

    // G. Required.
    policy.save('default', fields({ enabled: true, snoozeDays: 3,
                                    graceDays: 1, method: 'alongside' }));
    const past = new postLogin.PostLogin(Object.assign(
      postLogin.PostLogin.defaultDeps(),
      { now: function () { return Date.now() - 2 * DAY; } }));
    past.noteSkipped('pla-dan', past.dueFor('pla-dan'));
    const dan = postLogin.dueFor('pla-dan');
    note(dan && dan.required === true,
         'G1. past the allotted time the activity is required, whatever ' +
         'was put off', JSON.stringify(dan));
    s = await signIn('pla-dan', danOld);
    opened = await openStep(s.b, s.answer);
    const noSkip = await stepAct(s.b, opened, 'post-login/skip');
    note(opened.view && opened.view.postLogin &&
         opened.view.postLogin.canSkip === false &&
         noSkip.apiStatus === 400 && codeRecorded('STS-AUTHN-0474'),
         'G2. Skip is not offered, and is refused (STS-AUTHN-0474)',
         JSON.stringify([opened.view, noSkip.json]));
    const elsewhere = { request: { headers: {} },
                        credential: { kind: 'federation' } };
    const other = authn.startSession(fakeRes, 'pla-dan', ['fed'], '1',
                                     'a test', elsewhere);
    note(other === null && elsewhere.refusedWith === 'STS-AUTHN-0473',
         'G3. a door that cannot draw the step is refused (STS-AUTHN-0473)',
         JSON.stringify(elsewhere.refusedWith || ''));
    const keyed = authn.startSession(fakeRes, 'pla-dan', ['pwd'], '1',
      'a test', { key: 'pla-key-' + Date.now(), credential: {} });
    note(!!keyed, 'G4. a keyed caller is never asked');

    // H. A device that cannot make it (#1105).
    const toDanKey = await stepAct(s.b, opened, 'post-login/register');
    const danPage = toDanKey.next === 'mfa'
      ? await openStep(s.b, toDanKey) : {};
    const failedAct = await stepAct(s.b, danPage, 'webauthn',
      { credential: JSON.stringify({ error: 'NotSupportedError' }) });
    const back = failedAct.next === 'mfa'
      ? await openStep(s.b, failedAct) : {};
    const unsupported = rows('authn.post-login.unsupported', 'pla-dan');
    note(failedAct.step === 'post-login' && back.view &&
         back.view.postLogin.failed === 'NotSupportedError' &&
         unsupported.length === 1 &&
         unsupported[0].detail.error === 'NotSupportedError',
         'H. a ceremony the device did not complete goes back to the step ' +
         'page, which names it and says what to do, and leaves an audit row',
         JSON.stringify([failedAct.json, back.view && back.view.postLogin,
                         unsupported.map(function (one) {
                           return one.detail;
                         })]));

    // I. A post-quantum attestation required (#1102).
    policy.save('default', fields({ enabled: true, snoozeDays: 3,
                                    attestation: 'post-quantum' }));
    postLogin.forget('pla-ann');
    const annAgain = postLogin.dueFor('pla-ann');
    note(annAgain && annAgain.reason === 'attestation' &&
         annAgain.method === 'alongside',
         'I. an ML-DSA passkey with no post-quantum attestation recorded ' +
         'does not count where the profile asks for one; its holder is due ' +
         'one beside it', JSON.stringify(annAgain));

    // J. The classical fallback for a person with no passkey (#1103).
    policy.save('default', fields({ enabled: true, snoozeDays: 3,
                                    noPasskey: 'invite',
                                    noPasskeyFallback: 'classical' }));
    s = await signIn('pla-ivy');
    opened = await openStep(s.b, s.answer);
    const toIvy = await stepAct(s.b, opened, 'post-login/register');
    const ivyPage = toIvy.next === 'mfa' ? await openStep(s.b, toIvy) : {};
    const ivyFacts = (ivyPage.view || {}).webauthn || {};
    const ivyRetry = await stepAct(s.b, ivyPage, 'webauthn/options',
                                   { algorithms: 'classical' });
    note(ivyFacts.fallback && ivyFacts.fallback.classical === true &&
         ivyRetry.apiStatus === 200 && ivyRetry.json &&
         ivyRetry.json.options &&
         (ivyRetry.json.options.algorithms || []).every(function (one) {
           return [-48, -49, -50].indexOf(Number(one)) < 0;
         }),
         'J. a person with no passkey is offered the classical retry where ' +
         'the profile allows it, and the retry asks for no ML-DSA',
         JSON.stringify([ivyFacts.fallback, ivyRetry.apiStatus,
                         ivyRetry.json && ivyRetry.json.options &&
                         ivyRetry.json.options.algorithms]));

    // K. A row a later registration may have replaced (#1101).
    const gusNew = await makeAuthenticator(-7, RPID, ORIGIN, MODEL);
    const gusSecond = await enrol('pla-gus', gusNew);
    const marked = credentials.keysOf('pla-gus').filter(function (one) {
      return one.credentialId === gusOld.credentialId;
    })[0] || {};
    const markRows = rows('webauthn.key.possibly-replaced', 'pla-gus');
    const guarded = credentials.removeKey('pla-gus', gusNew.credentialId);
    credentials.noteKeyUsed('pla-gus', gusOld.credentialId, 5);
    const cleared = credentials.keysOf('pla-gus').filter(function (one) {
      return one.credentialId === gusOld.credentialId;
    })[0] || {};
    const portalRow = new accountKeys.AccountKeys(
      accountKeys.AccountKeys.defaultDeps()).keyRow(marked);
    note(gusSecond.ok && marked.possiblyReplacedBy === gusNew.credentialId &&
         markRows.length === 1 && portalRow.possiblyReplaced &&
         !credentials.hasPassword('pla-gus') && !guarded.ok &&
         errorCodes.codeOf(guarded) === 'STS-AUTHN-0070' &&
         !cleared.possiblyReplacedBy,
         'K. a key registered under the same handle and AAGUID marks the ' +
         'older row, which the portal shows, the removal guard does not ' +
         'count, and a use clears',
         JSON.stringify([gusSecond.errors, marked.possiblyReplacedBy,
                         markRows.length, guarded,
                         cleared.possiblyReplacedBy]));

    // L. Two lanes per population (#1104).
    passkeyPolicy.select('pla-hal', '');
    const laneOff = webauthnPolicy.alongsideClassical();
    const both = passkeyPolicy.save('default', Object.assign({},
      passkeyPolicy.DEFAULTS, { lanes: 'both' }));
    passkeyPolicy.select('pla-hal', '');
    const laneOn = webauthnPolicy.alongsideClassical();
    const contradiction = passkeyPolicy.save('default', Object.assign({},
      passkeyPolicy.DEFAULTS, { lanes: 'both',
                                registrationMode: 'classical-only' }));
    passkeyPolicy.reset('default');
    note(laneOff === false && both.ok && laneOn === true &&
         !contradiction.ok &&
         errorCodes.codeOf(contradiction) === 'STS-AUTHN-0476',
         'L. a profile\'s lanes: both turns two lanes on for its people ' +
         'with the realm\'s setting off, and is refused beside ' +
         'classical-only (STS-AUTHN-0476)',
         JSON.stringify([laneOff, both.errors, laneOn,
                         contradiction.errors]));

    // M. The portal's Upgrade and its setting are gone.
    const ops = new accountKeys.AccountKeys(
      accountKeys.AccountKeys.defaultDeps()).accountOperations({
        BASE: '/account-api', PORTAL: '/portal' });
    let setting;
    try {
      setting = config.value('webauthn.pqcUpgrade');
    } catch (e) {
      // An unknown setting throws, which is what is being asserted.
      setting = undefined;
    }
    note(!ops.some(function (op) {
      return op.operationId === 'upgradeKey';
    }) && setting === undefined,
         'M. /account-api has no upgrade operation and webauthn.pqcUpgrade ' +
         'is no setting', String(setting));

    ldap.setGroupPolicy('pla-excluded', 'stsPostLoginPolicy', '');
    policy.reset('pla-excluded');
    policy.reset('default');
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
  const out = path.join(os.tmpdir(), 'sts-pla-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = Object.assign({}, process.env, { PLA_OUT: out, PLA_ROOT: ROOT,
    STS_HTTPS: 'false' });
  delete env.CONFIG_FILE;
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      cwd: ROOT, env: env, encoding: 'utf8', timeout: 240000,
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
  name: 'post_login',
  describe: 'post-login activities (#1096, #1100-#1105): the post-quantum ' +
            'passkey migration — the held session, Skip, the upgrade in ' +
            'place, alongside, required, a device that cannot, the ' +
            'attestation rule, the classical fallback, a possibly replaced ' +
            'row, two lanes per population, and the portal Upgrade gone',
  run: run
};
