// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/credential_removal_sessions.js
//
// ===========================================================================
// REMOVING A CREDENTIAL ENDS THE SESSIONS IT SIGNED IN, AND NO OTHER (#722).
//
// Removing a passkey used to end nothing: the relying parties were told over
// CAEP and every session the key had signed in kept working until it
// expired. `logout/logout.ts`'s `endFactorSessions()` ends them now, for the
// sessions whose authentication events `authn.sessionNamesFactor()` says
// the removed credential completed.
//
// Asserted in a CHILD PROCESS serving the stack on a loopback port, with
// REAL ceremonies from a software authenticator (`passkey_discoverable.js`'s)
// and real OAuth code and refresh grants:
//
//   1. THE PORTAL'S REMOVE (`POST /account-api/keys/remove`): a person signs
//      in with key A in one browser and key B in another, each session
//      holding a refresh token. Removing A answers 200 with `sessionsEnded`
//      1 and the sentence saying so, and the audit row counts it; A's
//      session cookie no longer signs anybody in and its refresh token is
//      `invalid_grant`; B's session and refresh token still work.
//   2. THE CONSOLE'S AND THE API'S `clear-key`, the same for another person.
//   3. THE AUTHENTICATOR APP (the console's `clear-totp`, the portal's
//      `remove`): a session a code completed ends; a password-only session
//      of the same person stays.
//   4. THE RECOVERY CODES (`clear-backup-codes`): a session a recovery code
//      completed ends; one the app completed stays.
//   5. THE EMAILED SECOND FACTOR (`clear-email-factor`, the portal's
//      `email-factor-off`): a session the emailed code completed as a
//      second factor ends; one an emailed sign-in link began as the FIRST
//      factor stays.
//   6. Nothing a removal did not authenticate is ended: a removal for a
//      person whose sessions none of it signed in answers 0.
//
// Sections 3 to 5 make their sessions through `authn.startSession()` with
// the credential detail each sign-in door hands it (`finishTotp()`,
// `finishBackupCode()`, `finishEmailSecondFactor()`,
// `finishEmailFirstFactor()`), because driving a one-time code, a recovery
// code and an emailed code through the screens is what their own files do;
// what is under test here is the removal reading the event they leave.
// ===========================================================================

delete process.env.CONFIG_FILE;

const path = require('path');
const os = require('os');
const fs = require('fs');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'credential_removal_sessions',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  const ROOT = process.env.CRS_ROOT;
  const OUT = process.env.CRS_OUT;
  const http = require('http');
  const nodeCrypto = require('crypto');
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };

  function browser(port) {
    const jar = {};
    const go = function (method, urlPath, opts) {
      const o = opts || {};
      return new Promise(function (resolve) {
        const body = o.form ? new URLSearchParams(o.form).toString() : '';
        const headers = {};
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
            let json = null;
            try {
              json = JSON.parse(text);
            } catch (e) {
              json = null;
            }
            resolve({ status: res.statusCode, headers: res.headers,
                      text: text, json: json });
          });
        });
        req.end(body);
      });
    };
    return { go: go, jar: jar };
  }

  // A SOFTWARE AUTHENTICATOR — `passkey_discoverable.js`'s, for its reason:
  // the server's half of the ceremony is under test, so the bytes are the
  // ones a real authenticator produces, signed with a real key.
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
      jwk: jwk,
      register: function (challenge, handle) {
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
                 clientExtensionResults: { credProps: { rk: true } },
                 response: {
                   attestationObject: attestationObject.toString('base64url'),
                   clientDataJSON: clientData('webauthn.create', challenge)
                     .toString('base64url'),
                   userHandle: handle || null } };
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
                   signature: signature.toString('base64url'),
                   userHandle: null } };
      }
    };
  };

  // A response object for a handler called in this process: what
  // `AccountApi.json()` and `startSession()` use of express's.
  const fakeRes = function () {
    const r = { statusCode: 0, body: '', headers: {}, req: null };
    r.status = function (s) { r.statusCode = s; return r; };
    r.set = function (k, v) { r.headers[String(k).toLowerCase()] = v;
                              return r; };
    r.setHeader = r.set;
    r.type = function () { return r; };
    r.send = function (b) { r.body = b; return r; };
    r.json = function () {
      try {
        return JSON.parse(r.body);
      } catch (e) {
        return null;
      }
    };
    return r;
  };

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const authnScreen = require(ROOT + '/tests/tools/authn_screen');
    const app = require(ROOT + '/common/app');
    const config = require(ROOT + '/common/config');
    const realms = require(ROOT + '/common/realms');
    const applications = require(ROOT + '/common/applications');
    const credentials = require(ROOT + '/common/credentials');
    const totp = require(ROOT + '/common/totp');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const audit = require(ROOT + '/common/audit');
    const authn = require(ROOT + '/authn/authn');
    const accountApi = require(ROOT + '/account-api/account_api');
    const actions = require(ROOT + '/admin-core/admin_actions');
    const authnPolicy = require(ROOT + '/common/authn_policy');
    const mail = require(ROOT + '/common/mail');
    const mailFactor = require(ROOT + '/common/mail_factor');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const ORIGIN = 'http://127.0.0.1:' + port;
    const RPID = '127.0.0.1';
    const REDIRECT = 'https://rp.crs.example/cb';
    const CLIENT = 'crs-public';
    const PASSWORD = 'correct-horse-battery-staple-crs-7!';
    const stamp = String(process.pid);
    config.setOverride('oauth2.consentRequired', false);

    applications.createApplication({ identifier: CLIENT,
      protocols: ['oauth2'],
      fields: { oauthClientId: CLIENT, oauthClientSecret: '',
                oauthRedirectUri: [REDIRECT],
                oauthTokenEndpointAuthMethod: 'none',
                oauthGrantType: ['authorization_code', 'refresh_token'] } });
    const person = function (name) {
      ldap.createUser(name, { invent: false });
      credentials.setPassword(name, PASSWORD);
    };

    // An authorization request, from a browser that may already hold a
    // session: the PKCE verifier and the answer.
    const authorize = async function (b) {
      const verifier = nodeCrypto.randomBytes(32).toString('base64url');
      const start = await b.go('GET', '/oauth2/authorize?' +
        new URLSearchParams({ client_id: CLIENT, response_type: 'code',
          redirect_uri: REDIRECT, scope: 'openid', state: 's',
          nonce: 'n-' + nodeCrypto.randomBytes(8).toString('hex'),
          code_challenge: nodeCrypto.createHash('sha256').update(verifier)
            .digest('base64url'),
          code_challenge_method: 'S256' }).toString());
      return { verifier: verifier, start: start };
    };
    const codeIn = function (location) {
      return location && String(location).indexOf(REDIRECT) === 0
        ? new URL(String(location)).searchParams.get('code') : null;
    };
    const redeem = async function (b, code, verifier) {
      const token = await b.go('POST', '/oauth2/token', { form: {
        grant_type: 'authorization_code', code: code,
        redirect_uri: REDIRECT, client_id: CLIENT,
        code_verifier: verifier } });
      return (token.json && token.json.refresh_token) || '';
    };
    // Does this browser's session still sign it in? An authorization
    // request it sends is answered with a code at once, or sent to sign in.
    const stillSignedIn = async function (b) {
      const a = await authorize(b);
      return !!codeIn(a.start.headers.location);
    };
    const refreshes = async function (refreshToken) {
      const r = await browser(port).go('POST', '/oauth2/token', { form: {
        grant_type: 'refresh_token', refresh_token: refreshToken,
        client_id: CLIENT } });
      return r;
    };
    // A REAL PASSKEY SIGN-IN: the screen, its passwordless box, the passkey
    // step's ceremony — the enrolment on first use for a person holding no
    // key, an assertion otherwise — and the code grant after it.
    const signInWithKey = async function (name, key) {
      const b = browser(port);
      const a = await authorize(b);
      const opened = await authnScreen.open({ port: port, jar: b.jar,
        at: String(a.start.headers.location || '') });
      const step = await authnScreen.follow({ port: port, jar: b.jar,
        opened: opened, fields: { action: 'login', username: name,
                                  password: '', webauthn_only: '1' } });
      const armed = await authnScreen.stepAct({ port: port, jar: b.jar,
        opened: step, op: 'webauthn/options', body: {} });
      const c = armed.json || {};
      const credential = c.mode === 'create'
        ? key.register(c.challenge, String((c.user || {}).id || ''))
        : key.assert(c.challenge);
      const answer = await authnScreen.stepAct({ port: port, jar: b.jar,
        opened: step, op: 'webauthn', body: {
          credential: JSON.stringify(credential) } });
      let refresh = '';
      if (answer.next === 'redirect') {
        const back = await b.go('GET', answer.location);
        const code = codeIn(back.headers.location);
        refresh = code ? await redeem(b, code, a.verifier) : '';
      }
      return { b: b, mode: String(c.mode || ''), next: answer.next,
               refresh: refresh, text: String(answer.text || '').slice(0, 200) };
    };
    // Two sessions of one person, one per key, each holding a refresh
    // token: A enrolled on first use, B added beside it and asserted.
    const twoKeySessions = async function (name) {
      person(name);
      const keyA = makeAuthenticator(RPID, ORIGIN);
      const keyB = makeAuthenticator(RPID, ORIGIN);
      const one = await signInWithKey(name, keyA);
      credentials.addKey(name, { credentialId: keyB.credentialId,
        publicKeyJwk: keyB.jwk, label: 'key B' }, 'primary');
      const two = await signInWithKey(name, keyB);
      return { keyA: keyA, keyB: keyB, one: one, two: two };
    };
    const auditRow = function (action, target) {
      return audit.list().filter(function (r) {
        return r.action === action &&
               (r.target === target || r.actor === target);
      }).slice(-1)[0] || null;
    };
    // An account API operation's handler, called as the wrapper calls it,
    // for the person the token would have named.
    const accountOp = function (method, opPath) {
      return accountApi.operations().filter(function (op) {
        return op.method === method && op.path === opPath;
      })[0];
    };
    const fakeReq = function () {
      return { headers: { host: '127.0.0.1:' + port }, protocol: 'http',
               method: 'POST', url: '/', ip: '127.0.0.1',
               socket: { remoteAddress: '127.0.0.1' },
               connection: { remoteAddress: '127.0.0.1' } };
    };
    const callAccount = async function (method, opPath, username, body) {
      const op = accountOp(method, opPath);
      const res = fakeRes();
      if (!op) {
        return { status: 0, json: null };
      }
      await realms.run(realms.DEFAULT_REALM, async function () {
        await op.handler(fakeReq(), res, { username: username,
          sub: '', realm: realms.DEFAULT_REALM, clientId: 'sts-user-portal',
          scopes: ['account:manage'] }, { body: body, query: {} });
      });
      return { status: res.statusCode, json: res.json() };
    };
    // A session made as a sign-in door makes one, for sections 3 to 5.
    const sessionFor = function (name, amr, acr, credential) {
      return realms.run(realms.DEFAULT_REALM, function () {
        return authn.startSession(fakeRes(), name, amr, acr,
          'OAuth 2.0 / OIDC', { credential: credential });
      });
    };
    const live = function (session) {
      return !!(session && authn.sessionById(session.id));
    };
    const ctx = { via: 'api', actor: 'crs-admin', base: ORIGIN };

    // ====================================================================
    // 1. THE PORTAL'S REMOVE
    // ====================================================================
    const ALICE = 'crs-alice-' + stamp;
    const a = await twoKeySessions(ALICE);
    note(a.one.mode === 'create' && a.one.next === 'redirect' &&
         !!a.one.refresh && a.two.mode === 'get' &&
         a.two.next === 'redirect' && !!a.two.refresh,
         '1. (precondition) alice signs in with key A, enrolled on first ' +
         'use, in one browser and with key B in another, each holding a ' +
         'refresh token', JSON.stringify([a.one.mode, a.one.next,
           !!a.one.refresh, a.one.text, a.two.mode, a.two.next,
           !!a.two.refresh, a.two.text]));
    note(await stillSignedIn(a.one.b) && await stillSignedIn(a.two.b),
         '1. (precondition) both sessions sign their browser in');
    const removed = await callAccount('POST', '/account-api/keys/remove',
      ALICE, { credentialId: a.keyA.credentialId });
    const removedJson = removed.json || {};
    note(removed.status === 200 && removedJson.ok === true &&
         removedJson.sessionsEnded === 1 &&
         /The session signed in with it has ended\./
           .test(String(removedJson.message || '')),
         '1a. removing key A at the portal answers 200, sessionsEnded 1, ' +
         'and says the session it signed in has ended',
         removed.status + ' ' + JSON.stringify(removedJson).slice(0, 300));
    const portalRow = auditRow('portal.key.removed', ALICE);
    note(portalRow && portalRow.detail &&
         String(portalRow.detail.sessionsEnded) === '1',
         '1b. the audit row counts the session ended',
         JSON.stringify(portalRow && portalRow.detail));
    note(!(await stillSignedIn(a.one.b)),
         '1c. key A\'s session cookie no longer signs its browser in');
    const r1 = await refreshes(a.one.refresh);
    note(r1.status === 400 && r1.json && r1.json.error === 'invalid_grant',
         '1d. and the refresh token issued on it is refused (invalid_grant)',
         r1.status + ' ' + r1.text.slice(0, 160));
    note(await stillSignedIn(a.two.b),
         '1e. key B\'s session still signs its browser in');
    const r2 = await refreshes(a.two.refresh);
    note(r2.status === 200 && r2.json && !!r2.json.access_token,
         '1f. and the refresh token issued on it still works',
         r2.status + ' ' + r2.text.slice(0, 160));
    note(audit.list().some(function (r) {
      return r.action === 'logout.selective' && r.target === ALICE;
    }), '1g. the session ended through the logout model\'s selective ' +
        'sign-out, with its audit row');

    // ====================================================================
    // 2. THE CONSOLE'S AND THE API'S clear-key
    // ====================================================================
    const BOB = 'crs-bob-' + stamp;
    const bob = await twoKeySessions(BOB);
    note(!!bob.one.refresh && !!bob.two.refresh,
         '2. (precondition) bob signs in with key C and key D',
         JSON.stringify([bob.one.next, bob.one.text, bob.two.next,
                         bob.two.text]));
    const cleared = await realms.run(realms.DEFAULT_REALM, function () {
      return actions.usersAction({ action: 'clear-key', user: BOB,
        credentialId: bob.keyA.credentialId }, ctx);
    });
    note(cleared && cleared.ok === true && cleared.sessionsEnded === 1 &&
         /1 session it signed in was ended/.test(String(cleared.message)),
         '2a. clear-key answers ok with sessionsEnded 1, and says so',
         JSON.stringify(cleared).slice(0, 300));
    const clearRow = auditRow('admin.mfa.key.cleared', BOB);
    note(clearRow && clearRow.detail &&
         String(clearRow.detail.sessionsEnded) === '1',
         '2b. the audit row counts it', JSON.stringify(clearRow &&
                                                         clearRow.detail));
    const r3 = await refreshes(bob.one.refresh);
    note(!(await stillSignedIn(bob.one.b)) && r3.status === 400,
         '2c. key C\'s session and its refresh token are refused',
         r3.status + ' ' + r3.text.slice(0, 160));
    const r4 = await refreshes(bob.two.refresh);
    note(await stillSignedIn(bob.two.b) && r4.status === 200,
         '2d. key D\'s session and its refresh token still work',
         r4.status + ' ' + r4.text.slice(0, 160));

    // ====================================================================
    // 3. THE AUTHENTICATOR APP
    // ====================================================================
    const CAROL = 'crs-carol-' + stamp;
    const enrolTotp = function (name) {
      return realms.run(realms.DEFAULT_REALM, function () {
        const begun = credentials.beginTotpEnrolment(name, {});
        return credentials.confirmTotpEnrolment(name,
          totp.codeAt(begun.secret, Date.now(), begun));
      });
    };
    person(CAROL);
    enrolTotp(CAROL);
    let byCode = sessionFor(CAROL, ['pwd', 'otp'], 'mfa', { kind: 'totp' });
    let byPassword = sessionFor(CAROL, ['pwd'], '1', { kind: 'password' });
    const totpCleared = await realms.run(realms.DEFAULT_REALM, function () {
      return actions.usersAction({ action: 'clear-totp', user: CAROL }, ctx);
    });
    note(totpCleared.ok && totpCleared.sessionsEnded === 1 &&
         !live(byCode) && live(byPassword),
         '3a. clear-totp ends the session the app\'s code completed and ' +
         'leaves the password-only one', JSON.stringify(totpCleared)
           .slice(0, 300) + ' code=' + live(byCode) + ' password=' +
         live(byPassword));
    enrolTotp(CAROL);
    byCode = sessionFor(CAROL, ['pwd', 'otp'], 'mfa', { kind: 'totp' });
    const totpRemoved = await callAccount('POST', '/account-api/mfa', CAROL,
                                          { action: 'remove' });
    note(totpRemoved.status === 200 && totpRemoved.json &&
         totpRemoved.json.sessionsEnded === 1 && !live(byCode) &&
         live(byPassword),
         '3b. the portal\'s remove does the same',
         totpRemoved.status + ' ' + JSON.stringify(totpRemoved.json)
           .slice(0, 300));

    // ====================================================================
    // 4. THE RECOVERY CODES
    // ====================================================================
    const DAVE = 'crs-dave-' + stamp;
    person(DAVE);
    enrolTotp(DAVE);
    await realms.run(realms.DEFAULT_REALM, function () {
      const begun = credentials.beginBackupCodes(DAVE);
      return credentials.confirmBackupCodes(DAVE, begun.handle);
    });
    const byRecovery = sessionFor(DAVE, ['pwd', 'otp'], 'mfa',
                                  { kind: 'backup-code' });
    const byApp = sessionFor(DAVE, ['pwd', 'otp'], 'mfa', { kind: 'totp' });
    const codesCleared = await realms.run(realms.DEFAULT_REALM, function () {
      return actions.usersAction({ action: 'clear-backup-codes', user: DAVE },
                                 ctx);
    });
    note(codesCleared.ok && codesCleared.sessionsEnded === 1 &&
         !live(byRecovery) && live(byApp),
         '4. clear-backup-codes ends the session a recovery code completed ' +
         'and leaves the one the app completed',
         JSON.stringify(codesCleared).slice(0, 300));

    // ====================================================================
    // 5. THE EMAILED SECOND FACTOR
    // ====================================================================
    const ERIN = 'crs-erin-' + stamp;
    person(ERIN);
    await realms.run(realms.DEFAULT_REALM, function () {
      mail.directory().writeAddress(ERIN, 'erin@crs.example', 'admin');
      const saved = authnPolicy.save('default', Object.assign({},
        authnPolicy.DEFAULTS, { emailCodeSecondFactor: true,
          emailLinkSecondFactor: true, emailLinkPrimary: true,
          emailFailureLimit: 5 }));
      note(saved.ok, '5. (precondition) the policy offers the emailed ' +
           'second factor, and the emailed link as a first factor',
           JSON.stringify(saved.errors || []));
    });
    // The emailed sign-in link's session first, while erin holds no second
    // factor: once she does, a first factor alone signs nobody in, and the
    // link would go on to a second step.
    const byLink = sessionFor(ERIN, ['otp'], '1', { kind: 'email-link' });
    note(live(byLink), '5. (precondition) an emailed sign-in link signs ' +
         'erin in as the first factor');
    await realms.run(realms.DEFAULT_REALM, function () {
      const opted = mailFactor.optIn(ERIN, 'code', ERIN, 'test');
      note(opted.ok, '5. (precondition) erin opts in to the emailed code',
           JSON.stringify(opted.errors || []));
    });
    let byEmail = sessionFor(ERIN, ['pwd', 'otp'], 'mfa',
                             { kind: 'email-code' });
    const emailCleared = await realms.run(realms.DEFAULT_REALM, function () {
      return actions.usersAction({ action: 'clear-email-factor',
                                   user: ERIN }, ctx);
    });
    note(emailCleared.ok && emailCleared.sessionsEnded === 1 &&
         !live(byEmail) && live(byLink),
         '5a. clear-email-factor ends the session the emailed code ' +
         'completed as a second factor and leaves the one an emailed link ' +
         'began as the first', JSON.stringify(emailCleared).slice(0, 300) +
         ' code=' + live(byEmail) + ' link=' + live(byLink));
    await realms.run(realms.DEFAULT_REALM, function () {
      mailFactor.optIn(ERIN, 'code', ERIN, 'test');
    });
    byEmail = sessionFor(ERIN, ['pwd', 'otp'], 'mfa',
                         { kind: 'email-code' });
    const emailOff = await callAccount('POST', '/account-api/mfa', ERIN,
                                       { action: 'email-factor-off' });
    note(emailOff.status === 200 && emailOff.json &&
         emailOff.json.sessionsEnded === 1 && !live(byEmail) && live(byLink),
         '5b. the portal\'s email-factor-off does the same',
         emailOff.status + ' ' + JSON.stringify(emailOff.json).slice(0, 300));

    // ====================================================================
    // 6. NOTHING IT DID NOT AUTHENTICATE
    // ====================================================================
    const FRANK = 'crs-frank-' + stamp;
    person(FRANK);
    credentials.addKey(FRANK, { credentialId: 'crs-frank-spare',
      publicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' },
      label: 'spare' }, 'mfa');
    const frankSession = sessionFor(FRANK, ['pwd'], '1',
                                    { kind: 'password' });
    const spare = await realms.run(realms.DEFAULT_REALM, function () {
      return actions.usersAction({ action: 'clear-key', user: FRANK,
        credentialId: 'crs-frank-spare' }, ctx);
    });
    note(spare.ok && spare.sessionsEnded === 0 && live(frankSession),
         '6. removing a key that signed in none of a person\'s sessions ' +
         'ends none', JSON.stringify(spare).slice(0, 300));

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
  const out = path.join(os.tmpdir(), 'sts-crs-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = Object.assign({}, process.env, { CRS_OUT: out, CRS_ROOT: ROOT,
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
  name: 'credential_removal_sessions',
  describe: 'removing a credential ends the sessions it signed in (#722)',
  run: run
};
