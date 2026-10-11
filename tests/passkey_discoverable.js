// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/passkey_discoverable.js
//
// ===========================================================================
// PASSKEYS AS DISCOVERABLE CREDENTIALS (#474).
//
// Three changes, each asserted with a REAL ceremony from a software
// authenticator, in a CHILD PROCESS serving the stack on a loopback port
// (`passkey_first_use_product.js`'s harness):
//
//   * THE USER HANDLE is 64 random bytes per person (WebAuthn Level 3
//     section 5.4.3), never the username: minted on the entry, given to the
//     browser as `data-userid`, recorded on the key row;
//   * SECTION 7.2 STEP 6: a returned `userHandle` must be the one the key
//     was created under, at the passkey step after a typed username too;
//   * A SIGN-IN WITH NO USERNAME (the passkey policy's `allowUsernameless`,
//     off by default; `webauthn.usernameless` until #527):
//     the screen's button and autofill, the handle naming the account, user
//     verification REQUIRED, the session `amr ["hwk","user"]` `acr "mfa"`,
//     a key from before #474 told to type its username, a credential nobody
//     holds reported to the browser (`signalUnknownCredential`).
//
// Asserted:
//   1. OFF BY DEFAULT: no passkey button, no autofill token, and a posted
//      `action=passkey` refused with STS-AUTHN-0301.
//   2. A key registered at the sign-in screen is created under a minted
//      handle that is not the username's bytes, and the row records it.
//   3. ON: the screen draws the button, the autofill token, the script and
//      `script-src 'self'`; a usernameless assertion signs the owner in and
//      the ID Token says `amr ["hwk","user"]`, `acr "mfa"`.
//   4. The same assertion again is refused (the challenge is spent).
//   5. An assertion WITHOUT user verification is refused.
//   6. A handle nobody holds: STS-AUTHN-0302, and the page names the
//      credential for `signalUnknownCredential`.
//   7. Somebody else's handle with this credential: refused.
//   8. A key registered before #474 (no handle on its row): STS-AUTHN-0304
//      without a username, accepted where the username is typed — and a
//      wrong handle there is STS-AUTHN-0303.
//   9. A SECOND-FACTOR key does not answer a usernameless sign-in.
//  10. The real button with the script blocked: told it needs JavaScript.
//  11. The portal's enrolment carries the person's handle, and a passkey is
//      asked for with `residentKey: required`; the key lists say which
//      passkey signs in with no username.
//  12. `webauthn.primaryAllowed` off takes the usernameless sign-in away.
// ===========================================================================

delete process.env.CONFIG_FILE;

const path = require('path');
const os = require('os');
const fs = require('fs');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'passkey_discoverable',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// Runs in the child. Stringified, so it may use nothing from this file's
// scope, and — code in a `node -e` child — is exempt from the Entering/Leaving
// rule (root CLAUDE.md, *Code style*).
function childMain() {
  const ROOT = process.env.PKD_ROOT;
  const OUT = process.env.PKD_OUT;
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
            resolve({ status: res.statusCode, headers: res.headers,
                      text: text });
          });
        });
        req.end(body);
      });
    };
    return { go: go, jar: jar };
  }

  // A SOFTWARE AUTHENTICATOR — `wsfed_wauth_step_up.js`'s, which holds the
  // user handle it was created under and hands it back on every assertion,
  // as a discoverable credential does.
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
    let userHandle = '';
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
      handle: function () { return userHandle; },
      setHandle: function (h) { userHandle = h; },
      register: function (challenge, handle) {
        userHandle = handle;
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
                     .toString('base64url') } };
      },
      // `uv` false clears the UV flag (0x04): user presence only.
      assert: function (challenge, opts) {
        const o = opts || {};
        signCount += 1;
        const data = authData({ flags: o.uv === false ? 0x01 : 0x05,
                                signCount: signCount });
        const cdj = clientData('webauthn.get', challenge);
        const signature = nodeCrypto.sign(
          'sha256', Buffer.concat([data, sha256(cdj)]), pair.privateKey);
        const handle = o.handle === undefined ? userHandle : o.handle;
        return { id: credentialId.toString('base64url'),
                 rawId: credentialId.toString('base64url'),
                 type: 'public-key',
                 response: {
                   authenticatorData: data.toString('base64url'),
                   clientDataJSON: cdj.toString('base64url'),
                   signature: signature.toString('base64url'),
                   userHandle: handle || null } };
      }
    };
  };
  const dataAttribute = function (html, name, within) {
    let text = html;
    if (within) {
      const at = html.indexOf('id="' + within + '"');
      text = at < 0 ? '' : html.slice(at, html.indexOf('>', at));
    }
    const found = new RegExp(' data-' + name + '="([^"]*)"').exec(text);
    return found ? found[1].replace(/&quot;/g, '"').replace(/&amp;/g, '&')
      : '';
  };
  const hiddenFields = function (html) {
    const form = {};
    (html.match(/<input type="hidden"[^>]*>/g) || []).forEach(function (tag) {
      const name = /name="([^"]+)"/.exec(tag);
      const value = /value="([^"]*)"/.exec(tag);
      if (name && !/ disabled/.test(tag)) {
        form[name[1]] = value ? value[1].replace(/&amp;/g, '&') : '';
      }
    });
    return form;
  };

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const config = require(ROOT + '/common/config');
    // #527: usernameless sign-in is the passkey policy's now.
    const passkeyPolicy = require(ROOT + '/common/passkey_policy');
    const applications = require(ROOT + '/common/applications');
    const credentials = require(ROOT + '/common/credentials');
    const webauthnPolicy = require(ROOT + '/authn/webauthn_policy');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const audit = require(ROOT + '/common/audit');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const ORIGIN = 'http://127.0.0.1:' + port;
    const RPID = '127.0.0.1';
    const REDIRECT = 'https://rp.pkd.example/cb';
    const PASSWORD = 'correct-horse-battery-staple-pkd-7!';
    config.setOverride('oauth2.consentRequired', false);

    applications.createApplication({ identifier: 'pkd-public',
      protocols: ['oauth2'],
      fields: { oauthClientId: 'pkd-public', oauthClientSecret: '',
                oauthRedirectUri: [REDIRECT],
                oauthTokenEndpointAuthMethod: 'none',
                oauthGrantType: ['authorization_code'] } });
    ['pkd-alice', 'pkd-bob', 'pkd-legacy', 'pkd-carol'].forEach(
      function (name) {
        ldap.createUser(name, { invent: false });
        credentials.setPassword(name, PASSWORD);
      });

    const codeRecorded = function (code) {
      return audit.list().some(function (row) {
        return row.errorCode === code;
      });
    };
    // The sign-in screen, reached the way a person reaches it.
    const screenFor = async function () {
      const b = browser(port);
      const verifier = nodeCrypto.randomBytes(32).toString('base64url');
      const start = await b.go('GET', '/oauth2/authorize?' +
        new URLSearchParams({ client_id: 'pkd-public', response_type: 'code',
          redirect_uri: REDIRECT, scope: 'openid', state: 's',
          nonce: 'n-' + nodeCrypto.randomBytes(8).toString('hex'),
          code_challenge: nodeCrypto.createHash('sha256').update(verifier)
            .digest('base64url'),
          code_challenge_method: 'S256' }).toString());
      const screen = await b.go('GET', String(start.headers.location || ''));
      return { b: b, screen: screen, verifier: verifier };
    };
    // The screen's usernameless form, posted with an assertion.
    const usernameless = async function (s, credential) {
      const form = hiddenFields(s.screen.text);
      form.action = 'passkey';
      form.passkey_credential = credential ? JSON.stringify(credential) : '';
      return s.b.go('POST', '/authn/login', { form: form });
    };
    // Follows a finished sign-in to the code and redeems it.
    const idTokenOf = async function (s, posted) {
      if (!(posted.status === 302 || posted.status === 303)) {
        return null;
      }
      const back = await s.b.go('GET', String(posted.headers.location));
      const code = new URL(String(back.headers.location || ''),
                           'https://x').searchParams.get('code');
      if (!code) {
        return null;
      }
      const token = await s.b.go('POST', '/oauth2/token', { form: {
        grant_type: 'authorization_code', code: code,
        redirect_uri: REDIRECT, client_id: 'pkd-public',
        code_verifier: s.verifier } });
      let idToken = '';
      try {
        idToken = JSON.parse(token.text).id_token || '';
      } catch (e) {
        // A token response that is not JSON: no ID Token, which the check
        // that reads this says with the response beside it.
        idToken = '';
      }
      return idToken ? JSON.parse(Buffer.from(idToken.split('.')[1],
                                              'base64url').toString('utf8'))
                     : null;
    };

    // 1. Off by default.
    let s = await screenFor();
    note(s.screen.status === 200 && !/id="wa-passkey"/.test(s.screen.text) &&
         !/autocomplete="username webauthn"/.test(s.screen.text),
         '1a. OFF BY DEFAULT: the screen draws no passkey button and no ' +
         'autofill token', s.screen.status + ' ' + s.screen.text.slice(0, 160));
    let posted = await usernameless(s, null);
    note(posted.status === 200 && !(posted.status === 302 ||
                                    posted.status === 303) &&
         codeRecorded('STS-AUTHN-0301'),
         '1b. and a posted action=passkey is refused with STS-AUTHN-0301',
         posted.status + ' ' + posted.text.slice(0, 200));

    // 2. A key registered at the sign-in screen (development's first use),
    // created under a minted handle.
    const alice = makeAuthenticator(RPID, ORIGIN);
    s = await screenFor();
    let form = hiddenFields(s.screen.text);
    form.username = 'pkd-alice';
    form.password = '';
    form.webauthn_only = '1';
    form.action = 'login';
    const step = await s.b.go('POST', '/authn/login', { form: form });
    const givenHandle = dataAttribute(step.text, 'userid');
    note(dataAttribute(step.text, 'mode') === 'create' &&
         credentials.isUserHandle(givenHandle) &&
         givenHandle !== Buffer.from('pkd-alice').toString('base64url') &&
         givenHandle === credentials.userHandleOf('pkd-alice'),
         '2a. the enrol ceremony names a minted 64-byte user handle — the ' +
         'person\'s own, on their entry — and not the username\'s bytes',
         givenHandle);
    const mfaId = (step.text.match(/name="mfa_id" value="([^"]+)"/) || [])[1];
    const registered = await s.b.go('POST', '/authn/webauthn', { form: {
      mfa_id: mfaId, mode: 'create',
      credential: JSON.stringify(alice.register(
        dataAttribute(step.text, 'challenge'), givenHandle)) } });
    const aliceKey = credentials.keysOf('pkd-alice')[0] || {};
    note((registered.status === 302 || registered.status === 303) &&
         aliceKey.userHandle === givenHandle && aliceKey.role === 'primary' &&
         aliceKey.discoverable === true,
         '2b. and the key row records the handle it was created under',
         registered.status + ' ' + JSON.stringify(aliceKey).slice(0, 200));

    // 3. On.
    const turnedOn = passkeyPolicy.save('default', Object.assign({},
      passkeyPolicy.DEFAULTS, { allowUsernameless: true }));
    note(turnedOn.ok, '3. the passkey policy allows a usernameless sign-in ' +
         '(#527)', JSON.stringify(turnedOn.errors || []));
    s = await screenFor();
    const csp = String(s.screen.headers['content-security-policy'] || '');
    note(/id="wa-passkey-go"[^>]*value="passkey"/.test(s.screen.text) &&
         /autocomplete="username webauthn"/.test(s.screen.text) &&
         /<script src="\/authn\/webauthn\.js">/.test(s.screen.text) &&
         /script-src 'self'/.test(csp) && /frame-ancestors/.test(csp) &&
         JSON.parse(dataAttribute(s.screen.text, 'options', 'wa-passkey') ||
                    '{}').userVerification === 'required',
         '3a. ON: the screen draws the real button, the autofill token, the ' +
         'script under script-src \'self\' (framing kept), and asks for user ' +
         'verification', csp);
    posted = await usernameless(s, alice.assert(
      dataAttribute(s.screen.text, 'challenge', 'wa-passkey')));
    const claims = await idTokenOf(s, posted);
    note(claims && JSON.stringify(claims.amr) === '["hwk","user"]' &&
         claims.acr === 'mfa',
         '3b. a usernameless assertion signs its owner in: amr ' +
         '["hwk","user"], acr "mfa"', posted.status + ' ' +
         JSON.stringify(claims) + ' ' + posted.text.slice(0, 200));

    // 4. Replay.
    s = await screenFor();
    const once = alice.assert(dataAttribute(s.screen.text, 'challenge',
                                            'wa-passkey'));
    posted = await usernameless(s, once);
    note(posted.status === 302 || posted.status === 303,
         '4a. (a fresh usernameless sign-in)', posted.status);
    const again = await screenFor();
    posted = await usernameless(again, once);
    note(posted.status === 200,
         '4b. the same assertion on another screen is refused — its ' +
         'challenge is not that screen\'s', posted.status);

    // 5. No user verification.
    s = await screenFor();
    posted = await usernameless(s, alice.assert(
      dataAttribute(s.screen.text, 'challenge', 'wa-passkey'), { uv: false }));
    note(posted.status === 200 &&
         /could not sign you in/.test(posted.text),
         '5. an assertion WITHOUT user verification is refused, whatever ' +
         'webauthn.userVerification says', posted.status);

    // 6. A handle nobody holds.
    s = await screenFor();
    const stranger = credentials.newUserHandle();
    posted = await usernameless(s, alice.assert(
      dataAttribute(s.screen.text, 'challenge', 'wa-passkey'),
      { handle: stranger }));
    note(posted.status === 200 && codeRecorded('STS-AUTHN-0302') &&
         dataAttribute(posted.text, 'unknown', 'wa-passkey') ===
           alice.credentialId,
         '6. a handle nobody holds is STS-AUTHN-0302, and the page names ' +
         'the credential for signalUnknownCredential', posted.status);

    // 7. Somebody else's handle.
    const bobHandle = credentials.userHandleOf('pkd-bob', { mint: true });
    s = await screenFor();
    posted = await usernameless(s, alice.assert(
      dataAttribute(s.screen.text, 'challenge', 'wa-passkey'),
      { handle: bobHandle }));
    note(posted.status === 200 && credentials.isUserHandle(bobHandle),
         '7. alice\'s credential presented under bob\'s handle is refused',
         posted.status);

    // 8. A key registered before #474.
    const legacy = makeAuthenticator(RPID, ORIGIN);
    legacy.setHandle(Buffer.from('pkd-legacy').toString('base64url'));
    credentials.addKey('pkd-legacy', { credentialId: legacy.credentialId,
      publicKeyJwk: legacy.jwk }, 'primary');
    s = await screenFor();
    posted = await usernameless(s, legacy.assert(
      dataAttribute(s.screen.text, 'challenge', 'wa-passkey')));
    note(posted.status === 200 && codeRecorded('STS-AUTHN-0304') &&
         /Type your username/.test(posted.text) &&
         !dataAttribute(posted.text, 'unknown', 'wa-passkey'),
         '8a. a key from before #474 is told to type its username, and is ' +
         'not reported unknown', posted.status + ' ' +
         posted.text.slice(0, 200));
    const typed = async function (handle) {
      const t = await screenFor();
      const f = hiddenFields(t.screen.text);
      f.username = 'pkd-legacy';
      f.password = '';
      f.webauthn_only = '1';
      f.action = 'login';
      const st = await t.b.go('POST', '/authn/login', { form: f });
      const id = (st.text.match(/name="mfa_id" value="([^"]+)"/) || [])[1];
      return t.b.go('POST', '/authn/webauthn', { form: {
        mfa_id: id, mode: 'get',
        credential: JSON.stringify(legacy.assert(
          dataAttribute(st.text, 'challenge', 'wa-data'),
          handle === undefined ? {} : { handle: handle })) } });
    };
    posted = await typed();
    note(posted.status === 302 || posted.status === 303,
         '8b. where the username is typed it still signs in', posted.status +
         ' ' + posted.text.slice(0, 200));
    posted = await typed(credentials.newUserHandle());
    note(posted.status === 200 && codeRecorded('STS-AUTHN-0303'),
         '8c. and a handle that is not the key\'s is refused there, ' +
         'STS-AUTHN-0303 (section 7.2 step 6)', posted.status);

    // 9. A second-factor key.
    const carol = makeAuthenticator(RPID, ORIGIN);
    const carolHandle = credentials.userHandleOf('pkd-carol', { mint: true });
    carol.setHandle(carolHandle);
    credentials.addKey('pkd-carol', { credentialId: carol.credentialId,
      publicKeyJwk: carol.jwk, userHandle: carolHandle }, 'mfa');
    s = await screenFor();
    posted = await usernameless(s, carol.assert(
      dataAttribute(s.screen.text, 'challenge', 'wa-passkey')));
    note(posted.status === 200,
         '9. a SECOND-FACTOR key does not sign anybody in without a password',
         posted.status);

    // 10. The real button, script blocked.
    s = await screenFor();
    posted = await usernameless(s, null);
    note(posted.status === 200 && /needs JavaScript/.test(posted.text) &&
         codeRecorded('STS-AUTHN-0022'),
         '10. the button with the script blocked is told the ceremony needs ' +
         'JavaScript', posted.status);

    // 11. The portal's enrolment, and a passkey's resident key.
    const begun = credentials.beginKeyEnrolment('pkd-bob',
      { role: 'primary', kind: 'passkey' });
    const selection = webauthnPolicy.creationOptions(RPID, 'passkey')
      .authenticatorSelection;
    note(begun.ok && begun.userHandle === bobHandle &&
         selection.residentKey === 'required' &&
         selection.requireResidentKey === true,
         '11. the portal\'s enrolment carries the person\'s handle, and a ' +
         'passkey asks residentKey: required', JSON.stringify(selection));
    credentials.abandonKeyEnrolment('pkd-bob');
    const ready = function (name) {
      return credentials.withoutUsername(credentials.keysOf(name)[0]);
    };
    note(ready('pkd-alice').ready && !ready('pkd-legacy').ready &&
         !ready('pkd-carol').ready &&
         /create it again/.test(ready('pkd-legacy').text),
         '11b. the key lists say which passkey signs in with no username: ' +
         'alice\'s does, the key from before #474 and the second-step key ' +
         'do not', JSON.stringify([ready('pkd-alice'), ready('pkd-legacy'),
                                   ready('pkd-carol')]));

    // 12. primaryAllowed off.
    config.setOverride('webauthn.primaryAllowed', false);
    try {
      s = await screenFor();
      note(!/id="wa-passkey"/.test(s.screen.text),
           '12. webauthn.primaryAllowed off takes the usernameless sign-in ' +
           'away');
    } finally {
      config.clearOverride('webauthn.primaryAllowed');
    }
    passkeyPolicy.reset('default');
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
  const out = path.join(os.tmpdir(), 'sts-pkd-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = Object.assign({}, process.env, { PKD_OUT: out, PKD_ROOT: ROOT,
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
  name: 'passkey_discoverable',
  describe: 'passkeys as discoverable credentials: the user handle, section ' +
            '7.2 step 6, and the usernameless sign-in (#474)',
  run: run
};
