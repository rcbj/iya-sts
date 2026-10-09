// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/passkey_pin_length.js
//
// ===========================================================================
// A MINIMUM SECURITY-KEY PIN LENGTH (#529): the passkey policy's
// `enforcePinLength`, `minPinLength` and `pinLengthOnlyIfSupported`, with
// REAL ceremonies from a software authenticator that reports — or does not —
// CTAP 2.1 section 12.4's `minPinLength` in its authenticator extension
// outputs, in a CHILD PROCESS serving the stack on a loopback port
// (`passkey_backup_eligible.js`'s harness):
//
//   1. OFF BY DEFAULT: the registration options ask for no minPinLength, and
//      a key reporting a short minimum registers.
//   2. ON (minimum 6): the options ask for it; a key reporting 8 registers
//      and its row records 8; one reporting 4 is refused (STS-AUTHN-0314),
//      the page saying why; one that reports nothing is refused too.
//   3. `pinLengthOnlyIfSupported` on: a key that reports nothing registers.
//   4. AT SIGN-IN: the minimum raised to 10, the key that reported 8 does
//      not sign in (STS-AUTHN-0315, a session.refuse row); the key that
//      reported nothing signs in only while `pinLengthOnlyIfSupported` is on.
//   5. Off again: every key signs in.
// ===========================================================================

delete process.env.CONFIG_FILE;

const path = require('path');
const os = require('os');
const fs = require('fs');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'passkey_pin_length',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// Runs in the child. Stringified, so it may use nothing from this file's
// scope, and — code in a `node -e` child — is exempt from the Entering/Leaving
// rule (root CLAUDE.md, *Code style*).
function childMain() {
  const ROOT = process.env.PKP_ROOT;
  const OUT = process.env.PKP_OUT;
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

  // A SOFTWARE AUTHENTICATOR — `passkey_backup_eligible.js`'s, whose
  // registration may report a minimum PIN length in its authenticator
  // extension outputs, which is the whole of what this file varies.
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
  // `pin` (#529): a whole number is the minimum PIN length the key reports
  // in its extension outputs (CTAP 2.1 section 12.4), the ED flag set;
  // anything else reports nothing.
  const cborUint = function (n) {
    return n < 24 ? Buffer.from([n]) : Buffer.from([0x18, n]);
  };
  const makeAuthenticator = function (rpId, origin, pin) {
    const reports = typeof pin === 'number';
    const backupBits = 0;
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
      // `backup` (#528): 'eligible' sets BE (0x08), 'synced' BE and BS
      // (0x10); anything else leaves both clear, a device-bound key.
      register: function (challenge, handle) {
        userHandle = handle;
        let data = authData({ flags: 0x45 | backupBits | (reports ? 0x80 : 0),
                              signCount: signCount, attested: true });
        if (reports) {
          data = Buffer.concat([data, cborMapHeader(1),
                                cborText('minPinLength'), cborUint(pin)]);
        }
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
        const data = authData({ flags: (o.uv === false ? 0x01 : 0x05) |
                                       backupBits,
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
    const passkeyPolicy = require(ROOT + '/common/passkey_policy');
    const applications = require(ROOT + '/common/applications');
    const credentials = require(ROOT + '/common/credentials');
    const errorCodes = require(ROOT + '/common/error_codes');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const audit = require(ROOT + '/common/audit');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const ORIGIN = 'http://127.0.0.1:' + port;
    const RPID = '127.0.0.1';
    const REDIRECT = 'https://rp.pkp.example/cb';
    const PASSWORD = 'correct-horse-battery-staple-pkp-7!';
    config.setOverride('oauth2.consentRequired', false);

    applications.createApplication({ identifier: 'pkp-public',
      protocols: ['oauth2'],
      fields: { oauthClientId: 'pkp-public', oauthClientSecret: '',
                oauthRedirectUri: [REDIRECT],
                oauthTokenEndpointAuthMethod: 'none',
                oauthGrantType: ['authorization_code'] } });
    ['pkp-alice', 'pkp-bob', 'pkp-carol', 'pkp-dave', 'pkp-erin',
     'pkp-frank'].forEach(
      function (name) {
        ldap.createUser(name, { invent: false });
        credentials.setPassword(name, PASSWORD);
      });

    const webauthnPolicy = require(ROOT + '/authn/webauthn_policy');
    const sessionRefused = function (name, code) {
      return audit.list().some(function (row) {
        return row.action === 'session.refuse' && row.errorCode === code &&
               String(row.actor) === name;
      });
    };
    const codeRecorded = function (code) {
      return audit.list().some(function (row) {
        return row.errorCode === code;
      });
    };
    const policy = function (fields) {
      return passkeyPolicy.save('default', Object.assign({},
        passkeyPolicy.DEFAULTS, fields));
    };
    const screenFor = async function () {
      const b = browser(port);
      const start = await b.go('GET', '/oauth2/authorize?' +
        new URLSearchParams({ client_id: 'pkp-public', response_type: 'code',
          redirect_uri: REDIRECT, scope: 'openid', state: 's',
          nonce: 'n-' + nodeCrypto.randomBytes(8).toString('hex'),
          code_challenge: nodeCrypto.createHash('sha256')
            .update(nodeCrypto.randomBytes(32).toString('base64url'))
            .digest('base64url'),
          code_challenge_method: 'S256' }).toString());
      const screen = await b.go('GET', String(start.headers.location || ''));
      return { b: b, screen: screen };
    };
    // The password screen's first step: passwordless (`webauthn_only`) or a
    // password, then the passkey page it draws.
    const firstStep = async function (name, passwordless) {
      const s = await screenFor();
      const form = hiddenFields(s.screen.text);
      form.username = name;
      form.password = passwordless ? '' : PASSWORD;
      if (passwordless) {
        form.webauthn_only = '1';
      }
      form.action = 'login';
      const step = await s.b.go('POST', '/authn/login', { form: form });
      return { s: s, step: step,
               mfaId: (step.text.match(/name="mfa_id" value="([^"]+)"/) ||
                       [])[1] };
    };
    const register = async function (name, key) {
      const f = await firstStep(name, true);
      return f.s.b.go('POST', '/authn/webauthn', { form: {
        mfa_id: f.mfaId, mode: 'create',
        credential: JSON.stringify(key.register(
          dataAttribute(f.step.text, 'challenge'),
          dataAttribute(f.step.text, 'userid'))) } });
    };
    const signIn = async function (name, key, passwordless) {
      const f = await firstStep(name, passwordless);
      return f.s.b.go('POST', '/authn/webauthn', { form: {
        mfa_id: f.mfaId, mode: 'get',
        credential: JSON.stringify(key.assert(
          dataAttribute(f.step.text, 'challenge', 'wa-data'))) } });
    };
    const usernameless = async function (key) {
      const s = await screenFor();
      const form = hiddenFields(s.screen.text);
      form.action = 'passkey';
      form.passkey_credential = JSON.stringify(key.assert(
        dataAttribute(s.screen.text, 'challenge', 'wa-passkey')));
      return s.b.go('POST', '/authn/login', { form: form });
    };
    const redirected = function (r) {
      return r.status === 302 || r.status === 303;
    };

    const on = function (fields) {
      return policy(Object.assign({ enforcePinLength: true, minPinLength: 6,
                                    pinLengthOnlyIfSupported: false },
                                  fields || {}));
    };
    const rowOf = function (name) {
      return credentials.keysOf(name)[0] || {};
    };

    // 1. Off by default.
    note(webauthnPolicy.creationOptions(RPID).minPinLength === undefined,
         '1a. OFF BY DEFAULT: the registration options ask for no ' +
         'minPinLength', JSON.stringify(webauthnPolicy.creationOptions(RPID)));
    const alice = makeAuthenticator(RPID, ORIGIN, 4);
    let r = await register('pkp-alice', alice);
    note(redirected(r) && rowOf('pkp-alice').minPinLength === 4,
         '1b. and a key reporting a minimum PIN of 4 registers, the row ' +
         'recording 4', r.status + ' ' + JSON.stringify(rowOf('pkp-alice'))
           .slice(0, 300));

    // 2. On, minimum 6.
    const saved = on();
    note(saved.ok && webauthnPolicy.creationOptions(RPID).minPinLength ===
         true, '2. ON (minimum 6): the registration options ask for ' +
         'minPinLength', JSON.stringify(saved.errors || []));
    const bob = makeAuthenticator(RPID, ORIGIN, 8);
    r = await register('pkp-bob', bob);
    note(redirected(r) && rowOf('pkp-bob').minPinLength === 8,
         '2a. a key reporting 8 registers, and its row records 8',
         r.status + ' ' + r.text.slice(0, 200));
    r = await register('pkp-carol', makeAuthenticator(RPID, ORIGIN, 4));
    note(r.status === 200 && !redirected(r) &&
         /requires at least 6/.test(r.text) &&
         codeRecorded('STS-AUTHN-0314') &&
         credentials.keysOf('pkp-carol').length === 0,
         '2b. one reporting 4 is refused (STS-AUTHN-0314): the page says ' +
         'why and nothing is written', r.status + ' ' + r.text.slice(0, 300));
    r = await register('pkp-dave', makeAuthenticator(RPID, ORIGIN, null));
    note(r.status === 200 && !redirected(r) &&
         /did not report its minimum PIN length/.test(r.text) &&
         credentials.keysOf('pkp-dave').length === 0,
         '2c. and one that reports nothing is refused too',
         r.status + ' ' + r.text.slice(0, 300));

    // 3. Only if supported.
    on({ pinLengthOnlyIfSupported: true });
    const erin = makeAuthenticator(RPID, ORIGIN, null);
    r = await register('pkp-erin', erin);
    note(redirected(r) && rowOf('pkp-erin').minPinLength === null,
         '3. pinLengthOnlyIfSupported on: a key that reports nothing ' +
         'registers, its row recording none', r.status + ' ' +
         r.text.slice(0, 200));

    // 4. At sign-in.
    on({ minPinLength: 10, pinLengthOnlyIfSupported: false });
    r = await signIn('pkp-bob', bob, true);
    note(r.status === 200 && !redirected(r) &&
         /requires at least 10/.test(r.text) &&
         sessionRefused('pkp-bob', 'STS-AUTHN-0315'),
         '4a. AT SIGN-IN, the minimum raised to 10: the key that reported 8 ' +
         'does not sign in (STS-AUTHN-0315, a session.refuse row), the page ' +
         'saying why', r.status + ' ' + r.text.slice(0, 300));
    r = await signIn('pkp-erin', erin, true);
    note(r.status === 200 && !redirected(r) &&
         sessionRefused('pkp-erin', 'STS-AUTHN-0315'),
         '4b. nor does the key that reported nothing, while ' +
         'pinLengthOnlyIfSupported is off', r.status + ' ' +
         r.text.slice(0, 300));
    on({ minPinLength: 10, pinLengthOnlyIfSupported: true });
    r = await signIn('pkp-erin', erin, true);
    note(redirected(r), '4c. and it does while it is on', r.status + ' ' +
         r.text.slice(0, 200));
    on({ minPinLength: 8 });
    r = await signIn('pkp-bob', bob, true);
    note(redirected(r), '4d. a key that reported exactly the minimum signs ' +
         'in', r.status + ' ' + r.text.slice(0, 200));

    // 5. Off.
    passkeyPolicy.reset('default');
    r = await signIn('pkp-alice', alice, true);
    note(redirected(r) && webauthnPolicy.creationOptions(RPID)
      .minPinLength === undefined,
         '5. off again, every key signs in and nothing is asked',
         r.status + ' ' + r.text.slice(0, 200));
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
  const out = path.join(os.tmpdir(), 'sts-pkp-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = Object.assign({}, process.env, { PKP_OUT: out, PKP_ROOT: ROOT,
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
  name: 'passkey_pin_length',
  describe: 'a minimum security-key PIN length (CTAP 2.1 minPinLength) ' +
            'asked for, recorded and enforced at registration and at ' +
            'sign-in (#529)',
  run: run
};
