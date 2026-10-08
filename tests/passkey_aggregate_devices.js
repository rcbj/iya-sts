// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/passkey_aggregate_devices.js
//
// ===========================================================================
// A PERSON'S PASSKEYS AS ONE SIGN-IN CHOICE, OR ONE PER DEVICE (#534): the
// passkey policy's `aggregateDevices`, read off the passkey step's page in a
// CHILD PROCESS serving the stack on a loopback port, for a person with one,
// two and five keys:
//
//   1. ON (the default, what the sign-in did before): one ceremony whose
//      `allowCredentials` lists every key, whatever the count.
//   2. OFF: one key is still one ceremony; two and five are a choice, a
//      link per key labelled with its name.
//   3. A chosen key draws the ceremony naming only it, with a way back to
//      the choice; a key that is not the person's is not a choice.
//   4. The second-factor step follows the same rule.
// ===========================================================================

delete process.env.CONFIG_FILE;

const path = require('path');
const os = require('os');
const fs = require('fs');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'passkey_aggregate_devices',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// Runs in the child. Stringified, so it may use nothing from this file's
// scope, and — code in a `node -e` child — is exempt from the Entering/Leaving
// rule (root CLAUDE.md, *Code style*).
function childMain() {
  const ROOT = process.env.PKG_ROOT;
  const OUT = process.env.PKG_OUT;
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

  // A SOFTWARE AUTHENTICATOR — `passkey_discoverable.js`'s, with the
  // authenticator data's backup flags settable (WebAuthn Level 3 section
  // 6.1), which is the whole of what this file varies.
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
  const makeAuthenticator = function (rpId, origin, backup) {
    const backupBits = backup === 'synced' ? 0x18
      : (backup === 'eligible' ? 0x08 : 0);
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
        const data = authData({ flags: 0x45 | backupBits,
                                signCount: signCount, attested: true });
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
    const REDIRECT = 'https://rp.pkg.example/cb';
    const PASSWORD = 'correct-horse-battery-staple-pkg-7!';
    config.setOverride('oauth2.consentRequired', false);

    applications.createApplication({ identifier: 'pkg-public',
      protocols: ['oauth2'],
      fields: { oauthClientId: 'pkg-public', oauthClientSecret: '',
                oauthRedirectUri: [REDIRECT],
                oauthTokenEndpointAuthMethod: 'none',
                oauthGrantType: ['authorization_code'] } });
    ['pkg-one', 'pkg-two', 'pkg-five', 'pkg-dave', 'pkg-erin'].forEach(
      function (name) {
        ldap.createUser(name, { invent: false });
        credentials.setPassword(name, PASSWORD);
      });

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
        new URLSearchParams({ client_id: 'pkg-public', response_type: 'code',
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
               // From the form, or — on the per-passkey choice, which draws
               // no form (#534) — from its links.
               mfaId: decodeURIComponent(
                 (step.text.match(/name="mfa_id" value="([^"]+)"/) ||
                  step.text.match(/[?]mfa=([^&"]+)/) || [])[1] || '') };
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

    const keysFor = function (name, count, role) {
      const ids = [];
      for (let i = 0; i < count; i += 1) {
        const id = name + '-key-' + i;
        credentials.addKey(name, { credentialId: id, label: 'Key ' + i,
          publicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'AA', y: 'AA' } },
          role);
        ids.push(id);
      }
      return ids;
    };
    const ones = keysFor('pkg-one', 1, 'primary');
    const twos = keysFor('pkg-two', 2, 'primary');
    const fives = keysFor('pkg-five', 5, 'primary');
    const daves = keysFor('pkg-dave', 2, 'mfa');
    const allowOf = function (html) {
      const v = dataAttribute(html, 'allow', 'wa-data');
      return v ? v.split(',') : [];
    };
    const choicesOf = function (html) {
      const list = /<ul id="wa-choices">([\s\S]*?)<\/ul>/.exec(html);
      return list ? (list[1].match(/<li>/g) || []).length : 0;
    };
    const same = function (a, b) {
      return JSON.stringify(a.slice().sort()) ===
             JSON.stringify(b.slice().sort());
    };

    // 1. On.
    let f1 = await firstStep('pkg-one', true);
    let f2 = await firstStep('pkg-two', true);
    let f5 = await firstStep('pkg-five', true);
    note(same(allowOf(f1.step.text), ones) &&
         same(allowOf(f2.step.text), twos) &&
         same(allowOf(f5.step.text), fives) &&
         !choicesOf(f2.step.text) && !choicesOf(f5.step.text),
         '1. ON (the default): one ceremony listing every key, for one, two ' +
         'and five', JSON.stringify([allowOf(f2.step.text).length,
                                     allowOf(f5.step.text).length]));

    // 2. Off.
    policy({ aggregateDevices: false });
    f1 = await firstStep('pkg-one', true);
    f2 = await firstStep('pkg-two', true);
    f5 = await firstStep('pkg-five', true);
    note(same(allowOf(f1.step.text), ones) && !choicesOf(f1.step.text),
         '2a. OFF, one key is still one ceremony', f1.step.text.slice(0, 200));
    note(choicesOf(f2.step.text) === 2 && choicesOf(f5.step.text) === 5 &&
         !/id="wa-data"/.test(f5.step.text) &&
         /Key 3/.test(f5.step.text),
         '2b. two and five are a choice: a link per key, by its name, and ' +
         'no ceremony until one is chosen',
         choicesOf(f2.step.text) + ' ' + choicesOf(f5.step.text));

    // 3. Chosen.
    const pick = await f5.s.b.go('GET', '/authn/webauthn?mfa=' +
      encodeURIComponent(f5.mfaId) + '&key=' + encodeURIComponent(fives[3]));
    note(pick.status === 200 && same(allowOf(pick.text), [fives[3]]) &&
         /choose another/.test(pick.text) && /Using <strong>Key 3/.test(
           pick.text),
         '3a. a chosen key draws the ceremony naming only it, with a way ' +
         'back', pick.status + ' ' + JSON.stringify(allowOf(pick.text)) +
           ' ' + pick.text.slice(0, 300));
    const stray = await f5.s.b.go('GET', '/authn/webauthn?mfa=' +
      encodeURIComponent(f5.mfaId) + '&key=' + encodeURIComponent(twos[0]));
    note(stray.status === 200 && choicesOf(stray.text) === 5 &&
         !/id="wa-data"/.test(stray.text),
         '3b. a key that is not this person\'s is not a choice: the list ' +
         'again', stray.status);

    // 4. The second-factor step.
    const fd = await firstStep('pkg-dave', false);
    const dpick = await fd.s.b.go('GET', '/authn/webauthn?mfa=' +
      encodeURIComponent(fd.mfaId) + '&key=' + encodeURIComponent(daves[1]));
    note(choicesOf(fd.step.text) === 2 &&
         same(allowOf(dpick.text), [daves[1]]),
         '4. the second-factor step follows the same rule',
         choicesOf(fd.step.text) + ' ' + JSON.stringify(allowOf(dpick.text)));
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
  const out = path.join(os.tmpdir(), 'sts-pkg-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = Object.assign({}, process.env, { PKG_OUT: out, PKG_ROOT: ROOT,
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
  name: 'passkey_aggregate_devices',
  describe: 'a person\'s passkeys as one sign-in choice or one per device ' +
            '(#534)',
  run: run
};
