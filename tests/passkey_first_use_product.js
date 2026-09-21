'use strict';
//
// File: tests/passkey_first_use_product.js
//
// ===========================================================================
// PRODUCT MODE ENROLS NO SECURITY KEY AT THE SIGN-IN SCREEN (2026-09-21).
//
// The passwordless box on `/authn/login` reads no password, and a person who
// held no `primary` key was answered with the ENROL ceremony — "enrol on first
// use". In development that is the point: the first person to claim a name
// gets it, and the screen says so. In product the only other check was that
// the name EXISTS (`knownUser()`), so anybody who knew a username could
// register their own authenticator as that person's primary credential and be
// signed in as them — and keep the key. `common/mode.js`'s
// `enrolsKeysOnFirstUse()` is the switch now; `authn/authn.ts` refuses at the
// sign-in handler, before a ceremony is drawn, and again at the registration.
//
// Asserted, in a CHILD PROCESS serving the stack on a loopback port, with a
// REAL ceremony from a software authenticator (`wsfed_wauth_step_up.js`'s,
// which is `webauthn_session.js`'s):
//   1. DEVELOPMENT, the control: a passwordless sign-in for a keyless person
//      is the enrol ceremony, and a real registration signs them in — so the
//      harness can drive the path the refusals below close;
//   2. PRODUCT: the same sign-in for a person who EXISTS, holds a password
//      and no key is refused with STS-AUTHN-0206 — no ceremony drawn, no key
//      written, no session;
//   3. PRODUCT: a name that does not exist gets the SAME sentence, so the
//      refusal is not a way to learn which usernames do;
//   4. PRODUCT: a person who HOLDS a primary key still gets the ceremony,
//      as an assertion — the refusal is about enrolling, not signing in;
//   5. PRODUCT: a step minted in development and completed after the switch
//      is refused at the registration too, and the key is not written;
//   6. PRODUCT: the sign-in screen no longer says no password is checked.
// ===========================================================================

delete process.env.CONFIG_FILE;

const path = require('path');
const os = require('os');
const fs = require('fs');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'passkey_first_use_product',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// Runs in the child. Stringified, so it may use nothing from this file's
// scope, and — code in a `node -e` child — is exempt from the Entering/Leaving
// rule (root CLAUDE.md, *Code style*).
function childMain() {
  const ROOT = process.env.PFU_ROOT;
  const OUT = process.env.PFU_OUT;
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

  // A SOFTWARE AUTHENTICATOR — `wsfed_wauth_step_up.js`'s, for its reason:
  // the server's half of the ceremony is under test, and producing the bytes
  // a real authenticator produces is the honest way to reach it.
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
  const register = function (rpId, origin, challenge) {
    const pair = nodeCrypto.generateKeyPairSync('ec',
                                                { namedCurve: 'prime256v1' });
    const jwk = pair.publicKey.export({ format: 'jwk' });
    const credentialId = nodeCrypto.randomBytes(32);
    const idLen = Buffer.alloc(2);
    idLen.writeUInt16BE(credentialId.length, 0);
    const data = Buffer.concat([sha256(Buffer.from(rpId, 'utf8')),
                                Buffer.from([0x45]), Buffer.alloc(4),
                                Buffer.alloc(16), idLen, credentialId,
                                coseKey(jwk)]);
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
               clientDataJSON: Buffer.from(JSON.stringify({
                 type: 'webauthn.create', challenge: challenge,
                 origin: origin, crossOrigin: false }), 'utf8')
                 .toString('base64url') } };
  };
  const dataAttribute = function (html, name) {
    const found = new RegExp(' data-' + name + '="([^"]*)"').exec(html);
    return found ? found[1].replace(/&amp;/g, '&') : '';
  };
  const hiddenFields = function (html) {
    const form = {};
    (html.match(/<input type="hidden"[^>]*>/g) || []).forEach(function (tag) {
      const name = /name="([^"]+)"/.exec(tag);
      const value = /value="([^"]*)"/.exec(tag);
      if (name) {
        form[name[1]] = value ? value[1].replace(/&amp;/g, '&') : '';
      }
    });
    return form;
  };

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const config = require(ROOT + '/common/config');
    const applications = require(ROOT + '/common/applications');
    const credentials = require(ROOT + '/common/credentials');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const audit = require(ROOT + '/common/audit');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const ORIGIN = 'http://127.0.0.1:' + port;
    const REDIRECT = 'https://rp.pfu.example/cb';
    const PASSWORD = 'correct-horse-battery-staple-pfu-7!';
    const REFUSAL = 'There is no security key registered for signing in to ' +
                    'this account';
    config.setOverride('oauth2.consentRequired', false);

    // Made in DEVELOPMENT: product mode creates nothing because it was named.
    applications.createApplication({ identifier: 'pfu-public',
      protocols: ['oauth2'],
      fields: { oauthClientId: 'pfu-public', oauthClientSecret: '',
                oauthRedirectUri: [REDIRECT],
                oauthTokenEndpointAuthMethod: 'none',
                oauthGrantType: ['authorization_code'] } });
    ['pfu-dev', 'pfu-victim', 'pfu-holder', 'pfu-late'].forEach(
      function (name) {
        ldap.createUser(name, { invent: false });
        credentials.setPassword(name, PASSWORD);
      });
    credentials.addKey('pfu-holder', { credentialId: 'pfu-holder-key',
      publicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' },
      label: 'holder key' }, 'primary');

    const codeRecorded = function (code) {
      return audit.list().some(function (row) {
        return row.errorCode === code;
      });
    };
    // The sign-in screen, reached the way a person reaches it, and the
    // passwordless box ticked.
    const passwordless = async function (username) {
      const b = browser(port);
      const verifier = nodeCrypto.randomBytes(32).toString('base64url');
      const start = await b.go('GET', '/oauth2/authorize?' +
        new URLSearchParams({ client_id: 'pfu-public', response_type: 'code',
          redirect_uri: REDIRECT, scope: 'openid', state: 's',
          nonce: 'n-' + nodeCrypto.randomBytes(8).toString('hex'),
          code_challenge: nodeCrypto.createHash('sha256').update(verifier)
            .digest('base64url'),
          code_challenge_method: 'S256' }).toString());
      const screen = await b.go('GET', String(start.headers.location || ''));
      const form = hiddenFields(screen.text);
      form.username = username;
      form.password = '';
      form.webauthn_only = '1';
      form.action = 'login';
      const posted = await b.go('POST', '/authn/login', { form: form });
      return { b: b, screen: screen, posted: posted };
    };
    const finish = function (b, step) {
      const mfaId = (step.text.match(/name="mfa_id" value="([^"]+)"/) ||
                     [])[1];
      const credential = register(dataAttribute(step.text, 'rpid'), ORIGIN,
                                  dataAttribute(step.text, 'challenge'));
      return b.go('POST', '/authn/webauthn', { form: {
        mfa_id: mfaId, mode: 'create',
        credential: JSON.stringify(credential) } });
    };
    const primaryKeys = function (name) {
      return credentials.keysOf(name).filter(function (k) {
        return k.role === 'primary';
      }).length;
    };

    // 1. Development, the control.
    let s = await passwordless('pfu-dev');
    note(s.posted.status === 200 &&
         dataAttribute(s.posted.text, 'mode') === 'create',
         '1a. DEVELOPMENT: a passwordless sign-in for a keyless person is the ' +
         'ENROL ceremony', s.posted.status + ' ' + s.posted.text.slice(0, 160));
    let done = await finish(s.b, s.posted);
    note((done.status === 302 || done.status === 303) &&
         primaryKeys('pfu-dev') === 1,
         '1b. and a real registration is accepted and signs them in — the ' +
         'harness reaches the path the refusals below close',
         done.status + ' keys=' + primaryKeys('pfu-dev') + ' ' +
         done.text.slice(0, 200));

    // The step for 5, minted while still in development.
    const late = await passwordless('pfu-late');

    config.setOverride('global.mode', 'product');
    try {
      // 2. The attack.
      s = await passwordless('pfu-victim');
      note(s.posted.status === 200 && s.posted.text.indexOf(REFUSAL) >= 0 &&
           !dataAttribute(s.posted.text, 'mode') &&
           !/name="mfa_id"/.test(s.posted.text),
           '2a. PRODUCT: a passwordless sign-in for somebody who exists and ' +
           'holds no key is REFUSED before any ceremony — it was the enrol ' +
           'ceremony, which gave the account to whoever asked',
           s.posted.status + ' ' + s.posted.text.slice(0, 200));
      note(primaryKeys('pfu-victim') === 0,
           '2b. and no key is on the victim\'s entry');
      note(codeRecorded('STS-AUTHN-0206'), '2c. with STS-AUTHN-0206');

      // 3. No enumeration.
      s = await passwordless('pfu-nobody-' + Date.now().toString(36));
      note(s.posted.status === 200 && s.posted.text.indexOf(REFUSAL) >= 0,
           '3. PRODUCT: a name that does not exist gets the SAME sentence',
           s.posted.status + ' ' + s.posted.text.slice(0, 200));

      // 4. A key holder is not refused.
      s = await passwordless('pfu-holder');
      note(s.posted.status === 200 &&
           dataAttribute(s.posted.text, 'mode') === 'get' &&
           s.posted.text.indexOf(REFUSAL) < 0,
           '4. PRODUCT: a person who HOLDS a primary key still gets the ' +
           'ceremony, as an assertion — the refusal is about enrolling',
           s.posted.status + ' ' + s.posted.text.slice(0, 200));

      // 5. A development step completed in product.
      note(dataAttribute(late.posted.text, 'mode') === 'create',
           '5a. (precondition: the step minted in development was an ' +
           'enrolment)', late.posted.text.slice(0, 160));
      done = await finish(late.b, late.posted);
      note(!(done.status === 302 || done.status === 303) &&
           /never at the sign-in screen/.test(done.text) &&
           primaryKeys('pfu-late') === 0,
           '5b. PRODUCT: that step is refused at the REGISTRATION too, and ' +
           'no key is written', done.status + ' keys=' +
           primaryKeys('pfu-late') + ' ' + done.text.slice(0, 200));

      // 6. The screen says what it checks.
      note(!/No password is checked/.test(s.screen.text) &&
           !/first person to claim a name/.test(s.screen.text),
           '6. PRODUCT: the sign-in screen no longer says no password is ' +
           'checked, or that a key is enrolled on first use');
    } finally {
      config.clearOverride('global.mode');
    }
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
  const out = path.join(os.tmpdir(), 'sts-pfu-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = Object.assign({}, process.env, { PFU_OUT: out, PFU_ROOT: ROOT,
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
  name: 'passkey_first_use_product',
  describe: 'product mode enrols no security key at the sign-in screen',
  run: run
};
