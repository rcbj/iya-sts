// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/passkey_named_policies.js
//
// ===========================================================================
// NAMED PASSKEY POLICIES, SELECTED BY APPLICATION OR GROUP (#535).
//
//   A. In process: a named profile saved with its selectors, and refused
//      with none, with a bad name or a bad precedence; selection by group,
//      by application and by precedence, with `default` the fallback; the
//      ambient selection read by every answer; a realm's named profiles not
//      inherited; a removed profile selecting the default.
//   B. Over HTTP, in a CHILD PROCESS serving the stack on a loopback port
//      with real ceremonies (`passkey_backup_eligible.js`'s harness): two
//      policies in one realm applied to two people — a group's profile that
//      refuses synced passkeys refusing its member's, the default taking the
//      other person's — and an application's profile deciding what the
//      sign-in screen offers.
// ===========================================================================

delete process.env.CONFIG_FILE;

const path = require('path');
const os = require('os');
const fs = require('fs');
const childProcess = require('child_process');

const realms = require('../common/realms');
const errorCodes = require('../common/error_codes');
const passkeyPolicy = require('../common/passkey_policy');
const ldap = require('../ldap/ldap_server');

const log = require('bunyan').createLogger({ name: 'passkey_named_policies',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function named(name, fields, selectors) {
  log.debug('Entering named().');
  log.debug('Leaving named().');
  return passkeyPolicy.save(name, Object.assign({}, passkeyPolicy.DEFAULTS,
                                                fields || {}, selectors || {}));
}

function inProcess(t) {
  log.debug('Entering inProcess().');
  const tag = require('crypto').randomBytes(3).toString('hex');
  const admin = 'pnp-admin-' + tag;
  const user = 'pnp-user-' + tag;
  const group = 'pnp-admins-' + tag;
  ldap.createUser(admin, { invent: false });
  ldap.createUser(user, { invent: false });
  ldap.createGroup(group);
  ldap.addGroupMember(group, admin);
  try {
    const saved = named('admins', { backupEligibility: 'disallow' },
                        { selectGroups: group, precedence: 20 });
    const app = named('strict-app', { enforcePinLength: true },
                      { selectApplications: 'pnp-app', precedence: 5 });
    const none = named('nobody', {}, {});
    const badName = named('Admins!', {}, { selectGroups: group });
    const badRank = named('ranked', {}, { selectGroups: group,
                                          precedence: 0 });
    t.check(saved.ok && saved.profile.name === 'admins' &&
            saved.profile.precedence === 20 &&
            JSON.stringify(saved.profile.selectGroups) ===
              JSON.stringify([group]) && app.ok,
            'A1. a named profile is saved with its selectors',
            JSON.stringify([saved.errors, app.errors]));
    t.check(!none.ok && errorCodes.codeOf(none) === 'STS-AUTHN-0309' &&
            !badName.ok && errorCodes.codeOf(badName) === 'STS-AUTHN-0308' &&
            !badRank.ok,
            'A1b. one with no selector, a bad name, or a precedence out of ' +
            '1..1000 is refused', JSON.stringify([none.errors,
                                                  badName.errors,
                                                  badRank.errors]));
    t.check(passkeyPolicy.selectionFor(admin, '') === 'admins' &&
            passkeyPolicy.selectionFor(user, '') === 'default' &&
            passkeyPolicy.selectionFor(user, 'pnp-app') === 'strict-app' &&
            passkeyPolicy.selectionFor(admin, 'pnp-app') === 'strict-app' &&
            passkeyPolicy.selectionFor(admin, 'other-app') === 'admins',
            'A2. by group, by application, the lower precedence where both ' +
            'match, and default where none does');
    named('strict-app', { enforcePinLength: true },
          { selectApplications: 'pnp-app', precedence: 50 });
    t.check(passkeyPolicy.selectionFor(admin, 'pnp-app') === 'admins',
            'A2b. raising the application profile\'s number lets the group ' +
            'profile win');
    const ambient = passkeyPolicy.withSelection(admin, '', function () {
      log.debug('Entering inProcess() withSelection.');
      log.debug('Leaving inProcess() withSelection.');
      return [passkeyPolicy.read().name,
              !!passkeyPolicy.backupEligibleRefusal(true, 'registration')];
    });
    const outside = passkeyPolicy.withSelection(user, '', function () {
      log.debug('Entering inProcess() withSelection (user).');
      log.debug('Leaving inProcess() withSelection (user).');
      return [passkeyPolicy.read().name,
              !!passkeyPolicy.backupEligibleRefusal(true, 'registration')];
    });
    t.check(ambient[0] === 'admins' && ambient[1] === true &&
            outside[0] === 'default' && outside[1] === false,
            'A3. every answer reads the selected profile',
            JSON.stringify([ambient, outside]));
    const id = 'pnp-' + tag;
    const made = realms.create({ id: id, name: id,
                                description: 'Created by ' + __filename });
    try {
      const there = realms.run(made.realm, function () {
        log.debug('Entering inProcess() in the realm.');
        log.debug('Leaving inProcess() in the realm.');
        return [passkeyPolicy.selectionFor(admin, 'pnp-app'),
                passkeyPolicy.list().map(function (one) {
                  return one.name;
                })];
      });
      t.check(there[0] === 'default' &&
              JSON.stringify(there[1]) === '["default"]',
              'A4. another realm does not inherit the named profiles',
              JSON.stringify(there));
    } finally {
      realms.remove(id);
    }
    const listed = passkeyPolicy.list().map(function (one) {
      return one.name;
    });
    t.check(JSON.stringify(listed) === '["default","admins","strict-app"]',
            'A5. the list: default, then the named by precedence',
            JSON.stringify(listed));
    passkeyPolicy.reset('admins');
    t.check(passkeyPolicy.selectionFor(admin, '') === 'default' &&
            passkeyPolicy.read('admins').name === 'default',
            'A6. a removed profile selects nobody, and reads as the default');
  } finally {
    passkeyPolicy.reset('admins');
    passkeyPolicy.reset('strict-app');
  }
  log.debug('Leaving inProcess().');
}

// Runs in the child. Stringified, so it may use nothing from this file's
// scope, and — code in a `node -e` child — is exempt from the Entering/Leaving
// rule (root CLAUDE.md, *Code style*).
function childMain() {
  const ROOT = process.env.PKN_ROOT;
  const OUT = process.env.PKN_OUT;
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
    const REDIRECT = 'https://rp.pkn.example/cb';
    const PASSWORD = 'correct-horse-battery-staple-pkn-7!';
    config.setOverride('oauth2.consentRequired', false);

    applications.createApplication({ identifier: 'pkn-public',
      protocols: ['oauth2'],
      fields: { oauthClientId: 'pkn-public', oauthClientSecret: '',
                oauthRedirectUri: [REDIRECT],
                oauthTokenEndpointAuthMethod: 'none',
                oauthGrantType: ['authorization_code'] } });
    ['pkn-admin', 'pkn-user', 'pkn-carol', 'pkn-dave', 'pkn-erin'].forEach(
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
    const policy = function (fields, name, selectors) {
      return passkeyPolicy.save(name || 'default', Object.assign({},
        passkeyPolicy.DEFAULTS, fields, selectors || {}));
    };
    const screenFor = async function () {
      const b = browser(port);
      const start = await b.go('GET', '/oauth2/authorize?' +
        new URLSearchParams({ client_id: 'pkn-public', response_type: 'code',
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

    ldap.createGroup('pkn-admins');
    ldap.addGroupMember('pkn-admins', 'pkn-admin');
    const ok = policy({ backupEligibility: 'disallow' }, 'admins',
                      { selectGroups: 'pkn-admins', precedence: 10 });
    note(ok.ok, 'B1. the group profile is saved', JSON.stringify(ok.errors));
    let r = await register('pkn-admin', makeAuthenticator(RPID, ORIGIN,
                                                          'synced'));
    note(r.status === 200 && !redirected(r) &&
         /device-bound passkeys/.test(r.text) &&
         credentials.keysOf('pkn-admin').length === 0,
         'B2. the group\'s member: a synced passkey is refused by the ' +
         'group\'s profile', r.status + ' ' + r.text.slice(0, 200));
    r = await register('pkn-user', makeAuthenticator(RPID, ORIGIN, 'synced'));
    note(redirected(r) && credentials.keysOf('pkn-user').length === 1,
         'B3. somebody else in the same realm: the default takes it',
         r.status + ' ' + r.text.slice(0, 200));
    policy({ allowUsernameless: true });
    policy({ allowUsernameless: false }, 'strict-app',
           { selectApplications: 'pkn-public', precedence: 5 });
    const s = await screenFor();
    note(s.screen.status === 200 && !/id="wa-passkey"/.test(s.screen.text),
         'B4. the application\'s profile decides what its sign-in screen ' +
         'offers: no usernameless passkey, where the default allows one',
         s.screen.status);
    passkeyPolicy.reset('strict-app');
    const s2 = await screenFor();
    note(/id="wa-passkey"/.test(s2.screen.text),
         'B4b. and with it removed, the default\'s is offered again');
    passkeyPolicy.reset('admins');
    passkeyPolicy.reset('default');
    server.close();
  })().catch(function (e) {
    note(false, 'the child ran to the end', e && e.stack);
  }).then(function () {
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function overHttp(t) {
  log.debug("Entering overHttp().");
  const out = path.join(os.tmpdir(), 'sts-pkn-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = Object.assign({}, process.env, { PKN_OUT: out, PKN_ROOT: ROOT,
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
  log.debug("Leaving overHttp().");
}

module.exports = {
  name: 'passkey_named_policies',
  describe: 'named passkey policies selected by application, by group and ' +
            'by precedence, with the default as the fallback (#535)',
  run: function (t) {
    log.debug('Entering run().');
    inProcess(t);
    overHttp(t);
    log.debug('Leaving run().');
  }
};
