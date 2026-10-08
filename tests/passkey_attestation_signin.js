// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/passkey_attestation_signin.js
//
// ===========================================================================
// THE ATTESTATION RULES AT SIGN-IN (#530): the passkey policy's
// `enforceAttestationAtSignIn`, which holds every passkey sign-in to the
// `webauthn.attestation*` rules in force and to the FIDO Metadata Service as
// it is now.
//
//   A. THE VERDICT, `webauthn_attestation.ts`'s `signInVerdict()`, over key
//      rows, with the metadata service stubbed:
//        1. nothing demanding trust: every key passes;
//        2. a key registered under a wide AAGUID list passes it, and is
//           refused once the list is narrowed (STS-AUTHN-0316);
//        3. a key with no trusted statement (`none`, or none recorded at
//           all) fails a rule that demands trust, a list included;
//        4. a model the metadata service now reports compromised is
//           refused, whatever else is set;
//        5. a certification level the model no longer meets is refused,
//           and one it meets passes;
//        6. a lookup that throws refuses (STS-AUTHN-0317).
//   B. THE DOORS, in a CHILD PROCESS serving the stack on a loopback port
//      with REAL ceremonies (`passkey_backup_eligible.js`'s harness): a key
//      registered with `none` attestation signs in until a rule demands
//      trust and the passkey policy enforces it at sign-in; then it is
//      refused at the typed passkey step and with no username, the page
//      saying why, with a `session.refuse` row, the key's row marked once and
//      one CAEP credential-change; the switch off, it signs in again.
// ===========================================================================

delete process.env.CONFIG_FILE;

const path = require('path');
const os = require('os');
const fs = require('fs');
const childProcess = require('child_process');

const config = require('../common/config');
const errorCodes = require('../common/error_codes');
const attestation = require('../authn/webauthn_attestation');

const log = require('bunyan').createLogger({ name: 'passkey_attestation_signin',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const AAGUID_A = 'ee882879-721c-4913-9775-3dfcce97072a';
const AAGUID_B = 'cb69481e-8ff7-4039-93ec-0a2729a154a8';

// A verifier over a stubbed metadata service: `models` by AAGUID, or a throw.
function verifierWith(models, throws) {
  log.debug('Entering verifierWith().');
  const deps = Object.assign({}, attestation.WebauthnAttestation.defaultDeps(),
    { metadata: function () {
      return { lookupAuthenticatorBy: async function (kind, value) {
        if (throws) {
          throw new Error('the metadata store is down, on purpose');
        }
        return kind === 'aaguid' && models[value]
          ? { model: models[value], version: '1' } : null;
      } };
    } });
  log.debug('Leaving verifierWith().');
  return new attestation.WebauthnAttestation(deps);
}

function key(aaguid, trusted, type) {
  log.debug('Entering key().');
  log.debug('Leaving key().');
  return { credentialId: 'cred-' + aaguid.slice(0, 4), aaguid: aaguid,
           attestation: trusted === undefined ? undefined : {
             aaguid: aaguid, trusted: trusted, verified: true,
             type: type || (trusted ? 'basic' : 'none') } };
}

async function withSettings(settings, fn) {
  log.debug('Entering withSettings().');
  Object.keys(settings).forEach(function (name) {
    config.setOverride(name, settings[name]);
  });
  try {
    log.debug('Leaving withSettings().');
    return await fn();
  } finally {
    Object.keys(settings).forEach(function (name) {
      config.clearOverride(name);
    });
  }
}

async function theVerdict(t) {
  log.debug('Entering theVerdict().');
  const v = verifierWith({});
  const plain = await v.signInVerdict(key(AAGUID_A, false));
  t.check(plain.ok === true, 'A1. nothing demands trust: a key with no ' +
          'trusted statement passes', JSON.stringify(plain));
  await withSettings({ 'webauthn.attestationAllowedAaguids':
                         AAGUID_A + ',' + AAGUID_B }, async function () {
    const wide = await v.signInVerdict(key(AAGUID_A, true));
    t.check(wide.ok === true, 'A2. a trusted key passes the wide list it ' +
            'was registered under', JSON.stringify(wide));
  });
  await withSettings({ 'webauthn.attestationAllowedAaguids': AAGUID_B },
                     async function () {
    const narrow = await v.signInVerdict(key(AAGUID_A, true));
    t.check(!narrow.ok && errorCodes.codeOf(narrow) === 'STS-AUTHN-0316' &&
            /no longer one this realm allows/.test(narrow.why),
            'A2b. and is refused once the list is narrowed (STS-AUTHN-0316)',
            JSON.stringify(narrow));
    const none = await v.signInVerdict(key(AAGUID_B, false, 'none'));
    const unrecorded = await v.signInVerdict(key(AAGUID_B));
    t.check(!none.ok && !unrecorded.ok &&
            /trusted one/.test(none.why) && /trusted one/.test(unrecorded.why),
            'A3. a key with no trusted statement fails a rule that demands ' +
            'trust — even naming an AAGUID on the list — and so does one ' +
            'with no attestation recorded at all',
            JSON.stringify([none, unrecorded]));
  });
  const bad = verifierWith({ [AAGUID_A]: { description: 'Bad Key',
    compromised: true, statusReports: [{ status: 'ATTESTATION_KEY_COMPROMISE'
    }] } });
  await withSettings({ 'webauthn.attestationPolicy': 'verify-if-present' },
                     async function () {
    const compromised = await bad.signInVerdict(key(AAGUID_A, true));
    t.check(!compromised.ok &&
            /ATTESTATION_KEY_COMPROMISE/.test(compromised.why),
            'A4. a model the metadata service now reports compromised is ' +
            'refused', JSON.stringify(compromised));
  });
  const levelled = verifierWith({ [AAGUID_A]: {
    description: 'L1 Key', certificationLevel: 'FIDO_CERTIFIED_L1' } });
  await withSettings({ 'webauthn.attestationMinCertificationLevel': 'L2' },
                     async function () {
    const low = await levelled.signInVerdict(key(AAGUID_A, true));
    t.check(!low.ok && /certified at L1/.test(low.why),
            'A5. a model below the certification level asked for is refused',
            JSON.stringify(low));
  });
  await withSettings({ 'webauthn.attestationMinCertificationLevel': 'L1' },
                     async function () {
    const met = await levelled.signInVerdict(key(AAGUID_A, true));
    t.check(met.ok === true, 'A5b. and one that meets it passes',
            JSON.stringify(met));
  });
  await withSettings({ 'webauthn.attestationPolicy': 'verify-if-present' },
                     async function () {
    const thrown = await verifierWith({}, true).signInVerdict(
      key(AAGUID_A, true));
    t.check(!thrown.ok && errorCodes.codeOf(thrown) === 'STS-AUTHN-0317',
            'A6. a lookup that throws refuses (STS-AUTHN-0317)',
            JSON.stringify(thrown));
  });
  log.debug('Leaving theVerdict().');
}

// Runs in the child. Stringified, so it may use nothing from this file's
// scope, and — code in a `node -e` child — is exempt from the Entering/Leaving
// rule (root CLAUDE.md, *Code style*).
function childMain() {
  const ROOT = process.env.PKA_ROOT;
  const OUT = process.env.PKA_OUT;
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
    const REDIRECT = 'https://rp.pka.example/cb';
    const PASSWORD = 'correct-horse-battery-staple-pka-7!';
    config.setOverride('oauth2.consentRequired', false);

    applications.createApplication({ identifier: 'pka-public',
      protocols: ['oauth2'],
      fields: { oauthClientId: 'pka-public', oauthClientSecret: '',
                oauthRedirectUri: [REDIRECT],
                oauthTokenEndpointAuthMethod: 'none',
                oauthGrantType: ['authorization_code'] } });
    ['pka-alice', 'pka-bob', 'pka-carol', 'pka-dave', 'pka-erin'].forEach(
      function (name) {
        ldap.createUser(name, { invent: false });
        credentials.setPassword(name, PASSWORD);
      });

    // EVERY CAEP credential-change this child sends, counted (#530): the
    // facade is the object `authn.ts` holds as its dependency.
    const accountSignals = require(ROOT + '/ssf/account_signals');
    const changes = [];
    const realChanged = accountSignals.credentialChanged;
    accountSignals.credentialChanged = function (said) {
      changes.push(said);
      return realChanged.apply(this, arguments);
    };
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
        new URLSearchParams({ client_id: 'pka-public', response_type: 'code',
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

    const AAGUID = 'ee882879-721c-4913-9775-3dfcce97072a';
    const alice = makeAuthenticator(RPID, ORIGIN, 'device-bound');
    let r = await register('pka-alice', alice);
    const row = function () {
      return credentials.keysOf('pka-alice')[0] || {};
    };
    note(redirected(r) && row().attestation &&
         row().attestation.trusted === false,
         'B1. a key registered with `none` attestation (nothing trusted)',
         r.status + ' ' + JSON.stringify(row().attestation || null));
    r = await signIn('pka-alice', alice, true);
    note(redirected(r), 'B1b. signs in', r.status);
    config.setOverride('webauthn.attestationAllowedAaguids', AAGUID);
    r = await signIn('pka-alice', alice, true);
    note(redirected(r), 'B2. a rule demanding trust (an AAGUID list) is ' +
         'still a REGISTRATION rule while the switch is off',
         r.status + ' ' + r.text.slice(0, 200));
    policy({ enforceAttestationAtSignIn: true, allowUsernameless: true });
    // The registration sent its own credential-change (`create`); only what
    // the refusals send is counted from here.
    changes.length = 0;
    r = await signIn('pka-alice', alice, true);
    const marked = row().attestationRefused || null;
    note(r.status === 200 && !redirected(r) &&
         /requires a trusted one/.test(r.text) &&
         sessionRefused('pka-alice', 'STS-AUTHN-0316') && !!marked &&
         changes.length === 1 && changes[0].changeType === 'update' &&
         changes[0].initiatingEntity === 'policy',
         'B3. the switch on: the key is refused at the passkey step, the ' +
         'page saying why, with a session.refuse row (STS-AUTHN-0316), the ' +
         'row marked, and one CAEP credential-change by policy',
         r.status + ' ' + JSON.stringify(marked) + ' ' + changes.length +
           ' ' + r.text.slice(0, 300));
    r = await usernameless(alice);
    note(r.status === 200 && !redirected(r) &&
         /requires a trusted one/.test(r.text) && changes.length === 1 &&
         (row().attestationRefused || {}).at === (marked || {}).at,
         'B4. and with no username, saying why — and the same refusal ' +
         'again marks nothing new and sends no second signal',
         r.status + ' ' + changes.length + ' ' + r.text.slice(0, 300));
    policy({ enforceAttestationAtSignIn: false });
    r = await signIn('pka-alice', alice, true);
    note(redirected(r), 'B5. the switch off again, it signs in',
         r.status + ' ' + r.text.slice(0, 200));
    config.clearOverride('webauthn.attestationAllowedAaguids');
    passkeyPolicy.reset('default');
    server.close();
  })().catch(function (e) {
    note(false, 'the child ran to the end', e && e.stack);
  }).then(function () {
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function theDoors(t) {
  log.debug("Entering theDoors().");
  const out = path.join(os.tmpdir(), 'sts-pka-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = Object.assign({}, process.env, { PKA_OUT: out, PKA_ROOT: ROOT,
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
  log.debug("Leaving theDoors().");
}

module.exports = {
  name: 'passkey_attestation_signin',
  describe: 'the attestation rules held at every passkey sign-in while the ' +
            'passkey policy says so: a narrowed AAGUID list, an untrusted ' +
            'statement, a compromised or under-certified model (#530)',
  run: async function (t) {
    log.debug('Entering run().');
    await theVerdict(t);
    theDoors(t);
    log.debug('Leaving run().');
  }
};
