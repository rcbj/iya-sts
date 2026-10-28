// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/post_login.js
//
// ===========================================================================
// POST-LOGIN ACTIVITIES: THE POST-QUANTUM PASSKEY MIGRATION (#1096).
//
// rcbj: a "post login activity", targeted at groups, configurable and
// enabled per realm; the
// first one asks a person holding a classical passkey to register a
// post-quantum one, skippable for a number of days, with a grace period after
// which the sign-in is held. In a CHILD PROCESS serving the stack on a
// loopback port (`passkey_dual_lane.js`'s harness), with REAL ceremonies from
// a software authenticator over `webauthn_attestation_kit.js`'s ML-DSA keys:
//
//   A. The policy: off by default (nobody is due anything); a bad profile
//      name, a missing field and a named profile with no group are refused
//      under STS-AUTHN-0470 / 0471.
//   B. On: a person holding a classical PRIMARY passkey is due one in
//      `primary`, a person holding a classical second-factor passkey in
//      `mfa`; a person with no passkey only as `noPasskey` says.
//   C. Exclusion by group: a named profile with `enabled` off at a lower
//      precedence reaches its members, who are due nothing.
//   D. Over HTTP: a password sign-in by the classical-passkey holder starts
//      NO session and lands on `/authn/post-login`; another step's act on
//      the step's id is refused (the way round); Skip starts the held
//      session and puts it off, so the next sign-in is not asked.
//   E. Register: the passkey page's registration offers ML-DSA only and no
//      classical retry; an ML-DSA credential registers in the activity's
//      role, the held session starts, and nothing is due afterwards.
//   F. Required: past the allotted time Skip is refused (STS-AUTHN-0474);
//      a door that cannot draw the step is refused (STS-AUTHN-0473); a
//      keyed caller is never asked.
//   G. A realm that cannot make an ML-DSA passkey asks nobody.
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

  // A SOFTWARE AUTHENTICATOR: registration only, `passkey_dual_lane.js`'s.
  const sha256 = function (buf) {
    return nodeCrypto.createHash('sha256').update(buf).digest();
  };
  const makeAuthenticator = async function (alg, rpId, origin) {
    const cred = await kit.credential(alg);
    const id = cred.id.toString('base64url');
    return {
      credentialId: id,
      register: function (challenge) {
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
                   clientDataJSON: Buffer.from(JSON.stringify({
                     type: 'webauthn.create', challenge: challenge,
                     origin: origin, crossOrigin: false }), 'utf8')
                     .toString('base64url') } };
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
    const authnScreen = require(ROOT + '/tests/tools/authn_screen');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const ORIGIN = 'http://127.0.0.1:' + port;
    const RPID = '127.0.0.1';
    const REDIRECT = 'https://rp.pla.example/cb';
    const PASSWORD = 'correct-horse-battery-staple-pla-7!';
    const EC = { kty: 'EC', crv: 'P-256', x: 'AA', y: 'AA' };
    config.setOverride('oauth2.consentRequired', false);
    applications.createApplication({ identifier: 'pla-public',
      protocols: ['oauth2'],
      fields: { oauthClientId: 'pla-public', oauthClientSecret: '',
                oauthRedirectUri: [REDIRECT],
                oauthTokenEndpointAuthMethod: 'none',
                oauthGrantType: ['authorization_code'] } });
    ['pla-ann', 'pla-bob', 'pla-cat', 'pla-dan', 'pla-eve']
      .forEach(function (name) {
        ldap.createUser(name, { invent: false });
        credentials.setPassword(name, PASSWORD);
      });
    // ann, dan and eve sign in with a classical passkey; cat's is a second
    // factor; bob holds none.
    credentials.addKey('pla-ann', { credentialId: 'pla-ann-ec',
                                    publicKeyJwk: EC }, 'primary');
    credentials.addKey('pla-dan', { credentialId: 'pla-dan-ec',
                                    publicKeyJwk: EC }, 'primary');
    credentials.addKey('pla-eve', { credentialId: 'pla-eve-ec',
                                    publicKeyJwk: EC }, 'primary');
    credentials.addKey('pla-cat', { credentialId: 'pla-cat-ec',
                                    publicKeyJwk: EC }, 'mfa');
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
      }).length;
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
    const signIn = async function (name) {
      const s = await screenFor();
      const answer = await authnScreen.submit({ port: port, jar: s.b.jar,
        opened: s.opened, fields: { action: 'login', username: name,
                                    password: PASSWORD } });
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
    const noGroup = policy.save('pilot', fields({ selectGroups: [] }));
    note(!badName.ok && errorCodes.codeOf(badName) === 'STS-AUTHN-0470' &&
         !missing.ok && errorCodes.codeOf(missing) === 'STS-AUTHN-0471' &&
         !noGroup.ok && errorCodes.codeOf(noGroup) === 'STS-AUTHN-0471',
         'A2. a bad name, a missing field and a named profile with no ' +
         'group are refused under their codes',
         JSON.stringify([badName.errors, missing.errors, noGroup.errors]));

    // B. On.
    const on = policy.save('default', fields({ enabled: true,
                                               snoozeDays: 3 }));
    const ann = postLogin.dueFor('pla-ann');
    const cat = postLogin.dueFor('pla-cat');
    const bobLeft = postLogin.dueFor('pla-bob');
    policy.save('default', fields({ enabled: true, snoozeDays: 3,
                                    noPasskey: 'invite',
                                    noPasskeyRole: 'mfa' }));
    const bobInvited = postLogin.dueFor('pla-bob');
    note(on.ok && ann && ann.role === 'primary' &&
         ann.reason === 'classical' && ann.required === false &&
         cat && cat.role === 'mfa' && bobLeft === null && bobInvited &&
         bobInvited.reason === 'none' && bobInvited.role === 'mfa' &&
         bobInvited.enforceable === false,
         'B. on: classical primary and second-factor holders are due a ' +
         'post-quantum passkey in that role; one with none only as ' +
         'noPasskey says', JSON.stringify([on.errors, ann, cat, bobLeft,
                                           bobInvited]));
    policy.save('default', fields({ enabled: true, snoozeDays: 3 }));

    // C. Exclusion by group.
    const excluded = policy.save('pla-excluded', fields({ enabled: false,
      selectGroups: ['pla-excluded'], precedence: 10 }));
    note(excluded.ok && policy.profileNameFor('pla-eve') === 'pla-excluded' &&
         policy.profileNameFor('pla-ann') === 'default' &&
         postLogin.dueFor('pla-eve') === null,
         'C. a disabled named profile reaches its group\'s members, who ' +
         'are due nothing', JSON.stringify(excluded.errors || []));

    // D. Over HTTP: held, a way round refused, Skip.
    let s = await signIn('pla-ann');
    const startsBefore = rows('session.start', 'pla-ann');
    note(s.answer.next === 'mfa' && s.answer.step === 'post-login' &&
         /\/authn\/post-login\?mfa=/.test(s.answer.location) &&
         rows('session.start', 'pla-ann') === startsBefore &&
         rows('authn.post-login.asked', 'pla-ann') === 1,
         'D1. the password sign-in starts no session and lands on the ' +
         'post-login step', JSON.stringify(s.answer.json));
    let opened = await openStep(s.b, s.answer);
    const v = (opened.view || {}).postLogin || {};
    note(opened.status === 200 && v.role === 'primary' &&
         v.reason === 'classical' && v.canSkip === true &&
         v.snoozeDays === 3,
         'D2. its view names the role, the reason and Skip',
         JSON.stringify(opened.view));
    const roundAbout = await stepAct(s.b, opened, 'totp',
                                     { code: '000000' });
    note(roundAbout.apiStatus === 400 &&
         rows('session.start', 'pla-ann') === startsBefore,
         'D3. another step\'s act on the post-login step is refused and ' +
         'starts nothing', roundAbout.apiStatus + ' ' + roundAbout.next);
    const skipped = await stepAct(s.b, opened, 'post-login/skip');
    const snoozed = postLogin.stateOf('pla-ann');
    note(startsSession(skipped) &&
         rows('session.start', 'pla-ann') === startsBefore + 1 &&
         snoozed.snoozedUntil > Date.now() + 2 * DAY &&
         rows('authn.post-login.skipped', 'pla-ann') === 1,
         'D4. Skip starts the held session and puts it off for snoozeDays',
         JSON.stringify([skipped.json, snoozed]));
    s = await signIn('pla-ann');
    note(startsSession(s.answer),
         'D5. while it is put off, the next sign-in is not asked',
         JSON.stringify(s.answer.json));

    // E. Register.
    postLogin.forget('pla-ann');
    s = await signIn('pla-ann');
    opened = await openStep(s.b, s.answer);
    const toPasskey = await stepAct(s.b, opened, 'post-login/register');
    const page = toPasskey.next === 'mfa'
      ? await openStep(s.b, toPasskey) : {};
    const w = (page.view || {}).webauthn || {};
    note(toPasskey.step === 'webauthn' && w.mode === 'create' &&
         (w.algorithms || []).length > 0 &&
         w.algorithms.every(function (one) {
           return /^ML-DSA-/.test(one);
         }) && w.fallback && w.fallback.classical === false &&
         w.postLogin && w.postLogin.role === 'primary',
         'E1. Register draws a registration offering ML-DSA only, with no ' +
         'classical retry', JSON.stringify(w).slice(0, 400));
    const retry = await stepAct(s.b, page, 'webauthn/options',
                                { algorithms: 'classical' });
    note(retry.apiStatus === 400,
         'E2. a classical retry is refused on a post-login step',
         retry.apiStatus + ' ' + JSON.stringify(retry.errors));
    const pq = await makeAuthenticator(-49, RPID, ORIGIN);
    const made = await authnScreen.passkeyStep({ port: port, jar: s.b.jar,
      opened: page }, function (armed) {
      return pq.register(armed.challenge);
    });
    const keys = credentials.keysOf('pla-ann');
    const pqKey = keys.filter(function (one) {
      return credentials.keyAlgorithm(one).postQuantum;
    })[0];
    note(startsSession(made.answer) && pqKey && pqKey.role === 'primary' &&
         keys.length === 2 && postLogin.dueFor('pla-ann') === null &&
         rows('authn.post-login.done', 'pla-ann') === 1,
         'E3. an ML-DSA passkey registers as primary beside the classical ' +
         'one, the held session starts, and nothing is due afterwards',
         JSON.stringify([made.armed.json && made.armed.json.options &&
                         made.armed.json.options.algorithms,
                         made.answer.json, keys.map(function (one) {
                           return [one.role,
                                   credentials.keyAlgorithm(one).name];
                         })]));

    // F. Required.
    policy.save('default', fields({ enabled: true, snoozeDays: 3,
                                    graceDays: 1 }));
    const past = new postLogin.PostLogin(Object.assign(
      postLogin.PostLogin.defaultDeps(),
      { now: function () { return Date.now() - 2 * DAY; } }));
    past.noteSkipped('pla-dan', past.dueFor('pla-dan'));
    const dan = postLogin.dueFor('pla-dan');
    note(dan && dan.required === true,
         'F1. past the allotted time the activity is required, whatever ' +
         'was put off', JSON.stringify(dan));
    s = await signIn('pla-dan');
    opened = await openStep(s.b, s.answer);
    const noSkip = await stepAct(s.b, opened, 'post-login/skip');
    note(opened.view && opened.view.postLogin &&
         opened.view.postLogin.canSkip === false &&
         noSkip.apiStatus === 400 && codeRecorded('STS-AUTHN-0474'),
         'F2. Skip is not offered, and is refused (STS-AUTHN-0474)',
         JSON.stringify([opened.view, noSkip.json]));
    const elsewhere = { request: { headers: {} },
                        credential: { kind: 'federation' } };
    const other = authn.startSession(fakeRes, 'pla-dan', ['fed'], '1',
                                     'a test', elsewhere);
    note(other === null && elsewhere.refusedWith === 'STS-AUTHN-0473',
         'F3. a door that cannot draw the step is refused (STS-AUTHN-0473)',
         JSON.stringify(elsewhere.refusedWith || ''));
    const keyed = authn.startSession(fakeRes, 'pla-dan', ['pwd'], '1',
      'a test', { key: 'pla-key-' + Date.now(), credential: {} });
    note(!!keyed, 'F4. a keyed caller is never asked');

    // G. No ML-DSA here.
    config.setOverride('webauthn.enabled', false);
    const off = postLogin.dueFor('pla-cat');
    config.clearOverride('webauthn.enabled');
    note(off === null,
         'G. a realm that cannot make a passkey asks nobody for one');

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
  name: 'post_login',
  describe: 'post-login activities (#1096): the post-quantum passkey ' +
            'migration, targeted by group, skippable, then required — the ' +
            'held session, Skip, an ML-DSA registration, and the doors that ' +
            'cannot ask',
  run: run
};
