// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';

// ===========================================================================
// tests/recovery_assurance.js — ACCOUNT RECOVERY NO WEAKER THAN THE PASSKEY
// IT REPLACES (#724).
//
// The passkey policy's `recoveryAssurance` row (`any`, `not-weaker`,
// `operator-only`), the `recover-account` rules of the issuance policy that
// decide it, and the doors that ask: a reset link's spend, the
// forgot-password request, and the session's start (`startSessionHere()`),
// where the sign-in screen offers the registration of a passkey instead.
//
// In a CHILD PROCESS, for `admin_credential_controls.js`'s reason: it loads
// the whole protocol stack, creates people in the default realm and saves
// that realm's passkey policy, which every other file in `run.js`'s one
// process would see.
//
// The claims:
//
//   A. The row's built-in default is `any` in development and `not-weaker`
//      in product (rcbj's decision on #724), and a save that leaves the row
//      out is accepted and keeps the default.
//   B. The built-in document's `recover-account` rules and
//      `common/passkey_rules.js`'s reading of them give one answer —
//      verdict, code and reason — over a grid of every fact they read.
//   C. UNDER `any` (today's behaviour, and step 1's finding on the ticket):
//      an administrator's reset link, spent, lets a person who holds only a
//      passkey sign in with the password alone, and the session reaches the
//      application. No recovery is recorded.
//   D. UNDER `not-weaker`: the spent link leaves a pending recovery; the
//      password sign-in starts NO session and draws the set-up step, marked
//      `recovery`, offering only a passkey, whose ceremony is a
//      REGISTRATION; a session that a passkey did not answer is refused
//      STS-AUTHN-0381 at `startSession()`; a passkey's is started and
//      clears the recovery.
//   E. A RECOVERY CODE at the second-factor step, for a person holding an
//      `mfa` passkey, is itself a recovery door: under `not-weaker` it
//      leads to the same registration (a REGISTRATION although they hold a
//      key), and under `operator-only` the step offers no recovery code and
//      one spent anyway is refused STS-AUTHN-0380.
//   F. UNDER `operator-only`: a reset link the person asked for is refused
//      at its spend (403, STS-AUTHN-0380) and an administrator's is not;
//      the forgot-password request mails nothing to a passkey holder.
//   G. /admin-api's save-passkey-policy takes the row (rule 7's parity), a
//      value outside the three is refused, and a body that leaves it out —
//      every caller written before it existed — is accepted.
// ===========================================================================

delete process.env.CONFIG_FILE;

const path = require('path');
const os = require('os');
const fs = require('fs');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'recovery_assurance',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.RA_ROOT;
  const OUT = process.env.RA_OUT;
  const http = require('http');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  function request(port, method, urlPath, body) {
    return new Promise(function (resolve) {
      const text = body ? JSON.stringify(body) : '';
      const headers = {};
      if (method !== 'GET') {
        headers['content-type'] = 'application/json';
        headers['content-length'] = Buffer.byteLength(text);
      }
      const req = http.request({ host: '127.0.0.1', port: port, path: urlPath,
                                 method: method, headers: headers },
                               function (res) {
        let out = '';
        res.on('data', function (c) { out += c; });
        res.on('end', function () {
          resolve({ status: res.statusCode, headers: res.headers,
                    text: out });
        });
      });
      req.end(text);
    });
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const config = require(ROOT + '/common/config');
    const realms = require(ROOT + '/common/realms');
    const credentials = require(ROOT + '/common/credentials');
    const ldapServer = require(ROOT + '/ldap/ldap_server');
    const actions = require(ROOT + '/admin-core/admin_actions');
    const passkeyPolicy = require(ROOT + '/common/passkey_policy');
    const passkeyRules = require(ROOT + '/common/passkey_rules');
    const verdicts = require(ROOT + '/xacml/xacml_passkey_verdicts');
    const authn = require(ROOT + '/authn/authn');
    const mailUses = require(ROOT + '/common/mail_uses');
    const screen = require(ROOT + '/tests/tools/authn_screen');

    const STAMP = Date.now().toString(36);
    const context = { via: 'api', actor: 'tester', base: 'https://sts.test' };
    const KEY = { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' };
    const withRow = function (value) {
      const fields = Object.assign({}, passkeyPolicy.DEFAULTS);
      if (value) {
        fields.recoveryAssurance = value;
      } else {
        delete fields.recoveryAssurance;
      }
      return passkeyPolicy.save('default', fields);
    };
    // A fake response for `startSession()` called directly.
    const res = { set: function () { return res; },
                  append: function () { return res; },
                  status: function () { return res; },
                  type: function () { return res; },
                  send: function () { return res; },
                  req: null };

    await realms.run(realms.DEFAULT_REALM, async function () {
      // ==================================================================
      // A. THE DEFAULTS
      // ==================================================================
      passkeyPolicy.reset('default');
      const devDefault = passkeyPolicy.read().recoveryAssurance;
      config.setOverride('global.mode', 'product');
      const productDefault = passkeyPolicy.read().recoveryAssurance;
      const productConstant = passkeyPolicy.DEFAULTS.recoveryAssurance;
      config.clearOverride('global.mode');
      note(devDefault === 'any' && productDefault === 'not-weaker' &&
           productConstant === 'not-weaker',
           'A1. recoveryAssurance is any in development and not-weaker in ' +
           'product by default', devDefault + ' / ' + productDefault +
           ' / ' + productConstant);
      const leftOut = withRow('');
      note(leftOut.ok && leftOut.profile.recoveryAssurance === 'any' &&
           leftOut.profile.sources.recoveryAssurance === 'built-in',
           'A2. a save that leaves the row out is accepted and keeps the ' +
           'built-in default', JSON.stringify(leftOut.errors || []));
      const bad = withRow('sometimes');
      note(!bad.ok, 'A3. a value outside the three is refused',
           JSON.stringify(bad.errors || []));

      // ==================================================================
      // B. THE DOCUMENT AND THE READING FROM THE FACTS AGREE
      // ==================================================================
      const differ = [];
      let asked = 0;
      let refusals = 0;
      ['any', 'not-weaker', 'operator-only'].forEach(function (row) {
        ['', 'forgot-password', 'admin-reset', 'recovery-code']
          .forEach(function (door) {
          ['door', 'session'].forEach(function (at) {
            ['', 'password', 'webauthn'].forEach(function (credential) {
              [true, false].forEach(function (covered) {
                [true, false].forEach(function (pending) {
                  const q = {
                    action: 'recover-account', subject: 'ra-grid',
                    groups: ['recovery'],
                    recovery: { door: door, at: at, credential: credential,
                      selfService: !!(passkeyPolicy.RECOVERY_DOORS[door] &&
                        passkeyPolicy.RECOVERY_DOORS[door].selfService),
                      covered: covered, pending: pending },
                    policy: { backupEligibility: 'allow',
                              enforcePinLength: false, minPinLength: 4,
                              pinLengthOnlyIfSupported: false,
                              enforceAttestationAtSignIn: false,
                              enterpriseSerialAttribute: '',
                              recoveryAssurance: row },
                    settings: {} };
                  const doc = verdicts.decide(q, null, {});
                  const read = passkeyRules.strictReading(q);
                  asked += 1;
                  if (doc.verdict === 'refuse') {
                    refusals += 1;
                  }
                  if (doc.verdict !== read.verdict || doc.code !== read.code ||
                      doc.reason !== read.reason ||
                      doc.decidedBy !== 'built-in') {
                    differ.push(JSON.stringify({ q: q.recovery, row: row,
                                                 doc: doc, read: read }));
                  }
                });
              });
            });
          });
        });
      });
      note(differ.length === 0 && refusals > 0,
           'B1. the built-in document and the rules read from the facts ' +
           'give one answer over ' + asked + ' questions (' + refusals +
           ' refusals)', differ.slice(0, 3).join(' | '));

      // ==================================================================
      // THE STACK OVER HTTP
      // ==================================================================
      const server = http.createServer(app);
      await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
      const port = server.address().port;
      const json = function (r) {
        try {
          return JSON.parse(r.text);
        } catch (e) {
          // Not JSON: the assertion names the text.
          return {};
        }
      };
      const spend = function (user, token, password) {
        return request(port, 'POST', '/account-api/reset-password',
          { user: user, token: token, password: password,
            confirm: password });
      };
      const issueLink = function (user) {
        const issued = actions.usersAction({ action: 'issue-password-reset',
                                             user: user }, context);
        const link = String(issued.resetUrl || '');
        return decodeURIComponent((link.match(/[?&]token=([^&]+)/) ||
                                   [])[1] || '');
      };
      const startSignIn = async function () {
        const got = await request(port, 'GET', '/oauth2/authorize?' +
          new URLSearchParams({ client_id: 'ra-client',
                                response_type: 'code',
                                redirect_uri: 'https://rp.ra.example/cb',
                                scope: 'openid', state: 's' }).toString());
        const location = String(got.headers.location || '');
        return (location.match(/[?&]authn=([^&]+)/) || [])[1] || '';
      };
      const signInAt = async function (fields) {
        const jar = {};
        const authnId = await startSignIn();
        const got = await screen.follow({ port: port, jar: jar,
          at: '/authn/login?authn=' + authnId,
          fields: Object.assign({ action: 'login' }, fields) });
        got.jar = jar;
        return got;
      };
      const stepAct = function (page, op, body) {
        return screen.stepAct({ port: port, jar: page.jar, opened: page,
                                op: op, body: body || {} });
      };
      const reopen = async function (page, answer) {
        const got = await screen.openStep({ port: port, jar: page.jar,
          at: answer.location || page.at });
        got.jar = page.jar;
        return got;
      };
      const cookieOf = function (r) {
        const lines = [].concat((r.headers || {})['set-cookie'] || []);
        return lines.map(function (one) {
          return String(one).split(';')[0];
        }).filter(function (one) { return /^sts_session=./.test(one); })[0] ||
          '';
      };
      const noSession = function (r) {
        return !cookieOf(r) && !(r.answer && cookieOf(r.answer));
      };

      // A person who holds ONLY a passkey that signs them in on its own.
      const ANN = 'ra-ann-' + STAMP;
      ldapServer.createUser(ANN, {});
      credentials.addKey(ANN, { credentialId: 'ann-primary-' + STAMP,
        publicKeyJwk: KEY, label: 'ann key' }, 'primary');
      // Usernameless sign-in OFF, so the screen's own passkey button is not
      // what answers below.
      const rows = function (value) {
        return passkeyPolicy.save('default', Object.assign({},
          passkeyPolicy.DEFAULTS, { allowUsernameless: false,
                                    recoveryAssurance: value }));
      };

      // ==================================================================
      // C. UNDER any: TODAY'S BEHAVIOUR
      // ==================================================================
      rows('any');
      let token = issueLink(ANN);
      let r = await spend(ANN, token, 'Ann-Pass-111!');
      note(r.status === 200 && json(r).ok === true &&
           credentials.recoveryPending(ANN) === null,
           'C1. under any the administrator\'s link is spent and no ' +
           'recovery is recorded', r.status + ' ' + r.text.slice(0, 200));
      r = await signInAt({ username: ANN, password: 'Ann-Pass-111!' });
      note(r.next === 'redirect' && !noSession(r) &&
           /rp\.ra\.example|\/oauth2\/authorize/.test(String(r.location)),
           'C2. and the password alone, for a person who holds only a ' +
           'passkey, starts a session that goes on to the application',
           (r.next || r.status) + ' ' + String(r.location || r.text)
             .slice(0, 160));

      // ==================================================================
      // D. UNDER not-weaker
      // ==================================================================
      rows('not-weaker');
      token = issueLink(ANN);
      r = await spend(ANN, token, 'Ann-Pass-222!');
      const pending = credentials.recoveryPending(ANN);
      note(r.status === 200 && pending && pending.door === 'admin-reset',
           'D1. the spent link leaves a pending recovery naming its door',
           r.status + ' ' + JSON.stringify(pending));
      r = await signInAt({ username: ANN, password: 'Ann-Pass-222!' });
      const setupPage = r;
      const setup = (r.view && r.view.setup) || {};
      note(r.view && r.view.page === 'setup' && setup.recovery === true &&
           setup.offered && setup.offered.webauthn === true &&
           setup.offered.totp === false && noSession(r),
           'D2. the password sign-in starts no session and draws the ' +
           'set-up step, marked recovery, offering only a passkey',
           r.status + ' ' + JSON.stringify(r.view || r.text).slice(0, 240));
      r = await stepAct(setupPage, 'setup/webauthn');
      const ceremony = r.next === 'mfa' ? await reopen(setupPage, r) : r;
      note(ceremony.view && ceremony.view.webauthn &&
           ceremony.view.webauthn.mode === 'create',
           'D3. choosing a passkey draws a registration ceremony',
           (r.apiStatus || r.status) + ' ' +
           JSON.stringify(ceremony.view || ceremony.text).slice(0, 200));
      const pwDetail = { credential: { kind: 'password' } };
      const pw = authn.startSession(res, ANN, ['pwd'], '1', 'a test',
                                    pwDetail);
      note(pw === null && pwDetail.refusedWith === 'STS-AUTHN-0381' &&
           pwDetail.recoveryLimited === true,
           'D4. at startSession() a session a passkey did not answer is ' +
           'refused STS-AUTHN-0381', JSON.stringify(pwDetail));
      const keyDetail = { credential: { kind: 'webauthn',
                                        id: 'ann-primary-' + STAMP } };
      const key = authn.startSession(res, ANN, ['hwk', 'user'], 'mfa',
                                     'a test', keyDetail);
      note(!!key && credentials.recoveryPending(ANN) === null,
           'D5. a passkey\'s session is started and clears the recovery',
           JSON.stringify(keyDetail.refusedWith || '') + ' ' +
           JSON.stringify(credentials.recoveryPending(ANN)));
      const after = authn.startSession(res, ANN, ['pwd'], '1', 'a test',
        { credential: { kind: 'password' } });
      note(!!after, 'D6. once completed, the password signs in as before');

      // ==================================================================
      // E. A RECOVERY CODE AT THE SECOND-FACTOR STEP
      // ==================================================================
      const BOB = 'ra-bob-' + STAMP;
      ldapServer.createUser(BOB, {});
      credentials.setPassword(BOB, 'Bob-Pass-333!');
      credentials.addKey(BOB, { credentialId: 'bob-mfa-' + STAMP,
        publicKeyJwk: KEY, label: 'bob key' }, 'mfa');
      const set = credentials.beginBackupCodes(BOB);
      credentials.confirmBackupCodes(BOB, set.handle);
      r = await signInAt({ username: BOB, password: 'Bob-Pass-333!' });
      const keyStep = r;
      note(r.view && r.view.page === 'webauthn' && r.view.links &&
           r.view.links.backup === true,
           'E1. the passkey step offers a recovery code under not-weaker',
           JSON.stringify(r.view || r.text).slice(0, 200));
      let rc = await screen.openStep({ port: port, jar: keyStep.jar,
        at: '/authn/backup-code?mfa=' + keyStep.id });
      r = await screen.stepAct({ port: port, jar: keyStep.jar, opened: rc,
        op: 'backup-code', body: { code: set.codes[0] } });
      const bobSetup = r.next === 'mfa' ? await reopen(keyStep, r) : r;
      note(r.next === 'mfa' && r.step === 'enrol' && noSession(r) &&
           bobSetup.view && bobSetup.view.setup &&
           bobSetup.view.setup.recovery === true,
           'E2. a recovery code in place of the passkey starts no session ' +
           'and draws the recovery set-up step',
           (r.next || r.apiStatus) + ' ' + JSON.stringify(r).slice(0, 200));
      r = await stepAct(bobSetup, 'setup/webauthn');
      const bobCeremony = r.next === 'mfa' ? await reopen(bobSetup, r) : r;
      note(bobCeremony.view && bobCeremony.view.webauthn &&
           bobCeremony.view.webauthn.mode === 'create',
           'E3. and its ceremony is a REGISTRATION although they hold a ' +
           'passkey', JSON.stringify(bobCeremony.view || '').slice(0, 200));

      rows('operator-only');
      r = await signInAt({ username: BOB, password: 'Bob-Pass-333!' });
      const closedStep = r;
      note(r.view && r.view.page === 'webauthn' && r.view.links &&
           r.view.links.backup === false,
           'E4. under operator-only the step offers no recovery code',
           JSON.stringify((r.view && r.view.links) || r.text));
      rc = await screen.openStep({ port: port, jar: closedStep.jar,
        at: '/authn/backup-code?mfa=' + closedStep.id });
      r = await screen.stepAct({ port: port, jar: closedStep.jar,
        opened: rc, op: 'backup-code', body: { code: set.codes[1] } });
      note(r.next === 'refused' && noSession(r) &&
           /only by whoever manages it/.test((r.errors || []).join(' ') +
                                            String(r.text || '')),
           'E5. and one spent anyway is refused (STS-AUTHN-0380)',
           (r.next || r.apiStatus) + ' ' + String(r.text || '').slice(0, 200));
      const bcDetail = { credential: { kind: 'backup-code' } };
      const bc = authn.startSession(res, BOB, ['pwd', 'otp'], 'mfa',
                                    'a test', bcDetail);
      note(bc === null && bcDetail.refusedWith === 'STS-AUTHN-0380',
           'E6. at startSession() a recovery code is refused STS-AUTHN-0380',
           JSON.stringify(bcDetail));

      // ==================================================================
      // F. UNDER operator-only: THE SELF-SERVICE DOORS
      // ==================================================================
      const self = credentials.issuePasswordReset(ANN, { source: 'self' });
      r = await spend(ANN, self.token, 'Ann-Pass-444!');
      note(r.status === 403 && /operator-only/.test(r.text) &&
           credentials.checkPasswordReset(ANN, self.token).ok,
           'F1. a reset link the person asked for is refused at its spend ' +
           '(403), and stays unspent', r.status + ' ' + r.text.slice(0, 200));
      token = issueLink(ANN);
      r = await spend(ANN, token, 'Ann-Pass-555!');
      note(r.status === 200 && json(r).ok === true &&
           (credentials.recoveryPending(ANN) || {}).door === 'admin-reset',
           'F2. an administrator\'s link is spent, and the recovery is ' +
           'pending', r.status + ' ' + r.text.slice(0, 200));
      const issued = [];
      const uses = new mailUses.MailUses(Object.assign(
        mailUses.MailUses.defaultDeps(), {
          config: { value: function (key) {
            return key === 'mail.selfServiceReset' ? true
              : key === 'mail.resetRequiresBackupCode' ? false
              : config.value(key);
          } },
          mode: Object.assign({}, require(ROOT + '/common/mode'), {
            verifiesCredentials: function () { return true; } }),
          mail: {
            available: function () { return true; },
            directory: function () {
              return { personEntry: function (u) {
                return u === ANN || u === 'ra-nokey' ? { dn: u } : null;
              } };
            },
            recipient: function () {
              return { address: 'ann@ra.example', verified: true };
            },
            send: function () { return { ok: true, refused: [] }; }
          },
          credentials: function () {
            return { accountDisabled: function () { return false; },
                     holdsPasskey: function (u) { return u === ANN; },
                     issuePasswordReset: function (u) {
                       issued.push(u);
                       return { ok: true, token: 't', expiresAt: 'soon' };
                     } };
          },
          accountSignals: function () {
            return { recoveryActivated: function () {} };
          }
        }));
      const refused = await uses.requestReset(ANN, 'a test');
      const allowed = await uses.requestReset('ra-nokey', 'a test');
      note(refused.message === mailUses.MailUses.RESET_ANSWER &&
           /only an operator/.test(refused.outcome) &&
           issued.indexOf(ANN) < 0 && issued.indexOf('ra-nokey') >= 0 &&
           allowed.outcome === 'mailed',
           'F3. the forgot-password request mails nothing to a passkey ' +
           'holder, answers its one sentence, and still mails somebody ' +
           'holding none', refused.outcome + ' / ' + allowed.outcome);

      // ==================================================================
      // G. THE MANAGEMENT API TAKES THE ROW
      // ==================================================================
      const adminApi = require(ROOT + '/mgmt-api/admin_api');
      let target = null;
      adminApi.ROUTES.forEach(function (entry) {
        (entry.actions || []).forEach(function (one) {
          if (one.action === 'save-passkey-policy' && entry.route) {
            target = { route: entry.route, action: one.action,
                       schema: one.requestBody || {} };
          }
        });
      });
      const askApi = function (body) {
        return adminApi.checkRequestBody({
          __adminApiRoute: target.route,
          params: { action: target.action },
          body: JSON.stringify(body),
          headers: { 'content-type': 'application/json' } });
      };
      const whole = Object.assign({ profile: 'default' },
                                  passkeyPolicy.DEFAULTS);
      const without = Object.assign({}, whole);
      delete without.recoveryAssurance;
      const taken = target && askApi(Object.assign({}, whole,
        { recoveryAssurance: 'operator-only' }));
      const odd = target && askApi(Object.assign({}, whole,
        { recoveryAssurance: 'sometimes' }));
      const old = target && askApi(without);
      note(!!target && !!(target.schema.properties || {}).recoveryAssurance &&
           (target.schema.required || []).indexOf('recoveryAssurance') < 0 &&
           taken.ok && !odd.ok && old.ok,
           'G1. save-passkey-policy takes recoveryAssurance, refuses a value ' +
           'outside the three, and accepts a body without it',
           JSON.stringify([taken, odd, old]).slice(0, 300));

      passkeyPolicy.reset('default');
      server.close();
    });

    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child ran to the end',
                    detail: e && e.stack });
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function inAChild(t) {
  log.debug("Entering inAChild().");
  const out = path.join(os.tmpdir(), 'recovery-assurance-' + process.pid +
                        '-' + require('crypto').randomBytes(8)
                          .toString('hex') + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|ADMIN_|CONFIG_FILE$)/
        .test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', RA_ROOT: ROOT,
                                  RA_OUT: out }),
      encoding: 'utf8', timeout: 240000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
    // No report: the child died before writing one. Reported below with its
    // exit status and stderr, which is where the reason is.
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written, which the read above has already reported.
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings), 'the child process reported its ' +
                                        'findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-800))) {
    log.debug("Leaving inAChild().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving inAChild().");
}

async function run(t) {
  log.debug("Entering run().");
  inAChild(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'recovery assurance',
  describe: 'account recovery no weaker than the passkey it replaces: the ' +
            'passkey policy\'s recoveryAssurance, the recover-account ' +
            'rules, the reset link, the forgot-password request, the ' +
            'recovery code and the sign-in limited to registering a ' +
            'passkey (#724)',
  run: run
};
