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
// forgot-password request, the session's start (`startSessionHere()`),
// where the sign-in screen offers the registration of a passkey instead,
// and (#960) an administrator's set-password, keytab reset and LDAP
// `userPassword` — not a portal change that proved the current one.
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
//      out is accepted and keeps the default, or the value stored (#907).
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
//      STS-AUTHN-0381 at `startSession()`, as is one a key REGISTERED in
//      the act answered (#901); a passkey's is started and clears the
//      recovery.
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
//   H. AN ADMINISTRATOR'S PASSWORD ON A PASSKEY HOLDER (#960). Under
//      not-weaker, set-password (generated, and typed) leaves a pending
//      recovery naming `admin-password`; the password sign-in draws the
//      set-up step and starts no session; `pwdReset` stays clear and a
//      session they already held is not ended. Under `any`, the same
//      action leaves nothing pending and the password signs in. A portal
//      change that proved the current password, and a self LDAP bind,
//      note nothing. A non-self LDAP `userPassword` (an unbound bind's
//      create, and someone else's update) notes `admin-password`; a
//      revoke does not. `reset-person-keytab` notes the same hold when
//      this realm's KDC accepts it. A refusal before the password is set
//      — a realm whose `krb5.enabled` is off, which a new realm is —
//      leaves no pending recovery, and the password that was stored
//      still verifies. The default realm's KDC is not switched off.
//   I. A recovery write that returns false (#962) is not a finished reset
//      when a hold is required. Under not-weaker, spending an
//      administrator's link for a passkey holder does not answer success,
//      leaves the link spendable and leaves no password that signs in
//      with nothing pending. The same false write still completes a reset
//      for a person who holds no passkey. reset-password refuses rather
//      than returning a password. The directory function is restored
//      before the child exits. Sections D and H already ran with the
//      real write.
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
      // #907: left out of a LATER save, a stored row is kept, not deleted.
      const stored = withRow('operator-only');
      const resaved = withRow('');
      note(stored.ok && resaved.ok &&
           resaved.profile.recoveryAssurance === 'operator-only' &&
           resaved.profile.sources.recoveryAssurance !== 'built-in',
           'A2b. a later save that leaves the row out keeps the stored ' +
           'operator-only rather than deleting it (#907)',
           JSON.stringify(resaved.profile ? resaved.profile.recoveryAssurance
                                          : resaved.errors));
      passkeyPolicy.reset('default');
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
      // #901: a key REGISTERED in the act is not a passkey signing them in.
      const regDetail = { credential: { kind: 'webauthn',
                                        id: 'ann-new-' + STAMP,
                                        ceremony: 'registration' } };
      const reg = authn.startSession(res, ANN, ['hwk', 'user'], 'mfa',
                                     'a test', regDetail);
      note(reg === null && regDetail.refusedWith === 'STS-AUTHN-0381' &&
           !!credentials.recoveryPending(ANN),
           'D4b. a session a key REGISTERED in the act answered is refused ' +
           'STS-AUTHN-0381 too, and the recovery stays pending (#901)',
           JSON.stringify(regDetail.refusedWith || '') + ' ' +
           JSON.stringify(credentials.recoveryPending(ANN)));
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

      // ==================================================================
      // H. AN ADMINISTRATOR'S PASSWORD ON A PASSKEY HOLDER (#960)
      //
      // Section E left the row at operator-only. noteRecovery() writes
      // for that and for not-weaker, and writes nothing for `any` or for
      // a person who holds no passkey — so a false return must not fail
      // the action. A primary key is not a second factor: without the
      // hold, the password is an ordinary session. D2's set-up step is
      // what shows the hold. setPassword() itself notes nothing; these
      // doors do. The portal change and a self LDAP bind prove the
      // current password and must not.
      // ==================================================================
      const stsCrypto = require(ROOT + '/common/crypto');
      const errorCodes = require(ROOT + '/common/error_codes');
      const accountApi = require(ROOT + '/account-api/account_api');
      // A person who holds only a primary passkey.
      const primaryOnly = function (name) {
        ldapServer.createUser(name, {});
        const id = name + '-key-' + STAMP;
        credentials.addKey(name, { credentialId: id, publicKeyJwk: KEY,
                                   label: name }, 'primary');
        return id;
      };
      const doorOf = function (name) {
        const held = credentials.recoveryPending(name);
        return held && held.door ? held.door : '';
      };
      // D2's reading of the password sign-in: the recovery set-up step,
      // only a passkey, and no session.
      const recoveryStep = function (page) {
        const setup = (page && page.view && page.view.setup) || {};
        const offered = setup.offered || {};
        return !!(page && page.view && page.view.page === 'setup' &&
                  setup.recovery === true && offered.webauthn === true &&
                  offered.totp === false && noSession(page));
      };
      // C2's reading: the password went on to the application.
      const signedIn = function (page) {
        return !!(page && page.next === 'redirect' && !noSession(page) &&
                  /rp\.ra\.example|\/oauth2\/authorize/
                    .test(String(page.location || '')));
      };
      // The stored hash. Development's verify() accepts any password but
      // `invalid`, so a hash is what shows a refused keytab changed
      // nothing and a portal or LDAP write stored the new one.
      const passwordHash = function (name) {
        const view = ldapServer.objectFor(name);
        const attributes = (view && view.entry && view.entry.attributes) ||
                           {};
        const key = Object.keys(attributes).filter(function (one) {
          return one.toLowerCase() === 'userpassword';
        })[0];
        const values = key ? [].concat(attributes[key]) : [];
        return values.length ? String(values[0]) : '';
      };
      const dnOf = function (name) {
        const view = ldapServer.objectFor(name);
        return (view && view.entry && view.entry.dn) || '';
      };
      // The listeners start from listen(), which this child does not
      // call. performOperation() is the modify the socket would have
      // run, hash included, and notePasswordWritten() runs inside it.
      // boundDn '' is the unbound connection boundDnOf() reports as ''.
      const ldapModify = function (name, operation, values, boundDn) {
        return Promise.resolve(ldapServer.performOperation('modify', {
          dn: dnOf(name),
          boundDn: boundDn,
          channel: 'ldap',
          changes: [{ operation: operation,
                      modification: { type: 'userPassword',
                                      values: values } }]
        }));
      };
      const otherDn = 'uid=ra-operator-' + STAMP + ',ou=not-a-person';

      rows('not-weaker');
      const NONE = 'ra-none-' + STAMP;
      ldapServer.createUser(NONE, {});
      const noneSet = actions.usersAction({ action: 'set-password',
        user: NONE, password: 'None-Pass-960!' }, context);
      note(noneSet.ok === true &&
           passkeyPolicy.read().recoveryAssurance === 'not-weaker' &&
           credentials.recoveryPending(NONE) === null,
           'H1. under not-weaker, set-password on somebody who holds no ' +
           'passkey is still ok and notes nothing',
           JSON.stringify(noneSet.errors || noneSet.ok) + ' ' +
           JSON.stringify(credentials.recoveryPending(NONE)));

      const GEN = 'ra-gen-' + STAMP;
      const genKey = primaryOnly(GEN);
      const heldSession = authn.startSession(res, GEN, ['hwk', 'user'],
        'mfa', 'a test',
        { credential: { kind: 'webauthn', id: genKey } });
      const generated = actions.usersAction({ action: 'set-password',
        user: GEN, generate: true }, context);
      const genPage = await signInAt({ username: GEN,
        password: generated.password });
      note(generated.ok === true && !!generated.password &&
           stsCrypto.verifySecret(generated.password,
                                  passwordHash(GEN)) &&
           doorOf(GEN) === 'admin-password' &&
           credentials.passwordResetRequired(GEN) === false &&
           !!(heldSession && authn.sessionById(heldSession.id)) &&
           recoveryStep(genPage),
           'H2. a generated set-password on a primary-passkey holder ' +
           'notes admin-password, leaves pwdReset clear and the session ' +
           'they held, and the password sign-in draws the recovery ' +
           'set-up step and starts no session',
           JSON.stringify({ ok: generated.ok,
             door: doorOf(GEN),
             pwdReset: credentials.passwordResetRequired(GEN),
             session: !!(heldSession &&
                         authn.sessionById(heldSession.id)),
             page: genPage.view && genPage.view.page,
             next: genPage.next }));

      const TYPED = 'ra-typed-' + STAMP;
      primaryOnly(TYPED);
      const typedPw = 'Hal-Typed-960!';
      const typed = actions.usersAction({ action: 'set-password',
        user: TYPED, password: typedPw, passwordConfirm: typedPw },
        context);
      const typedPage = await signInAt({ username: TYPED,
        password: typedPw });
      note(typed.ok === true && typed.password === undefined &&
           stsCrypto.verifySecret(typedPw, passwordHash(TYPED)) &&
           doorOf(TYPED) === 'admin-password' &&
           credentials.passwordResetRequired(TYPED) === false &&
           recoveryStep(typedPage),
           'H3. a typed set-password notes the same door, does not echo ' +
           'the password, leaves pwdReset clear, and the sign-in is the ' +
           'same limited step',
           JSON.stringify({ ok: typed.ok, echoed: typed.password,
             door: doorOf(TYPED),
             page: typedPage.view && typedPage.view.page,
             next: typedPage.next }));

      rows('any');
      const ANYG = 'ra-anyg-' + STAMP;
      primaryOnly(ANYG);
      const anyGen = actions.usersAction({ action: 'set-password',
        user: ANYG, generate: true }, context);
      const anyGenPage = await signInAt({ username: ANYG,
        password: anyGen.password });
      note(anyGen.ok === true &&
           passkeyPolicy.read().recoveryAssurance === 'any' &&
           credentials.recoveryPending(ANYG) === null &&
           signedIn(anyGenPage),
           'H4. under any, a generated set-password leaves nothing ' +
           'pending and the password signs in',
           (anyGenPage.next || anyGenPage.status) + ' ' +
           String(anyGenPage.location || anyGenPage.text).slice(0, 160));

      const ANYT = 'ra-anyt-' + STAMP;
      primaryOnly(ANYT);
      const anyTypedPw = 'Any-Typed-960!';
      const anyTyped = actions.usersAction({ action: 'set-password',
        user: ANYT, password: anyTypedPw }, context);
      const anyTypedPage = await signInAt({ username: ANYT,
        password: anyTypedPw });
      note(anyTyped.ok === true &&
           credentials.recoveryPending(ANYT) === null &&
           stsCrypto.verifySecret(anyTypedPw, passwordHash(ANYT)) &&
           signedIn(anyTypedPage),
           'H5. and a typed one does the same',
           (anyTypedPage.next || anyTypedPage.status) + ' ' +
           String(anyTypedPage.location || anyTypedPage.text)
             .slice(0, 160));

      // Back to not-weaker, so a note these doors must not write would
      // be visible as the set-up step rather than a session.
      rows('not-weaker');
      const PORT = 'ra-port-' + STAMP;
      primaryOnly(PORT);
      const portNow = 'Port-Now-960!';
      const portNext = 'Port-Next-960!';
      credentials.setPassword(PORT, portNow);
      const accountOp = accountApi.operations().filter(function (one) {
        return one.method === 'POST' &&
               one.path === '/account-api/password';
      })[0];
      const pres = { statusCode: 0, body: '' };
      pres.status = function (s) {
        pres.statusCode = s;
        return pres;
      };
      pres.set = function () {
        return pres;
      };
      pres.type = function () {
        return pres;
      };
      pres.send = function (b) {
        pres.body = b;
        return pres;
      };
      const preq = { headers: { host: '127.0.0.1:' + port },
                     protocol: 'http', method: 'POST', url: '/',
                     ip: '127.0.0.1',
                     socket: { remoteAddress: '127.0.0.1' },
                     connection: { remoteAddress: '127.0.0.1' } };
      if (accountOp) {
        await accountOp.handler(preq, pres, {
          username: PORT, sub: '', realm: realms.DEFAULT_REALM,
          clientId: 'sts-user-portal', scopes: ['account:manage'] },
          { body: { current: portNow, next: portNext,
                    confirm: portNext }, query: {} });
      }
      const portBody = json({ text: String(pres.body || '') });
      const portPage = await signInAt({ username: PORT,
        password: portNext });
      note(!!accountOp && pres.statusCode === 200 &&
           portBody.ok === true &&
           credentials.recoveryPending(PORT) === null &&
           stsCrypto.verifySecret(portNext, passwordHash(PORT)) &&
           signedIn(portPage),
           'H6. a portal change that proved the current password notes ' +
           'nothing, and the new password signs in',
           pres.statusCode + ' ' + String(pres.body).slice(0, 180) +
           ' ' + (portPage.next || ''));

      const ldapCreate = 'ra-lcreate-' + STAMP;
      primaryOnly(ldapCreate);
      const ldapCreatePw = 'Ldap-Create-960!';
      const created = await ldapModify(ldapCreate, 'replace',
                                       [ldapCreatePw], '');
      const createPage = await signInAt({ username: ldapCreate,
        password: ldapCreatePw });
      note(created.ok === true &&
           stsCrypto.verifySecret(ldapCreatePw,
                                  passwordHash(ldapCreate)) &&
           doorOf(ldapCreate) === 'admin-password' &&
           recoveryStep(createPage),
           'H7. an unbound LDAP modify that creates userPassword notes ' +
           'admin-password, and that password draws the recovery ' +
           'set-up step',
           JSON.stringify({ ok: created.ok, error: created.error,
             door: doorOf(ldapCreate),
             page: createPage.view && createPage.view.page }));

      const ldapUp = 'ra-lupdate-' + STAMP;
      primaryOnly(ldapUp);
      credentials.setPassword(ldapUp, 'Ldap-Old-960!');
      const ldapUpPw = 'Ldap-Update-960!';
      const updated = await ldapModify(ldapUp, 'replace', [ldapUpPw],
                                       otherDn);
      const updatePage = await signInAt({ username: ldapUp,
        password: ldapUpPw });
      note(updated.ok === true && otherDn !== dnOf(ldapUp) &&
           stsCrypto.verifySecret(ldapUpPw, passwordHash(ldapUp)) &&
           doorOf(ldapUp) === 'admin-password' &&
           recoveryStep(updatePage),
           'H8. an LDAP update of userPassword by somebody else notes ' +
           'the same door',
           JSON.stringify({ ok: updated.ok, error: updated.error,
             door: doorOf(ldapUp),
             page: updatePage.view && updatePage.view.page }));

      const ldapSelf = 'ra-lself-' + STAMP;
      primaryOnly(ldapSelf);
      credentials.setPassword(ldapSelf, 'Ldap-Self-Old-960!');
      const selfDn = dnOf(ldapSelf);
      const ldapSelfPw = 'Ldap-Self-960!';
      const selfWrote = await ldapModify(ldapSelf, 'replace',
                                        [ldapSelfPw], selfDn);
      const selfPage = await signInAt({ username: ldapSelf,
        password: ldapSelfPw });
      note(selfWrote.ok === true && selfDn !== '' &&
           stsCrypto.verifySecret(ldapSelfPw, passwordHash(ldapSelf)) &&
           credentials.recoveryPending(ldapSelf) === null &&
           signedIn(selfPage),
           'H9. a self bind that changes their own password notes ' +
           'nothing, and the new password signs in',
           JSON.stringify({ ok: selfWrote.ok, error: selfWrote.error,
             door: doorOf(ldapSelf), next: selfPage.next }));

      const ldapRev = 'ra-lrevoke-' + STAMP;
      primaryOnly(ldapRev);
      credentials.setPassword(ldapRev, 'Ldap-Revoke-960!');
      const revoked = await ldapModify(ldapRev, 'delete', [], otherDn);
      note(revoked.ok === true && passwordHash(ldapRev) === '' &&
           credentials.recoveryPending(ldapRev) === null,
           'H10. a non-self revoke of userPassword notes nothing',
           JSON.stringify({ ok: revoked.ok, error: revoked.error,
             door: doorOf(ldapRev),
             hash: passwordHash(ldapRev) !== '' }));

      const KIT = 'ra-kit-' + STAMP;
      primaryOnly(KIT);
      const kitPw = 'Kit-New-960!';
      const kit = await actions.kerberosPrincipalsAction({
        action: 'reset-person-keytab', username: KIT, password: kitPw
      }, context);
      const kitPage = kit && kit.ok
        ? await signInAt({ username: KIT, password: kitPw }) : null;
      note(!!(kit && kit.ok) && doorOf(KIT) === 'admin-password' &&
           credentials.passwordResetRequired(KIT) === false &&
           stsCrypto.verifySecret(kitPw, passwordHash(KIT)) &&
           !!kitPage && recoveryStep(kitPage),
           'H11. reset-person-keytab, accepted by this realm\'s KDC, ' +
           'notes admin-password and the password sign-in is the ' +
           'recovery set-up step',
           JSON.stringify({ ok: kit && kit.ok,
             passwordSet: kit && kit.passwordSet,
             errors: kit && kit.errors, door: doorOf(KIT),
             page: kitPage && kitPage.view && kitPage.view.page }));

      // A new realm is seeded with krb5.enabled off, so the register
      // refuses before setPassword and nothing may be noted. The row is
      // saved here too: development's built-in value is `any`, and a
      // realm with no entry of its own inherits the default realm's, so
      // a read-back that is not not-weaker would make a no-op look like
      // this refusal. The default realm's KDC stays as it is.
      const nokdcId = 'ra960-' + STAMP;
      const nokdcPerson = 'ra-nokdc-' + STAMP;
      const nokdcOld = 'Nokdc-Old-960!';
      const made = realms.create({ id: nokdcId, name: 'no kdc',
        description: 'recovery assurance 960' });
      let savedOk = false;
      let assurance = '';
      let keytabRefusal = null;
      let hashBefore = '';
      let hashAfter = '';
      let pendingAfter = 'not-run';
      let oldStill = false;
      if (made.ok) {
        try {
          await realms.run(made.realm, async function () {
            ldapServer.createUser(nokdcPerson, {});
            credentials.setPassword(nokdcPerson, nokdcOld);
            credentials.addKey(nokdcPerson, {
              credentialId: nokdcPerson + '-key-' + STAMP,
              publicKeyJwk: KEY, label: nokdcPerson }, 'primary');
            const saved = rows('not-weaker');
            savedOk = !!(saved && saved.ok);
            assurance = String((passkeyPolicy.read() || {})
              .recoveryAssurance || '');
            hashBefore = passwordHash(nokdcPerson);
            keytabRefusal = await actions.kerberosPrincipalsAction({
              action: 'reset-person-keytab', username: nokdcPerson,
              password: 'Nokdc-New-960!' }, context);
            hashAfter = passwordHash(nokdcPerson);
            pendingAfter = credentials.recoveryPending(nokdcPerson);
            oldStill = stsCrypto.verifySecret(nokdcOld, hashAfter);
          });
        } finally {
          realms.remove(nokdcId);
        }
      }
      note(made.ok === true && savedOk && assurance === 'not-weaker' &&
           keytabRefusal && keytabRefusal.ok === false &&
           keytabRefusal.passwordSet !== true &&
           errorCodes.codeOf(keytabRefusal) === 'STS-KRB-0128' &&
           pendingAfter === null && hashBefore !== '' &&
           hashBefore === hashAfter && oldStill === true,
           'H12. a keytab refused before the password is set, in a new ' +
           'realm whose KDC is off, leaves no pending recovery and the ' +
           'password that was stored still verifies',
           JSON.stringify({ created: made.ok,
             errors: made.errors, saved: savedOk, assurance: assurance,
             ok: keytabRefusal && keytabRefusal.ok,
             passwordSet: keytabRefusal && keytabRefusal.passwordSet,
             code: keytabRefusal ? errorCodes.codeOf(keytabRefusal) : '',
             pending: pendingAfter, sameHash: hashBefore === hashAfter,
             verifies: oldStill }));
      // ==================================================================
      // I. A RECOVERY WRITE THAT FAILS IS NOT A FINISHED RESET (#962)
      //
      // After D and H, so those real writes are untouched. The stub is
      // the directory function the child stack holds (the object
      // setDirectory was given), and it is put back before anything else
      // in this process runs. errorCodes is the binding section H made.
      // ==================================================================
      rows('not-weaker');
      const credDir = credentials.directoryInstalled();
      note(!!credDir && typeof credDir.writeRecoveryPending === 'function',
           'I0. the directory the stack uses exposes writeRecoveryPending',
           credDir ? typeof credDir.writeRecoveryPending : 'no directory');
      if (credDir && typeof credDir.writeRecoveryPending === 'function') {
        const realRecoveryWrite = credDir.writeRecoveryPending;
        let recoveryWritesFail = false;
        let failedWrites = 0;
        credDir.writeRecoveryPending = function (key, value) {
          if (recoveryWritesFail) {
            // The directory could not record the recovery (#962).
            failedWrites += 1;
            return false;
          }
          return realRecoveryWrite(key, value);
        };
        const passwordSignsIn = function (who, password) {
          // Product mode is the check development mode does not do: a
          // name signs in there with no stored password. The override
          // is only around verify, and is cleared before the next HTTP
          // call, which must stay in development like the rest of this
          // file.
          config.setOverride('global.mode', 'product');
          let verified = { ok: true, reason: 'not-run' };
          try {
            verified = credentials.verify(who, password, { via: 'test' });
          } catch (e) {
            // A throw is not a sign-in. The finding reports it.
            verified = { ok: false, reason: String((e && e.message) || e) };
          } finally {
            config.clearOverride('global.mode');
          }
          return verified;
        };
        try {
          recoveryWritesFail = true;
          const CARA = 'ra-cara-' + STAMP;
          ldapServer.createUser(CARA, {});
          credentials.addKey(CARA, { credentialId: 'cara-primary-' + STAMP,
            publicKeyJwk: KEY, label: 'cara key' }, 'primary');
          token = issueLink(CARA);
          const writesAtSpend = failedWrites;
          r = await spend(CARA, token, 'Cara-Pass-111!');
          const failedBody = json(r);
          note(r.status !== 200 && failedBody.ok !== true &&
               /not kept/.test(r.text) && /used again/.test(r.text) &&
               !/STS-AUTHN-0382/.test(r.text) &&
               failedWrites > writesAtSpend &&
               !credentials.hasPassword(CARA) &&
               credentials.recoveryPending(CARA) === null &&
               credentials.checkPasswordReset(CARA, token).ok === true,
               'I1. under not-weaker a failed recovery write does not ' +
               'spend an administrator\'s link, does not answer success, ' +
               'and does not keep the password',
               r.status + ' ' + r.text.slice(0, 240));
          const again = await spend(CARA, token, 'Cara-Pass-111!');
          const againErrors = (json(again).errors || []).join(' ');
          note(again.status !== 200 && json(again).ok !== true &&
               /not kept/.test(againErrors) &&
               !/not valid/.test(againErrors) &&
               credentials.checkPasswordReset(CARA, token).ok === true,
               'I2. the claim was released, so a second spend can still ' +
               'be attempted and is not the spent-link refusal',
               again.status + ' ' + againErrors.slice(0, 220));
          const verified = passwordSignsIn(CARA, 'Cara-Pass-111!');
          r = await signInAt({ username: CARA, password: 'Cara-Pass-111!' });
          const ordinary = r.next === 'redirect' && !noSession(r) &&
            credentials.hasPassword(CARA) &&
            credentials.recoveryPending(CARA) === null;
          note(!verified.ok && !credentials.hasPassword(CARA) &&
               credentials.recoveryPending(CARA) === null && !ordinary,
               'I3. it does not leave a password that signs in without a ' +
               'pending recovery',
               (verified.reason || verified.ok) + ' ' +
               (r.next || r.status) + ' hasPassword=' +
               credentials.hasPassword(CARA));

          const PLAIN = 'ra-plain-' + STAMP;
          ldapServer.createUser(PLAIN, {});
          token = issueLink(PLAIN);
          const writesAtPlain = failedWrites;
          r = await spend(PLAIN, token, 'Plain-Pass-111!');
          note(r.status === 200 && json(r).ok === true &&
               credentials.recoveryPending(PLAIN) === null &&
               credentials.hasPassword(PLAIN) === true &&
               !credentials.checkPasswordReset(PLAIN, token).ok &&
               failedWrites === writesAtPlain,
               'I4. a person with no passkey still completes the reset, ' +
               'with nothing pending, while the recovery write would ' +
               'return false',
               r.status + ' writes=' + failedWrites + ' ' +
               r.text.slice(0, 160));

          const writesAtReset = failedWrites;
          const reset = actions.usersAction({ action: 'reset-password',
                                              user: CARA }, context);
          const resetText = (reset.errors || []).join(' ');
          const resetVerified = passwordSignsIn(CARA,
                                                 String(reset.password || ''));
          r = await signInAt({ username: CARA,
                               password: String(reset.password ||
                                                'Cara-Pass-111!') });
          const resetOrdinary = r.next === 'redirect' && !noSession(r) &&
            credentials.hasPassword(CARA) &&
            credentials.recoveryPending(CARA) === null;
          note(reset.ok !== true && !reset.password &&
               errorCodes.codeOf(reset) === 'STS-AUTHN-0382' &&
               /not kept/.test(resetText) && /not complete/.test(resetText) &&
               !/STS-AUTHN-0382/.test(resetText) &&
               failedWrites > writesAtReset &&
               !resetVerified.ok && !credentials.hasPassword(CARA) &&
               credentials.recoveryPending(CARA) === null && !resetOrdinary,
               'I5. reset-password under not-weaker does not return ok ' +
               'with a password when the recovery write fails, and a ' +
               'password sign-in is not an ordinary session',
               JSON.stringify({ ok: reset.ok, password: !!reset.password,
                                code: errorCodes.codeOf(reset),
                                next: r.next,
                                hasPassword: credentials.hasPassword(CARA) })
                 .slice(0, 240));
        } finally {
          recoveryWritesFail = false;
          credDir.writeRecoveryPending = realRecoveryWrite;
        }
      }

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
            'recovery code, an administrator\'s set-password, keytab and ' +
            'LDAP password (#960), a recovery that cannot be recorded ' +
            '(#962), and the sign-in limited to registering a passkey ' +
            '(#724)',
  run: run
};
