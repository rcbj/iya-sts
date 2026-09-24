'use strict';

// ===========================================================================
// tests/admin_credential_controls.js — WHAT AN ADMINISTRATOR DOES TO
// SOMEBODY'S CREDENTIALS, AND THE SECOND FACTOR A SIGN-IN MAY NOW ENROL
// (2026-09-13).
//
// The six actions on a person's /admin/users page (and POST
// /admin-api/users/{action}), the password reset link they issue, the
// per-account and per-realm second-factor requirement, and the Shared Signals
// each of them sends.
//
// In a CHILD PROCESS, for `admin_bootstrap.js`'s reason: it loads the whole
// protocol stack, creates people and streams in the default realm, and flips
// realm settings that every other file in `run.js`'s one process would see.
//
// The claims:
//
//   1. reset-password returns a generated password ONCE, sets pwdReset, and
//      sends CAEP credential-change (password, update) and RISC
//      account-credential-change-required to a stream that asked for them.
//   2. issue-password-reset returns an absolute link on the base it was given,
//      REMOVES the password, is refused once expired, and sends
//      credential-change (password, revoke) and
//      account-credential-change-required.
//   3. OVER HTTP, /portal/reset-password draws the form for a good link,
//      answers one sentence for a bad one, refuses a mismatch, sets the
//      password, spends the link, and sends credential-change (password,
//      create, initiated by the user).
//   4. disable-primary-keys refuses somebody with no password, and otherwise
//      removes every primary key and only those, with a credential-change per
//      key.
//   5. disable-mfa removes the authenticator app, every mfa key and the
//      recovery codes, sends a credential-change per credential and RISC
//      recovery-information-changed, and refuses somebody holding none.
//   6. require-mfa / stop-requiring-mfa write the per-account requirement, and
//      the authentication policy's requireSecondFactor is the realm's.
//   7. OVER HTTP, a sign-in for somebody of whom a second factor is required
//      and who holds none is shown the set-up step with no session; a wrong
//      code keeps the step; the right one enrols the app and signs them in;
//      a passwordless sign-in under the requirement is refused; the realm
//      requirement reaches somebody with no flag; a security key choice draws
//      the ceremony; and with both mechanisms off the sign-in is refused.
// ===========================================================================

delete process.env.CONFIG_FILE;

const path = require('path');
const os = require('os');
const fs = require('fs');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'admin_credential_controls',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.ACC_ROOT;
  const OUT = process.env.ACC_OUT;
  const http = require('http');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  function request(port, method, urlPath, form, cookie) {
    return new Promise(function (resolve) {
      const body = form ? new URLSearchParams(form).toString() : '';
      const headers = {};
      if (cookie) {
        headers.cookie = cookie;
      }
      if (method !== 'GET') {
        headers['content-type'] = 'application/x-www-form-urlencoded';
        headers['content-length'] = Buffer.byteLength(body);
      }
      const req = http.request({ host: '127.0.0.1', port: port, path: urlPath,
                                 method: method, headers: headers },
                               function (res) {
        let text = '';
        res.on('data', function (c) { text += c; });
        res.on('end', function () {
          resolve({ status: res.statusCode, headers: res.headers,
                    text: text });
        });
      });
      req.end(body);
    });
  }

  function sleep(ms) {
    return new Promise(function (r) { setTimeout(r, ms); });
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const config = require(ROOT + '/common/config');
    const realms = require(ROOT + '/common/realms');
    const credentials = require(ROOT + '/common/credentials');
    const totp = require(ROOT + '/common/totp');
    const errorCodes = require(ROOT + '/common/error_codes');
    const ldapServer = require(ROOT + '/ldap/ldap_server');
    const streams = require(ROOT + '/ssf/ssf_streams');
    const risc = require(ROOT + '/ssf/risc');
    const actions = require(ROOT + '/admin-core/admin_actions');
    // #64: the realm-wide requirement and the authenticator-app switch are
    // the authentication policy's rows now (they were authn.mfaRequired and
    // totp.enabled).
    const authnPolicy = require(ROOT + '/common/authn_policy');
    const policyWith = function (fields) {
      const saved = authnPolicy.save('default',
        Object.assign({}, authnPolicy.DEFAULTS, fields));
      if (!saved.ok) {
        throw new Error('policy not saved: ' + JSON.stringify(saved.errors));
      }
    };

    const CAEP = 'https://schemas.openid.net/secevent/caep/event-type/';
    const RISC = 'https://schemas.openid.net/secevent/risc/event-type/';

    await realms.run(realms.DEFAULT_REALM, async function () {
      config.setOverride('ssf.enabled', 'true');
      config.setOverride('caep.enabled', 'true');
      config.setOverride('risc.enabled', 'true');
      const made = streams.createStream(
        { delivery: { method: streams.DELIVERY_POLL },
          events_requested: [CAEP + 'credential-change',
                             RISC + 'account-credential-change-required',
                             RISC + 'recovery-information-changed'] },
        { issuer: 'https://sts.test', principal: 'credential-probe',
          audience: 'https://receiver.test/credentials' });
      note(made.ok, '0. a poll stream asking for the three types is created',
           JSON.stringify(made.errors));
      const streamId = made.stream && made.stream.stream_id;

      // Every SET queued on the stream about one person so far — named in
      // `sub_id` by their NAME (an email or account subject) or by their
      // SUBJECT, which since 2026-09-14 is `urn:uuid:<entryUUID>` and is what
      // an iss_sub carries.
      const helpersC = require(ROOT + '/common/helpers');
      const setsAbout = function (username) {
        const record = streams.getStream(streamId);
        const subject = helpersC.subjectForName(username);
        return streams.queueOf(record).map(function (one) {
          return one.claims || {};
        }).filter(function (claims) {
          const text = JSON.stringify(claims.sub_id || {});
          return text.indexOf('"' + username + '"') >= 0 ||
                 (!!subject && text.indexOf('"' + subject + '"') >= 0);
        });
      };
      // Wait for `count` SETs about somebody, since signing is asynchronous.
      const waitFor = async function (username, count) {
        for (let i = 0; i < 100; i += 1) {
          if (setsAbout(username).length >= count) {
            break;
          }
          await sleep(50);
        }
        return setsAbout(username);
      };
      const payloadOf = function (claims, uri) {
        return (claims.events || {})[uri] || null;
      };
      const context = { via: 'api', actor: 'tester', base: 'https://sts.test' };

      // ====================================================================
      // 1. RESET PASSWORD
      // ====================================================================
      ldapServer.createUser('ctl-alice', {});
      credentials.setPassword('ctl-alice', 'Old-Pass-123!');
      const reset = actions.usersAction({ action: 'reset-password',
                                          user: 'ctl-alice' }, context);
      note(reset.ok && reset.password && reset.forcedChange,
           '1a. reset-password returns a generated password and records the ' +
           'forced change', JSON.stringify(reset.errors || []));
      note(credentials.passwordResetRequired('ctl-alice'),
           '1b. pwdReset is set on the entry');
      note(credentials.verify('ctl-alice', reset.password).ok,
           '1c. the returned password is the one stored');
      let sets = await waitFor('ctl-alice', 2);
      const change1 = sets.map(function (c) {
        return payloadOf(c, CAEP + 'credential-change');
      }).filter(Boolean)[0];
      note(change1 && change1.credential_type === 'password' &&
           change1.change_type === 'update',
           '1d. a CAEP credential-change (password, update) was queued',
           JSON.stringify(sets.map(function (c) {
             return Object.keys(c.events || {});
           })));
      note(sets.some(function (c) {
        return !!payloadOf(c, RISC + 'account-credential-change-required');
      }), '1e. and a RISC account-credential-change-required');
      note(risc.get('ctl-alice') &&
           risc.get('ctl-alice').credentialChangeRequired,
           '1f. the RISC register records the required change');

      // ====================================================================
      // 2. ISSUE A PASSWORD RESET LINK
      // ====================================================================
      const linked = actions.usersAction({ action: 'issue-password-reset',
                                           user: 'ctl-alice' }, context);
      const linkShape =
        /^https:\/\/sts\.test\/portal\/reset-password\?user=ctl-alice&token=./;
      note(linked.ok && linkShape.test(String(linked.resetUrl || '')),
           '2a. the reset link is absolute on the base the action was given',
           String(linked.resetUrl));
      note(linked.passwordRevoked && !credentials.hasPassword('ctl-alice'),
           '2b. the password the person had is REMOVED');
      note(!credentials.passwordResetRequired('ctl-alice'),
           '2c. and pwdReset is cleared, since there is no password to change');
      const token = decodeURIComponent(
        (String(linked.resetUrl).match(/token=([^&]+)/) || [])[1] || '');
      note(credentials.checkPasswordReset('ctl-alice', token).ok &&
           !credentials.checkPasswordReset('ctl-alice', token + 'x').ok,
           '2d. the token checks, and a different one does not');
      // THE CLOCK IS MOVED RATHER THAN WAITED FOR: the shortest lifetime the
      // setting allows is a minute.
      const realNow = Date.now;
      let expiredCheck;
      try {
        Date.now = function () {
          return realNow() + 2 * 60 * 60 * 1000;
        };
        expiredCheck = credentials.checkPasswordReset('ctl-alice', token);
      } finally {
        Date.now = realNow;
      }
      note(!expiredCheck.ok && expiredCheck.reason === 'expired',
           '2d2. the same token two hours later is refused as expired',
           JSON.stringify(expiredCheck));
      sets = await waitFor('ctl-alice', 4);
      note(sets.some(function (c) {
        const p = payloadOf(c, CAEP + 'credential-change');
        return p && p.change_type === 'revoke';
      }), '2e. a credential-change (password, revoke) was queued');

      // ====================================================================
      // 3. /portal/reset-password OVER HTTP
      // ====================================================================
      const server = http.createServer(app);
      await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
      const port = server.address().port;
      const resetPath = '/portal/reset-password';
      let r = await request(port, 'GET', resetPath + '?user=ctl-alice&token=' +
                            encodeURIComponent(token));
      note(r.status === 200 && /Choose a new password/.test(r.text),
           '3a. a good link draws the form', r.status);
      r = await request(port, 'GET', resetPath + '?user=ctl-alice&token=' +
                        encodeURIComponent(token.slice(0, -2) + 'zz'));
      note(r.status === 400 && /not valid/.test(r.text),
           '3b. a bad link answers the one sentence', r.status);
      r = await request(port, 'POST', resetPath,
        { user: 'ctl-alice', token: token, password: 'New-Pass-456!',
          confirm: 'Other-Pass-456!' });
      note(r.status === 400 && /do not match/.test(r.text),
           '3c. two different passwords are refused', r.status);
      r = await request(port, 'POST', resetPath,
        { user: 'ctl-alice', token: token, password: 'New-Pass-456!',
          confirm: 'New-Pass-456!' });
      note(r.status === 200 && /Your password is set/.test(r.text),
           '3d. a good password is set', r.status + ' ' + r.text.slice(0, 80));
      note(credentials.hasPassword('ctl-alice') &&
           !credentials.checkPasswordReset('ctl-alice', token).ok,
           '3e. the entry has a password and the link is spent');
      r = await request(port, 'POST', resetPath,
        { user: 'ctl-alice', token: token, password: 'New-Pass-789!',
          confirm: 'New-Pass-789!' });
      note(r.status === 400, '3f. the spent link is refused', r.status);
      sets = await waitFor('ctl-alice', 5);
      note(sets.some(function (c) {
        const p = payloadOf(c, CAEP + 'credential-change');
        return p && p.change_type === 'create' &&
               p.initiating_entity === 'user';
      }), '3g. a credential-change (password, create, by the user) was queued');

      // ====================================================================
      // 4. DISABLE PASSKEYS AS PRIMARY
      // ====================================================================
      ldapServer.createUser('ctl-bob', {});
      const jwk = { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' };
      credentials.addKey('ctl-bob', { credentialId: 'bob-primary',
        publicKeyJwk: jwk, label: 'desk key' }, 'primary');
      credentials.addKey('ctl-bob', { credentialId: 'bob-mfa',
        publicKeyJwk: jwk, label: 'drawer key' }, 'mfa');
      let refused = actions.usersAction({ action: 'disable-primary-keys',
                                          user: 'ctl-bob' }, context);
      note(!refused.ok && errorCodes.codeOf(refused) === 'STS-AUTHN-0161',
           '4a. refused for somebody whose primary key is their only way in',
           errorCodes.codeOf(refused));
      credentials.setPassword('ctl-bob', 'Bob-Pass-123!');
      const disabledKeys = actions.usersAction({ action: 'disable-primary-keys',
                                                 user: 'ctl-bob' }, context);
      const bobKeys = credentials.keysOf('ctl-bob');
      note(disabledKeys.ok && bobKeys.length === 1 &&
           bobKeys[0].role === 'mfa',
           '4b. every primary key goes and the mfa key stays',
           JSON.stringify(bobKeys.map(function (k) { return k.role; })));
      sets = await waitFor('ctl-bob', 1);
      note(sets.some(function (c) {
        const p = payloadOf(c, CAEP + 'credential-change');
        return p && p.credential_type === 'fido2-roaming' &&
               p.change_type === 'delete' && p.friendly_name === 'desk key';
      }), '4c. a credential-change (fido2-roaming, delete) names the key');

      // ====================================================================
      // 5. DISABLE ALL MFA
      // ====================================================================
      const begun = credentials.beginTotpEnrolment('ctl-bob', {});
      credentials.confirmTotpEnrolment('ctl-bob', totp.codeAt(begun.secret));
      const codes = credentials.beginBackupCodes('ctl-bob', {});
      credentials.confirmBackupCodes('ctl-bob', codes.handle);
      note(credentials.mechanismsFor('ctl-bob').totp &&
           credentials.mechanismsFor('ctl-bob').backupCodes.present,
           '5a. the fixture holds an app, an mfa key and recovery codes');
      const disabled = actions.usersAction({ action: 'disable-mfa',
                                             user: 'ctl-bob' }, context);
      const after = credentials.mechanismsFor('ctl-bob');
      note(disabled.ok && disabled.removed.totp &&
           disabled.removed.keys.length === 1 && disabled.removed.backupCodes &&
           !after.totp && after.mfaKeys === 0 && !after.backupCodes.present &&
           after.password,
           '5b. every second factor is removed and the password stays',
           JSON.stringify(disabled.removed));
      sets = await waitFor('ctl-bob', 4);
      note(sets.some(function (c) {
        const p = payloadOf(c, CAEP + 'credential-change');
        return p && p.credential_type === 'app' && p.change_type === 'delete';
      }), '5c. a credential-change (app, delete) was queued');
      note(sets.some(function (c) {
        return !!payloadOf(c, RISC + 'recovery-information-changed');
      }), '5d. and a RISC recovery-information-changed');
      refused = actions.usersAction({ action: 'disable-mfa', user: 'ctl-bob' },
                                    context);
      note(!refused.ok && errorCodes.codeOf(refused) === 'STS-AUTHN-0162',
           '5e. refused for somebody holding no second factor',
           errorCodes.codeOf(refused));

      // ====================================================================
      // 6. THE REQUIREMENT
      // ====================================================================
      ldapServer.createUser('ctl-carol', {});
      let required = actions.usersAction({ action: 'require-mfa',
                                           user: 'ctl-carol' }, context);
      note(required.ok &&
           credentials.mfaRequirementFor('ctl-carol').byUser &&
           !credentials.mfaRequirementFor('ctl-carol').byRealm,
           '6a. require-mfa writes the per-account requirement');
      required = actions.usersAction({ action: 'stop-requiring-mfa',
                                       user: 'ctl-carol' }, context);
      note(required.ok && !credentials.mfaRequirementFor('ctl-carol').required,
           '6b. stop-requiring-mfa takes it off');
      policyWith({ requireSecondFactor: 'always' });
      note(credentials.mfaRequirementFor('ctl-carol').byRealm,
           '6c. the authentication policy\'s requireSecondFactor is the ' +
           'realm\'s requirement');
      authnPolicy.reset('default');
      actions.usersAction({ action: 'require-mfa', user: 'ctl-carol' },
                          context);

      // ====================================================================
      // 7. THE SET-UP STEP AT SIGN-IN, OVER HTTP
      // ====================================================================
      const startSignIn = async function () {
        const got = await request(port, 'GET', '/oauth2/authorize?' +
          new URLSearchParams({ client_id: 'acc-client',
                                response_type: 'code',
                                redirect_uri: 'https://rp.acc.example/cb',
                                scope: 'openid', state: 's' }).toString());
        const location = String(got.headers.location || '');
        return (location.match(/[?&]authn=([^&]+)/) || [])[1] || '';
      };
      const cookieOf = function (res) {
        return [].concat(res.headers['set-cookie'] || []).map(function (one) {
          return String(one).split(';')[0];
        }).filter(function (one) { return /^sts_session=./.test(one); })[0] ||
          '';
      };
      let authnId = await startSignIn();
      r = await request(port, 'POST', '/authn/login',
        { authn_id: authnId, username: 'ctl-carol', password: 'anything',
          action: 'login' });
      const setupId = (r.text.match(/name="mfa_id" value="([^"]+)"/) ||
                       [])[1];
      note(r.status === 200 && /Set up a second factor/.test(r.text) &&
           setupId && !cookieOf(r),
           '7a. the sign-in draws the set-up step and starts no session',
           r.status + ' ' + r.text.slice(0, 120));
      r = await request(port, 'POST', '/authn/mfa-setup',
        { mfa_id: setupId, action: 'totp' });
      const shown = (r.text.match(/Or type it in: <code>([^<]+)<\/code>/) ||
                     [])[1] || '';
      const secret = shown.replace(/\s+/g, '');
      note(r.status === 200 && secret.length >= 16,
           '7b. choosing an app shows its secret', r.status);
      r = await request(port, 'POST', '/authn/mfa-setup',
        { mfa_id: setupId, action: 'confirm-totp', code: '000000' });
      note(r.status === 400 && /Scan this/.test(r.text) && !cookieOf(r),
           '7c. a wrong code keeps the step and the same secret', r.status);
      r = await request(port, 'POST', '/authn/mfa-setup',
        { mfa_id: setupId, action: 'confirm-totp',
          code: totp.codeAt(secret) });
      note((r.status === 302 || r.status === 303) && !!cookieOf(r) &&
           credentials.mechanismsFor('ctl-carol').totp,
           '7d. the right code enrols the app and signs them in',
           r.status + ' ' + String(r.headers.location));
      r = await request(port, 'POST', '/authn/mfa-setup',
        { mfa_id: setupId, action: 'confirm-totp',
          code: totp.codeAt(secret) });
      note(r.status === 400, '7e. the step is spent', r.status);

      authnId = await startSignIn();
      r = await request(port, 'POST', '/authn/login',
        { authn_id: authnId, username: 'ctl-carol', password: 'anything',
          action: 'login' });
      note(r.status === 200 && /one-time code/i.test(r.text) &&
           !/Set up a second factor/.test(r.text),
           '7f. once enrolled, the sign-in asks for the code, not a set-up',
           r.status);

      // A PRIMARY KEY FIRST, so that without the refusal this sign-in would
      // go on to a ceremony rather than be refused for having no key.
      credentials.addKey('ctl-carol', { credentialId: 'carol-primary',
        publicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' },
        label: 'carol key' }, 'primary');
      authnId = await startSignIn();
      r = await request(port, 'POST', '/authn/login',
        { authn_id: authnId, username: 'ctl-carol', webauthn_only: '1',
          action: 'login' });
      note(r.status === 200 &&
           /security key on\s+its own is one factor/.test(r.text) &&
           !/\/authn\/webauthn\.js/.test(r.text) &&
           !/Set up a second factor/.test(r.text) && !cookieOf(r),
           '7g. a passwordless sign-in under the requirement is refused',
           r.status + ' ' + r.text.slice(0, 100));

      ldapServer.createUser('ctl-dave', {});
      policyWith({ requireSecondFactor: 'always' });
      authnId = await startSignIn();
      r = await request(port, 'POST', '/authn/login',
        { authn_id: authnId, username: 'ctl-dave', password: 'anything',
          action: 'login' });
      const daveSetup = (r.text.match(/name="mfa_id" value="([^"]+)"/) ||
                         [])[1];
      note(r.status === 200 && /Set up a second factor/.test(r.text) &&
           daveSetup,
           '7h. the realm requirement reaches somebody with no flag',
           r.status);
      r = await request(port, 'POST', '/authn/mfa-setup',
        { mfa_id: daveSetup, action: 'webauthn' });
      note(r.status === 200 && /\/authn\/webauthn\.js/.test(r.text),
           '7i. choosing a security key draws the ceremony', r.status);

      policyWith({ requireSecondFactor: 'always', totpSecondFactor: false });
      config.setOverride('webauthn.enabled', 'false');
      authnId = await startSignIn();
      r = await request(port, 'POST', '/authn/login',
        { authn_id: authnId, username: 'ctl-dave', password: 'anything',
          action: 'login' });
      note(r.status === 200 && /switched\s+off/.test(r.text) &&
           !cookieOf(r),
           '7j. with both mechanisms off the sign-in is refused, not let ' +
           'through', r.status + ' ' + r.text.slice(0, 100));
      config.clearOverride('webauthn.enabled');
      authnPolicy.reset('default');

      // ====================================================================
      // 8. ENROLMENT IN PRODUCT MODE (2026-09-18)
      // ====================================================================
      // Both enrolments asked the wrong "does this person exist": TOTP asked
      // `hasEntry()`, which is always false, so product refused every
      // authenticator app; security keys asked a key-store read that is true
      // for anybody, so product enrolled keys for nobody. Found by the
      // protocol suite against a product-mode deployment.
      ldapServer.createUser('ctl-erin', {});
      config.setOverride('global.mode', 'product');
      try {
        const erinTotp = credentials.beginTotpEnrolment('ctl-erin', {});
        note(erinTotp.ok, '8a. product mode enrols an authenticator app ' +
             'for somebody who exists', JSON.stringify(erinTotp.errors));
        const ghost = 'ctl-nobody-' + Date.now();
        const ghostTotp = credentials.beginTotpEnrolment(ghost, {});
        note(!ghostTotp.ok &&
             errorCodes.codeOf(ghostTotp) === 'STS-AUTHN-0024',
             '8b. and refuses one for a name nobody created',
             JSON.stringify(ghostTotp));
        const erinKey = credentials.beginKeyEnrolment('ctl-erin',
                                                      { role: 'mfa' });
        note(erinKey.ok, '8c. it begins a security key enrolment for ' +
             'somebody who exists', JSON.stringify(erinKey.errors));
        const ghostKey = credentials.beginKeyEnrolment(ghost, { role: 'mfa' });
        note(!ghostKey.ok &&
             errorCodes.codeOf(ghostKey) === 'STS-AUTHN-0024',
             '8d. and refuses one for a name nobody created',
             JSON.stringify(ghostKey));

        // A CLIENTLESS RFC 7523 GRANT REACHES THE ASSERTION CHECK (2026-09-18).
        // Product mode's client check refused it as an unknown client —
        // `invalid_client`, 401 — before the assertion was looked at, though
        // RFC 7521 section 4.1 makes client authentication optional there.
        // An assertion from an issuer nobody declared must be refused FOR
        // THAT: `invalid_grant`, 400.
        const nodeCrypto = require('crypto');
        const pair = nodeCrypto.generateKeyPairSync('rsa',
                                                    { modulusLength: 2048 });
        const b64 = function (o) {
          return Buffer.from(JSON.stringify(o)).toString('base64url');
        };
        const now = Math.floor(Date.now() / 1000);
        const input = b64({ alg: 'RS256', typ: 'JWT' }) + '.' +
          b64({ iss: 'undeclared-' + now, sub: 'ctl-erin',
                aud: 'http://127.0.0.1:' + port + '/oauth2/token',
                iat: now, exp: now + 120, jti: 'j-' + now });
        const jwt = input + '.' + nodeCrypto.sign('sha256',
          Buffer.from(input), pair.privateKey).toString('base64url');
        const grant = await request(port, 'POST', '/oauth2/token',
          { grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            assertion: jwt });
        note(grant.status === 400 && /invalid_grant/.test(grant.text),
             '8e. a clientless assertion grant is judged on its assertion ' +
             '(invalid_grant), not refused as an unknown client',
             grant.status + ' ' + grant.text.slice(0, 200));
      } finally {
        config.clearOverride('global.mode');
      }
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
  const out = path.join(os.tmpdir(), 'admin-credential-controls-' +
                        process.pid + '-' +
                        require('crypto').randomBytes(8).toString('hex') +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|ADMIN_|CONFIG_FILE$)/
        .test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', ACC_ROOT: ROOT,
                                  ACC_OUT: out }),
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
  name: 'admin credential controls',
  describe: 'password reset, reset links, disabling passkeys and MFA, the ' +
            'second-factor requirement and its sign-in enrolment, and the ' +
            'CAEP and RISC events each sends',
  run: run
};
