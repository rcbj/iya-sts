'use strict';

// ===========================================================================
// tests/admin_bootstrap.js — THE BOOTSTRAP ADMINISTRATOR (2026-09-13).
//
// `admin.bootstrapUsername` in the default realm: seeded at startup into both
// console roles, forced to change its password at the sign-in screen, the
// account whose first console sign-in ends the window in which every
// signed-in person may use the console, and impossible to delete.
//
// In a CHILD PROCESS, for `oauth_oid4vc_hardcoded.js`'s reason: it loads the
// whole protocol stack, flips `global.mode`, and seeds a default realm that
// every other file in `run.js`'s one process shares — a seeded roster left
// behind would change what the empty-roster tests elsewhere mean.
//
// The claims:
//
//   1. Seeding makes the account, puts it in both groups and flags pwdReset;
//      a second seed changes nothing.
//   2. Until it signs in to the console, a person holding no role is OPEN;
//      the account itself holds both roles by membership.
//   3. A sign-in through another realm does not close the window; the
//      default realm's does, and a person holding no role is then refused.
//   4. A roster that already names somebody else is not re-opened by seeding.
//   5. The account cannot be deleted in the default realm; an ordinary person
//      can, and a trust realm's `admin` is an ordinary person there.
//   6. PRODUCT MODE: a correct password flagged pwdReset is refused at a door
//      that cannot ask for a new one, and accepted where it can.
//   7. OVER HTTP: the sign-in screen draws the change step before any session,
//      refuses a mismatch, and a new password resumes the sign-in and clears
//      the flag — and in product mode the password policy applies.
//
// The console's own sign-in over the authorization code flow needs the
// service's real port for its back channel; it was driven against an isolated
// instance by hand, and is not repeated here.
// ===========================================================================

delete process.env.CONFIG_FILE;

const path = require('path');
const os = require('os');
const fs = require('fs');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'admin_bootstrap',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.AB_ROOT;
  const OUT = process.env.AB_OUT;
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

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const config = require(ROOT + '/common/config');
    const realms = require(ROOT + '/common/realms');
    const rbac = require(ROOT + '/admin-ui/admin_rbac');
    const credentials = require(ROOT + '/common/credentials');
    const ldapServer = require(ROOT + '/ldap/ldap_server');

    const inDefault = function (fn) {
      return realms.run(realms.DEFAULT_REALM, fn);
    };

    // ======================================================================
    // 8. A BOOTSTRAP PASSWORD THE OPERATOR SUPPLIED (2026-09-17) — a child of
    // its own, because it needs product mode BEFORE anything has a
    // credential, which is the one moment `bootstrap()` acts in, and the
    // parts above give the default realm an administrator.
    //
    // The claims are the three the setting makes: the configured value is
    // what the account gets, the log does NOT carry it, and a value the
    // password policy refuses is refused rather than quietly replaced with a
    // generated one.
    // ======================================================================
    if (process.env.AB_PART === 'configured') {
      config.setOverride('global.mode', 'product');

      // WHAT THE PROCESS PRINTED WHILE THE BOOTSTRAP RAN. bunyan writes to
      // stdout, so this is the whole of what an operator would find in
      // CloudWatch — which is exactly the claim being tested, and it cannot
      // be tested by asking the function what it returned.
      let printed = '';
      const realWrite = process.stdout.write.bind(process.stdout);
      process.stdout.write = function (chunk) {
        printed += String(chunk);
        return true;
      };
      let ran;
      try {
        ran = inDefault(function () {
          return credentials.bootstrap({ username: 'admin' });
        });
      } finally {
        // Restored in a `finally` so that a throw inside the bootstrap does
        // not leave this child unable to report anything at all.
        process.stdout.write = realWrite;
      }
      // Read from the SETTING and not from the environment variable behind
      // it: what section 8a claims is that the account gets what the service
      // was configured with.
      const supplied = String(config.value('admin.bootstrapPassword') || '');
      const verified = inDefault(function () {
        return credentials.verify('admin', supplied,
                                  { via: 'the sign-in screen',
                                    allowPasswordReset: true });
      });
      note(ran.ran === true && ran.supplied === true && verified.ok === true,
           '8a. the configured password is what the bootstrap account gets',
           JSON.stringify([ran, verified.ok, verified.reason]));
      note(printed.indexOf(supplied) === -1 && printed.length > 0,
           '8b. and it is NOT printed — the log says where it came from and ' +
           'not what it is',
           JSON.stringify({ printedChars: printed.length,
                            carriesIt: printed.indexOf(supplied) !== -1 }));
      note(printed.indexOf('admin.bootstrapPassword') !== -1,
           '8c. the announcement names the setting, so a reader knows where ' +
           'to look for the value');

      require('fs').writeFileSync(OUT, JSON.stringify(findings));
      process.exit(0);
    }

    // ======================================================================
    // 9. A CONFIGURED PASSWORD THE POLICY REFUSES (2026-09-17) — a child of
    // its own because the setting is RESTART-ONLY: it is read once, at the
    // one moment the bootstrap acts, so an override set while running is a
    // value nothing reads. The first attempt at this section set one and
    // measured the previous child's password instead.
    // ======================================================================
    if (process.env.AB_PART === 'refused') {
      config.setOverride('global.mode', 'product');
      let printed = '';
      const realWrite = process.stdout.write.bind(process.stdout);
      process.stdout.write = function (chunk) {
        printed += String(chunk);
        return true;
      };
      let refused;
      try {
        refused = inDefault(function () {
          return credentials.bootstrap({ username: 'admin' });
        });
      } finally {
        process.stdout.write = realWrite;
      }
      const weak = String(config.value('admin.bootstrapPassword') || '');
      const nobody = inDefault(function () {
        return credentials.verify('admin', weak,
                                  { via: 'the sign-in screen',
                                    allowPasswordReset: true });
      });
      note(refused.ran === false && nobody.ok !== true,
           '9a. a configured password the policy refuses creates no account',
           JSON.stringify([refused, nobody.ok, nobody.reason]));
      note(printed.indexOf('STS-AUTHN-0205') !== -1,
           '9b. and says so under its own error code',
           JSON.stringify({ printedChars: printed.length }));
      note(printed.indexOf('SHOWN ONCE AND NEVER AGAIN') === -1,
           '9c. and NOT by generating one instead — which would put a ' +
           'working credential in the log of a deployment that asked for it ' +
           'not to be there');
      require('fs').writeFileSync(OUT, JSON.stringify(findings));
      process.exit(0);
    }

    // ======================================================================
    // 4. AN ALREADY-ADMINISTERED ROSTER IS NOT RE-OPENED — a child of its own,
    // because it needs a default realm in which somebody held a role BEFORE
    // anything was seeded, and `admin.bootstrapUsername` is restart-only.
    // ======================================================================
    if (process.env.AB_PART === 'administered') {
      inDefault(function () {
        return rbac.grant('operator-ab', 'write', { via: 'test' });
      });
      const administered = inDefault(function () {
        return rbac.seedBootstrapAdministrator();
      });
      note(administered.ran && administered.created &&
           administered.windowClosed &&
           inDefault(function () { return rbac.rolesOf('admin').write; }) &&
           !inDefault(function () {
             return rbac.rolesOf('stranger-ab').open;
           }) &&
           !!inDefault(function () { return rbac.bootstrapState().claimedAt; }),
           '4a. seeding over a roster that names somebody else gives the ' +
           'account both roles and does not open the console',
           JSON.stringify(administered));
      require('fs').writeFileSync(OUT, JSON.stringify(findings));
      process.exit(0);
    }

    // ======================================================================
    // 1. SEEDING
    // ======================================================================
    const seeded = inDefault(function () {
      return rbac.seedBootstrapAdministrator();
    });
    const state = inDefault(function () { return rbac.bootstrapState(); });
    note(seeded.ran && seeded.created && state.seeded && !state.claimedAt,
         '1a. the bootstrap administrator is created and marked seeded',
         JSON.stringify([seeded, state]));
    const adminRoles = inDefault(function () { return rbac.rolesOf('admin'); });
    note(adminRoles.read && adminRoles.write && !adminRoles.open,
         '1b. it holds both roles by membership, not by the open console',
         JSON.stringify(adminRoles));
    note(inDefault(function () {
      return credentials.passwordResetRequired('admin');
    }), '1c. and its password must be changed (pwdReset)');
    const again = inDefault(function () {
      return rbac.seedBootstrapAdministrator();
    });
    note(again.ran && !again.created && !again.windowClosed,
         '1d. a second seed creates nothing and closes nothing',
         JSON.stringify(again));

    // ======================================================================
    // 2. OPEN UNTIL IT SIGNS IN
    // ======================================================================
    const visitor = inDefault(function () {
      return rbac.rolesOf('visitor-ab');
    });
    note(visitor.open && visitor.read && visitor.write,
         '2a. a person holding no role may use the console while it has not ' +
         'signed in, although the roster is not empty',
         JSON.stringify(visitor));
    note(inDefault(function () { return rbac.describe().openToAnyone; }),
         '2b. and the roster view reports the console open to anyone');

    // ======================================================================
    // 3. THE CLAIM
    // ======================================================================
    const viaRealm = inDefault(function () {
      return rbac.noteConsoleSignIn('admin', { derivedFromRealm: 'acme' },
                                    realms.DEFAULT_ID);
    });
    const viaOther = inDefault(function () {
      return rbac.noteConsoleSignIn('visitor-ab', {}, realms.DEFAULT_ID);
    });
    note(!viaRealm && !viaOther &&
         inDefault(function () { return rbac.rolesOf('visitor-ab').open; }),
         '3a. a sign-in through another realm, or by anybody else, does not ' +
         'close the window', JSON.stringify([viaRealm, viaOther]));
    const claimed = inDefault(function () {
      return rbac.noteConsoleSignIn('admin', {}, realms.DEFAULT_ID);
    });
    const after = inDefault(function () { return rbac.rolesOf('visitor-ab'); });
    note(claimed && !after.open && !after.read && !after.write,
         '3b. the default realm\'s own sign-in closes it, and a person holding ' +
         'no role is then refused', JSON.stringify([claimed, after]));
    note(inDefault(function () {
      return rbac.rolesOf('admin').write && !rbac.describe().openToAnyone;
    }), '3c. the administrator keeps its roles and the view reports it closed');
    const reseed = inDefault(function () {
      return rbac.seedBootstrapAdministrator();
    });
    note(!reseed.ran, '3d. a seed after the claim leaves it alone',
         JSON.stringify(reseed));

    // ======================================================================
    // 5. IT CANNOT BE DELETED
    // ======================================================================
    const adminDn = inDefault(function () { return rbac.bootstrapState().dn; });
    const refusedDelete = inDefault(function () {
      return ldapServer.deletePerson(adminDn);
    });
    note(refusedDelete.ok === false && refusedDelete.reason === 'protected' &&
         !!inDefault(function () { return rbac.bootstrapState().dn; }),
         '5a. the default realm\'s bootstrap administrator is not deleted',
         JSON.stringify(refusedDelete));
    inDefault(function () { return ldapServer.createUser('plain-ab', {}); });
    const plainDelete = inDefault(function () {
      return ldapServer.deletePerson('uid=plain-ab,' + ldapServer.usersDn());
    });
    note(plainDelete.ok === true, '5b. an ordinary person still is',
         JSON.stringify(plainDelete));
    realms.create({ id: 'abrealm' });
    const realmAdmin = realms.run(realms.get('abrealm'), function () {
      ldapServer.createUser('admin', {});
      return ldapServer.deletePerson('uid=admin,' + ldapServer.usersDn());
    });
    note(realmAdmin.ok === true,
         '5c. a trust realm\'s own "admin" is an ordinary person there',
         JSON.stringify(realmAdmin));

    // ======================================================================
    // 6. PRODUCT MODE: A FLAGGED PASSWORD AT A DOOR THAT CANNOT ASK
    // ======================================================================
    config.setOverride('global.mode', 'product');
    const strong = 'Bootstrap-Strong-Pass-9!';
    const set = inDefault(function () {
      return credentials.setPassword('admin', strong, { generated: true });
    });
    inDefault(function () {
      return credentials.setPasswordResetRequired('admin', true);
    });
    const atBind = inDefault(function () {
      return credentials.verify('admin', strong, { via: 'an LDAP bind' });
    });
    const atScreen = inDefault(function () {
      return credentials.verify('admin', strong,
                                { via: 'the sign-in screen',
                                  allowPasswordReset: true });
    });
    note(set.ok && atBind.ok === false &&
         atBind.reason === 'password-reset-required' && atScreen.ok === true,
         '6a. product: a right password flagged pwdReset is refused at a door ' +
         'that cannot ask for a new one and accepted at the sign-in screen',
         JSON.stringify([set.ok, atBind, atScreen.reason]));
    const wrong = inDefault(function () {
      return credentials.verify('admin', 'not-it', { via: 'an LDAP bind' });
    });
    note(wrong.reason === 'wrong-password',
         '6b. and a wrong password is still just a wrong password',
         wrong.reason);

    // ======================================================================
    // 7. THE CHANGE STEP, OVER HTTP
    // ======================================================================
    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;

    // PKCE ON EVERY REQUEST, INCLUDING THE DEVELOPMENT ONES (2026-09-17).
    // `ab-client` is never registered here — development mode creates it
    // because it was named — so this service cannot see it to be confidential
    // and RFC 9700 section 2.1.1 requires PKCE of it. Product mode enforces
    // the BCP since public clients were allowed (`common/mode.js`,
    // `enforcesOauthSecurityBcp()`), so without this the product half of
    // section 7 got no `authn` id at all and failed at the step after.
    // Sending it in both modes keeps ONE helper rather than two that differ
    // in the parameter the mode is about.
    const VERIFIER = 'ab-verifier-0123456789-0123456789-0123456789';
    const CHALLENGE = require('crypto').createHash('sha256')
      .update(VERIFIER).digest('base64')
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const startSignIn = async function () {
      const r = await request(port, 'GET', '/oauth2/authorize?' +
        new URLSearchParams({ client_id: 'ab-client', response_type: 'code',
                              redirect_uri: 'https://rp.ab.example/cb',
                              scope: 'openid', state: 's',
                              code_challenge: CHALLENGE,
                              code_challenge_method: 'S256' }).toString());
      const location = String(r.headers.location || '');
      return (location.match(/[?&]authn=([^&]+)/) || [])[1] || '';
    };
    const cookieOf = function (r) {
      return [].concat(r.headers['set-cookie'] || []).map(function (one) {
        return String(one).split(';')[0];
      }).filter(function (one) { return /^sts_session=./.test(one); })[0] ||
        '';
    };

    // Development first: any password, the change page, a mismatch, success.
    config.clearOverride('global.mode');
    let authnId = await startSignIn();
    let r = await request(port, 'POST', '/authn/login',
      { authn_id: authnId, username: 'admin', password: 'anything-at-all',
        action: 'login' });
    const changeId = (r.text.match(/name="change_id" value="([^"]+)"/) ||
                      [])[1];
    note(r.status === 200 && /Choose a new password/.test(r.text) &&
         changeId && !cookieOf(r),
         '7a. the sign-in screen draws the change step and starts no session',
         r.status + ' ' + r.text.slice(0, 120));
    r = await request(port, 'POST', '/authn/password-change',
      { change_id: changeId, new_password: 'one-Pass-1!',
        confirm_password: 'two-Pass-1!' });
    note(r.status === 200 && /not the same/.test(r.text),
         '7b. two different passwords are refused and the step kept',
         r.status);
    r = await request(port, 'POST', '/authn/password-change',
      { change_id: changeId, new_password: 'invalid',
        confirm_password: 'invalid' });
    note(r.status === 200 && /reserved/.test(r.text),
         '7c. the reserved refusal password is refused', r.status);
    r = await request(port, 'POST', '/authn/password-change',
      { change_id: changeId, new_password: 'Chosen-Pass-42!',
        confirm_password: 'Chosen-Pass-42!' });
    note((r.status === 302 || r.status === 303) && !!cookieOf(r) &&
         /\/oauth2\/authorize/.test(String(r.headers.location || '')) &&
         !inDefault(function () {
           return credentials.passwordResetRequired('admin');
         }),
         '7d. a new password resumes the sign-in, starts the session and ' +
         'clears pwdReset', r.status + ' ' + r.headers.location);
    r = await request(port, 'POST', '/authn/password-change',
      { change_id: changeId, new_password: 'Chosen-Pass-42!',
        confirm_password: 'Chosen-Pass-42!' });
    note(r.status === 400, '7e. the step is spent', r.status);

    // Product: the policy decides what a new password may be.
    //
    // AND THE REDIRECT URI IS REGISTERED FIRST (2026-09-17). Product mode
    // enforces RFC 9700 since it began allowing public clients, and section
    // 2.1 compares a redirect_uri by exact string against the ones REGISTERED
    // for the client. `ab-client` is never registered — development mode made
    // it because it was named — so in product mode its redirect URI matched
    // nothing and the authorization endpoint refused it before any sign-in.
    // That is the rule working; what this section tests is the change step,
    // so the URI is registered the way the refusal itself says to.
    config.setOverride('global.mode', 'product');
    config.setOverride('oauth2.redirectUris', ['https://rp.ab.example/cb']);
    inDefault(function () {
      credentials.setPassword('admin', strong, { generated: true });
      return credentials.setPasswordResetRequired('admin', true);
    });
    authnId = await startSignIn();
    r = await request(port, 'POST', '/authn/login',
      { authn_id: authnId, username: 'admin', password: 'wrong-one',
        action: 'login' });
    note(r.status === 200 && !/Choose a new password/.test(r.text),
         '7f. product: a wrong password never reaches the change step',
         r.status);
    authnId = await startSignIn();
    r = await request(port, 'POST', '/authn/login',
      { authn_id: authnId, username: 'admin', password: strong,
        action: 'login' });
    const productChange = (r.text.match(/name="change_id" value="([^"]+)"/) ||
                           [])[1];
    r = await request(port, 'POST', '/authn/password-change',
      { change_id: productChange, new_password: 'short',
        confirm_password: 'short' });
    note(productChange && r.status === 200 &&
         /Choose a new password/.test(r.text) && !cookieOf(r),
         '7g. product: the password policy refuses a weak new password on the ' +
         'change page', r.status + ' ' + r.text.slice(0, 80));
    config.clearOverride('global.mode');
    config.clearOverride('oauth2.redirectUris');

    server.close();
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child ran to the end',
                    detail: e && e.stack });
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function inAChild(t, part, extra) {
  log.debug("Entering inAChild(). part=" + part);
  const out = path.join(os.tmpdir(), 'admin-bootstrap-' + process.pid + '-' +
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
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', AB_ROOT: ROOT, AB_OUT: out,
                           AB_PART: part,
                           // tests/run.js turns the Pwned Passwords screen
                           // off for the whole run, and the strip above took
                           // that away: a product-mode child setting a
                           // password dialled api.pwnedpasswords.com.
                           STS_RISK_BREACH_CHECK: 'off' },
                         // The `clean` copy above strips every STS_ and
                         // ADMIN_ variable, which is what keeps one part's
                         // settings out of the next; a part that needs one
                         // passes it here, after the strip.
                         extra || {}),
      encoding: 'utf8', timeout: 180000, cwd: ROOT
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
  if (!t.check(Array.isArray(findings), 'the ' + part + ' child process ' +
                                        'reported its findings',
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

// A password that satisfies the default policy — twelve characters, an
// uppercase letter, a digit and a symbol — because the point of section 8 is
// what happens to a value the policy ACCEPTS. Section 8d supplies one it does
// not.
const SUPPLIED = 'Secrets-Manager-Put-This-Here-7!';

async function run(t) {
  log.debug("Entering run().");
  inAChild(t, 'main');
  inAChild(t, 'administered');
  // `info` and not the `fatal` the other two run at: section 8b asserts what
  // the bootstrap PRINTS, and a child whose service logger is silenced would
  // pass it without testing anything.
  inAChild(t, 'configured', { STS_LOG_LEVEL: 'info',
                              STS_ADMIN_BOOTSTRAP_PASSWORD: SUPPLIED });
  // `short` breaks three of the four default rules at once (length, an
  // uppercase letter, a digit) and is the shape of the mistake somebody makes
  // when they put a placeholder in a secret store.
  inAChild(t, 'refused', { STS_LOG_LEVEL: 'info',
                           STS_ADMIN_BOOTSTRAP_PASSWORD: 'short' });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'bootstrap administrator',
  describe: 'the default realm\'s admin account: seeded into both roles, ' +
            'forced password change, the open console until it signs in, ' +
            'undeletable, and a bootstrap password an operator supplied ' +
            'rather than one generated into the log',
  run: run
};
