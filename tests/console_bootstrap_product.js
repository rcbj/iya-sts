// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';

// ===========================================================================
// tests/console_bootstrap_product.js — PRODUCT MODE NEVER OPENS THE CONSOLE
// TO WHOEVER SIGNS IN, AND ITS BOOTSTRAP ADMINISTRATOR CLAIMS IT ONLY WITH ITS
// PASSWORD (2026-09-22, #103).
//
// Until that day a realm's bootstrap window — open until its `admin` first
// signed in to /admin, while `admin.openWhenEmpty` was on — gave BOTH console
// roles to anybody who signed in by any method, in both modes: a federation
// partner's assertion, a trusted certificate, a wallet, a Kerberos ticket. And
// the account `admin` itself could be signed in as by any of those doors, which
// inherited its roles by membership and claimed the console by arriving.
// `admin-ui/CLAUDE.md` 8a argues the fix; these are its claims, each one a
// state no request over HTTP can choose:
//
//   1. DEVELOPMENT KEEPS ITS WINDOW: a person holding no role is open, the
//      roster view says so, and any sign-in as `admin` claims it.
//   2. A REALM IN PRODUCT MODE IS PRODUCT WHERE THE PROCESS IS NOT: the mode
//      is asked in the roster's realm.
//   3. PRODUCT NEVER OPENS IT, with `admin.openWhenEmpty` still on: a person
//      holding no role holds nothing, `withheld` says why, and the roster view
//      says a password is required of the bootstrap administrator.
//   4. WHAT A PASSWORD SIGN-IN IS: `pwd` in the amr, not `federated`, and a
//      sign-on session this service vouched for.
//   5. THE CLAIM: a federated, Kerberos, certificate or wallet sign-in as
//      `admin` claims nothing; a password sign-in through its own realm does.
//   6. THE OTHER DOORS AGREE: the debugger refuses the unclaimed account
//      (STS-DBG-0033) and a person holding no role; a portal session's
//      certificate-enrollment authority waits for the claim.
//   7. (THE CONSOLE'S GATE until the cutover, #446: the console has no gate
//      of its own now, and the claim at issuance is
//      `tests/console_claim_at_issuance.js`.)
//   8. THE UN-SEEDED PRODUCT REALM is closed to everybody and logs
//      STS-ADMIN-0798; a development realm and a seeded one log nothing.
//
// In a CHILD PROCESS, for `admin_bootstrap.js`'s reason: it loads the whole
// protocol stack, flips `global.mode` and writes rosters that every other file
// in `run.js`'s one process would otherwise meet. The same claims over the
// service's own port, against a running stack, are
// `tests/vendored/sts_console_bootstrap_product.js`.
// ===========================================================================

delete process.env.CONFIG_FILE;

const path = require('path');
const os = require('os');
const fs = require('fs');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'console_bootstrap_product',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  const ROOT = process.env.CB_ROOT;
  const OUT = process.env.CB_OUT;
  const fs = require('fs');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  // A response object that keeps what `setCookieHeader()` writes.
  function fakeRes() {
    const out = { cookie: '', req: null };
    out.set = function (name, value) {
      if (String(name).toLowerCase() === 'set-cookie') {
        out.cookie = String(value).split(';')[0];
      }
      return out;
    };
    return out;
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const config = require(ROOT + '/common/config');
    const realms = require(ROOT + '/common/realms');
    const rbac = require(ROOT + '/admin-ui/admin_rbac');
    const authn = require(ROOT + '/authn/authn');
    const debuggerAccess = require(ROOT + '/debugger/debugger_access');
    const enrollment = require(ROOT + '/common/cert_enrollment');
    const ldapServer = require(ROOT + '/ldap/ldap_server');

    const inRealm = function (id, fn) {
      return realms.run(realms.get(id) || realms.DEFAULT_REALM, fn);
    };
    const tag = String(process.pid);

    // ---------------------------------------------------------------------
    // 1. DEVELOPMENT KEEPS ITS WINDOW.
    // ---------------------------------------------------------------------
    const D = 'cbd' + tag;
    realms.create({ id: D, name: 'Development window' });
    rbac.seedBootstrapAdministrator(D);
    const devVisitor = rbac.rolesOf('visitor', D);
    note(devVisitor.open === true && devVisitor.write === true &&
         devVisitor.windowOpens === true,
         '1a. development: a person holding no role holds both while the ' +
         'bootstrap administrator has not signed in',
         JSON.stringify(devVisitor));
    const devView = rbac.describe(D);
    note(devView.openToAnyone === true && devView.windowOpens === true &&
         devView.bootstrapPasswordRequired === false,
         '1b. and the roster view says the console is open to anyone',
         JSON.stringify({ open: devView.openToAnyone,
                          windowOpens: devView.windowOpens,
                          pwd: devView.bootstrapPasswordRequired }));
    note(rbac.rolesOf('admin', D).claimPending === false,
         '1c. development marks no claim as pending');
    note(rbac.noteConsoleSignIn('admin',
           { derivedFromRealm: D, amr: ['swk'], signInAuthority: 'local' },
           realms.DEFAULT_ID) === true &&
         rbac.rolesOf('visitor', D).open === false,
         '1d. and ANY sign-in as `admin` claims it there, as it always did');

    // ---------------------------------------------------------------------
    // 2. A PRODUCT REALM IN A DEVELOPMENT PROCESS.
    // ---------------------------------------------------------------------
    const Q = 'cbq' + tag;
    const madeQ = realms.create({ id: Q, name: 'A product realm',
                                  overrides: { 'global.mode': 'product' } });
    if (madeQ && madeQ.ok) {
      rbac.seedBootstrapAdministrator(Q);
      const qVisitor = rbac.rolesOf('visitor', Q);
      note(qVisitor.open === false && qVisitor.windowOpens === false &&
           rbac.rolesOf('visitor', D).windowOpens === true,
           '2a. the mode is asked in the roster\'s realm: a product realm ' +
           'opens nothing while the process is in development',
           JSON.stringify(qVisitor));
    } else {
      note(false, '2a. a realm carrying global.mode could be created',
           JSON.stringify(madeQ));
    }

    // ---------------------------------------------------------------------
    // 3. PRODUCT NEVER OPENS IT.
    // ---------------------------------------------------------------------
    config.setOverride('global.mode', 'product');
    const P = 'cbp' + tag;
    realms.create({ id: P, name: 'Product window' });
    rbac.seedBootstrapAdministrator(P);
    inRealm(P, function () {
      ldapServer.createUser('visitor', {});
      return ldapServer.createUser('bystander', {});
    });
    note(!!config.value('admin.openWhenEmpty'),
         '3a. precondition: admin.openWhenEmpty is ON');
    const visitor = rbac.rolesOf('visitor', P);
    note(visitor.open === false && visitor.read === false &&
         visitor.write === false && visitor.roles.length === 0 &&
         visitor.openable === true && visitor.withheld === true,
         '3b. product: a person holding no role holds NOTHING while the ' +
         'window is unclaimed; openable and withheld say why',
         JSON.stringify(visitor));
    const view = rbac.describe(P);
    note(view.openToAnyone === false && view.windowOpens === false &&
         view.bootstrapPasswordRequired === true &&
         view.openWhenEmpty === true && view.closedToEveryone === false,
         '3c. the roster view says it is not open to anyone, and that the ' +
         'bootstrap administrator\'s password is required',
         JSON.stringify({ open: view.openToAnyone, opens: view.windowOpens,
                          pwd: view.bootstrapPasswordRequired,
                          closed: view.closedToEveryone }));
    const boot = rbac.rolesOf('admin', P);
    note(boot.write === true && boot.claimPending === true,
         '3d. the bootstrap account holds both roles by membership, with its ' +
         'claim pending', JSON.stringify(boot));

    // ---------------------------------------------------------------------
    // 4. WHAT A PASSWORD SIGN-IN IS.
    // ---------------------------------------------------------------------
    const cases = [
      [{ amr: ['pwd'], signInAuthority: 'local' }, true, 'the password screen'],
      [{ amr: ['pwd', 'otp'], signInAuthority: 'local' }, true,
       'a password and a second factor'],
      [{ amr: ['pwd'], signInAuthority: 'kerberos' }, false,
       'SPNEGO with a pre-authenticated ticket'],
      [{ amr: ['federated', 'pwd'], signInAuthority: 'federation' }, false,
       'a federation partner that says it checked a password'],
      [{ amr: ['federated', 'pwd'], signInAuthority: 'local' }, false,
       'a federated amr, whatever the authority'],
      [{ amr: ['swk'], signInAuthority: 'local' }, false,
       'a client certificate'],
      [{ amr: ['pop', 'hwk'], signInAuthority: 'local' }, false, 'a wallet'],
      [{ amr: ['hwk'], signInAuthority: 'local' }, false,
       'a passwordless security key'],
      [{ amr: ['pwd'] }, false, 'a session with no recorded authority'],
      [null, false, 'no session']
    ];
    cases.forEach(function (one) {
      note(rbac.passwordSignIn(one[0]) === one[1],
           '4. passwordSignIn(): ' + one[2] + ' is ' +
           (one[1] ? '' : 'NOT ') + 'a password sign-in',
           JSON.stringify(one[0]));
    });

    // ---------------------------------------------------------------------
    // 5. THE CLAIM.
    // ---------------------------------------------------------------------
    const notPasswords = cases.filter(function (one) {
      return one[0] && !one[1];
    });
    const claimedByOther = notPasswords.map(function (one) {
      return rbac.noteConsoleSignIn('admin',
        Object.assign({ derivedFromRealm: P }, one[0]), realms.DEFAULT_ID);
    });
    note(claimedByOther.every(function (c) { return c === false; }) &&
         !rbac.bootstrapState(P).claimedAt,
         '5a. a federated, Kerberos, certificate, wallet or passwordless ' +
         'sign-in as `admin` claims nothing in product',
         JSON.stringify(claimedByOther));
    note(rbac.noteConsoleSignIn('admin',
           { derivedFromRealm: D, amr: ['pwd'], signInAuthority: 'local' },
           realms.DEFAULT_ID) === false && !rbac.bootstrapState(P).claimedAt,
         '5b. nor does a password sign-in through ANOTHER realm');

    // ---------------------------------------------------------------------
    // 6. THE OTHER DOORS AGREE — the debugger in the default realm, whose
    // bootstrap account is seeded here, and enrollment in P.
    // ---------------------------------------------------------------------
    rbac.seedBootstrapAdministrator();
    const dbgAdmin = inRealm(realms.DEFAULT_ID, function () {
      return debuggerAccess.isAdministrator({ kind: 'user', name: 'admin',
                                              authenticated: true });
    });
    note(dbgAdmin.allowed === false && dbgAdmin.code === 'STS-DBG-0033',
         '6a. the debugger refuses the unclaimed bootstrap administrator ' +
         '(STS-DBG-0033)', JSON.stringify(dbgAdmin));
    const dbgNarrowed = inRealm(realms.DEFAULT_ID, function () {
      return debuggerAccess.narrowScope('openid ' +
        debuggerAccess.PERMISSION_ID,
        { kind: 'user', name: 'admin', authenticated: true },
        { clientId: 'sts-debugger-ui', grant: 'authorization_code' });
    });
    note(dbgNarrowed === 'openid',
         '6b. and takes the permission off its grant', dbgNarrowed);
    const dbgVisitor = inRealm(realms.DEFAULT_ID, function () {
      return debuggerAccess.isAdministrator({ kind: 'user',
                                              name: 'cb-visitor-' + tag,
                                              authenticated: true });
    });
    note(dbgVisitor.allowed === false && dbgVisitor.code === 'STS-DBG-0009',
         '6c. and a person holding no role is refused for holding none, not ' +
         'for an open window', JSON.stringify(dbgVisitor));
    note(inRealm(P, function () {
      return enrollment.sessionIsAdmin('admin');
    }) === false,
         '6d. a portal session as the unclaimed `admin` is not an enrollment ' +
         'administrator');

    // ---------------------------------------------------------------------
    // 7. THE GATE, OVER A LOOPBACK SOCKET.
    // ---------------------------------------------------------------------
    // SECTION 7 TESTED THE CONSOLE'S GATE — a console session as `admin`
    // refused `bootstrap_password_required` on a certificate or a partner's
    // assertion, let in and claiming on a password — and the gate is gone
    // since the cutover (#446): the console is a static client of
    // `/admin-api`, and the claim is made where its client is issued the
    // admin scopes. `tests/console_claim_at_issuance.js` holds the same
    // cases there.


    // ---------------------------------------------------------------------
    // 8. THE UN-SEEDED PRODUCT REALM.
    // ---------------------------------------------------------------------
    const U = 'cbu' + tag;
    realms.create({ id: U, name: 'Nobody seeded' });
    const unseeded = rbac.rolesOf('visitor', U);
    note(unseeded.open === false && rbac.describe(U).closedToEveryone === true,
         '8a. a product realm with no bootstrap administrator and an empty ' +
         'roster is closed to everybody', JSON.stringify(unseeded));
    let printed = '';
    const realWrite = process.stdout.write.bind(process.stdout);
    process.stdout.write = function (chunk) {
      printed += String(chunk);
      return true;
    };
    let said;
    let saidSeeded;
    let saidDev;
    try {
      said = rbac.reportClosedConsole(U);
      saidSeeded = rbac.reportClosedConsole(P);
      config.clearOverride('global.mode');
      saidDev = rbac.reportClosedConsole(U);
    } finally {
      // Restored in a `finally` so that a throw above cannot leave this child
      // unable to report anything at all.
      process.stdout.write = realWrite;
    }
    note(said === true && printed.indexOf('STS-ADMIN-0798') >= 0 &&
         printed.indexOf(U) >= 0,
         '8b. and says so at startup, at error level, under STS-ADMIN-0798',
         JSON.stringify({ said: said, chars: printed.length }));
    note(saidSeeded === false && saidDev === false,
         '8c. a seeded product realm and a development realm say nothing',
         JSON.stringify({ seeded: saidSeeded, dev: saidDev }));

    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child ran to the end',
                    detail: e && e.stack });
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function inAChild(t) {
  log.debug("Entering inAChild().");
  const out = path.join(os.tmpdir(), 'console-bootstrap-product-' +
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
      // `info`, and not the `fatal` a quieter child would run at: section 8
      // asserts what the report PRINTS, and a silenced logger would pass it
      // without testing anything.
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'info',
                                  CB_ROOT: ROOT, CB_OUT: out }),
      encoding: 'utf8', timeout: 240000, cwd: ROOT,
      maxBuffer: 256 * 1024 * 1024
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
  name: 'console bootstrap window in product mode',
  describe: 'product never opens the console to whoever signs in; the ' +
            'bootstrap administrator claims it only with a password; the ' +
            'gate, the debugger and enrollment agree; development keeps its ' +
            'window; an un-seeded product realm logs STS-ADMIN-0798',
  run: run
};
