// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/reserved_password_refusal.js
// ===========================================================================
// THE RESERVED PASSWORD `invalid` IS REFUSED OVER AN LDAP BIND AND A WS-TRUST
// USERNAMETOKEN, IN BOTH MODES (#412, 2026-10-02).
//
// Development mode checks no password, so one literal is refused at every
// door that takes one — `common/credentials.ts`'s `RESERVED_REFUSAL`, and the
// LDAP bind's own copy (`ldap/ldap_server.js`'s `REFUSED_PASSWORD`) in front
// of it — so that a client has a refusal to be tested against without
// anything being configured. Both are refused in product too, and that is
// argued beside the LDAP copy: it can only turn a bind that would have been
// verified into a refusal, so nobody can HOLD `invalid` as a password. Nothing
// held either half (#113 item 5): `tests/vendored/sts_xml_schema_validation.js`
// sends the literal in a UsernameToken but only validates the fault's schema,
// and `tests/vendored/sts_ldaps.js` binds with a different wrong password.
//
// In a CHILD PROCESS with the whole stack, one person with a real password:
//
//   A. DEVELOPMENT — an LDAP simple bind with `invalid` answers
//      invalidCredentials (49), recorded under STS-LDAP-0001, while any other
//      password binds (the control: nothing else is checked); a WS-Trust Issue
//      whose UsernameToken carries `invalid` is a SOAP Fault under
//      STS-WSTRUST-0003, while any other password is issued a token.
//   B. PRODUCT — the person's real password binds and is issued (the
//      control); `invalid` is refused at both doors with exactly the answer a
//      wrong password gets (49; the same Fault, status and body), and
//      recorded as the reserved refusal rather than as a wrong password.
//   C. PRODUCT, A PERSON WHOSE STORED PASSWORD IS `invalid` (its hash written
//      onto the entry past the password policy, as an LDAP client holding the
//      store could once): still refused at both doors — what the both-modes
//      rule is FOR, and the one case a mutant that made the refusal a
//      development-only rule cannot pass.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'reserved_password_refusal',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.RP_ROOT;
  const OUT = process.env.RP_OUT;
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const config = require(ROOT_DIR + '/common/config');
    const ldap = require(ROOT_DIR + '/ldap/ldap_server');
    const credentials = require(ROOT_DIR + '/common/credentials');
    const wstrust = require(ROOT_DIR + '/ws-trust/wstrust');
    const websecurity = require(ROOT_DIR + '/common/websecurity');
    const audit = require(ROOT_DIR + '/common/audit');
    const stsCrypto = require(ROOT_DIR + '/common/crypto');

    const stamp = Date.now().toString(36);
    const PASSWORD = 'Rpr-' + stamp + '-Correct.Horse.Battery.Staple.42';
    const WRONG = PASSWORD + '-wrong';
    const PERSON = 'rpr-person-' + stamp;
    const HOLDER = 'rpr-holder-' + stamp;
    let address = 0;

    ldap.createUser(PERSON, { invent: false });
    const set = credentials.setPassword(PERSON, PASSWORD);
    note(set && set.ok !== false, 'precondition: ' + PERSON + ' has a ' +
         'password', JSON.stringify(set));
    ldap.createUser(HOLDER, { invent: false });
    // THE STORED PASSWORD IS `invalid`, written as the hash `setPassword()`
    // would write — but past the password policy, which would refuse a
    // seven-letter dictionary word, because the case under test is a store
    // that somehow holds it.
    const holderKey = 'uid=' + HOLDER + ',' + ldap.usersDn().toLowerCase();
    const holderEntry = ldap.entries.get(holderKey);
    if (holderEntry) {
      holderEntry.attributes.userpassword =
        [stsCrypto.hashSecret(credentials.RESERVED_REFUSAL)];
    }
    note(!!holderEntry && stsCrypto.verifySecret('invalid',
         String(holderEntry.attributes.userpassword[0])),
         'precondition: ' + HOLDER + '\'s stored password is the hash of ' +
         '"invalid"', holderKey);

    // A fresh address per bind, so the bind limiter's address bucket never
    // decides a check it is not the subject of.
    const bind = async function (name, password) {
      address += 1;
      websecurity.reset();
      const dn = ldap.objectFor(name).entry.dn;
      const result = await Promise.resolve(ldap.performOperation('bind', {
        dn: dn, boundDn: '', channel: 'ldaps', credentials: password,
        remoteAddress: '198.51.100.' + (address % 250 + 1) }));
      // The code the refusal was recorded under: the newest bind row for
      // this DN — `audit.list()` answers newest FIRST.
      const rows = audit.list().filter(function (row) {
        return row.action === 'directory.bind' &&
               String(row.target || '').toLowerCase() === dn.toLowerCase();
      });
      result.code = rows.length ? rows[0].errorCode || '' : '';
      return result;
    };
    const rst = function (name, password) {
      return wstrust.handleRst(
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" ' +
        'xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/' +
        'oasis-200401-wss-wssecurity-secext-1.0.xsd"><s:Header>' +
        '<wsse:Security><wsse:UsernameToken><wsse:Username>' + name +
        '</wsse:Username><wsse:Password>' + password + '</wsse:Password>' +
        '</wsse:UsernameToken></wsse:Security></s:Header><s:Body>' +
        '<wst:RequestSecurityToken xmlns:wst="http://docs.oasis-open.org/' +
        'ws-sx/ws-trust/200512"><wst:RequestType>http://docs.oasis-open.org/' +
        'ws-sx/ws-trust/200512/Issue</wst:RequestType>' +
        '</wst:RequestSecurityToken></s:Body></s:Envelope>',
        'application/soap+xml');
    };
    const issued = function (r) {
      return r.status === 200 && !/Fault/.test(String(r.body));
    };
    const faulted = function (r) {
      return r.status >= 400 && /Fault/.test(String(r.body));
    };
    const brief = function (r) {
      return r.status + ' ' + (r.errorCode || '') + ' ' +
             String(r.body).slice(0, 200);
    };
    // The credential codes a reserved refusal is recorded under: the LDAP
    // bind's own (it answers before asking the verifier) or the verifier's.
    const RESERVED_CODES = ['STS-LDAP-0001', 'STS-AUTHN-0048'];

    // --- A. development --------------------------------------------------
    let r = await bind(PERSON, 'anything-at-all');
    note(r.ok === true, 'A1. DEVELOPMENT: an LDAP bind with any other ' +
         'password succeeds (the control: nothing else is checked)',
         JSON.stringify(r));
    r = await bind(PERSON, 'invalid');
    note(r.ok === false && r.errorName === 'InvalidCredentialsError' &&
         r.code === 'STS-LDAP-0001',
         'A2. DEVELOPMENT: an LDAP bind with "invalid" is invalidCredentials ' +
         '(49), recorded under STS-LDAP-0001', JSON.stringify(r));
    r = rst(PERSON, 'anything-at-all');
    note(issued(r), 'A3. DEVELOPMENT: a WS-Trust Issue with any other ' +
         'password is issued a token (the control)', brief(r));
    r = rst(PERSON, 'invalid');
    note(faulted(r) && r.errorCode === 'STS-WSTRUST-0003',
         'A4. DEVELOPMENT: a WS-Trust Issue whose UsernameToken carries ' +
         '"invalid" is a SOAP Fault under STS-WSTRUST-0003', brief(r));
    const devVerdict = credentials.verify(PERSON, 'invalid',
                                          { via: 'test', door: 'wstrust' });
    note(devVerdict.ok === false && devVerdict.reason === 'reserved-refusal',
         'A5. DEVELOPMENT: and it is the verifier\'s reserved refusal that ' +
         'says no', JSON.stringify(devVerdict));

    // --- B. and C. product -----------------------------------------------
    config.setOverride('global.mode', 'product');
    try {
      r = await bind(PERSON, PASSWORD);
      note(r.ok === true, 'B1. PRODUCT: an LDAP bind with the person\'s ' +
           'real password succeeds (the control)', JSON.stringify(r));
      const wrongBind = await bind(PERSON, WRONG);
      r = await bind(PERSON, 'invalid');
      note(r.ok === false && wrongBind.ok === false &&
           r.errorName === wrongBind.errorName &&
           r.errorName === 'InvalidCredentialsError' &&
           r.error === wrongBind.error,
           'B2. PRODUCT: an LDAP bind with "invalid" is answered exactly as ' +
           'a wrong password is — invalidCredentials (49)',
           JSON.stringify({ reserved: r, wrong: wrongBind }));
      note(RESERVED_CODES.indexOf(r.code) >= 0 &&
           wrongBind.code === 'STS-AUTHN-0054',
           'B3. PRODUCT: and it is recorded as the reserved refusal, where ' +
           'the wrong password is recorded as one (STS-AUTHN-0054)',
           r.code + ' / ' + wrongBind.code);

      r = rst(PERSON, PASSWORD);
      note(issued(r), 'B4. PRODUCT: a WS-Trust Issue with the person\'s ' +
           'real password is issued a token (the control)', brief(r));
      const wrongRst = rst(PERSON, WRONG);
      r = rst(PERSON, 'invalid');
      note(faulted(r) && r.status === wrongRst.status &&
           r.body === wrongRst.body && r.errorCode === 'STS-WSTRUST-0003' &&
           wrongRst.errorCode === 'STS-WSTRUST-0003',
           'B5. PRODUCT: a WS-Trust Issue with "invalid" is the same SOAP ' +
           'Fault, status and body, that a wrong password gets',
           brief(r) + ' | ' + brief(wrongRst));
      const productVerdict = credentials.verify(PERSON, 'invalid',
                                                { via: 'test',
                                                  door: 'wstrust' });
      note(productVerdict.ok === false &&
           productVerdict.reason === 'reserved-refusal',
           'B6. PRODUCT: and the verifier says why — the reserved refusal, ' +
           'not a hash that did not match', JSON.stringify(productVerdict));

      r = await bind(HOLDER, 'invalid');
      note(r.ok === false && r.errorName === 'InvalidCredentialsError',
           'C1. PRODUCT: a person whose STORED password is "invalid" is ' +
           'still refused an LDAP bind with it', JSON.stringify(r));
      r = rst(HOLDER, 'invalid');
      note(faulted(r) && r.errorCode === 'STS-WSTRUST-0003',
           'C2. PRODUCT: and a WS-Trust Issue with it', brief(r));
    } finally {
      config.clearOverride('global.mode');
    }
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    note(false, 'the child process ran to the end', e && e.stack);
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

async function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'rpr-' + process.pid + '-' +
                        Date.now() + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal',
                                  RP_ROOT: ROOT, RP_OUT: out }),
      encoding: 'utf8', timeout: 180000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings),
               'the child process reported its findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-800))) {
    log.debug("Leaving run().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'reserved_password_refusal',
  describe: 'the reserved password "invalid" is refused over an LDAP bind ' +
            'and a WS-Trust UsernameToken in development, and as a wrong ' +
            'password in product (#412)',
  run: run
};
