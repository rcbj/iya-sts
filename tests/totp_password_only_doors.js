// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/totp_password_only_doors.js
// ===========================================================================
// A PERSON ENROLLED IN AN AUTHENTICATOR APP IS REFUSED THEIR PASSWORD ALONE AT
// EVERY PASSWORD-ONLY DOOR, AS A WRONG PASSWORD IS (#417, 2026-10-02).
//
// #101: in product a person who holds a second factor is refused their own
// RIGHT password at the five doors that cannot ask for one — an LDAP simple
// bind, a WS-Security UsernameToken, SCIM Basic, SSF Basic and EST Basic —
// with exactly the answer a wrong password gets, because a different answer
// would be a password oracle. "Holds a second factor" is
// `credentials.secondFactorDemand()`: a security key in the `mfa` role OR an
// authenticator app. `tests/second_factor_doors.js` and
// `tests/vendored/sts_second_factor_doors.js` hold the doors with a key, with
// `stsMfaRequired` and with the policy, never with an app; TOTP enrolment was
// asserted only at the Kerberos door (`sts_kerberos_fast_otp.js`).
//
// In a CHILD PROCESS with the whole stack on an ephemeral TLS port, the default
// realm, two people with real passwords — one ENROLLED in an authenticator
// app the way `/portal/mfa` enrols one (begin, then confirm with a code
// computed here), one with no second factor — and each door driven as a
// client drives it: the LDAP bind through `performOperation()`, the other
// four over HTTP:
//
//   A. DEVELOPMENT, the control that the doors are reached: the enrolled
//      person's password is accepted at all five, as every password is;
//   B. PRODUCT: the person with no second factor is accepted at each door
//      with their password (the control: the door verifies and admits);
//      the enrolled person's RIGHT password is refused at each, with the
//      same answer their WRONG password gets — the same LDAP result, the
//      same status and body; and the verifier records the refusal as
//      STS-AUTHN-0213 (`second-factor-required`) for every door, where the
//      wrong password is STS-AUTHN-0054.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'totp_password_only_doors',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.TD_ROOT;
  const OUT = process.env.TD_OUT;
  const https = require('https');
  const nodeCrypto = require('crypto');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  function send(port, method, urlPath, headers, body) {
    return new Promise(function (resolve, reject) {
      const text = body === undefined ? '' : body;
      const all = Object.assign({}, headers || {});
      if (method !== 'GET') {
        all['content-length'] = Buffer.byteLength(text);
      }
      const req = https.request({ host: '127.0.0.1', port: port,
                                  path: urlPath, method: method,
                                  headers: all, rejectUnauthorized: false,
                                  agent: false }, function (res) {
        let raw = '';
        res.on('data', function (d) { raw += d; });
        res.on('end', function () {
          resolve({ status: res.statusCode, raw: raw });
        });
      });
      req.on('error', reject);
      req.end(text);
    });
  }
  const basic = function (who, password) {
    return 'Basic ' + Buffer.from(who + ':' + password).toString('base64');
  };

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    const config = require(ROOT_DIR + '/common/config');
    const ldap = require(ROOT_DIR + '/ldap/ldap_server');
    const credentials = require(ROOT_DIR + '/common/credentials');
    const totp = require(ROOT_DIR + '/common/totp');
    const applications = require(ROOT_DIR + '/common/applications');
    const websecurity = require(ROOT_DIR + '/common/websecurity');
    const errorCodes = require(ROOT_DIR + '/common/error_codes');

    // OVER TLS, AS THE MAIN PORT IS: EST is served over TLS only (RFC 7030
    // section 3.2) and product refuses it otherwise, 403 — an answer that
    // is not about the password at all.
    await require(ROOT_DIR + '/common/service_state').start();
    await require(ROOT_DIR + '/common/pki').ensureScope('');
    const tls = require(ROOT_DIR + '/tls/tls_server');
    const serverCert = tls.serverCertificate();
    const server = https.createServer(Object.assign({
      cert: serverCert.certPem, key: serverCert.privateKeyPem
    }, tls.protocolOptions()), app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const stamp = nodeCrypto.randomBytes(4).toString('hex');
    const PASSWORD = 'Td-' + stamp + '-Correct.Horse.Battery.Staple.42';
    const WRONG = PASSWORD + '-wrong';
    const ENROLLED = 'td-app-' + stamp;
    const PLAIN = 'td-plain-' + stamp;
    const APPLIES_TO = 'https://wstrust.td417.example.test/' + stamp;
    const DOORS = ['ldap', 'wstrust', 'scim', 'ssf', 'est'];
    let address = 0;

    [ENROLLED, PLAIN].forEach(function (who) {
      ldap.createUser(who, { invent: false });
      const set = credentials.setPassword(who, PASSWORD);
      note(set && set.ok !== false, 'precondition: ' + who + ' has a ' +
           'password', JSON.stringify(set));
    });
    // ENROLLED AS `/portal/mfa` ENROLS: begin, then confirm with the code
    // the app would show now.
    const begun = credentials.beginTotpEnrolment(ENROLLED,
      { base: 'https://127.0.0.1:' + port });
    const confirmed = begun && begun.ok !== false
      ? credentials.confirmTotpEnrolment(ENROLLED,
          totp.codeAt(begun.secret, Date.now(), begun))
      : begun;
    const demand = credentials.secondFactorDemand(ENROLLED);
    note(confirmed && confirmed.ok !== false && credentials.hasTotp(ENROLLED) &&
         demand.totp === true && demand.key === false &&
         demand.required === false,
         'precondition: ' + ENROLLED + ' is enrolled in an authenticator ' +
         'app — and holds no key and is required nothing else',
         JSON.stringify(demand));
    applications.createApplication({ identifier: APPLIES_TO,
      protocols: ['wstrust'], fields: { wstrustAppliesTo: [APPLIES_TO] } });
    // This file refuses many binds and enrolments on purpose, from one
    // address; the limit is not what it is about.
    config.setOverride('est.attemptsPerAddress', 100000);

    // --- the five doors: `{ accepted, answer }` --------------------------
    const ldapBind = async function (who, password) {
      address += 1;
      websecurity.reset();
      const r = await Promise.resolve(ldap.performOperation('bind', {
        dn: ldap.objectFor(who).entry.dn, boundDn: '', channel: 'ldaps',
        credentials: password,
        remoteAddress: '198.51.100.' + (address % 250 + 1) }));
      return { accepted: r.ok === true,
               answer: 'ldap ' + (r.ok ? 'success' : r.errorName + ' ' +
                                  r.error) };
    };
    const wsTrust = async function (who, password) {
      const rst = '<?xml version="1.0" encoding="UTF-8"?>' +
        '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">' +
        '<soap:Header><wsse:Security xmlns:wsse="http://docs.oasis-open.org/' +
        'wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">' +
        '<wsse:UsernameToken><wsse:Username>' + who + '</wsse:Username>' +
        '<wsse:Password>' + password + '</wsse:Password>' +
        '</wsse:UsernameToken></wsse:Security></soap:Header>' +
        '<soap:Body><wst:RequestSecurityToken ' +
        'xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">' +
        '<wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/' +
        'Issue</wst:RequestType><wsp:AppliesTo xmlns:wsp="http://schemas.' +
        'xmlsoap.org/ws/2004/09/policy"><wsa:EndpointReference xmlns:wsa=' +
        '"http://www.w3.org/2005/08/addressing"><wsa:Address>' + APPLIES_TO +
        '</wsa:Address></wsa:EndpointReference></wsp:AppliesTo>' +
        '</wst:RequestSecurityToken></soap:Body></soap:Envelope>';
      const r = await send(port, 'POST', '/sts',
                           { 'content-type': 'application/soap+xml' }, rst);
      // Ids and instants differ between any two responses; what is compared
      // is everything else.
      return { accepted: r.status === 200 && /Assertion/.test(r.raw),
               answer: r.status + ' ' + r.raw
                 .replace(/(uuid|urn:uuid):[0-9a-f-]+/gi, 'ID')
                 .replace(/_[0-9a-f]{16,}/gi, 'ID')
                 .replace(/\d{4}-\d\d-\d\dT[\d:.]+Z/g, 'TIME') };
    };
    const scim = async function (who, password) {
      const r = await send(port, 'GET', '/scim/v2/Users?count=1',
        { authorization: basic(who, password),
          accept: 'application/scim+json' });
      return { accepted: r.status !== 401, answer: r.status + ' ' + r.raw };
    };
    const ssf = async function (who, password) {
      const r = await send(port, 'GET', '/ssf/stream',
        { authorization: basic(who, password) });
      return { accepted: r.status !== 401, answer: r.status + ' ' + r.raw };
    };
    // A body that is not a certificate request: an authenticated caller is
    // answered 400 about the body, an unauthenticated one 401 before it is
    // read — `sts_second_factor_doors.js`'s arrangement. Accepted is the 400
    // and nothing else, so that a refusal on some other ground (a 403 for
    // the transport) cannot pass for an admitted caller.
    const est = async function (who, password) {
      const r = await send(port, 'POST', '/.well-known/est/simpleenroll',
        { authorization: basic(who, password),
          'content-type': 'application/pkcs10' },
        'not-a-certificate-request');
      return { accepted: r.status === 400, answer: r.status + ' ' + r.raw };
    };
    const DOOR = { ldap: ldapBind, wstrust: wsTrust, scim: scim, ssf: ssf,
                   est: est };

    // --- A. development -------------------------------------------------
    for (const door of DOORS) {
      const r = await DOOR[door](ENROLLED, PASSWORD);
      note(r.accepted, 'A. DEVELOPMENT, ' + door + ': ' + ENROLLED + '\'s ' +
           'password is accepted, as every password is (the control: the ' +
           'door is reached)', r.answer.slice(0, 240));
    }

    // --- B. product -----------------------------------------------------
    config.setOverride('global.mode', 'product');
    try {
      for (const door of DOORS) {
        const plain = await DOOR[door](PLAIN, PASSWORD);
        note(plain.accepted, 'B1. PRODUCT, ' + door + ': a person with no ' +
             'second factor is accepted with their password (the control)',
             plain.answer.slice(0, 240));
        const right = await DOOR[door](ENROLLED, PASSWORD);
        const wrong = await DOOR[door](ENROLLED, WRONG);
        note(!right.accepted && !wrong.accepted,
             'B2. PRODUCT, ' + door + ': ' + ENROLLED + '\'s RIGHT password ' +
             'is refused', right.answer.slice(0, 240));
        note(right.answer === wrong.answer,
             'B3. PRODUCT, ' + door + ': with exactly the answer their ' +
             'WRONG password gets', right.answer.slice(0, 200) + ' | ' +
             wrong.answer.slice(0, 200));
        const verdict = credentials.verify(ENROLLED, PASSWORD,
                                           { via: 'test ' + door,
                                             door: door });
        const wrongVerdict = credentials.verify(ENROLLED, WRONG,
                                                { via: 'test ' + door,
                                                  door: door });
        note(verdict.ok === false &&
             errorCodes.codeOf(verdict) === 'STS-AUTHN-0213' &&
             verdict.reason === 'second-factor-required' &&
             errorCodes.codeOf(wrongVerdict) === 'STS-AUTHN-0054',
             'B4. PRODUCT, ' + door + ': the verifier records it as ' +
             'STS-AUTHN-0213 (second-factor-required), the wrong password ' +
             'as STS-AUTHN-0054', JSON.stringify({ right: verdict.reason,
               code: errorCodes.codeOf(verdict),
               wrong: errorCodes.codeOf(wrongVerdict) }));
      }
      const doors = credentials.passwordOnlyDoors(ENROLLED);
      note(doors.refused.join(',') === DOORS.join(','),
           'B5. PRODUCT: passwordOnlyDoors() names all five for the enrolled ' +
           'person', JSON.stringify(doors.refused));
    } finally {
      config.clearOverride('global.mode');
      config.clearOverride('est.attemptsPerAddress');
    }
    server.close();
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
  const out = path.join(os.tmpdir(), 'td-' + process.pid + '-' + Date.now() +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|SCIM_|CONFIG_FILE$)/
        .test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal',
                                  TD_ROOT: ROOT, TD_OUT: out }),
      encoding: 'utf8', timeout: 240000, cwd: ROOT
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
  name: 'totp_password_only_doors',
  describe: 'a person enrolled in an authenticator app is refused their ' +
            'password alone at the LDAP bind, WS-Trust, SCIM, SSF and EST ' +
            'Basic in product, as a wrong password is (#417)',
  run: run
};
