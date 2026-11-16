// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/pep_assertion_credential.js
// ===========================================================================
// A REMOTE PEP'S ASSERTION KEY, CERTIFIED FROM ITS OWN REQUEST (#1827's
// follow-up, phase 3; rcbj 2026-11-16: "the service never holds the PEP's
// private key").
//
// In a CHILD PROCESS with the whole stack on an ephemeral plain-HTTP port,
// as `remote_pep_token_door.js` runs, so the key this file generates is the
// only credential anything presents. The PEP is a person in the remote PEPs
// group — a service account — and the key pair is made HERE, with
// `tests/tools/pep-credential.js`'s `assertionRequest()`; only the PKCS #10
// request reaches the service, through `issue-pep-credential`:
//
//   R. the refusals before anything is certified: no name, nobody by that
//      name (STS-XACML-0298), a person who is not a service account
//      (STS-XACML-0299), a service account outside the group
//      (STS-XACML-0301), no request (STS-PKI-0278), a tampered request —
//      its signature does not prove possession (STS-ENROLL-0033) — and an
//      Ed25519 key (STS-PKI-0279). None of them leaves a key on the entry.
//   C. the certificate: issued by the realm's Issuing CA, naming
//      `urn:sts:sa:<name>` and the PEP's username, whatever the request's
//      subject and subjectAltName asked for; the answer carries the chain,
//      the kid, the urn and the environment, and no private key.
//   E. the entry: one more RFC 7523 key, `source` `issued-from-csr`, no
//      private value written (`stsAssertionPrivateKey` unchanged), and an
//      audit row naming the kid and carrying no PEM.
//   G. the grant: the key signs the RFC 7523 self-assertion through
//      `sts-remote-pep` for a DPoP-bound xacml:pep token; a key that was
//      never registered is refused.
//   P. revokePrevious: a second key registered with it, the first is revoked
//      and refused at the grant, the second works.
//   V. revocation: the second key revoked onto its authority's list, and the
//      grant refuses it.
//   A. the management API's conversion: a refusal carries `errors`.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'pep_assertion_credential',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.PAC_ROOT;
  const OUT = process.env.PAC_OUT;
  const http = require('http');
  const nodeCrypto = require('crypto');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  function call(port, method, where, headers, body) {
    return new Promise(function (resolve, reject) {
      const req = http.request({ host: '127.0.0.1', port: port,
        path: where, method: method,
        headers: Object.assign({ 'Content-Length': Buffer.byteLength(
          body || '') }, headers) },
      function (res) {
        let text = '';
        res.on('data', function (d) { text += d; });
        res.on('end', function () {
          let json = null;
          try {
            json = JSON.parse(text);
          } catch (e) {
            // Not JSON; the finding reports the text.
            json = null;
          }
          resolve({ status: res.statusCode, text: text, json: json,
                    headers: res.headers });
        });
      });
      req.on('error', reject);
      req.end(body || '');
    });
  }
  const b64u = function (o) {
    return Buffer.from(JSON.stringify(o)).toString('base64url');
  };
  const brief = function (r) {
    return r.status + ' ' + String(r.text || '').slice(0, 300);
  };

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    const config = require(ROOT_DIR + '/common/config');
    const ldap = require(ROOT_DIR + '/ldap/ldap_server');
    const pki = require(ROOT_DIR + '/common/pki');
    const errorCodes = require(ROOT_DIR + '/common/error_codes');
    const audit = require(ROOT_DIR + '/common/audit');
    const personAssertions = require(ROOT_DIR + '/common/person_assertions');
    const serviceAccounts = require(ROOT_DIR + '/common/service_accounts');
    const xacmlAdmin = require(ROOT_DIR + '/xacml/xacml_admin');
    const adminActions = require(ROOT_DIR + '/admin-core/admin_actions');
    const tool = require(ROOT_DIR + '/tests/tools/pep-credential.js');
    const x509 = require(ROOT_DIR + '/common/crypto_impl/x509');
    const keyMaterial = require(ROOT_DIR + '/common/crypto_impl/key_material');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const BASE = 'http://127.0.0.1:' + port;
    const TOKEN = BASE + '/oauth2/token';
    const stamp = Date.now().toString(36);
    const PEP = 'pac-pep-' + stamp;
    const PLAIN = 'pac-person-' + stamp;
    const LONER = 'pac-loner-' + stamp;
    const GROUP = String(config.value('roles.remotePepGroup') ||
                         'remote-peps');
    const act = function (body) {
      return Promise.resolve(xacmlAdmin.combinedAction(
        Object.assign({ action: 'issue-pep-credential' }, body)));
    };
    const codeOf = function (result) {
      return String(errorCodes.codeOf(result) || '');
    };

    const built = pki.hasChain() ? { ok: true } : await pki.start({});
    note(built.ok, 'a certificate authority exists to certify from',
         (built.errors || []).join(' '));

    // The PEP: a person in the group, which makes it a service account
    // (`designateRemotePep()`); asked again here in case the group change
    // was not the one that did it.
    // A bare process has no Admin Write group and no bootstrap
    // administrator for `designateRemotePep()` to name as the owner, so
    // the flag is set here with an owner of this file's own.
    const OWNER = 'pac-owner-' + stamp;
    ldap.createUser(OWNER, { invent: false });
    ldap.createUser(PEP, { invent: false });
    ldap.addGroupMember(GROUP, PEP);
    if (!serviceAccounts.of(PEP)) {
      serviceAccounts.set(PEP, { serviceAccount: true, owners: [OWNER] });
    }
    const pepAccount = serviceAccounts.of(PEP);
    note(!!pepAccount, 'the PEP\'s entry is a service account',
         JSON.stringify(pepAccount && pepAccount.owners));
    // A person who is not a service account, and a service account that is
    // not in the group.
    ldap.createUser(PLAIN, { invent: false });
    ldap.createUser(LONER, { invent: false });
    const lonerSet = serviceAccounts.set(LONER,
      { serviceAccount: true, owners: [OWNER] });
    note(lonerSet && lonerSet.ok !== false && !!serviceAccounts.of(LONER),
         'a service account outside the group exists to be refused',
         JSON.stringify(lonerSet && (lonerSet.errors || lonerSet)));

    const first = await tool.assertionRequest({ keyAlg: 'ec-p256',
                                                name: PEP });
    const keyOf = { first: nodeCrypto.createPrivateKey(first.privateKeyPem) };

    // ---------------------------------------------------------------------
    // R. THE REFUSALS.
    // ---------------------------------------------------------------------
    const heldBefore = personAssertions.listFor(PEP, 'jwt').length;
    const noName = await act({ csr: first.csrPem });
    note(!noName.ok && codeOf(noName) === 'STS-XACML-0298',
         'R1. no name is refused (STS-XACML-0298)', codeOf(noName));
    const nobody = await act({ name: 'pac-nobody-' + stamp,
                               csr: first.csrPem });
    note(!nobody.ok && codeOf(nobody) === 'STS-XACML-0298',
         'R2. nobody by that name is refused (STS-XACML-0298)',
         codeOf(nobody) + ' ' + nobody.why);
    const plain = await act({ name: PLAIN, csr: first.csrPem });
    note(!plain.ok && codeOf(plain) === 'STS-XACML-0299',
         'R3. a person who is not a service account is refused ' +
         '(STS-XACML-0299)', codeOf(plain) + ' ' + plain.why);
    const loner = await act({ name: LONER, csr: first.csrPem });
    note(!loner.ok && codeOf(loner) === 'STS-XACML-0301',
         'R4. a service account outside ' + GROUP + ' is refused ' +
         '(STS-XACML-0301)', codeOf(loner) + ' ' + loner.why);
    const noCsr = await act({ name: PEP });
    note(!noCsr.ok && codeOf(noCsr) === 'STS-PKI-0278',
         'R5. no request is refused (STS-PKI-0278)',
         codeOf(noCsr) + ' ' + noCsr.why);
    // A byte of the SIGNATURE flipped: the request still parses and no
    // longer proves possession of the key it carries.
    const der = Buffer.from(first.csrPem.replace(/-----[A-Z ]+-----/g, '')
                              .replace(/\s+/g, ''), 'base64');
    der[der.length - 3] ^= 0x5a;
    const tampered = await act({ name: PEP, csr: der.toString('base64') });
    note(!tampered.ok && codeOf(tampered) === 'STS-ENROLL-0033',
         'R6. a tampered request does not prove possession and is refused',
         codeOf(tampered) + ' ' + tampered.why);
    const edPair = await keyMaterial.generateKeyPair('ed25519');
    const edReq = await x509.certificationRequest({
      subject: [{ name: 'CN', value: PEP }],
      publicKeyPem: edPair.publicPem, privateKeyPem: edPair.privatePem });
    const ed = await act({ name: PEP,
                           csr: Buffer.from(edReq.der).toString('base64') });
    note(!ed.ok && codeOf(ed) === 'STS-PKI-0279',
         'R7. an Ed25519 key is refused by name (STS-PKI-0279)',
         codeOf(ed) + ' ' + ed.why);
    note(personAssertions.listFor(PEP, 'jwt').length === heldBefore,
         'R8. no refusal left a key on the entry',
         personAssertions.listFor(PEP, 'jwt').length + ' vs ' + heldBefore);

    // ---------------------------------------------------------------------
    // C. THE CERTIFICATE, WHATEVER THE REQUEST ASKED TO BE CALLED.
    // ---------------------------------------------------------------------
    const pairOf = await keyMaterial.generateKeyPair('ec-p256');
    const asking = await x509.certificationRequest({
      subject: [{ name: 'CN', value: 'somebody-else' }],
      publicKeyPem: pairOf.publicPem, privateKeyPem: pairOf.privatePem,
      subjectAltName: [{ kind: 'uri', value: 'urn:sts:person:alice' },
                       { kind: 'dns', value: 'evil.example' }] });
    // The key in THIS request is the one registered: `first` above stays
    // unregistered for G3.
    keyOf.named = nodeCrypto.createPrivateKey(pairOf.privatePem);
    const issued = await act({ name: PEP, label: 'pac-first',
      csr: Buffer.from(asking.der).toString('base64') });
    note(issued.ok, 'C1. issue-pep-credential certifies the PEP\'s key',
         issued.why || '');
    const leaf = issued.ok
      ? new nodeCrypto.X509Certificate(issued.certificatePem) : null;
    const san = leaf ? String(leaf.subjectAltName || '') : '';
    note(!!leaf && san === 'URI:urn:sts:sa:' + PEP,
         'C2. the leaf names urn:sts:sa:' + PEP + ' and nothing the ' +
         'request asked for', san);
    note(!!leaf && /CN=pac-pep-/.test(String(leaf.subject)) &&
         String(leaf.subject).indexOf('somebody-else') < 0,
         'C3. its common name is the entry\'s, not the request\'s',
         leaf && leaf.subject);
    note(issued.ok && issued.urn === 'urn:sts:sa:' + PEP &&
         /^.+$/.test(String(issued.kid)) &&
         (issued.chainPem || []).length >= 1 &&
         /BEGIN CERTIFICATE/.test(String(issued.fullChainPem)),
         'C4. the answer carries the urn, the kid and the chain',
         JSON.stringify({ urn: issued.urn, kid: issued.kid }));
    note(issued.ok && !('privateKeyPem' in issued) &&
         !/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(JSON.stringify(issued)),
         'C5. the answer carries no private key');
    note(issued.ok && issued.environment &&
         issued.environment.PEP_NAME === PEP &&
         issued.environment.PEP_CLIENT_ID === 'sts-remote-pep' &&
         !!issued.environment.PEP_ASSERTION_KEY,
         'C6. and the environment the PEP is started with',
         JSON.stringify(issued.environment));
    let chained = false;
    try {
      const issuing = new nodeCrypto.X509Certificate(issued.chainPem[0]);
      chained = leaf.verify(issuing.publicKey) && leaf.checkIssued(issuing);
    } catch (e) {
      // Reported by the finding.
      chained = false;
    }
    note(chained, 'C7. the realm\'s Issuing CA signed it');

    // ---------------------------------------------------------------------
    // E. THE ENTRY.
    // ---------------------------------------------------------------------
    const rows = personAssertions.listFor(PEP, 'jwt');
    const row = rows.filter(function (one) {
      return one.kid === issued.kid;
    })[0] || {};
    note(row.state === 'valid' && row.source === 'issued-from-csr' &&
         row.privateKeyHeld === false && row.label === 'pac-first',
         'E1. the entry holds one more RFC 7523 key, issued-from-csr, ' +
         'with no private half', JSON.stringify({ state: row.state,
           source: row.source, held: row.privateKeyHeld, label: row.label }));
    const opened = personAssertions.recordFor(PEP) || { keys: { jwt: [] } };
    const openedRow = (opened.keys.jwt || []).filter(function (one) {
      return one.kid === issued.kid;
    })[0] || {};
    note(!openedRow.privateKeyPem,
         'E2. opening every private key on the entry finds none for it',
         String(openedRow.privateKeyPem || '').slice(0, 20));
    note(row.caId && row.serialHex === String(issued.serialHex).toLowerCase(),
         'E3. the record names the authority that signed it and its serial',
         row.caId + ' ' + row.serialHex);
    const audited = audit.list().filter(function (one) {
      return one.action === 'xacml.pep.credential' &&
             JSON.stringify(one).indexOf(issued.kid) >= 0;
    })[0];
    note(!!audited && JSON.stringify(audited).indexOf('BEGIN') < 0,
         'E4. the act is audited, naming the kid and carrying no PEM',
         audited && JSON.stringify(audited).slice(0, 300));

    // ---------------------------------------------------------------------
    // G. THE GRANT.
    // ---------------------------------------------------------------------
    const algOf = function (key) {
      return key.asymmetricKeyType === 'ec' ? 'ES256' : 'RS256';
    };
    const sign = function (key, input) {
      return nodeCrypto.sign('sha256', Buffer.from(input),
        key.asymmetricKeyType === 'ec'
          ? { key: key, dsaEncoding: 'ieee-p1363' } : key)
        .toString('base64url');
    };
    const jwkOf = function (key) {
      const full = nodeCrypto.createPublicKey(key).export({ format: 'jwk' });
      return key.asymmetricKeyType === 'ec'
        ? { kty: full.kty, crv: full.crv, x: full.x, y: full.y }
        : { kty: full.kty, n: full.n, e: full.e };
    };
    const proofFor = function (key, method, url) {
      const head = b64u({ typ: 'dpop+jwt', alg: algOf(key),
                          jwk: jwkOf(key) });
      const body = b64u({
        jti: nodeCrypto.randomBytes(16).toString('hex'), htm: method,
        htu: url, iat: Math.floor(Date.now() / 1000) });
      return head + '.' + body + '.' + sign(key, head + '.' + body);
    };
    const tokenWith = function (key) {
      const head = b64u({ alg: algOf(key), typ: 'JWT' });
      const now = Math.floor(Date.now() / 1000);
      const body = b64u({ iss: PEP, sub: PEP, aud: TOKEN, iat: now,
                          exp: now + 120,
                          jti: nodeCrypto.randomBytes(16).toString('hex') });
      const assertion = head + '.' + body + '.' + sign(key, head + '.' + body);
      const form = new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        assertion: assertion, client_id: 'sts-remote-pep',
        scope: 'xacml:pep', resource: BASE + '/xacml/pep' }).toString();
      return call(port, 'POST', '/oauth2/token',
        { 'Content-Type': 'application/x-www-form-urlencoded',
          DPoP: proofFor(key, 'POST', TOKEN) }, form);
    };
    const granted = await tokenWith(keyOf.named);
    note(granted.status === 200 && granted.json &&
         granted.json.token_type === 'DPoP' &&
         / ?xacml:pep ?/.test(' ' + granted.json.scope + ' '),
         'G1. the certified key signs the self-assertion for a DPoP-bound ' +
         'xacml:pep token', brief(granted));
    const pulled = granted.json && granted.json.access_token
      ? await call(port, 'GET', '/xacml/pep/policies', {
          Authorization: 'DPoP ' + granted.json.access_token,
          DPoP: (function () {
            const head = b64u({ typ: 'dpop+jwt', alg: 'ES256',
                                jwk: jwkOf(keyOf.named) });
            const body = b64u({
              jti: nodeCrypto.randomBytes(16).toString('hex'), htm: 'GET',
              htu: BASE + '/xacml/pep/policies',
              iat: Math.floor(Date.now() / 1000),
              ath: nodeCrypto.createHash('sha256')
                .update(granted.json.access_token).digest('base64url') });
            return head + '.' + body + '.' +
              sign(keyOf.named, head + '.' + body);
          })() })
      : { status: 0, text: 'no token' };
    note(pulled.status === 200,
         'G2. and the PEP pulls its policies on that token', brief(pulled));
    const stranger = await tokenWith(keyOf.first);
    note(stranger.status === 400 || stranger.status === 401,
         'G3. a key that was never registered is refused at the grant',
         brief(stranger));

    // ---------------------------------------------------------------------
    // P. revokePrevious.
    // ---------------------------------------------------------------------
    const second = await tool.assertionRequest({ keyAlg: 'rsa-2048',
                                                 name: PEP });
    keyOf.second = nodeCrypto.createPrivateKey(second.privateKeyPem);
    const rotated = await act({ name: PEP, csr: second.csrPem,
                                revokePrevious: true });
    note(rotated.ok && (rotated.revoked || []).indexOf(issued.kid) >= 0 &&
         rotated.keyAlg === 'rsa-2048',
         'P1. a second (RSA) key registered with revokePrevious revokes ' +
         'the first', JSON.stringify({ ok: rotated.ok, why: rotated.why,
                                       revoked: rotated.revoked }));
    const states = {};
    personAssertions.listFor(PEP, 'jwt').forEach(function (one) {
      states[one.kid] = one.state;
    });
    note(states[issued.kid] === 'revoked' && states[rotated.kid] === 'valid',
         'P2. the first reads revoked and the second valid',
         JSON.stringify(states));
    const oldRefused = await tokenWith(keyOf.named);
    note(oldRefused.status === 400 || oldRefused.status === 401,
         'P3. the revoked key is refused at the grant', brief(oldRefused));
    const newGranted = await tokenWith(keyOf.second);
    note(newGranted.status === 200,
         'P4. the new key is granted', brief(newGranted));

    // ---------------------------------------------------------------------
    // V. REVOCATION, ONTO THE AUTHORITY'S LIST.
    // ---------------------------------------------------------------------
    const revoked = personAssertions.revoke(PEP, 'jwt', rotated.kid,
      'keyCompromise', { initiatingEntity: 'admin', via: 'test' });
    note(revoked.ok && revoked.onList === true,
         'V1. revoking it puts its certificate on its authority\'s list',
         JSON.stringify({ ok: revoked.ok, onList: revoked.onList }));
    const afterRevoke = await tokenWith(keyOf.second);
    note(afterRevoke.status === 400 || afterRevoke.status === 401,
         'V2. and the grant refuses it', brief(afterRevoke));

    // ---------------------------------------------------------------------
    // A. THE MANAGEMENT API'S CONVERSION.
    // ---------------------------------------------------------------------
    const viaApi = await Promise.resolve(adminActions.xacmlAction({
      action: 'issue-pep-credential', name: PLAIN, csr: first.csrPem }));
    note(!viaApi.ok && Array.isArray(viaApi.errors) && viaApi.errors.length &&
         codeOf(viaApi) === 'STS-XACML-0299',
         'A1. through the management API a refusal carries errors and its ' +
         'code', JSON.stringify(viaApi.errors) + ' ' + codeOf(viaApi));
    note(xacmlAdmin.actionNames().indexOf('issue-pep-credential') >= 0,
         'A2. the act is among the names the unknown-action sentence lists');

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
  const out = path.join(os.tmpdir(), 'pac-' + process.pid + '-' +
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
                                  PAC_ROOT: ROOT, PAC_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
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
  name: 'pep_assertion_credential',
  describe: 'issue-pep-credential certifies the key in a remote PEP\'s own ' +
            'certificate request as its RFC 7523 assertion key, names it ' +
            'urn:sts:sa:<name>, keeps no private key, and the key then ' +
            'authenticates the grant until it is revoked (#1827, phase 3)',
  run: run
};
