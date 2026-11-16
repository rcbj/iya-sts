// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/remote_pep_audit.js
// ===========================================================================
// A REMOTE PEP'S DECISION RECORDS, PUSHED THROUGH THE MANAGEMENT API (#1827).
//
// rcbj: "Every log event pushed to iya-sts must be through an authenticated
// request on the mgmt API. Tie access to the built in group of remote PEPs."
// In a CHILD PROCESS with the whole stack on an ephemeral port, a PEP that is
// a person entry in `remote-peps`, registered in ou=peps and holding an
// RFC 7523 key pair:
//
//   1. the seeded client and resource: `sts-remote-pep` is a public client
//      on the jwt-bearer grant, its tokens bound to a certificate, holding a
//      delegated permission grant of `xacml:pep-audit`, which
//      `sts-management-api` defines; over a connection with no client
//      certificate its token for /admin-api is refused (STS-OAUTH-0489);
//   2. an entry missing the permission is given it at the next seed
//      (`fillApiPermissions()`, the upgrade from 1.1.0);
//   3. the PEP's own self-assertion, through a client in that shape but
//      unbound (this test speaks plain HTTP), is issued `xacml:pep-audit`;
//      somebody NOT in the group is not;
//   4. the push records one row per record — `xacml.remote.enforcement`,
//      `authzen.remote.decision` — with the PEP, instance, seq and the
//      time it decided, and counts an unknown kind as ignored;
//      `acknowledged` is the highest seq;
//   5. the same token at another operation is refused (STS-API-0147), and
//      an admin token at the push is refused too;
//   6. a PEP not registered in ou=peps is refused 404 (STS-XACML-0287), a
//      malformed batch 400;
//   7. taken out of the group, the PEP's token stops at its next push.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'remote_pep_audit',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.RPA_ROOT;
  const OUT = process.env.RPA_OUT;
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
          resolve({ status: res.statusCode, text: text, json: json });
        });
      });
      req.on('error', reject);
      req.end(body || '');
    });
  }
  const b64u = function (o) {
    return Buffer.from(JSON.stringify(o)).toString('base64url');
  };

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    const config = require(ROOT_DIR + '/common/config');
    const ldap = require(ROOT_DIR + '/ldap/ldap_server');
    const applications = require(ROOT_DIR + '/common/applications');
    const audit = require(ROOT_DIR + '/common/audit');
    const pki = require(ROOT_DIR + '/common/pki');
    const pkiAdmin = require(ROOT_DIR + '/admin-ui/pki_admin');
    const peps = require(ROOT_DIR + '/xacml/xacml_pep_registry');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const BASE = 'http://127.0.0.1:' + port;
    const TOKEN = BASE + '/oauth2/token';
    const stamp = Date.now().toString(36);
    const PEP = 'rpa-pep-' + stamp;
    const STRANGER = 'rpa-stranger-' + stamp;
    const UNREGISTERED = 'rpa-unreg-' + stamp;
    const CLIENT = 'rpa-client-' + stamp;
    const GROUP = String(config.value('roles.remotePepGroup') ||
                         'remote-peps');

    // ---------------------------------------------------------------------
    // 1. THE SEEDED CLIENT AND RESOURCE.
    // ---------------------------------------------------------------------
    const seeded = applications.clientConfigOf('sts-remote-pep') || {};
    const remotePep = applications.get('sts-remote-pep') || { fields: {} };
    const grants = [].concat(remotePep.fields.oauthGrantType || []);
    note(seeded.known && seeded.token_endpoint_auth_method === 'none' &&
         grants.join(' ') ===
           'urn:ietf:params:oauth:grant-type:jwt-bearer' &&
         seeded.tls_client_certificate_bound_access_tokens === true,
         '1. sts-remote-pep is seeded: public, jwt-bearer only, bound tokens',
         JSON.stringify({ known: seeded.known,
                          method: seeded.token_endpoint_auth_method,
                          grants: grants,
                          bound: seeded.tls_client_certificate_bound_access_tokens }));
    const permissionsOf = function (identifier) {
      const viewed = applications.get(identifier) || { fields: {} };
      return [].concat(viewed.fields.oauthPermission || []);
    };
    const defined = permissionsOf('sts-management-api')
      .map(function (one) { return String(one).split('|')[0]; });
    note(defined.indexOf('xacml:pep-audit') >= 0,
         '1. sts-management-api defines xacml:pep-audit', defined.join(' '));

    // ---------------------------------------------------------------------
    // 2. THE UPGRADE: an entry without the permission is given it.
    // ---------------------------------------------------------------------
    const held = permissionsOf('sts-management-api').filter(function (one) {
      return String(one).split('|')[0] === 'xacml:pep-audit';
    });
    held.forEach(function (one) {
      applications.updateApplication('sts-management-api',
        { attribute: 'oauthPermission', mode: 'remove', value: one });
    });
    const gone = permissionsOf('sts-management-api').every(function (one) {
      return String(one).split('|')[0] !== 'xacml:pep-audit';
    });
    note(gone, '2. (the permission is taken off, as on a 1.1.0 entry)',
         permissionsOf('sts-management-api').join(' '));
    applications.seedInternalApplications({ scope: 'default' });
    const after = permissionsOf('sts-management-api').map(function (one) {
      return String(one).split('|')[0];
    });
    note(after.indexOf('xacml:pep-audit') >= 0 &&
         after.indexOf('admin:read') >= 0,
         '2. a seed gives an existing sts-management-api the permission ' +
         'it lacked, and keeps the rest', after.join(' '));

    // ---------------------------------------------------------------------
    // The PEP, the stranger, and the test's unbound client.
    // ---------------------------------------------------------------------
    const built = pki.hasChain() ? { ok: true } : await pki.start({});
    note(built.ok, 'a certificate authority exists to issue from',
         (built.errors || []).join(' '));
    const keyOf = {};
    for (const who of [PEP, STRANGER, UNREGISTERED]) {
      ldap.createUser(who, { invent: false });
      const issued = await pkiAdmin.pkiAction({ action: 'issue',
        target: 'person', purpose: 'jwt', identifier: who,
        leafKeyAlg: 'rsa-2048' });
      note(issued.ok && /PRIVATE KEY/.test(String(issued.privateKeyPem)),
           'a key pair is issued to ' + who, issued.why || '');
      keyOf[who] = issued.privateKeyPem;
    }
    ldap.addGroupMember(GROUP, PEP);
    ldap.addGroupMember(GROUP, UNREGISTERED);
    const registered = peps.register({ name: PEP });
    note(registered.ok, 'the PEP is registered in ou=peps',
         registered.why || '');
    applications.createApplication({ identifier: CLIENT,
      protocols: ['oauth2'],
      fields: {
        oauthClientId: CLIENT,
        oauthTokenEndpointAuthMethod: 'none',
        oauthGrantType: ['urn:ietf:params:oauth:grant-type:jwt-bearer'],
        oauthDelegatedPermission: ['urn:sts:admin-api:xacml:pep-audit'],
        oauthGlobalConsent: ['xacml:pep-audit']
      } });

    const assertionFor = function (who) {
      const head = b64u({ alg: 'RS256', typ: 'JWT' });
      const now = Math.floor(Date.now() / 1000);
      const body = b64u({ iss: who, sub: who, aud: TOKEN, iat: now,
                          exp: now + 120,
                          jti: nodeCrypto.randomBytes(16).toString('hex') });
      const sig = nodeCrypto.sign('sha256', Buffer.from(head + '.' + body),
                                  keyOf[who]).toString('base64url');
      return head + '.' + body + '.' + sig;
    };
    const tokenFor = function (who, clientId) {
      const form = new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        assertion: assertionFor(who), client_id: clientId,
        scope: 'xacml:pep-audit', resource: BASE + '/admin-api' }).toString();
      return call(port, 'POST', '/oauth2/token',
                  { 'Content-Type': 'application/x-www-form-urlencoded' },
                  form);
    };
    const push = function (token, body) {
      return call(port, 'POST', '/admin-api/pep-audit',
                  { 'Content-Type': 'application/json',
                    Authorization: 'Bearer ' + token },
                  JSON.stringify(body));
    };

    // 1, continued: the seeded client's token is bound, so plain HTTP is no.
    const unbound = await tokenFor(PEP, 'sts-remote-pep');
    note(unbound.status === 400 &&
         /client certificate/.test(String((unbound.json || {})
           .error_description || '')),
         '1. sts-remote-pep\'s /admin-api token over a connection with no ' +
         'client certificate is refused (RFC 8705, STS-OAUTH-0489)',
         unbound.status + ' ' + unbound.text.slice(0, 300));

    // ---------------------------------------------------------------------
    // 3. ISSUANCE.
    // ---------------------------------------------------------------------
    const got = await tokenFor(PEP, CLIENT);
    const token = got.json && got.json.access_token;
    note(got.status === 200 && !!token &&
         / ?xacml:pep-audit ?/.test(' ' + got.json.scope + ' '),
         '3. the PEP\'s self-assertion is issued xacml:pep-audit',
         got.status + ' ' + got.text.slice(0, 300));
    const stranger = await tokenFor(STRANGER, CLIENT);
    note(!(stranger.json && / ?xacml:pep-audit ?/.test(
           ' ' + String(stranger.json.scope || '') + ' ')),
         '3. somebody NOT in ' + GROUP + ' is not issued xacml:pep-audit',
         stranger.status + ' ' + stranger.text.slice(0, 300));

    // ---------------------------------------------------------------------
    // 4. THE PUSH.
    // ---------------------------------------------------------------------
    const instance = nodeCrypto.randomBytes(16).toString('hex');
    const decidedAt = new Date(Date.now() - 5000).toISOString();
    const pushed = await push(token, { instance: instance, events: [
      { seq: 7, at: decidedAt, kind: 'enforcement', decision: 'Deny',
        allowed: false, fault: false, code: '', subject: 'alice-' + stamp,
        resource: 'https://pep/protected', action: 'read',
        bias: 'deny-biased', why: 'the policy denied',
        policies: ['urn:example:p v1'], discharged: [],
        undischargeable: [] },
      { seq: 8, at: decidedAt, kind: 'authzen', decision: 'Permit',
        allowed: true, fault: false, code: '', subject: '',
        resource: 'document', action: 'read', bias: 'deny-biased', why: '',
        policies: [], discharged: [], undischargeable: [],
        caller: 'caller-' + stamp, application: 'app-' + stamp,
        subjectType: 'user', endpoint: 'evaluation', requestId: 'r1' },
      { seq: 9, at: decidedAt, kind: 'something-new' }
    ] });
    note(pushed.status === 200 && pushed.json &&
         pushed.json.acknowledged === 9 && pushed.json.recorded === 2 &&
         pushed.json.ignored === 1,
         '4. a push of three is acknowledged to seq 9: two recorded, the ' +
         'unknown kind ignored', pushed.status + ' ' + pushed.text);
    const rows = audit.list().filter(function (one) {
      return one.detail && one.detail.instance === instance;
    });
    const enforcement = rows.filter(function (one) {
      return one.action === 'xacml.remote.enforcement';
    })[0] || {};
    const decided = rows.filter(function (one) {
      return one.action === 'authzen.remote.decision';
    })[0] || {};
    note(rows.length === 2, '4. two audit rows name the instance',
         rows.length);
    note(enforcement.outcome === 'refused' &&
         enforcement.actor === 'alice-' + stamp &&
         enforcement.detail.pep === PEP && enforcement.detail.seq === 7 &&
         enforcement.detail.decidedAt === decidedAt &&
         enforcement.at > Date.parse(decidedAt),
         '4. the enforcement row: refused, the subject as actor, the PEP, ' +
         'seq and the time it decided — and its own `at` the receipt',
         JSON.stringify(enforcement));
    note(decided.outcome === 'success' &&
         decided.actor === 'caller-' + stamp &&
         decided.detail.application === 'app-' + stamp,
         '4. the AuthZEN row: allowed, the caller as actor, the application',
         JSON.stringify(decided));

    // ---------------------------------------------------------------------
    // 5. THE SCOPE REACHES NOTHING ELSE, AND NOTHING ELSE REACHES IT.
    // ---------------------------------------------------------------------
    const elsewhere = await call(port, 'GET', '/admin-api/me',
                                 { Authorization: 'Bearer ' + token }, '');
    note(elsewhere.status === 403 && /xacml:pep-audit reaches/.test(
           elsewhere.text),
         '5. the PEP\'s token at GET /admin-api/me is refused (STS-API-0147)',
         elsewhere.status + ' ' + elsewhere.text.slice(0, 300));
    const adminForm = new URLSearchParams({ grant_type: 'client_credentials',
      scope: 'admin:read admin:write',
      resource: BASE + '/admin-api' }).toString();
    const adminSecret = applications.clientConfigOf('sts-api-client')
      .client_secret;
    const adminGot = await call(port, 'POST', '/oauth2/token', {
      'Content-Type': 'application/x-www-form-urlencoded',
      Authorization: 'Basic ' + Buffer.from('sts-api-client:' +
                                            adminSecret).toString('base64') },
    adminForm);
    const adminToken = adminGot.json && adminGot.json.access_token;
    const adminPush = await push(adminToken || 'none',
      { instance: instance, events: [{ seq: 10, kind: 'enforcement' }] });
    note(!!adminToken && adminPush.status === 403,
         '5. an administrator\'s token at the push is refused',
         adminGot.status + ' / ' + adminPush.status + ' ' +
         adminPush.text.slice(0, 300));

    // ---------------------------------------------------------------------
    // 6. NOT REGISTERED, AND MALFORMED.
    // ---------------------------------------------------------------------
    const otherGot = await tokenFor(UNREGISTERED, CLIENT);
    const notRegistered = await push(otherGot.json &&
                                     otherGot.json.access_token,
      { instance: instance, events: [{ seq: 1, kind: 'enforcement' }] });
    note(notRegistered.status === 404 &&
         /not registered|No Policy Enforcement Point/.test(
           notRegistered.text),
         '6. a PEP in the group but not registered is refused 404 ' +
         '(STS-XACML-0287)',
         notRegistered.status + ' ' + notRegistered.text.slice(0, 300));
    const malformed = await push(token, { instance: instance, events: [] });
    note(malformed.status === 400, '6. an empty batch is refused 400',
         malformed.status + ' ' + malformed.text.slice(0, 300));

    // ---------------------------------------------------------------------
    // 7. OUT OF THE GROUP, OUT OF THE API.
    // ---------------------------------------------------------------------
    // An ldapmodify's work: the console has no remove-member for a group
    // that is not the console roster's. The PEP is in no other group.
    ldap.dropMemberships(ldap.locateEntry(PEP).dn);
    const removed = await push(token,
      { instance: instance, events: [{ seq: 11, kind: 'enforcement' }] });
    note(removed.status === 403,
         '7. taken out of ' + GROUP + ', the PEP\'s token stops at once',
         removed.status + ' ' + removed.text.slice(0, 300));

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
  const out = path.join(os.tmpdir(), 'rpa-' + process.pid + '-' +
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
                                  RPA_ROOT: ROOT, RPA_OUT: out }),
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
  name: 'remote_pep_audit',
  describe: 'a remote PEP\'s decision records reach the audit log through ' +
            'POST /admin-api/pep-audit, on its own RFC 7523 token, only ' +
            'while it is in the remote PEPs\' group (#1827)',
  run: run
};
