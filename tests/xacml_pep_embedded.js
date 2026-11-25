// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/xacml_pep_embedded.js
// ===========================================================================
// AN EMBEDDED REMOTE PEP: ITS REGISTRATION, ITS HEARTBEAT AND ITS AUTHZEN
// SCOPE (#2026, work item 3 of #1206).
//
// In a CHILD PROCESS with the whole stack on an ephemeral PLAIN-HTTP port,
// as `remote_pep_token_door.js` runs it: two PEPs, each a person in
// `remote-peps` with one ES256 key, reach the PEP door and `/access/v1` on
// the DPoP-bound tokens that key earns through `sts-remote-pep`, exactly as
// the `iya-pep` package does.
//
//   I. `identityOf()`, the one reading, case by case with its code: kind,
//      mode, protocol version, policyEvents, the binding (0338-0342).
//   R. THE REGISTRATION: no kind is a container, as an older PEP is;
//      embedded and bound to nothing (403), bound elsewhere (403), an
//      unsupported protocolVersion (400), mode with a container (400); then
//      the package's own body accepted and the row and `pepsJson()` saying
//      kind, application, mode and protocol version.
//   H. THE HEARTBEAT: policyEvents stored and refused, an absent member
//      kept, a mode change written, a binding moved refusing the next
//      heartbeat (403) without touching the row.
//   Z. AUTHZEN IN central MODE: the bound PEP, in no AUTHZEN group, asks
//      about its application (200, and with no context.application) and is
//      refused another (403); the batch the same; a PEP bound to nothing is
//      refused by the policy (no AUTHZEN_PEPS).
//
// Over the wire against the container: `tests/protocol/
// sts_xacml_pep_embedded.js`.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'xacml_pep_embedded',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.PE_ROOT;
  const OUT = process.env.PE_OUT;
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
    const applications = require(ROOT_DIR + '/common/applications');
    const pki = require(ROOT_DIR + '/common/pki');
    const pkiAdmin = require(ROOT_DIR + '/admin-ui/pki_admin');
    const peps = require(ROOT_DIR + '/xacml/xacml_pep_registry');
    const xacmlAdmin = require(ROOT_DIR + '/xacml/xacml_admin');
    const PepBinding = require(ROOT_DIR + '/xacml/xacml_pep_binding');
    const serviceAccounts = require(ROOT_DIR + '/common/service_accounts');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const BASE = 'http://127.0.0.1:' + port;
    const TOKEN = BASE + '/oauth2/token';
    const stamp = Date.now().toString(36);
    const PEP = 'pe-pep-' + stamp;
    const LONE = 'pe-lone-' + stamp;
    const APP = 'pe-app-' + stamp;
    const APP2 = 'pe-app2-' + stamp;
    const GROUP = String(config.value('roles.remotePepGroup') ||
                         'remote-peps');
    const binding = PepBinding.shared();

    // ---------------------------------------------------------------------
    // I. THE ONE READING, CASE BY CASE.
    // ---------------------------------------------------------------------
    const kept = { kind: 'embedded', registeredApplication: APP,
                   mode: 'central', protocolVersion: 1, policyEvents: '' };
    const cases = [
      ['I1. no kind is a container', {}, null, '', true, 'container'],
      ['I2. an unknown kind', { kind: 'sidecar' }, null, '', 'STS-XACML-0344'],
      ['I3. mode with no kind (a container)', { mode: 'local' }, null, '',
       'STS-XACML-0343'],
      ['I4. mode with kind container', { kind: 'container', mode: 'central' },
       null, '', 'STS-XACML-0343'],
      ['I5. embedded with no mode', { kind: 'embedded', application: APP,
       protocolVersion: 1 }, null, APP, 'STS-XACML-0344'],
      ['I6. embedded with no protocolVersion', { kind: 'embedded',
       application: APP, mode: 'local' }, null, APP, 'STS-XACML-0342'],
      ['I7. protocolVersion 2', { kind: 'embedded', application: APP,
       mode: 'local', protocolVersion: 2 }, null, APP, 'STS-XACML-0342'],
      ['I8. a container\'s unsupported protocolVersion', {
       protocolVersion: '1' }, null, '', 'STS-XACML-0342'],
      ['I9. embedded and bound to nothing', { kind: 'embedded',
       application: APP, mode: 'local', protocolVersion: 1 }, null, '',
       'STS-XACML-0340'],
      ['I10. embedded and bound elsewhere', { kind: 'embedded',
       application: APP, mode: 'local', protocolVersion: 1 }, null, APP2,
       'STS-XACML-0341'],
      ['I11. embedded naming no application', { kind: 'embedded',
       mode: 'local', protocolVersion: 1 }, null, APP, 'STS-XACML-0341'],
      ['I12. an unknown policyEvents', { policyEvents: 'sometimes' }, kept,
       APP, 'STS-XACML-0344'],
      ['I13. a heartbeat with nothing keeps the row', {}, kept, APP, true,
       'embedded'],
      ['I14. the package\'s body', { kind: 'embedded', application: APP,
       mode: 'local', protocolVersion: 1, policyEvents: 'requested' }, null,
       APP, true, 'embedded']
    ];
    cases.forEach(function (one) {
      const got = peps.identityOf(one[1], one[2], one[3]);
      const ok = one[4] === true
        ? got.ok && got.kind === one[5]
        : !got.ok && got.code === one[4] &&
          got.status === (/0338|0339/.test(one[4]) ? 403 : 400);
      note(ok, one[0] + (one[4] === true ? '' : ' (' + one[4] + ')'),
           JSON.stringify(got));
    });

    // ---------------------------------------------------------------------
    // The cast: two PEPs, each holding one key pair, and two applications.
    // ---------------------------------------------------------------------
    const built = pki.hasChain() ? { ok: true } : await pki.start({});
    note(built.ok, 'a certificate authority exists to issue from',
         (built.errors || []).join(' '));
    [APP, APP2].forEach(function (identifier) {
      applications.createApplication({ identifier: identifier,
        name: identifier, protocols: ['oauth2'] });
    });
    const keyOf = {};
    const OWNER = 'pe-owner-' + stamp;
    ldap.createUser(OWNER, { invent: false });
    for (const who of [PEP, LONE]) {
      ldap.createUser(who, { invent: false });
      const issued = await pkiAdmin.pkiAction({ action: 'issue',
        target: 'person', purpose: 'jwt', identifier: who,
        leafKeyAlg: 'ec-p256' });
      note(issued.ok && /PRIVATE KEY/.test(String(issued.privateKeyPem)),
           'a key pair is issued to ' + who, issued.why || '');
      keyOf[who] = nodeCrypto.createPrivateKey(issued.privateKeyPem);
      ldap.addGroupMember(GROUP, who);
      // A remote PEP's identity is a service account (#1760); a realm
      // with no Admin Write group to own it defers, so it is made one here,
      // as `xacml_pep_binding.js` does.
      if (!serviceAccounts.of(who)) {
        serviceAccounts.set(who, { serviceAccount: true, owners: [OWNER] });
      }
    }
    const jwkOf = function (key) {
      const full = nodeCrypto.createPublicKey(key).export({ format: 'jwk' });
      return { kty: full.kty, crv: full.crv, x: full.x, y: full.y };
    };
    const sign = function (key, input) {
      return nodeCrypto.sign('sha256', Buffer.from(input),
        { key: key, dsaEncoding: 'ieee-p1363' }).toString('base64url');
    };
    const proofFor = function (who, method, url, extra) {
      const head = b64u({ typ: 'dpop+jwt', alg: 'ES256',
                          jwk: jwkOf(keyOf[who]) });
      const body = b64u(Object.assign({
        jti: nodeCrypto.randomBytes(16).toString('hex'), htm: method,
        htu: url, iat: Math.floor(Date.now() / 1000) }, extra || {}));
      return head + '.' + body + '.' + sign(keyOf[who], head + '.' + body);
    };
    const tokenFor = async function (who, scope, resource) {
      const now = Math.floor(Date.now() / 1000);
      const head = b64u({ alg: 'ES256', typ: 'JWT' });
      const claims = b64u({ iss: who, sub: who, aud: TOKEN, iat: now,
        exp: now + 120, jti: nodeCrypto.randomBytes(16).toString('hex') });
      const form = new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        assertion: head + '.' + claims + '.' +
                   sign(keyOf[who], head + '.' + claims),
        client_id: 'sts-remote-pep', scope: scope,
        resource: resource }).toString();
      const got = await call(port, 'POST', '/oauth2/token',
        { 'Content-Type': 'application/x-www-form-urlencoded',
          DPoP: proofFor(who, 'POST', TOKEN) }, form);
      return (got.json && got.json.access_token) || '';
    };
    const atDoor = function (who, method, where, token, body) {
      const url = BASE + where.split('?')[0];
      const ath = nodeCrypto.createHash('sha256').update(token)
        .digest('base64url');
      const headers = { Authorization: 'DPoP ' + token,
                        DPoP: proofFor(who, method, url, { ath: ath }) };
      if (body !== undefined) {
        headers['Content-Type'] = 'application/json';
      }
      return call(port, method, where, headers,
                  body === undefined ? '' : JSON.stringify(body));
    };
    const pepToken = {};
    const zToken = {};
    for (const who of [PEP, LONE]) {
      pepToken[who] = await tokenFor(who, 'xacml:pep', BASE + '/xacml/pep');
      zToken[who] = await tokenFor(who, 'authzen:evaluate',
                                   BASE + '/access/v1');
    }
    note(!!pepToken[PEP] && !!zToken[PEP] && !!zToken[LONE],
         'the PEPs are issued xacml:pep and authzen:evaluate on their keys');
    const VERSION = 'iya-pep-rust/0.1.0';
    const embedded = function (extra) {
      return Object.assign({ name: PEP, kind: 'embedded', application: APP,
        mode: 'central', protocolVersion: 1, version: VERSION }, extra || {});
    };
    const register = function (who, body) {
      return atDoor(who, 'POST', '/xacml/pep/register', pepToken[who], body);
    };
    const heartbeat = function (body) {
      return atDoor(PEP, 'POST', '/xacml/pep/heartbeat', pepToken[PEP],
                    body);
    };

    // ---------------------------------------------------------------------
    // R. THE REGISTRATION.
    // ---------------------------------------------------------------------
    const asContainer = await register(PEP, { name: PEP, version: 'x' });
    const containerRow = peps.read(PEP) || {};
    note((asContainer.status === 201 || asContainer.status === 200) &&
         containerRow.kind === 'container' && containerRow.mode === '',
         'R1. a registration with no kind is a container, as an older ' +
         'PEP\'s is', brief(asContainer) + ' ' + containerRow.kind);
    const unbound = await register(PEP, embedded());
    note(unbound.status === 403 && unbound.json &&
         unbound.json.error === 'access_denied' &&
         /bound to no application/.test(unbound.text) &&
         (peps.read(PEP) || {}).kind === 'container',
         'R2. embedded with the entry bound to nothing is refused 403 ' +
         '(STS-XACML-0340) and the row is untouched', brief(unbound));
    const bound = binding.set({ name: PEP, application: APP2 });
    note(bound.ok, 'the PEP is bound to ' + APP2, JSON.stringify(bound));
    const elsewhere = await register(PEP, embedded());
    note(elsewhere.status === 403 && /is bound to/.test(elsewhere.text),
         'R3. embedded naming an application other than its binding is ' +
         'refused 403 (STS-XACML-0341)', brief(elsewhere));
    binding.set({ name: PEP, application: APP });
    const version2 = await register(PEP, embedded({ protocolVersion: 2 }));
    note(version2.status === 400 && version2.json &&
         version2.json.error === 'invalid_request' &&
         /protocol version 1/.test(version2.text),
         'R4. an unsupported protocolVersion is refused 400 (STS-XACML-0342)',
         brief(version2));
    const containerMode = await register(PEP, { name: PEP, mode: 'local' });
    note(containerMode.status === 400 && /an embedded PEP/.test(
           containerMode.text),
         'R5. mode with a container is refused 400 (STS-XACML-0343)',
         brief(containerMode));
    const good = await register(PEP, embedded());
    const row = peps.read(PEP) || {};
    note(good.status === 200 && row.kind === 'embedded' &&
         row.registeredApplication === APP && row.mode === 'central' &&
         row.protocolVersion === 1 && row.version === VERSION,
         'R6. the package\'s registration is accepted and the row says ' +
         'embedded, its application, central and protocol 1',
         brief(good) + ' ' + JSON.stringify({ kind: row.kind,
           application: row.registeredApplication, mode: row.mode,
           protocolVersion: row.protocolVersion }));
    const view = (xacmlAdmin.pepsJson(PEP).peps || [])[0] || {};
    note(view.kind === 'embedded' && view.application === APP &&
         view.registeredApplication === APP && view.mode === 'central' &&
         view.protocolVersion === 1,
         'R7. the console\'s row carries kind, application, mode and ' +
         'protocol version', JSON.stringify(view).slice(0, 300));

    // ---------------------------------------------------------------------
    // H. THE HEARTBEAT.
    // ---------------------------------------------------------------------
    const beat = await heartbeat(embedded({ decisions: 4, allowed: 3,
      refused: 1, undischargeable: 0, policyEvents: 'excluded' }));
    note(beat.status === 200 && (peps.read(PEP) || {}).policyEvents ===
         'excluded',
         'H1. a heartbeat\'s policyEvents is stored', brief(beat));
    const bad = await heartbeat({ name: PEP, policyEvents: 'often' });
    note(bad.status === 400 && (peps.read(PEP) || {}).policyEvents ===
         'excluded',
         'H2. a policyEvents outside the four is refused 400 ' +
         '(STS-XACML-0344) and nothing changes', brief(bad));
    const bare = await heartbeat({ name: PEP, decisions: 5 });
    const bareRow = peps.read(PEP) || {};
    note(bare.status === 200 && bareRow.kind === 'embedded' &&
         bareRow.mode === 'central' && bareRow.policyEvents === 'excluded',
         'H3. a heartbeat that leaves the identity out keeps it', brief(bare));
    const toLocal = await heartbeat(embedded({ mode: 'local',
      policyEvents: 'requested' }));
    const localRow = peps.read(PEP) || {};
    note(toLocal.status === 200 && localRow.mode === 'local' &&
         localRow.policyEvents === 'requested',
         'H4. a heartbeat in another mode is written', brief(toLocal));
    binding.set({ name: PEP, application: APP2 });
    const moved = await heartbeat(embedded({ mode: 'local' }));
    note(moved.status === 403 && (peps.read(PEP) || {})
         .registeredApplication === APP,
         'H5. once the binding moves, the next heartbeat is refused 403 ' +
         '(STS-XACML-0341) and the row is untouched', brief(moved));
    binding.set({ name: PEP, application: APP });
    const lone = await atDoor(LONE, 'POST', '/xacml/pep/heartbeat',
                              pepToken[LONE], { name: LONE });
    note(lone.status === 404,
         'H6. a heartbeat from a PEP never registered is still 404',
         brief(lone));

    // ---------------------------------------------------------------------
    // Z. AUTHZEN IN central MODE.
    // ---------------------------------------------------------------------
    const question = function (application) {
      const q = { subject: { type: 'user', id: 'someone-' + stamp },
                  action: { name: 'read' },
                  resource: { type: 'document', id: 'd1' } };
      if (application !== undefined) {
        q.context = { application: application };
      }
      return q;
    };
    const own = await atDoor(PEP, 'POST', '/access/v1/evaluation',
                             zToken[PEP], question(APP));
    note(own.status === 200 && own.json &&
         typeof own.json.decision === 'boolean',
         'Z1. the bound PEP, in no AuthZEN group, is admitted for its own ' +
         'application', brief(own));
    const implied = await atDoor(PEP, 'POST', '/access/v1/evaluation',
                                 zToken[PEP], question());
    note(implied.status === 200,
         'Z2. and with no context.application its one application is ' +
         'implied', brief(implied));
    const other = await atDoor(PEP, 'POST', '/access/v1/evaluation',
                               zToken[PEP], question(APP2));
    note(other.status === 403,
         'Z3. another application is refused 403 (STS-AUTHZEN-0025)',
         brief(other));
    const batch = await atDoor(PEP, 'POST', '/access/v1/evaluations',
      zToken[PEP], Object.assign(question(APP), {
        evaluations: [{ action: { name: 'read' } },
                      { action: { name: 'write' } }] }));
    note(batch.status === 200 && batch.json &&
         Array.isArray(batch.json.evaluations),
         'Z4. the batch is admitted for its own application', brief(batch));
    const batchOther = await atDoor(PEP, 'POST', '/access/v1/evaluations',
      zToken[PEP], Object.assign(question(APP2), {
        evaluations: [{ action: { name: 'read' } }] }));
    // A BATCH ANSWERS 200 WITH EACH ITEM'S OWN REFUSAL (AuthZEN 1.0's
    // evaluations): the scope refusal is the item's error, status 403.
    const itemOther = ((batchOther.json || {}).evaluations || [])[0] || {};
    note(batchOther.status === 200 && itemOther.decision === false &&
         ((itemOther.context || {}).error || {}).status === 403,
         'Z5. and refused for another, item by item (403)',
         brief(batchOther));
    const loneZ = await atDoor(LONE, 'POST', '/access/v1/evaluation',
                               zToken[LONE], question(APP));
    note(loneZ.status === 403,
         'Z6. a PEP bound to nothing holds no AUTHZEN_PEPS and is refused ' +
         'by the policy (STS-AUTHZEN-0024)', brief(loneZ));
    binding.clear({ name: PEP });
    const cleared = await atDoor(PEP, 'POST', '/access/v1/evaluation',
                                 zToken[PEP], question(APP));
    note(cleared.status === 403,
         'Z7. its binding cleared, the same PEP is refused', brief(cleared));

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
  const out = path.join(os.tmpdir(), 'pe-' + process.pid + '-' +
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
                                  PE_ROOT: ROOT, PE_OUT: out }),
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
  name: 'xacml_pep_embedded',
  describe: 'an embedded remote PEP: kind, application, mode and protocol ' +
            'version on its registration and heartbeat, refused unless its ' +
            'binding agrees, and an AuthZEN caller scoped to its bound ' +
            'application (#2026)',
  run: run
};
