// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/remote_pep_token_door.js
// ===========================================================================
// A REMOTE PEP ON A DPoP-BOUND ACCESS TOKEN INSTEAD OF A CERTIFICATE
// (#1827's follow-up, rcbj-approved plan, 2026-11-16, phase 1).
//
// In a CHILD PROCESS with the whole stack on an ephemeral PLAIN-HTTP port —
// so no client certificate can arrive, which is the point: every door below
// is reached on the token alone. A PEP that is a person entry in
// `remote-peps` holding one ES256 key pair signs its RFC 7523
// self-assertion, presents it through `sts-remote-pep` with a DPoP proof by
// the same key, and is issued a DPoP-bound token per audience:
//
//   S. the seeded objects: `sts-xacml-pep-api` defines `xacml:pep` for the
//      realm's /xacml/pep; `sts-remote-pep` holds the three delegated
//      permission grants; one taken off comes back at the next seed.
//   I. issuance: a request with no DPoP proof is refused; `xacml:pep` and
//      `authzen:evaluate` and `xacml:pep-audit` are issued DPoP-bound to
//      the PEP; somebody not in the group is not issued `xacml:pep`.
//   X. the PEP door: register (named by the username, the row's thumbprint
//      the DPoP key's RFC 7638 thumbprint), the policy pull, a heartbeat,
//      the PIP reached; the token sent as Bearer, a replayed proof, a token
//      for another audience, and no proof at all each refused 401 with a
//      DPoP challenge; a server nonce asked for and honoured;
//      `xacml.pepAuthentication` certificate refusing the token, token
//      refusing a request without one.
//   A. the push to /admin-api/pep-audit on a DPoP-bound token with no
//      certificate.
//   Z. AuthZEN under `authzen.callerAuthentication` mtls: the PEP's token is
//      authenticated (the policy then decides on AUTHZEN_PEPS), somebody
//      outside the remote PEPs' group on the same client is refused, and
//      `xacml.pepAuthentication` certificate refuses it.
//   G. out of the group, the PEP's token is refused by the policy.
//   C. what a DPoP-checked call costs in process (reported, not asserted).
//
// WHAT IS NOT HERE: anything needing a TLS socket — a PEP presenting both a
// certificate and a token, `certificate` mode with a certificate, a
// certificate-bound token beside a DPoP one. Those are the protocol jobs'.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'remote_pep_token_door',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.RPT_ROOT;
  const OUT = process.env.RPT_OUT;
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
    return r.status + ' ' + String(r.headers['www-authenticate'] || '') +
      ' ' + String(r.text || '').slice(0, 300);
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
    const dpop = require(ROOT_DIR + '/oauth-oidc/dpop');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const BASE = 'http://127.0.0.1:' + port;
    const TOKEN = BASE + '/oauth2/token';
    const stamp = Date.now().toString(36);
    const PEP = 'rpt-pep-' + stamp;
    const STRANGER = 'rpt-stranger-' + stamp;
    const GROUP = String(config.value('roles.remotePepGroup') ||
                         'remote-peps');

    // ---------------------------------------------------------------------
    // S. THE SEEDED OBJECTS.
    // ---------------------------------------------------------------------
    const api = applications.get('sts-xacml-pep-api') || { fields: {} };
    const defined = [].concat(api.fields.oauthPermission || [])
      .map(function (one) { return String(one).split('|')[0]; });
    const audiences = [].concat(api.fields.oauthAudience || []);
    note(defined.indexOf('xacml:pep') >= 0 &&
         audiences.some(function (one) { return /\/xacml\/pep$/.test(one); }),
         'S1. sts-xacml-pep-api defines xacml:pep, audienced to /xacml/pep',
         defined.join(' ') + ' | ' + audiences.join(' '));
    const grantsOf = function () {
      const viewed = applications.get('sts-remote-pep') || { fields: {} };
      return [].concat(viewed.fields.oauthDelegatedPermission || [])
        .map(String);
    };
    const wanted = ['urn:sts:admin-api:xacml:pep-audit',
                    'urn:sts:xacml-pep-api:xacml:pep',
                    'urn:sts:authzen-api:authzen:evaluate'];
    note(wanted.every(function (one) {
      return grantsOf().indexOf(one) >= 0;
    }), 'S2. sts-remote-pep holds the three delegated permission grants',
         grantsOf().join(' '));
    applications.updateApplication('sts-remote-pep',
      { attribute: 'oauthDelegatedPermission', mode: 'remove',
        value: 'urn:sts:xacml-pep-api:xacml:pep' });
    const taken = grantsOf().indexOf('urn:sts:xacml-pep-api:xacml:pep') < 0;
    applications.seedInternalApplications({ scope: 'default' });
    note(taken && grantsOf().indexOf('urn:sts:xacml-pep-api:xacml:pep') >= 0,
         'S3. a grant taken off an existing sts-remote-pep comes back at the ' +
         'next seed (the upgrade)', taken + ' ' + grantsOf().join(' '));

    // ---------------------------------------------------------------------
    // The PEP and the stranger, each holding one key pair.
    // ---------------------------------------------------------------------
    const built = pki.hasChain() ? { ok: true } : await pki.start({});
    note(built.ok, 'a certificate authority exists to issue from',
         (built.errors || []).join(' '));
    const keyOf = {};
    for (const who of [PEP, STRANGER]) {
      ldap.createUser(who, { invent: false });
      let issued = await pkiAdmin.pkiAction({ action: 'issue',
        target: 'person', purpose: 'jwt', identifier: who,
        leafKeyAlg: 'ec-p256' });
      if (!(issued.ok && issued.privateKeyPem)) {
        issued = await pkiAdmin.pkiAction({ action: 'issue',
          target: 'person', purpose: 'jwt', identifier: who,
          leafKeyAlg: 'rsa-2048' });
      }
      note(issued.ok && /PRIVATE KEY/.test(String(issued.privateKeyPem)),
           'a key pair is issued to ' + who, issued.why || '');
      keyOf[who] = nodeCrypto.createPrivateKey(issued.privateKeyPem);
    }
    ldap.addGroupMember(GROUP, PEP);

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
    const thumbprintOf = function (key) {
      const jwk = jwkOf(key);
      const canonical = jwk.kty === 'EC'
        ? JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y })
        : JSON.stringify({ e: jwk.e, kty: jwk.kty, n: jwk.n });
      return nodeCrypto.createHash('sha256').update(canonical)
        .digest('base64url');
    };
    const proofFor = function (who, method, url, extra) {
      const key = keyOf[who];
      const head = b64u({ typ: 'dpop+jwt', alg: algOf(key),
                          jwk: jwkOf(key) });
      const body = b64u(Object.assign({
        jti: nodeCrypto.randomBytes(16).toString('hex'), htm: method,
        htu: url, iat: Math.floor(Date.now() / 1000) }, extra || {}));
      return head + '.' + body + '.' + sign(key, head + '.' + body);
    };
    const athOf = function (token) {
      return nodeCrypto.createHash('sha256').update(token)
        .digest('base64url');
    };
    const assertionFor = function (who) {
      const head = b64u({ alg: algOf(keyOf[who]), typ: 'JWT' });
      const now = Math.floor(Date.now() / 1000);
      const body = b64u({ iss: who, sub: who, aud: TOKEN, iat: now,
                          exp: now + 120,
                          jti: nodeCrypto.randomBytes(16).toString('hex') });
      return head + '.' + body + '.' + sign(keyOf[who], head + '.' + body);
    };
    const tokenFor = function (who, scope, resource, withProof) {
      const form = new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        assertion: assertionFor(who), client_id: 'sts-remote-pep',
        scope: scope, resource: resource }).toString();
      const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
      if (withProof !== false) {
        headers.DPoP = proofFor(who, 'POST', TOKEN);
      }
      return call(port, 'POST', '/oauth2/token', headers, form);
    };
    const atDoor = function (who, method, where, token, opts) {
      const o = opts || {};
      const url = BASE + where.split('?')[0];
      const proof = o.proof || proofFor(who, method, url,
        Object.assign({ ath: athOf(token) },
                      o.nonce ? { nonce: o.nonce } : {}));
      const headers = { Authorization: (o.scheme || 'DPoP') + ' ' + token,
                        DPoP: proof };
      if (o.contentType) {
        headers['Content-Type'] = o.contentType;
      }
      return call(port, method, where, headers, o.body || '');
    };

    // ---------------------------------------------------------------------
    // I. ISSUANCE.
    // ---------------------------------------------------------------------
    const noProof = await tokenFor(PEP, 'xacml:pep', BASE + '/xacml/pep',
                                   false);
    note(noProof.status === 400,
         'I1. a token request through sts-remote-pep with no DPoP proof is ' +
         'refused', brief(noProof));
    const got = await tokenFor(PEP, 'xacml:pep', BASE + '/xacml/pep');
    const token = got.json && got.json.access_token;
    const claims = token ? JSON.parse(Buffer.from(token.split('.')[1],
                                                  'base64url')) : {};
    note(got.status === 200 && !!token &&
         String(got.json.token_type) === 'DPoP' &&
         / ?xacml:pep ?/.test(' ' + got.json.scope + ' ') &&
         claims.cnf && claims.cnf.jkt === thumbprintOf(keyOf[PEP]),
         'I2. the PEP is issued xacml:pep, DPoP-bound to its assertion key',
         brief(got));
    const zGot = await tokenFor(PEP, 'authzen:evaluate', BASE + '/access/v1');
    const zToken = zGot.json && zGot.json.access_token;
    note(zGot.status === 200 && !!zToken &&
         / ?authzen:evaluate ?/.test(' ' + zGot.json.scope + ' '),
         'I3. and authzen:evaluate for /access/v1', brief(zGot));
    const aGot = await tokenFor(PEP, 'xacml:pep-audit', BASE + '/admin-api');
    const aToken = aGot.json && aGot.json.access_token;
    note(aGot.status === 200 && !!aToken,
         'I4. and xacml:pep-audit for /admin-api over a connection with no ' +
         'certificate: the DPoP key stands for the certificate binding',
         brief(aGot));
    const sGot = await tokenFor(STRANGER, 'xacml:pep', BASE + '/xacml/pep');
    const sToken = sGot.json && sGot.json.access_token;
    note(!(sGot.json && / ?xacml:pep ?/.test(
           ' ' + String(sGot.json.scope || '') + ' ')),
         'I5. somebody not in ' + GROUP + ' is not issued xacml:pep',
         brief(sGot));

    // ---------------------------------------------------------------------
    // X. THE PEP DOOR.
    // ---------------------------------------------------------------------
    const registered = await atDoor(PEP, 'POST', '/xacml/pep/register', token,
      { contentType: 'application/json',
        body: JSON.stringify({ name: 'somebody-else', version: 't' }) });
    const row = peps.read(PEP) || {};
    note((registered.status === 201 || registered.status === 200) &&
         registered.json && registered.json.authenticated === true &&
         String(registered.json.name).toLowerCase() === PEP.toLowerCase(),
         'X1. the PEP registers on its token alone, named by its username ' +
         '(not the name the body sent)', brief(registered));
    note(row.thumbprint === thumbprintOf(keyOf[PEP]) &&
         row.authenticated === true,
         'X2. its row carries the DPoP key\'s RFC 7638 thumbprint',
         JSON.stringify({ thumbprint: row.thumbprint,
                          authenticated: row.authenticated }));
    const pulled = await atDoor(PEP, 'GET', '/xacml/pep/policies', token);
    note(pulled.status === 200 && pulled.json && !!pulled.json.syncToken,
         'X3. it pulls the policies', brief(pulled));
    const beat = await atDoor(PEP, 'POST', '/xacml/pep/heartbeat', token,
      { contentType: 'application/json',
        body: JSON.stringify({ syncToken: pulled.json &&
                                          pulled.json.syncToken,
                               decisions: 3 }) });
    note(beat.status === 200, 'X4. it reports a heartbeat', brief(beat));
    const settings = await atDoor(PEP, 'GET', '/xacml/pep/settings', token);
    note(settings.status === 200, 'X5. it reads its managed settings',
         brief(settings));
    const pip = await atDoor(PEP, 'POST', '/xacml/pip', token,
      { contentType: 'application/xml', body: '<nonsense/>' });
    note(pip.status !== 401 && pip.status !== 403,
         'X6. the PIP admits it (the body is then refused on its own terms)',
         brief(pip));
    const bearer = await atDoor(PEP, 'GET', '/xacml/pep/policies', token,
                                { scheme: 'Bearer' });
    note(bearer.status === 401 &&
         /^DPoP/.test(String(bearer.headers['www-authenticate'] || '')),
         'X7. the token sent as Bearer is refused 401 with a DPoP challenge',
         brief(bearer));
    const once = proofFor(PEP, 'GET', BASE + '/xacml/pep/policies',
                          { ath: athOf(token) });
    const first = await atDoor(PEP, 'GET', '/xacml/pep/policies', token,
                               { proof: once });
    const replay = await atDoor(PEP, 'GET', '/xacml/pep/policies', token,
                                { proof: once });
    note(first.status === 200 && replay.status === 401,
         'X8. a replayed proof is refused', first.status + ' / ' +
         brief(replay));
    const elsewhere = await atDoor(PEP, 'GET', '/xacml/pep/policies',
                                   zToken || 'none');
    note(elsewhere.status === 401 && /audience/.test(elsewhere.text),
         'X9. a token for /access/v1 is refused at /xacml/pep (audience)',
         brief(elsewhere));
    const noDpop = await call(port, 'GET', '/xacml/pep/policies',
                              { Authorization: 'DPoP ' + token }, '');
    note(noDpop.status === 401, 'X10. a token with no proof is refused',
         brief(noDpop));
    if (sToken) {
      const stranger = await atDoor(STRANGER, 'GET', '/xacml/pep/policies',
                                    sToken);
      note(stranger.status === 401 || stranger.status === 403,
           'X11. the stranger\'s token, whatever it carries, is refused',
           brief(stranger));
    }
    config.setOverride('oauth2.dpopNonceRequired', 'true');
    const wantNonce = await atDoor(PEP, 'GET', '/xacml/pep/policies', token);
    const nonce = String(wantNonce.headers['dpop-nonce'] || '');
    const withNonce = await atDoor(PEP, 'GET', '/xacml/pep/policies', token,
                                   { nonce: nonce });
    config.setOverride('oauth2.dpopNonceRequired', 'false');
    note(wantNonce.status === 401 && !!nonce &&
         /use_dpop_nonce/.test(String(wantNonce.headers['www-authenticate'])) &&
         withNonce.status === 200,
         'X12. a server nonce is asked for (401 use_dpop_nonce, DPoP-Nonce) ' +
         'and the retry with it is admitted',
         brief(wantNonce) + ' / ' + withNonce.status);
    config.setOverride('xacml.pepAuthentication', 'certificate');
    const certOnly = await atDoor(PEP, 'GET', '/xacml/pep/policies', token);
    config.setOverride('xacml.pepAuthentication', 'token');
    const tokenOnly = await call(port, 'GET', '/xacml/pep/policies', {}, '');
    const tokenOk = await atDoor(PEP, 'GET', '/xacml/pep/policies', token);
    config.setOverride('xacml.pepAuthentication', 'either');
    note(certOnly.status === 401 && /certificate/.test(certOnly.text),
         'X13. xacml.pepAuthentication certificate refuses the token',
         brief(certOnly));
    note(tokenOnly.status === 401 && /pepAuthentication is token/.test(
           tokenOnly.text) && tokenOk.status === 200,
         'X14. xacml.pepAuthentication token refuses a request without one ' +
         'and admits the token', brief(tokenOnly) + ' / ' + tokenOk.status);

    // ---------------------------------------------------------------------
    // A. THE PUSH ON A DPoP-BOUND TOKEN.
    // ---------------------------------------------------------------------
    const pushed = await atDoor(PEP, 'POST', '/admin-api/pep-audit',
      aToken || 'none', { contentType: 'application/json',
        body: JSON.stringify({ instance: nodeCrypto.randomBytes(8)
                                 .toString('hex'),
                               events: [{ seq: 1, kind: 'enforcement',
                                          decision: 'Permit',
                                          allowed: true }] }) });
    note(pushed.status === 200 && pushed.json &&
         pushed.json.acknowledged === 1,
         'A1. the decision-record push is taken on a DPoP-bound token with ' +
         'no certificate (STS-API-0137 lets the DPoP key stand)',
         brief(pushed));

    // ---------------------------------------------------------------------
    // Z. AUTHZEN, UNDER callerAuthentication mtls.
    // ---------------------------------------------------------------------
    config.setOverride('authzen.callerAuthentication', 'mtls');
    const question = JSON.stringify({
      subject: { type: 'user', id: 'nobody-' + stamp },
      action: { name: 'read' },
      resource: { type: 'document', id: 'd1' } });
    const evaluated = await atDoor(PEP, 'POST', '/access/v1/evaluation',
      zToken || 'none', { contentType: 'application/json', body: question });
    note(evaluated.status !== 401 && /evaluation|decision|policy/i.test(
           evaluated.text),
         'Z1. under mtls the PEP\'s token is authenticated as the PEP\'s ' +
         'entry (the access policy then decides on AUTHZEN_PEPS)',
         brief(evaluated));
    const zNone = await call(port, 'POST', '/access/v1/evaluation',
      { 'Content-Type': 'application/json' }, question);
    note(zNone.status === 401,
         'Z2. and with nothing presented the certificate door still refuses',
         brief(zNone));
    const strangerZ = await tokenFor(STRANGER, 'authzen:evaluate',
                                     BASE + '/access/v1');
    const strangerZToken = strangerZ.json && strangerZ.json.access_token;
    if (strangerZToken) {
      const refused = await atDoor(STRANGER, 'POST', '/access/v1/evaluation',
        strangerZToken, { contentType: 'application/json',
                          body: question });
      note(refused.status === 403 && /not a remote PEP/.test(refused.text),
           'Z3. a token of sts-remote-pep for somebody outside ' + GROUP +
           ' is refused (STS-AUTHZEN-0120)', brief(refused));
    } else {
      note(true, 'Z3. (the stranger was not issued authzen:evaluate)',
           brief(strangerZ));
    }
    config.setOverride('xacml.pepAuthentication', 'certificate');
    const zCert = await atDoor(PEP, 'POST', '/access/v1/evaluation',
      zToken || 'none', { contentType: 'application/json', body: question });
    config.setOverride('xacml.pepAuthentication', 'either');
    note(zCert.status === 401 && /certificate/.test(zCert.text),
         'Z4. xacml.pepAuthentication certificate refuses it here too ' +
         '(STS-AUTHZEN-0121)', brief(zCert));

    // ---------------------------------------------------------------------
    // C. WHAT A DPoP-CHECKED CALL COSTS, IN PROCESS (reported).
    // ---------------------------------------------------------------------
    const ROUNDS = 200;
    let started = process.hrtime.bigint();
    for (let i = 0; i < ROUNDS; i++) {
      await atDoor(PEP, 'GET', '/xacml/pep/policies', token);
    }
    const perCall = Number(process.hrtime.bigint() - started) / 1e6 / ROUNDS;
    const sample = proofFor(PEP, 'GET', BASE + '/x', { ath: athOf(token) });
    started = process.hrtime.bigint();
    for (let i = 0; i < ROUNDS; i++) {
      dpop.verifyProof(proofFor(PEP, 'GET', BASE + '/x',
                                { ath: athOf(token) }),
        { htm: 'GET', htu: BASE + '/x', accessToken: token,
          expectedJkt: claims.cnf && claims.cnf.jkt });
    }
    const perProof = Number(process.hrtime.bigint() - started) / 1e6 / ROUNDS;
    note(!!sample, 'C1. cost: ' + perCall.toFixed(2) + ' ms per policy pull ' +
         'on a DPoP-bound token over HTTP; ' + perProof.toFixed(3) +
         ' ms per proof built and verified (memory store)', '');

    // ---------------------------------------------------------------------
    // G. OUT OF THE GROUP, OUT OF THE DOOR.
    // ---------------------------------------------------------------------
    ldap.dropMemberships(ldap.locateEntry(PEP).dn);
    const removed = await atDoor(PEP, 'GET', '/xacml/pep/policies', token);
    note(removed.status === 403,
         'G1. taken out of ' + GROUP + ', the PEP\'s token is refused by ' +
         'the access policy', brief(removed));

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
  const out = path.join(os.tmpdir(), 'rpt-' + process.pid + '-' +
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
                                  RPT_ROOT: ROOT, RPT_OUT: out }),
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
  name: 'remote_pep_token_door',
  describe: 'a remote PEP reaches /xacml/pep, /xacml/pip, /admin-api/' +
            'pep-audit and /access/v1 on a DPoP-bound access token from ' +
            'sts-remote-pep instead of a client certificate (#1827)',
  run: run
};
