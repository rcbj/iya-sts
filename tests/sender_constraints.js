'use strict';
//
// File: sender_constraints.js
//
// ===========================================================================
// ASKING FOR MORE THAN EITHER SPECIFICATION REQUIRES (#34, 2026-09-15).
//
// `oauth-oidc/sender_constraints.js` argues the design; this is what holds it.
// The claim worth testing is not "DPoP works" — `tests/vendored/sts_dpop.js`
// does that — but the five settings' own behaviour, and in particular the
// three things a reader of the code would have to take on trust:
//
//   1. THE DECISIONS. Every branch of the four refusals, with the code each
//      carries, read per realm so that one realm requiring a constraint does
//      not make the next one require it.
//   2. THE EXEMPTION IS THE ONE THAT WAS ARGUED. `MTLS_EXEMPT_CLIENTS` is
//      written out in that file because it may not require `oidc_rp.js`, so
//      this is what stops the copy drifting — and it asserts that the
//      debugger's client is NOT on it, which is a decision (#34, 6) rather
//      than an oversight.
//   3. THE DOORS, in a child process on an ephemeral port: the token endpoint
//      refusing to hand out an unconstrained refresh token, the refresh grant
//      refusing an unbound one rather than binding it, UserInfo refusing a
//      Bearer token while DPoP is required, and `/admin-api` refusing a
//      DPoP-bound token presented as Bearer — which it accepted until this
//      change, in every mode.
//
// **SECTION 3 IS IN A CHILD** for `tests/refresh_token_encryption.js`'s
// reason: loading the whole protocol stack into `run.js`'s one process builds
// a certificate authority and registers every route on the shared app, which
// changes what later files see.
//
// What is NOT here: the mutual TLS doors end to end. They need a listener with
// `requestCert` and a client certificate issued by this service's own CA, and
// `tests/rfc8705_mtls.js` section 3 already builds exactly that — the two
// settings' end-to-end halves belong beside it rather than in a second child
// that would build the same thing again. The DECISIONS for both are here.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'sender_constraints',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

const config = require('../common/config');
const realms = require('../common/realms');
const oidcRp = require('../common/oidc_rp');
const sc = require('../oauth-oidc/sender_constraints');

// Every realm this file makes, so that it can take them away again. An
// in-process test runs in `run.js`'s one process, and two later files assert
// that only the default realm exists — a throwaway left standing here is a
// failure over there, attributed to a file that did nothing wrong.
const MADE = [];

// A realm of its own per section, so that a setting one section turns on
// cannot reach the next. `tests/oauth21_mode.js`'s pattern.
function throwaway(id, overrides) {
  log.debug("Entering throwaway(). id=" + id);
  if (!realms.get(id)) {
    realms.create({ id: id, label: id });
    MADE.push(id);
  }
  Object.keys(overrides || {}).forEach(function (key) {
    realms.setOverride(id, key, String(overrides[key]));
  });
  log.debug("Leaving throwaway().");
  return realms.get(id);
}

function inRealm(id, fn) {
  log.debug("Entering inRealm().");
  const answer = realms.run(realms.get(id), fn);
  log.debug("Leaving inRealm().");
  return answer;
}

// ---------------------------------------------------------------------------
// 1. THE DECISIONS.
// ---------------------------------------------------------------------------
function checkTheDecisions(t) {
  log.debug("Entering checkTheDecisions().");
  t.log.info('=== 1. the decisions, per realm ===');

  throwaway('sc-off', {});
  throwaway('sc-rotation', { 'oauth2.refreshTokenRotation': 'true' });
  throwaway('sc-dpop', { 'oauth2.refreshTokenRequireDpop': 'true' });
  throwaway('sc-mtls', { 'oauth2.refreshTokenRequireMtls': 'true' });
  throwaway('sc-at-dpop', { 'oauth2.accessTokenRequireDpop': 'true' });
  throwaway('sc-at-mtls', { 'oauth2.accessTokenRequireMtls': 'true' });

  t.equal(inRealm('sc-off', sc.rotationRequired), false,
          '1a. with neither mode nor the setting, nothing rotates');
  t.equal(inRealm('sc-rotation', sc.rotationRequired), true,
          '1b. the setting alone requires rotation');
  t.equal(inRealm('sc-rotation', sc.rotationSource),
          'oauth2.refreshTokenRotation',
          '1c. and says so');
  t.equal(inRealm('sc-off', sc.rotationRequired), false,
          '1d. and the realm next door is untouched — the settings are per ' +
          'realm, which is what makes one realm strict and another not');

  // A compliance mode still wins, and is NAMED ahead of the setting: an
  // operator who turned the setting off while a mode is on must not be told
  // the setting is what is rotating their tokens.
  throwaway('sc-mode', { 'oauth2.rfc9700': 'true',
                         'oauth2.refreshTokenRotation': 'false' });
  t.equal(inRealm('sc-mode', sc.rotationRequired), true,
          '1e. RFC 9700 mode rotates whatever the setting says');
  t.equal(inRealm('sc-mode', sc.rotationSource), 'RFC 9700 mode',
          '1f. and the mode is named rather than the setting');

  // --- issuance -----------------------------------------------------------
  t.equal(inRealm('sc-off', function () {
    return sc.refreshIssuanceRefusal({ grant: 'authorization_code' });
  }), null, '1g. nothing is refused with every setting off');

  const noProof = inRealm('sc-dpop', function () {
    return sc.refreshIssuanceRefusal({ grant: 'authorization_code' });
  });
  t.equal(noProof && noProof.errorCode, 'STS-OAUTH-0521',
          '1h. a token request with no proof is refused when DPoP is required');
  t.equal(noProof && noProof.error, 'invalid_dpop_proof',
          '1i. as invalid_dpop_proof');
  t.equal(inRealm('sc-dpop', function () {
    return sc.refreshIssuanceRefusal({ grant: 'authorization_code',
                                       dpopJkt: 'a-thumbprint' });
  }), null, '1j. and passes once a proof came');

  const noCert = inRealm('sc-mtls', function () {
    return sc.refreshIssuanceRefusal({ grant: 'authorization_code',
                                       mtlsAvailable: true });
  });
  t.equal(noCert && noCert.errorCode, 'STS-OAUTH-0522',
          '1k. a token request with no client certificate is refused when ' +
          'mutual TLS is required');
  t.equal(noCert && noCert.error, 'invalid_client',
          '1l. as invalid_client, which is RFC 6749 section 5.2\'s 401');

  // The precondition, and the reason it is a refusal rather than a startup
  // failure: an operator may turn this on over HTTP, and a service that
  // refused to start would take every other protocol down with it.
  const noTls = inRealm('sc-mtls', function () {
    return sc.refreshIssuanceRefusal({ grant: 'authorization_code',
                                       mtlsAvailable: false });
  });
  t.equal(noTls && noTls.errorCode, 'STS-OAUTH-0527',
          '1m. and a port that cannot ask for a certificate is its own ' +
          'refusal, naming the reason');

  t.equal(inRealm('sc-mtls', function () {
    return sc.refreshIssuanceRefusal({ grant: 'authorization_code',
                                       mtlsAvailable: true, exempt: true });
  }), null, '1n. the exempt clients are not refused by the mutual TLS row');

  // --- redemption ---------------------------------------------------------
  const unbound = inRealm('sc-dpop', function () {
    return sc.refreshRedemptionRefusal({ provedJkt: 'a-thumbprint',
                                         tokenJkt: '' });
  });
  t.equal(unbound && unbound.errorCode, 'STS-OAUTH-0523',
          '1o. AN UNBOUND REFRESH TOKEN IS REFUSED, not bound to whoever ' +
          'presents it first');
  t.equal(unbound && unbound.error, 'invalid_grant',
          '1p. as invalid_grant — the token is the problem, not the client');

  const noProofAtRefresh = inRealm('sc-dpop', function () {
    return sc.refreshRedemptionRefusal({ tokenJkt: 'a-thumbprint' });
  });
  t.equal(noProofAtRefresh && noProofAtRefresh.errorCode, 'STS-OAUTH-0524',
          '1q. and a refresh with no proof at all is its own refusal');

  t.equal(inRealm('sc-dpop', function () {
    return sc.refreshRedemptionRefusal({ tokenJkt: 'k', provedJkt: 'k' });
  }), null, '1r. a bound token with its own proof passes');

  // RFC 8705 section 7.1: the client authenticated with its certificate on
  // this request and owns the token, so the token's own thumbprint is not
  // compared — which is what lets it present the certificate its old one
  // expired into.
  t.equal(inRealm('sc-mtls', function () {
    return sc.refreshRedemptionRefusal({ mtlsAvailable: true,
                                         section71: true,
                                         tokenThumbprint: '' });
  }), null, '1s. section 7.1 passes a certificate-authenticated client with ' +
            'no thumbprint on its token');
  const unboundCert = inRealm('sc-mtls', function () {
    return sc.refreshRedemptionRefusal({ mtlsAvailable: true,
                                         certificateVerified: true,
                                         tokenThumbprint: '' });
  });
  t.equal(unboundCert && unboundCert.errorCode, 'STS-OAUTH-0525',
          '1t. and everybody else is refused an unbound one');

  // --- the resource side --------------------------------------------------
  const bearer = inRealm('sc-at-dpop', function () {
    return sc.accessTokenRefusal({ where: 'UserInfo', boundJkt: '' });
  });
  t.equal(bearer && bearer.errorCode, 'STS-OAUTH-0528',
          '1u. a bearer token is refused at a resource when DPoP is required');
  t.equal(bearer && bearer.error, 'invalid_token',
          '1v. as invalid_token, which is what a resource server answers');
  const unproved = inRealm('sc-at-dpop', function () {
    return sc.accessTokenRefusal({ boundJkt: 'k', proofOk: false });
  });
  t.equal(unproved && unproved.errorCode, 'STS-OAUTH-0529',
          '1w. and a bound token with no proof beside it is refused too');
  t.equal(inRealm('sc-at-dpop', function () {
    return sc.accessTokenRefusal({ boundJkt: 'k', proofOk: true });
  }), null, '1x. a proved bound token passes');

  const unboundAt = inRealm('sc-at-mtls', function () {
    return sc.accessTokenRefusal({ mtlsAvailable: true, boundThumbprint: '' });
  });
  t.equal(unboundAt && unboundAt.errorCode, 'STS-OAUTH-0530',
          '1y. and the mutual TLS row refuses a token carrying no thumbprint');
  const wrongCert = inRealm('sc-at-mtls', function () {
    return sc.accessTokenRefusal({ mtlsAvailable: true, boundThumbprint: 't',
                                   certificateMatches: false,
                                   certificate: true });
  });
  t.equal(wrongCert && wrongCert.errorCode, 'STS-OAUTH-0531',
          '1z. or a connection carrying a different one');
  log.debug("Leaving checkTheDecisions().");
}

// ---------------------------------------------------------------------------
// 2. THE EXEMPTION.
// ---------------------------------------------------------------------------
function checkTheExemption(t) {
  log.debug("Entering checkTheExemption().");
  t.log.info('=== 2. the exemption is the one that was argued ===');

  const hosted = Object.keys(oidcRp.SURFACES).map(function (id) {
    return oidcRp.SURFACES[id].clientId;
  });
  sc.MTLS_EXEMPT_CLIENTS.forEach(function (clientId) {
    t.check(hosted.indexOf(clientId) >= 0,
            '2a. every exempt client is one of this service\'s own relying ' +
            'parties (' + clientId + ')', hosted.join(', '));
  });
  t.equal(sc.MTLS_EXEMPT_CLIENTS.slice().sort().join(','),
          'sts-admin-console,sts-user-portal',
          '2b. and the list is the console and the portal, nothing else');
  t.equal(sc.mtlsExemptClient('sts-debugger-ui'), false,
          '2c. THE DEBUGGER IS NOT EXEMPT — it is an ordinary client of this ' +
          'authorization server, configured to meet whatever the realm it ' +
          'points at requires (#34, decision 6)');
  t.equal(sc.mtlsExemptClient('sts-admin-console'), true,
          '2d. the console is');
  t.equal(sc.mtlsExemptClient(''), false,
          '2e. and an unnamed client is not');

  // The exemption is the mutual TLS row's ALONE. The two surfaces carry a
  // DPoP key of their own instead, which is why that half needed no exemption
  // — see tests/oidc_rp_dpop.js.
  throwaway('sc-both', { 'oauth2.refreshTokenRequireDpop': 'true',
                         'oauth2.refreshTokenRequireMtls': 'true' });
  const consoleAtIssuance = inRealm('sc-both', function () {
    return sc.refreshIssuanceRefusal({ grant: 'authorization_code',
                                       mtlsAvailable: true,
                                       exempt: true });
  });
  t.equal(consoleAtIssuance && consoleAtIssuance.errorCode, 'STS-OAUTH-0521',
          '2f. an exempt client with no DPoP proof is still refused: the ' +
          'exemption covers the certificate row and not the key row');
  log.debug("Leaving checkTheExemption().");
}

// ---------------------------------------------------------------------------
// 3. THE DOORS, in a child process.
// ---------------------------------------------------------------------------
function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.SC_ROOT;
  const OUT = process.env.SC_OUT;
  const http = require('http');
  const nodeCrypto = require('crypto');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  function request(port, method, urlPath, form, headers) {
    return new Promise(function (resolve) {
      const body = form ? new URLSearchParams(form).toString() : '';
      const req = http.request({ host: '127.0.0.1', port: port, path: urlPath,
        method: method,
        headers: Object.assign({
          'content-type': 'application/x-www-form-urlencoded',
          'content-length': Buffer.byteLength(body) }, headers || {}) },
        function (res) {
          let text = '';
          res.on('data', function (c) { text += c; });
          res.on('end', function () {
            let json = null;
            try {
              json = JSON.parse(text);
            } catch (e) {
              // Not JSON — an HTML refusal page is the interesting case, and
              // the raw text is what the finding carries. No logger here.
              json = null;
            }
            resolve({ status: res.statusCode, text: text, json: json,
                      headers: res.headers });
          });
        });
      req.end(body);
    });
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    const config2 = require(ROOT_DIR + '/common/config');
    const ldap = require(ROOT_DIR + '/ldap/ldap_server');
    const applications = require(ROOT_DIR + '/common/applications');
    const oidcRp2 = require(ROOT_DIR + '/common/oidc_rp');
    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const base = 'http://127.0.0.1:' + port;
    const client = { client_id: 'sc-client',
                     client_secret: 'sc-client-secret-0123456789' };
    ldap.createUser('sc-alice', { invent: false });
    applications.createApplication({ identifier: 'sc-client',
      protocols: ['oauth2'],
      fields: { oauthClientId: 'sc-client',
                oauthClientSecret: client.client_secret,
                oauthTokenEndpointAuthMethod: 'client_secret_post',
                oauthGrantType: ['password', 'refresh_token'] } });

    const key = oidcRp2.dpopKey();
    const proofFor = function (method, url) {
      return oidcRp2.dpopProof(key, method, url, {});
    };
    const issue = function (headers) {
      return request(port, 'POST', '/oauth2/token', Object.assign({
        grant_type: 'password', username: 'sc-alice', password: 'anything',
        scope: 'openid offline_access' }, client), headers);
    };

    // --- 3a: the settings are off, and nothing changed ---------------------
    let r = await issue({});
    note(r.status === 200 && r.json && r.json.refresh_token,
         '3a. with the settings off a plain token request still gets a ' +
         'refresh token', r.status);
    const unboundRefresh = (r.json && r.json.refresh_token) || '';
    const bearerAccess = (r.json && r.json.access_token) || '';

    // --- 3b: DPoP required at issuance ------------------------------------
    config2.setOverride('oauth2.refreshTokenRequireDpop', 'true');
    r = await issue({});
    note(r.status === 400 && r.json &&
         r.json.error === 'invalid_dpop_proof' &&
         !(r.json.access_token),
         '3b. with oauth2.refreshTokenRequireDpop on, a token request ' +
         'carrying no proof is refused WHOLE — no access token either',
         r.status + ' ' + (r.json && r.json.error));
    note(r.text.indexOf('STS-OAUTH-') < 0,
         '3c. and the refusal carries no error code on the wire',
         r.text.slice(0, 200));

    r = await issue({ dpop: proofFor('POST', base + '/oauth2/token') });
    const bound = r.json || {};
    note(r.status === 200 && bound.refresh_token && bound.access_token,
         '3d. the same request with a proof is issued', r.status);
    note(String(bound.token_type || '').toLowerCase() === 'dpop',
         '3e. and comes back as a DPoP token set', bound.token_type);

    // --- 3f: the refresh grant --------------------------------------------
    r = await request(port, 'POST', '/oauth2/token', Object.assign({
      grant_type: 'refresh_token', refresh_token: bound.refresh_token },
      client), {});
    // `invalid_grant` and not `invalid_dpop_proof`: the token carries its own
    // binding, so RFC 9449 section 5's refusal (STS-OAUTH-0215) answers first
    // and this setting never has to. That ordering is the point — the setting
    // adds the case the existing checks cannot see, and takes none of theirs.
    note(r.status === 400 && r.json && r.json.error === 'invalid_grant',
         '3f. redeeming a bound refresh token without a proof is refused by ' +
         'the binding check that was already there',
         r.status + ' ' + (r.json && r.json.error));

    r = await request(port, 'POST', '/oauth2/token', Object.assign({
      grant_type: 'refresh_token', refresh_token: unboundRefresh },
      client), { dpop: proofFor('POST', base + '/oauth2/token') });
    note(r.status === 400 && r.json && r.json.error === 'invalid_grant',
         '3g. AND AN UNBOUND REFRESH TOKEN IS REFUSED RATHER THAN BOUND to ' +
         'the key presenting it', r.status + ' ' + (r.json && r.json.error));

    r = await request(port, 'POST', '/oauth2/token', Object.assign({
      grant_type: 'refresh_token', refresh_token: bound.refresh_token },
      client), { dpop: proofFor('POST', base + '/oauth2/token') });
    note(r.status === 200 && r.json && r.json.access_token,
         '3h. and the bound one with its own proof is redeemed', r.status);
    config2.setOverride('oauth2.refreshTokenRequireDpop', 'false');

    // --- 3i: the resource side --------------------------------------------
    config2.setOverride('oauth2.accessTokenRequireDpop', 'true');
    r = await request(port, 'GET', '/oauth2/userinfo', null,
                      { authorization: 'Bearer ' + bearerAccess });
    note(r.status === 401,
         '3i. with oauth2.accessTokenRequireDpop on, UserInfo refuses a ' +
         'bearer token', r.status + ' ' + r.text.slice(0, 120));
    note(String(r.headers['www-authenticate'] || '').indexOf('DPoP') === 0,
         '3j. and says DPoP in WWW-Authenticate',
         r.headers['www-authenticate']);
    config2.setOverride('oauth2.accessTokenRequireDpop', 'false');
    r = await request(port, 'GET', '/oauth2/userinfo', null,
                      { authorization: 'Bearer ' + bearerAccess });
    note(r.status === 200,
         '3k. and with the setting off the same token is accepted — the ' +
         'refusal is the setting and nothing else', r.status);

    // --- 3l: the hole /admin-api carried ----------------------------------
    // A DPoP-bound token was usable at /admin-api as a bearer token until
    // 2026-09-15, in every mode. This is that refusal, with every new setting
    // off.
    const adminToken = bound.access_token;
    r = await request(port, 'GET', '/admin-api/health', null,
                      { authorization: 'Bearer ' + adminToken });
    note(r.status !== 200 || !config2.value('adminApi.authRequired'),
         '3l. a DPoP-bound token presented to /admin-api as Bearer is not ' +
         'simply accepted', r.status);
    server.close();
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    try {
      require('fs').writeFileSync(OUT, JSON.stringify(findings.concat([{
        ok: false, what: 'the child ran to the end',
        detail: (e && e.stack) || String(e) }])));
    } catch (inner) {
      console.error('sender_constraints child: ' + inner.message);
    }
    process.exit(1);
  });
}

function checkTheDoors(t) {
  log.debug("Entering checkTheDoors().");
  t.log.info('=== 3. the doors, in a child process ===');
  const out = path.join(os.tmpdir(), 'sc-' + process.pid + '-' +
                        Math.random().toString(36).slice(2) + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', SC_ROOT: ROOT, SC_OUT: out }),
      encoding: 'utf8', timeout: 180000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in checkTheDoors(): " + ((e && e.message) || e));
    // The child died before writing a report; reported by the check below.
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in checkTheDoors(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings),
               'the child process reported its findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-800))) {
    log.debug("Leaving checkTheDoors(). No report.");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving checkTheDoors().");
}

function removeRealms() {
  log.debug("Entering removeRealms().");
  MADE.splice(0).forEach(function (id) {
    realms.remove(id);
  });
  log.debug("Leaving removeRealms().");
}

function run(t) {
  log.debug("Entering run().");
  try {
    checkTheDecisions(t);
    checkTheExemption(t);
    checkTheDoors(t);
  } finally {
    // In a `finally`, because a failed assertion must not leave a realm
    // standing for the next file to trip over.
    removeRealms();
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'sender_constraints',
  describe: 'the five settings that require more than OAuth 2.1 or RFC 9700 ' +
            'does: rotation on its own switch, and DPoP or mutual TLS ' +
            'required at the token endpoint and at every resource',
  run: run
};
