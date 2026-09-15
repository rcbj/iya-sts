'use strict';
//
// File: rfc9068_access_tokens.js
//
// ===========================================================================
// RFC 9068 — EVERY ACCESS TOKEN THIS SERVICE ISSUES IS A JWT ACCESS TOKEN BY
// THAT PROFILE, AND EVERY RESOURCE SERVER HERE CHECKS ONE AS SECTION 4 SAYS
// (2026-09-13).
//
// `oauth-oidc/jwt_access_token.js` argues the design. What is held here:
//
//   1. THE LIBRARY: the `typ` reading (RFC 7515 section 4.1.9's case and
//      prefix rules), the issuer and audience readings against a base and the
//      named authorization servers under it, and section 4's three refusals
//      each with its code;
//   2. THE PLAN: section 3 and section 2.2.3 as one decision — the default
//      audience, the Entra-style token for an API with its OpenID Connect
//      scopes left off, the three refusals (two APIs in a scope, a scope naming
//      an API the request did not address, several resources with a scope tied
//      to none of them) and the two multi-audience tokens that are allowed;
//   3. THE ENDPOINTS, in a child process on an ephemeral loopback port — the
//      issued header and claims for two grants, UserInfo refusing an ID Token,
//      a token for another host name, a token for another resource server and
//      a token for an API, the token endpoint's refusals, and `/admin-api`
//      refusing a token that is not an access token.
//
// **SECTION 3 IS IN A CHILD** for `tests/oauth_oid4vc_hardcoded.js`'s reason:
// loading the whole protocol stack into `run.js`'s one process builds a
// certificate authority and registers every route on the shared app, which
// changes what later files see.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'rfc9068_access_tokens',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

const config = require('../common/config');
const errorCodes = require('../common/error_codes');
const jat = require('../oauth-oidc/jwt_access_token');

// A compact JWS with the header and payload asked for and a signature nobody
// checks: section 4's type, issuer and audience readings run on a token the
// caller has already verified, so the signature is not what they are about.
function compact(header, payload) {
  log.debug("Entering compact().");
  const part = function (value) {
    return Buffer.from(JSON.stringify(value)).toString('base64url');
  };
  log.debug("Leaving compact().");
  return part(header) + '.' + part(payload) + '.c2lnbmF0dXJl';
}

function codeOf(refusal) {
  log.debug("Entering codeOf().");
  log.debug("Leaving codeOf().");
  return refusal ? errorCodes.codeOf(refusal) : '(accepted)';
}

// ---------------------------------------------------------------------------
// 1. THE LIBRARY.
// ---------------------------------------------------------------------------
function library(t) {
  log.debug("Entering library().");
  t.log.info('=== 1. the type, the issuer and the audience ===');
  t.check(jat.isAccessTokenType('at+jwt') &&
          jat.isAccessTokenType('AT+JWT') &&
          jat.isAccessTokenType('application/at+jwt'),
          '1a. at+jwt is the type in any case and with or without ' +
          'application/');
  t.check(!jat.isAccessTokenType('JWT') && !jat.isAccessTokenType('') &&
          !jat.isAccessTokenType('secevent+jwt'),
          '1b. JWT, nothing and another media type are not');
  t.equal(jat.header().typ, 'at+jwt', '1c. the header minted says at+jwt');

  const BASE = 'https://idp.example';
  t.equal(jat.defaultAudienceFor(BASE), BASE + '/resource',
          '1d. the default resource indicator is <base>/resource');
  t.check(jat.isHostedIssuer(BASE, BASE) &&
          jat.isHostedIssuer(BASE + '/tenant1', BASE),
          '1e. the default and a named authorization server are hosted ' +
          'issuers at their base');
  t.check(!jat.isHostedIssuer('https://other.example', BASE) &&
          !jat.isHostedIssuer(BASE + '/a/b', BASE) &&
          !jat.isHostedIssuer('', BASE),
          '1f. another host, a two-segment path and no issuer are not');
  t.check(!jat.isHostedIssuer('http://127.0.0.1:8081',
                              'http://localhost:8081'),
          '1g. an issuer is an ADDRESS: 127.0.0.1 is not localhost');
  t.check(jat.isOwnResourceAudience(BASE + '/resource', BASE) &&
          jat.isOwnResourceAudience(BASE + '/tenant1/resource', BASE),
          '1h. this resource server is the default and a named ' +
          'authorization server\'s default resource indicator');
  t.check(!jat.isOwnResourceAudience('https://api.partner.example/resource',
                                     BASE),
          '1i. somebody else\'s URL ending in /resource is NOT this resource ' +
          'server — the path-only reading this replaced accepted it');

  try {
    config.setOverride('oauth2.issuer', 'https://pinned.example');
    t.check(jat.isHostedIssuer('https://pinned.example', BASE) &&
            !jat.isHostedIssuer(BASE, BASE),
            '1j. a pinned oauth2.issuer is the issuer, and the base no ' +
            'longer is');
  } finally {
    config.clearOverride('oauth2.issuer');
  }

  const good = { iss: BASE, aud: BASE + '/resource', sub: 'a' };
  t.equal(codeOf(jat.resourceServerRefusal(
    compact({ alg: 'RS256', typ: 'at+jwt' }, good), good, BASE)), '(accepted)',
          '1k. section 4: at+jwt, a hosted issuer and this audience is ' +
          'accepted');
  t.equal(codeOf(jat.resourceServerRefusal(
    compact({ alg: 'RS256', typ: 'JWT' }, good), good, BASE)),
          'STS-OAUTH-0247', '1l. step 1: typ JWT is refused');
  t.equal(codeOf(jat.resourceServerRefusal(
    compact({ alg: 'RS256' }, good), good, BASE)),
          'STS-OAUTH-0247', '1m. step 1: no typ is refused');
  const otherIss = Object.assign({}, good, { iss: 'https://evil.example' });
  t.equal(codeOf(jat.resourceServerRefusal(
    compact({ alg: 'RS256', typ: 'at+jwt' }, otherIss), otherIss, BASE)),
          'STS-OAUTH-0248', '1n. step 3: an issuer not hosted here is ' +
          'refused');
  const otherAud = Object.assign({}, good,
                                 { aud: ['https://api.partner.example/'] });
  t.equal(codeOf(jat.resourceServerRefusal(
    compact({ alg: 'RS256', typ: 'at+jwt' }, otherAud), otherAud, BASE)),
          'STS-OAUTH-0114', '1o. step 4: an audience that is not this ' +
          'resource server is refused');
  const both = Object.assign({}, good,
    { aud: ['https://api.partner.example/', BASE + '/resource'] });
  t.equal(codeOf(jat.resourceServerRefusal(
    compact({ alg: 'RS256', typ: 'at+jwt' }, both), both, BASE)),
          '(accepted)', '1p. an audience list that contains this resource ' +
          'server is accepted');
  t.equal(codeOf(jat.resourceServerRefusal(
    compact({ alg: 'RS256', typ: 'JWT' }, otherIss), otherIss, BASE)),
          'STS-OAUTH-0247', '1q. the steps run in the section\'s order: the ' +
          'type is refused before the issuer is looked at');
  log.debug("Leaving library().");
}

// ---------------------------------------------------------------------------
// 2. THE PLAN.
// ---------------------------------------------------------------------------
function plan(t) {
  log.debug("Entering plan().");
  t.log.info('=== 2. sections 3 and 2.2.3: audiences and scopes ===');
  const OWN = 'https://idp.example/resource';
  const oidc = function (value) {
    return { value: value, kind: 'oidc' };
  };
  const ordinary = function (value) {
    return { value: value, kind: 'ordinary' };
  };
  const app = function (value) {
    return { value: value, kind: 'audience' };
  };
  const perm = function (base, name) {
    return { value: base + name, kind: 'permission', name: name,
             audience: base };
  };

  let p = jat.audiencePlan({ ownResource: OWN, explicit: [],
    scopes: [oidc('openid'), oidc('profile'), ordinary('read')] });
  t.check(!p.refusal && p.audiences.join() === OWN &&
          p.scope === 'openid profile read',
          '2a. nothing named: the default audience, every scope kept',
          JSON.stringify(p));

  p = jat.audiencePlan({ ownResource: OWN, explicit: [], scopes: [] });
  t.check(!p.refusal && p.audiences.join() === OWN && p.scope === '',
          '2b. no scope: the default audience and an empty scope',
          JSON.stringify(p));

  p = jat.audiencePlan({ ownResource: OWN, explicit: [],
    scopes: [oidc('openid'), oidc('profile'), app('apigw1'),
             ordinary('extra')] });
  t.check(!p.refusal && p.audiences.join() === 'apigw1' &&
          p.scope === 'extra' && p.stripped.join() === 'openid,profile',
          '2c. openid profile apigw1: a token for apigw1 ALONE, the OpenID ' +
          'Connect scopes left off it (Entra ID\'s shape)', JSON.stringify(p));

  p = jat.audiencePlan({ ownResource: OWN, explicit: [],
    scopes: [perm('https://api.example/', 'read'),
             perm('https://api.example/', 'write')] });
  t.check(!p.refusal && p.audiences.join() === 'https://api.example/' &&
          p.scope === 'read write',
          '2d. one API\'s permissions: aud is the base, scope the bare names',
          JSON.stringify(p));

  p = jat.audiencePlan({ ownResource: OWN, explicit: [],
    scopes: [app('apigw1'), app('apigw2')] });
  t.equal(codeOf(p.refusal), 'STS-OAUTH-0244',
          '2e. two applications in one scope: refused');
  t.equal(p.refusal && p.refusal.error, 'invalid_scope',
          '2f. with invalid_scope, the code section 3 names');

  p = jat.audiencePlan({ ownResource: OWN, explicit: [],
    scopes: [perm('https://a.example/', 'read'),
             perm('https://b.example/', 'write')] });
  t.equal(codeOf(p.refusal), 'STS-OAUTH-0244',
          '2g. two APIs\' permissions in one scope: refused');

  p = jat.audiencePlan({ ownResource: OWN, explicit: ['https://x.example/'],
    scopes: [app('apigw1')] });
  t.equal(codeOf(p.refusal), 'STS-OAUTH-0245',
          '2h. resource=X with a scope naming apigw1: refused');
  t.equal(p.refusal && p.refusal.error, 'invalid_scope',
          '2i. with invalid_scope');

  p = jat.audiencePlan({ ownResource: OWN, explicit: ['apigw1'],
    scopes: [app('apigw1'), ordinary('read')] });
  t.check(!p.refusal && p.audiences.join() === 'apigw1' && p.scope === 'read',
          '2j. resource=apigw1 with a scope naming apigw1 agrees and is ' +
          'issued', JSON.stringify(p));

  p = jat.audiencePlan({ ownResource: OWN,
    explicit: ['https://a.example/', 'https://b.example/'],
    scopes: [ordinary('read')] });
  t.equal(codeOf(p.refusal), 'STS-OAUTH-0246',
          '2k. two resources and a scope tied to neither: refused');
  t.equal(p.refusal && p.refusal.error, 'invalid_target',
          '2l. with invalid_target');

  p = jat.audiencePlan({ ownResource: OWN,
    explicit: ['https://a.example/', 'https://b.example/'], scopes: [] });
  t.check(!p.refusal && p.audiences.length === 2 && p.scope === '',
          '2m. two resources and no scope: nothing is ambiguous, issued',
          JSON.stringify(p));

  p = jat.audiencePlan({ ownResource: OWN,
    explicit: ['https://a.example/', 'https://b.example/'],
    scopes: [perm('https://a.example/', 'read')] });
  t.check(!p.refusal && p.scope === 'https://a.example/read',
          '2n. several audiences: a permission keeps its WHOLE identifier, ' +
          'the one spelling that names its API', JSON.stringify(p));

  p = jat.audiencePlan({ ownResource: OWN,
    explicit: [OWN, 'https://a.example/'],
    scopes: [oidc('openid'), perm('https://a.example/', 'read')] });
  t.check(!p.refusal && p.scope === 'openid https://a.example/read',
          '2o. this service among several: an OpenID Connect scope is tied ' +
          'to it and kept', JSON.stringify(p));

  p = jat.audiencePlan({ ownResource: OWN, explicit: ['https://x.example/'],
    scopes: [oidc('openid'), ordinary('read')] });
  t.check(!p.refusal && p.scope === 'read' && p.stripped.join() === 'openid',
          '2p. resource=X: the OpenID Connect scopes are left off a token ' +
          'for X', JSON.stringify(p));

  // oauth2.js's `protocolScopes()` exempts these same six names from being
  // read as an application's client_id. Two lists answering two questions,
  // compared here so that one cannot grow a seventh alone.
  const source = fs.readFileSync(path.join(ROOT, 'oauth-oidc', 'oauth2.js'),
                                 'utf8');
  const listed = /const names = \[([^\]]*)\]/.exec(source);
  const names = listed ? listed[1].replace(/[\s']/g, '').split(',') : [];
  t.equal(names.join(','), jat.OIDC_SCOPES.join(','),
          '2q. OIDC_SCOPES is exactly the six protocolScopes() reserves');
  log.debug("Leaving plan().");
}

// ---------------------------------------------------------------------------
// 3. THE ENDPOINTS, IN A CHILD.
// ---------------------------------------------------------------------------
function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.R9_ROOT;
  const OUT = process.env.R9_OUT;
  const http = require('http');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  function request(port, method, urlPath, opts) {
    const o = opts || {};
    return new Promise(function (resolve) {
      const body = o.raw !== undefined ? o.raw
        : (o.form ? new URLSearchParams(o.form).toString() : '');
      const headers = Object.assign({}, o.headers || {});
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
          let parsed = null;
          try {
            parsed = JSON.parse(text);
          } catch (e) {
            // An HTML page or plain text: the raw body is kept. This runs in
            // a `node -e` child with no logger, so the reason travels here.
            parsed = { parseError: e.message };
          }
          resolve({ status: res.statusCode, headers: res.headers, text: text,
                    json: parsed });
        });
      });
      req.end(body);
    });
  }

  function part(jwt, i) {
    return JSON.parse(Buffer.from(String(jwt).split('.')[i], 'base64url')
                            .toString('utf8'));
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const applications = require(ROOT + '/common/applications');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const BASE = 'http://127.0.0.1:' + port;
    const SECRET = 'r9-client-secret-0123456789abcdef';
    const client = { client_id: 'r9-client', client_secret: SECRET };
    applications.createApplication({ identifier: 'r9-client',
      protocols: ['oauth2'],
      fields: { oauthClientId: 'r9-client', oauthClientSecret: SECRET,
                oauthTokenEndpointAuthMethod: 'client_secret_post',
                oauthGrantType: ['password', 'client_credentials'] } });
    ['r9-api-a', 'r9-api-b'].forEach(function (id) {
      applications.createApplication({ identifier: id, protocols: ['oauth2'],
        fields: { oauthClientId: id } });
    });
    const token = function (form) {
      return request(port, 'POST', '/oauth2/token',
                     { form: Object.assign({}, form, client) });
    };

    // 3a. client_credentials: the header and the seven REQUIRED claims.
    let r = await token({ grant_type: 'client_credentials' });
    if (r.status === 200 && r.json.access_token) {
      const head = part(r.json.access_token, 0);
      const claims = part(r.json.access_token, 1);
      note(head.typ === 'at+jwt' && head.alg === 'RS256',
           '3a. section 2.1: the access token\'s header is typ at+jwt, alg ' +
           'RS256', JSON.stringify(head));
      note(['iss', 'exp', 'aud', 'sub', 'client_id', 'iat', 'jti']
             .every(function (k) { return claims[k] !== undefined; }),
           '3b. section 2.2: iss, exp, aud, sub, client_id, iat and jti are ' +
           'all present', JSON.stringify(claims));
      note(claims.iss === BASE && claims.aud === BASE + '/resource',
           '3c. iss is this authorization server and aud its default ' +
           'resource indicator', claims.iss + ' ' + claims.aud);
      note(!('scope' in claims),
           '3d. section 2.2.3: a token granted no scope carries no scope ' +
           'claim', JSON.stringify(claims.scope));
      note(!('preferred_username' in claims) && !('auth_time' in claims),
           '3e. and a client_credentials token names no end user and no ' +
           'authentication event', JSON.stringify(claims));
    } else {
      note(false, '3a. client_credentials issued a token', r.status + ' ' +
           r.text.slice(0, 200));
    }

    // 3f. The password grant with openid: preferred_username, and UserInfo.
    r = await token({ grant_type: 'password', username: 'r9-alice',
                      password: 'anything', scope: 'openid profile' });
    const access = r.json && r.json.access_token;
    const idToken = r.json && r.json.id_token;
    note(r.status === 200 && access && idToken,
         '3f. the password grant issued an access token and an ID Token',
         r.status + ' ' + r.text.slice(0, 200));
    if (access) {
      const claims = part(access, 1);
      note(claims.preferred_username === 'r9-alice' &&
           claims.scope === 'openid profile',
           '3g. section 2.2.2: the person\'s name is preferred_username, ' +
           'and the scope is kept', JSON.stringify(claims));
      r = await request(port, 'GET', '/oauth2/userinfo',
                        { headers: { authorization: 'Bearer ' + access } });
      // The person's `urn:uuid:<entryUUID>` since 2026-09-14.
      note(r.status === 200 && r.json.sub ===
             require(ROOT + '/common/helpers').subjectForName('r9-alice') &&
           /^urn:uuid:/.test(r.json.sub),
           '3h. UserInfo accepts it', r.status + ' ' + r.text.slice(0, 160));
      r = await request(port, 'GET', '/oauth2/userinfo',
                        { headers: { authorization: 'Bearer ' + access,
                                     host: 'localhost:' + port } });
      note(r.status === 401 && /iss claim/.test(r.text),
           '3i. section 4 step 3: the same token presented under another ' +
           'host name is refused for its issuer',
           r.status + ' ' + r.text.slice(0, 200));
    }
    if (idToken) {
      r = await request(port, 'GET', '/oauth2/userinfo',
                        { headers: { authorization: 'Bearer ' + idToken } });
      note(r.status === 401 && /at\+jwt/.test(r.text),
           '3j. section 4 step 1: an ID Token signed by the same key is ' +
           'refused at UserInfo for its header',
           r.status + ' ' + r.text.slice(0, 200));
      r = await request(port, 'GET', '/admin-api/status',
                        { headers: { authorization: 'Bearer ' + idToken } });
      note(r.status === 401 && /at\+jwt/.test(r.text),
           '3k. and at /admin-api, whose gate verifies with the same key',
           r.status + ' ' + r.text.slice(0, 200));
    }

    // 3l. A token narrowed to another resource server is refused here.
    r = await token({ grant_type: 'password', username: 'r9-alice',
                      password: 'anything', scope: 'openid',
                      resource: 'https://api.partner.example/resource' });
    if (r.status === 200) {
      const claims = part(r.json.access_token, 1);
      note(claims.aud === 'https://api.partner.example/resource' &&
           !('scope' in claims) && r.json.id_token,
           '3l. resource=partner: aud is the partner, openid is left off the ' +
           'access token and the ID Token is still issued',
           JSON.stringify(claims));
      const u = await request(port, 'GET', '/oauth2/userinfo',
        { headers: { authorization: 'Bearer ' + r.json.access_token } });
      note(u.status === 401 && /aud/.test(u.text),
           '3m. and UserInfo refuses it — a URL ending in /resource is no ' +
           'longer read as this resource server',
           u.status + ' ' + u.text.slice(0, 200));
    } else {
      note(false, '3l. resource=partner issued a token',
           r.status + ' ' + r.text.slice(0, 200));
    }

    // 3n. openid profile <API>: a token for the API alone.
    r = await token({ grant_type: 'password', username: 'r9-alice',
                      password: 'anything',
                      scope: 'openid profile r9-api-a' });
    if (r.status === 200) {
      const claims = part(r.json.access_token, 1);
      note(claims.aud === 'r9-api-a' && !('scope' in claims) &&
           r.json.id_token && !/openid/.test(r.json.scope || ''),
           '3n. openid profile r9-api-a: aud is r9-api-a alone, no OpenID ' +
           'Connect scope on it or in the response, and an ID Token',
           JSON.stringify(claims) + ' scope=' + r.json.scope);
    } else {
      note(false, '3n. openid profile r9-api-a issued a token',
           r.status + ' ' + r.text.slice(0, 200));
    }

    // 3o-3r. The token endpoint's refusals.
    r = await token({ grant_type: 'client_credentials',
                      scope: 'r9-api-a r9-api-b' });
    note(r.status === 400 && r.json.error === 'invalid_scope',
         '3o. two applications in one scope: invalid_scope',
         r.status + ' ' + r.text.slice(0, 200));
    r = await token({ grant_type: 'client_credentials', scope: 'r9-api-a',
                      resource: 'https://x.example/' });
    note(r.status === 400 && r.json.error === 'invalid_scope',
         '3p. resource=X with a scope naming r9-api-a: invalid_scope',
         r.status + ' ' + r.text.slice(0, 200));
    r = await request(port, 'POST', '/oauth2/token', { raw:
      new URLSearchParams(client).toString() +
      '&grant_type=client_credentials&scope=read' +
      '&resource=' + encodeURIComponent('https://a.example/') +
      '&resource=' + encodeURIComponent('https://b.example/') });
    note(r.status === 400 && r.json.error === 'invalid_target',
         '3q. two resources and a scope tied to neither: invalid_target',
         r.status + ' ' + r.text.slice(0, 200));
    r = await request(port, 'POST', '/oauth2/token', { raw:
      new URLSearchParams(client).toString() +
      '&grant_type=client_credentials' +
      '&resource=' + encodeURIComponent('https://a.example/') +
      '&resource=' + encodeURIComponent('https://b.example/') });
    note(r.status === 200 &&
         Array.isArray(part(r.json.access_token, 1).aud) &&
         part(r.json.access_token, 1).aud.length === 2,
         '3r. two resources and no scope: issued, addressed to both',
         r.status + ' ' + r.text.slice(0, 200));

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

function inAChild(t) {
  log.debug("Entering inAChild().");
  t.log.info('=== 3. the endpoints, in a child process ===');
  const out = path.join(os.tmpdir(), 'rfc9068-' + process.pid + '-' +
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
                         { LOG_LEVEL: 'fatal', R9_ROOT: ROOT, R9_OUT: out }),
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
  library(t);
  plan(t);
  inAChild(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'rfc9068 access tokens',
  describe: 'the JWT access token profile: at+jwt, the required claims, the ' +
            'audience and scope plan, and section 4 at every resource server',
  run: run
};
