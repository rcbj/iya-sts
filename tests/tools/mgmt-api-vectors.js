// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: mgmt-api-vectors.js
//
// ---------------------------------------------------------------------------
// `/admin-api` AS NODE ANSWERS IT, FOR `sts-mgmt-api` (#444, phase 4, the
// `mgmtapi` slice). `crypto-vectors.js` writes what this builds to
// `mgmt-api-node.json`; `rust/crates/sts-mgmt-api/tests/mgmt_api_vectors.rs`
// sends every request to the Rust router and holds its answer to Node's.
//
// The whole stack is loaded and served IN PROCESS on an ephemeral port, as
// the in-process tests serve it, with access tokens minted as the token
// endpoint mints them (and a few made by hand, each wrong in one way). Every
// request is recorded with its status, the headers a caller reads, the body
// and the error code it was marked with, which is recorded and never sent.
//
// What the gate and the setup operations read outside sts-core — a token's
// roles, a client's declarations, a realm's kid and listeners, the console's
// totals — is recorded too, as the answers the Rust test's ports give.
// ---------------------------------------------------------------------------

const http = require('http');
const path = require('path');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'mgmt-api-vectors',
  level: process.env.STS_LOG_LEVEL || 'info' });

const SCOPES = ['admin:read', 'admin:write', 'admin:security',
                'admin:console', 'device:compliance', 'owner:read',
                'owner:write'];

/**
 * Builds the vector set.
 *
 * @param {string} ROOT - the repository root
 * @returns {Promise<any>} the set
 */
async function build(ROOT) {
  log.debug("Entering build().");
  const req = function (rel) {
    return require(path.join(ROOT, rel));
  };
  req('common/protocol_stack');
  const app = req('common/app');
  const config = req('common/config');
  const realms = req('common/realms');
  const helpers = req('common/helpers');
  const errorCodes = req('common/error_codes');
  const rolePermissions = req('common/role_permissions');
  const scopePolicy = req('common/scope_policy');
  const applications = req('common/applications');
  const mtls = req('oauth-oidc/mtls');
  const adminScope = req('admin-ui/admin_scope');
  const admin = req('admin-ui/admin');
  const persistence = req('persistence/persistence');
  const version = req('common/version');
  const tables = require('./export-admin-api-tables.js').tables();

  const answers = [];
  const server = http.createServer(function (rq, rs) {
    rs.on('finish', function () {
      answers.push(errorCodes.codeOf(rs));
    });
    app(rq, rs);
  });
  await new Promise(function (resolve) {
    server.listen(0, '127.0.0.1', resolve);
  });
  const port = server.address().port;
  const base = 'http://127.0.0.1:' + port;
  const now = Math.floor(Date.now() / 1000);

  // Tokens, by name, and the claims each carries.
  const tokens = {};
  const claimsOf = {};
  const sign = function (name, claims, realmId, typ) {
    const realm = realms.get(realmId || realms.DEFAULT_ID);
    const token = realms.run(realm, function () {
      return helpers.signJwt(claims, {}, typ === null ? {}
        : { header: { typ: typ || 'at+jwt' } });
    });
    tokens[name] = token;
    claimsOf[name] = { claims: claims, realm: realmId || 'default' };
  };
  const good = function (extra) {
    return Object.assign({ iss: base, aud: base + '/admin-api',
      iat: now, exp: now + 3600, client_id: 'sts-api-client',
      sub: 'sts-api-client', scope: 'admin:read admin:write',
      jti: 'mgmt-' + Math.random().toString(36).slice(2) }, extra || {});
  };
  sign('service', good());
  sign('readOnly', good({ scope: 'admin:read' }));
  sign('expired', good({ exp: now - 60, iat: now - 3600 }));
  sign('idToken', good(), null, 'JWT');
  sign('otherIssuer', good({ iss: 'https://elsewhere.example' }));
  sign('otherAudience', good({ aud: 'https://elsewhere.example/api' }));
  sign('dpopBound', good({ cnf: { jkt: 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs' } }));
  sign('undeclared', good({ client_id: 'mgmt-undeclared-client',
                            sub: 'mgmt-undeclared-client' }));
  sign('nobody', good({ sub: 'mgmt-nobody-person', username: 'mgmt-nobody-person' }));
  sign('owner', good({ scope: 'owner:write' }));

  const call = function (method, url, token, body, extra) {
    return new Promise(function (resolve, reject) {
      const text = body === undefined ? null
        : (typeof body === 'string' ? body : JSON.stringify(body));
      const headers = Object.assign({ host: '127.0.0.1:' + port,
                                      accept: 'application/json' },
                                    extra || {});
      if (token) {
        headers.authorization = 'Bearer ' + token;
      }
      if (text !== null) {
        headers['content-type'] = headers['content-type'] ||
          'application/json';
        headers['content-length'] = Buffer.byteLength(text);
      }
      const r = http.request({ host: '127.0.0.1', port: port, path: url,
                               method: method, headers: headers },
      function (res) {
        let raw = '';
        res.setEncoding('utf8');
        res.on('data', function (d) {
          raw += d;
        });
        res.on('end', function () {
          setImmediate(function () {
            resolve({ status: res.statusCode, body: raw,
                      headers: {
                        'content-type': res.headers['content-type'] || null,
                        'cache-control': res.headers['cache-control'] || null,
                        'www-authenticate':
                          res.headers['www-authenticate'] || null
                      },
                      code: answers[answers.length - 1] || '' });
          });
        });
      });
      r.on('error', reject);
      if (text !== null) {
        r.write(text);
      }
      r.end();
    });
  };

  const cases = [];
  const ask = async function (name, method, url, tokenName, body, extra) {
    const sent = { name: name, method: method, url: url,
                   token: tokenName || null,
                   body: body === undefined ? null
                     : (typeof body === 'string' ? body
                       : JSON.stringify(body)),
                   headers: extra || {} };
    const got = await call(method, url, tokenName ? tokens[tokenName] : null,
                           body, extra);
    cases.push(Object.assign(sent, { answer: got }));
    return got;
  };

  // --- the gate's every refusal ----------------------------------------
  await ask('no token', 'GET', '/admin-api/config');
  await ask('not ours', 'GET', '/admin-api/config', null, undefined,
            { authorization: 'Bearer a.b.c' });
  await ask('expired', 'GET', '/admin-api/mode', 'expired');
  await ask('not at+jwt', 'GET', '/admin-api/mode', 'idToken');
  await ask('another issuer', 'GET', '/admin-api/mode', 'otherIssuer');
  await ask('another audience', 'GET', '/admin-api/mode', 'otherAudience');
  await ask('dpop-bound as bearer', 'GET', '/admin-api/mode', 'dpopBound');
  await ask('undeclared scope', 'GET', '/admin-api/mode', 'undeclared');
  await ask('withdrawn role', 'GET', '/admin-api/mode', 'nobody');
  await ask('policy refuses a write', 'POST', '/admin-api/config/set',
            'readOnly', { key: 'saml.organizationName', value: 'X' });
  await ask('security change', 'POST', '/admin-api/config/set', 'service',
            { key: 'admin.securityGroup', value: 'sec' });
  await ask('console operation without admin:console', 'GET',
            '/admin-api/console/operations', 'service');
  await ask('owner token', 'GET', '/admin-api/config', 'owner');
  // --- the reads ---------------------------------------------------------
  await ask('index', 'GET', '/admin-api', 'service');
  await ask('openapi', 'GET', '/admin-api/openapi.json', 'service');
  await ask('mode', 'GET', '/admin-api/mode', 'service');
  await ask('config', 'GET', '/admin-api/config', 'service');
  await ask('realms', 'GET', '/admin-api/realms', 'service');
  await ask('realms paged', 'GET', '/admin-api/realms?page=3&per=1',
            'service');
  // --- what a request may name and hold ----------------------------------
  await ask('unknown query name', 'GET', '/admin-api/config?x=1', 'service');
  await ask('query of the wrong type', 'GET', '/admin-api/realms?page=abc',
            'service');
  await ask('a header nobody defined', 'GET', '/admin-api/mode', 'service',
            undefined, { 'x-made-up': '1' });
  await ask('body member the model lacks', 'POST', '/admin-api/config/set',
            'service', { key: 'saml.organizationName', value: 'X', y: 1 });
  await ask('body member of the wrong type', 'POST', '/admin-api/config/set',
            'service', { key: 5, value: 'X' });
  await ask('body breaking a pattern', 'POST', '/admin-api/realms/create',
            'service', { id: 'Bad Id!' });
  await ask('malformed JSON', 'POST', '/admin-api/config/set', 'service',
            '{bad');
  // --- the configuration ---------------------------------------------------
  await ask('set', 'POST', '/admin-api/config/set', 'service',
            { key: 'saml.organizationName', value: 'Example Org' });
  await ask('set an unknown key', 'POST', '/admin-api/config/set', 'service',
            { key: 'no.such', value: '1' });
  await ask('set a restart-only key', 'POST', '/admin-api/config/set',
            'service', { key: 'global.port', value: '9' });
  await ask('set a value of the wrong type', 'POST', '/admin-api/config/set',
            'service', { key: 'oauth2.accessTokenTtlS', value: 'many' });
  await ask('set-many', 'POST', '/admin-api/config/set-many', 'service',
            { 'saml.organizationName': 'Org Two',
              'oauth2.accessTokenTtlS': '900' });
  await ask('set-many, nothing', 'POST', '/admin-api/config/set-many',
            'service', { 'no.such': '1' });
  await ask('set-many, one refused', 'POST', '/admin-api/config/set-many',
            'service', { 'saml.organizationName': 'Org Three',
                         'oauth2.accessTokenTtlS': 'many' });
  await ask('reset', 'POST', '/admin-api/config/reset', 'service',
            { key: 'saml.organizationName' });
  await ask('reset, nothing to reset', 'POST', '/admin-api/config/reset',
            'service', { key: 'saml.organizationName' });
  await ask('config after the writes', 'GET', '/admin-api/config', 'service');
  await ask('reset-all', 'POST', '/admin-api/config/reset-all', 'service',
            {});
  await ask('unknown config action', 'POST', '/admin-api/config/frob',
            'service', {});
  // --- the trust realms ----------------------------------------------------
  await ask('create a realm', 'POST', '/admin-api/realms/create', 'service',
            { id: 'acme', name: 'Acme' });
  await ask('create it again', 'POST', '/admin-api/realms/create', 'service',
            { id: 'acme' });
  await ask('update', 'POST', '/admin-api/realms/update', 'service',
            { id: 'acme', description: 'The Acme realm' });
  await ask('set on a realm', 'POST', '/admin-api/realms/set', 'service',
            { id: 'acme', key: 'saml.organizationName', value: 'Acme Inc' });
  await ask('unset on a realm', 'POST', '/admin-api/realms/unset', 'service',
            { id: 'acme', key: 'saml.organizationName' });
  await ask('unset what is not set', 'POST', '/admin-api/realms/unset',
            'service', { id: 'acme', key: 'saml.organizationName' });
  await ask('remove a realm nobody defined', 'POST',
            '/admin-api/realms/remove', 'service', { id: 'nope' });
  await ask('unknown realm action', 'POST', '/admin-api/realms/frob',
            'service', {});
  await ask('realms after the writes', 'GET', '/admin-api/realms',
            'service');
  // A realm's own token, under its prefix, and outside it.
  const realmBase = base + '/realm/acme';
  sign('realmToken', Object.assign(good({ iss: realmBase,
                                          aud: realmBase + '/admin-api' })),
       'acme');
  await ask('realm token in its realm', 'GET', '/realm/acme/admin-api/mode',
            'realmToken');
  await ask('realm token outside it', 'GET', '/admin-api/mode', 'realmToken');
  await ask('service token in a realm', 'GET',
            '/realm/acme/admin-api/config', 'service');
  await ask('remove the realm from inside it', 'POST',
            '/realm/acme/admin-api/realms/remove', 'service', { id: 'acme' });
  // --- an answer its model refuses ----------------------------------------
  const realStatus = admin.dashboardJsonAsync;
  await ask('status', 'GET', '/admin-api/status', 'service');
  admin.dashboardJsonAsync = function (r) {
    return realStatus.call(admin, r).then(function (json) {
      return Object.assign({}, json, { bogus: true });
    });
  };
  await ask('an answer its model refuses', 'GET', '/admin-api/status',
            'service');
  admin.dashboardJsonAsync = realStatus;
  // --- the open API of development (authRequired off) ----------------------
  config.setOverride('adminApi.authRequired', false);
  await ask('open: console operations', 'GET',
            '/admin-api/console/operations');
  await ask('open: console document', 'GET',
            '/admin-api/console/openapi.json');
  await ask('open: the document, last (it changes the model in Node)', 'GET',
            '/admin-api/openapi.json');
  config.clearOverride('adminApi.authRequired');
  server.close();

  // --- what the Rust test's ports answer ----------------------------------
  const ports = { effective: {}, declares: {}, clientMethod: {},
                  certificate: {}, realmRefusal: {} };
  Object.keys(claimsOf).forEach(function (name) {
    const one = claimsOf[name];
    const client = String(one.claims.client_id || '');
    const carried = String(one.claims.scope || '').split(/\s+/)
      .filter(Boolean);
    const realm = realms.get(one.realm);
    const declares = realms.run(realm, function () {
      const out = {};
      SCOPES.forEach(function (s) {
        out[s] = !!scopePolicy.declares(client, s);
      });
      return out;
    });
    ports.declares[one.realm + ' ' + client] = declares;
    const kept = carried.filter(function (s) {
      return SCOPES.indexOf(s) < 0 || declares[s];
    });
    const effective = rolePermissions.effectiveRoles(one.claims, kept,
                                                     one.realm);
    ports.effective[String(one.claims.jti)] = {
      roles: effective.roles, withdrawn: effective.withdrawn,
      why: effective.why, subjectKind: effective.subject.kind,
      subjectName: String(effective.subject.name || '')
    };
    realms.run(realm, function () {
      const entry = applications.clientConfigOf(client) || {};
      ports.clientMethod[one.realm + ' ' + client] =
        String(entry.token_endpoint_auth_method || '');
      ports.certificate[one.realm + ' ' + client] =
        String(mtls.certificateDeclaration(
          applications.clientConfigOf(client)) || '');
    });
  });
  ['/admin/config', '/admin/realms', '/admin/mode'].forEach(function (page) {
    const refusal = adminScope.refusalFor(
      { authority: 'realm', identityRealm: 'acme' }, page, null, {});
    ports.realmRefusal[page] = refusal ? refusal.detail : null;
  });
  const store = persistence.status();
  const operator = process.env.CONFIG_FILE ? require(process.env.CONFIG_FILE)
                                           : null;
  const env = {};
  Object.keys(process.env).forEach(function (k) {
    if (/^(STS_|ADMIN_API_|CONFIG_FILE$)/.test(k)) {
      env[k] = process.env[k];
    }
  });
  const kids = {};
  const keySets = {};
  realms.list().forEach(function (r) {
    realms.run(r, function () {
      keySets[r.id] = JSON.parse(JSON.stringify(helpers.stsKeysFor()));
      kids[r.id] = helpers.stsKeysFor().kid;
    });
  });
  const out = {
    port: port,
    now: now,
    tables: tables,
    operator: operator,
    env: env,
    facts: { configFile: process.env.CONFIG_FILE || null,
             defaultsFile: config.DEFAULTS_FILE,
             persistsAppconfig: !!store.persistsAppconfig,
             persistsRealms: !!store.persistsRealms,
             persistenceMode: String(store.mode),
             persistenceEnabled: !!store.enabled },
    version: version.load(),
    keySets: keySets,
    kids: kids,
    tokens: tokens,
    ports: ports,
    cases: cases
  };
  log.debug("Leaving build(). " + cases.length + " case(s).");
  return out;
}

module.exports = { build: build };
