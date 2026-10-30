// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/uma_protection.js
//
// ---------------------------------------------------------------------------
// THE UMA 2.0 PROTECTION API, IN PROCESS (#1168 phase 2, #1191).
//
// The whole stack in a child process (`authzen_evaluation.js`'s reason: it
// registers every route and builds the realm's keys), on a plain listener,
// in a throwaway realm with uma.enabled on. Real PATs from the token
// endpoint; then:
//
//   P. THE PAT'S DOORS: none (401, Bearer challenge), a garbage token (401),
//      a token for another audience (401), one without uma_protection
//      (403 insufficient_scope), a client not declared for uma (403), a
//      client_credentials PAT without umaOwnsResources (403), and one with
//      it (the application owns).
//   R. REGISTRATION: create (201, _id, user_access_policy_uri, Location),
//      list, read, update, delete (204), every refusal — no
//      resource_scopes, too many scopes, a bad icon_uri, another resource
//      server's resource (404), an unsupported method (405), the
//      per-owner bound — and an unknown member not stored.
//   T. THE PERMISSION ENDPOINT: one ticket for several permissions (201),
//      stored by digest; invalid_resource_id, invalid_scope, a malformed
//      body.
//   W. DISCOVERY: the UMA members over the realm's RFC 8414 document,
//      no-store, every advertised UMA URL a registered route, the grant and
//      the claims endpoint NOT advertised (nothing unimplemented), the
//      inserted form, 404 for a path naming no realm.
//   O. OFF: uma.enabled off answers 501 everywhere, discovery included.
//   J. THE SWEEP is a registered scheduler job.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const http = require('http');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const CHILD_FLAG = 'STS_UMA_PROTECTION_CHILD';
const MARK = 'UMA-PROTECTION-CHILD ';
const REALM = 'umaprot';
const PREFIX = '/realm/' + REALM;
const SECRET = 'umaprot-secret-0123456789abcdef';
const PROTECTION = 'urn:sts:uma-protection-api:uma_protection';

const log = require('bunyan').createLogger({ name: 'uma_protection',
  level: process.env.LOG_LEVEL || 'info' });

function recorder() {
  log.debug("Entering recorder().");
  const rows = [];
  log.debug("Leaving recorder().");
  return {
    rows: rows,
    check: function (ok, what, detail) {
      log.debug("Entering check().");
      rows.push({ ok: !!ok, what: what,
                  detail: detail === undefined ? '' : String(detail) });
      log.debug("Leaving check().");
    }
  };
}

function request(port, method, urlPath, body, headers) {
  log.debug("Entering request().");
  log.debug("Leaving request().");
  return new Promise(function (resolve) {
    const text = body === undefined ? ''
      : (typeof body === 'string' ? body : JSON.stringify(body));
    const sent = Object.assign({ 'content-type': 'application/json',
                                 'content-length': Buffer.byteLength(text) },
                               headers || {});
    const req = http.request({ host: '127.0.0.1', port: port, path: urlPath,
      method: method, headers: sent, agent: false }, function (res) {
      let raw = '';
      res.on('data', function (chunk) {
        raw += chunk;
      });
      res.on('end', function () {
        let json = null;
        try {
          json = JSON.parse(raw);
        } catch (e) {
          log.debug("Caught in request(): " + e.message);
          json = null;
        }
        resolve({ status: res.statusCode, headers: res.headers, text: raw,
                  json: json });
      });
    });
    req.on('error', function (e) {
      log.debug("Caught in request(): " + e.message);
      resolve({ status: 0, headers: {}, text: '', json: null,
                error: e.message });
    });
    req.end(text);
  });
}

async function childBody() {
  log.debug("Entering childBody().");
  const t = recorder();
  require(ROOT + '/common/protocol_stack');
  const app = require(ROOT + '/common/app');
  const keystore = require(ROOT + '/common/keystore');
  const pki = require(ROOT + '/common/pki');
  const helpers = require(ROOT + '/common/helpers');
  const realms = require(ROOT + '/common/realms');
  const config = require(ROOT + '/common/config');
  const applications = require(ROOT + '/common/applications');
  const errorCodes = require(ROOT + '/common/error_codes');
  const umaStore = require(ROOT + '/uma/uma_store');
  const scheduler = require(ROOT + '/cluster/scheduler');

  const marks = [];
  const mark = errorCodes.mark;
  errorCodes.mark = function (res, code) {
    marks.push(code);
    return mark.apply(this, arguments);
  };
  const markedSince = function (since, code) {
    log.debug("Entering markedSince().");
    log.debug("Leaving markedSince().");
    return marks.slice(since).indexOf(code) >= 0;
  };

  await keystore.start();
  if (!realms.get(REALM)) {
    realms.create({ id: REALM, name: REALM });
  }
  await pki.start({ realmIds: ['', REALM],
    keySetFor: function (id) {
      log.debug("Entering keySetFor().");
      log.debug("Leaving keySetFor().");
      return helpers.stsKeysFor.of(id);
    },
    keySetHeldFor: function () {
      log.debug("Entering keySetHeldFor().");
      log.debug("Leaving keySetHeldFor().");
      return false;
    } });
  const inRealm = function (fn) {
    log.debug("Entering inRealm().");
    log.debug("Leaving inRealm().");
    return realms.run(realms.get(REALM), fn);
  };
  const client = function (id, fields) {
    log.debug("Entering client().");
    log.debug("Leaving client().");
    return applications.createApplication({ identifier: id,
      protocols: ['oauth2'],
      fields: Object.assign({ oauthClientId: id, oauthClientSecret: SECRET,
        oauthGrantType: ['client_credentials'],
        oauthTokenEndpointAuthMethod: 'client_secret_basic',
        oauthDelegatedPermission: [PROTECTION] }, fields || {}) });
  };
  const made = inRealm(function () {
    config.setOverride('uma.enabled', true);
    return [
      client('uma-rs-owns', { appAllowedProtocol: ['oauth2', 'uma'],
                              umaOwnsResources: 'TRUE' }),
      client('uma-rs-plain', { appAllowedProtocol: ['oauth2', 'uma'] }),
      client('uma-not-rs', { appAllowedProtocol: ['oauth2'] }),
      client('uma-rs-other', { appAllowedProtocol: ['oauth2', 'uma'],
                               umaOwnsResources: 'TRUE' }),
      client('uma-no-grant', { appAllowedProtocol: ['oauth2', 'uma'],
                               umaOwnsResources: 'TRUE',
                               oauthDelegatedPermission: [] })
    ];
  });
  t.check(made.every(function (one) {
    return one && one.ok !== false;
  }), 'setup: five clients in the realm', JSON.stringify(made));
  t.check(inRealm(function () {
    return !!applications.get('sts-uma-protection-api');
  }), 'setup: the realm was seeded with sts-uma-protection-api');

  const server = http.createServer(app);
  await new Promise(function (ok) {
    server.listen(0, '127.0.0.1', ok);
  });
  const port = server.address().port;
  const base = 'http://127.0.0.1:' + port + PREFIX;
  const brief = function (r) {
    log.debug("Entering brief().");
    log.debug("Leaving brief().");
    return r.status + ' ' + String(r.text || '').slice(0, 300);
  };
  const tokenFor = async function (id, scope, resource) {
    log.debug("Entering tokenFor(). " + id);
    const r = await request(port, 'POST', PREFIX + '/oauth2/token',
      'grant_type=client_credentials&scope=' + encodeURIComponent(scope) +
      (resource ? '&resource=' + encodeURIComponent(resource) : ''),
      { 'content-type': 'application/x-www-form-urlencoded',
        authorization: 'Basic ' + Buffer.from(id + ':' + SECRET)
          .toString('base64') });
    log.debug("Leaving tokenFor(). " + r.status);
    return { r: r, token: r.json && r.json.access_token };
  };
  const owns = await tokenFor('uma-rs-owns', 'uma_protection', base + '/uma');
  t.check(!!owns.token, 'setup: a client_credentials PAT for /uma carrying ' +
          'uma_protection is issued', brief(owns.r));
  const plain = await tokenFor('uma-rs-plain', 'uma_protection',
                               base + '/uma');
  const notRs = await tokenFor('uma-not-rs', 'uma_protection', base + '/uma');
  const other = await tokenFor('uma-rs-other', 'uma_protection',
                               base + '/uma');
  const noGrant = await tokenFor('uma-no-grant', 'uma_protection',
                                 base + '/uma');
  const elsewhere = await tokenFor('uma-rs-owns', 'openid', '');
  const bearer = function (token) {
    log.debug("Entering bearer().");
    log.debug("Leaving bearer().");
    return { authorization: 'Bearer ' + token };
  };
  const RREG = PREFIX + '/uma/rreg';
  const PERM = PREFIX + '/uma/perm';
  const description = { resource_scopes: ['read', 'write'], name: 'Photo 1',
                        type: 'https://example.com/photo',
                        icon_uri: 'https://example.com/i.png' };

  // --- P. the PAT's doors ------------------------------------------------
  let since = marks.length;
  let r = await request(port, 'POST', RREG, description);
  t.check(r.status === 401 && markedSince(since, 'STS-UMA-0100') &&
          /^Bearer realm="[^"]+"/.test(String(r.headers['www-authenticate'])),
          'P1. no PAT is 401 (STS-UMA-0100) with a Bearer challenge',
          brief(r));
  since = marks.length;
  r = await request(port, 'POST', RREG, description, bearer('x.y.z'));
  t.check(r.status === 401 && markedSince(since, 'STS-UMA-0101') &&
          r.json && r.json.error === 'invalid_token',
          'P2. a token that does not verify is 401 invalid_token', brief(r));
  since = marks.length;
  r = await request(port, 'POST', RREG, description,
                    bearer(elsewhere.token || 'none'));
  t.check(r.status === 401 && (markedSince(since, 'STS-UMA-0102') ||
                               markedSince(since, 'STS-UMA-0101')),
          'P3. an access token not audienced to /uma is 401', brief(r));
  if (!noGrant.token) {
    t.check(true, 'P4. a client with no delegated permission grant of ' +
            'uma_protection is not issued a PAT at all', brief(noGrant.r));
  } else {
    since = marks.length;
    r = await request(port, 'POST', RREG, description, bearer(noGrant.token));
    t.check(r.status === 403 && markedSince(since, 'STS-UMA-0103'),
            'P4. a PAT whose client holds no delegated permission grant of ' +
            'uma_protection is 403 (STS-UMA-0103)', brief(r));
  }
  since = marks.length;
  r = await request(port, 'POST', RREG, description,
                    bearer(notRs.token || 'none'));
  t.check(r.status === 403 && markedSince(since, 'STS-UMA-0104'),
          'P5. a client not declared for uma is no resource server: 403 ' +
          '(STS-UMA-0104)', brief(r) + ' / token ' + brief(notRs.r));
  since = marks.length;
  r = await request(port, 'POST', RREG, description,
                    bearer(plain.token || 'none'));
  t.check(r.status === 403 && markedSince(since, 'STS-UMA-0105'),
          'P6. a client_credentials PAT whose application lacks ' +
          'umaOwnsResources owns nothing: 403 (STS-UMA-0105)', brief(r));

  // --- R. registration --------------------------------------------------
  r = await request(port, 'POST', RREG,
                    Object.assign({ owner: 'somebody-else' }, description),
                    bearer(owns.token));
  const id = r.json && r.json._id;
  t.check(r.status === 201 && !!id &&
          /\/uma\/rreg\/[A-Za-z0-9_-]+$/.test(String(r.headers.location)) &&
          /\/admin\/uma\?owner=uma-rs-owns$/.test(
            String(r.json.user_access_policy_uri)) &&
          r.headers['cache-control'] === 'no-store',
          'R1. a registration is 201 with _id, Location and the ' +
          'user_access_policy_uri of an application owner', brief(r) + ' ' +
          r.headers.location);
  const stored = inRealm(function () {
    return umaStore.resource(id);
  });
  t.check(stored && stored.owner === 'uma-rs-owns' &&
          stored.ownerKind === 'application' &&
          stored.resourceServer === 'uma-rs-owns' && !('somebody-else' ===
            stored.owner) && stored.owner !== 'somebody-else',
          'R2. the owner is the PAT\'s, never a member the resource server ' +
          'sent', JSON.stringify(stored));
  r = await request(port, 'GET', RREG + '/' + id, undefined,
                    bearer(owns.token));
  t.check(r.status === 200 && r.json && r.json._id === id &&
          r.json.resource_scopes.join() === 'read,write' &&
          r.json.name === 'Photo 1' && r.json.owner === undefined,
          'R3. read answers the description, and an unknown member was not ' +
          'stored', brief(r));
  r = await request(port, 'GET', RREG, undefined, bearer(owns.token));
  t.check(r.status === 200 && Array.isArray(r.json) &&
          r.json.indexOf(id) >= 0,
          'R4. list answers this resource server\'s _ids', brief(r));
  r = await request(port, 'GET', RREG, undefined, bearer(other.token));
  t.check(r.status === 200 && Array.isArray(r.json) &&
          r.json.indexOf(id) < 0,
          'R5. another resource server lists none of them', brief(r));
  since = marks.length;
  r = await request(port, 'GET', RREG + '/' + id, undefined,
                    bearer(other.token));
  t.check(r.status === 404 && markedSince(since, 'STS-UMA-0114') &&
          r.json.error === 'not_found',
          'R6. another resource server reading it is not_found (404)',
          brief(r));
  since = marks.length;
  r = await request(port, 'POST', RREG, { name: 'x' }, bearer(owns.token));
  t.check(r.status === 400 && markedSince(since, 'STS-UMA-0111') &&
          r.json.error === 'invalid_request',
          'R7. no resource_scopes is invalid_request (STS-UMA-0111)',
          brief(r));
  inRealm(function () {
    config.setOverride('uma.maxResourceScopes', 2);
  });
  since = marks.length;
  r = await request(port, 'POST', RREG,
                    { resource_scopes: ['a', 'b', 'c'] }, bearer(owns.token));
  t.check(r.status === 400 && markedSince(since, 'STS-UMA-0112'),
          'R8. more scopes than uma.maxResourceScopes is refused', brief(r));
  since = marks.length;
  r = await request(port, 'POST', RREG,
                    { resource_scopes: ['a'], icon_uri: 'http://x/i.png' },
                    bearer(owns.token));
  t.check(r.status === 400 && markedSince(since, 'STS-UMA-0113'),
          'R9. an icon_uri that is not https is refused', brief(r));
  r = await request(port, 'PUT', RREG + '/' + id,
                    { resource_scopes: ['read'], name: 'Photo one' },
                    bearer(owns.token));
  const updated = inRealm(function () {
    return umaStore.resource(id);
  });
  t.check(r.status === 200 && r.json._id === id &&
          updated.resource_scopes.join() === 'read' &&
          updated.name === 'Photo one' && !updated.icon_uri &&
          updated.owner === 'uma-rs-owns',
          'R10. update replaces the description and keeps the owner',
          brief(r) + ' ' + JSON.stringify(updated));
  since = marks.length;
  r = await request(port, 'PATCH', RREG + '/' + id, {}, bearer(owns.token));
  t.check(r.status === 405 && markedSince(since, 'STS-UMA-0115') &&
          r.json.error === 'unsupported_method_type',
          'R11. an unsupported method is 405 unsupported_method_type',
          brief(r));
  inRealm(function () {
    config.setOverride('uma.maxResourcesPerOwner', 1);
  });
  since = marks.length;
  r = await request(port, 'POST', RREG, { resource_scopes: ['read'] },
                    bearer(owns.token));
  t.check(r.status === 400 && markedSince(since, 'STS-UMA-0116'),
          'R12. past uma.maxResourcesPerOwner a registration is refused',
          brief(r));
  inRealm(function () {
    config.setOverride('uma.maxResourcesPerOwner', 1000);
    config.setOverride('uma.maxResourceScopes', 64);
  });
  r = await request(port, 'POST', RREG,
                    { resource_scopes: ['view', 'print'] },
                    bearer(owns.token));
  const second = r.json && r.json._id;

  // --- T. the permission endpoint ----------------------------------------
  r = await request(port, 'POST', PERM,
                    [{ resource_id: id, resource_scopes: ['read'] },
                     { resource_id: second, resource_scopes: ['view'] },
                     { resource_id: second, resource_scopes: ['print'] }],
                    bearer(owns.token));
  const ticket = r.json && r.json.ticket;
  const row = inRealm(function () {
    return ticket ? umaStore.ticket(ticket) : null;
  });
  t.check(r.status === 201 && !!ticket && row && row.state === 'issued' &&
          row.permissions.length === 2 &&
          row.permissions[1].resource_scopes.join() === 'view,print' &&
          row.owner === 'uma-rs-owns' && row.key !== ticket,
          'T1. one ticket for several permissions (201), merged by ' +
          'resource, stored under its digest', brief(r) + ' ' +
          JSON.stringify(row));
  r = await request(port, 'POST', PERM,
                    { resource_id: id, resource_scopes: ['read'] },
                    bearer(owns.token));
  t.check(r.status === 201 && r.json && r.json.ticket &&
          r.json.ticket !== ticket,
          'T2. a single object is a permission request too, with a ticket ' +
          'of its own', brief(r));
  since = marks.length;
  r = await request(port, 'POST', PERM,
                    { resource_id: 'nothing', resource_scopes: ['read'] },
                    bearer(owns.token));
  t.check(r.status === 400 && markedSince(since, 'STS-UMA-0118') &&
          r.json.error === 'invalid_resource_id',
          'T3. an unregistered resource is invalid_resource_id', brief(r));
  since = marks.length;
  r = await request(port, 'POST', PERM,
                    { resource_id: id, resource_scopes: ['write'] },
                    bearer(owns.token));
  t.check(r.status === 400 && markedSince(since, 'STS-UMA-0119') &&
          r.json.error === 'invalid_scope',
          'T4. a scope the resource was not registered with (write, ' +
          'withdrawn by R10) is invalid_scope', brief(r));
  since = marks.length;
  r = await request(port, 'POST', PERM,
                    { resource_id: id, resource_scopes: ['read'] },
                    bearer(other.token));
  t.check(r.status === 400 && markedSince(since, 'STS-UMA-0118'),
          'T5. another resource server\'s resource is invalid_resource_id',
          brief(r));
  since = marks.length;
  r = await request(port, 'POST', PERM, '[]', bearer(owns.token));
  t.check(r.status === 400 && markedSince(since, 'STS-UMA-0117') &&
          r.json.error === 'invalid_request',
          'T6. an empty array is invalid_request', brief(r));

  // --- W. discovery ----------------------------------------------------
  r = await request(port, 'GET', PREFIX + '/.well-known/uma2-configuration');
  const doc = r.json || {};
  t.check(r.status === 200 && r.headers['cache-control'] === 'no-store' &&
          doc.permission_endpoint === base + '/uma/perm' &&
          doc.resource_registration_endpoint === base + '/uma/rreg' &&
          Array.isArray(doc.uma_profiles_supported) &&
          !doc.uma_profiles_supported.length &&
          typeof doc.issuer === 'string' && !!doc.token_endpoint &&
          !!doc.introspection_endpoint,
          'W1. the document carries the UMA members over the realm\'s RFC ' +
          '8414 metadata, no-store', brief(r));
  const umaGate = require(ROOT + '/common/uma_gate');
  const claimsOn = (function () {
    try {
      return !!require(ROOT + '/uma/uma_claims');
    } catch (e) {
      log.debug("Caught in childBody(): " + e.message);
      return false;
    }
  })();
  t.check(!!doc.claims_interaction_endpoint === claimsOn &&
          ((doc.grant_types_supported || []).indexOf(
            'urn:ietf:params:oauth:grant-type:uma-ticket') >= 0) ===
            umaGate.installed(),
          'W2. nothing unimplemented is advertised: the uma-ticket grant ' +
          'and the claims interaction endpoint each only where it is ' +
          'performed', JSON.stringify(doc.grant_types_supported));
  const registered = [];
  app._router.stack.forEach(function (layer) {
    if (layer.route && layer.route.path) {
      registered.push(String(layer.route.path));
    }
  });
  const unrouted = ['/uma/perm', '/uma/rreg'].filter(function (p) {
    return registered.indexOf(p) < 0;
  });
  t.check(!unrouted.length, 'W3. every advertised UMA URL is a registered ' +
          'route', unrouted.join(', '));
  r = await request(port, 'GET', '/.well-known/uma2-configuration' + PREFIX);
  t.check(r.status === 200 && r.json &&
          r.json.permission_endpoint === doc.permission_endpoint,
          'W4. the inserted form answers the same document', brief(r));
  since = marks.length;
  r = await request(port, 'GET', '/.well-known/uma2-configuration/nowhere');
  t.check(r.status === 404 && markedSince(since, 'STS-UMA-0120'),
          'W5. a path naming no realm is 404', brief(r));
  r = await request(port, 'GET', PREFIX + '/uma?format=json');
  t.check(r.status === 200 && r.json && r.json.enabled === true &&
          r.json.resourceServers.indexOf('uma-rs-owns') >= 0 &&
          r.json.resourceServers.indexOf('uma-not-rs') < 0,
          'W6. the description lists the resource servers declared for uma',
          brief(r));

  // --- R13. delete, after the tickets ------------------------------------
  r = await request(port, 'DELETE', RREG + '/' + id, undefined,
                    bearer(owns.token));
  t.check(r.status === 204 && !inRealm(function () {
    return umaStore.resource(id);
  }), 'R13. delete is 204 and the registration is gone', brief(r));

  // --- O. off ----------------------------------------------------------
  inRealm(function () {
    config.setOverride('uma.enabled', false);
  });
  since = marks.length;
  r = await request(port, 'POST', RREG, description, bearer(owns.token));
  const off2 = await request(port, 'GET',
                             PREFIX + '/.well-known/uma2-configuration');
  const off3 = await request(port, 'POST', PERM, {}, bearer(owns.token));
  t.check(r.status === 501 && off2.status === 501 && off3.status === 501 &&
          markedSince(since, 'STS-UMA-0108'),
          'O1. uma.enabled off answers 501 on every route, discovery ' +
          'included (STS-UMA-0108)', brief(r) + ' / ' + brief(off2));

  // --- J. the sweep ----------------------------------------------------
  t.check(!!scheduler.job('uma.sweep'), 'J1. uma.sweep is a scheduler job');

  await new Promise(function (ok) {
    server.close(ok);
  });
  log.debug("Leaving childBody().");
  return t.rows;
}

function spawnChild() {
  log.debug("Entering spawnChild().");
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(KRB5_|STS_|LDAP_|LDAPS_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  clean[CHILD_FLAG] = '1';
  clean.LOG_LEVEL = 'fatal';
  const result = childProcess.spawnSync(process.execPath,
    process.execArgv.concat([__filename]), {
    cwd: ROOT, env: clean, encoding: 'utf8', timeout: 300000,
    maxBuffer: 64 * 1024 * 1024
  });
  const line = String(result.stdout || '').split('\n').filter(function (one) {
    return one.indexOf(MARK) === 0;
  })[0];
  if (!line) {
    log.debug("Leaving spawnChild(). No result.");
    return { error: 'the child produced no result (exit ' + result.status +
                    '): ' + String(result.stderr || '').slice(-1500) };
  }
  log.debug("Leaving spawnChild().");
  return { rows: JSON.parse(line.slice(MARK.length)) };
}

function run(t) {
  log.debug("Entering run().");
  t.log.info('=== the UMA 2.0 protection API (#1168, #1191) ===');
  const got = spawnChild();
  if (got.error) {
    t.bad('the child did not run', got.error);
    log.debug("Leaving run(). No child.");
    return;
  }
  got.rows.forEach(function (row) {
    t.check(row.ok, row.what, row.detail);
  });
  log.debug("Leaving run().");
}

if (require.main === module && process.env[CHILD_FLAG]) {
  childBody().then(function (rows) {
    process.stdout.write('\n' + MARK + JSON.stringify(rows) + '\n');
    process.exit(0);
  }, function (e) {
    process.stderr.write('child failed: ' + String((e && e.stack) || e) +
                         '\n');
    process.exit(1);
  });
}

module.exports = {
  name: 'uma_protection',
  describe: 'the UMA 2.0 protection API (#1168 phase 2): the PAT\'s doors, ' +
            'resource registration, the permission endpoint, discovery ' +
            'advertising nothing unimplemented, the off switch and the sweep',
  run: run
};
