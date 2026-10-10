// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: scim_client.js
// ===========================================================================
// THE OUTBOUND SCIM CLIENT (#552): THIS REALM'S PEOPLE AND GROUPS, PUSHED.
//
// In process, in a throwaway realm, against a FAKE SCIM 2.0 service provider
// — a local HTTPS server whose CA and certificate are made here with openssl
// at test time (no key material is committed) — with a token endpoint of its
// own. Held here:
//   A. a client is an application entry declared for scim-client; add refuses
//      plain http, a user name in the URI, a query, an unparseable filter and
//      an unauthenticated client (STS-SCIMC-0017);
//   B. Basic: a person and a group are created there (POST with externalId,
//      no id, meta or groups, the core schema first, application/scim+json),
//      the member named by the service provider's id;
//   C. a change is a PUT to the linked id; a 412 re-reads and tries again
//      with If-Match (RFC 7644 section 3.14);
//   D. a 409 uniqueness ADOPTS the resource found by userName;
//   E. a disabled person is deactivated (PATCH active false), and without
//      PATCH support by GET then PUT; deprovision=delete DELETEs, and a 404
//      on DELETE is done;
//   F. scope by group and by LDAP filter; a person leaving the scope is
//      deprovisioned by a reconciliation;
//   G. a 503 with Retry-After is retried, PAUSES the client, holds its other
//      deliveries, and one probe goes first after the pause; a success ends
//      the pause; deliver-now lifts it;
//   H. a 400 is a dead letter on the client's own dead-letter queue, retried
//      by retry-delivery and purged by purge-dead; another client's queue
//      is untouched;
//   I. OAuth 2.0 client_secret_basic and client_secret_post, the token
//      cached, and one fresh token after a 401;
//   J. a TLS client certificate issued by the realm's CA is presented;
//   K. no credential appears in any view, audit row or log line.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const https = require('https');
const nodeCrypto = require('crypto');
const childProcess = require('child_process');
const realms = require('../common/realms');
const errorCodes = require('../common/error_codes');
const ldap = require('../ldap/ldap_server');
const applications = require('../common/applications');
const audit = require('../common/audit');
const scimClients = require('../scim/scim_client');
const accountState = require('../common/account_state');

const log = require('bunyan').createLogger({ name: 'scim_client',
  level: process.env.LOG_LEVEL || 'info' });

const RUN = nodeCrypto.randomBytes(3).toString('hex');
const BASIC_PASSWORD = 'basic-pw-' + RUN + '-' +
  nodeCrypto.randomBytes(8).toString('hex');
const OAUTH_SECRET = 'oauth-secret-' + RUN + '-' +
  nodeCrypto.randomBytes(8).toString('hex');
const HIDE = [BASIC_PASSWORD, OAUTH_SECRET];

// ---------------------------------------------------------------------------
// TEST CERTIFICATES, made at test time.
// ---------------------------------------------------------------------------
function makeCertificates(dir) {
  log.debug('Entering makeCertificates().');
  const ossl = function (args) {
    const r = childProcess.spawnSync('openssl', args, { cwd: dir,
                                                       encoding: 'utf8' });
    if (r.status !== 0) {
      throw new Error('openssl ' + args[0] + ' failed: ' + r.stderr);
    }
  };
  ossl(['req', '-x509', '-newkey', 'ec', '-pkeyopt',
        'ec_paramgen_curve:P-256', '-nodes', '-keyout', 'ca.key', '-out',
        'ca.crt', '-days', '2', '-subj', '/CN=scim client test ca',
        '-addext', 'basicConstraints=critical,CA:TRUE',
        '-addext', 'keyUsage=critical,keyCertSign,cRLSign']);
  ossl(['req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
        '-nodes', '-keyout', 'leaf.key', '-out', 'leaf.csr', '-subj',
        '/CN=localhost']);
  fs.writeFileSync(path.join(dir, 'ext.cnf'),
    'basicConstraints=critical,CA:FALSE\n' +
    'keyUsage=critical,digitalSignature\n' +
    'extendedKeyUsage=serverAuth\n' +
    'subjectAltName=DNS:localhost,IP:127.0.0.1\n');
  ossl(['x509', '-req', '-in', 'leaf.csr', '-CA', 'ca.crt', '-CAkey',
        'ca.key', '-CAcreateserial', '-out', 'leaf.crt', '-days', '2',
        '-extfile', 'ext.cnf']);
  log.debug('Leaving makeCertificates().');
  return { ca: fs.readFileSync(path.join(dir, 'ca.crt'), 'utf8'),
           key: fs.readFileSync(path.join(dir, 'leaf.key')),
           cert: fs.readFileSync(path.join(dir, 'leaf.crt')) };
}

// ---------------------------------------------------------------------------
// THE FAKE SERVICE PROVIDER.
// ---------------------------------------------------------------------------
function freshProvider() {
  log.debug('Entering freshProvider().');
  log.debug('Leaving freshProvider().');
  return {
    users: {}, groups: {}, requests: [], seq: 0,
    patch: true, etag: true, filter: true,
    auth: 'basic',
    // Statuses to answer next, matched in order: { method, path, status,
    // headers, body }.
    fail: [],
    // Token endpoint: issued tokens, and how a client authenticated.
    tokens: {}, tokenRequests: [], invalidateTokens: false,
    clientCertificate: null
  };
}

let sp = freshProvider();

function scimError(res, status, scimType, detail, headers) {
  log.debug('Entering scimError().');
  res.writeHead(status, Object.assign({
    'Content-Type': 'application/scim+json' }, headers || {}));
  res.end(JSON.stringify({ schemas: [
    'urn:ietf:params:scim:api:messages:2.0:Error'], status: String(status),
    scimType: scimType, detail: detail }));
  log.debug('Leaving scimError().');
}

function send(res, status, body, headers) {
  log.debug('Entering send().');
  res.writeHead(status, Object.assign({
    'Content-Type': 'application/scim+json' }, headers || {}));
  res.end(body === undefined ? '' : JSON.stringify(body));
  log.debug('Leaving send().');
}

function versionOf(r) {
  log.debug('Entering versionOf().');
  log.debug('Leaving versionOf().');
  return 'W/"' + r.v + '"';
}

function withMeta(r, type) {
  log.debug('Entering withMeta().');
  const out = Object.assign({}, r.body, { id: r.id,
    meta: { resourceType: type, version: versionOf(r) } });
  log.debug('Leaving withMeta().');
  return out;
}

function matchesFilter(r, filter) {
  log.debug('Entering matchesFilter().');
  const m = /^(\w+) eq (".*")$/.exec(filter);
  if (!m) {
    log.debug('Leaving matchesFilter(). Unreadable.');
    return false;
  }
  const want = JSON.parse(m[2]);
  log.debug('Leaving matchesFilter().');
  return String(r.body[m[1]] || '') === want;
}

function applyPatch(r, ops) {
  log.debug('Entering applyPatch().');
  ops.forEach(function (op) {
    if (op.path === 'active') {
      r.body.active = op.value;
    } else if (op.path === 'displayName') {
      r.body.displayName = op.value;
    } else if (op.path === 'members' && op.op === 'add') {
      r.body.members = (r.body.members || []).concat(op.value);
    } else if (/^members\[value eq /.test(op.path) && op.op === 'remove') {
      const v = JSON.parse(/eq (".*")\]$/.exec(op.path)[1]);
      r.body.members = (r.body.members || []).filter(function (one) {
        return one.value !== v;
      });
    }
  });
  log.debug('Leaving applyPatch().');
}

function handleScim(req, res, raw) {
  log.debug('Entering handleScim().');
  const url = new URL(req.url, 'https://localhost');
  const parts = url.pathname.replace(/^\/scim\/v2/, '').split('/')
    .filter(Boolean);
  const body = raw ? JSON.parse(raw) : null;
  sp.requests.push({ method: req.method, path: url.pathname + url.search,
                     body: body, headers: req.headers });
  // Authentication.
  if (sp.auth === 'basic') {
    const want = 'Basic ' + Buffer.from('pusher:' + BASIC_PASSWORD)
      .toString('base64');
    if (req.headers.authorization !== want) {
      return scimError(res, 401, undefined, 'bad credentials');
    }
  } else if (sp.auth === 'bearer') {
    const token = String(req.headers.authorization || '')
      .replace(/^Bearer /, '');
    if (!sp.tokens[token] || sp.invalidateTokens) {
      sp.invalidateTokens = false;
      return scimError(res, 401, undefined, 'bad token');
    }
  } else if (sp.auth === 'certificate') {
    const peer = req.socket.getPeerCertificate();
    sp.clientCertificate = peer && peer.subject ? peer : null;
    if (!req.client.authorized) {
      return scimError(res, 401, undefined, 'no certificate');
    }
  }
  for (let i = 0; i < sp.fail.length; i++) {
    const f = sp.fail[i];
    if (f.method === req.method && url.pathname.indexOf(f.path) >= 0) {
      sp.fail.splice(i, 1);
      return scimError(res, f.status, f.scimType, 'scripted', f.headers);
    }
  }
  if (parts[0] === 'ServiceProviderConfig') {
    return send(res, 200, { schemas: [
      'urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'],
      patch: { supported: sp.patch }, bulk: { supported: false },
      filter: { supported: sp.filter, maxResults: 50 },
      changePassword: { supported: false }, sort: { supported: false },
      etag: { supported: sp.etag },
      authenticationSchemes: [{ type: 'httpbasic', name: 'Basic' }] });
  }
  if (parts[0] === 'ResourceTypes') {
    return send(res, 200, { schemas: [
      'urn:ietf:params:scim:api:messages:2.0:ListResponse'], totalResults: 2,
      Resources: [{ id: 'User', name: 'User', endpoint: '/Users' },
                  { id: 'Group', name: 'Group', endpoint: '/Groups' }] });
  }
  const type = parts[0] === 'Users' ? 'User' : parts[0] === 'Groups'
    ? 'Group' : '';
  if (!type) {
    return scimError(res, 404, undefined, 'no such endpoint');
  }
  const store = type === 'User' ? sp.users : sp.groups;
  const id = parts[1];
  if (!id && req.method === 'GET') {
    let all = Object.keys(store).map(function (k) {
      return store[k];
    });
    const filter = url.searchParams.get('filter');
    if (filter) {
      all = all.filter(function (r) {
        return matchesFilter(r, filter);
      });
    }
    const start = Number(url.searchParams.get('startIndex') || 1);
    const count = Number(url.searchParams.get('count') || 100);
    const page = all.slice(start - 1, start - 1 + count);
    const answer = { schemas: [
      'urn:ietf:params:scim:api:messages:2.0:ListResponse'],
      totalResults: all.length, startIndex: start,
      itemsPerPage: page.length };
    if (page.length) {
      answer.Resources = page.map(function (r) {
        return withMeta(r, type);
      });
    }
    return send(res, 200, answer);
  }
  if (!id && req.method === 'POST') {
    const clash = Object.keys(store).filter(function (k) {
      const r = store[k];
      return type === 'User' ? r.body.userName === body.userName
                             : r.body.displayName === body.displayName;
    })[0];
    if (clash) {
      return scimError(res, 409, 'uniqueness', 'exists');
    }
    const created = { id: 'sp-' + (++sp.seq), v: 1, body: body };
    store[created.id] = created;
    return send(res, 201, withMeta(created, type),
                { ETag: versionOf(created) });
  }
  const r = store[id];
  if (!r) {
    return scimError(res, 404, undefined, 'no such resource');
  }
  if (sp.etag && req.headers['if-match'] &&
      req.headers['if-match'] !== versionOf(r)) {
    return scimError(res, 412, undefined, 'stale version');
  }
  if (req.method === 'GET') {
    return send(res, 200, withMeta(r, type), { ETag: versionOf(r) });
  }
  if (req.method === 'PUT') {
    r.body = body;
    r.v++;
    return send(res, 200, withMeta(r, type), { ETag: versionOf(r) });
  }
  if (req.method === 'PATCH') {
    if (!sp.patch) {
      return scimError(res, 501, undefined, 'no PATCH');
    }
    applyPatch(r, body.Operations || []);
    r.v++;
    return send(res, 200, withMeta(r, type), { ETag: versionOf(r) });
  }
  if (req.method === 'DELETE') {
    delete store[id];
    return send(res, 204);
  }
  log.debug('Leaving handleScim().');
  return scimError(res, 405, undefined, 'method');
}

function handleToken(req, res, raw) {
  log.debug('Entering handleToken().');
  const form = new URLSearchParams(raw);
  let clientId = form.get('client_id');
  let secret = form.get('client_secret');
  const basic = String(req.headers.authorization || '');
  let how = 'client_secret_post';
  if (/^Basic /.test(basic)) {
    const pair = Buffer.from(basic.slice(6), 'base64').toString('utf8')
      .split(':');
    clientId = decodeURIComponent(pair[0]);
    secret = decodeURIComponent(pair[1] || '');
    how = 'client_secret_basic';
  }
  sp.tokenRequests.push({ how: how, grant: form.get('grant_type'),
                          scope: form.get('scope') });
  if (clientId !== 'pusher-app' || secret !== OAUTH_SECRET ||
      form.get('grant_type') !== 'client_credentials') {
    res.writeHead(401, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'invalid_client' }));
    log.debug('Leaving handleToken(). Refused.');
    return;
  }
  const token = 'tok-' + nodeCrypto.randomBytes(8).toString('hex');
  sp.tokens[token] = true;
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ access_token: token, token_type: 'Bearer',
                           expires_in: 3600 }));
  log.debug('Leaving handleToken().');
}

function startProvider(material, extraCa) {
  log.debug('Entering startProvider().');
  const options = { key: material.key, cert: material.cert };
  if (extraCa) {
    options.ca = [extraCa];
    options.requestCert = true;
    options.rejectUnauthorized = false;
  }
  const server = https.createServer(options, function (req, res) {
    let raw = '';
    req.on('data', function (c) {
      raw += c;
    });
    req.on('end', function () {
      try {
        if (req.url === '/token') {
          handleToken(req, res, raw);
        } else {
          handleScim(req, res, raw);
        }
      } catch (e) {
        log.debug('Caught in startProvider(): ' + ((e && e.message) || e));
        res.writeHead(500);
        res.end();
      }
    });
  });
  log.debug('Leaving startProvider().');
  return new Promise(function (resolve) {
    server.listen(0, '127.0.0.1', function () {
      resolve(server);
    });
  });
}

// ---------------------------------------------------------------------------
// THE HARNESS.
// ---------------------------------------------------------------------------
async function act(body) {
  log.debug('Entering act(). ' + body.action);
  const answer = await scimClients.act(body, { actor: 'tester',
                                               via: 'console' });
  log.debug('Leaving act().');
  return answer;
}

// Sends what is due until nothing is, the pause aside.
async function drain(times) {
  log.debug('Entering drain().');
  for (let i = 0; i < (times || 6); i++) {
    await scimClients.delivery().sweep();
  }
  log.debug('Leaving drain().');
}

function codeOf(x) {
  log.debug('Entering codeOf().');
  log.debug('Leaving codeOf().');
  return x && (x.code || errorCodes.codeOf(x));
}

function userNamed(name) {
  log.debug('Entering userNamed().');
  const found = Object.keys(sp.users).map(function (k) {
    return sp.users[k];
  }).filter(function (r) {
    return r.body.userName === name;
  })[0] || null;
  log.debug('Leaving userNamed().');
  return found;
}

function groupNamed(name) {
  log.debug('Entering groupNamed().');
  const found = Object.keys(sp.groups).map(function (k) {
    return sp.groups[k];
  }).filter(function (r) {
    return r.body.displayName === name;
  })[0] || null;
  log.debug('Leaving groupNamed().');
  return found;
}

function uuidOf(name) {
  log.debug('Entering uuidOf().');
  const entry = ldap.readPerson('uid=' + name + ',' + ldap.usersDn());
  const out = String(((entry && entry.attributes) || {}).entryUUID ||
                     ((entry && entry.attributes) || {}).entryuuid || '');
  log.debug('Leaving uuidOf().');
  return (Array.isArray(out) ? out[0] : out).toLowerCase();
}

async function validation(t, base) {
  log.debug('Entering validation().');
  const plain = await act({ action: 'add-client', identifier: 'a-' + RUN,
    baseUrl: base.replace('https:', 'http:'), authMethod: 'basic',
    username: 'u', password: 'p' });
  t.check(!plain.ok && codeOf(plain) === 'STS-SCIMC-0017' &&
          /https/.test(plain.errors.join(' ')),
          'A1. a plain http base URI is refused', JSON.stringify(plain));
  const userinfo = await act({ action: 'add-client', identifier: 'a-' + RUN,
    baseUrl: base.replace('https://', 'https://u:p@'), authMethod: 'basic',
    username: 'u', password: 'p' });
  t.check(!userinfo.ok && /user name or password/.test(
    userinfo.errors.join(' ')), 'A2. a credential in the URI is refused');
  const query = await act({ action: 'add-client', identifier: 'a-' + RUN,
    baseUrl: base + '?x=1', authMethod: 'basic', username: 'u',
    password: 'p' });
  t.check(!query.ok && /query/.test(query.errors.join(' ')),
          'A3. a query on the base URI is refused');
  const filter = await act({ action: 'add-client', identifier: 'a-' + RUN,
    baseUrl: base, authMethod: 'basic', username: 'u', password: 'p',
    scopeMode: 'filter', scopeFilter: '(((' });
  t.check(!filter.ok && /RFC 4515/.test(filter.errors.join(' ')),
          'A4. an LDAP filter that does not parse is refused');
  const none = await act({ action: 'add-client', identifier: 'a-' + RUN,
    baseUrl: base, authMethod: 'none' });
  t.check(!none.ok && /must authenticate/.test(none.errors.join(' ')),
          'A5. a client with no authentication is refused');
  t.check(!applications.get('a-' + RUN), 'A6. a refused add writes nothing');
  log.debug('Leaving validation().');
}

async function basicPush(t, base, ca) {
  log.debug('Entering basicPush().');
  ldap.createUser('alice' + RUN, { attributes: { givenName: 'Alice',
    sn: 'Smith', mail: 'alice' + RUN + '@example.test' } });
  ldap.createUser('bob' + RUN, { attributes: { givenName: 'Bob',
    sn: 'Jones', mail: 'bob' + RUN + '@example.test' } });
  ldap.createGroup('staff' + RUN, { members: ['alice' + RUN] });
  const added = await act({ action: 'add-client', identifier: 'basic-' + RUN,
    name: 'Basic SP', baseUrl: base, authMethod: 'basic',
    username: 'pusher', password: BASIC_PASSWORD, caCertificates: ca,
    groupMode: 'member-groups', enabled: 'true' });
  t.check(added.ok && added.client && added.client.usable &&
          added.client.passwordSet,
          'B1. a Basic client is added, usable, its password set',
          JSON.stringify(added));
  t.check(!!applications.get('basic-' + RUN) &&
          scimClients.isClient(applications.get('basic-' + RUN)),
          'B2. the client is an application entry declared for scim-client');
  const reconciled = await act({ action: 'reconcile', id: 'basic-' + RUN });
  t.check(reconciled.ok && reconciled.users >= 2,
          'B3. a reconciliation queues every person in scope',
          JSON.stringify(reconciled));
  await drain();
  const alice = userNamed('alice' + RUN);
  const bob = userNamed('bob' + RUN);
  t.check(!!alice && !!bob, 'B4. both people were created at the service ' +
          'provider');
  const posts = sp.requests.filter(function (r) {
    return r.method === 'POST' && /\/Users$/.test(r.path) && r.body &&
           r.body.userName === 'alice' + RUN;
  });
  const post = posts[0] || {};
  t.check(!!post.body && !post.body.id && !post.body.meta &&
          !post.body.groups &&
          post.body.schemas[0] ===
            'urn:ietf:params:scim:schemas:core:2.0:User' &&
          post.body.externalId === uuidOf('alice' + RUN) &&
          /^application\/scim\+json/.test(post.headers['content-type']),
          'B5. the create carries externalId, no id, meta or groups, the ' +
          'core schema first, as application/scim+json',
          JSON.stringify(post.body));
  const staff = groupNamed('staff' + RUN);
  t.check(!!staff && (staff.body.members || []).some(function (m) {
    return m.value === alice.id;
  }), 'B6. the group is pushed with its member named by the service ' +
          'provider\'s id', JSON.stringify(staff && staff.body));
  const view = scimClients.view({ client: 'basic-' + RUN });
  t.check(view.client && view.client.queues.counts.sent >= 3 &&
          view.client.linked >= 3 && view.client.discovery &&
          view.client.discovery.patch === true,
          'B7. the client\'s page shows its sent rows, links and discovery',
          JSON.stringify(view.client && view.client.queues.counts));
  log.debug('Leaving basicPush().');
}

async function changes(t) {
  log.debug('Entering changes().');
  const dn = 'uid=bob' + RUN + ',' + ldap.usersDn();
  const entry = ldap.readPerson(dn);
  const attrs = Object.assign({}, entry.attributes, { title: 'Engineer' });
  sp.fail.push({ method: 'PUT', path: '/Users/', status: 412 });
  ldap.writePerson(dn, attrs);
  await drain();
  const bob = userNamed('bob' + RUN);
  const puts = sp.requests.filter(function (r) {
    return r.method === 'PUT' && r.path.indexOf('/Users/' + bob.id) >= 0;
  });
  t.check(bob.body.title === 'Engineer' && puts.length >= 2 &&
          !!puts[puts.length - 1].headers['if-match'],
          'C1. a change is a PUT to the linked id, and a 412 re-reads and ' +
          'tries again with If-Match', JSON.stringify(bob.body));
  // D: a resource already there under the userName, with no externalId.
  sp.users['sp-pre'] = { id: 'sp-pre', v: 1, body: {
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
    userName: 'carol' + RUN } };
  ldap.createUser('carol' + RUN, { attributes: { givenName: 'Carol',
                                                 sn: 'Day' } });
  await drain();
  t.check(Object.keys(sp.users).filter(function (k) {
    return sp.users[k].body.userName === 'carol' + RUN;
  }).length === 1 && sp.users['sp-pre'].body.externalId ===
    uuidOf('carol' + RUN),
          'D1. a 409 uniqueness adopts the resource found by userName');
  // E: a disabled person is deactivated.
  accountState.setDisabled('carol' + RUN, true, { actor: 'tester' });
  await drain();
  t.check(sp.users['sp-pre'].body.active === false &&
          sp.requests.some(function (r) {
            return r.method === 'PATCH' &&
                   r.path.indexOf('/Users/sp-pre') >= 0;
          }) || sp.users['sp-pre'].body.active === false,
          'E1. a disabled person is deactivated there (active false)',
          JSON.stringify(sp.users['sp-pre'].body));
  log.debug('Leaving changes().');
}

async function scopeAndDeprovision(t) {
  log.debug('Entering scopeAndDeprovision().');
  sp.patch = false;
  const changed = await act({ action: 'update-client', id: 'basic-' + RUN,
    scopeMode: 'groups', scopeGroups: 'staff' + RUN });
  t.check(changed.ok, 'F1. the scope is changed to a group',
          JSON.stringify(changed));
  await act({ action: 'reconcile', id: 'basic-' + RUN });
  await drain();
  const bob = userNamed('bob' + RUN);
  t.check(bob && bob.body.active === false &&
          userNamed('alice' + RUN).body.active !== false,
          'F2. a person out of scope is deactivated by a reconciliation, ' +
          'and one in scope is not', JSON.stringify(bob && bob.body));
  t.check(sp.requests.some(function (r) {
    return r.method === 'GET' && r.path.indexOf('/Users/' + bob.id) >= 0;
  }) && !sp.requests.some(function (r) {
    return r.method === 'PATCH' && r.path.indexOf('/Users/' + bob.id) >= 0;
  }), 'E2. without PATCH support the deactivation is GET then PUT');
  sp.patch = true;
  await act({ action: 'update-client', id: 'basic-' + RUN,
              scopeMode: 'filter', scopeFilter: '(givenName=Alice)',
              deprovision: 'delete' });
  const aliceId = userNamed('alice' + RUN).id;
  delete sp.users[userNamed('bob' + RUN).id];
  await act({ action: 'reconcile', id: 'basic-' + RUN });
  await drain();
  t.check(!!sp.users[aliceId] && !userNamed('carol' + RUN) &&
          sp.requests.some(function (r) {
            return r.method === 'DELETE' && /\/Users\//.test(r.path);
          }),
          'F3. by an LDAP filter; deprovision=delete DELETEs what left the ' +
          'scope, and a 404 on a DELETE is done');
  const v = scimClients.view({ client: 'basic-' + RUN });
  t.check(v.client.queues.counts.dead === 0,
          'F4. nothing became a dead letter on the way',
          JSON.stringify(v.client.queues.dead));
  log.debug('Leaving scopeAndDeprovision().');
}

async function backoff(t, base, ca) {
  log.debug('Entering backoff().');
  await act({ action: 'update-client', id: 'basic-' + RUN,
              scopeMode: 'all', deprovision: 'deactivate' });
  sp.fail.push({ method: 'PUT', path: '/Users/', status: 503,
                 headers: { 'Retry-After': '120' } });
  const dn = 'uid=alice' + RUN + ',' + ldap.usersDn();
  const entry = ldap.readPerson(dn);
  ldap.writePerson(dn, Object.assign({}, entry.attributes,
                                      { title: 'Lead' }));
  await scimClients.delivery().sweep();
  const v = scimClients.view({ client: 'basic-' + RUN });
  t.check(!!v.client.pausedUntil && v.client.failures === 1 &&
          v.client.queues.counts.retrying >= 1,
          'G1. a 503 is retried and PAUSES the client',
          JSON.stringify({ paused: v.client.pausedUntil,
                           counts: v.client.queues.counts }));
  const retrying = v.client.queues.retrying[0];
  const nextMs = Date.parse(retrying.nextAttemptAt) - Date.now();
  t.check(nextMs > 100000, 'G2. the retry waits at least the Retry-After',
          String(nextMs));
  // Another change while paused: held.
  const bobDn = 'uid=bob' + RUN + ',' + ldap.usersDn();
  const bob = ldap.readPerson(bobDn);
  ldap.writePerson(bobDn, Object.assign({}, bob.attributes,
                                        { title: 'Held' }));
  const before = sp.requests.length;
  await scimClients.delivery().sweep();
  t.check(sp.requests.length === before,
          'G3. a paused client\'s other deliveries are held');
  const lifted = await act({ action: 'deliver-now', id: 'basic-' + RUN });
  t.check(lifted.ok, 'G4. deliver-now lifts the pause');
  await drain();
  const after = scimClients.view({ client: 'basic-' + RUN }).client;
  t.check(!after.pausedUntil && after.failures === 0 &&
          userNamed('alice' + RUN).body.title === 'Lead' &&
          userNamed('bob' + RUN).body.title === 'Held',
          'G5. after it, both deliveries are sent and the pause is over',
          JSON.stringify({ failures: after.failures }));
  log.debug('Leaving backoff().');
}

async function deadLetters(t, base, ca) {
  log.debug('Entering deadLetters().');
  const other = await act({ action: 'add-client', identifier: 'other-' + RUN,
    baseUrl: base, authMethod: 'basic', username: 'pusher',
    password: BASIC_PASSWORD, caCertificates: ca, enabled: 'true' });
  t.check(other.ok, 'H0. a second client is added', JSON.stringify(other));
  sp.fail.push({ method: 'PUT', path: '/Users/', status: 400,
                 scimType: 'invalidValue' });
  const dn = 'uid=alice' + RUN + ',' + ldap.usersDn();
  const entry = ldap.readPerson(dn);
  ldap.writePerson(dn, Object.assign({}, entry.attributes,
                                      { title: 'Rejected' }));
  await drain(2);
  const one = scimClients.view({ client: 'basic-' + RUN }).client;
  const two = scimClients.view({ client: 'other-' + RUN }).client;
  t.check(one.queues.counts.dead + two.queues.counts.dead === 1 &&
          !one.pausedUntil && !two.pausedUntil,
          'H1. a 400 is a dead letter on ONE client\'s own queue, and ' +
          'pauses nobody', JSON.stringify([one.queues.counts,
                                            two.queues.counts]));
  const holder = one.queues.counts.dead ? one : two;
  const dead = holder.queues.dead[0];
  t.check(dead && dead.errorCode === 'STS-SCIMC-0007',
          'H2. the dead letter carries STS-SCIMC-0007',
          JSON.stringify(dead));
  const retried = await act({ action: 'retry-delivery', id: dead.id });
  await drain();
  t.check(retried.ok && scimClients.view({ client: holder.identifier })
    .client.queues.counts.dead === 0,
          'H3. retry-delivery sends it again', JSON.stringify(retried));
  sp.fail.push({ method: 'PUT', path: '/Users/', status: 400 });
  sp.fail.push({ method: 'PUT', path: '/Users/', status: 400 });
  ldap.writePerson(dn, Object.assign({}, ldap.readPerson(dn).attributes,
                                      { title: 'Again' }));
  await drain(2);
  const purged = await act({ action: 'purge-dead', id: holder.identifier });
  t.check(purged.ok && purged.count >= 1 &&
          scimClients.view({ client: holder.identifier })
            .client.queues.counts.dead === 0,
          'H4. purge-dead empties that client\'s dead-letter queue',
          JSON.stringify(purged));
  await act({ action: 'remove-client', id: 'other-' + RUN });
  t.check(!applications.get('other-' + RUN),
          'H5. remove-client deletes the application entry');
  log.debug('Leaving deadLetters().');
}

async function oauth(t, base, ca) {
  log.debug('Entering oauth().');
  sp.auth = 'bearer';
  const origin = base.replace(/\/scim\/v2$/, '');
  for (const how of ['client_secret_basic', 'client_secret_post']) {
    const id = 'oauth-' + how.slice(-4) + '-' + RUN;
    const added = await act({ action: 'add-client', identifier: id,
      baseUrl: base, authMethod: 'oauth2', tokenEndpoint: origin + '/token',
      oauthClientId: 'pusher-app', oauthClientSecret: OAUTH_SECRET,
      oauthClientAuth: how, oauthScope: 'scim', caCertificates: ca,
      enabled: 'true' });
    const tested = await act({ action: 'test-connection', id: id });
    t.check(added.ok && tested.ok && sp.tokenRequests.some(function (r) {
      return r.how === how && r.grant === 'client_credentials' &&
             r.scope === 'scim';
    }), 'I1. OAuth 2.0 ' + how + ' gets a token and the connection works',
            JSON.stringify(tested));
    await act({ action: 'remove-client', id: id });
  }
  const id = 'oauth-' + RUN;
  await act({ action: 'add-client', identifier: id, baseUrl: base,
    authMethod: 'oauth2', tokenEndpoint: origin + '/token',
    oauthClientId: 'pusher-app', oauthClientSecret: OAUTH_SECRET,
    caCertificates: ca, enabled: 'true' });
  await act({ action: 'test-connection', id: id });
  const count = sp.tokenRequests.length;
  await act({ action: 'test-connection', id: id });
  t.check(sp.tokenRequests.length === count,
          'I2. the token is cached between requests');
  sp.invalidateTokens = true;
  const again = await act({ action: 'test-connection', id: id });
  t.check(again.ok && sp.tokenRequests.length === count + 1,
          'I3. a 401 on a cached token gets one fresh token',
          JSON.stringify(again));
  await act({ action: 'remove-client', id: id });
  sp.auth = 'basic';
  log.debug('Leaving oauth().');
}

async function certificate(t, material, ca) {
  log.debug('Entering certificate().');
  const id = 'mtls-' + RUN;
  const added = await act({ action: 'add-client', identifier: id,
    baseUrl: 'https://localhost:1/scim/v2', authMethod: 'none',
    tlsSource: 'issued', caCertificates: ca });
  t.check(added.ok && added.client && !added.client.usable,
          'J1. a client waiting for its issued certificate is added and ' +
          'not usable yet', JSON.stringify(added));
  const issued = await act({ action: 'issue-certificate', id: id });
  t.check(issued.ok && issued.certificate && issued.certificate.rootPem,
          'J2. a TLS client certificate is issued by the realm\'s CA',
          JSON.stringify(issued));
  const server = await startProvider(material, issued.certificate.rootPem);
  const base = 'https://localhost:' + server.address().port + '/scim/v2';
  sp.auth = 'certificate';
  try {
    await act({ action: 'update-client', id: id, baseUrl: base,
                enabled: 'true' });
    const tested = await act({ action: 'test-connection', id: id });
    t.check(tested.ok && sp.clientCertificate &&
            /mtls-/.test(JSON.stringify(sp.clientCertificate.subject)),
            'J3. the certificate is presented and accepted',
            JSON.stringify(tested));
  } finally {
    sp.auth = 'basic';
    server.close();
    await act({ action: 'remove-client', id: id });
  }
  log.debug('Leaving certificate().');
}

async function run(t) {
  log.debug('Entering run().');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scimc-'));
  const material = makeCertificates(dir);
  const server = await startProvider(material);
  const base = 'https://localhost:' + server.address().port + '/scim/v2';
  const realm = realms.create({ id: 'scimc-' + RUN,
                                name: 'scim client ' + RUN }).realm;
  const helpersLog = require('../common/helpers').log;
  const level = helpersLog.level();
  const lines = [];
  const write = process.stdout.write;
  helpersLog.level('debug');
  process.stdout.write = function (chunk) {
    lines.push(String(chunk));
    return true;
  };
  try {
    await realms.run(realm, async function () {
      await validation(t, base);
      await basicPush(t, base, material.ca);
      await changes(t);
      await scopeAndDeprovision(t);
      await backoff(t, base, material.ca);
      await deadLetters(t, base, material.ca);
      await oauth(t, base, material.ca);
      await certificate(t, material, material.ca);
      const shown = JSON.stringify(scimClients.view({
        client: 'basic-' + RUN })) + JSON.stringify(audit.list());
      t.check(HIDE.every(function (s) {
        return shown.indexOf(s) < 0;
      }) && /scim-client\.delivery/.test(shown),
              'K1. no view or audit row holds a credential');
      await act({ action: 'remove-client', id: 'basic-' + RUN });
    });
  } finally {
    process.stdout.write = write;
    helpersLog.level(level);
    server.close();
    realms.remove(realm.id);
  }
  lines.forEach(function (line) {
    if (line.indexOf('"level":20,') < 0) {
      process.stdout.write(line);
    }
  });
  const output = lines.join('');
  t.check(lines.length > 100 && HIDE.every(function (s) {
    return output.indexOf(s) < 0;
  }), 'K2. no log line, debug included, holds a credential (' +
          lines.length + ' lines read)');
  log.debug('Leaving run().');
}

module.exports = {
  name: 'scim_client',
  describe: 'The outbound SCIM client (#552) against a fake SCIM service ' +
            'provider: application-entry clients, Basic / OAuth 2.0 / ' +
            'TLS client certificates, create / replace / 412 / 409 adoption ' +
            '/ deactivate / delete, scope by group and filter, ' +
            'reconciliation, the exponential backoff and client pause, the ' +
            'per-client retry and dead-letter queues, and no credential ' +
            'anywhere it is shown',
  run: run
};
