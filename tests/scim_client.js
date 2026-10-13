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
//   K. no credential appears in any view, audit row or log line;
// and, added by the audit against #552's checklist (2026-10-13), each
// against a fresh service provider and a client of its own:
//   L. the four group modes — none, selected, member-groups, all — and a
//      group's members changed by PATCH add and PATCH remove by value;
//   M. a 409 uniqueness adopts the resource found by EXTERNALID (a linked
//      id gone, the resource re-created there under another id); a 409
//      without uniqueness is a dead letter, nothing adopted;
//   N. a required enterprise extension is sent (empty); any other required
//      extension is a dead letter naming it (STS-SCIMC-0029); the required
//      attributes (STS-SCIMC-0030); a replace clears what the entry lost
//      (null, []) — and a change after a purge-dead is sent at once, not
//      after the lease its old row's claim held; 408 is not retried; a 400
//      invalidVers re-reads and tries again; an Error body's status read as
//      a number or a string;
//   O. a reconciliation pages through a service provider that sends no
//      totalResults and answers tooMany above three a page — narrowed, and
//      every page read; an externalId lookup answered tooMany is narrowed;
//   P. the scheduled reconciliation (scim-client.reconcile): a client whose
//      interval has come round is reconciled, and not again before it has;
//   Q. a DELETE answered 412 re-reads and deletes again with If-Match;
//   R. an UPLOADED TLS client certificate is presented with Basic, and with
//      an OAuth 2.0 token.
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
const scimRules = require('../scim/scim_client_rules');
const scheduler = require('../cluster/scheduler');
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
    clientCertificate: null,
    // A verified client certificate asked of every SCIM request, beside
    // `auth`.
    requireCert: false,
    // An unfiltered list asking for more than this a page is answered 400
    // tooMany (0: never).
    tooManyAbove: 0,
    // Lists answer no totalResults.
    omitTotal: false,
    // /ResourceTypes' required schemaExtensions, by type.
    requiredExtensions: {}
  };
}

let sp = freshProvider();

// RFC 7644 section 3.12's Error. `numeric` sends `status` as a number, as
// some service providers do; the specification's examples use a string.
function scimError(res, status, scimType, detail, headers, numeric) {
  log.debug('Entering scimError().');
  res.writeHead(status, Object.assign({
    'Content-Type': 'application/scim+json' }, headers || {}));
  res.end(JSON.stringify({ schemas: [
    'urn:ietf:params:scim:api:messages:2.0:Error'],
    status: numeric ? status : String(status),
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
  const present = /^(\w+) pr$/.exec(filter);
  if (present) {
    log.debug('Leaving matchesFilter(). pr.');
    return !!r.body[present[1]];
  }
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
  // Authentication: a client certificate where asked, and then the scheme.
  if (sp.requireCert) {
    const peer = req.socket.getPeerCertificate();
    sp.clientCertificate = peer && peer.subject ? peer : null;
    if (!req.client.authorized) {
      return scimError(res, 401, undefined, 'no certificate');
    }
  }
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
    if (f.method === req.method && url.pathname.indexOf(f.path) >= 0 &&
        (!f.query || url.search.indexOf(f.query) >= 0)) {
      sp.fail.splice(i, 1);
      return scimError(res, f.status, f.scimType, 'scripted', f.headers,
                       f.numeric);
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
      Resources: ['User', 'Group'].map(function (name) {
        return { id: name, name: name, endpoint: '/' + name + 's',
                 schemaExtensions: (sp.requiredExtensions[name] || [])
                   .map(function (schema) {
                     return { schema: schema, required: true };
                   }) };
      }) });
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
    if (sp.tooManyAbove && !filter && count > sp.tooManyAbove) {
      return scimError(res, 400, 'tooMany', 'ask for fewer');
    }
    const page = all.slice(start - 1, start - 1 + count);
    const answer = { schemas: [
      'urn:ietf:params:scim:api:messages:2.0:ListResponse'],
      startIndex: start, itemsPerPage: page.length };
    if (!sp.omitTotal) {
      answer.totalResults = all.length;
    }
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

// One sweep, then a pause in which the event loop serves the fake service
// provider: a sweep that resolves on promises alone never yields to I/O, so
// the provider — in this process — would never get to answer. A sweep the
// reconciliation started, and did not wait for, settles in the pause too.
async function sweepOnce() {
  log.debug('Entering sweepOnce().');
  await scimClients.delivery().sweep();
  await new Promise(function (resolve) {
    setTimeout(resolve, 150);
  });
  log.debug('Leaving sweepOnce().');
}

// Sends what is due until nothing more reaches the provider, the pause aside.
async function drain(times) {
  log.debug('Entering drain().');
  let quiet = 0;
  for (let i = 0; i < (times || 40) && quiet < 3; i++) {
    const before = sp.requests.length;
    await sweepOnce();
    quiet = sp.requests.length === before ? quiet + 1 : 0;
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
  await sweepOnce();
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
  await sweepOnce();
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

// ---------------------------------------------------------------------------
// THE AUDIT'S SECTIONS (2026-10-13): each against a fresh service provider
// and a client of its own, after the Basic client is gone.
// ---------------------------------------------------------------------------
const ENTERPRISE =
  'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User';

// A Basic client of the realm, enabled, with what `extra` adds.
async function addBasic(id, base, ca, extra) {
  log.debug('Entering addBasic(). ' + id);
  const answer = await act(Object.assign({ action: 'add-client',
    identifier: id, baseUrl: base, authMethod: 'basic', username: 'pusher',
    password: BASIC_PASSWORD, caCertificates: ca, enabled: 'true' },
    extra || {}));
  log.debug('Leaving addBasic().');
  return answer;
}

// A person's entry rewritten: `set` added, the attributes `drop` names gone.
function rewrite(name, set, drop) {
  log.debug('Entering rewrite(). ' + name);
  const dn = 'uid=' + name + ',' + ldap.usersDn();
  const attrs = Object.assign({}, ldap.readPerson(dn).attributes);
  (drop || []).forEach(function (gone) {
    Object.keys(attrs).forEach(function (key) {
      if (key.toLowerCase() === gone.toLowerCase()) {
        delete attrs[key];
      }
    });
  });
  ldap.writePerson(dn, Object.assign(attrs, set || {}));
  log.debug('Leaving rewrite().');
}

// The requests whose method is `method` and whose path holds `part`.
function requestsTo(method, part) {
  log.debug('Entering requestsTo().');
  const out = sp.requests.filter(function (r) {
    return r.method === method && r.path.indexOf(part) >= 0;
  });
  log.debug('Leaving requestsTo(). ' + out.length);
  return out;
}

function deadOf(id) {
  log.debug('Entering deadOf().');
  const out = scimClients.view({ client: id }).client.queues.dead;
  log.debug('Leaving deadOf(). ' + out.length);
  return out;
}

async function groupModes(t, base, ca) {
  log.debug('Entering groupModes().');
  sp = freshProvider();
  ldap.createGroup('other' + RUN, { members: ['bob' + RUN] });
  const id = 'gm-' + RUN;
  await addBasic(id, base, ca, { groupMode: 'none' });
  await act({ action: 'reconcile', id: id });
  await drain();
  t.check(!!userNamed('alice' + RUN) && !Object.keys(sp.groups).length &&
          !requestsTo('POST', '/Groups').length,
          'L1. group mode none pushes people and no group');
  await act({ action: 'update-client', id: id, groupMode: 'selected',
              groups: 'staff' + RUN });
  await act({ action: 'reconcile', id: id });
  await drain();
  t.check(!!groupNamed('staff' + RUN) && !groupNamed('other' + RUN),
          'L2. group mode selected pushes the named group and no other');
  await act({ action: 'update-client', id: id, groupMode: 'member-groups',
              scopeMode: 'filter', scopeFilter: '(givenName=Alice)' });
  await act({ action: 'reconcile', id: id });
  await drain();
  t.check(!!groupNamed('staff' + RUN) && !groupNamed('other' + RUN),
          'L3. group mode member-groups pushes only a group with a member ' +
          'in scope');
  await act({ action: 'update-client', id: id, groupMode: 'all' });
  await act({ action: 'reconcile', id: id });
  await drain();
  const other = groupNamed('other' + RUN);
  t.check(!!other && !(other.body.members || []).length,
          'L4. group mode all pushes every group, its members limited to ' +
          'the people in scope', JSON.stringify(other && other.body));
  await act({ action: 'update-client', id: id, scopeMode: 'all' });
  await act({ action: 'reconcile', id: id });
  await drain();
  const bob = userNamed('bob' + RUN);
  const added = requestsTo('PATCH', '/Groups/' + other.id).filter(
    function (r) {
      return (r.body.Operations || []).some(function (op) {
        return op.op === 'add' && op.path === 'members' &&
               JSON.stringify(op.value) === JSON.stringify([{
                 value: bob.id }]);
      });
    });
  t.check(added.length >= 1 && (groupNamed('other' + RUN).body.members ||
    []).some(function (m) {
    return m.value === bob.id;
  }), 'L5. a member who came into scope is added by PATCH add members',
          JSON.stringify(requestsTo('PATCH', '/Groups/').map(function (r) {
            return r.body;
          })));
  await act({ action: 'update-client', id: id, scopeMode: 'filter',
             scopeFilter: '(givenName=Alice)' });
  await act({ action: 'reconcile', id: id });
  await drain();
  const removed = requestsTo('PATCH', '/Groups/' + other.id).filter(
    function (r) {
      return (r.body.Operations || []).some(function (op) {
        return op.op === 'remove' &&
               op.path === 'members[value eq ' + JSON.stringify(bob.id) +
                           ']';
      });
    });
  t.check(removed.length >= 1 &&
          !(groupNamed('other' + RUN).body.members || []).length,
          'L6. a member who left the scope is removed by PATCH remove ' +
          'members[value eq "..."]');
  t.check(deadOf(id).length === 0, 'L7. no dead letter on the way',
          JSON.stringify(deadOf(id)));
  await act({ action: 'remove-client', id: id });
  log.debug('Leaving groupModes().');
}

async function adoption(t, base, ca) {
  log.debug('Entering adoption().');
  sp = freshProvider();
  const id = 'adopt-' + RUN;
  ldap.createUser('dave' + RUN, { attributes: { givenName: 'Dave',
                                                sn: 'Moore' } });
  await addBasic(id, base, ca);
  await act({ action: 'reconcile', id: id });
  await drain();
  const first = userNamed('dave' + RUN);
  // Re-created there under another id: the link's id is gone.
  delete sp.users[first.id];
  sp.users['sp-moved'] = Object.assign({}, first, { id: 'sp-moved' });
  const mark = sp.requests.length;
  rewrite('dave' + RUN, { title: 'Moved' });
  await drain();
  const after = sp.requests.slice(mark);
  const post = after.findIndex(function (r) {
    return r.method === 'POST' && /\/Users$/.test(r.path);
  });
  const search = after.findIndex(function (r, i) {
    return i > post && r.method === 'GET' &&
           decodeURIComponent(r.path).indexOf('externalId eq ' +
             JSON.stringify(uuidOf('dave' + RUN))) >= 0;
  });
  t.check(post >= 0 && search > post &&
          sp.users['sp-moved'].body.title === 'Moved' &&
          !after.some(function (r) {
            return /userName eq/.test(decodeURIComponent(r.path));
          }),
          'M1. a 409 uniqueness adopts the resource found by externalId',
          JSON.stringify(after.map(function (r) {
            return r.method + ' ' + r.path;
          })));
  sp.fail.push({ method: 'POST', path: '/Users', status: 409 });
  ldap.createUser('frank' + RUN, { attributes: { givenName: 'Frank',
                                                 sn: 'Hill' } });
  await drain(3);
  const dead = deadOf(id);
  t.check(dead.length === 1 && dead[0].errorCode === 'STS-SCIMC-0007' &&
          /409/.test(dead[0].why) && !userNamed('frank' + RUN),
          'M2. a 409 without uniqueness is a dead letter, nothing adopted',
          JSON.stringify(dead));
  await act({ action: 'remove-client', id: id });
  log.debug('Leaving adoption().');
}

async function resourceRules(t, base, ca) {
  log.debug('Entering resourceRules().');
  sp = freshProvider();
  sp.requiredExtensions = { User: [ENTERPRISE] };
  const id = 'ext-' + RUN;
  await addBasic(id, base, ca, { scopeMode: 'filter',
                                 scopeFilter: '(sn=Green)' });
  ldap.createUser('gina' + RUN, { attributes: { givenName: 'Gina',
    sn: 'Green', title: 'Analyst', mail: 'gina' + RUN + '@example.test' } });
  await drain();
  const post = requestsTo('POST', '/Users').filter(function (r) {
    return r.body && r.body.userName === 'gina' + RUN;
  })[0];
  t.check(!!post && post.body.schemas.indexOf(ENTERPRISE) > 0 &&
          typeof post.body[ENTERPRISE] === 'object',
          'N1. a required enterprise extension is sent, empty if need be',
          JSON.stringify(post && post.body));
  sp.requiredExtensions = { User: ['urn:example:scim:ext:Badge'] };
  await act({ action: 'test-connection', id: id });
  rewrite('gina' + RUN, { title: 'Lead' });
  await drain(3);
  let dead = deadOf(id);
  t.check(dead.length === 1 && dead[0].errorCode === 'STS-SCIMC-0029' &&
          dead[0].why.indexOf('urn:example:scim:ext:Badge') >= 0 &&
          userNamed('gina' + RUN).body.title === 'Analyst',
          'N2. any other required extension is a dead letter naming it, ' +
          'and nothing is sent', JSON.stringify(dead));
  await act({ action: 'purge-dead', id: id });
  sp.requiredExtensions = {};
  await act({ action: 'test-connection', id: id });
  t.check(scimRules.missingRequired('User', {}).join() === 'userName' &&
          scimRules.missingRequired('Group', { displayName: ' ' }).join() ===
            'displayName' &&
          scimRules.missingRequired('User', { userName: 'x' }).length === 0,
          'N3. a User without userName or a Group without displayName is ' +
          'not sendable (STS-SCIMC-0030)');
  rewrite('gina' + RUN, { title: 'Lead' });
  await drain();
  const mark = sp.requests.length;
  rewrite('gina' + RUN, {}, ['title', 'mail']);
  await drain();
  const put = sp.requests.slice(mark).filter(function (r) {
    return r.method === 'PUT' && /\/Users\//.test(r.path);
  }).pop();
  t.check(!!put && 'title' in put.body && put.body.title === null &&
          Array.isArray(put.body.emails) && !put.body.emails.length,
          'N4. a replace clears what the entry lost: null, and [] for a ' +
          'multi-valued attribute', JSON.stringify(put && put.body));
  sp.fail.push({ method: 'PUT', path: '/Users/', status: 408 });
  rewrite('gina' + RUN, { title: 'Timed' });
  await drain(3);
  dead = deadOf(id);
  t.check(dead.length === 1 && dead[0].attempts === 1 &&
          dead[0].errorCode === 'STS-SCIMC-0007',
          'N5. 408 is not retried: a dead letter after one attempt',
          JSON.stringify(dead));
  await act({ action: 'purge-dead', id: id });
  const user = userNamed('gina' + RUN);
  const before = sp.requests.length;
  sp.fail.push({ method: 'PUT', path: '/Users/', status: 400,
                 scimType: 'invalidVers' });
  rewrite('gina' + RUN, { title: 'Versioned' });
  await drain();
  const seq = sp.requests.slice(before).filter(function (r) {
    return r.path.indexOf('/Users/' + user.id) >= 0;
  }).map(function (r) {
    return r.method;
  }).join(' ');
  t.check(/PUT GET PUT/.test(seq) &&
          userNamed('gina' + RUN).body.title === 'Versioned' &&
          deadOf(id).length === 0,
          'N6. a 400 invalidVers re-reads the version and tries again', seq);
  sp.fail.push({ method: 'PUT', path: '/Users/', status: 400,
                 scimType: 'invalidValue', numeric: true });
  rewrite('gina' + RUN, { title: 'Numbered' });
  await drain(3);
  dead = deadOf(id);
  t.check(dead.length === 1 && /scimType invalidValue/.test(dead[0].why) &&
          scimRules.errorOf({ status: 409, scimType: 'uniqueness' })
            .status === 409 &&
          scimRules.errorOf({ status: '409' }).status === 409 &&
          scimRules.errorOf({ scimType: 'a b' }).scimType === '',
          'N7. an Error body is read whether its status is a number or a ' +
          'string, and its scimType is on the dead letter',
          JSON.stringify(dead));
  await act({ action: 'remove-client', id: id });
  log.debug('Leaving resourceRules().');
}

async function paging(t, base, ca) {
  log.debug('Entering paging().');
  sp = freshProvider();
  sp.omitTotal = true;
  sp.tooManyAbove = 3;
  const id = 'page-' + RUN;
  await addBasic(id, base, ca, { scopeMode: 'filter',
                                 scopeFilter: '(givenName=Alice)' });
  // Every other person of the realm is there already, out of scope; and two
  // resources nobody here owns.
  const first = function (attrs, name) {
    log.debug('Entering first(). ' + name);
    const key = Object.keys(attrs || {}).filter(function (one) {
      return one.toLowerCase() === name.toLowerCase();
    })[0];
    log.debug('Leaving first().');
    return key ? String([].concat(attrs[key])[0]) : '';
  };
  let known = 0;
  ldap.allPersons().forEach(function (person) {
    const uuid = first(person.attributes, 'entryUUID').toLowerCase();
    const given = first(person.attributes, 'givenName');
    if (!uuid || given === 'Alice') {
      return;
    }
    known++;
    sp.users['seed-' + known] = { id: 'seed-' + known, v: 1, body: {
      schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
      userName: 'seed-' + known, externalId: uuid } };
  });
  ['f0', 'f1'].forEach(function (k) {
    sp.users['foreign-' + k] = { id: 'foreign-' + k, v: 1, body: {
      schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
      userName: 'foreign-' + k, externalId: nodeCrypto.randomUUID() } };
  });
  const result = await act({ action: 'reconcile', id: id });
  const lists = requestsTo('GET', '/Users?startIndex=').map(function (r) {
    return r.path;
  });
  t.check(known >= 3 && result.ok && result.deprovisioned === known,
          'O1. with no totalResults every page is read: each of ' + known +
          ' resources out of scope is found', JSON.stringify(result));
  t.check(lists.some(function (one) {
    return /count=50/.test(one);
  }) && lists.some(function (one) {
    return /count=3&/.test(one) && !/startIndex=1&/.test(one);
  }), 'O2. tooMany halves the page until it is answered, then pages on',
          JSON.stringify(lists));
  await drain();
  sp.tooManyAbove = 0;
  sp.fail.push({ method: 'GET', path: '/Users', query: 'filter=',
                 status: 400, scimType: 'tooMany' });
  ldap.createUser('hank' + RUN, { attributes: { givenName: 'Alice',
                                                sn: 'Hank' } });
  await drain();
  t.check(!!userNamed('hank' + RUN) && requestsTo('GET', 'count=2').some(
    function (r) {
      return /filter=/.test(r.path);
    }), 'O3. an externalId lookup answered tooMany asks for a page of two');
  t.check(deadOf(id).length === 0, 'O4. no dead letter on the way',
          JSON.stringify(deadOf(id)));
  await act({ action: 'remove-client', id: id });
  log.debug('Leaving paging().');
}

async function scheduled(t, base, ca) {
  log.debug('Entering scheduled().');
  sp = freshProvider();
  const id = 'sched-' + RUN;
  await addBasic(id, base, ca, { scopeMode: 'filter',
                                 scopeFilter: '(givenName=Alice)',
                                 reconcileMinutes: '1' });
  t.check(!!scheduler.job('scim-client.reconcile') &&
          !!scheduler.job('scim-client.deliver'),
          'P0. both cluster scheduler jobs are registered');
  const first = await scimClients.reconcileDue();
  const view = scimClients.view({ client: id }).client;
  t.check(first.reconciled === 1 && !!view.lastReconcileAt,
          'P1. a client whose interval has come round is reconciled',
          JSON.stringify(first));
  await act({ action: 'update-client', id: id, enabled: 'false' });
  const refused = await act({ action: 'reconcile', id: id });
  t.check(!refused.ok && codeOf(refused) === 'STS-SCIMC-0017',
          'P1b. a disabled client is not reconciled by hand',
          JSON.stringify(refused));
  await act({ action: 'update-client', id: id, enabled: 'true' });
  const second = await scimClients.reconcileDue();
  t.check(second.reconciled === 0,
          'P2. and not again before its interval has passed',
          JSON.stringify(second));
  await drain();
  t.check(!!userNamed('alice' + RUN),
          'P3. what the scheduled reconciliation queued is delivered');
  await act({ action: 'remove-client', id: id });
  log.debug('Leaving scheduled().');
}

async function deleteStale(t, base, ca) {
  log.debug('Entering deleteStale().');
  sp = freshProvider();
  const id = 'del-' + RUN;
  await addBasic(id, base, ca, { scopeMode: 'filter',
                                 scopeFilter: '(givenName=Alice)',
                                 deprovision: 'delete' });
  await act({ action: 'reconcile', id: id });
  await drain();
  const alice = userNamed('alice' + RUN);
  sp.fail.push({ method: 'DELETE', path: '/Users/', status: 412 });
  await act({ action: 'update-client', id: id,
              scopeFilter: '(givenName=Nobody' + RUN + ')' });
  await act({ action: 'reconcile', id: id });
  await drain();
  // Everybody given Alice was pushed and is deleted now; the first DELETE,
  // whichever it was, was answered 412.
  const deleted = requestsTo('DELETE', '/Users/').map(function (r) {
    return r.path.split('/').pop();
  });
  const seqs = deleted.map(function (rid) {
    return sp.requests.filter(function (r) {
      return r.path.indexOf('/Users/' + rid) >= 0;
    }).map(function (r) {
      return r.method + (r.headers['if-match'] ? '+If-Match' : '');
    }).join(' ');
  });
  t.check(seqs.some(function (seq) {
    return /DELETE\+If-Match GET DELETE\+If-Match/.test(seq);
  }) && !!alice && !sp.users[alice.id] && deadOf(id).length === 0,
          'Q1. a DELETE answered 412 re-reads and deletes again with ' +
          'If-Match', JSON.stringify(seqs));
  await act({ action: 'remove-client', id: id });
  log.debug('Leaving deleteStale().');
}

// A client certificate signed by the test CA, as an operator would upload.
function clientCertificate(dir) {
  log.debug('Entering clientCertificate().');
  const ossl = function (args) {
    const r = childProcess.spawnSync('openssl', args, { cwd: dir,
                                                       encoding: 'utf8' });
    if (r.status !== 0) {
      throw new Error('openssl ' + args[0] + ' failed: ' + r.stderr);
    }
  };
  ossl(['req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
        '-nodes', '-keyout', 'client.key', '-out', 'client.csr', '-subj',
        '/CN=uploaded-client-' + RUN]);
  fs.writeFileSync(path.join(dir, 'client.cnf'),
    'basicConstraints=critical,CA:FALSE\n' +
    'keyUsage=critical,digitalSignature\n' +
    'extendedKeyUsage=clientAuth\n');
  ossl(['x509', '-req', '-in', 'client.csr', '-CA', 'ca.crt', '-CAkey',
        'ca.key', '-CAcreateserial', '-out', 'client.crt', '-days', '2',
        '-extfile', 'client.cnf']);
  log.debug('Leaving clientCertificate().');
  return { cert: fs.readFileSync(path.join(dir, 'client.crt'), 'utf8'),
           key: fs.readFileSync(path.join(dir, 'client.key'), 'utf8') };
}

async function uploaded(t, material, dir) {
  log.debug('Entering uploaded().');
  sp = freshProvider();
  const pair = clientCertificate(dir);
  const server = await startProvider(material, material.ca);
  const base = 'https://localhost:' + server.address().port + '/scim/v2';
  const origin = base.replace(/\/scim\/v2$/, '');
  sp.requireCert = true;
  try {
    const id = 'up-' + RUN;
    const added = await addBasic(id, base, material.ca, {
      tlsSource: 'uploaded', tlsCertificate: pair.cert,
      tlsPrivateKey: pair.key });
    const tested = await act({ action: 'test-connection', id: id });
    t.check(added.ok && added.client.usable && tested.ok &&
            sp.clientCertificate &&
            /uploaded-client-/.test(JSON.stringify(
              sp.clientCertificate.subject)),
            'R1. an uploaded TLS client certificate is presented with Basic',
            JSON.stringify(tested));
    const shown = JSON.stringify(scimClients.view({ client: id }));
    const keyBody = pair.key.replace(/-----[^-]+-----/g, '')
      .replace(/\s+/g, '').slice(0, 40);
    t.check(shown.indexOf(keyBody) < 0 && /"tlsPrivateKeySet":true/.test(
      shown), 'R2. the uploaded private key is never shown, only that it ' +
            'is set');
    await act({ action: 'remove-client', id: id });
    sp.auth = 'bearer';
    sp.clientCertificate = null;
    const oid = 'upo-' + RUN;
    await act({ action: 'add-client', identifier: oid, baseUrl: base,
      authMethod: 'oauth2', tokenEndpoint: origin + '/token',
      oauthClientId: 'pusher-app', oauthClientSecret: OAUTH_SECRET,
      tlsSource: 'uploaded', tlsCertificate: pair.cert,
      tlsPrivateKey: pair.key, caCertificates: material.ca,
      enabled: 'true' });
    const count = sp.tokenRequests.length;
    const again = await act({ action: 'test-connection', id: oid });
    t.check(again.ok && sp.tokenRequests.length > count &&
            !!sp.clientCertificate,
            'R3. an uploaded TLS client certificate is presented with an ' +
            'OAuth 2.0 token', JSON.stringify(again));
    await act({ action: 'remove-client', id: oid });
  } finally {
    sp.auth = 'basic';
    sp.requireCert = false;
    server.close();
  }
  log.debug('Leaving uploaded().');
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
      await groupModes(t, base, material.ca);
      await adoption(t, base, material.ca);
      await resourceRules(t, base, material.ca);
      await paging(t, base, material.ca);
      await scheduled(t, base, material.ca);
      await deleteStale(t, base, material.ca);
      await uploaded(t, material, dir);
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
