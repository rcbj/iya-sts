// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: audit-vectors.js
//
// ---------------------------------------------------------------------------
// THE AUDIT LOG'S VECTORS (#444, phase 4): `auditmail-node.json`'s `audit`,
// which `rust/crates/sts-audit/tests/node_vectors.rs` replays.
//
// Everything is built in a CHILD process (`--child`), for two reasons: the
// ring, its counters and the actor resolvers are module state, and the row
// checksums need a key-encryption key, which is read once per process. The
// child freezes `Date.now()` (every row's `at`, every cursor's instants),
// uses an ephemeral KEK handed over as text (so Rust's keystore makes the
// same keyed digests), and writes its answer to a file.
//
// What it records, each as the STEPS that were run and what Node answered,
// so Rust runs the same steps and compares:
//
//   ring     audit(), failure(), recordDirectory(), recordHttp() and
//            withSource(), the ring after them, list(), summary(), the
//            readers of the attempts tabs, verifyIntegrity() over the ring
//            and over tampered copies, and the /admin-api/audit answer for
//            a set of queries (auditView().json)
//   helpers  the pure functions: redaction and classification
//   export   AuditExport (#641): every act and its refusal, every screen,
//            and ticks against scripted receivers — what each destination
//            was sent, byte for byte, the cursor after, the rows the
//            exporter audited, and view()
//
// The other direction (`fromRust()`): `audit-rust.json`, rows and events
// Rust made, checked with Node's own functions in a child of the same kind.
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');
const nodeCrypto = require('crypto');
const EventEmitter = require('events');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'audit_vectors',
  level: process.env.STS_LOG_LEVEL || 'info' });

const T0 = 1763100000000;

/**
 * Runs the child and returns what it wrote.
 *
 * @param {string} root - the repository root
 * @param {string} out - the vectors directory
 * @returns {Promise<any>} the audit vectors
 */
async function build(root, out) {
  log.debug("Entering build().");
  const childProcess = require('child_process');
  const kek = nodeCrypto.randomBytes(32).toString('hex');
  const answer = path.join(out, 'audit-answer.json');
  const work = path.join(out, 'audit-export-files');
  fs.rmSync(work, { recursive: true, force: true });
  fs.mkdirSync(work, { recursive: true });
  childProcess.execFileSync(process.execPath,
    [__filename, '--child', root, answer, kek, work],
    { env: Object.assign({}, process.env, { STS_LOG_LEVEL: 'fatal',
                                            STS_KEYS_SOURCE: 'generated' }),
      stdio: ['ignore', 'ignore', 'inherit'] });
  const built = JSON.parse(fs.readFileSync(answer, 'utf8'));
  fs.unlinkSync(answer);
  fs.rmSync(work, { recursive: true, force: true });
  built.kek = kek;
  log.debug("Leaving build().");
  return built;
}

// ===========================================================================
// THE CHILD.
// ===========================================================================

let NOW = T0;

/**
 * The child's work: every part, written to the answer file.
 *
 * @param {string} root - the repository root
 * @param {string} answer - where to write
 * @param {string} kek - the ephemeral KEK, hex
 * @param {string} work - a directory for the file destinations
 */
async function child(root, answer, kek, work) {
  log.debug("Entering child().");
  Date.now = function () {
    return NOW;
  };
  const C = function (name) {
    return require(path.join(root, 'common', name));
  };
  const keystore = C('keystore');
  keystore.useEphemeralKek(kek);
  const config = C('config');
  const out = {
    t0: T0,
    hostname: require('os').hostname(),
    pid: process.pid,
    userAgent: C('version').userAgent('audit-export'),
    realm: String(C('realms').currentId()),
    ring: ringPart(root, C, config),
    helpers: helpersPart(C)
  };
  out.export = await exportPart(root, C, config, work, out.ring.local);
  fs.writeFileSync(answer, JSON.stringify(out));
  log.debug("Leaving child().");
}

/**
 * Sets a setting, throwing when it is refused.
 *
 * @param {any} config - config.js
 * @param {string} key - the key
 * @param {any} value - the value
 * @returns {boolean} taken
 */
function setting(config, key, value) {
  log.debug("Entering setting(). " + key);
  const result = config.setOverride(key, value);
  if (!result || !result.ok) {
    throw new Error('setting ' + key + ' refused: ' +
                    JSON.stringify(result));
  }
  log.debug("Leaving setting().");
  return true;
}

const LONG = 'x'.repeat(190) + 'é😀' + 'y'.repeat(30);

// The ring's steps. Rust replays them in order.
const RING_STEPS = [
  { op: 'set', key: 'audit.maxEvents', value: 40 },
  { op: 'set', key: 'audit.protocolCalls', value: true },
  { op: 'audit', event: { action: 'authentication', actor: 'alice',
    actorForm: 'uid=alice,ou=users,dc=sts,dc=mock', target: 'sess-1',
    protocol: 'OIDC', channel: 'http', summary: 'Alice signed in',
    detail: { client_id: 'app-1', method: 'password', sub: 'urn:uuid:a1',
              nested: { a: 1 }, list: [1, 'two', null, [3, 4]],
              n: 1.5, yes: true, empty: '', gone: null } } },
  { op: 'now', at: T0 + 1000 },
  { op: 'audit', event: { action: 'authentication.refused',
    errorCode: 'STS-AUTHN-0001', actor: 'bob', summary: 'Bob refused',
    detail: { application: 'app-2', presented: 'bob@STS.MOCK' } } },
  { op: 'audit', event: { action: 'session.start', outcome: 'success',
    actor: 'alice', detail: 'a sentence as the detail' } },
  { op: 'audit', event: { action: 'session.end', summary: 'ended',
    detail: 'kept as a note' } },
  { op: 'audit', event: { action: 'no.such.action', category: 'oddity',
    summary: LONG, actor: LONG, target: LONG, protocol: LONG,
    channel: LONG, detail: { long: LONG } } },
  { op: 'audit', event: { action: 'session.refused', outcome: 'bogus',
    errorCode: 'STS-NOT-9999', detail: { client_id: ' app-1 ' } } },
  { op: 'audit', event: { action: 'session.presented', actor: 'carol',
    address: '::ffff:192.0.2.7', detail: { application: 'app-1',
    method: 'existing session' } } },
  { op: 'audit', event: { action: 'admin.view', address: 'unknown' } },
  { op: 'audit', event: { action: 'protocol.call', seq: 900,
    summary: 'given its own number' } },
  { op: 'audit', event: { action: 'protocol.call', seq: -3,
    summary: 'a bad number is ignored' } },
  { op: 'audit', event: { action: 'protocol.call',
    detail: { b: 1, 2: 'two', 1: 'one', a: 'x', 10: 'ten', '01': 'z',
              k1: 1, k2: 2, k3: 3, k4: 4, k5: 5, k6: 6, k7: 7 } } },
  { op: 'audit', event: { action: 'authentication', actor: 0,
    summary: 12345, errorCode: '', detail: [1, 2] } },
  { op: 'failure', code: 'STS-AUDIT-0007', event: { summary: 'export broke',
    target: 'hook' } },
  { op: 'failure', code: 'STS-AUDIT-0009', event: { action: 'service.failure',
    outcome: 'error', summarised: true, summary: 'trimmed' } },
  { op: 'directory', event: { action: 'user.delete', actor: 'admin',
    target: 'uid=bob,ou=users,dc=sts,dc=mock', summary: 'deleted bob',
    detail: { attributes: 'cn,mail' } } },
  { op: 'directory', event: { action: 'entry.update', protocol: 'LDAPS',
    channel: 'ldaps', errorCode: 'STS-LDAP-0001',
    address: '10.1.1.1' } },
  { op: 'source', address: '::ffff:198.51.100.4', then:
    { op: 'audit', event: { action: 'consent.granted', actor: 'alice' } } },
  { op: 'source', address: '2001:db8::5', then:
    { op: 'audit', event: { action: 'session.start', actor: 'dave',
      address: '203.0.113.9' } } },
  { op: 'now', at: T0 + 2000 },
  { op: 'http', req: { method: 'GET', url: '/healthcheck', query: {} },
    res: { status: 200 } },
  { op: 'http', req: { method: 'HEAD', url: '/healthcheck', query: {} },
    res: { status: 503 } },
  { op: 'http', req: { method: 'GET',
    url: '/oauth2/authorize?code=abc&state=s&x=1', query: { code: 'abc',
    state: 's', x: '1', client_id: 'app-1', CODE: 'up' } },
    res: { status: 302 }, info: { route: '/oauth2/authorize',
    matched: true, durationMs: 12 }, actor: 'alice' },
  { op: 'http', req: { method: 'POST', url: '/admin-api/users',
    query: {}, body: '{"action":"set-password","password":"hunter2"}',
    contentType: 'application/json' }, res: { status: 200,
    locals: { apiCaller: { name: 'root', owner: true } } },
    info: { route: '/admin-api/users', matched: true, durationMs: 3 },
    actor: 'not-used', session: 'sess-x' },
  { op: 'http', req: { method: 'POST', url: '/admin/users', query: {},
    body: 'action=' + 'z'.repeat(70) + '&token=t',
    contentType: 'application/x-www-form-urlencoded' },
    res: { status: 400, mark: 'STS-API-0001' }, actor: 'alice',
    session: 'sess-y' },
  { op: 'http', req: { method: 'POST', url: '/admin/users', query: {},
    body: '{not json', contentType: 'application/json' },
    res: { status: 200, mark: 'STS-API-0001' }, actor: 'alice' },
  { op: 'http', req: { method: 'GET', url: '/admin-api/audit', query: {} },
    res: { status: 200 } },
  { op: 'http', req: { method: 'OPTIONS', url: '/admin', query: {} },
    res: { status: 204 } },
  { op: 'http', req: { method: 'GET', url: '/nowhere', query: {} },
    res: { status: 404 }, info: { matched: false } },
  { op: 'http', req: { method: 'GET', url: '/oauth2/x', query: {} },
    res: { status: 404 }, info: { matched: true } },
  { op: 'http', req: { method: 'PUT', url: '/upload', query: {} },
    res: { status: 413 } },
  { op: 'http', req: { method: 'GET', url: '/vc', query: {} },
    res: { status: 501 } },
  { op: 'http', req: { method: 'GET', url: '/boom', query: {} },
    res: { status: 500 } },
  { op: 'http', req: { method: 'POST', url: '/ssf/poll', query: {} },
    res: { status: 200, locals: { auditQuietWhenOk: true } } },
  { op: 'http', req: { method: 'POST', url: '/ssf/poll', query: {} },
    res: { status: 403, locals: { auditQuietWhenOk: true } } },
  { op: 'http', reserve: true, req: { method: 'GET',
    url: '/authn-api/pending/abc123/x?authn=p&t=tok&mfa=m', query:
    { authn: 'p', t: 'tok', mfa: 'm', page: '2' } },
    res: { status: 500 } },
  { op: 'http', req: { method: 'GET',
    url: '/authn-api/wallet/st8?response_code=rc', query: {} },
    res: { status: 200 }, address: '::ffff:10.9.9.9' },
  { op: 'set', key: 'audit.protocolCalls', value: false },
  { op: 'http', req: { method: 'GET', url: '/jwks', query: {} },
    res: { status: 200 } },
  { op: 'http', req: { method: 'GET', url: '/jwks', query: {} },
    res: { status: 400 } },
  { op: 'http', req: { method: 'GET', url: '/admin/audit', query: {} },
    res: { status: 200 } },
  { op: 'set', key: 'audit.protocolCalls', value: true },
  { op: 'now', at: T0 + 3000 },
  { op: 'audit', event: { action: 'logout.global', actor: 'eve',
    detail: { sub: 'urn:uuid:e5' } } },
  { op: 'audit', event: { action: 'authentication', actor: 'eve',
    detail: { sub: 'urn:uuid:e5', client_id: 'app-2' } } }
];

// Paged and filtered queries of /admin-api/audit.
const VIEW_QUERIES = [
  {}, { category: 'authentication' }, { action: 'session.start' },
  { category: 'session', action: 'authentication' }, { outcome: 'refused' },
  { outcome: 'error' }, { actor: 'ALICE' }, { actor: 'uid=alice' },
  { q: 'SIGNED' }, { q: '/admin' }, { code: 'sts-audit' },
  { code: 'STS-HTTP-0001' }, { address: '10.' }, { address: '2001:DB8' },
  { per: '5' }, { per: '5', page: '3' }, { per: '7', page: '999' },
  { per: '-1', page: 'abc' }, { per: '1000' }, { page: '0' },
  { category: 'nothing' }
];

const ATTEMPT_NAMES = [[], ['app-1'], [' app-2 '], ['nobody'],
                       ['app-1', 'app-2']];

const PERSON_NAMES = [[['alice'], 0], [['bob@STS.MOCK'], 0],
                      [['urn:uuid:e5'], 0], [['eve'], T0 + 3000],
                      [['eve'], T0 + 3001], [['alice', 'carol'], -1],
                      [[], 0]];

/**
 * Runs one ring step.
 *
 * @param {any} audit - audit.js
 * @param {any} C - a require of common/
 * @param {any} config - config.js
 * @param {any} step - the step; `resolved` and `reserved` are added
 * @returns {any} the row written, or null, or what a set did
 */
function ringStep(audit, C, config, step) {
  log.debug("Entering ringStep(). " + step.op);
  let result = null;
  if (step.op === 'set') {
    result = setting(config, step.key, step.value);
  } else if (step.op === 'now') {
    NOW = step.at;
    result = NOW;
  } else if (step.op === 'audit') {
    result = audit.audit(step.event);
  } else if (step.op === 'failure') {
    result = audit.failure(step.code, step.event);
  } else if (step.op === 'directory') {
    result = audit.recordDirectory(step.event);
  } else if (step.op === 'source') {
    result = audit.withSource({ address: step.address }, function () {
      return ringStep(audit, C, config, step.then);
    });
  } else if (step.op === 'http') {
    const errorCodes = C('error_codes');
    const peer = step.address || '::ffff:192.0.2.1';
    const req = {
      method: step.req.method,
      originalUrl: step.req.url,
      url: step.req.url,
      query: step.req.query || {},
      body: step.req.body,
      headers: step.req.contentType
        ? { 'content-type': step.req.contentType } : {},
      socket: { remoteAddress: peer },
      connection: { remoteAddress: peer },
      __actor: step.actor || '',
      __session: step.session || ''
    };
    const res = { statusCode: step.res.status,
                  locals: step.res.locals || {} };
    if (step.res.mark) {
      errorCodes.mark(res, step.res.mark);
    }
    step.resolved = C('client_address').clientAddressOf(req);
    if (step.reserve) {
      step.reserved = audit.reserveIncident(res);
    }
    result = audit.recordHttp(req, res, step.info || {});
  }
  log.debug("Leaving ringStep().");
  return result === undefined ? null : result;
}

/**
 * The ring part.
 *
 * @param {string} root - the repository root
 * @param {any} C - a require of common/
 * @param {any} config - config.js
 * @returns {any} steps, results and state
 */
function ringPart(root, C, config) {
  log.debug("Entering ringPart().");
  const audit = C('audit');
  audit.setActorResolver(function (req) {
    return req.__actor;
  });
  audit.setActorSessionResolver(function (req) {
    return req.__session;
  });
  const steps = JSON.parse(JSON.stringify(RING_STEPS));
  // The cap bites: a cap of 38 under 43 rows, then six more.
  steps.push({ op: 'set', key: 'audit.maxEvents', value: 38 });
  for (let i = 0; i < 6; i++) {
    steps.push({ op: 'audit', event: { action: 'protocol.call',
      summary: 'filler ' + i } });
  }
  const results = steps.map(function (step) {
    return JSON.parse(JSON.stringify(ringStep(audit, C, config, step)));
  });
  const local = audit.localEvents();
  const copy = function () {
    return JSON.parse(JSON.stringify(local));
  };
  const altered = copy();
  altered[3].summary = 'rewritten';
  const middle = copy();
  middle.splice(5, 1);
  const tail = copy();
  tail.pop();
  const unsigned = copy();
  delete unsigned[0].mac;
  const legacy = copy();
  delete legacy[1].prev;
  const adminViews = require(path.join(root, 'admin-core', 'admin_views'));
  const views = VIEW_QUERIES.map(function (query) {
    const json = JSON.parse(JSON.stringify(adminViews.auditView(query).json));
    delete json.settings;
    return { query: query, json: json };
  });
  const out = {
    steps: steps,
    results: results,
    local: JSON.parse(JSON.stringify(local)),
    list: JSON.parse(JSON.stringify(audit.list())),
    summary: audit.summary(),
    integrity: audit.verifyIntegrity(),
    tampered: [['altered', altered], ['middle', middle], ['tail', tail],
               ['unsigned', unsigned], ['legacy', legacy]]
      .map(function (one) {
        return { name: one[0], held: one[1],
                 verdict: audit.verifyIntegrity(one[1]) };
      }),
    attempts: ATTEMPT_NAMES.map(function (names) {
      return { names: names, seqs: audit.authenticationEventsFor(names)
        .map(function (row) {
          return row.seq;
        }) };
    }),
    person: PERSON_NAMES.map(function (one) {
      return { names: one[0], since: one[1],
               seqs: audit.authenticationEventsForPerson(one[0], one[1])
                 .map(function (row) {
                   return row.seq;
                 }) };
    }),
    views: views
  };
  log.debug("Leaving ringPart().");
  return out;
}

/**
 * The pure functions.
 *
 * @param {any} C - a require of common/
 * @returns {any} inputs and answers
 */
function helpersPart(C) {
  log.debug("Entering helpersPart().");
  const audit = C('audit');
  const paths = ['/authn-api/pending/abc/next', '/authn-api/consent/c1',
    '/authn-api/mfa/m1?x=1', '/authn/login?authn=a&mfa=b&state=c&ok=1',
    '/authn/email-link/open?t=secret#frag', '/x?change=1&consent=2&t=3',
    '/authn-api/password-change/p', '/authn-api/other/p', '', '/',
    '/a?authn=1&authn=2', '/authn-api/wallet/w/x/authn-api/mfa/y'];
  const queries = [{ authn: 'a', MFA: 'b', x: 'y' }, {}, { t: '1', T: '2' }];
  const dns = ['uid=a,ou=users,dc=x', 'uid=a , ou=Users , dc=X',
    'ou=users,dc=x', 'cn=g,ou=groups,dc=x', 'cn=other,dc=x', '',
    'uid=b,ou=users,dc=xx'];
  const containers = [{ users: 'ou=users,dc=x', groups: 'ou=groups,dc=x' },
                      {}, { users: 'OU=Users, DC=X' }];
  const quiet = [['GET', '/healthcheck', 200], ['head', '/healthcheck', '200'],
    ['POST', '/healthcheck', 200], ['GET', '/healthcheck/', 200],
    ['GET', '/healthcheck', 204]];
  const out = {
    redactedPath: paths.map(function (p) {
      return [p, audit.redactedPath(p)];
    }),
    redactedQuery: queries.map(function (q) {
      return [q, audit.redactedQuery(q)];
    }),
    objectKindOf: [],
    directoryActionFor: [],
    quietWhenOk: quiet.map(function (q) {
      return [q, audit.quietWhenOk(q[0], q[1], q[2])];
    })
  };
  dns.forEach(function (dn) {
    containers.forEach(function (c) {
      out.objectKindOf.push([dn, c, audit.objectKindOf(dn, c)]);
      ['create', 'delete'].forEach(function (op) {
        out.directoryActionFor.push([op, dn, c,
                                     audit.directoryActionFor(op, dn, c)]);
      });
    });
  });
  log.debug("Leaving helpersPart().");
  return out;
}

// ---------------------------------------------------------------------------
// THE EXPORT PART.
// ---------------------------------------------------------------------------

/**
 * A map with the realms.map() surface the exporter uses.
 *
 * @returns {any} the map
 */
function memoryMap() {
  log.debug("Entering memoryMap().");
  const data = new Map();
  log.debug("Leaving memoryMap().");
  return {
    data: data,
    get: function (key) {
      return data.has(key) ? data.get(key) : null;
    },
    set: function (key, value) {
      data.set(key, value);
    },
    delete: function (key) {
      data.delete(key);
    },
    forEach: function (fn) {
      data.forEach(fn);
    }
  };
}

/**
 * The receivers: scripted HTTP answers, TCP and TLS sockets that record
 * every frame, a UDP socket shaped as node's (it has no setTimeout), and
 * DNS from a table.
 *
 * @param {any} sent - where every transmission is recorded
 * @returns {any} the fakes, the answer queue and the DNS table
 */
function receivers(sent) {
  log.debug("Entering receivers().");
  const queue = [];
  const dnsTable = {};
  const http = {
    request: function (options, cb) {
      const chunks = [];
      const req = {
        setTimeout: function () {
          return req;
        },
        on: function () {
          return req;
        },
        write: function (buf) {
          chunks.push(Buffer.from(buf));
          return true;
        },
        end: function () {
          const body = Buffer.concat(chunks).toString('utf8');
          const headers = {};
          Object.keys(options.headers || {}).forEach(function (name) {
            headers[name] = String(options.headers[name]);
          });
          let pinned = null;
          if (options.lookup) {
            options.lookup(options.hostname, {}, function (e, a) {
              pinned = a;
            });
          }
          sent.push({ kind: 'http', protocol: options.protocol,
                      hostname: options.hostname, port: options.port,
                      path: options.path, method: options.method,
                      headers: headers, body: body, pinned: pinned,
                      rejectUnauthorized: options.rejectUnauthorized });
          const answered = queue.length ? queue.shift() : { status: 200 };
          const status = answered.status;
          const res = {
            statusCode: status,
            headers: answered.headers || {},
            destroy: function () {},
            on: function (ev, fn) {
              if (ev === 'data' && answered.body != null &&
                  !(status >= 300 && status < 400)) {
                fn(Buffer.from(typeof answered.body === 'string'
                  ? answered.body : JSON.stringify(answered.body)));
              }
              if (ev === 'end') {
                process.nextTick(fn);
              }
              return res;
            }
          };
          cb(res);
        },
        destroy: function () {}
      };
      return req;
    }
  };
  const socket = function (kind, opts, ready) {
    const s = new EventEmitter();
    s.destroyed = false;
    s.setTimeout = function () {
      return s;
    };
    s.write = function (buf, cb) {
      sent.push({ kind: kind, host: opts.host, port: opts.port,
                  servername: opts.servername || '',
                  rejectUnauthorized: opts.rejectUnauthorized,
                  bytes: Buffer.from(buf).toString('utf8') });
      if (cb) {
        cb(null);
      }
      return true;
    };
    s.end = function () {};
    s.destroy = function () {
      s.destroyed = true;
    };
    process.nextTick(function () {
      s.emit(ready);
    });
    return s;
  };
  log.debug("Leaving receivers().");
  return {
    queue: queue,
    dnsTable: dnsTable,
    http: http,
    https: http,
    net: { connect: function (opts) {
      return socket('tcp', opts, 'connect');
    } },
    tls: { connect: function (opts) {
      return socket('tls', opts, 'secureConnect');
    } },
    dgram: { createSocket: function () {
      // node's dgram.Socket, which has no setTimeout().
      const s = new EventEmitter();
      s.close = function () {};
      s.send = function (buf, port, ip, cb) {
        sent.push({ kind: 'udp', host: ip, port: port,
                    bytes: Buffer.from(buf).toString('utf8') });
        cb(null);
      };
      return s;
    } },
    dns: { lookup: function (host) {
      const name = String(host || '').toLowerCase();
      const answer = Object.prototype.hasOwnProperty.call(dnsTable, name)
        ? dnsTable[name] : ['8.8.8.8'];
      if (answer === 'fail') {
        return Promise.reject(new Error('lookup failed'));
      }
      return Promise.resolve(answer.map(function (a) {
        return { address: a, family: a.indexOf(':') >= 0 ? 6 : 4 };
      }));
    } }
  };
}

// The settings every scenario starts from, so an earlier one cannot leak.
const EXPORT_SETTINGS = {
  'global.mode': 'development',
  'auditExport.enabled': true,
  'auditExport.batch': 50,
  'auditExport.budgetMs': 2000,
  'auditExport.retryInitialMs': 1000,
  'auditExport.retryMaxMs': 300000,
  'auditExport.retryMaxPeriodMs': 86400000,
  'auditExport.timeoutMs': 5000,
  'auditExport.allowHttp': false,
  'auditExport.skipTlsVerification': false,
  'auditExport.caFile': '',
  'auditExport.allowPrivateDestinations': false,
  'auditExport.fileRoots': '',
  'auditExport.redactKeys': 'password,secret,token,authorization,' +
    'client_secret,assertion,access_token,refresh_token,id_token',
  'audit.allowPlainSyslog': false
};

// What the scripted resolver answers; a name it does not hold is 8.8.8.8.
const DNS = {
  'siem.example.com': ['203.0.113.10'],
  'splunk.example.com': ['203.0.113.20', '203.0.113.21'],
  'syslog.example.com': ['203.0.113.30'],
  'v6.example.com': ['2001:db8::30'],
  'inside.example.com': ['10.0.0.8'],
  'loopy.example.com': ['127.0.0.1'],
  'meta.example.com': ['169.254.169.254'],
  'gone.example.com': 'fail',
  'empty.example.com': [],
  'localhost': ['127.0.0.1'],
  'mixed.example.com': ['127.0.0.1', '203.0.113.1']
};

/**
 * A row as the ring holds it, for a scenario that needs its own.
 *
 * @param {number} seq - its number
 * @param {any} extra - members to set
 * @returns {any} the row
 */
function exportRow(seq, extra) {
  log.debug("Entering exportRow().");
  const row = Object.assign({
    seq: seq, origin: '', at: T0 + seq, category: 'authentication',
    action: 'authentication', outcome: 'success', errorCode: '',
    actor: 'alice', actorForm: '', target: 't' + seq, protocol: 'OIDC',
    channel: 'http', address: '192.0.2.1', summary: 'event ' + seq,
    detail: { client_id: 'app', password: 'p', Token: 't',
              inner: { secret: 's', ok: 1, list: [{ id_token: 'x' }, 2] } }
  }, extra || {});
  log.debug("Leaving exportRow().");
  return row;
}

/**
 * Rows `from` to `to`.
 *
 * @param {number} from - the first seq
 * @param {number} to - the last seq
 * @param {any} extra - members to set on each
 * @returns {any[]} the rows
 */
function rowsOf(from, to, extra) {
  log.debug("Entering rowsOf().");
  const out = [];
  for (let s = from; s <= to; s++) {
    out.push(exportRow(s, extra));
  }
  log.debug("Leaving rowsOf().");
  return out;
}

/**
 * The export scenarios. Each `do` is an act, a tick, a ring change, a clock
 * move, answers queued, a setting, a screen, a view or the files read back;
 * Rust replays them.
 *
 * @param {any[]} ring - the ring part's rows
 * @param {string} work - the file destinations' directory
 * @returns {any[]} the scenarios
 */
function scenarios(ring, work) {
  log.debug("Entering scenarios().");
  const rows = rowsOf;
  const screens = ['siem.example.com', 'inside.example.com',
    'loopy.example.com', 'meta.example.com', 'gone.example.com',
    'empty.example.com', 'localhost', 'mixed.example.com', '127.0.0.1',
    '[::1]', '10.0.0.1', '100.64.0.1', '100.128.0.1', '172.16.0.1',
    '172.32.0.1', '192.168.1.1', '169.254.1.1', '0.0.0.0',
    '::ffff:10.0.0.1', '::ffff:169.254.169.254', 'fe80::1%eth0', 'fc00::1',
    '::', '2001:db8::1', 'instance-data', 'INSTANCE-DATA.ec2.internal.',
    '1.2.3', 'a@b', ''];
  const screenSteps = [];
  screens.forEach(function (host) {
    screenSteps.push({ do: 'screenHost', host: host, atSend: false });
    screenSteps.push({ do: 'screenHost', host: host, atSend: true });
  });
  ['https://siem.example.com/a', 'http://localhost:1/x',
   'http://siem.example.com/', 'https://u@siem.example.com/',
   'gopher://x/', '::nonsense', 'https://loopy.example.com/']
    .forEach(function (url) {
      screenSteps.push({ do: 'screenUrl', url: url, atSend: true });
    });
  [{ do: 'set', key: 'auditExport.allowHttp', value: true },
   { do: 'screenUrl', url: 'http://localhost:1/x', atSend: true },
   { do: 'screenUrl', url: 'http://loopy.example.com/', atSend: true },
   { do: 'screenUrl', url: 'http://loopy.example.com/', atSend: false },
   { do: 'screenUrl', url: 'http://mixed.example.com/', atSend: true },
   { do: 'set', key: 'global.mode', value: 'product' },
   { do: 'screenUrl', url: 'http://localhost:1/x', atSend: true },
   { do: 'screenHost', host: 'localhost', atSend: false },
   { do: 'set', key: 'auditExport.allowPrivateDestinations', value: true },
   { do: 'screenHost', host: 'inside.example.com', atSend: true },
   { do: 'screenHost', host: '169.254.169.254', atSend: true }]
    .forEach(function (one) {
      screenSteps.push(one);
    });
  const add = function (body) {
    return { do: 'act', body: Object.assign({ action: 'add', id: 'a' },
                                            body) };
  };
  const list = [
    { name: 'webhook', steps: [
      { do: 'act', body: { action: 'add', id: 'hook', type: 'webhook',
        url: 'https://siem.example.com/in?x=1',
        headers: 'X-Tenant: t1\nAuthorization: Bearer abc\n\nX-Other:  two ',
        secretHeaders: 'X-Api-Key: k1', excludeAttributes: 'Note , inner' } },
      { do: 'ring', rows: ring.slice(0, 6) },
      { do: 'tick' },
      { do: 'view' },
      { do: 'ring', rows: ring.slice(0, 9) },
      { do: 'answer', answers: [{ status: 200 }, { status: 503,
        headers: { 'retry-after': '7' } }] },
      { do: 'now', at: T0 + 10000 },
      { do: 'tick' },
      { do: 'view' },
      { do: 'now', at: T0 + 12000 },
      { do: 'tick' },
      { do: 'now', at: T0 + 18000 },
      { do: 'answer', answers: [{ status: 429,
        headers: { 'retry-after': 'Thu, 01 Jan 2099 00:00:00 GMT' } }] },
      { do: 'tick' },
      { do: 'now', at: T0 + 4000000 },
      { do: 'answer', answers: [{ status: 200 }, { status: 200 }] },
      { do: 'tick' },
      { do: 'view' },
      { do: 'act', body: { action: 'update', id: 'hook', headers: '',
        secretHeaders: 'X-Api-Key:\nX-New: n', name: ' Renamed ' } },
      { do: 'act', body: { action: 'test', id: 'hook' } },
      { do: 'answer', answers: [{ status: 500 }] },
      { do: 'act', body: { action: 'test', id: 'hook' } },
      { do: 'act', body: { action: 'disable', id: 'hook' } },
      { do: 'tick' },
      { do: 'act', body: { action: 'enable', id: 'hook' } },
      { do: 'view' },
      { do: 'act', body: { action: 'remove', id: 'hook' } },
      { do: 'view' }
    ] },
    { name: 'webhook-template', steps: [
      { do: 'act', body: { action: 'add', id: 't1', type: 'webhook',
        url: 'https://siem.example.com/t',
        template: '{timestamp} {severity} {event_type} {subject} ' +
          '{message} {id} {realm} {outcome} {category} {target} ' +
          '{address} {origin} {protocol} {channel} {unknown} {Upper}' } },
      { do: 'ring', rows: rows(1, 6, { summary: 'with {message} inside' }) },
      { do: 'answer', answers: [{ status: 400 }, { status: 200 },
        { status: 302, headers: { location: 'https://evil.example/x' } }] },
      { do: 'tick' },
      { do: 'now', at: T0 + 5000 },
      { do: 'answer', answers: [{ status: 401 }] },
      { do: 'tick' },
      { do: 'now', at: T0 + 9000 },
      { do: 'answer', answers: [{ status: 200, body: 'x'.repeat(70000) },
        { status: 418 }] },
      { do: 'tick' },
      { do: 'view' }
    ] },
    { name: 'splunk', steps: [
      { do: 'act', body: { action: 'add', id: 'spl', type: 'splunk',
        url: 'https://splunk.example.com:8088/services/collector/event?a=b',
        token: 'tok-1', index: 'main', ack: true } },
      { do: 'ring', rows: rows(1, 3) },
      { do: 'answer', answers: [{ status: 200, body: { text: 'Success',
        code: 0, ackId: 7 } }] },
      { do: 'tick' },
      { do: 'answer', answers: [{ status: 200,
        body: { acks: { 7: false } } }] },
      { do: 'tick' },
      { do: 'answer', answers: [{ status: 200, body: { acks: { 7: true } } },
        { status: 200, body: { code: 0, ackId: 8 } }] },
      { do: 'tick' },
      { do: 'answer', answers: [{ status: 200, body: { acks: {} } },
        { status: 200, body: { code: 6, text: 'Invalid data format' } }] },
      { do: 'tick' },
      { do: 'view' },
      { do: 'act', body: { action: 'update', id: 'spl', token: '',
        ack: false, url: 'https://splunk.example.com/services/collector' } },
      { do: 'now', at: T0 + 400000 },
      { do: 'answer', answers: [{ status: 503 }] },
      { do: 'tick' },
      { do: 'view' }
    ] },
    { name: 'syslog', steps: [
      { do: 'act', body: { action: 'add', id: 'sys', type: 'syslog',
        host: 'syslog.example.com', facility: 4, appName: 'iya app' } },
      { do: 'act', body: { action: 'add', id: 'lr', type: 'logrhythm',
        host: '[2001:db8::30]', port: 1514, transport: 'tls' } },
      { do: 'act', body: { action: 'add', id: 'udp', type: 'syslog',
        host: 'syslog.example.com', transport: 'udp', port: '5140' } },
      { do: 'ring', rows: rows(1, 2, { summary: 'naïve message\r\nline' })
        .concat([exportRow(3, { outcome: 'refused', action: 'a b c',
          summary: '' }), exportRow(4, { outcome: 'error',
          origin: 'node-b' })]) },
      { do: 'tick' },
      { do: 'view' }
    ] },
    { name: 'file', steps: [
      { do: 'set', key: 'auditExport.fileRoots', value: work + ' , /nope' },
      { do: 'act', body: { action: 'add', id: 'f1', type: 'file',
        path: work + '/audit.log', mode: '600', rotateBytes: 600 } },
      { do: 'ring', rows: rows(1, 3) },
      { do: 'tick' },
      { do: 'files' },
      { do: 'ring', rows: rows(1, 5) },
      { do: 'now', at: T0 + 1000 },
      { do: 'tick' },
      { do: 'files' },
      { do: 'act', body: { action: 'update', id: 'f1',
        path: work + '/b/../second.log' } },
      { do: 'act', body: { action: 'update', id: 'f1',
        path: '/elsewhere/x.log' } },
      { do: 'act', body: { action: 'update', id: 'f1',
        path: work + '/second.log', mode: 640, rotateBytes: 0 } },
      { do: 'ring', rows: rows(1, 6) },
      { do: 'tick' },
      { do: 'files' },
      { do: 'view' }
    ] },
    { name: 'give-up', steps: [
      { do: 'set', key: 'auditExport.retryMaxPeriodMs', value: 60000 },
      { do: 'set', key: 'auditExport.batch', value: 3 },
      { do: 'act', body: { action: 'add', id: 'g', type: 'webhook',
        url: 'https://siem.example.com/g' } },
      { do: 'ring', rows: rows(1, 8) },
      { do: 'answer', answers: [{ status: 500 }] },
      { do: 'tick' },
      { do: 'now', at: T0 + 70000 },
      { do: 'answer', answers: [{ status: 500 }] },
      { do: 'tick' },
      { do: 'now', at: T0 + 80000 },
      { do: 'answer', answers: [{ status: 200 }, { status: 200 },
        { status: 200 }] },
      { do: 'tick' },
      { do: 'view' }
    ] },
    { name: 'gap', steps: [
      { do: 'act', body: { action: 'add', id: 'gp', type: 'webhook',
        url: 'https://siem.example.com/gap', enabled: false } },
      { do: 'ring', rows: rows(10, 14) },
      { do: 'view' },
      { do: 'act', body: { action: 'enable', id: 'gp' } },
      { do: 'answer', answers: [{ status: 200 }, { status: 500 }] },
      { do: 'tick' },
      { do: 'ring', rows: rows(20, 22).concat([exportRow(23,
        { detail: { exportSkip: true } })]) },
      { do: 'now', at: T0 + 5000 },
      { do: 'tick' },
      { do: 'ring', rows: [] },
      { do: 'tick' },
      { do: 'view' }
    ] },
    { name: 'acts', steps: [
      { do: 'act', body: { action: 'frobnicate' } },
      { do: 'act', body: null },
      add({ id: '-bad', type: 'webhook' }),
      add({ id: 'Upper', type: 'webhook' }),
      add({ type: 'ftp' }),
      add({ type: 'webhook', name: 'n'.repeat(129) }),
      add({ type: 'webhook', name: '   ' }),
      add({ type: 'webhook', excludeAttributes: 'e'.repeat(1001) }),
      add({ type: 'syslog' }),
      add({ type: 'syslog', host: 'h.example.com', appName: 'x'.repeat(49) }),
      add({ type: 'syslog', host: 'h.example.com', transport: 'sctp' }),
      add({ type: 'syslog', host: 'h.example.com', facility: 24 }),
      add({ type: 'syslog', host: 'h.example.com', facility: 'x' }),
      add({ type: 'syslog', host: 'h.example.com', port: 70000 }),
      add({ type: 'syslog', host: 'h ost' }),
      add({ type: 'syslog', host: '169.254.169.254' }),
      add({ type: 'syslog', host: 'inside.example.com' }),
      add({ type: 'syslog', host: 'gone.example.com' }),
      add({ type: 'file', path: 'relative.log' }),
      add({ type: 'file', path: '/x/../y.log' }),
      add({ type: 'file', path: '/x/y.log', mode: '999' }),
      add({ type: 'file', path: '/x/y.log', rotateBytes: -1 }),
      add({ type: 'file', path: '/' + 'p'.repeat(1025) }),
      add({ type: 'webhook', url: 'not a url' }),
      add({ type: 'webhook', url: 'https://u:p@siem.example.com/' }),
      add({ type: 'webhook', url: 'ftp://siem.example.com/' }),
      add({ type: 'webhook', url: 'http://siem.example.com/' }),
      add({ type: 'webhook', url: 'https://meta.example.com/' }),
      add({ type: 'webhook', url: 'https://metadata.google.internal/' }),
      add({ type: 'webhook', url: 'https://x.metadata.azure.com/' }),
      add({ type: 'webhook', url: 'https://[fd00::1]/' }),
      add({ type: 'webhook', url: 'https://siem.example.com/',
            headers: 'NoColon' }),
      add({ type: 'webhook', url: 'https://siem.example.com/',
            headers: 'Bad Name: v' }),
      add({ type: 'webhook', url: 'https://siem.example.com/',
            template: 't'.repeat(4001) }),
      add({ type: 'webhook', url: 'https://siem.example.com/',
            headers: 'h'.repeat(8001) }),
      add({ type: 'splunk', url: 'https://splunk.example.com/' }),
      add({ type: 'splunk', url: 'https://splunk.example.com/',
            token: 't'.repeat(4097) }),
      add({ type: 'webhook', url: 'https://localhost:9/x' }),
      add({ id: 'ok', type: 'webhook', url: 'https://gone.example.com/' }),
      add({ id: 'ok', type: 'webhook', url: 'https://siem.example.com/' }),
      { do: 'act', body: { action: 'update', id: 'nope' } },
      { do: 'act', body: { action: 'remove', id: 'nope' } },
      { do: 'act', body: { action: 'enable', id: 'nope' } },
      { do: 'act', body: { action: 'test', id: 'nope' } },
      { do: 'set', key: 'auditExport.allowHttp', value: true },
      add({ id: 'plain', type: 'webhook', url: 'http://localhost:8080/hook' }),
      { do: 'set', key: 'auditExport.allowPrivateDestinations',
        value: true },
      add({ id: 'priv', type: 'syslog', host: 'inside.example.com' }),
      add({ id: 'meta', type: 'syslog', host: 'meta.example.com' }),
      { do: 'set', key: 'global.mode', value: 'product' },
      add({ id: 'p1', type: 'syslog', host: 'syslog.example.com' }),
      add({ id: 'p2', type: 'webhook', url: 'http://siem.example.com/' }),
      { do: 'set', key: 'audit.allowPlainSyslog', value: true },
      add({ id: 'p3', type: 'syslog', host: 'syslog.example.com',
            transport: 'udp' }),
      { do: 'view' }
    ] },
    { name: 'screens', steps: screenSteps }
  ];
  log.debug("Leaving scenarios().");
  return list;
}

/**
 * The exporter's cursors, as stored.
 *
 * @param {any} maps - the two maps
 * @returns {any} id → cursor
 */
function cursorsOf(maps) {
  log.debug("Entering cursorsOf().");
  const out = {};
  maps.cursors.forEach(function (value, key) {
    out[key] = JSON.parse(JSON.stringify(value));
  });
  log.debug("Leaving cursorsOf().");
  return out;
}

/**
 * The export part.
 *
 * @param {string} root - the repository root
 * @param {any} C - a require of common/
 * @param {any} config - config.js
 * @param {string} work - the file destinations' directory
 * @param {any} ring - the ring part's rows
 * @returns {Promise<any>} scenarios, their results, the statics
 */
async function exportPart(root, C, config, work, ring) {
  log.debug("Entering exportPart().");
  const AuditExport = C('audit_export').AuditExport;
  const base = AuditExport.defaultDeps();
  const results = [];
  const list = scenarios(ring, work);
  for (const scenario of list) {
    Object.keys(EXPORT_SETTINGS).forEach(function (key) {
      setting(config, key, EXPORT_SETTINGS[key]);
    });
    NOW = T0;
    const sent = [];
    const fakes = receivers(sent);
    Object.assign(fakes.dnsTable, DNS);
    const recorded = [];
    let held = [];
    let uuid = 0;
    const registered = [];
    const maps = { destinations: memoryMap(), cursors: memoryMap() };
    const deps = Object.assign({}, base, {
      log: log,
      audit: {
        localEvents: function () {
          return held.slice();
        },
        failure: function (code, row) {
          recorded.push(Object.assign({ kind: 'failure', errorCode: code },
                                      JSON.parse(JSON.stringify(row))));
        },
        audit: function (row) {
          recorded.push(Object.assign({ kind: 'audit' },
                                      JSON.parse(JSON.stringify(row))));
        }
      },
      destinations: maps.destinations,
      cursors: maps.cursors,
      http: fakes.http,
      https: fakes.https,
      net: fakes.net,
      tls: fakes.tls,
      dgram: fakes.dgram,
      dns: fakes.dns,
      crypto: { randomUuid: function () {
        uuid += 1;
        return '00000000-0000-4000-8000-' + String(uuid).padStart(12, '0');
      } },
      scheduler: function () {
        return {
          job: function () {
            return null;
          },
          register: function (spec) {
            registered.push(spec);
          }
        };
      }
    });
    const exporter = new AuditExport(deps);
    const answers = [];
    for (const step of scenario.steps) {
      let answer = null;
      if (step.do === 'act') {
        const result = await exporter.act(step.body);
        answer = { result: JSON.parse(JSON.stringify(result)),
                   code: C('error_codes').codeOf(result),
                   recorded: recorded.splice(0), sent: sent.splice(0) };
      } else if (step.do === 'ring') {
        held = step.rows;
      } else if (step.do === 'answer') {
        step.answers.forEach(function (one) {
          fakes.queue.push(one);
        });
      } else if (step.do === 'now') {
        NOW = step.at;
      } else if (step.do === 'set') {
        setting(config, step.key, step.value);
      } else if (step.do === 'tick') {
        const ran = await exporter.runAsync({ stillOwner: function () {
          return true;
        } });
        answer = { ran: ran, sent: sent.splice(0),
                   recorded: recorded.splice(0),
                   cursors: cursorsOf(maps) };
      } else if (step.do === 'view') {
        answer = exporter.view();
      } else if (step.do === 'files') {
        answer = fs.readdirSync(work).sort().filter(function (name) {
          return fs.statSync(path.join(work, name)).isFile();
        }).map(function (name) {
          const full = path.join(work, name);
          return { name: name, mode: fs.statSync(full).mode & 0o777,
                   text: fs.readFileSync(full, 'utf8') };
        });
      } else if (step.do === 'screenHost') {
        answer = await exporter.screenHost(step.host, step.atSend);
      } else if (step.do === 'screenUrl') {
        const one = await exporter.screenUrl(step.url, step.atSend);
        answer = Object.assign({}, one, one.url
          ? { url: String(one.url) } : {});
      }
      answers.push(answer === undefined ? null :
        JSON.parse(JSON.stringify(answer)));
    }
    if (scenario.name === 'webhook') {
      exporter.registerJobs();
    }
    results.push({ name: scenario.name, steps: scenario.steps,
                   answers: answers,
                   registered: registered.map(function (spec) {
                     const copy = {};
                     Object.keys(spec).forEach(function (key) {
                       if (typeof spec[key] !== 'function') {
                         copy[key] = spec[key];
                       }
                     });
                     return copy;
                   }) });
    // resetForTests() clears realms.map()s these memory maps are not; the
    // file handles are what it would close.
    for (const held of exporter.files.values()) {
      await exporter.closeHeld(held);
    }
    exporter.files.clear();
    fs.readdirSync(work).forEach(function (name) {
      fs.rmSync(path.join(work, name), { recursive: true, force: true });
    });
  }
  Object.keys(EXPORT_SETTINGS).forEach(function (key) {
    setting(config, key, EXPORT_SETTINGS[key]);
  });
  const offs = {};
  const bare = function () {
    return new AuditExport(Object.assign({}, base, {
      log: log, destinations: memoryMap(), cursors: memoryMap() }));
  };
  offs.noDestination = bare().offHere();
  const one = bare();
  one.deps.destinations.set('x', { id: 'x', enabled: true });
  offs.on = one.offHere();
  setting(config, 'auditExport.enabled', false);
  offs.off = one.offHere();
  setting(config, 'auditExport.enabled', true);
  const out = { work: work, settings: EXPORT_SETTINGS, dns: DNS,
                offs: offs, scenarios: results,
                statics: staticsOf(AuditExport, ring) };
  log.debug("Leaving exportPart().");
  return out;
}

/**
 * The exporter's pure functions over fixed inputs.
 *
 * @param {any} AuditExport - the class
 * @param {any[]} ring - rows to build events from
 * @returns {any} inputs and answers
 */
function staticsOf(AuditExport, ring) {
  log.debug("Entering staticsOf().");
  const names = ['password', 'token', 'inner'];
  const opts = { realm: 'default', origin: '', source: 'ua',
                 names: new Set(names) };
  const events = ring.slice(0, 8).map(function (row) {
    return AuditExport.canonical(row, opts);
  });
  const out = {
    names: names,
    ackUrl: ['https://h/services/collector/event',
      'https://h/services/collector', 'https://h/services/collector/',
      'https://h:8088/x?token=1#f', 'https://h'].map(function (u) {
      return [u, AuditExport.ackUrl(u)];
    }),
    retryAfter: ['', '0', '5', '7200', ' 12 ', '1.5', 'soon',
      'Thu, 01 Jan 2099 00:00:00 GMT', 'Thu, 01 Jan 2000 00:00:00 GMT',
      new Date(T0 + 4000).toUTCString()].map(function (v) {
      return [v, AuditExport.retryAfter({ headers: { 'retry-after': v } })];
    }),
    parseMode: [null, '', 0, '0', '640', 640, '0600', ' 755 ',
      '888', '6400', 'abc', 600, 7].map(function (v) {
      return [v, AuditExport.parseMode(v)];
    }),
    safeWhy: ['', 'plain', 'see https://x/y?token=1 and HTTP://Z now',
      'a\r\nb\tc', ' trim ', 'w'.repeat(301), 'w'.repeat(300)]
      .map(function (v) {
        return [v, AuditExport.safeWhy(v)];
      }),
    classify: [
      [{ status: 200 }, false], [{ status: 204, json: { ackId: 3 } }, true],
      [{ status: 200, json: { code: 0, ackId: 0 } }, true],
      [{ status: 200, json: { code: 9 } }, false],
      [{ status: 400 }, false], [{ status: 401 }, false],
      [{ status: 403 }, false], [{ status: 404 }, false],
      [{ status: 408, retryAfterMs: 5 }, false], [{ status: 429 }, false],
      [{ status: 503, why: 'down' }, false], [{ status: 0, code: '' }, false],
      [{ status: 301, why: 'r' }, false],
      [{ status: 0, code: 'STS-AUDIT-0014' }, false],
      [{ status: 0, code: 'STS-CORE-0104', why: 'ca' }, false]
    ].map(function (one) {
      return [one[0], one[1], AuditExport.classifyHttp(one[0], one[1])];
    }),
    rows: ring.slice(0, 8),
    events: events,
    template: events.slice(0, 2).map(function (event) {
      return AuditExport.fillTemplate('{id}|{message}|{x}|{{realm}}',
                                      event);
    }),
    syslog: events.slice(0, 6).map(function (event, i) {
      const dest = [{}, { facility: 23, appName: 'a b' },
        { facility: -1 }, { facility: 'q' }, { appName: 'z'.repeat(60) },
        { facility: 99 }][i];
      return [dest, AuditExport.syslogLine(event, dest)];
    }),
    sdEscape: ['a"b\\c]d', null, 3].map(function (v) {
      return [v, AuditExport.sdEscape(v)];
    }),
    hosts: ['10.1.1.1', '::ffff:192.168.0.1', 'fe80::', 'febf::1',
      'fec0::1', 'fdff::1', '::1', '::2', '1::', 'x', '2001:db8::',
      '1:2:3:4:5:6:7:8', '1:2:3:4:5:6:7:8:9', '::ffff:1.2.3.4',
      '64:ff9b::10.0.0.1', '[::1]', '127.0.0.1.', '01.2.3.4',
      '1.2.3.256'].map(function (h) {
      return [h, AuditExport.isPrivate(h), AuditExport.isMetadata(h),
              AuditExport.isIp(AuditExport.bareHost(h)),
              AuditExport.bareHost(h)];
    }),
    transport: [{}, { transport: 'udp' }, { transport: 'tls' },
      { transport: 'x' }, { port: 0, transport: 'tls' }, { port: '99' }]
      .map(function (d) {
        return [d, AuditExport.transportOf(d), AuditExport.portOf(d)];
      })
  };
  log.debug("Leaving staticsOf().");
  return out;
}

// ===========================================================================
// THE OTHER DIRECTION: what Rust made, read by Node.
// ===========================================================================

/**
 * Checks `audit-rust.json` in Node, in a child that holds the same KEK:
 * every row Rust wrote passes Node's integrity check, and every canonical
 * event and syslog line Rust built from a row is the one Node builds.
 *
 * @param {any} t - the runner's check collector
 * @param {any} v - audit-rust.json
 * @param {string} dir - the vectors directory
 * @returns {Promise<void>} when done
 */
async function fromRust(t, v, dir) {
  log.debug("Entering fromRust().");
  const root = path.join(__dirname, '..', '..');
  const childProcess = require('child_process');
  const input = path.join(dir, 'audit-rust-check.json');
  fs.writeFileSync(input, JSON.stringify(v));
  let verdict = null;
  try {
    const text = childProcess.execFileSync(process.execPath,
      [__filename, '--check', root, input],
      { env: Object.assign({}, process.env, { STS_LOG_LEVEL: 'fatal',
                                              STS_KEYS_SOURCE: 'generated' }),
        stdio: ['ignore', 'pipe', 'inherit'] }).toString('utf8');
    verdict = JSON.parse(text.trim().split('\n').pop());
  } catch (e) {
    log.debug("Caught in fromRust(): " + ((e && e.message) || e));
    verdict = { error: String((e && e.message) || e) };
  }
  fs.unlinkSync(input);
  t.check(!verdict.error, 'audit: the Node check of what Rust made ran',
          verdict.error || '');
  (verdict.checks || []).forEach(function (one) {
    t.check(one.ok, 'audit: ' + one.what, one.detail || '');
  });
  log.debug("Leaving fromRust().");
}

/**
 * The child of `fromRust()`.
 *
 * @param {string} root - the repository root
 * @param {string} input - audit-rust.json, copied
 */
function check(root, input) {
  log.debug("Entering check().");
  const v = JSON.parse(fs.readFileSync(input, 'utf8'));
  const keystore = require(path.join(root, 'common', 'keystore'));
  keystore.useEphemeralKek(v.kek);
  const audit = require(path.join(root, 'common', 'audit'));
  const AuditExport = require(path.join(root, 'common', 'audit_export'))
    .AuditExport;
  const checks = [];
  const verdict = audit.verifyIntegrity(v.rows);
  checks.push({ ok: verdict.checked === v.rows.length &&
                    v.rows.length > 0 &&
                    verdict.altered.length === 0 &&
                    verdict.missing.length === 0,
                what: 'every row Rust wrote carries a checksum and a chain ' +
                      'Node verifies (' + v.rows.length + ' rows)',
                detail: JSON.stringify(verdict) });
  (v.events || []).forEach(function (one, i) {
    const made = AuditExport.canonical(one.row, { realm: one.realm,
      origin: one.origin, source: one.source, names: new Set(one.names) });
    checks.push({ ok: JSON.stringify(made) === JSON.stringify(one.event),
                  what: 'canonical event ' + i + ' is Node\'s',
                  detail: JSON.stringify(made) });
    if (one.syslog) {
      // The host and the pid are each process's own.
      const line = AuditExport.syslogLine(one.event, one.dest);
      const bare = function (text) {
        return text.replace(/^(<\d+>1 \S+) \S+ (\S+) \d+ /, '$1 H $2 P ');
      };
      checks.push({ ok: bare(line) === bare(one.syslog),
                    what: 'syslog line ' + i + ' is Node\'s',
                    detail: line });
    }
  });
  process.stdout.write(JSON.stringify({ checks: checks }) + '\n');
  log.debug("Leaving check().");
}

if (require.main === module) {
  const argv = process.argv;
  if (argv[2] === '--child') {
    child(argv[3], argv[4], argv[5], argv[6]).then(function () {
      process.exit(0);
    }, function (e) {
      console.error(e);
      process.exit(1);
    });
  } else if (argv[2] === '--check') {
    check(argv[3], argv[4]);
    process.exit(0);
  }
}

module.exports = { build: build, fromRust: fromRust };
