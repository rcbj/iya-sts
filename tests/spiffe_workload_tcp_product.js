'use strict';
//
// File: spiffe_workload_tcp_product.js
//
// ===========================================================================
// THE WORKLOAD API OVER TCP IN PRODUCT, AND WHAT AN ENTRY MUST SELECT (#166).
//
// The SPIFFE Workload Endpoint specification section 3: "TCP transport MUST
// NOT be used unless the underlying network allows the Workload Endpoint
// server to strongly authenticate the workload based on source IP address."
// Product bound the TCP port on every interface by default and attested
// nobody on it, and an administrator could register an entry selecting only
// `transport:tcp`, which every host that reached the port was then issued.
// Four halves, in a CHILD PROCESS — requiring the protocol stack builds
// certificate authorities and binds listeners, and `run.js` runs every file
// in one process (`account_disable.js`'s arrangement):
//
//   1. THE POSTURE, `SpiffeAuth.workloadTcpPosture()`: development serves;
//      product without `spiffe.workloadTcpSourceAuthenticated` does not
//      (STS-SPIFFE-0120); product with it and a wildcard `spiffe.grpcHost`
//      (0.0.0.0, ::) does not (STS-SPIFFE-0121); product with it and a named
//      address does; a port of 0 is off with no code.
//   2. THE BIND, a realm of this run's own with its TCP port on 127.0.0.1:
//      product and undeclared — not listening, 0120 on the binding, the port
//      refuses a connection, GET /spiffe says "not served"; product, declared,
//      wildcard — not listening, 0121; product, declared, named — listening,
//      and a real gRPC client over TCP is issued a JWT-SVID for the entry
//      selecting its `peer:` address and not for a transport-only entry
//      written while the realm was in development (STS-SPIFFE-0123); the
//      declaration withdrawn with the port still bound — every call refused
//      UNAVAILABLE; development — listening without any declaration.
//   3. THE ENTRY, through all three doors in a product realm: the registry,
//      the SPIRE Server API's BatchCreateEntry and BatchUpdateEntry
//      (INVALID_ARGUMENT per item), and the console's and /admin-api's action
//      layer — an entry with only `transport:`, only `endpoint:`, both, or no
//      selector at all is refused STS-SPIFFE-0122; one with `peer:` is
//      accepted; development accepts the transport-only one.
//   4. `peer:` MATCHES EXACTLY: 127.0.0.1 is not 127.0.0.10, and a prefix is
//      not a selector anybody's address carries.
//
// The realm is left standing with SPIFFE off, for `tests/spiffe_pki.js`'s
// reason.
// ===========================================================================

const os = require('os');
const fs = require('fs');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'spiffe_workload_tcp_product',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// The child's program. Runs in the child only, which the code style exempts
// from the Entering/Leaving lines; its findings are written to WT_OUT.
function childMain() {
  const ROOT = process.env.WT_ROOT;
  const OUT = process.env.WT_OUT;
  const REALM = 'spiffe-workload-tcp';
  const fs = require('fs');
  const net = require('net');
  const http = require('http');
  const findings = [];
  const check = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' :
                      (typeof detail === 'string' ? detail
                                                  : JSON.stringify(detail)) });
  };
  const freePort = function () {
    return new Promise(function (resolve) {
      const probe = net.createServer();
      probe.listen(0, '127.0.0.1', function () {
        const port = probe.address().port;
        probe.close(function () { resolve(port); });
      });
    });
  };
  const connects = function (port) {
    return new Promise(function (resolve) {
      const socket = net.connect(port, '127.0.0.1');
      socket.on('connect', function () { socket.destroy(); resolve(true); });
      socket.on('error', function () { resolve(false); });
    });
  };

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const config = require(ROOT + '/common/config');
    const realms = require(ROOT + '/common/realms');
    const errorCodes = require(ROOT + '/common/error_codes');
    const server = require(ROOT + '/spiffe/spiffe_server');
    const auth = require(ROOT + '/spiffe/spiffe_auth');
    const rpc = require(ROOT + '/spiffe/spiffe_grpc');
    const ca = require(ROOT + '/spiffe/spiffe_ca');
    const registry = require(ROOT + '/spiffe/spiffe_registry');
    const spiffeIdLib = require(ROOT + '/spiffe/spiffe_id');
    const adminActions = require(ROOT + '/admin-core/admin_actions');

    // ---- 1. the posture, in a realm of this run's own ------------------
    // The rows are restart-only for the PROCESS and settable on a REALM
    // (`realmRuntime`), which is also where the listener that asks lives.
    const port = await freePort();
    const made = realms.get(REALM) ? { ok: true } : realms.create({
      id: REALM, name: REALM, overrides: {
        'spiffe.workloadPort': port, 'spiffe.serverPort': 0,
        'spiffe.grpcHost': '127.0.0.1',
        'spiffe.workloadSocketEnabled': false,
        'spiffe.serverSocketEnabled': false } });
    check(made.ok, 'a realm of this run\'s own', (made.errors || []).join(' '));
    const realm = realms.get(REALM);
    const inRealm = function (fn) {
      return realms.run(realm, fn);
    };
    const set = function (key, value) {
      const r = realms.setOverride(REALM, key, value);
      if (!r.ok) {
        throw new Error(key + ': ' + (r.errors || []).join(' '));
      }
    };
    const posture = function () {
      return inRealm(function () {
        return auth.workloadTcpPosture();
      });
    };
    try {
      set('spiffe.grpcHost', '0.0.0.0');
      set('global.mode', 'development');
      let p = posture();
      check(p.served && !p.errorCode && /development/.test(p.state),
            'development: the Workload API is served over TCP, wildcard ' +
            'and undeclared alike', p);
      set('global.mode', 'product');
      p = posture();
      check(!p.served && p.errorCode === 'STS-SPIFFE-0120' &&
            p.state === 'not served (product, source not declared ' +
                        'authenticated)' &&
            /section 3/.test(p.why),
            'product without spiffe.workloadTcpSourceAuthenticated: not ' +
            'served (STS-SPIFFE-0120)', p);
      set('spiffe.workloadTcpSourceAuthenticated', true);
      p = posture();
      check(!p.served && p.errorCode === 'STS-SPIFFE-0121' &&
            /wildcard/.test(p.state),
            'product, declared, spiffe.grpcHost 0.0.0.0: refused ' +
            '(STS-SPIFFE-0121)', p);
      set('spiffe.grpcHost', '::');
      p = posture();
      check(!p.served && p.errorCode === 'STS-SPIFFE-0121',
            'product, declared, spiffe.grpcHost ::: refused too', p);
      set('spiffe.grpcHost', '10.1.2.3');
      p = posture();
      check(p.served && !p.errorCode && p.declared &&
            /declared authenticated/.test(p.state),
            'product, declared, a named address: served', p);
      set('spiffe.workloadPort', 0);
      p = posture();
      check(!p.served && !p.errorCode && /off/.test(p.state),
            'a port of 0 is off, with no code, in any mode', p);
    } catch (e) {
      check(false, 'the posture half ran to the end', e.stack);
    } finally {
      set('spiffe.workloadPort', port);
      set('spiffe.grpcHost', '127.0.0.1');
      set('spiffe.workloadTcpSourceAuthenticated', false);
      set('global.mode', 'development');
    }

    // ---- 2. the bind ------------------------------------------------------
    const tcpBinding = function () {
      return (server.bindings().workload || []).filter(function (b) {
        return b.realm === REALM && !b.socket;
      })[0] || null;
    };
    // SPIFFE off and on again, which is what binds a realm's listeners anew.
    const rebind = async function () {
      set('spiffe.enabled', false);
      await server.reconcile();
      set('spiffe.enabled', true);
      await server.reconcile();
    };
    const httpServer = http.createServer(app);
    await new Promise(function (r) { httpServer.listen(0, '127.0.0.1', r); });
    const spiffeDocument = function (html) {
      return new Promise(function (resolve) {
        http.get('http://127.0.0.1:' + httpServer.address().port + '/realm/' +
                 REALM + '/spiffe' + (html ? '' : '?format=json'),
               function (res) {
          let text = '';
          res.on('data', function (c) { text += c; });
          res.on('end', function () {
            try {
              resolve(html ? { html: text } : JSON.parse(text));
            } catch (e) {
              resolve({ unparsed: text.slice(0, 400) });
            }
          });
        }).on('error', function (e) {
          resolve({ error: e.message });
        });
      });
    };
    const client = function () {
      return new (rpc.grpc.makeGenericClientConstructor(
        rpc.SERVICES.workload, 'SpiffeWorkloadAPI'))(
          '127.0.0.1:' + port, rpc.grpc.credentials.createInsecure());
    };
    const fetchJwt = function (spiffeId) {
      return new Promise(function (resolve) {
        const c = client();
        const metadata = new rpc.grpc.Metadata();
        metadata.set(rpc.SECURITY_HEADER, 'true');
        c.FetchJWTSVID({ audience: ['urn:probe:166'], spiffe_id: spiffeId },
                       metadata, { deadline: Date.now() + 20000 },
                       function (err, reply) {
          c.close();
          resolve(err ? { ok: false, code: err.code, details: err.details }
                      : { ok: true,
                          ids: ((reply && reply.svids) || [])
                            .map(function (s) { return s.spiffe_id; }) });
        });
      });
    };
    try {
      await server.listen().whenReady;
      set('global.mode', 'product');
      set('spiffe.enabled', true);
      await server.reconcile();
      let b = tcpBinding();
      check(!!b && !b.listening && errorCodes.codeOf(b) === 'STS-SPIFFE-0120',
            'product, undeclared: the realm\'s Workload API TCP port is NOT ' +
            'bound, recorded as STS-SPIFFE-0120', b);
      check(!(await connects(port)),
            'and nothing answers a connection on it');
      let doc = await spiffeDocument();
      const tcpOf = function (d) {
        return (d && d.workloadAttestation && d.workloadAttestation.tcp) || {};
      };
      check(tcpOf(doc).state ===
              'not served (product, source not declared authenticated)' &&
            tcpOf(doc).listening === false &&
            JSON.stringify(doc).indexOf('STS-SPIFFE-') < 0,
            'GET /spiffe says so under workloadAttestation.tcp, and sends ' +
            'no error code',
            tcpOf(doc));

      set('spiffe.workloadTcpSourceAuthenticated', true);
      set('spiffe.grpcHost', '0.0.0.0');
      await rebind();
      b = tcpBinding();
      check(!!b && !b.listening && errorCodes.codeOf(b) === 'STS-SPIFFE-0121',
            'product, declared, wildcard address: NOT bound ' +
            '(STS-SPIFFE-0121)', b);

      set('spiffe.grpcHost', '127.0.0.1');
      // Written while the realm is in development: a transport-only entry,
      // which product must not answer anybody with.
      set('global.mode', 'development');
      const td = inRealm(function () { return ca.trustDomain(); });
      const id = function (p) { return 'spiffe://' + td + p; };
      const SERVER = spiffeIdLib.serverId(td);
      const legacy = inRealm(function () {
        return registry.createEntry({ spiffeId: id('/probe/any-tcp'),
          parentId: SERVER,
          selectors: [{ type: 'transport', value: 'tcp' }] },
        'test', td, 'test');
      });
      check(legacy.ok, 'development accepts an entry selecting only ' +
            'transport:tcp', (legacy.errors || []).join(' '));
      set('global.mode', 'product');
      const good = inRealm(function () {
        return registry.createEntry({ spiffeId: id('/probe/from-loopback'),
          parentId: SERVER,
          selectors: [{ type: 'transport', value: 'tcp' },
                      { type: 'peer', value: '127.0.0.1' }] },
        'test', td, 'test');
      });
      check(good.ok, 'product accepts an entry selecting peer:127.0.0.1',
            (good.errors || []).join(' '));
      await rebind();
      b = tcpBinding();
      check(!!b && b.listening,
            'product, declared, a named address: the port is bound', b);
      doc = await spiffeDocument();
      check(tcpOf(doc).state ===
              'served (product, source declared authenticated)' &&
            tcpOf(doc).listening === true,
            'and GET /spiffe says it is served, on the declaration',
            tcpOf(doc));
      const page = await spiffeDocument(true);
      check(/served \(product, source declared authenticated\)/.test(
              page.html || ''),
            'and so does the page a person reads');
      let answer = await fetchJwt(id('/probe/from-loopback'));
      check(answer.ok && answer.ids.length === 1 &&
            answer.ids[0] === id('/probe/from-loopback'),
            'a TCP caller from 127.0.0.1 is issued a JWT-SVID for the entry ' +
            'selecting its peer: address', answer);
      answer = await fetchJwt(id('/probe/any-tcp'));
      check(answer.ok && answer.ids.length === 0,
            'and nothing for the transport-only entry written in ' +
            'development, which answers nobody in product ' +
            '(STS-SPIFFE-0123)', answer);

      // The declaration withdrawn with the port still bound: the read is
      // the guard.
      set('spiffe.workloadTcpSourceAuthenticated', false);
      answer = await fetchJwt(id('/probe/from-loopback'));
      check(!answer.ok && answer.code === 14 &&
            /not served over TCP/.test(answer.details || ''),
            'the declaration withdrawn while the port is bound: every call ' +
            'is refused UNAVAILABLE, naming why (STS-SPIFFE-0120)', answer);

      set('global.mode', 'development');
      await rebind();
      b = tcpBinding();
      check(!!b && b.listening,
            'development, undeclared: the port is bound, as it always was', b);
      answer = await fetchJwt(id('/probe/any-tcp'));
      check(answer.ok && answer.ids.length === 1,
            'and the transport-only entry answers a TCP caller there', answer);
      inRealm(function () {
        registry.deleteEntry(legacy.id, 'test');
        registry.deleteEntry(good.id, 'test');
      });
    } catch (e) {
      check(false, 'the bind half ran to the end', e.stack);
    }

    // ---- 3. the entry, through all three doors ---------------------------
    try {
      set('global.mode', 'product');
      const td = inRealm(function () { return ca.trustDomain(); });
      const id = function (p) { return 'spiffe://' + td + p; };
      const SERVER = spiffeIdLib.serverId(td);
      const refusedShapes = [
        { name: 'transport:tcp only', selectors: [
          { type: 'transport', value: 'tcp' }] },
        { name: 'endpoint: only', selectors: [
          { type: 'endpoint', value: '127.0.0.1:' + port }] },
        { name: 'transport: and endpoint:', selectors: [
          { type: 'transport', value: 'tcp' },
          { type: 'endpoint', value: '127.0.0.1:' + port }] },
        { name: 'no selector at all', selectors: [] }
      ];
      refusedShapes.forEach(function (shape) {
        const r = inRealm(function () {
          return registry.createEntry({ spiffeId: id('/probe/refused'),
            parentId: SERVER, selectors: shape.selectors }, 'test', td,
          'test');
        });
        check(!r.ok && errorCodes.codeOf(r) === 'STS-SPIFFE-0122' &&
              /product mode/.test((r.errors || []).join(' ')) &&
              !Object.prototype.hasOwnProperty.call(r, 'errorCode'),
              'registry, product: ' + shape.name + ' is refused ' +
              '(STS-SPIFFE-0122, carried as a mark and never as a member)',
              { errors: r.errors, code: errorCodes.codeOf(r) });
      });

      const create = rpc.localMethod('server', 'Entry.BatchCreateEntry');
      const update = rpc.localMethod('server', 'Entry.BatchUpdateEntry');
      const proto = function (spiffeId, selectors) {
        return {
          spiffe_id: { trust_domain: td,
                       path: spiffeId.slice(('spiffe://' + td).length) },
          parent_id: { trust_domain: td,
                       path: SERVER.slice(('spiffe://' + td).length) },
          selectors: selectors
        };
      };
      let reply = await inRealm(function () {
        return create({ request: { entries: [
          proto(id('/probe/grpc-refused'), [{ type: 'transport',
                                              value: 'tcp' }]),
          proto(id('/probe/grpc-ok'), [{ type: 'transport', value: 'tcp' },
                                       { type: 'peer',
                                         value: '127.0.0.1' }])] },
                        spiffeCaller: null });
      });
      const results = (reply && reply.results) || [];
      check(results.length === 2 && results[0].status.code === 3 &&
            /identifies its workload|every caller/.test(
              results[0].status.message) &&
            results[1].status.code === 0 && !!results[1].entry,
            'SPIRE Server API, product: BatchCreateEntry refuses the ' +
            'transport-only item INVALID_ARGUMENT and creates the peer: one ' +
            'beside it', results.map(function (r) { return r.status; }));
      const okId = results[1] && results[1].entry && results[1].entry.id;
      reply = await inRealm(function () {
        return update({ request: { entries: [{ id: okId, selectors: [
          { type: 'transport', value: 'tcp' }] }],
                                   input_mask: { selectors: true } },
                        spiffeCaller: null });
      });
      const u = ((reply && reply.results) || [])[0] || {};
      check(!!u.status && u.status.code === 3,
            'and BatchUpdateEntry refuses narrowing that entry to ' +
            'transport:tcp alone', u.status);

      const viaAction = inRealm(function () {
        return adminActions.spiffeEntriesAction({ action: 'create',
          spiffeId: id('/probe/console-refused'),
          selectors: 'transport:tcp, endpoint:127.0.0.1:' + port });
      });
      check(!viaAction.ok && errorCodes.codeOf(viaAction) ===
              'STS-SPIFFE-0122',
            'the console\'s and /admin-api\'s action layer, product: ' +
            'refused with the registry\'s own code', {
              errors: viaAction.errors, code: errorCodes.codeOf(viaAction) });
      const viaActionOk = inRealm(function () {
        return adminActions.spiffeEntriesAction({ action: 'create',
          spiffeId: id('/probe/console-ok'),
          selectors: 'transport:tcp, peer:127.0.0.1' });
      });
      check(viaActionOk.ok,
            'and accepts the entry with a peer: selector',
            viaActionOk.errors);
      const updated = inRealm(function () {
        return adminActions.spiffeEntriesAction({ action: 'update',
          entry: viaActionOk.id, field: 'selectors', value: 'endpoint:x:1' });
      });
      check(!updated.ok && errorCodes.codeOf(updated) === 'STS-SPIFFE-0122',
            'and refuses an update to endpoint: alone', updated.errors);

      set('global.mode', 'development');
      const devOk = inRealm(function () {
        return adminActions.spiffeEntriesAction({ action: 'create',
          spiffeId: id('/probe/console-dev'), selectors: 'transport:tcp' });
      });
      check(devOk.ok, 'development: the same action accepts transport:tcp ' +
            'alone', devOk.errors);
      inRealm(function () {
        [okId, viaActionOk.id, devOk.id].forEach(function (entryId) {
          if (entryId) {
            registry.deleteEntry(entryId, 'test');
          }
        });
      });
    } catch (e) {
      check(false, 'the entry half ran to the end', e.stack);
    }

    // ---- 4. peer: matches exactly ----------------------------------------
    const entrySelectors = [{ type: 'peer', value: '127.0.0.1' }];
    const fromLoopback = [{ type: 'transport', value: 'tcp' },
                          { type: 'peer', value: '127.0.0.1' }];
    check(registry.selectorsMatch(entrySelectors, fromLoopback),
          'peer:127.0.0.1 matches a caller from 127.0.0.1');
    check(!registry.selectorsMatch(entrySelectors, [
      { type: 'transport', value: 'tcp' },
      { type: 'peer', value: '127.0.0.10' }]),
          'and not one from 127.0.0.10');
    check(!registry.selectorsMatch([{ type: 'peer', value: '127.0.0.0/8' }],
                                   fromLoopback),
          'and a prefix is not a selector any caller carries');

    // ---- and /admin/mode lists both requirements -------------------------
    const mode = require(ROOT + '/common/mode');
    const ids = mode.report().requirements.map(function (row) {
      return row.id;
    });
    check(ids.indexOf('spiffe-workload-tcp') >= 0 &&
          ids.indexOf('spiffe-entry-selectors') >= 0 &&
          typeof mode.servesUnattestedWorkloadTcp === 'function' &&
          typeof mode.registersUnidentifyingEntries === 'function',
          'mode.report() carries both requirements, and both predicates ' +
          'exist', ids.join(', '));

    try {
      set('global.mode', 'development');
      set('spiffe.enabled', false);
      await server.reconcile();
    } catch (e) {
      check(false, 'the realm was put back', e.message);
    }
    server.close();
    httpServer.close();
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child ran to the end',
                    detail: String(e && e.stack) });
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(1);
  });
}

function inAChild(t) {
  log.debug("Entering inAChild().");
  const out = path.join(os.tmpdir(), 'spiffe-workload-tcp-' + process.pid +
                        '-' + Math.random().toString(36).slice(2) + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  // The DEFAULT realm binds nothing: this file's realm is the only one with
  // a listener, on a port of its own, on loopback.
  const env = Object.assign(clean, {
    LOG_LEVEL: 'fatal', WT_ROOT: ROOT, WT_OUT: out,
    STS_SPIFFE_WORKLOAD_PORT: '0', STS_SPIFFE_SERVER_PORT: '0',
    STS_SPIFFE_WORKLOAD_SOCKET_ENABLED: 'false',
    STS_SPIFFE_SERVER_SOCKET_ENABLED: 'false'
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'],
    { env: env, encoding: 'utf8', timeout: 300000, cwd: ROOT });
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
               String(result.stderr || '').slice(-1200))) {
    log.debug("Leaving inAChild().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving inAChild().");
}

function run(t) {
  log.debug("Entering run().");
  t.log.info('=== #166: the Workload API over TCP, and what an entry must ' +
             'select ===');
  inAChild(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'spiffe_workload_tcp_product',
  describe: '#166: product serves the Workload API over TCP only where the ' +
            'network is declared to authenticate source addresses, on a ' +
            'named address, and refuses an entry that selects nothing ' +
            'identifying; development is unchanged',
  run: run
};
