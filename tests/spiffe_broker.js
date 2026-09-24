'use strict';
//
// File: spiffe_broker.js
//
// ===========================================================================
// THE SPIFFE BROKER API, OVER A REAL MUTUAL-TLS LISTENER (#170, 2026-09-23).
//
// In a CHILD PROCESS — requiring the protocol stack builds certificate
// authorities and binds listeners, and `run.js` runs every file in one
// process (`account_disable.js`'s arrangement). A realm of this run's own
// binds the Broker endpoint on 127.0.0.1 and a port of its own; a fake
// kubelet answers the read-only port on loopback; a gRPC CLIENT written here
// from `brokerapi.proto` (never the service's wrappers) calls it with SVIDs
// the realm's authority mints:
//
//   * REFUSED WITHOUT A BROKER SVID: no `broker.spiffe.io` header is
//     INVALID_ARGUMENT; no client certificate is UNAUTHENTICATED; an SVID
//     that verifies and names no broker is PERMISSION_DENIED;
//   * THE REFERENCE: none is INVALID_ARGUMENT with a google.rpc.ErrorInfo
//     (WORKLOAD_REFERENCE_INVALID, domain spiffe.io) in
//     `grpc-status-details-bin`; a type the broker is not allowed, and a type
//     nobody knows, are PERMISSION_DENIED; a pid that does not exist is
//     NOT_FOUND (WORKLOAD_NOT_FOUND); a pod by name without a namespace and
//     a non-pod resource are INVALID_ARGUMENT; a pod not on the node is
//     NOT_FOUND; a pod with no entry is PERMISSION_DENIED
//     (WORKLOAD_NOT_ENTITLED) — even with development's
//     `spiffe.attestWorkloads` off, because a brokered call is always
//     narrowed;
//   * ANSWERED WITH ONE: FetchJWTSVID for a PROCESS reference (the unix
//     attestor's uid selector) — one SVID, the admin entry left out, the
//     duplicate hint dropped — and for a POD reference by UID (the k8s
//     attestor over the kubelet's pod list); SubscribeToX509SVID's first
//     message, a leaf naming the entry; the two bundle streams;
//   * THE WORKLOAD'S LIFETIME (section 4.9): a stream held for a process
//     that then exits ends NOT_FOUND at the next re-send;
//   * THE BROKER LIST'S ACTION (rule 7's layer): an entry that is not a
//     SPIFFE ID, or names no reference type, is refused STS-SPIFFE-0141, and
//     a good one is written to `spiffe.brokers` in the realm;
//   * PRODUCT: the same broker answered in a product realm.
//
// The realm is left standing with SPIFFE off, for `tests/spiffe_pki.js`'s
// reason.
// ===========================================================================

const os = require('os');
const fs = require('fs');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'spiffe_broker', level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// The child's program. Runs in the child only, which the code style exempts
// from the Entering/Leaving lines; its findings are written to BK_OUT.
function childMain() {
  const ROOT = process.env.BK_ROOT;
  const OUT = process.env.BK_OUT;
  const REALM = 'spiffe-broker';
  const POD = '0f0e0d0c-0b0a-4908-8706-050403020100';
  const EMPTY_POD = '11111111-2222-4333-8444-555555555555';
  const fs = require('fs');
  const net = require('net');
  const http = require('http');
  const childProcess = require('child_process');
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
  const sleep = function (ms) {
    return new Promise(function (resolve) { setTimeout(resolve, ms); });
  };
  // Protobuf, this file's own: a varint, a field, and the one decoder the
  // ErrorInfo needs.
  const varint = function (n) {
    const out = [];
    let v = BigInt(n);
    do {
      let b = Number(v & BigInt(0x7f));
      v >>= BigInt(7);
      if (v > BigInt(0)) b |= 0x80;
      out.push(b);
    } while (v > BigInt(0));
    return Buffer.from(out);
  };
  const field = function (no, bytes) {
    const body = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes, 'utf8');
    return Buffer.concat([varint((no << 3) | 2), varint(body.length), body]);
  };
  const decode = function (buf) {
    const out = [];
    let at = 0;
    const read = function () {
      let v = 0;
      let shift = 0;
      for (;;) {
        const b = buf[at++];
        v += (b & 0x7f) * Math.pow(2, shift);
        shift += 7;
        if (!(b & 0x80)) return v;
      }
    };
    while (at < buf.length) {
      const key = read();
      const wire = key & 7;
      if (wire === 0) {
        out.push({ no: key >> 3, int: read() });
      } else {
        const len = read();
        out.push({ no: key >> 3, bytes: buf.subarray(at, at + len) });
        at += len;
      }
    }
    return out;
  };
  const errorInfo = function (err) {
    const raw = err && err.metadata
      ? err.metadata.get('grpc-status-details-bin') : [];
    if (!raw || !raw.length) return null;
    const status = decode(Buffer.from(raw[0]));
    const any = status.filter(function (f) { return f.no === 3; })[0];
    if (!any) return null;
    const parts = decode(any.bytes);
    const typeUrl = parts.filter(function (f) { return f.no === 1; })[0];
    const value = parts.filter(function (f) { return f.no === 2; })[0];
    const info = decode(value.bytes);
    const text = function (no) {
      const f = info.filter(function (x) { return x.no === no; })[0];
      return f ? Buffer.from(f.bytes).toString('utf8') : '';
    };
    return { typeUrl: Buffer.from(typeUrl.bytes).toString('utf8'),
             reason: text(1), domain: text(2) };
  };
  const PID_URL = 'type.googleapis.com/spiffe.broker.WorkloadPIDReference';
  const K8S_URL =
    'type.googleapis.com/spiffe.broker.KubernetesObjectReference';
  const pidRef = function (pid) {
    return { reference: { type_url: PID_URL,
                          value: Buffer.concat([varint(1 << 3),
                                                varint(pid)]) } };
  };
  const podRef = function (o) {
    const typeMsg = Buffer.concat([field(1, o.plural || 'pods'),
                                   field(2, o.group || 'core')]);
    const parts = [field(1, typeMsg)];
    if (o.name !== undefined) {
      parts.push(field(2, Buffer.concat([
        o.namespace ? field(1, o.namespace) : Buffer.alloc(0),
        field(2, o.name)])));
    }
    if (o.uid) parts.push(field(3, o.uid));
    return { reference: { type_url: K8S_URL,
                          value: Buffer.concat(parts) } };
  };

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const realms = require(ROOT + '/common/realms');
    const errorCodes = require(ROOT + '/common/error_codes');
    const server = require(ROOT + '/spiffe/spiffe_server');
    const ca = require(ROOT + '/spiffe/spiffe_ca');
    const registry = require(ROOT + '/spiffe/spiffe_registry');
    const spiffeIdLib = require(ROOT + '/spiffe/spiffe_id');
    const adminActions = require(ROOT + '/admin-core/admin_actions');
    const grpc = require('@grpc/grpc-js');
    const loader = require('@grpc/proto-loader');

    // ---- the fake kubelet, the read-only port on loopback ----------------
    const pods = { items: [
      { metadata: { name: 'web-0', namespace: 'shop', uid: POD,
                    labels: { app: 'web' } },
        spec: { serviceAccountName: 'web-sa', nodeName: 'node-1' },
        status: { containerStatuses: [] } },
      { metadata: { name: 'idle-0', namespace: 'shop', uid: EMPTY_POD },
        spec: { serviceAccountName: 'idle', nodeName: 'node-1' },
        status: { containerStatuses: [] } }] };
    const kubelet = http.createServer(function (req, res) {
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify(req.url === '/pods' ? pods : {}));
    });
    await new Promise(function (r) { kubelet.listen(0, '127.0.0.1', r); });

    const port = await freePort();
    const made = realms.get(REALM) ? { ok: true } : realms.create({
      id: REALM, name: REALM, overrides: {
        'spiffe.workloadPort': 0, 'spiffe.serverPort': 0,
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
    const children = [];
    let client = null;
    try {
      set('spiffe.brokerPort', port);
      set('spiffe.workloadAttestors', 'unix,k8s');
      set('spiffe.k8sKubeletReadOnlyPort', kubelet.address().port);
      set('spiffe.k8sMaxPollAttempts', 1);
      await server.listen().whenReady;
      set('spiffe.enabled', true);
      await server.reconcile();
      const binding = (server.bindings().broker || []).filter(function (b) {
        return b.realm === REALM;
      })[0];
      check(binding && binding.listening && binding.tls &&
            binding.address === '127.0.0.1:' + port,
            'the realm\'s Broker endpoint is bound, mutual TLS, on its own ' +
            'address', binding);

      const td = inRealm(function () { return ca.trustDomain(); });
      const anchors = inRealm(function () {
        return ca.state().trustAnchors.map(function (a) {
          return a.certificatePem;
        }).join('\n');
      });
      const mint = function (pathPart) {
        return inRealm(function () {
          return ca.mintX509Svid(spiffeIdLib.make(td, pathPart),
                                 { ttl: 600 });
        });
      };
      const brokerId = spiffeIdLib.make(td, '/broker');
      const podBrokerId = spiffeIdLib.make(td, '/pod-broker');
      const brokerSvid = await mint('/broker');
      const podBrokerSvid = await mint('/pod-broker');
      const strangerSvid = await mint('/stranger');

      // ---- the broker list, through the action layer (rule 7) -----------
      const action = function (body) {
        return inRealm(function () {
          return adminActions.spiffeBrokersAction(body);
        });
      };
      let r = action({ action: 'set', id: 'not-a-spiffe-id',
                       referenceTypes: 'pid' });
      check(r.ok === false && errorCodes.codeOf(r) === 'STS-SPIFFE-0141',
            'a broker that is not a SPIFFE ID is refused (STS-SPIFFE-0141)', r);
      r = action({ action: 'set', id: brokerId, referenceTypes: '' });
      check(r.ok === false && errorCodes.codeOf(r) === 'STS-SPIFFE-0141',
            'a broker allowed no reference type is refused', r);
      r = action({ action: 'set', id: brokerId,
                   referenceTypes: ['pid', 'k8s'] });
      const r2 = action({ action: 'set', id: podBrokerId,
                          referenceTypes: 'k8s' });
      check(r.ok && r2.ok && /pid,k8s/.test(inRealm(function () {
              return String(require(ROOT + '/common/config')
                .value('spiffe.brokers'));
            })),
            'two brokers are written to spiffe.brokers in the realm', [r, r2]);

      // ---- entries -------------------------------------------------------
      const uid = process.getuid();
      const entry = function (record) {
        return inRealm(function () {
          return registry.createEntry(Object.assign({
            parentId: spiffeIdLib.serverId(td) }, record), 'test', td, '');
        });
      };
      const pidEntry = entry({ spiffeId: spiffeIdLib.make(td, '/by-pid'),
                               selectors: [{ type: 'unix',
                                             value: 'uid:' + uid }],
                               hint: 'internal', x509SvidTtl: 2 });
      const dupHint = entry({ spiffeId: spiffeIdLib.make(td, '/dup-hint'),
                              selectors: [{ type: 'unix',
                                            value: 'uid:' + uid }],
                              hint: 'internal' });
      const adminEntry = entry({ spiffeId: spiffeIdLib.make(td, '/admin-one'),
                                 selectors: [{ type: 'unix',
                                               value: 'uid:' + uid }],
                                 admin: true });
      const podEntry = entry({ spiffeId: spiffeIdLib.make(td, '/by-pod'),
                               selectors: [{ type: 'k8s',
                                             value: 'pod-uid:' + POD }] });
      check(pidEntry.ok && dupHint.ok && adminEntry.ok && podEntry.ok,
            'four registration entries in the realm', [pidEntry.errors,
            dupHint.errors, adminEntry.errors, podEntry.errors]);

      // ---- the client ----------------------------------------------------
      const definition = loader.loadSync('brokerapi.proto', {
        keepCase: true, longs: String, enums: String, defaults: true,
        oneofs: true, includeDirs: [ROOT + '/spiffe/protos'] });
      const Client = grpc.makeGenericClientConstructor(
        definition['spiffe.broker.API'], 'API');
      const serverId = spiffeIdLib.serverId(td);
      const connect = function (svid) {
        const verify = { checkServerIdentity: function (host, cert) {
          return String(cert.subjectaltname || '').indexOf('URI:' +
                                                            serverId) >= 0
            ? undefined : new Error('not ' + serverId);
        } };
        const creds = svid
          ? grpc.credentials.createSsl(Buffer.from(anchors),
              Buffer.from(svid.privateKeyPem), Buffer.from(
                svid.chainPem.join('\n')), verify)
          : grpc.credentials.createSsl(Buffer.from(anchors), null, null,
                                       verify);
        return new Client('127.0.0.1:' + port, creds,
                          { 'grpc.use_local_subchannel_pool': 1 });
      };
      const header = function () {
        const md = new grpc.Metadata();
        md.set('broker.spiffe.io', 'true');
        return md;
      };
      const unary = function (c, method, request, metadata) {
        return new Promise(function (resolve) {
          c[method](request, metadata || header(), { deadline:
            Date.now() + 20000 }, function (err, reply) {
            resolve({ err: err, reply: reply });
          });
        });
      };
      const first = function (c, method, request) {
        return new Promise(function (resolve) {
          const stream = c[method](request, header());
          let done = false;
          stream.on('data', function (message) {
            if (!done) {
              done = true;
              resolve({ message: message, stream: stream });
            }
          });
          stream.on('error', function (err) {
            if (!done) {
              done = true;
              resolve({ err: err, stream: stream });
            }
          });
        });
      };
      const jwtRequest = function (ref) {
        return { reference: ref, audience: ['https://api.test'] };
      };

      // ---- refused without a broker SVID --------------------------------
      client = connect(brokerSvid);
      let a = await unary(client, 'FetchJWTSVID', jwtRequest(pidRef(
        process.pid)), new grpc.Metadata());
      check(a.err && a.err.code === grpc.status.INVALID_ARGUMENT &&
            /security header/.test(a.err.details),
            'no broker.spiffe.io header: INVALID_ARGUMENT', a.err);
      const anonymous = connect(null);
      a = await unary(anonymous, 'FetchJWTSVID', jwtRequest(pidRef(
        process.pid)));
      check(a.err && a.err.code === grpc.status.UNAUTHENTICATED,
            'no client certificate: UNAUTHENTICATED', a.err);
      anonymous.close();
      const stranger = connect(strangerSvid);
      a = await unary(stranger, 'FetchJWTSVID', jwtRequest(pidRef(
        process.pid)));
      check(a.err && a.err.code === grpc.status.PERMISSION_DENIED &&
            /not an authorized broker/.test(a.err.details),
            'an SVID that verifies and names no broker: PERMISSION_DENIED',
            a.err);
      stranger.close();

      // ---- the reference -------------------------------------------------
      a = await unary(client, 'FetchJWTSVID',
                      { reference: null, audience: ['a'] });
      let info = errorInfo(a.err);
      check(a.err && a.err.code === grpc.status.INVALID_ARGUMENT && info &&
            info.reason === 'WORKLOAD_REFERENCE_INVALID' &&
            info.domain === 'spiffe.io' &&
            info.typeUrl === 'type.googleapis.com/google.rpc.ErrorInfo',
            'no reference: INVALID_ARGUMENT with a google.rpc.ErrorInfo, ' +
            'WORKLOAD_REFERENCE_INVALID in the spiffe.io domain',
            { err: a.err && a.err.details, info: info });
      const podOnly = connect(podBrokerSvid);
      a = await unary(podOnly, 'FetchJWTSVID', jwtRequest(pidRef(
        process.pid)));
      check(a.err && a.err.code === grpc.status.PERMISSION_DENIED &&
            /not allowed to use reference type/.test(a.err.details),
            'a reference type the broker is not allowed: PERMISSION_DENIED',
            a.err);
      podOnly.close();
      a = await unary(client, 'FetchJWTSVID', jwtRequest({ reference: {
        type_url: 'type.googleapis.com/example.Unknown',
        value: Buffer.alloc(0) } }));
      check(a.err && a.err.code === grpc.status.PERMISSION_DENIED,
            'a type nobody knows is refused by the allow list first, as ' +
            'SPIRE refuses it', a.err);
      let missing = 4194000;
      while (fs.existsSync('/proc/' + missing)) missing--;
      a = await unary(client, 'FetchJWTSVID', jwtRequest(pidRef(missing)));
      info = errorInfo(a.err);
      check(a.err && a.err.code === grpc.status.NOT_FOUND && info &&
            info.reason === 'WORKLOAD_NOT_FOUND',
            'a pid that does not exist: NOT_FOUND, WORKLOAD_NOT_FOUND',
            { err: a.err && a.err.details, info: info });
      a = await unary(client, 'FetchJWTSVID', jwtRequest(podRef(
        { name: 'web-0' })));
      check(a.err && a.err.code === grpc.status.INVALID_ARGUMENT &&
            /namespace is required/.test(a.err.details),
            'a pod by name without its namespace: INVALID_ARGUMENT', a.err);
      a = await unary(client, 'FetchJWTSVID', jwtRequest(podRef(
        { plural: 'deployments', group: 'apps', namespace: 'shop',
          name: 'web' })));
      check(a.err && a.err.code === grpc.status.INVALID_ARGUMENT &&
            /only pods/.test(a.err.details),
            'a reference to a resource other than a pod: INVALID_ARGUMENT',
            a.err);
      a = await unary(client, 'FetchJWTSVID', jwtRequest(podRef(
        { uid: '99999999-2222-4333-8444-555555555555' })));
      check(a.err && a.err.code === grpc.status.NOT_FOUND &&
            /not found on agent node/.test(a.err.details),
            'a pod not on this node: NOT_FOUND', a.err);
      a = await unary(client, 'FetchJWTSVID', jwtRequest(podRef(
        { uid: EMPTY_POD })));
      info = errorInfo(a.err);
      check(a.err && a.err.code === grpc.status.PERMISSION_DENIED && info &&
            info.reason === 'WORKLOAD_NOT_ENTITLED',
            'a pod no entry selects: PERMISSION_DENIED, WORKLOAD_NOT_ENTITLED',
            { err: a.err && a.err.details, info: info });
      set('spiffe.attestWorkloads', false);
      a = await unary(client, 'FetchJWTSVID', jwtRequest(podRef(
        { uid: EMPTY_POD })));
      check(a.err && a.err.code === grpc.status.PERMISSION_DENIED,
            'and still with development\'s spiffe.attestWorkloads off: a ' +
            'brokered call is always narrowed', a.err);
      set('spiffe.attestWorkloads', true);
      a = await unary(client, 'FetchJWTSVID',
                      { reference: pidRef(process.pid), audience: [] });
      check(a.err && a.err.code === grpc.status.INVALID_ARGUMENT,
            'no audience: INVALID_ARGUMENT', a.err);

      // ---- answered with one ---------------------------------------------
      a = await unary(client, 'FetchJWTSVID', jwtRequest(pidRef(
        process.pid)));
      const svids = (a.reply && a.reply.svids) || [];
      const claims = svids.length ? JSON.parse(Buffer.from(
        svids[0].svid.split('.')[1], 'base64url').toString('utf8')) : {};
      check(!a.err && svids.length === 1 &&
            svids[0].spiffe_id === spiffeIdLib.make(td, '/by-pid') &&
            svids[0].hint === 'internal' &&
            claims.sub === svids[0].spiffe_id &&
            [].concat(claims.aud).indexOf('https://api.test') >= 0,
            'a PROCESS reference is attested by the unix attestor and ' +
            'answered with its entry\'s JWT-SVID — the admin entry left out, ' +
            'the duplicate hint dropped', { err: a.err, svids: svids });
      a = await unary(client, 'FetchJWTSVID', jwtRequest(podRef(
        { uid: POD })));
      check(!a.err && a.reply.svids.length === 1 &&
            a.reply.svids[0].spiffe_id === spiffeIdLib.make(td, '/by-pod'),
            'a POD reference by UID is attested by the k8s attestor over the ' +
            'kubelet\'s pod list', a.err || a.reply);
      a = await unary(client, 'FetchJWTSVID', jwtRequest(podRef(
        { namespace: 'shop', name: 'web-0', uid: POD })));
      check(!a.err && a.reply.svids.length === 1,
            'by namespace and name with a matching UID too', a.err);
      a = await unary(client, 'FetchJWTSVID', jwtRequest(podRef(
        { namespace: 'shop', name: 'web-0', uid: EMPTY_POD })));
      check(a.err && a.err.code === grpc.status.NOT_FOUND &&
            /expected/.test(a.err.details),
            'by name with a UID that does not match: NOT_FOUND', a.err);

      let s = await first(client, 'SubscribeToX509SVID',
                          { reference: pidRef(process.pid) });
      const got = (s.message && s.message.svids) || [];
      let leafUri = '';
      try {
        const cert = new (require('crypto').X509Certificate)(
          Buffer.from(got[0].x509_svid));
        leafUri = String(cert.subjectAltName || '');
      } catch (e) {
        leafUri = 'unreadable: ' + e.message;
      }
      check(!s.err && got.length === 1 &&
            leafUri.indexOf(spiffeIdLib.make(td, '/by-pid')) >= 0 &&
            got[0].x509_svid_key.length > 0 && got[0].bundle.length > 0,
            'SubscribeToX509SVID answers a leaf naming the entry, its key ' +
            'and the bundle', s.err || leafUri);
      s.stream.cancel();
      s = await first(client, 'SubscribeToX509Bundles',
                      { reference: pidRef(process.pid) });
      check(!s.err && s.message && s.message.bundles &&
            Buffer.from(s.message.bundles[spiffeIdLib.trustDomainId(td)] ||
                        []).length > 0,
            'SubscribeToX509Bundles answers this trust domain\'s bundle',
            s.err);
      s.stream.cancel();
      s = await first(client, 'SubscribeToJWTBundles',
                      { reference: podRef({ uid: POD }) });
      const jwks = s.message && s.message.bundles
        ? JSON.parse(Buffer.from(s.message.bundles[
            spiffeIdLib.trustDomainId(td)] || '{}').toString('utf8')) : {};
      check(!s.err && Array.isArray(jwks.keys) && jwks.keys.length > 0 &&
            jwks.keys.every(function (k) { return k.use === 'jwt-svid'; }),
            'SubscribeToJWTBundles answers the jwt-svid keys', s.err || jwks);
      s.stream.cancel();

      // ---- the workload's lifetime ---------------------------------------
      const sleeper = childProcess.spawn('sleep', ['60'], { stdio: 'ignore' });
      children.push(sleeper);
      await sleep(200);
      s = await first(client, 'SubscribeToX509SVID',
                      { reference: pidRef(sleeper.pid) });
      check(!s.err && s.message && s.message.svids.length === 1,
            'a stream for another process is answered', s.err);
      const ended = new Promise(function (resolve) {
        s.stream.on('error', function (err) { resolve(err); });
        setTimeout(function () { resolve(null); }, 10000);
      });
      sleeper.kill('SIGKILL');
      const endErr = await ended;
      check(endErr && endErr.code === grpc.status.NOT_FOUND &&
            /has stopped/.test(endErr.details),
            'and once that process has exited the stream ENDS, NOT_FOUND, at ' +
            'the next re-send — nothing more is sent for it', endErr);

      // ---- product -------------------------------------------------------
      set('global.mode', 'product');
      a = await unary(client, 'FetchJWTSVID', jwtRequest(pidRef(
        process.pid)));
      check(!a.err && a.reply.svids.length === 1,
            'a product realm answers the same broker the same way', a.err);
      set('global.mode', 'development');
      r = action({ action: 'remove', id: brokerId });
      check(r.ok, 'a broker removed', r);
      a = await unary(connect(brokerSvid), 'FetchJWTSVID', jwtRequest(pidRef(
        process.pid)));
      check(a.err && a.err.code === grpc.status.PERMISSION_DENIED,
            'is refused on its next call', a.err);
    } catch (e) {
      check(false, 'the broker half ran to the end', e.stack);
    } finally {
      children.forEach(function (c) {
        try {
          c.kill('SIGKILL');
        } catch (e) {
          // Already gone.
        }
      });
      if (client) client.close();
      try {
        set('global.mode', 'development');
        set('spiffe.enabled', false);
        await server.reconcile();
      } catch (e) {
        check(false, 'the realm was turned off again', e.stack);
      }
      kubelet.close();
    }
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
  const out = path.join(os.tmpdir(), 'spiffe-broker-' + process.pid + '-' +
                        require('crypto').randomBytes(8).toString('hex') +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  // The DEFAULT realm binds nothing: this file's realm is the only one with
  // a listener, on a port of its own, on loopback.
  const env = Object.assign(clean, {
    LOG_LEVEL: 'fatal', BK_ROOT: ROOT, BK_OUT: out,
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
  t.log.info('=== #170: the SPIFFE Broker API ===');
  inAChild(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'spiffe_broker',
  describe: '#170: the SPIFFE Broker API over mutual TLS — refused without a ' +
            'broker SVID, every reference refusal of section 4.8, answered ' +
            'for a process and a pod reference, and a stream that ends with ' +
            'its workload',
  run: run
};
