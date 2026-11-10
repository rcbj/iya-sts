// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/spiffe_model_wire.js
//
// ---------------------------------------------------------------------------
// WHAT THE SPIFFE ENDPOINTS ANSWER, HELD TO A RECORD (#1579 item 6).
//
// The messages of the Workload API, the SPIRE Server API and the Broker API,
// the SPIFFE ID grammar, the bundle's members and the X509-SVID and JWT-SVID
// facts come from `models/spiffe/*.tsp` since #1579. The switch was to change
// NOTHING a client sees — the model describes and validates the wire, it
// does not reshape it — so this records what the service answered before it,
// in `tests/spiffe_model_wire.snapshot.json`, and holds every later build to
// it: a scripted conversation over real gRPC, on a realm's own Unix sockets
// and its own mutual-TLS Broker port, and with the HTTP bundle endpoint, in
// development and in product mode.
//
// What is recorded of each call: the gRPC status code, its details, the
// trailing metadata (a binary value as base64), and every message the
// server sent, decoded by the same vendored protos a client uses — field by
// field, with `bytes` described rather than copied: a certificate (or a
// chain) as its subject, issuer, URI SAN, CA flag, key usage, extended key
// usage and key type; a private key as its type; a JWKS document parsed. A
// JWT is its header and claims. Values that differ from run to run — an
// instant, an expiry, a serial, a key's material, an entry's id, a token —
// are replaced by a placeholder; the comparison is of everything else.
//
// `SPIFFE_WIRE_PRINT=1 node tests/spiffe_model_wire.js` prints the record
// instead of comparing it; that is how the snapshot was written, from the
// image of the tree before the switch, and how it is rewritten when the
// wire is MEANT to change.
//
// A CHILD PROCESS, as tests/spiffe_broker.js runs one: the protocol stack,
// the authorities and the listeners are built once, fresh, and nothing
// leaks into the runner. The realm is left standing with SPIFFE off, for
// `tests/spiffe_pki.js`'s reason.
// ---------------------------------------------------------------------------

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const log = require('bunyan').createLogger({ name: 'spiffe_model_wire',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const SNAPSHOT = path.join(__dirname, 'spiffe_model_wire.snapshot.json');

// The child's whole program, serialised with toString() and run by `node -e`
// — so it may use nothing from this file's scope, and (root CLAUDE.md, Code
// style) it is exempt from the Entering/Leaving rule and carries its errors
// on the result it writes.
function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.SW_ROOT;
  const OUT = process.env.SW_OUT;
  const REALM = 'spiffe-model-wire';
  const TRUST_DOMAIN = 'model-wire.example.test';
  const fs = require('fs');
  const os = require('os');
  const net = require('net');
  const path = require('path');
  const http = require('http');
  const nodeCrypto = require('crypto');
  const record = { wire: [], problems: [] };
  const SOCKETS = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-spiffe-wire-'));

  const freePort = function () {
    return new Promise(function (resolve) {
      const probe = net.createServer();
      probe.listen(0, '127.0.0.1', function () {
        const port = probe.address().port;
        probe.close(function () {
          resolve(port);
        });
      });
    });
  };

  // ---- what a `bytes` field is ------------------------------------------
  // Splits concatenated DER into its top-level elements, or null when the
  // bytes are not DER all the way through.
  const derElements = function (buf) {
    const out = [];
    let at = 0;
    while (at < buf.length) {
      if (buf[at] !== 0x30 || at + 2 > buf.length) {
        return null;
      }
      let len = buf[at + 1];
      let head = 2;
      if (len & 0x80) {
        const n = len & 0x7f;
        if (n < 1 || n > 4 || at + 2 + n > buf.length) {
          return null;
        }
        len = 0;
        for (let i = 0; i < n; i++) {
          len = (len * 256) + buf[at + 2 + i];
        }
        head = 2 + n;
      }
      if (at + head + len > buf.length) {
        return null;
      }
      out.push(buf.slice(at, at + head + len));
      at += head + len;
    }
    return out.length ? out : null;
  };

  // The key usage bits of a certificate, read off its DER: node does not
  // expose them, and they are one of the X509-SVID facts the model states.
  const KU_NAMES = ['digitalSignature', 'nonRepudiation', 'keyEncipherment',
                    'dataEncipherment', 'keyAgreement', 'keyCertSign',
                    'cRLSign', 'encipherOnly', 'decipherOnly'];
  const keyUsageOf = function (der) {
    const oid = Buffer.from([0x06, 0x03, 0x55, 0x1d, 0x0f]);
    const at = der.indexOf(oid);
    if (at < 0) {
      return null;
    }
    let p = at + oid.length;
    let critical = false;
    if (der[p] === 0x01) {
      critical = der[p + 2] !== 0;
      p += 3;
    }
    if (der[p] !== 0x04) {
      return null;
    }
    const bits = der.slice(p + 2, p + 2 + der[p + 1]);
    if (bits[0] !== 0x03) {
      return null;
    }
    const value = bits.slice(3, 3 + bits[1] - 1);
    const names = [];
    KU_NAMES.forEach(function (name, i) {
      const byte = value[Math.floor(i / 8)] || 0;
      if (byte & (0x80 >> (i % 8))) {
        names.push(name);
      }
    });
    return { critical: critical, usages: names };
  };

  const describeCertificate = function (der) {
    const cert = new nodeCrypto.X509Certificate(der);
    return {
      certificate: true,
      subject: cert.subject,
      issuer: cert.issuer,
      san: cert.subjectAltName || null,
      ca: cert.ca,
      keyUsage: keyUsageOf(der),
      extKeyUsage: cert.keyUsage || null,
      keyType: cert.publicKey.asymmetricKeyType,
      lifetime: Math.round((Date.parse(cert.validTo) -
                            Date.parse(cert.validFrom)) / 1000)
    };
  };

  const describeBytes = function (buf) {
    if (!buf.length) {
      return '<empty>';
    }
    const text = buf.toString('utf8');
    if (text.charAt(0) === '{') {
      try {
        return { json: JSON.parse(text) };
      } catch (e) {
        // not JSON; described below
      }
    }
    const elements = derElements(buf);
    if (elements) {
      try {
        return elements.map(describeCertificate);
      } catch (e) {
        try {
          const key = nodeCrypto.createPrivateKey({ key: buf, format: 'der',
                                                    type: 'pkcs8' });
          return { privateKey: key.asymmetricKeyType };
        } catch (e2) {
          try {
            const key = nodeCrypto.createPublicKey({ key: buf, format: 'der',
                                                     type: 'spki' });
            return { publicKey: key.asymmetricKeyType };
          } catch (e3) {
            return '<der:' + elements.length + '>';
          }
        }
      }
    }
    return '<bytes>';
  };

  const describeJwt = function (token) {
    const parts = String(token).split('.');
    const decode = function (part) {
      return JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
    };
    return { jwt: { header: decode(parts[0]), claims: decode(parts[1]) } };
  };

  const plain = function (value, key) {
    // A JWK's certificate chain is base64 DER (RFC 7517 section 4.7).
    if (key === 'x5c' && Array.isArray(value)) {
      return value.map(function (one) {
        return describeCertificate(Buffer.from(String(one), 'base64'));
      });
    }
    if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
      return describeBytes(Buffer.from(value));
    }
    if (Array.isArray(value)) {
      return value.map(function (one) {
        return plain(one);
      });
    }
    if (value && typeof value === 'object') {
      const out = {};
      Object.keys(value).sort().forEach(function (name) {
        out[name] = plain(value[name], name);
      });
      return out;
    }
    if (typeof value === 'string' &&
        /^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+$/.test(value)) {
      try {
        return describeJwt(value);
      } catch (e) {
        return value;
      }
    }
    return value;
  };

  const trailers = function (metadata) {
    if (!metadata || typeof metadata.getMap !== 'function') {
      return {};
    }
    const map = metadata.getMap();
    const out = {};
    Object.keys(map).sort().forEach(function (key) {
      if (key === 'date') {
        return;
      }
      const value = map[key];
      // A binary value as its printable characters, each other byte a dot:
      // a google.rpc.Status reads as its type URL and its reason.
      out[key] = Buffer.isBuffer(value)
        ? value.toString('latin1').replace(/[^\x20-\x7e]/g, '.') : value;
    });
    return out;
  };

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const config = require(ROOT + '/common/config');
    const realms = require(ROOT + '/common/realms');
    const server = require(ROOT + '/spiffe/spiffe_server');
    const rpc = require(ROOT + '/spiffe/spiffe_grpc');
    const ca = require(ROOT + '/spiffe/spiffe_ca');
    const registry = require(ROOT + '/spiffe/spiffe_registry');
    const spiffeIdLib = require(ROOT + '/spiffe/spiffe_id');
    const x509 = require(ROOT + '/common/crypto_impl/x509.js');
    const grpc = rpc.grpc;

    // The default realm binds nothing in this run.
    config.setOverride('spiffe.workloadPort', 0);
    config.setOverride('spiffe.serverPort', 0);
    config.setOverride('spiffe.brokerPort', 0);
    config.setOverride('spiffe.workloadSocketEnabled', false);
    config.setOverride('spiffe.serverSocketEnabled', false);

    const brokerPort = await freePort();
    const WORKLOAD_SOCKET = path.join(SOCKETS, 'workload', 'api.sock');
    // A directory the service creates, 0700, which is what makes the socket
    // the trusted `local` entity in product (#104).
    const SERVER_SOCKET = path.join(SOCKETS, 'server', 'api.sock');
    const made = realms.get(REALM) ? { ok: true } : realms.create({
      id: REALM, name: REALM, overrides: {
        'spiffe.trustDomain': TRUST_DOMAIN,
        'spiffe.workloadPort': 0, 'spiffe.serverPort': 0,
        'spiffe.brokerPort': brokerPort,
        'spiffe.grpcHost': '127.0.0.1',
        'spiffe.workloadSocket': WORKLOAD_SOCKET,
        'spiffe.serverSocket': SERVER_SOCKET,
        'spiffe.workloadSocketEnabled': true,
        'spiffe.serverSocketEnabled': true } });
    if (!made.ok) {
      throw new Error('realm: ' + (made.errors || []).join(' '));
    }
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

    const httpServer = http.createServer(app);
    await new Promise(function (r) {
      httpServer.listen(0, '127.0.0.1', r);
    });
    const httpGet = function (urlPath) {
      return new Promise(function (resolve) {
        http.get({ host: '127.0.0.1', port: httpServer.address().port,
                   path: urlPath }, function (res) {
          let text = '';
          res.setEncoding('utf8');
          res.on('data', function (c) {
            text += c;
          });
          res.on('end', function () {
            let body = text;
            try {
              body = JSON.parse(text);
            } catch (e) {
              body = text.slice(0, 200);
            }
            const headers = {};
            ['cache-control', 'content-type'].forEach(function (name) {
              headers[name] = res.headers[name];
            });
            resolve({ status: res.statusCode, headers: headers,
                      body: body });
          });
        }).on('error', function (e) {
          resolve({ status: 0, error: e.message });
        });
      });
    };

    await server.listen().whenReady;
    set('spiffe.enabled', true);
    await server.reconcile();
    await inRealm(function () {
      return ca.ready();
    });
    const td = inRealm(function () {
      return ca.trustDomain();
    });
    const id = function (p) {
      return spiffeIdLib.make(td, p);
    };
    const SERVER_ID = spiffeIdLib.serverId(td);
    const anchors = inRealm(function () {
      return ca.state().trustAnchors.map(function (a) {
        return a.certificatePem;
      }).join('\n');
    });
    const anchorDer = Buffer.from(String(anchors)
      .split('-----END CERTIFICATE-----')[0]
      .replace(/-----BEGIN CERTIFICATE-----/, '')
      .replace(/\s+/g, ''), 'base64');
    const uid = process.getuid();

    // ---- the clients -------------------------------------------------------
    const client = function (service, address, creds) {
      const Ctor = grpc.makeGenericClientConstructor(rpc.SERVICES[service],
                                                     service);
      return new Ctor(address, creds || grpc.credentials.createInsecure(),
                      { 'grpc.use_local_subchannel_pool': 1 });
    };
    const workloadHeader = function () {
      const md = new grpc.Metadata();
      md.set('workload.spiffe.io', 'true');
      return md;
    };
    const brokerHeader = function () {
      const md = new grpc.Metadata();
      md.set('broker.spiffe.io', 'true');
      return md;
    };
    const unary = function (c, method, request, metadata) {
      return new Promise(function (resolve) {
        let reply = null;
        let error = null;
        const call = c[method](request, metadata || new grpc.Metadata(),
                               { deadline: Date.now() + 30000 },
                               function (err, answer) {
          error = err;
          reply = answer;
        });
        call.on('status', function (s) {
          setImmediate(function () {
            resolve({ code: s.code, details: s.details,
                      trailers: trailers(s.metadata),
                      messages: error ? [] : [plain(reply)] });
          });
        });
      });
    };
    // A server stream's FIRST message, then a cancel: the stream stays open
    // and re-sends on rotation, which is not this record's subject.
    const first = function (c, method, request, metadata) {
      return new Promise(function (resolve) {
        const stream = c[method](request, metadata || new grpc.Metadata());
        let done = false;
        stream.on('data', function (message) {
          if (!done) {
            done = true;
            resolve({ code: 0, details: '(first message)', trailers: {},
                      messages: [plain(message)] });
            stream.cancel();
          }
        });
        stream.on('error', function (err) {
          if (!done) {
            done = true;
            resolve({ code: err.code, details: err.details,
                      trailers: trailers(err.metadata), messages: [] });
          }
        });
        stream.on('status', function () {
          // ends after the error or the cancel
        });
      });
    };
    // A bidirectional stream with one message and a half-close.
    const bidi = function (c, method, request) {
      return new Promise(function (resolve) {
        const stream = c[method](new grpc.Metadata());
        const messages = [];
        let error = null;
        stream.on('data', function (message) {
          messages.push(plain(message));
        });
        stream.on('error', function (err) {
          error = err;
        });
        stream.on('status', function (s) {
          setImmediate(function () {
            resolve({ code: s.code, details: s.details,
                      trailers: trailers(s.metadata),
                      messages: error ? [] : messages });
          });
        });
        stream.write(request);
        stream.end();
      });
    };

    const note = function (mode, step, service, method, answer) {
      record.wire.push(Object.assign({ mode: mode, step: step,
                                       service: service, method: method },
                                     answer));
    };

    const csrFor = async function (subjectAltName) {
      const pair = nodeCrypto.generateKeyPairSync('ec',
                                                  { namedCurve: 'P-256' });
      const csr = await x509.certificationRequest({
        subject: 'CN=wire-probe',
        publicKeyPem: pair.publicKey.export({ type: 'spki', format: 'pem' }),
        privateKeyPem: pair.privateKey.export({ type: 'pkcs8',
                                                format: 'pem' }),
        subjectAltName: subjectAltName });
      return Buffer.from(csr.der);
    };
    const proto = function (spiffeId) {
      return spiffeIdLib.toProto(spiffeId);
    };

    const PID_URL = 'type.googleapis.com/spiffe.broker.WorkloadPIDReference';
    const varint = function (n) {
      const out = [];
      let v = n;
      while (v > 0x7f) {
        out.push((v & 0x7f) | 0x80);
        v = Math.floor(v / 128);
      }
      out.push(v);
      return Buffer.from(out);
    };
    const pidRef = function (pid) {
      return { reference: { type_url: PID_URL,
                            value: Buffer.concat([varint(1 << 3),
                                                  varint(pid)]) } };
    };

    const conversation = async function (mode) {
      set('global.mode', mode);
      const tag = mode === 'product' ? '/p' : '/d';
      const entries = [];
      const entry = function (rec) {
        const r = inRealm(function () {
          return registry.createEntry(Object.assign({ parentId: SERVER_ID },
                                                    rec), 'test', td, '');
        });
        if (!r.ok) {
          record.problems.push(mode + ' entry ' + rec.spiffeId + ': ' +
                               (r.errors || []).join(' '));
        } else {
          entries.push(r.id);
        }
        return r;
      };
      entry({ spiffeId: id(tag + '/workload'),
              selectors: [{ type: 'unix', value: 'uid:' + uid }],
              hint: 'wire' });

      // ---- the bundle endpoint, over HTTP ----------------------------------
      note(mode, 'the bundle endpoint', 'http', 'GET /spiffe/bundle',
           plain(await httpGet('/realm/' + REALM + '/spiffe/bundle')));

      // ---- the Workload API, on the realm's Unix socket ------------------
      const w = client('workload', 'unix://' + WORKLOAD_SOCKET);
      note(mode, 'an X509-SVID', 'workload', 'FetchX509SVID',
           await first(w, 'FetchX509SVID', {}, workloadHeader()));
      note(mode, 'the X.509 bundles', 'workload', 'FetchX509Bundles',
           await first(w, 'FetchX509Bundles', {}, workloadHeader()));
      const jwt = await unary(w, 'FetchJWTSVID',
                              { audience: ['urn:wire:one', 'urn:wire:two'] },
                              workloadHeader());
      note(mode, 'a JWT-SVID', 'workload', 'FetchJWTSVID', jwt);
      note(mode, 'a JWT-SVID for a named id', 'workload', 'FetchJWTSVID',
           await unary(w, 'FetchJWTSVID',
                       { audience: ['urn:wire:one'],
                         spiffe_id: id(tag + '/workload') },
                       workloadHeader()));
      note(mode, 'no audience', 'workload', 'FetchJWTSVID',
           await unary(w, 'FetchJWTSVID', { audience: [] },
                       workloadHeader()));
      note(mode, 'a blank audience', 'workload', 'FetchJWTSVID',
           await unary(w, 'FetchJWTSVID', { audience: ['  '] },
                       workloadHeader()));
      const badIds = ['not-an-id', 'spiffe://UPPER.example/x',
                      'spiffe://a.test/x/', 'spiffe://a.test/./x',
                      'spiffe://a.test:80/x', 'spiffe://u@a.test/x',
                      'spiffe://a.test/x?q=1', 'spiffe://a.test/%41',
                      'spiffe://a.test/x$y', 'spiffe:///x',
                      'spiffe://a!b.test/x',
                      'spiffe://' + 'a'.repeat(256) + '/x',
                      'spiffe://a.test/' + 'b'.repeat(2048)];
      for (let i = 0; i < badIds.length; i++) {
        note(mode, 'a malformed spiffe_id (' + i + ')', 'workload',
             'FetchJWTSVID',
             await unary(w, 'FetchJWTSVID',
                         { audience: ['urn:wire:one'],
                           spiffe_id: badIds[i] }, workloadHeader()));
      }
      note(mode, 'an id the caller is not entitled to', 'workload',
           'FetchJWTSVID',
           await unary(w, 'FetchJWTSVID',
                       { audience: ['urn:wire:one'],
                         spiffe_id: id('/nobody') }, workloadHeader()));
      note(mode, 'no security header', 'workload', 'FetchJWTSVID',
           await unary(w, 'FetchJWTSVID', { audience: ['urn:wire:one'] }));
      note(mode, 'the JWT bundles', 'workload', 'FetchJWTBundles',
           await first(w, 'FetchJWTBundles', {}, workloadHeader()));
      // The token itself, unnormalised, for ValidateJWTSVID.
      const raw = await new Promise(function (resolve) {
        w.FetchJWTSVID({ audience: ['urn:wire:one'] }, workloadHeader(),
                       function (err, reply) {
          resolve(err ? '' : ((reply.svids || [])[0] || {}).svid || '');
        });
      });
      note(mode, 'a JWT-SVID validated', 'workload', 'ValidateJWTSVID',
           await unary(w, 'ValidateJWTSVID',
                       { audience: 'urn:wire:one', svid: raw },
                       workloadHeader()));
      note(mode, 'the wrong audience', 'workload', 'ValidateJWTSVID',
           await unary(w, 'ValidateJWTSVID',
                       { audience: 'urn:wire:other', svid: raw },
                       workloadHeader()));
      note(mode, 'no audience to validate', 'workload', 'ValidateJWTSVID',
           await unary(w, 'ValidateJWTSVID', { audience: '', svid: raw },
                       workloadHeader()));
      note(mode, 'no token to validate', 'workload', 'ValidateJWTSVID',
           await unary(w, 'ValidateJWTSVID',
                       { audience: 'urn:wire:one', svid: '' },
                       workloadHeader()));
      note(mode, 'a token that is not a JWT', 'workload', 'ValidateJWTSVID',
           await unary(w, 'ValidateJWTSVID',
                       { audience: 'urn:wire:one', svid: 'not.a.jwt' },
                       workloadHeader()));
      const parts = raw.split('.');
      const forged = parts.length === 3
        ? parts[0] + '.' + parts[1] + '.' +
          Buffer.from('forged').toString('base64url')
        : 'x';
      note(mode, 'a bad signature', 'workload', 'ValidateJWTSVID',
           await unary(w, 'ValidateJWTSVID',
                       { audience: 'urn:wire:one', svid: forged },
                       workloadHeader()));
      note(mode, 'a WIT-SVID', 'workload', 'FetchWITSVID',
           await first(w, 'FetchWITSVID', {}, workloadHeader()));
      // Development's loosening switches: no header required, an entry
      // invented for a caller nothing selects. Product answers the default
      // whatever is stored (#104, #181).
      if (mode === 'development') {
        set('spiffe.requireSecurityHeader', false);
        note(mode, 'no security header, the requirement off', 'workload',
             'FetchJWTSVID',
             await unary(w, 'FetchJWTSVID', { audience: ['urn:wire:one'] }));
        set('spiffe.requireSecurityHeader', true);
      }
      inRealm(function () {
        entries.forEach(function (one) {
          registry.deleteEntry(one, 'test');
        });
      });
      entries.length = 0;
      set('spiffe.autoCreateEntries', false);
      note(mode, 'a caller nothing selects, invention off', 'workload',
           'FetchJWTSVID',
           await unary(w, 'FetchJWTSVID', { audience: ['urn:wire:one'] },
                       workloadHeader()));
      note(mode, 'an X509-SVID for a caller nothing selects', 'workload',
           'FetchX509SVID',
           await first(w, 'FetchX509SVID', {}, workloadHeader()));
      set('spiffe.autoCreateEntries', true);
      note(mode, 'a caller nothing selects, invention on', 'workload',
           'FetchJWTSVID',
           await unary(w, 'FetchJWTSVID', { audience: ['urn:wire:one'] },
                       workloadHeader()));
      inRealm(function () {
        registry.allEntries().filter(function (one) {
          return one.spiffeId === id('/workload') ||
            /\/workload$/.test(one.spiffeId);
        }).forEach(function (one) {
          registry.deleteEntry(one.id, 'test');
        });
      });
      entry({ spiffeId: id(tag + '/workload'),
              selectors: [{ type: 'unix', value: 'uid:' + uid }],
              hint: 'wire' });

      // ---- the SPIRE Server API, on the realm's private Unix socket --------
      const address = 'unix://' + SERVER_SOCKET;
      const entry1 = client('entry', address);
      const agent1 = client('agent', address);
      const bundle1 = client('bundle', address);
      const svid1 = client('svid', address);
      const tdc = client('trustdomain', address);
      const debug1 = client('debug', address);

      note(mode, 'the bundle', 'bundle', 'GetBundle',
           await unary(bundle1, 'GetBundle', {}));
      note(mode, 'the bundle count', 'bundle', 'CountBundles',
           await unary(bundle1, 'CountBundles', {}));
      const fed = 'federated' + tag.slice(1) + '.example.test';
      note(mode, 'a federated bundle created', 'bundle',
           'BatchCreateFederatedBundle',
           await unary(bundle1, 'BatchCreateFederatedBundle', {
             bundle: [{ trust_domain: fed,
                        x509_authorities: [{ asn1: anchorDer }],
                        refresh_hint: 300, sequence_number: 1 },
                      { trust_domain: td,
                        x509_authorities: [{ asn1: anchorDer }] },
                      { trust_domain: 'Not A Domain',
                        x509_authorities: [{ asn1: anchorDer }] }] }));
      note(mode, 'the federated bundles', 'bundle', 'ListFederatedBundles',
           await unary(bundle1, 'ListFederatedBundles', {}));
      note(mode, 'one federated bundle', 'bundle', 'GetFederatedBundle',
           await unary(bundle1, 'GetFederatedBundle', { trust_domain: fed }));
      note(mode, 'a federated bundle nobody created', 'bundle',
           'GetFederatedBundle',
           await unary(bundle1, 'GetFederatedBundle',
                       { trust_domain: 'nobody.example.test' }));
      note(mode, 'federated bundles deleted', 'bundle',
           'BatchDeleteFederatedBundle',
           await unary(bundle1, 'BatchDeleteFederatedBundle',
                       { trust_domains: [fed, 'nobody.example.test'] }));
      note(mode, 'a WIT authority', 'bundle', 'PublishWITAuthority',
           await unary(bundle1, 'PublishWITAuthority', {}));

      const created = await unary(entry1, 'BatchCreateEntry', {
        entries: [{ spiffe_id: proto(id(tag + '/created')),
                    parent_id: proto(SERVER_ID),
                    selectors: [{ type: 'unix', value: 'uid:4242' }],
                    x509_svid_ttl: 600, hint: 'made' },
                  { spiffe_id: { trust_domain: td, path: '/spire/reserved' },
                    parent_id: proto(SERVER_ID),
                    selectors: [{ type: 'unix', value: 'uid:1' }] },
                  { spiffe_id: { trust_domain: 'other.example.test',
                                 path: '/x' },
                    parent_id: proto(SERVER_ID),
                    selectors: [{ type: 'unix', value: 'uid:1' }] },
                  { spiffe_id: proto(id(tag + '/no-selectors')),
                    parent_id: proto(SERVER_ID), selectors: [] }] });
      note(mode, 'entries created', 'entry', 'BatchCreateEntry', created);
      const createdId = await new Promise(function (resolve) {
        entry1.ListEntries({ filter: { by_spiffe_id:
                                         proto(id(tag + '/created')) } },
                           function (err, reply) {
          resolve(err ? '' : (((reply.entries || [])[0]) || {}).id || '');
        });
      });
      note(mode, 'the entry count', 'entry', 'CountEntries',
           await unary(entry1, 'CountEntries', {}));
      note(mode, 'the entries, by SPIFFE ID', 'entry', 'ListEntries',
           await unary(entry1, 'ListEntries',
                       { filter: { by_spiffe_id:
                                     proto(id(tag + '/created')) } }));
      note(mode, 'the entries, by selector', 'entry', 'ListEntries',
           await unary(entry1, 'ListEntries',
                       { filter: { by_selectors: {
                         selectors: [{ type: 'unix', value: 'uid:4242' }],
                         match: 'MATCH_EXACT' } } }));
      note(mode, 'one entry', 'entry', 'GetEntry',
           await unary(entry1, 'GetEntry', { id: createdId }));
      note(mode, 'an entry nobody created', 'entry', 'GetEntry',
           await unary(entry1, 'GetEntry', { id: 'no-such-entry' }));
      note(mode, 'an entry updated', 'entry', 'BatchUpdateEntry',
           await unary(entry1, 'BatchUpdateEntry', {
             entries: [{ id: createdId, hint: 'changed',
                         x509_svid_ttl: 900 },
                       { id: 'no-such-entry', hint: 'x' }],
             input_mask: { hint: true, x509_svid_ttl: true } }));
      note(mode, 'entries deleted', 'entry', 'BatchDeleteEntry',
           await unary(entry1, 'BatchDeleteEntry',
                       { ids: [createdId, 'no-such-entry'] }));

      const joined = await unary(agent1, 'CreateJoinToken', { ttl: 600 });
      note(mode, 'a join token', 'agent', 'CreateJoinToken', joined);
      note(mode, 'a join token with no lifetime', 'agent', 'CreateJoinToken',
           await unary(agent1, 'CreateJoinToken', { ttl: 0 }));
      const joinToken = await new Promise(function (resolve) {
        agent1.CreateJoinToken({ ttl: 600 }, function (err, reply) {
          resolve(err ? '' : reply.value);
        });
      });
      note(mode, 'an agent attested', 'agent', 'AttestAgent',
           await bidi(agent1, 'AttestAgent', { params: {
             data: { type: 'join_token',
                     payload: Buffer.from(joinToken, 'utf8') },
             params: { csr: await csrFor() } } }));
      note(mode, 'a spent join token', 'agent', 'AttestAgent',
           await bidi(agent1, 'AttestAgent', { params: {
             data: { type: 'join_token',
                     payload: Buffer.from(joinToken, 'utf8') },
             params: { csr: await csrFor() } } }));
      note(mode, 'an attestation with no type', 'agent', 'AttestAgent',
           await bidi(agent1, 'AttestAgent', { params: {
             data: { type: '', payload: Buffer.from('x') },
             params: { csr: await csrFor() } } }));
      note(mode, 'an attestor nobody configured', 'agent', 'AttestAgent',
           await bidi(agent1, 'AttestAgent', { params: {
             data: { type: 'aws_iid', payload: Buffer.from('x') },
             params: { csr: await csrFor() } } }));
      note(mode, 'an attestation with no CSR', 'agent', 'AttestAgent',
           await bidi(agent1, 'AttestAgent', { params: {
             data: { type: 'join_token', payload: Buffer.from('x') },
             params: {} } }));
      note(mode, 'a challenge response nobody asked for', 'agent',
           'AttestAgent',
           await bidi(agent1, 'AttestAgent',
                      { challenge_response: Buffer.from('x') }));
      note(mode, 'the agent count', 'agent', 'CountAgents',
           await unary(agent1, 'CountAgents', {}));
      note(mode, 'the agents', 'agent', 'ListAgents',
           await unary(agent1, 'ListAgents', {}));
      note(mode, 'an agent nobody attested', 'agent', 'GetAgent',
           await unary(agent1, 'GetAgent',
                       { id: proto(id('/spire/agent/none/x')) }));
      note(mode, 'a renewal on the local socket', 'agent', 'RenewAgent',
           await unary(agent1, 'RenewAgent',
                       { params: { csr: await csrFor() } }));
      note(mode, 'a renewal with no CSR', 'agent', 'RenewAgent',
           await unary(agent1, 'RenewAgent', { params: {} }));

      note(mode, 'an X509-SVID minted', 'svid', 'MintX509SVID',
           await unary(svid1, 'MintX509SVID', {
             csr: await csrFor([{ kind: 'uri', value: id(tag + '/minted') }]),
             ttl: 300 }));
      note(mode, 'an X509-SVID with no CSR', 'svid', 'MintX509SVID',
           await unary(svid1, 'MintX509SVID', {}));
      note(mode, 'an X509-SVID with no SPIFFE ID', 'svid', 'MintX509SVID',
           await unary(svid1, 'MintX509SVID', { csr: await csrFor() }));
      note(mode, 'a JWT-SVID minted', 'svid', 'MintJWTSVID',
           await unary(svid1, 'MintJWTSVID', { id: proto(id(tag + '/jwt')),
                                               audience: ['urn:wire:mint'],
                                               ttl: 300 }));
      note(mode, 'a JWT-SVID with no id', 'svid', 'MintJWTSVID',
           await unary(svid1, 'MintJWTSVID', { audience: ['urn:wire:mint'] }));
      note(mode, 'a JWT-SVID with no audience', 'svid', 'MintJWTSVID',
           await unary(svid1, 'MintJWTSVID', { id: proto(id(tag + '/jwt')) }));
      note(mode, 'a WIT-SVID minted', 'svid', 'MintWITSVID',
           await unary(svid1, 'MintWITSVID', {}));

      note(mode, 'the federation relationships', 'trustdomain',
           'ListFederationRelationships',
           await unary(tdc, 'ListFederationRelationships', {}));
      note(mode, 'a bundle refreshed', 'trustdomain', 'RefreshBundle',
           await unary(tdc, 'RefreshBundle',
                       { trust_domain: 'federated.example.test' }));
      note(mode, 'the server\'s information', 'debug', 'GetInfo',
           await unary(debug1, 'GetInfo', {}));

      [w, entry1, agent1, bundle1, svid1, tdc, debug1].forEach(function (c) {
        c.close();
      });

      // ---- the Broker API, on the realm's mutual-TLS port ----------------
      const mint = function (p) {
        return inRealm(function () {
          return ca.mintX509Svid(id(p), { ttl: 600 });
        });
      };
      const brokerSvid = await mint(tag + '/broker');
      const strangerSvid = await mint(tag + '/stranger');
      inRealm(function () {
        return require(ROOT + '/admin-core/admin_actions')
          .spiffeBrokersAction({ action: 'set', id: id(tag + '/broker'),
                                 referenceTypes: 'pid' });
      });
      const verify = { checkServerIdentity: function (host, cert) {
        return String(cert.subjectaltname || '').indexOf('URI:' +
                                                          SERVER_ID) >= 0
          ? undefined : new Error('not ' + SERVER_ID);
      } };
      const connect = function (svid) {
        const creds = svid
          ? grpc.credentials.createSsl(Buffer.from(anchors),
              Buffer.from(svid.privateKeyPem),
              Buffer.from(svid.chainPem.join('\n')), verify)
          : grpc.credentials.createSsl(Buffer.from(anchors), null, null,
                                       verify);
        return client('broker', '127.0.0.1:' + brokerPort, creds);
      };
      const b = connect(brokerSvid);
      note(mode, 'no broker header', 'broker', 'FetchJWTSVID',
           await unary(b, 'FetchJWTSVID',
                       { reference: pidRef(process.pid),
                         audience: ['urn:wire:broker'] }));
      const anonymous = connect(null);
      note(mode, 'no client certificate', 'broker', 'FetchJWTSVID',
           await unary(anonymous, 'FetchJWTSVID',
                       { reference: pidRef(process.pid),
                         audience: ['urn:wire:broker'] }, brokerHeader()));
      anonymous.close();
      const stranger = connect(strangerSvid);
      note(mode, 'a caller that is no broker', 'broker', 'FetchJWTSVID',
           await unary(stranger, 'FetchJWTSVID',
                       { reference: pidRef(process.pid),
                         audience: ['urn:wire:broker'] }, brokerHeader()));
      stranger.close();
      note(mode, 'a JWT-SVID for a pid', 'broker', 'FetchJWTSVID',
           await unary(b, 'FetchJWTSVID',
                       { reference: pidRef(process.pid),
                         audience: ['urn:wire:broker'] }, brokerHeader()));
      note(mode, 'no audience for a pid', 'broker', 'FetchJWTSVID',
           await unary(b, 'FetchJWTSVID',
                       { reference: pidRef(process.pid), audience: [] },
                       brokerHeader()));
      note(mode, 'a malformed spiffe_id for a pid', 'broker', 'FetchJWTSVID',
           await unary(b, 'FetchJWTSVID',
                       { reference: pidRef(process.pid),
                         audience: ['urn:wire:broker'],
                         spiffe_id: 'not-an-id' }, brokerHeader()));
      note(mode, 'no reference', 'broker', 'FetchJWTSVID',
           await unary(b, 'FetchJWTSVID',
                       { audience: ['urn:wire:broker'] }, brokerHeader()));
      note(mode, 'a reference of an unknown type', 'broker', 'FetchJWTSVID',
           await unary(b, 'FetchJWTSVID',
                       { reference: { reference: {
                         type_url: 'type.example/x',
                         value: Buffer.from('x') } },
                         audience: ['urn:wire:broker'] }, brokerHeader()));
      note(mode, 'an X509-SVID for a pid', 'broker', 'SubscribeToX509SVID',
           await first(b, 'SubscribeToX509SVID',
                       { reference: pidRef(process.pid) }, brokerHeader()));
      note(mode, 'the X.509 bundles for a pid', 'broker',
           'SubscribeToX509Bundles',
           await first(b, 'SubscribeToX509Bundles',
                       { reference: pidRef(process.pid) }, brokerHeader()));
      note(mode, 'the JWT bundles for a pid', 'broker',
           'SubscribeToJWTBundles',
           await first(b, 'SubscribeToJWTBundles',
                       { reference: pidRef(process.pid) }, brokerHeader()));
      b.close();
      inRealm(function () {
        require(ROOT + '/admin-core/admin_actions')
          .spiffeBrokersAction({ action: 'delete', id: id(tag + '/broker') });
        entries.forEach(function (one) {
          registry.deleteEntry(one, 'test');
        });
      });
    };

    for (const mode of ['development', 'product']) {
      try {
        await conversation(mode);
      } catch (e) {
        record.problems.push(mode + ': ' + (e && e.stack));
      }
    }
    try {
      const SpiffeModel = require(ROOT + '/spiffe/spiffe_model');
      record.gaps = SpiffeModel.gaps();
    } catch (e) {
      record.gaps = [];
    }
    set('global.mode', 'development');
    set('spiffe.enabled', false);
    await server.reconcile();
    httpServer.close();
    fs.writeFileSync(OUT, JSON.stringify(record));
    process.exit(0);
  })().catch(function (e) {
    record.problems.push('threw: ' + (e && e.stack));
    fs.writeFileSync(OUT, JSON.stringify(record));
    process.exit(0);
  });
}

// Replaces what differs from run to run with a placeholder.
function normalise(record) {
  log.debug("Entering normalise().");
  const VOLATILE = ['exp', 'iat', 'nbf', 'jti', 'expires_at', 'created_at',
                    'expiresAt', 'x', 'y', 'n', 'kid', 'lifetime',
                    'revision_number', 'value', 'agentSpiffeId', 'key_id',
                    'uptime'];
  const scrub = function (value, key) {
    if (Array.isArray(value)) {
      const items = value.map(function (one) {
        return scrub(one, key);
      });
      // A listing's order is the store's, by an id that is random.
      if (['entries', 'agents', 'bundles'].indexOf(key) >= 0) {
        items.sort(function (a, b) {
          return JSON.stringify(a) < JSON.stringify(b) ? -1 : 1;
        });
      }
      return items;
    }
    // A claim of a google.protobuf.Struct is an object: `jti` is
    // `{ stringValue }`.
    if (value && typeof value === 'object' &&
        ['jti', 'exp', 'iat', 'nbf'].indexOf(key) >= 0) {
      return '<' + key + '>';
    }
    if (value && typeof value === 'object') {
      const out = {};
      Object.keys(value).forEach(function (k) {
        out[k] = scrub(value[k], k);
      });
      return out;
    }
    // An uptime is seconds since start, which may be zero.
    if (key === 'uptime') {
      return '<uptime>';
    }
    if (typeof value === 'number' && /^1[789]\d{8}$/.test(String(value))) {
      return '<epoch>';
    }
    if (VOLATILE.indexOf(key) >= 0 && value !== '' && value !== 0 &&
        value !== null && value !== undefined && typeof value !== 'boolean') {
      // A join token's value and a selector's value share the name; a
      // selector's value is kept unless it is a digest.
      if (key === 'value' && !/^[0-9a-f-]{32,}$/.test(String(value))) {
        return value;
      }
      return '<' + key + '>';
    }
    return value;
  };
  const PATTERNS = [
    ['uuid', /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi],
    ['time', /\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z/g],
    ['port', /127\.0\.0\.1(:|%3A)\d+/g],
    ['epoch', /\b1[789]\d{8}\b/g],
    ['socket', /\/tmp\/sts-spiffe-wire-[A-Za-z0-9]+/g],
    ['uid', /uid:\d+(?!\d)/g],
    ['pid', /\bpid:? ?\d+\b/g],
    ['version', /\b\d+\.\d+\.\d+\.\d{14}\b/g],
    ['digest', /\b[0-9a-f]{16,}\b/g],
    ['token-sha256', /token-sha256:[0-9a-f<>a-z]+/g],
    ['random', /(?<![A-Za-z0-9_-])(?=[A-Za-z0-9_-]*[A-Z])(?=[A-Za-z0-9_-]*[0-9])[A-Za-z0-9_-]{24,}/g]
  ];
  const text = JSON.stringify(scrub(record, ''), null, 1);
  let out = text;
  PATTERNS.forEach(function (pair) {
    out = out.replace(pair[1], '<' + pair[0] + '>');
  });
  log.debug("Leaving normalise().");
  return JSON.parse(out);
}

// Runs the child and answers its record, normalised, or null.
function capture() {
  log.debug("Entering capture().");
  const out = path.join(os.tmpdir(), 'spiffe-model-wire-' + process.pid +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|SPIFFE_|LDAP_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', SW_ROOT: ROOT, SW_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let record = null;
  try {
    record = JSON.parse(fs.readFileSync(out, 'utf8'));
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in capture(): " + ((e && e.message) || e));
    log.debug("Leaving capture(). No record: exit " + result.status + " " +
              String(result.stderr || '').slice(-800));
    return null;
  }
  log.debug("Leaving capture().");
  return normalise(record);
}

// The first place two values differ, as a dotted path, or null.
function firstDifference(a, b, where) {
  log.debug("Entering firstDifference().");
  if (JSON.stringify(a) === JSON.stringify(b)) {
    log.debug("Leaving firstDifference(). Equal.");
    return null;
  }
  if (a && b && typeof a === 'object' && typeof b === 'object') {
    const keys = Array.from(new Set(Object.keys(a).concat(Object.keys(b))));
    for (let i = 0; i < keys.length; i++) {
      const inner = firstDifference(a[keys[i]], b[keys[i]],
                                    where + '.' + keys[i]);
      if (inner) {
        log.debug("Leaving firstDifference().");
        return inner;
      }
    }
  }
  log.debug("Leaving firstDifference().");
  return where + ': ' + JSON.stringify(b).slice(0, 300) + ' where ' +
    JSON.stringify(a).slice(0, 300) + ' was recorded';
}

function run(t) {
  log.debug("Entering run().");
  const now = capture();
  if (!t.check(!!now, 'the child process reported')) {
    log.debug("Leaving run().");
    return;
  }
  t.check(now.problems.length === 0, 'the child ran to the end',
          now.problems.join('\n'));
  t.check(Array.isArray(now.gaps) && now.gaps.length === 0,
          'every answer of the conversation is its model\'s ' +
          '(models/spiffe/*.tsp; none recorded under STS-SPIFFE-0154/0155)',
          JSON.stringify(now.gaps).slice(0, 2000));
  let recorded = null;
  try {
    recorded = JSON.parse(fs.readFileSync(SNAPSHOT, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    recorded = null;
  }
  if (!t.check(!!recorded, 'the recorded wire is in the tree', SNAPSHOT)) {
    log.debug("Leaving run().");
    return;
  }
  t.check(recorded.wire.length === now.wire.length,
          'the conversation has as many steps as recorded',
          now.wire.length + ' vs ' + recorded.wire.length);
  recorded.wire.forEach(function (one, i) {
    t.check(firstDifference(one, now.wire[i], 'wire') === null,
            one.mode + ', ' + one.step + ': ' + one.service + '.' +
            one.method + ' answers as recorded (' + one.code + ')',
            firstDifference(one, now.wire[i], 'wire'));
  });
  log.debug("Leaving run().");
}

if (require.main === module && process.env.SPIFFE_WIRE_PRINT) {
  process.stdout.write(JSON.stringify(capture(), null, 1) + '\n');
}

module.exports = {
  name: 'spiffe_model_wire',
  describe: 'what the SPIFFE endpoints answer, against the record made ' +
            'before their messages, the SPIFFE ID grammar, the bundle and ' +
            'the SVID facts came from the model (#1579): the bundle ' +
            'endpoint, the Workload API, the SPIRE Server API and the ' +
            'Broker API over real gRPC on a realm\'s own sockets, their ' +
            'answers and refusals, in development and product mode',
  run: run
};
