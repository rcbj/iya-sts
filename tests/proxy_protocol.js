'use strict';
//
// File: proxy_protocol.js
//
// ===========================================================================
// THE PROXY PROTOCOL V2 READER (2026-09-14, #46), IN PROCESS.
//
// `common/proxy_protocol.ts` takes a binary header off the front of every TCP
// connection BEFORE the listener — TLS included — sees a byte, and puts the
// client address it names on the socket. Four claims are held here:
//
//   1. **The parser reads the specification exactly**: IPv4, IPv6 and LOCAL;
//      TLVs read (AWS 0xEA, authority) or ignored; a CRC32C checked; a header
//      split at every byte boundary answered `incomplete` and never wrong;
//      and a bad signature, version 1, a bad version, command, family or
//      transport, a short address block, a TLV past the end and an oversize
//      length each refused with its own code.
//   2. **Who may send one**: a trusted address must, an untrusted address is
//      closed, this host is served plain (and a header it sends is NOT
//      parsed), and a trusted address that is also this host may do either.
//      With nobody trusted the service does not start.
//   3. **The address reaches the readers that already exist**, unchanged:
//      `req.socket.remoteAddress` on http and https, `client_address.js`'s
//      `clientAddressOf()` (what the rate limiter and the request pool read),
//      a plain `net` listener's socket (the KDC's shape), and an ldapjs
//      connection's `remoteAddress` (the bind limiter's).
//   4. **Mutual TLS is unaffected**: a client certificate presented in the
//      handshake that follows the header — coalesced into the same segment —
//      still verifies and still reaches the request.
//
// WHY IN PROCESS: every connection a test opens comes from this host, and
// the remote-peer rules are reachable only by telling the module what counts
// as this host (`setThisHostCheck`). The live probe against a running node,
// from a container on the docker bridge, is in the report of the change.
// ===========================================================================

delete process.env.CONFIG_FILE;

const http = require('http');
const https = require('https');
const net = require('net');
const tls = require('tls');
const nodeCrypto = require('crypto');
const forge = require('node-forge');

const log = require('bunyan').createLogger({ name: 'proxy_protocol',
  level: process.env.LOG_LEVEL || 'info' });

const config = require('../common/config');
const clientAddress = require('../common/client_address');
const proxyProtocol = require('../common/proxy_protocol');

// ---------------------------------------------------------------------------
// A self-signed certificate that is both the server's and the client's, and
// the anchor both sides trust — enough to show `authorized` survives.
// ---------------------------------------------------------------------------
function makeCertificate() {
  log.debug("Entering makeCertificate().");
  const pair = nodeCrypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const keyPem = pair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const publicPem = pair.publicKey.export({ type: 'spki', format: 'pem' });
  const cert = forge.pki.createCertificate();
  cert.publicKey = forge.pki.publicKeyFromPem(publicPem);
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date(Date.now() - 60000);
  cert.validity.notAfter = new Date(Date.now() + 86400000);
  const attrs = [{ name: 'commonName', value: 'localhost' }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([
    { name: 'basicConstraints', cA: true },
    { name: 'keyUsage', digitalSignature: true, keyEncipherment: true,
      keyCertSign: true },
    { name: 'extKeyUsage', serverAuth: true, clientAuth: true },
    { name: 'subjectAltName', altNames: [{ type: 2, value: 'localhost' }] }
  ]);
  cert.sign(forge.pki.privateKeyFromPem(
    pair.privateKey.export({ type: 'pkcs1', format: 'pem' })),
            forge.md.sha256.create());
  log.debug("Leaving makeCertificate().");
  return { key: keyPem, cert: forge.pki.certificateToPem(cert) };
}

// ---------------------------------------------------------------------------
// 1. THE PARSER.
// ---------------------------------------------------------------------------
function checkParser(t) {
  log.debug("Entering checkParser().");
  t.log.info('1. the parser');
  const v4 = proxyProtocol.build({
    source: { address: '203.0.113.7', port: 51000 },
    destination: { address: '10.0.0.5', port: 443 } });
  const one = proxyProtocol.parse(Buffer.concat([v4, Buffer.from('GET')]));
  t.equal(one.state, 'complete', '1a. an IPv4 PROXY header parses');
  t.equal(one.length, 28, '1a. and is 16 + 12 bytes, the bytes after it ' +
          'left alone');
  t.equal(one.header.source.address + ':' + one.header.source.port,
          '203.0.113.7:51000', '1a. the source address and port');
  t.equal(one.header.destination.address + ':' + one.header.destination.port,
          '10.0.0.5:443', '1a. the destination address and port');
  t.equal(one.header.command + '/' + one.header.family + '/' +
          one.header.transport, 'PROXY/INET/STREAM', '1a. command and family');

  const v6 = proxyProtocol.parse(proxyProtocol.build({
    source: { address: '2001:db8:0:0:0:0:0:7', port: 1234 },
    destination: { address: '2001:db8::1', port: 636 } }));
  t.equal(v6.state === 'complete' && v6.header.source.address,
          '2001:db8::7', '1b. an IPv6 header, the address canonicalised the ' +
          'way node reports a peer');
  t.equal(v6.length, 16 + 36, '1b. and the IPv6 block is 36 bytes');

  const local = proxyProtocol.parse(proxyProtocol.build({ command: 'LOCAL' }));
  t.equal(local.state === 'complete' && local.header.command, 'LOCAL',
          '1c. a LOCAL header (a health check) parses');
  t.equal(local.header.source, null, '1c. and names no source');
  // PROXY with the UNSPEC family and no block: the other shape a header
  // "without client connection information" may take (AWS's words).
  const unspec = Buffer.concat([proxyProtocol.SIGNATURE,
                                Buffer.from([0x21, 0x00, 0x00, 0x00])]);
  const unspecParsed = proxyProtocol.parse(unspec);
  t.equal(unspecParsed.state === 'complete' && unspecParsed.header.source,
          null, '1c. PROXY with the UNSPEC family parses and names no source');
  const badTransport = Buffer.from(unspec);
  badTransport[13] = 0x13;
  t.equal(proxyProtocol.parse(badTransport).code, 'STS-PROXY-0004',
          '1c. an unknown transport under PROXY is refused');

  const withTlvs = proxyProtocol.parse(proxyProtocol.build({
    source: { address: '198.51.100.2', port: 9 },
    tlvs: [{ type: 0xEA, value: Buffer.concat([Buffer.from([0x01]),
                                               Buffer.from('vpce-0abc')]) },
           { type: 0x02, value: Buffer.from('idp.example.com') },
           { type: 0x7F, value: Buffer.from('ignored') },
           { type: 0x04, value: Buffer.alloc(5) }],
    crc32c: true }));
  t.equal(withTlvs.state, 'complete',
          '1d. a header with an AWS TLV, an authority, an unknown type, a ' +
          'NOOP and a correct CRC32C parses');
  t.equal(withTlvs.header.awsVpceId, 'vpce-0abc',
          '1d. PP2_TYPE_AWS / PP2_SUBTYPE_AWS_VPCE_ID is read');
  t.equal(withTlvs.header.authority, 'idp.example.com',
          '1d. PP2_TYPE_AUTHORITY is read');
  t.equal(withTlvs.header.tlvs.length, 5,
          '1d. and every TLV, the unknown one included, is carried');

  const corrupted = proxyProtocol.build({
    source: { address: '198.51.100.2', port: 9 }, crc32c: true });
  corrupted[20] ^= 0xFF;
  t.equal(proxyProtocol.parse(corrupted).code, 'STS-PROXY-0006',
          '1e. a header that no longer matches its CRC32C is refused');
  // The published CRC32C check value, so the table is the Castagnoli one.
  t.equal(proxyProtocol.crc32c(Buffer.from('123456789')), 0xE3069283,
          '1e. crc32c("123456789") is the standard check value 0xE3069283');

  let neverWrong = true;
  for (let cut = 0; cut < v4.length; cut++) {
    const part = proxyProtocol.parse(v4.subarray(0, cut));
    if (part.state !== 'incomplete') {
      neverWrong = false;
    }
  }
  t.check(neverWrong, '1f. every prefix of a valid header, at every byte, ' +
          'is incomplete — never invalid, never complete');

  t.equal(proxyProtocol.parse(Buffer.from('GET / HTTP/1.1\r\n')).code,
          'STS-PROXY-0002', '1g. an HTTP request is not a header, at once');
  t.equal(proxyProtocol.parse(Buffer.from([0x16, 0x03, 0x01])).code,
          'STS-PROXY-0002', '1g. nor is a TLS record');
  t.equal(proxyProtocol.parse(Buffer.from('PROX')).state, 'incomplete',
          '1h. four bytes of "PROXY " wait');
  t.equal(proxyProtocol.parse(Buffer.from('PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\n'))
    .code, 'STS-PROXY-0003', '1h. a version 1 line is refused by name');

  const badVersion = Buffer.from(v4);
  badVersion[12] = 0x11;
  t.equal(proxyProtocol.parse(badVersion).code, 'STS-PROXY-0004',
          '1i. version 1 in a v2 signature is refused');
  const badCommand = Buffer.from(v4);
  badCommand[12] = 0x2F;
  t.equal(proxyProtocol.parse(badCommand).code, 'STS-PROXY-0004',
          '1i. an unknown command is refused');
  const badFamily = Buffer.from(v4);
  badFamily[13] = 0x51;
  t.equal(proxyProtocol.parse(badFamily).code, 'STS-PROXY-0004',
          '1i. an unknown address family is refused');
  const shortBlock = proxyProtocol.build({
    source: { address: '203.0.113.7', port: 1 } }).subarray(0, 16 + 8);
  shortBlock.writeUInt16BE(8, 14);
  t.equal(proxyProtocol.parse(shortBlock).code, 'STS-PROXY-0004',
          '1i. an INET header declaring 8 bytes of a 12-byte block is ' +
          'refused');
  const badTlv = Buffer.concat([v4, Buffer.from([0x02, 0x00, 0x09, 0x41])]);
  badTlv.writeUInt16BE(12 + 4, 14);
  t.equal(proxyProtocol.parse(badTlv).code, 'STS-PROXY-0004',
          '1i. a TLV that runs past the declared length is refused');
  const oversize = proxyProtocol.build({
    source: { address: '203.0.113.7', port: 1 },
    declaredLength: proxyProtocol.MAX_BLOCK_LENGTH + 1 });
  t.equal(proxyProtocol.parse(oversize).code, 'STS-PROXY-0005',
          '1j. a declared length over the bound is refused from the first ' +
          '16 bytes, before anything is buffered');
  log.debug("Leaving checkParser().");
}

// ---------------------------------------------------------------------------
// 2. THE SETTING AND THE STARTUP REFUSAL.
// ---------------------------------------------------------------------------
function checkSetting(t) {
  log.debug("Entering checkSetting().");
  t.log.info('2. the setting');
  t.equal(proxyProtocol.enabled(), false, '2a. off by default');
  t.equal(proxyProtocol.install(http.createServer()), false,
          '2a. and install() is then a no-op');
  t.equal(proxyProtocol.startupProblem(), '',
          '2a. and nothing refuses to start');
  process.env.STS_PROXY_PROTOCOL = 'v2';
  try {
    config.clearOverride('global.trustedProxies');
    t.check(/no connection could be believed/.test(
      proxyProtocol.startupProblem()),
            '2b. v2 with global.trustedProxies empty does not start',
            proxyProtocol.startupProblem());
    config.setOverride('global.trustedProxies', 'nonsense');
    t.check(/1 ignored/.test(proxyProtocol.startupProblem()),
            '2b. nor with only entries that are not ranges');
    config.setOverride('global.trustedProxies', '10.0.0.0/8');
    t.equal(proxyProtocol.startupProblem(), '',
            '2c. v2 with a range starts');
  } finally {
    delete process.env.STS_PROXY_PROTOCOL;
    config.clearOverride('global.trustedProxies');
  }
  log.debug("Leaving checkSetting().");
}

// ---------------------------------------------------------------------------
// The socket helpers.
// ---------------------------------------------------------------------------
function listen(server) {
  log.debug("Entering listen().");
  log.debug("Leaving listen().");
  return new Promise(function (resolve) {
    server.listen(0, '127.0.0.1', function () {
      resolve(server.address().port);
    });
  });
}

// Writes `chunks` to a raw connection, `gapMs` apart, and resolves with
// everything that came back and whether the server closed without a byte.
function exchange(port, chunks, gapMs) {
  log.debug("Entering exchange().");
  log.debug("Leaving exchange().");
  return new Promise(function (resolve) {
    let received = '';
    const socket = net.connect(port, '127.0.0.1', function () {
      chunks.forEach(function (chunk, i) {
        setTimeout(function () {
          if (!socket.destroyed) {
            socket.write(chunk);
          }
        }, i * (gapMs || 0));
      });
    });
    socket.on('data', function (d) {
      received += d.toString('latin1');
    });
    socket.on('error', function (e) {
      log.debug("Caught in exchange(): " + ((e && e.message) || e));
    });
    socket.on('close', function () {
      resolve(received);
    });
    setTimeout(function () {
      socket.destroy();
    }, 4000);
  });
}

const REQUEST = 'GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n';

function bodyOf(raw) {
  log.debug("Entering bodyOf().");
  const at = raw.indexOf('\r\n\r\n');
  log.debug("Leaving bodyOf().");
  return at >= 0 ? raw.slice(at + 4) : '';
}

// ---------------------------------------------------------------------------
// 3. ROUND TRIPS THROUGH REAL SERVERS.
// ---------------------------------------------------------------------------
async function checkRoundTrips(t) {
  log.debug("Entering checkRoundTrips().");
  t.log.info('3. round trips');
  const material = makeCertificate();
  const servers = [];
  process.env.STS_PROXY_PROTOCOL = 'v2';
  config.setOverride('global.trustedProxies', '127.0.0.1/32');
  proxyProtocol.reset();
  // Loopback is a REMOTE trusted proxy for 3a–3j: nothing here is this host.
  proxyProtocol.setThisHostCheck(function () {
    return false;
  });
  try {
    const plain = http.createServer(function (req, res) {
      res.end(JSON.stringify({
        remoteAddress: req.socket.remoteAddress,
        remotePort: req.socket.remotePort,
        remoteFamily: req.socket.remoteFamily,
        clientAddress: clientAddress.clientAddressOf(req),
        via: (proxyProtocol.describe(req.socket) || {}).via || null,
        command: (proxyProtocol.describe(req.socket) || {}).command || null
      }));
    });
    servers.push(plain);
    t.equal(proxyProtocol.install(plain, { label: 'test http' }), true,
            '3. install() on an http.Server with v2 on');
    const plainPort = await listen(plain);
    const header = proxyProtocol.build({
      source: { address: '203.0.113.7', port: 51000 },
      destination: { address: '127.0.0.1', port: plainPort } });

    let seen = JSON.parse(bodyOf(await exchange(plainPort,
      [Buffer.concat([header, Buffer.from(REQUEST)])])) || '{}');
    t.equal(seen.remoteAddress + ':' + seen.remotePort, '203.0.113.7:51000',
            '3a. header and request in ONE segment: req.socket.remoteAddress ' +
            'and remotePort are the header\'s');
    t.equal(seen.clientAddress, '203.0.113.7',
            '3a. and client_address.clientAddressOf() — the rate limiter\'s ' +
            'and the request pool\'s reader — says the same');
    t.equal(seen.via, '127.0.0.1', '3a. and describe() keeps the balancer');

    const whole = Buffer.concat([header, Buffer.from(REQUEST)]);
    seen = JSON.parse(bodyOf(await exchange(plainPort,
      [whole.subarray(0, 3), whole.subarray(3, 14), whole.subarray(14, 20),
       whole.subarray(20)], 60)) || '{}');
    t.equal(seen.remoteAddress, '203.0.113.7',
            '3b. the header split across four TCP writes 60ms apart');

    seen = JSON.parse(bodyOf(await exchange(plainPort,
      [proxyProtocol.build({ command: 'LOCAL' }), Buffer.from(REQUEST)], 50)) ||
      '{}');
    t.equal(seen.remoteAddress + ' ' + seen.command, '127.0.0.1 LOCAL',
            '3c. a LOCAL header (a health check) is served with the ' +
            'socket\'s own address');

    let raw = await exchange(plainPort, [Buffer.from(REQUEST)]);
    t.equal(raw, '', '3d. a trusted proxy that sends no header is closed ' +
            'without a byte of HTTP');
    t.equal(proxyProtocol.report().refused['STS-PROXY-0002'], 1,
            '3d. counted as STS-PROXY-0002');

    config.setOverride('global.trustedProxies', '10.9.9.9/32');
    raw = await exchange(plainPort, [Buffer.concat([header,
                                                    Buffer.from(REQUEST)])]);
    t.equal(raw, '', '3e. an address outside global.trustedProxies is ' +
            'closed even with a well-formed header');
    t.equal(proxyProtocol.report().refused['STS-PROXY-0001'], 1,
            '3e. counted as STS-PROXY-0001');
    config.setOverride('global.trustedProxies', '127.0.0.1/32');

    config.setOverride('global.proxyProtocolTimeoutMs', 200);
    raw = await exchange(plainPort, [header.subarray(0, 10)]);
    t.equal(raw, '', '3f. half a header and silence is closed');
    t.equal(proxyProtocol.report().refused['STS-PROXY-0007'], 1,
            '3f. at global.proxyProtocolTimeoutMs, as STS-PROXY-0007');
    config.clearOverride('global.proxyProtocolTimeoutMs');

    raw = await exchange(plainPort, [proxyProtocol.build({
      source: { address: '203.0.113.7', port: 1 },
      declaredLength: 60000 })]);
    t.equal(proxyProtocol.report().refused['STS-PROXY-0005'], 1,
            '3g. a declared 60000-byte block is refused (STS-PROXY-0005)');

    // The KDC's and LDAP's shape: a plain net.Server reading `data`.
    const echo = net.createServer(function (socket) {
      socket.once('data', function (d) {
        socket.end(socket.remoteAddress + ' ' + d.toString());
      });
    });
    servers.push(echo);
    proxyProtocol.install(echo, { label: 'test net' });
    const echoPort = await listen(echo);
    raw = await exchange(echoPort, [Buffer.concat([proxyProtocol.build({
      source: { address: '192.0.2.44', port: 88 } }), Buffer.from('krb')])]);
    t.equal(raw, '192.0.2.44 krb', '3h. a plain net.Server (the KDC\'s ' +
            'shape) reads the bytes after the header and the header\'s ' +
            'address');

    // Mutual TLS behind the header.
    const secure = https.createServer({
      key: material.key, cert: material.cert, ca: [material.cert],
      requestCert: true, rejectUnauthorized: true
    }, function (req, res) {
      const peerCert = req.socket.getPeerCertificate();
      res.end(JSON.stringify({
        remoteAddress: req.socket.remoteAddress,
        remoteFamily: req.socket.remoteFamily,
        authorized: req.socket.authorized,
        cn: peerCert && peerCert.subject ? peerCert.subject.CN : null,
        clientAddress: clientAddress.clientAddressOf(req),
        via: (proxyProtocol.describe(req.socket) || {}).via || null
      }));
    });
    let secureConnectionFrom = null;
    secure.on('secureConnection', function (s) {
      secureConnectionFrom = s.remoteAddress;
    });
    servers.push(secure);
    proxyProtocol.install(secure, { label: 'test https' });
    const securePort = await listen(secure);

    function overTls(source, apart) {
      log.debug("Entering overTls().");
      log.debug("Leaving overTls().");
      return new Promise(function (resolve) {
        const rawSocket = net.connect(securePort, '127.0.0.1', function () {
          // Corked, so the header and the ClientHello leave as ONE segment
          // — the case where the TLS engine is handed bytes that arrived
          // with the header.
          if (apart) {
            // Or the header ALONE, and the handshake 80ms later: the TLS
            // engine is handed a paused socket with nothing buffered.
            rawSocket.write(proxyProtocol.build({ source: source }));
            setTimeout(function () {
              handshake();
            }, 80);
            return;
          }
          rawSocket.cork();
          rawSocket.write(proxyProtocol.build({ source: source }));
          handshake();
          process.nextTick(function () {
            rawSocket.uncork();
          });
        });

        function handshake() {
          log.debug("Entering handshake().");
          const client = tls.connect({ socket: rawSocket, key: material.key,
                                       cert: material.cert,
                                       ca: [material.cert],
                                       servername: 'localhost' },
                                     function () {
            client.write(REQUEST);
          });
          let out = '';
          client.on('data', function (d) {
            out += d.toString();
          });
          client.on('end', function () {
            resolve(JSON.parse(bodyOf(out) || '{}'));
          });
          client.on('error', function (e) {
            log.debug("Caught in overTls(): " + ((e && e.message) || e));
            resolve({ error: e.message });
          });
          log.debug("Leaving handshake().");
        }
      });
    }

    seen = await overTls({ address: '198.51.100.9', port: 6000 });
    t.equal(seen.remoteAddress, '198.51.100.9',
            '3i. HTTPS: the header coalesced with the ClientHello, and the ' +
            'TLS socket\'s remoteAddress is the header\'s',
            JSON.stringify(seen));
    t.equal(seen.authorized === true && seen.cn, 'localhost',
            '3i. and the client certificate still verified and reached the ' +
            'request — mutual TLS is unaffected');
    t.equal(secureConnectionFrom, '198.51.100.9',
            '3i. and `secureConnection` — where tls_server.js records a ' +
            'certificate — saw the same address');
    t.equal(seen.via, '127.0.0.1',
            '3i. describe() finds the header through the TLS socket');
    seen = await overTls({ address: '198.51.100.10', port: 6002 }, true);
    t.equal(seen.remoteAddress + ' ' + seen.authorized, '198.51.100.10 true',
            '3i. and with the header in a segment of its own, the handshake ' +
            'following it, the same', JSON.stringify(seen));
    seen = await overTls({ address: '2001:db8::7', port: 6001 });
    t.equal(seen.remoteAddress + ' ' + seen.remoteFamily, '2001:db8::7 IPv6',
            '3j. an IPv6 header over TLS');

    // An ldapjs server: the bind limiter reads the connection's address.
    const ldap = require('ldapjs');
    const directory = ldap.createServer({ log: log });
    let bindFrom = null;
    directory.bind('cn=probe', function (req, res, next) {
      bindFrom = req.connection.remoteAddress + ' ' + req.connection.ldap.id;
      res.end();
      return next();
    });
    servers.push(directory);
    proxyProtocol.install(directory.server, { label: 'test ldap' });
    const ldapPort = await new Promise(function (resolve) {
      directory.listen(0, '127.0.0.1', function () {
        resolve(directory.address().port);
      });
    });
    // A simple BindRequest for cn=probe with the password "x", message id
    // 1, LDAPv3, BER by hand so no client library decides how it is framed.
    const bindRequest = Buffer.concat([
      Buffer.from([0x30, 0x15, 0x02, 0x01, 0x01, 0x60, 0x10, 0x02, 0x01, 0x03,
                   0x04, 0x08]),
      Buffer.from('cn=probe'),
      Buffer.from([0x80, 0x01, 0x78])]);
    raw = await exchange(ldapPort, [Buffer.concat([proxyProtocol.build({
      source: { address: '192.0.2.77', port: 40389 } }), bindRequest])]);
    t.equal(bindFrom, '192.0.2.77 192.0.2.77:40389',
            '3k. ldapjs: the connection a bind handler reads, and ldapjs\'s ' +
            'own connection id, carry the header\'s address');
    t.check(raw.length > 0 && raw.charCodeAt(0) === 0x30,
            '3k. and the BindResponse came back');

    // THIS HOST, with the real check.
    proxyProtocol.setThisHostCheck(null);
    config.setOverride('global.trustedProxies', '10.9.9.9/32');
    seen = JSON.parse(bodyOf(await exchange(plainPort,
      [Buffer.from(REQUEST)])) || '{}');
    t.equal(seen.remoteAddress, '127.0.0.1', '3l. a loopback peer that is ' +
            'not a trusted proxy is this host, served plain — the service\'s ' +
            'own back channel');
    raw = await exchange(plainPort, [Buffer.concat([header,
                                                    Buffer.from(REQUEST)])]);
    t.check(/^HTTP\/1\.1 400/.test(raw), '3l. and a header it sends is NOT ' +
            'parsed: it is protocol bytes, and HTTP answers 400', raw.slice(0,
                                                                        30));
    config.setOverride('global.trustedProxies', '127.0.0.1/32');
    seen = JSON.parse(bodyOf(await exchange(plainPort,
      [Buffer.concat([header, Buffer.from(REQUEST)])])) || '{}');
    t.equal(seen.remoteAddress, '203.0.113.7', '3m. this host AND a trusted ' +
            'proxy (a sidecar): a header is read');
    seen = JSON.parse(bodyOf(await exchange(plainPort,
      [Buffer.from(REQUEST)])) || '{}');
    t.equal(seen.remoteAddress, '127.0.0.1', '3m. and without one it is ' +
            'plain, because the back channel shares the address');
  } finally {
    servers.forEach(function (server) {
      try {
        server.close();
      } catch (e) {
        log.debug("Caught in checkRoundTrips(): " + ((e && e.message) || e));
      }
    });
    delete process.env.STS_PROXY_PROTOCOL;
    config.clearOverride('global.trustedProxies');
    config.clearOverride('global.proxyProtocolTimeoutMs');
    proxyProtocol.reset();
  }
  log.debug("Leaving checkRoundTrips().");
}

async function run(t) {
  log.debug("Entering run().");
  checkParser(t);
  checkSetting(t);
  await checkRoundTrips(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'proxy_protocol',
  describe: 'PROXY protocol v2: the parser, who may send a header, the ' +
            'address reaching http, https, net and ldapjs readers, and ' +
            'mutual TLS behind it',
  run: run
};
