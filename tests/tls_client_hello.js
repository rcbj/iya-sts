'use strict';
//
// File: tls_client_hello.js
//
// ===========================================================================
// THE CLIENT'S JA4 TLS FINGERPRINT (#62 P0, 2026-09-22).
//
// `tls/client_hello.ts` parses a ClientHello and computes FoxIO's JA4 from
// it; `server.js` installs it on the main port; `request_pool.js` forwards
// the answer to a request worker in a header it strips from what a client
// sent. This file holds all three to account:
//
//   A. JA4 against the specification's OWN worked example — the cipher list,
//      extension list and signature algorithms it publishes, and the answer
//      `t13d1516h2_8daaf6152771_e5627efa2ab1` it says they make. A ClientHello
//      is built here that carries exactly those values, plus GREASE in every
//      list, which JA4 must ignore. An answer this file computed itself would
//      agree with any implementation that shared its mistake.
//   B. The rules around the edges: a hello fragmented over two records, one
//      cut short, a connection that is not TLS, no SNI, no ALPN, an ALPN that
//      is not alphanumeric, and no signature algorithms.
//   C. A real handshake through `install()`: the request sees its own
//      fingerprint, and the TLS engine — which is handed back every byte this
//      read — completes the handshake and answers.
//   D. The worker's side: a forwarded header is adopted when well formed,
//      ignored when not, and stripped either way.
// ===========================================================================

delete process.env.CONFIG_FILE;

const https = require('https');
const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const clientHello = require('../tls/client_hello');

// This file's own logger, for the Entering/Leaving lines the code style asks
// for; the harness's `t` is handed to run() and kept here for the parts.
const log = require('bunyan').createLogger({ name: 'tls_client_hello',
  level: process.env.LOG_LEVEL || 'info' });
let t = null;

// ---------------------------------------------------------------------------
// A ClientHello, built from lists, as the bytes a client sends.
// ---------------------------------------------------------------------------
function u16(value) {
  log.debug("Entering u16().");
  const b = Buffer.alloc(2);
  b.writeUInt16BE(value, 0);
  log.debug("Leaving u16().");
  return b;
}

function extension(type, data) {
  log.debug("Entering extension().");
  log.debug("Leaving extension().");
  return Buffer.concat([u16(type), u16(data.length), data]);
}

function listOf16(values, lengthBytes) {
  log.debug("Entering listOf16().");
  const body = Buffer.concat(values.map(u16));
  const length = lengthBytes === 1 ? Buffer.from([body.length])
                                   : u16(body.length);
  log.debug("Leaving listOf16().");
  return Buffer.concat([length, body]);
}

function sniExtension(host) {
  log.debug("Entering sniExtension().");
  const name = Buffer.from(host, 'latin1');
  const entry = Buffer.concat([Buffer.from([0]), u16(name.length), name]);
  log.debug("Leaving sniExtension().");
  return extension(0x0000, Buffer.concat([u16(entry.length), entry]));
}

function alpnExtension(values) {
  log.debug("Entering alpnExtension().");
  const list = Buffer.concat(values.map(function (v) {
    const b = Buffer.isBuffer(v) ? v : Buffer.from(v, 'latin1');
    return Buffer.concat([Buffer.from([b.length]), b]);
  }));
  log.debug("Leaving alpnExtension().");
  return extension(0x0010, Buffer.concat([u16(list.length), list]));
}

// The handshake message, wrapped in one TLS record or split over two.
function helloBytes(opts) {
  log.debug("Entering helloBytes().");
  const extensions = Buffer.concat(opts.extensions);
  const body = Buffer.concat([
    u16(0x0303), Buffer.alloc(32, 7),
    Buffer.from([32]), Buffer.alloc(32, 9),
    listOf16(opts.ciphers, 2),
    Buffer.from([1, 0]),
    opts.noExtensions ? Buffer.alloc(0) : u16(extensions.length),
    opts.noExtensions ? Buffer.alloc(0) : extensions
  ]);
  const length = Buffer.alloc(3);
  length.writeUIntBE(body.length, 0, 3);
  const message = Buffer.concat([Buffer.from([0x01]), length, body]);
  const record = function (part) {
    return Buffer.concat([Buffer.from([0x16, 0x03, 0x01]), u16(part.length),
                          part]);
  };
  log.debug("Leaving helloBytes().");
  if (opts.split) {
    const cut = Math.floor(message.length / 2);
    return Buffer.concat([record(message.subarray(0, cut)),
                          record(message.subarray(cut))]);
  }
  return record(message);
}

// The specification's worked example, with a GREASE value in every list.
const GREASE = 0x3a3a;
const SPEC_CIPHERS = [GREASE, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c,
                      0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d,
                      0x002f, 0x0035];
const SPEC_SIGALGS = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806,
                      0x0601];

function specExtensions(opts) {
  log.debug("Entering specExtensions().");
  const o = opts || {};
  const out = [extension(0x5a5a, Buffer.alloc(0))];
  if (!o.noSni) {
    out.push(sniExtension('sts.example'));
  }
  out.push(extension(0x0017, Buffer.alloc(0)));
  out.push(extension(0xff01, Buffer.from([0])));
  out.push(extension(0x000a, listOf16([GREASE, 0x001d, 0x0017], 2)));
  out.push(extension(0x000b, Buffer.from([1, 0])));
  out.push(extension(0x0023, Buffer.alloc(0)));
  if (!o.noAlpn) {
    out.push(alpnExtension(o.alpn || ['h2', 'http/1.1']));
  }
  out.push(extension(0x0005, Buffer.from([1, 0, 0, 0, 0])));
  if (!o.noSigalgs) {
    out.push(extension(0x000d, listOf16(SPEC_SIGALGS, 2)));
  }
  out.push(extension(0x0012, Buffer.alloc(0)));
  out.push(extension(0x0033, Buffer.from([0, 0])));
  out.push(extension(0x002d, Buffer.from([1, 1])));
  out.push(extension(0x002b, listOf16([GREASE, 0x0304, 0x0303], 1)));
  out.push(extension(0x001b, Buffer.from([2, 0, 2])));
  out.push(extension(0x4469, Buffer.alloc(0)));
  out.push(extension(0x0015, Buffer.alloc(4)));
  log.debug("Leaving specExtensions().");
  return out;
}

function ja4Of(bytes) {
  log.debug("Entering ja4Of().");
  const parsed = clientHello.parse(bytes);
  log.debug("Leaving ja4Of().");
  return parsed.state === 'complete' ? clientHello.ja4(parsed.hello, 't')
                                     : parsed.state;
}

// ---------------------------------------------------------------------------
// A. The specification's worked example.
// ---------------------------------------------------------------------------
function partA() {
  log.debug("Entering partA().");
  t.equal(ja4Of(helloBytes({ ciphers: SPEC_CIPHERS,
                             extensions: specExtensions() })),
          't13d1516h2_8daaf6152771_e5627efa2ab1',
          'A1. the JA4 specification\'s worked example gives its published ' +
          'answer, with GREASE in every list ignored');
  const parsed = clientHello.parse(
    helloBytes({ ciphers: SPEC_CIPHERS, extensions: specExtensions() }));
  const info = clientHello.describe(parsed.hello);
  t.check(info.sni === 'sts.example' && info.version === '13' &&
          info.alpn.join(',') === 'h2,http/1.1',
          'A2. the SNI, the highest supported version and the ALPN list are ' +
          'reported beside it', JSON.stringify(info));
  log.debug("Leaving partA().");
}

// ---------------------------------------------------------------------------
// B. The edges.
// ---------------------------------------------------------------------------
function partB() {
  log.debug("Entering partB().");
  const whole = helloBytes({ ciphers: SPEC_CIPHERS,
                             extensions: specExtensions() });
  t.equal(ja4Of(helloBytes({ ciphers: SPEC_CIPHERS,
                             extensions: specExtensions(), split: true })),
          't13d1516h2_8daaf6152771_e5627efa2ab1',
          'B1. a ClientHello fragmented over two records reads the same');
  t.equal(ja4Of(whole.subarray(0, whole.length - 10)), 'incomplete',
          'B2. a hello cut short asks for more bytes');
  t.equal(ja4Of(Buffer.from('GET / HTTP/1.1\r\n\r\n')), 'invalid',
          'B3. a connection that does not begin with a TLS handshake is not ' +
          'a ClientHello');
  const noSni = ja4Of(helloBytes({ ciphers: SPEC_CIPHERS,
                                   extensions: specExtensions({
                                     noSni: true }) }));
  t.check(/^t13i1515h2_8daaf6152771_e5627efa2ab1$/.test(noSni),
          'B4. without SNI the destination is "i", one extension fewer is ' +
          'counted, and the hashes do not move (SNI is never hashed)', noSni);
  const noAlpn = ja4Of(helloBytes({ ciphers: SPEC_CIPHERS,
                                    extensions: specExtensions({
                                      noAlpn: true }) }));
  t.check(/^t13d151500_/.test(noAlpn),
          'B5. no ALPN is "00"', noAlpn);
  const oddAlpn = ja4Of(helloBytes({ ciphers: SPEC_CIPHERS,
    extensions: specExtensions({ alpn: [Buffer.from([0xab, 0x01, 0xcd])] }) }));
  t.check(/^t13d1516ad_/.test(oddAlpn),
          'B6. an ALPN whose ends are not alphanumeric is written as the ' +
          'first and last hex digits', oddAlpn);
  const noSig = ja4Of(helloBytes({ ciphers: SPEC_CIPHERS,
                                   extensions: specExtensions({
                                     noSigalgs: true }) }));
  const sorted = '0005,000a,000b,0012,0015,0017,001b,0023,002b,002d,0033,' +
                 '4469,ff01';
  const expected = require('../common/crypto').truncatedSha256Hex(sorted, 12);
  t.check(noSig === 't13d1515h2_8daaf6152771_' + expected,
          'B7. with no signature algorithms part c hashes the extensions ' +
          'alone, with no trailing underscore', noSig + ' vs ' + expected);
  t.equal(ja4Of(helloBytes({ ciphers: [], extensions: [],
                             noExtensions: true })),
          't12i000000_000000000000_000000000000',
          'B8. no ciphers and no extensions are twelve zeros each, and the ' +
          'version falls back to the record\'s');
  t.check(clientHello.isGrease(0x0a0a) && clientHello.isGrease(0xfafa) &&
          !clientHello.isGrease(0x0a1a) && !clientHello.isGrease(0x1301),
          'B9. GREASE is the sixteen 0x?a?a values and nothing else');
  log.debug("Leaving partB().");
}

// ---------------------------------------------------------------------------
// C. A real handshake through install().
// ---------------------------------------------------------------------------
async function partC() {
  log.debug("Entering partC().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ja4-'));
  childProcess.execFileSync('openssl', ['req', '-x509', '-newkey', 'ec',
    '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-keyout',
    path.join(dir, 'k.pem'), '-out', path.join(dir, 'c.pem'), '-days', '1',
    '-subj', '/CN=localhost'], { stdio: 'ignore' });
  const seen = [];
  const server = https.createServer({
    key: fs.readFileSync(path.join(dir, 'k.pem')),
    cert: fs.readFileSync(path.join(dir, 'c.pem'))
  }, function (req, res) {
    seen.push(clientHello.of(req));
    res.end('answered');
  });
  clientHello.install(server, { label: 'the test listener' });
  await new Promise(function (resolve) {
    server.listen(0, '127.0.0.1', resolve);
  });
  const port = server.address().port;
  const ask = function () {
    return new Promise(function (resolve) {
      https.get({ host: '127.0.0.1', port: port, servername: 'localhost',
                  rejectUnauthorized: false, agent: false,
                  ALPNProtocols: ['http/1.1'] }, function (res) {
        let text = '';
        res.on('data', function (c) {
          text += c;
        });
        res.on('end', function () {
          resolve(text);
        });
      }).on('error', function (e) {
        resolve('error: ' + e.message);
      });
    });
  };
  const first = await ask();
  const second = await ask();
  server.close();
  fs.rmSync(dir, { recursive: true, force: true });
  t.check(first === 'answered' && second === 'answered',
          'C1. the TLS engine completes the handshake on the bytes handed ' +
          'back to it, twice', first + ' / ' + second);
  const one = seen[0] || {};
  t.check(/^t1[23]d\d{4}h1_[0-9a-f]{12}_[0-9a-f]{12}$/.test(one.ja4 || ''),
          'C2. the request sees its own connection\'s JA4 (SNI sent, ALPN ' +
          'http/1.1)', one.ja4);
  t.check(seen[1] && seen[1].ja4 === one.ja4,
          'C3. the same client stack fingerprints the same on a second ' +
          'connection', JSON.stringify(seen));
  t.check(clientHello.report().fingerprinted >= 2 &&
          clientHello.report().waiting === 0,
          'C4. both were counted, and nothing is left waiting for its TLS ' +
          'socket', JSON.stringify(clientHello.report()));
  log.debug("Leaving partC().");
}

// ---------------------------------------------------------------------------
// D. The worker's side.
// ---------------------------------------------------------------------------
function partD() {
  log.debug("Entering partD().");
  const good = { ja4: 't13d1516h2_8daaf6152771_e5627efa2ab1', version: '13',
                 sni: 'sts.example', alpn: ['h2'] };
  const encoded = Buffer.from(JSON.stringify(good)).toString('base64url');
  const req = { headers: { [clientHello.FORWARD_HEADER]: encoded } };
  clientHello.adoptForwarded(req);
  t.check(clientHello.of(req) && clientHello.of(req).ja4 === good.ja4 &&
          !(clientHello.FORWARD_HEADER in req.headers),
          'D1. a forwarded fingerprint is put on the request and the header ' +
          'is stripped');
  const forged = { headers: { [clientHello.FORWARD_HEADER]:
    Buffer.from(JSON.stringify({ ja4: '<script>' })).toString('base64url') } };
  clientHello.adoptForwarded(forged);
  t.check(!clientHello.of(forged) &&
          !(clientHello.FORWARD_HEADER in forged.headers),
          'D2. one that is not the shape of a JA4 is ignored, and stripped');
  const garbage = { headers: { [clientHello.FORWARD_HEADER]: '%%%' } };
  clientHello.adoptForwarded(garbage);
  t.check(!clientHello.of(garbage),
          'D3. one that does not decode is ignored');
  t.check(clientHello.encodeForward(req) !== '' &&
          clientHello.encodeForward({ socket: {} }) === '',
          'D4. the front process forwards what it read, and nothing when it ' +
          'read nothing');
  log.debug("Leaving partD().");
}

async function run(harness) {
  log.debug("Entering run().");
  t = harness;
  partA();
  partB();
  await partC();
  partD();
  log.debug("Leaving run().");
}

module.exports = {
  name: 'tls_client_hello',
  describe: 'the JA4 TLS fingerprint: the specification\'s worked example, ' +
            'the edges, a real handshake through install(), and the ' +
            'request worker\'s forwarded header',
  run: run
};
