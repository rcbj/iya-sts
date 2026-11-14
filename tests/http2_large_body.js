// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/http2_large_body.js
//
// ---------------------------------------------------------------------------
// A LARGE BODY OVER HTTP/2 ALWAYS FINISHES (#1725, 2026-11-13).
//
// `GET /admin-api/openapi.json` is about 6.5 MB, and the console fetches it
// on its first form submission. Over HTTP/2 its headers sometimes arrived
// with a 200 and its body never ended (5 in 124 runs, none in 70 with
// HTTP/2 off). The cause: `res.send()` ends a response with the whole body
// in one `end(chunk)`, node's HTTP/2 stream holds that chunk in the
// SESSION's outbound memory until flow control has let it all out, and two
// such bodies on one connection pass node's `maxSessionMemory` (10 MB). From
// then on node refuses every new stream on that connection with
// ENHANCE_YOUR_CALM, and past its count of refusals tears the session down,
// which leaves a stream whose headers had arrived waiting for ever.
// `common/http2_express.ts` now hands such a body to the stream a slice at
// a time, as `request_pool.proxy()`'s pipe always did.
//
// In a CHILD PROCESS with the whole stack, on node's http2 secure server
// with HTTP/1.1 allowed — the main port's shape — and over one HTTP/2
// session, as a browser holds one:
//
//   A. The document itself: one fetch is a 200 whose body parses, and is
//      over 4 MB (or the load below proves nothing).
//   B. UNDER LOAD: four fetches of it at once, each reader pausing two
//      seconds a megabyte in (a slow browser tab), with three hundred small
//      requests on the same session meanwhile. Every body ends and parses
//      within the bound, no small request is refused, and the session never
//      fails. Without the slicing, a body stalls or a stream is refused
//      ENHANCE_YOUR_CALM here.
//   C. THROUGH THE REQUEST POOL: the same load against a front app proxying
//      to a worker that answers 6.5 MB with one `end()`, as a request worker
//      does — the pipe's path, which must stay whole.
//   D. THE PACED METHODS' CONTRACT, on an adapted app's own routes: a large
//      `write()` then a small `end()`, a large `end()` with a callback, and
//      a pipe of large chunks each arrive whole; `writableEnded` reads true
//      from the `end()` call; a small body is node's own write, unsliced;
//      and an HTTP/1.1 request is answered by express's own response.
// ---------------------------------------------------------------------------

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'http2_large_body',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.HB_ROOT;
  const OUT = process.env.HB_OUT;
  const fs = require('fs');
  const os = require('os');
  const path = require('path');
  const http2 = require('http2');
  const http = require('http');
  const https = require('https');
  const stream = require('stream');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  const BOUND_MS = 45000;

  // One request on a session: its status, its body's bytes, and how it
  // ended. `pauseMs` pauses the reader that long once a megabyte is in.
  function fetchOn(session, pathname, pauseMs) {
    return new Promise(function (resolve) {
      if (session.destroyed || session.closed) {
        resolve({ status: 0, bytes: 0, error: 'session gone' });
        return;
      }
      const s = session.request({ ':path': pathname });
      const parts = [];
      let bytes = 0;
      let status = 0;
      let paused = false;
      let settled = false;
      const settle = function (out) {
        if (!settled) {
          settled = true;
          clearTimeout(timer);
          resolve(out);
        }
      };
      const timer = setTimeout(function () {
        settle({ status: status, bytes: bytes, error: 'stalled' });
        s.close();
      }, BOUND_MS);
      s.on('response', function (h) { status = h[':status']; });
      s.on('data', function (d) {
        parts.push(d);
        bytes += d.length;
        if (pauseMs && !paused && bytes > 1e6) {
          paused = true;
          s.pause();
          setTimeout(function () { s.resume(); }, pauseMs);
        }
      });
      s.on('end', function () {
        settle({ status: status, bytes: bytes,
                 body: Buffer.concat(parts) });
      });
      s.on('error', function (e) {
        settle({ status: status, bytes: bytes,
                 error: String((e && e.code) || (e && e.message) || e) });
      });
      s.end();
    });
  }
  function parses(body) {
    try {
      JSON.parse(body.toString('utf8'));
      return true;
    } catch (e) {
      return false;
    }
  }
  // Four large fetches at once, slow readers, and three hundred small
  // requests on the same session meanwhile.
  async function underLoad(url, bigPath, smallPath, tls) {
    const session = http2.connect(url, tls);
    let sessionError = '';
    session.on('error', function (e) {
      sessionError = String((e && e.message) || e);
    });
    const big = [];
    for (let i = 0; i < 4; i++) {
      big.push(fetchOn(session, bigPath, 2000));
    }
    const small = [];
    for (let k = 0; k < 300; k++) {
      small.push(new Promise(function (resolve) {
        setTimeout(function () {
          fetchOn(session, smallPath, 0).then(resolve);
        }, k * 5);
      }));
    }
    const bigOut = await Promise.all(big);
    const smallOut = await Promise.all(small);
    session.close();
    return { big: bigOut, small: smallOut, sessionError: sessionError };
  }
  function describe(out) {
    return out.map(function (r) {
      return r.status + '/' + r.bytes + (r.error ? '/' + r.error : '');
    }).join(' ');
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    const config = require(ROOT_DIR + '/common/config');
    const tlsServer = require(ROOT_DIR + '/tls/tls_server');
    const Http2Express = require(ROOT_DIR + '/common/http2_express');
    const express = require('express');
    // The document needs no token here: development mode's own switch.
    config.setOverride('adminApi.authRequired', 'false');
    const own = tlsServer.serverCertificate();
    const tls = { rejectUnauthorized: false };
    const server = http2.createSecureServer({
      allowHTTP1: true, cert: own.certPem, key: own.privateKeyPem }, app);
    server.prependListener('request',
      require(ROOT_DIR + '/common/http2_framing').markFramedBody);
    tlsServer.registerHttpListener(server, 'main');
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const url = 'https://127.0.0.1:' + server.address().port;

    // A. The document.
    const one = http2.connect(url, tls);
    one.on('error', function () {});
    const doc = await fetchOn(one, '/admin-api/openapi.json', 0);
    one.close();
    note(doc.status === 200 && doc.body && parses(doc.body) &&
         doc.bytes > 4e6,
         'A. GET /admin-api/openapi.json over HTTP/2 is a 200 whose body ' +
         'parses, and is over 4 MB',
         doc.status + ' ' + doc.bytes + ' ' + (doc.error || ''));

    // B. Under load, answered by this process.
    const loaded = await underLoad(url, '/admin-api/openapi.json',
                                   '/healthcheck', tls);
    note(loaded.big.every(function (r) {
      return r.status === 200 && !r.error && r.body && parses(r.body) &&
             r.bytes === doc.bytes;
    }), 'B. four fetches of it at once on one session, slow readers, ' +
        'each end whole and parse within ' + BOUND_MS + ' ms',
         describe(loaded.big));
    const refused = loaded.small.filter(function (r) {
      return r.status !== 200 || r.error;
    });
    note(refused.length === 0,
         'B. and none of the 300 small requests on that session meanwhile ' +
         'is refused', refused.length + ': ' + describe(refused.slice(0, 5)));
    note(!loaded.sessionError, 'B. and the session never fails',
         loaded.sessionError);

    // C. Through the request pool, to a worker answering with one end().
    const pool = require(ROOT_DIR + '/common/request_pool');
    const large = Buffer.from(JSON.stringify({ x: 'a'.repeat(6.5e6) }));
    const socketPath = path.join(os.tmpdir(), 'sts-h2-big-' + process.pid +
                                 '.sock');
    const worker = http.createServer(function (req, res) {
      req.resume();
      req.on('end', function () {
        res.setHeader('Content-Type', 'application/json');
        res.end(req.url === '/small' ? Buffer.from('{}') : large);
      });
    });
    await new Promise(function (r) { worker.listen(socketPath, r); });
    const entry = { pid: 915, socket: socketPath, tickets: new Set(),
                    agent: new http.Agent({ keepAlive: false,
                                            maxSockets: 64 }),
                    inFlight: 0, served: 0, generation: 0 };
    const frontApp = Http2Express.adapt(express());
    frontApp.use(function (req, res) {
      pool.proxy(entry, req, res, 0, 0);
    });
    const front = http2.createSecureServer({
      allowHTTP1: true, cert: own.certPem, key: own.privateKeyPem },
    frontApp);
    front.prependListener('request',
      require(ROOT_DIR + '/common/http2_framing').markFramedBody);
    await new Promise(function (r) { front.listen(0, '127.0.0.1', r); });
    const frontUrl = 'https://127.0.0.1:' + front.address().port;
    const proxied = await underLoad(frontUrl, '/big', '/small', tls);
    note(proxied.big.every(function (r) {
      return r.status === 200 && !r.error && r.body &&
             r.body.equals(large);
    }) && proxied.small.every(function (r) {
      return r.status === 200 && !r.error;
    }) && !proxied.sessionError,
         'C. through request_pool.proxy() the same load ends every body ' +
         'whole and refuses nothing',
         describe(proxied.big) + ' ' + proxied.sessionError);
    front.close();
    entry.agent.destroy();
    worker.close();

    // D. The paced methods' contract.
    const seen = {};
    const probe = Http2Express.adapt(express());
    const part = Buffer.alloc(300 * 1024, 0x62);
    probe.get('/write-then-end', function (req, res) {
      res.setHeader('Content-Type', 'application/octet-stream');
      seen.firstWrite = res.write(part);
      res.end(Buffer.from('tail'));
      seen.endedAtCall = res.writableEnded;
    });
    probe.get('/end-with-callback', function (req, res) {
      res.setHeader('Content-Type', 'application/octet-stream');
      res.end(part, function () {
        seen.endCallback = true;
      });
      seen.endedBig = res.writableEnded && res.finished;
    });
    probe.get('/piped', function (req, res) {
      res.setHeader('Content-Type', 'application/octet-stream');
      const chunks = [part, part, part, part];
      stream.Readable.from(chunks).pipe(res);
    });
    probe.get('/small', function (req, res) {
      seen.smallWrite = res.write('x');
      res.end('y');
    });
    probe.get('/which', function (req, res) {
      seen.h1Write = res.write === http.ServerResponse.prototype.write;
      res.end('ok');
    });
    const probeServer = http2.createSecureServer({
      allowHTTP1: true, cert: own.certPem, key: own.privateKeyPem }, probe);
    await new Promise(function (r) { probeServer.listen(0, '127.0.0.1', r); });
    const probeUrl = 'https://127.0.0.1:' + probeServer.address().port;
    const ps = http2.connect(probeUrl, tls);
    ps.on('error', function () {});
    const wte = await fetchOn(ps, '/write-then-end', 0);
    note(wte.status === 200 && wte.body &&
         wte.body.equals(Buffer.concat([part, Buffer.from('tail')])),
         'D. a large write() then a small end() arrive whole and in order',
         wte.status + ' ' + wte.bytes);
    note(seen.firstWrite === false && seen.endedAtCall === true,
         'D. the large write() asks its caller to wait, and writableEnded ' +
         'reads true from the end() call',
         seen.firstWrite + ' ' + seen.endedAtCall);
    const ewc = await fetchOn(ps, '/end-with-callback', 1000);
    note(ewc.status === 200 && ewc.body && ewc.body.equals(part) &&
         seen.endCallback === true && seen.endedBig === true,
         'D. a large end() with a callback arrives whole, calls it, and ' +
         'reads as ended (writableEnded, finished) at once',
         ewc.bytes + ' ' + seen.endCallback + ' ' + seen.endedBig);
    const piped = await fetchOn(ps, '/piped', 1000);
    note(piped.status === 200 && piped.bytes === part.length * 4,
         'D. a pipe of large chunks into the response arrives whole',
         piped.status + ' ' + piped.bytes + ' ' + (piped.error || ''));
    const small = await fetchOn(ps, '/small', 0);
    note(small.status === 200 && small.body &&
         small.body.toString() === 'xy' && seen.smallWrite === true,
         'D. a small body is node\'s own write, which does not ask to wait',
         small.body + ' ' + seen.smallWrite);
    ps.close();
    const h1 = await new Promise(function (resolve) {
      https.get(Object.assign({ host: '127.0.0.1',
        port: probeServer.address().port, path: '/which',
        ALPNProtocols: ['http/1.1'], agent: false }, tls), function (res) {
        res.resume();
        res.on('end', function () { resolve(res.statusCode); });
      }).on('error', function (e) { resolve(String(e && e.message)); });
    });
    note(h1 === 200 && seen.h1Write === true,
         'D. an HTTP/1.1 response keeps express\'s own write', h1 + ' ' +
         seen.h1Write);
    probeServer.close();
    server.close();
    config.clearOverride('adminApi.authRequired');
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    note(false, 'the child ran to the end', (e && e.stack) || e);
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(1);
  });
}

async function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'h2big-' + process.pid + '-' +
                        Date.now() + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$|ADMIN_API_)/
        .test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = await new Promise(function (resolve) {
    childProcess.execFile(process.execPath,
      ['-e', '(' + childMain.toString() + ')()'], {
        env: Object.assign(clean, { LOG_LEVEL: 'fatal',
                                    STS_LOG_LEVEL: 'fatal',
                                    HB_ROOT: ROOT, HB_OUT: out }),
        encoding: 'utf8', timeout: 240000, cwd: ROOT,
        maxBuffer: 16 * 1024 * 1024
      }, function (err, stdout, stderr) {
        if (err) {
          log.debug("Caught in run(): " + ((err && err.message) || err));
        }
        resolve({ stderr: stderr || '' });
      });
  });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Already gone, or never written; the check below says which.
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  t.check(Array.isArray(findings) && findings.length > 0,
          'the child process wrote its findings',
          (result.stderr || '').slice(-600));
  (findings || []).forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'http2 large body',
  describe: 'a 6.5 MB body over HTTP/2 always finishes (#1725): ' +
            '/admin-api/openapi.json four at a time on one session with ' +
            'slow readers and 300 small requests beside them, the same ' +
            'through the request pool, and the paced write() and end()',
  run: run
};
