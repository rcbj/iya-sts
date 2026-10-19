// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/main_port_http2.js
//
// ---------------------------------------------------------------------------
// THE MAIN PORT ANSWERS HTTP/2 AND HTTP/1.1 ALIKE (#407).
//
// `server.js` builds the main port as node's `http2` secure server with
// `allowHTTP1`, and `common/app.js` builds the application through
// `http2-express`, because plain express — 4.22 and 5.3 alike — sets every
// request's prototype to one derived from `http.IncomingMessage` and throws
// on the first HTTP/2 request. A child process loads the whole stack, serves
// the real application on that kind of server, and drives it over both
// protocols:
//
//   1. THE SAME ANSWER OVER EACH: the discovery document, a token request
//      with a form body, a refusal from an unknown realm, an unrouted path —
//      status, body and the `frame-ancestors` clause, and no `X-Powered-By`
//      (the wrapper's names the package).
//   2. A CLIENT CERTIFICATE AT THE HANDSHAKE STILL BINDS (RFC 8705): the
//      token's `cnf` carries the presented certificate's thumbprint, over
//      HTTP/2 as over HTTP/1.1 — `getPeerCertificate()` is reached through
//      node's socket proxy on an HTTP/2 request.
//   3. MULTIPLEXING, which is the point: ten requests in flight together on
//      one HTTP/2 session, each answered.
//   4. `lingeringClose.arm()` LEAVES AN HTTP/2 STREAM ALONE: its socket is
//      the whole connection, and `Connection` is a header HTTP/2 forbids.
//      An HTTP/1.1 request is still armed, as the control.
//   1a. A BODY WITH NO `content-length`, which HTTP/2 allows (RFC 9113
//      8.1.1) and body-parser read as no body until
//      `common/http2_framing.ts`: the token request in section 1 sends
//      none, and one more sends a length, as curl does.
//   5. AND THE SOURCE: the main port is built that way, so reverting it
//      fails here rather than in a browser.
// ---------------------------------------------------------------------------

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');
const lingeringClose = require('../common/lingering_close');

const log = bunyan.createLogger({ name: 'main_port_http2',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.AG_ROOT;
  const OUT = process.env.AG_OUT;
  const http2 = require('http2');
  const https = require('https');
  const crypto = require('crypto');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  function claimsOf(jwt) {
    try {
      return JSON.parse(Buffer.from(String(jwt).split('.')[1], 'base64url')
        .toString('utf8'));
    } catch (e) {
      // Not a JWT; the finding that reads it reports that.
      return { unreadable: String((e && e.message) || e) };
    }
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    const tlsServer = require(ROOT_DIR + '/tls/tls_server');
    const own = tlsServer.serverCertificate();
    // Asked for and not required, as the main port does; the client below
    // presents the listener's own certificate, which binds a token as well
    // as any (RFC 8705 section 3 permits a self-signed one).
    const server = http2.createSecureServer({
      allowHTTP1: true, cert: own.certPem, key: own.privateKeyPem,
      requestCert: true, rejectUnauthorized: false }, app);
    // As server.js installs it on the main port, ahead of the application.
    server.prependListener('request',
      require(ROOT_DIR + '/common/http2_framing').markFramedBody);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const tls = { cert: own.certPem, key: own.privateKeyPem,
                  rejectUnauthorized: false };
    const session = http2.connect('https://127.0.0.1:' + port, tls);
    session.on('error', function (e) {
      note(false, 'the HTTP/2 session stays up', e && e.message);
    });

    // `withLength` sends a content-length, as curl does; without it the
    // body's length is the framing's alone, which RFC 9113 8.1.1 allows.
    const overHttp2 = function (method, pathname, form, withLength) {
      return new Promise(function (resolve) {
        const headers = { ':method': method, ':path': pathname };
        if (form) {
          headers['content-type'] = 'application/x-www-form-urlencoded';
        }
        if (form && withLength) {
          headers['content-length'] = String(Buffer.byteLength(form));
        }
        const stream = session.request(headers);
        let status = 0;
        let got = {};
        let body = '';
        stream.on('response', function (h) {
          status = h[':status'];
          got = h;
        });
        stream.setEncoding('utf8');
        stream.on('data', function (d) { body += d; });
        stream.on('end', function () {
          resolve({ status: status, headers: got, body: body });
        });
        stream.on('error', function (e) {
          resolve({ status: 0, headers: {}, body: String(e && e.message) });
        });
        stream.end(form || undefined);
      });
    };
    const overHttp1 = function (method, pathname, form) {
      return new Promise(function (resolve) {
        const headers = {};
        if (form) {
          headers['content-type'] = 'application/x-www-form-urlencoded';
        }
        const req = https.request(Object.assign({
          host: '127.0.0.1', port: port, method: method, path: pathname,
          headers: headers, ALPNProtocols: ['http/1.1'], agent: false
        }, tls), function (res) {
          let body = '';
          res.setEncoding('utf8');
          res.on('data', function (d) { body += d; });
          res.on('end', function () {
            resolve({ status: res.statusCode, headers: res.headers,
                      body: body, version: res.httpVersion });
          });
        });
        req.on('error', function (e) {
          resolve({ status: 0, headers: {}, body: String(e && e.message) });
        });
        req.end(form || undefined);
      });
    };

    // 1. The same answer over each.
    const form = 'grant_type=client_credentials&client_id=demo&' +
                 'client_secret=x';
    const asks = [
      ['GET', '/.well-known/openid-configuration', null, 200],
      ['POST', '/oauth2/token', form, 200],
      ['GET', '/realm/no-such-realm/.well-known/openid-configuration', null,
       404],
      ['GET', '/no/such/path', null, 404]
    ];
    const tokens = {};
    const framed = await overHttp2('POST', '/oauth2/token', form, true);
    note(framed.status === 200 && /access_token/.test(framed.body),
         '1. a token request over HTTP/2 WITH a content-length is answered',
         framed.status + ' ' + framed.body.slice(0, 200));
    for (const ask of asks) {
      const two = await overHttp2(ask[0], ask[1], ask[2]);
      const one = await overHttp1(ask[0], ask[1], ask[2]);
      note(two.status === ask[3] && one.status === ask[3],
           '1. ' + ask[0] + ' ' + ask[1] + ' answers ' + ask[3] +
           ' over HTTP/2 and over HTTP/1.1',
           two.status + ' / ' + one.status + ' ' + two.body.slice(0, 200));
      const policy = function (r) {
        return String(r.headers['content-security-policy'] || '');
      };
      note(/frame-ancestors 'none'/.test(policy(two)) &&
           /frame-ancestors 'none'/.test(policy(one)),
           '1. and keeps frame-ancestors over both',
           policy(two) + ' / ' + policy(one));
      note(!two.headers['x-powered-by'] && !one.headers['x-powered-by'],
           '1. and sends no X-Powered-By over either',
           two.headers['x-powered-by'] + ' / ' + one.headers['x-powered-by']);
      if (ask[1] === '/.well-known/openid-configuration') {
        let issuers = '';
        try {
          issuers = JSON.parse(two.body).issuer + ' ' +
                    JSON.parse(one.body).issuer;
        } catch (e) {
          issuers = 'unreadable: ' + ((e && e.message) || e);
        }
        const halves = issuers.split(' ');
        note(halves.length === 2 && halves[0] === halves[1] &&
             /^https?:\/\//.test(halves[0]),
             '1. the discovery document names the same issuer over both',
             issuers);
      }
      if (ask[1] === '/oauth2/token') {
        tokens.two = two;
        tokens.one = one;
      }
    }

    // 2. A client certificate at the handshake still binds.
    const der = new crypto.X509Certificate(own.certPem).raw;
    const thumbprint = crypto.createHash('sha256').update(der)
      .digest('base64url');
    const cnfOf = function (r) {
      try {
        return claimsOf(JSON.parse(r.body).access_token).cnf || {};
      } catch (e) {
        return { unreadable: String((e && e.message) || e) };
      }
    };
    note(cnfOf(tokens.two)['x5t#S256'] === thumbprint &&
         cnfOf(tokens.one)['x5t#S256'] === thumbprint,
         '2. the token is bound to the presented certificate over HTTP/2 ' +
         'as over HTTP/1.1 (RFC 8705)',
         JSON.stringify(cnfOf(tokens.two)) + ' / ' +
         JSON.stringify(cnfOf(tokens.one)) + ' want ' + thumbprint);

    // 3. Multiplexing: ten in flight on one session.
    const many = [];
    for (let i = 0; i < 10; i++) {
      many.push(overHttp2('GET', '/.well-known/openid-configuration'));
    }
    const answered = await Promise.all(many);
    note(answered.every(function (r) { return r.status === 200; }),
         '3. ten requests in flight together on one HTTP/2 session are ' +
         'each answered',
         answered.map(function (r) { return r.status; }).join(','));

    session.close();
    server.close();
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    note(false, 'the child process ran to the end', e && e.stack);
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

// 4. A stand-in request of each protocol, its body still arriving.
function checkLingeringClose(t) {
  log.debug("Entering checkLingeringClose().");
  const fakeSocket = function () {
    log.debug("Entering fakeSocket().");
    const original = function () {};
    log.debug("Leaving fakeSocket().");
    return { destroyed: false, destroySoon: original, original: original };
  };
  const fakeResponse = function () {
    log.debug("Entering fakeResponse().");
    const set = {};
    log.debug("Leaving fakeResponse().");
    return { set: set, setHeader: function (k, v) { set[k] = v; } };
  };
  const twoSocket = fakeSocket();
  const twoRes = fakeResponse();
  lingeringClose.arm({ httpVersionMajor: 2, complete: false,
                       socket: twoSocket }, twoRes);
  t.check(!('Connection' in twoRes.set) &&
          twoSocket.destroySoon === twoSocket.original,
          '4. lingeringClose.arm() sets no Connection header and leaves an ' +
          'HTTP/2 request\'s socket — the whole connection — alone',
          JSON.stringify(twoRes.set));
  const oneSocket = fakeSocket();
  const oneRes = fakeResponse();
  lingeringClose.arm({ httpVersionMajor: 1, complete: false,
                       socket: oneSocket }, oneRes);
  t.check(oneRes.set.Connection === 'close' &&
          oneSocket.destroySoon !== oneSocket.original,
          '4. while an HTTP/1.1 request is still armed (the control)',
          JSON.stringify(oneRes.set));
  log.debug("Leaving checkLingeringClose().");
}

// 5. The source: the main port is the http2 server, with HTTP/1.1 allowed,
// and the application is built through the wrapper. Read by statement.
function checkTheSource(t) {
  log.debug("Entering checkTheSource().");
  const server = fs.readFileSync(path.join(ROOT, 'server.js'), 'utf8')
    .replace(/\s+/g, ' ');
  const app = fs.readFileSync(path.join(ROOT, 'common', 'app.js'), 'utf8')
    .replace(/\s+/g, ' ');
  t.check(/const mainServer = http2\.createSecureServer\(Object\.assign\(\{ allowHTTP1: true,/
    .test(server),
          '5. server.js builds the main port as an http2 secure server ' +
          'with allowHTTP1', '');
  t.check(/mainServer\.prependListener\('request', require\('\.\/common\/http2_framing'\)\.markFramedBody\);/
    .test(server),
          '5. and marks a framed HTTP/2 body ahead of the application', '');
  t.check(/const app = require\('http2-express'\)\(express\);/.test(app),
          '5. and common/app.js builds the application through ' +
          'http2-express', '');
  log.debug("Leaving checkTheSource().");
}

async function run(t) {
  log.debug("Entering run().");
  checkLingeringClose(t);
  checkTheSource(t);
  const out = path.join(os.tmpdir(), 'h2-' + process.pid + '-' + Date.now() +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$|ADMIN_API_)/
        .test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal',
                                  AG_ROOT: ROOT, AG_OUT: out }),
      encoding: 'utf8', timeout: 180000, cwd: ROOT
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
  name: 'main port http2',
  describe: 'the main port on node\'s http2 server with HTTP/1.1 allowed ' +
            '(#407): the same answers over each protocol, a client ' +
            'certificate still binding a token, ten requests multiplexed ' +
            'on one session, and the lingering close leaving an HTTP/2 ' +
            'stream alone',
  run: run
};
