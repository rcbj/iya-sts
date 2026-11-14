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
// `allowHTTP1`, and `common/app.js` adapts the application with
// `common/http2_express.ts`, because plain express — 4.22 and 5.3 alike —
// sets every request's prototype to one derived from `http.IncomingMessage`
// and throws on the first HTTP/2 request. A child process loads the whole
// stack, serves the real application on that kind of server, and drives it
// over both protocols:
//
//   1. THE SAME ANSWER OVER EACH: the discovery document, a token request
//      with a form body, a refusal from an unknown realm, an unrouted path —
//      status, body and the `frame-ancestors` clause, and no `X-Powered-By`
//      (express's names the framework).
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
//   6. THE SETTING (rcbj, 2026-10-19: on by default on every listener, and
//      the user can turn it off): `http.http2` on by default; off, the next
//      handshake negotiates `http/1.1` while an open HTTP/2 session keeps
//      answering; a listener's own `on` beats the service's `off`, and the
//      debugger inherits it; cleared, `h2` again; and a custom listener's
//      `tls.http2` is read and validated like the other per-listener names.
//   7. THROUGH THE REQUEST POOL: an HTTP/2 request proxied to a worker by
//      `request_pool.proxy()` reaches it with no pseudo-header (node's
//      HTTP/1.1 client throws on `:path`, so every dispatched HTTP/2 request
//      failed), its `:authority` as `host`, its body whole, and the client
//      certificate `getPeerCertificate()` read off the HTTP/2 session in
//      the header the worker rebuilds it from.
//   8. THE HTTP/2 BOUNDS: `http2MaxConcurrentStreams` is what a session is
//      told, and no more streams than that run at once on one connection;
//      an idle session is closed after the keep-alive timeout; and a
//      session that has carried `maxRequestsPerSocket` requests is sent a
//      GOAWAY — so HTTP/2 cannot carry what HTTP/1.1 is bounded from.
//   9. :authority AND host (RFC 9113 section 8.3.1): `host` is built from
//      `:authority`; the two naming different hosts is refused 400 with
//      STS-HTTP-0024, by the app's `init` and by `request_pool.proxy()`
//      itself; the same host spelled with its default port or in another
//      case is not a difference.
//  10. THE EXPRESS MODULE IS UNTOUCHED: the adapter gives the app an own
//      `lazyrouter` and changes nothing on `express.application`, so a
//      plain `express()` app elsewhere in the process is express's.
//  11. `tls.http2` AS THE STRINGS "true" AND "false" (#1304), beside on and
//      off: a custom listener's definition is accepted with either, each
//      decides that listener's offer whatever http.http2 says, a real
//      handshake on each negotiates accordingly, and http.http2 written as
//      "true" is on.
//  12. THE DEBUGGER'S API PROXY OVER HTTP/2 (#1304): the debugger listener's
//      own app forwards an HTTP/2 POST to the api process with no
//      pseudo-header and its :authority as host; :authority and host naming
//      different hosts is refused 400 with STS-HTTP-0024 and never
//      forwarded; and `forward()` refuses a host changed after the app's
//      check, on its own.
//  13. CONNECT (#1304): answered 501 over HTTP/2 and HTTP/1.1 by
//      `common/connect_refusal.ts`, no-store and frame-ancestors kept,
//      marked STS-HTTP-0025, never reaching the application. Node's own
//      answers were a 405 with no Allow and a dropped connection.
//  14. `OPTIONS *` OVER HTTP/2 (#1304): answered 204 by the application's
//      preflight, and never dispatched, even with `workers.dispatch` `*`
//      (`request_pool.js` `answeredAtOnce()`).
//  15. THE LISTENERS PAGE (#1304): the `/admin-api/listeners` view carries
//      `http2MaxConcurrentStreams`, and `admin-ui/web_listeners.ts` draws it
//      beside HTTP/2 offered.
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
    // And held to the main port's HTTP policy, which is where the HTTP/2
    // offer is applied (section 6).
    tlsServer.registerHttpListener(server, 'main');
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

    // 6. The setting.
    const config = require(ROOT_DIR + '/common/config');
    const listenerMap = require(ROOT_DIR + '/common/listener_map');
    const tlsModule = require('tls');
    const negotiated = function () {
      return new Promise(function (resolve) {
        const socket = tlsModule.connect({
          host: '127.0.0.1', port: port, ALPNProtocols: ['h2', 'http/1.1'],
          rejectUnauthorized: false }, function () {
          const chosen = socket.alpnProtocol;
          socket.end();
          resolve(chosen);
        });
        socket.on('error', function (e) {
          resolve('error: ' + (e && e.message));
        });
      });
    };
    const settle = function () {
      tlsServer.reapplyPolicy();
    };
    note(tlsServer.httpPolicyFor('main').http2 === true &&
         config.value('http.http2') === true,
         '6. http.http2 is on by default, and the main port offers it',
         JSON.stringify(tlsServer.httpPolicyFor('main')));
    note(await negotiated() === 'h2',
         '6. so a client offering h2 and http/1.1 gets h2', '');
    config.setOverride('http.http2', 'false');
    settle();
    const offWhat = await negotiated();
    note(offWhat === 'http/1.1',
         '6. turned off for the service, the next handshake gets http/1.1',
         offWhat);
    const stillOne = await overHttp1('GET',
                                     '/.well-known/openid-configuration');
    note(stillOne.status === 200,
         '6. and HTTP/1.1 is answered on it', stillOne.status);
    const openSession = await overHttp2('GET',
                                        '/.well-known/openid-configuration');
    note(openSession.status === 200,
         '6. while the HTTP/2 session opened before keeps answering',
         openSession.status + ' ' + openSession.body.slice(0, 120));
    note(tlsServer.httpPolicyFor('debugger').http2 === false,
         '6. and the debugger\'s listener, which inherits it, is off too',
         JSON.stringify(tlsServer.httpPolicyFor('debugger')));
    config.setOverride('listenerMain.http2', 'on');
    settle();
    const ownOn = await negotiated();
    note(ownOn === 'h2' && tlsServer.httpPolicyFor('main').http2 === true,
         '6. the main port\'s own listenerMain.http2=on beats the ' +
         'service\'s off', ownOn);
    config.clearOverride('listenerMain.http2');
    config.clearOverride('http.http2');
    settle();
    const cleared = await negotiated();
    note(cleared === 'h2', '6. cleared, h2 is offered again', cleared);
    const define = function (value) {
      return listenerMap.parseListeners(JSON.stringify([{
        id: 'h2probe', port: 9555, publicBaseUrl: 'https://h2.example.com',
        tls: { http2: value } }]), '');
    };
    const offDefined = define('off');
    note(!offDefined.problem && offDefined.listeners.length === 1 &&
         offDefined.listeners[0].tls.http2 === 'off',
         '6. a custom listener\'s tls.http2 is accepted',
         JSON.stringify(offDefined.problem));
    const badDefined = define('maybe');
    note(!!badDefined.problem && badDefined.problem.code === 'STS-CORE-0153',
         '6. and a value http.http2 does not take is refused',
         JSON.stringify(badDefined.problem));

    // 7. Through the request pool, to a worker that says what it was sent.
    const pool = require(ROOT_DIR + '/common/request_pool');
    const http = require('http');
    const os = require('os');
    const pathModule = require('path');
    const express = require('express');
    const socketPath = pathModule.join(os.tmpdir(), 'sts-h2-pool-' +
                                       process.pid + '.sock');
    const worker = http.createServer(function (req, res) {
      let body = '';
      req.setEncoding('utf8');
      req.on('data', function (d) { body += d; });
      req.on('end', function () {
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ method: req.method, url: req.url,
                                 headers: req.headers, body: body }));
      });
    });
    await new Promise(function (r) { worker.listen(socketPath, r); });
    const entry = { pid: 914, socket: socketPath, tickets: new Set(),
                    agent: new http.Agent({ keepAlive: false,
                                            maxSockets: 8 }),
                    inFlight: 0, served: 0, generation: 0 };
    const frontApp = require(ROOT_DIR + '/common/http2_express')
      .adapt(express());
    frontApp.use(function (req, res) {
      pool.proxy(entry, req, res, 0, 0);
    });
    const front = http2.createSecureServer({
      allowHTTP1: true, cert: own.certPem, key: own.privateKeyPem,
      requestCert: true, rejectUnauthorized: false }, frontApp);
    front.prependListener('request',
      require(ROOT_DIR + '/common/http2_framing').markFramedBody);
    await new Promise(function (r) { front.listen(0, '127.0.0.1', r); });
    const frontPort = front.address().port;
    const poolSession = http2.connect('https://127.0.0.1:' + frontPort, tls);
    const sent = 'a=1&b=2';
    const proxied = await new Promise(function (resolve) {
      const stream = poolSession.request({
        ':method': 'POST', ':path': '/oauth2/token?x=1',
        'content-type': 'application/x-www-form-urlencoded' });
      let status = 0;
      let text = '';
      stream.on('response', function (h) { status = h[':status']; });
      stream.setEncoding('utf8');
      stream.on('data', function (d) { text += d; });
      stream.on('end', function () {
        resolve({ status: status, text: text });
      });
      stream.on('error', function (e) {
        resolve({ status: 0, text: String(e && e.message) });
      });
      stream.end(sent);
    });
    let echoed = {};
    try {
      echoed = JSON.parse(proxied.text);
    } catch (e) {
      echoed = { unreadable: proxied.text.slice(0, 300) };
    }
    const names = Object.keys(echoed.headers || {});
    note(proxied.status === 200 && echoed.method === 'POST' &&
         echoed.url === '/oauth2/token?x=1' && echoed.body === sent,
         '7. an HTTP/2 POST with no length reaches the worker through the ' +
         'pool: method, path and body whole',
         proxied.status + ' ' + JSON.stringify(echoed).slice(0, 300));
    note(names.length > 0 && names.every(function (n) {
      return n.charAt(0) !== ':';
    }) && echoed.headers.host === '127.0.0.1:' + frontPort,
         '7. with no pseudo-header, and its :authority as host',
         names.join(','));
    let forwarded = null;
    try {
      forwarded = JSON.parse(Buffer.from(
        String(echoed.headers['x-sts-peer-certificate'] || ''), 'base64')
        .toString('utf8'));
    } catch (e) {
      forwarded = { unreadable: String((e && e.message) || e) };
    }
    const forwardedDer = forwarded && forwarded.raw && forwarded.raw.__buffer
      ? Buffer.from(forwarded.raw.__buffer, 'base64') : Buffer.alloc(0);
    note(forwardedDer.length > 0 && forwardedDer.equals(der),
         '7. and the client certificate getPeerCertificate() read off the ' +
         'HTTP/2 session goes to the worker',
         forwarded ? Object.keys(forwarded).join(',') : 'none');
    poolSession.close();
    front.close();
    entry.agent.destroy();
    worker.close();
    try {
      require('fs').unlinkSync(socketPath);
    } catch (e) {
      // Already gone with the server; recorded rather than failed.
      note(true, '7. (the worker socket was already gone: ' +
           String((e && e.message) || e) + ')', '');
    }

    // 8. The HTTP/2 bounds, on a listener of its own held to the main
    // port's policy, whose handler waits until it is let go.
    const MARK = Symbol.for('iya-sts.errorCode');
    let active = 0;
    let most = 0;
    const waiting = [];
    const slow = http2.createSecureServer({
      allowHTTP1: true, cert: own.certPem, key: own.privateKeyPem },
    function (req, res) {
      active += 1;
      most = Math.max(most, active);
      waiting.push(function () {
        active -= 1;
        res.end('ok');
      });
    });
    const unregisterSlow = tlsServer.registerHttpListener(slow, 'main');
    await new Promise(function (r) { slow.listen(0, '127.0.0.1', r); });
    const slowUrl = 'https://127.0.0.1:' + slow.address().port;
    note(tlsServer.httpPolicyFor('main').http2MaxConcurrentStreams === 100,
         '8. http.http2MaxConcurrentStreams is 100 by default',
         JSON.stringify(tlsServer.httpPolicyFor('main')));
    config.setOverride('listenerMain.http2MaxConcurrentStreams', '2');
    settle();
    const capped = http2.connect(slowUrl, { rejectUnauthorized: false });
    capped.on('error', function () {});
    await new Promise(function (r) { capped.once('remoteSettings', r); });
    note(capped.remoteSettings.maxConcurrentStreams === 2,
         '8. a new session is told the listener\'s stream cap',
         capped.remoteSettings.maxConcurrentStreams);
    const ends = [];
    for (let i = 0; i < 5; i++) {
      ends.push(new Promise(function (resolve) {
        const st = capped.request({ ':path': '/slow/' + i });
        let status = 0;
        st.on('response', function (h) { status = h[':status']; });
        st.resume();
        st.on('end', function () { resolve(String(status)); });
        st.on('error', function (e) { resolve(String(e && e.code)); });
      }));
    }
    await new Promise(function (r) { setTimeout(r, 400); });
    const atOnce = most;
    const release = setInterval(function () {
      while (waiting.length) {
        waiting.shift()();
      }
    }, 50);
    const outcomes = await Promise.all(ends);
    clearInterval(release);
    note(atOnce === 2 && most === 2,
         '8. no more than the cap\'s streams run at once on one connection',
         'at once ' + atOnce + ', ever ' + most);
    note(outcomes.every(function (o) {
      return o === '200' || o === 'ERR_HTTP2_STREAM_ERROR';
    }), '8. and the rest are queued or refused, never run past it',
         outcomes.join(','));
    capped.close();
    config.clearOverride('listenerMain.http2MaxConcurrentStreams');
    config.setOverride('listenerMain.keepAliveTimeoutS', '1');
    settle();
    const idle = http2.connect(slowUrl, { rejectUnauthorized: false });
    idle.on('error', function () {});
    const idleAt = Date.now();
    const idleEnd = await new Promise(function (resolve) {
      const give = setTimeout(function () { resolve('still open'); }, 5000);
      idle.once('goaway', function () {
        clearTimeout(give);
        resolve('goaway');
      });
      idle.once('close', function () {
        clearTimeout(give);
        resolve('closed');
      });
    });
    note(idleEnd !== 'still open' && Date.now() - idleAt >= 900,
         '8. an idle HTTP/2 session is closed after the keep-alive timeout',
         idleEnd + ' after ' + (Date.now() - idleAt) + ' ms');
    idle.destroy();
    config.clearOverride('listenerMain.keepAliveTimeoutS');
    config.setOverride('listenerMain.maxRequestsPerSocket', '2');
    settle();
    const counted = http2.connect(slowUrl, { rejectUnauthorized: false });
    counted.on('error', function () {});
    let goneAway = false;
    counted.on('goaway', function () { goneAway = true; });
    const one = function (n) {
      return new Promise(function (resolve) {
        const st = counted.request({ ':path': '/count/' + n });
        let status = 0;
        st.on('response', function (h) { status = h[':status']; });
        st.resume();
        st.on('end', function () { resolve(status); });
        st.on('error', function (e) { resolve(String(e && e.code)); });
        setTimeout(function () {
          while (waiting.length) {
            waiting.shift()();
          }
        }, 20);
      });
    };
    const firstTwo = [await one(1), await one(2)];
    await new Promise(function (r) { setTimeout(r, 200); });
    note(firstTwo[0] === 200 && firstTwo[1] === 200 && goneAway,
         '8. a session that has carried maxRequestsPerSocket requests is ' +
         'answered and then sent a GOAWAY', firstTwo.join(',') + ' goaway=' +
         goneAway);
    counted.destroy();
    config.clearOverride('listenerMain.maxRequestsPerSocket');
    settle();
    unregisterSlow();
    slow.close();

    // 9. :authority and host. On the real application first, the response
    // kept so its error code can be read.
    let lastRes = null;
    server.prependListener('request', function (req, res) {
      lastRes = res;
    });
    // Both, explicitly: node's client turns a lone `host` into the
    // `:authority` and sends no `host` at all.
    const withHost = function (who, host, named) {
      return new Promise(function (resolve) {
        const headers = { ':path': '/.well-known/openid-configuration' };
        if (host !== undefined) {
          headers[':authority'] = named;
          headers.host = host;
        }
        const st = who.request(headers);
        let status = 0;
        let body = '';
        st.on('response', function (h) { status = h[':status']; });
        st.setEncoding('utf8');
        st.on('data', function (d) { body += d; });
        st.on('end', function () { resolve({ status: status, body: body }); });
        st.on('error', function (e) {
          resolve({ status: 0, body: String(e && e.message) });
        });
        st.end();
      });
    };
    const authority = '127.0.0.1:' + port;
    // A session of its own: section 8's one-second keep-alive closed the
    // idle one opened at the top, as it should.
    const hosted = http2.connect('https://127.0.0.1:' + port, tls);
    hosted.on('error', function () {});
    const differs = await withHost(hosted, 'evil.example', authority);
    note(differs.status === 400 && lastRes && lastRes[MARK] === 'STS-HTTP-0024',
         '9. :authority and host naming different hosts is refused 400 ' +
         'with STS-HTTP-0024', differs.status + ' ' +
         (lastRes && lastRes[MARK]) + ' ' + differs.body.slice(0, 120));
    const same = await withHost(hosted, authority.toUpperCase(),
                              authority);
    note(same.status === 200,
         '9. the same host in another case is not a difference', same.status);
    const fromAuthority = await withHost(hosted, undefined);
    note(fromAuthority.status === 200 && lastRes &&
         lastRes.req && lastRes.req.headers.host === authority,
         '9. with no host, the host is the :authority',
         fromAuthority.status + ' ' +
         (lastRes && lastRes.req && lastRes.req.headers.host));
    const H2 = require(ROOT_DIR + '/common/http2_express');
    const dflt = { ':authority': 'sts.example', ':scheme': 'https',
                   host: 'sts.example:443' };
    note(H2.hostProblem(dflt) === false &&
         H2.hostProblem({ ':authority': 'a.example', host: 'b.example' }),
         '9. a default port spelled out is not a difference; another host is',
         JSON.stringify(dflt));
    // And request_pool.proxy() asks it itself, on a request no adapted app
    // saw first.
    const raw = http2.createSecureServer({
      allowHTTP1: true, cert: own.certPem, key: own.privateKeyPem },
    function (req, res) {
      lastRes = res;
      pool.proxy(entry, req, res, 0, 0);
    });
    await new Promise(function (r) { raw.listen(0, '127.0.0.1', r); });
    const rawSession = http2.connect('https://127.0.0.1:' +
      raw.address().port, { rejectUnauthorized: false });
    rawSession.on('error', function () {});
    const proxiedBad = await withHost(rawSession, 'evil.example',
                                      '127.0.0.1:' + raw.address().port);
    note(proxiedBad.status === 400 && lastRes[MARK] === 'STS-HTTP-0024',
         '9. request_pool.proxy() refuses the same request 400 with ' +
         'STS-HTTP-0024', proxiedBad.status + ' ' + lastRes[MARK]);
    rawSession.close();
    raw.close();
    hosted.close();

    // 11. `tls.http2` as the strings "true" and "false" (#1304): a custom
    // listener's definition may say either, as well as on and off, and each
    // decides that listener's offer over the service's http.http2.
    for (const value of ['true', 'false', true, false]) {
      const one = define(value);
      note(!one.problem && one.listeners.length === 1,
           '11. a custom listener\'s tls.http2 ' + JSON.stringify(value) +
           ' is accepted', JSON.stringify(one.problem));
    }
    let customSet = '';
    try {
      config.setOverride('listeners.custom', JSON.stringify([
        { id: 'h2true', port: 9556, publicBaseUrl: 'https://t.example.com',
          tls: { http2: 'true' } },
        { id: 'h2false', port: 9557, publicBaseUrl: 'https://f.example.com',
          tls: { http2: 'false' } }]));
    } catch (e) {
      customSet = String((e && e.message) || e);
    }
    note(!customSet && listenerMap.listenerById('h2true') &&
         listenerMap.listenerById('h2false'),
         '11. two custom listeners saying "true" and "false" are defined',
         customSet);
    const offerOf = function (id) {
      return tlsServer.httpPolicyFor('custom', id).http2;
    };
    note(offerOf('h2true') === true && offerOf('h2false') === false,
         '11. "true" offers h2 and "false" does not, the service\'s on',
         offerOf('h2true') + ' / ' + offerOf('h2false'));
    config.setOverride('http.http2', 'false');
    settle();
    note(offerOf('h2true') === true && offerOf('h2false') === false &&
         offerOf('nobody') === false,
         '11. and with the service\'s off, "true" still offers it, "false" ' +
         'still does not, and a listener saying nothing follows the service',
         offerOf('h2true') + ' / ' + offerOf('h2false') + ' / ' +
         offerOf('nobody'));
    // On real servers registered as those two listeners, what a client
    // offering both protocols is given.
    const alpnOn = async function (id) {
      const probe = http2.createSecureServer({
        allowHTTP1: true, cert: own.certPem, key: own.privateKeyPem },
      function (req, res) {
        res.end('ok');
      });
      const unregister = tlsServer.registerHttpListener(probe, 'custom', id);
      await new Promise(function (r) { probe.listen(0, '127.0.0.1', r); });
      const chosen = await new Promise(function (resolve) {
        const socket = tlsModule.connect({
          host: '127.0.0.1', port: probe.address().port,
          ALPNProtocols: ['h2', 'http/1.1'], rejectUnauthorized: false },
        function () {
          const got = socket.alpnProtocol;
          socket.end();
          resolve(got);
        });
        socket.on('error', function (e) {
          resolve('error: ' + (e && e.message));
        });
      });
      unregister();
      probe.close();
      return chosen;
    };
    const trueChose = await alpnOn('h2true');
    config.clearOverride('http.http2');
    settle();
    const falseChose = await alpnOn('h2false');
    note(trueChose === 'h2' && falseChose === 'http/1.1',
         '11. so a handshake on "true" (the service off) negotiates h2, and ' +
         'on "false" (the service on) http/1.1', trueChose + ' / ' +
         falseChose);
    config.setOverride('http.http2', 'true');
    settle();
    note(config.value('http.http2') === true &&
         tlsServer.httpPolicyFor('main').http2 === true,
         '11. http.http2 itself written as the string "true" is on',
         JSON.stringify(config.value('http.http2')));
    config.clearOverride('http.http2');
    config.clearOverride('listeners.custom');
    settle();

    // 12. The debugger's API proxy over HTTP/2: the debugger listener's own
    // app, on the kind of server debugger_server.ts builds, forwarding to a
    // stand-in api process that says what reached it.
    const dbg = require(ROOT_DIR + '/debugger/debugger_server');
    const apiProcess = require(ROOT_DIR + '/debugger/debugger_api_process');
    const apiSocket = pathModule.join(os.tmpdir(), 'sts-h2-dbg-' +
                                      process.pid + '.sock');
    const apiSeen = [];
    const fakeApi = http.createServer(function (req, res) {
      let body = '';
      req.setEncoding('utf8');
      req.on('data', function (d) { body += d; });
      req.on('end', function () {
        apiSeen.push({ method: req.method, url: req.url,
                       headers: req.headers, body: body });
        res.setHeader('Content-Type', 'application/json');
        res.end('{"ok":true}');
      });
    });
    await new Promise(function (r) { fakeApi.listen(apiSocket, r); });
    const stub = {
      ready: function () { return true; },
      socketPath: function () { return apiSocket; },
      status: function () {
        return { state: 'running', uiUrl: 'http://child.invalid:1',
                 allowList: false, allowedRanges: [] };
      },
      updateAnchor: function () { return false; }
    };
    const saved = {};
    Object.keys(stub).forEach(function (k) {
      saved[k] = apiProcess[k];
      apiProcess[k] = stub[k];
    });
    const dbgServer = http2.createSecureServer({
      allowHTTP1: true, cert: own.certPem, key: own.privateKeyPem }, dbg.app);
    dbgServer.prependListener('request',
      require(ROOT_DIR + '/common/http2_framing').markFramedBody);
    let dbgRes = null;
    dbgServer.prependListener('request', function (req, res) {
      dbgRes = res;
    });
    await new Promise(function (r) { dbgServer.listen(0, '127.0.0.1', r); });
    const dbgAuthority = '127.0.0.1:' + dbgServer.address().port;
    const dbgSession = http2.connect('https://' + dbgAuthority,
                                     { rejectUnauthorized: false });
    dbgSession.on('error', function () {});
    // `POST /api/samlacs` is a landing: no credential, straight to the
    // forwarder (tests/debugger_server.js B).
    const toDebugger = function (who, host) {
      return new Promise(function (resolve) {
        const headers = { ':method': 'POST', ':path': '/api/samlacs',
                          ':authority': dbgAuthority,
                          'content-type': 'application/x-www-form-urlencoded',
                          accept: 'application/json' };
        if (host !== undefined) {
          headers.host = host;
        }
        const st = who.request(headers);
        let status = 0;
        let body = '';
        st.on('response', function (h) { status = h[':status']; });
        st.setEncoding('utf8');
        st.on('data', function (d) { body += d; });
        st.on('end', function () { resolve({ status: status, body: body }); });
        st.on('error', function (e) {
          resolve({ status: 0, body: String(e && e.message) });
        });
        st.end('SAMLResponse=abc');
      });
    };
    const dbgGood = await toDebugger(dbgSession);
    const reached = apiSeen[apiSeen.length - 1] || { headers: {} };
    const reachedNames = Object.keys(reached.headers);
    note(dbgGood.status === 200 && reached.url === '/samlacs' &&
         reached.body === 'SAMLResponse=abc',
         '12. an HTTP/2 POST to the debugger\'s /api reaches the api process ' +
         'with the prefix stripped and its body whole',
         dbgGood.status + ' ' + JSON.stringify(reached).slice(0, 300));
    note(reachedNames.length > 0 && reachedNames.every(function (n) {
      return n.charAt(0) !== ':';
    }) && reached.headers.host === dbgAuthority &&
         reached.headers['x-forwarded-host'] === dbgAuthority,
         '12. with no pseudo-header, and its :authority as host and as the ' +
         'forwarded host', reachedNames.join(',') + ' host=' +
         reached.headers.host);
    const seenBefore = apiSeen.length;
    const dbgBad = await toDebugger(dbgSession, 'evil.example');
    note(dbgBad.status === 400 && dbgRes && dbgRes[MARK] === 'STS-HTTP-0024' &&
         apiSeen.length === seenBefore,
         '12. :authority and host naming different hosts is refused 400 ' +
         'with STS-HTTP-0024 on the debugger listener, and never reaches ' +
         'the api', dbgBad.status + ' ' + (dbgRes && dbgRes[MARK]) + ' ' +
         (apiSeen.length - seenBefore) + ' forwarded');
    const dbgSame = await toDebugger(dbgSession, dbgAuthority.toUpperCase());
    note(dbgSame.status === 200,
         '12. the same host in another case is forwarded', dbgSame.status);
    // And the forwarder asks it ITSELF (debugger_server.ts forward()),
    // because the api believes the host it is sent: here a host that
    // changed after the app's own check saw the request, on an instance
    // built over the stand-in.
    const forwarder = new dbg.DebuggerServer(Object.assign(
      dbg.DebuggerServer.defaultDeps(), { apiProcess: stub }));
    const changed = H2.adapt(express());
    changed.use(function (req, res) {
      req.headers.host = 'evil.example';
      dbgRes = res;
      forwarder.forward(req, res);
    });
    const changedServer = http2.createSecureServer({
      allowHTTP1: true, cert: own.certPem, key: own.privateKeyPem }, changed);
    await new Promise(function (r) {
      changedServer.listen(0, '127.0.0.1', r);
    });
    const changedSession = http2.connect('https://127.0.0.1:' +
      changedServer.address().port, { rejectUnauthorized: false });
    changedSession.on('error', function () {});
    const forwardBefore = apiSeen.length;
    const changedAnswer = await new Promise(function (resolve) {
      const st = changedSession.request({ ':method': 'GET',
                                          ':path': '/api/healthcheck',
                                          accept: 'application/json' });
      let status = 0;
      st.on('response', function (h) { status = h[':status']; });
      st.resume();
      st.on('end', function () { resolve(status); });
      st.on('error', function (e) { resolve(String(e && e.code)); });
      st.end();
    });
    note(changedAnswer === 400 && dbgRes[MARK] === 'STS-HTTP-0024' &&
         apiSeen.length === forwardBefore,
         '12. the forwarder refuses a host that no longer matches the ' +
         ':authority itself, 400 with STS-HTTP-0024, forwarding nothing',
         changedAnswer + ' ' + dbgRes[MARK]);
    changedSession.close();
    changedServer.close();
    dbgSession.close();
    dbgServer.close();
    Object.keys(saved).forEach(function (k) {
      apiProcess[k] = saved[k];
    });
    fakeApi.close();
    try {
      require('fs').unlinkSync(apiSocket);
    } catch (e) {
      // Already gone with the server; recorded rather than failed.
      note(true, '12. (the api socket was already gone: ' +
           String((e && e.message) || e) + ')', '');
    }

    // 13. CONNECT (RFC 9110 sections 9.1 and 9.3.6). This service is an
    // origin server and implements none, so 501, over either protocol, from
    // the refusal server.js installs on the main port; the application never
    // sees it (it has no path to route). Node's own answers were a bare 405
    // with no Allow over HTTP/2 and a dropped connection over HTTP/1.1.
    const ConnectRefusal = require(ROOT_DIR + '/common/connect_refusal');
    const fresh = http2.createSecureServer({
      allowHTTP1: true, cert: own.certPem, key: own.privateKeyPem }, app);
    ConnectRefusal.install(fresh, 'the probe');
    let connectRes = null;
    fresh.on('connect', function (req, res) {
      connectRes = res;
    });
    let appSaw = 0;
    fresh.prependListener('request', function () {
      appSaw += 1;
    });
    await new Promise(function (r) { fresh.listen(0, '127.0.0.1', r); });
    const freshPort = fresh.address().port;
    const freshSession = http2.connect('https://127.0.0.1:' + freshPort,
                                       { rejectUnauthorized: false });
    freshSession.on('error', function () {});
    const connectTo = function (target) {
      return new Promise(function (resolve) {
        const st = freshSession.request({ ':method': 'CONNECT',
                                          ':authority': target });
        let status = 0;
        let got = {};
        let body = '';
        st.on('response', function (h) {
          status = h[':status'];
          got = h;
        });
        st.setEncoding('utf8');
        st.on('data', function (d) { body += d; });
        st.on('end', function () {
          resolve({ status: status, headers: got, body: body });
        });
        st.on('error', function (e) {
          resolve({ status: 0, headers: {}, body: String(e && e.code) });
        });
        st.end();
      });
    };
    for (const target of ['example.com:443', '127.0.0.1:' + freshPort]) {
      const answer = await connectTo(target);
      note(answer.status === 501 &&
           answer.headers['cache-control'] === 'no-store' &&
           /frame-ancestors 'none'/.test(
             String(answer.headers['content-security-policy'])) &&
           !/STS-/.test(answer.body) &&
           connectRes && connectRes[MARK] === 'STS-HTTP-0025',
           '13. an HTTP/2 CONNECT to ' + target + ' is answered 501, ' +
           'no-store, frame-ancestors kept, marked STS-HTTP-0025 and the ' +
           'code not sent', answer.status + ' ' +
           JSON.stringify(answer.headers) + ' ' + answer.body.slice(0, 120));
    }
    note(appSaw === 0, '13. and the application saw neither', appSaw);
    const afterConnect = await new Promise(function (resolve) {
      const st = freshSession.request({ ':path':
                                        '/.well-known/openid-configuration' });
      let status = 0;
      st.on('response', function (h) { status = h[':status']; });
      st.resume();
      st.on('end', function () { resolve(status); });
      st.on('error', function (e) { resolve(String(e && e.code)); });
      st.end();
    });
    note(afterConnect === 200,
         '13. while the same session goes on answering', afterConnect);
    const overOne = await new Promise(function (resolve) {
      const socket = tlsModule.connect({
        host: '127.0.0.1', port: freshPort, ALPNProtocols: ['http/1.1'],
        rejectUnauthorized: false }, function () {
        socket.write('CONNECT example.com:443 HTTP/1.1\r\n' +
                     'Host: example.com:443\r\n\r\n');
      });
      let got = '';
      socket.setEncoding('utf8');
      socket.on('data', function (d) { got += d; });
      socket.on('close', function () { resolve(got); });
      socket.on('error', function (e) {
        resolve(got + ' error: ' + (e && e.message));
      });
      setTimeout(function () { socket.destroy(); }, 5000);
    });
    note(/^HTTP\/1\.1 501 /.test(overOne) && /Connection: close/i
      .test(overOne) && /frame-ancestors 'none'/.test(overOne) &&
         !/STS-/.test(overOne),
         '13. and an HTTP/1.1 CONNECT on the same port is answered 501 ' +
         'and the connection closed, not dropped unanswered',
         JSON.stringify(overOne.slice(0, 200)));
    freshSession.close();
    fresh.close();

    // 14. `OPTIONS *` (RFC 9110 section 9.3.7; `:path: *`, RFC 9113 8.3.1):
    // the server as a whole. Answered by the application's CORS preflight,
    // 204, and never dispatched: no dispatch prefix — not even `*`, which
    // means every PATH — names it, and like the liveness probe it reads no
    // state (request_pool.js answeredAtOnce()).
    const starSession = http2.connect('https://127.0.0.1:' + port, tls);
    starSession.on('error', function () {});
    let starUrl = '';
    server.prependListener('request', function (req) {
      if (req.method === 'OPTIONS') {
        starUrl = req.url;
      }
    });
    const star = await new Promise(function (resolve) {
      const st = starSession.request({ ':method': 'OPTIONS', ':path': '*' });
      let status = 0;
      let got = {};
      st.on('response', function (h) {
        status = h[':status'];
        got = h;
      });
      st.resume();
      st.on('end', function () { resolve({ status: status, headers: got }); });
      st.on('error', function (e) {
        resolve({ status: String(e && e.code), headers: {} });
      });
      st.end();
    });
    note(star.status === 204 && starUrl === '*' &&
         /frame-ancestors 'none'/.test(
           String(star.headers['content-security-policy'])),
         '14. OPTIONS * over HTTP/2 reaches the application as * and is ' +
         'answered 204, frame-ancestors kept',
         star.status + ' url=' + starUrl);
    note(String(config.value('workers.dispatch')) === '*' &&
         pool.dispatched('*') === false &&
         pool.dispatched('/.well-known/openid-configuration') === true &&
         pool.dispatched('/healthcheck') === false,
         '14. and with workers.dispatch * it is not dispatched, as ' +
         '/healthcheck is not, while every path is',
         'dispatch=' + config.value('workers.dispatch') + ' * ' +
         pool.dispatched('*'));
    starSession.close();

    // 15. The Listeners page shows the stream cap beside HTTP/2 (#1304): the
    // view /admin-api/listeners answers carries it, and the page draws it.
    // This child runs with global.https off, so the main port's tab shows
    // no TLS rows (it is plain HTTP); a custom listener, always TLS, is the
    // tab drawn.
    const listenersAdmin = require(ROOT_DIR + '/admin-ui/listeners_admin');
    const ListenersPage = require(ROOT_DIR + '/admin-ui/web_listeners');
    config.setOverride('listenerMain.http2MaxConcurrentStreams', '7');
    config.setOverride('listeners.custom', JSON.stringify([
      { id: 'h2cap', port: 9558, publicBaseUrl: 'https://c.example.com',
        tls: { http2MaxConcurrentStreams: 9 } }]));
    settle();
    const view = listenersAdmin.listenersView();
    const mainRow = (view.listeners || []).filter(function (row) {
      return row.id === 'main';
    })[0] || {};
    const capRow = (view.custom || []).filter(function (row) {
      return row.id === 'h2cap';
    })[0] || {};
    note(mainRow.http && mainRow.http.http2MaxConcurrentStreams === 7 &&
         capRow.http && capRow.http.http2MaxConcurrentStreams === 9 &&
         capRow.http.http2 === true,
         '15. the listeners view carries each listener\'s stream cap, the ' +
         'main port\'s and a custom listener\'s',
         JSON.stringify(mainRow.http) + ' / ' + JSON.stringify(capRow.http));
    const drawn = ListenersPage.render(view);
    const tab = drawn.slice(drawn.indexOf('id="tab-custom-h2cap"'));
    note(tab.indexOf('<th>HTTP/2 offered</th><td><code>yes</code></td>' +
                     '</tr><tr><th>HTTP/2 streams at once per connection' +
                     '</th><td><code>9</code></td>') >= 0,
         '15. and the page draws it beside HTTP/2 offered in that ' +
         'listener\'s tab',
         JSON.stringify(tab.slice(tab.indexOf('HTTP/2'),
                                  tab.indexOf('HTTP/2') + 200)));
    config.clearOverride('listeners.custom');
    config.clearOverride('listenerMain.http2MaxConcurrentStreams');
    settle();

    // 10. The express module is untouched.
    const plain = express();
    note(plain.lazyrouter === express.application.lazyrouter &&
         app.lazyrouter !== express.application.lazyrouter &&
         /middleware\.init\(this\)/
           .test(String(express.application.lazyrouter)),
         '10. the adapter changes this app and not express.application',
         '');

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
  t.check(/const server = http2\.createSecureServer\(Object\.assign\(\{ allowHTTP1: true,/
    .test(server),
          '5. and so is every custom listener', '');
  const debuggerServer = fs.readFileSync(path.join(ROOT, 'debugger',
    'debugger_server.ts'), 'utf8').replace(/\s+/g, ' ');
  t.check(/http2\.createSecureServer\(Object\.assign\(\{ allowHTTP1: true \},/
    .test(debuggerServer) &&
          /const app = Http2Express\.adapt\(express\(\)\);/
            .test(debuggerServer) &&
          /server\.prependListener\('request', Http2Framing\.markFramedBody\);/
            .test(debuggerServer),
          '5. and the debugger\'s listener, with its own app adapted', '');
  t.check((server.match(/require\('\.\/common\/connect_refusal'\)\.install\(/g) ||
           []).length === 3 &&
          /ConnectRefusal\.install\(server, /.test(debuggerServer),
          '5. and a CONNECT is answered by common/connect_refusal.ts on the ' +
          'main port (TLS and plain), every custom listener and the ' +
          'debugger\'s (#1304)', '');
  t.check(/const app = require\('\.\/http2_express'\)\.adapt\(express\(\)\);/
    .test(app),
          '5. and common/app.js adapts the application', '');
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'),
                                         'utf8'));
  t.check(!(pkg.dependencies || {})['http2-express'],
          '5. and no third-party wrapper patches express for it', '');
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
            'on one session, the lingering close leaving an HTTP/2 stream ' +
            'alone, http.http2 on by default and turned off in the ' +
            'next handshake, the HTTP/2 stream cap, idle timeout and ' +
            'request count, :authority against host there and on the ' +
            'debugger\'s proxy, tls.http2 as "true" and "false", CONNECT ' +
            'answered 501, OPTIONS * kept in the front process, and the ' +
            'stream cap on the Listeners page',
  run: run
};
