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
            'request count, and :authority against host',
  run: run
};
