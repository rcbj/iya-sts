// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: http2_express.ts
//
// ---------------------------------------------------------------------------
// EXPRESS 4 ON AN HTTP/2 REQUEST, FOR THE APPS THIS SERVICE BUILDS AND NO
// OTHER (#407, 2026-10-19).
//
// Express's own `init` middleware sets every request's prototype to the
// app's `request` (which derives from `http.IncomingMessage`) and every
// response's to its `response` (from `http.ServerResponse`). Node's
// `Http2ServerRequest` and `Http2ServerResponse` are not those classes and
// keep their state behind their OWN prototypes, so plain express throws
// `Cannot read properties of undefined (reading 'readable')` on the first
// HTTP/2 body it reads.
//
// **WHY NOT `http2-express`, which #703 used first.** It replaced
// `express.application.lazyrouter` — on the SHARED express module, so every
// express app in the process, including any a library builds, ran its
// middleware — and named itself in `X-Powered-By`. This class changes
// nothing on the express module: `adapt(app)` gives ONE app an own
// `lazyrouter` (express 4's, with a protocol-aware `init` in place of
// express's) and two prototypes of its own for an HTTP/2 request and
// response, each carrying express's methods and getters over node's HTTP/2
// classes. An HTTP/1.1 request gets exactly what express would have given it.
// `common/app.js` adapts the shared app and `debugger/debugger_server.ts` the
// debugger's; nothing else is adapted, and nothing else needs to be.
//
// **THE HOST IS THE AUTHORITY (RFC 9113 section 8.3.1).** An HTTP/2 request
// carries its authority in `:authority`, and everything here that reads a
// host (`req.hostname`, the issuer a realm derives from the request, the
// request pool's forward) reads `host`. So `host` is built from `:authority`
// before any middleware runs; and a request carrying BOTH that name
// different entities is malformed — "a server SHOULD treat a request as
// malformed if it contains a Host header field that identifies an entity
// that differs from the entity in the ':authority' pseudo-header field" —
// and is refused 400, STS-HTTP-0024, before the realm middleware, because a
// host the two halves of one request disagree about is the start of a
// cache-poisoning or virtual-host confusion and has no legitimate sender.
//
// **A STATIC UTILITY CLASS** (rcbj's rule for small helpers, #50). It
// requires express, node's http2 and the error-code table, so the request
// pool, which may require only leaves, can share `hostProblem()`.
// ---------------------------------------------------------------------------

import http2 = require('http2');
import express = require('express');
import errorCodes = require('./error_codes');

// The default port of each scheme, which an authority may or may not spell
// out and still name the same origin (RFC 9110 section 4.2).
const DEFAULT_PORT = { https: ':443', http: ':80' };

/**
 * Makes one express 4 app answer HTTP/2 requests, and holds the rule about
 * an HTTP/2 request's authority and host.
 *
 * A static utility class; it holds no state of its own.
 */
export = class Http2Express {
  /**
   * Whether a request arrived over HTTP/2: node's compatibility request,
   * whichever prototype it has been given since.
   *
   * @param req - the request
   * @returns true for an HTTP/2 request
   */
  // Runs on every request, so no Entering/Leaving pair — the hot-path
  // exception the code style allows, stated as it requires.
  static isHttp2(req: any): boolean {
    return req instanceof http2.Http2ServerRequest;
  }

  /**
   * An authority as a comparable name: lower case, the scheme's default port
   * dropped.
   *
   * @param value - a `:authority` or `host` value
   * @param scheme - the request's `:scheme`
   * @returns the normalised authority
   */
  // Hot path; see isHttp2().
  static normalise(value: any, scheme: any): string {
    let out = String(value).trim().toLowerCase();
    const dflt = DEFAULT_PORT[String(scheme || 'https').toLowerCase()];
    if (dflt && out.length > dflt.length &&
        out.slice(-dflt.length) === dflt) {
      out = out.slice(0, -dflt.length);
    }
    return out;
  }

  /**
   * Brings an HTTP/2 request's `host` into line with its `:authority`: sets
   * it from `:authority` when the request has none, and says whether the
   * two name different entities, which makes the request malformed (RFC
   * 9113 section 8.3.1). Leaves an HTTP/1.1 request's headers alone.
   *
   * @param headers - the request's headers, changed in place
   * @returns true when the request must be refused
   */
  // Hot path; see isHttp2().
  static hostProblem(headers: any): boolean {
    if (!headers) {
      return false;
    }
    const authority = headers[':authority'];
    if (authority === undefined || authority === '') {
      return false;
    }
    if (headers.host === undefined || headers.host === '') {
      headers.host = String(authority);
      return false;
    }
    const scheme = headers[':scheme'];
    return Http2Express.normalise(headers.host, scheme) !==
           Http2Express.normalise(authority, scheme);
  }

  /**
   * Refuses a request whose `:authority` and `host` disagree: 400, a plain
   * body, STS-HTTP-0024 on the response for the call log.
   *
   * @param res - the response, not yet started
   */
  static refuseHostMismatch(res: any): void {
    errorCodes.mark(res, 'STS-HTTP-0024');
    res.statusCode = 400;
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    res.end('The request\'s :authority and Host name different hosts ' +
            '(RFC 9113 section 8.3.1).\n');
  }

  /**
   * Makes one express 4 app answer HTTP/2 as well as HTTP/1.1, by giving it
   * an own `lazyrouter` whose `init` middleware picks the prototypes by the
   * request's protocol. Must be called before the app's first `use()` or
   * route. The express module itself is not changed.
   *
   * @param app - the app, as `express()` returned it
   * @returns the same app
   */
  static adapt(app: any): any {
    const proto = function (base: any, from: any): any {
      const out = Object.create(base);
      Reflect.ownKeys(from).forEach(function (key) {
        Object.defineProperty(out, key,
                              Object.getOwnPropertyDescriptor(from, key));
      });
      return Object.create(out, {
        app: { configurable: true, enumerable: true, writable: true,
               value: app } });
    };
    // Built from the app's own prototypes' parents — express's `request` and
    // `response` — so they carry exactly the methods an HTTP/1.1 request
    // gets.
    const h2Request = proto(http2.Http2ServerRequest.prototype,
                            Object.getPrototypeOf(app.request));
    const h2Response = proto(http2.Http2ServerResponse.prototype,
                             Object.getPrototypeOf(app.response));
    const anyExpress: any = express;
    // EXPRESS 4's `lazyrouter`, as an own property of this app: the router,
    // the query parser, and then `init` — express's own six lines with the
    // prototype chosen by protocol, and the authority rule ahead of them.
    app.lazyrouter = function lazyrouter() {
      if (this._router) {
        return;
      }
      const self = this;
      this._router = new anyExpress.Router({
        caseSensitive: this.enabled('case sensitive routing'),
        strict: this.enabled('strict routing')
      });
      this._router.use(anyExpress.query(this.get('query parser fn')));
      // Hot path, once per request: no Entering/Leaving pair.
      this._router.use(function expressInit(req, res, next) {
        const h2 = Http2Express.isHttp2(req);
        if (self.enabled('x-powered-by')) {
          res.setHeader('X-Powered-By', 'Express');
        }
        req.res = res;
        res.req = req;
        req.next = next;
        Object.setPrototypeOf(req, h2 ? h2Request : self.request);
        Object.setPrototypeOf(res, h2 ? h2Response : self.response);
        res.locals = res.locals || Object.create(null);
        if (h2 && Http2Express.hostProblem(req.headers)) {
          Http2Express.refuseHostMismatch(res);
          return;
        }
        next();
      });
    };
    return app;
  }
};
