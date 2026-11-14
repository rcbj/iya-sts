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
// **A LARGE BODY IS HANDED TO THE STREAM A SLICE AT A TIME (#1725,
// 2026-11-13).** `res.send()` and `res.json()` end the response with the
// whole body in one `end(chunk)`, and node's HTTP/2 stream takes that chunk
// whole: it sits in the SESSION's outbound memory until the client's flow
// control lets the last frame of it out. Every stream on one connection
// shares that memory, and node holds it to `maxSessionMemory` (10 MB by
// default). Two `GET /admin-api/openapi.json` answers (6.5 MB each) in
// flight on one browser's connection are past it, and from then on node
// refuses every new stream on that connection with RST_STREAM
// ENHANCE_YOUR_CALM — and, past its count of refused streams, tears the
// session down, which leaves a stream whose headers had arrived with a body
// that never ends: the console's `res.json()` waiting for ever, measured
// as 5 hangs in 124 runs with HTTP/2 on and none in 70 with it off. A body
// that went through `request_pool.proxy()`'s pipe never did this, because
// a pipe writes 64 KiB at a time and waits for `drain`.
//
// So an HTTP/2 response's `write()` and `end()` do what that pipe does for
// a chunk over `SLICE_BYTES`: the chunk is written a slice at a time, each
// after the stream has drained, and `end()` is called once the last slice
// is written. A body that fits in one slice goes straight to node's own
// `write()` and `end()`, as before, and an HTTP/1.1 response is untouched
// (node's socket has no session to share). `writableEnded` and `finished`
// read true from the `end()` call, as node's do, so nothing that asks
// whether a response has been ended sees the slices still going out.
// `tests/http2_large_body.js` holds it.
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

// The most of a body an HTTP/2 response hands its stream at once: the size
// of the chunks `request_pool.proxy()`'s pipe writes (#1725).
const SLICE_BYTES = 64 * 1024;

// Where a response keeps the slices still to be written, on the response.
const PACING = Symbol('sts.http2.pacing');

// Node's own HTTP/2 response methods, which the paced ones call.
const BASE_WRITE = http2.Http2ServerResponse.prototype.write;
const BASE_END = http2.Http2ServerResponse.prototype.end;
const BASE_ENDED = Object.getOwnPropertyDescriptor(
  http2.Http2ServerResponse.prototype, 'writableEnded');
const BASE_FINISHED = Object.getOwnPropertyDescriptor(
  http2.Http2ServerResponse.prototype, 'finished');

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
   * The bytes of a body chunk, or null for one node's own `write()` should
   * judge (an absent chunk, or something that is not text or bytes).
   *
   * @param chunk - what the caller wrote
   * @param encoding - its encoding, when it is text
   * @returns the bytes, or null
   */
  // Hot path, once per write of an HTTP/2 body; see isHttp2().
  static bytesOf(chunk: any, encoding: any): Buffer | null {
    if (typeof chunk === 'string') {
      return Buffer.from(chunk, typeof encoding === 'string' ? encoding as
                         BufferEncoding : 'utf8');
    }
    if (chunk instanceof Uint8Array) {
      return Buffer.isBuffer(chunk) ? chunk
        : Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength);
    }
    return null;
  }

  /**
   * How many bytes a chunk is, without copying it, or -1 for one node's own
   * `write()` should judge.
   *
   * @param chunk - what the caller wrote
   * @param encoding - its encoding, when it is text
   * @returns its length in bytes, or -1
   */
  // Hot path; see bytesOf().
  static sizeOf(chunk: any, encoding: any): number {
    if (typeof chunk === 'string') {
      return Buffer.byteLength(chunk, typeof encoding === 'string' ?
                               encoding as BufferEncoding : 'utf8');
    }
    if (chunk instanceof Uint8Array) {
      return chunk.byteLength;
    }
    return -1;
  }

  /**
   * A response's pacing state, made on first use: the slices still to be
   * written, the `end()` waiting behind them, and whether a caller was told
   * to wait for `drain`. Dropped when the stream closes.
   *
   * @param res - an HTTP/2 response
   * @returns its state
   */
  // Hot path; see bytesOf().
  static pacing(res: any): any {
    let state = res[PACING];
    if (!state) {
      state = { queue: [], ending: null, endCalled: false, waiting: false,
                told: false };
      res[PACING] = state;
      res.once('close', function () {
        state.queue = [];
        state.ending = null;
      });
    }
    return state;
  }

  /**
   * Queues a chunk as slices of at most SLICE_BYTES, the caller's callback
   * on the last.
   *
   * @param state - the response's pacing state
   * @param bytes - the chunk
   * @param cb - the caller's write callback, or undefined
   */
  // Hot path; see bytesOf().
  static enqueue(state: any, bytes: Buffer, cb: any): void {
    for (let at = 0; at < bytes.length; at += SLICE_BYTES) {
      const part = bytes.subarray(at, Math.min(at + SLICE_BYTES,
                                               bytes.length));
      state.queue.push({ bytes: part,
                         cb: at + SLICE_BYTES >= bytes.length ? cb :
                           undefined });
    }
  }

  /**
   * Writes queued slices until the stream asks to wait, then waits for its
   * `drain`; with the queue empty, makes the `end()` that was waiting.
   *
   * @param res - an HTTP/2 response
   * @returns true when everything queued has been handed to the stream
   *   and the stream did not ask to wait
   */
  // Hot path, once per slice; see bytesOf().
  static pump(res: any): boolean {
    const state = res[PACING];
    while (state.queue.length) {
      const stream = res.stream;
      if (!stream || stream.destroyed || stream.closed) {
        // The client went, or the stream was reset: nothing more can be
        // sent, and node's own write would only throw.
        state.queue = [];
        state.ending = null;
        return false;
      }
      const part = state.queue.shift();
      if (!BASE_WRITE.call(res, part.bytes, part.cb)) {
        state.waiting = true;
        res.once('drain', function () {
          state.waiting = false;
          if (Http2Express.pump(res) && state.told) {
            // A caller told to wait heard the drain that resumed this
            // queue before the queue had emptied, and the stream did not
            // ask to wait again: tell it now, or a pipe waits for ever.
            // Defensive: a 64 KiB slice is over node's 16 KiB stream
            // high-water mark, so today the last write always asks to wait
            // and the real `drain` that follows reaches the caller too.
            state.told = false;
            res.emit('drain');
          }
        });
        return false;
      }
    }
    if (state.ending) {
      const ending = state.ending;
      state.ending = null;
      BASE_END.call(res, ending.cb);
    }
    return true;
  }

  /**
   * An HTTP/2 response's `write()`: node's own for a chunk that fits in a
   * slice with nothing queued, and otherwise the chunk queued as slices
   * written as the stream drains (#1725). Returns false, as node's does,
   * when the caller should wait for `drain`.
   *
   * @param res - the response
   * @param chunk - the chunk
   * @param encoding - its encoding, or the callback
   * @param cb - the callback
   * @returns whether the caller may write more now
   */
  // Hot path: every chunk of every HTTP/2 body. No Entering/Leaving pair,
  // for isHttp2()'s reason.
  static pacedWrite(res: any, chunk: any, encoding?: any, cb?: any): boolean {
    const state = res[PACING];
    const pending = !!(state && (state.queue.length || state.waiting));
    if (state && state.endCalled) {
      // Node's own answer to a write after end.
      return BASE_WRITE.call(res, chunk, encoding, cb);
    }
    const size = Http2Express.sizeOf(chunk, encoding);
    if (size < 0 || (!pending && size <= SLICE_BYTES)) {
      return BASE_WRITE.call(res, chunk, encoding, cb);
    }
    const callback = typeof encoding === 'function' ? encoding : cb;
    const paced = Http2Express.pacing(res);
    Http2Express.enqueue(paced, Http2Express.bytesOf(chunk, encoding),
                         callback);
    if (!pending && Http2Express.pump(res)) {
      return true;
    }
    paced.told = true;
    return false;
  }

  /**
   * An HTTP/2 response's `end()`: node's own when nothing is queued and the
   * last chunk fits in a slice, and otherwise the chunk queued as slices
   * and the end made once the last is written (#1725).
   *
   * @param res - the response
   * @param args - `end()`'s arguments: a chunk, an encoding, a callback
   * @returns the response
   */
  // Hot path: once per HTTP/2 response. See pacedWrite().
  static pacedEnd(res: any, args: any[]): any {
    let chunk = args[0];
    let encoding = args[1];
    let cb = args[2];
    if (typeof chunk === 'function') {
      cb = chunk;
      chunk = undefined;
      encoding = undefined;
    } else if (typeof encoding === 'function') {
      cb = encoding;
      encoding = undefined;
    }
    const state = res[PACING];
    const pending = !!(state && (state.queue.length || state.waiting));
    const size = chunk === undefined || chunk === null ? 0
      : Http2Express.sizeOf(chunk, encoding);
    if ((state && state.endCalled) || size < 0 ||
        (!pending && size <= SLICE_BYTES)) {
      return BASE_END.apply(res, args);
    }
    const paced = Http2Express.pacing(res);
    if (size > 0) {
      Http2Express.enqueue(paced, Http2Express.bytesOf(chunk, encoding),
                           undefined);
    }
    paced.ending = { cb: cb };
    paced.endCalled = true;
    if (!paced.waiting) {
      Http2Express.pump(res);
    }
    return res;
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
    // A LARGE BODY A SLICE AT A TIME (#1725), on this app's HTTP/2
    // responses only; see the header. Hot path: no Entering/Leaving pair.
    Object.defineProperties(h2Response, {
      write: { configurable: true, writable: true,
               value: function write(this: any, chunk: any, encoding?: any,
                                     cb?: any): boolean {
                 return Http2Express.pacedWrite(this, chunk, encoding, cb);
               } },
      end: { configurable: true, writable: true,
             value: function end(this: any, ...args: any[]): any {
               return Http2Express.pacedEnd(this, args);
             } },
      writableEnded: { configurable: true,
                       get: function (this: any): boolean {
                         const state = this[PACING];
                         return !!(state && state.endCalled) ||
                           !!(BASE_ENDED && BASE_ENDED.get &&
                              BASE_ENDED.get.call(this));
                       } },
      finished: { configurable: true,
                  get: function (this: any): boolean {
                    const state = this[PACING];
                    return !!(state && state.endCalled) ||
                      !!(BASE_FINISHED && BASE_FINISHED.get &&
                         BASE_FINISHED.get.call(this));
                  } }
    });
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
