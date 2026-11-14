// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: http2_framing.ts
//
// ---------------------------------------------------------------------------
// AN HTTP/2 REQUEST BODY WITH NO `content-length` IS STILL A BODY (#407,
// 2026-10-19).
//
// HTTP/2 frames a body itself: DATA frames until one carries END_STREAM, so
// `content-length` is optional (RFC 9113 section 8.1.1) and
// `transfer-encoding` is forbidden (section 8.2.2; node refuses a request
// that sends it). Every reader of a body in this service decides whether
// there IS one the HTTP/1.1 way — body-parser's `type-is.hasBody()` asks for
// `transfer-encoding` or a numeric `content-length` — so a form posted over
// HTTP/2 without a length was read as no body at all: the token endpoint
// answered `grant_type '' is not supported`, through the request worker as
// well as in the front process. curl always sends a length; a client need not.
//
// The answer is to say, in the request's headers, what the framing already
// says: a request whose HEADERS frame did not end the stream has a body of
// framed length, which is what `transfer-encoding: chunked` means to an
// HTTP/1.1 reader. It is set only where the client sent no length, and it
// cannot meet a client's own value, because an HTTP/2 client cannot send one.
// `common/request_pool.js` forwards it to a worker as the chunked body node's
// client sends there anyway.
//
// Installed by `server.js` on the main port's `request` event, AHEAD of the
// application, because nothing may be registered above the realm middleware
// (`common/app.js`), and this has to happen before anything reads a body.
//
// **A STATIC UTILITY CLASS** — rcbj's rule for the small helpers (#50): it
// holds no state and takes no dependencies.
// ---------------------------------------------------------------------------

import http2 = require('http2');

/**
 * Makes an HTTP/2 request's framed body visible to HTTP/1.1 body readers.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
export = class Http2Framing {
  // Runs once per request on the main port, before the application, so no
  // Entering/Leaving pair — the hot-path exception the code style allows,
  // stated here as it requires.
  /**
   * Marks an HTTP/2 request that has a body and no `content-length` as
   * `transfer-encoding: chunked`. Leaves an HTTP/1.1 request, a request with
   * no body (END_STREAM on its HEADERS frame), and one with a length alone.
   *
   * @param req - the request, as the main port's `request` event hands it
   */
  static markFramedBody(req: http2.Http2ServerRequest |
                        { httpVersionMajor: number }): void {
    const h2 = req as http2.Http2ServerRequest;
    if (req.httpVersionMajor !== 2 || !h2.stream ||
        h2.stream.endAfterHeaders) {
      return;
    }
    if (h2.headers['content-length'] === undefined &&
        h2.headers['transfer-encoding'] === undefined) {
      h2.headers['transfer-encoding'] = 'chunked';
    }
  }
};
