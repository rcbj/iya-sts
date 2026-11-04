// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: connect_refusal.ts
//
// ---------------------------------------------------------------------------
// CONNECT IS ANSWERED 501 ON EVERY HTTP LISTENER (#1304, 2026-11-04).
//
// This service is an origin server and never a proxy, so it implements no
// CONNECT (RFC 9110 section 9.3.6), and RFC 9110 section 9.1 says what an
// origin server answers a method it does not implement: 501 (Not
// Implemented). Node never hands a CONNECT to the application — its target
// is an authority (`:authority` alone in HTTP/2, RFC 9113 section 8.5; the
// authority form in HTTP/1.1, RFC 9112 section 3.2.3), so it has no path an
// express router could read — and with no `connect` listener on the server
// node answered on its own, differently per protocol, and wrongly in both:
//
//   * HTTP/2: a bare 405 with no `Allow`, which RFC 9110 section 15.5.6 says
//     a 405 MUST carry, and no security header of this service's;
//   * HTTP/1.1: no answer at all — the connection was destroyed.
//
// `tests/main_port_http2.js` section 11 found both. `install()` gives a
// listener a `connect` listener that answers 501 over either, with
// `Cache-Control: no-store` and a policy carrying `frame-ancestors 'none'`
// (the root CLAUDE.md's one clause no page may drop), the response marked
// `STS-HTTP-0025`. `server.js` installs it on the main port, plain or TLS,
// and on each custom listener; `debugger/debugger_server.ts` on its own.
//
// RECORDED SPARINGLY: a CONNECT is what a scanner sends, so the first is
// logged under its code and the rest are counted into one line a minute at
// most — rcbj's rule for a refusal that can repeat per event. No timer: the
// count is told when the next one arrives after the minute.
//
// **A STATIC UTILITY CLASS** (#50): it takes no dependencies but the logger
// and the error codes, and holds only the count above.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');
import config = require('./config');
import errorCodes = require('./error_codes');

const log = bunyan.createLogger({ name: 'sts-connect-refusal' });
config.registerLogger(log);

const BODY = 'CONNECT is not implemented here: this is an origin server, ' +
             'not a proxy (RFC 9110 sections 9.1 and 9.3.6).\n';
const POLICY = "default-src 'none'; base-uri 'none'; frame-ancestors 'none'";
const LOG_EVERY_MS = 60 * 1000;

let lastLoggedAt = 0;
let unlogged = 0;

/**
 * Answers a CONNECT request 501 on any of this service's HTTP listeners.
 *
 * A static utility class; it holds only the count of refusals not yet logged.
 */
export = class ConnectRefusal {
  /**
   * The error code a refused CONNECT is marked with.
   */
  static readonly CODE = 'STS-HTTP-0025';

  /**
   * Gives a server a `connect` listener that answers 501.
   *
   * @param server - an `http`, `https` or `http2` server
   * @param label - the listener, for the log line
   */
  static install(server: any, label: string): void {
    log.debug("Entering ConnectRefusal.install(). " + label);
    server.on('connect', function (req: any, resOrSocket: any): void {
      ConnectRefusal.answer(req, resOrSocket, label);
    });
    log.debug("Leaving ConnectRefusal.install().");
  }

  /**
   * Answers one CONNECT: through an HTTP/2 response, or written on an
   * HTTP/1.1 socket, which is then closed.
   *
   * @param req - the request
   * @param resOrSocket - an `Http2ServerResponse` over HTTP/2; the socket
   *   over HTTP/1.1, which node hands over unanswered
   * @param label - the listener, for the log line
   */
  static answer(req: any, resOrSocket: any, label: string): void {
    log.debug("Entering ConnectRefusal.answer().");
    ConnectRefusal.record(req, label);
    if (resOrSocket && typeof resOrSocket.writeHead === 'function') {
      errorCodes.mark(resOrSocket, 'STS-HTTP-0025');
      resOrSocket.writeHead(501, {
        'content-type': 'text/plain; charset=utf-8',
        'content-length': String(Buffer.byteLength(BODY)),
        'cache-control': 'no-store',
        'content-security-policy': POLICY,
        'x-content-type-options': 'nosniff' });
      resOrSocket.end(BODY);
      log.debug("Leaving ConnectRefusal.answer(). HTTP/2.");
      return;
    }
    const socket = resOrSocket;
    if (!socket || socket.destroyed || !socket.writable) {
      log.debug("Leaving ConnectRefusal.answer(). The socket is gone.");
      return;
    }
    errorCodes.mark(socket, 'STS-HTTP-0025');
    socket.end('HTTP/1.1 501 Not Implemented\r\n' +
               'Date: ' + new Date().toUTCString() + '\r\n' +
               'Content-Type: text/plain; charset=utf-8\r\n' +
               'Content-Length: ' + Buffer.byteLength(BODY) + '\r\n' +
               'Cache-Control: no-store\r\n' +
               'Content-Security-Policy: ' + POLICY + '\r\n' +
               'X-Content-Type-Options: nosniff\r\n' +
               'Connection: close\r\n\r\n' + BODY);
    log.debug("Leaving ConnectRefusal.answer(). HTTP/1.1.");
  }

  /**
   * Logs a refused CONNECT under its code: the first, then one line a
   * minute at most with the count since.
   *
   * @param req - the request
   * @param label - the listener
   */
  static record(req: any, label: string): void {
    log.debug("Entering ConnectRefusal.record().");
    const now = Date.now();
    if (lastLoggedAt && now - lastLoggedAt < LOG_EVERY_MS) {
      unlogged += 1;
      log.debug("Leaving ConnectRefusal.record(). Counted.");
      return;
    }
    const target = String((req && (req.authority || req.url)) || '');
    log.info(errorCodes.tag('STS-HTTP-0025') + 'http: a CONNECT to ' +
             JSON.stringify(target.slice(0, 200)) + ' on ' + label +
             ' was answered 501, as every CONNECT is' +
             (unlogged ? ' (and ' + unlogged + ' more since the last such ' +
                         'line)' : '') + '.');
    lastLoggedAt = now;
    unlogged = 0;
    log.debug("Leaving ConnectRefusal.record().");
  }
};
