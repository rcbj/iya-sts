// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
// @ts-check
//
// ===========================================================================
// A REQUEST THE PARSER REFUSES KEEPS ITS ANSWER (#1500).
//
// Node answers a request it cannot parse (431 for a request line or headers
// past its limit, 400 otherwise) and destroys the socket at once. With the
// rest of the request still arriving, the unread bytes in the kernel's buffer
// turn that close into a TCP reset, and the reset throws away the answer the
// client had not read: a 65 KB query string got a 431 only some of the time
// and otherwise "Connection reset by peer", which a client cannot tell from a
// crash. `common/lingering_close.js` is the answer to that for a response sent
// before an upload has arrived, and this is the same answer for the one path
// that never reaches a response object: write, half-close, discard the rest.
//
// A `clientError` listener replaces node's own handling, so this writes what
// node would have: 431, 408 for a request timeout, 400 for the rest.
// ===========================================================================

import bunyan = require('bunyan');
import config = require('./config');
import errorCodes = require('./error_codes');
import lingeringClose = require('./lingering_close');

const log = bunyan.createLogger({ name: 'sts-parser-refusal' });
config.registerLogger(log);

// A malformed request is what a scanner sends: the first and then a count, at
// most once a minute, and no timer (`connect_refusal.ts`'s arrangement).
const LOG_EVERY_MS = 60000;
let lastLoggedAt = 0;
let unlogged = 0;

const ANSWERS: Record<string, string> = {
  HPE_HEADER_OVERFLOW: '431 Request Header Fields Too Large',
  ERR_HTTP_REQUEST_TIMEOUT: '408 Request Timeout'
};

class ParserRefusal {
  /**
   * Answers what this listener's HTTP parser refuses.
   *
   * @param server - an HTTP or HTTPS server
   * @param label - the listener, for the log line
   */
  static install(server: any, label: string): void {
    log.debug("Entering ParserRefusal.install(). " + label);
    server.on('clientError', function (err: any, socket: any): void {
      ParserRefusal.answer(err, socket, label);
    });
    log.debug("Leaving ParserRefusal.install().");
  }

  /**
   * Writes the refusal, then lets the client finish sending.
   *
   * @param err - what the parser reported
   * @param socket - the connection
   * @param label - the listener
   */
  static answer(err: any, socket: any, label: string): void {
    log.debug("Entering ParserRefusal.answer().");
    const code = String((err && err.code) || '');
    // The peer has gone, so nobody is left to answer.
    if (code === 'ECONNRESET' || !socket.writable) {
      socket.destroy();
      log.debug("Leaving ParserRefusal.answer(). Nobody to answer.");
      return;
    }
    const status = ANSWERS[code] || '400 Bad Request';
    ParserRefusal.record(status, label);
    ParserRefusal.release(socket);
    lingeringClose.lingerOn(socket);
    socket.write('HTTP/1.1 ' + status + '\r\nConnection: close\r\n' +
                 'Content-Length: 0\r\n\r\n');
    socket.destroySoon();
    log.debug("Leaving ParserRefusal.answer().");
  }

  // NODE'S PARSER STILL OWNS THE SOCKET AT THIS POINT: it consumes the handle
  // directly, so `resume()` reads nothing, the bytes stay in the kernel's
  // buffer and the close is still a reset (25 of 25, measured with only
  // lingerOn()). `unconsume()` is not public API, hence the guard;
  // tests/parser_refusal.js fails if a release of node takes it away.
  private static release(socket: any): void {
    log.debug("Entering ParserRefusal.release().");
    if (socket.parser && typeof socket.parser.unconsume === 'function') {
      socket.parser.unconsume();
    }
    socket.removeAllListeners('data');
    socket.on('data', function (): void {
      return;
    });
    log.debug("Leaving ParserRefusal.release().");
  }

  private static record(status: string, label: string): void {
    log.debug("Entering ParserRefusal.record().");
    const now = Date.now();
    if (lastLoggedAt && now - lastLoggedAt < LOG_EVERY_MS) {
      unlogged += 1;
      log.debug("Leaving ParserRefusal.record(). Counted.");
      return;
    }
    log.info(errorCodes.tag('STS-HTTP-0026') + 'http: ' + label +
             ' refused a request it could not parse with ' + status +
             (unlogged ? ' (and ' + unlogged + ' more since the last such ' +
                         'line)' : '') + '.');
    lastLoggedAt = now;
    unlogged = 0;
    log.debug("Leaving ParserRefusal.record().");
  }
}

export = ParserRefusal;
