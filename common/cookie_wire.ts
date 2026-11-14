// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

// File: common/cookie_wire.ts
// ---------------------------------------------------------------------------
// WHAT ONLY THE PROCESS HOLDING THE SOCKET CAN KNOW (#1441, #1438).
//
// ASVS 5.0.0 3.3.1 wants every cookie named `__Host-` or `__Secure-`. This
// service writes sixteen cookies in some forty places and reads them in more,
// so the rule is applied once, on the wire: inside the service a cookie is
// still `sts_session`, and between the socket and the browser it is
// `__Host-sts_session`. A cookie added tomorrow is covered without anybody
// remembering.
//
// IT RUNS IN THE MAIN THREAD ONLY. A request worker sits behind a unix socket,
// so it cannot see whether the request arrived over TLS, and the front process
// reads the names itself to route (`common/request_pool.js`). The front
// translates a request before routing it and an answer as it leaves, so a
// worker only ever sees the inside names.
//
// `__Host-` needs Secure, Path=/ and no Domain. A cookie with a Domain
// (`authn.cookieDomain`, DBSC's site scope) can only be `__Secure-`.
//
// AN UNPREFIXED `sts_*` COOKIE IS DROPPED ON THE WAY IN: accepting it would
// undo the point of the prefix, since a sibling host or a cleartext response
// can set one. So is `__Secure-` where nothing here writes that form (`SCOPED`
// names the cookies that always are). The pool
// pins are spared: they select a worker and authorize nothing, and
// `common/oidc_rp.ts` sends them to this service itself by their inside name.
//
// HSTS is here for the same reason it is not in `common/app.js`: only this
// process can tell a TLS socket from the plain-HTTP revocation listener.
// ---------------------------------------------------------------------------

import workerThreads = require('worker_threads');
import helpers = require('./helpers');
import config = require('./config');
import mode = require('./mode');

const log = helpers.log;

const MANAGED = /^sts_/;
const PREFIXED = /^__(Host|Secure)-(sts_.*)$/;
const SPARED = ['sts_pool', 'sts_pool_surfaces'];
// The cookie this service writes as `__Secure-` whatever `authn.cookieDomain`
// says: DBSC's site-scoped one.
const SCOPED = /^sts_session_bound/;

class CookieWire {
  // Hot path: every request and every Set-Cookie line. No Entering/Leaving
  // pair on this or the two below — one would drown the log.
  static prefixFor(attributes: string): string {
    const hasDomain = /;\s*domain=/i.test(attributes);
    const atRoot = /;\s*path=\/\s*(;|$)/i.test(attributes);
    return !hasDomain && atRoot ? '__Host-' : '__Secure-';
  }

  /**
   * Puts one `Set-Cookie` line into its wire form.
   *
   * @param line - the line as the service wrote it
   * @returns the line the browser receives
   */
  static wrapLine(line: string): string {
    const text = String(line);
    const equals = text.indexOf('=');
    const name = equals > 0 ? text.slice(0, equals).trim() : '';
    if (!MANAGED.test(name)) {
      return text;
    }
    const secure = /;\s*secure\s*(;|$)/i.test(text) ? text : text + '; Secure';
    return CookieWire.prefixFor(secure) + secure;
  }

  /**
   * Puts a `Cookie` header into the names the service reads.
   *
   * @param header - the header as the browser sent it
   * @param sharedDomain - whether `__Secure-` is a form this service writes
   * @returns the header with inside names, without what must not be believed
   */
  static unwrapHeader(header: string, sharedDomain: boolean): string {
    const kept: string[] = [];
    String(header).split(';').forEach(function (part) {
      const bit = part.trim();
      const equals = bit.indexOf('=');
      const name = equals > 0 ? bit.slice(0, equals) : bit;
      const value = equals > 0 ? bit.slice(equals) : '';
      const match = PREFIXED.exec(name);
      if (match) {
        if (match[1] === 'Host' || sharedDomain || SCOPED.test(match[2])) {
          kept.push(match[2] + value);
        }
      } else if (!MANAGED.test(name) || SPARED.indexOf(name) >= 0) {
        if (bit) {
          kept.push(bit);
        }
      }
    });
    return kept.join('; ');
  }

  /**
   * The name a browser will know a cookie by, for a document that must name it
   * (DBSC's session instructions). Asked in a worker, so it asks the settings.
   *
   * @param name - the inside name
   * @param attributes - the cookie's attributes
   * @returns the wire name
   */
  static wireName(name: string, attributes: string): string {
    log.debug("Entering CookieWire.wireName().");
    log.debug("Leaving CookieWire.wireName().");
    if (!mode.prefixesCookies() || !config.value('global.https')) {
      return name;
    }
    return CookieWire.prefixFor('; ' + attributes) + name;
  }

  /**
   * The middleware. In a worker it does nothing.
   *
   * @returns an express middleware
   */
  static middleware() {
    log.debug("Entering CookieWire.middleware().");
    log.debug("Leaving CookieWire.middleware().");
    return function cookieWire(req, res, next) {
      if (!workerThreads.isMainThread ||
          !(req.socket && req.socket.encrypted)) {
        return next();
      }
      const prefixes = mode.prefixesCookies();
      const hsts = !mode.omitsStrictTransportSecurity();
      if (prefixes && req.headers.cookie) {
        const header = CookieWire.unwrapHeader(req.headers.cookie,
          !!config.value('authn.cookieDomain'));
        if (header) {
          req.headers.cookie = header;
        } else {
          delete req.headers.cookie;
        }
      }
      if (prefixes || hsts) {
        // AT THE FLUSH, for `common/app.js`'s reason: a framework's error
        // handler clears the headers set before it.
        const writeHead = res.writeHead;
        res.writeHead = function () {
          if (hsts) {
            res.setHeader('Strict-Transport-Security', 'max-age=31536000' +
              (config.value('security.hstsIncludeSubDomains')
                ? '; includeSubDomains' : ''));
          }
          const lines = prefixes ? res.getHeader('Set-Cookie') : undefined;
          if (lines !== undefined) {
            res.setHeader('Set-Cookie',
                          ([] as any[]).concat(lines).map(CookieWire.wrapLine));
          }
          return writeHead.apply(res, arguments);
        };
      }
      return next();
    };
  }
}

export = CookieWire;
