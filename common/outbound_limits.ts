// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

// File: common/outbound_limits.ts
// ---------------------------------------------------------------------------
// THE LIMITS EVERY OUTBOUND HTTP CALL SHARES (#2220, ASVS 5.0.0 13.1.2,
// 13.1.3 and 13.2.6).
//
// Until #2220 each dialer (`federation/federation_http.ts`, the Shared
// Signals and GNAP pushers, SAML metadata, the revocation fetch, the malware
// scanner) set one thing: an INACTIVITY timeout, `request.setTimeout()`,
// which resets on every byte. A peer that answered one byte a second held
// the call open for as long as it liked, a peer that never completed the
// TCP handshake was waited for as long as the inactivity bound, and every
// call used Node.js's global agent, which has no cap on open connections.
// Three things are added here, once, for all of them:
//
//   1. **A SHARED AGENT PER SCHEME** (`agentFor()`), with keep-alive and two
//      caps: `federation.outboundMaxSockets` connections to one destination
//      and `federation.outboundMaxTotalSockets` in all. Past either, a
//      request WAITS in the agent's queue for a socket; nothing is refused
//      for being over the cap, and the wait counts against the call's
//      deadline (2), so it is bounded. The first time requests queue a
//      warning is logged (STS-HTTP-0032), and again only after the queue has
//      drained: a state change, not a line per request.
//   2. **AN OVERALL DEADLINE** (`guard()`): `federation.outboundDeadlineMs`
//      from the moment the request is made, through the wait for a socket,
//      the connect, the handshake and the whole answer, or the caller's own
//      inactivity timeout where that is longer, so that no existing setting
//      is shortened by this one. At the deadline the request is destroyed
//      and the caller's own timeout path runs (STS-HTTP-0033 is logged).
//   3. **A CONNECT TIMEOUT**: `federation.outboundConnectTimeoutMs` for a
//      NEW connection to finish its TCP (and, over TLS, its handshake). A
//      socket the agent reuses is already connected and is not timed.
//      (STS-HTTP-0034.)
//
//   4. **A BOUND ON WHAT IS SENT** (#2247, ASVS 5.0.0 4.2.5): a request
//      whose request-target is over `MAX_REQUEST_TARGET_BYTES` (8 KiB), or
//      whose header fields come to more than `MAX_HEADER_BYTES` (16 KiB), is
//      destroyed before it is sent, with an error the caller's own `error`
//      path reports (STS-HTTP-0035, STS-HTTP-0036). RFC 9110 section 4.1
//      asks a server to accept at least 8000 octets of request-target, and
//      16 KiB is Node.js's own default bound on a request's headers, so a
//      partner running on Node.js would answer 431 to anything larger; most
//      other servers stop at 8 KiB. A refusal here costs no connection and
//      names the cause, where the partner's 414 or 431 would name neither.
//      CONSTANTS rather than settings: no call this service makes comes
//      near them (the longest is a front-channel logout URL or a SCIM
//      filter, a few hundred bytes), and the bound exists so that a value a
//      partner or a caller supplied cannot make one arbitrarily large.
//
// THE DEFAULTS CHANGE NOTHING A NORMAL CALL DOES: 64 connections to one
// partner and 1024 in all are far above what one process opens (a sign-in
// opens one or two), two minutes is eight times the longest inactivity
// timeout a dialer has by default, and ten seconds is longer than any TCP
// and TLS handshake that is going to succeed.
//
// The timers here are one-shot, per request, and cleared when it closes:
// "a per-request timeout" is what the scheduler directive says is not
// periodic work (root CLAUDE.md).
// ---------------------------------------------------------------------------

import http = require('http');
import https = require('https');
import helpers = require('./helpers');
import config = require('./config');
import errorCodes = require('./error_codes');

const log = helpers.log;

// The settings an agent is built from, as one string: a change of either cap
// builds a new agent for the calls after it (the old one's sockets finish
// their calls and close when idle).
interface Built {
  signature: string;
  agent: http.Agent;
}

/** What `guard()` is told. */
interface GuardOptions {
  // The caller's own (inactivity) timeout; the deadline is never shorter.
  timeoutMs?: number;
  // A deadline other than the setting, or 0 for none (a stream bounded by
  // its own byte and event caps).
  deadlineMs?: number;
  // Over TLS, the connect timeout runs to the end of the handshake.
  secure?: boolean;
  // Where the call goes, for the log line.
  where?: string;
  // Called once at the deadline or the connect timeout, after the request
  // was destroyed, with why.
  onTimeout?: (why: string) => void;
}

const built: { http: Built | null; https: Built | null } = {
  http: null, https: null
};

// A NAME FOR WHAT THE POOL KEY LEAVES OUT. Node's agent keeps a socket for
// reuse under a name made of the host, the port and the TLS options it
// knows (`ca`, `cert`, `servername`, ...), and two things this service sets
// per request are not among them: a `lookup` pinned to the address that was
// vetted (federation_http.ts, `pinnedLookup()`), and a `checkServerIdentity`
// (the path rules of #201, or "exactly this process's own leaf"). A socket
// verified under one check must not be handed to a request that asked for
// another, so each is added to the name: a pinned lookup by the address it
// answers (`stsPinned`), any other function by its identity, which makes a
// closure built per request a socket of its own. The realm and the
// outbound gate's options are added for the same reason (`useAgent()`).
const functionIds = new WeakMap<object, number>();
let nextFunctionId = 1;

function idOf(fn: any): string {
  if (typeof fn !== 'function') {
    return '';
  }
  if (fn.stsPinned) {
    return 'pin=' + String(fn.stsPinned);
  }
  let id = functionIds.get(fn);
  if (!id) {
    id = nextFunctionId++;
    functionIds.set(fn, id);
  }
  return 'fn=' + id;
}

// The agents, with that name added. No Entering/Leaving pair: once per
// request, inside node's agent.
class KeyedHttpAgent extends http.Agent {
  getName(options?: any): string {
    return super.getName(options) + ':' +
      String((options && options.stsPoolKey) || '');
  }
}

class KeyedHttpsAgent extends https.Agent {
  getName(options?: any): string {
    return super.getName(options) + ':' +
      String((options && options.stsPoolKey) || '');
  }
}

// How long a kept-alive socket may stay idle in the pool.
const IDLE_SOCKET_MS = 30000;

// The most a request-target (path and query) may take, in bytes: RFC 9110
// section 4.1's "at least 8000 octets", rounded to 8 KiB (#2247).
const MAX_REQUEST_TARGET_BYTES = 8192;

// The most the header fields of one request may take, in bytes, counted as
// `name: value` plus the CRLF: Node.js's default `maxHeaderSize` (#2247).
const MAX_HEADER_BYTES = 16384;

// Whether the warning that requests are waiting for a socket stands.
let waitingNoted = false;

class OutboundLimits {
  /**
   * The connection caps, from the settings.
   *
   * @returns `{ perHost, total }`
   */
  static caps(): { perHost: number; total: number } {
    log.debug("Entering OutboundLimits.caps().");
    const perHost = Math.max(1, Number(config.value(
      'federation.outboundMaxSockets')) || 64);
    const total = Math.max(perHost, Number(config.value(
      'federation.outboundMaxTotalSockets')) || 1024);
    log.debug("Leaving OutboundLimits.caps().");
    return { perHost: perHost, total: total };
  }

  /**
   * The shared agent for one scheme, built from the settings and rebuilt
   * when they change.
   *
   * @param secure - true for https
   * @returns the agent
   */
  static agentFor(secure: boolean): http.Agent {
    log.debug("Entering OutboundLimits.agentFor(). secure=" + secure);
    const caps = OutboundLimits.caps();
    const signature = caps.perHost + '/' + caps.total;
    const slot = secure ? 'https' : 'http';
    const held = built[slot];
    if (held && held.signature === signature) {
      log.debug("Leaving OutboundLimits.agentFor(). Held.");
      return held.agent;
    }
    // `timeout` is how long a kept-alive socket may sit idle before the
    // agent closes it; a request's own `setTimeout()` replaces it while the
    // request runs.
    const options = { keepAlive: true, maxSockets: caps.perHost,
                      maxTotalSockets: caps.total, timeout: IDLE_SOCKET_MS,
                      scheduling: 'fifo' as const };
    const agent = secure ? new KeyedHttpsAgent(options)
      : new KeyedHttpAgent(options);
    built[slot] = { signature: signature, agent: agent };
    log.debug("Leaving OutboundLimits.agentFor(). Built " + signature + ".");
    return agent;
  }

  /**
   * Gives a request's options the shared agent, with the pool key that
   * keeps a socket to the checks it was made under. Called after `lookup`
   * and `checkServerIdentity` are set. A request that brings its own agent
   * (or `agent: false`), a Unix socket, or its own `createConnection` is
   * left as it is.
   *
   * @param requestOptions - the options about to be given to request()
   * @param secure - true for https
   * @returns the same options
   */
  static useAgent(requestOptions: any, secure: boolean): any {
    log.debug("Entering OutboundLimits.useAgent().");
    if (!requestOptions || requestOptions.agent !== undefined ||
        requestOptions.socketPath || requestOptions.createConnection) {
      log.debug("Leaving OutboundLimits.useAgent(). Its own connection.");
      return requestOptions;
    }
    // THE REALM, TOO: paranoid PKI mode judges an outbound certificate in
    // the realm the connection was made in (`outbound_tls.ts`,
    // `holdSocket()`), so a socket is not lent across realms. Lazily, for a
    // library that must not move the require order.
    const realmId = String(require('./realms').currentId() || '');
    requestOptions.stsPoolKey = [idOf(requestOptions.lookup),
                                 idOf(requestOptions.checkServerIdentity),
                                 'realm=' + realmId,
                                 'gate=' + String(requestOptions
                                   .stsOutboundGate !== false),
                                 'variant=' + String(requestOptions
                                   .stsOutboundVariant || '')]
      .join(',');
    requestOptions.agent = OutboundLimits.agentFor(secure);
    log.debug("Leaving OutboundLimits.useAgent().");
    return requestOptions;
  }

  /**
   * The deadline a call gets: the setting, or the caller's own timeout where
   * that is longer.
   *
   * @param timeoutMs - the caller's own timeout
   * @returns milliseconds
   */
  static deadlineMs(timeoutMs?: number): number {
    log.debug("Entering OutboundLimits.deadlineMs().");
    const setting = Math.max(1000, Number(config.value(
      'federation.outboundDeadlineMs')) || 120000);
    log.debug("Leaving OutboundLimits.deadlineMs().");
    return Math.max(setting, Number(timeoutMs) || 0);
  }

  /**
   * The connect timeout, from the setting.
   *
   * @returns milliseconds
   */
  static connectTimeoutMs(): number {
    log.debug("Entering OutboundLimits.connectTimeoutMs().");
    log.debug("Leaving OutboundLimits.connectTimeoutMs().");
    return Math.max(100, Number(config.value(
      'federation.outboundConnectTimeoutMs')) || 10000);
  }

  // Notes, as a state change, whether requests are queued for a socket on
  // the agent. No Entering/Leaving pair: once per outbound request.
  private static noteQueue(agent: any, where: string): void {
    const queued = Object.keys((agent && agent.requests) || {}).length > 0;
    if (queued && !waitingNoted) {
      waitingNoted = true;
      const caps = OutboundLimits.caps();
      log.warn(errorCodes.tag('STS-HTTP-0032') + 'outbound: requests are ' +
               'waiting for a connection (to ' + (where || 'a partner') +
               '): the cap of ' + caps.perHost + ' per destination ' +
               '(federation.outboundMaxSockets) or ' + caps.total + ' in all ' +
               '(federation.outboundMaxTotalSockets) is reached. They wait ' +
               'within their deadline; logged again only after the queue ' +
               'has drained.');
    } else if (!queued && waitingNoted) {
      waitingNoted = false;
      log.info('outbound: no request is waiting for a connection any more.');
    }
  }

  /**
   * Measures what a request just made would send: its request-target and
   * its header fields, against the two bounds (#2247).
   *
   * @param request - the ClientRequest
   * @returns `{ code, why }` when one is over, or null
   */
  static sizeProblem(request: any): { code: string; why: string } | null {
    log.debug("Entering OutboundLimits.sizeProblem().");
    const target = Buffer.byteLength(String((request && request.path) || ''));
    if (target > MAX_REQUEST_TARGET_BYTES) {
      log.debug("Leaving OutboundLimits.sizeProblem(). The target.");
      return { code: 'STS-HTTP-0035',
               why: 'was not sent: its request-target is ' + target +
                    ' bytes, over the ' + MAX_REQUEST_TARGET_BYTES +
                    '-byte bound on what this service sends' };
    }
    let headers: Record<string, unknown> = {};
    try {
      headers = typeof request.getHeaders === 'function'
        ? request.getHeaders() || {} : {};
    } catch (e) {
      // A request whose headers cannot be read has nothing to measure; it
      // is sent as it was before this bound.
      log.debug("Caught in OutboundLimits.sizeProblem(): " +
                ((e && e.message) || e));
      headers = {};
    }
    let total = 0;
    Object.keys(headers).forEach(function (name) {
      [].concat(headers[name] as any).forEach(function (value: unknown) {
        total += Buffer.byteLength(name) + 4 +
          Buffer.byteLength(String(value));
      });
    });
    if (total > MAX_HEADER_BYTES) {
      log.debug("Leaving OutboundLimits.sizeProblem(). The headers.");
      return { code: 'STS-HTTP-0036',
               why: 'was not sent: its header fields come to ' + total +
                    ' bytes, over the ' + MAX_HEADER_BYTES +
                    '-byte bound on what this service sends' };
    }
    log.debug("Leaving OutboundLimits.sizeProblem().");
    return null;
  }

  /**
   * Arms the deadline and the connect timeout on a request just made, and
   * notes whether it had to wait for a socket. Both timers are cleared when
   * the request closes. A request over a size bound (`sizeProblem()`) is
   * destroyed instead, with an error its caller's `error` handler reports.
   *
   * @param request - the ClientRequest
   * @param options - see GuardOptions
   */
  static guard(request: any, options?: GuardOptions): void {
    log.debug("Entering OutboundLimits.guard().");
    const o = options || {};
    if (!request || typeof request.once !== 'function') {
      log.debug("Leaving OutboundLimits.guard(). No request.");
      return;
    }
    const where = String(o.where || '');
    const oversize = OutboundLimits.sizeProblem(request);
    if (oversize) {
      log.warn(errorCodes.tag(oversize.code) + 'outbound: a request to ' +
               (where || 'a peer') + ' ' + oversize.why + '.');
      try {
        request.destroy(new Error('the request ' + oversize.why));
      } catch (e) {
        log.debug("Caught in OutboundLimits.guard(): " +
                  ((e && e.message) || e));
      }
      log.debug("Leaving OutboundLimits.guard(). Over a size bound.");
      return;
    }
    let fired = false;
    let deadline: NodeJS.Timeout | null = null;
    let connect: NodeJS.Timeout | null = null;
    const clear = function (): void {
      if (deadline) {
        clearTimeout(deadline);
        deadline = null;
      }
      if (connect) {
        clearTimeout(connect);
        connect = null;
      }
    };
    const expire = function (code: string, why: string): void {
      log.debug("Entering expire(). " + code);
      clear();
      if (fired) {
        log.debug("Leaving expire(). Already.");
        return;
      }
      fired = true;
      log.warn(errorCodes.tag(code) + 'outbound: a request to ' +
               (where || 'a peer') + ' ' + why + '.');
      try {
        request.destroy(new Error(why));
      } catch (e) {
        // Destroying a request that already ended is not a failure.
        log.debug("Caught in expire(): " + ((e && e.message) || e));
      }
      if (typeof o.onTimeout === 'function') {
        o.onTimeout(why);
      }
      log.debug("Leaving expire().");
    };
    const total = o.deadlineMs === 0 ? 0
      : (Number(o.deadlineMs) > 0 ? Number(o.deadlineMs)
        : OutboundLimits.deadlineMs(o.timeoutMs));
    if (total > 0) {
      deadline = setTimeout(function () {
        expire('STS-HTTP-0033', 'did not finish within its overall deadline ' +
               'of ' + total + 'ms (federation.outboundDeadlineMs)');
      }, total);
      if (deadline && typeof deadline.unref === 'function') {
        deadline.unref();
      }
    }
    const connectMs = OutboundLimits.connectTimeoutMs();
    request.once('socket', function (socket: any) {
      if (!socket || !socket.connecting || fired) {
        // A kept-alive socket, already connected: nothing to time.
        return;
      }
      connect = setTimeout(function () {
        expire('STS-HTTP-0034', 'did not connect within ' + connectMs +
               'ms (federation.outboundConnectTimeoutMs)');
      }, connectMs);
      if (connect && typeof connect.unref === 'function') {
        connect.unref();
      }
      socket.once(o.secure ? 'secureConnect' : 'connect', function () {
        if (connect) {
          clearTimeout(connect);
          connect = null;
        }
      });
    });
    request.once('close', clear);
    OutboundLimits.noteQueue(request.agent, where);
    log.debug("Leaving OutboundLimits.guard().");
  }

  /**
   * The deadline and connect timeout for a raw socket (the ICAP scanner),
   * which has no agent. Cleared when the socket closes.
   *
   * @param socket - the net or tls socket, just made
   * @param options - `deadlineMs`, `secure`, `where`, `onTimeout`
   */
  static guardSocket(socket: any, options?: GuardOptions): void {
    log.debug("Entering OutboundLimits.guardSocket().");
    const o = options || {};
    if (!socket || typeof socket.once !== 'function') {
      log.debug("Leaving OutboundLimits.guardSocket(). No socket.");
      return;
    }
    let fired = false;
    const timers: NodeJS.Timeout[] = [];
    const expire = function (code: string, why: string): void {
      log.debug("Entering expire(). " + code);
      timers.forEach(function (one) {
        clearTimeout(one);
      });
      if (fired) {
        log.debug("Leaving expire(). Already.");
        return;
      }
      fired = true;
      log.warn(errorCodes.tag(code) + 'outbound: a connection to ' +
               (o.where || 'a peer') + ' ' + why + '.');
      if (typeof o.onTimeout === 'function') {
        o.onTimeout(why);
      }
      log.debug("Leaving expire().");
    };
    const total = Number(o.deadlineMs) > 0 ? Number(o.deadlineMs)
      : OutboundLimits.deadlineMs(o.timeoutMs);
    const deadline = setTimeout(function () {
      expire('STS-HTTP-0033', 'did not finish within its overall deadline ' +
             'of ' + total + 'ms');
    }, total);
    timers.push(deadline);
    const connectMs = OutboundLimits.connectTimeoutMs();
    const connect = setTimeout(function () {
      expire('STS-HTTP-0034', 'did not connect within ' + connectMs +
             'ms (federation.outboundConnectTimeoutMs)');
    }, connectMs);
    timers.push(connect);
    timers.forEach(function (one) {
      if (typeof one.unref === 'function') {
        one.unref();
      }
    });
    socket.once(o.secure ? 'secureConnect' : 'connect', function () {
      clearTimeout(connect);
    });
    socket.once('close', function () {
      timers.forEach(function (one) {
        clearTimeout(one);
      });
    });
    log.debug("Leaving OutboundLimits.guardSocket().");
  }
}

export = OutboundLimits;
