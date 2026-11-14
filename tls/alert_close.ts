// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: alert_close.ts
//
// ===========================================================================
// A TLS CONNECTION THAT FAILED IS CLOSED LATER, SO ITS ALERT IS READ
// (2026-11-13, the memory-mode run on 9300a96d1).
//
// A TLS failure on the server's side — a bad record MAC, a record over the
// size limit, a handshake with nothing in common — has a fatal alert to send
// (RFC 8446 section 6.2, RFC 5246 section 7.2.2), and OpenSSL writes it. The
// peer is usually still sending the record the alert is about. Node then
// closed the socket within a tick, with that record unread in the kernel's
// receive buffer, so the kernel answered with a TCP reset, and a reset that
// reached the peer before it had read the alert discarded the alert: the
// peer saw the connection close with no reason. tlsfuzzer's
// `test-tls13-record-layer-limits.py` against the main port lost it about
// one probe in seventy under a full run's load ("Unexpected closure from
// peer"). LDAPS had the same failure and the same fix in the node-ldapjs
// fork's `errorCloseDelay` (`ldap/ldap_server.js`, ERROR_CLOSE_MS).
//
// WHERE NODE CLOSES IT, AND WHERE THIS STEPS IN. A TLS server's socket is a
// TLSSocket over the raw TCP socket the listener accepted, and closing the
// TLSSocket (`TLSWrap.close()`) ends in `destroy()` on that raw socket,
// which is what closes the descriptor. There are two ways in:
//
//   1. A failure BEFORE node counts the handshake finished — a handshake
//      failure, or a bad record that arrives with the client's Finished, as
//      tlsfuzzer sends them. Node destroys the TLSSocket itself, and closes
//      its handle a microtask later "so that the socket can be accessible
//      when an `error` event is handled" — after `tlsClientError`, which is
//      where this sees it.
//   2. A failure AFTER it. The TLSSocket emits `error`; HTTP/1.1
//      (`clientError`, `common/parser_refusal.ts`) and HTTP/2 (the session)
//      destroy it in that same call. This sees it first, from an `error`
//      listener prepended at `secureConnection`.
//
// Either way the raw socket is marked before its `destroy()` is reached, and
// its `destroy()` — that one socket's, nothing shared — then ENDS the
// socket's sending side at once (a FIN behind the alert) and holds the
// descriptor for CLOSE_DELAY_MS before closing it for real. While it is held
// the TLS engine keeps reading the TCP stream and throws the bytes away, so
// the receive buffer stays empty and the peer reads the alert and the FIN
// before anything is reset; the close that follows may still be a reset, by
// which time it no longer matters.
//
// THE FIN IS NOT HELD, AND THE FIRST VERSION HELD IT. A peer that waits for
// the close after the alert waits briefly — tlsfuzzer's ExpectClose after an
// ExpectNoMessage, well under a second — and holding the whole close for two
// seconds failed 23 probes of test-truncating-of-client-hello.py on the
// debugger's listener and stalled two more scripts to their watchdog. Only
// the reset is the problem, and only close() with unread data sends one.
//
// WHAT IT COSTS. One one-shot timer per FAILED connection, cleared when the
// socket closes — the per-connection timeout root CLAUDE.md's scheduler
// section says does not count — and nothing for a connection that does not
// fail. At most MAX_HELD sockets per listener are held; a failure beyond that
// is closed at once, as before (STS-TLS-0061, logged the first time and then
// as a count at most once a minute, with no timer of its own). An alert the
// PEER sent (a browser refusing this service's certificate) is not held:
// nothing is owed back.
//
// WHAT IT RESTS ON. `TLSSocket._parent` (the raw socket a server-side
// TLSSocket wraps) is not public API; a node without it gets the old
// behaviour, logged once (STS-TLS-0062). `tests/tls_alert_close.js` holds
// both ways in, the bound and the control.
// ===========================================================================

import bunyan = require('bunyan');
import net = require('net');
import tls = require('tls');
import config = require('../common/config');
import errorCodes = require('../common/error_codes');

const log = bunyan.createLogger({ name: 'sts-tls-alert-close' });
config.registerLogger(log);

// LDAPS's ERROR_CLOSE_MS, for its measurement: under load 18 of 18 runs kept
// the alert with two seconds, against 5 of 8 losing it with none.
const CLOSE_DELAY_MS = 2000;
// How many failed connections one listener holds at once. A flood of bad
// records costs at most this many descriptors for CLOSE_DELAY_MS.
const MAX_HELD = 256;
// The bound reached is what a flood does: the first, then a count at most
// once a minute (`connect_refusal.ts`'s arrangement).
const LOG_EVERY_MS = 60000;

// Per listener: what it holds and its bounds.
interface Listener {
  label: string;
  delayMs: number;
  maxHeld: number;
  held: number;
  lastLoggedAt: number;
  unlogged: number;
}

const listeners = new WeakMap<object, Listener>();
let warnedNoParent = false;

class AlertClose {
  /**
   * Holds each connection that fails at the TLS layer on `server` open for a
   * moment before it is closed, so its alert reaches the peer.
   *
   * @param server - a TLS server (node's https or http2 secure server); any
   *   other server is left alone
   * @param label - the listener, for the log
   * @param options - `delayMs` and `maxHeld`, for the tests; the defaults
   *   are this file's constants
   * @returns true when it is installed (or already was)
   */
  static install(server: any, label: string,
                 options?: { delayMs?: number; maxHeld?: number }): boolean {
    log.debug("Entering AlertClose.install(). " + label);
    if (!(server instanceof tls.Server)) {
      log.debug("Leaving AlertClose.install(). Not a TLS server.");
      return false;
    }
    if (listeners.has(server)) {
      log.debug("Leaving AlertClose.install(). Already installed.");
      return true;
    }
    const opts = options || {};
    const listener: Listener = {
      label: label,
      delayMs: typeof opts.delayMs === 'number' ? opts.delayMs
        : CLOSE_DELAY_MS,
      maxHeld: typeof opts.maxHeld === 'number' ? opts.maxHeld : MAX_HELD,
      held: 0,
      lastLoggedAt: 0,
      unlogged: 0
    };
    listeners.set(server, listener);
    // Way 2: after the handshake. Prepended, because HTTP/1.1 and HTTP/2
    // destroy the socket from their own `error` listeners.
    server.on('secureConnection', function (socket: any): void {
      socket.prependListener('error', function (err: any): void {
        AlertClose.note(listener, socket, err);
      });
    });
    // Way 1: before it. The handshake's failure is logged and audited by
    // tls/tls_server.js's observeConnectionsOn(); this only marks the socket.
    // error-code: none — marks a socket to be closed later; the failure's
    // own code (STS-TLS-0021, STS-TLS-0034) is tls_server.js's
    server.on('tlsClientError', function (err: any, socket: any): void {
      AlertClose.note(listener, socket, err);
    });
    log.debug("Leaving AlertClose.install().");
    return true;
  }

  /**
   * Whether `err` is a failure of this end's TLS engine, which has an alert
   * to send: an OpenSSL error that is not the peer's own alert.
   *
   * @param err - what the socket reported
   * @returns true for such a failure
   */
  static isTlsFailure(err: any): boolean {
    log.debug("Entering AlertClose.isTlsFailure().");
    const code = String((err && err.code) || '');
    const openssl = !!(err && err.library) || /^ERR_SSL_/.test(code);
    // ERR_SSL_SSLV3_ALERT_…, ERR_SSL_TLSV1_ALERT_…: the peer's alert.
    const peers = /_ALERT_/.test(code);
    log.debug("Leaving AlertClose.isTlsFailure().");
    return openssl && !peers;
  }

  /**
   * How many failed connections `server` is holding now.
   *
   * @param server - a server `install()` was given
   * @returns the count, 0 for a server it was not given
   */
  static heldOn(server: any): number {
    log.debug("Entering AlertClose.heldOn().");
    const listener = listeners.get(server);
    log.debug("Leaving AlertClose.heldOn().");
    return listener ? listener.held : 0;
  }

  // Marks the raw socket under a TLSSocket that failed: its next destroy()
  // is held. Called once or twice per failed connection, never otherwise.
  private static note(listener: Listener, socket: any, err: any): void {
    log.debug("Entering AlertClose.note().");
    if (!AlertClose.isTlsFailure(err)) {
      log.debug("Leaving AlertClose.note(). Not this end's TLS failure.");
      return;
    }
    const raw = socket && socket._parent;
    if (!(raw instanceof net.Socket)) {
      if (!warnedNoParent) {
        warnedNoParent = true;
        log.error(errorCodes.tag('STS-TLS-0062') + 'tls: a TLS socket on ' +
                  listener.label + ' has no raw socket under it ' +
                  '(TLSSocket._parent), so a connection that fails at the ' +
                  'TLS layer is closed at once and its alert can be lost to ' +
                  'the TCP reset. Logged once.');
      }
      log.debug("Leaving AlertClose.note(). No raw socket.");
      return;
    }
    if (raw.destroyed || (raw as any).stsAlertHeld !== undefined) {
      log.debug("Leaving AlertClose.note(). Already closed or marked.");
      return;
    }
    (raw as any).stsAlertHeld = false;
    const destroy = raw.destroy;
    raw.destroy = function (this: any, error?: Error): any {
      return AlertClose.hold(listener, raw, destroy, error);
    };
    log.debug("Leaving AlertClose.note().");
  }

  // The marked socket's destroy(): held once, for the listener's delay,
  // unless the listener already holds its bound.
  private static hold(listener: Listener, raw: any, destroy: Function,
                      error?: Error): any {
    log.debug("Entering AlertClose.hold().");
    if (raw.stsAlertHeld === true) {
      // Asked again while held: the timer below closes it.
      log.debug("Leaving AlertClose.hold(). Already held.");
      return raw;
    }
    raw.destroy = destroy;
    if (raw.destroyed || listener.delayMs <= 0) {
      log.debug("Leaving AlertClose.hold(). Closed at once.");
      return destroy.call(raw, error);
    }
    if (listener.held >= listener.maxHeld) {
      AlertClose.recordFull(listener);
      log.debug("Leaving AlertClose.hold(). The bound is reached.");
      return destroy.call(raw, error);
    }
    raw.stsAlertHeld = true;
    raw.destroy = function (this: any): any {
      return raw;
    };
    listener.held += 1;
    // The FIN goes now, behind the alert: a peer waiting for the close after
    // the alert sees it at once (tlsfuzzer's ExpectClose waits well under a
    // second), and only the CLOSE of the descriptor — the reset — waits.
    AlertClose.halfClose(raw);
    const closer = setTimeout(function (): void {
      destroy.call(raw, error);
    }, listener.delayMs);
    // NOT unref'd: a held socket is still a connection the server counts,
    // so a server.close() waits for it, and an unref'd timer let the event
    // loop drain under that wait (tests/tlsfuzzer_debugger.js's run stopped
    // unfinished). The timer is at most CLOSE_DELAY_MS.
    raw.once('close', function (): void {
      clearTimeout(closer);
      listener.held -= 1;
      raw.destroy = destroy;
    });
    log.debug("Leaving AlertClose.hold(). Held for " + listener.delayMs +
              " ms.");
    return raw;
  }

  // Ends the raw socket's sending side (a TCP FIN after whatever the TLS
  // engine already queued — the alert), leaving its receiving side to be
  // drained. A socket that cannot is left to the timer.
  private static halfClose(raw: any): void {
    log.debug("Entering AlertClose.halfClose().");
    try {
      if (raw.writable && typeof raw.end === 'function') {
        raw.end();
      }
    } catch (e) {
      log.debug("Caught in AlertClose.halfClose(): " +
                ((e && (e as Error).message) || e));
      // The close still comes from the timer.
    }
    log.debug("Leaving AlertClose.halfClose().");
  }

  private static recordFull(listener: Listener): void {
    log.debug("Entering AlertClose.recordFull().");
    const now = Date.now();
    if (listener.lastLoggedAt && now - listener.lastLoggedAt < LOG_EVERY_MS) {
      listener.unlogged += 1;
      log.debug("Leaving AlertClose.recordFull(). Counted.");
      return;
    }
    log.warn(errorCodes.tag('STS-TLS-0061') + 'tls: ' + listener.label +
             ' already holds ' + listener.maxHeld + ' connections that ' +
             'failed at the TLS layer, so another was closed at once and ' +
             'its alert may be lost to the TCP reset' +
             (listener.unlogged ? ' (and ' + listener.unlogged + ' more ' +
                                  'since the last such line)' : '') + '.');
    listener.lastLoggedAt = now;
    listener.unlogged = 0;
    log.debug("Leaving AlertClose.recordFull().");
  }
}

export = AlertClose;
