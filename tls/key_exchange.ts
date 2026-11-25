// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tls/key_exchange.ts
//
// ===========================================================================
// WHICH KEY EXCHANGE A TLS CONNECTION NEGOTIATED, AND HOW MANY WERE
// POST-QUANTUM (#2220, ASVS 5.0.0 11.1.4).
//
// `tls.groups` puts the three ML-KEM hybrids first, so a client that offers
// one gets one. Until #2220 nothing said whether clients DID: the plan of
// `docs/v1.2.0/post-quantum-migration.md` turns on `tls.pqcOnly` once
// "every client offers an ML-KEM group", and there was no way to tell. So
// each completed handshake on a listener of this process is recorded here
// by the group it negotiated, and counted per listener and group.
//
// **WHERE THE GROUP COMES FROM, AND WHY NOT `getEphemeralKeyInfo()`.**
// Node answers `getEphemeralKeyInfo()` on a CLIENT socket only; on a server
// socket it is null (node's documentation says so, and node 24.22 with
// OpenSSL 3.5.9 was seen to answer null for every group, 2026-11-25). Nor
// does `getSharedSigalgs()` help: it is the signature algorithms. What the
// server side DOES hand out is the session, `getSession()`, which is
// OpenSSL's own DER encoding of SSL_SESSION (ssl/ssl_asn1.c) — and since
// OpenSSL 1.1.1 that carries the negotiated group as `kex_group`, an
// INTEGER under the context tag [19], the IANA TLS Supported Groups code
// point. Seen there for X25519MLKEM768 (0x11ec), SecP256r1MLKEM768
// (0x11eb), X25519 (0x001d) and P-256 (0x0017), in TLS 1.3 and in TLS 1.2,
// 2026-11-25. It is the value the server put in its ServerHello, so it is
// observed, not inferred from what the client offered.
//
// **AN ENCODING THAT IS OpenSSL's, NOT A STANDARD's**, so it is read
// defensively: a session that is not a SEQUENCE, or that has no [19], is
// a connection whose group is `unknown`, counted as such — never a failure
// of the connection, which this module never touches. A TLS 1.2 suite
// with no (EC)DHE in its name exchanged no ephemeral key at all (RSA key
// transport) and is counted as `none`, whatever the session holds.
//
// **COUNTED BY THE FRONT PROCESS, SINCE IT STARTED.** Every listener's
// socket is the front process's (root CLAUDE.md, *One front process*), so
// the counts are this node's and are not kept across a restart: a
// measurement of what clients send, not a record. `GET
// /admin-api/tls/key-exchange` is in `request_pool.js`'s NEVER_DISPATCHED
// for that reason. Bounded: at most MAX_GROUPS distinct groups a listener,
// the rest counted under `other`, and at most MAX_LISTENERS listeners.
//
// A LIBRARY (rule 3): no route. It requires bunyan and `config` for the
// logger, and nothing of this service's state.
// ===========================================================================

import bunyan = require('bunyan');
import config = require('../common/config');

const log = bunyan.createLogger({ name: 'sts-tls-key-exchange' });
config.registerLogger(log);

type Json = any;

/** At most this many distinct groups are counted per listener. */
const MAX_GROUPS = 32;

/** At most this many listeners are counted. */
const MAX_LISTENERS = 64;

/** The context tag OpenSSL's SSL_SESSION_ASN1 keeps `kex_group` under. */
const KEX_GROUP_TAG = 0xb3;

interface GroupRow {
  name: string;
  postQuantum: boolean;
  hybrid: boolean;
}

// The IANA TLS Supported Groups registry, the rows a TLS 1.2 or 1.3
// handshake here can negotiate: the NIST and Edwards curves, the FFDHE
// groups, ML-KEM alone (draft-ietf-tls-mlkem) and the three hybrids
// (draft-ietf-tls-ecdhe-mlkem), and the TLS 1.3 Brainpool code points.
const GROUPS: { [code: number]: GroupRow } = Object.freeze({
  0x0017: { name: 'secp256r1', postQuantum: false, hybrid: false },
  0x0018: { name: 'secp384r1', postQuantum: false, hybrid: false },
  0x0019: { name: 'secp521r1', postQuantum: false, hybrid: false },
  0x001a: { name: 'brainpoolP256r1', postQuantum: false, hybrid: false },
  0x001b: { name: 'brainpoolP384r1', postQuantum: false, hybrid: false },
  0x001c: { name: 'brainpoolP512r1', postQuantum: false, hybrid: false },
  0x001d: { name: 'x25519', postQuantum: false, hybrid: false },
  0x001e: { name: 'x448', postQuantum: false, hybrid: false },
  0x001f: { name: 'brainpoolP256r1tls13', postQuantum: false, hybrid: false },
  0x0020: { name: 'brainpoolP384r1tls13', postQuantum: false, hybrid: false },
  0x0021: { name: 'brainpoolP512r1tls13', postQuantum: false, hybrid: false },
  0x0100: { name: 'ffdhe2048', postQuantum: false, hybrid: false },
  0x0101: { name: 'ffdhe3072', postQuantum: false, hybrid: false },
  0x0102: { name: 'ffdhe4096', postQuantum: false, hybrid: false },
  0x0103: { name: 'ffdhe6144', postQuantum: false, hybrid: false },
  0x0104: { name: 'ffdhe8192', postQuantum: false, hybrid: false },
  0x0200: { name: 'MLKEM512', postQuantum: true, hybrid: false },
  0x0201: { name: 'MLKEM768', postQuantum: true, hybrid: false },
  0x0202: { name: 'MLKEM1024', postQuantum: true, hybrid: false },
  0x11eb: { name: 'SecP256r1MLKEM768', postQuantum: true, hybrid: true },
  0x11ec: { name: 'X25519MLKEM768', postQuantum: true, hybrid: true },
  0x11ed: { name: 'SecP384r1MLKEM1024', postQuantum: true, hybrid: true }
});

/** What one connection negotiated. */
interface Negotiated {
  group: string;
  codePoint: number | null;
  postQuantum: boolean;
  hybrid: boolean;
  protocol: string | null;
}

interface Count {
  group: string;
  codePoint: number | null;
  postQuantum: boolean;
  hybrid: boolean;
  connections: number;
  lastAt: string;
}

interface ListenerCounts {
  listener: string;
  label: string;
  groups: Map<string, Count>;
  connections: number;
}

const counts = new Map<string, ListenerCounts>();
let since = new Date().toISOString();
let droppedListeners = 0;
const installed = new WeakSet<object>();

class KeyExchange {
  /** The registry rows, by code point, for a test and the page. */
  static readonly GROUPS = GROUPS;

  /** The per-listener bound on distinct groups. */
  static readonly MAX_GROUPS = MAX_GROUPS;

  /**
   * The `kex_group` an OpenSSL SSL_SESSION DER carries, or null.
   *
   * @param der - what `TLSSocket.getSession()` answered
   * @returns the IANA code point, or null when there is none to read
   */
  static groupCodeOfSession(der: any): number | null {
    log.debug("Entering KeyExchange.groupCodeOfSession().");
    const buf = Buffer.isBuffer(der) ? der : null;
    if (!buf || buf.length < 2 || buf[0] !== 0x30) {
      log.debug("Leaving KeyExchange.groupCodeOfSession(). Not a SEQUENCE.");
      return null;
    }
    const outer = KeyExchange.lengthAt(buf, 1);
    if (!outer) {
      log.debug("Leaving KeyExchange.groupCodeOfSession(). Length.");
      return null;
    }
    const end = Math.min(buf.length, outer.next + outer.length);
    let i = outer.next;
    while (i < end) {
      const tag = buf[i];
      const len = KeyExchange.lengthAt(buf, i + 1);
      if (!len || len.next + len.length > end) {
        log.debug("Leaving KeyExchange.groupCodeOfSession(). Truncated.");
        return null;
      }
      if (tag === KEX_GROUP_TAG) {
        // [19] EXPLICIT INTEGER: 02 <len> <value>.
        const inner = buf.subarray(len.next, len.next + len.length);
        if (inner.length < 3 || inner[0] !== 0x02 ||
            inner[1] < 1 || inner[1] > 4 || inner.length < 2 + inner[1]) {
          log.debug("Leaving KeyExchange.groupCodeOfSession(). Not an " +
                    "INTEGER.");
          return null;
        }
        let value = 0;
        for (let k = 0; k < inner[1]; k++) {
          value = value * 256 + inner[2 + k];
        }
        log.debug("Leaving KeyExchange.groupCodeOfSession(). 0x" +
                  value.toString(16));
        return value;
      }
      i = len.next + len.length;
    }
    log.debug("Leaving KeyExchange.groupCodeOfSession(). No [19].");
    return null;
  }

  /**
   * What a group code point is called, and whether it is post-quantum.
   *
   * @param code - the IANA code point, or null
   * @returns `{ group, codePoint, postQuantum, hybrid }`
   */
  static describeCode(code: number | null): Negotiated {
    log.debug("Entering KeyExchange.describeCode().");
    const row = code === null ? null : GROUPS[code];
    const out: Negotiated = {
      group: row ? row.name : (code === null ? 'unknown'
        : '0x' + ('0000' + code.toString(16)).slice(-4)),
      codePoint: code,
      postQuantum: !!(row && row.postQuantum),
      hybrid: !!(row && row.hybrid),
      protocol: null
    };
    log.debug("Leaving KeyExchange.describeCode(). " + out.group);
    return out;
  }

  /**
   * What a completed TLS connection negotiated. Never throws.
   *
   * @param socket - a server-side TLSSocket after its handshake
   * @returns the group, or null for a socket that is not TLS
   */
  static negotiatedOn(socket: any): Negotiated | null {
    log.debug("Entering KeyExchange.negotiatedOn().");
    if (!socket || typeof socket.getSession !== 'function') {
      log.debug("Leaving KeyExchange.negotiatedOn(). Not TLS.");
      return null;
    }
    let protocol: string | null = null;
    let cipher = '';
    let der: any = null;
    try {
      protocol = typeof socket.getProtocol === 'function'
        ? (socket.getProtocol() || null) : null;
      const c = typeof socket.getCipher === 'function'
        ? socket.getCipher() : null;
      cipher = String((c && (c.standardName || c.name)) || '');
      der = socket.getSession();
    } catch (e) {
      // A socket that closed between its handshake and this line: its group
      // is unknown, and the connection is not this module's to judge.
      log.debug("Caught in KeyExchange.negotiatedOn(): " +
                ((e && e.message) || e));
    }
    // TLS 1.2 with RSA key transport has no ephemeral key at all. In OpenSSL
    // a TLS 1.3 suite name has no key exchange in it, and every TLS 1.3
    // handshake here is (EC)DHE or ML-KEM.
    if (protocol && protocol !== 'TLSv1.3' && cipher &&
        !/(ECDHE|DHE|EDH)/.test(cipher)) {
      log.debug("Leaving KeyExchange.negotiatedOn(). Key transport.");
      return { group: 'none', codePoint: null, postQuantum: false,
               hybrid: false, protocol: protocol };
    }
    const out = KeyExchange.describeCode(
      KeyExchange.groupCodeOfSession(der));
    out.protocol = protocol;
    log.debug("Leaving KeyExchange.negotiatedOn(). " + out.group);
    return out;
  }

  /**
   * Counts every completed handshake on `server` by its group, under
   * `listener`. Installed once per server; a second call is a no-op.
   *
   * @param server - a TLS server (https, http2 secure, tls, ldapjs's)
   * @param listener - the listener's id: `main`, `ldaps`, `debugger`,
   *   `custom:<id>`
   * @param label - what the page calls it
   * @returns true when it is installed (or already was)
   */
  static install(server: any, listener: string, label: string): boolean {
    log.debug("Entering KeyExchange.install(). " + listener);
    if (!server || typeof server.on !== 'function') {
      log.debug("Leaving KeyExchange.install(). Not a server.");
      return false;
    }
    if (installed.has(server)) {
      log.debug("Leaving KeyExchange.install(). Already installed.");
      return true;
    }
    installed.add(server);
    server.on('secureConnection', function (socket: any): void {
      KeyExchange.record(listener, label, KeyExchange.negotiatedOn(socket));
    });
    log.debug("Leaving KeyExchange.install().");
    return true;
  }

  // No Entering/Leaving pair: one call per completed TLS handshake on every
  // listener of this process, and a debug line per connection would drown
  // the log under load.
  /**
   * Adds one connection to the counts.
   *
   * @param listener - the listener's id
   * @param label - what the page calls it
   * @param negotiated - `negotiatedOn()`'s answer
   */
  static record(listener: string, label: string,
                negotiated: Negotiated | null): void {
    if (!negotiated) {
      return;
    }
    let row = counts.get(listener);
    if (!row) {
      if (counts.size >= MAX_LISTENERS) {
        droppedListeners++;
        return;
      }
      row = { listener: listener, label: String(label || listener),
              groups: new Map<string, Count>(), connections: 0 };
      counts.set(listener, row);
    }
    let key = negotiated.group;
    if (!row.groups.has(key) && row.groups.size >= MAX_GROUPS) {
      key = 'other';
    }
    let count = row.groups.get(key);
    if (!count) {
      count = { group: key,
                codePoint: key === 'other' ? null : negotiated.codePoint,
                postQuantum: key === 'other' ? false
                  : negotiated.postQuantum,
                hybrid: key === 'other' ? false : negotiated.hybrid,
                connections: 0, lastAt: '' };
      row.groups.set(key, count);
    }
    count.connections++;
    count.lastAt = new Date().toISOString();
    row.connections++;
  }

  /**
   * The counts, as `GET /admin-api/tls/key-exchange` answers them.
   *
   * @returns `{ since, connections, postQuantum, classical, unknown,
   *   listeners, droppedListeners, note }`
   */
  static report(): Json {
    log.debug("Entering KeyExchange.report().");
    let total = 0;
    let pq = 0;
    let unknown = 0;
    const listeners = Array.from(counts.values()).map(function (row) {
      log.debug("Entering KeyExchange.report() listener.");
      let rowPq = 0;
      const groups = Array.from(row.groups.values())
        .sort(function (a, b) {
          return b.connections - a.connections ||
            (a.group < b.group ? -1 : a.group > b.group ? 1 : 0);
        }).map(function (one) {
          if (one.postQuantum) {
            rowPq += one.connections;
          }
          if (one.group === 'unknown' || one.group === 'other') {
            unknown += one.connections;
          }
          return { group: one.group, codePoint: one.codePoint,
                   postQuantum: one.postQuantum, hybrid: one.hybrid,
                   connections: one.connections, lastAt: one.lastAt };
        });
      total += row.connections;
      pq += rowPq;
      log.debug("Leaving KeyExchange.report() listener.");
      return { listener: row.listener, label: row.label,
               connections: row.connections, postQuantum: rowPq,
               groups: groups };
    });
    log.debug("Leaving KeyExchange.report().");
    return {
      since: since,
      connections: total,
      postQuantum: pq,
      classical: total - pq - unknown,
      unknown: unknown,
      listeners: listeners,
      droppedListeners: droppedListeners,
      note: 'The key exchange each completed TLS handshake negotiated on ' +
            'this node\'s listeners since its front process started, read ' +
            'from the session the server holds. Post-quantum means an ' +
            'ML-KEM group, alone or in a hybrid. The counts are this ' +
            'node\'s, and are not kept across a restart.'
    };
  }

  /** Empties the counts, for a test. Nothing in the service calls it. */
  static reset(): void {
    log.debug("Entering KeyExchange.reset().");
    counts.clear();
    droppedListeners = 0;
    since = new Date().toISOString();
    log.debug("Leaving KeyExchange.reset().");
  }

  // No Entering/Leaving pair: read once per field of a session, from
  // groupCodeOfSession(), which is itself called once per connection.
  private static lengthAt(buf: Buffer, at: number):
    { length: number; next: number } | null {
    if (at >= buf.length) {
      return null;
    }
    const first = buf[at];
    if (first < 0x80) {
      return { length: first, next: at + 1 };
    }
    const n = first & 0x7f;
    if (n < 1 || n > 3 || at + n >= buf.length) {
      return null;
    }
    let length = 0;
    for (let k = 1; k <= n; k++) {
      length = length * 256 + buf[at + k];
    }
    return { length: length, next: at + 1 + n };
  }
}

export = KeyExchange;
