// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: session_tickets.ts
//
// ===========================================================================
// ONE TLS SESSION-TICKET KEY FOR EVERY NODE OF AN ACTIVE-ACTIVE CLUSTER
// (2026-09-27).
//
// A TLS session ticket (RFC 5077, and TLS 1.3's PSK tickets, RFC 8446 section
// 4.6.1) is state the SERVER encrypts and hands to the client, under a key
// only the server holds. OpenSSL makes that key at random for each TLS
// context, so every process of this service has its own — and behind a load
// balancer that picks a node per connection, a ticket issued by node A is
// sealed under a key node B has never seen. B cannot open it, so every
// resumption that lands on the other node falls back to a full handshake.
// Nothing fails, but resumption works about half the time, and tlsfuzzer's
// session-resumption scripts (#212) refused it in the cluster mode.
//
// So in active-active mode the nodes share ONE key:
//
//   * it is 48 random bytes — what node's `setTicketKeys()` takes (a 16-byte
//     name, a 16-byte HMAC key and a 16-byte AES key) — held in a persisted,
//     service-wide store, sealed at rest under the key-encryption key like
//     every minted row, and replicated to the other nodes by the change log;
//   * the CLUSTER job `tls.ticket-key-rotate` replaces it every
//     `tls.sessionTicketRotationS`, on one node, and the key it replaces is
//     DELETED, not kept: forward secrecy for a resumed session is bounded by
//     how long its ticket key lives, and a kept key would stretch that. A
//     ticket issued under the old key is refused after a rotation and the
//     client does a full handshake, as it would after a restart;
//   * `track(server)` makes a listener apply the current key at every new
//     connection, before its handshake. Node can hold one ticket key per
//     server, and `setSecureContext()` RESETS it to a fresh random one (a
//     re-issued listener certificate, a truststore change), so applying at
//     the connection is what keeps every handshake on the shared key with no
//     timer and nothing to remember across a context rebuild.
//
// **OUTSIDE ACTIVE-ACTIVE THERE IS NO SHARED KEY.** One node answering (a
// single process, a container with request workers — only its front process
// holds a TLS socket — or active-passive, where one node serves at a time)
// resumes on its own keys, and OpenSSL's per-context random keys never reach
// the store at all, which is the stronger arrangement. The job is off there
// and `current()` answers null. A listener that applied a shared key and then
// finds none (the cluster mode or the setting changed) is given a fresh
// random key once, so a key the store no longer holds is not used on.
//
// **WHAT IS NOT SHARED, AND WHY THAT IS RIGHT**: each node's listener
// presents a certificate over a key of its own (`tls/CLAUDE.md`). A ticket
// carries the session's secret, not the certificate, so resumption does not
// care; a client that does a FULL handshake on one node and then checks the
// other node's signature against the first node's key does, and that is
// tlsfuzzer's different-SNI probe (an exception in
// `tests/vendored/tlsfuzzer_kit.js`, for the cluster mode only).
//
// A LIBRARY: it registers no route. Built beside `tls/client_hello` in
// `common/protocol_stack.ts`, before `tls/tls_server` and `ldap/ldap_server`,
// whose listeners call `track()`.
// ===========================================================================

import helpers = require('../common/helpers');
import config = require('../common/config');
import realms = require('../common/realms');
import errorCodes = require('../common/error_codes');
import stsCrypto = require('../common/crypto');
import InstanceSlot = require('../common/instance_slot');

type Json = any;

const ROTATE_JOB = 'tls.ticket-key-rotate';
// What node's setTicketKeys() takes: name, HMAC key and AES key, 16 each.
const KEY_BYTES = 48;
// The one row of the store.
const ROW = 'current';

// Service-wide: the key belongs to the listeners, which belong to no realm.
const store = realms.sharedMap({ persist: 'tls.sessionTicketKey',
                                 scope: 'shared' });

interface SessionTicketsDeps {
  log: typeof helpers.log;
  config: typeof config;
  errorCodes: typeof errorCodes;
  // The row store: `realms.sharedMap()`, or a Map in a test.
  store: { get(key: string): Json; set(key: string, value: Json): Json };
  // Lazily: the cluster module and the scheduler load after this one.
  activeActive: () => boolean;
  scheduler: () => Json;
  randomBytes: (n: number) => Buffer;
  now: () => number;
}

// What one tracked listener last had applied.
interface Tracked {
  label: string;
  // The stored key's base64 currently on the listener, or '' when it has
  // OpenSSL's own.
  applied: string;
}

class SessionTickets {
  static readonly ROTATE_JOB = ROTATE_JOB;
  static readonly KEY_BYTES = KEY_BYTES;

  private readonly tracked = new Map<Json, Tracked>();
  // The decoded key, cached by the stored base64 it came from.
  private decoded: { text: string; key: Buffer } | null = null;
  private applications = 0;
  private failures = 0;

  constructor(private readonly deps: SessionTicketsDeps) {
    deps.log.debug("Entering SessionTickets.constructor().");
    deps.log.debug("Leaving SessionTickets.constructor().");
  }

  static defaultDeps(): SessionTicketsDeps {
    helpers.log.debug("Entering SessionTickets.defaultDeps().");
    helpers.log.debug("Leaving SessionTickets.defaultDeps().");
    return {
      log: helpers.log,
      config: config,
      errorCodes: errorCodes,
      store: store,
      activeActive: function (): boolean {
        return !!require('../cluster/cluster').isActiveActive();
      },
      scheduler: function (): Json {
        return require('../cluster/scheduler');
      },
      randomBytes: function (n: number): Buffer {
        return stsCrypto.randomBytes(n);
      },
      now: function (): number {
        return Date.now();
      }
    };
  }

  // The rotation interval in seconds; 0 means no shared key.
  intervalS(): number {
    const { log, config } = this.deps;
    log.debug("Entering SessionTickets.intervalS().");
    const n = Number(config.value('tls.sessionTicketRotationS'));
    log.debug("Leaving SessionTickets.intervalS().");
    return Number.isFinite(n) && n > 0 ? n : 0;
  }

  // Why no key is shared, or '' when one is.
  offReason(): string {
    const { log } = this.deps;
    log.debug("Entering SessionTickets.offReason().");
    let why = '';
    if (!this.intervalS()) {
      why = 'tls.sessionTicketRotationS is 0, so every node keeps ' +
            'OpenSSL\'s own ticket keys';
    } else {
      let clustered = false;
      try {
        clustered = this.deps.activeActive();
      } catch (e) {
        log.debug("Caught in SessionTickets.offReason(): " +
                  ((e && (e as Error).message) || e));
      }
      if (!clustered) {
        why = 'cluster.mode is not active-active: one node answers, and it ' +
              'resumes sessions on OpenSSL\'s own ticket keys';
      }
    }
    log.debug("Leaving SessionTickets.offReason(). " + (why || 'on'));
    return why;
  }

  // The shared key to apply now, or null. HOT PATH — asked at every new TLS
  // connection on a tracked listener — so no Entering/Leaving pair here: it
  // would write two debug lines per handshake and drown the log.
  current(): Buffer | null {
    if (this.offReason()) {
      return null;
    }
    const row = this.deps.store.get(ROW);
    const text = row && typeof row.key === 'string' ? row.key : '';
    if (!text) {
      return null;
    }
    if (this.decoded && this.decoded.text === text) {
      return this.decoded.key;
    }
    const key = Buffer.from(text, 'base64');
    if (key.length !== KEY_BYTES) {
      this.deps.log.error(this.deps.errorCodes.tag('STS-TLS-0037') +
        'tls: the shared session-ticket key in the store is ' + key.length +
        ' bytes, not ' + KEY_BYTES + '; the listeners keep their own keys ' +
        'until the next rotation replaces it.');
      return null;
    }
    this.decoded = { text: text, key: key };
    return key;
  }

  // Applies the shared key (or, where there is none any more, a fresh random
  // one) to one listener. HOT PATH, for current()'s reason.
  private applyTo(server: Json, entry: Tracked): void {
    const key = this.current();
    const text = key && this.decoded ? this.decoded.text : '';
    try {
      if (key) {
        // Every connection, and not only when it changed: setSecureContext()
        // puts a random key back without telling anybody.
        server.setTicketKeys(key);
        if (entry.applied !== text) {
          entry.applied = text;
          this.applications += 1;
        }
      } else if (entry.applied) {
        // The store's key is no longer to be used here: a fresh key of this
        // listener's own, once, rather than the old shared one for ever.
        server.setTicketKeys(this.deps.randomBytes(KEY_BYTES));
        entry.applied = '';
      }
    } catch (e) {
      this.failures += 1;
      this.deps.log.error(this.deps.errorCodes.tag('STS-TLS-0036') +
        'tls: the shared session-ticket key could not be applied to ' +
        entry.label + ' (' + ((e && (e as Error).message) || e) + '); ' +
        'that connection resumes only on the node that issued its ticket.');
    }
  }

  // Makes a TLS listener use the shared key from its next connection on. A
  // `tls.Server` (or `https.Server`); ldapjs's secure server passes its
  // `.server`. Safe to call twice for one listener.
  track(server: Json, label: string): boolean {
    const { log } = this.deps;
    log.debug("Entering SessionTickets.track(). " + label);
    if (!server || typeof server.setTicketKeys !== 'function' ||
        typeof server.on !== 'function') {
      log.debug("Leaving SessionTickets.track(). Not a TLS server.");
      return false;
    }
    if (this.tracked.has(server)) {
      log.debug("Leaving SessionTickets.track(). Already tracked.");
      return true;
    }
    const entry: Tracked = { label: String(label || 'a TLS listener'),
                             applied: '' };
    this.tracked.set(server, entry);
    const self = this;
    // 'connection' is the TCP connection, before the TLS engine has read a
    // byte of the ClientHello, so the key is in place for its handshake.
    // The PROXY protocol's emit shadow still emits it, after the header.
    server.on('connection', function () {
      self.applyTo(server, entry);
    });
    // And once now, so the first connection is not the first application.
    this.applyTo(server, entry);
    log.debug("Leaving SessionTickets.track().");
    return true;
  }

  // Replaces the shared key with a new random one; the old one is deleted.
  // What the job runs. Nothing about the key is returned or logged.
  rotate(reason: string): Json {
    const { log, store } = this.deps;
    log.debug("Entering SessionTickets.rotate(). " + reason);
    const held = store.get(ROW);
    const generation = (held && Number(held.generation)) || 0;
    const row = {
      key: this.deps.randomBytes(KEY_BYTES).toString('base64'),
      generation: generation + 1,
      rotatedAt: new Date(this.deps.now()).toISOString(),
      reason: String(reason || 'scheduled')
    };
    store.set(ROW, row);
    log.info('tls: the shared session-ticket key is now generation ' +
             row.generation + ' (' + row.reason + '); tickets issued under ' +
             'the one it replaced are refused and those clients do a full ' +
             'handshake.');
    log.debug("Leaving SessionTickets.rotate().");
    return { generation: row.generation, rotatedAt: row.rotatedAt };
  }

  // What the console and the tests read. Never the key.
  report(): Json {
    const { log, store } = this.deps;
    log.debug("Entering SessionTickets.report().");
    const held = store.get(ROW);
    const off = this.offReason();
    const listeners: Json[] = [];
    this.tracked.forEach(function (entry) {
      listeners.push({ label: entry.label, shared: !!entry.applied });
    });
    log.debug("Leaving SessionTickets.report().");
    return {
      shared: !off && !!(held && held.key),
      off: off,
      intervalS: this.intervalS(),
      generation: held ? Number(held.generation) || 0 : 0,
      rotatedAt: held ? String(held.rotatedAt || '') : '',
      listeners: listeners,
      applications: this.applications,
      failures: this.failures
    };
  }

  // THE JOB, registered at build in every process (cluster/CLAUDE.md: every
  // process registers the same jobs).
  registerJobs(): boolean {
    const { log } = this.deps;
    log.debug("Entering SessionTickets.registerJobs().");
    const s = this.deps.scheduler();
    if (s.job(ROTATE_JOB)) {
      log.debug("Leaving SessionTickets.registerJobs(). Already there.");
      return false;
    }
    const self = this;
    s.register({
      id: ROTATE_JOB,
      title: 'TLS session-ticket key rotation',
      describe: 'Replaces the session-ticket key every node\'s TLS ' +
                'listeners share in an active-active cluster, so a ticket ' +
                'one node issued resumes on another. The key it replaces ' +
                'is deleted, which bounds how long a resumed session\'s ' +
                'secrets can be recovered from a ticket.',
      owner: 'tls/session_tickets.ts',
      kind: 'cluster', scope: 'service',
      everySetting: 'tls.sessionTicketRotationS', everySettingUnit: 's',
      off: function (): string {
        return self.offReason();
      },
      manual: true,
      run: function (ctx: Json): Json {
        const manual = !!(ctx && ctx.trigger === 'manual');
        const done = self.rotate(manual ? 'requested' : 'scheduled');
        return { summary: 'generation ' + done.generation };
      }
    });
    log.debug("Leaving SessionTickets.registerJobs().");
    return true;
  }
}

const slot = new InstanceSlot<SessionTickets>(
  'tls/session_tickets',
  () => new SessionTickets(SessionTickets.defaultDeps()),
  function (instance: SessionTickets): void {
    instance.registerJobs();
  },
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  SessionTickets: SessionTickets,
  installInstance: (instance: SessionTickets): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  ROTATE_JOB: ROTATE_JOB,
  KEY_BYTES: KEY_BYTES,
  track: slot.forward('track'),
  current: slot.forward('current'),
  rotate: slot.forward('rotate'),
  offReason: slot.forward('offReason'),
  report: slot.forward('report')
};
