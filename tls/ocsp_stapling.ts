// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tls/ocsp_stapling.ts
//
// ===========================================================================
// OCSP STAPLING ON THIS SERVICE'S OWN LISTENERS (#2254, ASVS 5.0.0 12.1.4).
//
// The service asks about the revocation of every certificate a peer
// presents, and until #2254 it answered nobody about its own: a client that
// sent RFC 6066's `status_request` got no `CertificateStatus`. Every listener
// this process holds — the main port, LDAPS 636, the debugger listener and
// each custom listener (`tls/listeners.js`, built by `server.js`'s
// `customListener()`) — now has `install()` on its server, which answers
// node's `OCSPRequest` event with a staple. node sends it in TLS 1.2's
// CertificateStatus message and in TLS 1.3's Certificate entry extension
// (RFC 8446 section 4.4.2.1) alike; both were seen with node 22 and 24,
// 2026-11-25.
//
// **WHERE THE RESPONSE COMES FROM: THIS SERVICE'S OWN RESPONDER, IN PROCESS.**
// A listener certificate is a leaf of this service's own CA (the process
// branch's TLS Issuing CA, or a realm's `realm-tls` CA for a realm listener),
// so `common/pki_revocation.js`'s `stapleFor()` builds an OCSP request for
// it and hands it to `answerOcsp()` — the function `/pki/ocsp/{scope}/{ca}`
// answers with. Same signer (the issuing CA's key, through `common/crypto.js`
// whether it is in software or a hardware module), same register, same
// thisUpdate and nextUpdate (`pki.crlLifetimeMinutes`), and no network.
//
// **A CERTIFICATE FROM AN OUTSIDE AUTHORITY IS NOT STAPLED, AND THAT IS THE
// CHOICE (#2254 item 1).** `tls.certificateFile`, or a custom listener's own
// `certificateFile`, is a certificate somebody else issued: `stapleFor()`
// finds no authority of this service that is its issuer and answers null.
// Fetching from that certificate's AIA OCSP URL would be acceptable under
// federation/CLAUDE.md's rule (the URL is in the operator's own certificate),
// and it is still not done, for three reasons. It would put an outbound dial
// on the path of the front process's listeners, whose failure modes (a slow
// or unreachable responder, a proxy, a responder answering for a different
// key) are the operator's CA's and not this service's to diagnose. An
// operator who brings a certificate already has the place stapling belongs
// for it — the TLS terminator or balancer in front, which is where such a
// certificate is usually terminated. And `tls/CLAUDE.md`'s rule for a
// supplied certificate is that it is LEFT ALONE: renewing it is theirs, and
// so is asking its authority about it. A client asking about it gets no
// staple and checks the responder the certificate names, exactly as before
// #2254. No setting dials, so none is needed.
//
// **KEPT PER PROCESS, IN THE PROCESS HOLDING THE SOCKET** (root CLAUDE.md,
// *One front process*: a certificate a socket presents is reachable from no
// other process). A staple is kept per (issuer, set of leaves) and served
// from the event's callback. node names the LAST certificate of the secure
// context in the event, whichever one OpenSSL then selects for the client
// (`tls.certificateAlgorithms` = `rsa,ml-dsa-65`), so the staple carries a
// SingleResponse for every leaf this process presents under the same issuer,
// and a client finds its own by CertID.
//
// **REFRESHED BY A PER-PROCESS SCHEDULER JOB, NEVER A TIMER**
// (`tls.ocsp-staple-refresh`, cluster/CLAUDE.md): every quarter of
// `pki.crlLifetimeMinutes` (bounded to 30 s – 15 min) it re-makes every
// staple a listener served in the last day, so a staple always has at least
// three quarters of its validity left when it is sent. It is RE-MADE AT ONCE
// when the listener certificate changes (renewal by #2220's
// `tls.server-certificate-renew`, a rebuilt hierarchy, a custom listener's
// renewal — a new certificate is a new key here, made at its first
// handshake) and when this process revokes or releases one of its serials
// (`pki_revocation.onStatusChange()`). A revocation made in another process
// reaches the staple at the job's next run.
//
// **A STAPLE NEVER FAILS A HANDSHAKE.** No current response — the setting
// off, an outside issuer, a responder that refused, a signature that failed,
// a making slower than HANDSHAKE_WAIT_MS — is a handshake without one. The
// callback is never handed an error, because node fails the handshake on
// one. A failure is logged when it STARTS (STS-TLS-0079) and its recovery
// when it ends; a staple saying REVOKED is logged when it starts saying so
// (STS-TLS-0080).
//
// **MUST-STAPLE IS NOT ADDED (#2254 item 5).** The certificates this service
// issues carry no TLS Feature extension (RFC 7633, status_request): with it a
// client must refuse a handshake without a staple, and a staple here is best
// effort by design — the setting off, a restart's first handshake, a failing
// signer. Adding it is a decision for when stapling has run in product.
//
// A LIBRARY (rule 3): no route. It requires `config`, `mode`, `error_codes`,
// `crypto` and `pki_revocation` (libraries), and reaches `tls_server.js` and
// the scheduler lazily.
// ===========================================================================

import bunyan = require('bunyan');
import config = require('../common/config');
import errorCodes = require('../common/error_codes');
import serviceMode = require('../common/mode');
import stsCrypto = require('../common/crypto');
import revocation = require('../common/pki_revocation');

const log = bunyan.createLogger({ name: 'sts-tls-ocsp-stapling' });
config.registerLogger(log);

type Json = any;

/** The scheduler job that refreshes every staple. */
const JOB = 'tls.ocsp-staple-refresh';

/** How long a handshake waits for a staple being made, at most. */
const HANDSHAKE_WAIT_MS = 3000;

/** A failed making is not retried by a handshake sooner than this. */
const RETRY_MS = 60 * 1000;

/** A staple no listener served for this long is dropped. */
const IDLE_MS = 24 * 3600 * 1000;

/** At most this many staples are kept. */
const MAX_STAPLES = 64;

/** The job's interval, bounded. */
const MIN_EVERY_MS = 30 * 1000;
const MAX_EVERY_MS = 15 * 60 * 1000;

interface Staple {
  key: string;
  issuerPem: string;
  leafPems: string[];
  serials: string[];
  listeners: Set<string>;
  der: Buffer | null;
  thisUpdateMs: number;
  nextUpdateMs: number;
  status: string;
  scope: string;
  ca: string;
  state: 'new' | 'current' | 'failing' | 'outside';
  why: string;
  making: Promise<void> | null;
  lastServedMs: number;
  lastAttemptMs: number;
  made: number;
}

const staples = new Map<string, Staple>();
const installed = new WeakSet<object>();
let observing = false;

class OcspStapling {
  /** The job's id, for a test and the documentation. */
  static readonly JOB = JOB;

  /** How long a handshake waits for a staple being made. */
  static readonly HANDSHAKE_WAIT_MS = HANDSHAKE_WAIT_MS;

  /**
   * Whether the listeners staple now: `tls.ocspStapling`, `auto` resolved
   * by `mode.staplesOcsp()`.
   *
   * @returns true when a staple is sent to a client that asks
   */
  static enabled(): boolean {
    log.debug("Entering OcspStapling.enabled().");
    const value = String(config.value('tls.ocspStapling') || 'auto');
    const on = value === 'on' ? true
      : value === 'off' ? false
        : !!serviceMode.staplesOcsp();
    log.debug("Leaving OcspStapling.enabled(). " + on);
    return on;
  }

  /**
   * Answers `OCSPRequest` on a TLS server with this process's staple.
   * Idempotent per server.
   *
   * @param server - a `tls.Server` (or an http2/https secure server)
   * @param listener - the listener's id (`main`, `ldaps`, `debugger`,
   *   `custom:<id>`)
   * @param label - what a log line calls it
   * @returns true when it is installed (or already was)
   */
  static install(server: any, listener: string, label: string): boolean {
    log.debug("Entering OcspStapling.install(). " + listener);
    if (!server || typeof server.on !== 'function') {
      log.debug("Leaving OcspStapling.install(). Not a server.");
      return false;
    }
    if (installed.has(server)) {
      log.debug("Leaving OcspStapling.install(). Already installed.");
      return true;
    }
    installed.add(server);
    OcspStapling.observe();
    server.on('OCSPRequest', function (certificate: any, issuer: any,
                                       callback: any): void {
      OcspStapling.answer(listener, label, certificate, issuer, callback);
    });
    log.debug("Leaving OcspStapling.install().");
    return true;
  }

  // No Entering/Leaving pair: one call per handshake whose client asked for
  // the certificate status — every browser does — on every listener of this
  // process, and a debug line per handshake would drown the log under load.
  /**
   * Hands node's callback the current staple, or none. Never an error.
   *
   * @param listener - the listener's id
   * @param label - what a log line calls it
   * @param certificate - the DER node names (the context's certificate)
   * @param issuer - the DER of its issuer, from the chain the context sends
   * @param callback - node's `(err, response)`
   */
  static answer(listener: string, label: string, certificate: any,
                issuer: any, callback: any): void {
    let called = false;
    const finish = function (der: Buffer | null): void {
      if (called) {
        return;
      }
      called = true;
      try {
        callback(null, der || null);
      } catch (e) {
        // node's own callback; a socket already gone throws here, and the
        // handshake it belonged to is over either way.
        log.debug("Caught in OcspStapling.answer(): " +
                  ((e && (e as any).message) || e));
      }
    };
    try {
      if (!certificate || !issuer || !OcspStapling.enabled()) {
        finish(null);
        return;
      }
      const staple = OcspStapling.stapleOf(certificate, issuer, listener);
      const now = Date.now();
      staple.lastServedMs = now;
      if (OcspStapling.current(staple, now)) {
        finish(staple.der);
        return;
      }
      if (staple.state === 'outside' ||
          (staple.state === 'failing' && !staple.making &&
           now - staple.lastAttemptMs < RETRY_MS)) {
        finish(null);
        return;
      }
      // ONE WAIT AT MOST, NOT A CHAIN: the first handshake after a start or
      // a change waits for the making, bounded; a slower one goes without
      // and the next handshake has it.
      const timer = setTimeout(function () {
        finish(null);
      }, HANDSHAKE_WAIT_MS);
      if (timer && typeof timer.unref === 'function') {
        timer.unref();
      }
      OcspStapling.make(staple).then(function () {
        clearTimeout(timer);
        finish(OcspStapling.current(staple, Date.now()) ? staple.der : null);
      });
    } catch (e) {
      log.debug("Caught in OcspStapling.answer(): " +
                ((e && (e as any).message) || e) + " (" + label + ")");
      finish(null);
    }
  }

  /**
   * Whether a staple can be sent at `nowMs`: made, and before its
   * nextUpdate.
   *
   * @param staple - the staple
   * @param nowMs - the time
   * @returns true when it is current
   */
  static current(staple: Staple, nowMs: number): boolean {
    log.debug("Entering OcspStapling.current().");
    const yes = !!staple.der && nowMs < staple.nextUpdateMs;
    log.debug("Leaving OcspStapling.current(). " + yes);
    return yes;
  }

  // The staple for the certificate node names: found by the certificate's
  // and the issuer's fingerprints, or made empty with every leaf this
  // process presents under the same issuer.
  static stapleOf(certificate: any, issuer: any, listener: string): Staple {
    log.debug("Entering OcspStapling.stapleOf().");
    const cert = stsCrypto.parseCertificate(certificate);
    const iss = stsCrypto.parseCertificate(issuer);
    const key = cert.fingerprint256 + '|' + iss.fingerprint256;
    let staple = staples.get(key);
    if (staple) {
      staple.listeners.add(listener);
      log.debug("Leaving OcspStapling.stapleOf(). Held.");
      return staple;
    }
    const leaves = [cert];
    const seen = new Set<string>([cert.fingerprint256]);
    OcspStapling.presentedLeaves().forEach(function (pem: string): void {
      let one: any = null;
      try {
        one = stsCrypto.parseCertificate(pem);
      } catch (e) {
        log.debug("Caught in a callback in OcspStapling.stapleOf(): " +
                  ((e && (e as any).message) || e));
        return;
      }
      if (!seen.has(one.fingerprint256) && one.issuer === iss.subject) {
        seen.add(one.fingerprint256);
        leaves.push(one);
      }
    });
    // A BOUND AT THE INSERT (root CLAUDE.md: a size cap cannot wait for a
    // timer): the staple served longest ago goes.
    if (staples.size >= MAX_STAPLES) {
      let oldest: Staple | null = null;
      staples.forEach(function (one: Staple): void {
        if (!oldest || one.lastServedMs < oldest.lastServedMs) {
          oldest = one;
        }
      });
      if (oldest) {
        staples.delete((oldest as Staple).key);
      }
    }
    staple = {
      key: key,
      issuerPem: iss.toString(),
      leafPems: leaves.map(function (one: any): string {
        return one.toString();
      }),
      serials: leaves.map(function (one: any): string {
        return revocation.normalSerial(one.serialNumber);
      }),
      listeners: new Set<string>([listener]),
      der: null, thisUpdateMs: 0, nextUpdateMs: 0, status: '',
      scope: '', ca: '',
      state: 'new', why: '', making: null, lastServedMs: 0,
      lastAttemptMs: 0, made: 0
    };
    staples.set(key, staple);
    log.debug("Leaving OcspStapling.stapleOf(). New, " + leaves.length +
              " leaf/leaves.");
    return staple;
  }

  // The leaves this process's main port presents, from `tls_server.js`,
  // lazily: a JavaScript route module (root CLAUDE.md, rule 1), loaded long
  // before any handshake.
  static presentedLeaves(): string[] {
    log.debug("Entering OcspStapling.presentedLeaves().");
    let out: string[] = [];
    try {
      out = require('./tls_server').presentedCertificatePems() || [];
    } catch (e) {
      log.debug("Caught in OcspStapling.presentedLeaves(): " +
                ((e && (e as any).message) || e));
      out = [];
    }
    log.debug("Leaving OcspStapling.presentedLeaves(). " + out.length);
    return out;
  }

  /**
   * Makes (or re-makes) one staple. Coalesced: a making already under way
   * is the one returned. Never rejects.
   *
   * @param staple - the staple
   * @returns a promise settled when it is made or has failed
   */
  static make(staple: Staple): Promise<void> {
    log.debug("Entering OcspStapling.make().");
    if (staple.making) {
      log.debug("Leaving OcspStapling.make(). Under way.");
      return staple.making;
    }
    staple.lastAttemptMs = Date.now();
    staple.making = revocation.stapleFor(staple.leafPems, staple.issuerPem)
      .then(function (made: Json): void {
        OcspStapling.took(staple, made);
      }, function (e: any): void {
        log.debug("Caught in OcspStapling.make(): " +
                  ((e && e.message) || e));
        OcspStapling.failed(staple, String((e && e.message) || e));
      }).then(function (): void {
        staple.making = null;
      });
    log.debug("Leaving OcspStapling.make().");
    return staple.making as Promise<void>;
  }

  // What the responder answered, taken.
  static took(staple: Staple, made: Json): void {
    log.debug("Entering OcspStapling.took().");
    if (!made) {
      if (staple.state !== 'outside') {
        log.info('tls: the certificate presented on ' +
                 Array.from(staple.listeners).join(', ') +
                 ' was issued by an authority that is ' +
                 'not this service\'s, so it is not stapled; a client ' +
                 'asks the responder the certificate names (#2254).');
      }
      staple.state = 'outside';
      staple.der = null;
      staple.why = 'issued by an outside authority';
      log.debug("Leaving OcspStapling.took(). Outside.");
      return;
    }
    if (!made.ok || made.status !== 'successful' || !made.der) {
      OcspStapling.failed(staple, 'the responder answered ' +
                                  String(made.status || 'nothing'));
      log.debug("Leaving OcspStapling.took(). Refused.");
      return;
    }
    const answers = (made.answers || []).map(function (one: Json): string {
      return String(one.status);
    });
    const status = answers.indexOf('revoked') >= 0 ? 'revoked'
      : answers.every(function (one: string): boolean {
        return one === 'good';
      }) ? 'good' : 'unknown';
    if (status === 'revoked' && staple.status !== 'revoked') {
      log.warn(errorCodes.tag('STS-TLS-0080') + 'tls: the OCSP response ' +
               'stapled on ' + Array.from(staple.listeners).join(', ') +
               ' says the certificate it presents is REVOKED (serial(s) ' +
               staple.serials.join(', ') + '). Every client that asks is ' +
               'told so; replace the certificate.');
    }
    if (staple.state === 'failing') {
      log.info('tls: the OCSP staple for ' +
               Array.from(staple.listeners).join(', ') + ' is current ' +
               'again (' + status + ').');
    }
    staple.der = made.der;
    staple.thisUpdateMs = Date.parse(made.thisUpdate) || Date.now();
    staple.nextUpdateMs = Date.parse(made.nextUpdate) || 0;
    staple.status = status;
    staple.scope = String(made.scope);
    staple.ca = String(made.ca);
    staple.state = 'current';
    staple.why = '';
    staple.made += 1;
    log.debug("Leaving OcspStapling.took(). " + status + ".");
  }

  // A making that failed. The previous staple is kept while it is current:
  // a valid response is a valid response until its nextUpdate.
  static failed(staple: Staple, why: string): void {
    log.debug("Entering OcspStapling.failed().");
    if (staple.state !== 'failing') {
      log.warn(errorCodes.tag('STS-TLS-0079') + 'tls: no OCSP response ' +
               'could be made for the certificate presented on ' +
               Array.from(staple.listeners).join(', ') + ': ' +
               why + '. Handshakes go on ' +
               (OcspStapling.current(staple, Date.now())
                 ? 'with the previous staple until its nextUpdate, ' +
                   new Date(staple.nextUpdateMs).toISOString()
                 : 'without a staple') +
               '; none is failed. tls.ocsp-staple-refresh tries again.');
    }
    staple.state = 'failing';
    staple.why = why;
    log.debug("Leaving OcspStapling.failed().");
  }

  /**
   * Re-makes every staple a listener served in the last day, and drops the
   * rest. The job's run; a test calls it too. Never rejects.
   *
   * @returns a promise of `{ staples, made, failing, revoked, dropped }`
   */
  static async refresh(): Promise<Json> {
    log.debug("Entering OcspStapling.refresh().");
    const now = Date.now();
    let dropped = 0;
    const kept: Staple[] = [];
    staples.forEach(function (one: Staple): void {
      if (now - one.lastServedMs > IDLE_MS) {
        staples.delete(one.key);
        dropped += 1;
      } else if (one.state !== 'outside') {
        kept.push(one);
      }
    });
    for (const one of kept) {
      await OcspStapling.make(one);
    }
    const out = { staples: staples.size, made: kept.length,
                  failing: kept.filter(function (one: Staple): boolean {
                    return one.state === 'failing';
                  }).length,
                  revoked: kept.filter(function (one: Staple): boolean {
                    return one.status === 'revoked';
                  }).length,
                  dropped: dropped };
    log.debug("Leaving OcspStapling.refresh(). " + JSON.stringify(out));
    return out;
  }

  /**
   * Forgets every staple: the listener certificate changed, so the next
   * handshake makes the staple for the certificate it now presents.
   */
  static forget(): void {
    log.debug("Entering OcspStapling.forget().");
    staples.clear();
    log.debug("Leaving OcspStapling.forget().");
  }

  /**
   * Re-makes at once every staple about a serial whose status changed in
   * this process (`pki_revocation.onStatusChange()`).
   *
   * @param serialHex - the serial
   * @returns how many staples were about it
   */
  static statusChanged(serialHex: string): number {
    log.debug("Entering OcspStapling.statusChanged().");
    const serial = revocation.normalSerial(serialHex);
    let n = 0;
    staples.forEach(function (one: Staple): void {
      if (one.serials.indexOf(serial) >= 0 && one.state !== 'outside') {
        n += 1;
        // NOT SERVED MEANWHILE: it says the status before the change.
        one.der = null;
        one.nextUpdateMs = 0;
        OcspStapling.make(one);
      }
    });
    log.debug("Leaving OcspStapling.statusChanged(). " + n);
    return n;
  }

  // The two observers, once per process, at the first install: the
  // listener certificate replaced (`tls_server.js`, in the process holding
  // the sockets) and a status changed here.
  static observe(): void {
    log.debug("Entering OcspStapling.observe().");
    if (observing) {
      log.debug("Leaving OcspStapling.observe(). Already.");
      return;
    }
    observing = true;
    try {
      require('./tls_server').onServerCertificateChange(function (): void {
        OcspStapling.forget();
      });
    } catch (e) {
      log.debug("Caught in OcspStapling.observe(): " +
                ((e && (e as any).message) || e));
    }
    log.debug("Leaving OcspStapling.observe().");
  }

  /**
   * The job's interval: a quarter of `pki.crlLifetimeMinutes` (the
   * nextUpdate every response carries), between 30 seconds and 15 minutes.
   *
   * @returns milliseconds
   */
  static everyMs(): number {
    log.debug("Entering OcspStapling.everyMs().");
    const lifetime = (Number(config.value('pki.crlLifetimeMinutes')) || 60) *
                     60000;
    const ms = Math.max(MIN_EVERY_MS, Math.min(MAX_EVERY_MS, lifetime / 4));
    log.debug("Leaving OcspStapling.everyMs(). " + ms);
    return ms;
  }

  /**
   * Why the job is off in this process, or ''.
   *
   * @returns the reason
   */
  static offReason(): string {
    log.debug("Entering OcspStapling.offReason().");
    let why = '';
    if (process.env.STS_REQUEST_WORKER) {
      why = 'a request worker holds no listener; the front process staples';
    } else if (!OcspStapling.enabled()) {
      why = 'tls.ocspStapling is off (auto is off in development mode)';
    } else if (!staples.size) {
      why = 'no listener of this process has been asked for a staple yet';
    }
    log.debug("Leaving OcspStapling.offReason(). " + (why || 'on'));
    return why;
  }

  /**
   * What each staple is, without its bytes: for a test and a status view.
   *
   * @returns the rows
   */
  static report(): Json[] {
    log.debug("Entering OcspStapling.report().");
    const out: Json[] = [];
    staples.forEach(function (one: Staple): void {
      out.push({ listeners: Array.from(one.listeners).sort(),
                 serials: one.serials.slice(), status: one.status,
                 scope: one.scope, ca: one.ca,
                 state: one.state, why: one.why, made: one.made,
                 thisUpdate: one.thisUpdateMs
                   ? new Date(one.thisUpdateMs).toISOString() : '',
                 nextUpdate: one.nextUpdateMs
                   ? new Date(one.nextUpdateMs).toISOString() : '' });
    });
    log.debug("Leaving OcspStapling.report(). " + out.length);
    return out;
  }

  // The job, registered at this module's load in EVERY process
  // (cluster/CLAUDE.md: every process registers the same jobs) and off in a
  // request worker, which holds no socket.
  static registerJob(): boolean {
    log.debug("Entering OcspStapling.registerJob().");
    let scheduler: any = null;
    try {
      scheduler = require('../cluster/scheduler');
    } catch (e) {
      log.debug("Caught in OcspStapling.registerJob(): " +
                ((e && (e as any).message) || e));
      scheduler = null;
    }
    if (!scheduler || typeof scheduler.register !== 'function' ||
        scheduler.job(JOB)) {
      log.debug("Leaving OcspStapling.registerJob(). None, or already " +
                "there.");
      return false;
    }
    scheduler.register({
      id: JOB,
      title: 'OCSP staple refresh',
      describe: 'Re-makes the OCSP response each listener of this process ' +
                'staples (the main port, LDAPS, the debugger and the custom ' +
                'listeners), from this service\'s own responder, every ' +
                'quarter of pki.crlLifetimeMinutes, so a staple is always ' +
                'well before its nextUpdate and a revocation made elsewhere ' +
                'reaches it. Runs in every node\'s front process.',
      owner: 'tls/ocsp_stapling.ts',
      kind: 'per-process', quiet: true,
      everyMs: function (): number {
        return OcspStapling.everyMs();
      },
      off: function (): string {
        return OcspStapling.offReason();
      },
      manual: true,
      run: function (): Promise<Json> {
        return OcspStapling.refresh().then(function (done: Json): Json {
          return { summary: done.made + ' made, ' + done.failing +
                            ' failing, ' + done.revoked + ' revoked' };
        });
      }
    });
    log.debug("Leaving OcspStapling.registerJob().");
    return true;
  }
}

revocation.onStatusChange(function (scopeId: string, caId: string,
                                    serialHex: string): void {
  OcspStapling.statusChanged(serialHex);
});

OcspStapling.registerJob();

export = OcspStapling;
