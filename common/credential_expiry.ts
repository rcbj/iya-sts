// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: credential_expiry.ts
//
// ===========================================================================
// A PERSON IS REMINDED BEFORE A CREDENTIAL THEY HOLD EXPIRES (#2247, ASVS
// 5.0.0 6.4.5: "users are reminded to renew authentication mechanisms that
// expire").
//
// Until 1.2.0 nothing told a person their certificate was about to lapse;
// the one prompt was the post-login `piv-reissue` activity and its mail,
// both off by default. Here a CLUSTER SCHEDULER JOB per realm,
// `mail.credential-expiry` (hourly), finds the credentials of the realm's
// people that reach one of `mail.expiryReminderDays` (30, 7 and 1 by
// default) and mails each person ONE message per run naming every one due
// — what it is, the day it expires and how to renew it — through
// `common/mail_uses.ts`'s `credentialsExpiring()`, a security notice.
//
// WHAT EXPIRES, AND IS FOLLOWED (`KINDS`), each a certificate on the
// person's entry, which is the master of their credentials:
//
//   * `certificate` — one this realm issued over ACME, EST or SCEP
//     (`stsEnrolledCertificate`, `common/cert_enrollment.ts`'s records),
//     renewed on the portal's Certificates page;
//   * `piv` — the same records under a PIV slot profile (`piv-*`), renewed
//     on the PIV tab of Tokens and keys;
//   * `smime` — an S/MIME certificate mail is encrypted to
//     (`userSMIMECertificate`), replaced on the OpenPGP and S/MIME tab
//     of Tokens and keys;
//   * `tls-client` — a TLS client certificate this realm issued the person
//     from the portal's Signing keys page or an administrator's page
//     (`common/tls_client_certificates.js`), the one certificate sign-in
//     most often presents. It is kept in the realm's PKI register, not on
//     the entry, so that module tells this one at its issue and its
//     revocation (`noteHeld()`, `noteGone()`); renewed on the Signing keys
//     page;
//   * `signin-certificate` — one stored for certificate sign-in
//     (`userCertificate`, #1061), from whichever authority issued it, so
//     the person is told to ask their administrator.
//
// One certificate on two of them (an `email` certificate issued here and
// set as the S/MIME one) is one row, the first kind above. What is NOT
// followed, and why: an SSH user certificate lives an hour at most
// (`pki.sshHardwareLifetimeSeconds`' ceiling) and is asked for again at each
// use, so a reminder days ahead names nothing; a passkey, an authenticator
// app, a one-time code or YubiKey OTP token, recovery codes, an app password
// and a password do not expire here (no password ages out in this service);
// an OpenPGP key's own expiry is the holder's tool's to set and is not read.
//
// FINDING THEM IS AN INDEX, NEVER A WALK (rcbj's "no full scans; async
// only" and "constant cost"). A per-realm store, `credential_expiry.due`,
// holds one row per certificate a person holds — its kind, a label, when it
// expires, and the steps it was told at — ON DEMAND with its index
// (`sts_minted_index`, the existing generic one: no SQL schema change). A
// row is filed under the DAY ITS NEXT REMINDER IS DUE (`n:YYYY-MM-DD`), so
// the job asks for the days from LOOKBACK_DAYS ago to today — at most 31
// equality lookups a run, each answering only rows owed a reminder — and a
// row told at its step moves to the day of its next one, or out of the
// index after the last. A row expires with its certificate (the store's
// own expiry purge is its bound; no sweep of this module's).
//
// THE INDEX IS KEPT RIGHT BY THE ENTRIES' OWN WRITES. `common/
// entry_observer.ts`'s WATCHER (`watch()`) hands this module every write of
// a person's entry that changed one of the three attributes, by every door:
// `noteAccountChange()` for the console, `/admin-api`, the portal, SCIM and
// LDAP, and `ldap_server.js`'s two in-place writers (the enrollment slot and
// `changeStoredCertificate()`), which tell the watchers themselves. A
// certificate removed, revoked or replaced takes its row with it; one added
// files a row; one whose expiry moved (renewed under the same key, a new
// thumbprint) starts its steps again. In a promise job after the write,
// which has already returned.
//
// BACKWARDS COMPATIBILITY (from 1.0.0 on): a certificate on an entry before
// 1.2.0 has no row. The job's runs also BACKFILL, a slice at a time, over
// the realm's people in key order after a cursor (`passkeyScanAsync()`,
// BACKFILL_PER_RUN people a run), the walk a one-time backfill is allowed
// (`persistence/CLAUDE.md`, the granting index's): the cursor and the done
// mark are a row of the store (`$backfill$`); the realm's TLS client
// register is read once, whole, when the walk is done (a held list, the
// realm's own). Until it reaches a person,
// their old certificates are reminded only once their entry is next
// written; a realm of a million people is through in about eight days.
//
// ONCE PER CREDENTIAL PER STEP, AND NO STORM. A step told is recorded on
// the row (`told`), which outlives the outbox's `mail.retentionS`; the
// outbox is the cluster's record too (`dedupKey` / `dedupAlso`,
// `Mail.queuedWithin()`, as #2162's sign-in alerts), so a run on another
// node, or this one's after a crash between the send and the row, sends
// nothing twice. A certificate first seen inside a step is told at the
// nearest one and never at a step it has already passed. One message per
// person per run, naming every item due; at most MAILS_PER_RUN people a
// run, the rest at the next.
//
// THE PIV RE-ISSUE ACTIVITY STAYS AS IT WAS (`common/post_login_piv.ts`,
// off by default). It is not a reminder but the step that renews at a
// sign-in, and a realm that wants it turns it on; this reminder tells every
// holder, whether or not it is on, and names the PIV tab of Tokens and
// keys, where the same enrolment form is.
//
// A LIBRARY (rule 3): it registers no route, and its job and its watcher
// when it is built. The directory and the mail uses are required LAZILY,
// at the moment of use — `ldap/ldap_server.js` is a JavaScript route module
// (root CLAUDE.md, rule 1) and must not be dragged forward from here.
// ===========================================================================

import helpers = require('./helpers');
import InstanceSlot = require('./instance_slot');
import realms = require('./realms');
import config = require('./config');
import errorCodes = require('./error_codes');
import stsCrypto = require('./crypto');
import entryObserver = require('./entry_observer');
import DomainMap = require('./domain_map');

type Json = any;

const { log } = helpers;

const DAY_MS = 24 * 60 * 60 * 1000;

/** The scheduler job. */
const JOB = 'mail.credential-expiry';
/** How often it runs, in every realm. */
const EVERY_MS = 60 * 60 * 1000;
/** How many days back a reminder's due day is still looked for. */
const LOOKBACK_DAYS = 30;
/** The most people one run mails; the rest are at the next run. */
const MAILS_PER_RUN = 1000;
/** The most people one run's backfill reads. */
const BACKFILL_PER_RUN = 5000;
/** The rows a process holds of the store. */
const HELD = 5000;
/** The store row holding the backfill's cursor and done mark. */
const BACKFILL_KEY = '$backfill$';

/** The kinds followed (header), in the order one certificate is filed. */
const KINDS = ['certificate', 'piv', 'smime', 'tls-client',
               'signin-certificate'];

/** The kinds read from the entry's attributes (the rest are told). */
const ENTRY_KINDS = ['certificate', 'piv', 'smime', 'signin-certificate'];

/** The attributes the watcher reads. */
const ATTRIBUTES = ['stsEnrolledCertificate', 'userSMIMECertificate',
                    'userCertificate'];

/** One certificate a person holds, as the index files it. */
interface Held {
  id: string;
  kind: string;
  label: string;
  notAfter: number;
}

/** One row of the index. */
interface DueRow {
  subject: string;
  username: string;
  kind: string;
  label: string;
  notAfter: number;
  told: number[];
  next: string;
}

// ---------------------------------------------------------------------------
// THE STORE, per realm at its declaration. `indexBy` and `expiresAt` run on
// every row a flush writes, so neither has an Entering/Leaving pair (a hot
// path).
// ---------------------------------------------------------------------------
const due = realms.map({
  persist: 'credential_expiry.due',
  onDemand: { maxEntries: HELD },
  tombstone: true,
  indexBy: function (row: Json): string[] {
    const out: string[] = [];
    if (row && row.subject) {
      out.push('p:' + String(row.subject));
    }
    if (row && row.next) {
      out.push('n:' + String(row.next));
    }
    return out;
  },
  expiresAt: function (row: Json): number | null {
    const at = row ? Number(row.notAfter) : NaN;
    return at > 0 ? at : null;
  }
});

interface ExpiryDeps {
  log: typeof helpers.log;
  config: { value(key: string): any };
  errorCodes: typeof errorCodes;
  realms: typeof realms;
  store: Json;
  now: () => number;
  mailUses: () => Json;
  directory: () => Json;
  tlsClients: () => Json;
  scheduler: () => Json;
}

/**
 * The credential expiry reminder (#2247): the index of when each
 * certificate a person holds expires, and the job that reminds them.
 */
class CredentialExpiry {
  static readonly JOB = JOB;
  static readonly KINDS = KINDS;
  static readonly ATTRIBUTES = ATTRIBUTES;
  static readonly LOOKBACK_DAYS = LOOKBACK_DAYS;

  /**
   * Builds the reminder over its dependencies.
   *
   * @param deps - the logger, the settings, the error codes, the realms,
   *   the index store, the clock, the mail uses, the directory and the
   *   scheduler
   */
  constructor(private readonly deps: ExpiryDeps) {
    deps.log.debug("Entering CredentialExpiry.constructor().");
    deps.log.debug("Leaving CredentialExpiry.constructor().");
  }

  /**
   * The dependencies the service uses.
   *
   * @returns the dependencies
   */
  static defaultDeps(): ExpiryDeps {
    log.debug("Entering CredentialExpiry.defaultDeps().");
    log.debug("Leaving CredentialExpiry.defaultDeps().");
    return {
      log: log, config: config, errorCodes: errorCodes, realms: realms,
      store: due,
      now: function (): number {
        return Date.now();
      },
      mailUses: function (): Json {
        return require('./mail_uses');
      },
      directory: function (): Json {
        return require('../ldap/ldap_server');
      },
      tlsClients: function (): Json {
        return require('./tls_client_certificates');
      },
      scheduler: function (): Json {
        return require('../cluster/scheduler');
      }
    };
  }

  /**
   * A day, `YYYY-MM-DD` in UTC.
   *
   * @param ms - the instant
   * @returns the day
   */
  static dayOf(ms: number): string {
    log.debug("Entering CredentialExpiry.dayOf().");
    log.debug("Leaving CredentialExpiry.dayOf().");
    return new Date(ms).toISOString().slice(0, 10);
  }

  /**
   * The reminder steps of the ambient realm, in days, largest first.
   *
   * @returns the steps
   */
  steps(): number[] {
    const { log, config } = this.deps;
    log.debug("Entering CredentialExpiry.steps().");
    const held = config.value('mail.expiryReminderDays');
    const list = Array.isArray(held) ? held : String(held || '').split(',');
    const out = list.map(function (one: unknown): number {
      return Math.floor(Number(String(one).trim()));
    }).filter(function (n: number, i: number, all: number[]): boolean {
      return n > 0 && all.indexOf(n) === i;
    }).sort(function (a: number, b: number): number {
      return b - a;
    });
    log.debug("Leaving CredentialExpiry.steps(). " + out.join(','));
    return out;
  }

  /**
   * The kinds a reminder names in the ambient realm.
   *
   * @returns the kinds
   */
  kindsOn(): string[] {
    const { log, config } = this.deps;
    log.debug("Entering CredentialExpiry.kindsOn().");
    const held = config.value('mail.expiryReminderKinds');
    const list = Array.isArray(held) ? held : String(held || '').split(',');
    const out = list.map(function (one: unknown): string {
      return String(one).trim();
    }).filter(function (k: string): boolean {
      return KINDS.indexOf(k) >= 0;
    });
    log.debug("Leaving CredentialExpiry.kindsOn(). " + out.join(','));
    return out;
  }

  /**
   * The steps not yet told: those below every step that was. A step told
   * means every larger one is past.
   *
   * @param row - the row
   * @param steps - the realm's steps, largest first
   * @returns the steps still owed, largest first
   */
  static owed(row: DueRow, steps: number[]): number[] {
    log.debug("Entering CredentialExpiry.owed().");
    const told = Array.isArray(row.told) ? row.told.map(Number) : [];
    const least = told.length ? Math.min.apply(null, told) : Infinity;
    log.debug("Leaving CredentialExpiry.owed().");
    return steps.filter(function (s: number): boolean {
      return s < least;
    });
  }

  /**
   * The day a row's next reminder is due, or '' when none is.
   *
   * @param row - the row
   * @param steps - the realm's steps, largest first
   * @param nowMs - now
   * @returns `YYYY-MM-DD`, or ''
   */
  static nextOf(row: DueRow, steps: number[], nowMs: number): string {
    log.debug("Entering CredentialExpiry.nextOf().");
    const owed = CredentialExpiry.owed(row, steps);
    if (!owed.length || !(Number(row.notAfter) > nowMs)) {
      log.debug("Leaving CredentialExpiry.nextOf(). None.");
      return '';
    }
    const at = Number(row.notAfter) - owed[0] * DAY_MS;
    log.debug("Leaving CredentialExpiry.nextOf().");
    return CredentialExpiry.dayOf(Math.max(at, nowMs));
  }

  /**
   * The step a row is told at now: the nearest owed step it is inside, or
   * null when it is inside none.
   *
   * @param row - the row
   * @param steps - the realm's steps, largest first
   * @param nowMs - now
   * @returns the step in days, or null
   */
  static stepNow(row: DueRow, steps: number[], nowMs: number): number | null {
    log.debug("Entering CredentialExpiry.stepNow().");
    const left = Number(row.notAfter) - nowMs;
    if (!(left > 0)) {
      log.debug("Leaving CredentialExpiry.stepNow(). Expired.");
      return null;
    }
    const inside = CredentialExpiry.owed(row, steps)
      .filter(function (s: number): boolean {
        return left <= s * DAY_MS;
      });
    log.debug("Leaving CredentialExpiry.stepNow().");
    return inside.length ? inside[inside.length - 1] : null;
  }

  /**
   * One certificate value — PEM, or base64 DER as the directory keeps a
   * `;binary` value — as its thumbprint, label and expiry; null when it
   * does not read.
   *
   * @param value - the value
   * @returns `{ id, label, notAfter }`, or null
   */
  static certificateOf(value: string): Json {
    log.debug("Entering CredentialExpiry.certificateOf().");
    try {
      const text = String(value || '').trim();
      const input = text.indexOf('-----BEGIN') >= 0 ? text
        : Buffer.from(text.replace(/\s+/g, ''), 'base64');
      const cert = stsCrypto.parseCertificate(input);
      const notAfter = Date.parse(cert.validTo);
      const id = stsCrypto.certificateThumbprint(cert, { format: 'hex' });
      const subject = String(cert.subject || '');
      const cn = /(?:^|\n)CN=([^\n]+)/.exec(subject);
      log.debug("Leaving CredentialExpiry.certificateOf().");
      return notAfter > 0 && id
        ? { id: String(id).toLowerCase(),
            label: cn ? cn[1] : (subject.split('\n')[0] || id.slice(0, 16)),
            notAfter: notAfter }
        : null;
    } catch (e) {
      log.debug("Caught in CredentialExpiry.certificateOf(): " +
                ((e && e.message) || e));
      log.debug("Leaving CredentialExpiry.certificateOf(). Unreadable.");
      return null;
    }
  }

  /**
   * The certificates an entry's attributes hold, each once, filed under
   * the first kind it is (header).
   *
   * @param attributes - the entry's attributes, lower-cased names
   * @returns the certificates
   */
  static heldIn(attributes: Record<string, unknown>): Held[] {
    log.debug("Entering CredentialExpiry.heldIn().");
    const out: Held[] = [];
    const seen: Record<string, boolean> = {};
    const add = function (one: Held): void {
      if (one && one.id && !seen[one.id] && one.notAfter > 0) {
        seen[one.id] = true;
        out.push(one);
      }
    };
    entryObserver.valuesIn(attributes || {}, 'stsEnrolledCertificate')
      .forEach(function (value: string): void {
        let record: Json = null;
        try {
          record = JSON.parse(value);
        } catch (e) {
          log.debug("Caught in CredentialExpiry.heldIn(): " +
                    ((e && e.message) || e));
          record = null;
        }
        if (!record || record.revoked || !record.thumbprint) {
          return;
        }
        add({ id: String(record.thumbprint).toLowerCase(),
              kind: /^piv-/.test(String(record.profile || '')) ? 'piv'
                : 'certificate',
              label: String(record.subject || record.serialHex || ''),
              notAfter: Date.parse(String(record.notAfter || '')) });
      });
    [['userSMIMECertificate', 'smime'],
     ['userCertificate', 'signin-certificate']].forEach(function (pair:
        string[]): void {
      entryObserver.valuesIn(attributes || {}, pair[0])
        .forEach(function (value: string): void {
          const cert = CredentialExpiry.certificateOf(value);
          if (cert) {
            add({ id: cert.id, kind: pair[1], label: cert.label,
                  notAfter: cert.notAfter });
          }
        });
    });
    log.debug("Leaving CredentialExpiry.heldIn(). " + out.length);
    return out;
  }

  /**
   * The row key of one certificate of one person.
   *
   * @param subject - the person's subject
   * @param id - the certificate's thumbprint
   * @returns the key
   */
  static keyOf(subject: string, id: string): string {
    log.debug("Entering CredentialExpiry.keyOf().");
    log.debug("Leaving CredentialExpiry.keyOf().");
    return String(subject) + '|' + String(id);
  }

  /**
   * Files one person's certificates as the entry now holds them: a row for
   * each, its told steps kept where its expiry is the one already filed,
   * and the rows of certificates no longer held removed. In the ambient
   * realm.
   *
   * @param who - `{ subject, username }`
   * @param before - the certificates the entry held before the write (all
   *   it could hold, for a backfill: `null` reads the person's rows)
   * @param after - the certificates it holds now
   * @returns a promise of `{ filed, removed }`
   */
  async file(who: Json, before: Held[] | null,
             after: Held[]): Promise<Json> {
    const { log, store, now } = this.deps;
    log.debug("Entering CredentialExpiry.file().");
    const subject = String((who && who.subject) || '');
    const username = String((who && who.username) || '');
    if (!subject || !username) {
      log.debug("Leaving CredentialExpiry.file(). Nobody.");
      return { filed: 0, removed: 0 };
    }
    const keep: Record<string, Held> = {};
    after.forEach(function (one: Held): void {
      keep[CredentialExpiry.keyOf(subject, one.id)] = one;
    });
    let gone: string[] = [];
    if (before) {
      gone = before.map(function (one: Held): string {
        return CredentialExpiry.keyOf(subject, one.id);
      });
    } else {
      // Every row of the person that the entry is the record of; a TLS
      // client certificate's is told by its own module, and stays.
      gone = ((await store.lookupEntriesAsync('p:' + subject)) || [])
        .filter(function (e: Json): boolean {
          return !!(e && e.value &&
                    ENTRY_KINDS.indexOf(String(e.value.kind)) >= 0);
        }).map(function (e: Json): string {
          return String(e.key);
        });
    }
    gone = gone.filter(function (key: string): boolean {
      return !keep[key];
    });
    const keys = Object.keys(keep);
    if (typeof store.warm === 'function') {
      await store.warm(keys.concat(gone));
    }
    let removed = 0;
    gone.forEach(function (key: string): void {
      if (store.has(key)) {
        store.delete(key);
        removed += 1;
      }
    });
    const steps = this.steps();
    const nowMs = now();
    let filed = 0;
    keys.forEach(function (key: string): void {
      const one = keep[key];
      const held = store.get(key);
      const told = held && Number(held.notAfter) === one.notAfter &&
        Array.isArray(held.told) ? held.told.slice(0) : [];
      const row: DueRow = { subject: subject, username: username,
        kind: one.kind, label: one.label, notAfter: one.notAfter,
        told: told, next: '' };
      row.next = CredentialExpiry.nextOf(row, steps, nowMs);
      if (!held || JSON.stringify(held) !== JSON.stringify(row)) {
        store.set(key, row);
        filed += 1;
      }
    });
    log.debug("Leaving CredentialExpiry.file(). " + filed + " filed, " +
              removed + " removed.");
    return { filed: filed, removed: removed };
  }

  /**
   * Removes every row of one person, in the ambient realm.
   *
   * @param subject - the person's subject
   * @returns a promise of how many were removed
   */
  async forget(subject: string): Promise<number> {
    const { log, store } = this.deps;
    log.debug("Entering CredentialExpiry.forget().");
    if (!subject) {
      log.debug("Leaving CredentialExpiry.forget(). Nobody.");
      return 0;
    }
    let removed = 0;
    ((await store.lookupEntriesAsync('p:' + subject)) || [])
      .forEach(function (e: Json): void {
        if (store.has(e.key)) {
          store.delete(e.key);
          removed += 1;
        }
      });
    log.debug("Leaving CredentialExpiry.forget(). " + removed);
    return removed;
  }

  /**
   * A certificate the entry does not hold was issued to a person (a TLS
   * client certificate, header): its row filed, in the ambient realm.
   * Never throws.
   *
   * @param username - the person
   * @param pem - the certificate
   * @param kind - its kind, of KINDS
   * @returns a promise of what `file()` answered, or null
   */
  noteHeld(username: string, pem: string, kind: string): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering CredentialExpiry.noteHeld(). " + kind);
    const self = this;
    log.debug("Leaving CredentialExpiry.noteHeld().");
    return Promise.resolve().then(function (): Promise<Json> {
      return self.fileOne(username, pem, kind, true);
    }).catch(function (e: Json): null {
      log.error(self.deps.errorCodes.tag('STS-MAIL-0247') + 'credential ' +
                'expiry: a ' + kind + ' certificate of ' + username +
                ' was not filed: ' + ((e && e.message) || e));
      return null;
    });
  }

  /**
   * A certificate told by `noteHeld()` was revoked: its row removed, in
   * the ambient realm. Never throws.
   *
   * @param username - the person
   * @param pem - the certificate
   * @returns a promise of what `file()` answered, or null
   */
  noteGone(username: string, pem: string): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering CredentialExpiry.noteGone().");
    const self = this;
    log.debug("Leaving CredentialExpiry.noteGone().");
    return Promise.resolve().then(function (): Promise<Json> {
      return self.fileOne(username, pem, '', false);
    }).catch(function (e: Json): null {
      log.error(self.deps.errorCodes.tag('STS-MAIL-0247') + 'credential ' +
                'expiry: a revoked certificate of ' + username + ' was not ' +
                'removed from the index: ' + ((e && e.message) || e));
      return null;
    });
  }

  // One told certificate filed (`held`) or removed, by the person's
  // current subject.
  private async fileOne(username: string, pem: string, kind: string,
                        held: boolean): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering CredentialExpiry.fileOne().");
    const cert = CredentialExpiry.certificateOf(pem);
    const subject = String(helpers.subjectForName(username) || '');
    if (!cert || !subject) {
      log.debug("Leaving CredentialExpiry.fileOne(). Nothing to file.");
      return { filed: 0, removed: 0 };
    }
    const one: Held = { id: cert.id, kind: kind, label: cert.label,
                        notAfter: cert.notAfter };
    log.debug("Leaving CredentialExpiry.fileOne().");
    return this.file({ subject: subject, username: username },
                     held ? [] : [one], held ? [one] : []);
  }

  /**
   * The entry observer's watcher (header): one person's entry was written,
   * and one of ATTRIBUTES changed. Files what it holds now, in a promise
   * job after the write. Never throws.
   *
   * @param change - the observer's change: `subject`, `username`,
   *   `deleted`, `before` and `after`
   * @returns a promise of what `file()` answered, or null
   */
  entryChanged(change: Json): Promise<Json> {
    const { log, errorCodes } = this.deps;
    log.debug("Entering CredentialExpiry.entryChanged().");
    const c = change || {};
    const self = this;
    const before = CredentialExpiry.heldIn(c.before || {});
    const after = c.deleted ? [] : CredentialExpiry.heldIn(c.after || {});
    log.debug("Leaving CredentialExpiry.entryChanged().");
    return Promise.resolve().then(async function (): Promise<Json> {
      const filed = await self.file({ subject: c.subject,
                                      username: c.username }, before, after);
      if (c.deleted) {
        // A DELETED PERSON TAKES EVERY ROW WITH THEM, a TLS client
        // certificate's too: nobody is left to remind.
        filed.removed += await self.forget(String(c.subject || ''));
      }
      return filed;
    }).catch(function (e: Json): null {
      log.error(errorCodes.tag('STS-MAIL-0247') + 'credential expiry: the ' +
                'index of ' + String(c.dn || c.username || '') + ' was not ' +
                'kept in step with its entry: ' + ((e && e.message) || e));
      return null;
    });
  }

  /**
   * Why the job does nothing in a realm, or '' when it runs: the switch,
   * security notices, or no transport.
   *
   * @param realmId - the realm
   * @returns the reason, or ''
   */
  offIn(realmId: string): string {
    const { log, realms, config } = this.deps;
    log.debug("Entering CredentialExpiry.offIn().");
    const self = this;
    const why = realms.run(String(realmId || ''), function (): string {
      if (!config.value('mail.expiryReminders')) {
        return 'mail.expiryReminders is off in this realm.';
      }
      if (!config.value('mail.securityNotices')) {
        return 'mail.securityNotices is off in this realm.';
      }
      if (!self.deps.mailUses().expiryRemindersOn()) {
        return 'No mail transport is configured in this realm.';
      }
      return '';
    });
    log.debug("Leaving CredentialExpiry.offIn(). " + (why || 'on'));
    return why;
  }

  /**
   * One slice of the backfill (header), in the ambient realm: the people
   * after the cursor, each one's certificates filed; the cursor and the
   * done mark kept on BACKFILL_KEY's row.
   *
   * @returns a promise of `{ read, done }`
   */
  async backfill(): Promise<Json> {
    const { log, store } = this.deps;
    log.debug("Entering CredentialExpiry.backfill().");
    if (typeof store.warm === 'function') {
      await store.warm([BACKFILL_KEY]);
    }
    const mark = store.get(BACKFILL_KEY) || {};
    if (mark.done) {
      log.debug("Leaving CredentialExpiry.backfill(). Done before.");
      return { read: 0, done: true };
    }
    const directory = this.deps.directory();
    if (!directory || typeof directory.passkeyScanAsync !== 'function') {
      log.debug("Leaving CredentialExpiry.backfill(). No directory.");
      return { read: 0, done: false };
    }
    const people: Json[] = [];
    const answer = await directory.passkeyScanAsync({
      attribute: '', after: String(mark.cursor || ''),
      readLimit: BACKFILL_PER_RUN, wanted: Number.MAX_SAFE_INTEGER,
      rowOf: function (stored: Json): Json {
        const attributes = (stored && stored.attributes) || {};
        // The subject through its concept (#1579), not entryUUID by name.
        const uuid = String(DomainMap.fieldOf('DirectoryEntry', 'entryUuid',
                                              attributes) || '');
        return { id: String(directory.usernameOfEntry(stored) || ''),
                 subject: uuid ? 'urn:uuid:' +
                   uuid.replace(/^urn:uuid:/i, '') : '',
                 held: CredentialExpiry.heldIn(attributes) };
      },
      accept: function (row: Json): boolean {
        if (row.held.length && row.subject) {
          people.push(row);
        }
        return true;
      }
    });
    for (const one of people) {
      await this.file({ subject: one.subject, username: one.id }, null,
                      one.held);
    }
    const done = answer.done === true || answer.next === mark.cursor;
    if (done) {
      await this.backfillTlsClients();
    }
    store.set(BACKFILL_KEY, { cursor: String(answer.next || ''),
                              done: done });
    log.debug("Leaving CredentialExpiry.backfill(). " + answer.read +
              " read" + (done ? ', done.' : '.'));
    return { read: Number(answer.read) || 0, done: done };
  }

  // The realm's TLS client certificates issued before 1.2.0 (header), read
  // once from their own register when the people's walk is done.
  private async backfillTlsClients(): Promise<number> {
    const { log } = this.deps;
    log.debug("Entering CredentialExpiry.backfillTlsClients().");
    let held: Json[] = [];
    try {
      held = this.deps.tlsClients().personCertificatesOf(
        this.deps.realms.currentId()) || [];
    } catch (e) {
      log.debug("Caught in CredentialExpiry.backfillTlsClients(): " +
                ((e && e.message) || e));
      held = [];
    }
    for (const one of held) {
      await this.fileOne(String(one.username), String(one.certificatePem),
                         'tls-client', true);
    }
    log.debug("Leaving CredentialExpiry.backfillTlsClients(). " +
              held.length);
    return held.length;
  }

  /**
   * The rows owed a reminder in the ambient realm: those filed under a due
   * day from LOOKBACK_DAYS ago to today.
   *
   * @param nowMs - now
   * @returns a promise of `{ key, value }` entries, each key once
   */
  async dueRows(nowMs: number): Promise<Json[]> {
    const { log, store } = this.deps;
    log.debug("Entering CredentialExpiry.dueRows().");
    const out: Json[] = [];
    const seen: Record<string, boolean> = {};
    for (let back = LOOKBACK_DAYS; back >= 0; back -= 1) {
      const day = CredentialExpiry.dayOf(nowMs - back * DAY_MS);
      const rows = (await store.lookupEntriesAsync('n:' + day)) || [];
      rows.forEach(function (e: Json): void {
        const key = String(e.key);
        if (!seen[key] && e.value && e.value.next === day) {
          seen[key] = true;
          out.push({ key: key, value: e.value });
        }
      });
    }
    log.debug("Leaving CredentialExpiry.dueRows(). " + out.length);
    return out;
  }

  /**
   * The scheduled run for one realm (header): a slice of the backfill,
   * then every reminder due, one message per person.
   *
   * @param ctx - the scheduler's context (`realm`)
   * @returns a promise of the run's summary
   */
  runAsync(ctx: Json): Promise<Json> {
    const { log, realms } = this.deps;
    log.debug("Entering CredentialExpiry.runAsync().");
    const realmId = String((ctx && ctx.realm) || '');
    const self = this;
    log.debug("Leaving CredentialExpiry.runAsync().");
    return realms.run(realmId, function (): Promise<Json> {
      return self.remindAsync().catch(function (e: Json): Json {
        log.error(self.deps.errorCodes.tag('STS-MAIL-0246') + 'credential ' +
                  'expiry: the run in the "' + realmId + '" realm failed: ' +
                  ((e && e.message) || e));
        return { ok: false, error: String((e && e.message) || e) };
      });
    });
  }

  /**
   * One run in the ambient realm (`runAsync()`).
   *
   * @returns a promise of `{ ok, backfilled, due, mailed, told, held }`
   */
  async remindAsync(): Promise<Json> {
    const { log, store, now } = this.deps;
    log.debug("Entering CredentialExpiry.remindAsync().");
    const uses = this.deps.mailUses();
    if (!uses.expiryRemindersOn()) {
      log.debug("Leaving CredentialExpiry.remindAsync(). Off.");
      return { ok: true, skipped: 'off', mailed: 0 };
    }
    const filled = await this.backfill();
    const nowMs = now();
    const steps = this.steps();
    const kinds = this.kindsOn();
    const rows = await this.dueRows(nowMs);
    const byPerson: Record<string, Json[]> = {};
    let moved = 0;
    rows.forEach(function (e: Json): void {
      const row: DueRow = e.value;
      const step = CredentialExpiry.stepNow(row, steps, nowMs);
      if (step === null) {
        // Not inside an owed step after all (the steps changed, or none
        // is left): filed again under its next due day, or none.
        const next = CredentialExpiry.nextOf(row, steps, nowMs);
        if (next !== row.next) {
          store.set(e.key, Object.assign({}, row, { next: next }));
          moved += 1;
        }
        return;
      }
      if (kinds.indexOf(row.kind) < 0) {
        return;
      }
      (byPerson[row.username] = byPerson[row.username] || []).push({
        key: e.key, step: step, kind: row.kind, label: row.label,
        notAfter: row.notAfter, row: row });
    });
    const people = Object.keys(byPerson).sort();
    let mailed = 0;
    let told = 0;
    let held = 0;
    for (let at = 0; at < people.length; at += 1) {
      if (at >= MAILS_PER_RUN) {
        held = people.length - at;
        break;
      }
      const username = people[at];
      const items = byPerson[username];
      const answer = uses.credentialsExpiring(username, items.map(
        function (i: Json): Json {
          return { key: i.key, step: i.step, kind: i.kind, label: i.label,
                   notAfter: i.notAfter };
        })) || {};
      if (answer.ok) {
        mailed += 1;
      }
      const toldKeys = Array.isArray(answer.told) ? answer.told : [];
      items.forEach(function (i: Json): void {
        if (toldKeys.indexOf(i.key) < 0) {
          return;
        }
        const row: DueRow = Object.assign({}, i.row, {
          told: (Array.isArray(i.row.told) ? i.row.told : [])
            .concat([i.step]) });
        row.next = CredentialExpiry.nextOf(row, steps, nowMs);
        store.set(i.key, row);
        told += 1;
      });
      if (answer.again && !answer.ok) {
        // The realm's own problem (no transport, no link base), the same
        // for everybody: the rest wait for the next run.
        held = people.length - at;
        break;
      }
    }
    const out = { ok: true, backfilled: filled.read,
                  backfillDone: filled.done, due: rows.length,
                  people: people.length, mailed: mailed, told: told,
                  held: held, moved: moved };
    log.debug("Leaving CredentialExpiry.remindAsync(). " + mailed +
              " mailed.");
    return out;
  }

  /**
   * Registers the job with the scheduler, once per process.
   *
   * @returns true when registered, false when it already was
   */
  registerJobs(): boolean {
    const { log } = this.deps;
    log.debug("Entering CredentialExpiry.registerJobs().");
    let s: Json = null;
    try {
      s = this.deps.scheduler();
    } catch (e) {
      // A process with no scheduler runs no job; the index is still kept.
      log.debug("Caught in CredentialExpiry.registerJobs(): " +
                ((e && e.message) || e));
      s = null;
    }
    if (!s || typeof s.register !== 'function' || s.job(JOB)) {
      log.debug("Leaving CredentialExpiry.registerJobs(). Not registered.");
      return false;
    }
    const self = this;
    s.register({
      id: JOB,
      title: 'Credential expiry reminders',
      describe: 'Mails each person whose certificate expires within one of ' +
                'mail.expiryReminderDays a reminder naming every one due: ' +
                'what it is, the day it expires and how to renew it, one ' +
                'message per person, each certificate once per step. ' +
                'Reads only the expiry index\'s rows due today or in the ' +
                'last thirty days, never the directory, except for a slice ' +
                'of people a run until certificates held before the index ' +
                'existed have been filed.',
      owner: 'common/credential_expiry.ts',
      kind: 'cluster', scope: 'realm',
      everyMs: function (): number {
        return EVERY_MS;
      },
      off: function (realmId: string): string {
        return self.offIn(realmId);
      },
      manual: true,
      timeoutS: 900,
      run: function (ctx: Json): Promise<Json> {
        return self.runAsync(ctx);
      }
    });
    log.debug("Leaving CredentialExpiry.registerJobs().");
    return true;
  }

  /**
   * Registers the entry observer's watcher, once per process.
   *
   * @returns true when registered
   */
  watch(): boolean {
    const { log } = this.deps;
    log.debug("Entering CredentialExpiry.watch().");
    const self = this;
    const ok = entryObserver.watch('common/credential_expiry', ATTRIBUTES, {
      changed: function (change: Json): void {
        self.entryChanged(change);
      }
    });
    log.debug("Leaving CredentialExpiry.watch(). " + ok);
    return ok;
  }
}

const slot = new InstanceSlot<CredentialExpiry>(
  'common/credential_expiry',
  () => new CredentialExpiry(CredentialExpiry.defaultDeps()),
  function (instance: CredentialExpiry): void {
    instance.watch();
    instance.registerJobs();
  },
  log);

slot.buildNowUnlessDeferred();

/**
 * The credential expiry reminder (#2247). The exports forward to the
 * instance the composition root installs.
 *
 * @namespace
 */
export = {
  CredentialExpiry: CredentialExpiry,
  /**
   * Installs the instance the module-level functions forward to.
   */
  installInstance: (instance: CredentialExpiry): void =>
    slot.install(instance),
  /**
   * Says where the installed instance came from.
   */
  instanceOrigin: (): string => slot.origin(),
  JOB: JOB,
  KINDS: KINDS,
  ATTRIBUTES: ATTRIBUTES,
  store: due,
  heldIn: CredentialExpiry.heldIn,
  entryChanged: slot.forward('entryChanged'),
  noteHeld: slot.forward('noteHeld'),
  noteGone: slot.forward('noteGone'),
  forget: slot.forward('forget'),
  file: slot.forward('file'),
  backfill: slot.forward('backfill'),
  runAsync: slot.forward('runAsync'),
  remindAsync: slot.forward('remindAsync'),
  offIn: slot.forward('offIn'),
  registerJobs: slot.forward('registerJobs')
};
