// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: post_login_piv.ts
//
// ---------------------------------------------------------------------------
// THE PIV CERTIFICATE RE-ISSUE AS A POST-LOGIN ACTIVITY (#2009 P3, design
// X5): `piv-reissue`.
//
// A YubiKey's PIV slots hold classical keys (no PIV card makes a
// post-quantum key today), so what a post-quantum migration can move is the
// ISSUER: a slot certificate a classical CA signed can be forged once that
// CA's key falls, and one this realm's post-quantum EST Issuing CA signs
// cannot. The same step renews a certificate that is about to lapse. So a
// person holding a PIV slot certificate this realm issued is asked, after
// signing in, to enrol a new one through the PIV enrolment form
// (`common/piv_enrolment.ts`), unchanged: the request from `ykman piv keys
// generate` and `ykman piv certificates request`, the slot's attestation and
// the f9 certificate.
//
// WHO IS DUE IT (`due()`), from the person's own certificate records (the
// entry, never the progress row), slot by slot over `pivSlots`:
//
//   * the newest unrevoked, unexpired certificate of the slot's profile
//     (9a piv-auth, 9c piv-sign, 9d piv-key-management, 9e piv-card-auth) —
//     a person holding none for a slot is asked nothing for it: this
//     activity re-issues, it does not hand out smart cards;
//   * `classical-issuer`: its issuer signed it with a classical algorithm
//     AND the realm's EST Issuing CA is post-quantum or composite — a
//     re-issue under a classical CA would be no better, so it is not asked;
//   * `expiring`: it expires within `pivRenewDays`;
//   * a slot whose profile `est.allowedProfiles` leaves out is never asked
//     (the enrolment would be refused);
//   * `pivTarget` `rekey` — a post-quantum key ON the card — asks nobody:
//     nothing can make one today.
//
// D5 (rcbj's decision on #2009): THE CERTIFICATE A RE-ISSUE SUPERSEDES IS
// REVOKED (`superseded`) WHEN THE NEW ONE IS FIRST USED AT A SIGN-IN, not
// when it is issued. Issued, the new certificate has still to be written
// to the card (`ykman piv certificates import`), and a revocation at issue
// would leave a person whose import failed with a card that signs nobody
// in. So the enrolment records, under the NEW serial, what it replaces
// (`piv.supersedes`, a store keyed by serial — the one lookup a sign-in
// makes, never a scan), and `certificateUsed()`, asked by the sign-in
// service whenever a session starts on a certificate, revokes the old one
// and forgets the row. A row whose old certificate has expired meanwhile
// is moot, and expires with it (the store's own expiry purge).
//
// A LIBRARY (rule 3): no route, no job. Everything it reads — the
// certificate records, the PKI, the PIV enrolment form — is reached at the
// moment of use, because `cert_enrollment.ts` and `pki.js` are built long
// before it and neither requires it. `post_login.ts` requires it lazily
// from the kinds table; `authn/authn.ts` lazily at a sign-in.
// ---------------------------------------------------------------------------

import helpers = require('./helpers');
import config = require('./config');
import errorCodes = require('./error_codes');
import audit = require('./audit');
import realms = require('./realms');
import InstanceSlot = require('./instance_slot');
import PostLoginKinds = require('./post_login_kinds');

type Json = any;

const { log } = helpers;

/** The activity's id. */
const ID = PostLoginKinds.PIV_REISSUE;

/** Each PIV slot's enrolment profile (`piv_attestation.ts`'s, inverted). */
const SLOT_PROFILES: Readonly<Record<string, string>> = Object.freeze({
  '9a': 'piv-auth',
  '9c': 'piv-sign',
  '9d': 'piv-key-management',
  '9e': 'piv-card-auth'
});

/** The slots, in the order the step draws them. */
const SLOTS = Object.keys(SLOT_PROFILES);

/** How many rows of superseded certificates a realm holds at most. */
const SUPERSEDES_MAX = 100000;

/** The longest PEM text an act may carry, as the enrolment form's. */
const MAX_PEM = 32768;

// D5: under the NEW certificate's serial, what it replaces. The row expires
// with the certificate it replaces, after which there is nothing to revoke.
const supersedes = realms.map({
  persist: 'piv.supersedes',
  onDemand: { maxEntries: SUPERSEDES_MAX },
  tombstone: true,
  expiresAt: realms.expiryField('expiresAt', 1)
});

interface PivDeps {
  log: typeof helpers.log;
  config: { value(key: string): any };
  errorCodes: typeof errorCodes;
  audit: { audit(row: Json): void };
  store: Json;
  currentRealm: () => string;
  enrollment: () => Json;
  pki: () => Json;
  pqc: () => Json;
  enrolment: () => Json;
  now: () => number;
}

/**
 * The PIV certificate re-issue (#2009 P3), as the activity `post_login.ts`
 * asks, the step's act, and D5's revocation at first use.
 */
class PostLoginPiv {
  static readonly ID = ID;
  static readonly SLOT_PROFILES = SLOT_PROFILES;
  static readonly SLOTS = SLOTS;

  /**
   * Builds the activity over its dependencies.
   *
   * @param deps - the logger, the settings, the error codes, the audit, the
   *   supersede store, the realm, the enrolment core, the PKI, the
   *   post-quantum classifier, the PIV enrolment form and the clock
   */
  constructor(private readonly deps: PivDeps) {
    deps.log.debug("Entering PostLoginPiv.constructor().");
    deps.log.debug("Leaving PostLoginPiv.constructor().");
  }

  /**
   * The dependencies the service uses.
   *
   * @returns the dependencies
   */
  static defaultDeps(): PivDeps {
    log.debug("Entering PostLoginPiv.defaultDeps().");
    log.debug("Leaving PostLoginPiv.defaultDeps().");
    return {
      log: log, config: config, errorCodes: errorCodes, audit: audit,
      store: supersedes,
      currentRealm: function (): string {
        return realms.currentId();
      },
      enrollment: function (): Json {
        return require('./cert_enrollment');
      },
      pki: function (): Json {
        return require('./pki');
      },
      pqc: function (): Json {
        return require('./pqc_support');
      },
      enrolment: function (): Json {
        return require('./piv_enrolment');
      },
      now: function (): number {
        return Date.now();
      }
    };
  }

  /**
   * Whether a profile turns the activity on: its own switch, `pivEnabled`.
   *
   * @param profile - a post-login profile
   * @returns true when on
   */
  enabledIn(profile: Record<string, any>): boolean {
    const { log } = this.deps;
    log.debug("Entering PostLoginPiv.enabledIn().");
    log.debug("Leaving PostLoginPiv.enabledIn().");
    return !!profile && profile.pivEnabled === true;
  }

  /**
   * The profile's rules with the activity turned on, for a running started
   * activity.
   *
   * @param profile - a post-login profile
   * @returns the rules
   */
  turnedOn(profile: Record<string, any>): Record<string, any> {
    const { log } = this.deps;
    log.debug("Entering PostLoginPiv.turnedOn().");
    log.debug("Leaving PostLoginPiv.turnedOn().");
    return Object.assign({}, profile, { pivEnabled: true });
  }

  /**
   * Skip's length and the allotted time: the block's own rows.
   *
   * @param rules - the profile's rules
   * @returns `{ snoozeDays, graceDays }`
   */
  timing(rules: Record<string, any>): { snoozeDays: number;
                                        graceDays: number } {
    const { log } = this.deps;
    log.debug("Entering PostLoginPiv.timing().");
    log.debug("Leaving PostLoginPiv.timing().");
    return { snoozeDays: Number(rules.pivSnoozeDays) || 7,
             graceDays: Number(rules.pivGraceDays) || 0 };
  }

  /**
   * The slots a profile looks at, in the step's order.
   *
   * @param rules - the profile's rules
   * @returns the slots
   */
  slotsOf(rules: Record<string, any>): string[] {
    const { log } = this.deps;
    log.debug("Entering PostLoginPiv.slotsOf().");
    const raw = rules && rules.pivSlots !== undefined ? rules.pivSlots
      : SLOTS.join(',');
    const named = String(raw).toLowerCase().split(/[\s,]+/).filter(Boolean);
    const out = SLOTS.filter(function (slot) {
      return named.indexOf(slot) >= 0;
    });
    log.debug("Leaving PostLoginPiv.slotsOf(). " + out.join(','));
    return out;
  }

  /**
   * Whether the realm's EST Issuing CA signs with a post-quantum or
   * composite key: its key as built, or the algorithm a build would use.
   *
   * @returns true when it does
   */
  issuerIsPostQuantum(): boolean {
    const { log } = this.deps;
    log.debug("Entering PostLoginPiv.issuerIsPostQuantum().");
    let out = false;
    try {
      const described = this.deps.pki().describeIssuer(
        this.deps.currentRealm(), 'est');
      const alg = described && described.keyAlg
        ? String(described.keyAlg)
        : String(this.deps.config.value('pki.keyAlgorithm') || '');
      const info = alg ? this.deps.pqc().ofAlgorithm(alg) : null;
      out = !!info && (info.kind === 'pq' || info.kind === 'composite');
    } catch (e) {
      // An authority that cannot be read is not post-quantum: nothing is
      // asked on its account.
      log.debug("Caught in PostLoginPiv.issuerIsPostQuantum(): " +
                ((e && e.message) || e));
      out = false;
    }
    log.debug("Leaving PostLoginPiv.issuerIsPostQuantum(). " + out);
    return out;
  }

  /**
   * Whether a certificate's issuer signed it with a post-quantum or
   * composite algorithm.
   *
   * @param pem - the certificate
   * @returns true when it did
   */
  signedPostQuantum(pem: string): boolean {
    const { log } = this.deps;
    log.debug("Entering PostLoginPiv.signedPostQuantum().");
    let out = false;
    try {
      const info = this.deps.pqc().ofSignature(pem);
      out = !!info && (info.kind === 'pq' || info.kind === 'composite');
    } catch (e) {
      log.debug("Caught in PostLoginPiv.signedPostQuantum(): " +
                ((e && e.message) || e));
      out = false;
    }
    log.debug("Leaving PostLoginPiv.signedPostQuantum(). " + out);
    return out;
  }

  /**
   * Whether the realm would enrol a profile: `est.allowedProfiles` names
   * it.
   *
   * @param profile - a PIV profile
   * @returns true when it would
   */
  canIssue(profile: string): boolean {
    const { log } = this.deps;
    log.debug("Entering PostLoginPiv.canIssue(). " + profile);
    let out = false;
    try {
      out = [].concat(this.deps.enrollment().allowedProfiles('est') || [])
        .map(String).indexOf(profile) >= 0;
    } catch (e) {
      log.debug("Caught in PostLoginPiv.canIssue(): " +
                ((e && e.message) || e));
      out = false;
    }
    log.debug("Leaving PostLoginPiv.canIssue(). " + out);
    return out;
  }

  /**
   * Why this person is due the activity, or null: per slot, the newest
   * certificate of its profile, and why it is due. Never throws past the
   * caller's catch.
   *
   * @param username - the person
   * @param rules - the profile's rules
   * @param application - the application signed in to (unused: the
   *   activity is about the person's card)
   * @returns the due's facts, or null
   */
  due(username: string, rules: Record<string, any>,
      application: string): Json {
    const { log, now } = this.deps;
    log.debug("Entering PostLoginPiv.due(). " + (application ? 'app' : ''));
    if (String(rules.pivTarget || 'reissue') === 'rekey') {
      // Nothing can make a post-quantum key on a PIV card today.
      log.debug("Leaving PostLoginPiv.due(). Rekey cannot be done.");
      return null;
    }
    const trigger = String(rules.pivTrigger || 'both');
    const renewMs = Math.max(1, Number(rules.pivRenewDays) || 30) * 86400000;
    const askClassical = trigger !== 'expiring' && this.issuerIsPostQuantum();
    const askExpiring = trigger !== 'classical-issuer';
    const held: Json[] = this.deps.enrollment()
      .enrolledOf({ kind: 'person', id: username }) || [];
    const at = now();
    const slots: Json[] = [];
    this.slotsOf(rules).forEach((slot) => {
      const profile = SLOT_PROFILES[slot];
      if (!this.canIssue(profile)) {
        return;
      }
      const newest = held.filter(function (one: Json) {
        return one && one.profile === profile && !one.revoked &&
          new Date(one.notAfter).getTime() > at;
      })[0];
      if (!newest) {
        return;
      }
      const classical = askClassical &&
        !this.signedPostQuantum(String(newest.certificatePem || ''));
      const expiring = askExpiring &&
        new Date(newest.notAfter).getTime() - at < renewMs;
      if (!classical && !expiring) {
        return;
      }
      slots.push({ slot: slot, profile: profile,
                   serialHex: String(newest.serialHex || ''),
                   notAfter: String(newest.notAfter || ''),
                   reason: classical ? 'classical-issuer' : 'expiring' });
    });
    if (!slots.length) {
      log.debug("Leaving PostLoginPiv.due(). No slot is due.");
      return null;
    }
    const reason = slots.some(function (one) {
      return one.reason === 'classical-issuer';
    }) ? 'classical-issuer' : 'expiring';
    log.debug("Leaving PostLoginPiv.due(). " + reason + " " + slots.length);
    return { reason: reason, enforceable: true, method: 'reissue',
             fallback: 'none', slots: slots };
  }

  // A coded refusal, in the shape the step reads.
  private refuse(code: string, why: string): Json {
    const { log, errorCodes } = this.deps;
    log.debug("Entering PostLoginPiv.refuse(). " + code);
    log.debug("Leaving PostLoginPiv.refuse().");
    return errorCodes.mark({ ok: false, errors: [why], error: why }, code);
  }

  /**
   * The normal form of a serial: lower-case hex, no leading zeros.
   *
   * @param serial - a serial in any spelling
   * @returns the hex
   */
  static normalSerial(serial: unknown): string {
    log.debug("Entering PostLoginPiv.normalSerial().");
    log.debug("Leaving PostLoginPiv.normalSerial().");
    return String(serial || '').replace(/[^0-9a-fA-F]/g, '').toLowerCase()
      .replace(/^0+(?=.)/, '');
  }

  /**
   * Enrols a new certificate for one due slot at the step, through the PIV
   * enrolment form with the step's person as the caller, and records under
   * its serial what it replaces (D5).
   *
   * @param username - the person
   * @param due - the step's due
   * @param body - `{ slot, csr, slotPem, attestationPem }`
   * @returns `{ ok, slot, profile, serialHex, certificatePem, chainPem,
   *   command }`, or a coded refusal
   */
  async enrol(username: string, due: Json, body: Json): Promise<Json> {
    const { log, store, audit } = this.deps;
    log.debug("Entering PostLoginPiv.enrol().");
    const slot = String((body && body.slot) || '').toLowerCase();
    const wanted = [].concat((due && due.slots) || []).filter(
      function (one: Json) {
        return one && one.slot === slot;
      })[0];
    if (!wanted) {
      log.debug("Leaving PostLoginPiv.enrol(). Not a due slot.");
      return this.refuse('STS-AUTHN-0620', 'This step does not ask for a ' +
        'certificate in slot "' + slot.slice(0, 8) + '".');
    }
    if (!this.canIssue(String(wanted.profile))) {
      log.debug("Leaving PostLoginPiv.enrol(). No longer issued here.");
      return this.refuse('STS-AUTHN-0621', 'This realm no longer enrols ' +
        'the ' + wanted.profile + ' profile (est.allowedProfiles).');
    }
    const issued: Json = await this.deps.enrolment().enrol({
      username: username, actor: username, admin: false,
      profile: String(wanted.profile),
      csr: String((body && body.csr) || '').slice(0, MAX_PEM),
      slotPem: String((body && body.slotPem) || '').slice(0, MAX_PEM),
      attestationPem: String((body && body.attestationPem) || '')
        .slice(0, MAX_PEM),
      via: 'post-login:piv' });
    if (!issued || !issued.ok) {
      log.debug("Leaving PostLoginPiv.enrol(). Refused.");
      return issued;
    }
    const fresh = PostLoginPiv.normalSerial(issued.serialHex);
    const old = PostLoginPiv.normalSerial(wanted.serialHex);
    if (fresh && old && fresh !== old) {
      store.set(fresh, { username: username, profile: wanted.profile,
                         slot: slot, replaces: [old],
                         expiresAt: String(wanted.notAfter || ''),
                         at: new Date(this.deps.now()).toISOString() });
      audit.audit({
        action: 'piv.reissued', outcome: 'success', actor: username,
        target: username, channel: 'http',
        summary: username + ' enrolled a new ' + wanted.profile +
                 ' certificate (' + fresh + ') for slot ' + slot +
                 ' after signing in; ' + old + ' is revoked when the new ' +
                 'one is first used',
        detail: { slot: slot, profile: String(wanted.profile),
                  serialHex: fresh, replaces: old,
                  reason: String(wanted.reason || '') } });
    }
    log.debug("Leaving PostLoginPiv.enrol(). " + fresh);
    return { ok: true, slot: slot, profile: String(wanted.profile),
             serialHex: fresh,
             certificatePem: String(issued.certificatePem || ''),
             chainPem: [].concat(issued.chainPem || []).map(String),
             command: 'ykman piv certificates import ' + slot +
                      ' certificate.pem' };
  }

  /**
   * D5: a session started on a certificate. Where the certificate is one a
   * re-issue enrolled, the certificates it replaces are revoked
   * (`superseded`) and the row forgotten; a row whose revocation failed is
   * kept, so the next sign-in tries again. Never throws.
   *
   * @param username - who signed in
   * @param serial - the certificate's serial, in any spelling
   * @returns a promise of how many certificates were revoked
   */
  async certificateUsed(username: string, serial: unknown): Promise<number> {
    const { log, store, audit, errorCodes } = this.deps;
    log.debug("Entering PostLoginPiv.certificateUsed().");
    const key = PostLoginPiv.normalSerial(serial);
    let row: Json = null;
    try {
      row = key ? store.get(key) : null;
    } catch (e) {
      log.debug("Caught in PostLoginPiv.certificateUsed(): " +
                ((e && e.message) || e));
      row = null;
    }
    if (!row) {
      log.debug("Leaving PostLoginPiv.certificateUsed(). Nothing replaced.");
      return 0;
    }
    if (String(row.username) !== String(username)) {
      // The serial is another person's: nothing of theirs is revoked
      // because somebody else's sign-in named it.
      log.warn(errorCodes.tag('STS-PIV-0039') + 'post_login_piv: ' +
               'certificate ' + key + ' replaces a certificate of "' +
               row.username + '" and was used by "' + username +
               '"; nothing is revoked.');
      log.debug("Leaving PostLoginPiv.certificateUsed(). Not theirs.");
      return 0;
    }
    const enrollment = this.deps.enrollment();
    let revoked = 0;
    let failed = 0;
    const replaces: string[] = [].concat(row.replaces || []).map(String);
    for (let i = 0; i < replaces.length; i++) {
      const old = replaces[i];
      let done: Json = null;
      try {
        const found = enrollment.findEnrolled(old);
        if (!found || (found.record && found.record.revoked)) {
          // Gone or already revoked: nothing is left to do for it.
          continue;
        }
        done = await enrollment.revokeEnrolled(old, 'superseded', username,
          { quiet: true, entry: { kind: 'person', id: username } });
      } catch (e) {
        log.debug("Caught in PostLoginPiv.certificateUsed(): " +
                  ((e && e.message) || e));
        done = { ok: false, why: String((e && e.message) || e) };
      }
      if (done && done.ok !== false) {
        revoked += 1;
      } else {
        failed += 1;
        log.error(errorCodes.tag('STS-PIV-0038') + 'post_login_piv: ' +
                  'certificate ' + old + ' of "' + username + '", ' +
                  'superseded by ' + key + ', could not be revoked (' +
                  String((done && (done.why || (done.errors || [])[0])) ||
                         'no answer') + '); the next sign-in with ' + key +
                  ' tries again.');
      }
    }
    if (!failed) {
      store.delete(key);
    }
    if (revoked) {
      audit.audit({
        action: 'piv.superseded', outcome: 'success', actor: username,
        target: username, channel: 'http',
        summary: username + '\'s new ' + String(row.profile || 'PIV') +
                 ' certificate ' + key + ' was used to sign in, so the ' +
                 'certificate it replaces was revoked (superseded)',
        detail: { serialHex: key, replaces: replaces,
                  profile: String(row.profile || ''),
                  slot: String(row.slot || '') } });
    }
    log.debug("Leaving PostLoginPiv.certificateUsed(). " + revoked);
    return revoked;
  }

  /**
   * What a re-issue recorded under a serial (D5), for a page and a test.
   *
   * @param serial - the new certificate's serial
   * @returns the row, or null
   */
  supersedeOf(serial: unknown): Json {
    const { log, store } = this.deps;
    log.debug("Entering PostLoginPiv.supersedeOf().");
    const row = store.get(PostLoginPiv.normalSerial(serial)) || null;
    log.debug("Leaving PostLoginPiv.supersedeOf().");
    return row ? Object.assign({}, row) : null;
  }

  /**
   * Forgets every row, for a test.
   */
  forgetForTests(): void {
    const { log, store } = this.deps;
    log.debug("Entering PostLoginPiv.forgetForTests().");
    store.clear();
    log.debug("Leaving PostLoginPiv.forgetForTests().");
  }
}

const slot = new InstanceSlot<PostLoginPiv>(
  'common/post_login_piv',
  () => new PostLoginPiv(PostLoginPiv.defaultDeps()),
  null,
  log);

slot.buildNowUnlessDeferred();

/**
 * The PIV certificate re-issue as a post-login activity (#2009 P3). The
 * exports forward to the instance the composition root installs; `kind` is
 * what `post_login.ts` asks, the shape `post_login_kinds.ts` describes.
 *
 * @namespace
 */
export = {
  PostLoginPiv: PostLoginPiv,
  /**
   * Installs the instance the module-level functions forward to.
   */
  installInstance: (instance: PostLoginPiv): void => slot.install(instance),
  /**
   * Says where the installed instance came from.
   */
  instanceOrigin: (): string => slot.origin(),
  ID: ID,
  SLOT_PROFILES: SLOT_PROFILES,
  SLOTS: SLOTS,
  kind: {
    id: ID,
    exposure: 'forgery',
    enabledIn: slot.forward('enabledIn'),
    turnedOn: slot.forward('turnedOn'),
    timing: slot.forward('timing'),
    due: slot.forward('due')
  },
  canIssue: slot.forward('canIssue'),
  issuerIsPostQuantum: slot.forward('issuerIsPostQuantum'),
  enrol: slot.forward('enrol'),
  certificateUsed: slot.forward('certificateUsed'),
  supersedeOf: slot.forward('supersedeOf'),
  forgetForTests: slot.forward('forgetForTests')
};
