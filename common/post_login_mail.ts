// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: post_login_mail.ts
//
// ---------------------------------------------------------------------------
// THE MAIL-ENCRYPTION MIGRATION AS A POST-LOGIN ACTIVITY (#2009 P2, design
// X4): `pqc-mail-encryption`.
//
// Mail encrypted to a classical key today is readable once that key falls
// (harvest now, decrypt later), so this is the urgent migration: its
// exposure is `decrypt-later`, and a sign-in asks it before the passkey
// migration (`post_login_kinds.ts`). rcbj's decisions on #2009:
//
//   D1  ONE activity for OpenPGP and S/MIME: what migrates is the person's
//       MAIL ENCRYPTION, whichever of the two carries it.
//   D3  A classical OpenPGP key a post-quantum one replaces is KEPT beside
//       it for `mailKeepClassical` days (90 by default), published in the
//       Web Key Directory with it; new mail goes to the post-quantum key at
//       once; afterwards the job `post-login.mail-classical-retire` (this
//       module's) removes it from the entry and so from the directory.
//       `common/openpgp_keys.ts` holds the second slot.
//   D4  An ML-KEM S/MIME certificate is UPLOADED at this step (a KEM key
//       cannot sign a request, so issuing one needs a proof of possession
//       of its own; a later ticket). That ticket is #2220: the realm now
//       issues one on the OpenPGP and S/MIME tab of Tokens and keys, on
//       an RFC 9810 challenge-response
//       (`common/openpgp_keys.ts`), and a certificate issued there is what
//       this activity then finds on the entry. The step itself still takes
//       an upload.
//
// WHO IS DUE IT (`due()`), from the person's entry and never the progress
// row, so "done" is always the credentials' to say:
//
//   * mail encrypted with OpenPGP to a key whose encryption key is not one
//     of RFC 9980's ML-KEM composites — `openpgp-classical`;
//   * mail encrypted with S/MIME to a certificate whose key is not ML-KEM
//     (RFC 9935) — `smime-classical`;
//   * mail not encrypted at all — `none`, asked only as `mailNoKey` says
//     (`invite` never required, `require` once the allotted time passes);
//   * and nobody where the realm can take neither kind of post-quantum key
//     (`offers()`): an RFC 9980 encryption algorithm on `openpgp.algorithms`
//     for OpenPGP, a runtime that can encapsulate to ML-KEM for S/MIME
//     (`crypto.smimeKemAvailable()`). A sign-in is never held for something
//     that cannot be done. A person with no mail address is due nothing:
//     a key is registered for the address on the entry.
//
// WHAT THE STEP DOES (`challenge()`, `registerOpenPgp()`,
// `registerSmime()`), each through `common/openpgp_keys.ts`'s own door,
// unchanged: the challenge and proof of possession, the user-id/`mail`
// rule and the allow list for a key; the address rule for a certificate.
// What the activity adds is that the key or certificate must be
// post-quantum (STS-OPENPGP-0033, STS-AUTHN-0600), and that mail is then
// encrypted with it. Nothing registered here is hardware-bound (design X8;
// an OpenPGP card cannot hold an RFC 9980 key, U2).
//
// A LIBRARY (rule 3): no route. It requires `openpgp_keys` and `crypto` —
// both loaded long before this, and neither requires it — and the
// scheduler LAZILY, when its job is registered. `post_login.ts` requires
// it lazily from the table (rule 3e there), so this module never requires
// `post_login.ts`.
// ---------------------------------------------------------------------------

import helpers = require('./helpers');
import config = require('./config');
import errorCodes = require('./error_codes');
import stsCrypto = require('./crypto');
import openpgpKeys = require('./openpgp_keys');
import InstanceSlot = require('./instance_slot');
import PostLoginKinds = require('./post_login_kinds');

type Json = any;

const { log } = helpers;

/** The activity's id. */
const ID = PostLoginKinds.PQC_MAIL_ENCRYPTION;

/** The scheduler job that removes a kept classical key past its time. */
const JOB = 'post-login.mail-classical-retire';

/** How often it runs. */
const EVERY_MS = 60 * 60 * 1000;

/** The kinds of key the step may offer. */
const KINDS = ['openpgp', 'smime'];

interface MailDeps {
  log: typeof helpers.log;
  config: { value(key: string): any };
  crypto: Json;
  openpgp: Json;
  errorCodes: typeof errorCodes;
  scheduler: () => Json;
  now: () => number;
}

/**
 * The mail-encryption migration (#2009 P2), as the activity `post_login.ts`
 * asks, and the step's three acts.
 */
class PostLoginMail {
  static readonly ID = ID;
  static readonly JOB = JOB;
  static readonly KINDS = KINDS;

  /**
   * Builds the activity over its dependencies.
   *
   * @param deps - the logger, the settings, the crypto module, the OpenPGP
   *   keys, the error codes, the scheduler and the clock
   */
  constructor(private readonly deps: MailDeps) {
    deps.log.debug("Entering PostLoginMail.constructor().");
    deps.log.debug("Leaving PostLoginMail.constructor().");
  }

  /**
   * The dependencies the service uses.
   *
   * @returns the dependencies
   */
  static defaultDeps(): MailDeps {
    log.debug("Entering PostLoginMail.defaultDeps().");
    log.debug("Leaving PostLoginMail.defaultDeps().");
    return {
      log: log, config: config, crypto: stsCrypto, openpgp: openpgpKeys,
      errorCodes: errorCodes,
      scheduler: function (): Json {
        return require('../cluster/scheduler');
      },
      now: function (): number {
        return Date.now();
      }
    };
  }

  /**
   * Whether a profile turns the activity on: its own switch, `mailEnabled`
   * (design X2), never the passkey migration's `enabled`.
   *
   * @param profile - a post-login profile
   * @returns true when on
   */
  enabledIn(profile: Record<string, any>): boolean {
    const { log } = this.deps;
    log.debug("Entering PostLoginMail.enabledIn().");
    log.debug("Leaving PostLoginMail.enabledIn().");
    return !!profile && profile.mailEnabled === true;
  }

  /**
   * The profile's rules with the activity turned on, for a running started
   * activity (it overrides only the switch).
   *
   * @param profile - a post-login profile
   * @returns the rules
   */
  turnedOn(profile: Record<string, any>): Record<string, any> {
    const { log } = this.deps;
    log.debug("Entering PostLoginMail.turnedOn().");
    log.debug("Leaving PostLoginMail.turnedOn().");
    return Object.assign({}, profile, { mailEnabled: true });
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
    log.debug("Entering PostLoginMail.timing().");
    log.debug("Leaving PostLoginMail.timing().");
    return { snoozeDays: Number(rules.mailSnoozeDays) || 7,
             graceDays: Number(rules.mailGraceDays) || 0 };
  }

  /**
   * Whether the realm can take an RFC 9980 OpenPGP key: one of its ML-KEM
   * encryption algorithms is on `openpgp.algorithms` (empty names every
   * one).
   *
   * @returns true when it can
   */
  canOpenpgp(): boolean {
    const { log, crypto } = this.deps;
    log.debug("Entering PostLoginMail.canOpenpgp().");
    let out = false;
    try {
      const listed = [].concat(this.deps.config.value('openpgp.algorithms') ||
                               []).map(String).filter(Boolean);
      const kem = (crypto.OPENPGP_ENCRYPTION_ALGORITHMS || [])
        .filter(function (name: string): boolean {
          return crypto.openpgpIsPq(name);
        });
      out = !listed.length || kem.some(function (name: string): boolean {
        return listed.indexOf(name) >= 0;
      });
    } catch (e) {
      // A setting that cannot be read offers nothing.
      log.debug("Caught in PostLoginMail.canOpenpgp(): " +
                ((e && e.message) || e));
      out = false;
    }
    log.debug("Leaving PostLoginMail.canOpenpgp(). " + out);
    return out;
  }

  /**
   * Whether mail could be encrypted to an ML-KEM S/MIME certificate here.
   *
   * @returns true when it could
   */
  canSmime(): boolean {
    const { log, crypto } = this.deps;
    log.debug("Entering PostLoginMail.canSmime().");
    let out = false;
    try {
      out = crypto.smimeKemAvailable() === true;
    } catch (e) {
      log.debug("Caught in PostLoginMail.canSmime(): " +
                ((e && e.message) || e));
      out = false;
    }
    log.debug("Leaving PostLoginMail.canSmime(). " + out);
    return out;
  }

  /**
   * What the step offers, in order: the kinds `mailPrefer` allows that the
   * realm can take, the kind the person uses now first.
   *
   * @param rules - the profile's rules
   * @param current - the person's `stsMailEncryption`
   * @returns the kinds, possibly none
   */
  offers(rules: Record<string, any>, current: string): string[] {
    const { log } = this.deps;
    log.debug("Entering PostLoginMail.offers().");
    const prefer = String(rules.mailPrefer || 'either');
    const allowed = prefer === 'either' ? KINDS.slice() : [prefer];
    const order = allowed.indexOf(current) > 0
      ? [current].concat(allowed.filter(function (k) {
        return k !== current;
      })) : allowed;
    const out = order.filter((kind) => {
      return kind === 'openpgp' ? this.canOpenpgp() : this.canSmime();
    });
    log.debug("Leaving PostLoginMail.offers(). " + out.join(','));
    return out;
  }

  // What the person's mail is encrypted to now, and whether it is
  // post-quantum: `{ kind, postQuantum, algorithm, fingerprint }`.
  private currentOf(p: Json): Json {
    const { log, crypto, now } = this.deps;
    log.debug("Entering PostLoginMail.currentOf().");
    let out: Json = { kind: 'none', postQuantum: false, algorithm: '',
                      fingerprint: '' };
    if (p.mailEncryption === 'openpgp') {
      // RFC 9980's composite names, `crypto.openpgpIsPq()`'s list — the
      // first word of what `openpgp_keys.ts` drew of the encryption key.
      const named = String((p.info && p.info.encryption) || '').trim()
        .split(' ')[0];
      out = { kind: 'openpgp',
              postQuantum: !!named && crypto.openpgpIsPq(named) === true,
              algorithm: String((p.info && p.info.encryption) || ''),
              fingerprint: String(p.fingerprint || '') };
    } else if (p.mailEncryption === 'smime') {
      const cert = p.smime.length
        ? crypto.smimeRecipientCertificate(p.smime, new Date(now()))
        : { ok: false };
      out = { kind: 'smime', postQuantum: !!(cert.ok && cert.postQuantum),
              algorithm: String((cert.ok && cert.keyAlgorithm) || ''),
              fingerprint: cert.ok ? String(cert.serial || '') : '' };
    }
    log.debug("Leaving PostLoginMail.currentOf(). " + out.kind);
    return out;
  }

  /**
   * Why this person is due the activity, or null: their mail is encrypted
   * to a classical key, or not at all where `mailNoKey` asks, and the realm
   * can take a post-quantum one. Never throws past the caller's catch.
   *
   * @param username - the person
   * @param rules - the profile's rules
   * @param application - the application signed in to (unused: the
   *   activity is about the person's mail, not the sign-in)
   * @returns the due's facts, or null
   */
  due(username: string, rules: Record<string, any>,
      application: string): Json {
    const { log, openpgp } = this.deps;
    log.debug("Entering PostLoginMail.due(). " + (application ? 'app' : ''));
    const p = openpgp.person(username);
    if (!p || !String(p.mail || '').includes('@')) {
      log.debug("Leaving PostLoginMail.due(). No person or no address.");
      return null;
    }
    const current = this.currentOf(p);
    if (current.postQuantum) {
      log.debug("Leaving PostLoginMail.due(). Already post-quantum.");
      return null;
    }
    const noKey = String(rules.mailNoKey || 'leave');
    if (current.kind === 'none' && noKey !== 'invite' &&
        noKey !== 'require') {
      log.debug("Leaving PostLoginMail.due(). No encryption, not asked.");
      return null;
    }
    const offers = this.offers(rules, current.kind);
    if (!offers.length) {
      log.debug("Leaving PostLoginMail.due(). Nothing can be offered.");
      return null;
    }
    const reason = current.kind === 'none' ? 'none'
      : current.kind + '-classical';
    log.debug("Leaving PostLoginMail.due(). " + reason);
    return {
      reason: reason,
      enforceable: reason !== 'none' || noKey === 'require',
      method: offers[0],
      fallback: 'none',
      offers: offers,
      current: current,
      keepClassicalDays: Number(rules.mailKeepClassical) >= 0
        ? Number(rules.mailKeepClassical) : 90
    };
  }

  // A coded refusal, in the shape the step reads.
  private refuse(code: string, why: string): Json {
    const { log, errorCodes } = this.deps;
    log.debug("Entering PostLoginMail.refuse(). " + code);
    log.debug("Leaving PostLoginMail.refuse().");
    return errorCodes.mark({ ok: false, errors: [why], error: why }, code);
  }

  // Refuses a kind the step was not asked with: the browser said it, the
  // step decides.
  private kindProblem(due: Json, kind: string): Json {
    const { log } = this.deps;
    log.debug("Entering PostLoginMail.kindProblem(). " + kind);
    const offered = [].concat((due && due.offers) || []).map(String);
    log.debug("Leaving PostLoginMail.kindProblem().");
    return offered.indexOf(kind) >= 0 ? null
      : this.refuse('STS-AUTHN-0601', 'This step does not offer ' +
                    (kind === 'smime' ? 'an S/MIME certificate'
                                      : 'an OpenPGP key') + '.');
  }

  /**
   * Issues the person an OpenPGP registration challenge for the step.
   *
   * @param username - the person
   * @param due - the step's due
   * @returns `{ ok, challenge }`, or a coded refusal
   */
  challenge(username: string, due: Json): Json {
    const { log, openpgp } = this.deps;
    log.debug("Entering PostLoginMail.challenge().");
    const refused = this.kindProblem(due, 'openpgp');
    if (refused) {
      log.debug("Leaving PostLoginMail.challenge(). Not offered.");
      return refused;
    }
    const out = openpgp.issueChallenge(username, { actor: username,
                                                   via: 'post-login' });
    log.debug("Leaving PostLoginMail.challenge(). " + !!(out && out.ok));
    return out;
  }

  /**
   * Registers the person's post-quantum OpenPGP key at the step: the
   * proof of possession and every rule are `openpgp_keys.register()`'s;
   * the key must be post-quantum (STS-OPENPGP-0033); the replaced
   * classical key is kept for the profile's days (D3); and mail is then
   * encrypted with OpenPGP.
   *
   * @param username - the person
   * @param due - the step's due
   * @param body - `{ publicKey, signed }`
   * @returns `{ ok, fingerprint, keptUntil }`, or a coded refusal
   */
  async registerOpenPgp(username: string, due: Json,
                        body: Json): Promise<Json> {
    const { log, openpgp } = this.deps;
    log.debug("Entering PostLoginMail.registerOpenPgp().");
    const refused = this.kindProblem(due, 'openpgp');
    if (refused) {
      log.debug("Leaving PostLoginMail.registerOpenPgp(). Not offered.");
      return refused;
    }
    const done: Json = await openpgp.register(username, {
      publicKey: String((body && body.publicKey) || ''),
      signed: String((body && body.signed) || '') }, {
      actor: username, via: 'post-login', requirePostQuantum: true,
      keepClassicalDays: Number(due && due.keepClassicalDays) >= 0
        ? Number(due.keepClassicalDays) : 90 });
    if (!done || !done.ok) {
      log.debug("Leaving PostLoginMail.registerOpenPgp(). Refused.");
      return done;
    }
    const chosen: Json = openpgp.setMailEncryption(username, 'openpgp',
      { actor: username, via: 'post-login' });
    if (!chosen || !chosen.ok) {
      log.debug("Leaving PostLoginMail.registerOpenPgp(). The choice.");
      return chosen;
    }
    log.debug("Leaving PostLoginMail.registerOpenPgp(). " + done.fingerprint);
    return { ok: true, kind: 'openpgp', fingerprint: done.fingerprint,
             keptUntil: String(done.classicalKeptUntil || '') };
  }

  /**
   * Sets the person's uploaded ML-KEM S/MIME certificate at the step (D4):
   * a certificate whose key is not ML-KEM is refused (STS-AUTHN-0600)
   * before anything is written; the address rule and the write are
   * `setSmimeCertificate()`'s; mail is then encrypted with S/MIME.
   *
   * @param username - the person
   * @param due - the step's due
   * @param body - `{ certificate }`
   * @returns `{ ok, serial }`, or a coded refusal
   */
  registerSmime(username: string, due: Json, body: Json): Json {
    const { log, openpgp, crypto, now } = this.deps;
    log.debug("Entering PostLoginMail.registerSmime().");
    const refused = this.kindProblem(due, 'smime');
    if (refused) {
      log.debug("Leaving PostLoginMail.registerSmime(). Not offered.");
      return refused;
    }
    const text = String((body && body.certificate) || '').trim();
    const read = text ? crypto.smimeRecipientCertificate([text],
                                                         new Date(now()))
      : { ok: false, error: 'no certificate was given' };
    if (read.ok && !read.postQuantum) {
      log.debug("Leaving PostLoginMail.registerSmime(). Classical.");
      return this.refuse('STS-AUTHN-0600', 'The certificate\'s key is ' +
        String(read.keyAlgorithm || 'classical') + ', not ML-KEM: mail ' +
        'encrypted to it could be read once that key falls.');
    }
    const set: Json = openpgp.setSmimeCertificate(username, text,
      { actor: username, via: 'post-login' });
    if (!set || !set.ok) {
      log.debug("Leaving PostLoginMail.registerSmime(). Refused.");
      return set;
    }
    const chosen: Json = openpgp.setMailEncryption(username, 'smime',
      { actor: username, via: 'post-login' });
    if (!chosen || !chosen.ok) {
      log.debug("Leaving PostLoginMail.registerSmime(). The choice.");
      return chosen;
    }
    log.debug("Leaving PostLoginMail.registerSmime().");
    return { ok: true, kind: 'smime', serial: String(set.serial || '') };
  }

  /**
   * Registers the job that removes a kept classical key once its time has
   * passed (D3), once per process.
   *
   * @returns true when registered, false when it already was
   */
  registerJobs(): boolean {
    const { log } = this.deps;
    log.debug("Entering PostLoginMail.registerJobs().");
    let s: Json = null;
    try {
      s = this.deps.scheduler();
    } catch (e) {
      // A process with no scheduler runs no job; the read-time check still
      // stops a key past its time from being published.
      log.debug("Caught in PostLoginMail.registerJobs(): " +
                ((e && e.message) || e));
      s = null;
    }
    if (!s || typeof s.register !== 'function' || s.job(JOB)) {
      log.debug("Leaving PostLoginMail.registerJobs(). Not registered.");
      return false;
    }
    const self = this;
    s.register({
      id: JOB,
      title: 'Kept classical OpenPGP keys removed',
      describe: 'Removes a classical OpenPGP key that the post-login ' +
                'mail-encryption activity kept beside the post-quantum key ' +
                'that replaced it (#2009, D3), once the profile\'s ' +
                'mailKeepClassical days have passed: from the person\'s ' +
                'entry and so from the Web Key Directory. Walks the rows ' +
                'of kept keys only, never the directory, and writes one ' +
                'audit row per key removed. A key past its time is ' +
                'already left out of the directory and every page, ' +
                'whether or not this job has run.',
      owner: 'common/post_login_mail.ts',
      kind: 'cluster', scope: 'realm',
      everyMs: function (): number {
        return EVERY_MS;
      },
      manual: true,
      timeoutS: 300,
      run: function (ctx: Json): Promise<Json> {
        return self.deps.openpgp.retireClassicalDueAsync(ctx);
      }
    });
    log.debug("Leaving PostLoginMail.registerJobs().");
    return true;
  }
}

const slot = new InstanceSlot<PostLoginMail>(
  'common/post_login_mail',
  () => new PostLoginMail(PostLoginMail.defaultDeps()),
  function (instance: PostLoginMail): void {
    instance.registerJobs();
  },
  log);

slot.buildNowUnlessDeferred();

/**
 * The mail-encryption migration as a post-login activity (#2009 P2). The
 * exports forward to the instance the composition root installs; `kind` is
 * what `post_login.ts` asks, the shape `post_login_kinds.ts` describes.
 *
 * @namespace
 */
export = {
  PostLoginMail: PostLoginMail,
  /**
   * Installs the instance the module-level functions forward to.
   */
  installInstance: (instance: PostLoginMail): void => slot.install(instance),
  /**
   * Says where the installed instance came from.
   */
  instanceOrigin: (): string => slot.origin(),
  ID: ID,
  JOB: JOB,
  KINDS: KINDS,
  kind: {
    id: ID,
    exposure: 'decrypt-later',
    enabledIn: slot.forward('enabledIn'),
    turnedOn: slot.forward('turnedOn'),
    timing: slot.forward('timing'),
    due: slot.forward('due')
  },
  offers: slot.forward('offers'),
  canOpenpgp: slot.forward('canOpenpgp'),
  canSmime: slot.forward('canSmime'),
  challenge: slot.forward('challenge'),
  registerOpenPgp: slot.forward('registerOpenPgp'),
  registerSmime: slot.forward('registerSmime'),
  registerJobs: slot.forward('registerJobs')
};
