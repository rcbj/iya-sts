// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: hotp.ts
//
// ===========================================================================
// COUNTER-BASED ONE-TIME PASSWORDS: RFC 4226 (#1955 P4, design S3 and X5).
//
// The second factor a YubiKey types when its OTP slot is touched
// (`ykman otp hotp`), and the one a vendor's pre-provisioned token shows on
// its display — with no app, no clock and no browser API. It is `totp.ts`'s
// sibling and shares everything that is not about time: `crypto.hotpCode()`
// is the RFC 4226 section 5.3 truncation both call, `totp.ts`'s base32 is the
// secret's encoding, and like TOTP it is A SECOND FACTOR AND NEVER A FIRST
// (this service holds the same secret the token does; `totp.ts` argues it).
//
// ---------------------------------------------------------------------------
// WHAT IS DIFFERENT, AND WHY EACH DIFFERENCE IS HERE.
//
//   * **THE MOVING FACTOR IS A COUNTER THE TOKEN ADVANCES ON EVERY PRESS**,
//     not the clock. A press that never reached this service (a code typed
//     into the wrong window, a touch by accident) moves the token ahead of
//     the record, so verification is a LOOK-AHEAD (RFC 4226 section 7.4):
//     the codes for the stored counter C and the next `hotp.window` values
//     are tried, and a match at C+k accepts and moves the record to C+k+1.
//     Never BEHIND: a code at a counter below C is spent, and that is the
//     whole replay defence (section 7.2).
//   * **A TOKEN PRESSED TOO OFTEN FALLS OUT OF THE WINDOW**, and section
//     7.4's answer is RESYNCHRONISATION: the person presents TWO CONSECUTIVE
//     codes and the larger `hotp.resyncWindow` is searched for a counter c
//     where c gives the first and c+1 the second. One code in a window of a
//     hundred is a hundred guesses; two consecutive codes in it are a
//     hundred guesses at a pair, which is what makes the larger search safe.
//   * **THE COUNTER IS ADVANCED BY COMPARE-AND-SET IN THE STORE (X5)**, not
//     here: `common/credentials.ts` spends an accepted counter through
//     `cluster/cluster_counters.js`'s `advance()`, the one conditional upsert
//     that lets exactly one of two concurrent verifications of a code win,
//     on two nodes or two workers. This file has no store, deliberately, so
//     a test and a sign-in call it with the same meaning (`totp.verify()`'s
//     arrangement).
//   * **THROTTLING IS THE SIGN-IN STEP'S** (section 7.3): every door that
//     takes a code sits behind `websecurity.attemptShared('mfa-code')`, the
//     same buckets TOTP's codes spend, so a person holding both has one
//     budget, not two.
//
// **SETTINGS ARE READ AT ENROLMENT AND AT VERIFICATION AS TOTP'S ARE**: the
// digits are the token's and are copied onto the record (a QR code told the
// app, or the vendor's file told this service); the look-ahead and the resync
// window are policy and are read live, so changing them invalidates nothing
// anybody enrolled.
//
// A LIBRARY (rule 3): it registers no route. It requires `config`, `crypto`,
// `helpers`, `error_codes`, the authentication policy and `totp` (for the
// base32), none of which requires it back.
// ===========================================================================

import helpers = require('./helpers');
import config = require('./config');
import crypto = require('./crypto');
import errorCodes = require('./error_codes');
import InstanceSlot = require('./instance_slot');
import authnPolicy = require('./authn_policy');
import totp = require('./totp');

/** What an HOTP record carries that verification reads. */
interface HotpRecord {
  secret?: string;
  digits?: number | string;
  algorithm?: string;
  counter?: number | string;
  [key: string]: unknown;
}

interface HotpSettings {
  enabled: boolean;
  digits: number;
  window: number;
  resyncWindow: number;
}

type HotpVerdict =
  | { ok: true; counter: number; next: number; ahead: number }
  | { ok: false; reason: string; detail: string };

interface HotpDeps {
  log: {
    debug(message: string): void;
    info(message: string): void;
    error(message: string): void;
  };
  config: { value(key: string): any };
  crypto: {
    HOTP_ALGS: Record<string, { note: string }>;
    hotpCode(key: Buffer, counter: number,
             opts?: { digits?: number | string; algorithm?: string }): string;
    constantTimeEquals(a: unknown, b: unknown): boolean;
  };
  authnPolicy: { allows(mechanism: string, role: string): boolean };
  errorCodes: {
    mark<T>(result: T, code: string): T;
    tag(code: string): string;
  };
  base32Decode(text: unknown): Buffer;
}

// The bounds the settings rows also state; held here so a value that reaches
// this module some other way is clamped the same.
const MAX_WINDOW = 100;
const MAX_RESYNC_WINDOW = 1000;

/**
 * Counter-based one-time passwords (RFC 4226) as a second factor: the
 * look-ahead window, two-code resynchronisation and the otpauth URI. The
 * counter is spent by the caller, through the cluster counter (X5).
 */
class Hotp {
  static readonly MAX_WINDOW = MAX_WINDOW;
  static readonly MAX_RESYNC_WINDOW = MAX_RESYNC_WINDOW;

  /**
   * Builds the instance over its dependencies.
   *
   * @param deps - the logger, settings, crypto, policy, codes and base32
   */
  constructor(private readonly deps: HotpDeps) {
    deps.log.debug("Entering Hotp.constructor().");
    deps.log.debug("Leaving Hotp.constructor().");
  }

  /**
   * The dependencies the service builds the instance with.
   *
   * @returns the real modules
   */
  static defaultDeps(): HotpDeps {
    helpers.log.debug("Entering Hotp.defaultDeps().");
    helpers.log.debug("Leaving Hotp.defaultDeps().");
    return {
      log: helpers.log,
      config: config,
      crypto: crypto as unknown as HotpDeps['crypto'],
      authnPolicy: authnPolicy,
      errorCodes: errorCodes as unknown as HotpDeps['errorCodes'],
      base32Decode: function (text: unknown): Buffer {
        return totp.base32Decode(text);
      }
    };
  }

  // A setting as a number, or the fallback where it is not one — never
  // `|| fallback`, which would make the legal zero of `hotp.window`
  // unreachable (the root CLAUDE.md's rule).
  private numberOr(value: unknown, fallback: number): number {
    const { log } = this.deps;
    log.debug("Entering Hotp.numberOr().");
    const n = Number(value);
    log.debug("Leaving Hotp.numberOr().");
    return (value === '' || value === null || value === undefined ||
            !isFinite(n)) ? fallback : Math.floor(n);
  }

  /**
   * The HOTP settings of the ambient realm, bounded to their ranges.
   *
   * @returns `{ enabled, digits, window, resyncWindow }`
   */
  settings(): HotpSettings {
    const { log, config: cfg } = this.deps;
    log.debug("Entering Hotp.settings().");
    const out = {
      // The authentication policy's `hotp` row: off stops ENROLMENT and a
      // claim of an imported token, never a credential already held (TOTP's
      // contract, `totp.ts`'s `offered()`).
      enabled: this.deps.authnPolicy.allows('hotp', 'second-factor'),
      digits: Math.max(6, Math.min(8, this.numberOr(cfg.value('hotp.digits'),
                                                    6))),
      window: Math.max(0, Math.min(MAX_WINDOW,
        this.numberOr(cfg.value('hotp.window'), 10))),
      resyncWindow: Math.max(2, Math.min(MAX_RESYNC_WINDOW,
        this.numberOr(cfg.value('hotp.resyncWindow'), 100)))
    };
    log.debug("Leaving Hotp.settings().");
    return out;
  }

  /**
   * Whether new HOTP enrolments are offered in the ambient realm.
   *
   * @returns the policy's answer
   */
  offered(): boolean {
    const { log } = this.deps;
    log.debug("Entering Hotp.offered().");
    log.debug("Leaving Hotp.offered().");
    return this.settings().enabled;
  }

  // The code's shape: the record's number of digits, spaces and hyphens
  // forgiven (a token's display groups them).
  private cleaned(presented: unknown): string {
    const { log } = this.deps;
    log.debug("Entering Hotp.cleaned().");
    log.debug("Leaving Hotp.cleaned().");
    return String(presented == null ? '' : presented).replace(/[\s-]/g, '');
  }

  private secretOf(record: HotpRecord | null | undefined): Buffer | null {
    const { log, errorCodes: codes } = this.deps;
    log.debug("Entering Hotp.secretOf().");
    try {
      const out = this.deps.base32Decode(record && record.secret);
      log.debug("Leaving Hotp.secretOf().");
      return out.length ? out : null;
    } catch (e) {
      log.error(codes.tag('STS-OATH-0002') + 'hotp: the stored secret could ' +
                'not be decoded: ' + ((e && e.message) || e));
      log.debug("Leaving Hotp.secretOf(). Unusable.");
      return null;
    }
  }

  /**
   * The code for a secret at a counter; used by an enrolment confirmation
   * and the tests, never to answer a request.
   *
   * @param secret - the base32 secret
   * @param counter - the counter
   * @param opts - `digits`, `algorithm`
   * @returns the code
   */
  codeAt(secret: unknown, counter: number,
         opts?: { digits?: number | string; algorithm?: string }): string {
    const { log, crypto: c } = this.deps;
    log.debug("Entering Hotp.codeAt().");
    const o = opts || {};
    const out = c.hotpCode(this.deps.base32Decode(secret), counter,
                           { digits: o.digits || 6,
                             algorithm: o.algorithm || 'SHA1' });
    log.debug("Leaving Hotp.codeAt().");
    return out;
  }

  // -------------------------------------------------------------------------
  // THE LOOK-AHEAD (RFC 4226 section 7.4). Every counter in the window is
  // computed even after a match, for `totp.verify()`'s reason: an early
  // return would make the time taken say which counter matched. The match
  // kept is the LOWEST, so a code that by chance repeats inside the window
  // (one in a million per pair at six digits) moves the counter the least.
  // -------------------------------------------------------------------------
  /**
   * Verifies a presented code against a record by look-ahead from its
   * counter. A refusal carries its error code.
   *
   * @param record - the HOTP record (`secret`, `digits`, `algorithm`,
   *   `counter`, the next counter the token is expected to show)
   * @param presented - the code as typed
   * @param opts - `window`, overriding `hotp.window`
   * @returns `{ ok: true, counter, next, ahead }` or `{ ok: false, reason,
   *   detail }`, `reason` one of `shape`, `store` or `mismatch`
   */
  verify(record: HotpRecord | null | undefined, presented: unknown,
         opts?: { window?: number | string }): HotpVerdict {
    const { log, crypto: c, errorCodes: codes } = this.deps;
    log.debug("Entering Hotp.verify().");
    const o = opts || {};
    const digits = Number((record && record.digits) || this.settings().digits);
    const algorithm = String((record && record.algorithm) || 'SHA1');
    const window = o.window === undefined ? this.settings().window
      : Math.max(0, Math.min(MAX_WINDOW, Math.floor(Number(o.window) || 0)));
    const code = this.cleaned(presented);
    if (!/^[0-9]+$/.test(code) || code.length !== digits) {
      log.debug("Leaving Hotp.verify(). Not " + digits + " digits.");
      return codes.mark({ ok: false, reason: 'shape',
        detail: 'A code is ' + digits + ' digits.' }, 'STS-OATH-0001');
    }
    const secret = this.secretOf(record);
    if (!secret) {
      log.debug("Leaving Hotp.verify(). The secret is unusable.");
      return codes.mark({ ok: false, reason: 'store',
        detail: 'The stored shared secret could not be read.' },
        'STS-OATH-0002');
    }
    const base = Math.max(0, Math.floor(Number((record && record.counter) ||
                                               0)));
    let matched = -1;
    for (let k = 0; k <= window; k++) {
      const candidate = c.hotpCode(secret, base + k,
                                   { digits: digits, algorithm: algorithm });
      if (c.constantTimeEquals(candidate, code) && matched < 0) {
        matched = base + k;
      }
    }
    if (matched < 0) {
      log.debug("Leaving Hotp.verify(). No counter in the window.");
      return codes.mark({ ok: false, reason: 'mismatch',
        detail: 'That code is not right. If your token has been pressed ' +
                'many times without signing in, resynchronise it with two ' +
                'codes in a row.' }, 'STS-OATH-0003');
    }
    log.debug("Leaving Hotp.verify(). Accepted at counter " + matched + ".");
    return { ok: true, counter: matched, next: matched + 1,
             ahead: matched - base };
  }

  // -------------------------------------------------------------------------
  // RESYNCHRONISATION (RFC 4226 section 7.4): two consecutive codes, over the
  // larger window. The answer's `next` is the counter after the SECOND code,
  // so neither of the two can be presented again.
  // -------------------------------------------------------------------------
  /**
   * Finds the counter two consecutive codes came from, over the resync
   * window. A refusal carries its error code.
   *
   * @param record - the HOTP record
   * @param first - the first code
   * @param second - the code the token showed next
   * @param opts - `window`, overriding `hotp.resyncWindow`
   * @returns `{ ok: true, counter, next, ahead }` (`counter` the second
   *   code's), or a refusal
   */
  resync(record: HotpRecord | null | undefined, first: unknown,
         second: unknown, opts?: { window?: number | string }): HotpVerdict {
    const { log, crypto: c, errorCodes: codes } = this.deps;
    log.debug("Entering Hotp.resync().");
    const o = opts || {};
    const digits = Number((record && record.digits) || this.settings().digits);
    const algorithm = String((record && record.algorithm) || 'SHA1');
    const window = o.window === undefined ? this.settings().resyncWindow
      : Math.max(2, Math.min(MAX_RESYNC_WINDOW,
                             Math.floor(Number(o.window) || 2)));
    const one = this.cleaned(first);
    const two = this.cleaned(second);
    if (!/^[0-9]+$/.test(one) || one.length !== digits ||
        !/^[0-9]+$/.test(two) || two.length !== digits) {
      log.debug("Leaving Hotp.resync(). Not two codes of " + digits +
                " digits.");
      return codes.mark({ ok: false, reason: 'shape',
        detail: 'Resynchronising takes two codes of ' + digits + ' digits, ' +
                'one after the other.' }, 'STS-OATH-0001');
    }
    const secret = this.secretOf(record);
    if (!secret) {
      log.debug("Leaving Hotp.resync(). The secret is unusable.");
      return codes.mark({ ok: false, reason: 'store',
        detail: 'The stored shared secret could not be read.' },
        'STS-OATH-0002');
    }
    const base = Math.max(0, Math.floor(Number((record && record.counter) ||
                                               0)));
    // Each counter's code once: the window plus one, so the pair at its edge
    // is found. Every one is computed, for verify()'s reason.
    const codesAt: string[] = [];
    for (let k = 0; k <= window; k++) {
      codesAt.push(c.hotpCode(secret, base + k,
                              { digits: digits, algorithm: algorithm }));
    }
    let matched = -1;
    for (let k = 0; k < window; k++) {
      const pair = c.constantTimeEquals(codesAt[k], one) &&
                   c.constantTimeEquals(codesAt[k + 1], two);
      if (pair && matched < 0) {
        matched = base + k + 1;
      }
    }
    if (matched < 0) {
      log.debug("Leaving Hotp.resync(). No consecutive pair.");
      return codes.mark({ ok: false, reason: 'mismatch',
        detail: 'Those two codes are not consecutive codes of this token ' +
                'within ' + window + ' presses. Press it twice more and ' +
                'enter both codes.' }, 'STS-OATH-0004');
    }
    log.debug("Leaving Hotp.resync(). Found at counter " + matched + ".");
    return { ok: true, counter: matched, next: matched + 1,
             ahead: matched - base };
  }

  // -------------------------------------------------------------------------
  // THE `otpauth://hotp/` URI: Google's Key Uri Format, as `totp.ts`'s
  // `otpauthUri()` writes it, with `counter` (REQUIRED for hotp there) in
  // place of `period`. A YubiKey's OTP slot is programmed from the secret
  // and digits instead (`ykman otp hotp 2 <secret>`), which the portal shows
  // beside the QR code.
  // -------------------------------------------------------------------------
  /**
   * Builds the `otpauth://hotp/` URI.
   *
   * @param spec - `{ issuer, account, secret, digits, counter }`
   * @returns the URI
   */
  otpauthUri(spec: { issuer?: string; account?: string; secret?: string;
                     digits?: number | string; counter?: number | string }):
      string {
    const { log } = this.deps;
    log.debug("Entering Hotp.otpauthUri().");
    const o = spec || {};
    const issuer = String(o.issuer || 'IYA STS');
    const label = encodeURIComponent(issuer) + ':' +
      encodeURIComponent(String(o.account || 'user'));
    const params = [
      'secret=' + String(o.secret || '').replace(/=+$/, ''),
      'issuer=' + encodeURIComponent(issuer),
      'algorithm=SHA1',
      'digits=' + String(o.digits || 6),
      'counter=' + String(Math.max(0, Math.floor(Number(o.counter) || 0)))
    ];
    log.debug("Leaving Hotp.otpauthUri().");
    return 'otpauth://hotp/' + label + '?' + params.join('&');
  }

  /**
   * Describes the mechanism for `/admin/crypto-metadata`.
   *
   * @returns the report object
   */
  report() {
    const { log } = this.deps;
    log.debug("Entering Hotp.report().");
    const live = this.settings();
    log.debug("Leaving Hotp.report().");
    return {
      offered: live.enabled,
      algorithm: 'HMAC-SHA-1 (RFC 4226 section 5); an imported token may ' +
                 'name SHA-256 or SHA-512. There is no post-quantum MAC.',
      digits: live.digits,
      window: live.window,
      resyncWindow: live.resyncWindow,
      truncation: 'RFC 4226 section 5.3 dynamic truncation.',
      counter: 'Advanced by compare-and-set in the store ' +
               '(cluster/cluster_counters.js), so one code is accepted ' +
               'once across every node and worker.'
    };
  }
}

const slot = new InstanceSlot<Hotp>(
  'common/hotp',
  () => new Hotp(Hotp.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * Counter-based one-time passwords (RFC 4226) as a second factor (#1955 P4).
 * @namespace
 */
export = {
  Hotp: Hotp,
  installInstance: (instance: Hotp): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  settings: slot.forward('settings'),
  offered: slot.forward('offered'),
  codeAt: slot.forward('codeAt'),
  verify: slot.forward('verify'),
  resync: slot.forward('resync'),
  otpauthUri: slot.forward('otpauthUri'),
  report: slot.forward('report')
};
