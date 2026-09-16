'use strict';
//
// File: totp.ts
//
// ===========================================================================
// TIME-BASED ONE-TIME PASSWORDS: RFC 6238, OVER RFC 4226 (2026-09-10).
//
// The second factor this service can ask for that needs no hardware, no
// browser API and no origin — which is the whole reason it exists beside
// WebAuthn rather than instead of it. A WebAuthn ceremony is bound to an
// origin and runs in a browser; a six-digit code is typed into a form, so it
// works from a curl script, from a test job, and from a phone standing beside
// a machine that has neither.
//
// ---------------------------------------------------------------------------
// IT IS A SECOND FACTOR AND IT CANNOT BE MADE A FIRST ONE.
//
// `common/credentials.ts`'s `ROLES` has `primary` and `mfa` for a security key
// because a WebAuthn credential really can be either — the ceremony proves
// possession of a key the authenticator will not release, and can be asked to
// prove user verification as well. **A TOTP secret proves possession of a
// SHARED SECRET THIS SERVICE ALSO HOLDS**, which is a different claim
// altogether: anybody who can read the store can generate the same codes. That
// is fine for a second factor, whose whole job is to be a second thing, and it
// is not a credential to hang an account on.
//
// So there is no `role` on a TOTP record and no setting that adds one. A
// person with a TOTP secret and nothing else cannot sign in, and every door
// that could arrive at that state refuses it — the same rule, at the same two
// ends, that `credentials.removeKey()` and `/portal/activate` already enforce
// for an `mfa` security key.
//
// ---------------------------------------------------------------------------
// THE CODE IS VERIFIED FOR REAL, IN BOTH MODES, AND THAT IS THE SURPRISING
// PART OF THIS FILE.
//
// Everything else in this service is permissive by default — that is, in
// development mode; product mode checks them: the sign-in screen takes any
// password, an LDAP bind takes any DN, WS-Trust takes any
// UsernameToken. `common/credentials.ts`'s header argues at length that
// permissiveness is an IMPLEMENTATION here rather than an absence.
//
// **This mechanism is the second exception, and it is the SPNEGO exception
// read again.** `kerberos/CLAUDE.md` makes the argument for the first: Kerberos
// cannot be permissive the way the rest of this service is, because the
// password there IS the key — an acceptor that skipped the checksum would not
// be a permissive Kerberos acceptor, it would be a broken one. A TOTP verifier
// that accepted any six digits is in exactly that position. There is nothing
// left of RFC 6238 once the comparison goes: no artifact to inspect, no
// failure mode to demonstrate, and nothing for a client author to test their
// authenticator integration against.
//
// **And unlike a password there is no usability cost to being strict.** The
// permissiveness elsewhere exists so that somebody can type any name and get a
// token about it. Here the person has already been let in under whatever name
// they typed — the code is checked against a secret THIS SERVICE generated and
// showed them ninety seconds ago, so being strict costs a tester nothing but a
// glance at their phone, and `tests/vendored/sts_portal_totp.js` computes the
// code in the job.
//
// What development mode DOES still relax is everything around it: the password
// in front of it is unchecked, the name is unchecked, and any name may enrol.
//
// ---------------------------------------------------------------------------
// ONE SECRET PER PERSON, AND THAT IS NOT AN ARBITRARY LIMIT.
//
// `stsWebauthnCredential` is multi-valued because WebAuthn has a CREDENTIAL ID:
// an assertion says which key produced it, so holding a laptop's key and a
// phone's key is one lookup and no ambiguity. **A TOTP code carries nothing
// but six digits.** With two secrets enrolled, a code would have to be tried
// against both — which doubles the acceptance surface for a guess, makes the
// RFC 6238 section 5.2 replay guard ambiguous (which counter was spent?), and
// answers a question no person could act on when it goes wrong.
//
// So enrolling again REPLACES. The page says so before it draws the new QR
// code, because somebody who scans a second code and keeps the old app
// configured has an authenticator that silently stopped working.
//
// ---------------------------------------------------------------------------
// WHAT IS HERE AND WHAT IS IN `common/crypto.js`.
//
// The truncated HMAC — RFC 4226 section 5.3 — is `crypto.hotpCode()`, because
// this service signs and verifies in one module and an HMAC is a signature.
// Everything that is a DEPLOYMENT DECISION rather than arithmetic is here: the
// time step, how much clock skew is forgiven, how long an unconfirmed
// enrolment lives, what a secret is encoded as, and what goes in the QR code.
//
// A LIBRARY (rule 3): it registers no route, so its position in the require
// order is not a position. It requires `config`, `crypto`, `helpers`,
// `realms` and `error_codes` — none of which requires it back — and it is
// required by `common/credentials.ts`, `portal/portal.ts`, `authn/authn.ts`,
// `admin-ui/admin.js`, `admin-ui/crypto_metadata.js` and
// `admin-core/admin_views.ts`.
//
// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16).
//
//   * **`Totp` TAKES ITS DEPENDENCIES THROUGH ITS CONSTRUCTOR** — the logger,
//     the settings reader, `crypto.js`'s HOTP half, the realm registry, the
//     error codes, node's `randomBytes` and a LAZY loader for `qrcode` (still
//     required only when a QR code is drawn, for `qrSvgDataUri()`'s reason).
//     Nothing inside the class reaches for a module on its own.
//   * **THE MODULE STILL EXPORTS EVERY NAME IT DID**, from ONE TRANSITIONAL
//     instance built from the real modules at the bottom of this file, because
//     `credentials.ts`, the portal, the sign-in screen and the console require
//     it by those names. That instance goes when the composition root exists;
//     `Totp` is exported beside it for that root.
// ===========================================================================

import nodeCrypto = require('crypto');
import helpers = require('./helpers');
import config = require('./config');
import crypto = require('./crypto');
import realms = require('./realms');
// The error codes. A LEAF that requires nothing, so it cannot close a cycle
// from here. A refusal this module RETURNS carries its code non-enumerably,
// under the Symbol `mark()` uses, so a caller reads it with `codeOf()` and
// nothing that serialises the answer can send it anywhere.
import errorCodes = require('./error_codes');

// What an enrolment copied onto the record, and what `verify()` reads back.
interface TotpRecord {
  secret?: string;
  digits?: number | string;
  period?: number | string;
  algorithm?: string;
  lastCounter?: number | string;
  [key: string]: unknown;
}

interface TotpSettings {
  enabled: boolean;
  issuer: string;
  algorithm: string;
  digits: number;
  period: number;
  window: number;
  secretBytes: number;
  enrolmentTtlMs: number;
}

// What `verify()` answers. A refusal carries its error code under
// `error_codes.js`'s Symbol, which is not part of this shape.
type VerifyResult =
  | { ok: true; counter: number; drift: number }
  | { ok: false; reason: string; detail: string; counter?: number };

interface OtpauthSpec {
  issuer?: string;
  account?: string;
  secret?: string;
  algorithm?: string;
  digits?: number | string;
  period?: number | string;
}

interface HotpOptions {
  digits?: number | string;
  algorithm?: string;
}

// What a `Totp` needs from the rest of the service, named for what is asked.
interface TotpDeps {
  log: {
    debug(message: string): void;
    info(message: string): void;
    error(message: string): void;
  };
  config: { value(key: string): any };
  crypto: {
    HOTP_ALGS: Record<string, { note: string }>;
    hotpCode(key: Buffer, counter: number, opts?: HotpOptions): string;
    constantTimeEquals(a: unknown, b: unknown): boolean;
  };
  realms: { current?: () => { id?: unknown } | null | undefined };
  errorCodes: {
    mark<T>(result: T, code: string): T;
    tag(code: string): string;
  };
  randomBytes(size: number): Buffer;
  // LAZY, as the require was: see `qrSvgDataUri()`.
  loadQrcode(): {
    toString(text: string, options: Record<string, unknown>): Promise<string>;
  };
}

// ---------------------------------------------------------------------------
// RFC 4648 SECTION 6 BASE32, WRITTEN OUT HERE.
//
// Node has base64url built in and has no base32 at all, and there is no
// dependency worth adding for thirty lines. It is the encoding the whole TOTP
// world uses for a shared secret — the `secret=` parameter of an `otpauth://`
// URI is base32 by convention rather than by any specification, and every
// authenticator app expects it — so this is interoperability rather than
// taste.
//
// **PADDING IS STRIPPED ON THE WAY OUT AND TOLERATED ON THE WAY IN.** RFC 4648
// pads to a multiple of eight characters with `=`; the otpauth convention
// omits it, and several apps refuse a URI carrying one because `=` also
// separates a query parameter from its value. Accepting it on input costs one
// character class and means a secret pasted from anywhere works.
//
// **SPACES AND CASE ARE FORGIVEN ON INPUT** for one reason: the manual-entry
// path shows the secret in groups of four so that a person can type it, and a
// person typing it will type the spaces they can see.
// ---------------------------------------------------------------------------
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

class Totp {
  static readonly BASE32_ALPHABET = BASE32_ALPHABET;

  constructor(private readonly deps: TotpDeps) {
    deps.log.debug("Entering Totp.constructor().");
    deps.log.debug("Leaving Totp.constructor().");
  }

  base32Encode(buffer: Buffer | string): string {
    const { log } = this.deps;
    log.debug('Entering Totp.base32Encode(). bytes=' +
              (buffer && buffer.length));
    const bytes = Buffer.isBuffer(buffer) ? buffer :
                  Buffer.from(String(buffer), 'utf8');
    let bits = 0;
    let value = 0;
    let out = '';
    for (let i = 0; i < bytes.length; i++) {
      value = (value << 8) | bytes[i];
      bits += 8;
      while (bits >= 5) {
        out += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
        bits -= 5;
      }
    }
    if (bits > 0) {
      out += BASE32_ALPHABET[(value << (5 - bits)) & 31];
    }
    log.debug('Leaving Totp.base32Encode(). ' + out.length +
              ' character(s).');
    return out;
  }

  base32Decode(text: unknown): Buffer {
    const { log } = this.deps;
    log.debug('Entering Totp.base32Decode().');
    const cleaned = String(text || '').toUpperCase().replace(/[\s-]/g, '')
                                      .replace(/=+$/, '');
    let bits = 0;
    let value = 0;
    const out: number[] = [];
    for (let i = 0; i < cleaned.length; i++) {
      const index = BASE32_ALPHABET.indexOf(cleaned[i]);
      if (index < 0) {
        // NAMED rather than skipped. A character that is not in the alphabet
        // is a typo or a paste of something that is not a secret at all, and
        // quietly dropping it produces a secret that is WRONG rather than
        // refused — which fails later, at a sign-in, as "your code is not
        // right".
        log.debug('Leaving Totp.base32Decode(). Not base32.');
        throw new Error('"' + cleaned[i] + '" is not a base32 character. ' +
                        'A shared secret is the letters A to Z and the ' +
                        'digits 2 to 7.');
      }
      value = (value << 5) | index;
      bits += 5;
      if (bits >= 8) {
        out.push((value >>> (bits - 8)) & 255);
        bits -= 8;
      }
    }
    log.debug('Leaving Totp.base32Decode(). ' + out.length + ' byte(s).');
    return Buffer.from(out);
  }

  // The manual-entry rendering: groups of four, which is what every
  // authenticator app's own setup screen shows and what a person transcribing
  // thirty-two characters needs in order not to lose their place.
  grouped(secret: unknown): string {
    const { log } = this.deps;
    log.debug("Entering Totp.grouped().");
    log.debug("Leaving Totp.grouped().");
    return String(secret || '').replace(/(.{4})/g, '$1 ').trim();
  }

  // -------------------------------------------------------------------------
  // THE SETTINGS, READ IN ONE PLACE.
  //
  // Every one of them is read through `config.value()`, which answers out of
  // the AMBIENT REALM — so a realm may run six-digit SHA-1 codes while another
  // runs eight-digit SHA-512, and neither had to be told about the other. That
  // falls out of the realm design rather than being arranged here.
  //
  // **THE PARAMETERS ARE COPIED ONTO THE RECORD WHEN A SECRET IS ENROLLED**,
  // and this function is what an enrolment reads. Verification reads the
  // RECORD and not this — see `verify()`, where the reason is argued. A
  // setting changed after somebody enrolled must not silently invalidate the
  // authenticator they already configured.
  // -------------------------------------------------------------------------
  // A setting as a number, or the fallback where it is not one. NOT `||
  // fallback`, which is wrong for the one row here whose documented range
  // starts at zero.
  private numberOr(value: unknown, fallback: number): number {
    const { log } = this.deps;
    log.debug("Entering Totp.numberOr().");
    const n = Number(value);
    log.debug("Leaving Totp.numberOr().");
    return (value === '' || value === null || value === undefined ||
            !isFinite(n))
      ? fallback : n;
  }

  settings(): TotpSettings {
    const { log, config, crypto } = this.deps;
    log.debug("Entering Totp.settings().");
    const algorithm = String(config.value('totp.algorithm') ||
                             'SHA1').toUpperCase();
    log.debug("Leaving Totp.settings().");
    return {
      enabled: config.value('totp.enabled') !== false,
      issuer: String(config.value('totp.issuer') || '').trim(),
      algorithm: crypto.HOTP_ALGS[algorithm] ? algorithm : 'SHA1',
      digits: Math.max(6,
                       Math.min(8, Number(config.value('totp.digits') || 6))),
      period: Math.max(15,
                       Math.min(300,
                                Number(config.value('totp.period') || 30))),
      // **ZERO IS A LEGAL WINDOW AND `|| 1` TURNED IT INTO ONE** (fixed
      // 2026-09-12). The row's own description names zero as the setting to
      // reach for when demonstrating a perfectly synchronised clock, and this
      // line quietly forgave a step either side instead. `numberOr()` falls
      // back only where there is no number at all.
      window: Math.max(0,
                       Math.min(10,
                                this.numberOr(config.value('totp.window'),
                                              1))),
      secretBytes: Math.max(16, Math.min(64,
        Number(config.value('totp.secretBytes') || 20))),
      enrolmentTtlMs: Math.max(1,
                               Number(config.value(
                                 'totp.enrolmentTtlMinutes') || 10)) *
                      60 * 1000
    };
  }

  // Is the mechanism offered at all? Read at every door rather than only on
  // the page that draws the enrolment form, for the reason `authn.js` gives
  // about `authn.unauthenticatedSessions`: a page is markup and an endpoint is
  // a door, and a form posted by hand while the setting is off must not enrol
  // anybody.
  //
  // **TURNING IT OFF DOES NOT DISABLE AN EXISTING SECRET**, and that is
  // deliberate. A person who enrolled while it was on still holds the second
  // factor their account is configured for, and a setting that silently
  // DOWNGRADED every one of those accounts to a password alone would be a
  // security control with an off switch that says something else. What it
  // stops is new enrolments. `/admin/totp` says so beside the setting.
  offered(): boolean {
    const { log } = this.deps;
    log.debug("Entering Totp.offered().");
    log.debug("Leaving Totp.offered().");
    return this.settings().enabled;
  }

  // -------------------------------------------------------------------------
  // A NEW SHARED SECRET. 160 bits by default, which is RFC 4226 section 4's
  // R6 recommendation and the size every authenticator expects for
  // HMAC-SHA-1.
  //
  // `randomBytes` and nothing derived from the username, the time or a
  // counter: a secret guessable from a name is a list of accounts whose second
  // factor is no factor.
  // -------------------------------------------------------------------------
  generateSecret(opts?: { bytes?: number | string }): string {
    const { log, randomBytes } = this.deps;
    log.debug('Entering Totp.generateSecret().');
    const options = opts || {};
    const bytes = Number(options.bytes || this.settings().secretBytes);
    const secret = this.base32Encode(randomBytes(bytes));
    log.debug('Leaving Totp.generateSecret(). ' + bytes + ' byte(s).');
    return secret;
  }

  // The step number RFC 6238 section 4.2 calls T. `at` is milliseconds, so
  // that callers pass `Date.now()` and the one division lives here.
  counterAt(at: number | string, period: number | string): number {
    const { log } = this.deps;
    log.debug("Entering Totp.counterAt().");
    log.debug("Leaving Totp.counterAt().");
    return Math.floor(Number(at) / 1000 / Number(period));
  }

  // -------------------------------------------------------------------------
  // THE CODE FOR A SECRET AT A MOMENT. Used by the enrolment confirmation, by
  // the verifier below, and by NOTHING that answers a request — this service
  // never tells anybody what the current code is, which would make the whole
  // mechanism a decoration.
  // -------------------------------------------------------------------------
  codeAt(secret: unknown, at?: number,
         opts?: { period?: number | string } & HotpOptions): string {
    const { log, crypto } = this.deps;
    log.debug("Entering Totp.codeAt().");
    const options = opts || {};
    const period = Number(options.period || this.settings().period);
    log.debug("Leaving Totp.codeAt().");
    return crypto.hotpCode(this.base32Decode(secret),
                           this.counterAt(at || Date.now(), period),
                           { digits: options.digits,
                             algorithm: options.algorithm });
  }

  // -------------------------------------------------------------------------
  // VERIFY A CODE, AND ANSWER WHICH STEP IT WAS.
  //
  // **THE ANSWER IS THE COUNTER AND NOT A BOOLEAN**, because the caller needs
  // it: RFC 6238 section 5.2 requires that a code be accepted ONCE, and the
  // only way to enforce that is to remember which step was spent and refuse
  // anything at or below it next time. `common/credentials.ts` stores it on
  // the record; this function has no store and deliberately none, so that it
  // can be called from a test, from an enrolment confirmation and from a
  // sign-in with the same meaning.
  //
  // **THE PARAMETERS COME FROM THE RECORD**, which is the argument
  // `settings()` above defers to. The digits, the period and the algorithm are
  // what the QR code told the authenticator app when it was scanned, and they
  // are the app's now — this service cannot change them retrospectively. An
  // operator who edits `totp.digits` therefore changes what the NEXT enrolment
  // is, and every existing one goes on working. The alternative was measured
  // against the only thing that matters here: an operator adjusting a setting
  // must not silently lock out everybody who already enrolled.
  //
  // **THE SKEW WINDOW IS SYMMETRIC AND IT IS A REAL WINDOW.** RFC 6238 section
  // 5.2 recommends at most one step either side, which is what the default of
  // 1 gives — a code is good for its own 30 seconds plus 30 either side, so a
  // phone whose clock is a little off still works and a code lives at most 90
  // seconds. It is settable because a mock is run on laptops that have been
  // asleep.
  //
  // **THE COMPARISON IS CONSTANT TIME.** A six-digit code has a million values
  // and a rate limiter in front of it, so a timing oracle here is not the
  // interesting attack — but `crypto.constantTimeEquals()` is one call and the
  // alternative is the `===` this repository's credential module was written
  // to abolish.
  // -------------------------------------------------------------------------
  verify(record: TotpRecord | null | undefined, presented: unknown,
         opts?: { at?: number; window?: number | string }): VerifyResult {
    const { log, crypto, errorCodes } = this.deps;
    log.debug('Entering Totp.verify().');
    const options = opts || {};
    const now = Number(options.at || Date.now());
    const digits = Number((record && record.digits) ||
                          this.settings().digits);
    const period = Number((record && record.period) ||
                          this.settings().period);
    const algorithm = String((record &&
                              record.algorithm) || this.settings().algorithm);
    // The window is a POLICY and not a property of the enrolment, so it is the
    // one parameter read live rather than off the record: how much clock skew
    // this deployment forgives is the operator's to change today, and changing
    // it invalidates nothing anybody scanned.
    const window = options.window === undefined
      ? this.settings().window : Math.max(0, Number(options.window));
    const code = String(presented == null ? '' : presented)
      .replace(/[\s-]/g, '');
    if (!/^[0-9]+$/.test(code) || code.length !== digits) {
      log.debug('Leaving Totp.verify(). Not ' + digits + ' digits.');
      return errorCodes.mark({ ok: false, reason: 'shape',
               detail: 'A code is ' + digits + ' digits.' }, 'STS-AUTHN-0103');
    }
    let secret: Buffer;
    try {
      secret = this.base32Decode(record && record.secret);
    } catch (e) {
      log.error(errorCodes.tag('STS-AUTHN-0104') +
                'totp: the stored secret could not be decoded: ' + e.message);
      log.debug('Leaving Totp.verify(). The stored secret is unusable.');
      return errorCodes.mark({ ok: false, reason: 'store',
               detail: 'The stored shared secret could not be read.' },
                             'STS-AUTHN-0104');
    }
    const centre = this.counterAt(now, period);
    // EVERY STEP IN THE WINDOW IS TRIED EVEN AFTER A MATCH, deliberately. An
    // early `return` inside the loop makes the work — and so the time taken —
    // depend on WHICH step matched, which is a far better oracle than the
    // digit comparison this file bothers to make constant-time. The cost is at
    // most a handful of HMACs.
    let matched: { counter: number; drift: number } | null = null;
    for (let drift = -window; drift <= window; drift++) {
      const counter = centre + drift;
      if (counter < 0) {
        continue;
      }
      const candidate = crypto.hotpCode(secret, counter,
                                        { digits: digits,
                                          algorithm: algorithm });
      if (crypto.constantTimeEquals(candidate, code) && matched === null) {
        matched = { counter: counter, drift: drift };
      }
    }
    if (matched === null) {
      log.debug('Leaving Totp.verify(). No step in the window produced ' +
                'that code.');
      return errorCodes.mark({ ok: false, reason: 'mismatch',
               detail: 'That code is not right, or it has expired.' },
                             'STS-AUTHN-0105');
    }
    // RFC 6238 SECTION 5.2: ONCE. The counter this service last accepted is on
    // the record, and anything at or below it has already been spent — which
    // includes the ordinary case of somebody pressing the back button and
    // re-posting the same form, and the case the requirement is actually for,
    // which is a code read off somebody's screen.
    //
    // **IT REFUSES A REPEAT RATHER THAN IGNORING IT**, and the message says so
    // rather than saying the code is wrong: a person who signs in twice inside
    // thirty seconds has done nothing suspicious and needs to be told to wait
    // for the next code, not that their authenticator is broken.
    const spent = Number((record && record.lastCounter) || 0);
    if (spent && matched.counter <= spent) {
      log.info('totp: a code was refused as already spent (step ' +
               matched.counter + ', last accepted ' + spent + ').');
      log.debug('Leaving Totp.verify(). Already spent.');
      return errorCodes.mark({ ok: false, reason: 'replay',
               counter: matched.counter,
               detail: 'That code has already been used. Wait for your ' +
                       'authenticator to show the next one.' },
                             'STS-AUTHN-0106');
    }
    log.debug('Leaving Totp.verify(). Accepted at step ' + matched.counter +
              ' (drift ' + matched.drift + ').');
    return { ok: true, counter: matched.counter, drift: matched.drift };
  }

  // -------------------------------------------------------------------------
  // THE `otpauth://` URI — the de facto standard behind every QR code an
  // authenticator app has ever scanned, and a specification nobody wrote.
  //
  // It is Google's Key Uri Format, which is why this comment names a wiki page
  // rather than an RFC. Three things about it are worth stating because each
  // has been got wrong by somebody:
  //
  //   * **THE ISSUER IS SAID TWICE**, once as a prefix on the label
  //     (`Issuer:account`) and once as an `issuer=` parameter. Older apps read
  //     only the first and newer ones prefer the second; an app given only one
  //     of them shows an account with no organisation beside it, which is
  //     unhelpful the moment somebody holds two.
  //   * **THE SECRET CARRIES NO PADDING.** `=` inside a query string is what
  //     separates a parameter from its value, and several apps take the URI
  //     apart with a split rather than a parser.
  //   * **`algorithm`, `digits` AND `period` ARE ALWAYS WRITTEN OUT** even at
  //     their defaults. An app that reads them is then told exactly what this
  //     service will check, and an app that ignores them is no worse off —
  //     which is the state Google Authenticator is in, and the reason
  //     `/admin/totp` warns against changing the algorithm.
  //
  // **THE ISSUER DEFAULTS TO THIS REALM'S HOST** rather than to a constant.
  // Two realms of one process are two identity providers, and an
  // authenticator showing two accounts both labelled `mock STS` is one a
  // person cannot use.
  // -------------------------------------------------------------------------
  issuerFor(base: unknown): string {
    const { log, realms } = this.deps;
    log.debug("Entering Totp.issuerFor().");
    const configured = this.settings().issuer;
    if (configured) {
      log.debug("Leaving Totp.issuerFor().");
      return configured;
    }
    let host = String(base || '').replace(/^https?:\/\//i, '')
                                 .replace(/\/.*$/, '');
    if (!host) {
      host = 'mock STS';
    }
    // The realm, where there is one, because the whole point of the default is
    // to tell two of them apart in a list of accounts on a phone.
    const realm = realms.current && realms.current();
    const id = realm && realm.id ? String(realm.id) : '';
    log.debug("Leaving Totp.issuerFor().");
    return id ? host + ' (' + id + ')' : host;
  }

  otpauthUri(spec: OtpauthSpec | null | undefined): string {
    const { log } = this.deps;
    log.debug('Entering Totp.otpauthUri(). account=' +
              (spec && spec.account));
    const options = spec || {};
    const issuer = String(options.issuer || 'mock STS');
    const account = String(options.account || 'user');
    const label = encodeURIComponent(issuer) + ':' +
      encodeURIComponent(account);
    const params = [
      'secret=' + String(options.secret || '').replace(/=+$/, ''),
      'issuer=' + encodeURIComponent(issuer),
      'algorithm=' + String(options.algorithm || 'SHA1'),
      'digits=' + String(options.digits || 6),
      'period=' + String(options.period || 30)
    ];
    const uri = 'otpauth://totp/' + label + '?' + params.join('&');
    log.debug('Leaving Totp.otpauthUri().');
    return uri;
  }

  // -------------------------------------------------------------------------
  // THE QR CODE, AS AN SVG DATA URI.
  //
  // **IT IS AN IMAGE AND NOT A SCRIPT, WHICH IS THE WHOLE REASON THIS IS DRAWN
  // ON THE SERVER.** Every page of the user portal is `script-src 'none'` —
  // see `common/app.js`, whose comment argues that the absence of script is
  // what makes a family of reflected-content problems moot rather than merely
  // unlikely — so a QR code rendered by a JavaScript library in the browser
  // would have cost this surface that guarantee. `img-src 'self' data:` is
  // already in the policy for the two OID4VC offer pages, which draw their
  // codes exactly this way and with the same library.
  //
  // **SVG RATHER THAN PNG**, which is the one difference from those two pages.
  // A QR code is squares; an SVG of it is a few hundred bytes against a PNG's
  // several kilobytes, it scales to whatever a phone camera wants without
  // blurring, and it costs no canvas. The two older pages are not changed to
  // match, because changing a page that works to make a file consistent is
  // how the two QR renderings would come to be maintained as one thing.
  //
  // It is ASYNCHRONOUS because the library is. The two callers await it, which
  // makes both handlers `async` — and that is worth noticing rather than
  // hiding: `common/CLAUDE.md`'s worker-pool section lists exactly four
  // asynchronous call paths in this service, and this is not one of them. The
  // work is a few hundred microseconds of squares, not a post-quantum
  // signature.
  // -------------------------------------------------------------------------
  qrSvgDataUri(uri: unknown): Promise<string> {
    const { log, loadQrcode } = this.deps;
    log.debug('Entering Totp.qrSvgDataUri().');
    // REQUIRED HERE AND NOT AT THE TOP, which is the one lazy require in this
    // file. `qrcode` pulls in a chain this module has no other use for, and
    // this module is loaded by `credentials.ts` — which is on the path of
    // every password verification in the service, including the ones in `npm
    // test` where no QR code is ever drawn. (Since #50 the require is in the
    // transitional instance's `loadQrcode`, still called only from here.)
    const qrcode = loadQrcode();
    log.debug("Leaving Totp.qrSvgDataUri().");
    return qrcode.toString(String(uri), {
      type: 'svg', errorCorrectionLevel: 'M', margin: 2, width: 240
    }).then(function (svg) {
      log.debug('Leaving Totp.qrSvgDataUri(). ' + svg.length +
                ' bytes of SVG.');
      return 'data:image/svg+xml;base64,' +
             Buffer.from(svg, 'utf8').toString('base64');
    });
  }

  // -------------------------------------------------------------------------
  // WHAT `/admin/crypto-metadata` DRAWS. Read from this module rather than
  // written down over there, which is that page's whole design: the algorithm
  // table lives with the code that performs the algorithm, so the report
  // cannot describe something this service does not do.
  // -------------------------------------------------------------------------
  report() {
    const { log, crypto } = this.deps;
    log.debug("Entering Totp.report().");
    const live = this.settings();
    log.debug("Leaving Totp.report().");
    return {
      offered: live.enabled,
      algorithms: Object.keys(crypto.HOTP_ALGS).map(function (name) {
        return { name: 'HMAC-' + name.replace(/^SHA/, 'SHA-'),
                 id: name,
                 inUse: live.algorithm === name,
                 note: crypto.HOTP_ALGS[name].note };
      }),
      digits: live.digits,
      period: live.period,
      window: live.window,
      secretBits: live.secretBytes * 8,
      truncation: 'RFC 4226 section 5.3 dynamic truncation, modulo 10^' +
                  live.digits + '.',
      encoding: 'RFC 4648 base32, unpadded, as the otpauth Key Uri Format ' +
                'expects.'
    };
  }
}

// THE TRANSITIONAL INSTANCE — see the header. Built from the real modules, as
// the composition root will build one.
const totp = new Totp({
  log: helpers.log,
  config: config,
  crypto: crypto as unknown as TotpDeps['crypto'],
  realms: realms,
  errorCodes: errorCodes as unknown as TotpDeps['errorCodes'],
  randomBytes: function (size: number): Buffer {
    return nodeCrypto.randomBytes(size);
  },
  loadQrcode: function () {
    return require('qrcode');
  }
});

export = {
  Totp: Totp,
  BASE32_ALPHABET: Totp.BASE32_ALPHABET,
  base32Encode: totp.base32Encode.bind(totp) as Totp['base32Encode'],
  base32Decode: totp.base32Decode.bind(totp) as Totp['base32Decode'],
  grouped: totp.grouped.bind(totp) as Totp['grouped'],
  settings: totp.settings.bind(totp) as Totp['settings'],
  offered: totp.offered.bind(totp) as Totp['offered'],
  generateSecret: totp.generateSecret.bind(totp) as Totp['generateSecret'],
  counterAt: totp.counterAt.bind(totp) as Totp['counterAt'],
  codeAt: totp.codeAt.bind(totp) as Totp['codeAt'],
  verify: totp.verify.bind(totp) as Totp['verify'],
  issuerFor: totp.issuerFor.bind(totp) as Totp['issuerFor'],
  otpauthUri: totp.otpauthUri.bind(totp) as Totp['otpauthUri'],
  qrSvgDataUri: totp.qrSvgDataUri.bind(totp) as Totp['qrSvgDataUri'],
  report: totp.report.bind(totp) as Totp['report']
};
