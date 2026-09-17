'use strict';
//
// File: backup_codes.ts
//
// ===========================================================================
// RECOVERY CODES: THE SECOND FACTOR THAT WORKS WHEN THE OTHER ONE CANNOT
// (2026-09-10).
//
// A short list of single-use strings, generated once, that stand in for
// whichever second factor a person is configured for when they cannot produce
// it — the phone with the authenticator on it is lost, flat or in another
// country, or the security key is in a drawer at home.
//
// ---------------------------------------------------------------------------
// **IT IS THE ONE MECHANISM IN THIS SERVICE THAT NO SPECIFICATION DEFINES**,
// and that is worth saying at the top because everything else here is an
// implementation of somebody's document. There is no RFC for a recovery code.
// What every identity provider does converges anyway — a handful of random
// strings, shown once, each accepted once — and the decisions that are left
// are the ones this file makes: how many, how long, out of which characters,
// and what happens when the last one is spent.
//
// So there is no interoperability argument available here and no test vectors
// to check against. The arguments are all about the person holding the list.
//
// ---------------------------------------------------------------------------
// THE ALPHABET IS THE SAME THIRTY-TWO CHARACTERS AS RFC 4648 BASE32 AND IT IS
// NOT SHARED WITH IT.
//
// `common/totp.ts` uses `ABCDEFGHIJKLMNOPQRSTUVWXYZ234567` because the
// `otpauth://` Key Uri Format says a shared secret is base32 — an
// INTEROPERABILITY requirement, and changing it would break every
// authenticator app.
//
// This file uses the same thirty-two characters for a completely different
// reason: **they contain no confusable pair.** There is no `0` beside `O`, no
// `1` beside `I` or `l`, no `8` beside `B`. A recovery code is the one
// credential in this service that a person WRITES DOWN ON PAPER and types back
// months later, possibly from their own handwriting, so a character set that
// makes `O0` a coin-toss is a code that fails and is blamed on the service.
//
// The two are therefore declared separately rather than one importing the
// other. They are the same set today by coincidence of good properties, and a
// change to either — a base32 variant demanded by some app, a decision here to
// drop vowels so that no code spells anything — must not silently move the
// other.
//
// ---------------------------------------------------------------------------
// ~~WHY THE CODES ARE ENCRYPTED AT REST AND NOT HASHED~~ — **REVERSED ON
// 2026-09-11, AND THIS HEADER WENT ON SAYING IT FOR A DAY.** The two sections
// below are kept as the record of the argument that lost: since that date a
// set is SHOWN ONCE and stored as a scrypt HASH per code (see `hash()` and the
// block above it), nothing can show a stored set again, and a set is generated
// when the person ASKS rather than by the act of enrolling. `common/CLAUDE.md`
// rule 3y carries what the reversal cost. `report().atRest` said "ENCRYPTED
// and not hashed" until 2026-09-12 as well, and `/admin/crypto-metadata`
// printed it.
//
// WHY THE CODES WERE ENCRYPTED AT REST AND NOT HASHED, WHICH IS THE OPPOSITE OF
// WHAT `userPassword` DOES.
//
// `common/crypto.js`'s own comment states this repository's rule: **a secret
// this service VERIFIES is hashed, and a secret it must PRESENT cannot be.** A
// password is verified and never shown again, so it is scrypt. A federation
// relationship's `fedClientSecret` is sent to somebody else's token endpoint,
// so it has to be recoverable.
//
// A recovery code is verified AND presented, and which half wins is decided by
// one product question: **may a person look at their remaining codes again?**
//
// This service says yes, and `/portal/mfa` has a control that shows them. The
// reason is the failure mode: a list shown exactly once, at the end of an
// enrolment somebody is rushing through, is a list most people close without
// reading — and the moment it matters is months later, when the phone is gone
// and the account is the only way into whatever they are trying to reach. A
// mock identity service whose recovery mechanism is unusable in the one
// situation it exists for teaches a client author nothing.
//
// **So they are recoverable, which means they are encrypted rather than
// hashed** — AES-256-GCM under the same key-encryption key that protects the
// signing keys, through `common/keystore.js`, exactly as the TOTP shared
// secret beside them is. `common/credentials.ts` does the sealing; this file
// holds no store and touches no key.
//
// **WHAT THAT COSTS IS SAID OUT LOUD RATHER THAN HIDDEN**: anybody who holds
// the key-encryption key can read somebody's recovery codes, where nobody who
// holds it can read their password. That is the same exposure the TOTP shared
// secret already has and for the same arithmetic reason, and it is the whole
// of why both are SECOND factors here and neither can be made a first one.
//
// ---------------------------------------------------------------------------
// THEY WERE GENERATED ONCE, AUTOMATICALLY, WHEN A SECOND FACTOR WAS ENROLLED —
// reversed with the section above on 2026-09-11; `recoveryAdvised` is what
// replaced the automatic issue.
//
// Not on request, and not again afterwards. `common/credentials.ts` calls
// `ensureBackupCodes()` from the two places a person comes to hold a second
// factor — a confirmed authenticator app, and a security key enrolled in the
// `mfa` role — and that function does nothing at all when a set already
// exists.
//
// **"ONCE" IS ABOUT THE SET AND NOT ABOUT THE ACCOUNT.** Regenerating silently
// is the defect being avoided: somebody who printed a list in March and
// re-enrolled an authenticator in June would be holding a page of strings that
// stopped working without anybody telling them. An operator's Clear on that
// person's row under `/admin/users` deletes the set, and the next enrolment
// issues a new one — which is the same shape as the Clear that is the only way
// back from a lost phone, and is deliberately not something the person can do
// for themselves.
//
// ---------------------------------------------------------------------------
// A LIBRARY (rule 3). It registers no route, so its position in the require
// order is not a position. It requires `helpers` (for `log`), `config`,
// `crypto` and `error_codes` — none of which requires it back — and it is
// required by `common/credentials.ts`, `portal/portal.ts`,
// `admin-ui/admin.ts`, `admin-ui/crypto_metadata.ts` and
// `admin-core/admin_views.ts` (`authn/authn.ts` reaches it through
// `credentials.ts`).
//
// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16).
//
//   * **`BackupCodes` TAKES ITS DEPENDENCIES THROUGH ITS CONSTRUCTOR** — the
//     logger, the settings reader, `crypto.js`'s comparison and secret-hashing
//     half, the error codes and node's `randomInt`. Nothing inside the class
//     reaches for a module on its own.
//   * **THE MODULE STILL EXPORTS EVERY NAME IT DID**, because `credentials.ts`,
//     the portal and the console require it by those names. Since #50's R2 the
//     composition root builds the instance (`BackupCodes.defaultDeps()`) and
//     installs it; the module's old export names are FACADES that forward to
//     it, for the JavaScript callers, and a process without the root builds a
//     default when this module finishes loading. `BackupCodes` is exported
//     beside them for that root.
// ===========================================================================

import nodeCrypto = require('crypto');
import helpers = require('./helpers');
import config = require('./config');
import crypto = require('./crypto');
// The error codes. A LEAF that requires nothing, so it cannot close a cycle
// from here; the one failure this module has is logged with its code.
import errorCodes = require('./error_codes');
import InstanceSlot = require('./instance_slot');

// See the header: the same thirty-two characters as base32 and for a different
// reason, declared here so that a change to either cannot move the other.
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

interface BackupCodeSettings {
  enabled: boolean;
  count: number;
  length: number;
  groupSize: number;
}

// What a `BackupCodes` needs from the rest of the service.
interface BackupCodesDeps {
  log: {
    debug(message: string): void;
    error(message: string): void;
  };
  config: { value(key: string): any };
  crypto: {
    constantTimeEquals(a: unknown, b: unknown): boolean;
    hashSecret(plaintext: string): string;
    hashSecretAsync(plaintext: string): Promise<string>;
    verifySecret(plaintext: string, stored: unknown): boolean;
    verifySecretAsync(plaintext: string, stored: unknown): Promise<boolean>;
  };
  errorCodes: { tag(code: string): string };
  randomInt(min: number, max: number): number;
}

class BackupCodes {
  static readonly ALPHABET = ALPHABET;

  constructor(private readonly deps: BackupCodesDeps) {
    deps.log.debug("Entering BackupCodes.constructor().");
    deps.log.debug("Leaving BackupCodes.constructor().");
  }

  // What the composition root passes: the modules the load-time instance
  // was built from before R2.
  static defaultDeps(): BackupCodesDeps {
    helpers.log.debug("Entering BackupCodes.defaultDeps().");
    helpers.log.debug("Leaving BackupCodes.defaultDeps().");
    return {
      log: helpers.log,
      config: config,
      crypto: crypto as unknown as BackupCodesDeps['crypto'],
      errorCodes: errorCodes,
      randomInt: function (min: number, max: number): number {
        return nodeCrypto.randomInt(min, max);
      }
    };
  }

  // -------------------------------------------------------------------------
  // THE SETTINGS, READ IN ONE PLACE AND READ LIVE.
  //
  // Through `config.value()`, which answers out of the AMBIENT REALM — so one
  // realm may issue six long codes while another issues twelve short ones,
  // and neither had to be told about the other.
  //
  // **UNLIKE TOTP, NONE OF THESE IS COPIED ONTO THE RECORD**, and the
  // difference is real rather than an inconsistency. A TOTP parameter was TOLD
  // TO AN APP that this service cannot reach, so changing it retrospectively
  // would break an enrolment somebody already scanned. A recovery code is a
  // string compared against a stored string: shortening `backupCodes.length`
  // changes what the NEXT set looks like and leaves an existing set matching
  // exactly as it did, because nothing about the comparison depends on the
  // setting.
  // -------------------------------------------------------------------------
  settings(): BackupCodeSettings {
    const { log, config } = this.deps;
    log.debug("Entering BackupCodes.settings().");
    log.debug("Leaving BackupCodes.settings().");
    return {
      enabled: config.value('backupCodes.enabled') !== false,
      count: Math.max(1, Math.min(50,
        Number(config.value('backupCodes.count') || 10))),
      length: Math.max(8, Math.min(32,
        Number(config.value('backupCodes.length') || 10))),
      // How the code is broken up for reading. Purely presentational — every
      // door strips it back out before comparing.
      //
      // **ZERO IS DOCUMENTED AS "PRINT IT UNBROKEN" AND `|| 5` MADE IT FIVE**
      // (fixed 2026-09-12). `numberOr()` falls back only where there is no
      // number at all.
      groupSize: Math.max(0, Math.min(16,
        this.numberOr(config.value('backupCodes.groupSize'), 5)))
    };
  }

  // A setting as a number, or the fallback where it is not one — never `||`,
  // which reads a legal zero as absent.
  private numberOr(value: unknown, fallback: number): number {
    const { log } = this.deps;
    log.debug("Entering BackupCodes.numberOr().");
    const n = Number(value);
    log.debug("Leaving BackupCodes.numberOr().");
    return (value === '' || value === null || value === undefined ||
            !isFinite(n))
      ? fallback : n;
  }

  // Is the mechanism offered at all? Read at every door and not only on the
  // page that draws the list, for `totp.offered()`'s reason: a page is markup
  // and an endpoint is a door.
  //
  // **TURNING IT OFF DOES NOT INVALIDATE A SET SOMEBODY ALREADY HOLDS**, which
  // is the contract `totp.enabled` and `webauthn.enabled` both keep. A person
  // who was issued ten codes still holds ten codes, and the sign-in door still
  // accepts one — a setting that silently took away the only way back into an
  // account whose phone is lost would be the worst possible knob in this
  // service. What it stops is a new set being ISSUED.
  offered(): boolean {
    const { log } = this.deps;
    log.debug("Entering BackupCodes.offered().");
    log.debug("Leaving BackupCodes.offered().");
    return this.settings().enabled;
  }

  // -------------------------------------------------------------------------
  // ONE CODE.
  //
  // **`randomInt` PER CHARACTER AND NOT `randomBytes` WITH A MODULO.**
  // Thirty-two divides 256 exactly, so a modulo would in fact be unbiased here
  // — and that is precisely the kind of accident that stops being true the
  // moment somebody drops the vowels to stop a code spelling something and
  // leaves twenty-six characters behind. `nodeCrypto.randomInt()` is
  // rejection-sampled inside node and is correct for every alphabet size, so
  // the property does not depend on a coincidence a later reader would have
  // to re-derive.
  // -------------------------------------------------------------------------
  generateCode(length?: number | string): string {
    const { log, randomInt } = this.deps;
    log.debug("Entering BackupCodes.generateCode().");
    const want = Number(length || this.settings().length);
    let out = '';
    for (let i = 0; i < want; i++) {
      out += ALPHABET[randomInt(0, ALPHABET.length)];
    }
    log.debug("Leaving BackupCodes.generateCode().");
    return out;
  }

  // -------------------------------------------------------------------------
  // A WHOLE SET. Returns plain strings; `common/credentials.ts` is what turns
  // them into records and decides where they live.
  //
  // **DUPLICATES ARE REJECTED RATHER THAN TOLERATED.** With ten codes of fifty
  // bits each a collision is not going to happen, and the loop costs nothing —
  // but a duplicate inside one person's set would mean one code that, when
  // spent, leaves an identical string on the list still marked unused. That
  // is a code which works twice, which is the one property a single-use
  // credential may not have, and it would be found by nobody.
  // -------------------------------------------------------------------------
  generate(opts?: { count?: number | string;
                    length?: number | string }): string[] | null {
    const { log, errorCodes } = this.deps;
    log.debug('Entering BackupCodes.generate().');
    const options = opts || {};
    const live = this.settings();
    const count = Math.max(1, Number(options.count || live.count));
    const length = Math.max(8, Number(options.length || live.length));
    const codes: string[] = [];
    // A bound rather than `while (true)`. At fifty bits per code the body
    // below will not run twice; the bound is what stops a future alphabet of
    // two characters turning a generation into a hang on the one thread that
    // answers every socket this service holds.
    const ceiling = count * 20;
    let tries = 0;
    while (codes.length < count && tries < ceiling) {
      tries++;
      const candidate = this.generateCode(length);
      if (codes.indexOf(candidate) < 0) {
        codes.push(candidate);
      }
    }
    if (codes.length < count) {
      // NAMED rather than returned short. A caller that got eight codes when
      // it asked for ten would write eight to the directory and tell the
      // person they had ten.
      log.error(errorCodes.tag('STS-AUTHN-0083') +
                'backup_codes: only ' + codes.length + ' distinct code(s) ' +
                'could be generated out of ' + count + ' asked for, in ' +
                tries + ' attempt(s). The alphabet or the length must have ' +
                'been made too small to hold that many.');
      log.debug('Leaving BackupCodes.generate(). Short.');
      return null;
    }
    log.debug('Leaving BackupCodes.generate(). ' + codes.length +
              ' code(s) of ' + length + ' character(s).');
    return codes;
  }

  // -------------------------------------------------------------------------
  // WHAT A PERSON TYPED, TURNED INTO WHAT IS STORED.
  //
  // Upper-cased, and spaces and dashes dropped. Both forgivenesses are for the
  // same person: this service PRINTS the code in groups with a dash between
  // them so that it can be transcribed, and somebody transcribing it will type
  // the dash they can see. Refusing their own rendering back would be the
  // service arguing with its own page.
  //
  // **NOTHING ELSE IS FORGIVEN.** A character outside the alphabet is left in
  // place rather than stripped, so it fails the comparison — dropping unknown
  // characters would turn `ABCD3-EFGH!` into a code that matched `ABCD3EFGH`,
  // which is a comparison against a string the person did not type.
  // -------------------------------------------------------------------------
  normalise(text: unknown): string {
    const { log } = this.deps;
    log.debug("Entering BackupCodes.normalise().");
    log.debug("Leaving BackupCodes.normalise().");
    return String(text == null ? '' : text).toUpperCase()
      .replace(/[\s-]/g, '');
  }

  // The printed form: groups with a dash between them, which is the rendering
  // `normalise()` above is written to accept back.
  formatted(code: unknown, groupSize?: number | string): string {
    const { log } = this.deps;
    log.debug("Entering BackupCodes.formatted().");
    const size = groupSize === undefined ? this.settings().groupSize :
                 Number(groupSize);
    const text = String(code || '');
    if (!size || size <= 0 || size >= text.length) {
      log.debug("Leaving BackupCodes.formatted().");
      return text;
    }
    const parts: string[] = [];
    for (let i = 0; i < text.length; i += size) {
      parts.push(text.slice(i, i + size));
    }
    log.debug("Leaving BackupCodes.formatted().");
    return parts.join('-');
  }

  // -------------------------------------------------------------------------
  // DOES A PRESENTED CODE MATCH A STORED ONE?
  //
  // **CONSTANT TIME**, through the one comparison this repository has. Unlike
  // the six digits of a TOTP code, a recovery code has fifty bits in it and a
  // timing oracle is not the attack anybody would reach for — the reason it is
  // here is that `===` is right for everything else in a JavaScript file, so
  // the wrong one is what gets written by reflex. `common/credentials.ts` has
  // a whole header about that.
  // -------------------------------------------------------------------------
  matches(presented: unknown, stored: unknown): boolean {
    const { log, crypto } = this.deps;
    log.debug("Entering BackupCodes.matches().");
    log.debug("Leaving BackupCodes.matches().");
    return crypto.constantTimeEquals(this.normalise(presented),
                                     this.normalise(stored));
  }

  // =========================================================================
  // HASHING A CODE, AND CHECKING ONE AGAINST A HASH (2026-09-11).
  //
  // **THIS REVERSES THIS MODULE'S OLDEST DECISION AND THE HEADER RECORDS WHAT
  // IT COST.** A set used to be stored ENCRYPTED, on the argument that
  // `crypto.js` states — *a secret this service VERIFIES is hashed, a secret
  // it must PRESENT cannot be* — and a recovery code was both, because
  // `/portal/mfa` let a person read their remaining codes back months later.
  //
  // It does not any more: a set is SHOWN ONCE, at the moment it is generated,
  // and what is stored is a hash. So the code is a verify-only secret like
  // `userPassword` beside it, and the rule points the other way.
  //
  // **IT IS `crypto.hashSecret()` AND NOT A DIGEST OF THIS MODULE'S OWN**,
  // which is rule 3r: there is one place this service hashes a secret it will
  // later check, and `userPassword` and `stsActivationToken` already go
  // through it. scrypt at N=2^15 is expensive on purpose — and for a code with
  // fifty bits of CSPRNG entropy in it, that is belt AND braces rather than
  // the whole defence: SHA-256 over fifty bits is about 2^50 guesses, which is
  // hours of GPU time per code, and scrypt turns that into something nobody
  // finishes.
  //
  // **THE COST IS REAL AND IT IS WHY THERE IS AN ASYNC DOOR.** Measured on
  // this machine: one hash is 72ms, and a WRONG code has to be compared
  // against every code in the set — ten by default — which measured **906ms
  // of blocked event loop**. That is not a price a sign-in path can pay on
  // one thread, so `common/credentials.ts` checks a presented code through
  // the WORKER POOL and in parallel. The synchronous door is kept for `npm
  // test` and for `workers.count = 0`, which is a supported configuration.
  //
  // A hash carries its own random salt, so two identical codes in two sets —
  // or in one — hash differently, and there is no shortcut that would let a
  // presented code be looked up rather than walked.
  // =========================================================================
  hash(code: unknown): string {
    const { log, crypto } = this.deps;
    log.debug("Entering BackupCodes.hash().");
    log.debug("Leaving BackupCodes.hash().");
    return crypto.hashSecret(this.normalise(code));
  }

  hashAsync(code: unknown): Promise<string> {
    const { log, crypto } = this.deps;
    log.debug("Entering BackupCodes.hashAsync().");
    log.debug("Leaving BackupCodes.hashAsync().");
    return crypto.hashSecretAsync(this.normalise(code));
  }

  // **`matchesHash()` AND NOT `matches()`, AND BOTH ARE KEPT.** They answer
  // different questions now: `matches()` compares two CODES and is what a test
  // with both halves in its hand uses, and this compares a code against a
  // STORED HASH, which is all a running service ever has. Folding them into
  // one function that sniffed the stored form would be a function that
  // silently did a plaintext comparison against anything that did not look
  // like a hash — which is precisely what a set written by an older build
  // looks like.
  matchesHash(presented: unknown, storedHash: unknown): boolean {
    const { log, crypto } = this.deps;
    log.debug("Entering BackupCodes.matchesHash().");
    log.debug("Leaving BackupCodes.matchesHash().");
    return crypto.verifySecret(this.normalise(presented), storedHash);
  }

  matchesHashAsync(presented: unknown, storedHash: unknown): Promise<boolean> {
    const { log, crypto } = this.deps;
    log.debug("Entering BackupCodes.matchesHashAsync().");
    log.debug("Leaving BackupCodes.matchesHashAsync().");
    return crypto.verifySecretAsync(this.normalise(presented), storedHash);
  }

  // Is a stored value one of OUR hashes? A prefix test, for `isSealed()`'s
  // reason one file along: a marker beside the value would be a second fact to
  // keep in step, and a set written by a build that stored the codes
  // themselves is exactly the case this has to be able to tell apart.
  isHash(stored: unknown): boolean {
    const { log } = this.deps;
    log.debug("Entering BackupCodes.isHash().");
    log.debug("Leaving BackupCodes.isHash().");
    return /^\$scrypt\$/.test(String(stored || ''));
  }

  // Is this even the right SHAPE? Checked before the list is walked, so that a
  // password typed into the code box is refused with a sentence about the
  // shape rather than being compared — in constant time — against every code
  // the person holds.
  wellFormed(presented: unknown): boolean {
    const { log } = this.deps;
    log.debug("Entering BackupCodes.wellFormed().");
    const text = this.normalise(presented);
    if (!text) {
      log.debug("Leaving BackupCodes.wellFormed().");
      return false;
    }
    for (let i = 0; i < text.length; i++) {
      if (ALPHABET.indexOf(text[i]) < 0) {
        log.debug("Leaving BackupCodes.wellFormed().");
        return false;
      }
    }
    log.debug("Leaving BackupCodes.wellFormed().");
    return true;
  }

  // -------------------------------------------------------------------------
  // WHAT `/admin/backup-codes` AND `/admin/crypto-metadata` DRAW. Read from
  // this module rather than written down over there, which is that page's
  // whole design: the table lives with the code that performs the thing.
  // -------------------------------------------------------------------------
  report() {
    const { log } = this.deps;
    log.debug("Entering BackupCodes.report().");
    const live = this.settings();
    // The entropy per code, said in bits rather than left for a reader to work
    // out from an alphabet size and a length. It is the number that decides
    // whether the mechanism is worth anything.
    const bits = Math.floor(live.length * Math.log2(ALPHABET.length));
    log.debug("Leaving BackupCodes.report().");
    return {
      offered: live.enabled,
      count: live.count,
      length: live.length,
      groupSize: live.groupSize,
      alphabet: ALPHABET,
      alphabetSize: ALPHABET.length,
      bitsPerCode: bits,
      source: 'crypto.randomInt() per character — rejection-sampled inside ' +
              'node, so the uniformity does not depend on the alphabet size ' +
              'dividing 256.',
      comparison: 'crypto.constantTimeEquals(), after upper-casing and ' +
                  'dropping the spaces and dashes this service itself prints.',
      // **THIS SENTENCE SAID "ENCRYPTED and not hashed" FOR A DAY AFTER IT
      // STOPPED BEING TRUE** (fixed 2026-09-12). The set has been a scrypt
      // hash per code since 2026-09-11 — `hash()` above — and
      // `/admin/crypto-metadata` reads this report, so the one page whose
      // subject is what this service does to a secret was describing the
      // design that had been reversed.
      atRest: 'A scrypt HASH of each code, through crypto.hashSecret() — ' +
              'the same function and the same stored form as userPassword — ' +
              'so this service can check a code and can never show one ' +
              'again, its owner included. A set written by a build before ' +
              '2026-09-11 holds the codes themselves and is still accepted, ' +
              'code by code, until its owner generates a new one.',
      comparisonOfAHash: 'crypto.verifySecret() in constant time against ' +
                         'each stored hash in turn, on the worker pool ' +
                         'where the door is asynchronous.'
    };
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds no
// instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` when this module finishes loading (see
// `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<BackupCodes>(
  'common/backup_codes',
  () => new BackupCodes(BackupCodes.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  BackupCodes: BackupCodes,
  installInstance: (instance: BackupCodes): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  ALPHABET: BackupCodes.ALPHABET,
  settings: slot.forward('settings'),
  offered: slot.forward('offered'),
  generate: slot.forward('generate'),
  generateCode: slot.forward('generateCode'),
  normalise: slot.forward('normalise'),
  formatted: slot.forward('formatted'),
  matches: slot.forward('matches'),
  hash: slot.forward('hash'),
  hashAsync: slot.forward('hashAsync'),
  matchesHash: slot.forward('matchesHash'),
  matchesHashAsync: slot.forward('matchesHashAsync'),
  isHash: slot.forward('isHash'),
  wellFormed: slot.forward('wellFormed'),
  report: slot.forward('report')
};
