'use strict';
//
// File: app_passwords.ts
//
// ===========================================================================
// APP PASSWORDS: WHAT A PERSON WITH A SECOND FACTOR TYPES INTO A CLIENT THAT
// CAN ONLY SEND A PASSWORD (#101, 2026-09-22).
//
// Five doors here take a password and nothing else — an LDAP simple bind, a
// WS-Security UsernameToken, SCIM and SSF HTTP Basic, and EST Basic — because
// the specifications behind them define nothing else: RFC 4513 section 5.1.3,
// the UsernameToken Profile, RFC 7617 and RFC 7030 section 3.2.3. None of them
// can ask for a second factor. So in product mode a person who holds one, or
// of whom one is required, is REFUSED their own password at those doors
// (`common/credentials.ts`, `secondFactorRefusal()`): NIST SP 800-63B section
// 4.2 puts an account bound to two factors at AAL2, and a door that accepts
// one of them alone brings the whole account down to AAL1.
//
// What such a person uses there instead is an APP PASSWORD — the arrangement
// every large identity provider converged on, for exactly this reason:
//
//   * **GENERATED HERE, SHOWN ONCE, STORED AS A SCRYPT HASH** on the person's
//     own entry, which is rule 3y's shape for a recovery code. Nobody chooses
//     one, so it is never a password somebody also uses elsewhere; and nothing
//     — the person, the console, `/admin-api` — can show it again.
//   * **NAMED AND SCOPED TO ONE OR MORE OF THE FIVE DOORS.** It is accepted
//     only at a door it names, and NEVER at `/authn/login` or any other
//     browser sign-in: a browser can do the second factor, so a credential
//     that skips it has no business there.
//   * **ONE FACTOR, AND SAID SO.** A door that accepts one records `amr
//     ["pwd"]`-grade authentication and says an app password was used. It is
//     not a second factor and does not pretend to be one: what makes it safer
//     than the password is that it is random, per client, revocable one at a
//     time, and useless at every door it does not name.
//   * **REVOCABLE ONE AT A TIME**, with a CAEP `credential-change` said about
//     it; **LAST USE RECORDED**; **REFUSED ON A DISABLED ACCOUNT** (the
//     disabled check comes first at every door); and **UNTOUCHED BY A PASSWORD
//     RESET**, because it is not derived from the password.
//
// No `password || OTP` concatenation (the FreeIPA shape): it is ambiguous to
// parse, spends a TOTP step per connection — which a pooled LDAP client cannot
// do — and no specification describes it. rcbj's decision on #101.
//
// ---------------------------------------------------------------------------
// THE SHAPE: TWENTY-FOUR CHARACTERS, AND THE FIRST FOUR ARE A PUBLIC ID.
//
// Out of `common/backup_codes.ts`'s thirty-two characters and for its reason
// (no confusable pair), in six groups of four when printed. The first four
// are the password's ID, stored in the clear beside its hash, and they are
// what makes a presented password cost ONE scrypt comparison however many a
// person holds: the door looks the record up by its id and checks that one
// hash, where a list walked in constant time would cost a scrypt per record
// on every wrong password — 70ms each, on a pooled LDAP client's every bind.
// The other twenty characters are a hundred bits of secret, which is what the
// strength rests on; the id says which record to check and nothing more.
//
// A LIBRARY (rule 3; `common/CLAUDE.md` rule 3ax). It registers no route. It
// requires `helpers`, `config` and `crypto`, none of which requires it back,
// and it is required by `common/credentials.ts` (which keeps the records on
// the entry), `portal/portal_app_passwords.ts` and `admin-core/admin_views.ts`.
//
// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50) — `common/backup_codes.ts`'s shape: the
// dependencies arrive through the constructor, the composition root builds
// the instance, and the module's export names are FACADES forwarding to it.
// ===========================================================================

import nodeCrypto = require('crypto');
import helpers = require('./helpers');
import config = require('./config');
import crypto = require('./crypto');
import InstanceSlot = require('./instance_slot');

// The thirty-two characters, declared here rather than imported from
// `backup_codes.ts` for the reason that file declares its own apart from
// `totp.ts`: the same set by coincidence of good properties, and a change to
// one must not silently move the other.
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

// The public id, and the whole password, in characters.
const ID_LENGTH = 4;
const LENGTH = 24;
const GROUP = 4;

// THE FIVE DOORS, and the only five. Each is a place a person's password is
// taken with no way to ask for more; the ids are what a door passes to
// `credentials.verify()` as `door`, what `authn.passwordAloneDoors` lists and
// what a record's scope names.
const DOORS = [
  { id: 'ldap', label: 'LDAP bind',
    what: 'an LDAP simple bind on 389 or 636 (RFC 4513)' },
  { id: 'wstrust', label: 'WS-Trust',
    what: 'a WS-Security UsernameToken sent to the security token service' },
  { id: 'scim', label: 'SCIM',
    what: 'HTTP Basic at /scim/v2 (RFC 7617)' },
  { id: 'ssf', label: 'Shared Signals',
    what: 'HTTP Basic at the /ssf endpoints (RFC 7617)' },
  { id: 'est', label: 'EST',
    what: 'HTTP Basic at /.well-known/est (RFC 7030 section 3.2.3)' }
];

const DOOR_IDS = DOORS.map(function (one) { return one.id; });

const MAX_NAME = 64;

interface AppPasswordSettings {
  enabled: boolean;
  maxPerPerson: number;
}

interface AppPasswordsDeps {
  log: {
    debug(message: string): void;
  };
  config: { value(key: string): any };
  crypto: {
    hashSecret(plaintext: string): string;
    verifySecret(plaintext: string, stored: unknown): boolean;
    verifySecretAsync(plaintext: string, stored: unknown): Promise<boolean>;
  };
  randomInt(min: number, max: number): number;
}

class AppPasswords {
  static readonly ALPHABET = ALPHABET;
  static readonly DOORS = DOORS;
  static readonly DOOR_IDS = DOOR_IDS;
  static readonly LENGTH = LENGTH;
  static readonly ID_LENGTH = ID_LENGTH;
  static readonly MAX_NAME = MAX_NAME;

  constructor(private readonly deps: AppPasswordsDeps) {
    deps.log.debug("Entering AppPasswords.constructor().");
    deps.log.debug("Leaving AppPasswords.constructor().");
  }

  static defaultDeps(): AppPasswordsDeps {
    helpers.log.debug("Entering AppPasswords.defaultDeps().");
    helpers.log.debug("Leaving AppPasswords.defaultDeps().");
    return {
      log: helpers.log,
      config: config,
      crypto: crypto as unknown as AppPasswordsDeps['crypto'],
      randomInt: function (min: number, max: number): number {
        return nodeCrypto.randomInt(min, max);
      }
    };
  }

  // The settings, read live and per realm through `config.value()`. The
  // maximum is read directly and bounded, never through `|| n`, for the code
  // style's reason.
  settings(): AppPasswordSettings {
    const { log, config } = this.deps;
    log.debug("Entering AppPasswords.settings().");
    const asked = Number(config.value('appPasswords.maxPerPerson'));
    log.debug("Leaving AppPasswords.settings().");
    return {
      enabled: config.value('appPasswords.enabled') !== false,
      maxPerPerson: isFinite(asked) && asked >= 1
        ? Math.min(50, Math.floor(asked)) : 10
    };
  }

  // Is a door one of the five? Asked by `credentials.ts` before it looks at
  // an app password at all, so a caller that passes no door — the sign-in
  // screen — never has one accepted.
  isDoor(door: unknown): boolean {
    const { log } = this.deps;
    log.debug("Entering AppPasswords.isDoor().");
    log.debug("Leaving AppPasswords.isDoor().");
    return DOOR_IDS.indexOf(String(door || '')) >= 0;
  }

  // The doors `authn.passwordAloneDoors` lists, as ids. An unknown name is
  // dropped rather than honoured: a typo there must not widen anything.
  passwordAloneDoors(): string[] {
    const { log, config } = this.deps;
    log.debug("Entering AppPasswords.passwordAloneDoors().");
    const asked = config.value('authn.passwordAloneDoors');
    const list = Array.isArray(asked) ? asked : String(asked || '').split(',');
    const out = list.map(function (one) {
      return String(one).trim().toLowerCase();
    }).filter(function (one) {
      return DOOR_IDS.indexOf(one) >= 0;
    });
    log.debug("Leaving AppPasswords.passwordAloneDoors(). " + out.join(','));
    return out;
  }

  // -------------------------------------------------------------------------
  // WHAT A CALLER SENT AS A SCOPE, TURNED INTO ONE. A list or a
  // comma-separated string (a form's repeated checkbox arrives as either);
  // every entry must be one of the five and at least one must be there, and
  // anything else is refused whole rather than trimmed, because a scope that
  // silently lost a door would be a password that did not work where its
  // owner was told it would.
  // -------------------------------------------------------------------------
  scopeOf(asked: unknown): { ok: boolean; doors: string[]; bad: string[] } {
    const { log } = this.deps;
    log.debug("Entering AppPasswords.scopeOf().");
    const raw = Array.isArray(asked) ? asked
      : String(asked == null ? '' : asked).split(',');
    const doors: string[] = [];
    const bad: string[] = [];
    raw.forEach(function (one) {
      const id = String(one == null ? '' : one).trim().toLowerCase();
      if (!id) {
        return;
      }
      if (DOOR_IDS.indexOf(id) < 0) {
        bad.push(id);
      } else if (doors.indexOf(id) < 0) {
        doors.push(id);
      }
    });
    // In the table's order, so two scopes naming the same doors print alike.
    doors.sort(function (a, b) {
      return DOOR_IDS.indexOf(a) - DOOR_IDS.indexOf(b);
    });
    log.debug("Leaving AppPasswords.scopeOf(). doors=" + doors.join(',') +
              " bad=" + bad.join(','));
    return { ok: doors.length > 0 && bad.length === 0, doors: doors,
             bad: bad };
  }

  // A name a person gives one, so a list of several says which client each
  // is in. Printable text, trimmed, at most sixty-four characters; '' where
  // it is none of those.
  nameOf(asked: unknown): string {
    const { log } = this.deps;
    log.debug("Entering AppPasswords.nameOf().");
    const text = String(asked == null ? '' : asked).trim();
    // No control characters: a name is drawn on three pages and written to
    // the audit log, and a newline in either is somebody else's line.
    const ok = text.length > 0 && text.length <= MAX_NAME &&
               !/[\u0000-\u001f\u007f]/.test(text);
    log.debug("Leaving AppPasswords.nameOf(). ok=" + ok);
    return ok ? text : '';
  }

  // -------------------------------------------------------------------------
  // ONE NEW PASSWORD. `randomInt` per character, rejection-sampled inside
  // node, for `backup_codes.ts`'s reason. `taken` is the ids the person
  // already holds: the id must be unique on the entry, since it is how the
  // record is found, and a clash is drawn again rather than tolerated.
  // -------------------------------------------------------------------------
  generate(taken?: string[]): { id: string; password: string;
                                printed: string } {
    const { log, randomInt } = this.deps;
    log.debug("Entering AppPasswords.generate().");
    const held = taken || [];
    let password = '';
    // A bound rather than `while (true)`: with a million ids and at most
    // fifty held, a second draw is already unlikely.
    for (let tries = 0; tries < 50; tries++) {
      password = '';
      for (let i = 0; i < LENGTH; i++) {
        password += ALPHABET[randomInt(0, ALPHABET.length)];
      }
      if (held.indexOf(password.slice(0, ID_LENGTH)) < 0) {
        break;
      }
    }
    log.debug("Leaving AppPasswords.generate().");
    return { id: password.slice(0, ID_LENGTH), password: password,
             printed: this.printed(password) };
  }

  // The printed form: six groups of four with a dash between them, which is
  // what `normalise()` is written to accept back.
  printed(password: unknown): string {
    const { log } = this.deps;
    log.debug("Entering AppPasswords.printed().");
    const text = String(password || '');
    const parts: string[] = [];
    for (let i = 0; i < text.length; i += GROUP) {
      parts.push(text.slice(i, i + GROUP));
    }
    log.debug("Leaving AppPasswords.printed().");
    return parts.join('-');
  }

  // What a client sent, as it is hashed and compared: upper-cased, and the
  // spaces and dashes this service prints dropped. Nothing else is forgiven,
  // for `backup_codes.ts`'s reason.
  normalise(text: unknown): string {
    const { log } = this.deps;
    log.debug("Entering AppPasswords.normalise().");
    log.debug("Leaving AppPasswords.normalise().");
    return String(text == null ? '' : text).toUpperCase()
      .replace(/[\s-]/g, '');
  }

  // Is a presented password even the SHAPE of an app password? Asked before
  // any record is looked at, so an ordinary password costs nothing extra.
  wellFormed(text: unknown): boolean {
    const { log } = this.deps;
    log.debug("Entering AppPasswords.wellFormed().");
    const value = this.normalise(text);
    if (value.length !== LENGTH) {
      log.debug("Leaving AppPasswords.wellFormed(). Wrong length.");
      return false;
    }
    for (let i = 0; i < value.length; i++) {
      if (ALPHABET.indexOf(value[i]) < 0) {
        log.debug("Leaving AppPasswords.wellFormed(). Not the alphabet.");
        return false;
      }
    }
    log.debug("Leaving AppPasswords.wellFormed().");
    return true;
  }

  // The public id of a presented password; '' where it is not the shape.
  idOf(text: unknown): string {
    const { log } = this.deps;
    log.debug("Entering AppPasswords.idOf().");
    log.debug("Leaving AppPasswords.idOf().");
    return this.wellFormed(text)
      ? this.normalise(text).slice(0, ID_LENGTH) : '';
  }

  // rule 3r: `crypto.hashSecret()`, the one place a verify-only secret is
  // hashed — scrypt, and the stored form `userPassword` has.
  hash(password: unknown): string {
    const { log, crypto } = this.deps;
    log.debug("Entering AppPasswords.hash().");
    log.debug("Leaving AppPasswords.hash().");
    return crypto.hashSecret(this.normalise(password));
  }

  matchesHash(presented: unknown, stored: unknown): boolean {
    const { log, crypto } = this.deps;
    log.debug("Entering AppPasswords.matchesHash().");
    log.debug("Leaving AppPasswords.matchesHash().");
    return crypto.verifySecret(this.normalise(presented), stored);
  }

  matchesHashAsync(presented: unknown, stored: unknown): Promise<boolean> {
    const { log, crypto } = this.deps;
    log.debug("Entering AppPasswords.matchesHashAsync().");
    log.debug("Leaving AppPasswords.matchesHashAsync().");
    return crypto.verifySecretAsync(this.normalise(presented), stored);
  }

  // The label a door is drawn with.
  doorLabel(id: unknown): string {
    const { log } = this.deps;
    log.debug("Entering AppPasswords.doorLabel().");
    const row = DOORS.filter(function (one) { return one.id === id; })[0];
    log.debug("Leaving AppPasswords.doorLabel().");
    return row ? row.label : String(id || '');
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2), `backup_codes.ts`'s
// arrangement: facades for the callers that still `require()` this module,
// and a default instance for a process that never runs the root.
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<AppPasswords>(
  'common/app_passwords',
  () => new AppPasswords(AppPasswords.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  AppPasswords: AppPasswords,
  installInstance: (instance: AppPasswords): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  ALPHABET: AppPasswords.ALPHABET,
  DOORS: AppPasswords.DOORS,
  DOOR_IDS: AppPasswords.DOOR_IDS,
  LENGTH: AppPasswords.LENGTH,
  ID_LENGTH: AppPasswords.ID_LENGTH,
  MAX_NAME: AppPasswords.MAX_NAME,
  settings: slot.forward('settings'),
  isDoor: slot.forward('isDoor'),
  passwordAloneDoors: slot.forward('passwordAloneDoors'),
  scopeOf: slot.forward('scopeOf'),
  nameOf: slot.forward('nameOf'),
  generate: slot.forward('generate'),
  printed: slot.forward('printed'),
  normalise: slot.forward('normalise'),
  wellFormed: slot.forward('wellFormed'),
  idOf: slot.forward('idOf'),
  hash: slot.forward('hash'),
  matchesHash: slot.forward('matchesHash'),
  matchesHashAsync: slot.forward('matchesHashAsync'),
  doorLabel: slot.forward('doorLabel')
};
