'use strict';
//
// File: common/breached_passwords.ts
//
// ===========================================================================
// A PASSWORD THAT HAS APPEARED IN A DATA BREACH IS REFUSED (#62 P6,
// 2026-09-22) — NIST SP 800-63B section 3.1.1.2: a verifier SHALL compare a
// prospective memorized secret against a list of values known to be
// compromised, and refuse one that is on it.
//
// **THE LIST IS HAVE I BEEN PWNED'S "PWNED PASSWORDS", ASKED BY K-ANONYMITY,
// NEVER HELD** (rcbj's decision of 2026-09-22 — the range API rather than a
// filter built from the downloadable corpus, whose terms were the open
// question on #62). The password's SHA-1 (`crypto.pwnedPasswordDigest()`) is
// split after five hex characters; only those five go to the range endpoint
// (`risk.breachApiUrl`), which answers every suffix it knows under that
// prefix with a count; the match is made here. Neither the password nor its
// full digest leaves this process, and a prefix names roughly half a million
// passwords.
//
// **THE ONE OUTBOUND REQUEST HERE WHOSE ADDRESS NOBODY SUPPLIED PER
// REQUEST**: the operator's `risk.breachApiUrl`, with a five-character
// path segment computed here. It goes through `federation_http.ts`'s
// `fetchPublished()`, so `federation.outbound` switches it off with every
// other outbound request and product mode verifies its TLS (#171). The root
// CLAUDE.md's list of addresses the service dials names it.
//
// **HOW IT IS USED, WITHOUT MAKING EVERY PASSWORD DOOR ASYNCHRONOUS.**
// `screen(password)` asks (a range answer is cached per prefix for
// `risk.breachCacheMinutes`) and remembers the VERDICT for that
// password for a few minutes; `credentials.preparePassword()` — synchronous,
// and where every door that sets a password ends — reads the verdict with
// `verdictOf()` and refuses a breached password (STS-AUTHN-0222). Each door
// awaits `screen()` before it calls the synchronous code. A door that did not
// screen gets no verdict, and the password is set: an unreachable API is not
// a reason nobody can change their password, and the unscreened door is
// logged (STS-AUTHN-0223) so it is found.
//
// **PRODUCT MODE ONLY**, as the password policy is (`mode.verifiesCredentials()`):
// development checks no password anywhere.
// ===========================================================================

import bunyan = require('bunyan');
import config = require('./config');
import stsCrypto = require('./crypto');
import errorCodes = require('./error_codes');
import cacheRegistry = require('./cache_registry');
import InstanceSlot = require('./instance_slot');

const log = bunyan.createLogger({ name: 'sts-breached-passwords' });
config.registerLogger(log);

type Json = any;

// How long a password's verdict stands for `preparePassword()` to read: the
// time between a door screening it and the same request setting it.
const VERDICT_MS = 5 * 60 * 1000;
// The most verdicts one process holds; the oldest go first.
const MAX_VERDICTS = 1000;

// prefix -> { at, counts: Map<suffix, count> }
const ranges = new Map<string, Json>();
// full digest -> { at, breached, count }
const verdicts = new Map<string, Json>();

const rangesCount = cacheRegistry.register({
  name: 'passwords.breach-ranges',
  title: 'Breached-password ranges',
  description: 'Pwned Passwords range answers, by the five-character SHA-1 ' +
    'prefix asked for (#62 P6): which password digests under it are known ' +
    'to be breached, and how often.',
  owner: 'common/breached_passwords.ts',
  scope: 'process', kind: 'cache', persisted: false,
  hitMeaning: 'a prefix already asked, so no request was made',
  settings: ['risk.breachCacheMinutes', 'risk.breachCacheSize'],
  maxEntries: function (): number {
    return Number(config.value('risk.breachCacheSize'));
  },
  bound: 'Enforced: risk.breachCacheSize prefixes; full, the oldest ' +
    'is dropped and asked again when next needed.',
  lifetime: function (): string {
    return 'risk.breachCacheMinutes after it was fetched.';
  },
  eject: cacheRegistry.mapEjector(ranges,
    function (row: Json, key: unknown, now: number): boolean {
      return !row || now - Number(row.at) >
        Number(config.value('risk.breachCacheMinutes')) * 60000;
    }),
  entries: function (): unknown[] {
    const ttl = Number(config.value('risk.breachCacheMinutes')) * 60000;
    const out: Json[] = [];
    ranges.forEach(function (row: Json, key: string): void {
      out.push({ key: key, validUntil: Number(row.at) + ttl,
                 basis: row.counts.size + ' suffix(es)' });
    });
    return out;
  }
});

const verdictsCount = cacheRegistry.register({
  name: 'passwords.breach-verdicts',
  title: 'Breached-password verdicts',
  description: 'Whether a password a door just screened is breached, for the ' +
    'synchronous password rules to read in the same request (#62 P6). Keyed ' +
    'by a digest of the password, never the password.',
  owner: 'common/breached_passwords.ts',
  scope: 'process', kind: 'cache', persisted: false,
  hitMeaning: 'a verdict found for a password being set',
  settings: [],
  maxEntries: function (): number {
    return MAX_VERDICTS;
  },
  bound: 'Enforced: ' + MAX_VERDICTS + ' verdicts; full, the oldest is ' +
    'dropped.',
  lifetime: function (): string {
    return 'five minutes after the password was screened.';
  },
  eject: cacheRegistry.mapEjector(verdicts,
    function (row: Json, key: unknown, now: number): boolean {
      return !row || now - Number(row.at) > VERDICT_MS;
    }),
  entries: function (): unknown[] {
    const out: Json[] = [];
    verdicts.forEach(function (row: Json, key: string): void {
      out.push({ key: cacheRegistry.digestKey(key),
                 validUntil: Number(row.at) + VERDICT_MS,
                 basis: row.breached ? 'breached' : 'not found' });
    });
    return out;
  }
});

interface BreachedPasswordsDeps {
  log: { debug(m: string): void; info(m: string): void; warn(m: string): void };
  config: { value(key: string): any };
  now(): number;
  mode(): Json;
  // The outbound request: `federation_http.ts`'s `fetchPublished()`.
  fetch(url: string, opts: Json): Promise<Json>;
}

class BreachedPasswords {
  constructor(private readonly deps: BreachedPasswordsDeps) {
    deps.log.debug("Entering BreachedPasswords.constructor().");
    deps.log.debug("Leaving BreachedPasswords.constructor().");
  }

  static defaultDeps(): BreachedPasswordsDeps {
    log.debug("Entering BreachedPasswords.defaultDeps().");
    log.debug("Leaving BreachedPasswords.defaultDeps().");
    return {
      log: log, config: config,
      now: function (): number {
        return Date.now();
      },
      mode: function (): Json {
        return require('./mode');
      },
      fetch: function (url: string, opts: Json): Promise<Json> {
        return require('../federation/federation_http').fetchPublished(url,
                                                                       opts);
      }
    };
  }

  // Whether a password is screened at all: the setting, in product mode.
  enabled(): boolean {
    const { log, config, mode } = this.deps;
    log.debug("Entering BreachedPasswords.enabled().");
    let enforced = false;
    try {
      enforced = !!mode().verifiesCredentials();
    } catch (e) {
      log.debug("Caught in BreachedPasswords.enabled(): " +
                ((e && e.message) || e));
      // No mode module: development's answer, which screens nothing.
      enforced = false;
    }
    log.debug("Leaving BreachedPasswords.enabled().");
    return enforced && config.value('risk.breachCheck') === 'on';
  }

  // -------------------------------------------------------------------------
  // SCREEN ONE PASSWORD. Answers `{ checked, breached, count, why }` and
  // remembers the verdict for `verdictOf()`. Never rejects: an API that
  // cannot answer is `checked: false`, logged, and decides nothing.
  // -------------------------------------------------------------------------
  async screen(password: string): Promise<Json> {
    const { log, config, now, fetch } = this.deps;
    log.debug("Entering BreachedPasswords.screen().");
    if (!password || !this.enabled()) {
      log.debug("Leaving BreachedPasswords.screen(). Not screened.");
      return { checked: false, breached: false, count: 0,
               why: 'breached-password screening is off' };
    }
    const digest = stsCrypto.pwnedPasswordDigest(password);
    const prefix = digest.slice(0, 5);
    const suffix = digest.slice(5);
    const ttl = Number(config.value('risk.breachCacheMinutes')) * 60000;
    let range = ranges.get(prefix);
    if (range && now() - Number(range.at) <= ttl) {
      rangesCount.hit();
    } else {
      rangesCount.miss();
      const base = String(config.value('risk.breachApiUrl') || '');
      let answer: Json = null;
      try {
        answer = await fetch(base + prefix, { accept: 'text/plain',
          timeoutMs: Number(config.value('risk.breachTimeoutMs')) });
      } catch (e) {
        log.debug("Caught in BreachedPasswords.screen(): " +
                  ((e && e.message) || e));
        answer = { ok: false, why: String((e && e.message) || e) };
      }
      if (!answer || !answer.ok) {
        log.warn(errorCodes.tag('STS-AUTHN-0224') + 'breached passwords: ' +
                 'the range API at ' + base + ' did not answer (' +
                 String((answer && answer.why) || 'no answer') + '); the ' +
                 'password is set unscreened.');
        log.debug("Leaving BreachedPasswords.screen(). No answer.");
        return { checked: false, breached: false, count: 0,
                 why: 'the breached-password service did not answer' };
      }
      const counts = new Map<string, number>();
      String(answer.body || '').split(/\r?\n/).forEach(function (line) {
        const at = line.indexOf(':');
        if (at > 0) {
          counts.set(line.slice(0, at).trim().toUpperCase(),
                     Number(line.slice(at + 1)) || 0);
        }
      });
      range = { at: now(), counts: counts };
      ranges.delete(prefix);
      cacheRegistry.makeRoom(ranges,
        Number(config.value('risk.breachCacheSize')),
        { name: 'passwords.breach-ranges', counter: rangesCount });
      ranges.set(prefix, range);
    }
    // A padded answer (the API's Add-Padding) lists decoys with a count of
    // zero; a zero is not a breach.
    const count = Number(range.counts.get(suffix) || 0);
    const verdict = { at: now(), breached: count > 0, count: count };
    verdicts.delete(digest);
    cacheRegistry.makeRoom(verdicts, MAX_VERDICTS,
      { name: 'passwords.breach-verdicts', counter: verdictsCount });
    verdicts.set(digest, verdict);
    log.debug("Leaving BreachedPasswords.screen(). " +
              (verdict.breached ? 'Breached.' : 'Not found.'));
    return { checked: true, breached: verdict.breached, count: count,
             why: '' };
  }

  // Every password a request carries, screened in turn — for a door whose
  // synchronous action takes a body (the console and the management API).
  // Anything that is not a non-empty string is not a password. Never rejects.
  async screenAll(values: unknown[]): Promise<void> {
    const { log } = this.deps;
    log.debug("Entering BreachedPasswords.screenAll().");
    for (const one of values || []) {
      if (typeof one === 'string' && one) {
        await this.screen(one);
      }
    }
    log.debug("Leaving BreachedPasswords.screenAll().");
  }

  // The verdict a door's `screen()` left for this password, or null — read
  // synchronously by `credentials.preparePassword()`. A hot path's helper:
  // one map read, and no Entering/Leaving pair would add anything.
  verdictOf(password: string): Json | null {
    const { now } = this.deps;
    const row = verdicts.get(stsCrypto.pwnedPasswordDigest(password));
    if (!row || now() - Number(row.at) > VERDICT_MS) {
      verdictsCount.miss();
      return null;
    }
    verdictsCount.hit();
    return row;
  }
}

const slot = new InstanceSlot<BreachedPasswords>(
  'common/breached_passwords',
  () => new BreachedPasswords(BreachedPasswords.defaultDeps()),
  null,
  log);

slot.buildNowUnlessDeferred();

export = {
  BreachedPasswords: BreachedPasswords,
  installInstance: (instance: BreachedPasswords): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  enabled: slot.forward('enabled'),
  screen: slot.forward('screen'),
  screenAll: slot.forward('screenAll'),
  verdictOf: slot.forward('verdictOf'),
  // For the tests: forget every range and verdict.
  forget: function (): void {
    log.debug("Entering forget().");
    ranges.clear();
    verdicts.clear();
    log.debug("Leaving forget().");
  }
};
