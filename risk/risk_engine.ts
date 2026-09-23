'use strict';
//
// File: risk/risk_engine.ts
//
// ===========================================================================
// ASSESSING ONE SIGN-IN (#62 P2, 2026-09-23). OBSERVE ONLY.
//
// `authn/authn.ts` hands every authentication event that starts or
// re-authenticates a session here, AFTER the session exists and without
// waiting: in P2 nothing is decided by a score. What happens to one sign-in,
// in order:
//
//   1. ENRICHED: what the active datasets say about the address
//      (`risk_datasets.lookup()` — country, ASN, the lists it is on, and the
//      attributions those providers' terms ask for).
//   2. THE DEVICE, from the `User-Agent` read in memory and dropped: browser
//      and major version, operating system, device type (`bowser`, MIT), and
//      whether it is an automated client (`isbot`, Unlicense). The header
//      itself is never kept; the event's `uaFingerprint` is what stands for
//      it.
//   3. SCORED by the Freeman et al. port (`risk_model.ts`) against this
//      person's history and the realm's, both read from
//      `sts_risk_feature_counts` BEFORE this sign-in is counted — the
//      notebook's order. A first sign-in is not scored.
//   4. THE EVALUATORS: the signals the model does not see, each a factor on
//      the score (SIGNALS below) — an address on a Tor, reputation or
//      operator list, an automated client, a TLS stack this person has never
//      used, recent refused passwords for this person or from this network.
//   5. A LEVEL: LOW, MEDIUM or HIGH — CAEP's own words — by
//      `risk.mediumScorePercent` and `risk.highScorePercent`; UNSCORED for a
//      first sign-in with nothing else to say.
//   6. RECORDED: an `sts_risk_assessments` row with every value that went in,
//      the dataset versions that answered, the signals and the score; the
//      counts moved on; the person's standing and the session's context
//      replaced.
//
// **THE ADDRESS IS NEVER A FEATURE VALUE AS IT STANDS**: it enters the
// history as a keyed digest (`keystore.keyedDigest()`), the network as its
// ASN, and the assessment holds it sealed and as a prefix — the plan's §7
// rule, and `risk_store.ts`'s: history goes to the database only where it can
// be sealed.
//
// **A FAILURE HERE IS NEVER A FAILED SIGN-IN.** `assess()` is not awaited by
// the door, never rejects, and logs STS-RISK-0013 when it could not finish.
// ===========================================================================

import bunyan = require('bunyan');
import bowser = require('bowser');
import isbotModule = require('isbot');
import config = require('../common/config');
import stsCrypto = require('../common/crypto');
import errorCodes = require('../common/error_codes');
import InstanceSlot = require('../common/instance_slot');
import riskStore = require('./risk_store');
import riskDatasets = require('./risk_datasets');
import riskModel = require('./risk_model');

const log = bunyan.createLogger({ name: 'sts-risk-engine' });
config.registerLogger(log);

type Json = any;

// ---------------------------------------------------------------------------
// THE EVALUATORS' FACTORS. Each multiplies the score when its signal is
// present; a factor below 1 is evidence FOR the sign-in (an operator's allow
// list). They are this service's first calibration, deliberately round and
// deliberately visible: P2 observes, and the Monitoring page shows every
// assessment's signals, so what they should be is something to read off the
// record before P3 lets anything be decided by them.
// ---------------------------------------------------------------------------
const SIGNALS: Record<string, Json> = {
  'tor-exit': { factor: 5, what: 'the address is a Tor exit' },
  'reputation': { factor: 5,
    what: 'the address is on the IP reputation list' },
  'operator-deny': { factor: 50,
    what: 'the address is on this realm\'s operator deny list' },
  'operator-allow': { factor: 0.2,
    what: 'the address is on this realm\'s operator allow list' },
  'automated-client': { factor: 10,
    what: 'the User-Agent is an automated client\'s' },
  'new-tls-stack': { factor: 2,
    what: 'a TLS client (JA4) this person has not signed in with before' },
  'account-failures': { factor: 3,
    what: 'refused passwords for this person in the last hour' },
  'network-failures': { factor: 3,
    what: 'refused passwords from this network in the last hour' }
};

// How many refused passwords in the last hour make a signal of each kind.
const ACCOUNT_FAILURES = 5;
const NETWORK_FAILURES = 20;
const HOUR_MS = 3600 * 1000;

// The population's subject in `sts_risk_feature_counts`.
const POPULATION = '*';

interface RiskEngineDeps {
  log: { debug(m: string): void; info(m: string): void; warn(m: string): void };
  config: { value(key: string): any };
  store: typeof riskStore;
  datasets: typeof riskDatasets;
  now(): number;
  keystore(): Json;
  randomId(): string;
}

class RiskEngine {
  static readonly SIGNALS = SIGNALS;

  constructor(private readonly deps: RiskEngineDeps) {
    deps.log.debug("Entering RiskEngine.constructor().");
    deps.log.debug("Leaving RiskEngine.constructor().");
  }

  static defaultDeps(): RiskEngineDeps {
    log.debug("Entering RiskEngine.defaultDeps().");
    log.debug("Leaving RiskEngine.defaultDeps().");
    return {
      log: log,
      config: config,
      store: riskStore,
      datasets: riskDatasets,
      now: function (): number {
        return Date.now();
      },
      keystore: function (): Json {
        return require('../common/keystore');
      },
      randomId: function (): string {
        return require('crypto').randomUUID();
      }
    };
  }

  // ---------------------------------------------------------------------------
  // THE DEVICE, from a User-Agent, which is read here and not kept. `bowser`
  // throws on an empty string, which a request with no header is, so an
  // empty one is answered without it.
  // ---------------------------------------------------------------------------
  static deviceOf(userAgent: string): Json {
    log.debug("Entering RiskEngine.deviceOf().");
    const ua = String(userAgent || '');
    if (!ua) {
      log.debug("Leaving RiskEngine.deviceOf(). No User-Agent.");
      return { browser: '', os: '', device: '', bot: false, present: false };
    }
    let parsed: Json = {};
    try {
      parsed = bowser.parse(ua) || {};
    } catch (e) {
      log.debug("Caught in RiskEngine.deviceOf(): " +
                ((e && e.message) || e));
      // A header bowser cannot read is a device nobody can name: the three
      // levels are empty and the fingerprint still stands for it.
      parsed = {};
    }
    const b = parsed.browser || {};
    const o = parsed.os || {};
    const p = parsed.platform || {};
    const major = String(b.version || '').split('.')[0];
    log.debug("Leaving RiskEngine.deviceOf().");
    return {
      browser: b.name ? String(b.name) + (major ? ' ' + major : '') : '',
      os: o.name ? String(o.name) + (o.versionName || o.version
        ? ' ' + String(o.versionName || o.version) : '') : '',
      device: String(p.type || ''),
      bot: !!isbotModule.isbot(ua),
      present: true
    };
  }

  // Whether history may go to the database: a key to seal and digest under.
  private sealing(): boolean {
    const { log, keystore } = this.deps;
    log.debug("Entering RiskEngine.sealing().");
    let sealed = false;
    try {
      sealed = !!keystore().sealed();
    } catch (e) {
      log.debug("Caught in RiskEngine.sealing(): " + ((e && e.message) || e));
      // No keystore yet: nothing personal leaves this process.
      sealed = false;
    }
    log.debug("Leaving RiskEngine.sealing(). " + sealed);
    return sealed;
  }

  // The address as a history value: a keyed digest where there is a key,
  // and a plain one otherwise — which then never leaves this process.
  private addressKey(address: string, sealing: boolean): string {
    const { log, keystore } = this.deps;
    log.debug("Entering RiskEngine.addressKey().");
    const text = String(address || '');
    const keyed = sealing && text
      ? keystore().keyedDigest('risk-feature-address', text) : '';
    log.debug("Leaving RiskEngine.addressKey().");
    return text ? (keyed || stsCrypto.credentialFingerprint(
      'risk-feature-address:' + text)) : '';
  }

  // ---------------------------------------------------------------------------
  // A HISTORY FROM THE STORE, for one subject: every count the model will
  // ask for, fetched first, then answered synchronously. `population` adds
  // the distinct counts the smoothed side needs and the number of users.
  // ---------------------------------------------------------------------------
  private async historyOf(realm: string, subject: string, attempt: Json,
                          population: boolean,
                          sealing: boolean): Promise<Json> {
    const { log, store } = this.deps;
    log.debug("Entering RiskEngine.historyOf(). " + subject);
    const pairs = [{ feature: '_total', value: '' }];
    riskModel.FEATURES.forEach(function (f: Json): void {
      f.levels.forEach(function (level: Json): void {
        pairs.push({ feature: level[0], value: String(attempt[level[0]]) });
      });
    });
    const rows = await store.featureCounts(realm, subject, pairs, sealing);
    const counts = new Map<string, number>();
    rows.forEach(function (r: Json): void {
      counts.set(r.feature + '\u0000' + r.value, r.count);
    });
    const distinct = new Map<string, number>();
    let users = 0;
    if (population) {
      for (const f of riskModel.FEATURES) {
        const first = f.levels[0][0];
        for (const level of f.levels.slice(1)) {
          distinct.set(level[0], await store.distinctValues(
            realm, subject, level[0], '', sealing));
          distinct.set(first + '>' + level[0], await store.distinctValues(
            realm, subject, first + '>' + level[0],
            String(attempt[first]) + '|', sealing));
        }
      }
      users = await store.distinctValues(realm, subject, 'user', '',
                                         sealing);
    }
    log.debug("Leaving RiskEngine.historyOf().");
    return {
      n: counts.get('_total\u0000') || 0,
      users: users,
      count: function (level: string, value: string): number {
        return counts.get(level + '\u0000' + value) || 0;
      },
      distinct: function (level: string): number {
        return distinct.get(level) || 0;
      },
      distinctWithin: function (first: string, value: string,
                                level: string): number {
        return distinct.get(first + '>' + level) || 0;
      }
    };
  }

  // The level a score is at, by the two settings (percent of the score).
  private levelOf(score: number): string {
    const { log, config } = this.deps;
    log.debug("Entering RiskEngine.levelOf().");
    const high = Number(config.value('risk.highScorePercent')) / 100;
    const medium = Number(config.value('risk.mediumScorePercent')) / 100;
    log.debug("Leaving RiskEngine.levelOf().");
    return score >= high ? 'HIGH' : (score >= medium ? 'MEDIUM' : 'LOW');
  }

  // -------------------------------------------------------------------------
  // assess(input) — see the header. `input`: { realm, subject, sessionId,
  // door, clientId, context (the authentication event's), userAgent (the raw
  // header, read here and dropped) }. Answers the assessment, or null when
  // it could not be made; never rejects.
  // -------------------------------------------------------------------------
  async assess(input: Json): Promise<Json | null> {
    const { log, config } = this.deps;
    log.debug("Entering RiskEngine.assess().");
    if (config.value('risk.assessSignIns') === false || !input ||
        !input.subject) {
      log.debug("Leaving RiskEngine.assess(). Not assessed.");
      return null;
    }
    try {
      const answer = await this.assessNow(input);
      log.debug("Leaving RiskEngine.assess().");
      return answer;
    } catch (e) {
      log.warn(errorCodes.tag('STS-RISK-0013') + 'risk: a sign-in for ' +
               input.subject + ' at ' + input.door + ' could not be ' +
               'assessed: ' + ((e && e.message) || e) + '. The sign-in ' +
               'stands.');
      log.debug("Leaving RiskEngine.assess(). Failed.");
      return null;
    }
  }

  private async assessNow(input: Json): Promise<Json> {
    const { log, store, datasets, now, keystore, randomId } = this.deps;
    log.debug("Entering RiskEngine.assessNow().");
    const realm = String(input.realm || '');
    const subject = String(input.subject);
    const context = input.context || {};
    const credential = context.credential || {};
    const address = String(context.address || '');
    const sealing = this.sealing();
    const at = now();
    const found = await datasets.lookup(address, realm);
    const device = RiskEngine.deviceOf(input.userAgent);
    const geo = found.geo || {};
    const network = found.asn || {};
    const attempt: Json = {
      ip: this.addressKey(address, sealing),
      asn: network.asn ? String(network.asn) : '',
      country: String(geo.country || ''),
      ua: String(context.uaFingerprint || ''),
      browser: device.browser, os: device.os, device: device.device
    };
    const user = await this.historyOf(realm, subject, attempt, false,
                                      sealing);
    const population = await this.historyOf(realm, POPULATION, attempt,
                                            true, sealing);
    const modelled = riskModel.score(attempt, user, population);

    // THE EVALUATORS (SIGNALS).
    const signals: Json[] = [];
    const add = function (id: string, evidence: string): void {
      log.debug("Entering add(). " + id);
      signals.push({ signal: id, factor: SIGNALS[id].factor,
                     what: SIGNALS[id].what, evidence: evidence });
      log.debug("Leaving add().");
    };
    found.lists.forEach(function (l: Json): void {
      if (SIGNALS[l.category]) {
        add(l.category, l.dataset);
      }
    });
    if (device.bot) {
      add('automated-client', device.browser || 'unnamed');
    }
    if (context.ja4 && user.n > 0) {
      const seen = await store.featureCounts(realm, subject,
        [{ feature: 'ja4', value: String(context.ja4) }], sealing);
      if (!seen.length) {
        add('new-tls-stack', String(context.ja4));
      }
    }
    const since = at - HOUR_MS;
    const mine = await store.listFailures(realm, { since: since,
      subject: subject, limit: 1 }, sealing);
    if (mine.total >= ACCOUNT_FAILURES) {
      add('account-failures', String(mine.total));
    }
    if (found.prefix) {
      const theirs = await store.listFailures(realm, { since: since,
        prefix: found.prefix, limit: 1 }, sealing);
      if (theirs.total >= NETWORK_FAILURES) {
        add('network-failures', String(theirs.total));
      }
    }

    // THE SCORE AND ITS LEVEL.
    let score = modelled.score === null ? 1 : modelled.score;
    signals.forEach(function (s: Json): void {
      score *= s.factor;
    });
    const level = modelled.score === null && !signals.length ? 'UNSCORED'
      : this.levelOf(score);
    const assessment: Json = {
      realm: realm, id: randomId(), at: at, phase: 'user',
      door: String(input.door || ''), subject: subject,
      sessionId: String(input.sessionId || ''),
      clientId: String(input.clientId || ''),
      addressSealed: sealing && address
        ? String(keystore().seal(address, 'risk.address') || '') : '',
      addressPrefix: found.prefix || '0.0.0.0/0',
      asn: Number(network.asn) || 0, asOrg: String(network.asOrg || ''),
      country: String(geo.country || ''),
      subdivision: String(geo.subdivision || ''),
      city: String(geo.city || ''),
      latitude: geo.latitude === undefined ? null : geo.latitude,
      longitude: geo.longitude === undefined ? null : geo.longitude,
      accuracyKm: Number(geo.accuracyKm) || 0,
      ipLists: found.lists.map(function (l: Json): string {
        return l.category;
      }),
      uaHash: attempt.ua, uaFamily: device.browser, uaOs: device.os,
      uaPlatform: device.device, bot: device.bot,
      ja4: String(context.ja4 || ''),
      credentialKind: String(credential.kind || ''),
      credentialHash: String(credential.fingerprint || ''),
      aaguid: String(credential.aaguid || ''),
      backupEligible: credential.backupEligible,
      backupState: credential.backupState,
      datasets: Object.assign({}, found.datasets,
                              { stale: found.stale,
                                attributions: found.attributions }),
      signals: [{ signal: 'model', score: modelled.score,
                  factors: modelled.factors || null,
                  why: modelled.why || '' }].concat(signals),
      score: score, level: level, decision: 'observe'
    };
    await store.recordAssessment(assessment, sealing);

    // THE HISTORY MOVES ON, after the score was taken against it.
    const moves: Json[] = [];
    const seenKeys = new Set<string>();
    // Called once per count moved, so no Entering/Leaving pair: a hot path,
    // as the code style allows when it says so.
    const move = function (who: string, feature: string,
                           value: string): void {
      const k = who + '\u0000' + feature + '\u0000' + value;
      if (!seenKeys.has(k)) {
        seenKeys.add(k);
        moves.push({ subject: who, feature: feature, value: value });
      }
    };
    [subject, POPULATION].forEach(function (who: string): void {
      move(who, '_total', '');
      riskModel.FEATURES.forEach(function (f: Json): void {
        f.levels.forEach(function (level: Json): void {
          move(who, level[0], String(attempt[level[0]]));
        });
      });
    });
    riskModel.FEATURES.forEach(function (f: Json): void {
      const first = f.levels[0][0];
      f.levels.slice(1).forEach(function (level: Json): void {
        move(POPULATION, first + '>' + level[0], String(attempt[first]) +
             '|' + String(attempt[level[0]]));
      });
    });
    move(POPULATION, 'user', subject);
    if (context.ja4) {
      move(subject, 'ja4', String(context.ja4));
    }
    if (credential.fingerprint || credential.kind) {
      move(subject, 'credential', String(credential.kind || '') + ':' +
           String(credential.fingerprint || ''));
    }
    await store.incrementCounts(realm, moves, at, sealing);
    await store.upsertSubject({ realm: realm, subject: subject,
      score: score, level: level,
      reason: signals.map(function (s: Json): string {
        return s.signal;
      }).join(', ') || (modelled.score === null ? String(modelled.why)
                                                : 'the model'),
      lastAssessment: assessment.id, updatedAt: at }, sealing);
    if (assessment.sessionId) {
      await store.upsertSessionContext({ realm: realm,
        sessionId: assessment.sessionId, subject: subject,
        addressPrefix: assessment.addressPrefix, asn: assessment.asn,
        country: assessment.country, uaHash: assessment.uaHash,
        ja4: assessment.ja4, jkt: '', score: score, level: level,
        updatedAt: at }, sealing);
    }
    log.info('risk: ' + subject + ' at ' + assessment.door + ' scored ' +
             (modelled.score === null ? 'nothing (' + modelled.why + ')'
                                      : score.toPrecision(3)) + ' — ' +
             level + (signals.length ? ' (' + signals.length +
                                       ' signal(s))' : '') + '.');
    log.debug("Leaving RiskEngine.assessNow().");
    return assessment;
  }

  // A page of assessments and the people by standing, for the page.
  async view(realm: string, opts: Json): Promise<Json> {
    const { log, store, now } = this.deps;
    log.debug("Entering RiskEngine.view().");
    const sealing = this.sealing();
    const o = opts || {};
    const assessments = await store.listAssessments(realm, {
      since: now() - 7 * 86400000, level: o.level || '',
      limit: 50, offset: Number(o.offset) || 0 }, sealing);
    const subjects = await store.listSubjects(realm, { limit: 25 }, sealing);
    log.debug("Leaving RiskEngine.view().");
    return { assessments: assessments, subjects: subjects,
             inDatabase: store.failuresInDatabase(sealing),
             signals: Object.keys(SIGNALS).map(function (id: string): Json {
               return Object.assign({ signal: id }, SIGNALS[id]);
             }) };
  }

  // History past its retention, for the retention job.
  async purge(): Promise<Json> {
    const { log, config, store, now } = this.deps;
    log.debug("Entering RiskEngine.purge().");
    const sealing = this.sealing();
    const day = 86400000;
    const out = { assessments: 0, counts: 0, sessions: 0 };
    const plan: Array<[string, number]> = [
      ['assessments', Number(config.value('risk.assessmentRetentionDays'))],
      ['counts', Number(config.value('risk.historyRetentionDays'))],
      ['sessions', Number(config.value('risk.historyRetentionDays'))]
    ];
    for (const pair of plan) {
      for (;;) {
        const gone = await store.purgeHistory(pair[0], now() - pair[1] * day,
                                              20000, sealing);
        out[pair[0]] += gone;
        if (gone < 20000) {
          break;
        }
      }
    }
    log.debug("Leaving RiskEngine.purge().");
    return out;
  }
}

const slot = new InstanceSlot<RiskEngine>(
  'risk/risk_engine',
  () => new RiskEngine(RiskEngine.defaultDeps()),
  null,
  log);

slot.buildNowUnlessDeferred();

export = {
  RiskEngine: RiskEngine,
  installInstance: (instance: RiskEngine): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  SIGNALS: RiskEngine.SIGNALS,
  deviceOf: RiskEngine.deviceOf,
  assess: slot.forward('assess'),
  view: slot.forward('view'),
  purge: slot.forward('purge')
};
