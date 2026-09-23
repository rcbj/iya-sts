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
import cacheRegistry = require('../common/cache_registry');

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
  mode(): Json;
}

// ---------------------------------------------------------------------------
// A PERSON'S STANDING, PER PROCESS (#62 P3). What an issuance with NO
// SESSION to read its risk from stands on — a Kerberos service ticket (the
// KDC is the parent project's locked code and asks the gate synchronously),
// a WS-Trust token — so that a person made HIGH at the browser is not issued
// a ticket at the next door. Filled by every assessment made in this
// process and by `loadStanding()` where a door can wait for the store;
// read by `standingOf()` only while `risk.standingValidMinutes` says it
// still answers. A standing forgotten or never held is an issuance decided
// on roles alone: unknown never denies. Keyed by realm and USERNAME, because
// the gate's subject is a name.
// ---------------------------------------------------------------------------
const standings = new Map<string, Json>();
const standingsCount = cacheRegistry.register({
  name: 'risk.standings',
  title: 'Risk standings',
  description: 'Each person\'s last assessed risk (level, score, signals), ' +
    'for an issuance with no session to read it from — a Kerberos ticket, ' +
    'a WS-Trust token (#62 P3).',
  owner: 'risk/risk_engine.ts',
  scope: 'process',
  kind: 'cache',
  persisted: false,
  hitMeaning: 'a standing held and still valid, so the issuance was ' +
    'decided with it',
  settings: ['risk.standingValidMinutes', 'risk.standingCacheSize'],
  maxEntries: function (): number {
    return Number(config.value('risk.standingCacheSize'));
  },
  bound: 'Enforced: risk.standingCacheSize people per process; full, the ' +
    'oldest is dropped, which decides that person\'s next sessionless ' +
    'issuance on roles alone.',
  lifetime: function (): string {
    return 'risk.standingValidMinutes after the assessment it records.';
  },
  eject: cacheRegistry.mapEjector(standings,
    function (row: Json, key: unknown, now: number): boolean {
      return !row || now - Number(row.at) >
        Number(config.value('risk.standingValidMinutes')) * 60000;
    }),
  entries: function (): unknown[] {
    const valid = Number(config.value('risk.standingValidMinutes')) * 60000;
    const out: Json[] = [];
    standings.forEach(function (row: Json, key: string): void {
      out.push({ realm: key.split('\u0000')[0],
                 key: cacheRegistry.digestKey(key),
                 validUntil: Number(row.at) + valid,
                 basis: 'the assessment ' + row.assessmentId });
    });
    return out;
  }
});

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
      },
      mode: function (): Json {
        return require('../common/mode');
      }
    };
  }

  // -------------------------------------------------------------------------
  // THE STEP-UPS AN AUTHENTICATION ALREADY MEETS (#62 P3), from the `amr`
  // and `acr` of the session or event it rests on — the issuance policy's
  // `risk-satisfied` bag. `second-factor` for two factors (acr `mfa`);
  // `security-key` — and second-factor with it — where a WebAuthn key
  // (amr `hwk`) was one of them, passwordless included: a key bound to this
  // origin is the step-up a relayed one-time code cannot pass, and asking
  // somebody who just used one for a code as well would be the weaker
  // factor demanded after the stronger.
  // -------------------------------------------------------------------------
  static satisfiedBy(amr: unknown, acr: unknown): string[] {
    log.debug("Entering RiskEngine.satisfiedBy().");
    const list = Array.isArray(amr) ? amr.map(String) : [];
    const out: string[] = [];
    if (list.indexOf('hwk') >= 0) {
      out.push('security-key', 'second-factor');
    } else if (String(acr || '') === 'mfa') {
      out.push('second-factor');
    }
    log.debug("Leaving RiskEngine.satisfiedBy(). " + out.join(','));
    return out;
  }

  // Whether a risk Deny is KEPT: product, or development with
  // `risk.enforceInDevelopment` (`mode.observesRiskOnly()`).
  enforced(): boolean {
    const { log, config, mode } = this.deps;
    log.debug("Entering RiskEngine.enforced().");
    let observes = true;
    try {
      observes = !!mode().observesRiskOnly();
    } catch (e) {
      log.debug("Caught in RiskEngine.enforced(): " + ((e && e.message) || e));
      // No mode module in this process: observe, which is development's
      // answer and never refuses anybody.
      observes = true;
    }
    const answer = !observes ||
      config.value('risk.enforceInDevelopment') === true;
    log.debug("Leaving RiskEngine.enforced(). " + answer);
    return answer;
  }

  // -------------------------------------------------------------------------
  // WHAT A SESSION CARRIES (#62 P3): the assessment reduced to what the
  // issuance policy reads, so every later issuance on the session is
  // decided on the risk its authentication established — and what P4's
  // re-scoring will replace. Never the address, never a dataset's answer.
  // -------------------------------------------------------------------------
  static riskOf(assessment: Json): Json | null {
    log.debug("Entering RiskEngine.riskOf().");
    if (!assessment || !assessment.level) {
      log.debug("Leaving RiskEngine.riskOf(). None.");
      return null;
    }
    const modelled = (assessment.signals || []).filter(function (s: Json) {
      return s && s.signal === 'model';
    })[0];
    log.debug("Leaving RiskEngine.riskOf().");
    return {
      level: String(assessment.level),
      score: modelled && modelled.score === null ? null
        : Number(assessment.score),
      signals: (assessment.signals || []).filter(function (s: Json) {
        return s && s.signal && s.signal !== 'model';
      }).map(function (s: Json): string {
        return String(s.signal);
      }),
      assessmentId: String(assessment.id || ''),
      at: Number(assessment.at) || 0
    };
  }

  // -------------------------------------------------------------------------
  // THE FACTS THE ISSUANCE GATE HANDS THE POLICY (#62 P3): a `riskOf()`
  // record, the step-ups the authentication meets, and whether a risk Deny
  // is enforced. Null — no risk attribute in the request — when there is
  // nothing assessed, or when `risk.assessSignIns` is off.
  // -------------------------------------------------------------------------
  factsOf(risk: Json, amr: unknown, acr: unknown): Json | null {
    const { log, config } = this.deps;
    log.debug("Entering RiskEngine.factsOf().");
    if (!risk || !risk.level ||
        config.value('risk.assessSignIns') === false) {
      log.debug("Leaving RiskEngine.factsOf(). None.");
      return null;
    }
    log.debug("Leaving RiskEngine.factsOf().");
    return {
      level: String(risk.level),
      score: risk.score === null || risk.score === undefined ? null
        : Number(risk.score),
      signals: (risk.signals || []).map(String),
      satisfied: RiskEngine.satisfiedBy(amr, acr),
      enforced: this.enforced(),
      assessmentId: String(risk.assessmentId || '')
    };
  }

  // -------------------------------------------------------------------------
  // THE FACTS FOR AN ISSUANCE, WHEREVER THEY ARE (#62 P3) — what
  // `common/issuance_gate.js` asks when a caller named no `risk` of its
  // own: the session's, where the caller handed one; the standing held in
  // this process for the person, where not. `amr`/`acr` come with the
  // session; a standing meets no step-up, because nothing says what the
  // next authentication will carry.
  // -------------------------------------------------------------------------
  factsForIssuance(asked: Json): Json | null {
    const { log } = this.deps;
    log.debug("Entering RiskEngine.factsForIssuance().");
    const q = asked || {};
    const session = q.session;
    if (session && session.risk) {
      log.debug("Leaving RiskEngine.factsForIssuance(). The session's.");
      return this.factsOf(session.risk, session.amr, session.acr);
    }
    const subject = q.subject || {};
    if (subject.kind !== 'user' || !subject.name ||
        subject.authenticated === false) {
      log.debug("Leaving RiskEngine.factsForIssuance(). Not a person.");
      return null;
    }
    const standing = this.standingOf(String(q.realm || ''),
                                     String(subject.name));
    log.debug("Leaving RiskEngine.factsForIssuance(). " +
              (standing ? 'A standing.' : 'None.'));
    return standing ? this.factsOf(standing, [], '') : null;
  }

  // A person's standing held in this process, while it still answers.
  // A hot path — asked at every sessionless issuance — so no Entering or
  // Leaving pair would add anything but volume, as the code style allows
  // when it says so.
  standingOf(realm: string, username: string): Json | null {
    const { config, now } = this.deps;
    const row = standings.get(realm + '\u0000' + username);
    if (!row || now() - Number(row.at) >
        Number(config.value('risk.standingValidMinutes')) * 60000) {
      standingsCount.miss();
      return null;
    }
    standingsCount.hit();
    return row;
  }

  // Held from an assessment made in this process, or read from the store.
  private holdStanding(realm: string, username: string, risk: Json): void {
    const { log, config } = this.deps;
    log.debug("Entering RiskEngine.holdStanding().");
    if (!username || !risk) {
      log.debug("Leaving RiskEngine.holdStanding(). Nothing to hold.");
      return;
    }
    const key = realm + '\u0000' + username;
    standings.delete(key);
    cacheRegistry.makeRoom(standings,
                           Number(config.value('risk.standingCacheSize')),
                           { name: 'risk.standings', counter: standingsCount,
                             setting: 'risk.standingCacheSize' });
    standings.set(key, risk);
    log.debug("Leaving RiskEngine.holdStanding().");
  }

  // -------------------------------------------------------------------------
  // A PERSON'S STANDING READ FROM THE STORE, for a door that can wait for it
  // before asking the gate (WS-Trust). `subject` is the person's `sub`;
  // `username` is what the gate is asked about. Never rejects.
  // -------------------------------------------------------------------------
  async loadStanding(realm: string, username: string,
                     subject: string): Promise<Json | null> {
    const { log, store } = this.deps;
    log.debug("Entering RiskEngine.loadStanding().");
    try {
      const row = await store.subjectOf(realm, subject, this.sealing());
      if (!row || !row.level) {
        log.debug("Leaving RiskEngine.loadStanding(). None.");
        return null;
      }
      const risk = { level: String(row.level), score: Number(row.score),
                     signals: String(row.reason || '').split(', ')
                       .filter(function (one: string): boolean {
                         return !!SIGNALS[one];
                       }),
                     assessmentId: String(row.lastAssessment || ''),
                     at: Number(row.updatedAt) || 0 };
      this.holdStanding(realm, username, risk);
      log.debug("Leaving RiskEngine.loadStanding().");
      return risk;
    } catch (e) {
      log.debug("Caught in RiskEngine.loadStanding(): " +
                ((e && e.message) || e));
      // The store could not answer: no standing, and the issuance is decided
      // on roles alone — unknown never denies.
      log.debug("Leaving RiskEngine.loadStanding(). Failed.");
      return null;
    }
  }

  // -------------------------------------------------------------------------
  // WHAT WAS DECIDED, written onto the assessment (#62 P3): the policy's
  // answer — permit, step-up, refuse, or observed — the policy that gave it,
  // the code of a refusal, and the session it became. Not awaited by the
  // sign-in; never rejects.
  // -------------------------------------------------------------------------
  settle(realm: string, assessmentId: string, outcome: Json): void {
    const { log, store } = this.deps;
    log.debug("Entering RiskEngine.settle(). " + assessmentId);
    if (!assessmentId) {
      log.debug("Leaving RiskEngine.settle(). No assessment.");
      return;
    }
    const o = outcome || {};
    store.settleAssessment({ realm: realm, id: assessmentId,
      decision: String(o.decision || ''), policyId: String(o.policy || ''),
      errorCode: String(o.errorCode || ''),
      sessionId: String(o.sessionId || '') }, this.sealing())
      .catch(function (e: Json): void {
        log.debug("Caught in RiskEngine.settle(): " + ((e && e.message) || e));
        // The decision stands; only its record on the assessment is lost.
      });
    if (o.sessionId && o.context) {
      store.upsertSessionContext(Object.assign({}, o.context,
        { sessionId: String(o.sessionId) }), this.sealing())
        .catch(function (e: Json): void {
          log.debug("Caught in RiskEngine.settle(): " +
                    ((e && e.message) || e));
          // Continuous evaluation (P4) will find no context for this
          // session, and will assess its next request afresh.
        });
    }
    log.debug("Leaving RiskEngine.settle().");
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
    // THE SESSION'S CONTEXT, for continuous evaluation (P4). Since P3 an
    // assessment is made BEFORE the session exists, so the context rides on
    // the answer and `settle()` writes it once the session has an id; an
    // assessment made for a session that already exists writes it here.
    const sessionContext = { realm: realm, subject: subject,
      addressPrefix: assessment.addressPrefix, asn: assessment.asn,
      country: assessment.country, uaHash: assessment.uaHash,
      ja4: assessment.ja4, jkt: '', score: score, level: level,
      updatedAt: at };
    if (assessment.sessionId) {
      await store.upsertSessionContext(Object.assign({
        sessionId: assessment.sessionId }, sessionContext), sealing);
    }
    Object.defineProperty(assessment, 'sessionContext',
                          { value: sessionContext, enumerable: false });
    this.holdStanding(realm, String(input.username || ''),
                      RiskEngine.riskOf(assessment));
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
  satisfiedBy: RiskEngine.satisfiedBy,
  riskOf: RiskEngine.riskOf,
  assess: slot.forward('assess'),
  factsOf: slot.forward('factsOf'),
  factsForIssuance: slot.forward('factsForIssuance'),
  standingOf: slot.forward('standingOf'),
  loadStanding: slot.forward('loadStanding'),
  settle: slot.forward('settle'),
  enforced: slot.forward('enforced'),
  view: slot.forward('view'),
  purge: slot.forward('purge')
};
