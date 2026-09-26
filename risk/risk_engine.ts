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
//      used, recent refused passwords for this person or from this network,
//      and (#164 phase 5) what the device register says about the device
//      that proved the sign-in — compromised, not compliant, missing for a
//      person who registered one, or theirs and compliant, which LOWERS the
//      score. The person's own registered device is then the `device`
//      history feature, and after the sign-in it takes the sign-in's level
//      (`setDeviceLevel()`).
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
  // ×20 since #226 (2026-09-26); it was ×50, HIGH on its own for anybody
  // whatever their history said, and one bogon on a list put a whole NAT's
  // population there at once. ×20 is still HIGH over a model of even odds.
  'operator-deny': { factor: 20,
    what: 'the address is on this realm\'s operator deny list' },
  'operator-allow': { factor: 0.2,
    what: 'the address is on this realm\'s operator allow list' },
  'automated-client': { factor: 10,
    what: 'the User-Agent is an automated client\'s' },
  'new-tls-stack': { factor: 2,
    what: 'a TLS client (JA4) this person has not signed in with before' },
  // #62 P6, only where the realm turned `risk.fingerprinting` on.
  'new-device': { factor: 2,
    what: 'a browser (by its fingerprint) this person has not signed in ' +
          'from before' },
  'account-failures': { factor: 3,
    what: 'refused passwords for this person in the last hour' },
  'network-failures': { factor: 3,
    what: 'refused passwords from this network in the last hour' },
  // #62 P5: the FIDO Metadata Service says the security key's MODEL was
  // revoked, or its keys can be extracted or its user verification bypassed.
  // A key from such a model proves possession of something anybody may hold.
  // #62 P6: the person said, on /portal/sign-ins, that a sign-in of theirs
  // was NOT them. Not a factor on a score — it sets their standing to HIGH
  // outright — and named so the risk-response policy can tell RISC the
  // credential used is compromised.
  'reported-not-me': { factor: 1,
    what: 'the person reported a sign-in as not theirs' },
  'authenticator-compromised': { factor: 50,
    what: 'the security key\'s model is reported revoked or compromised in ' +
          'the FIDO metadata' },
  // -------------------------------------------------------------------------
  // THE REGISTERED DEVICE (#164 decision 4, phase 5, 2026-09-26): what the
  // device register says about the device that proved this sign-in —
  // recognised by one of its keys (`common/device_recognition.ts`) and
  // recorded on the authentication event before the engine is asked.
  //
  //   * `compromised-device` (×50, HIGH on its own, as
  //     `authenticator-compromised` is): the device is marked compromised. A
  //     compromise ends every session the device authenticated and revokes
  //     its certificates and secret, but its JWK and WebAuthn keys still
  //     prove the device — they belong to the hardware — so a sign-in from
  //     it is still possible, and is exactly the one to refuse.
  //   * `non-compliant-device` (×3, the refused-password weight): an MDM, a
  //     posture feed or an administrator says the device does not meet the
  //     organisation's policy. Evidence, so it applies however new the
  //     person is.
  //   * `unregistered-device` (×2, `new-device`'s weight): NO device of this
  //     person's was recognised — none at all, or one owned by somebody
  //     else. SCOPED so it does not fire on everybody in a realm that has
  //     no devices: only for a person who has REGISTERED one (`devices.
  //     holdsAny()`, an index lookup), or in a realm that says it expects
  //     every person to (`devices.expectRegistered`). A person who never
  //     registered a device signing in from a browser is the ordinary case,
  //     and a signal that fired on every ordinary case would only move
  //     every score by the same factor, which is calibration noise and not
  //     evidence. And it waits for `risk.minimumHistory`, as `new-device`
  //     does: it is an ABSENCE, and an absence says nothing about somebody
  //     the model cannot score yet — without that, a device owner's second
  //     sign-in from a laptop would be MEDIUM on this alone and asked for a
  //     second factor.
  //   * `compliant-attested-device` (×0.5) and `compliant-device` (×0.8):
  //     the person's OWN device, compliant, not compromised — attested (a
  //     verifier checked a statement about the key's hardware) or
  //     self-asserted. LOWERING factors, as `operator-allow` (×0.2) already
  //     is: the model is a likelihood ratio and the evaluators multiply it,
  //     so a factor below 1 is evidence FOR the sign-in with no new
  //     machinery. The self-asserted one lowers less, because what vouches
  //     for it is only the enrolment that proved the key. Neither ever
  //     makes a sign-in scored on its own (see `LOWERING_ONLY`), and
  //     neither is weighed against a compromise: a compromised device is
  //     never "compliant" here, whatever its compliance says.
  // -------------------------------------------------------------------------
  'compromised-device': { factor: 50,
    what: 'the registered device that proved the sign-in is marked ' +
          'compromised' },
  'non-compliant-device': { factor: 3,
    what: 'the registered device that proved the sign-in is not compliant' },
  'unregistered-device': { factor: 2,
    what: 'no registered device of this person\'s was recognised, and they ' +
          'have registered one (or the realm expects every person to)' },
  'compliant-attested-device': { factor: 0.5,
    what: 'the person\'s own registered device, compliant and attested' },
  'compliant-device': { factor: 0.8,
    what: 'the person\'s own registered device, compliant and ' +
          'self-asserted' }
};

// THE SIGNALS THAT ONLY LOWER A SCORE and do not, alone, make an UNSCORED
// sign-in scored (#164 phase 5). A first sign-in with nothing else to say is
// UNSCORED so that nothing is decided on no evidence; "it came from the
// person's compliant device" is evidence FOR it, and a level of LOW
// manufactured from that alone would be the first standing the risk-response
// policy announces for every new device owner.
const LOWERING_ONLY = ['compliant-attested-device', 'compliant-device'];

// How many refused passwords in the last hour make a signal of each kind:
// `risk.accountFailureThreshold` (5) and `risk.networkFailureThreshold`
// (20), read per assessment. They were constants until 2026-09-23, when the
// suite's own deliberate wrong passwords — every job from one /24 — put
// `network-failures` on every first sign-in in the default realm.
const accountFailureThreshold = function (): number {
  return Number(config.value('risk.accountFailureThreshold'));
};
const networkFailureThreshold = function (): number {
  return Number(config.value('risk.networkFailureThreshold'));
};
// HOW MANY EARLIER SIGN-INS A PERSON NEEDS BEFORE THE MODEL SCORES THEM
// (`risk.minimumHistory`, 5; 2026-09-23). The Freeman et al. model compares a
// sign-in with this person's history, and with one or two earlier sign-ins
// that history is mostly the population's prior: a new person's second
// sign-in came out MEDIUM because everybody else shares their network and
// browser, and the issuance policy asked for a security key. Fewer sign-ins
// than this are UNSCORED, as a first sign-in always was, and the two NOVELTY
// signals (`new-device`, `new-tls-stack`) wait for the same history, because
// "not seen before" says nothing about somebody seen once. The EVIDENCE
// signals — a list, an automated client, refused passwords, a compromised
// security key — still apply however new the person is.
const minimumHistory = function (): number {
  return Math.max(1, Number(config.value('risk.minimumHistory')) || 1);
};

// ---------------------------------------------------------------------------
// THE SIGNALS THAT ARE ABOUT THE ADDRESS AND NOTHING ELSE (#226,
// 2026-09-26): a list the address is on, and the refused passwords from its
// network. What they have in common is that every person behind one NAT, one
// proxy or one container bridge shares them — so one listed address, or one
// person mistyping twenty times, is a signal on EVERYBODY there at once. That
// is how #226 refused every sign-in to the service, the console's included:
// the address was the Docker bridge, 172.29.0.1, and a loaded block list
// carried the bogons, 172.16.0.0/12 among them.
//
// Two rules read this set:
//
//   * A KNOWN CONTEXT CAPS THEM AT MEDIUM. A person with at least
//     `risk.minimumHistory` earlier sign-ins from this very address AND this
//     very browser (by its fingerprint) is somebody the address evidence is
//     least likely to be about: it can ask them for a step-up, and it cannot
//     refuse them. The evidence about the CREDENTIAL — refused passwords for
//     this person, a compromised security key, a sign-in they said was not
//     them, an automated client — is not capped, because none of it is
//     shared by a network.
//   * `risk.listsMatchSpecialPurpose` off makes a LIST signal inapplicable
//     to a loopback, private, link-local or reserved address — below.
// ---------------------------------------------------------------------------
const ADDRESS_SIGNALS = ['tor-exit', 'reputation', 'operator-deny',
                         'network-failures'];

// The lists whose match RAISES risk. The operator's allow list lowers it,
// and is not set aside for a special-purpose address: an operator vouching
// for their own private network is saying exactly what they mean.
const RAISING_LISTS = ['tor-exit', 'reputation', 'operator-deny'];
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
  scheduler(): Json;
  lazy(name: string): Json;
}

// The scheduler job that re-checks live sessions (#62 P4).
const RESCORE_JOB = 'risk.rescore';

// A level's rank, for "did it go up".
const RANK: Record<string, number> = { UNSCORED: 0, LOW: 1, MEDIUM: 2,
                                       HIGH: 3 };

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

// ---------------------------------------------------------------------------
// WHAT THIS PROCESS HAS DONE, for Monitoring → Risk Scoring (#62). The
// assessments themselves are rows in the store and are counted there, over
// any window; what is NOT a row is counted here — how long an assessment
// took, one that failed, the reactions taken, the live-session re-checks,
// what people said about their sign-ins — and so it is per process and
// since the process started, and the page says so. The durations are the
// last DURATIONS_KEPT, which is what a percentile is taken over.
// ---------------------------------------------------------------------------
const DURATIONS_KEPT = 1000;
const tally = {
  since: Date.now(),
  assessed: 0,
  failed: 0,
  durations: [] as number[],
  reactions: { taken: {} as Record<string, number>,
               observed: {} as Record<string, number>,
               failed: {} as Record<string, number> },
  rescore: { runs: 0, sessions: 0, raised: 0 }
};

// ---------------------------------------------------------------------------
// THE FACTORS AN OPERATOR SET (#62, calibration): `risk.signalFactors` is a
// list of `signal=factor` — `tor-exit=8,new-device=1.5` — over SIGNALS'
// built-in factors, per realm like every setting, so a factor the
// calibration report suggests is applied without a release. The parse is
// kept per raw value, and a malformed entry is logged ONCE for that value
// (STS-RISK-0026) rather than at every sign-in, and ignored: an unknown
// signal, or a factor that is not a positive number, would otherwise change
// every score by a typo.
// ---------------------------------------------------------------------------
const parsedFactors = new Map<string, Json>();

// How many calibration answers a signal needs before a factor is suggested
// for it, and how many assessments a window needs before thresholds are:
// below these a suggestion is noise, and the report says "not enough".
const MIN_ANSWERS_PER_SIGNAL = 20;
const MIN_ASSESSMENTS_FOR_THRESHOLDS = 100;

// One more of `key` in a count table. A hot path's helper, no pair.
function bump(table: Record<string, number>, key: string): void {
  table[key] = (table[key] || 0) + 1;
}

// The value at fraction `p` of a sorted list, or 0 for an empty one.
function percentile(sorted: number[], p: number): number {
  log.debug("Entering percentile().");
  if (!sorted.length) {
    log.debug("Leaving percentile(). Empty.");
    return 0;
  }
  log.debug("Leaving percentile().");
  return sorted[Math.min(sorted.length - 1,
                         Math.floor(p * sorted.length))];
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
      },
      mode: function (): Json {
        return require('../common/mode');
      },
      scheduler: function (): Json {
        return require('../cluster/scheduler');
      },
      // The modules a reaction reaches — SSF, RISC, the account, the XACML
      // PEP, the sign-in service — all built long after this one (18j), so
      // each is required when a reaction is taken and never at load.
      lazy: function (name: string): Json {
        return require(name);
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
  //
  // **AN EMAILED CODE OR LINK MEETS NONE (#64, rcbj's D1)**: NIST SP
  // 800-63B-4 section 3.1.3.1 does not count email as an authenticator, and
  // a step-up is asked for exactly when something about the sign-in is
  // doubted — the password, most often, which is the credential a mailbox
  // is so often opened with. `kinds` are the credential kinds the
  // authentication used; a key still meets the key step-up beside one.
  static satisfiedBy(amr: unknown, acr: unknown, kinds?: unknown): string[] {
    log.debug("Entering RiskEngine.satisfiedBy().");
    const list = Array.isArray(amr) ? amr.map(String) : [];
    const byEmail = (Array.isArray(kinds) ? kinds.map(String) : [])
      .some(function (kind) {
        return kind.indexOf('email-') === 0;
      });
    const out: string[] = [];
    if (list.indexOf('hwk') >= 0) {
      out.push('security-key', 'second-factor');
    } else if (String(acr || '') === 'mfa' && !byEmail) {
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
      at: Number(assessment.at) || 0,
      // A KNOWN CONTEXT (#226): the sign-in came from an address and a
      // browser this person has used `risk.minimumHistory` times, which
      // caps the address evidence at MEDIUM — and so caps what the
      // `risk.rescore` job may raise the session to on a list it gains.
      knownContext: !!(modelled && modelled.knownContext),
      // THE DEVICE, AS A FAMILY (#62 P4): the browser and the operating
      // system without their versions, which is what continuous evaluation
      // compares a later request with. A browser updating itself mid-session
      // changes the User-Agent and its fingerprint; it does not change what
      // the person is signing in with.
      device: Object.assign(RiskEngine.familyOf({
        browser: assessment.uaFamily, os: assessment.uaOs }),
        // The person's own registered device, where one proved the sign-in
        // (#164 phase 5) — by its register id, which is what the history
        // counted it under.
        modelled && modelled.device && modelled.device.own
          ? { registered: String(modelled.device.id) } : {})
    };
  }

  // Whether `fact` (a recognition, or null) is `username`'s OWN device: a
  // person's, by name — `ownerMatches` where recognition computed it.
  static ownDevice(fact: Json, username: string): boolean {
    log.debug("Entering RiskEngine.ownDevice().");
    const own = !!fact && !!username && (fact.ownerMatches === true ||
      (fact.ownerMatches === undefined && fact.ownerKind === 'person' &&
       String(fact.ownerName || '') === username));
    log.debug("Leaving RiskEngine.ownDevice(). " + own);
    return own;
  }

  // What an assessment records of the registered device, or null.
  static deviceOnAssessment(fact: Json, own: boolean): Json {
    log.debug("Entering RiskEngine.deviceOnAssessment().");
    if (!fact) {
      log.debug("Leaving RiskEngine.deviceOnAssessment(). None.");
      return null;
    }
    log.debug("Leaving RiskEngine.deviceOnAssessment().");
    return { id: String(fact.id || ''), via: String(fact.via || ''),
             own: !!own, compliance: String(fact.compliance || 'unknown'),
             attestation: String(fact.attestation || ''),
             status: String(fact.status || 'active') };
  }

  // -------------------------------------------------------------------------
  // WHETHER A MISSING DEVICE IS A SIGNAL for this person (#164 phase 5;
  // `unregistered-device` above): the realm expects everybody to sign in
  // from a registered device (`devices.expectRegistered`), or this person
  // registered one. Never throws: a register that cannot answer expects
  // nothing, and the signal does not fire.
  // -------------------------------------------------------------------------
  private expectsDevice(username: string): boolean {
    const { log, config, lazy } = this.deps;
    log.debug("Entering RiskEngine.expectsDevice().");
    if (config.value('devices.expectRegistered') === true) {
      log.debug("Leaving RiskEngine.expectsDevice(). The realm expects one.");
      return true;
    }
    let holds = false;
    try {
      holds = !!username && !!lazy('../common/devices').holdsAny(username);
    } catch (e) {
      log.debug("Caught in RiskEngine.expectsDevice(): " +
                ((e && e.message) || e));
      // No register in this process (a test of this file): nothing is
      // expected of anybody.
      holds = false;
    }
    log.debug("Leaving RiskEngine.expectsDevice(). " + holds);
    return holds;
  }

  // -------------------------------------------------------------------------
  // THE DEVICE'S OWN RISK LEVEL (#164 decision 4, phase 5): after a sign-in
  // the person's own registered device proved, the device takes THE LEVEL
  // OF THAT SIGN-IN — LOW, MEDIUM or HIGH, the engine's own mapping of the
  // score — through `devices.setRiskLevel()`, which sends CAEP
  // risk-level-change with principal DEVICE only when the level MOVED.
  //
  // WHY THE SAME LEVEL, AND NOT A SCORE OF ITS OWN. The model is one
  // likelihood ratio over the whole context — address, network, browser,
  // TLS client — and the evaluators multiply it; nothing in it says which
  // part of a score is "the device's", and dividing the credential signals
  // back out would be a second model nobody calibrated. What the device
  // took part in is this sign-in, and the most recent sign-in it proved is
  // the best evidence there is about what is happening on it — which is
  // what a CAEP receiver reading a DEVICE principal wants to know. So:
  //
  //   * UNSCORED sets nothing: there was nothing to say about the sign-in,
  //     so there is nothing to say about the device.
  //   * A COMPROMISED device keeps its HIGH: `setRiskLevel()` holds a
  //     compromised device for source `risk`, and only a restore moves it.
  //   * Only a sign-in (`phase` user) sets it — not a live session's
  //     re-assessment, whose request proved no device.
  //   * Somebody else's device is not moved by this person's sign-in: its
  //     level is its owner's story.
  //
  // Never throws, and never fails the sign-in: a register that cannot store
  // the level is logged (STS-DEVICE-0036).
  // -------------------------------------------------------------------------
  private setDeviceLevel(fact: Json, assessment: Json): void {
    const { log, lazy } = this.deps;
    log.debug("Entering RiskEngine.setDeviceLevel().");
    const level = String(assessment.level || '');
    if (!fact || !fact.id || ['LOW', 'MEDIUM', 'HIGH'].indexOf(level) < 0) {
      log.debug("Leaving RiskEngine.setDeviceLevel(). Nothing to set.");
      return;
    }
    const reason = (assessment.signals || []).filter(function (s: Json) {
      return s && s.signal && s.signal !== 'model';
    }).map(function (s: Json): string {
      return String(s.signal);
    }).join(', ') || 'the sign-in it proved scored ' + level;
    try {
      const done = lazy('../common/devices').setRiskLevel(String(fact.id),
        level, reason, { source: 'risk', actor: 'risk scoring' });
      if (!done || !done.ok) {
        log.warn(errorCodes.tag('STS-DEVICE-0036') + 'risk: device ' +
                 fact.id + '\'s risk level was not set to ' + level + ': ' +
                 String((done && done.error) || 'no answer') + '.');
      }
    } catch (e) {
      log.debug("Caught in RiskEngine.setDeviceLevel(): " +
                ((e && e.message) || e));
      // No register in this process (a test of this file), or it threw:
      // the sign-in stands and the device keeps the level it had.
    }
    log.debug("Leaving RiskEngine.setDeviceLevel(). " + level);
  }

  // A device's browser and OS without their versions: `Chrome 140` is
  // `Chrome`, `Windows 10` is `Windows`, `macOS Sequoia` is `macOS`.
  static familyOf(device: Json): Json {
    log.debug("Entering RiskEngine.familyOf().");
    const d = device || {};
    log.debug("Leaving RiskEngine.familyOf().");
    return { browser: String(d.browser || '').replace(/\s+[\d.]+$/, ''),
             os: String(d.os || '').split(/\s+/)[0] || '' };
  }

  // -------------------------------------------------------------------------
  // THE FACTS THE ISSUANCE GATE HANDS THE POLICY (#62 P3): a `riskOf()`
  // record, the step-ups the authentication meets, and whether a risk Deny
  // is enforced. Null — no risk attribute in the request — when there is
  // nothing assessed, or when `risk.assessSignIns` is off.
  // -------------------------------------------------------------------------
  factsOf(risk: Json, amr: unknown, acr: unknown,
          kinds?: unknown): Json | null {
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
      satisfied: RiskEngine.satisfiedBy(amr, acr, kinds),
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
      // The credential kinds of the events it stands on (#64): an emailed
      // one meets no step-up.
      const kinds = (Array.isArray(session.events) ? session.events : [])
        .map(function (event: Json) {
          return String((event && event.context && event.context.credential &&
                         event.context.credential.kind) || '');
        }).filter(Boolean);
      return this.factsOf(session.risk, session.amr, session.acr, kinds);
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

  // -------------------------------------------------------------------------
  // THE LISTS THAT COUNT for an address (#226): every match whose category
  // is a signal — except, while `risk.listsMatchSpecialPurpose` is off, a
  // list that RAISES risk matching a loopback, private, link-local or
  // reserved address. It is ON by default: a list says what it says, and
  // FireHOL's level 1 carries the bogons on purpose. Off is for a service
  // tested on one machine, or run behind a bridge or a NAT that every
  // person arrives through, where a bogon on a list is a signal on
  // everybody. The set of addresses is the one the outbound rules refuse to
  // dial (`federation_http.ts`'s `internalAddressProblem()`), so this
  // service has one opinion of what is internal, not two.
  // -------------------------------------------------------------------------
  private countedLists(found: Json, address: string): Json[] {
    const { log, config, lazy } = this.deps;
    log.debug("Entering RiskEngine.countedLists().");
    const all = (found.lists || []).filter(function (l: Json): boolean {
      return !!SIGNALS[l.category];
    });
    const raising = all.filter(function (l: Json): boolean {
      return RAISING_LISTS.indexOf(l.category) >= 0;
    });
    if (!raising.length ||
        config.value('risk.listsMatchSpecialPurpose') !== false) {
      log.debug("Leaving RiskEngine.countedLists(). " + all.length + ".");
      return all;
    }
    const internal = lazy('../federation/federation_http')
      .internalAddressProblem(address);
    if (!internal || / is not an IP address$/.test(internal)) {
      log.debug("Leaving RiskEngine.countedLists(). A public address.");
      return all;
    }
    log.debug("Leaving RiskEngine.countedLists(). " + raising.length +
              " list(s) set aside for a special-purpose address.");
    return all.filter(function (l: Json): boolean {
      return raising.indexOf(l) < 0;
    });
  }

  // -------------------------------------------------------------------------
  // THE CAP ON ADDRESS EVIDENCE (#226): `{ score, why }` when `score` is
  // HIGH and would not be without the ADDRESS_SIGNALS among `signals`, or
  // null. The capped score is the largest number under the HIGH line, so
  // the level is MEDIUM and the score still says how close it came.
  // -------------------------------------------------------------------------
  private capped(score: number, signals: Json[]): Json | null {
    const { log, config } = this.deps;
    log.debug("Entering RiskEngine.capped().");
    const high = Number(config.value('risk.highScorePercent')) / 100;
    let address = 1;
    const named: string[] = [];
    signals.forEach(function (s: Json): void {
      if (ADDRESS_SIGNALS.indexOf(s.signal) >= 0 && s.factor > 1) {
        address *= s.factor;
        named.push(s.signal);
      }
    });
    if (score < high || !named.length || score / address >= high) {
      log.debug("Leaving RiskEngine.capped(). Not capped.");
      return null;
    }
    const under = high * (1 - 1e-9);
    log.debug("Leaving RiskEngine.capped(). Capped.");
    return { score: under,
             why: 'a known address and browser: ' + named.join(', ') +
                  ' capped at MEDIUM (' + score.toPrecision(3) + ', held ' +
                  'just under the HIGH line at ' + high + ')' };
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
  // header, read here and dropped), registeredDevice (the event's
  // recognised device, #164 phase 5, or null) }. Answers the assessment, or
  // null when it could not be made; never rejects.
  // -------------------------------------------------------------------------
  async assess(input: Json): Promise<Json | null> {
    const { log, config } = this.deps;
    log.debug("Entering RiskEngine.assess().");
    if (config.value('risk.assessSignIns') === false || !input ||
        !input.subject) {
      log.debug("Leaving RiskEngine.assess(). Not assessed.");
      return null;
    }
    const started = Date.now();
    try {
      const answer = await this.assessNow(input);
      tally.assessed++;
      tally.durations.push(Date.now() - started);
      if (tally.durations.length > DURATIONS_KEPT) {
        tally.durations.splice(0, tally.durations.length - DURATIONS_KEPT);
      }
      log.debug("Leaving RiskEngine.assess().");
      return answer;
    } catch (e) {
      tally.failed++;
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
    const enough = user.n >= minimumHistory();
    const modelled = enough ? riskModel.score(attempt, user, population)
      : { score: null,
          why: user.n
            ? 'only ' + user.n + ' earlier sign-in(s): fewer than ' +
              'risk.minimumHistory (' + minimumHistory() + ') is too ' +
              'little history to score'
            : 'the first sign-in: there is no history to compare it with' };

    // THE EVALUATORS (SIGNALS), each at the realm's factor.
    const factorOf = this.factors().factors;
    const signals: Json[] = [];
    const add = function (id: string, evidence: string): void {
      log.debug("Entering add(). " + id);
      signals.push({ signal: id, factor: factorOf[id],
                     what: SIGNALS[id].what, evidence: evidence });
      log.debug("Leaving add().");
    };
    const lists = this.countedLists(found, address);
    lists.forEach(function (l: Json): void {
      add(l.category, l.dataset);
    });
    if (device.bot) {
      add('automated-client', device.browser || 'unnamed');
    }
    // THE SECURITY KEY'S MODEL, from the FIDO metadata (#62 P5).
    const authenticator = credential.aaguid
      ? await datasets.lookupAuthenticator(String(credential.aaguid)) : null;
    if (authenticator && authenticator.model.compromised) {
      add('authenticator-compromised',
          String(authenticator.model.description || credential.aaguid) +
          ' (' + String(authenticator.model.latestStatus || '') + ')');
    }
    // THE REGISTERED DEVICE (#164 phase 5; SIGNALS above). `own` is the
    // person's own device, which is what the lowering factors and the
    // device feature read; a device owned by somebody else is evidence about
    // the device and nothing about this person's.
    const registered = input.registeredDevice || null;
    const username = String(input.username || '');
    const own = RiskEngine.ownDevice(registered, username);
    const compromised = !!registered && registered.status === 'compromised';
    if (compromised) {
      add('compromised-device', String(registered.id));
    } else if (registered && registered.compliance === 'not-compliant') {
      add('non-compliant-device', String(registered.id));
    }
    if (!own && enough && this.expectsDevice(username)) {
      add('unregistered-device', registered
        ? 'another owner\'s device ' + String(registered.id)
        : 'none recognised');
    }
    if (own && !compromised && registered.compliance === 'compliant') {
      add(registered.attestation === 'attested' ? 'compliant-attested-device'
                                                : 'compliant-device',
          String(registered.id));
    }
    // THE DEVICE FEATURE: the person's own registered device where one
    // proved the sign-in — its register id, which no browser update or
    // cleared fingerprint changes — and the browser fingerprint (#62 P6)
    // otherwise. A registered device of the person's own is NEVER a
    // `new-device`: its key was proven to be theirs at enrolment, which is
    // stronger than any history, so the first sign-in from a phone they
    // just registered is not doubted for being the first. The history still
    // records it under its id.
    const deviceFeature = own ? 'registered:' + String(registered.id)
                              : String(context.device || '');
    if (!own && context.device && enough) {
      const seenDevice = await store.featureCounts(realm, subject,
        [{ feature: 'device', value: deviceFeature }], sealing);
      if (!seenDevice.length) {
        add('new-device', deviceFeature.slice(0, 12));
      }
    }
    // THE TLS STACK, not the raw JA4: a resumed session adds two extensions,
    // so one client has two JA4s (`tls/client_hello.ts`'s `stack()`).
    const tlsStack = String(context.tlsStack || context.ja4 || '');
    if (tlsStack && enough) {
      const seen = await store.featureCounts(realm, subject,
        [{ feature: 'ja4', value: tlsStack }], sealing);
      if (!seen.length) {
        add('new-tls-stack', tlsStack);
      }
    }
    const since = at - HOUR_MS;
    const mine = await store.listFailures(realm, { since: since,
      subject: subject, limit: 1 }, sealing);
    if (mine.total >= accountFailureThreshold()) {
      add('account-failures', String(mine.total));
    }
    if (found.prefix) {
      const theirs = await store.listFailures(realm, { since: since,
        prefix: found.prefix, limit: 1 }, sealing);
      if (theirs.total >= networkFailureThreshold()) {
        add('network-failures', String(theirs.total));
      }
    }

    // THE SCORE AND ITS LEVEL, with the address evidence capped at MEDIUM
    // for a known context (#226; ADDRESS_SIGNALS, above). The cap holds the
    // SCORE just under the HIGH line rather than relabelling the level, so
    // the score, the level and the bands Monitoring → Risk Scoring draws
    // stay one story; what was capped is on the model's row.
    const knownContext = enough && !!attempt.ua &&
      user.count('ip', attempt.ip) >= minimumHistory() &&
      user.count('ua', attempt.ua) >= minimumHistory();
    let score = modelled.score === null ? 1 : modelled.score;
    signals.forEach(function (s: Json): void {
      score *= s.factor;
    });
    const capped = knownContext ? this.capped(score, signals) : null;
    if (capped) {
      score = capped.score;
    }
    const evidence = signals.filter(function (s: Json): boolean {
      return LOWERING_ONLY.indexOf(s.signal) < 0;
    });
    const level = modelled.score === null && !evidence.length ? 'UNSCORED'
      : this.levelOf(score);
    const assessment: Json = {
      realm: realm, id: randomId(), at: at,
      // `user` for a sign-in; `session` for a live session whose context
      // moved (#62 P4), which is scored against the history and does not
      // add to it — it is not an attempt to sign in.
      phase: input.phase === 'session' ? 'session' : 'user',
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
      // The model's FIDO certification level, where the metadata lists it.
      authenticatorCert: authenticator
        ? String(authenticator.model.certificationLevel || '') : '',
      backupEligible: credential.backupEligible,
      backupState: credential.backupState,
      datasets: Object.assign({}, found.datasets,
                              authenticator
                                ? { 'fido.mds3': authenticator.version } : {},
                              { stale: found.stale,
                                attributions: found.attributions }),
      signals: [{ signal: 'model', score: modelled.score,
                  factors: modelled.factors || null,
                  why: modelled.why || '',
                  knownContext: knownContext,
                  capped: capped ? capped.why : '',
                  // Lists the address is on that were set aside for a
                  // special-purpose address (#226), so the record says so.
                  listsSetAside: found.lists.filter(function (l: Json) {
                    return !!SIGNALS[l.category] && lists.indexOf(l) < 0;
                  }).map(function (l: Json): string {
                    return l.category;
                  }),
                  // THE REGISTERED DEVICE BEHIND THE SIGN-IN (#164 phase
                  // 5), on the model's row because that row is a JSON
                  // value in every store — what Monitoring → Risk draws
                  // beside the browser. Never a key, never a thumbprint.
                  device: RiskEngine.deviceOnAssessment(registered, own)
                }].concat(signals),
      score: score, level: level, decision: 'observe'
    };
    await store.recordAssessment(assessment, sealing);

    // THE HISTORY MOVES ON, after the score was taken against it — for a
    // sign-in. A live session's re-assessment (#62 P4) is not an attempt to
    // sign in, and counting it would teach the model that the context a
    // stolen cookie is replayed from is where this person signs in.
    const moves: Json[] = [];
    const counting = input.phase !== 'session';
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
    if (context.tlsStack || context.ja4) {
      move(subject, 'ja4', String(context.tlsStack || context.ja4));
    }
    if (deviceFeature) {
      move(subject, 'device', deviceFeature);
    }
    if (credential.fingerprint || credential.kind) {
      move(subject, 'credential', String(credential.kind || '') + ':' +
           String(credential.fingerprint || ''));
    }
    if (counting) {
      await store.incrementCounts(realm, moves, at, sealing);
    }
    // THE STANDING BEFORE, so a CHANGE of level is seen (#62 P4).
    const before = await store.subjectOf(realm, subject, sealing);
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
    this.noteChange(realm, subject, String(input.username || ''),
                    before ? String(before.level || '') : '', assessment);
    if (own && counting) {
      this.setDeviceLevel(registered, assessment);
    }
    log.info('risk: ' + subject + ' at ' + assessment.door + ' scored ' +
             (modelled.score === null ? 'nothing (' + modelled.why + ')'
                                      : score.toPrecision(3)) + ' — ' +
             level + (signals.length ? ' (' + signals.length +
                                       ' signal(s))' : '') + '.');
    log.debug("Leaving RiskEngine.assessNow().");
    return assessment;
  }

  // -------------------------------------------------------------------------
  // A CHANGE OF A PERSON'S LEVEL (#62 P4). Not awaited: the reactions run
  // after the assessment is answered, and a failure in one is logged
  // (STS-RISK-0021) and never reaches the sign-in. UNSCORED is no level to
  // react to, and a first standing has no level before it.
  // -------------------------------------------------------------------------
  private noteChange(realm: string, subject: string, username: string,
                     previous: string, assessment: Json): void {
    const { log } = this.deps;
    log.debug("Entering RiskEngine.noteChange().");
    const level = String(assessment.level || '');
    const was = previous === 'UNSCORED' ? '' : previous;
    if (!level || level === 'UNSCORED' || level === was) {
      log.debug("Leaving RiskEngine.noteChange(). No change.");
      return;
    }
    // A CHANGE ABOUT SOMEBODY NOBODY NAMED is recorded on the standing and
    // answered by nothing: every reaction is about a person by name — their
    // sessions, their account, the subject of an event. Every door names
    // them; an assessment made without a name (a test of the model) does
    // not reach out to the rest of the service.
    if (!username) {
      log.debug("Leaving RiskEngine.noteChange(). Nobody named.");
      return;
    }
    const risk = RiskEngine.riskOf(assessment);
    // WHAT THE PERSON HELD BEFORE THIS SIGN-IN (#226), taken NOW — in the
    // same tick as the assessment, before the door that asked for it starts
    // a session. The reactions run afterwards, and ending "everything" then
    // ended the session this sign-in had just been PERMITTED, by the
    // issuance policy, on this very risk: the console's alarm-permitted
    // sign-in was thrown out 150 ms after it was let in. A sign-in's
    // reaction ends what was held before it; a session re-assessment
    // (`phase` session or rescore) has no new session to spare and ends all.
    let heldBefore: string[] | null = null;
    if (assessment.phase === 'user') {
      try {
        heldBefore = this.deps.lazy('../common/account_state')
          .heldBy(username);
      } catch (e) {
        log.debug("Caught in RiskEngine.noteChange(): " +
                  ((e && e.message) || e));
        // Cannot say what was held: the reaction ends everything, as it did.
        heldBefore = null;
      }
    }
    this.respond({ realm: realm, subject: subject, username: username,
                   level: level, previousLevel: was,
                   score: risk ? risk.score : null,
                   signals: risk ? risk.signals : [],
                   heldBefore: heldBefore,
                   assessmentId: String(assessment.id || '') })
      .catch(function (e: Json): void {
        log.debug("Caught in RiskEngine.noteChange(): " +
                  ((e && e.message) || e));
        // respond() handles its own failures; this is its belt and braces.
      });
    log.debug("Leaving RiskEngine.noteChange(). " + (was || 'none') +
              " to " + level + ".");
  }

  // -------------------------------------------------------------------------
  // THE REACTIONS TO A CHANGE (#62 P4): the `risk-response` policy says
  // which (`xacml/xacml_risk_pep.ts`), each is claimed once for this
  // assessment (`claimAction()`), and each is taken — announced over CAEP
  // in every mode; ending everything, RISC credential-compromise and
  // disabling only where risk decisions are ENFORCED (product, or
  // `risk.enforceInDevelopment`), and recorded as observed otherwise. One
  // audit row says what was decided and what was done. Never rejects.
  // -------------------------------------------------------------------------
  async respond(change: Json): Promise<Json> {
    const { log, store, lazy } = this.deps;
    log.debug("Entering RiskEngine.respond(). " + change.username);
    const sealing = this.sealing();
    let decided: Json = { reactions: [], policy: '', why: '' };
    try {
      decided = lazy('../xacml/xacml_risk_pep').decide({
        username: change.username, level: change.level,
        previousLevel: change.previousLevel, score: change.score,
        signals: change.signals });
    } catch (e) {
      log.debug("Caught in RiskEngine.respond(): " + ((e && e.message) || e));
      // No XACML family in this process: nothing is decided, so nothing is
      // done — the change itself is recorded on the standing.
      decided = { reactions: [], policy: '', why: 'no risk-response PEP' };
    }
    const enforced = this.enforced();
    const taken: string[] = [];
    const observed: string[] = [];
    const failed: string[] = [];
    for (const reaction of decided.reactions) {
      let claimed = false;
      try {
        claimed = await store.claimAction(change.realm, change.subject,
                                          reaction, change.assessmentId,
                                          sealing);
      } catch (e) {
        log.debug("Caught in RiskEngine.respond(): " +
                  ((e && e.message) || e));
        // A claim that could not be made is a reaction not taken: taking it
        // unclaimed could take it twice.
        claimed = false;
      }
      if (!claimed) {
        continue;
      }
      if (reaction !== 'risk-announce' && !enforced) {
        observed.push(reaction);
        bump(tally.reactions.observed, reaction);
        continue;
      }
      try {
        await this.take(reaction, change);
        taken.push(reaction);
        bump(tally.reactions.taken, reaction);
      } catch (e) {
        bump(tally.reactions.failed, reaction);
        log.warn(errorCodes.tag('STS-RISK-0021') + 'risk: the reaction ' +
                 reaction + ' to ' + change.username + '\'s risk going to ' +
                 change.level + ' failed: ' + ((e && e.message) || e));
        failed.push(reaction);
      }
    }
    try {
      lazy('../common/audit').audit({
        action: 'risk.response', actor: 'risk scoring',
        protocol: 'Risk scoring', channel: 'internal',
        target: change.username,
        errorCode: failed.length ? 'STS-RISK-0021'
          : (observed.length ? 'STS-RISK-0019' : undefined),
        summary: change.username + '\'s risk went from ' +
                 (change.previousLevel || 'none') + ' to ' + change.level +
                 (taken.length ? '; taken: ' + taken.join(', ') : '') +
                 (observed.length ? '; observed only: ' +
                                    observed.join(', ') : '') +
                 (failed.length ? '; FAILED: ' + failed.join(', ') : ''),
        detail: { level: change.level, previous: change.previousLevel,
                  signals: (change.signals || []).join(', '),
                  assessment: change.assessmentId,
                  policy: String(decided.policy || ''),
                  permitted: decided.reactions.join(', ') }
      });
    } catch (e) {
      log.debug("Caught in RiskEngine.respond(): " + ((e && e.message) || e));
      // The audit log is not loaded in this process; the log line below is
      // the record.
    }
    log.info('risk: ' + change.username + ' went from ' +
             (change.previousLevel || 'none') + ' to ' + change.level +
             '; the risk-response policy permitted ' +
             (decided.reactions.join(', ') || 'nothing') +
             (observed.length ? ' (observed only: ' + observed.join(', ') +
                                ')' : '') + '.');
    log.debug("Leaving RiskEngine.respond().");
    return { reactions: decided.reactions, taken: taken, observed: observed,
             failed: failed };
  }

  // One reaction, taken. Throws on failure, which respond() records.
  private async take(reaction: string, change: Json): Promise<void> {
    const { log, lazy } = this.deps;
    log.debug("Entering RiskEngine.take(). " + reaction);
    const reason = (change.signals || []).join(', ');
    if (reaction === 'risk-announce') {
      await lazy('../ssf/ssf').riskAutoEmit({ username: change.username,
        sub: change.subject, previous: change.previousLevel,
        current: change.level, reason: reason });
    } else if (reaction === 'risk-end-sessions') {
      // A sign-in's reaction ends only what was held BEFORE it (#226; see
      // noteChange()), and nothing when nothing was — an empty selection
      // is a GLOBAL logout to `terminate()`, which would end exactly the
      // session this is sparing.
      const before = Array.isArray(change.heldBefore)
        ? change.heldBefore : null;
      if (before && !before.length) {
        log.debug("Leaving RiskEngine.take(). Nothing was held before.");
        return;
      }
      const ended = lazy('../common/account_state').endEverything(
        change.username, { actor: 'risk scoring', channel: 'internal',
          selection: before || undefined,
          by: 'the person\'s risk went to ' + change.level +
              (reason ? ' (' + reason + ')' : '') });
      if (ended && ended.ended === false) {
        throw new Error(String(ended.message || 'nothing was ended'));
      }
    } else if (reaction === 'risk-credential-compromise') {
      const signals = lazy('../ssf/account_signals');
      // WHICH CREDENTIAL: the security key where the evidence is its model
      // (#62 P5), the password otherwise.
      const aKey = (change.signals || []).indexOf(
        'authenticator-compromised') >= 0;
      await signals.credentialCompromised({
        username: change.username,
        credentialType: aKey ? signals.KEY_CREDENTIAL_TYPE : 'password',
        initiatingEntity: 'system',
        reasonAdmin: change.username + '\'s risk went to ' + change.level +
                     ' on evidence about their ' +
                     (aKey ? 'security key' : 'password') + ' (' + reason +
                     ').',
        reasonUser: aKey
          ? 'The model of security key you signed in with is reported ' +
            'compromised. Replace it.'
          : 'Your password may be known to somebody else. Change it.' });
    } else if (reaction === 'risk-disable') {
      const done = lazy('../common/account_state').setDisabled(
        change.username, true, { actor: 'risk scoring', via: 'internal',
          door: 'risk scoring', riscReason: 'hijacking',
          by: 'risk scoring disabled the account: its risk went to ' +
              change.level + ' at a score of ' + change.score,
          reason: 'risk ' + change.level + ' (' + reason + ')' });
      if (!done || !done.ok) {
        throw new Error(((done && done.errors) || ['not disabled']).join(' '));
      }
    }
    log.debug("Leaving RiskEngine.take().");
  }

  // -------------------------------------------------------------------------
  // A LIVE SESSION, RE-CHECKED (#62 P4) by the `risk.rescore` job: what can
  // change about a session nobody is using is what the datasets and the
  // failure history say about where it came from — an address that has
  // become a Tor exit, a network the operator has since denied, a password
  // being guessed for this person. The device and the model do not move
  // without a request, and a request is `phase: 'session'`'s business.
  //
  // Only UPWARD: a signal the session did not carry makes it riskier, and a
  // signal it carried that has gone (a list rotated) is not a reason to
  // trust it more than its sign-in did. Answers the session's new risk, or
  // null when nothing new was found.
  // -------------------------------------------------------------------------
  async rescoreSession(realm: string, session: Json): Promise<Json | null> {
    const { log, store, datasets, now, keystore, randomId } = this.deps;
    log.debug("Entering RiskEngine.rescoreSession().");
    const risk = session && session.risk;
    const events = session && Array.isArray(session.events)
      ? session.events : [];
    const last = events.length ? events[events.length - 1] : null;
    const address = last && last.context ? String(last.context.address || '')
                                         : '';
    if (!risk || !address || !session.user || !session.user.sub) {
      log.debug("Leaving RiskEngine.rescoreSession(). Nothing to re-check.");
      return null;
    }
    const sealing = this.sealing();
    const found = await datasets.lookup(address, realm);
    const signals: string[] = [];
    this.countedLists(found, address).forEach(function (l: Json): void {
      signals.push(l.category);
    });
    const since = now() - HOUR_MS;
    const mine = await store.listFailures(realm, { since: since,
      subject: String(session.user.sub), limit: 1 }, sealing);
    if (mine.total >= accountFailureThreshold()) {
      signals.push('account-failures');
    }
    if (found.prefix) {
      const theirs = await store.listFailures(realm, { since: since,
        prefix: found.prefix, limit: 1 }, sealing);
      if (theirs.total >= networkFailureThreshold()) {
        signals.push('network-failures');
      }
    }
    // A key whose MODEL the FIDO metadata has since reported compromised
    // (#62 P5): the session rests on it.
    const aaguid = last.context.credential
      ? String(last.context.credential.aaguid || '') : '';
    const listed = aaguid ? await datasets.lookupAuthenticator(aaguid) : null;
    if (listed && listed.model.compromised) {
      signals.push('authenticator-compromised');
    }
    const held = (risk.signals || []).map(String);
    const factorOf = this.factors().factors;
    const fresh = signals.filter(function (one: string): boolean {
      return held.indexOf(one) < 0 && factorOf[one] > 1;
    });
    if (!fresh.length) {
      log.debug("Leaving RiskEngine.rescoreSession(). Nothing new.");
      return null;
    }
    let score = typeof risk.score === 'number' ? risk.score : 1;
    fresh.forEach(function (one: string): void {
      score *= factorOf[one];
    });
    // The sign-in's known context caps what the session is raised to on
    // address evidence, as it capped the sign-in (#226). The score the
    // session carries already holds its own signals, so the cap is asked
    // about the FRESH ones on top of it.
    const recapped = risk.knownContext
      ? this.capped(score, fresh.map(function (one: string): Json {
        return { signal: one, factor: factorOf[one] };
      })) : null;
    if (recapped) {
      score = recapped.score;
    }
    const level = this.levelOf(score);
    if ((RANK[level] || 0) <= (RANK[String(risk.level)] || 0)) {
      log.debug("Leaving RiskEngine.rescoreSession(). No higher.");
      return null;
    }
    const at = now();
    const subject = String(session.user.sub);
    const assessment: Json = {
      realm: realm, id: randomId(), at: at, phase: 'rescore',
      door: 'the risk.rescore job', subject: subject,
      sessionId: String(session.id || ''), clientId: '',
      addressSealed: sealing
        ? String(keystore().seal(address, 'risk.address') || '') : '',
      addressPrefix: found.prefix || '0.0.0.0/0',
      asn: Number((found.asn || {}).asn) || 0,
      asOrg: String((found.asn || {}).asOrg || ''),
      country: String((found.geo || {}).country || ''),
      ipLists: found.lists.map(function (l: Json): string {
        return l.category;
      }),
      datasets: Object.assign({}, found.datasets,
                              { stale: found.stale,
                                attributions: found.attributions }),
      signals: [{ signal: 'model', score: risk.score, factors: null,
                  why: 'the sign-in\'s score, re-checked' }]
        .concat(held.concat(fresh).map(function (one: string): Json {
          return { signal: one, factor: factorOf[one],
                   what: SIGNALS[one].what,
                   evidence: fresh.indexOf(one) >= 0 ? 'new' : 'held' };
        })),
      score: score, level: level, decision: 'rescore'
    };
    await store.recordAssessment(assessment, sealing);
    const before = await store.subjectOf(realm, subject, sealing);
    await store.upsertSubject({ realm: realm, subject: subject,
      score: score, level: level, reason: held.concat(fresh).join(', '),
      lastAssessment: assessment.id, updatedAt: at }, sealing);
    const username = String(session.user.username || '');
    const next = RiskEngine.riskOf(assessment);
    this.holdStanding(realm, username, next);
    this.noteChange(realm, subject, username,
                    before ? String(before.level || '') : '', assessment);
    log.info('risk: session ' + session.id + ' of ' + username + ' re-checked ' +
             'at ' + level + ' (' + fresh.join(', ') + ').');
    log.debug("Leaving RiskEngine.rescoreSession(). " + level + ".");
    return next;
  }

  // -------------------------------------------------------------------------
  // THE `risk.rescore` JOB (#62 P4): every live session the sign-in service
  // holds, re-checked; a session whose risk rose carries the new risk, so
  // every token on it is decided on it. A cluster job — the sessions are a
  // shared store — run once on the leader.
  // -------------------------------------------------------------------------
  async rescoreLiveSessions(): Promise<Json> {
    const { log, lazy } = this.deps;
    log.debug("Entering RiskEngine.rescoreLiveSessions().");
    const authn = lazy('../authn/authn');
    const realms = lazy('../common/realms');
    const out = { sessions: 0, raised: 0 };
    for (const row of authn.sessionsForRisk()) {
      out.sessions++;
      const self = this;
      const raised = await realms.run(row.realm, function (): Promise<Json> {
        return self.rescoreSession(row.realm.id || '', row.session);
      });
      if (raised) {
        realms.run(row.realm, function (): void {
          authn.adoptSessionRisk(row.id, raised);
        });
        out.raised++;
      }
    }
    tally.rescore.runs++;
    tally.rescore.sessions += out.sessions;
    tally.rescore.raised += out.raised;
    log.debug("Leaving RiskEngine.rescoreLiveSessions(). " + out.raised +
              " raised.");
    return out;
  }

  registerJobs(): boolean {
    const { log, scheduler, config } = this.deps;
    log.debug("Entering RiskEngine.registerJobs().");
    let s: Json = null;
    try {
      s = scheduler();
    } catch (e) {
      log.debug("Caught in RiskEngine.registerJobs(): " +
                ((e && e.message) || e));
      // No scheduler in this process (a test of this file): no job.
      s = null;
    }
    if (!s || typeof s.register !== 'function' || s.job(RESCORE_JOB)) {
      log.debug("Leaving RiskEngine.registerJobs(). Nothing to do.");
      return false;
    }
    const self = this;
    s.register({
      id: RESCORE_JOB,
      title: 'Risk re-check of live sessions',
      describe: 'Re-checks every live sign-on session against the active ' +
                'datasets and the failure history, and raises the risk of ' +
                'one that has become riskier — an address now on a Tor or ' +
                'deny list, a password being guessed — so every token on it ' +
                'is decided on the new risk, and a person crossing into HIGH ' +
                'is answered by the risk-response policy.',
      owner: 'risk/risk_engine.ts',
      kind: 'cluster',
      everySetting: 'risk.rescoreEveryS', everySettingUnit: 's',
      manual: true,
      off: function (): string {
        return config.value('risk.assessSignIns') === false
          ? 'risk.assessSignIns is off' : '';
      },
      run: function (): Promise<Json> {
        return self.rescoreLiveSessions();
      }
    });
    log.debug("Leaving RiskEngine.registerJobs().");
    return true;
  }

  // -------------------------------------------------------------------------
  // WHAT THE PERSON SAID ABOUT ONE OF THEIR OWN SIGN-INS (#62 P6), from
  // /portal/sign-ins. `input`: realm, subject, username, assessmentId,
  // verdict (`confirmed` | `denied`), and the session it was said FROM with
  // that session's level. Answered once per assessment.
  //
  // **"THIS WASN'T ME" is taken at its word**: the person's standing goes to
  // HIGH, `reported-not-me`, and the change is answered by the risk-response
  // policy like any other — everything they hold ended, RISC told the
  // credential is compromised. Anybody who can sign in as the person can say
  // it, and the worst it does is sign the person out and ask them to change
  // a password, which is the right answer to anybody holding it.
  //
  // **"THIS WAS ME" only vouches from somewhere trusted**: it lowers the
  // standing to LOW only when said from a DIFFERENT session that is itself
  // LOW (or unscored) — a hijacked session confirming its own sign-in would
  // otherwise talk its way back to LOW. Said from the flagged session, it is
  // recorded, for calibration, and moves nothing.
  // -------------------------------------------------------------------------
  async feedback(input: Json): Promise<Json> {
    const { log, store, now } = this.deps;
    log.debug("Entering RiskEngine.feedback(). " + input.verdict);
    const realm = String(input.realm || '');
    const subject = String(input.subject || '');
    const verdict = input.verdict === 'denied' ? 'denied' : 'confirmed';
    const sealing = this.sealing();
    const at = now();
    const held = await store.listAssessments(realm, { since: 0,
      subject: subject, limit: 500 }, sealing);
    const row = held.rows.filter(function (a: Json): boolean {
      return a.id === input.assessmentId;
    })[0];
    if (!row) {
      log.debug("Leaving RiskEngine.feedback(). Not theirs.");
      return { ok: false, why: 'That sign-in is not one of yours, or it is ' +
               'too old to answer.' };
    }
    const recorded = await store.setFeedback(realm, row.id, subject, verdict,
                                             at, sealing);
    if (!recorded) {
      log.debug("Leaving RiskEngine.feedback(). Already answered.");
      return { ok: false, why: 'That sign-in has already been answered.' };
    }
    const before = await store.subjectOf(realm, subject, sealing);
    let moved = '';
    if (verdict === 'denied') {
      const high = Number(this.deps.config.value('risk.highScorePercent')) /
                   100;
      const score = Math.max(high, before ? Number(before.score) || 0 : 0);
      await store.upsertSubject({ realm: realm, subject: subject,
        score: score, level: 'HIGH', reason: 'reported-not-me',
        lastAssessment: row.id, updatedAt: at }, sealing);
      this.holdStanding(realm, String(input.username || ''),
        { level: 'HIGH', score: score, signals: ['reported-not-me'],
          assessmentId: row.id, at: at });
      this.noteChange(realm, subject, String(input.username || ''),
        before ? String(before.level || '') : '',
        { id: 'feedback:' + row.id, level: 'HIGH', score: score,
          signals: [{ signal: 'reported-not-me' }], at: at });
      moved = 'HIGH';
    } else if (String(input.fromSessionId || '') !== String(row.sessionId ||
               '') && ['LOW', 'UNSCORED', ''].indexOf(
                 String(input.fromSessionLevel || '')) >= 0 && before &&
               (before.level === 'MEDIUM' || before.level === 'HIGH')) {
      await store.upsertSubject({ realm: realm, subject: subject,
        score: Math.min(Number(before.score) || 0, 0.5), level: 'LOW',
        reason: 'confirmed by the person', lastAssessment: row.id,
        updatedAt: at }, sealing);
      this.holdStanding(realm, String(input.username || ''),
        { level: 'LOW', score: 0.5, signals: [], assessmentId: row.id,
          at: at });
      this.noteChange(realm, subject, String(input.username || ''),
        String(before.level), { id: 'feedback:' + row.id, level: 'LOW',
                                score: 0.5, signals: [], at: at });
      moved = 'LOW';
    }
    try {
      this.deps.lazy('../common/audit').audit({
        action: 'risk.feedback', actor: String(input.username || subject),
        protocol: 'Risk scoring', channel: 'http', target: row.id,
        summary: String(input.username || subject) + ' said a sign-in (' +
                 row.level + ', ' + String(row.door || '') + ') ' +
                 (verdict === 'denied' ? 'WAS NOT them' : 'was them') +
                 (moved ? '; their standing is now ' + moved : ''),
        detail: { assessment: row.id, verdict: verdict,
                  level: String(row.level || ''), moved: moved } });
    } catch (e) {
      log.debug("Caught in RiskEngine.feedback(): " + ((e && e.message) ||
                                                        e));
      // No audit log in this process; the log line below is the record.
    }
    log.info('risk: ' + String(input.username || subject) + ' said sign-in ' +
             row.id + ' ' + (verdict === 'denied' ? 'was NOT them' :
                             'was them') + (moved ? '; standing ' + moved :
                                            '') + '.');
    log.debug("Leaving RiskEngine.feedback().");
    return { ok: true, verdict: verdict, moved: moved };
  }

  // -------------------------------------------------------------------------
  // EVERY SIGNAL'S FACTOR, as scored now: SIGNALS' own, with the realm's
  // `risk.signalFactors` over them. `invalid` names the entries ignored.
  // -------------------------------------------------------------------------
  factors(): Json {
    const { log, config } = this.deps;
    log.debug("Entering RiskEngine.factors().");
    const listed = config.value('risk.signalFactors') || [];
    const raw = (Array.isArray(listed) ? listed : [listed]).join(',');
    const held = parsedFactors.get(raw);
    if (held) {
      log.debug("Leaving RiskEngine.factors(). Held.");
      return held;
    }
    const map: Record<string, number> = {};
    Object.keys(SIGNALS).forEach(function (id: string): void {
      map[id] = SIGNALS[id].factor;
    });
    const set: Record<string, number> = {};
    const invalid: string[] = [];
    (Array.isArray(listed) ? listed : [listed]).forEach(function (one) {
      const text = String(one || '').trim();
      if (!text) {
        return;
      }
      const at = text.indexOf('=');
      const id = at > 0 ? text.slice(0, at).trim() : '';
      const value = at > 0 ? Number(text.slice(at + 1).trim()) : NaN;
      if (!SIGNALS[id] || !isFinite(value) || value <= 0) {
        invalid.push(text);
        return;
      }
      map[id] = value;
      set[id] = value;
    });
    if (invalid.length) {
      log.warn(errorCodes.tag('STS-RISK-0026') + 'risk: risk.signalFactors ' +
               'entries ignored, each needing a known signal and a positive ' +
               'factor: ' + invalid.join(', ') + '.');
    }
    const answer = { factors: map, set: set, invalid: invalid };
    if (parsedFactors.size > 64) {
      // Bounded: one entry per distinct value a realm has been given.
      parsedFactors.clear();
    }
    parsedFactors.set(raw, answer);
    log.debug("Leaving RiskEngine.factors().");
    return answer;
  }

  // -------------------------------------------------------------------------
  // THE CALIBRATION REPORT (#62; rcbj: "calibrate the factors"). Advice, from
  // the window's assessments, and never applied by itself:
  //
  //   * THRESHOLDS: the score at which the target share of sign-ins
  //     (`risk.calibrationMediumPercent`, `risk.calibrationHighPercent`)
  //     would be MEDIUM or worse and HIGH — the window's own quantiles.
  //   * FACTORS: for each signal, how often a sign-in carrying it was
  //     answered "not me" on /portal/sign-ins against how often any answered
  //     sign-in was. The suggested factor is the current one scaled by that
  //     ratio, bounded to [0.1, 100]. The answers are a biased sample — a
  //     flagged sign-in is likelier to be asked about — which is why this is
  //     advice and the page says so.
  // -------------------------------------------------------------------------
  static calibrate(counted: Json, thresholds: Json, targets: Json,
                   factors: Json): Json {
    log.debug("Entering RiskEngine.calibrate().");
    const total = Number(counted.total) || 0;
    const shareAtOrAbove = function (levels: string[]): number {
      return total ? levels.reduce(function (s: number, l: string): number {
        return s + (Number(counted.byLevel[l]) || 0);
      }, 0) / total : 0;
    };
    const q = counted.scoreQuantiles || {};
    const enough = total >= MIN_ASSESSMENTS_FOR_THRESHOLDS;
    const answered = (Number(counted.feedback.denied) || 0) +
                     (Number(counted.feedback.confirmed) || 0);
    const baseline = answered
      ? (Number(counted.feedback.denied) || 0) / answered : 0;
    // `reported-not-me` IS the answer rather than evidence for one, so it
    // has nothing to be calibrated against.
    const signals = Object.keys(factors.factors).filter(function (id) {
      return id !== 'reported-not-me';
    }).map(function (id: string) {
      const fb = (counted.bySignalFeedback || {})[id] || {};
      const denied = Number(fb.denied) || 0;
      const confirmed = Number(fb.confirmed) || 0;
      const levels = (counted.bySignalLevel || {})[id] || {};
      const fired = Number((counted.bySignal || {})[id]) || 0;
      const current = factors.factors[id];
      let suggested: number | null = null;
      let advice = 'not enough answers (' + (denied + confirmed) + ' of ' +
                   MIN_ANSWERS_PER_SIGNAL + ')';
      if (denied + confirmed >= MIN_ANSWERS_PER_SIGNAL && baseline > 0) {
        const lift = (denied / (denied + confirmed)) / baseline;
        const raw = Math.min(100, Math.max(0.1, current * lift));
        suggested = Number(raw.toPrecision(2));
        advice = suggested > current * 1.25 ? 'raise'
          : (suggested < current / 1.25 ? 'lower' : 'keep');
      } else if (denied + confirmed >= MIN_ANSWERS_PER_SIGNAL) {
        advice = 'nobody has answered "not me" yet: no baseline';
      }
      return { signal: id, factor: current, builtIn: SIGNALS[id].factor,
               fired: fired,
               high: Number(levels.HIGH) || 0,
               answered: denied + confirmed, notMe: denied,
               suggested: suggested, advice: advice };
    });
    log.debug("Leaving RiskEngine.calibrate().");
    return {
      assessments: total, answered: answered, notMeRate: baseline,
      minimums: { assessments: MIN_ASSESSMENTS_FOR_THRESHOLDS,
                  answersPerSignal: MIN_ANSWERS_PER_SIGNAL },
      thresholds: {
        medium: { current: thresholds.medium,
                  share: shareAtOrAbove(['MEDIUM', 'HIGH']),
                  target: targets.medium,
                  suggested: enough && q[String(1 - targets.medium)] !==
                    undefined ? q[String(1 - targets.medium)] : null },
        high: { current: thresholds.high, share: shareAtOrAbove(['HIGH']),
                target: targets.high,
                suggested: enough && q[String(1 - targets.high)] !==
                  undefined ? q[String(1 - targets.high)] : null }
      },
      signals: signals,
      invalidFactors: factors.invalid
    };
  }

  // -------------------------------------------------------------------------
  // THE SCORING SYSTEM, MEASURED (#62): what Monitoring → Risk Scoring draws
  // and `GET /admin-api/risk/metrics` returns. Two kinds of number, and the
  // answer keeps them apart: `assessments` and `standings` are counted in
  // the STORE over the window (the whole service, on postgres), `process`
  // is THIS process since it started. `signals` is the table with each
  // signal's factor beside how often it fired, which is what calibrating a
  // factor starts from.
  // -------------------------------------------------------------------------
  async metrics(realm: string, windowMs: number): Promise<Json> {
    const { log, store, config, now, lazy } = this.deps;
    log.debug("Entering RiskEngine.metrics().");
    const sealing = this.sealing();
    const span = Math.max(3600000, Number(windowMs) || 86400000);
    // A bar per five minutes for an hour, per hour for up to two days, and
    // per day beyond: between twelve and sixty bars on every window offered.
    const bucketMs = span <= 3600000 ? 300000
      : (span <= 2 * 86400000 ? 3600000 : 86400000);
    const since = now() - span;
    const targets = {
      medium: Number(config.value('risk.calibrationMediumPercent')) / 100,
      high: Number(config.value('risk.calibrationHighPercent')) / 100 };
    const counted = await store.assessmentMetrics(realm, {
      since: since, bucketMs: bucketMs,
      quantiles: [1 - targets.medium, 1 - targets.high] }, sealing);
    const factors = this.factors();
    const standings = await store.subjectLevels(realm, sealing);
    const sorted = tally.durations.slice().sort(function (a: number,
                                                          b: number): number {
      return a - b;
    });
    let breach: Json = null;
    try {
      breach = lazy('../common/breached_passwords').metrics();
    } catch (e) {
      log.debug("Caught in RiskEngine.metrics(): " + ((e && e.message) || e));
      // Not loaded in this process: the page says so rather than a zero.
      breach = null;
    }
    const signals = Object.keys(SIGNALS).map(function (id: string): Json {
      return { signal: id, factor: factors.factors[id],
               builtIn: SIGNALS[id].factor, what: SIGNALS[id].what,
               fired: Number(counted.bySignal[id]) || 0 };
    });
    const thresholds = {
      medium: Number(config.value('risk.mediumScorePercent')) / 100,
      high: Number(config.value('risk.highScorePercent')) / 100 };
    log.debug("Leaving RiskEngine.metrics().");
    return {
      realm: realm, windowMs: span, since: since, bucketMs: bucketMs,
      database: store.failuresInDatabase(sealing),
      enforced: this.enforced(),
      thresholds: thresholds,
      assessments: counted,
      calibration: RiskEngine.calibrate(counted, thresholds, targets,
                                        factors),
      standings: standings,
      signals: signals,
      process: {
        since: tally.since, assessed: tally.assessed, failed: tally.failed,
        durationMs: {
          samples: sorted.length,
          mean: sorted.length ? sorted.reduce(function (a: number,
                                                        b: number): number {
            return a + b;
          }, 0) / sorted.length : 0,
          p50: percentile(sorted, 0.5), p95: percentile(sorted, 0.95),
          p99: percentile(sorted, 0.99),
          max: sorted.length ? sorted[sorted.length - 1] : 0 },
        reactions: JSON.parse(JSON.stringify(tally.reactions)),
        rescore: Object.assign({}, tally.rescore),
        breachedPasswords: breach
      }
    };
  }

  // -------------------------------------------------------------------------
  // ONE PERSON'S CURRENT STANDING, from the store (#62): what the console's
  // user page draws large and `/admin-api/users?user=` returns. Null for a
  // person never assessed. Never rejects.
  // -------------------------------------------------------------------------
  async standingFor(realm: string, subject: string): Promise<Json | null> {
    const { log, store } = this.deps;
    log.debug("Entering RiskEngine.standingFor().");
    try {
      const row = subject ? await store.subjectOf(realm, subject,
                                                  this.sealing()) : null;
      log.debug("Leaving RiskEngine.standingFor(). " +
                (row ? row.level : 'None.'));
      return row ? { subject: subject, level: String(row.level || ''),
                     score: Number(row.score) || 0,
                     previousLevel: String(row.previousLevel || ''),
                     reason: String(row.reason || ''),
                     lastAssessment: String(row.lastAssessment || ''),
                     crossedAt: Number(row.crossedAt) || 0,
                     updatedAt: Number(row.updatedAt) || 0 } : null;
    } catch (e) {
      log.debug("Caught in RiskEngine.standingFor(): " +
                ((e && e.message) || e));
      // The store could not answer: the page says the risk is unknown.
      log.debug("Leaving RiskEngine.standingFor(). Unknown.");
      return null;
    }
  }

  // A page of assessments and the people by standing, for the page.
  async view(realm: string, opts: Json): Promise<Json> {
    const { log, store, now } = this.deps;
    log.debug("Entering RiskEngine.view().");
    const sealing = this.sealing();
    const o = opts || {};
    // `subject` and `days` for one person's own page (#62 P6).
    const assessments = await store.listAssessments(realm, {
      since: now() - (Number(o.days) || 7) * 86400000, level: o.level || '',
      subject: String(o.subject || ''),
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
  function (instance: RiskEngine): void {
    // The re-check job (#62 P4), registered when the instance is wired —
    // the datasets' two are registered the same way.
    instance.registerJobs();
  },
  log);

slot.buildNowUnlessDeferred();

export = {
  RiskEngine: RiskEngine,
  installInstance: (instance: RiskEngine): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  SIGNALS: RiskEngine.SIGNALS,
  deviceOf: RiskEngine.deviceOf,
  satisfiedBy: RiskEngine.satisfiedBy,
  familyOf: RiskEngine.familyOf,
  riskOf: RiskEngine.riskOf,
  assess: slot.forward('assess'),
  factsOf: slot.forward('factsOf'),
  factsForIssuance: slot.forward('factsForIssuance'),
  standingOf: slot.forward('standingOf'),
  loadStanding: slot.forward('loadStanding'),
  settle: slot.forward('settle'),
  respond: slot.forward('respond'),
  feedback: slot.forward('feedback'),
  metrics: slot.forward('metrics'),
  factors: slot.forward('factors'),
  calibrate: RiskEngine.calibrate,
  standingFor: slot.forward('standingFor'),
  rescoreSession: slot.forward('rescoreSession'),
  rescoreLiveSessions: slot.forward('rescoreLiveSessions'),
  enforced: slot.forward('enforced'),
  view: slot.forward('view'),
  purge: slot.forward('purge')
};
