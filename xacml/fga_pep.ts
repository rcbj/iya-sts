// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: fga_pep.ts
//
// ===========================================================================
// THE EMBEDDED FINE-GRAINED AUTHORIZATION PEP (#564, phase P3): one RFC 9396
// authorization detail, asked of the policy of the application that owns its
// type, and enforced deny-biased.
//
// `common/fga_gate.ts` is where an issuance site asks; this module is what
// answers it, installed into that gate's slot when it is wired at 23c (rule
// 3e — the gate's header argues why it is a slot both ways round). It puts
// together the three pieces the earlier phases built:
//
//   1. `fga_policies.resolve()` (P1): the application's own policy, parsed,
//      or a precise failure — no reference (0003), not in ou=policies (0004),
//      not its own or orphaned (0005), disabled (0006), not parseable (0007),
//      no such application (0009). Each is an OPERATIONAL FAILURE: the
//      application enforces, and there is nothing to decide with.
//   2. `fga_map.request()` (P2): the detail as an XACML request, with the
//      facts the adapter knows written as trusted attributes. A detail the
//      mapping refuses (0100–0107) is a DENIAL — it cannot be put to the
//      policy, so it is not granted — never an attribute and never a fault.
//   3. `xacml.ts`'s `decidePolicy()`: evaluated against THAT POLICY ALONE —
//      not the realm root, and with no PolicyIdReference map, because an
//      owned policy's PolicyId is chosen by whoever named the application
//      and the store keeps owned policies out of the map for that reason.
//
// **ONLY A PERMIT WITH NOTHING UNDISCHARGEABLE IS YES** — `enforce()`'s
// deny-biased reading, as AuthZEN's endpoint reads it. Deny, NotApplicable
// and an Indeterminate over a missing attribute are DENIALS (STS-FGA-0014):
// the policy answered, and the answer was not Permit. An Indeterminate the
// engine reached through a processing or syntax error (`decidePolicy()`
// marks it STS-XACML-0013) is a FAULT (STS-FGA-0015): nobody decided, and a
// client told `invalid_authorization_details` would believe the detail
// itself was wrong.
//
// THE PIP is asked only for a PERSON: the subject of a client credentials
// grant, or the client at PAR before anybody signed in, is not a directory
// entry, and AuthZEN's `resolves()` draws the same line.
//
// ---------------------------------------------------------------------------
// ONE AUDIT ROW PER DECISION, `fga.decision`: the application, the policy's
// entry name, PolicyId and version, the detail's type and the definition's
// digest, the subject and its kind, the client, the stage and the grant, the
// outcome with its XACML decision and code — and a SHA-256 of the detail's
// canonical JSON, NEVER ITS VALUES. A detail is a statement about one
// transaction — this payment, this amount, this account — and the audit log
// is read by people who were never meant to see it; the digest is enough to
// tell two decisions about the same detail apart, which is what an
// investigation needs.
//
// ONE MONITOR ROW, `fga`, per decision the PDP reached: counted as a decision
// AND an enforcement, because this process enforces it — the issuance and
// access PEPs' case, not the PDP endpoint's. A resolve failure or a refused
// mapping reached no PDP, so it is audited and not counted: the monitor's
// reconciliation (allowed + refused + unenforced = decisions) is about
// decisions the engine made.
//
// AND SINCE P4 THE ACCESS-TIME QUESTION, `decideAccess()`: an AuthZEN
// evaluation about an application that enforces FGA, decided against that
// application's policy by the same first step and the same `decidePolicy()`
// — AuthZEN's request, AuthZEN's result rules, AuthZEN's audit row and
// monitor row (the method's comment argues each).
//
// Not by mode: nothing here differs between development and product.
// ===========================================================================

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import model = require('./xacml_model');

const { log } = helpers;

// One question, as `common/fga_gate.ts` hands it over.
interface FgaQuestion {
  application: string;
  detail: any;
  definition: any;
  stage: string;
  realm?: string;
  clientId?: string;
  subject?: { id?: string; kind?: string };
  grantType?: string;
}

// The answer the gate expects.
interface FgaAnswer {
  outcome: 'permit' | 'deny' | 'failure';
  code: string;
  why: string;
  policy?: string;
  policyId?: string;
  version?: string;
  decision?: string;
  digest?: string;
}

// The application's policy, as both questions' first step finds it.
interface PolicyFound {
  ok: boolean;
  code: string;
  why: string;
  policy: string;
  parsed?: any;
  policyId?: string;
  version?: string;
}

// What `decideAccess()` answers AuthZEN.
interface AccessAnswer {
  ok: boolean;
  code: string;
  why: string;
  policy: string;
  answer?: any;
  policyId?: string;
  version?: string;
}

interface FgaPepDeps {
  log: { debug(message: string): void; warn(message: string): void;
         error(message: string): void };
  errorCodes: { tag(code: string): string; codeOf(target: any): any };
  audit: { audit(row: Record<string, unknown>): unknown };
  policies: { resolve(identifier: string): any };
  map: { request(detail: unknown, definition: any, trusted: any): any;
         digest(definition: any): string };
  gate: { setDecider(fn: ((question: FgaQuestion) => FgaAnswer) | null):
            boolean };
  sha256Hex(text: string): string;
  // Lazily, for the reasons the header gives: the surface and the monitor
  // are the XACML family's, and a test that loads this module alone must
  // not load the console through them.
  loadXacml(): { decidePolicy(policy: any, request: any, options?: any): any;
                 enforce(answer: any, bias?: string): any };
  loadMonitor(): { record(id: string, outcome?: any): void };
}

/**
 * The embedded FGA PEP: an authorization detail decided by its owning
 * application's policy alone, deny-biased, audited, counted.
 */
class FgaPep {
  /**
   * Builds the PEP over its dependencies.
   *
   * @param deps - the logger, error codes, audit log, the lifecycle
   *   (`resolve`), the mapping, the gate, a SHA-256 and the two lazy loaders
   */
  constructor(private readonly deps: FgaPepDeps) {
    deps.log.debug("Entering FgaPep.constructor().");
    deps.log.debug("Leaving FgaPep.constructor().");
  }

  /**
   * The dependencies built from the real modules.
   *
   * @returns the dependencies
   */
  static defaultDeps(): FgaPepDeps {
    log.debug("Entering FgaPep.defaultDeps().");
    const crypto: typeof import('../common/crypto') =
      require('../common/crypto');
    log.debug("Leaving FgaPep.defaultDeps().");
    return {
      log: log,
      errorCodes: require('../common/error_codes'),
      audit: require('../common/audit'),
      policies: require('./fga_policies'),
      map: require('./fga_map'),
      gate: require('../common/fga_gate'),
      sha256Hex: function (text: string): string {
        return crypto.digest('sha256', text, 'hex');
      },
      loadXacml: function (): any {
        log.debug("Entering loadXacml().");
        log.debug("Leaving loadXacml().");
        return require('./xacml');
      },
      loadMonitor: function (): any {
        log.debug("Entering loadMonitor().");
        log.debug("Leaving loadMonitor().");
        return require('./xacml_monitor');
      }
    };
  }

  /**
   * A value with every object's members in sorted order, so two details
   * that differ only in member order digest alike.
   *
   * @param value - any JSON value
   * @returns the same value, canonically ordered
   */
  static canonical(value: any): any {
    log.debug("Entering FgaPep.canonical().");
    if (Array.isArray(value)) {
      log.debug("Leaving FgaPep.canonical(). An array.");
      return value.map(FgaPep.canonical);
    }
    if (value && typeof value === 'object') {
      const out: any = {};
      Object.keys(value).sort().forEach(function (key) {
        out[key] = FgaPep.canonical(value[key]);
      });
      log.debug("Leaving FgaPep.canonical(). An object.");
      return out;
    }
    log.debug("Leaving FgaPep.canonical().");
    return value;
  }

  /**
   * The SHA-256, lowercase hex, of a detail's canonical JSON: what the audit
   * row carries in place of the detail.
   *
   * @param detail - the detail
   * @returns the digest
   */
  detailDigest(detail: unknown): string {
    const { log, sha256Hex } = this.deps;
    log.debug("Entering FgaPep.detailDigest().");
    const out = sha256Hex(JSON.stringify(FgaPep.canonical(detail)));
    log.debug("Leaving FgaPep.detailDigest().");
    return out;
  }

  // THE AUDIT ROW (the header): facts and digests, never a detail value.
  private recordDecision(asked: FgaQuestion, answer: FgaAnswer,
                         definitionDigest: string): void {
    const { log, audit } = this.deps;
    log.debug("Entering FgaPep.recordDecision(). " + answer.outcome);
    const subject = asked.subject || {};
    const type = String((asked.definition && asked.definition.type) ||
                        (asked.detail && asked.detail.type) || '');
    audit.audit({
      action: 'fga.decision',
      outcome: answer.outcome === 'permit' ? 'success'
        : (answer.outcome === 'deny' ? 'refused' : 'error'),
      errorCode: answer.code || undefined,
      actor: String(subject.id || asked.clientId || ''),
      target: String(asked.application || ''),
      protocol: 'OAuth 2.0',
      channel: 'internal',
      summary: 'Fine-grained authorization ' +
        (answer.outcome === 'permit' ? 'granted'
          : (answer.outcome === 'deny' ? 'refused' : 'could not decide')) +
        ' an authorization detail of type "' + type.slice(0, 200) +
        '" for the application "' + String(asked.application || '') +
        '" at stage ' + String(asked.stage || '') +
        (answer.policy ? ', policy "' + answer.policy + '"' : '') +
        (answer.decision ? ' (XACML ' + answer.decision + ')' : '') + '.',
      detail: {
        application: String(asked.application || ''),
        policy: answer.policy || '',
        policyId: answer.policyId || '',
        policyVersion: answer.version || '',
        type: type,
        definitionDigest: definitionDigest,
        subject: String(subject.id || ''),
        subjectKind: String(subject.kind || ''),
        client: String(asked.clientId || ''),
        stage: String(asked.stage || ''),
        grantType: String(asked.grantType || ''),
        outcome: answer.outcome,
        decision: answer.decision || '',
        code: answer.code || '',
        detailDigest: answer.digest || ''
      }
    });
    log.debug("Leaving FgaPep.recordDecision().");
  }

  // Counts a decision the PDP reached; never throws (the monitor's own
  // record() swallows, and a monitor that cannot be loaded is logged).
  private count(decision: string, allowed: boolean,
                undischargeable: boolean): void {
    const { log } = this.deps;
    log.debug("Entering FgaPep.count().");
    try {
      this.deps.loadMonitor().record('fga', {
        decision: decision, allowed: allowed,
        undischargeable: undischargeable });
    } catch (e) {
      log.debug("Caught in FgaPep.count(): " + ((e && e.message) || e));
      // A counter is never the reason a decision fails (`xacml_monitor.ts`'s
      // record() argues it); logged under the monitor's own code.
      log.warn(this.deps.errorCodes.tag('STS-XACML-0062') + 'fga_pep: the ' +
               'decision counter could not be reached: ' +
               ((e && e.message) || e));
    }
    log.debug("Leaving FgaPep.count().");
  }

  /**
   * Decides one authorization detail against its owning application's
   * policy, and audits the decision.
   *
   * @param question - the application, the detail, its `declaredTypes()`
   *   entry, the stage, and the realm, client, subject and grant
   * @returns `{ outcome, code, why, policy, policyId, version, decision,
   *   digest }`: `permit`; `deny` (STS-FGA-0014, or the mapping's
   *   0100–0107); `failure` (the resolve failure's code, or STS-FGA-0015)
   */
  decide(question: FgaQuestion): FgaAnswer {
    const { log, errorCodes, map } = this.deps;
    const asked: FgaQuestion = question || ({} as FgaQuestion);
    const application = String(asked.application || '');
    log.debug("Entering FgaPep.decide(). application=" + application +
              ", stage=" + asked.stage);
    const digest = this.detailDigest(asked.detail);
    let definitionDigest = '';
    let answer: FgaAnswer;
    try {
      definitionDigest = asked.definition ? map.digest(asked.definition) : '';
      answer = this.evaluate(asked, digest, definitionDigest);
    } catch (e) {
      log.debug("Caught in FgaPep.decide(): " + ((e && e.message) || e));
      // A FAULT, AND IT REFUSES: audited here so the row exists, which a
      // throw out to the gate would not leave.
      log.error(errorCodes.tag('STS-FGA-0015') + 'fga_pep: deciding a ' +
                'detail of "' + application + '" threw: ' +
                ((e && e.stack) || e));
      answer = { outcome: 'failure', code: 'STS-FGA-0015', digest: digest,
                 why: 'The fine-grained authorization decision could not be ' +
                      'made: ' + ((e && e.message) || e) };
    }
    this.recordDecision(asked, answer, definitionDigest);
    log.debug("Leaving FgaPep.decide(). " + answer.outcome +
              (answer.code ? ' ' + answer.code : ''));
    return answer;
  }

  // STEP 1, SHARED BY BOTH QUESTIONS: the application's policy, parsed, or
  // the resolve failure under its own code (0003–0007, 0009). Logged here,
  // once, whichever question asked.
  private policyOf(application: string): PolicyFound {
    const { log, errorCodes, policies } = this.deps;
    log.debug("Entering FgaPep.policyOf(). " + application);
    const resolved = policies.resolve(application);
    if (!resolved || !resolved.ok) {
      const code = String(errorCodes.codeOf(resolved) || 'STS-FGA-0015');
      log.warn(errorCodes.tag(code) + 'fga_pep: "' + application +
               '" enforces fine-grained authorization and its policy cannot ' +
               'be used: ' + ((resolved && resolved.why) || 'no answer') +
               ' The question is refused.');
      log.debug("Leaving FgaPep.policyOf(). Not resolved: " + code);
      return { ok: false, code: code,
               policy: String((resolved && resolved.row &&
                               resolved.row.name) || ''),
               why: 'The fine-grained authorization policy of "' +
                    application + '" cannot be used (' + code + ').' };
    }
    const row = resolved.row || {};
    log.debug("Leaving FgaPep.policyOf().");
    return { ok: true, code: '', why: '', parsed: resolved.parsed,
             policy: String(resolved.policy || row.name || ''),
             policyId: String(row.id || ''),
             version: String(row.version || '') };
  }

  // The three steps of the header, each failure under its own code.
  private evaluate(asked: FgaQuestion, digest: string,
                   definitionDigest: string): FgaAnswer {
    const { log, errorCodes, map } = this.deps;
    log.debug("Entering FgaPep.evaluate().");
    const application = String(asked.application || '');
    const found = this.policyOf(application);
    if (!found.ok) {
      log.debug("Leaving FgaPep.evaluate(). Not resolved: " + found.code);
      return { outcome: 'failure', code: found.code, digest: digest,
               policy: found.policy, why: found.why };
    }
    const resolved = { parsed: found.parsed };
    const known = { policy: found.policy, policyId: found.policyId || '',
                    version: found.version || '', digest: digest };
    const subject = asked.subject || {};
    const built = map.request(asked.detail, asked.definition, {
      realm: asked.realm, protocol: 'oauth2',
      subject: { id: subject.id, kind: subject.kind },
      clientId: asked.clientId, application: application,
      stage: asked.stage, grantType: asked.grantType,
      definitionDigest: definitionDigest || undefined });
    if (built.refusal) {
      log.debug("Leaving FgaPep.evaluate(). The mapping refused: " +
                built.refusal.code);
      return Object.assign({ outcome: 'deny' as const,
        code: String(built.refusal.code || 'STS-FGA-0103'),
        why: 'The authorization detail cannot be put to the fine-grained ' +
             'policy of "' + application + '": ' + built.refusal.message },
        known);
    }
    const xacml = this.deps.loadXacml();
    const decided = xacml.decidePolicy(resolved.parsed, built.request, {
      repository: null, resolve: String(subject.kind || '') === 'user' });
    const enforcement = xacml.enforce(decided, 'deny-biased');
    const decision = String((decided && decided.decision) || '');
    this.count(decision, !!enforcement.allowed,
               (enforcement.undischargeable || []).length > 0);
    const fault = String(errorCodes.codeOf(decided) || '') ===
                  'STS-XACML-0013' ||
      (decision === model.DECISION.INDETERMINATE && decided.status &&
       (decided.status.code === model.STATUS.PROCESSING_ERROR ||
        decided.status.code === model.STATUS.SYNTAX_ERROR));
    if (fault) {
      log.error(errorCodes.tag('STS-FGA-0015') + 'fga_pep: the fine-grained ' +
                'policy "' + known.policy + '" of "' + application + '" ' +
                'could not be evaluated: ' +
                String((decided.status && decided.status.message) || ''));
      log.debug("Leaving FgaPep.evaluate(). A fault.");
      return Object.assign({ outcome: 'failure' as const,
        code: 'STS-FGA-0015', decision: decision,
        why: 'The fine-grained authorization policy of "' + application +
             '" could not be evaluated.' }, known);
    }
    if (!enforcement.allowed) {
      log.debug("Leaving FgaPep.evaluate(). Refused: " + decision);
      return Object.assign({ outcome: 'deny' as const, code: 'STS-FGA-0014',
        decision: decision,
        why: 'The fine-grained authorization policy of "' + application +
             '" does not grant this authorization detail of type "' +
             String((asked.definition && asked.definition.type) || '')
               .slice(0, 200) + '" (' + enforcement.why + ')' }, known);
    }
    log.debug("Leaving FgaPep.evaluate(). Permit.");
    return Object.assign({ outcome: 'permit' as const, code: '',
      decision: decision, why: 'The fine-grained authorization policy of "' +
      application + '" permits it.' }, known);
  }

  // -------------------------------------------------------------------------
  // THE ACCESS-TIME QUESTION (#564, P4; rcbj's decision 4): an AuthZEN
  // evaluation whose application enforces fine-grained authorization is
  // decided against THAT application's policy instead of the realm root.
  // The same first step as an issuance question (`policyOf()`), and the
  // same `decidePolicy()` with NO PolicyIdReference map — so the two
  // questions cannot come to differ about which policy is the application's
  // or how it is evaluated. What differs is everything AuthZEN already owns:
  //
  //   * the REQUEST is AuthZEN's (`authzen_map.ts` and the builder's
  //     `fgaAccess()`), built by the caller and passed in; a detail is not
  //     involved, so `fga_map.ts` is not either;
  //   * the RESULT is the PDP's answer, unenforced: AuthZEN reads it through
  //     its own decision 8 (`outcome()`), which already tells a fault from a
  //     denial by STS-XACML-0013, the mark `decidePolicy()` puts on it;
  //   * the AUDIT ROW and the MONITOR COUNT are AuthZEN's `authzen.decision`
  //     and `authzen` row: the PEP that enforces this answer is the caller's,
  //     in its own process, so counting it here on `fga` — a row that
  //     counts enforcements — would claim an enforcement nobody here made,
  //     and counting it on both would count one decision twice.
  //
  // It never throws: a throw is a failure under STS-FGA-0015, as at
  // issuance.
  // -------------------------------------------------------------------------
  /**
   * Decides an AuthZEN request against an application's own fine-grained
   * policy alone.
   *
   * @param application - the application the caller is asking about
   * @param request - AuthZEN's request, in `xacml_model.js`'s shape, with
   *   `fgaAccess()`'s two facts
   * @param options - `resolve`: false decides with no PIP (AuthZEN's
   *   `resolveSubjectTypes` line)
   * @returns `{ ok: true, answer, policy, policyId, version }`, the answer
   *   the PDP's (an Indeterminate through a fault marked STS-XACML-0013); or
   *   `{ ok: false, code, why, policy }` — the resolve failure's code, or
   *   STS-FGA-0015 for a throw
   */
  decideAccess(application: string, request: any,
               options?: { resolve?: boolean }): AccessAnswer {
    const { log, errorCodes } = this.deps;
    const named = String(application || '');
    log.debug("Entering FgaPep.decideAccess(). application=" + named);
    try {
      const found = this.policyOf(named);
      if (!found.ok) {
        log.debug("Leaving FgaPep.decideAccess(). Not resolved: " +
                  found.code);
        return { ok: false, code: found.code, why: found.why,
                 policy: found.policy };
      }
      const answer = this.deps.loadXacml().decidePolicy(found.parsed,
        request, { repository: null,
                   resolve: !(options && options.resolve === false) });
      log.debug("Leaving FgaPep.decideAccess(). " +
                String((answer && answer.decision) || ''));
      return { ok: true, code: '', why: '', answer: answer,
               policy: found.policy, policyId: found.policyId,
               version: found.version };
    } catch (e) {
      log.debug("Caught in FgaPep.decideAccess(): " +
                ((e && e.message) || e));
      // A FAULT, AND NEVER A DECISION: the caller answers an error.
      log.error(errorCodes.tag('STS-FGA-0015') + 'fga_pep: deciding an ' +
                'access question about "' + named + '" threw: ' +
                ((e && e.stack) || e));
      log.debug("Leaving FgaPep.decideAccess(). Threw.");
      return { ok: false, code: 'STS-FGA-0015', policy: '',
               why: 'The fine-grained authorization decision could not be ' +
                    'made: ' + ((e && e.message) || e) };
    }
  }

  /**
   * Fills `common/fga_gate.ts`'s decider slot with this instance.
   */
  installDecider(): void {
    const self = this;
    const { log, gate } = this.deps;
    log.debug("Entering FgaPep.installDecider().");
    gate.setDecider(function (question: FgaQuestion): FgaAnswer {
      return self.decide(question);
    });
    log.debug("Leaving FgaPep.installDecider().");
  }
}

// The module's own work with its instance: the gate's slot.
function wireFgaPep(instance: FgaPep): void {
  log.debug("Entering wireFgaPep().");
  instance.installDecider();
  log.debug("Leaving wireFgaPep().");
}

// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2) at 23c, after
// `fga_policies.ts`; its wire step is what ARMS fine-grained authorization at
// issuance — before it, `common/fga_gate.ts` refuses an enforcing
// application's every detail.
const slot = new InstanceSlot<FgaPep>(
  'xacml/fga_pep',
  () => new FgaPep(FgaPep.defaultDeps()),
  wireFgaPep,
  helpers.log);

// Standalone, build the default now, as every module on the pattern does.
slot.buildNowUnlessDeferred();

/**
 * The embedded fine-grained authorization PEP (#564, P3): one detail, its
 * owning application's policy, deny-biased.
 * @namespace
 */
export = {
  FgaPep: FgaPep,
  installInstance: (instance: FgaPep): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  canonical: FgaPep.canonical,
  decide: slot.forward('decide'),
  decideAccess: slot.forward('decideAccess'),
  detailDigest: slot.forward('detailDigest')
};
