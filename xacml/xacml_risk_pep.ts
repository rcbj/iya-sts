'use strict';
//
// File: xacml_risk_pep.ts
//
// ---------------------------------------------------------------------------
// THE EMBEDDED PEP FOR WHAT A CHANGE OF RISK LEADS TO (#62 P4, 2026-09-22).
//
// `xacml_role_pep.ts` decides what is ISSUED, and since P3 decides it on the
// risk of the authentication too. This one decides what HAPPENS when a
// person's risk level CHANGES — announced over CAEP, everything they hold
// ended, RISC told a credential is compromised, the account disabled — and
// `risk/risk_engine.ts` does what it permits. rcbj's directive is that every
// authorization decision is policy; ending somebody's access is one, so the
// reactions are rules in a document an operator edits, not branches here.
//
// **ONE QUESTION PER REACTION.** The request is the same each time — the
// person as the subject, the change as the environment — and the action-id is
// the reaction (`xacml_templates.ts`'s `RISK_RESPONSE`). A Permit means do
// it. The template's header says why this is not one question with a list of
// obligations.
//
// **THE POLICY IS BUILT IN**, called rather than seeded, as the other two
// are: `xacml.riskResponsePolicy` names it (`risk-response`), a realm's own
// entry in `ou=policies` overrides it in that realm, and a DISABLED override
// does not fall back — it decides nothing, so nothing happens, and says so.
//
// **IT NEVER THROWS.** A reaction that could not be decided is a reaction
// not taken, logged under its code; the change of risk itself is recorded
// whatever happens here.
//
// A LIBRARY (rule 3): it registers no route. The risk engine reaches it
// LAZILY, when a level changes — the XACML family is built at 23c, long after
// `risk/` at 18j — and a process without it takes no reaction.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');
import errorCodes = require('../common/error_codes');
import model = require('./xacml_model');
import store = require('./xacml_store');
import pdp = require('./xacml_pdp');
import pip = require('./xacml_pip');
import templates = require('./xacml_templates');

type Json = any;

// What changed, as the risk engine states it.
interface RiskChange {
  username: string;
  level: string;
  previousLevel: string;
  score: number | null;
  signals: string[];
}

interface LoadedPolicy {
  policy?: Json;
  name?: string;
  builtIn?: boolean;
  why?: string;
}

interface XacmlRiskPepDeps {
  log: typeof helpers.log;
  config: { value(key: string): any };
  errorCodes: { tag(code: string): string };
  model: typeof model;
  store: { read(name: string): any; parseDocument(document: string): any;
           repository(): Record<string, any> };
  pdp: { evaluate(policy: any, request: any, options: object): any };
  pip: { resolverFor(request: any): (designator: any) => any[] };
  templates: { build(id: string, answers: any, options: any): any };
}

const RISK = templates.RISK_ATTRIBUTE;
const RESPONSE = templates.RISK_RESPONSE;

class XacmlRiskPep {
  static readonly RESPONSE = RESPONSE;

  constructor(private readonly deps: XacmlRiskPepDeps) {
    deps.log.debug("Entering XacmlRiskPep.constructor().");
    deps.log.debug("Leaving XacmlRiskPep.constructor().");
  }

  static defaultDeps(): XacmlRiskPepDeps {
    helpers.log.debug("Entering XacmlRiskPep.defaultDeps().");
    helpers.log.debug("Leaving XacmlRiskPep.defaultDeps().");
    return { log: helpers.log, config: config, errorCodes: errorCodes,
             model: model, store: store, pdp: pdp, pip: pip,
             templates: templates };
  }

  policyName(): string {
    const { log, config } = this.deps;
    log.debug("Entering XacmlRiskPep.policyName().");
    log.debug("Leaving XacmlRiskPep.policyName().");
    return String(config.value('xacml.riskResponsePolicy') ||
                  'risk-response');
  }

  // The document that decides: the realm's own entry, or the built-in one;
  // `why` when neither can.
  responsePolicy(): LoadedPolicy {
    const { log, store, templates } = this.deps;
    log.debug("Entering XacmlRiskPep.responsePolicy().");
    const name = this.policyName();
    const row = store.read(name);
    if (!row) {
      const built = templates.build('risk-response', {}, { name: name });
      log.debug("Leaving XacmlRiskPep.responsePolicy(). Built in.");
      return built.ok ? { policy: built.policy, name: name, builtIn: true }
        : { why: 'the built-in risk-response template would not build: ' +
                 built.why };
    }
    if (!row.enabled) {
      log.debug("Leaving XacmlRiskPep.responsePolicy(). Disabled.");
      return { why: 'the policy "' + name + '" is DISABLED, so no reaction ' +
                    'to a change of risk is taken — and it does not fall ' +
                    'back to the built-in one, because disabling it is a ' +
                    'deliberate act' };
    }
    try {
      const policy = store.parseDocument(row.document);
      log.debug("Leaving XacmlRiskPep.responsePolicy(). Loaded.");
      return { policy: policy, name: name };
    } catch (e) {
      log.debug("Caught in XacmlRiskPep.responsePolicy(): " +
                ((e && e.message) || e));
      log.debug("Leaving XacmlRiskPep.responsePolicy(). Will not load.");
      return { why: 'the policy "' + name + '" does not load: ' +
                    ((e && e.message) || e) };
    }
  }

  private attribute(attributeId: string, values: unknown[],
                    type?: string): Json {
    const { log, model } = this.deps;
    log.debug("Entering XacmlRiskPep.attribute().");
    log.debug("Leaving XacmlRiskPep.attribute().");
    return { attributeId: attributeId, issuer: null, includeInResult: false,
             values: values.map(function (one) {
               return { type: type || model.TYPE.STRING, lexical: String(one) };
             }) };
  }

  // The question: the person, the reaction, and the change.
  buildRequest(change: RiskChange, action: string): Json {
    const { log, model } = this.deps;
    log.debug("Entering XacmlRiskPep.buildRequest(). " + action);
    const environment = [
      this.attribute(RISK.LEVEL, change.level ? [change.level] : []),
      this.attribute(RISK.PREVIOUS_LEVEL,
                     change.previousLevel ? [change.previousLevel] : []),
      this.attribute(RISK.SIGNAL, change.signals || [])
    ];
    if (typeof change.score === 'number' && isFinite(change.score)) {
      environment.push(this.attribute(RISK.SCORE, [change.score],
                                      model.TYPE.DOUBLE));
    }
    log.debug("Leaving XacmlRiskPep.buildRequest().");
    return {
      returnPolicyIdList: false, combinedDecision: false,
      categories: [
        { category: model.CATEGORY.ACCESS_SUBJECT, id: null, content: null,
          attributes: [this.attribute(model.ATTRIBUTE.SUBJECT_ID,
                                      [change.username || ''])] },
        { category: model.CATEGORY.ACTION, id: null, content: null,
          attributes: [this.attribute(model.ATTRIBUTE.ACTION_ID, [action])] },
        { category: model.CATEGORY.ENVIRONMENT, id: null, content: null,
          attributes: environment }
      ]
    };
  }

  // -------------------------------------------------------------------------
  // THE DECISION: which reactions the policy permits for this change.
  // Answers `{ reactions, policy, why }` — `reactions` the RESPONSE values
  // that were permitted, in RESPONSE's order.
  // -------------------------------------------------------------------------
  decide(change: RiskChange): Json {
    const { log, pdp, pip, store, model, errorCodes } = this.deps;
    log.debug("Entering XacmlRiskPep.decide().");
    const loaded = this.responsePolicy();
    if (!loaded.policy) {
      log.warn(errorCodes.tag('STS-RISK-0020') + 'risk: no reaction to ' +
               (change.username || 'somebody') + '\'s change of risk (' +
               (change.previousLevel || 'none') + ' to ' + change.level +
               ') could be decided: ' + loaded.why + '.');
      log.debug("Leaving XacmlRiskPep.decide(). No policy.");
      return { reactions: [], policy: this.policyName(), why: loaded.why };
    }
    const reactions: string[] = [];
    Object.keys(RESPONSE).forEach(function (key: string): void {
      const action = RESPONSE[key];
      const request = this.buildRequest(change, action);
      let answer: Json = null;
      try {
        answer = pdp.evaluate(loaded.policy, request, {
          repository: store.repository(),
          resolver: pip.resolverFor(request) });
      } catch (e) {
        log.debug("Caught in XacmlRiskPep.decide(): " +
                  ((e && e.message) || e));
        // An evaluation that threw decides nothing: the reaction is not
        // taken, which is what an Indeterminate under deny-unless-permit
        // would have said anyway.
        answer = null;
      }
      if (answer && answer.decision === model.DECISION.PERMIT) {
        reactions.push(action);
      }
    }, this);
    log.debug("Leaving XacmlRiskPep.decide(). " + reactions.join(', '));
    return { reactions: reactions, policy: loaded.name || this.policyName(),
             builtIn: !!loaded.builtIn, why: '' };
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2) at 23c beside the
// other two PEPs; a process without the root builds the default here.
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<XacmlRiskPep>(
  'xacml/xacml_risk_pep',
  () => new XacmlRiskPep(XacmlRiskPep.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  XacmlRiskPep: XacmlRiskPep,
  installInstance: (instance: XacmlRiskPep): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  RESPONSE: XacmlRiskPep.RESPONSE,
  decide: slot.forward('decide'),
  policyName: slot.forward('policyName'),
  responsePolicy: slot.forward('responsePolicy'),
  buildRequest: slot.forward('buildRequest')
};
