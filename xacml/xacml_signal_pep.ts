'use strict';
//
// File: xacml_signal_pep.ts
//
// ---------------------------------------------------------------------------
// THE EMBEDDED PEP FOR WHAT A RECEIVED SIGNAL LEADS TO (#62, 2026-09-22).
//
// `xacml_risk_pep.ts` decides what happens when a person's risk CHANGES
// here, on the transmitter's side. This one decides what the RECEIVING side
// does: this service's own console and portal are registered receivers of
// its own transmitter (`ssf/ssf_receivers.ts`), and a verified CAEP or RISC
// event they receive may end their own sessions for the person it names.
// rcbj's directive is that every authorization decision is policy; ending a
// session is one, so the reaction is a rule in `signal-response`, not a
// branch in the receiver.
//
// **ONE QUESTION PER REACTION PER EVENT TYPE.** The subject is nobody — a
// received event names a person, and whether it is about the person holding
// a session is the receiver's fail-closed match (`isAbout()`), not the
// policy's — and the environment is the event: its short name, its
// namespace, the surface that received it, and its `current_level` where it
// carries one. A Permit means do it.
//
// **THE POLICY IS BUILT IN**, called rather than seeded, as the risk one is:
// `xacml.signalResponsePolicy` names it (`signal-response`), a realm's own
// entry in `ou=policies` overrides it in that realm, and a DISABLED override
// decides nothing, so nothing is ended, and says so (STS-SSF-0110).
//
// **VERIFICATION IS NOT ASKED HERE.** Issue #117's rule — nothing acts on a
// received SET unless it verified — is enforced by the receiver before it
// asks, so no policy an operator writes can relax it.
//
// **IT NEVER THROWS.** A reaction that could not be decided is not taken.
//
// A LIBRARY (rule 3): it registers no route. The receivers reach it LAZILY,
// when a push arrives, and a process without the XACML family ends nothing.
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

// What arrived, as the receiver states it.
interface ReceivedSignal {
  event: string;
  family: string;
  surface: string;
  level: string;
}

interface LoadedPolicy {
  policy?: Json;
  name?: string;
  builtIn?: boolean;
  why?: string;
}

interface XacmlSignalPepDeps {
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

const SIGNAL = templates.SIGNAL_ATTRIBUTE;
const RESPONSE = templates.SIGNAL_RESPONSE;

class XacmlSignalPep {
  static readonly RESPONSE = RESPONSE;

  constructor(private readonly deps: XacmlSignalPepDeps) {
    deps.log.debug("Entering XacmlSignalPep.constructor().");
    deps.log.debug("Leaving XacmlSignalPep.constructor().");
  }

  static defaultDeps(): XacmlSignalPepDeps {
    helpers.log.debug("Entering XacmlSignalPep.defaultDeps().");
    helpers.log.debug("Leaving XacmlSignalPep.defaultDeps().");
    return { log: helpers.log, config: config, errorCodes: errorCodes,
             model: model, store: store, pdp: pdp, pip: pip,
             templates: templates };
  }

  policyName(): string {
    const { log, config } = this.deps;
    log.debug("Entering XacmlSignalPep.policyName().");
    log.debug("Leaving XacmlSignalPep.policyName().");
    return String(config.value('xacml.signalResponsePolicy') ||
                  'signal-response');
  }

  // The document that decides: the realm's own entry, or the built-in one;
  // `why` when neither can.
  responsePolicy(): LoadedPolicy {
    const { log, store, templates } = this.deps;
    log.debug("Entering XacmlSignalPep.responsePolicy().");
    const name = this.policyName();
    const row = store.read(name);
    if (!row) {
      const built = templates.build('signal-response', {}, { name: name });
      log.debug("Leaving XacmlSignalPep.responsePolicy(). Built in.");
      return built.ok ? { policy: built.policy, name: name, builtIn: true }
        : { why: 'the built-in signal-response template would not build: ' +
                 built.why };
    }
    if (!row.enabled) {
      log.debug("Leaving XacmlSignalPep.responsePolicy(). Disabled.");
      return { why: 'the policy "' + name + '" is DISABLED, so no received ' +
                    'signal is acted on — and it does not fall back to the ' +
                    'built-in one, because disabling it is a deliberate act' };
    }
    try {
      const policy = store.parseDocument(row.document);
      log.debug("Leaving XacmlSignalPep.responsePolicy(). Loaded.");
      return { policy: policy, name: name };
    } catch (e) {
      log.debug("Caught in XacmlSignalPep.responsePolicy(): " +
                ((e && e.message) || e));
      log.debug("Leaving XacmlSignalPep.responsePolicy(). Will not load.");
      return { why: 'the policy "' + name + '" does not load: ' +
                    ((e && e.message) || e) };
    }
  }

  private attribute(attributeId: string, values: unknown[]): Json {
    const { log, model } = this.deps;
    log.debug("Entering XacmlSignalPep.attribute().");
    log.debug("Leaving XacmlSignalPep.attribute().");
    return { attributeId: attributeId, issuer: null, includeInResult: false,
             values: values.map(function (one) {
               return { type: model.TYPE.STRING, lexical: String(one) };
             }) };
  }

  // The question: the reaction, and what arrived. An absent value is an
  // empty bag, so a rule about a level never matches an event without one.
  buildRequest(signal: ReceivedSignal, action: string): Json {
    const { log, model } = this.deps;
    log.debug("Entering XacmlSignalPep.buildRequest(). " + action);
    const present = function (value: string): string[] {
      log.debug("Entering present().");
      log.debug("Leaving present().");
      return value ? [value] : [];
    };
    log.debug("Leaving XacmlSignalPep.buildRequest().");
    return {
      returnPolicyIdList: false, combinedDecision: false,
      categories: [
        { category: model.CATEGORY.ACTION, id: null, content: null,
          attributes: [this.attribute(model.ATTRIBUTE.ACTION_ID, [action])] },
        { category: model.CATEGORY.ENVIRONMENT, id: null, content: null,
          attributes: [
            this.attribute(SIGNAL.EVENT, present(signal.event)),
            this.attribute(SIGNAL.FAMILY, present(signal.family)),
            this.attribute(SIGNAL.SURFACE, present(signal.surface)),
            this.attribute(SIGNAL.LEVEL, present(signal.level))] }
      ]
    };
  }

  // -------------------------------------------------------------------------
  // THE DECISION: which reactions the policy permits for this event.
  // Answers `{ reactions, policy, builtIn, why }`.
  // -------------------------------------------------------------------------
  decide(signal: ReceivedSignal): Json {
    const { log, pdp, pip, store, model, errorCodes } = this.deps;
    log.debug("Entering XacmlSignalPep.decide(). " + signal.event);
    const loaded = this.responsePolicy();
    if (!loaded.policy) {
      log.warn(errorCodes.tag('STS-SSF-0110') + 'ssf: no reaction to a ' +
               signal.event + ' received by the ' + signal.surface +
               ' could be decided: ' + loaded.why + '.');
      log.debug("Leaving XacmlSignalPep.decide(). No policy.");
      return { reactions: [], policy: this.policyName(), why: loaded.why };
    }
    const reactions: string[] = [];
    Object.keys(RESPONSE).forEach(function (key: string): void {
      const action = RESPONSE[key];
      const request = this.buildRequest(signal, action);
      let answer: Json = null;
      try {
        answer = pdp.evaluate(loaded.policy, request, {
          repository: store.repository(),
          resolver: pip.resolverFor(request) });
      } catch (e) {
        log.debug("Caught in XacmlSignalPep.decide(): " +
                  ((e && e.message) || e));
        // An evaluation that threw decides nothing: the reaction is not
        // taken, as an Indeterminate under deny-unless-permit would say.
        answer = null;
      }
      if (answer && answer.decision === model.DECISION.PERMIT) {
        reactions.push(action);
      }
    }, this);
    log.debug("Leaving XacmlSignalPep.decide(). " + reactions.join(', '));
    return { reactions: reactions, policy: loaded.name || this.policyName(),
             builtIn: !!loaded.builtIn, why: '' };
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2) at 23c beside the
// other PEPs; a process without the root builds the default here.
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<XacmlSignalPep>(
  'xacml/xacml_signal_pep',
  () => new XacmlSignalPep(XacmlSignalPep.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  XacmlSignalPep: XacmlSignalPep,
  installInstance: (instance: XacmlSignalPep): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  RESPONSE: XacmlSignalPep.RESPONSE,
  decide: slot.forward('decide'),
  policyName: slot.forward('policyName'),
  responsePolicy: slot.forward('responsePolicy'),
  buildRequest: slot.forward('buildRequest')
};
