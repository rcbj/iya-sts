// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: uma_pep.ts
//
// ===========================================================================
// THE EMBEDDED UMA PEP (#1168 phase 4, #1193): one RPT permission — one
// registered resource, one scope — put to the policies that decide it, in
// order, each a separate PDP question with its own audit row. NO DECISION
// LIVES HERE: this file gathers the trusted facts, asks, and reads the
// answers back.
//
//   1. the realm's `uma-authorization` policy — the `ou=policies` entry
//      `uma.authorizationPolicy` names, or the built-in template where there
//      is none; a DISABLED entry does not fall back (it is a fault). Decided
//      with the repository and the PIP, as the issuance policy is.
//   2. the resource OWNER's own document (`uma_owner_policy.ts`), decided
//      ALONE — no repository — with a PIP BOUNDED to
//      `uma.requestingPartyAttributes`: what a person's own rule may read
//      about a stranger is the realm's to say. No document is NotApplicable,
//      which refuses: absence is never consent.
//   3. the resource server's fine-grained policy, only while it enforces one
//      (#564): `xacml/fga_pep.ts`'s `decideAccess()`, the same resolve and
//      evaluation every FGA question gets, with `urn:sts:xacml:fga:stage` =
//      `uma`. Its Deny stands over an owner's Permit.
//
// (The fourth layer, the issuance gate's `issue-access-token`, is asked by
// the token endpoint's own funnel when the RPT is minted — `uma_grant.ts`.)
//
// HOW AN ANSWER IS READ — rcbj's design, decision 1 and 6:
//
//   * Permit with nothing undischargeable is yes. The one obligation this
//     PEP knows is `urn:sts:xacml:obligation:uma-approval`, on the owner's
//     layer, which says an approval is needed (phase 5); `…:log` is
//     discharged as everywhere. Any other refuses (STS-UMA-0214).
//   * Deny, NotApplicable, and an Indeterminate over a missing attribute
//     ABOUT ANYTHING BUT THE REQUESTING PARTY refuse.
//   * An Indeterminate over a missing attribute OF THE ACCESS-SUBJECT
//     CATEGORY is `need` — the token endpoint answers `need_info`, naming
//     the attribute.
//   * An Indeterminate through a processing or syntax error, a throw, a
//     document that will not parse, a disabled realm policy or an FGA policy
//     that cannot be used is a FAULT: `server_error`, never `request_denied`
//     — nobody decided.
//
// THE AUDIT ROW, `uma.decision`, one per question: the layer, the policy,
// the resource's id and type, the scope, the client, the requesting party
// and how they became known, the stage, the XACML decision and the outcome
// — never a claim value, a resource's name or its description.
// THE MONITOR: the realm and owner layers on the `uma` row, the FGA layer
// on the `fga` row (rcbj's design).
//
// A LIBRARY (rule 3): no route. The XACML family is reached lazily.
// ===========================================================================

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');
import errorCodes = require('../common/error_codes');
import audit = require('../common/audit');
import applications = require('../common/applications');
import realms = require('../common/realms');
import model = require('../xacml/xacml_model');
import xacmlRequest = require('../xacml/xacml_request');
import templates = require('../xacml/xacml_templates');
import ownerPolicy = require('./uma_owner_policy');

const { log } = helpers;

type Json = any;

const V = xacmlRequest.VOCABULARY;
const U = templates.UMA_ATTRIBUTE;
const LOG_OBLIGATION = 'urn:sts:xacml:obligation:log';

/** One question: the facts `xacml_request.js`'s `uma()` takes, less the
 * layer, which this file sets. */
interface UmaQuestion {
  resource: Json;
  scope: string;
  requestingParty: Json;
  clientId: string;
  clientGrantDeclared: boolean;
  claims: Json;
  ticketAgeS: number;
  rptPresented: boolean;
  stage: string;
  // A what-if (#1195): asked and read as any question, and neither audited
  // nor counted — a dry run is a question about a decision and not one.
  dryRun?: boolean;
}

/** One permission's verdict. */
interface Verdict {
  outcome: 'permit' | 'refuse' | 'need' | 'fault';
  layer: string;
  code: string;
  approval: boolean;
  missing: string[];
  why: string;
  // Every layer asked, in order (#1195's what-if); the last decided.
  layers?: Verdict[];
}

interface UmaPepDeps {
  log: typeof log;
  config: typeof config;
  errorCodes: typeof errorCodes;
  audit: typeof audit;
  applications: Json;
  realms: typeof realms;
  owner: Json;
  templates: typeof templates;
  loadXacml(): Json;
  loadStore(): Json;
  loadPdp(): Json;
  loadPip(): Json;
  loadFgaPep(): Json;
  loadMonitor(): Json;
}

// The built-in realm policy's model, kept once built — it depends on
// nothing but the template, and building it is the costly part (the
// verdict modules' reason).
let builtInRealm: Json = null;

/**
 * The embedded UMA PEP: one permission, three policies, every answer read
 * deny-biased.
 */
class UmaPep {
  /**
   * Builds the PEP over its dependencies.
   *
   * @param deps - the logger, settings, error codes, audit log, registry,
   *   realms, the owner's document, the templates and the lazy loaders
   */
  constructor(private readonly deps: UmaPepDeps) {
    deps.log.debug("Entering UmaPep.constructor().");
    deps.log.debug("Leaving UmaPep.constructor().");
  }

  /**
   * The dependencies built from the real modules.
   *
   * @returns the dependencies
   */
  static defaultDeps(): UmaPepDeps {
    log.debug("Entering UmaPep.defaultDeps().");
    const lazy = function (name: string, path: string): () => Json {
      return function (): Json {
        log.debug("Entering " + name + "().");
        log.debug("Leaving " + name + "().");
        return require(path);
      };
    };
    log.debug("Leaving UmaPep.defaultDeps().");
    return {
      log: log, config: config, errorCodes: errorCodes, audit: audit,
      applications: applications, realms: realms, owner: ownerPolicy,
      templates: templates,
      loadXacml: lazy('loadXacml', '../xacml/xacml'),
      loadStore: lazy('loadStore', '../xacml/xacml_store'),
      loadPdp: lazy('loadPdp', '../xacml/xacml_pdp'),
      loadPip: lazy('loadPip', '../xacml/xacml_pip'),
      loadFgaPep: lazy('loadFgaPep', '../xacml/fga_pep'),
      loadMonitor: lazy('loadMonitor', '../xacml/xacml_monitor')
    };
  }

  /**
   * The request one layer is asked, through THE builder (rule 3br).
   *
   * @param q - the question
   * @param layer - realm, owner or fga
   * @returns the request
   */
  requestFor(q: UmaQuestion, layer: string): Json {
    const { log, realms, config } = this.deps;
    log.debug("Entering UmaPep.requestFor(). " + layer);
    const r = q.resource || {};
    const built = new xacmlRequest.AuthorizationRequest({}).uma({
      realm: String(realms.currentId() || ''), layer: layer,
      stage: q.stage, scope: q.scope,
      resource: { id: r._id, type: r.type, resourceServer: r.resourceServer,
                  resourceServerDeclared: this.declared(r.resourceServer),
                  owner: r.owner, ownerKind: r.ownerKind },
      requestingParty: q.requestingParty || {},
      clientId: q.clientId, clientGrantDeclared: q.clientGrantDeclared,
      claims: q.claims || {}, ticketAgeS: q.ticketAgeS,
      rptPresented: q.rptPresented,
      mode: String(config.value('global.mode') || ''),
      settings: { 'uma.partialRpt': config.value('uma.partialRpt') === true }
    });
    if (layer === 'fga') {
      built.resource(V.FGA_APPLICATION, [String(r.resourceServer || '')]);
      built.environment(V.FGA_STAGE, ['uma']);
    }
    log.debug("Leaving UmaPep.requestFor().");
    return built.build();
  }

  /**
   * Whether an application is declared for the protocol `uma`.
   *
   * @param identifier - the application
   * @returns true when it is
   */
  declared(identifier: unknown): boolean {
    const { log, applications } = this.deps;
    log.debug("Entering UmaPep.declared().");
    let out = false;
    try {
      const entry = identifier ? applications.get(String(identifier)) : null;
      out = !!entry &&
        applications.declaredFamiliesOf(entry).indexOf('uma') >= 0;
    } catch (e) {
      log.debug("Caught in UmaPep.declared(): " + ((e && e.message) || e));
      out = false;
    }
    log.debug("Leaving UmaPep.declared(). " + out);
    return out;
  }

  // The realm's policy: the named entry, or the built-in template.
  private realmPolicy(): Json {
    const { log, config, templates } = this.deps;
    log.debug("Entering UmaPep.realmPolicy().");
    const name = String(config.value('uma.authorizationPolicy') ||
                        U.REALM_TEMPLATE);
    const store = this.deps.loadStore();
    const row = store.read(name);
    if (row) {
      if (!row.enabled) {
        log.debug("Leaving UmaPep.realmPolicy(). Disabled.");
        return { fault: 'STS-UMA-0211', name: name,
                 why: 'the policy "' + name + '" is disabled, and a ' +
                      'disabled policy does not fall back to the built-in ' +
                      'one' };
      }
      log.debug("Leaving UmaPep.realmPolicy(). The entry.");
      return { policy: store.parseDocument(row.document), name: name,
               repository: store.repository() };
    }
    if (!builtInRealm) {
      const built = templates.build(U.REALM_TEMPLATE, {},
                                    { name: U.REALM_TEMPLATE });
      builtInRealm = built.policy;
    }
    log.debug("Leaving UmaPep.realmPolicy(). Built in.");
    return { policy: builtInRealm, name: 'built-in ' + U.REALM_TEMPLATE,
             repository: store.repository() };
  }

  // A resolver that answers only the directory attributes the realm lets an
  // owner's rule read (`uma.requestingPartyAttributes`), and never a role.
  private boundedResolver(request: Json): (designator: Json) => Json[] {
    const { log, config } = this.deps;
    log.debug("Entering UmaPep.boundedResolver().");
    const pip = this.deps.loadPip();
    const raw = config.value('uma.requestingPartyAttributes');
    const allowed = (Array.isArray(raw) ? raw : String(raw || '').split(','))
      .map(function (one: unknown) {
        return String(one).trim().toLowerCase();
      }).filter(Boolean);
    const inner = pip.resolverFor(request);
    log.debug("Leaving UmaPep.boundedResolver().");
    return function (designator: Json): Json[] {
      if (designator.category !== model.CATEGORY.ACCESS_SUBJECT ||
          designator.attributeId === pip.ROLE_ATTRIBUTE) {
        return [];
      }
      const name = pip.directoryAttributeFor(designator.attributeId);
      if (!name || allowed.indexOf(String(name).toLowerCase()) < 0) {
        return [];
      }
      return inner(designator);
    };
  }

  /**
   * Reads one answer: permit (with the approval it may need), refuse,
   * need (a missing attribute of the requesting party) or fault.
   *
   * @param answer - the PDP's response
   * @param layer - the layer that answered
   * @param marked - the error code the surface marked the answer with
   * @returns the verdict
   */
  static read(answer: Json, layer: string, marked: string): Verdict {
    log.debug("Entering UmaPep.read(). " + layer);
    const out: Verdict = { outcome: 'refuse', layer: layer, code: '',
                           approval: false, missing: [], why: '' };
    const decision = String((answer && answer.decision) || '');
    const status = (answer && answer.status) || {};
    if (marked === 'STS-XACML-0013' || (/^Indeterminate/.test(decision) &&
        (status.code === model.STATUS.PROCESSING_ERROR ||
         status.code === model.STATUS.SYNTAX_ERROR))) {
      out.outcome = 'fault';
      out.code = 'STS-UMA-0208';
      out.why = 'the ' + layer + ' policy could not be evaluated: ' +
        String(status.message || '');
      log.debug("Leaving UmaPep.read(). A fault.");
      return out;
    }
    if (/^Indeterminate/.test(decision) &&
        status.code === model.STATUS.MISSING_ATTRIBUTE) {
      const detail = status.detail || {};
      if (detail.category === model.CATEGORY.ACCESS_SUBJECT) {
        out.outcome = 'need';
        out.code = 'STS-UMA-0209';
        out.missing = [String(detail.attributeId || '')];
        out.why = 'the ' + layer + ' policy needs ' + detail.attributeId +
                  ' about the requesting party';
        log.debug("Leaving UmaPep.read(). Need.");
        return out;
      }
      out.code = 'STS-UMA-0212';
      out.why = 'the ' + layer + ' policy needs ' + detail.attributeId +
                ', which is not about the requesting party';
      log.debug("Leaving UmaPep.read(). Missing, not the party's.");
      return out;
    }
    if (decision !== model.DECISION.PERMIT) {
      out.code = 'STS-UMA-0210';
      out.why = 'the ' + layer + ' policy said ' + (decision || 'nothing');
      log.debug("Leaving UmaPep.read(). Not Permit.");
      return out;
    }
    const strange: string[] = [];
    (answer.obligations || []).forEach(function (o: Json) {
      if (o.id === U.APPROVAL_OBLIGATION && layer === 'owner') {
        out.approval = true;
      } else if (o.id !== LOG_OBLIGATION) {
        strange.push(String(o.id));
      }
    });
    if (strange.length) {
      out.code = 'STS-UMA-0214';
      out.why = 'the ' + layer + ' policy permitted with an obligation ' +
                'this PEP cannot discharge (' + strange.join(', ') + ')';
      log.debug("Leaving UmaPep.read(). Undischargeable.");
      return out;
    }
    out.outcome = 'permit';
    log.debug("Leaving UmaPep.read(). Permit.");
    return out;
  }

  // The audit row and the monitor's count for one question.
  private record(q: UmaQuestion, layer: string, policy: string,
                 decision: string, verdict: Verdict): void {
    const { log, audit } = this.deps;
    log.debug("Entering UmaPep.record(). " + layer);
    const r = q.resource || {};
    const party = q.requestingParty || {};
    audit.audit({
      action: 'uma.decision', protocol: 'UMA 2.0',
      actor: String(q.clientId || ''), target: String(r._id || ''),
      outcome: verdict.outcome === 'permit' ? 'success'
        : (verdict.outcome === 'fault' ? 'error' : 'refused'),
      errorCode: verdict.code || undefined,
      summary: 'The UMA ' + layer + ' layer ' + (verdict.outcome === 'permit'
        ? 'permitted' : (verdict.outcome === 'need' ? 'needs claims for'
          : (verdict.outcome === 'fault' ? 'could not decide'
                                         : 'refused'))) + ' the scope "' +
        String(q.scope).slice(0, 200) + '" of the resource ' + r._id +
        (policy ? ', policy "' + policy + '"' : '') +
        (decision ? ' (XACML ' + decision + ')' : '') + '.',
      detail: { layer: layer, policy: policy, resource: String(r._id || ''),
                resourceType: String(r.type || ''),
                resourceServer: String(r.resourceServer || ''),
                scope: String(q.scope || ''), client: String(q.clientId || ''),
                requestingParty: String(party.id || ''),
                claimSource: String(party.claimSource || ''),
                stage: String(q.stage || ''), decision: decision,
                outcome: verdict.outcome, approval: verdict.approval,
                code: verdict.code }
    });
    try {
      this.deps.loadMonitor().record(layer === 'fga' ? 'fga' : 'uma', {
        decision: decision, allowed: verdict.outcome === 'permit',
        undischargeable: verdict.code === 'STS-UMA-0214' });
    } catch (e) {
      log.debug("Caught in UmaPep.record(): " + ((e && e.message) || e));
      log.warn(this.deps.errorCodes.tag('STS-XACML-0062') + 'uma_pep: the ' +
               'decision counter could not be reached: ' +
               ((e && e.message) || e));
    }
    log.debug("Leaving UmaPep.record().");
  }

  // One layer, asked and read; a throw is a fault.
  private ask(q: UmaQuestion, layer: string): Verdict {
    const self = this;
    const { log, errorCodes } = this.deps;
    log.debug("Entering UmaPep.ask(). " + layer);
    let policyName = '';
    let decision = '';
    let verdict: Verdict;
    try {
      const request = self.requestFor(q, layer);
      let answer: Json = null;
      if (layer === 'realm') {
        const found = self.realmPolicy();
        policyName = found.name;
        if (found.fault) {
          verdict = { outcome: 'fault', layer: layer, code: found.fault,
                      approval: false, missing: [], why: found.why };
        } else {
          answer = self.deps.loadXacml().decidePolicy(found.policy, request,
            { repository: found.repository, resolve: true });
        }
      } else if (layer === 'owner') {
        const xml = self.deps.owner.documentXml(
          String(q.resource.owner || ''));
        policyName = templates.umaOwnerPolicyId(q.resource.owner);
        if (!xml) {
          answer = { decision: model.DECISION.NOT_APPLICABLE, status: null,
                     obligations: [], advice: [] };
        } else {
          let policy: Json = null;
          try {
            policy = self.deps.loadStore().parseDocument(xml);
          } catch (e) {
            log.debug("Caught in UmaPep.ask(): " + ((e && e.message) || e));
            policy = null;
          }
          if (!policy) {
            verdict = { outcome: 'fault', layer: layer,
                        code: 'STS-UMA-0213', approval: false, missing: [],
                        why: 'the owner\'s document does not parse' };
          } else {
            answer = self.deps.loadPdp().evaluate(policy, request, {
              repository: null, resolver: self.boundedResolver(request) });
          }
        }
      } else {
        const routed = self.deps.loadFgaPep().decideAccess(
          String(q.resource.resourceServer || ''), request,
          { resolve: true });
        policyName = String((routed && routed.policy) || '');
        if (!routed || !routed.ok) {
          verdict = { outcome: 'fault', layer: layer,
                      code: String((routed && routed.code) || 'STS-FGA-0015'),
                      approval: false, missing: [],
                      why: 'the resource server\'s fine-grained policy ' +
                           'cannot be used' };
        } else {
          answer = routed.answer;
        }
      }
      if (answer) {
        decision = String(answer.decision || '');
        verdict = UmaPep.read(answer, layer,
                              String(errorCodes.codeOf(answer) || ''));
      }
    } catch (e) {
      log.error(errorCodes.tag('STS-UMA-0208') + 'uma_pep: the ' + layer +
                ' layer threw: ' + ((e && e.stack) || e));
      verdict = { outcome: 'fault', layer: layer, code: 'STS-UMA-0208',
                  approval: false, missing: [],
                  why: 'the ' + layer + ' layer could not be asked' };
    }
    if (!q.dryRun) {
      self.record(q, layer, policyName, decision, verdict);
    }
    (verdict as Json).policy = policyName;
    (verdict as Json).decision = decision;
    log.debug("Leaving UmaPep.ask(). " + verdict.outcome);
    return verdict;
  }

  /**
   * Decides one permission: the realm's layer, the owner's, and the
   * resource server's fine-grained policy where it enforces one; the first
   * that does not permit is the answer.
   *
   * @param q - the question
   * @returns the verdict; `approval` set where the owner asks to be asked
   */
  decide(q: UmaQuestion): Verdict {
    const self = this;
    const { log, applications } = this.deps;
    log.debug("Entering UmaPep.decide().");
    const layers: Verdict[] = [];
    const realm = self.ask(q, 'realm');
    layers.push(realm);
    if (realm.outcome !== 'permit') {
      log.debug("Leaving UmaPep.decide(). The realm: " + realm.outcome);
      return Object.assign(realm, { layers: layers });
    }
    const owner = self.ask(q, 'owner');
    layers.push(owner);
    if (owner.outcome !== 'permit') {
      log.debug("Leaving UmaPep.decide(). The owner: " + owner.outcome);
      return Object.assign(owner, { layers: layers });
    }
    let enforced = false;
    try {
      enforced = !!applications.fgaStateOf(
        String(q.resource.resourceServer || '')).enforced;
    } catch (e) {
      log.debug("Caught in UmaPep.decide(): " + ((e && e.message) || e));
      log.debug("Leaving UmaPep.decide(). FGA unreadable.");
      return { outcome: 'fault', layer: 'fga', code: 'STS-FGA-0015',
               approval: false, missing: [],
               why: 'whether the resource server enforces fine-grained ' +
                    'authorization could not be read' };
    }
    if (enforced) {
      const fga = self.ask(q, 'fga');
      layers.push(fga);
      if (fga.outcome !== 'permit') {
        log.debug("Leaving UmaPep.decide(). FGA: " + fga.outcome);
        return Object.assign(fga, { layers: layers });
      }
    }
    log.debug("Leaving UmaPep.decide(). Permit.");
    return Object.assign({}, owner, { layers: layers });
  }

  /**
   * Forgets the built-in realm policy's cached model. For a test.
   */
  static resetForTests(): void {
    log.debug("Entering UmaPep.resetForTests().");
    builtInRealm = null;
    log.debug("Leaving UmaPep.resetForTests().");
  }
}

const slot = new InstanceSlot<UmaPep>(
  'uma/uma_pep',
  () => new UmaPep(UmaPep.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The embedded UMA PEP (#1168 phase 4).
 * @namespace
 */
export = {
  UmaPep: UmaPep,
  installInstance: (instance: UmaPep): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  read: UmaPep.read,
  resetForTests: UmaPep.resetForTests,
  decide: slot.forward('decide'),
  requestFor: slot.forward('requestFor'),
  declared: slot.forward('declared')
};
