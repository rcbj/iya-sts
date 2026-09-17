'use strict';
//
// File: xacml_access_pep.ts
//
// ---------------------------------------------------------------------------
// THE EMBEDDED POLICY ENFORCEMENT POINT FOR THIS SERVICE'S OWN ACCESS CONTROL
// (2026-09-06).
//
// `xacml_role_pep.ts` beside this file decides what may be ISSUED. This one
// decides who may REACH something: the admin console, the management API, the
// User Portal, SCIM, the SPIRE Server API, the embedded debugger and the
// `/xacml` surface itself (`common/access_gate.ts` lists them). It fills
// `common/access_gate.ts`'s decider exactly as that one fills
// `common/issuance_gate.js`'s, and the two are deliberately the same shape.
//
// ---------------------------------------------------------------------------
// THE SUBJECT IS THE SECURITY CONTEXT'S PERSON, AND THAT IS THE WHOLE POINT.
//
// Every authenticated session this service holds carries the person it belongs
// to. That person is the subject of every decision made here — `session.user`,
// never a username in a query string or an id in a body — and their DIRECTORY
// ENTRY is already an attribute source, because `xacml_pip.ts` IS the embedded
// directory: a designator in the access-subject category is looked up on that
// person's own entry.
//
// So a policy written here can ask about anything the entry holds — a title, a
// department, a group — without this file knowing those attributes exist. What
// this file supplies is the part the directory cannot know: which RESOURCE is
// being reached, what is being DONE to it, whose it IS, and what it REQUIRES.
//
// ---------------------------------------------------------------------------
// WHERE THE REQUIREMENT COMES FROM, and why it is not in the policy.
//
// A resource's required role is looked up in the APPLICATION REGISTRY, the same
// place `xacml_role_pep.ts` looks: the five surfaces above are ordinary entries
// under `ou=applications`, so narrowing the console is editing an entry rather
// than editing a policy. One document therefore decides for every surface, and
// there is nothing to keep in step between a rule and a fact.
//
// **THE CONSOLE'S TWO ROLES ARE THE EXCEPTION AND THEY STAY WHERE THEY ARE.**
// `admin_rbac.js` reads `cn=admin-read` and `cn=admin-write` — the default
// realm's for a service administrator, and since 2026-09-14 (#32) a realm's own
// for that realm's administrator, whom `admin-ui/admin_scope.ts` confines to
// the realm. What this PEP does is put the roles that module found INTO the
// request, so the policy decides on them; it does not take over deciding what
// they are, or which roster they came from.
//
// ---------------------------------------------------------------------------
// A LIBRARY (rule 3). It registers no route; `xacml.ts` requires it at 23c,
// which is what arms the gate. Before that line every access decision is
// ALLOWED, which is what a process without the XACML family does — see the
// gate's header for why that is a smaller service rather than a broken one.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `XacmlAccessPep` takes the settings, the audit log, the registers,
// the policy store, the engine, the PIP, the templates and the monitor through
// its constructor (`XacmlAccessPepDeps`).
//
// **THE ARMING STILL HAPPENS AT LOAD, AND IN THE ORIGINAL ORDER.** Since
// #50's R2 the composition root builds the instance and installs it here, and
// every old name is exported as a FACADE forwarding to it. The code at the
// bottom fills `common/access_gate.ts`'s decider with the `decide` facade —
// built ONCE, so the gate holds the function this module exports — at load,
// as the original did. The banner that says the PEP is armed names the
// instance's policy, so `XacmlAccessPep.wire()` logs it when the instance is
// installed. A process without the root builds and wires a default when this
// module loads. `XacmlAccessPep` is exported for the root.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');
import gate = require('../common/access_gate');
// The audit log, for the refusals. A LEAF in the ordinary direction (rule
// 3c): it registers no route and requires nothing here, so it can be required
// from a module reached through `common/access_gate.ts` without moving a route
// or closing a cycle.
import audit = require('../common/audit');
// The error-code registry (a leaf): a refusal's code rides on the audit row and
// on the log line, never on anything a caller of a gated surface receives.
import errorCodes = require('../common/error_codes');
import roles = require('../common/roles');
import applications = require('../common/applications');
import templates = require('./xacml_templates');
import model = require('./xacml_model');
import pdp = require('./xacml_pdp');
import pip = require('./xacml_pip');
import store = require('./xacml_store');
// The decision counters. A LEAF (rule 3) that requires no route-registering
// module — which is what makes it safe to require from a file reached through
// `common/access_gate.ts`; its header argues that constraint in full.
import monitor = require('./xacml_monitor');

// The question a gated surface asks, through `common/access_gate.ts`.
interface AccessQuestion {
  resource?: any;
  action?: any;
  owner?: any;
  subject?: any;
  requiredRoles?: unknown[];
}

// What a decision answers.
// The index signature matches `common/access_gate.ts`'s own AccessAnswer, so
// this decider fits the gate's AccessDecider (#50, after merging batches E
// and F).
interface AccessAnswer {
  allowed: boolean;
  decision: string;
  why: string;
  policy: any;
  [key: string]: unknown;
}

// Which document decides: `policy` when one does, `why` and `errorCode`
// when none can.
interface LoadedPolicy {
  policy?: any;
  name?: string;
  builtIn?: boolean;
  why?: string;
  errorCode?: string;
}

interface XacmlAccessPepDeps {
  log: typeof helpers.log;
  config: { value(key: string): any };
  audit: { audit(row: object): unknown };
  errorCodes: { tag(code: string): string };
  roles: { rolesOf(subject: any): string[] };
  applications: { requiredRolesOf(resource: any): string[] };
  templates: { build(id: string, answers: any, options: any): any;
               ISSUANCE_ATTRIBUTE: Record<string, string> };
  model: typeof model;
  pdp: { evaluate(policy: any, request: any, options: object): any };
  pip: { resolverFor(request: any): (designator: any) => any[] };
  store: { read(name: string): any; parseDocument(document: string): any;
           repository(): Record<string, any> };
  monitor: { record(asker: string, what: object): unknown };
}

const ATTRIBUTE = templates.ISSUANCE_ATTRIBUTE;

class XacmlAccessPep {
  constructor(private readonly deps: XacmlAccessPepDeps) {
    deps.log.debug("Entering XacmlAccessPep.constructor().");
    deps.log.debug("Leaving XacmlAccessPep.constructor().");
  }

  // What the composition root passes, from the real modules.
  static defaultDeps(): XacmlAccessPepDeps {
    helpers.log.debug("Entering XacmlAccessPep.defaultDeps().");
    helpers.log.debug("Leaving XacmlAccessPep.defaultDeps().");
    return {
      log: helpers.log,
      config: config,
      audit: audit,
      errorCodes: errorCodes,
      roles: roles,
      applications: applications,
      templates: templates,
      model: model,
      pdp: pdp,
      pip: pip,
      store: store,
      monitor: monitor
    };
  }

  // The policy this PEP evaluates. BUILT IN and called rather than seeded, for
  // the reason `xacml_role_pep.ts` records at length: `ou=policies` is per
  // realm, and a policy seeded once in the default realm leaves every realm
  // created later unable to decide anything. A repository entry named by
  // `xacml.accessPolicy` overrides it.
  accessPolicyName(): string {
    const { log, config } = this.deps;
    log.debug("Entering XacmlAccessPep.accessPolicyName().");
    log.debug("Leaving XacmlAccessPep.accessPolicyName().");
    return String(config.value('xacml.accessPolicy') || 'access-control');
  }

  private builtInPolicy(): LoadedPolicy {
    const { log, templates } = this.deps;
    log.debug('Entering XacmlAccessPep.builtInPolicy().');
    const built = templates.build('access-control', {},
                                  { name: this.accessPolicyName() });
    if (!built.ok) {
      // A DEFECT AND NOT A STATE — the template is in this repository and
      // takes no required parameter, so it cannot fail for anything an
      // administrator did.
      log.debug('Leaving XacmlAccessPep.builtInPolicy(). The template would ' +
                'not build.');
      return { errorCode: 'STS-XACML-0049',
               why: 'the built-in access policy could not be built from the ' +
                    '`access-control` template, which is a defect in this ' +
                    'service rather than a configuration: ' + built.why };
    }
    log.debug('Leaving XacmlAccessPep.builtInPolicy(). Built.');
    return { policy: built.policy, name: this.accessPolicyName(),
             builtIn: true };
  }

  // -------------------------------------------------------------------------
  // **THE OVERRIDE HAD NEVER ONCE BEEN PICKED UP, AND THAT IS WHAT THIS
  // FUNCTION LOOKED LIKE (2026-09-06):**
  //
  //     const repository = store.repository();
  //     const found = repository && typeof repository.get === 'function'
  //       ? repository.get(name) : null;
  //
  // `store.repository()` returns a PLAIN OBJECT keyed by PolicyId — it is what
  // the PDP resolves `PolicyIdReference` through — so it has no `get` method
  // at all and `typeof repository.get === 'function'` is false on every call.
  // The guard was written as a defensive one and was in fact the whole
  // condition: `found` was always null, the built-in document always
  // answered, and `xacml.accessPolicy` was a documented setting, offered on
  // the console, that did nothing. Two further mistakes were hiding under it —
  // the name is an ENTRY name and that map is keyed by PolicyId, and a value
  // in it is a parsed policy rather than a row with an `enabled` flag — so
  // even a `get` would have missed.
  //
  // It reads the entry the way `xacml_role_pep.ts`'s `issuancePolicy()` does,
  // which is the function this one's header has always claimed to follow.
  //
  // **AND THE DISABLED CASE NOW BEHAVES AS THAT FUNCTION DOES, which is a
  // change rather than a fix.** It used to fall back to the built-in document.
  // That makes the console's Disable button mean "evaluate something else
  // instead", which is the exact thing `issuancePolicy()` refuses to do and
  // calls a lie — and the two behaving oppositely was invisible, because the
  // branch was unreachable. Falling back is also not what keeps an operator
  // safe here: `decide()` below ALLOWS when no policy is loaded, precisely so
  // that a broken or absent policy cannot close the door on the console that
  // is the only place to fix it. So disabling the access policy now means what
  // the button says — this layer stops deciding, every gated surface behaves
  // as it did before the policy existed, and it is logged at error level
  // rather than passing quietly.
  // -------------------------------------------------------------------------
  accessPolicy(): LoadedPolicy {
    const { log, store } = this.deps;
    log.debug('Entering XacmlAccessPep.accessPolicy().');
    const name = this.accessPolicyName();
    const row = store.read(name);
    if (!row) {
      log.debug('Leaving XacmlAccessPep.accessPolicy(). Using the built-in ' +
                'one.');
      return this.builtInPolicy();
    }
    if (!row.enabled) {
      log.debug('Leaving XacmlAccessPep.accessPolicy(). It is disabled.');
      return { errorCode: 'STS-XACML-0047',
               why: 'the policy "' + name + '" is DISABLED, so it is not ' +
                    'evaluated — and this does NOT fall back to the ' +
                    'built-in one, because disabling it is a deliberate act ' +
                    'and a button that quietly evaluated something else ' +
                    'instead would be a lie. Enable it, or delete it and the ' +
                    'built-in policy answers again' };
    }
    try {
      const policy = store.parseDocument(row.document);
      log.debug('Leaving XacmlAccessPep.accessPolicy(). A repository entry ' +
                'answers.');
      return { policy: policy, name: name, builtIn: false };
    } catch (error) {
      log.debug('Caught in XacmlAccessPep.accessPolicy(): ' +
                ((error && error.message) || error));
      log.debug('Leaving XacmlAccessPep.accessPolicy(). It will not load.');
      return { errorCode: 'STS-XACML-0048',
               why: 'the policy "' + name + '" does not load: ' +
                    error.message };
    }
  }

  // **`{ type, lexical }` AND NOT `{ dataType, value }`.** The engine's
  // attribute value carries the datatype as `type` and the unparsed text as
  // `lexical`, and the plausible-looking names are the trap: a value built the
  // other way is not rejected, it simply never matches, and the decision comes
  // back as a clean Deny with no error in it at all. `issuer` and
  // `includeInResult` are part of the shape too. This is `xacml_role_pep.ts`'s
  // helper, and the duplication is deliberate — the two PEPs build different
  // requests and a shared helper would be one module knowing about both.
  private attribute(attributeId: string, values: unknown[] | null | undefined,
                    type?: string): any {
    const { log, model } = this.deps;
    log.debug("Entering XacmlAccessPep.attribute().");
    log.debug("Leaving XacmlAccessPep.attribute().");
    return {
      attributeId: attributeId,
      issuer: null,
      includeInResult: true,
      values: (values || []).filter(function (v) {
        return v !== undefined && v !== null && String(v) !== '';
      }).map(function (v) {
        return { type: type || model.TYPE.STRING, lexical: String(v) };
      })
    };
  }

  // -------------------------------------------------------------------------
  // THE REQUEST. Three categories, and what goes in each is the division this
  // whole component rests on:
  //
  //   ACCESS_SUBJECT   who is asking — from the SESSION, plus the roles they
  //                    hold and whether anybody authenticated. The PIP adds
  //                    whatever else the policy asks for off their entry.
  //   RESOURCE         what is being reached, whose it is, and what it
  //                    requires.
  //   ACTION           what is being done to it.
  // -------------------------------------------------------------------------
  buildRequest(asked: AccessQuestion, held: string[],
               required: string[]): any {
    const { log, model } = this.deps;
    log.debug("Entering XacmlAccessPep.buildRequest().");
    const subject = asked.subject || {};
    log.debug("Leaving XacmlAccessPep.buildRequest().");
    return {
      // `returnPolicyIdList` so a refusal can name the policy that produced it
      // — which is most of what makes an access denial actionable rather than
      // mysterious.
      returnPolicyIdList: true,
      combinedDecision: false,
      // **EVERY CATEGORY CARRIES `id` AND `content`, AND THE ENVIRONMENT
      // CATEGORY IS PRESENT EVEN THOUGH IT IS EMPTY.** Both are required by
      // the engine and neither is obvious: a request built without them
      // evaluates to Indeterminate with `Cannot read properties of undefined
      // (reading 'forEach')`, which under deny-unless-permit is a Deny — so
      // every surface refused everybody and the reason named the policy rather
      // than the request. `xacml_role_pep.ts` builds the same four; this is
      // the second caller and the shape is the contract.
      // **`categories` AND NOT `attributes`.** The engine's request has a
      // `categories` array whose entries each carry an `attributes` array, and
      // the two names one level apart are exactly the trap: a request built
      // with `attributes` at the top is not malformed enough to be rejected —
      // it evaluates to Indeterminate with `Cannot read properties of
      // undefined (reading 'forEach')`, which under deny-unless-permit is a
      // Deny. So every surface refused everybody, and the reason named the
      // POLICY rather than the request that never reached it.
      categories: [
        { category: model.CATEGORY.ACCESS_SUBJECT, id: null, content: null,
          attributes: [
            this.attribute(model.ATTRIBUTE.SUBJECT_ID, [subject.name || '']),
            this.attribute(ATTRIBUTE.ROLE, held),
            // A BOOLEAN and not a string, so a policy compares it with
            // `boolean-equal` rather than against the text "true" — which is
            // the kind of thing that works until somebody writes "True".
            this.attribute(ATTRIBUTE.AUTHENTICATED,
                           [subject.authenticated === false ? 'false'
                                                            : 'true'],
                           model.TYPE.BOOLEAN)
          ] },
        { category: model.CATEGORY.RESOURCE, id: null, content: null,
          attributes: [
            this.attribute(model.ATTRIBUTE.RESOURCE_ID, [asked.resource]),
            this.attribute(ATTRIBUTE.REQUIRED_ROLE, required),
            // WHOSE IT IS. Only the portal sets this today, and the EMPTY BAG
            // is load-bearing rather than a default: the policy's ownership
            // conjunct reads `string-bag-size(owner) == 0` as "this resource
            // names nobody", which is what makes one document serve the four
            // ownerless surfaces and the portal at once. `attribute()` drops
            // an empty string, so `asked.owner || ''` produces that empty bag
            // rather than a bag holding one value nothing can ever equal.
            this.attribute(ATTRIBUTE.OWNER, [asked.owner || ''])
          ] },
        { category: model.CATEGORY.ACTION, id: null, content: null,
          attributes: [
            this.attribute(model.ATTRIBUTE.ACTION_ID, [asked.action])
          ] },
        { category: model.CATEGORY.ENVIRONMENT, id: null, content: null,
          attributes: [] }
      ]
    };
  }

  // -------------------------------------------------------------------------
  // THE TWO FUNNELS EVERY ANSWER PASSES THROUGH, AND SINCE 2026-09-06 THEY
  // COUNT.
  //
  // Told here rather than at the return sites, for the reason the issuance
  // PEP's pair gives: a branch added later is counted by construction.
  // `record()` never throws, and this is one of the two call sites that
  // argument is about — every request to a gated surface in this service
  // comes through here.
  // -------------------------------------------------------------------------
  private allowed(why: string, answer?: any): AccessAnswer {
    const { log, monitor } = this.deps;
    log.debug("Entering XacmlAccessPep.allowed().");
    const decision = answer ? answer.decision : 'NotApplicable';
    monitor.record('access', { decision: decision, allowed: true });
    log.debug("Leaving XacmlAccessPep.allowed().");
    return { allowed: true, decision: decision,
             why: why, policy: answer ? answer.policyId : null };
  }

  private refused(why: string, decision: string, answer: any): AccessAnswer {
    const { log, monitor } = this.deps;
    log.debug("Entering XacmlAccessPep.refused().");
    monitor.record('access', { decision: decision, allowed: false });
    log.debug("Leaving XacmlAccessPep.refused().");
    return { allowed: false, decision: decision, why: why,
             policy: answer ? answer.policyId : null };
  }

  // -------------------------------------------------------------------------
  // THE DECISION.
  // -------------------------------------------------------------------------
  decide(asked: AccessQuestion): AccessAnswer {
    const { log, config, audit, errorCodes, roles, applications, model,
            pdp, pip, store } = this.deps;
    log.debug('Entering XacmlAccessPep.decide(). resource=' + asked.resource +
              ' action=' + asked.action);

    if (config.value('xacml.enabled') === false) {
      log.debug('Leaving XacmlAccessPep.decide(). The XACML family is ' +
                'switched off.');
      return this.allowed('xacml.enabled is off, so no policy is evaluated ' +
                          'at all.');
    }

    const subject = asked.subject || {};
    // The roles this person holds — the register's, plus the six computed
    // built-ins. The SAME function the issuance PEP calls, so "holds a role"
    // means one thing in this service.
    const held = roles.rolesOf({
      kind: 'user',
      name: subject.name || '',
      authenticated: subject.authenticated !== false,
      groups: subject.groups || []
    });
    // Roles the CALLER already established — the console's two, which
    // `admin_rbac.js` decides and this does not take over. Unioned in rather
    // than replacing, so a policy can be written against either.
    (subject.roles || []).forEach(function (one) {
      if (held.indexOf(one) < 0) {
        held.push(one);
      }
    });
    // THE REQUIREMENT COMES FROM THE CALLER WHEN THE CALLER HAS ONE, AND FROM
    // THE APPLICATION REGISTER OTHERWISE (2026-09-06).
    //
    // The five original resources are surfaces an operator NARROWS: they
    // require `EVERYBODY` until somebody says otherwise, which is
    // `requiredRolesOf()`'s permissive default and is what keeps this layer
    // from changing behaviour the day it was added. A BUILT-IN resource can be
    // the other shape — one that is restricted from the start — and
    // `/xacml/pep/*` is the first: the three endpoints a remote enforcement
    // point lives on require `REMOTE_PEPS` out of the box, because a gate that
    // is permissive until configured is a gate that is open on every
    // deployment nobody has configured.
    //
    // It is still a POLICY decision and not a hard-coded refusal: the
    // requirement travels in the REQUEST, the same access-control document
    // decides it as decides the console, and an operator who edits that
    // document or names a different group changes the answer. What is fixed
    // is only the DEFAULT.
    const required = (Array.isArray(asked.requiredRoles) &&
                      asked.requiredRoles.length)
      ? asked.requiredRoles.map(String)
      : applications.requiredRolesOf(asked.resource);

    const loaded = this.accessPolicy();
    if (!loaded.policy) {
      // **ALLOWED, AND THIS IS THE OPPOSITE OF WHAT THE ISSUANCE PEP DOES WITH
      // A MISSING POLICY** — worth understanding rather than reading as an
      // inconsistency. There, a narrowed application is REFUSED because
      // somebody deliberately restricted it and the restriction cannot be
      // evaluated. Here, refusing would lock every operator out of the console
      // that is the only place to fix the policy, and the management API with
      // it. A deployment cannot be recovered from a fully closed door.
      log.error(errorCodes.tag(loaded.errorCode || 'STS-XACML-0048') +
                'xacml: ' + loaded.why + '. Access is NOT being gated by ' +
                'policy; every surface behaves as it did before the policy ' +
                'existed. The roles the console and SCIM already enforce are ' +
                'unaffected — this is the POLICY layer above them.');
      log.debug("Leaving XacmlAccessPep.decide().");
      return this.allowed('No access policy is loaded: ' + loaded.why);
    }

    const request = this.buildRequest(asked, held, required);
    const answer = pdp.evaluate(loaded.policy, request, {
      repository: store.repository(),
      // THE SAME PIP THE PUBLIC ENDPOINT USES — see the same note in
      // xacml_role_pep.ts. A decision made here against a different attribute
      // source from the one `/xacml/pdp` and `/admin/xacml/decide` use would
      // be a decision nobody could reproduce on the page built to reproduce
      // it.
      resolver: pip.resolverFor(request)
    });

    if (answer.decision === model.DECISION.PERMIT) {
      log.debug('Leaving XacmlAccessPep.decide(). Permit.');
      return this.allowed('The access policy permitted it.', answer);
    }

    // The three refusals mean different things to whoever has to fix one, so
    // the sentence says which — the same division the issuance PEP makes.
    const who = subject.name
      ? '"' + subject.name + '"' + (subject.authenticated === false
          ? ' (who did not authenticate)' : '')
      : 'an unauthenticated caller';
    const what = asked.action + ' on ' + asked.resource +
                 (asked.owner ? ', owned by "' + asked.owner + '"' : '');
    let why;
    let refusalCode;
    if (answer.decision === model.DECISION.DENY) {
      refusalCode = 'STS-XACML-0044';
      why = 'The access policy denied ' + what + ' for ' + who +
            '. They hold ' +
            (held.length ? held.join(', ') : 'no role') + '; it requires ' +
            (required.length ? required.join(' or ') : 'nothing') + '.';
    } else if (answer.decision === model.DECISION.INDETERMINATE) {
      refusalCode = 'STS-XACML-0045';
      why = 'The access policy could not be evaluated for ' + what + ' (' +
            ((answer.status && answer.status.message) || 'no reason given') +
            '), which is a fault in the policy rather than a decision about ' +
            who + '.';
    } else {
      refusalCode = 'STS-XACML-0046';
      why = 'The access policy did not cover ' + what + ', and its ' +
            'combining algorithm is deny-unless-permit — so a question it ' +
            'does not answer is a refusal rather than a permission.';
    }
    // -----------------------------------------------------------------------
    // AND IT IS AUDITED (2026-09-06), WHICH IT WAS NOT BEFORE.
    //
    // The issuance PEP has audited its refusals since it was written; this one
    // logged at info level and recorded nothing, so a refusal at a gated
    // surface was findable in a log file and nowhere in `/admin/audit`. That
    // gap became worth closing rather than noting when
    // `/admin/xacml/monitor` began COUNTING these refusals: a page that says
    // how many and points at a log for the reason has to be pointing at a log
    // that has them.
    //
    // ONLY THE REFUSALS. A permit here is every request to every gated surface
    // in the service — the console draws sixty pages, each with its own
    // request — and auditing those would push everything else out of a
    // 5,000-event ring within minutes. That is the same line the issuance PEP
    // draws, and the ordinary one: an audit log is of things that were
    // refused, changed or issued.
    // -----------------------------------------------------------------------
    audit.audit({
      action: 'xacml.access.refused',
      errorCode: refusalCode,
      actor: subject.name || '',
      protocol: 'XACML',
      detail: answer.decision + ' for ' + what + ': ' + why
    });
    log.debug('Leaving XacmlAccessPep.decide(). Refused: ' + answer.decision);
    return this.refused(why, answer.decision, answer);
  }

  // -------------------------------------------------------------------------
  // WHAT IS DECIDING, FOR THE CONSOLE. `issuancePolicyState()`'s twin, and it
  // carries the same four facts kept apart for the same reason: whether an
  // override ENTRY exists is a different question from whether one is
  // DECIDING, and `builtIn` alone cannot tell "nobody has written one" from
  // "somebody wrote one and disabled it".
  //
  // **THE `disabled` CASE IS NOW THE SAME AS THE ISSUANCE PEP'S**, and it was
  // not until 2026-09-06 — see `accessPolicy()` above, where the divergence
  // and its removal are argued. What still differs is the CONSEQUENCE and that
  // is deliberate: a disabled issuance policy REFUSES a narrowed application,
  // and a disabled access policy ALLOWS every gated surface, because refusing
  // there would close the console that is the only place to fix it. Two
  // different answers to "what does not deciding mean here", from one answer
  // to "is it deciding".
  // -------------------------------------------------------------------------
  accessPolicyState(): Record<string, any> {
    const { log, store } = this.deps;
    log.debug('Entering XacmlAccessPep.accessPolicyState().');
    const name = this.accessPolicyName();
    const loaded = this.accessPolicy();
    // **`store.read()` AND NOT `store.repository().get()`, WHICH IS WHAT THIS
    // REACHED FOR FIRST AND GOT WRONG.** The repository facade is what the PDP
    // resolves references through, so it only holds ENABLED policies — a
    // disabled override is simply absent from it. Asking it here reported
    // `entry: false` for an entry that plainly exists, which is precisely the
    // "nobody wrote one" / "somebody wrote one and disabled it" confusion this
    // function was added to remove, restated one level down.
    //
    // The two fields answer two different questions and must come from two
    // different places: `entry`/`enabled` are facts about the DIRECTORY and
    // come from `store.read()`; `builtIn` is a fact about the DECISION and
    // comes from `accessPolicy()` above, which is what the PEP actually calls.
    const row = store.read(name);
    const out = { name: name, ok: !!loaded.policy,
                  builtIn: !!loaded.builtIn, why: loaded.why || '',
                  setting: 'xacml.accessPolicy',
                  template: 'access-control',
                  entry: !!row,
                  enabled: row ? !!row.enabled : null,
                  effect: '' };
    if (!out.ok) {
      out.effect = 'NOTHING IS BEING EVALUATED, and every gated surface is ' +
                   'ALLOWED — refusing would lock every operator out of the ' +
                   'console that is the only place to fix it: ' + loaded.why;
    } else if (!out.builtIn) {
      out.effect = 'The repository entry "' + name + '" decides. It ' +
                   'overrides the built-in document.';
    } else {
      out.effect = 'The BUILT-IN document decides. It is what the ' +
                   '`access-control` template builds, called rather than ' +
                   'seeded, so every realm has it with nothing written down ' +
                   'and nothing to delete.';
    }
    log.debug('Leaving XacmlAccessPep.accessPolicyState(). ' +
              (out.ok ? (out.builtIn ? 'Built in.' : 'Overridden.')
                      : 'Not evaluated.'));
    return out;
  }

  // THE WORK LOADING THIS MODULE USED TO DO WITH ITS OWN INSTANCE (#50, R2),
  // run by `common/instance_slot.ts` once for whichever instance is
  // installed: the banner that says the gate is armed, which names the
  // instance's policy. The arming itself is a facade and stays at load.
  static wire(instance: XacmlAccessPep): void {
    helpers.log.debug("Entering XacmlAccessPep.wire().");
    helpers.log.info('xacml: the embedded access PEP is armed. Every access ' +
                     'decision in this service — the admin console, the ' +
                     'management API, the User Portal, SCIM and the SPIRE ' +
                     'Server API — is now a XACML decision against the "' +
                     instance.accessPolicyName() + '" policy, with the ' +
                     'SUBJECT taken from the session\'s security context and ' +
                     'the subject\'s own directory entry available to the ' +
                     'policy through the PIP.');
    helpers.log.debug("Leaving XacmlAccessPep.wire().");
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds no
// instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` when this module loads (see
// `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<XacmlAccessPep>(
  'xacml/xacml_access_pep',
  () => new XacmlAccessPep(XacmlAccessPep.defaultDeps()),
  XacmlAccessPep.wire,
  helpers.log);

// `decide` is a facade built ONCE, so the gate and this module's exports hold
// the same function.
const decide = slot.forward('decide');

// ARMING THE GATE, at require time, which is what `xacml.ts` requiring this
// module at 23c does. Before that line every access decision is allowed. A
// facade resolves nothing until it is called, so this stays at load (#50,
// R2); the banner that names the policy reads the instance, and is logged by
// `XacmlAccessPep.wire()`.
gate.setDecider(decide);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  XacmlAccessPep: XacmlAccessPep,
  installInstance: (instance: XacmlAccessPep): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  decide: decide,
  accessPolicy: slot.forward('accessPolicy'),
  accessPolicyName: slot.forward('accessPolicyName'),
  accessPolicyState: slot.forward('accessPolicyState'),
  buildRequest: slot.forward('buildRequest')
};
