'use strict';
//
// File: xacml_role_pep.ts
//
// ---------------------------------------------------------------------------
// THE EMBEDDED POLICY ENFORCEMENT POINT FOR THIS SERVICE'S OWN ISSUANCE.
//
// Every other thing in this directory answers a question about somebody
// else's boundary — that is what a PDP is, and it is why `xacml/CLAUDE.md`
// calls this the only family here that is handed a subject authenticated
// elsewhere and asked whether they may. This file is the exception and it is
// deliberately the only one: it turns THIS service's own issuances into XACML
// requests and refuses the ones the PDP will not permit.
//
// It is what `common/issuance_gate.js` calls. Nine issuance sites ask that
// file, that file asks this one, and this one asks the engine. **There is no
// second implementation of the rule** — no `if (roles.includes(...))` in
// oauth2.js, no membership test in the SAML builder — which is the whole point
// of routing an internal decision through a policy engine that is already
// here: the reason a person was refused is a document an administrator can
// read, edit, test on `/admin/xacml/decide` and see in the audit log.
//
// ---------------------------------------------------------------------------
// THE REQUEST IT BUILDS, WHICH IS THE CONTRACT.
//
//   access-subject   subject-id                    who is being authenticated
//                    urn:sts:xacml:role       the roles they hold
//                    urn:sts:xacml:role-from-token
//                                                  roles read out of a token
//                                                  they PRESENTED
//   resource         resource-id                   the application
//                    urn:sts:xacml:required-role
//                                                  what it demands
//   action           action-id                     issue-access-token,
//                                                  start-session, and the rest
//                                                  of issuance_gate's ISSUANCE
//
// **THE SUBJECT IS THE PARTY BEING AUTHENTICATED AND NOT ALWAYS A PERSON.** In
// a browser flow it is whoever signed in; in a `client_credentials` grant
// there is no person at all and it is the CLIENT. That is the case the role
// register exists to be able to answer — an application is a first-class
// member of a role precisely so that this decision has a subject when nobody
// is there.
//
// **THE APPLICATION IS THE RESOURCE AND ALSO, OFTEN, THE SUBJECT'S EMPLOYER.**
// A client asking for a token for itself appears in both categories, and that
// is not a confusion: as a resource it is the thing being reached, and as a
// subject it is the party whose roles are being read. A policy may name either.
//
// ---------------------------------------------------------------------------
// THE TWO WAYS THIS CAN FAIL, AND THEY GET OPPOSITE ANSWERS.
//
// This is the part to read before changing anything here.
//
// **A MISSING OR BROKEN ISSUANCE POLICY FAILS OPEN FOR AN APPLICATION THAT
// REQUIRES ONLY `EVERYBODY`, AND CLOSED FOR ONE THAT REQUIRES ANYTHING ELSE.**
//
// An application that names no required role is the default state of every
// application in this service. It requires EVERYBODY, everybody holds
// EVERYBODY, and the only answer the policy could ever give is Permit — so a
// missing policy costs that application nothing, and refusing it would mean a
// service whose issuance policy was deleted stops issuing ANYTHING to ANYBODY,
// including the session an administrator needs to put the policy back. That is
// not a security posture, it is a locked room with the key inside.
//
// An application whose entry names `staff` is a different sentence entirely:
// somebody deliberately asked for a restriction. Answering Permit because the
// document implementing that restriction is missing would be the one failure
// this feature must not have — a configured refusal silently not happening.
// So that one is refused, and the refusal NAMES the policy and the template
// that rebuilds it.
//
// **AN ERROR IS NOT A DECISION.** A throw out of the engine is a defect, and
// `issuance_gate.js` answers a throw by allowing, for the locked-room reason
// above. A Deny, a NotApplicable and an Indeterminate are not throws — they
// are answers, and every one of them refuses here, because the policy is
// `deny-unless-permit` and an issuance decision must not rest on a PEP's bias.
// `xacml.pepBias` is the EMBEDDED DEMO PEP's setting at `/xacml/protected` and
// it is deliberately not read here: that one exists to show what bias does,
// and this one is enforcing.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `XacmlRolePep` takes the settings, the audit log, the registers, the
// policy store, the engine, the PIP, the templates and the monitor through its
// constructor (`XacmlRolePepDeps`).
//
// **THE ARMING STILL HAPPENS AT LOAD, AND IN THE ORIGINAL ORDER.** The
// TRANSITIONAL code at the bottom builds one instance from the real modules,
// then — exactly where the original did, after everything else in this file —
// requires `admin-ui/admin`, fills its `setRolePreviewer()` slot, and fills
// `common/issuance_gate.js`'s decider with the instance's `decide`, bound
// ONCE so the function the gate holds is the function this module exports.
// Every old name is still exported, from that instance; it goes when the
// composition root exists, and `XacmlRolePep` is exported beside it.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import config = require('../common/config');
import audit = require('../common/audit');
// The error-code registry (a leaf): a refused issuance's code rides on the
// audit row and the log line, never on the protocol error the client is sent.
import errorCodes = require('../common/error_codes');
import applications = require('../common/applications');
import roles = require('../common/roles');
import gate = require('../common/issuance_gate');
import model = require('./xacml_model');
import store = require('./xacml_store');
// The decision counters. A LEAF that registers no route and requires nothing
// that does — see its header for the list and for why it may not require the
// console, which is the constraint that decides where the
// /admin/xacml/monitor page lives.
import monitor = require('./xacml_monitor');
import pdp = require('./xacml_pdp');
import pip = require('./xacml_pip');
import templates = require('./xacml_templates');

// The question an issuance site asks, through `common/issuance_gate.js`.
interface IssuanceQuestion {
  application?: any;
  kind?: string;
  subject?: any;
  claims?: any;
  preview?: boolean;
}

// What a decision answers.
interface IssuanceAnswer {
  allowed: boolean;
  decision: string;
  why: string;
  roles: string[];
  required: string[];
  policy: string;
  status?: any;
}

// Which document decides: `policy` when one does, `why` when none can.
interface LoadedPolicy {
  policy?: any;
  name?: string;
  builtIn?: boolean;
  why?: string;
}

interface XacmlRolePepDeps {
  log: typeof helpers.log;
  config: { value(key: string): any };
  audit: { audit(row: object): unknown;
           failure(code: string, row: object): unknown };
  errorCodes: { tag(code: string): string };
  applications: { requiredRolesOf(application: any): string[];
                  requiresNarrowedRoles(application: any): boolean };
  roles: { rolesOf(subject: any): string[];
           rolesInClaims(claims: any): string[];
           DEFAULT_REQUIRED_ROLE: string };
  gate: { ISSUANCE: Record<string, string> };
  model: typeof model;
  store: { read(name: string): any; parseDocument(document: string): any;
           repository(): Record<string, any> };
  monitor: { record(asker: string, what: object): unknown };
  pdp: { evaluate(policy: any, request: any, options: object): any };
  pip: { resolverFor(request: any): (designator: any) => any[] };
  templates: { build(id: string, answers: any, options: any): any;
               ISSUANCE_ATTRIBUTE: Record<string, string> };
}

const ATTRIBUTE = templates.ISSUANCE_ATTRIBUTE;

// Said once per process rather than once per issuance. A service running
// without its issuance policy would otherwise write a line per token, which
// buries the one thing anybody needs to read.
let warnedAboutMissingPolicy = false;

// ---------------------------------------------------------------------------
// A DRY RUN IS A QUESTION ABOUT A DECISION AND NOT ONE (2026-09-06).
//
// `preview: true` on the request means NOTHING IS BEING ISSUED — somebody is
// looking at a page that says what would happen. Two things must not follow
// from that:
//
//   * **No audit row.** `xacml.issuance.refused` says this service refused to
//     issue something, and it did not: nobody asked it to. A page that listed
//     forty applications and permitted two would otherwise write thirty-eight
//     of those rows on every load, into a ring that holds 5,000 events — so
//     drawing a page would push real refusals out of the log.
//   * **No counter.** `/admin/xacml/monitor` answers "what is this service
//     actually deciding", and its own header keeps a decision apart from an
//     enforcement precisely so the number means something. A hypothetical is
//     neither.
//
// **THE DECISION ITSELF IS IDENTICAL.** The flag reaches nothing above the two
// funnels: same policy, same PIP, same request, same answer — which is what
// keeps a preview worth having at all. `issuance_gate.js` needed no change,
// because it hands the request through untouched.
//
// It is held in a module variable rather than threaded through the eleven
// return sites, and SAVED AND RESTORED rather than merely set: `decide()` is
// synchronous from end to end — its own header in `issuance_gate.js` says why
// it must stay so — so nothing can interleave, and the save/restore is what
// makes that a property of this code rather than of an assumption about its
// callers.
//
// Two callers set it: `preview()` below, which is the console's dry run at
// `/admin/roles` and had been writing those rows since it was written, and the
// user portal's applications page, which asks this question once per
// application every time somebody opens it.
// ---------------------------------------------------------------------------
let dryRun = false;

class XacmlRolePep {
  static readonly ATTRIBUTE = ATTRIBUTE;

  constructor(private readonly deps: XacmlRolePepDeps) {
    deps.log.debug("Entering XacmlRolePep.constructor().");
    deps.log.debug("Leaving XacmlRolePep.constructor().");
  }

  issuancePolicyName(): string {
    const { log, config } = this.deps;
    log.debug("Entering XacmlRolePep.issuancePolicyName().");
    log.debug("Leaving XacmlRolePep.issuancePolicyName().");
    return String(config.value('xacml.issuancePolicy') || 'role-issuance');
  }

  // -------------------------------------------------------------------------
  // THE BUILT-IN ISSUANCE POLICY, AND WHY THIS DOCUMENT IS NOT SEEDED.
  //
  // It was, for one afternoon, and the realm case is what killed it.
  // `ou=policies` is PER REALM and the seed is written once — at require time,
  // in the default realm — so a realm created five minutes later had no
  // issuance policy at all. Every application narrowed in that realm then met
  // the fail-closed branch below and was issued NOTHING, with a sentence
  // naming a policy the administrator had never deleted. A feature that is on
  // by default cannot have a state where creating a realm breaks it.
  //
  // The two alternatives were both worse. Seeding on `realms.onChange` puts a
  // policy in every realm's repository, which changes what `/xacml/policies`
  // answers, what a remote PEP pulls and what every count in
  // `tests/vendored/sts_xacml_endpoints.js` asserts — for a document that has
  // nothing to do with anybody else's boundary. Falling back to the DEFAULT
  // realm's copy couples two realms, which is the one thing the realm design
  // does not do.
  //
  // **SO THE POLICY IS BUILT IN AND A REPOSITORY ENTRY OVERRIDES IT.** Three
  // states, and each says something different:
  //
  //   no entry            the built-in document, identical to what the
  //                       `role-issuance` template builds — because it IS
  //                       that template, called here. Every realm has it, out
  //                       of the box, with nothing seeded and nothing to
  //                       delete.
  //   an entry, enabled   that document. Somebody wrote one, and it wins.
  //   an entry, DISABLED  a deliberate act, and it does NOT fall back:
  //                       somebody took the issuance policy out of the
  //                       decision, which is exactly what the console's
  //                       Disable button is for while editing, and quietly
  //                       evaluating a different document instead would make
  //                       that button a lie.
  //
  // The override is authored the ordinary way — `/admin/xacml/policies`,
  // create from the `role-issuance` template, named whatever
  // `xacml.issuancePolicy` says — so this costs no new control anywhere.
  //
  // **IT IS NOT SENT TO REMOTE PEPs**, which falls out of it not being in the
  // repository and is right rather than incidental: `GET /xacml/pep/policies`
  // carries the policies about somebody ELSE's boundary, and this one is about
  // this service's own issuance. A remote PEP has nothing to enforce with it.
  //
  // Answers `{ policy }` or `{ why }`. Kept apart from the decision below so
  // that "there is no policy" is a state with its own sentence rather than an
  // Indeterminate somebody has to interpret.
  // -------------------------------------------------------------------------
  builtInPolicy(): LoadedPolicy {
    const { log, templates } = this.deps;
    log.debug('Entering XacmlRolePep.builtInPolicy().');
    const built = templates.build('role-issuance', {},
                                  { name: this.issuancePolicyName() });
    if (!built.ok) {
      // A DEFECT AND NOT A STATE. The template is in this repository and takes
      // no required parameter, so it cannot fail for anything an administrator
      // did — which is why this reads as a fault rather than as "there is no
      // policy".
      log.debug('Leaving XacmlRolePep.builtInPolicy(). The template would ' +
                'not build.');
      return { why: 'the built-in issuance policy could not be built from ' +
                    'the `role-issuance` template, which is a defect in this ' +
                    'service rather than a configuration: ' + built.why };
    }
    log.debug('Leaving XacmlRolePep.builtInPolicy(). Built.');
    return { policy: built.policy, name: this.issuancePolicyName(),
             builtIn: true };
  }

  issuancePolicy(): LoadedPolicy {
    const { log, store } = this.deps;
    log.debug('Entering XacmlRolePep.issuancePolicy().');
    const name = this.issuancePolicyName();
    const row = store.read(name);
    if (!row) {
      log.debug('Leaving XacmlRolePep.issuancePolicy(). Using the built-in ' +
                'one.');
      return this.builtInPolicy();
    }
    if (!row.enabled) {
      // A DISABLED POLICY IS A DELIBERATE ACT and reads differently from a
      // missing one, so it says so: somebody took it out of the decision,
      // which is exactly what the console's Disable button is for while
      // editing.
      log.debug('Leaving XacmlRolePep.issuancePolicy(). It is disabled.');
      return { why: 'the policy "' + name + '" is DISABLED, so it is not ' +
                    'evaluated — and this does NOT fall back to the ' +
                    'built-in one, because disabling it is a deliberate act ' +
                    'and a button that quietly evaluated something else ' +
                    'instead would be a lie. Enable it, or delete it and the ' +
                    'built-in policy answers again' };
    }
    try {
      const policy = store.parseDocument(row.document);
      log.debug('Leaving XacmlRolePep.issuancePolicy(). Loaded.');
      return { policy: policy, name: name };
    } catch (error) {
      log.debug('Caught in XacmlRolePep.issuancePolicy(): ' +
                ((error && error.message) || error));
      log.debug('Leaving XacmlRolePep.issuancePolicy(). It will not load.');
      return { why: 'the policy "' + name + '" does not load: ' +
                    error.message };
    }
  }

  // -------------------------------------------------------------------------
  // ONE ATTRIBUTE, MULTI-VALUED.
  //
  // A bag rather than a value everywhere, because every one of these genuinely
  // is one: a party holds several roles and an application requires several.
  // A single-valued spelling would have made the policy's intersection test
  // impossible to write and would have been discovered at the first
  // application that needed two.
  // -------------------------------------------------------------------------
  private attribute(attributeId: string, values: unknown[] | null | undefined,
                    type?: string): any {
    const { log, model } = this.deps;
    log.debug("Entering XacmlRolePep.attribute().");
    log.debug("Leaving XacmlRolePep.attribute().");
    return {
      attributeId: attributeId,
      issuer: null,
      includeInResult: true,
      values: (values || []).map(function (one) {
        return { type: type || model.TYPE.STRING, lexical: String(one) };
      })
    };
  }

  buildRequest(asked: IssuanceQuestion, held: string[], fromToken: string[],
               required: string[]): any {
    const { log, model } = this.deps;
    log.debug('Entering XacmlRolePep.buildRequest().');
    const subjectAttributes = [
      this.attribute(model.ATTRIBUTE.SUBJECT_ID, [asked.subject.name || '']),
      this.attribute(ATTRIBUTE.ROLE, held),
      this.attribute(ATTRIBUTE.TOKEN_ROLE, fromToken)
    ];
    const request = {
      returnPolicyIdList: true,
      combinedDecision: false,
      categories: [
        { category: model.CATEGORY.ACCESS_SUBJECT, id: null, content: null,
          attributes: subjectAttributes },
        { category: model.CATEGORY.RESOURCE, id: null, content: null,
          attributes: [
            // THE APPLICATION IS THE RESOURCE-ID and it is a STRING rather
            // than an anyURI, unlike `/admin/xacml/decide`'s. An application
            // handle here is a client_id, a wtrealm or a SAML entityID slug,
            // and only some of those are URIs — typing them all as anyURI
            // would make the ones that are not fail to parse and take the
            // decision Indeterminate, which under deny-unless-permit refuses
            // everybody with a message about a datatype.
            this.attribute(model.ATTRIBUTE.RESOURCE_ID, [asked.application]),
            this.attribute(ATTRIBUTE.REQUIRED_ROLE, required)
          ] },
        { category: model.CATEGORY.ACTION, id: null, content: null,
          attributes: [this.attribute(model.ATTRIBUTE.ACTION_ID,
                                      [asked.kind])] },
        { category: model.CATEGORY.ENVIRONMENT, id: null, content: null,
          attributes: [] }
      ]
    };
    log.debug('Leaving XacmlRolePep.buildRequest().');
    return request;
  }

  // -------------------------------------------------------------------------
  // THE DECISION.
  // -------------------------------------------------------------------------
  decide(asked: IssuanceQuestion): IssuanceAnswer {
    const { log } = this.deps;
    log.debug("Entering XacmlRolePep.decide().");
    const outer = dryRun;
    dryRun = !!(asked && asked.preview);
    try {
      log.debug("Leaving XacmlRolePep.decide().");
      return this.decideNow(asked);
    } finally {
      dryRun = outer;
    }
  }

  private decideNow(asked: IssuanceQuestion): IssuanceAnswer {
    const { log, config, audit, errorCodes, applications, roles, model,
            store, pdp, pip } = this.deps;
    log.debug('Entering XacmlRolePep.decideNow(). application=' +
              asked.application + ' kind=' + asked.kind +
              (dryRun ? ' (a dry run: nothing is audited or counted)' : ''));

    if (config.value('xacml.enabled') === false) {
      log.debug('Leaving XacmlRolePep.decideNow(). The XACML family is ' +
                'switched off.');
      return this.allowed('xacml.enabled is off, so no policy is evaluated ' +
                          'at all.', [], []);
    }

    const subject = asked.subject || {};
    const required = applications.requiredRolesOf(asked.application);
    const held = roles.rolesOf(subject);
    const fromToken = roles.rolesInClaims(asked.claims);
    const narrowed = applications.requiresNarrowedRoles(asked.application);

    const loaded = this.issuancePolicy();
    if (!loaded.policy) {
      // The split the header argues. Both halves log; only one refuses.
      if (!narrowed) {
        if (!warnedAboutMissingPolicy) {
          warnedAboutMissingPolicy = true;
          log.warn(errorCodes.tag('STS-XACML-0043') +
                   'xacml: ' + loaded.why + '. Issuance is NOT being gated: ' +
                   'every application that has not been narrowed requires ' +
                   'EVERYBODY, which everybody holds, so nothing is refused ' +
                   'that would have been permitted. An application whose ' +
                   'entry names a role WILL be refused until it is back — ' +
                   'enable it, or delete it on /admin/xacml/policies and the ' +
                   'BUILT-IN issuance policy answers again.');
        }
        log.debug('Leaving XacmlRolePep.decideNow(). No policy, and nothing ' +
                  'narrowed.');
        return this.allowed('No issuance policy is loaded, and "' +
                            asked.application + '" requires only ' +
                            roles.DEFAULT_REQUIRED_ROLE +
                            ', which everybody holds.',
                            held, required);
      }
      log.debug('Leaving XacmlRolePep.decideNow(). No policy, and this ' +
                'application is narrowed.');
      // FAIL-CLOSED, and until error codes it wrote no audit row at all: the
      // issuance site answers in its own protocol's words and this is the only
      // record of WHY. Not on a dry run, for the reason the block above
      // decide() gives.
      if (!dryRun) {
        audit.failure('STS-XACML-0042', {
          action: 'xacml.issuance.refused',
          protocol: 'XACML', channel: 'internal',
          actor: subject.name || '', target: String(asked.application || ''),
          summary: 'Refused ' + (asked.kind || 'an issuance') + ' for a ' +
                   'narrowed application because no issuance policy is ' +
                   'loaded.',
          outcome: 'refused'
        });
      }
      log.debug("Leaving XacmlRolePep.decideNow().");
      return this.refused(
        'This application requires ' + required.join(' or ') + ', and ' +
        loaded.why + ' — so the restriction cannot be evaluated. It is ' +
        'refused rather than permitted BECAUSE somebody asked for it: an ' +
        'application that requires only ' + roles.DEFAULT_REQUIRED_ROLE +
        ' would have been let through. Enable or delete the policy on ' +
        '/admin/xacml/policies — deleting it puts the BUILT-IN issuance ' +
        'policy back, which is what a service that never had one uses — or ' +
        'clear appRequiredRole on the application.',
        'NotApplicable', held, required, null);
    }

    const request = this.buildRequest(asked, held, fromToken, required);
    const answer = pdp.evaluate(loaded.policy, request, {
      repository: store.repository(),
      // THE SAME PIP THE PUBLIC ENDPOINT USES. A decision made here against a
      // different attribute source from the one `/xacml/pdp` and
      // `/admin/xacml/decide` use would be a decision nobody could reproduce
      // on the page built to reproduce it — which is the drift `xacml.ts`'s
      // `decide()` exists to prevent, and this is the second caller that has
      // to honour it.
      resolver: pip.resolverFor(request)
    });

    if (answer.decision === model.DECISION.PERMIT) {
      log.debug('Leaving XacmlRolePep.decideNow(). Permit.');
      return this.allowed('The issuance policy permitted it.', held, required,
                          answer);
    }

    // EVERYTHING ELSE REFUSES, and the sentence says which of the three it
    // was, because they mean quite different things to whoever has to fix it:
    // a Deny is the policy working, a NotApplicable is a policy that did not
    // cover the question, and an Indeterminate is a policy that could not be
    // evaluated.
    const why = this.reasonFor(answer, held, required, asked);
    if (!dryRun) {
      audit.audit({
        action: 'xacml.issuance.refused',
        errorCode: answer.decision === model.DECISION.DENY ? 'STS-XACML-0039'
          : (answer.decision === model.DECISION.NOT_APPLICABLE
              ? 'STS-XACML-0040' : 'STS-XACML-0041'),
        actor: subject.name || '',
        protocol: 'XACML',
        detail: answer.decision + ' for ' + (asked.kind || 'an issuance') +
                ' to "' + asked.application + '": ' + why
      });
    }
    log.info('xacml: ' +
             (dryRun ? 'a dry run would have REFUSED ' : 'REFUSED ') +
             (asked.kind || 'an issuance') + ' for "' +
             asked.application + '" to "' + (subject.name || 'nobody') +
             '" — ' + answer.decision + '. ' + why);
    log.debug('Leaving XacmlRolePep.decideNow(). ' + answer.decision + '.');
    return this.refused(why, answer.decision, held, required, answer);
  }

  private reasonFor(answer: any, held: string[], required: string[],
                    asked: IssuanceQuestion): string {
    const { log, model } = this.deps;
    log.debug("Entering XacmlRolePep.reasonFor().");
    const who = asked.subject && asked.subject.name
      ? '"' + asked.subject.name + '"' : 'the caller';
    if (answer.decision === model.DECISION.DENY ||
        answer.decision === model.DECISION.NOT_APPLICABLE) {
      log.debug("Leaving XacmlRolePep.reasonFor().");
      return '"' + asked.application + '" requires ' +
        (required.length ? required.join(' or ') : 'a role nothing named') +
        ' and ' + who + ' holds ' +
        (held.length ? held.join(', ') : 'no role at all') + '.';
    }
    const status = (answer.status && answer.status.message) || '';
    log.debug("Leaving XacmlRolePep.reasonFor().");
    return 'the issuance policy could not be evaluated' +
      (status ? ': ' + status : '') + '. Nothing is issued on an ' +
      'Indeterminate, because the alternative is issuing on an error.';
  }

  // -------------------------------------------------------------------------
  // THE TWO FUNNELS EVERY ANSWER PASSES THROUGH, AND SINCE 2026-09-06 THEY
  // COUNT.
  //
  // `xacml_monitor.ts` is told here rather than at the eleven return sites
  // above, and that is the reason this pair existed before the counting did: a
  // return path added later is counted BY CONSTRUCTION rather than by whoever
  // adds it remembering to. The same argument `delegation.js` makes for its
  // own funnel.
  //
  // `record()` never throws — its header says why at length, and this is the
  // call site the argument is about: every issuance in this service comes
  // through here, so a counter that could fail would be a monitoring feature
  // causing the outage it exists to show.
  // -------------------------------------------------------------------------
  private allowed(why: string, held: string[], required: string[],
                  answer?: any): IssuanceAnswer {
    const { log, model, monitor } = this.deps;
    log.debug("Entering XacmlRolePep.allowed().");
    const decision = answer ? answer.decision : model.DECISION.NOT_APPLICABLE;
    // NOT ON A DRY RUN. See the block above `decide()`: the monitor answers
    // what this service is actually deciding, and a page asking what WOULD
    // happen is not an issuance. It is skipped here rather than by the caller
    // so that both funnels obey it — which is the same argument this pair
    // exists for.
    if (!dryRun) {
      monitor.record('issuance', { decision: decision, allowed: true });
    }
    log.debug("Leaving XacmlRolePep.allowed().");
    return { allowed: true,
             decision: decision,
             why: why, roles: held || [], required: required || [],
             policy: this.issuancePolicyName() };
  }

  private refused(why: string, decision: string, held: string[],
                  required: string[], answer: any): IssuanceAnswer {
    const { log, monitor } = this.deps;
    log.debug("Entering XacmlRolePep.refused().");
    if (!dryRun) {
      monitor.record('issuance', { decision: decision, allowed: false });
    }
    log.debug("Leaving XacmlRolePep.refused().");
    return { allowed: false, decision: decision, why: why,
             roles: held || [], required: required || [],
             policy: this.issuancePolicyName(),
             status: answer ? answer.status : null };
  }

  // -------------------------------------------------------------------------
  // WHICH OF THE THREE STATES THE ISSUANCE POLICY IS IN, for the console.
  //
  // It answers an OBJECT and not the name, because the name is the one thing
  // /admin/roles already knows — `xacml.issuancePolicy` is a setting drawn on
  // that very page — and the three states read completely differently to
  // somebody looking at a refusal: the built-in document, an override
  // somebody wrote, and an override somebody disabled, which is the only one
  // of the three where a narrowed application is refused.
  // -------------------------------------------------------------------------
  issuancePolicyState(): Record<string, any> {
    const { log, store } = this.deps;
    log.debug('Entering XacmlRolePep.issuancePolicyState().');
    const name = this.issuancePolicyName();
    const loaded = this.issuancePolicy();
    // WHETHER THERE IS AN ENTRY IS A SEPARATE FACT FROM WHETHER ONE IS
    // DECIDING, and the console needs both. `builtIn` alone cannot tell
    // "nobody has written an override" from "somebody wrote one and disabled
    // it" — and those are opposite situations: the first is the ordinary
    // state of every realm, and the second is a deliberate act that takes
    // this policy OUT of the decision without falling back.
    const row = store.read(name);
    const out = { name: name, ok: !!loaded.policy,
                  builtIn: !!loaded.builtIn, why: loaded.why || '',
                  setting: 'xacml.issuancePolicy',
                  template: 'role-issuance',
                  entry: !!row,
                  enabled: row ? !!row.enabled : null,
                  effect: '' };
    out.effect = out.ok
      ? (out.builtIn
          ? 'The BUILT-IN document decides. It is what the `role-issuance` ' +
            'template builds, called rather than seeded, so every realm has ' +
            'it with nothing written down and nothing to delete.'
          : 'The repository entry "' + name + '" decides. It overrides the ' +
            'built-in document.')
      : 'NOTHING IS BEING EVALUATED: ' + loaded.why;
    log.debug('Leaving XacmlRolePep.issuancePolicyState(). ' +
              (out.ok ? (out.builtIn ? 'Built in.' : 'Overridden.')
                      : 'Not evaluated.'));
    return out;
  }

  // -------------------------------------------------------------------------
  // A DRY RUN, FOR THE CONSOLE.
  //
  // The same decision, asked without anything being issued, so that
  // `/admin/roles` can answer "would alice get a token for this application"
  // without somebody having to try it. It goes through `decide()` rather than
  // reimplementing it — a preview that agreed with the enforcement only by
  // coincidence is worse than no preview.
  // -------------------------------------------------------------------------
  preview(question?: IssuanceQuestion | null): IssuanceAnswer {
    const { log, gate } = this.deps;
    log.debug('Entering XacmlRolePep.preview().');
    const asked = question || {};
    const answer = this.decide({
      application: String(asked.application || ''),
      kind: asked.kind || gate.ISSUANCE.ACCESS_TOKEN,
      subject: asked.subject ||
        { kind: 'user', name: '', authenticated: false },
      claims: asked.claims || null,
      // A DRY RUN, AND SAYING SO IS A FIX RATHER THAN A NEW FEATURE. This
      // function has always been `/admin/roles`'s "would alice be issued a
      // token" button, and every refused preview it answered wrote an
      // `xacml.issuance.refused` audit row and moved a counter on
      // /admin/xacml/monitor — for an issuance nobody had asked for. The
      // decision is unchanged; what stops is the recording of it.
      preview: true
    });
    log.debug('Leaving XacmlRolePep.preview(). ' +
              (answer.allowed ? 'Permit.' : 'Refused.'));
    return answer;
  }
}

// THE TRANSITIONAL INSTANCE — see the header. Built from the real modules, as
// the composition root will build one. `decide` is bound ONCE, so the gate and
// this module's exports hold the same function.
const pep = new XacmlRolePep({
  log: helpers.log,
  config: config,
  audit: audit,
  errorCodes: errorCodes,
  applications: applications,
  roles: roles,
  gate: gate,
  model: model,
  store: store,
  monitor: monitor,
  pdp: pdp,
  pip: pip,
  templates: templates
});
const decide = pep.decide.bind(pep) as XacmlRolePep['decide'];
const preview = pep.preview.bind(pep) as XacmlRolePep['preview'];
const issuancePolicyState = pep.issuancePolicyState.bind(pep) as
  XacmlRolePep['issuancePolicyState'];

// ---------------------------------------------------------------------------
// FILL THE SLOT.
//
// At require time, which is what `xacml/xacml.ts` requiring this file at 23c
// buys: from that moment every issuance site's call to
// `issuance_gate.check()` reaches the engine. Before it — and in any process
// that never loads the XACML family — the gate answers "allowed" and this
// service is what it always was.
// ---------------------------------------------------------------------------
// AND THE CONSOLE'S PREVIEW, which is admin.js's `setRolePreviewer()` slot.
// Filled from here rather than that module requiring this one, and rule 3e's
// test answers yes both ways round: a require from `admin-ui/admin.ts` (18) to
// this file would load the XACML engine there and — much worse — fill the
// DECIDER above from the console, so a process that loaded the console and not
// `xacml/xacml.ts` would gate every issuance in the service with half this
// family present. A require from here to `admin.js` would close a cycle,
// because `xacml_admin.ts` requires it for the page shell.
//
// It carries TWO functions and `admin.js` validates them together: a preview
// that could be installed without `policy()` would be a page able to ask the
// question and unable to say which document answered.
//
// The console is required HERE, where the original required it, and not with
// the imports at the top — so it is loaded after everything above, as it
// always was. A plain require, because an `import` is emitted at the top.
const admin = require('../admin-ui/admin');
if (typeof admin.setRolePreviewer === 'function') {
  admin.setRolePreviewer({ preview: preview, policy: issuancePolicyState });
} else {
  helpers.log.warn('xacml: admin-ui/admin.ts offers no setRolePreviewer(), ' +
                   'so /admin/roles cannot preview an issuance decision. ' +
                   'Enforcement is unaffected — the gate below is what ' +
                   'decides.');
}

if (typeof gate.setDecider === 'function') {
  gate.setDecider(decide);
} else {
  helpers.log.warn('xacml: common/issuance_gate.js offers no setDecider(), ' +
                   'so issuance is not gated by policy. Every other part of ' +
                   'the XACML family is unaffected.');
}

export = {
  XacmlRolePep: XacmlRolePep,
  decide: decide,
  builtInPolicy: pep.builtInPolicy.bind(pep) as XacmlRolePep['builtInPolicy'],
  issuancePolicyState: issuancePolicyState,
  preview: preview,
  issuancePolicy: pep.issuancePolicy.bind(pep) as
    XacmlRolePep['issuancePolicy'],
  issuancePolicyName: pep.issuancePolicyName.bind(pep) as
    XacmlRolePep['issuancePolicyName'],
  buildRequest: pep.buildRequest.bind(pep) as XacmlRolePep['buildRequest'],
  ATTRIBUTE: XacmlRolePep.ATTRIBUTE
};
