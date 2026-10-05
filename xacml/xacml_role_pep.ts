// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

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
//                    urn:sts:xacml:requested-scope the scope values asked for
//   access-subject   urn:sts:xacml:client-id       the client, where named
//   environment      urn:sts:xacml:grant-type      the OAuth grant, where any
//                    urn:sts:xacml:protocol        the protocol family
//                                                  (#304: these four since C)
//
// **AND A SECOND QUESTION, ONE PER REQUESTED SCOPE (#304, part C of #88).**
// action-id `issue-scope`, the scope as the resource-id, whether its resource
// gates it (`urn:sts:xacml:scope-gated`) and which roles authorize it
// (`urn:sts:xacml:authorizing-role`) on the resource, the subject's roles on
// the subject. The answer's scope obligation says keep, drop or refuse, with
// a code; no verdict falls back to the BUILT-IN policy — `decideScopes()`.
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
// **THE ARMING STILL HAPPENS AT LOAD, AND IN THE ORIGINAL ORDER.** Since
// #50's R2 the composition root builds the instance and installs it here, and
// every old name is exported as a FACADE forwarding to it. The code at the
// bottom — exactly where the original did, after everything else in this
// file — requires `admin-ui/admin`, fills its `setRolePreviewer()` slot, and
// fills `common/issuance_gate.js`'s decider with the `decide` facade, built
// ONCE so the function the gate holds is the function this module exports.
// Passing a facade resolves nothing, so both fills stay at load and need no
// `wire` step. A process without the root builds a default when this module
// loads. `XacmlRolePep` is exported for the root.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
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
// THE ONE REQUEST BUILDER (#306): every PEP's request is made there.
import xacmlRequest = require('./xacml_request');
// THE PER-SCOPE QUESTION, asked one way (#304, #305).
import scopeVerdicts = require('./xacml_scope_verdicts');
// THE TRANSFER QUESTIONS (#98 D4), asked the one way the gate asks them too.
import transferVerdicts = require('./xacml_transfer_verdicts');
// #186: who may act for whom, asked the same way by the gate.
import exchangeVerdicts = require('./xacml_exchange_verdicts');
// #432 phase 3: one question per GNAP access right, asked the same way by
// the gate.
import gnapRightVerdicts = require('./xacml_gnap_right_verdicts');
const { AuthorizationRequest } = xacmlRequest;

// The question an issuance site asks, through `common/issuance_gate.js`.
interface IssuanceQuestion {
  application?: any;
  kind?: string;
  subject?: any;
  claims?: any;
  preview?: boolean;
  // The RISK of the authentication this issuance rests on (#62 P3), as
  // `risk/risk_engine.ts`'s `factsOf()` states it: level, score, signals,
  // the step-ups already met, and whether a risk Deny is ENFORCED here
  // (product) or only recorded (development). Absent — nothing assessed —
  // puts no risk attribute in the request, and the risk rules do not apply.
  risk?: RiskFacts | null;
  // The ROLE question is waived — nothing named an application, or
  // `roles.enforceIssuance` is off — and the policy is asked only because
  // there are risk facts. A Deny that is not about risk is then not a
  // refusal. See `common/issuance_gate.js`.
  rolesWaived?: boolean;
  // THE AUTHENTICATION A SESSION STANDS ON (#64): `{ amr, acr, kinds }`,
  // named by `authn.startSession()` and by nothing else.
  authentication?: { amr?: string[]; acr?: string; kinds?: string[] } | null;
  // WHO MAY ACT FOR WHOM (#186): present, this is the exchange question
  // `issuance_gate.checkExchange()` asks, answered with a verdict
  // (`decideExchange()`).
  exchangeQuestion?: Record<string, any> | null;
  // THE REGISTERED DEVICE (#164 phase 6): the recognition fact, brought up
  // to date by the gate, or null for none; and what the realm requires of
  // one (`issuance_gate.deviceRequirementOf()`). A question with no
  // requirement array — a delegation, a caller that went round the gate —
  // carries no device attribute, and every device rule is inapplicable.
  device?: any;
  deviceRequirement?: string[];
  // THE PROTOCOL DECLARATION (2026-10-01): the families this issuance
  // satisfies, the families the application is declared for, and the realm's
  // mode — named by the gate only where the application is declared for
  // something. Absent, no protocol attribute is sent and the rule does not
  // apply.
  protocolFamilies?: string[];
  declaredProtocols?: string[];
  mode?: string;
  // WHAT THE REQUEST CARRIES (#304, part C of #88): the scope values asked
  // for, the client it came through, the grant type and the protocol — sent
  // to the policy on every issuance question where the caller names them.
  scopes?: string[];
  client?: string;
  grantType?: string;
  protocol?: string;
  // THE PER-SCOPE QUESTION (#304): present, this is not an issuance question
  // but one question per requested scope, answered with a verdict each
  // (`decideScopes()`).
  scopeQuestion?: ScopeQuestion | null;
  // THE TRANSFER QUESTION (#98 D4): present, this is `hold-session`,
  // `serve-request` or `release-attributes`, asked by
  // `common/cell_transfer.ts` through `issuance_gate.checkTransfer()`, and
  // answered with a verdict (`decideTransfer()`).
  transferQuestion?: Record<string, any> | null;
  // THE PER-RIGHT GNAP QUESTION (#432 phase 3): present, one question per
  // GNAP access right, answered with a verdict each
  // (`decideGnapRights()`).
  gnapRightQuestion?: Record<string, any> | null;
}

// One requested scope (or RFC 9396 detail), with the facts the policy
// decides it on (#304, #305): each fact an attribute, sent only by the
// subsystem that knows it. `gated` is kept beside them for the one reading
// that needs no policy — a defect where not even the built-in one answers.
interface ScopeFact {
  scope: string;
  gated?: boolean;
  attributes?: Array<{ category: string; id: string; values: unknown[];
                       type?: string }>;
}

// The per-scope question: the subject's configured roles, each fact, and the
// environment the rules read (mode, settings, stage, consent-required).
interface ScopeQuestion {
  held?: string[];
  facts: ScopeFact[];
  action?: string;
  requested?: string[];
  mode?: string;
  settings?: Record<string, unknown>;
  stage?: string;
  consentRequired?: boolean;
  client?: string;
  grantType?: string;
  protocol?: string;
}

// One scope's verdict.
interface ScopeVerdict {
  scope: string;
  verdict: string;
  code: string;
  // Which document decided: the issuance policy, or the built-in one it
  // fell back to (#304's decision) — `none` when neither could.
  decidedBy: string;
}

// The risk facts, as the gate hands them on.
interface RiskFacts {
  level: string;
  score: number | null;
  signals: string[];
  satisfied: string[];
  enforced: boolean;
  assessmentId?: string;
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
  // The risk rule that denied (#62 P3): `refuse`, or `step-up` with the
  // factor to ask for. `observed` when development let it through.
  risk?: { action: string; factor: string; observed: boolean } | null;
  // The device rule that denied (#164 phase 6): `compromised` or
  // `not-compliant`.
  device?: { refusal: string } | null;
  // The protocol rule that denied (2026-10-01): the declaration and the
  // families this issuance satisfies.
  protocolRefused?: { declared: string[]; families: string[] } | null;
  // The per-scope verdicts, for a scope question (#304).
  scopes?: ScopeVerdict[];
  // The verdict on a transfer question (#98): `hold` / `relay`, `serve` /
  // `refuse` or `release` / `withhold`, and which document decided.
  transfer?: { verdict: string; decidedBy: string } | null;
  // The exchange verdict (#186), `xacml_exchange_verdicts.js`'s shape.
  exchange?: Record<string, any> | null;
  // The per-right verdicts, for a GNAP right question (#432).
  gnapRights?: Array<Record<string, any>>;
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
  // THE STEP-UPS A PERSON COULD ANSWER (#226), for `RISK.HELD`: what they
  // hold, not what this authentication carried. Optional, so a test's PEP
  // built without it sends none — and a policy then reads "holds nothing".
  heldFactors?: (username: string) => string[];
  templates: { build(id: string, answers: any, options: any): any;
               ISSUANCE_ATTRIBUTE: Record<string, string>;
               DEVICE_ATTRIBUTE?: Record<string, string>;
               PROTOCOL_ATTRIBUTE?: Record<string, string> };
}

const ATTRIBUTE = templates.ISSUANCE_ATTRIBUTE;

const RISK = templates.RISK_ATTRIBUTE;
// #164 phase 6: the registered device an issuance came from.
const DEVICE = templates.DEVICE_ATTRIBUTE;
// The protocol families an issuance satisfies and the application's
// declaration (2026-10-01).
const PROTOCOL = templates.PROTOCOL_ATTRIBUTE;
// #64: the authentication a session stands on.
const AUTHN = templates.AUTHN_ATTRIBUTE;

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

/**
 * The embedded policy enforcement point for this service's own issuance:
 * turns each issuance `common/issuance_gate.js` asks about into an XACML
 * request and refuses what the issuance policy does not permit.
 */
class XacmlRolePep {
  /**
   * The attribute identifiers of the issuance request (roles held, roles
   * from a token, required roles, subject kind).
   */
  static readonly ATTRIBUTE = ATTRIBUTE;

  /**
   * Builds the enforcement point over its dependencies.
   *
   * @param deps - the logger, configuration, audit log, error codes,
   *   application and role registers, the gate, the engine, the policy
   *   store, the monitor, the PIP, the templates and `heldFactors()`
   */
  constructor(private readonly deps: XacmlRolePepDeps) {
    deps.log.debug("Entering XacmlRolePep.constructor().");
    deps.log.debug("Leaving XacmlRolePep.constructor().");
  }

  // What the composition root passes, from the real modules.
  /**
   * Returns the dependencies built from the real modules, as the
   * composition root passes them.
   *
   * @returns the dependencies
   */
  static defaultDeps(): XacmlRolePepDeps {
    helpers.log.debug("Entering XacmlRolePep.defaultDeps().");
    helpers.log.debug("Leaving XacmlRolePep.defaultDeps().");
    return {
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
      templates: templates,
      // `common/credentials.ts` reaches the directory, which is built long
      // after this module (23c against 21); asked when a decision is made.
      heldFactors: function heldFactors(username: string): string[] {
        helpers.log.debug("Entering heldFactors().");
        const held: string[] = [];
        try {
          const m = require('../common/credentials').mechanismsFor(username);
          if (m.mfaKeys + m.primaryKeys > 0) {
            held.push('security-key', 'second-factor');
          } else if (m.totp) {
            held.push('second-factor');
          }
        } catch (e) {
          // A person whose credentials cannot be read holds nothing this
          // decision can count on; the policy then treats them as holding
          // no factor, which for a protected application is the alarm.
          helpers.log.debug("Caught in heldFactors(): " +
                            ((e && e.message) || e));
        }
        helpers.log.debug("Leaving heldFactors(). " + held.join(', '));
        return held;
      }
    };
  }

  /**
   * Returns the name of the issuance policy, from `xacml.issuancePolicy`
   * (`role-issuance` when unset).
   *
   * @returns the policy name
   */
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
  /**
   * Builds the built-in issuance policy from the `role-issuance` template.
   *
   * @returns `{ policy, name, builtIn: true }`, or `{ why }` when the
   *   template will not build, which is a defect rather than a state
   */
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

  /**
   * Loads the issuance policy that decides in this realm.
   *
   * A repository entry of that name overrides the built-in document; with
   * no entry the built-in one answers. A DISABLED entry does not fall back.
   * @returns `{ policy, name }` (with `builtIn` for the built-in one), or
   *   `{ why }` when the entry is disabled or does not load
   */
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

  /**
   * Builds the XACML request for one issuance question.
   *
   * The subject's name, kind, held roles and token roles; the application
   * as a string resource-id with its required roles; the issuance kind as
   * the action; and the risk, authentication and device facts as
   * environment attributes, each only when present. Through the one
   * builder every PEP uses (`xacml_request.js`, #306).
   * @param asked - the issuance question
   * @param held - the roles the subject holds
   * @param fromToken - the roles read from a token the subject presented
   * @param required - the roles the application requires
   * @returns the request, in the shapes of `xacml_model.js`
   */
  buildRequest(asked: IssuanceQuestion, held: string[], fromToken: string[],
               required: string[]): any {
    const { log } = this.deps;
    log.debug('Entering XacmlRolePep.buildRequest().');
    const request = this.requestFor(asked, held, fromToken, required).build();
    log.debug('Leaving XacmlRolePep.buildRequest().');
    return request;
  }

  // The request before it is built, so the delegation question can add its
  // intermediary and its two attributes to the same one.
  private requestFor(asked: IssuanceQuestion, held: string[],
                     fromToken: string[], required: string[]): any {
    const { log, model } = this.deps;
    log.debug('Entering XacmlRolePep.requestFor().');
    const subject = asked.subject || {};
    const req = new AuthorizationRequest({ includeInResult: true })
      // #303: person or application, so a policy can tell them apart by more
      // than which built-in role matched.
      .principal(subject.name || '',
                 subject.kind === 'application' ? 'application' : 'user')
      .roles(held)
      .subject(ATTRIBUTE.TOKEN_ROLE, fromToken)
      // THE APPLICATION IS THE RESOURCE-ID and it is a STRING rather than an
      // anyURI, unlike `/admin/xacml/decide`'s. An application handle here is
      // a client_id, a wtrealm or a SAML entityID slug, and only some of
      // those are URIs — typing them all as anyURI would make the ones that
      // are not fail to parse and take the decision Indeterminate, which
      // under deny-unless-permit refuses everybody with a message about a
      // datatype.
      .target(asked.application)
      .resource(ATTRIBUTE.REQUIRED_ROLE, required)
      .requestedAction(asked.kind);
    // WHAT THE REQUEST CARRIES (#304), where the caller named it: the scope
    // values asked for, the client, the grant type and the protocol.
    if (Array.isArray(asked.scopes)) {
      req.requestedScopes(asked.scopes);
    }
    if (asked.client) {
      req.client(asked.client);
    }
    // THE ENVIRONMENT IS ALWAYS SENT, empty or not, as it always was.
    req.category(model.CATEGORY.ENVIRONMENT);
    if (asked.grantType) {
      req.grantType(asked.grantType);
    }
    if (asked.protocol) {
      req.protocol(asked.protocol);
    }
    this.riskAttributes(req, asked.risk, String(subject.name || ''));
    this.authenticationAttributes(req, asked.authentication);
    this.deviceAttributes(req, asked);
    // THE PROTOCOL DECLARATION, only where the gate named both halves: the
    // declaration on the resource (it is a fact about the application), the
    // families and the mode in the environment (facts about this request).
    const declared = asked.declaredProtocols || [];
    const families = asked.protocolFamilies || [];
    if (declared.length && families.length) {
      req.resource(PROTOCOL.DECLARED, declared);
      req.environment(PROTOCOL.FAMILY, families);
      if (asked.mode) {
        req.mode(asked.mode);
      }
    }
    log.debug('Leaving XacmlRolePep.requestFor().');
    return req;
  }

  // -------------------------------------------------------------------------
  // THE RISK FACTS AS ENVIRONMENT ATTRIBUTES (#62 P3). None at all when there
  // are none: an absent level is what makes the risk rules inapplicable, and
  // an empty string would be a level nobody wrote a rule for. The score goes
  // only when there is one — a first sign-in is UNSCORED and has none.
  // -------------------------------------------------------------------------
  private riskAttributes(req: any, risk: RiskFacts | null | undefined,
                         username: string): void {
    const { log, model, heldFactors } = this.deps;
    log.debug("Entering XacmlRolePep.riskAttributes().");
    if (!risk || !risk.level) {
      log.debug("Leaving XacmlRolePep.riskAttributes(). No facts.");
      return;
    }
    req.environment(RISK.LEVEL, [risk.level])
      .environment(RISK.SIGNAL, risk.signals || [])
      .environment(RISK.SATISFIED, risk.satisfied || [])
      // What the person holds (#226) — asked only when there are risk
      // facts, since no risk rule reads it otherwise.
      .environment(RISK.HELD, heldFactors && username
        ? heldFactors(username) : []);
    if (typeof risk.score === 'number' && isFinite(risk.score)) {
      req.environment(RISK.SCORE, [risk.score], model.TYPE.DOUBLE);
    }
    log.debug("Leaving XacmlRolePep.riskAttributes().");
  }

  // -------------------------------------------------------------------------
  // THE AUTHENTICATION A SESSION STANDS ON (#64), as environment attributes:
  // `amr`, `acr` and the credential kinds. Sent only by a caller that names
  // them — the session's start — and none otherwise, so a rule about them is
  // inapplicable to every other issuance.
  // -------------------------------------------------------------------------
  private authenticationAttributes(req: any, facts: any): void {
    const { log } = this.deps;
    log.debug("Entering XacmlRolePep.authenticationAttributes().");
    if (!facts) {
      log.debug("Leaving XacmlRolePep.authenticationAttributes(). None.");
      return;
    }
    req.environment(AUTHN.AMR, (facts.amr || []).map(String))
      .environment(AUTHN.CREDENTIAL_KIND,
                   (facts.kinds || []).filter(Boolean).map(String));
    if (facts.acr) {
      req.environment(AUTHN.ACR, [String(facts.acr)]);
    }
    log.debug("Leaving XacmlRolePep.authenticationAttributes().");
  }

  // -------------------------------------------------------------------------
  // THE REGISTERED DEVICE AS ENVIRONMENT ATTRIBUTES (#164 decision 3, phase
  // 6) — `xacml_templates.ts`'s DEVICE_ATTRIBUTE. Sent only where the gate
  // asked the device question (a requirement array, however empty); then
  // `recognized` always, the requirement bag always, and the rest only for a
  // device in hand. Whether it is the subject's OWN is decided here, from
  // the subject the gate names: a person's device for that person, an
  // application's for that application (a `client_credentials` grant's
  // subject is the client).
  // -------------------------------------------------------------------------
  private deviceAttributes(req: any, asked: IssuanceQuestion): void {
    const { log, model } = this.deps;
    log.debug("Entering XacmlRolePep.deviceAttributes().");
    if (!Array.isArray(asked.deviceRequirement)) {
      log.debug("Leaving XacmlRolePep.deviceAttributes(). Not asked.");
      return;
    }
    const fact = asked.device || null;
    req.environment(DEVICE.REQUIREMENT, asked.deviceRequirement)
      .environment(DEVICE.RECOGNIZED, [!!fact], model.TYPE.BOOLEAN);
    if (fact) {
      const subject = asked.subject || {};
      const ownerKind = subject.kind === 'application' ? 'application'
                                                       : 'person';
      const owned = fact.ownerKind === ownerKind && !!subject.name &&
        String(fact.ownerName || '') === String(subject.name);
      req.environment(DEVICE.ID, [String(fact.id || '')])
        .environment(DEVICE.VIA, [String(fact.via || '')])
        .environment(DEVICE.OWNER_MATCHES, [owned], model.TYPE.BOOLEAN)
        .environment(DEVICE.OWNER_KIND, [String(fact.ownerKind || '')])
        .environment(DEVICE.COMPLIANCE, [String(fact.compliance || 'unknown')])
        .environment(DEVICE.ATTESTATION,
                     [String(fact.attestation || 'self-asserted')])
        .environment(DEVICE.STATUS, [String(fact.status || 'active')]);
      if (fact.riskLevel) {
        req.environment(DEVICE.RISK_LEVEL, [String(fact.riskLevel)]);
      }
    }
    log.debug("Leaving XacmlRolePep.deviceAttributes(). " +
              (fact ? String(fact.id) : 'No device.'));
  }

  // The device obligation on a Deny, read: which rule refused, or null when
  // the Deny is not about the device. `not-compliant` when the obligation
  // names nothing this PEP knows: a device Deny is a refusal either way.
  private deviceObligationOf(answer: any): string | null {
    const { log } = this.deps;
    log.debug("Entering XacmlRolePep.deviceObligationOf().");
    const found = (answer && answer.obligations || []).filter(function (o) {
      return o && o.id === DEVICE.OBLIGATION;
    })[0];
    if (!found) {
      log.debug("Leaving XacmlRolePep.deviceObligationOf(). None.");
      return null;
    }
    const hit = (found.assignments || []).filter(function (a) {
      return a.attributeId === DEVICE.REFUSAL;
    })[0];
    const said = hit ? String(hit.lexical !== undefined ? hit.lexical
                                                        : hit.value) : '';
    log.debug("Leaving XacmlRolePep.deviceObligationOf(). " + said);
    return said === 'compromised' ? 'compromised' : 'not-compliant';
  }

  // The risk obligation on a Deny, read: `{ action, factor }`, or null when
  // the Deny is not about risk. The action defaults to `refuse`: an
  // obligation this PEP cannot read is a policy saying no, not a policy
  // saying nothing.
  private riskObligationOf(answer: any): { action: string;
                                           factor: string } | null {
    const { log } = this.deps;
    log.debug("Entering XacmlRolePep.riskObligationOf().");
    const found = (answer && answer.obligations || []).filter(function (o) {
      return o && o.id === RISK.OBLIGATION;
    })[0];
    if (!found) {
      log.debug("Leaving XacmlRolePep.riskObligationOf(). None.");
      return null;
    }
    const valueOf = function (id: string): string {
      log.debug("Entering valueOf().");
      const hit = (found.assignments || []).filter(function (a) {
        return a.attributeId === id;
      })[0];
      log.debug("Leaving valueOf().");
      return hit ? String(hit.lexical !== undefined ? hit.lexical
                                                     : hit.value) : '';
    };
    const action = valueOf(RISK.ACTION) === 'step-up' ? 'step-up' : 'refuse';
    log.debug("Leaving XacmlRolePep.riskObligationOf(). " + action);
    return { action: action,
             factor: action === 'step-up'
               ? (valueOf(RISK.FACTOR) || 'second-factor') : '' };
  }

  // -------------------------------------------------------------------------
  // THE ALARM ON A PERMIT (#226): the policy let an elevated authentication
  // through for an application risk may never lock out, because the person
  // holds no factor to step up with. Permitted, as the policy said — and
  // said loudly, since it is exactly what an attacker holding an
  // administrator's password would also be let through by. Not on a dry
  // run, and only where risk is enforced: development observes anyway.
  // -------------------------------------------------------------------------
  private raiseAlarm(asked: IssuanceQuestion, answer: any): void {
    const { log, audit, errorCodes } = this.deps;
    log.debug("Entering XacmlRolePep.raiseAlarm().");
    const alarmed = (answer && answer.obligations || []).some(function (o) {
      return o && o.id === RISK.ALARM_OBLIGATION;
    });
    const facts = asked.risk as RiskFacts;
    // ONCE PER SIGN-IN: the session's decision. Every code and token issued
    // on that session carries the same facts and is permitted by the same
    // rule, and six warnings for one sign-in is how an alarm stops being
    // read.
    const onSession = asked.kind === this.deps.gate.ISSUANCE.SESSION;
    if (!alarmed || dryRun || !facts || !facts.enforced || !onSession) {
      log.debug("Leaving XacmlRolePep.raiseAlarm(). No alarm.");
      return;
    }
    const who = String(asked.subject && asked.subject.name || '');
    const what = 'The risk of this authentication is ' + facts.level + ' (' +
      (facts.signals.join(', ') || 'the model') + '), "' +
      String(asked.application || '') + '" may never be locked out on ' +
      'risk, and "' + who + '" holds no second factor to step up with: ' +
      'PERMITTED. Enrol a second factor for them.';
    audit.audit({
      action: 'xacml.issuance.alarm', errorCode: 'STS-RISK-0038',
      actor: who, protocol: 'XACML', outcome: 'success',
      detail: what + (facts.assessmentId
        ? ' Assessment ' + facts.assessmentId + '.' : '')
    });
    log.warn(errorCodes.tag('STS-RISK-0038') + 'xacml: ' + what);
    log.debug("Leaving XacmlRolePep.raiseAlarm().");
  }

  // -------------------------------------------------------------------------
  // THE DECISION.
  // -------------------------------------------------------------------------
  /**
   * Decides whether an issuance is permitted; the decider installed in
   * `common/issuance_gate.js`.
   *
   * Synchronous throughout. With `xacml.enabled` off everything is allowed.
   * With no loadable policy an application that is not narrowed is allowed
   * and a narrowed one is refused. A question with `preview` set is a dry
   * run: nothing is audited or counted.
   * @param asked - the issuance question
   * @returns the answer: `allowed`, `decision`, `why`, the roles held and
   *   required, the policy name and, on a refusal, the status
   */
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

    if (asked.scopeQuestion) {
      log.debug('Leaving XacmlRolePep.decideNow(). A scope question.');
      return this.decideScopes(asked);
    }

    if (asked.exchangeQuestion) {
      log.debug('Leaving XacmlRolePep.decideNow(). An exchange question.');
      return this.decideExchange(asked);
    }

    if (asked.transferQuestion) {
      log.debug('Leaving XacmlRolePep.decideNow(). A transfer question.');
      return this.decideTransfer(asked);
    }

    if (asked.gnapRightQuestion) {
      log.debug('Leaving XacmlRolePep.decideNow(). A GNAP right question.');
      return this.decideGnapRights(asked);
    }

    if (config.value('xacml.enabled') === false) {
      log.debug('Leaving XacmlRolePep.decideNow(). The XACML family is ' +
                'switched off.');
      return this.allowed('xacml.enabled is off, so no policy is evaluated ' +
                          'at all.', [], []);
    }


    const subject = asked.subject || {};
    // A WAIVED ROLE QUESTION requires nothing, which the policy's "requires
    // nothing" arm permits — and a Deny that is not about risk is set aside
    // below, for a policy written without that arm.
    const required = asked.rolesWaived ? []
      : applications.requiredRolesOf(asked.application);
    // THE ROLES HELD FOR THIS APPLICATION (#310): realm-wide roles by name,
    // and this application's own roles by their name inside it — which is
    // what its `appRequiredRole` names. Another application's role is not
    // held here, so it can never satisfy this one's requirement.
    const held = roles.rolesOf(Object.assign({}, subject,
      { application: String(asked.application || '') }));
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

    // -----------------------------------------------------------------------
    // A DENY ABOUT THE REGISTERED DEVICE (#164 phase 6) — the policy's
    // device obligation says so. Asked FIRST, because it is final: a risk
    // Deny may only ask for a step-up, and a device refused after one would
    // be one refusal made in two steps. Enforced in BOTH modes and even
    // where the role question was waived — the two rules it comes from are
    // a compromise and a realm's explicit requirement, neither of which is
    // about roles or is anything development should observe instead. The
    // client is told what every failed authentication is told; which rule
    // refused, and the device, are on the audit row.
    // -----------------------------------------------------------------------
    const deviceDeny = answer.decision === model.DECISION.DENY
      ? this.deviceObligationOf(answer) : null;
    if (deviceDeny) {
      const fact = asked.device || null;
      const code = deviceDeny === 'compromised' ? 'STS-DEVICE-0038'
                                                : 'STS-DEVICE-0037';
      const deviceWhy = deviceDeny === 'compromised'
        ? 'The registered device ' + String(fact && fact.id || '') +
          ' this came from is marked compromised, and the realm refuses one.'
        : 'The realm requires a compliant registered device of the ' +
          'subject\'s own' + ((asked.deviceRequirement || [])
            .indexOf('attested') >= 0 ? ', attested,' : '') + ' and this ' +
          (fact ? 'came from device ' + String(fact.id) + ' (' +
                  String(fact.compliance || 'unknown') + ', ' +
                  String(fact.attestation || '') + ')'
                : 'came from no registered device') + '.';
      if (!dryRun) {
        audit.audit({
          action: 'xacml.issuance.refused', errorCode: code,
          actor: subject.name || '', protocol: 'XACML',
          detail: 'Deny on the device for ' + (asked.kind || 'an issuance') +
                  ' to "' + String(asked.application || '') + '": ' +
                  deviceWhy
        });
      }
      log.info('xacml: ' + (dryRun ? 'a dry run would have REFUSED '
                                   : 'REFUSED ') +
               (asked.kind || 'an issuance') + ' for "' +
               String(asked.application || '') + '" to "' +
               (subject.name || 'nobody') + '" on the device — ' + deviceWhy);
      const refusal = this.refused(deviceDeny === 'compromised'
        ? 'Authentication failed.'
        : 'A compliant registered device is required.', answer.decision,
        held, required, answer);
      refusal.device = { refusal: deviceDeny };
      log.debug('Leaving XacmlRolePep.decideNow(). Deny on the device.');
      return refusal;
    }

    // -----------------------------------------------------------------------
    // A DENY ABOUT THE PROTOCOL (2026-10-01) — the policy's protocol
    // obligation says so: in product mode, an issuance through a family the
    // application is not declared for. Final like the device's, asked before
    // risk so it is never turned into a step-up, and enforced where the role
    // question was waived, because it is not about roles. The rule fires only
    // in product, so development is never refused here.
    // -----------------------------------------------------------------------
    const protocolDeny = answer.decision === model.DECISION.DENY &&
      (answer.obligations || []).some(function (o) {
        return o && o.id === PROTOCOL.OBLIGATION;
      });
    if (protocolDeny) {
      const protocolWhy = 'The application "' +
        String(asked.application || '') + '" is declared for ' +
        (asked.declaredProtocols || []).join(', ') + ', and this ' +
        (asked.kind || 'issuance') + ' belongs to ' +
        (asked.protocolFamilies || []).join(' or ') + '.';
      if (!dryRun) {
        audit.audit({
          action: 'xacml.issuance.refused', errorCode: 'STS-XACML-0084',
          actor: subject.name || '', protocol: 'XACML',
          detail: 'Deny on the protocol for ' +
                  (asked.kind || 'an issuance') + ': ' + protocolWhy
        });
      }
      log.info(errorCodes.tag('STS-XACML-0084') + 'xacml: ' +
               (dryRun ? 'a dry run would have REFUSED ' : 'REFUSED ') +
               (asked.kind || 'an issuance') + ' to "' +
               (subject.name || 'nobody') + '" on the protocol — ' +
               protocolWhy);
      const refusal = this.refused('The application is not configured for ' +
        'this protocol.', answer.decision, held, required, answer);
      refusal.protocolRefused = {
        declared: asked.declaredProtocols || [],
        families: asked.protocolFamilies || []
      };
      log.debug('Leaving XacmlRolePep.decideNow(). Deny on the protocol.');
      return refusal;
    }

    // -----------------------------------------------------------------------
    // A DENY ABOUT RISK (#62 P3) — the policy's risk obligation says so. In
    // product it refuses, and the answer carries what to do about it (a
    // step-up and its factor) for the doors that can. In development it is
    // RECORDED and set aside: the policy is asked again without the risk
    // facts, and the roles decide, exactly as before risk scoring decided
    // anything. Asked again rather than the role rule read off this answer,
    // because under deny-overrides a Deny says nothing about the Permit it
    // overrode — and an operator's own document may have rules of its own.
    // -----------------------------------------------------------------------
    const riskDeny = answer.decision === model.DECISION.DENY
      ? this.riskObligationOf(answer) : null;
    if (riskDeny) {
      const facts = asked.risk as RiskFacts;
      if (facts && facts.enforced) {
        const code = riskDeny.action === 'step-up' ? 'STS-RISK-0017'
                                                   : 'STS-RISK-0016';
        const riskWhy = riskDeny.action === 'step-up'
          ? 'The risk of this authentication is ' + facts.level + ' (' +
            (facts.signals.join(', ') || 'the model') + '), and the ' +
            'issuance policy asks for a ' + riskDeny.factor.replace('-', ' ') +
            ' before anything is issued.'
          : 'The risk of this authentication is ' + facts.level + ' (' +
            (facts.signals.join(', ') || 'the model') + '), and the ' +
            'issuance policy refuses it.';
        if (!dryRun) {
          audit.audit({
            action: 'xacml.issuance.refused', errorCode: code,
            actor: subject.name || '', protocol: 'XACML',
            detail: 'Deny on risk for ' + (asked.kind || 'an issuance') +
                    ' to "' + String(asked.application || '') + '": ' +
                    riskWhy + (facts.assessmentId
                      ? ' Assessment ' + facts.assessmentId + '.' : '')
          });
        }
        log.info('xacml: ' + (dryRun ? 'a dry run would have REFUSED '
                                     : 'REFUSED ') +
                 (asked.kind || 'an issuance') + ' for "' +
                 String(asked.application || '') + '" to "' +
                 (subject.name || 'nobody') + '" on risk — ' + riskWhy);
        // THE SENTENCE A CLIENT MAY SEE IS NOT `riskWhy`. Issuance sites put
        // a refusal's `why` in an error_description, a SOAP fault or a SAML
        // status message, and the level and the signals are exactly what an
        // attacker probing from a Tor exit would like to read back. The
        // detail is on the audit row and in the log above; the answer says
        // what every failed authentication says.
        const refusal = this.refused(riskDeny.action === 'step-up'
          ? 'A stronger authentication is required.'
          : 'Authentication failed.', answer.decision, held, required,
                                     answer);
        refusal.risk = { action: riskDeny.action, factor: riskDeny.factor,
                         observed: false };
        log.debug('Leaving XacmlRolePep.decideNow(). Deny on risk.');
        return refusal;
      }
      if (!dryRun) {
        log.info(errorCodes.tag('STS-RISK-0019') + 'xacml: the issuance ' +
                 'policy would have ' + (riskDeny.action === 'step-up'
                   ? 'asked for a ' + riskDeny.factor + ' before issuing '
                   : 'REFUSED ') + (asked.kind || 'an issuance') + ' to "' +
                 (subject.name || 'nobody') + '" on risk (' +
                 (facts ? facts.level : '?') + '); development observes, ' +
                 'so the roles decide.');
      }
      const withoutRisk = Object.assign({}, asked, { risk: null });
      const roleAnswer = this.decideNow(withoutRisk);
      roleAnswer.risk = { action: riskDeny.action, factor: riskDeny.factor,
                          observed: true };
      log.debug('Leaving XacmlRolePep.decideNow(). Risk observed.');
      return roleAnswer;
    }

    if (answer.decision === model.DECISION.PERMIT) {
      this.raiseAlarm(asked, answer);
      log.debug('Leaving XacmlRolePep.decideNow(). Permit.');
      return this.allowed('The issuance policy permitted it.', held, required,
                          answer);
    }

    // A DENY ABOUT THE AUTHENTICATION (#64) refuses even where the role
    // question was waived: it is not about roles.
    const aboutAuthentication = answer.decision === model.DECISION.DENY &&
      (answer.obligations || []).some(function (o) {
        return o && o.id === AUTHN.OBLIGATION;
      });
    if (asked.rolesWaived && !aboutAuthentication) {
      log.debug('Leaving XacmlRolePep.decideNow(). Not about risk, and the ' +
                'role question was waived.');
      return this.allowed('The role question was waived and the issuance ' +
                          'policy denied nothing on risk.', held, required,
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

  // -------------------------------------------------------------------------
  // WHO MAY ACT FOR WHOM (#186): the two exchange questions, asked by
  // `common/delegation_policy.ts` through `issuance_gate.checkExchange()`,
  // against the realm's issuance policy and — where that gives no verdict,
  // or xacml.enabled is off — the built-in one
  // (`xacml_exchange_verdicts.js`, the transfer question's arrangement). The
  // answer is the verdict; the door enforces it, and records the act.
  // -------------------------------------------------------------------------
  private decideExchange(asked: IssuanceQuestion): IssuanceAnswer {
    const { log, config, store, pip } = this.deps;
    log.debug('Entering XacmlRolePep.decideExchange().');
    const question = asked.exchangeQuestion as Record<string, any>;
    const loaded = config.value('xacml.enabled') === false
      ? null : this.issuancePolicy();
    const found = exchangeVerdicts.decide(Object.assign({}, question, {
      policyName: this.issuancePolicyName()
    }), loaded && loaded.policy ? loaded : null, function (request: any): any {
      return { repository: store.repository(),
               resolver: pip.resolverFor(request) };
    });
    log.debug('Leaving XacmlRolePep.decideExchange(). ' + found.verdict);
    return { allowed: found.verdict === 'allow',
             decision: found.verdict === 'allow' ? 'Permit' : 'Deny',
             why: 'The exchange verdict is ' + found.verdict +
                  (found.refusal ? ' (' + found.refusal + ')' : '') +
                  ', decided by ' +
                  (found.decidedBy === 'policy'
                    ? 'the issuance policy "' +
                      ((loaded && loaded.name) || '') + '"'
                    : found.decidedBy === 'none'
                      ? 'nothing: no policy answered, so it is refused'
                      : 'the built-in issuance policy') + '.',
             roles: [], required: [],
             policy: (loaded && loaded.name) || '', exchange: found };
  }

  // -------------------------------------------------------------------------
  // THE PER-SCOPE QUESTION (#304, part C of #88).
  //
  // One request per requested scope — action-id `issue-scope`, the scope as
  // the resource-id, whether its resource gates it and which roles
  // authorize it on the resource, the roles the subject holds on the
  // subject — and one verdict each out of the policy's scope obligation:
  // keep, drop or refuse, with a code. Code supplies the facts; the policy
  // decides (rcbj's rule, 2026-09-22).
  //
  // **NO VERDICT IS NOT A VERDICT (rcbj's decision on #304).** With
  // `xacml.enabled` off, no issuance policy loadable, or a document that
  // answers without the obligation — an operator's override built from a
  // template older than these rules — the BUILT-IN policy is asked instead,
  // with the same engine: the rule lives in one document and role gating
  // never silently switches off. Only if the built-in one cannot answer
  // either (a defect) is a gated scope dropped and an ungated one kept.
  // Nothing is audited here: the caller records what it took off, once.
  // -------------------------------------------------------------------------
  private decideScopes(asked: IssuanceQuestion): IssuanceAnswer {
    const { log, config, store, pip } = this.deps;
    log.debug('Entering XacmlRolePep.decideScopes().');
    const question = asked.scopeQuestion as ScopeQuestion;
    const loaded = config.value('xacml.enabled') === false ? null
                                                           : this.issuancePolicy();
    // THE ONE WAY THE QUESTION IS ASKED (`xacml_scope_verdicts.js`), the same
    // module the gate asks the built-in policy through where no family is
    // loaded; here against the realm's policy, with the repository and the
    // PIP every other decision here uses.
    const verdicts = scopeVerdicts.decide(Object.assign({}, question, {
      subject: asked.subject || {},
      client: asked.client || question.client || '',
      grantType: asked.grantType || question.grantType || '',
      protocol: asked.protocol || question.protocol || '',
      policyName: this.issuancePolicyName()
    }), loaded && loaded.policy ? loaded : null, function (request: any): any {
      return { repository: store.repository(),
               resolver: pip.resolverFor(request) };
    });
    log.debug('Leaving XacmlRolePep.decideScopes(). ' + verdicts.length +
              ' verdict(s).');
    return { allowed: true, decision: 'Permit',
             why: 'One verdict per requested scope.',
             roles: question.held || [], required: [],
             policy: (loaded && loaded.name) || '', scopes: verdicts };
  }

  // -------------------------------------------------------------------------
  // THE PER-RIGHT GNAP QUESTION (#432 phase 3), `decideScopes()`'s
  // arrangement: the realm's issuance policy first, with the repository and
  // the PIP, the BUILT-IN policy for a right it says nothing about —
  // `xacml.enabled` off, no loadable policy, an override built without the
  // GNAP rules — through `xacml_gnap_right_verdicts.ts`, the one library the
  // gate asks too. Nothing is audited here: the grant engine records what it
  // refused or narrowed, once.
  // -------------------------------------------------------------------------
  private decideGnapRights(asked: IssuanceQuestion): IssuanceAnswer {
    const { log, config, store, pip } = this.deps;
    log.debug('Entering XacmlRolePep.decideGnapRights().');
    const question = asked.gnapRightQuestion as Record<string, any>;
    const loaded = config.value('xacml.enabled') === false
      ? null : this.issuancePolicy();
    const verdicts = gnapRightVerdicts.decide(Object.assign({}, question, {
      policyName: this.issuancePolicyName()
    }), loaded && loaded.policy ? loaded : null, function (request: any): any {
      return { repository: store.repository(),
               resolver: pip.resolverFor(request) };
    });
    log.debug('Leaving XacmlRolePep.decideGnapRights(). ' + verdicts.length +
              ' verdict(s).');
    return { allowed: true, decision: 'Permit',
             why: 'One verdict per GNAP access right.',
             roles: [], required: [],
             policy: (loaded && loaded.name) || '', gnapRights: verdicts };
  }

  // -------------------------------------------------------------------------
  // THE TRANSFER QUESTION (#98 D4): `hold-session`, `serve-request` or
  // `release-attributes`, the facts `cell_transfer.ts` gathered, and one
  // verdict out of the policy's transfer obligation. The scope question's
  // arrangement exactly: the realm's issuance policy first, with the repository
  // and the PIP, and the BUILT-IN policy where that gives no verdict —
  // `xacml.enabled` off, no loadable policy, or an override built without the
  // transfer rules — so the strict default never silently switches off. Nothing
  // is audited or counted here: the caller records the relay or the refusal.
  // -------------------------------------------------------------------------
  private decideTransfer(asked: IssuanceQuestion): IssuanceAnswer {
    const { log, config, store, pip } = this.deps;
    log.debug('Entering XacmlRolePep.decideTransfer().');
    const question = asked.transferQuestion as Record<string, any>;
    const loaded = config.value('xacml.enabled') === false
      ? null : this.issuancePolicy();
    const found = transferVerdicts.decide(Object.assign({}, question, {
      policyName: this.issuancePolicyName()
    }), loaded && loaded.policy ? loaded : null, function (request: any): any {
      return { repository: store.repository(),
               resolver: pip.resolverFor(request) };
    });
    log.debug('Leaving XacmlRolePep.decideTransfer(). ' + found.verdict);
    return { allowed: ['hold', 'serve', 'release']
               .indexOf(found.verdict) >= 0,
             decision: 'Permit',
             why: 'The transfer verdict is ' + found.verdict + ', decided by ' +
                  (found.decidedBy === 'policy'
                    ? 'the issuance policy "' +
                      ((loaded && loaded.name) || '') + '"'
                    : found.decidedBy === 'none'
                      ? 'the strict default, because no policy answered'
                      : 'the built-in issuance policy') + '.',
             roles: [], required: [],
             policy: (loaded && loaded.name) || '', transfer: found };
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
  /**
   * Describes which of its three states the issuance policy is in, for the
   * console: built in, overridden by an entry, or not evaluated.
   *
   * @returns the name, whether it loads, whether it is built in, whether an
   *   entry exists and is enabled, whether it reads the risk level, and a
   *   sentence on its effect
   */
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
    // A DOCUMENT THAT READS NO RISK ATTRIBUTE DECIDES NOTHING ON RISK (#62
    // P3), and says so rather than being rewritten: an override built from
    // the template before the risk rules existed — or written by hand
    // without them — is the operator's document, and this realm then
    // assesses every sign-in and refuses none on it.
    (out as any).readsRisk = !!loaded.policy &&
      JSON.stringify(loaded.policy).indexOf(RISK.LEVEL) >= 0;
    if (out.ok && !(out as any).readsRisk) {
      out.effect += ' IT READS NO RISK ATTRIBUTE (' + RISK.LEVEL + '), so ' +
        'nothing is refused or stepped up on the risk of an authentication ' +
        'in this realm (#62): rebuild it from the `role-issuance` template, ' +
        'or add the risk rules, to decide on it.';
    }
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
  /**
   * Asks the issuance decision as a dry run, for `/admin/roles`.
   *
   * Goes through `decide()`; nothing is issued, audited or counted.
   * @param question - the application, kind (an access token by default),
   *   subject (an anonymous person by default) and claims
   * @returns the answer `decide()` gives
   */
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

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds no
// instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` when this module loads (see
// `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<XacmlRolePep>(
  'xacml/xacml_role_pep',
  () => new XacmlRolePep(XacmlRolePep.defaultDeps()),
  null,
  helpers.log);

// `decide` is a facade built ONCE, so the gate and this module's exports hold
// the same function.
const decide = slot.forward('decide');
const preview = slot.forward('preview');
const issuancePolicyState = slot.forward('issuancePolicyState');

// ---------------------------------------------------------------------------
// FILL THE SLOT.
//
// With FACADES, so both fills stay at load (#50, R2): a facade resolves the
// instance only when it is called, which is not before a request.
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

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

/**
 * The embedded PEP for this service's own issuance.
 *
 * Loading it installs `decide` in `common/issuance_gate.js` and the
 * console's role previewer. The functions forward to the `XacmlRolePep`
 * instance the composition root installs.
 * @namespace
 */
export = {
  XacmlRolePep: XacmlRolePep,
  installInstance: (instance: XacmlRolePep): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  decide: decide,
  builtInPolicy: slot.forward('builtInPolicy'),
  issuancePolicyState: issuancePolicyState,
  preview: preview,
  issuancePolicy: slot.forward('issuancePolicy'),
  issuancePolicyName: slot.forward('issuancePolicyName'),
  buildRequest: slot.forward('buildRequest'),
  ATTRIBUTE: XacmlRolePep.ATTRIBUTE
};
