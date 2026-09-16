'use strict';
//
// File: xacml.ts
//
// ---------------------------------------------------------------------------
// THE XACML SURFACE: A DECISION ENDPOINT, THE REPOSITORY, AND AN EMBEDDED PEP.
//
// The engine modules in this directory are libraries with no DOM, no HTTP and
// no store. This file is the only one that registers a PROTOCOL route
// (`xacml_admin.ts` registers the console pages), and it is deliberately thin
// — it reads a request, hands it to `xacml_pdp.js`, and writes what comes
// back. No decision logic lives here, and none should: the
// whole point of the conformance suite driving the engine in process is that
// the thing that decides is reachable without a port.
//
//   GET  /xacml            what this surface is, and what it decides against
//   POST /xacml/pdp        a decision. JSON Profile in, JSON Profile out.
//   GET  /xacml/policies   the repository, as the PDP sees it
//   GET  /xacml/protected  THE EMBEDDED PEP — a resource this service guards
//                          with its own PDP
//
// and, in the PHASE FIVE section further down, the three `/xacml/pep/*`
// endpoints a remote PEP uses and `POST /xacml/pip`.
//
// ---------------------------------------------------------------------------
// THE EMBEDDED PEP IS THE POINT OF THE LAST ONE, AND IT IS NOT A DEMO PAGE.
//
// A PDP endpoint answers questions in the abstract; a PEP is where a decision
// stops being an opinion. `/xacml/protected` builds a request out of the
// caller — who they are, what they asked for, how they asked for it — asks the
// PDP, and then ENFORCES the answer, including the part everybody skips: an
// obligation it cannot discharge turns a Permit into a refusal (section 7.2).
//
// It is also where `xacml.pepBias` lives, and that setting is the reason this
// exists as a real component rather than a canned response. XACML lets a PEP
// be deny-biased or permit-biased, the two agree on every Permit and every
// Deny, and they differ on exactly the answer nobody tests: Indeterminate and
// NotApplicable. Being able to flip it and watch the same policy produce two
// different outcomes is the thing a debugger is for.
//
// ---------------------------------------------------------------------------
// ALL FOUR REQUIRE A CLIENT CERTIFICATE NOW, AND THIS BLOCK USED TO SAY THE
// OPPOSITE.
//
// What stood here was an argument for authenticating nobody, and half of it is
// still true: **a PDP is not an authorization boundary.** It is a function that
// answers a question about somebody ELSE'S boundary, the caller of `POST
// /xacml/pdp` is an enforcement point asking on behalf of a subject it NAMES IN
// THE REQUEST, and the identity on the connection is therefore not the identity
// the decision is about. That distinction is unchanged and is load-bearing:
// `xacmlAccess()` below decides who may ASK, and nothing it learns is allowed
// to reach `decide()`. A PDP that decided about whoever holds the client
// certificate would be a different and much worse component.
//
// **WHAT CHANGED IS THAT "NOT A BOUNDARY" WAS BEING READ AS "NOT WORTH
// GUARDING", AND THOSE ARE DIFFERENT SENTENCES.** Three of these four endpoints
// do something an anonymous caller should not get for free:
//
//   * `GET /xacml/policies` publishes the repository, and since the access and
//     issuance PEPs were embedded, the documents in it are the ones this
//     service decides its OWN admissions with. Publishing a demonstration
//     policy and publishing the exact conditions under which a service lets
//     people in are not the same act. `GET /xacml/pep/policies` reached this
//     conclusion first and its comment carries the long form.
//   * `GET /xacml/protected` ENFORCES, and it names its own subject from a
//     query parameter — so unguarded it is an oracle anybody can drive to map
//     the policy by asking about one subject at a time.
//   * `POST /xacml/pdp` evaluates an arbitrary document against the repository
//     on this service's thread, which is the ordinary reason a decision
//     endpoint asks who is calling.
//
// `GET /xacml` is here because it describes the other three, and because a
// surface with one door left open is a surface whose gate somebody will read as
// advisory. Its refusal names the group and the setting, so the page's job —
// telling a caller how this works — survives being refused.
//
// **THE MECHANISM IS THE ONE `/xacml/pep/*` ALREADY USES**, four steps deep,
// and it is described where it is implemented rather than twice: see MAY THIS
// CALLER REACH THE XACML SURFACE below. What differs is the ROLE —
// `XACML_USER` here, `REMOTE_PEPS` there — and `common/roles.js` argues at
// length why those must not be one role.

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape, for a module that registers routes (rule 1):
//
//   * **`XacmlSurface` TAKES EVERY MODULE IT USES THROUGH ITS CONSTRUCTOR**
//     (`XacmlSurfaceDeps`): the helpers it reads, the settings, the audit log,
//     the error-code registry, the engine, the store, the PIP, the register
//     of remote PEPs and its nudge, the monitor, the role register and the
//     access gate. `cluster/cluster_barrier` and `persistence/persistence`
//     arrive as LOADERS, because this file always required them lazily,
//     inside the one function that needs them.
//   * **`registerRoutes(app)` HOLDS EVERY ROUTE, IN THE ORIGINAL ORDER**, and
//     installs the repository's change observer at the point the original
//     did — after `POST /xacml/pip` and before `GET /xacml`.
//   * **THE THREE REQUIRES THAT ARM THIS FAMILY STAY AT THE TOP**, as plain
//     `require()` calls in their old order and before any route: the console
//     pages, then the role PEP (which fills `common/issuance_gate.js`'s
//     decider), then the access PEP (which fills `common/access_gate.js`'s).
//   * **THE MODULE STILL EXPORTS `decide`, `enforce`, `description`,
//     `enabled`, `pipMaxDesignators` AND `nudgeRegisteredPeps`**, bound to a
//     TRANSITIONAL instance built at the bottom from the real modules, which
//     registers the routes at load. `xacml_admin.ts` requires this module
//     lazily and the tests require it by name. The instance goes when the
//     composition root exists; `XacmlSurface` is exported beside it for that
//     root. As before, the exports are assigned last.
// ---------------------------------------------------------------------------

import app = require('../common/app');
import helpers = require('../common/helpers');

// The input validator. A LEAF (rule 3): registers no route, closes no cycle.
// **What it adds here is narrow, and deliberately so.** The XACML request
// documents this family reads are validated by `xacml_xml.js`'s own parser and
// the JSON Profile reader, both held to 454 of 455 mandatory OASIS conformance
// cases — a schema over those would be a second, worse reading of a
// specification this directory already implements. What is left is the two
// scalar parameters those readers never see.
import validation = require('../common/validation');
// THE RATE LIMITER AND THE CSRF TOKENS. A LEAF (rule 3) — it registers no
// route and requires only `config` and `helpers` — so it can be required from
// anywhere. Only the limiter is used here: this family has no browser form, so
// there is nothing for a CSRF token to protect.
import websecurity = require('../common/websecurity');
import config = require('../common/config');
import audit = require('../common/audit');
// The error-code registry (a leaf). A code is marked on the RESPONSE and never
// written into it — every refusal below keeps the body it always had.
import errorCodes = require('../common/error_codes');
import model = require('./xacml_model');
import json = require('./xacml_json');
import pdp = require('./xacml_pdp');
import store = require('./xacml_store');
import pip = require('./xacml_pip');
// The datatype table, for `POST /xacml/pip` alone: a resolver answers with
// PARSED values and a caller's engine wants the LEXICAL form its own parser
// reads. A LEAF (rule 3) that registers nothing and requires nothing that
// requires it back, so its position here is not a position.
import datatypes = require('./xacml_datatypes');
// The XML reader and writer, for `POST /xacml/pip` — which speaks XACML's own
// XML in both directions rather than a vocabulary of this service's own. A
// LEAF (rule 3) like every other module in this directory bar two.
import xml = require('./xacml_xml');
import validate = require('./xacml_validate');
import mtls = require('../oauth-oidc/mtls');
import peps = require('./xacml_pep_registry');
import pepHttp = require('./xacml_pep_http');
// The decision counters behind /admin/xacml/monitor. A LEAF (rule 3): it
// registers no route, so its position here is not a position, and it requires
// nothing that requires it back.
import monitor = require('./xacml_monitor');
// THE ROLE REGISTER AND THE ACCESS GATE, for the three /xacml/pep endpoints.
// Both are LEAVES that register nothing (rule 3), so neither can move a route
// or join a cycle: `roles.js` requires config and its directory arrives across
// a slot `ldap_server.js` fills, and `access_gate.js` requires config and holds
// a decider this family itself installs at 23c.
import roles = require('../common/roles');
import accessGate = require('../common/access_gate');
// THE CONSOLE PAGES. Required from here rather than from
// `common/protocol_stack.js` so that the require order has ONE line for this
// family: this module is 23c and the
// pages are part of it. `xacml_admin.ts` requires `admin-ui/admin` (18) for
// the shell, which is already loaded by the time anything here runs — and it
// requires THIS module lazily, inside the one function that needs it, because
// a require at its top would close a cycle and node answers a cycle with a
// half-initialised module rather than with an error.
require('./xacml_admin');

// THE EMBEDDED PEP FOR THIS SERVICE'S OWN ISSUANCE, required from here for the
// same reason and with one extra consequence: requiring it is what FILLS
// `common/issuance_gate.js`'s decider slot, so from this line onward every
// issuance site's `gate.check()` reaches the engine. Before it — and in any
// process that never loads this family, which is `npm test`, the parent
// project's in-process Kerberos jobs and the remote PEP container — the gate
// answers "allowed" and this service is exactly what it was.
//
// It registers NO ROUTE and is therefore a library (rule 3): it is here rather
// than in `common/protocol_stack.js` so that the require order keeps its one
// line for this family, and its position within that line does not matter. It
// must come after `xacml_admin.ts` for no technical reason at all, and does,
// because the pages are what an administrator fixes a refusal with.
require('./xacml_role_pep');
// THE ACCESS PEP. Requiring it ARMS `common/access_gate.js` — the admin
// console, the User Portal, SCIM, the SPIRE Server API, the embedded debugger
// and this file's own two gates all ask it, and the management API does in
// PRODUCT MODE (it is open in development by design, so there is no subject
// to decide about). Each asks AFTER its own check rather than instead of it.
// Before this line every one of them is allowed, which is what a process
// without the XACML family does. Same arrangement as the role PEP one line
// up, for the same reason.
require('./xacml_access_pep');

const { log, xmlEscape, baseUrlOf, parseBody } = helpers;

type Req = import('express').Request;
type Res = import('express').Response;
type Handler = (req: Req, res: Res) => unknown;

// The routes' own table of what an express app offers.
interface RouteTable {
  get(path: string, handler: Handler): unknown;
  post(path: string, handler: Handler): unknown;
}

// What `callerIdentity()` answers: what the connection carried, never a
// verdict.
interface CallerIdentity {
  authenticated: boolean;
  verified: boolean;
  subject: string;
  thumbprint: string;
  dn: string;
  commonName: string;
  why: string;
  revocationRefused?: boolean;
  revocation?: any;
}

// What `xacmlAccess()` and `pepAccess()` answer.
interface AccessResult {
  allowed: boolean;
  identity?: CallerIdentity;
  roles?: string[];
}

// What `enforce()` answers.
interface Enforcement {
  allowed: boolean;
  bias: string;
  why: string;
  discharged: string[];
  undischargeable: string[];
}

// One resolved designator in a PIP response, values in lexical form.
interface PipAnswer {
  category: string;
  attributeId: string;
  dataType: string;
  values: string[];
}

// One designator a PIP query could not resolve, and why.
interface PipUnresolved {
  category: string;
  attributeId: string;
  dataType: string;
  mustBePresent: boolean;
  why: string;
}

// The two cluster modules, required only when a nudge is due.
interface Barrier {
  isActive(): boolean;
}
interface CommitWaiter {
  writeGeneration(): unknown;
  commitThrough(target: unknown): Promise<Array<{ error?: unknown }> | null>;
}

interface XacmlSurfaceDeps {
  log: typeof log;
  xmlEscape: typeof xmlEscape;
  baseUrlOf: typeof baseUrlOf;
  parseBody: typeof parseBody;
  validation: typeof validation;
  websecurity: typeof websecurity;
  config: typeof config;
  audit: typeof audit;
  errorCodes: typeof errorCodes;
  model: typeof model;
  json: typeof json;
  pdp: typeof pdp;
  store: typeof store;
  pip: typeof pip;
  datatypes: typeof datatypes;
  xml: typeof xml;
  validate: typeof validate;
  mtls: typeof mtls;
  peps: typeof peps;
  pepHttp: typeof pepHttp;
  monitor: typeof monitor;
  roles: typeof roles;
  accessGate: typeof accessGate;
  // Required at the moment a nudge is due, never at load.
  loadBarrier(): Barrier;
  loadPersistence(): CommitWaiter;
}

// The role those four endpoints require. Named once here rather than written
// at four call sites, for the reason `REMOTE_PEP_ROLE` below is: a rename in
// `roles.js` is one line to follow here.
const XACML_USER_ROLE = 'XACML_USER';

// The role those endpoints require. Named once here rather than written at
// each call site, so that a rename in `roles.js`'s catalogue (where the name
// is defined) is one line to follow here rather than several to hunt for.
const REMOTE_PEP_ROLE = 'REMOTE_PEPS';

// ---------------------------------------------------------------------------
// The scalar parameters the XACML readers never see.
//
// `format` is CASE-INSENSITIVE because the call site compares after
// `.toLowerCase()`; `bias` is CASE-SENSITIVE because nothing lower-cases it.
// Getting either backwards would make this refuse a value the handler accepts,
// which is a validator changing what an endpoint does rather than checking it.
//
// **The two biases are the PEP's, and they are the one pair that must disagree
// somewhere** — a NotApplicable decision is enforced differently by each, which
// is the property `tests/xacml_pep.js` asserts over seven probes.
// ---------------------------------------------------------------------------
const XACML_QUERY = validation.z.looseObject({
  format: validation.types.opt(validation.z.string().regex(/^(json|xml|html)$/i,
    'must be "json", "xml" or "html"')),
  bias: validation.types.opt(validation.types.oneOf(
      ['deny-biased', 'permit-biased']))
});

// The obligations `enforce()` can discharge; the argument is above that
// method.
const DISCHARGEABLE = ['urn:sts:xacml:obligation:log'];

// This service's own namespace, for the two elements XACML does not define. It
// is NOT the core namespace, and that separation is the `<Unresolved>` argument
// (at `POST /xacml/pip`, in the class) made mechanical: everything a caller is
// invited to splice is in OASIS's namespace and everything invented here is in
// this one, so the two can never be confused by a parser or by a reader.
const PIP_NS = 'urn:sts:xacml:pip:1.0';

// The designators a caller may ask about, per call. A cap for the reason every
// other container here has one: this endpoint walks a list a caller supplies,
// and an unbounded list on a surface reachable over the network is a way to
// spend this service's single thread. It is generous — no real policy
// designates fifty attributes about one subject — so reaching it is a sign of
// something else.
//
// **`xacml.pipMaxDesignators` SINCE 2026-09-12**, beside
// `xacml.pipMaxPerWindow` — that one bounds how many queries and this bounds
// one query, so they are the two halves of what one enforcement point may cost.
// This constant is the default, read per query so a change reaches the next
// one.
const PIP_MAX_DESIGNATORS = 50;

class XacmlSurface {
  constructor(private readonly deps: XacmlSurfaceDeps) {
    deps.log.debug("Entering XacmlSurface.constructor().");
    deps.log.debug("Leaving XacmlSurface.constructor().");
  }

  enabled(): boolean {
    const { log, config } = this.deps;
    log.debug("Entering XacmlSurface.enabled().");
    log.debug("Leaving XacmlSurface.enabled().");
    return config.value('xacml.enabled') !== false;
  }

  // The same shape `ssf.ts`'s `offCheck()` has, and the same argument: the
  // routes stay REGISTERED and answer 501, because the feature being off and
  // the URL being wrong are different sentences to a client.
  private offCheck(res: Res): boolean {
    const self = this;
    const { log, errorCodes } = this.deps;
    log.debug('Entering XacmlSurface.offCheck().');
    if (self.enabled()) {
      log.debug('Leaving XacmlSurface.offCheck(). On.');
      return false;
    }
    errorCodes.mark(res, 'STS-XACML-0001');
    res.status(501).type('application/json').set('Cache-Control', 'no-store')
       .send(JSON.stringify({
         error: 'not_implemented',
         error_description:
           'XACML is turned off on this service (xacml.enabled). The routes ' +
           'stay registered and answer 501 rather than 404, because the ' +
           'feature being off and the URL being wrong are different ' +
           'sentences to a client. The policy repository in ou=policies is ' +
           'untouched.'
       }, null, 2));
    log.debug('Leaving XacmlSurface.offCheck(). Off.');
    return true;
  }

  // error-code: none — the helper's definition, not a call to it.
  private fail(res: Res, status: number, code: string,
               description: string): void {
    const { log } = this.deps;
    log.debug("Entering XacmlSurface.fail().");
    res.status(status).type('application/json').set('Cache-Control', 'no-store')
       .send(JSON.stringify({ error: code, error_description: description },
                            null, 2));
    log.debug("Leaving XacmlSurface.fail().");
  }

  // ===========================================================================
  // MAY THIS CALLER REACH THE XACML SURFACE AT ALL?
  //
  // The four endpoints above this file's own PHASE FIVE section — `GET /xacml`,
  // `POST /xacml/pdp`, `GET /xacml/policies` and `GET /xacml/protected` — go
  // through here. It is `pepAccess()`'s sibling and rests on the SAME four-step
  // chain, which is described once, below, at MAY THIS CALLER REACH THE
  // REMOTE-PEP ENDPOINTS AT ALL: a chain built to an anchor in this service's
  // truststore, a DN resolved to a directory entry, the roles that entry holds,
  // and a policy decision. Every link is a real check and none of them is
  // permissive.
  //
  // **THE ROLE AND THE RESOURCE ARE BOTH DIFFERENT, AND NEITHER IS AN
  // ACCIDENT.** `XACML_USER` rather than `REMOTE_PEPS`, because admitting
  // somebody to a decision endpoint must not silently admit them to the
  // documents this service enforces its own access with — `common/roles.js`
  // argues that at the role. `XACML_API` rather than `XACML_PEP_API`, because
  // an operator narrowing one surface and not the other needs two names to
  // target, and a policy layer that cannot express the distinction its own
  // register makes is one somebody will work around.
  //
  // WHAT IT DOES NOT DO, and it is the same list its sibling has. It does not
  // require a certificate as a step of its own: a caller that presents none has
  // no verified DN, holds only `EVERYBODY`, and is refused ON THE POLICY —
  // which is the correct and visible outcome rather than a second refusal spelt
  // differently, and it is what makes `/admin/xacml/decide` able to reproduce
  // this answer. And it does not tell `decide()` anything: the identity on the
  // CONNECTION is not the identity a XACML request is ABOUT, and a PDP that
  // conflated them would decide about whoever holds the client certificate.
  // ===========================================================================
  private xacmlAccess(req: Req, res: Res, action: string,
                      what: string): AccessResult {
    const self = this;
    const { log, config, errorCodes, roles, accessGate } = this.deps;
    log.debug('Entering XacmlSurface.xacmlAccess(). action=' + action);
    const identity = self.callerIdentity(req);
    // THE NAME IS THE VERIFIED DN OR NOTHING AT ALL, for `pepAccess()`'s
    // reason: an unverified certificate's DN is a name the caller chose for
    // itself, and handing one to `rolesOf()` would be an unauthenticated caller
    // naming itself into a group.
    const name = identity.verified ? identity.dn : '';
    // The groups are left UNRESOLVED deliberately — passing no `groups` is what
    // makes `roles.js` read them out of the directory, and passing `[]` would
    // mean "in no group" and quietly answer no to every group-derived role,
    // XACML_USER among them.
    const held = name
      ? roles.rolesOf({ kind: 'user', name: name, authenticated: true })
      : [];
    const policy = accessGate.check({
      resource: accessGate.RESOURCE.XACML_API,
      action: action,
      requiredRoles: [XACML_USER_ROLE],
      subject: { name: name, authenticated: !!identity.verified, roles: held },
      context: { method: req.method, path: req.originalUrl || req.url }
    });
    if (policy.allowed) {
      log.debug('Leaving XacmlSurface.xacmlAccess(). Allowed.');
      return { allowed: true, identity: identity, roles: held };
    }
    log.info('xacml: the access policy refused ' + what + ' for ' +
             (name || 'an unidentified caller') + '. ' + policy.why);
    // THE REFUSAL IS THE ONLY THING AN UNADMITTED CALLER CAN READ ON THIS
    // SURFACE, so it carries what `GET /xacml` would have told them about the
    // gate: what to present, where the trust anchor goes, which group grants,
    // and which setting names that group. A 403 saying "access_denied" and
    // nothing else would make the one endpoint that documents this family
    // unreachable by exactly the people who need it.
    if (!identity.authenticated) {
      errorCodes.mark(res, 'STS-XACML-0003');
    } else if (identity.revocationRefused) {
      errorCodes.mark(res,
                      errorCodes.codeOf(identity.revocation) || 'STS-PKI-0118');
    } else if (!identity.verified) {
      errorCodes.mark(res, 'STS-XACML-0004');
    } else if (held.indexOf(XACML_USER_ROLE) < 0) {
      errorCodes.mark(res, 'STS-XACML-0005');
    } else {
      errorCodes.mark(res, 'STS-XACML-0006');
    }
    self.fail(res, 403, 'access_denied',
      'The access policy refused this request. ' + policy.why +
      ' The XACML endpoints are reached by presenting a client certificate ' +
      'this service VERIFIES — the issuing CA goes in with POST /tls/trust — ' +
      'whose subject resolves to a directory entry that is a member of the ' +
      'group named by roles.xacmlUserGroup ("' +
      String(config.value('roles.xacmlUserGroup') || '') +
      '"), which is what ' +
      'grants the built-in ' + XACML_USER_ROLE + ' role. That is a DIFFERENT ' +
      'group from the one /xacml/pep/* requires (roles.remotePepGroup), on ' +
      'purpose: those endpoints hand out the documents this service enforces ' +
      'its own access with. This caller ' +
      (identity.verified
        ? 'presented a certificate that VERIFIED, resolved to "' + name +
          '", and holds ' + (held.length ? held.join(', ') : 'no role') + '.'
        : (identity.authenticated
            ? 'presented a certificate that did NOT verify: ' + identity.why
            : 'presented no client certificate at all.')) +
      ' xacml.enforceAccess turns this layer off.');
    log.debug('Leaving XacmlSurface.xacmlAccess(). Refused.');
    return { allowed: false };
  }

  // ---------------------------------------------------------------------------
  // A DECISION, FROM A PARSED REQUEST.
  //
  // The one place the engine, the store and the PIP are put together, so that
  // the endpoint and the embedded PEP cannot decide against different policies
  // or with different attribute sources — which is exactly the drift that makes
  // a PEP and a PDP disagree in a real deployment and is the hardest kind to
  // find.
  // ---------------------------------------------------------------------------
  decide(request: any): any {
    const { log, config, errorCodes, model, pdp, store, pip } = this.deps;
    log.debug('Entering XacmlSurface.decide().');
    const root = store.root();
    if (!root) {
      // NOT an error, and not a Permit. A repository with no root has nothing
      // to say about this request, which is precisely `NotApplicable` — and
      // what the PEP then does with it is the PEP's bias, which is where that
      // decision belongs.
      log.debug('Leaving XacmlSurface.decide(). No root policy.');
      return { decision: model.DECISION.NOT_APPLICABLE,
               status: { code: model.STATUS.OK },
               obligations: [], advice: [], policyIdentifiers: [],
               note: 'This repository has no root policy, so there is ' +
                     'nothing to evaluate. Mark one policy as the root.' };
    }
    let policy;
    try {
      policy = store.parseDocument(root.document);
    } catch (error) {
      log.debug("Caught in XacmlSurface.decide(): " +
                ((error && error.message) || error));
      log.debug('Leaving XacmlSurface.decide(). The root policy will not ' +
                'load.');
      // MARKED ON THE ANSWER, NOT IN IT: a non-enumerable property that neither
      // `json.writeResponse()` nor anything else serialises, so a handler that
      // sends this answer can mark its response with the condition behind it.
      return errorCodes.mark({ decision: model.DECISION.INDETERMINATE,
               status: { code: error.xacmlStatus || model.STATUS.SYNTAX_ERROR,
                         message: 'The root policy "' + root.name + '" does ' +
                                  'not load: ' + error.message },
               obligations: [], advice: [], policyIdentifiers: [] },
               'STS-XACML-0012');
    }
    if (config.value('xacml.returnPolicyIdList') === true) {
      request.returnPolicyIdList = true;
    }
    const answer = pdp.evaluate(policy, request, {
      repository: store.repository(),
      resolver: pip.resolverFor(request)
    });
    // AN INDETERMINATE THE ENGINE REACHED THROUGH A PROCESSING OR SYNTAX ERROR
    // is a fault somebody has to fix, where a missing attribute is an answer
    // about the request; only the first two carry a code.
    if (answer && answer.decision === model.DECISION.INDETERMINATE &&
        answer.status &&
        (answer.status.code === model.STATUS.PROCESSING_ERROR ||
         answer.status.code === model.STATUS.SYNTAX_ERROR)) {
      errorCodes.mark(answer, 'STS-XACML-0013');
    }
    log.debug('Leaving XacmlSurface.decide(). ' + answer.decision);
    return answer;
  }

  // ---------------------------------------------------------------------------
  // WHAT A PEP DOES WITH A DECISION. Section 7.2, and the obligation rule.
  //
  // TWO THINGS, and the second is the one implementations skip:
  //
  //   1. The BIAS decides what a non-Permit means. Deny-biased: only Permit
  //      allows. Permit-biased: only Deny refuses. They agree on Permit and on
  //      Deny and differ on Indeterminate and NotApplicable — which is to say
  //      they differ on exactly the cases nobody writes a test for.
  //   2. AN OBLIGATION THAT CANNOT BE DISCHARGED TURNS A PERMIT INTO A REFUSAL.
  //      That is not a nicety: an obligation is the half of a decision that
  //      says "yes, AND you must also do this", and a PEP that allows the
  //      access while dropping the obligation has enforced half a policy and
  //      reported success. This PEP can discharge exactly one obligation — the
  //      one it knows about, below — and refuses on any other, loudly.
  // ---------------------------------------------------------------------------
  enforce(answer: any): Enforcement {
    const { log, config, model } = this.deps;
    log.debug('Entering XacmlSurface.enforce(). decision=' + answer.decision);
    const bias = config.value('xacml.pepBias') === 'permit-biased'
      ? 'permit-biased' : 'deny-biased';
    const discharged = [];
    const undischargeable = [];
    (answer.obligations || []).forEach(function (obligation) {
      if (DISCHARGEABLE.indexOf(obligation.id) >= 0) {
        log.info('xacml: discharging obligation ' + obligation.id + ' with ' +
                 (obligation.assignments || []).length + ' assignment(s).');
        discharged.push(obligation.id);
        return;
      }
      undischargeable.push(obligation.id);
    });
    const permitted = answer.decision === model.DECISION.PERMIT;
    const denied = answer.decision === model.DECISION.DENY;
    let allowed = bias === 'deny-biased' ? permitted : !denied;
    let why;
    if (bias === 'deny-biased') {
      why = permitted ? 'The PDP said Permit.'
        : 'The PDP said ' + answer.decision + ', and this PEP is ' +
          'deny-biased, so anything that is not Permit is a refusal.';
    } else {
      why = denied ? 'The PDP said Deny.'
        : 'The PDP said ' + answer.decision + ', and this PEP is ' +
          'permit-biased, so anything that is not Deny is allowed.';
    }
    if (allowed && undischargeable.length) {
      allowed = false;
      why = 'The PDP said ' + answer.decision + ', but the decision carries ' +
            (undischargeable.length === 1 ? 'an obligation' : 'obligations') +
            ' this PEP cannot discharge (' + undischargeable.join(', ') +
            '). Section 7.2: a PEP that cannot fulfil an obligation MUST NOT ' +
            'grant the access. Allowing it and dropping the obligation would ' +
            'enforce half a policy and report success.';
    }
    log.debug('Leaving XacmlSurface.enforce(). ' +
              (allowed ? 'Allowed.' : 'Refused.'));
    return { allowed: allowed, bias: bias, why: why, discharged: discharged,
             undischargeable: undischargeable };
  }

  // ===========================================================================
  // PHASE FIVE: THE REMOTE PEP. THREE ENDPOINTS, AND THE PULL IS THE CONTRACT.
  //
  //   POST /xacml/pep/register   a PEP says it exists, over mutual TLS
  //   GET  /xacml/pep/policies   the repository, for a PEP to LOAD and
  //                              evaluate
  //   POST /xacml/pep/heartbeat  what it has enforced, and what it holds
  //
  // ---------------------------------------------------------------------------
  // WHY THE PEP PULLS AND THIS SERVICE DOES NOT PUSH.
  //
  // A remote PEP holds its own copy of the engine and evaluates locally — which
  // is the whole point of having one, because a PEP that asked this service per
  // request would be `POST /xacml/pdp` with extra steps and would put a network
  // hop in front of every access decision. So something has to move POLICY from
  // here to there, and it could have moved either way.
  //
  // It moves by PULL, for three reasons and the first is this repository's own:
  //
  //   1. **A PUSH WOULD BE AN OUTBOUND REQUEST CARRYING CONTENT.** Outbound
  //      requests are deliberately rare here — federation's and SSF's headers
  //      each argue their own — and a push would make policy DISTRIBUTION
  //      depend on this service being able to dial every PEP. The nudge below
  //      is an outbound request too, and it is affordable precisely because it
  //      carries nothing.
  //   2. **A PEP KNOWS WHEN IT IS BEHIND AND THIS SERVICE DOES NOT.** Under
  //      push, a PEP that was down for a minute has a stale copy and no way to
  //      discover it; under pull, being current is the PEP's own responsibility
  //      and it is checked on every poll. That inverts the failure: a network
  //      partition leaves a pulling PEP knowingly stale rather than unknowingly
  //      wrong.
  //   3. **IT WORKS WHERE A PEP CANNOT BE DIALLED.** Behind NAT, in another
  //      cluster, on a laptop. A PDP that could only serve PEPs it could reach
  //      would be a PDP for one deployment topology.
  //
  // **AND THE NUDGE DOES NOT CHANGE ANY OF THAT.** When the repository changes,
  // this service POSTs a few bytes to each registered PEP that gave a URL,
  // saying "pull now". It is an optimisation over the polling interval and
  // never the mechanism — `xacml_pep_http.ts` makes that argument at length,
  // because it is what makes a third outbound requester affordable in this
  // repository.
  //
  // ---------------------------------------------------------------------------
  // WHAT IS AUTHENTICATED HERE.
  //
  // **EVERY ENDPOINT IN THIS FAMILY, AND THIS BLOCK USED TO SAY OTHERWISE.** It
  // read that `POST /xacml/pdp` and `GET /xacml/pep/policies` needed no
  // credential — and the second of those had already stopped being true when
  // `pepAccess()` went in front of that endpoint, in this same file, on the
  // same day. Both go through the four-step chain below now, and the four
  // endpoints at the top of this file go through `xacmlAccess()`, which is the
  // same chain with `XACML_USER` on the end.
  //
  // **WHAT DID NOT CHANGE IS THE ARGUMENT.** A PDP is still not an
  // authorization boundary and the identity that matters is still IN the
  // request — the gate decides who may ASK and nothing it learns reaches
  // `decide()`. A policy is still a rule, and a rule nobody can read is a rule
  // nobody can check; the documents are still served in full to anybody the
  // policy admits. What changed is that *who may read it* turned out to be a
  // different question from *is it redacted*, once these became the documents
  // this service decides its own admissions with.
  //
  // **REGISTERING ASKS A SECOND QUESTION ON TOP**, and it is a different one:
  // not who the decision is about, but WHICH PEP IS THIS. That question has an
  // answer worth having, because a registration writes a directory entry, puts
  // a row on the console, and supplies an address this service will later dial.
  // So `xacml.pepRequireCertificate` is on by default and a registration with
  // no client certificate is refused.
  //
  // It is a TURNSTILE like every other gate here. The certificate need not
  // chain to anything — RFC 8705 section 3's argument applies unchanged, that
  // what is proved is that the same key completed the handshake — and the main
  // listener already asks for one (`server.js`: `requestCert: true,
  // rejectUnauthorized: false`), so phase five needed no new socket and no new
  // TLS configuration at all.
  //
  // **AND THE REGISTRATION IS NOT A PERMISSION.** An unregistered PEP can pull
  // and enforce perfectly. What registration buys is visibility and a nudge,
  // and `xacml_pep_registry.ts` says so where the register is defined, because
  // the shape looks like an access-control list and is not one.
  // ===========================================================================

  private remotePepsEnabled(): boolean {
    const { log, config } = this.deps;
    log.debug("Entering XacmlSurface.remotePepsEnabled().");
    log.debug("Leaving XacmlSurface.remotePepsEnabled().");
    return config.value('xacml.remotePeps') !== false;
  }

  // The same shape `offCheck()` has one screen up, and a second function rather
  // than a parameter because the two answer different sentences: one says XACML
  // is off here, the other says XACML is on and remote enforcement points are
  // not. A caller told the first when the second was true would go looking in
  // the wrong place.
  private remotePepOffCheck(res: Res): boolean {
    const self = this;
    const { log, errorCodes } = this.deps;
    log.debug('Entering XacmlSurface.remotePepOffCheck().');
    if (self.offCheck(res)) {
      log.debug('Leaving XacmlSurface.remotePepOffCheck(). XACML is off.');
      return true;
    }
    if (self.remotePepsEnabled()) {
      log.debug('Leaving XacmlSurface.remotePepOffCheck(). On.');
      return false;
    }
    errorCodes.mark(res, 'STS-XACML-0002');
    res.status(501).type('application/json').set('Cache-Control', 'no-store')
       .send(JSON.stringify({
         error: 'not_implemented',
         error_description:
           'XACML is on, but remote Policy Enforcement Points are turned off ' +
           'on this service (xacml.remotePeps). The register in ou=peps is ' +
           'untouched, so a PEP that was registered is still listed and ' +
           'comes back the moment this is turned on again.'
       }, null, 2));
    log.debug('Leaving XacmlSurface.remotePepOffCheck(). Off.');
    return true;
  }

  // ---------------------------------------------------------------------------
  // WHAT A PEP IS TOLD ITS IDENTITY IS.
  //
  // One function, so that the registration and the refusal cannot disagree
  // about what the connection carried. It returns what was presented rather
  // than a verdict — the caller decides what to do about `authenticated:
  // false`, because that is `xacml.pepRequireCertificate`'s decision and not
  // this function's.
  // ---------------------------------------------------------------------------
  private callerIdentity(req: Req): CallerIdentity {
    const { log, mtls, peps } = this.deps;
    log.debug('Entering XacmlSurface.callerIdentity().');
    const certificate = mtls.peerCertificate(req);
    if (!certificate) {
      log.debug('Leaving XacmlSurface.callerIdentity(). No client ' +
                'certificate.');
      return { authenticated: false, verified: false, subject: '',
               thumbprint: '', dn: '', commonName: '',
               why: 'No client certificate was presented.' };
    }
    // PRESENTED AND VERIFIED, KEPT APART (2026-09-06). `authenticated` has
    // always meant "a certificate arrived" on this door, and it still does —
    // RFC 8705 binding rests on the certificate rather than on anybody's
    // opinion of it, and `xacml.pepRequireCertificate` was written against that
    // meaning. `verified` is the new, stronger question: did the chain build to
    // an anchor in this service's truststore. **THE DIFFERENCE IS WHAT MAKES A
    // DN WORTH READING**: a name off an unverified certificate is a name the
    // caller chose for itself, and the identity resolution below must not rest
    // on one.
    const verdict = mtls.peerVerified(req);
    // The DN and the common name come from `certificatePlan()`, across the
    // register's slot — this service already has exactly one answer to "what
    // identity is this certificate" and a second one written here would be how
    // a PEP ends up filed under two names on two pages.
    const named = peps.certificateIdentity(certificate);
    const identity = {
      authenticated: true,
      verified: verdict.verified,
      // A chain that built and was REFUSED ON REVOCATION (2026-09-12) is
      // `verified: false` — `mtls.peerVerified()` decides that — and carries
      // the verdict so the two refusals below can mark the revocation code
      // rather than the "did not verify" one, which would send an operator
      // looking at the truststore for a certificate that is in it.
      revocationRefused: !!(verdict.revocation && verdict.revocation.refused),
      revocation: verdict.revocation || null,
      why: verdict.why,
      subject: named.subject,
      // RFC 8705 x5t#S256, through the same function the token endpoint binds a
      // certificate-bound token with, so the two spellings cannot drift.
      thumbprint: mtls.presentedThumbprint(req),
      dn: named.dn,
      commonName: named.commonName
    };
    log.debug('Leaving XacmlSurface.callerIdentity(). dn=' + identity.dn);
    return identity;
  }

  // ===========================================================================
  // MAY THIS CALLER REACH THE REMOTE-PEP ENDPOINTS AT ALL? (2026-09-06)
  //
  // **THIS IS THE ONE PLACE THE CERTIFICATE STOPS BEING A HANDSHAKE AND BECOMES
  // AN IDENTITY.** Four steps, and each is a different question that a
  // different part of this service answers:
  //
  //   1. WAS A CHAIN BUILT? `mtls.peerVerified()` — did what arrived verify
  //      against an anchor in the truststore `POST /tls/trust` fills. A
  //      certificate that verified against nothing is a name the caller chose
  //      for itself, and everything below would be reading it.
  //   2. WHICH ENTRY IS THAT? `peps.certificateIdentity()` across the
  //      registry's slot, which is the same lookup a certificate arriving on
  //      the main port or 636 gets — so one certificate is one person here
  //      however it turns up.
  //   3. WHAT DO THEY HOLD? `roles.rolesOf()` with the groups LEFT UNRESOLVED,
  //      deliberately: passing no `groups` is what makes that module read them
  //      out of the directory, and passing `[]` would mean "in no group" and
  //      quietly answer no to every group-derived role — REMOTE_PEPS among
  //      them.
  //   4. DOES THE POLICY ALLOW IT? `accessGate.check()`, which is the SAME
  //      embedded PEP and the SAME access-control document that decide the
  //      console, the management API and the portal. The requirement travels in
  //      the request rather than being tested here, so an operator who edits
  //      that policy changes this answer too.
  //
  // **WHY THE GATE RATHER THAN AN `if` ON THE ROLE.** Because the whole design
  // of this family is that access decisions are POLICY decisions, and a
  // hard-coded role test on three endpoints would be the one surface in this
  // service whose answer no document explains and no `/admin/xacml/decide`
  // reproduces.
  //
  // WHAT IT DOES NOT DO: it does not require a certificate. That is
  // `xacml.pepRequireCertificate`'s decision, it is made at the registration,
  // and it can be turned off — a deployment that has turned it off has said it
  // wants unauthenticated PEPs, and this gate then sees an anonymous subject
  // holding only EVERYBODY and refuses it on the policy, which is the correct
  // and visible outcome rather than a second refusal spelt differently.
  // ===========================================================================
  private pepAccess(req: Req, res: Res, action: string,
                    what: string,
                    known?: CallerIdentity): AccessResult {
    const self = this;
    const { log, config, errorCodes, roles, accessGate } = this.deps;
    log.debug('Entering XacmlSurface.pepAccess(). action=' + action);
    // `known` IS AN OPTIONAL PRE-RESOLVED IDENTITY, and it exists for exactly
    // one caller: `POST /xacml/pip` rate-limits on the DN, so it has to know
    // who is asking BEFORE it asks whether they may. Reading the certificate
    // twice would be a second `getPeerCertificate()` and a second DN parse per
    // request — and, worse, two places that could come to disagree about who
    // the caller is. Omitting it is what the other three doors do and is
    // unchanged.
    const identity = known || self.callerIdentity(req);
    // THE NAME IS THE VERIFIED DN OR NOTHING AT ALL. An unverified
    // certificate's DN must never reach `rolesOf()`: it would be an
    // unauthenticated caller naming itself into a group, which is the one thing
    // this whole chain exists to prevent.
    const name = identity.verified ? identity.dn : '';
    const held = name
      ? roles.rolesOf({ kind: 'user', name: name, authenticated: true })
      : [];
    const policy = accessGate.check({
      resource: accessGate.RESOURCE.XACML_PEP_API,
      action: action,
      requiredRoles: [REMOTE_PEP_ROLE],
      subject: { name: name, authenticated: !!identity.verified, roles: held },
      context: { method: req.method, path: req.originalUrl || req.url }
    });
    if (policy.allowed) {
      log.debug('Leaving XacmlSurface.pepAccess(). Allowed.');
      return { allowed: true, identity: identity, roles: held };
    }
    log.info('xacml: the access policy refused ' + what + ' for ' +
             (name || 'an unidentified caller') + '. ' + policy.why);
    if (!identity.authenticated) {
      errorCodes.mark(res, 'STS-XACML-0007');
    } else if (identity.revocationRefused) {
      errorCodes.mark(res,
                      errorCodes.codeOf(identity.revocation) || 'STS-PKI-0118');
    } else if (!identity.verified) {
      errorCodes.mark(res, 'STS-XACML-0008');
    } else if (held.indexOf(REMOTE_PEP_ROLE) < 0) {
      errorCodes.mark(res, 'STS-XACML-0009');
    } else {
      errorCodes.mark(res, 'STS-XACML-0010');
    }
    self.fail(res, 403, 'access_denied',
      'The access policy refused this request. ' + policy.why +
      ' A remote Policy Enforcement Point reaches these endpoints by ' +
      'presenting a client certificate this service VERIFIES — the issuing ' +
      'CA goes in with POST /tls/trust — whose subject resolves to a ' +
      'directory entry that is a member of the group named by ' +
      'roles.remotePepGroup ("' +
      String(config.value('roles.remotePepGroup') || '') +
      '"), which is what ' +
      'grants the built-in ' + REMOTE_PEP_ROLE + ' role. This caller ' +
      (identity.verified
        ? 'presented a certificate that VERIFIED, resolved to "' + name +
          '", and holds ' + (held.length ? held.join(', ') : 'no role') + '.'
        : (identity.authenticated
            ? 'presented a certificate that did NOT verify: ' + identity.why
            : 'presented no client certificate at all.')) +
      ' xacml.enforceAccess turns this layer off.');
    log.debug('Leaving XacmlSurface.pepAccess(). Refused.');
    return { allowed: false };
  }

  // ===========================================================================
  // POST /xacml/pip — THE POLICY INFORMATION POINT, OVER HTTP. XML IN, XML OUT.
  //
  // ---------------------------------------------------------------------------
  // THE GAP IT CLOSES, WHICH IS A REAL ONE AND NOT A CONVENIENCE.
  //
  // A remote PEP holds its own copy of the engine and evaluates locally — that
  // is the whole point of having one. What it does NOT hold is the PIP: this
  // service's PIP *is* the embedded directory (`xacml_pip.ts`'s first
  // sentence), and a process in another container has no access to it. So a
  // policy with an attribute designator the request did not carry resolves to
  // an EMPTY BAG out there and to a real value in here, and **the same policy
  // decides two different ways in two enforcement points** — which is the drift
  // a shared repository exists to prevent, reappearing one layer down.
  //
  // The remote PEP could not have fixed this for itself: the attributes are on
  // directory entries this service owns, and handing a PEP an LDAP connection
  // would be a much larger grant than handing it an answer to one question.
  //
  // ---------------------------------------------------------------------------
  // **XACML DEFINES NO PIP PROTOCOL, SO THIS INVENTS AS LITTLE AS POSSIBLE.**
  //
  // The specification describes the PIP as an architectural component and says
  // nothing about how a PDP reaches one — there is no request document, no
  // response document and no binding. So the temptation is to design a JSON
  // envelope of this service's own, and the first draft of this endpoint did
  // exactly that. It was wrong, and the reason is worth keeping: an invented
  // vocabulary means the remote PEP has to TRANSLATE, and every translation is
  // somewhere the two engines can come to disagree about a datatype, a category
  // or what an absent value means. That is the drift this endpoint exists to
  // remove, moved into the transport.
  //
  // So both directions are **XACML's own XML**, and the envelope is two
  // elements thick:
  //
  //   REQUEST   `<PIPRequest>` carrying the XACML `<Request>` the PDP is
  //             deciding — which is what names the subject — and one
  //             `<AttributeDesignator>` per attribute wanted. Both are exactly
  //             the elements the core schema already defines, read by
  //             `xacml_xml.js`'s own `readRequest()` and `readExpression()`
  //             rather than by anything written here.
  //
  //   RESPONSE  `<PIPResponse>` carrying `<Attributes>` elements **in the XACML
  //             core namespace, in the shape a `<Request>` carries them**.
  //
  // ---------------------------------------------------------------------------
  // THAT RESPONSE SHAPE IS THE WHOLE DESIGN, AND IT IS WHAT MAKES THE REMOTE
  // PEP BEHAVE LIKE THE EMBEDDED ONE.
  //
  // A PIP's answer is a bag of attribute values for a designator. The XACML XML
  // rendering of exactly that already exists: it is the `<Attributes>` /
  // `<Attribute>` / `<AttributeValue>` tree a `<Request>` is made of. So what
  // comes back here is a REQUEST FRAGMENT, and a remote PEP has two ways to use
  // it and neither needs a translator:
  //
  //   * splice the `<Attributes>` into its own request and evaluate — after
  //     which its engine finds the values where a designator looks for them,
  //     which is precisely what happens in this process when the embedded PDP
  //     asks the embedded PIP; or
  //   * read them with its own copy of `xacml_xml.js`'s request reader, which
  //     is the same code that read them out here.
  //
  // **AN EMPTY BAG IS AN ABSENT `<Attribute>` AND NOT AN EMPTY ONE.** Two
  // reasons and they point the same way. The schema requires at least one
  // `<AttributeValue>` inside an `<Attribute>`, so an empty one is not a legal
  // request fragment and a PEP splicing it would produce a request its own
  // parser refuses. And *the request did not carry it* is what an unresolved
  // designator ALREADY looks like to every engine — so a remote PEP that
  // receives nothing behaves exactly as the embedded PDP behaves when the PIP
  // answers nothing, with no branch of its own.
  //
  // **`MustBePresent` IS READ AND DELIBERATELY NOT APPLIED.** It is carried on
  // the designator, this endpoint parses it, and it changes nothing here:
  // whether an empty bag ends a decision is settled by the designator and by
  // the function the bag is handed to, and both of those are in the CALLER's
  // engine. Applying it here would move a decision across a network boundary
  // and answer a question nobody asked — and it would make an absent attribute
  // an ERROR on the wire, which is the classic PIP defect in its most damaging
  // form.
  //
  // ---------------------------------------------------------------------------
  // `<Unresolved>` IS THE ONE THING HERE THAT IS NOT XACML, AND IT IS OUT OF
  // THE WAY ON PURPOSE.
  //
  // A bag can be empty for five reasons that need five different fixes, and to
  // a PDP they are one empty bag and must be. That is correct for deciding and
  // useless for debugging — `xacml_pip.ts` logs the difference at debug level,
  // in a log that is in another container as far as the caller is concerned.
  //
  // So the reasons come back in a `<Unresolved>` element in **this service's
  // own namespace**, a sibling of the `<Attributes>` rather than inside them. A
  // PEP that reads only the XACML core namespace — which is every PEP — never
  // sees it, so the payload stays a clean request fragment; a person or a PEP
  // that wants to know why finds it named. Adding a diagnostic INSIDE the core
  // namespace would have been the mistake: it would put an element the OASIS
  // schema does not define into a document a caller is invited to splice.
  //
  // ---------------------------------------------------------------------------
  // IT REQUIRES `REMOTE_PEPS` AND NOT `XACML_USER`, AND THAT IS THE ONE PLACE
  // THE ROLE DOES NOT FOLLOW THE PATH.
  //
  // Every other endpoint under `/xacml/*` that is not under `/xacml/pep/*`
  // requires `XACML_USER`. This one does not, and the exception is deliberate —
  // the `Requires` column on `GET /xacml` exists precisely so that a role never
  // has to be inferred from a path.
  //
  // **WHAT COMES BACK IS SOMEBODY'S PERSONAL DATA**, off their own directory
  // entry, named by whoever asked. That is a strictly stronger thing to hand
  // out than a policy document: a policy is a rule anybody may check, and
  // `mail`, `employeeType` and `departmentNumber` are facts about a person. The
  // narrower role is the right one, and the caller this was built for — a
  // remote enforcement point resolving a designator mid-evaluation — holds it
  // already.
  //
  // **THE PATH IS `/xacml/pip` AND NOT `/xacml/pep/attributes`** because this
  // repository names an endpoint for the COMPONENT it is, the way `/xacml/pdp`
  // is named for the PDP. A reader looking for the Policy Information Point
  // finds it where its name says it is; who may call it is a fact about the
  // policy, which changes, and putting that in the path would freeze it there.
  //
  // **AND `xacml.remotePeps` TURNS IT OFF WITH THEM**, which is the same
  // decision read from the other side: the switch follows the CALLER rather
  // than the name, so a deployment that has said it wants no enforcement point
  // outside this process does not keep an endpoint handing out directory
  // attributes to one. The handler carries the argument.
  //
  // **IT IS NOT COUNTED ON `/admin/xacml/monitor`.** That page keeps decisions
  // and enforcements apart and reconciles a total; a PIP query is neither, and
  // recording it as either would make a number that means two things. It IS
  // audited — `xacml.pip.query`, one row per call rather than per designator —
  // because a read of a named person's directory attributes by another process
  // is exactly what an audit log is for.
  // ===========================================================================

  pipMaxDesignators(): number {
    const { log, config } = this.deps;
    log.debug("Entering XacmlSurface.pipMaxDesignators().");
    const n = Number(config.value('xacml.pipMaxDesignators'));
    log.debug("Leaving XacmlSurface.pipMaxDesignators().");
    return isFinite(n) && n > 0 ? Math.floor(n) : PIP_MAX_DESIGNATORS;
  }

  // ---------------------------------------------------------------------------
  // WHY A BAG IS EMPTY. Five reasons, five different fixes, and the resolver
  // cannot tell them apart — deliberately, because a PDP must see one empty bag
  // whichever it was. This is the only place the difference is visible to a
  // caller, and it is why `<Unresolved>` exists.
  // ---------------------------------------------------------------------------
  private pipWhy(designator: any, subject: string, stored: any,
                 mapped: string | null): string {
    const { log, model, pip } = this.deps;
    log.debug("Entering XacmlSurface.pipWhy().");
    if (designator.category !== model.CATEGORY.ACCESS_SUBJECT) {
      log.debug("Leaving XacmlSurface.pipWhy().");
      return 'Only the access-subject category is resolved by this PIP: a ' +
             'resource or environment designator has no directory entry to ' +
             'be looked up on.';
    }
    if (!mapped) {
      log.debug("Leaving XacmlSurface.pipWhy().");
      return 'That AttributeId is not a directory attribute name. This PIP ' +
             'accepts a bare LDAP name (mail, employeeType) or the prefix ' +
             pip.ATTRIBUTE_PREFIX + '<name>; a standard XACML URI is ' +
             'deliberately never mapped to an entry, because a policy could ' +
             'then silently read a different subject-id from the one being ' +
             'decided about.';
    }
    if (!subject) {
      log.debug("Leaving XacmlSurface.pipWhy().");
      return 'The request names no ' + model.ATTRIBUTE.SUBJECT_ID +
             ', so there is no entry to read. That is an ordinary request ' +
             'rather than an error.';
    }
    if (!stored) {
      log.debug("Leaving XacmlSurface.pipWhy().");
      return 'No directory entry resolves from the subject "' + subject + '".';
    }
    // THE LAST TWO ARE THE ONES WORTH SEPARATING. An entry that does not hold
    // the attribute is a policy designating something nobody has set; an entry
    // that holds it in a form the declared datatype cannot read is a DATA
    // problem, and it is the one a caller would otherwise chase in the wrong
    // place — this service drops such a value with a warning in a log the
    // caller cannot see.
    const raw = pip.rawAttribute(stored.attributes, mapped);
    if (raw === undefined || raw === null) {
      log.debug("Leaving XacmlSurface.pipWhy().");
      return 'The entry for "' + subject + '" does not hold "' + mapped + '".';
    }
    const count = Array.isArray(raw) ? raw.length : 1;
    log.debug("Leaving XacmlSurface.pipWhy().");
    return 'The entry for "' + subject + '" holds ' + count +
           ' value(s) for "' + mapped + '", and none of them parses as ' +
           designator.dataType +
           '. Each was dropped with a warning rather than making the ' +
           'decision Indeterminate: one bad value among five must not take ' +
           'the other four with it.';
  }

  // ---------------------------------------------------------------------------
  // THE RESPONSE DOCUMENT.
  //
  // Grouped into ONE `<Attributes>` per category, in the order the designators
  // were asked in, because that is what a `<Request>` looks like and a caller
  // is invited to splice this straight into one. Several `<Attributes>` of the
  // same category IS legal — it is how the Multiple Decision Profile's scheme
  // 2.3 works — but a fragment that used it here would be a request fragment
  // shaped unlike any request, for no gain.
  // ---------------------------------------------------------------------------
  private writePipResponse(answers: PipAnswer[],
                           unresolved: PipUnresolved[]): string {
    const { log, xmlEscape, model } = this.deps;
    log.debug("Entering XacmlSurface.writePipResponse().");
    const byCategory = [];
    answers.forEach(function (answer) {
      let group = byCategory.filter(function (one) {
        return one.category === answer.category;
      })[0];
      if (!group) {
        group = { category: answer.category, attributes: [] };
        byCategory.push(group);
      }
      group.attributes.push(answer);
    });
    const parts = ['<?xml version="1.0" encoding="UTF-8"?>',
                   '<PIPResponse xmlns="' + PIP_NS + '">'];
    byCategory.forEach(function (group) {
      parts.push('  <Attributes xmlns="' + model.NS_XACML + '" Category="' +
                 xmlEscape(group.category) + '">');
      group.attributes.forEach(function (answer) {
        // `IncludeInResult="false"` explicitly rather than by omission. It is
        // what the resolver's values would have carried had they been resolved
        // in process, and a PEP splicing this into a request it then echoes
        // must not start reporting this service's directory contents back to
        // its own callers.
        parts.push('    <Attribute AttributeId="' +
                   xmlEscape(answer.attributeId) +
                   '" IncludeInResult="false">');
        answer.values.forEach(function (lexical) {
          parts.push('      <AttributeValue DataType="' +
                     xmlEscape(answer.dataType) + '">' + xmlEscape(lexical) +
                     '</AttributeValue>');
        });
        parts.push('    </Attribute>');
      });
      parts.push('  </Attributes>');
    });
    if (unresolved.length) {
      parts.push('  <Unresolved>');
      unresolved.forEach(function (one) {
        parts.push('    <Designator Category="' + xmlEscape(one.category) +
                   '" AttributeId="' + xmlEscape(one.attributeId) +
                   '" DataType="' + xmlEscape(one.dataType) +
                   '" MustBePresent="' +
                   (one.mustBePresent ? 'true' : 'false') +
                   '">');
        parts.push('      <Reason>' + xmlEscape(one.why) + '</Reason>');
        parts.push('    </Designator>');
      });
      parts.push('  </Unresolved>');
    }
    parts.push('</PIPResponse>');
    log.debug("Leaving XacmlSurface.writePipResponse().");
    return parts.join('\n') + '\n';
  }

  // A refusal, in XML, because a caller that POSTed XML and asked for nothing
  // else should not have to parse two content types to find out what went
  // wrong. It carries the same two members `fail()` does so that a reader
  // moving between this endpoint and the seven beside it meets one vocabulary.
  // error-code: none — the helper's definition, not a call to it.
  private pipFail(res: Res, status: number, code: string,
                  description: string): void {
    const { log, xmlEscape } = this.deps;
    log.debug("Entering XacmlSurface.pipFail().");
    res.status(status).type('application/xml').set('Cache-Control', 'no-store')
       .send('<?xml version="1.0" encoding="UTF-8"?>\n' +
             '<PIPError xmlns="' + PIP_NS + '" error="' + xmlEscape(code) +
             '">\n  <Description>' + xmlEscape(description) +
             '</Description>\n</PIPError>\n');
    log.debug("Leaving XacmlSurface.pipFail().");
  }

  // ---------------------------------------------------------------------------
  // THE SCALARS A CALLER CHOOSES, AND WHY THE XML READERS DO NOT COVER THEM.
  //
  // `xacml_xml.js` reads a `<Request>` and an `<AttributeDesignator>` and is
  // held to 454 of 455 OASIS conformance cases, so what a DESIGNATOR is is not
  // this file's to re-check — a schema over it would be a second, worse reading
  // of a specification this directory implements. What those readers do NOT do
  // is bound a string: `requiredAttribute()` returns whatever the attribute
  // holds, and a conformance suite has no opinion about an AttributeId a
  // megabyte long.
  //
  // **THREE OF THESE COME BACK OUT AGAIN**, which is what makes the bound
  // matter rather than being tidiness. An unresolved designator is echoed into
  // `<Unresolved>`, every one of them is named in the `xacml.pip.query` audit
  // row, and the subject goes into that row and into `locateEntry()`. So a
  // caller choosing the length chooses how much of somebody else's audit log
  // and this process's memory it spends.
  //
  // The caps are `validation.js`'s own: an AttributeId and a category are
  // IDENTIFIERs (they are URIs in practice, but a URI cap of 2048 on a name
  // this service only ever compares and echoes buys nothing), and a subject is
  // a NAME — the same cap `userFor()` and every other door in this service puts
  // on one.
  // ---------------------------------------------------------------------------
  private pipScalarProblem(what: string, value: unknown,
                           cap: number): string {
    const { log } = this.deps;
    log.debug("Entering XacmlSurface.pipScalarProblem().");
    const text = String(value === undefined || value === null ? '' : value);
    if (text.length > cap) {
      log.debug("Leaving XacmlSurface.pipScalarProblem().");
      return 'the ' + what + ' is ' + text.length + ' characters and the ' +
             'limit is ' + cap + '. It is echoed back in <Unresolved>, ' +
             'written into this service\'s audit log, and held in memory ' +
             'while the ' +
             'query is answered, so its length is not the caller\'s to choose.';
    }
    // CONTROL CHARACTERS, on the STRICT reading. These end up in an XML
    // attribute value in the reply and in a log line; a NUL or an escape
    // sequence in either is a caller writing something other than what it
    // appears to be writing. `xmlEscape()` handles `<`, `>`, `&` and quotes and
    // has nothing to say about C0.
    if (/[\u0000-\u001F\u007F]/.test(text)) {
      log.debug("Leaving XacmlSurface.pipScalarProblem().");
      return 'the ' + what + ' carries a control character. It is written ' +
             'into ' +
             'an XML attribute value and into a log line, and neither is a ' +
             'place for one.';
    }
    log.debug("Leaving XacmlSurface.pipScalarProblem().");
    return '';
  }

  // ---------------------------------------------------------------------------
  // THE NUDGE, FIRED WHEN THE REPOSITORY CHANGES.
  //
  // Installed as `xacml_store.ts`'s change observer, which is an inverted hook
  // for a mechanical reason that file states: the register requires the store
  // for the sync token, so a require in the obvious direction closes a cycle.
  //
  // **NOTHING WAITS ON THIS.** The promise is deliberately not returned and not
  // awaited: the console form that saved a policy has finished its work whether
  // or not four PEPs answered, and a save that blocked on somebody else's web
  // server would be exactly the mistake `saml/CLAUDE.md` records about not
  // dialling a service provider's metadata URL while issuing. What each PEP
  // answered is recorded on its own row and read on /admin/xacml/peps.
  //
  // ON AN ACTIVE-ACTIVE NODE THE NUDGE WAITS FOR THE COMMIT (2026-09-15, #46).
  //
  // The observer runs inside `xacml_store.write()`, so the nudge left while the
  // policy was in this node's memory and not yet in the store. The PEP answers
  // 204 and pulls at once — through the load balancer, on whatever node its
  // connection lands — and a node that is not this one serves from what has
  // COMMITTED: it answered the old sync token (304), and the PEP converged on
  // its next heartbeat or poll instead. The suite's `cluster` mode measured
  // 2018ms and 916ms for a nudge that takes tens of milliseconds on one node.
  //
  // So a clustered node dispatches it once `persistence.commitThrough()` says
  // the write has reached the store: after `setImmediate`, so the request that
  // made the change has usually answered and its barrier's commit is the flush
  // in flight this shares, rather than a second transaction started
  // mid-request. A commit that fails still nudges — the nudge is an
  // optimisation, and the PEP's pull then converges as it would have.
  // Everywhere else (one node, the cluster off, a dispatched pool) nothing
  // changes: the nudge goes at once.
  // ---------------------------------------------------------------------------
  private afterCommit(dispatch: () => void): void {
    const { log, errorCodes, loadBarrier, loadPersistence } = this.deps;
    log.debug("Entering XacmlSurface.afterCommit().");
    const barrier = loadBarrier();
    if (!barrier.isActive()) {
      log.debug("Leaving XacmlSurface.afterCommit(). Not active-active; " +
                "at once.");
      dispatch();
      return;
    }
    setImmediate(function () {
      const persistence = loadPersistence();
      Promise.resolve().then(function () {
        return persistence.commitThrough(persistence.writeGeneration());
      }).then(function (results) {
        const failed = (results || []).filter(function (one) {
          return one && one.error;
        });
        if (failed.length) {
          log.debug('xacml: the policy change did not commit before the ' +
                    'nudge (' + failed.map(function (one) {
                      return one.error;
                    }).join('; ') + '); nudging anyway.');
        }
      }, function (e) {
        log.debug("Caught in XacmlSurface.afterCommit(): " +
                  ((e && e.message) || e));
      }).then(dispatch).catch(function (error) {
        // What `changed()` in xacml_store.ts catches when the nudge goes at
        // once, caught here because a deferred dispatch has left that frame.
        log.warn(errorCodes.tag('STS-XACML-0060') +
                 'xacml: the repository change observer threw and the change ' +
                 'itself was fine: ' + ((error && error.message) || error));
      });
    });
    log.debug("Leaving XacmlSurface.afterCommit(). Deferred until the commit.");
  }

  nudgeRegisteredPeps(what: string): void {
    const self = this;
    const { log, pepHttp } = this.deps;
    log.debug('Entering XacmlSurface.nudgeRegisteredPeps(). what=' + what);
    if (!pepHttp.notifyAllowed() || !self.remotePepsEnabled()) {
      log.debug('Leaving XacmlSurface.nudgeRegisteredPeps(). Turned off.');
      return;
    }
    self.afterCommit(function () {
      self.dispatchNudge(what);
    });
    log.debug('Leaving XacmlSurface.nudgeRegisteredPeps().');
  }

  private dispatchNudge(what: string): void {
    const { log, errorCodes, peps, pepHttp } = this.deps;
    log.debug('Entering XacmlSurface.dispatchNudge(). what=' + what);
    const rows = peps.notifiable();
    if (!rows.length) {
      log.debug('Leaving XacmlSurface.dispatchNudge(). Nobody to nudge.');
      return;
    }
    log.info('xacml: ' + what + '; nudging ' + rows.length +
             ' registered PEP(s) to pull. The nudge is an optimisation — ' +
             'every one of them would converge on its next poll without it.');
    pepHttp.nudgeAll(rows, '', peps.recordNotify).then(function (results) {
      const failed = results.filter(function (one) {
        return !one.ok;
      });
      if (failed.length) {
        log.warn('xacml: ' + failed.length + ' of ' + results.length +
                 ' nudge(s) were not delivered. Each is recorded on that ' +
                 'PEP\'s row at /admin/xacml/peps. No policy change is lost ' +
                 'by this: those PEPs converge on their next poll.');
      }
    }).catch(function (error) {
      // `nudgeAll()` resolves rather than rejects for every ordinary failure,
      // so reaching here means a defect in this file rather than an unreachable
      // PEP. Logged and swallowed regardless: a policy that was written stays
      // written.
      log.warn(errorCodes.tag('STS-XACML-0065') +
               'xacml: the nudge dispatcher threw, which is a bug here ' +
               'rather than a PEP being unreachable: ' + error.message);
    });
    log.debug('Leaving XacmlSurface.dispatchNudge(). Dispatched.');
  }

  // Installs `nudgeRegisteredPeps()` as the repository's change observer.
  installChangeObserver(): void {
    const { log, store } = this.deps;
    log.debug("Entering XacmlSurface.installChangeObserver().");
    store.setChangeObserver(this.nudgeRegisteredPeps.bind(this));
    log.debug("Leaving XacmlSurface.installChangeObserver().");
  }

  // ---------------------------------------------------------------------------
  // GET /xacml — what this surface is.
  // ---------------------------------------------------------------------------
  description(req: Req): any {
    const self = this;
    const { log, baseUrlOf, config, store, pip, peps, pepHttp } = this.deps;
    log.debug("Entering XacmlSurface.description().");
    const root = store.root();
    const policies = store.all();
    log.debug("Leaving XacmlSurface.description().");
    return {
      enabled: self.enabled(),
      specification: 'OASIS XACML 3.0 (core), JSON Profile 1.1',
      pdpEndpoint: baseUrlOf(req) + '/xacml/pdp',
      repository: {
        container: 'ou=policies in the embedded directory',
        policies: policies.length,
        enabledPolicies: policies.filter(function (one) {
          return one.enabled;
        }).length,
        root: root ? root.name : null
      },
      pep: { embeddedAt: baseUrlOf(req) + '/xacml/protected',
             bias: config.value('xacml.pepBias') },
      // THE EMBEDDED PEP'S BIAS IS NOT REPORTED HERE FOR THE REMOTE ONES, and
      // the omission is deliberate: `xacml.pepBias` governs the endpoint above
      // and nothing else. A remote PEP is a separate process with its own
      // configuration and reports the bias it is actually running with on every
      // heartbeat, which is what /admin/xacml/peps shows.
      remotePeps: {
        enabled: self.remotePepsEnabled(),
        registerAt: baseUrlOf(req) + '/xacml/pep/register',
        policiesAt: baseUrlOf(req) + '/xacml/pep/policies',
        heartbeatAt: baseUrlOf(req) + '/xacml/pep/heartbeat',
        requiresCertificate:
          config.value('xacml.pepRequireCertificate') !== false,
        syncToken: peps.syncToken(),
        registered: peps.all().length,
        notify: pepHttp.notifyAllowed(),
        contract: 'THE PULL IS THE CONTRACT. A PEP polls the policies ' +
                  'endpoint on its own interval with ?since=<syncToken>; an ' +
                  'unchanged repository answers 304. The nudge this service ' +
                  'sends on a change is an optimisation over that interval ' +
                  'and never a replacement for it.'
      },
      pip: { source: 'the embedded directory, access-subject category only',
             attributePrefix: pip.ATTRIBUTE_PREFIX,
             available: pip.available() },
      conformance: '454 of the 455 mandatory OASIS conformance cases; see ' +
                   'xacml/conformance/ and xacml/CLAUDE.md.',
      // EVERY ROW SAYS WHAT IT REQUIRES, and the two answers are the point of
      // the column rather than decoration: the four endpoints proper require
      // XACML_USER and the four a remote enforcement point uses (the three
      // under /xacml/pep and POST /xacml/pip) require REMOTE_PEPS, so a reader
      // can see that being admitted to one surface is not being admitted to the
      // other. The role names are read from this file's own two constants
      // rather than spelt again, so a rename cannot leave this document
      // describing a gate that no longer exists.
      endpoints: [
        { method: 'GET', path: '/xacml', what: 'this document',
          requires: XACML_USER_ROLE },
        { method: 'POST', path: '/xacml/pdp',
          what: 'a decision — JSON Profile request in, response out',
          requires: XACML_USER_ROLE },
        { method: 'GET', path: '/xacml/policies',
          what: 'the repository as the PDP sees it, documents included',
          requires: XACML_USER_ROLE },
        { method: 'GET', path: '/xacml/protected',
          what: 'the embedded PEP: a resource guarded by this PDP',
          requires: XACML_USER_ROLE },
        { method: 'POST', path: '/xacml/pep/register',
          what: 'a remote PEP registers, over mutual TLS',
          requires: REMOTE_PEP_ROLE },
        { method: 'GET', path: '/xacml/pep/policies',
          what: 'the enabled policies for a remote PEP to LOAD and evaluate; ' +
                '?since=<syncToken> answers 304 when nothing changed',
          requires: REMOTE_PEP_ROLE },
        { method: 'POST', path: '/xacml/pep/heartbeat',
          what: 'what a remote PEP has enforced, and which repository it holds',
          requires: REMOTE_PEP_ROLE },
        { method: 'POST', path: '/xacml/pip',
          what: 'the Policy Information Point, in XACML\'s own XML: POST a ' +
                '<PIPRequest> carrying the <Request> you are deciding and ' +
                'one <AttributeDesignator> per attribute, get <Attributes> ' +
                'back in the shape a <Request> carries them. For a remote ' +
                'PEP, whose engine has no directory of its own',
          requires: REMOTE_PEP_ROLE }
      ],
      // WHAT A CALLER HAS TO PRESENT, said in the document a caller reads
      // rather than only in the refusal they get for not having it.
      access: {
        mechanism: 'a client certificate this service verifies against an ' +
                   'anchor in its own truststore (POST /tls/trust), whose ' +
                   'subject DN resolves to a directory entry',
        xacmlUserGroup: String(config.value('roles.xacmlUserGroup') || ''),
        remotePepGroup: String(config.value('roles.remotePepGroup') || ''),
        enforced: config.value('xacml.enforceAccess') !== false,
        note: 'The group is the GRANT and the certificate is only the ' +
              'IDENTITY: a valid certificate for a common name that is in ' +
              'neither group is fully authenticated and still refused. ' +
              'xacml.enforceAccess turns the whole layer off.'
      },
      notYetHere: [
        'AttributeSelector and the XPath functions — a policy using one is ' +
          'Indeterminate rather than silently empty'
      ]
    };
  }

  // Every route, in the order this file has always registered them — with
  // the change observer installed where it always was, between the PIP
  // and `GET /xacml`.
  registerRoutes(app: RouteTable): void {
    const self = this;
    const { log, xmlEscape, baseUrlOf, parseBody, validation, websecurity,
            config, audit, errorCodes, model, json, store, pip, datatypes,
            xml, validate, peps, pepHttp, monitor, accessGate } = this.deps;
    log.debug("Entering XacmlSurface.registerRoutes().");

    // -------------------------------------------------------------------------
    // POST /xacml/pdp — the decision endpoint.
    // -------------------------------------------------------------------------
    app.post('/xacml/pdp', function (req, res) {
      log.debug('Entering POST /xacml/pdp.');
      if (self.offCheck(res)) {
        log.debug('Leaving POST /xacml/pdp. Off.');
        return;
      }
      // WRITE AND NOT READ, which is the one action choice in this family that
      // is arguable. Nothing in the repository changes here — but a decision
      // request is a document this service PARSES and EVALUATES on its own
      // thread against every policy in the repository, which is work a caller
      // directs rather than a page a caller reads. Filing it as `read` would
      // put it in the same bucket as fetching the policy list, and an operator
      // writing "readers may look, nobody may drive the engine" would have no
      // way to say it.
      if (!self.xacmlAccess(req, res, accessGate.ACTION.WRITE,
                            'a decision request').allowed) {
        log.debug('Leaving POST /xacml/pdp. The access policy refused.');
        return;
      }
      // `app.js` parses every body as TEXT, which is what this endpoint wants
      // rather than a parsed object: the JSON Profile's integer/double
      // inference reads the raw source (see `xacml_json.js`, trap 1), and an
      // already-parsed body has thrown that away.
      const raw = typeof req.body === 'string' ? req.body
        : (Buffer.isBuffer(req.body) ? req.body.toString('utf8') : '');
      let request;
      try {
        request = json.parseRequest(raw);
      } catch (error) {
        log.debug("Caught in POST /xacml/pdp: " +
                  ((error && error.message) || error));
        // A MALFORMED REQUEST IS A 400, NOT AN INDETERMINATE, and the
        // distinction is the one a PEP most needs: an Indeterminate is an
        // answer ABOUT the request and a 400 says there was no request to
        // answer about. Collapsing them would have a PEP enforce its bias over
        // somebody's typo.
        log.debug('Leaving POST /xacml/pdp. The request would not parse.');
        errorCodes.mark(res, 'STS-XACML-0011');
        self.fail(res, 400, 'invalid_request', error.message);
        return;
      }
      const answer = self.decide(request);
      // A Permit, a Deny or a NotApplicable is the ANSWER and carries no code;
      // an Indeterminate this service reached through a fault does.
      if (errorCodes.codeOf(answer)) {
        errorCodes.mark(res, errorCodes.codeOf(answer));
      }
      // COUNTED AS A DECISION AND NOT AS AN ENFORCEMENT, which is the
      // distinction `/admin/xacml/monitor` is built around. Somebody else's PEP
      // asked; this service produced the decision and never saw what was done
      // with it, so the `pdp` row on that page carries the four decision counts
      // and an EMPTY allowed/refused cell rather than a zero. A zero there
      // would read as "it refused nothing", which is a claim about an
      // enforcement this service was not present for.
      monitor.record('pdp', { decision: answer.decision });
      audit.audit({
        action: 'xacml.decision',
        actor: pip.subjectOf(request) || '',
        protocol: 'XACML',
        detail: 'POST /xacml/pdp decided ' + answer.decision + '.'
      });
      res.status(200).type('application/json').set('Cache-Control', 'no-store')
         .send(JSON.stringify(json.writeResponse(answer), null, 2));
      log.debug('Leaving POST /xacml/pdp. ' + answer.decision);
    });

    // -------------------------------------------------------------------------
    // GET /xacml/policies — the repository as the PDP sees it.
    //
    // The DOCUMENT is included, because this is a debugger and the policy is
    // the thing somebody is trying to understand. That is a deliberate
    // departure from how `/admin/ldap/*` treats the directory — those pages
    // hide `oauthClientSecret` — and the argument for it is that a policy is
    // not a credential: it is a rule, and a rule nobody can read is a rule
    // nobody can check. Anything secret that ends up inside a policy document
    // is in the wrong place, and hiding the document would conceal that rather
    // than fix it.
    // -------------------------------------------------------------------------
    app.get('/xacml/policies', function (req, res) {
      log.debug('Entering GET /xacml/policies.');
      if (self.offCheck(res)) {
        log.debug('Leaving GET /xacml/policies. Off.');
        return;
      }
      if (!self.xacmlAccess(req, res, accessGate.ACTION.READ,
                            'a policy listing').allowed) {
        log.debug('Leaving GET /xacml/policies. The access policy refused.');
        return;
      }
      const root = store.root();
      const rows = store.all().map(function (row) {
        const view: Record<string, unknown> = {
          name: row.name, policyId: row.id, kind: row.kind,
          version: row.version,
          combiningAlgId: row.combiningAlgId,
          enabled: row.enabled,
          isRoot: !!(root && root.name === row.name),
          description: row.description,
          document: row.document };
        // A policy that does not load is reported HERE rather than only when a
        // decision meets it, because the moment somebody is looking at the list
        // is the moment they can fix it.
        try {
          const parsed = store.parseDocument(row.document);
          view.problems = validate.problemsIn(parsed);
        } catch (error) {
          log.debug("Caught in GET /xacml/policies: " +
                    ((error && error.message) || error));
          view.problems = [error.message];
        }
        return view;
      });
      res.status(200).type('application/json').set('Cache-Control', 'no-store')
         .send(JSON.stringify({
           root: root ? root.name : null,
           rootNote: root ? undefined
             : 'No policy is marked as the root, so every decision is ' +
               'NotApplicable. A PDP evaluates one document and reaches the ' +
               'rest through PolicyIdReference.',
           policies: rows
         }, null, 2));
      log.debug('Leaving GET /xacml/policies. ' + rows.length +
                ' policy(ies).');
    });

    // -------------------------------------------------------------------------
    // GET /xacml/protected — THE EMBEDDED PEP.
    //
    // Builds a request out of the caller, asks the PDP, and enforces the
    // answer. The three query parameters are what a PEP would ordinarily get
    // from its own context; here they are supplied so that one endpoint can
    // exercise a whole policy without a client having to be written.
    // -------------------------------------------------------------------------
    app.get('/xacml/protected', function (req, res) {
      log.debug('Entering GET /xacml/protected.');
      if (self.offCheck(res)) {
        log.debug('Leaving GET /xacml/protected. Off.');
        return;
      }
      // ---------------------------------------------------------------------
      // TWO GATES ON ONE ENDPOINT, AND THEY ARE ABOUT TWO DIFFERENT PEOPLE.
      //
      // This one asks whether the CALLER may drive the embedded PEP at all. The
      // enforcement below asks whether the SUBJECT NAMED IN `?subject=` may
      // reach the resource — which is the thing this endpoint exists to
      // demonstrate and is not an authentication of anybody.
      //
      // Keeping them apart is what stops the demonstration from being ruined by
      // the gate: an admitted caller can still ask about `?subject=nobody` and
      // watch the PEP refuse, because the answer is about the subject and the
      // admission was about the connection. Conflating them would turn this
      // into an endpoint that reports what the caller already knows.
      // ---------------------------------------------------------------------
      if (!self.xacmlAccess(req, res, accessGate.ACTION.READ,
                            'an embedded PEP enforcement').allowed) {
        log.debug('Leaving GET /xacml/protected. The access policy refused.');
        return;
      }
      const subject = String(req.query.subject || '');
      const resource = String(req.query.resource ||
                              baseUrlOf(req) + '/xacml/protected');
      const action = String(req.query.action || 'GET');
      const request = {
        returnPolicyIdList: true,
        combinedDecision: false,
        categories: [
          { category: model.CATEGORY.ACCESS_SUBJECT, id: null, content: null,
            attributes: subject ? [{ attributeId: model.ATTRIBUTE.SUBJECT_ID,
                                     issuer: null, includeInResult: true,
                                     values: [{ type: model.TYPE.STRING,
                                                lexical: subject }] }] : [] },
          { category: model.CATEGORY.RESOURCE, id: null, content: null,
            attributes: [{ attributeId: model.ATTRIBUTE.RESOURCE_ID,
                           issuer: null, includeInResult: true,
                           values: [{ type: model.TYPE.ANYURI,
                                      lexical: resource }] }] },
          { category: model.CATEGORY.ACTION, id: null, content: null,
            attributes: [{ attributeId: model.ATTRIBUTE.ACTION_ID,
                           issuer: null, includeInResult: true,
                           values: [{ type: model.TYPE.STRING,
                                      lexical: action }] }] },
          { category: model.CATEGORY.ENVIRONMENT, id: null, content: null,
            attributes: [] }
        ]
      };
      const answer = self.decide(request);
      const enforcement = self.enforce(answer);
      // ---------------------------------------------------------------------
      // COUNTED HERE AND DELIBERATELY NOT INSIDE `enforce()`.
      //
      // `enforce()` looks like the obvious funnel and is the wrong one:
      // `/admin/xacml/decide` calls it too, to show a reader what the embedded
      // PEP WOULD do with the decision they just asked about. That is a
      // what-if, not a request anybody guarded — counting it would put a
      // console page's own experiments into the figure an operator reads to
      // find out how much traffic authorization is actually seeing, and the
      // number would grow every time somebody looked at it.
      //
      // So the count is at the one place a real request was enforced.
      // ---------------------------------------------------------------------
      monitor.record('protected', { decision: answer.decision,
                                    allowed: enforcement.allowed,
                                    undischargeable:
                                      (enforcement.undischargeable ||
                                       []).length > 0 });
      audit.audit({
        action: 'xacml.enforcement',
        actor: subject,
        protocol: 'XACML',
        detail: 'The embedded PEP got ' + answer.decision + ' and ' +
                (enforcement.allowed ? 'allowed' : 'refused') + ' access to ' +
                resource + ' (' + enforcement.bias + ').'
      });
      const body: Record<string, unknown> = {
        decision: answer.decision,
        allowed: enforcement.allowed,
        bias: enforcement.bias,
        why: enforcement.why,
        status: answer.status,
        obligations: (answer.obligations || []).map(function (one) {
          return { id: one.id, discharged: enforcement.discharged
            .indexOf(one.id) >= 0 };
        }),
        advice: (answer.advice || []).map(function (one) {
          return one.id;
        }),
        request: { subject: subject || null, resource: resource,
                   action: action },
        applicablePolicies: answer.policyIdentifiers || []
      };
      if (answer.note) {
        body.note = answer.note;
      }
      if (!enforcement.allowed) {
        errorCodes.mark(res, (enforcement.undischargeable || []).length &&
                             answer.decision === model.DECISION.PERMIT
          ? 'STS-XACML-0015' : 'STS-XACML-0014');
      }
      // A fault behind the decision is the more specific condition, and the
      // last mark wins.
      if (errorCodes.codeOf(answer)) {
        errorCodes.mark(res, errorCodes.codeOf(answer));
      }
      res.status(enforcement.allowed ? 200 : 403)
         .type('application/json').set('Cache-Control', 'no-store')
         .send(JSON.stringify(body, null, 2));
      log.debug('Leaving GET /xacml/protected. ' +
                (enforcement.allowed ? 'Allowed.' : 'Refused.'));
    });

    // -------------------------------------------------------------------------
    // POST /xacml/pep/register
    // -------------------------------------------------------------------------
    app.post('/xacml/pep/register', function (req, res) {
      log.debug('Entering POST /xacml/pep/register.');
      if (self.remotePepOffCheck(res)) {
        log.debug('Leaving POST /xacml/pep/register. Off.');
        return;
      }
      // THE POLICY BEFORE THE CERTIFICATE REQUIREMENT, and the order is worth
      // stating: this asks whether the caller may be here at all, and the check
      // below asks whether this deployment accepts a PEP that proved nothing. A
      // caller refused by both should hear about the policy, because that is
      // the one an operator changes.
      const access = self.pepAccess(req, res, accessGate.ACTION.WRITE,
                                    'a remote PEP registration');
      if (!access.allowed) {
        log.debug('Leaving POST /xacml/pep/register. The access policy ' +
                  'refused.');
        return;
      }
      const body = parseBody(req);
      const identity = access.identity;
      const required = config.value('xacml.pepRequireCertificate') !== false;
      if (required && !identity.authenticated) {
        // THE REFUSAL NAMES THE CAUSE AND THE WAY OUT, and it distinguishes the
        // two ways to arrive here — because they need opposite fixes and a
        // single sentence covering both would send half the readers the wrong
        // way. A plain-HTTP listener cannot carry a certificate at all, however
        // good the client's; an https one can, and a client that sent none
        // simply did not.
        const plain = !(req.socket &&
                        typeof req.socket.getPeerCertificate === 'function');
        log.debug('Leaving POST /xacml/pep/register. No client certificate.');
        errorCodes.mark(res, plain ? 'STS-XACML-0017' : 'STS-XACML-0018');
        self.fail(res, 401, 'invalid_client', plain
          ? 'This registration arrived on a PLAIN HTTP connection, which ' +
            'cannot carry a client certificate at all — so there is nothing ' +
            'a better client could have sent. Either turn on global.https ' +
            '(STS_HTTPS) so the main listener asks for one, or turn off ' +
            'xacml.pepRequireCertificate, in which case the registration is ' +
            'accepted and marked UNAUTHENTICATED on its own row rather than ' +
            'being quietly indistinguishable from one that proved something. ' +
            'Note that registering is not what lets a PEP ENFORCE — an ' +
            'unregistered PEP that can pull still decides — but the PULL ' +
            'itself needs a verified certificate holding REMOTE_PEPS, so a ' +
            'plain-HTTP deployment needs xacml.enforceAccess off as well.'
          : 'A remote Policy Enforcement Point registers over mutual TLS and ' +
            'this connection carried no client certificate ' +
            '(xacml.pepRequireCertificate). The certificate does not have to ' +
            'chain to anything — what is proved is that the same key ' +
            'completed the handshake, which is RFC 8705 section 3\'s ' +
            'argument and it holds ' +
            // THIS CLAUSE CONTRADICTED ITSELF UNTIL IT WAS FIXED, and it is
            // worth knowing why rather than just that. It said "GET
            // /xacml/pep/policies requires no credential" and then, eleven
            // words later, "GET /xacml/pep/policies requires REMOTE_PEPS" — the
            // first half left over from before 2026-09-06 and the second added
            // on the day that stopped being true. A refusal is the one message
            // that has to be right, and this one is quoted VERBATIM into the
            // PEP container's own `registration.why`, so both halves were read
            // together by exactly the person trying to work out what to fix.
            'here unchanged. Note that registering is not what lets a PEP ' +
            'enforce: what a registration buys is a row on /admin/xacml/peps ' +
            'and an address for the change nudge. You will need a ' +
            'certificate for the PULL regardless, since GET ' +
            '/xacml/pep/policies requires the REMOTE_PEPS role.');
        return;
      }
      // THE NAME COMES FROM THE CERTIFICATE WHEN THERE IS ONE, and from the
      // body only when there is not. A PEP that could name itself while holding
      // a certificate could register as somebody else's PEP and take over their
      // row — which is the one thing in this whole family that would be a
      // security bug rather than a fidelity one.
      const name = identity.authenticated
        ? (identity.commonName || identity.dn)
        : String(body.name || '');
      const result = peps.register({
        name: name,
        identity: identity.dn,
        certificateSubject: identity.subject,
        thumbprint: identity.thumbprint,
        authenticated: identity.authenticated,
        notifyUrl: String(body.notifyUrl || body.notify_url || ''),
        bias: String(body.bias || ''),
        resource: String(body.resource || ''),
        version: String(body.version || ''),
        description: String(body.description || '')
      });
      if (!result.ok) {
        log.debug('Leaving POST /xacml/pep/register. Refused.');
        errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-XACML-0019');
        self.fail(res, 400, 'invalid_request', result.why);
        return;
      }
      audit.audit({
        action: 'xacml.pep.register',
        actor: identity.dn || result.name,
        protocol: 'XACML',
        detail: 'Remote PEP "' + result.name + '" ' +
                (result.created ? 'registered' : 're-registered') +
                (identity.authenticated ? ' over mutual TLS.'
                                        : ' with no client certificate.')
      });
      const notifyProblem = pepHttp.urlProblem(String(body.notifyUrl ||
                                                      body.notify_url || ''));
      res.status(result.created ? 201 : 200).type('application/json')
         .set('Cache-Control', 'no-store')
         .send(JSON.stringify({
           registered: true,
           name: result.name,
           created: result.created,
           authenticated: identity.authenticated,
           // PRESENTED AND VERIFIED, ANSWERED SEPARATELY (2026-09-06). A PEP
           // that reads only `authenticated` learns that its certificate
           // arrived; this is the one that says the chain built to an anchor
           // this service holds, which is what everything downstream of the DN
           // rests on. Said back in the reply rather than left to be
           // discovered, for the same reason the notify verdict is: a PEP whose
           // certificate this service will never recognise should find out
           // while somebody is still looking at the deployment.
           verified: identity.verified,
           verifiedWhy: identity.why,
           identity: identity.dn,
           syncToken: peps.syncToken(),
           policiesUrl: baseUrlOf(req) + '/xacml/pep/policies',
           heartbeatUrl: baseUrlOf(req) + '/xacml/pep/heartbeat',
           // SAID BACK IMMEDIATELY, rather than being discovered the first time
           // a nudge is not delivered. A PEP whose notify URL this service will
           // never dial should find that out while somebody is still looking at
           // the deployment, and it costs nothing to answer because the check
           // is a string test rather than a request.
           notify: { url: String(body.notifyUrl || body.notify_url || '') ||
                          null,
                     usable: !notifyProblem,
                     why: notifyProblem || 'This URL will be nudged when the ' +
                                           'repository changes.' },
           note: 'THE PULL IS THE CONTRACT. Poll ' + baseUrlOf(req) +
                 '/xacml/pep/policies on your own interval and pass the ' +
                 'syncToken you hold as ?since= — an unchanged repository ' +
                 'answers 304. The nudge is an optimisation over that ' +
                 'interval and never a replacement for it, so a PEP that is ' +
                 'never nudged still converges.'
         }, null, 2));
      log.debug('Leaving POST /xacml/pep/register. ' + result.name);
    });

    // -------------------------------------------------------------------------
    // GET /xacml/pep/policies — WHAT A REMOTE PEP LOADS.
    //
    // The ENABLED policies and which one is the root, plus the sync token over
    // exactly those bytes. Three differences from `GET /xacml/policies`, and
    // each is because this answer is for a MACHINE that is about to evaluate it
    // rather than for a person reading:
    //
    //   * DISABLED POLICIES ARE NOT HERE. That page shows them because somebody
    //     wants to see what is in the repository; a PEP that loaded one would
    //     enforce a policy this service does not.
    //   * THE STATIC PROBLEMS ARE NOT HERE either — a document that does not
    //     typecheck cannot be written through the store in the first place, and
    //     a PEP has its own validator and will refuse it again.
    //   * IT CARRIES A SYNC TOKEN AND HONOURS `?since=`, which is what makes
    //     polling cheap enough to be the contract.
    //
    // **IT REQUIRES `REMOTE_PEPS`**, and the comment inside the handler carries
    // the argument: this header said "no credential is required" for one day
    // after that stopped being true, which is exactly the drift the endpoint
    // list on `GET /xacml` now makes machine-readable.
    // -------------------------------------------------------------------------
    app.get('/xacml/pep/policies', function (req, res) {
      log.debug('Entering GET /xacml/pep/policies.');
      if (self.remotePepOffCheck(res)) {
        log.debug('Leaving GET /xacml/pep/policies. Off.');
        return;
      }
      // **THIS ENDPOINT USED TO NEED NO CREDENTIAL AT ALL AND THE OLD ARGUMENT
      // FOR THAT IS STILL SOUND** — a policy is a rule, and a rule nobody can
      // read is a rule nobody can check. What changed is not the value of
      // publishing policy; it is that these documents are now the ones this
      // service ENFORCES ITS OWN ACCESS WITH, and handing an unauthenticated
      // caller the exact conditions under which it lets people in is a
      // different act from publishing a demonstration policy. The repository is
      // still readable at `GET /xacml/policies` (behind `XACML_USER`, since the
      // same day), which is where a person reads it; this endpoint is for a
      // machine that is about to enforce it.
      const access = self.pepAccess(req, res, accessGate.ACTION.READ,
                                    'a remote PEP policy pull');
      if (!access.allowed) {
        log.debug('Leaving GET /xacml/pep/policies. The access policy ' +
                  'refused.');
        return;
      }
      const token = peps.syncToken();
      const since = String(req.query.since || '');
      // A PEP that reports the name it registered under gets its `lastSeen`
      // moved by a PULL as well as by a heartbeat, because a PEP that is
      // polling is plainly alive and a register that called it stale would be
      // reporting on its own heartbeat interval rather than on the PEP.
      const asName = peps.nameFrom(String(req.query.pep || ''));
      if (asName && peps.read(asName)) {
        peps.heartbeat(asName, {});
      }
      if (since && since === token) {
        // 304 AND NOT 200 WITH A FLAG, because a PEP polling every few seconds
        // is the ordinary case and this is the answer it gets almost every
        // time. The token goes in an ETag as well so that an ordinary HTTP
        // cache — or a client library that already speaks conditional requests
        // — behaves correctly without knowing anything about XACML.
        res.status(304)
           .set('Cache-Control', 'no-store')
           .set('ETag', '"' + token + '"')
           .end();
        log.debug('Leaving GET /xacml/pep/policies. Unchanged.');
        return;
      }
      const root = store.root();
      // =======================================================================
      // THIS SERVICE'S OWN POLICIES ARE NOT PUSHED (2026-09-06), AND THEY ARE
      // THE ONLY THINGS EVER WITHHELD FROM A PEP.
      //
      // Two documents in this repository are not about somebody else's boundary
      // at all — they are how THIS SERVICE decides its own questions:
      //
      //   * `xacml.accessPolicy` (`access-control`) decides who reaches the
      //     admin console, the management API, the User Portal, SCIM, the SPIRE
      //     Server API, the embedded debugger and the rest of `/xacml` — and,
      //     since 2026-09-06, these very endpoints;
      //   * `xacml.issuancePolicy` (`role-issuance`) decides whether this
      //     service issues a token, an assertion or a ticket at its nine
      //     issuance sites.
      //
      // **A REMOTE PEP MUST NOT ENFORCE EITHER, AND THE REASON IS NOT
      // SECRECY.** A PEP evaluates what it pulls against ITS OWN requests, and
      // those two documents are written against attributes only this process
      // can supply — `urn:sts:xacml:attribute:required-role` off an application
      // entry, the resource owner off a portal session. Enforced out there they
      // would answer NotApplicable to everything a remote PEP ever asks, and a
      // deny-biased PEP turns NotApplicable into a refusal: shipping them would
      // silently make every remote decision a Deny, which is the exact shape of
      // the defect `xacml-pep/CLAUDE.md` records having cost a run already.
      //
      // The second reason is the ordinary one and it is worth saying too: these
      // documents state the conditions under which this service lets people in,
      // and handing them to every registered enforcement point publishes that.
      // They remain readable at `GET /xacml/policies`, which is where a PERSON
      // reads the repository and where "a rule nobody can check is a rule
      // nobody can trust" still applies.
      //
      // FILTERED BY NAME AND NOT BY A FLAG ON THE ENTRY, because the two names
      // are SETTINGS: an operator who points `xacml.accessPolicy` at a document
      // of their own has made THAT one internal, and a stored flag would still
      // be on the old one. Reading the settings is reading the same answer
      // `xacml_access_pep.ts` and `xacml_role_pep.ts` read.
      // =======================================================================
      const internal = [config.value('xacml.accessPolicy') || 'access-control',
                        config.value('xacml.issuancePolicy') || 'role-issuance']
        .map(function (one) { return String(one).toLowerCase(); });
      const withheld = [];
      const rows = store.all().filter(function (row) {
        if (internal.indexOf(String(row.name).toLowerCase()) >= 0) {
          withheld.push(row.name);
          return false;
        }
        return row.enabled;
      }).map(function (row) {
        return { name: row.name, policyId: row.id, kind: row.kind,
                 version: row.version, combiningAlgId: row.combiningAlgId,
                 isRoot: !!(root && root.name === row.name),
                 description: row.description, document: row.document };
      });
      res.status(200).type('application/json').set('Cache-Control', 'no-store')
         .set('ETag', '"' + token + '"')
         .send(JSON.stringify({
           syncToken: token,
           root: root ? root.name : null,
           rootNote: root ? undefined
             : 'No policy is marked as the root, so a PEP loading this ' +
               'decides NotApplicable to everything — which its bias then ' +
               'turns into a refusal or an allowance. That is a real state ' +
               'and not an error, and it is reported rather than hidden.',
           policies: rows,
           // NAMED RATHER THAN SILENTLY ABSENT. A PEP whose policy count
           // disagrees with the console's is exactly what that column exists to
           // show, and a reader comparing the two needs to know the difference
           // is deliberate. The names are all that is published — never the
           // documents.
           withheld: withheld,
           note: 'Every ENABLED policy EXCEPT this service\'s own. A ' +
                 'disabled policy is left out rather than sent with a flag, ' +
                 'because a PEP that loaded one would enforce a policy this ' +
                 'service does not — and the access-control and ' +
                 'role-issuance documents are left out because they decide ' +
                 'THIS service\'s questions against attributes only this ' +
                 'process can supply. Enforced elsewhere they would answer ' +
                 'NotApplicable to everything, which a deny-biased PEP turns ' +
                 'into a refusal of everything. They are readable at GET ' +
                 '/xacml/policies.' +
                 (withheld.length
                   ? ' Withheld here: ' + withheld.join(', ') + '.'
                   : '')
         }, null, 2));
      log.debug('Leaving GET /xacml/pep/policies. ' + rows.length +
                ' policy(ies).');
    });

    // -------------------------------------------------------------------------
    // POST /xacml/pep/heartbeat — WHAT A REMOTE PEP REPORTS.
    //
    // Its counters, and the sync token it is holding. The second is what makes
    // "current" a comparison this service can perform rather than a claim the
    // PEP makes about itself, and the first is the only way the enforcement a
    // remote PEP does is visible here at all — those decisions happened in
    // another process and this service did not see one of them, which is the
    // entire point of a remote PEP.
    //
    // IT DOES NOT CREATE A ROW. A heartbeat from something that never
    // registered is refused naming the registration endpoint, because a row
    // created here would carry no certificate, no notify URL and no
    // registration date.
    // -------------------------------------------------------------------------
    app.post('/xacml/pep/heartbeat', function (req, res) {
      log.debug('Entering POST /xacml/pep/heartbeat.');
      if (self.remotePepOffCheck(res)) {
        log.debug('Leaving POST /xacml/pep/heartbeat. Off.');
        return;
      }
      const access = self.pepAccess(req, res, accessGate.ACTION.WRITE,
                                    'a remote PEP heartbeat');
      if (!access.allowed) {
        log.debug('Leaving POST /xacml/pep/heartbeat. The access policy ' +
                  'refused.');
        return;
      }
      const body = parseBody(req);
      const identity = access.identity;
      // A CERTIFICATE, WHERE THERE IS ONE, OVERRIDES THE NAME IN THE BODY —
      // the same rule the registration follows and for the same reason: a PEP
      // holding a certificate must not be able to file its counters against
      // somebody else's row.
      const name = peps.nameFrom(identity.authenticated
        ? (identity.commonName || identity.dn)
        : String(body.name || ''));
      if (!name) {
        log.debug('Leaving POST /xacml/pep/heartbeat. Nameless.');
        errorCodes.mark(res, 'STS-XACML-0020');
        self.fail(res, 400, 'invalid_request',
                  'A heartbeat says which PEP it is from — by the client ' +
                  'certificate it arrives with, or by `name` when it carries ' +
                  'none.');
        return;
      }
      const result = peps.heartbeat(name, {
        syncToken: body.syncToken === undefined ? undefined : body.syncToken,
        policyCount: body.policyCount,
        decisions: body.decisions,
        allowed: body.allowed,
        refused: body.refused,
        undischargeable: body.undischargeable,
        bias: body.bias,
        resource: body.resource,
        version: body.version,
        notifyUrl: body.notifyUrl === undefined ? body.notify_url
                                                : body.notifyUrl
      });
      if (!result.ok) {
        log.debug('Leaving POST /xacml/pep/heartbeat. Refused.');
        errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-XACML-0021');
        self.fail(res, 404, 'invalid_request', result.why);
        return;
      }
      const row = peps.read(name);
      res.status(200).type('application/json').set('Cache-Control', 'no-store')
         .send(JSON.stringify({
           acknowledged: true,
           name: name,
           syncToken: result.current,
           // TOLD RATHER THAN LEFT TO BE COMPARED. A PEP that has to diff two
           // strings to find out it is behind is a PEP that will get it wrong
           // once; this service has both values in front of it here.
           current: !!row && row.current,
           action: row && row.current ? 'nothing — your copy is the current one'
             : 'pull GET /xacml/pep/policies; your copy is not the current one'
         }, null, 2));
      log.debug('Leaving POST /xacml/pep/heartbeat. ' + name);
    });

    // ASYNCHRONOUS SINCE 2026-09-14 (#46): the rate limit below counts in the
    // cluster's shared window, which is a round trip. Everything else is as it
    // was.
    app.post('/xacml/pip', async function (req, res) {
      log.debug('Entering POST /xacml/pip.');
      // ---------------------------------------------------------------------
      // `remotePepOffCheck()` AND NOT `offCheck()`, WHICH IS A DECISION AND WAS
      // MADE THE OTHER WAY FIRST.
      //
      // This endpoint is NAMED for the component it is — the PIP, the way
      // `/xacml/pdp` is named for the PDP — and the first draft therefore put
      // it behind `xacml.enabled` alone, on the reasoning that a PIP is not
      // part of the registration feature.
      //
      // **THE OFF-SWITCH FOLLOWS THE CALLER RATHER THAN THE NAME.** An operator
      // who sets `xacml.remotePeps` false has said they want no enforcement
      // point outside this process; leaving an endpoint that hands a named
      // person's directory attributes to anything holding `REMOTE_PEPS` still
      // answering would be that switch not doing what its own description says.
      // The only caller this exists for is a remote PEP, and a remote PEP with
      // no way to pull policy has nothing to resolve designators FOR.
      //
      // So the role does not follow the path here and neither does the switch,
      // and both point the same way — which is why this is one decision rather
      // than two exceptions.
      // ---------------------------------------------------------------------
      if (self.remotePepOffCheck(res)) {
        log.debug('Leaving POST /xacml/pip. Off.');
        return;
      }
      // ---------------------------------------------------------------------
      // THE IDENTITY IS READ ONCE, HERE, BEFORE ANYTHING ELSE.
      //
      // The rate limiter below needs to know WHO is asking and the access check
      // needs to know whether they may — two questions about one certificate,
      // and reading it twice would be two places that could come to disagree
      // about the answer. `pepAccess()` takes it as an argument for exactly
      // this door.
      // ---------------------------------------------------------------------
      const identity = self.callerIdentity(req);

      // ---------------------------------------------------------------------
      // THE RATE LIMIT, AND IT IS BEFORE THE ACCESS CHECK ON PURPOSE.
      //
      // Put after it, an unadmitted caller could ask this service to build a
      // certificate chain, resolve a DN and evaluate an access policy as fast
      // as it could send — refused every time and never counted. Put here, the
      // ADDRESS bucket bounds that, and the IDENTITY bucket bounds the case
      // that actually costs something: a caller this service ADMITTED reading
      // directory attributes in a loop.
      //
      // **IT NAMES ITS OWN CEILING AND THAT IS THE WHOLE POINT.**
      // `security.rateLimitPerIdentity` is FIVE, because it guards a sign-in. A
      // PIP query is one per access decision, so a busy enforcement point makes
      // several a second and every one is legitimate — sharing the sign-in
      // number would have switched this endpoint off for its only caller, and
      // it would have done it SILENTLY, because `xacml-pep/pip.js` treats a
      // refused query as an empty bag and goes on deciding.
      // `xacml.pipMaxPerWindow` is that number and `websecurity.js` argues the
      // argument that carries it.
      //
      // The identity is the VERIFIED DN or nothing, for `pepAccess()`'s reason:
      // an unverified certificate's DN is a name the caller chose for itself,
      // and a limiter keyed on one would let an attacker mint a fresh bucket
      // per request by changing a string.
      // ---------------------------------------------------------------------
      const within = await websecurity.attemptShared('xacml-pip', req,
        identity.verified ? identity.dn : '',
        config.value('xacml.pipMaxPerWindow'));
      if (!within.ok) {
        log.debug('Leaving POST /xacml/pip. Rate limited.');
        res.set('Retry-After', String(within.retryAfterS));
        errorCodes.mark(res, 'STS-XACML-0022');
        self.pipFail(res, 429, 'too_many_requests',
          'Too many PIP queries. ' + within.detail + ' The limit is ' +
          within.limit + ' per ' + config.value('security.rateLimitWindowS') +
          's on the ' + within.kind + ' bucket (xacml.pipMaxPerWindow, over ' +
          'security.rateLimitWindowS). A remote PEP that meets this is ' +
          'querying per decision with no caching — and note that it treats a ' +
          'refusal as an empty bag and goes on deciding on less information, ' +
          'so raising the limit is a real change rather than a cosmetic one.');
        return;
      }

      // READ AND NOT WRITE: nothing changes here, and it is the one endpoint in
      // this family whose whole answer is somebody else's stored data.
      const access = self.pepAccess(req, res, accessGate.ACTION.READ,
                                    'a PIP attribute query', identity);
      if (!access.allowed) {
        log.debug('Leaving POST /xacml/pip. The access policy refused.');
        return;
      }
      // `app.js` parses every body as TEXT, which is exactly what an XML
      // endpoint wants — the same reason `/xacml/pdp` reads the raw source.
      const raw = typeof req.body === 'string' ? req.body
        : (Buffer.isBuffer(req.body) ? req.body.toString('utf8') : '');
      let request;
      let designators;
      try {
        // ---------------------------------------------------------------------
        // `validation.parseXml()` AND NOT `xml.parseDocument()`, WHICH IS WHAT
        // THIS REACHED FOR FIRST.
        //
        // The engine's own parser is right for a POLICY — it is the one held to
        // the conformance suite — and it is the wrong one for a body a stranger
        // POSTs, for two reasons that are both about the door rather than about
        // XML. It has NO SIZE CEILING, so a caller chooses how much of this
        // process's memory one request costs; and it THROWS, which is fine
        // inside a policy load and is one more thing to catch on a request
        // path. `validation.js`'s wrapper caps at `CAP.LARGE` and answers a
        // refusal, and it is the same function every other XML door in this
        // service reads a body with — so the ceiling is one number in one
        // place.
        //
        // **ENTITY EXPANSION IS NOT A HAZARD HERE AND THAT IS MEASURED RATHER
        // THAN ASSUMED.** `@xmldom/xmldom` resolves no entity declared in a
        // DTD, internal or external: a billion-laughs document and an `<!ENTITY
        // xxe SYSTEM "file:///etc/passwd">` both come back as *entity not
        // found*, refused as not well-formed. So there is no expansion limit to
        // set and no external resolver to disable — and this paragraph is here
        // so the next person to look does not have to run the probe again.
        // ---------------------------------------------------------------------
        const parsed = validation.parseXml(raw, 'PIP query',
                                           { max: validation.CAP.LARGE });
        if (!parsed.ok) {
          throw model.syntaxError(parsed.detail);
        }
        const root = parsed.value.documentElement;
        if (xml.localName(root) !== 'PIPRequest') {
          throw model.syntaxError(
            'A PIP query\'s root element must be <PIPRequest> in the ' +
            'namespace ' + PIP_NS + '; this one is <' +
            xml.localName(root) + '>. It carries ' +
            'the XACML <Request> you are deciding — which is what names the ' +
            'subject — and one <AttributeDesignator> per attribute wanted.');
        }
        const requestNode = xml.firstNamed(root, 'Request');
        if (!requestNode) {
          throw model.syntaxError(
            'A PIP query must carry the XACML <Request> being decided. The ' +
            'subject is read out of it exactly as the embedded PDP reads it, ' +
            'which is what makes this endpoint answer what the embedded PIP ' +
            'would have answered.');
        }
        request = xml.readRequest(requestNode);
        const nodes = xml.childrenNamed(root, 'AttributeDesignator');
        if (!nodes.length) {
          throw model.syntaxError(
            'A PIP query must carry at least one <AttributeDesignator>. This ' +
            'endpoint resolves the designators you name and never dumps an ' +
            'entry — a PIP resolves designators, and a directory dump is a ' +
            'different and much larger thing.');
        }
        const most = self.pipMaxDesignators();
        if (nodes.length > most) {
          errorCodes.mark(res, 'STS-XACML-0024');
          throw model.syntaxError('A PIP query may name at most ' +
            most + ' designators (xacml.pipMaxDesignators); this one named ' +
            nodes.length + '.');
        }
        // `readExpression()` AND NOT A READER WRITTEN HERE. It is the function
        // that reads an <AttributeDesignator> out of a POLICY, so a designator
        // means the same thing on this wire as it does in the document the PEP
        // is evaluating — including the reading of MustBePresent, where absent
        // and false are recorded as different things.
        designators = nodes.map(function (node) {
          const read = xml.readExpression(node);
          if (read.kind !== 'designator') {
            throw model.syntaxError('Expected an <AttributeDesignator>.');
          }
          // ---------------------------------------------------------------
          // AND THE SCALARS ARE BOUNDED, WHICH THAT READER DOES NOT DO.
          //
          // `readExpression()` is held to 454 of 455 OASIS conformance cases,
          // so what a designator IS is not this file's to re-check — a schema
          // over it would be a second, worse reading of a specification this
          // directory implements. What a conformance suite has no opinion about
          // is an AttributeId a megabyte long.
          //
          // **THESE THREE COME BACK OUT AGAIN**, which is what makes the bound
          // matter rather than being tidiness: an unresolved designator is
          // echoed into `<Unresolved>`, every one of them is named in the
          // `xacml.pip.query` audit row, and both are places a caller does not
          // get to choose the size of.
          // ---------------------------------------------------------------
          ['category', 'attributeId', 'dataType'].forEach(function (field) {
            const problem = self.pipScalarProblem(field, read[field],
                                                  validation.CAP.IDENTIFIER);
            if (problem) {
              errorCodes.mark(res, 'STS-XACML-0025');
              throw model.syntaxError(problem);
            }
          });
          return read;
        });
      } catch (error) {
        log.debug("Caught in POST /xacml/pip: " +
                  ((error && error.message) || error));
        // A MALFORMED QUERY IS A 400 AND NEVER AN EMPTY ANSWER, which is this
        // endpoint's version of `/xacml/pdp`'s 400-not-Indeterminate rule and
        // matters more here: an unresolved designator is a legitimate ANSWER,
        // so a reader that answered one for a typo would be indistinguishable
        // from the attribute being absent, and the caller's PDP would go on to
        // decide on it.
        log.debug('Leaving POST /xacml/pip. The query would not parse.');
        // The two bounds above marked their own condition before throwing; any
        // other throw here is a query that is not a well-formed <PIPRequest>.
        errorCodes.mark(res, errorCodes.codeOf(res) || 'STS-XACML-0023');
        self.pipFail(res, 400, 'invalid_request', error.message);
        return;
      }
      // THE SUBJECT IS BOUNDED TOO, and it is the one scalar that goes
      // somewhere other than a log: `locateSubject()` hands it to the
      // directory's `locateEntry()`, which walks the tree comparing it against
      // every DN, every uid and every certificate subject. It is a NAME by this
      // service's own reckoning — the same cap `userFor()` puts on one — and
      // refusing a longer one here is refusing it at the only door that takes
      // it from a stranger.
      const subjectProblem = self.pipScalarProblem('subject-id',
                                                   pip.subjectOf(request) || '',
                                                   validation.CAP.NAME);
      if (subjectProblem) {
        log.debug('Leaving POST /xacml/pip. The subject is not a name.');
        errorCodes.mark(res, 'STS-XACML-0025');
        self.pipFail(res, 400, 'invalid_request', subjectProblem);
        return;
      }
      const resolve = pip.resolverFor(request);
      const subject = pip.subjectOf(request) || '';
      // RESOLVED ONCE, HERE, for the reason `resolverFor()` resolves its own
      // copy once per decision rather than once per designator: a caller asking
      // about six attributes of one person must not be able to see six
      // different people because somebody wrote to the directory in between.
      // This is the same lookup through the same function, and it exists only
      // so `<Unresolved>` can say which of the five reasons applied.
      const stored = subject ? pip.locateSubject(subject) : null;
      const answers = [];
      const unresolved = [];
      designators.forEach(function (designator) {
        const values = resolve(designator);
        if (values.length) {
          answers.push({
            category: designator.category,
            attributeId: designator.attributeId,
            dataType: designator.dataType,
            // THE LEXICAL FORM. `writeValue()` is `parseValue()`'s exact
            // inverse and is the one function that knows how each datatype is
            // written; anything else here would be a second, worse spelling of
            // a dateTime.
            values: values.map(function (one) {
              return datatypes.writeValue(designator.dataType, one);
            })
          });
          return;
        }
        const mapped = designator.category === model.CATEGORY.ACCESS_SUBJECT
          ? pip.directoryAttributeFor(designator.attributeId) : null;
        unresolved.push({
          category: designator.category,
          attributeId: designator.attributeId,
          dataType: designator.dataType,
          mustBePresent: designator.mustBePresent,
          why: self.pipWhy(designator, subject, stored, mapped)
        });
      });
      audit.audit({
        action: 'xacml.pip.query',
        // THE PEP THAT ASKED, not the subject it asked about. Two identities
        // are in this request and the audit row is about who reached the
        // endpoint — the subject is in the detail, which is where a reader
        // looking for "who has been asking about alice" will search.
        actor: access.identity.dn || '',
        protocol: 'XACML',
        detail: 'A remote PEP resolved ' + designators.length +
                ' designator(s) about "' + (subject || '(no subject named)') +
                '"; ' + answers.length + ' answered with values. Attributes: ' +
                designators.map(function (one) {
                  return one.attributeId;
                }).join(', ') + '.'
      });
      res.status(200).type('application/xml').set('Cache-Control', 'no-store')
         .send(self.writePipResponse(answers, unresolved));
      log.debug('Leaving POST /xacml/pip. ' + answers.length + ' resolved, ' +
                unresolved.length + ' not.');
    });

    self.installChangeObserver();

    app.get('/xacml', function (req, res) {
      log.debug('Entering GET /xacml.');
      // BEFORE THE QUERY IS EVEN LOOKED AT, deliberately. A caller this policy
      // will not admit must not be able to tell a well-formed `?format=` from a
      // malformed one on this surface — and more simply, the answer to "may you
      // read this page" does not depend on how they asked for it.
      if (!self.xacmlAccess(req, res, accessGate.ACTION.READ,
                            'the XACML surface description').allowed) {
        log.debug('Leaving GET /xacml. The access policy refused.');
        return;
      }
      const info = self.description(req);
      const askedFormat = validation.check(req, 'query', XACML_QUERY);
      if (!askedFormat.ok) {
        log.debug('Leaving the XACML page. ' + askedFormat.detail);
        errorCodes.mark(res, 'STS-XACML-0016');
        return res.status(400).type('text/plain')
                  .send(askedFormat.detail + '\n');
      }
      if (String(req.query.format || '').toLowerCase() === 'json') {
        res.status(200).set('Cache-Control', 'no-store').json(info);
        log.debug('Leaving GET /xacml. JSON.');
        return;
      }
      const rows = info.endpoints.map(function (row) {
        return '<tr><td><code>' + xmlEscape(row.method) +
          '</code></td><td><code>' +
          xmlEscape(row.path) + '</code></td><td>' + xmlEscape(row.what) +
          '</td><td><code>' + xmlEscape(row.requires) + '</code></td></tr>';
      }).join('');
      const later = info.notYetHere.map(function (one) {
        return '<li>' + xmlEscape(one) + '</li>';
      }).join('');
      res.status(200).type('text/html').set('Cache-Control', 'no-store').send(
        '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">' +
        '<title>XACML 3.0</title><style>' +
        'body{font-family:system-ui,sans-serif;' +
        'margin:2rem;max-width:52rem;line-height:1.5}table{border-collapse:' +
        'collapse;margin:1rem 0}td,th{border:1px solid #ccc;' +
        'padding:.35rem .6rem;' +
        'text-align:left}code{font-size:.9em}</style></head><body>' +
        '<h1>XACML 3.0</h1>' +
        '<p>This service is a Policy Decision Point. Policies live in ' +
        '<code>ou=policies</code> in the embedded directory — that ' +
        'container <strong>is</strong> the repository rather than a copy of ' +
        'one — and the Policy Information Point reads attributes off the ' +
        'subject&rsquo;s own directory entry.</p>' +
        '<p>' + (info.enabled ? 'XACML is <strong>on</strong>.'
                              : 'XACML is <strong>off</strong> ' +
                                '(<code>xacml.enabled</code>); these ' +
                                'endpoints answer 501.') + '</p>' +
        '<p>The repository holds ' + info.repository.policies +
        ' policy(ies), ' +
        info.repository.enabledPolicies + ' enabled, and the root is ' +
        (info.repository.root
          ? '<code>' + xmlEscape(info.repository.root) + '</code>.'
          : '<strong>not set</strong>, so every decision is NotApplicable.') +
        '</p>' +
        '<table><tr><th>Method</th><th>Path</th><th>What</th><th>Requires' +
        '</th></tr>' + rows + '</table>' +
        '<h2>Getting in</h2>' +
        '<p>' + (info.access.enforced
          ? 'Every endpoint above requires a <strong>client ' +
            'certificate</strong> this service verifies against an anchor ' +
            'in its own truststore (<code>POST /tls/trust</code>). The ' +
            'subject DN is resolved to a directory entry, and that ' +
            'entry&rsquo;s group membership is what grants the role in the ' +
            'last column: <code>' +
            xmlEscape(info.access.xacmlUserGroup ||
                      '(none — nobody holds it)') +
            '</code> grants <code>XACML_USER</code> and <code>' +
            xmlEscape(info.access.remotePepGroup ||
                      '(none — nobody holds it)') +
            '</code> grants <code>REMOTE_PEPS</code>. <strong>The ' +
            'certificate says who and the group says whether</strong> ' +
            '&mdash; a perfectly valid certificate for a common name in ' +
            'neither group is fully authenticated and still refused.'
          : 'Access enforcement is <strong>off</strong> ' +
            '(<code>xacml.enforceAccess</code>), so every endpoint above ' +
            'answers without a credential. The roles in the last column ' +
            'are what would be required with it on.') + '</p>' +
        '<h2>The embedded PEP</h2>' +
        '<p><code>GET /xacml/protected?subject=&hellip;&amp;resource=&hellip;' +
        '&amp;action=&hellip;</code> asks this PDP and then ' +
        '<em>enforces</em> the answer. It is <code>' +
        xmlEscape(info.pep.bias) + '</code>: the ' +
        'two biases agree on every Permit and every Deny and differ on ' +
        'Indeterminate and NotApplicable, which is the case worth looking ' +
        'at. An obligation it cannot discharge turns a Permit into a ' +
        'refusal, which is section 7.2 and is the part implementations ' +
        'skip.</p>' +
        '<h2>Remote enforcement points</h2>' +
        '<p>' + (info.remotePeps.enabled
          ? 'A Policy Enforcement Point in another process registers at ' +
            '<code>/xacml/pep/register</code>, <strong>pulls</strong> the ' +
            'enabled policies from <code>/xacml/pep/policies</code> and ' +
            'evaluates them itself with its own copy of this engine. ' +
            info.remotePeps.registered +
            ' registered. The repository&rsquo;s ' +
            'sync token is <code>' + xmlEscape(info.remotePeps.syncToken) +
            '</code>; pass it as <code>?since=</code> and an unchanged ' +
            'repository answers 304.'
          : 'Remote Policy Enforcement Points are <strong>off</strong> ' +
            '(<code>xacml.remotePeps</code>); those three endpoints ' +
            'answer 501.') +
        '</p><h2>The Policy Information Point, over HTTP</h2><p>A remote ' +
        'PEP holds the engine but <strong>not the directory</strong>, so a ' +
        'designator the request did not carry resolves to an empty bag out ' +
        'there and to a real value here &mdash; the same policy deciding ' +
        'two ways in two enforcement points. <code>POST /xacml/pip</code> ' +
        'closes that.</p><p>XACML defines no PIP protocol, so this invents ' +
        'as little as possible: both directions are <strong>XACML&rsquo;s ' +
        'own XML</strong>. ' +
        'Send a <code>&lt;PIPRequest&gt;</code> carrying the ' +
        '<code>&lt;Request&gt;</code> you are deciding &mdash; which is what ' +
        'names the subject &mdash; and one ' +
        '<code>&lt;AttributeDesignator&gt;</code> per attribute wanted. What ' +
        'comes back is <code>&lt;Attributes&gt;</code> <em>in the shape a ' +
        '<code>&lt;Request&gt;</code> carries them</em>, so a PEP splices it ' +
        'into its own request and evaluates &mdash; after which its engine ' +
        'finds the values where a designator looks for them, which is ' +
        'exactly what happens in this process when the embedded PDP asks ' +
        'the embedded PIP.</p><p>An unresolved designator comes back as an ' +
        '<strong>absent</strong> <code>&lt;Attribute&gt;</code> rather than ' +
        'an empty one: that is what a request that never carried it looks ' +
        'like, so a PEP needs no branch for it. <code>MustBePresent</code> ' +
        'is read and deliberately <em>not</em> applied &mdash; what an ' +
        'empty bag means is settled by the designator and the function it ' +
        'is handed to, both in your engine. The five reasons a bag can be ' +
        'empty come back in <code>&lt;Unresolved&gt;</code>, in this ' +
        'service&rsquo;s own namespace so that a PEP reading only the XACML ' +
        'core namespace never sees it.</p><p>The pull <em>is</em> the ' +
        'contract. When the repository changes this service also POSTs a ' +
        'few bytes to each registered PEP that gave a notify URL, saying ' +
        'only that something changed &mdash; an optimisation over the ' +
        'polling interval and never a replacement for it, so a PEP that is ' +
        'never nudged still converges.</p><h2>Not here ' +
        'yet</h2><ul>' + later + '</ul>' +
        '<p><a href="?format=json">This document as JSON</a></p>' +
        '</body></html>');
      log.debug('Leaving GET /xacml. HTML.');
    });

    log.debug("Leaving XacmlSurface.registerRoutes().");
  }
}

// ---------------------------------------------------------------------------
// THE TRANSITIONAL INSTANCE — see the header. Built from the real modules, as
// the composition root will build one, and its routes registered at load,
// after the three arming requires at the top, exactly where they always were.
// ---------------------------------------------------------------------------
const surface = new XacmlSurface({
  log: log,
  xmlEscape: xmlEscape,
  baseUrlOf: baseUrlOf,
  parseBody: parseBody,
  validation: validation,
  websecurity: websecurity,
  config: config,
  audit: audit,
  errorCodes: errorCodes,
  model: model,
  json: json,
  pdp: pdp,
  store: store,
  pip: pip,
  datatypes: datatypes,
  xml: xml,
  validate: validate,
  mtls: mtls,
  peps: peps,
  pepHttp: pepHttp,
  monitor: monitor,
  roles: roles,
  accessGate: accessGate,
  loadBarrier: function (): Barrier {
    return require('../cluster/cluster_barrier');
  },
  loadPersistence: function (): CommitWaiter {
    return require('../persistence/persistence');
  }
});
surface.registerRoutes(app);

export = {
  XacmlSurface: XacmlSurface,
  decide: surface.decide.bind(surface) as XacmlSurface['decide'],
  enforce: surface.enforce.bind(surface) as XacmlSurface['enforce'],
  description: surface.description.bind(surface) as
    XacmlSurface['description'],
  enabled: surface.enabled.bind(surface) as XacmlSurface['enabled'],
  // The designator cap a PIP query is held to, for
  // `tests/scan_and_rate_limits.js` (2026-09-12).
  pipMaxDesignators: surface.pipMaxDesignators.bind(surface) as
    XacmlSurface['pipMaxDesignators'],
  // The repository change observer, for
  // `tests/cluster_observation_counters.js` (2026-09-15):
  // a clustered node nudges only after the commit.
  nudgeRegisteredPeps: surface.nudgeRegisteredPeps.bind(surface) as
    XacmlSurface['nudgeRegisteredPeps']
};
