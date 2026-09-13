'use strict';
//
// File: access_gate.js
//
// ---------------------------------------------------------------------------
// EVERY ACCESS-CONTROL DECISION IN THIS SERVICE, ASKED IN ONE PLACE
// (2026-09-06).
//
// This is `issuance_gate.js`'s sibling and is deliberately the same shape. That
// one answers "may this be ISSUED"; this one answers "may this subject DO this
// to this resource" — the console, the management API, the User Portal, SCIM
// and the SPIRE Server API.
//
// **THE SUBJECT COMES FROM THE SECURITY CONTEXT AND NEVER FROM THE REQUEST**,
// and the two halves of that sentence are the whole architecture:
//
//   * every authenticated session in this service carries the person it
//     belongs to, so the SUBJECT of a decision is `session.user` — not a
//     username in a query string, not an id in a body;
//   * that subject, the resource and the action are what the PDP is asked
//     about, and the PDP decides.
//
// Those are different layers and conflating them is the classic mistake in both
// directions. Reading the identity from the request would mean the PDP
// faithfully deciding about whatever subject the CALLER nominated, which is
// broken access control with a policy engine in front of it. Hard-coding "your
// own data only" in the handler means the rule cannot be changed without a code
// change — and a helpdesk role that MAY read somebody else's account is a
// perfectly ordinary thing for a real deployment to want.
//
// **THE USER OBJECT IS ALREADY AN ATTRIBUTE SOURCE.** `xacml/xacml_pip.js` IS
// the embedded directory: a designator in the access-subject category is looked
// up on that person's own entry. So a policy can be written against anything
// the entry holds — a department, a title, a group — without this file or any
// call site knowing those attributes exist.
//
// ---------------------------------------------------------------------------
// AN EMPTY DECIDER MEANS ALLOW, exactly as it does for issuance, and for the
// same reason: a process that has not loaded `xacml/xacml.js` is a SMALLER
// service rather than a broken one. `npm test`, the parent project's in-process
// Kerberos jobs and the remote PEP container all run without the XACML family,
// and a console that refused everybody there would be unusable.
//
// **THAT IS NOT THE SAME AS FAILING OPEN ON AN ERROR.** A decider that THROWS
// is a defect in the PEP or the engine, and this allows — narrowly, loudly, and
// for the reason `issuance_gate.js` gives at length: the console that would let
// somebody fix the policy is reached through the gate that would be refusing
// them. A decider that returns Deny is a DECISION and is honoured.
//
// ---------------------------------------------------------------------------
// IT NEVER THROWS AND NEVER RETURNS A PROMISE. The console gate is express
// middleware, the portal reads it inside a page render, and an authorization
// check that made either asynchronous would be a change to every surface rather
// than to one file.
//
// A LIBRARY (rule 3): it registers no route and requires only `config` and
// `helpers`, so it is a LEAF and everything above it may require it.
// ---------------------------------------------------------------------------

const { log } = require('./helpers');
const config = require('./config');
// The error-code registry. A LEAF that requires nothing here, so this file
// stays one; the two failures below are tagged in the log rather than audited,
// because `audit.js` is a heavier require than a leaf gate should carry.
const errorCodes = require('./error_codes');

// ---------------------------------------------------------------------------
// THE RESOURCES. A closed list, because a resource id that only ever appears at
// one call site is a policy nobody can write against — an operator writing a
// rule has to be able to name the thing, and this is where the names are.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// ALL FIVE ASK NOW (2026-09-06). Three of them did not until that date, and
// the prose in four files said otherwise for the whole of the day between —
// which is why each entry below names its caller: a resource id that nothing
// asks about is a rule somebody can write and never see refuse anything.
//
//   admin-console       `admin-ui/admin.js`'s gate, on every page and form
//   user-portal         `portal/portal.js`'s requireSignIn()
//   management-api      `mgmt-api/admin_api.js`'s middleware, PRODUCT MODE
//                       ONLY — that surface is open in development by design
//   scim                `scim/scim_auth.js`'s authenticate() funnel
//   spire-server-api    `spiffe/spiffe_grpc.js`'s prepareCall()
//   xacml-pep-api       `xacml/xacml.js`'s pepAccess()
//   xacml-api           `xacml/xacml.js`'s xacmlAccess()
//
// **THE LAST TWO ARE NOT LIKE THE FIVE ABOVE THEM AND THE DIFFERENCE IS THE
// DEFAULT.** The five are surfaces an operator NARROWS: they require
// `EVERYBODY` until somebody says otherwise, so this layer changed nothing the
// day it was added. The two XACML ones carry their requirement in the REQUEST
// and are restricted out of the box, because a gate that is permissive until
// configured is a gate that is open on every deployment nobody has configured.
// It is still a POLICY decision either way — the same document decides all
// seven, and `xacml.enforceAccess` is the one switch that stops it deciding.
//
// **AND ONE OF THE FIVE HAS CALLERS THERE IS NOBODY TO DECIDE ABOUT
// (2026-09-10).** The SPIRE Server API's TCP port asks for a client
// certificate and does not require one — `AttestAgent` is reached by an agent
// that has no SVID yet and `GetBundle` by whoever is about to trust the trust
// domain, both `any` in SPIRE's own table — so an anonymous caller there is
// the specification rather than a mistake. The `access-control` document's
// `requireAuthenticated` conjunct refused every one of them, which closed the
// bootstrap on an unedited service and made the paragraph above untrue for
// that surface. `spiffe_grpc.js`'s policyRefusal() therefore asks about a
// caller it can NAME and skips one it cannot; nothing is widened, because
// every method SPIRE restricts is already refused before the gate is reached.
// See tests/spire_api_access_policy.js.
//
// **EACH ONE ASKS AFTER ITS OWN CHECK AND NEVER INSTEAD OF IT.** The console's
// two roles, SCIM's six RFC 7644 schemes and SPIRE's per-method table are
// unchanged and still decide first; this is the layer above them, so a
// deployment can narrow a surface by policy and an unedited one behaves
// exactly as it did — the built-in document asks for a role only where
// somebody has required one.
//
// **THE MANAGEMENT API IS THE ONE ASYMMETRY AND IT IS DELIBERATE.** In
// development that surface is open, so there is no credential, no session and
// no subject; asking a policy that refuses an unauthenticated subject would
// close the door the tests drive and the door somebody locked out of the
// console gets back in through. A policy layer must not remove the recovery
// path.
// ---------------------------------------------------------------------------
const RESOURCE = {
  CONSOLE: 'admin-console',
  MANAGEMENT_API: 'management-api',
  PORTAL: 'user-portal',
  SCIM: 'scim',
  SPIRE_SERVER_API: 'spire-server-api',
  // THE THREE ENDPOINTS A REMOTE POLICY ENFORCEMENT POINT LIVES ON
  // (2026-09-06): register, policies, heartbeat. It is the sixth resource and
  // the FIRST that is not permissive by default — see `requiredRoles` on
  // `check()` below, and `xacml/xacml.js` where it is asked.
  XACML_PEP_API: 'xacml-pep-api',
  // THE XACML SURFACE PROPER: GET /xacml, POST /xacml/pdp, GET
  // /xacml/policies, GET /xacml/protected. The seventh resource and the second
  // that is restricted from the start — it requires `XACML_USER`, which
  // `xacml/xacml.js` puts in the request.
  //
  // **A SEPARATE RESOURCE FROM `XACML_PEP_API` AND NOT A WIDENING OF IT**, and
  // the two ids are what make the separation writable: an operator adding a
  // second Permit rule for a helpdesk role, or narrowing one surface and not
  // the other, needs two names to target. One id covering all seven endpoints
  // would mean every policy anybody wrote about the demonstration surface also
  // decided who may pull the documents this service enforces its own access
  // with, which is the collapse `roles.js` keeps the two roles apart to
  // prevent — and a policy layer that cannot express the distinction its own
  // register makes is a policy layer somebody will work around.
  XACML_API: 'xacml-api'
};

// THE ACTIONS. Deliberately coarse — `read` and `write` are what the console's
// two roles already distinguish, and a vocabulary finer than the thing it
// describes is a vocabulary nobody uses correctly.
//
// `manage-own` is the portal's, and it is its own action rather than `write`
// because it means something different: not "may change things" but "may change
// THEIR OWN things", which is the distinction a helpdesk policy would later be
// written against.
const ACTION = {
  READ: 'read',
  WRITE: 'write',
  MANAGE_OWN: 'manage-own'
};

let decider = null;

function setDecider(fn) {
  log.debug('Entering setDecider().');
  if (typeof fn !== 'function' && fn !== null) {
    log.error(errorCodes.tag('STS-XACML-0050') +
              'access_gate: setDecider() was given something that is not a ' +
              'function, so it was refused. Every access decision will be ' +
              'ALLOWED, which is what a process without the XACML family ' +
              'does.');
    log.debug("Leaving setDecider().");
    return false;
  }
  decider = fn;
  log.debug('Leaving setDecider(). ' + (fn ? 'Installed.' : 'Cleared.'));
  return true;
}

function deciderInstalled() {
  log.debug("Entering deciderInstalled().");
  log.debug("Leaving deciderInstalled().");
  return !!decider;
}

function allow(why) {
  log.debug("Entering allow().");
  log.debug("Leaving allow().");
  return { allowed: true, decision: 'NotApplicable', why: why, policy: null };
}

// ---------------------------------------------------------------------------
// THE QUESTION.
//
//   { resource   one of RESOURCE above — WHAT is being reached.
//     action     one of ACTION — what is being done to it.
//     subject    the SECURITY CONTEXT's person:
//                  { name, authenticated, roles, sub, sessionId }
//                `name` is `session.user.username` and nothing else. A caller
//                that has no session passes `null`, which is a subject the
//                policy can decide about (ALL_UNAUTHENTICATED_USERS holds for
//                it) rather than an error.
//     owner      WHOSE resource it is, where that is a different person from
//                the subject. The portal sets it; nothing else does yet. It is
//                what lets a policy say "the subject is the owner" — and what
//                lets a LATER policy say "or the subject holds helpdesk".
//     context    anything else worth deciding on: the method, the path. For
//                the log and for a policy that wants it. }
//
// The answer is `{ allowed, decision, why, policy }` — `allowed` is what a
// caller branches on and the rest is what it logs or shows.
// ---------------------------------------------------------------------------
function check(request) {
  log.debug("Entering check().");
  const asked = request || {};
  log.debug('Entering check(). resource=' + asked.resource +
            ', action=' + asked.action);
  if (!decider) {
    log.debug('Leaving check(). No decider, so nothing is gated.');
    return allow('The XACML access subsystem is not loaded in this process, ' +
                 'so access is not gated by policy.');
  }
  if (config.value('xacml.enforceAccess') === false) {
    log.debug('Leaving check(). Enforcement is off.');
    return allow('xacml.enforceAccess is off, so the decision was not asked ' +
                 'for.');
  }
  if (!asked.resource || !asked.action) {
    // A caller that does not know what it is asking about. Allowed rather than
    // refused, and logged, because the alternative is a gate that refuses
    // because of a bug in the code that called it.
    log.warn('access_gate: a check named ' +
             (asked.resource ? 'no action' : 'no resource') +
             ', so it was allowed. That is a defect at the call site rather ' +
             'than a decision.');
    log.debug("Leaving check().");
    return allow('The check named no resource or no action.');
  }
  let answer;
  try {
    answer = decider(asked);
  } catch (error) {
    // See the header: a THROW is a defect, not a Deny.
    log.error(errorCodes.tag('STS-XACML-0051') +
              'access_gate: the decider threw and access was ALLOWED; this ' +
              'is a defect in the embedded PEP rather than a decision. ' +
              error.message);
    log.debug("Leaving check().");
    return allow('The embedded PEP threw, which is a defect rather than a ' +
                 'decision: ' + error.message);
  }
  const result = answer || allow('The embedded PEP answered nothing.');
  log.debug('Leaving check(). ' + (result.allowed ? 'Allowed.' : 'REFUSED: ' +
            result.why));
  return result;
}

module.exports = {
  RESOURCE: RESOURCE,
  ACTION: ACTION,
  setDecider: setDecider,
  deciderInstalled: deciderInstalled,
  check: check
};
