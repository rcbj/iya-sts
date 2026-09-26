// @ts-check
'use strict';
//
// File: issuance_gate.js
//
// ---------------------------------------------------------------------------
// THE ONE PLACE THIS SERVICE ASKS "MAY I ISSUE THIS?", AND THE REASON IT IS AN
// EMPTY SHELL.
//
// Every protocol family here ends in an issuance: an access token, an ID
// Token, a SAML assertion, a WS-Federation response, a WS-Trust token, a
// browser session. Since 2026-09-05 each of those asks this file first, and
// this file asks whoever filled the slot below — which is
// `xacml/xacml_role_pep.ts`, an EMBEDDED POLICY ENFORCEMENT POINT that turns
// the question into a XACML request and puts it to the PDP.
//
// So the answer to "may this application be issued anything for this person"
// is a POLICY DECISION in this service, made by the same engine that answers
// `/xacml/pdp` for anybody else, against a policy an administrator can read,
// edit and test on the console. There is no second implementation of the rule
// and there is no `if` in an issuance site.
//
// ---------------------------------------------------------------------------
// WHY THIS FILE EXISTS AT ALL, RATHER THAN oauth2.js CALLING THE PEP.
//
// Rule 3e's test, and it fails both ways round, which is exactly when a slot
// is the answer:
//
//   * A require from an issuance site to `xacml/` would MOVE ROUTES. Eight
//     modules issue something and all but one are required BEFORE
//     `xacml/xacml.ts` at 23c — `wstrust` at 7, `authn` at 8, `oauth2` at 9,
//     `wsfed` at 10, the two SAML profiles at 10a and 10b, the KDC at 15.
//     (GNAP, at 23d, came later and asks through this file like the rest.)
//     Requiring the XACML family from any of the seven registers eight
//     `/xacml` routes and six `/admin/xacml` pages at that position
//     instead, ahead of the management API's own, which is the failure
//     CLAUDE.md's require-order table exists to prevent.
//   * And it would CLOSE A CYCLE. `xacml_admin.js` requires
//     `admin-ui/admin.ts`, which requires `oauth2.js`.
//
// A require in the other direction — the PEP reaching into `oauth2.js` — is
// not a candidate at all: the PEP would then have to know about every caller.
//
// **SO THIS FILE REQUIRES ALMOST NOTHING AND MUST STAY THAT WAY.** `helpers`
// and `config`, both of which every module here already has. It is a LEAF, and
// a leaf can be required from position 7 without dragging anything with it.
//
// ---------------------------------------------------------------------------
// AN EMPTY SLOT MEANS ISSUE, AND THAT IS THE MOST IMPORTANT LINE HERE.
//
// A process that never loaded the XACML family — the parent project's
// in-process Kerberos jobs, `npm test`, any of the module tests that require
// two files and an app — has no decider installed, and every call answers
// `allowed`. The service is then exactly what it was before this existed: a
// smaller service, not a broken one, which is the same rule every other slot
// in this repository follows.
//
// It is the right default for a second reason that is about failure rather
// than about tests. This service exists to be exercised, and an authorization
// subsystem that could brick every protocol family by being half-loaded would
// be the worst possible thing to put in front of a mock. **Where enforcement
// must fail CLOSED it does so in the PEP, which knows whether somebody
// actually asked for a restriction** — see `xacml/xacml_role_pep.ts`, which
// argues the one case that refuses on a missing policy and the one that does
// not. This file's job is to be absent-safe; it is not the file that decides
// what a restriction means.
// ---------------------------------------------------------------------------

const { log } = require('./helpers');
const config = require('./config');
// The error-code registry. A LEAF that requires nothing here, so this file
// stays one; the one failure below is tagged in the log rather than audited.
const errorCodes = require('./error_codes');

// The kinds of issuance a caller may ask about. They become the XACML
// `action-id` of the request, so this list is a VOCABULARY that policies are
// written against — adding one is adding a word a policy author can match on,
// and renaming one silently stops every policy that named the old word from
// matching, which is a policy that permits nothing rather than an error.
const ISSUANCE = {
  SESSION: 'start-session',
  ACCESS_TOKEN: 'issue-access-token',
  ID_TOKEN: 'issue-id-token',
  REFRESH_TOKEN: 'issue-refresh-token',
  AUTHORIZATION_CODE: 'issue-authorization-code',
  SAML_ASSERTION: 'issue-saml-assertion',
  WSFED_TOKEN: 'issue-wsfed-token',
  WSTRUST_TOKEN: 'issue-wstrust-token',
  KERBEROS_TICKET: 'issue-kerberos-ticket'
};

const KINDS = Object.keys(ISSUANCE).map(function (key) {
  return ISSUANCE[key];
});

let decider = null;

function setDecider(fn) {
  log.debug('Entering setDecider().');
  decider = typeof fn === 'function' ? fn : null;
  log.debug('Leaving setDecider(). Issuance is now ' +
            (decider ? 'decided by the embedded PEP.' : 'ungated.'));
}

// What is installed, for a test that stubs it — `xacml_store.js` argues why
// this is not pedantry, and it is the same one-process, one-reference
// situation here.
function deciderInstalled() {
  log.debug("Entering deciderInstalled().");
  log.debug("Leaving deciderInstalled().");
  return decider;
}

// ---------------------------------------------------------------------------
// THE QUESTION.
//
// `request` is:
//   { application   the handle of the application something is being issued
//                   FOR — a client_id, a SAML entityID's slug, a wtrealm.
//                   ABSENT MEANS THERE IS NOTHING TO DECIDE ABOUT: this
//                   service issues nothing to nobody, so a call with no
//                   application is a caller that does not know who it is
//                   serving, and the honest answer is to allow rather than to
//                   invent a subject.
//     kind          one of ISSUANCE above.
//     subject       { kind, name, authenticated, groups } — the party being
//                   authenticated, which is a PERSON in a browser flow and the
//                   CLIENT ITSELF in a client_credentials grant. That is the
//                   whole of the "user or application" the requirement is
//                   about.
//     claims        the claims of a token the caller presented, if any, so
//                   that a roles claim in it can be read back.
//     realm         for the log line only; the decision runs in the ambient
//                   realm like everything else.
//     risk          (#62 P3) the RISK of the authentication this issuance
//                   rests on, as `risk/risk_engine.ts`'s `factsOf()` states
//                   it — or null for "none". A caller that names none has
//                   it found (`riskFactsOf()` below).
//     session       (#62 P3) the session the issuance rests on, where the
//                   caller holds it: its `risk` and its `amr`/`acr` are the
//                   facts, so every token on a session is decided on the
//                   risk its sign-in established.
//     device        (#164 phase 6) the REGISTERED DEVICE this issuance came
//                   from — `common/device_recognition.ts`'s fact, or null
//                   for "none". A caller that names none has the session's
//                   found (`deviceFactsOf()` below), brought up to date
//                   against the register.
//     deviceDeferred  (#164 phase 6) true where a caller asks BEFORE the
//                   credential that could name the device has been
//                   presented — the sign-in screen, ahead of its WebAuthn
//                   ceremony — so the device question is left to the
//                   session's start. }
//
// The answer is `{ allowed, decision, why, roles, required, policy }` — the
// XACML decision and the reason, kept apart on purpose: `allowed` is what an
// issuance site branches on and everything else is what it puts in a log, an
// error description or an audit record.
//
// IT NEVER THROWS AND NEVER RETURNS A PROMISE. A dozen issuance sites in
// eight modules call it, several of them inside code paths this service has
// always run synchronously, and an authorization check that could make a
// token endpoint asynchronous would be a change to eight protocol
// implementations rather than to one file.
// ---------------------------------------------------------------------------
function check(request) {
  log.debug('Entering check(). kind=' + (request || {}).kind);
  const asked = request || {};
  // ---------------------------------------------------------------------
  // A DISABLED ACCOUNT IS ISSUED NOTHING (2026-09-17, #36 follow-up), and it
  // is asked FIRST — before the three early "allowed" answers below, none of
  // which is about the person: no decider loaded, enforcement off, no
  // application named. A disable is not a role decision, so it holds whatever
  // `roles.enforceIssuance` says, and it is here because this function is the
  // one every issuance site calls — a token of any grant, an ID Token, a
  // SAML or WS-Federation assertion, a WS-Trust token, a Kerberos ticket, a
  // session. `common/account_state.ts` is the reader, required LAZILY: this
  // file is a leaf loaded by modules that load before it, and the question is
  // only ever asked of a running service.
  // ---------------------------------------------------------------------
  const subject = asked.subject || {};
  if (subject.kind === 'user' && subject.name &&
      disabledSubject(String(subject.name))) {
    log.info('issuance_gate: ' + subject.name + ' is disabled; ' +
             String(asked.kind || 'issuance') + ' is refused.');
    log.debug('Leaving check(). The account is disabled.');
    return errorCodes.mark({
      allowed: false, decision: 'Deny', disabled: true,
      why: 'The account "' + subject.name + '" is disabled, so nothing is ' +
           'issued on its behalf.',
      roles: [], required: [], policy: null
    }, 'STS-AUTHN-0201');
  }
  if (!decider) {
    log.debug('Leaving check(). No decider is installed, so nothing is gated.');
    return allow('The XACML role subsystem is not loaded in this process, ' +
                 'so issuance is not gated.');
  }
  // -------------------------------------------------------------------------
  // THE TWO SHORTCUTS WAIVE THE ROLE QUESTION AND NOTHING ELSE (#62 P3,
  // 2026-09-22). `roles.enforceIssuance` off and a call that names no
  // application both used to answer "allowed" without asking — which was
  // right while the policy asked only about roles, and would be a way round
  // every RISK decision now that the same policy asks about both. So the
  // policy is still asked whenever there are risk facts, told the role
  // question is waived, and only a Deny about risk refuses.
  // -------------------------------------------------------------------------
  const risk = riskFactsOf(asked);
  // THE AUTHENTICATION A SESSION STANDS ON (#64) rides along whenever the
  // policy IS asked, and does not make it asked: a sign-in that names no
  // application and carries no risk facts is not put to the policy, as it
  // never was. A rule refusing an emailed factor therefore reaches every
  // session an application is being signed in to, and every assessed one.
  const enforceRoles = config.value('roles.enforceIssuance') !== false;
  // THE REGISTERED DEVICE (#164 phase 6) rides along whenever the policy is
  // asked, and makes it asked — past both shortcuts, as risk does — only
  // where a device rule could refuse: the realm requires a compliant device,
  // or the device in hand is compromised and the realm refuses one. Every
  // other issuance is asked exactly when it was before.
  const deferred = asked.deviceDeferred === true;
  const device = deferred ? null : deviceFactsOf(asked);
  const deviceRequirement = deferred ? [] : deviceRequirementOf();
  const deviceMatters = deviceRequirement.indexOf('compliant') >= 0 ||
    (!!device && device.status === 'compromised' &&
     deviceRequirement.indexOf('not-compromised') >= 0);
  if (!enforceRoles && !risk && !deviceMatters) {
    log.debug('Leaving check(). Enforcement is switched off.');
    return allow('roles.enforceIssuance is off, so the decision was not ' +
                 'asked for.');
  }
  if (!asked.application && !risk && !deviceMatters) {
    log.debug('Leaving check(). No application to decide about.');
    return allow('Nothing named an application, so there is no requirement ' +
                 'to check.');
  }
  const question = Object.assign({}, asked, {
    risk: risk,
    device: device,
    deviceRequirement: deviceRequirement,
    rolesWaived: asked.rolesWaived === true || !enforceRoles ||
                 !asked.application
  });
  let answer;
  try {
    answer = decider(question);
  } catch (error) {
    // THE ONE PLACE THIS FAILS OPEN ON AN ERROR, and it is deliberate and
    // narrow. A THROW here is a defect in the PEP or the engine — not a Deny,
    // not an Indeterminate, both of which the PEP returns as ordinary answers.
    // A mock whose every protocol family stopped issuing because a policy
    // module threw would be unusable and, worse, unfixable: the console that
    // would let somebody correct the policy is reached through a session this
    // service would then refuse to mint.
    log.error(errorCodes.tag('STS-XACML-0052') +
              'issuance_gate: the decider threw and issuance was ALLOWED; ' +
              'this is a defect in the embedded PEP rather than a decision. ' +
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

// Whether a subject name is a disabled account. Never throws: a reader that
// cannot be loaded disables nobody, which is what a process without the
// directory has always meant.
// ---------------------------------------------------------------------------
// THE RISK FACTS OF AN ISSUANCE (#62 P3). The caller's own, where it named
// them — `startSession()` does, from the assessment it was handed, and an
// explicit null means none. Otherwise `risk/risk_engine.ts` finds them: the
// session's, where the caller passed it, or the person's standing held in
// this process. Required LAZILY: the risk modules are built by the
// composition root (18j) long after this leaf, and a process without them —
// a test that loads the gate alone — has no facts, which decides on roles
// alone. Synchronous, as `check()` must be.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// THE DELEGATION QUESTION (#108, 2026-09-23): action-id `delegate`, asked by
// `common/delegation_policy.ts` AFTER its attribute rule has allowed a
// WS-Trust OnBehalfOf / ActAs or an RFC 8693 exchange.
//
// **DENY-ONLY, AND THAT IS THE WHOLE DIFFERENCE FROM `check()`.** The
// attributes on the entries are the policy and stay readable on their own —
// Kerberos's model — and this is an administrator's layer ON TOP of them: a
// Permit, a NotApplicable and an Indeterminate all leave the attribute rule's
// answer standing, and only an explicit Deny refuses. So the built-in issuance
// policy, which says nothing about `delegate`, changes nothing, and an
// operator who writes a rule denying one intermediary, one subject or one
// target gets exactly that and no more.
//
// NOT A MEMBER OF `ISSUANCE`: delegating is not an issuance of its own — the
// token the act produces is still issued through the ordinary site and asked
// about there — and every reader of `KINDS` lists issuances.
//
// `delegation`: { intermediary, subject, target, mode, protocol }.
// ---------------------------------------------------------------------------
const DELEGATE = 'delegate';

function checkDelegation(delegation) {
  log.debug('Entering checkDelegation().');
  const asked = delegation || {};
  if (!decider) {
    log.debug('Leaving checkDelegation(). No decider is installed.');
    return allow('The XACML role subsystem is not loaded in this process, ' +
                 'so the delegation is not put to it.');
  }
  let answer;
  try {
    answer = decider({
      kind: DELEGATE,
      denyOnly: true,
      application: String(asked.target || ''),
      subject: { kind: 'user', name: String(asked.subject || ''),
                 authenticated: true },
      claims: null,
      risk: null,
      rolesWaived: true,
      delegation: {
        intermediary: String(asked.intermediary || ''),
        subject: String(asked.subject || ''),
        target: String(asked.target || ''),
        mode: String(asked.mode || ''),
        protocol: String(asked.protocol || '')
      }
    });
  } catch (error) {
    log.error(errorCodes.tag('STS-XACML-0052') +
              'issuance_gate: the decider threw on a delegation question and ' +
              'the attribute rule\'s answer stands; this is a defect in the ' +
              'embedded PEP rather than a decision. ' + error.message);
    log.debug("Leaving checkDelegation().");
    return allow('The embedded PEP threw, which is a defect rather than a ' +
                 'decision: ' + error.message);
  }
  const result = answer || allow('The embedded PEP answered nothing.');
  log.debug('Leaving checkDelegation(). ' + (result.allowed ? 'Allowed.'
    : 'DENIED: ' + result.why));
  return result;
}

function riskFactsOf(asked) {
  log.debug("Entering riskFactsOf().");
  if (Object.prototype.hasOwnProperty.call(asked, 'risk')) {
    log.debug("Leaving riskFactsOf(). The caller's.");
    return asked.risk || null;
  }
  let facts = null;
  try {
    facts = require('../risk/risk_engine').factsForIssuance(Object.assign({
      realm: require('./realms').currentId() }, asked));
  } catch (e) {
    log.debug("Caught in riskFactsOf(): " + ((e && e.message) || e));
    // No risk engine in this process: no facts, and the roles decide.
    facts = null;
  }
  log.debug("Leaving riskFactsOf(). " + (facts ? facts.level : 'None.'));
  return facts;
}

// ---------------------------------------------------------------------------
// THE REGISTERED DEVICE OF AN ISSUANCE (#164 phase 6). The caller's own,
// where it named one — the token endpoint recognises the DPoP key, the client
// certificate or the Native SSO secret it was handed, and the session's start
// the credential it was handed — and an explicit null means none. Otherwise
// the device the session's latest authentication event recognised. Either
// way BROUGHT UP TO DATE against the register (`device_recognition.ts`'s
// `current()`): compliance is exactly what moves under a live session, and a
// device removed since is no device. Required LAZILY, for `riskFactsOf()`'s
// reason; a process without the register has no device facts, which a
// device rule reads as "none".
// ---------------------------------------------------------------------------
function deviceFactsOf(asked) {
  log.debug("Entering deviceFactsOf().");
  let fact = null;
  if (Object.prototype.hasOwnProperty.call(asked, 'device')) {
    fact = asked.device || null;
  } else if (asked.session && Array.isArray(asked.session.events) &&
             asked.session.events.length) {
    const last = asked.session.events[asked.session.events.length - 1];
    fact = (last && last.registeredDevice) || null;
  }
  if (!fact) {
    log.debug("Leaving deviceFactsOf(). None.");
    return null;
  }
  let current = fact;
  try {
    current = require('./device_recognition').current(fact);
  } catch (e) {
    log.debug("Caught in deviceFactsOf(): " + ((e && e.message) || e));
    // No register in this process: the fact as it was recorded.
    current = fact;
  }
  log.debug("Leaving deviceFactsOf(). " + (current ? current.id : 'Gone.'));
  return current;
}

// ---------------------------------------------------------------------------
// WHAT THIS REALM REQUIRES OF A DEVICE (#164 decision 3, phase 6), as the
// bag the issuance policy reads (`urn:sts:xacml:device-requirement`):
// `not-compromised` while `devices.refuseCompromised` is on (the default),
// `compliant` while `devices.requireCompliantDevice` is (off by default in
// both modes, rcbj's decision), and `attested` beside it while
// `devices.compliantDeviceAttested` is. The settings SWITCH the rules and
// the policy states them — `xacml/xacml_templates.ts` argues it.
// ---------------------------------------------------------------------------
function deviceRequirementOf() {
  log.debug("Entering deviceRequirementOf().");
  const out = [];
  if (config.value('devices.refuseCompromised') !== false) {
    out.push('not-compromised');
  }
  if (config.value('devices.requireCompliantDevice') === true) {
    out.push('compliant');
    if (config.value('devices.compliantDeviceAttested') === true) {
      out.push('attested');
    }
  }
  log.debug("Leaving deviceRequirementOf(). " + out.join(', '));
  return out;
}

function disabledSubject(name) {
  log.debug("Entering disabledSubject().");
  let disabled = false;
  try {
    disabled = !!require('./account_state').isDisabled(name);
  } catch (e) {
    log.debug("Caught in disabledSubject(): " + ((e && e.message) || e));
    disabled = false;
  }
  log.debug("Leaving disabledSubject(). " + disabled);
  return disabled;
}

function allow(why) {
  log.debug("Entering allow().");
  log.debug("Leaving allow().");
  return { allowed: true, decision: 'NotApplicable', why: why,
           roles: [], required: [], policy: null };
}

module.exports = {
  ISSUANCE: ISSUANCE,
  KINDS: KINDS,
  setDecider: setDecider,
  deciderInstalled: deciderInstalled,
  check: check,
  deviceFactsOf: deviceFactsOf,
  deviceRequirementOf: deviceRequirementOf,
  DELEGATE: DELEGATE,
  checkDelegation: checkDelegation
};
