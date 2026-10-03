// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

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
/**
 * The kinds of issuance a caller may ask about, each the XACML `action-id`
 * policies are written against.
 */
const ISSUANCE = {
  SESSION: 'start-session',
  ACCESS_TOKEN: 'issue-access-token',
  ID_TOKEN: 'issue-id-token',
  REFRESH_TOKEN: 'issue-refresh-token',
  AUTHORIZATION_CODE: 'issue-authorization-code',
  SAML_ASSERTION: 'issue-saml-assertion',
  WSFED_TOKEN: 'issue-wsfed-token',
  WSTRUST_TOKEN: 'issue-wstrust-token',
  KERBEROS_TICKET: 'issue-kerberos-ticket',
  // A CERTIFICATE ENROLLED over ACME, EST or SCEP (2026-10-01), asked by
  // `common/cert_enrollment.ts` for an application subject, roles waived and
  // the device deferred: it is the protocol-declaration rule (#380) that
  // decides it, the family the caller names.
  CERTIFICATE: 'issue-certificate'
};

/**
 * Every value of `ISSUANCE`.
 */
const KINDS = Object.keys(ISSUANCE).map(function (key) {
  return ISSUANCE[key];
});

// THE PROTOCOL OF AN ISSUANCE, where the caller did not name one (#304): the
// issuance request carries it as an environment attribute, and every kind but
// a session belongs to one family. A session is protocol-independent — the
// authenticated identity is `authn/`'s — so it carries none unless named.
const PROTOCOL_OF_KIND = {
  'issue-access-token': 'OAuth 2.0',
  'issue-id-token': 'OpenID Connect',
  'issue-refresh-token': 'OAuth 2.0',
  'issue-authorization-code': 'OAuth 2.0',
  'issue-saml-assertion': 'SAML',
  'issue-wsfed-token': 'WS-Federation',
  'issue-wstrust-token': 'WS-Trust',
  'issue-kerberos-ticket': 'Kerberos',
  'issue-certificate': 'Certificate enrollment'
};

// THE PROTOCOL FAMILIES AN ISSUANCE SATISFIES (2026-10-01), as the ids of
// `applications.PROTOCOLS`, where the caller named none (`protocolFamilies`).
// An application declared for any one of them may be issued it. An access
// token, a refresh token and a code are OAuth 2.0's, and so OpenID Connect's,
// OpenID4VCI's and mutual TLS's, all of which are spoken over the same token
// endpoint; an ID Token is OpenID Connect's alone; a SAML assertion is either
// version's unless the caller says which. A session has no family.
const FAMILIES_OF_KIND = {
  'issue-access-token': ['oauth2', 'oidc', 'oid4vci', 'mtls'],
  'issue-refresh-token': ['oauth2', 'oidc', 'oid4vci', 'mtls'],
  'issue-authorization-code': ['oauth2', 'oidc', 'oid4vci', 'mtls'],
  'issue-id-token': ['oidc'],
  'issue-saml-assertion': ['saml2', 'saml11'],
  'issue-wsfed-token': ['wsfed'],
  'issue-wstrust-token': ['wstrust'],
  'issue-kerberos-ticket': ['krb5'],
  'issue-certificate': ['acme', 'est', 'scep']
};

let decider = null;

/**
 * Installs the function that decides issuance: the embedded PEP,
 * `xacml/xacml_role_pep.ts`.
 *
 * @param fn - the decider; anything but a function empties the slot, and
 * issuance is then ungated
 */
function setDecider(fn) {
  log.debug('Entering setDecider().');
  decider = typeof fn === 'function' ? fn : null;
  log.debug('Leaving setDecider(). Issuance is now ' +
            (decider ? 'decided by the embedded PEP.' : 'ungated.'));
}

// What is installed, for a test that stubs it — `xacml_store.js` argues why
// this is not pedantry, and it is the same one-process, one-reference
// situation here.
/**
 * Returns the decider now installed, for a test that stubs it.
 *
 * @returns the decider, or null
 */
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
/**
 * Asks whether something may be issued: a session, a token, an assertion, a
 * ticket.
 *
 * Refuses first for a realm being removed (STS-CORE-0121) and a disabled
 * account (STS-AUTHN-0201). With no decider installed every other call is
 * allowed; otherwise the embedded PEP decides on roles, risk and the registered
 * device. Never throws and never returns a promise; a decider that throws is
 * logged (STS-XACML-0052) and the issuance allowed.
 *
 * @param request - the question: `application`, `kind` (one of `ISSUANCE`),
 * `subject`, `claims`, `realm`, and optionally `risk`, `session`, `device` and
 * `deviceDeferred`
 * @returns `{ allowed, decision, why, roles, required, policy }`, where
 * `allowed` is what the caller branches on
 */
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
  // -------------------------------------------------------------------------
  // A REALM BEING REMOVED ISSUES NOTHING NEW (#262, 2026-09-26), asked before
  // everything, the disabled account included: it is about the realm and not
  // the person, and it holds in both modes and whatever any policy says.
  // `realms.retire()` marks the realm before it ends the sessions and
  // announces the removal, so a session or a token started in the bounded
  // wait that follows would outlive the announcement and be dropped by the
  // purge unannounced. `STS-CORE-0121`, carried on the answer (`retiring`)
  // and logged here, so every issuance site records it whatever code it
  // puts on its own response.
  // -------------------------------------------------------------------------
  const retiring = retiringRealm();
  if (retiring) {
    log.info(errorCodes.tag('STS-CORE-0121') + 'issuance_gate: ' +
             String(asked.kind || 'issuance') + ' refused. ' + retiring.why);
    log.debug('Leaving check(). The realm is being removed.');
    return errorCodes.mark({
      allowed: false, decision: 'Deny', retiring: true,
      why: retiring.why, roles: [], required: [], policy: null
    }, 'STS-CORE-0121');
  }
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
  // THE PROTOCOL DECLARATION (2026-10-01) rides along whenever the
  // application named is declared for something, and makes the policy asked
  // past the role shortcut in product, where its rule can refuse.
  const protocol = protocolFactsOf(asked);
  // `mode.js` is required LAZILY: it is a leaf, but this file is in the
  // parent project's Kerberos COPY closure and a top-level require here would
  // add a file to it (kerberos/CLAUDE.md).
  const mode = protocol ? require('./mode') : null;
  const protocolMatters = !!mode && !mode.issuesThroughUndeclaredProtocols();
  if (!enforceRoles && !risk && !deviceMatters && !protocolMatters) {
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
    protocol: asked.protocol || PROTOCOL_OF_KIND[String(asked.kind)] || '',
    risk: risk,
    device: device,
    deviceRequirement: deviceRequirement,
    protocolFamilies: protocol ? protocol.families : [],
    declaredProtocols: protocol ? protocol.declared : [],
    mode: mode ? mode.current() : '',
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

// ---------------------------------------------------------------------------
// THE PROTOCOL FACTS OF AN ISSUANCE (2026-10-01): the families it satisfies
// and the families the named application is declared for, or null when there
// is nothing to compare — no application, no family (a session), or an
// application declared for nothing, which no rule refuses. Required LAZILY,
// for `disabledSubject()`'s reason: this file is a leaf. A Kerberos service
// is named without its realm by the KDC, so its entry is also looked up with
// `@<krb5.realm>`. Never throws: a registry that cannot be read declares
// nothing.
// ---------------------------------------------------------------------------
function protocolFactsOf(asked) {
  log.debug('Entering protocolFactsOf().');
  const families = (Array.isArray(asked.protocolFamilies)
    ? asked.protocolFamilies : FAMILIES_OF_KIND[String(asked.kind)] || [])
    .map(function (one) { return String(one).trim().toLowerCase(); })
    .filter(function (one) { return !!one; });
  if (!asked.application || !families.length) {
    log.debug('Leaving protocolFactsOf(). Nothing to compare.');
    return null;
  }
  let declared = [];
  try {
    const applications = require('./applications');
    const names = [String(asked.application)];
    if (asked.kind === ISSUANCE.KERBEROS_TICKET &&
        names[0].indexOf('@') < 0 && config.value('krb5.realm')) {
      names.push(names[0] + '@' + String(config.value('krb5.realm')));
    }
    for (let i = 0; i < names.length && !declared.length; i += 1) {
      declared = applications.declaredFamiliesFor(names[i]);
    }
  } catch (e) {
    log.debug('Caught in protocolFactsOf(): ' + ((e && e.message) || e));
    declared = [];
  }
  if (!declared.length) {
    log.debug('Leaving protocolFactsOf(). Declared for nothing.');
    return null;
  }
  log.debug('Leaving protocolFactsOf(). ' + families.join(',') + ' against ' +
            declared.join(','));
  return { families: families, declared: declared };
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
// WHO MAY ACT FOR WHOM (#186): the two exchange questions an RFC 8693 token
// exchange, a WS-Trust OnBehalfOf / ActAs and a Kerberos S4U request ask —
// `choose-exchange-semantics` and `exchange-token` — with the facts
// `common/delegation_policy.ts` gathers. It replaced #108's deny-only
// `delegate` question: the attribute rule that question sat on top of is now
// the policy's own rules, and the attributes are only its facts.
//
// `request`: `{ facts, mode, protocol, realm, settings }`, as
// `xacml/xacml_exchange_verdicts.js` takes it. The answer is that library's:
// `{ verdict, refusal, enforced, semantics, chosen, audience, decidedBy }`.
//
// **WITH NO DECIDER THE BUILT-IN POLICY STILL DECIDES**, the transfer
// question's arrangement: a process with no XACML family asks the built-in
// document through the library, and a decider that THROWS is a defect and the
// built-in document is asked the same way (STS-XACML-0086). A process that
// cannot load the engine at all REFUSES (STS-XACML-0085): acting for somebody
// is never the answer to a defect.
//
// NOT MEMBERS OF `ISSUANCE`: acting for somebody issues nothing of its own —
// the token the act produces is still issued through the ordinary site.
// ---------------------------------------------------------------------------
/**
 * The action-ids of the two exchange questions (#186). Not members of
 * `ISSUANCE`.
 */
const EXCHANGE = {
  CHOOSE: 'choose-exchange-semantics',
  EXCHANGE: 'exchange-token'
};

function builtInExchangeVerdict(asked, why) {
  log.debug('Entering builtInExchangeVerdict().');
  let out;
  try {
    const verdicts = require('../xacml/xacml_exchange_verdicts');
    out = verdicts.decide(asked, null, {});
  } catch (error) {
    log.error(errorCodes.tag('STS-XACML-0085') + 'issuance_gate: the ' +
              'built-in issuance policy could not be evaluated for an ' +
              'exchange; it is refused. ' +
              ((error && error.message) || error));
    out = { verdict: 'refuse', refusal: 'policy', enforced: true,
            semantics: '', chosen: '', audience: '', decidedBy: 'none' };
  }
  log.debug('Leaving builtInExchangeVerdict(). ' + out.verdict);
  return Object.assign({ why: why }, out);
}

/**
 * Puts the two exchange questions (#186) to the issuance policy, with the
 * facts `common/delegation_policy.ts` gathered.
 *
 * Never throws and never returns a promise. With no decider, or a decider
 * that throws or answers no verdict, the built-in policy decides.
 *
 * @param request - `{ facts, mode, protocol, realm, settings }`
 * @returns `{ verdict, refusal, enforced, semantics, chosen, audience,
 *   decidedBy, why }`
 */
function checkExchange(request) {
  log.debug('Entering checkExchange().');
  const asked = Object.assign({}, request || {});
  if (!decider) {
    log.debug('Leaving checkExchange(). No decider: the built-in policy.');
    return builtInExchangeVerdict(asked, 'No XACML family is loaded in this ' +
                                  'process; the built-in policy decided.');
  }
  let answer;
  try {
    answer = decider({
      kind: EXCHANGE.EXCHANGE,
      application: '',
      subject: { kind: 'user', name: '', authenticated: true },
      claims: null,
      risk: null,
      rolesWaived: true,
      exchangeQuestion: asked
    });
  } catch (error) {
    log.error(errorCodes.tag('STS-XACML-0086') +
              'issuance_gate: the decider threw on an exchange question; the ' +
              'built-in policy decides instead. This is a defect in the ' +
              'embedded PEP rather than a decision. ' + error.message);
    log.debug('Leaving checkExchange(). The decider threw.');
    return builtInExchangeVerdict(asked, 'The embedded PEP threw: ' +
                                  error.message);
  }
  const exchange = answer && answer.exchange;
  if (!exchange || !exchange.verdict) {
    log.debug('Leaving checkExchange(). The PEP answered no verdict.');
    return builtInExchangeVerdict(asked, 'The embedded PEP answered no ' +
                                  'exchange verdict.');
  }
  log.debug('Leaving checkExchange(). ' + exchange.verdict);
  return Object.assign({ why: answer.why || '' }, exchange);
}

// ---------------------------------------------------------------------------
// THE PER-SCOPE QUESTION (#304, #305 — parts C and D of #88): which requested
// scopes (or RFC 9396 details) are issued. `request` is the question
// `xacml/xacml_scope_verdicts.js` asks — `{ subject, client, grantType,
// protocol, held, mode, settings, stage, consentRequired, action, requested,
// facts: [{ scope, gated?, attributes }] }` — the FACTS, gathered by the
// subsystem that knows them; the issuance policy decides each one and this
// answers `{ verdicts: [{ scope, verdict, code, decidedBy }] }`, verdict
// `keep`, `drop`, `refuse` or `consent`.
//
// **WITH NO DECIDER THE BUILT-IN POLICY STILL DECIDES (rcbj's decision on
// #305).** A process with no XACML family loaded — the in-process tests, the
// parent project's Kerberos jobs — loads the engine's LIBRARIES here, lazily
// (the model, the PDP, the templates and the request builder, none of which
// registers a route or fills a slot), and asks the built-in document itself:
// the rules live in one place and hold in every process. A decider that
// THROWS is a defect, and the built-in policy is asked the same way.
// ---------------------------------------------------------------------------
function builtInScopeVerdicts(asked, why) {
  log.debug('Entering builtInScopeVerdicts().');
  let verdicts;
  try {
    verdicts = require('../xacml/xacml_scope_verdicts').decide(asked, null, {});
  } catch (error) {
    // THE ENGINE ITSELF COULD NOT BE LOADED OR RUN — a defect. What is left
    // is the fact-level reading the policy module uses for its own defect:
    // a gated scope dropped, everything else kept.
    log.error(errorCodes.tag('STS-XACML-0079') + 'issuance_gate: the ' +
              'built-in issuance policy could not be evaluated for the ' +
              'scope question; gated scopes are dropped. ' + error.message);
    verdicts = (asked.facts || []).map(function (one) {
      return { scope: one.scope, verdict: one.gated ? 'drop' : 'keep',
               code: one.gated ? 'STS-ADMIN-0821' : '', decidedBy: 'none' };
    });
  }
  log.debug('Leaving builtInScopeVerdicts().');
  return { verdicts: verdicts, why: why, policy: 'built-in' };
}

function checkScopes(request) {
  log.debug('Entering checkScopes().');
  const asked = Object.assign({}, request || {});
  asked.facts = Array.isArray(asked.facts) ? asked.facts : [];
  if (!asked.facts.length) {
    log.debug('Leaving checkScopes(). Nothing asked.');
    return { verdicts: [], why: '' };
  }
  if (!decider) {
    log.debug('Leaving checkScopes(). No decider: the built-in policy.');
    return builtInScopeVerdicts(asked, 'No XACML family is loaded in this ' +
                                'process; the built-in policy decided.');
  }
  let answer;
  try {
    answer = decider({
      kind: asked.action || 'issue-scope',
      application: String(asked.application || ''),
      subject: asked.subject || {},
      client: asked.client || '',
      grantType: asked.grantType || '',
      protocol: asked.protocol || '',
      claims: null,
      risk: null,
      rolesWaived: true,
      scopeQuestion: asked
    });
  } catch (error) {
    log.error(errorCodes.tag('STS-XACML-0052') +
              'issuance_gate: the decider threw on the scope question; the ' +
              'built-in policy decides instead. This is a defect in the ' +
              'embedded PEP rather than a decision. ' + error.message);
    log.debug('Leaving checkScopes(). The decider threw.');
    return builtInScopeVerdicts(asked, 'The embedded PEP threw: ' +
                                error.message);
  }
  const verdicts = answer && Array.isArray(answer.scopes) ? answer.scopes
    : null;
  if (!verdicts) {
    log.debug('Leaving checkScopes(). The PEP answered no verdicts.');
    return builtInScopeVerdicts(asked, 'The embedded PEP answered no ' +
                                'verdicts.');
  }
  log.debug('Leaving checkScopes(). ' + verdicts.length + ' verdict(s).');
  return { verdicts: verdicts, why: '', policy: answer.policy || '' };
}

// ---------------------------------------------------------------------------
// THE TRANSFER QUESTIONS (#98 D4, the design's section 6): action-ids
// `hold-session`, `serve-request` and `release-attributes`, asked by
// `common/cell_transfer.ts` when the service is deployed as cells.
// `hold-session`: may a session of a subject homed in one jurisdiction be
// HELD by a cell in another? `serve-request`: may a request about them be
// served from that cell at all, even by relaying it home?
// `release-attributes` (#98 D11): may residents' personal data be RELEASED
// to a reader at a cell in another jurisdiction?
//
// **NOT MEMBERS OF `ISSUANCE`**, for `EXCHANGE`'s reason and the scope
// question's: neither issues anything — holding a session somewhere is a
// question about WHERE a session already decided on lives, and serving a
// request or releasing a directory listing is not an issuance at all — and
// every reader of `KINDS` lists
// issuances (the /admin/roles preview, `/admin-api`'s closed set of issuance
// kinds, the realm-retiring test that refuses each one). They are still
// action-ids of the ISSUANCE POLICY, spelt in the verb-noun shape of the
// kinds above, and a realm's policy writes rules against them exactly as it
// does against `issue-scope`.
//
// `request`: `{ action, subject, home, serving, clientCountry, listed,
// hardGeofence, category, realm, purpose }` — FACTS, gathered by
// `cell_transfer.ts`; the answer is `{ verdict, decidedBy, why }`, verdict
// `hold` / `relay`, `serve` / `refuse` or `release` / `withhold`.
//
// **WITH NO DECIDER THE BUILT-IN POLICY STILL DECIDES**, the scope question's
// arrangement (rcbj's decision on #305): the engine's libraries are loaded
// here lazily and asked the built-in document, and a decider that THROWS is
// a defect and the built-in policy is asked the same way. A process that
// cannot load the engine at all falls to the strict reading of the same rule
// (`xacml_transfer_verdicts.js`'s `strictReading()`), STS-CELL-0181 — never
// to something looser.
// ---------------------------------------------------------------------------
/**
 * The action-ids of the three transfer questions (#98). Not members of
 * `ISSUANCE`.
 */
const TRANSFER = {
  HOLD_SESSION: 'hold-session',
  SERVE_REQUEST: 'serve-request',
  RELEASE_ATTRIBUTES: 'release-attributes'
};

function builtInTransferVerdict(asked, why) {
  log.debug('Entering builtInTransferVerdict().');
  let out;
  try {
    const verdicts = require('../xacml/xacml_transfer_verdicts');
    out = verdicts.decide(asked, null, {});
  } catch (error) {
    log.error(errorCodes.tag('STS-CELL-0181') + 'issuance_gate: the ' +
              'built-in issuance policy could not be evaluated for ' +
              String(asked.action) + '; the strict default decides. ' +
              ((error && error.message) || error));
    out = { verdict: strictTransferReading(asked), decidedBy: 'none' };
  }
  log.debug('Leaving builtInTransferVerdict(). ' + out.verdict);
  return Object.assign({ why: why }, out);
}

// The strict default read from the facts — the built-in rule, for the one
// case where not even the engine can be loaded. A copy of
// `xacml_transfer_verdicts.js`'s `strictReading()`, because this is exactly
// the process that cannot load that module; `tests/cell_transfer.js` holds
// the two to the same truth table.
function strictTransferReading(asked) {
  log.debug('Entering strictTransferReading().');
  const q = asked || {};
  const same = !!q.home && !!q.serving && q.home === q.serving;
  const permitted = same || !!q.listed;
  let verdict;
  if (q.action === TRANSFER.SERVE_REQUEST) {
    verdict = q.hardGeofence && !permitted ? 'refuse' : 'serve';
  } else if (q.action === TRANSFER.RELEASE_ATTRIBUTES) {
    verdict = permitted ? 'release' : 'withhold';
  } else {
    verdict = permitted ? 'hold' : 'relay';
  }
  log.debug('Leaving strictTransferReading(). ' + verdict);
  return verdict;
}

/**
 * Puts a transfer question (#98) to the issuance policy: `hold-session`,
 * `serve-request` or `release-attributes`, with the facts
 * `common/cell_transfer.ts` gathered.
 *
 * Never throws and never returns a promise. With no decider, or a decider
 * that throws or answers nothing, the built-in policy decides.
 *
 * @param request - `{ action, subject, home, serving, clientCountry, listed,
 * hardGeofence, category, realm, purpose }`
 * @returns `{ verdict, decidedBy, why }`
 */
function checkTransfer(request) {
  log.debug('Entering checkTransfer().');
  const asked = Object.assign({}, request || {});
  if (!decider) {
    log.debug('Leaving checkTransfer(). No decider: the built-in policy.');
    return builtInTransferVerdict(asked, 'No XACML family is loaded in this ' +
                                  'process; the built-in policy decided.');
  }
  let answer;
  try {
    answer = decider({
      kind: asked.action,
      application: '',
      subject: { kind: 'user', name: String(asked.subject || ''),
                 authenticated: true },
      claims: null,
      risk: null,
      rolesWaived: true,
      transferQuestion: asked
    });
  } catch (error) {
    log.error(errorCodes.tag('STS-XACML-0052') +
              'issuance_gate: the decider threw on a transfer question; the ' +
              'built-in policy decides instead. This is a defect in the ' +
              'embedded PEP rather than a decision. ' + error.message);
    log.debug('Leaving checkTransfer(). The decider threw.');
    return builtInTransferVerdict(asked, 'The embedded PEP threw: ' +
                                  error.message);
  }
  const transfer = answer && answer.transfer;
  if (!transfer || !transfer.verdict) {
    log.debug('Leaving checkTransfer(). The PEP answered no verdict.');
    return builtInTransferVerdict(asked, 'The embedded PEP answered no ' +
                                  'transfer verdict.');
  }
  log.debug('Leaving checkTransfer(). ' + transfer.verdict);
  return { verdict: transfer.verdict, decidedBy: transfer.decidedBy || '',
           why: answer.why || '' };
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
/**
 * Finds the registered device an issuance came from, brought up to date against
 * the device register.
 *
 * @param asked - the issuance request: its own `device` where named (null
 * meaning none), otherwise the device the session's latest authentication event
 * recognised
 * @returns the device fact, or null
 */
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
/**
 * Lists what the ambient realm requires of a device, as the bag the issuance
 * policy reads.
 *
 * @returns some of `not-compromised`, `compliant` and `attested`, as the
 * `devices.*` settings say
 */
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

// The ambient realm's retirement refusal, or null. `realms.js` is required
// LAZILY, for `account_state`'s reason below: this file is a leaf, and the
// question is only ever asked of a running service. Never throws.
function retiringRealm() {
  log.debug("Entering retiringRealm().");
  let refusal = null;
  try {
    refusal = require('./realms').retiringRefusal();
  } catch (e) {
    log.debug("Caught in retiringRealm(): " + ((e && e.message) || e));
    refusal = null;
  }
  log.debug("Leaving retiringRealm(). " + !!refusal);
  return refusal;
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

/**
 * The one place this service asks "may I issue this?", answered by whichever
 * policy enforcement point filled its slot.
 *
 * A leaf; an empty slot means issue. The embedded XACML PEP fills it.
 *
 * @namespace
 */
module.exports = {
  ISSUANCE: ISSUANCE,
  KINDS: KINDS,
  setDecider: setDecider,
  deciderInstalled: deciderInstalled,
  check: check,
  checkScopes: checkScopes,
  PROTOCOL_OF_KIND: PROTOCOL_OF_KIND,
  FAMILIES_OF_KIND: FAMILIES_OF_KIND,
  deviceFactsOf: deviceFactsOf,
  deviceRequirementOf: deviceRequirementOf,
  EXCHANGE: EXCHANGE,
  checkExchange: checkExchange,
  TRANSFER: TRANSFER,
  checkTransfer: checkTransfer,
  strictTransferReading: strictTransferReading
};
