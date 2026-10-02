// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: xacml_scope_verdicts.js
//
// ---------------------------------------------------------------------------
// THE PER-SCOPE QUESTION, ASKED ONE WAY (#304, #305 — parts C and D of #88).
//
// Which requested scopes are issued — and, since #305, which need consent and
// which RFC 9396 detail types are allowed — is decided by the issuance policy,
// one question per scope (or detail): the scope as the resource-id, the FACTS
// about it on the resource, the subject and its held roles on the subject, and
// the mode, the settings a rule reads and the STAGE in the environment. The
// answer's scope obligation is the verdict: keep, drop, refuse or consent,
// with a code.
//
// Two callers ask it and they must ask it identically:
//
//   * `xacml_role_pep.ts`, the issuance PEP, against the realm's issuance
//     policy (with the repository and the PIP), falling back to the BUILT-IN
//     policy where that gives no verdict (rcbj's decision on #304);
//   * `common/issuance_gate.js`, in a process with no XACML family loaded
//     (in-process tests, the parent project's Kerberos jobs), against the
//     built-in policy alone (rcbj's decision on #305) — so the rules hold
//     everywhere and live in one document.
//
// That second caller is why this is a LIBRARY with no route and no store: it
// requires the engine, the request builder and the templates, each a library,
// and nothing that registers a route or fills a slot — the gate loads it
// lazily, from a process that may have loaded nothing else of this family.
// ---------------------------------------------------------------------------

const { log } = require('../common/helpers');
const model = require('./xacml_model');
const pdp = require('./xacml_pdp');
const xacmlRequest = require('./xacml_request');
const templates = require('./xacml_templates');
// The error-code registry, a leaf.
const errorCodes = require('../common/error_codes');

const SCOPE = templates.SCOPE_ATTRIBUTE;
const ATTRIBUTE = templates.ISSUANCE_ATTRIBUTE;

// ---------------------------------------------------------------------------
// The request for one fact. `question`:
//   subject { kind, name }, held (the configured roles it holds), client,
//   grantType, protocol, mode, settings { key: value }, stage,
//   consentRequired (a boolean, or undefined), action (default issue-scope),
//   requested (every value asked for)
// `fact`: { scope, attributes: [{ category, id, values, type }] } — the
// facts the asking subsystem knows, and nothing it does not.
// ---------------------------------------------------------------------------
function requestFor(question, fact) {
  log.debug("Entering requestFor().");
  const q = question || {};
  const subject = q.subject || {};
  const req = new xacmlRequest.AuthorizationRequest({ includeInResult: true })
    .principal(subject.name || '',
               subject.kind === 'application' ? 'application' : 'user')
    .roles(q.held || [])
    .target(fact.scope)
    .requestedAction(q.action || SCOPE.ACTION)
    .requestedScopes(q.requested || []);
  if (q.client) {
    req.client(q.client);
  }
  (fact.attributes || []).forEach(function (one) {
    req.attribute(one.category, one.id, one.values, one.type);
  });
  req.category(model.CATEGORY.ENVIRONMENT);
  if (q.grantType) {
    req.grantType(q.grantType);
  }
  if (q.protocol) {
    req.protocol(q.protocol);
  }
  if (q.mode) {
    req.mode(q.mode);
  }
  if (q.stage) {
    req.stage(q.stage);
  }
  Object.keys(q.settings || {}).forEach(function (key) {
    req.setting(key, q.settings[key]);
  });
  if (typeof q.consentRequired === 'boolean') {
    req.environment(ATTRIBUTE.CONSENT_REQUIRED, [q.consentRequired],
                    model.TYPE.BOOLEAN);
  }
  log.debug("Leaving requestFor().");
  return req.build();
}

// The scope obligation of an answer: `{ verdict, code }`, or null when the
// document said nothing. A verdict outside the known ones is read as `drop`:
// a policy asking for something this PEP does not know how to do must not
// have it read as `keep`.
function verdictOf(answer) {
  log.debug("Entering verdictOf().");
  const found = (answer && answer.obligations || []).filter(function (o) {
    return o && o.id === SCOPE.OBLIGATION;
  })[0];
  if (!found) {
    log.debug("Leaving verdictOf(). None.");
    return null;
  }
  const valueOf = function (id) {
    log.debug("Entering valueOf().");
    const hit = (found.assignments || []).filter(function (a) {
      return a.attributeId === id;
    })[0];
    log.debug("Leaving valueOf().");
    return hit ? String(hit.lexical !== undefined ? hit.lexical : hit.value)
               : '';
  };
  const said = valueOf(SCOPE.VERDICT);
  const verdict = SCOPE.VERDICTS.indexOf(said) >= 0 ? said : 'drop';
  log.debug("Leaving verdictOf(). " + verdict);
  return { verdict: verdict, code: valueOf(SCOPE.CODE) };
}

// The built-in issuance policy's model, or null (a defect: the template takes
// no required parameter).
function builtInPolicy(name) {
  log.debug("Entering builtInPolicy().");
  const built = templates.build('role-issuance', {},
                                { name: String(name || 'role-issuance') });
  log.debug("Leaving builtInPolicy(). " + (built.ok ? 'Built.' : built.why));
  return built.ok ? built.policy : null;
}

// ---------------------------------------------------------------------------
// decide(question, primary, evaluation)
//
// One verdict per fact: `{ scope, verdict, code, decidedBy }`. `primary` is
// `{ policy, builtIn }` — the document to ask first, null for none — and a
// fact it gives no verdict on is asked of the built-in policy. Neither
// answering (a defect) drops a fact marked `gated` and keeps the rest, and
// says so. `evaluation` is the engine's options (repository, resolver).
// ---------------------------------------------------------------------------
function decide(question, primary, evaluation) {
  log.debug("Entering decide().");
  const q = question || {};
  const facts = Array.isArray(q.facts) ? q.facts : [];
  const first = primary && primary.policy ? primary : null;
  let fallback = null;
  const theBuiltIn = function () {
    log.debug("Entering theBuiltIn().");
    if (!fallback) {
      fallback = { policy: builtInPolicy(q.policyName), builtIn: true };
    }
    log.debug("Leaving theBuiltIn().");
    return fallback;
  };
  const ask = function (policy, fact) {
    log.debug("Entering ask(). " + fact.scope);
    const request = requestFor(q, fact);
    const options = typeof evaluation === 'function' ? evaluation(request)
                                                     : (evaluation || {});
    log.debug("Leaving ask().");
    return pdp.evaluate(policy, request, options);
  };
  const out = facts.map(function (fact) {
    let decidedBy = first && !first.builtIn ? 'policy' : 'built-in';
    let found = first ? verdictOf(ask(first.policy, fact)) : null;
    if (!found && (!first || !first.builtIn)) {
      const built = theBuiltIn();
      found = built.policy ? verdictOf(ask(built.policy, fact)) : null;
      decidedBy = 'built-in';
    }
    if (!found) {
      log.warn(errorCodes.tag('STS-XACML-0078') +
               'xacml: no issuance policy, not even the built-in one, gave ' +
               'a verdict on "' + fact.scope + '"; it is ' +
               (fact.gated ? 'DROPPED, because its resource gates it'
                           : 'kept') + '.');
      return { scope: fact.scope, verdict: fact.gated ? 'drop' : 'keep',
               code: fact.gated ? 'STS-ADMIN-0821' : '', decidedBy: 'none' };
    }
    return { scope: fact.scope, verdict: found.verdict, code: found.code,
             decidedBy: decidedBy };
  });
  log.debug("Leaving decide(). " + out.map(function (one) {
    return one.scope + '=' + one.verdict;
  }).join(' '));
  return out;
}

// A boolean fact on the resource (the scope), the shape every subsystem
// hands in.
function resourceFact(id, value) {
  log.debug("Entering resourceFact().");
  log.debug("Leaving resourceFact().");
  return { category: model.CATEGORY.RESOURCE, id: id, values: [!!value],
           type: model.TYPE.BOOLEAN };
}

// A boolean fact on the subject (the client, for the scope policy's two).
function subjectFact(id, value) {
  log.debug("Entering subjectFact().");
  log.debug("Leaving subjectFact().");
  return { category: model.CATEGORY.ACCESS_SUBJECT, id: id, values: [!!value],
           type: model.TYPE.BOOLEAN };
}

// A string-bag fact on the resource.
function resourceStrings(id, values) {
  log.debug("Entering resourceStrings().");
  log.debug("Leaving resourceStrings().");
  return { category: model.CATEGORY.RESOURCE, id: id,
           values: (values || []).map(String), type: model.TYPE.STRING };
}

module.exports = {
  requestFor: requestFor,
  verdictOf: verdictOf,
  builtInPolicy: builtInPolicy,
  decide: decide,
  resourceFact: resourceFact,
  subjectFact: subjectFact,
  resourceStrings: resourceStrings,
  ATTRIBUTE: ATTRIBUTE,
  SCOPE: SCOPE
};
