// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: xacml_exchange_verdicts.js
//
// ---------------------------------------------------------------------------
// WHO MAY ACT FOR WHOM, ASKED ONE WAY (#186).
//
// An RFC 8693 token exchange, a WS-Trust OnBehalfOf / ActAs and a Kerberos
// S4U request all ask the issuance policy the same two questions, with the
// facts `common/delegation_policy.ts` gathers (`xacml_request.js`'s
// `exchange()` spells them):
//
//   * `choose-exchange-semantics` — delegation or impersonation, by the
//     precedence the policy states (the request, the actor's default, the
//     subject's, the realm's);
//   * `exchange-token` — whether the act is allowed with those semantics,
//     and what to issue: the answer's exchange obligation carries the
//     verdict, the refusal kind, whether a refusal is enforced, the
//     semantics and the audience (`xacml_templates.ts`'s EXCHANGE_ATTRIBUTE).
//
// Two callers ask and must ask identically — `xacml_transfer_verdicts.js`'s
// arrangement, and for its reasons: `xacml_role_pep.ts` against the realm's
// issuance policy, falling back to the BUILT-IN policy where that gives no
// verdict; `common/issuance_gate.js`, in a process with no XACML family
// loaded, against the built-in policy alone. Where not even the built-in
// policy answers — a defect — the exchange is REFUSED (STS-XACML-0085): a
// broken engine must not become permission to act for somebody.
//
// A LIBRARY with no route and no store.
// ---------------------------------------------------------------------------

const { log } = require('../common/helpers');
const pdp = require('./xacml_pdp');
const xacmlRequest = require('./xacml_request');
const templates = require('./xacml_templates');
const errorCodes = require('../common/error_codes');

const EX = templates.EXCHANGE_ATTRIBUTE;

// ---------------------------------------------------------------------------
// The request for one question. `question`: `{ action, facts, mode,
// protocol, realm, settings: { defaultSemantics, actorRole } }`, `facts` as
// `xacml_request.js`'s `exchange()` takes them.
// ---------------------------------------------------------------------------
function requestFor(question) {
  log.debug("Entering requestFor().");
  const q = question || {};
  const settings = q.settings || {};
  const req = new xacmlRequest.AuthorizationRequest({ includeInResult: true })
    .requestedAction(q.action || EX.EXCHANGE_ACTION)
    .exchange(q.facts || {})
    .mode(q.mode || '')
    .protocol(q.protocol || '')
    .setting('delegation.defaultSemantics',
             String(settings.defaultSemantics || ''))
    .setting('delegation.actorRole', String(settings.actorRole || ''));
  if (q.realm) {
    req.environment(xacmlRequest.VOCABULARY.REALM, [String(q.realm)]);
  }
  log.debug("Leaving requestFor().");
  return req.build();
}

// The values of one assignment of one obligation of an answer.
function assigned(answer, obligationId, attributeId) {
  log.debug("Entering assigned().");
  const found = (answer && answer.obligations || []).filter(function (o) {
    return o && o.id === obligationId;
  });
  const out = [];
  found.forEach(function (o) {
    (o.assignments || []).forEach(function (a) {
      if (a.attributeId === attributeId) {
        out.push(String(a.lexical !== undefined ? a.lexical : a.value));
      }
    });
  });
  log.debug("Leaving assigned(). " + out.length);
  return out;
}

// The chosen semantics of a choose answer, or '' when the document said
// nothing, or something that is not one of the two.
function chosenOf(answer) {
  log.debug("Entering chosenOf().");
  const said = assigned(answer, EX.CHOOSE_OBLIGATION, EX.CHOSEN)[0] || '';
  const out = EX.SEMANTICS_VALUES.indexOf(said) >= 0 ? said : '';
  log.debug("Leaving chosenOf(). " + (out || 'None.'));
  return out;
}

// The verdict of an exchange answer: `{ verdict, refusal, enforced,
// semantics, audience }`, or null when the document carried no exchange
// obligation. A verdict outside the two is read as a refusal.
function verdictOf(answer) {
  log.debug("Entering verdictOf().");
  const verdicts = assigned(answer, EX.OBLIGATION, EX.VERDICT);
  if (!verdicts.length) {
    log.debug("Leaving verdictOf(). None.");
    return null;
  }
  // A Deny carries one refusal; a Permit one allow. Should a document say
  // both, the refusal wins.
  const refused = verdicts.indexOf('allow') < 0 || verdicts.indexOf('refuse') >= 0;
  const out = {
    verdict: refused ? 'refuse' : 'allow',
    refusal: assigned(answer, EX.OBLIGATION, EX.REFUSAL)[0] || '',
    enforced: assigned(answer, EX.OBLIGATION, EX.ENFORCED)
      .indexOf('true') >= 0,
    semantics: assigned(answer, EX.OBLIGATION, EX.ISSUED_SEMANTICS)[0] || '',
    audience: assigned(answer, EX.OBLIGATION, EX.AUDIENCE)[0] || ''
  };
  if (refused && !out.refusal) {
    out.refusal = 'policy';
  }
  log.debug("Leaving verdictOf(). " + out.verdict + ' ' + out.refusal);
  return out;
}

// The built-in issuance policy's model, kept per name — the transfer
// library's reason: building it is the costly part, and it depends on
// nothing but its name.
const builtInByName = new Map();

function builtInPolicy(name) {
  log.debug("Entering builtInPolicy().");
  const key = String(name || 'role-issuance');
  if (builtInByName.has(key)) {
    log.debug("Leaving builtInPolicy(). Kept.");
    return builtInByName.get(key);
  }
  const built = templates.build('role-issuance', {}, { name: key });
  if (built.ok) {
    builtInByName.set(key, built.policy);
  }
  log.debug("Leaving builtInPolicy(). " + (built.ok ? 'Built.' : built.why));
  return built.ok ? built.policy : null;
}

// The parties a may_act answer names: `{ parties }` when the answer carries
// the may_act obligation — EMPTY when it assigns nobody, which is how a
// policy takes the claim away — or null when it does not, and has said
// nothing. A bare Deny is NOT "none": a rule written for every action (a risk
// or device refusal) must not silently drop a restriction the subject chose.
function mayActOf(answer) {
  log.debug("Entering mayActOf().");
  const carried = (answer && answer.obligations || []).some(function (o) {
    return o && o.id === EX.MAY_ACT_OBLIGATION;
  });
  if (!carried) {
    log.debug("Leaving mayActOf(). Nothing said.");
    return null;
  }
  const parties = assigned(answer, EX.MAY_ACT_OBLIGATION, EX.MAY_ACT_PARTY)
    .filter(function (one) { return !!one; });
  log.debug("Leaving mayActOf(). " + parties.length);
  return { parties: parties };
}

// One question, asked of `primary` first and the built-in policy where it
// gives no answer `read` accepts. Answers `{ found, decidedBy }`.
function ask(question, primary, evaluation, read) {
  log.debug("Entering ask().");
  const first = primary && primary.policy ? primary : null;
  const request = requestFor(question);
  const options = typeof evaluation === 'function' ? evaluation(request)
                                                   : (evaluation || {});
  let decidedBy = first && !first.builtIn ? 'policy' : 'built-in';
  let found = first ? read(pdp.evaluate(first.policy, request, options))
                    : null;
  if (!found && (!first || !first.builtIn)) {
    const built = builtInPolicy(question.policyName);
    found = built ? read(pdp.evaluate(built, request, options)) : null;
    decidedBy = 'built-in';
  }
  log.debug("Leaving ask(). " + (found ? 'Answered by ' + decidedBy
                                       : 'No answer.'));
  return { found: found, decidedBy: found ? decidedBy : 'none' };
}

// ---------------------------------------------------------------------------
// decide(question, primary, evaluation)
//
// Asks both questions. `question`: `{ facts, mode, protocol, realm,
// settings, policyName }`. Answers `{ verdict, refusal, enforced, semantics,
// chosen, audience, decidedBy }` — `chosen` is what the choosing question
// settled on, `semantics` what the exchange answer says to issue (`self`
// for a self exchange). Neither policy answering refuses, enforced
// (STS-XACML-0085).
// ---------------------------------------------------------------------------
function decide(question, primary, evaluation) {
  log.debug("Entering decide().");
  const q = question || {};
  if (q.action === EX.MAY_ACT_ACTION) {
    log.debug("Leaving decide(). The may_act question.");
    return decideMayAct(q, primary, evaluation);
  }
  const choice = ask(Object.assign({}, q, { action: EX.CHOOSE_ACTION }),
                     primary, evaluation, function (answer) {
    return chosenOf(answer) || null;
  });
  const chosen = choice.found || '';
  const facts = Object.assign({}, q.facts || {}, { semantics: chosen });
  const exchange = ask(Object.assign({}, q, { action: EX.EXCHANGE_ACTION,
                                              facts: facts }),
                       primary, evaluation, verdictOf);
  if (!exchange.found) {
    log.error(errorCodes.tag('STS-XACML-0085') + 'xacml: no issuance ' +
              'policy, not even the built-in one, gave a verdict on an ' +
              'exchange by "' + String((q.facts && q.facts.actor &&
                                        q.facts.actor.id) || '') +
              '"; it is refused.');
    log.debug("Leaving decide(). No verdict.");
    return { verdict: 'refuse', refusal: 'policy', enforced: true,
             semantics: '', chosen: chosen, audience: '', decidedBy: 'none' };
  }
  const out = Object.assign({ chosen: chosen,
                              decidedBy: exchange.decidedBy },
                            exchange.found);
  log.debug("Leaving decide(). " + out.verdict + ' ' +
            (out.refusal || out.semantics) + ' by ' + out.decidedBy);
  return out;
}

// ---------------------------------------------------------------------------
// decideMayAct(question, primary, evaluation)
//
// The third question: which parties RFC 8693 section 4.4's `may_act` on a
// token about the subject names. `question.facts.subject.delegates` is what
// the subject chose. Answers `{ verdict: 'allow', mayAct: [parties],
// decidedBy }`. Where neither policy answers although the subject chose
// somebody — a defect — the subject's own choice stands (STS-XACML-0087):
// `may_act` RESTRICTS who may act, so dropping it would widen what the
// subject allowed.
// ---------------------------------------------------------------------------
function decideMayAct(question, primary, evaluation) {
  log.debug("Entering decideMayAct().");
  const q = question || {};
  const declared = ((q.facts && q.facts.subject &&
                     q.facts.subject.delegates) || []).map(String);
  const answer = ask(q, primary, evaluation, mayActOf);
  if (!answer.found) {
    if (declared.length) {
      log.error(errorCodes.tag('STS-XACML-0087') + 'xacml: no issuance ' +
                'policy, not even the built-in one, answered the may_act ' +
                'question for "' + String(q.facts.subject.id || '') +
                '"; their own choice stands.');
    }
    log.debug("Leaving decideMayAct(). No answer.");
    return { verdict: 'allow', mayAct: declared, decidedBy: 'none' };
  }
  log.debug("Leaving decideMayAct(). " + answer.found.parties.length +
            " by " + answer.decidedBy);
  return { verdict: 'allow', mayAct: answer.found.parties,
           decidedBy: answer.decidedBy };
}

module.exports = {
  requestFor: requestFor,
  mayActOf: mayActOf,
  chosenOf: chosenOf,
  verdictOf: verdictOf,
  builtInPolicy: builtInPolicy,
  decide: decide,
  EXCHANGE: EX
};
