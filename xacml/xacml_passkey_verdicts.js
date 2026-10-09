// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: xacml_passkey_verdicts.js
//
// ---------------------------------------------------------------------------
// THE PASSKEY QUESTIONS, ASKED ONE WAY (#536).
//
// Whether a passkey may be REGISTERED (`register-passkey`) or may SIGN
// SOMEBODY IN (`use-passkey`) is decided by the issuance policy: the facts —
// the key's BE flag, its reported minimum PIN length, its device serial and
// whether the person holds it, its recorded attestation and what the FIDO
// Metadata Service says of its model now — and the selected passkey policy's
// rows go in as attributes, and the answer's passkey obligation is the
// verdict, the error code and the reason (`xacml_templates.ts`'s
// PASSKEY_ATTRIBUTE argues the shape).
//
// Two callers ask it and they must ask it identically — the arrangement
// `xacml_transfer_verdicts.js` has, and for its reasons:
//
//   * `xacml_role_pep.ts`, the issuance PEP, against the realm's issuance
//     policy (with the repository and the PIP), falling back to the BUILT-IN
//     policy where that gives no verdict;
//   * `common/issuance_gate.js`, in a process with no XACML family loaded,
//     against the built-in policy alone.
//
// A LIBRARY with no route and no store.
// ---------------------------------------------------------------------------

const { log } = require('../common/helpers');
const pdp = require('./xacml_pdp');
const xacmlRequest = require('./xacml_request');
const templates = require('./xacml_templates');
// The error-code registry, a leaf.
const errorCodes = require('../common/error_codes');
// The rules read from the facts, for a defect only (a leaf).
const passkeyRules = require('../common/passkey_rules');

const PASSKEY = templates.PASSKEY_ATTRIBUTE;

// ---------------------------------------------------------------------------
// The request for one passkey question — `issuance_gate.checkPasskey()`'s
// shape: `{ action, subject, groups, backupEligible, minPinLength, serial,
// serialHeld, attestation, policy, settings }`.
// ---------------------------------------------------------------------------
function requestFor(question) {
  log.debug("Entering requestFor().");
  const q = question || {};
  const req = new xacmlRequest.AuthorizationRequest({ includeInResult: true })
    .principal(q.subject || '', 'user')
    .target('passkey')
    .requestedAction(q.action || '')
    .passkey(q);
  if (q.realm) {
    req.environment(xacmlRequest.VOCABULARY.REALM, [String(q.realm)]);
  }
  log.debug("Leaving requestFor().");
  return req.build();
}

// The passkey obligation of an answer: `{ verdict, code, reason }`, or null
// when the document said nothing. A verdict outside `allow` / `refuse` is
// read as `refuse` — a policy asking for something this reader does not know
// must not have it read as permission. A refusal that names no code records
// the reason's own, or STS-AUTHN-0322 for a reason the built-in rules do not
// give (a realm's own rule).
function verdictOf(answer, action) {
  log.debug("Entering verdictOf().");
  const found = (answer && answer.obligations || []).filter(function (o) {
    return o && o.id === PASSKEY.OBLIGATION;
  })[0];
  if (!found) {
    log.debug("Leaving verdictOf(). None.");
    return null;
  }
  const said = function (id) {
    log.debug("Entering said().");
    const hit = (found.assignments || []).filter(function (a) {
      return a.attributeId === id;
    })[0];
    log.debug("Leaving said().");
    return hit ? String(hit.lexical !== undefined ? hit.lexical : hit.value)
               : '';
  };
  const verdict = PASSKEY.VERDICTS.indexOf(said(PASSKEY.VERDICT)) >= 0
    ? said(PASSKEY.VERDICT) : 'refuse';
  const reason = verdict === 'refuse' ? said(PASSKEY.REASON) : '';
  const code = verdict === 'refuse'
    ? (said(PASSKEY.CODE) || passkeyRules.codeFor(reason, action) ||
       'STS-AUTHN-0322')
    : '';
  log.debug("Leaving verdictOf(). " + verdict + (code ? ' ' + code : ''));
  return { verdict: verdict, code: code, reason: reason };
}

// The built-in issuance policy's model, or null (a defect). KEPT once built,
// per name: every passkey sign-in asks, and building it is the costly part.
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

// ---------------------------------------------------------------------------
// decide(question, primary, evaluation)
//
// `{ verdict, code, reason, decidedBy }`. `primary` is `{ policy, builtIn }`
// — the document to ask first, null for none — and a question it gives no
// verdict on is asked of the built-in policy. Neither answering (a defect)
// falls to the rules read from the facts and says so (STS-AUTHN-0323).
// `evaluation` is the engine's options, or a function of the request that
// returns them.
// ---------------------------------------------------------------------------
function decide(question, primary, evaluation) {
  log.debug("Entering decide().");
  const q = question || {};
  const first = primary && primary.policy ? primary : null;
  const request = requestFor(q);
  const options = typeof evaluation === 'function' ? evaluation(request)
                                                   : (evaluation || {});
  let decidedBy = first && !first.builtIn ? 'policy' : 'built-in';
  let found = first ? verdictOf(pdp.evaluate(first.policy, request, options),
                                q.action) : null;
  if (!found && (!first || !first.builtIn)) {
    const built = builtInPolicy(q.policyName);
    found = built ? verdictOf(pdp.evaluate(built, request, options),
                              q.action) : null;
    decidedBy = 'built-in';
  }
  if (!found) {
    found = passkeyRules.strictReading(q);
    log.warn(errorCodes.tag('STS-AUTHN-0323') + 'xacml: no issuance ' +
             'policy, not even the built-in one, gave a verdict on ' +
             q.action + '; the passkey rules read from the facts answered ' +
             found.verdict + '.');
    decidedBy = 'none';
  }
  log.debug("Leaving decide(). " + q.action + '=' + found.verdict + ' by ' +
            decidedBy);
  return { verdict: found.verdict, code: found.code, reason: found.reason,
           decidedBy: decidedBy };
}

module.exports = {
  requestFor: requestFor,
  verdictOf: verdictOf,
  builtInPolicy: builtInPolicy,
  decide: decide,
  PASSKEY: PASSKEY
};
