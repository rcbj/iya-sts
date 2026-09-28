// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: xacml_transfer_verdicts.js
//
// ---------------------------------------------------------------------------
// THE TRANSFER QUESTIONS, ASKED ONE WAY (#98 D4, the design's section 6:
// "geofencing is policy, not code").
//
// When the service is deployed as cells, whether a traveller's session may be
// HELD in a cell outside their home jurisdiction (`hold-session`), whether a
// request about them may be SERVED there at all (`serve-request`), and whether
// residents' data may be RELEASED to a reader at another cell
// (`release-attributes`, #98 D11) are decided by the issuance policy: the facts
// — home and serving jurisdiction, the client's country, whether the realm
// lists the transfer, the data category, the realm, and `cells.hardGeofence` —
// go in as attributes, and the answer's transfer obligation is the verdict
// (`xacml_templates.ts`'s TRANSFER_ATTRIBUTE argues the shape).
//
// Two callers ask it and they must ask it identically — the arrangement
// `xacml_scope_verdicts.js` has for the scope question, and for its reasons:
//
//   * `xacml_role_pep.ts`, the issuance PEP, against the realm's issuance
//     policy (with the repository and the PIP), falling back to the BUILT-IN
//     policy where that gives no verdict;
//   * `common/issuance_gate.js`, in a process with no XACML family loaded,
//     against the built-in policy alone — so the strict default holds in
//     every process and lives in one document.
//
// A LIBRARY with no route and no store: it requires the engine, the request
// builder and the templates, each a library, and nothing that registers a
// route or fills a slot.
// ---------------------------------------------------------------------------

const { log } = require('../common/helpers');
const model = require('./xacml_model');
const pdp = require('./xacml_pdp');
const xacmlRequest = require('./xacml_request');
const templates = require('./xacml_templates');
// The error-code registry, a leaf.
const errorCodes = require('../common/error_codes');

const TRANSFER = templates.TRANSFER_ATTRIBUTE;

// ---------------------------------------------------------------------------
// The request for one transfer question. `question`:
//   action          TRANSFER.HOLD_ACTION, SERVE_ACTION or RELEASE_ACTION
//   subject         the subject's `urn:uuid:` (the principal); '' for a
//                   release, which is about a cell's residents
//   home, serving   the two jurisdictions ('' when unknown)
//   clientCountry   the client's country, when known
//   listed          whether the realm lists home>serving
//   hardGeofence    `cells.hardGeofence`, a boolean
//   category        `session`, `request` or `attributes`
//   realm           the realm id
//   purpose         a release's purpose (`directory-list`, `api`)
// ---------------------------------------------------------------------------
function requestFor(question) {
  log.debug("Entering requestFor().");
  const q = question || {};
  const req = new xacmlRequest.AuthorizationRequest({ includeInResult: true })
    .principal(q.subject || '', 'user')
    .target(q.category || '')
    .requestedAction(q.action || '')
    .transfer({ home: q.home, serving: q.serving,
                clientCountry: q.clientCountry, listed: !!q.listed,
                category: q.category, realm: q.realm,
                purpose: q.purpose })
    .setting('cells.hardGeofence', !!q.hardGeofence);
  log.debug("Leaving requestFor().");
  return req.build();
}

// The transfer obligation of an answer: the verdict, or null when the
// document said nothing. A verdict outside the known ones — or one that
// answers ANOTHER question — is read as the strict one for this question
// (`relay`, `refuse`, `withhold`): a policy asking for something this
// reader does not know must not have it read as permission.
function verdictOf(answer, action) {
  log.debug("Entering verdictOf().");
  const found = (answer && answer.obligations || []).filter(function (o) {
    return o && o.id === TRANSFER.OBLIGATION;
  })[0];
  if (!found) {
    log.debug("Leaving verdictOf(). None.");
    return null;
  }
  const hit = (found.assignments || []).filter(function (a) {
    return a.attributeId === TRANSFER.VERDICT;
  })[0];
  const said = hit ? String(hit.lexical !== undefined ? hit.lexical
                                                      : hit.value) : '';
  const fits = FITS[action] || FITS[TRANSFER.HOLD_ACTION];
  const verdict = fits.indexOf(said) >= 0 ? said : fits[1];
  log.debug("Leaving verdictOf(). " + verdict);
  return verdict;
}

// The two verdicts that answer each question, the permissive one first.
const FITS = {};
FITS[TRANSFER.HOLD_ACTION] = ['hold', 'relay'];
FITS[TRANSFER.SERVE_ACTION] = ['serve', 'refuse'];
FITS[TRANSFER.RELEASE_ACTION] = ['release', 'withhold'];

// The built-in issuance policy's model, or null (a defect: the template takes
// no required parameter). KEPT once built, per name: a cell may ask
// `serve-request` on every request it receives, the built-in document
// depends on nothing but its name, and building it is the costly part.
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
// THE BUILT-IN RULE READ FROM THE FACTS — for a DEFECT only, where not even
// the built-in document gave a verdict (the engine could not be loaded, the
// template would not build). It is the same rule as the document's, so a
// broken engine cannot loosen anything: hold and release only in the same
// jurisdiction or a listed transfer; refuse to serve only under a hard
// geofence.
// ---------------------------------------------------------------------------
function strictReading(question) {
  log.debug("Entering strictReading().");
  const q = question || {};
  const same = !!q.home && !!q.serving && q.home === q.serving;
  const permitted = same || !!q.listed;
  let verdict;
  if (q.action === TRANSFER.SERVE_ACTION) {
    verdict = q.hardGeofence && !permitted ? 'refuse' : 'serve';
  } else if (q.action === TRANSFER.RELEASE_ACTION) {
    verdict = permitted ? 'release' : 'withhold';
  } else {
    verdict = permitted ? 'hold' : 'relay';
  }
  log.debug("Leaving strictReading(). " + verdict);
  return verdict;
}

// ---------------------------------------------------------------------------
// decide(question, primary, evaluation)
//
// `{ verdict, decidedBy }`. `primary` is `{ policy, builtIn }` — the document
// to ask first, null for none — and a question it gives no verdict on is
// asked of the built-in policy. Neither answering (a defect) falls to the
// strict reading above and says so (STS-CELL-0180). `evaluation` is the
// engine's options (repository, resolver), or a function of the request
// that returns them.
// ---------------------------------------------------------------------------
function decide(question, primary, evaluation) {
  log.debug("Entering decide().");
  const q = question || {};
  const first = primary && primary.policy ? primary : null;
  const request = requestFor(q);
  const options = typeof evaluation === 'function' ? evaluation(request)
                                                   : (evaluation || {});
  let decidedBy = first && !first.builtIn ? 'policy' : 'built-in';
  let verdict = first ? verdictOf(pdp.evaluate(first.policy, request, options),
                                  q.action) : null;
  if (!verdict && (!first || !first.builtIn)) {
    const built = builtInPolicy(q.policyName);
    verdict = built ? verdictOf(pdp.evaluate(built, request, options),
                                q.action) : null;
    decidedBy = 'built-in';
  }
  if (!verdict) {
    verdict = strictReading(q);
    log.warn(errorCodes.tag('STS-CELL-0180') + 'xacml: no issuance ' +
             'policy, not even the built-in one, gave a verdict on ' +
             q.action + ' for ' + (q.home || '?') + '>' +
             (q.serving || '?') + '; the strict default answered ' +
             verdict + '.');
    decidedBy = 'none';
  }
  log.debug("Leaving decide(). " + q.action + '=' + verdict + ' by ' +
            decidedBy);
  return { verdict: verdict, decidedBy: decidedBy };
}

module.exports = {
  requestFor: requestFor,
  verdictOf: verdictOf,
  builtInPolicy: builtInPolicy,
  strictReading: strictReading,
  decide: decide,
  TRANSFER: TRANSFER,
  CATEGORY: model.CATEGORY
};
