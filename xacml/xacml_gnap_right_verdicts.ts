// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: xacml_gnap_right_verdicts.ts
//
// ---------------------------------------------------------------------------
// THE PER-RIGHT GNAP QUESTION, ASKED ONE WAY (#432 phase 3, 2026-10-03).
//
// Which GNAP access rights are issued — and narrowed, and for how long — is
// decided by the issuance policy, one question per right: action-id
// `issue-gnap-right`, the right's type (or its reference string) as the
// resource-id, the facts `gnap/gnap_rights.ts` gathers in the categories
// `xacml_request.js`'s `gnapRight()` puts them, and the realm's mode, the
// settings a rule reads and the STAGE in the environment. The answer's
// `urn:sts:xacml:obligation:gnap-right` is the verdict (`xacml_templates.ts`'s
// GNAP_RIGHT_ATTRIBUTE argues the shape). It is #304's per-scope question
// (`xacml_scope_verdicts.js`) for the protocol whose request names its
// rights as objects rather than strings, and it is built the same way for the
// same reasons:
//
//   * TWO CALLERS ASK IT AND MUST ASK IT IDENTICALLY — `xacml_role_pep.ts`,
//     against the realm's issuance policy with the repository and the PIP,
//     falling back to the BUILT-IN policy where that gives no verdict; and
//     `common/issuance_gate.js`, in a process with no XACML family loaded,
//     against the built-in policy alone. So the rules hold in every process
//     and live in one document.
//   * A LIBRARY with no route and no store: the engine, the request builder
//     and the templates, each a library, and nothing that registers a route
//     or fills a slot.
//
// **WHAT IT ADDS TO THE SCOPE QUESTION'S SHAPE IS `narrow` AND A LIFETIME.**
// A scope is a word and can only be kept or dropped; an access right has five
// dimensions (RFC 9635 section 8), so a policy may take values off one
// (`DROP_*`) rather than refuse the right, and the catalogue's maximum
// lifetime travels as an obligation the token honours. Several Permit rules
// may each carry the obligation — the built-in lifetime rule and an
// operator's narrowing rule, say — so `verdictOf()` MERGES every obligation
// the answer carries: refuse over narrow over keep, the drops unioned, the
// shortest lifetime. A verdict this reader does not know is read as REFUSE
// (STS-GNAP-0815): a right is not issued on a word nobody can interpret.
// SINCE #432 PHASE 6 the answer also says who must be asked (`interaction`,
// the most demanding stated, '' where none is) and the acr values the
// approving session must meet (`acr`, every one stated) — the obligation's
// two members `xacml_templates.ts` argues; an interaction word nobody knows
// is read as `always`.
//
// **NO VERDICT AT ALL IS A DEFECT, AND IT REFUSES** (STS-XACML-0168, the right
// refused STS-GNAP-0816) — the exchange question's answer, for its reason:
// the built-in document always answers, so reaching here means the engine
// could not run, and a right issued because the engine broke would be
// authority nobody granted.
//
// TYPESCRIPT, AS A UTILITY CLASS OF STATIC METHODS (#50's rule for a small
// stateless helper, `common/html.ts`'s shape): it holds nothing, so there is
// no instance for the composition root to build.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import errorCodes = require('../common/error_codes');
import model = require('./xacml_model');
import pdp = require('./xacml_pdp');
import xacmlRequest = require('./xacml_request');
import templates = require('./xacml_templates');

type Json = any;

const GR = templates.GNAP_RIGHT_ATTRIBUTE;
const log = helpers.log;

// The built-in issuance policy's model, KEPT once built per name — the
// transfer verdicts' reason: every grant asks a question per right, the
// document depends on nothing but its name, and building it is the costly
// part.
const builtInByName: Map<string, Json> = new Map();

/**
 * One GNAP access right's question to the issuance policy (#432 phase 3):
 * the request for it, the verdict out of its answer, and the decision.
 */
class GnapRightVerdicts {
  /** The action-id and the obligation's vocabulary. */
  static readonly GNAP_RIGHT = GR;

  // -------------------------------------------------------------------------
  // The request for one right. `question`:
  //   subject { kind, name }   the principal: the resource owner where one
  //                            is known, else the client as itself
  //   protocol, mode, stage, settings { key: value }
  //   facts                    `xacml_request.js`'s gnapRight() facts for
  //                            THIS right, the resource-id among them as
  //                            `facts.right.id`
  // -------------------------------------------------------------------------
  /**
   * Builds the XACML request for one right.
   *
   * @param question - the common part of every right's question
   * @param facts - this right's facts, as `gnapRight()` takes them
   * @returns the request, in the engine's shape
   */
  static requestFor(question: Json, facts: Json): Json {
    log.debug("Entering GnapRightVerdicts.requestFor().");
    const q = question || {};
    const subject = q.subject || {};
    const right = (facts && facts.right) || {};
    const req = new xacmlRequest.AuthorizationRequest({
      includeInResult: true })
      .principal(subject.name || '',
                 subject.kind === 'application' ? 'application' : 'user')
      .target(String(right.id || ''))
      .requestedAction(GR.ACTION)
      .gnapRight(facts || {});
    req.category(model.CATEGORY.ENVIRONMENT);
    if (q.protocol) {
      req.protocol(q.protocol);
    }
    if (q.mode) {
      req.mode(q.mode);
    }
    if (q.stage) {
      req.stage(q.stage);
    }
    Object.keys(q.settings || {}).forEach(function (key: string): void {
      req.setting(key, q.settings[key]);
    });
    log.debug("Leaving GnapRightVerdicts.requestFor().");
    return req.build();
  }

  // -------------------------------------------------------------------------
  // THE VERDICT OUT OF ONE ANSWER, every gnap-right obligation merged, or
  // null when the document said nothing about the right. `{ verdict, code,
  // drop: { actions, locations, datatypes, privileges }, maxLifetimeS }`.
  // -------------------------------------------------------------------------
  /**
   * Reads the merged GNAP right verdict out of one answer.
   *
   * @param answer - the engine's answer
   * @returns the verdict, or null when no gnap-right obligation was carried
   */
  static verdictOf(answer: Json): Json {
    log.debug("Entering GnapRightVerdicts.verdictOf().");
    const found = ((answer && answer.obligations) || []).filter(
      function (o: Json): boolean {
        return !!o && o.id === GR.OBLIGATION;
      });
    if (!found.length) {
      log.debug("Leaving GnapRightVerdicts.verdictOf(). None.");
      return null;
    }
    const out: Json = { verdict: 'keep', code: '',
                        drop: { actions: [], locations: [], datatypes: [],
                                privileges: [] },
                        maxLifetimeS: null, interaction: '', acr: [] };
    const rank: Record<string, number> = { keep: 0, narrow: 1, refuse: 2 };
    // #432 phase 6: the most demanding interaction any obligation states,
    // and every acr any requires.
    const asking: Record<string, number> = { none: 0, skippable: 1,
                                             always: 2 };
    const DROPS: Record<string, string> = {};
    DROPS[GR.DROP_ACTION] = 'actions';
    DROPS[GR.DROP_LOCATION] = 'locations';
    DROPS[GR.DROP_DATATYPE] = 'datatypes';
    DROPS[GR.DROP_PRIVILEGE] = 'privileges';
    found.forEach(function (obligation: Json): void {
      let verdict = '';
      let code = '';
      (obligation.assignments || []).forEach(function (a: Json): void {
        const value = String(a.lexical !== undefined ? a.lexical : a.value);
        if (a.attributeId === GR.VERDICT) {
          verdict = value;
        } else if (a.attributeId === GR.CODE) {
          code = value;
        } else if (DROPS[a.attributeId]) {
          const into = out.drop[DROPS[a.attributeId]];
          if (into.indexOf(value) < 0) {
            into.push(value);
          }
        } else if (a.attributeId === GR.INTERACTION) {
          // A word this reader does not know asks for the person: never
          // fewer interactions on a value nobody can read.
          const wanted = asking[value] === undefined ? 'always' : value;
          if (!out.interaction ||
              asking[wanted] > asking[out.interaction]) {
            out.interaction = wanted;
          }
        } else if (a.attributeId === GR.REQUIRED_ACR) {
          if (value && out.acr.indexOf(value) < 0) {
            out.acr.push(value);
          }
        } else if (a.attributeId === GR.MAX_LIFETIME) {
          const seconds = Number(value);
          if (Number.isInteger(seconds) && seconds > 0 &&
              (out.maxLifetimeS === null || seconds < out.maxLifetimeS)) {
            out.maxLifetimeS = seconds;
          }
        }
      });
      if (GR.VERDICTS.indexOf(verdict) < 0) {
        // A word this reader does not know is not permission.
        verdict = 'refuse';
        code = code || 'STS-GNAP-0815';
      }
      if (rank[verdict] > rank[out.verdict]) {
        out.verdict = verdict;
        out.code = code;
      } else if (verdict === out.verdict && !out.code && code) {
        out.code = code;
      }
    });
    const dropped = out.drop.actions.length + out.drop.locations.length +
      out.drop.datatypes.length + out.drop.privileges.length;
    if (out.verdict === 'keep' && dropped) {
      out.verdict = 'narrow';
    }
    log.debug("Leaving GnapRightVerdicts.verdictOf(). " + out.verdict);
    return out;
  }

  /**
   * Returns the built-in issuance policy's model, kept once built.
   *
   * @param name - the policy name the built-in document is given
   * @returns the policy, or null (a defect: the template takes no required
   *   parameter)
   */
  static builtInPolicy(name: unknown): Json {
    log.debug("Entering GnapRightVerdicts.builtInPolicy().");
    const key = String(name || 'role-issuance');
    if (builtInByName.has(key)) {
      log.debug("Leaving GnapRightVerdicts.builtInPolicy(). Kept.");
      return builtInByName.get(key);
    }
    const built = templates.build('role-issuance', {}, { name: key });
    if (built.ok) {
      builtInByName.set(key, built.policy);
    }
    log.debug("Leaving GnapRightVerdicts.builtInPolicy(). " +
              (built.ok ? 'Built.' : built.why));
    return built.ok ? built.policy : null;
  }

  // -------------------------------------------------------------------------
  // decide(question, primary, evaluation)
  //
  // One verdict per right in `question.rights` (each `xacml_request.js`'s
  // gnapRight() facts): `{ id, verdict, code, drop, maxLifetimeS, decidedBy
  // }`. `primary` is `{ policy, builtIn }` — the document to ask first, null
  // for none — and a right it gives no verdict on is asked of the built-in
  // policy. Neither answering is a defect, and REFUSES (the header).
  // `evaluation` is the engine's options, or a function of the request that
  // returns them.
  // -------------------------------------------------------------------------
  /**
   * Decides every right of one question, the realm's policy first and the
   * built-in one where it says nothing.
   *
   * @param question - `{ subject, protocol, mode, stage, settings, rights,
   *   policyName }`
   * @param primary - `{ policy, builtIn }`, or null
   * @param evaluation - the engine's options, or a function of the request
   * @returns one verdict per right
   */
  static decide(question: Json, primary: Json, evaluation: Json): Json[] {
    log.debug("Entering GnapRightVerdicts.decide().");
    const q = question || {};
    const rights: Json[] = Array.isArray(q.rights) ? q.rights : [];
    const first = primary && primary.policy ? primary : null;
    const ask = function (policy: Json, facts: Json): Json {
      log.debug("Entering ask().");
      const request = GnapRightVerdicts.requestFor(q, facts);
      const options = typeof evaluation === 'function' ? evaluation(request)
                                                       : (evaluation || {});
      log.debug("Leaving ask().");
      return pdp.evaluate(policy, request, options);
    };
    const out = rights.map(function (facts: Json): Json {
      const id = String((facts && facts.right && facts.right.id) || '');
      let decidedBy = first && !first.builtIn ? 'policy' : 'built-in';
      let found = first ? GnapRightVerdicts.verdictOf(ask(first.policy, facts))
                        : null;
      if (!found && (!first || !first.builtIn)) {
        const built = GnapRightVerdicts.builtInPolicy(q.policyName);
        found = built ? GnapRightVerdicts.verdictOf(ask(built, facts)) : null;
        decidedBy = 'built-in';
      }
      if (!found) {
        log.warn(errorCodes.tag('STS-XACML-0168') + 'xacml: no issuance ' +
                 'policy, not even the built-in one, gave a verdict on the ' +
                 'GNAP access right "' + id + '"; it is REFUSED.');
        return { id: id, verdict: 'refuse', code: 'STS-GNAP-0816',
                 drop: { actions: [], locations: [], datatypes: [],
                         privileges: [] },
                 maxLifetimeS: null, interaction: '', acr: [],
                 decidedBy: 'none' };
      }
      return Object.assign({ id: id, decidedBy: decidedBy }, found);
    });
    log.debug("Leaving GnapRightVerdicts.decide(). " +
              out.map(function (one: Json): string {
                return one.id + '=' + one.verdict;
              }).join(' '));
    return out;
  }
}

/**
 * The per-right GNAP question (#432 phase 3), asked one way by the issuance
 * PEP and by the issuance gate.
 *
 * @namespace
 */
export = {
  GnapRightVerdicts: GnapRightVerdicts,
  GNAP_RIGHT: GnapRightVerdicts.GNAP_RIGHT,
  requestFor: GnapRightVerdicts.requestFor,
  verdictOf: GnapRightVerdicts.verdictOf,
  builtInPolicy: GnapRightVerdicts.builtInPolicy,
  decide: GnapRightVerdicts.decide
};
