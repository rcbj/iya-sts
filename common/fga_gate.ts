// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: fga_gate.ts
//
// ---------------------------------------------------------------------------
// APPLICATION-SCOPED FINE-GRAINED AUTHORIZATION AT ISSUANCE (#564, P3): THE
// ONE PLACE AN ISSUANCE SITE ASKS "MAY THIS DETAIL BE GRANTED?", AND THE
// REASON IT IS AN EMPTY SHELL THAT REFUSES.
//
// An RFC 9396 authorization detail whose TYPE belongs to an application that
// enforces fine-grained authorization (`appFgaEnforced`) is granted only when
// that application's own policy says Permit (rcbj's decisions 1 and 5 on
// #564). The authorization endpoint, the PAR endpoint and the token
// endpoint's funnel ask here; this file asks whoever filled the slot below —
// `xacml/fga_pep.ts`, the embedded FGA PEP, which resolves the policy,
// builds the request (`xacml/fga_map.ts`) and evaluates it.
//
// ---------------------------------------------------------------------------
// WHY THIS FILE EXISTS, RATHER THAN `oauth2.ts` CALLING THE PEP. Rule 3e's
// test, and it fails both ways round exactly as it does for
// `issuance_gate.js`, whose header argues it at length:
//
//   * `oauth2.ts` is at 9 and the XACML family at 23c. A require from the
//     authorization server to `xacml/fga_pep.ts` would load the policy store,
//     the templates and the lifecycle there — their `InstanceSlot`s would be
//     reached long before the composition root builds them — and the PEP
//     reaches the XACML surface, whose `xacml_admin.ts` requires the console,
//     which requires `oauth2.ts`: a cycle.
//   * The other direction, the PEP reaching into `oauth2.ts`, would make the
//     PEP know every place a detail is issued.
//
// So this file requires `helpers`, the error-code table and `InstanceSlot`,
// and nothing else: a LEAF, required from `oauth-oidc/authorization_details.ts`
// at any position without dragging anything with it.
//
// ---------------------------------------------------------------------------
// **AN EMPTY SLOT MEANS REFUSE — THE OPPOSITE OF `issuance_gate.js`, AND ON
// PURPOSE.** That gate answers "allowed" with no decider because nobody asked
// for a restriction a process without the XACML family cannot evaluate. Here
// somebody DID: this file is consulted only for a detail whose application
// has `appFgaEnforced` TRUE, which an administrator switched on, against a
// policy they wrote. Issuing that detail undecided would be the restriction
// silently not applying — the one failure an authorization switch must not
// have. So the question is never asked of an application that does not
// enforce (the caller checks `applications.fgaStateOf()` first, which is
// `common/`'s and needs no decider), and an enforcing application's detail
// with no decider is refused as an OPERATIONAL failure (STS-FGA-0016,
// `server_error`), as is a decider that throws or answers nothing
// (STS-FGA-0015). The design's sentence is "a policy that is missing, does
// not parse or throws refuses under its own code. This is unlike the
// issuance gate's 'a throw allows'."
//
// Nothing here differs by mode: FGA does not.
//
// ---------------------------------------------------------------------------
// THE QUESTION AND THE ANSWER. The question carries what the ADAPTER knows —
// the owning application, the validated detail and its `declaredTypes()`
// entry, the stage (one of `xacml_request.js`'s FGA_STAGES), the realm, the
// client, the subject and its kind, the grant — and never anything the detail
// says about itself; `fga_map.ts` turns the detail into attributes. The
// answer is
//
//   { outcome   'permit' | 'deny' | 'failure'
//     code      '' on a permit; the denial's or the failure's STS-FGA code
//     why       a sentence for the log and the error_description
//     policy, policyId, version, decision, digest   what the audit row and a
//               caller's log line want }
//
// `deny` is a DECISION (`invalid_authorization_details` or `access_denied`);
// `failure` is a FAULT (`server_error`). The caller branches on `outcome`.
//
// IT NEVER THROWS AND NEVER RETURNS A PROMISE, for `issuance_gate.js`'s
// reason: it is asked inside code paths that are synchronous today, and an
// authorization check that made them asynchronous would be a change to every
// grant rather than to one file.
// ---------------------------------------------------------------------------

import helpers = require('./helpers');
// The error-code registry. A LEAF that requires nothing here; the two
// failures below are tagged in the log rather than audited, because
// `audit.js` is a heavier require than a leaf gate should carry — and a
// failure with no decider is not a decision anybody made.
import errorCodes = require('./error_codes');
import InstanceSlot = require('./instance_slot');

// One fine-grained question, as an issuance site asks it.
interface FgaQuestion {
  application: string;
  detail: any;
  definition: any;
  stage: string;
  realm?: string;
  clientId?: string;
  subject?: { id?: string; kind?: string };
  grantType?: string;
}

// What the gate answers.
interface FgaAnswer {
  outcome: 'permit' | 'deny' | 'failure';
  code: string;
  why: string;
  policy?: string;
  policyId?: string;
  version?: string;
  decision?: string;
  digest?: string;
  [key: string]: unknown;
}

type FgaDecider = (question: FgaQuestion) => FgaAnswer | null | undefined;

// What the gate needs from the rest of the service.
interface FgaGateDeps {
  log: {
    debug(message: string): void;
    warn(message: string): void;
    error(message: string): void;
  };
  errorCodes: { tag(code: string): string };
}

// The three outcomes a decider may answer.
const OUTCOMES = Object.freeze(['permit', 'deny', 'failure']);

/**
 * The gate every fine-grained authorization question at issuance is asked
 * through. It forwards the question to the decider the XACML family installs
 * (`xacml/fga_pep.ts`); with none installed, every question is a FAILURE —
 * it is only asked for an application that enforces.
 */
class FgaGate {
  static readonly OUTCOMES = OUTCOMES;

  private decider: FgaDecider | null = null;

  /**
   * Builds a gate with no decider installed.
   *
   * @param deps - the logger and the error-code table
   */
  constructor(private readonly deps: FgaGateDeps) {
    deps.log.debug("Entering FgaGate.constructor().");
    deps.log.debug("Leaving FgaGate.constructor().");
  }

  /**
   * Returns the dependencies the default instance is built from.
   *
   * @returns the service logger and the error-code table
   */
  static defaultDeps(): FgaGateDeps {
    helpers.log.debug("Entering FgaGate.defaultDeps().");
    helpers.log.debug("Leaving FgaGate.defaultDeps().");
    return { log: helpers.log, errorCodes: errorCodes };
  }

  /**
   * Installs, replaces or clears the decider. Anything that is neither a
   * function nor null is refused and logged, which leaves the slot as it
   * was.
   *
   * @param fn - the decider, or null to clear it
   * @returns true when installed or cleared, false when refused
   */
  setDecider(fn: FgaDecider | null): boolean {
    const { log, errorCodes } = this.deps;
    log.debug("Entering FgaGate.setDecider().");
    if (typeof fn !== 'function' && fn !== null) {
      log.error(errorCodes.tag('STS-FGA-0016') +
                'fga_gate: setDecider() was given something that is not a ' +
                'function, so it was refused. A detail of an application ' +
                'that enforces fine-grained authorization is refused while ' +
                'no decider is installed.');
      log.debug("Leaving FgaGate.setDecider(). Refused.");
      return false;
    }
    this.decider = fn;
    log.debug("Leaving FgaGate.setDecider(). " +
              (fn ? 'Installed.' : 'Cleared.'));
    return true;
  }

  /**
   * Returns the decider now installed, so a test that replaces it can put
   * back what was there.
   *
   * @returns the decider, or null
   */
  deciderInstalled(): FgaDecider | null {
    const { log } = this.deps;
    log.debug("Entering FgaGate.deciderInstalled().");
    log.debug("Leaving FgaGate.deciderInstalled().");
    return this.decider;
  }

  // A failure answer, logged under its code: never a permit.
  private failure(code: string, why: string): FgaAnswer {
    const { log, errorCodes } = this.deps;
    log.debug("Entering FgaGate.failure(). " + code);
    // error-code: none — tagged with the caller's code, STS-FGA-0015 or 0016
    log.error(errorCodes.tag(code) + 'fga_gate: ' + why);
    log.debug("Leaving FgaGate.failure().");
    return { outcome: 'failure', code: code, why: why };
  }

  /**
   * Asks whether one authorization detail of an application that ENFORCES
   * fine-grained authorization may be granted. Never throws.
   *
   * @param question - the application, the detail, its `declaredTypes()`
   *   entry, the stage, and the realm, client, subject and grant
   * @returns `{ outcome, code, why, … }`: `permit`, `deny` (a decision) or
   *   `failure` (a fault: no decider, STS-FGA-0016; a decider that threw or
   *   answered nothing usable, STS-FGA-0015; or the decider's own failure)
   */
  decide(question: FgaQuestion): FgaAnswer {
    const { log } = this.deps;
    log.debug("Entering FgaGate.decide().");
    const asked: FgaQuestion = question || ({} as FgaQuestion);
    if (!this.decider) {
      log.debug("Leaving FgaGate.decide(). No decider: refused.");
      return this.failure('STS-FGA-0016', 'the application "' +
        String(asked.application || '') + '" enforces fine-grained ' +
        'authorization and no FGA decider is installed in this process, so ' +
        'its authorization details cannot be decided and are refused.');
    }
    let answer: FgaAnswer | null | undefined;
    try {
      answer = this.decider(asked);
    } catch (error) {
      log.debug("Caught in FgaGate.decide(): " +
                ((error && error.message) || error));
      // A THROW IS A FAULT AND REFUSES (the header): unlike the issuance
      // gate, nothing here falls back to allowing.
      log.debug("Leaving FgaGate.decide(). The decider threw.");
      return this.failure('STS-FGA-0015', 'the embedded FGA PEP threw ' +
        'deciding a detail of "' + String(asked.application || '') + '": ' +
        ((error && error.message) || error));
    }
    if (!answer || OUTCOMES.indexOf(String(answer.outcome)) < 0) {
      log.debug("Leaving FgaGate.decide(). No usable answer.");
      return this.failure('STS-FGA-0015', 'the embedded FGA PEP answered ' +
        'no outcome for a detail of "' + String(asked.application || '') +
        '".');
    }
    if (answer.outcome !== 'permit' && !answer.code) {
      // A refusal must say which; one that does not is still a refusal.
      answer = Object.assign({}, answer, {
        code: answer.outcome === 'deny' ? 'STS-FGA-0014' : 'STS-FGA-0015' });
    }
    log.debug("Leaving FgaGate.decide(). " + answer.outcome);
    return answer;
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2), `access_gate.ts`'s
// arrangement: the exports are facades over the installed instance, and a
// process without the root builds a default when this module loads.
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<FgaGate>(
  'common/fga_gate',
  () => new FgaGate(FgaGate.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as every module on the pattern does.
slot.buildNowUnlessDeferred();

/**
 * The fine-grained authorization gate at issuance (#564): one question per
 * authorization detail of an application that enforces FGA, decided by the
 * embedded FGA PEP — and refused when there is none.
 *
 * @namespace
 */
export = {
  FgaGate: FgaGate,
  installInstance: (instance: FgaGate): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  OUTCOMES: OUTCOMES,
  setDecider: slot.forward('setDecider'),
  deciderInstalled: slot.forward('deciderInstalled'),
  decide: slot.forward('decide')
};
