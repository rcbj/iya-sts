// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: did_claim.ts
//
// ===========================================================================
// THE `did` CLAIM: A PERSON'S PREFERRED DID, RELEASED TO A CLIENT THEY
// CONSENTED TO (#693, phase 2, 2026-10-20).
//
// A person proves a DID with their wallet on `/portal/self-issued` (SIOPv2,
// `oid4vc/siop.ts`) and may mark one as PREFERRED. This file decides whether
// an ID Token or a UserInfo response carries it, as the claim `did`, and it
// is the ONLY place that decides: `oauth2.ts` calls `apply()` last on each
// of the two, and nothing else writes the name.
//
// **THE NAMES.** The claim is `did` and the scope that asks for it is `did`.
// Neither is in IANA's JSON Web Token Claims registry or among OpenID
// Connect's scope values (Core section 5.4, and the registrations since), so
// neither redefines a name a relying party already reads; `did` is what a
// reader would guess, and a URI would buy nothing a private claim needs.
//
// **EVERY CONDITION, AND THE CLAIM IS SIMPLY ABSENT WHEN ONE FAILS** — never
// an error, which would tell a client something about the person it was not
// given (OIDC Core 5.5.1: a claim the OP will not release is left out):
//
//   1. `oauth2.didClaim` is on in the realm (off by default);
//   2. the token's scope holds `did` — the request asked for it and it was
//      granted;
//   3. the client DECLARES `did` on `oauthAllowedScope`, in BOTH modes
//      (`scopePolicy.declares()`). Development grants an undeclared scope
//      to a client under test (`mode.grantsUndeclaredScopes()`), and that is
//      not enough here: the scope is in no default set, and a DID is a
//      stable identifier, so only a client an administrator meant to have it
//      gets it (STS-OAUTH-0972);
//   4. the client's subject type is public — a PAIRWISE or EPHEMERAL client
//      (OIDC Core section 8, #149) exists so that it cannot correlate the
//      person with any other client, and one value told to every client
//      defeats that — unless its entry opts in with
//      `oauthDidClaimWithPairwise` TRUE (STS-OAUTH-0974);
//   5. the account is not disabled (STS-OAUTH-0976);
//   6. the PERSON consented to `did` for this client THEMSELVES: a consent
//      record of their own on their entry (`common/consent.ts`). An
//      administrator's global consent (`oauthGlobalConsent`) does not count,
//      and neither does consent turned off (`oauth2.consentRequired`): the
//      screen lists `did` as releasing their DID, and only an answer to it
//      releases one (STS-OAUTH-0973);
//   7. the person has a PREFERRED DID that they PROVED
//      (`siop.preferredSubjectOf()`: `proof: 'wallet'`, never an
//      administrator's by-value entry, and a DID rather than a JWK
//      thumbprint) (STS-OAUTH-0975).
//
// **NOTHING ELSE MAY CARRY THE NAME.** A configured or typed claim called
// `did`, one a client named in OIDC Core 5.5's claims request, or one a
// Claims Provider would aggregate, is REMOVED before the decision is
// applied (STS-OAUTH-0977), so the claims request is not a way round the
// scope, the consent or the pairwise rule.
//
// **SAML IS LEFT OUT, DELIBERATELY.** An assertion's attributes have no
// per-attribute consent: nothing a person answers stands between a service
// provider's configuration and what it is sent, so condition 6 could not
// hold, and a DID released without it would be the one thing this claim
// exists not to do.
//
// **WHAT AN OMISSION RECORDS.** Its code, at the front of an info line —
// at most once per client and reason in `LOG_EVERY_MS`, because UserInfo
// may be polled and the same misconfiguration would otherwise write a line
// per call. The cap on the remembered keys is checked at the insert; no
// timer is started.
//
// A LIBRARY (rule 3): it registers nothing. `siop.ts` is reached LAZILY, at
// the decision, so requiring this from `oauth2.ts` moves nothing of the
// OpenID4VC family forward.
// ===========================================================================

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');
import errorCodes = require('../common/error_codes');
import applications = require('../common/applications');
import scopePolicy = require('../common/scope_policy');
import consent = require('../common/consent');
import accountState = require('../common/account_state');

// A loose JSON-shaped value: a token's claims, a decision.
type Json = any;

/**
 * The claim's name.
 */
const CLAIM = 'did';

/**
 * The scope that asks for it.
 */
const SCOPE = 'did';

/**
 * The application attribute that lets a pairwise or ephemeral client be
 * told it.
 */
const PAIRWISE_ATTRIBUTE = 'oauthDidClaimWithPairwise';

// How often one omission is logged for one client and reason, and how many
// such keys are remembered (the cap is checked at the insert).
const LOG_EVERY_MS = 10 * 60 * 1000;
const LOG_KEYS_MAX = 1000;

interface DidClaimDeps {
  log: typeof helpers.log;
  config: typeof config;
  errorCodes: typeof errorCodes;
  applications: typeof applications;
  scopePolicy: typeof scopePolicy;
  consent: typeof consent;
  accountState: typeof accountState;
  preferredSubjectOf: (username: string) => Json;
  nowMs: () => number;
}

// What a caller says about the token being built.
interface DidClaimInput {
  username: unknown;
  clientId: unknown;
  scope: unknown;
}

// What `decide()` answers: the DID, or why not (`code` '' for the two
// obvious reasons — the setting off, the scope not granted).
interface DidClaimDecision {
  did: string;
  code: string;
  why: string;
}

/**
 * The `did` claim (#693): a person's preferred, proved DID, released in an
 * ID Token or a UserInfo response only when every condition holds.
 */
class DidClaim {
  /** The claim's name. */
  static readonly CLAIM = CLAIM;
  /** The scope that asks for it. */
  static readonly SCOPE = SCOPE;
  /** The attribute a pairwise or ephemeral client opts in with. */
  static readonly PAIRWISE_ATTRIBUTE = PAIRWISE_ATTRIBUTE;

  // When each (client, code) omission was last logged.
  private readonly logged = new Map<string, number>();

  /**
   * Builds the decision over the modules it reads.
   *
   * @param deps - the modules the composition root passes
   */
  constructor(private readonly deps: DidClaimDeps) {
    deps.log.debug("Entering DidClaim.constructor().");
    deps.log.debug("Leaving DidClaim.constructor().");
  }

  /**
   * Returns the dependencies built from the real modules, with the SIOPv2
   * library reached lazily.
   *
   * @returns the default dependencies
   */
  static defaultDeps(): DidClaimDeps {
    helpers.log.debug("Entering DidClaim.defaultDeps().");
    helpers.log.debug("Leaving DidClaim.defaultDeps().");
    return {
      log: helpers.log,
      config: config,
      errorCodes: errorCodes,
      applications: applications,
      scopePolicy: scopePolicy,
      consent: consent,
      accountState: accountState,
      preferredSubjectOf: function (username: string): Json {
        helpers.log.debug("Entering preferredSubjectOf().");
        const siop = require('../oid4vc/siop');
        helpers.log.debug("Leaving preferredSubjectOf().");
        return siop.preferredSubjectOf(username);
      },
      nowMs: function (): number {
        helpers.log.debug("Entering nowMs().");
        helpers.log.debug("Leaving nowMs().");
        return Date.now();
      }
    };
  }

  /**
   * Says whether the realm releases the claim at all (`oauth2.didClaim`).
   *
   * @returns true when it is on
   */
  enabled(): boolean {
    const { log, config } = this.deps;
    log.debug("Entering DidClaim.enabled().");
    const on = config.value('oauth2.didClaim') === true;
    log.debug("Leaving DidClaim.enabled(). " + on);
    return on;
  }

  /**
   * Decides whether a token for this person and client carries the claim,
   * and why not when it does not.
   *
   * @param input - `{ username, clientId, scope }`: the scope as granted
   * @returns `{ did, code, why }`; `did` is '' when the claim is left out
   */
  decide(input: DidClaimInput): DidClaimDecision {
    const { log } = this.deps;
    log.debug("Entering DidClaim.decide().");
    const out = this.firstProblem(input);
    log.debug("Leaving DidClaim.decide(). " + (out.code || out.why));
    return out;
  }

  // The conditions of the header, in its order; the first that fails is the
  // answer.
  private firstProblem(input: DidClaimInput): DidClaimDecision {
    const { log, applications, scopePolicy, consent, accountState,
            preferredSubjectOf } = this.deps;
    log.debug("Entering DidClaim.firstProblem().");
    const username = String((input && input.username) || '').trim();
    const clientId = String((input && input.clientId) || '').trim();
    const scopes = String((input && input.scope) || '').split(/\s+/);
    let out: DidClaimDecision = { did: '', code: '', why: '' };
    if (!this.enabled()) {
      out.why = 'oauth2.didClaim is off';
    } else if (scopes.indexOf(SCOPE) < 0 || !username || !clientId) {
      out.why = 'the did scope was not granted';
    } else if (!scopePolicy.declares(clientId, SCOPE)) {
      out = { did: '', code: 'STS-OAUTH-0972', why: 'the client does not ' +
              'declare the did scope on oauthAllowedScope' };
    } else {
      const subjectType = String(applications.clientConfigOf(clientId)
        .subject_type || 'public');
      if (subjectType !== 'public' &&
          !applications.didClaimWithPairwiseOf(clientId)) {
        out = { did: '', code: 'STS-OAUTH-0974', why: 'the client uses ' +
                subjectType + ' subject identifiers and does not set ' +
                PAIRWISE_ATTRIBUTE + ' TRUE' };
      } else if (accountState.isDisabled(username)) {
        out = { did: '', code: 'STS-OAUTH-0976',
                why: 'the account is disabled' };
      } else if (!consent.consentsOf(username).some(function (one: Json) {
        return one.client === clientId && one.scope === SCOPE;
      })) {
        out = { did: '', code: 'STS-OAUTH-0973', why: 'the person has not ' +
                'consented to the did scope for this client themselves' };
      } else {
        const preferred = preferredSubjectOf(username);
        out = preferred && preferred.subject
          ? { did: String(preferred.subject), code: '', why: 'released' }
          : { did: '', code: 'STS-OAUTH-0975', why: 'the person has no ' +
              'preferred DID they proved' };
      }
    }
    log.debug("Leaving DidClaim.firstProblem(). " + (out.code || out.why));
    return out;
  }

  /**
   * Applies the decision to a token being built: removes a `did` any other
   * layer put there, then sets the claim when every condition holds.
   *
   * @param target - the ID Token's payload or the UserInfo body, changed in
   *   place
   * @param input - `{ username, clientId, scope }`
   * @param where - `ID Token` or `UserInfo response`, for the log
   * @returns the decision
   */
  apply(target: Json, input: DidClaimInput, where: string): DidClaimDecision {
    const { log } = this.deps;
    log.debug("Entering DidClaim.apply(). " + where);
    const clientId = String((input && input.clientId) || '');
    const names = target && target._claim_names;
    if (target && (target[CLAIM] !== undefined ||
                   (names && names[CLAIM] !== undefined))) {
      delete target[CLAIM];
      if (names) {
        delete names[CLAIM];
      }
      this.note('STS-OAUTH-0977', clientId, where + ': a claim named did ' +
                'from another layer was removed; the name is released only ' +
                'as the DID claim.');
    }
    const decision = this.decide(input);
    if (decision.did) {
      target[CLAIM] = decision.did;
    } else if (decision.code) {
      this.note(decision.code, clientId, where + ': the did claim was left ' +
                'out for client "' + clientId + '": ' + decision.why + '.');
    }
    log.debug("Leaving DidClaim.apply(). " +
              (decision.did ? 'Released.' : decision.why));
    return decision;
  }

  // One omission's line, at most once per client and code in LOG_EVERY_MS.
  private note(code: string, clientId: string, message: string): void {
    const { log, errorCodes, nowMs } = this.deps;
    log.debug("Entering DidClaim.note(). " + code);
    const key = code + ' ' + clientId;
    const now = nowMs();
    const last = this.logged.get(key);
    if (last !== undefined && now - last < LOG_EVERY_MS) {
      log.debug("Leaving DidClaim.note(). Logged recently.");
      return;
    }
    if (last === undefined && this.logged.size >= LOG_KEYS_MAX) {
      this.logged.clear();
    }
    this.logged.set(key, now);
    log.info(errorCodes.tag(code) + 'oauth2: ' + message);
    log.debug("Leaving DidClaim.note().");
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2) — see
// `common/instance_slot.ts`.
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<DidClaim>(
  'oauth-oidc/did_claim',
  () => new DidClaim(DidClaim.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The `did` claim (#693): a person's preferred, proved DID in an ID Token
 * or a UserInfo response.
 *
 * @namespace
 */
export = {
  DidClaim: DidClaim,
  /**
   * Installs the instance the composition root built (#50, R2).
   *
   * @param instance - the instance the facades forward to
   */
  installInstance: (instance: DidClaim): void => slot.install(instance),
  /**
   * Says where the installed instance came from: `root`, `default`, or
   * `none`.
   *
   * @returns the origin label
   */
  instanceOrigin: (): string => slot.origin(),
  CLAIM: CLAIM,
  SCOPE: SCOPE,
  PAIRWISE_ATTRIBUTE: PAIRWISE_ATTRIBUTE,
  enabled: slot.forward('enabled'),
  decide: slot.forward('decide'),
  apply: slot.forward('apply')
};
