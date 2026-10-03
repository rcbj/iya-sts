// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: gnap_delegation.ts
//
// ===========================================================================
// WHO MAY ACT FOR WHOM IN GNAP (#432 PHASE 1) — the fourth protocol asking
// #186's question, through #186's policy and #186's settings.
//
// GNAP has two ways for one party to obtain a token about somebody else, and
// each is a Kerberos act in another protocol's clothes:
//
//   GNAP act                                   Kerberos      semantics
//   ---------------------------------------    ----------    -------------
//   a `gnapSkipInteraction` client presents    S4U2Self      impersonation
//   a VERIFIED user assertion and is issued
//   tokens for that person, nobody asked
//   (RFC 9635 sections 2.3.3 and 2.4)
//   a resource server DERIVES a token for a    S4U2Proxy     delegation
//   downstream one (RFC 9767 section 4)
//
// Until #432 neither asked anything: the first needed only the flag on the
// client's entry, and the second only that the deriving resource server was
// in the original token's audience — after which it could ADD any right a
// downstream resource server had registered. So both now ask
// `common/delegation_policy.ts`'s `decide()`, which gathers the facts and
// puts #186's two questions (`choose-exchange-semantics`, `exchange-token`)
// to the issuance policy. **There is no GNAP setting about who may act**:
// the relationships are the entries' own — `appDelegationSemantics` (an
// actor allows delegation only unless it lists impersonation),
// `appAllowedToDelegateTo`, `appAllowedToActOnBehalfOf`,
// `appDelegationSubjectGroup`, `appNotDelegated` / `stsNotDelegated`,
// `delegation.protectedGroups` and the console roster — exactly as for the
// token exchange, WS-Trust and Kerberos. The parties, as #186 states them:
//
//   impersonation  actor = the client's application entry; subject = the
//                  person the assertion names; no S (there is no subject
//                  token issued FOR anybody — Kerberos's S4U2Self passes
//                  none either, `kerberos/krb5_delegation.ts`); R = each
//                  resource server the requested rights resolve to
//                  (`gnap_grants.ts`'s `resourceServersFor()`), or the client
//                  itself where they resolve to none — S4U2Self's "a ticket
//                  to yourself", which still needs impersonation in the
//                  client's allowed semantics, because here the token is
//                  presentable;
//   derivation     actor = S = the deriving resource server's entry; subject
//                  = the person the original token is about (its client
//                  application where it is about nobody); R = each downstream
//                  resource server the requested rights resolve to, or the
//                  deriving resource server itself (a narrowing for itself,
//                  which the policy calls `self`).
//
// ONE QUESTION PER TARGET, because the policy issues for exactly one R and a
// GNAP grant may ask for tokens at several resource servers. The first
// refusal is the one the client hears.
//
// **ENFORCED IN PRODUCT; RECORDED IN DEVELOPMENT** — the policy's own
// `enforced`, so this file reads no mode. A `may_act` mismatch is enforced in
// every mode (the subject's own token says no). In development the act is
// issued and its row reads "WOULD HAVE BEEN REFUSED in product".
//
// **`appAllowedProtocol` IS HONOURED THE WAY #186 HONOURS IT**: the acting
// application — the client, or the deriving resource server — is asked the
// issuance gate's question with GNAP's family (`gnap_grants.ts`'s
// `issueTokens()`), whose `protocol-not-declared` rule refuses, in product,
// an application declared for protocols that do not include GNAP. The
// target's declaration is not read, as it is not for an RFC 8693 R.
//
// EVERY ACT IS RECORDED in `common/delegation.js` (rule 3l), protocol GNAP,
// types `gnap-impersonation` and `gnap-derivation`, so Monitoring →
// Delegation and its map show GNAP beside the other three.
//
// ---------------------------------------------------------------------------
// A DERIVED TOKEN IS A SUBSET OF THE ONE IT CAME FROM (rcbj's decision 3 on
// #432), and the actor chain goes on it.
//
//   * `derivationWidens()` refuses a right the original token does not cover
//     (`gnap_access.accessCovers()`). The exception that let a derivation add
//     "rights registered for a downstream resource server" is GONE: it let
//     any resource server a token reached mint access nobody approved.
//   * **THE ONE EXTENSION POINT IS `derivableBeyond()`**, filled by #432's
//     phase 4: rcbj's decision 3 adds the rights of an access-type catalogue
//     entry that declares itself "derivable from" a type the original token
//     carries (`gnap_rights.ts`'s `derivable()`), and nothing else.
//   * `actorChainFor()` builds RFC 8693 section 4.1's `act`: the deriving
//     resource server outermost, the original token's chain nested under it.
//     Every derivation adds a link, including a narrowing for the deriving
//     resource server itself: the token it gets is still a token ABOUT the
//     person held by a party that is not the person's client.
//     `gnap.maxDerivationDepth` caps the chain (STS-GNAP-0782, every mode):
//     each hop is a resource server further from anything the person
//     approved.
//
// A LIBRARY (rule 3): no route and no store. It requires
// `common/delegation_policy.ts` and `common/delegation.js`, both libraries
// the token endpoint already requires, and `gnap_access.ts`; nothing it
// requires reaches `gnap/`, so it closes no cycle and needs no slot (rule 3e).
// ===========================================================================

import helpers = require('../common/helpers');
import config = require('../common/config');
import errorCodes = require('../common/error_codes');
import applications = require('../common/applications');
import InstanceSlot = require('../common/instance_slot');
import delegationPolicy = require('../common/delegation_policy');
import delegation = require('../common/delegation');
import accessRights = require('./gnap_access');
// THE ACCESS-TYPE CATALOGUE'S "derivable from" (#432 phase 4), the one
// extension point below. A library that requires nothing of `gnap/` but the
// store, so it closes no cycle.
import gnapRights = require('./gnap_rights');

type Json = any;

interface GnapDelegationDeps {
  log: typeof helpers.log;
  config: { value(key: string): any };
  errorCodes: { mark<T>(target: T, code: string): T };
  applications: Json;
  policy: Json;
  register: Json;
  access: Json;
  rights: Json;
}

// One act's question, and what each door passes.
interface ActQuestion {
  // `impersonation` or `derivation`.
  act: 'impersonation' | 'derivation';
  // The acting application's entry (the client, or the deriving RS).
  actor: Json;
  // Who the token will be about: a username, or an application identifier.
  subject: string;
  // The resource servers the requested rights resolve to; empty means none.
  targets: string[];
  // The verified assertion's `may_act` (impersonation only), or null.
  mayAct?: Json;
  // The verified assertion's format (impersonation only).
  format?: string;
  // What was presented, for the act's row: the assertion's format, or the
  // original token's jti.
  consumed: { kind: string; identifier: string; note: string };
  grantId: string;
}

// One target's decision, kept so the act can be recorded when the outcome is
// known.
interface Decided {
  target: string;
  decision: Json;
}

// The refusal codes, by `delegation_policy.decide()`'s refusal kind, per act.
const REFUSAL_CODES: Record<string, Record<string, string>> = {
  impersonation: {
    relationship: 'STS-GNAP-0770', subject: 'STS-GNAP-0771',
    semantics: 'STS-GNAP-0772', authority: 'STS-GNAP-0773',
    'may-act': 'STS-GNAP-0774', policy: 'STS-GNAP-0775'
  },
  derivation: {
    relationship: 'STS-GNAP-0776', subject: 'STS-GNAP-0777',
    semantics: 'STS-GNAP-0778', authority: 'STS-GNAP-0779',
    'may-act': 'STS-GNAP-0780', policy: 'STS-GNAP-0781'
  }
};

// The policy's refusal kinds that are all "the relationship does not hold":
// the target is not one the actor may reach, or there is no usable target.
const RELATIONSHIP_KINDS = ['target', 'intermediary', 'unregistered-target',
                            'no-target', 'targets'];

const DEPTH_CODE = 'STS-GNAP-0782';

/**
 * Who may act for whom in GNAP (#432 phase 1): impersonation by a user
 * assertion and RFC 9767 derivation, asked of #186's delegation policy,
 * recorded in the delegation register, and the actor chain a derived token
 * carries.
 */
class GnapDelegation {
  /** The delegation register's type for each act. */
  static readonly TYPES = Object.freeze({
    impersonation: 'gnap-impersonation',
    derivation: 'gnap-derivation'
  });

  /** The protocol name the policy and the register are told. */
  static readonly PROTOCOL = 'GNAP';

  /** The refusal codes, by act and refusal kind. */
  static readonly REFUSAL_CODES = REFUSAL_CODES;

  /**
   * Builds the library from the modules it reads.
   *
   * @param deps - the modules the composition root passes
   */
  constructor(private readonly deps: GnapDelegationDeps) {
    deps.log.debug("Entering GnapDelegation.constructor().");
    deps.log.debug("Leaving GnapDelegation.constructor().");
  }

  /**
   * Returns the real modules the composition root passes.
   *
   * @returns the default dependencies
   */
  static defaultDeps(): GnapDelegationDeps {
    helpers.log.debug("Entering GnapDelegation.defaultDeps().");
    helpers.log.debug("Leaving GnapDelegation.defaultDeps().");
    return {
      log: helpers.log,
      config: config,
      errorCodes: errorCodes,
      applications: applications,
      policy: delegationPolicy,
      register: delegation,
      access: accessRights,
      rights: gnapRights
    };
  }

  // A refusal in `gnap_grants.ts`'s shape, marked with its code.
  private refusal(code: string, why: string): Json {
    const { log, errorCodes } = this.deps;
    log.debug("Entering GnapDelegation.refusal().");
    const out = { ok: false, errorCode: code, why: why,
                  gnapError: 'request_denied', status: 403 };
    log.debug("Leaving GnapDelegation.refusal().");
    return errorCodes.mark(out, code);
  }

  // -------------------------------------------------------------------------
  // THE NAMES AN APPLICATION IS SPELT BY in a `may_act` claim: its
  // identifier, its client_ids, and `urn:sts:client:<client_id>` — what
  // `delegation_policy.ts`'s `claimForDn()` writes for an application and
  // what a client_credentials token's `sub` is.
  // -------------------------------------------------------------------------
  /**
   * Returns the names a `may_act` claim may use for an application.
   *
   * @param app - the application view
   * @returns `{ sub, aliases }` for `delegation_policy.mayActNames()`
   */
  actorNames(app: Json): { sub: string; aliases: string[] } {
    const { log } = this.deps;
    log.debug("Entering GnapDelegation.actorNames().");
    const identifier = String((app && app.identifier) || '');
    const raw = app && app.fields ? app.fields.oauthClientId : undefined;
    const clientIds = (Array.isArray(raw) ? raw : (raw ? [raw] : []))
      .map(String).filter(function (one: string) { return !!one; });
    const aliases: string[] = [];
    clientIds.concat([identifier]).forEach(function (one: string) {
      [one, 'urn:sts:client:' + one].forEach(function (name) {
        if (name !== identifier && aliases.indexOf(name) < 0) {
          aliases.push(name);
        }
      });
    });
    log.debug("Leaving GnapDelegation.actorNames().");
    return { sub: identifier, aliases: aliases };
  }

  // The code a refusal kind is spoken with, for one act.
  private codeFor(act: string, refusal: string): string {
    const { log } = this.deps;
    log.debug("Entering GnapDelegation.codeFor().");
    const table = REFUSAL_CODES[act] || REFUSAL_CODES.impersonation;
    const kind = RELATIONSHIP_KINDS.indexOf(refusal) >= 0 ? 'relationship'
      : (table[refusal] ? refusal : 'policy');
    log.debug("Leaving GnapDelegation.codeFor(). " + table[kind]);
    return table[kind];
  }

  // -------------------------------------------------------------------------
  // DECIDE ONE ACT: one `decide()` per target, in order. Answers
  // `{ ok: true, decided }` — every decision, allowed or (in development)
  // would-have-been-refused — or the first ENFORCED refusal, with the
  // decisions that refused it so the caller can record them.
  // -------------------------------------------------------------------------
  /**
   * Asks the delegation policy about one GNAP act, one question per target.
   *
   * @param q - the act, the acting application, the subject, the targets,
   *   the assertion's `may_act` and what was presented
   * @returns `{ ok: true, decided }`, or a refusal carrying `decided`
   */
  decide(q: ActQuestion): Json {
    const { log, policy } = this.deps;
    log.debug("Entering GnapDelegation.decide(). " + q.act + " by " +
              (q.actor && q.actor.identifier) + " for " + q.subject);
    const actorId = String(q.actor.identifier);
    const targets = (q.targets || []).filter(function (one, i, all) {
      return !!one && all.indexOf(one) === i;
    });
    if (!targets.length) {
      // No resource server named: the token is for the acting application
      // itself (S4U2Self's ticket to yourself; a derivation's narrowing).
      targets.push(actorId);
    }
    const mayAct = q.mayAct && typeof q.mayAct === 'object' ? q.mayAct : null;
    const mayActNamesActor = !!mayAct &&
      policy.mayActNames(mayAct, this.actorNames(q.actor));
    const decided: Decided[] = [];
    for (let i = 0; i < targets.length; i++) {
      const decision = policy.decide({
        protocol: GnapDelegation.PROTOCOL,
        // The mechanism fixes the semantics, as Kerberos's does.
        requested: q.act === 'impersonation' ? 'impersonation' : 'delegation',
        actor: actorId,
        subject: q.subject,
        source: q.act === 'derivation' ? [actorId] : [],
        targets: [targets[i]],
        targetKind: 'audience',
        mayActPresent: !!mayAct,
        mayActNamesActor: mayActNamesActor
      });
      decided.push({ target: targets[i], decision: decision });
      if (!decision.allowed && decision.enforced) {
        const code = this.codeFor(q.act, decision.refusal);
        const refused = this.refusal(code, 'the delegation policy refused ' +
          (q.act === 'impersonation'
            ? 'this client tokens for the person its assertion names'
            : 'this derivation') + ': ' + decision.why);
        refused.decided = decided;
        log.debug("Leaving GnapDelegation.decide(). Refused, " + code + ".");
        return refused;
      }
    }
    log.debug("Leaving GnapDelegation.decide(). " + decided.length +
              " target(s).");
    return { ok: true, decided: decided };
  }

  // -------------------------------------------------------------------------
  // RECORD THE ACT (rule 3l): one row per target, with the policy's sentence
  // — what allowed it, what refused it, or in development what would have.
  // -------------------------------------------------------------------------
  /**
   * Records a decided GNAP act in the delegation register, one row per
   * target.
   *
   * @param q - the act's question
   * @param decided - the decisions `decide()` made
   * @param outcome - `issued` or `refused`
   * @param produced - the jtis of the tokens issued
   */
  record(q: ActQuestion, decided: Decided[], outcome: 'issued' | 'refused',
         produced: string[]): void {
    const { log, policy, register } = this.deps;
    log.debug("Entering GnapDelegation.record(). " + q.act + " " + outcome);
    const actorId = String(q.actor.identifier);
    const tokens = (produced || []).map(function (jti) {
      return { kind: 'access_token', identifier: jti,
               note: q.act === 'derivation'
                 ? 'a GNAP access token whose act chain names "' + actorId +
                   '"'
                 : 'a GNAP access token about the person, naming no actor' };
    });
    (decided || []).forEach(function (one: Decided) {
      // Only the refused decisions are recorded as refused; a target the
      // policy allowed before another refused issued nothing either, and is
      // not an act anybody performed.
      if (outcome === 'refused' && one.decision.allowed) {
        return;
      }
      const self = one.target === actorId;
      register.record({
        protocol: GnapDelegation.PROTOCOL,
        type: GnapDelegation.TYPES[q.act],
        outcome: outcome,
        initial: { presented: q.subject,
                   what: q.act === 'impersonation'
                     ? 'the person the verified ' + (q.format || 'user') +
                       ' assertion names'
                     : 'the subject of the token the resource server ' +
                       'was handed' },
        intermediary: { presented: actorId, application: actorId,
                        what: q.act === 'impersonation'
                          ? 'the client, trusted to skip interaction'
                          : 'the resource server deriving a token' },
        target: { application: one.target,
                  what: self
                    ? (q.act === 'impersonation'
                      ? 'the client itself: the rights asked for name no ' +
                        'resource server'
                      : 'the deriving resource server itself: a narrower ' +
                        'token for its own use')
                    : (q.act === 'impersonation'
                      ? 'the resource server the requested rights resolve to'
                      : 'the downstream resource server') },
        authorizedBy: policy.rowText(one.decision),
        reason: outcome === 'refused' ? one.decision.why : '',
        consumed: [q.consumed],
        produced: outcome === 'issued' ? tokens : [],
        sessionId: '',
        note: 'GNAP grant ' + q.grantId
      });
    });
    log.debug("Leaving GnapDelegation.record().");
  }

  // -------------------------------------------------------------------------
  // THE EXTENSION POINT (rcbj's decision 3 on #432). Whether one right a
  // derivation asks for, which the original token does NOT cover, may still
  // be derived: FILLED BY #432 PHASE 4 — a right of a catalogued type whose
  // `derivableFrom` names a type the original token carries
  // (`gnap_rights.ts`'s `derivable()`). Nothing else widens a derivation; a
  // right so derived is still put to the issuance policy (`issue-gnap-right`,
  // approval `derived`) and to #186's delegation question for its resource
  // server, like any other.
  // -------------------------------------------------------------------------
  /**
   * Says whether a right the original token does not cover may still be
   * derived: a right of a type the access-type catalogue declares derivable
   * from a type the original carries.
   *
   * @param original - the original token's access rights
   * @param right - the right asked for
   * @param context - `{ rs, downstream }`: the deriving resource server and
   *   the downstream ones (recorded on the log line)
   * @returns true when the catalogue makes it derivable
   */
  derivableBeyond(original: Json[], right: Json, context: Json): boolean {
    const { log, rights } = this.deps;
    log.debug("Entering GnapDelegation.derivableBeyond().");
    const from = rights.derivable(original, right);
    if (from) {
      log.info('gnap: a derivation by ' + String((context && context.rs) ||
               '') + ' adds a right of type "' + String(right.type) +
               '", which the catalogue declares derivable from "' + from +
               '" (#432).');
    }
    log.debug("Leaving GnapDelegation.derivableBeyond(). " + !!from);
    return !!from;
  }

  // -------------------------------------------------------------------------
  // THE SUBSET RULE: the first right a derivation asks for that the original
  // token does not cover (and the extension point does not allow), or null.
  // -------------------------------------------------------------------------
  /**
   * Returns the first requested right a derivation may not carry: one the
   * original token does not cover and `derivableBeyond()` does not allow.
   *
   * @param original - the original token's access rights
   * @param requested - the access rights asked for, every token's together
   * @param context - passed to `derivableBeyond()`
   * @returns the right, or null when every one is derivable
   */
  derivationWidens(original: Json[], requested: Json[],
                   context: Json): Json {
    const { log, access } = this.deps;
    log.debug("Entering GnapDelegation.derivationWidens().");
    for (let i = 0; i < (requested || []).length; i++) {
      const right = requested[i];
      if (!access.accessCovers(original, [right]) &&
          !this.derivableBeyond(original, right, context)) {
        log.debug("Leaving GnapDelegation.derivationWidens(). Right " + i +
                  ".");
        return right;
      }
    }
    log.debug("Leaving GnapDelegation.derivationWidens(). None.");
    return null;
  }

  // The deepest chain a derived token may carry: `gnap.maxDerivationDepth`.
  /**
   * Returns `gnap.maxDerivationDepth`, the deepest actor chain a derived
   * token may carry.
   *
   * @returns the depth
   */
  maxDepth(): number {
    const { log, config } = this.deps;
    log.debug("Entering GnapDelegation.maxDepth().");
    const value = Number(config.value('gnap.maxDerivationDepth'));
    log.debug("Leaving GnapDelegation.maxDepth(). " + value);
    return Number.isSafeInteger(value) && value >= 1 ? value : 1;
  }

  // -------------------------------------------------------------------------
  // THE DERIVED TOKEN'S `act`: the deriving resource server outermost, the
  // original token's chain under it. Refused past `gnap.maxDerivationDepth`
  // (STS-GNAP-0782, in every mode — a bound, not a relationship).
  // -------------------------------------------------------------------------
  /**
   * Builds a derived token's actor chain: the deriving resource server, then
   * the original token's chain.
   *
   * @param rsId - the deriving resource server's identifier
   * @param originalAct - the original token's `act`, or null
   * @returns `{ ok: true, act, depth }`, or a refusal past the cap
   */
  actorChainFor(rsId: string, originalAct: Json): Json {
    const { log, access } = this.deps;
    log.debug("Entering GnapDelegation.actorChainFor().");
    const prior = access.actorChain(originalAct) || [];
    const chain = [String(rsId)].concat(prior);
    const max = this.maxDepth();
    if (chain.length > max) {
      log.debug("Leaving GnapDelegation.actorChainFor(). Too deep.");
      return this.refusal(DEPTH_CODE, 'the token was itself derived ' +
                          prior.length + ' time(s), and a derived token ' +
                          'may carry at most ' + max + ' actor(s) ' +
                          '(gnap.maxDerivationDepth; RFC 9767 section 4).');
    }
    log.debug("Leaving GnapDelegation.actorChainFor(). Depth " +
              chain.length + ".");
    return { ok: true, act: access.nestActors(chain), depth: chain.length };
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2) — see
// `common/instance_slot.ts`.
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<GnapDelegation>(
  'gnap/gnap_delegation',
  () => new GnapDelegation(GnapDelegation.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * Who may act for whom in GNAP: the delegation policy asked for impersonation
 * by assertion and RFC 9767 derivation, and the derived token's actor chain.
 *
 * @namespace
 */
export = {
  GnapDelegation: GnapDelegation,
  /**
   * Installs the instance the composition root built (#50, R2).
   *
   * @param instance - the instance the facades forward to
   */
  installInstance: (instance: GnapDelegation): void => slot.install(instance),
  /**
   * Says where the installed instance came from: `root`, `default`, or `none`.
   *
   * @returns the origin label
   */
  instanceOrigin: (): string => slot.origin(),
  TYPES: GnapDelegation.TYPES,
  REFUSAL_CODES: GnapDelegation.REFUSAL_CODES,
  actorNames: slot.forward('actorNames'),
  decide: slot.forward('decide'),
  record: slot.forward('record'),
  derivableBeyond: slot.forward('derivableBeyond'),
  derivationWidens: slot.forward('derivationWidens'),
  maxDepth: slot.forward('maxDepth'),
  actorChainFor: slot.forward('actorChainFor')
};
