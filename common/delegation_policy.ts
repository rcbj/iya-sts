// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: delegation_policy.ts
//
// ===========================================================================
// WHO MAY ACT FOR WHOM AT WS-TRUST `OnBehalfOf` / `ActAs` AND THE RFC 8693
// TOKEN EXCHANGE (#108, 2026-09-23) — rule 3az.
//
// Until this file the two delegating families other than Kerberos decided
// nothing about the act. WS-Trust puts no authorization on either element
// (1.3 section 9.2, 1.4 section 9.3) and RFC 8693 section 5 leaves the policy
// to the authorization server, so a requester that could authenticate got a
// token about anybody for any AppliesTo, and any client could exchange any
// verified token for one about its subject addressed anywhere. The act was
// RECORDED (`common/delegation.js`, rule 3l) with "authorized by nothing" in
// the column where a Kerberos row names an attribute.
//
// **SINCE #186 THIS FILE DECIDES NOTHING.** It gathers the FACTS — who the
// subject, the actor, S (the application the subject token was issued for)
// and R (the one the new token is asked for) are, what each entry says, which
// roles each holds and requires — and puts two questions to the issuance
// policy through `issuance_gate.checkExchange()`: which semantics
// (`choose-exchange-semantics`, by the policy's precedence) and whether the
// act is allowed (`exchange-token`). The rules are the policy's
// (`xacml/xacml_templates.ts`, EXCHANGE_ATTRIBUTE); an operator changes them
// in the realm's own issuance policy. The same facts and the same questions
// serve RFC 8693 token exchange, WS-Trust OnBehalfOf / ActAs and Kerberos S4U,
// so the three protocols share one set of settings:
//
//   appAllowedToDelegateTo     on an application: the applications it may
//                              delegate to (msDS-AllowedToDelegateTo).
//   appAllowedToActOnBehalfOf  on the TARGET: the actors it accepts
//                              (msDS-AllowedToActOnBehalfOfOtherIdentity).
//   appDelegationSubjectGroup  on the actor: the people it may act for, as
//                              group DNs; empty is anybody unprotected.
//   appDelegationSemantics,    on an application, and the person's
//   stsDelegationSemantics     counterpart: the semantics it allows. It
//                              replaced appTrustedToImpersonate.
//   appDefaultDelegationSemantics, stsDefaultDelegationSemantics
//                              the default when the request says none.
//   appNotDelegated,           NOT_DELEGATED: never acted for.
//   stsNotDelegated
//   delegation.protectedGroups the groups never acted for (Protected Users),
//                              besides the console roster.
//   delegation.actorRole       the role a PERSON needs to be the actor.
//   delegation.defaultSemantics the last word in the precedence.
//
// **ENFORCED IN PRODUCT; RECORDED IN DEVELOPMENT**, and that is the policy's
// to say too: a refusal's obligation carries `enforced`, computed from the
// mode (a may_act mismatch is enforced in every mode). A caller in
// development issues anyway and writes the refusal on the act's row as
// "would have been refused: …".
//
// A LIBRARY (rule 3): no route, no store of its own — `ou=applications` and
// the person's entry are the store, read through `applications.js` and
// `credentials.ts`'s directory slot. It adds NO slot (rule 3e): everything it
// requires is a library the token endpoint and WS-Trust already require.
// ===========================================================================

import helpers = require('./helpers');
import InstanceSlot = require('./instance_slot');
import config = require('./config');
import mode = require('./mode');
import applications = require('./applications');
import credentials = require('./credentials');
import gate = require('./issuance_gate');
import roles = require('./roles');

type Json = any;

// The two acts, as `delegation.js` names them, and `self` — nobody acted for.
type DelegationMode = 'impersonation' | 'delegation';
type Semantics = '' | 'self' | DelegationMode;

// Which lookup turns a target string into an application.
type TargetKind = 'audience' | 'appliesTo';

interface DelegationPolicyDeps {
  log: typeof helpers.log;
  config: { value(key: string): any };
  mode: { authorizesDelegation(): boolean; current(): string };
  applications: Json;
  credentials: Json;
  gate: Json;
  roles: { rolesOf(who: Json): string[] };
}

// What a door asks (#186).
interface DecideQuestion {
  protocol: string;
  // The semantics the REQUEST asked for: the token exchange's extension
  // parameter, the WS-Trust element, the Kerberos mechanism; '' for none.
  requested?: '' | DelegationMode;
  // The ACTOR: the actor_token's subject, else the authenticated client — a
  // client_id or application identifier, or a person's name or subject.
  actor: string;
  // Who the token will be about: a username, a `urn:uuid:` subject, or an
  // application's identifier or client_id.
  subject: string;
  // The application the subject token was issued for, as candidates in
  // order (its `aud` values, then its `client_id` / `azp`); the first that
  // resolves to an application is S.
  source?: string[];
  // The raw targets — audiences and resources, or the AppliesTo.
  targets: string[];
  targetKind: TargetKind;
  // The verified subject token carried may_act, and whether it names the
  // actor (`mayActNames()`).
  mayActPresent?: boolean;
  mayActNamesActor?: boolean;
}

// What `decide()` answers. `refusal` says which rule refused, so each door can
// speak its own protocol's error.
interface Decision {
  allowed: boolean;
  enforced: boolean;
  refusal: string;
  why: string;
  authorizedBy: string;
  attribute: string;
  // The semantics to issue with: `self`, `delegation` or `impersonation` —
  // the policy's answer where it allowed, the chosen semantics where not.
  semantics: Semantics;
  // The application the token is for (R, or S for a self exchange that
  // named none), and the raw string asked for.
  audience: string;
  intermediary: string;
  decidedBy: string;
  targets: Array<{ asked: string; application: string }>;
}

/**
 * Who may act for whom at WS-Trust `OnBehalfOf` / `ActAs` and the RFC 8693
 * token exchange (rule 3az).
 *
 * Kerberos's constrained-delegation model on application entries, the
 * person's flags, `may_act` — facts the issuance policy decides on. Enforced in
 * product mode; recorded in development.
 */
class DelegationPolicy {
  /** The four application-entry attributes the policy reads, by role. */
  static readonly ATTRIBUTES = Object.freeze({
    DELEGATE_TO: 'appAllowedToDelegateTo',
    ACT_ON_BEHALF_OF: 'appAllowedToActOnBehalfOf',
    SUBJECT_GROUP: 'appDelegationSubjectGroup',
    SEMANTICS: 'appDelegationSemantics',
    DEFAULT_SEMANTICS: 'appDefaultDelegationSemantics',
    NOT_DELEGATED: 'appNotDelegated',
    // #186: the party an application names as its delegate, as a person's
    // stsMayAct — a DN.
    MAY_ACT: 'appMayAct'
  });

  /**
   * Builds a policy over the given dependencies.
   *
   * @param deps - the logger, settings, mode, application register,
   *   credentials and issuance gate
   */
  constructor(private readonly deps: DelegationPolicyDeps) {
    deps.log.debug("Entering DelegationPolicy.constructor().");
    deps.log.debug("Leaving DelegationPolicy.constructor().");
  }

  /**
   * Returns the dependencies the composition root passes.
   *
   * @returns the default dependencies
   */
  static defaultDeps(): DelegationPolicyDeps {
    helpers.log.debug("Entering DelegationPolicy.defaultDeps().");
    helpers.log.debug("Leaving DelegationPolicy.defaultDeps().");
    return {
      log: helpers.log,
      config: config,
      mode: mode,
      applications: applications,
      credentials: credentials,
      gate: gate,
      roles: roles
    };
  }

  // Every value of one attribute on an application view, as strings.
  /**
   * Returns every value of one attribute on an application view, as trimmed
   * non-empty strings.
   *
   * @param row - an application view with `fields`
   * @param attribute - the attribute name
   * @returns the values, empty when there are none
   */
  static valuesOf(row: Json, attribute: string): string[] {
    helpers.log.debug("Entering DelegationPolicy.valuesOf().");
    const raw = row && row.fields ? row.fields[attribute] : undefined;
    const out = (Array.isArray(raw) ? raw : (raw === undefined ||
      raw === null || raw === '' ? [] : [raw]))
      .map(function (one) { return String(one).trim(); })
      .filter(function (one) { return !!one; });
    helpers.log.debug("Leaving DelegationPolicy.valuesOf().");
    return out;
  }

  // A DN compared the way `ldap_server.js`'s `normalizeDn()` compares one.
  /**
   * Normalises a DN the way `ldap_server.js`'s `normalizeDn()` compares one:
   * each RDN trimmed and lower-cased.
   *
   * @param value - the DN
   * @returns the normalised DN
   */
  static normalizeDn(value: unknown): string {
    helpers.log.debug("Entering DelegationPolicy.normalizeDn().");
    helpers.log.debug("Leaving DelegationPolicy.normalizeDn().");
    return String(value == null ? '' : value).trim().split(',')
      .map(function (part) { return part.trim().toLowerCase(); }).join(',');
  }

  // The application an identifier, client_id or name belongs to, or null.
  //
  // A CLIENT'S SUBJECT IS ITS APPLICATION TOO (#471): `urn:sts:client:<id>`,
  // the form a client is named by as an actor in RFC 9700 mode, resolves to
  // the application whose client_id is `<id>` — so a party handed over in
  // either of a client's two spellings has the same facts, and the policy's
  // actor fact is the application's identifier in both modes. The token
  // exchange hands the bare client_id today; this keeps any other caller (or
  // a realm policy's party) from finding nobody behind the namespaced one.
  /**
   * Finds the application an identifier, client_id or client subject
   * (`urn:sts:client:<id>`) belongs to.
   *
   * @param name - an application identifier, client_id or client subject
   * @returns the application view, or null
   */
  applicationFor(name: string): Json {
    const { log, applications } = this.deps;
    log.debug("Entering DelegationPolicy.applicationFor(). name=" + name);
    const wanted = String(name || '').trim();
    if (!wanted) {
      log.debug("Leaving DelegationPolicy.applicationFor(). Nothing asked.");
      return null;
    }
    // The name as written first, so an entry whose identifier happens to
    // begin with the prefix is still found by it.
    const clientId = /^urn:sts:client:./.test(wanted)
      ? wanted.slice('urn:sts:client:'.length) : '';
    const found = applications.get(wanted) ||
      applications.forClientId(wanted) ||
      (clientId ? applications.forClientId(clientId) : null) || null;
    log.debug("Leaving DelegationPolicy.applicationFor(). " +
              (found ? found.identifier : 'None.'));
    return found;
  }

  // A target string resolved to the application that registered it — the
  // lookup `oauth2.ts` and `wstrust.ts` already make to file the act.
  /**
   * Resolves a target string to the application that registered it.
   *
   * @param asked - an audience, resource or AppliesTo
   * @param kind - `audience` or `appliesTo`, which lookup to try first
   * @returns the application's identifier, or empty when none registered it
   */
  resolveTarget(asked: string, kind: TargetKind): string {
    const { log, applications } = this.deps;
    log.debug("Entering DelegationPolicy.resolveTarget().");
    const wanted = String(asked || '').trim();
    let found = null;
    if (wanted) {
      found = kind === 'appliesTo'
        ? applications.forAppliesTo(wanted)
        : (applications.forAudience(wanted) ||
           applications.forClientId(wanted));
      found = found || applications.get(wanted) || null;
    }
    log.debug("Leaving DelegationPolicy.resolveTarget(). " +
              (found ? found.identifier : 'Unregistered.'));
    return found ? String(found.identifier) : '';
  }

  // The console roster's two groups, as the settings name them.
  /**
   * Returns the console roster's two groups as `admin.readGroup` and
   * `admin.writeGroup` name them.
   *
   * @returns the group names that are set
   */
  rosterGroups(): string[] {
    const { log, config } = this.deps;
    log.debug("Entering DelegationPolicy.rosterGroups().");
    const out = ['admin.readGroup', 'admin.writeGroup'].map(function (key) {
      let value = '';
      try {
        value = String(config.value(key) || '').trim();
      } catch (e) {
        log.debug("Caught in DelegationPolicy.rosterGroups(): " +
                  ((e && e.message) || e));
        value = '';
      }
      return value;
    }).filter(function (one) { return !!one; });
    log.debug("Leaving DelegationPolicy.rosterGroups().");
    return out;
  }

  // The protected groups as written — `delegation.protectedGroups` and the
  // console roster — for the policy table.
  /**
   * Returns the protected groups as configured, for display.
   *
   * @returns the configured names and DNs, then the roster's groups
   */
  protectedGroupNames(): string[] {
    const { log, config } = this.deps;
    log.debug("Entering DelegationPolicy.protectedGroupNames().");
    let configured: any = [];
    try {
      configured = config.value('delegation.protectedGroups') || [];
    } catch (e) {
      log.debug("Caught in DelegationPolicy.protectedGroupNames(): " +
                ((e && e.message) || e));
      configured = [];
    }
    const out = (Array.isArray(configured) ? configured
      : String(configured).split(','))
      .map(function (one: any) { return String(one).trim(); })
      .filter(function (one: string) { return !!one; })
      .concat(this.rosterGroups());
    log.debug("Leaving DelegationPolicy.protectedGroupNames().");
    return out;
  }

  // -------------------------------------------------------------------------
  // THE GROUPS NOBODY ACTS FOR (#186): `delegation.protectedGroups` and the
  // console roster, each as written lower-cased and as a normalised DN, so a
  // subject's group matches by cn or by DN.
  // -------------------------------------------------------------------------
  /**
   * Returns the groups whose members are never acted for, in every spelling
   * the policy compares.
   *
   * @returns the lower-cased names and normalised DNs
   */
  protectedGroupKeys(): string[] {
    const { log } = this.deps;
    log.debug("Entering DelegationPolicy.protectedGroupKeys().");
    const out = DelegationPolicy.groupKeys(this.protectedGroupNames()
      .map(function (one) {
        return /=/.test(one) ? { dn: one, cn: '' } : { dn: '', cn: one };
      }));
    log.debug("Leaving DelegationPolicy.protectedGroupKeys(). " + out.length);
    return out;
  }

  // IS THIS PARTY NEVER ACTED FOR? (#186) — its own flag (stsNotDelegated,
  // appNotDelegated), or a protected group: delegation.protectedGroups and
  // the console roster. The same facts the policy's `exchange-protected-
  // subject` rule reads, asked on their own by Kerberos, where a protected
  // account is not refused a ticket but is never given a FORWARDABLE one —
  // Active Directory's NOT_DELEGATED and Protected Users.
  /**
   * Says whether a party is protected from being acted for: its own flag,
   * or membership of a protected group or the console roster.
   *
   * @param name - an application identifier or client_id, or a person's
   *   name or `urn:uuid:` subject
   * @returns true when nobody may act for it
   */
  subjectProtected(name: string): boolean {
    const { log } = this.deps;
    log.debug("Entering DelegationPolicy.subjectProtected().");
    const facts = this.partyFacts(name);
    const protectedKeys = this.protectedGroupKeys();
    const out = !!facts.notDelegated ||
      (facts.groups || []).some(function (one: string) {
        return protectedKeys.indexOf(one) >= 0;
      });
    log.debug("Leaving DelegationPolicy.subjectProtected(). " + out);
    return out;
  }

  // Groups `{ dn, cn }` as the keys the policy compares: each cn lower-cased
  // and each DN normalised, both sent.
  /**
   * Turns groups into the keys the exchange policy compares.
   *
   * @param groups - `{ dn, cn }` pairs
   * @returns the lower-cased cns and normalised DNs
   */
  static groupKeys(groups: Json[]): string[] {
    const out: string[] = [];
    (groups || []).forEach(function (group: Json) {
      const cn = String((group && group.cn) || '').trim().toLowerCase();
      const dn = DelegationPolicy.normalizeDn((group && group.dn) || '');
      if (cn && out.indexOf(cn) < 0) {
        out.push(cn);
      }
      if (dn && out.indexOf(dn) < 0) {
        out.push(dn);
      }
      const leading = /^cn=([^,]+)/.exec(dn);
      if (leading && out.indexOf(leading[1]) < 0) {
        out.push(leading[1]);
      }
    });
    return out;
  }

  // Each value resolved to the application that registered it, the raw
  // value kept beside it, so the policy matches either.
  /**
   * Resolves each value of a relationship attribute to an application
   * identifier, keeping the raw value too.
   *
   * @param values - identifiers, client_ids, audiences or AppliesTo values
   * @returns the identifiers and the raw values, without repeats
   */
  resolvedList(values: string[]): string[] {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering DelegationPolicy.resolvedList().");
    const out: string[] = [];
    (values || []).forEach(function (one) {
      const resolved = self.resolveTarget(one, 'audience') ||
        self.resolveTarget(one, 'appliesTo');
      [resolved, one].forEach(function (value) {
        if (value && out.indexOf(value) < 0) {
          out.push(value);
        }
      });
    });
    log.debug("Leaving DelegationPolicy.resolvedList(). " + out.length);
    return out;
  }

  // ONE PARTY — a subject or an actor — as the exchange question states it:
  // an application by its identifier and entry, a person by their name and
  // entry, or nobody this realm knows.
  /**
   * Describes one party of an act as the exchange policy reads it.
   *
   * @param name - an application identifier or client_id, or a person's
   *   name or `urn:uuid:` subject
   * @returns `{ id, kind, registered, roles, notDelegated, groups,
   *   semantics, defaultSemantics, delegatesTo, subjectGroups, mayAct }`
   */
  partyFacts(name: string): Json {
    const { log, credentials, roles } = this.deps;
    const A = DelegationPolicy.ATTRIBUTES;
    log.debug("Entering DelegationPolicy.partyFacts().");
    const wanted = String(name || '').trim();
    const rolesFor = function (kind: string, who: string): string[] {
      try {
        return roles.rolesOf({ kind: kind, name: who, authenticated: true }) ||
               [];
      } catch (e) {
        log.debug("Caught in DelegationPolicy.partyFacts(): " +
                  ((e && e.message) || e));
        return [];
      }
    };
    const application = this.applicationFor(wanted);
    if (application) {
      const id = String(application.identifier);
      log.debug("Leaving DelegationPolicy.partyFacts(). An application.");
      return {
        id: id, kind: 'application', registered: true,
        roles: rolesFor('application', id),
        notDelegated: DelegationPolicy.valuesOf(application, A.NOT_DELEGATED)
          .some(function (one) { return one.toUpperCase() === 'TRUE'; }),
        groups: [],
        semantics: DelegationPolicy.valuesOf(application, A.SEMANTICS)
          .map(function (one) { return one.toLowerCase(); }),
        defaultSemantics: (DelegationPolicy.valuesOf(application,
          A.DEFAULT_SEMANTICS)[0] || '').toLowerCase(),
        delegatesTo: this.resolvedList(DelegationPolicy.valuesOf(application,
          A.DELEGATE_TO)),
        subjectGroups: DelegationPolicy.valuesOf(application, A.SUBJECT_GROUP)
          .map(function (one) { return DelegationPolicy.normalizeDn(one); }),
        accepts: this.resolvedList(DelegationPolicy.valuesOf(application,
          A.ACT_ON_BEHALF_OF)),
        mayAct: ''
      };
    }
    const facts = wanted ? (credentials.delegationFactsFor(wanted) || {}) : {};
    if (facts.found && facts.person) {
      const username = String(facts.username || wanted);
      log.debug("Leaving DelegationPolicy.partyFacts(). A person.");
      return {
        id: username, kind: 'user', registered: true,
        roles: rolesFor('user', username),
        notDelegated: !!facts.notDelegated,
        groups: DelegationPolicy.groupKeys(facts.groups || []),
        semantics: (facts.semantics || []).map(function (one: string) {
          return String(one).toLowerCase();
        }),
        defaultSemantics: String(facts.defaultSemantics || '').toLowerCase(),
        delegatesTo: [], subjectGroups: [], accepts: [],
        mayAct: String(facts.mayAct || '')
      };
    }
    log.debug("Leaving DelegationPolicy.partyFacts(). Nobody known.");
    return { id: wanted, kind: /^urn:uuid:/i.test(wanted) ? 'user'
                                                         : 'application',
             registered: false, roles: [], notDelegated: false, groups: [],
             semantics: [], defaultSemantics: '', delegatesTo: [],
             subjectGroups: [], accepts: [], mayAct: '' };
  }

  // -------------------------------------------------------------------------
  // THE DECISION (#186). The facts, then the two questions through the
  // issuance gate; the policy's answer, translated for the doors. Mode-free
  // here: `enforced` is the policy's.
  // -------------------------------------------------------------------------
  /**
   * Gathers the facts of an act and asks the issuance policy which semantics
   * it has and whether it is allowed.
   *
   * @param question - the protocol, the requested semantics, the actor, the
   *   subject, S's candidates, the targets and their kind, and may_act
   * @returns the decision: whether it is allowed, whether a refusal is
   *   enforced, which rule refused, the semantics and the audience
   */
  decide(question: DecideQuestion): Decision {
    const { log, applications, gate, config, mode } = this.deps;
    const self = this;
    log.debug("Entering DelegationPolicy.decide(). " + question.protocol +
              " by " + question.actor + " for " + question.subject);
    const subject = this.partyFacts(question.subject);
    const actor = this.partyFacts(question.actor);
    // S: the first candidate that resolves to an application.
    let sourceId = '';
    (question.source || []).some(function (one) {
      sourceId = self.resolveTarget(String(one || ''), question.targetKind) ||
        (self.applicationFor(String(one || '')) || { identifier: '' })
          .identifier || '';
      return !!sourceId;
    });
    const source = sourceId ? this.partyFacts(sourceId) : null;
    const asked = (question.targets || []).map(function (one) {
      return String(one || '').trim();
    }).filter(function (one) { return !!one; });
    const targetId = asked.length
      ? this.resolveTarget(asked[0], question.targetKind) : '';
    const target = targetId ? this.partyFacts(targetId) : null;
    const setting = function (key: string): string {
      try {
        return String(config.value(key) || '');
      } catch (e) {
        log.debug("Caught in DelegationPolicy.decide(): " +
                  ((e && e.message) || e));
        return '';
      }
    };
    const facts = {
      subject: subject, actor: actor,
      source: { id: sourceId,
                requiredRoles: sourceId
                  ? applications.requiredRolesOf(sourceId) : [],
                delegatesTo: source ? source.delegatesTo : [] },
      target: { id: targetId || (asked[0] || ''), count: asked.length,
                registered: !!targetId,
                requiredRoles: targetId
                  ? applications.requiredRolesOf(targetId) : [],
                accepts: target ? target.accepts : [] },
      requestedSemantics: String(question.requested || ''),
      mayActPresent: !!question.mayActPresent,
      mayActNamesActor: !!question.mayActNamesActor,
      protectedGroups: this.protectedGroupKeys()
    };
    const answer = gate.checkExchange({
      facts: facts, mode: mode.current(), protocol: question.protocol,
      settings: { defaultSemantics: setting('delegation.defaultSemantics'),
                  actorRole: setting('delegation.actorRole') }
    }) || {};
    const allowed = answer.verdict === 'allow';
    const semantics = (allowed ? answer.semantics : answer.chosen) || '';
    const decision: Decision = {
      allowed: allowed,
      enforced: allowed ? false : answer.enforced !== false,
      refusal: allowed ? '' : String(answer.refusal || 'policy'),
      why: '', authorizedBy: '', attribute: '',
      semantics: (['self', 'delegation', 'impersonation']
        .indexOf(semantics) >= 0 ? semantics : '') as Semantics,
      audience: allowed ? String(answer.audience || '') : targetId,
      intermediary: actor.id,
      decidedBy: String(answer.decidedBy || ''),
      targets: asked.map(function (one, i) {
        return { asked: one, application: i === 0 ? targetId
          : self.resolveTarget(one, question.targetKind) };
      })
    };
    if (allowed) {
      decision.authorizedBy = this.allowedBecause(decision, facts, question);
    } else {
      decision.why = this.refusedBecause(decision, facts, question);
      decision.attribute = DelegationPolicy.REFUSAL_ATTRIBUTE[
        decision.refusal] || '';
      log.info('delegation_policy: ' + (decision.enforced ? 'REFUSED'
        : 'would have refused (development records it)') + ' ' +
        question.protocol + ' ' + (decision.semantics || 'act') + ' by "' +
        actor.id + '" for "' + subject.id + '": ' + decision.why);
    }
    log.debug("Leaving DelegationPolicy.decide(). " +
              (allowed ? 'Allowed, ' + decision.semantics + '.'
                       : 'Refused: ' + decision.refusal));
    return decision;
  }

  // The attribute each refusal is about, for the act's row.
  static readonly REFUSAL_ATTRIBUTE: Record<string, string> = {
    'subject': 'stsNotDelegated',
    'semantics': 'appDelegationSemantics',
    'target': 'appAllowedToDelegateTo',
    'no-target': 'appAllowedToDelegateTo',
    'intermediary': 'appAllowedToDelegateTo'
  };

  // The sentence a refusal is spoken in. The rule is the policy's; the
  // sentence names the facts it read, so the act's row and the client's
  // error say which.
  /**
   * Says, in a sentence, why the policy refused an act.
   *
   * @param decision - the decision so far
   * @param facts - the facts the policy was asked on
   * @param question - the door's question
   * @returns the sentence
   */
  refusedBecause(decision: Decision, facts: Json, question: DecideQuestion):
      string {
    const { log } = this.deps;
    log.debug("Entering DelegationPolicy.refusedBecause(). " +
              decision.refusal);
    const actor = '"' + facts.actor.id + '"';
    const subject = '"' + facts.subject.id + '"';
    const target = '"' + (facts.target.id || '') + '"';
    const what = decision.semantics || 'act';
    const noTarget = question.protocol === 'WS-Trust' ? 'no AppliesTo'
      : question.protocol === 'Kerberos' ? 'no service'
        : 'neither audience nor resource';
    const sentences: Record<string, string> = {
      'may-act': 'The subject token\'s may_act (RFC 8693 section 4.4) names ' +
        'somebody other than ' + actor + '.',
      'targets': 'The request names ' + facts.target.count + ' targets; a ' +
        'token is issued for exactly one.',
      'unregistered-target': 'No application in this realm registers ' +
        target + ', so there is nothing to read its roles or relationships ' +
        'from.',
      'no-target': 'The request names no target (' + noTarget + '), and ' +
        'only a self exchange defaults to the subject token\'s own audience.',
      'subject': subject + ' is protected — its entry says it is never ' +
        'delegated, it is in a protected group (delegation.protectedGroups, ' +
        'the console roster), or it is outside the groups ' + actor +
        ' may act for (appDelegationSubjectGroup) — so ' + actor +
        ' may not act for it.',
      'intermediary': actor + ' may not act for anybody here: it has no ' +
        'entry in this realm, or it is a person without the role ' +
        'delegation.actorRole names.',
      'semantics': (decision.semantics
        ? 'The semantics chosen, ' + decision.semantics + ', are not ' +
          'allowed by ' + actor + ' or ' + subject + ' (their delegation ' +
          'semantics; an actor allows delegation only unless its entry ' +
          'says otherwise).'
        : 'No semantics could be chosen for this act.'),
      'authority': subject + ' holds none of the roles the application ' +
        'this ' + what + ' stands on requires.',
      'target': (decision.semantics === 'impersonation'
        ? 'Nothing allows ' + actor + ' to reach ' + target + ' as ' +
          subject + ': R is not the actor itself, nor on its ' +
          'appAllowedToDelegateTo, nor does R accept it ' +
          '(appAllowedToActOnBehalfOf).'
        : 'Nothing allows this delegation to ' + target + ': the actor ' +
          'must be the application the subject token was issued for or ' +
          'the target, and that application must delegate to the target ' +
          '(appAllowedToDelegateTo on it, or appAllowedToActOnBehalfOf on ' +
          'the target).'),
      'policy': 'The issuance policy refused this ' + what + '.'
    };
    const out = sentences[decision.refusal] || sentences.policy;
    log.debug("Leaving DelegationPolicy.refusedBecause().");
    return out;
  }

  // What allowed an act, for the act's row.
  /**
   * Says, in a sentence, what the policy allowed and why.
   *
   * @param decision - the decision so far
   * @param facts - the facts the policy was asked on
   * @param question - the door's question
   * @returns the sentence
   */
  allowedBecause(decision: Decision, facts: Json,
                 question: DecideQuestion): string {
    const { log } = this.deps;
    log.debug("Entering DelegationPolicy.allowedBecause().");
    let out: string;
    if (decision.semantics === 'self') {
      out = 'nothing was needed: "' + facts.actor.id + '" acts for nobody ' +
            'but itself.';
    } else {
      out = 'the issuance policy allowed ' + decision.semantics + ' by "' +
            facts.actor.id + '" for "' + facts.subject.id + '" to "' +
            decision.audience + '"' + (facts.source.id
              ? ' (the subject token was issued for "' + facts.source.id +
                '")' : '') +
            (question.mayActNamesActor
              ? '; the subject named this actor in may_act' : '') + '.';
    }
    log.debug("Leaving DelegationPolicy.allowedBecause().");
    return out;
  }

  // The sentence the act's row carries in `authorizedBy` for either answer —
  // so the page says what allowed an act, what refused it, and in
  // development what WOULD have refused it.
  /**
   * Returns the sentence the act's delegation row carries in `authorizedBy`.
   *
   * @param decision - what `decide()` answered
   * @returns what allowed the act, what refused it, or in development what
   *   would have refused it
   */
  rowText(decision: Decision): string {
    const { log } = this.deps;
    log.debug("Entering DelegationPolicy.rowText().");
    let out: string;
    if (decision.allowed) {
      out = decision.authorizedBy;
    } else if (decision.enforced) {
      out = 'refused by the delegation policy: ' + decision.why;
    } else {
      out = 'nothing, in development mode — and it WOULD HAVE BEEN REFUSED ' +
            'in product: ' + decision.why;
    }
    log.debug("Leaving DelegationPolicy.rowText().");
    return out;
  }

  // -------------------------------------------------------------------------
  // `may_act` FOR AN ACCESS TOKEN ABOUT THIS PERSON (RFC 8693 section 4.4),
  // from their own `stsMayAct` and nothing else — the person's explicit
  // choice, never derived from an application's permissions. Answers the
  // claim's value or null. A delegate that is a person is named by their
  // `urn:uuid:` subject; an application by its client_id (its identifier
  // where it has none), which is what the token endpoint compares against a
  // client exchanging with no actor_token.
  // -------------------------------------------------------------------------
  /**
   * Returns the RFC 8693 `may_act` claim for an access token about a person,
   * from their own `stsMayAct` and nothing else.
   *
   * @param username - the person's username
   * @returns `{ sub }` naming the delegate (a person's `urn:uuid:` subject or
   *   an application's client_id), or null
   */
  mayActClaimFor(username: string): Json {
    const { log, credentials, gate, mode, config } = this.deps;
    log.debug("Entering DelegationPolicy.mayActClaimFor().");
    const name = String(username || '').trim();
    if (!name) {
      log.debug("Leaving DelegationPolicy.mayActClaimFor(). Nobody.");
      return null;
    }
    // WHOM THE SUBJECT NAMED: a person's stsMayAct, or an application's
    // appMayAct (#186) — each a DN, resolved to what the claim says.
    let subjectId = name;
    let kind = 'user';
    let declared: Json = null;
    const application = this.applicationFor(name);
    if (application) {
      subjectId = String(application.identifier);
      kind = 'application';
      const dn = DelegationPolicy.valuesOf(application,
                                           DelegationPolicy.ATTRIBUTES
                                             .MAY_ACT)[0] || '';
      declared = dn ? this.claimForDn(dn) : null;
    } else {
      const facts = credentials.delegationFactsFor(name);
      if (facts && facts.person && facts.mayAct) {
        subjectId = String(facts.username || name);
        declared = this.claimForDelegate(facts.delegate);
      }
    }
    if (!declared) {
      // Nobody named, nothing to ask: the built-in rule assigns nothing, and
      // asking the policy for every token would cost every issuance an
      // evaluation to learn that.
      log.debug("Leaving DelegationPolicy.mayActClaimFor(). None named.");
      return null;
    }
    // THE ISSUANCE POLICY SAYS WHAT THE CLAIM NAMES (#186): its built-in
    // answer is the subject's choice; a realm's policy may name another
    // party, or none.
    const answer = gate.checkExchange({
      action: 'assign-may-act',
      facts: { subject: { id: subjectId, kind: kind,
                          delegates: [declared.sub] } },
      mode: mode.current(), protocol: '',
      settings: { defaultSemantics: String(
        config.value('delegation.defaultSemantics') || ''),
                  actorRole: String(config.value('delegation.actorRole') ||
                                    '') }
    }) || {};
    const parties = Array.isArray(answer.mayAct) ? answer.mayAct : [];
    log.debug("Leaving DelegationPolicy.mayActClaimFor(). " +
              (parties[0] ? parties[0] : 'None assigned.'));
    return parties[0] ? { sub: String(parties[0]) } : null;
  }

  // The claim a delegate resolved by the credential store names: a person by
  // their `urn:uuid:` subject, an application by its client_id.
  private claimForDelegate(delegate: Json): Json {
    const { log } = this.deps;
    log.debug("Entering DelegationPolicy.claimForDelegate().");
    if (delegate && delegate.kind === 'person' && delegate.sub) {
      log.debug("Leaving DelegationPolicy.claimForDelegate(). A person.");
      return { sub: delegate.sub };
    }
    if (delegate && delegate.kind === 'application') {
      const out = this.claimForDn(delegate.dn);
      log.debug("Leaving DelegationPolicy.claimForDelegate(). An " +
                "application.");
      return out;
    }
    log.debug("Leaving DelegationPolicy.claimForDelegate(). Nothing here.");
    return null;
  }

  // The claim a DN names: an application by its client_id (or identifier),
  // a person by their `urn:uuid:` subject; null when it names nobody here.
  private claimForDn(dn: string): Json {
    const { log, credentials } = this.deps;
    log.debug("Entering DelegationPolicy.claimForDn().");
    const row = this.applicationByDn(dn);
    if (row) {
      const clientIds = DelegationPolicy.valuesOf(row, 'oauthClientId');
      log.debug("Leaving DelegationPolicy.claimForDn(). An application.");
      return { sub: clientIds[0] || String(row.identifier) };
    }
    const facts = credentials.delegationFactsFor(dn);
    if (facts && facts.found && facts.person) {
      const out = this.claimForDelegate({ kind: 'person', sub: facts.sub });
      log.debug("Leaving DelegationPolicy.claimForDn(). A person.");
      return out;
    }
    log.debug("Leaving DelegationPolicy.claimForDn(). Nobody.");
    return null;
  }

  private applicationByDn(dn: string): Json {
    const { log, applications } = this.deps;
    log.debug("Entering DelegationPolicy.applicationByDn().");
    const wanted = DelegationPolicy.normalizeDn(dn);
    const found = (applications.list() || []).filter(function (row: Json) {
      return DelegationPolicy.normalizeDn(row.dn) === wanted;
    })[0] || null;
    log.debug("Leaving DelegationPolicy.applicationByDn().");
    return found;
  }

  // Does a `may_act` claim name this actor? `actor` carries `sub` (and `iss`
  // where the actor_token had one); section 4.4 lets the pair be needed to
  // identify a party, so an `iss` in the claim must match too.
  /**
   * Says whether a `may_act` claim names this actor; an `iss` in the claim
   * must match too.
   *
   * @param mayAct - the verified subject token's `may_act` claim
   * @param actor - `sub`, and `iss` and `aliases` where known
   * @returns true when the claim names the actor
   */
  static mayActNames(mayAct: Json, actor: { sub: string; iss?: string;
                                            aliases?: string[] }): boolean {
    helpers.log.debug("Entering DelegationPolicy.mayActNames().");
    if (!mayAct || typeof mayAct !== 'object') {
      helpers.log.debug("Leaving DelegationPolicy.mayActNames(). No claim.");
      return false;
    }
    const names = [String(actor.sub || '')].concat(actor.aliases || [])
      .filter(function (one) { return !!one; });
    const subOk = names.indexOf(String(mayAct.sub || '')) >= 0;
    const issOk = !mayAct.iss || String(mayAct.iss) === String(actor.iss || '');
    helpers.log.debug("Leaving DelegationPolicy.mayActNames().");
    return subOk && issOk;
  }

  // -------------------------------------------------------------------------
  // THE POLICY AS A REGISTER, for /admin/delegation and
  // GET /admin-api/delegation/policy: `pairs` in `krb5_principals.js`'s
  // `delegationPolicy()` shape (one per intermediary, target and attribute),
  // `intermediaries` carrying a flag or a subject group, and `people` carrying
  // stsNotDelegated or stsMayAct. Whole lists; the view model pages them.
  // -------------------------------------------------------------------------
  /**
   * Returns the policy as a register, for `/admin/delegation` and
   * `GET /admin-api/delegation/policy`.
   *
   * @returns `{ pairs, intermediaries, people, protectedGroups, enforced,
   *   attributes }`, whole lists
   */
  list(): Json {
    const { log, applications, credentials } = this.deps;
    const self = this;
    log.debug("Entering DelegationPolicy.list().");
    const A = DelegationPolicy.ATTRIBUTES;
    const pairs: Json[] = [];
    const intermediaries: Json[] = [];
    const rows = applications.list() || [];
    const known = function (identifier: string): boolean {
      log.debug("Entering known().");
      log.debug("Leaving known().");
      return !!self.applicationFor(identifier);
    };
    rows.forEach(function (row: Json) {
      const semantics = DelegationPolicy.valuesOf(row, A.SEMANTICS)
        .map(function (one) { return one.toLowerCase(); });
      const trusted = semantics.indexOf('impersonation') >= 0;
      const defaultSemantics = (DelegationPolicy.valuesOf(row,
        A.DEFAULT_SEMANTICS)[0] || '').toLowerCase();
      const notDelegated = DelegationPolicy.valuesOf(row, A.NOT_DELEGATED)
        .some(function (one) { return one.toUpperCase() === 'TRUE'; });
      const groups = DelegationPolicy.valuesOf(row, A.SUBJECT_GROUP);
      DelegationPolicy.valuesOf(row, A.DELEGATE_TO).forEach(function (target) {
        const resolved = self.resolveTarget(target, 'audience') ||
          self.resolveTarget(target, 'appliesTo');
        pairs.push({ mechanism: 'constrained', intermediary: row.identifier,
          target: target, targetApplication: resolved,
          attribute: A.DELEGATE_TO, setOn: row.identifier,
          setOnRole: 'intermediary', impersonates: trusted,
          subjectGroups: groups, targetKnown: !!resolved,
          warning: resolved ? '' : 'No application here has registered "' +
            target + '"; it is matched exactly as written.' });
      });
      DelegationPolicy.valuesOf(row, A.ACT_ON_BEHALF_OF)
        .forEach(function (who) {
          const found = self.applicationFor(who);
          pairs.push({ mechanism: 'resource-based', intermediary: who,
            target: row.identifier, targetApplication: row.identifier,
            attribute: A.ACT_ON_BEHALF_OF, setOn: row.identifier,
            setOnRole: 'target',
            impersonates: found ? DelegationPolicy.valuesOf(found,
              A.SEMANTICS).some(function (one) {
              return one.toLowerCase() === 'impersonation';
            }) : false,
            subjectGroups: found ? DelegationPolicy.valuesOf(found,
              A.SUBJECT_GROUP) : [],
            targetKnown: true,
            warning: known(who) ? '' : 'No application here is called "' +
              who + '", so nothing can act under that name.' });
        });
      if (semantics.length || defaultSemantics || notDelegated ||
          groups.length) {
        intermediaries.push({ application: row.identifier,
                              impersonates: trusted, semantics: semantics,
                              defaultSemantics: defaultSemantics,
                              notDelegated: notDelegated,
                              subjectGroups: groups });
      }
    });
    pairs.sort(function (a, b) {
      return String(a.target).localeCompare(String(b.target)) ||
             String(a.intermediary).localeCompare(String(b.intermediary));
    });
    intermediaries.sort(function (a, b) {
      return String(a.application).localeCompare(String(b.application));
    });
    const people = (credentials.delegationFlaggedPersons() || [])
      .slice(0).sort(function (a: Json, b: Json) {
        return String(a.username).localeCompare(String(b.username));
      });
    log.debug("Leaving DelegationPolicy.list(). " + pairs.length +
              " pair(s).");
    return { pairs: pairs, intermediaries: intermediaries, people: people,
             protectedGroups: this.protectedGroupNames(),
             enforced: this.deps.mode.authorizesDelegation(),
             attributes: A };
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2) — see
// `common/instance_slot.ts`.
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<DelegationPolicy>(
  'common/delegation_policy',
  () => new DelegationPolicy(DelegationPolicy.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * Who may act for whom at WS-Trust and the RFC 8693 token exchange.
 *
 * A library with no route and no store of its own; the functions forward
 * to the instance the composition root installs.
 * @namespace
 */
export = {
  DelegationPolicy: DelegationPolicy,
  /**
   * Installs the instance the facades forward to, and runs its wiring.
   *
   * Installing twice, or after a default was built, is refused.
   * @param instance - the instance the composition root built
   */
  installInstance: (instance: DelegationPolicy): void => slot.install(instance),
  /**
   * Says where the instance the facades use came from.
   *
   * @returns `root`, `default` or `none`
   */
  instanceOrigin: (): string => slot.origin(),
  ATTRIBUTES: DelegationPolicy.ATTRIBUTES,
  mayActNames: DelegationPolicy.mayActNames,
  decide: slot.forward('decide'),
  rowText: slot.forward('rowText'),
  mayActClaimFor: slot.forward('mayActClaimFor'),
  list: slot.forward('list'),
  resolveTarget: slot.forward('resolveTarget'),
  applicationFor: slot.forward('applicationFor'),
  partyFacts: slot.forward('partyFacts'),
  subjectProtected: slot.forward('subjectProtected')
};
