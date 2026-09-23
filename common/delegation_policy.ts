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
// **KERBEROS'S MODEL, DELIBERATELY AND BY NAME** — the one this service
// already polices, and the one an administrator of a directory already
// reads. Four attributes on APPLICATION entries and one on a PERSON:
//
//   appAllowedToDelegateTo     on the INTERMEDIARY — the targets it may
//                              reach as somebody else;
//                              msDS-AllowedToDelegateTo.
//   appAllowedToActOnBehalfOf  on the TARGET — the intermediaries it accepts.
//                              msDS-AllowedToActOnBehalfOfOtherIdentity.
//   appDelegationSubjectGroup  on the intermediary — the people it may act
//                              for, as group DNs; empty is anybody unprotected.
//   appTrustedToImpersonate    on the intermediary, default FALSE — may it
//                              IMPERSONATE as well as delegate. The analogue
//                              of TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION
//                              (protocol transition).
//   stsNotDelegated            on the PERSON — "sensitive and cannot be
//                              delegated", NOT_DELEGATED. Members of the
//                              console's Admin Read and Admin Write rosters
//                              are protected too, COMPUTED from the roster at
//                              decision time rather than seeded, so a role
//                              granted later is covered by construction.
//
// **IMPERSONATION AND DELEGATION ARE TWO ACTS** (RFC 8693 section 1.1, and
// `delegation.js`'s MODES): `OnBehalfOf` and an exchange with no
// `actor_token` produce a token indistinguishable from the subject's own, so
// they need the stronger permission; `ActAs` and an exchange with an
// `actor_token` carry the chain (`act`, a composite token).
//
// **`may_act` (RFC 8693 section 4.4) IS THE SUBJECT'S OWN SAY.** A verified
// subject_token naming its authorized actor is read in EVERY mode by the
// token endpoint, and a mismatch refused there; a MATCH is passed in as
// `mayActHonoured` and stands in for the two questions it answers — may this
// party act for this subject (the subject groups) and may it do so without
// saying so (impersonation). It does not stand in for the TARGETS: the
// subject named who, not where. `stsMayAct` on the person is where the claim
// comes from (`mayActClaimFor()`, asked by the token minting funnel).
//
// **THEN A DENY-ONLY XACML LAYER.** When the attributes allow, the decision
// is put to the issuance policy as action-id `delegate`
// (`issuance_gate.checkDelegation()`), and only an explicit Deny refuses —
// so the attribute model stays the readable one and an administrator can
// still write something stricter on /admin/xacml/policies.
//
// **ENFORCED IN PRODUCT; RECORDED IN DEVELOPMENT**
// (`mode.authorizesDelegation()`).
// `decide()` answers the same in both modes and says whether its answer is
// ENFORCED; a caller in development issues anyway and writes the refusal on
// the act's row as "would have been refused: …", which is how Kerberos's
// development fixtures and `exchangesUnverifiedTokens()` already behave.
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

type Json = any;

// The two acts, as `delegation.js` names them.
type DelegationMode = 'impersonation' | 'delegation';

// Which lookup turns a target string into an application.
type TargetKind = 'audience' | 'appliesTo';

interface DelegationPolicyDeps {
  log: typeof helpers.log;
  config: { value(key: string): any };
  mode: { authorizesDelegation(): boolean };
  applications: Json;
  credentials: Json;
  gate: Json;
}

// What a door asks.
interface DecideQuestion {
  protocol: string;
  mode: DelegationMode;
  // The APPLICATION acting — the OAuth client, the WS-Trust requester's name.
  intermediary: string;
  // Who the token will be about: a username, a `urn:uuid:` subject.
  subject: string;
  // The raw targets — audiences and resources, or the AppliesTo.
  targets: string[];
  targetKind: TargetKind;
  // The verified subject_token's `may_act` named this actor.
  mayActHonoured?: boolean;
  // The subject IS the intermediary (a client exchanging its own token):
  // nobody is being acted for, so there is nothing to decide.
  self?: boolean;
}

// What `decide()` answers. `refusal` says which kind, so each door can speak
// its own protocol's error: `subject` and `intermediary` and `no-target` are
// RFC 8693's invalid_request, `target` is its invalid_target, `xacml` is the
// deny-only layer; WS-Trust answers every one with wst:RequestFailed.
interface Decision {
  allowed: boolean;
  enforced: boolean;
  refusal: '' | 'subject' | 'intermediary' | 'impersonation' | 'target' |
           'no-target' | 'xacml';
  why: string;
  authorizedBy: string;
  attribute: string;
  intermediary: string;
  targets: Array<{ asked: string; application: string }>;
}

class DelegationPolicy {
  static readonly ATTRIBUTES = Object.freeze({
    DELEGATE_TO: 'appAllowedToDelegateTo',
    ACT_ON_BEHALF_OF: 'appAllowedToActOnBehalfOf',
    SUBJECT_GROUP: 'appDelegationSubjectGroup',
    IMPERSONATE: 'appTrustedToImpersonate'
  });

  constructor(private readonly deps: DelegationPolicyDeps) {
    deps.log.debug("Entering DelegationPolicy.constructor().");
    deps.log.debug("Leaving DelegationPolicy.constructor().");
  }

  static defaultDeps(): DelegationPolicyDeps {
    helpers.log.debug("Entering DelegationPolicy.defaultDeps().");
    helpers.log.debug("Leaving DelegationPolicy.defaultDeps().");
    return {
      log: helpers.log,
      config: config,
      mode: mode,
      applications: applications,
      credentials: credentials,
      gate: gate
    };
  }

  // Every value of one attribute on an application view, as strings.
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
  static normalizeDn(value: unknown): string {
    helpers.log.debug("Entering DelegationPolicy.normalizeDn().");
    helpers.log.debug("Leaving DelegationPolicy.normalizeDn().");
    return String(value == null ? '' : value).trim().split(',')
      .map(function (part) { return part.trim().toLowerCase(); }).join(',');
  }

  // The application an identifier, client_id or name belongs to, or null.
  applicationFor(name: string): Json {
    const { log, applications } = this.deps;
    log.debug("Entering DelegationPolicy.applicationFor(). name=" + name);
    const wanted = String(name || '').trim();
    if (!wanted) {
      log.debug("Leaving DelegationPolicy.applicationFor(). Nothing asked.");
      return null;
    }
    const found = applications.get(wanted) ||
      applications.forClientId(wanted) || null;
    log.debug("Leaving DelegationPolicy.applicationFor(). " +
              (found ? found.identifier : 'None.'));
    return found;
  }

  // A target string resolved to the application that registered it — the
  // lookup `oauth2.ts` and `wstrust.ts` already make to file the act.
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

  // Is this subject PROTECTED — never delegated whatever any application
  // says? Answers the sentence that says why, or ''.
  protectedBecause(facts: Json, subject: string): string {
    const { log } = this.deps;
    log.debug("Entering DelegationPolicy.protectedBecause().");
    if (facts && facts.notDelegated) {
      log.debug("Leaving DelegationPolicy.protectedBecause(). The flag.");
      return '"' + subject + '" carries stsNotDelegated — "sensitive and ' +
             'cannot be delegated" — so nobody may act for them.';
    }
    const roster = this.rosterGroups().map(function (one) {
      return one.toLowerCase();
    });
    const hit = ((facts && facts.groups) || []).filter(function (group) {
      const cn = String(group.cn || '').toLowerCase();
      const dn = DelegationPolicy.normalizeDn(group.dn);
      return roster.some(function (name) {
        return cn === name || dn === DelegationPolicy.normalizeDn(name) ||
               dn.indexOf('cn=' + name + ',') === 0;
      });
    })[0];
    if (hit) {
      log.debug("Leaving DelegationPolicy.protectedBecause(). The roster.");
      return '"' + subject + '" is a member of ' + (hit.cn || hit.dn) +
             ', a console administrator roster, and an administrator is ' +
             'never delegated.';
    }
    log.debug("Leaving DelegationPolicy.protectedBecause(). Not protected.");
    return '';
  }

  // -------------------------------------------------------------------------
  // THE DECISION. Mode-free: `enforced` says whether a refusal refuses.
  // -------------------------------------------------------------------------
  decide(question: DecideQuestion): Decision {
    const { log, credentials, gate } = this.deps;
    const self = this;
    log.debug("Entering DelegationPolicy.decide(). " + question.protocol +
              " " + question.mode + " by " + question.intermediary + " for " +
              question.subject);
    const enforced = this.deps.mode.authorizesDelegation();
    const A = DelegationPolicy.ATTRIBUTES;
    const answer: Decision = {
      allowed: false, enforced: enforced, refusal: '', why: '',
      authorizedBy: '', attribute: '',
      intermediary: String(question.intermediary || ''), targets: []
    };
    const refuse = function (kind: Decision['refusal'], why: string,
                             attribute?: string): Decision {
      log.debug("Entering refuse().");
      answer.refusal = kind;
      answer.why = why;
      answer.attribute = attribute || '';
      log.info('delegation_policy: ' + (enforced ? 'REFUSED' :
               'would have refused (development records it)') + ' ' +
               question.protocol + ' ' + question.mode + ' by "' +
               question.intermediary + '" for "' + question.subject + '": ' +
               why);
      log.debug("Leaving refuse().");
      return answer;
    };

    if (question.self) {
      answer.allowed = true;
      answer.authorizedBy = 'nothing was needed: the subject is "' +
        question.intermediary + '" itself, so nobody is being acted for.';
      log.debug("Leaving DelegationPolicy.decide(). Self.");
      return answer;
    }

    // 1. THE SUBJECT, first, because a protected subject is refused whoever
    //    asks and whatever any application says — NOT_DELEGATED's rule.
    const facts = credentials.delegationFactsFor(question.subject) || {};
    const protectedWhy = this.protectedBecause(facts, question.subject);
    if (protectedWhy) {
      log.debug("Leaving DelegationPolicy.decide(). Protected subject.");
      return refuse('subject', protectedWhy, 'stsNotDelegated');
    }

    // 2. THE INTERMEDIARY must be an application entry.
    const intermediary = this.applicationFor(question.intermediary);
    if (!intermediary) {
      log.debug("Leaving DelegationPolicy.decide(). No intermediary entry.");
      return refuse('intermediary', '"' + question.intermediary + '" has no ' +
        'application entry in this realm, and only an application may act ' +
        'for somebody else — its entry is where the permission to do so ' +
        'lives (appAllowedToDelegateTo).');
    }
    answer.intermediary = String(intermediary.identifier);
    const reasons: string[] = [];

    // 3. IMPERSONATION needs the stronger permission, unless the subject's own
    //    may_act named this party.
    const trusted = DelegationPolicy.valuesOf(intermediary, A.IMPERSONATE)
      .some(function (one) { return one.toUpperCase() === 'TRUE'; });
    if (question.mode === 'impersonation') {
      if (question.mayActHonoured) {
        reasons.push('the subject_token\'s may_act names this actor, so it ' +
                     'may act without appTrustedToImpersonate');
      } else if (!trusted) {
        log.debug("Leaving DelegationPolicy.decide(). Not trusted.");
        return refuse('impersonation', '"' + answer.intermediary + '" ' +
          'asked to IMPERSONATE "' + question.subject + '" (' +
          (question.protocol === 'WS-Trust' ? '<wst:OnBehalfOf>'
            : 'a token exchange with no actor_token') + ') and its entry ' +
          'does not carry appTrustedToImpersonate TRUE. Delegation (' +
          (question.protocol === 'WS-Trust' ? '<wst14:ActAs>'
            : 'an actor_token') + ') needs no such flag.', A.IMPERSONATE);
      } else {
        reasons.push('appTrustedToImpersonate TRUE on "' +
                     answer.intermediary + '"');
      }
    }

    // 4. THE SUBJECT GROUPS, when the intermediary names any.
    const groups = DelegationPolicy.valuesOf(intermediary, A.SUBJECT_GROUP);
    if (groups.length && !question.mayActHonoured) {
      const held = ((facts && facts.groups) || []).map(function (one) {
        return DelegationPolicy.normalizeDn(one.dn);
      });
      const matched = groups.filter(function (dn) {
        return held.indexOf(DelegationPolicy.normalizeDn(dn)) >= 0;
      })[0];
      if (!matched) {
        log.debug("Leaving DelegationPolicy.decide(). Not in a group.");
        return refuse('subject', '"' + question.subject + '" is in none of ' +
          'the groups "' + answer.intermediary + '" may act for (' +
          'appDelegationSubjectGroup: ' + groups.join('; ') + ').',
          A.SUBJECT_GROUP);
      }
      reasons.push('"' + question.subject + '" is in ' + matched +
                   ' (appDelegationSubjectGroup)');
    } else if (question.mayActHonoured) {
      reasons.push('the subject named this actor in may_act');
    }

    // 5. EVERY TARGET, by either attribute.
    const asked = (question.targets || []).map(function (one) {
      return String(one || '').trim();
    }).filter(function (one) { return !!one; });
    if (!asked.length) {
      log.debug("Leaving DelegationPolicy.decide(). No target.");
      return refuse('no-target', 'The request names no target (' +
        (question.protocol === 'WS-Trust' ? 'no AppliesTo'
          : 'neither audience nor resource') + '), so there is nothing the ' +
        'delegation policy could allow: a token about somebody else with no ' +
        'audience restriction is one no attribute describes.',
        A.DELEGATE_TO);
    }
    const delegateTo = DelegationPolicy.valuesOf(intermediary, A.DELEGATE_TO);
    for (let i = 0; i < asked.length; i++) {
      const target = asked[i];
      const application = self.resolveTarget(target, question.targetKind);
      answer.targets.push({ asked: target, application: application });
      if (delegateTo.indexOf(target) >= 0 ||
          (application && delegateTo.indexOf(application) >= 0)) {
        reasons.push('appAllowedToDelegateTo on "' + answer.intermediary +
                     '" names ' + (application || target));
        continue;
      }
      const targetRow = application ? self.applicationFor(application) : null;
      const accepts = targetRow
        ? DelegationPolicy.valuesOf(targetRow, A.ACT_ON_BEHALF_OF) : [];
      if (accepts.indexOf(answer.intermediary) >= 0 ||
          accepts.indexOf(String(question.intermediary)) >= 0) {
        reasons.push('appAllowedToActOnBehalfOf on "' + application +
                     '" names ' + answer.intermediary);
        continue;
      }
      log.debug("Leaving DelegationPolicy.decide(). A target is not allowed.");
      return refuse('target', 'Nothing allows "' + answer.intermediary +
        '" to reach "' + target + '"' + (application && application !==
          target ? ' (the application "' + application + '")' : '') +
        ' on somebody else\'s behalf: neither appAllowedToDelegateTo on "' +
        answer.intermediary + '" nor appAllowedToActOnBehalfOf on ' +
        (application ? '"' + application + '"' : 'an application ' +
          'registered for it') + ' names the other.', A.DELEGATE_TO);
    }

    // 6. THE DENY-ONLY XACML LAYER, once per target.
    for (let i = 0; i < answer.targets.length; i++) {
      const one = answer.targets[i];
      const xacml = gate.checkDelegation({
        intermediary: answer.intermediary, subject: question.subject,
        target: one.application || one.asked, mode: question.mode,
        protocol: question.protocol });
      if (xacml && !xacml.allowed) {
        log.debug("Leaving DelegationPolicy.decide(). XACML denied it.");
        return refuse('xacml', xacml.why || 'The issuance policy denies ' +
                      'this delegation (action-id delegate).');
      }
    }

    answer.allowed = true;
    answer.authorizedBy = reasons.join('; ') + '.';
    log.debug("Leaving DelegationPolicy.decide(). Allowed: " +
              answer.authorizedBy);
    return answer;
  }

  // The sentence the act's row carries in `authorizedBy` for either answer —
  // so the page says what allowed an act, what refused it, and in
  // development what WOULD have refused it.
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
  mayActClaimFor(username: string): Json {
    const { log, credentials } = this.deps;
    log.debug("Entering DelegationPolicy.mayActClaimFor().");
    const name = String(username || '').trim();
    if (!name) {
      log.debug("Leaving DelegationPolicy.mayActClaimFor(). Nobody.");
      return null;
    }
    const facts = credentials.delegationFactsFor(name);
    if (!facts || !facts.person || !facts.mayAct) {
      log.debug("Leaving DelegationPolicy.mayActClaimFor(). None named.");
      return null;
    }
    const delegate = facts.delegate;
    if (delegate && delegate.kind === 'person' && delegate.sub) {
      log.debug("Leaving DelegationPolicy.mayActClaimFor(). A person.");
      return { sub: delegate.sub };
    }
    if (delegate && delegate.kind === 'application') {
      const row = this.applicationByDn(delegate.dn);
      if (row) {
        const clientIds = DelegationPolicy.valuesOf(row, 'oauthClientId');
        log.debug("Leaving DelegationPolicy.mayActClaimFor(). An " +
                  "application.");
        return { sub: clientIds[0] || String(row.identifier) };
      }
    }
    log.debug("Leaving DelegationPolicy.mayActClaimFor(). The delegate " +
              "names nothing here.");
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
      const trusted = DelegationPolicy.valuesOf(row, A.IMPERSONATE)
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
              A.IMPERSONATE).some(function (one) {
              return one.toUpperCase() === 'TRUE';
            }) : false,
            subjectGroups: found ? DelegationPolicy.valuesOf(found,
              A.SUBJECT_GROUP) : [],
            targetKnown: true,
            warning: known(who) ? '' : 'No application here is called "' +
              who + '", so nothing can act under that name.' });
        });
      if (trusted || groups.length) {
        intermediaries.push({ application: row.identifier,
                              trustedToImpersonate: trusted,
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
             protectedGroups: this.rosterGroups(),
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

export = {
  DelegationPolicy: DelegationPolicy,
  installInstance: (instance: DelegationPolicy): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  ATTRIBUTES: DelegationPolicy.ATTRIBUTES,
  mayActNames: DelegationPolicy.mayActNames,
  decide: slot.forward('decide'),
  rowText: slot.forward('rowText'),
  mayActClaimFor: slot.forward('mayActClaimFor'),
  list: slot.forward('list'),
  resolveTarget: slot.forward('resolveTarget'),
  applicationFor: slot.forward('applicationFor')
};
