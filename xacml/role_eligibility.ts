// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: role_eligibility.ts
//
// ===========================================================================
// WHO MAY BE OFFERED A DYNAMIC SELECTABLE ROLE (#1072, phase P2).
//
// A dynamic selectable role (`common/roles.js`, DYNAMIC SELECTABLE ROLES) is
// held by nobody. A person is OFFERED it at sign-in when the role's own
// XACML policy permits them, and keeps it on a token only while the policy
// still does. rcbj's decision of 2026-11-20: **XACML is the policy language
// and the PDP the decider**; no expression language of its own and no
// second engine. This module is that question, and the policy's lifecycle:
//
//   setPolicy(role, …)   the role's OWN policy, written from XACML XML or
//                        ALFA into ou=policies with `xacmlRole`, and named
//                        on the role as `roleEligibilityPolicy`
//   removePolicy(role)   on the role's deletion: its policy goes with it
//   resolve(role)        the role and its policy, parsed, or a coded failure
//   decide(question)     one person, one role, one stage: eligible or not
//   offer(question)      every dynamic role of the realm a sign-in to that
//                        application may be offered, each decided
//   test(role, user, …)  an administrator's dry run, with what the PDP said
//
// **IT IS fga_pep.ts'S ARRANGEMENT (#564)**: an OWNED policy, decided ALONE
// by `xacml.ts`'s `decidePolicy()` with no PolicyIdReference map — never the
// realm's root, never in the map, never sent to a remote PEP
// (`xacml_store.ts`'s `owned()`), because the policy is written for ONE
// question and a Permit in it means "may choose this role", nothing else.
//
// **ONLY PERMIT IS ELIGIBLE** (the ticket's section 5.2, fail closed).
// `enforce()`'s deny-biased reading: Deny, NotApplicable, an Indeterminate
// over a missing attribute, an obligation this PEP cannot discharge, a
// missing or disabled or unparseable policy, a role that is not dynamic, and
// a throw all answer NOT ELIGIBLE, each under its own code so the audit row
// says which. AND/OR semantics are the policy's own: its rules and their
// combining algorithm, which XACML 3.0 defines deterministically.
//
// **THE RESOURCE BOUNDARY IS THE ROLE'S, ASKED HERE BEFORE THE POLICY**: a
// role that belongs to an application (`roleApplication`, #310) is offered
// only on a sign-in to THAT application, whatever its policy says, so a
// policy cannot carry a role across applications by forgetting to check.
// A realm-wide role is offered on a sign-in to any application. The realm
// boundary is the ambient realm's: every read here is the current realm's
// directory and policy store.
//
// ONE AUDIT ROW per offer and per test (`roles.eligibility`): the role, the
// person, the application, the stage, the outcome and its code, and the
// policy's entry name — NEVER the policy's text or the person's attributes.
// The `issue` stage, asked at every issuance that carries a chosen role, is
// audited only where it drops one (`authn/role_selection.ts`), so a busy
// realm's log is a record of decisions that changed something.
// ===========================================================================
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');

const { log } = helpers;

// The longest slug kept in an entry name, which the store bounds at 128.
const MAX_SLUG = 80;

// One role row, as `roles.read()` answers it (the members this reads).
interface RoleRow {
  name: string;
  application: string;
  localName: string;
  displayName: string;
  description: string;
  membershipMode: string;
  eligibilityPolicy: string;
  selection: string;
  exclusiveGroup: string;
  [name: string]: any;
}

// One policy row, as `xacml_store.ts` answers it (the members this reads).
interface PolicyRow {
  name: string;
  id: string | null;
  version: string;
  enabled: boolean;
  document: string;
  role?: string | null;
  [name: string]: any;
}

// What every refusal and resolution answers.
interface EligibilityResult {
  ok: boolean;
  why?: string;
  failure?: string;
  role?: RoleRow | null;
  row?: PolicyRow | null;
  parsed?: any;
  policy?: string;
  created?: boolean;
  [name: string]: any;
}

// One question.
interface EligibilityQuestion {
  role: string;
  username: string;
  application?: string;
  clientId?: string;
  stage?: string;
  protocol?: string;
  acr?: string;
  amr?: string[];
  actor?: string;
}

// One answer. `eligible` is the whole decision; the rest is for the audit
// row and the administrator's test.
interface EligibilityAnswer {
  eligible: boolean;
  code: string;
  why: string;
  decision?: string;
  status?: any;
  policy?: string;
  policyId?: string;
  policies?: string[];
}

interface EligibilityDeps {
  log: { debug(message: string): void; warn(message: string): void;
         error(message: string): void };
  errorCodes: {
    tag(code: string): string;
    mark<T>(target: T, code: string): T;
    codeOf(result: unknown): string;
  };
  audit: { audit(row: Record<string, unknown>): unknown };
  realms: { currentId(): string };
  roles: {
    read(name: string): RoleRow | null;
    write(name: string, record: Record<string, any>): any;
    isDynamic(row: RoleRow | null): boolean;
    dynamicRoles(): RoleRow[];
  };
  store: {
    read(name: string): PolicyRow | null;
    write(name: string, document: string, options: object): any;
    remove(name: string): boolean;
    parseDocument(document: string): any;
  };
  xml: { writePolicy(policy: any): string };
  alfa: { parse(text: string): any };
  slug(text: unknown): string;
  sha256Hex(text: string): string;
  // `xacml.ts`, read inside a decision: it requires the store and this
  // module is built before it at 23c.
  loadXacml(): { decidePolicy(policy: any, request: any, options?: any): any;
                 enforce(answer: any, bias?: string): any };
  request: { AuthorizationRequest: any };
  // The application registry and the settings (#1072's follow-ups): which
  // entry a protocol's own name for an application is, and whether dynamic
  // roles are offered for it.
  applications: {
    get(identifier: string): any;
    forClientId(clientId: string): any;
    forAppliesTo(appliesTo: string): any;
    forServicePrincipal(spn: string): any;
    settingFor(identifier: string, key: string, config: any): any;
  };
  config: any;
}

class RoleEligibility {
  /**
   * Builds the module over its dependencies.
   *
   * @param deps - the logger, error codes, the audit log, the realms, the
   *   role register, the policy store, the XML writer, the ALFA reader, a
   *   slug and a SHA-256, the XACML surface (lazily) and the request builder
   */
  constructor(private readonly deps: EligibilityDeps) {
    deps.log.debug("Entering RoleEligibility.constructor().");
    deps.log.debug("Leaving RoleEligibility.constructor().");
  }

  /**
   * The dependencies built from the real modules.
   *
   * @returns the dependencies
   */
  static defaultDeps(): EligibilityDeps {
    log.debug("Entering RoleEligibility.defaultDeps().");
    const crypto: typeof import('../common/crypto') =
      require('../common/crypto');
    const templates = require('./xacml_templates');
    log.debug("Leaving RoleEligibility.defaultDeps().");
    return {
      log: log,
      errorCodes: require('../common/error_codes'),
      audit: require('../common/audit'),
      realms: require('../common/realms'),
      roles: require('../common/roles'),
      store: require('./xacml_store'),
      xml: require('./xacml_xml'),
      alfa: require('./xacml_alfa'),
      slug: function (text: unknown): string {
        return templates.slug(text);
      },
      sha256Hex: function (text: string): string {
        return crypto.digest('sha256', text, 'hex');
      },
      loadXacml: function (): any {
        log.debug("Entering loadXacml().");
        log.debug("Leaving loadXacml().");
        return require('./xacml');
      },
      request: require('./xacml_request'),
      applications: require('../common/applications'),
      config: require('../common/config')
    };
  }

  // -------------------------------------------------------------------------
  // THE APPLICATION, BY ITS REGISTRY IDENTIFIER (#1072's follow-ups). A
  // sign-in names its application in its protocol's own words — a
  // client_id, a service provider's entityID, a wtrealm, a Kerberos service
  // principal — and a role's `roleApplication`, the per-application setting
  // and the applications a token is for are all the registry IDENTIFIER.
  // Where the two differ, a choice was recorded under one name and looked
  // for under the other, and dropped. So every reader here resolves the
  // name once, the way `admin_stats.js`'s claimApplicationsOf() does: the
  // identifier itself, then a client_id, an AppliesTo or entityID, a
  // service principal. A name nothing registered is itself, as before.
  // -------------------------------------------------------------------------
  /**
   * Resolves a protocol's name for an application to its registry
   * identifier.
   *
   * @param raw - an identifier, client_id, entityID, AppliesTo, wtrealm or
   *   service principal
   * @returns the identifier, or `raw` trimmed where nothing registered it
   */
  applicationOf(raw: unknown): string {
    const { log, applications } = this.deps;
    const wanted = String(raw == null ? '' : raw).trim();
    log.debug("Entering RoleEligibility.applicationOf(). " + wanted);
    if (!wanted) {
      log.debug("Leaving RoleEligibility.applicationOf(). None.");
      return '';
    }
    let found: any = null;
    try {
      found = (applications.get(wanted) && { identifier: wanted }) ||
              applications.forClientId(wanted) ||
              applications.forAppliesTo(wanted) ||
              applications.forServicePrincipal(wanted);
    } catch (e) {
      // A registry that cannot be read names no entry: the name stands as
      // given, which is what every reader here used before.
      log.debug("Caught in RoleEligibility.applicationOf(): " +
                ((e && e.message) || e));
      found = null;
    }
    const out = found && found.identifier ? String(found.identifier)
                                          : wanted;
    log.debug("Leaving RoleEligibility.applicationOf(). " + out);
    return out;
  }

  /**
   * Whether dynamic roles are offered and carried for an application:
   * `roles.dynamicSelection`, with the application's
   * `appDynamicRoleSelection` overriding it (rcbj's decision 2). With no
   * application, the realm's setting.
   *
   * @param application - the application, in any of its names
   * @returns true when on
   */
  selectionOn(application: unknown): boolean {
    const { log, applications, config } = this.deps;
    log.debug("Entering RoleEligibility.selectionOn().");
    let on = false;
    try {
      on = applications.settingFor(this.applicationOf(application),
                                   'roles.dynamicSelection', config) === true;
    } catch (e) {
      log.debug("Caught in RoleEligibility.selectionOn(): " +
                ((e && e.message) || e));
      on = false;
    }
    log.debug("Leaving RoleEligibility.selectionOn(). " + on);
    return on;
  }

  // -------------------------------------------------------------------------
  // A REQUIRED ROLE THIS PERSON WOULD HAVE TO CHOOSE (rcbj's decisions 3 and
  // 5): every `required` dynamic role a sign-in to this application would
  // offer them — the realm-wide ones and the application's own, each
  // decided as the offer decides it. The role step draws the same answer
  // (`offer()`, then `required`); this is it for a flow that cannot draw
  // the step, which is refused where it is non-empty, and for single sign-on
  // into an application the session chose nothing for. Not audited per
  // role: the caller audits the refusal it makes of it.
  //
  // With no application, the realm-wide roles alone: a bind to the
  // directory, a ticket-granting ticket and a certificate sign-in name no
  // application, and a required realm-wide role is asked of every sign-in.
  // -------------------------------------------------------------------------
  /**
   * Lists the required dynamic roles a person would be offered for an
   * application.
   *
   * @param question - the person (`username`), the `application` in any of
   *   its names, and the sign-in's `acr`, `amr`, `clientId` and `protocol`
   * @returns `{ required, application, roles }`: the resolved application
   *   and the required roles' names, `required` true where there is one
   */
  requiredFor(question: Omit<EligibilityQuestion, 'role'>):
      { required: boolean; application: string; roles: string[] } {
    const { log, roles } = this.deps;
    const asked = question || ({} as EligibilityQuestion);
    const application = this.applicationOf(asked.application);
    log.debug("Entering RoleEligibility.requiredFor(). application=" +
              (application || '(none)'));
    const none = { required: false, application: application,
                   roles: [] as string[] };
    if (!String(asked.username || '').trim() ||
        !this.selectionOn(application)) {
      log.debug("Leaving RoleEligibility.requiredFor(). Not asked here.");
      return none;
    }
    const self = this;
    const out: string[] = [];
    roles.dynamicRoles().filter(function (role) {
      return role.selection === 'required' &&
        (!role.application || role.application === application);
    }).forEach(function (role) {
      const answer = self.decide(Object.assign({}, asked, {
        role: role.name, application: application, stage: 'offer' }));
      if (answer.eligible) {
        out.push(role.name);
      }
    });
    log.debug("Leaving RoleEligibility.requiredFor(). " + out.length +
              " required.");
    return { required: out.length > 0, application: application,
             roles: out };
  }

  // A refusal, coded, naming which failure it is.
  private refused(code: string, failure: string, why: string,
                  extra?: Partial<EligibilityResult>): EligibilityResult {
    const { log, errorCodes } = this.deps;
    log.debug("Entering RoleEligibility.refused(). " + code);
    log.debug("Leaving RoleEligibility.refused().");
    return errorCodes.mark(Object.assign({ ok: false, failure: failure,
                                           why: why }, extra || {}), code);
  }

  // -------------------------------------------------------------------------
  // THE ENTRY NAME: `role-`, a slug of the role's name for a reader, and the
  // first twelve hex digits of its SHA-256 because the slug is lossy —
  // `fga_policies.ts`'s `nameFor()`.
  // -------------------------------------------------------------------------
  /**
   * Returns the entry name a role's eligibility policy is given.
   *
   * @param role - the role's name
   * @returns `role-<slug>-<12 hex digits>`
   */
  nameFor(role: string): string {
    const { log, slug, sha256Hex } = this.deps;
    log.debug("Entering RoleEligibility.nameFor().");
    const text = slug(role).slice(0, MAX_SLUG).replace(/-+$/, '') || 'x';
    const name = 'role-' + text + '-' + sha256Hex(String(role)).slice(0, 12);
    log.debug("Leaving RoleEligibility.nameFor(). " + name);
    return name;
  }

  // -------------------------------------------------------------------------
  // THE POLICY. Written from XACML XML or from ALFA, which is compiled to the
  // model and written as XML, as the policy editor's import does: the store
  // holds one representation. The entry carries `xacmlRole`, so the store
  // keeps it out of the root, the map and every pull; the role carries the
  // entry's name. A role keeps ONE entry name across rewrites, so every
  // audit row that named it still does.
  // -------------------------------------------------------------------------
  /**
   * Writes a dynamic role's eligibility policy.
   *
   * @param roleName - the role's name
   * @param source - `document` (XACML XML) or `alfa` (ALFA text), one of them
   * @param options - `actor`
   * @returns `{ ok, policy, created }`, or a refusal: no such role
   *   (STS-XACML-0311), a static role (0312), neither or both sources
   *   (0321), ALFA that does not parse (STS-XACML-0037), a document the
   *   store refused (its code), a reference the role would not take (0322)
   */
  setPolicy(roleName: string, source: { document?: string; alfa?: string },
            options?: { actor?: string }): EligibilityResult {
    const { log, roles, store, xml, alfa, audit, errorCodes } = this.deps;
    const name = String(roleName || '');
    const actor = (options && options.actor) || '';
    log.debug("Entering RoleEligibility.setPolicy(). role=" + name);
    const role = roles.read(name);
    if (!role) {
      log.debug("Leaving RoleEligibility.setPolicy(). No such role.");
      return this.refused('STS-XACML-0311', 'unknown-role',
                          'There is no role called "' + name + '".');
    }
    if (!roles.isDynamic(role)) {
      log.debug("Leaving RoleEligibility.setPolicy(). A static role.");
      return this.refused('STS-XACML-0312', 'static-role',
                          '"' + name + '" is a static role, held by its ' +
                          'members; only a dynamic selectable role has an ' +
                          'eligibility policy. Make it dynamic first ' +
                          '(set-membership-mode).');
    }
    const given = source || {};
    const hasDocument = String(given.document || '').trim() !== '';
    const hasAlfa = String(given.alfa || '').trim() !== '';
    if (hasDocument === hasAlfa) {
      log.debug("Leaving RoleEligibility.setPolicy(). One source, please.");
      return this.refused('STS-XACML-0321', 'no-source',
                          'An eligibility policy is given as `document` ' +
                          '(XACML 3.0 XML) or as `alfa` (ALFA), exactly one.');
    }
    let document = String(given.document || '');
    let description = 'The eligibility policy of the dynamic role "' + name +
                      '" (#1072).';
    if (hasAlfa) {
      let policy;
      try {
        policy = alfa.parse(String(given.alfa));
      } catch (error) {
        log.debug("Caught in RoleEligibility.setPolicy(): " +
                  ((error && error.message) || error));
        log.debug("Leaving RoleEligibility.setPolicy(). The ALFA would not " +
                  "parse.");
        return errorCodes.mark({ ok: false, failure: 'unparseable',
                                 why: (error && error.message) ||
                                      String(error) }, 'STS-XACML-0037');
      }
      document = xml.writePolicy(policy);
      description = policy.description || description;
    }
    const own = this.ownPolicy(role);
    const entry = own ? own.name : this.nameFor(name);
    const written = store.write(entry, document, {
      enabled: true, isRoot: false, description: description, role: name,
      application: null });
    if (!written.ok) {
      log.debug("Leaving RoleEligibility.setPolicy(). The store refused.");
      return Object.assign({ failure: 'not-written' }, written);
    }
    if (role.eligibilityPolicy !== entry) {
      const referenced = roles.write(name, {
        description: role.description, users: role.users,
        groups: role.groups, applications: role.applications,
        permissions: role.permissions, application: role.application,
        displayName: role.displayName, memberTypes: role.memberTypes,
        eligibilityPolicy: entry });
      if (!referenced.ok) {
        // TAKEN BACK when it was new, so that a policy carrying the role's
        // name that nothing names is never left behind (ensure()'s rule).
        if (!own) {
          store.remove(entry);
        }
        log.debug("Leaving RoleEligibility.setPolicy(). The role refused " +
                  "the reference.");
        return this.refused('STS-XACML-0322', 'not-referenced',
                            referenced.why || 'The role would not take the ' +
                            'reference to its eligibility policy.');
      }
    }
    audit.audit({ action: 'xacml.policy.write', actor: actor,
                  protocol: 'XACML', target: name,
                  detail: (own ? 'Rewrote "' : 'Created "') + entry +
                          '", the eligibility policy of the dynamic role "' +
                          name + '"' + (hasAlfa ? ', from ALFA.' : '.') });
    log.debug("Leaving RoleEligibility.setPolicy(). " + entry);
    return { ok: true, policy: entry, created: !own, id: written.id };
  }

  // The role's OWN policy through its reference, or null: the entry its
  // `roleEligibilityPolicy` names, carrying the role's name in `xacmlRole`.
  // A policy that merely carries the name is never adopted (`ensure()`'s
  // rule in fga_policies.ts): a role deleted through LDAP and created again
  // would otherwise inherit the policy written for the one that went.
  private ownPolicy(role: RoleRow): PolicyRow | null {
    const { log, store } = this.deps;
    log.debug("Entering RoleEligibility.ownPolicy().");
    const row = role.eligibilityPolicy ? store.read(role.eligibilityPolicy)
                                       : null;
    const own = !!row && row.role === role.name;
    log.debug("Leaving RoleEligibility.ownPolicy(). " +
              (own ? 'Own.' : 'None.'));
    return own ? row : null;
  }

  /**
   * Removes a role's eligibility policy, on the role's deletion. A policy
   * the role names but does not own is left alone.
   *
   * @param roleName - the deleted role's name
   * @param policy - the name its `roleEligibilityPolicy` carried
   * @param options - `actor`
   * @returns true when a policy was removed
   */
  removePolicy(roleName: string, policy: string,
               options?: { actor?: string }): boolean {
    const { log, store, audit } = this.deps;
    log.debug("Entering RoleEligibility.removePolicy(). role=" + roleName);
    const row = policy ? store.read(policy) : null;
    if (!row || row.role !== String(roleName)) {
      log.debug("Leaving RoleEligibility.removePolicy(). Not its own.");
      return false;
    }
    const removed = store.remove(row.name);
    if (removed) {
      audit.audit({ action: 'xacml.policy.delete',
                    actor: (options && options.actor) || '',
                    protocol: 'XACML', target: String(roleName),
                    detail: 'Removed "' + row.name + '", the eligibility ' +
                            'policy of the deleted role "' + roleName + '".' });
    }
    log.debug("Leaving RoleEligibility.removePolicy(). " + removed);
    return removed;
  }

  /**
   * Resolves a dynamic role and its eligibility policy, parsed.
   *
   * @param roleName - the role's name
   * @returns `{ ok: true, role, row, parsed, policy }`, or a refusal whose
   *   `failure` is `unknown-role` (STS-XACML-0311), `static-role` (0312),
   *   `no-policy` (0313), `missing-policy` (0314), `not-its-policy` (0315),
   *   `disabled-policy` (0316) or `unparseable-policy` (0317)
   */
  resolve(roleName: string): EligibilityResult {
    const { log, roles, store, errorCodes } = this.deps;
    const name = String(roleName || '');
    log.debug("Entering RoleEligibility.resolve(). role=" + name);
    const role = roles.read(name);
    if (!role) {
      log.debug("Leaving RoleEligibility.resolve(). No such role.");
      return this.refused('STS-XACML-0311', 'unknown-role',
                          'There is no role called "' + name + '".');
    }
    if (!roles.isDynamic(role)) {
      log.debug("Leaving RoleEligibility.resolve(). Static.");
      return this.refused('STS-XACML-0312', 'static-role',
                          '"' + name + '" is not a dynamic selectable role.',
                          { role: role });
    }
    if (!role.eligibilityPolicy) {
      log.debug("Leaving RoleEligibility.resolve(). No policy.");
      return this.refused('STS-XACML-0313', 'no-policy',
                          'The dynamic role "' + name + '" has no ' +
                          'eligibility policy, so nobody is eligible for it.',
                          { role: role });
    }
    const row = store.read(role.eligibilityPolicy);
    if (!row) {
      log.debug("Leaving RoleEligibility.resolve(). Not in ou=policies.");
      return this.refused('STS-XACML-0314', 'missing-policy',
                          'The eligibility policy "' +
                          role.eligibilityPolicy + '" of the role "' + name +
                          '" is not in ou=policies.', { role: role });
    }
    if (row.role !== name) {
      log.debug("Leaving RoleEligibility.resolve(). Not its own.");
      return this.refused('STS-XACML-0315', 'not-its-policy',
                          'The policy "' + row.name + '" that the role "' +
                          name + '" names is not its own (xacmlRole is ' +
                          (row.role ? '"' + row.role + '"' : 'absent') +
                          ').', { role: role, row: row });
    }
    if (!row.enabled) {
      log.debug("Leaving RoleEligibility.resolve(). Disabled.");
      return this.refused('STS-XACML-0316', 'disabled-policy',
                          'The eligibility policy "' + row.name + '" of the ' +
                          'role "' + name + '" is disabled.',
                          { role: role, row: row });
    }
    let parsed = null;
    try {
      parsed = store.parseDocument(row.document);
    } catch (error) {
      log.debug("Caught in RoleEligibility.resolve(): " +
                ((error && error.message) || error));
      log.warn(errorCodes.tag('STS-XACML-0317') + 'role_eligibility: the ' +
               'eligibility policy "' + row.name + '" of the role "' + name +
               '" does not parse: ' + ((error && error.message) || error));
      log.debug("Leaving RoleEligibility.resolve(). Does not parse.");
      return this.refused('STS-XACML-0317', 'unparseable-policy',
                          'The eligibility policy "' + row.name + '" of the ' +
                          'role "' + name + '" does not parse.',
                          { role: role, row: row });
    }
    log.debug("Leaving RoleEligibility.resolve(). " + row.name);
    return { ok: true, role: role, row: row, parsed: parsed,
             policy: row.name };
  }

  // -------------------------------------------------------------------------
  // THE QUESTION.
  // -------------------------------------------------------------------------
  /**
   * Decides whether one person is eligible for one dynamic role, now.
   *
   * @param question - the role, the person's username, the application the
   *   sign-in is for, the client, the stage, the protocol, and the
   *   session's acr and amr
   * @returns `{ eligible, code, why, decision, status, policy, policyId,
   *   policies }`; never throws
   */
  decide(question: EligibilityQuestion): EligibilityAnswer {
    const { log, errorCodes } = this.deps;
    const asked = question || ({} as EligibilityQuestion);
    log.debug("Entering RoleEligibility.decide(). role=" + asked.role +
              ", stage=" + asked.stage);
    let answer: EligibilityAnswer;
    try {
      answer = this.evaluate(asked);
    } catch (e) {
      log.debug("Caught in RoleEligibility.decide(): " +
                ((e && e.message) || e));
      // A FAULT, AND NOT ELIGIBLE: nobody decided, and a fault never grants.
      log.error(errorCodes.tag('STS-XACML-0318') + 'role_eligibility: ' +
                'deciding the role "' + asked.role + '" threw: ' +
                ((e && e.stack) || e));
      answer = { eligible: false, code: 'STS-XACML-0318',
                 why: 'The eligibility decision could not be made.' };
    }
    log.debug("Leaving RoleEligibility.decide(). " +
              (answer.eligible ? 'Eligible.' : 'Not eligible: ' +
               answer.code));
    return answer;
  }

  // The boundary, the policy, the decision — each failure under its code.
  private evaluate(asked: EligibilityQuestion): EligibilityAnswer {
    const { log, errorCodes, realms } = this.deps;
    log.debug("Entering RoleEligibility.evaluate().");
    const username = String(asked.username || '').trim();
    if (!username) {
      log.debug("Leaving RoleEligibility.evaluate(). Nobody named.");
      return { eligible: false, code: 'STS-XACML-0319',
               why: 'No person was named, so nobody is eligible.' };
    }
    const resolved = this.resolve(asked.role);
    if (!resolved.ok) {
      const code = String(errorCodes.codeOf(resolved) || 'STS-XACML-0313');
      log.debug("Leaving RoleEligibility.evaluate(). Not resolved: " + code);
      return { eligible: false, code: code, why: resolved.why || '',
               policy: String((resolved.row && resolved.row.name) || '') };
    }
    const role = resolved.role;
    // By its registry identifier (#1072's follow-ups): a client_id that is
    // not the identifier names the same application here.
    const application = this.applicationOf(asked.application);
    if (role.application && role.application !== application) {
      log.debug("Leaving RoleEligibility.evaluate(). Another application's.");
      return { eligible: false, code: 'STS-XACML-0320',
               why: 'The role "' + role.name + '" belongs to the ' +
                    'application "' + role.application + '", and this ' +
                    'sign-in is for ' + (application
                      ? '"' + application + '"' : 'no application') + '.',
               policy: resolved.policy };
    }
    const built = new this.deps.request.AuthorizationRequest({})
      .roleEligibility({
      subject: username, role: role.name,
      roleApplication: role.application || undefined,
      application: application || undefined,
      clientId: asked.clientId || undefined, stage: asked.stage,
      protocol: asked.protocol, realm: realms.currentId(),
      acr: asked.acr || undefined, amr: asked.amr || [] }).build();
    // The applicable policies, for an administrator's test only: a sign-in
    // has no use for them.
    if (asked.stage === 'test') {
      built.returnPolicyIdList = true;
    }
    const xacml = this.deps.loadXacml();
    const decided = xacml.decidePolicy(resolved.parsed, built,
                                       { repository: null, resolve: true });
    const enforcement = xacml.enforce(decided, 'deny-biased');
    const decision = String((decided && decided.decision) || '');
    const known = { decision: decision, status: (decided && decided.status) ||
                    null, policy: resolved.policy,
                    policyId: String((resolved.row && resolved.row.id) || ''),
                    policies: ((decided && decided.policyIdentifiers) || [])
                      .map(function (one: any) {
                        return String((one && (one.id || one)) || '');
                      }) };
    if (String(errorCodes.codeOf(decided) || '') === 'STS-XACML-0013') {
      log.error(errorCodes.tag('STS-XACML-0318') + 'role_eligibility: the ' +
                'eligibility policy "' + resolved.policy + '" of the role "' +
                role.name + '" could not be evaluated: ' +
                String((decided.status && decided.status.message) || ''));
      log.debug("Leaving RoleEligibility.evaluate(). A fault.");
      return Object.assign({ eligible: false, code: 'STS-XACML-0318',
        why: 'The eligibility policy of "' + role.name + '" could not be ' +
             'evaluated.' }, known);
    }
    if (!enforcement.allowed) {
      log.debug("Leaving RoleEligibility.evaluate(). " + decision);
      return Object.assign({ eligible: false, code: 'STS-XACML-0319',
        why: 'The eligibility policy of "' + role.name + '" does not ' +
             'permit this person (' + enforcement.why + ')' }, known);
    }
    log.debug("Leaving RoleEligibility.evaluate(). Permit.");
    return Object.assign({ eligible: true, code: '',
      why: 'The eligibility policy of "' + role.name + '" permits this ' +
           'person.' }, known);
  }

  // One audit row: the decision, never the policy or the attributes.
  private recordDecision(asked: EligibilityQuestion,
                         answer: EligibilityAnswer): void {
    const { log, audit } = this.deps;
    log.debug("Entering RoleEligibility.recordDecision().");
    const row: Record<string, unknown> = {
      action: 'roles.eligibility', actor: asked.actor || asked.username || '',
      target: asked.role, protocol: 'XACML',
      detail: '"' + asked.username + '" is ' +
              (answer.eligible ? '' : 'not ') + 'eligible for the dynamic ' +
              'role "' + asked.role + '" (' + String(asked.stage || 'test') +
              (asked.application ? ', for "' + asked.application + '"' : '') +
              (answer.policy ? '; policy "' + answer.policy + '"' : '') +
              (answer.decision ? ', ' + answer.decision : '') + ')' };
    if (!answer.eligible && answer.code) {
      row.errorCode = answer.code;
    }
    audit.audit(row);
    log.debug("Leaving RoleEligibility.recordDecision().");
  }

  // -------------------------------------------------------------------------
  // THE OFFER: every dynamic role a sign-in to this application may carry —
  // the realm-wide ones and the application's own — each decided, in name
  // order. Only the eligible come back, with what the role step shows: the
  // name a token carries, the display name and the description; never the
  // policy, and never why another was not offered (the ticket's 6.2 and
  // 11.2). Each decision is audited, so "why was a role (not) offered" is a
  // question the log answers.
  // -------------------------------------------------------------------------
  /**
   * Lists the dynamic roles a person may be offered at sign-in.
   *
   * @param question - the person, the application, the client, the
   *   protocol and the session's acr and amr; `role` is ignored
   * @returns one row per eligible role: `name`, `localName`, `displayName`,
   *   `description`, `selection`, `exclusiveGroup`, `application`
   */
  offer(question: Omit<EligibilityQuestion, 'role'>): any[] {
    const { log, roles } = this.deps;
    const asked = Object.assign({}, question || {}) as EligibilityQuestion;
    // BY ITS REGISTRY IDENTIFIER (#1072's follow-ups), as the role's own
    // application and the token's applications are named.
    const application = this.applicationOf(asked.application);
    asked.application = application;
    log.debug("Entering RoleEligibility.offer(). application=" + application);
    const self = this;
    const out = [];
    roles.dynamicRoles().filter(function (role) {
      return !role.application || role.application === application;
    }).forEach(function (role) {
      const one = Object.assign({}, asked, { role: role.name,
                                             stage: 'offer' });
      const answer = self.decide(one);
      self.recordDecision(one, answer);
      if (answer.eligible) {
        out.push({ name: role.name, localName: role.localName || role.name,
                   displayName: role.displayName || '',
                   description: role.description || '',
                   selection: role.selection === 'required' ? 'required'
                                                            : 'optional',
                   exclusiveGroup: role.exclusiveGroup || '',
                   application: role.application || '' });
      }
    });
    log.debug("Leaving RoleEligibility.offer(). " + out.length +
              " eligible.");
    return out;
  }

  /**
   * An administrator's dry run (the ticket's 5.3): one role's eligibility
   * policy against one person, with what the PDP said. Audited.
   *
   * @param roleName - the role
   * @param username - the person
   * @param options - `application`, `acr`, `amr` and `actor`
   * @returns the answer, with the facts the request carried
   */
  test(roleName: string, username: string,
       options?: { application?: string; acr?: string; amr?: string[];
                   actor?: string }): Record<string, any> {
    const { log } = this.deps;
    const opts = options || {};
    log.debug("Entering RoleEligibility.test(). role=" + roleName);
    const asked: EligibilityQuestion = {
      role: String(roleName || ''), username: String(username || ''),
      application: opts.application || '', stage: 'test',
      acr: opts.acr || '', amr: opts.amr || [], actor: opts.actor || '' };
    const answer = this.decide(asked);
    this.recordDecision(asked, answer);
    const status = answer.status || null;
    log.debug("Leaving RoleEligibility.test(). " + answer.eligible);
    return {
      role: asked.role, username: asked.username,
      application: asked.application || null,
      eligible: answer.eligible, code: answer.code || null, why: answer.why,
      decision: answer.decision || null, policy: answer.policy || null,
      policyId: answer.policyId || null,
      // WHY, AS FAR AS THE PDP SAYS: its status (a missing attribute names
      // itself there, with its category) and the policies that applied.
      status: status ? { code: String(status.code || ''),
                         message: String(status.message || ''),
                         missing: status.detail && status.detail.attributeId
                           ? { attributeId: String(status.detail.attributeId),
                               category: String(status.detail.category ||
                                                '') }
                           : null } : null,
      applicable: answer.policies || [],
      asked: { stage: 'test', acr: asked.acr || null,
               amr: asked.amr || [] }
    };
  }
}

// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2) at 23c.
const slot = new InstanceSlot<RoleEligibility>(
  'xacml/role_eligibility',
  () => new RoleEligibility(RoleEligibility.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as every module on the pattern does.
slot.buildNowUnlessDeferred();

/**
 * Dynamic selectable roles' eligibility (#1072): each role's own XACML
 * policy, decided alone for one person.
 * @namespace
 */
export = {
  RoleEligibility: RoleEligibility,
  installInstance: (instance: RoleEligibility): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  nameFor: slot.forward('nameFor'),
  applicationOf: slot.forward('applicationOf'),
  selectionOn: slot.forward('selectionOn'),
  requiredFor: slot.forward('requiredFor'),
  setPolicy: slot.forward('setPolicy'),
  removePolicy: slot.forward('removePolicy'),
  resolve: slot.forward('resolve'),
  decide: slot.forward('decide'),
  offer: slot.forward('offer'),
  test: slot.forward('test')
};
