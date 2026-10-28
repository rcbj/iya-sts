// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: policy_kinds.ts
//
// ---------------------------------------------------------------------------
// THE KINDS OF POLICY ON DIRECTORY > POLICIES (#64, 2026-09-23).
//
// rcbj: "I do want the /admin/policies page to be one page that holds both
// policies. And, all future policies that we will define." So the page, its
// JSON, `GET /admin-api/policies` and `POST /admin-api/policies/{action}` are
// drawn from THIS LIST rather than from any one policy, and a future policy
// costs a module and a row here — no page, route, navigation entry or API
// resource.
//
// **THE POLICIES STAY SEPARATE** (rcbj, the same day: "I want the password
// policy to remain separate from the new policy"). A kind is a MODULE that
// owns its own entry, container, schema and rules; nothing here shares a
// field, a store or a decision between two kinds. What they share is the
// INTERFACE `password_policy.ts` established, which every kind implements:
//
//   FIELDS, DEFAULTS, SCHEMA, DEFAULT_PROFILE,
//   read(name), list(), save(name, body), reset(name), describe(profile)
//
// and the two actions each kind answers, `save-<id>-policy` and
// `reset-<id>-policy` — so the password policy's two keep the names they had.
//
// IT IS A LIBRARY (rule 3): it requires the policy modules, which are leaves,
// registers no route, and is required by `admin_views`, `admin_actions`,
// `admin.ts` and `admin_api.ts` in the ordinary direction.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import passwordPolicy = require('../common/password_policy');
import authnPolicy = require('../common/authn_policy');
import serviceAccountPolicy = require('../common/service_account_policy');
import passkeyPolicy = require('../common/passkey_policy');
import localePolicy = require('../common/locale_policy');
import attributePolicy = require('../common/attribute_policy');
import postLoginPolicy = require('../common/post_login_policy');
// The page's sentences, in the reader's language (#543): the templates the
// messages below are filled with, and the namespace `prose()` extracts.
import serverProse = require('../common/server_prose');

const { log } = helpers;

// What every kind's module offers — `password_policy.ts`'s shape.
interface PolicyModule {
  FIELDS: ReadonlyArray<Record<string, any>>;
  DEFAULTS: Readonly<Record<string, unknown>>;
  SCHEMA: { container: string; objectClasses: any[]; attributes: any[];
            personAttributes?: any[] };
  DEFAULT_PROFILE: string;
  read(name?: string): Record<string, any>;
  list(): Record<string, any>[];
  save(name: unknown, body?: Record<string, any> | null):
    { ok: boolean; errors?: string[]; profile?: Record<string, any> };
  reset(name: unknown):
    { ok: boolean; errors?: string[]; removed?: boolean;
      profile?: Record<string, any> };
  describe(profile?: Record<string, any> | null): string[];
  // A kind whose profiles may be NAMED and selected (#535, the passkey
  // policy): the selectors each named profile carries.
  SELECTORS?: ReadonlyArray<Record<string, any>>;
  // Population registration algorithms and mode (#940), on the passkey
  // policy. A kind without them leaves those members off the policies read.
  registrationAlgorithms?(profile?: Record<string, any> | null): string[];
  registrationMode?(profile?: Record<string, any> | null): string;
  // A kind with acts of its own beside save and reset (#396, the attribute
  // policy's custom attribute register): each named in the kind's
  // `extraActions`, answered here.
  act?(action: string, body: Record<string, any>):
    { ok: boolean; errors?: string[]; message?: string;
      [member: string]: any };
}

// An act a kind has beside save and reset (#396): its name, the module's
// audit action, what it does (for the API's description) and its body.
interface ExtraAction {
  action: string;
  operationId: string;
  summary: string;
  description: string;
  auditAction: string;
  requestBody: Record<string, any>;
}

interface PolicyKind {
  id: string;                    // the anchor, the JSON member, the actions
  label: string;
  container: string;
  governs: string;
  module: PolicyModule;
  auditAction: string;
  // What a save applies to, finishing the sentence "It applies to ...".
  appliesTo: string;
  // What resetting falls back to, finishing "... and ... is in force".
  fallsBackTo: string;
  // A field whose value is a secret is never drawn; none are today, and the
  // flag is here so a kind that has one says so rather than relying on it.
  secretFields?: string[];
  // Acts beside save and reset (#396), answered by the module's `act()`.
  extraActions?: ExtraAction[];
}

const KINDS: PolicyKind[] = [];

/**
 * The kinds of policy on Directory → Policies: the one list the page, its JSON
 * and the `/admin-api/policies` operations are drawn from.
 *
 * Each kind is a separate module owning its own entry, container, schema and
 * rules, implementing `password_policy.ts`'s interface; a future policy costs a
 * module and a row here. A library that registers no route.
 */
// ---------------------------------------------------------------------------
// WHAT A SAVE OR A RESET ANSWERS, as templates (#543 phase 2). One copy:
// `admin-core/admin_actions.ts` fills them with `ServerProse.fill()`, and
// `common/server_prose.ts` matches the answer's `message` against them to
// refill it in the reader's language — the noun and the kind's sentences
// translated inside it, the profile's name and DN carried over.
// ---------------------------------------------------------------------------
const MESSAGES: Readonly<Record<string, string>> = Object.freeze({
  saved: 'The {{noun}} "{{name}}" is saved at {{dn}}. It applies to ' +
    '{{appliesTo}}.',
  savedNotEnforced: 'The {{noun}} "{{name}}" is saved at {{dn}}. It ' +
    'applies to {{appliesTo}} — and it is not enforced here until this ' +
    'realm is in product mode.',
  removed: 'The stored profile is gone, and this realm follows ' +
    '{{fallsBackTo}}: {{rules}}.',
  nothingStored: 'Nothing was stored in this realm, so it already ' +
    'followed {{fallsBackTo}}.'
});

// ---------------------------------------------------------------------------
// WHAT THE PAGE SAYS BESIDES EACH KIND'S OWN TABLES (#543 phase 2): the
// password policy's enforcement, generator and doors, and why the email
// mechanisms cannot be on. Here, beside the kinds, rather than inline in
// `admin-core/admin_views.ts`, so the policies namespace can be extracted
// without loading the console's views; that module reads them from here.
// ---------------------------------------------------------------------------
const VIEW_PROSE = Object.freeze({
  enforced: 'ENFORCED. This realm is in product mode, so every password ' +
    'set here — at every door below — must meet the profile, and a new ' +
    'password may not repeat a remembered one.',
  notEnforced: 'NOT ENFORCED. This realm is in development mode, where no ' +
    'password is checked at any door, so a rule about one would be a rule ' +
    'about a credential nothing reads. The history is still RECORDED, so a ' +
    'realm switched to product mode starts with one. A GENERATED password ' +
    'meets the profile in both modes.',
  generatorSource: 'node\'s crypto.randomInt, rejection-sampled so that no ' +
    'character of the pool is likelier than another',
  generatorPools: Object.freeze(['lowercase letters', 'uppercase letters',
                                 'digits', 'symbols']),
  generatorDrawsUntil: 'the password satisfies the profile, so every ' +
    'generated password is uniform over the passwords the profile accepts',
  doors: Object.freeze([
    Object.freeze({ door: '/admin/users/new and /admin/users (Set password)',
                    via: 'credentials.setPassword()' }),
    Object.freeze({ door: 'POST /admin-api/users/create and ' +
                          '/admin-api/users/set-password',
                    via: 'credentials.setPassword()' }),
    Object.freeze({ door: '/portal/password',
                    via: 'credentials.setPassword()' }),
    Object.freeze({ door: '/portal/activate (the first password a person ' +
                          'sets)',
                    via: 'credentials.setPassword()' }),
    Object.freeze({ door: 'an LDAP add or modify of userPassword on 389 or ' +
                          '636',
                    via: 'credentials.preparePassword()' })
  ]),
  notDoors: 'SCIM carries no password (this service advertises ' +
    'changePassword: false), and a password is never set by signing in. ' +
    'Passwords stored BEFORE a rule changed are not re-checked: nothing ' +
    'here holds a password in a form that could be, and the rule applies ' +
    'from the next change.',
  mailWhy: 'This realm cannot send mail, so the two email mechanisms cannot ' +
    'be turned on and are never offered. Configure a transport on Server ' +
    'configuration > Mail.'
});

// The routes whose answers carry the policies namespace's prose (#543).
const PROSE_ROUTES = ['/admin-api/policies', '/admin-api/policies/:action'];

class PolicyKinds {
  /**
   * What a save or a reset answers, as templates (#543).
   */
  static readonly MESSAGES = MESSAGES;
  /**
   * What the page says besides each kind's own tables (#543).
   */
  static readonly VIEW_PROSE = VIEW_PROSE;
  /**
   * The routes whose answers carry the policies namespace's prose.
   */
  static readonly PROSE_ROUTES = PROSE_ROUTES;

  /**
   * Extracts the policies namespace (#543 phase 2): every kind's label and
   * sentences and the noun a message names it by, each kind module's
   * field table, schema, mechanism, door and selector prose and its
   * `describe()` templates, and the page's own sentences and messages.
   *
   * @returns key → English
   */
  static prose(): Record<string, string> {
    log.debug("Entering PolicyKinds.prose().");
    const harvest = serverProse.harvest;
    // `door` is prose only on the page's list; a field's `door` is an id.
    const MEMBERS = ['label', 'what', 'unit', 'governs', 'appliesTo',
                     'fallsBackTo'];
    const out: Record<string, string> = {};
    KINDS.forEach(function (kind) {
      const mod = kind.module as unknown as Record<string, unknown>;
      Object.assign(out, harvest('kinds.' + kind.id, {
        label: kind.label, governs: kind.governs, appliesTo: kind.appliesTo,
        fallsBackTo: kind.fallsBackTo }, MEMBERS));
      out['kinds.' + kind.id + '.param.noun'] = PolicyKinds.nounOf(kind);
      ['FIELDS', 'SCHEMA', 'MECHANISMS', 'DOORS', 'SELECTORS', 'SYNTAXES']
        .forEach(function (name) {
          if (mod[name]) {
            Object.assign(out, harvest(kind.id + '.' + name, mod[name],
                                       MEMBERS));
          }
        });
      if (typeof mod.NIST_EMAIL_WARNING === 'string') {
        out[kind.id + '.nistWarning'] = mod.NIST_EMAIL_WARNING;
      }
      const sentences = (mod.SENTENCES || {}) as Record<string, string>;
      Object.keys(sentences).forEach(function (key) {
        out[kind.id + '.sentences.' + key] = sentences[key];
      });
    });
    Object.keys(MESSAGES).forEach(function (key) {
      out['messages.' + key] = MESSAGES[key];
    });
    Object.assign(out, harvest('page', {
      enforced: VIEW_PROSE.enforced, notEnforced: VIEW_PROSE.notEnforced,
      source: VIEW_PROSE.generatorSource,
      drawsUntil: VIEW_PROSE.generatorDrawsUntil,
      notDoors: VIEW_PROSE.notDoors, mailWhy: VIEW_PROSE.mailWhy,
      doors: VIEW_PROSE.doors },
      MEMBERS.concat(['door', 'enforced', 'notEnforced', 'source',
                      'drawsUntil', 'notDoors', 'mailWhy'])));
    VIEW_PROSE.generatorPools.forEach(function (pool, i) {
      out['page.pools.' + i] = pool;
    });
    log.debug("Leaving PolicyKinds.prose(). " + Object.keys(out).length);
    return out;
  }

  /**
   * The noun a message names a kind's profile by: its label, lower-cased,
   * and "profile".
   *
   * @param kind - the kind
   * @returns the noun
   */
  static nounOf(kind: PolicyKind): string {
    log.debug("Entering PolicyKinds.nounOf().");
    log.debug("Leaving PolicyKinds.nounOf().");
    return kind.label.toLowerCase() + ' profile';
  }

  /**
   * Adds a kind to the list; a second registration of the same id is ignored.
   *
   * @param kind - the kind: its id, label, container, module and the sentences
   *   the page draws
   */
  static register(kind: PolicyKind): void {
    log.debug("Entering PolicyKinds.register(). " + kind.id);
    if (KINDS.some(function (k) {
      return k.id === kind.id;
    })) {
      log.debug("Leaving PolicyKinds.register(). Already registered.");
      return;
    }
    KINDS.push(kind);
    log.debug("Leaving PolicyKinds.register(). " + KINDS.length +
              " kind(s).");
  }

  // For a test that registers a stub kind: take it away again.
  /**
   * Removes a kind, for a test that registered a stub.
   *
   * @param id - the kind's id
   */
  static unregister(id: string): void {
    log.debug("Entering PolicyKinds.unregister(). " + id);
    const at = KINDS.findIndex(function (k) {
      return k.id === id;
    });
    if (at >= 0) {
      KINDS.splice(at, 1);
    }
    log.debug("Leaving PolicyKinds.unregister().");
  }

  /**
   * Returns every kind, in the order the page draws them.
   *
   * @returns a copy of the list
   */
  static list(): PolicyKind[] {
    log.debug("Entering PolicyKinds.list().");
    log.debug("Leaving PolicyKinds.list().");
    return KINDS.slice();
  }

  /**
   * Returns one kind by id.
   *
   * @param id - the kind's id
   * @returns the kind, or null
   */
  static byId(id: string): PolicyKind | null {
    log.debug("Entering PolicyKinds.byId().");
    log.debug("Leaving PolicyKinds.byId().");
    return KINDS.filter(function (k) {
      return k.id === id;
    })[0] || null;
  }

  /**
   * Returns the name of a kind's save action, `save-<id>-policy`.
   *
   * @param kind - the kind
   * @returns the action
   */
  static saveAction(kind: PolicyKind): string {
    log.debug("Entering PolicyKinds.saveAction().");
    log.debug("Leaving PolicyKinds.saveAction().");
    return 'save-' + kind.id + '-policy';
  }

  /**
   * Returns the name of a kind's reset action, `reset-<id>-policy`.
   *
   * @param kind - the kind
   * @returns the action
   */
  static resetAction(kind: PolicyKind): string {
    log.debug("Entering PolicyKinds.resetAction().");
    log.debug("Leaving PolicyKinds.resetAction().");
    return 'reset-' + kind.id + '-policy';
  }

  // Every action every kind answers, in kind order: save then reset, then
  // its own (#396).
  /**
   * Returns every action every kind answers, in kind order: save then reset,
   * then any the kind has of its own.
   *
   * @returns the actions
   */
  static actions(): string[] {
    log.debug("Entering PolicyKinds.actions().");
    const out: string[] = [];
    KINDS.forEach(function (kind) {
      out.push(PolicyKinds.saveAction(kind), PolicyKinds.resetAction(kind));
      (kind.extraActions || []).forEach(function (extra) {
        out.push(extra.action);
      });
    });
    log.debug("Leaving PolicyKinds.actions(). " + out.length + ".");
    return out;
  }

  // Which kind answers an action, and whether it is its save or its reset.
  /**
   * Returns which kind answers an action, and whether it is its save or its
   * reset.
   *
   * @param action - the action's name
   * @returns the kind and verb, or null
   */
  static forAction(action: string):
      { kind: PolicyKind; verb: 'save' | 'reset' | 'act';
        extra?: ExtraAction } | null {
    log.debug("Entering PolicyKinds.forAction(). " + action);
    for (const kind of KINDS) {
      if (action === PolicyKinds.saveAction(kind)) {
        log.debug("Leaving PolicyKinds.forAction(). save " + kind.id);
        return { kind: kind, verb: 'save' };
      }
      if (action === PolicyKinds.resetAction(kind)) {
        log.debug("Leaving PolicyKinds.forAction(). reset " + kind.id);
        return { kind: kind, verb: 'reset' };
      }
      const extra = (kind.extraActions || []).filter(function (one) {
        return one.action === action;
      })[0];
      if (extra) {
        log.debug("Leaving PolicyKinds.forAction(). act " + kind.id);
        return { kind: kind, verb: 'act', extra: extra };
      }
    }
    log.debug("Leaving PolicyKinds.forAction(). None.");
    return null;
  }
}

// ---------------------------------------------------------------------------
// THE KINDS THIS SERVICE DEFINES, in the order the page draws them.
// ---------------------------------------------------------------------------
PolicyKinds.register({
  id: 'password',
  label: 'Password policy',
  container: 'ou=passwordPolicies',
  governs: 'userPassword',
  module: passwordPolicy as unknown as PolicyModule,
  auditAction: 'admin.password-policy.change',
  appliesTo: 'the NEXT password set in this realm and to nothing already ' +
             'stored',
  fallsBackTo: 'the built-in defaults'
});

PolicyKinds.register({
  id: 'authn',
  label: 'Authentication policy',
  container: 'ou=authnPolicies',
  governs: 'which mechanisms are accepted as a first and as a second factor',
  module: authnPolicy as unknown as PolicyModule,
  auditAction: 'admin.authn-policy.change',
  appliesTo: 'the NEXT sign-in in this realm; a session already started ' +
             'keeps the factors it was started with',
  fallsBackTo: 'the default realm\'s profile where it has one, and the ' +
               'built-in defaults where it has not'
});

// #221: the third kind, rcbj's "a third kind of policy, the service-account
// policy ... set per realm and inherited from the default realm".
PolicyKinds.register({
  id: 'serviceAccount',
  label: 'Service-account policy',
  container: 'ou=serviceAccountPolicies',
  governs: 'what a service account may do — the second factor, the ' +
           'browser, the password doors — and how its password rotates',
  module: serviceAccountPolicy as unknown as PolicyModule,
  auditAction: 'admin.service-account-policy.change',
  appliesTo: 'every service account in this realm from the next time it ' +
             'signs in, binds or is rotated',
  fallsBackTo: 'the default realm\'s profile where it has one, and the ' +
               'built-in defaults where it has not'
});

// #527: the fourth kind, rcbj's "a new policy (which can be overridden per
// realm) that governs the behavior of passkeys".
PolicyKinds.register({
  id: 'passkey',
  label: 'Passkey policy',
  container: 'ou=passkeyPolicies',
  governs: 'how passkeys behave — whether a sign-in may name no username, ' +
           'and what a security key is asked to store',
  module: passkeyPolicy as unknown as PolicyModule,
  auditAction: 'admin.passkey-policy.change',
  appliesTo: 'the NEXT sign-in and the NEXT passkey enrolled in this realm; ' +
             'a passkey already enrolled keeps what its authenticator stored',
  fallsBackTo: 'the default realm\'s profile where it has one, and the ' +
               'built-in defaults where it has not'
});

// #539: the fifth kind, rcbj's "a policy default per realm that automatically
// populates user locale parameter", with named profiles "assign[ed] ... to
// application objects".
PolicyKinds.register({
  id: 'locale',
  label: 'Locale policy',
  container: 'ou=localePolicies',
  governs: 'the language a page falls back to, the language mail is ' +
           'written in when a person names none, and the preferredLanguage ' +
           'a new person is given',
  module: localePolicy as unknown as PolicyModule,
  auditAction: 'admin.locale-policy.change',
  appliesTo: 'the NEXT page drawn and the NEXT person created in this ' +
             'realm; a person created before keeps the preferredLanguage ' +
             'they have, or none',
  fallsBackTo: 'the default realm\'s profile where it has one, and the ' +
               'built-in defaults where it has not'
});

// #396: the sixth kind, rcbj's "Add a policy that defines what the required
// fields must be for a realm", and on the ticket "a list of all attributes,
// custom attributes, ability to add a new attribute, and require each
// individual attribute as needed" — the custom attribute register is this
// kind's two acts of its own.
PolicyKinds.register({
  id: 'attributes',
  label: 'Attribute policy',
  container: 'ou=attributePolicies',
  governs: 'the attributes every person in this realm must hold, and the ' +
           'custom attributes a person here may be given',
  module: attributePolicy as unknown as PolicyModule,
  auditAction: 'admin.attribute-policy.change',
  appliesTo: 'the NEXT person created and the NEXT edit in this realm; a ' +
             'person who already lacks an attribute it requires keeps every ' +
             'other door',
  fallsBackTo: 'the default realm\'s profile where it has one, and the ' +
               'built-in default (givenName, sn and mail) where it has not',
  extraActions: [
    { action: 'define-person-attribute',
      operationId: 'definePersonAttribute',
      summary: 'Define a custom attribute in this realm',
      description: 'Writes `cn=<name>,ou=attributeDefinitions` in this ' +
                   'realm\'s directory: an attribute a person here may be ' +
                   'given, with a label, a syntax its values are checked ' +
                   'against and whether it holds several values. It is then ' +
                   'editable on a person\'s page and through ' +
                   '`/admin-api/users/*-attribute`, settable at a create, ' +
                   'and may be required by this policy. **The realm\'s ' +
                   'own**: ' +
                   'not inherited from the default realm. The name is an ' +
                   'RFC 4512 descr of at most 64 characters, and may not be ' +
                   'a name the directory already knows, `memberOf`, or ' +
                   'begin `sts` (STS-LDAP-0170). At most 100 per realm.',
      auditAction: 'admin.attribute-policy.define',
      requestBody: {
        type: 'object',
        properties: {
          name: { type: 'string', pattern: '^[A-Za-z][A-Za-z0-9-]{0,63}$',
                  description: 'The attribute\'s name.' },
          label: { type: 'string', maxLength: 128,
                   description: 'What the pages draw beside the name.' },
          syntax: { type: 'string',
                    enum: attributePolicy.SYNTAXES.map(function (one) {
                      return one.id;
                    }),
                    description: 'What its values are checked against. ' +
                                 'Default `string`.' },
          multiValued: { oneOf: [{ type: 'boolean' }, { type: 'string' }],
                         description: 'Whether it holds several values ' +
                                      '(`true`, or `multiple` from a form). ' +
                                      'Default false.' },
          description: { type: 'string', maxLength: 1024,
                         description: 'What it is for. Optional.' }
        },
        required: ['name', 'label'],
        examples: [{ name: 'employeeBadge', label: 'Badge number',
                     syntax: 'string', multiValued: false }],
        additionalProperties: false
      } },
    { action: 'remove-person-attribute',
      operationId: 'removePersonAttribute',
      summary: 'Remove a custom attribute of this realm',
      description: 'Deletes `cn=<name>,ou=attributeDefinitions`. Refused ' +
                   'while any person in the realm holds a value of it ' +
                   '(STS-LDAP-0172) and while this realm\'s own profile ' +
                   'requires it (STS-LDAP-0173): a definition removed from ' +
                   'under its values would leave data no door offers again.',
      auditAction: 'admin.attribute-policy.undefine',
      requestBody: {
        type: 'object',
        properties: {
          name: { type: 'string', description: 'The attribute\'s name.' }
        },
        required: ['name'],
        examples: [{ name: 'employeeBadge' }],
        additionalProperties: false
      } }
  ]
});

// #1096: the seventh kind, rcbj's "post login activity" — what a person is
// asked to do after signing in, targeted by group membership, configurable
// and enabled per realm. The first activity is the post-quantum passkey
// migration.
PolicyKinds.register({
  id: 'postLogin',
  label: 'Post-login activity policy',
  container: 'ou=postLoginPolicies',
  governs: 'what a person is asked to do after signing in, before they are ' +
           'sent back to the application — today, to register a ' +
           'post-quantum passkey',
  module: postLoginPolicy as unknown as PolicyModule,
  auditAction: 'admin.post-login-policy.change',
  appliesTo: 'the NEXT sign-in of every person the profile reaches in this ' +
             'realm; a session already started is not interrupted',
  fallsBackTo: 'the default realm\'s profile where it has one, and the ' +
               'built-in defaults (nobody is asked anything) where it has not'
});

export = PolicyKinds;
