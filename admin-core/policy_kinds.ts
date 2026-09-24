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
}

const KINDS: PolicyKind[] = [];

class PolicyKinds {
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

  static list(): PolicyKind[] {
    log.debug("Entering PolicyKinds.list().");
    log.debug("Leaving PolicyKinds.list().");
    return KINDS.slice();
  }

  static byId(id: string): PolicyKind | null {
    log.debug("Entering PolicyKinds.byId().");
    log.debug("Leaving PolicyKinds.byId().");
    return KINDS.filter(function (k) {
      return k.id === id;
    })[0] || null;
  }

  static saveAction(kind: PolicyKind): string {
    log.debug("Entering PolicyKinds.saveAction().");
    log.debug("Leaving PolicyKinds.saveAction().");
    return 'save-' + kind.id + '-policy';
  }

  static resetAction(kind: PolicyKind): string {
    log.debug("Entering PolicyKinds.resetAction().");
    log.debug("Leaving PolicyKinds.resetAction().");
    return 'reset-' + kind.id + '-policy';
  }

  // Every action every kind answers, in kind order: save then reset.
  static actions(): string[] {
    log.debug("Entering PolicyKinds.actions().");
    const out: string[] = [];
    KINDS.forEach(function (kind) {
      out.push(PolicyKinds.saveAction(kind), PolicyKinds.resetAction(kind));
    });
    log.debug("Leaving PolicyKinds.actions(). " + out.length + ".");
    return out;
  }

  // Which kind answers an action, and whether it is its save or its reset.
  static forAction(action: string):
      { kind: PolicyKind; verb: 'save' | 'reset' } | null {
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

export = PolicyKinds;
