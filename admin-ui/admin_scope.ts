'use strict';
//
// File: admin_scope.ts
//
// ---------------------------------------------------------------------------
// WHAT A REALM ADMINISTRATOR MAY NOT REACH (2026-09-14, ticket #32).
//
// A trust realm has an administrator roster of its own since #32 — its own
// `cn=admin-read` and `cn=admin-write` — beside the DEFAULT realm's, which is
// the SERVICE roster and administers everything. rcbj's rule for the realm
// roster is that its members are CONFINED to their realm: every page and action
// about the realm they signed in through, and nothing that belongs to the whole
// process.
//
// **THIS FILE IS THE ONE PLACE THAT LINE IS DRAWN**, for the console and the
// management API alike. `admin-core/admin_views.ts`'s `gateStateFor()` decides
// WHO holds which authority; this decides WHAT a realm authority may not touch.
// A second copy of either half is how the console and `/admin-api` would
// come to disagree about what a realm administrator can do, which is rule 7's
// subject read as a security property.
//
// Three kinds of thing are service-wide, and each is a table below:
//
//   * PAGES whose subject is the process — the store, the database, the secret
//     store, TLS and its client-certificate truststore, the directory's
//     sockets, the API explorer, the embedded debugger. Refused whatever the
//     method, and hidden from the navigation.
//   * ACTIONS on a realm-scoped page that reach past the realm — creating or
//     removing a realm, editing another realm's row, replacing the service Root
//     or the process branch, exporting the TLS listener's private key.
//   * SETTINGS a realm administrator may not write, wherever the form that
//     posts them is drawn. `config.setOverride()` sends a write for a row a
//     realm may not carry to the PROCESS-WIDE map even while a realm is
//     ambient, so a Save on `/realm/acme/admin/config` would otherwise change
//     the process; and a handful of rows a realm may carry still name the
//     whole service (the console's own roles, the management API's gate, file
//     paths and listener addresses).
//
// **A LIBRARY** (rule 3): no route, and it requires only `config.js` and the
// logger, neither of which requires it.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `AdminScope` takes the logger and the two `config` readers it asks
// through its constructor. The three tables of names stay module constants,
// exported as static members; the two tables of RULES are built in the
// constructor, because each rule logs through the instance's logger.
//
// R2 (#50): the composition root (`common/protocol_stack.ts`) builds the
// instance and installs it; this module builds none of its own. It still
// exports every name it did, as FACADES that forward to that instance, for
// `admin-ui/admin.ts`, `mgmt-api/admin_api.ts` and the test. A process
// without the root builds a default instance at load, as loading this module
// always did.
// ---------------------------------------------------------------------------


import helpers = require('../common/helpers');
import config = require('../common/config');
import InstanceSlot = require('../common/instance_slot');

// What a gate state is, as far as this file reads one: `gateStateFor()`'s
// answer in `admin-core/admin_views.ts`.
interface ScopeState {
  authority?: string;
  identityRealm?: string;
  [other: string]: any;
}

// What `refusalFor()` answers when something here refuses.
interface ScopeRefusal {
  code: string;
  reason: string;
  detail: string;
  settings?: string[];
}

// A rule over a write's parsed body and the realm the administrator signed in
// through: a sentence when the action is service-wide, '' otherwise.
type ActionRule = (body: any, realmId?: string) => string;

// A rule over a read's query, the same way.
type ReadRule = (query: any, realmId?: string) => string;

interface AdminScopeDeps {
  log: { debug(message: string): void };
  // The setting table and the per-process test, from `common/config.js`.
  settings: () => ReadonlyArray<{ key: string }>;
  isPerProcess: (key: string) => boolean;
}

// Pages whose whole subject is the process. A prefix ends at a segment
// boundary, so `/admin/tls` covers `/admin/tls/trust` and not `/admin/tlsx`.
const SERVICE_PAGES = [
  '/admin/persistence',
  '/admin/cluster',
  '/admin/database',
  '/admin/encryption',
  '/admin/secrets',
  // Every realm's partition of every cache, and the process-wide ones (#74).
  '/admin/caches',
  '/admin/debugger',
  '/admin/tls',
  // `/admin/kerberos` and `/admin/kerberos/principals` LEFT THIS LIST on
  // 2026-09-15, when a trust realm got a Kerberos realm and a principal
  // database of its own: what those pages show is then the realm's own, and a
  // realm administrator managing their realm's people and service principals
  // is exactly #32's rule. The settings that are still the PROCESS's — the two
  // sockets and the development-mode trust — are refused by
  // SERVICE_SETTING_KEYS below, per key rather than by the `krb5.` prefix this
  // used to carry.
  '/admin/ldap/service',
  // The explorer mints a DEFAULT-realm token for whoever holds the session,
  // which would hand a realm administrator a service credential. It is a
  // realm page only once it mints a realm token for a realm authority.
  '/admin/api-explorer'
];

// Settings a realm administrator may not write. A row a realm may not carry at
// all (`perProcess`, the two `realms.*` rows) is refused by
// `settingIsServiceOnly()` without being listed; these are the prefixes and
// keys a realm CAN carry that still name the whole service.
const SERVICE_SETTING_PREFIXES = [
  'admin.', 'adminApi.', 'realms.', 'workers.', 'persistence.', 'debugger.',
  'tls.', 'keys.', 'security.passwordHash'
];

const SERVICE_SETTING_KEYS = [
  'global.logLevel', 'global.mode', 'global.trustProxy', 'global.publicBaseUrl',
  'pki.revocationCrlIssuersFile', 'pki.revocationLdapCaFile',
  'pki.revocationLdapDirectory', 'pki.distributionPort',
  'pki.distributionBaseUrl', 'pki.distributionLdapHost',
  'pki.distributionLdapPort', 'pki.httpPort',
  'spiffe.workloadSocket', 'spiffe.serverSocket', 'spiffe.grpcHost',
  'spiffe.workloadPort', 'spiffe.serverPort',
  // KERBEROS, PER KEY SINCE 2026-09-15 (it was the `krb5.` prefix). A realm
  // carries its own Kerberos realm, principal database and keys, so the rows
  // those are built from are the realm administrator's. These six are not:
  // the two SOCKETS are bound once for the process, and the development-mode
  // trust is the DEFAULT realm's second Kerberos realm — no other realm has
  // one, so setting them on a realm would say something untrue.
  'krb5.kdcPort', 'krb5.servicePort', 'krb5.trustedRealm',
  'krb5.trustPassword', 'krb5.trustedDomainSid', 'krb5.trustedKrbtgtPassword'
];

class AdminScope {
  static readonly SERVICE_PAGES = SERVICE_PAGES;
  static readonly SERVICE_SETTING_PREFIXES = SERVICE_SETTING_PREFIXES;
  static readonly SERVICE_SETTING_KEYS = SERVICE_SETTING_KEYS;

  // The realm-scoped pages whose ACTIONS can reach past the realm, and what
  // each refuses. Each rule is handed the parsed body and the realm the
  // administrator signed in through and answers a sentence when the action is
  // service-wide.
  private readonly serviceActions: Record<string, ActionRule>;

  // The realm-scoped pages whose QUERY can name another realm, and what each
  // refuses to a realm administrator: `/admin/realms?realm=<id>` draws that
  // realm's row, its settings and its overrides.
  private readonly realmReads: Record<string, ReadRule>;

  constructor(private readonly deps: AdminScopeDeps) {
    deps.log.debug("Entering AdminScope.constructor().");
    const log = deps.log;
    const self = this;
    this.serviceActions = {
      '/admin/realms': function (body, realmId) {
        log.debug("Entering the realms action rule.");
        const action = String((body && body.action) || '').trim();
        if (action === 'create' || action === 'remove') {
          log.debug("Leaving the realms action rule. Service-wide.");
          return 'Creating or removing a trust realm is a service ' +
                 'administrator\'s act.';
        }
        const id = String((body && body.id) || '').trim();
        if (id && id !== realmId) {
          log.debug("Leaving the realms action rule. Another realm.");
          return 'That action names the "' + id + '" realm, and a realm ' +
                 'administrator of "' + realmId + '" may change that realm ' +
                 'only.';
        }
        log.debug("Leaving the realms action rule. Allowed.");
        return '';
      },
      '/admin/pki': function (body) {
        log.debug("Entering the PKI action rule.");
        const action = String((body && body.action) || '').trim();
        const scope = String((body && body.scope) || '').trim();
        if (action === 'build-root') {
          log.debug("Leaving the PKI action rule. The Root.");
          return 'Replacing the service Root re-certifies every realm\'s ' +
                 'branch, so it is a service administrator\'s act.';
        }
        if (scope.charAt(0) === '*') {
          log.debug("Leaving the PKI action rule. A service branch.");
          return 'That action names the "' + scope + '" branch, which ' +
                 'belongs to the whole service rather than to a realm.';
        }
        log.debug("Leaving the PKI action rule. Allowed.");
        return '';
      },
      '/admin/keys/export': function (body) {
        return self.tlsServerKeyRule(body);
      },
      // The management API's spelling of the same export: `POST
      // /admin-api/keys/export` is an `export` action on `/admin/keys`.
      '/admin/keys': function (body) {
        log.debug("Entering the key action rule.");
        log.debug("Leaving the key action rule.");
        return String((body && body.action) || '') === 'export'
          ? self.tlsServerKeyRule(body) : '';
      }
    };
    this.realmReads = {
      '/admin/realms': function (query, realmId) {
        log.debug("Entering the realms read rule.");
        const raw = query ? query.realm : '';
        const id = String((Array.isArray(raw) ? raw[0] : raw) || '').trim();
        log.debug("Leaving the realms read rule.");
        return id && id !== realmId
          ? 'That page names the "' + id + '" realm, and a realm ' +
            'administrator of "' + realmId + '" may read that realm only.'
          : '';
      }
    };
    deps.log.debug("Leaving AdminScope.constructor().");
  }

  // What the composition root passes: the real modules, as the load-time
  // instance was built from before R2 (#50). The setting table is read when
  // it is asked, as `config.SETTINGS` was.
  static defaultDeps(): AdminScopeDeps {
    helpers.log.debug("Entering AdminScope.defaultDeps().");
    helpers.log.debug("Leaving AdminScope.defaultDeps().");
    return {
      log: helpers.log,
      settings: function () {
        return config.SETTINGS;
      },
      isPerProcess: config.isPerProcess
    };
  }

  // The one key on `/admin/keys` that is not a realm's.
  private tlsServerKeyRule(body: any): string {
    const { log } = this.deps;
    log.debug("Entering AdminScope.tlsServerKeyRule().");
    const key = String((body && body.key) || '').trim();
    log.debug("Leaving AdminScope.tlsServerKeyRule().");
    return key === 'tls-server'
      ? 'The TLS listener\'s private key belongs to the process, which every ' +
        'realm shares.'
      : '';
  }

  // Whether `path` is `prefix` or under it, at a segment boundary.
  private under(path: string, prefix: string): boolean {
    const { log } = this.deps;
    log.debug("Entering AdminScope.under().");
    const p = String(path || '');
    log.debug("Leaving AdminScope.under().");
    return p === prefix || p.indexOf(prefix + '/') === 0;
  }

  pageIsService(path: string): boolean {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering AdminScope.pageIsService(). " + path);
    const hit = SERVICE_PAGES.some(function (prefix) {
      return self.under(path, prefix);
    });
    log.debug("Leaving AdminScope.pageIsService(). " + hit);
    return hit;
  }

  private knownSetting(key: string): boolean {
    const { log, settings } = this.deps;
    log.debug("Entering AdminScope.knownSetting().");
    const hit = settings().some(function (setting) {
      return setting.key === key;
    });
    log.debug("Leaving AdminScope.knownSetting().");
    return hit;
  }

  settingIsServiceOnly(key: string): boolean {
    const { log, isPerProcess } = this.deps;
    log.debug("Entering AdminScope.settingIsServiceOnly(). " + key);
    const name = String(key || '');
    const hit = isPerProcess(name) ||
      SERVICE_SETTING_KEYS.indexOf(name) >= 0 ||
      SERVICE_SETTING_PREFIXES.some(function (prefix) {
        return name.indexOf(prefix) === 0;
      });
    log.debug("Leaving AdminScope.settingIsServiceOnly(). " + hit);
    return hit;
  }

  // Every setting a body names that a realm administrator may not write: the
  // `key` of a `set` or `reset`, and every field of a `set-many` that is a
  // setting's key.
  serviceSettingsIn(body: any): string[] {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering AdminScope.serviceSettingsIn().");
    const named = [];
    const add = function (key) {
      log.debug("Entering add().");
      if (self.knownSetting(key) && self.settingIsServiceOnly(key) &&
          named.indexOf(key) < 0) {
        named.push(key);
      }
      log.debug("Leaving add().");
    };
    Object.keys(body || {}).forEach(add);
    if (body && typeof body.key === 'string') {
      add(body.key.trim());
    }
    log.debug("Leaving AdminScope.serviceSettingsIn(). " + named.length + ".");
    return named;
  }

  // The action rule for a page, or null.
  actionRuleFor(path: string): ActionRule | null {
    const { log } = this.deps;
    log.debug("Entering AdminScope.actionRuleFor().");
    log.debug("Leaving AdminScope.actionRuleFor().");
    return this.serviceActions[path] || null;
  }

  // -------------------------------------------------------------------------
  // THE DECISION. `state` is `gateStateFor()`'s answer; `path` is the console
  // path the request is for, realm prefix already stripped; `body` is the
  // parsed body of a write, or null for a read; `query` is the query string.
  // Answers null when nothing here refuses, or `{ code, reason, detail }`.
  //
  // A SERVICE authority is never refused here — a service administrator
  // reaches everything, in every realm, exactly as before #32. Nor is an
  // unauthenticated request: the gate has already sent that one to sign in.
  // -------------------------------------------------------------------------
  refusalFor(state: ScopeState | null | undefined, path: string, body?: any,
             query?: any): ScopeRefusal | null {
    const { log } = this.deps;
    log.debug("Entering AdminScope.refusalFor(). " + path);
    if (!state || state.authority !== 'realm') {
      log.debug("Leaving AdminScope.refusalFor(). Not a realm authority.");
      return null;
    }
    if (this.pageIsService(path)) {
      log.debug("Leaving AdminScope.refusalFor(). A service page.");
      return { code: 'STS-ADMIN-0787', reason: 'service_page',
               detail: path + ' is about the whole service, which a realm ' +
                       'administrator of "' + state.identityRealm + '" does ' +
                       'not administer.' };
    }
    const reads = this.realmReads[path];
    const named = reads ? reads(query, state.identityRealm) : '';
    if (named) {
      log.debug("Leaving AdminScope.refusalFor(). Another realm named.");
      return { code: 'STS-ADMIN-0787', reason: 'service_action',
               detail: named };
    }
    if (body) {
      const rule = this.serviceActions[path];
      const why = rule ? rule(body, state.identityRealm) : '';
      if (why) {
        log.debug("Leaving AdminScope.refusalFor(). A service action.");
        return { code: 'STS-ADMIN-0787', reason: 'service_action',
                 detail: why };
      }
      const settings = this.serviceSettingsIn(body);
      if (settings.length) {
        log.debug("Leaving AdminScope.refusalFor(). Service settings.");
        return { code: 'STS-ADMIN-0788', reason: 'service_setting',
                 settings: settings,
                 detail: 'A realm administrator may not change ' +
                         settings.join(', ') + ': ' +
                         (settings.length === 1 ? 'it names' : 'they name') +
                         ' the whole service rather than the "' +
                         state.identityRealm + '" realm.' };
      }
    }
    log.debug("Leaving AdminScope.refusalFor(). Allowed.");
    return null;
  }

  // Whether a navigation row is drawn for this state. Only service pages are
  // hidden, and only from a realm authority.
  pageVisible(state: ScopeState | null | undefined, path: string): boolean {
    const { log } = this.deps;
    log.debug("Entering AdminScope.pageVisible().");
    const visible = !(state && state.authority === 'realm' &&
                      this.pageIsService(path));
    log.debug("Leaving AdminScope.pageVisible(). " + visible);
    return visible;
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds no
// instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` (see `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<AdminScope>(
  'admin-ui/admin_scope',
  () => new AdminScope(AdminScope.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  AdminScope: AdminScope,
  installInstance: (instance: AdminScope): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  SERVICE_PAGES: AdminScope.SERVICE_PAGES,
  SERVICE_SETTING_PREFIXES: AdminScope.SERVICE_SETTING_PREFIXES,
  SERVICE_SETTING_KEYS: AdminScope.SERVICE_SETTING_KEYS,
  pageIsService: slot.forward('pageIsService'),
  settingIsServiceOnly: slot.forward('settingIsServiceOnly'),
  serviceSettingsIn: slot.forward('serviceSettingsIn'),
  actionRuleFor: slot.forward('actionRuleFor'),
  refusalFor: slot.forward('refusalFor'),
  pageVisible: slot.forward('pageVisible')
};
