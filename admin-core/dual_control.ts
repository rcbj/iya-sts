// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: dual_control.ts
//
// ===========================================================================
// TWO-PERSON APPROVAL FOR HIGH-RISK ADMINISTRATOR ACTS (#2166, ASVS 5.0.0
// 2.3.5; rcbj's decision of 2026-11-24): built, and OFF by default behind
// `admin.dualControl`, a realm's own setting.
//
// With it on, the acts `HELD` names are not performed when the first
// administrator asks. `mgmt-api/admin_api.ts`'s POST wrapper — the one place
// every `/admin-api` write passes, after the gate and the request schema, and
// the place the static console's forms reach too — asks `heldRowFor()`, and
// for a held act `hold()` stores the operation and its validated body as a
// PENDING REQUEST and the wrapper answers 202 with its id. A second, DIFFERENT
// administrator holding the same authority approves it, and the stored
// operation runs then, through the same handler, as the requester's act; or
// refuses it; or the requester withdraws it; or it expires.
//
// THE TABLE IS THE ONE PLACE AN ACT IS MADE HIGH-RISK. A row names an
// `/admin-api` operation (its operationId) and, where only some bodies of it
// are high-risk, a predicate over the validated body. Adding an action is
// one row. `tests/dual_control.js` holds every row to an operation the
// management API declares, and that operation to a console page it mirrors.
//
// THE PATTERNS ARE #1180's (`authzen/authzen_access_request.ts`): a store
// declared per realm at module scope and persisted as minted rows (so no
// table and no schema change), a pending index row so a list reads one row,
// the deadline applied at every read, a realm-scope cluster job as the only
// periodic work, every transition one audit row, and the instance built by
// the composition root through an `InstanceSlot`. The AuthZEN module itself
// is not generalised: its task, binding and callback semantics are the
// profile's, and a second reader of them would be a second answer to what an
// approval is.
//
// THE SINGLE-ADMINISTRATOR RULE: when fewer than two people could decide —
// the requester left out — the act PROCEEDS, and the audit row says nobody
// approved it (`STS-ADMIN-0962`). Refusing to turn the setting on instead
// would test the roster once, on the day it was turned on; a realm whose
// administrators later left (and a person can leave the admin group over
// LDAP, SCIM or a delete, none of which this holds) would have every held
// act held for ever, turning the control off included. So the rule chosen is
// the one that cannot lock a realm out, and the door a compromised lone
// administrator would use to get there, revoking the others, is a row of the
// table: a revoke that would leave fewer than two approvers is held itself.
// `/admin/mode` draws whether the control is in force (`state()`).
//
// A LIBRARY (rule 3): it registers no route — `mgmt-api/admin_api.ts` carries
// the two operations and the console page draws from them — and its job is
// registered when the composition root installs the instance.
// ===========================================================================

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import realms = require('../common/realms');
import stsCrypto = require('../common/crypto');

const { log } = helpers;

type Json = any;

// The scheduler job, and how often it runs.
const JOB = 'admin.dual-control';
const JOB_EVERY_MS = 60000;

// How long a finished request is kept for the console to show, seconds.
const RETENTION_S = 7 * 86400;

// The index row of every pending request's id.
const PENDING_KEY = 'pending:requests';

// The most pending requests one realm holds; past it a new hold is refused
// (STS-ADMIN-0961), so the index row stays one small row.
const MAX_PENDING = 200;

// The id prefix, so an id is recognisably one of these in a log line.
const ID_PREFIX = 'dc_';

// The lifecycle: `pending`, then exactly once one of the others. `approved`
// is never a resting state: the replay that follows makes it `done` or
// `failed` in the same call.
const STATES = Object.freeze(['pending', 'done', 'failed', 'refused',
                              'withdrawn', 'expired']);

// The settings.
const SETTING = 'admin.dualControl';
const LIFETIME_SETTING = 'admin.dualControlLifetimeHours';

// The console roles whose groups name administrators, and the settings that
// name those groups. ADMIN_READ is among them: a read role is an
// administrator role the console treats as one, and granting it is an act
// rcbj named.
const CONSOLE_ROLE_NAMES = Object.freeze(['ADMIN_READ', 'ADMIN_WRITE',
                                          'SECURITY_ADMIN']);
const CONSOLE_GROUP_SETTINGS = Object.freeze(['admin.readGroup',
                                              'admin.writeGroup',
                                              'admin.securityGroup']);

// The two authorities an approver can need, and the console roster role
// (`admin_rbac.ts`) whose holders are the people who hold each.
const AUTHORITY_ROSTER: Record<string, string> = Object.freeze({
  ADMIN_WRITE: 'write',
  SECURITY_ADMIN: 'security'
});

// The members of a held body never shown on the console or in the API's
// list: private keys and passwords an import carries.
const SECRET_MEMBER = /private|password|secret|passphrase|pkcs12|pfx/i;

// ---------------------------------------------------------------------------
// THE STORE, per realm at its declaration and persisted (persistence/
// CLAUDE.md's minted-row rule), so a pending request survives a restart in
// product mode and every request worker reads the same one. Its tier is
// GLOBAL (`persistence/tiers.js`): a held realm deletion or KEK rotation is
// control-plane state every cell's console must see.
// ---------------------------------------------------------------------------
// A hot path (every row a flush writes): no Entering/Leaving pair.
const requests = realms.map({
  persist: 'dualControl.requests',
  expiresAt: function (row: Json): number | null {
    const until = row && typeof row === 'object' ? Number(row.keepUntil) : 0;
    return until > 0 ? (until + 3600) * 1000 : null;
  }
});

// The parts of a `realms.map()` store this module uses.
interface Store {
  get(key: string): any;
  set(key: string, value: any): unknown;
  delete(key: string): boolean;
  forEach(fn: (value: any, key: string) => void): void;
}

// Who asked, or who decided, as `/admin-api`'s gate named them
// (`res.locals.apiCaller`).
interface Caller {
  kind: string;
  name: string;
  sub?: string;
  clientId?: string;
  realm?: string;
  authTime?: number;
  roles?: string[];
}

// What a predicate is handed besides the body.
interface RowContext {
  // Whether two-person approval is on in a realm (the ambient one for '').
  onIn(realmId: string): boolean;
  // The people holding a console roster role (`write`, `security`) here.
  holders(rosterRole: string): string[];
  // The configured group names of the console roles.
  consoleGroups(): string[];
}

// One held act.
interface HeldRow {
  // The `/admin-api` operation.
  operationId: string;
  // What it does, for the console, the API's list and the audit row.
  what: string;
  // Held only when this answers true; absent, always.
  when?: (body: Json, ctx: RowContext) => boolean;
  // A realm, other than the one the act is made in, whose own setting also
  // holds it (a realm removed, or a realm's own settings written from
  // outside it).
  alsoIn?: (body: Json) => string;
}

// The setting `admin.dualControl` being turned off, or its lifetime changed,
// by a body of the settings operations: the control holding its own off
// switch, or one administrator could take it off and then act alone.
function touchesControl(key: unknown): boolean {
  log.debug("Entering touchesControl().");
  const k = String(key || '').trim();
  log.debug("Leaving touchesControl().");
  return k === SETTING || k === LIFETIME_SETTING;
}

// Whether a raw setting value reads as on.
function readsOn(value: unknown): boolean {
  log.debug("Entering readsOn().");
  const v = String(value === undefined || value === null ? '' : value)
    .trim().toLowerCase();
  log.debug("Leaving readsOn().");
  return v === 'true' || v === '1' || v === 'on' || v === 'yes';
}

// A setting write that would leave the control off or change its lifetime.
function settingWrite(body: Json): boolean {
  log.debug("Entering settingWrite().");
  const b = body || {};
  const held = touchesControl(b.key) &&
    (String(b.key).trim() === LIFETIME_SETTING || !readsOn(b.value));
  log.debug("Leaving settingWrite(). " + held);
  return held;
}

// ---------------------------------------------------------------------------
// THE TABLE. One row per `/admin-api` operation; see the header.
// ---------------------------------------------------------------------------
const HELD: ReadonlyArray<HeldRow> = Object.freeze([
  // DELETING A REALM. Held by the setting where the act is made, or in the
  // realm being removed.
  { operationId: 'removeRealm', what: 'Remove a trust realm',
    alsoIn: function (body: Json): string {
      return String((body || {}).id || '');
    } },
  // GRANTING AN ADMINISTRATOR ROLE, through each door that grants one: the
  // roster, the role register (a member, or a client conferring the role on
  // everybody who signs in through it) and the role's group.
  { operationId: 'grantAdminRole',
    what: 'Grant an administrator role' },
  { operationId: 'addRoleMember',
    what: 'Add a member to an administrator role',
    when: function (body: Json): boolean {
      return CONSOLE_ROLE_NAMES.indexOf(
        String((body || {}).role || '').trim().toUpperCase()) >= 0;
    } },
  { operationId: 'addRoleConferringClient',
    what: 'Let a client confer an administrator role',
    when: function (body: Json): boolean {
      return CONSOLE_ROLE_NAMES.indexOf(
        String((body || {}).role || '').trim().toUpperCase()) >= 0;
    } },
  { operationId: 'addGroupMember',
    what: 'Add a member to an administrator role\'s group',
    when: function (body: Json, ctx: RowContext): boolean {
      const group = String((body || {}).group || '').trim().toLowerCase()
        .replace(/^cn=([^,]+),.*$/, '$1');
      return ctx.consoleGroups().indexOf(group) >= 0;
    } },
  // TAKING THE CONTROL OUT OF FORCE: a revoke that would leave fewer than
  // two people holding Admin Write or Security Administrator (see the
  // header's single-administrator rule).
  { operationId: 'revokeAdminRole',
    what: 'Revoke an administrator role from one of the last two holders',
    when: function (body: Json, ctx: RowContext): boolean {
      const role = String((body || {}).role || '').trim();
      if (role !== 'write' && role !== 'security') {
        return false;
      }
      const name = String((body || {}).username || '').trim().toLowerCase();
      const holders = ctx.holders(role).map(function (one: string) {
        return one.toLowerCase();
      });
      return holders.indexOf(name) >= 0 && holders.length - 1 < 2;
    } },
  // THE CERTIFICATE AUTHORITY: re-keying the Root, a branch, an Issuing CA.
  { operationId: 'buildPkiRoot', what: 'Re-key the Root CA' },
  { operationId: 'buildPkiScope',
    what: 'Re-key an Intermediate CA and its branch' },
  { operationId: 'reissuePkiUseCase', what: 'Re-key an Issuing CA' },
  // Revoking an issuing CA: a serial on the Root's or an Intermediate's list
  // is a CA certificate, since those two issue nothing else.
  { operationId: 'revokePkiCertificate',
    what: 'Revoke a CA certificate',
    when: function (body: Json): boolean {
      const ca = String((body || {}).ca || '').trim();
      return ca === 'root' || ca === 'intermediate';
    } },
  // Replacing a trust anchor: an imported CA, the client-certificate
  // truststore, the signer truststore.
  { operationId: 'importPkiCa',
    what: 'Import a CA in place of one built here' },
  { operationId: 'addTrustAnchors',
    what: 'Add a client-certificate trust anchor' },
  { operationId: 'removeTrustAnchor',
    what: 'Remove a client-certificate trust anchor' },
  { operationId: 'addSignerTrustAnchors', what: 'Add a signer trust anchor' },
  { operationId: 'removeSignerTrustAnchor',
    what: 'Remove a signer trust anchor' },
  // THE SIGNING KEYS: rotate on demand, import an operator's key, and retire
  // (destroy) an imported one — unpinning is the one act that retires an
  // operator-supplied signing key.
  { operationId: 'rotateSigningKeys', what: 'Rotate signing keys on demand' },
  { operationId: 'rotateSigningKeysEmergency',
    what: 'Rotate signing keys as compromised' },
  { operationId: 'pinPkiKeyPair', what: 'Import a signing key' },
  { operationId: 'unpinPkiKeyPair', what: 'Retire an imported signing key' },
  // THE KEY-ENCRYPTION KEY.
  { operationId: 'rotateKek', what: 'Rotate the key-encryption key' },
  // THE CONTROL'S OWN OFF SWITCH, at every door that writes a setting.
  { operationId: 'setSetting',
    what: 'Turn two-person approval off, or change its lifetime',
    when: function (body: Json): boolean {
      return settingWrite(body);
    } },
  { operationId: 'setSettings',
    what: 'Turn two-person approval off, or change its lifetime',
    when: function (body: Json): boolean {
      const b = body || {};
      return Object.keys(b).some(function (key: string) {
        return settingWrite({ key: key, value: b[key] });
      });
    } },
  { operationId: 'resetSetting',
    what: 'Turn two-person approval off, or change its lifetime',
    when: function (body: Json): boolean {
      return touchesControl((body || {}).key);
    } },
  { operationId: 'resetAllSettings',
    what: 'Reset every setting, two-person approval with them' },
  { operationId: 'setRealmSetting',
    what: 'Turn a realm\'s two-person approval off, or change its lifetime',
    when: function (body: Json): boolean {
      return settingWrite(body);
    },
    alsoIn: function (body: Json): string {
      return String((body || {}).id || '');
    } },
  { operationId: 'unsetRealmSetting',
    what: 'Turn a realm\'s two-person approval off, or change its lifetime',
    when: function (body: Json): boolean {
      return touchesControl((body || {}).key);
    },
    alsoIn: function (body: Json): string {
      return String((body || {}).id || '');
    } }
]);

interface DualControlDeps {
  log: typeof log;
  config: any;
  audit: any;
  errorCodes: any;
  realms: any;
  requests: Store;
  now: () => number;
  // Loaded when used, never at load: each is far up a chain this library
  // must not load early.
  loadRbac(): any;
  loadRolePermissions(): any;
  loadScheduler(): any;
  loadMode(): any;
}

/**
 * Two-person approval of the acts `HELD` names: the hold, the decision, the
 * replay through a handler the management API hands in, the expiry job.
 */
class DualControl {
  /**
   * Builds the module over its dependencies.
   *
   * @param deps - the logger, settings, audit log, error codes, realms, the
   *   store, a clock and lazy loaders
   */
  constructor(private readonly deps: DualControlDeps) {
    deps.log.debug("Entering DualControl.constructor().");
    deps.log.debug("Leaving DualControl.constructor().");
  }

  /**
   * The dependencies built from the real modules.
   *
   * @returns the dependencies
   */
  static defaultDeps(): DualControlDeps {
    log.debug("Entering DualControl.defaultDeps().");
    const lazy = function (name: string, path: string): () => any {
      log.debug("Entering lazy(). " + name);
      log.debug("Leaving lazy().");
      return function (): any {
        log.debug("Entering " + name + "().");
        log.debug("Leaving " + name + "().");
        return require(path);
      };
    };
    log.debug("Leaving DualControl.defaultDeps().");
    return {
      log: log,
      config: require('../common/config'),
      audit: require('../common/audit'),
      errorCodes: require('../common/error_codes'),
      realms: realms,
      requests: requests,
      // A hot path (every read asks the clock): no Entering/Leaving pair.
      now: function (): number {
        return Date.now();
      },
      loadRbac: lazy('loadRbac', '../admin-ui/admin_rbac'),
      loadRolePermissions: lazy('loadRolePermissions',
                                '../common/role_permissions'),
      loadScheduler: lazy('loadScheduler', '../cluster/scheduler'),
      loadMode: lazy('loadMode', '../common/mode')
    };
  }

  // -------------------------------------------------------------------------
  // SETTINGS AND THE TABLE
  // -------------------------------------------------------------------------
  /**
   * Whether two-person approval is on in a realm.
   *
   * @param realmId - the realm, or '' for the ambient one
   * @returns true when `admin.dualControl` is on there
   */
  on(realmId?: string): boolean {
    const { log, config, realms } = this.deps;
    log.debug("Entering DualControl.on(). " + (realmId || '(ambient)'));
    let out = false;
    const id = String(realmId || '');
    if (!id || id === realms.currentId()) {
      out = config.value(SETTING) === true;
    } else {
      const realm = realms.get(id);
      out = !!realm && realms.run(realm, function () {
        return config.value(SETTING) === true;
      });
    }
    log.debug("Leaving DualControl.on(). " + out);
    return out;
  }

  /**
   * How long a held request waits for a decision, in seconds.
   *
   * @returns the lifetime
   */
  lifetimeS(): number {
    const { log, config } = this.deps;
    log.debug("Entering DualControl.lifetimeS().");
    const hours = Number(config.value(LIFETIME_SETTING));
    log.debug("Leaving DualControl.lifetimeS().");
    return (Number.isFinite(hours) && hours > 0 ? hours : 24) * 3600;
  }

  /**
   * The table's row for an operation, whatever its body.
   *
   * @param operationId - the `/admin-api` operation
   * @returns the row, or null when the operation is never held
   */
  rowOf(operationId: string): HeldRow | null {
    const { log } = this.deps;
    log.debug("Entering DualControl.rowOf(). " + operationId);
    const row = HELD.filter(function (one: HeldRow) {
      return one.operationId === operationId;
    })[0] || null;
    log.debug("Leaving DualControl.rowOf(). " + !!row);
    return row;
  }

  /**
   * The table, as the console and `GET /admin-api/approvals` list it.
   *
   * @returns `{ operationId, what, conditional }` per row
   */
  table(): Json[] {
    const { log } = this.deps;
    log.debug("Entering DualControl.table().");
    const out = HELD.map(function (one: HeldRow) {
      return { operationId: one.operationId, what: one.what,
               conditional: typeof one.when === 'function' };
    });
    log.debug("Leaving DualControl.table(). " + out.length);
    return out;
  }

  /**
   * The row that holds this act, when two-person approval is on where it
   * applies and the row's condition holds for this body.
   *
   * @param operationId - the `/admin-api` operation
   * @param body - the request body, as the schema passed it
   * @returns the row, or null when the act runs at once
   */
  heldRowFor(operationId: string, body: Json): HeldRow | null {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering DualControl.heldRowFor(). " + operationId);
    const row = self.rowOf(operationId);
    if (!row) {
      log.debug("Leaving DualControl.heldRowFor(). Not a held act.");
      return null;
    }
    const other = row.alsoIn ? row.alsoIn(body) : '';
    if (!self.on('') && !(other && self.on(other))) {
      log.debug("Leaving DualControl.heldRowFor(). Off.");
      return null;
    }
    let held = true;
    if (typeof row.when === 'function') {
      try {
        held = !!row.when(body, self.rowContext());
      } catch (e) {
        // A condition that cannot be worked out holds the act: the control
        // fails closed, and the approver sees what was asked.
        log.debug("Caught in DualControl.heldRowFor(): " +
                  ((e && e.message) || e));
        held = true;
      }
    }
    log.debug("Leaving DualControl.heldRowFor(). " + held);
    return held ? row : null;
  }

  // What a predicate reads besides the body.
  private rowContext(): RowContext {
    const { log, config } = this.deps;
    const self = this;
    log.debug("Entering DualControl.rowContext().");
    log.debug("Leaving DualControl.rowContext().");
    return {
      onIn: function (realmId: string): boolean {
        return self.on(realmId);
      },
      holders: function (rosterRole: string): string[] {
        return self.holders(rosterRole);
      },
      consoleGroups: function (): string[] {
        return CONSOLE_GROUP_SETTINGS.map(function (key: string) {
          return String(config.value(key) || '').trim().toLowerCase();
        }).filter(Boolean);
      }
    };
  }

  /**
   * The people who hold a console roster role in the ambient realm, by the
   * name they sign in as. Applications and groups are not people and are not
   * counted: an approval is a person's.
   *
   * @param rosterRole - `write` or `security`
   * @returns the usernames, each once
   */
  holders(rosterRole: string): string[] {
    const { log } = this.deps;
    log.debug("Entering DualControl.holders(). " + rosterRole);
    const out: string[] = [];
    try {
      const roster = this.deps.loadRbac().rosterFor(rosterRole);
      const members = (roster && roster.members || [])
        .concat(roster && roster.claimed || []);
      members.forEach(function (one: Json) {
        const name = String((one && one.username) || '').trim();
        const kind = String((one && one.kind) || '');
        if (one && one.present !== false && name &&
            kind !== 'application' && kind !== 'group' &&
            out.indexOf(name) < 0) {
          out.push(name);
        }
      });
    } catch (e) {
      log.debug("Caught in DualControl.holders(): " +
                ((e && e.message) || e));
    }
    log.debug("Leaving DualControl.holders(). " + out.length);
    return out;
  }

  /**
   * The people who could decide a request needing an authority, the
   * requester left out.
   *
   * @param authority - `ADMIN_WRITE` or `SECURITY_ADMIN`
   * @param requester - the requester's name, or ''
   * @returns the usernames
   */
  approversOf(authority: string, requester: string): string[] {
    const { log } = this.deps;
    log.debug("Entering DualControl.approversOf(). " + authority);
    const role = AUTHORITY_ROSTER[authority] || 'write';
    const who = String(requester || '').trim().toLowerCase();
    // A DECISION IS A WRITE: `POST /admin-api/approvals/approve` passes the
    // gate on admin:write, so a Security Administrator who does not also
    // hold Admin Write could not reach it, and is not counted as somebody
    // who could decide.
    const writers = role === 'write' ? null
      : this.holders('write').map(function (one: string) {
        return one.toLowerCase();
      });
    const out = this.holders(role).filter(function (one: string) {
      return one.toLowerCase() !== who &&
             (!writers || writers.indexOf(one.toLowerCase()) >= 0);
    });
    log.debug("Leaving DualControl.approversOf(). " + out.length);
    return out;
  }

  // -------------------------------------------------------------------------
  // THE HOLD
  // -------------------------------------------------------------------------
  /**
   * Holds an act for a second administrator, or says why it runs at once.
   *
   * @param spec - `{ row, operationId, route, action, body, caller,
   *   authority }`: the table's row, the operation, its route and action,
   *   the validated body, the gate's caller and the role the act needed
   * @returns `{ held: true, request }` for a stored request, `{ held: false,
   *   why, code }` for an act that runs at once, or `{ held: false, refused:
   *   true, errors, code }` when it can be neither held nor run
   */
  hold(spec: Json): Json {
    const { log, audit, requests } = this.deps;
    const self = this;
    log.debug("Entering DualControl.hold(). " + spec.operationId);
    const caller: Caller | null = spec.caller || null;
    const authority = String(spec.authority || 'ADMIN_WRITE');
    // THE OPEN GATE (development's `adminApi.authRequired` off) names nobody,
    // so there are no two administrators to tell apart: the act runs, and
    // the row says so.
    if (!caller || !caller.name) {
      self.recordProceeded(spec, 'STS-ADMIN-0963',
                           'the management API named no caller');
      log.debug("Leaving DualControl.hold(). No caller.");
      return { held: false, code: 'STS-ADMIN-0963' };
    }
    // THE SINGLE-ADMINISTRATOR RULE (the header).
    const approvers = self.approversOf(authority, caller.name);
    if (approvers.length < 1) {
      self.recordProceeded(spec, 'STS-ADMIN-0962',
                           'nobody but the requester holds ' + authority);
      log.debug("Leaving DualControl.hold(). Nobody else could decide.");
      return { held: false, code: 'STS-ADMIN-0962' };
    }
    const pending = self.pendingIds();
    if (pending.length >= MAX_PENDING) {
      audit.audit({ action: 'admin.dual-control.held', category: 'admin',
                    actor: caller.name, errorCode: 'STS-ADMIN-0961',
                    target: spec.operationId, outcome: 'refused',
                    detail: { operation: spec.operationId,
                              pending: pending.length } });
      log.debug("Leaving DualControl.hold(). Too many pending.");
      return { held: false, refused: true, code: 'STS-ADMIN-0961',
               errors: ['This realm already holds ' + pending.length +
                        ' acts waiting for a second administrator. Decide ' +
                        'or withdraw some on /admin/approvals first.'] };
    }
    const now = self.nowS();
    const row = {
      id: ID_PREFIX + stsCrypto.randomToken(128),
      status: 'pending',
      operationId: String(spec.operationId),
      what: String((spec.row && spec.row.what) || spec.operationId),
      route: String(spec.route || ''),
      action: String(spec.action || ''),
      body: spec.body && typeof spec.body === 'object'
        ? JSON.parse(JSON.stringify(spec.body)) : {},
      requester: {
        kind: String(caller.kind || 'person'),
        name: String(caller.name),
        sub: String(caller.sub || ''),
        clientId: String(caller.clientId || ''),
        realm: String(caller.realm || '')
      },
      authority: authority,
      approvers: approvers.length,
      createdAt: now,
      expiresAt: now + self.lifetimeS(),
      keepUntil: now + self.lifetimeS() + RETENTION_S
    };
    requests.set(row.id, row);
    self.notePending(row.id, true);
    audit.audit({ action: 'admin.dual-control.held', category: 'admin',
                  actor: row.requester.name, target: row.id,
                  summary: row.what + ' is held for a second administrator ' +
                           '(' + row.operationId + ').',
                  detail: { request: row.id, operation: row.operationId,
                            authority: authority,
                            expiresAt: row.expiresAt } });
    log.debug("Leaving DualControl.hold(). " + row.id);
    return { held: true, request: self.viewOf(row) };
  }

  // The audit row of an act that ran because nobody else could decide it.
  private recordProceeded(spec: Json, code: string, why: string): void {
    const { log, audit } = this.deps;
    log.debug("Entering DualControl.recordProceeded(). " + code);
    audit.audit({ action: 'admin.dual-control.proceeded', category: 'admin',
                  actor: String((spec.caller && spec.caller.name) || ''),
                  target: String(spec.operationId || ''),
                  errorCode: code, outcome: 'success',
                  summary: String(spec.operationId) + ' ran without a ' +
                           'second administrator: ' + why + '.',
                  detail: { operation: spec.operationId,
                            authority: spec.authority } });
    log.debug("Leaving DualControl.recordProceeded().");
  }

  // -------------------------------------------------------------------------
  // READS
  // -------------------------------------------------------------------------
  /**
   * One request, its deadline applied: a pending one past it is finished as
   * expired here, whenever the job last ran.
   *
   * @param id - the request's id
   * @returns the stored row, or null
   */
  get(id: string): Json {
    const { log, requests } = this.deps;
    log.debug("Entering DualControl.get(). " + id);
    const key = String(id || '');
    const row = key.indexOf(ID_PREFIX) === 0 ? requests.get(key) : null;
    if (row && row.status === 'pending' &&
        Number(row.expiresAt) <= this.nowS()) {
      this.finish(row, 'expired', '', 'it reached its deadline');
    }
    log.debug("Leaving DualControl.get(). " + !!row);
    return row || null;
  }

  /**
   * Every request this realm holds, newest first, pending ones first.
   *
   * @returns the views
   */
  list(): Json[] {
    const { log, requests } = this.deps;
    const self = this;
    log.debug("Entering DualControl.list().");
    const ids: string[] = [];
    requests.forEach(function (value: Json, key: string) {
      if (key.indexOf(ID_PREFIX) === 0) {
        ids.push(key);
      }
    });
    const out = ids.map(function (id: string) {
      return self.get(id);
    }).filter(Boolean).sort(function (a: Json, b: Json) {
      const pa = a.status === 'pending' ? 0 : 1;
      const pb = b.status === 'pending' ? 0 : 1;
      return pa - pb || Number(b.createdAt) - Number(a.createdAt);
    }).map(function (row: Json) {
      return self.viewOf(row);
    });
    log.debug("Leaving DualControl.list(). " + out.length);
    return out;
  }

  /**
   * A request as the console and the API show it: the body with its secret
   * members masked.
   *
   * @param row - the stored row
   * @returns the view
   */
  viewOf(row: Json): Json {
    const { log } = this.deps;
    log.debug("Entering DualControl.viewOf().");
    const body: Json = {};
    Object.keys(row.body || {}).forEach(function (key: string) {
      const value = row.body[key];
      body[key] = SECRET_MEMBER.test(key) && value !== '' &&
                  value !== undefined && value !== null
        ? '(withheld)'
        : (typeof value === 'string' && value.length > 400
          ? value.slice(0, 400) + '…' : value);
    });
    const out: Json = {
      id: row.id, status: row.status, operationId: row.operationId,
      what: row.what, action: row.action, body: body,
      requester: row.requester.name, authority: row.authority,
      createdAt: DualControl.instant(row.createdAt),
      expiresAt: DualControl.instant(row.expiresAt)
    };
    if (row.decidedBy) {
      out.decidedBy = row.decidedBy;
    }
    if (row.decidedAt) {
      out.decidedAt = DualControl.instant(row.decidedAt);
    }
    if (row.reason) {
      out.reason = row.reason;
    }
    if (row.outcome) {
      out.outcome = row.outcome;
    }
    log.debug("Leaving DualControl.viewOf().");
    return out;
  }

  /**
   * What `/admin/mode` and `GET /admin-api/approvals` say about the control
   * in this realm: on or off, how many people hold each authority, and
   * whether it is in force.
   *
   * @returns `{ on, lifetimeHours, authorities, inForce, why }`
   */
  state(): Json {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering DualControl.state().");
    const on = self.on('');
    const authorities = Object.keys(AUTHORITY_ROSTER).map(function (a) {
      const holders = self.approversOf(a, '');
      return { authority: a, holders: holders.length,
               inForce: on && holders.length >= 2 };
    });
    const tokenRequired =
      self.deps.loadMode().valueInForce('adminApi.authRequired') === true;
    const inForce = on && tokenRequired && authorities.every(function (one) {
      return one.inForce;
    });
    const why = !on
      ? 'Off: every act runs when its administrator asks.'
      : (!tokenRequired
        ? 'On, but not in force: adminApi.authRequired is off, so the ' +
          'management API names no administrator and every act runs, ' +
          'with an audit row saying nobody approved it.'
        : (inForce
          ? 'In force: a held act waits for a second administrator.'
          : 'On, but fewer than two people hold ' +
            authorities.filter(function (one) {
              return !one.inForce;
            }).map(function (one) {
              return one.authority;
            }).join(' and ') + ': an act needing that authority runs ' +
            'without a second approver, with an audit row saying so, so ' +
            'that the realm cannot be locked out.'));
    log.debug("Leaving DualControl.state(). " + inForce);
    return { on: on, lifetimeHours: Math.round(self.lifetimeS() / 3600),
             authorities: authorities, inForce: inForce, why: why,
             pending: self.pendingIds().length };
  }

  // -------------------------------------------------------------------------
  // THE DECISIONS
  // -------------------------------------------------------------------------
  /**
   * Checks that a caller may decide a request: a person, not the requester,
   * holding the authority the act needed. Writes the refusal's audit row.
   *
   * @param row - the pending row
   * @param caller - the gate's caller
   * @param verb - `approve` or `refuse`
   * @returns null when they may, or `{ ok: false, errors, errorCode }`
   */
  private mayDecide(row: Json, caller: Caller | null, verb: string): Json {
    const { log, audit } = this.deps;
    log.debug("Entering DualControl.mayDecide(). " + verb);
    let code = '';
    let why = '';
    const name = String((caller && caller.name) || '');
    if (!caller || !name || caller.kind !== 'person') {
      code = 'STS-ADMIN-0958';
      why = 'Only a person signed in to the console or holding a person\'s ' +
            'access token may ' + verb + ' a held act; this caller is ' +
            (name ? 'an application' : 'nobody') + '.';
    } else if (name.toLowerCase() === String(row.requester.name)
                 .toLowerCase() ||
               (caller.sub && row.requester.sub &&
                String(caller.sub) === String(row.requester.sub))) {
      code = 'STS-ADMIN-0957';
      why = 'You asked for this act, so you cannot ' + verb + ' it: a ' +
            'second, different administrator must. You may withdraw it.';
    } else if ((caller.roles || []).indexOf(row.authority) < 0) {
      code = 'STS-ADMIN-0959';
      why = 'Deciding this act needs ' + row.authority + ', the authority ' +
            'the act itself needs, and this token does not carry it.';
    }
    if (!code) {
      log.debug("Leaving DualControl.mayDecide(). Yes.");
      return null;
    }
    audit.audit({ action: 'admin.dual-control.decision-refused',
                  category: 'admin', actor: name, target: row.id,
                  errorCode: code,
                  detail: { request: row.id, operation: row.operationId,
                            verb: verb } });
    log.debug("Leaving DualControl.mayDecide(). " + code);
    return { ok: false, errors: [why], errorCode: code };
  }

  // A request that cannot be decided: unknown, or no longer pending.
  private undecidable(id: string, caller: Caller | null, verb: string): Json {
    const { log, audit } = this.deps;
    log.debug("Entering DualControl.undecidable(). " + verb);
    const row = this.get(id);
    let out: Json = null;
    if (!row) {
      out = { ok: false, errorCode: 'STS-ADMIN-0956', status: 404,
              errors: ['There is no held act ' + JSON.stringify(String(id)) +
                       ' in this realm.'] };
    } else if (row.status !== 'pending') {
      out = { ok: false, status: 409,
              errorCode: row.status === 'expired' ? 'STS-ADMIN-0960'
                                                  : 'STS-ADMIN-0964',
              errors: ['This held act is ' + row.status + ', so it can no ' +
                       'longer be ' + (verb === 'withdraw' ? 'withdrawn'
                         : verb + 'd') + '.'] };
    }
    if (out) {
      audit.audit({ action: 'admin.dual-control.decision-refused',
                    category: 'admin',
                    actor: String((caller && caller.name) || ''),
                    target: String(id), errorCode: out.errorCode,
                    detail: { request: String(id), verb: verb } });
    }
    log.debug("Leaving DualControl.undecidable(). " + !!out);
    return out ? { out: out } : { row: row };
  }

  /**
   * Approves a held act and runs it: the stored operation, through the
   * handler `replay` calls, as the requester's act. The requester must still
   * hold the authority; the handler re-validates the body against the state
   * as it is now.
   *
   * @param id - the request
   * @param caller - the approver, as the gate named them
   * @param replay - `(request) => Promise<{ status, body }>`, the
   *   management API's run of the stored operation
   * @returns `{ ok, status, body, approval }`, or a refusal `{ ok: false,
   *   errors, errorCode, status }`
   */
  async approve(id: string, caller: Caller | null,
                replay: (row: Json) => Promise<Json>): Promise<Json> {
    const { log, audit } = this.deps;
    const self = this;
    log.debug("Entering DualControl.approve(). " + id);
    const found = self.undecidable(id, caller, 'approve');
    if (found.out) {
      log.debug("Leaving DualControl.approve(). Undecidable.");
      return found.out;
    }
    const row = found.row;
    const refused = self.mayDecide(row, caller, 'approve');
    if (refused) {
      log.debug("Leaving DualControl.approve(). May not decide.");
      return Object.assign({ status: 403 }, refused);
    }
    // THE REQUESTER STILL HOLDS IT: a role revoked since the request was
    // made takes the request with it, as it would have taken the act.
    if (!self.requesterStillHolds(row)) {
      self.finish(row, 'failed', caller.name,
                  'the requester no longer holds ' + row.authority,
                  'STS-ADMIN-0965');
      log.debug("Leaving DualControl.approve(). Requester lost it.");
      return { ok: false, status: 409, errorCode: 'STS-ADMIN-0965',
               errors: [row.requester.name + ' no longer holds ' +
                        row.authority + ', so the act they asked for is not ' +
                        'run.'] };
    }
    // Claimed before the replay, so a second approver racing this one finds
    // it decided rather than running the act twice.
    row.status = 'approved';
    row.decidedBy = caller.name;
    row.decidedAt = self.nowS();
    self.deps.requests.set(row.id, row);
    self.notePending(row.id, false);
    let answer: Json = null;
    try {
      answer = await replay(row);
    } catch (e) {
      log.debug("Caught in DualControl.approve(): " +
                ((e && e.message) || e));
      answer = { status: 500, body: { ok: false, errors: [
        'The held act failed when it was run.'] } };
    }
    const status = Number(answer && answer.status) || 500;
    const ok = status < 400 && !!(answer && answer.body &&
                                  answer.body.ok !== false);
    row.outcome = { status: status, ok: ok,
                    errors: ok ? [] : [].concat((answer && answer.body &&
                                                 answer.body.errors) || []) };
    self.finish(row, ok ? 'done' : 'failed', caller.name,
                ok ? 'approved and run' : 'approved, and the act was refused ' +
                'when it ran', ok ? '' : 'STS-ADMIN-0966');
    audit.audit({ action: 'admin.dual-control.approved', category: 'admin',
                  actor: row.requester.name, target: row.id,
                  errorCode: ok ? '' : 'STS-ADMIN-0966',
                  outcome: ok ? 'success' : 'failure',
                  summary: row.what + ' (' + row.operationId + '), asked by ' +
                           row.requester.name + ', approved by ' +
                           caller.name + (ok ? ', ran.' : ', was refused ' +
                           'when it ran.'),
                  detail: { request: row.id, operation: row.operationId,
                            requestedBy: row.requester.name,
                            approvedBy: caller.name, status: status } });
    log.debug("Leaving DualControl.approve(). " + status);
    return { ok: ok, status: status, body: (answer && answer.body) || {},
             approval: self.viewOf(row) };
  }

  /**
   * Refuses a held act. The same people may refuse as may approve.
   *
   * @param id - the request
   * @param caller - who refuses, as the gate named them
   * @param reason - why, optional
   * @returns `{ ok: true, approval }` or a refusal
   */
  refuse(id: string, caller: Caller | null, reason?: string): Json {
    const { log } = this.deps;
    log.debug("Entering DualControl.refuse(). " + id);
    const found = this.undecidable(id, caller, 'refuse');
    if (found.out) {
      log.debug("Leaving DualControl.refuse(). Undecidable.");
      return found.out;
    }
    const refused = this.mayDecide(found.row, caller, 'refuse');
    if (refused) {
      log.debug("Leaving DualControl.refuse(). May not decide.");
      return Object.assign({ status: 403 }, refused);
    }
    this.finish(found.row, 'refused', caller.name,
                String(reason || '').slice(0, 500) || 'refused');
    log.debug("Leaving DualControl.refuse().");
    return { ok: true, approval: this.viewOf(found.row) };
  }

  /**
   * Withdraws a held act. Only its requester may.
   *
   * @param id - the request
   * @param caller - who withdraws, as the gate named them
   * @param reason - why, optional
   * @returns `{ ok: true, approval }` or a refusal
   */
  withdraw(id: string, caller: Caller | null, reason?: string): Json {
    const { log, audit } = this.deps;
    log.debug("Entering DualControl.withdraw(). " + id);
    const found = this.undecidable(id, caller, 'withdraw');
    if (found.out) {
      log.debug("Leaving DualControl.withdraw(). Undecidable.");
      return found.out;
    }
    const row = found.row;
    const name = String((caller && caller.name) || '');
    if (!name || name.toLowerCase() !==
        String(row.requester.name).toLowerCase()) {
      audit.audit({ action: 'admin.dual-control.decision-refused',
                    category: 'admin', actor: name, target: row.id,
                    errorCode: 'STS-ADMIN-0967',
                    detail: { request: row.id, verb: 'withdraw' } });
      log.debug("Leaving DualControl.withdraw(). Not the requester.");
      return { ok: false, status: 403, errorCode: 'STS-ADMIN-0967',
               errors: ['Only ' + row.requester.name + ', who asked for ' +
                        'this act, may withdraw it. Refuse it instead.'] };
    }
    this.finish(row, 'withdrawn', name,
                String(reason || '').slice(0, 500) || 'withdrawn');
    log.debug("Leaving DualControl.withdraw().");
    return { ok: true, approval: this.viewOf(row) };
  }

  // Whether the requester holds the act's authority now: the roles their
  // token's subject would be decided on, asked afresh (held ∩ carried, with
  // the authority's own permission carried).
  private requesterStillHolds(row: Json): boolean {
    const { log } = this.deps;
    log.debug("Entering DualControl.requesterStillHolds().");
    let held = false;
    try {
      const scope = row.authority === 'SECURITY_ADMIN' ? 'admin:security'
                                                       : 'admin:write';
      const claims: Json = { sub: row.requester.sub || row.requester.name,
                             client_id: row.requester.clientId || undefined };
      const effective = this.deps.loadRolePermissions().effectiveRoles(
        claims, [scope], row.requester.realm || this.deps.realms.currentId());
      held = (effective.roles || []).indexOf(row.authority) >= 0;
    } catch (e) {
      // Not known is not held: the act is not run on a guess.
      log.debug("Caught in DualControl.requesterStillHolds(): " +
                ((e && e.message) || e));
      held = false;
    }
    log.debug("Leaving DualControl.requesterStillHolds(). " + held);
    return held;
  }

  // Moves a row to a finished status, once, with its audit row. `approved`
  // rows write their own row in approve(); every other status's is here.
  private finish(row: Json, status: string, actor: string, reason: string,
                 code?: string): void {
    const { log, audit, requests } = this.deps;
    log.debug("Entering DualControl.finish(). " + row.id + " " + status);
    const now = this.nowS();
    row.status = status;
    if (actor) {
      row.decidedBy = actor;
    }
    row.decidedAt = row.decidedAt || now;
    row.reason = reason;
    row.keepUntil = now + RETENTION_S;
    requests.set(row.id, row);
    this.notePending(row.id, false);
    if (status !== 'done' && status !== 'failed') {
      audit.audit({ action: status === 'refused'
                      ? 'admin.dual-control.refused'
                      : (status === 'withdrawn'
                        ? 'admin.dual-control.withdrawn'
                        : 'admin.dual-control.expired'),
                    category: 'admin',
                    actor: actor || 'the two-person approval service',
                    target: row.id, errorCode: code || '',
                    summary: row.what + ' (' + row.operationId + '), asked ' +
                             'by ' + row.requester.name + ', ' + status +
                             (reason ? ': ' + reason : '') + '.',
                    detail: { request: row.id, operation: row.operationId,
                              requestedBy: row.requester.name,
                              decidedBy: actor || '' } });
    } else if (status === 'failed' && code === 'STS-ADMIN-0965') {
      audit.audit({ action: 'admin.dual-control.failed', category: 'admin',
                    actor: actor, target: row.id, errorCode: code,
                    outcome: 'refused',
                    summary: row.what + ' (' + row.operationId + ') was not ' +
                             'run: ' + reason + '.',
                    detail: { request: row.id, operation: row.operationId,
                              requestedBy: row.requester.name,
                              decidedBy: actor } });
    }
    log.debug("Leaving DualControl.finish().");
  }

  // -------------------------------------------------------------------------
  // THE PENDING INDEX
  // -------------------------------------------------------------------------
  // The ids the pending index lists.
  private pendingIds(): string[] {
    const { log, requests } = this.deps;
    log.debug("Entering DualControl.pendingIds().");
    const row = requests.get(PENDING_KEY);
    const out = row && Array.isArray(row.ids) ? row.ids.slice(0) : [];
    log.debug("Leaving DualControl.pendingIds(). " + out.length);
    return out;
  }

  // Adds an id to the pending index, or takes it out.
  private notePending(id: string, add: boolean): void {
    const { log, requests } = this.deps;
    log.debug("Entering DualControl.notePending(). " + add);
    const ids = this.pendingIds().filter(function (one: string) {
      return one !== id;
    });
    if (add) {
      ids.push(id);
    }
    if (ids.length) {
      requests.set(PENDING_KEY, { ids: ids,
                                  keepUntil: this.nowS() + RETENTION_S * 4 });
    } else if (requests.get(PENDING_KEY)) {
      requests.delete(PENDING_KEY);
    }
    log.debug("Leaving DualControl.notePending().");
  }

  // -------------------------------------------------------------------------
  // THE JOB (rcbj's rule on periodic work): expiry, and the retention.
  // -------------------------------------------------------------------------
  /**
   * One run in the ambient realm: every pending request past its deadline
   * moved to `expired`, every finished one past its retention removed, and
   * the pending index repaired.
   *
   * @param ctx - the scheduler's run context
   * @returns `{ summary }`
   */
  sweep(ctx?: Json): Json {
    const { log, requests, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering DualControl.sweep().");
    const now = self.nowS();
    let expired = 0;
    let removed = 0;
    try {
      const rows: Json[] = [];
      requests.forEach(function (row: Json, key: string) {
        if (key.indexOf(ID_PREFIX) === 0 && row) {
          rows.push(row);
        }
      });
      const pending: string[] = [];
      for (let i = 0; i < rows.length; i += 1) {
        if (ctx && typeof ctx.stillOwner === 'function' && !ctx.stillOwner()) {
          break;
        }
        const row = rows[i];
        if (row.status === 'pending' && Number(row.expiresAt) <= now) {
          self.finish(row, 'expired', '', 'it reached its deadline');
          expired += 1;
        } else if (row.status === 'pending') {
          pending.push(String(row.id));
        } else if (Number(row.keepUntil) <= now) {
          requests.delete(row.id);
          removed += 1;
        }
      }
      if (pending.length) {
        requests.set(PENDING_KEY, { ids: pending,
                                    keepUntil: now + RETENTION_S * 4 });
      } else if (requests.get(PENDING_KEY)) {
        requests.delete(PENDING_KEY);
      }
    } catch (e) {
      log.error(errorCodes.tag('STS-ADMIN-0968') + 'dual control: the ' +
                'sweep failed: ' + ((e && e.message) || e));
      throw e;
    }
    const summary = expired || removed
      ? expired + ' held act(s) expired, ' + removed + ' removed.' : '';
    log.debug("Leaving DualControl.sweep(). " + (summary || 'Nothing.'));
    return { summary: summary };
  }

  /**
   * Registers the job with the scheduler, once per process.
   *
   * @returns true when registered, false when it already was
   */
  registerJobs(): boolean {
    const { log, config } = this.deps;
    const self = this;
    log.debug("Entering DualControl.registerJobs().");
    const s = self.deps.loadScheduler();
    if (s.job(JOB)) {
      log.debug("Leaving DualControl.registerJobs(). Already there.");
      return false;
    }
    s.register({
      id: JOB,
      title: 'Two-person approval expiry',
      describe: 'Moves every administrator act held for a second ' +
                'administrator (#2166) past its deadline to expired, ' +
                'writing its audit row, removes a finished one a week ' +
                'after it finished, and repairs the list of pending ones. ' +
                'A read applies the deadline itself, so this is the record ' +
                'and the clean-up, never what decides.',
      owner: 'admin-core/dual_control.ts',
      kind: 'cluster', scope: 'realm',
      everyMs: function (): number {
        return JOB_EVERY_MS;
      },
      off: function (): string {
        let pending = 0;
        try {
          pending = self.pendingIds().length;
        } catch (e) {
          log.debug("Caught in off(): " + ((e && e.message) || e));
        }
        return config.value(SETTING) !== true && !pending
          ? 'admin.dualControl is off in this realm and nothing is held.'
          : '';
      },
      manual: true,
      timeoutS: 120,
      run: function (ctx: Json): Promise<Json> {
        return Promise.resolve().then(function () {
          return self.sweep(ctx);
        });
      }
    });
    log.debug("Leaving DualControl.registerJobs().");
    return true;
  }

  /**
   * Forgets every request of the ambient realm. For a test.
   */
  resetForTests(): void {
    const { log, requests } = this.deps;
    log.debug("Entering DualControl.resetForTests().");
    const keys: string[] = [];
    requests.forEach(function (value: Json, key: string) {
      keys.push(key);
    });
    keys.forEach(function (key: string) {
      requests.delete(key);
    });
    log.debug("Leaving DualControl.resetForTests().");
  }

  // The clock, in seconds. A hot path (every read asks it): no
  // Entering/Leaving pair.
  private nowS(): number {
    return Math.floor(this.deps.now() / 1000);
  }

  /**
   * Formats epoch seconds as an RFC 3339 instant.
   *
   * @param s - epoch seconds
   * @returns the instant, `Z`
   */
  static instant(s: number): string {
    log.debug("Entering DualControl.instant().");
    const n = Number(s);
    log.debug("Leaving DualControl.instant().");
    return Number.isFinite(n) && n > 0 && n < 8.64e12
      ? new Date(n * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z') : '';
  }
}

// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2); the job is
// registered when it is installed, as `authzen_access_request.ts`'s is.
const slot = new InstanceSlot<DualControl>(
  'admin-core/dual_control',
  () => new DualControl(DualControl.defaultDeps()),
  function (instance: DualControl): void {
    instance.registerJobs();
  },
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * Two-person approval for high-risk administrator acts (#2166).
 * @namespace
 */
export = {
  DualControl: DualControl,
  installInstance: (instance: DualControl): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  HELD: HELD,
  STATES: STATES,
  JOB: JOB,
  SETTING: SETTING,
  LIFETIME_SETTING: LIFETIME_SETTING,
  on: slot.forward('on'),
  lifetimeS: slot.forward('lifetimeS'),
  rowOf: slot.forward('rowOf'),
  table: slot.forward('table'),
  heldRowFor: slot.forward('heldRowFor'),
  holders: slot.forward('holders'),
  approversOf: slot.forward('approversOf'),
  hold: slot.forward('hold'),
  get: slot.forward('get'),
  list: slot.forward('list'),
  viewOf: slot.forward('viewOf'),
  state: slot.forward('state'),
  approve: slot.forward('approve'),
  refuse: slot.forward('refuse'),
  withdraw: slot.forward('withdraw'),
  sweep: slot.forward('sweep'),
  registerJobs: slot.forward('registerJobs'),
  resetForTests: slot.forward('resetForTests')
};
