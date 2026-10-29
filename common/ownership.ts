// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: ownership.ts
//
// ===========================================================================
// WHO OWNS WHAT, AND WHAT AN OWNER MAY NOT TOUCH (#607, 2026-10-13).
//
// rcbj: "I'd like for a user to be able to make updates to the application,
// role, service account, and group objects that they own in the User
// Portal." Four kinds of object name their owners — a role's and a group's
// `owner` (#604, #603), a service account's `stsServiceAccountOwner` (#600)
// and an application's `appOwner` (#604) — each value the DN of a PERSON or
// a GROUP of the realm. Since #607 an owner may administer what they own
// through `/admin-api`, with `owner:read` and `owner:write`; WHETHER they may,
// object by object and action by action, is the access-control policy's
// second rule (`xacml/xacml_templates.ts`), and this file answers the facts
// that rule decides on:
//
//   * WHO THE PERSON IS AS AN OWNER — their own DN and every group they are
//     in, direct and through `memberOf` (`identityOf()`), the policy's
//     `urn:sts:xacml:owner-identity`;
//   * WHO OWNS AN OBJECT — its owner DNs as stored (`objectOf()`), the
//     policy's `urn:sts:xacml:object-owner`;
//   * WHETHER THE OBJECT IS CLOSED TO ITS OWNERS (`protectionOf()`), the
//     policy's `urn:sts:xacml:object-protected`;
//   * WHETHER THE PERSON OWNS ANYTHING AT ALL (`ownsAnything()`), which is
//     what OWNER_READ and OWNER_WRITE are computed from (`common/roles.js`,
//     rcbj's decision 2).
//
// **A FACT, NEVER A DECISION.** Nothing here answers "may". A PIP that
// decided would be the `if` in a handler that rcbj's directive — every
// authorization decision is policy — exists to remove; the policy reads these
// facts and an override of `access-control` can read them differently.
//
// **DNs ARE COMPARED, NEVER NAMES**, through `dnKey()`: case and the spaces
// around a comma do not matter, which is how the directory compares them.
// Owner values are written as DNs by every door that writes one (each
// resolves a username or a cn first), so a DN is what is stored.
//
// ---------------------------------------------------------------------------
// PROTECTED: WHAT AN OWNER MUST NEVER BE ABLE TO DO (#607 section 4).
//
// Ownership is delegated administration, so the obvious paths from owning
// something to holding this service's own permissions are closed, and they
// are closed as a FACT the policy reads rather than as a refusal here:
//
//   * a ROLE that is built in or native (ADMIN_READ, ADMIN_WRITE,
//     ADMIN_CONSOLE, DEVICE_COMPLIANCE, the owner roles and the computed
//     ones), or that authorizes a native permission or one of this service's
//     protected scopes (#110) — otherwise its owner adds themselves as a
//     member and is issued the scope;
//   * a GROUP that grants something by being named — the console rosters
//     (`admin.readGroup`, `admin.writeGroup`), `roles.remotePepGroup`,
//     `roles.xacmlUserGroup` — or that is a member of a protected role;
//   * an APPLICATION that is one of this service's own (the console's, the
//     portal's, the management API's and the debugger's clients), that is a
//     member of a protected role, or that declares a protected scope — its
//     owner regenerating its secret would hold whatever it holds;
//   * a SERVICE ACCOUNT that holds a protected role — its owner pushing its
//     rotated password to a destination they can read would be the same;
//   * and anything an administrator MARKED (`stsOwnerProtected`, rcbj's
//     decision 4), through `setProtected()`.
//
// ---------------------------------------------------------------------------
// A LIBRARY (rule 3). It registers no route, and everything it reads it
// reaches LAZILY, when a decision asks: the directory, the role register, the
// application registry, the service accounts and the scope policy are built
// at 9 and later, and `common/role_permissions.ts` — which oauth2 at 9
// requires — reads this file. So a require of it closes no cycle and moves
// no route.
// ===========================================================================

import helpers = require('./helpers');
import InstanceSlot = require('./instance_slot');
import errorCodes = require('./error_codes');

const { log } = helpers;

type Json = any;

/**
 * The four kinds of object an owner may administer, as the policy's
 * `urn:sts:xacml:object-kind` names them.
 */
const KINDS = Object.freeze(['role', 'group', 'service-account',
                             'application']);

// The reason an administrator's mark gives (rcbj's decision 4), named once so
// `objectOf()` can say whether the mark is set as well as why it is closed.
// THE CONSOLE MATCHES IT TO THE LETTER — `admin-ui/web_answers.ts`'s
// OWNER_MARK_REASON and `web_groups.ts`'s `ownerProtectionSection()` tell the
// mark from the reasons no checkbox opens by it — so a change here is a
// change there too.
const MARKED = 'an administrator closed it to its owners';

/**
 * Who a person is as an owner: their DN, their groups and every DN that
 * makes something theirs, compared.
 */
interface OwnerIdentity {
  username: string;
  dn: string;
  groups: { dn: string; cn: string }[];
  // `dnKey()` of the person's DN and of each group's.
  keys: string[];
}

/**
 * One object's ownership facts.
 */
interface ObjectFacts {
  found: boolean;
  kind: string;
  name: string;
  dn: string;
  // The owner values as stored.
  owners: string[];
  // Closed to its owners, and why ('' where it is not).
  protected: boolean;
  reasons: string[];
  // Whether an administrator's mark is one of the reasons.
  marked: boolean;
}

interface OwnershipDeps {
  log: typeof log;
  errorCodes: typeof errorCodes;
  config: () => Json;
  ldap: () => Json;
  roles: () => Json;
  applications: () => Json;
  serviceAccounts: () => Json;
  scopePolicy: () => Json;
}

/**
 * Who owns what, and what an owner may not touch (#607): the facts the
 * access-control policy's owner rule decides on.
 */
class Ownership {
  /**
   * The settings that name a group which grants something by being held:
   * the console rosters and the two group-derived roles. One list, read here
   * and by `ldap/ldap_server.js`'s federated-group guard (#358), so the two
   * cannot disagree about which groups are authority.
   */
  static readonly GRANTING_GROUP_SETTINGS: readonly string[] = [
    'admin.readGroup', 'admin.writeGroup', 'roles.remotePepGroup',
    'roles.xacmlUserGroup'];

  /**
   * Builds the module over its dependencies.
   *
   * @param deps - the logger, the error codes and lazy reads of the
   *   registers
   */
  constructor(private readonly deps: OwnershipDeps) {
    deps.log.debug("Entering Ownership.constructor().");
    deps.log.debug("Leaving Ownership.constructor().");
  }

  /**
   * Returns the dependencies the composition root passes.
   *
   * @returns the production dependency set
   */
  static defaultDeps(): OwnershipDeps {
    log.debug("Entering Ownership.defaultDeps().");
    log.debug("Leaving Ownership.defaultDeps().");
    return {
      log: log,
      errorCodes: errorCodes,
      config: function config() {
        log.debug("Entering config().");
        log.debug("Leaving config().");
        return require('./config');
      },
      ldap: function ldap() {
        log.debug("Entering ldap().");
        log.debug("Leaving ldap().");
        return require('../ldap/ldap_server');
      },
      roles: function roles() {
        log.debug("Entering roles().");
        log.debug("Leaving roles().");
        return require('./roles');
      },
      applications: function applications() {
        log.debug("Entering applications().");
        log.debug("Leaving applications().");
        return require('./applications');
      },
      serviceAccounts: function serviceAccounts() {
        log.debug("Entering serviceAccounts().");
        log.debug("Leaving serviceAccounts().");
        return require('./service_accounts');
      },
      scopePolicy: function scopePolicy() {
        log.debug("Entering scopePolicy().");
        log.debug("Leaving scopePolicy().");
        return require('./scope_policy');
      }
    };
  }

  /**
   * A DN as it is compared: case and the spaces around a comma do not
   * matter.
   *
   * @param dn - a DN
   * @returns the comparable form
   */
  static dnKey(dn: unknown): string {
    log.debug("Entering Ownership.dnKey().");
    log.debug("Leaving Ownership.dnKey().");
    return String(dn == null ? '' : dn).toLowerCase()
      .replace(/\s*,\s*/g, ',').trim();
  }

  /**
   * Tells whether a kind is one an owner may administer.
   *
   * @param kind - a kind
   * @returns true for one of `KINDS`
   */
  static isKind(kind: unknown): boolean {
    log.debug("Entering Ownership.isKind().");
    log.debug("Leaving Ownership.isKind().");
    return KINDS.indexOf(String(kind)) >= 0;
  }

  // ---------------------------------------------------------------------------
  // WHO THE PERSON IS AS AN OWNER.
  // ---------------------------------------------------------------------------
  /**
   * Who a person is as an owner, in the ambient realm: their own DN and
   * every group they are in, direct and through `memberOf`.
   *
   * @param username - the person's username (or DN, or `urn:uuid:` subject)
   * @returns `{ username, dn, groups, keys }`; empty keys for nobody
   */
  identityOf(username: unknown): OwnerIdentity {
    const { log } = this.deps;
    log.debug("Entering Ownership.identityOf().");
    const out: OwnerIdentity = { username: String(username || ''), dn: '',
                                 groups: [], keys: [] };
    if (!out.username) {
      log.debug("Leaving Ownership.identityOf(). Nobody named.");
      return out;
    }
    try {
      const found = this.deps.ldap().groupsOfUser(out.username) || {};
      if (found.entryFound) {
        out.dn = String(found.dn || '');
      }
      out.groups = (found.groups || []).map(function (one: Json): Json {
        return { dn: String(one.dn), cn: String(one.cn || one.dn) };
      });
    } catch (e) {
      // A directory that cannot be read makes the person nobody's owner:
      // the safe direction, since an owner is somebody something is opened
      // to.
      log.debug("Caught in Ownership.identityOf(): " +
                ((e && e.message) || e));
    }
    out.keys = [out.dn].concat(out.groups.map(function (one) {
      return one.dn;
    })).filter(Boolean).map(Ownership.dnKey);
    log.debug("Leaving Ownership.identityOf(). " + out.keys.length +
              " key(s).");
    return out;
  }

  // Whether any of `owners` is among `keys`.
  private names(owners: string[], keys: string[]): boolean {
    const { log } = this.deps;
    log.debug("Entering Ownership.names().");
    const answer = (owners || []).some(function (dn) {
      return keys.indexOf(Ownership.dnKey(dn)) >= 0;
    });
    log.debug("Leaving Ownership.names(). " + answer);
    return answer;
  }

  // ---------------------------------------------------------------------------
  // WHETHER THE PERSON OWNS ANYTHING — OWNER_READ AND OWNER_WRITE.
  //
  // Every register is read, at the moment of the decision, because the role
  // is computed (rcbj's decision 2): an owner taken off the last thing they
  // owned does not hold it on the next request. The cheap registers first,
  // and the first hit answers.
  // ---------------------------------------------------------------------------
  /**
   * Tells whether a person owns anything of the four kinds in the ambient
   * realm, directly or through a group they are in.
   *
   * @param username - the person's username
   * @returns true when some object names them or a group of theirs
   */
  ownsAnything(username: unknown): boolean {
    const { log } = this.deps;
    log.debug("Entering Ownership.ownsAnything().");
    const who = this.identityOf(username);
    if (!who.keys.length) {
      log.debug("Leaving Ownership.ownsAnything(). Nobody.");
      return false;
    }
    const self = this;
    const asks: (() => boolean)[] = [
      function roles(): boolean {
        log.debug("Entering roles().");
        log.debug("Leaving roles().");
        return self.deps.roles().all().some(function (row: Json) {
          return self.names(row.owners || [], who.keys);
        });
      },
      function groups(): boolean {
        log.debug("Entering groups().");
        log.debug("Leaving groups().");
        return (self.deps.ldap().groupsOwnedBy(
          [who.dn].concat(who.groups.map(function (one) {
            return one.dn;
          })).filter(Boolean)) || []).length > 0;
      },
      function serviceAccounts(): boolean {
        log.debug("Entering serviceAccounts().");
        log.debug("Leaving serviceAccounts().");
        return self.deps.serviceAccounts().list().some(function (one: Json) {
          return self.names((one.owners || []).map(function (o: Json) {
            return o.dn;
          }), who.keys);
        });
      },
      function applications(): boolean {
        log.debug("Entering applications().");
        // The owners off the kept listing, with no view of every
        // application built per decision (#759).
        const apps = self.deps.applications();
        if (typeof apps.ownerValues === 'function') {
          log.debug("Leaving applications(). From the listing.");
          return apps.ownerValues().some(function (owners: string[]) {
            return self.names(owners, who.keys);
          });
        }
        log.debug("Leaving applications().");
        return apps.list().some(function (app: Json) {
          return self.names([].concat((app.fields || {}).appOwner || [])
            .map(String), who.keys);
        });
      }
    ];
    for (let i = 0; i < asks.length; i += 1) {
      let hit = false;
      try {
        hit = asks[i]();
      } catch (e) {
        // A register that cannot be read owns nobody anything: the safe
        // direction. The others are still asked.
        log.debug("Caught in Ownership.ownsAnything(): " +
                  ((e && e.message) || e));
        hit = false;
      }
      if (hit) {
        log.debug("Leaving Ownership.ownsAnything(). Yes.");
        return true;
      }
    }
    log.debug("Leaving Ownership.ownsAnything(). No.");
    return false;
  }

  // ---------------------------------------------------------------------------
  // ONE OBJECT.
  // ---------------------------------------------------------------------------
  /**
   * One object's ownership facts in the ambient realm: its DN, its owners as
   * stored, and whether it is closed to them and why.
   *
   * @param kind - one of `KINDS`
   * @param name - a role's name, a group's cn or DN, a service account's
   *   username, an application's identifier
   * @returns the facts; `found: false` where there is no such object
   */
  objectOf(kind: unknown, name: unknown): ObjectFacts {
    const { log } = this.deps;
    log.debug("Entering Ownership.objectOf(). kind=" + kind);
    const out: ObjectFacts = { found: false, kind: String(kind || ''),
                               name: String(name == null ? '' : name).trim(),
                               dn: '', owners: [], protected: false,
                               reasons: [], marked: false };
    if (!Ownership.isKind(out.kind) || !out.name) {
      log.debug("Leaving Ownership.objectOf(). Nothing named.");
      return out;
    }
    try {
      if (out.kind === 'role') {
        const row = this.deps.roles().read(out.name);
        if (row) {
          out.found = true;
          out.name = row.name;
          out.dn = String(row.dn || '');
          out.owners = (row.owners || []).map(String);
        }
      } else if (out.kind === 'group') {
        const group = this.deps.ldap().groupOwnership(out.name);
        if (group) {
          out.found = true;
          out.name = group.cn || group.dn;
          out.dn = group.dn;
          out.owners = group.owners.slice(0);
        }
      } else if (out.kind === 'service-account') {
        const facts = this.deps.serviceAccounts().of(out.name);
        if (facts) {
          out.found = true;
          out.name = facts.username;
          out.dn = facts.dn;
          out.owners = (facts.owners || []).map(function (one: Json) {
            return String(one.dn);
          });
        }
      } else {
        const app = this.deps.applications().get(out.name);
        if (app) {
          out.found = true;
          out.name = String(app.identifier);
          out.dn = String(app.dn || '');
          out.owners = [].concat((app.fields || {}).appOwner || [])
            .map(String).filter(Boolean);
        }
      }
    } catch (e) {
      // A register that cannot be read names no object: a decision about
      // it then has no owner to match, and refuses.
      log.debug("Caught in Ownership.objectOf(): " +
                ((e && e.message) || e));
      out.found = false;
    }
    if (out.found) {
      out.reasons = this.protectionOf(out.kind, out.name);
      out.protected = out.reasons.length > 0;
      out.marked = out.reasons.indexOf(MARKED) >= 0;
    }
    log.debug("Leaving Ownership.objectOf(). " +
              (out.found ? out.owners.length + " owner(s)" +
                           (out.protected ? ", protected." : ".")
                         : "Not found."));
    return out;
  }

  /**
   * Tells whether a person owns an object, directly or through a group.
   *
   * @param username - the person
   * @param kind - one of `KINDS`
   * @param name - the object
   * @returns true where an owner value names them or a group of theirs
   */
  owns(username: unknown, kind: unknown, name: unknown): boolean {
    const { log } = this.deps;
    log.debug("Entering Ownership.owns().");
    const facts = this.objectOf(kind, name);
    const answer = facts.found &&
                   this.names(facts.owners, this.identityOf(username).keys);
    log.debug("Leaving Ownership.owns(). " + answer);
    return answer;
  }

  // ---------------------------------------------------------------------------
  // PROTECTED — see the header for each reason.
  // ---------------------------------------------------------------------------
  // The permissions no owner may come to hold by administering something:
  // this service's protected scopes (#110), the native roles' and the owner
  // roles'.
  private protectedPermissions(): string[] {
    const { log } = this.deps;
    log.debug("Entering Ownership.protectedPermissions().");
    const roles = this.deps.roles();
    let out: string[] = [];
    try {
      out = this.deps.scopePolicy().protectedScopes().slice(0);
    } catch (e) {
      log.debug("Caught in Ownership.protectedPermissions(): " +
                ((e && e.message) || e));
      out = [];
    }
    roles.NATIVE_ROLES.concat(roles.OWNER_ROLES).forEach(function (row: Json) {
      if (out.indexOf(row.permission) < 0) {
        out.push(row.permission);
      }
    });
    log.debug("Leaving Ownership.protectedPermissions(). " + out.length);
    return out;
  }

  // The configured roles that are protected, by name, with the reason.
  private protectedRoles(): Record<string, string> {
    const { log } = this.deps;
    log.debug("Entering Ownership.protectedRoles().");
    const roles = this.deps.roles();
    const permissions = this.protectedPermissions();
    const out: Record<string, string> = {};
    roles.all().forEach(function (row: Json) {
      if (row.native) {
        out[row.name] = 'it is a native role of this service';
        return;
      }
      const held = (row.permissions || []).filter(function (one: string) {
        return permissions.indexOf(one) >= 0;
      });
      if (held.length) {
        out[row.name] = 'it authorizes ' + held.join(', ') + ', a ' +
          'permission of this service no owner may come to hold';
      }
    });
    log.debug("Leaving Ownership.protectedRoles(). " +
              Object.keys(out).length + " role(s).");
    return out;
  }

  // The group names that grant something by being named.
  private grantingGroups(): string[] {
    const { log } = this.deps;
    log.debug("Entering Ownership.grantingGroups().");
    const config = this.deps.config();
    const out = Ownership.GRANTING_GROUP_SETTINGS
      .map(function (key) {
        return String(config.value(key) || '').trim().toLowerCase();
      }).filter(Boolean);
    log.debug("Leaving Ownership.grantingGroups(). " + out.length);
    return out;
  }

  /**
   * Why an object is closed to its owners, in the ambient realm: one
   * sentence per reason, none where it is open to them.
   *
   * @param kind - one of `KINDS`
   * @param name - the object, as `objectOf()` names it
   * @returns the reasons; empty where its owners may administer it
   */
  protectionOf(kind: unknown, name: unknown): string[] {
    const { log } = this.deps;
    log.debug("Entering Ownership.protectionOf(). kind=" + kind);
    const wanted = String(name == null ? '' : name);
    const reasons: string[] = [];
    try {
      const roles = this.deps.roles();
      const protectedRoles = this.protectedRoles();
      const protectedNames = Object.keys(protectedRoles);
      if (kind === 'role') {
        if (roles.isBuiltIn(wanted)) {
          reasons.push('it is a built-in role, computed rather than stored');
        } else if (protectedRoles[wanted]) {
          reasons.push(protectedRoles[wanted]);
        }
        const row = roles.read(wanted);
        if (row && row.ownerProtected) {
          reasons.push(MARKED);
        }
      } else if (kind === 'group') {
        const group = this.deps.ldap().groupOwnership(wanted);
        if (group) {
          const cn = String(group.cn || '').toLowerCase();
          if (this.grantingGroups().indexOf(cn) >= 0) {
            reasons.push('it is a group this service grants a role or the ' +
                         'console roster through by its name');
          }
          const inRole = roles.all().filter(function (row: Json) {
            return protectedNames.indexOf(row.name) >= 0 &&
              (row.groups || []).some(function (one: string) {
                return String(one).toLowerCase() === cn ||
                       Ownership.dnKey(one) === Ownership.dnKey(group.dn);
              });
          }).map(function (row: Json) {
            return row.name;
          });
          if (inRole.length) {
            reasons.push('it is a member of ' + inRole.join(', ') +
                         ', which no owner may administer');
          }
          if (group.ownerProtected) {
            reasons.push(MARKED);
          }
        }
      } else if (kind === 'application') {
        const applications = this.deps.applications();
        if (applications.isInternalIdentifier(wanted)) {
          reasons.push('it is one of this service\'s own applications');
        }
        const inRole = roles.all().filter(function (row: Json) {
          return protectedNames.indexOf(row.name) >= 0 &&
            (row.applications || []).indexOf(wanted) >= 0;
        }).map(function (row: Json) {
          return row.name;
        });
        if (inRole.length) {
          reasons.push('it is a member of ' + inRole.join(', ') +
                       ', which no owner may administer');
        }
        const permissions = this.protectedPermissions();
        // Declared, or since #1141 granted on one of this service's APIs.
        const declared = (this.deps.scopePolicy().declaredScopes(wanted) ||
                          []).concat(this.deps.scopePolicy()
                            .grantedScopes(wanted))
          .filter(function (one: string) {
          return permissions.indexOf(one) >= 0;
        });
        if (declared.length) {
          reasons.push('it declares ' + declared.join(', ') + ', a ' +
                       'permission of this service no owner may come to ' +
                       'hold');
        }
        if (applications.ownerProtected(wanted)) {
          reasons.push(MARKED);
        }
      } else if (kind === 'service-account') {
        const facts = this.deps.serviceAccounts().of(wanted);
        const held = facts ? roles.rolesOf({
          kind: 'user', name: facts.username, authenticated: true
        }) : [];
        const closing = held.filter(function (role: string) {
          return protectedNames.indexOf(role) >= 0 ||
                 role === 'REMOTE_PEPS' || role === 'XACML_USER';
        });
        if (closing.length) {
          reasons.push('it holds ' + closing.join(', ') + ', which no ' +
                       'owner may come to hold through it');
        }
        if (facts && facts.ownerProtected) {
          reasons.push(MARKED);
        }
      }
    } catch (e) {
      // A register that cannot be read leaves the object CLOSED: not
      // knowing whether something is protected is not permission.
      log.debug("Caught in Ownership.protectionOf(): " +
                ((e && e.message) || e));
      reasons.push('whether it is protected could not be read');
    }
    log.debug("Leaving Ownership.protectionOf(). " + reasons.length +
              " reason(s).");
    return reasons;
  }

  // ---------------------------------------------------------------------------
  // THE ADMINISTRATOR'S MARK (rcbj's decision 4), through each register's
  // own write so that every other rule of the object stays its own.
  // ---------------------------------------------------------------------------
  /**
   * Marks an object closed to its owners, or opens it again.
   *
   * @param kind - one of `KINDS`
   * @param name - the object
   * @param flag - true closes it to its owners
   * @param options - `actor`, `channel`, `protocol`, for a group's audit row
   * @returns `{ ok: true, changed, kind, name, ownerProtected }`, or
   *   `{ ok: false, errors }` carrying an error code
   */
  setProtected(kind: unknown, name: unknown, flag: unknown,
               options?: Json): Json {
    const { log, errorCodes } = this.deps;
    log.debug("Entering Ownership.setProtected(). kind=" + kind);
    const wanted = flag === true || String(flag) === 'true';
    const what = String(name == null ? '' : name).trim();
    if (!Ownership.isKind(kind)) {
      log.debug("Leaving Ownership.setProtected(). Not a kind.");
      return errorCodes.mark({ ok: false, errors: ['`kind` must be one of ' +
               KINDS.join(', ') + '.'] }, 'STS-API-0134');
    }
    if (!what) {
      log.debug("Leaving Ownership.setProtected(). Nothing named.");
      return errorCodes.mark({ ok: false, errors: ['Which ' + kind + '? ' +
               'Send `name`.'] }, 'STS-API-0134');
    }
    let done: Json;
    if (kind === 'role') {
      done = this.deps.roles().setOwnerProtected(what, wanted);
      if (!done.ok) {
        done = { ok: false, errors: [done.why] };
        errorCodes.mark(done, 'STS-XACML-0057');
      }
    } else if (kind === 'group') {
      done = this.deps.ldap().setGroupOwnerProtected(what, wanted, options);
    } else if (kind === 'service-account') {
      done = this.deps.serviceAccounts().setOwnerProtected(what, wanted);
    } else {
      done = this.deps.applications().setOwnerProtected(what, wanted);
    }
    if (!done || done.ok !== true) {
      log.debug("Leaving Ownership.setProtected(). Refused.");
      return done;
    }
    log.debug("Leaving Ownership.setProtected(). " +
              (done.changed ? "Changed." : "Unchanged."));
    return { ok: true, changed: done.changed !== false, kind: String(kind),
             name: what, ownerProtected: wanted,
             message: what + (wanted
               ? ' is closed to its owners: they may not administer it ' +
                 'through /admin-api.'
               : ' is open to its owners again, unless another reason ' +
                 'closes it.') };
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2) — see
// `common/instance_slot.ts`. The exports below are FACADES.
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<Ownership>(
  'common/ownership',
  () => new Ownership(Ownership.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading a module always did.
slot.buildNowUnlessDeferred();

/**
 * Who owns what, and what an owner may not touch (#607). A library (rule 3).
 * @namespace
 */
export = {
  Ownership: Ownership,
  KINDS: KINDS,
  GRANTING_GROUP_SETTINGS: Ownership.GRANTING_GROUP_SETTINGS,
  dnKey: Ownership.dnKey,
  isKind: Ownership.isKind,
  /**
   * Installs the instance the composition root built.
   */
  installInstance: (instance: Ownership): void => slot.install(instance),
  /**
   * Names where the installed instance came from.
   */
  instanceOrigin: (): string => slot.origin(),
  identityOf: slot.forward('identityOf'),
  ownsAnything: slot.forward('ownsAnything'),
  objectOf: slot.forward('objectOf'),
  owns: slot.forward('owns'),
  protectionOf: slot.forward('protectionOf'),
  setProtected: slot.forward('setProtected')
};
