'use strict';
//
// File: admin_rbac.ts
//
// ---------------------------------------------------------------------------
// WHO MAY USE THE ADMIN CONSOLE, AND WHAT THEY MAY DO ON IT.
//
// Two roles — **Admin Read** and **Admin Write** — and one rule about them:
// WRITE IMPLIES READ. A role that could post a form to a page it was not
// allowed to look at would be a trap rather than a permission, and somebody
// would eventually be granted it on purpose.
//
// ---------------------------------------------------------------------------
// THE ROLES ARE TWO ORDINARY GROUPS IN THE EMBEDDED DIRECTORY.
//
// `cn=admin-read,ou=groups` and `cn=admin-write,ou=groups` by default, both
// renameable (`admin.readGroup`, `admin.writeGroup`). They are not a store of
// this console's own, and that was the first decision made here.
//
// The reason is the one-store rule this service follows everywhere it has been
// tempted otherwise: the revoked-jti set is shared between `/oauth2/revoke` and
// the console, the session store is owned by `authn.js` and read by three
// modules, and SCIM writes into the SAME directory `/admin/users` reads. A
// membership store of this module's own would be a SECOND answer to "is alice
// an admin" — one that an `ldapmodify`, a SCIM PATCH and `/admin/groups` could
// not see, and that would drift from them silently, because nothing anywhere
// compares two stores that were never meant to disagree.
//
// So there are FOUR DOORS onto one membership and they all end up in the same
// entry: this module's own screen at `/admin/rbac`, `POST /admin-api/rbac/…`,
// an `ldapmodify` on 389 or 636, and a SCIM PATCH of the Group resource. That
// is the point rather than a side effect — a mock exists to be driven, and a
// role you can only grant through a web form is one no test can grant.
//
// ---------------------------------------------------------------------------
// AND IT MAKES ONE SENTENCE IN THIS REPOSITORY NO LONGER UNIVERSALLY TRUE.
//
// "A group here grants nothing" is written in README.md, in three CLAUDE.md
// files, in `sts_metadata.js`, on `/admin/groups` itself and in
// `group_claims.js`. It is STILL true of every other group and it is still true
// of these two everywhere except this console: no token's scopes change, no
// assertion gains an attribute, no protocol endpoint reads them, and a member
// of `admin-write` has exactly the same access to `/oauth2/token` as anybody
// else. What changed is that ONE surface — `/admin` — now reads two named
// groups. Every place that sentence appears has been qualified rather than
// deleted, because deleting it would leave a reader believing that adding
// somebody to `cn=developers` changed what their token could do.
//
// ---------------------------------------------------------------------------
// THE OPEN WINDOW, which is the only interesting decision in the file.
//
// The console gate is unconditional — `mode.gatesConsole()`, where this used
// to read `admin.authRequired` — so a new service whose roster opened nothing
// would have a console that NO browser could ever reach, and no amount of
// signing in would help.
//
// So a window is open while nobody has taken charge, and anybody who signs in
// holds BOTH roles in it, with a banner on every page that says so. SINCE
// 2026-09-13 what closes it is the BOOTSTRAP ADMINISTRATOR's first console
// sign-in (see `seedBootstrapAdministrator()` below, and
// `admin-ui/CLAUDE.md` 8a) rather than the first grant, which locked out an
// operator who granted themselves Admin Read alone. Where no bootstrap account
// was seeded (an in-process test that never runs `server.js`) the older rule
// still applies: open while neither role group has a member.
// `admin.openWhenEmpty` turns the window off for somebody who wants the locked
// case; the way back in from it is `POST /admin-api/rbac/grant`, with an
// access token carrying `admin:write`.
//
// It is deliberately "no members" rather than "the groups do not exist": a
// group that exists with nobody in it is the state a revoke of the last grant
// leaves behind, and treating that as closed would mean the console silently
// locking itself the moment somebody tidied up. Both spellings of empty mean
// the same thing here, which is the answer that has no surprising edge.
//
// ---------------------------------------------------------------------------
// This module is a LIBRARY (rule 3). It registers no route, so its position in
// `server.js`'s require order does not matter, and it cannot join a cycle: it
// requires `config.js`, `helpers.js`, `mode.js`, `audit.js`, `error_codes.js`
// and `realms.js`, none of which requires it.
//
// It reaches the directory through a SLOT that `ldap_server.js` fills at its
// own require time, for the reason `admin.js`'s directory slots exist
// (rule 3e):
// requiring `ldap_server.js` from here would pull every `/ldap` route into the
// express router ahead of every `/admin` route, and `GET /admin/sts-metadata`
// is built by walking that router. The slot is on THIS module rather than
// another on `admin.js` because what fills it is one coherent thing — the group
// functions — and because both callers of it (`admin.js` and `admin_api.js`)
// want the decisions here rather than the raw directory.
//
// The slot takes ONE OBJECT where `admin.js`'s original directory slots
// deliberately took separate functions, and the concern stated there — "a
// module that filled a combined slot with only the readers would silently
// disable creation" — is answered rather than ignored: `setDirectory()`
// CHECKS every member it needs and refuses a partial object loudly. A
// half-filled slot is a startup warning here, not a control that quietly does
// nothing.
// ---------------------------------------------------------------------------


// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `AdminRbac` takes the logger, `config`, `mode`, `audit`, the error
// codes and `realms` through its constructor, and every function below is one
// of its methods. The two module-level lets — `installed` and `directory`, the
// slot — stay where they were, with the same writers: `setDirectory()`, now a
// method, and `inRosterRealm()`'s binding for one call. The module still
// exports every name it did, the realm-taking wrappers included, from a
// TRANSITIONAL instance at the bottom, for `admin-ui/admin.ts`,
// `mgmt-api/admin_api.ts`, `ldap/ldap_server.js`, `server.js`, the
// `admin-core/` layer and the tests; `AdminRbac` is exported beside them for
// the composition root.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import config = require('../common/config');
// The mode. A LEAF (rule 3): registers nothing, requires only `config`.
import mode = require('../common/mode');
import audit = require('../common/audit');
// THE ERROR CODES (common/error_codes.js, a leaf). A refusal here is a RESULT
// that `/admin/rbac` redirects with and `/admin-api/rbac` sends as JSON, so its
// code rides on the object under the non-enumerable Symbol `mark()` uses —
// invisible to JSON.stringify, read back with `errorCodes.codeOf(result)`.
import errorCodes = require('../common/error_codes');
// THE REALMS, for their ids and the default realm's. A leaf here: this module
// asks the registry whether a realm exists and never enters one itself — the
// directory slot's `forRealm()` does that.
import realms = require('../common/realms');

// ---------------------------------------------------------------------------
// A ROSTER PER REALM (2026-09-14, ticket #32), AND THE DEFAULT REALM'S IS STILL
// THE SERVICE'S.
//
// Until that day there was ONE roster — the default realm's two groups — and
// the prose said a per-realm one would let anybody who can create a realm
// administer the service. rcbj asked for per-realm administrators with the
// default realm's roster kept as the SUPER administrator over every realm, and
// the argument is answered rather than dropped: a realm's roster grants
// AUTHORITY IN THAT REALM ONLY, which `admin-core/admin_views.ts`'s
// `gateStateFor()` and `admin-ui/admin_scope.ts` enforce, and creating a realm
// is itself a service action.
//
// So every public function here takes an OPTIONAL realm id. Absent, it answers
// about whatever realm is bound — the default realm, at the top level — which
// is what keeps every caller written before this unchanged, and what lets a
// function here call another without re-binding. Present, it binds that realm
// for the call through the slot's `forRealm()`.
// ---------------------------------------------------------------------------

// The two roles. An array rather than two constants because everything below
// walks it — the screen, the API, the JSON view, the decision — and a third
// role, if there is ever one, should cost one row rather than six edits.
//
// `implies` is what makes WRITE IMPLY READ a property of the table rather than
// an `if` somewhere: `rolesOf()` expands it, so a page asking "may this person
// read" gets the same answer wherever it asks from.
const ROLES = [
  { id: 'read', label: 'Admin Read', setting: 'admin.readGroup',
    implies: [],
    what: 'Look at every page of this console, and at every ?format=json ' +
          'view of one. It changes nothing: a reader can see which tokens ' +
          'are revoked and cannot revoke one.' },
  { id: 'write', label: 'Admin Write', setting: 'admin.writeGroup',
    implies: ['read'],
    what: 'Post every form on this console — revoke a token, add a custom ' +
          'claim, change a setting, create a person, grant a role. IT ' +
          'INCLUDES READ, so a member of this role alone can use the whole ' +
          'console.' }
];

const ROLE_IDS = ROLES.map(function (role) {
  return role.id;
});

// ---------------------------------------------------------------------------
// The slot. See the header.
// ---------------------------------------------------------------------------

// `installed` is what the filler offered, bound to the DEFAULT realm;
// `directory` is the view in use for the call in progress, which is the same
// object except while `inRosterRealm()` has bound another realm.
let installed = null;
let directory = null;

// What the filler has to provide. Named here rather than checked inline so the
// warning can say which member was missing — "the admin roles cannot be read"
// with no further detail is the kind of message that costs an hour.
const DIRECTORY_MEMBERS = ['groupsOfUser', 'readGroupEntry', 'writeGroupEntry',
                           'groupDnFor', 'normalizeDn', 'existingUserEntry',
                           'usernameOfEntry', 'nameUsableInDn', 'allPersons',
                           'claimedMembersOf', 'usersDn', 'groupsDn'];

// The operational attributes `writableAttributes()` leaves out of a group it
// writes back; the reason is above that method.
const NOT_WRITTEN_BACK = ['entrydn', 'createtimestamp', 'modifytimestamp'];

const NO_DIRECTORY =
  'No LDAP directory is loaded in this process, so there is nowhere to hold ' +
  'the roles. That is a build of this service without ldap_server.js and not ' +
  'a failure — but it means nobody can be granted anything, so the console ' +
  'gate leaves this console reachable only while admin.openWhenEmpty is on.';

// What an `AdminRbac` needs from the rest of the service.
interface AdminRbacDeps {
  log: typeof helpers.log;
  config: typeof config;
  mode: typeof mode;
  audit: typeof audit;
  errorCodes: typeof errorCodes;
  realms: typeof realms;
}

class AdminRbac {
  static readonly ROLES = ROLES;
  static readonly ROLE_IDS = ROLE_IDS;

  constructor(private readonly deps: AdminRbacDeps) {
    deps.log.debug("Entering AdminRbac.constructor().");
    deps.log.debug("Leaving AdminRbac.constructor().");
  }

  private refused(code, result) {
    const { log, errorCodes } = this.deps;
    log.debug("Entering AdminRbac.refused().");
    log.debug("Leaving AdminRbac.refused().");
    return errorCodes.mark(result, code);
  }

  roleFor(id) {
    const { log } = this.deps;
    log.debug("Entering AdminRbac.roleFor().");
    const wanted = String(id == null ? '' : id).trim().toLowerCase();
    log.debug("Leaving AdminRbac.roleFor().");
    return ROLES.filter(function (role) { return role.id === wanted; })[0] ||
           null;
  }

  // The cn of the group behind a role, read WHERE IT IS USED rather than
  // captured at require time, because both settings are `runtime: true` —
  // somebody who renames the write group on /admin/config expects the next
  // request to use the new name.
  private groupCnFor(role) {
    const { log, config } = this.deps;
    log.debug("Entering AdminRbac.groupCnFor().");
    log.debug("Leaving AdminRbac.groupCnFor().");
    return String(config.value(role.setting) || '').trim();
  }

  setDirectory(fns) {
    const { log, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering AdminRbac.setDirectory().");
    const given = fns || {};
    const missing = DIRECTORY_MEMBERS.filter(function (name) {
      return given[name] === undefined || given[name] === null;
    });
    if (missing.length) {
      // Refused rather than half-installed, which is the whole argument for a
      // single slot being safe here: the failure is one loud line at startup
      // instead of a grant button that answers 200 and writes nothing.
      log.error(errorCodes.tag('STS-ADMIN-0587') +
                'admin_rbac: the directory slot was offered an object ' +
                'missing ' + missing.join(', ') + '. It is NOT installed — ' +
                'the console ' +
                'roles will read as "no directory is loaded", which is the ' +
                'same answer a build without ldap_server.js gives.');
      log.debug("Leaving AdminRbac.setDirectory(). Refused: " +
                missing.length + " member(s) missing.");
      return false;
    }
    installed = given;
    directory = given;
    log.debug("Leaving AdminRbac.setDirectory(). Installed.");
    log.info('admin_rbac: the admin console roles are the directory groups ' +
             self.groupCnFor(ROLES[0]) + ' and ' + self.groupCnFor(ROLES[1]) +
             ' under ' + given.groupsDn + '. An ldapmodify, a SCIM PATCH, ' +
             '/admin/rbac and ' +
             'POST /admin-api/rbac are four doors onto the same membership.');
    log.debug("Leaving AdminRbac.setDirectory().");
    return true;
  }

  available() {
    const { log } = this.deps;
    log.debug("Entering AdminRbac.available().");
    log.debug("Leaving AdminRbac.available().");
    return !!directory;
  }

  // The realm this module answers about when a caller names one. `''`, null and
  // undefined mean "whatever is bound", so an inner call inherits its caller's
  // realm; the default realm's own id binds the installed view.
  private realmIdOf(realmId) {
    const { log } = this.deps;
    log.debug("Entering AdminRbac.realmIdOf().");
    const id = realmId === undefined || realmId === null ? '' : String(realmId);
    log.debug("Leaving AdminRbac.realmIdOf().");
    return id.trim();
  }

  // The directory view for a named realm: the installed one for the default
  // realm, `forRealm()`'s for any other, and NULL for a realm that does not
  // exist or a filler that offers no per-realm view — which every function here
  // already answers as "no directory is loaded", so an unknown realm grants
  // nothing.
  private viewFor(realmId) {
    const { log, realms } = this.deps;
    log.debug("Entering AdminRbac.viewFor(). realm=" + realmId);
    if (!installed) {
      log.debug("Leaving AdminRbac.viewFor(). Nothing installed.");
      return null;
    }
    if (realmId === realms.DEFAULT_ID) {
      log.debug("Leaving AdminRbac.viewFor(). The default realm.");
      return installed;
    }
    if (typeof installed.forRealm !== 'function' || !realms.get(realmId)) {
      log.debug("Leaving AdminRbac.viewFor(). No view for that realm.");
      return null;
    }
    const view = installed.forRealm(realmId);
    log.debug("Leaving AdminRbac.viewFor(). " + (view ? "Bound." : "Refused."));
    return view || null;
  }

  // Run `fn` with the named realm's roster bound, or with whatever is bound
  // when no realm is named. Synchronous throughout, like every function it
  // wraps, so the binding cannot leak into another request.
  private inRosterRealm(realmId, fn) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering AdminRbac.inRosterRealm().");
    const id = self.realmIdOf(realmId);
    if (!id) {
      log.debug("Leaving AdminRbac.inRosterRealm(). Inherited.");
      return fn();
    }
    const previous = directory;
    directory = self.viewFor(id);
    try {
      log.debug("Leaving AdminRbac.inRosterRealm(). Bound " + id + ".");
      return fn();
    } finally {
      directory = previous;
    }
  }

  // The realm a view answers about, for the words a result carries.
  private boundRealmId() {
    const { log, realms } = this.deps;
    log.debug("Entering AdminRbac.boundRealmId().");
    log.debug("Leaving AdminRbac.boundRealmId().");
    return directory && directory.realmId ? String(directory.realmId)
                                          : realms.DEFAULT_ID;
  }

  // ---------------------------------------------------------------------------
  // Reading the roster.
  // ---------------------------------------------------------------------------

  private dnForRole(role) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering AdminRbac.dnForRole().");
    log.debug("Leaving AdminRbac.dnForRole().");
    return directory.groupDnFor(self.groupCnFor(role));
  }

  // One role's group as it stands: whether the entry is there at all, and who
  // is in it with each membership value resolved to an entry or reported as
  // dangling.
  //
  // A group that does not exist and a group with no members are DIFFERENT
  // states here and the same decision — see the header — so both are reported
  // and both count as empty. The distinction is kept because the screen says
  // which, and "the group is not there" sends a reader somewhere different from
  // "the group is there and you took the last person out of it".
  rosterFor(roleId) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering AdminRbac.rosterFor(). role=" + roleId);
    const role = self.roleFor(roleId);
    if (!role) {
      log.debug("Leaving AdminRbac.rosterFor(). No such role.");
      return null;
    }
    const cn = self.groupCnFor(role);
    // Every member of this shape is present on EVERY branch, including the two
    // that return early. A role whose group does not exist used to come back
    // without `claimedCount` at all, so a caller walking both roles hit an
    // undefined on one of them — the sort of asymmetry that is invisible until
    // something iterates.
    const out: any = { role: role.id, label: role.label, what: role.what,
                       implies: role.implies.slice(0), cn: cn, dn: '',
                       exists: false, members: [], memberCount: 0,
                       presentCount: 0, danglingCount: 0, claimed: [],
                       claimedCount: 0 };
    if (!directory) {
      log.debug("Leaving AdminRbac.rosterFor(). No directory is loaded.");
      return out;
    }
    out.dn = self.dnForRole(role);
    const entry = directory.readGroupEntry(out.dn);
    if (!entry) {
      log.debug("Leaving AdminRbac.rosterFor(). " + out.dn +
                " does not exist.");
      return out;
    }
    out.exists = true;
    out.origin = entry.origin;
    out.modifiedAt = entry.modifiedAt;
    out.members = entry.members.map(function (member) {
      return {
        // `value` is what the attribute literally holds and `dn` is what it
        // RESOLVED to, which are different for memberUid — and a screen showing
        // only one of them cannot explain why removing `alice` also removed
        // `uid=alice,ou=users`.
        value: member.value,
        attribute: member.attribute,
        holds: member.holds,
        dn: member.dn,
        present: member.present,
        kind: member.kind,
        // The name this console knows them by, which is what links a row here
        // to /admin/users. Empty for a dangling member, and the screen says so
        // rather than drawing a link to a page about nobody.
        userKey: member.userKey,
        username: self.usernameOfMember(member)
      };
    });
    out.memberCount = out.members.length;
    out.presentCount = out.members.filter(function (
        m) { return m.present; }).length;
    out.danglingCount = out.memberCount - out.presentCount;
    self.addClaimedMembers(out);
    log.debug("Leaving AdminRbac.rosterFor(). " + out.memberCount +
              " member value(s), " + out.claimedCount +
              " of them claimed from the other side.");
    return out;
  }

  // ---------------------------------------------------------------------------
  // THE OTHER DIRECTION OF MEMBERSHIP, AND THE REASON IT IS NOT OPTIONAL HERE.
  //
  // A group lists its members; an entry's own `memberOf` claims a group.
  // Nothing in this directory keeps the two in step — `memberOf` is not even a
  // standard attribute — so a client can write one and produce a disagreement,
  // which is a state `/admin/groups` reports rather than repairs.
  //
  // `groupsOfUser()` HONOURS BOTH DIRECTIONS, which means somebody added that
  // way REALLY HOLDS THE ROLE. So a roster built from the group entry alone
  // would have shown a console that person could use and a list they were not
  // on — a permissions page that under-reports who has access, which is the
  // single worst thing this page could do. They are merged in and marked, not
  // hidden and not silently promoted: the row says which side of the
  // disagreement it came from.
  //
  // **The edge worth knowing, because it cost a test to find:** a `memberOf`
  // naming a group that DOES NOT EXIST grants nothing. `groupsOfUser()`
  // resolves each claimed DN against the group index, and an unresolvable one
  // is skipped — so writing `memberOf: cn=admin-read,...` onto an entry before
  // anybody has ever been granted Admin Read does nothing at all, and starts
  // working the moment the first ordinary grant creates that group. That is the
  // directory's rule rather than this module's, and it is the same rule
  // `/admin/groups` applies when it decides what counts as a group.
  // ---------------------------------------------------------------------------
  private addClaimedMembers(out) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering AdminRbac.addClaimedMembers().");
    if (!out.exists) {
      // Nothing claims a group that is not there — see the edge above. The
      // lookup would answer honestly anyway; skipping it says why.
      out.claimed = [];
      out.claimedCount = 0;
      log.debug("Leaving AdminRbac.addClaimedMembers().");
      return;
    }
    const claimed = directory.claimedMembersOf(out.dn) || [];
    out.claimed = claimed.map(function (row) {
      return { dn: row.dn, userKey: row.userKey, cn: row.cn, mail: row.mail };
    });
    out.claimedCount = out.claimed.length;
    claimed.forEach(function (row) {
      out.members.push({
        value: row.dn,
        // Named for what it IS rather than dressed as a `member` value: no
        // attribute on the group holds this, and a revoke has to go to the
        // PERSON'S entry instead — which this module does not do, and says so.
        attribute: 'memberOf (on their own entry)',
        holds: 'dn',
        dn: row.dn,
        present: true,
        kind: 'claimed',
        userKey: row.userKey,
        username: self.usernameOfMember({ holds: 'dn', dn: row.dn,
                                          value: row.dn })
      });
    });
    out.memberCount = out.members.length;
    out.presentCount = out.members.filter(function (
        m) { return m.present; }).length;
    out.danglingCount = out.memberCount - out.presentCount;
    log.debug("Leaving AdminRbac.addClaimedMembers().");
  }

  // What to CALL a membership value on the screen and in a revoke button.
  //
  // It is the local name wherever there is one, because that is what somebody
  // typed into the grant form and what they will type to take it away again. A
  // member value that resolves to an entry gives its own username; a DANGLING
  // one has no entry to ask, so the RDN value is read off the DN — which is
  // exactly the name a grant to somebody who has never authenticated wrote.
  private usernameOfMember(member) {
    const { log } = this.deps;
    log.debug("Entering AdminRbac.usernameOfMember().");
    if (member.holds === 'uid') {
      log.debug("Leaving AdminRbac.usernameOfMember().");
      return member.value;
    }
    const rdn = String(member.dn || '').split(',')[0] || '';
    const eq = rdn.indexOf('=');
    const value = eq > 0 ? rdn.slice(eq + 1) : '';
    // RFC 4514 escaping, undone: `cn=Smith\, John` is one RDN whose value has a
    // comma in it, and a name shown with the backslash still in is a name that
    // will not match when it is typed back.
    log.debug("Leaving AdminRbac.usernameOfMember().");
    return value.replace(/\\([,+"\\<>;=#]|20|22|23|2B|2C|3B|3C|3D|3E|5C)/g,
                         function (whole, what) {
                           if (what.length === 1) {
                             return what;
                           }
                           return String.fromCharCode(parseInt(what, 16));
                         });
  }

  roster() {
    const { log } = this.deps;
    log.debug("Entering AdminRbac.roster().");
    const self = this;
    const out = ROLE_IDS.map(function (id) {
      return self.rosterFor(id);
    });
    log.debug("Leaving AdminRbac.roster(). " + out.length + " role(s).");
    return out;
  }

  // ---------------------------------------------------------------------------
  // THE BOOTSTRAP ADMINISTRATOR (2026-09-13).
  //
  // A new instance has ONE account that administers it:
  // `admin.bootstrapUsername` (default `admin`) in the DEFAULT realm, a member
  // of both console roles, whose password must be changed at its first sign-in
  // (`pwdReset`, enforced by `authn/authn.ts`). Development accepts any
  // password for it, as for anybody; product mode's first password is the
  // generated one `credentials.bootstrap()` prints once.
  //
  // **UNTIL THAT ACCOUNT FIRST SIGNS IN TO THE CONSOLE, EVERY SIGNED-IN PERSON
  // MAY USE THE CONSOLE** — the window the empty roster used to open, kept open
  // by something that cannot happen by accident. It replaced "open while nobody
  // holds a role" because that rule closed on the FIRST GRANT: an operator who
  // granted themselves only Admin Read locked themselves out of every write,
  // with nobody left who could undo it from the console. Seeding both roles
  // onto one named account and closing on THAT account's arrival means the
  // first thing to close the door is the administrator walking through it.
  //
  // Three facts, all on the account's own entry (`ldap_server.js`'s
  // readPersonFlags()), so they persist and replicate with it:
  // `stsBootstrapAdministrator` says it was seeded, `stsConsoleClaimedAt` says
  // the window is closed, and `pwdReset` is the password rule.
  // ---------------------------------------------------------------------------
  private bootstrapName() {
    const { log, config } = this.deps;
    log.debug("Entering AdminRbac.bootstrapName().");
    log.debug("Leaving AdminRbac.bootstrapName().");
    return String(config.value('admin.bootstrapUsername') || '').trim();
  }

  bootstrapState() {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering AdminRbac.bootstrapState().");
    const name = self.bootstrapName();
    const out = { username: name, seeded: false, claimedAt: '', dn: '' };
    if (!directory || !name ||
        typeof directory.readPersonFlags !== 'function') {
      log.debug("Leaving AdminRbac.bootstrapState(). Nothing to read.");
      return out;
    }
    let flags = null;
    try {
      flags = directory.readPersonFlags(name);
    } catch (e) {
      log.debug("Caught in AdminRbac.bootstrapState(): " +
                ((e && e.message) || e));
      flags = null;
    }
    if (flags) {
      out.seeded = !!flags.bootstrapAdministrator;
      out.claimedAt = String(flags.consoleClaimedAt || '');
      out.dn = flags.dn;
    }
    log.debug("Leaving AdminRbac.bootstrapState(). seeded=" + out.seeded +
              ", claimed=" + !!out.claimedAt);
    return out;
  }

  private nowGeneralized() {
    const { log } = this.deps;
    log.debug("Entering AdminRbac.nowGeneralized().");
    log.debug("Leaving AdminRbac.nowGeneralized().");
    return new Date().toISOString().replace(/[-:T]/g, '').replace(/\.\d+Z$/,
                                                                   'Z');
  }

  // ---------------------------------------------------------------------------
  // MAKE IT, ONCE, AT STARTUP. `server.js` calls this after the persistence
  // store has been restored and before `credentials.bootstrap()` gives the
  // account its generated password in product mode.
  //
  // **IT NEVER UNDOES AN OPERATOR.** An account whose window has closed is left
  // exactly as it is, including if somebody took its roles away. And a roster
  // that already names somebody ELSE when the account is first marked is a
  // service that was already administered before this existed: the account is
  // made and given both roles, as asked, and the window is recorded as closed
  // at once rather than re-opening the console to everybody on an upgrade.
  //
  // `pwdReset` is set only on an account this call CREATED — an existing entry
  // was somebody's before, and forcing a change on it is not this step's call.
  // ---------------------------------------------------------------------------
  seedBootstrapAdministrator() {
    const { log, audit, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering AdminRbac.seedBootstrapAdministrator().");
    const name = self.bootstrapName();
    if (!directory || !name ||
        typeof directory.readPersonFlags !== 'function' ||
        typeof directory.writePersonFlag !== 'function' ||
        typeof directory.createPerson !== 'function') {
      log.debug("Leaving AdminRbac.seedBootstrapAdministrator(). No " +
                "directory to seed.");
      return { ran: false, why: 'no directory offers the bootstrap functions' };
    }
    let flags = directory.readPersonFlags(name);
    if (flags && flags.bootstrapAdministrator && flags.consoleClaimedAt) {
      log.debug("Leaving AdminRbac.seedBootstrapAdministrator(). Already " +
                "claimed.");
      return { ran: false, why: 'the bootstrap administrator has already ' +
                                'signed in to the console', username: name };
    }
    const administeredBy = self.roster().reduce(function (names, row) {
      row.members.concat(row.claimed || []).forEach(function (member) {
        const who = String(member.username || '');
        if (who && who.toLowerCase() !== name.toLowerCase() &&
            names.indexOf(who) < 0) {
          names.push(who);
        }
      });
      return names;
    }, []);
    let created = false;
    if (!flags) {
      const made = directory.createPerson(name);
      if (!made || made.ok === false) {
        log.error(errorCodes.tag('STS-ADMIN-0706') + 'admin_rbac: the ' +
                  'bootstrap administrator "' + name + '" could not be ' +
                  'created in the "' + self.boundRealmId() + '" realm: ' +
                  ((made && (made.errors || []).join(' ')) || 'no reason'));
        log.debug("Leaving AdminRbac.seedBootstrapAdministrator(). Not " +
                  "created.");
        return { ran: false, why: 'the account could not be created',
                 username: name };
      }
      created = true;
      flags = directory.readPersonFlags(name);
    }
    if (!flags.bootstrapAdministrator) {
      directory.writePersonFlag(name, 'stsBootstrapAdministrator', true);
    }
    if (created) {
      directory.writePersonFlag(name, 'pwdReset', true);
    }
    const granted = ROLE_IDS.map(function (id) {
      return self.grant(name, id, { via: 'bootstrap', actor: 'bootstrap' });
    });
    const failed = granted.filter(function (one) { return !one.ok; });
    if (failed.length) {
      log.error(errorCodes.tag('STS-ADMIN-0706') + 'admin_rbac: the ' +
                'bootstrap administrator "' + name + '" could not be given ' +
                'both console roles: ' + failed.map(function (one) {
                  return (one.errors || []).join(' ');
                }).join(' '));
    }
    const closedAtOnce = administeredBy.length > 0;
    if (closedAtOnce) {
      directory.writePersonFlag(name, 'stsConsoleClaimedAt',
                                self.nowGeneralized());
    }
    audit.record({
      action: 'admin.console.bootstrap', outcome: 'success', actor: 'bootstrap',
      target: flags.dn, channel: 'internal',
      summary: 'The bootstrap administrator "' + name + '" was ' +
               (created ? 'created and ' : '') + 'given both console roles' +
               (closedAtOnce
                 ? '; the console was already administered, so it ' +
                   'is not opened to everybody' : ''),
      detail: { event: 'seeded', username: name, created: created,
                realm: self.boundRealmId(),
                passwordResetRequired: created,
                administeredBy: administeredBy.slice(0, 20),
                windowClosed: closedAtOnce }
    });
    log.info('admin_rbac: "' + name + '" in the "' + self.boundRealmId() +
             '" realm holds Admin Read ' +
             'and Admin Write' +
             (created ? ', and must change its password at ' +
                        'its first sign-in' : '') + '. ' + (closedAtOnce
               ? 'The roster already named ' + administeredBy.join(', ') +
                 ', so the console stays enforced.'
               : 'Until it first signs in to /admin, every signed-in ' +
                 'person may use the console.'));
    log.debug("Leaving AdminRbac.seedBootstrapAdministrator().");
    return { ran: true, username: name, created: created,
             realm: self.boundRealmId(), windowClosed: closedAtOnce };
  }

  // ---------------------------------------------------------------------------
  // THE WINDOW CLOSES WHEN THE BOOTSTRAP ADMINISTRATOR ARRIVES. Called by the
  // console gate for every signed-in request, so the common answer — not that
  // account, or already closed — is one flag read and no write.
  //
  // **A SIGN-IN CLOSES THE WINDOW OF THE REALM IT CAME FROM, AND NO OTHER.**
  // The console's code flow runs in the realm it was reached in, so a trust
  // realm's
  // own `admin` signing in closes THAT realm's window (2026-09-14, #32) and
  // must never close the default realm's, which belongs to the service's
  // account. Until #32 a sign-in through another realm closed nothing at all,
  // because there was no realm window to close. The password has already been
  // changed by then: `authn.js` asks for it before any session exists.
  // ---------------------------------------------------------------------------
  noteConsoleSignIn(username, session, defaultRealmId) {
    const { log, realms } = this.deps;
    const self = this;
    log.debug("Entering AdminRbac.noteConsoleSignIn().");
    const name = String(username || '').trim();
    const wanted = self.bootstrapName();
    if (!name || !wanted || name.toLowerCase() !== wanted.toLowerCase()) {
      log.debug("Leaving AdminRbac.noteConsoleSignIn(). Not the bootstrap " +
                "administrator.");
      return false;
    }
    const fromRealm = String((session && session.derivedFromRealm) ||
                             defaultRealmId || realms.DEFAULT_ID);
    const closed = self.inRosterRealm(fromRealm, function () {
      return self.closeBootstrapWindow(name, wanted);
    });
    log.debug("Leaving AdminRbac.noteConsoleSignIn(). " +
              (closed ? "Closed " : "Open ") + "in " + fromRealm + ".");
    return closed;
  }

  private closeBootstrapWindow(name, wanted) {
    const { log, audit } = this.deps;
    const self = this;
    log.debug("Entering AdminRbac.closeBootstrapWindow().");
    const state = self.bootstrapState();
    if (!state.seeded || state.claimedAt) {
      log.debug("Leaving AdminRbac.closeBootstrapWindow(). Nothing to close.");
      return false;
    }
    const at = self.nowGeneralized();
    directory.writePersonFlag(wanted, 'stsConsoleClaimedAt', at);
    audit.record({
      action: 'admin.console.bootstrap', outcome: 'success', actor: name,
      target: state.dn, channel: 'internal',
      summary: 'The bootstrap administrator "' + name + '" signed in to the ' +
               'console; it is enforced from now on',
      detail: { event: 'claimed', username: name, at: at }
    });
    log.info('admin_rbac: the bootstrap administrator "' + name + '" of the "' +
             self.boundRealmId() + '" realm signed in to the console. That ' +
             'realm\'s roster is enforced from now on: only members of its ' +
             'two role groups may use it.');
    log.debug("Leaving AdminRbac.closeBootstrapWindow(). Closed.");
    return true;
  }

  // Is the whole roster empty — which is what opens the console to anybody who
  // signs in, while `admin.openWhenEmpty` says so, where no bootstrap
  // administrator was seeded (see `rolesOf()`).
  //
  // Note what it counts: MEMBERSHIP VALUES, not resolvable members. A grant to
  // somebody who has never authenticated is a value naming an entry that is not
  // there yet, and it is still a grant — treating it as empty would mean
  // granting a role to a future colleague quietly leaving the door open.
  rosterEmpty() {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering AdminRbac.rosterEmpty().");
    log.debug("Leaving AdminRbac.rosterEmpty().");
    return self.roster().reduce(function (n, row) {
      return n + row.memberCount;
    }, 0) === 0;
  }

  // ---------------------------------------------------------------------------
  // The decision. Everything that guards a request comes through here.
  // ---------------------------------------------------------------------------

  // Every role a person holds, with `write` expanded to `read` by the table's
  // own `implies`.
  //
  // Membership is asked of `groupsOfUser()` rather than read off the group
  // entry, and that is not the same question asked backwards. That function
  // does the three-shaped lookup every other reader here uses — a local name, a
  // certificate's subject DN, a `did:` — and it reads BOTH directions of
  // membership: the group listing the person, and the person's own `memberOf`
  // naming the group. So somebody an LDAP client added by writing `memberOf` on
  // their entry holds the role, which is what an administrator of a real
  // directory would expect and is not what a scan of `member` would have said.
  rolesOf(username) {
    const { log, config } = this.deps;
    const self = this;
    log.debug("Entering AdminRbac.rolesOf(). username=" + username);
    const name = String(username == null ? '' : username).trim();
    const held : Record<string, any> = {};
    const out: any = { username: name, roles: [], read: false, write: false,
                  groups: [], open: false, openable: false,
                  available: !!directory, empty: false };
    if (!directory || !name) {
      log.debug("Leaving AdminRbac.rolesOf(). " +
                (directory ? "No name." : "No directory."));
      return out;
    }

    const wanted : Record<string, any> = {};
    ROLES.forEach(function (role) {
      const cn = self.groupCnFor(role);
      if (cn) {
        wanted[cn.toLowerCase()] = role;
        wanted[directory.normalizeDn(self.dnForRole(role))] = role;
      }
    });

    const membership = directory.groupsOfUser(name);
    membership.groups.forEach(function (group) {
      const byCn = wanted[String(group.cn || '').trim().toLowerCase()];
      const byDn = wanted[directory.normalizeDn(group.dn)];
      const role = byCn || byDn;
      if (!role) {
        return;
      }
      out.groups.push({ role: role.id, cn: group.cn, dn: group.dn,
                        via: group.via, viaMemberOf: group.viaMemberOf });
      held[role.id] = true;
      role.implies.forEach(function (implied) { held[implied] = true; });
    });

    out.empty = self.rosterEmpty();
    // THE OPEN-CONSOLE RULE, and it is applied here rather than at the guard so
    // that the console's own banner, the management API's answer and the
    // refusal itself cannot come to disagree about whether the door is open.
    //
    // **SINCE 2026-09-13 IT IS ABOUT THE BOOTSTRAP ADMINISTRATOR, NOT THE EMPTY
    // ROSTER, wherever one was seeded.** `seedBootstrapAdministrator()` puts
    // `admin.bootstrapUsername` in both groups at startup, so the roster is
    // never empty on a service started through server.js — and the console
    // stays open to every signed-in person until THAT account first signs in to
    // it (`noteConsoleSignIn()`), after which the roster is enforced for good.
    // A directory with no seeded account (an in-process test, a process that
    // never ran the startup step) keeps the old rule: open while the roster is
    // empty.
    const bootstrap = self.bootstrapState();
    out.bootstrap = { username: bootstrap.username, seeded: bootstrap.seeded,
                      claimedAt: bootstrap.claimedAt };
    const unclaimed = bootstrap.seeded ? !bootstrap.claimedAt : out.empty;
    if (unclaimed && !Object.keys(held).length) {
      out.openable = true;
      if (config.value('admin.openWhenEmpty')) {
        out.open = true;
        ROLE_IDS.forEach(function (id) { held[id] = true; });
      }
    }

    out.roles = ROLE_IDS.filter(function (id) { return !!held[id]; });
    out.read = !!held.read;
    out.write = !!held.write;
    log.debug("Leaving AdminRbac.rolesOf(). " + name + " holds " +
              (out.roles.join(', ') || 'no role') +
              (out.open ? " (empty roster)." : "."));
    return out;
  }

  // ---------------------------------------------------------------------------
  // Granting and revoking.
  //
  // Both go through the SAME two functions the directory offers everything else
  // — `readGroupEntry()` and `writeGroupEntry()` — so a grant made here and a
  // grant made with an `ldapmodify` leave the identical entry. Nothing about
  // what a group IS is decided in this file; see the note at the end of
  // admin.js's slots about the console not being a second definition of
  // anything.
  // ---------------------------------------------------------------------------

  // The attributes of an existing group, ready to be written back: everything
  // it holds MINUS the operational ones.
  //
  // `entryDN` is the one that matters and it is the reason this is a function.
  // `readGroupEntry()` SYNTHESISES it — the DN is where the entry is, so
  // holding a copy would be a second definition of the same fact — and writing
  // the read object straight back would turn that synthesised value into a
  // stored attribute, which is the one thing every door onto this directory is
  // told never to do.
  private writableAttributes(entry) {
    const { log } = this.deps;
    log.debug("Entering AdminRbac.writableAttributes().");
    const out = {};
    Object.keys(entry.attributes).forEach(function (name) {
      if (NOT_WRITTEN_BACK.indexOf(name.toLowerCase()) >= 0) {
        return;
      }
      out[name] = entry.attributes[name].slice(0);
    });
    log.debug("Leaving AdminRbac.writableAttributes().");
    return out;
  }

  // WHERE THE MEMBERSHIP VALUE POINTS.
  //
  // The person's OWN entry when they have one, whatever it is named — somebody
  // whose entry was created by a client certificate is at `cn=<name>,ou=users`
  // and not at `uid=<name>,ou=users`, and a grant that wrote the uid form would
  // dangle beside the entry it was meant to name. When there is no entry, the
  // uid form is what a person created later will be at, so the value resolves
  // the moment they authenticate.
  private memberValueFor(username) {
    const { log } = this.deps;
    log.debug("Entering AdminRbac.memberValueFor(). username=" + username);
    const existing = directory.existingUserEntry(username);
    if (existing) {
      log.debug("Leaving AdminRbac.memberValueFor(). Their entry is at " +
                existing.dn + ".");
      return { dn: existing.dn, present: true };
    }
    const dn = 'uid=' + username + ',' + directory.usersDn;
    log.debug("Leaving AdminRbac.memberValueFor(). Nothing there yet; " +
              dn + " is where they would go.");
    return { dn: dn, present: false };
  }

  // Is this person already in this group — asked across all three membership
  // attributes, because the answer has to be the same one `rolesOf()` gives or
  // a grant would appear to work and change nothing.
  private memberIndex(entry, username, memberDn) {
    const { log } = this.deps;
    log.debug("Entering AdminRbac.memberIndex().");
    const normalized = directory.normalizeDn(memberDn);
    const wantedName = String(username).trim().toLowerCase();
    const hits = [];
    entry.members.forEach(function (member, index) {
      if (member.holds === 'uid') {
        if (String(member.value).trim().toLowerCase() === wantedName) {
          hits.push(index);
        }
        return;
      }
      if (directory.normalizeDn(member.value) === normalized) {
        hits.push(index);
        return;
      }
      // A value that resolved to the person's entry by some other spelling —
      // the dangling/present distinction again. Compared on the RESOLVED dn so
      // that `uid=alice,ou=users` and the same DN with different spacing are
      // one membership rather than two.
      if (member.present && directory.normalizeDn(member.dn) === normalized) {
        hits.push(index);
      }
    });
    log.debug("Leaving AdminRbac.memberIndex().");
    return hits;
  }

  private nameProblem(username) {
    const { log } = this.deps;
    log.debug("Entering AdminRbac.nameProblem().");
    if (!username) {
      log.debug("Leaving AdminRbac.nameProblem().");
      return 'No name was given. Choose somebody from the list, or type the ' +
             'name they will authenticate under.';
    }
    if (!directory.nameUsableInDn(username)) {
      log.debug("Leaving AdminRbac.nameProblem().");
      return '"' + username + '" carries a character RFC 4514 reserves in a ' +
             'DN, so it cannot name an entry ' +
             'under ' + directory.usersDn + '. That ' +
             'is the same refusal creating a person gets, and for the same ' +
             'reason: names of that shape get into this directory by being ' +
             'PRESENTED — a certificate subject, a did: — rather than by ' +
             'being typed.';
    }
    log.debug("Leaving AdminRbac.nameProblem().");
    return '';
  }

  grant(username, roleId, context) {
    const { log, audit } = this.deps;
    const self = this;
    log.debug("Entering AdminRbac.grant(). username=" + username +
              ", role=" + roleId);
    const name = String(username == null ? '' : username).trim();
    const role = self.roleFor(roleId);
    const via = (context || {}).via || 'console';
    const actor = (context || {}).actor || '';

    if (!directory) {
      log.debug("Leaving AdminRbac.grant(). No directory is loaded.");
      return self.refused('STS-ADMIN-0501',
                          { ok: false, errors: [NO_DIRECTORY] });
    }
    if (!role) {
      log.debug("Leaving AdminRbac.grant(). No such role.");
      return self.refused('STS-ADMIN-0582',
                     { ok: false, errors: ['Unknown role "' + roleId + '". ' +
          'There are two: ' +
                                   ROLE_IDS.join(' and ') + '.'] });
    }
    const problem = self.nameProblem(name);
    if (problem) {
      log.debug("Leaving AdminRbac.grant(). " + problem);
      return self.refused('STS-ADMIN-0583', { ok: false, errors: [problem] });
    }

    const dn = self.dnForRole(role);
    const cn = self.groupCnFor(role);
    const existing = directory.readGroupEntry(dn);
    const target = self.memberValueFor(name);
    const wasEmpty = self.rosterEmpty();

    if (existing && self.memberIndex(existing, name, target.dn).length) {
      // Not an error. Granting a role somebody already holds is the state the
      // caller wanted, and a 400 here would make a script that grants on every
      // run fail on its second one.
      log.debug("Leaving AdminRbac.grant(). Already a member.");
      return { ok: true, changed: false, role: role.id, username: name, dn: dn,
               member: target.dn,
               message: name + ' already holds ' + role.label + ' — ' + dn +
                        ' lists them. Nothing was changed.' };
    }

    let attributes;
    if (existing) {
      attributes = self.writableAttributes(existing);
      attributes.member = (attributes.member || []).concat([target.dn]);
    } else {
      // The group is created on the first grant rather than seeded at startup,
      // which is what makes "no members" and "no group" the same state: a
      // service nobody has granted anything on has neither, and the screen says
      // so once.
      attributes = {
        objectClass: ['top', 'groupOfNames'],
        cn: [cn],
        description: ['The ' + role.label + ' role for this service\'s ' +
                      'admin console. It grants nothing anywhere else: no ' +
                      'token, assertion, ticket or credential this service ' +
                      'issues is changed by being in it.'],
        member: [target.dn]
      };
    }

    const written = directory.writeGroupEntry(dn, attributes, 'console');
    if (!written.ok) {
      log.debug("Leaving AdminRbac.grant(). The directory refused: " +
                written.reason);
      return self.refused('STS-ADMIN-0585',
                     { ok: false, errors: [self.refusalText(written, dn)],
                       reason: written.reason });
    }

    audit.record({
      action: 'admin.role.change', outcome: 'success', actor: actor,
      target: dn, channel: via === 'api' ? 'http' : 'internal',
      summary: name + ' was granted ' + role.label,
      detail: { role: role.id, username: name, member: target.dn,
                created: written.created, via: via,
                resolves: target.present,
                rosterWasEmpty: wasEmpty }
    });

    log.debug("Leaving AdminRbac.grant(). " + name + " now holds " +
              role.id + ".");
    return { ok: true, changed: true, role: role.id, username: name, dn: dn,
             member: target.dn, created: !!written.created,
             resolves: target.present,
             entry: written.entry,
             message: name + ' now holds ' + role.label + ', as ' + target.dn +
                      ' in ' + dn + '.' +
                      (written.created ? ' The group did not exist and was ' +
                                         'created.' : '') +
                      (target.present ? ''
                                      : ' NOTHING IS AT THAT DN YET — they ' +
                                        'have not authenticated here and ' +
                                        'nobody has created them, so the ' +
                                        'membership dangles until one of ' +
                                        'those happens. The role still ' +
                                        'counts.') +
                      (wasEmpty ? ' This was the FIRST grant, so the ' +
                                  'roster is now enforced: whoever is not ' +
                                  'in one of ' +
                                  'these two groups can no longer use this ' +
                                  'console.' : '') };
  }

  revoke(username, roleId, context) {
    const { log, config, audit } = this.deps;
    const self = this;
    log.debug("Entering AdminRbac.revoke(). username=" + username +
              ", role=" + roleId);
    const name = String(username == null ? '' : username).trim();
    const role = self.roleFor(roleId);
    const via = (context || {}).via || 'console';
    const actor = (context || {}).actor || '';

    if (!directory) {
      log.debug("Leaving AdminRbac.revoke(). No directory is loaded.");
      return self.refused('STS-ADMIN-0501',
                          { ok: false, errors: [NO_DIRECTORY] });
    }
    if (!role) {
      log.debug("Leaving AdminRbac.revoke(). No such role.");
      return self.refused('STS-ADMIN-0582',
                     { ok: false, errors: ['Unknown role "' + roleId + '". ' +
          'There are two: ' +
                                   ROLE_IDS.join(' and ') + '.'] });
    }
    if (!name) {
      log.debug("Leaving AdminRbac.revoke(). No name.");
      return self.refused('STS-ADMIN-0584',
                     { ok: false, errors: ['No name was given.'] });
    }

    const dn = self.dnForRole(role);
    const existing = directory.readGroupEntry(dn);
    if (!existing) {
      log.debug("Leaving AdminRbac.revoke(). The group does not exist.");
      return { ok: true, changed: false, role: role.id, username: name, dn: dn,
               message: 'There is no ' + dn + ', so nobody holds ' +
                        role.label + ' and there was nothing to take away.' };
    }

    const target = self.memberValueFor(name);
    const hits = self.memberIndex(existing, name, target.dn);
    if (!hits.length) {
      // A CLAIMED membership is the one case where "not in the group" and "does
      // not hold the role" come apart, and answering the ordinary "nothing was
      // changed" here would be a revoke that reports success and leaves
      // somebody with access. It is REFUSED with where to go instead, because
      // the value is on the PERSON'S entry and this module writes only to
      // groups — writing to a person from here would make the console a second
      // definition of what an entry may hold, which is the thing every slot in
      // this feature avoids.
      const claimed = (directory.claimedMembersOf(dn) || []).filter(
          function (row) {
        return directory.normalizeDn(row.dn) ===
               directory.normalizeDn(target.dn);
      });
      if (claimed.length) {
        log.debug("Leaving AdminRbac.revoke(). Claimed through memberOf; " +
                  "refused.");
        return self.refused('STS-ADMIN-0586',
                            { ok: false, reason: 'claimed', role: role.id,
                              username: name, dn: dn,
                              errors: [name + ' holds ' + role.label +
                                       ' through a memberOf ' +
                                       'value on THEIR OWN entry ' +
                                       '(' + target.dn + ') rather than ' +
                                       'through a member value ' +
                                       'on ' + dn + ', so there is nothing ' +
                                       'in the group to remove. Nothing ' +
                                       'here maintains memberOf — a client ' +
                                       'wrote it — and this console writes ' +
                                       'only to groups, deliberately. ' +
                                       'Delete that value with an ' +
                                       'ldapmodify or a SCIM PATCH of the ' +
                                       'person and the role goes with it.'] });
      }
      log.debug("Leaving AdminRbac.revoke(). Not a member.");
      return { ok: true, changed: false, role: role.id, username: name, dn: dn,
               message: name + ' does not hold ' + role.label +
                        '. Nothing was changed.' };
    }

    // Removed from EVERY membership attribute that named them rather than from
    // the first one found. A person listed as both `member` and `memberUid` —
    // two clients, two conventions, one directory — would otherwise still hold
    // the role after a revoke that reported success, which is the worst shape a
    // permissions bug takes.
    const removed =
        hits.map(function (index) { return existing.members[index]; });
    const attributes = self.writableAttributes(existing);
    removed.forEach(function (member) {
      const key = Object.keys(attributes).filter(function (name2) {
        return name2.toLowerCase() === member.attribute.toLowerCase();
      })[0];
      if (!key) {
        return;
      }
      attributes[key] = attributes[key].filter(function (value) {
        return String(value) !== String(member.value);
      });
      if (!attributes[key].length) {
        delete attributes[key];
      }
    });

    const written = directory.writeGroupEntry(dn, attributes, 'console');
    if (!written.ok) {
      log.debug("Leaving AdminRbac.revoke(). The directory refused: " +
                written.reason);
      return self.refused('STS-ADMIN-0585',
                     { ok: false, errors: [self.refusalText(written, dn)],
                       reason: written.reason });
    }

    const nowEmpty = self.rosterEmpty();
    audit.record({
      action: 'admin.role.change', outcome: 'success', actor: actor,
      target: dn, channel: via === 'api' ? 'http' : 'internal',
      summary: name + ' was stripped of ' + role.label,
      detail: { role: role.id, username: name, via: via,
                values: removed.map(function (m) {
                  return m.attribute + ': ' + m.value;
                }).join(', '),
                rosterNowEmpty: nowEmpty }
    });

    // A seeded bootstrap administrator who has signed in has CLOSED the open
    // window for good, so an empty roster no longer opens the console.
    const boot = nowEmpty ? self.bootstrapState() : null;
    const reopens = nowEmpty && config.value('admin.openWhenEmpty') &&
                    !(boot.seeded && boot.claimedAt);
    log.debug("Leaving AdminRbac.revoke(). " + name + " no longer holds " +
              role.id + ".");
    return { ok: true, changed: true, role: role.id, username: name, dn: dn,
             removed: removed.length,
             message: name + ' no longer holds ' + role.label + ' — ' +
                      removed.length + ' membership value(s) removed from ' +
                      dn + '.' +
                      (nowEmpty
                        ? ' THAT WAS THE LAST GRANT ON THIS SERVICE. The ' +
                          'roster is empty again, so ' +
                          (reopens
                            ? 'this console is open to anybody who signs in ' +
                              'until somebody is granted a role.'
                            : 'nobody can use this console at all. POST ' +
                              '/admin-api/rbac/grant is the way back in.')
                        : '') };
  }

  private refusalText(written, dn) {
    const { log } = this.deps;
    log.debug("Entering AdminRbac.refusalText().");
    if (written.reason === 'notAGroup') {
      log.debug("Leaving AdminRbac.refusalText().");
      return 'There is already an entry at ' + dn + ' and it is not a group. ' +
             'Something wrote it — an ldapadd, a SCIM POST — and this ' +
             'console will not overwrite an entry it did not make. Delete ' +
             'it, or point the role at another cn on /admin/rbac.';
    }
    if (written.reason === 'noParent') {
      log.debug("Leaving AdminRbac.refusalText().");
      return 'There is no ' + written.parent + ' to put ' + dn +
             ' under. The groups container is created at startup, so ' +
             'something deleted it.';
    }
    if (written.reason === 'full') {
      log.debug("Leaving AdminRbac.refusalText().");
      return 'The directory holds its maximum number of entries ' +
             '(ldap.maxEntries), so the role group could not be created.';
    }
    log.debug("Leaving AdminRbac.refusalText().");
    return 'The directory refused to write ' + dn + ' (' + written.reason +
           ').';
  }

  // ---------------------------------------------------------------------------
  // WHO CAN BE CHOSEN, for the screen's person search (a `<select>` until
  // 2026-09-13; `admin-ui/CLAUDE.md` says why it is a search pane now).
  //
  // Two sources, unioned, and the difference between them is the difference
  // this console keeps straight everywhere: the DIRECTORY holds whoever
  // somebody wrote an entry for, and the console's user list holds whoever has
  // actually presented a credential. A person can be in either and not the
  // other, and a picker built from one of them alone would silently refuse to
  // offer half the people somebody wants to grant a role to.
  //
  // It is not a whitelist. A name that is in neither list can still be granted
  // a role by typing it, because the interesting case for a mock — grant the
  // role BEFORE the person first signs in, then watch them arrive with it — is
  // exactly the one that is in neither.
  // ---------------------------------------------------------------------------
  candidates(seen) {
    const { log } = this.deps;
    log.debug("Entering AdminRbac.candidates().");
    const out = new Map();
    const add = function (name, source) {
      log.debug("Entering add().");
      const value = String(name == null ? '' : name).trim();
      if (!value) {
        log.debug("Leaving add().");
        return;
      }
      const key = value.toLowerCase();
      if (!out.has(key)) {
        out.set(key, { username: value, inDirectory: false, seen: false });
      }
      out.get(key)[source] = true;
      log.debug("Leaving add().");
    };

    if (directory) {
      directory.allPersons().forEach(function (person) {
        // The RDN value, which is what `existingUserEntry()` matches a typed
        // name against — so what the search offers is what a grant will find.
        const rdn = String(person.dn).split(',')[0];
        const eq = rdn.indexOf('=');
        add(eq > 0 ? rdn.slice(eq + 1) : '', 'inDirectory');
      });
    }
    (seen || []).forEach(function (key) { add(key, 'seen'); });

    const rows = Array.from(out.values()).filter(function (row) {
      // A name that cannot be spelt in a DN cannot be granted a role, so
      // offering it in the search would be offering a control that answers with
      // a refusal. They are still listed on /admin/users; this is a grant form.
      return !directory || directory.nameUsableInDn(row.username);
    });
    rows.sort(function (a, b) {
      return a.username.toLowerCase() < b.username.toLowerCase() ? -1 : 1;
    });
    log.debug("Leaving AdminRbac.candidates(). " + rows.length +
              " candidate(s).");
    return rows;
  }

  // ---------------------------------------------------------------------------
  // The whole feature as one object, for the screen, for ?format=json and for
  // GET /admin-api/rbac. One builder so that the three cannot disagree — the
  // same rule /admin/scim follows about describing SCIM in the module that
  // implements it.
  // ---------------------------------------------------------------------------
  describe() {
    const { log, config, mode, realms } = this.deps;
    const self = this;
    log.debug("Entering AdminRbac.describe().");
    const rows = self.roster();
    const out: any = {
      enforced: mode.gatesConsole(),
      openWhenEmpty: !!config.value('admin.openWhenEmpty'),
      available: !!directory,
      groupsDn: directory ? directory.groupsDn : '',
      usersDn: directory ? directory.usersDn : '',
      // WHOSE ROSTER THIS IS (2026-09-14, #32). The default realm's is the
      // SERVICE roster — its members administer every realm and the whole
      // service; any other realm's grants authority in that realm alone.
      realm: self.boundRealmId(),
      authority: self.boundRealmId() === realms.DEFAULT_ID ? 'service'
                                                           : 'realm',
      roles: rows,
      grantCount: rows.reduce(function (n, row) { return n + row.memberCount; },
                              0)
    };
    out.empty = out.grantCount === 0;
    // THE BOOTSTRAP ADMINISTRATOR (2026-09-13) — see bootstrapState(). Where
    // one was seeded, the console is open until it signs in; otherwise, while
    // the roster is empty, as before.
    const bootstrap = self.bootstrapState();
    out.bootstrap = { username: bootstrap.username, seeded: bootstrap.seeded,
                      claimedAt: bootstrap.claimedAt };
    const unclaimed = bootstrap.seeded ? !bootstrap.claimedAt : out.empty;
    // Said as one flag rather than left to the caller to compute from three,
    // because it is the sentence every surface has to render and three of them
    // computing it separately is three chances to say the door is shut while it
    // is open.
    out.openToAnyone = out.enforced && unclaimed && out.openWhenEmpty;
    out.closedToEveryone = out.enforced && out.empty && !out.openToAnyone;
    log.debug("Leaving AdminRbac.describe(). " + out.grantCount + " grant(s).");
    return out;
  }

  // ---------------------------------------------------------------------------
  // THE PUBLIC FUNCTIONS, EACH TAKING THE REALM (2026-09-14, #32).
  //
  // `bound(fn, at)` answers a function that binds the realm found at argument
  // `at` for the call and then runs `fn` with the same arguments. The functions
  // above never re-bind — they read `directory` — so one of them calling
  // another stays in the realm its caller named.
  //
  // `grant()` and `revoke()` take it as `context.realm`, where their other
  // options already are.
  //
  // The signature says what the wrapper accepts (#50): the wrapped function's
  // arguments and then any number more, the realm among them, returning what
  // the wrapped function returns. It was JSDoc while this file was JavaScript.
  //
  // A method runs with `this`, so each wrapper applies the method to the
  // instance that built it.
  // ---------------------------------------------------------------------------
  private bound<F extends (...args: any[]) => any>(
      fn: F, at: number): (...args: any[]) => ReturnType<F> {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering AdminRbac.bound(). " + fn.name);
    log.debug("Leaving AdminRbac.bound().");
    return function () {
      const args = arguments;
      return self.inRosterRealm(args[at], function () {
        return fn.apply(self, args);
      });
    };
  }

  private inContextRealm<F extends (username: any, roleId: any,
                                    context?: any) => any>(
      fn: F): (username: any, roleId: any, context?: any) => ReturnType<F> {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering AdminRbac.inContextRealm(). " + fn.name);
    log.debug("Leaving AdminRbac.inContextRealm().");
    return function (username, roleId, context) {
      return self.inRosterRealm((context || {}).realm, function () {
        return fn.call(self, username, roleId, context);
      });
    };
  }

  // Whether a realm id names the SERVICE roster's realm — the default one,
  // which an empty or absent id also means here.
  isServiceRealm(realmId) {
    const { log, realms } = this.deps;
    const self = this;
    log.debug("Entering AdminRbac.isServiceRealm().");
    const id = self.realmIdOf(realmId);
    log.debug("Leaving AdminRbac.isServiceRealm().");
    return !id || id === realms.DEFAULT_ID;
  }

  // The public functions, each wrapped to take its realm — the table
  // `module.exports` was while this file was JavaScript.
  wrappers() {
    const { log } = this.deps;
    log.debug("Entering AdminRbac.wrappers().");
    const out = {
      available: this.bound(this.available, 0),
      roster: this.bound(this.roster, 0),
      rosterFor: this.bound(this.rosterFor, 1),
      rosterEmpty: this.bound(this.rosterEmpty, 0),
      seedBootstrapAdministrator: this.bound(this.seedBootstrapAdministrator,
                                             0),
      bootstrapState: this.bound(this.bootstrapState, 0),
      rolesOf: this.bound(this.rolesOf, 1),
      grant: this.inContextRealm(this.grant),
      revoke: this.inContextRealm(this.revoke),
      candidates: this.bound(this.candidates, 1),
      describe: this.bound(this.describe, 0)
    };
    log.debug("Leaving AdminRbac.wrappers().");
    return out;
  }
}

// THE TRANSITIONAL INSTANCE — see the header. Built from the real modules, as
// the composition root will build one; the public functions are wrapped as
// they were, so each takes the realm where it always did.
const rbac = new AdminRbac({
  log: helpers.log,
  config: config,
  mode: mode,
  audit: audit,
  errorCodes: errorCodes,
  realms: realms
});

const wrap = rbac.wrappers();

export = {
  AdminRbac: AdminRbac,
  ROLES: AdminRbac.ROLES,
  ROLE_IDS: AdminRbac.ROLE_IDS,
  roleFor: rbac.roleFor.bind(rbac) as AdminRbac['roleFor'],
  setDirectory: rbac.setDirectory.bind(rbac) as AdminRbac['setDirectory'],
  available: wrap.available,
  roster: wrap.roster,
  rosterFor: wrap.rosterFor,
  rosterEmpty: wrap.rosterEmpty,
  // THE BOOTSTRAP ADMINISTRATOR (2026-09-13), one per realm since 2026-09-14.
  seedBootstrapAdministrator: wrap.seedBootstrapAdministrator,
  noteConsoleSignIn: rbac.noteConsoleSignIn.bind(rbac) as
    AdminRbac['noteConsoleSignIn'],
  bootstrapState: wrap.bootstrapState,
  rolesOf: wrap.rolesOf,
  grant: wrap.grant,
  revoke: wrap.revoke,
  candidates: wrap.candidates,
  describe: wrap.describe,
  isServiceRealm: rbac.isServiceRealm.bind(rbac) as
    AdminRbac['isServiceRealm']
};
