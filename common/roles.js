'use strict';
//
// File: roles.js
//
// ---------------------------------------------------------------------------
// ROLES: THE ONE THING IN THIS SERVICE A USER, A GROUP AND AN APPLICATION ARE
// ALL FIRST-CLASS MEMBERS OF.
//
// A role is a NAME somebody may hold. Three kinds of directory object can be
// mapped into one — a person, a group (so every member of it holds the role),
// and an application (so a client authenticating as itself holds it) — and
// that third one is the part that is unusual and is the point: a
// `client_credentials` grant has no person in it at all, and until an
// application could hold a role there was nothing to decide about one.
//
// WHAT A ROLE IS FOR, in two sentences that are deliberately separate:
//
//   * It is CARRIED. Every access token, ID Token, SAML 2.0 assertion and
//     SAML 1.1 assertion this service issues can name the roles its subject
//     holds, in a claim of its own (`roles.claim`). A relying party reads it.
//   * It is ENFORCED. An application entry names the roles it REQUIRES, and
//     nothing is issued for that application to somebody who holds none of
//     them — a decision made by the XACML PDP through the embedded PEP in
//     `xacml/xacml_role_pep.js`, never by an `if` in an issuance site.
//
// THOSE ARE TWO DIFFERENT RELATIONS AND THIS FILE KEEPS THEM APART, because
// collapsing them is the mistake that makes the whole feature unreadable:
//
//   MEMBERSHIP   role -> users, groups, applications that HOLD it.
//                Stored on the ROLE entry, edited at /admin/roles.
//   REQUIREMENT  application -> roles it DEMANDS before anything is issued.
//                Stored on the APPLICATION entry (`appRequiredRole`), edited
//                on the application's own page.
//
// An application appears in both and means opposite things in each: in the
// first it HOLDS the role, in the second it DEMANDS it. `app_permissions.js`
// draws the same line between what MAY happen and what DID; this one is
// between what somebody IS and what somebody ASKS OF OTHERS.
//
// ---------------------------------------------------------------------------
// SIX ROLES ARE BUILT IN, COMPUTED, AND IN NO CONTAINER.
//
// They cannot be created, edited or deleted, they have no members to list, and
// every one of them is answered from the CONTEXT of the request being decided
// rather than from a store:
//
//   EVERYBODY                        anybody at all, authenticated or not.
//   ALL_AUTHENTICATED_USERS          a person with a live session here.
//   ALL_UNAUTHENTICATED_USERS        a person without one.
//   ALL_APPLICATIONS                 any client, however it turned up.
//   ALL_AUTHENTICATED_APPLICATIONS   a client that proved who it is — a
//                                    secret, a private_key_jwt assertion or a
//                                    verified client certificate.
//   ALL_UNAUTHENTICATED_APPLICATIONS a public client that proved nothing.
//
// **EVERYBODY IS WHAT MAKES THIS FEATURE OFF BY DEFAULT WITHOUT BEING ABSENT.**
// An application that names no required role is treated as requiring
// EVERYBODY, everybody holds EVERYBODY, so the decision is Permit and the
// service behaves exactly as it did before any of this existed. That is a
// better default than "no roles configured means do not ask", because the
// machinery is then always running and always visible: the console shows the
// decision, the audit log records it, and turning enforcement on for an
// application is narrowing a list rather than switching on a subsystem that
// has never run.
//
// The pairs are deliberately NOT complementary by accident — they are
// complementary on purpose, and both halves exist because "everyone who did
// not sign in" is a thing policy authors reach for and cannot express as a
// negation in a XACML target.
//
// ---------------------------------------------------------------------------
// IT IS A LIBRARY (rule 3), A LEAF, AND THAT IS LOAD-BEARING.
//
// It registers no route, so its place in the route order is not a place. It
// requires `helpers.js` and `config.js` and NOTHING ELSE in this repository —
// which is what lets `admin_stats.js` require it in the ORDINARY DIRECTION for
// the roles claim, rather than offering it a fifth inverted hook. CLAUDE.md
// rule 3e is explicit that a slot is what you reach for when a require would
// close a cycle or move a route, and that a fifth must not be added by
// analogy with the fourth: here a plain require works, so a plain require is
// what is used. **Do not make this file require `admin_stats.js`.** The moment
// it does, that argument is gone and a slot is the only way back.
//
// The DIRECTORY arrives through a slot pointing the other way, exactly as
// `group_claims.js`, `applications.js` and `xacml_store.js` do it: only
// `ldap/ldap_server.js` can answer what is in `ou=roles`, and it is the last
// module `server.js` requires, so a require reaching it from here would drag
// every `/ldap` route to the front of the router.
// ---------------------------------------------------------------------------

const { log } = require('./helpers');
const config = require('./config');

// ---------------------------------------------------------------------------
// THE SCHEMA. Published on `/admin/ldap/roles` the way every other container's
// is, because this directory is schemaless and a container of entries carrying
// invented attributes has to say what they mean somewhere.
// ---------------------------------------------------------------------------
const SCHEMA = {
  objectClasses: [
    { name: 'stsRole',
      what: 'One ROLE. The entry is named by the role name (`cn=staff`), and ' +
            'everything on it is MEMBERSHIP — who holds the role. What a ' +
            'role is REQUIRED for lives on the application entry that ' +
            'requires it, in `appRequiredRole`, because that is a fact about ' +
            'the application rather than about the role.' }
  ],
  attributes: [
    { name: 'roleName',
      what: 'The role name, which is also the `cn`. Carried explicitly as ' +
            'well so that a reader who has only the attributes has the name.' },
    { name: 'roleMemberUser',
      what: 'A username that holds this role. Multi-valued. The person need ' +
            'not exist yet — this service creates a directory entry for any ' +
            'name on first sight, so a role may be granted before its holder ' +
            'has ever signed in.' },
    { name: 'roleMemberGroup',
      what: 'A group whose every member holds this role. Multi-valued. ' +
            'Resolved at DECISION TIME rather than expanded on write, so an ' +
            '`ldapmodify` adding somebody to the group changes the very next ' +
            'token.' },
    { name: 'roleMemberApplication',
      what: 'An application that holds this role AS ITSELF — what a ' +
            'client_credentials grant is decided on, where there is no ' +
            'person. Multi-valued. NOT the same relation as `appRequiredRole` ' +
            'on the application entry, which is what that application ' +
            'DEMANDS of others.' },
    { name: 'description',
      what: 'What the role is for, for the next person.' }
  ]
};

// ---------------------------------------------------------------------------
// THE BUILT-IN ROLES. SIX WHEN THIS TABLE WAS WRITTEN, SEVEN SINCE 2026-09-06
// AND EIGHT SINCE THE XACML SURFACE WAS CLOSED.
//
// A table rather than six constants, because three things have to agree about
// them — the console's menus, the resolver below, and the refusal that stops
// somebody creating a role with one of these names — and three copies of a
// list is three chances for one to be missed.
//
// **THE COUNT IS NOT WRITTEN DOWN ANYWHERE THAT MATTERS, AND THAT IS
// DELIBERATE.** `BUILT_IN_NAMES`, `builtInCatalogue()` and `isBuiltIn()` are
// all derived from this array, so adding a row is the whole of adding a role.
// The numbers in the prose around it are the part that goes stale — this
// heading said "six" for the whole of the day REMOTE_PEPS existed.
// ---------------------------------------------------------------------------
const BUILT_IN = [
  { name: 'EVERYBODY',
    what: 'Anybody at all, authenticated or not, person or application. ' +
          'THIS IS THE DEFAULT REQUIREMENT: an application that names no ' +
          'required role requires this one, everybody holds it, and nothing ' +
          'is refused — which is exactly how this service behaved before ' +
          'roles existed.',
    holds: function () {
      return true;
    } },
  { name: 'ALL_AUTHENTICATED_USERS',
    what: 'A person with a live authenticated session in the security ' +
          'context this decision is being made in.',
    holds: function (who) {
      return who.kind === 'user' && who.authenticated;
    } },
  { name: 'ALL_UNAUTHENTICATED_USERS',
    what: 'A person who has NOT authenticated. It is not the negation of the ' +
          'role above as far as a policy is concerned — it is a name a ' +
          'target can match, and XACML targets cannot say "not".',
    holds: function (who) {
      return who.kind === 'user' && !who.authenticated;
    } },
  // ---------------------------------------------------------------------
  // THE TWO MANAGEMENT-API ROLES (2026-09-09), and they are the first
  // built-ins computed from a CREDENTIAL rather than from what the party IS.
  //
  // `/admin-api` is reached with an OAuth 2.0 access token whose audience is
  // the management API and whose scopes say what it may do. A scope is not a
  // role — it is what the client ASKED FOR and the authorization server
  // granted — so the mapping is stated here, once, and the policy is written
  // in terms of roles like every other policy in this service. That is what
  // lets `/admin/xacml` express "a read needs ADMIN_READ" without the
  // document having to know that scopes exist.
  //
  // They are built-in rather than configured for the same reason
  // ALL_AUTHENTICATED_USERS is: nobody grants them, they are READ OFF the
  // request, and a deployment that could edit the membership of "holds
  // admin:write" would have two answers to one question.
  // ---------------------------------------------------------------------
  { name: 'ADMIN_READ',
    what: 'A caller presenting an access token for the management API that ' +
          'carries the `admin:read` scope. Every READ operation on ' +
          '/admin-api requires it.',
    holds: function (who) {
      return who.scopes.indexOf('admin:read') >= 0;
    } },
  { name: 'ADMIN_WRITE',
    what: 'A caller presenting an access token for the management API that ' +
          'carries the `admin:write` scope. Every operation on /admin-api ' +
          'that CHANGES anything requires it. It does not imply ADMIN_READ: ' +
          'a token may carry either, both or neither, and the policy asks ' +
          'for the one the operation needs.',
    holds: function (who) {
      return who.scopes.indexOf('admin:write') >= 0;
    } },
  { name: 'ALL_APPLICATIONS',
    what: 'Any client, however it turned up.',
    holds: function (who) {
      return who.kind === 'application';
    } },
  { name: 'ALL_AUTHENTICATED_APPLICATIONS',
    what: 'A client that PROVED who it is — a secret, a private_key_jwt ' +
          'assertion, or a verified client certificate. A public client that ' +
          'merely sent a client_id is not this.',
    holds: function (who) {
      return who.kind === 'application' && who.authenticated;
    } },
  { name: 'ALL_UNAUTHENTICATED_APPLICATIONS',
    what: 'A public client that proved nothing.',
    holds: function (who) {
      return who.kind === 'application' && !who.authenticated;
    } },
  // -------------------------------------------------------------------------
  // THE SEVENTH, AND THE FIRST ONE COMPUTED FROM A GROUP (2026-09-06).
  //
  // The six above are computed from what the party IS — a person or a client,
  // authenticated or not — and none of them reads the directory. This one is
  // held by whoever is in one named GROUP, which makes it a hybrid and the
  // hybrid is deliberate:
  //
  //   * it is BUILT IN rather than a row in `ou=roles`, because the surface it
  //     guards (`/xacml/pep/*`) has to be guarded in a realm nobody has
  //     configured. A configured role is absent until somebody makes it, and a
  //     gate that is absent is a gate that is open.
  //   * it is held through a GROUP rather than by name, because the party
  //     holding it is a certificate DN that does not exist until a launcher
  //     mints one — there is no name to write into a role definition in
  //     advance, and there IS a group to put whatever turns up into.
  //
  // **THE GROUP IS THE GRANT AND THE CERTIFICATE IS ONLY THE IDENTITY.** A
  // remote PEP presenting a certificate this service verified is somebody it
  // can NAME; it is not thereby somebody it lets in. Membership of this group
  // is the deliberate act, and a verified certificate whose DN is not in it is
  // refused — which is the whole point of resolving the DN rather than
  // stopping at the handshake.
  // -------------------------------------------------------------------------
  { name: 'REMOTE_PEPS',
    what: 'A remote XACML Policy Enforcement Point: whoever is a member of ' +
          'the group named by `roles.remotePepGroup` (default ' +
          '"remote-peps"). It is what `/xacml/pep/register`, ' +
          '`/xacml/pep/policies` and `/xacml/pep/heartbeat` require, and the ' +
          'party that holds it is normally a client-certificate DN rather ' +
          'than a person — the certificate says WHO, and this group says ' +
          'whether they may.',
    holds: function (who) {
      const wanted = remotePepGroupName().toLowerCase();
      if (!wanted) {
        return false;
      }
      return (who.groups || []).some(function (one) {
        return String(one).toLowerCase() === wanted;
      });
    } },
  // -------------------------------------------------------------------------
  // THE EIGHTH, AND THE SECOND COMPUTED FROM A GROUP.
  //
  // **THE ARGUMENT IS MADE AGAIN RATHER THAN CITED, and it comes out in the
  // same place for a different reason.** REMOTE_PEPS is group-derived because
  // the party holding it is a certificate DN that does not exist until a
  // launcher mints one — there is no name to write into a role definition in
  // advance. That reason does NOT apply here: the parties reaching
  // `/xacml/pdp`, `/xacml/policies` and `/xacml/protected` are ordinary
  // callers and some of them are people who already have directory entries.
  //
  // What decides it is the other half of REMOTE_PEPS's argument, and that one
  // does apply, harder: **A CONFIGURED ROLE IS ABSENT UNTIL SOMEBODY MAKES
  // IT.** `ou=roles` is per realm, so a role seeded once in the default realm
  // leaves every realm created afterwards with a XACML surface that either
  // refuses everybody (if the requirement still travels) or admits everybody
  // (if it does not) — and both of those are answers nobody chose. A built-in
  // role is computed, so it exists in a realm nobody has configured, which is
  // the only realm most of them ever are.
  //
  // **SO A GROUP IS THE GRANT AND IT REACHES BOTH THINGS THAT WERE ASKED
  // FOR.** A GROUP is admitted by naming it in `roles.xacmlUserGroup`; a
  // PERSON is admitted by being put in that group, which is one line on
  // `/admin/ldap/directory` and one `ldapmodify` on the raw socket. Neither
  // costs a per-realm entry that can be deleted, and membership is resolved at
  // DECISION TIME, so adding somebody changes the very next request rather
  // than the next restart.
  //
  // **IT IS NOT THE SAME ROLE AS REMOTE_PEPS AND MUST NOT BECOME ONE.** A
  // remote enforcement point pulls the documents this service enforces its own
  // access with; a XACML caller asks a question and reads a demonstration
  // policy. One group granting both would mean admitting somebody to the
  // second silently admits them to the first, which is exactly the collapse
  // the two-register split in this file exists to prevent.
  // -------------------------------------------------------------------------
  { name: 'XACML_USER',
    what: 'A caller of the XACML surface proper: whoever is a member of the ' +
          'group named by `roles.xacmlUserGroup` (default "xacml-users"). ' +
          'It is what `GET /xacml`, `POST /xacml/pdp`, `GET /xacml/policies` ' +
          'and `GET /xacml/protected` require, and the party that holds it ' +
          'is normally a client-certificate DN — the certificate says WHO, ' +
          'and this group says whether they may. It is deliberately NOT ' +
          'REMOTE_PEPS: that role reaches the three /xacml/pep endpoints, ' +
          'which hand out the documents this service enforces its own access ' +
          'with, and one group granting both would make admitting a caller ' +
          'to the demonstration surface silently admit it to those.',
    holds: function (who) {
      const wanted = xacmlUserGroupName().toLowerCase();
      if (!wanted) {
        return false;
      }
      return (who.groups || []).some(function (one) {
        return String(one).toLowerCase() === wanted;
      });
    } }
];

// The group that grants REMOTE_PEPS. A setting rather than a constant because
// a deployment that already has a group for its enforcement points should be
// able to name it rather than make a second one — and because naming it '' is
// how somebody turns the role off entirely, which `holds()` above reads as
// "nobody".
function remotePepGroupName() {
  return String(config.value('roles.remotePepGroup') || '').trim();
}

// The group that grants XACML_USER, on the same terms and with one extra
// consequence worth stating where somebody will read it before typing: naming
// it '' closes the four XACML endpoints to EVERY caller, including one holding
// a certificate this service verified. That is a supported configuration — it
// is how a deployment turns the surface off without turning `xacml.enabled`
// off and losing the embedded PEPs with it — and it is not a mistake this
// function should second-guess.
function xacmlUserGroupName() {
  return String(config.value('roles.xacmlUserGroup') || '').trim();
}

const BUILT_IN_NAMES = BUILT_IN.map(function (one) {
  return one.name;
});

// The default requirement, and the one name in this file that other modules
// hard-code. Exported so that `applications.js`, the console and the XACML PEP
// all mean the same string by "the permissive default".
const DEFAULT_REQUIRED_ROLE = 'EVERYBODY';

function isBuiltIn(name) {
  return BUILT_IN_NAMES.indexOf(String(name)) >= 0;
}

function builtInCatalogue() {
  return BUILT_IN.map(function (one) {
    return { name: one.name, what: one.what, builtIn: true };
  });
}

// ---------------------------------------------------------------------------
// THE DIRECTORY SLOT.
// ---------------------------------------------------------------------------
let directory = null;
let warnedAboutNoDirectory = false;

function setDirectory(hooks) {
  log.debug('Entering setDirectory().');
  directory = hooks || null;
  log.debug('Leaving setDirectory(). The role register ' +
            (directory ? 'has its container.' : 'has none.'));
}

// WHAT IS CURRENTLY INSTALLED, so that a test which stubs the slot can put
// back what was there rather than `null` — `xacml_store.js` argues why that
// distinction is not pedantry, and it is the same one process, one reference
// situation here.
function directoryInstalled() {
  return directory;
}

function haveDirectory() {
  if (directory && typeof directory.allRoles === 'function') {
    return true;
  }
  if (!warnedAboutNoDirectory) {
    warnedAboutNoDirectory = true;
    log.warn('roles: the embedded directory was never loaded, so there is no ' +
             'ou=roles to hold a role. The six BUILT-IN roles still answer — ' +
             'they are computed rather than stored — so an application ' +
             'requiring EVERYBODY still admits everybody, which is the ' +
             'default. Only configured roles are missing. There is no ' +
             'fallback store, deliberately: a role register that quietly ' +
             'lived in memory would decide things nobody could find.');
  }
  return false;
}

// ---------------------------------------------------------------------------
// READING THE REGISTER.
// ---------------------------------------------------------------------------
function firstValue(attributes, name) {
  const found = attributes[name] || attributes[name.toLowerCase()];
  return Array.isArray(found) ? (found[0] || '') : (found || '');
}

function allValues(attributes, name) {
  const found = attributes[name] || attributes[name.toLowerCase()];
  if (!found) {
    return [];
  }
  return (Array.isArray(found) ? found : [found]).map(function (one) {
    return String(one).trim();
  }).filter(function (one) {
    return one.length > 0;
  });
}

function all() {
  log.debug('Entering all().');
  if (!haveDirectory()) {
    log.debug('Leaving all(). No directory.');
    return [];
  }
  const rows = directory.allRoles().map(function (entry) {
    const at = entry.attributes || {};
    return {
      name: entry.name,
      dn: entry.dn,
      description: firstValue(at, 'description'),
      users: allValues(at, 'roleMemberUser'),
      groups: allValues(at, 'roleMemberGroup'),
      applications: allValues(at, 'roleMemberApplication'),
      builtIn: false
    };
  });
  rows.sort(function (a, b) {
    return a.name.localeCompare(b.name);
  });
  log.debug('Leaving all(). ' + rows.length + ' role(s).');
  return rows;
}

function read(name) {
  log.debug('Entering read(). name=' + name);
  const wanted = String(name || '');
  const found = all().filter(function (row) {
    return row.name === wanted;
  })[0] || null;
  log.debug('Leaving read(). ' + (found ? 'Found.' : 'Not here.'));
  return found;
}

// Every role a policy or a console menu may name: the configured ones and the
// built-in ones, in one list, marked. One list because a policy author
// choosing a required role does not care which kind it is — and the mark is
// there because everything else about them differs.
function catalogue() {
  log.debug('Entering catalogue().');
  const out = builtInCatalogue().concat(all().map(function (row) {
    return { name: row.name, what: row.description, builtIn: false,
             members: row.users.length + row.groups.length +
                      row.applications.length };
  }));
  log.debug('Leaving catalogue(). ' + out.length + ' role(s).');
  return out;
}

// ---------------------------------------------------------------------------
// WRITING.
// ---------------------------------------------------------------------------
function checkName(name) {
  const text = String(name || '').trim();
  if (!text) {
    return 'A role needs a name.';
  }
  if (isBuiltIn(text)) {
    return 'There is already a built-in role called "' + text + '", and the ' +
           'built-in ones are COMPUTED rather than stored — a stored role of ' +
           'the same name could never be reached, because the resolver ' +
           'answers the built-in one first. The six are: ' +
           BUILT_IN_NAMES.join(', ') + '.';
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9 ._:@-]{0,63}$/.test(text)) {
    return 'A role name is up to 64 characters of letters, digits, and ' +
           '. _ : @ - or a space, starting with a letter or a digit. "' +
           text + '" is not, and the name becomes an LDAP RDN and a value in ' +
           'a token claim.';
  }
  return null;
}

function write(name, record) {
  log.debug('Entering write(). name=' + name);
  const problem = checkName(name);
  if (problem) {
    log.debug('Leaving write(). ' + problem);
    return { ok: false, why: problem };
  }
  if (!haveDirectory()) {
    log.debug('Leaving write(). No directory.');
    return { ok: false,
             why: 'There is no embedded directory in this process, so there ' +
                  'is nowhere to keep a role. ou=roles IS the register.' };
  }
  const given = record || {};
  const attributes = {
    roleName: String(name),
    description: String(given.description || ''),
    roleMemberUser: (given.users || []).map(String),
    roleMemberGroup: (given.groups || []).map(String),
    roleMemberApplication: (given.applications || []).map(String)
  };
  const written = directory.writeRole(String(name), attributes);
  if (!written) {
    log.debug('Leaving write(). The directory refused.');
    return { ok: false,
             why: 'The directory would not store the role — it is at its ' +
                  'maximum number of entries.' };
  }
  log.debug('Leaving write(). Stored.');
  return { ok: true, name: String(name) };
}

function remove(name) {
  log.debug('Entering remove(). name=' + name);
  if (isBuiltIn(name)) {
    log.debug('Leaving remove(). Built in.');
    return { ok: false,
             why: '"' + name + '" is a built-in role. It is computed rather ' +
                  'than stored, so there is nothing to delete — and an ' +
                  'application requiring it would be requiring something ' +
                  'that no longer existed.' };
  }
  if (!haveDirectory() || !directory.deleteRole(String(name))) {
    log.debug('Leaving remove(). Not here.');
    return { ok: false, why: 'There is no role called "' + name + '".' };
  }
  log.debug('Leaving remove(). Gone.');
  return { ok: true };
}

// ---------------------------------------------------------------------------
// THE RESOLVER: WHICH ROLES DOES THIS PARTY HOLD.
//
// `who` is the SECURITY CONTEXT of one decision:
//
//   { kind: 'user' | 'application',
//     name: the username or the application's client id / handle,
//     authenticated: whether this party proved anything,
//     groups: the group names a person is in (a user only) }
//
// THE GROUPS ARE PASSED IN RATHER THAN LOOKED UP HERE where the caller already
// has them, and looked up through the directory slot where it does not. Both,
// because the two callers are genuinely different: the issuance gate is
// deciding about a session it already read the groups for, and the roles claim
// is being built inside a token mint that has only a name.
//
// IT NEVER THROWS. A register this service consults must not be able to fail
// the issuance it was consulted during — the same rule every directory read
// here follows — so a broken lookup answers "the built-in roles only", which
// still contains EVERYBODY and therefore still admits everybody an unedited
// application admits.
// ---------------------------------------------------------------------------
function rolesOf(who) {
  log.debug('Entering rolesOf(). kind=' + (who || {}).kind);
  const context = normalizeContext(who);
  // THE GROUPS ARE RESOLVED BEFORE THE BUILT-INS ARE ASKED, AND THAT IS NEW.
  // Five of the built-in roles are computed from `kind` and `authenticated`
  // alone and never needed this; REMOTE_PEPS and XACML_USER are held through a
  // group, so `holds()` has to be able to see one. It is resolved ONCE and put
  // on the context, which is also what `configuredRolesOf()` below then reads —
  // so this is the same directory walk that was already happening, moved
  // earlier and shared, rather than a second one.
  context.groups = groupsFor(context);
  const held = BUILT_IN.filter(function (one) {
    return one.holds(context);
  }).map(function (one) {
    return one.name;
  });
  let configured = [];
  try {
    configured = configuredRolesOf(context);
  } catch (error) {
    // Swallowed and logged: see the header. A token issued without a role it
    // should have carried is a defect; an issuance that FAILED because the
    // role register threw would be a worse one, and this service's whole job
    // is to keep answering.
    log.error('roles: the register threw while resolving roles for "' +
              context.name + '" and was ignored; only the built-in roles ' +
              'were used. ' + error.message);
  }
  const out = held.concat(configured.filter(function (one) {
    return held.indexOf(one) < 0;
  }));
  log.debug('Leaving rolesOf(). ' + out.length + ' role(s): ' +
            out.join(', '));
  return out;
}

function normalizeContext(who) {
  const given = who || {};
  const kind = given.kind === 'application' ? 'application' : 'user';
  return {
    kind: kind,
    name: String(given.name || ''),
    authenticated: given.authenticated === true,
    groups: Array.isArray(given.groups) ? given.groups.map(String) : null,
    // THE SCOPES OF THE ACCESS TOKEN THIS DECISION IS BEING MADE FOR, when
    // there is one. Two built-in roles below are computed from them — see
    // ADMIN_READ — and everything else ignores them, so a caller that
    // presented no token is exactly what it was.
    scopes: Array.isArray(given.scopes)
      ? given.scopes.map(String)
      : String(given.scopes || '').split(/\s+/).filter(Boolean)
  };
}

function groupsFor(context) {
  if (context.groups) {
    return context.groups;
  }
  if (context.kind !== 'user' || !context.name ||
      !directory || typeof directory.groupsOfUser !== 'function') {
    return [];
  }
  return directory.groupsOfUser(context.name) || [];
}

function configuredRolesOf(context) {
  if (!context.name) {
    // AN ANONYMOUS PARTY HOLDS NO CONFIGURED ROLE and every built-in one that
    // applies. Not an error: `ALL_UNAUTHENTICATED_USERS` is a real answer, and
    // it is the whole reason that role exists.
    return [];
  }
  const groups = context.kind === 'user' ? groupsFor(context) : [];
  const lowerGroups = groups.map(function (one) {
    return String(one).toLowerCase();
  });
  return all().filter(function (role) {
    if (context.kind === 'application') {
      return contains(role.applications, context.name);
    }
    if (contains(role.users, context.name)) {
      return true;
    }
    return role.groups.some(function (group) {
      return lowerGroups.indexOf(String(group).toLowerCase()) >= 0;
    });
  }).map(function (role) {
    return role.name;
  });
}

// Case-insensitively, because a username here arrives from a login form, a
// SAML subject, a Kerberos principal and a client_id, and this service has
// always treated those as one identity however they were typed —
// `admin_stats.js`'s `identityKeyOf()` is the same decision one layer up.
function contains(list, wanted) {
  const key = String(wanted).toLowerCase();
  return list.some(function (one) {
    return String(one).toLowerCase() === key;
  });
}

// ---------------------------------------------------------------------------
// THE CLAIM.
//
// `admin_stats.js` calls this while building a token or an assertion, through
// a PLAIN REQUIRE in the ordinary direction — see the header for why that is
// worth protecting.
//
// **THE CLAIM IS OMITTED ENTIRELY FOR SOMEBODY WITH NO CONFIGURED ROLE**, and
// the BUILT-IN ones are not in it at all. That second half is the one worth
// arguing: EVERYBODY and ALL_AUTHENTICATED_USERS are true of almost every
// token this service issues, so putting them in the claim would add two
// meaningless members to every token every existing client parses, and would
// tell a relying party nothing it did not already know from holding the token.
// They exist to be REQUIRED, not to be carried.
// ---------------------------------------------------------------------------
function claimFor(who) {
  log.debug('Entering claimFor().');
  if (config.value('roles.claim') === false) {
    log.debug('Leaving claimFor(). The claim is off.');
    return null;
  }
  const context = normalizeContext(who);
  let names = [];
  try {
    names = configuredRolesOf(context);
  } catch (error) {
    log.error('roles: the register threw while building the roles claim and ' +
              'was ignored; the token is issued without it. ' + error.message);
    return null;
  }
  if (!names.length) {
    log.debug('Leaving claimFor(). No configured role, so no claim.');
    return null;
  }
  const name = String(config.value('roles.claimName') || 'roles');
  const out = {};
  out[name] = names.sort();
  log.debug('Leaving claimFor(). ' + names.length + ' role(s).');
  return out;
}

// ---------------------------------------------------------------------------
// READING THE ROLES OUT OF A TOKEN SOMEBODY PRESENTED.
//
// The other direction, and the one the standard policy template is written
// around: a request may arrive carrying a token, and that token may carry the
// claim this service put in it. Reading it back is what makes a policy about
// roles enforceable at a door where the SUBJECT is a token rather than a
// session.
//
// **WHAT COMES OUT IS NOT TRUSTED MORE THAN THE TOKEN IT CAME FROM**, and this
// service does not verify access tokens it did not issue. So the roles found
// here are UNIONED with the ones the register answers rather than replacing
// them, and the register is what an enforcement decision can rest on. A claim
// naming `admin` in a token this service never minted adds a role to the
// request and the policy may match it — which is the mock's usual bargain, and
// it is written down here rather than discovered.
// ---------------------------------------------------------------------------
function rolesInClaims(claims) {
  log.debug('Entering rolesInClaims().');
  if (!claims || typeof claims !== 'object') {
    log.debug('Leaving rolesInClaims(). Nothing to read.');
    return [];
  }
  const name = String(config.value('roles.claimName') || 'roles');
  const raw = claims[name];
  if (raw === undefined || raw === null) {
    log.debug('Leaving rolesInClaims(). The claim is not there.');
    return [];
  }
  // THREE SHAPES ARE ACCEPTED because three are what real identity providers
  // send: an array, a single string, and a space-separated string (which is
  // what a `scope`-shaped claim looks like and what several products emit).
  // Reading only the first would silently find nothing in the other two, and
  // finding nothing looks exactly like holding no roles.
  const values = Array.isArray(raw) ? raw
    : (typeof raw === 'string' ? raw.split(/[\s,]+/) : [raw]);
  const out = values.map(function (one) {
    return String(one).trim();
  }).filter(function (one) {
    return one.length > 0;
  });
  log.debug('Leaving rolesInClaims(). ' + out.length + ' role(s).');
  return out;
}

module.exports = {
  SCHEMA: SCHEMA,
  BUILT_IN: BUILT_IN,
  BUILT_IN_NAMES: BUILT_IN_NAMES,
  DEFAULT_REQUIRED_ROLE: DEFAULT_REQUIRED_ROLE,
  isBuiltIn: isBuiltIn,
  builtInCatalogue: builtInCatalogue,
  setDirectory: setDirectory,
  directoryInstalled: directoryInstalled,
  all: all,
  read: read,
  catalogue: catalogue,
  checkName: checkName,
  write: write,
  remove: remove,
  rolesOf: rolesOf,
  claimFor: claimFor,
  rolesInClaims: rolesInClaims
};
