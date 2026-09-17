'use strict';
//
// File: scim_map.ts
//
// ---------------------------------------------------------------------------
// WHAT A SCIM RESOURCE IS, IN TERMS OF LDAP ATTRIBUTES.
//
// `scim.ts` speaks RFC 7644 and reaches the directory; this says which LDAP
// attribute each SCIM member is, in both directions. It is the FOURTH library
// over the same territory and the split is the one rule 3d already draws:
//
//   vc_claims.ts            what an issued CREDENTIAL carries      /admin/vc
//   vc_verifier_config.ts   what the mock Verifier ASKS FOR        /admin/vc-verifier-config
//   claim_attributes.js     what a TOKEN carries                   /admin/claims
//   claim_attributes.js     what an ASSERTION carries              /admin/saml-attributes
//   this file               what a SCIM RESOURCE is made of        /admin/scim
//
// The first three are SELECTIONS out of one catalogue and are deliberately
// independent of each other. This one is NOT a selection and there is nothing
// to tick: SCIM defines its own schema (RFC 7643), so what a User carries is
// decided by that document rather than by this service, and the only question
// left is which LDAP attribute each member is stored in. That is a mapping and
// a mapping is a table.
//
// **THE ATTRIBUTE SPELLINGS ARE NOT A FIFTH LIST.** Every row that names an
// attribute vc_claims.ts already knows is checked against that catalogue at
// require time and DISAGREEMENTS ARE REPORTED — the same rule ldap_server.js's
// learnName() follows, and for the same reason: four independently maintained
// sets of spellings is how one of them comes to be quietly wrong about
// `schacDateOfBirth` while all four look right read alone. Reported and not
// thrown, because a table of how to capitalise a name must never be able to
// stop this service starting.
//
// ---------------------------------------------------------------------------
// IT IS A LIBRARY (rule 3) AND IT TOUCHES NO DIRECTORY.
//
// It registers no route, so its position in the require order is not a
// position. It requires `helpers.js` and `vc_claims.ts` and nothing else here,
// and neither requires it back — which is what lets `admin.js` require it to
// draw the mapping table on /admin/scim even though admin.js is required BEFORE
// ldap_server.js. That is the whole reason the conversions live here rather
// than in `scim.ts`: a require from the console into the SCIM module would
// have dragged the /scim routes into the express router ahead of /admin, and
// /admin/sts-metadata is built by walking that router. Since #50's R1
// requiring `scim.ts` registers nothing of its own, but it still requires
// `ldap_server.js`, which is JavaScript and DOES register its routes when
// required — so the argument stands, one module further down.
//
// So there are two readers and they read different halves:
//
//   scim.ts    the CONVERSIONS, on every request
//   admin.js   the CATALOGUE, to draw it on a page
//
// Nothing in this file reads or writes an entry. It is handed an entry object —
// the {dn, origin, createdAt, modifiedAt, attributes} shape ldap_server.js's
// entryObject() produces — and hands back a SCIM resource, or the reverse. That
// is what makes it testable without a directory and what keeps the placement
// rules (where a person's entry goes, what counts as a group) in the one module
// that already owns them.
//
// ---------------------------------------------------------------------------
// FIVE DECISIONS ARE LOAD-BEARING, and each is easy to undo by accident.
//
// **THE SCIM `id` WAS THE ENTRY'S DN UNTIL 2026-09-14, AND IS ITS `entryUUID`
// NOW** — the paragraph below is the argument that was made for the DN, kept
// because its last sentence is the one that lost: RFC 7643 section 3.1's id
// "MUST NOT be reassigned", a rename reassigned it, and a stable subject made
// that a defect rather than a quirk. The UUID is the value a person's token
// carries in `sub` as `urn:uuid:<value>`; `scimIdOf()` reads it off the entry,
// and the SCIM handlers translate member and manager ids to and from DNs.
//
// RFC 7643 section 3.1 wants an opaque,
// server-assigned, unique identifier that the client must not parse, and the DN
// is exactly that and is already the key the entry is stored under. Any other
// choice is a SECOND definition of one fact: a `uid` is not unique in this tree
// (nothing stops `uid=alice,ou=users` and `cn=alice,ou=people` existing side by
// side), a synthesised id would have to be stored on the entry and would go
// stale on a rename the way `applicationEntry()` shows a stored DN does, and a
// digest would be unusable in the place a reader most wants to read one. The
// cost is stated rather than hidden: a DN in a URL path segment is ugly
// (`/scim/v2/Users/uid%3Dalice%2Cou%3Dusers%2Cdc%3Dexample%2Cdc%3Dcom`), and an
// LDAP rename gives the same person a new SCIM id — which is a real deviation
// from "stable for the lifetime of the resource" and is on /admin/scim in those
// words. It is the honest one for a directory-backed server: after a rename it
// IS a different key.
//
// **SCIM SEES A WINDOW ONTO THE ENTRY AND A PUT REPLACES ONLY WHAT IS INSIDE
// IT.** RFC 7644 section 3.5.1 says a PUT replaces the resource, and read
// strictly against an LDAP entry that would mean a provisioning client
// deleting `schacDateOfBirth`, `authnMethod`, `mfaAuthenticated` and every
// x509 attribute the moment it updated somebody's phone number — facts SCIM
// never knew about, cannot send, and cannot restore. So `fromScimUser()` is
// given the attributes the entry already has and REPLACES ONLY THE MAPPED
// ONES. Everything outside the window is carried through untouched. A client
// that means to remove a mapped value still can, by omitting it, which is what
// the PUT semantics are actually for.
//
// **A TYPE ON A MULTI-VALUED MEMBER IS SCIM'S IDEA, NOT THE DIRECTORY'S.** LDAP
// has `telephoneNumber` and `mobile` as separate attribute types; SCIM has one
// `phoneNumbers` array whose entries carry a `type`. So the type on the way OUT
// says which attribute the value came from, and on the way IN it decides which
// attribute it goes to — with an untyped value going to the first row for that
// member. `primary` is emitted for the first value and is NOT stored: there is
// no attribute for it, and inventing one would mean this service quietly
// disagreeing with an `ldapmodify` about which of somebody's two mail values is
// the real one.
//
// **`active` AND `externalId` ARE THIS SERVICE'S OWN ATTRIBUTES AND NOTHING
// READS THEM.** There is no standard LDAP attribute for either —
// `nsAccountLock` and `pwdAccountLockedTime` are vendor inventions and mean
// something narrower — so they are stored as `scimActive` and `scimExternalId`,
// named the way every other invention here is. Setting `active` to false
// DEACTIVATES NOBODY: no endpoint in this service reads it, no bind is refused
// because of it and no token is withheld. That is the same distinction this
// service already draws about a group (carrying a fact is not acting on one),
// it is stated on /admin/scim and in the ServiceProviderConfig's own
// documentation link, and it matters more here than for a group because
// deprovisioning is the single most common thing a SCIM client is built to do.
// A mock that silently pretended to disable an account would teach a
// provisioning client that its deprovisioning path works.
//
// **EVERY PERSON UNDER `ou=users` MAPS, INCLUDING THE ONES WITH NO `uid`.**
// `userName` is RFC 7643's one required User attribute and scimmy enforces it
// on the way OUT, while a client certificate's entry is named `cn=<CN>` and
// carries no `uid` at all — so one such entry used to make `GET /Users` a 400
// for the WHOLE directory. `toScimUser()` therefore falls back to the RDN
// value (the directory's own `usernameOfEntry()`, passed in) and then to the
// DN, exactly as `toScimGroup()` does for `displayName`. The rule is that this
// mapping is TOTAL: it is handed whatever is in the tree and it must produce a
// resource, because the alternative is one entry making every other person
// unreadable. The whole argument is at the code.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `ScimMap` takes the logger and the credential claim catalogue
// (`vc_claims.ts`'s CANONICAL_NAMES) through its constructor, and the two
// mapping tables, the schema URNs and OWN_NAMES are its static members. The
// module still exports every old name, the functions as FACADES forwarding
// to the instance the composition root builds and installs (#50, R2),
// because `scim.ts`, `admin-ui/admin.ts`, `admin-core/admin_views.ts` and
// `ldap/ldap_server.js` are not converted and require it by those names. The
// spelling check that ran at require time runs in `ScimMap.wire()`, when that
// instance is installed — or, in a process without the root, when the
// default is built at the end of loading this module.
//
// The two row functions on `addresses.formatted` (`toScim`, `fromScim`) are
// DATA in a module-scope table built before any instance exists, so they log
// through `helpers.log` directly; that is the one reach outside the class,
// and it goes when the tables do.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import vcClaims = require('../oid4vc/vc_claims');

// The logger the two row functions in USER_ATTRIBUTES use — see above.
const log = helpers.log;

// One row of either mapping table. See "THE USER MAPPING" below for what each
// member means.
interface MapRow {
  scim: string;
  ldap: string;
  kind: string;
  schema?: string;
  note?: string;
  type?: string;
  parent?: string;
  required?: boolean;
  readOnly?: boolean;
  extension?: boolean;
  toScim?(value: unknown): string;
  fromScim?(value: unknown): string;
}

// The entry object `ldap_server.js`'s entryObject() produces, as far as this
// module reads it.
interface EntryObject {
  dn?: string;
  createdAt?: string;
  modifiedAt?: string;
  attributes?: Record<string, any>;
}

// What a caller hands the two egress converters.
interface ResourceContext {
  location?: string;
  rdnName?: string;
  groups?: Array<{ id?: string; dn?: string; cn?: string }>;
  members?: Array<{ id?: string; dn?: string; cn?: string;
                    displayName?: string; value?: string; kind?: string }>;
}

// What the two ingress converters answer.
interface Converted {
  attributes: Record<string, string[]>;
  errors: string[];
}

interface ScimMapDeps {
  log: {
    debug(message: string): void;
    warn(message: string): void;
  };
  // `vc_claims.ts`'s catalogue spellings, lower-cased name -> spelling.
  canonicalNames: Record<string, string>;
}

// The schema URNs, written once. RFC 7643 sections 4.1, 4.2 and 4.3.
const USER_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:User';
const GROUP_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:Group';
const ENTERPRISE_SCHEMA =
    'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User';

// ---------------------------------------------------------------------------
// THE ATTRIBUTES THIS SERVICE INVENTED FOR SCIM.
//
// Merged into ldap_server.js's canonical-name table through learnName(), which
// is the ONE door into it, so that /admin/users and /admin/ldap/directory show
// `scimActive` rather than the `scimactive` the store lower-cases it to. Both
// are `stsApplication`-style inventions: nothing standard carries them, and
// saying so beside them is cheaper than leaving a reader to search RFC 4519 for
// an attribute that is not in it.
// ---------------------------------------------------------------------------
const OWN_NAMES = [
  'scimActive',
  'scimExternalId'
];

// ---------------------------------------------------------------------------
// THE USER MAPPING.
//
// `scim` is the SCIM attribute path as RFC 7643 spells it — dotted for a
// sub-attribute of a complex type. `ldap` is the attribute type in the
// directory. `kind` says how the two shapes differ, which is the only thing a
// converter has to branch on:
//
//   'single'   one SCIM value, one LDAP value
//   'bool'     as above, stored as the LDAP boolean strings TRUE / FALSE
//   'multi'    a SCIM array of complex values, one LDAP attribute per `type`
//   'complex'  a SCIM complex value whose sub-attributes are separate LDAP types
//   'derived'  read-only: computed rather than stored (`groups`, the meta block)
//
// `schema` names the document that defines the LDAP attribute, the way
// vc_claims.ts's rows do, so that a reader can tell an RFC 4519 type from one
// of this service's own without leaving the page.
// ---------------------------------------------------------------------------
const USER_ATTRIBUTES: MapRow[] = [
  { scim: 'userName', ldap: 'uid', kind: 'single', required: true,
    schema: 'RFC 4519 2.39',
    note: 'The SCIM uniqueness constraint. It is the RDN of an auto-created ' +
          'entry, so for anybody this service authenticated it is also their ' +
          'sign-in name — but it is NOT the SCIM id, which is the entry\'s ' +
          'entryUUID.' },
  { scim: 'externalId', ldap: 'scimExternalId', kind: 'single',
    schema: "this service's own (no standard type)",
    note: 'The provisioning client\'s own identifier for this person. Stored ' +
          'verbatim and read by nothing here.' },
  { scim: 'name.formatted', ldap: 'cn', kind: 'single',
    schema: 'RFC 4519 2.3' },
  { scim: 'name.familyName', ldap: 'sn', kind: 'single',
    schema: 'RFC 4519 2.32' },
  { scim: 'name.givenName', ldap: 'givenName', kind: 'single', schema: 'RFC ' +
      '4519 2.6' },
  { scim: 'displayName', ldap: 'displayName', kind: 'single', schema: 'RFC ' +
      '2798 2.3' },
  { scim: 'title', ldap: 'title', kind: 'single', schema: 'RFC 4519 2.38' },
  // RFC 2798 2.7 is `preferredLanguage`; `employeeType` is 2.5. Corrected
  // 2026-09-11 against the RFC text.
  { scim: 'userType', ldap: 'employeeType', kind: 'single', schema: 'RFC ' +
      '2798 2.5' },
  { scim: 'preferredLanguage', ldap: 'preferredLanguage', kind: 'single',
    schema: 'RFC 2798 2.10' },
  { scim: 'profileUrl', ldap: 'labeledURI', kind: 'single',
    schema: 'RFC 2079 2' },
  { scim: 'active', ldap: 'scimActive', kind: 'bool',
    schema: "this service's own (no standard type)",
    note: 'DEACTIVATES NOBODY. Nothing in this service reads it: no bind is ' +
          'refused, no token is withheld and no session ends. It is recorded ' +
          'and that is all.' },

  { scim: 'emails', ldap: 'mail', kind: 'multi', type: 'work',
    schema: 'RFC 4524 2.16' },
  { scim: 'phoneNumbers', ldap: 'telephoneNumber', kind: 'multi', type: 'work',
    schema: 'RFC 4519 2.35' },
  { scim: 'phoneNumbers', ldap: 'mobile', kind: 'multi', type: 'mobile',
    schema: 'RFC 4524 2.18' },

  { scim: 'addresses.streetAddress', ldap: 'street', kind: 'complex',
    parent: 'addresses', schema: 'RFC 4519 2.34' },
  { scim: 'addresses.locality', ldap: 'l', kind: 'complex',
    parent: 'addresses', schema: 'RFC 4519 2.16' },
  { scim: 'addresses.region', ldap: 'st', kind: 'complex',
    parent: 'addresses', schema: 'RFC 4519 2.33' },
  { scim: 'addresses.postalCode', ldap: 'postalCode', kind: 'complex',
    parent: 'addresses', schema: 'RFC 4519 2.24' },
  { scim: 'addresses.country', ldap: 'c', kind: 'complex',
    parent: 'addresses', schema: 'RFC 4519 2.2' },
  { scim: 'addresses.formatted', ldap: 'postalAddress', kind: 'complex',
    parent: 'addresses', schema: 'RFC 4519 2.23',
    // RFC 4517 3.3.28 separates the lines of a postal address with '$'; SCIM's
    // `formatted` is a display string with newlines. The same conversion
    // vc_claims.ts does for the OIDC `formatted` member, for the same reason:
    // two documents spelling one address differently.
    toScim: function toScim(value) {
      log.debug("Entering toScim().");
      log.debug("Leaving toScim().");
      return String(value).split('$').join('\n');
    },
    fromScim: function fromScim(value) {
      log.debug("Entering fromScim().");
      log.debug("Leaving fromScim().");
      return String(value).split('\n').join('$');
    } },

  { scim: ENTERPRISE_SCHEMA + ':employeeNumber', ldap: 'employeeNumber',
    kind: 'single', extension: true, schema: 'RFC 2798 2.6' },
  { scim: ENTERPRISE_SCHEMA + ':department', ldap: 'departmentNumber',
    kind: 'single', extension: true, schema: 'RFC 2798 2.4' },
  { scim: ENTERPRISE_SCHEMA + ':organization', ldap: 'o',
    kind: 'single', extension: true, schema: 'RFC 4519 2.19' },
  { scim: ENTERPRISE_SCHEMA + ':division', ldap: 'ou',
    kind: 'single', extension: true, schema: 'RFC 4519 2.20' },
  { scim: ENTERPRISE_SCHEMA + ':manager.value', ldap: 'manager',
    kind: 'single', extension: true, schema: 'RFC 2798 2.9',
    note: 'A DN in the directory and an id in SCIM, translated both ways by ' +
          'the SCIM handlers since the id became the entryUUID ' +
          '(2026-09-14). A value naming no entry is kept as it was sent.' },

  { scim: 'groups', ldap: '(member, uniqueMember, memberUid on the group)',
    kind: 'derived', readOnly: true,
    schema: 'RFC 4519 2.17, 2.40; RFC 2307 2.3',
    note: 'READ-ONLY, as RFC 7643 section 4.1.2 requires. Membership is a ' +
          'fact about the GROUP\'s entry, so it is changed through a Group ' +
          'resource and never through a User one. Resolved by ' +
          'ldap_server.js\'s groupsOfUser(), which is the same function the ' +
          'groups claim reads — so a token and a SCIM resource cannot ' +
          'disagree about who is in what.' },
  { scim: 'meta.created', ldap: 'createTimestamp', kind: 'derived',
    readOnly: true,
    schema: 'RFC 4512 3.4' },
  { scim: 'meta.lastModified', ldap: 'modifyTimestamp', kind: 'derived',
    readOnly: true,
    schema: 'RFC 4512 3.4' }
];

// ---------------------------------------------------------------------------
// THE GROUP MAPPING, which is smaller and has one hard part.
//
// `members` is not a mapping of one attribute: ldap_server.js resolves THREE
// (`member` and `uniqueMember` hold a DN, `memberUid` holds a bare name) and
// treating them alike is how every posixGroup membership silently disappears.
// So the read side is handed the already-resolved list that module produces and
// this file only reshapes it; the WRITE side puts every value in `member`,
// because a SCIM client sends an id, scim.ts turns each id into the DN it names
// before this file sees it (2026-09-14), and `member` is the attribute that
// holds one. A group that already used `memberUid` keeps it — see
// `fromScimGroup()`, which is the window rule again.
// ---------------------------------------------------------------------------
const GROUP_ATTRIBUTES: MapRow[] = [
  { scim: 'displayName', ldap: 'cn', kind: 'single', required: true,
    schema: 'RFC 4519 2.3' },
  { scim: 'externalId', ldap: 'scimExternalId', kind: 'single',
    schema: "this service's own (no standard type)" },
  { scim: 'members', ldap: 'member', kind: 'members',
    schema: 'RFC 4519 2.17',
    note: 'READ resolves member, uniqueMember and memberUid alike; WRITE ' +
          'puts a new value in `member`, since a SCIM member id is a DN. A ' +
          'dangling member — a DN nothing is stored at — is returned as a ' +
          'member, because the group saying so is the fact, and this ' +
          'directory does no referential integrity on purpose.' },
  { scim: 'meta.created', ldap: 'createTimestamp', kind: 'derived',
    readOnly: true,
    schema: 'RFC 4512 3.4' },
  { scim: 'meta.lastModified', ldap: 'modifyTimestamp', kind: 'derived',
    readOnly: true,
    schema: 'RFC 4512 3.4' }
];

// ---------------------------------------------------------------------------
// EVERYTHING OUTSIDE THE MAPPING'S WINDOW, CARRIED THROUGH — EXCEPT THREE
// ATTRIBUTES THAT ARE NOT REALLY ON THE ENTRY.
//
// The entry object this is given comes from ldap_server.js's entryObject(),
// which adds `entryDN` SYNTHESISED from where the entry is stored and includes
// the two operational timestamps. None of the three is a stored attribute:
// `entryDN` is the key the entry lives under (RFC 5020), and createTimestamp
// and modifyTimestamp belong to the entry rather than to whatever wrote it.
//
// Carrying them through would WRITE them, because the write replaces the whole
// attribute set — and it did, until an audit row showed `entryDN` among the
// attributes a SCIM PUT had just written. What that produces is precisely the
// failure the synthesis exists to prevent: a stored copy of the DN, which is a
// second definition of one fact and the one that goes stale the moment
// somebody renames the entry with an LDAP modrdn. The timestamps are less
// dramatic and wrong the same way — writePerson() sets both itself, so a
// carried-through copy is overwritten a line later and only ever confused an
// audit row.
//
// Dropped HERE rather than in ldap_server.js's write, because that module is
// right to accept whatever attributes it is handed: what is operational is a
// property of the read that produced them, and this is the only place that
// read and that write meet.
// ---------------------------------------------------------------------------
const NOT_STORED = ['entrydn', 'createtimestamp', 'modifytimestamp'];

class ScimMap {
  static readonly USER_SCHEMA = USER_SCHEMA;
  static readonly GROUP_SCHEMA = GROUP_SCHEMA;
  static readonly ENTERPRISE_SCHEMA = ENTERPRISE_SCHEMA;
  static readonly OWN_NAMES = OWN_NAMES;
  static readonly USER_ATTRIBUTES = USER_ATTRIBUTES;
  static readonly GROUP_ATTRIBUTES = GROUP_ATTRIBUTES;
  static readonly NOT_STORED = NOT_STORED;

  constructor(private readonly deps: ScimMapDeps) {
    deps.log.debug("Entering ScimMap.constructor().");
    deps.log.debug("Leaving ScimMap.constructor().");
  }

  // THE WORK LOADING THIS MODULE USED TO DO WITH ITS OWN INSTANCE (#50, R2),
  // run by `common/instance_slot.ts` once for whichever instance is
  // installed: the spelling check, which ran at require time as it always
  // did and now runs when the instance is installed.
  static wire(instance: ScimMap): void {
    helpers.log.debug("Entering ScimMap.wire().");
    instance.checkSpellings();
    helpers.log.debug("Leaving ScimMap.wire().");
  }

  // What the composition root passes, from the real modules.
  static defaultDeps(): ScimMapDeps {
    helpers.log.debug("Entering ScimMap.defaultDeps().");
    helpers.log.debug("Leaving ScimMap.defaultDeps().");
    return {
      log: helpers.log,
      canonicalNames: vcClaims.CANONICAL_NAMES
    };
  }

  // -------------------------------------------------------------------------
  // THE SPELLING CHECK, run once at require time (by the transitional
  // instance below).
  //
  // Every row whose LDAP attribute is one vc_claims.ts already knows is
  // compared against that catalogue's spelling. This is learnName()'s rule
  // applied one module earlier: that function will also see these names
  // (ldap_server.js merges OWN_NAMES below), but it would compare them against
  // the FIRST spelling learnt and could not say which list disagreed. Here the
  // answer is specific.
  // -------------------------------------------------------------------------
  checkSpellings(): void {
    const { log, canonicalNames } = this.deps;
    log.debug("Entering ScimMap.checkSpellings().");
    let checked = 0;
    USER_ATTRIBUTES.concat(GROUP_ATTRIBUTES)
      .forEach(function (row) {
      if (row.kind === 'derived') {
        return;
      }
      const known = canonicalNames[String(row.ldap).toLowerCase()];
      if (known === undefined) {
        return;
      }
      checked++;
      if (known !== row.ldap) {
        log.warn('scim: the SCIM mapping spells the attribute type "' +
                 String(row.ldap).toLowerCase() + '" as "' + row.ldap +
                 '" and the credential claim catalogue spells it "' + known +
                 '". They match identically either way (RFC 4512 section ' +
                 '2.5 makes attribute descriptions case-insensitive) so ' +
                 'nothing is found or missed differently; it is only the ' +
                 'spelling shown on a page, and one of the two tables is ' +
                 'wrong.');
      }
    });
    log.debug("Leaving ScimMap.checkSpellings(). " + checked +
              " row(s) had a spelling to check.");
  }

  // -------------------------------------------------------------------------
  // Reading an attribute off an entry object.
  //
  // ldap_server.js hands attributes back CANONICALLY SPELLED (`givenName`)
  // while the store holds them lower-cased, and a caller may have either in
  // hand. So every lookup here is case-insensitive, exactly as
  // applications.js's byLowerName() is and for the same reason: an index that
  // assumed either produces a resource with an empty userName rather than an
  // error.
  // -------------------------------------------------------------------------
  valuesOf(attributes: Record<string, any> | null | undefined,
           name: string): any[] {
    const { log } = this.deps;
    log.debug("Entering ScimMap.valuesOf().");
    const wanted = String(name || '').toLowerCase();
    const keys = Object.keys(attributes || {});
    for (let i = 0; i < keys.length; i++) {
      if (keys[i].toLowerCase() === wanted) {
        const value = attributes[keys[i]];
        log.debug("Leaving ScimMap.valuesOf().");
        return Array.isArray(value) ? value.slice(0) : [value];
      }
    }
    log.debug("Leaving ScimMap.valuesOf().");
    return [];
  }

  firstOf(attributes: Record<string, any> | null | undefined,
          name: string): string {
    const { log } = this.deps;
    log.debug("Entering ScimMap.firstOf().");
    const values = this.valuesOf(attributes, name);
    log.debug("Leaving ScimMap.firstOf().");
    return values.length ? String(values[0]) : '';
  }

  // Put a value at a dotted path, creating the objects on the way. Written out
  // rather than reached for from a dependency because the whole of it is this.
  //
  // A LIST of segments is accepted as well as a dotted string, for the one
  // path here that cannot be spelt as one: an extension attribute's member
  // name holds the schema URN, and that has dots of its own. See egressPath().
  private setPath(target: any, path: string | string[], value: unknown): void {
    const { log } = this.deps;
    log.debug("Entering ScimMap.setPath().");
    const parts = Array.isArray(path) ? path : String(path).split('.');
    let node = target;
    for (let i = 0; i < parts.length - 1; i++) {
      if (node[parts[i]] === undefined) {
        node[parts[i]] = {};
      }
      node = node[parts[i]];
    }
    node[parts[parts.length - 1]] = value;
    log.debug("Leaving ScimMap.setPath().");
  }

  private getPath(source: any, path: string | string[]): any {
    const { log } = this.deps;
    log.debug("Entering ScimMap.getPath().");
    const parts = Array.isArray(path) ? path : String(path).split('.');
    let node = source;
    for (let i = 0; i < parts.length; i++) {
      if (node === null || node === undefined || typeof node !== 'object') {
        log.debug("Leaving ScimMap.getPath().");
        return undefined;
      }
      node = node[parts[i]];
    }
    log.debug("Leaving ScimMap.getPath().");
    return node;
  }

  // The two halves of an extension row's path, separated at the LAST colon —
  // the attribute half never contains one. RFC 7643 section 3.3 spells such a
  // path as the schema URN, a colon, and then an ordinary (possibly dotted)
  // attribute: `urn:...:extension:enterprise:2.0:User:manager.value`.
  private extensionParts(scimPath: string): { urn: string; path: string } {
    const { log } = this.deps;
    log.debug("Entering ScimMap.extensionParts().");
    const path = String(scimPath);
    const colon = path.lastIndexOf(':');
    log.debug("Leaving ScimMap.extensionParts().");
    return { urn: path.slice(0, colon), path: path.slice(colon + 1) };
  }

  // -------------------------------------------------------------------------
  // WHERE AN EXTENSION ROW'S VALUE SITS ON THE WAY OUT, AND WHY IT IS NOT
  // WHERE IT SITS ON THE WAY IN.
  //
  // RFC 7643 section 3.3 lets a resource carry an extension attribute in
  // either of two shapes: a member named by the schema URN holding an object,
  // or a top-level member whose name is the URN, a colon and the attribute.
  // scimmy hands the ingress handler the FIRST — its coercion normalises to it
  // — and accepts either on the way out, so the two look interchangeable and
  // are not. What decides it is the FILTER MATCHER: `SCIMMY.Types.Filter`
  // parses `urn:...:User:manager.value eq "x"` into the key
  // `urn:...:User:manager` carrying a nested `value`, which is the SECOND
  // shape. A resource carrying only the object form therefore matches no
  // filter naming an enterprise attribute — and a filter naming a
  // sub-attribute of one throws, which is the same scimmy defect applyFilter()
  // in scim.ts documents.
  //
  // So egress writes the namespaced form and ingress reads the object form,
  // each being the one the side of scimmy it faces actually looks at.
  //
  // Both come back as a LIST of segments rather than a dotted string, because
  // the first segment cannot be spelt in one: the URN has dots of its own
  // (`...:enterprise:2.0:User`), so splitting the whole path on '.' — which is
  // what this file used to do — buries the value under a member named
  // `...:enterprise:2` that no client asks for and scimmy's coercion drops.
  // That is why the enterprise attributes went out of a POST and came back as
  // nothing.
  //
  // Neither is entered and left out loud, and nor is extensionParts() above:
  // they sit with setPath(), getPath() and valuesOf() — called once per
  // attribute per resource, so a pair of log lines in them is a list of a
  // thousand rows for one page of users, and the converters that call them
  // already log the conversion.
  // -------------------------------------------------------------------------
  private egressPath(row: MapRow): string[] {
    const { log } = this.deps;
    log.debug("Entering ScimMap.egressPath().");
    if (!row.extension) {
      log.debug("Leaving ScimMap.egressPath().");
      return String(row.scim).split('.');
    }
    const parts = this.extensionParts(row.scim);
    const steps = String(parts.path).split('.');
    log.debug("Leaving ScimMap.egressPath().");
    return [parts.urn + ':' + steps[0]].concat(steps.slice(1));
  }

  private ingressPath(row: MapRow): string[] {
    const { log } = this.deps;
    log.debug("Entering ScimMap.ingressPath().");
    if (!row.extension) {
      log.debug("Leaving ScimMap.ingressPath().");
      return String(row.scim).split('.');
    }
    const parts = this.extensionParts(row.scim);
    log.debug("Leaving ScimMap.ingressPath().");
    return [parts.urn].concat(String(parts.path).split('.'));
  }

  // The LDAP boolean strings. RFC 4517 section 3.3.3 spells them in capitals
  // and nothing else is a boolean, so `true` and `1` written by an ldapmodify
  // are read generously on the way out and never written on the way in.
  private boolFromLdap(text: unknown): boolean {
    const { log } = this.deps;
    log.debug("Entering ScimMap.boolFromLdap().");
    const value = String(text || '').trim().toLowerCase();
    log.debug("Leaving ScimMap.boolFromLdap().");
    return value === 'true' || value === '1' || value === 'yes';
  }

  // A generalized time (RFC 4517 3.3.13, `20260821T...Z` as this service
  // writes it) as the ISO 8601 instant SCIM's `meta` wants. A value this
  // service did not write is passed through rather than guessed at:
  // `meta.created` showing the raw directory value is a reader's clue about
  // where it came from, and a fabricated date is not.
  private isoFromGeneralizedTime(text: unknown): string | undefined {
    const { log } = this.deps;
    log.debug("Entering ScimMap.isoFromGeneralizedTime().");
    const digits = String(text || '').replace(/[^0-9]/g, '');
    if (digits.length < 14) {
      log.debug("Leaving ScimMap.isoFromGeneralizedTime().");
      return String(text || '') || undefined;
    }
    const iso = digits.slice(0, 4) + '-' + digits.slice(4, 6) + '-' +
                digits.slice(6, 8) +
                'T' + digits.slice(8, 10) + ':' + digits.slice(10, 12) + ':' +
                digits.slice(12, 14) + 'Z';
    log.debug("Leaving ScimMap.isoFromGeneralizedTime().");
    return Number.isNaN(new Date(iso).getTime()) ? String(text) : iso;
  }

  private carryThrough(existing: Record<string, any> | null | undefined):
      Record<string, string[]> {
    const { log } = this.deps;
    log.debug("Entering ScimMap.carryThrough().");
    const out: Record<string, string[]> = {};
    Object.keys(existing || {}).forEach(function (name) {
      if (NOT_STORED.indexOf(String(name).toLowerCase()) >= 0) {
        return;
      }
      const value = existing[name];
      out[name] = Array.isArray(value) ? value.slice(0) : [String(value)];
    });
    log.debug("Leaving ScimMap.carryThrough().");
    return out;
  }

  // -------------------------------------------------------------------------
  // AN ENTRY AS A SCIM USER.
  //
  // `context` carries what this file cannot work out on its own — the groups
  // the person is in, which needs the directory — and the location prefix for
  // `meta`. Everything else is read off the entry.
  //
  // THE RESULT IS PADDED and that is a route around a defect rather than a
  // style. `SCIMMY.Types.Filter#match()` in scimmy 1.3.5 does
  // `Object.entries(actual)` on the value of a nested attribute without
  // checking it is there, so a filter naming `emails.value` throws — not "does
  // not match", THROWS — for every resource that has no `emails` member at
  // all. That is the ordinary case: a filter like `emails.value co
  // "@example.com"` against a directory where one person has no mail. So
  // every multi-valued and complex member is present, empty where there is
  // nothing, and `prune()` below takes the empties back off before the
  // resource is returned to a client. The two steps are separate on purpose —
  // the padding is for the matcher and the pruning is for the wire, and
  // folding them together is how one of them quietly stops happening.
  // -------------------------------------------------------------------------
  // The id of a resource: the entry's `entryUUID`, and its DN where it has
  // none. Read off the entry the caller already holds, so this module still
  // asks the directory nothing.
  private scimIdOf(entry: EntryObject | null | undefined): string {
    const { log } = this.deps;
    log.debug("Entering ScimMap.scimIdOf().");
    const uuid = this.firstOf((entry && entry.attributes) || {}, 'entryUUID');
    log.debug("Leaving ScimMap.scimIdOf().");
    return uuid ? String(uuid) : String((entry && entry.dn) || '');
  }

  toScimUser(entry: EntryObject, context?: ResourceContext | null): any {
    const { log } = this.deps;
    log.debug("Entering ScimMap.toScimUser(). dn=" + (entry && entry.dn));
    const self = this;
    const ctx = context || {};
    const attributes = (entry && entry.attributes) || {};
    const resource: any = {
      schemas: [USER_SCHEMA],
      // THE ENTRY'S `entryUUID` (2026-09-14), which a rename does not change —
      // RFC 7643 section 3.1's id "MUST NOT be reassigned", and the DN it was
      // until then was reassigned by every rename. An entry without one (a
      // process with no directory behind it) keeps the DN.
      id: this.scimIdOf(entry),
      // Padded for the matcher; pruned before it goes out.
      name: {},
      emails: [],
      phoneNumbers: [],
      addresses: [],
      groups: [],
      meta: {
        resourceType: 'User',
        created: this.isoFromGeneralizedTime(
          this.firstOf(attributes, 'createTimestamp') || entry.createdAt),
        lastModified: this.isoFromGeneralizedTime(
          this.firstOf(attributes, 'modifyTimestamp') || entry.modifiedAt),
        location: (ctx.location || '') +
          encodeURIComponent(this.scimIdOf(entry))
      }
    };

    // The extension members this mapping writes into, padded like the members
    // above and for the same reason: `manager.value` is a sub-attribute, so a
    // filter naming it dives into a value that has to be there. Built from the
    // catalogue rather than written out, so an extension row cannot be added
    // without its padding, and every parent on the way is created because the
    // matcher walks the whole path and not just the leaf.
    USER_ATTRIBUTES.forEach(function (row) {
      if (!row.extension) {
        return;
      }
      const steps = self.egressPath(row);
      let node = resource;
      for (let i = 0; i < steps.length - 1; i++) {
        if (node[steps[i]] === undefined) {
          node[steps[i]] = {};
        }
        node = node[steps[i]];
      }
    });

    const address: Record<string, any> = {};
    USER_ATTRIBUTES.forEach(function (row) {
      if (row.kind === 'derived') {
        return;
      }
      const values = self.valuesOf(attributes, row.ldap);
      if (!values.length) {
        return;
      }
      // An extension row is written as its namespaced member rather than at a
      // dotted path off the resource. See egressPath().
      const path = self.egressPath(row);
      if (row.kind === 'single') {
        self.setPath(resource, path,
                     row.toScim ? row.toScim(values[0]) : String(values[0]));
        return;
      }
      if (row.kind === 'bool') {
        self.setPath(resource, path, self.boolFromLdap(values[0]));
        return;
      }
      if (row.kind === 'complex') {
        address[row.scim.split('.').pop()] = row.toScim ?
          row.toScim(values[0]) : String(values[0]);
        return;
      }
      // 'multi'. One SCIM entry per LDAP value, carrying the type this row
      // says — which is what tells a client that `mobile` and
      // `telephoneNumber` are two kinds of one SCIM member rather than one
      // attribute listed twice.
      values.forEach(function (value) {
        resource[row.scim].push({ value: String(value), type: row.type });
      });
    });

    // ONE MEMBER IS NOT OPTIONAL, AND AN ENTRY THAT COULD NOT SUPPLY IT USED TO
    // TAKE THE WHOLE LIST DOWN WITH IT.
    //
    // `userName` is the only REQUIRED attribute in RFC 7643's User schema, and
    // scimmy enforces it on the way OUT as well as on the way in: a resource
    // without one throws `Required attribute 'userName' is missing` out of its
    // coercion. The egress handler maps every person in `ou=users` in one
    // pass, so ONE entry that produced no `userName` answered a plain
    // `GET /Users` with a 400 naming an attribute and naming no entry — every
    // other person in the directory unreadable over SCIM because of one of
    // them, and the message pointing at the client's request, which had
    // nothing wrong with it.
    //
    // An entry with no `uid` is ordinary here rather than corrupt, which is why
    // this is a mapping decision and not a repair. `certificatePlan()` names a
    // client certificate's entry `cn=<CN>,ou=users` and deliberately writes no
    // `uid` — the certificate is the identity, and `namePlan()`'s fold is what
    // later adds one if that person also signs in by name — so a single mutual
    // TLS connection presenting a client certificate was enough to break every
    // SCIM list until somebody deleted the entry. An `ldapadd` can produce the
    // same thing at will: this directory enforces no schema, on purpose.
    //
    // The fallback is the RDN VALUE, and it is the DIRECTORY'S rule rather
    // than a second one invented here: `usernameOfEntry()` is what
    // `existingUserEntry()` matches a typed name against, so the `userName`
    // SCIM reports is the name a create of that person would collide with.
    // `entry.dn` is the last resort — exactly as `toScimGroup()` falls back to
    // it for `displayName`, and for the same reason: whatever is under
    // `ou=users`, this function has to produce a resource rather than an
    // exception.
    if (!String(resource.userName || '').trim()) {
      resource.userName = String(ctx.rdnName || '').trim() || entry.dn;
      log.debug("ScimMap.toScimUser(). The entry carries no uid, so its " +
                "userName is the RDN value: " + resource.userName);
    }

    // `primary` marks the FIRST value of each multi-valued member and is not
    // stored anywhere — see the header. Set after the loop rather than inside
    // it because two rows feed `phoneNumbers` and the first value of the
    // member is not the first value of either row.
    ['emails', 'phoneNumbers'].forEach(function (member) {
      if (resource[member].length) {
        resource[member][0].primary = true;
      }
    });

    if (Object.keys(address).length) {
      address.type = 'work';
      resource.addresses.push(address);
    }

    // The groups this person is in, resolved by the caller. `type` is `direct`
    // for every one of them because nothing in this service expands a nested
    // group — the console says the same thing about the same data, and
    // claiming `indirect` membership we never computed would be a lie about a
    // feature that is not here.
    (ctx.groups || []).forEach(function (group) {
      resource.groups.push({
        value: group.id || group.dn,
        display: group.cn || group.dn,
        type: 'direct'
      });
    });

    log.debug("Leaving ScimMap.toScimUser(). " +
              Object.keys(resource).length + " member(s).");
    return resource;
  }

  // -------------------------------------------------------------------------
  // A SCIM USER AS ATTRIBUTES, over the attributes the entry already has.
  //
  // `existing` is the entry's current attribute object, or {} for a create.
  // What comes back is the WHOLE attribute set to write, because
  // ldap_server.js's write replaces rather than merges (the reason is written
  // there): so everything outside the mapping's window has to be carried
  // through here, or a SCIM update would silently delete the credential
  // claims and the authentication history.
  //
  // Returns `{ attributes, errors }` rather than throwing, the same contract
  // vc_claims.setSelection() has: the caller is a request handler that has to
  // turn a refusal into a SCIM error with the right `scimType`, and an
  // exception thrown through scimmy's ingress handler comes back as a 404 (see
  // the note in scim.ts).
  // -------------------------------------------------------------------------
  fromScimUser(resource: any,
               existing?: Record<string, any> | null): Converted {
    const { log } = this.deps;
    log.debug("Entering ScimMap.fromScimUser().");
    const self = this;
    const errors: string[] = [];
    const out = this.carryThrough(existing);

    // Then take every mapped attribute back off, so that an omitted SCIM
    // member REMOVES the value rather than leaving the old one behind. That is
    // what makes this a PUT and not a PATCH, and doing it as a separate pass
    // is what makes it true for the rows the resource does not mention at all.
    USER_ATTRIBUTES.forEach(function (row) {
      if (row.kind === 'derived' || row.readOnly) {
        return;
      }
      Object.keys(out).forEach(function (name) {
        if (name.toLowerCase() === String(row.ldap).toLowerCase()) {
          delete out[name];
        }
      });
    });

    const address = (Array.isArray(resource.addresses) &&
                     resource.addresses.length)
      ? resource.addresses[0] : {};

    USER_ATTRIBUTES.forEach(function (row) {
      if (row.kind === 'derived' || row.readOnly) {
        return;
      }
      if (row.kind === 'single' || row.kind === 'bool') {
        // Read an extension row out of the object at its schema URN, which is
        // the shape scimmy's coercion hands this handler and NOT the one the
        // egress side writes. See egressPath().
        const value = self.getPath(resource, self.ingressPath(row));
        if (value === undefined || value === null || String(value) === '') {
          return;
        }
        out[row.ldap] = [row.kind === 'bool'
          ? (value === true || String(value).toLowerCase() === 'true' ?
             'TRUE' : 'FALSE')
          : (row.fromScim ? row.fromScim(value) : String(value))];
        return;
      }
      if (row.kind === 'complex') {
        const value = address[row.scim.split('.').pop()];
        if (value === undefined || value === null || String(value) === '') {
          return;
        }
        out[row.ldap] = [row.fromScim ? row.fromScim(value) : String(value)];
        return;
      }
      // 'multi'. Every value whose `type` names this row, plus — for the row
      // that is the member's DEFAULT — every value carrying no type at all.
      // Without that second half a client sending `{"value": "a@b.example"}`
      // with no type, which is legal and common, would have its email accepted
      // and stored nowhere.
      const values = (Array.isArray(resource[row.scim]) ?
        resource[row.scim] : [])
        .filter(function (item) {
          const type = String((item && item.type) || '').toLowerCase();
          return type === String(row.type).toLowerCase() ||
                 (type === '' && self.isDefaultRowFor(row.scim, row));
        })
        .map(function (item) {
          return String(item && item.value === undefined ? '' : item.value);
        })
        .filter(function (value) {
          return value !== '';
        });
      if (values.length) {
        out[row.ldap] = values;
      }
    });

    const userName = String(this.getPath(resource, 'userName') || '').trim();
    if (!userName) {
      errors.push('userName is required (RFC 7643 section 4.1.1) and was ' +
                  'not sent.');
    }

    log.debug("Leaving ScimMap.fromScimUser(). " + Object.keys(out).length +
              " attribute(s), " + errors.length + " error(s).");
    return { attributes: out, errors: errors };
  }

  // Which row of a multi-valued member takes the values that carry no type.
  // The FIRST row for that member in the catalogue, which is why the
  // catalogue's order is not arbitrary: an untyped phone number is a
  // `telephoneNumber` because that row is listed before `mobile`.
  private isDefaultRowFor(member: string, row: MapRow): boolean {
    const { log } = this.deps;
    log.debug("Entering ScimMap.isDefaultRowFor().");
    const rows = USER_ATTRIBUTES.filter(function (candidate) {
      return candidate.kind === 'multi' && candidate.scim === member;
    });
    log.debug("Leaving ScimMap.isDefaultRowFor().");
    return rows.length > 0 && rows[0].ldap === row.ldap;
  }

  // -------------------------------------------------------------------------
  // A GROUP ENTRY AS A SCIM GROUP.
  //
  // `members` arrives already resolved — the array ldap_server.js's
  // membersOf() builds, whose items carry `value`, `dn`, `present` and
  // `kind`. This file reshapes it and decides nothing about it, for the reason
  // group_claims.js gives about the same data: that module owns WHAT A GROUP
  // IS and this owns what SCIM says about one.
  // -------------------------------------------------------------------------
  toScimGroup(entry: EntryObject, context?: ResourceContext | null): any {
    const { log } = this.deps;
    log.debug("Entering ScimMap.toScimGroup(). dn=" + (entry && entry.dn));
    const ctx = context || {};
    const attributes = (entry && entry.attributes) || {};
    const resource: any = {
      schemas: [GROUP_SCHEMA],
      id: this.scimIdOf(entry),
      displayName: this.firstOf(attributes, 'cn') || entry.dn,
      members: [],
      meta: {
        resourceType: 'Group',
        created: this.isoFromGeneralizedTime(
          this.firstOf(attributes, 'createTimestamp') || entry.createdAt),
        lastModified: this.isoFromGeneralizedTime(
          this.firstOf(attributes, 'modifyTimestamp') || entry.modifiedAt),
        location: (ctx.location || '') +
          encodeURIComponent(this.scimIdOf(entry))
      }
    };
    const externalId = this.firstOf(attributes, 'scimExternalId');
    if (externalId) {
      resource.externalId = externalId;
    }

    (ctx.members || []).forEach(function (member) {
      resource.members.push({
        // The member's SCIM id (added by scim.ts since 2026-09-14), or its DN
        // where there is none — never the raw value, so that a `memberUid`
        // holding `alice` comes back as the same id the User resource has.
        // Sending the bare name would be SCIM saying two different things
        // about one person depending on which attribute their membership
        // happened to be written in.
        value: member.id || member.dn,
        display: member.cn || member.displayName || member.value,
        // RFC 7643 section 4.2 defines `type` on a member as User or Group. A
        // dangling member is neither and is reported as a User rather than
        // omitted: the group listing it IS the fact, this directory does no
        // referential integrity on purpose, and dropping the row would hide
        // the one thing /admin/groups exists to show.
        type: member.kind === 'group' ? 'Group' : 'User'
      });
    });

    log.debug("Leaving ScimMap.toScimGroup(). " + resource.members.length +
              " member(s).");
    return resource;
  }

  // A SCIM group as attributes, over what the entry already has — the same
  // window rule `fromScimUser()` follows, and here it does one extra thing
  // worth knowing about: a group whose membership was written as
  // `uniqueMember` or `memberUid` has THOSE attributes cleared as well,
  // because SCIM's `members` is the whole membership and leaving half of it in
  // a second attribute would make a client that removed everybody find the
  // group still populated.
  fromScimGroup(resource: any,
                existing?: Record<string, any> | null): Converted {
    const { log } = this.deps;
    log.debug("Entering ScimMap.fromScimGroup().");
    const errors: string[] = [];
    const out = this.carryThrough(existing);

    ['cn', 'scimExternalId', 'member', 'uniqueMember', 'memberUid'].forEach(
        function (name) {
      Object.keys(out).forEach(function (key) {
        if (key.toLowerCase() === name.toLowerCase()) {
          delete out[key];
        }
      });
    });

    const displayName = String(resource.displayName || '').trim();
    if (!displayName) {
      errors.push('displayName is required (RFC 7643 section 4.2) and was ' +
                  'not sent.');
    } else {
      out.cn = [displayName];
    }
    if (resource.externalId) {
      out.scimExternalId = [String(resource.externalId)];
    }
    const members = (Array.isArray(resource.members) ? resource.members : [])
      .map(function (item) {
        return String((item && item.value) || '').trim();
      })
      .filter(function (value) {
        return value !== '';
      });
    if (members.length) {
      out.member = members;
    }
    // An objectClass so that the entry is a group by BOTH of ldap_server.js's
    // rules rather than only by where it sits — a client that moves it out of
    // ou=groups should not stop it being one, and `groupOfNames` is what
    // `member` belongs to (RFC 4519 section 3.5).
    if (!Object.keys(out)
               .some(function (key) {
                 return key.toLowerCase() === 'objectclass';
               })) {
      out.objectClass = ['top', 'groupOfNames'];
    }

    log.debug("Leaving ScimMap.fromScimGroup(). " + Object.keys(out).length +
              " attribute(s), " + errors.length + " error(s).");
    return { attributes: out, errors: errors };
  }

  // -------------------------------------------------------------------------
  // Take the padding back off.
  //
  // An empty array or an empty object in a SCIM response is not wrong, but it
  // is noise a client has to read past — and `"name": {}` in particular reads
  // as "we know their name and it is nothing". The padding exists for scimmy's
  // filter matcher (see toScimUser()) and this is where it stops being useful.
  // -------------------------------------------------------------------------
  prune(resource: Record<string, any>): Record<string, any> {
    const { log } = this.deps;
    log.debug("Entering ScimMap.prune().");
    const out: Record<string, any> = {};
    Object.keys(resource).forEach((key) => {
      const value = resource[key];
      if (Array.isArray(value)) {
        if (value.length) {
          out[key] = value;
        }
        return;
      }
      if (value && typeof value === 'object') {
        const inner = this.prune(value);
        if (Object.keys(inner).length) {
          out[key] = inner;
        }
        return;
      }
      if (value !== undefined && value !== null && value !== '') {
        out[key] = value;
      }
    });
    log.debug("Leaving ScimMap.prune().");
    return out;
  }

  // -------------------------------------------------------------------------
  // ONE ROW OF EITHER TABLE, AS IT IS PUBLISHED (2026-09-06).
  //
  // **IT IS HERE BECAUSE IT WAS IN TWO PLACES AND THEY HAD ALREADY DRIFTED.**
  // `/admin/scim` and `GET /admin-api/scim` render the mapping from
  // `admin-ui/admin.ts`'s own projection; `GET /scim` renders it from
  // `scim.ts`'s. The two carried different sets of members — one had
  // `required`, `schema` and `note`, the other did not — so the same table
  // published at two endpoints of one service described itself differently
  // depending on which one you asked. Nothing failed, because nothing read
  // either of them: they were documentation, and documentation that disagrees
  // with itself is the shape of defect this repository's "one copy of each
  // fact" rule exists for.
  //
  // What turned it up was a reader:
  // `tests/vendored/sts_directory_bulk_load_scim.js` BUILDS every resource it
  // sends out of this table rather than out of a copy, and `type`, `parent`
  // and `extension` are what make that possible — two rows both map to
  // `phoneNumbers` and only `type` tells `telephoneNumber` from `mobile`, five
  // rows are members of one `addresses` entry and only `parent` says so, and
  // an extension member goes under a URN rather than at the top level. Adding
  // those three to one of the two projections would have left the other still
  // unusable, and a reader unable to say which endpoint was right.
  //
  // So the projection is HERE, beside the table it projects, and both
  // endpoints call it. This module is a LIBRARY — rule 3d-iii,
  // `scim/CLAUDE.md` — so it registers nothing and either caller may require
  // it.
  describeRow(row: MapRow) {
    const { log } = this.deps;
    log.debug("Entering ScimMap.describeRow().");
    log.debug("Leaving ScimMap.describeRow().");
    return { scim: row.scim, ldap: row.ldap, kind: row.kind,
             // `type` and `parent` are null rather than absent where a row has
             // none, so that a client can tell "this mapping has no type" from
             // "this document does not report types" — which is exactly the
             // question the job above had to answer about the version of this
             // service it is running against.
             type: row.type || null, parent: row.parent || null,
             extension: !!row.extension, readOnly: !!row.readOnly,
             required: !!row.required,
             schema: row.schema || '', note: row.note || '' };
  }

  describeMapping() {
    const { log } = this.deps;
    log.debug("Entering ScimMap.describeMapping().");
    log.debug("Leaving ScimMap.describeMapping().");
    return {
      user: USER_ATTRIBUTES.map((row) => this.describeRow(row)),
      group: GROUP_ATTRIBUTES.map((row) => this.describeRow(row))
    };
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds no
// instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` when this module loads (see
// `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<ScimMap>(
  'scim/scim_map',
  () => new ScimMap(ScimMap.defaultDeps()),
  ScimMap.wire,
  helpers.log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  ScimMap: ScimMap,
  installInstance: (instance: ScimMap): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  USER_SCHEMA: ScimMap.USER_SCHEMA,
  describeRow: slot.forward('describeRow'),
  describeMapping: slot.forward('describeMapping'),
  GROUP_SCHEMA: ScimMap.GROUP_SCHEMA,
  ENTERPRISE_SCHEMA: ScimMap.ENTERPRISE_SCHEMA,
  USER_ATTRIBUTES: ScimMap.USER_ATTRIBUTES,
  GROUP_ATTRIBUTES: ScimMap.GROUP_ATTRIBUTES,
  OWN_NAMES: ScimMap.OWN_NAMES,
  toScimUser: slot.forward('toScimUser'),
  fromScimUser: slot.forward('fromScimUser'),
  toScimGroup: slot.forward('toScimGroup'),
  fromScimGroup: slot.forward('fromScimGroup'),
  prune: slot.forward('prune'),
  valuesOf: slot.forward('valuesOf'),
  firstOf: slot.forward('firstOf')
};
