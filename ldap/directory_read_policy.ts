'use strict';
//
// File: ldap/directory_read_policy.ts
//
// ===========================================================================
// WHO MAY READ WHAT OVER THE DIRECTORY'S OWN SOCKET (2026-09-23, #106).
//
// Until this date a connection that had bound as ANYBODY could search and
// compare every entry in the realm its base named and read every attribute on
// it that was not a credential — every person's mail, telephone number and
// group memberships, every application's redirect URIs, every federation's
// signing certificate. Product mode required the bind and withheld the
// credentials (`ldap_server.js`, *THE DIRECTORY'S READ AND BIND SECURITY*);
// what the bound identity could then SEE was not decided by anybody.
//
// **THIS IS THE RULE TABLE, AND ONLY THE RULE TABLE.** A pure decision: it is
// handed a READER (who is asking, classified once per operation by
// `ldap_server.js`'s `readerOf()`) and an ENTRY (what it is, classified by
// `readKindOf()` there, because only that file knows the containers), and it
// answers whether the entry is visible and which of its attributes are
// readable. It reads no store, no setting and no clock — everything it needs
// arrives in its arguments — so it can be asked once per entry at fifty
// thousand entries without a round trip, and a test can drive every row of it
// with plain objects.
//
// **A NATIVE TABLE, NOT AN XACML DECISION PER ENTRY** (the owner's decision 3
// on #106). A subtree search visits every entry under its base; a PDP call for
// each is the access gate's walk history in `ldap/CLAUDE.md` over again. The
// write half (`directoryWriteRefusal()`) is a native rule for the same reason.
//
// THE ROWS — `ldap/CLAUDE.md`, *WHO MAY READ THIS DIRECTORY OVER THE SOCKET*,
// argues each:
//
//   * UNRESTRICTED (development, `mode.authorizesDirectoryReads()` false):
//     every entry, every attribute. A bound DN proves nothing there.
//   * AN ADMINISTRATOR (Admin Read or Admin Write; the default realm's roster
//     for every realm, a realm's own for that realm, never the open window):
//     every entry in scope, every attribute.
//   * ANYBODY BOUND reads THEIR OWN ENTRY whole — `memberOf` included, since
//     it describes them.
//   * A PERSON reading ANOTHER PERSON sees the attributes
//     `ldap.directoryReadableAttributes` names — EMPTY by default, and an
//     empty list means the other person is not there at all (self-only).
//   * A PERSON reading a GROUP sees it only if they are a direct member of it,
//     and then `objectClass`, `cn` and `description`; its member list too when
//     `ldap.groupMembersReadable` is on.
//   * CONTAINERS (the realm's base and every `ou=`/`dc=`/`o=` entry that is
//     not a person or a group) are visible to anybody bound, with their naming
//     attributes only, so a subtree search from the base does not fail AT the
//     base.
//   * A CRL DISTRIBUTION POINT is public, to anybody, anonymous included —
//     the base read `isCrlDistributionEntry()` exempts from the bind.
//   * EVERYTHING ELSE — applications, federations, policies, roles, PEPs,
//     trust anchors, password policies, SPIFFE registrations and agents — is
//     invisible to anybody who is not an administrator.
//   * AN OUTSIDER — bound, but not as an entry of the realm being read, and
//     not holding the default realm's roster — sees the containers and
//     nothing else. A realm's own administrator is an outsider in every other
//     realm.
//
// **INVISIBLE MEANS ABSENT, NOT REFUSED.** An entry this table hides is
// skipped by a search before its filter is evaluated, and a base search or a
// compare naming it is answered noSuchObject exactly as a missing entry is —
// so a reader cannot tell "there is nothing there" from "you may not see it".
// An attribute this table hides is absent from the entry AND Undefined to the
// filter, or `(telephoneNumber=555*)` would read it one digit at a time.
//
// **CREDENTIALS ARE NOT THIS TABLE'S.** `SECRET_ATTRIBUTES` in
// `ldap_server.js` is withheld from every reader, administrator included, by
// `withheldFromReaders()` — a separate question asked after this one, so a
// row here that answered "all" can never hand out a password hash.
// ===========================================================================

// Who is asking. Built once per operation by `ldap_server.js`'s `readerOf()`.
//   unrestricted   development: nothing is decided
//   anonymous      no bind (product lets it read the root DSE and a CRL)
//   administrator  Admin Read or Admin Write over the realm being read
//   person         bound as an entry of the realm being read
//   outsider       bound, but as nobody in the realm being read
type ReaderKind = 'unrestricted' | 'anonymous' | 'administrator' | 'person' |
                  'outsider';

interface DirectoryReader {
  kind: ReaderKind;
  // The bound DN, NORMALISED, or '' for nobody.
  dn: string;
  // `ldap.directoryReadableAttributes`, lower-cased.
  readableOfOthers?: string[];
  // `ldap.groupMembersReadable`.
  groupMembersReadable?: boolean;
}

// What an entry is, for this table. Decided by placement and class in
// `ldap_server.js`'s `readKindOf()`.
type EntryKind = 'container' | 'person' | 'group' | 'public' | 'other';

interface DirectoryEntryFacts {
  kind: EntryKind;
  // The entry's DN, NORMALISED.
  dn: string;
  // For a group: every member it lists, as NORMALISED DNs.
  members?: string[];
}

// Which attributes of one entry one reader may read. `all` or a list of
// lower-cased names.
interface AttributeRule {
  all: boolean;
  names: string[];
}

// The naming attributes of a container: what a client needs to walk the tree
// and nothing it could learn anything else from.
const CONTAINER_ATTRIBUTES = ['objectclass', 'ou', 'dc', 'o'];

// A group, to a member of it: that it is a group, what it is called, and what
// it says it is for.
const GROUP_ATTRIBUTES = ['objectclass', 'cn', 'description'];

// The three attributes that carry membership (`ldap_server.js`'s
// MEMBER_ATTRIBUTES), readable on a group only with
// `ldap.groupMembersReadable`.
const GROUP_MEMBER_ATTRIBUTES = ['member', 'uniquemember', 'memberuid'];

// `entryDN` is the DN of an entry the reader can already see, so it is never
// withheld from a visible entry — and the filter needs it for `(entryDN=...)`.
const ALWAYS_WITH_THE_ENTRY = ['entrydn'];

export = class DirectoryReadPolicy {
  static readonly CONTAINER_ATTRIBUTES = CONTAINER_ATTRIBUTES;
  static readonly GROUP_ATTRIBUTES = GROUP_ATTRIBUTES;
  static readonly GROUP_MEMBER_ATTRIBUTES = GROUP_MEMBER_ATTRIBUTES;

  // Does this reader see this entry at all? Asked once per entry in scope of a
  // search, before its filter, so no Entering/Leaving pair — a subtree search
  // of a large directory would drown the log in them (the hot-path exception
  // the code style allows, stated here as it requires).
  static visible(reader: DirectoryReader, entry: DirectoryEntryFacts)
      : boolean {
    if (reader.kind === 'unrestricted' || reader.kind === 'administrator') {
      return true;
    }
    if (entry.kind === 'public') {
      return true;
    }
    if (reader.kind === 'anonymous') {
      return false;
    }
    if (reader.dn && reader.dn === entry.dn) {
      return true;
    }
    if (entry.kind === 'container') {
      return true;
    }
    if (reader.kind !== 'person') {
      return false;
    }
    if (entry.kind === 'person') {
      return (reader.readableOfOthers || []).length > 0;
    }
    if (entry.kind === 'group') {
      return (entry.members || []).indexOf(reader.dn) !== -1;
    }
    return false;
  }

  // Which attributes of a VISIBLE entry this reader may read. Asked once per
  // entry, for the hot-path reason above; the answer is then asked per
  // attribute through `readable()`.
  static attributeRule(reader: DirectoryReader, entry: DirectoryEntryFacts)
      : AttributeRule {
    if (reader.kind === 'unrestricted' || reader.kind === 'administrator' ||
        entry.kind === 'public' || (reader.dn && reader.dn === entry.dn)) {
      return { all: true, names: [] };
    }
    if (entry.kind === 'container') {
      return { all: false,
               names: CONTAINER_ATTRIBUTES.concat(ALWAYS_WITH_THE_ENTRY) };
    }
    if (entry.kind === 'person') {
      return { all: false,
               names: (reader.readableOfOthers || [])
                 .concat(ALWAYS_WITH_THE_ENTRY) };
    }
    if (entry.kind === 'group') {
      return { all: false,
               names: GROUP_ATTRIBUTES
                 .concat(reader.groupMembersReadable
                   ? GROUP_MEMBER_ATTRIBUTES : [])
                 .concat(ALWAYS_WITH_THE_ENTRY) };
    }
    return { all: false, names: [] };
  }

  // Is one attribute readable under a rule? Case-insensitive, and an RFC 4522
  // `;binary` option is the attribute it options. Asked per attribute per
  // entry: the hot-path exception above.
  static readable(rule: AttributeRule, name: string): boolean {
    if (rule.all) {
      return true;
    }
    const lower = String(name || '').toLowerCase();
    const type = lower.replace(/;binary$/, '');
    return rule.names.indexOf(type) !== -1;
  }
};
