// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
// File: sourced_attributes.ts
// ---------------------------------------------------------------------------
// THE DIRECTORY ATTRIBUTES NO OUTSIDE SOURCE MAY WRITE (#94, 2026-09-28).
//
// A value that arrives from outside this service — a federation partner's
// attribute through `fedAttributeMap`, and (#94 part C) a column of an
// operator's database — is written onto a person's directory entry. Until
// #94 a relationship's map named ANY target: `groups=memberOf` let a partner
// put a person in the console's Admin Write group, `x=pwdAccountLockedTime`
// let it disable them, and `x=stsTotpCredential` let it replace their second
// factor. Nothing checked, because the directory has no schema and the map
// was only ever meant for a partner's own names.
//
// **REFUSED BY RULE, NOT BY LIST.** What this service keeps on an entry is
// named by prefix — `sts*` (credentials, flags, provenance), `app*`
// (application entries), `fed*`/`federation*` (links and provenance), `pwd*`
// (the password policy's account state) — so a credential attribute added
// next year is refused without anybody remembering this file. Beside the
// prefixes, a short list of names that are the entry's identity, its
// structure or its authorization: `uid` (the entry's name), `objectClass`,
// `memberOf` (a group is joined through the group, never written on the
// member), `userPassword`, and the operational attributes.
//
// **`mail` IS NOT HERE.** A partner's `email` is mapped onto `mail` by the
// default table and marked verified unless the partner says otherwise — the
// ordinary shape of federation, and `federation/CLAUDE.md` argues it. An
// attribute source (#94 part C) refuses `mail` itself: its verification and
// its change notice belong to the mail flow.
//
// A leaf: it requires only the logger, so `federation.js`, `federation_map`
// and `ldap_server.js` can all ask it without a cycle.
// ---------------------------------------------------------------------------

import helpers = require('./helpers');

const log = helpers.log;

// The prefixes of the attributes this service keeps, lower-cased.
const PREFIXES = ['sts', 'app', 'fed', 'federation', 'pwd', 'hoba'];

// Names refused outright, lower-cased: identity, structure, authorization and
// the operational attributes.
const NAMES = ['uid', 'objectclass', 'memberof', 'ismemberof', 'userpassword',
  'entryuuid', 'entrydn', 'createtimestamp', 'modifytimestamp',
  'creatorsname', 'modifiersname', 'subschemasubentry', 'hassubordinates',
  'structuralobjectclass'];

/**
 * The directory attributes no outside source — a federation partner, an
 * attribute source — may write onto a person's entry.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
export = class SourcedAttributes {
  /**
   * Says why an outside source may not write an attribute, or '' when it
   * may.
   *
   * @param name - the directory attribute
   * @returns the reason, or '' for an attribute a source may write
   */
  static refusal(name: unknown): string {
    log.debug("Entering SourcedAttributes.refusal().");
    const key = String(name == null ? '' : name).trim().toLowerCase();
    if (!key) {
      log.debug("Leaving SourcedAttributes.refusal(). No name.");
      return 'no attribute is named';
    }
    if (NAMES.indexOf(key) >= 0) {
      log.debug("Leaving SourcedAttributes.refusal(). A named attribute.");
      return '"' + String(name) + '" is the entry\'s own identity, ' +
             'structure or authorization, which no outside source writes';
    }
    const prefix = PREFIXES.filter(function (one) {
      return key.indexOf(one) === 0;
    })[0];
    if (prefix) {
      log.debug("Leaving SourcedAttributes.refusal(). A kept prefix.");
      return '"' + String(name) + '" is one of the attributes this service ' +
             'keeps (' + prefix + '*): credentials, account state, links ' +
             'and provenance, which no outside source writes';
    }
    log.debug("Leaving SourcedAttributes.refusal(). Writable.");
    return '';
  }

  /**
   * The rule, for a page or a reply that states it.
   *
   * @returns `{ prefixes, names }`, lower-cased
   */
  static rule(): { prefixes: string[]; names: string[] } {
    log.debug("Entering SourcedAttributes.rule().");
    log.debug("Leaving SourcedAttributes.rule().");
    return { prefixes: PREFIXES.slice(), names: NAMES.slice() };
  }
};
