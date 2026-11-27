// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: create_forms.ts
// ---------------------------------------------------------------------------
// WHAT EACH DIRECTORY OBJECT'S CREATE TAKES, AND WHICH OF IT IS REQUIRED
// (#1132).
//
// Every object under the console's Directory section has a create page of
// its own, and each calls out its required fields the way New user does
// (`WebKit.createForm()`). Which fields are required is decided HERE and
// nowhere on a page: each `GET /admin-api/<object>/new` answers its
// `createFields` from this table, and the page draws what the answer says.
//
// **A FIELD IS REQUIRED WHEN THE CREATE REFUSES WITHOUT IT, AND ONLY THEN**
// (rcbj on #1132: what the server requires today is the guide; everything
// else is optional). So this table is a DESCRIPTION of each create's own
// refusals, not a second set of rules: nothing reads it to refuse anything,
// and the Management API's request models say the same in their own words
// (a required member has no `?` in `models/api/management.tsp`).
// `tests/create_forms.js` holds the two together by calling each create
// without each required field and with the required fields alone.
//
// A NAME HERE IS THE NAME THE FORM POSTS AND THE CREATE TAKES, so a caller
// reading `createFields` can build the create's body from it.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');

type Json = any;

/**
 * One field of a create: the name it is posted and sent under, and whether
 * the create refuses without it.
 */
interface CreateField {
  name: string;
  required: boolean;
  // REQUIRED FOR SOME CHOICES ONLY: the create refuses without it when
  // another field holds one of these values, and is otherwise indifferent.
  // `*` is any value at all: two fields that go together name each other.
  requiredWhen?: { field: string; values: string[] };
}

// THE TABLE, by the object's create page. Each list is in the order the page
// draws it: the required fields first, as New user's username is.
const FORMS: Record<string, CreateField[]> = {
  // `usersAction()`'s `create`: the username is the entry's `uid` and RDN.
  // The attribute grid's own required fields are the realm's attribute
  // policy's (`requiredAttributes` beside this, #1066), drawn by the grid.
  //
  // A SERVICE ACCOUNT FROM THE START (#221, #1132's follow-ups): with the
  // box ticked (`serviceAccount` `true`), `service_accounts.ts`'s check()
  // refuses a create naming no owner while the account's service-account
  // policy requires one (STS-SVCACCT-0023; `requireOwner`, on by default,
  // so `newUserJson()` drops the condition where the realm's default policy
  // turns it off), and a push destination and the secret's name there go
  // together (STS-SVCACCT-0026): each is required once the other holds
  // anything (`*`).
  users: [
    { name: 'username', required: true },
    { name: 'serviceAccount', required: false },
    { name: 'owners', required: false,
      requiredWhen: { field: 'serviceAccount', values: ['true'] } },
    { name: 'destination', required: false,
      requiredWhen: { field: 'secretName', values: ['*'] } },
    { name: 'secretName', required: false,
      requiredWhen: { field: 'destination', values: ['*'] } }
  ],
  // `createApplication()`: the identifier is the registry key. The name
  // defaults to it. The field grid's attributes are optional.
  applications: [
    { name: 'identifier', required: true },
    { name: 'name', required: false }
  ],
  // `groupsAction()`'s `create`: the cn is the RDN and is refused empty
  // (`displayName` is accepted for it, SCIM's spelling, and the form does
  // not offer the second name). An empty group is allowed.
  // `rolesAction()`'s `create-role`: `roles.js` refuses a role with no
  // name ("A role needs a name."). An application, when given, must exist;
  // left empty the role is the realm's.
  roles: [
    { name: 'role', required: true },
    { name: 'description', required: false },
    { name: 'application', required: false },
    { name: 'displayName', required: false },
    { name: 'memberTypes', required: false }
  ],
  // `DevicesAdmin.action()`'s `create`, then `devices.create()`: an owner
  // the directory does not hold, or none, is STS-DEVICE-0001. A first key
  // is optional: a kind with no key, or a key with no kind, records none.
  devices: [
    { name: 'owner', required: true },
    { name: 'ownerKind', required: false },
    { name: 'label', required: false },
    { name: 'platform', required: false },
    { name: 'model', required: false },
    { name: 'os', required: false },
    { name: 'applications', required: false },
    { name: 'keyKind', required: false },
    { name: 'key', required: false }
  ],
  // `attributeSources.act()`'s `add-source` (`normalise()`, `problemOf()`,
  // STS-ATTR-0005 for each): the id, where the database is, who to sign in
  // as, the table, its key column and at least one `column=attribute` are
  // refused when empty. Everything else has a default the create applies
  // when it is absent — the port the dialect's, the key attribute `uid`,
  // reading at sign-in — or is checked only when given.
  attributeSources: [
    { name: 'id', required: true },
    { name: 'dialect', required: false },
    { name: 'host', required: true },
    { name: 'port', required: false },
    { name: 'database', required: true },
    { name: 'user', required: true },
    { name: 'passwordProvider', required: false },
    { name: 'passwordRef', required: false },
    { name: 'passwordField', required: false },
    { name: 'caFile', required: false },
    { name: 'serverName', required: false },
    { name: 'caCertificates', required: false },
    { name: 'trustPublicRoots', required: false },
    { name: 'table', required: true },
    { name: 'keyColumn', required: true },
    { name: 'keyAttribute', required: false },
    { name: 'columns', required: true },
    { name: 'refresh', required: false },
    { name: 'scheduleS', required: false },
    { name: 'timeoutMs', required: false },
    { name: 'onFailure', required: false },
    { name: 'enabled', required: false }
  ],
  // `secretDestinations.act()`'s `add-destination`: the identifier
  // (STS-SECDEST-0011) and the provider ("No provider is set.") always; the
  // write credential for every provider but `file`; AWS's region; Azure's
  // and Vault's https endpoint; the file provider's absolute directory.
  secretDestinations: [
    { name: 'identifier', required: true },
    { name: 'name', required: false },
    { name: 'provider', required: true },
    { name: 'payload', required: false },
    { name: 'region', required: false,
      requiredWhen: { field: 'provider', values: ['aws'] } },
    { name: 'project', required: false },
    { name: 'endpoint', required: false,
      requiredWhen: { field: 'provider', values: ['azure', 'vault'] } },
    { name: 'mount', required: false },
    { name: 'field', required: false },
    { name: 'directory', required: false,
      requiredWhen: { field: 'provider', values: ['file'] } },
    { name: 'caCertificates', required: false },
    { name: 'credential', required: false,
      requiredWhen: { field: 'provider',
                      values: ['aws', 'gcp', 'azure', 'vault'] } }
  ],
  groups: [
    { name: 'group', required: true },
    { name: 'note', required: false },
    { name: 'mail', required: false },
    { name: 'members', required: false }
  ]
};

/**
 * The fields of each directory object's create, and which are required.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class CreateForms {
  /**
   * The objects this table describes.
   *
   * @returns their names, as `fieldsOf()` takes them
   */
  static objects(): string[] {
    helpers.log.debug("Entering CreateForms.objects().");
    helpers.log.debug("Leaving CreateForms.objects().");
    return Object.keys(FORMS);
  }

  /**
   * One object's create fields, copied.
   *
   * @param object - the object, as `objects()` names it
   * @returns `[{ name, required }]`, in the order the page draws them; an
   *   empty list for an object this table does not describe
   */
  static fieldsOf(object: string): CreateField[] {
    helpers.log.debug("Entering CreateForms.fieldsOf(). object=" + object);
    const rows = Object.prototype.hasOwnProperty.call(FORMS, object)
      ? FORMS[object] : [];
    helpers.log.debug("Leaving CreateForms.fieldsOf(). " + rows.length +
                      " field(s).");
    return rows.map(function (row: CreateField): CreateField {
      const out: CreateField = { name: row.name, required: row.required };
      if (row.requiredWhen) {
        out.requiredWhen = { field: row.requiredWhen.field,
                             values: row.requiredWhen.values.slice() };
      }
      return out;
    });
  }

  /**
   * The names of one object's required fields.
   *
   * @param object - the object, as `objects()` names it
   * @returns the names
   */
  static requiredOf(object: string): string[] {
    helpers.log.debug("Entering CreateForms.requiredOf(). object=" + object);
    const out = CreateForms.fieldsOf(object).filter(function (row: Json) {
      return row.required;
    }).map(function (row: Json): string {
      return row.name;
    });
    helpers.log.debug("Leaving CreateForms.requiredOf(). " + out.length +
                      " required.");
    return out;
  }
}

export = CreateForms;
