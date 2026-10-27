// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: catalog.ts
//
// ---------------------------------------------------------------------------
// THE REPORT CATALOG (#956).
//
// A report names a source and fields from this catalog. It never names a
// table, and it never names a credential: the credential attribute ids are
// absent, so a query that asks for one fails as an unknown field rather than
// as a value this service then has to remember not to print. The field set
// is closed. A reader who wants a column that is not here is asking for a
// catalog change, not a query.
//
// `bounded` is the adapter's promise that a limit can be honoured without
// holding the population: an ordered read keeps a heap of that size, and a
// count keeps the groups and discards the rows. A source a test builds with
// `bounded: false` cannot be run synchronously.
//
// `indexed` (#985) is the list of operators the STORE can answer for a field
// without reading every row, and it is a fact about the directory rather
// than a preference. A person's attributes are one sealed value in the
// database, so nothing can filter on most of them there; beside the sealed
// value the store keeps a keyed digest of `uid`, `mail` and `entryUUID`,
// each with an index, and the RDN value — a person's `uid`, in the clear —
// with a trigram index (`persistence/directory_queries.js`). So `username`
// is indexed for `eq`, `in`, `contains` and `startsWith`, `mail` and
// `entryUuid` for `eq` and `in`, and every other field for nothing.
// `report/sources.ts` reads the list to decide whether a walk is bounded;
// the page and the OpenAPI document show it. `operatorsFor()` still offers
// every operator on every field of the type: a filter on a sealed field is
// applied in process, after the indexed one has named the candidates.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'sts-report-catalog' });

// Credential attribute ids. None of them is a field of any source. Selecting
// one is `unknown_field` because the catalog does not have it, which is the
// property the test holds: the id is absent, not specially rejected.
const CREDENTIALS = ['userPassword', 'unicodePwd', 'ntPassword', 'krb5Key',
  'totpSecret', 'webauthnCredential', 'backupCodes', 'mailSecret',
  'clientSecret'];

// Low-cardinality enumerations a count may group by. A username is not one
// of them, and neither is a member list. `day` and `mechanism` are the
// authentication-activity counts. `dialect`, `mode` and `onFailure` are the
// attribute-source register.
const GROUPABLE = ['status', 'enabled', 'type', 'protocol', 'category',
  'action', 'outcome', 'format', 'family', 'application', 'day',
  'mechanism', 'dialect', 'mode', 'onFailure', 'role', 'algorithm',
  'lane', 'factors', 'hasPassword', 'channel', 'format'];

// Scalars a filter may name and a sort may not. `members` is not in this
// list because it cannot be filtered either.
const UNSORTABLE = ['entryUuid', 'memberOf', 'members'];

const OPERATORS = {
  string: ['eq', 'ne', 'contains', 'startsWith', 'in', 'isNull'],
  number: ['eq', 'ne', 'lt', 'le', 'gt', 'ge', 'in', 'isNull'],
  timestamp: ['eq', 'ne', 'lt', 'le', 'gt', 'ge', 'isNull'],
  boolean: ['eq', 'ne', 'isNull']
};

interface FieldSpec {
  id: string;
  type: string;
  meaning: string;
  filter: boolean;
  sort: boolean;
  group: boolean;
  indexed: string[];
  // Every value the field can hold, when it is an enumeration (#1007): the
  // page draws a dropdown of them for equals and not-equals. Absent for a
  // field whose values are open.
  values?: string[];
}

// The mechanisms `credentialHolders` knows (#1002), in `sources.ts`'s
// `MECHANISM_TABLE` order; `tests/report_query.js` holds the two lists equal,
// because the catalog cannot require `sources.ts` (it requires the catalog).
const HOLDER_MECHANISMS = ['passkey', 'totp', 'emailFactor', 'certificate',
  'kerberos', 'password', 'recoveryCodes', 'selfIssued',
  'verifiableCredential'];
const HOLDER_ROLES = ['primary', 'mfa', 'recovery'];
// Where a wallet credential came from (#1021): a web wallet, a native wallet
// app, the browser's Digital Credentials API, or an administrator's hand.
const HOLDER_CHANNELS = ['web', 'app', 'dc_api', 'admin'];

// The operators the store answers with an index, per field of `users`. No
// other source reads the directory row by row, so no other source has a row.
const INDEXED: Record<string, string[]> = {
  username: ['eq', 'in', 'contains', 'startsWith'],
  mail: ['eq', 'in'],
  entryUuid: ['eq', 'in']
};

// The `credentialHolders` source's indexed fields (#1002): a mechanism is
// the holders of its attribute through the store's asked-names index, and a
// group is its members; neither reads the population.
const HOLDER_INDEXED: Record<string, string[]> = {
  mechanism: ['eq', 'in'],
  memberOf: ['eq', 'in']
};

interface SourceSpec {
  id: string;
  bounded: boolean;
  retention: string;
  // Offset is not a query key. A second source is not either.
  paging: string;
  relationships: string[];
  fields: FieldSpec[];
}

function field(id: string, type: string, meaning: string,
               indexed?: string[], values?: string[]): FieldSpec {
  log.debug("Entering field().");
  const spec: FieldSpec = {
    id: id,
    type: type,
    meaning: meaning,
    filter: id !== 'members',
    sort: UNSORTABLE.indexOf(id) < 0,
    group: GROUPABLE.indexOf(id) >= 0,
    indexed: (indexed || []).slice()
  };
  if (values && values.length) {
    spec.values = values.slice();
  }
  log.debug("Leaving field().");
  return spec;
}

function source(id: string, retention: string,
                fields: FieldSpec[]): SourceSpec {
  log.debug("Entering source().");
  const spec = {
    id: id,
    bounded: true,
    retention: retention,
    paging: 'limit',
    relationships: [],
    fields: fields
  };
  log.debug("Leaving source().");
  return spec;
}

function standardSources(): SourceSpec[] {
  log.debug("Entering standardSources().");
  const sources = [
    source('users',
      'The directory as it is now. Not a history of accounts. status ' +
      'locked means pwdAccountLockedTime is set.',
      [field('username', 'string', 'The directory uid.', INDEXED.username),
       field('status', 'string',
         'locked when pwdAccountLockedTime is set, which is an ' +
         'administrative disable or any other lock; active otherwise.'),
       field('createdAt', 'timestamp',
         'When the directory created the entry.'),
       field('modifiedAt', 'timestamp',
         'When the directory last changed the entry.'),
       field('entryUuid', 'string',
         'The entryUUID. It can be filtered and cannot be sorted.',
         INDEXED.entryUuid),
       field('mail', 'string', 'The mail attribute.', INDEXED.mail),
       field('displayName', 'string',
         'displayName, or cn when displayName is empty.'),
       field('memberOf', 'string',
         'The names of the groups that list this person, joined.'),
       field('hasPassword', 'boolean',
         'Whether a password is set on the entry (#1019).'),
       field('factors', 'number',
         'How many second-factor credentials the person holds: passkeys ' +
         'enrolled as a second factor, authenticator apps and mail ' +
         'factors. hasPassword true and factors 0 is a password alone.'),
       field('methodsUsed', 'string',
         'The RFC 8176 methods the person has ever signed in with here ' +
         '(pwd, hwk, otp, ...), joined; compared value by value.'),
       field('mfaLastAuthTime', 'timestamp',
         'When the person last completed a multi-factor sign-in.')]),
    source('groups',
      'The directory as it is now. member lists are selected, not filtered.',
      [field('name', 'string', 'The group cn.'),
       field('description', 'string', 'The description attribute.'),
       field('memberCount', 'number', 'How many members the group lists.'),
       field('members', 'string',
         'Member names, joined. Selected, not filtered or sorted.')]),
    source('applications',
      'The realm\'s configured applications, as they are now.',
      [field('id', 'string', 'The application identifier.'),
       field('name', 'string', 'The application name.'),
       field('status', 'string',
         'active when the application is registered and enabled; ' +
         'disabled otherwise.'),
       field('enabled', 'boolean',
         'Whether the application is registered and enabled.')]),
    source('federation',
      'The realm\'s configured federation relationships, as they are now.',
      [field('id', 'string', 'The relationship id.'),
       field('partner', 'string', 'The partner name.'),
       field('protocol', 'string', 'The protocol the relationship speaks.'),
       field('enabled', 'boolean', 'Whether the relationship is enabled.')]),
    source('authMechanisms',
      'The realm authentication policy, one row per mechanism with ' +
      'application realm, plus one row per mechanism an application ' +
      'lists. An application that lists none inherits the realm policy ' +
      'and adds no row. Not a count of sign-ins. Non-browser doors are ' +
      'outside appAuthnMechanism.',
      [field('id', 'string',
         'The mechanism id. Realm rows use the policy names. An ' +
         'application row uses the value it lists.'),
       field('type', 'string',
         'both, primary, second or other for a realm row. primary for ' +
         'appAuthnMechanism and second for appMfaMechanism.'),
       field('enabled', 'boolean',
         'For a realm row, whether that policy flag is on. For an ' +
         'application row, true because the application lists it; a ' +
         'listed second factor the realm has switched off stays off ' +
         'at sign-in.'),
       field('application', 'string',
         'realm, or the application identifier when the row comes from ' +
         'that application\'s list.')]),
    source('auditEvents',
      'The audit ring still held in this process, newest first, capped by ' +
      'audit.maxEvents (5000 unless an operator set another cap). Not a ' +
      'warehouse of sign-ins.',
      [field('timestamp', 'timestamp', 'When the event was recorded.'),
       field('category', 'string', 'The audit category.'),
       field('action', 'string', 'The audit action.'),
       field('outcome', 'string', 'The audit outcome.'),
       field('actor', 'string', 'The account name on the audit row.')]),
    source('authActivity',
      'Sign-in attempts still in the same audit ring as auditEvents, ' +
      'capped by audit.maxEvents. Not a warehouse of sign-ins. A session ' +
      'id, an address, a note and a presented credential are not fields.',
      [field('timestamp', 'timestamp', 'When the attempt was recorded.'),
       field('day', 'string',
         'The UTC calendar day of timestamp, yyyy-mm-dd, so a count ' +
         'can group events per day.'),
       field('outcome', 'string',
         'The audit outcome, such as success or refused.'),
       field('mechanism', 'string',
         'detail.method when the audit row has one, otherwise ' +
         'detail.amr.'),
       field('actor', 'string', 'The account name on the audit row.'),
       field('application', 'string',
         'detail.application, or detail.client_id when the row has ' +
         'no application.'),
       field('protocol', 'string', 'The protocol on the audit row.')]),
    source('serviceMetrics',
      'Numeric leaves of a live service-counter snapshot. Not a time ' +
      'series. Route rows, token kinds and other lists are not leaves, ' +
      'so they are not here. /admin/metrics and /admin-api/metrics stay.',
      [field('name', 'string',
         'family.leaf, the snapshot member and the number under it.'),
       field('value', 'number', 'The number at the moment of the read.'),
       field('family', 'string',
         'The snapshot member the leaf was read from, such as calls ' +
         'or tokens.')]),
    source('reportJobs',
      'Report jobs this realm still holds. Artifacts age out on their own ' +
      'retention; the job row ages out later.',
      [field('id', 'string', 'The job id. It is not an authorization.'),
       field('status', 'string',
         'queued, running, completed, failed, cancelled or expired.'),
       field('format', 'string', 'json, csv or pdf.'),
       field('submittedAt', 'timestamp', 'When the job was queued.'),
       field('completedAt', 'timestamp',
         'When the job finished, or null while it has not.'),
       field('byteSize', 'number',
         'The stored artifact size, or null before it exists.')]),
    source('credentialHolders',
      'Who holds which authentication credential, as the directory is ' +
      'now: one row per person, per mechanism, per role (#1002). A ' +
      'passkey\'s role is the one chosen at its enrolment, primary or ' +
      'mfa; an authenticator app and an emailed code are mfa; a ' +
      'certificate and a Kerberos key are primary. Filter on mechanism or ' +
      'memberOf to read only those holders; a query naming neither reads ' +
      'every holder of every mechanism and runs as a job. Count with ' +
      'groupBy mechanism, role, algorithms or lanes for the census.',
      [field('username', 'string', 'The directory uid.'),
       field('displayName', 'string',
         'displayName, or cn when displayName is empty.'),
       field('mechanism', 'string',
         'passkey, totp, emailFactor, certificate, kerberos, password, ' +
         'recoveryCodes, verifiableCredential or selfIssued (the password ' +
         'is counted from the realm\'s counter and listed only narrowed ' +
         'by memberOf; its row carries the hash scheme, never the hash; a ' +
         'recovery code set is one row, its codes counted, never shown; a ' +
         'verifiable credential is one this realm issued, read from its ' +
         'register; a self-issued subject is a DID or key the person ' +
         'enrolled with a wallet).',
         HOLDER_INDEXED.mechanism, HOLDER_MECHANISMS),
       field('role', 'string',
         'primary (signs the person in on its own), mfa (a second ' +
         'factor after a password) or recovery (a recovery code set). A ' +
         'passkey\'s is the one chosen at enrolment and enforced at ' +
         'sign-in.', undefined, HOLDER_ROLES),
       field('credentials', 'number',
         'How many credentials of this mechanism and role the person ' +
         'holds; the same on each of their rows (#1011).'),
       field('credentialId', 'string',
         'This credential\'s own id: a passkey\'s credential id, or what ' +
         'the stored value names itself (#1011, one row per credential).'),
       field('algorithm', 'string',
         'This credential\'s signature algorithm: a passkey\'s JOSE name ' +
         '(ES256, ML-DSA-65), an authenticator app\'s HMAC algorithm.'),
       field('lane', 'string',
         'A passkey\'s or a wallet key\'s lane, classical or pqc; empty ' +
         'for the others.', undefined, ['classical', 'pqc']),
       field('channel', 'string',
         'Where a wallet credential came from (#1021): web (a web ' +
         'wallet), app (a native wallet), dc_api (the browser\'s Digital ' +
         'Credentials API) or admin (enrolled by an administrator). Empty ' +
         'for the other mechanisms, and for a credential recorded before ' +
         'the channel was kept.', undefined, HOLDER_CHANNELS),
       field('format', 'string',
         'A verifiable credential\'s format: dc+sd-jwt, jwt_vc_json or ' +
         'ldp_vc. Empty for the other mechanisms.'),
       field('enrolledAt', 'timestamp',
         'When this credential was enrolled, where it records it.'),
       field('lastUsedAt', 'timestamp',
         'When this credential was last used, where it records it.'),
       field('methodsUsed', 'string',
         'The RFC 8176 methods the person has ever signed in with here ' +
         '(authnMethod), joined.'),
       field('mfaLastAuthTime', 'timestamp',
         'When the person last completed a multi-factor sign-in.'),
       field('memberOf', 'string',
         'The names of the groups that list this person, joined.',
         HOLDER_INDEXED.memberOf)]),
    source('attributeSources',
      'The attribute-source register as it is now. Connection details ' +
      'and secrets are not fields. This source does not run SQL and ' +
      'does not read the remote table. Values those sources write are ' +
      'already on directory entries.',
      [field('id', 'string', 'The source id.'),
       field('dialect', 'string', 'postgres or mysql, as configured.'),
       field('database', 'string', 'The database name. Not the host.'),
       field('table', 'string', 'The table the lookup reads.'),
       field('keyAttribute', 'string',
         'The directory attribute the lookup key is taken from.'),
       field('mode', 'string',
         'The refresh modes, joined, such as sign-in or schedule.'),
       field('onFailure', 'string',
         'keep or refuse, as the source is configured.'),
       field('enabled', 'boolean', 'Whether the source is enabled.')])
  ];
  log.debug("Leaving standardSources().");
  return sources;
}

/**
 * The closed set of sources a report may name, and the fields of each.
 */
class Catalog {
  sources: SourceSpec[];

  /**
   * @param sources - a test's own sources; omitted, the standard ones
   */
  constructor(sources?: SourceSpec[]) {
    log.debug("Entering Catalog().");
    this.sources = sources ? sources.slice() : standardSources();
    log.debug("Leaving Catalog().");
  }

  /**
   * The operators the store can answer for a field with an index (#985),
   * read off the field's `indexed` list; a test's own field with none is
   * indexed for nothing.
   *
   * @param sourceId - the source
   * @param fieldId - the field
   * @returns the operator names, or an empty list
   */
  indexedFor(sourceId: string, fieldId: string): string[] {
    log.debug("Entering Catalog.indexedFor().");
    const spec = this.field(sourceId, fieldId);
    const list = spec && Array.isArray((spec as any).indexed) ?
      (spec as any).indexed.slice() : [];
    log.debug("Leaving Catalog.indexedFor().");
    return list;
  }

  /**
   * The credential attribute ids, which no source registers.
   *
   * @returns the ids
   */
  static credentialIds(): string[] {
    log.debug("Entering Catalog.credentialIds().");
    log.debug("Leaving Catalog.credentialIds().");
    return CREDENTIALS.slice();
  }

  /**
   * The comparison operators a field type allows. Logical operators are
   * not among them.
   *
   * @param type - string, number, boolean or timestamp
   * @returns the operator names, or an empty list
   */
  static operatorsFor(type: string): string[] {
    log.debug("Entering Catalog.operatorsFor().");
    const list = OPERATORS[type] || [];
    log.debug("Leaving Catalog.operatorsFor().");
    return list.slice();
  }

  /**
   * Every source, in catalog order.
   *
   * @returns the sources
   */
  list(): SourceSpec[] {
    log.debug("Entering Catalog.list().");
    log.debug("Leaving Catalog.list().");
    return this.sources.slice();
  }

  /**
   * One source by its id.
   *
   * @param id - the source name
   * @returns the source, or null
   */
  source(id: string): SourceSpec | null {
    log.debug("Entering Catalog.source().");
    let found = null;
    for (let i = 0; i < this.sources.length; i++) {
      if (this.sources[i].id === id) {
        found = this.sources[i];
      }
    }
    log.debug("Leaving Catalog.source().");
    return found;
  }

  /**
   * One field of a source.
   *
   * @param sourceId - the source name
   * @param fieldId - the field id
   * @returns the field, or null
   */
  field(sourceId: string, fieldId: string): FieldSpec | null {
    log.debug("Entering Catalog.field().");
    const src = this.source(sourceId);
    let found = null;
    const fields = src ? src.fields : [];
    for (let i = 0; i < fields.length; i++) {
      if (fields[i].id === fieldId) {
        found = fields[i];
      }
    }
    log.debug("Leaving Catalog.field().");
    return found;
  }
}

export = Catalog;
