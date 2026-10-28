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
  'lane', 'factors', 'hasPassword', 'channel', 'format',
  // The post-login progress source (#1110, #1111).
  'activity', 'profile', 'done', 'graceEnded', 'mailedBy', 'progress',
  'askedBy'];

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
  // The values whose equality the index answers, when it answers only some
  // (#1040): `status equals locked` is the holders of the lock, and
  // `active` is everybody else, which nothing indexes. Absent when every
  // value of an indexed operator is answered.
  indexedValues?: string[];
}

// The mechanisms `credentialHolders` knows (#1002), in `sources.ts`'s
// `MECHANISM_TABLE` order; `tests/report_query.js` holds the two lists equal,
// because the catalog cannot require `sources.ts` (it requires the catalog).
const HOLDER_MECHANISMS = ['passkey', 'totp', 'emailFactor', 'certificate',
  'kerberos', 'password', 'recoveryCodes', 'jwtSigningKey', 'samlSigningKey',
  'acmeAccountKey', 'scepChallenge', 'selfIssued', 'verifiableCredential'];
const HOLDER_ROLES = ['primary', 'mfa', 'recovery', 'signer', 'enrollment'];
// Where a wallet credential came from (#1021): a web wallet, a native wallet
// app, the browser's Digital Credentials API, or an administrator's hand.
// Since #1036 also the enrollment protocol that issued a certificate or
// that a credential is for, and where a signing key pair came from.
const HOLDER_CHANNELS = ['web', 'app', 'dc_api', 'admin', 'acme', 'est',
  'scep', 'issued', 'uploaded'];

// The operators the store answers with an index, per field of `users`. No
// other source reads the directory row by row, so no other source has a row.
const INDEXED: Record<string, string[]> = {
  username: ['eq', 'in', 'contains', 'startsWith'],
  mail: ['eq', 'in'],
  entryUuid: ['eq', 'in'],
  // A group's member list is an index of who is in it (rcbj, 2026-10-27:
  // "use every index available on every source"): `memberOf` equals a
  // group name reads the group and fetches its members by name.
  memberOf: ['eq', 'in'],
  // #1028: the lock is an asked name (`status equals locked` is a holders
  // read; `active` is the complement and anchors nothing), and the two
  // dates are B-trees over the directory's own columns, so a range on
  // either reads the span.
  status: ['eq'],
  createdAt: ['lt', 'le', 'gt', 'ge'],
  modifiedAt: ['lt', 'le', 'gt', 'ge']
};

// The groups source's own lookups: a group by its name is one read.
const GROUP_INDEXED: Record<string, string[]> = {
  name: ['eq', 'in']
};

// The `credentialHolders` source's indexed fields (#1002): a mechanism is
// the holders of its attribute through the store's asked-names index, and a
// group is its members; neither reads the population.
const HOLDER_INDEXED: Record<string, string[]> = {
  mechanism: ['eq', 'in'],
  memberOf: ['eq', 'in'],
  // The person's own keys (rcbj, 2026-10-27: `username equals rcbj` on
  // this source was refused as too large — it read every mechanism's
  // holders): the users source's lookups, through the same doors.
  username: INDEXED.username,
  mail: INDEXED.mail,
  entryUuid: INDEXED.entryUuid
};

// A PREDEFINED QUERY (#1110): a name and a document the page offers as a
// starting point on the source's own page and in New Query. It is DATA, not
// a stored definition: nobody owns it, it runs nothing by itself, and the
// person who starts from it saves their own copy if they want one. Each
// document validates (`tests/report_query.js`), so a catalog change that
// breaks one fails the suite rather than the page.
interface PresetSpec {
  id: string;
  name: string;
  document: Record<string, any>;
}

interface SourceSpec {
  id: string;
  bounded: boolean;
  // A DIRECTORY-BACKED SOURCE (rcbj, 2026-10-27: a filter on a field the
  // store cannot answer "will never work given the constraints"): a filter
  // on it has to name an indexed field — a leaf of an `and`, every arm of
  // an `or` — and the page offers only those in a first filter row. The
  // other fields narrow an indexed read; alone they would read everybody.
  anchored?: boolean;
  retention: string;
  // Offset is not a query key. A second source is not either.
  paging: string;
  relationships: string[];
  fields: FieldSpec[];
  presets?: PresetSpec[];
}

function field(id: string, type: string, meaning: string,
               indexed?: string[], values?: string[],
               indexedValues?: string[]): FieldSpec {
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
  if (indexedValues && indexedValues.length) {
    spec.indexedValues = indexedValues.slice();
  }
  log.debug("Leaving field().");
  return spec;
}

function source(id: string, retention: string,
                fields: FieldSpec[], anchored?: boolean,
                presets?: PresetSpec[]): SourceSpec {
  log.debug("Entering source().");
  const spec: SourceSpec = {
    id: id,
    bounded: true,
    retention: retention,
    paging: 'limit',
    relationships: [],
    fields: fields
  };
  if (anchored) {
    spec.anchored = true;
  }
  if (presets && presets.length) {
    spec.presets = presets.map(function (one: PresetSpec): PresetSpec {
      return { id: one.id, name: one.name,
               document: JSON.parse(JSON.stringify(one.document)) };
    });
  }
  log.debug("Leaving source().");
  return spec;
}

// THE POST-LOGIN PROGRESS SOURCE (#1110): `post_login.progress` read back,
// one row per person and activity the realm has asked or mailed — the
// post-quantum passkey migration's progress (#1096), and since #1111 what a
// started activity's mail did for each person. Read from the store, not the
// directory, so it is neither anchored nor indexed: an unordered read stops
// at its limit, and an ordered read or a count walks the rows a page at a
// time under the usual time caps.
const POST_LOGIN_ACTIVITIES = ['pqc-passkey-migration'];
const POST_LOGIN_ROLES = ['primary', 'mfa'];
// Where a person stands, ONE word (the page groups by one field): done; past
// the allotted time and not done; put off by Skip; asked and not done;
// mailed by a started activity and never asked at a sign-in.
const POST_LOGIN_PROGRESS = ['done', 'past-grace', 'snoozed', 'asked',
  'mailed'];

function postLoginProgressSource(): SourceSpec {
  log.debug("Entering postLoginProgressSource().");
  const spec = source('postLoginProgress',
    'One row per person and post-login activity this realm has asked at a ' +
    'sign-in or mailed about, as the post-login progress store ' +
    'holds it now (#1110). Somebody never asked and never mailed has no ' +
    'row. The profile, role and allotted time are the ones that applied ' +
    'when the row was last written.',
    [field('username', 'string', 'The directory uid of the person.'),
     field('activity', 'string',
       'The post-login activity: pqc-passkey-migration, a post-quantum ' +
       '(ML-DSA) passkey where the person holds a classical one or none.',
       undefined, POST_LOGIN_ACTIVITIES),
     field('profile', 'string',
       'The post-login profile that reached the person when the row was ' +
       'last written (default, or a named profile chosen by group).'),
     field('role', 'string',
       'The role the passkey is asked for: primary (passwordless sign-in) ' +
       'or mfa (a second factor).', undefined, POST_LOGIN_ROLES),
     field('progress', 'string',
       'Where the person stands, in one word, the first that holds: done; ' +
       'past-grace (the allotted time ended and it is not done); snoozed ' +
       '(Skip put it off and the time has not run out); asked (at a ' +
       'sign-in, not done); mailed (by a started activity, never asked at a ' +
       'sign-in).', undefined, POST_LOGIN_PROGRESS),
     field('invitedAt', 'timestamp',
       'When the person was first asked at a sign-in; the allotted time ' +
       'counts from here. Null when they were only mailed.'),
     field('snoozedUntil', 'timestamp',
       'Until when Skip put the activity off, or null.'),
     field('asks', 'number', 'How many sign-ins asked the person.'),
     field('skips', 'number', 'How many times the person chose Skip.'),
     field('done', 'boolean', 'Whether the person did the activity.'),
     field('doneAt', 'timestamp', 'When the person did it, or null.'),
     field('deadline', 'timestamp',
       'When the allotted time (graceDays from the first invitation) ends, ' +
       'or null where there is none.'),
     field('graceEnded', 'boolean',
       'Whether the allotted time has ended and the activity is not done: ' +
       'Skip is gone and the next sign-in is held until it is.'),
     field('askedBy', 'string',
       'Who asked the person at a sign-in (#1126): policy (the post-login ' +
       'profile itself is on for them), or the id (pla-…) of the running ' +
       'started post-login activity whose groups hold them; empty when they ' +
       'were never asked at a sign-in.'),
     field('mailedBy', 'string',
       'The started post-login activity (its id, pla-…) that last mailed ' +
       'the person (#1111), or empty.'),
     field('mails', 'number',
       'How many mails the started activity named in mailedBy sent the ' +
       'person about the activity.'),
     field('firstMailedAt', 'timestamp',
       'When that started activity\'s first mail went, or null.'),
     field('lastMailedAt', 'timestamp',
       'When the last reminder mail went, or null.')], false,
    // Each document is one the New Query form can draw — one filter leaf,
    // one order, one group — so starting from it and saving it keeps it.
    [{ id: 'progress-by-activity', name: 'Progress by activity',
       document: { source: 'postLoginProgress',
                   select: ['progress'],
                   where: { op: 'eq', field: 'activity',
                            value: 'pqc-passkey-migration' },
                   aggregate: 'count', groupBy: ['progress'],
                   orderBy: [{ field: 'progress', dir: 'asc' }],
                   limit: 100, format: 'json', mode: 'auto' } },
     { id: 'past-grace-period', name: 'People past their grace period',
       document: { source: 'postLoginProgress',
                   select: ['username', 'activity', 'profile', 'role',
                            'invitedAt', 'deadline', 'asks', 'skips',
                            'mails', 'lastMailedAt'],
                   where: { op: 'eq', field: 'graceEnded', value: true },
                   orderBy: [{ field: 'deadline', dir: 'asc' }],
                   limit: 1000, format: 'json', mode: 'auto' } },
     { id: 'skipped-most', name: 'People who skipped most',
       document: { source: 'postLoginProgress',
                   select: ['username', 'activity', 'profile', 'skips',
                            'asks', 'done', 'snoozedUntil', 'deadline'],
                   where: { op: 'gt', field: 'skips', value: 0 },
                   orderBy: [{ field: 'skips', dir: 'desc' }],
                   limit: 100, format: 'json', mode: 'auto' } }]);
  log.debug("Leaving postLoginProgressSource().");
  return spec;
}

// ---------------------------------------------------------------------------
// PASSKEY HISTORY (#1109): `passkey_report.history`, one stored row per realm
// per UTC day written by the passkey report's daily recount, projected by
// `report/passkey_history.ts` into several rows told apart by `scope` — the
// realm's people and passkeys, each named profile's population, and the
// passkeys by algorithm, by lane and by attestation algorithm. The read is
// the store held in memory, at most `webauthn.passkeyHistoryDays` days, so
// nothing is indexed and nothing needs to be: the source is bounded by its
// retention. In a block of its own so a source added beside it merges
// cleanly.
// ---------------------------------------------------------------------------
const HISTORY_SCOPES = ['realm', 'profile', 'algorithm', 'lane',
  'attestation'];
// Fields of this source a count may group by, beyond `GROUPABLE`'s.
const HISTORY_GROUPABLE = ['scope', 'name', 'postQuantum',
  'postQuantumRequired', 'complete', 'counted'];

function passkeyHistorySource(): SourceSpec {
  log.debug("Entering passkeyHistorySource().");
  const people = 'On a realm or profile row; null on the others.';
  const fields = [
    field('day', 'string',
      'The UTC calendar day the row counts, yyyy-mm-dd. A later recount ' +
      'the same day replaced the day\'s rows.'),
    field('countedAt', 'timestamp',
      'When the recount that wrote the day finished.'),
    field('scope', 'string',
      'What the row counts: realm (the realm\'s people and passkeys, one ' +
      'a day), profile (a named passkey profile\'s population), algorithm ' +
      '(passkeys of one algorithm in one lane), lane (passkeys in one ' +
      'lane) or attestation (passkeys whose attestation certificate one ' +
      'algorithm signed). Filter on it: the scopes count the same ' +
      'passkeys more than once.', undefined, HISTORY_SCOPES),
    field('name', 'string',
      'The profile, algorithm (JOSE name), lane or attestation ' +
      'certificate algorithm the row is for; empty on a realm row.'),
    field('coseAlg', 'number',
      'The COSE algorithm identifier of an algorithm row, or of an ' +
      'attestation row\'s algorithm where it has one; null otherwise.'),
    field('lane', 'string',
      'classical or pqc (#643) on an algorithm or lane row; empty ' +
      'otherwise.', undefined, ['classical', 'pqc']),
    field('postQuantum', 'boolean',
      'Whether an algorithm or attestation row\'s algorithm is ML-DSA; ' +
      'null on the other scopes. The kind is the algorithm, never the ' +
      'lane.'),
    field('count', 'number',
      'Passkeys counted in the row: all of them on a realm or profile ' +
      'row, those of the row\'s algorithm, lane or attestation algorithm ' +
      'otherwise.'),
    field('people', 'number',
      'People in the realm, or in the profile\'s population as far as it ' +
      'was read. ' + people),
    field('holding', 'number',
      'People holding at least one passkey. ' + people),
    field('postQuantumOnly', 'number',
      'People whose passkeys are all ML-DSA. ' + people),
    field('classicalOnly', 'number',
      'People whose passkeys are all classical. ' + people),
    field('both', 'number',
      'People holding an ML-DSA and a classical passkey. ' + people),
    field('none', 'number',
      'People holding no passkey; null where the realm\'s count of its ' +
      'people could not be read. ' + people),
    field('withPostQuantum', 'number',
      'People holding at least one ML-DSA passkey (postQuantumOnly plus ' +
      'both). ' + people),
    field('postQuantumShare', 'number',
      'withPostQuantum as a percentage of holding, to one decimal: the ' +
      'adoption figure. Null where nobody holds a passkey. ' + people),
    field('postQuantumKeys', 'number',
      'ML-DSA passkeys among count. ' + people),
    field('postQuantumRequired', 'string',
      'A profile row\'s postQuantumRequired setting on the day (#718); ' +
      'empty otherwise.'),
    field('members', 'number',
      'A profile row\'s members, as the profile\'s groups list them; ' +
      'null otherwise.'),
    field('complete', 'boolean',
      'Whether a profile row read every member: false where the ' +
      'population was larger than the passkey report reads for a filter, ' +
      'and the numbers cover the members read. Null otherwise.'),
    field('counted', 'boolean',
      'False on a profile row the day did not count: past the profiles a ' +
      'day counts, or a population that could not be read. True ' +
      'otherwise.')
  ];
  fields.forEach(function (spec: FieldSpec): void {
    if (HISTORY_GROUPABLE.indexOf(spec.id) >= 0) {
      spec.group = true;
    }
  });
  // THE PREDEFINED QUERIES (#1109), in #1110's `presets` shape: each one
  // filter leaf on `scope`, one order on `day`, so the form draws it and
  // a save keeps it. Their longer descriptions are in `docs/reporting.md`.
  const presets: PresetSpec[] = [{
    id: 'post-quantum-adoption-by-day',
    name: 'Post-quantum adoption by day',
    document: { source: 'passkeyHistory',
      select: ['day', 'people', 'holding', 'withPostQuantum',
               'postQuantumShare', 'postQuantumOnly', 'both',
               'classicalOnly', 'none', 'postQuantumKeys', 'count'],
      where: { op: 'eq', field: 'scope', value: 'realm' },
      orderBy: [{ field: 'day', dir: 'asc' }],
      // One row a day: the default synchronous cap (500) holds the default
      // retention (400 days), so it answers at once rather than as a job.
      limit: 500, format: 'json', mode: 'auto' }
  }, {
    id: 'passkeys-by-algorithm-by-day',
    name: 'Passkeys by algorithm by day',
    document: { source: 'passkeyHistory',
      select: ['day', 'name', 'coseAlg', 'lane', 'postQuantum', 'count'],
      where: { op: 'eq', field: 'scope', value: 'algorithm' },
      orderBy: [{ field: 'day', dir: 'asc' }],
      limit: 1000, format: 'json', mode: 'auto' }
  }, {
    id: 'profile-adoption-by-day',
    name: 'Post-quantum adoption by passkey profile by day',
    document: { source: 'passkeyHistory',
      select: ['day', 'name', 'postQuantumRequired', 'members', 'complete',
               'holding', 'withPostQuantum', 'postQuantumShare', 'counted'],
      where: { op: 'eq', field: 'scope', value: 'profile' },
      orderBy: [{ field: 'day', dir: 'asc' }],
      limit: 1000, format: 'json', mode: 'auto' }
  }];
  const spec = source('passkeyHistory',
    'One stored row per realm per UTC day, written by the passkey ' +
    'report\'s daily recount (#1109) and kept for ' +
    'webauthn.passkeyHistoryDays days; each day is read as several rows, ' +
    'one per scope. A day the recount did not run has no rows. Read from ' +
    'the history store, never the directory.', fields, false, presets);
  log.debug("Leaving passkeyHistorySource().");
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
         'administrative disable or any other lock; active otherwise. ' +
         'Indexed for locked only: active is everybody else.',
         INDEXED.status, ['active', 'locked'], ['locked']),
       field('createdAt', 'timestamp',
         'When the directory created the entry.', INDEXED.createdAt),
       field('modifiedAt', 'timestamp',
         'When the directory last changed the entry.', INDEXED.modifiedAt),
       field('entryUuid', 'string',
         'The entryUUID. It can be filtered and cannot be sorted.',
         INDEXED.entryUuid),
       field('mail', 'string', 'The mail attribute.', INDEXED.mail),
       field('displayName', 'string',
         'displayName, or cn when displayName is empty.'),
       field('memberOf', 'string',
         'The names of the groups that list this person, joined.',
         INDEXED.memberOf),
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
         'When the person last completed a multi-factor sign-in.')], true),
    source('groups',
      'The directory as it is now. member lists are selected, not filtered.',
      [field('name', 'string', 'The group cn.', GROUP_INDEXED.name),
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
         'disabled otherwise.', undefined, ['active', 'disabled']),
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
         'appAuthnMechanism and second for appMfaMechanism.', undefined,
         ['both', 'primary', 'second', 'other']),
       field('enabled', 'boolean',
         'For a realm row, whether that policy flag is on. For an ' +
         'application row, true because the application lists it; a ' +
         'listed second factor the realm has switched off stays off ' +
         'at sign-in.'),
       field('application', 'string',
         'realm, or the application identifier when the row comes from ' +
         'that application\'s list.')]),
    source('auditEvents',
      'The audit rings still held by the service\'s processes, newest ' +
      'first, each capped by audit.maxEvents (5000 unless an operator set ' +
      'another cap). Not a warehouse of sign-ins.',
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
         'queued, running, completed, failed, cancelled or expired.',
         undefined, ['queued', 'running', 'completed', 'failed',
           'cancelled', 'expired']),
       field('format', 'string', 'json, csv or pdf.', undefined,
         ['json', 'csv', 'pdf']),
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
      [field('username', 'string', 'The directory uid.',
         HOLDER_INDEXED.username),
       field('mail', 'string', 'The mail attribute.', HOLDER_INDEXED.mail),
       field('entryUuid', 'string',
         'The entryUUID. It can be filtered and cannot be sorted.',
         HOLDER_INDEXED.entryUuid),
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
         '(ES256, ML-DSA-65), an authenticator app\'s HMAC algorithm, a ' +
         'certificate\'s or signing key\'s key (RSA-2048, P-256, ' +
         'Ed25519, ML-DSA-44).'),
       field('lane', 'string',
         'A passkey\'s or a wallet key\'s lane, classical or pqc; empty ' +
         'for the others.', undefined, ['classical', 'pqc']),
       field('channel', 'string',
         'Where the credential came from: for a wallet credential (#1021) ' +
         'web, app, dc_api or admin; for a certificate or an enrollment ' +
         'credential (#1036) the protocol, acme, est or scep; for a ' +
         'signing key pair issued (here) or uploaded. Empty where nothing ' +
         'was recorded.', undefined, HOLDER_CHANNELS),
       field('format', 'string',
         'What kind of credential it is within its mechanism: a verifiable ' +
         'credential\'s format (dc+sd-jwt, jwt_vc_json, ldp_vc), a ' +
         'certificate\'s or enrollment credential\'s profile (tls-client, ' +
         'server, device, …), a signing key\'s profile (RFC 7523, RFC ' +
         '7522).'),
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
         HOLDER_INDEXED.memberOf)], true),
    source('attributeSources',
      'The attribute-source register as it is now. Connection details ' +
      'and secrets are not fields. This source does not run SQL and ' +
      'does not read the remote table. Values those sources write are ' +
      'already on directory entries.',
      [field('id', 'string', 'The source id.'),
       field('dialect', 'string', 'postgres or mysql, as configured.',
         undefined, ['postgres', 'mysql']),
       field('database', 'string', 'The database name. Not the host.'),
       field('table', 'string', 'The table the lookup reads.'),
       field('keyAttribute', 'string',
         'The directory attribute the lookup key is taken from.'),
       field('mode', 'string',
         'The refresh modes, joined, such as sign-in or schedule.'),
       field('onFailure', 'string',
         'keep or refuse, as the source is configured.', undefined,
         ['keep', 'refuse']),
       field('enabled', 'boolean', 'Whether the source is enabled.')]),
    postLoginProgressSource(),
    passkeyHistorySource(),
    passkeyCeremonySource()
  ];
  log.debug("Leaving standardSources().");
  return sources;
}

// ---------------------------------------------------------------------------
// PASSKEY CEREMONIES (#1107): every `webauthn.ceremony` and
// `webauthn.algorithm-mismatch` row still in the audit ring, one row each —
// what an operator moving a realm to ML-DSA passkeys reads to see where
// registrations and sign-ins with post-quantum keys fail, and for which
// clients. The row shape is `authn/webauthn_ceremonies.ts`'s (#943, folded
// by #1108); `report/passkey_ceremonies.ts` projects it. The ring is a list
// in memory capped by `audit.maxEvents` and the audit store indexes no
// detail field, so no field here declares an index, and none is needed:
// the read is bounded by the ring, as `authActivity`'s is.
//
// In a block of its own so a source added beside it merges cleanly.
// ---------------------------------------------------------------------------
// The doors a ceremony row may name: `webauthn_ceremonies.ts`'s `DOORS`,
// which `tests/report_passkey_ceremonies.js` holds the door field's meaning
// to naming every one of. The catalog cannot require that module, which
// the web bundle would then carry.
const CEREMONY_DOORS = ['sign-in-step', 'usernameless', 'portal',
  'activation', 'upgrade', 'admin-enrolment', 'device-link'];
// Fields of this source a count may group by, beyond `GROUPABLE`'s.
const CEREMONY_GROUPABLE = ['kind', 'ceremony', 'door', 'client',
  'clientError', 'attachment', 'offeredFirst', 'postQuantum',
  'postQuantumOffered', 'errorCode', 'held', 'offerRule'];

function passkeyCeremonySource(): SourceSpec {
  log.debug("Entering passkeyCeremonySource().");
  const fields = [
    field('timestamp', 'timestamp', 'When the ceremony\'s row was recorded.'),
    field('day', 'string',
      'The UTC calendar day of timestamp, yyyy-mm-dd, so a count can ' +
      'group ceremonies per day.'),
    field('kind', 'string',
      'ceremony for a webauthn.ceremony row (one registration or sign-in, ' +
      'completed or not); algorithm-mismatch for a sign-in with a ' +
      'classical passkey by a person who holds an ML-DSA one, where ' +
      'post-quantum was not required. Filter on it before counting, so a ' +
      'mismatch is not counted twice with its ceremony.', undefined,
      ['ceremony', 'algorithm-mismatch']),
    field('ceremony', 'string',
      'registration or assertion (a sign-in); empty on a mismatch row.',
      undefined, ['registration', 'assertion']),
    field('door', 'string',
      'Where it ran: ' + CEREMONY_DOORS.slice(0, -1).join(', ') + ' or ' +
      CEREMONY_DOORS[CEREMONY_DOORS.length - 1] + ' (portal is ' +
      '/portal/keys); on a mismatch row, the sign-in\'s own name for its ' +
      'way in.'),
    field('outcome', 'string', 'success or refused.', undefined,
      ['success', 'refused']),
    field('errorCode', 'string',
      'The error code a refused ceremony was recorded under ' +
      '(STS-AUTHN-0022 where the browser gave up); empty on success.'),
    field('actor', 'string',
      'The person, where known; empty before a usernameless passkey ' +
      'names anybody.'),
    field('application', 'string',
      'The application the sign-in was for, its client or relying-party ' +
      'id; empty at /portal/keys, an activation link, a device link and ' +
      'an administrator\'s enrolment, and on rows written before #1108.'),
    field('role', 'string', 'primary or mfa; empty where none applied.',
      undefined, ['primary', 'mfa']),
    field('lane', 'string', 'classical or pqc (#643).', undefined,
      ['classical', 'pqc']),
    field('offered', 'string',
      'The algorithms offered, in order, comma-separated: a ' +
      'registration\'s list as the browser was given it; for a sign-in, ' +
      'the algorithms of the person\'s passkeys the ceremony could use.'),
    field('offerRule', 'string',
      'The client rule that narrowed this registration\'s offer, or ' +
      'would have, where one applied (#1112): configured: <rule>, ' +
      'learned: <client>, or not applied (<why>): ...; empty otherwise.'),
    field('offeredFirst', 'string',
      'The first algorithm offered: the one a client honouring the order ' +
      'makes when it can.'),
    field('postQuantumOffered', 'boolean',
      'Whether an ML-DSA algorithm was among those offered.'),
    field('algorithm', 'string',
      'The algorithm used: the new passkey\'s, or the signing one\'s. ' +
      'Empty where the ceremony reached none. On a mismatch row, the ' +
      'classical algorithm that signed.'),
    field('postQuantum', 'boolean',
      'Whether the algorithm used is an ML-DSA algorithm.'),
    field('held', 'string',
      'On a mismatch row, the ML-DSA algorithms of the person\'s ' +
      'passkeys; empty otherwise.'),
    field('client', 'string',
      'The browser and operating system by name and major version only ' +
      '(Chrome 141 on macOS 15), from the User-Agent.'),
    field('clientError', 'string',
      'For a ceremony the browser did not complete, the error name its ' +
      'script reported (NotAllowedError, NotSupportedError, ' +
      'InvalidStateError, ...), or other; never its message.'),
    field('capabilities', 'string',
      'The client capabilities the browser reported as available, ' +
      'comma-separated, from a fixed list.'),
    field('attachment', 'string',
      'platform or cross-platform, as the browser reported it.', undefined,
      ['platform', 'cross-platform']),
    field('transports', 'string',
      'The transports the browser reported, comma-separated (internal, ' +
      'hybrid, usb, nfc, ble).'),
    field('attestation', 'string',
      'For a registration, what its attestation was signed with, leaf to ' +
      'anchor, and (PQ) where all of it is post-quantum.'),
    field('durationMs', 'number',
      'Milliseconds from the ceremony\'s options being issued to its ' +
      'response, measured by the service (#1108). It includes the ' +
      'person\'s time at the prompt; compare many rows. Null on rows ' +
      'written before #1108 and where no options were issued.')
  ];
  fields.forEach(function (spec: FieldSpec): void {
    if (CEREMONY_GROUPABLE.indexOf(spec.id) >= 0) {
      spec.group = true;
    }
  });
  // THE PREDEFINED QUERIES (#1107), in #1110's `presets` shape: what an
  // operator moving a realm to ML-DSA passkeys asks first. Their longer
  // descriptions are in `docs/reporting.md`.
  const presets: PresetSpec[] = [{
    // Registrations that offered ML-DSA and did not complete, per client;
    // group by clientError instead to see how they failed.
    id: 'ml-dsa-registrations-failed-by-client',
    name: 'ML-DSA registrations that failed, by client',
    document: {
      source: 'passkeyCeremonies',
      where: { op: 'and', args: [
        { op: 'eq', field: 'kind', value: 'ceremony' },
        { op: 'eq', field: 'ceremony', value: 'registration' },
        { op: 'eq', field: 'postQuantumOffered', value: true },
        { op: 'eq', field: 'outcome', value: 'refused' }] },
      aggregate: 'count', groupBy: ['client'], limit: 100
    }
  }, {
    // Completed registrations that offered ML-DSA and produced a classical
    // passkey: clients that cannot make ML-DSA yet, or do not honour the
    // offered order.
    id: 'ml-dsa-asked-classical-made-by-client',
    name: 'Registrations that asked for ML-DSA and made a classical ' +
      'passkey, by client',
    document: {
      source: 'passkeyCeremonies',
      where: { op: 'and', args: [
        { op: 'eq', field: 'kind', value: 'ceremony' },
        { op: 'eq', field: 'ceremony', value: 'registration' },
        { op: 'eq', field: 'outcome', value: 'success' },
        { op: 'eq', field: 'postQuantumOffered', value: true },
        { op: 'eq', field: 'postQuantum', value: false }] },
      aggregate: 'count', groupBy: ['client'], limit: 100
    }
  }, {
    // Sign-ins with a classical passkey by people who hold an ML-DSA one:
    // who requiring post-quantum at sign-in would refuse today.
    id: 'classical-sign-ins-by-ml-dsa-holders',
    name: 'Classical sign-ins by people who hold an ML-DSA passkey',
    document: {
      source: 'passkeyCeremonies',
      where: { op: 'eq', field: 'kind', value: 'algorithm-mismatch' },
      aggregate: 'count', groupBy: ['client'], limit: 100
    }
  }];
  const spec = source('passkeyCeremonies',
    'Passkey registrations and sign-ins still in the same audit ring as ' +
    'auditEvents (webauthn.ceremony and webauthn.algorithm-mismatch rows, ' +
    '#943), capped by audit.maxEvents. Not a warehouse of ceremonies: run ' +
    'it on a schedule to keep a history. Nothing here is indexed; the ' +
    'read is bounded by the ring.', fields, false, presets);
  log.debug("Leaving passkeyCeremonySource().");
  return spec;
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
   * The indexed fields of a source as a refusal names them (#1040):
   * `username (eq, in, contains, startsWith)`, and a field whose index
   * answers only some values with them, `status (eq locked)`.
   *
   * @param sourceId - the source
   * @returns one phrase per indexed field
   */
  indexedPhrases(sourceId: string): string[] {
    log.debug("Entering Catalog.indexedPhrases().");
    const src = this.source(sourceId) || { fields: [] };
    const out = (src.fields || []).filter(function (spec: any): boolean {
      return Array.isArray(spec.indexed) && spec.indexed.length > 0;
    }).map(function (spec: any): string {
      const only = Array.isArray(spec.indexedValues) &&
        spec.indexedValues.length ? ' ' + spec.indexedValues.join(' or ') :
        '';
      return spec.id + ' (' + spec.indexed.join(', ') + only + ')';
    });
    log.debug("Leaving Catalog.indexedPhrases().");
    return out;
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
   * One predefined query of a source (#1110).
   *
   * @param sourceId - the source name
   * @param presetId - the preset's id
   * @returns a copy of the preset, or null
   */
  preset(sourceId: string, presetId: string): PresetSpec | null {
    log.debug("Entering Catalog.preset().");
    const src = this.source(sourceId);
    const found = (src && src.presets ? src.presets : [])
      .filter(function (one: PresetSpec): boolean {
        return one.id === presetId;
      })[0] || null;
    log.debug("Leaving Catalog.preset(). " + (found ? 'Found.' : 'None.'));
    return found ? { id: found.id, name: found.name,
                     document: JSON.parse(JSON.stringify(found.document)) }
                 : null;
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
