// @ts-check
'use strict';
//
// File: persistence/persistence_postgres.js
//
// ---------------------------------------------------------------------------
// THE SHARED STORE, AND THE FIRST HALF OF THE SCALABILITY WORK.
//
// `persistence.mode=postgres`. Three tables, one connection pool, and a
// transaction per flush. What it is FOR is two things at once, and it is worth
// keeping them apart because only the first of them is finished:
//
//   1. PERSISTENCE. This process's directory, realms and runtime appconfig
//      overrides survive a restart. Done, and it is the whole of what was
//      asked for.
//   2. COORDINATION. Several processes sharing one directory. NOT done, and
//      deliberately: see THE SEAM below. Pointing two copies of this service at
//      one database today gives you two copies that each write to it and
//      neither of which sees the other's writes until it restarts.
//
// **WHY POSTGRES AND NOT A DIRECTORY.** The obvious answer to "make LDAP
// persistent" is slapd, and `persistence.js`'s header argues at length why that
// would end this service rather than extend it. The second obvious answer is a
// key-value store, and JSONB is what makes Postgres the better one here: an
// entry is `{attributename: [values]}` with no schema, which is a document, and
// Postgres will index into a document (`attrs -> 'uid'`) while still giving a
// primary key, a transaction, and a `DELETE` that means it. Redis would be
// faster and would make every search a client-side scan; Mongo would match the
// shape exactly and is a heavier thing to put in a mock's compose file.
//
// ---------------------------------------------------------------------------
// THE SCHEMA, AND THE TWO COLUMN DECISIONS THAT ARE NOT OBVIOUS.
//
//   sts_ldap_entries(realm, dn_key, dn, attrs, origin, created_at, modified_at)
//   sts_realms(id, name, description, created_at, overrides)
//   sts_appconfig(key, value)
//
// **THE PRIMARY KEY IS (realm, dn_key) AND dn_key IS THE NORMALISED DN.** Not
// the DN as written. Two clients may spell one DN four ways — `UID=Alice,
// OU=Users` and `uid=alice,ou=users` name one entry — and `ldap_server.js`'s
// `normalizeDn()` is the single function in this service that decides that. The
// written spelling is kept beside it in `dn`, because it is what a client sees
// in a search result and losing it would mean every restored entry came back
// lower-cased.
//
// **created_at AND modified_at ARE text, NOT timestamptz.** They hold an RFC
// 4517 generalized time — `20260827192200Z` — which is what LDAP puts in
// `createTimestamp`, and a round trip through `timestamptz` would re-render it
// in whatever format the driver felt like and in whatever timezone the session
// had. The values are also already IN `attrs` as the two operational
// attributes; these columns exist so that a human or a report can `ORDER BY`
// them without digging into JSONB, and their being redundant is the reason they
// must be byte-identical rather than merely equivalent.
//
// ---------------------------------------------------------------------------
// A FLUSH IS ONE TRANSACTION, AND THAT IS THE WHOLE DURABILITY STORY.
//
// `persistence.js` hands this driver a diff — the upserts and deletes that take
// the last written state to the current one. They go in one `BEGIN … COMMIT`,
// so another reader of this database sees the whole of one change or none of
// it, and a failure rolls back to a state this process still has an accurate
// shadow of. There is no partial write to recover from, which is why the retry
// on the other side can be as simple as "leave the dirty bit on".
//
// ---------------------------------------------------------------------------
// THE SEAM IS CLOSED (2026-09-06). THIS DRIVER COORDINATES PROCESSES NOW, AND
// THE SHAPE OF IT IS THE ONE SENTENCE WORTH REMEMBERING: **THE CHANGE LOG IS
// THE CONTRACT AND THE NOTIFICATION IS ONLY LATENCY.**
//
// This section used to be a checklist of what a later phase would need. Every
// item on it is done, and the design that closed it is not the obvious one, so
// what it says now is why.
//
// `sts_changes` is a monotonic log — `seq bigserial`, an origin, a kind, a
// realm and a key — WRITTEN INSIDE THE SAME TRANSACTION AS THE DATA. A process
// remembers the highest `seq` it has applied and asks for everything after it.
// That single fact is what makes every hard part of this easy:
//
//   * A PROCESS THAT WAS NOT LISTENING MISSES NOTHING. `NOTIFY` is
//     at-most-once and connection-scoped — a listener that drops for four
//     seconds loses every notification in that window and cannot tell that it
//     did. A log it reads by sequence number has no such window.
//   * THE 8000-BYTE PAYLOAD LIMIT STOPS MATTERING, because the payload is a
//     POINTER and never the row. The receiver re-reads what the log named.
//   * AND THE DATABASE CAN RESTART UNDER IT. The listener reconnects, asks for
//     everything after its own high-water mark, and is correct again.
//
// So `NOTIFY` stays exactly what it was — a nudge that wakes the poll early —
// and it is allowed to be lossy because losing it costs latency and never
// correctness. **THAT IS THE SAME ARGUMENT `xacml-pep/` MAKES ABOUT ITS OWN
// PULL**, which is the strongest reason to trust it: this repository has run
// that trade in production shape once already, in the one place where the
// alternative was a push nobody could guarantee.
//
// The rest of the old checklist, as it was answered:
//   * The `LISTEN` is on a connection of its own, because a pooled client
//     cannot hold one — the pool would hand it to somebody else.
//   * The change is applied to the in-memory Map rather than reloading the
//     realm, inside `realms.run()` so the ambient realm is right.
//   * A process ignores its own rows, by the origin id that was already in
//     this payload for exactly that reason.
//   * `ldap.maxEntries` is still a ceiling on what THIS PROCESS holds, and it
//     is reported as such.
//   * **AND THE LAST ITEM IS REVERSED.** It read "nothing about tokens,
//     sessions or codes, which are not in this database and are not going to
//     be". They are, in product mode, since `sts_minted` — and they replicate
//     through this same log, because a design that coordinated the directory
//     and not the sessions would be a service where two processes agree about
//     who exists and disagree about who is signed in.
// ---------------------------------------------------------------------------

// A LEAF with no requires: the failure codes on the log lines and the startup
// refusals below. It reaches for no setting and no store, so this driver still
// reaches for nothing.
const errorCodes = require('../common/error_codes');
// node's own, for the process origin's UUID.
const nodeCrypto = require('crypto');
// A LEAF with no requires: the three-way merge a directory upsert is written
// through when another node has changed the row (#46 section 3).
const directoryMerge = require('./directory_merge');
// The table of what active-active mode depends on (#46). A LEAF but for bunyan
// and config, and it reads no setting at require time. The two rows this
// driver provides are provided at the foot of this file.
const capabilities = require('../cluster/cluster_capabilities');

// A CHANNEL NAME AND A SCHEMA VERSION, both spelt once here.
const CHANNEL = 'sts_ldap_change';
// How many change-log rows go in one INSERT. Four bind parameters a row, and
// the protocol's limit is 65,535, so 5,000 leaves room and still makes a large
// flush a handful of statements. See recordChanges().
const CHANGE_ROWS_PER_STATEMENT = 5000;
// 2 SINCE 2026-09-06, when `sts_keys` joined the three tables this driver has
// always had. Nothing reads this yet — it is here so that a future change has
// something to look at other than the shape of the tables — but leaving it at 1
// over a different schema would make the one thing it is for useless. 4 SINCE
// 2026-09-13, for `sts_used_assertions`. 5 SINCE 2026-09-14, for the four
// `sts_cluster_*` tables (#46) — see their block below. 6 SINCE 2026-09-18,
// for `sts_realms.domain` — a realm's DNS domain, fixed at creation — which is
// the first COLUMN this schema has added to a table that already existed, and
// so the first that `CREATE TABLE IF NOT EXISTS` cannot add: see
// SCHEMA_COLUMNS below. 7 SINCE 2026-09-22, for the thirteen `sts_risk_*`
// tables of risk scoring (#62) — see their block in SCHEMA_OBJECTS. 8 SINCE
// 2026-09-23, for `sts_risk_terms_acceptances`, the record of who accepted
// which dataset provider's terms (the second licence review on #62).
const SCHEMA_VERSION = 9;

// THE DATABASE'S CLOCK, in the milliseconds every cluster table stores. See the
// cluster block in SCHEMA_OBJECTS for why no process's own clock is used.
// `clock_timestamp()` and not `now()`: `now()` is the START of the transaction,
// and a lease checked late in a long transaction must be checked against when
// the check ran.
const DB_NOW = '(extract(epoch from clock_timestamp()) * 1000)::bigint';

// The advisory lock two joining nodes serialise on, so that "is every live
// node configured the same as me" and "write my row" are one decision. An
// advisory lock needs no privilege, which is why it is usable by `sts_app`.
const JOIN_LOCK = 460046;

// ---------------------------------------------------------------------------
// WHAT AN ENDED MINTED ROW LEAVES BEHIND (2026-09-14, #46 section 3).
//
// A session ended on node A was a DELETE, and node B — holding the session in
// memory, a moment behind — wrote its copy back on the next request that
// touched it (`noteSessionUsed()` stamps `lastSeenAt` and re-sets the row), so
// the session somebody had signed out of came back on every node. Nothing in
// the store said the key had ever been ended.
//
// So a store that declares `tombstone: true` has its deletes written as a row
// whose body is this marker, and an upsert of a key holding it does nothing
// (`… DO UPDATE … WHERE sts_minted.body <> $tombstone`). Every reader here
// treats a tombstone as absent. `$` is not in the sealed form's alphabet
// (`$aesgcm$1$…` is the only shape `keystore.seal()` writes and a body is
// always one), and this is not that shape, so no sealed row can be mistaken
// for one. It expires with `persistence.mintedRetention` — `purgeTombstones()`.
// ---------------------------------------------------------------------------
const TOMBSTONE = '$tombstone$1';

// How long a node row is kept after it expired, for `/admin/cluster` to show a
// node that went away. A join purges older ones.
const DEAD_NODE_RETENTION_MS = 24 * 60 * 60 * 1000;

// The schema, created if it is not there. `IF NOT EXISTS` throughout rather
// than a migration table, and that is a decision rather than laziness: this is
// a mock identity service, the schema is seven tables, and a migration
// framework would be a larger dependency than the feature. If a column ever has
// to change, the honest answer for a service like this one is to say so in the
// release note and let an operator drop the tables.
//
// ---------------------------------------------------------------------------
// EACH STATEMENT IS PAIRED WITH THE OBJECT IT CREATES, AND SINCE 2026-09-06
// THAT PAIRING IS LOAD-BEARING RATHER THAN DOCUMENTATION.
//
// `open()` PROBES for the object and issues the statement only when it is
// missing, instead of running the whole list and letting `IF NOT EXISTS` sort
// it out. The reason is a permission check that happens in an order almost
// nobody expects:
//
//   **`CREATE TABLE IF NOT EXISTS` CHECKS CREATE ON THE SCHEMA BEFORE IT
//   CHECKS WHETHER THE TABLE EXISTS.** PostgreSQL's own parse_utilcmd.c says
//   so in a comment on the line that does it ("this also checks permissions on
//   the creation namespace, possibly causing a permission failure before the
//   IF NOT EXISTS test is performed"). `CREATE INDEX IF NOT EXISTS` is the
//   same shape one step worse: it takes the table's OWNERSHIP first.
//
// So a role that may read and write the rows and may not change the schema —
// which is what `postgres/schema.sql` creates, and what docker-compose.yml
// now dials with — was refused on every single start by six statements that
// had nothing to do. Probing first is what lets the two halves be separate:
// an OWNER builds the schema once, and this service's own role never issues a
// CREATE against a database that already has one.
//
// **THE CREATES ARE STILL HERE AND MUST STAY.** A run against an empty
// database with a privileged role — `node server.js` against a local postgres,
// which is what the default connection string is for — has no script to have
// been run and creates its own schema exactly as it always did. What changed
// is only that it no longer does so when there is nothing to create.
//
// `postgres/schema.sql` holds the same statements for the owner to run, and
// `tests/postgres_schema.js` fails if the two lists disagree.
// ---------------------------------------------------------------------------
const SCHEMA_OBJECTS = [
  { name: 'sts_ldap_entries', statement:
  'CREATE TABLE IF NOT EXISTS sts_ldap_entries (' +
  '  realm       text        NOT NULL,' +
  '  dn_key      text        NOT NULL,' +
  '  dn          text        NOT NULL,' +
  '  attrs       jsonb       NOT NULL,' +
  '  origin      text,' +
  '  created_at  text,' +
  '  modified_at text,' +
  '  PRIMARY KEY (realm, dn_key))' },
  // The one index worth having beyond the primary key: every enumerator in
  // this service walks one realm.
  { name: 'sts_ldap_entries_realm', statement:
  'CREATE INDEX IF NOT EXISTS sts_ldap_entries_realm ON sts_ldap_entries ' +
  '(realm)' },
  { name: 'sts_realms', statement:
  'CREATE TABLE IF NOT EXISTS sts_realms (' +
  '  id          text PRIMARY KEY,' +
  '  name        text,' +
  '  description text,' +
  '  created_at  bigint,' +
  '  overrides   jsonb NOT NULL DEFAULT \'{}\'::jsonb,' +
  '  domain      text)' },
  { name: 'sts_appconfig', statement:
  'CREATE TABLE IF NOT EXISTS sts_appconfig (' +
  '  key   text PRIMARY KEY,' +
  '  value jsonb NOT NULL)' },
  // THE SIGNING KEYS, ONE ROW PER TRUST REALM, AND THE COLUMN HOLDS
  // CIPHERTEXT (2026-09-06). `keystore.js` encrypts with AES-256-GCM before
  // anything reaches this driver, so nothing in this database is ever a
  // private key — which is what makes it acceptable for them to live beside
  // the directory in the same store. The key that opens them is read from
  // outside the service entirely; see common/secrets.js.
  //
  // `text` and not `bytea`, because the stored form is the self-describing
  // ASCII `$aesgcm$1$salt$iv$tag$body` that crypto.js writes — the same
  // decision `userPassword` follows, and it means a row can be read and
  // reasoned about with psql without a decode step.
  { name: 'sts_keys', statement:
  'CREATE TABLE IF NOT EXISTS sts_keys (' +
  '  realm      text PRIMARY KEY,' +
  '  material   text NOT NULL,' +
  '  written_at timestamptz NOT NULL DEFAULT now())' },
  // -------------------------------------------------------------------------
  // WHAT THIS PROCESS MINTED (2026-09-06). ONE TABLE FOR ALL OF IT, and the
  // shape is the whole design: a HANDLE names the store, a REALM names its
  // partition, a KEY names the row inside it, and the body is opaque.
  //
  // ONE TABLE RATHER THAN A TABLE PER FAMILY, because the handle list lives in
  // the store declarations (`realms.map({ persist: … })`) and a table per
  // family would be a SECOND place it is written down — which is the shape of
  // drift the whole `sts_metadata.js` design exists to prevent. Adding a
  // persisted store must cost one word at its declaration and nothing here.
  //
  // `realm` IS THE EMPTY STRING FOR THE SHARED STORES — the rate limiter's
  // buckets and the directory's cluster connection lists today; the Kerberos
  // principal database and replay cache were shared too until they became per
  // realm (#33, 2026-09-15) — which have no realm because what they belong to
  // has no path to put one in. It is
  // a column value rather than a nullable, so the primary key needs no COALESCE
  // and a query for one realm's rows cannot accidentally match them.
  //
  // `body` IS CIPHERTEXT, always, in the same self-describing
  // `$aesgcm$1$salt$iv$tag$body` form `sts_keys` uses and under the SAME
  // key-encryption key. A session id is a cookie value and an authorization
  // code is redeemable, so a dump of this table must not be a set of usable
  // credentials. What it costs is that nothing here is queryable by SQL, which
  // is the trade `persistence_minted.js` argues.
  //
  // `written_at` IS WHAT RETENTION READS. A row older than
  // `persistence.mintedRetention` is neither restored nor kept, and its index
  // is what makes the purge on start a range scan rather than a table scan.
  // -------------------------------------------------------------------------
  { name: 'sts_minted', statement:
  'CREATE TABLE IF NOT EXISTS sts_minted (' +
  '  handle     text        NOT NULL,' +
  '  realm      text        NOT NULL,' +
  '  key        text        NOT NULL,' +
  '  body       text        NOT NULL,' +
  '  written_at timestamptz NOT NULL DEFAULT now(),' +
  '  PRIMARY KEY (handle, realm, key))' },
  { name: 'sts_minted_handle', statement:
  'CREATE INDEX IF NOT EXISTS sts_minted_handle ON sts_minted (handle, ' +
  'realm)' },
  { name: 'sts_minted_written', statement:
  'CREATE INDEX IF NOT EXISTS sts_minted_written ON sts_minted (written_at)' },
  // -------------------------------------------------------------------------
  // THE CHANGE LOG (2026-09-06), which is what makes several processes against
  // one store agree rather than merely coexist.
  //
  // `seq` IS A bigserial AND EVERYTHING RESTS ON IT: it is assigned by the
  // database, it only goes up, and a process that has applied up to N asks for
  // N+1 onwards. That is the whole synchronisation primitive — no timestamps
  // (two clocks), no version columns per row (a merge rule per table), no
  // advisory locks (a process that dies holding one).
  //
  // `origin` is who wrote it, so a process can skip its own rows without
  // applying its own work back over itself.
  //
  // `kind` and `realm` and `key` are a POINTER. The row that changed is read
  // from its own table; nothing here carries data, which is why this table
  // needs no encryption while `sts_minted` does.
  //
  // **IT IS WRITTEN INSIDE THE TRANSACTION THAT MADE THE CHANGE**, which is the
  // one property that makes it trustworthy: there is no window in which the
  // data is committed and the log entry is not, so "I have applied up to N"
  // really does mean "I have seen everything committed before N".
  // -------------------------------------------------------------------------
  { name: 'sts_changes', statement:
  'CREATE TABLE IF NOT EXISTS sts_changes (' +
  '  seq    bigserial PRIMARY KEY,' +
  '  origin text        NOT NULL,' +
  '  kind   text        NOT NULL,' +
  '  realm  text        NOT NULL DEFAULT \'\',' +
  '  key    text        NOT NULL DEFAULT \'\',' +
  '  at     timestamptz NOT NULL DEFAULT now())' },
  { name: 'sts_changes_at', statement:
  'CREATE INDEX IF NOT EXISTS sts_changes_at ON sts_changes (at)' },
  // -------------------------------------------------------------------------
  // THE USED-ASSERTION HISTORY (2026-09-13): every RFC 7523 JWT and RFC 7522
  // SAML assertion this service accepted, until it would have expired.
  // `common/used_assertions.js` argues the design; three things are this
  // table's.
  //
  // **A TABLE OF ITS OWN AND NOT A HANDLE IN `sts_minted`**, because what it is
  // for is an ATOMIC CLAIM: `(realm, key)` is the primary key, and recording a
  // use is one `INSERT … ON CONFLICT`, so two processes against this store
  // cannot both accept one assertion. `sts_minted` is written by a journal
  // flush after the fact and converges through the change log, which is exactly
  // the window this table exists to close — and it is sealed, so nothing in it
  // could be compared by SQL anyway.
  //
  // **NOT SEALED, AND NOTHING IN IT IS A CREDENTIAL.** `key` is a SHA-256 of the
  // format, issuer and identifier; the rest is an issuer's name, a `jti` or
  // `ID`, a client and a subject — what an audit row already carries. The
  // assertion itself is never stored, so a dump of this table replays nothing.
  //
  // **THE TIMES ARE MILLISECONDS IN `bigint`**, the unit every reader of the
  // row works in, and `expires_at` is what every read filters on — the index is
  // what makes the live count and the sweep a range scan.
  // -------------------------------------------------------------------------
  { name: 'sts_used_assertions', statement:
  'CREATE TABLE IF NOT EXISTS sts_used_assertions (' +
  '  realm       text   NOT NULL,' +
  '  key         text   NOT NULL,' +
  '  format      text   NOT NULL,' +
  '  used_as     text   NOT NULL,' +
  '  issuer      text   NOT NULL,' +
  '  identifier  text   NOT NULL,' +
  '  client_id   text   NOT NULL DEFAULT \'\',' +
  '  subject     text   NOT NULL DEFAULT \'\',' +
  '  state       text   NOT NULL,' +
  '  reservation text   NOT NULL,' +
  '  origin      text   NOT NULL DEFAULT \'\',' +
  '  used_at     bigint NOT NULL,' +
  '  spent_at    bigint NOT NULL DEFAULT 0,' +
  '  expires_at  bigint NOT NULL,' +
  '  PRIMARY KEY (realm, key))' },
  { name: 'sts_used_assertions_expiry', statement:
  'CREATE INDEX IF NOT EXISTS sts_used_assertions_expiry ON ' +
  'sts_used_assertions (realm, expires_at)' },
  // -------------------------------------------------------------------------
  // THE CLUSTER (2026-09-14, #46): SEVERAL CONTAINERS AGAINST THIS ONE STORE.
  // `cluster/CLAUDE.md` argues all four tables; what is the driver's is below.
  //
  // **EVERY TIME IN THEM IS THE DATABASE'S CLOCK**, as milliseconds in a
  // `bigint`, and never a time a process sent. Two containers' clocks differ,
  // and a lease that expires by the clock of whoever happens to be asking is a
  // lease two nodes can both believe they hold. `DB_NOW` below is the one
  // spelling of it.
  //
  // `sts_cluster_nodes` — ONE ROW PER PROCESS START THAT JOINED, keyed by a
  // UUID made at that start. A row whose `expires_at` has passed is dead FOR
  // GOOD: the heartbeat's UPDATE refuses to renew an expired row, so a node
  // that paused past its lifetime cannot quietly come back and must exit.
  //
  // `sts_cluster_leases` — A NAMED ROLE ONLY ONE NODE MAY HOLD, with a FENCING
  // TOKEN that goes up by one every time the lease changes hands. A write that
  // needs the role carries the token it acquired, and the transaction checks it
  // under a share lock on the lease row — so a node that lost the lease while
  // paused cannot commit afterwards. A released lease is EXPIRED rather than
  // deleted, so the token never goes back to 1.
  //
  // `sts_cluster_claims` — AN ATOMIC "ONCE": the primary key picks one winner
  // among concurrent claims in every process against this store. `key` is a
  // digest (`cluster/cluster_claims.js` hashes it) and never a bearer value.
  //
  // `sts_cluster_secrets` — A SECRET EVERY NODE MUST AGREE ON (the CSRF key,
  // the ACME nonce key), SEALED under the key-encryption key before it arrives
  // here and written first-writer-wins.
  // -------------------------------------------------------------------------
  { name: 'sts_cluster_nodes', statement:
  'CREATE TABLE IF NOT EXISTS sts_cluster_nodes (' +
  '  node_id      text   PRIMARY KEY,' +
  '  name         text   NOT NULL DEFAULT \'\',' +
  '  mode         text   NOT NULL,' +
  '  version      text   NOT NULL DEFAULT \'\',' +
  '  fingerprint  text   NOT NULL DEFAULT \'\',' +
  '  started_at   bigint NOT NULL,' +
  '  heartbeat_at bigint NOT NULL,' +
  '  expires_at   bigint NOT NULL,' +
  '  left_at      bigint NOT NULL DEFAULT 0,' +
  '  info         jsonb  NOT NULL DEFAULT \'{}\'::jsonb)' },
  { name: 'sts_cluster_nodes_expiry', statement:
  'CREATE INDEX IF NOT EXISTS sts_cluster_nodes_expiry ON ' +
  'sts_cluster_nodes (expires_at)' },
  { name: 'sts_cluster_leases', statement:
  'CREATE TABLE IF NOT EXISTS sts_cluster_leases (' +
  '  name        text   PRIMARY KEY,' +
  '  holder      text   NOT NULL,' +
  '  token       bigint NOT NULL,' +
  '  acquired_at bigint NOT NULL,' +
  '  expires_at  bigint NOT NULL)' },
  { name: 'sts_cluster_claims', statement:
  'CREATE TABLE IF NOT EXISTS sts_cluster_claims (' +
  '  scope       text   NOT NULL,' +
  '  realm       text   NOT NULL,' +
  '  key         text   NOT NULL,' +
  '  reservation text   NOT NULL,' +
  '  origin      text   NOT NULL DEFAULT \'\',' +
  '  claimed_at  bigint NOT NULL,' +
  '  expires_at  bigint NOT NULL,' +
  '  PRIMARY KEY (scope, realm, key))' },
  { name: 'sts_cluster_claims_expiry', statement:
  'CREATE INDEX IF NOT EXISTS sts_cluster_claims_expiry ON ' +
  'sts_cluster_claims (expires_at)' },
  { name: 'sts_cluster_secrets', statement:
  'CREATE TABLE IF NOT EXISTS sts_cluster_secrets (' +
  '  name       text   PRIMARY KEY,' +
  '  material   text   NOT NULL,' +
  '  created_by text   NOT NULL DEFAULT \'\',' +
  '  created_at bigint NOT NULL)' },
  // `sts_cluster_counters` — A VALUE THAT ONLY GOES UP (2026-09-14, #46
  // section 2): a WebAuthn signature counter, the last RFC 6238 time step a
  // person spent. One `INSERT … ON CONFLICT DO UPDATE … WHERE value < new`
  // under the primary key's row lock, so two nodes advancing one counter at
  // once cannot both win and a lower value can never overwrite a higher one —
  // which is exactly what the directory entry's last-writer-wins copy could
  // not promise. `key` is a digest, as in the claims table.
  // `cluster/cluster_counters.js` argues it.
  { name: 'sts_cluster_counters', statement:
  'CREATE TABLE IF NOT EXISTS sts_cluster_counters (' +
  '  scope      text   NOT NULL,' +
  '  realm      text   NOT NULL,' +
  '  key        text   NOT NULL,' +
  '  value      bigint NOT NULL,' +
  '  origin     text   NOT NULL DEFAULT \'\',' +
  '  updated_at bigint NOT NULL,' +
  '  PRIMARY KEY (scope, realm, key))' },
  // `sts_cluster_windows` — A COUNT INSIDE A FIXED WINDOW (2026-09-14, #46
  // section 2): the rate limiter's buckets, counted by every node against one
  // budget. One `INSERT … ON CONFLICT DO UPDATE SET count = CASE WHEN the
  // window has passed THEN 1 ELSE count + 1 END` under the primary key's row
  // lock, so two nodes counting one bucket at once both land and neither
  // overwrites the other's count — which is what two copies of a Map row,
  // last writer wins, could not promise. `key` is a digest.
  // `cluster/cluster_counters.js` argues it.
  { name: 'sts_cluster_windows', statement:
  'CREATE TABLE IF NOT EXISTS sts_cluster_windows (' +
  '  scope          text   NOT NULL,' +
  '  realm          text   NOT NULL,' +
  '  key            text   NOT NULL,' +
  '  count          bigint NOT NULL,' +
  '  window_ends_at bigint NOT NULL,' +
  '  origin         text   NOT NULL DEFAULT \'\',' +
  '  PRIMARY KEY (scope, realm, key))' },
  { name: 'sts_cluster_windows_expiry', statement:
  'CREATE INDEX IF NOT EXISTS sts_cluster_windows_expiry ON ' +
  'sts_cluster_windows (window_ends_at)' },
  // `sts_change_readers` — WHERE EVERY PROCESS READING `sts_changes` HAS GOT
  // TO (2026-09-14, #46 section 8). One row per process that coordinates —
  // a front process, and each of its request workers, which are origins of
  // their own — carrying its low-water mark and the database time it last
  // said so. The change log is trimmed below the lowest mark of the readers
  // still reporting, and never below a reader nobody has declared gone.
  // `persistence/persistence_replication.js` argues the bound.
  { name: 'sts_change_readers', statement:
  'CREATE TABLE IF NOT EXISTS sts_change_readers (' +
  '  origin      text   PRIMARY KEY,' +
  '  node_id     text   NOT NULL DEFAULT \'\',' +
  '  applied     bigint NOT NULL,' +
  '  started_at  bigint NOT NULL,' +
  '  reported_at bigint NOT NULL)' },
  // ---------------------------------------------------------------------------
  // RISK SCORING (#62, schema version 7, 2026-09-22). Thirteen tables, added
  // whole so the schema moves once for the subsystem rather than once per
  // phase. `risk/CLAUDE.md` argues the design; three things are this file's:
  //
  //   * EVERY EXTERNAL DATASET IS ROWS, by version (`sts_risk_dataset_*`, the
  //     geo, ASN, IP-list and FIDO tables), so what a score used can be named
  //     after the dataset has rotated. An IP range is `inet` start and end
  //     rather than `cidr`, because DB-IP publishes ranges that are not
  //     CIDR-aligned; a lookup is one probe of the primary key.
  //   * THE HISTORY THE MODEL KEEPS IS ROWS TOO (`sts_risk_assessments`,
  //     `_feature_counts`, `_failures`, `_session_context`, `_subjects`),
  //     because it needs atomic upserts every node agrees on and SQL to
  //     aggregate — which a sealed `sts_minted` body gives neither of.
  //   * AN ADDRESS IS PERSONAL DATA AND NOT A CREDENTIAL, so it is kept SEALED
  //     (`address_sealed`, under the key-encryption key `sts_minted` uses) and
  //     as a /24 or /48 `cidr` prefix SQL can group on. Nothing here holds a
  //     `User-Agent`, a credential id or a name a person typed in the clear.
  // ---------------------------------------------------------------------------
  { name: 'sts_risk_datasets', statement:
  'CREATE TABLE IF NOT EXISTS sts_risk_datasets (' +
  '  realm            text   NOT NULL DEFAULT \'\',' +
  '  dataset          text   NOT NULL,' +
  '  kind             text   NOT NULL,' +
  '  active_version   text   NOT NULL DEFAULT \'\',' +
  '  previous_version text   NOT NULL DEFAULT \'\',' +
  '  state            text   NOT NULL,' +
  '  updated_at       bigint NOT NULL,' +
  '  PRIMARY KEY (realm, dataset))' },
  { name: 'sts_risk_dataset_versions', statement:
  'CREATE TABLE IF NOT EXISTS sts_risk_dataset_versions (' +
  '  realm           text   NOT NULL DEFAULT \'\',' +
  '  dataset         text   NOT NULL,' +
  '  version         text   NOT NULL,' +
  '  format          text   NOT NULL,' +
  '  provider        text   NOT NULL,' +
  '  licence         text   NOT NULL,' +
  '  attribution     text   NOT NULL DEFAULT \'\',' +
  '  source          text   NOT NULL,' +
  '  source_uri      text   NOT NULL DEFAULT \'\',' +
  '  sha256          text   NOT NULL,' +
  '  byte_count      bigint NOT NULL,' +
  '  row_count       bigint NOT NULL DEFAULT 0,' +
  '  parameters      jsonb  NOT NULL DEFAULT \'{}\'::jsonb,' +
  '  verification    text   NOT NULL,' +
  '  published_at    bigint NOT NULL,' +
  '  next_update_at  bigint NOT NULL DEFAULT 0,' +
  '  fetched_at      bigint NOT NULL,' +
  '  loaded_at       bigint NOT NULL DEFAULT 0,' +
  '  activated_at    bigint NOT NULL DEFAULT 0,' +
  '  superseded_at   bigint NOT NULL DEFAULT 0,' +
  '  rows_deleted_at bigint NOT NULL DEFAULT 0,' +
  '  state           text   NOT NULL,' +
  '  refusal         text   NOT NULL DEFAULT \'\',' +
  '  error_code      text   NOT NULL DEFAULT \'\',' +
  '  origin          text   NOT NULL DEFAULT \'\',' +
  '  PRIMARY KEY (realm, dataset, version))' },
  { name: 'sts_risk_dataset_blobs', statement:
  'CREATE TABLE IF NOT EXISTS sts_risk_dataset_blobs (' +
  '  realm   text    NOT NULL DEFAULT \'\',' +
  '  dataset text    NOT NULL,' +
  '  version text    NOT NULL,' +
  '  part    integer NOT NULL,' +
  '  content bytea   NOT NULL,' +
  '  PRIMARY KEY (realm, dataset, version, part))' },
  { name: 'sts_risk_geo_locations', statement:
  'CREATE TABLE IF NOT EXISTS sts_risk_geo_locations (' +
  '  dataset     text   NOT NULL,' +
  '  version     text   NOT NULL,' +
  '  location_id bigint NOT NULL,' +
  '  continent   text   NOT NULL DEFAULT \'\',' +
  '  country     text   NOT NULL DEFAULT \'\',' +
  '  subdivision text   NOT NULL DEFAULT \'\',' +
  '  city        text   NOT NULL DEFAULT \'\',' +
  '  time_zone   text   NOT NULL DEFAULT \'\',' +
  '  PRIMARY KEY (dataset, version, location_id))' },
  { name: 'sts_risk_geo_ranges', statement:
  'CREATE TABLE IF NOT EXISTS sts_risk_geo_ranges (' +
  '  dataset            text             NOT NULL,' +
  '  version            text             NOT NULL,' +
  '  range_start        inet             NOT NULL,' +
  '  range_end          inet             NOT NULL,' +
  '  location_id        bigint           NOT NULL DEFAULT 0,' +
  '  continent          text             NOT NULL DEFAULT \'\',' +
  '  country            text             NOT NULL DEFAULT \'\',' +
  '  subdivision        text             NOT NULL DEFAULT \'\',' +
  '  city               text             NOT NULL DEFAULT \'\',' +
  '  registered_country text             NOT NULL DEFAULT \'\',' +
  '  latitude           double precision,' +
  '  longitude          double precision,' +
  '  accuracy_km        integer          NOT NULL DEFAULT 0,' +
  '  anonymous_proxy    boolean          NOT NULL DEFAULT false,' +
  '  satellite          boolean          NOT NULL DEFAULT false,' +
  '  PRIMARY KEY (dataset, version, range_start))' },
  { name: 'sts_risk_asn_ranges', statement:
  'CREATE TABLE IF NOT EXISTS sts_risk_asn_ranges (' +
  '  dataset     text   NOT NULL,' +
  '  version     text   NOT NULL,' +
  '  range_start inet   NOT NULL,' +
  '  range_end   inet   NOT NULL,' +
  '  asn         bigint NOT NULL,' +
  '  as_org      text   NOT NULL DEFAULT \'\',' +
  '  as_domain   text   NOT NULL DEFAULT \'\',' +
  '  PRIMARY KEY (dataset, version, range_start))' },
  { name: 'sts_risk_ip_lists', statement:
  'CREATE TABLE IF NOT EXISTS sts_risk_ip_lists (' +
  '  realm       text NOT NULL DEFAULT \'\',' +
  '  dataset     text NOT NULL,' +
  '  version     text NOT NULL,' +
  '  range_start inet NOT NULL,' +
  '  range_end   inet NOT NULL,' +
  '  category    text NOT NULL,' +
  '  note        text NOT NULL DEFAULT \'\',' +
  '  PRIMARY KEY (realm, dataset, version, range_start))' },
  { name: 'sts_risk_fido_authenticators', statement:
  'CREATE TABLE IF NOT EXISTS sts_risk_fido_authenticators (' +
  '  dataset             text    NOT NULL,' +
  '  version             text    NOT NULL,' +
  '  key_kind            text    NOT NULL,' +
  '  authenticator_key   text    NOT NULL,' +
  '  description         text    NOT NULL DEFAULT \'\',' +
  '  protocol_family     text    NOT NULL DEFAULT \'\',' +
  '  certification_level text    NOT NULL DEFAULT \'\',' +
  '  latest_status       text    NOT NULL DEFAULT \'\',' +
  '  latest_status_at    bigint  NOT NULL DEFAULT 0,' +
  '  compromised         boolean NOT NULL DEFAULT false,' +
  '  status_reports      jsonb   NOT NULL DEFAULT \'[]\'::jsonb,' +
  '  metadata_statement  jsonb   NOT NULL DEFAULT \'{}\'::jsonb,' +
  '  PRIMARY KEY (dataset, version, key_kind, authenticator_key))' },
  { name: 'sts_risk_fido_by_key', statement:
  'CREATE INDEX IF NOT EXISTS sts_risk_fido_by_key ON ' +
  'sts_risk_fido_authenticators (key_kind, authenticator_key)' },
  { name: 'sts_risk_assessments', statement:
  'CREATE TABLE IF NOT EXISTS sts_risk_assessments (' +
  '  realm              text    NOT NULL,' +
  '  id                 text    NOT NULL,' +
  '  at                 bigint  NOT NULL,' +
  '  phase              text    NOT NULL,' +
  '  door               text    NOT NULL,' +
  '  subject            text    NOT NULL DEFAULT \'\',' +
  '  session_id         text    NOT NULL DEFAULT \'\',' +
  '  client_id          text    NOT NULL DEFAULT \'\',' +
  '  address_sealed     text    NOT NULL,' +
  '  address_prefix     cidr    NOT NULL,' +
  '  asn                bigint  NOT NULL DEFAULT 0,' +
  '  as_org             text    NOT NULL DEFAULT \'\',' +
  '  country            text    NOT NULL DEFAULT \'\',' +
  '  subdivision        text    NOT NULL DEFAULT \'\',' +
  '  city               text    NOT NULL DEFAULT \'\',' +
  '  latitude           double precision,' +
  '  longitude          double precision,' +
  '  accuracy_km        integer NOT NULL DEFAULT 0,' +
  '  ip_lists           text[]  NOT NULL DEFAULT \'{}\',' +
  '  ua_hash            text    NOT NULL DEFAULT \'\',' +
  '  ua_family          text    NOT NULL DEFAULT \'\',' +
  '  ua_os              text    NOT NULL DEFAULT \'\',' +
  '  ua_platform        text    NOT NULL DEFAULT \'\',' +
  '  bot                boolean NOT NULL DEFAULT false,' +
  '  ja4                text    NOT NULL DEFAULT \'\',' +
  '  credential_kind    text    NOT NULL DEFAULT \'\',' +
  '  credential_hash    text    NOT NULL DEFAULT \'\',' +
  '  aaguid             text    NOT NULL DEFAULT \'\',' +
  '  authenticator_cert text    NOT NULL DEFAULT \'\',' +
  '  backup_eligible    boolean,' +
  '  backup_state       boolean,' +
  '  jkt                text    NOT NULL DEFAULT \'\',' +
  '  cert_fingerprint   text    NOT NULL DEFAULT \'\',' +
  '  datasets           jsonb   NOT NULL DEFAULT \'{}\'::jsonb,' +
  '  signals            jsonb   NOT NULL DEFAULT \'[]\'::jsonb,' +
  '  score              real    NOT NULL,' +
  '  level              text    NOT NULL,' +
  '  decision           text    NOT NULL,' +
  '  policy_id          text    NOT NULL DEFAULT \'\',' +
  '  error_code         text    NOT NULL DEFAULT \'\',' +
  '  origin             text    NOT NULL DEFAULT \'\',' +
  '  feedback           text    NOT NULL DEFAULT \'\',' +
  '  feedback_at        bigint  NOT NULL DEFAULT 0,' +
  '  PRIMARY KEY (realm, id))' },
  { name: 'sts_risk_assessments_subject', statement:
  'CREATE INDEX IF NOT EXISTS sts_risk_assessments_subject ON ' +
  'sts_risk_assessments (realm, subject, at)' },
  { name: 'sts_risk_assessments_session', statement:
  'CREATE INDEX IF NOT EXISTS sts_risk_assessments_session ON ' +
  'sts_risk_assessments (realm, session_id)' },
  { name: 'sts_risk_assessments_at', statement:
  'CREATE INDEX IF NOT EXISTS sts_risk_assessments_at ON ' +
  'sts_risk_assessments (at)' },
  { name: 'sts_risk_feature_counts', statement:
  'CREATE TABLE IF NOT EXISTS sts_risk_feature_counts (' +
  '  realm    text   NOT NULL,' +
  '  subject  text   NOT NULL,' +
  '  feature  text   NOT NULL,' +
  '  value    text   NOT NULL,' +
  '  count    bigint NOT NULL,' +
  '  first_at bigint NOT NULL,' +
  '  last_at  bigint NOT NULL,' +
  '  PRIMARY KEY (realm, subject, feature, value))' },
  { name: 'sts_risk_feature_counts_age', statement:
  'CREATE INDEX IF NOT EXISTS sts_risk_feature_counts_age ON ' +
  'sts_risk_feature_counts (realm, last_at)' },
  { name: 'sts_risk_failures', statement:
  'CREATE TABLE IF NOT EXISTS sts_risk_failures (' +
  '  realm          text      NOT NULL,' +
  '  id             bigserial NOT NULL,' +
  '  at             bigint    NOT NULL,' +
  '  door           text      NOT NULL,' +
  '  subject        text      NOT NULL DEFAULT \'\',' +
  '  name_hmac      text      NOT NULL DEFAULT \'\',' +
  '  address_sealed text      NOT NULL,' +
  '  address_prefix cidr      NOT NULL,' +
  '  asn            bigint    NOT NULL DEFAULT 0,' +
  '  error_code     text      NOT NULL,' +
  '  origin         text      NOT NULL DEFAULT \'\',' +
  '  PRIMARY KEY (realm, id))' },
  { name: 'sts_risk_failures_subject', statement:
  'CREATE INDEX IF NOT EXISTS sts_risk_failures_subject ON ' +
  'sts_risk_failures (realm, subject, at)' },
  { name: 'sts_risk_failures_name', statement:
  'CREATE INDEX IF NOT EXISTS sts_risk_failures_name ON ' +
  'sts_risk_failures (realm, name_hmac, at)' },
  { name: 'sts_risk_failures_prefix', statement:
  'CREATE INDEX IF NOT EXISTS sts_risk_failures_prefix ON ' +
  'sts_risk_failures (realm, address_prefix, at)' },
  { name: 'sts_risk_failures_at', statement:
  'CREATE INDEX IF NOT EXISTS sts_risk_failures_at ON ' +
  'sts_risk_failures (at)' },
  { name: 'sts_risk_session_context', statement:
  'CREATE TABLE IF NOT EXISTS sts_risk_session_context (' +
  '  realm          text   NOT NULL,' +
  '  session_id     text   NOT NULL,' +
  '  subject        text   NOT NULL,' +
  '  address_prefix cidr   NOT NULL,' +
  '  asn            bigint NOT NULL DEFAULT 0,' +
  '  country        text   NOT NULL DEFAULT \'\',' +
  '  ua_hash        text   NOT NULL DEFAULT \'\',' +
  '  ja4            text   NOT NULL DEFAULT \'\',' +
  '  jkt            text   NOT NULL DEFAULT \'\',' +
  '  score          real   NOT NULL,' +
  '  level          text   NOT NULL,' +
  '  updated_at     bigint NOT NULL,' +
  '  PRIMARY KEY (realm, session_id))' },
  { name: 'sts_risk_subjects', statement:
  'CREATE TABLE IF NOT EXISTS sts_risk_subjects (' +
  '  realm           text  NOT NULL,' +
  '  subject         text  NOT NULL,' +
  '  score           real  NOT NULL,' +
  '  level           text  NOT NULL,' +
  '  previous_level  text  NOT NULL DEFAULT \'\',' +
  '  reason          text  NOT NULL DEFAULT \'\',' +
  '  last_assessment text  NOT NULL DEFAULT \'\',' +
  '  crossed_at      bigint NOT NULL DEFAULT 0,' +
  '  actions         jsonb NOT NULL DEFAULT \'{}\'::jsonb,' +
  '  feedback        text  NOT NULL DEFAULT \'\',' +
  '  updated_at      bigint NOT NULL,' +
  '  PRIMARY KEY (realm, subject))' },
  // WHO ACCEPTED WHICH PROVIDER'S TERMS (#62, schema version 8, 2026-09-23 —
  // the second licence review). One row per acceptance, never updated: the
  // provider, a digest and the text of the terms as this build states them,
  // who accepted them and through which door, the deployment, and the digest
  // of the provider's own terms page when the install-time loader was asked
  // to fetch it. An import of a provider's data is refused unless a row here
  // matches that provider's CURRENT terms digest (`risk/risk_terms.ts`).
  { name: 'sts_risk_terms_acceptances', statement:
  'CREATE TABLE IF NOT EXISTS sts_risk_terms_acceptances (' +
  '  id            bigserial NOT NULL,' +
  '  provider      text      NOT NULL,' +
  '  terms_digest  text      NOT NULL,' +
  '  terms_text    text      NOT NULL,' +
  '  accepted_by   text      NOT NULL,' +
  '  accepted_via  text      NOT NULL,' +
  '  deployment    text      NOT NULL DEFAULT \'\',' +
  '  page_digest   text      NOT NULL DEFAULT \'\',' +
  '  accepted_at   bigint    NOT NULL,' +
  '  origin        text      NOT NULL DEFAULT \'\',' +
  '  PRIMARY KEY (id))' },
  { name: 'sts_risk_terms_acceptances_provider', statement:
  'CREATE INDEX IF NOT EXISTS sts_risk_terms_acceptances_provider ON ' +
  'sts_risk_terms_acceptances (provider, accepted_at)' },
  // What version of the above is on disk. One row, and nothing reads it yet —
  // it is here so that a future change has something to look at other than the
  // shape of the tables.
  { name: 'sts_schema', statement:
  'CREATE TABLE IF NOT EXISTS sts_schema (' +
  '  version int PRIMARY KEY,' +
  '  applied_at timestamptz NOT NULL DEFAULT now())' }
];

// COLUMNS ADDED TO A TABLE THAT MAY ALREADY EXIST (2026-09-18). A table in
// SCHEMA_OBJECTS is created whole when it is missing, and `CREATE TABLE IF NOT
// EXISTS` does nothing to one that is there — so a column added later reaches
// a new database and never an old one. Each row here is probed by name in
// `information_schema.columns`, which needs no privilege beyond seeing the
// table, and added where it is missing. The least-privileged role cannot
// ALTER, and is refused with STS-STORE-0029's sentence naming
// `postgres/schema.sql`, which carries the same `ADD COLUMN IF NOT EXISTS`.
const SCHEMA_COLUMNS = [
  { table: 'sts_realms', column: 'domain', statement:
  'ALTER TABLE sts_realms ADD COLUMN IF NOT EXISTS domain text' },
  // What the person said about a sign-in (#62 P6, schema version 9).
  { table: 'sts_risk_assessments', column: 'feedback', statement:
  'ALTER TABLE sts_risk_assessments ADD COLUMN IF NOT EXISTS feedback text ' +
  'NOT NULL DEFAULT \'\'' },
  { table: 'sts_risk_assessments', column: 'feedback_at', statement:
  'ALTER TABLE sts_risk_assessments ADD COLUMN IF NOT EXISTS feedback_at ' +
  'bigint NOT NULL DEFAULT 0' }
];

// THE STATEMENTS ALONE, which is what this module exported before the pairing
// above existed and what `tests/postgres_schema.js` compares against
// `postgres/schema.sql`. Derived rather than written twice, so the two cannot
// come apart.
const SCHEMA =
    SCHEMA_OBJECTS.map(function (object) { return object.statement; });


// ===========================================================================
// THE METRICS PROBES (2026-09-11), FOR `/admin/database`.
//
// **EVERY ONE OF THEM IS A `SELECT` AGAINST A CATALOG VIEW AND NOTHING HERE
// TOUCHES A ROW THIS SERVICE WROTE.** That is the whole safety argument for
// running arbitrary-looking SQL from a console page: the statements are
// DECLARED here, in a table, and none of them is composed from anything a
// request carries. There is no query box on that page and there must never be
// one — this service's database role can write, so a console that could send
// it a statement would be a console that could empty the directory.
//
// ---------------------------------------------------------------------------
// `SELECT *` IS DELIBERATE, AND IT IS THIS REPOSITORY'S OWN RULE ONE LAYER
// OUT.
//
// `crypto_metadata.js` reads an algorithm table from the module that PERFORMS
// the algorithm rather than writing it down, so a page cannot go on looking
// complete while being wrong. The same argument applies to a statistics view:
// **the columns of `pg_stat_*` are the SERVER's and they move between major
// versions**, sharply. Measured on the two this repository has met:
//
//   * `pg_stat_bgwriter` has ELEVEN columns on PostgreSQL 16 and FOUR on 17
//     and later, because the checkpoint counters moved to
//     `pg_stat_checkpointer` — a view that does not exist before 17;
//   * `pg_stat_wal` arrived in 14, `pg_stat_database.session_time` in 14,
//     `pg_stat_user_tables.total_vacuum_time` in 18.
//
// A page naming its columns would therefore be a page that is wrong on every
// server but the one it was written against, and wrong SILENTLY — a missing
// column reads as a blank cell. So each probe takes the whole row and the
// renderer draws the keys it was given. **"Pull everything available" is a
// property of the query rather than a list somebody maintains.**
//
// ---------------------------------------------------------------------------
// EVERY PROBE FAILS ON ITS OWN, AND THAT IS THE DESIGN RATHER THAN CAUTION.
//
// The role this service dials with is `sts_app`, which holds SELECT, INSERT,
// UPDATE and DELETE on seven tables and USAGE — not CREATE — on one schema. It
// is NOT `pg_monitor`. Most of these views are readable by anybody and a few
// are not, and which few depends on the server's version and on how the
// operator set it up. A page that ran all of this as one statement, or that
// let one rejection throw, would show NOTHING because of one view — so each
// probe is run, timed and caught separately, and a probe that failed is drawn
// as a row saying which one and why.
//
// **THE VERSION-GATED PROBES ARE NOT GUARDED BY A VERSION TEST.** Asking the
// server whether it is at least 17 and then asking for `pg_stat_checkpointer`
// is two round trips and a second thing to get wrong; asking for the view and
// reporting `relation does not exist` is one round trip and says the same
// thing more honestly. `expected` marks the ones whose absence is ORDINARY, so
// the page can draw them differently from a probe that failed for a reason
// somebody should look at.
// ===========================================================================
const METRIC_PROBES = [
  // -------------------------------------------------------------------------
  // WHAT THIS SERVER IS.
  // -------------------------------------------------------------------------
  { id: 'server', group: 'Server', shape: 'row',
    what: 'Which PostgreSQL this is, who this service is connected AS, and ' +
          'how long the server has been up.',
    sql: 'SELECT version() AS version,        ' +
         'current_setting(\'server_version_num\') AS version_num,        ' +
         'current_database() AS database,        current_user AS ' +
         'connected_as,        session_user AS session_user,        ' +
         'current_schema() AS search_schema,        pg_backend_pid() AS ' +
         'backend_pid,        pg_postmaster_start_time() AS ' +
         'started_at,        date_trunc(\'second\', now() - ' +
         'pg_postmaster_start_time())::text AS uptime,        ' +
         'pg_conf_load_time() AS config_loaded_at,        ' +
         'pg_is_in_recovery() AS in_recovery,        ' +
         'current_setting(\'server_encoding\') AS server_encoding,        ' +
         'current_setting(\'TimeZone\') AS timezone' },

  // THE SIZE, as a number AND as a string. `pg_size_pretty` is what a person
  // reads and the raw byte count is what anything comparing two of these
  // needs; computing the pretty form here rather than in the renderer means
  // one answer to "how big is this" rather than this service's own rounding
  // beside postgres's.
  { id: 'size', group: 'Server', shape: 'row',
    what: 'How much disk this database occupies.',
    sql: 'SELECT pg_database_size(current_database()) AS bytes,        ' +
         'pg_size_pretty(pg_database_size(current_database())) AS pretty' },

  // -------------------------------------------------------------------------
  // WHAT IT HAS DONE. `pg_stat_database` is the densest view here — thirty
  // columns on PostgreSQL 18 — and every one of them is drawn.
  // -------------------------------------------------------------------------
  { id: 'database', group: 'Activity', shape: 'row',
    what: 'Every counter PostgreSQL keeps for this database: commits and ' +
          'rollbacks, blocks read against blocks found in cache, tuples in ' +
          'every direction, deadlocks, temp files, and the I/O and session ' +
          'timings where the server collects them.',
    sql: 'SELECT * FROM pg_stat_database WHERE datname = current_database()' },

  { id: 'conflicts', group: 'Activity', shape: 'row',
    what: 'Queries cancelled by recovery conflicts. All zero on a server ' +
          'that is not a standby, which is the ordinary case here.',
    sql: 'SELECT * FROM pg_stat_database_conflicts ' +
         'WHERE datname = current_database()' },

  // -------------------------------------------------------------------------
  // WHO IS CONNECTED.
  //
  // **THIS IS THE ONE PROBE WHOSE ANSWER IS NARROWED BY THE ROLE, AND THE
  // PAGE SAYS SO RATHER THAN UNDER-REPORTING QUIETLY.** A backend belonging
  // to another role is VISIBLE — it is a row — but `state`, `query`,
  // `client_addr` and `wait_event` are withheld: `state` comes back NULL and
  // `query` comes back as the literal string `<insufficient privilege>`,
  // which is a value and not an error and would be drawn as somebody's SQL by
  // anything that did not know. Granting `pg_monitor` to the application role
  // is what fills them in, and this service does not ask for it.
  //
  // So the counts are taken in SQL with that in mind: `visible` is every row,
  // `readable` is the ones this role may actually see the state of.
  // -------------------------------------------------------------------------
  { id: 'connections', group: 'Activity', shape: 'row',
    what: 'How many backends this database has, against the server\'s limit.',
    sql: 'SELECT count(*) AS visible,        count(state) AS ' +
         'readable,        count(*) FILTER (WHERE state = \'active\') AS ' +
         'active,        count(*) FILTER (WHERE state = \'idle\') AS ' +
         'idle,        count(*) FILTER (WHERE state = \'idle in ' +
         'transaction\')          AS idle_in_transaction,        count(*) ' +
         'FILTER (WHERE wait_event IS NOT NULL) AS waiting,        ' +
         'current_setting(\'max_connections\')::int AS ' +
         'max_connections,        (SELECT count(*) FROM pg_stat_activity) AS ' +
         'server_wide FROM pg_stat_activity WHERE datname = ' +
         'current_database()' },

  { id: 'backends', group: 'Activity', shape: 'rows',
    what: 'One row per backend on this database. A backend belonging to ' +
          'another role shows as a row with its state and its query ' +
          'withheld, which is what a non-monitoring role is shown.',
    sql: 'SELECT pid, usename, application_name, client_addr, ' +
         'backend_type,        state, wait_event_type, wait_event,        ' +
         'date_trunc(\'second\', now() - backend_start)::text AS ' +
         'connected_for,        date_trunc(\'second\', now() - ' +
         'state_change)::text AS in_state_for,        CASE WHEN xact_start ' +
         'IS NULL THEN NULL             ELSE date_trunc(\'second\', now() - ' +
         'xact_start)::text END          AS transaction_age FROM ' +
         'pg_stat_activity WHERE datname = current_database() ORDER BY ' +
         'backend_start' },

  { id: 'locks', group: 'Activity', shape: 'rows',
    what: 'Locks held and waited for, by mode. A waiting lock on a mock is ' +
          'almost always this service contending with itself across the ' +
          'request-worker pool.',
    sql: 'SELECT mode, granted, count(*) AS count FROM pg_locks WHERE ' +
         'database IS NULL OR database =       (SELECT oid FROM pg_database ' +
         'WHERE datname = current_database()) GROUP BY mode, granted ORDER ' +
         'BY granted, mode' },

  // -------------------------------------------------------------------------
  // THE BACKGROUND MACHINERY. Four views, three of them version-dependent,
  // and every one of them `SELECT *`.
  // -------------------------------------------------------------------------
  { id: 'bgwriter', group: 'Background', shape: 'row',
    what: 'The background writer. ELEVEN columns before PostgreSQL 17 and ' +
          'FOUR from 17, when the checkpoint counters moved out of it — ' +
          'which is why this asks for all of them rather than naming any.',
    sql: 'SELECT * FROM pg_stat_bgwriter' },

  { id: 'checkpointer', group: 'Background', shape: 'row', expected: 17,
    what: 'The checkpointer. A view of its own since PostgreSQL 17; before ' +
          'that these counters are the tail of pg_stat_bgwriter above.',
    sql: 'SELECT * FROM pg_stat_checkpointer' },

  { id: 'wal', group: 'Background', shape: 'row', expected: 14,
    what: 'Write-ahead log generation. PostgreSQL 14 and later.',
    sql: 'SELECT * FROM pg_stat_wal' },

  { id: 'archiver', group: 'Background', shape: 'row',
    what: 'WAL archiving. All zero unless archive_mode is on, which it is ' +
          'not in any stack this repository ships.',
    sql: 'SELECT * FROM pg_stat_archiver' },

  { id: 'replication', group: 'Background', shape: 'rows',
    what: 'Standbys streaming from this server. EMPTY is the ordinary ' +
          'answer, and it is also what a role without pg_monitor is shown ' +
          'when there ARE standbys — so an empty table here is two different ' +
          'facts and the page says which one it cannot tell apart.',
    // `SELECT *` like every other view whose SHAPE is the server's. The
    // first version of this named seven columns and `tests/database_metrics.js`
    // caught it: `pg_stat_replication` gains columns between major versions
    // like the rest of them, so a named list here would have been the one
    // place on this page where "everything available" quietly meant "the
    // seven somebody thought of".
    sql: 'SELECT * FROM pg_stat_replication' },

  // -------------------------------------------------------------------------
  // THE SCHEMA THIS SERVICE OWNS.
  //
  // **EVERY ONE OF THESE IS SCOPED TO `current_schema()` AND NOT TO A NAME
  // WRITTEN DOWN HERE.** There is no setting for the schema: it is chosen by
  // the `search_path` in the connection string — `postgres/schema.sql` takes
  // it as a psql variable and `docker-compose.yml` puts it in the URL — or by
  // the database's own default. So a probe naming `sts` would answer about
  // somebody else's tables, or about nothing, for any operator who moved it,
  // and `current_schema()` is the only reading that is right by construction:
  // it is the same resolution every other statement in this driver uses.
  // -------------------------------------------------------------------------
  { id: 'tables', group: 'Schema', shape: 'rows',
    what: 'Every counter PostgreSQL keeps per table: sequential and index ' +
          'scans, tuples in every direction, live and dead rows, and when ' +
          'each was last vacuumed and analysed.',
    sql: 'SELECT * FROM pg_stat_user_tables ' +
         'WHERE schemaname = current_schema() ORDER BY relname' },

  { id: 'tableIo', group: 'Schema', shape: 'rows',
    what: 'Per-table block I/O: how much came out of the buffer cache and ' +
          'how much off disk, for the heap, its indexes and its TOAST.',
    sql: 'SELECT * FROM pg_statio_user_tables ' +
         'WHERE schemaname = current_schema() ORDER BY relname' },

  // THE SIZES, WITH THE PLANNER'S ROW ESTIMATE BESIDE THEM.
  //
  // **`reltuples` IS `-1` FOR A TABLE THAT HAS NEVER BEEN ANALYSED**, which is
  // the state of every table in a database this service has just built — and
  // a page that printed it would report minus one row. It is normalised to
  // NULL here, in SQL, so that one answer reaches every reader rather than
  // each renderer remembering.
  { id: 'sizes', group: 'Schema', shape: 'rows',
    what: 'How much disk each table occupies, split into the heap, its ' +
          'indexes and its TOAST, with the planner\'s row estimate.',
    sql: 'SELECT c.relname AS relname,        pg_total_relation_size(c.oid) ' +
         'AS total_bytes,        ' +
         'pg_size_pretty(pg_total_relation_size(c.oid)) AS total,        ' +
         'pg_size_pretty(pg_relation_size(c.oid)) AS heap,        ' +
         'pg_size_pretty(pg_indexes_size(c.oid)) AS indexes,        CASE ' +
         'WHEN c.reltoastrelid = 0 THEN NULL             ELSE ' +
         'pg_size_pretty(pg_total_relation_size(c.reltoastrelid))        END ' +
         'AS toast,        CASE WHEN c.reltuples < 0 THEN NULL             ' +
         'ELSE c.reltuples::bigint END AS estimated_rows,        (SELECT ' +
         'count(*) FROM pg_index i WHERE i.indrelid = c.oid)          AS ' +
         'index_count FROM pg_class c WHERE c.relnamespace = ' +
         'current_schema()::regnamespace   AND c.relkind = \'r\' ORDER BY ' +
         'pg_total_relation_size(c.oid) DESC' },

  // THE INDEXES, AND THE ONES NOTHING HAS EVER USED. `idx_scan = 0` on a
  // database that has been running is the most actionable number on this
  // page — an index nothing reads is write cost and disk for nothing — and
  // on a database that has just started it means only that nothing has
  // queried yet. The page draws the distinction; the probe just reports.
  { id: 'indexes', group: 'Schema', shape: 'rows',
    what: 'Every index, how often it has been scanned, how big it is, and ' +
          'whether it is a primary key or unique.',
    sql: 'SELECT s.relname AS table_name, s.indexrelname AS index_name, ' +
         '       s.idx_scan, s.idx_tup_read, s.idx_tup_fetch, ' +
         '       pg_relation_size(s.indexrelid) AS bytes, ' +
         '       pg_size_pretty(pg_relation_size(s.indexrelid)) AS size, ' +
         '       i.indisprimary AS is_primary, i.indisunique AS is_unique, ' +
         '       pg_get_indexdef(s.indexrelid) AS definition ' +
         'FROM pg_stat_user_indexes s ' +
         'JOIN pg_index i ON i.indexrelid = s.indexrelid ' +
         'WHERE s.schemaname = current_schema() ' +
         'ORDER BY s.relname, s.indexrelname' },

  { id: 'columns', group: 'Schema', shape: 'rows',
    what: 'Every column of every table this service owns, with its type, ' +
          'whether it may be null, and its default.',
    sql: 'SELECT table_name, ordinal_position, column_name, ' +
         '       data_type, is_nullable, column_default ' +
         'FROM information_schema.columns ' +
         'WHERE table_schema = current_schema() ' +
         'ORDER BY table_name, ordinal_position' },

  { id: 'constraints', group: 'Schema', shape: 'rows',
    what: 'Primary keys, unique constraints, foreign keys and checks.',
    sql: 'SELECT rel.relname AS table_name, con.conname AS name, ' +
         '       CASE con.contype WHEN \'p\' THEN \'primary key\' ' +
         '                        WHEN \'u\' THEN \'unique\' ' +
         '                        WHEN \'f\' THEN \'foreign key\' ' +
         '                        WHEN \'c\' THEN \'check\' ' +
         '                        ELSE con.contype::text END AS kind, ' +
         '       pg_get_constraintdef(con.oid) AS definition ' +
         'FROM pg_constraint con ' +
         'JOIN pg_class rel ON rel.oid = con.conrelid ' +
         'WHERE con.connamespace = current_schema()::regnamespace ' +
         'ORDER BY rel.relname, con.conname' },

  // -------------------------------------------------------------------------
  // HOW IT IS CONFIGURED.
  //
  // **THE SETTINGS ARE THE ONES AN OPERATOR CHANGED, plus a named handful.**
  // There are 375 of them on PostgreSQL 18 and a page that drew all of them
  // would be a page nobody reads — which is the `audit.js` argument about a
  // list long enough to scroll. `source NOT IN ('default', 'override')` is
  // postgres's own answer to "what did somebody set", so the list is the
  // server's judgement rather than this file's.
  // -------------------------------------------------------------------------
  { id: 'settings', group: 'Configuration', shape: 'rows',
    what: 'Every setting an operator has changed from its built-in default, ' +
          'and where it was set — plus the handful that matter whether or ' +
          'not anybody touched them.',
    sql: 'SELECT name, setting, unit, source, boot_val, pending_restart FROM ' +
         'pg_settings WHERE source NOT IN (\'default\', \'override\')    OR ' +
         'name IN (\'max_connections\', \'shared_buffers\',                ' +
         '\'work_mem\', \'maintenance_work_mem\',                ' +
         '\'effective_cache_size\', \'wal_level\',                ' +
         '\'synchronous_commit\', \'fsync\',                ' +
         '\'full_page_writes\', \'autovacuum\',                ' +
         '\'checkpoint_timeout\', \'max_wal_size\',                \'ssl\', ' +
         '\'data_checksums\',                ' +
         '\'default_transaction_isolation\',                ' +
         '\'statement_timeout\', \'idle_in_transaction_session_timeout\') ' +
         'ORDER BY name' },

  { id: 'extensions', group: 'Configuration', shape: 'rows',
    what: 'Extensions installed in this database.',
    sql: 'SELECT extname AS name, extversion AS version, ' +
         '       n.nspname AS schema ' +
         'FROM pg_extension e JOIN pg_namespace n ON n.oid = e.extnamespace ' +
         'ORDER BY extname' }
];

// The claim scope a stable origin is held under (`adoptOrigin()`).
const ORIGIN_SCOPE = 'persistence.origin';

function create(options) {
  const url = options.url;
  const log = options.log;

  // RISK ROWS (#62) in the shapes `risk/risk_store.ts` works in: camelCase,
  // times as numbers, an `inet` as its text.
  function riskDatasetFrom(r) {
    log.debug("Entering riskDatasetFrom().");
    log.debug("Leaving riskDatasetFrom().");
    return { realm: r.realm, dataset: r.dataset, kind: r.kind,
             activeVersion: r.active_version,
             previousVersion: r.previous_version, state: r.state,
             updatedAt: Number(r.updated_at) || 0 };
  }

  function riskVersionFrom(r) {
    log.debug("Entering riskVersionFrom().");
    log.debug("Leaving riskVersionFrom().");
    return { realm: r.realm, dataset: r.dataset, version: r.version,
             format: r.format, provider: r.provider, licence: r.licence,
             attribution: r.attribution, source: r.source,
             sourceUri: r.source_uri, sha256: r.sha256,
             byteCount: Number(r.byte_count) || 0,
             rowCount: Number(r.row_count) || 0,
             parameters: r.parameters || {},
             verification: r.verification,
             publishedAt: Number(r.published_at) || 0,
             nextUpdateAt: Number(r.next_update_at) || 0,
             fetchedAt: Number(r.fetched_at) || 0,
             loadedAt: Number(r.loaded_at) || 0,
             activatedAt: Number(r.activated_at) || 0,
             supersededAt: Number(r.superseded_at) || 0,
             rowsDeletedAt: Number(r.rows_deleted_at) || 0,
             state: r.state, refusal: r.refusal, errorCode: r.error_code,
             origin: r.origin };
  }

  function riskRangeFrom(kind, r) {
    log.debug("Entering riskRangeFrom(). kind=" + kind);
    const out = { start: String(r.range_start), end: String(r.range_end) };
    if (kind === 'geo') {
      Object.assign(out, {
        locationId: Number(r.location_id) || 0, continent: r.continent,
        country: r.country, subdivision: r.subdivision, city: r.city,
        registeredCountry: r.registered_country,
        latitude: r.latitude === null ? null : Number(r.latitude),
        longitude: r.longitude === null ? null : Number(r.longitude),
        accuracyKm: Number(r.accuracy_km) || 0,
        anonymousProxy: !!r.anonymous_proxy, satellite: !!r.satellite });
    } else if (kind === 'asn') {
      Object.assign(out, { asn: Number(r.asn) || 0, asOrg: r.as_org,
                           asDomain: r.as_domain });
    } else {
      Object.assign(out, { category: r.category, note: r.note });
    }
    log.debug("Leaving riskRangeFrom().");
    return out;
  }

  function riskFailureFrom(r) {
    log.debug("Entering riskFailureFrom().");
    log.debug("Leaving riskFailureFrom().");
    return { id: String(r.id), realm: r.realm, at: Number(r.at) || 0,
             door: r.door, subject: r.subject, nameHmac: r.name_hmac,
             addressSealed: r.address_sealed,
             addressPrefix: String(r.address_prefix),
             asn: Number(r.asn) || 0, errorCode: r.error_code,
             origin: r.origin };
  }

  // A stored used-assertion row in the shape `common/used_assertions.js` works
  // in. `bigint` columns arrive from `pg` as STRINGS, because a 64-bit integer
  // does not fit a double in general; every time here does, so they are
  // numbers from here on.
  function usedRowFrom(row) {
    log.debug("Entering usedRowFrom().");
    log.debug("Leaving usedRowFrom().");
    return {
      format: row.format, use: row.used_as, issuer: row.issuer,
      identifier: row.identifier, clientId: row.client_id,
      subject: row.subject, state: row.state, origin: row.origin,
      usedAt: Number(row.used_at) || 0, spentAt: Number(row.spent_at) || 0,
      expiresAt: Number(row.expires_at) || 0
    };
  }

  if (!url) {
    // ---------------------------------------------------------------------
    // ONLY REACHABLE BY SETTING IT EMPTY ON PURPOSE, since 2026-08-27.
    //
    // `persistence.databaseUrl` has a default now — the local development
    // string that matches this repository's docker-compose.yml — so the
    // ordinary "I turned postgres on and configured nothing" run no longer
    // arrives here; it attempts a connection to localhost and reports what
    // that says, with persistence.js naming this setting on the way past.
    // See the block above that row in common/config.js for why the empty
    // default was the wrong call and what replacing it cost.
    //
    // The check is KEPT because an operator can still write `databaseUrl: ''`
    // or `STS_DATABASE_URL=`, and "postgres mode with no connection string" is
    // a clearer thing to be told than whatever `pg` makes of an empty one.
    // Thrown from create() rather than open(), so persistence.js's one catch
    // reports it before anything has been restored.
    // ---------------------------------------------------------------------
    throw new Error(errorCodes.tag('STS-STORE-0027') +
                    'persistence.mode is "postgres" but ' +
                    'persistence.databaseUrl is empty — it has been set to ' +
                    'nothing explicitly, since it has a default. Set it, or ' +
                    'STS_DATABASE_URL, to a connection string ' +
                    '(postgres://user:password@host:5432/database), or unset ' +
                    'it to fall back to the local development default.');
  }

  let Pool;
  let Client;
  try {
    // REQUIRED LAZILY, and that is the point: `pg` is a dependency only this
    // mode needs, and a person running `persistence.mode=ldif` — or the default
    // memory mode, which is everybody who has not asked for any of this —
    // must not be stopped by its absence. The message names the package,
    // because "Cannot find module 'pg'" arriving out of a mock identity
    // service is a sentence with no obvious cause.
    Pool = require('pg').Pool;
    // AND THE BARE CLIENT, for the `LISTEN` connection. A pooled client cannot
    // hold a subscription — the pool hands it to the next caller — so the
    // change listener needs a connection outside the pool. Same lazy require
    // and the same reason.
    Client = require('pg').Client;
  } catch (err) {
    throw new Error(errorCodes.tag('STS-STORE-0028') +
                    'persistence.mode is "postgres" but the "pg" package is ' +
                    'not installed (' + err.message + '). Run `npm install` ' +
                    'in this package, or use persistence.mode=ldif, which ' +
                    'needs nothing but a directory to write in.');
  }

  // ---------------------------------------------------------------------
  // TLS, AND THE TWO HALVES OF IT THAT LIVE IN DIFFERENT PLACES.
  //
  // ENCRYPTION is `sslmode` in the connection string, which is postgres's own
  // spelling and which `pg` parses for itself — `?sslmode=require` is in the
  // compose default, and the database refuses a plaintext connection anyway
  // because every `host` rule in its pg_hba.conf is `hostssl`. Nothing here
  // has to do anything for that to work.
  //
  // TRUST is not expressible in a connection string as far as `pg` is
  // concerned: `rejectUnauthorized` is a TLS option. So it is a setting, and
  // it is applied HERE rather than pushed into the URL, where it would be
  // silently ignored.
  //
  // THE OPTION IS ONLY SET WHEN sslmode ASKED FOR TLS. Passing `ssl` to `pg`
  // turns TLS on regardless of the URL, so setting it unconditionally would
  // make `sslmode=disable` mean its opposite — a connection string saying one
  // thing and the client doing another, which is the shape of bug this whole
  // change exists to remove.
  const wantsTls = /[?&]sslmode=(require|verify-ca|verify-full|prefer)/i
    .test(url);
  const verify = !!options.verifyTls;
  if (wantsTls) {
    log.info('persistence: the database connection is TLS (sslmode in the ' +
             'connection string), and the server certificate is ' +
             (verify ? 'VERIFIED against this process\'s trust anchors.'
                     : 'NOT verified — ' +
                       'persistence.databaseTlsRejectUnauthorized is off, ' +
                       'which is the honest setting for the self-signed pair ' +
                       'the compose stack generates. The connection is ' +
                       'encrypted either way.'));
  } else {
    log.warn('persistence: the database connection string does not ask for ' +
             'TLS (no sslmode=require). The compose stack\'s database ' +
             'REFUSES a plaintext connection, so this will fail to connect ' +
             'there; against another database it will connect in the clear.');
  }

  // ONE DECIDER, AND A FAILED CONNECTION IS WHY.
  //
  // `pg` parses `sslmode` out of the connection string ITSELF and builds an
  // `ssl` config from it — so a string carrying `sslmode=require` and an
  // explicit `ssl: { rejectUnauthorized: false }` beside it are two answers to
  // one question, and the string's won: the first run of this against the
  // compose stack died with `self-signed certificate` despite the option
  // saying not to verify.
  //
  // So the `sslmode` parameter is STRIPPED before the string reaches `pg`, and
  // this driver configures the TLS. The parameter is still what the connection
  // string SAYS — it is read above to decide whether TLS is wanted at all, and
  // it is what an operator writes — but there is exactly one place that turns
  // it into a socket option, which is what stops the two disagreeing again.
  const dialled = (function () {
    if (!wantsTls) {
      return url;
    }
    try {
      const parsed = new URL(url);
      parsed.searchParams.delete('sslmode');
      return parsed.toString();
    } catch (e) {
      log.debug("Caught in a callback in create(): " + ((e && e.message) || e));
      // A libpq keyword/value string rather than a URL. `pg` accepts those and
      // this cannot edit one safely, so it is passed through untouched and
      // whatever it says about ssl is what happens.
      log.debug('persistence: the connection string is not a URL, so its ' +
                'sslmode was left as it is.');
      return url;
    }
  })();

  // ONE PLACE THE CONNECTION IS DESCRIBED, because the pool and the change
  // listener have to dial the same database the same way — and a listener that
  // quietly used different TLS settings from the pool would be a second,
  // weaker connection to the same store that nothing would ever report.
  function clientOptions() {
    log.debug("Entering clientOptions().");
    log.debug("Leaving clientOptions().");
    return {
      connectionString: dialled,
      ssl: wantsTls ? { rejectUnauthorized: verify } : undefined,
      connectionTimeoutMillis: 5000
    };
  }

  const pool = new Pool({
    connectionString: dialled,
    ssl: wantsTls ? { rejectUnauthorized: verify } : undefined,
    // Small on purpose. Every query this driver makes is on the flush path,
    // there is one flush at a time by construction (persistence.js serialises
    // them), and a mock does not need a connection per core.
    max: 4,
    // A mock must not hang waiting for a database that is not there: the
    // failure has to arrive as a logged error and a service that keeps
    // answering, which needs the connection attempt to give up.
    connectionTimeoutMillis: 5000,
    idleTimeoutMillis: 30000
  });

  pool.on('error', function (err) {
    // A pooled client that died while idle. Logged rather than thrown — an
    // unhandled 'error' on a Pool is a process exit, and a mock identity
    // service must not exit because a database restarted.
    log.error(errorCodes.tag('STS-STORE-0030') +
              'persistence: an idle postgres client errored: ' + err.message +
              '. The pool will make a new one on the next write.');
  });

  // WHO THIS PROCESS IS. It is stamped on every `sts_changes` row and on every
  // notification, and it does ONE job: letting a process skip its own writes
  // instead of applying its own work back over itself.
  //
  // **A RANDOM UUID SINCE 2026-09-14 (#46), AND THE PID IS KEPT ONLY AS A
  // PREFIX FOR A PERSON READING THE LOG.** It was `pid-Date.now()`, which was
  // written against "two containers can hold the same pid" and did not finish
  // the thought: identical containers start the same processes in the same
  // order, so they DO hold the same pids, and two started in the same
  // millisecond would share an origin. That failure is silent and permanent —
  // `changesSince()`'s callers skip "their own" rows, so each would drop the
  // other's writes for ever, and `merge: 'own'` counters would overwrite each
  // other under one key. A UUID makes it unreachable rather than unlikely.
  //
  // **A PROCESS THAT RESTARTS UNDER A STABLE NAME TAKES ITS ORIGIN BACK
  // (2026-09-18)** — see `adoptOrigin()` below. The random value here is what
  // a process uses when it has no stable name, or when the name is still held
  // by a live process, which is exactly the case the paragraph above guards.
  let processId = String(process.pid) + '-' + nodeCrypto.randomUUID();
  // The claim this process holds on a stable origin, or null.
  let originClaim = null;

  // ---------------------------------------------------------------------
  // THE FENCE (2026-09-14, #46), installed by `cluster/cluster.js`.
  //
  // A function answering `{ nodeId, leases: [{ name, token }] }` for the write
  // about to happen, or null for "no cluster". When it answers, EVERY
  // transaction this driver opens checks it before running anything else:
  // the node's row must still be live, and every named lease must still be
  // held by this node AT THAT TOKEN — under a SHARE lock on the lease row, so a
  // takeover cannot commit between the check and this transaction's COMMIT.
  //
  // `onFenced` is what happens when the check fails, and cluster.js makes it
  // an exit: a process that has lost its right to write and keeps running is a
  // process that will try again on the next change, and the one after.
  // ---------------------------------------------------------------------
  let fence = null;
  let onFenced = null;
  // What to do when the ORIGIN fence fails outside a cluster (a cluster's
  // `onFenced` decides it inside one). Installed by persistence.js.
  let onOriginLost = null;

  // `reason` is `node` (the membership is gone — fatal for every process of
  // the node) or `lease` (one role was lost — fatal only to the write that
  // needed it, unless the role is the service itself). cluster.js decides.
  function fenced(reason, message, lost) {
    log.debug("Entering fenced().");
    const err = /** @type {any} */ (
      new Error(errorCodes.tag('STS-CLUSTER-0001') + message));
    err.fenced = true;
    err.reason = reason;
    err.lost = lost || [];
    log.debug("Leaving fenced().");
    return err;
  }

  // ---------------------------------------------------------------------
  // THE ORIGIN FENCE (2026-09-18). A process that ADOPTED a stable origin
  // holds a claim on it (`adoptOrigin()`), and every transaction checks the
  // claim is still its own — under a SHARE lock held to COMMIT, so a
  // successor cannot take the origin between the check and the write. That
  // is what makes a shared origin safe: a process paused past its claim's
  // lifetime wakes to find its writes refused, rather than overwriting the
  // rows its successor has taken over.
  // ---------------------------------------------------------------------
  function checkOriginFence(client) {
    log.debug("Entering checkOriginFence().");
    if (!originClaim) {
      log.debug("Leaving checkOriginFence(). No claim.");
      return Promise.resolve();
    }
    const held = originClaim;
    log.debug("Leaving checkOriginFence().");
    return client.query(
      'SELECT 1 FROM sts_cluster_claims WHERE scope = $1 AND realm = \'\' ' +
      'AND key = $2 AND reservation = $3 AND expires_at > ' + DB_NOW +
      ' FOR SHARE', [ORIGIN_SCOPE, held.key, held.reservation]
    ).then(function (r) {
      if (r.rowCount) {
        return null;
      }
      // -------------------------------------------------------------------
      // LAPSED IS NOT TAKEN (2026-09-21). The claim's time ran out, but that
      // alone does not mean another process holds it: a process that TAKES
      // the claim replaces its reservation, in one statement on this row. So
      // when the row still carries OUR reservation nobody wrote under this
      // origin in between, and extending it is exactly as safe as the
      // renewal that should have happened — which is what this does, inside
      // the write's own transaction. Only a reservation that is somebody
      // else's is fenced.
      //
      // Found in the suite's first product-mode run: a single process under
      // the SCIM bulk load could not get one of its 4 pooled connections
      // for two renewals in a row, the claim lapsed with nobody else
      // anywhere, the next write was fenced, and the process EXITED saying
      // another process held its origin (STS-STORE-0061) — which killed the
      // service for the last three jobs.
      // -------------------------------------------------------------------
      return reassertOrigin(client, held).then(function (still) {
        if (!still) {
          throw fenced('origin', 'this process no longer holds its origin ' +
                       held.key + ' (another process took it after the ' +
                       'claim lapsed), so it may not write.');
        }
        return null;
      });
    });
  }

  // The claim extended while the row still carries this process's
  // reservation, lapsed or not: true when it did, false when another process
  // has taken the claim (and so replaced the reservation). One statement, so a
  // claimant racing it either wins first (and this matches nothing) or finds
  // a live claim and is refused. `runner` is a client inside a transaction, or
  // the pool.
  function reassertOrigin(runner, held) {
    log.debug("Entering reassertOrigin().");
    log.debug("Leaving reassertOrigin().");
    return runner.query(
      'UPDATE sts_cluster_claims SET expires_at = ' + DB_NOW + ' + $4 ' +
      'WHERE scope = $1 AND realm = \'\' AND key = $2 AND reservation = $3',
      [ORIGIN_SCOPE, held.key, held.reservation,
       Math.max(1000, Number(held.ttlMs) || 30000)]
    ).then(function (r) {
      // DEBUG, by rcbj's rule (2026-09-21): it is only reached for a claim
      // that really lapsed, which says renewals are running late — worth
      // having when somebody asks for the whole record, not at info.
      if (r.rowCount) {
        log.debug('persistence: the claim on origin ' + held.key +
                  ' had lapsed with nobody else taking it, and was extended.');
      }
      return r.rowCount > 0;
    });
  }

  function checkFence(client) {
    log.debug("Entering checkFence().");
    log.debug("Leaving checkFence().");
    return checkOriginFence(client).then(function () {
      return checkClusterFence(client);
    });
  }

  function checkClusterFence(client) {
    log.debug("Entering checkClusterFence().");
    const wanted = fence ? fence() : null;
    if (!wanted || !wanted.nodeId) {
      log.debug("Leaving checkClusterFence(). No fence.");
      return Promise.resolve();
    }
    const leases = (wanted.leases || []).filter(function (one) {
      return one && one.name;
    });
    log.debug("Leaving checkClusterFence(). The node and " + leases.length +
              " lease(s).");
    // THE MEMBERSHIP FIRST, unlocked: a node row is only ever renewed by its
    // own heartbeat, so there is no takeover of it to race.
    return client.query(
      'SELECT 1 FROM sts_cluster_nodes WHERE node_id = $1 AND ' +
      'left_at = 0 AND expires_at > ' + DB_NOW, [wanted.nodeId]
    ).then(function (r) {
      if (!r.rowCount) {
        throw fenced('node', 'this node\'s membership row (' +
                     wanted.nodeId + ') has expired or been left, so it may ' +
                     'not write.');
      }
      if (!leases.length) {
        return null;
      }
      // THE LEASES UNDER A SHARE LOCK, held to COMMIT: a takeover is an UPDATE
      // of the lease row, so it waits for this transaction and cannot land
      // between the check and the write.
      return client.query(
        'SELECT l.name FROM sts_cluster_leases l ' +
        'JOIN unnest($2::text[], $3::bigint[]) AS w(name, token) ' +
        '  ON l.name = w.name AND l.token = w.token ' +
        'WHERE l.holder = $1 AND l.expires_at > ' + DB_NOW + ' ' +
        'FOR SHARE OF l',
        [wanted.nodeId,
         leases.map(function (one) { return String(one.name); }),
         leases.map(function (one) { return String(one.token); })]
      ).then(function (locked) {
        const names = (locked.rows || []).map(function (row) {
          return row.name;
        });
        const lost = leases.filter(function (one) {
          return names.indexOf(one.name) < 0;
        });
        if (lost.length) {
          throw fenced('lease', 'this node (' + wanted.nodeId + ') no ' +
                       'longer holds ' + lost.map(function (one) {
                         return one.name + '@' + one.token;
                       }).join(', ') + ', so it may not write.', lost);
        }
        return null;
      });
    });
  }

  // ---------------------------------------------------------------------
  // THE CHANGE LOG, WRITTEN INSIDE SOMEBODY ELSE'S TRANSACTION.
  //
  // It takes the CLIENT rather than using the pool, and that is the whole
  // point: the log row and the data row commit together or neither does. A
  // helper that used the pool would open a second connection outside the
  // transaction, and the two would be able to disagree in the one direction
  // that matters — a committed change with no log entry is a change no other
  // process will ever hear about.
  //
  // The NOTIFY goes out in the same transaction too. Postgres holds notifies
  // until commit by definition, so a rolled-back transaction wakes nobody,
  // which is exactly right and costs nothing to arrange.
  // ---------------------------------------------------------------------
  // HOW MANY CHANGE ROWS THIS PROCESS HAS WRITTEN. A local counter and not a
  // query: `common/request_worker.ts` needs to know whether its flush actually
  // wrote anything, and asking the database that after every request is a round
  // trip for a question this process already knows the answer to.
  //
  // **COUNTED AT COMMIT, NOT AT INSERT (2026-09-13).** It was `written +=
  // rows.length` here, before the INSERT was even sent — so a transaction
  // still open, or one about to roll back, had already moved the count. Two
  // readers depend on it meaning COMMITTED and both were wrong by it: a worker
  // reads it either side of its flush to say whether it `wrote`, and one that
  // waited on another transaction's commit could find the count already moved
  // before it sampled and report `wrote: false` for a write it had just
  // waited for; and `request_pool.js`'s noteLocalWrites() moved the read
  // generation for rows no other process could fetch yet. So a transaction's
  // rows are held against its CLIENT and added only once COMMIT has returned.
  let written = 0;
  const uncommittedRows = new WeakMap();

  function recordChanges(client, rows) {
    log.debug("Entering recordChanges().");
    if (!rows || !rows.length) {
      log.debug("Leaving recordChanges().");
      return Promise.resolve();
    }
    if (uncommittedRows.has(client)) {
      uncommittedRows.set(client, uncommittedRows.get(client) + rows.length);
    } else {
      // Not inside withTransaction(): every caller today is, and a statement
      // outside one commits as it runs, so it is counted as it is sent.
      written += rows.length;
    }
    // ONE STATEMENT PER CHUNK. A directory flush can carry hundreds of moved
    // entries and a round trip each would make the log more expensive than
    // the write it describes.
    //
    // **CHUNKED SINCE 2026-09-12**, because one statement for the whole batch
    // has a ceiling: the wire protocol counts bind parameters in 16 bits, and
    // at four per row a batch past 16,383 rows wrapped the count — `bind
    // message has 63088 parameter formats but 0 parameters`. A minted flush
    // that had failed for a while reached that size, and so can a directory
    // flush after a large bulk load.
    let chain = Promise.resolve();
    for (let start = 0; start < rows.length; start +=
        CHANGE_ROWS_PER_STATEMENT) {
      const chunk = rows.slice(start, start + CHANGE_ROWS_PER_STATEMENT);
      chain = chain.then(function () {
        const values = [];
        const params = [];
        chunk.forEach(function (row, i) {
          const base = i * 4;
          values.push('($' + (base + 1) + ', $' + (base + 2) + ', $' +
                      (base + 3) + ', $' + (base + 4) + ')');
          params.push(processId, row.kind, row.realm || '', row.key || '');
        });
        return client.query(
          'INSERT INTO sts_changes (origin, kind, realm, key) VALUES ' +
          values.join(', '), params
        );
      });
    }
    log.debug("Leaving recordChanges().");
    return chain.then(function () {
      // THE NUDGE. It carries the origin and the kinds and NOT the rows —
      // the receiver reads `sts_changes` for what actually moved, so this
      // can be lossy, can be truncated and can be missed entirely without
      // costing anything but latency. See the header.
      const kinds = [];
      rows.forEach(function (row) {
        if (kinds.indexOf(row.kind) < 0) kinds.push(row.kind);
      });
      return client.query('SELECT pg_notify($1, $2)', [CHANNEL,
        JSON.stringify({ from: processId, kinds: kinds, rows: rows.length })]);
    });
  }


  // ---------------------------------------------------------------------------
  // A CHECKED-OUT CLIENT HAS NO ERROR LISTENER, AND AN UNHANDLED ONE IS A
  // PROCESS EXIT (2026-09-11).
  //
  // `pool.on('error')` above covers a client that dies while IDLE IN THE POOL,
  // and its comment is right about why that matters. **It does not cover a
  // client that is checked out**, and that is not an oversight in this file —
  // it is what `pg-pool` does: `_acquireClient()` calls
  // `client.removeListener('error', idleListener)` as it hands the client
  // over, because from that moment the borrower owns it.
  //
  // So a connection that dies while somebody is holding it emits `'error'` on
  // an EventEmitter with no listener, and node's rule for that is to throw —
  // **taking this service down**. Measured: `docker stop` on the database
  // while a page was reading from it exited the process with
  // `Unhandled 'error' event ... 57P01 terminating connection due to
  // administrator command`. A mock identity service must not exit because a
  // database restarted, which is exactly what the idle handler above says.
  //
  // **IT IS A HAZARD IN THE WRITE PATH TOO AND HAS BEEN SINCE THIS DRIVER WAS
  // WRITTEN.** `withTransaction()` borrows a client for every flush, so a
  // database restarted during one took the service with it; the failure was
  // just far rarer than a page somebody opens. Both call sites are wrapped
  // now, which is why this is a function rather than two lines.
  //
  // The listener is REMOVED before release. Leaving it attached would leak one
  // per checkout onto a client the pool reuses — node warns at eleven — and
  // would sit alongside the idle listener pg puts back, so one dead connection
  // would be reported twice.
  // ---------------------------------------------------------------------------
  function guardClient(client, what) {
    log.debug("Entering guardClient().");
    const onError = function (err) {
      log.debug("Entering onError().");
      log.error(errorCodes.tag('STS-STORE-0031') +
                'persistence: the postgres connection held by ' + what +
                ' errored: ' + err.message + '. It is being discarded; the ' +
                'pool will make another. This is logged rather than thrown ' +
                'because an unhandled error on a client is a process exit, ' +
                'and this service must not die because its database ' +
                'restarted.');
      log.debug("Leaving onError().");
    };
    client.on('error', onError);
    log.debug("Leaving guardClient().");
    return function () {
      client.removeListener('error', onError);
    };
  }

  function withTransaction(fn) {
    log.debug('Entering withTransaction().');
    log.debug("Leaving withTransaction().");
    return pool.connect().then(function (client) {
      const unguard = guardClient(client, 'a transaction');
      // THE CHANGE ROWS THIS TRANSACTION RECORDS, held until COMMIT returns —
      // see `written` above. Keyed by the client, which is what
      // recordChanges() is handed, and removed on both endings so that a
      // client the pool hands to the next transaction starts at nothing.
      uncommittedRows.set(client, 0);
      return client.query('BEGIN').then(function () {
        // THE FENCE FIRST, before the transaction has written anything. See
        // `fence` above.
        return checkFence(client);
      }).then(function () {
        return fn(client);
      }).then(function (result) {
        return client.query('COMMIT').then(function () {
          written += uncommittedRows.get(client) || 0;
          uncommittedRows.delete(client);
          unguard();
          client.release();
          log.debug('Leaving withTransaction(). Committed.');
          return result;
        });
      }).catch(function (err) {
        // NOTHING THIS TRANSACTION RECORDED WAS COMMITTED, so none of it is
        // counted — including a COMMIT that itself failed.
        uncommittedRows.delete(client);
        return client.query('ROLLBACK').catch(function (rollbackErr) {
          // The rollback itself failed, which means the connection is gone.
          // Logged and swallowed: the original error is the one worth
          // reporting, and releasing the client with an error tells the pool
          // to discard rather than reuse it.
          log.warn(errorCodes.tag('STS-STORE-0032') +
                   'persistence: a rollback failed (' + rollbackErr.message +
                   '); the connection is being discarded.');
        }).then(function () {
          unguard();
          client.release(err);
          log.debug('Leaving withTransaction(). Rolled back.');
          if (err && err.fenced && typeof onFenced === 'function') {
            onFenced(err);
          } else if (err && err.fenced && err.reason === 'origin' &&
                     typeof onOriginLost === 'function') {
            // No cluster to decide, and a process that has lost its origin
            // must not go on trying to write under it (`adoptOrigin()`).
            onOriginLost(err);
          }
          throw err;
        });
      });
    });
  }

  return {
    name: 'postgres',

    open: function () {
      log.debug('Entering the postgres driver open().');
      const created = [];
      log.debug("Leaving open().");
      return withTransaction(function (client) {
        // -------------------------------------------------------------
        // WHAT IS ALREADY THERE. One query for the whole list — see the
        // comment on SCHEMA_OBJECTS for why this cannot be left to
        // `IF NOT EXISTS`.
        //
        // `to_regclass` answers NULL rather than raising for a name that
        // does not exist, and it resolves against the search path, which
        // is the same way every other statement in this driver names a
        // table. It needs no privilege of any kind.
        // -------------------------------------------------------------
        const probes = SCHEMA_OBJECTS.map(function (object, index) {
          return 'to_regclass($' + (index + 1) + ') AS o' + index;
        }).join(', ');
        const names = SCHEMA_OBJECTS.map(function (object) {
          return object.name;
        });
        return client.query('SELECT ' + probes, names).then(function (result) {
          const row = result.rows[0] || {};
          const missing = SCHEMA_OBJECTS.filter(function (object, index) {
            return !row['o' + index];
          });
          if (!missing.length) {
            log.debug('open(): every object in the schema is present; no ' +
                      'CREATE is issued.');
            return null;
          }
          log.info('persistence: the postgres store is missing ' +
                   missing.length + ' object(s) (' +
                   missing.map(function (o) { return o.name; }).join(', ') +
                   ') and this process is creating them. A store built by ' +
                   'postgres/schema.sql needs none of this.');
          let chain = Promise.resolve();
          missing.forEach(function (object) {
            chain = chain.then(function () {
              return client.query(object.statement).then(function () {
                created.push(object.name);
              });
            });
          });
          return chain;
        }).then(function () {
          // The columns, after the tables they belong to exist.
          return client.query(
            'SELECT table_name, column_name FROM information_schema.columns ' +
            'WHERE table_schema = current_schema() AND ' +
            '(table_name, column_name) IN (' +
            SCHEMA_COLUMNS.map(function (one, index) {
              return '($' + (2 * index + 1) + ', $' + (2 * index + 2) + ')';
            }).join(', ') + ')',
            [].concat.apply([], SCHEMA_COLUMNS.map(function (one) {
              return [one.table, one.column];
            }))).then(function (result) {
            const present = new Set(result.rows.map(function (row) {
              return row.table_name + '.' + row.column_name;
            }));
            let chain = Promise.resolve();
            SCHEMA_COLUMNS.forEach(function (one) {
              const name = one.table + '.' + one.column;
              if (present.has(name)) {
                return;
              }
              chain = chain.then(function () {
                return client.query(one.statement).then(function () {
                  created.push(name);
                });
              });
            });
            return chain;
          });
        }).then(function () {
          // DML, and the one statement here that runs on every open. The
          // script writes this row too; `ON CONFLICT DO NOTHING` is what
          // makes running both harmless.
          return client.query(
            'INSERT INTO sts_schema (version) VALUES ($1) ' +
            'ON CONFLICT (version) DO NOTHING', [SCHEMA_VERSION]);
        });
      }).catch(function (err) {
        // -------------------------------------------------------------
        // 42501 IS insufficient_privilege, AND IT IS THE ONE FAILURE HERE
        // THAT HAS AN ANSWER WORTH PRINTING.
        //
        // It means the schema is not built and the role dialling cannot
        // build it — which is the correct arrangement the wrong way round:
        // somebody pointed the service at an empty database with the
        // least-privileged role. The message names the script rather than
        // the statement, because "permission denied for schema sts"
        // arriving out of a mock identity service names nothing an
        // operator can act on.
        //
        // Rethrown either way: persistence.js treats a failed open as
        // FATAL, deliberately (see its CLAUDE.md), and this changes what
        // is SAID and not what happens.
        // -------------------------------------------------------------
        if (err && (err.code === '42501' || err.code === '42P01')) {
          throw new Error(errorCodes.tag('STS-STORE-0029') +
                          'persistence: the postgres store could not be ' +
                          'opened — ' + err.message + '. This role may not ' +
                          'create what is missing, which is how it is meant ' +
                          'to be: build the schema once with ' +
                          'postgres/schema.sql, run by a superuser or by the ' +
                          'owner of the database (the compose stack does it ' +
                          'through postgres/apply-schema.sh, on the start ' +
                          'that creates the cluster — an OLD VOLUME has ' +
                          'neither the schema nor the role, and `docker ' +
                          'compose down -v` is the answer). If the objects ' +
                          'ARE there, check the search path: this driver ' +
                          'names them unqualified, and the script sets it on ' +
                          'the database.');
        }
        throw err;
      }).then(function () {
        log.info('persistence: the postgres store is open; schema version ' +
                 SCHEMA_VERSION + ' is present' +
                 (created.length
                   ? ' (this process created ' + created.join(', ') + ')'
                   : ' and this process created none of it') +
                 '. NOTE that this is ' +
                 'PERSISTENCE and not COORDINATION — a second process ' +
                 'pointed at this database will not see this one\'s writes ' +
                 'until it restarts.');
        log.debug('Leaving the postgres driver open().');
      });
    },

    // =====================================================================
    // THE METRICS, FOR `/admin/database` (2026-09-11).
    //
    // **IT IS HERE AND NOT IN THE CONSOLE BECAUSE THIS MODULE OWNS THE
    // POOL.** `admin-ui/` must never hold a connection string — it is a
    // credential — and must never require `pg`, which is a dependency only
    // this mode needs and which `persistence.js` takes care to require
    // lazily. So the console asks `persistence.databaseMetrics()`, that
    // function asks the active driver, and only a driver that HAS a database
    // answers.
    //
    // ---------------------------------------------------------------------
    // ONE CLIENT, A STATEMENT TIMEOUT, AND EVERY PROBE CAUGHT SEPARATELY.
    //
    // Three decisions, and each is about what must not happen to a service
    // because somebody opened a page:
    //
    //   * **ONE CLIENT FOR THE WHOLE RENDER**, checked out once and released
    //     once. The pool's `max` is 4 and this service answers protocol
    //     traffic out of the same pool, so nineteen separate `pool.query()`
    //     calls would be nineteen checkouts racing every other caller.
    //   * **`statement_timeout` IS SET ON THAT CLIENT**, from
    //     `persistence.metricsTimeoutMs`. These are catalog reads and they
    //     are fast, but `pg_stat_activity` on a busy server and
    //     `pg_total_relation_size` over a large schema are not free, and a
    //     console page must not be able to pin a connection. It is `SET`
    //     rather than `SET LOCAL` because there is no transaction — and the
    //     client is RESET on the way out so the setting cannot escape into
    //     the next caller that borrows it.
    //   * **EACH PROBE IS RUN, TIMED AND CAUGHT ON ITS OWN.** The role this
    //     service dials with is not `pg_monitor`, and which views that
    //     narrows depends on the server's version and the operator's grants.
    //     One rejection must cost one row on the page rather than the page.
    //
    // **NOTHING HERE IS COMPOSED FROM A REQUEST.** Every statement is a
    // literal in `METRIC_PROBES`; the only thing that varies is which probes
    // ran. There is no query box on that page and there must never be one —
    // this role can write.
    // =====================================================================
    metrics: function (options) {
      log.debug('Entering the postgres driver metrics().');
      const opts = options || {};
      const timeoutMs = Math.max(250, Number(opts.timeoutMs) || 5000);
      const began = Date.now();
      const out = { ok: true, probes: {}, pool: null, tookMs: 0 };

      // THE POOL'S OWN NUMBERS, which are this PROCESS's and are not in any
      // catalog view: postgres can say how many backends exist and only `pg`
      // can say how many of them this process is holding, how many are idle
      // in its pool, and how many callers are queued for one. A page drawing
      // only the server's side would answer "how contended is this service's
      // database handle" with a number about somebody else.
      //
      // **SAMPLED BEFORE THIS FUNCTION CHECKS A CLIENT OUT**, so the figures
      // are what the pool was doing when somebody asked rather than what it
      // is doing because they asked. A sample taken afterwards would include
      // this page's own connection and report a pool one busier than it is —
      // which on a `max` of 4 is a quarter of it, invented by the act of
      // looking.
      out.pool = {
        total: pool.totalCount,
        idle: pool.idleCount,
        waiting: pool.waitingCount,
        max: pool.options && pool.options.max
      };

      log.debug("Leaving metrics().");
      return pool.connect().then(function (client) {
        const unguard = guardClient(client, 'the metrics page');
        return client.query('SET statement_timeout = ' + timeoutMs)
          .catch(function (err) {
            // Swallowed with a reason: a server that refuses to set a
            // statement timeout is a server this page can still report on,
            // and the probes below are bounded by the pool's own
            // connectionTimeout in any case. It is recorded so the page can
            // say the bound is not in force.
            out.timeoutSet = false;
            out.timeoutError = err.message;
          })
          .then(function () {
            if (out.timeoutSet !== false) {
              out.timeoutSet = true;
            }
            let chain = Promise.resolve();
            METRIC_PROBES.forEach(function (probe) {
              chain = chain.then(function () {
                const started = Date.now();
                return client.query(probe.sql).then(function (result) {
                  out.probes[probe.id] = {
                    ok: true,
                    group: probe.group,
                    what: probe.what,
                    shape: probe.shape,
                    // A `row` probe that matched nothing answers null rather
                    // than an empty object, so "no such row" and "a row of
                    // zeroes" stay different facts.
                    row: probe.shape === 'row' ? (result.rows[0] || null) :
                         null,
                    rows: probe.shape === 'rows' ? result.rows : null,
                    count: result.rows.length,
                    tookMs: Date.now() - started
                  };
                }).catch(function (err) {
                  out.probes[probe.id] = {
                    ok: false,
                    group: probe.group,
                    what: probe.what,
                    shape: probe.shape,
                    // `code` is postgres's SQLSTATE and is worth more than
                    // the message to anybody diagnosing this: 42P01 is "no
                    // such relation" (a view this server version does not
                    // have) and 42501 is "insufficient privilege" (a grant
                    // this role does not hold), and those are completely
                    // different things to do something about.
                    error: err.message,
                    code: err.code || '',
                    expected: probe.expected || null,
                    tookMs: Date.now() - started
                  };
                  log.debug('metrics(): the "' + probe.id + '" probe failed: ' +
                            err.message);
                });
              });
            });
            return chain;
          })
          .then(function () {
            // RESET rather than setting the timeout back to a value this
            // function guessed: `RESET ALL` puts the session back to what the
            // server and the connection string say, which is the only
            // definition of "as we found it" that stays right when somebody
            // changes either.
            return client.query('RESET ALL').catch(function (err) {
              log.warn(errorCodes.tag('STS-STORE-0033') +
                       'persistence: a metrics connection could not be reset ' +
                       '(' + err.message + '); it is being discarded rather ' +
                       'than returned to the pool with a statement timeout ' +
                       'on it.');
              out.resetFailed = true;
            });
          })
          .then(function () {
            unguard();
            client.release(out.resetFailed ? new Error('not reset') :
                           undefined);
            out.tookMs = Date.now() - began;
            log.debug('Leaving the postgres driver metrics(). ' +
                      Object.keys(out.probes).length + ' probe(s), ' +
                      out.tookMs + 'ms.');
            return out;
          });
      }).catch(function (err) {
        // THE WHOLE THING FAILED, which means no connection — the database is
        // down, or unreachable, or refusing this role. That is one fact and
        // it is reported as one rather than as nineteen identical probe
        // failures.
        out.ok = false;
        out.error = err.message;
        out.tookMs = Date.now() - began;
        log.warn(errorCodes.tag('STS-STORE-0034') +
                 'persistence: the database metrics could not be collected: ' +
                 err.message);
        return out;
      });
    },

    close: function () {
      log.debug('Entering the postgres driver close().');
      log.debug("Leaving close().");
      return pool.end().then(function () {
        log.debug('Leaving the postgres driver close().');
      });
    },

    loadDirectory: function () {
      log.debug('Entering the postgres driver loadDirectory().');
      log.debug("Leaving loadDirectory().");
      return pool.query(
        'SELECT realm, dn, attrs, origin, created_at, modified_at ' +
        'FROM sts_ldap_entries ORDER BY realm, dn_key'
      ).then(function (result) {
        if (!result.rows.length) {
          log.debug('Leaving loadDirectory(). The table is empty.');
          return null;
        }
        const out = {};
        result.rows.forEach(function (row) {
          if (!out[row.realm]) {
            out[row.realm] = [];
          }
          out[row.realm].push({
            dn: row.dn,
            attributes: row.attrs || {},
            origin: row.origin || undefined,
            createdAt: row.created_at || null,
            modifiedAt: row.modified_at || row.created_at || null
          });
        });
        Object.keys(out).forEach(function (realmId) {
          log.info('persistence: read ' + out[realmId].length + ' entry/ies ' +
                   'for the realm "' + realmId + '" from postgres.');
        });
        log.debug('Leaving loadDirectory(). ' + result.rows.length +
                  ' row(s).');
        return out;
      });
    },

    loadRealms: function () {
      log.debug('Entering the postgres driver loadRealms().');
      log.debug("Leaving loadRealms().");
      return pool.query(
        'SELECT id, name, description, created_at, overrides, domain ' +
        'FROM sts_realms ' +
        'ORDER BY created_at NULLS FIRST, id'
      ).then(function (result) {
        if (!result.rows.length) {
          log.debug('Leaving loadRealms(). The table is empty.');
          return null;
        }
        log.debug('Leaving loadRealms(). ' + result.rows.length + ' realm(s).');
        return result.rows.map(function (row) {
          return {
            id: row.id,
            name: row.name,
            description: row.description,
            domain: row.domain || '',
            // bigint comes back as a STRING from node-postgres, because a
            // 64-bit integer does not fit a JS number. It is an epoch
            // millisecond count, which does, so it is converted here rather
            // than left as a string for realms.js to be surprised by.
            createdAt: row.created_at === null ? null : Number(row.created_at),
            overrides: row.overrides || {}
          };
        });
      });
    },

    loadOverrides: function () {
      log.debug('Entering the postgres driver loadOverrides().');
      log.debug("Leaving loadOverrides().");
      return pool.query('SELECT key, value FROM sts_appconfig')
        .then(function (result) {
          if (!result.rows.length) {
            log.debug('Leaving loadOverrides(). The table is empty.');
            return null;
          }
          const out = {};
          result.rows.forEach(function (row) {
            // The value is stored WRAPPED — `{"raw": …}` — rather than as a
            // bare JSONB scalar, and the reason is that config.js keeps an
            // override RAW: a boolean set from a form is the string "true" and
            // the same setting from a file is `true`, and both must come back
            // as what they were. A bare jsonb column would round-trip that
            // correctly too; the wrapper is what makes it possible to add a
            // second field later (who set it, when) without a migration.
            out[row.key] = row.value && typeof row.value === 'object' &&
                           'raw' in row.value ? row.value.raw : row.value;
          });
          log.debug('Leaving loadOverrides(). ' + result.rows.length +
                    ' override(s).');
          return out;
        });
    },

    // ONE TRANSACTION for the whole diff, and a NOTIFY at the end of it. See
    // the header for both.
    //
    // -----------------------------------------------------------------------
    // **AND A MERGE, NOT AN OVERWRITE, SINCE 2026-09-14 (#46 section 3).**
    //
    // The upsert was `ON CONFLICT DO UPDATE SET attrs = EXCLUDED.attrs`, which
    // is right for one process — the shadow it diffed against IS the row — and
    // wrong for two: of two nodes that each added a member to one group, the
    // one that committed second wrote its whole copy over the other's, and one
    // member left the group on every node with nothing failing. Two adds of one
    // DN replaced each other the same way, password hash included.
    //
    // So an upsert that carries `base` (what the diff compared against: the
    // shadow's JSON, or null when this process believed the DN empty) is
    // three-way merged with the row as it is NOW, read under `FOR UPDATE` in
    // this transaction — `persistence/directory_merge.js` argues the rules.
    // What the merge decided that this process does not already hold comes back
    // as `outcomes`, which `persistence.js` applies to the live directory and
    // the shadow. An upsert without `base` (a caller from before this, and
    // every test double) is written the old way.
    //
    // **ONE LOCK ORDER FOR EVERY FLUSH, OR TWO NODES DEADLOCK.** Every existing
    // row this flush touches is locked by ONE statement, ordered by the primary
    // key, before anything is written; a new row is then inserted in the same
    // order. A flush therefore holds no lock when it starts taking them and
    // takes them in the order every other flush does, which is
    // `saveMinted()`'s argument one table over. An insert that finds its row
    // committed by somebody else in the meantime (`ON CONFLICT DO NOTHING`
    // answering no row) locks it and merges again.
    // -----------------------------------------------------------------------
    saveDirectory: function (change) {
      log.debug('Entering the postgres driver saveDirectory().');
      const outcomes = [];
      const idOf = function (realm, key) {
        return String(realm) + '\n' + String(key);
      };
      const byKey = function (a, b) {
        const left = idOf(a.realm, a.key);
        const right = idOf(b.realm, b.key);
        if (left === right) {
          return 0;
        }
        return left < right ? -1 : 1;
      };
      const merging = change.upserts.filter(function (row) {
        return row.base !== undefined;
      }).sort(byKey);
      const blind = change.upserts.filter(function (row) {
        return row.base === undefined;
      });
      log.debug("Leaving saveDirectory().");
      return withTransaction(function (client) {
        let chain = Promise.resolve();
        const moved = [];
        const stored = new Map();

        const entryOf = function (row) {
          return {
            dn: row.dn,
            attributes: row.attrs || {},
            origin: row.origin || undefined,
            createdAt: row.created_at || null,
            modifiedAt: row.modified_at || row.created_at || null
          };
        };
        const params = function (row, entry) {
          return [row.realm, row.key, entry.dn,
                  JSON.stringify(entry.attributes || {}),
                  entry.origin || null, entry.createdAt || null,
                  entry.modifiedAt || null];
        };
        const update = function (row, entry) {
          moved.push({ realm: row.realm, dn: row.key, op: 'put' });
          return client.query(
            'UPDATE sts_ldap_entries SET dn = $3, attrs = $4::jsonb, ' +
            'origin = $5, created_at = $6, modified_at = $7 ' +
            'WHERE realm = $1 AND dn_key = $2', params(row, entry));
        };
        // What the merge decided, turned into a statement and an outcome.
        // `again` is false on the second look after a lost insert race, so a
        // row that keeps vanishing cannot loop.
        const settle = function (row, theirs, again) {
          const base = row.base ? JSON.parse(row.base) : null;
          const verdict = directoryMerge.mergeEntry(base, row.entry, theirs);
          if (verdict.outcome === 'theirs' || verdict.outcome === 'deleted') {
            outcomes.push({ realm: row.realm, key: row.key,
                            outcome: verdict.outcome, entry: verdict.entry });
            return null;
          }
          if (verdict.outcome === 'merged') {
            outcomes.push({ realm: row.realm, key: row.key,
                            outcome: 'merged', entry: verdict.entry });
          }
          if (theirs) {
            return update(row, verdict.entry);
          }
          return client.query(
            'INSERT INTO sts_ldap_entries ' +
            '  (realm, dn_key, dn, attrs, origin, created_at, modified_at) ' +
            'VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7) ' +
            'ON CONFLICT (realm, dn_key) DO NOTHING',
            params(row, verdict.entry)
          ).then(function (r) {
            if (r && r.rowCount) {
              moved.push({ realm: row.realm, dn: row.key, op: 'put' });
              return null;
            }
            if (!again) {
              // Committed by another node between the lock and the insert,
              // twice. Written as it is rather than lost; the next flush
              // merges against whatever is there.
              return update(row, verdict.entry);
            }
            return client.query(
              'SELECT realm, dn_key, dn, attrs, origin, created_at, ' +
              'modified_at FROM sts_ldap_entries ' +
              'WHERE realm = $1 AND dn_key = $2 FOR UPDATE',
              [row.realm, row.key]
            ).then(function (found) {
              const now = (found.rows || [])[0];
              // The merge was recorded against `theirs` = null; forget it.
              for (let i = outcomes.length - 1; i >= 0; i--) {
                if (outcomes[i].realm === row.realm &&
                    outcomes[i].key === row.key) {
                  outcomes.splice(i, 1);
                }
              }
              return settle(row, now ? entryOf(now) : null, false);
            });
          });
        };

        // THE LOCKS, in one statement per chunk and in primary-key order.
        const locking = merging.concat(change.deletes.slice(0).sort(byKey));
        for (let at = 0; at < locking.length;
             at += CHANGE_ROWS_PER_STATEMENT) {
          const chunk = locking.slice(at, at + CHANGE_ROWS_PER_STATEMENT);
          chain = chain.then(function () {
            return client.query(
              'SELECT realm, dn_key, dn, attrs, origin, created_at, ' +
              'modified_at FROM sts_ldap_entries ' +
              'WHERE (realm, dn_key) IN ' +
              '(SELECT r, k FROM unnest($1::text[], $2::text[]) AS u(r, k)) ' +
              'ORDER BY realm, dn_key FOR UPDATE',
              [chunk.map(function (row) { return String(row.realm); }),
               chunk.map(function (row) { return String(row.key); })]
            ).then(function (r) {
              (r.rows || []).forEach(function (found) {
                stored.set(idOf(found.realm, found.dn_key), entryOf(found));
              });
            });
          });
        }

        merging.forEach(function (row) {
          chain = chain.then(function () {
            return settle(row, stored.get(idOf(row.realm, row.key)) || null,
                          true);
          });
        });

        blind.forEach(function (row) {
          chain = chain.then(function () {
            // **`row.key` AND NOT `row.entry.dn` (2026-09-07).** A change row
            // is a POINTER, and the receiver dereferences it with
            // `readEntry(realm, key)` — which is `WHERE dn_key = $2`, the
            // NORMALISED dn. `row.entry.dn` is the DN as written, so every
            // upsert pointed at a key that column never holds: the receiver
            // looked it up, MISSED, concluded the entry had been deleted, and
            // called `removeEntry()` — actively removing the entry it had just
            // been told to add. (The merging path above records `row.key` for
            // the same reason.)
            moved.push({ realm: row.realm, dn: row.key, op: 'put' });
            return client.query(
              'INSERT INTO sts_ldap_entries ' +
              '  (realm, dn_key, dn, attrs, origin, created_at, modified_at) ' +
              'VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7) ' +
              'ON CONFLICT (realm, dn_key) DO UPDATE SET ' +
              '  dn = EXCLUDED.dn, attrs = EXCLUDED.attrs, ' +
              '  origin = EXCLUDED.origin, created_at = EXCLUDED.created_at, ' +
              '  modified_at = EXCLUDED.modified_at',
              params(row, row.entry));
          });
        });

        change.deletes.forEach(function (row) {
          chain = chain.then(function () {
            moved.push({ realm: row.realm, dn: row.key, op: 'delete' });
            return client.query(
              'DELETE FROM sts_ldap_entries WHERE realm = $1 AND dn_key = $2',
              [row.realm, row.key]);
          });
        });

        // A REALM THAT WENT AWAY takes its rows with it. The per-row deletes
        // above already cover every row this process knew about; this catches
        // rows written by an earlier run of this process that the current
        // shadow never saw, which is the difference between "the realm is
        // gone" and "the realm is gone as far as I remember".
        //
        // **ONLY A REALM THIS PROCESS REMOVED (2026-09-14, #46).** This list
        // was every realm in the shadow that the live registry no longer held
        // — and a realm another node created, whose entries had replicated
        // here before its registry row did, is exactly that. So a realm
        // created on B and a flush on A in the window deleted B's realm, its
        // directory and everything it had minted, on every node.
        // `persistence.js` now names only the realms `realms.remove()` was
        // called for in this process.
        change.removedRealms.forEach(function (realmId) {
          chain = chain.then(function () {
            return client.query('DELETE FROM sts_ldap_entries WHERE realm = $1',
                                [realmId]);
          });
          chain = chain.then(function () {
            return client.query('DELETE FROM sts_realms WHERE id = $1',
                                [realmId]);
          });
          // ---------------------------------------------------------------
          // AND EVERYTHING THAT REALM MINTED (2026-09-07). Until this, a
          // removed realm's sessions, tokens, authorization codes, artifacts,
          // Kerberos principals and audit rows STAYED in `sts_minted` — the
          // two lines above took its directory and its registry row and left
          // the rest — and the only thing that ever collected them was the
          // `persistence.mintedRetention` sweep, seven days later, by age.
          //
          // **THE LEAK WAS NOT THE POINT; THE RESTORE WAS.** Every one of
          // those rows is read back at the next start, so a realm that had
          // been deleted came back holding live sessions and redeemable
          // authorization codes belonging to a realm that no longer exists.
          //
          // `realm` IS THE SECOND COLUMN OF THE PRIMARY KEY (handle, realm,
          // key), so this is the one query in this driver a primary key
          // cannot serve and it scans. That is deliberate rather than an
          // oversight: an index on `realm` would be paid for by every INSERT
          // into the busiest table here — measured at about a third of the
          // insert cost for an index of this shape — to speed up an operator
          // action that happens by hand. A scan is the right side of that
          // trade, and this comment is here so the next person weighing it
          // has the measurement rather than the intuition.
          // ---------------------------------------------------------------
          chain = chain.then(function () {
            return client.query('DELETE FROM sts_minted WHERE realm = $1',
                                [realmId]);
          });
        });

        return chain.then(function () {
          // ONE LOG ROW PER MOVED ENTRY, and the old 50-entry `capped` flag is
          // gone with the payload it protected. It existed because Postgres
          // refuses a notification over 8000 bytes, so a bulk import had to
          // send "something moved, reload everything" instead of a list —
          // which was the weakest part of the old seam. Now the rows are in
          // `sts_changes` and the notification carries nothing but a nudge,
          // so a batch of five thousand is an ordinary batch of five thousand.
          return recordChanges(client, moved.map(function (row) {
            return { kind: 'directory', realm: row.realm, key: row.dn };
          }));
        });
      }).then(function () {
        log.debug('Leaving the postgres driver saveDirectory(). ' +
                  change.upserts.length + ' upsert(s), ' +
                  change.deletes.length + ' delete(s), ' + outcomes.length +
                  ' decided by another node\'s row.');
        return { outcomes: outcomes };
      });
    },

    // -----------------------------------------------------------------------
    // THE REALM REGISTRY, ONE ROW PER REALM THAT MOVED (2026-09-14, #46).
    //
    // It was replaced WHOLESALE: `DELETE … WHERE NOT (id = ANY(<every realm
    // this process holds>))` and an upsert of each. For one process that is
    // exactly the registry, and "a diff would be more code than the thing it
    // optimises" was true. For two it is data loss: a realm created on B, then
    // ANY realm change saved on A before B's row had replicated, deleted B's
    // realm — and a setting changed on one realm in B was put back by A's
    // upsert of the copy A held.
    //
    // So `persistence.js` hands a DELTA beside the rows: `upserts` names only
    // the realms that changed and, for each, whether its name and description
    // moved and which overrides were set and which cleared; `removed` names
    // the realms `realms.remove()` was called for here. The overrides are
    // merged IN SQL — `(stored - cleared) || set` — so a setting another node
    // wrote to the same realm survives. **A ROW IS NEVER DELETED BECAUSE IT IS
    // ABSENT FROM THIS PROCESS'S COPY.**
    //
    // Called without a delta (a test double, or a driver's caller from before
    // this), every row given is upserted whole and nothing is deleted.
    // -----------------------------------------------------------------------
    saveRealms: function (rows, delta) {
      log.debug('Entering the postgres driver saveRealms().');
      const upserts = delta && Array.isArray(delta.upserts) ? delta.upserts
        : (rows || []).map(function (row) {
          return { row: row, name: true, description: true,
                   set: row.overrides || {}, cleared: [], whole: true };
        });
      const removed = delta && Array.isArray(delta.removed) ? delta.removed
        : [];
      log.debug("Leaving saveRealms().");
      return withTransaction(function (client) {
        let chain = Promise.resolve();
        removed.forEach(function (id) {
          chain = chain.then(function () {
            return client.query('DELETE FROM sts_realms WHERE id = $1', [id]);
          });
        });
        upserts.forEach(function (one) {
          const row = one.row;
          chain = chain.then(function () {
            return client.query(
              'INSERT INTO sts_realms (id, name, description, created_at, ' +
              'overrides, domain) VALUES ($1, $2, $3, $4, $5::jsonb, $11) ' +
              'ON CONFLICT (id) DO UPDATE SET ' +
              // FIXED AT CREATION, so the first value written stays.
              '  domain = COALESCE(sts_realms.domain, EXCLUDED.domain), ' +
              '  name = CASE WHEN $6 THEN EXCLUDED.name ' +
              '              ELSE sts_realms.name END, ' +
              '  description = CASE WHEN $7 THEN EXCLUDED.description ' +
              '                     ELSE sts_realms.description END, ' +
              '  created_at = COALESCE(sts_realms.created_at, ' +
              '                        EXCLUDED.created_at), ' +
              '  overrides = CASE WHEN $10 THEN EXCLUDED.overrides ELSE ' +
              '    (COALESCE(sts_realms.overrides, \'{}\'::jsonb) - ' +
              '     $8::text[]) || $9::jsonb END',
              [row.id, row.name, row.description, row.createdAt,
               JSON.stringify(row.overrides || {}), !!one.name,
               !!one.description, (one.cleared || []).map(String),
               JSON.stringify(one.set || {}), !!one.whole,
               row.domain || null]);
          });
        });
        return chain.then(function () {
          if (!upserts.length && !removed.length) {
            return null;
          }
          // ONE LOG ROW FOR THE REGISTRY, as before: the applier re-reads the
          // whole table (a handful of rows) and merges what it finds.
          return recordChanges(client, [{ kind: 'realms' }]);
        });
      }).then(function () {
        log.debug('Leaving the postgres driver saveRealms(). ' +
                  upserts.length + ' realm(s) written, ' + removed.length +
                  ' removed.');
      });
    },

    // -----------------------------------------------------------------------
    // THE PROCESS-WIDE OVERRIDES, KEY BY KEY (2026-09-14, #46), for
    // saveRealms()'s reason: `DELETE … WHERE NOT (key = ANY(<this process's
    // keys>))` removed a setting another node had just written. `delta.set` is
    // what this process set or changed and `delta.cleared` what it cleared —
    // a reset-all clears every key this process knew was stored — and nothing
    // else is touched. Without a delta, the map is upserted and nothing is
    // deleted.
    // -----------------------------------------------------------------------
    saveOverrides: function (map, delta) {
      log.debug('Entering the postgres driver saveOverrides().');
      const set = delta && delta.set ? delta.set : (map || {});
      const cleared = delta && Array.isArray(delta.cleared) ? delta.cleared
        : [];
      log.debug("Leaving saveOverrides().");
      return withTransaction(function (client) {
        let chain = Promise.resolve();
        if (cleared.length) {
          chain = chain.then(function () {
            return client.query(
              'DELETE FROM sts_appconfig WHERE key = ANY($1::text[])',
              [cleared.map(String)]);
          });
        }
        Object.keys(set).forEach(function (key) {
          chain = chain.then(function () {
            return client.query(
              'INSERT INTO sts_appconfig (key, value) VALUES ($1, ' +
              '$2::jsonb) ON CONFLICT (key) DO UPDATE SET value = ' +
              'EXCLUDED.value',
              [key, JSON.stringify({ raw: set[key] })]);
          });
        });
        return chain.then(function () {
          if (!cleared.length && !Object.keys(set).length) {
            return null;
          }
          return recordChanges(client, [{ kind: 'appconfig' }]);
        });
      }).then(function () {
        log.debug('Leaving the postgres driver saveOverrides(). ' +
                  Object.keys(set).length + ' set, ' + cleared.length +
                  ' cleared.');
      });
    },

    // -----------------------------------------------------------------------
    // THE KEY MATERIAL. See the CREATE TABLE above for why a column of text is
    // the right shape and why this driver never holds a private key.
    // -----------------------------------------------------------------------
    loadKeys: function () {
      log.debug('Entering the postgres driver loadKeys().');
      log.debug("Leaving loadKeys().");
      return pool.query('SELECT realm, material FROM sts_keys')
                 .then(function (r) {
        const rows = (r.rows || []).map(function (row) {
          return { realm: row.realm, material: row.material };
        });
        log.debug('Leaving the postgres driver loadKeys(). ' + rows.length +
                  ' realm(s).');
        return rows;
      });
    },

    // A TRANSACTION SINCE 2026-09-06, WHERE IT USED TO BE ONE POOL QUERY, and
    // the only reason is the change log: the log row has to commit with the
    // key or another process can be told about a key that is not there yet.
    // The write itself is unchanged.
    saveKeys: function (realmId, ciphertext) {
      log.debug('Entering the postgres driver saveKeys(). realm=' + realmId);
      log.debug("Leaving saveKeys().");
      return withTransaction(function (client) {
        return client.query(
          'INSERT INTO sts_keys (realm, material, written_at) ' +
          'VALUES ($1, $2, now()) ' +
          'ON CONFLICT (realm) DO UPDATE SET material = EXCLUDED.material, ' +
          'written_at = now()',
          [realmId, ciphertext]
        ).then(function () {
          return recordChanges(client, [{ kind: 'keys', realm: realmId }]);
        });
      }).then(function () {
        log.debug('Leaving the postgres driver saveKeys().');
      });
    },

    // **A TRANSACTION WITH A CHANGE ROW SINCE 2026-09-14 (#46)**, where it was
    // one pool statement that told nobody. A rotation and a removed hierarchy
    // are DELETEs, and a node that never heard of one went on signing with the
    // key the operator threw away — so the delete is logged like every other
    // write to this table, and `keystore.applyStoredChange()` on every other
    // node reads the row gone.
    deleteKeys: function (realmId) {
      log.debug('Entering the postgres driver deleteKeys(). realm=' + realmId);
      log.debug("Leaving deleteKeys().");
      return withTransaction(function (client) {
        return client.query('DELETE FROM sts_keys WHERE realm = $1',
                            [realmId])
          .then(function (r) {
            if (!r.rowCount) {
              return null;
            }
            return recordChanges(client, [{ kind: 'keys', realm: realmId }]);
          });
      }).then(function () {
        log.debug('Leaving the postgres driver deleteKeys().');
      });
    },

    // -----------------------------------------------------------------------
    // WHAT THIS PROCESS MINTED. Three functions, and the middle one is the
    // only place in this driver that writes rows it did not compute a diff
    // for — `persistence_minted.js` hands it exactly the rows that moved, so
    // there is nothing here to work out.
    // -----------------------------------------------------------------------
    loadMinted: function () {
      log.debug('Entering the postgres driver loadMinted().');
      log.debug("Leaving loadMinted().");
      return pool.query(
        'SELECT handle, realm, key, body,        (extract(epoch from ' +
        'written_at) * 1000)::bigint AS written_ms FROM sts_minted ' +
        'WHERE body <> $1', [TOMBSTONE]
      ).then(function (r) {
        const rows = (r.rows || []).map(function (row) {
          return {
            handle: row.handle,
            realm: row.realm,
            key: row.key,
            body: row.body,
            // A NUMBER of milliseconds rather than a Date, because the one
            // reader compares it against `Date.now()` and a driver that
            // answered a Date would make the ldif driver — which has no
            // timestamptz — answer something different for the same field.
            writtenAt: Number(row.written_ms || 0)
          };
        });
        log.debug('Leaving the postgres driver loadMinted(). ' + rows.length +
                  ' row(s).');
        return rows;
      });
    },

    // ONE TRANSACTION FOR THE WHOLE BATCH, for `saveDirectory()`'s reason: a
    // request that ended a session and started another must not be able to
    // land half-written. It is a SEPARATE transaction from the directory's,
    // which `persistence.js` argues where it calls this.
    saveMinted: function (upserts, deletes) {
      log.debug('Entering the postgres driver saveMinted(). ' +
                upserts.length + ' upsert(s), ' + deletes.length +
                ' delete(s).');
      // **IN ONE ORDER, BY PRIMARY KEY, UPSERTS AND DELETES INTERLEAVED
      // (2026-09-12).** Each statement takes a row lock that is held to COMMIT,
      // and every request worker flushes into this table at once. The
      // statements went in journal order — upserts, then deletes — so two
      // workers touching the same two rows could each lock one and wait on the
      // other: `deadlock detected`, about a hundred and twelve times in one
      // dispatched run. Every one of those failed the whole flush, put its keys
      // back, and made the next flush bigger. Sorting on (handle, realm, key)
      // gives every transaction the same lock order, which is what makes a
      // cycle impossible rather than rare. Compared as code units rather than
      // with `localeCompare()`, because the order has to be the same in every
      // process whatever its locale.
      const statements = upserts.map(function (row) {
        return { row: row, upsert: true };
      }).concat(deletes.map(function (row) {
        return { row: row, upsert: false };
      })).sort(function (a, b) {
        const left = [a.row.handle, a.row.realm, a.row.key].map(String);
        const right = [b.row.handle, b.row.realm, b.row.key].map(String);
        for (let i = 0; i < 3; i++) {
          if (left[i] !== right[i]) {
            return left[i] < right[i] ? -1 : 1;
          }
        }
        return 0;
      });
      // ---------------------------------------------------------------------
      // TWO KINDS OF ROW DECLARED BY THEIR STORE (2026-09-14, #46 section 3),
      // and a row of either is written in the same lock order as the rest:
      //
      //   * `tombstone` — a delete leaves TOMBSTONE behind and an upsert of a
      //     key holding one does nothing and is reported in `refused`, so a
      //     node holding an old copy cannot put back a session, a code or a
      //     token another node ended. See TOMBSTONE above.
      //   * `merge(storedBody)` — an in-place edit two nodes can make to one
      //     row (a session's relying-party lists, its upgrade from an arrival
      //     to a sign-in). The row is read `FOR UPDATE`, handed to the store's
      //     merge (which opens, merges and seals — this driver never holds a
      //     key), and what comes back is written and reported in `merged` for
      //     the caller to apply to its own copy.
      // ---------------------------------------------------------------------
      const refused = [];
      const merged = [];
      const skip = new Set();
      log.debug("Leaving saveMinted().");
      return withTransaction(function (client) {
        let chain = Promise.resolve();
        const upsert = function (row, body, guarded) {
          return client.query(
            'INSERT INTO sts_minted (handle, realm, key, body, ' +
            'written_at) VALUES ($1, $2, $3, $4, now()) ON CONFLICT ' +
            '(handle, realm, key) DO UPDATE SET   body = EXCLUDED.body, ' +
            'written_at = now()' +
            (guarded ? ' WHERE sts_minted.body <> $5' : ''),
            guarded ? [row.handle, row.realm, row.key, body, TOMBSTONE]
                    : [row.handle, row.realm, row.key, body]
          ).then(function (r) {
            if (guarded && !(r && r.rowCount)) {
              refused.push(row);
              skip.add(row);
            }
            return r;
          });
        };
        statements.forEach(function (one) {
          const row = one.row;
          chain = chain.then(function () {
            if (one.upsert && typeof row.merge === 'function') {
              return client.query(
                'SELECT body FROM sts_minted WHERE handle = $1 AND ' +
                'realm = $2 AND key = $3 FOR UPDATE',
                [row.handle, row.realm, row.key]
              ).then(function (r) {
                const found = (r.rows || [])[0];
                if (found && found.body === TOMBSTONE) {
                  refused.push(row);
                  skip.add(row);
                  return null;
                }
                let body = row.body;
                if (found && found.body !== row.body) {
                  const answer = row.merge(found.body);
                  if (answer && answer !== row.body) {
                    body = answer;
                    merged.push({ handle: row.handle, realm: row.realm,
                                  key: row.key, journalKey: row.journalKey,
                                  body: answer });
                  }
                }
                return upsert(row, body, true);
              });
            }
            if (one.upsert) {
              return upsert(row, row.body, !!row.tombstone);
            }
            if (row.tombstone) {
              return client.query(
                'INSERT INTO sts_minted (handle, realm, key, body, ' +
                'written_at) VALUES ($1, $2, $3, $4, now()) ON CONFLICT ' +
                '(handle, realm, key) DO UPDATE SET body = EXCLUDED.body, ' +
                'written_at = now()',
                [row.handle, row.realm, row.key, TOMBSTONE]
              );
            }
            return client.query(
              'DELETE FROM sts_minted WHERE handle = $1 AND realm = $2 ' +
              'AND key = $3',
              [row.handle, row.realm, row.key]
            );
          });
        });
        return chain.then(function () {
          // A LOG ROW PER MINTED KEY, upserts and deletes alike — the receiver
          // re-reads `sts_minted` for each and applies what it finds, or
          // removes what it does not, so the two cases need no distinction
          // here. A change row names ONE key and a minted row is identified by
          // the PAIR, so the two are packed into it.
          //
          // **THE SEPARATOR WAS A LITERAL NUL UNTIL 2026-09-07, AND
          // `sts_changes.key` IS `text`.** PostgreSQL refuses a NUL in text, so
          // this INSERT failed — and it is the last statement in the minted
          // transaction, which means the sealed rows written just above it were
          // rolled back too. Every minted flush was lost, reported once as
          // `invalid byte sequence for encoding "UTF8": 0x00` and then as "the
          // service is unaffected", which it was: it went on answering from
          // memory, alone, which is exactly what a request worker pool cannot
          // do. This is the same mistake `storedKey()` made and the second
          // place it was made.
          //
          // base64url both halves, joined with '.', which is not in that
          // alphabet — same encoding as `storedKey()`, for the same reason, and
          // nothing to migrate because no row in the old shape was ever
          // committed.
          return recordChanges(client,
                               upserts.filter(function (row) {
                                 // A REFUSED UPSERT CHANGED NOTHING, so it
                                 // tells nobody anything.
                                 return !skip.has(row);
                               }).concat(deletes).map(function (row) {
            // `minted-own` IS A SECOND KIND AND NOT A FLAG, because the only
            // thing that reads it is a `WHERE kind <> …` on the barrier's
            // target — see latestBlockingChangeSeq(). A column would have had
            // to be added to `sts_changes` and indexed; a kind is already
            // there and already selected on.
            return { kind: row.own ? 'minted-own' : 'minted', realm: row.realm,
                     key: Buffer.from(String(row.handle), 'utf8')
                                .toString('base64url') +
                          '.' +
                          Buffer.from(String(row.key), 'utf8')
                                .toString('base64url') };
          }));
        });
      }).then(function () {
        log.debug('Leaving the postgres driver saveMinted(). ' +
                  refused.length + ' refused by a tombstone, ' +
                  merged.length + ' merged.');
        return { refused: refused, merged: merged };
      });
    },

    // -----------------------------------------------------------------------
    // WHAT A READER ACTUALLY HAS TO WAIT FOR (2026-09-07).
    //
    // `latestChangeSeq()` is every row, and the read barrier used it — so a
    // reader waited for the whole change log including the STATISTICS. One
    // dispatch run wrote 115,945 minted change rows, and the three busiest
    // stores in it (`admin_stats.users`, `admin_stats.calls`,
    // `admin_stats.artifacts`) are all `merge: 'own'`: per-process tallies that
    // every process keeps its own of and the console sums when somebody asks.
    // Nobody's correctness waits on them, and waiting on them cost 224 barrier
    // timeouts in one run — every one of which serves a stale answer.
    //
    // So the barrier targets everything EXCEPT `minted-own`. Those rows are
    // still replicated, still applied by the ordinary pull, and still summed on
    // read; they simply do not hold a reader up.
    // -----------------------------------------------------------------------
    // See `written` above.
    changeRowsWritten: function () {
      log.debug("Entering changeRowsWritten().");
      log.debug("Leaving changeRowsWritten().");
      return written;
    },

    latestBlockingChangeSeq: function () {
      log.debug("Entering latestBlockingChangeSeq().");
      log.debug("Leaving latestBlockingChangeSeq().");
      // ---------------------------------------------------------------------
      // AND NOT THIS PROCESS'S OWN ROWS (2026-09-08). `changesSince()` above
      // filters `origin <> processId` — a process never re-applies what it
      // wrote — so counting its own rows here sets a target the pull can never
      // reach: `changesSince()` answers nothing, `applied` stays put, and
      // `syncNow()`'s loop burns its whole bound before giving up.
      //
      // The log said so precisely and it took five give-ups to read it: "gave
      // up at 10303 of 10304", "30414 of 30415", "60280 of 60281" — every one
      // exactly ONE change short, which is the shape of a target that includes
      // a row the reader is defined never to fetch. It happens whenever the
      // newest change in the log is this worker's own, which after any write
      // it just served is most of the time.
      //
      // The cost was not incorrectness — a process that wrote the newest change
      // HAS it — but a full barrier bound added to reads on the worker that had
      // just written, which under a loaded suite is exactly the latency that
      // pushes something else past its own deadline.
      // ---------------------------------------------------------------------
      return pool.query(
        "SELECT COALESCE(MAX(seq), 0) AS seq FROM sts_changes " +
        "WHERE kind <> 'minted-own' AND origin <> $1",
        [processId]
      ).then(function (r) { return Number((r.rows[0] || {}).seq) || 0; });
    },

    // -----------------------------------------------------------------------
    // MANY MINTED ROWS IN ONE ROUND TRIP (2026-09-07).
    //
    // `readMinted()` above answers ONE row, and the applier called it once per
    // change — which was affordable only while minted rows never reached the
    // change log at all. They do now, and they are the overwhelming majority of
    // it: one measured dispatch run held 5,452 minted changes against 460
    // directory ones, because a session, a token and an authorization code are
    // each a row and a browser flow mints several.
    //
    // Catching up was therefore up to 500 SEQUENTIAL queries per page, which is
    // seconds — and `workers.readYourWrite` gives a worker 5000ms to catch up
    // before it gives up and serves what it has. So the barrier timed out, the
    // worker answered from a directory it had not caught up on, and a test that
    // had just created an application through /admin-api was told there was no
    // such application. **The volume was not the defect; the round trips
    // were.**
    //
    // A VALUES join rather than `IN (...)`: the key is a triple, and this keeps
    // one bind per column per row instead of building a composite string that
    // both ends would have to agree how to escape.
    // -----------------------------------------------------------------------
    readMintedMany: function (refs) {
      log.debug('Entering the postgres driver readMintedMany(). ' +
                (refs || []).length + ' ref(s).');
      const list = (refs || []);
      if (!list.length) {
        log.debug("Leaving readMintedMany().");
        return Promise.resolve([]);
      }
      const values = [];
      const binds = [];
      list.forEach(function (ref, i) {
        values.push('($' + (i * 3 + 1) + '::text, $' + (i * 3 + 2) +
                    '::text, $' + (i * 3 + 3) + '::text)');
        binds.push(String(ref.handle), String(ref.realm), String(ref.key));
      });
      log.debug("Leaving readMintedMany().");
      return pool.query(
        'SELECT m.handle, m.realm, m.key, m.body, ' +
        '(extract(epoch from m.written_at) * 1000)::bigint AS written_ms ' +
        'FROM sts_minted m JOIN (VALUES ' + values.join(', ') +
        ') AS w(handle, realm, key) ' +
        'ON m.handle = w.handle AND m.realm = w.realm AND m.key = w.key',
        binds
      ).then(function (res) {
        const rows = (res.rows || []).filter(function (row) {
          return row.body !== TOMBSTONE;
        }).map(function (row) {
          return { handle: row.handle, realm: row.realm, key: row.key,
                   body: row.body, writtenAt: Number(row.written_ms) || 0 };
        });
        log.debug('Leaving the postgres driver readMintedMany(). ' +
                  rows.length + ' row(s) of ' + list.length + ' asked for.');
        return rows;
      });
    },

    // -----------------------------------------------------------------------
    // THE COORDINATION HALF: READING THE CHANGE LOG, AND BEING WOKEN.
    // -----------------------------------------------------------------------

    // WHO THIS PROCESS IS. Every row this driver writes carries it, and the
    // replication layer skips its own — so this has to be readable from
    // outside the driver rather than only stamped inside it.
    origin: function () {
      log.debug("Entering origin().");
      log.debug("Leaving origin().");
      return processId;
    },

    // -----------------------------------------------------------------
    // A STABLE ORIGIN FOR A PROCESS THAT RESTARTS UNDER THE SAME NAME
    // (2026-09-18).
    //
    // A process's origin was random per start, so a container restarted
    // under the same node name was a NEW origin: everything its previous
    // life wrote to a `merge: 'own'` store (its audit ring, its counters,
    // its share of the users register) became another process's
    // contribution, visible only to readers that fan in and left behind for
    // good. Now a process with a stable `name` (node name and slot) takes
    // the origin `n:<name>` — the one its previous life wrote under — and
    // restores those rows as its own.
    //
    // **ONLY WHILE NOBODY ELSE HOLDS IT.** Two live processes sharing an
    // origin would each skip the other's writes for ever (the paragraph
    // above `processId`), so the origin is taken through a claim in
    // `sts_cluster_claims` that lives `ttlMs` and is renewed. A claim still
    // live is waited out for up to `waitMs` — a crashed predecessor's lapses
    // in that time — and if it is still held after that, this process
    // keeps its random origin and says so. Every transaction then checks the
    // claim (`checkOriginFence()`).
    //
    // Must be called after `open()` and before anything reads `origin()`.
    // -----------------------------------------------------------------
    adoptOrigin: function (opts) {
      log.debug("Entering the postgres driver adoptOrigin().");
      const o = opts || {};
      const name = String(o.name || '').trim();
      if (!name) {
        log.debug("Leaving adoptOrigin(). No stable name.");
        return Promise.resolve({ adopted: false, origin: processId,
                                 why: 'no stable name' });
      }
      const key = 'n:' + name;
      const ttlMs = Math.max(1000, Number(o.ttlMs) || 30000);
      const waitMs = Math.max(0, Number(o.waitMs) || 0);
      const pollMs = Math.max(100, Number(o.pollMs) || 2000);
      const reservation = nodeCrypto.randomUUID();
      const started = Date.now();
      const self = this;
      function attempt() {
        return self.claimOnce(ORIGIN_SCOPE, '', key, {
          ttlMs: ttlMs, reservation: reservation
        }).then(function (answer) {
          if (answer.claimed) {
            processId = key;
            originClaim = { key: key, reservation: reservation, ttlMs: ttlMs };
            return { adopted: true, origin: key,
                     waitedMs: Date.now() - started };
          }
          if (Date.now() - started + pollMs > waitMs) {
            return { adopted: false, origin: processId,
                     why: 'held by a live process (' +
                       ((answer.existing && answer.existing.origin) || '?') +
                       ')' };
          }
          return new Promise(function (resolve) {
            setTimeout(resolve, pollMs);
          }).then(attempt);
        });
      }
      log.debug("Leaving the postgres driver adoptOrigin().");
      return attempt();
    },

    // The claim renewed; false when it is no longer this process's.
    renewOrigin: function (ttlMs) {
      log.debug("Entering the postgres driver renewOrigin().");
      if (!originClaim) {
        log.debug("Leaving renewOrigin(). No claim.");
        return Promise.resolve(true);
      }
      log.debug("Leaving the postgres driver renewOrigin().");
      // By the RESERVATION, not by the claim still being live (2026-09-21): a
      // renewal that could not reach the store in time finds the claim
      // lapsed, and a lapse nobody took is still this process's — see
      // checkOriginFence(). It asked `AND expires_at > now()` until then, so
      // one late renewal read as "another process holds it" and the process
      // exited in a single-process stack.
      //
      // **THE LIVE CLAIM FIRST, AND QUIETLY (the same day).** A renewal went
      // straight to `reassertOrigin()`, whose "had lapsed with nobody else
      // taking it" line is only true when the claim HAD lapsed — so every
      // routine renewal logged it: every request worker, every ten seconds,
      // about a lapse that never happened. The ordinary renewal is the update
      // that needs the claim still live; only when that matches nothing is
      // the claim extended by its reservation, and said so.
      const held = { key: originClaim.key,
                     reservation: originClaim.reservation, ttlMs: ttlMs };
      return pool.query(
        'UPDATE sts_cluster_claims SET expires_at = ' + DB_NOW + ' + $4 ' +
        'WHERE scope = $1 AND realm = \'\' AND key = $2 AND reservation = $3 ' +
        'AND expires_at > ' + DB_NOW,
        [ORIGIN_SCOPE, held.key, held.reservation,
         Math.max(1000, Number(ttlMs) || 30000)]
      ).then(function (r) {
        return r.rowCount > 0 ? true : reassertOrigin(pool, held);
      });
    },

    setOriginLost: function (fn) {
      log.debug("Entering setOriginLost().");
      onOriginLost = typeof fn === 'function' ? fn : null;
      log.debug("Leaving setOriginLost().");
    },

    // Given back at a clean stop, so a restart takes it at once.
    releaseOrigin: function () {
      log.debug("Entering the postgres driver releaseOrigin().");
      if (!originClaim) {
        log.debug("Leaving releaseOrigin(). No claim.");
        return Promise.resolve(false);
      }
      const held = originClaim;
      originClaim = null;
      log.debug("Leaving the postgres driver releaseOrigin().");
      return this.releaseClaim(ORIGIN_SCOPE, '', held.key, held.reservation);
    },

    // The high-water mark at startup. A process that has just RESTORED the
    // whole store is, by definition, up to date with everything committed
    // before this instant — so it starts from here rather than from 0 and
    // does not re-apply the entire history of the deployment on the way up.
    latestChangeSeq: function () {
      log.debug('Entering the postgres driver latestChangeSeq().');
      log.debug("Leaving latestChangeSeq().");
      return pool.query('SELECT COALESCE(MAX(seq), 0) AS seq FROM sts_changes')
        .then(function (r) {
          const seq = Number((r.rows[0] || {}).seq || 0);
          log.debug('Leaving the postgres driver latestChangeSeq(). ' + seq);
          return seq;
        });
    },

    // Everything another process committed after `afterSeq`, oldest first.
    // ORDER MATTERS AND IS THE POINT: two writes to one key have to be applied
    // in the order they were committed, or the loser of a race wins on the
    // reader. `seq` is the commit order, which is why it is a bigserial
    // assigned inside the transaction rather than a timestamp taken by
    // whichever process happened to be writing.
    //
    // **`limit` IS A REAL CEILING AND THE CALLER HAS TO HANDLE IT.** A process
    // that was down for an hour has an hour of log to catch up on, and reading
    // it in one query would be a multi-second stall on the event loop that
    // owns every socket in this service. The caller takes a page, applies it,
    // and comes straight back for the next.
    changesSince: function (afterSeq, limit) {
      log.debug('Entering the postgres driver changesSince(). after=' +
                afterSeq);
      log.debug("Leaving changesSince().");
      // ---------------------------------------------------------------------
      // EVERY ROW, INCLUDING THIS PROCESS'S OWN (2026-09-08).
      //
      // It used to filter `origin <> $2`, and that filter was hiding the one
      // thing the caller has to be able to see: a HOLE in the sequence.
      //
      // `seq` is allocated when a row is INSERTED and the row becomes visible
      // when its transaction COMMITS, and those two orders are not the same.
      // A poller that reads at the moment seq 105 is visible and seq 103 is
      // still in flight takes 105, advances its watermark to it, and never
      // asks for 103 again — because it only ever asks for `seq > watermark`.
      // The row is committed a moment later and is skipped FOREVER, silently,
      // with no failure to count and a watermark that looks healthy.
      //
      // That is what left one worker of three permanently missing a directory
      // entry that was committed in the store: asked nine times, the same
      // group answered "100 of 100" twice and "99 of 100" seven times.
      //
      // With the filter gone the sequence is contiguous, so `pull()` can tell
      // "this seq was mine" from "this seq has not committed yet" and wait for
      // the second. `applyRows()` skips this process's own rows itself — it
      // always did — so nothing is applied twice.
      // ---------------------------------------------------------------------
      return pool.query(
        'SELECT seq, origin, kind, realm, key FROM sts_changes ' +
        'WHERE seq > $1 ORDER BY seq ASC LIMIT $2',
        [Number(afterSeq) || 0, Number(limit) || 500]
      ).then(function (r) {
        const rows = (r.rows || []).map(function (row) {
          return { seq: Number(row.seq), origin: row.origin, kind: row.kind,
                   realm: row.realm, key: row.key };
        });
        log.debug('Leaving the postgres driver changesSince(). ' + rows.length +
                  ' row(s).');
        return rows;
      });
    },

    // The HIGHEST seq in the log regardless of origin, so a catch-up loop can
    // tell "I read a full page and there is more" from "I am up to date"
    // without a second query per page.
    changeCeiling: function () {
      log.debug("Entering changeCeiling().");
      log.debug("Leaving changeCeiling().");
      return pool.query('SELECT COALESCE(MAX(seq), 0) AS seq FROM sts_changes')
        .then(function (r) { return Number((r.rows[0] || {}).seq || 0); });
    },

    // One directory entry, for the applier. It re-reads rather than being sent
    // the row, which is what lets the notification carry nothing.
    readEntry: function (realmId, dnKey) {
      log.debug("Entering readEntry().");
      log.debug("Leaving readEntry().");
      return pool.query(
        'SELECT realm, dn_key, dn, attrs, origin, created_at, modified_at ' +
        'FROM sts_ldap_entries WHERE realm = $1 AND dn_key = $2',
        [realmId, dnKey]
      ).then(function (r) {
        const row = (r.rows || [])[0];
        if (!row) {
          return null;
        }
        return { realm: row.realm, key: row.dn_key, entry: {
          dn: row.dn, attributes: row.attrs || {}, origin: row.origin,
          createdAt: row.created_at, modifiedAt: row.modified_at } };
      });
    },

    // One minted row, same reason.
    readMinted: function (handle, realmId, key) {
      log.debug("Entering readMinted().");
      log.debug("Leaving readMinted().");
      return pool.query(
        'SELECT handle, realm, key, body,        (extract(epoch from ' +
        'written_at) * 1000)::bigint AS written_ms FROM sts_minted WHERE ' +
        'handle = $1 AND realm = $2 AND key = $3',
        [handle, realmId, key]
      ).then(function (r) {
        const row = (r.rows || [])[0];
        // A TOMBSTONE IS AN ABSENCE to every reader: the key was ended.
        if (!row || row.body === TOMBSTONE) {
          return null;
        }
        return { handle: row.handle, realm: row.realm, key: row.key,
                 body: row.body, writtenAt: Number(row.written_ms || 0) };
      });
    },

    // -----------------------------------------------------------------------
    // THE NUDGE, ON A CONNECTION OF ITS OWN.
    //
    // **A POOLED CLIENT CANNOT HOLD A `LISTEN`** — the pool hands it to the
    // next caller, who may release it, and the subscription goes with it. So
    // this is a `Client` outside the pool, and it is the only long-lived
    // connection this driver holds.
    //
    // **EVERY FAILURE HERE IS A LATENCY FAILURE AND NEVER A CORRECTNESS ONE**,
    // which is what lets this whole function be best-effort: if the connection
    // never opens, or drops and never comes back, the poll in
    // `persistence_replication.js` still converges. That is the property the
    // change log was chosen for, and this is where it is spent.
    // -----------------------------------------------------------------------
    watchChanges: function (onNudge) {
      log.debug('Entering the postgres driver watchChanges().');
      let client = null;
      let closed = false;
      let backoff = 1000;

      function connect() {
        log.debug("Entering connect().");
        if (closed) {
          log.debug("Leaving connect().");
          return;
        }
        client = new Client(clientOptions());
        client.on('notification', function (msg) {
          let payload = null;
          try {
            payload = JSON.parse(msg.payload || '{}');
          } catch (e) {
            log.debug("Caught in a callback in connect(): " +
                      ((e && e.message) || e));
            // Not JSON. Treated as a bare nudge rather than dropped: the
            // payload is advisory and the poll it triggers is what is
            // actually correct.
            payload = {};
          }
          if (payload.from === processId) {
            return;
          }
          onNudge(payload);
        });
        client.on('error', function (err) {
          // A dropped listener is EXPECTED — a database restart, a failover, a
          // network blip — so this is a warn and a reconnect rather than an
          // error. The poll covers the gap.
          log.warn(errorCodes.tag('STS-STORE-0035') +
                   'persistence: the change listener dropped (' + err.message +
                   '). Reconnecting; the poll covers the gap in the ' +
                   'meantime, which is why losing this connection costs ' +
                   'latency and not correctness.');
          try {
            client.end();
          } catch (e) {
            // Ending a connection that is already gone. Nothing to do and
            // nothing to say: the reconnect below is the whole response.
            log.debug("Caught in a callback in connect(): " +
                      ((e && e.message) || e));
          }
          client = null;
          if (!closed) {
            const wait = backoff;
            backoff = Math.min(backoff * 2, 30000);
            const timer = setTimeout(connect, wait);
            if (timer.unref) timer.unref();
          }
        });
        client.connect().then(function () {
          return client.query('LISTEN ' + CHANNEL);
        }).then(function () {
          backoff = 1000;
          log.info('persistence: listening on "' + CHANNEL + '" for other ' +
                   'processes\' writes. This is the NUDGE; the change log is ' +
                   'the contract, so a missed notification costs latency and ' +
                   'never a lost change.');
          // AND A PULL IMMEDIATELY. Between the last poll and this connection
          // being ready there is a window in which notifications were missed,
          // and the whole reason the log exists is that the window can be
          // closed by asking rather than by hoping.
          onNudge({ reconnected: true });
        }).catch(function (err) {
          log.warn(errorCodes.tag('STS-STORE-0036') +
                   'persistence: the change listener could not connect (' +
                   err.message + '). The poll still converges.');
          client = null;
          if (!closed) {
            const wait = backoff;
            backoff = Math.min(backoff * 2, 30000);
            const timer = setTimeout(connect, wait);
            if (timer.unref) timer.unref();
          }
        });
        log.debug("Leaving connect().");
      }

      connect();
      log.debug('Leaving the postgres driver watchChanges().');
      return function () {
        closed = true;
        if (client) {
          try {
            client.end();
          } catch (e) {
            // Shutting down a connection that has already gone. See above.
            log.debug("Caught in a callback in watchChanges(): " +
                      ((e && e.message) || e));
          }
          client = null;
        }
      };
    },

    // Log rows nothing will ever ask for again. Every live process has applied
    // past `beforeSeq` — the caller works that out — so what is below it is
    // history nobody reads. Without this the log is the one table here that
    // grows for ever.
    purgeChanges: function (beforeSeq) {
      log.debug("Entering purgeChanges().");
      log.debug("Leaving purgeChanges().");
      return pool.query('DELETE FROM sts_changes WHERE seq < $1',
                        [Number(beforeSeq) || 0])
        .then(function (r) { return r.rowCount || 0; });
    },

    // THE ROWS AT THESE SEQUENCE NUMBERS, for `persistence_replication.js`'s
    // re-check of the holes it stepped past (2026-09-14, #46). A hole is a seq
    // that was allocated and not yet visible — a transaction still committing
    // — and with several nodes writing at once there is nearly always one, so
    // the reader applies what it can see and asks for the holes again rather
    // than stopping at the first.
    changesAt: function (seqs) {
      log.debug("Entering changesAt().");
      const list = (seqs || []).map(Number).filter(function (n) {
        return n > 0;
      });
      if (!list.length) {
        log.debug("Leaving changesAt(). Nothing asked.");
        return Promise.resolve([]);
      }
      log.debug("Leaving changesAt().");
      return pool.query(
        'SELECT seq, origin, kind, realm, key FROM sts_changes ' +
        'WHERE seq = ANY($1::bigint[]) ORDER BY seq ASC', [list]
      ).then(function (r) {
        return (r.rows || []).map(function (row) {
          return { seq: Number(row.seq), origin: row.origin, kind: row.kind,
                   realm: row.realm, key: row.key };
        });
      });
    },

    // =====================================================================
    // THE CLUSTER (2026-09-14, #46). `cluster/cluster.js` owns the decisions;
    // these are the statements, and every time in them is `DB_NOW`.
    // =====================================================================

    // The fence every transaction checks, and what to do when it fails. See
    // `fence` near the top of create().
    setFence: function (provider, whenFenced) {
      log.debug("Entering setFence().");
      fence = typeof provider === 'function' ? provider : null;
      onFenced = typeof whenFenced === 'function' ? whenFenced : null;
      log.debug("Leaving setFence().");
    },

    // The database's clock, for a status page that has to say how far away a
    // node's expiry is without trusting this process's own.
    clusterClock: function () {
      log.debug("Entering clusterClock().");
      log.debug("Leaving clusterClock().");
      return pool.query('SELECT ' + DB_NOW + ' AS now').then(function (r) {
        return Number((r.rows[0] || {}).now) || 0;
      });
    },

    // JOINING. One transaction under an advisory lock, so that two nodes
    // starting together cannot both see "nobody else is configured
    // differently" and both write a row. `node.fingerprint` is compared with
    // every LIVE node's; a mismatch writes nothing and answers who differs —
    // the caller turns that into a refusal to start. Rows dead for longer than
    // DEAD_NODE_RETENTION_MS are swept on the way.
    joinCluster: function (node) {
      log.debug("Entering joinCluster(). node=" + node.nodeId);
      log.debug("Leaving joinCluster().");
      return withTransaction(function (client) {
        return client.query('SELECT pg_advisory_xact_lock($1)', [JOIN_LOCK])
          .then(function () {
            return client.query(
              'DELETE FROM sts_cluster_nodes WHERE expires_at < ' + DB_NOW +
              ' - $1', [DEAD_NODE_RETENTION_MS]);
          }).then(function () {
            return client.query(
              'SELECT node_id, name, mode, version, fingerprint FROM ' +
              'sts_cluster_nodes WHERE left_at = 0 AND expires_at > ' +
              DB_NOW + ' AND node_id <> $1', [node.nodeId]);
          }).then(function (r) {
            const live = r.rows || [];
            // THE MODE ONLY. A joining node has no fingerprint yet — it is
            // keyed by the key-encryption key, which is opened after the join —
            // so the settings are compared by agreeFingerprint() below.
            const differing = live.filter(function (row) {
              return row.mode !== node.mode;
            }).map(function (row) {
              return { nodeId: row.node_id, name: row.name, mode: row.mode,
                       version: row.version, fingerprint: row.fingerprint };
            });
            if (differing.length) {
              return { joined: false, differing: differing,
                       live: live.length };
            }
            return client.query(
              'INSERT INTO sts_cluster_nodes (node_id, name, mode, version, ' +
              'fingerprint, started_at, heartbeat_at, expires_at, info) ' +
              'VALUES ($1, $2, $3, $4, $5, ' + DB_NOW + ', ' + DB_NOW + ', ' +
              DB_NOW + ' + $6, $7::jsonb)',
              [node.nodeId, node.name || '', node.mode, node.version || '',
               node.fingerprint || '', Number(node.ttlMs),
               JSON.stringify(node.info || {})]
            ).then(function () {
              return { joined: true, differing: [], live: live.length };
            });
          });
      });
    },

    // AGREEMENT, once the key-encryption key is open: this node's fingerprint
    // of the settings every node must share is written on its row and compared
    // with every live node that has written one — under the join lock, so two
    // nodes agreeing at once see each other. A difference writes nothing.
    agreeFingerprint: function (nodeId, fingerprint) {
      log.debug("Entering agreeFingerprint(). node=" + nodeId);
      log.debug("Leaving agreeFingerprint().");
      return withTransaction(function (client) {
        return client.query('SELECT pg_advisory_xact_lock($1)', [JOIN_LOCK])
          .then(function () {
            return client.query(
              'SELECT node_id, name, mode, version, fingerprint FROM ' +
              'sts_cluster_nodes WHERE left_at = 0 AND expires_at > ' +
              DB_NOW + ' AND node_id <> $1 AND fingerprint <> \'\' AND ' +
              'fingerprint <> $2', [nodeId, String(fingerprint)]);
          }).then(function (r) {
            const differing = (r.rows || []).map(function (row) {
              return { nodeId: row.node_id, name: row.name, mode: row.mode,
                       version: row.version };
            });
            if (differing.length) {
              return { differing: differing };
            }
            return client.query(
              'UPDATE sts_cluster_nodes SET fingerprint = $2 WHERE ' +
              'node_id = $1', [nodeId, String(fingerprint)]
            ).then(function () {
              return { differing: [] };
            });
          });
      });
    },

    // THE HEARTBEAT, and every lease this node holds renewed with it — one
    // round trip. **AN EXPIRED ROW IS NOT RENEWED**: `alive` comes back false
    // and the caller exits, because a node that was declared dead may already
    // have had its leases taken over. A lease already expired is not renewed
    // either and simply is not in `leases`, which is how the caller learns it
    // lost one.
    heartbeat: function (nodeId, ttlMs, info) {
      log.debug("Entering heartbeat(). node=" + nodeId);
      log.debug("Leaving heartbeat().");
      return pool.query(
        'WITH n AS (UPDATE sts_cluster_nodes SET heartbeat_at = ' + DB_NOW +
        ', expires_at = ' + DB_NOW + ' + $2, info = COALESCE($3::jsonb, ' +
        'info) WHERE node_id = $1 AND left_at = 0 AND expires_at > ' + DB_NOW +
        ' RETURNING node_id), ' +
        'l AS (UPDATE sts_cluster_leases SET expires_at = ' + DB_NOW +
        ' + $2 WHERE holder = $1 AND expires_at > ' + DB_NOW +
        ' AND EXISTS (SELECT 1 FROM n) RETURNING name, token) ' +
        'SELECT (SELECT count(*) FROM n) AS alive, ' +
        'COALESCE((SELECT json_agg(json_build_object(\'name\', name, ' +
        '\'token\', token)) FROM l), \'[]\'::json) AS leases',
        [nodeId, Number(ttlMs), info ? JSON.stringify(info) : null]
      ).then(function (r) {
        const row = r.rows[0] || {};
        return {
          alive: Number(row.alive) > 0,
          leases: (row.leases || []).map(function (one) {
            return { name: one.name, token: Number(one.token) };
          })
        };
      });
    },

    // LEAVING, on a clean shutdown: the row is marked left and every lease it
    // held expires NOW rather than at the end of its lifetime, so a standby
    // takes over in one heartbeat instead of `cluster.nodeTtlMs`. Expired and
    // not deleted, so a lease's token keeps counting up.
    leaveCluster: function (nodeId) {
      log.debug("Entering leaveCluster(). node=" + nodeId);
      log.debug("Leaving leaveCluster().");
      return pool.query(
        'WITH n AS (UPDATE sts_cluster_nodes SET left_at = ' + DB_NOW +
        ', expires_at = LEAST(expires_at, ' + DB_NOW + ') WHERE node_id = $1 ' +
        'RETURNING node_id) ' +
        'UPDATE sts_cluster_leases SET expires_at = 0 WHERE holder = $1',
        [nodeId]).then(function () {
        return true;
      });
    },

    // ACQUIRING A LEASE. Taken when nobody holds it (no row, or an expired
    // one), and only by a node whose own row is live. The token is one more
    // than the last holder's. A node that already holds it gets its current
    // token back, unchanged: re-asking is not a new tenure.
    acquireLease: function (name, nodeId, ttlMs) {
      log.debug("Entering acquireLease(). name=" + name);
      log.debug("Leaving acquireLease().");
      return pool.query(
        'INSERT INTO sts_cluster_leases (name, holder, token, acquired_at, ' +
        'expires_at) SELECT $1, $2, 1, ' + DB_NOW + ', ' + DB_NOW + ' + $3 ' +
        'WHERE EXISTS (SELECT 1 FROM sts_cluster_nodes WHERE node_id = $2 ' +
        'AND left_at = 0 AND expires_at > ' + DB_NOW + ') ' +
        'ON CONFLICT (name) DO UPDATE SET holder = EXCLUDED.holder, ' +
        'token = CASE WHEN sts_cluster_leases.holder = EXCLUDED.holder AND ' +
        'sts_cluster_leases.expires_at > ' + DB_NOW + ' THEN ' +
        'sts_cluster_leases.token ELSE sts_cluster_leases.token + 1 END, ' +
        'acquired_at = CASE WHEN sts_cluster_leases.holder = EXCLUDED.holder ' +
        'AND sts_cluster_leases.expires_at > ' + DB_NOW + ' THEN ' +
        'sts_cluster_leases.acquired_at ELSE EXCLUDED.acquired_at END, ' +
        'expires_at = EXCLUDED.expires_at ' +
        'WHERE sts_cluster_leases.expires_at <= ' + DB_NOW + ' OR ' +
        'sts_cluster_leases.holder = EXCLUDED.holder ' +
        'RETURNING holder, token, expires_at',
        [name, nodeId, Number(ttlMs)]
      ).then(function (r) {
        const row = (r.rows || [])[0];
        if (row && row.holder === nodeId) {
          return { held: true, token: Number(row.token),
                   expiresAt: Number(row.expires_at) };
        }
        return pool.query(
          'SELECT holder, token, expires_at FROM sts_cluster_leases ' +
          'WHERE name = $1', [name]
        ).then(function (found) {
          const other = (found.rows || [])[0] || null;
          return { held: false, holder: other ? other.holder : '',
                   token: other ? Number(other.token) : 0,
                   expiresAt: other ? Number(other.expires_at) : 0 };
        });
      });
    },

    // Giving one lease up early — a node standing down from a role.
    releaseLease: function (name, nodeId, token) {
      log.debug("Entering releaseLease(). name=" + name);
      log.debug("Leaving releaseLease().");
      return pool.query(
        'UPDATE sts_cluster_leases SET expires_at = 0 WHERE name = $1 AND ' +
        'holder = $2 AND token = $3', [name, nodeId, Number(token)]
      ).then(function (r) {
        return (r.rowCount || 0) > 0;
      });
    },

    // Every node row still retained and every lease, with the database clock
    // they are to be read against. `/admin/cluster` and the API draw this.
    clusterState: function () {
      log.debug("Entering clusterState().");
      log.debug("Leaving clusterState().");
      return Promise.all([
        pool.query(
          'SELECT node_id, name, mode, version, fingerprint, started_at, ' +
          'heartbeat_at, expires_at, left_at, info FROM sts_cluster_nodes ' +
          'ORDER BY started_at DESC LIMIT 200'),
        pool.query(
          'SELECT name, holder, token, acquired_at, expires_at FROM ' +
          'sts_cluster_leases ORDER BY name'),
        pool.query('SELECT ' + DB_NOW + ' AS now')
      ]).then(function (answers) {
        return {
          now: Number((answers[2].rows[0] || {}).now) || 0,
          nodes: answers[0].rows.map(function (row) {
            return { nodeId: row.node_id, name: row.name, mode: row.mode,
                     version: row.version, fingerprint: row.fingerprint,
                     startedAt: Number(row.started_at),
                     heartbeatAt: Number(row.heartbeat_at),
                     expiresAt: Number(row.expires_at),
                     leftAt: Number(row.left_at), info: row.info || {} };
          }),
          leases: answers[1].rows.map(function (row) {
            return { name: row.name, holder: row.holder,
                     token: Number(row.token),
                     acquiredAt: Number(row.acquired_at),
                     expiresAt: Number(row.expires_at) };
          })
        };
      });
    },

    // A CLAIM: exactly one concurrent caller for `(scope, realm, key)` gets
    // `claimed: true`. An EXPIRED row is replaced, which is what a claim's
    // lifetime means; a live one refuses. Both times are the database's.
    // `reservation` is the capability to release the claim later and is
    // returned only to the caller that made it.
    claimOnce: function (scope, realmId, key, opts) {
      log.debug('Entering claimOnce(). scope=' + scope);
      const o = opts || {};
      const ttlMs = Math.max(1, Math.floor(Number(o.ttlMs) || 0));
      const reservation = String(o.reservation || '');
      log.debug("Leaving claimOnce().");
      return pool.query(
        'INSERT INTO sts_cluster_claims (scope, realm, key, reservation, ' +
        'origin, claimed_at, expires_at) VALUES ($1, $2, $3, $4, $5, ' +
        DB_NOW + ', ' + DB_NOW + ' + $6) ON CONFLICT (scope, realm, key) DO ' +
        'UPDATE SET reservation = EXCLUDED.reservation, origin = ' +
        'EXCLUDED.origin, claimed_at = EXCLUDED.claimed_at, expires_at = ' +
        'EXCLUDED.expires_at WHERE sts_cluster_claims.expires_at <= ' +
        'EXCLUDED.claimed_at RETURNING claimed_at, expires_at',
        [String(scope), String(realmId || ''), String(key), reservation,
         processId, ttlMs]
      ).then(function (r) {
        if (r.rowCount) {
          const row = r.rows[0];
          return { claimed: true, claimedAt: Number(row.claimed_at),
                   expiresAt: Number(row.expires_at) };
        }
        return pool.query(
          'SELECT origin, claimed_at, expires_at FROM sts_cluster_claims ' +
          'WHERE scope = $1 AND realm = $2 AND key = $3',
          [String(scope), String(realmId || ''), String(key)]
        ).then(function (found) {
          const row = (found.rows || [])[0] || null;
          return { claimed: false, existing: row ? {
            origin: row.origin,
            claimedAt: Number(row.claimed_at),
            expiresAt: Number(row.expires_at)
          } : null };
        });
      });
    },

    // Giving a claim back — the work it guarded did not happen. Pinned to the
    // reservation, so a claim that outlived its row cannot release a later
    // claimant's.
    releaseClaim: function (scope, realmId, key, reservation) {
      log.debug("Entering releaseClaim(). scope=" + scope);
      log.debug("Leaving releaseClaim().");
      return pool.query(
        'DELETE FROM sts_cluster_claims WHERE scope = $1 AND realm = $2 AND ' +
        'key = $3 AND reservation = $4',
        [String(scope), String(realmId || ''), String(key),
         String(reservation)]
      ).then(function (r) {
        return (r.rowCount || 0) > 0;
      });
    },

    // Whether a claim is live, without making one — for a reader that must
    // refuse what another process has already spent.
    claimHeld: function (scope, realmId, key) {
      log.debug("Entering claimHeld(). scope=" + scope);
      log.debug("Leaving claimHeld().");
      return pool.query(
        'SELECT 1 FROM sts_cluster_claims WHERE scope = $1 AND realm = $2 ' +
        'AND key = $3 AND expires_at > ' + DB_NOW,
        [String(scope), String(realmId || ''), String(key)]
      ).then(function (r) {
        return (r.rowCount || 0) > 0;
      });
    },

    purgeClaims: function () {
      log.debug("Entering purgeClaims().");
      log.debug("Leaving purgeClaims().");
      return pool.query('DELETE FROM sts_cluster_claims WHERE expires_at <= ' +
                        DB_NOW).then(function (r) {
        return r.rowCount || 0;
      });
    },

    // A COUNTER THAT ONLY GOES UP (2026-09-14, #46). One statement: a row that
    // is absent is inserted at `value`; a row below `value` is raised to it;
    // a row at or above `value` is left alone and nothing is returned, under
    // the primary key's row lock, so of two nodes advancing one counter to
    // the same value exactly one gets a row back. The second statement runs
    // only on that refusal, to say what the counter is — a report, never a
    // decision. `cluster/cluster_counters.js` reads the two answers.
    advanceCounter: function (scope, realmId, key, value) {
      log.debug("Entering advanceCounter(). scope=" + scope);
      const wanted = Math.max(0, Math.floor(Number(value) || 0));
      log.debug("Leaving advanceCounter().");
      return pool.query(
        'INSERT INTO sts_cluster_counters (scope, realm, key, value, origin, ' +
        'updated_at) VALUES ($1, $2, $3, $4, $5, ' + DB_NOW + ') ON CONFLICT ' +
        '(scope, realm, key) DO UPDATE SET value = EXCLUDED.value, origin = ' +
        'EXCLUDED.origin, updated_at = EXCLUDED.updated_at WHERE ' +
        'sts_cluster_counters.value < EXCLUDED.value RETURNING value',
        [String(scope), String(realmId || ''), String(key), wanted, processId]
      ).then(function (r) {
        if (r.rowCount) {
          return { advanced: true, highest: Number(r.rows[0].value) };
        }
        return pool.query(
          'SELECT value FROM sts_cluster_counters WHERE scope = $1 AND ' +
          'realm = $2 AND key = $3',
          [String(scope), String(realmId || ''), String(key)]
        ).then(function (found) {
          const row = (found.rows || [])[0] || null;
          return { advanced: false, highest: row ? Number(row.value) : 0 };
        });
      });
    },

    // A COUNT INSIDE A FIXED WINDOW (2026-09-14, #46 section 2). One
    // statement: an absent row is inserted at 1 with a window ending
    // `windowMs` from now; a row whose window has passed is RESET to 1 with a
    // fresh window; a live one is incremented. Under the primary key's row
    // lock, so of two nodes counting one bucket at the same moment both
    // increments land. "Now" is taken ONCE, from the inserted row's own
    // window end less the span — `DB_NOW` is `clock_timestamp()` and two
    // readings of it in one statement are two different instants, which at
    // the boundary would reset the count and keep the old window.
    // `cluster/cluster_counters.js` reads the answer.
    countWindow: function (scope, realmId, key, windowMs) {
      log.debug("Entering countWindow(). scope=" + scope);
      const span = Math.max(1, Math.floor(Number(windowMs) || 0));
      log.debug("Leaving countWindow().");
      return pool.query(
        'INSERT INTO sts_cluster_windows (scope, realm, key, count, ' +
        'window_ends_at, origin) VALUES ($1, $2, $3, 1, ' + DB_NOW +
        ' + $4::bigint, $5) ON CONFLICT (scope, realm, key) DO UPDATE SET ' +
        'count = CASE WHEN sts_cluster_windows.window_ends_at <= ' +
        'EXCLUDED.window_ends_at - $4::bigint THEN 1 ELSE ' +
        'sts_cluster_windows.count + 1 END, window_ends_at = CASE WHEN ' +
        'sts_cluster_windows.window_ends_at <= EXCLUDED.window_ends_at - ' +
        '$4::bigint THEN EXCLUDED.window_ends_at ELSE ' +
        'sts_cluster_windows.window_ends_at END, origin = EXCLUDED.origin ' +
        'RETURNING count, window_ends_at - ' + DB_NOW + ' AS remaining',
        [String(scope), String(realmId || ''), String(key), span, processId]
      ).then(function (r) {
        const row = (r.rows || [])[0] || {};
        return { count: Number(row.count) || 0,
                 remainingMs: Math.max(0, Number(row.remaining) || 0) };
      });
    },

    // The count of a window still running, without counting. A row whose
    // window has passed is a count of zero, which is what it means.
    peekWindow: function (scope, realmId, key) {
      log.debug("Entering peekWindow(). scope=" + scope);
      log.debug("Leaving peekWindow().");
      return pool.query(
        'SELECT count, window_ends_at - ' + DB_NOW + ' AS remaining FROM ' +
        'sts_cluster_windows WHERE scope = $1 AND realm = $2 AND key = $3 ' +
        'AND window_ends_at > ' + DB_NOW,
        [String(scope), String(realmId || ''), String(key)]
      ).then(function (r) {
        const row = (r.rows || [])[0] || null;
        return row ? { count: Number(row.count) || 0,
                       remainingMs: Math.max(0, Number(row.remaining) || 0) }
          : { count: 0, remainingMs: 0 };
      });
    },

    // Forgetting a window — what a success does to its bucket.
    clearWindow: function (scope, realmId, key) {
      log.debug("Entering clearWindow(). scope=" + scope);
      log.debug("Leaving clearWindow().");
      return pool.query(
        'DELETE FROM sts_cluster_windows WHERE scope = $1 AND realm = $2 AND ' +
        'key = $3', [String(scope), String(realmId || ''), String(key)]
      ).then(function (r) {
        return (r.rowCount || 0) > 0;
      });
    },

    purgeWindows: function () {
      log.debug("Entering purgeWindows().");
      log.debug("Leaving purgeWindows().");
      return pool.query('DELETE FROM sts_cluster_windows WHERE ' +
                        'window_ends_at <= ' + DB_NOW).then(function (r) {
        return r.rowCount || 0;
      });
    },

    // =====================================================================
    // CHANGE-LOG RETENTION (2026-09-14, #46 section 8). Three statements;
    // `persistence/persistence_replication.js` owns the decisions and argues
    // the bound.
    // =====================================================================

    // THIS PROCESS'S LOW-WATER MARK. `applied` never goes backwards in the
    // row (GREATEST), and `inserted` tells a process that has reported before
    // that its row was REMOVED in between — declared gone by a purge, which
    // may already have trimmed changes it had not applied.
    reportChangeReader: function (applied, nodeId) {
      log.debug("Entering reportChangeReader().");
      log.debug("Leaving reportChangeReader().");
      return pool.query(
        'INSERT INTO sts_change_readers (origin, node_id, applied, ' +
        'started_at, reported_at) VALUES ($1, $2, $3, ' + DB_NOW + ', ' +
        DB_NOW + ') ON CONFLICT (origin) DO UPDATE SET node_id = ' +
        'EXCLUDED.node_id, applied = GREATEST(sts_change_readers.applied, ' +
        'EXCLUDED.applied), reported_at = EXCLUDED.reported_at ' +
        'RETURNING (xmax = 0) AS inserted',
        [processId, String(nodeId || ''), Math.max(0, Number(applied) || 0)]
      ).then(function (r) {
        const row = (r.rows || [])[0] || {};
        return { inserted: row.inserted === true };
      });
    },

    // A clean stop: this process reads the log no longer.
    leaveChangeReader: function () {
      log.debug("Entering leaveChangeReader().");
      log.debug("Leaving leaveChangeReader().");
      return pool.query('DELETE FROM sts_change_readers WHERE origin = $1',
                        [processId]).then(function (r) {
        return (r.rowCount || 0) > 0;
      });
    },

    // THE TRIM, in one statement so that the readers it declares gone and the
    // bound it computes are one snapshot. A reader is GONE when it has not
    // reported for `readerTtlMs`, or when it names a cluster node whose
    // membership is no longer live — a node that left or expired is dead for
    // good (`cluster/cluster.js`), and so are the workers it forked. The bound
    // is the lowest mark of every reader that is not gone; with no reader at
    // all nothing is trimmed, because a store nobody is reading is a store
    // whose next reader has not said where it is yet. A change is removed
    // only below the bound AND older than `retentionMs` by the database's
    // clock. Every sub-statement sees the snapshot before the deletes, which
    // is why `live` filters out `gone` by hand.
    purgeChangeLog: function (opts) {
      log.debug("Entering purgeChangeLog().");
      const o = opts || {};
      const readerTtlMs = Math.max(1, Math.floor(Number(o.readerTtlMs) || 0));
      const retentionMs = Math.max(0, Math.floor(Number(o.retentionMs) || 0));
      log.debug("Leaving purgeChangeLog().");
      return pool.query(
        'WITH gone AS (DELETE FROM sts_change_readers r WHERE ' +
        'r.reported_at < ' + DB_NOW + ' - $1::bigint OR (r.node_id <> \'\' ' +
        'AND NOT EXISTS (SELECT 1 FROM sts_cluster_nodes n WHERE n.node_id = ' +
        'r.node_id AND n.left_at = 0 AND n.expires_at > ' + DB_NOW + ')) ' +
        'RETURNING r.origin), ' +
        'live AS (SELECT min(r.applied) AS low, count(*) AS readers FROM ' +
        'sts_change_readers r WHERE NOT EXISTS (SELECT 1 FROM gone g WHERE ' +
        'g.origin = r.origin)), ' +
        'trimmed AS (DELETE FROM sts_changes c WHERE (SELECT readers FROM ' +
        'live) > 0 AND c.seq < (SELECT low FROM live) AND c.at < now() - ' +
        '($2::bigint * interval \'1 millisecond\') RETURNING 1) ' +
        'SELECT (SELECT count(*) FROM gone) AS gone, (SELECT low FROM live) ' +
        'AS low, (SELECT readers FROM live) AS readers, (SELECT count(*) ' +
        'FROM trimmed) AS trimmed',
        [readerTtlMs, retentionMs]
      ).then(function (r) {
        const row = (r.rows || [])[0] || {};
        return { readersGone: Number(row.gone) || 0,
                 readers: Number(row.readers) || 0,
                 bound: row.low === null || row.low === undefined ? null
                   : Number(row.low),
                 trimmed: Number(row.trimmed) || 0 };
      });
    },

    // =====================================================================
    // ONE ROW OF `sts_keys`, AND THE WRITE THAT MAKES THE STORE THE ARBITER
    // (2026-09-14, #46 section 1).
    //
    // `saveKeys()` above is an unconditional upsert, which is right for one
    // process and is the whole of issue #46's worst section across several:
    // two nodes cold-starting against an empty store each generated a realm's
    // signing keys and the later upsert replaced the earlier, while the
    // earlier node went on signing with what it had written; and the whole
    // certificate authority of a scope — revocations included — was one row
    // any node's next save threw another node's changes out of.
    //
    // `mergeKeys(realm, ciphertext, merge)` hands the decision to the caller
    // UNDER THE ROW'S LOCK. `merge(currentCiphertext | null)` answers the
    // ciphertext the row should hold, or null to leave it as it is; it is
    // `keystore.js`'s, because only that module holds the key-encryption key
    // the row is sealed under, and the driver never sees a key. It is called
    // with null when there is no row, and may be called a second time when a
    // concurrent INSERT lands between the lock and ours — so it must be pure.
    //
    // Fenced like every write (`withTransaction()`), and logged in
    // `sts_changes` only when the row actually moved, so a merge that decided
    // "keep what is there" wakes no other process.
    // =====================================================================
    loadKey: function (realmId) {
      log.debug("Entering loadKey(). realm=" + realmId);
      log.debug("Leaving loadKey().");
      return pool.query('SELECT material FROM sts_keys WHERE realm = $1',
                        [String(realmId)]).then(function (r) {
        const row = (r.rows || [])[0];
        return row ? row.material : null;
      });
    },

    // =========================================================================
    // RISK SCORING (#62): the external datasets by version, and the
    // attributable failure history. `risk/risk_store.ts` picks this group by
    // its names (RISK_GROUP there) and holds the same shapes in memory when
    // the driver has none of them. `risk/CLAUDE.md` argues both.
    // =========================================================================

    // Every dataset's live version and state, for every realm.
    riskListDatasets: function () {
      log.debug("Entering riskListDatasets().");
      log.debug("Leaving riskListDatasets().");
      return pool.query(
        'SELECT realm, dataset, kind, active_version, previous_version, ' +
        'state, updated_at FROM sts_risk_datasets ORDER BY realm, dataset'
      ).then(function (r) {
        return r.rows.map(riskDatasetFrom);
      });
    },

    // Every version of one dataset (or of every dataset, for ''), newest
    // first — refused and deleted ones included, because this table is the
    // record of what was loaded.
    riskListVersions: function (realm, dataset) {
      log.debug("Entering riskListVersions(). dataset=" + dataset);
      log.debug("Leaving riskListVersions().");
      return pool.query(
        'SELECT * FROM sts_risk_dataset_versions ' +
        'WHERE realm = $1 AND ($2 = \'\' OR dataset = $2) ' +
        'ORDER BY fetched_at DESC, version DESC',
        [String(realm || ''), String(dataset || '')]
      ).then(function (r) {
        return r.rows.map(riskVersionFrom);
      });
    },

    // A version begun: its row in `loading`, or false when that version of
    // that dataset is already recorded — a second node importing the same
    // file, or the same file seen again, loads nothing twice.
    riskBeginVersion: function (v) {
      log.debug("Entering riskBeginVersion(). " + v.dataset + " " +
                v.version);
      log.debug("Leaving riskBeginVersion().");
      return pool.query(
        'INSERT INTO sts_risk_dataset_versions (realm, dataset, version, ' +
        'format, provider, licence, attribution, source, source_uri, ' +
        'sha256, byte_count, parameters, verification, published_at, ' +
        'next_update_at, fetched_at, state, origin) VALUES ($1, $2, $3, $4, ' +
        '$5, $6, $7, $8, $9, $10, $11, $12::jsonb, $13, $14, $15, $16, ' +
        '\'loading\', $17) ON CONFLICT (realm, dataset, version) DO NOTHING ' +
        'RETURNING version',
        [v.realm || '', v.dataset, v.version, v.format, v.provider,
         v.licence, v.attribution || '', v.source, v.sourceUri || '',
         v.sha256, Number(v.byteCount) || 0,
         JSON.stringify(v.parameters || {}), v.verification,
         Number(v.publishedAt) || 0, Number(v.nextUpdateAt) || 0,
         Number(v.fetchedAt) || 0, processId]
      ).then(function (r) {
        return r.rowCount > 0;
      });
    },

    // -------------------------------------------------------------------------
    // ROWS, IN BATCHES, AS ONE `INSERT … SELECT FROM unnest()` PER BATCH: one
    // array parameter per column rather than one parameter per value, so a
    // batch is not bounded by the protocol's 65,535 bind parameters that
    // `recordChanges()` above had to learn about. `COPY` would be faster and
    // needs a dependency (pg-copy-streams); a city dataset is a few million
    // rows, loaded once a week, off every request's path.
    // -------------------------------------------------------------------------
    riskInsertRows: function (kind, realm, dataset, version, rows) {
      log.debug("Entering riskInsertRows(). kind=" + kind + " rows=" +
                rows.length);
      // A column's values, with its default where a row has none: an
      // explicit null in an unnest() array is a NULL, which a NOT NULL
      // column refuses whatever its DEFAULT says. `null` as the default is
      // for the two nullable columns (latitude, longitude).
      const col = function (name, dflt) {
        return rows.map(function (row) {
          const value = row[name];
          return value === undefined || value === null
            ? (dflt === undefined ? null : dflt) : value;
        });
      };
      let statement;
      let params;
      if (kind === 'geo') {
        statement =
          'INSERT INTO sts_risk_geo_ranges (dataset, version, range_start, ' +
          'range_end, location_id, continent, country, subdivision, city, ' +
          'registered_country, latitude, longitude, accuracy_km, ' +
          'anonymous_proxy, satellite) SELECT $1, $2, u.* FROM unnest(' +
          '$3::inet[], $4::inet[], $5::bigint[], $6::text[], $7::text[], ' +
          '$8::text[], $9::text[], $10::text[], $11::float8[], ' +
          '$12::float8[], $13::int[], $14::bool[], $15::bool[]) AS u ' +
          'ON CONFLICT DO NOTHING';
        params = [dataset, version, col('start'), col('end'),
                  col('locationId', 0), col('continent', ''),
                  col('country', ''), col('subdivision', ''),
                  col('city', ''), col('registeredCountry', ''),
                  col('latitude'), col('longitude'), col('accuracyKm', 0),
                  col('anonymousProxy', false), col('satellite', false)];
      } else if (kind === 'asn') {
        statement =
          'INSERT INTO sts_risk_asn_ranges (dataset, version, range_start, ' +
          'range_end, asn, as_org, as_domain) SELECT $1, $2, u.* FROM ' +
          'unnest($3::inet[], $4::inet[], $5::bigint[], $6::text[], ' +
          '$7::text[]) AS u ON CONFLICT DO NOTHING';
        params = [dataset, version, col('start'), col('end'),
                  col('asn', 0), col('asOrg', ''), col('asDomain', '')];
      } else if (kind === 'iplist') {
        statement =
          'INSERT INTO sts_risk_ip_lists (realm, dataset, version, ' +
          'range_start, range_end, category, note) SELECT $1, $2, $3, u.* ' +
          'FROM unnest($4::inet[], $5::inet[], $6::text[], $7::text[]) AS u ' +
          'ON CONFLICT DO NOTHING';
        params = [realm || '', dataset, version, col('start'), col('end'),
                  col('category', ''), col('note', '')];
      } else if (kind === 'fido') {
        // One FIDO MDS3 entry per row (#62 P5): an authenticator model by
        // its AAGUID, AAID or attestation key identifier, with its status
        // reports and a copy of its metadata statement for the page.
        statement =
          'INSERT INTO sts_risk_fido_authenticators (dataset, version, ' +
          'key_kind, authenticator_key, description, protocol_family, ' +
          'certification_level, latest_status, latest_status_at, ' +
          'compromised, status_reports, metadata_statement) SELECT $1, $2, ' +
          'u.* FROM unnest($3::text[], $4::text[], $5::text[], $6::text[], ' +
          '$7::text[], $8::text[], $9::bigint[], $10::bool[], ' +
          '$11::jsonb[], $12::jsonb[]) AS u ON CONFLICT DO NOTHING';
        params = [dataset, version, col('keyKind', ''), col('key', ''),
                  col('description', ''), col('protocolFamily', ''),
                  col('certificationLevel', ''), col('latestStatus', ''),
                  col('latestStatusAt', 0), col('compromised', false),
                  rows.map(function (row) {
                    return JSON.stringify(row.statusReports || []);
                  }),
                  rows.map(function (row) {
                    return JSON.stringify(row.metadataStatement || {});
                  })];
      } else {
        log.debug("Leaving riskInsertRows(). Unknown kind.");
        return Promise.reject(new Error(errorCodes.tag('STS-RISK-0006') +
          'no risk dataset table holds rows of kind "' + kind + '".'));
      }
      log.debug("Leaving riskInsertRows().");
      return pool.query(statement, params).then(function (r) {
        return r.rowCount || 0;
      });
    },

    // A version's outcome: `ready` with its row count, or `refused` with the
    // reason and the code.
    riskFinishVersion: function (realm, dataset, version, patch) {
      log.debug("Entering riskFinishVersion(). " + dataset + " " + version +
                " " + patch.state);
      log.debug("Leaving riskFinishVersion().");
      return pool.query(
        'UPDATE sts_risk_dataset_versions SET state = $4, row_count = $5, ' +
        'loaded_at = $6, refusal = $7, error_code = $8, ' +
        'parameters = parameters || $9::jsonb ' +
        'WHERE realm = $1 AND dataset = $2 AND version = $3',
        [realm || '', dataset, version, patch.state,
         Number(patch.rowCount) || 0, Number(patch.loadedAt) || 0,
         String(patch.refusal || ''), String(patch.errorCode || ''),
         JSON.stringify(patch.parameters || {})]
      ).then(function (r) {
        return r.rowCount > 0;
      });
    },

    // -------------------------------------------------------------------------
    // ACTIVATION, IN ONE TRANSACTION WITH ITS CHANGE ROW. The dataset's row
    // names the new version and remembers the one it replaces, the new
    // version becomes `active` and the old one `superseded`, and a
    // `risk-dataset` change row tells every other process to drop what it
    // cached — so no node answers from a version the others have left. The
    // version must be `ready` or `superseded` (a rollback); anything else is
    // refused without writing.
    // -------------------------------------------------------------------------
    riskActivate: function (realm, dataset, kind, version, now) {
      log.debug("Entering riskActivate(). " + dataset + " " + version);
      const r0 = String(realm || '');
      log.debug("Leaving riskActivate().");
      return withTransaction(function (client) {
        return client.query(
          'SELECT state FROM sts_risk_dataset_versions WHERE realm = $1 ' +
          'AND dataset = $2 AND version = $3 FOR UPDATE',
          [r0, dataset, version]
        ).then(function (r) {
          const state = r.rows[0] ? r.rows[0].state : '';
          if (state !== 'ready' && state !== 'superseded' &&
              state !== 'active') {
            return { activated: false, state: state };
          }
          return client.query(
            'SELECT active_version FROM sts_risk_datasets WHERE realm = $1 ' +
            'AND dataset = $2 FOR UPDATE', [r0, dataset]
          ).then(function (d) {
            const previous = d.rows[0] ? d.rows[0].active_version : '';
            if (previous === version) {
              return { activated: true, previous: previous, unchanged: true };
            }
            return client.query(
              'INSERT INTO sts_risk_datasets (realm, dataset, kind, ' +
              'active_version, previous_version, state, updated_at) VALUES ' +
              '($1, $2, $3, $4, $5, \'active\', $6) ON CONFLICT (realm, ' +
              'dataset) DO UPDATE SET active_version = EXCLUDED.' +
              'active_version, previous_version = EXCLUDED.previous_version, ' +
              'kind = EXCLUDED.kind, state = \'active\', updated_at = ' +
              'EXCLUDED.updated_at',
              [r0, dataset, kind, version, previous, Number(now)]
            ).then(function () {
              return client.query(
                'UPDATE sts_risk_dataset_versions SET state = \'superseded\', ' +
                'superseded_at = $4 WHERE realm = $1 AND dataset = $2 AND ' +
                'state = \'active\' AND version <> $3',
                [r0, dataset, version, Number(now)]);
            }).then(function () {
              return client.query(
                'UPDATE sts_risk_dataset_versions SET state = \'active\', ' +
                'activated_at = $4, superseded_at = 0 WHERE realm = $1 AND ' +
                'dataset = $2 AND version = $3',
                [r0, dataset, version, Number(now)]);
            }).then(function () {
              return recordChanges(client, [{ kind: 'risk-dataset',
                                              realm: r0, key: dataset }]);
            }).then(function () {
              return { activated: true, previous: previous };
            });
          });
        });
      });
    },

    // A version's rows, deleted a batch at a time (the application role has
    // no TRUNCATE and cannot drop a partition). The count deleted, so the
    // caller knows when it is done.
    riskDeleteRows: function (kind, realm, dataset, version, limit) {
      log.debug("Entering riskDeleteRows(). kind=" + kind + " " + dataset +
                " " + version);
      const table = { geo: 'sts_risk_geo_ranges',
                      asn: 'sts_risk_asn_ranges',
                      iplist: 'sts_risk_ip_lists',
                      fido: 'sts_risk_fido_authenticators' }[kind];
      if (!table) {
        log.debug("Leaving riskDeleteRows(). Unknown kind.");
        return Promise.resolve(0);
      }
      const realmClause = kind === 'iplist' ? 'realm = $4 AND ' : '';
      const params = [dataset, version, Number(limit) || 10000];
      if (kind === 'iplist') {
        params.push(realm || '');
      }
      log.debug("Leaving riskDeleteRows().");
      return pool.query(
        'DELETE FROM ' + table + ' WHERE ctid IN (SELECT ctid FROM ' + table +
        ' WHERE ' + realmClause + 'dataset = $1 AND version = $2 LIMIT $3)',
        params
      ).then(function (r) {
        return r.rowCount || 0;
      });
    },

    // The version's rows are gone; its row stays, as the record.
    riskMarkRowsDeleted: function (realm, dataset, version, now) {
      log.debug("Entering riskMarkRowsDeleted(). " + dataset + " " + version);
      log.debug("Leaving riskMarkRowsDeleted().");
      return pool.query(
        'UPDATE sts_risk_dataset_versions SET state = \'deleted\', ' +
        'rows_deleted_at = $4 WHERE realm = $1 AND dataset = $2 AND ' +
        'version = $3 AND state <> \'active\'',
        [realm || '', dataset, version, Number(now)]
      ).then(function (r) {
        return r.rowCount > 0;
      });
    },

    // -------------------------------------------------------------------------
    // ONE ADDRESS IN ONE VERSION: the range with the greatest start not above
    // it, kept only if its end is not below it. One descending probe of the
    // primary key. IPv4 sorts before IPv6 in `inet`, so an IPv6 address with
    // no IPv6 range beneath it finds an IPv4 range whose end is below it and
    // answers nothing, which is right.
    // -------------------------------------------------------------------------
    // One authenticator model in a version of the FIDO MDS3 dataset (#62
    // P5), by the kind of key it is listed under and the key; or null.
    riskLookupFido: function (dataset, version, keyKind, key) {
      log.debug("Entering riskLookupFido(). " + keyKind);
      log.debug("Leaving riskLookupFido().");
      return pool.query(
        'SELECT key_kind, authenticator_key, description, protocol_family, ' +
        'certification_level, latest_status, latest_status_at, compromised, ' +
        'status_reports FROM sts_risk_fido_authenticators WHERE dataset = ' +
        '$1 AND version = $2 AND key_kind = $3 AND authenticator_key = $4',
        [dataset, version, keyKind, String(key || '').toLowerCase()]
      ).then(function (r) {
        const row = r.rows[0];
        return row ? { keyKind: row.key_kind, key: row.authenticator_key,
                       description: row.description,
                       protocolFamily: row.protocol_family,
                       certificationLevel: row.certification_level,
                       latestStatus: row.latest_status,
                       latestStatusAt: Number(row.latest_status_at) || 0,
                       compromised: !!row.compromised,
                       statusReports: row.status_reports || [] } : null;
      });
    },

    riskLookupRange: function (kind, realm, dataset, version, address) {
      log.debug("Entering riskLookupRange(). kind=" + kind);
      const table = { geo: 'sts_risk_geo_ranges',
                      asn: 'sts_risk_asn_ranges',
                      iplist: 'sts_risk_ip_lists' }[kind];
      if (!table) {
        log.debug("Leaving riskLookupRange(). Unknown kind.");
        return Promise.resolve(null);
      }
      const realmClause = kind === 'iplist' ? 'realm = $4 AND ' : '';
      const params = [dataset, version, String(address)];
      if (kind === 'iplist') {
        params.push(realm || '');
      }
      log.debug("Leaving riskLookupRange().");
      return pool.query(
        'SELECT * FROM (SELECT * FROM ' + table + ' WHERE ' + realmClause +
        'dataset = $1 AND version = $2 AND range_start <= $3::inet ' +
        'ORDER BY range_start DESC LIMIT 1) s WHERE s.range_end >= $3::inet',
        params
      ).then(function (r) {
        return r.rows[0] ? riskRangeFrom(kind, r.rows[0]) : null;
      });
    },

    // One attributable failure. The address arrives sealed and as a prefix;
    // the name as a subject or a keyed digest — never as typed.
    riskRecordFailure: function (row) {
      log.debug("Entering riskRecordFailure(). door=" + row.door);
      log.debug("Leaving riskRecordFailure().");
      return pool.query(
        'INSERT INTO sts_risk_failures (realm, at, door, subject, name_hmac, ' +
        'address_sealed, address_prefix, asn, error_code, origin) VALUES ' +
        '($1, $2, $3, $4, $5, $6, $7::cidr, $8, $9, $10) RETURNING id',
        [row.realm || '', Number(row.at), row.door, row.subject || '',
         row.nameHmac || '', row.addressSealed || '', row.addressPrefix,
         Number(row.asn) || 0, row.errorCode, processId]
      ).then(function (r) {
        return r.rows[0] ? String(r.rows[0].id) : '';
      });
    },

    // A page of one realm's failures, newest first, since `since`, narrowed
    // to one subject, one name digest or one prefix; with the matching count.
    riskListFailures: function (realm, opts) {
      log.debug("Entering riskListFailures(). realm=" + realm);
      const o = opts || {};
      const where = 'WHERE realm = $1 AND at >= $2 ' +
        'AND ($3 = \'\' OR subject = $3) AND ($4 = \'\' OR name_hmac = $4) ' +
        'AND ($5 = \'\' OR address_prefix = $5::cidr) ' +
        'AND ($6 = \'\' OR door = $6)';
      const params = [realm || '', Number(o.since) || 0, o.subject || '',
                      o.nameHmac || '', o.prefix || '', o.door || ''];
      log.debug("Leaving riskListFailures().");
      return Promise.all([
        pool.query(
          'SELECT id, realm, at, door, subject, name_hmac, address_sealed, ' +
          'host(address_prefix) || \'/\' || masklen(address_prefix) AS ' +
          'address_prefix, asn, error_code, origin FROM sts_risk_failures ' +
          where + ' ORDER BY at DESC, id DESC LIMIT $7 OFFSET $8',
          params.concat([Number(o.limit) || 50, Number(o.offset) || 0])),
        pool.query('SELECT count(*) AS total FROM sts_risk_failures ' + where,
                   params)
      ]).then(function (answers) {
        return { rows: answers[0].rows.map(riskFailureFrom),
                 total: Number((answers[1].rows[0] || {}).total) || 0 };
      });
    },

    // Failures older than `beforeMs`, deleted a batch at a time.
    riskPurgeFailures: function (beforeMs, limit) {
      log.debug("Entering riskPurgeFailures().");
      log.debug("Leaving riskPurgeFailures().");
      return pool.query(
        'DELETE FROM sts_risk_failures WHERE ctid IN (SELECT ctid FROM ' +
        'sts_risk_failures WHERE at < $1 LIMIT $2)',
        [Number(beforeMs), Number(limit) || 10000]
      ).then(function (r) {
        return r.rowCount || 0;
      });
    },

    // ===== THE MODEL'S HISTORY (#62 P2) =====================================

    // The counts of the given (feature, value) pairs for one subject — a
    // person's sub, or '*' for the realm's population. A pair never seen has
    // no row and is left out; the caller reads it as 0.
    riskFeatureCounts: function (realm, subject, pairs) {
      log.debug("Entering riskFeatureCounts(). pairs=" + pairs.length);
      log.debug("Leaving riskFeatureCounts().");
      return pool.query(
        'SELECT c.feature, c.value, c.count FROM sts_risk_feature_counts c ' +
        'JOIN unnest($3::text[], $4::text[]) AS p(feature, value) ' +
        'ON c.feature = p.feature AND c.value = p.value ' +
        'WHERE c.realm = $1 AND c.subject = $2',
        [realm || '', subject, pairs.map(function (p) {
          return p.feature;
        }), pairs.map(function (p) {
          return p.value;
        })]
      ).then(function (r) {
        return r.rows.map(function (row) {
          return { feature: row.feature, value: row.value,
                   count: Number(row.count) || 0 };
        });
      });
    },

    // How many distinct values a feature has for one subject, optionally
    // only those beginning with `prefix` — which is how a combination
    // feature (`ip>asn`, valued `<ip>|<asn>`) answers "how many networks has
    // this address been seen in".
    riskDistinctValues: function (realm, subject, feature, prefix) {
      log.debug("Entering riskDistinctValues(). " + feature);
      log.debug("Leaving riskDistinctValues().");
      return pool.query(
        'SELECT count(*) AS n FROM sts_risk_feature_counts WHERE realm = $1 ' +
        'AND subject = $2 AND feature = $3 AND ($4 = \'\' OR ' +
        'starts_with(value, $4))',
        [realm || '', subject, feature, prefix || '']
      ).then(function (r) {
        return Number((r.rows[0] || {}).n) || 0;
      });
    },

    // One sign-in counted: each (subject, feature, value) goes up by one, in
    // ONE statement, so two nodes counting at once never lose a count. The
    // caller has made the rows distinct (a statement may touch a row once).
    riskIncrementCounts: function (realm, rows, at) {
      log.debug("Entering riskIncrementCounts(). rows=" + rows.length);
      log.debug("Leaving riskIncrementCounts().");
      return pool.query(
        'INSERT INTO sts_risk_feature_counts (realm, subject, feature, value, ' +
        'count, first_at, last_at) SELECT $1, u.subject, u.feature, u.value, ' +
        '1, $5, $5 FROM unnest($2::text[], $3::text[], $4::text[]) AS ' +
        'u(subject, feature, value) ON CONFLICT (realm, subject, feature, ' +
        'value) DO UPDATE SET count = sts_risk_feature_counts.count + 1, ' +
        'last_at = EXCLUDED.last_at',
        [realm || '', rows.map(function (r) {
          return r.subject;
        }), rows.map(function (r) {
          return r.feature;
        }), rows.map(function (r) {
          return r.value;
        }), Number(at)]
      ).then(function (r) {
        return r.rowCount || 0;
      });
    },

    // One assessment, as `risk/risk_engine.ts` builds it. The address comes
    // sealed and as a prefix, as a failure's does.
    riskRecordAssessment: function (a) {
      log.debug("Entering riskRecordAssessment(). " + a.id);
      log.debug("Leaving riskRecordAssessment().");
      return pool.query(
        'INSERT INTO sts_risk_assessments (realm, id, at, phase, door, ' +
        'subject, session_id, client_id, address_sealed, address_prefix, ' +
        'asn, as_org, country, subdivision, city, latitude, longitude, ' +
        'accuracy_km, ip_lists, ua_hash, ua_family, ua_os, ua_platform, bot, ' +
        'ja4, credential_kind, credential_hash, aaguid, authenticator_cert, ' +
        'backup_eligible, backup_state, jkt, cert_fingerprint, datasets, ' +
        'signals, score, level, decision, policy_id, error_code, origin) ' +
        'VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::cidr, $11, $12, ' +
        '$13, $14, $15, $16, $17, $18, $19::text[], $20, $21, $22, $23, $24, ' +
        '$25, $26, $27, $28, $29, $30, $31, $32, $33, $34::jsonb, ' +
        '$35::jsonb, $36, $37, $38, $39, $40, $41) ON CONFLICT DO NOTHING',
        [a.realm || '', a.id, Number(a.at), a.phase, a.door, a.subject || '',
         a.sessionId || '', a.clientId || '', a.addressSealed || '',
         a.addressPrefix, Number(a.asn) || 0, a.asOrg || '', a.country || '',
         a.subdivision || '', a.city || '',
         a.latitude === null || a.latitude === undefined ? null
           : Number(a.latitude),
         a.longitude === null || a.longitude === undefined ? null
           : Number(a.longitude),
         Number(a.accuracyKm) || 0, a.ipLists || [], a.uaHash || '',
         a.uaFamily || '', a.uaOs || '', a.uaPlatform || '', !!a.bot,
         a.ja4 || '', a.credentialKind || '', a.credentialHash || '',
         a.aaguid || '', a.authenticatorCert || '',
         typeof a.backupEligible === 'boolean' ? a.backupEligible : null,
         typeof a.backupState === 'boolean' ? a.backupState : null,
         a.jkt || '', a.certFingerprint || '',
         JSON.stringify(a.datasets || {}), JSON.stringify(a.signals || []),
         Number(a.score), a.level, a.decision, a.policyId || '',
         a.errorCode || '', processId]
      ).then(function (r) {
        return r.rowCount > 0;
      });
    },

    // A page of one realm's assessments, newest first, optionally one
    // subject's or one level's; with the matching count. Never the sealed
    // address.
    riskListAssessments: function (realm, opts) {
      log.debug("Entering riskListAssessments(). realm=" + realm);
      const o = opts || {};
      const where = 'WHERE realm = $1 AND at >= $2 AND ($3 = \'\' OR ' +
        'subject = $3) AND ($4 = \'\' OR level = $4)';
      const params = [realm || '', Number(o.since) || 0, o.subject || '',
                      o.level || ''];
      log.debug("Leaving riskListAssessments().");
      return Promise.all([
        pool.query(
          'SELECT id, at, phase, door, subject, session_id, client_id, ' +
          'host(address_prefix) || \'/\' || masklen(address_prefix) AS ' +
          'address_prefix, asn, as_org, country, subdivision, city, ' +
          'ip_lists, ua_family, ua_os, ua_platform, bot, ja4, ' +
          'credential_kind, aaguid, backup_eligible, backup_state, ' +
          'datasets, signals, score, level, decision, feedback, ' +
          'feedback_at FROM ' +
          'sts_risk_assessments ' + where +
          ' ORDER BY at DESC, id DESC LIMIT $5 OFFSET $6',
          params.concat([Number(o.limit) || 50, Number(o.offset) || 0])),
        pool.query('SELECT count(*) AS total FROM sts_risk_assessments ' +
                   where, params)
      ]).then(function (answers) {
        return {
          total: Number((answers[1].rows[0] || {}).total) || 0,
          rows: answers[0].rows.map(function (r) {
            return { id: r.id, at: Number(r.at), phase: r.phase,
                     door: r.door, subject: r.subject,
                     sessionId: r.session_id, clientId: r.client_id,
                     addressPrefix: String(r.address_prefix),
                     asn: Number(r.asn) || 0, asOrg: r.as_org,
                     country: r.country, subdivision: r.subdivision,
                     city: r.city, ipLists: r.ip_lists || [],
                     uaFamily: r.ua_family, uaOs: r.ua_os,
                     uaPlatform: r.ua_platform, bot: !!r.bot, ja4: r.ja4,
                     credentialKind: r.credential_kind, aaguid: r.aaguid,
                     backupEligible: r.backup_eligible,
                     backupState: r.backup_state,
                     datasets: r.datasets || {}, signals: r.signals || [],
                     score: Number(r.score), level: r.level,
                     decision: r.decision,
                     feedback: r.feedback || '',
                     feedbackAt: Number(r.feedback_at) || 0 };
          })
        };
      });
    },

    // WHAT THE PERSON SAID about one of their own sign-ins (#62 P6): only
    // an assessment of that subject is touched, and only once.
    riskSetFeedback: function (realm, id, subject, feedback, at) {
      log.debug("Entering riskSetFeedback(). " + id);
      log.debug("Leaving riskSetFeedback().");
      return pool.query(
        'UPDATE sts_risk_assessments SET feedback = $4, feedback_at = $5 ' +
        'WHERE realm = $1 AND id = $2 AND subject = $3 AND feedback = \'\'',
        [realm || '', id, subject, feedback, Number(at)]
      ).then(function (r) {
        return r.rowCount > 0;
      });
    },

    // WHAT WAS DECIDED on an assessment (#62 P3): the issuance policy's
    // answer, the policy that gave it and the code of a refusal, and the
    // session it became — none of which exists when the assessment is
    // written, because it is written BEFORE the session is started. A
    // session id is only ever filled in, never cleared.
    riskSettleAssessment: function (a) {
      log.debug("Entering riskSettleAssessment(). " + a.id);
      log.debug("Leaving riskSettleAssessment().");
      return pool.query(
        'UPDATE sts_risk_assessments SET decision = $3, policy_id = $4, ' +
        'error_code = $5, session_id = CASE WHEN $6 = \'\' THEN session_id ' +
        'ELSE $6 END WHERE realm = $1 AND id = $2',
        [a.realm || '', a.id, a.decision || '', a.policyId || '',
         a.errorCode || '', a.sessionId || '']
      ).then(function (r) {
        return r.rowCount > 0;
      });
    },

    // A REACTION TO A CHANGE OF RISK, CLAIMED ONCE (#62 P4): `actions` holds
    // one key per reaction naming the assessment it was last taken for, and
    // the claim succeeds only where that is not already this one — so a
    // retry, or a second node reading the same change, does not end
    // somebody's sessions twice. Bounded by the number of reactions.
    riskClaimAction: function (realm, subject, reaction, assessmentId) {
      log.debug("Entering riskClaimAction(). " + reaction);
      log.debug("Leaving riskClaimAction().");
      return pool.query(
        'UPDATE sts_risk_subjects SET actions = actions || ' +
        'jsonb_build_object($3::text, $4::text) WHERE realm = $1 AND ' +
        'subject = $2 AND (actions->>$3::text) IS DISTINCT FROM $4::text',
        [realm || '', subject || '', reaction, assessmentId || '']
      ).then(function (r) {
        return r.rowCount > 0;
      });
    },

    // One person's standing, or null — what an issuance with no session to
    // read its risk from stands on (#62 P3).
    riskSubjectOf: function (realm, subject) {
      log.debug("Entering riskSubjectOf(). realm=" + realm);
      log.debug("Leaving riskSubjectOf().");
      return pool.query(
        'SELECT subject, score, level, previous_level, reason, ' +
        'last_assessment, crossed_at, updated_at FROM sts_risk_subjects ' +
        'WHERE realm = $1 AND subject = $2', [realm || '', subject || '']
      ).then(function (r) {
        const row = r.rows[0];
        return row ? { subject: row.subject, score: Number(row.score),
                       level: row.level, previousLevel: row.previous_level,
                       reason: row.reason,
                       lastAssessment: row.last_assessment,
                       crossedAt: Number(row.crossed_at) || 0,
                       updatedAt: Number(row.updated_at) || 0 } : null;
      });
    },

    // A person's current standing, replaced whole.
    riskUpsertSubject: function (s) {
      log.debug("Entering riskUpsertSubject().");
      log.debug("Leaving riskUpsertSubject().");
      return pool.query(
        'INSERT INTO sts_risk_subjects (realm, subject, score, level, ' +
        'previous_level, reason, last_assessment, crossed_at, actions, ' +
        'feedback, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, ' +
        '$9::jsonb, $10, $11) ON CONFLICT (realm, subject) DO UPDATE SET ' +
        'score = EXCLUDED.score, level = EXCLUDED.level, previous_level = ' +
        'sts_risk_subjects.level, reason = EXCLUDED.reason, last_assessment ' +
        '= EXCLUDED.last_assessment, crossed_at = CASE WHEN ' +
        'sts_risk_subjects.level <> EXCLUDED.level THEN EXCLUDED.updated_at ' +
        'ELSE sts_risk_subjects.crossed_at END, updated_at = ' +
        'EXCLUDED.updated_at',
        [s.realm || '', s.subject, Number(s.score), s.level, '', s.reason || '',
         s.lastAssessment || '', Number(s.updatedAt), JSON.stringify({}), '',
         Number(s.updatedAt)]
      ).then(function (r) {
        return r.rowCount > 0;
      });
    },

    // The realm's people by current standing, highest score first.
    riskListSubjects: function (realm, opts) {
      log.debug("Entering riskListSubjects(). realm=" + realm);
      const o = opts || {};
      log.debug("Leaving riskListSubjects().");
      return pool.query(
        'SELECT subject, score, level, previous_level, reason, ' +
        'last_assessment, crossed_at, updated_at FROM sts_risk_subjects ' +
        'WHERE realm = $1 ORDER BY score DESC, updated_at DESC LIMIT $2',
        [realm || '', Number(o.limit) || 50]
      ).then(function (r) {
        return r.rows.map(function (row) {
          return { subject: row.subject, score: Number(row.score),
                   level: row.level, previousLevel: row.previous_level,
                   reason: row.reason, lastAssessment: row.last_assessment,
                   crossedAt: Number(row.crossed_at) || 0,
                   updatedAt: Number(row.updated_at) || 0 };
        });
      });
    },

    // The last context a live session was assessed in, replaced whole — what
    // continuous evaluation (P4) compares a later request with.
    riskUpsertSessionContext: function (c) {
      log.debug("Entering riskUpsertSessionContext().");
      log.debug("Leaving riskUpsertSessionContext().");
      return pool.query(
        'INSERT INTO sts_risk_session_context (realm, session_id, subject, ' +
        'address_prefix, asn, country, ua_hash, ja4, jkt, score, level, ' +
        'updated_at) VALUES ($1, $2, $3, $4::cidr, $5, $6, $7, $8, $9, $10, ' +
        '$11, $12) ON CONFLICT (realm, session_id) DO UPDATE SET subject = ' +
        'EXCLUDED.subject, address_prefix = EXCLUDED.address_prefix, asn = ' +
        'EXCLUDED.asn, country = EXCLUDED.country, ua_hash = ' +
        'EXCLUDED.ua_hash, ja4 = EXCLUDED.ja4, jkt = EXCLUDED.jkt, score = ' +
        'EXCLUDED.score, level = EXCLUDED.level, updated_at = ' +
        'EXCLUDED.updated_at',
        [c.realm || '', c.sessionId, c.subject, c.addressPrefix,
         Number(c.asn) || 0, c.country || '', c.uaHash || '', c.ja4 || '',
         c.jkt || '', Number(c.score), c.level, Number(c.updatedAt)]
      ).then(function (r) {
        return r.rowCount > 0;
      });
    },

    // Assessments, feature counts and session contexts past their
    // retention, a batch at a time.
    riskPurgeHistory: function (table, beforeMs, limit) {
      log.debug("Entering riskPurgeHistory(). " + table);
      const column = { assessments: 'at', counts: 'last_at',
                       sessions: 'updated_at' }[table];
      const name = { assessments: 'sts_risk_assessments',
                     counts: 'sts_risk_feature_counts',
                     sessions: 'sts_risk_session_context' }[table];
      if (!column) {
        log.debug("Leaving riskPurgeHistory(). Unknown table.");
        return Promise.resolve(0);
      }
      log.debug("Leaving riskPurgeHistory().");
      return pool.query(
        'DELETE FROM ' + name + ' WHERE ctid IN (SELECT ctid FROM ' + name +
        ' WHERE ' + column + ' < $1 LIMIT $2)',
        [Number(beforeMs), Number(limit) || 10000]
      ).then(function (r) {
        return r.rowCount || 0;
      });
    },

    // ===== WHO ACCEPTED WHICH PROVIDER'S TERMS (#62, schema 8) ==============

    // One acceptance, appended; never updated or deleted, because it is the
    // record of who agreed to hold a provider's data on what terms.
    riskRecordAcceptance: function (a) {
      log.debug("Entering riskRecordAcceptance(). " + a.provider);
      log.debug("Leaving riskRecordAcceptance().");
      return pool.query(
        'INSERT INTO sts_risk_terms_acceptances (provider, terms_digest, ' +
        'terms_text, accepted_by, accepted_via, deployment, page_digest, ' +
        'accepted_at, origin) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ' +
        'RETURNING id',
        [a.provider, a.termsDigest, a.termsText, a.acceptedBy, a.acceptedVia,
         a.deployment || '', a.pageDigest || '', Number(a.acceptedAt),
         processId]
      ).then(function (r) {
        return r.rows[0] ? String(r.rows[0].id) : '';
      });
    },

    // Every acceptance, newest first.
    riskListAcceptances: function () {
      log.debug("Entering riskListAcceptances().");
      log.debug("Leaving riskListAcceptances().");
      return pool.query(
        'SELECT id, provider, terms_digest, terms_text, accepted_by, ' +
        'accepted_via, deployment, page_digest, accepted_at FROM ' +
        'sts_risk_terms_acceptances ORDER BY accepted_at DESC, id DESC'
      ).then(function (r) {
        return r.rows.map(function (row) {
          return { id: String(row.id), provider: row.provider,
                   termsDigest: row.terms_digest, termsText: row.terms_text,
                   acceptedBy: row.accepted_by,
                   acceptedVia: row.accepted_via,
                   deployment: row.deployment, pageDigest: row.page_digest,
                   acceptedAt: Number(row.accepted_at) || 0 };
        });
      });
    },

    mergeKeys: function (realmId, ciphertext, merge) {
      log.debug("Entering mergeKeys(). realm=" + realmId);
      const id = String(realmId);
      log.debug("Leaving mergeKeys().");
      return withTransaction(function (client) {
        function lockAndMerge() {
          log.debug("Entering lockAndMerge().");
          log.debug("Leaving lockAndMerge().");
          return client.query(
            'SELECT material FROM sts_keys WHERE realm = $1 FOR UPDATE', [id]
          ).then(function (r) {
            const row = (r.rows || [])[0] || null;
            const current = row ? row.material : null;
            const next = merge(current);
            if (!next || next === current) {
              return { written: false, inserted: false, material: current };
            }
            if (row) {
              return client.query(
                'UPDATE sts_keys SET material = $2, written_at = now() ' +
                'WHERE realm = $1', [id, next]
              ).then(function () {
                return recordChanges(client, [{ kind: 'keys', realm: id }]);
              }).then(function () {
                return { written: true, inserted: false, material: next };
              });
            }
            // NO ROW TO LOCK. The INSERT is the arbiter here: of two
            // transactions reaching this line for one realm, the second waits
            // on the first's uncommitted row and then inserts nothing — and
            // is sent round again, where the row now exists and is locked.
            return client.query(
              'INSERT INTO sts_keys (realm, material, written_at) VALUES ' +
              '($1, $2, now()) ON CONFLICT (realm) DO NOTHING', [id, next]
            ).then(function (inserted) {
              if (!inserted.rowCount) {
                return null;
              }
              return recordChanges(client, [{ kind: 'keys', realm: id }])
                .then(function () {
                  return { written: true, inserted: true, material: next };
                });
            });
          });
        }
        return lockAndMerge().then(function (first) {
          return first || lockAndMerge();
        }).then(function (second) {
          if (!second) {
            throw new Error(errorCodes.tag('STS-STORE-0050') + 'the "' + id +
                            '" row of sts_keys was inserted and removed by ' +
                            'other writers while this one waited, twice; ' +
                            'nothing was written.');
          }
          return second;
        });
      });
    },

    // A SHARED SECRET, first writer wins. `material` is already sealed by the
    // caller. Whatever is in the table afterwards is what every node uses —
    // this caller's offer if it was first, somebody else's if not.
    ensureSharedSecret: function (name, material) {
      log.debug("Entering ensureSharedSecret(). name=" + name);
      log.debug("Leaving ensureSharedSecret().");
      return pool.query(
        'INSERT INTO sts_cluster_secrets (name, material, created_by, ' +
        'created_at) VALUES ($1, $2, $3, ' + DB_NOW + ') ON CONFLICT (name) ' +
        'DO NOTHING', [String(name), String(material), processId]
      ).then(function (inserted) {
        return pool.query(
          'SELECT material, created_by, created_at FROM sts_cluster_secrets ' +
          'WHERE name = $1', [String(name)]
        ).then(function (r) {
          const row = (r.rows || [])[0] || null;
          return row ? { material: row.material, createdBy: row.created_by,
                         createdAt: Number(row.created_at),
                         offered: (inserted.rowCount || 0) > 0 } : null;
        });
      });
    },

    // =====================================================================
    // THE USED-ASSERTION HISTORY. Six statements, and the first is the one
    // the table exists for.
    // =====================================================================

    // THE CLAIM. One statement decides all three outcomes a caller cares
    // about, under the primary key's own lock:
    //
    //   * no live row with this key, and room → INSERTED, `claimed: true`;
    //   * a live row with this key → the conflict's UPDATE is guarded by
    //     `expires_at < now`, so it updates nothing and nothing is returned;
    //   * no room → the SELECT feeding the INSERT yields no row.
    //
    // An EXPIRED row with the key — a client reusing a jti after its first
    // document expired, before the sweep — is REPLACED, which is what "until it
    // would have expired" means. Two concurrent claims for one key: the second
    // waits on the first's uncommitted row, then sees a live conflict and
    // updates nothing. The cap's count is not under a lock, so two claims at
    // the edge can put the realm one or two over; the cap bounds a table, and a
    // replay is what the key bounds.
    //
    // Only on the no-row answer is the store asked again, to say WHICH of the
    // two refusals it was and whose row it is — a refusal is the uncommon case
    // and an accepted assertion costs one round trip.
    claimUsedAssertion: function (row, opts) {
      log.debug("Entering claimUsedAssertion().");
      const now = Number(opts.now);
      const cap = Number(opts.cap);
      log.debug("Leaving claimUsedAssertion().");
      return pool.query(
        'INSERT INTO sts_used_assertions (realm, key, format, used_as, ' +
        'issuer, identifier, client_id, subject, state, reservation, origin, ' +
        'used_at, spent_at, expires_at) ' +
        'SELECT $1::text, $2::text, $3::text, $4::text, $5::text, $6::text, ' +
        '$7::text, $8::text, $9::text, $10::text, $11::text, $12::bigint, ' +
        '$13::bigint, $14::bigint ' +
        'WHERE (SELECT count(*) FROM sts_used_assertions ' +
        '       WHERE realm = $1::text AND expires_at >= $15::bigint) ' +
        '      < $16::bigint ' +
        'ON CONFLICT (realm, key) DO UPDATE SET ' +
        'format = EXCLUDED.format, used_as = EXCLUDED.used_as, ' +
        'issuer = EXCLUDED.issuer, identifier = EXCLUDED.identifier, ' +
        'client_id = EXCLUDED.client_id, subject = EXCLUDED.subject, ' +
        'state = EXCLUDED.state, reservation = EXCLUDED.reservation, ' +
        'origin = EXCLUDED.origin, used_at = EXCLUDED.used_at, ' +
        'spent_at = EXCLUDED.spent_at, expires_at = EXCLUDED.expires_at ' +
        'WHERE sts_used_assertions.expires_at < $15::bigint ' +
        'RETURNING key',
        [row.realm, row.key, row.format, row.use, row.issuer, row.identifier,
         row.clientId, row.subject, row.state, row.reservation, row.origin,
         row.usedAt, row.spentAt, row.expiresAt, now, cap]
      ).then(function (r) {
        if (r.rowCount) {
          return { claimed: true };
        }
        return Promise.all([
          pool.query(
            'SELECT format, used_as, issuer, identifier, client_id, subject, ' +
            'state, origin, used_at, spent_at, expires_at ' +
            'FROM sts_used_assertions ' +
            'WHERE realm = $1 AND key = $2 AND expires_at >= $3',
            [row.realm, row.key, now]),
          pool.query(
            'SELECT count(*) AS live FROM sts_used_assertions ' +
            'WHERE realm = $1 AND expires_at >= $2', [row.realm, now])
        ]).then(function (answers) {
          const found = answers[0].rows[0];
          const live = Number((answers[1].rows[0] || {}).live) || 0;
          return { claimed: false, live: live,
                   existing: found ? usedRowFrom(found) : null };
        });
      });
    },

    // A reservation becomes `spent` when its response finished with a 2xx, and
    // is DELETED otherwise. Both are pinned to the reservation, so a claim that
    // outlived its row (it expired and somebody else's replaced it) cannot
    // settle a row that is not its own.
    settleUsedAssertion: function (realm, key, reservation, spent, at) {
      log.debug("Entering settleUsedAssertion(). spent=" + spent);
      log.debug("Leaving settleUsedAssertion().");
      return (spent
        ? pool.query(
            'UPDATE sts_used_assertions SET state = \'spent\', ' +
            'spent_at = $4 WHERE realm = $1 AND key = $2 AND reservation = $3',
            [realm, key, reservation, Number(at)])
        : pool.query(
            'DELETE FROM sts_used_assertions WHERE realm = $1 AND key = $2 ' +
            'AND reservation = $3 AND state = \'reserved\'',
            [realm, key, reservation])
      ).then(function (r) {
        return r.rowCount || 0;
      });
    },

    // ONE LIVE ROW BY ITS KEY, or null — `used_assertions.peek()`, the look an
    // RFC 9101 request object gets on each pass through the authorization
    // endpoint before it is claimed (#35). A read and nothing else: the claim
    // above is what decides.
    findUsedAssertion: function (realm, key, nowMs) {
      log.debug("Entering findUsedAssertion(). realm=" + realm);
      log.debug("Leaving findUsedAssertion().");
      return pool.query(
        'SELECT format, used_as, issuer, identifier, client_id, subject, ' +
        'state, origin, used_at, spent_at, expires_at ' +
        'FROM sts_used_assertions ' +
        'WHERE realm = $1 AND key = $2 AND expires_at >= $3',
        [realm, key, Number(nowMs)]
      ).then(function (r) {
        return r.rows[0] ? usedRowFrom(r.rows[0]) : null;
      });
    },

    // One page of one realm's unexpired rows, newest first, with the count that
    // matched and the realm's live total. The search is a substring over the
    // four text columns a reader would paste into it, with `strpos` rather
    // than `LIKE` so that a `%` or `_` in somebody's jti is a character and not
    // a pattern.
    listUsedAssertions: function (realm, opts) {
      log.debug("Entering listUsedAssertions(). realm=" + realm);
      const o = opts || {};
      const now = Number(o.now);
      const where = 'WHERE realm = $1 AND expires_at >= $2 ' +
        'AND ($3 = \'\' OR format = $3) AND ($4 = \'\' OR used_as = $4) ' +
        'AND ($5 = \'\' OR state = $5) ' +
        'AND ($6 = \'\' OR strpos(lower(issuer || \' \' || identifier || ' +
        '\' \' || client_id || \' \' || subject), lower($6)) > 0)';
      const params = [realm, now, o.format || '', o.use || '', o.state || '',
                      o.q || ''];
      log.debug("Leaving listUsedAssertions().");
      return Promise.all([
        pool.query(
          'SELECT format, used_as, issuer, identifier, client_id, subject, ' +
          'state, origin, used_at, spent_at, expires_at ' +
          'FROM sts_used_assertions ' + where +
          ' ORDER BY used_at DESC LIMIT $7 OFFSET $8',
          params.concat([Number(o.limit) || 50, Number(o.offset) || 0])),
        pool.query('SELECT count(*) AS total FROM sts_used_assertions ' + where,
                   params),
        pool.query(
          'SELECT count(*) AS live FROM sts_used_assertions ' +
          'WHERE realm = $1 AND expires_at >= $2', [realm, now])
      ]).then(function (answers) {
        return {
          rows: answers[0].rows.map(usedRowFrom),
          total: Number((answers[1].rows[0] || {}).total) || 0,
          live: Number((answers[2].rows[0] || {}).live) || 0
        };
      });
    },

    purgeUsedAssertions: function (nowMs) {
      log.debug("Entering purgeUsedAssertions().");
      log.debug("Leaving purgeUsedAssertions().");
      return pool.query('DELETE FROM sts_used_assertions WHERE expires_at < $1',
                        [Number(nowMs)])
        .then(function (r) {
          return r.rowCount || 0;
        });
    },

    removeUsedAssertions: function (realm) {
      log.debug("Entering removeUsedAssertions(). realm=" + realm);
      log.debug("Leaving removeUsedAssertions().");
      return pool.query('DELETE FROM sts_used_assertions WHERE realm = $1',
                        [realm])
        .then(function (r) {
          return r.rowCount || 0;
        });
    },

    // Rows older than the retention window. Returns HOW MANY, because the one
    // caller logs it and a purge that reported nothing would leave an operator
    // unable to tell "it worked" from "there was nothing to do".
    // THE TOMBSTONES OF ENDED ROWS, older than `beforeMs` (2026-09-14, #46).
    // A tombstone must outlive every copy of its row a node could still write
    // back; `persistence_minted.js` asks with `persistence.mintedRetention`,
    // which is also the most a restored row can be. One statement on the pool
    // and idempotent, so any node may run it.
    purgeTombstones: function (beforeMs) {
      log.debug('Entering the postgres driver purgeTombstones().');
      log.debug("Leaving purgeTombstones().");
      return pool.query(
        'DELETE FROM sts_minted WHERE body = $1 AND ' +
        'written_at < to_timestamp($2 / 1000.0)',
        [TOMBSTONE, Number(beforeMs)]
      ).then(function (r) {
        return r.rowCount || 0;
      });
    },

    // `handles`, when given, limits the delete to those stores — the
    // short-lived ones (`retain: 'age'`, 2026-09-18). Without it every row
    // older than `beforeMs` goes, which is right only for the ephemeral-key
    // clear, where nothing in the table can be opened anyway.
    purgeMinted: function (beforeMs, handles) {
      log.debug('Entering the postgres driver purgeMinted(). before=' +
                beforeMs);
      log.debug("Leaving purgeMinted().");
      if (Array.isArray(handles) && !handles.length) {
        return Promise.resolve(0);
      }
      const limited = Array.isArray(handles);
      return pool.query(
        'DELETE FROM sts_minted WHERE written_at < to_timestamp($1 / 1000.0)' +
        (limited ? ' AND handle = ANY($2::text[])' : ''),
        limited ? [Number(beforeMs), handles.map(String)] : [Number(beforeMs)]
      ).then(function (r) {
        log.debug('Leaving the postgres driver purgeMinted(). ' +
                  (r.rowCount || 0) + ' row(s).');
        return r.rowCount || 0;
      });
    }
  };
}

// ---------------------------------------------------------------------------
// WHAT THIS DRIVER MAKES TRUE FOR SEVERAL NODES (#46 section 3), at require
// time — which is before `cluster.gate()` reads the table, because
// `persistence.openStore()` requires this module to create the driver it then
// hands the gate.
//
//   * `store.no-foreign-deletes` — `saveRealms()` and `saveOverrides()` write
//     a delta and delete only what the writer removed; `saveDirectory()`
//     deletes a realm's rows only for a realm `persistence.js` removed here.
//   * `directory.concurrent-writes` — `saveDirectory()` merges each entry with
//     the row as it is now (`directory_merge.js`) and keeps the first of two
//     adds; `persistence.js` applies what the store decided; the create doors
//     claim their names across nodes (`ldap/directory_create_claims.ts`).
// ---------------------------------------------------------------------------
capabilities.provide('store.no-foreign-deletes');
capabilities.provide('directory.concurrent-writes');

module.exports = {
  create: create,
  // For `tests/database_metrics.js`, which checks that every probe is
  // GROUPED into a section the page actually draws — a probe in a group the
  // renderer has no heading for is collected on every render and shown to
  // nobody, and that is an error nowhere.
  METRIC_PROBES: METRIC_PROBES,
  CHANNEL: CHANNEL,
  SCHEMA: SCHEMA,
  SCHEMA_OBJECTS: SCHEMA_OBJECTS,
  SCHEMA_COLUMNS: SCHEMA_COLUMNS,
  SCHEMA_VERSION: SCHEMA_VERSION
};
