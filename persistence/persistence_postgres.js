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
// the DN as written. Two clients may spell one DN four ways — `UID=Alice, OU=Users`
// and `uid=alice,ou=users` name one entry — and `ldap_server.js`'s
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

// A CHANNEL NAME AND A SCHEMA VERSION, both spelt once here.
const CHANNEL = 'sts_ldap_change';
// 2 SINCE 2026-09-06, when `sts_keys` joined the three tables this driver has
// always had. Nothing reads this yet — it is here so that a future change has
// something to look at other than the shape of the tables — but leaving it at 1
// over a different schema would make the one thing it is for useless.
const SCHEMA_VERSION = 3;

// The schema, created if it is not there. `IF NOT EXISTS` throughout rather
// than a migration table, and that is a decision rather than laziness: this is
// a mock identity service, the schema is six tables, and a migration
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
  'CREATE INDEX IF NOT EXISTS sts_ldap_entries_realm ON sts_ldap_entries (realm)' },
  { name: 'sts_realms', statement:
  'CREATE TABLE IF NOT EXISTS sts_realms (' +
  '  id          text PRIMARY KEY,' +
  '  name        text,' +
  '  description text,' +
  '  created_at  bigint,' +
  '  overrides   jsonb NOT NULL DEFAULT \'{}\'::jsonb)' },
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
  // `realm` IS THE EMPTY STRING FOR THE SHARED STORES — the Kerberos principal
  // database, the replay caches, the rate limiter's buckets — which have no
  // realm because the sockets they belong to have no path to put one in. It is
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
  'CREATE INDEX IF NOT EXISTS sts_minted_handle ON sts_minted (handle, realm)' },
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
  // What version of the above is on disk. One row, and nothing reads it yet —
  // it is here so that a future change has something to look at other than the
  // shape of the tables.
  { name: 'sts_schema', statement:
  'CREATE TABLE IF NOT EXISTS sts_schema (' +
  '  version int PRIMARY KEY,' +
  '  applied_at timestamptz NOT NULL DEFAULT now())' }
];

// THE STATEMENTS ALONE, which is what this module exported before the pairing
// above existed and what `tests/postgres_schema.js` compares against
// `postgres/schema.sql`. Derived rather than written twice, so the two cannot
// come apart.
const SCHEMA = SCHEMA_OBJECTS.map(function (object) { return object.statement; });


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
// UPDATE and DELETE on six tables and USAGE — not CREATE — on one schema. It
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
    sql: 'SELECT version() AS version, ' +
         '       current_setting(\'server_version_num\') AS version_num, ' +
         '       current_database() AS database, ' +
         '       current_user AS connected_as, ' +
         '       session_user AS session_user, ' +
         '       current_schema() AS search_schema, ' +
         '       pg_backend_pid() AS backend_pid, ' +
         '       pg_postmaster_start_time() AS started_at, ' +
         '       date_trunc(\'second\', now() - pg_postmaster_start_time())::text AS uptime, ' +
         '       pg_conf_load_time() AS config_loaded_at, ' +
         '       pg_is_in_recovery() AS in_recovery, ' +
         '       current_setting(\'server_encoding\') AS server_encoding, ' +
         '       current_setting(\'TimeZone\') AS timezone' },

  // THE SIZE, as a number AND as a string. `pg_size_pretty` is what a person
  // reads and the raw byte count is what anything comparing two of these
  // needs; computing the pretty form here rather than in the renderer means
  // one answer to "how big is this" rather than this service's own rounding
  // beside postgres's.
  { id: 'size', group: 'Server', shape: 'row',
    what: 'How much disk this database occupies.',
    sql: 'SELECT pg_database_size(current_database()) AS bytes, ' +
         '       pg_size_pretty(pg_database_size(current_database())) AS pretty' },

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
    sql: 'SELECT count(*) AS visible, ' +
         '       count(state) AS readable, ' +
         '       count(*) FILTER (WHERE state = \'active\') AS active, ' +
         '       count(*) FILTER (WHERE state = \'idle\') AS idle, ' +
         '       count(*) FILTER (WHERE state = \'idle in transaction\') ' +
         '         AS idle_in_transaction, ' +
         '       count(*) FILTER (WHERE wait_event IS NOT NULL) AS waiting, ' +
         '       current_setting(\'max_connections\')::int AS max_connections, ' +
         '       (SELECT count(*) FROM pg_stat_activity) AS server_wide ' +
         'FROM pg_stat_activity WHERE datname = current_database()' },

  { id: 'backends', group: 'Activity', shape: 'rows',
    what: 'One row per backend on this database. A backend belonging to ' +
          'another role shows as a row with its state and its query ' +
          'withheld, which is what a non-monitoring role is shown.',
    sql: 'SELECT pid, usename, application_name, client_addr, backend_type, ' +
         '       state, wait_event_type, wait_event, ' +
         '       date_trunc(\'second\', now() - backend_start)::text AS connected_for, ' +
         '       date_trunc(\'second\', now() - state_change)::text AS in_state_for, ' +
         '       CASE WHEN xact_start IS NULL THEN NULL ' +
         '            ELSE date_trunc(\'second\', now() - xact_start)::text END ' +
         '         AS transaction_age ' +
         'FROM pg_stat_activity WHERE datname = current_database() ' +
         'ORDER BY backend_start' },

  { id: 'locks', group: 'Activity', shape: 'rows',
    what: 'Locks held and waited for, by mode. A waiting lock on a mock is ' +
          'almost always this service contending with itself across the ' +
          'request-worker pool.',
    sql: 'SELECT mode, granted, count(*) AS count FROM pg_locks ' +
         'WHERE database IS NULL OR database = ' +
         '      (SELECT oid FROM pg_database WHERE datname = current_database()) ' +
         'GROUP BY mode, granted ORDER BY granted, mode' },

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
    sql: 'SELECT c.relname AS relname, ' +
         '       pg_total_relation_size(c.oid) AS total_bytes, ' +
         '       pg_size_pretty(pg_total_relation_size(c.oid)) AS total, ' +
         '       pg_size_pretty(pg_relation_size(c.oid)) AS heap, ' +
         '       pg_size_pretty(pg_indexes_size(c.oid)) AS indexes, ' +
         '       CASE WHEN c.reltoastrelid = 0 THEN NULL ' +
         '            ELSE pg_size_pretty(pg_total_relation_size(c.reltoastrelid)) ' +
         '       END AS toast, ' +
         '       CASE WHEN c.reltuples < 0 THEN NULL ' +
         '            ELSE c.reltuples::bigint END AS estimated_rows, ' +
         '       (SELECT count(*) FROM pg_index i WHERE i.indrelid = c.oid) ' +
         '         AS index_count ' +
         'FROM pg_class c ' +
         'WHERE c.relnamespace = current_schema()::regnamespace ' +
         '  AND c.relkind = \'r\' ORDER BY pg_total_relation_size(c.oid) DESC' },

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
    sql: 'SELECT name, setting, unit, source, boot_val, pending_restart ' +
         'FROM pg_settings ' +
         'WHERE source NOT IN (\'default\', \'override\') ' +
         '   OR name IN (\'max_connections\', \'shared_buffers\', ' +
         '               \'work_mem\', \'maintenance_work_mem\', ' +
         '               \'effective_cache_size\', \'wal_level\', ' +
         '               \'synchronous_commit\', \'fsync\', ' +
         '               \'full_page_writes\', \'autovacuum\', ' +
         '               \'checkpoint_timeout\', \'max_wal_size\', ' +
         '               \'ssl\', \'data_checksums\', ' +
         '               \'default_transaction_isolation\', ' +
         '               \'statement_timeout\', \'idle_in_transaction_session_timeout\') ' +
         'ORDER BY name' },

  { id: 'extensions', group: 'Configuration', shape: 'rows',
    what: 'Extensions installed in this database.',
    sql: 'SELECT extname AS name, extversion AS version, ' +
         '       n.nspname AS schema ' +
         'FROM pg_extension e JOIN pg_namespace n ON n.oid = e.extnamespace ' +
         'ORDER BY extname' }
];

function create(options) {
  const url = options.url;
  const log = options.log;

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
                     : 'NOT verified — persistence.databaseTlsRejectUnauthorized ' +
                       'is off, which is the honest setting for the ' +
                       'self-signed pair the compose stack generates. The ' +
                       'connection is encrypted either way.'));
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

  // WHO THIS PROCESS IS. `process.pid` alone is not enough — two containers can
  // hold the same pid — so it is joined to the start time. It is stamped on
  // every `sts_changes` row and on every notification, and it does ONE job:
  // letting a process skip its own writes instead of applying its own work
  // back over itself. That was written for "a future listener"; the listener
  // is `watchChanges()` below.
  const processId = String(process.pid) + '-' + String(Date.now());

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
  // query: `common/request_worker.js` needs to know whether its flush actually
  // wrote anything, and asking the database that after every request is a round
  // trip for a question this process already knows the answer to.
  let written = 0;

  function recordChanges(client, rows) {
    if (!rows || !rows.length) {
      return Promise.resolve();
    }
    written += rows.length;
    // ONE STATEMENT FOR THE WHOLE BATCH. A directory flush can carry hundreds
    // of moved entries and a round trip each would make the log more
    // expensive than the write it describes.
    const values = [];
    const params = [];
    rows.forEach(function (row, i) {
      const base = i * 4;
      values.push('($' + (base + 1) + ', $' + (base + 2) + ', $' +
                  (base + 3) + ', $' + (base + 4) + ')');
      params.push(processId, row.kind, row.realm || '', row.key || '');
    });
    return client.query(
      'INSERT INTO sts_changes (origin, kind, realm, key) VALUES ' +
      values.join(', '), params
    ).then(function () {
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
    const onError = function (err) {
      log.error(errorCodes.tag('STS-STORE-0031') +
                'persistence: the postgres connection held by ' + what +
                ' errored: ' + err.message + '. It is being discarded; the ' +
                'pool will make another. This is logged rather than thrown ' +
                'because an unhandled error on a client is a process exit, ' +
                'and this service must not die because its database ' +
                'restarted.');
    };
    client.on('error', onError);
    return function () {
      client.removeListener('error', onError);
    };
  }

  function withTransaction(fn) {
    log.debug('Entering withTransaction().');
    return pool.connect().then(function (client) {
      const unguard = guardClient(client, 'a transaction');
      return client.query('BEGIN').then(function () {
        return fn(client);
      }).then(function (result) {
        return client.query('COMMIT').then(function () {
          unguard();
          client.release();
          log.debug('Leaving withTransaction(). Committed.');
          return result;
        });
      }).catch(function (err) {
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
                    row: probe.shape === 'row' ? (result.rows[0] || null) : null,
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
                       'than returned to the pool with a statement timeout on ' +
                       'it.');
              out.resetFailed = true;
            });
          })
          .then(function () {
            unguard();
            client.release(out.resetFailed ? new Error('not reset') : undefined);
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
      return pool.end().then(function () {
        log.debug('Leaving the postgres driver close().');
      });
    },

    loadDirectory: function () {
      log.debug('Entering the postgres driver loadDirectory().');
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
        log.debug('Leaving loadDirectory(). ' + result.rows.length + ' row(s).');
        return out;
      });
    },

    loadRealms: function () {
      log.debug('Entering the postgres driver loadRealms().');
      return pool.query(
        'SELECT id, name, description, created_at, overrides FROM sts_realms ' +
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
    saveDirectory: function (change) {
      log.debug('Entering the postgres driver saveDirectory().');
      return withTransaction(function (client) {
        let chain = Promise.resolve();
        const moved = [];

        change.upserts.forEach(function (row) {
          chain = chain.then(function () {
            // **`row.key` AND NOT `row.entry.dn` (2026-09-07).** A change row is
            // a POINTER, and the receiver dereferences it with
            // `readEntry(realm, key)` — which is `WHERE dn_key = $2`, the
            // NORMALISED dn. `row.entry.dn` is the DN as written, so every
            // upsert pointed at a key that column never holds: the receiver
            // looked it up, MISSED, concluded the entry had been deleted, and
            // called `removeEntry()` — actively removing the entry it had just
            // been told to add.
            //
            // The delete branch below always used `row.key` and was right,
            // which is why only upserts were affected and why nothing failed
            // until several processes started reading each other's writes. A
            // registered OAuth client vanished on every other worker, which
            // then treated the next request as "first sight" and wrote a stub
            // over the complete row.
            moved.push({ realm: row.realm, dn: row.key, op: 'put' });
            return client.query(
              'INSERT INTO sts_ldap_entries ' +
              '  (realm, dn_key, dn, attrs, origin, created_at, modified_at) ' +
              'VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7) ' +
              'ON CONFLICT (realm, dn_key) DO UPDATE SET ' +
              '  dn = EXCLUDED.dn, attrs = EXCLUDED.attrs, ' +
              '  origin = EXCLUDED.origin, created_at = EXCLUDED.created_at, ' +
              '  modified_at = EXCLUDED.modified_at',
              [row.realm, row.key, row.entry.dn,
               JSON.stringify(row.entry.attributes || {}),
               row.entry.origin || null,
               row.entry.createdAt || null,
               row.entry.modifiedAt || null]);
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
                  change.deletes.length + ' delete(s).');
      });
    },

    // The realm registry, replaced wholesale inside one transaction. Wholesale
    // rather than diffed because there are never more than a handful of realms
    // and a diff would be more code than the thing it optimises — and because
    // a DELETE of what is not in the list is the only way a removed realm's
    // row goes away when persistence.realms is on and the directory is not.
    saveRealms: function (rows) {
      log.debug('Entering the postgres driver saveRealms().');
      return withTransaction(function (client) {
        const ids = rows.map(function (row) { return row.id; });
        // `= ANY($1)` with an empty array is valid and matches nothing, which
        // is exactly right when the last realm has just been removed.
        return client.query(
          'DELETE FROM sts_realms WHERE NOT (id = ANY($1::text[]))', [ids]
        ).then(function () {
          let chain = Promise.resolve();
          rows.forEach(function (row) {
            chain = chain.then(function () {
              return client.query(
                'INSERT INTO sts_realms (id, name, description, created_at, overrides) ' +
                'VALUES ($1, $2, $3, $4, $5::jsonb) ' +
                'ON CONFLICT (id) DO UPDATE SET ' +
                '  name = EXCLUDED.name, description = EXCLUDED.description, ' +
                '  created_at = EXCLUDED.created_at, ' +
                '  overrides = EXCLUDED.overrides',
                [row.id, row.name, row.description, row.createdAt,
                 JSON.stringify(row.overrides || {})]);
            });
          });
          return chain;
        }).then(function () {
          // ONE LOG ROW FOR THE WHOLE REGISTRY, because that is how it is
          // written: this function replaces every realm wholesale rather than
          // diffing, so "the realms changed" is the finest thing there is to
          // say about it and a row per realm would be a lie about precision.
          return recordChanges(client, [{ kind: 'realms' }]);
        });
      }).then(function () {
        log.debug('Leaving the postgres driver saveRealms(). ' + rows.length +
                  ' realm(s).');
      });
    },

    saveOverrides: function (map) {
      log.debug('Entering the postgres driver saveOverrides().');
      return withTransaction(function (client) {
        const keys = Object.keys(map);
        return client.query(
          'DELETE FROM sts_appconfig WHERE NOT (key = ANY($1::text[]))', [keys]
        ).then(function () {
          let chain = Promise.resolve();
          keys.forEach(function (key) {
            chain = chain.then(function () {
              return client.query(
                'INSERT INTO sts_appconfig (key, value) VALUES ($1, $2::jsonb) ' +
                'ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value',
                [key, JSON.stringify({ raw: map[key] })]);
            });
          });
          return chain;
        }).then(function () {
          // ONE ROW, for saveRealms()'s reason: the override set is replaced
          // wholesale rather than diffed.
          return recordChanges(client, [{ kind: 'appconfig' }]);
        });
      }).then(function () {
        log.debug('Leaving the postgres driver saveOverrides(). ' +
                  Object.keys(map).length + ' override(s).');
      });
    },

    // -----------------------------------------------------------------------
    // THE KEY MATERIAL. See the CREATE TABLE above for why a column of text is
    // the right shape and why this driver never holds a private key.
    // -----------------------------------------------------------------------
    loadKeys: function () {
      log.debug('Entering the postgres driver loadKeys().');
      return pool.query('SELECT realm, material FROM sts_keys').then(function (r) {
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

    deleteKeys: function (realmId) {
      log.debug('Entering the postgres driver deleteKeys(). realm=' + realmId);
      return pool.query('DELETE FROM sts_keys WHERE realm = $1', [realmId])
        .then(function () {
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
      return pool.query(
        'SELECT handle, realm, key, body, ' +
        '       (extract(epoch from written_at) * 1000)::bigint AS written_ms ' +
        'FROM sts_minted'
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
                upserts.length + ' upsert(s), ' + deletes.length + ' delete(s).');
      return withTransaction(function (client) {
        let chain = Promise.resolve();
        upserts.forEach(function (row) {
          chain = chain.then(function () {
            return client.query(
              'INSERT INTO sts_minted (handle, realm, key, body, written_at) ' +
              'VALUES ($1, $2, $3, $4, now()) ' +
              'ON CONFLICT (handle, realm, key) DO UPDATE SET ' +
              '  body = EXCLUDED.body, written_at = now()',
              [row.handle, row.realm, row.key, row.body]
            );
          });
        });
        deletes.forEach(function (row) {
          chain = chain.then(function () {
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
          return recordChanges(client, upserts.concat(deletes).map(function (row) {
            // `minted-own` IS A SECOND KIND AND NOT A FLAG, because the only
            // thing that reads it is a `WHERE kind <> …` on the barrier's
            // target — see latestBlockingChangeSeq(). A column would have had
            // to be added to `sts_changes` and indexed; a kind is already
            // there and already selected on.
            return { kind: row.own ? 'minted-own' : 'minted', realm: row.realm,
                     key: Buffer.from(String(row.handle), 'utf8').toString('base64url') +
                          '.' +
                          Buffer.from(String(row.key), 'utf8').toString('base64url') };
          }));
        });
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
    changeRowsWritten: function () { return written; },

    latestBlockingChangeSeq: function () {
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
    // such application. **The volume was not the defect; the round trips were.**
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
        return Promise.resolve([]);
      }
      const values = [];
      const binds = [];
      list.forEach(function (ref, i) {
        values.push('($' + (i * 3 + 1) + '::text, $' + (i * 3 + 2) +
                    '::text, $' + (i * 3 + 3) + '::text)');
        binds.push(String(ref.handle), String(ref.realm), String(ref.key));
      });
      return pool.query(
        'SELECT m.handle, m.realm, m.key, m.body, ' +
        '(extract(epoch from m.written_at) * 1000)::bigint AS written_ms ' +
        'FROM sts_minted m JOIN (VALUES ' + values.join(', ') +
        ') AS w(handle, realm, key) ' +
        'ON m.handle = w.handle AND m.realm = w.realm AND m.key = w.key',
        binds
      ).then(function (res) {
        const rows = (res.rows || []).map(function (row) {
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
    origin: function () { return processId; },

    // The high-water mark at startup. A process that has just RESTORED the
    // whole store is, by definition, up to date with everything committed
    // before this instant — so it starts from here rather than from 0 and
    // does not re-apply the entire history of the deployment on the way up.
    latestChangeSeq: function () {
      log.debug('Entering the postgres driver latestChangeSeq().');
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
      log.debug('Entering the postgres driver changesSince(). after=' + afterSeq);
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
      return pool.query('SELECT COALESCE(MAX(seq), 0) AS seq FROM sts_changes')
        .then(function (r) { return Number((r.rows[0] || {}).seq || 0); });
    },

    // One directory entry, for the applier. It re-reads rather than being sent
    // the row, which is what lets the notification carry nothing.
    readEntry: function (realmId, dnKey) {
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
      return pool.query(
        'SELECT handle, realm, key, body, ' +
        '       (extract(epoch from written_at) * 1000)::bigint AS written_ms ' +
        'FROM sts_minted WHERE handle = $1 AND realm = $2 AND key = $3',
        [handle, realmId, key]
      ).then(function (r) {
        const row = (r.rows || [])[0];
        if (!row) {
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
        if (closed) {
          return;
        }
        client = new Client(clientOptions());
        client.on('notification', function (msg) {
          let payload = null;
          try {
            payload = JSON.parse(msg.payload || '{}');
          } catch (e) {
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
      return pool.query('DELETE FROM sts_changes WHERE seq < $1',
                        [Number(beforeSeq) || 0])
        .then(function (r) { return r.rowCount || 0; });
    },

    // Rows older than the retention window. Returns HOW MANY, because the one
    // caller logs it and a purge that reported nothing would leave an operator
    // unable to tell "it worked" from "there was nothing to do".
    purgeMinted: function (beforeMs) {
      log.debug('Entering the postgres driver purgeMinted(). before=' + beforeMs);
      return pool.query(
        'DELETE FROM sts_minted WHERE written_at < to_timestamp($1 / 1000.0)',
        [Number(beforeMs)]
      ).then(function (r) {
        log.debug('Leaving the postgres driver purgeMinted(). ' +
                  (r.rowCount || 0) + ' row(s).');
        return r.rowCount || 0;
      });
    }
  };
}

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
  SCHEMA_VERSION: SCHEMA_VERSION
};
