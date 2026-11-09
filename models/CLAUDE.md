# models/

The common model (#1390). **#1390 stays open until TypeSpec is what the service
is built from.** **The whole directory namespace is switched.** Every object is
written by hand in `directory/*.tsp`, the directory's three name lists
(`STANDARD_NAMES`, `OWN_NAMES`, `SECRET_ATTRIBUTES`) are `directory/names.tsp`, and
the owning module reads what the build generates, through
`common/model_tables.ts`. **Persistence is switched too**: every PostgreSQL and
MariaDB table and index is in `persistence/*.tsp`.

| Path | What it is | Who writes it |
|---|---|---|
| `main.tsp` | What the compiler is pointed at | by hand |
| `lib/model_lib.tsp`, `lib/model_lib.mjs` | The decorators, their closed value types, and the reader of a compiled program | by hand |
| `tools/import_rfc_schema.mjs` | Reads the RFCs' LDAP definitions into `directory/rfc_schema.json` | by hand; run when an RFC is added |
| `directory/rfc_schema.json` | Every OID, syntax, matching rule, superior and MUST/MAY the RFCs publish | the tool |
| `directory/application.tsp`, `role.tsp`, `device.tsp`, `service_account.tsp`, `spiffe.tsp`, `xacml_policy.tsp`, `xacml_pep.tsp`, `federation_relationship.tsp`, `policy_*.tsp` | **The source of each object's `SCHEMA`**, and of a policy's settings. A row added here is a row the service has | by hand |
| `directory/application.overlay.ts` | The application's key, derived subject and withheld list, and the same links as `application.tsp`, held equal by the test | by hand |
| `directory/person.tsp`, `group.tsp`, `operational.tsp`, `attribute_source.tsp`, `oidfed.tsp`, `claim_provider.tsp`, `kerberos_trust.tsp`, `trust_anchor.tsp`, `signer_trust_anchor.tsp` | The objects no module owned. `common/directory_model_catalog.ts` reads their generated tables for the collector | by hand |
| `directory/names.tsp` | The directory's name lists, generated into `directory.names.json`, which `ldap/ldap_server.js` reads. A row with no sentence takes the comment above its name here | by hand |
| `persistence/persistence.tsp`, `persistence_mariadb.tsp` | **The source of every table and index**, one file per engine because their types, keys and indexes differ. Each generates what the driver runs and the owner's script | by hand |
| `api/management.tsp`, `console.tsp`, `account.tsp`, `authn.tsp`, `report.tsp`, `lib/api_lib.*` | **The Management API, Admin Console API, Account API, Authentication API and Reports API OpenAPI documents, all switched.** Each is the source: the build generates the document, the service serves it, validates each request body against it (Management and Admin Console), and holds every answer to it. **A change to an API is made here.** A routing row in code keeps the path, the handler, what it mirrors and its parameters | by hand |
| `persistence/schema.template.sql`, `mariadb.template.sql` | Everything else in `postgres/schema.sql` and `mariadb/schema.sql`: comments, `psql` commands, grants, routines, the upgrade block. `--@table name` and `--@index name` lines are where the model's go | by hand |
| `tools/generate.mjs` | Compiles the model and writes `generated/<id>.schema.json` for each object written by hand. Run by `build-typescript.sh`, so only inside an image build | by hand |

**How a switch was made, for the next object.** A one-time conversion wrote the
table as TypeSpec with its comments, `generate.mjs` produced the file, and the
file was compared with the JSON of the original literal: byte-identical, 171,311
bytes for `Application`. Only then was the literal removed. The object goes in
`ModelEmit`'s `AUTHORED` and `models/main.tsp`, and its id in
`compiled_tree.js`'s `GENERATED`, which refuses a tree without the file
(`STS-CORE-0093`). The module then asks `ModelTables.schema(id)`. `@entry`'s `authored: true` says `kind` is the author's.

**Three places where the code still holds part of a table, each on purpose.**

* **A policy's `FIELDS` is the model's `field` values** (`ModelTables.fields()`),
  which is where type, default, min, max, label and allowed values live now. A
  value the code computes, such as a limit `common/crypto.js` owns, is not in the
  TypeSpec: the module passes it in by row key.
* **`authn_policy.ts`'s `MECHANISMS` and `service_account_policy.ts`'s `DOORS`**
  are registers the code branches on, and the rows built from them stay built
  there (`computed` in `ModelTables.fields()`). The published table repeats each
  one's sentence, and `tests/model_typespec.js` holds the two equal.
* **`federation/federation.js`'s lists** (`SUBJECT_POLICY_IDS`, the key and content
  algorithms, `MECHANISM_IDS`) are in the model as each row's `allowed`, and the
  code validates against constants with finer structure than one row can state. The
  same test holds them equal. It is a second writing until a validator is generated
  from the model.

**`postgres/schema.sql` and `mariadb/schema.sql` are generated files that are
committed**, because `docker-compose.yml` mounts one from the host. A change to a
table or a template owes `tests/tools/regenerate-model-docs.sh`, and
`tests/model_typespec.js` fails until the committed script matches. Migrations stay
in the driver (`SCHEMA_COLUMNS`, `SCHEMA_UPGRADES`, the routines): they are history,
not shape, and the test holds each upgrade to the column the model says the table has.

**Things that can catch you.** `common/applications.js` adds `editable` to each
row after loading, from its `EDITABLE` table; that is not in the TypeSpec, and
the test compares the generated file rather than the loaded table.
`--strip` removes `models/lib`, `models/tools` and every `.tsp` from the shipped
image, which keeps `models/generated/`.

**The direction for the rest, and the test that says so.** The importers read the
code, `common/model_emit.ts` writes the TypeSpec, and `tests/model_typespec.js`
compiles it with `@typespec/compiler` and rebuilds the sources from the compiled
program: every `SCHEMA` table, equal to the one in code, and every statement of
`postgres/schema.sql`, in order. It also edits a copy of the TypeSpec and
requires the edit to reach the SCHEMA, the class and the DDL. That is the
equivalence the ticket requires before anything is switched.

**The compiler is a dependency of `tests/` only.** It is pinned in
`tests/package.json`, so it is in the tests image and in the `typescript` build
stage, and never in the shipped image.

**A value a decorator takes is closed.** `model_lib.tsp` declares every key; an
undeclared one is a compile error. A new fact about an attribute is added there.

**What each importer does, and what it does not.**

* `common/directory_model.ts` reads each object's generated table. Spellings
  and the secret list are read as text from `directory/names.tsp`, for the
  comments above each name.
  `kind` is what the module declared, or what the attribute's RFC says when the
  module says nothing; `declaredKind` keeps the difference. `withheld` is true
  for `sensitive`, for `secret`, and for anything in `SECRET_ATTRIBUTES`.
* An OID, syntax or matching rule for a published name comes only from
  `rfc_schema.json`. **This service's own names are numbered in
  `directory/oid_register.json`**: `<root>.1.1.n` for an attribute, `<root>.1.2.n`
  for a class. A number is assigned once and never reused, and a new name takes the
  next one (`tests/model_directory.js` fails on a name with neither).
  **`root` is `1.3.6.1.4.1.32473` for now, the number RFC 5612 reserves for
  documentation.** It is a placeholder (rcbj, 2026-11-09) until the Private Enterprise
  Number applied for on #1471 arrives; changing `root` and `placeholder` is the whole
  swap. Nothing may publish these before then. A name somebody else publishes is in
  the register's `publishedElsewhere` and stays without one. RFC 4512 requires a
  syntax, and nothing states one for our names, so they take Directory String, and a
  class is auxiliary beside a published structural class and structural otherwise.
* `common/postgres_import.ts` keeps each column's type and its clauses, and each
  statement's place in the script. Indexes hang off their table; everything else
  the script runs is on `PostgresSchema`, as text.
* `common/mariadb_import.ts` and `common/openapi_import.ts` still only capture
  their sources. `emit()` there returns the bytes it was given, so a test that
  compares it to those bytes proves nothing.

**What every operation of a document takes is stated once, as `x-iya-every-operation` in its `@apiDocument`** (#1476, #1483), and `lib/api_lib.mjs` adds it to each operation after the operation's own parameters: `DPoP` and `cell` on the Management API and Admin Console API OpenAPI documents, `DPoP` and `X-Requested-With` on the Account API and Reports API OpenAPI documents, `X-Requested-With` on the Authentication API OpenAPI document. **Examples live on the operation in the model** (#1475, #1483): a routing row has no use for one, and an operation that deliberately has none says why in a comment above its `@endpoint`, because an example is executed.

**What is not done**, in the order it is owed: the real OID root (#1471); rows built by helper functions in `mgmt-api/admin_api.ts` still carrying a summary
the model now overrides; a class
for each request and response body; domain models distinct from directory entries;
the CI gates (Spectral, oasdiff).

`tests/tools/regenerate-model-docs.sh` rewrites the TypeSpec and the reading
pages, and a change to the model owes it. `tests/model_directory.js` and
`tests/model_postgres.js` fail when they differ. `node common/model_emit.js
--write` also writes `model.json` and `gaps.json`, which are not kept in the
tree.

The class text is not committed, because a `.ts` file in this tree is compiled
into the image and these classes serve nothing yet.
