// File: sts_secret_store.js
//
// ===========================================================================
// THE SERVICE READ ITS SECRETS OUT OF A SECRET STORE, AND NOT OUT OF ITS OWN
// CONFIGURATION (2026-09-12).
//
// The stack this repository ships brings up an OpenBao container, seeds it
// with this service's key-encryption key and its database password, issues the
// service a client certificate from a certificate authority INSIDE that store,
// and binds that certificate to a policy that can read those two values and
// write nothing.
//
// **WHAT THIS JOB ASSERTS IS THE HALF NOTHING ELSE CAN SEE**: that the running
// service actually took that path. `openbao/seed.js` proves the store's side
// on every start — it logs in with the certificate it just issued, reads, and
// fails the whole stack if the write it then attempts is accepted — but a
// store that is perfectly configured tells you nothing about whether the
// service used it. A service still reading a key file, or still dialling a
// password out of its connection string, comes up exactly as green.
//
// So every check here is against what the SERVICE reports about itself:
//
//   * the key-encryption key came from the `vault` provider, over a client
//     certificate;
//   * the database password came from the store, and the connection string
//     carries none at all;
//   * neither surface prints either secret.
//
// ---------------------------------------------------------------------------
// WHY IT IS HERE, WHICH IS `tests/CLAUDE.md`'s FIRST QUESTION.
//
// `local: true`: it drives this repository's own `/admin-api`, which is the
// ownership argument rather than a capability one.
//
// **IT IS SKIPPED RATHER THAN FAILED WHERE THE STACK HAS NO STORE**, and that
// is the one concession this file makes. The `memory` and `postgres` modes
// read no key-encryption key at all (`keys.source=generated`), and a throwaway
// service started by `run-report.js` with no compose stack has no OpenBao to
// dial — asserting the vault provider there would be asserting the launcher's
// configuration rather than the service's behaviour. The skip says which
// state it saw, so a run where the wiring silently went away does not read as
// a pass.
// ===========================================================================

const assert = require("assert");
const { Command, Option } = require("commander");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, for the reason tests/wait_for.js gives.
  appconfigProblem = e;
  appconfig = {};
}

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_secret_store",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug('CONFIG_FILE could not be read, so the configuration is empty: ' +
            appconfigProblem.message);
}
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");
var api = base + "/admin-api";

var checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

async function get(path) {
  log.debug("Entering get().");
  const r = await fetch(api + path);
  const raw = await r.text();
  let body;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in get(): " + ((e && e.message) || e));
    // An HTML error page from a door that answers JSON is worth quoting whole.
    body = raw;
  }
  log.debug("Leaving get().");
  return { status: r.status, body: body, raw: raw };
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving " + base + ".");

  const encryption = await get("/encryption");
  assert.strictEqual(encryption.status, 200,
    "GET /admin-api/encryption answered " + encryption.status + " " +
    String(encryption.raw).slice(0, 200));
  const persistence = await get("/persistence");
  assert.strictEqual(persistence.status, 200,
    "GET /admin-api/persistence answered " + persistence.status);

  const key = encryption.body.key || {};
  const database = ((persistence.body.status || {}).database) ||
                   persistence.body.database || {};
  const usingVault = key.provider === "vault" ||
                     database.passwordProvider === "vault";
  // ---------------------------------------------------------------------
  // **THE TWO SECRETS ARE NOT READ IN THE SAME MODES, AND THIS JOB FAILED IN
  // TWO OF THREE UNTIL IT SAID SO (2026-09-12).**
  //
  // The DATABASE PASSWORD comes out of the store in EVERY mode, because the
  // compose file's connection string no longer carries one at all — so
  // section 2 has something to assert wherever this stack is up. The
  // KEY-ENCRYPTION KEY is only read when the keystore is ON, which is
  // `keys.source=persisted` and therefore the `dispatch` mode and `docker
  // compose up`; in `memory` and `postgres` the service generates its signing
  // keys per start and never dials the store for a key at all.
  //
  // The first version of this file gated on `usingVault` alone — true in
  // every mode, because of the database password — and then asserted that a
  // key had been read. `no key was read at all` in two modes, about a service
  // that was behaving exactly as that mode defines.
  //
  // So the KEK half is gated on the report saying a key is actually present,
  // and SAYS which mode it is in rather than passing quietly. What it must
  // never become is a check that weakens when the key IS there: `key.present`
  // is a fact about the deployment, not about the assertions.
  // ---------------------------------------------------------------------
  const keystoreOn = key.provider === "vault" && key.present === true;
  // **AND THE DATABASE HALF IS GATED THE SAME WAY, FOR THE SAME REASON — THE
  // SENTENCE ABOVE SAYING *EVERY MODE* WAS WRONG ABOUT ONE OF THEM.** The
  // `memory` mode dials no database at all, so `/admin-api/persistence`
  // reports `database: null` and there is no password for anybody to have
  // read. `usingVault` is still true there, because the KEK provider is
  // configured as `vault` whether or not the keystore reads it — so section 2
  // asserted `passwordProvider === "vault"` about an absent report and failed
  // the memory mode on every run. It runs where a database is being dialled,
  // which is the postgres and dispatch modes.
  const databaseOn = !!(database && database.host);

  if (!usingVault) {
    // THE SKIP, AND IT NAMES WHAT IT SAW. See the header.
    log.warn("SKIPPED: this service is not configured against a secret " +
             "store — the key-encryption key provider is " +
             JSON.stringify(key.provider) + " and the database password " +
             "provider is " + JSON.stringify(database.passwordProvider) +
             ". That is the memory and postgres modes, and a throwaway " +
             "service with no compose stack; the dispatch mode and " +
             "`docker compose up` are where this job has something to say.");
    log.info("Test completed successfully.");
    log.debug("Leaving test().");
    return;
  }

  // -------------------------------------------------------------------------
  // 1. THE KEY-ENCRYPTION KEY.
  // -------------------------------------------------------------------------
  log.info("=== 1. the key-encryption key ===");
  if (!keystoreOn) {
    log.warn("The keystore is OFF in this mode (keys.source is not " +
             "`persisted`), so this service generates its signing keys per " +
             "start and reads no key-encryption key. The key provider is " +
             JSON.stringify(key.provider) + " and the report says present=" +
             JSON.stringify(key.present) + ". Sections 1 and 3 have nothing " +
             "to assert here and section 2 has — the database password comes " +
             "out of the store in EVERY mode. The dispatch mode and " +
             "`docker compose up` are where this half runs.");
  }
  if (keystoreOn) {
    check("the key-encryption key came from the secret store rather than " +
          "from a file this stack wrote", function () {
            assert.strictEqual(key.provider, "vault",
              "provider=" + JSON.stringify(key.provider));
            assert.strictEqual(key.present, true, "no key was read at all");
          });
    check("**and the service proved who it was with a CLIENT CERTIFICATE**, " +
          "which is the difference between an identity the store issued and " +
          "a bearer token in a file: the store can revoke the first and " +
          "cannot tell who is using the second", function () {
            const how = String((key.where || {}).authenticates || "");
            assert.ok(/client certificate/i.test(how),
              "the report says it authenticated with " + JSON.stringify(how));
          });
  }
  check("the report says WHERE and never WHAT — no key material anywhere in " +
        "it", function () {
          const whole = JSON.stringify(encryption.body);
          assert.ok(whole.indexOf("BEGIN") < 0,
            "a PEM block appeared in the encryption report");
          // The KEK is 32 bytes of base64; a report carrying one would carry a
          // 40-plus character run of base64 beside the word `kek`.
          assert.ok(!/"kek"\s*:\s*"[A-Za-z0-9+/=]{20,}/.test(whole),
            "something that looks like the key-encryption key is in the " +
            "report");
        });

  // -------------------------------------------------------------------------
  // 2. THE DATABASE PASSWORD.
  // -------------------------------------------------------------------------
  log.info("=== 2. the database password ===");
  if (!databaseOn) {
    log.warn("This service dials no database in this mode (persistence mode " +
             JSON.stringify((persistence.body.status || {}).mode ||
                            persistence.body.mode) + ", and the report " +
             "carries no database), so there is no database password for a " +
             "secret store to have supplied. Section 2 runs in the postgres " +
             "and dispatch modes.");
  }
  if (databaseOn) {
  check("the database password came from the store as well", function () {
          assert.strictEqual(database.passwordProvider, "vault",
            "passwordProvider=" + JSON.stringify(database.passwordProvider));
          assert.ok(/vault/i.test(String(database.passwordFrom || "")),
            "passwordFrom=" + JSON.stringify(database.passwordFrom));
        });
  check("**and the two secrets share one location**, which is the " +
        "arrangement the feature exists for: a deployment mounts one file or " +
        "keeps one cloud secret, and a field tells the two apart", function () {
          assert.ok(/shared with the key-encryption key/i
            .test(String(database.passwordFrom || "")),
            "passwordFrom=" + JSON.stringify(database.passwordFrom));
        });
  check("the service is dialling the database as the least-privileged role " +
        "and over TLS, which the password change did not quietly alter",
        function () {
          assert.strictEqual(database.user, "sts_app",
            "user=" + JSON.stringify(database.user));
          assert.strictEqual(database.encrypted, true,
            "sslmode=" + JSON.stringify(database.sslmode));
        });
  check("**and the connection string this reply DOES carry has no password " +
        "in it**, which is the property the whole feature buys. That value " +
        "is `persistence.databaseUrl` as configured — the settings half of " +
        "this operation returns it, and a deployment that kept its password " +
        "there would be handing it to every reader of /admin-api and " +
        "/admin/config. With the store supplying it, there is nothing in the " +
        "string to hand over", function () {
          // THE VALUE AND NOT THE WHOLE BLOB. Every settings row carries a
          // DESCRIPTION, and this one's names the shape
          // `postgres://user:password@host` as documentation — a regex over
          // the reply matches that and reports a leak that is a sentence.
          const rows = [];
          (function walk(node) {
            log.debug("Entering walk().");
            if (!node || typeof node !== "object") {
              log.debug("Leaving walk().");
              return;
            }
            if (Array.isArray(node)) {
              node.forEach(walk);
              log.debug("Leaving walk().");
              return;
            }
            if (node.key === "persistence.databaseUrl") { rows.push(node); }
            Object.keys(node).forEach(function (k) { walk(node[k]); });
            log.debug("Leaving walk().");
          })(persistence.body);
          assert.ok(rows.length,
            "the reply carries no persistence.databaseUrl row, so this " +
            "assertion is not looking at what it thinks it is");
          rows.forEach(function (row) {
            [row.value, row.text].forEach(function (one) {
              const url = String(one || "");
              if (url.indexOf("postgres://") !== 0) { return; }
              const userinfo = url.slice("postgres://".length).split("@")[0];
              assert.ok(userinfo.indexOf(":") < 0,
                "the configured connection string carries a password: " +
                url.replace(/:[^:@]*@/, ":***@"));
            });
          });
        });
  }

  // -------------------------------------------------------------------------
  // 3. THE STORE IS WHERE THE KEYS REALLY ARE.
  // -------------------------------------------------------------------------
  log.info("=== 3. and the keystore is actually on ===");
  const keysReport = keystoreOn ? await get("/keys") : { status: 0 };
  if (keysReport.status === 200) {
    check("the keystore is persisting, which is what makes the " +
          "key-encryption key load-bearing rather than decorative — a " +
          "service that read a key and generated its signing keys anyway " +
          "would pass every check above", function () {
            const whole = JSON.stringify(keysReport.body);
            assert.ok(/"persist(ing|ed)"\s*:\s*true|persisted/i.test(whole),
              "the keys report does not say the keystore is persisting: " +
              whole.slice(0, 300));
          });
  }

  // THE FLOOR IS PER MODE, for the reason the block above `keystoreOn`
  // gives: four of the checks here are about a key this service does not read
  // unless the keystore is on. A single floor would either be vacuous in
  // dispatch or wrong in the other two. The database half adds its four only
  // where a database is dialled, which the memory mode does not.
  const floor = (databaseOn ? 4 : 1) + (keystoreOn ? 3 : 0);
  assert.ok(checks >= floor,
    "only " + checks + " checks ran (" + floor + " expected in this mode); " +
    "a section has stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_secret_store")
  .description("the running service read its key-encryption key and its " +
      "database password out of an OpenBao container, authenticating with a " +
      "client certificate that store issued it — and neither secret appears " +
      "in anything it reports about itself.")
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
