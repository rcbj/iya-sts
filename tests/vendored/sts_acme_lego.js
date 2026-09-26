"use strict";
//
// File: sts_acme_lego.js
//
// ===========================================================================
// LEGO AGAINST THE ACME SERVER (#208, 2026-09-26).
//
// go-acme's lego (MIT) is the second major independent ACME client — the
// library under Traefik and much of Caddy's ecosystem — with a reading of
// RFC 8555 of its own: POST-as-GET throughout, Retry-After, alternate chains
// through `Link`, RFC 9773 renewal information and `replaces`, and the key
// change certbot does not have. At the version tests/Dockerfile pins
// (v5.5.2, built with `go install` against the checksum database), in a
// throwaway realm it builds and leaves standing:
//
//   * REGISTRATION with External Account Binding, and refused without one.
//   * `run` for two registered hosts under `--profile tls-server`: lego logs
//     that the authorization is already valid and skips the challenge (it
//     still wants a solver named, `--http`, which binds nothing here). The
//     certificate chains to the realm's Intermediate and the service Root.
//   * `run` with NO profile for a host name: `tls-server` (serverAuth) — an
//     order of host names only is a server certificate request (#252) — and
//     `--profile tls-client` for the same host, which a named profile wins.
//   * `--not-after`, which this server refuses (a certificate's lifetime is
//     the realm's), and a profile it does not offer, and a host nobody
//     registered: each refused, nothing written.
//   * RENEWAL INFORMATION: a second `run` consults `renewalInfo` and renews
//     nothing; `--renew-force` reissues with the same names (it failed
//     rejectedIdentifier until #207's fix, lego reading CN + dNSNames back).
//   * KEY ROLLOVER (RFC 8555 section 7.3.5): `accounts keyrollover`, after
//     which the server holds the new thumbprint and the account still orders.
//   * REVOCATION: `certificates revoke --reason 4`, and the serial on the
//     ACME Issuing CA's CRL.
//   * lego's log, at `debug` in text form, for each successful command: no
//     `WARN` and no `ERROR` record.
//
// NOT EXERCISED, and recorded on #208: http-01, dns-01, dns-persist-01 and
// tls-alpn-01 — the service offers only `sts-entry-binding-01`
// (`acme/CLAUDE.md`), so an authorization is valid when the order is made.
// ===========================================================================

const assert = require("assert");
const fs = require("fs");
const path = require("path");
const { Command, Option } = require("commander");
const { usernameFor } = require("./random_username.js");
const K = require("./enroll_clients_kit.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, for the reason tests/vendored/wait_for.js gives.
  appconfigProblem = e;
  appconfig = {};
}

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_acme_lego",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

const STAMP = usernameFor("lg").replace(/[^a-z0-9-]/g, "").slice(0, 24);
const REALM = ("lego-" + STAMP).slice(0, 30);
const BOB = "bob-" + STAMP;
const MAIL = BOB + "@example.test";
const WWW = "www." + BOB + ".test";
const APIHOST = "api." + BOB + ".test";
const EKU = { serverAuth: "1.3.6.1.5.5.7.3.1",
              clientAuth: "1.3.6.1.5.5.7.3.2" };
const C = K.checker(log);

var work = "";
var directory = "";
var bundle = null;

async function lego(args, options) {
  log.debug("Entering lego().");
  const opts = options || {};
  const r = await K.run("lego", ["--log.level", "debug", "--log.format", "text"]
    .concat(args, ["--server", directory, "--path", opts.path || work,
                   "--account-id", BOB]), {
    env: { LEGO_CA_CERTIFICATES: bundle.file },
    input: opts.input, secrets: opts.secrets, timeoutMs: 180000 });
  log.debug("Leaving lego(). status=" + r.status);
  return r;
}

// lego's text log is `time=… level=WARN msg=…`.
function succeeded(r, what, allowed) {
  log.debug("Entering succeeded().");
  assert.strictEqual(r.status, 0, what + " exited " + r.status + ":\n" +
                     r.shown);
  const bad = K.problemLines(r.output, /level=(WARN|ERROR)\b/, allowed);
  assert.deepStrictEqual(bad, [], what + " logged a warning or an error:\n" +
                         bad.join("\n"));
  log.debug("Leaving succeeded().");
}

function findFile(dir, test) {
  log.debug("Entering findFile().");
  const out = [];
  const walk = function (d) {
    fs.readdirSync(d, { withFileTypes: true }).forEach(function (e) {
      const full = path.join(d, e.name);
      if (e.isDirectory()) {
        walk(full);
      } else if (test(full)) {
        out.push(full);
      }
    });
  };
  if (fs.existsSync(dir)) {
    walk(dir);
  }
  log.debug("Leaving findFile(). found=" + out.length);
  return out;
}

// The certificate lego stored under a name: `<name>.crt` holds the leaf and
// the chain the server sent (lego bundles by default).
function stored(name) {
  log.debug("Entering stored(). name=" + name);
  const files = findFile(path.join(work, "certificates"), function (f) {
    return path.basename(f) === name + ".crt";
  });
  assert.strictEqual(files.length, 1, "lego stored " + files.length +
                     " files named " + name + ".crt under " + work);
  const chain = K.pemChain(fs.readFileSync(files[0], "utf8"));
  log.debug("Leaving stored().");
  return { file: files[0], chain: chain, leaf: chain[0] };
}

function assertIssued(one, hosts, ekus, what) {
  log.debug("Entering assertIssued().");
  assert.strictEqual(one.chain.length, 3, what + ": the certificate, the " +
                     "ACME Issuing CA and the realm Intermediate");
  K.chainsTo(one.chain, bundle.root);
  hosts.forEach(function (h) {
    assert.ok(String(one.leaf.subjectAltName).indexOf("DNS:" + h) >= 0,
              what + ": the SAN names " + h + ": " +
              one.leaf.subjectAltName);
  });
  assert.ok(new RegExp("CN=" + hosts[0].replace(/\./g, "\\.") + "(\\n|$)")
              .test(one.leaf.subject),
            what + ": the CN is the first host: " + one.leaf.subject);
  assert.ok(one.leaf.subject.indexOf("UID=" + BOB) >= 0,
            what + ": the UID is the entry: " + one.leaf.subject);
  assert.deepStrictEqual((one.leaf.keyUsage || []).slice().sort(),
                         ekus.slice().sort(), what + ": EKU");
  log.debug("Leaving assertIssued().");
}

async function accountRow() {
  log.debug("Entering accountRow().");
  const view = await K.send(K.realmApi(REALM) + "/acme?per=100");
  const rows = ((view.body.accounts || {}).rows || []).filter(function (one) {
    return one.entryUri === "urn:sts:person:" + BOB;
  });
  log.debug("Leaving accountRow().");
  return rows[0];
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving " + K.base + " with lego in the trust realm \"" +
           REALM + "\".");
  log.info("lego: " + (await K.run("lego", ["--version"])).output.trim());

  // -------------------------------------------------------------------------
  log.info("=== 0. a realm, its CA, a person with two host names ===");
  await K.makeRealm(REALM, "lego job");
  await K.makePerson(REALM, BOB, MAIL);
  await K.setting(REALM, "acme.attemptsPerAddress", 100000);
  for (const host of [WWW, APIHOST]) {
    await K.ok(K.realmApi(REALM) + "/acme/add-host-name",
               { kind: "person", identifier: BOB, hostName: host },
               "registered " + host);
  }
  const eab = await K.ok(K.realmApi(REALM) + "/acme/create-eab",
                         { kind: "person", identifier: BOB },
                         "created bob's EAB key");
  directory = eab.directory;
  work = K.scratch("lego");
  bundle = await K.trustBundle(K.scratch("lego-trust"));
  const solver = ["--http", "--http.address", "127.0.0.1:18889"];

  // -------------------------------------------------------------------------
  log.info("=== 1. registration ===");
  // In a directory of its own: lego keeps the account key a refused
  // registration generated, and on the next `register` in the same
  // directory it asks for the account BY that key (onlyReturnExisting)
  // instead of registering — answered accountDoesNotExist, correctly.
  const bare = await lego(["accounts", "register", "--accept-tos", "-m", MAIL],
                          { path: K.scratch("lego-refused") });
  C.check("a registration with no External Account Binding is refused",
          function () {
    assert.notStrictEqual(bare.status, 0, bare.shown);
    assert.ok(/externalAccountRequired|external account/i.test(bare.output),
              bare.shown);
  });
  const reg = await lego(["accounts", "register", "--accept-tos", "-m", MAIL,
                    "--eab", "--eab.kid", eab.kid,
                    // One argument: a base64url key may begin with `-`.
                    "--eab.hmac=" + eab.hmacKey],
                   { secrets: [eab.hmacKey] });
  const account = await accountRow();
  C.check("lego registers with the administrator's EAB key, and the account " +
          "is bound to the person", function () {
    // lego's own advice to back up the account key, at WARN on every
    // registration: about the client's directory, not the server.
    succeeded(reg, "lego accounts register", [/HEADS UP/]);
    assert.ok(account, "no account bound to " + BOB);
    assert.strictEqual(account.status, "valid");
    assert.strictEqual(account.eabKid, eab.kid);
  });
  const listed = await K.run("lego", ["accounts", "list", "--json",
                                "--path", work]);
  C.check("accounts list shows the account", function () {
    assert.strictEqual(listed.status, 0, listed.shown);
    assert.ok(listed.output.indexOf(account.id) >= 0 ||
              listed.output.indexOf(MAIL) >= 0, listed.shown);
  });

  // -------------------------------------------------------------------------
  log.info("=== 2. issuance ===");
  const first = await lego(["run", "-m", MAIL, "--profile", "tls-server",
                      "-c", "web", "-d", WWW, "-d", APIHOST,
                      "--no-random-sleep"].concat(solver));
  const web = stored("web");
  C.check("run --profile tls-server issues for both hosts with no " +
          "challenge performed, chained to the Root", function () {
    succeeded(first, "lego run");
    assert.ok(/already valid|skip/i.test(first.output), first.shown);
    assertIssued(web, [WWW, APIHOST], [EKU.serverAuth], "tls-server");
  });
  const plain = await lego(["run", "-m", MAIL, "-c", "plain", "-d", WWW,
                      "--no-random-sleep"].concat(solver));
  C.check("run with no profile, for a host name only, is issued " +
          "tls-server (serverAuth, #252)", function () {
    succeeded(plain, "lego run (no profile)");
    assertIssued(stored("plain"), [WWW], [EKU.serverAuth], "default");
  });
  const named = await lego(["run", "-m", MAIL, "--profile", "tls-client",
                      "-c", "named", "-d", WWW, "--no-random-sleep"]
                     .concat(solver));
  C.check("a named profile wins over the host-only default: --profile " +
          "tls-client is issued clientAuth", function () {
    succeeded(named, "lego run --profile tls-client");
    assertIssued(stored("named"), [WWW], [EKU.clientAuth], "named");
  });
  const notAfter = await lego(["run", "-m", MAIL, "-c", "notafter", "-d", WWW,
                         "--not-after",
                         new Date(Date.now() + 86400000).toISOString()
                           .replace(/\.\d+Z$/, "Z"),
                         "--no-random-sleep"].concat(solver));
  C.check("--not-after is refused: the realm sets a certificate's lifetime",
          function () {
    assert.notStrictEqual(notAfter.status, 0, notAfter.shown);
    assert.ok(/notAfter|malformed/i.test(notAfter.output), notAfter.shown);
  });
  const badProfile = await lego(["run", "-m", MAIL, "-c", "rootca", "-d", WWW,
                           "--profile", "root-ca", "--no-random-sleep"]
                          .concat(solver));
  C.check("a profile the server does not offer is refused", function () {
    assert.notStrictEqual(badProfile.status, 0, badProfile.shown);
    assert.ok(/invalidProfile|profile/i.test(badProfile.output),
              badProfile.shown);
  });
  const stranger = await lego(["run", "-m", MAIL, "-c", "stranger",
                         "-d", "nobody-" + STAMP + ".example.org",
                         "--no-random-sleep"].concat(solver));
  C.check("a host nobody registered is refused rejectedIdentifier",
          function () {
    assert.notStrictEqual(stranger.status, 0, stranger.shown);
    assert.ok(/rejectedIdentifier/i.test(stranger.output), stranger.shown);
  });

  // -------------------------------------------------------------------------
  log.info("=== 3. renewal information and renewal ===");
  const notDue = await lego(["run", "-m", MAIL, "-c", "web", "-d", WWW,
                       "-d", APIHOST, "--profile", "tls-server",
                       "--no-random-sleep"].concat(solver));
  C.check("a second run consults renewalInfo (RFC 9773) and renews nothing",
          function () {
    succeeded(notDue, "lego run (not due)");
    assert.strictEqual(K.serialOf(stored("web").leaf), K.serialOf(web.leaf));
    assert.ok(/renewal|renewalInfo|ARI/i.test(notDue.output), notDue.shown);
  });
  const forced = await lego(["run", "-m", MAIL, "-c", "web", "-d", WWW,
                       "-d", APIHOST, "--profile", "tls-server",
                       "--renew-force", "--no-random-sleep"].concat(solver));
  const renewed = stored("web");
  C.check("--renew-force reissues the same names (it failed " +
          "rejectedIdentifier before #207's fix)", function () {
    succeeded(forced, "lego run --renew-force");
    assert.notStrictEqual(K.serialOf(renewed.leaf), K.serialOf(web.leaf));
    assertIssued(renewed, [WWW, APIHOST], [EKU.serverAuth], "renewed");
  });

  // -------------------------------------------------------------------------
  log.info("=== 4. key rollover ===");
  const rolled = await lego(["accounts", "keyrollover", "-m", MAIL,
                       "--key-type", "RSA2048"], { input: "y\n" });
  const account2 = await accountRow();
  C.check("accounts keyrollover changes the key the server holds",
          function () {
    succeeded(rolled, "lego accounts keyrollover");
    assert.strictEqual(account2.id, account.id);
    assert.notStrictEqual(account2.thumbprint, account.thumbprint);
  });
  const afterRoll = await lego(["run", "-m", MAIL, "-c", "rolled", "-d", APIHOST,
                          "--key-type", "RSA2048", "--no-random-sleep"]
                         .concat(solver));
  C.check("the account orders under its new key", function () {
    succeeded(afterRoll, "lego run after keyrollover");
    assertIssued(stored("rolled"), [APIHOST], [EKU.serverAuth], "rolled");
  });

  // -------------------------------------------------------------------------
  log.info("=== 5. revocation ===");
  const revoked = await lego(["certificates", "revoke", "-m", MAIL, "-c", "web",
                        "--reason", "4", "--keep"]);
  const crl = await K.crlSerials(REALM, "acme");
  C.check("certificates revoke --reason 4 puts the serial on the ACME CRL",
          function () {
    succeeded(revoked, "lego certificates revoke");
    assert.ok(crl.indexOf(K.serialOf(renewed.leaf)) >= 0,
              "serial " + K.serialOf(renewed.leaf) + " not in " +
              crl.join(","));
  });

  assert.ok(C.count >= 12,
    "only " + C.count + " checks ran; a section has stopped being called.");
  log.info(C.count + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_acme_lego")
  .description("go-acme's lego, at a pinned version, against the ACME " +
      "server: EAB registration, issuance with a profile, the refusals, " +
      "renewal information, forced renewal, key rollover and revocation.")
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error((e.stack || e.message) +
            (e.cause ? "\ncaused by: " + (e.cause.stack || e.cause) : ""));
  process.exit(1);
});
