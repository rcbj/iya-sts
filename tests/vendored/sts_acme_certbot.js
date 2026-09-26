"use strict";
//
// File: sts_acme_certbot.js
//
// ===========================================================================
// CERTBOT AGAINST THE ACME SERVER (#207, 2026-09-26).
//
// No official ACME server conformance suite exists — Let's Encrypt's Pebble
// is a test SERVER, the other side — so the strongest check is the reference
// client: EFF's certbot (Apache-2.0), at the version tests/Dockerfile pins
// (5.8.0, every package hash-pinned). `sts_acme_enrollment.js` drives the
// same server with this suite's own `acme_client.js`; this job asks whether
// the client everybody runs gets what it expects. In a throwaway realm it
// builds and leaves standing:
//
//   * REGISTRATION: refused with no External Account Binding and with a
//     binding MACed by the wrong key; accepted with the key an administrator
//     made, and the account listed on /admin-api/acme bound to the entry.
//   * ISSUANCE: `certonly` for two registered host names with no profile
//     (the realm's `acme.defaultProfile`), then `--required-profile
//     tls-server` and `--preferred-profile tls-server-client` — the
//     authorizations are valid at newOrder (`sts-entry-binding-01`), so
//     certbot performs no challenge. Each certificate chains to the realm's
//     Intermediate and the service Root, names the first host as its CN and
//     the entry as its UID (#207's fix), and carries the profile's EKU.
//   * A PROFILE THE SERVER DOES NOT OFFER (`--required-profile root-ca`) and
//     A HOST NOBODY REGISTERED: both refused.
//   * RENEWAL: `renew --force-renewal` reissues with the same names (every
//     renewal failed rejectedIdentifier until #207's fix), and a plain
//     `renew` renews nothing that is not due.
//   * THE ACCOUNT: `show_account`, `update_account` with a new address, and
//     `unregister` (deactivation), after which the server lists it
//     deactivated.
//   * REVOCATION: `revoke --reason keycompromise`, and the serial on the
//     ACME Issuing CA's CRL.
//   * certbot's own log at DEBUG for each successful command: no WARNING
//     and no ERROR line.
//
// NOT EXERCISED, and recorded on #207: http-01 and dns-01 (the service
// offers only `sts-entry-binding-01`, `acme/CLAUDE.md`), and key rollover
// (certbot has no RFC 8555 section 7.3.5 key change at all — lego's job
// drives it).
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
var log = bunyan.createLogger({ name: "sts_acme_certbot",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

const STAMP = usernameFor("cb").replace(/[^a-z0-9-]/g, "").slice(0, 22);
const REALM = ("certbot-" + STAMP).slice(0, 30);
const ALICE = "alice-" + STAMP;
const WWW = "www." + ALICE + ".test";
const APIHOST = "api." + ALICE + ".test";
const EKU = { serverAuth: "1.3.6.1.5.5.7.3.1",
              clientAuth: "1.3.6.1.5.5.7.3.2" };
const C = K.checker(log);

var work = "";
var directory = "";
var bundle = null;
var runs = 0;

// One certbot command, with the three directories certbot writes to and a
// fresh log directory per command, so the log read after it is that
// command's alone.
function certbot(args, secrets) {
  log.debug("Entering certbot().");
  runs += 1;
  const logs = path.join(work, "logs-" + runs);
  const r = K.run("certbot", args.concat([
    "--server", directory, "--non-interactive",
    "--config-dir", path.join(work, "config"),
    "--work-dir", path.join(work, "work"),
    "--logs-dir", logs, "-v"]), {
    env: { REQUESTS_CA_BUNDLE: bundle.file },
    secrets: secrets, timeoutMs: 180000 });
  let logText = "";
  try {
    logText = fs.readFileSync(path.join(logs, "letsencrypt.log"), "utf8");
  } catch (e) {
    log.debug("Caught in certbot(): " + ((e && e.message) || e));
    // A command refused before certbot set up logging writes no file; its
    // output is what the caller reads.
    logText = "";
  }
  r.log = logText;
  log.debug("Leaving certbot(). status=" + r.status);
  return r;
}

// A successful command's log holds no WARNING and no ERROR record. certbot's
// log format is `time:LEVEL:logger:message`.
function quiet(r, what) {
  log.debug("Entering quiet().");
  const bad = K.problemLines(r.log + "\n" + r.output,
                             /:(WARNING|ERROR|CRITICAL):|^(WARNING|ERROR)\b/);
  assert.deepStrictEqual(bad, [], what + " logged a warning or an error:\n" +
                         bad.join("\n"));
  log.debug("Leaving quiet().");
}

function succeeded(r, what) {
  log.debug("Entering succeeded().");
  assert.strictEqual(r.status, 0, what + " exited " + r.status + ":\n" +
                     r.shown);
  quiet(r, what);
  log.debug("Leaving succeeded().");
}

function lineage(name) {
  log.debug("Entering lineage().");
  const dir = path.join(work, "config", "live", name);
  const leaf = K.pemChain(fs.readFileSync(path.join(dir, "cert.pem"),
                                          "utf8"))[0];
  const full = K.pemChain(fs.readFileSync(path.join(dir, "fullchain.pem"),
                                          "utf8"));
  log.debug("Leaving lineage().");
  return { dir: dir, leaf: leaf, full: full };
}

function assertIssued(one, hosts, ekus, what) {
  log.debug("Entering assertIssued().");
  assert.strictEqual(one.full.length, 3,
                     what + ": fullchain is the certificate, the ACME " +
                     "Issuing CA and the realm Intermediate");
  assert.ok(Buffer.from(one.full[0].raw).equals(Buffer.from(one.leaf.raw)));
  K.chainsTo(one.full, bundle.root);
  assert.ok(/ACME/.test(one.full[1].subject), one.full[1].subject);
  const subject = one.leaf.subject;
  assert.ok(new RegExp("CN=" + hosts[0].replace(/\./g, "\\.") + "(\\n|$)")
              .test(subject),
            what + ": the CN is the first host: " + subject);
  assert.ok(/UID=/.test(subject) && subject.indexOf("UID=" + ALICE) >= 0,
            what + ": the UID is the entry: " + subject);
  hosts.forEach(function (h) {
    assert.ok(String(one.leaf.subjectAltName).indexOf("DNS:" + h) >= 0,
              what + ": the SAN names " + h + ": " +
              one.leaf.subjectAltName);
  });
  assert.ok(String(one.leaf.subjectAltName)
              .indexOf("URI:urn:sts:person:" + ALICE) >= 0,
            what + ": the SAN names the entry");
  const has = one.leaf.keyUsage || [];
  assert.deepStrictEqual(has.slice().sort(), ekus.slice().sort(),
                         what + ": EKU " + has.join(","));
  log.debug("Leaving assertIssued().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving " + K.base + " with certbot in the trust realm \"" +
           REALM + "\".");
  const version = K.run("certbot", ["--version"]);
  log.info("certbot: " + version.output.trim());

  // -------------------------------------------------------------------------
  log.info("=== 0. a realm, its CA, a person with two host names ===");
  await K.makeRealm(REALM, "certbot job");
  await K.makePerson(REALM, ALICE, ALICE + "@example.test");
  await K.setting(REALM, "acme.attemptsPerAddress", 100000);
  for (const host of [WWW, APIHOST]) {
    await K.ok(K.realmApi(REALM) + "/acme/add-host-name",
               { kind: "person", identifier: ALICE, hostName: host },
               "registered " + host);
  }
  const eab = await K.ok(K.realmApi(REALM) + "/acme/create-eab",
                         { kind: "person", identifier: ALICE },
                         "created alice's EAB key");
  directory = eab.directory;
  work = K.scratch("certbot");
  bundle = await K.trustBundle(work);
  const register = ["register", "--agree-tos", "--no-eff-email",
                    "-m", ALICE + "@example.test"];

  // -------------------------------------------------------------------------
  log.info("=== 1. registration ===");
  const bare = certbot(register);
  C.check("a registration with no External Account Binding is refused",
          function () {
    assert.notStrictEqual(bare.status, 0, bare.shown);
    assert.ok(/external account|externalAccountRequired/i.test(bare.output),
              bare.shown);
  });
  const wrong = certbot(register.concat([
    "--eab-kid", eab.kid,
    "--eab-hmac-key", Buffer.alloc(32, 7).toString("base64url")]));
  C.check("a binding MACed with the wrong key is refused unauthorized",
          function () {
    assert.notStrictEqual(wrong.status, 0, wrong.shown);
    assert.ok(/unauthorized/i.test(wrong.output), wrong.shown);
  });
  const reg = certbot(register.concat(["--eab-kid", eab.kid,
                                       "--eab-hmac-key", eab.hmacKey]),
                      [eab.hmacKey]);
  C.check("certbot registers with the administrator's EAB key", function () {
    succeeded(reg, "certbot register");
  });
  const view = await K.send(K.realmApi(REALM) + "/acme?per=100");
  const account = ((view.body.accounts || {}).rows || []).filter(
    function (one) {
      return one.eabKid === eab.kid;
    })[0];
  C.check("the account is listed, valid, bound to the person, with the " +
          "address certbot sent", function () {
    assert.ok(account, JSON.stringify(view.body.accounts).slice(0, 800));
    assert.strictEqual(account.status, "valid");
    assert.strictEqual(account.entryUri, "urn:sts:person:" + ALICE);
    assert.ok(account.contact.indexOf("mailto:" + ALICE + "@example.test") >=
              0, JSON.stringify(account.contact));
  });
  const shown = certbot(["show_account"]);
  C.check("show_account prints the account's URL", function () {
    succeeded(shown, "certbot show_account");
    assert.ok(shown.output.indexOf(account.id) >= 0 ||
              /Account URL: https:\/\//.test(shown.output), shown.shown);
  });

  // -------------------------------------------------------------------------
  log.info("=== 2. issuance ===");
  const auth = ["--standalone", "--http-01-port", "18888"];
  const plain = certbot(["certonly", "--cert-name", "plain"].concat(auth,
                        ["-d", WWW, "-d", APIHOST]));
  C.check("certonly with no profile is issued acme.defaultProfile " +
          "(tls-client) for both hosts, with no challenge performed",
          function () {
    succeeded(plain, "certbot certonly");
    assertIssued(lineage("plain"), [WWW, APIHOST], [EKU.clientAuth],
                 "no profile");
  });
  const server = certbot(["certonly", "--cert-name", "server",
                          "--required-profile", "tls-server"].concat(auth,
                         ["-d", WWW]));
  C.check("--required-profile tls-server is issued a serverAuth " +
          "certificate", function () {
    succeeded(server, "certbot certonly --required-profile");
    assertIssued(lineage("server"), [WWW], [EKU.serverAuth], "tls-server");
  });
  const both = certbot(["certonly", "--cert-name", "both",
                        "--preferred-profile", "tls-server-client"]
                       .concat(auth, ["-d", APIHOST]));
  C.check("--preferred-profile tls-server-client is issued both EKUs",
          function () {
    succeeded(both, "certbot certonly --preferred-profile");
    assertIssued(lineage("both"), [APIHOST],
                 [EKU.serverAuth, EKU.clientAuth], "tls-server-client");
  });
  const rootCa = certbot(["certonly", "--cert-name", "rootca",
                          "--required-profile", "root-ca"].concat(auth,
                         ["-d", WWW]));
  C.check("--required-profile root-ca is refused: the server does not " +
          "offer it", function () {
    assert.notStrictEqual(rootCa.status, 0, rootCa.shown);
    assert.ok(/profile/i.test(rootCa.output), rootCa.shown);
    assert.ok(!fs.existsSync(path.join(work, "config", "live", "rootca")));
  });
  const stranger = certbot(["certonly", "--cert-name", "stranger"].concat(
    auth, ["-d", "nobody-" + STAMP + ".example.org"]));
  C.check("a host nobody registered on the entry is refused " +
          "rejectedIdentifier", function () {
    assert.notStrictEqual(stranger.status, 0, stranger.shown);
    assert.ok(/rejectedIdentifier|not registered|does not own/i
                .test(stranger.output), stranger.shown);
  });

  // -------------------------------------------------------------------------
  log.info("=== 3. renewal ===");
  const before = lineage("server").leaf;
  const forced = certbot(["renew", "--cert-name", "server",
                          "--force-renewal"]);
  const after = lineage("server");
  C.check("renew --force-renewal reissues the same names under the same " +
          "profile (every renewal failed rejectedIdentifier before #207)",
          function () {
    succeeded(forced, "certbot renew --force-renewal");
    assert.notStrictEqual(K.serialOf(after.leaf), K.serialOf(before));
    assertIssued(after, [WWW], [EKU.serverAuth], "renewed");
  });
  const notDue = certbot(["renew", "--cert-name", "plain"]);
  C.check("a plain renew renews nothing that is not due", function () {
    succeeded(notDue, "certbot renew");
    assert.ok(/not (yet )?due for renewal/i.test(notDue.output),
              notDue.shown);
    assert.ok(/renewalInfo|renewal-info|ARI/i.test(notDue.log),
              "certbot did not consult renewal information (RFC 9773)");
  });

  // -------------------------------------------------------------------------
  log.info("=== 4. revocation ===");
  const revoked = certbot(["revoke", "--cert-path",
                           path.join(after.dir, "cert.pem"),
                           "--reason", "keycompromise",
                           "--no-delete-after-revoke"]);
  const crl = await K.crlSerials(REALM, "acme");
  C.check("revoke --reason keycompromise puts the serial on the ACME CRL",
          function () {
    succeeded(revoked, "certbot revoke");
    assert.ok(crl.indexOf(K.serialOf(after.leaf)) >= 0,
              "serial " + K.serialOf(after.leaf) + " not in " +
              crl.join(","));
  });

  // -------------------------------------------------------------------------
  log.info("=== 5. the account: update and deactivate ===");
  const updated = certbot(["update_account", "-m",
                           "renamed-" + ALICE + "@example.test"]);
  const view2 = await K.send(K.realmApi(REALM) + "/acme?per=100");
  const account2 = ((view2.body.accounts || {}).rows || []).filter(
    function (one) {
      return one.id === account.id;
    })[0];
  C.check("update_account changes the account's contact", function () {
    succeeded(updated, "certbot update_account");
    assert.ok(account2.contact.indexOf("mailto:renamed-" + ALICE +
                                       "@example.test") >= 0,
              JSON.stringify(account2.contact));
  });
  const gone = certbot(["unregister"]);
  const view3 = await K.send(K.realmApi(REALM) + "/acme?per=100");
  const account3 = ((view3.body.accounts || {}).rows || []).filter(
    function (one) {
      return one.id === account.id;
    })[0];
  C.check("unregister deactivates the account on the server", function () {
    succeeded(gone, "certbot unregister");
    assert.strictEqual(account3.status, "deactivated");
  });
  const again = certbot(register.concat(["--eab-kid", eab.kid,
                                         "--eab-hmac-key", eab.hmacKey]),
                        [eab.hmacKey]);
  C.check("the spent EAB key cannot bind a new account", function () {
    assert.notStrictEqual(again.status, 0, again.shown);
    assert.ok(/unauthorized/i.test(again.output), again.shown);
  });

  assert.ok(C.count >= 15,
    "only " + C.count + " checks ran; a section has stopped being called.");
  log.info(C.count + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_acme_certbot")
  .description("EFF's certbot, at a pinned version, against the ACME " +
      "server: EAB registration and its refusals, issuance with and " +
      "without a profile, renewal, revocation, account update and " +
      "deactivation, and no warning in certbot's own log.")
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
