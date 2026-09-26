"use strict";
//
// File: sts_est_libest.js
//
// ===========================================================================
// CISCO'S libest estclient AGAINST THE EST SERVER (#209, 2026-09-26).
//
// No official EST conformance suite exists. libest (BSD-3-Clause) is the
// reference implementation of RFC 7030, and its `estclient` is what an
// operator bootstraps a device with. At the commit tests/Dockerfile pins
// (a464ba8, statically linked against OpenSSL 1.1.1w — it does not build on
// OpenSSL 3), this job drives every operation and every authentication EST
// allows that this service accepts:
//
//   * BOOTSTRAP (section 4.1.1): `-g` against the service Root alone, then
//     the /cacerts answer — the EST Issuing CA, the realm Intermediate and
//     the Root — becomes the explicit trust anchor database for everything
//     after it, as the RFC has a client do. With the Root alone estclient
//     warns on every re-enrollment ("unable to get local issuer") because
//     it verifies what it was issued against that database.
//   * `-a` /csrattrs under a label (`--path-seg tls-server`): serverAuth and
//     a dNSName hint.
//   * `-e` /simpleenroll with HTTP Basic, the CSR estclient makes itself;
//     under `tls-server` with an `openssl req` CSR (`-y`) naming a host
//     registered on the entry: CN = the host, UID = the entry (#207's fix).
//   * `-r` /simplereenroll with the TLS client certificate; the one it
//     renewed is then refused as a credential (superseded, STS-ENROLL-0018).
//   * `-e` with a TLS client certificate instead of a password.
//   * `-q` /serverkeygen: a certificate and the key the server made, which
//     match (the multipart response failed "OSSL error" until #209's fix).
//   * `-z`, which puts a challengePassword in the CSR — enrolled; the
//     service does not read it (tls-unique does not exist in TLS 1.3,
//     `est/CLAUDE.md` section 3.5).
//   * REFUSALS: no credential (401), a wrong password (refused in product;
//     development checks no password, the root CLAUDE.md non-goal), an
//     unknown label (404), a refused profile (`root-ca`, 403), a host not
//     registered on the entry, a self-signed client certificate, an
//     `--auth-token` (Bearer is not an EST credential here), and `--srp`
//     (no TLS-SRP: TLS 1.3 has none; the handshake is refused).
//   * estclient's own output for every successful command: no `[WARNING]`
//     and no `[ERROR]` line beyond the three recorded below.
//
// **THE DEFAULT REALM, AND A THROWAWAY REALM NAMED IN THE LABEL (#251).**
// estclient builds its URL as https://host:port/.well-known/est[/label]/op
// and can be told nothing else; a realm's EST is at /realm/<id>/.well-known/
// est, which no RFC 7030 client can name, because the well-known URI is at
// the root (RFC 8615). rcbj's decision on #209: the label position names a
// realm. So every scenario runs twice — in the default realm, with people of
// its own names and no default-realm setting changed, and in a throwaway
// realm through `--path-seg <realm>`, where the CA, the CRL and the people
// are asserted to be that realm's and the default realm's password and
// certificate are refused. estclient sends ONE segment, so the realm-profile
// pair (/.well-known/est/<realm>/<profile>/…), a realm named twice, the
// directory's `estLabelUrl`, the console's label-form URLs and a realm
// refused a label's name are driven over HTTP at the end.
//
// THREE LINES estclient PRINTS THAT ARE NOT THE SERVER'S, accepted by name:
//   * `[WARNING]… Not using client certificate for TLS session, HTTP basic
//     or digest auth will be used.` — its note that it has no certificate.
//   * `[WARNING]… HTTP auth failure` — the 401 that asks for Basic: estclient
//     never sends credentials pre-emptively, and HTTP authentication is a
//     challenge first (RFC 9110 section 11.6.1).
//   * `OSSL error: (null)` after every successful /serverkeygen — libest's
//     est_client_verify_key_and_cert() dumps the OpenSSL error queue at its
//     `end:` label on success too, and the queue is empty.
// ===========================================================================

const assert = require("assert");
const fs = require("fs");
const nodeCrypto = require("crypto");
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
var log = bunyan.createLogger({ name: "sts_est_libest",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

const STAMP = usernameFor("le").replace(/[^a-z0-9-]/g, "").slice(0, 24);
// The throwaway realm reached through the label position (#251). A realm id
// is at most 31 characters and may not be an EST label.
const REALM = ("estlib-" + STAMP).slice(0, 31).replace(/-+$/, "");
const EKU = { serverAuth: "1.3.6.1.5.5.7.3.1",
              clientAuth: "1.3.6.1.5.5.7.3.2" };
const ACCEPTED = [
  /Not using client certificate for TLS session/,
  /\[WARNING\]\[est_client_send_enroll_request_internal:\d+\]--> HTTP auth failure/
];
const C = K.checker(log);

var work = "";
var host = "";
var port = "";

// `ctx.seg` is what names the realm to estclient: nothing for the default
// realm, `--path-seg <realm>` for the realm reached by the label form.
async function est(ctx, args, options) {
  log.debug("Entering est().");
  const opts = options || {};
  const out = path.join(work, ctx.tag + "-out-" + opts.name);
  fs.mkdirSync(out, { recursive: true });
  const r = await K.run("estclient", ["-s", host, "-p", port, "-o", out,
                                      "-w", "30"].concat(ctx.seg, args), {
    env: { EST_OPENSSL_CACERT: opts.anchors || ctx.anchors },
    secrets: opts.secrets, timeoutMs: 120000 });
  r.dir = out;
  r.files = fs.readdirSync(out);
  log.debug("Leaving est(). files=" + r.files.join(","));
  return r;
}

// estclient exits 0 on every failure, so success is the file it wrote and
// the absence of any warning or error line it was not expected to print.
function wrote(r, file, what, extra) {
  log.debug("Entering wrote().");
  assert.ok(r.files.indexOf(file) >= 0, what + ": estclient wrote no " +
            file + " (it wrote " + r.files.join(",") + "):\n" + r.shown);
  const bad = K.problemLines(r.output, /\[(WARNING|ERROR)\]|OSSL error/,
                             ACCEPTED.concat(extra || []));
  assert.deepStrictEqual(bad, [], what + ": estclient reported:\n" +
                         bad.join("\n"));
  log.debug("Leaving wrote().");
  return path.join(r.dir, file);
}

function refused(r, pattern, what) {
  log.debug("Entering refused().");
  assert.ok(!r.files.some(function (f) {
    return /^cert-/.test(f);
  }), what + ": a certificate was written:\n" + r.shown);
  assert.ok(pattern.test(r.output), what + ": " + r.shown);
  log.debug("Leaving refused().");
}

// A certs-only PKCS#7, base64 as estclient saves it, read with OpenSSL.
async function certsOf(file) {
  log.debug("Entering certsOf().");
  const der = path.join(work, path.basename(path.dirname(file)) + "-" +
                        path.basename(file) + ".der");
  fs.writeFileSync(der, Buffer.from(fs.readFileSync(file, "utf8"),
                                    "base64"));
  const r = await K.run("openssl", ["pkcs7", "-inform", "der", "-in", der,
                                    "-print_certs"]);
  assert.strictEqual(r.status, 0, r.shown);
  log.debug("Leaving certsOf().");
  return K.pemChain(r.stdout);
}

function leafOf(file) {
  log.debug("Entering leafOf().");
  const chain = K.pemChain(fs.readFileSync(file, "utf8"));
  log.debug("Leaving leafOf().");
  return chain[0];
}

function assertLeaf(ctx, leaf, ekus, what) {
  log.debug("Entering assertLeaf().");
  K.chainsTo([leaf].concat(ctx.cacerts.slice(0, 2)), ctx.cacerts[2]);
  assert.ok(String(leaf.subjectAltName)
              .indexOf("URI:urn:sts:person:" + ctx.person) >= 0,
            what + ": the SAN names the entry: " + leaf.subjectAltName);
  assert.deepStrictEqual((leaf.keyUsage || []).slice().sort(),
                         ekus.slice().sort(), what + ": EKU");
  log.debug("Leaving assertLeaf().");
}

// ---------------------------------------------------------------------------
// EVERY SCENARIO, IN ONE REALM. Run twice: in the default realm, and in a
// throwaway realm named in the label position (#251).
//
// estclient sends ONE label segment and refuses two, so in the realm the
// segment is the realm and a PROFILE cannot also be named: what the default
// realm asks under `--path-seg tls-server` the realm asks with its own
// `est.defaultProfile` set to tls-server for those requests, and set back.
// The two-segment pair form (/.well-known/est/<realm>/<profile>/…) is driven
// over HTTP by this job instead, in `labelForm()`.
// ---------------------------------------------------------------------------
async function scenarios(ctx, bundle, other) {
  log.debug("Entering scenarios(). realm=" + (ctx.realm || "default"));
  const where = ctx.realm ? " [realm " + ctx.realm + ", label form]"
                          : " [default realm]";
  const product = await K.isProduct(ctx.realm);

  // -------------------------------------------------------------------------
  log.info("=== 0. a person and a host name" + where + " ===");
  const password = await K.makePerson(ctx.realm, ctx.person,
                                      ctx.person + "@example.test");
  await K.ok(K.realmApi(ctx.realm) + "/est/add-host-name",
             { kind: "person", identifier: ctx.person, hostName: ctx.host },
             "registered " + ctx.host);
  const basic = ["-u", ctx.person, "-h", password];
  const secrets = [password];

  // -------------------------------------------------------------------------
  log.info("=== 1. /cacerts, the bootstrap" + where + " ===");
  const g = await est(ctx, ["-g"], { name: "cacerts", anchors: bundle.file });
  const cacerts = await certsOf(wrote(g, "cacert-0-0.pkcs7", "-g"));
  C.check("-g fetches the EST Issuing CA, the Intermediate and the Root, " +
          "which chain" + where, function () {
    assert.strictEqual(cacerts.length, 3);
    assert.ok(/EST/.test(cacerts[0].subject), cacerts[0].subject);
    K.chainsTo(cacerts, bundle.root);
    assert.ok(Buffer.from(cacerts[2].raw).equals(Buffer.from(bundle.root.raw)),
              "the third is the service Root");
  });
  if (ctx.realm) {
    const intermediate = await K.realmIntermediate(ctx.realm);
    C.check("-g through the label form answers the REALM's EST Issuing CA " +
            "under the realm's own Intermediate, not the default realm's",
            function () {
      assert.ok(Buffer.from(cacerts[1].raw)
                  .equals(Buffer.from(intermediate.raw)),
                "the second is " + cacerts[1].subject + ", not the realm " +
                "Intermediate " + intermediate.subject);
      assert.ok(!Buffer.from(cacerts[0].raw)
                   .equals(Buffer.from(other.cacerts[0].raw)),
                "the EST Issuing CA is the default realm's");
    });
  }
  ctx.cacerts = cacerts;
  ctx.anchors = path.join(work, ctx.tag + "-cacerts.pem");
  fs.writeFileSync(ctx.anchors, cacerts.map(function (x) {
    return x.toString();
  }).join("\n"));

  // -------------------------------------------------------------------------
  log.info("=== 2. tls-server: /csrattrs and a host certificate" + where +
           " ===");
  const server = ctx.realm ? [] : ["--path-seg", "tls-server"];
  if (ctx.realm) {
    await K.setting(ctx.realm, "est.defaultProfile", "tls-server");
  }
  const a = await est(ctx, ["-a"].concat(server), { name: "attrs" });
  const attrsFile = wrote(a, "csr-0-0.base64", "-a");
  const der = path.join(work, ctx.tag + "-attrs.der");
  fs.writeFileSync(der, Buffer.from(fs.readFileSync(attrsFile, "utf8"),
                                    "base64"));
  const parsed = await K.run("openssl", ["asn1parse", "-inform", "der",
                                         "-in", der]);
  C.check("-a under tls-server names serverAuth and a dNSName hint" + where,
          function () {
    assert.strictEqual(parsed.status, 0, parsed.shown);
    assert.ok(/TLS Web Server Authentication/.test(parsed.output),
              parsed.shown);
    assert.ok(/dNSName/.test(parsed.output), parsed.shown);
  });
  const serverReq = await K.opensslRequest(work, ctx.tag + "-server", {
    subject: "/CN=" + ctx.host, sans: "DNS:" + ctx.host, newkey: "rsa:2048" });
  const e2 = await est(ctx, ["-e"].concat(server, ["-y", serverReq.csr,
                                                   "--pem-output"], basic),
                       { name: "server", secrets: secrets });
  const leaf2 = leafOf(wrote(e2, "cert-0-0.pem", "-e tls-server"));
  C.check("-e under tls-server with an openssl CSR is issued serverAuth, " +
          "CN the host and UID the entry" + where, function () {
    assertLeaf(ctx, leaf2, [EKU.serverAuth], "tls-server");
    assert.ok(leaf2.subject.indexOf("CN=" + ctx.host) >= 0, leaf2.subject);
    assert.ok(leaf2.subject.indexOf("UID=" + ctx.person) >= 0, leaf2.subject);
    assert.ok(String(leaf2.subjectAltName).indexOf("DNS:" + ctx.host) >= 0);
  });
  const strangerReq = await K.opensslRequest(work, ctx.tag + "-stranger", {
    subject: "/CN=nobody-" + STAMP + ".example.org",
    sans: "DNS:nobody-" + STAMP + ".example.org", newkey: "rsa:2048" });
  const stranger = await est(ctx, ["-e"].concat(server,
                                                ["-y", strangerReq.csr],
                                                basic),
                             { name: "stranger", secrets: secrets });
  C.check("a host not registered on the entry is refused" + where,
          function () {
    refused(stranger, /failed with code/, "unregistered host");
  });
  if (ctx.realm) {
    await K.setting(ctx.realm, "est.defaultProfile", "tls-client");
  }

  // -------------------------------------------------------------------------
  log.info("=== 3. /simpleenroll" + where + " ===");
  const e1 = await est(ctx, ["-e"].concat(basic, ["--common-name", ctx.person,
                                                  "--pem-output"]),
                       { name: "enroll", secrets: secrets });
  const leaf1 = leafOf(wrote(e1, "cert-0-0.pem", "-e"));
  const key1 = path.join(e1.dir, "key-x-x.pem");
  C.check("-e with HTTP Basic is issued the default profile (tls-client) " +
          "for the entry, CN the entry" + where, function () {
    assertLeaf(ctx, leaf1, [EKU.clientAuth], "-e");
    assert.ok(/(^|\n)CN=/.test(leaf1.subject) &&
              leaf1.subject.indexOf("CN=" + ctx.person) >= 0, leaf1.subject);
    assert.ok(fs.existsSync(key1));
  });
  const z = await est(ctx, ["-e", "-z", "--common-name", ctx.person,
                            "--pem-output"].concat(basic),
                      { name: "pop", secrets: secrets });
  C.check("-z (a challengePassword in the CSR) enrolls; the service reads " +
          "no tls-unique, which TLS 1.3 does not have" + where, function () {
    assertLeaf(ctx, leafOf(wrote(z, "cert-0-0.pem", "-z")), [EKU.clientAuth],
               "-z");
  });

  // -------------------------------------------------------------------------
  log.info("=== 4. /simplereenroll and a certificate as the credential" +
           where + " ===");
  const r1 = await est(ctx, ["-r", "-c", path.join(e1.dir, "cert-0-0.pem"),
                             "-k", key1, "--pem-output"], { name: "reenroll" });
  const leaf3 = leafOf(wrote(r1, "cert-0-0.pem", "-r"));
  C.check("-r with the TLS client certificate re-enrolls the same entry " +
          "under a new serial" + where, function () {
    assertLeaf(ctx, leaf3, [EKU.clientAuth], "-r");
    assert.notStrictEqual(K.serialOf(leaf3), K.serialOf(leaf1));
    assert.strictEqual(leaf3.subject, leaf1.subject);
  });
  const crl = await K.crlSerials(ctx.realm || "default", "est");
  C.check("the renewed certificate is on the realm's EST CRL (superseded)" +
          where, function () {
    assert.ok(crl.indexOf(K.serialOf(leaf1)) >= 0, crl.join(","));
  });
  const stale = await est(ctx, ["-e", "-c", path.join(e1.dir, "cert-0-0.pem"),
                                "-k", key1, "--common-name", ctx.person],
                          { name: "stale" });
  C.check("the superseded certificate is refused as a credential" + where,
          function () {
    refused(stale, /EST_ERR_AUTH_FAIL/, "superseded certificate");
  });
  const byCert = await est(ctx, ["-e", "-c", path.join(r1.dir, "cert-0-0.pem"),
                                 "-k", key1, "--common-name", ctx.person,
                                 "--pem-output"], { name: "bycert" });
  C.check("-e with a current TLS client certificate and no password " +
          "enrolls" + where, function () {
    assertLeaf(ctx, leafOf(wrote(byCert, "cert-0-0.pem",
                                 "-e by certificate")),
               [EKU.clientAuth], "by certificate");
  });

  // -------------------------------------------------------------------------
  log.info("=== 5. /serverkeygen" + where + " ===");
  const qReq = await K.opensslRequest(work, ctx.tag + "-keygen", {
    subject: "/CN=" + ctx.person, newkey: "rsa:2048" });
  const q = await est(ctx, ["-q", "-x", qReq.key, "--common-name", ctx.person,
                            "--pem-output"].concat(basic),
                      { name: "keygen", secrets: secrets });
  const qLeaf = leafOf(wrote(q, "cert-0-0.pem", "-q",
                             [/^OSSL error: \(null\)$/]));
  const qKeyText = fs.readFileSync(wrote(q, "key-0-0.key", "-q",
                                         [/^OSSL error: \(null\)$/]),
                                   "utf8").replace(/\s+/g, "");
  C.check("-q is issued a certificate and the key the server made, and " +
          "they match" + where, function () {
    assertLeaf(ctx, qLeaf, [EKU.clientAuth], "-q");
    const key = nodeCrypto.createPrivateKey({
      key: Buffer.from(qKeyText, "base64"), format: "der", type: "pkcs8" });
    const pub = nodeCrypto.createPublicKey(key).export({ type: "spki",
                                                         format: "der" });
    assert.ok(Buffer.from(pub).equals(Buffer.from(qLeaf.publicKey.export({
      type: "spki", format: "der" }))), "the key is not the certificate's");
  });

  // -------------------------------------------------------------------------
  log.info("=== 6. refusals" + where + " ===");
  const none = await est(ctx, ["-e", "--common-name", ctx.person],
                         { name: "none" });
  C.check("no credential is refused (401)" + where, function () {
    refused(none, /EST_ERR_AUTH_FAIL/, "no credential");
  });
  const wrong = await est(ctx, ["-e", "-u", ctx.person, "-h",
                                "not-" + password, "--common-name",
                                ctx.person],
                          { name: "wrong", secrets: [password] });
  if (product) {
    C.check("a wrong password is refused (product mode)" + where,
            function () {
      refused(wrong, /EST_ERR_AUTH_FAIL/, "wrong password");
    });
  } else {
    C.check("a wrong password enrolls in development mode, which checks " +
            "no password" + where, function () {
      wrote(wrong, "cert-0-0.pkcs7", "wrong password (development)");
    });
  }
  if (!ctx.realm) {
    const label = await est(ctx, ["-e", "--path-seg", "nosuch",
                                  "--common-name", ctx.person].concat(basic),
                            { name: "label", secrets: secrets });
    C.check("an unknown label is 404", function () {
      refused(label, /EST_ERR_HTTP_NOT_FOUND/, "unknown label");
    });
    const rootCa = await est(ctx, ["-e", "--path-seg", "root-ca",
                                   "--common-name", ctx.person].concat(basic),
                             { name: "rootca", secrets: secrets });
    C.check("a refused profile (root-ca) is refused", function () {
      refused(rootCa, /failed with code/, "root-ca");
    });
  } else {
    // THE REALM BOUNDARY, through the label form: the default realm's
    // person and the default realm's certificate are nobody here.
    const foreign = await est(ctx, ["-e", "-u", other.person, "-h",
                                    other.password, "--common-name",
                                    other.person],
                              { name: "foreign", secrets: [other.password] });
    C.check("the default realm's person is refused in the realm reached " +
            "by the label form" + where, function () {
      refused(foreign, /EST_ERR_AUTH_FAIL|failed with code/,
              "a default-realm password");
    });
    const foreignCert = await est(ctx, ["-e", "-c", other.certFile, "-k",
                                        other.keyFile, "--common-name",
                                        other.person],
                                  { name: "foreigncert" });
    C.check("the default realm's certificate is refused as a credential in " +
            "the realm reached by the label form" + where, function () {
      refused(foreignCert, /EST_ERR_AUTH_FAIL|failed with code/,
              "a default-realm certificate");
    });
  }
  const selfKey = path.join(work, ctx.tag + "-self.key");
  const selfCert = path.join(work, ctx.tag + "-self.pem");
  const self = await K.run("openssl", ["req", "-x509", "-newkey", "ec",
    "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", selfKey,
    "-out", selfCert, "-days", "1", "-subj", "/CN=" + ctx.person]);
  assert.strictEqual(self.status, 0, self.shown);
  const selfSigned = await est(ctx, ["-e", "-c", selfCert, "-k", selfKey,
                                     "--common-name", ctx.person],
                               { name: "self" });
  C.check("a self-signed client certificate is refused" + where,
          function () {
    refused(selfSigned, /EST_ERR_AUTH_FAIL|failed with code/,
            "self-signed certificate");
  });
  const token = await est(ctx, ["-e", "--auth-token", "not-an-est-credential",
                                "--common-name", ctx.person],
                          { name: "token" });
  C.check("a Bearer token (--auth-token) is refused" + where, function () {
    refused(token, /EST_ERR_AUTH_FAIL/, "--auth-token");
  });
  const srp = await est(ctx, ["-e", "--srp", "--srp-user", ctx.person,
                              "--srp-password", password, "--common-name",
                              ctx.person], { name: "srp", secrets: secrets });
  C.check("TLS-SRP is refused at the handshake (the service offers none)" +
          where, function () {
    refused(srp, /EST_ERR_SSL_CONNECT|SSL/, "--srp");
  });
  log.debug("Leaving scenarios().");
  return { person: ctx.person, password: password, cacerts: cacerts,
           certFile: path.join(r1.dir, "cert-0-0.pem"), keyFile: key1 };
}

// ---------------------------------------------------------------------------
// THE LABEL FORM, OVER HTTP, WHERE ESTCLIENT CANNOT GO (#251): the pair
// form, the same bytes by both forms, a realm named twice, the realm
// directory and the console view, and a realm refused a label's name.
// ---------------------------------------------------------------------------
async function labelForm(realm) {
  log.debug("Entering labelForm().");
  log.info("=== 7. the label form over HTTP [realm " + realm + "] ===");
  const byLabel = await fetch(K.base + "/.well-known/est/" + realm +
                              "/cacerts");
  const byPrefix = await fetch(K.base + "/realm/" + realm +
                               "/.well-known/est/cacerts");
  const labelBytes = Buffer.from(await byLabel.arrayBuffer());
  const prefixBytes = Buffer.from(await byPrefix.arrayBuffer());
  C.check("/.well-known/est/<realm>/cacerts answers what " +
          "/realm/<realm>/.well-known/est/cacerts does", function () {
    assert.strictEqual(byLabel.status, 200);
    assert.strictEqual(byPrefix.status, 200);
    assert.ok(labelBytes.equals(prefixBytes), "the two forms differ");
  });
  const pairAttrs = await fetch(K.base + "/.well-known/est/" + realm +
                                "/tls-server/csrattrs");
  const pairText = Buffer.from(await pairAttrs.arrayBuffer())
    .toString("latin1");
  C.check("the pair form /.well-known/est/<realm>/<profile>/csrattrs " +
          "answers the profile in the realm", function () {
    assert.strictEqual(pairAttrs.status, 200, pairText.slice(0, 300));
    // serverAuth's OID, 1.3.6.1.5.5.7.3.1, in DER.
    assert.ok(Buffer.from(pairText.replace(/\s+/g, ""), "base64")
                .indexOf(Buffer.from("2b06010505070301", "hex")) >= 0,
              "no serverAuth in the tls-server csrattrs");
  });
  const twiceLabel = await fetch(K.base + "/.well-known/est/" + realm + "/" +
                                 realm + "/cacerts");
  const twicePrefix = await fetch(K.base + "/realm/" + realm +
                                  "/.well-known/est/" + realm + "/cacerts");
  C.check("a realm named twice — label and label, prefix and label — is " +
          "404, never a mix", function () {
    assert.strictEqual(twiceLabel.status, 404);
    assert.strictEqual(twicePrefix.status, 404);
  });
  const directory = await K.send(K.base + "/realms");
  C.check("GET /realms carries the realm's estLabelUrl, and none for the " +
          "default", function () {
    const rows = (directory.body && directory.body.realms) || [];
    const row = rows.filter(function (one) {
      return one.id === realm;
    })[0];
    const dflt = rows.filter(function (one) {
      return one.id === "default";
    })[0];
    assert.ok(row, "the realm is listed");
    assert.strictEqual(row.estLabelUrl, K.base + "/.well-known/est/" + realm);
    assert.strictEqual(dflt.estLabelUrl, null);
  });
  const view = await K.send(K.realmApi(realm) + "/est");
  C.check("/admin-api/est in the realm shows the label-form URLs",
          function () {
    assert.strictEqual(view.status, 200, view.raw.slice(0, 300));
    assert.ok(view.body.labelForm && /\/\.well-known\/est\/[^/]+$/
      .test(view.body.labelForm.base) &&
      view.body.labelForm.base.slice(-realm.length - 1) === "/" + realm,
              JSON.stringify(view.body.labelForm));
    assert.ok(view.body.endpoints.every(function (one) {
      return one.labelFormUrl === view.body.labelForm.base + "/" +
             one.operation;
    }), JSON.stringify(view.body.endpoints));
  });
  const clash = await K.post(K.realmApi(null) + "/realms/create",
                             { id: "tls-server", domain: "tls-server-" +
                               STAMP + ".example.net", name: "clash" });
  C.check("a realm may not be called by an EST label's name", function () {
    assert.ok(clash.status !== 200 || (clash.body && clash.body.ok === false),
              clash.raw.slice(0, 300));
    assert.ok(/EST label/.test(clash.raw), clash.raw.slice(0, 300));
  });
  log.debug("Leaving labelForm().");
}

async function test() {
  log.debug("Entering test().");
  const url = new URL(K.base);
  host = url.hostname;
  port = url.port || "443";
  log.info("Driving " + K.base + " with libest's estclient in the default " +
           "realm and in the realm \"" + REALM + "\" named in the label " +
           "position.");
  work = K.scratch("estclient");
  const bundle = await K.trustBundle(work);

  const dperson = "estlib-" + STAMP;
  const inDefault = await scenarios({ realm: null, tag: "d", seg: [],
                                      person: dperson,
                                      host: "dev." + dperson + ".test" },
                                    bundle, null);

  // -------------------------------------------------------------------------
  // A THROWAWAY REALM, reached the one way an EST client can be told (#251).
  await K.makeRealm(REALM, "estclient job");
  await K.setting(REALM, "est.attemptsPerAddress", 100000);
  const rperson = "estlibr-" + STAMP;
  await scenarios({ realm: REALM, tag: "r", seg: ["--path-seg", REALM],
                    person: rperson, host: "dev." + rperson + ".test" },
                  bundle, inDefault);
  await labelForm(REALM);

  assert.ok(C.count >= 43,
    "only " + C.count + " checks ran; a section has stopped being called.");
  log.info(C.count + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_est_libest")
  .description("Cisco's libest estclient, at a pinned commit, against the " +
      "EST server: bootstrap, csrattrs, simpleenroll with Basic and with a " +
      "certificate, simplereenroll, serverkeygen, and the refusals — in the " +
      "default realm and in a realm named in the label position (#251).")
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error((e.stack || e.message) +
            (e.cause ? "\ncaused by: " + (e.cause.stack || e.cause) : ""));
  process.exit(1);
});
