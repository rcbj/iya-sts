"use strict";
//
// File: sts_est_enrollment.js
//
// ===========================================================================
// EST (RFC 7030, RFC 8951) AGAINST THE RUNNING SERVICE, WITH A CLIENT OF ITS
// OWN (2026-09-13).
//
// `local: true`, on `tests/CLAUDE.md`'s third reason: every assertion spans an
// authoring door and a protocol door. A realm's certificate authority comes
// from `/admin-api/pki/build`, the people and applications from
// `/admin-api`, the host names a server certificate needs from
// `/admin-api/est/add-host-name` —
// and only then is there anything worth asking `/.well-known/est`.
//
// The client is `est_client.js`, written from the RFCs with nothing from `est/`
// or `common/cert_enrollment.js`, so a certs-only message, a multipart response
// and a csrattrs document are read by a SECOND implementation. CSRs are built
// with the parent project's vendored `x509.js`, the independent PKI code
// `sts_user_credentials.js` builds its certificates with.
//
// It works in throwaway trust realms it LEAVES STANDING (`tests/CLAUDE.md`'s
// *No job removes a realm*). It changes ONE thing outside them, for as short a
// time as the check takes: a default-realm person is put in the Admin Write
// roster so an administrator's enrollment for somebody else can be asserted,
// and taken out again in a `finally` — a left-over member would be a service
// administrator nobody meant, for every later job in the run.
//
// Mostly negatives, for `sts_dpop.js`'s reason: an enrollment server that hands
// a working client a certificate looks finished and can be worth nothing.
// ===========================================================================

const assert = require("assert");
const nodeCrypto = require("crypto");
const path = require("path");
const { Command, Option } = require("commander");
const { usernameFor } = require("./random_username.js");
const est = require("./est_client.js");

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
var log = bunyan.createLogger({ name: "sts_est_enrollment",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

const REPO = process.env.MOCK_STS_DIR || path.join(__dirname, "..", "..");
const x509 = require(path.join(REPO, "common", "vendored", "x509.js"));
const keys = require(path.join(REPO, "common", "vendored",
                               "key_material.js"));

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");
var api = base + "/admin-api";

function realmName(prefix) {
  log.debug("Entering realmName().");
  log.debug("Leaving realmName().");
  return usernameFor(prefix).replace(/[^a-z0-9-]/g, "").slice(0, 30);
}

const REALM = realmName("est");
const REALM_B = realmName("estb");
const REALM_P = realmName("estp");
const realmBase = base + "/realm/" + REALM;
const realmApi = realmBase + "/admin-api";
const EST = realmBase + "/.well-known/est";

const PERSON = usernameFor("estalice");
const OTHER = usernameFor("estbob");
const ADMIN = usernameFor("estadmin");
const APP = realmName("estapp");
const APP_SECRET = nodeCrypto.randomBytes(18).toString("base64url");
const HOST = APP + ".svc.example.test";
const PERSON_HOST = PERSON.replace(/[^a-z0-9-]/g, "") + ".host.example.test";
const MAIL = PERSON + "@est.example.test";

const OIDS = {
  signedData: "1.2.840.113549.1.7.2",
  extensionRequest: "1.2.840.113549.1.9.14",
  extKeyUsage: "2.5.29.37",
  subjectAltName: "2.5.29.17",
  ecdsaSha256: "1.2.840.10045.4.3.2",
  serverAuth: "1.3.6.1.5.5.7.3.1",
  clientAuth: "1.3.6.1.5.5.7.3.2",
  codeSigning: "1.3.6.1.5.5.7.3.3",
  emailProtection: "1.3.6.1.5.5.7.3.4",
  timeStamping: "1.3.6.1.5.5.7.3.8",
  msSmartcardLogon: "1.3.6.1.4.1.311.20.2.2",
  mlKem768: "2.16.840.1.101.3.4.4.2",
  ecPublicKey: "1.2.840.10045.2.1"
};

// What each profile certifies, written from the profile table rather than read
// from the service, so a certificate with the wrong purpose fails here.
const PROFILE_EKUS = {
  "tls-server": [OIDS.serverAuth],
  "tls-client": [OIDS.clientAuth],
  "tls-server-client": [OIDS.serverAuth, OIDS.clientAuth],
  "digital-signature": [],
  "key-encipherment": [],
  "code-signing": [OIDS.codeSigning],
  "email": [OIDS.emailProtection],
  "timestamping": [OIDS.timeStamping],
  "smartcard-logon": [OIDS.clientAuth, OIDS.msSmartcardLogon]
};

var checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  ✓ " + what);
  log.debug("Leaving check().");
}

async function send(url, options) {
  log.debug("Entering send().");
  const r = await fetch(url, options);
  const raw = await r.text();
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in send(): " + ((e && e.message) || e));
    // Not JSON — quoting the page whole says more than a parse failure.
    parsed = raw;
  }
  log.debug("Leaving send().");
  return { status: r.status, body: parsed, raw: raw };
}

async function post(url, body) {
  log.debug("Entering post().");
  const r = await send(url, { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}) });
  log.debug("Leaving post().");
  return r;
}

async function ok(url, body, what) {
  log.debug("Entering ok().");
  const r = await post(url, body);
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "POST " + url + " should have " + what + "; it answered " + r.status +
    " " + JSON.stringify((r.body && (r.body.errors || r.body.why)) || r.body)
      .slice(0, 500));
  log.debug("Leaving ok().");
  return r.body;
}

async function setIn(realmApiBase, key, value) {
  log.debug("Entering setIn(). " + key);
  await ok(realmApiBase + "/config/set", { key: key, value: value },
           "set " + key);
  log.debug("Leaving setIn().");
}

// Put a setting back the way `tests/CLAUDE.md` says: reset, never a write of
// the old value. Quiet, because a `finally` that throws hides the failure that
// got there.
async function resetIn(realmApiBase, key) {
  log.debug("Entering resetIn(). " + key);
  try {
    await post(realmApiBase + "/config/reset", { key: key });
  } catch (e) {
    log.warn("could not reset " + key + ": " + ((e && e.message) || e));
  }
  log.debug("Leaving resetIn().");
}

// A PKCS#10 request over a fresh key pair of `alg`.
async function csrFor(alg, commonName, names, keyPair) {
  log.debug("Entering csrFor(). " + alg);
  const pair = keyPair || await keys.generateKeyPair(alg);
  const built = await x509.certificationRequest({
    subject: commonName.indexOf("=") >= 0 ? commonName : "CN=" + commonName,
    publicKeyPem: pair.publicPem,
    privateKeyPem: pair.privatePem, subjectAltName: names || [] });
  log.debug("Leaving csrFor().");
  return { der: Buffer.from(built.der), pair: pair };
}

// POST a base64 PKCS#10 body. `extra` carries `basic`, `key`/`cert` or extra
// `headers`.
function enroll(url, der, extra) {
  log.debug("Entering enroll(). " + url);
  const more = extra || {};
  log.debug("Leaving enroll().");
  return est.send({
    method: "POST", url: url, body: est.requestBody(der),
    headers: Object.assign({ "Content-Type": "application/pkcs10" },
                           more.headers || {}),
    basic: more.basic, key: more.key, cert: more.cert
  });
}

// A certificate's subject as the "A=b, C=d" string the vendored CSR builder
// reads, in the order the certificate carries it — which RFC 7030 section
// 4.2.2 requires a re-enrollment to repeat exactly.
function subjectString(cert) {
  log.debug("Entering subjectString().");
  log.debug("Leaving subjectString().");
  return String(cert.subject).split("\n").join(", ");
}

function sameKey(cert, publicPem) {
  log.debug("Entering sameKey().");
  log.debug("Leaving sameKey().");
  return cert.publicKey.export({ type: "spki", format: "der" }).equals(
    nodeCrypto.createPublicKey(publicPem).export({ type: "spki",
                                                   format: "der" }));
}

function text(r) {
  log.debug("Entering text().");
  log.debug("Leaving text().");
  return r.body.toString("utf8").slice(0, 400);
}

function issuedCertificate(r, what) {
  log.debug("Entering issuedCertificate().");
  assert.strictEqual(r.status, 200, what + " should be issued; it answered " +
                     r.status + " " + text(r));
  assert.ok(/^application\/pkcs7-mime/.test(r.headers["content-type"] || ""),
            what + ": the media type is " + r.headers["content-type"]);
  assert.ok(/smime-type=certs-only/.test(r.headers["content-type"] || ""),
            what + ": smime-type=certs-only is missing");
  assert.strictEqual(r.headers["content-transfer-encoding"], "base64",
                     what + ": RFC 8951 makes the body base64");
  assert.strictEqual(r.headers["cache-control"], "no-store",
                     what + ": a certificate is served no-store");
  const parsed = est.parseCertsOnly(est.base64Body(r.body));
  assert.strictEqual(parsed.signerCount, 0,
                     what + ": a certs-only message has no signer");
  assert.strictEqual(parsed.certificates.length, 1,
                     what + ": exactly the issued certificate is returned");
  log.debug("Leaving issuedCertificate().");
  return new nodeCrypto.X509Certificate(parsed.certificates[0]);
}

function refused(r, status, what, pattern) {
  log.debug("Entering refused(). " + status);
  assert.strictEqual(r.status, status, what + ": expected " + status +
                     ", got " + r.status + " " + text(r));
  assert.ok(!/STS-[A-Z]+-\d{4}/.test(r.body.toString("utf8")),
            what + ": an error code reached the client");
  if (pattern) {
    assert.ok(pattern.test(r.body.toString("utf8")), what + ": the sentence " +
              "does not say why: " + text(r));
  }
  log.debug("Leaving refused().");
}

// Every JSON path under `value` whose string matches `pattern`.
function pathsHolding(value, pattern, prefix) {
  log.debug("Entering pathsHolding().");
  const here = prefix || "$";
  let out = [];
  if (typeof value === "string") {
    out = pattern.test(value) ? [here] : [];
  } else if (value && typeof value === "object") {
    Object.keys(value).forEach(function (key) {
      out = out.concat(pathsHolding(value[key], pattern, here + "." + key));
    });
  }
  log.debug("Leaving pathsHolding().");
  return out;
}

function sanUris(cert) {
  log.debug("Entering sanUris().");
  log.debug("Leaving sanUris().");
  return String(cert.subjectAltName || "").split(/,\s*/)
    .filter(function (one) {
      return one.indexOf("URI:") === 0;
    })
    .map(function (one) {
      return one.slice(4);
    });
}

function serialOf(cert) {
  log.debug("Entering serialOf().");
  log.debug("Leaving serialOf().");
  return String(cert.serialNumber).toLowerCase().replace(/^0+(?=.)/, "");
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving " + base + " in the trust realm \"" + REALM + "\".");
  const serials = {};
  let chain = null;

  // -------------------------------------------------------------------------
  log.info("=== 0. three realms, their certificate authorities, " +
           "the people ===");
  for (const one of [[REALM, "EST"], [REALM_B, "EST B"], [REALM_P,
                                                          "EST product"]]) {
    await ok(api + "/realms/create", { id: one[0], name: one[1] },
             "created the trust realm " + one[0]);
  }
  await ok(api + "/realms/set", { id: REALM_P, key: "global.mode",
                                  value: "product" },
           "made " + REALM_P + " a product-mode realm");
  for (const id of [REALM, REALM_B, REALM_P]) {
    const ra = base + "/realm/" + id + "/admin-api";
    await ok(ra + "/pki/build", { organisation: "EST Test", country: "US" },
             "built the certificate authority of " + id);
    // The address bucket is shared by every realm (it is keyed by the client
    // address), and this job refuses a great many requests on purpose.
    await setIn(ra, "est.attemptsPerAddress", 100000);
  }
  await ok(realmApi + "/users/create",
           { username: PERSON, invent: false, credential: "none",
             attributes: { cn: "EST Alice", sn: PERSON, mail: MAIL } },
           "created the person");
  await ok(realmApi + "/users/create",
           { username: OTHER, invent: false, credential: "none",
             attributes: { cn: "EST Bob", sn: OTHER,
                           mail: OTHER + "@est.example.test" } },
           "created a second person");
  await ok(realmApi + "/applications/create",
           { identifier: APP, protocols: ["oauth2"],
             fields: { oauthClientId: APP, oauthClientSecret: APP_SECRET } },
           "created an application");
  await ok(realmApi + "/est/add-host-name",
           { kind: "person", identifier: PERSON, hostName: PERSON_HOST },
           "registered a host name on the person");
  await ok(realmApi + "/est/add-host-name",
           { kind: "application", identifier: APP, hostName: HOST },
           "registered a host name on the application");
  const basic = [PERSON, "any-password-development-mode"];

  // -------------------------------------------------------------------------
  log.info("=== 1. /cacerts, unauthenticated, and the chain it returns ===");
  const ca = await est.send({ method: "GET", url: EST + "/cacerts" });
  check("GET /cacerts answers a certs-only message with three certificates, " +
        "base64, no signer", function () {
          assert.strictEqual(ca.status, 200, text(ca));
          assert.ok(/^application\/pkcs7-mime/.test(
            ca.headers["content-type"]));
          assert.strictEqual(ca.headers["content-transfer-encoding"], "base64");
          const parsed = est.parseCertsOnly(est.base64Body(ca.body));
          assert.strictEqual(parsed.signerCount, 0);
          assert.strictEqual(parsed.certificates.length, 3,
                             "the EST Issuing CA, the realm Intermediate and " +
                             "the service Root");
          chain = parsed.certificates.map(function (pem) {
            return new nodeCrypto.X509Certificate(pem);
          });
        });
  check("the three verify as a path: Issuing under Intermediate under a " +
        "self-signed Root", function () {
          assert.ok(chain[0].verify(chain[1].publicKey),
                    "the Issuing CA is not signed by the Intermediate");
          assert.ok(chain[1].verify(chain[2].publicKey),
                    "the Intermediate is not signed by the Root");
          assert.ok(chain[2].verify(chain[2].publicKey),
                    "the Root is not self-signed");
          assert.ok(chain[0].ca && chain[1].ca && chain[2].ca);
          assert.ok(/EST/.test(chain[0].subject), chain[0].subject);
        });
  const labelledCa = await est.send({ method: "GET",
                                      url: EST + "/tls-client/cacerts" });
  check("the labelled /cacerts returns the same CA", function () {
    assert.strictEqual(labelledCa.status, 200, text(labelledCa));
    const again = est.parseCertsOnly(est.base64Body(labelledCa.body));
    assert.strictEqual(new nodeCrypto.X509Certificate(again.certificates[0])
                         .fingerprint256, chain[0].fingerprint256);
  });

  // -------------------------------------------------------------------------
  log.info("=== 2. /csrattrs ===");
  const attrs = await est.send({ method: "GET",
                                 url: EST + "/tls-server/csrattrs" });
  check("GET /tls-server/csrattrs names a signature algorithm, the " +
        "extensionRequest attribute, serverAuth and a dNSName hint",
        function () {
          assert.strictEqual(attrs.status, 200, text(attrs));
          assert.ok(/^application\/csrattrs/.test(
            attrs.headers["content-type"]));
          const items = est.parseCsrAttrs(est.base64Body(attrs.body));
          const oids = items.filter(function (i) {
            return i.oid;
          }).map(function (i) {
            return i.oid;
          });
          assert.ok(oids.indexOf(OIDS.ecdsaSha256) >= 0, JSON.stringify(oids));
          assert.ok(oids.indexOf(OIDS.extensionRequest) >= 0);
          const eku = items.filter(function (i) {
            return i.type === OIDS.extKeyUsage;
          })[0];
          assert.ok(eku && eku.values.some(function (v) {
            return v.oid === OIDS.serverAuth;
          }), JSON.stringify(items));
          const san = items.filter(function (i) {
            return i.type === OIDS.subjectAltName;
          })[0];
          assert.ok(san && san.values.some(function (v) {
            return v.text === "dNSName";
          }));
        });

  // -------------------------------------------------------------------------
  log.info("=== 3. every profile, labelled, for a person ===");
  const PROFILES = Object.keys(PROFILE_EKUS);
  let reenrollSource = null;
  for (const profile of PROFILES) {
    const names = [];
    if (profile === "tls-server" || profile === "tls-server-client") {
      names.push({ kind: "dns", value: PERSON_HOST });
    }
    if (profile === "email") {
      names.push({ kind: "email", value: MAIL });
    }
    if (profile === "smartcard-logon") {
      names.push({ kind: "upn", value: MAIL });
    }
    const alg = profile === "key-encipherment" ? "rsa-2048" : "ec-p256";
    const request = await csrFor(alg, PERSON, names);
    const r = await enroll(EST + "/" + profile + "/simpleenroll", request.der,
                           { basic: basic });
    const cert = issuedCertificate(r, profile);
    serials[profile] = serialOf(cert);
    check(profile + ": chains to the EST Issuing CA, names the person, " +
          "certifies " + (PROFILE_EKUS[profile].join(", ") || "no EKU"),
          function () {
            assert.ok(cert.verify(chain[0].publicKey),
                      "not signed by the EST Issuing CA");
            assert.ok(cert.checkIssued(chain[0]));
            assert.deepStrictEqual(sanUris(cert),
                                   ["urn:sts:person:" + PERSON],
                                   String(cert.subjectAltName));
            assert.ok(/CN=/.test(cert.subject) &&
                      cert.subject.indexOf("CN=" + PERSON) >= 0,
                      cert.subject);
            const ekus = cert.keyUsage || [];
            PROFILE_EKUS[profile].forEach(function (oid) {
              assert.ok(ekus.indexOf(oid) >= 0, profile + " lacks " + oid +
                        ": " + JSON.stringify(ekus));
            });
            assert.strictEqual(cert.ca, false);
            assert.ok(sameKey(cert, request.pair.publicPem),
                      "the certificate is not over the key sent");
          });
    if (profile === "tls-server" || profile === "tls-server-client") {
      check(profile + ": the registered host name is a dNSName", function () {
        assert.ok(String(cert.subjectAltName).indexOf("DNS:" + PERSON_HOST) >=
                  0, cert.subjectAltName);
      });
    }
    if (profile === "email") {
      check("email: the rfc822Name is the person's mail", function () {
        assert.ok(String(cert.subjectAltName).indexOf("email:" + MAIL) >= 0,
                  cert.subjectAltName);
      });
    }
    if (profile === "smartcard-logon") {
      check("smartcard-logon: the UPN otherName equals the person's mail",
            function () {
              assert.ok(String(cert.subjectAltName)
                .indexOf("othername:UPN:" + MAIL) >= 0, cert.subjectAltName);
            });
    }
    if (profile === "tls-client") {
      reenrollSource = { cert: cert, pair: request.pair,
                         pem: cert.toString() };
    }
  }
  const unlabelled = await enroll(EST + "/simpleenroll",
                                  (await csrFor("ec-p256", PERSON, [])).der,
                                  { basic: basic });
  check("the unlabelled path issues est.defaultProfile (tls-client)",
        function () {
          const cert = issuedCertificate(unlabelled, "unlabelled");
          assert.ok((cert.keyUsage || []).indexOf(OIDS.clientAuth) >= 0);
        });

  // -------------------------------------------------------------------------
  log.info("=== 4. the record is on the entry, with no private key ===");
  const view = await send(realmApi + "/est?per=100");
  check("GET /admin-api/est lists every serial just issued, for the person",
        function () {
          assert.strictEqual(view.status, 200, view.raw.slice(0, 300));
          const rows = view.body.certificates.rows;
          PROFILES.forEach(function (profile) {
            const row = rows.filter(function (one) {
              return one.serialHex === serials[profile];
            })[0];
            assert.ok(row, profile + " serial " + serials[profile] +
                      " is not listed");
            assert.strictEqual(row.entryUri, "urn:sts:person:" + PERSON);
            assert.strictEqual(row.profile, profile);
          });
          assert.ok(!/PRIVATE KEY/.test(view.raw));
          assert.ok(view.body.hierarchy.built);
          assert.strictEqual(view.body.profiles.length, 9);
          assert.strictEqual(view.body.refusedProfiles.length, 5);
        });
  const user = await send(realmApi + "/users?user=" +
                          encodeURIComponent(PERSON));
  check("the person's entry carries the enrolled certificates", function () {
    assert.strictEqual(user.status, 200, user.raw.slice(0, 200));
    assert.ok(user.raw.indexOf(serials["tls-client"]) >= 0,
              "the serial is not on /admin-api/users?user=");
  });

  // -------------------------------------------------------------------------
  log.info("=== 5. an application, for itself ===");
  const appCsr = await csrFor("ec-p256", APP, [{ kind: "dns", value: HOST }]);
  const appCert = await enroll(EST + "/tls-server/simpleenroll", appCsr.der,
                               { basic: [APP, APP_SECRET] });
  check("client_id:client_secret enrolls a tls-server certificate naming the " +
        "application and its registered host", function () {
          const cert = issuedCertificate(appCert, "application");
          assert.deepStrictEqual(sanUris(cert),
                                 ["urn:sts:application:" + APP]);
          assert.ok(String(cert.subjectAltName).indexOf("DNS:" + HOST) >= 0);
        });

  // -------------------------------------------------------------------------
  log.info("=== 6. an administrator, for somebody else ===");
  await ok(api + "/users/create",
           { username: ADMIN, invent: false, credential: "none",
             attributes: { cn: "EST Admin", sn: ADMIN } },
           "created the administrator in the DEFAULT realm");
  const plainForOther = await enroll(EST + "/tls-client/simpleenroll",
    (await csrFor("ec-p256", OTHER,
                  [{ kind: "uri", value: "urn:sts:person:" + OTHER }])).der,
    { basic: [ADMIN, "anything"] });
  check("BEFORE the roster grant, the same name is refused", function () {
    refused(plainForOther, 401, "an unknown name with no Admin Write");
  });
  try {
    await ok(api + "/rbac/grant", { username: ADMIN, role: "write" },
             "granted Admin Write");
    const forOther = await enroll(EST + "/tls-client/simpleenroll",
      (await csrFor("ec-p256", OTHER,
                    [{ kind: "uri", value: "urn:sts:person:" + OTHER }])).der,
      { basic: [ADMIN, "anything"] });
    check("an administrator enrolls a certificate for ANOTHER person " +
          "named by URN", function () {
            const cert = issuedCertificate(forOther, "admin for other");
            assert.deepStrictEqual(sanUris(cert),
                                   ["urn:sts:person:" + OTHER]);
          });
  } finally {
    try {
      await post(api + "/rbac/revoke", { username: ADMIN, role: "write" });
    } catch (e) {
      log.warn("could not revoke Admin Write from " + ADMIN + ": " +
               ((e && e.message) || e));
    }
  }

  // -------------------------------------------------------------------------
  log.info("=== 7. /serverkeygen: an EC template and an ML-KEM template ===");
  const ecTemplate = await csrFor("ec-p384", PERSON, []);
  const ecKeygen = await enroll(EST + "/tls-client/serverkeygen",
                                ecTemplate.der, { basic: basic });
  check("an EC template answers multipart/mixed with a PKCS#8 key and a " +
        "certificate over THAT key (not the template's)", function () {
          assert.strictEqual(ecKeygen.status, 200, text(ecKeygen));
          assert.strictEqual(ecKeygen.headers["cache-control"], "no-store");
          const parts = est.parseMultipart(ecKeygen.headers["content-type"],
                                           ecKeygen.body);
          assert.strictEqual(parts.length, 2);
          assert.ok(/^application\/pkcs8/.test(
            parts[0].headers["content-type"]));
          assert.strictEqual(parts[0].headers["content-transfer-encoding"],
                             "base64");
          assert.ok(/smime-type=certs-only/.test(
            parts[1].headers["content-type"]));
          const privateKey = nodeCrypto.createPrivateKey({
            key: parts[0].der, format: "der", type: "pkcs8" });
          const cert = new nodeCrypto.X509Certificate(
            est.parseCertsOnly(parts[1].der).certificates[0]);
          assert.ok(cert.checkPrivateKey(privateKey),
                    "the key does not match the certificate");
          assert.ok(!sameKey(cert, ecTemplate.pair.publicPem),
                    "the template's key was certified");
          assert.ok(cert.verify(chain[0].publicKey));
          serials.serverkeygen = serialOf(cert);
        });
  const kemPair = await keys.generateKeyPair("ml-kem-768");
  const kemCsr = est.kemTemplateCsr(kemPair.publicPem, PERSON);
  const kemKeygen = await enroll(EST + "/key-encipherment/serverkeygen",
                                 kemCsr, { basic: basic });
  check("an ML-KEM template is answered with an ML-KEM-768 key and a " +
        "certificate for it", function () {
          assert.strictEqual(kemKeygen.status, 200, text(kemKeygen));
          const parts = est.parseMultipart(kemKeygen.headers["content-type"],
                                           kemKeygen.body);
          assert.strictEqual(est.pkcs8KeyOid(parts[0].der), OIDS.mlKem768);
          const pem = est.parseCertsOnly(parts[1].der).certificates[0];
          assert.strictEqual(est.certificateKeyOid(pem), OIDS.mlKem768);
          assert.ok(new nodeCrypto.X509Certificate(pem)
                      .verify(chain[0].publicKey));
        });
  const viewAfterKeygen = await send(realmApi + "/est?per=100");
  const userAfterKeygen = await send(realmApi + "/users?user=" +
                                     encodeURIComponent(PERSON));
  check("no private key is readable through the EST view, nor anywhere " +
        "in the user view but the raw directory dump", function () {
          assert.ok(!/PRIVATE KEY/.test(viewAfterKeygen.raw));
          // The user page's `ldap.entry.attributes` is the stored
          // entry dumped whole, by `ldap/ldap_server.js`'s own decision ("a
          // dump that silently dropped two of the entry's attributes would be
          // the one thing a dump must not do"). In development mode the key on
          // `stsEnrolledPrivateKey` is stored unsealed, and the dump now
          // WITHHOLDS its value in every mode
          // (`cert_enrollment.withheldValues()`). The attribute is still
          // dropped here so that this check is about everything ELSE in the
          // reply, whatever the dump does with it.
          const body = JSON.parse(userAfterKeygen.raw);
          const attrs = (body && body.ldap && body.ldap.entry &&
                         body.ldap.entry.attributes) || {};
          Object.keys(attrs).forEach(function (name) {
            if (name.toLowerCase() === "stsenrolledprivatekey") {
              delete attrs[name];
            }
          });
          assert.deepStrictEqual(pathsHolding(body, /PRIVATE KEY/), [],
                                 "a private key appears outside the " +
                                 "directory dump");
        });

  // -------------------------------------------------------------------------
  log.info("=== 8. /simplereenroll with the client certificate ===");
  const renewal = await csrFor("ec-p256", subjectString(reenrollSource.cert),
                               [{ kind: "uri",
                                  value: "urn:sts:person:" + PERSON }]);
  const renewed = await enroll(EST + "/simplereenroll", renewal.der,
                               { key: reenrollSource.pair.privatePem,
                                 cert: reenrollSource.pem });
  let renewedCert = null;
  check("a tls-client certificate from section 3 renews itself: a new " +
        "certificate over the new key", function () {
          renewedCert = issuedCertificate(renewed, "reenroll");
          assert.notStrictEqual(serialOf(renewedCert), serials["tls-client"]);
          assert.ok((renewedCert.keyUsage || []).indexOf(OIDS.clientAuth) >= 0,
                    "an unlabelled renewal keeps the renewed profile");
        });
  const crl = await est.send({ method: "GET", url: base + "/pki/crl/" +
                               REALM + "/est" });
  check("the renewed certificate is on the EST Issuing CA's CRL (superseded)",
        function () {
          assert.strictEqual(crl.status, 200, text(crl));
          assert.ok(est.crlSerials(crl.body).indexOf(serials["tls-client"]) >=
                    0, "serial " + serials["tls-client"] + " is not listed");
        });
  const badSubject = await csrFor("ec-p256", OTHER,
                                  [{ kind: "uri",
                                     value: "urn:sts:person:" + PERSON }]);
  const renewedPem = renewedCert.toString();
  const differs = await enroll(EST + "/simplereenroll", badSubject.der,
                               { key: renewal.pair.privatePem,
                                 cert: renewedPem });
  check("a re-enrollment whose subject differs is refused 400", function () {
    refused(differs, 400, "reenroll with another subject", /subject/i);
  });
  const oldAgain = await enroll(EST + "/simplereenroll", renewal.der,
                                { key: reenrollSource.pair.privatePem,
                                  cert: reenrollSource.pem });
  check("the superseded certificate no longer authenticates", function () {
    refused(oldAgain, 401, "a superseded client certificate");
  });
  const basicRenewal = await csrFor("ec-p256", subjectString(renewedCert),
                                    [{ kind: "uri",
                                       value: "urn:sts:person:" + PERSON }]);
  const byBasic = await enroll(EST + "/simplereenroll", basicRenewal.der,
                               { basic: basic });
  check("with Basic alone the certificate to renew is found by subject and " +
        "names", function () {
          const cert = issuedCertificate(byBasic, "reenroll by Basic");
          assert.notStrictEqual(serialOf(cert), serialOf(renewedCert));
        });
  const noneToRenew = await enroll(EST + "/simplereenroll",
    (await csrFor("ec-p256", OTHER, [])).der, { basic: [OTHER, "x"] });
  check("with Basic and nothing matching, the re-enrollment is refused 400",
        function () {
          refused(noneToRenew, 400, "nothing to renew", /renew/i);
        });

  // -------------------------------------------------------------------------
  log.info("=== 9. revocation through /admin-api ===");
  const before = est.crlSerials((await est.send({ method: "GET",
    url: base + "/pki/crl/" + REALM + "/est" })).body);
  check("the code-signing certificate is not on the CRL yet", function () {
    assert.ok(before.indexOf(serials["code-signing"]) < 0);
  });
  await ok(realmApi + "/est/revoke-certificate",
           { serialHex: serials["code-signing"], reason: "keyCompromise" },
           "revoked the code-signing certificate");
  const after = est.crlSerials((await est.send({ method: "GET",
    url: base + "/pki/crl/" + REALM + "/est" })).body);
  check("and it is on the CRL afterwards, and marked on the entry",
        function () {
    assert.ok(after.indexOf(serials["code-signing"]) >= 0);
  });
  const viewRevoked = await send(realmApi + "/est?per=100");
  check("the view reports it revoked", function () {
    const row = viewRevoked.body.certificates.rows.filter(function (one) {
      return one.serialHex === serials["code-signing"];
    })[0];
    assert.ok(row && row.status === "revoked", JSON.stringify(row));
  });

  // -------------------------------------------------------------------------
  log.info("=== 10. who may be issued a certificate for whom ===");
  const personForOther = await enroll(EST + "/tls-client/simpleenroll",
    (await csrFor("ec-p256", PERSON,
                  [{ kind: "uri", value: "urn:sts:person:" + OTHER }])).der,
    { basic: basic });
  check("a person asking for another person is refused 403", function () {
    refused(personForOther, 403, "person for another person");
  });
  const appForPerson = await enroll(EST + "/tls-client/simpleenroll",
    (await csrFor("ec-p256", APP,
                  [{ kind: "uri", value: "urn:sts:person:" + PERSON }])).der,
    { basic: [APP, APP_SECRET] });
  check("an application asking for a person is refused 403", function () {
    refused(appForPerson, 403, "application for a person");
  });

  // -------------------------------------------------------------------------
  log.info("=== 11. credentials ===");
  const plain = (await csrFor("ec-p256", PERSON, [])).der;
  const noCredential = await enroll(EST + "/simpleenroll", plain);
  check("no credential is 401 with WWW-Authenticate: Basic realm=\"EST\"",
        function () {
          refused(noCredential, 401, "no credential");
          assert.strictEqual(noCredential.headers["www-authenticate"],
                             "Basic realm=\"EST\"");
        });
  const unknownUser = await enroll(EST + "/simpleenroll", plain,
                                   { basic: ["nobody-" + REALM, "x"] });
  check("Basic with an unknown user is refused 401", function () {
    refused(unknownUser, 401, "unknown user");
  });
  const malformedBasic = await enroll(EST + "/simpleenroll", plain,
    { headers: { Authorization: "Basic !!!not-base64" } });
  check("a malformed Basic header is refused 401", function () {
    refused(malformedBasic, 401, "malformed Basic", /malformed/i);
  });
  const bearer = await enroll(EST + "/simpleenroll", plain,
    { headers: { Authorization: "Bearer abc" } });
  check("an Authorization scheme other than Basic is refused 401", function () {
    refused(bearer, 401, "Bearer");
  });
  const inB = await enroll(base + "/realm/" + REALM_B +
                           "/.well-known/est/simpleenroll", plain,
                           { basic: basic });
  check("the person's credential from realm A is refused at realm B",
        function () {
          refused(inB, 401, "a realm A person at realm B");
        });
  const appInB = await enroll(base + "/realm/" + REALM_B +
                              "/.well-known/est/simpleenroll", plain,
                              { basic: [APP, APP_SECRET] });
  check("the application's credential from realm A is refused at realm B",
        function () {
          refused(appInB, 401, "a realm A application at realm B");
        });
  const certInB = await enroll(base + "/realm/" + REALM_B +
                               "/.well-known/est/simplereenroll", renewal.der,
                               { key: renewal.pair.privatePem,
                                 cert: renewedPem });
  check("a client certificate from realm A is refused at realm B", function () {
    refused(certInB, 401, "a realm A certificate at realm B",
            /realm|verify/i);
  });
  const assertionPair = await ok(realmApi + "/pki/issue",
    { identifier: PERSON, target: "person", purpose: "jwt",
      keyAlg: "ec-p256" }, "issued an RFC 7523 key pair to the person");
  const notEnrolled = await enroll(EST + "/simplereenroll", renewal.der,
                                   { key: assertionPair.privateKeyPem,
                                     cert: assertionPair.certificatePem });
  check("a certificate from another use case (an assertion key pair, not " +
        "enrolled) is refused 401", function () {
          refused(notEnrolled, 401, "a certificate EST did not enroll");
        });

  // -------------------------------------------------------------------------
  log.info("=== 12. profiles and names ===");
  for (const refusedProfile of ["root-ca", "intermediate-ca", "issuing-ca",
                                "ocsp-responder", "kdc"]) {
    const r = await enroll(EST + "/" + refusedProfile + "/simpleenroll", plain,
                           { basic: basic });
    check("the " + refusedProfile + " profile is refused 403", function () {
      refused(r, 403, refusedProfile, /never issued/);
    });
  }
  await setIn(realmApi, "est.allowedProfiles",
              "tls-client,tls-server,email");
  try {
    const disallowed = await enroll(EST + "/code-signing/simpleenroll", plain,
                                    { basic: basic });
    check("a profile est.allowedProfiles leaves out is refused 403",
          function () {
            refused(disallowed, 403, "disallowed profile", /allowedProfiles/);
          });
  } finally {
    await resetIn(realmApi, "est.allowedProfiles");
  }
  const unregistered = await enroll(EST + "/tls-server/simpleenroll",
    (await csrFor("ec-p256", PERSON,
                  [{ kind: "dns", value: "not-registered.example.test" }]))
      .der, { basic: basic });
  check("an unregistered DNS name is refused 403", function () {
    refused(unregistered, 403, "unregistered DNS name", /registered/);
  });
  const wrongMail = await enroll(EST + "/email/simpleenroll",
    (await csrFor("ec-p256", PERSON,
                  [{ kind: "email", value: "someone-else@example.test" }]))
      .der, { basic: basic });
  check("an email that is not the entry's is refused 403", function () {
    refused(wrongMail, 403, "email not owned", /mail/);
  });
  const mine = await keys.generateKeyPair("ec-p256");
  const theirs = await keys.generateKeyPair("ec-p256");
  const forged = await x509.certificationRequest({
    subject: "CN=" + PERSON, publicKeyPem: mine.publicPem,
    privateKeyPem: theirs.privatePem });
  const badSignature = await enroll(EST + "/simpleenroll",
                                    Buffer.from(forged.der), { basic: basic });
  check("a CSR whose signature does not verify is refused 400", function () {
    refused(badSignature, 400, "bad proof of possession", /possession/);
  });
  const kemEnroll = await enroll(EST + "/key-encipherment/simpleenroll",
                                 kemCsr, { basic: basic });
  check("an ML-KEM key at /simpleenroll is refused 400 (it cannot prove " +
        "possession)", function () {
          refused(kemEnroll, 400, "KEM key in simpleenroll", /ML-KEM|sign/);
        });
  const kemSigning = await enroll(EST + "/tls-client/serverkeygen", kemCsr,
                                  { basic: basic });
  check("an ML-KEM template for a signing profile is refused 400",
        function () {
          refused(kemSigning, 400, "KEM for tls-client", /key-encipherment/);
        });

  // -------------------------------------------------------------------------
  log.info("=== 13. the request itself ===");
  const oversize = await est.send({ method: "POST",
    url: EST + "/simpleenroll", basic: basic,
    headers: { "Content-Type": "application/pkcs10" },
    body: Buffer.alloc(70000, 0x41) });
  check("a body over est.maxRequestBytes is refused 413", function () {
    refused(oversize, 413, "oversize");
  });
  const wrongType = await est.send({ method: "POST",
    url: EST + "/simpleenroll", basic: basic,
    headers: { "Content-Type": "text/plain" },
    body: est.requestBody(plain) });
  check("a body that is not application/pkcs10 is refused 415", function () {
    refused(wrongType, 415, "wrong media type");
  });
  const badBase64 = await est.send({ method: "POST",
    url: EST + "/simpleenroll", basic: basic,
    headers: { "Content-Type": "application/pkcs10" },
    body: Buffer.from("MIIB@@@@not*base64!", "latin1") });
  check("base64 with illegal characters is refused 400", function () {
    refused(badBase64, 400, "illegal base64", /base64/);
  });
  const badAsn1 = await est.send({ method: "POST",
    url: EST + "/simpleenroll", basic: basic,
    headers: { "Content-Type": "application/pkcs10" },
    body: Buffer.from(Buffer.from("hello, not DER").toString("base64")) });
  check("base64 of something that is not DER is refused 400", function () {
    refused(badAsn1, 400, "malformed ASN.1", /PKCS#10|readable/);
  });
  const withQuery = await est.send({ method: "GET",
                                     url: EST + "/cacerts?x=1" });
  check("a query string is refused 400", function () {
    refused(withQuery, 400, "query string");
  });
  const fullcmc = await enroll(EST + "/fullcmc", plain, { basic: basic });
  check("/fullcmc answers 501", function () {
    refused(fullcmc, 501, "fullcmc", /Full CMC/);
  });
  const unknownLabel = await est.send({ method: "GET",
                                        url: EST + "/no-such-label/cacerts" });
  check("an unknown label answers 404", function () {
    refused(unknownLabel, 404, "unknown label", /label/);
  });
  const wrongMethod = await est.send({ method: "GET",
                                       url: EST + "/simpleenroll" });
  check("GET /simpleenroll is 405 with Allow: POST", function () {
    refused(wrongMethod, 405, "wrong method");
    assert.strictEqual(wrongMethod.headers.allow, "POST");
  });

  // -------------------------------------------------------------------------
  log.info("=== 14. the family disabled, and throttling ===");
  await setIn(realmApi, "est.enabled", false);
  try {
    const off = await est.send({ method: "GET", url: EST + "/cacerts" });
    check("est.enabled=false answers 503", function () {
      refused(off, 503, "disabled", /turned off/);
    });
  } finally {
    await resetIn(realmApi, "est.enabled");
  }
  const onAgain = await est.send({ method: "GET", url: EST + "/cacerts" });
  check("and reset brings it back", function () {
    assert.strictEqual(onAgain.status, 200, text(onAgain));
  });
  await setIn(realmApi, "est.attemptsPerIdentity", 2);
  try {
    const name = "throttled-" + REALM;
    const one = await enroll(EST + "/simpleenroll", plain,
                             { basic: [name, "x"] });
    const two = await enroll(EST + "/simpleenroll", plain,
                             { basic: [name, "x"] });
    const three = await enroll(EST + "/simpleenroll", plain,
                               { basic: [name, "x"] });
    check("after est.attemptsPerIdentity failures the next is 429 with " +
          "Retry-After", function () {
            assert.strictEqual(one.status, 401, text(one));
            assert.strictEqual(two.status, 401, text(two));
            refused(three, 429, "throttled");
            assert.ok(Number(three.headers["retry-after"]) > 0);
          });
  } finally {
    await resetIn(realmApi, "est.attemptsPerIdentity");
  }

  // -------------------------------------------------------------------------
  log.info("=== 15. product mode ===");
  const productApi = base + "/realm/" + REALM_P + "/admin-api";
  const productEst = base + "/realm/" + REALM_P + "/.well-known/est";
  const productPerson = await ok(productApi + "/users/create",
    { username: PERSON, invent: false, credential: "generate",
      attributes: { cn: "EST Product", sn: PERSON, mail: MAIL } },
    "created a person with a generated password in the product realm");
  const productSecret = nodeCrypto.randomBytes(18).toString("base64url");
  await ok(productApi + "/applications/create",
           { identifier: APP, protocols: ["oauth2"],
             fields: { oauthClientId: APP, oauthClientSecret: productSecret } },
           "created the application in the product realm");
  const productPlain = (await csrFor("ec-p256", PERSON, [])).der;
  const wrongPassword = await enroll(productEst + "/simpleenroll",
                                     productPlain,
                                     { basic: [PERSON, "wrong-password"] });
  check("a wrong password in a product-mode realm is refused 401",
        function () {
          refused(wrongPassword, 401, "product wrong password");
        });
  const rightPassword = await enroll(productEst + "/simpleenroll",
                                     productPlain,
                                     { basic: [PERSON,
                                               productPerson.password] });
  check("and the right one is issued", function () {
    issuedCertificate(rightPassword, "product right password");
  });
  const wrongSecret = await enroll(productEst + "/simpleenroll",
    (await csrFor("ec-p256", APP, [])).der, { basic: [APP, "wrong-secret"] });
  check("an application with a wrong secret in product mode is refused 401",
        function () {
          refused(wrongSecret, 401, "product wrong secret");
        });
  if (/^https:/.test(base)) {
    log.info("  (the plain-HTTP refusal is not exercised: the service under " +
             "test is HTTPS, so there is no plain listener to send one to)");
  }

  // -------------------------------------------------------------------------
  log.info("=== 16. the monitor ===");
  const monitor = await send(realmApi + "/est/monitor");
  check("GET /admin-api/est/monitor counts what this job did", function () {
    assert.strictEqual(monitor.status, 200, monitor.raw.slice(0, 200));
    assert.ok(monitor.body.totals.issued >= 12,
              JSON.stringify(monitor.body.totals));
    assert.ok(monitor.body.totals.refused >= 20,
              JSON.stringify(monitor.body.totals));
    const codes = monitor.body.errorCodes.map(function (one) {
      return one.name;
    });
    assert.ok(codes.indexOf("STS-EST-0006") >= 0, JSON.stringify(codes));
    assert.ok(monitor.body.certificates.revoked >= 1);
  });

  assert.ok(checks >= 60, "only " + checks + " checks ran; a section " +
            "stopped being reached");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_est_enrollment")
  .description("EST (RFC 7030) enrollment against the running service.")
  .addOption(new Option("-u, --url <url>", "the STS base URL"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
