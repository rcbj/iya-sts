"use strict";
//
// File: sts_user_credentials.js
//
// ===========================================================================
// A PERSON'S RFC 7523 AND RFC 7522 KEY PAIRS, REPLACED THROUGH /admin-api AND
// USED AT A REAL TOKEN ENDPOINT (2026-09-13).
//
// The Credentials section of `/admin/users?user=…` shows the key pairs on a
// person's own entry — one for RFC 7523's JWT bearer grant, one for RFC 7522's
// SAML 2.0 bearer grant — and replaces either by issuing one from this realm's
// certificate authority or by uploading a certificate the person already
// holds, which from an external authority must come with its full chain.
// `tests/person_credentials.js` holds the register and the rules in process;
// what is here is the half that says the feature WORKS:
//
//   * AN RFC 7522 KEY PAIR ISSUED TO A PERSON SIGNS A SAML ASSERTION THE TOKEN
//     ENDPOINT ACCEPTS — about that person, and about nobody else. Until this
//     date a person could not hold one at all; the refusal is retired.
//   * THE PERSON'S RFC 7523 KEY PAIR DOES NOT SIGN FOR RFC 7522, which is the
//     crossing `tests/vendored/sts_saml2_bearer_grant.js` already asserts for
//     an application.
//   * AN EXTERNAL CERTIFICATE WITH ITS FULL CHAIN REPLACES A PERSON'S KEY PAIR:
//     the key the service issued before is refused afterwards and the key the
//     person holds is accepted. An incomplete chain changes nothing.
//   * A CERTIFICATE THIS REALM ISSUED TO AN APPLICATION IS REFUSED FOR A
//     PERSON, and the person's own is accepted alone — after which the person
//     still signs with the key they were given and this service holds none.
//   * `GET /admin-api/users?user=` ANSWERS `credentials` WITH NO PRIVATE KEY,
//     and taking one profile off leaves the other working at the endpoint.
//
// `local: true`, on `tests/CLAUDE.md`'s first question: the controls are this
// repository's own console and `/admin-api`, and the assertion spans those
// doors and `/oauth2/token`. It works in a throwaway trust realm, which it
// leaves standing.
// ===========================================================================

const assert = require("assert");
const nodeCrypto = require("crypto");
const path = require("path");
const { Command, Option } = require("commander");
const { usernameFor } = require("./random_username.js");
// This suite's own XML Signature — canonical by construction — so a document
// built by the module that verifies it is never what is under test.
const signer = require("./saml_xmldsig.js");

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
var log = bunyan.createLogger({ name: "sts_user_credentials",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

// The debugger's own certificate encoder, for the EXTERNAL authority.
const REPO = process.env.MOCK_STS_DIR || path.join(__dirname, "..", "..");
const x509 = require(path.join(REPO, "common", "vendored", "x509.js"));
const keys = require(path.join(REPO, "common", "vendored",
                               "key_material.js"));

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");
var api = base + "/admin-api";

var REALM = usernameFor("usercreds").replace(/[^a-z0-9-]/g, "").slice(0, 30);
var realmBase = base + "/realm/" + REALM;
var realmApi = realmBase + "/admin-api";
var TOKEN_ENDPOINT = realmBase + "/oauth2/token";

var PERSON = usernameFor("usercredalice");
var OTHER = usernameFor("usercredbob");
var APP = "usercreds-app";
var JWT_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer";
var SAML_GRANT = "urn:ietf:params:oauth:grant-type:saml2-bearer";

var checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  ✓ " + what);
  log.debug("Leaving check().");
}

function b64u(buf) {
  log.debug("Entering b64u().");
  log.debug("Leaving b64u().");
  return Buffer.from(buf).toString("base64url");
}

// THIS FILE'S OWN JWS SIGNER, for `sts_dpop.js`'s reason.
function signJws(header, payload, privateKeyPem) {
  log.debug("Entering signJws().");
  const signing = b64u(JSON.stringify(header)) + "." +
                  b64u(JSON.stringify(payload));
  const sig = nodeCrypto.sign("sha256", Buffer.from(signing), privateKeyPem);
  log.debug("Leaving signJws().");
  return signing + "." + b64u(sig);
}

function now() {
  log.debug("Entering now().");
  log.debug("Leaving now().");
  return Math.floor(Date.now() / 1000);
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

async function tokenRequest(fields) {
  log.debug("Entering tokenRequest().");
  const r = await send(TOKEN_ENDPOINT, { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(fields).toString() });
  log.debug("Leaving tokenRequest().");
  return r;
}

async function jwtGrant(iss, sub, kid, privateKeyPem) {
  log.debug("Entering jwtGrant().");
  const r = await tokenRequest({ grant_type: JWT_GRANT,
    assertion: signJws({ alg: "RS256", typ: "JWT", kid: kid },
                       { iss: iss, sub: sub, aud: TOKEN_ENDPOINT, iat: now(),
                         exp: now() + 120, jti: nodeCrypto.randomUUID() },
                       privateKeyPem) });
  log.debug("Leaving jwtGrant().");
  return r;
}

async function samlGrant(iss, sub, privateKeyPem, certificatePem) {
  log.debug("Entering samlGrant().");
  const built = signer.buildAssertion({ issuer: iss, subject: sub,
                                        audience: TOKEN_ENDPOINT,
                                        recipient: TOKEN_ENDPOINT });
  const r = await tokenRequest({ grant_type: SAML_GRANT,
    assertion: signer.b64u(signer.sign(built, privateKeyPem,
                                       certificatePem || "", {})) });
  log.debug("Leaving samlGrant().");
  return r;
}

async function credentialsOf(username) {
  log.debug("Entering credentialsOf().");
  const r = await send(realmApi + "/users?user=" +
                       encodeURIComponent(username));
  assert.strictEqual(r.status, 200, JSON.stringify(r.body).slice(0, 300));
  const byPurpose = {};
  (((r.body || {}).credentials || {}).keyPairs || []).forEach(function (one) {
    byPurpose[one.purpose] = one;
  });
  log.debug("Leaving credentialsOf().");
  return { raw: JSON.stringify((r.body || {}).credentials || null),
           jwt: byPurpose.jwt || {}, saml: byPurpose.saml || {} };
}

// An external certificate authority — a root and an intermediate — and an RSA
// leaf under it whose private key only this job holds. RSA because this
// suite's XML signer signs RSA-SHA256.
async function externalHierarchy() {
  log.debug("Entering externalHierarchy().");
  const rootPair = await keys.generateKeyPair("rsa-2048");
  const root = await x509.issueCertificate({
    subject: [{ name: "CN", value: "Usercreds External Root" }],
    subjectPublicKey: rootPair.publicPem, signatureAlg: "sha256-rsa",
    profile: "root-ca",
    issuer: { privateKeyPem: rootPair.privatePem, keyAlg: "rsa-2048" },
    extensions: {
      basicConstraints: { present: true, critical: true, ca: true,
                          pathLen: null },
      keyUsage: { present: true, critical: true,
                  usages: ["keyCertSign", "cRLSign"] }
    }
  });
  const interPair = await keys.generateKeyPair("rsa-2048");
  const inter = await x509.issueCertificate({
    subject: [{ name: "CN", value: "Usercreds External Intermediate" }],
    subjectPublicKey: interPair.publicPem, signatureAlg: "sha256-rsa",
    profile: "intermediate-ca",
    issuer: { certificatePem: root.pem, privateKeyPem: rootPair.privatePem,
              keyAlg: "rsa-2048" },
    extensions: {
      basicConstraints: { present: true, critical: true, ca: true,
                          pathLen: 0 },
      keyUsage: { present: true, critical: true,
                  usages: ["keyCertSign", "cRLSign"] }
    }
  });
  const leafPair = await keys.generateKeyPair("rsa-2048");
  const leaf = await x509.issueCertificate({
    subject: [{ name: "CN", value: PERSON }],
    subjectPublicKey: leafPair.publicPem, signatureAlg: "sha256-rsa",
    profile: "digital-signature",
    issuer: { certificatePem: inter.pem,
              privateKeyPem: interPair.privatePem, keyAlg: "rsa-2048" },
    extensions: {
      basicConstraints: { present: true, critical: true, ca: false },
      keyUsage: { present: true, critical: true,
                  usages: ["digitalSignature"] }
    }
  });
  log.debug("Leaving externalHierarchy().");
  return { rootPem: root.pem, interPem: inter.pem, leafPem: leaf.pem,
           leafPrivatePem: leafPair.privatePem };
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving " + base + " in the trust realm \"" + REALM + "\".");

  // -------------------------------------------------------------------------
  log.info("=== 0. a realm, a certificate authority, two people ===");
  await ok(api + "/realms/create", { id: REALM, name: "User credentials" },
           "created the trust realm");
  await ok(realmApi + "/pki/build", { organisation: "Usercreds",
                                      country: "US" },
           "built a certificate authority");
  await ok(realmApi + "/users/create",
           { username: PERSON, invent: false, credential: "none",
             attributes: { cn: "Usercreds Alice", sn: PERSON } },
           "created the person");
  await ok(realmApi + "/users/create",
           { username: OTHER, invent: false, credential: "none",
             attributes: { cn: "Usercreds Bob", sn: OTHER } },
           "created a second person");
  await ok(realmApi + "/applications/create",
           { identifier: APP, protocols: ["oauth2"],
             fields: { oauthClientId: APP } },
           "created an application to issue a certificate to");

  // -------------------------------------------------------------------------
  log.info("=== 1. an RFC 7522 key pair issued to a person ===");
  const samlIssued = await ok(realmApi + "/pki/issue",
    { identifier: PERSON, target: "person", purpose: "saml",
      keyAlg: "rsa-2048" }, "issued an RFC 7522 key pair to a PERSON");
  check("the reply carries the private key once, a thumbprint and no JWKS",
        function () {
          assert.ok(/PRIVATE KEY/.test(samlIssued.privateKeyPem || ""),
            JSON.stringify(samlIssued).slice(0, 300));
          assert.ok(samlIssued.thumbprint && !samlIssued.jwks);
        });
  let creds = await credentialsOf(PERSON);
  check("GET /admin-api/users?user= reads it as ISSUED, with the private key " +
        "HELD and not carried", function () {
          assert.strictEqual(creds.saml.held, true, creds.raw.slice(0, 300));
          assert.strictEqual(creds.saml.source, "issued");
          assert.strictEqual(creds.saml.privateKeyHeld, true);
          assert.strictEqual(creds.saml.handle, samlIssued.thumbprint);
          assert.strictEqual(creds.jwt.held, false);
          assert.ok(creds.raw.indexOf("PRIVATE KEY") < 0,
            "a private key is in the credentials member");
        });
  const samlSelf = await samlGrant(PERSON, PERSON, samlIssued.privateKeyPem,
                                   samlIssued.certificatePem);
  check("A SAML ASSERTION THE PERSON SIGNED ABOUT THEMSELVES IS ACCEPTED at " +
        "the token endpoint", function () {
          assert.strictEqual(samlSelf.status, 200,
            JSON.stringify(samlSelf.body).slice(0, 400));
          assert.ok(samlSelf.body.access_token);
        });
  const samlOther = await samlGrant(PERSON, OTHER, samlIssued.privateKeyPem,
                                    samlIssued.certificatePem);
  check("and one naming SOMEBODY ELSE as <Subject> is refused invalid_grant, " +
        "saying why", function () {
          assert.strictEqual(samlOther.status, 400);
          assert.strictEqual(samlOther.body.error, "invalid_grant");
          assert.ok(/only be about themselves/
                      .test(samlOther.body.error_description || ""),
            JSON.stringify(samlOther.body).slice(0, 300));
        });

  // -------------------------------------------------------------------------
  log.info("=== 2. the RFC 7523 key pair beside it ===");
  const jwtIssued = await ok(realmApi + "/pki/issue",
    { identifier: PERSON, target: "person", purpose: "jwt",
      keyAlg: "rsa-2048" }, "issued an RFC 7523 key pair to the person");
  const jwtSelf = await jwtGrant(PERSON, PERSON, jwtIssued.kid,
                                 jwtIssued.privateKeyPem);
  check("a JWT the person signed about themselves is accepted", function () {
    assert.strictEqual(jwtSelf.status, 200,
      JSON.stringify(jwtSelf.body).slice(0, 400));
  });
  const crossed = await samlGrant(PERSON, PERSON, jwtIssued.privateKeyPem,
                                  jwtIssued.certificatePem);
  check("THE RFC 7523 KEY DOES NOT SIGN A SAML ASSERTION for the same person",
        function () {
          assert.strictEqual(crossed.status, 400,
            JSON.stringify(crossed.body).slice(0, 300));
          assert.strictEqual(crossed.body.error, "invalid_grant");
        });
  creds = await credentialsOf(PERSON);
  check("and the read model holds two key pairs, one per profile", function () {
    assert.strictEqual(creds.jwt.source, "issued");
    assert.strictEqual(creds.saml.source, "issued");
  });

  // -------------------------------------------------------------------------
  log.info("=== 3. an external certificate replaces the SAML key pair ===");
  const ext = await externalHierarchy();
  const incomplete = await post(realmApi + "/pki/upload-certificate",
    { identifier: PERSON, target: "person", purpose: "saml",
      certificate: ext.leafPem, chain: ext.interPem });
  check("without its root it is refused 400 as an incomplete chain",
        function () {
          assert.strictEqual(incomplete.status, 400,
            JSON.stringify(incomplete.body).slice(0, 300));
          assert.ok(/incomplete/
                      .test((incomplete.body.errors || []).join(" ")));
        });
  creds = await credentialsOf(PERSON);
  check("and the entry still holds the issued SAML key pair", function () {
    assert.strictEqual(creds.saml.source, "issued");
  });
  const uploaded = await ok(realmApi + "/pki/upload-certificate",
    { identifier: PERSON, target: "person", purpose: "saml",
      certificate: ext.leafPem, chain: ext.rootPem + ext.interPem },
    "uploaded the external certificate for the person");
  check("the upload is accepted as an external authority's, through the " +
        "chain it names", function () {
          assert.strictEqual(uploaded.source, "uploaded-external-ca");
          assert.deepStrictEqual(uploaded.chain,
            ["CN=Usercreds External Intermediate",
             "CN=Usercreds External Root"]);
        });
  creds = await credentialsOf(PERSON);
  check("THE ISSUED SAML PRIVATE KEY IS GONE and the chain is two long; the " +
        "JWT key pair is untouched", function () {
          assert.strictEqual(creds.saml.source, "uploaded-external-ca");
          assert.strictEqual(creds.saml.privateKeyHeld, false);
          assert.strictEqual((creds.saml.chain || []).length, 2);
          assert.strictEqual(creds.jwt.source, "issued");
        });
  const oldSaml = await samlGrant(PERSON, PERSON, samlIssued.privateKeyPem,
                                  "");
  check("AN ASSERTION SIGNED WITH THE REPLACED KEY IS REFUSED", function () {
    assert.strictEqual(oldSaml.status, 400,
      JSON.stringify(oldSaml.body).slice(0, 300));
  });
  const ownSaml = await samlGrant(PERSON, PERSON, ext.leafPrivatePem,
                                  ext.leafPem);
  check("AND ONE SIGNED WITH THE KEY THE PERSON HOLDS — whose private half " +
        "this service never saw — IS ACCEPTED", function () {
          assert.strictEqual(ownSaml.status, 200,
            JSON.stringify(ownSaml.body).slice(0, 400));
        });

  // -------------------------------------------------------------------------
  log.info("=== 4. this realm's certificates, and whose they are ===");
  await ok(realmApi + "/pki/issue", { identifier: APP, purpose: "jwt" },
           "issued a key pair to the application");
  const appView = await send(realmApi + "/applications?application=" +
                             encodeURIComponent(APP));
  const appCert = ((appView.body.application || appView.body).fields || {})
    .oauthAssertionCertificate;
  const asApp = await post(realmApi + "/pki/upload-certificate",
    { identifier: PERSON, target: "person", purpose: "jwt",
      certificate: appCert });
  check("AN APPLICATION'S CERTIFICATE FROM THIS REALM IS REFUSED FOR A " +
        "PERSON, naming whom it was issued to", function () {
          assert.strictEqual(asApp.status, 400,
            JSON.stringify(asApp.body).slice(0, 300));
          assert.ok(/urn:sts:application:/
                      .test((asApp.body.errors || []).join(" ")));
        });
  const ownUpload = await ok(realmApi + "/pki/upload-certificate",
    { identifier: PERSON, target: "person", purpose: "jwt",
      certificate: jwtIssued.certificatePem },
    "uploaded the person's own certificate from this realm alone");
  check("the person's own certificate is accepted alone, as this realm's",
        function () {
          assert.strictEqual(ownUpload.source, "uploaded-realm-ca");
        });
  creds = await credentialsOf(PERSON);
  check("and now this service holds no JWT private key for them", function () {
    assert.strictEqual(creds.jwt.source, "uploaded-realm-ca");
    assert.strictEqual(creds.jwt.privateKeyHeld, false);
  });
  const stillSigns = await jwtGrant(PERSON, PERSON, ownUpload.kid,
                                    jwtIssued.privateKeyPem);
  check("THE PERSON STILL SIGNS WITH THE KEY THEY WERE GIVEN, verified " +
        "against the certificate they registered", function () {
          assert.strictEqual(stillSigns.status, 200,
            JSON.stringify(stillSigns.body).slice(0, 400));
        });

  // -------------------------------------------------------------------------
  log.info("=== 5. one profile taken off ===");
  await ok(realmApi + "/pki/revoke",
           { identifier: PERSON, target: "person", purpose: "saml" },
           "took the RFC 7522 key pair off the person");
  creds = await credentialsOf(PERSON);
  const samlGone = await samlGrant(PERSON, PERSON, ext.leafPrivatePem,
                                   ext.leafPem);
  const jwtStays = await jwtGrant(PERSON, PERSON, ownUpload.kid,
                                  jwtIssued.privateKeyPem);
  check("THE SAML ASSERTION IS REFUSED AND THE JWT ONE STILL ACCEPTED — " +
        "taking one profile off leaves the other", function () {
          assert.strictEqual(creds.saml.held, false);
          assert.strictEqual(samlGone.status, 400,
            JSON.stringify(samlGone.body).slice(0, 300));
          assert.strictEqual(jwtStays.status, 200,
            JSON.stringify(jwtStays.body).slice(0, 300));
        });

  assert.ok(checks >= 18,
    "only " + checks + " checks ran; a section has stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_user_credentials")
  .description("A person's RFC 7523 and RFC 7522 key pairs replaced through " +
      "/admin-api and used at a real token endpoint: an RFC 7522 key pair " +
      "signing an accepted SAML assertion about the person and a refused one " +
      "about somebody else, the JWT key refused for SAML, an external " +
      "certificate with its full chain replacing the SAML key pair, an " +
      "application's certificate refused for a person and the person's own " +
      "accepted alone, and one profile taken off leaving the other.")
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
