"use strict";
//
// File: sts_application_credentials.js
//
// ===========================================================================
// AN APPLICATION'S CREDENTIALS, REPLACED THROUGH /admin-api AND USED AT A REAL
// TOKEN ENDPOINT (2026-09-13).
//
// The Credentials section of `/admin/applications?application=…` shows an
// application's client secret and, per assertion profile, the key pair this
// service manages for it — and replaces that key pair either by issuing one
// from this realm's certificate authority or by uploading a certificate the
// application already holds, which from an external authority must come with
// its full chain. `tests/application_credentials.js` holds the chain rules in
// process; what is here is the half a request can see, and it is the half that
// says the feature works rather than that its functions do:
//
//   * A KEY PAIR ISSUED HERE SIGNS AN ASSERTION THE TOKEN ENDPOINT ACCEPTS —
//     and, once an external certificate has been uploaded in its place, the
//     SAME assertion signed with the OLD key is refused while one signed with
//     the application's OWN key, whose private half this service never saw,
//     is accepted. That pair is the whole claim of "replace".
//   * AN INCOMPLETE CHAIN AND A PASTED PRIVATE KEY ARE REFUSED, AND CHANGE
//     NOTHING: the key pair on the entry afterwards is the one before.
//   * THE READ MODEL SAYS WHERE A KEY PAIR CAME FROM — `issued`,
//     `uploaded-realm-ca`, `uploaded-external-ca` — and carries no secret and
//     no private key in its `credentials` member.
//   * A REGENERATED CLIENT SECRET IS HANDED BACK ONCE, IS WHAT THE ENTRY NOW
//     HOLDS, IS NOT IN THE AUDIT LOG, AND IS WHAT THE TOKEN ENDPOINT CHECKS —
//     in RFC 9700 mode, turned on in this realm only, the old secret is refused
//     `invalid_client` and the new one is accepted.
//
// `local: true`, on `tests/CLAUDE.md`'s first question: the thing under test is
// a control on this repository's own console and its `/admin-api` operation,
// and the assertion spans that door and `/oauth2/token`.
//
// It works in a throwaway trust realm, which it leaves standing — see *No job
// removes a realm* in `tests/CLAUDE.md`.
// ===========================================================================

const assert = require("assert");
const nodeCrypto = require("crypto");
const path = require("path");
const { Command, Option } = require("commander");
const { usernameFor } = require("./random_username.js");

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
var log = bunyan.createLogger({ name: "sts_application_credentials",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

// The debugger's own certificate encoder, which this repository vendors — the
// same file `tests/tools/pep-credential.js` builds a client certificate with.
// It builds the EXTERNAL authority here: a hierarchy this service did not make.
const REPO = process.env.MOCK_STS_DIR || path.join(__dirname, "..", "..");
const x509 = require(path.join(REPO, "common", "vendored", "x509.js"));
const keys = require(path.join(REPO, "common", "vendored",
                               "key_material.js"));

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");
var api = base + "/admin-api";

var REALM = usernameFor("appcreds").replace(/[^a-z0-9-]/g, "").slice(0, 30);
var realmBase = base + "/realm/" + REALM;
var realmApi = realmBase + "/admin-api";
var TOKEN_ENDPOINT = realmBase + "/oauth2/token";

var CLIENT = "appcreds-client";
var SECOND = "appcreds-second";
var ISS = "https://issuer.example.test/appcreds";
var GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer";
var PERSON = usernameFor("appcredsubject");

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

// THIS FILE'S OWN JWS SIGNER, for `sts_dpop.js`'s reason: a shared
// implementation at both ends would make a shared misunderstanding pass. RS256
// for the key pair this service issues, ES256 for the application's own.
function signJws(header, payload, privateKeyPem) {
  log.debug("Entering signJws().");
  const signing = b64u(JSON.stringify(header)) + "." +
                  b64u(JSON.stringify(payload));
  let sig;
  if (header.alg === "RS256") {
    sig = nodeCrypto.sign("sha256", Buffer.from(signing), privateKeyPem);
  } else if (header.alg === "ES256") {
    sig = nodeCrypto.sign("sha256", Buffer.from(signing),
                          { key: privateKeyPem, dsaEncoding: "ieee-p1363" });
  } else {
    throw new Error("this file signs RS256 and ES256; asked for " +
                    header.alg);
  }
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
    // Not JSON — an HTML error page. Quoting it whole says more than a parse
    // failure would.
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

async function get(url) {
  log.debug("Entering get().");
  const r = await send(url);
  log.debug("Leaving get().");
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

function assertion(header, privateKeyPem) {
  log.debug("Entering assertion().");
  log.debug("Leaving assertion().");
  return signJws(header, { iss: ISS, sub: PERSON, aud: TOKEN_ENDPOINT,
                           iat: now(), exp: now() + 120,
                           jti: nodeCrypto.randomUUID() }, privateKeyPem);
}

async function applicationView(identifier) {
  log.debug("Entering applicationView().");
  const r = await get(realmApi + "/applications?application=" +
                      encodeURIComponent(identifier));
  assert.strictEqual(r.status, 200, JSON.stringify(r.body).slice(0, 300));
  const body = r.body.application || r.body;
  log.debug("Leaving applicationView().");
  return body;
}

function keyPairOf(view, purpose) {
  log.debug("Entering keyPairOf().");
  log.debug("Leaving keyPairOf().");
  return ((view.credentials || {}).keyPairs || []).filter(function (one) {
    return one.purpose === purpose;
  })[0] || {};
}

// An external certificate authority, a root and an intermediate, and an EC
// leaf under it whose private key only this job holds.
async function externalHierarchy() {
  log.debug("Entering externalHierarchy().");
  const rootPair = await keys.generateKeyPair("rsa-2048");
  const root = await x509.issueCertificate({
    subject: [{ name: "CN", value: "Appcreds External Root" }],
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
    subject: [{ name: "CN", value: "Appcreds External Intermediate" }],
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
  const leafPair = await keys.generateKeyPair("ec-p256");
  const leaf = await x509.issueCertificate({
    subject: [{ name: "CN", value: CLIENT }],
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
  log.info("=== 0. a realm, a certificate authority, an application ===");
  await ok(api + "/realms/create", { id: REALM,
                                     domain: REALM + ".example.net",
                                     name: "Application credentials" },
           "created the trust realm");
  await ok(realmApi + "/pki/build", { organisation: "Appcreds", country: "US" },
           "built a certificate authority");
  await ok(realmApi + "/applications/create",
           { identifier: CLIENT, protocols: ["oauth2"],
             fields: { oauthClientId: CLIENT,
                       oauthClientSecret: CLIENT + "-secret-" + REALM,
                       oauthTokenEndpointAuthMethod: "client_secret_post" } },
           "created the application");
  await ok(realmApi + "/applications/create",
           { identifier: SECOND, protocols: ["oauth2"],
             fields: { oauthClientId: SECOND } },
           "created a second application");
  await ok(realmApi + "/users/create",
           { username: PERSON, invent: false, credential: "none",
             attributes: { cn: "Appcreds Subject", sn: PERSON,
                           mail: PERSON + "@appcreds.test" } },
           "created the person the assertions are about");
  await ok(realmApi + "/applications/add",
           { application: CLIENT, attribute: "oauthAssertionIssuer",
             value: ISS }, "declared the assertion issuer");

  // -------------------------------------------------------------------------
  log.info("=== 1. a key pair issued from this realm's CA ===");
  const issued = await ok(realmApi + "/pki/issue",
                          { identifier: CLIENT, purpose: "jwt" },
                          "issued a key pair");
  let view = await applicationView(CLIENT);
  const issuedPrivate = view.fields.oauthAssertionPrivateKey;
  const issuedPair = keyPairOf(view, "jwt");
  check("the read model says the JWT key pair was ISSUED here and that this " +
        "service holds its private half", function () {
          assert.strictEqual(issuedPair.source, "issued",
            JSON.stringify(issuedPair).slice(0, 300));
          assert.strictEqual(issuedPair.privateKeyHeld, true);
          assert.strictEqual(issuedPair.handle, issued.kid);
          assert.ok(/BEGIN PRIVATE KEY/.test(issuedPrivate || ""),
            "no private key on the entry to sign with");
        });
  const withIssued = await tokenRequest({ grant_type: GRANT,
    assertion: assertion({ alg: "RS256", typ: "JWT", kid: issued.kid },
                         issuedPrivate) });
  check("an assertion signed with it is accepted at the token endpoint",
        function () {
          assert.strictEqual(withIssued.status, 200,
            JSON.stringify(withIssued.body).slice(0, 400));
        });

  // -------------------------------------------------------------------------
  log.info("=== 2. uploads that are refused, and change nothing ===");
  const ext = await externalHierarchy();
  const incomplete = await post(realmApi + "/pki/upload-certificate",
    { identifier: CLIENT, purpose: "jwt", certificate: ext.leafPem,
      chain: ext.interPem });
  check("an external certificate WITHOUT its root is refused 400 as an " +
        "incomplete chain, naming the root that is missing", function () {
          assert.strictEqual(incomplete.status, 400,
            JSON.stringify(incomplete.body).slice(0, 300));
          const said = (incomplete.body.errors || []).join(" ");
          assert.ok(/incomplete/.test(said) &&
                    /Appcreds External Root/.test(said), said);
        });
  const withKey = await post(realmApi + "/pki/upload-certificate",
    { identifier: CLIENT, purpose: "jwt",
      certificate: ext.leafPem + ext.leafPrivatePem,
      chain: ext.interPem + ext.rootPem });
  check("an upload carrying a PRIVATE KEY is refused 400 and says to treat " +
        "the key as exposed", function () {
          assert.strictEqual(withKey.status, 400);
          assert.ok(/exposed/.test((withKey.body.errors || []).join(" ")),
            JSON.stringify(withKey.body).slice(0, 300));
          assert.ok(JSON.stringify(withKey.body)
                      .indexOf("BEGIN PRIVATE KEY") < 0,
            "the refusal echoed the private key back");
        });
  view = await applicationView(CLIENT);
  check("and after both refusals the entry still holds the ISSUED key pair",
        function () {
          assert.strictEqual(keyPairOf(view, "jwt").source, "issued");
          assert.strictEqual(view.fields.oauthAssertionKid, issued.kid);
        });

  // -------------------------------------------------------------------------
  log.info("=== 3. an external certificate with its full chain ===");
  const uploaded = await ok(realmApi + "/pki/upload-certificate",
    { identifier: CLIENT, purpose: "jwt", certificate: ext.leafPem,
      // Root FIRST — the chain is built by issuer, not by order.
      chain: ext.rootPem + ext.interPem },
    "uploaded the external certificate");
  check("the upload is accepted as an EXTERNAL authority's, with the chain it " +
        "was checked through named", function () {
          assert.strictEqual(uploaded.source, "uploaded-external-ca");
          assert.deepStrictEqual(uploaded.chain,
            ["CN=Appcreds External Intermediate",
             "CN=Appcreds External Root"]);
        });
  view = await applicationView(CLIENT);
  const extPair = keyPairOf(view, "jwt");
  check("THE ISSUED KEY PAIR IS GONE: the read model says uploaded, holds no " +
        "private key, and the chain beside the certificate is two long",
        function () {
          assert.strictEqual(extPair.source, "uploaded-external-ca");
          assert.strictEqual(extPair.privateKeyHeld, false);
          assert.strictEqual((extPair.chain || []).length, 2);
          assert.ok(!view.fields.oauthAssertionPrivateKey,
            "a private key is still on the entry");
          assert.strictEqual(extPair.handle, uploaded.kid);
        });
  check("the credentials member carries no private key and no client secret",
        function () {
          const text = JSON.stringify(view.credentials);
          assert.ok(text.indexOf("PRIVATE KEY") < 0, "a private key leaked");
          assert.ok(text.indexOf(CLIENT + "-secret-") < 0, "a secret leaked");
        });

  const oldKey = await tokenRequest({ grant_type: GRANT,
    assertion: assertion({ alg: "RS256", typ: "JWT", kid: issued.kid },
                         issuedPrivate) });
  check("AN ASSERTION SIGNED WITH THE REPLACED KEY IS NOW REFUSED " +
        "invalid_grant", function () {
          assert.strictEqual(oldKey.status, 400,
            JSON.stringify(oldKey.body).slice(0, 300));
          assert.strictEqual(oldKey.body.error, "invalid_grant");
        });
  const ownKey = await tokenRequest({ grant_type: GRANT,
    assertion: assertion({ alg: "ES256", typ: "JWT", kid: uploaded.kid },
                         ext.leafPrivatePem) });
  check("AND ONE SIGNED WITH THE APPLICATION'S OWN KEY — whose private half " +
        "this service never saw — IS ACCEPTED", function () {
          assert.strictEqual(ownKey.status, 200,
            JSON.stringify(ownKey.body).slice(0, 400));
          assert.ok(ownKey.body.access_token);
        });

  // -------------------------------------------------------------------------
  log.info("=== 4. this realm's own certificate, uploaded alone ===");
  const secondIssued = await ok(realmApi + "/pki/issue",
                                { identifier: SECOND, purpose: "saml" },
                                "issued a SAML key pair to the second app");
  const second = await applicationView(SECOND);
  const realmUpload = await ok(realmApi + "/pki/upload-certificate",
    { identifier: CLIENT, purpose: "saml",
      certificate: second.fields.oauthSamlAssertionCertificate },
    "uploaded this realm's certificate alone");
  check("a certificate this realm's authority issued needs no chain uploaded " +
        "and is recorded as uploaded-realm-ca", function () {
          assert.strictEqual(realmUpload.source, "uploaded-realm-ca");
          assert.strictEqual(realmUpload.thumbprint, secondIssued.thumbprint);
        });
  view = await applicationView(CLIENT);
  check("and the SAML key pair it replaced is on its own attribute set, the " +
        "JWT one untouched", function () {
          assert.strictEqual(keyPairOf(view, "saml").source,
                             "uploaded-realm-ca");
          assert.strictEqual(keyPairOf(view, "jwt").source,
                             "uploaded-external-ca");
        });

  // -------------------------------------------------------------------------
  log.info("=== 5. the client secret ===");
  const oldSecret = CLIENT + "-secret-" + REALM;
  const regenerated = await ok(realmApi + "/applications/regenerate-secret",
                               { application: CLIENT },
                               "regenerated the client secret");
  const newSecret = regenerated.clientSecret;
  check("the reply hands back a NEW secret, once, and says it replaced one",
        function () {
          assert.ok(newSecret && newSecret !== oldSecret,
            JSON.stringify(regenerated).slice(0, 200));
          assert.strictEqual(regenerated.replaced, true);
        });
  view = await applicationView(CLIENT);
  check("the entry now holds the new secret", function () {
    assert.strictEqual(view.fields.oauthClientSecret, newSecret);
  });
  const auditRows = await get(realmApi + "/audit?per=200");
  check("and the new secret is nowhere in the audit log", function () {
    assert.strictEqual(auditRows.status, 200);
    assert.ok(auditRows.raw.indexOf(newSecret) < 0,
      "the regenerated secret appears in GET /admin-api/audit");
  });

  await ok(realmApi + "/config/set", { key: "oauth2.rfc9700", value: "true" },
           "turned RFC 9700 mode on in this realm");
  try {
    const withOld = await tokenRequest({ grant_type: "client_credentials",
      client_id: CLIENT, client_secret: oldSecret });
    check("IN RFC 9700 MODE THE OLD SECRET IS REFUSED invalid_client",
          function () {
            assert.ok(withOld.status === 400 || withOld.status === 401,
              JSON.stringify(withOld.body).slice(0, 300));
            assert.strictEqual(withOld.body.error, "invalid_client",
              JSON.stringify(withOld.body).slice(0, 300));
          });
    const withNew = await tokenRequest({ grant_type: "client_credentials",
      client_id: CLIENT, client_secret: newSecret });
    check("and the regenerated one is accepted", function () {
      assert.strictEqual(withNew.status, 200,
        JSON.stringify(withNew.body).slice(0, 300));
    });
  } finally {
    // `reset` and not a second `set` — see tests/CLAUDE.md.
    await post(realmApi + "/config/reset", { key: "oauth2.rfc9700" });
  }

  const unknown = await post(realmApi + "/applications/regenerate-secret",
                             { application: CLIENT + "-absent" });
  check("an application that is not in the registry is refused 400",
        function () {
          assert.strictEqual(unknown.status, 400);
        });

  assert.ok(checks >= 18,
    "only " + checks + " checks ran; a section has stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_application_credentials")
  .description("An application's credentials replaced through /admin-api " +
      "and used at a real token endpoint: a key pair issued from the " +
      "realm's CA signing an accepted assertion, an external certificate " +
      "with its full chain uploaded in its place (the old key refused, the " +
      "application's own accepted), an incomplete chain and a pasted private " +
      "key refused with nothing changed, this realm's own certificate " +
      "uploaded alone, and a regenerated client secret checked in RFC 9700 " +
      "mode.")
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
