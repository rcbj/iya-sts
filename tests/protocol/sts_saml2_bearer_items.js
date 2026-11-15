// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_saml2_bearer_items.js
//
// ===========================================================================
// RFC 7522 SECTION 3, ITEM BY ITEM, AT A RUNNING TOKEN ENDPOINT (#444 D12,
// phase 7).
//
// `tests/saml_assertion_grant.js` holds the eleven items as a table against
// the module's `verify()`. `sts_saml2_bearer_grant.js` (vendored) carries the
// grant over HTTP with a handful of the refusals. Here EVERY row of that
// table is a token request to a realm of the job's own — an assertion
// built and signed by `saml_xmldsig.js`, this repository's second XML
// Signature implementation — and each refusal must be `invalid_grant` whose
// error_description names the RULE (the phrase, not the wording):
//
//   T. items 1, 2 (another audience; no Conditions), 3 (no Subject; no
//      NameID), 4 (no expiry anywhere), 5 (holder-of-key; another Recipient;
//      no Recipient), 6 (expired; not yet valid; the only confirmation
//      expired; an expiry unreasonably far off), 9 (a digest that does not
//      match; a stranger's key), 11 (a Condition nothing understands), a
//      Version that is not 2.0, an ID of blanks.
//   L. the two items whose lenient reading is the usual bug: item 4 — an
//      expiry on the SubjectConfirmationData ALONE, and on the Conditions
//      alone with no SubjectConfirmationData; item 6 — an expired
//      SubjectConfirmation is DISCARDED and the live one beside it used.
//   R. a certificate REGISTERED under `oauthSamlAssertionSigningCertificate`
//      (not one this realm issued) verifies; the same ID a second time is
//      refused ("used already").
//   V. STS-PKI-0129: a certificate this realm's CA issued (a person's RFC
//      7522 key pair), REGISTERED by value on an application entry, verifies
//      until the person's key pair is revoked onto the realm's CRL, and is
//      then refused — the registered-certificate code, off the audit log.
//
// NOT HERE: item 3B (a Subject that is not the client, section 2.2) and the
// crossing of the RFC 7523 key pair, which the vendored job asks over HTTP;
// the attribute sets' disjointness and the module's source (a property of
// the code, class (d)); `decode()` and `read()` as functions.
//
// OWNED HERE (local: true). Its realm is removed only on a private probe.
// ===========================================================================

const assert = require("assert");
const nodeCrypto = require("crypto");
const forge = require("node-forge");
const K = require("./oauth_wire_kit.js").kit("sts_saml2_bearer_items");
const saml = require("./saml_xmldsig.js");

const log = K.log;
const GRANT = "urn:ietf:params:oauth:grant-type:saml2-bearer";
const BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
const ISS = "https://issuer-" + K.STAMP + ".example/saml";
const ISS_REG = "https://registered-" + K.STAMP + ".example/saml";
const ISS_DARK = "https://dark-" + K.STAMP + ".example/saml";
let R = null;
let TOKEN = "";
let PERSON = "";

async function token(assertion) {
  log.debug("Entering token().");
  const r = await K.send(TOKEN, { form: { grant_type: GRANT,
                                          assertion: assertion } });
  log.debug("Leaving token(). " + r.status);
  return r;
}

function assertionFor(build, signOpts, keys) {
  log.debug("Entering assertionFor().");
  const k = keys || {};
  const doc = saml.buildAssertion(Object.assign({ issuer: ISS,
    subject: PERSON, audience: TOKEN, recipient: TOKEN }, build || {}));
  const xml = saml.sign(doc, k.key, k.cert === null ? "" : k.cert,
                        signOpts || {});
  log.debug("Leaving assertionFor().");
  return saml.b64u(xml);
}

// A self-signed RSA certificate.
function selfSigned(cn) {
  log.debug("Entering selfSigned(). " + cn);
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = "01" + nodeCrypto.randomBytes(8).toString("hex");
  cert.validity.notBefore = new Date(Date.now() - 60000);
  cert.validity.notAfter = new Date(Date.now() + 30 * 86400000);
  const name = [{ name: "commonName", value: cn }];
  cert.setSubject(name);
  cert.setIssuer(name);
  cert.setExtensions([{ name: "basicConstraints", cA: false },
    { name: "keyUsage", digitalSignature: true, critical: true }]);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  log.debug("Leaving selfSigned().");
  return { cert: forge.pki.certificateToPem(cert),
           key: forge.pki.privateKeyToPem(keys.privateKey) };
}

function refusedNaming(label, r, phrase) {
  log.debug("Entering refusedNaming().");
  K.check(label + " is refused invalid_grant, naming the rule (\"" +
          phrase + "\")", function () {
    assert.strictEqual(r.status, 400, K.shown(r));
    assert.strictEqual((r.json || {}).error, "invalid_grant", r.text);
    assert.ok(String((r.json || {}).error_description || "")
      .indexOf(phrase) >= 0, r.text.slice(0, 400));
  });
  log.debug("Leaving refusedNaming().");
}

function granted(label, r) {
  log.debug("Entering granted().");
  K.check(label, function () {
    assert.strictEqual(r.status, 200, K.shown(r));
    assert.ok(r.json && r.json.access_token, r.text.slice(0, 300));
  });
  log.debug("Leaving granted().");
}

async function setup() {
  log.debug("Entering setup().");
  R = await K.realm("s2b-items", "development");
  TOKEN = K.rb(R) + "/oauth2/token";
  PERSON = "s2b-" + K.STAMP;
  await K.ok(K.rb(R) + "/admin-api/pki/build", { organisation:
    "SAML items " + K.STAMP, country: "US" }, "built a CA");
  const client = "s2b-client-" + K.STAMP;
  await K.ok(K.rb(R) + "/admin-api/applications/create",
    { identifier: client, protocols: ["oauth2", "oidc"],
      fields: { oauthClientId: client,
                oauthClientSecret: client + "-secret",
                oauthTokenEndpointAuthMethod: "client_secret_post" } },
    "created the asserting application");
  await K.person(R, PERSON, "S2b-Passw0rd!-" + K.rand(3));
  await K.ok(K.rb(R) + "/admin-api/pki/issue",
             { identifier: client, purpose: "saml" },
             "issued the RFC 7522 key pair");
  const view = await K.send(K.rb(R) + "/admin-api/applications?application=" +
                            encodeURIComponent(client));
  const fields = ((view.json || {}).application || view.json || {}).fields ||
                 {};
  const secret = await K.ok(K.rb(R) +
    "/admin-api/applications/reveal-secret", { application: client,
    secret: "oauthSamlAssertionPrivateKey" }, "revealed the key");
  await K.ok(K.rb(R) + "/admin-api/applications/add", { application: client,
    attribute: "oauthSamlAssertionIssuer", value: ISS },
  "declared the issuer");
  log.debug("Leaving setup().");
  return { key: secret.value || "",
           cert: fields.oauthSamlAssertionCertificate };
}

async function table(k) {
  log.debug("Entering table().");
  log.info("=== T. section 3, item by item ===");
  const stranger = nodeCrypto.generateKeyPairSync("rsa",
    { modulusLength: 2048 }).privateKey.export({ type: "pkcs8",
                                                 format: "pem" });
  granted("T0. A SIGNATURE MADE BY THIS SUITE VERIFIES IN THIS SERVICE: " +
          "the well-formed assertion is granted",
  await token(assertionFor({ attributes: { department: "eng" } }, null,
                           k)));
  const rows = [
    ["T1. item 1 — no <Issuer>", { issuer: "" }, null, null, "item 1"],
    ["T2. item 2 — an audience that is somebody else",
     { audience: "https://elsewhere.example/token", recipient: TOKEN },
     null, null, "item 2"],
    ["T3. item 2 — no <Conditions> at all, so no audience",
     { omitConditions: true }, null, null, "item 2"],
    ["T4. item 3 — no <Subject>", { omitSubject: true }, null, null,
     "item 3"],
    ["T5. item 3 — a <Subject> with no <NameID>", { omitNameId: true },
     null, null, "item 3"],
    ["T6. item 4 — no expiry anywhere",
     { notOnOrAfter: null, confirmationNotOnOrAfter: null }, null, null,
     "item 4"],
    ["T7. item 5 — no bearer confirmation",
     { method: "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key" }, null, null,
     "item 5"],
    ["T8. item 5 — a Recipient that is another token endpoint",
     { recipient: "https://elsewhere.example/token" }, null, null,
     "items 5"],
    ["T9. item 5 — a <SubjectConfirmationData> with no Recipient",
     { recipient: null }, null, null, "items 5"],
    ["T10. item 6 — the <Conditions> have expired",
     { notOnOrAfter: saml.iso(-600000) }, null, null, "item 6"],
    ["T11. item 6 — it is not valid yet",
     { notBefore: saml.iso(600000), notOnOrAfter: saml.iso(900000) },
     null, null, "not valid until"],
    ["T12. item 6 — the confirmation has expired and it is the only one",
     { notOnOrAfter: null, confirmationNotOnOrAfter: saml.iso(-600000) },
     null, null, "items 5"],
    ["T13. item 6 — an expiry unreasonably far in the future",
     { notOnOrAfter: saml.iso(4000 * 1000) }, null, null,
     "saml2BearerMaxLifetimeS"],
    ["T14. item 9 — the digest does not match", {}, { breakDigest: true },
     null, "did not verify"],
    ["T15. item 9 — signed by a stranger", {}, null,
     { key: stranger, cert: null }, "did not verify"],
    ["T16. item 11 — a <Condition> nothing understands",
     { unknownCondition: "ProhibitedByLaw" }, null, null, "2.5.1"],
    ["T17. not SAML 2.0 at all", { version: "1.1" }, null, null, "Version"],
    ["T18. no ID to remember it by", { id: " " }, null, null, "ID"]
  ];
  for (const row of rows) {
    const r = await token(assertionFor(row[1], row[2], row[3] || k));
    refusedNaming(row[0], r, row[4]);
  }
  log.debug("Leaving table().");
}

async function lenient(k) {
  log.debug("Entering lenient().");
  log.info("=== L. the two items whose lenient reading is the usual bug ===");
  granted("L1. item 4: an expiry on the <SubjectConfirmationData> ALONE is " +
          "enough", await token(assertionFor({ notOnOrAfter: null }, null,
                                             k)));
  granted("L2. and an expiry on the <Conditions> alone, with NO " +
          "<SubjectConfirmationData> at all, is enough",
  await token(assertionFor({ omitConfirmationData: true }, null, k)));
  // ITEM 6's own distinction: an expired <SubjectConfirmation> beside a
  // live one is DISCARDED, and the live one used.
  const doc = saml.buildAssertion({ issuer: ISS, subject: PERSON,
    audience: TOKEN, recipient: TOKEN,
    confirmationNotOnOrAfter: saml.iso(-600000) });
  doc.xml = doc.xml.replace("</saml:Subject>",
    '<saml:SubjectConfirmation Method="' + BEARER + '">' +
    '<saml:SubjectConfirmationData NotOnOrAfter="' + saml.iso(120000) +
    '" Recipient="' + TOKEN + '"></saml:SubjectConfirmationData>' +
    "</saml:SubjectConfirmation></saml:Subject>");
  granted("L3. ITEM 6: AN EXPIRED <SubjectConfirmation> IS DISCARDED AND " +
          "THE LIVE ONE BESIDE IT IS USED",
  await token(saml.b64u(saml.sign(doc, k.key, k.cert))));
  log.debug("Leaving lenient().");
}

async function registered() {
  log.debug("Entering registered().");
  log.info("=== R. a registered certificate, and the replay ===");
  const reg = "s2b-registered-" + K.STAMP;
  const pair = selfSigned("s2b registered " + K.STAMP);
  await K.ok(K.rb(R) + "/admin-api/applications/create",
    { identifier: reg, protocols: ["oauth2", "oidc"],
      fields: { oauthClientId: reg,
                oauthSamlAssertionIssuer: [ISS_REG],
                oauthSamlAssertionSigningCertificate: [pair.cert] } },
    "created the application holding a registered certificate");
  const fixed = saml.id();
  const keys = { key: pair.key, cert: pair.cert };
  granted("R1. a certificate REGISTERED under " +
          "oauthSamlAssertionSigningCertificate, which no realm CA issued, " +
          "verifies the assertion it signed",
  await token(assertionFor({ issuer: ISS_REG, id: fixed }, null, keys)));
  refusedNaming("R2. THE SAME ID A SECOND TIME",
                await token(assertionFor({ issuer: ISS_REG, id: fixed },
                                         null, keys)), "used already");
  log.debug("Leaving registered().");
}

// A certificate the realm's own authority issued (a person's RFC 7522 key
// pair, its certificate copied onto an APPLICATION entry with its chain, so
// it is REGISTERED there), then revoked through the person's arm of
// `pki/revoke`: it goes on the realm's CRL, and the application's
// registered copy of it is refused.
async function revoked() {
  log.debug("Entering revoked().");
  log.info("=== V. a registered certificate, revoked ===");
  const holder = "s2b-holder-" + K.STAMP;
  await K.person(R, holder, "S2b-Passw0rd!-" + K.rand(3));
  const issued = await K.ok(K.rb(R) + "/admin-api/pki/issue",
    { identifier: holder, target: "person", purpose: "saml",
      label: "copied" }, "issued a person's RFC 7522 key pair");
  const dark = "s2b-copied-" + K.STAMP;
  await K.ok(K.rb(R) + "/admin-api/applications/create",
    { identifier: dark, protocols: ["oauth2", "oidc"],
      fields: { oauthClientId: dark,
                oauthSamlAssertionIssuer: [ISS_DARK],
                oauthSamlAssertionSigningCertificate: [issued.certificatePem +
                  "\n" + issued.chainPem] } },
    "registered the certificate on an application");
  const keys = { key: issued.privateKeyPem, cert: issued.certificatePem };
  granted("V1. the registered copy of a certificate this realm's CA issued " +
          "verifies an assertion", await token(assertionFor(
    { issuer: ISS_DARK }, null, keys)));
  const revokedAnswer = await K.ok(K.rb(R) + "/admin-api/pki/revoke",
    { identifier: holder, target: "person", purpose: "saml",
      handle: issued.thumbprint,
      reason: "keyCompromise" }, "revoked the person's key pair");
  const c = await K.coded(R, "STS-PKI-0129", function () {
    return token(assertionFor({ issuer: ISS_DARK }, null, keys));
  });
  K.check("V2. once revoked (on the realm's CRL), the REGISTERED copy " +
          "verifies the signature and is then refused, invalid_grant, " +
          "STS-PKI-0129 — the registered-certificate code", function () {
    assert.strictEqual(revokedAnswer.onList, true,
                       JSON.stringify(revokedAnswer).slice(0, 300));
    assert.strictEqual(c.answer.status, 400, K.shown(c.answer));
    assert.strictEqual((c.answer.json || {}).error, "invalid_grant");
    assert.ok(/may no longer be used/.test(
      (c.answer.json || {}).error_description || ""), c.answer.text);
    assert.ok(c.rose >= 1, "no new STS-PKI-0129 row");
    assert.ok(!/STS-[A-Z]+-\d{4}/.test(c.answer.text));
  });
  log.debug("Leaving revoked().");
}

async function test() {
  log.debug("Entering test().");
  const k = await setup();
  assert.ok(/BEGIN PRIVATE KEY/.test(k.key) && /BEGIN CERTIFICATE/.test(
    k.cert || ""), "the issued RFC 7522 key pair: " +
    String(k.key).slice(0, 40));
  await table(k);
  await lenient(k);
  await registered();
  await revoked();
  log.debug("Leaving test().");
}

K.main(test, 26);
