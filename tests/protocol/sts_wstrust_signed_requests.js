// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_wstrust_signed_requests.js
//
// ---------------------------------------------------------------------------
// A WS-TRUST REQUESTER AUTHENTICATED BY A WS-SECURITY SIGNATURE ON THE
// MESSAGE, OVER HTTP (#521).
//
// The other half of `tests/wstrust_message_signature.js`, against a running
// service and in whichever mode it runs (GET /admin-api/mode), with keys made
// at run time — by the service, through the administrator's doors:
//
//   1. a person and an application are each issued a message-signing
//      certificate (`/admin-api/users/issue-signing-certificate`,
//      `/admin-api/applications/issue-signing-certificate`); the private key
//      comes back once, encrypted, and is opened here;
//   2. an RST signed over the Body and the Timestamp with the person's key,
//      the certificate in a BinarySecurityToken, is answered with a SAML 2.0
//      assertion about the person stating X509, and a JWT with amr ["swk"];
//      the application's signature is a JWT whose client_id is the
//      application;
//   3. the same signed request sent again is refused in product
//      (wst:FailedAuthentication) and answered in development, which checks
//      no replay;
//   4. a signed part altered after signing: refused in product, answered in
//      development, which believes the certificate;
//   5. the person's certificate revoked
//      (`/admin-api/users/revoke-signing-certificate`): a freshly signed
//      request is refused in product, answered in development.
//
// The requests are signed with the WS-Security signer of the vendored
// engine (`common/crypto_impl/xmldsig.js`), its KeyInfo replaced with the
// SecurityTokenReference the X.509 Token Profile gives a requester.
//
// OWNED HERE (local: true): the feature is this repository's. Its entries are
// left behind; a rerun issues fresh certificates.
// ---------------------------------------------------------------------------

const assert = require("assert");
const nodeCrypto = require("crypto");
const { Command, Option } = require("commander");
const kit = require("./wstrust_chain_kit.js");
const registry = require("./sts_applications.js");
const xmldsig = require("../../common/crypto_impl/xmldsig.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand run without one still loads.
  appconfigProblem = e;
  appconfig = {};
}
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_wstrust_signed_requests",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug('CONFIG_FILE could not be read, so the configuration is empty: ' +
            appconfigProblem.message);
}

const WST = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
const WSSE = "http://docs.oasis-open.org/wss/2004/01/" +
  "oasis-200401-wss-wssecurity-secext-1.0.xsd";
const WSU = "http://docs.oasis-open.org/wss/2004/01/" +
  "oasis-200401-wss-wssecurity-utility-1.0.xsd";
const X509V3 = "http://docs.oasis-open.org/wss/2004/01/" +
  "oasis-200401-wss-x509-token-profile-1.0#X509v3";
const BASE64 = "http://docs.oasis-open.org/wss/2004/01/" +
  "oasis-200401-wss-soap-message-security-1.0#Base64Binary";
const SUFFIX = nodeCrypto.randomBytes(3).toString("hex");
const PERSON = "wssig-" + SUFFIX;
const APP = "wssig-app-" + SUFFIX;
const APPLIES_TO = "https://" + APP + ".example.com";
const FILE_PASSWORD = "file-" + nodeCrypto.randomBytes(8).toString("hex");

let checks = 0;
async function check(what, fn) {
  log.debug("Entering check().");
  await fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

// What an issue hands back, opened: the certificate's PEM and an
// unencrypted RSA key the engine's signer reads.
function openIssued(reply, what) {
  log.debug("Entering openIssued(). " + what);
  const cert = reply && reply.certificate;
  const key = reply && reply.files && reply.files.key;
  assert.ok(cert && cert.certificatePem && key && key.text, what + ": the " +
            "issue handed back no certificate or key: " +
            JSON.stringify(reply).slice(0, 300));
  const privateKey = nodeCrypto.createPrivateKey({
    key: key.text, format: "pem", passphrase: FILE_PASSWORD });
  log.debug("Leaving openIssued().");
  return { certPem: cert.certificatePem, serialHex: cert.serialHex,
           keyPem: privateKey.export({ type: "pkcs1", format: "pem" }) };
}

// An Issue for APPLIES_TO, signed with `holder`'s key over the Body and the
// Timestamp, the certificate in a BinarySecurityToken. `after` alters the
// signed document.
function signedRst(holder, tokenType, after) {
  log.debug("Entering signedRst().");
  const now = Date.now();
  const certB64 = String(holder.certPem)
    .replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  const xml = '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" ' +
    'xmlns:wsse="' + WSSE + '" xmlns:wsu="' + WSU + '"><s:Header>' +
    '<wsse:Security><wsu:Timestamp wsu:Id="ts"><wsu:Created>' +
    new Date(now).toISOString() + '</wsu:Created><wsu:Expires>' +
    new Date(now + 300000).toISOString() + '</wsu:Expires></wsu:Timestamp>' +
    '<wsse:BinarySecurityToken wsu:Id="x509" ValueType="' + X509V3 +
    '" EncodingType="' + BASE64 + '">' + certB64 +
    '</wsse:BinarySecurityToken></wsse:Security></s:Header>' +
    '<s:Body wsu:Id="body"><wst:RequestSecurityToken xmlns:wst="' + WST +
    '" Context="urn:uuid:' + nodeCrypto.randomUUID() + '">' +
    '<wst:RequestType>' + WST + '/Issue</wst:RequestType>' +
    '<wst:TokenType>' + tokenType + '</wst:TokenType>' +
    '<wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy">' +
    '<wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/08/' +
    'addressing"><wsa:Address>' + APPLIES_TO + '</wsa:Address>' +
    '</wsa:EndpointReference></wsp:AppliesTo>' +
    '</wst:RequestSecurityToken></s:Body></s:Envelope>';
  const signed = xmldsig.signWsSecurity(xml, {
    privateKeyPem: holder.keyPem, certPem: holder.certPem,
    signTimestamp: true })
    .replace(/<ds:KeyInfo>[\s\S]*?<\/ds:KeyInfo>/,
             '<ds:KeyInfo><wsse:SecurityTokenReference><wsse:Reference ' +
             'URI="#x509" ValueType="' + X509V3 + '"/>' +
             '</wsse:SecurityTokenReference></ds:KeyInfo>');
  log.debug("Leaving signedRst().");
  return after ? after(signed) : signed;
}

async function post(base, body) {
  log.debug("Entering post().");
  const r = await fetch(base + "/sts", { method: "POST", body: body,
    headers: { "Content-Type": "application/soap+xml" } });
  const text = await r.text();
  log.debug("Leaving post(). " + r.status);
  return { status: r.status, text: text };
}

function claimsOf(rstr) {
  log.debug("Entering claimsOf().");
  const found = /<wsse:BinarySecurityToken[^>]*>([^<]+)</.exec(String(rstr));
  assert.ok(found, "the RSTR carries no JWT: " + String(rstr).slice(0, 300));
  log.debug("Leaving claimsOf().");
  return JSON.parse(Buffer.from(found[1].split(".")[1], "base64url")
    .toString("utf8"));
}

async function test() {
  log.debug("Entering test().");
  const base = kit.serviceBase();
  const product = await kit.isProduct(base);
  log.info("WS-Trust signed requests at " + base + " (" +
           (product ? "product" : "development") + " mode).");
  await registry.ensurePerson(base, PERSON,
    "Pw-" + nodeCrypto.randomBytes(12).toString("hex") + "!9");
  await registry.provision(base, {
    identifier: APP, name: APP, protocols: ["wstrust", "saml2", "oauth2"],
    fields: { wstrustAppliesTo: [APPLIES_TO], samlEntityId: [APPLIES_TO] },
    why: "the relying party and signing application of the signed-request job"
  });
  const person = openIssued(await registry.adminPost(base,
    "/users/issue-signing-certificate",
    { user: PERSON, keyAlg: "rsa-2048", password: FILE_PASSWORD }),
    PERSON);
  const application = openIssued(await registry.adminPost(base,
    "/applications/issue-signing-certificate",
    { application: APP, keyAlg: "rsa-2048", password: FILE_PASSWORD }), APP);
  await check("1. a person and an application were each issued a " +
              "message-signing certificate naming them", function () {
    assert.ok(/urn:sts:person:/.test(String(
      new nodeCrypto.X509Certificate(person.certPem).subjectAltName)),
              "the person's certificate names no urn:sts:person:");
    assert.ok(/urn:sts:application:/.test(String(
      new nodeCrypto.X509Certificate(application.certPem).subjectAltName)),
              "the application's certificate names no urn:sts:application:");
  });

  let r = await post(base, signedRst(person, kit.SAML2_TOKEN_TYPE));
  await check("2a. a request signed by the person is answered with an " +
              "assertion about them stating X509", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 600));
    assert.ok(new RegExp(">" + PERSON + "<").test(r.text), "not about " +
              PERSON + ": " + r.text.slice(0, 600));
    assert.ok(/ac:classes:X509</.test(r.text), "no X509 AuthnContext");
  });
  r = await post(base, signedRst(person, kit.JWT_TOKEN_TYPE));
  await check("2b. and with a JWT carrying amr [\"swk\"]", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 600));
    assert.deepStrictEqual(claimsOf(r.text).amr, ["swk"]);
  });
  r = await post(base, signedRst(application, kit.JWT_TOKEN_TYPE));
  await check("2c. a request signed by the application is a JWT whose " +
              "client_id is the application", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 600));
    assert.strictEqual(claimsOf(r.text).client_id, APP);
  });

  const once = signedRst(person, kit.SAML2_TOKEN_TYPE);
  r = await post(base, once);
  assert.strictEqual(r.status, 200, "the request to be replayed was not " +
                     "answered: " + r.text.slice(0, 400));
  r = await post(base, once);
  await check("3. the same signed request again: " +
              (product ? "refused as a replay" : "answered (development " +
               "checks no replay)"), function () {
    if (product) {
      assert.strictEqual(r.status, 500, r.text.slice(0, 400));
      assert.ok(/FailedAuthentication/.test(r.text), r.text.slice(0, 400));
    } else {
      assert.strictEqual(r.status, 200, r.text.slice(0, 400));
    }
  });

  r = await post(base, signedRst(person, kit.SAML2_TOKEN_TYPE,
    function (xml) {
      return xml.replace('Context="urn:uuid:', 'Context="urn:uuid:0');
    }));
  await check("4. a signed part altered after signing: " +
              (product ? "refused" : "answered (development believes the " +
               "certificate)"), function () {
    if (product) {
      assert.strictEqual(r.status, 500, r.text.slice(0, 400));
      assert.ok(/FailedAuthentication/.test(r.text), r.text.slice(0, 400));
    } else {
      assert.strictEqual(r.status, 200, r.text.slice(0, 400));
    }
  });

  await registry.adminPost(base, "/users/revoke-signing-certificate",
    { user: PERSON, serialHex: person.serialHex, reason: "keyCompromise" });
  r = await post(base, signedRst(person, kit.SAML2_TOKEN_TYPE));
  await check("5. after the person's certificate is revoked: " +
              (product ? "refused" : "answered (development consults no " +
               "revocation)"), function () {
    if (product) {
      assert.strictEqual(r.status, 500, r.text.slice(0, 400));
      assert.ok(/FailedAuthentication/.test(r.text), r.text.slice(0, 400));
    } else {
      assert.strictEqual(r.status, 200, r.text.slice(0, 400));
    }
  });
  assert.ok(checks === 7, "only " + checks + " of 7 checks ran");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_wstrust_signed_requests")
  .description("WS-Trust requests signed with message-signing certificates " +
    "the service issued: the signer authenticated, and replays, altered " +
    "parts and revoked certificates refused in product.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
