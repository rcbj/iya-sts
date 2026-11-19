// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_wstrust_rules.js
//
// ===========================================================================
// WHAT WS-TRUST ANSWERS AND ISSUES, OVER THE WIRE (#444 D12, phase 7).
//
// The in-process WS-Trust files call `handleRst()` with assertions the test
// built with the realm's own key and the mode flipped per case. At the
// cutover they go, so this job asks the same of a running service through
// `/realm/<id>/sts`, in a PRODUCT realm and a DEVELOPMENT realm of its own,
// with every credential one the service ISSUED over `/sts` (altered here
// only where the alteration is the thing under test):
//
//   A. `wstrust_fault_codes.js` A: every refusal a request can reach, on
//      SOAP 1.1 AND SOAP 1.2, held to WS-Trust 1.4 section 11's code where
//      that version puts it, and to its STS-WSTRUST code on the realm's
//      audit log. The expired credential is a real one: asked for with a
//      one-minute wst:Lifetime in a realm whose clock skew is 0, and
//      presented after it has gone — a SAML 2.0 credential and ActAs, and
//      (`wstrust_jwt_claims.js` K2c, `wstrust_saml11.js` T3b) a JWT
//      (STS-WSTRUST-0027) and a SAML 1.1 assertion (0006) inside ActAs; and
//      K2b, a JWT another issuer named — another realm's (0026).
//   B. the fault's namespace is the request's own (2005/02).
//   E. the RSTR says Bearer when PublicKey was asked for; a response
//      recipient expression on an unsigned request is STS-WSTRUST-0081, and
//      on a signed one selects the signer's own token, the AppliesTo's
//      application choosing the cipher and the answer announcing its
//      EncryptedKey (#747, #1668).
//   R. `reserved_password_refusal.js`'s WS-Trust half: `invalid` refused in
//      both modes with a wrong password's answer, and the LDAP half: an LDAPS
//      simple bind with `invalid` is 49 in both modes, STS-LDAP-0001 in
//      development, while the real password binds.
//   J. `wstrust_jwt_claims.js` J1–J5, R1–R4, S1–S4, T1–T2: the JWT's
//      RFC 9068 / RFC 8693 shape, a JWT as the credential, an application
//      authenticating as itself, a credential addressed to somebody else.
//   S. `wstrust_saml11.js` T1, T3, T4: SAML 1.1 as a token type.
//   C. `wstrust_token_claims.js`: the AppliesTo's claim settings and
//      `wstrustJwtScope` judged as an OAuth access token's are.
//   W. `wstrust_scope_warnings.js` W1–W5: the warnings at configuration
//      time.
//
// NOT HERE, and why: `wstrust_fault_codes.js` C (an exception planted in
// the endpoint: no request makes this service fail) and the two cases
// needing an assertion SIGNED BY THE REALM'S KEY that the service never
// issues — one not yet valid (STS-WSTRUST-0005: no Issue states a NotBefore
// in the future) and one naming nobody (STS-WSTRUST-0007: no Issue omits
// the NameID). Those are (d).
//
// OWNED HERE (local: true). Its realms are removed only on a private probe
// (STS_TEST_REMOVE_REALMS=1).
// ===========================================================================

const assert = require("assert");
const ldapjs = require("ldapjs");
const nodeCrypto = require("crypto");
// xmldsig.js reaches for the bare DOM globals a node process lacks
// (sts_wstrust_signed_requests.js's note).
const xmldom = require("@xmldom/xmldom");
if (!global.DOMParser) {
  global.DOMParser = xmldom.DOMParser;
}
if (!global.XMLSerializer) {
  global.XMLSerializer = xmldom.XMLSerializer;
}
const xmldsig = require("../../common/crypto_impl/xmldsig.js");
const K = require("./oauth_wire_kit.js").kit("sts_wstrust_rules");
const W = require("./wstrust_wire_kit.js").wsKit(K);

const log = K.log;
const PASSWORD = "Ws-Rules-Passw0rd!-" + String(Date.now()).slice(-6);
const SECRET = "ws-rules-secret-" + K.rand(8);
const URL_OF = function (name) {
  return "https://" + name + "-" + K.STAMP + ".example";
};
const BACK = URL_OF("wf-back");
const OTHER = URL_OF("wf-other");
const FRONT = URL_OF("wf-front");
const LAST = URL_OF("wf-last");
const PLAIN = URL_OF("wf-plain");
const PAYROLL = URL_OF("wf-payroll");
const BASIC = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic";
const WSSE = "http://docs.oasis-open.org/wss/2004/01/" +
  "oasis-200401-wss-wssecurity-secext-1.0.xsd";
const WSU = "http://docs.oasis-open.org/wss/2004/01/" +
  "oasis-200401-wss-wssecurity-utility-1.0.xsd";
const X509V3 = "http://docs.oasis-open.org/wss/2004/01/" +
  "oasis-200401-wss-x509-token-profile-1.0#X509v3";
const BASE64 = "http://docs.oasis-open.org/wss/2004/01/" +
  "oasis-200401-wss-soap-message-security-1.0#Base64Binary";
const ASSERTION_XPATH = "//*[local-name()='Assertion' and " +
  "namespace-uri()='urn:oasis:names:tc:SAML:2.0:assertion']";
const RECIPIENT_XPATH = "//*[local-name()='Security']/*[local-name()=" +
  "'Signature']//*[local-name()='X509Certificate' and namespace-uri()=" +
  "'http://www.w3.org/2000/09/xmldsig#']";

async function responseMap(id, on, algorithm) {
  log.debug("Entering responseMap(). " + id + " " + on);
  await api(id, "/applications/set", { application: "wf-back",
    attribute: "wstrustEncryptResponse", value: on ? "true" : "" });
  await api(id, on ? "/applications/add" : "/applications/remove", {
    application: "wf-back", attribute: "wstrustEncryptResponseElements",
    value: ASSERTION_XPATH });
  await api(id, "/applications/set", { application: "wf-back",
    attribute: "wstrustResponseRecipientXPath",
    value: on ? RECIPIENT_XPATH : "" });
  if (algorithm !== undefined) {
    await api(id, "/applications/set", { application: "wf-back",
      attribute: "wstrustEncryptionAlgorithm",
      value: on ? algorithm : "" });
  }
  log.debug("Leaving responseMap().");
}

// #1908: a WS-Security signature over the Body and the Timestamp, made
// with a message-signing certificate the realm issued, the certificate in
// a BinarySecurityToken the signature references (as
// sts_wstrust_signed_requests.js signs).
const FILE_PASSWORD = "file-" + nodeCrypto.randomBytes(8).toString("hex");

function openIssued(reply) {
  log.debug("Entering openIssued().");
  const cert = reply && reply.certificate;
  const key = reply && reply.files && reply.files.key;
  assert.ok(cert && cert.certificatePem && key && key.text, "the issue " +
            "handed back no certificate or key: " +
            JSON.stringify(reply).slice(0, 300));
  const privateKey = nodeCrypto.createPrivateKey({
    key: key.text, format: "pem", passphrase: FILE_PASSWORD });
  log.debug("Leaving openIssued().");
  return { certPem: cert.certificatePem,
           keyPem: privateKey.export({ type: "pkcs1", format: "pem" }) };
}

function signedRst(holder, appliesTo) {
  log.debug("Entering signedRst().");
  const now = Date.now();
  const certB64 = String(holder.certPem)
    .replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  const xml = '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-' +
    'envelope" xmlns:wsse="' + WSSE + '" xmlns:wsu="' + WSU + '">' +
    '<s:Header><wsse:Security><wsu:Timestamp wsu:Id="ts"><wsu:Created>' +
    new Date(now).toISOString() + '</wsu:Created><wsu:Expires>' +
    new Date(now + 300000).toISOString() + '</wsu:Expires>' +
    '</wsu:Timestamp><wsse:BinarySecurityToken wsu:Id="x509" ValueType="' +
    X509V3 + '" EncodingType="' + BASE64 + '">' + certB64 +
    '</wsse:BinarySecurityToken></wsse:Security></s:Header>' +
    '<s:Body wsu:Id="body"><wst:RequestSecurityToken xmlns:wst="' + W.WST +
    '" Context="urn:uuid:' + nodeCrypto.randomUUID() + '">' +
    '<wst:RequestType>' + W.WST + '/Issue</wst:RequestType>' +
    '<wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/' +
    'policy"><wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/08/' +
    'addressing"><wsa:Address>' + appliesTo + '</wsa:Address>' +
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
  return signed;
}

async function api(id, path, body, what) {
  log.debug("Entering api(). " + path);
  log.debug("Leaving api().");
  return K.ok(K.rb(id) + "/admin-api" + path, body, what || path);
}

async function fixtures(id) {
  log.debug("Entering fixtures(). " + id);
  for (const who of ["wf-alice", "wf-carl", "wf-dana", "wf-erin",
                     "wf-person"]) {
    await K.person(id, who, PASSWORD);
  }
  await api(id, "/users/set-not-delegated", { user: "wf-carl", value: true });
  await api(id, "/groups/create", { group: "wf-team" });
  await api(id, "/groups/add-member", { group: "wf-team",
                                        member: "wf-alice" });
  await api(id, "/roles/create-role", { role: "wf-team-role" });
  await api(id, "/roles/add-member", { role: "wf-team-role", kind: "group",
                                       member: "wf-team" });
  for (const role of ["wf-gated-role", "wf-payroll-role"]) {
    await api(id, "/roles/create-role", { role: role });
  }
  await api(id, "/claims/replace", { set: "access_token",
    claims: [{ name: "realm-flag", value: "on" }] });
  await api(id, "/saml-attributes/replace", { set: "saml2",
    claims: [{ name: "realm-flag", value: "on" }] });
  const app = function (identifier, fields) {
    return api(id, "/applications/create", { identifier: identifier,
      name: identifier, protocols: ["wstrust", "saml2", "oauth2"],
      fields: Object.assign({ oauthClientId: [identifier] }, fields) });
  };
  await app("wf-back", {
    wstrustAppliesTo: [BACK], samlEntityId: BACK,
    oauthClientSecret: SECRET, appAllowedToDelegateTo: ["wf-last"],
    appGroupsClaim: "TRUE", appGroupsClaimName: "teams",
    appGroupsClaimValue: "dn", oauthAllowedScope: ["api.read"],
    wstrustJwtScope: ["api.read", "api.undeclared", "admin:write"],
    oauthClaimsAccessToken: JSON.stringify(
      [{ name: "tier", value: "gold-${username}" }]),
    saml2CustomAttributes: JSON.stringify(
      [{ name: "tier", value: "gold-${subject}", nameFormat: BASIC }]) });
  await app("wf-other", { wstrustAppliesTo: [OTHER] });
  await app("wf-last", { wstrustAppliesTo: [LAST] });
  await app("wf-plain", { wstrustAppliesTo: [PLAIN] });
  await app("wf-front", { wstrustAppliesTo: [FRONT], samlEntityId: FRONT,
    oauthClientSecret: SECRET, appAllowedToDelegateTo: ["wf-back"] });
  await app("wf-both", { oauthClientSecret: SECRET,
    appAllowedToDelegateTo: ["wf-back"],
    appDelegationSemantics: ["delegation", "impersonation"] });
  await app("wf-gated", { appRequiredRole: ["wf-gated-role"] });
  await app("wf-payroll", { oauthClientSecret: SECRET,
    wstrustAppliesTo: [PAYROLL],
    appAllowedToDelegateTo: ["wf-back"],
    appRequiredRole: ["wf-payroll-role"] });
  log.debug("Leaving fixtures().");
}

// A token about `who` (a person or an application authenticating with its
// secret) addressed to `to` (the IdP's own name when null).
async function tokenFor(id, who, to, type, more) {
  log.debug("Entering tokenFor(). " + who);
  const pass = /^wf-(alice|carl|dana|erin|person)$/.test(who) ? PASSWORD
                                                              : SECRET;
  const t = await W.issue(id, who, pass, to || K.rb(id), type || W.SAML2,
                          more);
  log.debug("Leaving tokenFor().");
  return t.assertion || W.jwtToken(t.jwt);
}

// One refusal, on both SOAP versions: the status, section 11's code in its
// place, and a new row of `code` on the realm's audit log.
async function refusal(id, label, opts, code, fault, query) {
  log.debug("Entering refusal(). " + code);
  for (const soap11 of [true, false]) {
    const o = Object.assign({ soap11: soap11 }, opts, { query: query });
    const ns = opts.raw !== undefined ? W.WST : (opts.trustNs || W.WST);
    const got = await K.coded(id, code, function () {
      return W.post(id, o);
    });
    const r = got.answer;
    K.check(code + " (" + label + "), SOAP " + (soap11 ? "1.1" : "1.2") +
            " is wst:" + fault, function () {
      assert.ok(r.status >= 400, r.status + " " + r.text.slice(0, 300));
      assert.ok(W.carries(r.text, soap11, fault, ns),
                "not wst:" + fault + " in its place: " + r.text.slice(0, 500));
      assert.ok(got.rose >= 1, "no new " + code + " row in " + id);
    });
  }
  log.debug("Leaving refusal().");
}

// ------------------------------------------------------------- A, B, E
async function faults(P, D) {
  log.debug("Entering faults().");
  log.info("=== A. every refusal a request reaches, both SOAP versions ===");
  // THE EXPIRED CREDENTIALS FIRST: asked for with a one-minute lifetime in
  // a realm whose clock skew is 0, and presented once they have gone.
  await K.set(P, "oauth2.clockSkewS", 0);
  const now = Date.now();
  const lifetime = '<wst:Lifetime xmlns:wsu="http://docs.oasis-open.org/' +
    'wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"><wsu:Created>' +
    new Date(now).toISOString() + "</wsu:Created><wsu:Expires>" +
    new Date(now + 60000).toISOString() + "</wsu:Expires></wst:Lifetime>";
  const shortFront = await tokenFor(P, "wf-front", null, W.SAML2,
                                    { body: lifetime });
  const shortAlice = await tokenFor(P, "wf-alice", FRONT, W.SAML2,
                                    { body: lifetime });
  // wstrust_jwt_claims K2c and wstrust_saml11 T3b: the same minute, a JWT
  // and a SAML 1.1 assertion.
  const shortAliceJwt = await tokenFor(P, "wf-alice", FRONT, W.JWT,
                                       { body: lifetime });
  const shortAlice11 = await tokenFor(P, "wf-alice", FRONT, W.SAML11,
                                      { body: lifetime });
  const frontSigned = await tokenFor(P, "wf-front");
  const aliceForFront = await tokenFor(P, "wf-alice", FRONT);
  const aliceSigned = await tokenFor(P, "wf-alice");
  const personSigned = await tokenFor(P, "wf-person");
  const payrollSigned = await tokenFor(P, "wf-payroll");
  const carlForFront = await tokenFor(P, "wf-carl", FRONT);
  const badCertificate = '<ds:Signature xmlns:ds="http://www.w3.org/2000/' +
    '09/xmldsig#"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>AAAA' +
    "</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>";
  const UT = W.usernameToken;
  const cases = [
    [P, "the reserved password, product", { security: UT("wf-alice",
      "invalid"), appliesTo: BACK }, "STS-WSTRUST-0003",
     "FailedAuthentication"],
    [P, "an unsigned assertion as the credential",
     { security: W.unsigned(frontSigned), appliesTo: BACK },
     "STS-WSTRUST-0004", "FailedAuthentication"],
    [P, "an unsigned assertion inside ActAs",
     { security: frontSigned, body: W.actAs(W.unsigned(aliceForFront)),
       appliesTo: BACK }, "STS-WSTRUST-0004", "InvalidRequest"],
    [P, "an ActAs carrying no assertion",
     { security: frontSigned, body: W.actAs(UT("wf-alice", "x")),
       appliesTo: BACK }, "STS-WSTRUST-0008", "InvalidRequest"],
    [P, "a delegation with no requester credential",
     { body: W.actAs(aliceForFront), appliesTo: BACK },
     "STS-WSTRUST-0009", "FailedAuthentication"],
    [P, "no credential at all", { appliesTo: BACK }, "STS-WSTRUST-0010",
     "FailedAuthentication"],
    [P, "response encryption with no recipient certificate",
     { security: W.stripCertificates(aliceSigned), appliesTo: BACK },
     "STS-WSTRUST-0076", "InvalidRequest"],
    [P, "response encryption with a certificate only inside the assertion",
     { security: aliceSigned, appliesTo: BACK }, "STS-WSTRUST-0076",
     "InvalidRequest"],
    [P, "response encryption with a certificate only inside ActAs",
     { security: W.stripCertificates(frontSigned),
       body: W.actAs(aliceForFront), appliesTo: BACK },
     "STS-WSTRUST-0076", "InvalidRequest"],
    // #1908: the recipient expression may select only a certificate an
    // accepted signature covers, and this request is not signed.
    [P, "response encryption to a certificate element no signature covers",
     { security: badCertificate + aliceSigned, appliesTo: BACK },
     "STS-WSTRUST-0081", "InvalidRequest"],
    [P, "a protected subject", { security: frontSigned,
      body: W.actAs(carlForFront), appliesTo: BACK }, "STS-WSTRUST-0018",
     "RequestFailed"],
    [P, "a person requester without delegation.actorRole",
     { security: personSigned, body: W.actAs(aliceForFront),
       appliesTo: BACK }, "STS-WSTRUST-0019", "RequestFailed"],
    [P, "impersonation asked of an actor allowing delegation only",
     { security: frontSigned, body: W.onBehalfOf(aliceForFront),
       appliesTo: BACK }, "STS-WSTRUST-0022", "RequestFailed"],
    [P, "a subject without the authority S requires",
     { security: payrollSigned, body: W.actAs(
       await tokenFor(P, "wf-alice", PAYROLL)), appliesTo: BACK },
     "STS-WSTRUST-0023", "RequestFailed"],
    [P, "a target the intermediary may not reach",
     { security: frontSigned, body: W.actAs(aliceForFront),
       appliesTo: OTHER }, "STS-WSTRUST-0018", "RequestFailed"],
    [P, "an AppliesTo nobody registered",
     { security: frontSigned, appliesTo: URL_OF("wf-nobody") },
     "STS-WSTRUST-0030", "InvalidScope"],
    [P, "no AppliesTo", { security: frontSigned }, "STS-WSTRUST-0031",
     "InvalidRequest"],
    // wstrust_jwt_claims K2b: a JWT another issuer named — over the wire,
    // another realm's, under that realm's key and issuer.
    [P, "a JWT another issuer named, inside ActAs",
     { security: frontSigned, body: W.actAs(await tokenFor(D, "wf-alice",
       FRONT, W.JWT)), appliesTo: BACK, tokenType: W.JWT },
     "STS-WSTRUST-0026", "InvalidRequest"],
    [D, "a malformed body", { raw: "<a><b></a>" }, "STS-WSTRUST-0001",
     "InvalidRequest"],
    [D, "a UsernameToken with no password",
     { security: UT("wf-alice", null) }, "STS-WSTRUST-0002",
     "FailedAuthentication"],
    [D, "the reserved password, development",
     { security: UT("wf-alice", "invalid") }, "STS-WSTRUST-0003",
     "FailedAuthentication"],
    [D, "the role gate", { security: UT("wf-alice", "x"),
      appliesTo: "wf-gated" }, "STS-WSTRUST-0011", "RequestFailed"],
    [D, "Cancel in WS-Trust 2004/04", { security: UT("wf-alice", "x"),
      op: "Cancel", trustNs: W.WST_2004_04 }, "STS-WSTRUST-0021",
     "InvalidRequest"],
    [D, "both OnBehalfOf and ActAs", { security: UT("wf-front", "x"),
      body: W.actAs(await tokenFor(D, "wf-alice", FRONT)) +
            W.onBehalfOf(await tokenFor(D, "wf-alice", FRONT)),
      appliesTo: BACK }, "STS-WSTRUST-0025", "InvalidRequest"]
  ];
  // wf-back's response map is on for the four encryption refusals. A
  // mismatch is the fault those cases record. It is off again before any
  // later success against the same application.
  await responseMap(P, true);
  for (const c of cases) {
    await refusal(c[0], c[1], c[2], c[3], c[4], c[5]);
  }
  await responseMap(P, false);
  // A JWT about somebody the directory does not hold, with autocreate off.
  await K.set(D, "ldap.autocreateUsers", false);
  await refusal(D, "a JWT about somebody the directory does not hold",
    { security: UT("wf-ghost-" + K.rand(3), "x"), tokenType: W.JWT },
    "STS-WSTRUST-0017", "RequestFailed");
  await K.unset(D, "ldap.autocreateUsers");

  log.info("=== B. the fault is qualified with the request's namespace ===");
  for (const soap11 of [true, false]) {
    const r = await W.post(D, { soap11: soap11, trustNs: W.WST_2005_02,
      security: UT("wf-alice", "invalid") });
    K.check("B. a 2005/02 request's fault is qualified with 2005/02's " +
            "namespace, SOAP " + (soap11 ? "1.1" : "1.2"), function () {
      assert.ok(W.carries(r.text, soap11, "FailedAuthentication",
                          W.WST_2005_02), r.text.slice(0, 400));
    });
  }

  log.info("=== E. what the RSTR says it issued (#747) ===");
  const asked = await W.post(D, { security: UT("wf-alice", "x"),
    appliesTo: BACK, body: "<wst:KeyType>" + W.WST +
      "/PublicKey</wst:KeyType>" });
  K.check("E1. the RSTR states Bearer when PublicKey was asked for",
          function () {
            assert.strictEqual(asked.status, 200, asked.text.slice(0, 300));
            assert.ok(asked.text.indexOf(W.WST + "/Bearer</wst:KeyType>") >
                      0, asked.text.slice(0, 400));
            assert.ok(asked.text.indexOf("/PublicKey") < 0);
          });
  // THE RECIPIENT EXPRESSION AND THE SIGNATURE (#1908, rcbj). An unsigned
  // request's certificate element is no recipient: STS-WSTRUST-0081.
  const certificate = (/<ds:X509Certificate>([^<]+)</.exec(
    await tokenFor(D, "wf-alice")) || [])[1] || "";
  await responseMap(D, true, "aes128-gcm");
  const unsignedAsk = await W.post(D, { appliesTo: BACK,
    security: UT("wf-alice", "x") + '<ds:Signature xmlns:ds="http://www.w3' +
      '.org/2000/09/xmldsig#"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>' +
      certificate + "</ds:X509Certificate></ds:X509Data></ds:KeyInfo>" +
      "</ds:Signature>" });
  K.check("E2. a recipient expression on an unsigned request is " +
          "wst:InvalidRequest (STS-WSTRUST-0081), and nothing is issued",
          function () {
            assert.ok(certificate, "no certificate in the request");
            assert.strictEqual(unsignedAsk.status, 500,
                               unsignedAsk.text.slice(0, 300));
            assert.ok(W.carries(unsignedAsk.text, false, "InvalidRequest",
                                W.WST) &&
                      !/EncryptedData/.test(unsignedAsk.text) &&
                      /accepted signature covers/.test(unsignedAsk.text),
                      unsignedAsk.text.slice(0, 500));
          });
  // Signed, the expression selects the signer's own BinarySecurityToken:
  // the recipient, and the AppliesTo's application chooses the cipher.
  await api(D, "/applications/set", { application: "wf-back",
    attribute: "wstrustResponseRecipientXPath",
    value: "//wsse:Security/wsse:BinarySecurityToken" });
  const holder = openIssued(await api(D, "/users/issue-signing-certificate",
    { user: "wf-alice", keyAlg: "rsa-2048", password: FILE_PASSWORD }));
  const encrypted = await K.send(K.rb(D) + "/sts", { method: "POST",
    raw: signedRst(holder, BACK),
    headers: { "Content-Type": "application/soap+xml" } });
  await responseMap(D, false, "aes128-gcm");
  K.check("E3. a signed request's own token is the recipient; the " +
          "AppliesTo's application chooses the cipher; the answer announces " +
          "its EncryptedKey in a security header", function () {
    assert.strictEqual(encrypted.status, 200, encrypted.text.slice(0, 300));
    assert.ok(/EncryptedData/.test(encrypted.text) &&
              !/EncryptedAssertion/.test(encrypted.text) &&
              /xmlenc11#aes128-gcm/.test(encrypted.text),
              encrypted.text.slice(0, 500));
    assert.ok(/<wsse:Security[^>]*><xenc:EncryptedKey[^>]*Id="iya-ek-1"/
                .test(encrypted.text) &&
              /<xenc:DataReference URI="#iya-ed-1"\/>/.test(encrypted.text),
              encrypted.text.slice(0, 700));
  });

  log.info("=== A. the expired credentials, after their minute ===");
  await K.sleep(Math.max(0, now + 62000 - Date.now()));
  await refusal(P, "an expired credential", { security: shortFront,
    appliesTo: BACK }, "STS-WSTRUST-0006", "ExpiredData");
  await refusal(P, "an expired token inside ActAs", { security: frontSigned,
    body: W.actAs(shortAlice), appliesTo: BACK }, "STS-WSTRUST-0006",
    "ExpiredData");
  await refusal(P, "an expired JWT inside ActAs", { security: frontSigned,
    body: W.actAs(shortAliceJwt), appliesTo: BACK, tokenType: W.JWT },
  "STS-WSTRUST-0027", "ExpiredData");
  await refusal(P, "an expired SAML 1.1 assertion inside ActAs",
    { security: frontSigned, body: W.actAs(shortAlice11), appliesTo: BACK,
      tokenType: W.SAML11 }, "STS-WSTRUST-0006", "ExpiredData");
  await K.unset(P, "oauth2.clockSkewS");
  log.debug("Leaving faults().");
}

// ----------------------------------------------------------------- R (LDAP)
function ldapBind(dn, password) {
  log.debug("Entering ldapBind(). " + dn);
  const host = new URL(K.base).hostname;
  const client = ldapjs.createClient({
    url: "ldaps://" + host + ":" + (process.env.STS_LDAPS_PORT || 636),
    reconnect: false, timeout: 20000, connectTimeout: 15000,
    tlsOptions: { rejectUnauthorized: true, servername: host } });
  client.on("error", function (e) {
    // The bind in flight reports it; an unhandled 'error' would throw.
    log.debug("The LDAP client emitted an error: " + e.message);
  });
  log.debug("Leaving ldapBind().");
  return new Promise(function (resolve) {
    client.bind(dn, password, function (e) {
      try {
        client.unbind(function () {
          return undefined;
        });
      } catch (u) {
        log.debug("Caught in ldapBind(): " + ((u && u.message) || u));
        // A connection the server closed cannot be unbound.
      }
      resolve(e ? e.code : 0);
    });
  });
}

async function reserved(P, D) {
  log.debug("Entering reserved().");
  log.info("=== R. the reserved password `invalid` (#412) ===");
  for (const [id, product] of [[D, false], [P, true]]) {
    const m = product ? "product" : "development";
    const who = "wf-res-" + K.rand(3);
    const made = await api(id, "/users/create", { username: who,
      invent: false, credential: "password", password: PASSWORD,
      attributes: { cn: "WS " + who, givenName: "WS", sn: who,
                    mail: who + "@ws-rules.test" } });
    const dn = String(made.dn);
    const good = await ldapBind(dn, PASSWORD);
    const other = product ? null : await ldapBind(dn, "anything-else");
    const refused = await K.coded(id, "STS-LDAP-0001", function () {
      return ldapBind(dn, "invalid");
    });
    const wrong = product ? await ldapBind(dn, "Wrong-" + PASSWORD) : null;
    K.check("R (" + m + "). an LDAPS simple bind with `invalid` is 49, " +
            "the real password binds" + (product ? ", as a wrong one is 49"
            : ", and any other password binds"), function () {
      assert.strictEqual(good, 0, "the real password: " + good);
      assert.strictEqual(refused.answer, 49, "invalid: " + refused.answer);
      if (product) {
        assert.strictEqual(wrong, 49, "a wrong password: " + wrong);
      } else {
        assert.strictEqual(other, 0, "another password: " + other);
      }
    });
    K.check("R (" + m + "). the `invalid` bind is recorded STS-LDAP-0001",
            function () {
              assert.ok(refused.rose >= 1, "no STS-LDAP-0001 row");
            });
    const ws = await W.post(id, { security: W.usernameToken(who, "invalid"),
                                  appliesTo: BACK });
    const ok = await W.post(id, { security: W.usernameToken(who, PASSWORD),
                                  appliesTo: BACK });
    const bad = await W.post(id, { security: W.usernameToken(who,
                                   "Wrong-" + PASSWORD), appliesTo: BACK });
    K.check("R (" + m + "). a UsernameToken with `invalid` is a wrong " +
            "password's fault" + (product ? ", byte for byte" : ""),
            function () {
              assert.strictEqual(ok.status, 200, ok.text.slice(0, 300));
              assert.strictEqual(ws.status, 500);
              assert.ok(W.carries(ws.text, false, "FailedAuthentication",
                                  W.WST), ws.text.slice(0, 300));
              if (product) {
                assert.strictEqual(bad.status, ws.status);
                assert.strictEqual(bad.text, ws.text);
              } else {
                assert.strictEqual(bad.status, 200, "development checks " +
                                   "no other password: " + bad.status);
              }
            });
  }
  log.debug("Leaving reserved().");
}

// --------------------------------------------------------------------- J
function claimsOf(jwt) {
  log.debug("Entering claimsOf().");
  log.debug("Leaving claimsOf().");
  return K.decode(jwt);
}

async function jwtShape(id, product) {
  log.debug("Entering jwtShape().");
  const m = product ? "product" : "development";
  log.info("=== J. the JWT's structure and claims, " + m + " ===");
  const own = await W.issue(id, "wf-alice", PASSWORD, BACK, W.JWT);
  const d = claimsOf(own.jwt);
  const p = d.payload;
  K.check("J1 (" + m + "). a person's own JWT: typ at+jwt, iss the realm, " +
          "sub urn:uuid, aud the AppliesTo, iat, exp, jti, no client_id, " +
          "no act", function () {
    assert.strictEqual(d.header.typ, "at+jwt");
    assert.strictEqual(p.iss, K.rb(id));
    assert.ok(/^urn:uuid:[0-9a-f-]{36}$/.test(p.sub), p.sub);
    assert.strictEqual(p.aud, BACK);
    assert.ok(p.iat > 0 && p.exp > p.iat && p.jti, JSON.stringify(p));
    assert.strictEqual(p.client_id, undefined);
    assert.strictEqual(p.act, undefined);
  });
  const app = await W.issue(id, "wf-front", SECRET, K.rb(id), W.JWT);
  const ap = claimsOf(app.jwt).payload;
  const clientSub = product ? "urn:sts:client:wf-front" : "wf-front";
  K.check("J2/S1 (" + m + "). an application's own JWT by its secret: " +
          "client_id its own, sub its client subject", function () {
    assert.strictEqual(ap.client_id, "wf-front", JSON.stringify(ap));
    assert.strictEqual(ap.sub, clientSub);
  });
  const nobody = await K.send(K.rb(id) + "/admin-api/users/view?user=" +
                              "wf-front");
  K.check("S4 (" + m + "). no person entry named after the application " +
          "was made", function () {
    assert.ok(nobody.status === 404 || nobody.status === 400,
              nobody.status + " " + nobody.text.slice(0, 200));
  });
  const wrongSecret = await W.post(id, { security: W.usernameToken(
    "wf-front", "not-" + SECRET), appliesTo: K.rb(id), tokenType: W.JWT });
  K.check("S2 (" + m + "). a wrong client secret is " +
          (product ? "refused as a wrong password" : "believed"),
          function () {
            if (product) {
              assert.ok(W.carries(wrongSecret.text, false,
                                  "FailedAuthentication", W.WST),
                        wrongSecret.status + " " +
                        wrongSecret.text.slice(0, 300));
            } else {
              assert.strictEqual(wrongSecret.status, 200);
            }
          });
  const frontSigned = await tokenFor(id, "wf-front");
  const aliceForFront = await tokenFor(id, "wf-alice", FRONT);
  const acted = await W.tokenOf(await W.post(id, { security: frontSigned,
    body: W.actAs(aliceForFront), appliesTo: BACK, tokenType: W.JWT }),
  "ActAs for BACK");
  const a = claimsOf(acted.jwt).payload;
  K.check("J3 (" + m + "). ActAs: client_id the requester, act naming it " +
          "(" + clientSub + ") with this token's iss", function () {
    assert.strictEqual(a.client_id, "wf-front", JSON.stringify(a));
    assert.strictEqual(a.sub, p.sub);
    assert.ok(a.act && a.act.sub === clientSub && a.act.iss === K.rb(id),
              JSON.stringify(a.act));
  });
  // J4: an ActAs of an ActAs ASSERTION, made by wf-back for wf-last.
  const actedSaml = await W.tokenOf(await W.post(id, {
    security: frontSigned, body: W.actAs(aliceForFront), appliesTo: BACK }),
  "ActAs (SAML) for BACK");
  const backSigned = await tokenFor(id, "wf-back");
  const nested = await W.tokenOf(await W.post(id, { security: backSigned,
    body: W.actAs(actedSaml.assertion), appliesTo: LAST, tokenType: W.JWT }),
  "ActAs of an ActAs for LAST");
  const n = claimsOf(nested.jwt).payload;
  K.check("J4 (" + m + "). an ActAs of an ActAs assertion: act nests, the " +
          "current actor outermost, iss at every level", function () {
    const backSub = product ? "urn:sts:client:wf-back" : "wf-back";
    assert.ok(n.act && n.act.sub === backSub && n.act.iss === K.rb(id),
              JSON.stringify(n.act));
    assert.ok(n.act.act && n.act.act.sub === clientSub &&
              n.act.act.iss === K.rb(id), JSON.stringify(n.act));
  });
  K.check("J6 (" + m + "). the SAML assertion an ActAs asks for names the " +
          "requester by its bare identifier in its Delegation Restriction",
          function () {
            assert.ok(/<del:Delegate[^>]*><saml:NameID[^>]*>wf-front</.test(
              actedSaml.assertion), actedSaml.assertion.slice(0, 200));
          });
  const both = await tokenFor(id, "wf-both");
  const obo = await W.tokenOf(await W.post(id, { security: both,
    body: W.onBehalfOf(await tokenFor(id, "wf-alice", null)),
    appliesTo: BACK, tokenType: W.JWT }), "OnBehalfOf for BACK");
  const o = claimsOf(obo.jwt).payload;
  K.check("J5 (" + m + "). OnBehalfOf: client_id the requester, no act",
          function () {
            assert.strictEqual(o.client_id, "wf-both", JSON.stringify(o));
            assert.strictEqual(o.act, undefined);
          });
  // R1, R2: the tier's own JWT as its credential.
  const ownJwt = W.jwtToken(app.jwt);
  const viaJwt = await W.tokenOf(await W.post(id, { security: ownJwt,
    body: W.actAs(aliceForFront), appliesTo: BACK, tokenType: W.JWT }),
  "ActAs on a JWT credential");
  const viaSaml = await W.tokenOf(await W.post(id, { security: ownJwt,
    appliesTo: FRONT }), "an Issue (SAML) on a JWT credential");
  K.check("R1/R2 (" + m + "). a tier's own JWT authenticates it: the " +
          "token issued names it as the client; the assertion states " +
          "PreviousSession", function () {
    assert.strictEqual(claimsOf(viaJwt.jwt).payload.client_id, "wf-front");
    assert.ok(/classes:PreviousSession</.test(viaSaml.assertion),
              viaSaml.assertion.slice(0, 2000));
  });
  // R3 / K2: a JWT that does not verify.
  const parts = app.jwt.split(".");
  const tamperedPayload = Object.assign({}, ap, { sub: "wf-mallory" });
  const tampered = [parts[0], K.b64u(JSON.stringify(tamperedPayload)),
                    parts[2]].join(".");
  const r3 = await W.post(id, { security: W.jwtToken(tampered),
    body: W.actAs(aliceForFront), appliesTo: BACK, tokenType: W.JWT });
  const tamperedAlice = (function () {
    const j = acted.jwt.split(".");
    return [j[0], K.b64u(JSON.stringify(Object.assign({}, a,
      { sub: "urn:uuid:00000000-0000-4000-8000-000000000000" }))), j[2]]
      .join(".");
  })();
  const k2 = await W.post(id, { security: backSigned,
    body: W.actAs(W.jwtToken(tamperedAlice)), appliesTo: LAST,
    tokenType: W.JWT });
  K.check("R3/K2 (" + m + "). a JWT that does not verify, as the " +
          "credential and inside ActAs: " +
          (product ? "refused" : "believed"), function () {
    if (product) {
      assert.ok(W.carries(r3.text, false, "FailedAuthentication", W.WST),
                r3.status + " " + r3.text.slice(0, 300));
      assert.ok(r3.status >= 400 && k2.status >= 400,
                r3.status + " " + k2.status + " " + k2.text.slice(0, 300));
    } else {
      assert.strictEqual(r3.status, 200, r3.text.slice(0, 300));
      assert.strictEqual(k2.status, 200, k2.text.slice(0, 300));
    }
  });
  const r4 = await W.post(id, { body: W.onBehalfOf(ownJwt), appliesTo: BACK,
                                tokenType: W.JWT });
  if (product) {
    K.check("R4 (product). a JWT inside OnBehalfOf is not the requester's " +
            "credential: STS-WSTRUST-0009's fault", function () {
      assert.ok(W.carries(r4.text, false, "FailedAuthentication", W.WST),
                r4.status + " " + r4.text.slice(0, 300));
    });
  }
  // T1, T2: a credential addressed to somebody else; the IdP's own name.
  const t1 = await K.coded(id, "STS-WSTRUST-0032", function () {
    return W.post(id, { security: aliceForFront, appliesTo: BACK,
                        tokenType: W.JWT });
  });
  K.check("T1 (" + m + "). a token about wf-alice addressed to wf-front " +
          "as her credential: " + (product ? "refused, STS-WSTRUST-0032"
                                           : "accepted"), function () {
    if (product) {
      assert.ok(t1.answer.status === 500 && W.carries(t1.answer.text, false,
                "FailedAuthentication", W.WST) && t1.rose >= 1,
                t1.answer.status + " " + t1.rose + " " +
                t1.answer.text.slice(0, 300));
    } else {
      assert.strictEqual(t1.answer.status, 200);
    }
  });
  const t2 = await W.post(id, { security: W.usernameToken("wf-alice",
    PASSWORD), appliesTo: K.rb(id) });
  const t3 = await W.post(id, { security: (W.tokenOf(t2, "T2")).assertion,
    appliesTo: BACK });
  K.check("T2/T3 (" + m + "). an RST addressed to the IdP's own name is " +
          "issued, and that token is accepted as the person's credential",
          function () {
            assert.strictEqual(t2.status, 200, t2.text.slice(0, 300));
            assert.strictEqual(t3.status, 200, t3.text.slice(0, 300));
          });
  log.debug("Leaving jwtShape().");
}

// --------------------------------------------------------------------- S
async function saml11(id, product) {
  log.debug("Entering saml11().");
  const m = product ? "product" : "development";
  log.info("=== S. SAML 1.1 as a token type, " + m + " ===");
  for (const type of [W.SAML11, W.SAML10]) {
    const r = await W.post(id, { security: W.usernameToken("wf-alice",
      PASSWORD), appliesTo: BACK, tokenType: type });
    K.check("T1 (" + m + "). an RST for " + type.replace(/.*[#:]/, "") +
            " is a signed SAML 1.1 assertion: Major 1 Minor 1, the " +
            "subject, the AppliesTo as audience, am:password", function () {
      assert.strictEqual(r.status, 200, r.text.slice(0, 300));
      const a = W.tokenOf(r, "SAML 1.1").inner;
      assert.ok(/MajorVersion="1"/.test(a) && /MinorVersion="1"/.test(a), a
        .slice(0, 300));
      assert.ok(/<(saml:)?Signature|<ds:Signature/.test(a));
      assert.ok(a.indexOf(">wf-alice<") > 0);
      assert.ok(a.indexOf(">" + BACK + "<") > 0, "no audience " + BACK);
      assert.ok(/AuthenticationMethod="urn:oasis:names:tc:SAML:1\.0:am:password"/
        .test(a), a.slice(0, 1500));
      assert.ok(/SAMLAssertionID/.test(r.text), "no AssertionID reference");
    });
  }
  const s11 = W.tokenOf(await W.post(id, { security: W.usernameToken(
    "wf-alice", PASSWORD), appliesTo: FRONT, tokenType: W.SAML11 }),
  "alice's SAML 1.1 for FRONT").inner;
  const frontSigned = await tokenFor(id, "wf-front");
  const acted = await W.post(id, { security: frontSigned,
    body: W.actAs(s11), appliesTo: BACK, tokenType: W.SAML11 });
  K.check("T3/T4 (" + m + "). a SAML 1.1 assertion this realm signed is " +
          "accepted inside ActAs, and the answer names the requester in " +
          "its delegates attribute, with no del:Delegate", function () {
    const a = W.tokenOf(acted, "ActAs SAML 1.1").inner;
    assert.ok(/AttributeName="delegates"/.test(a) &&
              /AttributeNamespace="urn:iya:sts:delegation"/.test(a),
              a.slice(0, 2500));
    assert.ok(a.indexOf("del:Delegate") < 0);
  });
  if (product) {
    await refusal(id, "an unsigned SAML 1.1 assertion inside ActAs",
      { security: frontSigned, body: W.actAs(W.unsigned(s11)),
        appliesTo: BACK }, "STS-WSTRUST-0004", "InvalidRequest");
  }
  log.debug("Leaving saml11().");
}

// --------------------------------------------------------------------- C
function attributes(assertion) {
  log.debug("Entering attributes().");
  const out = {};
  const re = /<saml:Attribute Name="([^"]+)"([^>]*)>([\s\S]*?)<\/saml:Attribute>/g;
  let mm = re.exec(assertion);
  while (mm) {
    const values = [...mm[3].matchAll(/<saml:AttributeValue[^>]*>([^<]*)</g)]
      .map(function (v) {
        return v[1];
      });
    const fmt = (/NameFormat="([^"]+)"/.exec(mm[2]) || [])[1];
    out[mm[1]] = { values: values, nameFormat: fmt };
    mm = re.exec(assertion);
  }
  log.debug("Leaving attributes().");
  return out;
}

async function claimSettings(id, product) {
  log.debug("Entering claimSettings().");
  const m = product ? "product" : "development";
  log.info("=== C. the AppliesTo's claim settings, " + m + " ===");
  const own = claimsOf((await W.issue(id, "wf-alice", PASSWORD, BACK,
                                      W.JWT)).jwt).payload;
  const saml = attributes((await W.issue(id, "wf-alice", PASSWORD, BACK,
                                         W.SAML2)).assertion);
  const front = await tokenFor(id, "wf-front");
  const aliceForFront = await tokenFor(id, "wf-alice", FRONT);
  const actedJwt = claimsOf(W.tokenOf(await W.post(id, { security: front,
    body: W.actAs(aliceForFront), appliesTo: BACK, tokenType: W.JWT }),
  "C3").jwt).payload;
  const actedSaml = attributes(W.tokenOf(await W.post(id, {
    security: front, body: W.actAs(aliceForFront), appliesTo: BACK }),
  "C4").assertion);
  const jwtOk = function (c) {
    assert.ok(Array.isArray(c.teams) && /^cn=wf-team,/.test(c.teams[0]),
              JSON.stringify(c.teams));
    assert.deepStrictEqual(c.roles, ["wf-team-role"]);
    assert.strictEqual(c.tier, "gold-wf-alice");
    assert.strictEqual(c["realm-flag"], "on");
  };
  const samlOk = function (s) {
    assert.ok(s.teams && /^cn=wf-team,/.test(s.teams.values[0]),
              JSON.stringify(s));
    assert.ok(s.roles && s.roles.values.indexOf("wf-team-role") >= 0);
    assert.ok(s["realm-flag"] && s.tier);
    assert.strictEqual(s.tier.nameFormat, BASIC);
  };
  K.check("C1 (" + m + "). a person's own JWT carries the groups claim " +
          "(teams, dn), the roles claim, the application's and the realm's " +
          "custom claims", function () {
    jwtOk(own);
  });
  K.check("C2 (" + m + "). their own SAML 2.0 assertion the same, the " +
          "custom attribute with its NameFormat", function () {
    samlOk(saml);
  });
  K.check("C3/C4 (" + m + "). an ActAs JWT and assertion describe the " +
          "SUBJECT the same way", function () {
    jwtOk(actedJwt);
    samlOk(actedSaml);
  });
  const expected = product ? "api.read" : "api.read api.undeclared";
  K.check("S1 (" + m + "). wstrustJwtScope is carried as judged: \"" +
          expected + "\" (admin:write protected in every mode)", function () {
    assert.strictEqual(own.scope, expected);
  });
  const plain = claimsOf((await W.issue(id, "wf-alice", PASSWORD, PLAIN,
                                        W.JWT)).jwt).payload;
  K.check("S2/S3 (" + m + "). an application with no wstrustJwtScope " +
          "issues no scope; the SAML assertion carries none", function () {
    assert.strictEqual(plain.scope, undefined);
    assert.ok(!saml.scope && JSON.stringify(saml).indexOf("api.read") < 0);
  });
  log.debug("Leaving claimSettings().");
}

// --------------------------------------------------------------------- W
async function scopeWarnings(id, product) {
  log.debug("Entering scopeWarnings().");
  const m = product ? "product" : "development";
  log.info("=== W. a wstrustJwtScope the policy will drop (#488), " + m +
           " ===");
  const ident = "wf-scoped-" + K.rand(3);
  await api(id, "/applications/create", { identifier: ident, name: ident,
    protocols: ["wstrust"], fields: { oauthClientId: [ident],
      wstrustAppliesTo: [URL_OF(ident)] } });
  const added = await K.send(K.rb(id) + "/admin-api/applications/add",
    { json: { application: ident, attribute: "wstrustJwtScope",
              value: "api.unknown" } });
  const added2 = await K.send(K.rb(id) + "/admin-api/applications/add",
    { json: { application: ident, attribute: "wstrustJwtScope",
              value: "admin:write" } });
  const said = JSON.stringify(added2.json && added2.json.warnings);
  K.check("W1 (" + m + "). both written; the reply warns of the undeclared " +
          "and the protected scope, saying WARNING and how to resolve it",
          function () {
            assert.strictEqual(added.status, 200, added.text.slice(0, 300));
            assert.ok(added2.json && added2.json.ok, added2.text);
            assert.ok(/api\.unknown/.test(said) && /admin:write/.test(said),
                      said);
            assert.ok(/WARNING/.test(String(added2.json.message || "")),
                      added2.text.slice(0, 500));
            // Product says it IS dropped; development that product would.
            assert.ok(product ? /is dropped from the JWT/.test(said)
                              : /PRODUCT/.test(said), said);
          });
  const view = await K.send(K.rb(id) + "/admin-api/applications?" +
                            "application=" + ident);
  const viewSaid = JSON.stringify((view.json || {}).warnings || null);
  K.check("W3 (" + m + "). the application's view carries the same " +
          "warnings", function () {
    assert.ok(/api\.unknown/.test(viewSaid) &&
              /admin:write/.test(viewSaid), view.status + " " +
              view.text.slice(0, 600));
  });
  const updated = await K.send(K.rb(id) +
    "/admin-api/applications/update-fields", { json: { application: ident,
      fields: { wstrustJwtScope: ["api.unknown", "admin:write"] } } });
  K.check("W2 (" + m + "). update-fields says the same", function () {
    const s = JSON.stringify(updated.json && updated.json.warnings);
    assert.ok(/api\.unknown/.test(s) && /admin:write/.test(s),
              updated.status + " " + updated.text.slice(0, 400));
  });
  await api(id, "/applications/add", { application: ident,
    attribute: "oauthAllowedScope", value: "api.unknown" });
  const declared = await K.send(K.rb(id) + "/admin-api/applications/" +
    "update-fields", { json: { application: ident,
      fields: { wstrustJwtScope: ["api.unknown", "admin:write"] } } });
  K.check("W4 (" + m + "). declared on oauthAllowedScope, the undeclared " +
          "warning goes and the protected one stays", function () {
    const s = JSON.stringify(declared.json && declared.json.warnings);
    assert.ok(!/api\.unknown/.test(s) && /admin:write/.test(s), s);
  });
  const emptied = await K.send(K.rb(id) + "/admin-api/applications/" +
    "update-fields", { json: { application: ident,
      fields: { wstrustJwtScope: [] } } });
  K.check("W5 (" + m + "). with the field empty there is no warning",
          function () {
            assert.strictEqual(emptied.status, 200, emptied.text);
            assert.ok(!emptied.json.warnings ||
                      emptied.json.warnings.length === 0, emptied.text);
          });
  log.debug("Leaving scopeWarnings().");
}

async function test() {
  log.debug("Entering test().");
  const P = await K.realm("wr-p", "product",
                          { "authn.allowOptionalSecondFactor": "true" });
  const D = await K.realm("wr-d", "development");
  await fixtures(P);
  await fixtures(D);
  await faults(P, D);
  await reserved(P, D);
  for (const [id, product] of [[D, false], [P, true]]) {
    await jwtShape(id, product);
    await saml11(id, product);
    await claimSettings(id, product);
    await scopeWarnings(id, product);
  }
  log.debug("Leaving test().");
}

K.main(test, 90);
