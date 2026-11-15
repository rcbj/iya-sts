// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_saml_family_rules.js
//
// ===========================================================================
// THE SAML / WS-TRUST / WS-FEDERATION HALF OF THE 2026-09-12 HARD-CODED-
// VALUES SWEEP, OVER THE WIRE (#444 D12, phase 7).
//
// `tests/saml_family_hardcoded.js` calls the handlers off the router with
// the mode flipped per call. Here a development realm D and a product realm
// P of the job's own answer the same requests over HTTP:
//
//   B. where a response may be delivered (its B and H): development sends an
//      unregistered AssertionConsumerServiceURL on to the sign-in screen;
//      product refuses it on a 400 page naming the attribute to register it
//      on and the address the request sent — never the registered addresses
//      nor how many (#1331) — compares exactly (a `/../` is not a prefix
//      match), takes a registered one, and refuses a provider with nothing
//      registered; WS-Federation the same for `wreply` (`wsfedReplyUrl`).
//      The SAML 2.0 entityID is the realm's one issuer in both modes (#523).
//   C. `saml.signatureAlgorithm` rsa-sha384 reaches the SAML 2.0 and SAML 1.1
//      assertions' SignatureMethod; the default is RSA-SHA256;
//      `saml.organizationName` emptied omits <md:Organization>, and the
//      default names the product.
//   E. WS-Trust: development issues for no credential and the assertion
//      claims no password (`unspecified`); product accepts an assertion THIS
//      STS signed as the credential and the token says PreviousSession;
//      development's anonymous OnBehalfOf issues; a year-long wst:Lifetime is
//      clamped to `wstrust.maxTokenLifetimeMin`; `wstrust.jwtAlgorithm` ES256
//      signs the JWT, with a kid and a jti.
//   G. the SAML 1.1 responder: development answers an AttributeQuery with
//      attributes and NO AuthenticationStatement; an AuthenticationQuery
//      about somebody who never signed in is Success with no assertion; one
//      about a real session states how it authenticated (am:password);
//      product refuses an unauthenticated AttributeQuery (Requester).
//   I. the WS-Federation metadata describes what each mode emits: the claim
//      descriptions differ between D and P.
//
// NOT HERE: A (the session's class for a certificate, a Kerberos ticket and a
// federated sign-in, each a sign-in of its own kind in the same browser:
// owed), D (the
// builders' defaults as functions), F (federation: owed with the stand-in
// partner jobs), I's `federation.outbound` (a process-wide switch, which a
// non-exclusive job does not turn).
//
// OWNED HERE (local: true). Its realms are removed only on a private probe.
// ===========================================================================

const assert = require("assert");
const K = require("./oauth_wire_kit.js").kit("sts_saml_family_rules");
const S = require("./saml_wire_kit.js").samlKit(K);
const W = require("./wstrust_wire_kit.js").wsKit(K);

const log = K.log;
const PASSWORD = "Sfr-Passw0rd!-" + K.rand(4);
const NS_SAMLP11 = "urn:oasis:names:tc:SAML:1.0:protocol";
const NS_SAML11 = "urn:oasis:names:tc:SAML:1.0:assertion";
const RSA_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
let D = null;
let P = null;
let CRED = null;

function id(label) {
  log.debug("Entering id().");
  log.debug("Leaving id().");
  return "sfr-" + label + "-" + K.STAMP;
}

async function sp(realm, label, acs) {
  log.debug("Entering sp(). " + label);
  const identifier = id(label);
  await K.ok(K.rb(realm) + "/admin-api/applications/create", {
    identifier: identifier, name: label, protocols: ["saml2"],
    fields: Object.assign({ samlEntityId: [identifier],
                            samlSigningCertificate: [CRED.certificatePem] },
    acs ? { samlAssertionConsumerService: [].concat(acs) } : {}) },
  "created " + label);
  log.debug("Leaving sp().");
  return identifier;
}

function authnAt(realm, issuer, acs) {
  log.debug("Entering authnAt().");
  const built = S.authnRequestXml({ issuer: issuer, acs: acs || undefined,
    destination: K.rb(realm) + "/saml2/sso" });
  log.debug("Leaving authnAt().");
  return S.redirect(K.rb(realm) + "/saml2/sso", built.xml, { sign: CRED });
}

function text(r) {
  log.debug("Entering text().");
  log.debug("Leaving text().");
  return String(r.text || "").replace(/<style[\s\S]*?<\/style>/g, "")
    .replace(/<[^>]*>/g, " ").replace(/\s+/g, " ");
}

// --------------------------------------------------------------------- B
async function delivery() {
  log.debug("Entering delivery().");
  log.info("=== B. where a response may be delivered ===");
  const devSp = await sp(D, "dev-sp", null);
  const dev = await K.send(authnAt(D, devSp, "https://anywhere-" + K.STAMP +
                                             ".example/acs"));
  K.check("B1. development: an unregistered AssertionConsumerServiceURL " +
          "goes on to the sign-in screen", function () {
    assert.ok(K.toSignIn(dev), K.shown(dev));
  });
  const reg = "https://sp-" + K.STAMP + ".example/acs";
  const prodSp = await sp(P, "prod-sp", [reg, reg + "2"]);
  const evil = "https://evil-" + K.STAMP + ".example/acs";
  const refused = await K.send(authnAt(P, prodSp, evil));
  K.check("B2. PRODUCT: an address not registered is refused on a 400 " +
          "page naming the attribute to register it on and the address " +
          "sent", function () {
    assert.strictEqual(refused.status, 400, K.shown(refused));
    assert.ok(/samlAssertionConsumerService/.test(text(refused)),
              text(refused).slice(0, 600));
    assert.ok(text(refused).indexOf(evil) >= 0, text(refused).slice(0, 600));
  });
  K.check("B3. and it names neither the registered addresses nor their " +
          "number (#1331)", function () {
    const at = text(refused).indexOf(reg);
    assert.ok(at < 0, text(refused).slice(Math.max(0, at - 300), at + 200));
    assert.ok(!/address\(es\)/.test(text(refused)));
  });
  const dotted = await K.send(authnAt(P, prodSp, reg.replace(/acs$/,
                                                             "acs/../x")));
  K.check("B4. the comparison is exact, not a prefix", function () {
    assert.strictEqual(dotted.status, 400, K.shown(dotted));
  });
  const good = await K.send(authnAt(P, prodSp, reg));
  K.check("B5. a registered address is taken, on to the sign-in screen",
          function () {
            assert.ok(K.toSignIn(good), K.shown(good));
          });
  const none = await K.send(authnAt(P, prodSp, null));
  K.check("B6. and with none named, the registered one", function () {
    assert.ok(K.toSignIn(none), K.shown(none));
  });
  const bare = await sp(P, "prod-bare", null);
  const nothing = await K.send(authnAt(P, bare, null));
  K.check("B7. PRODUCT: with nothing registered it is refused", function () {
    assert.ok(nothing.status >= 400, K.shown(nothing));
    assert.ok(!K.toSignIn(nothing));
  });

  // WS-Federation's wreply.
  const devRp = id("dev-rp");
  await K.ok(K.rb(D) + "/admin-api/applications/create", { identifier: devRp,
    name: devRp, protocols: ["wsfed"], fields: {} }, "created " + devRp);
  const wsDev = await K.send(K.rb(D) + "/wsfed?" + new URLSearchParams({
    wa: "wsignin1.0", wtrealm: devRp,
    wreply: "https://attacker-" + K.STAMP + ".example/reply" }));
  K.check("B8. development: an unregistered wreply goes on to the sign-in " +
          "screen", function () {
    assert.ok(K.toSignIn(wsDev), K.shown(wsDev));
  });
  const prodRp = id("prod-rp");
  await K.ok(K.rb(P) + "/admin-api/applications/create", {
    identifier: prodRp, name: prodRp, protocols: ["wsfed"], fields: {} },
  "created " + prodRp);
  const wsProd = await K.send(K.rb(P) + "/wsfed?" + new URLSearchParams({
    wa: "wsignin1.0", wtrealm: prodRp,
    wreply: "https://attacker-" + K.STAMP + ".example/reply" }));
  K.check("B9. PRODUCT: an unregistered wreply is refused, 400, naming " +
          "wsfedReplyUrl", function () {
    assert.strictEqual(wsProd.status, 400, K.shown(wsProd));
    assert.ok(/wsfedReplyUrl/.test(text(wsProd)), text(wsProd).slice(0, 600));
  });

  for (const [label, realm] of [["development", D], ["product", P]]) {
    const md = (await K.send(K.rb(realm) + "/saml2/metadata")).text;
    const oidc = await K.send(K.rb(realm) +
                              "/.well-known/openid-configuration");
    K.check("B10 (" + label + "). the SAML 2.0 entityID is the realm's one " +
            "issuer (#523)", function () {
      assert.strictEqual((/entityID="([^"]+)"/.exec(md) || [])[1],
                         (oidc.json || {}).issuer, md.slice(0, 300));
    });
  }
  log.debug("Leaving delivery().");
}

// --------------------------------------------------------------------- C
async function algorithms() {
  log.debug("Entering algorithms().");
  log.info("=== C. the configured signature algorithm, the organisation ===");
  const s2 = await sp(D, "alg-sp", ["https://alg-" + K.STAMP +
                                    ".example/acs"]);
  const rp = id("alg-rp");
  await K.ok(K.rb(D) + "/admin-api/applications/create", { identifier: rp,
    name: rp, protocols: ["saml11"], fields: { samlEntityId: [rp],
    samlAssertionConsumerService: ["https://" + rp + ".example/shire"] } },
  "created " + rp);
  const b = K.browser();
  const before = await S.drive(D, b, authnAt(D, s2, null),
                               { username: "sfr-alice" });
  K.check("C1. by default the assertion is signed RSA-SHA256", function () {
    assert.ok(before.response, K.shown(before.final));
    assert.ok(/SignatureMethod Algorithm="[^"]*rsa-sha256"/
      .test(before.response.xml), before.response.xml.slice(0, 600));
  });
  await K.set(D, "saml.signatureAlgorithm", "rsa-sha384");
  const after = await S.drive(D, b, authnAt(D, s2, null),
                              { username: "sfr-alice" });
  K.check("C2. saml.signatureAlgorithm rsa-sha384 reaches the SAML 2.0 " +
          "signature's SignatureMethod", function () {
    assert.ok(after.response, K.shown(after.final));
    assert.ok(after.response.xml.indexOf('SignatureMethod Algorithm="' +
                                         RSA_SHA384 + '"') >= 0,
    after.response.xml.slice(0, 600));
  });
  const s11 = await S.drive(D, b, K.rb(D) + "/saml11/sso?" +
    new URLSearchParams({ providerId: rp,
      shire: "https://" + rp + ".example/shire",
      TARGET: "https://" + rp + ".example/app" }).toString(),
  { username: "sfr-alice" });
  const xml11 = S.messageOf(s11.final.text);
  K.check("C3. and the SAML 1.1 builder reads the same setting",
          function () {
            assert.ok(xml11.indexOf('SignatureMethod Algorithm="' +
                                    RSA_SHA384 + '"') >= 0,
            K.shown(s11.final));
          });
  await K.unset(D, "saml.signatureAlgorithm");
  const md = (await K.send(K.rb(D) + "/saml2/metadata")).text;
  await K.set(D, "saml.organizationName", "");
  const emptied = (await K.send(K.rb(D) + "/saml2/metadata")).text;
  K.check("C4. an emptied saml.organizationName omits <md:Organization> " +
          "entirely, and the default names the product, sts", function () {
    assert.ok(/<md:OrganizationName xml:lang="en">sts</.test(md),
              md.slice(0, 300));
    assert.ok(!/<md:Organization\b/.test(emptied), emptied.slice(0, 300));
  });
  await K.unset(D, "saml.organizationName");
  log.debug("Leaving algorithms().");
}

// --------------------------------------------------------------------- E
async function wsTrust() {
  log.debug("Entering wsTrust().");
  log.info("=== E. WS-Trust ===");
  const to = {};
  for (const realm of [D, P]) {
    to[realm] = "https://sfr-rp-" + K.STAMP + ".example/" + realm;
    await K.ok(K.rb(realm) + "/admin-api/applications/create", {
      identifier: id("ws-" + (realm === D ? "d" : "p")), protocols:
        ["wstrust"], fields: { wstrustAppliesTo: [to[realm]] } },
    "registered the AppliesTo");
  }
  const anon = await W.post(D, { appliesTo: to[D] });
  K.check("E1. development: a request with no credential still issues, " +
          "and the assertion claims no password sign-in for it", function () {
    const t = W.tokenOf(anon, "the anonymous Issue");
    assert.ok(/ac:classes:unspecified/.test(t.inner), t.inner.slice(0, 600));
    assert.ok(!/PasswordProtectedTransport/.test(t.inner));
  });
  const own = await W.issue(P, "sfr-alice", PASSWORD, K.rb(P), W.SAML2);
  const prev = await W.post(P, { security: own.assertion,
                                 appliesTo: to[P] });
  K.check("E2. PRODUCT: an assertion THIS STS signed is accepted as the " +
          "credential, and the token it issues says PreviousSession",
          function () {
            const t = W.tokenOf(prev, "the assertion-credential Issue");
            assert.ok(/PreviousSession/.test(t.inner), t.inner.slice(0, 600));
          });
  const devOwn = await W.issue(D, "sfr-alice", PASSWORD, K.rb(D), W.SAML2);
  const obo = await W.post(D, { appliesTo: to[D],
                                body: W.onBehalfOf(devOwn.assertion) });
  K.check("E3. development: an anonymous delegation (OnBehalfOf, no " +
          "requester) still issues", function () {
    W.tokenOf(obo, "the anonymous delegation");
  });
  const life = '<wst:Lifetime xmlns:wsu="http://docs.oasis-open.org/wss/' +
    '2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"><wsu:Created>' +
    new Date().toISOString() + "</wsu:Created><wsu:Expires>" +
    new Date(Date.now() + 365 * 86400000).toISOString() +
    "</wsu:Expires></wst:Lifetime>";
  // A cap of its own, so the bound is the job's number and not a default.
  const cap = 30;
  await K.set(D, "wstrust.maxTokenLifetimeMin", cap);
  const long = await W.post(D, { security: W.usernameToken("sfr-alice",
    PASSWORD), appliesTo: to[D], body: life });
  K.check("E4. a year-long wst:Lifetime is CLAMPED to " +
          "wstrust.maxTokenLifetimeMin, in development too", function () {
    assert.strictEqual(long.status, 200, K.shown(long));
    const exp = /<wsu:Expires>([^<]+)</.exec(long.text);
    const minutes = (Date.parse(exp[1]) - Date.now()) / 60000;
    assert.ok(minutes <= cap + 1, "issued for " + Math.round(minutes) +
              " minutes against a cap of " + cap);
  });
  await K.unset(D, "wstrust.maxTokenLifetimeMin");
  await K.set(D, "wstrust.jwtAlgorithm", "ES256");
  const jwt = await W.issue(D, "sfr-alice", PASSWORD, to[D], W.JWT);
  const header = K.decode(jwt.jwt).header || {};
  const payload = K.decode(jwt.jwt).payload || {};
  K.check("E5. the WS-Trust JWT is signed with wstrust.jwtAlgorithm ES256, " +
          "names its key, and carries a jti", function () {
    assert.strictEqual(header.alg, "ES256", JSON.stringify(header));
    assert.ok(header.kid, JSON.stringify(header));
    assert.ok(typeof payload.jti === "string" && payload.jti.length > 10,
              JSON.stringify(payload));
  });
  await K.unset(D, "wstrust.jwtAlgorithm");
  log.debug("Leaving wsTrust().");
}

// --------------------------------------------------------------------- G
function soap11(inner) {
  log.debug("Entering soap11().");
  log.debug("Leaving soap11().");
  return '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/' +
    'envelope/"><soap:Body><samlp:Request xmlns:samlp="' + NS_SAMLP11 +
    '" xmlns:saml="' + NS_SAML11 + '" MajorVersion="1" MinorVersion="1" ' +
    'RequestID="_q' + K.rand(8) + '" IssueInstant="' +
    new Date().toISOString() + '">' + inner + "</samlp:Request>" +
    "</soap:Body></soap:Envelope>";
}

function ask11(realm, inner) {
  log.debug("Entering ask11().");
  log.debug("Leaving ask11().");
  return K.send(K.rb(realm) + "/saml11/responder", { raw: soap11(inner),
    headers: { "Content-Type": "text/xml; charset=utf-8" } });
}

async function responder() {
  log.debug("Entering responder().");
  log.info("=== G. the SAML 1.1 responder's queries ===");
  const rp = id("aq-rp");
  for (const realm of [D, P]) {
    await K.ok(K.rb(realm) + "/admin-api/applications/create", {
      identifier: rp, name: rp, protocols: ["saml11"],
      fields: { samlEntityId: [rp], samlAssertionConsumerService:
        ["https://" + rp + ".example/shire"] } }, "created " + rp);
  }
  const attributeQuery = '<samlp:AttributeQuery Resource="' + rp + '">' +
    "<saml:Subject><saml:NameIdentifier>sfr-erin</saml:NameIdentifier>" +
    "</saml:Subject></samlp:AttributeQuery>";
  const devAttr = await ask11(D, attributeQuery);
  K.check("G1. development: an AttributeQuery is answered with its " +
          "attributes, and CLAIMS NO AUTHENTICATION", function () {
    assert.ok(/samlp:Success/.test(devAttr.text), devAttr.text.slice(0, 400));
    assert.ok(/AttributeStatement/.test(devAttr.text),
              devAttr.text.slice(0, 600));
    assert.ok(!/AuthenticationStatement/.test(devAttr.text));
  });
  const authQuery = function (name) {
    log.debug("Entering authQuery().");
    log.debug("Leaving authQuery().");
    return "<samlp:AuthenticationQuery><saml:Subject><saml:NameIdentifier>" +
      name + "</saml:NameIdentifier></saml:Subject>" +
      "</samlp:AuthenticationQuery>";
  };
  const nobody = await ask11(D, authQuery("sfr-never-" + K.STAMP));
  K.check("G2. an AuthenticationQuery about somebody who never signed in " +
          "is Success with NO assertion", function () {
    assert.ok(/samlp:Success/.test(nobody.text), nobody.text.slice(0, 400));
    assert.ok(!/<saml:Assertion/.test(nobody.text));
    assert.ok(/no authentication is recorded/.test(nobody.text),
              nobody.text.slice(0, 400));
  });
  const b = K.browser();
  await S.drive(D, b, K.rb(D) + "/saml11/sso?" + new URLSearchParams({
    providerId: rp, shire: "https://" + rp + ".example/shire",
    TARGET: "https://" + rp + ".example/app" }).toString(),
  { username: "sfr-erin" });
  const real = await ask11(D, authQuery("sfr-erin"));
  K.check("G3. and one about a real session states how THAT session " +
          "authenticated (am:password)", function () {
    assert.ok(/AuthenticationMethod="urn:oasis:names:tc:SAML:1.0:am:password"/
      .test(real.text), real.text.slice(0, 600));
  });
  const prodAttr = await ask11(P, attributeQuery);
  K.check("G4. PRODUCT: an unauthenticated AttributeQuery is refused, " +
          "Requester", function () {
    assert.ok(/samlp:Requester/.test(prodAttr.text),
              prodAttr.text.slice(0, 400));
    assert.ok(!/AttributeStatement/.test(prodAttr.text));
  });
  log.debug("Leaving responder().");
}

// --------------------------------------------------------------------- I
async function metadataHonesty() {
  log.debug("Entering metadataHonesty().");
  log.info("=== I. WS-Federation metadata describes what each mode emits ===");
  const dev = (await K.send(K.rb(D) +
    "/FederationMetadata/2007-06/FederationMetadata.xml")).text;
  const prod = (await K.send(K.rb(P) +
    "/FederationMetadata/2007-06/FederationMetadata.xml")).text;
  const descriptions = function (doc) {
    log.debug("Entering descriptions().");
    const out = [];
    String(doc).replace(/<auth:Description>([^<]*)</g, function (all, one) {
      out.push(one);
      return all;
    });
    log.debug("Leaving descriptions().");
    return out.join("|");
  };
  K.check("I1. development's claim descriptions say the values are " +
          "invented, product's do not", function () {
    assert.ok(/Mock/.test(descriptions(dev)), descriptions(dev)
      .slice(0, 400) || dev.slice(0, 400));
    assert.ok(!/Always (&quot;|")Mock/.test(descriptions(prod)),
              descriptions(prod).slice(0, 400));
    assert.notStrictEqual(descriptions(dev), descriptions(prod));
  });
  log.debug("Leaving metadataHonesty().");
}

async function test() {
  log.debug("Entering test().");
  D = await K.realm("sfr-d", "development");
  P = await K.realm("sfr-p", "product",
                    { "authn.allowOptionalSecondFactor": "true" });
  CRED = await S.credential("sfr-sp");
  for (const realm of [D, P]) {
    for (const who of ["sfr-alice", "sfr-erin"]) {
      await K.person(realm, who, PASSWORD);
    }
  }
  await delivery();
  await algorithms();
  await wsTrust();
  await responder();
  await metadataHonesty();
  log.debug("Leaving test().");
}

K.main(test, 25);
