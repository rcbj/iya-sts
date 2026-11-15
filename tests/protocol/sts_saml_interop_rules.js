// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_saml_interop_rules.js
//
// ===========================================================================
// WHAT THE SAML INTEROPERABILITY HARNESSES FOUND, AND SINGLE LOGOUT'S
// SIGNATURES, OVER THE WIRE (#189–#192, #37; #444 D12, phase 7).
//
// The rest of `tests/saml_interop_findings.js` and of
// `tests/saml_request_signatures.js` (whose other sections
// `sts_saml_sso_rules.js` and `sts_saml_signatures.js` carry), against a
// development realm D and a product realm P of the job's own:
//
//   A. a LogoutRequest whose Destination is another address is refused, 400,
//      STS-SAML-0085.
//   C. identity-provider-initiated logout: the LogoutRequest the sign-out's
//      answer links to is signed on the Redirect binding's QUERY STRING
//      (verified here with the realm's metadata certificate), carries no
//      enveloped signature, and names the NameID the session's Response
//      gave that service provider.
//   D. `/saml2/unsolicited`: no provider named (STS-SAML-0092), a Response
//      on HTTP-Redirect (0093), product's unregistered provider (404, 0082);
//      with a session an UNSOLICITED Response — no InResponseTo — to the
//      registered consumer with the target as RelayState, carrying the
//      X.500/LDAP names (urn:oid:0.9.2342.19200300.100.1.1, FriendlyName
//      uid); an unregistered shire delivered in development and refused in
//      product.
//   E. product's attribute authority refuses an unauthenticated caller
//      (STS-SAML-0077).
//   G. SAML 1.1 for Shibboleth: the lower-case `target` comes back as
//      TARGET; no DoNotCacheCondition by default and one with
//      `saml11.doNotCacheCondition`; uid named as Shibboleth's map reads it;
//      product's responder refuses a query for an unregistered relying party
//      (0039), an unauthenticated caller, a subject no live session gave it
//      (0096), and ANSWERS the relying party authenticated by its registered
//      certificate as the TLS client certificate.
//   I. Single Logout's signatures: a signed LogoutRequest is answered at the
//      consumed ResponseLocation with a LogoutResponse; one tampered after
//      signing (0061, "NOT ended"); an unsigned one where signing is
//      required (product, 0063); development answers an unsigned one from a
//      provider that need not sign; a LogoutResponse signed by the wrong key
//      (0061).
//   J. the console's actions through `/admin-api/saml2`: a value that is
//      not a certificate (STS-REG-0160), a PEM registered as base64 DER, set
//      REPLACES, remove by PEM, an unknown action naming all eleven.
//
// NOT HERE: H (a partner's value under two names: owed with the federation
// partner jobs); J's `verifyQueryString()` and the absence of an implicit
// certificate (functions, class (d)).
//
// OWNED HERE (local: true). Its realms are removed only on a private probe.
// ===========================================================================

const assert = require("assert");
const https = require("https");
const zlib = require("zlib");
const nodeCrypto = require("crypto");
const K = require("./oauth_wire_kit.js").kit("sts_saml_interop_rules");
const S = require("./saml_wire_kit.js").samlKit(K);

const log = K.log;
const PASSWORD = "Sir-Passw0rd!-" + K.rand(4);
const NS_MD = "urn:oasis:names:tc:SAML:2.0:metadata";
const NS_SAMLP11 = "urn:oasis:names:tc:SAML:1.0:protocol";
const NS_SAML11 = "urn:oasis:names:tc:SAML:1.0:assertion";
const B_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
let D = null;
let P = null;
let A = null;
let B = null;

function name(label) {
  log.debug("Entering name().");
  log.debug("Leaving name().");
  return "sir-" + label + "-" + K.STAMP;
}

async function sp(realm, label, cred, fields) {
  log.debug("Entering sp(). " + label);
  const identifier = name(label);
  await K.ok(K.rb(realm) + "/admin-api/applications/create", {
    identifier: identifier, name: label, protocols: ["saml2"],
    fields: Object.assign({ samlEntityId: [identifier],
      samlAssertionConsumerService: ["https://" + identifier +
                                     ".example/acs"] },
    cred ? { samlSigningCertificate: [cred.certificatePem] } : {},
    fields || {}) }, "created " + label);
  log.debug("Leaving sp().");
  return identifier;
}

function logoutRequest(realm, issuer, nameId, destination) {
  log.debug("Entering logoutRequest().");
  log.debug("Leaving logoutRequest().");
  return '<samlp:LogoutRequest xmlns:samlp="' + S.NS_SAMLP + '" ' +
    'xmlns:saml="' + S.NS_SAML + '" ID="_lr' + K.rand(8) + '" ' +
    'Version="2.0" IssueInstant="' + new Date().toISOString() +
    '" Destination="' + (destination || K.rb(realm) + "/saml2/slo") +
    '"><saml:Issuer>' + issuer + "</saml:Issuer><saml:NameID>" + nameId +
    "</saml:NameID></samlp:LogoutRequest>";
}

function inflated(url, param) {
  log.debug("Entering inflated().");
  const v = new URL(url).searchParams.get(param || "SAMLRequest") || "";
  log.debug("Leaving inflated().");
  return v ? zlib.inflateRawSync(Buffer.from(v, "base64")).toString("utf8")
           : "";
}

async function signingCerts(realm) {
  log.debug("Entering signingCerts().");
  const md = (await K.send(K.rb(realm) + "/saml2/metadata")).text;
  const idp = md.slice(md.indexOf("<md:IDPSSODescriptor"),
                       md.indexOf("</md:IDPSSODescriptor>"));
  const out = [];
  idp.replace(/<md:KeyDescriptor use="signing">[\s\S]*?<ds:X509Certificate>([^<]+)</g,
    function (all, one) {
      out.push(one.replace(/\s+/g, ""));
      return all;
    });
  log.debug("Leaving signingCerts(). " + out.length);
  return out;
}

// A Redirect-binding query signature verified with any of `certs`, over the
// query's own octets as sent (saml-bindings-2.0-os 3.4.4.1).
function queryVerifies(url, certs) {
  log.debug("Entering queryVerifies().");
  const q = new URL(url).search.slice(1);
  const parts = q.split("&");
  const pick = function (key) {
    log.debug("Entering pick().");
    log.debug("Leaving pick().");
    return parts.filter(function (p) {
      return p.indexOf(key + "=") === 0;
    })[0] || "";
  };
  const octets = [pick("SAMLRequest"), pick("RelayState"), pick("SigAlg")]
    .filter(function (p) {
      return p;
    }).join("&");
  const sigAlg = decodeURIComponent(pick("SigAlg").split("=")[1] || "");
  const signature = Buffer.from(decodeURIComponent(
    pick("Signature").split("=")[1] || ""), "base64");
  const hash = /sha512$/.test(sigAlg) ? "sha512"
    : (/sha384$/.test(sigAlg) ? "sha384" : "sha256");
  const ok = certs.some(function (b64) {
    const pem = "-----BEGIN CERTIFICATE-----\n" +
      b64.replace(/(.{64})/g, "$1\n") + "\n-----END CERTIFICATE-----\n";
    try {
      const key = new nodeCrypto.X509Certificate(pem).publicKey;
      return nodeCrypto.verify(hash, Buffer.from(octets, "utf8"),
        /ecdsa/.test(sigAlg) ? { key: key, dsaEncoding: "der" } : key,
        signature);
    } catch (e) {
      log.debug("Caught in queryVerifies(): " + ((e && e.message) || e));
      // A certificate this job cannot read verifies nothing.
      return false;
    }
  });
  log.debug("Leaving queryVerifies(). " + ok);
  return ok;
}

async function codeRose(ids, code, act) {
  log.debug("Entering codeRose(). " + code);
  const before = [];
  for (const one of ids) {
    before.push(await K.codeCount(one, code));
  }
  const answer = await act();
  let rose = 0;
  for (let i = 0; i < 20 && rose === 0; i += 1) {
    rose = 0;
    for (let j = 0; j < ids.length; j += 1) {
      rose += (await K.codeCount(ids[j], code)) - before[j];
    }
    if (rose === 0) {
      await K.sleep(150);
    }
  }
  log.debug("Leaving codeRose(). " + rose);
  return { answer: answer, rose: rose };
}

function refusedWith(label, c, status, code) {
  log.debug("Entering refusedWith().");
  K.check(label + ": " + status + ", " + code, function () {
    assert.strictEqual(c.answer.status, status, K.shown(c.answer));
    assert.ok(c.rose >= 1, "no new " + code + " row");
  });
  log.debug("Leaving refusedWith().");
}

// ------------------------------------------------------------------- A, C
async function logoutLinks() {
  log.debug("Entering logoutLinks().");
  log.info("=== A. a LogoutRequest's Destination; C. the logout link ===");
  const spA = await sp(D, "slo-a", null, { samlSingleLogoutService:
    ["https://" + name("slo-a") + ".example/slo"] });
  const c = await codeRose([D, null], "STS-SAML-0085", function () {
    return K.send(K.rb(D) + "/saml2/slo", { form: { SAMLRequest:
      Buffer.from(logoutRequest(D, spA, "nobody",
        "https://elsewhere-" + K.STAMP + ".example/slo"), "utf8")
        .toString("base64") } });
  });
  refusedWith("A1. a LogoutRequest addressed elsewhere is REFUSED and ends " +
              "nothing", c, 400, "STS-SAML-0085");
  const b = K.browser();
  const f = await S.drive(D, b, S.redirect(K.rb(D) + "/saml2/sso",
    S.authnRequestXml({ issuer: spA, acs: "https://" + spA + ".example/acs",
                        destination: K.rb(D) + "/saml2/sso" }).xml),
  { username: "sir-cora" });
  const given = (/<saml:NameID[^>]*>([^<]+)</.exec(
    (f.response || {}).xml || "") || [])[1];
  const out = await b.go(K.rb(D) + "/logout", { method: "POST",
    raw: JSON.stringify({ scope: "global" }),
    headers: { "content-type": "application/json",
               accept: "application/json", origin: K.base } });
  const link = (((out.json || {}).logoutRequests || []).filter(
    function (one) {
      return one.entityId === spA;
    })[0] || {}).url || "";
  const sent = link ? inflated(link) : "";
  const certs = await signingCerts(D);
  K.check("C1. the sign-out names a LogoutRequest for the provider, signed " +
          "on the QUERY STRING with the realm's metadata certificate, and " +
          "carrying no enveloped signature (saml-bindings-2.0-os 3.4.4.1)",
          function () {
            assert.ok(link, JSON.stringify(out.json || out.text)
              .slice(0, 400));
            const u = new URL(link);
            assert.ok(u.searchParams.get("SigAlg") &&
                      u.searchParams.get("Signature"), link.slice(0, 200));
            assert.ok(!/<ds:Signature/.test(sent), sent.slice(0, 400));
            assert.ok(queryVerifies(link, certs), "the query signature " +
                      "does not verify with " + certs.length + " cert(s)");
          });
  K.check("C2. and names the NameID the session GAVE that provider",
          function () {
            assert.ok(given, K.shown(f.final));
            assert.ok(sent.indexOf(">" + given + "</saml:NameID>") >= 0,
                      given + " / " + sent.slice(0, 600));
          });
  log.debug("Leaving logoutLinks().");
}

// --------------------------------------------------------------------- D
function hidden(text, field) {
  log.debug("Entering hidden().");
  const m = new RegExp('name="' + field + '" value="([^"]*)"')
    .exec(String(text || ""));
  log.debug("Leaving hidden().");
  return m ? m[1] : "";
}

async function unsolicited() {
  log.debug("Entering unsolicited().");
  log.info("=== D. identity-provider-initiated SSO ===");
  const at = function (realm, query) {
    log.debug("Entering at().");
    log.debug("Leaving at().");
    return K.rb(realm) + "/saml2/unsolicited?" +
      new URLSearchParams(query).toString();
  };
  const acsD = "https://" + name("unsol") + ".example/acs";
  const spD = await sp(D, "unsol", null, { samlAssertionConsumerService:
    [acsD], saml2IdpInitiatedSso: "TRUE" });
  let c = await codeRose([D, null], "STS-SAML-0092", function () {
    return K.send(at(D, {}));
  });
  K.check("D1. no service provider named: refused, STS-SAML-0092",
          function () {
            assert.ok(c.answer.status >= 400, K.shown(c.answer));
            assert.ok(c.rose >= 1);
          });
  c = await codeRose([D, null], "STS-SAML-0093", function () {
    return K.send(at(D, { providerId: spD, binding: "redirect" }));
  });
  K.check("D2. a Response on HTTP-Redirect: refused, STS-SAML-0093",
          function () {
            assert.ok(c.answer.status >= 400, K.shown(c.answer));
            assert.ok(c.rose >= 1);
          });
  c = await codeRose([P, null], "STS-SAML-0082", function () {
    return K.send(at(P, { providerId: "https://never-" + K.STAMP +
                                      ".example/sp" }));
  });
  refusedWith("D3. PRODUCT: an unregistered service provider", c, 404,
              "STS-SAML-0082");
  const b = K.browser();
  await S.drive(D, b, S.redirect(K.rb(D) + "/saml2/sso",
    S.authnRequestXml({ issuer: spD, acs: acsD,
                        destination: K.rb(D) + "/saml2/sso" }).xml),
  { username: "sir-dora" });
  const sentD = await b.go(at(D, { providerId: spD, shire: acsD,
                                   target: "rs-" + K.STAMP }));
  const xml = Buffer.from(hidden(sentD.text, "SAMLResponse"), "base64")
    .toString("utf8");
  K.check("D4. with a session: an UNSOLICITED Response — no InResponseTo — " +
          "to the registered consumer, the target as RelayState",
          function () {
            assert.ok(/<samlp:Response\b/.test(xml), K.shown(sentD));
            assert.ok(!/InResponseTo=/.test(xml), xml.slice(0, 300));
            assert.ok(xml.indexOf('Destination="' + acsD + '"') >= 0);
            assert.strictEqual(hidden(sentD.text, "RelayState"),
                               "rs-" + K.STAMP);
          });
  K.check("D5. carrying the X.500/LDAP attribute profile's names (#189)",
          function () {
            assert.ok(/Name="urn:oid:0\.9\.2342\.19200300\.100\.1\.1"[^>]*FriendlyName="uid"/
              .test(xml), xml.slice(0, 1200));
            assert.ok(new RegExp(">sir-dora</saml:AttributeValue>")
              .test(xml));
          });
  const elsewhere = await b.go(at(D, { providerId: spD,
    shire: "https://evil-" + K.STAMP + ".example/acs" }));
  K.check("D6. development delivers to an unregistered shire, as its SSO " +
          "does", function () {
    assert.strictEqual(elsewhere.status, 200, K.shown(elsewhere));
  });
  const acsP = "https://" + name("unsol-p") + ".example/acs";
  const spP = await sp(P, "unsol-p", null, { samlAssertionConsumerService:
    [acsP], saml2IdpInitiatedSso: "TRUE" });
  const bp = K.browser();
  await S.drive(P, bp, at(P, { providerId: spP }),
                { username: "sir-dora", password: PASSWORD });
  const prodEvil = await bp.go(at(P, { providerId: spP,
    shire: "https://evil-" + K.STAMP + ".example/acs" }));
  K.check("D7. and PRODUCT refuses it, 400", function () {
    assert.strictEqual(prodEvil.status, 400, K.shown(prodEvil));
  });
  log.debug("Leaving unsolicited().");
}

// --------------------------------------------------------------------- E
async function attributeAuthority() {
  log.debug("Entering attributeAuthority().");
  log.info("=== E. product's attribute authority ===");
  const spE = await sp(P, "aa", null);
  const query = '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/' +
    'soap/envelope/"><soap:Body><samlp:AttributeQuery xmlns:samlp="' +
    S.NS_SAMLP + '" xmlns:saml="' + S.NS_SAML + '" ID="_aq' + K.rand(8) +
    '" Version="2.0" IssueInstant="' + new Date().toISOString() + '">' +
    "<saml:Issuer>" + spE + "</saml:Issuer><saml:Subject><saml:NameID>" +
    "sir-dora</saml:NameID></saml:Subject></samlp:AttributeQuery>" +
    "</soap:Body></soap:Envelope>";
  const c = await codeRose([P], "STS-SAML-0077", function () {
    return K.send(K.rb(P) + "/saml2/aa", { raw: query, headers: {
      "Content-Type": "text/xml; charset=utf-8" } });
  });
  K.check("E1. PRODUCT: an unauthenticated caller is refused, " +
          "STS-SAML-0077", function () {
    assert.ok(!/status:Success/.test(c.answer.text),
              c.answer.text.slice(0, 300));
    assert.ok(c.rose >= 1);
  });
  log.debug("Leaving attributeAuthority().");
}

// --------------------------------------------------------------------- G
function query11(nameId, resource) {
  log.debug("Entering query11().");
  log.debug("Leaving query11().");
  return '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/' +
    'envelope/"><soap:Body><samlp:Request xmlns:samlp="' + NS_SAMLP11 +
    '" MajorVersion="1" MinorVersion="1" RequestID="_r' + K.rand(8) +
    '" IssueInstant="' + new Date().toISOString() + '"><samlp:' +
    'AttributeQuery Resource="' + resource + '"><saml:Subject ' +
    'xmlns:saml="' + NS_SAML11 + '"><saml:NameIdentifier>' + nameId +
    "</saml:NameIdentifier></saml:Subject></samlp:AttributeQuery>" +
    "</samlp:Request></soap:Body></soap:Envelope>";
}

function post11(realm, body, cred) {
  log.debug("Entering post11().");
  const u = new URL(K.rb(realm) + "/saml11/responder");
  log.debug("Leaving post11().");
  return new Promise(function (resolve, reject) {
    const req = https.request({ host: u.hostname, port: u.port,
      path: u.pathname, method: "POST", agent: false,
      headers: { "Content-Type": "text/xml; charset=utf-8" },
      cert: cred ? cred.certificatePem : undefined,
      key: cred ? cred.privateKeyPem : undefined },
    function (res) {
      let text = "";
      res.setEncoding("utf8");
      res.on("data", function (chunk) {
        text += chunk;
      });
      res.on("end", function () {
        resolve({ status: res.statusCode, text: text });
      });
    });
    req.on("error", reject);
    req.end(body);
  });
}

async function shibboleth() {
  log.debug("Entering shibboleth().");
  log.info("=== G. SAML 1.1, as Shibboleth asks ===");
  const rp = name("rp11");
  const shire = "https://" + rp + ".example/SAML/POST";
  for (const realm of [D, P]) {
    await K.ok(K.rb(realm) + "/admin-api/applications/create", {
      identifier: rp, name: rp, protocols: ["saml11"],
      fields: { samlEntityId: [rp], samlAssertionConsumerService: [shire],
                samlSigningCertificate: [A.certificatePem] } },
    "created " + rp);
  }
  const b = K.browser();
  const go = function (realm, browser, o) {
    log.debug("Entering go().");
    log.debug("Leaving go().");
    return S.drive(realm, browser, K.rb(realm) + "/saml11/sso?" +
      new URLSearchParams({ providerId: rp, shire: shire,
        target: "ss:mem:" + K.STAMP,
        time: String(Math.floor(Date.now() / 1000)) }).toString(), o);
  };
  const posted = await go(D, b, { username: "sir-gil" });
  const a11 = S.messageOf(posted.final.text);
  K.check("G1. Shibboleth's lower-case `target` comes back as TARGET",
          function () {
            assert.strictEqual(hidden(posted.final.text, "TARGET"),
                               "ss:mem:" + K.STAMP, K.shown(posted.final));
          });
  K.check("G2. by default a Browser/POST assertion carries no " +
          "DoNotCacheCondition, and names uid as Shibboleth's attribute map " +
          "reads it", function () {
    assert.ok(!/DoNotCacheCondition/.test(a11), a11.slice(0, 300));
    assert.ok(a11.indexOf('AttributeName="urn:mace:dir:attribute-def:uid" ' +
      'AttributeNamespace="urn:mace:shibboleth:1.0:attributeNamespace:uri"') >=
      0, a11.slice(0, 1200));
  });
  await K.set(D, "saml11.doNotCacheCondition", true);
  const marked = await go(D, b, { username: "sir-gil" });
  K.check("G3. saml11.doNotCacheCondition on: a DoNotCacheCondition",
          function () {
            assert.ok(/DoNotCacheCondition/.test(
              S.messageOf(marked.final.text)), K.shown(marked.final));
          });
  await K.unset(D, "saml11.doNotCacheCondition");

  const bp = K.browser();
  await go(P, bp, { username: "sir-gil", password: PASSWORD });
  let c = await codeRose([P], "STS-SAML-0039", function () {
    return post11(P, query11("sir-gil", "https://nobody-" + K.STAMP +
                                        ".example/sp"), A);
  });
  K.check("G4. PRODUCT: a query for an unregistered relying party is " +
          "refused, STS-SAML-0039", function () {
    assert.ok(/samlp:Requester/.test(c.answer.text),
              c.answer.text.slice(0, 300));
    assert.ok(c.rose >= 1);
  });
  const anonymous = await post11(P, query11("sir-gil", rp));
  K.check("G5. PRODUCT: an unauthenticated caller is refused", function () {
    assert.ok(/samlp:Requester/.test(anonymous.text),
              anonymous.text.slice(0, 300));
  });
  c = await codeRose([P], "STS-SAML-0096", function () {
    return post11(P, query11("sir-nobody-" + K.STAMP, rp), A);
  });
  K.check("G6. PRODUCT: a subject no live session gave it is refused, " +
          "STS-SAML-0096", function () {
    assert.ok(!/samlp:Success/.test(c.answer.text) ||
              !/<saml:Assertion/.test(c.answer.text),
    c.answer.text.slice(0, 300));
    assert.ok(c.rose >= 1);
  });
  const released = await post11(P, query11("sir-gil", rp), A);
  K.check("G7. PRODUCT: the relying party authenticated by its registered " +
          "certificate (TLS), about the subject it holds a live session " +
          "for, is ANSWERED (#189)", function () {
    assert.ok(/samlp:Success/.test(released.text),
              released.text.slice(0, 400));
    assert.ok(/>sir-gil</.test(released.text), released.text.slice(0, 600));
  });
  log.debug("Leaving shibboleth().");
}

// --------------------------------------------------------------------- I
async function singleLogout() {
  log.debug("Entering singleLogout().");
  log.info("=== I. Single Logout's signatures ===");
  const run = async function (realm, label) {
    log.debug("Entering run(). " + label);
    const spM = await sp(realm, label, null);
    const host = "https://" + spM + ".example";
    const doc = '<md:EntityDescriptor xmlns:md="' + NS_MD + '" entityID="' +
      spM + '"><md:SPSSODescriptor protocolSupportEnumeration="' +
      S.NS_SAMLP + '" AuthnRequestsSigned="true"><md:KeyDescriptor ' +
      'use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/' +
      'xmldsig#"><ds:X509Data><ds:X509Certificate>' +
      S.b64cert(A.certificatePem) + "</ds:X509Certificate></ds:X509Data>" +
      '</ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding="' +
      B_REDIRECT + '" Location="' + host + '/slo" ResponseLocation="' + host +
      '/slo-response"/><md:AssertionConsumerService Binding="' +
      S.BINDING_POST + '" Location="' + host + '/acs" index="0"/>' +
      "</md:SPSSODescriptor></md:EntityDescriptor>";
    const up = await K.send(K.rb(realm) + "/admin-api/saml2/upload-metadata",
                            { json: { sp: spM, document: doc } });
    assert.strictEqual(up.status, 200, up.text.slice(0, 300));
    log.debug("Leaving run().");
    return { sp: spM, host: host };
  };
  const m = await run(P, "slo-m");
  const at = K.rb(P) + "/saml2/slo";
  const signed = S.redirect(at, logoutRequest(P, m.sp, "sir-ivy"),
                            { sign: A, relayState: "lo" });
  const ok = await K.send(signed);
  K.check("I1. a signed LogoutRequest is verified and answered at the " +
          "consumed SingleLogoutService ResponseLocation, on the Redirect " +
          "binding, with a LogoutResponse", function () {
    assert.strictEqual(ok.status, 303, K.shown(ok));
    assert.strictEqual(ok.location.indexOf(m.host + "/slo-response?"), 0,
                       ok.location);
    assert.ok(/LogoutResponse/.test(inflated(ok.location, "SAMLResponse")));
  });
  let c = await codeRose([P], "STS-SAML-0061", function () {
    return K.send(S.redirect(at, logoutRequest(P, m.sp, "sir-ivy"),
      { sign: A, relayState: "lo" }).replace("RelayState=lo",
                                             "RelayState=LO"));
  });
  K.check("I2. one tampered with after signing is REFUSED, 403, " +
          "STS-SAML-0061, and ends no session", function () {
    assert.strictEqual(c.answer.status, 403, K.shown(c.answer));
    assert.ok(/NOT ended/.test(c.answer.text), K.shown(c.answer));
    assert.ok(c.rose >= 1);
  });
  c = await codeRose([P], "STS-SAML-0063", function () {
    return K.send(S.redirect(at, logoutRequest(P, m.sp, "sir-ivy"),
                             { relayState: "lo" }));
  });
  refusedWith("I3. PRODUCT: an UNSIGNED LogoutRequest from a provider " +
              "that must sign", c, 403, "STS-SAML-0063");
  const spU = await sp(D, "slo-u", null, { samlSingleLogoutService:
    ["https://" + name("slo-u") + ".example/slo"] });
  const devU = await K.send(S.redirect(K.rb(D) + "/saml2/slo",
    logoutRequest(D, spU, "sir-ivy"), { relayState: "lo" }));
  K.check("I4. development: an unsigned LogoutRequest from a provider that " +
          "need not sign is still answered", function () {
    assert.ok(devU.status !== 403 && devU.status < 500, K.shown(devU));
  });
  const response = '<samlp:LogoutResponse xmlns:samlp="' + S.NS_SAMLP +
    '" xmlns:saml="' + S.NS_SAML + '" ID="_i4' + K.rand(6) + '" ' +
    'Version="2.0" IssueInstant="' + new Date().toISOString() + '">' +
    "<saml:Issuer>" + m.sp + "</saml:Issuer><samlp:Status><samlp:StatusCode " +
    'Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
    "</samlp:LogoutResponse>";
  c = await codeRose([P], "STS-SAML-0061", function () {
    return K.send(S.redirect(at, response, { sign: A, signWith: B,
                                             param: "SAMLResponse",
                                             relayState: "r" }));
  });
  refusedWith("I5. a LogoutResponse signed by the wrong key", c, 403,
              "STS-SAML-0061");
  log.debug("Leaving singleLogout().");
}

// --------------------------------------------------------------------- J
async function actions() {
  log.debug("Entering actions().");
  log.info("=== J. the console's SAML 2.0 actions through /admin-api ===");
  const spJ = await sp(D, "actions", null);
  const api = K.rb(D) + "/admin-api/saml2/";
  const fields = async function () {
    log.debug("Entering fields().");
    const r = await K.send(K.rb(D) + "/admin-api/applications?application=" +
                           encodeURIComponent(spJ));
    log.debug("Leaving fields().");
    return [].concat((((r.json || {}).attributes) || ((r.json || {})
      .fields) || {}).samlSigningCertificate || []);
  };
  const c = await K.coded(D, "STS-REG-0160", function () {
    return K.send(api + "set-signing-certificate", { json: { sp: spJ,
      value: "MIIBnotacert" } });
  });
  K.check("J1. a value that is not a certificate is refused, STS-REG-0160",
          function () {
            assert.ok(c.answer.status >= 400 ||
                      (c.answer.json || {}).ok === false,
            K.shown(c.answer));
            assert.ok(c.rose >= 1);
          });
  await K.ok(api + "set-signing-certificate", { sp: spJ,
    value: A.certificatePem }, "set A");
  let held = await fields();
  K.check("J2. a PEM is registered as base64 DER", function () {
    assert.strictEqual(held.join(), S.b64cert(A.certificatePem),
                       JSON.stringify(held).slice(0, 200));
  });
  await K.ok(api + "set-signing-certificate", { sp: spJ,
    value: S.b64cert(B.certificatePem) }, "set B");
  held = await fields();
  K.check("J3. set REPLACES the list", function () {
    assert.strictEqual(held.join(), S.b64cert(B.certificatePem));
  });
  await K.ok(api + "remove-signing-certificate", { sp: spJ,
    value: B.certificatePem }, "remove B");
  held = await fields();
  K.check("J4. remove takes one off, by value (a PEM is normalised)",
          function () {
            assert.strictEqual(held.length, 0, JSON.stringify(held));
          });
  const unknown = await K.send(api + "nope", { json: { sp: spJ } });
  K.check("J5. an unknown action is refused naming all eleven", function () {
    assert.ok(unknown.status >= 400, K.shown(unknown));
    assert.ok(/upload-metadata/.test(unknown.text) &&
              /mdq-import/.test(unknown.text), unknown.text.slice(0, 600));
  });
  log.debug("Leaving actions().");
}

async function test() {
  log.debug("Entering test().");
  D = await K.realm("sir-d", "development");
  P = await K.realm("sir-p", "product",
                    { "authn.allowOptionalSecondFactor": "true" });
  A = await S.credential("sir-a");
  B = await S.credential("sir-b");
  for (const realm of [D, P]) {
    for (const who of ["sir-cora", "sir-dora", "sir-gil", "sir-ivy"]) {
      await K.person(realm, who, PASSWORD);
    }
  }
  await logoutLinks();
  await unsolicited();
  await attributeAuthority();
  await shibboleth();
  await singleLogout();
  await actions();
  log.debug("Leaving test().");
}

K.main(test, 28);
