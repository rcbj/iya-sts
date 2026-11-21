// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_saml_signatures.js
//
// ===========================================================================
// A SAML 2.0 SERVICE PROVIDER'S SIGNATURES AND METADATA, OVER THE WIRE
// (#37; #444 D12, phase 7).
//
// `tests/saml_request_signatures.js`, `tests/saml_signature_algorithms.js`
// and `tests/saml_metadata_lifecycle.js` call the handlers off the router
// with keys the test holds and the mode flipped per case. Here the keys are
// still made by the job (a service provider's are its own), and every
// request goes to a running service: a development realm D and a product
// realm P of the job's own. A request the service takes is one it sends on
// to the sign-in screen; one it refuses is a 400 page; each refusal's code
// is read off the audit log.
//
//   A. the policy: development takes an unsigned AuthnRequest, refuses it
//      with `saml2.requireSignedAuthnRequests` on (STS-SAML-0063); product
//      refuses it by default (0063); the IdP metadata's
//      WantAuthnRequestsSigned follows the setting.
//   B. the Redirect binding: a query signature by the REGISTERED key is
//      taken, and recorded `verified` on the entry; RelayState or SigAlg
//      changed after signing, another key's signature (0061); a Signature
//      with no SigAlg (0062, nothing to verify it over); SHA-1 (0073) in
//      both modes; product refuses to turn `saml.allowSha1Signatures` on,
//      and development with it on takes SHA-1.
//   C. the POST binding (its 303 to the held request followed): an
//      enveloped signature is taken; an altered request (0061); a signature
//      moved onto a root it does not cover (0062); a signed request inside
//      an unsigned one is the unsigned one (0063); an inclusive-c14n
//      signature verifies.
//   D. a certificate only in the request's KeyInfo is not trusted: product
//      refuses the request (0063) and records it `no-certificate`;
//      development takes it and OBSERVES the certificate, not registering
//      it; `confirm-signing-certificate` registers it and the next request
//      is `verified`.
//   S. the families: an EC (P-256) service provider's AuthnRequest on both
//      bindings verified, a tampered one refused (0061).
//   G. metadata consumption (`upload-metadata`): the signing and encryption
//      certificates, every assertion consumer service with its index, the
//      SingleLogoutService with its ResponseLocation, the NameID formats,
//      AuthnRequestsSigned and WantAssertionsSigned, cacheDuration; the
//      metadata minted FOR that service provider says
//      WantAuthnRequestsSigned="true" while another's says false.
//   H. using it: AssertionConsumerServiceIndex, the default endpoint, an
//      unregistered URL (STS-SAML-0070), an unknown index (0069), a NameID
//      policy no format answers (InvalidNameIDPolicy, 0071).
//   X. expiry (`saml_metadata_lifecycle.js` 3): a document consumed seconds
//      before its validUntil refuses SSO afterwards (STS-SAML-0074) and the
//      view says expired; F: every per-provider path of each profile is a
//      404 for a name that is not a registered provider of that profile
//      (STS-SAML-0082, 0083); E: `saml2.encryptAssertion` on with no
//      certificate at all (through /saml2/unsolicited) — product answers
//      Responder with no assertion (STS-SAML-0011), development sends it in
//      clear.
//
// NOT HERE: the families the job cannot make keys for with node alone
// (DSA, ML-DSA, SLH-DSA, EdDSA in XML), the background refresher and MDQ
// against a local server (the service dials loopback addresses only in
// development with `federation.outbound` opened, process-wide), the
// metadata signature by a realm trust anchor (D) — OWED to a follow-up that
// mints the anchor through the PKI workbench.
//
// OWNED HERE (local: true). Its realms are removed only on a private probe.
// ===========================================================================

// An address compared by parsing it, not searched for as text
// (`url_match.js`).
const urls = require("./url_match.js");
const assert = require("assert");
const path = require("path");
const nodeCrypto = require("crypto");
const K = require("./oauth_wire_kit.js").kit("sts_saml_signatures");
const S = require("./saml_wire_kit.js").samlKit(K);
const xmldom = require("@xmldom/xmldom");
if (!global.DOMParser) {
  global.DOMParser = xmldom.DOMParser;
}
if (!global.XMLSerializer) {
  global.XMLSerializer = xmldom.XMLSerializer;
}
const REPO = process.env.MOCK_STS_DIR || path.join(__dirname, "..", "..");
const xmldsig = require(path.join(REPO, "common", "crypto_impl",
                                  "xmldsig.js"));

const log = K.log;
const B_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
const B_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
const F_EMAIL = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
const F_PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
const C14N_INCL = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
let D = null;
let P = null;

function acsOf(sp) {
  log.debug("Entering acsOf().");
  log.debug("Leaving acsOf().");
  return "https://" + sp.replace(/[^a-z0-9]+/gi, "-") + ".example/acs";
}

async function sp(id, label, cred, fields) {
  log.debug("Entering sp(). " + label);
  const identifier = "urn:saml-sig:" + label + ":" + K.STAMP;
  await K.ok(K.rb(id) + "/admin-api/applications/create", {
    identifier: identifier, name: label, protocols: ["saml2"],
    fields: Object.assign({ samlEntityId: [identifier],
      samlAssertionConsumerService: [acsOf(identifier)] },
    cred ? { samlSigningCertificate: [cred.certificatePem] } : {},
    fields || {}) }, "created " + label);
  log.debug("Leaving sp().");
  return identifier;
}

function request(id, issuer, o) {
  log.debug("Entering request().");
  const opts = o || {};
  log.debug("Leaving request().");
  return S.authnRequestXml(Object.assign({ issuer: issuer,
    acs: opts.noAcs ? undefined : acsOf(issuer),
    destination: K.rb(id) + "/saml2/sso" }, opts));
}

// The POST binding answers with a 303 to the held request (`?rid=`), whose
// answer is the verdict: followed once.
async function postForm(id, xml) {
  log.debug("Entering postForm().");
  const r = await K.send(K.rb(id) + "/saml2/sso", { form: {
    SAMLRequest: Buffer.from(xml, "utf8").toString("base64") } });
  if ((r.status === 302 || r.status === 303) &&
      /\/saml2\/sso\?rid=/.test(r.location)) {
    log.debug("Leaving postForm(). Through the held request.");
    return K.send(/^https?:/.test(r.location) ? r.location
                                              : K.base + r.location);
  }
  log.debug("Leaving postForm().");
  return r;
}

// An enveloped signature on the root, placed after its Issuer.
function enveloped(xml, cred, o) {
  log.debug("Entering enveloped().");
  const out = xmldsig.signEnveloped(xml, Object.assign({
    privateKeyPem: cred.privateKeyPem, certPem: cred.certificatePem },
  o || {}));
  log.debug("Leaving enveloped().");
  return out;
}

// A code's new rows in the realm and in the default realm.
async function coded(id, code, act) {
  log.debug("Entering coded(). " + code);
  const a = await K.codeCount(id, code);
  const b = await K.codeCount(null, code);
  const answer = await act();
  let rose = 0;
  for (let i = 0; i < 20 && rose === 0; i += 1) {
    rose = (await K.codeCount(id, code)) - a +
           (await K.codeCount(null, code)) - b;
    if (rose === 0) {
      await K.sleep(150);
    }
  }
  log.debug("Leaving coded(). " + rose);
  return { answer: answer, rose: rose };
}

async function refused(id, label, code, act) {
  log.debug("Entering refused(). " + code);
  const c = await coded(id, code, act);
  const recent = c.rose >= 1 ? "" : JSON.stringify([id, null].map(
    async function () {
      return null;
    }) && ((await K.send(K.base + "/admin-api/audit?per=6")).json ||
    { events: [] }).events.map(function (e) {
      return e.errorCode + ":" + e.action;
    })) + " " + K.shown(c.answer).slice(0, 300);
  K.check(label + ": refused, " + code, function () {
    assert.ok(c.answer.status >= 400 || /status:(Requester|Responder)/
      .test(S.messageOf(c.answer.text)), K.shown(c.answer));
    assert.ok(!K.toSignIn(c.answer), "sent on to the sign-in screen");
    assert.ok(c.rose >= 1, "no new " + code + " row; the realm's last " +
              "codes " + recent);
  });
  log.debug("Leaving refused().");
  return c.answer;
}

function taken(label, r) {
  log.debug("Entering taken().");
  K.check(label + ": taken, on to the sign-in screen", function () {
    assert.ok(K.toSignIn(r), K.shown(r));
  });
  log.debug("Leaving taken().");
}

async function fieldsOf(id, identifier) {
  log.debug("Entering fieldsOf().");
  const r = await K.send(K.rb(id) + "/admin-api/applications?application=" +
                         encodeURIComponent(identifier));
  log.debug("Leaving fieldsOf().");
  return ((r.json || {}).attributes) || ((r.json || {}).fields) || {};
}

function want(md) {
  log.debug("Entering want().");
  log.debug("Leaving want().");
  return (/WantAuthnRequestsSigned="([^"]+)"/.exec(md) || [])[1];
}

// -------------------------------------------------------------------- A
async function policy(credA) {
  log.debug("Entering policy().");
  log.info("=== A. the policy ===");
  const spD = await sp(D, "policy-d", credA);
  const spP = await sp(P, "policy-p", credA);
  taken("A1. development, the setting off: an unsigned AuthnRequest",
        await K.send(S.redirect(K.rb(D) + "/saml2/sso",
                                request(D, spD).xml)));
  const mdD = (await K.send(K.rb(D) + "/saml2/metadata")).text;
  const mdP = (await K.send(K.rb(P) + "/saml2/metadata")).text;
  K.check("A2. the IdP metadata's WantAuthnRequestsSigned follows the " +
          "setting: false in development, true in product", function () {
    assert.strictEqual(want(mdD), "false", mdD.slice(0, 300));
    assert.strictEqual(want(mdP), "true");
  });
  await K.set(D, "saml2.requireSignedAuthnRequests", "on");
  await refused(D, "A3. development with the setting on: an unsigned " +
    "AuthnRequest", "STS-SAML-0063", function () {
    return K.send(S.redirect(K.rb(D) + "/saml2/sso", request(D, spD).xml));
  });
  const mdOn = (await K.send(K.rb(D) + "/saml2/metadata")).text;
  K.check("A4. and the metadata then says WantAuthnRequestsSigned=\"true\"",
          function () {
            assert.strictEqual(want(mdOn), "true");
          });
  await K.unset(D, "saml2.requireSignedAuthnRequests");
  await refused(P, "A5. product by default: an unsigned AuthnRequest",
    "STS-SAML-0063", function () {
      return K.send(S.redirect(K.rb(P) + "/saml2/sso", request(P, spP).xml));
    });
  log.debug("Leaving policy().");
  return spP;
}

// ---------------------------------------------------------------- B, C, S
async function bindings(credA, credB, credEc, spP) {
  log.debug("Entering bindings().");
  log.info("=== B. the Redirect binding ===");
  const at = K.rb(P) + "/saml2/sso";
  const signedUrl = function (o) {
    return S.redirect(at, request(P, spP).xml, Object.assign({
      sign: credA, relayState: "rs-1" }, o || {}));
  };
  taken("B1. a query signature by the registered key", await K.send(
    signedUrl()));
  const f = await fieldsOf(P, spP);
  K.check("B2. and the entry records the request verified", function () {
    assert.ok(/verified/.test(JSON.stringify(f.samlAuthnRequestVerification ||
      "")), JSON.stringify(f.samlAuthnRequestVerification));
  });
  await refused(P, "B3. RelayState changed after signing", "STS-SAML-0061",
    function () {
      return K.send(signedUrl().replace("RelayState=rs-1",
                                        "RelayState=rs-2"));
    });
  await refused(P, "B4. SigAlg changed after signing", "STS-SAML-0061",
    function () {
      return K.send(signedUrl().replace(encodeURIComponent(S.RSA_SHA256),
        encodeURIComponent("http://www.w3.org/2001/04/xmldsig-more#" +
                           "rsa-sha512")));
    });
  await refused(P, "B5. a Signature with no SigAlg", "STS-SAML-0062",
    function () {
      return K.send(signedUrl().replace(/&SigAlg=[^&]*/, ""));
    });
  await refused(P, "B6. another key's signature", "STS-SAML-0061",
    function () {
      return K.send(signedUrl({ signWith: credB }));
    });
  await refused(P, "B7. SHA-1", "STS-SAML-0073", function () {
    return K.send(signedUrl({ sigAlg: S.RSA_SHA1 }));
  });
  const weak = await K.send(K.rb() + "/admin-api/realms/set", { json: {
    id: P, key: "saml.allowSha1Signatures", value: "true" } });
  K.check("B8. product refuses to turn saml.allowSha1Signatures on",
          function () {
            assert.strictEqual(weak.status, 400, weak.text.slice(0, 300));
            assert.ok(/product mode/.test(weak.text));
          });
  const spD = await sp(D, "sha1-d", credA);
  const devUrl = function () {
    return S.redirect(K.rb(D) + "/saml2/sso", request(D, spD).xml,
                      { sign: credA, sigAlg: S.RSA_SHA1 });
  };
  await refused(D, "B9. development refuses SHA-1 too by default",
    "STS-SAML-0073", function () {
      return K.send(devUrl());
    });
  await K.set(D, "saml.allowSha1Signatures", true);
  taken("B10. development with saml.allowSha1Signatures on takes it",
        await K.send(devUrl()));
  await K.unset(D, "saml.allowSha1Signatures");

  log.info("=== C. the POST binding ===");
  const req = function () {
    return request(P, spP).xml;
  };
  taken("C1. an enveloped signature by the registered key",
        await postForm(P, enveloped(req(), credA)));
  await refused(P, "C2. a request altered after signing", "STS-SAML-0061",
    function () {
      return postForm(P, enveloped(req(), credA).replace(
        'ProtocolBinding="', 'ForceAuthn="true" ProtocolBinding="'));
    });
  // A WRAPPING ATTEMPT: the genuine signed request carried inside an
  // Extensions of an unsigned one, and its Signature moved onto the outer
  // root — so the root has a signature that verifies, over an element that
  // is not the root (its Reference names the inner ID).
  const wrapped = (function () {
    const genuine = enveloped(req(), credA).replace(/<\?xml[^>]*>/, "");
    const sig = /<ds:Signature[\s\S]*?<\/ds:Signature>/.exec(genuine)[0];
    const evil = request(P, spP).xml;
    return evil.replace("</saml:Issuer>", "</saml:Issuer>" + sig +
                        "<samlp:Extensions>" + genuine +
                        "</samlp:Extensions>");
  })();
  const unsignedRoot = (function () {
    const genuine = enveloped(req(), credA).replace(/<\?xml[^>]*>/, "");
    return request(P, spP).xml.replace("</saml:Issuer>", "</saml:Issuer>" +
      "<samlp:Extensions>" + genuine + "</samlp:Extensions>");
  })();
  await refused(P, "C3b. a signed request inside an unsigned one is the " +
    "unsigned one", "STS-SAML-0063", function () {
    return postForm(P, unsignedRoot);
  });
  await refused(P, "C3. a wrapping attempt", "STS-SAML-0062", function () {
    return postForm(P, wrapped);
  });
  taken("C4. an inclusive-c14n signature verifies",
        await postForm(P, enveloped(req(), credA, { c14nAlg: C14N_INCL })));

  log.info("=== S. an EC service provider ===");
  const spEc = await sp(P, "ec", credEc);
  taken("S1. an EC AuthnRequest on the Redirect binding", await K.send(
    S.redirect(at, request(P, spEc).xml, { sign: credEc })));
  await refused(P, "S2. an EC request tampered after signing",
    "STS-SAML-0061", function () {
      return K.send(S.redirect(at, request(P, spEc).xml, { sign: credEc,
                                                           relayState: "a" })
        .replace("RelayState=a", "RelayState=b"));
    });
  log.debug("Leaving bindings().");
}

// -------------------------------------------------------------------- D
async function observed(credB) {
  log.debug("Entering observed().");
  log.info("=== D. a certificate only in the request's KeyInfo ===");
  const spO = await sp(P, "observed", null);
  await refused(P, "D1. product: a request signed by a key the entry does " +
    "not register, its certificate in KeyInfo", "STS-SAML-0063",
  function () {
    return postForm(P, enveloped(request(P, spO).xml, credB));
  });
  let f = await fieldsOf(P, spO);
  K.check("D2. product records it no-certificate, and registers nothing",
          function () {
            assert.ok(/no-certificate/.test(JSON.stringify(
              f.samlAuthnRequestVerification)),
            JSON.stringify(f.samlAuthnRequestVerification));
            assert.strictEqual([].concat(f.samlSigningCertificate || [])
              .length, 0);
          });
  const spDo = await sp(D, "observed-d", null);
  taken("D3. development takes it", await postForm(D,
    enveloped(request(D, spDo).xml, credB)));
  f = await fieldsOf(D, spDo);
  K.check("D4. and the certificate is OBSERVED on the entry, not " +
          "registered", function () {
    assert.ok([].concat(f.samlObservedSigningCertificate || []).length >= 1,
              JSON.stringify(f.samlAuthnRequestVerification));
    assert.strictEqual([].concat(f.samlSigningCertificate || []).length, 0);
  });
  const confirmed = await K.send(K.rb(D) + "/admin-api/saml2/confirm-" +
    "signing-certificate", { json: { sp: spDo } });
  K.check("D5. confirm-signing-certificate registers it", function () {
    assert.strictEqual(confirmed.status, 200, confirmed.text.slice(0, 300));
  });
  taken("D6. and the next request is taken", await postForm(D,
    enveloped(request(D, spDo).xml, credB)));
  f = await fieldsOf(D, spDo);
  K.check("D7. recorded verified", function () {
    assert.ok(/^\["?verified/.test(JSON.stringify(
      f.samlAuthnRequestVerification || "")),
    JSON.stringify(f.samlAuthnRequestVerification));
  });
  log.debug("Leaving observed().");
}

// ---------------------------------------------------------------- G, H
function spMetadata(entityId, o) {
  log.debug("Entering spMetadata().");
  const key = function (use, b64) {
    return '<md:KeyDescriptor use="' + use + '"><ds:KeyInfo xmlns:ds="' +
      'http://www.w3.org/2000/09/xmldsig#"><ds:X509Data>' +
      "<ds:X509Certificate>" + b64 + "</ds:X509Certificate></ds:X509Data>" +
      "</ds:KeyInfo></md:KeyDescriptor>";
  };
  log.debug("Leaving spMetadata().");
  return '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:' +
    'metadata" ID="_md1" entityID="' + entityId + '"' +
    (o.validUntil ? ' validUntil="' + o.validUntil + '"' : "") +
    ' cacheDuration="PT6H"><md:SPSSODescriptor protocolSupportEnumeration="' +
    S.NS_SAMLP + '" AuthnRequestsSigned="' + (o.requestsSigned ? "true"
                                                               : "false") +
    '" WantAssertionsSigned="true">' +
    (o.signing ? key("signing", o.signing) : "") +
    (o.encryption ? key("encryption", o.encryption) : "") +
    (o.slo || []).map(function (e) {
      return '<md:SingleLogoutService Binding="' + e[0] + '" Location="' +
             e[1] + '"' + (e[2] ? ' ResponseLocation="' + e[2] + '"' : "") +
             "/>";
    }).join("") + (o.formats || []).map(function (f) {
      return "<md:NameIDFormat>" + f + "</md:NameIDFormat>";
    }).join("") + (o.acs || []).map(function (e) {
      return '<md:AssertionConsumerService Binding="' + e.binding +
             '" Location="' + e.location + '" index="' + e.index + '"' +
             (e.isDefault !== undefined ? ' isDefault="' + e.isDefault + '"'
                                        : "") + "/>";
    }).join("") + "</md:SPSSODescriptor></md:EntityDescriptor>";
}

async function consumption(credA, credB) {
  log.debug("Entering consumption().");
  log.info("=== G. consuming a service provider's metadata ===");
  const spM = "urn:saml-sig:metadata:" + K.STAMP;
  await K.ok(K.rb(D) + "/admin-api/applications/create", { identifier: spM,
    name: "metadata", protocols: ["saml2"],
    fields: { samlEntityId: [spM] } }, "created the metadata SP");
  const base = "https://" + K.STAMP + ".m.example";
  const doc = spMetadata(spM, { requestsSigned: true,
    signing: S.b64cert(credA.certificatePem),
    encryption: S.b64cert(credB.certificatePem),
    formats: [F_EMAIL, F_PERSISTENT],
    slo: [[B_REDIRECT, base + "/slo", base + "/slo-response"],
          [B_POST, base + "/slo-post"]],
    acs: [{ binding: B_POST, location: base + "/acs0", index: 0,
            isDefault: "false" },
          { binding: B_REDIRECT, location: base + "/acs1", index: 1,
            isDefault: "true" }] });
  const up = await K.send(K.rb(D) + "/admin-api/saml2/upload-metadata",
                          { json: { sp: spM, document: doc } });
  const f = await fieldsOf(D, spM);
  K.check("G1. the document is consumed", function () {
    assert.strictEqual(up.status, 200, up.text.slice(0, 400));
  });
  K.check("G2. its signing certificate is registered, its encryption " +
          "certificate the encryption certificate", function () {
    assert.ok([].concat(f.samlSigningCertificate || []).join()
      .indexOf(S.b64cert(credA.certificatePem).slice(0, 60)) >= 0,
    JSON.stringify(f.samlSigningCertificate).slice(0, 200));
    assert.ok(String(f.samlEncryptionCertificate || "")
      .indexOf(S.b64cert(credB.certificatePem).slice(0, 60)) >= 0);
  });
  K.check("G3. both consumers, as `<index> <isDefault> <binding> " +
          "<location>`, and their locations registered", function () {
    const e = [].concat(f.samlAcsEndpoint || []);
    assert.strictEqual(e.length, 2, JSON.stringify(e));
    assert.ok(e.indexOf("1 true " + B_REDIRECT + " " + base + "/acs1") >= 0);
    for (const u of [base + "/acs0", base + "/acs1"]) {
      assert.ok(urls.holds(f.samlAssertionConsumerService, u), u);
    }
  });
  K.check("G4. the SingleLogoutService with its ResponseLocation, the " +
          "NameID formats, AuthnRequestsSigned, WantAssertionsSigned, " +
          "cacheDuration, unsigned", function () {
    assert.ok(urls.holds(f.samlSloEndpoint, B_REDIRECT + " " +
      base + "/slo " + base + "/slo-response"),
    JSON.stringify(f.samlSloEndpoint));
    assert.strictEqual([].concat(f.samlSpNameIdFormat || []).join(" "),
                       F_EMAIL + " " + F_PERSISTENT);
    const one = function (v) {
      return [].concat(v || []).join();
    };
    assert.strictEqual(one(f.samlSpAuthnRequestsSigned), "TRUE");
    assert.strictEqual(one(f.samlSpWantAssertionsSigned), "TRUE");
    assert.strictEqual(one(f.samlSpMetadataCacheDuration), "PT6H");
    assert.strictEqual(one(f.samlSpMetadataSignature), "unsigned");
  });
  const mine = (await K.send(K.rb(D) + "/saml2/metadata/" +
                             encodeURIComponent(spM))).text;
  const other = (await K.send(K.rb(D) + "/saml2/metadata")).text;
  K.check("G5. the metadata minted for it says WantAuthnRequestsSigned=" +
          "\"true\"; the realm's own still false", function () {
    assert.strictEqual(want(mine), "true");
    assert.strictEqual(want(other), "false");
  });
  const wrongEntity = await K.send(K.rb(D) + "/admin-api/saml2/upload-" +
    "metadata", { json: { sp: spM, document: spMetadata("urn:other:" +
      K.STAMP, { acs: [] }) } });
  const expired = await K.send(K.rb(D) + "/admin-api/saml2/upload-" +
    "metadata", { json: { sp: spM, document: spMetadata(spM, {
      validUntil: new Date(Date.now() - 60000).toISOString(), acs: [] }) } });
  K.check("G6. a document for another entityID, and one already expired, " +
          "are refused", function () {
    assert.ok(wrongEntity.status >= 400, wrongEntity.text.slice(0, 300));
    assert.ok(expired.status >= 400, expired.text.slice(0, 300));
  });

  log.info("=== H. using it ===");
  const at = K.rb(D) + "/saml2/sso";
  const withXml = function (attrs, extra) {
    const x = S.authnRequestXml({ issuer: spM, destination: at });
    return S.redirect(at, x.xml.replace(/ AssertionConsumerServiceURL="[^"]*"/,
                                        "")
      .replace("<samlp:AuthnRequest ", "<samlp:AuthnRequest " + attrs + " ")
      .replace("</saml:Issuer>", "</saml:Issuer>" + (extra || "")),
    { sign: credA });
  };
  taken("H1. AssertionConsumerServiceIndex 0", await K.send(
    withXml('AssertionConsumerServiceIndex="0"')));
  taken("H2. no consumer named: the default endpoint", await K.send(
    withXml("")));
  await refused(D, "H3. an unregistered AssertionConsumerServiceURL",
    "STS-SAML-0070", function () {
      return K.send(withXml('AssertionConsumerServiceURL="https://evil.' +
                            'example/acs"'));
    });
  await refused(D, "H4. an unknown AssertionConsumerServiceIndex",
    "STS-SAML-0069", function () {
      return K.send(withXml('AssertionConsumerServiceIndex="7"'));
    });
  const b = K.browser();
  const policyUrl = withXml("", '<samlp:NameIDPolicy Format="urn:oasis:' +
    'names:tc:SAML:2.0:nameid-format:kerberos" AllowCreate="false"/>');
  const c = await coded(D, "STS-SAML-0071", function () {
    return S.drive(D, b, policyUrl, { username: "ss-alice" });
  });
  K.check("H5. a NameIDPolicy no format answers: InvalidNameIDPolicy, " +
          "STS-SAML-0071", function () {
    const said = (c.answer.response && c.answer.response.codes) || [];
    assert.ok(said.indexOf("InvalidNameIDPolicy") >= 0,
              JSON.stringify(c.answer.response || K.shown(c.answer.final)));
    assert.ok(c.rose >= 1);
  });
  log.debug("Leaving consumption().");
}

// ---------------------------------------------------------------- X, F, E
async function lifecycle(credA) {
  log.debug("Entering lifecycle().");
  log.info("=== X. expiry; F. per-provider paths; E. encryption ===");
  const spX = "urn:saml-sig:expiring:" + K.STAMP;
  await K.ok(K.rb(D) + "/admin-api/applications/create", { identifier: spX,
    name: "expiring", protocols: ["saml2"],
    fields: { samlEntityId: [spX] } }, "created the expiring SP");
  const until = new Date(Date.now() + 4000).toISOString();
  const up = await K.send(K.rb(D) + "/admin-api/saml2/upload-metadata",
    { json: { sp: spX, document: spMetadata(spX, { validUntil: until,
      signing: S.b64cert(credA.certificatePem),
      acs: [{ binding: B_POST, location: acsOf(spX), index: 0,
              isDefault: "true" }] }) } });
  assert.strictEqual(up.status, 200, up.text.slice(0, 300));
  const at = K.rb(D) + "/saml2/sso";
  taken("X1. before its validUntil the service provider is answered",
        await K.send(S.redirect(at, request(D, spX).xml, { sign: credA })));
  await K.sleep(Math.max(0, Date.parse(until) - Date.now() + 1500));
  await refused(D, "X2. past its validUntil, its AuthnRequest",
    "STS-SAML-0074", function () {
      return K.send(S.redirect(at, request(D, spX).xml, { sign: credA }));
    });
  const view = await K.send(K.rb(D) + "/admin-api/saml2?sp=" +
                            encodeURIComponent(spX));
  K.check("X3. and the console/API view says expired", function () {
    assert.ok(/expired/i.test(JSON.stringify(view.json || {})),
              view.text.slice(0, 400));
  });
  for (const [label, url, code] of [
    ["SAML 2.0 metadata", "/saml2/metadata/nobody-" + K.STAMP,
     "STS-SAML-0082"],
    ["SAML 1.1 metadata", "/saml11/metadata/nobody-" + K.STAMP,
     "STS-SAML-0083"]]) {
    const c = await coded(P, code, function () {
      return K.send(K.rb(P) + url);
    });
    K.check("F. product: the " + label + " path for a name that is not a " +
            "registered provider is a 404, " + code, function () {
      assert.strictEqual(c.answer.status, 404, K.shown(c.answer));
      assert.ok(c.rose >= 1);
    });
  }
  // E. encryption with no certificate: an SP with none at all, through
  // /saml2/unsolicited (product refuses an unsigned AuthnRequest first).
  for (const [id, product] of [[D, false], [P, true]]) {
    await K.set(id, "saml2.encryptAssertion", true);
    const target = await sp(id, "enc-" + (product ? "p" : "d"), null,
                            { saml2IdpInitiatedSso: "TRUE" });
    const b = K.browser();
    const c = await coded(id, "STS-SAML-0011", function () {
      return S.drive(id, b, K.rb(id) + "/saml2/unsolicited?" +
        new URLSearchParams({ providerId: target }).toString(),
      { username: "ss-alice", password: PW });
    });
    const r = c.answer.response;
    K.check("E (" + (product ? "product" : "development") + "). " +
            "saml2.encryptAssertion on with no certificate: " +
            (product ? "Responder with no assertion, STS-SAML-0011"
                     : "the assertion in clear"), function () {
      assert.ok(r, K.shown(c.answer.final));
      if (product) {
        assert.ok(r.codes.indexOf("Responder") >= 0, JSON.stringify(r.codes));
        assert.ok(!/Assertion\b/.test(r.xml.replace(/StatusMessage>[^<]*</,
                                                     "")),
                  r.xml.slice(0, 400));
        assert.ok(c.rose >= 1);
      } else {
        assert.strictEqual(r.codes[0], "Success");
        assert.ok(/<saml2?:Assertion\b/.test(r.xml) &&
                  !/EncryptedAssertion/.test(r.xml), r.xml.slice(0, 400));
      }
    });
    await K.unset(id, "saml2.encryptAssertion");
  }
  log.debug("Leaving lifecycle().");
}

const PW = "Ss-Passw0rd!-" + String(Date.now()).slice(-6);

async function test() {
  log.debug("Entering test().");
  D = await K.realm("ssg-d", "development");
  P = await K.realm("ssg-p", "product",
                    { "authn.allowOptionalSecondFactor": "true" });
  await K.person(D, "ss-alice", PW);
  await K.person(P, "ss-alice", PW);
  const credA = await S.credential("sp key A", "rsa");
  const credB = await S.credential("sp key B", "rsa");
  const credEc = await S.credential("sp key EC", "ec");
  const spP = await policy(credA);
  await bindings(credA, credB, credEc, spP);
  await observed(credB);
  await consumption(credA, credB);
  await lifecycle(credA);
  log.debug("Leaving test().");
}

K.main(test, 47);
