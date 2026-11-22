// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_saml_sso_rules.js
//
// ===========================================================================
// WHAT THE SAML 2.0 AND SAML 1.1 SINGLE SIGN-ON SERVICES DO WITH A REQUEST,
// OVER THE WIRE (#444 D12, phase 7).
//
// The in-process files drive `/saml2/sso` in a child process and read the
// pending sign-in and the code off the stack. Here a running service is
// asked the same through a development realm of the job's own (any
// password; an unsigned AuthnRequest is taken there), the sign-in screen
// walked over `/authn-api`, and every code read off the realm's audit log:
//
//   F. `saml2_force_authn.js`, one trip to the screen per request:
//      1. ForceAuthn with no session: one trip, Success;
//      2. ForceAuthn with a session: the screen once, Success, a fresh
//         AuthnInstant;
//      3. ForceAuthn and back WITHOUT authenticating: AuthnFailed
//         (STS-SAML-0055);
//      4. Cancel at the screen: AuthnFailed after one trip, reported as the
//         cancellation (STS-SAML-0009);
//      5. a multi-factor RequestedAuthnContext still unmet on the way back:
//         NoAuthnContext (STS-SAML-0056);
//      6. a plain request with a session is single sign-on; IsPassive with
//         none is NoPassive;
//      7. only the phr URI forces a key, unmet NoAuthnContext (STS-SAML-0116);
//         the hardware URI the same;
//      8. phr beside PasswordProtectedTransport forces nothing and the
//         assertion keeps PasswordProtectedTransport;
//      9. IsPassive with only phr on a password session is NoPassive;
//     10. SAML 1.1's authnContextClassRef: one trip, then a page
//         (STS-SAML-0117); without it, am:password.
//   A. `saml_interop_findings.js` A, the envelope: an AuthnRequest addressed
//      elsewhere (STS-SAML-0085), stale, future or with no IssueInstant
//      (0086), not Version 2.0 (0087), replayed (0088); an unsigned one with
//      no Destination still answered.
//   B. `saml_interop_findings.js` B, back-channel logout: a LogoutRequest
//      with no cookie naming the session's SessionIndex and another NameID
//      ends nothing, UnknownPrincipal (STS-SAML-0090); with the NameID the
//      session gave the service provider it ends that session, Success.
//   E. its E, the attribute authority: not an AttributeQuery (STS-SAML-0095),
//      a subject no live session gave the service provider (UnknownPrincipal,
//      STS-SAML-0094), the one it did (Success, the NameID's qualifiers
//      echoed, no AuthnStatement or SubjectConfirmation), and a query
//      naming an attribute narrowed to it.
//   M. its F and `saml_listener_key.js` B, the metadata: the attribute
//      authority published, no HTTP-Artifact SingleSignOnService, SAML 1.1's
//      IDPSSODescriptor naming urn:mace:shibboleth:1.0, both paths one
//      entity; and the certificate the main port presents is the LAST
//      `use="signing"` KeyDescriptor of the IDPSSODescriptor and of the
//      AttributeAuthorityDescriptor, in both documents.
//   W. `saml11_metadata_written.js`: a relying party filed by its own
//      metadata ask, then registered by `add` per value and `set
//      samlSpMetadata`, has the document CONSUMED — the artifact shire a
//      303 with a 42-byte type 0x0001 SAMLart, the POST shire the form, an
//      unbound consumer the default — the same through `update-fields`; a
//      refused document writes nothing (STS-ADMIN-0935).
//   T. `saml_idp_initiated_tab.js` a–e: `GET /admin-api/saml-idp-initiated`
//      lists, in a realm of its own, exactly the SAML entries whose sign-in
//      may be started here, each in its family, with what a row lacks, its
//      `/launch` link and protocol endpoint, the realm switches, the
//      realm's SAML 2.0 setting widening it, paging by `idpInitiatedPage`.
//
// OWNED HERE (local: true). Its realm is removed only on a private probe.
// ===========================================================================

// An address compared by parsing it, not searched for as text
// (`url_match.js`).
const urls = require("./url_match.js");
const assert = require("assert");
const K = require("./oauth_wire_kit.js").kit("sts_saml_sso_rules");
const S = require("./saml_wire_kit.js").samlKit(K);

const log = K.log;
const MFA = "urn:oasis:names:tc:SAML:2.0:ac:classes:" +
            "MobileTwoFactorContract";
const PHR = "http://schemas.openid.net/pape/policies/2007/06/" +
            "phishing-resistant";
const PHRH = "http://schemas.openid.net/acr/2016/07/" +
             "phishing-resistant-hardware";
const PPT = "urn:oasis:names:tc:SAML:2.0:ac:classes:" +
            "PasswordProtectedTransport";
let D = null;
const SP = "urn:saml-sso-rules:sp:" + K.STAMP;
const ACS = "https://sp.saml-sso-rules.example/acs";
const RP11 = "urn:saml-sso-rules:rp11:" + K.STAMP;

function sso(o) {
  log.debug("Entering sso().");
  const built = S.authnRequestXml(Object.assign({ issuer: SP, acs: ACS },
                                                o || {}));
  log.debug("Leaving sso().");
  return { id: built.id,
           url: S.redirect(K.rb(D) + "/saml2/sso", built.xml) };
}

// A code's rows, in the realm and the default realm (a refusal before the
// realm is known lands in the default one).
async function codeRose(code, act) {
  log.debug("Entering codeRose(). " + code);
  const inRealm = await K.codeCount(D, code);
  const inDefault = await K.codeCount(null, code);
  const answer = await act();
  let rose = 0;
  for (let i = 0; i < 20 && rose === 0; i += 1) {
    rose = (await K.codeCount(D, code)) - inRealm +
           (await K.codeCount(null, code)) - inDefault;
    if (rose === 0) {
      await K.sleep(150);
    }
  }
  log.debug("Leaving codeRose(). " + rose);
  return { answer: answer, rose: rose };
}

// --------------------------------------------------------------------- F
async function forceAuthn() {
  log.debug("Entering forceAuthn().");
  log.info("=== F. one trip to the sign-in screen per request ===");
  let b = K.browser();
  let f = await S.drive(D, b, sso({ force: true }).url,
                        { username: "fa-alice" });
  K.check("F1. ForceAuthn with no session: ONE trip and a Success Response",
          function () {
            assert.strictEqual(f.screens, 1);
            assert.ok(f.response && f.response.codes[0] === "Success",
                      JSON.stringify(f.response || K.shown(f.final)));
          });
  const sso1 = await S.drive(D, b, sso().url, { username: "fa-alice" });
  K.check("F6a. a plain request with a session is single sign-on, no " +
          "screen", function () {
    assert.strictEqual(sso1.screens, 0);
    assert.strictEqual(sso1.response.codes[0], "Success");
  });
  await K.sleep(1100);
  const before = f.response.authnInstant;
  f = await S.drive(D, b, sso({ force: true }).url, { username: "fa-alice" });
  K.check("F2. ForceAuthn WITH a session shows the screen once, and a " +
          "FRESH AuthnInstant", function () {
    assert.strictEqual(f.screens, 1);
    assert.strictEqual(f.response.codes[0], "Success");
    assert.ok(f.response.authnInstant > before,
              f.response.authnInstant + " vs " + before);
  });
  await K.sleep(1100);
  let c = await codeRose("STS-SAML-0055", function () {
    return S.drive(D, b, sso({ force: true }).url, { at: "skip" });
  });
  K.check("F3. ForceAuthn and back WITHOUT authenticating: AuthnFailed, " +
          "STS-SAML-0055, not the screen again", function () {
    assert.strictEqual(c.answer.screens, 1);
    assert.ok(c.answer.response &&
              c.answer.response.codes.indexOf("AuthnFailed") >= 0,
              JSON.stringify(c.answer.response));
    assert.ok(c.rose >= 1);
  });
  b = K.browser();
  c = await codeRose("STS-SAML-0009", function () {
    return S.drive(D, b, sso().url, { at: "cancel" });
  });
  K.check("F4. Cancel with no session: AuthnFailed after ONE trip, " +
          "reported as the cancellation (STS-SAML-0009)", function () {
    assert.strictEqual(c.answer.screens, 1);
    assert.ok(c.answer.response &&
              c.answer.response.codes.indexOf("AuthnFailed") >= 0,
              JSON.stringify(c.answer.response || K.shown(c.answer.final)));
    assert.ok(!/no session/.test(c.answer.response.message));
    assert.ok(c.rose >= 1);
  });
  b = K.browser();
  await S.drive(D, b, sso().url, { username: "fa-bob" });
  c = await codeRose("STS-SAML-0056", function () {
    return S.drive(D, b, sso({ context: MFA }).url, { at: "skip" });
  });
  K.check("F5. a multi-factor RequestedAuthnContext still unmet on the way " +
          "back: NoAuthnContext, STS-SAML-0056", function () {
    assert.strictEqual(c.answer.screens, 1);
    assert.ok(c.answer.response.codes.indexOf("NoAuthnContext") >= 0,
              JSON.stringify(c.answer.response));
    assert.ok(c.rose >= 1);
  });
  b = K.browser();
  f = await S.drive(D, b, sso({ passive: true }).url);
  K.check("F6b. IsPassive with no session is NoPassive, no screen",
          function () {
            assert.strictEqual(f.screens, 0);
            assert.ok(f.response.codes.indexOf("NoPassive") >= 0);
          });
  b = K.browser();
  await S.drive(D, b, sso().url, { username: "fa-erin" });
  c = await codeRose("STS-SAML-0116", function () {
    return S.drive(D, b, sso({ context: PHR }).url, { at: "skip" });
  });
  K.check("F7. only the phr URI forces a key and, unmet, is NoAuthnContext " +
          "(STS-SAML-0116) after one trip", function () {
    assert.strictEqual(c.answer.screens, 1);
    assert.strictEqual(((c.answer.view || {}).demands || {}).key, true,
                       JSON.stringify((c.answer.view || {}).demands));
    assert.ok(c.answer.response.codes.indexOf("NoAuthnContext") >= 0);
    assert.ok(c.rose >= 1);
  });
  f = await S.drive(D, b, sso({ context: PHRH }).url, { at: "skip" });
  K.check("F7b. the hardware URI the same: a key, then NoAuthnContext",
          function () {
            assert.strictEqual(f.screens, 1);
            assert.strictEqual(((f.view || {}).demands || {}).key, true);
            assert.ok(f.response.codes.indexOf("NoAuthnContext") >= 0);
          });
  f = await S.drive(D, b, sso({ context: [PPT, PHR] }).url);
  K.check("F8. phr beside PasswordProtectedTransport forces no trip; the " +
          "assertion keeps PasswordProtectedTransport", function () {
    assert.strictEqual(f.screens, 0);
    assert.strictEqual(f.response.codes[0], "Success");
    assert.strictEqual(f.response.classRef, PPT);
  });
  f = await S.drive(D, b, sso({ context: PHR, passive: true }).url);
  K.check("F9. IsPassive with a password session and only phr is NoPassive",
          function () {
            assert.strictEqual(f.screens, 0);
            assert.ok(f.response.codes.indexOf("NoPassive") >= 0);
            assert.ok(/RequestedAuthnContext/.test(f.response.message),
                      f.response.message);
          });
  const saml11 = function (withClass) {
    return K.rb(D) + "/saml11/sso?providerId=" + encodeURIComponent(RP11) +
      "&shire=" + encodeURIComponent(ACS) + "&TARGET=" +
      encodeURIComponent("https://sp.saml-sso-rules.example/app") +
      (withClass ? "&authnContextClassRef=" + encodeURIComponent(PHR) : "");
  };
  c = await codeRose("STS-SAML-0117", function () {
    return S.drive(D, b, saml11(true), { at: "skip" });
  });
  K.check("F10. SAML 1.1's authnContextClassRef is one trip, then a page " +
          "(STS-SAML-0117)", function () {
    assert.strictEqual(c.answer.screens, 1);
    assert.strictEqual(((c.answer.view || {}).demands || {}).key, true);
    assert.strictEqual(c.answer.final.status, 403, K.shown(c.answer.final));
    assert.ok(c.rose >= 1);
  });
  f = await S.drive(D, b, saml11(false));
  K.check("F10b. without it, the SAML 1.1 assertion keeps am:password",
          function () {
            assert.strictEqual(f.screens, 0);
            assert.strictEqual(f.response && f.response.method,
                               "urn:oasis:names:tc:SAML:1.0:am:password",
                               K.shown(f.final));
          });
  log.debug("Leaving forceAuthn().");
}

// --------------------------------------------------------------------- A
async function envelope() {
  log.debug("Entering envelope().");
  log.info("=== A. the envelope of an AuthnRequest ===");
  const refusedAs = async function (label, code, o) {
    const c = await codeRose(code, function () {
      return K.send(sso(o).url);
    });
    K.check("A. " + label + " is refused, " + code, function () {
      assert.strictEqual(c.answer.status, 400, K.shown(c.answer));
      assert.ok(c.rose >= 1, "no new " + code + " row");
    });
  };
  await refusedAs("an AuthnRequest whose Destination is another endpoint",
                  "STS-SAML-0085",
                  { destination: "https://other-idp.example/sso" });
  await refusedAs("one issued an hour ago", "STS-SAML-0086",
    { issueInstant: new Date(Date.now() - 3600000).toISOString() });
  await refusedAs("one issued ten minutes ahead", "STS-SAML-0086",
    { issueInstant: new Date(Date.now() + 600000).toISOString() });
  await refusedAs("a Version other than 2.0", "STS-SAML-0087",
                  { version: "1.1" });
  const once = S.authnRequestXml({ issuer: SP, acs: ACS });
  const url = S.redirect(K.rb(D) + "/saml2/sso", once.xml);
  const first = await K.send(url);
  const again = await codeRose("STS-SAML-0088", function () {
    return K.send(url);
  });
  K.check("A. a fresh unsigned request goes on to the sign-in screen; the " +
          "SAME request again is a replay, STS-SAML-0088", function () {
    assert.ok(K.toSignIn(first), K.shown(first));
    assert.strictEqual(again.answer.status, 400, K.shown(again.answer));
    assert.ok(again.rose >= 1);
  });
  const unaddressed = await K.send(sso({ destination: "" }).url);
  K.check("A. an UNSIGNED request with no Destination is still answered",
          function () {
            assert.ok(K.toSignIn(unaddressed), K.shown(unaddressed));
          });
  log.debug("Leaving envelope().");
}

// ---------------------------------------------------------------- B, E
function soap(inner) {
  log.debug("Entering soap().");
  log.debug("Leaving soap().");
  return '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/' +
    'envelope/"><soap:Body>' + inner + "</soap:Body></soap:Envelope>";
}

function nameIdOf(xml) {
  log.debug("Entering nameIdOf().");
  log.debug("Leaving nameIdOf().");
  return (/<saml:NameID[^>]*>([^<]+)<\/saml:NameID>/.exec(xml) || [])[1] || "";
}

async function backChannel() {
  log.debug("Entering backChannel().");
  log.info("=== B. a back-channel LogoutRequest ends the session it names ===");
  const b = K.browser();
  const f = await S.drive(D, b, sso().url, { username: "fa-gina" });
  const xml = f.response ? f.response.xml : "";
  const index = (/SessionIndex="([^"]+)"/.exec(xml) || [])[1] || "";
  const nameId = nameIdOf(xml);
  const lr = function (who) {
    return '<samlp:LogoutRequest xmlns:samlp="' + S.NS_SAMLP + '" ' +
      'xmlns:saml="' + S.NS_SAML + '" ID="_lr' + K.rand(8) + '" ' +
      'Version="2.0" IssueInstant="' + new Date().toISOString() + '">' +
      "<saml:Issuer>" + SP + "</saml:Issuer><saml:NameID>" + who +
      "</saml:NameID><samlp:SessionIndex>" + index +
      "</samlp:SessionIndex></samlp:LogoutRequest>";
  };
  const post = function (doc) {
    return K.send(K.rb(D) + "/saml2/slo", { form: {
      SAMLRequest: Buffer.from(doc).toString("base64") } });
  };
  const live = async function () {
    const r = await b.go(K.rb(D) + "/logout",
                         { headers: { accept: "application/json" } });
    return Number((r.json && r.json.sessions) || 0);
  };
  K.check("B0. (a sign-in gave the service provider a NameID and a " +
          "SessionIndex)", function () {
    assert.ok(index && nameId, xml.slice(0, 400));
  });
  const wrong = await codeRose("STS-SAML-0090", function () {
    return post(lr("somebody-else-" + K.rand(3)));
  });
  const stillLive = await live();
  K.check("B1. a SessionIndex with ANOTHER NameID ends nothing: " +
          "UnknownPrincipal, STS-SAML-0090", function () {
    const said = S.messageOf(wrong.answer.text, "SAMLResponse") ||
                 wrong.answer.text;
    assert.ok(/UnknownPrincipal/.test(said), said.slice(0, 400));
    assert.ok(wrong.rose >= 1);
    assert.ok(stillLive >= 1, "the session ended");
  });
  const right = await post(lr(nameId));
  const after = await live();
  K.check("B2. the NameID the session gave it: Success, and the session " +
          "it names is ended", function () {
    const said = S.messageOf(right.text, "SAMLResponse") || right.text;
    assert.ok(/status:Success/.test(said), said.slice(0, 400));
    assert.strictEqual(after, 0);
  });
  log.debug("Leaving backChannel().");
}

async function attributeAuthority() {
  log.debug("Entering attributeAuthority().");
  log.info("=== E. the SAML 2.0 attribute authority ===");
  const b = K.browser();
  const f = await S.drive(D, b, sso().url, { username: "fa-hal" });
  const nameId = nameIdOf(f.response ? f.response.xml : "");
  const query = function (who, attrs) {
    return soap('<samlp:AttributeQuery xmlns:samlp="' + S.NS_SAMLP + '" ' +
      'xmlns:saml="' + S.NS_SAML + '" ID="_aq' + K.rand(8) + '" ' +
      'Version="2.0" IssueInstant="' + new Date().toISOString() + '">' +
      "<saml:Issuer>" + SP + "</saml:Issuer><saml:Subject>" +
      '<saml:NameID NameQualifier="urn:qual:idp" SPNameQualifier="' + SP +
      '">' + who + "</saml:NameID></saml:Subject>" + (attrs || "") +
      "</samlp:AttributeQuery>");
  };
  const ask = function (body) {
    return K.send(K.rb(D) + "/saml2/aa", { method: "POST", raw: body,
      headers: { "Content-Type": "text/xml; charset=utf-8" } });
  };
  const none = await codeRose("STS-SAML-0095", function () {
    return ask(soap("<nothing/>"));
  });
  K.check("E1. a body that is not an AttributeQuery: Requester, " +
          "STS-SAML-0095", function () {
    assert.ok(/Requester/.test(none.answer.text), none.answer.text
      .slice(0, 300));
    assert.ok(none.rose >= 1);
  });
  const unknown = await codeRose("STS-SAML-0094", function () {
    return ask(query("nobody-" + K.rand(3)));
  });
  K.check("E2. a subject no live session gave this SP: UnknownPrincipal, " +
          "STS-SAML-0094", function () {
    assert.ok(/UnknownPrincipal/.test(unknown.answer.text));
    assert.ok(unknown.rose >= 1);
  });
  const known = await ask(query(nameId));
  K.check("E3. the subject a live session gave it: Success, the NameID's " +
          "qualifiers echoed, no AuthnStatement, no SubjectConfirmation",
          function () {
            const t = known.text;
            assert.ok(nameId, "no NameID was given");
            assert.ok(/status:Success/.test(t), t.slice(0, 400));
            assert.ok(/NameQualifier="urn:qual:idp"/.test(t));
            assert.ok(t.indexOf('SPNameQualifier="' + SP + '"') >= 0);
            assert.ok(!/AuthnStatement/.test(t) &&
                      !/SubjectConfirmation/.test(t));
          });
  const narrowed = await ask(query(nameId,
    '<saml:Attribute Name="urn:oid:0.9.2342.19200300.100.1.3" ' +
    'NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"/>'));
  K.check("E4. an attribute named in the query narrows the answer to it",
          function () {
            assert.ok(/Name="urn:oid:0\.9\.2342\.19200300\.100\.1\.3"/
              .test(narrowed.text), narrowed.text.slice(0, 400));
            assert.ok(!/Name="urn:oid:0\.9\.2342\.19200300\.100\.1\.1"/
              .test(narrowed.text));
          });
  log.debug("Leaving attributeAuthority().");
}

// --------------------------------------------------------------------- M
function presentedLeaf() {
  log.debug("Entering presentedLeaf().");
  const tls = require("tls");
  const u = new URL(K.base);
  return new Promise(function (resolve, reject) {
    const socket = tls.connect({ host: u.hostname, port: Number(u.port),
      servername: u.hostname }, function () {
      const raw = socket.getPeerCertificate().raw;
      socket.end();
      log.debug("Leaving presentedLeaf().");
      resolve(raw.toString("base64"));
    });
    socket.on("error", reject);
  });
}

function signingKeysIn(xml, role) {
  log.debug("Entering signingKeysIn(). " + role);
  const m = new RegExp("<md:" + role + "[\\s>][\\s\\S]*?</md:" + role +
                       ">").exec(xml);
  const out = [];
  if (m) {
    const re = /<md:KeyDescriptor use="signing">[\s\S]*?<ds:X509Certificate>([^<]+)<\/ds:X509Certificate>/g;
    let one = re.exec(m[0]);
    while (one) {
      out.push(one[1].replace(/\s+/g, ""));
      one = re.exec(m[0]);
    }
  }
  log.debug("Leaving signingKeysIn(). " + out.length);
  return out;
}

async function metadata() {
  log.debug("Entering metadata().");
  log.info("=== M. the metadata ===");
  const md = (await K.send(K.rb(D) + "/saml2/metadata/" +
                           encodeURIComponent(SP))).text;
  const md11 = (await K.send(K.rb(D) + "/saml11/metadata/" +
                             encodeURIComponent(RP11))).text;
  K.check("M1. the SAML 2.0 metadata publishes the attribute authority, " +
          "and no HTTP-Artifact SingleSignOnService", function () {
    assert.ok(/<md:AttributeAuthorityDescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2\.0:protocol urn:oasis:names:tc:SAML:1\.1:protocol">/
      .test(md), md.slice(0, 300));
    assert.ok(/<md:AttributeService Binding="urn:oasis:names:tc:SAML:2\.0:bindings:SOAP" Location="[^"]*\/saml2\/aa\//
      .test(md));
    assert.ok(!/SingleSignOnService Binding="urn:oasis:names:tc:SAML:2\.0:bindings:HTTP-Artifact"/
      .test(md));
  });
  const entityOf = function (xml) {
    return (/entityID="([^"]*)"/.exec(xml) || [])[1] || "";
  };
  K.check("M2. SAML 1.1's IDPSSODescriptor names urn:mace:shibboleth:1.0 " +
          "beside SAML 1.1 and 2.0, and both paths are one entity",
          function () {
            assert.ok(/<md:IDPSSODescriptor[^>]*protocolSupportEnumeration="urn:oasis:names:tc:SAML:2\.0:protocol urn:oasis:names:tc:SAML:1\.1:protocol urn:mace:shibboleth:1\.0"/
              .test(md11), md11.slice(0, 400));
            assert.strictEqual(entityOf(md11), entityOf(md));
          });
  const leaf = await presentedLeaf();
  for (const [label, doc] of [["SAML 2.0", md], ["SAML 1.1", md11]]) {
    for (const role of ["IDPSSODescriptor", "AttributeAuthorityDescriptor"]) {
      const keys = signingKeysIn(doc, role);
      K.check("M3. " + label + "'s " + role + " carries the certificate the " +
              "main port presents, LAST among its signing keys", function () {
        assert.ok(keys.length >= 2, keys.length + " signing keys");
        assert.strictEqual(keys[keys.length - 1], leaf);
        assert.notStrictEqual(keys[0], leaf);
      });
    }
  }
  log.debug("Leaving metadata().");
}

// --------------------------------------------------------------------- W
function saml11Metadata(entityId, endpoints) {
  log.debug("Entering saml11Metadata().");
  const P11 = "urn:oasis:names:tc:SAML:1.0:profiles:";
  log.debug("Leaving saml11Metadata().");
  return '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:' +
    'metadata" entityID="' + entityId + '"><md:SPSSODescriptor ' +
    'protocolSupportEnumeration="urn:oasis:names:tc:SAML:1.1:protocol">' +
    endpoints.map(function (one, i) {
      return '<md:AssertionConsumerService index="' + (i + 1) + '" ' +
        'Binding="' + P11 + one[0] + '" Location="' + one[1] + '"/>';
    }).join("") + "</md:SPSSODescriptor></md:EntityDescriptor>";
}

async function metadataWritten() {
  log.debug("Entering metadataWritten().");
  log.info("=== W. a relying party's metadata written to its entry ===");
  const b = K.browser();
  await S.drive(D, b, sso().url, { username: "fa-ivy" });
  const api = K.rb(D) + "/admin-api/applications/";
  const run = async function (label, viaUpdate) {
    const rp = "urn:saml-sso-rules:written:" + label + ":" + K.STAMP;
    const asked = await K.send(K.rb(D) + "/saml11/metadata/" +
                               encodeURIComponent(rp));
    const filed = await K.send(K.rb(D) + "/admin-api/applications?" +
                               "application=" + encodeURIComponent(rp));
    if (filed.status !== 200) {
      await K.ok(api + "create", { identifier: rp, name: rp,
        protocols: ["saml11"], fields: { samlEntityId: [rp] } },
      "filed " + rp);
    }
    K.check("W0 (" + label + "). the relying party is on file before it is " +
            "registered (its metadata ask: " + asked.status + ")",
            function () {
              assert.ok(asked.status === 200 || asked.status === 404);
            });
    const host = "https://rp-" + label + "-" + K.STAMP +
                 ".saml11.example.test";
    const post = host + "/SAML/POST";
    const artifact = host + "/SAML/Artifact/rp";
    const unbound = host + "/SAML/Unbound";
    for (const step of [["appAllowedProtocol", "saml11"],
                        ["samlAssertionConsumerService", post],
                        ["samlAssertionConsumerService", artifact],
                        ["samlAssertionConsumerService", unbound]]) {
      await K.ok(api + "add", { application: rp, attribute: step[0],
                                value: step[1] }, "add " + step[0]);
    }
    const doc = saml11Metadata(rp, [["browser-post", post],
                                    ["artifact-01", artifact]]);
    const written = viaUpdate
      ? await K.send(api + "update-fields", { json: { application: rp,
          fields: { samlSpMetadata: doc } } })
      : await K.send(api + "set", { json: { application: rp,
          attribute: "samlSpMetadata", value: doc } });
    K.check("W1 (" + label + "). the document is written", function () {
      assert.strictEqual(written.status, 200, written.text.slice(0, 300));
    });
    const signIn = function (shire) {
      return b.go(K.rb(D) + "/saml11/sso?" + new URLSearchParams({
        providerId: rp, shire: shire,
        TARGET: "https://" + label + ".test/done?x=1" }).toString());
    };
    const art = await signIn(artifact);
    const sAMLart = decodeURIComponent((/[?&]SAMLart=([^&]+)/.exec(
      art.location || "") || [])[1] || "");
    const raw = Buffer.from(sAMLart, "base64");
    K.check("W2 (" + label + "). the artifact shire is answered on " +
            "Browser/Artifact: a 303 carrying TARGET and a 42-byte type " +
            "0x0001 SAMLart", function () {
      assert.strictEqual(art.status, 303, K.shown(art));
      assert.ok(urls.isAt(art.location, artifact), String(art.location));
      assert.ok(/[?&]TARGET=/.test(art.location));
      assert.strictEqual(raw.length, 42);
      assert.strictEqual(raw.readUInt16BE(0), 1);
    });
    const posted = await signIn(post);
    const plain = await signIn(unbound);
    K.check("W3 (" + label + "). the POST shire is the Browser/POST form " +
            "posting to it; an unbound consumer the default (post)",
            function () {
              assert.strictEqual(posted.status, 200, K.shown(posted));
              assert.ok(/name="SAMLResponse"/.test(posted.text));
              assert.ok(posted.text.indexOf('action="' + post + '"') >= 0);
              assert.strictEqual(plain.status, 200);
              assert.ok(/name="SAMLResponse"/.test(plain.text));
            });
    return rp;
  };
  const rp = await run("set", false);
  await run("grid", true);
  const refused = await K.coded(D, "STS-ADMIN-0935", function () {
    return K.send(api + "set", { json: { application: rp,
      attribute: "samlSpMetadata", value: "<not-metadata/>" } });
  });
  const after = await K.send(K.rb(D) + "/admin-api/applications?" +
                             "application=" + encodeURIComponent(rp));
  K.check("W4. a document that is refused writes nothing, STS-ADMIN-0935",
          function () {
            assert.ok(refused.answer.status >= 400, refused.answer.text);
            assert.ok(refused.rose >= 1);
            assert.ok(after.text.indexOf("not-metadata") < 0);
          });
  log.debug("Leaving metadataWritten().");
}

// --------------------------------------------------------------------- T
async function idpInitiatedTab() {
  log.debug("Entering idpInitiatedTab().");
  log.info("=== T. GET /admin-api/saml-idp-initiated ===");
  const T = await K.realm("ssr-t", "development");
  const acs = "https://sp.idpinit-tab.example/acs";
  const id = function (x) {
    return "urn:idpinit-tab:" + x;
  };
  const make = function (x, protocols, fields) {
    return K.ok(K.rb(T) + "/admin-api/applications/create", {
      identifier: id(x), name: x, protocols: protocols,
      fields: fields }, "created " + x);
  };
  await make("a-saml2-on", ["saml2"], { samlEntityId: [id("a-saml2-on")],
    samlAssertionConsumerService: [acs], saml2IdpInitiatedSso: "TRUE" });
  await make("b-saml2-plain", ["saml2"], {
    samlEntityId: [id("b-saml2-plain")],
    samlAssertionConsumerService: [acs] });
  await make("c-saml11-on", ["saml11"], { samlEntityId: [id("c-saml11-on")],
    samlAssertionConsumerService: [acs], saml11IdpInitiatedSso: "TRUE" });
  await make("d-both-saml2-on", ["saml2", "saml11"], {
    samlEntityId: [id("d-both-saml2-on")],
    samlAssertionConsumerService: [acs], saml2IdpInitiatedSso: "TRUE" });
  await make("e-saml2-no-acs", ["saml2"], {
    samlEntityId: [id("e-saml2-no-acs")], saml2IdpInitiatedSso: "TRUE" });
  await make("f-wsfed-on", ["wsfed"], { wsfedRealm: [id("f-wsfed-on")],
    wsfedReplyUrl: ["https://rp.idpinit-tab.example/ws"],
    wsfedIdpInitiatedSso: "TRUE" });
  await make("g-saml2-off", ["saml2"], { samlEntityId: [id("g-saml2-off")],
    samlAssertionConsumerService: [acs], saml2IdpInitiatedSso: "FALSE" });
  const ask = async function (q) {
    return K.send(K.rb(T) + "/admin-api/saml-idp-initiated" +
                  (q ? "?" + q : ""));
  };
  const keysOf = function (r) {
    return ((r.json && r.json.idpInitiated) || []).map(function (row) {
      return row.identifier + "|" + row.protocol;
    });
  };
  const rowOf = function (r, x, protocol) {
    return ((r.json && r.json.idpInitiated) || []).filter(function (row) {
      return row.identifier === id(x) && row.protocol === protocol;
    })[0] || null;
  };
  let r = await ask();
  K.check("Ta1. with the realm settings off, only entries whose own " +
          "override is TRUE are listed, each in its own family, by " +
          "identifier", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.strictEqual(keysOf(r).join(), [id("a-saml2-on") + "|saml2",
      id("c-saml11-on") + "|saml11", id("d-both-saml2-on") + "|saml2",
      id("e-saml2-no-acs") + "|saml2"].join());
  });
  K.check("Ta2. the answer says both realm switches are off", function () {
    const sw = r.json.realmSwitches || [];
    assert.strictEqual(sw.length, 2);
    assert.ok(sw.every(function (one) {
      return one.enabled === false;
    }));
    assert.strictEqual(sw[0].setting, "saml2.idpInitiatedSso");
    assert.strictEqual(sw[1].setting, "saml11.idpInitiatedSso");
  });
  K.check("Ta3. a row with nowhere to send the sign-in says what it lacks",
          function () {
            assert.strictEqual(rowOf(r, "e-saml2-no-acs", "saml2").missing
              .join(), "samlAssertionConsumerService");
            assert.strictEqual(rowOf(r, "a-saml2-on", "saml2").missing.length,
                               0);
          });
  const on2 = rowOf(r, "a-saml2-on", "saml2");
  const on11 = rowOf(r, "c-saml11-on", "saml11");
  K.check("Tc. each row carries the /launch link, under the realm's own " +
          "prefix, and the protocol's own endpoint", function () {
    assert.strictEqual(on2.launchUrl, K.rb(T) + "/launch/" +
                       encodeURIComponent(id("a-saml2-on")) +
                       "?protocol=saml2");
    assert.ok(on2.endpoint.indexOf(K.rb(T) + "/saml2/unsolicited/") === 0,
              on2.endpoint);
    assert.strictEqual(on2.label, "SAML 2.0");
    assert.strictEqual(on2.name, "a-saml2-on");
    assert.strictEqual(on2.attribute, "saml2IdpInitiatedSso");
    assert.ok(on11.launchUrl.indexOf("?protocol=saml11") > 0);
    assert.ok(on11.endpoint.indexOf("/saml11/sso/") > 0);
  });
  const listedOpen = await K.send(on2.launchUrl);
  const unlisted = await K.send(K.rb(T) + "/launch/" +
    encodeURIComponent(id("b-saml2-plain")) + "?protocol=saml2");
  K.check("Ta4. what is listed is what the /launch door opens: a listed " +
          "row's link goes on, an unlisted entry's is refused", function () {
    assert.ok(listedOpen.status < 400, K.shown(listedOpen));
    assert.ok(unlisted.status >= 400, K.shown(unlisted));
  });
  await K.set(T, "saml2.idpInitiatedSso", true);
  r = await ask();
  K.check("Tb. with the realm's saml2.idpInitiatedSso on, an entry with " +
          "nothing on joins, FALSE stays out, SAML 1.1 still its own",
          function () {
            const k = keysOf(r);
            assert.ok(k.indexOf(id("b-saml2-plain") + "|saml2") >= 0, k);
            assert.ok(k.indexOf(id("g-saml2-off") + "|saml2") < 0);
            assert.ok(k.indexOf(id("d-both-saml2-on") + "|saml11") < 0);
          });
  const p2 = await ask("per=2&idpInitiatedPage=2");
  const far = await ask("per=2&idpInitiatedPage=99");
  K.check("Td. per and idpInitiatedPage page the list; a page past the end " +
          "is the last page; the paging names idpInitiatedPage", function () {
    const pg = p2.json.paging || p2.json.idpInitiatedPaging || {};
    assert.strictEqual(keysOf(p2).length, 2, p2.text.slice(0, 300));
    assert.strictEqual(pg.page, 2, JSON.stringify(pg));
    assert.strictEqual(pg.param, "idpInitiatedPage");
    const fp = far.json.paging || far.json.idpInitiatedPaging || {};
    assert.strictEqual(fp.page, fp.pages);
  });
  const mine = await K.send(K.rb(D) + "/admin-api/saml-idp-initiated");
  K.check("Te. another realm sees none of these applications", function () {
    assert.ok(keysOf(mine).every(function (k) {
      return k.indexOf("urn:idpinit-tab:") < 0;
    }));
  });
  log.debug("Leaving idpInitiatedTab().");
}

async function test() {
  log.debug("Entering test().");
  D = await K.realm("ssr-d", "development");
  await K.ok(K.rb(D) + "/admin-api/applications/create", { identifier: SP,
    name: "saml sso rules", protocols: ["saml2"],
    fields: { samlEntityId: [SP], samlAssertionConsumerService: [ACS] } },
  "created the service provider");
  await K.ok(K.rb(D) + "/admin-api/applications/create", { identifier: RP11,
    name: "saml 1.1 rules", protocols: ["saml11"],
    fields: { samlEntityId: [RP11], samlAssertionConsumerService: [ACS] } },
  "created the relying party");
  for (const who of ["fa-alice", "fa-bob", "fa-erin", "fa-gina", "fa-hal",
                     "fa-ivy"]) {
    await K.person(D, who, "Fa-Passw0rd!-" + K.rand(3));
  }
  await forceAuthn();
  await envelope();
  await backChannel();
  await attributeAuthority();
  await metadata();
  await metadataWritten();
  await idpInitiatedTab();
  log.debug("Leaving test().");
}

K.main(test, 49);
