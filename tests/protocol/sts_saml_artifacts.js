// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_saml_artifacts.js
//
// ===========================================================================
// WHO MAY RESOLVE AN ARTIFACT, THE ARTIFACT STORES' BOUNDS, AND THE
// HTTP-POST-SimpleSign BINDING, OVER THE WIRE (#37 follow-up, #160, #189,
// #614; #444 D12, phase 7).
//
// `tests/saml_artifact_and_simplesign.js` and `tests/saml_artifact_digests.js`
// fill the artifact stores directly and stub a TLS client certificate onto a
// request's socket. Here every artifact is one the service MINTED for a
// browser that signed in — a service provider asking for HTTP-Artifact as
// its ProtocolBinding (SAML 2.0) or a realm whose `saml11.defaultProfile` is
// artifact (SAML 1.1) — and every resolution is a SOAP POST to a running
// service, signed by the job's own keys, or carrying the service provider's
// certificate as the TLS client certificate on a connection of its own.
// Codes are read off `/admin-api/audit`.
//
//   B1. `/saml2/ars`: an UNSIGNED ArtifactResolve where signatures are
//       required is the EMPTY response (Success, nothing embedded, no
//       StatusMessage), STS-SAML-0077; another key (0061); SHA-1 (0073); a
//       validly signed request from ANOTHER service provider (0078) and one
//       naming no Issuer (0078); none of them spent it, and the service
//       provider's own signed request resolves it; a replay is the empty
//       response (0018), and a refused caller, a replay and an artifact never
//       minted get the SAME answer. With `saml.allowSha1Signatures` on, a
//       SHA-1 request resolves. The registered certificate as the TLS client
//       certificate authenticates an unsigned request, another does not
//       (0077). Development takes an unsigned caller by default; the same
//       realm in product refuses it (0077). A service provider whose metadata
//       EXPIRED is refused (0074). An EC-signed request resolves.
//   B1b. A resolver answers only for its own SourceID (#160): an artifact
//       minted in realm D presented at realm E's resolver, and at the
//       default realm's, is the empty response, STS-SAML-0098, and NOT spent;
//       at D's per-provider resolver it resolves under an ArtifactResponse
//       naming D's one issuer (#523).
//   B2. `/saml11/responder`: unsigned where required (0077); at ANOTHER
//       relying party's responder (0078); another key (0061); the relying
//       party's own signed Request resolves the artifact none of those spent;
//       its registered certificate over TLS; development's unsigned default;
//       a replay is Success with no assertion (0037); another realm's
//       artifact (0098), not spent.
//   C. HTTP-POST-SimpleSign: an AuthnRequest signed over the RAW XML is
//      verified and recorded `verified simplesign <SigAlg>`; RelayState
//      changed (0061), another key (0061), signed over the BASE64 text
//      (0061, #189); a LogoutRequest and a LogoutResponse verified, tampered
//      or another key's refused (0061); a Response SENT on it to a service
//      provider whose consumed metadata's only consumer is SimpleSign — the
//      SigAlg and Signature form fields verify, with the realm's own
//      certificate from its metadata, over the raw XML and not its base64,
//      and the Response carries no enveloped signature; a request asking for
//      SimpleSign as ProtocolBinding is answered on it; the identity
//      provider's metadata advertises it for SSO and SLO.
//   M. `saml_artifact_digests.js` B, C, E, F: `saml2.maxArtifacts` 1 — the
//      second delivery is a 503 page with no redirect, STS-SAML-0110, and
//      the first artifact still resolves; `saml2.artifactTtlS` 0 — an
//      artifact is refused at the read (0018); the same for SAML 1.1
//      (`saml11.maxArtifacts`, 0110; `saml11.artifactTtlS`, 0037); a SAML
//      1.1 assertion kept for AssertionIDReference is answered while live and
//      not once past its NotOnOrAfter (STS-SAML-0038).
//
// (d), not reachable by a request: the store's keys and journal (A, D) and
// the cache-ejection internals (F); a repeated SimpleSign form control's
// octets (the library function; the request is refused as tampered either
// way); the two-name SAML 1.1 artifact (`providerId` beside a `{rp}` path
// segment), whose audience a registered relying party cannot be minted
// under without an unregistered providerId, which development autocreates.
//
// OWNED HERE (local: true). Its realms are removed only on a private probe.
// ===========================================================================

const assert = require("assert");
const https = require("https");
const path = require("path");
const nodeCrypto = require("crypto");
const K = require("./oauth_wire_kit.js").kit("sts_saml_artifacts");
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
const NS_SAMLP11 = "urn:oasis:names:tc:SAML:1.0:protocol";
const NS_SOAP = "http://schemas.xmlsoap.org/soap/envelope/";
const NS_MD = "urn:oasis:names:tc:SAML:2.0:metadata";
const B_ARTIFACT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact";
const B_SIMPLESIGN =
  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign";
const DS = "http://www.w3.org/2000/09/xmldsig#";
const XENC = "http://www.w3.org/2001/04/xmlenc#";
let D = null;
let E = null;

function soap(inner) {
  log.debug("Entering soap().");
  log.debug("Leaving soap().");
  return '<soap:Envelope xmlns:soap="' + NS_SOAP + '"><soap:Body>' + inner +
    "</soap:Body></soap:Envelope>";
}

function artifactResolve(issuer, artifact) {
  log.debug("Entering artifactResolve().");
  log.debug("Leaving artifactResolve().");
  return '<samlp:ArtifactResolve xmlns:samlp="' + S.NS_SAMLP + '" ' +
    'xmlns:saml="' + S.NS_SAML + '" ID="_ar' + K.rand(8) + '" ' +
    'Version="2.0" IssueInstant="' + new Date().toISOString() + '">' +
    (issuer ? "<saml:Issuer>" + issuer + "</saml:Issuer>" : "") +
    "<samlp:Artifact>" + artifact + "</samlp:Artifact>" +
    "</samlp:ArtifactResolve>";
}

function request11(inner) {
  log.debug("Entering request11().");
  log.debug("Leaving request11().");
  return '<samlp:Request xmlns:samlp="' + NS_SAMLP11 + '" ' +
    'MajorVersion="1" MinorVersion="1" RequestID="_rq' + K.rand(8) +
    '" IssueInstant="' + new Date().toISOString() + '">' + inner +
    "</samlp:Request>";
}

function artifact11(artifact) {
  log.debug("Entering artifact11().");
  log.debug("Leaving artifact11().");
  return request11("<samlp:AssertionArtifact>" + artifact +
                   "</samlp:AssertionArtifact>");
}

// An enveloped signature by `cred` (RSA or EC), made with this repository's
// XML Signature engine and signed with node's own crypto. `o.sha1` signs
// and digests with SHA-1.
function signed(xml, cred, o) {
  log.debug("Entering signed().");
  const opts = o || {};
  const ec = cred.alg === "ec";
  const sigAlg = opts.sha1 ? S.RSA_SHA1 : (ec ? S.ECDSA_SHA256
                                               : S.RSA_SHA256);
  const hash = opts.sha1 ? "sha1" : "sha256";
  const hasIssuer = /<(?:[A-Za-z_][\w.-]*:)?Issuer\b/.test(xml);
  const out = xmldsig.signXml(xml, {
    sigAlg: sigAlg,
    digestUri: opts.sha1 ? DS + "sha1" : XENC + "sha256",
    placement: hasIssuer ? "after-issuer" : "first",
    keyInfo: "x509", certPem: cred.certificatePem,
    transforms: [{ algorithm: DS + "enveloped-signature" },
                 { algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#" }],
    signer: function (octets) {
      log.debug("Entering signer().");
      log.debug("Leaving signer().");
      return nodeCrypto.sign(hash, Buffer.from(octets, "binary"),
        ec ? { key: cred.privateKeyPem, dsaEncoding: "ieee-p1363" }
           : cred.privateKeyPem).toString("binary");
    }
  });
  log.debug("Leaving signed().");
  return out.xml;
}

// What a resolver answered: RESOLVED is Success WITH the message; a refusal
// is the EMPTY response (saml-core-2.0-os 3.5.3; saml-bindings-1.1 4.1.1.6
// for the responder) — Success, nothing embedded, no StatusMessage.
function verdict(r, eleven) {
  log.debug("Entering verdict().");
  const body = String(r.text || "");
  const ok = eleven ? /samlp:Success/.test(body) : /status:Success/.test(body);
  const carried = eleven ? /<saml:Assertion\b/.test(body)
                         : /<samlp:Response\b/.test(body);
  log.debug("Leaving verdict().");
  return Object.assign(r, { success: ok && carried,
                            empty: ok && !carried &&
                                   !/StatusMessage/.test(body) });
}

// A SOAP POST to `url`; with `tls` ({ cert, key }) on a connection of its
// own presenting that client certificate.
async function soapPost(url, body, tls) {
  log.debug("Entering soapPost(). " + url);
  if (!tls) {
    const r = await K.send(url, { raw: body, headers: {
      "Content-Type": "text/xml; charset=utf-8", SOAPAction: '""' } });
    log.debug("Leaving soapPost(). " + r.status);
    return r;
  }
  const u = new URL(url);
  const r = await new Promise(function (resolve, reject) {
    const req = https.request({ host: u.hostname, port: u.port,
      path: u.pathname, method: "POST", agent: false,
      headers: { "Content-Type": "text/xml; charset=utf-8",
                 SOAPAction: '""' },
      cert: tls.cert, key: tls.key },
    function (res) {
      let text = "";
      res.setEncoding("utf8");
      res.on("data", function (c) {
        text += c;
      });
      res.on("end", function () {
        resolve({ status: res.statusCode, text: text });
      });
    });
    req.on("error", reject);
    req.end(body);
  });
  log.debug("Leaving soapPost(). " + r.status);
  return r;
}

async function resolve2(url, body, tls) {
  log.debug("Entering resolve2().");
  const r = await soapPost(url, soap(body), tls);
  log.debug("Leaving resolve2().");
  return verdict(r, false);
}

async function resolve11(url, body, tls) {
  log.debug("Entering resolve11().");
  const r = await soapPost(url, soap(body), tls);
  log.debug("Leaving resolve11().");
  return verdict(r, true);
}

// A code's new rows in `ids` (realms; null is the default realm).
async function coded(ids, code, act) {
  log.debug("Entering coded(). " + code);
  const before = [];
  for (const id of ids) {
    before.push(await K.codeCount(id, code));
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
  log.debug("Leaving coded(). " + rose);
  return { answer: answer, rose: rose };
}

async function sp(id, label, cred, fields) {
  log.debug("Entering sp(). " + label);
  const identifier = "art-" + label + "-" + K.STAMP;
  await K.ok(K.rb(id) + "/admin-api/applications/create", {
    identifier: identifier, name: label, protocols: ["saml2"],
    fields: Object.assign({ samlEntityId: [identifier],
      samlAssertionConsumerService: ["https://" + identifier +
                                     ".example/acs"] },
    cred ? { samlSigningCertificate: [cred.certificatePem] } : {},
    fields || {}) }, "created " + label);
  log.debug("Leaving sp().");
  return identifier;
}

async function rp11(id, label, cred) {
  log.debug("Entering rp11(). " + label);
  const identifier = "art11-" + label + "-" + K.STAMP;
  await K.ok(K.rb(id) + "/admin-api/applications/create", {
    identifier: identifier, name: label, protocols: ["saml11"],
    fields: Object.assign({ samlEntityId: [identifier],
      samlAssertionConsumerService: ["https://" + identifier +
                                     ".example/shire"] },
    cred ? { samlSigningCertificate: [cred.certificatePem] } : {}) },
  "created " + label);
  log.debug("Leaving rp11().");
  return identifier;
}

function samlArtOf(r) {
  log.debug("Entering samlArtOf().");
  const loc = String((r && r.location) || "");
  const m = /[?&]SAMLart=([^&]+)/.exec(loc);
  log.debug("Leaving samlArtOf().");
  return m ? decodeURIComponent(m[1]) : "";
}

// A signed-in browser's sign-in to `issuer` on HTTP-Artifact: answers the
// final answer (the 303 to the consumer) and its artifact. `cred` signs
// the AuthnRequest on the Redirect binding.
async function mint2(id, b, issuer, cred) {
  log.debug("Entering mint2().");
  const built = S.authnRequestXml({ issuer: issuer,
    acs: "https://" + issuer + ".example/acs",
    destination: K.rb(id) + "/saml2/sso", binding: B_ARTIFACT });
  const f = await S.drive(id, b, S.redirect(K.rb(id) + "/saml2/sso",
                                            built.xml,
                                            cred ? { sign: cred } : {}),
                          { username: "art-alice" });
  log.debug("Leaving mint2().");
  return { final: f.final, artifact: samlArtOf(f.final) };
}

async function mint11(id, b, rp, username) {
  log.debug("Entering mint11().");
  const f = await S.drive(id, b, K.rb(id) + "/saml11/sso?" +
    new URLSearchParams({ providerId: rp,
      shire: "https://" + rp + ".example/shire",
      TARGET: "https://" + rp + ".example/app" }).toString(),
  { username: username || "art-alice" });
  log.debug("Leaving mint11().");
  return { final: f.final, artifact: samlArtOf(f.final) };
}

function tlsOf(cred) {
  log.debug("Entering tlsOf().");
  log.debug("Leaving tlsOf().");
  return { cert: cred.certificatePem, key: cred.privateKeyPem };
}

function shape(body) {
  log.debug("Entering shape().");
  log.debug("Leaving shape().");
  return String(body).replace(/ID="[^"]*"/g, "")
    .replace(/IssueInstant="[^"]*"/g, "")
    .replace(/InResponseTo="[^"]*"/g, "");
}

// --------------------------------------------------------------------- B1
async function resolution(c) {
  log.debug("Entering resolution().");
  log.info("=== B1. who may resolve a SAML 2.0 artifact ===");
  const ars = K.rb(D) + "/saml2/ars";
  const mine = await sp(D, "ars", c.a);
  const stranger = await sp(D, "ars-other", c.b);
  const b = K.browser();
  let m = await mint2(D, b, mine, c.a);
  K.check("B1a. a service provider asking for HTTP-Artifact is sent a 303 " +
          "carrying a 44-byte type 0x0004 SAMLart", function () {
    assert.strictEqual(m.final.status, 303, K.shown(m.final));
    const bytes = Buffer.from(m.artifact, "base64");
    assert.strictEqual(bytes.length, 44, m.artifact);
    assert.strictEqual(bytes.readUInt16BE(0), 4);
  });
  const art = m.artifact;
  await K.set(D, "saml2.requireSignedAuthnRequests", "on");
  let x = await coded([D], "STS-SAML-0077", function () {
    return resolve2(ars, artifactResolve(mine, art));
  });
  const unsigned = x.answer;
  K.check("B1b. an UNSIGNED ArtifactResolve where signatures are required " +
          "is the EMPTY response, STS-SAML-0077", function () {
    assert.ok(unsigned.empty, unsigned.text.slice(0, 400));
    assert.ok(x.rose >= 1);
  });
  x = await coded([D], "STS-SAML-0061", function () {
    return resolve2(ars, signed(artifactResolve(mine, art), c.b));
  });
  K.check("B1c. one signed by ANOTHER key is refused, STS-SAML-0061",
          function () {
            assert.ok(!x.answer.success, x.answer.text.slice(0, 300));
            assert.ok(x.rose >= 1);
          });
  x = await coded([D], "STS-SAML-0073", function () {
    return resolve2(ars, signed(artifactResolve(mine, art), c.a,
                                { sha1: true }));
  });
  K.check("B1d. one signed with SHA-1 is refused, STS-SAML-0073",
          function () {
            assert.ok(!x.answer.success, x.answer.text.slice(0, 300));
            assert.ok(x.rose >= 1);
          });
  x = await coded([D], "STS-SAML-0078", function () {
    return resolve2(ars, signed(artifactResolve(stranger, art), c.b));
  });
  const wrongSp = x.answer;
  K.check("B1e. a validly signed request from a DIFFERENT service provider " +
          "is the empty response, STS-SAML-0078", function () {
    assert.ok(wrongSp.empty, wrongSp.text.slice(0, 300));
    assert.ok(x.rose >= 1);
  });
  x = await coded([D], "STS-SAML-0078", function () {
    return resolve2(ars, artifactResolve("", art));
  });
  K.check("B1f. and so is one naming no Issuer, STS-SAML-0078", function () {
    assert.ok(x.answer.empty, x.answer.text.slice(0, 300));
    assert.ok(x.rose >= 1);
  });
  const good = await resolve2(ars, signed(artifactResolve(mine, art), c.a));
  K.check("B1g. NONE OF THOSE SPENT IT: the service provider's own signed " +
          "ArtifactResolve then resolves it to a Success Response",
          function () {
            assert.ok(good.success, good.text.slice(0, 400));
            assert.ok(/<samlp:Response\b[\s\S]*status:Success/
              .test(good.text));
          });
  x = await coded([D], "STS-SAML-0018", function () {
    return resolve2(ars, signed(artifactResolve(mine, art), c.a));
  });
  const again = x.answer;
  K.check("B1h. it is one-shot after that: the empty response, " +
          "STS-SAML-0018", function () {
    assert.ok(again.empty, again.text.slice(0, 300));
    assert.ok(x.rose >= 1);
  });
  const fake = Buffer.concat([Buffer.from(art, "base64").subarray(0, 24),
                              nodeCrypto.randomBytes(20)]).toString("base64");
  const never = await resolve2(ars, signed(artifactResolve(mine, fake),
                                           c.a));
  K.check("B1i. a refused caller, a replay and an artifact never minted " +
          "get the SAME answer — no oracle for whether one exists",
          function () {
            assert.ok(never.empty, never.text.slice(0, 300));
            assert.strictEqual(shape(never.text), shape(again.text));
            assert.strictEqual(shape(unsigned.text), shape(again.text));
            assert.strictEqual(shape(wrongSp.text), shape(again.text));
          });

  await K.set(D, "saml.allowSha1Signatures", true);
  m = await mint2(D, b, mine, c.a);
  const sha1On = await resolve2(ars, signed(artifactResolve(mine,
    m.artifact), c.a, { sha1: true }));
  K.check("B1j. with saml.allowSha1Signatures on, a SHA-1 ArtifactResolve " +
          "resolves", function () {
    assert.ok(sha1On.success, sha1On.text.slice(0, 300));
  });
  await K.unset(D, "saml.allowSha1Signatures");

  m = await mint2(D, b, mine, c.a);
  x = await coded([D], "STS-SAML-0077", function () {
    return resolve2(ars, artifactResolve(mine, m.artifact), tlsOf(c.b));
  });
  K.check("B1k. a TLS client certificate that is NOT the service " +
          "provider's authenticates nothing, STS-SAML-0077", function () {
    assert.ok(x.answer.empty, x.answer.text.slice(0, 300));
    assert.ok(x.rose >= 1);
  });
  const mapped = await resolve2(ars, artifactResolve(mine, m.artifact),
                                tlsOf(c.a));
  K.check("B1l. its REGISTERED certificate as the TLS client certificate " +
          "authenticates an unsigned ArtifactResolve, the artifact none of " +
          "that spent", function () {
    assert.ok(mapped.success, mapped.status + " " +
              mapped.text.slice(0, 300));
  });

  const ec = await sp(D, "ars-ec", c.ec);
  m = await mint2(D, b, ec, c.ec);
  const ecGood = await resolve2(ars, signed(artifactResolve(ec, m.artifact),
                                            c.ec));
  K.check("B1m. an EC (P-256) service provider's signed ArtifactResolve " +
          "resolves", function () {
    assert.ok(ecGood.success, ecGood.text.slice(0, 300));
  });

  await K.unset(D, "saml2.requireSignedAuthnRequests");
  m = await mint2(D, b, mine, c.a);
  const devUnsigned = await resolve2(ars, artifactResolve(mine,
                                                          m.artifact));
  K.check("B1n. development, by default: an unsigned caller is accepted",
          function () {
            assert.ok(devUnsigned.success, devUnsigned.text.slice(0, 300));
          });

  // EXPIRED METADATA: a service provider whose consumed document's
  // validUntil passes while its artifact is held.
  const old = await sp(D, "ars-expiring", c.a);
  const until = new Date(Date.now() + 5000).toISOString();
  const up = await K.send(K.rb(D) + "/admin-api/saml2/upload-metadata",
    { json: { sp: old, document: '<md:EntityDescriptor xmlns:md="' + NS_MD +
      '" entityID="' + old + '" validUntil="' + until + '">' +
      '<md:SPSSODescriptor protocolSupportEnumeration="' + S.NS_SAMLP +
      '"><md:AssertionConsumerService Binding="' + B_ARTIFACT +
      '" Location="https://' + old + '.example/acs" index="0"/>' +
      "</md:SPSSODescriptor></md:EntityDescriptor>" } });
  assert.strictEqual(up.status, 200, up.text.slice(0, 300));
  m = await mint2(D, b, old, c.a);
  assert.ok(m.artifact, "no artifact for the expiring provider: " +
            K.shown(m.final));
  await K.sleep(Math.max(0, Date.parse(until) - Date.now() + 1500));
  x = await coded([D], "STS-SAML-0074", function () {
    return resolve2(ars, signed(artifactResolve(old, m.artifact), c.a));
  });
  K.check("B1o. a service provider whose metadata EXPIRED is refused, " +
          "STS-SAML-0074", function () {
    assert.ok(!x.answer.success, x.answer.text.slice(0, 300));
    assert.ok(x.rose >= 1);
  });

  // THE SAME REALM IN PRODUCT: its held artifact, unsigned, refused.
  m = await mint2(D, b, mine, c.a);
  await K.set(D, "global.mode", "product");
  x = await coded([D], "STS-SAML-0077", function () {
    return resolve2(ars, artifactResolve(mine, m.artifact));
  });
  K.check("B1p. product, by default: an unsigned caller is refused, " +
          "STS-SAML-0077", function () {
    assert.ok(x.answer.empty, x.answer.text.slice(0, 300));
    assert.ok(x.rose >= 1);
  });
  const prodSigned = await resolve2(ars, signed(artifactResolve(mine,
    m.artifact), c.a));
  K.check("B1q. and its own signed request still resolves it there",
          function () {
            assert.ok(prodSigned.success, prodSigned.text.slice(0, 300));
          });
  await K.set(D, "global.mode", "development");
  log.debug("Leaving resolution().");
  return mine;
}

// -------------------------------------------------------------------- B1b
async function sourceIds(c, mine) {
  log.debug("Entering sourceIds().");
  log.info("=== B1b. a resolver answers only for its own SourceID ===");
  const b = K.browser();
  const m = await mint2(D, b, mine, c.a);
  let x = await coded([E], "STS-SAML-0098", function () {
    return resolve2(K.rb(E) + "/saml2/ars", signed(artifactResolve(mine,
      m.artifact), c.a));
  });
  K.check("B1b-1. realm D's artifact at realm E's resolver is the empty " +
          "response, STS-SAML-0098", function () {
    assert.ok(x.answer.empty, x.answer.text.slice(0, 300));
    assert.ok(x.rose >= 1);
  });
  x = await coded([null], "STS-SAML-0098", function () {
    return resolve2(K.base + "/saml2/ars", signed(artifactResolve(mine,
      m.artifact), c.a));
  });
  K.check("B1b-2. and at the default realm's, STS-SAML-0098", function () {
    assert.ok(x.answer.empty, x.answer.text.slice(0, 300));
    assert.ok(x.rose >= 1);
  });
  const md = (await K.send(K.rb(D) + "/saml2/metadata")).text;
  const issuer = (/entityID="([^"]+)"/.exec(md) || [])[1] || "";
  const own = await resolve2(K.rb(D) + "/saml2/ars/" + mine,
    signed(artifactResolve(mine, m.artifact), c.a));
  K.check("B1b-3. NEITHER SPENT IT: at D's per-provider resolver it " +
          "resolves, under an ArtifactResponse naming D's one issuer (#523)",
          function () {
            assert.ok(own.success, own.text.slice(0, 300));
            assert.ok(issuer && own.text.indexOf("<saml:Issuer>" + issuer +
                                                 "</saml:Issuer>") >= 0,
                      issuer + " " + own.text.slice(0, 400));
          });
  log.debug("Leaving sourceIds().");
}

// --------------------------------------------------------------------- B2
async function responder(c) {
  log.debug("Entering responder().");
  log.info("=== B2. the SAML 1.1 responder ===");
  await K.set(D, "saml11.defaultProfile", "artifact");
  const at = K.rb(D) + "/saml11/responder";
  const rp = await rp11(D, "rp", c.a);
  const rpOther = await rp11(D, "rp-other", null);
  const b = K.browser();
  let m = await mint11(D, b, rp);
  K.check("B2a. a Browser/Artifact sign-in is a 303 to the shire with a " +
          "42-byte type 0x0001 SAMLart", function () {
    assert.strictEqual(m.final.status, 303, K.shown(m.final));
    const bytes = Buffer.from(m.artifact, "base64");
    assert.strictEqual(bytes.length, 42, m.artifact);
    assert.strictEqual(bytes.readUInt16BE(0), 1);
  });
  const art = m.artifact;
  await K.set(D, "saml2.requireSignedAuthnRequests", "on");
  let x = await coded([D], "STS-SAML-0077", function () {
    return resolve11(at, artifact11(art));
  });
  K.check("B2b. an unsigned Request where signatures are required is the " +
          "response with no assertion, STS-SAML-0077", function () {
    assert.ok(x.answer.empty, x.answer.text.slice(0, 300));
    assert.ok(x.rose >= 1);
  });
  x = await coded([D], "STS-SAML-0078", function () {
    return resolve11(at + "/" + rpOther, signed(artifact11(art), c.a));
  });
  K.check("B2c. at ANOTHER relying party's responder it is refused, " +
          "STS-SAML-0078", function () {
    assert.ok(x.answer.empty, x.answer.text.slice(0, 300));
    assert.ok(x.rose >= 1);
  });
  x = await coded([D], "STS-SAML-0061", function () {
    return resolve11(at, signed(artifact11(art), c.b));
  });
  K.check("B2d. a Request signed by another key is refused, STS-SAML-0061",
          function () {
            assert.ok(!x.answer.success, x.answer.text.slice(0, 300));
            assert.ok(x.rose >= 1);
          });
  const good = await resolve11(at, signed(artifact11(art), c.a));
  K.check("B2e. the relying party's own signed Request resolves the " +
          "artifact none of those spent", function () {
    assert.ok(good.success, good.text.slice(0, 300));
  });
  m = await mint11(D, b, rp);
  const tls = await resolve11(at, artifact11(m.artifact), tlsOf(c.a));
  K.check("B2f. the registered certificate as the TLS client certificate " +
          "authenticates an unsigned Request", function () {
    assert.ok(tls.success, tls.text.slice(0, 300));
  });
  await K.unset(D, "saml2.requireSignedAuthnRequests");
  m = await mint11(D, b, rp);
  const dev = await resolve11(at, artifact11(m.artifact));
  K.check("B2g. development accepts an unsigned caller by default",
          function () {
            assert.ok(dev.success, dev.text.slice(0, 300));
          });
  x = await coded([D], "STS-SAML-0037", function () {
    return resolve11(at, artifact11(m.artifact));
  });
  K.check("B2h. a replay gets Success with no assertion, STS-SAML-0037",
          function () {
            assert.ok(x.answer.empty, x.answer.text.slice(0, 300));
            assert.ok(x.rose >= 1);
          });
  m = await mint11(D, b, rp);
  x = await coded([E], "STS-SAML-0098", function () {
    return resolve11(K.rb(E) + "/saml11/responder", artifact11(m.artifact));
  });
  K.check("B2i. realm D's SAML 1.1 artifact at realm E's responder is " +
          "answered with no assertion, STS-SAML-0098", function () {
    assert.ok(x.answer.empty, x.answer.text.slice(0, 300));
    assert.ok(x.rose >= 1);
  });
  const own = await resolve11(at + "/" + rp, artifact11(m.artifact));
  K.check("B2j. and NOT SPENT: it resolves at its relying party's own " +
          "responder", function () {
    assert.ok(own.success, own.text.slice(0, 300));
  });
  await K.unset(D, "saml11.defaultProfile");
  log.debug("Leaving responder().");
}

// ---------------------------------------------------------------------- C
function simpleForm(field, xml, relayState, cred, o) {
  log.debug("Entering simpleForm().");
  const opts = o || {};
  const value = Buffer.from(xml, "utf8").toString("base64");
  const sigAlg = cred.alg === "ec" ? S.ECDSA_SHA256 : S.RSA_SHA256;
  // THE SIGNED OCTETS ARE THE RAW XML (the SimpleSign binding, section
  // 2.5, step 2); `overBase64` signs the base64 text, which is what this
  // service did until #189.
  const octets = field + "=" + (opts.overBase64 ? value : xml) +
    (relayState !== undefined ? "&RelayState=" + relayState : "") +
    "&SigAlg=" + sigAlg;
  const key = (opts.signWith || cred).privateKeyPem;
  const sig = nodeCrypto.sign("sha256", Buffer.from(octets, "utf8"),
    cred.alg === "ec" ? { key: key, dsaEncoding: "der" } : key);
  const form = {};
  form[field] = value;
  if (relayState !== undefined) {
    form.RelayState = opts.tamper ? relayState + "X" : relayState;
  }
  form.SigAlg = sigAlg;
  form.Signature = sig.toString("base64");
  log.debug("Leaving simpleForm().");
  return form;
}

async function postFollow(url, form) {
  log.debug("Entering postFollow().");
  const r = await K.send(url, { form: form });
  if ((r.status === 302 || r.status === 303) && /\?rid=/.test(r.location)) {
    log.debug("Leaving postFollow(). Through the held request.");
    return K.send(/^https?:/.test(r.location) ? r.location
                                              : K.base + r.location);
  }
  log.debug("Leaving postFollow().");
  return r;
}

async function fieldsOf(id, identifier) {
  log.debug("Entering fieldsOf().");
  const r = await K.send(K.rb(id) + "/admin-api/applications?application=" +
                         encodeURIComponent(identifier));
  log.debug("Leaving fieldsOf().");
  return ((r.json || {}).attributes) || ((r.json || {}).fields) || {};
}

function formField(text, name) {
  log.debug("Entering formField().");
  const m = new RegExp('name="' + name + '" value="([^"]*)"')
    .exec(String(text || ""));
  log.debug("Leaving formField().");
  return m ? m[1].replace(/&#x2B;|&#43;/g, "+").replace(/&#x3D;|&#61;/g, "=")
    .replace(/&#x2F;|&#47;/g, "/").replace(/&amp;/g, "&")
    .replace(/&quot;/g, '"').replace(/&#x20;|&#32;/g, " ") : "";
}

function verifiesWithAny(octets, sigAlg, signature, certs) {
  log.debug("Entering verifiesWithAny().");
  const hash = /sha512$/.test(sigAlg) ? "sha512"
    : (/sha384$/.test(sigAlg) ? "sha384"
      : (/sha1$/.test(sigAlg) ? "sha1" : "sha256"));
  const ec = /ecdsa/.test(sigAlg);
  const ok = certs.some(function (b64) {
    const pem = "-----BEGIN CERTIFICATE-----\n" +
      b64.replace(/(.{64})/g, "$1\n") + "\n-----END CERTIFICATE-----\n";
    try {
      const key = new nodeCrypto.X509Certificate(pem).publicKey;
      return nodeCrypto.verify(hash, Buffer.from(octets, "utf8"),
        ec ? { key: key, dsaEncoding: "ieee-p1363" } : key,
        Buffer.from(signature, "base64"));
    } catch (e) {
      log.debug("Caught in verifiesWithAny(): " + ((e && e.message) || e));
      // A certificate this job cannot read verifies nothing.
      return false;
    }
  });
  log.debug("Leaving verifiesWithAny(). " + ok);
  return ok;
}

async function simpleSign(c) {
  log.debug("Entering simpleSign().");
  log.info("=== C. HTTP-POST-SimpleSign ===");
  const ssoUrl = K.rb(D) + "/saml2/sso";
  const sloUrl = K.rb(D) + "/saml2/slo";
  const ssp = await sp(D, "simplesign", c.a, { samlSingleLogoutService:
    ["https://art-simplesign-" + K.STAMP + ".example/slo"] });
  const authn = S.authnRequestXml({ issuer: ssp,
    acs: "https://" + ssp + ".example/acs", destination: ssoUrl }).xml;
  const simple = await postFollow(ssoUrl, simpleForm("SAMLRequest", authn,
                                                     "r/s+1", c.a));
  const f = await fieldsOf(D, ssp);
  K.check("C1. a SimpleSign AuthnRequest is VERIFIED over the form values, " +
          "unencoded, recorded so, and goes on to the sign-in screen",
          function () {
            assert.ok(K.toSignIn(simple), K.shown(simple));
            assert.strictEqual(String(f.samlAuthnRequestVerification || "")
              .indexOf("verified simplesign " + S.RSA_SHA256), 0,
            JSON.stringify(f.samlAuthnRequestVerification));
          });
  for (const [label, form] of [
    ["C2. one whose RelayState was changed",
     simpleForm("SAMLRequest", authn, "r/s+1", c.a, { tamper: true })],
    ["C3. one signed by another key",
     simpleForm("SAMLRequest", authn, undefined, c.a, { signWith: c.b })],
    ["C4. one signed over the BASE64 text rather than the raw XML (#189)",
     simpleForm("SAMLRequest", authn, "r/s+1", c.a, { overBase64: true })]]) {
    const x = await coded([D], "STS-SAML-0061", function () {
      return postFollow(ssoUrl, form);
    });
    K.check(label + " is REFUSED, 403, STS-SAML-0061", function () {
      assert.strictEqual(x.answer.status, 403, K.shown(x.answer));
      assert.ok(x.rose >= 1);
    });
  }
  const logout = '<samlp:LogoutRequest xmlns:samlp="' + S.NS_SAMLP + '" ' +
    'xmlns:saml="' + S.NS_SAML + '" ID="_sl' + K.rand(6) + '" ' +
    'Version="2.0" IssueInstant="' + new Date().toISOString() +
    '" Destination="' + sloUrl + '"><saml:Issuer>' + ssp +
    "</saml:Issuer><saml:NameID>art-alice</saml:NameID>" +
    "</samlp:LogoutRequest>";
  const sloOk = await K.send(sloUrl, { form: simpleForm("SAMLRequest",
    logout, "lo", c.a) });
  K.check("C5. a SimpleSign LogoutRequest is accepted", function () {
    assert.ok(sloOk.status !== 403 && sloOk.status < 500, K.shown(sloOk));
  });
  let x = await coded([D], "STS-SAML-0061", function () {
    return K.send(sloUrl, { form: simpleForm("SAMLRequest", logout, "lo",
                                             c.a, { tamper: true }) });
  });
  K.check("C6. a tampered SimpleSign LogoutRequest is refused, 403, " +
          "STS-SAML-0061", function () {
    assert.strictEqual(x.answer.status, 403, K.shown(x.answer));
    assert.ok(x.rose >= 1);
  });
  const answer = '<samlp:LogoutResponse xmlns:samlp="' + S.NS_SAMLP + '" ' +
    'xmlns:saml="' + S.NS_SAML + '" ID="_sr' + K.rand(6) + '" ' +
    'Version="2.0" IssueInstant="' + new Date().toISOString() + '">' +
    "<saml:Issuer>" + ssp + "</saml:Issuer><samlp:Status><samlp:StatusCode " +
    'Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
    "</samlp:LogoutResponse>";
  const lrOk = await K.send(sloUrl, { form: simpleForm("SAMLResponse",
    answer, undefined, c.a) });
  K.check("C7. a SimpleSign LogoutResponse is verified", function () {
    assert.strictEqual(lrOk.status, 200, K.shown(lrOk));
    assert.ok(/verified/.test(lrOk.text), K.shown(lrOk));
  });
  x = await coded([D], "STS-SAML-0061", function () {
    return K.send(sloUrl, { form: simpleForm("SAMLResponse", answer,
      undefined, c.a, { signWith: c.b }) });
  });
  K.check("C8. and one signed by another key is refused, STS-SAML-0061",
          function () {
            assert.ok(x.answer.status >= 400, K.shown(x.answer));
            assert.ok(x.rose >= 1);
          });

  // THE RESPONSE, SENT ON SIMPLESIGN, to a provider whose consumed
  // metadata's one consumer is SimpleSign.
  await K.set(D, "saml2.signResponse", true);
  const acsSp = await sp(D, "simplesign-acs", null);
  const acs = "https://" + acsSp + ".example/simplesign-acs";
  const up = await K.send(K.rb(D) + "/admin-api/saml2/upload-metadata",
    { json: { sp: acsSp, document: '<md:EntityDescriptor xmlns:md="' +
      NS_MD + '" entityID="' + acsSp + '"><md:SPSSODescriptor ' +
      'protocolSupportEnumeration="' + S.NS_SAMLP + '">' +
      '<md:AssertionConsumerService Binding="' + B_SIMPLESIGN +
      '" Location="' + acs + '" index="0"/></md:SPSSODescriptor>' +
      "</md:EntityDescriptor>" } });
  K.check("C9. metadata whose only consumer is SimpleSign is consumed",
          function () {
            assert.strictEqual(up.status, 200, up.text.slice(0, 300));
          });
  const b = K.browser();
  // No AssertionConsumerServiceURL: the consumed metadata's one endpoint
  // is what is chosen. (The kit always names a ProtocolBinding, so the
  // request names the endpoint's own; one naming HTTP-POST would find no
  // consumer on it, STS-SAML-0072.)
  const built = S.authnRequestXml({ issuer: acsSp, destination: ssoUrl,
                                    binding: B_SIMPLESIGN });
  const walked = await S.drive(D, b, S.redirect(ssoUrl, built.xml,
    { relayState: "state 1" }), { username: "art-alice" });
  const page = walked.final.text;
  const xml = S.messageOf(page);
  const sigAlg = formField(page, "SigAlg");
  const signature = formField(page, "Signature");
  K.check("C10. the Response is POSTed to the SimpleSign consumer with " +
          "SigAlg and Signature form fields", function () {
    assert.ok(page.indexOf('action="' + acs + '"') >= 0,
              K.shown(walked.final));
    assert.ok(/<samlp:Response\b/.test(xml), xml.slice(0, 200));
    assert.ok(sigAlg && signature, page.slice(0, 600));
  });
  const root = xml.slice(0, xml.indexOf("<saml:Assertion") >= 0
    ? xml.indexOf("<saml:Assertion") : xml.length);
  K.check("C11. with NO enveloped signature on the Response itself",
          function () {
            assert.ok(!/<ds:Signature\b/.test(root), root.slice(0, 300));
          });
  const md = (await K.send(K.rb(D) + "/saml2/metadata")).text;
  const idp = md.slice(md.indexOf("<md:IDPSSODescriptor"),
                       md.indexOf("</md:IDPSSODescriptor>"));
  const certs = [];
  idp.replace(/<md:KeyDescriptor use="signing">[\s\S]*?<ds:X509Certificate>([^<]+)</g,
    function (all, one) {
      certs.push(one.replace(/\s+/g, ""));
      return all;
    });
  const octets = "SAMLResponse=" + xml + "&RelayState=state 1&SigAlg=" +
                 sigAlg;
  K.check("C12. the Signature verifies over the SimpleSign octets — the " +
          "RAW XML — with a signing certificate of the realm's metadata, " +
          "and not once RelayState changes", function () {
    assert.ok(certs.length >= 1, idp.slice(0, 400));
    assert.ok(verifiesWithAny(octets, sigAlg, signature, certs));
    assert.ok(!verifiesWithAny(octets.replace("state 1", "state 2"),
                               sigAlg, signature, certs));
  });
  K.check("C13. and NOT over the base64 text, which is what it signed " +
          "until #189", function () {
    assert.ok(!verifiesWithAny("SAMLResponse=" +
      Buffer.from(xml, "utf8").toString("base64") +
      "&RelayState=state 1&SigAlg=" + sigAlg, sigAlg, signature, certs));
  });
  const asked = S.authnRequestXml({ issuer: ssp, destination: ssoUrl,
    acs: "https://" + ssp + ".example/acs", binding: B_SIMPLESIGN });
  const askedWalk = await S.drive(D, b, S.redirect(ssoUrl, asked.xml),
                                  { username: "art-alice" });
  K.check("C14. a request asking for SimpleSign as ProtocolBinding is " +
          "answered on it", function () {
    assert.ok(formField(askedWalk.final.text, "SigAlg") &&
              formField(askedWalk.final.text, "Signature"),
    K.shown(askedWalk.final));
    assert.ok(/<samlp:Response\b/.test(S.messageOf(askedWalk.final.text)));
  });
  K.check("C15. the identity provider's metadata ADVERTISES SimpleSign for " +
          "SingleSignOnService and SingleLogoutService", function () {
    assert.ok(new RegExp('<md:SingleSignOnService Binding="' +
                         B_SIMPLESIGN).test(md), idp.slice(0, 600));
    assert.ok(new RegExp('<md:SingleLogoutService Binding="' +
                         B_SIMPLESIGN).test(md));
  });
  await K.unset(D, "saml2.signResponse");
  log.debug("Leaving simpleSign().");
}

// ---------------------------------------------------------------------- M
async function bounds(c) {
  log.debug("Entering bounds().");
  log.info("=== M. the artifact stores' bounds and lifetimes ===");
  const M = await K.realm("art-m", "development");
  await K.person(M, "art-alice", "Art-Passw0rd!-" + K.rand(3));
  const mine = await sp(M, "cap", c.a);
  const ars = K.rb(M) + "/saml2/ars";
  await K.set(M, "saml2.maxArtifacts", 1);
  const b = K.browser();
  const first = await mint2(M, b, mine, c.a);
  const x = await coded([M], "STS-SAML-0110", function () {
    return mint2(M, b, mine, c.a);
  });
  K.check("M1. saml2.maxArtifacts 1: the second delivery is REFUSED — a " +
          "503 page, no redirect to the service provider, STS-SAML-0110",
          function () {
            assert.ok(first.artifact, K.shown(first.final));
            assert.strictEqual(x.answer.final.status, 503,
                               K.shown(x.answer.final));
            assert.ok(!x.answer.final.location && !x.answer.artifact);
            assert.ok(x.rose >= 1);
          });
  const kept = await resolve2(ars, artifactResolve(mine, first.artifact));
  K.check("M2. nothing was evicted to make room: the first still resolves",
          function () {
            assert.ok(kept.success, kept.text.slice(0, 300));
          });
  const third = await mint2(M, b, mine, c.a);
  K.check("M3. and once it is resolved the store takes the next one",
          function () {
            assert.ok(third.artifact, K.shown(third.final));
          });
  await K.unset(M, "saml2.maxArtifacts");
  await K.set(M, "saml2.artifactTtlS", 0);
  const stale = await mint2(M, b, mine, c.a);
  await K.sleep(1100);
  let y = await coded([M], "STS-SAML-0018", function () {
    return resolve2(ars, artifactResolve(mine, stale.artifact));
  });
  K.check("M4. saml2.artifactTtlS 0: an expired artifact is refused AT " +
          "THE READ, the empty response, STS-SAML-0018", function () {
    assert.ok(stale.artifact, K.shown(stale.final));
    assert.ok(y.answer.empty, y.answer.text.slice(0, 300));
    assert.ok(y.rose >= 1);
  });
  await K.unset(M, "saml2.artifactTtlS");

  await K.set(M, "saml11.defaultProfile", "artifact");
  const rp = await rp11(M, "cap", c.a);
  const at = K.rb(M) + "/saml11/responder";
  await K.set(M, "saml11.maxArtifacts", 1);
  const one11 = await mint11(M, b, rp);
  y = await coded([M], "STS-SAML-0110", function () {
    return mint11(M, b, rp);
  });
  K.check("M5. saml11.maxArtifacts 1: the next Browser/Artifact delivery " +
          "is a 503 page with no redirect, STS-SAML-0110", function () {
    assert.ok(one11.artifact, K.shown(one11.final));
    assert.strictEqual(y.answer.final.status, 503, K.shown(y.answer.final));
    assert.ok(!y.answer.final.location);
    assert.ok(y.rose >= 1);
  });
  const kept11 = await resolve11(at, artifact11(one11.artifact));
  K.check("M6. and the unresolved one is kept and resolves", function () {
    assert.ok(kept11.success, kept11.text.slice(0, 300));
  });
  await K.unset(M, "saml11.maxArtifacts");
  await K.set(M, "saml11.artifactTtlS", 0);
  const stale11 = await mint11(M, b, rp);
  await K.sleep(1100);
  y = await coded([M], "STS-SAML-0037", function () {
    return resolve11(at, artifact11(stale11.artifact));
  });
  K.check("M7. saml11.artifactTtlS 0: an expired SAML 1.1 artifact is " +
          "refused at the read, STS-SAML-0037", function () {
    assert.ok(y.answer.empty, y.answer.text.slice(0, 300));
    assert.ok(y.rose >= 1);
  });
  await K.unset(M, "saml11.artifactTtlS");

  // A KEPT ASSERTION, answered by AssertionIDReference while live.
  const live = await mint11(M, b, rp);
  const got = await resolve11(at, artifact11(live.artifact));
  const assertionId = (/AssertionID="([^"]+)"/.exec(got.text) || [])[1];
  const ref = function (id) {
    log.debug("Entering ref().");
    log.debug("Leaving ref().");
    return request11("<samlp:AssertionIDReference>" + id +
                     "</samlp:AssertionIDReference>");
  };
  const liveRef = await resolve11(at, ref(assertionId));
  K.check("M8. a live assertion is answered by AssertionIDReference",
          function () {
            assert.ok(assertionId, got.text.slice(0, 300));
            assert.ok(liveRef.success && liveRef.text.indexOf(assertionId) >=
                      0, liveRef.text.slice(0, 300));
          });
  // ONE MINUTE, the shortest lifetime that is one, so the wait is the
  // minute, once. 0 is refused by the setting (#39, 2026-11-15); until then
  // it was accepted and read as the default 60 (`Number(...) || 60`).
  const zero = await K.send(K.base + "/admin-api/realms/set",
    { json: { id: M, key: "saml11.assertionLifetimeMin", value: "0" } });
  K.check("M8b. realms/set refuses saml11.assertionLifetimeMin 0 (#39)",
          function () {
            assert.strictEqual(zero.status, 400, K.shown(zero));
          });
  await K.set(M, "saml11.assertionLifetimeMin", 1);
  const brief = await mint11(M, b, rp);
  const briefGot = await resolve11(at, artifact11(brief.artifact));
  const briefId = (/AssertionID="([^"]+)"/.exec(briefGot.text) || [])[1];
  const until = (/NotOnOrAfter="([^"]+)"/.exec(briefGot.text) || [])[1];
  await K.sleep(Math.max(0, Date.parse(until) - Date.now() + 1500));
  y = await coded([M], "STS-SAML-0038", function () {
    return resolve11(at, ref(briefId));
  });
  K.check("M9. one past its NotOnOrAfter is NOT answered, STS-SAML-0038",
          function () {
            assert.ok(briefId && until, briefGot.text.slice(0, 300));
            assert.ok(!/<saml:Assertion\b/.test(y.answer.text),
                      y.answer.text.slice(0, 300));
            assert.ok(y.rose >= 1);
          });
  log.debug("Leaving bounds().");
}

async function test() {
  log.debug("Entering test().");
  D = await K.realm("art-d", "development");
  E = await K.realm("art-e", "development");
  await K.person(D, "art-alice", "Art-Passw0rd!-" + K.rand(3));
  const c = { a: await S.credential("art-a"), b: await S.credential("art-b"),
              ec: await S.credential("art-ec", "ec") };
  const mine = await resolution(c);
  await sourceIds(c, mine);
  await responder(c);
  await simpleSign(c);
  await bounds(c);
  log.debug("Leaving test().");
}

K.main(test, 54);
