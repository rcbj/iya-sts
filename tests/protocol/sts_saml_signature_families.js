// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_saml_signature_families.js
//
// ===========================================================================
// EVERY XML SIGNATURE FAMILY THE SERVICE VERIFIES, OVER THE WIRE (#37
// follow-up; #444 D12, phase 7).
//
// `tests/saml_signature_algorithms.js` holds the families against the
// handlers off the router. Here each family's key is made by
// `tests/tools/saml_signing_kit.js` (node's own crypto, certificates built by
// hand: nothing in this repository issues an Ed448, DSA or SLH-DSA
// certificate) and every request goes to a product realm P of the job's own,
// where a service provider's request must be signed:
//
//   1. for each of the kit's families — RSA (PKCS#1 v1.5, PSS), ECDSA, EdDSA,
//      DSA, ML-DSA, SLH-DSA — the certificate is registered through
//      `/admin-api/saml2/set-signing-certificate`; an enveloped AuthnRequest
//      on the POST binding and a detached one on the Redirect binding are
//      VERIFIED (recorded `verified post` / `verified redirect <SigAlg>`) and
//      go on to the sign-in screen; each tampered is refused (STS-SAML-0061);
//      a metadata document signed with the key verifies against
//      `set-metadata-signing-certificate` (`samlSpMetadataSignature`
//      verified), its KeyDescriptor certificate is consumed, and a tampered
//      one is refused.
//   2. Single Logout for ECDSA P-384, Ed25519 and ML-DSA-44: a signed
//      LogoutRequest accepted, a tampered one refused ending nothing, a
//      signed LogoutResponse verified, another key's refused.
//   3. SHA-1: as the DigestMethod under an RSA-SHA256 SignatureMethod, a
//      request is refused (STS-SAML-0073); signed metadata is refused
//      (STS-SAML-0065); in a development realm with
//      `saml.allowSha1Signatures` on it verifies. RSA-MD5 cannot be checked
//      and is refused by name (STS-SAML-0062), never as a wrong signature.
//
// NEEDS a runtime whose crypto generates ML-DSA and SLH-DSA keys (node 24,
// the tests image's); a family the runtime cannot make FAILS the job rather
// than being skipped.
//
// NOT HERE: the federation and RFC 7522 paths (A) — owed with the
// federation partner jobs; HMAC and HSS/LMS as `verifyQueryString()` verdicts
// (functions, class (d)).
//
// OWNED HERE (local: true). Its realms are removed only on a private probe.
// ===========================================================================

const assert = require("assert");
const path = require("path");
const zlib = require("zlib");
const K = require("./oauth_wire_kit.js").kit("sts_saml_signature_families");
const S = require("./saml_wire_kit.js").samlKit(K);
const kit = require("../tools/saml_signing_kit.js");
const xmldom = require("@xmldom/xmldom");
if (!global.DOMParser) {
  global.DOMParser = xmldom.DOMParser;
}
if (!global.XMLSerializer) {
  global.XMLSerializer = xmldom.XMLSerializer;
}
const REPO = process.env.MOCK_STS_DIR || path.join(__dirname, "..", "..");
const ENGINE = { xmldsig: require(path.join(REPO, "common", "crypto_impl",
                                            "xmldsig.js")) };

const log = K.log;
const U = kit.URIS;

// THE ENGINE'S SHELL KNOWS THE RSA URIS; `common/crypto.js` registers the
// rest into its table when it loads (its section 1a). This job does not load
// the service's crypto module, so it registers the kit's URIs the same way
// — only the shell's bookkeeping (a digest default and a label): the
// signature value is the kit's, made with node's crypto by `signer`.
kit.FAMILIES.forEach(function (row) {
  if (!ENGINE.xmldsig.SIG_METHODS[row[1]]) {
    ENGINE.xmldsig.SIG_METHODS[row[1]] = { family: row[2], hash:
      (row[4] && row[4].hash) || null, keyKind: row[2],
      digestUri: U.XENC + "sha256", label: row[0],
      registeredBy: "sts_saml_signature_families.js" };
  }
});
const NS_MD = "urn:oasis:names:tc:SAML:2.0:metadata";
let P = null;
let D = null;

function slug(text) {
  log.debug("Entering slug().");
  log.debug("Leaving slug().");
  return String(text).replace(/[^a-z0-9]/g, "");
}

async function sp(realm, label, fields) {
  log.debug("Entering sp(). " + label);
  const identifier = "ssf-" + label + "-" + K.STAMP;
  await K.ok(K.rb(realm) + "/admin-api/applications/create", {
    identifier: identifier, name: label, protocols: ["saml2"],
    fields: Object.assign({ samlEntityId: [identifier],
      samlAssertionConsumerService: ["https://" + identifier +
                                     ".example/acs"] }, fields || {}) },
  "created " + label);
  log.debug("Leaving sp().");
  return identifier;
}

function authn(realm, issuer) {
  log.debug("Entering authn().");
  log.debug("Leaving authn().");
  return S.authnRequestXml({ issuer: issuer,
    acs: "https://" + issuer + ".example/acs",
    destination: K.rb(realm) + "/saml2/sso" }).xml;
}

// A Redirect-binding query signed with `key` (saml-bindings-2.0-os 3.4.4.1).
function query(xml, key, param, relayState) {
  log.debug("Entering query().");
  let q = (param || "SAMLRequest") + "=" + encodeURIComponent(
    zlib.deflateRawSync(Buffer.from(xml, "utf8")).toString("base64"));
  if (relayState !== undefined) {
    q += "&RelayState=" + encodeURIComponent(relayState);
  }
  q += "&SigAlg=" + encodeURIComponent(key.uri);
  q += "&Signature=" + encodeURIComponent(
    kit.signatureValue(key, Buffer.from(q, "utf8")).toString("base64"));
  log.debug("Leaving query().");
  return q;
}

async function postSso(realm, xml) {
  log.debug("Entering postSso().");
  const r = await K.send(K.rb(realm) + "/saml2/sso", { form: {
    SAMLRequest: Buffer.from(xml, "utf8").toString("base64") } });
  if ((r.status === 302 || r.status === 303) && /\?rid=/.test(r.location)) {
    log.debug("Leaving postSso(). Through the held request.");
    return K.send(/^https?:/.test(r.location) ? r.location
                                              : K.base + r.location);
  }
  log.debug("Leaving postSso().");
  return r;
}

async function fieldsOf(realm, identifier) {
  log.debug("Entering fieldsOf().");
  const r = await K.send(K.rb(realm) + "/admin-api/applications?" +
                         "application=" + encodeURIComponent(identifier));
  log.debug("Leaving fieldsOf().");
  return ((r.json || {}).attributes) || ((r.json || {}).fields) || {};
}

function metadataFor(entityId, certB64) {
  log.debug("Entering metadataFor().");
  log.debug("Leaving metadataFor().");
  return '<md:EntityDescriptor xmlns:md="' + NS_MD + '" ID="_md' +
    K.rand(6) + '" entityID="' + entityId + '"><md:SPSSODescriptor ' +
    'protocolSupportEnumeration="' + S.NS_SAMLP + '"><md:KeyDescriptor ' +
    'use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/' +
    'xmldsig#"><ds:X509Data><ds:X509Certificate>' + certB64 +
    "</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>" +
    '<md:AssertionConsumerService Binding="' + S.BINDING_POST +
    '" Location="https://' + entityId + '.example/acs" index="0"/>' +
    "</md:SPSSODescriptor></md:EntityDescriptor>";
}

async function coded(realm, code, act) {
  log.debug("Entering coded(). " + code);
  const before = (await K.codeCount(realm, code)) +
                 (await K.codeCount(null, code));
  const answer = await act();
  let rose = 0;
  for (let i = 0; i < 20 && rose === 0; i += 1) {
    rose = (await K.codeCount(realm, code)) +
           (await K.codeCount(null, code)) - before;
    if (rose === 0) {
      await K.sleep(150);
    }
  }
  log.debug("Leaving coded(). " + rose);
  return { answer: answer, rose: rose };
}

function refused(label, c, status) {
  log.debug("Entering refused().");
  K.check(label, function () {
    assert.strictEqual(c.answer.status, status, K.shown(c.answer));
    assert.ok(c.rose >= 1, "no new row for the code");
  });
  log.debug("Leaving refused().");
}

// --------------------------------------------------------------------- 1
async function families() {
  log.debug("Entering families().");
  log.info("=== 1. every family, on every surface ===");
  const keys = {};
  for (let i = 0; i < kit.FAMILIES.length; i += 1) {
    const row = kit.FAMILIES[i];
    const key = kit.keyFor(row);
    keys[row[0]] = key;
    const spF = await sp(P, "fam-" + slug(row[0]));
    await K.ok(K.rb(P) + "/admin-api/saml2/set-signing-certificate",
               { sp: spF, value: key.cert.pem }, row[0] + ": registered");
    const post = await postSso(P, kit.signEnveloped(ENGINE, authn(P, spF),
                                                    key));
    let f = await fieldsOf(P, spF);
    K.check(row[0] + ": a POST-binding AuthnRequest is VERIFIED", function () {
      assert.ok(K.toSignIn(post), K.shown(post));
      assert.ok(/^verified post /.test(f.samlAuthnRequestVerification || ""),
                JSON.stringify(f.samlAuthnRequestVerification));
    });
    let c = await coded(P, "STS-SAML-0061", function () {
      return postSso(P, kit.signEnveloped(ENGINE, authn(P, spF), key)
        .replace('Version="2.0"', 'Version="2.0" IsPassive="false"'));
    });
    refused(row[0] + ": a tampered POST request is REFUSED, 403, " +
            "STS-SAML-0061", c, 403);
    const q = query(authn(P, spF), key, "SAMLRequest", "rs-" + i);
    const redirect = await K.send(K.rb(P) + "/saml2/sso?" + q);
    if (q.length > 16000) {
      // PINNED, WHERE THE WIRE DIFFERS: an SLH-DSA signature (17 088 bytes)
      // does not fit a request line node's HTTP parser takes (16 KiB of
      // headers), so the Redirect binding cannot carry it at all — the
      // listener answers 431 before the service reads anything. The
      // in-process file calls the handler and never meets the limit.
      K.check(row[0] + ": a Redirect-binding request this long (" +
              q.length + " octets) is refused by the listener, 431",
              function () {
                assert.strictEqual(redirect.status, 431, K.shown(redirect));
              });
      K.check(row[0] + ": and so its tampered twin never reaches a verifier",
              function () {
                assert.ok(!K.toSignIn(redirect));
              });
    } else {
      f = await fieldsOf(P, spF);
      K.check(row[0] + ": a Redirect-binding AuthnRequest is VERIFIED",
              function () {
                assert.ok(K.toSignIn(redirect), K.shown(redirect));
                assert.strictEqual(String(f.samlAuthnRequestVerification ||
                  "").indexOf("verified redirect " + row[1]), 0,
                JSON.stringify(f.samlAuthnRequestVerification));
              });
      c = await coded(P, "STS-SAML-0061", function () {
        return K.send(K.rb(P) + "/saml2/sso?" + q.replace(
          "RelayState=rs-" + i, "RelayState=rX-" + i));
      });
      refused(row[0] + ": a tampered Redirect request is REFUSED, 403", c,
              403);
    }
    const anchored = await sp(P, "md-" + slug(row[0]));
    await K.ok(K.rb(P) + "/admin-api/saml2/set-metadata-signing-certificate",
               { sp: anchored, value: key.cert.b64 },
               row[0] + ": the metadata signing certificate");
    const doc = kit.signEnveloped(ENGINE, metadataFor(anchored, key.cert.b64),
                                  key);
    const bad = await K.send(K.rb(P) + "/admin-api/saml2/upload-metadata",
      { json: { sp: anchored, document: doc.replace("index=\"0\"",
                                                    "index=\"1\"") } });
    K.check(row[0] + ": a tampered signed metadata document is REFUSED",
            function () {
              assert.ok(bad.status >= 400, K.shown(bad));
            });
    const good = await K.send(K.rb(P) + "/admin-api/saml2/upload-metadata",
                              { json: { sp: anchored, document: doc } });
    f = await fieldsOf(P, anchored);
    K.check(row[0] + ": a metadata document signed with it is VERIFIED, " +
            "and its KeyDescriptor certificate CONSUMED", function () {
      assert.strictEqual(good.status, 200, K.shown(good));
      assert.strictEqual([].concat(f.samlSpMetadataSignature).join(),
                         "verified",
                         JSON.stringify(f.samlSpMetadataSignature));
      assert.ok([].concat(f.samlSigningCertificate || [])
        .indexOf(key.cert.b64) >= 0);
    });
  }
  log.debug("Leaving families(). " + Object.keys(keys).length);
  return keys;
}

// --------------------------------------------------------------------- 2
async function singleLogout(keys) {
  log.debug("Entering singleLogout().");
  log.info("=== 2. Single Logout, for a subset ===");
  const lr = function (issuer) {
    log.debug("Entering lr().");
    log.debug("Leaving lr().");
    return '<samlp:LogoutRequest xmlns:samlp="' + S.NS_SAMLP + '" ' +
      'xmlns:saml="' + S.NS_SAML + '" ID="_l' + K.rand(8) + '" ' +
      'Version="2.0" IssueInstant="' + new Date().toISOString() +
      '" Destination="' + K.rb(P) + '/saml2/slo"><saml:Issuer>' + issuer +
      "</saml:Issuer><saml:NameID>ssf-nobody</saml:NameID>" +
      "</samlp:LogoutRequest>";
  };
  const resp = function (issuer) {
    log.debug("Entering resp().");
    log.debug("Leaving resp().");
    return '<samlp:LogoutResponse xmlns:samlp="' + S.NS_SAMLP + '" ' +
      'xmlns:saml="' + S.NS_SAML + '" ID="_m' + K.rand(8) + '" ' +
      'Version="2.0" IssueInstant="' + new Date().toISOString() + '">' +
      "<saml:Issuer>" + issuer + "</saml:Issuer><samlp:Status>" +
      '<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:' +
      'Success"/></samlp:Status></samlp:LogoutResponse>';
  };
  for (const name of ["ecdsa-p384-sha384", "ed25519", "ml-dsa-44"]) {
    const key = keys[name];
    const spL = await sp(P, "slo-" + slug(name), { samlSingleLogoutService:
      ["https://ssf-slo-" + slug(name) + "-" + K.STAMP + ".example/slo"] });
    await K.ok(K.rb(P) + "/admin-api/saml2/set-signing-certificate",
               { sp: spL, value: key.cert.b64 }, name + ": registered");
    const at = K.rb(P) + "/saml2/slo?";
    const q = query(lr(spL), key, "SAMLRequest", "lo");
    const ok = await K.send(at + q);
    K.check(name + ": a signed LogoutRequest is ACCEPTED", function () {
      assert.ok(ok.status !== 403 && ok.status < 500, K.shown(ok));
    });
    const bad = await K.send(at + q.replace("RelayState=lo",
                                            "RelayState=LO"));
    K.check(name + ": a tampered LogoutRequest is REFUSED and ends nothing",
            function () {
              assert.strictEqual(bad.status, 403, K.shown(bad));
              assert.ok(/NOT ended/.test(bad.text), K.shown(bad));
            });
    const answered = await K.send(at + query(resp(spL), key,
                                             "SAMLResponse"));
    K.check(name + ": a signed LogoutResponse is VERIFIED", function () {
      assert.strictEqual(answered.status, 200, K.shown(answered));
      assert.ok(/verified/.test(answered.text), K.shown(answered));
    });
    const wrong = await K.send(at + query(resp(spL), keys["rsa-sha256"],
                                          "SAMLResponse"));
    K.check(name + ": a LogoutResponse signed by another key is REFUSED",
            function () {
              assert.strictEqual(wrong.status, 403, K.shown(wrong));
            });
  }
  log.debug("Leaving singleLogout().");
}

// --------------------------------------------------------------------- 3
async function weak(keys) {
  log.debug("Entering weak().");
  log.info("=== 3. SHA-1, and an algorithm nothing can check ===");
  const rsa = keys["rsa-sha256"];
  const sha1 = Object.assign({}, rsa, { name: "rsa-sha1",
    uri: U.DS + "rsa-sha1", how: { hash: "sha1" } });
  const spS = await sp(P, "sha1", { samlSigningCertificate:
    [rsa.cert.pem] });
  let c = await coded(P, "STS-SAML-0073", function () {
    return postSso(P, kit.signEnveloped(ENGINE, authn(P, spS), rsa,
                                        { digestUri: U.DS + "sha1" }));
  });
  refused("3a. SHA-1 as the DigestMethod under RSA-SHA256 is REFUSED, 403, " +
          "STS-SAML-0073", c, 403);
  for (const [label, realm, allowed] of [["product", P, false],
                                         ["development, allowed", D, true]]) {
    const anchored = await sp(realm, "md-sha1-" + slug(label));
    await K.ok(K.rb(realm) +
               "/admin-api/saml2/set-metadata-signing-certificate",
    { sp: anchored, value: rsa.cert.b64 }, "the metadata anchor");
    const doc = kit.signEnveloped(ENGINE, metadataFor(anchored, rsa.cert.b64),
                                  sha1, { digestUri: U.DS + "sha1" });
    c = await coded(realm, "STS-SAML-0065", function () {
      return K.send(K.rb(realm) + "/admin-api/saml2/upload-metadata",
                    { json: { sp: anchored, document: doc } });
    });
    if (!allowed) {
      K.check("3b. metadata signed with SHA-1 is REFUSED, STS-SAML-0065",
              function () {
                assert.ok(c.answer.status >= 400, K.shown(c.answer));
                assert.ok(c.rose >= 1);
              });
      continue;
    }
    const f = await fieldsOf(realm, anchored);
    K.check("3c. with saml.allowSha1Signatures on (development), the same " +
            "document verifies", function () {
      assert.strictEqual(c.answer.status, 200, K.shown(c.answer));
      assert.strictEqual([].concat(f.samlSpMetadataSignature).join(),
                         "verified",
                         JSON.stringify(f.samlSpMetadataSignature));
    });
  }
  const md5 = Object.assign({}, rsa, { uri: U.MORE + "rsa-md5" });
  const spM = await sp(P, "md5", { samlSigningCertificate: [rsa.cert.pem] });
  c = await coded(P, "STS-SAML-0062", function () {
    return K.send(K.rb(P) + "/saml2/sso?" + query(authn(P, spM), md5));
  });
  refused("3d. RSA-MD5 cannot be checked and is REFUSED, 403, STS-SAML-0062",
          c, 403);
  log.debug("Leaving weak().");
}

async function test() {
  log.debug("Entering test().");
  P = await K.realm("ssf-p", "product");
  D = await K.realm("ssf-d", "development");
  await K.set(D, "saml.allowSha1Signatures", true);
  const keys = await families();
  await singleLogout(keys);
  await weak(keys);
  log.debug("Leaving test().");
}

K.main(test, 6 * kit.FAMILIES.length + 16);
