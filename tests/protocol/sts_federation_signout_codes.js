// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_federation_signout_codes.js
//
// ===========================================================================
// A FEDERATION PARTNER'S SIGN-OUT, EVERY REFUSAL BY ITS CODE, IN BOTH MODES,
// OVER THE WIRE (#167, #168; #444 D12, phase 7).
//
// `tests/federation_signout.js` holds a partner's sign-out in a child
// process per mode and reads each refusal's code off the audit ring.
// `sts_federation_signout.js` (vendored) drives the same requests against a
// running service in whichever mode the stack is in, and reads no code.
// This job carries the in-process file's codes over the wire, in a
// development AND a product realm of one running service, against partners
// written HERE (this job's own keys; the relationships hold the keys, so
// nothing is dialled and product's https-only back channel is not needed):
//
//   0. a new relationship accepts its partner's sign-out, requires it
//      signed and logs out on the Redirect binding; a binding that is not
//      Redirect or POST is refused (STS-FED-0133); fedRequireSignedLogout
//      off is refused in product (0132) and allowed in development;
//   B. OpenID Connect Back-Channel Logout: every section 2.6 refusal —
//      none (0127), a five-part token that does not decrypt (0138), another
//      key under the partner's kid or another audience (0128), a nonce, no
//      events, neither sub nor sid, typ at+jwt (0129), issued an hour ago
//      (0119) — each 400 and ending nothing; fedAcceptSignout off (0123); a
//      genuine token matching nothing 200 (0122) and the same again a
//      replay, 400 invalid_request no-store (0120); the match ending the
//      session, its own audit row;
//   F. Front-Channel Logout: no sid or another iss (0130), 400, ending
//      nothing; iss and sid ending the session, framable by the partner's
//      origin alone and running no script;
//   R. RP-Initiated Logout offered from /logout, its return matched once
//      (0134);
//   S. SAML 2.0: the LogoutRequest refusals — unsigned (0115), another key
//      (0116), another issuer (0117), another Destination (0118), stale
//      (0119) — each 403 and ending nothing, the refusal the shared error
//      page in French for a browser asking; an unknown SessionIndex
//      answered with a signed Requester/UnknownPrincipal LogoutResponse
//      (0122); the match ending the session with a signed Success; the
//      same request again (0120); the service-provider-initiated round
//      trip, its LogoutResponse matched once (0124); a non-Success answer
//      the outcome page (0125); a WS-Federation cleanup with nothing to end
//      (0122); a SessionNotOnOrAfter already passed (0131) and one that
//      passes during the session ending it.
//
// NOT HERE: section 0a's verifier (`verifyQueryString()` without a
// certificate, STS-KEYS-0060, is a function's verdict: every relationship
// that can verify holds a certificate) and the realm-to-realm genuine
// Back-Channel Logout Token (1d), which needs this service's own OpenID
// Provider to dial its own back channel at an address the probe does not
// publish to itself (`sts_federation_realms.js` argues the front-channel
// shape for that reason); the genuine token here is the partner's,
// written here.
//
// OWNED HERE (local: true). Its realms are removed only on a private probe.
// ===========================================================================

const assert = require("assert");
const nodeCrypto = require("crypto");
const zlib = require("zlib");
const authnSignin = require("./authn_signin");
const xmldsig = require("./saml_xmldsig.js");
const K = require("./oauth_wire_kit.js").kit("sts_federation_signout_codes");
const S = require("./saml_wire_kit.js").samlKit(K);

const log = K.log;
const RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const BCL_EVENT = "http://schemas.openid.net/event/backchannel-logout";
const PARTNER_OIDC = "https://oidc-partner-" + K.STAMP + ".invalid";
const PARTNER_SAML = "urn:test:fso-partner:" + K.STAMP;
const PARTNER_SLO = "https://saml-partner-" + K.STAMP + ".invalid/slo";
const PARTNER_WSFED = "urn:test:fso-wsfed:" + K.STAMP;
const NAMEID = "fso-saml-subject-" + K.STAMP;
const OIDC_SUB = "fso-oidc-subject-" + K.STAMP;
const T_CLIENT = "fso-client-" + K.STAMP;

function b64uJson(value) {
  log.debug("Entering b64uJson().");
  log.debug("Leaving b64uJson().");
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

function signJwt(header, payload, privateKey) {
  log.debug("Entering signJwt().");
  const input = b64uJson(header) + "." + b64uJson(payload);
  log.debug("Leaving signJwt().");
  return input + "." + nodeCrypto.sign("sha256", Buffer.from(input),
                                       privateKey).toString("base64url");
}

// A text as a regular expression that matches it and nothing else: every
// character the syntax gives a meaning to is escaped, the backslash
// included. Escaping only the dots left `?`, `+` and a backslash in a
// partner URL live, which matched other addresses or did not compile.
function literal(text) {
  log.debug("Entering literal().");
  log.debug("Leaving literal().");
  return String(text).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function htmlDecode(text) {
  log.debug("Entering htmlDecode().");
  log.debug("Leaving htmlDecode().");
  return String(text || "").replace(/&quot;/g, "\"").replace(/&#39;/g, "'")
    .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
}

function rawParam(url, name) {
  log.debug("Entering rawParam(). " + name);
  const raw = new URL(url).search.slice(1);
  const m = new RegExp("(?:^|&)" + name + "=([^&]*)").exec(raw);
  log.debug("Leaving rawParam().");
  return m ? m[1] : "";
}

// A SAML message on the Redirect binding, its signature checked with the
// service provider's own signing certificate over the octets as sent
// (SAML 2.0 Bindings section 3.4.4.1).
function messageIn(url, field, certPem) {
  log.debug("Entering messageIn(). " + field);
  const pick = function (name) {
    log.debug("Entering pick(). " + name);
    log.debug("Leaving pick().");
    return rawParam(url, name);
  };
  const octets = field + "=" + pick(field) +
    (pick("RelayState") ? "&RelayState=" + pick("RelayState") : "") +
    "&SigAlg=" + pick("SigAlg");
  const sigAlg = decodeURIComponent(pick("SigAlg"));
  let verified = false;
  try {
    const ec = /ecdsa/.test(sigAlg);
    verified = nodeCrypto.verify(/sha512/.test(sigAlg) ? "sha512"
      : /sha384/.test(sigAlg) ? "sha384" : "sha256", Buffer.from(octets),
    ec ? { key: certPem, dsaEncoding: "ieee-p1363" } : certPem,
    Buffer.from(decodeURIComponent(pick("Signature")), "base64"));
  } catch (e) {
    log.debug("Caught in messageIn(): " + ((e && e.message) || e));
    // Not verifiable with the certificate: reported as unverified.
    verified = false;
  }
  const xml = zlib.inflateRawSync(Buffer.from(decodeURIComponent(
    pick(field)), "base64")).toString("utf8");
  log.debug("Leaving messageIn().");
  return { verified: verified, xml: xml, sigAlg: sigAlg,
           codes: [...xml.matchAll(/StatusCode Value="([^"]+)"/g)]
             .map(function (m) {
               return m[1].split(":").pop();
             }),
           relay: decodeURIComponent(pick("RelayState")),
           to: new URL(url).origin + new URL(url).pathname };
}

function cookieOf(b) {
  log.debug("Entering cookieOf().");
  log.debug("Leaving cookieOf().");
  return Object.keys(b.jar).map(function (k) {
    return k + "=" + b.jar[k];
  }).join("; ");
}

function keepCookies(b, lines) {
  log.debug("Entering keepCookies().");
  (lines || []).forEach(function (line) {
    const pair = String(line).split(";")[0];
    const at = pair.indexOf("=");
    if (at > 0) {
      const value = pair.slice(at + 1);
      if (value === "" || /Expires=Thu, 01 Jan 1970/i.test(String(line))) {
        delete b.jar[pair.slice(0, at)];
      } else {
        b.jar[pair.slice(0, at)] = value;
      }
    }
  });
  log.debug("Leaving keepCookies().");
}

// ONE MODE'S WORLD: a service-provider realm and its four relationships to
// partners written here, and a person linked through each.
async function world(mode) {
  log.debug("Entering world(). " + mode);
  const w = { mode: mode, product: mode === "product" };
  w.SP = await K.realm("fso-" + mode.slice(0, 1), mode);
  await K.set(w.SP, "security.rateLimitPerAddress", 10000);
  await K.set(w.SP, "security.rateLimitPerIdentity", 1000);
  w.person = "fso-" + mode.slice(0, 1) + "-" + K.rand(3);
  await K.ok(K.rb(w.SP) + "/admin-api/users/create", { username: w.person,
    invent: false, credential: "none", attributes: {
      cn: "Signout " + w.person, givenName: "Signout", sn: w.person,
      mail: w.person + "@" + w.SP + ".example.net" } }, "created the person");
  w.partnerKey = await S.credential("fso partner " + K.STAMP);
  w.otherKey = await S.credential("fso somebody " + K.STAMP);
  w.partnerKey.der = S.b64cert(w.partnerKey.certificatePem);
  w.partnerKey.privateKey = nodeCrypto.createPrivateKey(
    w.partnerKey.privateKeyPem);
  w.otherKey.privateKey = nodeCrypto.createPrivateKey(
    w.otherKey.privateKeyPem);
  const partnerJwk = Object.assign(nodeCrypto.createPublicKey(
    w.partnerKey.privateKeyPem).export({ format: "jwk" }),
  { kid: "fso-partner", alg: "RS256", use: "sig" });
  w.oidc = await relationship(w, "oidc-t", "oidc", PARTNER_OIDC, {
    fedSsoUrl: PARTNER_OIDC + "/authorize", fedClientId: T_CLIENT,
    fedResponseType: "id_token", fedScope: "openid",
    fedJwks: JSON.stringify({ keys: [partnerJwk] }),
    fedSubjectPolicy: "pre-linked" });
  await link(w, "oidc-t", OIDC_SUB);
  w.saml = await relationship(w, "saml-t", "saml2", PARTNER_SAML, {
    fedSsoUrl: "https://saml-partner-" + K.STAMP + ".invalid/sso",
    fedSigningCertificate: w.partnerKey.der, fedAllowUnsolicited: "TRUE",
    fedSloUrl: PARTNER_SLO, fedSubjectPolicy: "pre-linked" });
  await link(w, "saml-t", NAMEID);
  w.wsfed = await relationship(w, "wsfed-t", "wsfed", PARTNER_WSFED, {
    fedSsoUrl: "https://wsfed-partner-" + K.STAMP + ".invalid/",
    fedSigningCertificate: w.partnerKey.der, fedAllowUnsolicited: "TRUE",
    fedSubjectPolicy: "pre-linked" });
  const md = await K.send(K.rb(w.SP) + "/federation/metadata/saml-t");
  const cert = ((/<md:KeyDescriptor[^>]*use="signing"[\s\S]*?<ds:X509Certificate>([^<]+)</
    .exec(md.text) || /X509Certificate>([^<]+)</.exec(md.text) || [])[1] ||
    "").replace(/\s+/g, "");
  w.spCertPem = "-----BEGIN CERTIFICATE-----\n" +
    (cert.match(/.{1,64}/g) || []).join("\n") + "\n-----END CERTIFICATE-----\n";
  w.metadata = md;
  log.debug("Leaving world().");
  return w;
}

async function relationship(w, id, protocol, peer, settings) {
  log.debug("Entering relationship(). " + id);
  await K.ok(K.rb(w.SP) + "/admin-api/federation/create", { id: id,
    role: "service-provider", protocol: protocol, peer: peer },
  "created " + id);
  const all = Object.assign({ fedAllowUnencrypted: "TRUE" }, settings);
  for (const field of Object.keys(all)) {
    await K.ok(K.rb(w.SP) + "/admin-api/federation/set", { id: id,
      field: field, value: all[field] }, "set " + field + " on " + id);
  }
  await K.ok(K.rb(w.SP) + "/admin-api/federation/enable", { id: id },
             "enabled " + id);
  const view = await K.send(K.rb(w.SP) +
                            "/admin-api/federation?relationship=" + id);
  log.debug("Leaving relationship().");
  return view.json.endpoints;
}

async function link(w, rel, subject) {
  log.debug("Entering link(). " + rel);
  await K.ok(K.rb(w.SP) + "/admin-api/users/federation-link", {
    user: w.person, relationship: rel, subject: subject }, "linked " + rel);
  log.debug("Leaving link().");
}

function setRel(w, id, field, value) {
  log.debug("Entering setRel(). " + field);
  log.debug("Leaving setRel().");
  return K.send(K.rb(w.SP) + "/admin-api/federation/set",
                { json: { id: id, field: field, value: value } });
}

// /logout answers a program with JSON: 200 naming the person, 401 when the
// request carries no live session.
async function liveIn(w, b) {
  log.debug("Entering liveIn().");
  const r = await b.go(K.rb(w.SP) + "/logout",
                       { headers: { accept: "application/json" } });
  log.debug("Leaving liveIn(). " + r.status);
  return r.status === 200;
}

async function follow(b, r) {
  log.debug("Entering follow().");
  let out = r;
  for (let i = 0; i < 3 && out.status >= 300 && out.status < 400 &&
       out.location; i += 1) {
    out = await b.go(new URL(out.location, K.base).toString());
  }
  log.debug("Leaving follow(). " + out.status);
  return out;
}

async function oidcSignIn(w, sid) {
  log.debug("Entering oidcSignIn(). " + sid);
  const b = K.browser();
  const begun = await b.go(K.rb(w.SP) + "/federation/login/oidc-t");
  const asked = new URL(begun.location);
  const now = Math.floor(Date.now() / 1000);
  const idToken = signJwt({ alg: "RS256", typ: "JWT", kid: "fso-partner" },
    { iss: PARTNER_OIDC, aud: T_CLIENT, sub: OIDC_SUB, sid: sid, iat: now,
      exp: now + 300, nonce: asked.searchParams.get("nonce") },
    w.partnerKey.privateKey);
  const r = await follow(b, await b.go(w.oidc.assertionConsumerService,
    { form: { id_token: idToken, state: asked.searchParams.get("state") } }));
  log.debug("Leaving oidcSignIn(). " + r.status);
  return { b: b, r: r };
}

function logoutToken(w, extra, key, header) {
  log.debug("Entering logoutToken().");
  const now = Math.floor(Date.now() / 1000);
  const claims = Object.assign({ iss: PARTNER_OIDC, aud: T_CLIENT, iat: now,
    exp: now + 120, jti: "fso-" + K.rand(8), sid: "fso-nobody",
    events: { [BCL_EVENT]: {} } }, extra || {});
  Object.keys(claims).forEach(function (k) {
    if (claims[k] === undefined) {
      delete claims[k];
    }
  });
  log.debug("Leaving logoutToken().");
  return signJwt(header || { alg: "RS256", typ: "logout+jwt",
                             kid: "fso-partner" },
                 claims, key || w.partnerKey.privateKey);
}

async function samlSignIn(w, sessionIndex, notOnOrAfter) {
  log.debug("Entering samlSignIn().");
  const acs = w.saml.assertionConsumerService;
  const built = xmldsig.buildAssertion({ issuer: PARTNER_SAML,
    subject: NAMEID, audience: acs, recipient: acs,
    nameIdFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
    authnStatement: true, sessionIndex: sessionIndex,
    sessionNotOnOrAfter: notOnOrAfter });
  const signed = xmldsig.sign(built, w.partnerKey.privateKeyPem, "");
  const response = "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:" +
    "2.0:protocol\" ID=\"_r" + K.rand(8) + "\" Version=\"2.0\" " +
    "IssueInstant=\"" + xmldsig.iso(0) + "\" Destination=\"" + acs +
    "\"><samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:" +
    "2.0:status:Success\"></samlp:StatusCode></samlp:Status>" + signed +
    "</samlp:Response>";
  const b = K.browser();
  const r = await follow(b, await b.go(acs, { form: {
    SAMLResponse: Buffer.from(response).toString("base64") } }));
  log.debug("Leaving samlSignIn(). " + r.status);
  return { b: b, r: r };
}

function logoutRequest(w, o) {
  log.debug("Entering logoutRequest().");
  const id = "_lr" + K.rand(8);
  const xml = "<samlp:LogoutRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:" +
    "2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" " +
    "ID=\"" + id + "\" Version=\"2.0\" IssueInstant=\"" +
    (o.issueInstant || xmldsig.iso(0)) + "\" Destination=\"" +
    (o.destination || w.saml.singleLogout) + "\"><saml:Issuer>" +
    (o.issuer || PARTNER_SAML) + "</saml:Issuer><saml:NameID Format=\"urn:" +
    "oasis:names:tc:SAML:2.0:nameid-format:persistent\">" + NAMEID +
    "</saml:NameID>" + (o.sessionIndex ? "<samlp:SessionIndex>" +
    o.sessionIndex + "</samlp:SessionIndex>" : "") +
    "</samlp:LogoutRequest>";
  let qs = "SAMLRequest=" + encodeURIComponent(
    zlib.deflateRawSync(Buffer.from(xml)).toString("base64")) +
    "&RelayState=fso-relay";
  if (o.key) {
    qs += "&SigAlg=" + encodeURIComponent(RSA_SHA256);
    qs += "&Signature=" + encodeURIComponent(nodeCrypto.sign("sha256",
      Buffer.from(qs), o.key.privateKeyPem).toString("base64"));
  }
  log.debug("Leaving logoutRequest().");
  return { id: id, url: w.saml.singleLogout + "?" + qs };
}

function logoutResponseQs(w, requestId, relay, status, message) {
  log.debug("Entering logoutResponseQs().");
  const xml = "<samlp:LogoutResponse xmlns:samlp=\"urn:oasis:names:tc:SAML:" +
    "2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" " +
    "ID=\"_lresp" + K.rand(6) + "\" Version=\"2.0\" IssueInstant=\"" +
    xmldsig.iso(0) + "\" Destination=\"" + w.saml.singleLogout +
    "\" InResponseTo=\"" + requestId + "\"><saml:Issuer>" + PARTNER_SAML +
    "</saml:Issuer><samlp:Status><samlp:StatusCode Value=\"urn:oasis:" +
    "names:tc:SAML:2.0:status:" + status + "\"/>" +
    (message ? "<samlp:StatusMessage>" + message + "</samlp:StatusMessage>"
             : "") + "</samlp:Status></samlp:LogoutResponse>";
  let qs = "SAMLResponse=" + encodeURIComponent(zlib.deflateRawSync(
    Buffer.from(xml)).toString("base64")) + "&RelayState=" +
    encodeURIComponent(relay) + "&SigAlg=" + encodeURIComponent(RSA_SHA256);
  qs += "&Signature=" + encodeURIComponent(nodeCrypto.sign("sha256",
    Buffer.from(qs), w.partnerKey.privateKeyPem).toString("base64"));
  log.debug("Leaving logoutResponseQs().");
  return qs;
}

async function signOutHere(w, b, headers) {
  log.debug("Entering signOutHere().");
  const out = await authnSignin.signOut(K.rb(w.SP), { scope: "global" },
    { cookie: cookieOf(b), headers: headers || {} });
  keepCookies(b, out.setCookies || []);
  log.debug("Leaving signOutHere(). " + out.status);
  return out;
}

function tag(w, what) {
  log.debug("Entering tag().");
  log.debug("Leaving tag().");
  return "[" + w.mode + "] " + what;
}

// ------------------------------------------------------------------- 0
async function defaults(w) {
  log.debug("Entering defaults().");
  log.info("=== 0. [" + w.mode + "] a new relationship's sign-out fields ===");
  const view = await K.send(K.rb(w.SP) +
                            "/admin-api/federation?relationship=oidc-t");
  const sview = await K.send(K.rb(w.SP) +
                             "/admin-api/federation?relationship=saml-t");
  const text = JSON.stringify(view.json) + JSON.stringify(sview.json);
  K.check(tag(w, "0a. a new relationship accepts its partner's sign-out, " +
          "requires it signed, and sends SAML logout on the Redirect " +
          "binding"), function () {
    assert.ok(/"fedAcceptSignout":\s*"TRUE"/.test(text), text.slice(0, 300));
    assert.ok(/"fedRequireSignedLogout":\s*"TRUE"/.test(text));
    assert.ok(/"fedSloBinding":\s*"HTTP-Redirect"/.test(text));
  });
  const bad = await K.coded(w.SP, "STS-FED-0133", function () {
    return setRel(w, "saml-t", "fedSloBinding", "SOAP");
  });
  K.check(tag(w, "0b. fedSloBinding refuses a binding that is not Redirect " +
          "or POST (STS-FED-0133)"), function () {
    assert.strictEqual(bad.answer.status, 400, bad.answer.text.slice(0, 200));
    assert.ok(bad.rose >= 1);
  });
  const off = await K.coded(w.SP, "STS-FED-0132", function () {
    return setRel(w, "saml-t", "fedRequireSignedLogout", "FALSE");
  });
  K.check(tag(w, "0c. fedRequireSignedLogout off is " + (w.product
    ? "REFUSED in product (STS-FED-0132)" : "allowed in development")),
  function () {
    if (w.product) {
      assert.strictEqual(off.answer.status, 400, off.answer.text);
      assert.ok(off.rose >= 1);
    } else {
      assert.strictEqual(off.answer.status, 200, off.answer.text);
      assert.strictEqual(off.rose, 0);
    }
  });
  await setRel(w, "saml-t", "fedRequireSignedLogout", "TRUE");
  log.debug("Leaving defaults().");
}

// ------------------------------------------------------------------- B
async function backChannel(w) {
  log.debug("Entering backChannel().");
  log.info("=== B. [" + w.mode + "] Back-Channel Logout ===");
  const bc = w.oidc.backchannelLogout;
  const sid = "fso-sid-" + K.rand(4);
  const signed = await oidcSignIn(w, sid);
  K.check(tag(w, "B0. (a federated sign-in through the OpenID Connect " +
          "partner written here, with a sid)"), function () {
    assert.ok(signed.r.status < 400, K.shown(signed.r));
  });
  assert.ok(await liveIn(w, signed.b), "the federated session is not live");
  const rogue = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const cases = [
    ["B1. no logout_token", {}, "STS-FED-0127"],
    ["B2. an encrypted (five-part) token that does not decrypt",
     { logout_token: "a.b.c.d.e" }, "STS-FED-0138"],
    ["B3. a token signed by another key under the partner's kid",
     { logout_token: logoutToken(w, {}, rogue.privateKey) }, "STS-FED-0128"],
    ["B4. a token with a nonce",
     { logout_token: logoutToken(w, { nonce: "n" }) }, "STS-FED-0129"],
    ["B5. a token with no events member",
     { logout_token: logoutToken(w, { events: {} }) }, "STS-FED-0129"],
    ["B6. a token naming neither sub nor sid",
     { logout_token: logoutToken(w, { sid: undefined }) }, "STS-FED-0129"],
    ["B7. a token typed at+jwt",
     { logout_token: logoutToken(w, {}, null, { alg: "RS256",
       typ: "at+jwt", kid: "fso-partner" }) }, "STS-FED-0129"],
    ["B8. a token for another audience",
     { logout_token: logoutToken(w, { aud: "somebody" }) }, "STS-FED-0128"],
    ["B9. a token issued an hour ago",
     { logout_token: logoutToken(w, {
       iat: Math.floor(Date.now() / 1000) - 3600,
       exp: Math.floor(Date.now() / 1000) + 60 }) }, "STS-FED-0119"]
  ];
  for (const one of cases) {
    const got = await K.coded(w.SP, one[2], function () {
      return K.send(bc, { form: one[1] });
    });
    const live = await liveIn(w, signed.b);
    K.check(tag(w, one[0] + ": 400 (" + one[2] + "), ending nothing"),
            function () {
              assert.strictEqual(got.answer.status, 400,
                                 got.answer.text.slice(0, 200));
              assert.ok(got.rose >= 1, "no " + one[2] + " row");
              assert.ok(live, "the session ended");
            });
  }
  await setRel(w, "oidc-t", "fedAcceptSignout", "FALSE");
  let got = await K.coded(w.SP, "STS-FED-0123", function () {
    return K.send(bc, { form: { logout_token: logoutToken(w, { sid: sid }) } });
  });
  let live = await liveIn(w, signed.b);
  K.check(tag(w, "B10. fedAcceptSignout off refuses a genuine token " +
          "(STS-FED-0123) and ends nothing"), function () {
    assert.strictEqual(got.answer.status, 400, got.answer.text);
    assert.ok(got.rose >= 1);
    assert.ok(live);
  });
  await setRel(w, "oidc-t", "fedAcceptSignout", "TRUE");
  const genuine = logoutToken(w, { sid: "no-such-sid" });
  const first = await K.coded(w.SP, "STS-FED-0122", function () {
    return K.send(bc, { form: { logout_token: genuine } });
  });
  const second = await K.coded(w.SP, "STS-FED-0120", function () {
    return K.send(bc, { form: { logout_token: genuine } });
  });
  K.check(tag(w, "B11. a genuine Logout Token matching nothing answers 200 " +
          "(STS-FED-0122); the same token again is a replay, 400 " +
          "invalid_request, no-store (STS-FED-0120)"), function () {
    assert.strictEqual(first.answer.status, 200, first.answer.text);
    assert.ok(first.rose >= 1);
    assert.strictEqual(second.answer.status, 400);
    assert.strictEqual((second.answer.json || {}).error, "invalid_request");
    assert.ok(second.rose >= 1);
    assert.ok(/no-store/.test(String(second.answer.headers
      .get("cache-control"))));
  });
  const matched = await K.send(bc, { form: { logout_token:
    logoutToken(w, { sid: sid }) } });
  live = await liveIn(w, signed.b);
  const rows = await K.send(K.rb(w.SP) + "/admin-api/audit?per=200&q=" +
                            encodeURIComponent("federation.signout"));
  K.check(tag(w, "B12. a genuine token naming the session's sid ends it, " +
          "200, and the partner's sign-out is its own audit row"),
  function () {
    assert.strictEqual(matched.status, 200, matched.text);
    assert.ok(!live, "the session is still live");
    assert.ok(/federation\.signout/.test(rows.text), rows.text.slice(0, 300));
  });
  log.debug("Leaving backChannel().");
}

// ------------------------------------------------------------------- F, R
async function frontChannel(w) {
  log.debug("Entering frontChannel().");
  log.info("=== F. [" + w.mode + "] Front-Channel and RP-Initiated ===");
  const fc = w.oidc.frontchannelLogout;
  const sid = "fso-fsid-" + K.rand(4);
  const signed = await oidcSignIn(w, sid);
  const got = await K.coded(w.SP, "STS-FED-0130", async function () {
    const a = await K.send(fc);
    const c = await K.send(fc + "?iss=" +
      encodeURIComponent("https://elsewhere.example") + "&sid=" +
      encodeURIComponent(sid));
    return [a, c];
  });
  const live = await liveIn(w, signed.b);
  K.check(tag(w, "F1. no sid, and an iss that is not the partner, are " +
          "refused 400 (STS-FED-0130) and end nothing"), function () {
    assert.strictEqual(got.answer[0].status, 400);
    assert.strictEqual(got.answer[1].status, 400);
    assert.ok(got.rose >= 1);
    assert.ok(live);
  });
  const front = await K.send(fc + "?iss=" + encodeURIComponent(PARTNER_OIDC) +
                             "&sid=" + encodeURIComponent(sid));
  const csp = String(front.headers.get("content-security-policy") || "");
  const after = await liveIn(w, signed.b);
  K.check(tag(w, "F2. iss and sid end the matched session; the page may be " +
          "framed by the partner's origin and nobody else, and runs no " +
          "script"), function () {
    assert.strictEqual(front.status, 200, K.shown(front));
    assert.ok(!after, "the session is still live");
    assert.ok(csp.indexOf("frame-ancestors " + PARTNER_OIDC) >= 0, csp);
    assert.ok(!/frame-ancestors 'none'/.test(csp) &&
              !/script-src 'self'/.test(csp), csp);
    assert.ok(!front.headers.get("x-frame-options"));
  });
  await setRel(w, "oidc-t", "fedEndSessionUrl", PARTNER_OIDC + "/logout");
  const again = await oidcSignIn(w, "fso-rsid-" + K.rand(4));
  const bye = await signOutHere(w, again.b);
  const link = htmlDecode((new RegExp("href=\"(" + literal(PARTNER_OIDC) +
    "/logout\\?[^\"]+)\"").exec(bye.text) ||
    [])[1] || JSON.stringify(bye.json || {}).match(new RegExp("\"(" +
    literal(PARTNER_OIDC) + "/logout\\?[^\"]+)\"")) &&
    JSON.stringify(bye.json || {}).match(new RegExp("\"(" +
    literal(PARTNER_OIDC) + "/logout\\?[^\"]+)\""))[1] || "");
  const asked = link ? new URL(link.replace(/\\u0026/g, "&")) : null;
  const ended = !(await liveIn(w, again.b));
  K.check(tag(w, "R1. /logout ends the session and offers RP-Initiated " +
          "Logout at the partner: id_token_hint, client_id, " +
          "post_logout_redirect_uri and state"), function () {
    assert.ok(asked, String(bye.text || JSON.stringify(bye.json))
      .slice(0, 600));
    assert.strictEqual(asked.searchParams.get("client_id"), T_CLIENT);
    assert.strictEqual(asked.searchParams.get("post_logout_redirect_uri"),
                       w.oidc.postLogoutRedirect);
    assert.ok(asked.searchParams.get("id_token_hint"));
    assert.ok(/^fed-/.test(asked.searchParams.get("state") || ""));
    assert.ok(ended);
  });
  const back = K.rb(w.SP) + "/federation/slo/oidc-t?state=" +
    encodeURIComponent(asked ? asked.searchParams.get("state") : "x");
  const first = await K.send(back);
  const twice = await K.coded(w.SP, "STS-FED-0134", function () {
    return K.send(back);
  });
  K.check(tag(w, "R2. the return from the partner is matched once; the same " +
          "state again is refused (STS-FED-0134)"), function () {
    assert.strictEqual(first.status, 200, K.shown(first));
    assert.ok(/Signed out/.test(first.text) || /signed/i.test(first.text));
    assert.strictEqual(twice.answer.status, 400);
    assert.ok(twice.rose >= 1);
  });
  log.debug("Leaving frontChannel().");
}

// ------------------------------------------------------------------- S
async function saml(w) {
  log.debug("Entering saml().");
  log.info("=== S. [" + w.mode + "] SAML 2.0 Single Logout ===");
  const slo = w.saml.singleLogout;
  K.check(tag(w, "S0. the relationship's metadata publishes " +
          "SingleLogoutService on the Redirect and POST bindings"),
  function () {
    assert.strictEqual(w.metadata.status, 200);
    assert.ok(w.metadata.text.indexOf("<md:SingleLogoutService Binding=\"" +
      "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"" +
      slo + "\"/>") >= 0, w.metadata.text.slice(0, 400));
    assert.ok(/SingleLogoutService Binding="[^"]*HTTP-POST"/.test(
      w.metadata.text));
  });
  const idx = "idx-one-" + K.rand(3);
  const signed = await samlSignIn(w, idx, "");
  assert.ok(await liveIn(w, signed.b), "no SAML session: " +
            K.shown(signed.r));
  const refusals = [
    ["S1. an UNSIGNED LogoutRequest", { sessionIndex: idx }, "STS-FED-0115"],
    ["S2. one signed by a key the relationship does not name",
     { sessionIndex: idx, key: w.otherKey }, "STS-FED-0116"],
    ["S3. one issued by somebody else", { sessionIndex: idx,
      key: w.partnerKey, issuer: "urn:somebody:else" }, "STS-FED-0117"],
    ["S4. one addressed to another endpoint", { sessionIndex: idx,
      key: w.partnerKey, destination: "https://elsewhere.example/slo" },
     "STS-FED-0118"],
    ["S5. one issued an hour ago", { sessionIndex: idx, key: w.partnerKey,
      issueInstant: new Date(Date.now() - 3600000).toISOString()
        .replace(/\.\d{3}Z$/, "Z") }, "STS-FED-0119"]
  ];
  for (const one of refusals) {
    const got = await K.coded(w.SP, one[2], function () {
      return K.send(logoutRequest(w, one[1]).url);
    });
    const live = await liveIn(w, signed.b);
    K.check(tag(w, one[0] + " is refused 403 (" + one[2] + "), and ends " +
            "nothing"), function () {
      assert.strictEqual(got.answer.status, 403, K.shown(got.answer));
      assert.ok(got.rose >= 1, "no " + one[2] + " row");
      assert.ok(live);
    });
  }
  const shown = await K.send(logoutRequest(w, { sessionIndex: idx }).url,
                             { headers: { "accept-language": "fr" } });
  K.check(tag(w, "S6. a refused sign-out is the shared error page, in " +
          "French for a browser that asks, with its incident ID and the " +
          "English detail as data"), function () {
    assert.strictEqual(shown.status, 403);
    assert.ok(/<html lang="fr"/.test(shown.text), shown.text.slice(0, 200));
    assert.ok(shown.text.indexOf(
      "La déconnexion du partenaire a été refusée") > 0);
    assert.ok(shown.text.indexOf("Aucune session n’a été fermée ici.") > 0);
    assert.ok(/section class="diagnostics"/.test(shown.text));
    assert.ok(/<dd><code>\d+<\/code><\/dd>/.test(shown.text));
    assert.ok(shown.text.indexOf("The LogoutRequest is not signed") > 0);
    assert.ok(!/STS-[A-Z]+-\d{4}/.test(shown.text));
  });
  const unknown = await K.coded(w.SP, "STS-FED-0122", function () {
    return K.send(logoutRequest(w, { sessionIndex: "idx-nobody",
                                     key: w.partnerKey }).url);
  });
  const ua = unknown.answer.location
    ? messageIn(unknown.answer.location, "SAMLResponse", w.spCertPem) : null;
  let live = await liveIn(w, signed.b);
  K.check(tag(w, "S7. an unknown SessionIndex is answered with a SIGNED " +
          "LogoutResponse, Requester/UnknownPrincipal, RelayState returned, " +
          "and ends nothing (STS-FED-0122)"), function () {
    assert.strictEqual(unknown.answer.status, 303, K.shown(unknown.answer));
    assert.ok(ua && ua.verified, JSON.stringify(ua && ua.sigAlg));
    assert.strictEqual(ua.to, PARTNER_SLO);
    assert.ok(ua.codes.indexOf("Requester") >= 0 &&
              ua.codes.indexOf("UnknownPrincipal") >= 0, ua.codes.join());
    assert.strictEqual(ua.relay, "fso-relay");
    assert.ok(unknown.rose >= 1);
    assert.ok(live);
  });
  const valid = logoutRequest(w, { sessionIndex: idx, key: w.partnerKey });
  const accepted = await K.send(valid.url);
  const answer = accepted.location
    ? messageIn(accepted.location, "SAMLResponse", w.spCertPem) : null;
  live = await liveIn(w, signed.b);
  K.check(tag(w, "S8. a signed LogoutRequest naming the session ends it and " +
          "is answered with a signed Success LogoutResponse"), function () {
    assert.strictEqual(accepted.status, 303, K.shown(accepted));
    assert.ok(answer && answer.verified);
    assert.strictEqual(answer.codes[0], "Success");
    assert.ok(new RegExp("InResponseTo=\"" + valid.id + "\"")
      .test(answer.xml));
    assert.ok(!live);
  });
  const replay = await K.coded(w.SP, "STS-FED-0120", function () {
    return K.send(valid.url);
  });
  K.check(tag(w, "S9. the same LogoutRequest again is a replay, 403 " +
          "(STS-FED-0120)"), function () {
    assert.strictEqual(replay.answer.status, 403);
    assert.ok(replay.rose >= 1);
  });
  // The service-provider-initiated round trip.
  const two = await samlSignIn(w, "idx-two-" + K.rand(3), "");
  const bye = await signOutHere(w, two.b);
  const re = new RegExp("(" + literal(PARTNER_SLO) +
                        "\\?[^\"]+)\"");
  const outLink = htmlDecode((re.exec(String(bye.text || "")) ||
    re.exec(JSON.stringify(bye.json || {})) || [])[1] || "")
    .replace(/\\u0026/g, "&");
  const sent = outLink ? messageIn(outLink, "SAMLRequest", w.spCertPem)
                       : null;
  const ended = !(await liveIn(w, two.b));
  K.check(tag(w, "S10. /logout ends the session and offers the partner a " +
          "SIGNED LogoutRequest naming the NameID and SessionIndex"),
  function () {
    assert.ok(sent, String(bye.text || "").slice(0, 400));
    assert.ok(sent.verified, sent.sigAlg);
    assert.ok(sent.xml.indexOf(">" + NAMEID + "</saml:NameID>") >= 0,
              sent.xml.slice(0, 400));
    assert.ok(/<samlp:SessionIndex>idx-two-/.test(sent.xml));
    assert.ok(ended);
  });
  if (sent) {
    const requestId = (/ID="([^"]+)"/.exec(sent.xml) || [])[1];
    const qs = logoutResponseQs(w, requestId, sent.relay, "Success");
    const confirmed = await K.send(slo + "?" + qs);
    const twice = await K.coded(w.SP, "STS-FED-0124", function () {
      return K.send(slo + "?" + qs);
    });
    K.check(tag(w, "S11. the partner's signed LogoutResponse is matched by " +
            "InResponseTo and RelayState once; again it is refused " +
            "(STS-FED-0124)"), function () {
      assert.strictEqual(confirmed.status, 200, K.shown(confirmed));
      assert.ok(/confirmed/.test(confirmed.text));
      assert.strictEqual(twice.answer.status, 400);
      assert.ok(twice.rose >= 1);
    });
  }
  const three = await samlSignIn(w, "idx-three-" + K.rand(3), "");
  const bye3 = await signOutHere(w, three.b);
  const link3 = htmlDecode((re.exec(String(bye3.text || "")) ||
    re.exec(JSON.stringify(bye3.json || {})) || [])[1] || "")
    .replace(/\\u0026/g, "&");
  const sent3 = link3 ? messageIn(link3, "SAMLRequest", w.spCertPem) : null;
  const outcome = await K.coded(w.SP, "STS-FED-0125", function () {
    if (!sent3) {
      return { status: 0, text: "" };
    }
    return K.send(slo + "?" + logoutResponseQs(w,
      (/ID="([^"]+)"/.exec(sent3.xml) || [])[1], sent3.relay, "Responder",
      "fso partner busy"), { headers: { "accept-language": "fr" } });
  });
  K.check(tag(w, "S12. a partner's non-Success LogoutResponse is the " +
          "outcome page (STS-FED-0125), 200, in French with the StatusCode " +
          "and StatusMessage as sent, and not the error page"), function () {
    assert.strictEqual(outcome.answer.status, 200, K.shown(outcome.answer));
    assert.ok(outcome.rose >= 1);
    assert.ok(/<html lang="fr"/.test(outcome.answer.text));
    assert.ok(/Déconnecté ici, mais pas chez le partenaire/
      .test(outcome.answer.text));
    assert.ok(/<code>urn:oasis:names:tc:SAML:2\.0:status:Responder<\/code>/
      .test(outcome.answer.text));
    assert.ok(/fso partner busy/.test(outcome.answer.text));
    assert.ok(!/<div class="warn"/.test(outcome.answer.text));
  });
  const nothing = await K.coded(w.SP, "STS-FED-0122", function () {
    return K.send(K.rb(w.SP) + "/federation/slo/wsfed-t?wa=" +
                  "wsignoutcleanup1.0", { headers: { "accept-language":
                                                     "fr" } });
  });
  K.check(tag(w, "S13. a wsignoutcleanup1.0 with nothing to end is the " +
          "outcome page (STS-FED-0122), 200, in French, not the error page"),
  function () {
    assert.strictEqual(nothing.answer.status, 200, K.shown(nothing.answer));
    assert.ok(nothing.rose >= 1);
    assert.ok(/<html lang="fr"/.test(nothing.answer.text));
    assert.ok(/<h1>Rien à déconnecter<\/h1>/.test(nothing.answer.text));
    assert.ok(!/<div class="warn"/.test(nothing.answer.text));
  });
  const late = await K.coded(w.SP, "STS-FED-0131", function () {
    return samlSignIn(w, "idx-late-" + K.rand(3),
      new Date(Date.now() - 3600000).toISOString().replace(/\.\d{3}Z$/, "Z"));
  });
  K.check(tag(w, "S14. an assertion whose SessionNotOnOrAfter has passed " +
          "starts no session (401, STS-FED-0131)"), function () {
    assert.strictEqual(late.answer.r.status, 401, K.shown(late.answer.r));
    assert.ok(late.rose >= 1);
  });
  await K.set(w.SP, "oauth2.clockSkewS", 0);
  const short = await samlSignIn(w, "idx-short-" + K.rand(3),
    new Date(Date.now() + 4000).toISOString().replace(/\.\d{3}Z$/, "Z"));
  const liveFirst = await liveIn(w, short.b);
  await K.sleep(5500);
  const liveAfter = await liveIn(w, short.b);
  await K.unset(w.SP, "oauth2.clockSkewS");
  K.check(tag(w, "S15. the partner's SessionNotOnOrAfter is the session's " +
          "expiry: live before it, ended once it passes"), function () {
    assert.ok(liveFirst, K.shown(short.r));
    assert.ok(!liveAfter);
  });
  log.debug("Leaving saml().");
}

async function test() {
  log.debug("Entering test().");
  for (const mode of ["development", "product"]) {
    const w = await world(mode);
    await defaults(w);
    await backChannel(w);
    await frontChannel(w);
    await saml(w);
  }
  log.debug("Leaving test().");
}

K.main(test, 72);
