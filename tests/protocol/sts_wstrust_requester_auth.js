// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_wstrust_requester_auth.js
//
// ===========================================================================
// THE WS-TRUST REQUESTER AUTHENTICATED BY ITS MESSAGE SIGNATURE OR ITS TLS
// CLIENT CERTIFICATE, OVER THE WIRE, EACH REFUSAL BY ITS CODE (#444 D12,
// phase 7).
//
// `tests/wstrust_message_signature.js` (#521) and
// `tests/wstrust_client_certificate.js` (#1046) call `handleRst()` with a
// faked socket and keys the child process's own CA made. Here every key is
// made by the SERVICE through the administrator's doors (or, for an outside
// authority, minted by `tools/pep-credential.js` and admitted to the client
// truststore through the gated door, removed again at the end), and every
// request goes over `/realm/<id>/sts` on the main port, presenting the
// client certificate on the handshake where that is the credential. Codes
// are read off the realm's audit log.
//
//   M. THE MESSAGE SIGNATURE, in a product realm:
//      A. a person's signing certificate is the requester — SAML 2.0 X509,
//         SAML 1.1 X509-PKI, a JWT with amr ["swk"] and the urn:uuid:
//         subject — named by the token, by thumbprint, by issuer and serial
//         and by Subject Key Identifier; an application's is the client;
//      B. replay, STS-WSTRUST-0050;
//      C. a Body altered after signing and another key's signature (0045);
//         an unsigned RST, wst:Forwardable or wst:Delegatable in a header
//         (0046); the Body's id on a second element, a signature over the
//         Body alone (wst:AuthenticationBadElements), SHA-1 (0040);
//      D. an expired Timestamp (0048, wst:ExpiredData), one Created an hour
//         ahead (0047);
//      E. this realm's TLS client certificate and another realm's signing
//         certificate (0042), a thumbprint naming nothing issued (0041), a
//         revoked certificate (0049), an outside certificate stored on
//         nobody (0043), a disabled person (0052);
//      F. a UsernameToken beside the signature naming the same person is
//         accepted, naming somebody else is 0053;
//      G. development believes an altered Body;
//      H. an outside certificate: development believes it stored on
//         nobody; product refuses it stored on nobody (0043) and, stored on
//         one entry, on revocation when its list cannot be read (0049,
//         hard-fail); the management API refuses a second entry it.
//   T. THE TLS CLIENT CERTIFICATE, in a product realm:
//      A. a person's (EST-issued) certificate with nothing in the header is
//         the requester — SAML 2.0 TLSClient, SAML 1.1 urn:ietf:rfc:2246, a
//         JWT amr ["swk"] — and a JWT from a UsernameToken carries ["pwd"];
//      B. a UsernameToken in the message wins;
//      C. an application's certificate is the application;
//      D. revoked (0034), another realm's authority (0035), a disabled
//         person (0037);
//      E. `wstrust.acceptClientCertificate` off: no credential (0010);
//      F. (dev) an outside authority's certificate stored on nobody (0038)
//         though its CN names a person, stored on one entry accepted as that
//         person, stored on two (0039).
//
// NOT HERE: STS-WSTRUST-0044 (a signer stored on two entries: product's
// LDAP write is authorized and the API refuses the second copy, so only a
// development realm can hold two, where the signature is believed);
// STS-WSTRUST-0051 (a signed request the endpoint did not check
// against the history: no route skips the check) and 0036 (a certificate
// the register forgets while it still verifies) are (d).
//
// OWNED HERE (local: true). Its realms are removed only on a private probe.
// ===========================================================================

const assert = require("assert");
const https = require("https");
const nodeCrypto = require("crypto");
const ldapjs = require("ldapjs");
const est = require("./est_client.js");
const anchors = require("../tools/pep-credential.js");
const K = require("./oauth_wire_kit.js").kit("sts_wstrust_requester_auth");
const W = require("./wstrust_wire_kit.js").wsKit(K);
// xmldsig.js reaches for the bare DOM globals a node process lacks.
const xmldom = require("@xmldom/xmldom");
if (!global.DOMParser) {
  global.DOMParser = xmldom.DOMParser;
}
if (!global.XMLSerializer) {
  global.XMLSerializer = xmldom.XMLSerializer;
}
const path = require("path");
const REPO = process.env.MOCK_STS_DIR || path.join(__dirname, "..", "..");
const xmldsig = require(path.join(REPO, "common", "crypto_impl",
                                  "xmldsig.js"));
const x509 = require(path.join(REPO, "common", "crypto_impl", "x509.js"));
const keys = require(path.join(REPO, "common", "crypto_impl",
                               "key_material.js"));

const log = K.log;
const added = [];
const WSSE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-" +
             "wssecurity-secext-1.0.xsd";
const WSU = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-" +
            "wssecurity-utility-1.0.xsd";
const X509V3 = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-" +
               "x509-token-profile-1.0#X509v3";
const THUMBPRINT = "http://docs.oasis-open.org/wss/oasis-wss-soap-message-" +
                   "security-1.1#ThumbprintSHA1";
const SKI = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-" +
            "x509-token-profile-1.0#X509SubjectKeyIdentifier";
const BASE64 = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-" +
               "soap-message-security-1.0#Base64Binary";
const RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
const FILE_PASSWORD = "file-" + K.rand(8);
const PW = "Ws-Auth-Passw0rd!-" + K.rand(4);
const BACK = "https://wsa-back-" + K.STAMP + ".example";

// ------------------------------------------------------------- plumbing
function pkcs1(pem, passphrase) {
  log.debug("Entering pkcs1().");
  const key = nodeCrypto.createPrivateKey({ key: pem, format: "pem",
    passphrase: passphrase });
  log.debug("Leaving pkcs1().");
  return key.export({ type: "pkcs1", format: "pem" });
}

// What an issue-signing-certificate answer hands back, opened.
function openIssued(reply, what) {
  log.debug("Entering openIssued().");
  const cert = reply && reply.certificate;
  const key = reply && reply.files && reply.files.key;
  assert.ok(cert && cert.certificatePem && key && key.text, what + ": no " +
            "certificate or key: " + JSON.stringify(reply).slice(0, 300));
  log.debug("Leaving openIssued().");
  return { certPem: cert.certificatePem, serialHex: cert.serialHex,
           keyPem: pkcs1(key.text, FILE_PASSWORD) };
}

// The Subject Key Identifier's bytes, read out of the DER (2.5.29.14).
function skiOf(certPem) {
  log.debug("Entering skiOf().");
  const der = new nodeCrypto.X509Certificate(certPem).raw;
  const oid = Buffer.from([0x06, 0x03, 0x55, 0x1d, 0x0e]);
  const at = der.indexOf(oid);
  assert.ok(at > 0, "the certificate carries no Subject Key Identifier");
  // OID, then an OCTET STRING wrapping an OCTET STRING holding the bytes.
  let i = at + oid.length;
  assert.strictEqual(der[i], 0x04);
  i += 2;
  assert.strictEqual(der[i], 0x04);
  const len = der[i + 1];
  log.debug("Leaving skiOf().");
  return der.slice(i + 2, i + 2 + len);
}

function keyInfoFor(form, certPem) {
  log.debug("Entering keyInfoFor(). " + form);
  const c = new nodeCrypto.X509Certificate(certPem);
  let inner = '<wsse:Reference URI="#x509" ValueType="' + X509V3 + '"/>';
  if (form === "thumbprint") {
    inner = '<wsse:KeyIdentifier ValueType="' + THUMBPRINT +
      '" EncodingType="' + BASE64 + '">' +
      nodeCrypto.createHash("sha1").update(c.raw).digest("base64") +
      "</wsse:KeyIdentifier>";
  } else if (form === "ski") {
    inner = '<wsse:KeyIdentifier ValueType="' + SKI + '" EncodingType="' +
      BASE64 + '">' + skiOf(certPem).toString("base64") +
      "</wsse:KeyIdentifier>";
  } else if (form === "issuer-serial") {
    inner = '<ds:X509Data xmlns:ds="http://www.w3.org/2000/09/xmldsig#">' +
      "<ds:X509IssuerSerial><ds:X509IssuerName>" +
      c.issuer.split("\n").join(",") + "</ds:X509IssuerName>" +
      "<ds:X509SerialNumber>" + BigInt("0x" + c.serialNumber).toString() +
      "</ds:X509SerialNumber></ds:X509IssuerSerial></ds:X509Data>";
  }
  log.debug("Leaving keyInfoFor().");
  return "<ds:KeyInfo><wsse:SecurityTokenReference>" + inner +
    "</wsse:SecurityTokenReference></ds:KeyInfo>";
}

// An unsigned RST with the ids a signer references.
function envelope(o) {
  log.debug("Entering envelope().");
  const now = Date.now();
  const certB64 = o.certPem ? String(o.certPem)
    .replace(/-----[^-]+-----/g, "").replace(/\s+/g, "") : "";
  log.debug("Leaving envelope().");
  return '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" ' +
    'xmlns:wsse="' + WSSE + '" xmlns:wsu="' + WSU + '"><s:Header>' +
    (o.header || "") + "<wsse:Security>" +
    '<wsu:Timestamp wsu:Id="ts"><wsu:Created>' +
    new Date(now + (o.createdOffsetMs || 0)).toISOString() +
    "</wsu:Created><wsu:Expires>" + new Date(now + (o.expiresOffsetMs ===
      undefined ? 300000 : o.expiresOffsetMs)).toISOString() +
    "</wsu:Expires></wsu:Timestamp>" +
    (certB64 ? '<wsse:BinarySecurityToken wsu:Id="x509" ValueType="' +
      X509V3 + '" EncodingType="' + BASE64 + '">' + certB64 +
      "</wsse:BinarySecurityToken>" : "") +
    (o.security || "") + "</wsse:Security></s:Header>" +
    '<s:Body wsu:Id="body"><wst:RequestSecurityToken xmlns:wst="' + W.WST +
    '" Context="urn:uuid:' + nodeCrypto.randomUUID() + '">' +
    "<wst:RequestType>" + W.WST + "/Issue</wst:RequestType>" +
    (o.tokenType ? "<wst:TokenType>" + o.tokenType + "</wst:TokenType>"
                 : "") +
    '<wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/' +
    'policy"><wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/' +
    '08/addressing"><wsa:Address>' + BACK + "</wsa:Address>" +
    "</wsa:EndpointReference></wsp:AppliesTo>" +
    "</wst:RequestSecurityToken></s:Body></s:Envelope>";
}

// A signed RST: the WS-Security signer over the Body and the Timestamp,
// its KeyInfo then replaced with a SecurityTokenReference (the KeyInfo is
// not signed, so the replacement changes nothing it covers).
function signed(holder, o) {
  log.debug("Entering signed().");
  const opts = o || {};
  const form = opts.form || "token";
  const xml = envelope(Object.assign({}, opts,
    { certPem: form === "token" ? holder.certPem : "" }));
  let out = xmldsig.signWsSecurity(xml, {
    privateKeyPem: opts.signKeyPem || holder.keyPem, certPem: holder.certPem,
    signTimestamp: opts.signTimestamp !== false,
    sigAlg: opts.sigAlg || undefined });
  out = out.replace(/<ds:KeyInfo>[\s\S]*?<\/ds:KeyInfo>/,
                    keyInfoFor(form, holder.certPem));
  log.debug("Leaving signed().");
  return opts.after ? opts.after(out) : out;
}

// A POST to a realm's /sts on its own connection, presenting `tls`.
function tlsPost(id, body, tls) {
  log.debug("Entering tlsPost().");
  const u = new URL(K.rb(id) + "/sts");
  return new Promise(function (resolve, reject) {
    const req = https.request({ host: u.hostname, port: u.port,
      path: u.pathname, method: "POST", agent: false,
      headers: { "Content-Type": "application/soap+xml" },
      cert: tls.cert, key: tls.key, passphrase: tls.passphrase },
    function (res) {
      let text = "";
      res.setEncoding("utf8");
      res.on("data", function (c) {
        text += c;
      });
      res.on("end", function () {
        log.debug("Leaving tlsPost(). " + res.statusCode);
        resolve({ status: res.statusCode, text: text });
      });
    });
    req.on("error", reject);
    req.end(body);
  });
}

function postRaw(id, body) {
  log.debug("Entering postRaw().");
  log.debug("Leaving postRaw().");
  return W.post(id, { raw: body });
}

function jwtOf(r) {
  log.debug("Entering jwtOf().");
  const t = W.tokenOf(r, "the RSTR");
  assert.ok(t.jwt, "no JWT: " + t.inner.slice(0, 200));
  log.debug("Leaving jwtOf().");
  return K.decode(t.jwt).payload;
}

// A refusal: a 4xx/5xx fault with section 11's `fault` in its place, and a
// new row of `code` in the realm.
async function refused(id, label, code, fault, act) {
  log.debug("Entering refused(). " + code);
  const got = await K.coded(id, code, act);
  K.check(label + " is " + code + ", wst:" + fault, function () {
    const r = got.answer;
    assert.ok(r.status >= 400, r.status + " " + r.text.slice(0, 300));
    assert.ok(W.carries(r.text, false, fault, W.WST), r.text.slice(0, 500));
    assert.ok(got.rose >= 1, "no new " + code + " row in " + id);
  });
  log.debug("Leaving refused().");
}

async function person(id, who) {
  log.debug("Entering person(). " + who);
  const made = await K.ok(K.rb(id) + "/admin-api/users/create", {
    username: who, invent: false, credential: "password", password: PW,
    attributes: { cn: "WSA " + who, givenName: "WSA", sn: who,
                  mail: who + "@wsa.example.test" } }, "created " + who);
  log.debug("Leaving person().");
  return String(made.dn);
}

async function signingCertificate(id, kind, name) {
  log.debug("Entering signingCertificate(). " + name);
  const r = await K.ok(K.rb(id) + "/admin-api/" + kind +
    "/issue-signing-certificate", Object.assign({ keyAlg: "rsa-2048",
      password: FILE_PASSWORD }, kind === "users" ? { user: name }
      : { application: name }), "issued " + name + " a signing certificate");
  log.debug("Leaving signingCertificate().");
  return openIssued(r, name);
}

async function tlsCertificateOf(id, app) {
  log.debug("Entering tlsCertificateOf(). " + app);
  const r = await K.ok(K.rb(id) + "/admin-api/applications/issue-tls-" +
    "client-certificate", { application: app, password: FILE_PASSWORD,
      keyAlg: "rsa-2048" }, "issued " + app + " a TLS client certificate");
  const keyPem = pkcs1(r.files.key.text, FILE_PASSWORD);
  const certPem = (r.files.chain.text.match(
    /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/) ||
    [""])[0];
  log.debug("Leaving tlsCertificateOf().");
  return { cert: r.files.chain.text, key: keyPem, certPem: certPem };
}

// A person's TLS client certificate over the realm's EST `tls-client`.
async function enrol(id, who) {
  log.debug("Entering enrol(). " + who);
  const rb = K.rb(id);
  const pair = await keys.generateKeyPair("ec-p256");
  const csr = await x509.certificationRequest({ subject: "CN=" + who,
    publicKeyPem: pair.publicPem, privateKeyPem: pair.privatePem });
  const r = await est.send({ method: "POST",
    url: rb + "/.well-known/est/tls-client/simpleenroll",
    headers: { "Content-Type": "application/pkcs10" },
    body: est.requestBody(csr.der), basic: [who, PW] });
  assert.strictEqual(r.status, 200, "EST enrolment: " + r.status + " " +
                     String(r.body).slice(0, 200));
  const pem = est.parseCertsOnly(est.base64Body(r.body)).certificates[0];
  const ca = await est.send({ method: "GET",
    url: rb + "/.well-known/est/tls-client/cacerts" });
  const chain = est.parseCertsOnly(est.base64Body(ca.body)).certificates;
  log.debug("Leaving enrol().");
  return { cert: pem + chain.join(""), key: pair.privatePem,
           serial: new nodeCrypto.X509Certificate(pem).serialNumber };
}

// An LDAP modify of one person's userCertificate;binary, bound as them
// (a development realm, where the bind is believed).
function ldapCertificate(dn, der, operation) {
  log.debug("Entering ldapCertificate(). " + operation);
  const url = "ldap://" + new URL(K.base).hostname + ":" +
              (process.env.STS_LDAP_PORT || "389");
  return new Promise(function (resolve) {
    const client = ldapjs.createClient({ url: url });
    function done(error) {
      client.unbind();
      log.debug("Leaving ldapCertificate().");
      resolve(error ? { ok: false, message: error.message } : { ok: true });
    }
    client.on("error", function (e) {
      log.debug("Caught in ldapCertificate(): " + e.message);
      resolve({ ok: false, message: String(e && e.message) });
    });
    client.bind(dn, "x-" + K.STAMP, function (bindError) {
      if (bindError) {
        done(bindError);
        return;
      }
      client.modify(dn, new ldapjs.Change({ operation: operation,
        modification: new ldapjs.Attribute({ type: "userCertificate;binary",
                                             values: [der] }) }), done);
    });
  });
}

// --------------------------------------------------------------------- M
async function messageSignature(P, Q, D) {
  log.debug("Entering messageSignature().");
  log.info("=== M. the message signature (#521), product ===");
  const alice = "wsa-alice";
  const bob = "wsa-bob";
  const dave = "wsa-dave";
  for (const who of [alice, bob, dave]) {
    await person(P, who);
  }
  await person(Q, alice);
  const mine = { alice: await signingCertificate(P, "users", alice),
                 bob: await signingCertificate(P, "users", bob),
                 dave: await signingCertificate(P, "users", dave),
                 app: await signingCertificate(P, "applications", "wsa-svc"),
                 other: await signingCertificate(Q, "users", alice) };
  const tls = await tlsCertificateOf(P, "wsa-svc");
  mine.tls = { certPem: tls.certPem, keyPem: tls.key };

  let r = await postRaw(P, signed(mine.alice, { tokenType: W.SAML2 }));
  K.check("MA1. a request signed by the person is an assertion about them " +
          "stating X509", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 400));
    assert.ok(r.text.indexOf(">" + alice + "<") > 0);
    assert.ok(/classes:X509</.test(r.text), r.text.slice(0, 2000));
  });
  r = await postRaw(P, signed(mine.alice, { tokenType: W.SAML11 }));
  K.check("MA2. SAML 1.1 says X509-PKI", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 400));
    assert.ok(/AuthenticationMethod="urn:oasis:names:tc:SAML:1\.0:am:X509-PKI"/
      .test(r.text), r.text.slice(0, 2000));
  });
  r = await postRaw(P, signed(mine.alice, { tokenType: W.JWT }));
  K.check("MA3. a JWT carries amr [\"swk\"] and the urn:uuid: subject",
          function () {
            const c = jwtOf(r);
            assert.deepStrictEqual(c.amr, ["swk"]);
            assert.ok(/^urn:uuid:/.test(c.sub), c.sub);
          });
  for (const form of ["thumbprint", "issuer-serial", "ski"]) {
    r = await postRaw(P, signed(mine.alice, { tokenType: W.JWT,
                                              form: form }));
    K.check("MA4. the certificate named by " + form + " is the person",
            function () {
              assert.strictEqual(r.status, 200, r.text.slice(0, 400));
              assert.strictEqual(jwtOf(r).name, alice);
            });
  }
  r = await postRaw(P, signed(mine.app, { tokenType: W.JWT }));
  K.check("MA5. an application's signature is the application: client_id " +
          "its own", function () {
    assert.strictEqual(jwtOf(r).client_id, "wsa-svc");
  });

  const once = signed(mine.alice, { tokenType: W.SAML2 });
  const first = await postRaw(P, once);
  assert.strictEqual(first.status, 200, first.text.slice(0, 300));
  await refused(P, "MB. the same signed request again (a replay)",
    "STS-WSTRUST-0050", "FailedAuthentication", function () {
      return postRaw(P, once);
    });

  await refused(P, "MC1. a Body altered after signing", "STS-WSTRUST-0045",
    "FailedAuthentication", function () {
      return postRaw(P, signed(mine.alice, { after: function (xml) {
        return xml.replace('Context="urn:uuid:', 'Context="urn:uuid:0');
      } }));
    });
  await refused(P, "MC2. a signature by a key that is not the named " +
    "certificate's", "STS-WSTRUST-0045", "FailedAuthentication", function () {
    return postRaw(P, signed(mine.alice, { signKeyPem: mine.bob.keyPem }));
  });
  const smuggled = [
    ["an unsigned RequestSecurityToken in a header",
     '<x:Smuggled xmlns:x="urn:x"><wst:RequestSecurityToken xmlns:wst="' +
     W.WST + '"><wst:RequestType>' + W.WST + "/Issue</wst:RequestType>" +
     "</wst:RequestSecurityToken></x:Smuggled>"],
    ["an unsigned wst:Forwardable in a header", '<wst:Forwardable ' +
     'xmlns:wst="' + W.WST + '">true</wst:Forwardable>'],
    ["an unsigned wst:Delegatable in a header", '<wst:Delegatable ' +
     'xmlns:wst="' + W.WST + '">true</wst:Delegatable>']];
  for (const s of smuggled) {
    await refused(P, "MC3. " + s[0], "STS-WSTRUST-0046",
      "FailedAuthentication", function () {
        return postRaw(P, signed(mine.alice, { header: s[1] }));
      });
  }
  await refused(P, "MC4. the Body's id on a second element",
    "STS-WSTRUST-0040", "FailedAuthentication", function () {
      return postRaw(P, signed(mine.alice, { after: function (xml) {
        return xml.replace("<s:Header>", '<s:Header><x:Copy xmlns:x="urn:x" ' +
                           'wsu:Id="body"/>');
      } }));
    });
  await refused(P, "MC5. a signature over the Body and not the Timestamp",
    "STS-WSTRUST-0040", "AuthenticationBadElements", function () {
      return postRaw(P, signed(mine.alice, { signTimestamp: false }));
    });
  await refused(P, "MC6. SHA-1, with saml.allowSha1Signatures off",
    "STS-WSTRUST-0040", "FailedAuthentication", function () {
      return postRaw(P, signed(mine.alice, { sigAlg: RSA_SHA1 }));
    });
  await refused(P, "MD1. an expired Timestamp", "STS-WSTRUST-0048",
    "ExpiredData", function () {
      return postRaw(P, signed(mine.alice, { createdOffsetMs: -3600000,
                                             expiresOffsetMs: -1800000 }));
    });
  await refused(P, "MD2. a Timestamp Created an hour ahead",
    "STS-WSTRUST-0047", "FailedAuthentication", function () {
      return postRaw(P, signed(mine.alice, { createdOffsetMs: 3600000,
                                             expiresOffsetMs: 7200000 }));
    });
  await refused(P, "ME1. this realm's TLS client certificate signs nobody " +
    "in", "STS-WSTRUST-0042", "FailedAuthentication", function () {
    return postRaw(P, signed(mine.tls));
  });
  await refused(P, "ME2. another realm's message-signing certificate",
    "STS-WSTRUST-0042", "FailedAuthentication", function () {
      return postRaw(P, signed(mine.other));
    });
  await refused(P, "ME3. a thumbprint naming no issued message-signing " +
    "certificate", "STS-WSTRUST-0041", "FailedAuthentication", function () {
    return postRaw(P, signed(mine.tls, { form: "thumbprint" }));
  });
  await K.ok(K.rb(P) + "/admin-api/users/revoke-signing-certificate",
             { user: bob, serialHex: mine.bob.serialHex,
               reason: "keyCompromise" }, "revoked bob's certificate");
  await refused(P, "ME4. a revoked signing certificate", "STS-WSTRUST-0049",
    "FailedAuthentication", function () {
      return postRaw(P, signed(mine.bob));
    });
  await K.ok(K.rb(P) + "/admin-api/users/disable", { user: dave },
             "disabled dave");
  await refused(P, "ME5. a disabled person's signature", "STS-WSTRUST-0052",
    "FailedAuthentication", function () {
      return postRaw(P, signed(mine.dave));
    });
  r = await postRaw(P, signed(mine.alice, { tokenType: W.JWT,
    security: W.usernameToken(alice, PW) }));
  K.check("MF1. a UsernameToken beside the signature naming the same " +
          "person is accepted, and names them", function () {
    assert.strictEqual(jwtOf(r).name, alice);
  });
  await refused(P, "MF2. a UsernameToken naming somebody else",
    "STS-WSTRUST-0053", "FailedAuthentication", function () {
      return postRaw(P, signed(mine.alice, {
        security: W.usernameToken(bob, PW) }));
    });

  log.info("=== M. development ===");
  await person(D, alice);
  const devAlice = await signingCertificate(D, "users", alice);
  r = await postRaw(D, signed(devAlice, { tokenType: W.SAML2,
    after: function (xml) {
      return xml.replace('Context="urn:uuid:', 'Context="urn:uuid:0');
    } }));
  K.check("MG. development believes a Body altered after signing",
          function () {
            assert.strictEqual(r.status, 200, r.text.slice(0, 400));
            assert.ok(r.text.indexOf(">" + alice + "<") > 0);
          });
  log.debug("Leaving messageSignature().");
}

// --------------------------------------------------------------------- T
async function clientCertificate(P, Q) {
  log.debug("Entering clientCertificate().");
  log.info("=== T. the TLS client certificate (#1046), product ===");
  const carol = "wsa-carol";
  const erin = "wsa-erin";
  const fred = "wsa-fred";
  for (const who of [carol, erin, fred]) {
    await person(P, who);
  }
  await person(Q, carol);
  const c = await enrol(P, carol);
  let r = await tlsPost(P, W.rst({ appliesTo: BACK, tokenType: W.SAML2 }), c);
  K.check("TA1. a person's certificate with nothing in the header is the " +
          "requester: SAML 2.0 TLSClient", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 400));
    assert.ok(r.text.indexOf(">" + carol + "<") > 0);
    assert.ok(/classes:TLSClient</.test(r.text), r.text.slice(0, 2000));
  });
  r = await tlsPost(P, W.rst({ appliesTo: BACK, tokenType: W.SAML11 }), c);
  K.check("TA2. SAML 1.1 says urn:ietf:rfc:2246", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 400));
    assert.ok(/AuthenticationMethod="urn:ietf:rfc:2246"/.test(r.text),
              r.text.slice(0, 2000));
  });
  r = await tlsPost(P, W.rst({ appliesTo: BACK, tokenType: W.JWT }), c);
  K.check("TA3. a JWT carries amr [\"swk\"] and the urn:uuid: subject",
          function () {
            const j = jwtOf(r);
            assert.deepStrictEqual(j.amr, ["swk"]);
            assert.ok(/^urn:uuid:/.test(j.sub));
          });
  r = await W.post(P, { security: W.usernameToken(carol, PW),
                        appliesTo: BACK, tokenType: W.JWT });
  K.check("TA4. a JWT from a UsernameToken carries [\"pwd\"]", function () {
    assert.deepStrictEqual(jwtOf(r).amr, ["pwd"]);
  });
  r = await tlsPost(P, W.rst({ appliesTo: BACK, tokenType: W.JWT,
    security: W.usernameToken(erin, PW) }), c);
  K.check("TB. a UsernameToken in the message wins over the certificate",
          function () {
            const j = jwtOf(r);
            assert.strictEqual(j.name, erin);
            assert.deepStrictEqual(j.amr, ["pwd"]);
          });
  const appTls = await tlsCertificateOf(P, "wsa-tls-app");
  r = await tlsPost(P, W.rst({ appliesTo: BACK, tokenType: W.JWT }), appTls);
  K.check("TC. an application's certificate is the application",
          function () {
            assert.strictEqual(jwtOf(r).client_id, "wsa-tls-app");
          });
  const e = await enrol(P, erin);
  await K.ok(K.rb(P) + "/admin-api/est/revoke-certificate",
             { serial: e.serial.toLowerCase(), reason: "keyCompromise" },
             "revoked erin's certificate");
  await refused(P, "TD1. a revoked client certificate", "STS-WSTRUST-0034",
    "FailedAuthentication", function () {
      return tlsPost(P, W.rst({ appliesTo: BACK }), e);
    });
  const foreign = await enrol(Q, carol);
  await refused(P, "TD2. another realm's authority's certificate",
    "STS-WSTRUST-0035", "FailedAuthentication", function () {
      return tlsPost(P, W.rst({ appliesTo: BACK }), foreign);
    });
  const f = await enrol(P, fred);
  await K.ok(K.rb(P) + "/admin-api/users/disable", { user: fred },
             "disabled fred");
  await refused(P, "TD3. a disabled person's certificate",
    "STS-WSTRUST-0037", "FailedAuthentication", function () {
      return tlsPost(P, W.rst({ appliesTo: BACK }), f);
    });
  await K.set(P, "wstrust.acceptClientCertificate", false);
  await refused(P, "TE. with wstrust.acceptClientCertificate off, the " +
    "certificate is no credential", "STS-WSTRUST-0010",
    "FailedAuthentication", function () {
      return tlsPost(P, W.rst({ appliesTo: BACK }), c);
    });
  await K.unset(P, "wstrust.acceptClientCertificate");
  log.debug("Leaving clientCertificate().");
}

// ------------------------------------------------- outside authority, dev
async function outside(D) {
  log.debug("Entering outside().");
  log.info("=== H / TF. an outside authority's certificate, development ===");
  const gina = "wsa-gina";
  const hank = "wsa-hank";
  const ginaDn = await person(D, gina);
  const hankDn = await person(D, hank);
  const minted = await anchors.mint({ subject: "CN=" + gina +
                                      ",O=outside authority" });
  const installed = await anchors.trustRecorded(K.base, minted.anchorPem,
                                                added);
  assert.ok(installed.ok, "the outside Root was not admitted: " +
            String(installed.why || installed.status));
  const tls = { cert: minted.certPem, key: minted.keyPem };
  const holder = { certPem: minted.leaf.pem, keyPem: pkcs1(minted.keyPem) };
  const der = new nodeCrypto.X509Certificate(minted.leaf.pem).raw;

  await refused(D, "TF1. a client certificate no entry stores, though its " +
    "CN names a person", "STS-WSTRUST-0038", "FailedAuthentication",
  function () {
    return tlsPost(D, W.rst({ appliesTo: BACK }), tls);
  });
  let r = await postRaw(D, signed(holder, { tokenType: W.JWT }));
  K.check("H1 (development). a message signed by an outside certificate " +
          "stored on nobody is believed (development maps no signer)",
          function () {
            assert.strictEqual(r.status, 200, r.text.slice(0, 300));
          });
  await K.ok(K.rb(D) + "/admin-api/users/add-certificate", { user: gina,
    certificate: minted.leaf.pem }, "stored it on " + gina);
  r = await tlsPost(D, W.rst({ appliesTo: BACK, tokenType: W.JWT }), tls);
  K.check("TF2. stored on one entry, the certificate is that person",
          function () {
            assert.strictEqual(jwtOf(r).name, gina);
          });
  r = await postRaw(D, signed(holder, { tokenType: W.JWT }));
  K.check("H2. and the message it signs is that person's", function () {
    assert.strictEqual(jwtOf(r).name, gina);
  });
  const second = await ldapCertificate(hankDn, der, "add");
  assert.ok(second.ok, "the second copy over LDAP: " + second.message);
  await refused(D, "TF3. a client certificate two entries store",
    "STS-WSTRUST-0039", "FailedAuthentication", function () {
      return tlsPost(D, W.rst({ appliesTo: BACK }), tls);
    });
  assert.ok(ginaDn);
  log.debug("Leaving outside().");
  return { minted: minted, holder: holder };
}

// H, product: the outside certificate (its Root already admitted) signs
// the message, stored on nobody and then on two entries.
async function outsideProduct(P, o) {
  log.debug("Entering outsideProduct().");
  log.info("=== H. an outside certificate's signature, product ===");
  const ivy = "wsa-ivy";
  const jon = "wsa-jon";
  await person(P, ivy);
  await person(P, jon);
  await refused(P, "H2. a message signed by an outside certificate stored " +
    "on nobody", "STS-WSTRUST-0043", "FailedAuthentication", function () {
    return postRaw(P, signed(o.holder));
  });
  await K.ok(K.rb(P) + "/admin-api/users/add-certificate", { user: ivy,
    certificate: o.minted.leaf.pem }, "stored it on " + ivy);
  // THE MINTED CHAIN NAMES A CRL ON THIS RUNNER'S LOOPBACK, which the
  // service cannot reach: product's hard-fail refuses it on revocation —
  // the in-process file's "refused on revocation when its issuer names no
  // list the service can read" (H1 shows development accepting it).
  await refused(P, "H3. stored on one entry, an outside signer whose list " +
    "cannot be read is refused under hard-fail", "STS-WSTRUST-0049",
    "FailedAuthentication", function () {
      return postRaw(P, signed(o.holder, { tokenType: W.JWT }));
    });
  const twice = await K.send(K.rb(P) + "/admin-api/users/add-certificate",
    { json: { user: jon, certificate: o.minted.leaf.pem } });
  // The door refuses a certificate another entry stores; the second copy
  // is written over LDAP in the development realm (TF3), so 0044 is not
  // reached in product here.
  K.check("H4. the management API refuses a second entry the same " +
          "outside certificate", function () {
    assert.strictEqual(twice.status, 400, twice.text.slice(0, 300));
  });
  log.debug("Leaving outsideProduct().");
}

async function test() {
  log.debug("Entering test().");
  const P = await K.realm("wa-p", "product",
                          { "authn.allowOptionalSecondFactor": "true" });
  const Q = await K.realm("wa-q", "product",
                          { "authn.allowOptionalSecondFactor": "true" });
  const D = await K.realm("wa-d", "development");
  for (const id of [P, Q, D]) {
    for (const app of ["wsa-back", "wsa-svc", "wsa-tls-app"]) {
      await K.ok(K.rb(id) + "/admin-api/applications/create", {
        identifier: app, name: app, protocols: ["wstrust", "oauth2"],
        fields: Object.assign({ oauthClientId: [app] }, app === "wsa-back"
          ? { wstrustAppliesTo: [BACK] } : {}) }, "created " + app);
    }
  }
  let failure = null;
  try {
    await messageSignature(P, Q, D);
    await clientCertificate(P, Q);
    await outsideProduct(P, await outside(D));
  } catch (e) {
    log.debug("Caught in test(): " + ((e && e.message) || e));
    // Rethrown after the outside anchor is removed.
    failure = e;
  }
  await anchors.settleAnchors(K.base, added, failure);
  log.debug("Leaving test().");
}

K.main(test, 40);
