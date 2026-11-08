// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_paranoid_pki_signers.js
//
// ===========================================================================
// PARANOID PKI MODE AT A SIGNER (#1360, Phase 3).
//
// `local: true`. In a realm of its own, with the master forced on, each case refused
// and then accepted with its row off:
//
//   * an SP's signed AuthnRequest, redirect binding, under an expired registered
//     certificate, refused at `/saml2/sso`;
//   * that expired certificate refused at the registration door;
//   * SP metadata that reaches no trust anchor, refused at the upload;
//   * a self-signed `x5c` on a client's registered key, at private_key_jwt.
//
// Partner signatures are `tests/certificate_trust.js`'s section L: driving one here
// would be a second identity provider, signing what this job would have to mint.
// ===========================================================================

const assert = require("assert");
const https = require("https");
const nodeCrypto = require("crypto");
const zlib = require("zlib");
const { Command, Option } = require("commander");
const kit = require("../tools/trust_kit.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, the arrangement tests/vendored/wait_for.js has.
  appconfigProblem = e;
  appconfig = {};
}

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_paranoid_pki_signers",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = Date.now().toString(36);
const REALM = "paranoid-sig-" + STAMP;
const SP = "https://sp.paranoid.example/" + STAMP;
const ANCHORED_SP = "https://anchored.paranoid.example/" + STAMP;
const CLIENT = "paranoid-jwt-" + STAMP;

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function send(method, path, payload) {
  log.debug("Entering send(). " + method + " " + path);
  const target = new URL(base + path);
  const headers = { accept: "application/json" };
  const body = payload === undefined ? "" : JSON.stringify(payload);
  if (body) {
    headers["content-type"] = "application/json";
    headers["content-length"] = Buffer.byteLength(body);
  }
  log.debug("Leaving send().");
  return new Promise(function (resolve, reject) {
    const transport = target.protocol === "http:" ? require("http") : https;
    const req = transport.request({
      method: method, hostname: target.hostname, port: target.port,
      path: target.pathname + target.search, headers: headers
    }, function (res) {
      const chunks = [];
      res.on("data", function (c) {
        chunks.push(c);
      });
      res.on("end", function () {
        const raw = Buffer.concat(chunks).toString("utf8");
        let json = null;
        try {
          json = JSON.parse(raw);
        } catch (e) {
          log.debug("Caught in send(): " + ((e && e.message) || e));
          json = null;
        }
        resolve({ status: res.statusCode, raw: raw, json: json });
      });
    });
    req.on("error", reject);
    req.end(body);
  });
}

function api() {
  log.debug("Entering api().");
  log.debug("Leaving api().");
  return "/realm/" + REALM + "/admin-api";
}

async function setRow(setting, value) {
  log.debug("Entering setRow(). " + setting);
  const out = await send("POST", api() + "/pki/trust/set-row",
                         { setting: setting, value: value });
  assert.strictEqual(out.status, 200, out.raw.slice(0, 300));
  log.debug("Leaving setRow().");
}

function plainGet(path) {
  log.debug("Entering plainGet().");
  const target = new URL(base + path);
  log.debug("Leaving plainGet().");
  return new Promise(function (resolve, reject) {
    https.get({ hostname: target.hostname, port: target.port,
                path: target.pathname + target.search, agent: false },
    function (res) {
      res.resume();
      res.on("end", function () {
        resolve({ status: res.statusCode, location: res.headers.location });
      });
    }).on("error", reject);
  });
}

// An AuthnRequest in the redirect binding, signed as SAML Bindings section 3.4.4.1
// says: over the query string as it is sent.
function signedRequest(cert) {
  log.debug("Entering signedRequest().");
  const xml = '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:' +
    'protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_' +
    nodeCrypto.randomBytes(8).toString("hex") + '" Version="2.0" IssueInstant="' +
    new Date().toISOString() + '" Destination="' + base + '/realm/' + REALM +
    '/saml2/sso"><saml:Issuer>' + SP +
    '</saml:Issuer></samlp:AuthnRequest>';
  const message = zlib.deflateRawSync(Buffer.from(xml)).toString("base64");
  const alg = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
  const signedPart = "SAMLRequest=" + encodeURIComponent(message) + "&SigAlg=" +
                     encodeURIComponent(alg);
  const signature = nodeCrypto.sign("sha256", Buffer.from(signedPart), cert.key)
    .toString("base64");
  log.debug("Leaving signedRequest().");
  return "/realm/" + REALM + "/saml2/sso?" + signedPart + "&Signature=" +
         encodeURIComponent(signature);
}

function b64(cert) {
  log.debug("Entering b64().");
  log.debug("Leaving b64().");
  return cert.pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
}

async function aSamlSigner() {
  log.debug("Entering aSamlSigner().");
  log.info("=== a. a SAML service provider's certificate ===");
  const now = Date.now();
  const expired = await kit.mint({ cn: "paranoid sp expired",
    notBefore: now - 3 * kit.DAY, notAfter: now - kit.DAY });
  await setRow("pki.paranoid", "on");
  const fields = { samlAssertionConsumerService: ["https://sp.paranoid.example/acs"],
                   samlSigningCertificate: b64(expired) };
  const refusedWrite = await send("POST", api() + "/applications/create", {
    identifier: SP, name: "paranoid sp", protocols: ["saml2"], fields: fields });
  check("an expired certificate is refused at the registration door",
        function () {
    assert.strictEqual(refusedWrite.status, 400, refusedWrite.raw.slice(0, 300));
    assert.ok(/expired/.test(refusedWrite.raw), refusedWrite.raw.slice(0, 300));
  });
  await setRow("pki.paranoidSamlSigner", false);
  const planted = await send("POST", api() + "/applications/create", {
    identifier: SP, name: "paranoid sp", protocols: ["saml2"], fields: fields });
  check("with the row off it is written, as it was", function () {
    assert.strictEqual(planted.status, 200, planted.raw.slice(0, 300));
  });
  const accepted = await plainGet(signedRequest(expired));
  check("and its request is taken, as it was", function () {
    assert.ok(accepted.status === 302 || accepted.status === 303 ||
              accepted.status === 200, String(accepted.status));
  });
  await setRow("pki.paranoidSamlSigner", true);
  const refused = await plainGet(signedRequest(expired));
  check("with the row on, the same signature is refused at /saml2/sso",
        function () {
    assert.ok(refused.status >= 400 && refused.status < 500,
              String(refused.status));
  });
  const metadata = '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:' +
    'metadata" entityID="' + SP + '"><md:SPSSODescriptor protocolSupport' +
    'Enumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:AssertionConsumer' +
    'Service Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location=' +
    '"https://sp.paranoid.example/acs" index="0"/></md:SPSSODescriptor>' +
    '</md:EntityDescriptor>';
  // AN ADMINISTRATOR'S ACT NAMES THE ANCHOR (rcbj). A background fetch cannot
  // be started over HTTP, so that refusal is
  // `tests/saml_metadata_lifecycle.js`'s; what is here is the administrator's
  // side of the same rule, whose third case is what a fetch would also meet.
  const signerOf = async function (cn) {
    log.debug("Entering signerOf().");
    const made = await kit.mint({ cn: cn });
    log.debug("Leaving signerOf().");
    return made.pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  };
  const withKey = function (b64) {
    log.debug("Entering withKey().");
    log.debug("Leaving withKey().");
    return metadata.replace("<md:AssertionConsumerService",
      '<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org' +
      '/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>' + b64 +
      "</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>" +
      "<md:AssertionConsumerService");
  };
  const upload = function (document) {
    log.debug("Entering upload().");
    log.debug("Leaving upload().");
    return send("POST", api() + "/saml2/upload-metadata",
                { sp: ANCHORED_SP, document: document });
  };
  const anchored = await send("POST", api() + "/applications/create", {
    identifier: ANCHORED_SP, name: ANCHORED_SP, protocols: ["saml2"],
    fields: { samlEntityId: ANCHORED_SP } });
  assert.strictEqual(anchored.status, 200, anchored.raw.slice(0, 300));
  const held = await signerOf("paranoid anchored sp");
  const other = await signerOf("paranoid other key");
  const asAnchored = function (key) {
    log.debug("Entering asAnchored().");
    log.debug("Leaving asAnchored().");
    return withKey(key).replace(SP, ANCHORED_SP);
  };
  const first = await upload(asAnchored(held));
  check("an administrator's first unsigned document is consumed, and creates " +
        "the anchor", function () {
    assert.strictEqual(first.status, 200, first.raw.slice(0, 300));
    assert.ok(/trust anchor/.test(first.raw), first.raw.slice(0, 300));
  });
  const reimport = await upload(asAnchored(held));
  check("the same document imported again keeps the anchor and is consumed",
        function () {
    assert.strictEqual(reimport.status, 200, reimport.raw.slice(0, 300));
  });
  const swapped = await upload(asAnchored(other));
  check("a document naming a different key is refused, naming the act that " +
        "replaces the anchor", function () {
    assert.strictEqual(swapped.status, 400, swapped.raw.slice(0, 300));
    assert.ok(/samlSpMetadataSigningCertificate/.test(swapped.raw),
              swapped.raw.slice(0, 300));
  });
  await setRow("pki.paranoidSamlSigner", false);
  const consumed = await send("POST", api() + "/saml2/upload-metadata",
                              { sp: SP, document: metadata });
  check("with the row off a document is consumed, as it was", function () {
    assert.strictEqual(consumed.status, 200, consumed.raw.slice(0, 300));
  });
  await setRow("pki.paranoidSamlSigner", true);
  log.debug("Leaving aSamlSigner().");
}

async function aJoseSigner() {
  log.debug("Entering aJoseSigner().");
  log.info("=== b. a self-signed x5c on a client's key ===");
  // Development mode verifies no client credential outside RFC 9700 mode, so
  // there is no signature to hold a certificate to until it is on.
  const strict = await send("POST", api() + "/config/set",
                            { key: "oauth2.rfc9700", value: true });
  assert.strictEqual(strict.status, 200, strict.raw.slice(0, 300));
  const self = await kit.mint({ cn: "paranoid jwt" });
  const x509 = new nodeCrypto.X509Certificate(self.pem);
  const jwk = Object.assign(x509.publicKey.export({ format: "jwk" }),
    { kid: "k1", x5c: [x509.raw.toString("base64")] });
  const made = await send("POST", api() + "/applications/create", {
    identifier: CLIENT, name: CLIENT, protocols: ["oauth2", "oidc"],
    fields: { oauthClientId: CLIENT,
              oauthTokenEndpointAuthMethod: "private_key_jwt",
              oauthJwks: JSON.stringify({ keys: [jwk] }) } });
  assert.strictEqual(made.status, 200, made.raw.slice(0, 400));
  const url = base + "/realm/" + REALM + "/oauth2/token";
  const ask = async function () {
    log.debug("Entering ask().");
    const now = Math.floor(Date.now() / 1000);
    const encode = function (one) {
      log.debug("Entering encode().");
      log.debug("Leaving encode().");
      return Buffer.from(JSON.stringify(one)).toString("base64url");
    };
    const signing = encode({ alg: "RS256", kid: "k1" }) + "." + encode({
      iss: CLIENT, sub: CLIENT, aud: url, iat: now, exp: now + 120,
      jti: nodeCrypto.randomBytes(8).toString("hex") });
    const jwt = signing + "." + nodeCrypto.sign("sha256", Buffer.from(signing),
                                                self.key).toString("base64url");
    const body = new URLSearchParams({
      grant_type: "client_credentials", client_id: CLIENT,
      client_assertion_type:
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      client_assertion: jwt }).toString();
    const reply = await fetch(url, { method: "POST", body: body,
      headers: { "content-type": "application/x-www-form-urlencoded" } });
    const out = { status: reply.status, raw: await reply.text() };
    log.debug("Leaving ask().");
    return out;
  };
  const refused = await ask();
  check("private_key_jwt under a self-signed x5c is refused", function () {
    assert.ok(refused.status === 400 || refused.status === 401,
              refused.status + " " + refused.raw.slice(0, 300));
    assert.ok(!/STS-[A-Z]+-[0-9]{4}/.test(refused.raw), refused.raw);
  });
  await setRow("pki.paranoidJoseSigner", false);
  const accepted = await ask();
  check("with the row off it is the pin it was", function () {
    assert.strictEqual(accepted.status, 200, accepted.raw.slice(0, 300));
  });
  log.debug("Leaving aJoseSigner().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Paranoid PKI at a signer, " + base);
  const made = await send("POST", "/admin-api/realms/create", {
    id: REALM, domain: REALM + ".example.net", name: REALM });
  assert.strictEqual(made.status, 200, made.raw.slice(0, 300));
  await aSamlSigner();
  await aJoseSigner();
  assert.ok(checks >= 8, "only " + checks + " checks ran; a section has " +
                                          "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_paranoid_pki_signers")
  .description("Paranoid PKI at a signer (#1360).")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().then(function () {
  process.exit(0);
}, function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
