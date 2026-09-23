"use strict";
//
// File: sts_gnap_mtls.js
//
// ---------------------------------------------------------------------------
// GNAP KEYS PROVED BY MUTUAL TLS (RFC 9635 SECTION 7.3.2) AGAINST A RUNNING
// SERVICE: THE PINNED AND PKI TRUST MODELS, REVOCATION IN BOTH, THE BINDING TO
// AN APPLICATION ENTRY, ROTATION AT THE AUTHORITY, THE PER-CLIENT OVERRIDE AND
// THE PRODUCT DEFAULT (#107, 2026-09-23).
//
// Every request here is a grant request whose only proof is the TLS client
// certificate on the connection — the main port asks every connection for
// one and requires none — so the client is plain `https.request` through
// `gnap_client.js`'s `rawRequest()`. Each application is registered first, as
// a TRUSTED client (`gnapSkipInteraction`), so a grant that asks for no
// subject information is answered with a token and no resource owner: a 200
// means the key was proved and bound, and nothing else.
//
//   0. a throwaway realm, its certificate authority, and which mode this is;
//   1. `gnap.mtlsTrust` at `auto`: a pinned self-signed certificate proves its
//      key in development and is refused STS-GNAP-0287 in product;
//   2. `pinned`: the same certificate proves its key in both modes; no
//      certificate is STS-GNAP-0277; another certificate is 0278; a pinned
//      certificate this realm issued and then revoked is STS-PKI-0118;
//   3. `pki`: the self-signed certificate is 0287; a certificate this realm
//      issued to the entry binds by value and its thumbprint is recorded; a
//      second one from the authority binds with no new registration (the
//      rotation of section 11.4) and is recorded; a revoked one is 0118;
//      another entry's certificate under this entry's instance identifier is
//      0291; a foreign authority's certificate binds by the entry's RFC 8705
//      subject, and is 0290 for another subject and 0288 for none;
//   4. `gnapMtlsTrust` on an entry: pki in a pinned realm refuses its
//      self-signed key (0287), and pinned in a pki realm is refused on write
//      (STS-REG-0196).
//
// Every refusal is read as its GNAP error AND as its STS code off the realm's
// `/admin-api/audit` — a code is recorded and never sent.
//
// **NOTHING HERE IS COMMITTED KEY MATERIAL.** The self-signed certificates and
// the foreign authority are made at run time with node-forge, and the foreign
// leaf names a CRL served from this process (`test_crl_host.js`), because a
// product service refuses a foreign certificate nobody could revoke
// (#174). The realm's own certificates come from its Credentials door.
//
// OWNED HERE (local: true): GNAP exists in this repository and nowhere else.
// ---------------------------------------------------------------------------

const assert = require("assert");
const nodeCrypto = require("crypto");
const { Command, Option } = require("commander");
const { usernameFor } = require("./random_username.js");
const gnap = require("./gnap_client.js");
const facts = require("./service_facts.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand run without one still loads.
  appconfigProblem = e;
  appconfig = {};
}
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_gnap_mtls",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug('CONFIG_FILE could not be read, so the configuration is empty: ' +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
var REALM = usernameFor("gnapmtls").replace(/[^a-z0-9-]/g, "").slice(0, 30);
var PASSWORD = "gnap-mtls-Passw0rd!-" + String(Date.now()).slice(-6);

const h = require("./gnap_flow.js").harness({ base: base, realm: REALM,
                                              password: PASSWORD, log: log });
const check = h.check;
const ok = h.ok;
const setting = h.setting;
const GRANT = h.GRANT;
const DEMO = h.DEMO;
const FILE_PASSWORD = "correct horse battery staple";

// ---------------------------------------------------------------------------
// CERTIFICATES MADE HERE.
// ---------------------------------------------------------------------------
function forgePair() {
  log.debug("Entering forgePair().");
  const forge = require("node-forge");
  log.debug("Leaving forgePair().");
  return forge.pki.rsa.generateKeyPair(2048);
}

// A self-signed clientAuth certificate: `{ pem, keyPem }`.
function selfSigned(name) {
  log.debug("Entering selfSigned().");
  const forge = require("node-forge");
  const pair = forgePair();
  const cert = forge.pki.createCertificate();
  cert.publicKey = pair.publicKey;
  cert.serialNumber = "01" + nodeCrypto.randomBytes(8).toString("hex");
  cert.validity.notBefore = new Date(Date.now() - 60000);
  cert.validity.notAfter = new Date(Date.now() + 3600000);
  const subject = [{ name: "commonName", value: name }];
  cert.setSubject(subject);
  cert.setIssuer(subject);
  cert.setExtensions([{ name: "extKeyUsage", clientAuth: true }]);
  cert.sign(pair.privateKey, forge.md.sha256.create());
  log.debug("Leaving selfSigned().");
  return { pem: forge.pki.certificateToPem(cert),
           keyPem: forge.pki.privateKeyToPem(pair.privateKey) };
}

// A foreign authority and a leaf with a dNSName, the leaf naming a CRL this
// process serves: `{ caPem, pem, keyPem }`.
async function foreignChain(dnsName) {
  log.debug("Entering foreignChain().");
  const forge = require("node-forge");
  const list = await require("./test_crl_host.js").reserve("gnap-mtls-ca");
  const caPair = forgePair();
  const ca = forge.pki.createCertificate();
  ca.publicKey = caPair.publicKey;
  ca.serialNumber = "01" + nodeCrypto.randomBytes(8).toString("hex");
  ca.validity.notBefore = new Date(Date.now() - 60000);
  ca.validity.notAfter = new Date(Date.now() + 3600000);
  const caName = [{ name: "commonName",
                    value: "GNAP mTLS test CA " + REALM }];
  ca.setSubject(caName);
  ca.setIssuer(caName);
  ca.setExtensions([{ name: "basicConstraints", cA: true },
                    { name: "keyUsage", keyCertSign: true, cRLSign: true }]);
  ca.sign(caPair.privateKey, forge.md.sha256.create());
  const pair = forgePair();
  const leaf = forge.pki.createCertificate();
  leaf.publicKey = pair.publicKey;
  leaf.serialNumber = "02" + nodeCrypto.randomBytes(8).toString("hex");
  leaf.validity.notBefore = new Date(Date.now() - 60000);
  leaf.validity.notAfter = new Date(Date.now() + 3600000);
  leaf.setSubject([{ name: "commonName", value: "gnap-mtls-external" }]);
  leaf.setIssuer(caName);
  leaf.setExtensions([{ name: "basicConstraints", cA: false },
                      { name: "extKeyUsage", clientAuth: true },
                      { name: "subjectAltName",
                        altNames: [{ type: 2, value: dnsName }] },
                      { name: "cRLDistributionPoints",
                        altNames: [{ type: 6, value: list.url }] }]);
  leaf.sign(caPair.privateKey, forge.md.sha256.create());
  const caPem = forge.pki.certificateToPem(ca);
  await list.publish({ pem: caPem,
                       privateKeyPem: forge.pki.privateKeyToPem(
                           caPair.privateKey) });
  log.debug("Leaving foreignChain().");
  return { caPem: caPem, pem: forge.pki.certificateToPem(leaf),
           keyPem: forge.pki.privateKeyToPem(pair.privateKey) };
}

function certKey(pem) {
  log.debug("Entering certKey().");
  log.debug("Leaving certKey().");
  return { proof: "mtls",
           cert: new nodeCrypto.X509Certificate(pem).raw.toString("base64") };
}

function identityOf(pem) {
  log.debug("Entering identityOf().");
  log.debug("Leaving identityOf().");
  return "x5t:" + nodeCrypto.createHash("sha256")
    .update(new nodeCrypto.X509Certificate(pem).raw).digest("base64url");
}

// ---------------------------------------------------------------------------
// REQUESTS.
// ---------------------------------------------------------------------------
async function grant(client, tls) {
  log.debug("Entering grant().");
  const body = Buffer.from(JSON.stringify({
    access_token: { access: [{ type: DEMO, actions: ["read"] }] },
    client: client }));
  const r = await gnap.rawRequest("POST", GRANT,
    { "Content-Type": "application/json",
      "Content-Length": String(body.length) }, body,
    tls ? { cert: tls.cert, key: tls.key, rejectUnauthorized: false }
        : { rejectUnauthorized: false });
  log.debug("Leaving grant().");
  return r;
}

async function codeCount(code) {
  log.debug("Entering codeCount().");
  await new Promise(function (r) { setTimeout(r, 150); });
  const r = await h.apiGet(h.realmApi + "/audit?per=500&code=" +
                           encodeURIComponent(code));
  const body = r.body && typeof r.body === "object" ? r.body : {};
  const rows = body.rows || body.events || [];
  log.debug("Leaving codeCount().");
  return rows.length;
}

// A refusal, as invalid_client (RFC 9635 section 3.6) and as `code` on a new
// audit row of this realm.
async function refusedAs(code, what, fn) {
  log.debug("Entering refusedAs().");
  const before = await codeCount(code);
  const r = await fn();
  let after = before;
  for (let i = 0; i < 10 && after <= before; i += 1) {
    after = await codeCount(code);
  }
  check(what + " — invalid_client, " + code, function () {
    h.refused(r, "invalid_client", what);
    assert.strictEqual(r.status, 401, r.text);
    assert.ok(after > before, "no new audit row carries " + code + ": " +
              before + " before, " + after + " after; the response was " +
              r.status + " " + String(r.text).slice(0, 300));
  });
  log.debug("Leaving refusedAs().");
  return r;
}

function issued(r, what) {
  log.debug("Entering issued().");
  check(what, function () {
    assert.strictEqual(r.status, 200, r.text);
    assert.ok(r.json && r.json.access_token, r.text);
  });
  log.debug("Leaving issued().");
}

async function register(identifier, fields) {
  log.debug("Entering register().");
  await ok(h.realmApi + "/applications/create", {
    identifier: identifier, kind: "gnap-client", protocols: ["gnap"],
    fields: Object.assign({ gnapSkipInteraction: "TRUE" }, fields || {}) },
           "registered " + identifier);
  log.debug("Leaving register().");
}

// A TLS client certificate from this realm's authority, through the
// application's Credentials door: `{ tls, pem, serialHex }`.
async function issueTo(identifier, label) {
  log.debug("Entering issueTo().");
  const body = await ok(h.realmApi + "/applications/issue-tls-client-" +
                        "certificate",
                        { application: identifier, password: FILE_PASSWORD,
                          keyAlg: "ec-p256", label: label },
                        "issued " + identifier + " a TLS client certificate");
  const key = nodeCrypto.createPrivateKey({ key: body.files.key.text,
                                            format: "pem",
                                            passphrase: FILE_PASSWORD })
    .export({ type: "pkcs8", format: "pem" });
  log.debug("Leaving issueTo().");
  return { tls: { cert: body.files.chain.text, key: key },
           pem: body.certificate.certificatePem,
           serialHex: body.certificate.serialHex };
}

async function revoke(identifier, serialHex) {
  log.debug("Entering revoke().");
  await ok(h.realmApi + "/applications/revoke-tls-client-certificate",
           { application: identifier, serialHex: serialHex,
             reason: "keyCompromise" },
           "revoked " + identifier + "'s certificate " + serialHex);
  log.debug("Leaving revoke().");
}

async function recordedIdentity(identifier) {
  log.debug("Entering recordedIdentity().");
  const r = await h.apiGet(h.realmApi + "/applications?application=" +
                           encodeURIComponent(identifier));
  const view = (r.body && (r.body.application || r.body)) || {};
  const value = (view.fields || {}).gnapKeyIdentity;
  log.debug("Leaving recordedIdentity().");
  return Array.isArray(value) ? value[0] : (value || "");
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving GNAP mutual TLS at " + GRANT);

  // =========================================================================
  // 0. A REALM, ITS AUTHORITY, AND WHICH MODE THIS IS.
  // =========================================================================
  log.info("=== 0. the realm ===");
  await h.createRealm("GNAP mutual TLS");
  await ok(h.realmApi + "/pki/build", { organisation: "Gnapmtls",
                                        country: "US" },
           "built the realm's certificate authority");
  const product = await facts.isProduct(h.api);
  log.info("This service is in " + (product ? "product" : "development") +
           " mode.");
  const self = selfSigned("gnap-mtls-self-" + REALM);
  const other = selfSigned("gnap-mtls-other-" + REALM);
  const selfTls = { cert: self.pem, key: self.keyPem };
  const otherTls = { cert: other.pem, key: other.keyPem };
  await register("pin-self", { gnapKey: JSON.stringify(certKey(self.pem)) });

  // =========================================================================
  // 1. THE DEFAULT: auto.
  // =========================================================================
  log.info("=== 1. gnap.mtlsTrust=auto ===");
  if (product) {
    await refusedAs("STS-GNAP-0287", "product mode holds GNAP mutual TLS to " +
                    "a PKI by default: a pinned self-signed certificate",
                    function () {
                      return grant({ key: certKey(self.pem) }, selfTls);
                    });
  } else {
    issued(await grant({ key: certKey(self.pem) }, selfTls),
           "development pins by default: a registered self-signed " +
           "certificate proves its key");
  }

  // =========================================================================
  // 2. PINNED.
  // =========================================================================
  log.info("=== 2. gnap.mtlsTrust=pinned ===");
  await setting("gnap.mtlsTrust", "pinned");
  issued(await grant({ key: certKey(self.pem) }, selfTls),
         "pinned: the registered self-signed certificate proves its key " +
         "(RFC 9635 section 7.3.2)");
  await refusedAs("STS-GNAP-0277", "an mtls key on a connection with no " +
                  "client certificate", function () {
                    return grant({ key: certKey(self.pem) }, null);
                  });
  await refusedAs("STS-GNAP-0278", "an mtls key on a connection made with " +
                  "another certificate", function () {
                    return grant({ key: certKey(self.pem) }, otherTls);
                  });
  await register("pin-revoked");
  const pinned = await issueTo("pin-revoked", "pinned");
  await ok(h.realmApi + "/applications/set",
           { application: "pin-revoked", attribute: "gnapKey",
             value: JSON.stringify(certKey(pinned.pem)) },
           "pinned the realm-issued certificate on the entry");
  issued(await grant({ key: certKey(pinned.pem) }, pinned.tls),
         "pinned: a certificate this realm issued, pinned on the entry");
  await revoke("pin-revoked", pinned.serialHex);
  await refusedAs("STS-PKI-0118", "pinned: the same certificate after it " +
                  "was revoked (revocation is consulted in both models)",
                  function () {
                    return grant({ key: certKey(pinned.pem) }, pinned.tls);
                  });

  // =========================================================================
  // 3. PKI.
  // =========================================================================
  log.info("=== 3. gnap.mtlsTrust=pki ===");
  await setting("gnap.mtlsTrust", "pki");
  await refusedAs("STS-GNAP-0287", "pki: the pinned self-signed certificate",
                  function () {
                    return grant({ key: certKey(self.pem) }, selfTls);
                  });
  await register("pki-issued");
  const first = await issueTo("pki-issued", "first");
  issued(await grant({ key: certKey(first.pem) }, first.tls),
         "pki: a certificate this realm issued to the entry binds by value " +
         "with nothing pinned");
  let recorded = await recordedIdentity("pki-issued");
  check("…and its thumbprint is recorded on the entry", function () {
    assert.strictEqual(recorded, identityOf(first.pem));
  });
  const second = await issueTo("pki-issued", "second");
  issued(await grant({ key: certKey(second.pem) }, second.tls),
         "rotation at the authority: a second certificate binds with no new " +
         "registration (RFC 9635 section 11.4)");
  recorded = await recordedIdentity("pki-issued");
  check("…and the new thumbprint is recorded", function () {
    assert.strictEqual(recorded, identityOf(second.pem));
  });
  await revoke("pki-issued", first.serialHex);
  await refusedAs("STS-PKI-0118", "pki: the first certificate after it was " +
                  "revoked", function () {
                    return grant({ key: certKey(first.pem) }, first.tls);
                  });
  issued(await grant({ key: certKey(second.pem) }, second.tls),
         "…while the second still binds");
  await register("pki-instance", { gnapInstanceId: "inst-" + REALM });
  const own = await issueTo("pki-instance", "own");
  await ok(h.realmApi + "/applications/set",
           { application: "pki-instance", attribute: "gnapKey",
             value: JSON.stringify(certKey(own.pem)) },
           "pinned the instance's own certificate");
  issued(await grant("inst-" + REALM, own.tls),
         "pki: an instance identifier with its own certificate");
  await refusedAs("STS-GNAP-0291", "pki: another entry's certificate under " +
                  "this instance identifier (unbound)", function () {
                    return grant("inst-" + REALM, second.tls);
                  });

  // A FOREIGN AUTHORITY, installed as a client trust anchor. The truststore
  // is applied to the NEXT handshake, so the first request is retried until
  // the chain verifies rather than the anchor being assumed live.
  const dns = "gnap-" + REALM + ".example.net";
  const foreign = await foreignChain(dns);
  // Through the GATED door, the only one a product service opens, with the
  // management API token the job's preload attaches to every /admin-api call.
  await ok(h.api + "/tls/trust/add", { certificates: foreign.caPem },
           "installed the foreign authority as a client trust anchor");
  const foreignTls = { cert: foreign.pem + foreign.caPem,
                       key: foreign.keyPem };
  await register("pki-foreign", { oauthTlsClientAuthSanDns: dns });
  let r = null;
  for (let attempt = 0; attempt < 8; attempt += 1) {
    r = await grant({ key: certKey(foreign.pem) }, foreignTls);
    if (r.status === 200) {
      break;
    }
    await new Promise(function (done) { setTimeout(done, 250); });
  }
  issued(r, "pki: a foreign authority's certificate binds by the entry's " +
         "RFC 8705 subject (oauthTlsClientAuthSanDns), found by it");
  recorded = await recordedIdentity("pki-foreign");
  check("…and its thumbprint is recorded", function () {
    assert.strictEqual(recorded, identityOf(foreign.pem));
  });
  await register("pki-wrong", { gnapInstanceId: "wrong-" + REALM,
    gnapKey: JSON.stringify(certKey(foreign.pem)),
    oauthTlsClientAuthSanDns: "other-" + dns });
  await refusedAs("STS-GNAP-0290", "pki: a certificate that does not carry " +
                  "the subject the entry registers (unbound)", function () {
                    return grant("wrong-" + REALM, foreignTls);
                  });
  await register("pki-none", { gnapInstanceId: "none-" + REALM,
    gnapKey: JSON.stringify(certKey(foreign.pem)) });
  await refusedAs("STS-GNAP-0288", "pki: a foreign certificate for an entry " +
                  "that registers no subject", function () {
                    return grant("none-" + REALM, foreignTls);
                  });

  // =========================================================================
  // 4. THE PER-CLIENT OVERRIDE: STRICTER, NEVER WEAKER.
  // =========================================================================
  log.info("=== 4. gnapMtlsTrust ===");
  await setting("gnap.mtlsTrust", "pinned");
  await register("strict", { gnapInstanceId: "strict-" + REALM,
    gnapKey: JSON.stringify(certKey(other.pem)), gnapMtlsTrust: "pki" });
  issued(await grant({ key: certKey(self.pem) }, selfTls),
         "the realm pins: an entry that asked for nothing proves its " +
         "self-signed key");
  await refusedAs("STS-GNAP-0287", "an entry holding itself to pki in a " +
                  "pinned realm (stricter)", function () {
                    return grant("strict-" + REALM, otherTls);
                  });
  await setting("gnap.mtlsTrust", "pki");
  const before = await codeCount("STS-REG-0196");
  const weaker = await h.apiPost(h.realmApi + "/applications/set",
                                 { application: "pin-self",
                                   attribute: "gnapMtlsTrust",
                                   value: "pinned" });
  let after = before;
  for (let i = 0; i < 10 && after <= before; i += 1) {
    after = await codeCount("STS-REG-0196");
  }
  check("an entry may not pin itself in a pki realm (weaker): refused on " +
        "write, STS-REG-0196", function () {
    assert.strictEqual(weaker.status, 400, weaker.raw);
    assert.ok(after > before, "no audit row carries STS-REG-0196");
  });

  await setting("gnap.mtlsTrust", "auto");
  assert.ok(h.checks >= 22, "only " + h.checks + " checks ran; a section " +
                                                 "has stopped being called.");
  log.info(h.checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_gnap_mtls")
  .description("GNAP keys proved by mutual TLS (RFC 9635 sections 7.3.2 and " +
    "11.4): the pinned and PKI trust models, revocation in both, the binding " +
    "to an application entry by issuance or RFC 8705 subject, rotation at " +
    "the authority, the per-client override and the product default.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
