"use strict";
//
// File: sts_scep_enrollment.js
//
// ===========================================================================
// SCEP (RFC 8894) AGAINST THE RUNNING SERVICE, WITH A CLIENT OF ITS OWN
// (2026-09-13).
//
// Every certificate here is obtained the way a device obtains one: GetCACaps,
// GetCACert, and a PKIOperation carrying a CMS SignedData signed by the device
// and a CMS EnvelopedData encrypted to the RA — built by `scep_client.js`,
// which shares no code with `scep/` or `common/cert_enrollment.ts`. A CertRep
// is read back, its RA signature verified, its envelope opened with the
// device's key, and the certificate inside it checked with node's own X509
// verifier up to the realm Intermediate and the service Root.
//
// WHAT IT HOLDS:
//
//   * the four operations and their HTTP refusals (400, 405, 413, 415, 501,
//     503) — the cases too malformed to be answered with a CertRep;
//   * the nine profiles issued over SCEP, each authorized by a challenge
//     password made through `/admin-api/scep/create-challenge` — an
//     ADMINISTRATOR'S act, so every one is also "an administrator issuing for
//     somebody"; one for a second person and one for an application for itself;
//   * GET and POST PKIOperation; a retried PKCSReq answered from the stored
//     transaction without spending its challenge again; CertPoll, GetCert and
//     GetCRL; RenewalReq signed by an earlier SCEP certificate, superseding it;
//   * OCSP `good` for an issued certificate, a revocation through
//     `/admin-api/scep/revoke-certificate`, and the serial on the SCEP Issuing
//     CA's CRL with OCSP answering `revoked`;
//   * every refusal as a CertRep FAILURE with its failInfo — and the STS code
//     read from `/admin-api/scep/monitor`, never from the reply, which is the
//     rule the codes are for;
//   * a second trust realm in PRODUCT mode: a challenge and a certificate from
//     the first refused there, and an ordinary enrollment accepted, because
//     SCEP is message-secured and is not refused over any transport.
//
// `local: true` because SCEP exists in this repository and nowhere else, so
// there is no copy anywhere to sync from. Both realms are left standing.
//
// **NO ADMINISTRATOR IS ADDED TO THE DEFAULT REALM'S ROSTER**, although the
// EST job adds one: a SCEP principal is the entry the challenge names, never
// the person redeeming it, so there is nothing an administrator does over SCEP
// that `/admin-api` did not already do by making the challenge — and a member
// put in `admin-write` is a change to the roster every later job shares.
// ===========================================================================

const assert = require("assert");
const nodeCrypto = require("crypto");
const path = require("path");
const { Command, Option } = require("commander");
const { usernameFor } = require("./random_username.js");
const client = require("./scep_client.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, for the reason tests/vendored/wait_for.js gives.
  appconfigProblem = e;
  appconfig = {};
}

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_scep_enrollment",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

// The parent project's independent PKI code, for the EC and ML-KEM keys forge
// cannot make, and pkijs for the CRL and OCSP messages.
const REPO = process.env.MOCK_STS_DIR || path.join(__dirname, "..", "..");
const x509 = require(path.join(REPO, "common", "vendored", "x509.js"));
const keys = require(path.join(REPO, "common", "vendored",
                               "key_material.js"));
const pkijs = require(path.join(REPO, "node_modules", "pkijs"));

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");
var rootApi = base + "/admin-api";

function realmName(prefix) {
  log.debug("Entering realmName().");
  log.debug("Leaving realmName().");
  return usernameFor(prefix).toLowerCase().replace(/[^a-z0-9-]/g, "")
    .slice(0, 30).replace(/-+$/, "");
}

var REALM = realmName("scepa");
var REALM_B = realmName("scepb");
var realmBase = base + "/realm/" + REALM;
var realmApi = realmBase + "/admin-api";
var SCEP = realmBase + "/enroll/scep";
var realmBBase = base + "/realm/" + REALM_B;
var realmBApi = realmBBase + "/admin-api";
var SCEP_B = realmBBase + "/enroll/scep";

var ALICE = usernameFor("scepalice");
var BOB = usernameFor("scepbob");
var CAROL = usernameFor("scepcarol");
var APP = "scep-app-" + nodeCrypto.randomBytes(3).toString("hex");
var HOST = "device." + REALM + ".example";

var PROFILES = ["tls-server", "tls-client", "tls-server-client",
                "digital-signature", "key-encipherment", "code-signing",
                "email", "timestamping", "smartcard-logon"];
var REFUSED = ["root-ca", "intermediate-ca", "issuing-ca", "ocsp-responder",
               "kdc"];
var EKU = {
  "tls-server": ["1.3.6.1.5.5.7.3.1"],
  "tls-client": ["1.3.6.1.5.5.7.3.2"],
  "tls-server-client": ["1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"],
  "code-signing": ["1.3.6.1.5.5.7.3.3"],
  "email": ["1.3.6.1.5.5.7.3.4"],
  "timestamping": ["1.3.6.1.5.5.7.3.8"],
  "smartcard-logon": ["1.3.6.1.4.1.311.20.2.2"]
};

var checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  ✓ " + what);
  log.debug("Leaving check().");
}

async function send(url, options) {
  log.debug("Entering send().");
  const r = await fetch(url, options);
  const raw = await r.text();
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in send(): " + ((e && e.message) || e));
    // Not JSON — quoting the page whole says more than a parse failure.
    parsed = raw;
  }
  log.debug("Leaving send().");
  return { status: r.status, body: parsed, raw: raw, headers: r.headers };
}

async function post(url, body) {
  log.debug("Entering post().");
  const r = await send(url, { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}) });
  log.debug("Leaving post().");
  return r;
}

async function ok(url, body, what) {
  log.debug("Entering ok().");
  const r = await post(url, body);
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "POST " + url + " should have " + what + "; it answered " + r.status +
    " " + JSON.stringify((r.body && (r.body.errors || r.body.why)) || r.body)
      .slice(0, 500));
  log.debug("Leaving ok().");
  return r.body;
}

async function setting(api, key, value) {
  log.debug("Entering setting(). " + key);
  await ok(api + "/config/set", { key: key, value: String(value) },
           "set " + key);
  log.debug("Leaving setting().");
}

// tests/CLAUDE.md: a setting is put back with `reset`, never by writing the
// old value.
async function reset(api, key) {
  log.debug("Entering reset(). " + key);
  await ok(api + "/config/reset", { key: key }, "reset " + key);
  log.debug("Leaving reset().");
}

async function challengeFor(api, kind, identifier, profile, lifetimeS) {
  log.debug("Entering challengeFor().");
  const body = { kind: kind, identifier: identifier, profile: profile };
  if (lifetimeS) {
    body.lifetimeS = lifetimeS;
  }
  const made = await ok(api + "/scep/create-challenge", body,
                        "created a " + profile + " challenge for " +
                        identifier);
  log.debug("Leaving challengeFor().");
  return made;
}

async function lastMonitorRow(api) {
  log.debug("Entering lastMonitorRow().");
  const r = await send(api + "/scep/monitor?per=5");
  assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
  log.debug("Leaving lastMonitorRow().");
  return (r.body.recent || [])[0] || {};
}

// ---------------------------------------------------------------------------
// ONE PKIOperation.
// ---------------------------------------------------------------------------
function device(commonName) {
  log.debug("Entering device().");
  const key = client.rsaKey(2048);
  log.debug("Leaving device().");
  return { key: key, certPem: client.selfSigned(key, commonName) };
}

async function operate(spec) {
  log.debug("Entering operate().");
  const nonce = spec.nonce || nodeCrypto.randomBytes(16);
  const txid = spec.txid || ("tx-" + nodeCrypto.randomBytes(8).toString("hex"));
  const env = spec.envelope ||
              client.envelope(spec.inner, spec.ra, spec.cipher);
  let msg = client.signedMessage({
    content: env, signerCertPem: spec.signerPem,
    signerKeyPem: spec.signerKeyPem, messageType: spec.messageType || "19",
    transactionID: txid, senderNonce: nonce, digest: spec.digest });
  if (spec.mutate) {
    msg = spec.mutate(msg);
  }
  const r = await client.pkiOperation(spec.url, msg, { get: spec.get });
  let rep = null;
  if (r.status === 200 && /x-pki-message/.test(r.type)) {
    rep = client.readCertRep(r.body, spec.ra);
  }
  log.debug("Leaving operate(). " + r.status);
  return { r: r, rep: rep, nonce: nonce, txid: txid };
}

function assertEchoes(done) {
  log.debug("Entering assertEchoes().");
  assert.strictEqual(done.r.status, 200,
    "a PKIOperation should be answered 200 with a CertRep; it was " +
    done.r.status + " " + done.r.body.toString("utf8").slice(0, 300));
  assert.ok(done.rep, "the reply is not application/x-pki-message");
  assert.strictEqual(done.rep.signatureVerifies, true,
                     "the CertRep's signature does not verify with the RA");
  assert.strictEqual(done.rep.digestMatches, true,
                     "the CertRep's messageDigest is not its content's");
  assert.strictEqual(done.rep.messageType, "3");
  assert.strictEqual(done.rep.transactionID, done.txid);
  assert.ok(Buffer.from(done.rep.recipientNonce).equals(done.nonce),
            "recipientNonce is not the request's senderNonce");
  assert.strictEqual(Buffer.from(done.rep.senderNonce).length, 16);
  log.debug("Leaving assertEchoes().");
}

async function expectFailure(what, done, failInfoName, code, api) {
  log.debug("Entering expectFailure().");
  assertEchoes(done);
  const row = await lastMonitorRow(api || realmApi);
  check(what + " — FAILURE " + failInfoName + " (" + code + " recorded)",
        function () {
          assert.strictEqual(done.rep.pkiStatus, "2",
            "expected FAILURE, got pkiStatus " + done.rep.pkiStatus +
            " (monitor: " + JSON.stringify(row) + ")");
          assert.strictEqual(done.rep.failInfoName, failInfoName,
            "failInfo " + done.rep.failInfoName + "; monitor " +
            JSON.stringify(row));
          assert.strictEqual(done.rep.content, null,
                             "a FAILURE carries no content");
          assert.strictEqual(row.errorCode, code,
                             "the monitor recorded " + JSON.stringify(row));
          assert.ok(done.r.body.toString("binary").indexOf(code) < 0,
                    "the STS code is in the CertRep");
        });
  log.debug("Leaving expectFailure().");
}

// A SUCCESS reply, opened: the certificate(s) or CRLs inside.
function successOf(done, dev) {
  log.debug("Entering successOf().");
  assertEchoes(done);
  assert.strictEqual(done.rep.pkiStatus, "0",
    "expected SUCCESS, got pkiStatus " + done.rep.pkiStatus + " failInfo " +
    done.rep.failInfoName);
  const opened = client.openReply(done.rep.content, dev.key, dev.certPem);
  const inner = client.certsOnly(opened.inner);
  log.debug("Leaving successOf().");
  return { certificates: inner.certificates, crls: inner.crls,
           cipher: opened.cipher };
}

function verifiesTo(leafPem, chain) {
  log.debug("Entering verifiesTo().");
  const leaf = new nodeCrypto.X509Certificate(leafPem);
  const issuing = new nodeCrypto.X509Certificate(chain.issuing);
  const intermediate = new nodeCrypto.X509Certificate(chain.intermediate);
  const root = new nodeCrypto.X509Certificate(chain.root);
  log.debug("Leaving verifiesTo().");
  return leaf.checkIssued(issuing) && leaf.verify(issuing.publicKey) &&
         issuing.verify(intermediate.publicKey) &&
         intermediate.verify(root.publicKey) && root.verify(root.publicKey);
}

async function caChain(url) {
  log.debug("Entering caChain().");
  const got = await client.getCaCert(url);
  assert.strictEqual(got.status, 200, got.body.toString().slice(0, 300));
  const cas = got.certificates.filter(function (pem) {
    return new nodeCrypto.X509Certificate(pem).ca;
  });
  log.debug("Leaving caChain().");
  return { ra: got.ra, issuing: cas[0], intermediate: cas[1], root: cas[2],
           all: got.certificates, type: got.type };
}

// ---------------------------------------------------------------------------
// OCSP AND CRL, with pkijs.
// ---------------------------------------------------------------------------
async function ocspStatus(realm, leafPem, issuingPem) {
  log.debug("Entering ocspStatus().");
  const leaf = pkijs.Certificate.fromBER(client.pemBody(leafPem));
  const issuer = pkijs.Certificate.fromBER(client.pemBody(issuingPem));
  const request = new pkijs.OCSPRequest();
  await request.createForCertificate(leaf, { hashAlgorithm: "SHA-1",
                                             issuerCertificate: issuer });
  const der = Buffer.from(request.toSchema(true).toBER(false));
  const r = await fetch(base + "/realm/" + realm + "/pki/ocsp/" + realm +
                        "/scep", { method: "POST",
    headers: { "Content-Type": "application/ocsp-request" }, body: der });
  const body = Buffer.from(await r.arrayBuffer());
  const response = pkijs.OCSPResponse.fromBER(body);
  const basic = pkijs.BasicOCSPResponse.fromBER(
    response.responseBytes.response.valueBlock.valueHexView);
  const status = basic.tbsResponseData.responses[0].certStatus;
  log.debug("Leaving ocspStatus().");
  return ["good", "revoked", "unknown"][status.idBlock.tagNumber];
}

function crlSerials(der) {
  log.debug("Entering crlSerials().");
  const crl = pkijs.CertificateRevocationList.fromBER(der);
  log.debug("Leaving crlSerials().");
  return (crl.revokedCertificates || []).map(function (one) {
    return Buffer.from(one.userCertificate.valueBlock.valueHexView)
      .toString("hex").replace(/^0+/, "");
  });
}

function serialOf(pem) {
  log.debug("Entering serialOf().");
  log.debug("Leaving serialOf().");
  return new nodeCrypto.X509Certificate(pem).serialNumber.toLowerCase()
    .replace(/^0+/, "");
}

// A CSR whose SubjectPublicKeyInfo is swapped for an ML-KEM key, which no
// library will sign: forge.asn1 on the request forge made.
async function kemCsr(challenge) {
  log.debug("Entering kemCsr().");
  const forge = require("node-forge");
  const kem = await keys.generateKeyPair("ml-kem-768");
  const good = client.csr(client.rsaKey(2048), { challenge: challenge });
  const tree = forge.asn1.fromDer(good.toString("binary"));
  tree.value[0].value[2] = forge.asn1.fromDer(
    client.pemBody(kem.publicPem).toString("binary"));
  log.debug("Leaving kemCsr().");
  return Buffer.from(forge.asn1.toDer(tree).getBytes(), "binary");
}

// ---------------------------------------------------------------------------
async function test() {
  log.debug("Entering test().");
  log.info("Driving " + base + " in the trust realms \"" + REALM + "\" and \"" +
           REALM_B + "\".");

  // -------------------------------------------------------------------------
  log.info("=== 0. two realms, two certificate authorities, people ===");
  await ok(rootApi + "/realms/create", { id: REALM,
                                         domain: REALM + ".example.net",
                                         name: "SCEP A" },
           "created realm A");
  await ok(rootApi + "/realms/create", { id: REALM_B,
                                         domain: REALM_B + ".example.net",
                                         name: "SCEP B" },
           "created realm B");
  await ok(rootApi + "/realms/set", { id: REALM_B, key: "global.mode",
                                      value: "product" },
           "put realm B in product mode");
  await ok(realmApi + "/pki/build", { organisation: "SCEP A", country: "US" },
           "built realm A's certificate authority");
  await ok(realmBApi + "/pki/build", { organisation: "SCEP B" },
           "built realm B's certificate authority");
  // One address drives every refusal below, and the address bucket is shared
  // by every realm; it is raised for this job and put back at the end.
  await setting(realmApi, "scep.attemptsPerAddress", 100000);
  await setting(realmBApi, "scep.attemptsPerAddress", 100000);
  for (const person of [ALICE, BOB]) {
    await ok(realmApi + "/users/create",
             { username: person, invent: false, credential: "none",
               attributes: { cn: person, sn: person,
                             mail: person + "@scep.example" } },
             "created " + person);
  }
  await ok(realmBApi + "/users/create",
           { username: CAROL, invent: false, credential: "none",
             attributes: { cn: CAROL, sn: CAROL,
                           mail: CAROL + "@scep.example" } },
           "created " + CAROL + " in realm B");
  await ok(realmApi + "/applications/create",
           { identifier: APP, protocols: ["oauth2"],
             fields: { oauthClientId: APP } }, "created the application");
  await ok(realmApi + "/scep/add-host-name",
           { kind: "person", identifier: ALICE, hostName: HOST },
           "registered a host name on " + ALICE);

  // -------------------------------------------------------------------------
  log.info("=== 1. GetCACaps, GetCACert and the HTTP refusals ===");
  const caps = await client.getCaCaps(SCEP);
  check("GetCACaps answers text/plain, one capability per line, and does not " +
        "advertise GetNextCACert", function () {
          assert.strictEqual(caps.status, 200);
          assert.ok(/^text\/plain/.test(caps.type), caps.type);
          ["POSTPKIOperation", "SHA-256", "SHA-512", "AES", "SCEPStandard",
           "Renewal"].forEach(function (one) {
            assert.ok(caps.lines.indexOf(one) >= 0, one + " missing");
          });
          assert.ok(caps.lines.indexOf("GetNextCACert") < 0);
        });
  const chain = await caChain(SCEP);
  const rootDer = Buffer.from(await (await fetch(
    realmBase + "/pki/ca/service/root.cer")).arrayBuffer());
  check("GetCACert is application/x-x509-ca-ra-cert holding the RA, the SCEP " +
        "Issuing CA, the realm Intermediate and the service Root", function () {
          assert.ok(/x-x509-ca-ra-cert/.test(chain.type), chain.type);
          assert.strictEqual(chain.all.length, 4);
          assert.ok(chain.ra, "no RA certificate");
          const ra = new nodeCrypto.X509Certificate(chain.ra);
          assert.strictEqual(ra.publicKey.asymmetricKeyType, "rsa");
          assert.ok(ra.verify(new nodeCrypto.X509Certificate(chain.issuing)
            .publicKey), "the RA is not a leaf of the SCEP Issuing CA");
          assert.ok(/SCEP/.test(new nodeCrypto.X509Certificate(chain.issuing)
            .subject));
          assert.ok(new nodeCrypto.X509Certificate(chain.root).raw
            .equals(rootDer), "the Root is not /pki/ca/service/root");
        });
  const chainB = await caChain(SCEP_B);
  check("realm B has an RA and an Issuing CA of its own", function () {
    assert.notStrictEqual(chainB.ra, chain.ra);
    assert.notStrictEqual(chainB.issuing, chain.issuing);
  });
  const next = await client.http(SCEP + "?operation=GetNextCACert");
  const unknown = await client.http(SCEP + "?operation=GetCRL");
  const noOp = await client.http(SCEP);
  const postCaps = await client.http(SCEP + "?operation=GetCACaps",
                                     { method: "POST" });
  const badSegment = await client.http(SCEP + "/Not_A_Profile" +
                                       "?operation=GetCACaps");
  const cgi = await client.getCaCaps(SCEP + "/pkiclient.exe");
  const profileCgi = await client.getCaCaps(SCEP + "/tls-client/pkiclient.exe");
  check("GetNextCACert is 501, an unknown or missing operation 400, a POST " +
        "of GetCACaps 405, a malformed profile segment 400; pkiclient.exe " +
        "answers at both paths", function () {
          assert.strictEqual(next.status, 501);
          assert.strictEqual(unknown.status, 400);
          assert.strictEqual(noOp.status, 400);
          assert.strictEqual(postCaps.status, 405);
          assert.strictEqual(badSegment.status, 400);
          assert.strictEqual(cgi.status, 200);
          assert.strictEqual(profileCgi.status, 200);
        });
  const wrongType = await client.pkiOperation(SCEP, Buffer.from("x"),
                                              { contentType: "text/plain" });
  const garbage = await client.pkiOperation(SCEP,
                                            Buffer.from("not a CMS message"));
  const garbageRow = await lastMonitorRow(realmApi);
  const oversize = await client.pkiOperation(SCEP, Buffer.alloc(262145, 0x30));
  const badBase64 = await client.pkiOperation(SCEP, null,
                                              { get: true,
                                                rawMessage: "not base64!" });
  const noMessage = await client.http(SCEP + "?operation=PKIOperation");
  check("PKIOperation: a wrong content type is 415, malformed DER 400 " +
        "(STS-SCEP-0010), an oversize body 413, malformed base64 and a " +
        "missing message 400", function () {
          assert.strictEqual(wrongType.status, 415);
          assert.strictEqual(garbage.status, 400);
          assert.strictEqual(garbageRow.errorCode, "STS-SCEP-0010");
          assert.strictEqual(oversize.status, 413);
          assert.strictEqual(badBase64.status, 400);
          assert.strictEqual(noMessage.status, 400);
        });

  // -------------------------------------------------------------------------
  log.info("=== 2. the nine profiles, each with its own challenge ===");
  const monitorBefore = (await send(realmApi + "/scep/monitor")).body;
  const issued = {};
  for (const profile of PROFILES) {
    const made = await challengeFor(realmApi, "person", ALICE, profile);
    const dev = device(ALICE);
    const sans = profile.indexOf("tls-server") === 0
      ? [{ type: "dns", value: HOST }] : [];
    const done = await operate({
      url: SCEP + (profile === "code-signing" ? "/code-signing" : ""),
      ra: chain.ra, signerPem: dev.certPem, signerKeyPem: dev.key.privateKeyPem,
      inner: client.csr(dev.key, { commonName: ALICE, challenge: made.challenge,
                                   sans: sans }),
      get: profile === "timestamping",
      cipher: profile === "digital-signature" ? "aes128" : "aes256",
      digest: profile === "email" ? "sha512" : "sha256"
    });
    const got = successOf(done, dev);
    const cert = got.certificates[0];
    const x = new nodeCrypto.X509Certificate(cert);
    check(profile + ": SUCCESS, one certificate for urn:sts:person:" + ALICE +
          ", chaining to the realm Intermediate and the service Root",
          function () {
            assert.strictEqual(got.certificates.length, 1);
            assert.ok(x.subjectAltName.indexOf("URI:urn:sts:person:" +
                                               ALICE) >= 0, x.subjectAltName);
            assert.ok(verifiesTo(cert, chain), "the chain does not verify");
            assert.strictEqual(x.publicKey.export({ type: "spki",
                                                    format: "der" })
              .equals(nodeCrypto.createPublicKey(dev.key.publicKeyPem)
                .export({ type: "spki", format: "der" })), true);
            (EKU[profile] || []).forEach(function (one) {
              assert.ok((x.keyUsage || []).indexOf(one) >= 0,
                        profile + " lacks " + one);
            });
          });
    if (profile.indexOf("tls-server") === 0) {
      check(profile + ": the registered host name is the dNSName",
            function () {
              assert.ok(x.subjectAltName.indexOf("DNS:" + HOST) >= 0);
            });
    }
    if (profile === "email") {
      check("email: the rfc822Name is the person's mail, and a SHA-512 " +
            "request is answered", function () {
              assert.ok(x.subjectAltName.indexOf("email:" + ALICE +
                                                 "@scep.example") >= 0,
                        x.subjectAltName);
            });
    }
    if (profile === "smartcard-logon") {
      check("smartcard-logon: the UPN otherName is the person's mail, since " +
            "no person is created with a userPrincipalName", function () {
              assert.ok(x.subjectAltName.indexOf(ALICE + "@scep.example") >= 0,
                        x.subjectAltName);
            });
    }
    if (profile === "digital-signature") {
      check("an AES-128 request is answered with AES-128", function () {
        assert.strictEqual(got.cipher, "2.16.840.1.101.3.4.1.2");
      });
    }
    issued[profile] = { cert: cert, dev: dev, txid: done.txid, made: made };
  }
  const monitorAfter = (await send(realmApi + "/scep/monitor")).body;
  check("the monitor counted nine issuances", function () {
    assert.ok(monitorAfter.totals.issued - monitorBefore.totals.issued >= 9,
              JSON.stringify(monitorAfter.totals));
  });
  const scepView = (await send(realmApi + "/scep?per=1000")).body;
  check("GET /admin-api/scep lists every certificate on the entry it names, " +
        "and no private key or challenge secret anywhere", function () {
          PROFILES.forEach(function (profile) {
            const serial = serialOf(issued[profile].cert);
            const row = scepView.certificates.rows.filter(function (one) {
              return String(one.serialHex).replace(/^0+/, "") === serial;
            })[0];
            assert.ok(row, profile + " is not listed");
            assert.strictEqual(row.entryUri, "urn:sts:person:" + ALICE);
            assert.strictEqual(row.profile, profile);
          });
          const text = JSON.stringify(scepView);
          assert.ok(text.indexOf("PRIVATE KEY") < 0);
          assert.ok(text.indexOf(issued["tls-client"].made.challenge) < 0);
          assert.strictEqual(scepView.hierarchyBuilt, true);
          assert.strictEqual(scepView.ra.keyAlgorithm, "rsa-2048");
          assert.strictEqual(scepView.refusedProfiles.length, 5);
        });

  // -------------------------------------------------------------------------
  log.info("=== 3. retry, CertPoll, GetCert ===");
  const tls = issued["tls-client"];
  const retry = await operate({
    url: SCEP, ra: chain.ra, txid: tls.txid, signerPem: tls.dev.certPem,
    signerKeyPem: tls.dev.key.privateKeyPem,
    inner: client.csr(tls.dev.key, { commonName: ALICE,
                                     challenge: tls.made.challenge })
  });
  check("a retried PKCSReq (same transactionID and request) is answered " +
        "with the stored certificate, without spending the challenge again",
        function () {
          const again = successOf(retry, tls.dev);
          assert.strictEqual(serialOf(again.certificates[0]),
                             serialOf(tls.cert));
        });
  const poll = await operate({
    url: SCEP, ra: chain.ra, txid: tls.txid, messageType: "20",
    signerPem: tls.dev.certPem, signerKeyPem: tls.dev.key.privateKeyPem,
    inner: client.issuerAndSubject(chain.issuing, ALICE)
  });
  check("CertPoll for that transaction returns its certificate", function () {
    assert.strictEqual(serialOf(successOf(poll, tls.dev).certificates[0]),
                       serialOf(tls.cert));
  });
  const stranger = device("stranger");
  const pollOther = await operate({
    url: SCEP, ra: chain.ra, txid: tls.txid, messageType: "20",
    signerPem: stranger.certPem, signerKeyPem: stranger.key.privateKeyPem,
    inner: client.issuerAndSubject(chain.issuing, ALICE)
  });
  await expectFailure("CertPoll for that transaction signed by another key",
                      pollOther, "badCertId", "STS-SCEP-0039");
  const pollUnknown = await operate({
    url: SCEP, ra: chain.ra, messageType: "20",
    signerPem: stranger.certPem, signerKeyPem: stranger.key.privateKeyPem,
    inner: client.issuerAndSubject(chain.issuing, ALICE)
  });
  await expectFailure("CertPoll for an unknown transaction", pollUnknown,
                      "badCertId", "STS-SCEP-0038");
  const getOwn = await operate({
    url: SCEP, ra: chain.ra, messageType: "21", signerPem: tls.cert,
    signerKeyPem: tls.dev.key.privateKeyPem,
    inner: client.issuerAndSerial(issued.email.cert)
  });
  check("GetCert signed by a SCEP certificate returns another certificate " +
        "the same entry holds", function () {
          const got = successOf(getOwn, { key: tls.dev.key,
                                          certPem: tls.cert });
          assert.strictEqual(serialOf(got.certificates[0]),
                             serialOf(issued.email.cert));
        });

  // -------------------------------------------------------------------------
  log.info("=== 4. another person, an application, renewal ===");
  const forBob = await challengeFor(realmApi, "person", BOB, "tls-client");
  const bobDev = device(BOB);
  const bobDone = await operate({
    url: SCEP, ra: chain.ra, signerPem: bobDev.certPem,
    signerKeyPem: bobDev.key.privateKeyPem,
    inner: client.csr(bobDev.key, { commonName: BOB,
                                    challenge: forBob.challenge })
  });
  const bobCert = successOf(bobDone, bobDev).certificates[0];
  check("an administrator's challenge for another person issues for THAT " +
        "person", function () {
          assert.ok(new nodeCrypto.X509Certificate(bobCert).subjectAltName
            .indexOf("URI:urn:sts:person:" + BOB) >= 0);
        });
  const getOthers = await operate({
    url: SCEP, ra: chain.ra, messageType: "21", signerPem: tls.cert,
    signerKeyPem: tls.dev.key.privateKeyPem,
    inner: client.issuerAndSerial(bobCert)
  });
  await expectFailure("GetCert for a certificate another entry holds",
                      getOthers, "badCertId", "STS-SCEP-0041");
  const forApp = await challengeFor(realmApi, "application", APP,
                                    "tls-client");
  const appDev = device(APP);
  const appDone = await operate({
    url: SCEP, ra: chain.ra, signerPem: appDev.certPem,
    signerKeyPem: appDev.key.privateKeyPem,
    inner: client.csr(appDev.key, { commonName: APP,
                                    challenge: forApp.challenge })
  });
  check("an application's challenge issues for the application itself",
        function () {
          const cert = successOf(appDone, appDev).certificates[0];
          assert.ok(new nodeCrypto.X509Certificate(cert).subjectAltName
            .indexOf("URI:urn:sts:application:" + APP) >= 0);
        });
  const renewKey = client.rsaKey(2048);
  const renewal = await operate({
    url: SCEP, ra: chain.ra, messageType: "17", signerPem: tls.cert,
    signerKeyPem: tls.dev.key.privateKeyPem,
    inner: client.csr(renewKey, { commonName: ALICE })
  });
  const renewed = successOf(renewal, { key: tls.dev.key,
                                       certPem: tls.cert }).certificates[0];
  const afterRenewal = (await send(realmApi + "/scep?per=1000")).body;
  check("RenewalReq signed by the earlier certificate issues a new one for " +
        "the new key, and the earlier one is revoked superseded", function () {
          assert.notStrictEqual(serialOf(renewed), serialOf(tls.cert));
          assert.ok(verifiesTo(renewed, chain));
          const old = afterRenewal.certificates.rows.filter(function (one) {
            return String(one.serialHex).replace(/^0+/, "") ===
                   serialOf(tls.cert);
          })[0];
          assert.strictEqual(old.status, "revoked", JSON.stringify(old));
          assert.strictEqual(old.revoked.reason, "superseded");
        });

  // -------------------------------------------------------------------------
  log.info("=== 5. OCSP, revocation, GetCRL ===");
  const codeCert = issued["code-signing"].cert;
  const before = await ocspStatus(REALM, codeCert, chain.issuing);
  check("OCSP answers good for an issued certificate", function () {
    assert.strictEqual(before, "good");
  });
  await ok(realmApi + "/scep/revoke-certificate",
           { serial: serialOf(codeCert), reason: "keyCompromise" },
           "revoked the code-signing certificate");
  const after = await ocspStatus(REALM, codeCert, chain.issuing);
  const crl = Buffer.from(await (await fetch(realmBase + "/pki/crl/" + REALM +
                                             "/scep")).arrayBuffer());
  check("after the revoke action OCSP answers revoked and the SCEP CRL " +
        "lists the serial and the superseded one", function () {
          assert.strictEqual(after, "revoked");
          const listed = crlSerials(crl);
          assert.ok(listed.indexOf(serialOf(codeCert)) >= 0);
          assert.ok(listed.indexOf(serialOf(tls.cert)) >= 0);
        });
  const renewedSigner = { key: renewKey, certPem: renewed };
  const getCrl = await operate({
    url: SCEP, ra: chain.ra, messageType: "22", signerPem: renewed,
    signerKeyPem: renewKey.privateKeyPem,
    inner: client.issuerAndSerial(codeCert)
  });
  check("GetCRL returns the SCEP Issuing CA's CRL, listing the revocation",
        function () {
          const got = successOf(getCrl, renewedSigner);
          assert.strictEqual(got.crls.length, 1);
          assert.ok(crlSerials(got.crls[0]).indexOf(serialOf(codeCert)) >= 0);
        });
  const getCrlOther = await operate({
    url: SCEP, ra: chain.ra, messageType: "22", signerPem: renewed,
    signerKeyPem: renewKey.privateKeyPem,
    inner: client.issuerAndSerial(chain.issuing)
  });
  await expectFailure("GetCRL naming another issuer", getCrlOther,
                      "badCertId", "STS-SCEP-0042");
  const byRevoked = await operate({
    url: SCEP, ra: chain.ra, messageType: "17", signerPem: codeCert,
    signerKeyPem: issued["code-signing"].dev.key.privateKeyPem,
    inner: client.csr(client.rsaKey(2048), { commonName: ALICE })
  });
  await expectFailure("RenewalReq signed by a revoked certificate", byRevoked,
                      "badMessageCheck", "STS-SCEP-0040");

  // -------------------------------------------------------------------------
  log.info("=== 6. who a certificate may be for ===");
  const mine = await challengeFor(realmApi, "person", ALICE, "tls-client");
  const d1 = device(ALICE);
  await expectFailure("a person's challenge with a request naming another " +
                      "person", await operate({
    url: SCEP, ra: chain.ra, signerPem: d1.certPem,
    signerKeyPem: d1.key.privateKeyPem,
    inner: client.csr(d1.key, { challenge: mine.challenge,
      sans: [{ type: "uri", value: "urn:sts:person:" + BOB }] })
  }), "badRequest", "STS-ENROLL-0021");
  const appsOwn = await challengeFor(realmApi, "application", APP,
                                     "tls-client");
  const d2 = device(APP);
  await expectFailure("an application's challenge with a request naming a " +
                      "person", await operate({
    url: SCEP, ra: chain.ra, signerPem: d2.certPem,
    signerKeyPem: d2.key.privateKeyPem,
    inner: client.csr(d2.key, { challenge: appsOwn.challenge,
      sans: [{ type: "uri", value: "urn:sts:person:" + ALICE }] })
  }), "badRequest", "STS-ENROLL-0021");
  const server = await challengeFor(realmApi, "person", ALICE, "tls-server");
  const d3 = device(ALICE);
  await expectFailure("an unregistered DNS name", await operate({
    url: SCEP, ra: chain.ra, signerPem: d3.certPem,
    signerKeyPem: d3.key.privateKeyPem,
    inner: client.csr(d3.key, { challenge: server.challenge,
      sans: [{ type: "dns", value: "unregistered." + REALM + ".example" }] })
  }), "badRequest", "STS-ENROLL-0051");
  const mailc = await challengeFor(realmApi, "person", ALICE, "email");
  const d4 = device(ALICE);
  await expectFailure("an email address that is not the entry's",
                      await operate({
    url: SCEP, ra: chain.ra, signerPem: d4.certPem,
    signerKeyPem: d4.key.privateKeyPem,
    inner: client.csr(d4.key, { challenge: mailc.challenge,
      sans: [{ type: "email", value: "someone.else@scep.example" }] })
  }), "badRequest", "STS-ENROLL-0052");
  for (const profile of REFUSED) {
    const refused = await post(realmApi + "/scep/create-challenge",
                               { kind: "person", identifier: ALICE,
                                 profile: profile });
    check("no challenge can be made for " + profile, function () {
      assert.strictEqual(refused.status, 400);
      assert.ok(/never issued/.test((refused.body.errors || []).join(" ")),
                JSON.stringify(refused.body));
    });
  }
  const narrowed = await challengeFor(realmApi, "person", ALICE,
                                      "code-signing");
  await setting(realmApi, "scep.allowedProfiles", "tls-client,email");
  const d5 = device(ALICE);
  const outOfSetting = await operate({
    url: SCEP, ra: chain.ra, signerPem: d5.certPem,
    signerKeyPem: d5.key.privateKeyPem,
    inner: client.csr(d5.key, { challenge: narrowed.challenge })
  });
  const makeNarrowed = await post(realmApi + "/scep/create-challenge",
                                  { kind: "person", identifier: ALICE,
                                    profile: "code-signing" });
  await reset(realmApi, "scep.allowedProfiles");
  await expectFailure("a profile scep.allowedProfiles no longer allows",
                      outOfSetting, "badRequest", "STS-ENROLL-0003");
  check("and no challenge can be made for it meanwhile", function () {
    assert.strictEqual(makeNarrowed.status, 400);
  });

  // -------------------------------------------------------------------------
  log.info("=== 7. the challenge, the message, the key ===");
  const reused = await challengeFor(realmApi, "person", ALICE, "tls-client");
  const d6 = device(ALICE);
  const firstUse = await operate({
    url: SCEP, ra: chain.ra, signerPem: d6.certPem,
    signerKeyPem: d6.key.privateKeyPem,
    inner: client.csr(d6.key, { challenge: reused.challenge })
  });
  successOf(firstUse, d6);
  await expectFailure("the same challenge in a second transaction",
                      await operate({
    url: SCEP, ra: chain.ra, signerPem: d6.certPem,
    signerKeyPem: d6.key.privateKeyPem,
    inner: client.csr(d6.key, { challenge: reused.challenge })
  }), "badRequest", "STS-ENROLL-0084");
  await expectFailure("a wrong challenge secret", await operate({
    url: SCEP, ra: chain.ra, signerPem: d6.certPem,
    signerKeyPem: d6.key.privateKeyPem,
    inner: client.csr(d6.key, {
      challenge: reused.id + "." + "A".repeat(32) })
  }), "badRequest", "STS-ENROLL-0083");
  const d7 = device(ALICE);
  await expectFailure("a request with no challengePassword", await operate({
    url: SCEP, ra: chain.ra, signerPem: d7.certPem,
    signerKeyPem: d7.key.privateKeyPem,
    inner: client.csr(d7.key, {})
  }), "badRequest", "STS-SCEP-0035");
  const urlChallenge = await challengeFor(realmApi, "person", ALICE,
                                          "tls-client");
  await expectFailure("a URL naming another profile than the challenge's",
                      await operate({
    url: SCEP + "/email", ra: chain.ra, signerPem: d7.certPem,
    signerKeyPem: d7.key.privateKeyPem,
    inner: client.csr(d7.key, { challenge: urlChallenge.challenge })
  }), "badRequest", "STS-SCEP-0036");
  const tamper = await challengeFor(realmApi, "person", ALICE, "tls-client");
  await expectFailure("a tampered signature", await operate({
    url: SCEP, ra: chain.ra, signerPem: d7.certPem,
    signerKeyPem: d7.key.privateKeyPem,
    inner: client.csr(d7.key, { challenge: tamper.challenge }),
    mutate: function (msg) {
      const out = Buffer.from(msg);
      out[out.length - 1] ^= 0x01;
      return out;
    }
  }), "badMessageCheck", "STS-SCEP-0023");
  await expectFailure("a request encrypted to somebody other than the RA",
                      await operate({
    url: SCEP, ra: chain.ra, signerPem: d7.certPem,
    signerKeyPem: d7.key.privateKeyPem,
    envelope: client.envelope(client.csr(d7.key, { challenge:
      tamper.challenge }), stranger.certPem)
  }), "badMessageCheck", "STS-SCEP-0027");
  await expectFailure("DES-EDE3-CBC content encryption", await operate({
    url: SCEP, ra: chain.ra, signerPem: d7.certPem,
    signerKeyPem: d7.key.privateKeyPem, cipher: "des3",
    inner: client.csr(d7.key, { challenge: tamper.challenge })
  }), "badAlg", "STS-SCEP-0029");
  await expectFailure("a SHA-1 signature", await operate({
    url: SCEP, ra: chain.ra, signerPem: d7.certPem,
    signerKeyPem: d7.key.privateKeyPem, digest: "sha1",
    inner: client.csr(d7.key, { challenge: tamper.challenge })
  }), "badAlg", "STS-SCEP-0020");
  const forged = client.csr(d7.key, { challenge: tamper.challenge });
  forged[forged.length - 2] ^= 0x01;
  await expectFailure("a CSR whose signature does not verify", await operate({
    url: SCEP, ra: chain.ra, signerPem: d7.certPem,
    signerKeyPem: d7.key.privateKeyPem, inner: forged
  }), "badMessageCheck", "STS-ENROLL-0033");
  const other = client.rsaKey(2048);
  await expectFailure("a PKCSReq signed by a key other than the CSR's",
                      await operate({
    url: SCEP, ra: chain.ra, signerPem: d7.certPem,
    signerKeyPem: d7.key.privateKeyPem,
    inner: client.csr(other, { challenge: tamper.challenge })
  }), "badMessageCheck", "STS-SCEP-0034");
  await expectFailure("an ML-KEM key in the request", await operate({
    url: SCEP, ra: chain.ra, signerPem: d7.certPem,
    signerKeyPem: d7.key.privateKeyPem,
    inner: await kemCsr(tamper.challenge)
  }), "badAlg", "STS-ENROLL-0032");
  const ec = await keys.generateKeyPair("ec-p256");
  const ecCsr = await x509.certificationRequest({
    subject: "CN=" + ALICE, publicKeyPem: ec.publicPem,
    privateKeyPem: ec.privatePem });
  await expectFailure("an EC key in the request (RSA only over SCEP)",
                      await operate({
    url: SCEP, ra: chain.ra, signerPem: d7.certPem,
    signerKeyPem: d7.key.privateKeyPem, inner: Buffer.from(ecCsr.der)
  }), "badAlg", "STS-SCEP-0033");
  const ecSigner = await x509.issueCertificate({
    subject: [{ name: "CN", value: ALICE }], subjectPublicKey: ec.publicPem,
    signatureAlg: "sha256-ecdsa", profile: "digital-signature",
    issuer: { privateKeyPem: ec.privatePem, keyAlg: "ec-p256" },
    extensions: { basicConstraints: { present: true, critical: true,
                                      ca: false } }
  });
  await expectFailure("an EC signer (no reply can be encrypted to it)",
                      await operate({
    url: SCEP, ra: chain.ra, signerPem: ecSigner.pem,
    signerKeyPem: ec.privatePem,
    inner: client.csr(d7.key, { challenge: tamper.challenge })
  }), "badAlg", "STS-SCEP-0025");
  await expectFailure("a messageType nobody defined", await operate({
    url: SCEP, ra: chain.ra, messageType: "99", signerPem: d7.certPem,
    signerKeyPem: d7.key.privateKeyPem,
    inner: client.csr(d7.key, { challenge: tamper.challenge })
  }), "badRequest", "STS-SCEP-0031");
  const stillGood = await operate({
    url: SCEP, ra: chain.ra, signerPem: d7.certPem,
    signerKeyPem: d7.key.privateKeyPem,
    inner: client.csr(d7.key, { challenge: tamper.challenge })
  });
  check("none of the refusals before the challenge was read spent it: the " +
        "same challenge still issues", function () {
          successOf(stillGood, d7);
        });

  // -------------------------------------------------------------------------
  log.info("=== 8. realm B, in product mode ===");
  const fromA = await challengeFor(realmApi, "person", ALICE, "tls-client");
  const d8 = device(ALICE);
  await expectFailure("realm A's challenge at realm B", await operate({
    url: SCEP_B, ra: chainB.ra, signerPem: d8.certPem,
    signerKeyPem: d8.key.privateKeyPem,
    inner: client.csr(d8.key, { challenge: fromA.challenge })
  }), "badRequest", "STS-ENROLL-0083", realmBApi);
  await expectFailure("a RenewalReq signed by realm A's certificate at " +
                      "realm B", await operate({
    url: SCEP_B, ra: chainB.ra, messageType: "17", signerPem: renewed,
    signerKeyPem: renewKey.privateKeyPem,
    inner: client.csr(client.rsaKey(2048), { commonName: ALICE })
  }), "badMessageCheck", "STS-SCEP-0040", realmBApi);
  await expectFailure("realm B's RA does not open an envelope made for " +
                      "realm A's", await operate({
    url: SCEP_B, ra: chainB.ra, signerPem: d8.certPem,
    signerKeyPem: d8.key.privateKeyPem,
    envelope: client.envelope(client.csr(d8.key, { challenge:
      fromA.challenge }), chain.ra)
  }), "badMessageCheck", "STS-SCEP-0027", realmBApi);
  const forCarol = await challengeFor(realmBApi, "person", CAROL,
                                      "tls-client");
  const d9 = device(CAROL);
  const carol = await operate({
    url: SCEP_B, ra: chainB.ra, signerPem: d9.certPem,
    signerKeyPem: d9.key.privateKeyPem,
    inner: client.csr(d9.key, { challenge: forCarol.challenge })
  });
  check("a product-mode realm issues over SCEP, chaining to ITS Intermediate",
        function () {
          const cert = successOf(carol, d9).certificates[0];
          assert.ok(verifiesTo(cert, chainB));
          assert.ok(!verifiesTo(cert, chain));
        });
  log.info("  (the plain-HTTP case is not exercised: SCEP is not refused " +
           "over plain HTTP in either mode, and this service is reached at " +
           base + ")");

  // -------------------------------------------------------------------------
  log.info("=== 9. disabled, throttled, expired ===");
  await setting(realmApi, "scep.enabled", "false");
  const disabled = await client.http(SCEP + "?operation=GetCACaps");
  await reset(realmApi, "scep.enabled");
  check("scep.enabled=false answers 503", function () {
    assert.strictEqual(disabled.status, 503);
  });
  await setting(realmApi, "scep.attemptsPerIdentity", 2);
  const throttle = await challengeFor(realmApi, "person", ALICE,
                                      "tls-client");
  let throttled = null;
  for (let i = 0; i < 8 && !throttled; i++) {
    const attempt = await operate({
      url: SCEP + "/email", ra: chain.ra, signerPem: d7.certPem,
      signerKeyPem: d7.key.privateKeyPem,
      inner: client.csr(d7.key, { challenge: throttle.challenge })
    });
    if (attempt.r.status === 429) {
      throttled = attempt;
    }
  }
  await reset(realmApi, "scep.attemptsPerIdentity");
  check("repeated refusals for one challenge are throttled: 429 with " +
        "Retry-After", function () {
          assert.ok(throttled, "no request was throttled");
          assert.ok(Number(throttled.r.headers.get("retry-after")) > 0);
        });
  // THE EXPIRING CHALLENGE IS MADE HERE, AFTER THE LAST OTHER CHALLENGE FOR
  // ALICE, AND NOT AT THE TOP (2026-09-15, issue #51). Creating a challenge
  // keeps only the entry's LIVE ones, so a challenge that has already expired
  // is pruned by the next one made for the same person. Made at the top, it
  // survived only while everything above ran inside its sixty seconds — true
  // against a local stack, false against a cluster across the internet, where
  // `throttle` was created after it expired and the redemption below was
  // (correctly) refused as unknown, STS-ENROLL-0083, instead of expired.
  const startedAt = Date.now();
  const expiring = await challengeFor(realmApi, "person", ALICE, "tls-client",
                                      60);
  const waitMs = startedAt + 62000 - Date.now();
  if (waitMs > 0) {
    log.info("  waiting " + Math.ceil(waitMs / 1000) + "s for a sixty-second " +
             "challenge to expire");
    await new Promise(function (resolve) { setTimeout(resolve, waitMs); });
  }
  const d10 = device(ALICE);
  await expectFailure("an expired challenge", await operate({
    url: SCEP, ra: chain.ra, signerPem: d10.certPem,
    signerKeyPem: d10.key.privateKeyPem,
    inner: client.csr(d10.key, { challenge: expiring.challenge })
  }), "badRequest", "STS-ENROLL-0085");

  const monitorEnd = (await send(realmApi + "/scep/monitor")).body;
  check("the monitor counted refusals by failInfo", function () {
    ["badRequest", "badMessageCheck", "badAlg", "badCertId"]
      .forEach(function (name) {
        assert.ok(monitorEnd.failInfo[name] > 0, name + ": " +
                  JSON.stringify(monitorEnd.failInfo));
      });
  });
  await reset(realmApi, "scep.attemptsPerAddress");
  await reset(realmBApi, "scep.attemptsPerAddress");
  const deleted = await challengeFor(realmApi, "person", ALICE, "tls-client");
  await ok(realmApi + "/scep/delete-challenge", { id: deleted.id },
           "deleted a challenge");
  const d11 = device(ALICE);
  await expectFailure("a deleted challenge", await operate({
    url: SCEP, ra: chain.ra, signerPem: d11.certPem,
    signerKeyPem: d11.key.privateKeyPem,
    inner: client.csr(d11.key, { challenge: deleted.challenge })
  }), "badRequest", "STS-ENROLL-0083");
  await ok(realmApi + "/scep/remove-host-name",
           { kind: "person", identifier: ALICE, hostName: HOST },
           "removed the host name");
  const reissued = await ok(realmApi + "/scep/reissue-ra", {},
                            "re-issued the RA certificate");
  const chainAfter = await caChain(SCEP);
  check("reissue-ra replaces the RA certificate GetCACert serves", function () {
    assert.notStrictEqual(chainAfter.ra, chain.ra);
    assert.strictEqual(serialOf(chainAfter.ra),
                       String(reissued.ra.serialHex).replace(/^0+/, ""));
  });

  assert.ok(checks >= 60,
    "only " + checks + " checks ran; a section has stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_scep_enrollment")
  .description("SCEP (RFC 8894) against the running service with an " +
      "independent client: GetCACaps, GetCACert and the HTTP refusals; the " +
      "nine profiles, another person, an application; retry, CertPoll, " +
      "GetCert, GetCRL, RenewalReq; OCSP and revocation; every refusal as a " +
      "CertRep FAILURE with its failInfo and recorded code; realm isolation " +
      "and a product-mode realm; disabled, throttled and expired.")
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});

