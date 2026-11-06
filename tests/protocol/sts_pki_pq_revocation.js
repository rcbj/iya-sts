// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_pki_pq_revocation.js
//
// ---------------------------------------------------------------------------
// A POST-QUANTUM AUTHORITY'S REVOCATION, OVER HTTP (#1368).
//
// A revocation nobody can read is a revocation lost. Until #1368 an ML-DSA
// authority could not sign a CRL or an OCSP response at all, and
// `tests/signature_doors.js` only calls the two signing functions directly. So
// this drives the whole of it from outside the process: a realm's authority
// built on ML-DSA-65, a certificate issued and revoked through `/admin-api`,
// and the CRL and the OCSP response fetched WITH NO CREDENTIAL, as a relying
// party fetches them.
//
// **THE SIGNATURES ARE CHECKED HERE AND NOT BY THIS SERVICE**: this file reads
// the DER itself and verifies with `@noble/post-quantum` over the exact signed
// bytes, so the service's own verifier cannot agree with its own signer.
//
// It works in a throwaway trust realm, which it leaves standing.
// ---------------------------------------------------------------------------
const assert = require("assert");
const nodeCrypto = require("crypto");
const { Command, Option } = require("commander");
const { ml_dsa65 } = require("@noble/post-quantum/ml-dsa.js");
const { usernameFor } = require("./random_username.js");

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
var log = bunyan.createLogger({ name: "sts_pki_pq_revocation",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const REALM = usernameFor("pqrevoke").replace(/[^a-z0-9-]/g, "").slice(0, 30);
const realmBase = base + "/realm/" + REALM;
const api = base + "/admin-api";
const realmApi = realmBase + "/admin-api";
const CLIENT = "pqr-client-" + String(Date.now()).slice(-6);
const ML_DSA_65 = "2.16.840.1.101.3.4.3.18";
const OCSP_BASIC = "1.3.6.1.5.5.7.48.1.1";

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

async function send(url, options) {
  log.debug("Entering send().");
  const r = await fetch(url, Object.assign({ redirect: "manual" },
                                           options || {}));
  const buffer = Buffer.from(await r.arrayBuffer());
  let json = null;
  try {
    json = JSON.parse(buffer.toString("utf8"));
  } catch (e) {
    log.debug("Caught in send(): " + ((e && e.message) || e));
    // DER, which is the point of most of what this file fetches.
    json = null;
  }
  log.debug("Leaving send().");
  return { status: r.status, type: r.headers.get("content-type") || "",
           buffer: buffer, json: json };
}

async function apiOk(url, body, what) {
  log.debug("Entering apiOk().");
  const r = await send(url, { method: "POST",
                              headers: { "Content-Type": "application/json" },
                              body: JSON.stringify(body) });
  assert.ok(r.status === 200 && r.json && r.json.ok !== false,
            what + ": " + url + " answered " + r.status + " " +
            r.buffer.toString("utf8").slice(0, 500));
  log.debug("Leaving apiOk().");
  return r.json;
}

// The signed bytes and the signature, by hand. NO ENTERING/LEAVING PAIR ON
// `readTlv()`: it runs once per node of every document, the style's hot path.
function readTlv(buf, pos) {
  const start = pos;
  const tag = buf[pos++];
  let len = buf[pos++];
  if (len & 0x80) {
    const n = len & 0x7f;
    len = 0;
    for (let i = 0; i < n; i++) {
      len = len * 256 + buf[pos++];
    }
  }
  const end = pos + len;
  assert.ok(end <= buf.length, "a DER length runs past the end");
  const node = { tag: tag, value: buf.subarray(pos, end),
                 raw: buf.subarray(start, end), end: end };
  if (tag & 0x20) {
    node.children = [];
    let p = pos;
    while (p < end) {
      const child = readTlv(buf, p);
      node.children.push(child);
      p = child.end;
    }
  }
  return node;
}

function parseDer(buf) {
  log.debug("Entering parseDer().");
  const node = readTlv(buf, 0);
  assert.strictEqual(node.end, buf.length, "bytes after the outer element");
  log.debug("Leaving parseDer().");
  return node;
}

function oidOf(node) {
  log.debug("Entering oidOf().");
  const b = node.value;
  const out = [Math.floor(b[0] / 40), b[0] % 40];
  let v = 0;
  for (let i = 1; i < b.length; i++) {
    v = v * 128 + (b[i] & 0x7f);
    if (!(b[i] & 0x80)) {
      out.push(v);
      v = 0;
    }
  }
  log.debug("Leaving oidOf().");
  return out.join(".");
}

// A DER element from its tag and content.
function tlv(tag, parts) {
  log.debug("Entering tlv().");
  const body = Buffer.isBuffer(parts) ? parts : Buffer.concat(parts);
  let head;
  if (body.length < 128) {
    head = Buffer.from([tag, body.length]);
  } else if (body.length < 256) {
    head = Buffer.from([tag, 0x81, body.length]);
  } else {
    head = Buffer.from([tag, 0x82, body.length >> 8, body.length & 0xff]);
  }
  log.debug("Leaving tlv().");
  return Buffer.concat([head, body]);
}

function sha1(bytes) {
  log.debug("Entering sha1().");
  log.debug("Leaving sha1().");
  return nodeCrypto.createHash("sha1").update(bytes).digest();
}

// The AKP key out of an authority's certificate: tbs, its SubjectPublicKeyInfo.
function authorityFacts(der) {
  log.debug("Entering authorityFacts().");
  const tbs = parseDer(der).children[0];
  const offset = tbs.children[0].tag === 0xa0 ? 1 : 0;
  const spki = tbs.children[offset + 5];
  const out = { subjectRaw: tbs.children[offset + 4].raw,
                keyOid: oidOf(spki.children[0].children[0]),
                publicKey: spki.children[1].value.subarray(1) };
  log.debug("Leaving authorityFacts().");
  return out;
}

function crlFacts(der) {
  log.debug("Entering crlFacts().");
  const top = parseDer(der);
  const tbs = top.children[0];
  const offset = tbs.children[0].tag === 0x02 ? 1 : 0;
  const entries = tbs.children.filter(function (one, i) {
    return i > offset + 2 && one.tag === 0x30;
  })[0];
  const out = { tbsRaw: tbs.raw,
                innerAlg: oidOf(tbs.children[offset].children[0]),
                outerAlg: oidOf(top.children[1].children[0]),
                algNodes: top.children[1].children.length,
                signature: top.children[2].value.subarray(1),
                serials: (entries ? entries.children : []).map(function (one) {
                  return Buffer.from(one.children[0].value).toString("hex")
                    .replace(/^0+/, "");
                }) };
  log.debug("Leaving crlFacts().");
  return out;
}

function ocspFacts(der) {
  log.debug("Entering ocspFacts().");
  const top = parseDer(der);
  const out = { status: top.children[0].value[0] };
  const bytes = top.children[1].children[0];
  out.type = oidOf(bytes.children[0]);
  const basic = parseDer(bytes.children[1].value);
  const data = basic.children[0];
  const i = data.children[0].tag === 0xa0 ? 1 : 0;
  out.tbsRaw = data.raw;
  out.alg = oidOf(basic.children[1].children[0]);
  out.signature = basic.children[2].value.subarray(1);
  out.single = data.children[i + 2].children.map(function (single) {
    return { serial: Buffer.from(single.children[0].children[3].value)
      .toString("hex").replace(/^0+/, ""),
             statusTag: single.children[1].tag };
  });
  log.debug("Leaving ocspFacts().");
  return out;
}

function ocspRequest(authority, serialHex) {
  log.debug("Entering ocspRequest().");
  const sha1Oid = Buffer.from([0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a]);
  const serial = Buffer.from(String(serialHex).length % 2 ? "0" + serialHex
                                                          : serialHex, "hex");
  const certId = tlv(0x30, [
    tlv(0x30, [sha1Oid, Buffer.from([0x05, 0x00])]),
    tlv(0x04, sha1(authority.subjectRaw)),
    tlv(0x04, sha1(authority.publicKey)),
    tlv(0x02, serial[0] & 0x80 ? Buffer.concat([Buffer.from([0]), serial])
                               : serial)
  ]);
  log.debug("Leaving ocspRequest().");
  return tlv(0x30, [tlv(0x30, [tlv(0x30, [tlv(0x30, [certId])])])]);
}

function normalSerial(hex) {
  log.debug("Entering normalSerial().");
  log.debug("Leaving normalSerial().");
  return String(hex).toLowerCase().replace(/[^0-9a-f]/g, "").replace(/^0+/, "");
}

function verifies(publicKey, bytes, signature) {
  log.debug("Entering verifies().");
  log.debug("Leaving verifies().");
  return ml_dsa65.verify(new Uint8Array(publicKey), new Uint8Array(bytes),
                         new Uint8Array(signature));
}

function changed(bytes) {
  log.debug("Entering changed().");
  const out = Buffer.from(bytes);
  out[out.length - 1] ^= 1;
  log.debug("Leaving changed().");
  return out;
}

async function askOcsp(path, authority, serial) {
  log.debug("Entering askOcsp().");
  const r = await send(realmBase + "/pki/ocsp/" + path, {
    method: "POST", headers: { "Content-Type": "application/ocsp-request" },
    body: ocspRequest(authority, serial) });
  assert.strictEqual(r.status, 200, r.buffer.toString("utf8").slice(0, 200));
  assert.ok(/application\/ocsp-response/.test(r.type), r.type);
  log.debug("Leaving askOcsp().");
  return ocspFacts(r.buffer);
}

async function issue(identifier) {
  log.debug("Entering issue().");
  const made = await apiOk(realmApi + "/pki/issue",
                           { target: "application", identifier: identifier },
                           "issued a certificate");
  log.debug("Leaving issue().");
  return made;
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving a post-quantum authority's revocation at " + realmBase);
  await apiOk(api + "/realms/create",
              { id: REALM, domain: REALM + ".example.net",
                name: "Post-quantum revocation" }, "created the realm");
  await apiOk(realmApi + "/pki/build", { keyAlg: "ml-dsa-65" },
              "built the realm's chain on ML-DSA-65");
  await apiOk(realmApi + "/applications/create", {
    identifier: CLIENT, kind: "oauth2-client", name: CLIENT,
    protocols: ["oauth2"],
    fields: { oauthClientId: [CLIENT],
              oauthTokenEndpointAuthMethod: "private_key_jwt" } },
              "registered the application");
  await issue(CLIENT);
  await issue(CLIENT);

  const view = (await send(realmApi + "/pki")).json;
  const authority = view.revocation.authorities.filter(function (one) {
    return one.issued.filter(function (cert) {
      return cert.kind === "leaf" && !cert.revoked;
    }).length >= 2;
  })[0];
  assert.ok(authority, "no authority holds the two leaves just issued: " +
            JSON.stringify(view.revocation.authorities.map(function (one) {
              return [one.ca, one.issued.length];
            })));
  const leaves = authority.issued.filter(function (cert) {
    return cert.kind === "leaf" && !cert.revoked;
  });
  const target = leaves[0];
  const bystander = leaves[1];
  const path = (authority.scopeSegment || REALM) + "/" + authority.ca;
  const serial = normalSerial(target.serialHex);

  const caDer = await send(realmBase + "/pki/ca/" + path + ".cer");
  check("the authority's certificate is fetched with no credential",
    function () {
      assert.strictEqual(caDer.status, 200);
    });
  const ca = authorityFacts(caDer.buffer);
  check("and its key IS ML-DSA-65, so what follows proves something",
    function () {
      assert.strictEqual(ca.keyOid, ML_DSA_65);
    });

  const before = await send(realmBase + "/pki/crl/" + path);
  check("before the revocation the CRL signs, and does not name the serial",
    function () {
      assert.strictEqual(before.status, 200,
                         before.buffer.toString("utf8").slice(0, 200));
      const crl = crlFacts(before.buffer);
      assert.ok(crl.serials.indexOf(serial) < 0);
      assert.ok(verifies(ca.publicKey, crl.tbsRaw, crl.signature));
    });

  await apiOk(realmApi + "/pki/revoke-certificate", {
    scope: authority.scope, ca: authority.ca, serialHex: target.serialHex,
    reason: "keyCompromise" }, "revoked the certificate");

  const listed = await send(realmBase + "/pki/crl/" + path);
  check("GET /pki/crl answers DER as application/pkix-crl, with no credential",
    function () {
      assert.strictEqual(listed.status, 200);
      assert.ok(/application\/pkix-crl/.test(listed.type), listed.type);
    });
  const crl = crlFacts(listed.buffer);
  check("the CRL names ML-DSA-65 in both places, with no parameters (RFC 9881)",
    function () {
      assert.strictEqual(crl.innerAlg, ML_DSA_65);
      assert.strictEqual(crl.outerAlg, ML_DSA_65);
      assert.strictEqual(crl.algNodes, 1);
    });
  check("THE REVOCATION IS IN THE SIGNED LIST", function () {
    assert.ok(crl.serials.indexOf(serial) >= 0, crl.serials.join());
    assert.ok(crl.serials.indexOf(normalSerial(bystander.serialHex)) < 0,
              "a certificate nobody revoked is on the list");
  });
  check("and its signature verifies independently, under the authority's key",
    function () {
      assert.ok(verifies(ca.publicKey, crl.tbsRaw, crl.signature));
    });
  check("and not over changed bytes", function () {
    assert.ok(!verifies(ca.publicKey, changed(crl.tbsRaw), crl.signature));
  });

  const revoked = await askOcsp(path, ca, target.serialHex);
  check("the OCSP responder answers successful, in a BasicOCSPResponse",
    function () {
      assert.strictEqual(revoked.status, 0);
      assert.strictEqual(revoked.type, OCSP_BASIC);
      assert.strictEqual(revoked.alg, ML_DSA_65);
    });
  check("THE RESPONSE SAYS REVOKED (RFC 6960 section 4.2.1, tag 1)",
    function () {
      assert.strictEqual(revoked.single.length, 1);
      assert.strictEqual(revoked.single[0].serial, serial);
      assert.strictEqual(revoked.single[0].statusTag, 0xa1);
    });
  check("and its signature verifies independently", function () {
    assert.ok(verifies(ca.publicKey, revoked.tbsRaw, revoked.signature));
  });
  check("and not over changed bytes", function () {
    assert.ok(!verifies(ca.publicKey, changed(revoked.tbsRaw),
                        revoked.signature));
  });

  // EVERY AUTHORITY OF THE REALM'S, the Intermediate above all: its CRL is
  // where a revoked Issuing CA is listed. It is an ML-DSA key under the
  // classical Root, and what its own certificate was signed with says nothing
  // about what it signs. This job's first run found STS-PKI-0063 here: the
  // signer was chosen by the certificate's algorithm rather than by the key.
  let postQuantumAuthorities = 0;
  for (const one of view.revocation.authorities) {
    const segment = (one.scopeSegment || REALM) + "/" + one.ca;
    const certificate = await send(realmBase + "/pki/ca/" + segment + ".cer");
    assert.strictEqual(certificate.status, 200, segment);
    const key = authorityFacts(certificate.buffer);
    if (key.keyOid !== ML_DSA_65) {
      continue;
    }
    const list = await send(realmBase + "/pki/crl/" + segment);
    check("the " + one.ca + " authority signs a CRL that verifies",
      function () {
        assert.strictEqual(list.status, 200,
                           list.buffer.toString("utf8").slice(0, 200));
        const signed = crlFacts(list.buffer);
        assert.strictEqual(signed.outerAlg, ML_DSA_65);
        assert.ok(verifies(key.publicKey, signed.tbsRaw, signed.signature));
      });
    const asked = one.issued.length ? one.issued[0].serialHex : "01";
    const answer = await askOcsp(segment, key, asked);
    check("and an OCSP response that verifies", function () {
      assert.strictEqual(answer.status, 0);
      assert.strictEqual(answer.alg, ML_DSA_65);
      assert.ok(verifies(key.publicKey, answer.tbsRaw, answer.signature));
    });
    postQuantumAuthorities += 1;
  }
  check("and that covered more than the one Issuing CA", function () {
    assert.ok(postQuantumAuthorities >= 2, String(postQuantumAuthorities));
  });

  const good = await askOcsp(path, ca, bystander.serialHex);
  check("a certificate nobody revoked answers good (tag 0), signed",
    function () {
      assert.strictEqual(good.single[0].statusTag, 0x80);
      assert.ok(verifies(ca.publicKey, good.tbsRaw, good.signature));
    });

  assert.ok(checks >= 12, "only " + checks + " checks ran; a section has " +
                          "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_pki_pq_revocation")
  .description("A post-quantum authority's CRL and OCSP response, fetched " +
    "over HTTP and verified independently.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
