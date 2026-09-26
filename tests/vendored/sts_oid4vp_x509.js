"use strict";
//
// File: sts_oid4vp_x509.js
//
// ---------------------------------------------------------------------------
// THE OPENID4VP VERIFIER'S x509_san_dns AND x509_hash CLIENT IDENTIFIERS,
// CHECKED THE WAY A WALLET CHECKS THEM (OpenID4VP 1.0 section 5.9.3, #230),
// over HTTP, in a throwaway realm.
//
//   0. The realm, and its Verifier's x509 identity at
//      /oid4vp/verifier-certificate. In PRODUCT mode, where the Verifier
//      never certifies a Host header, x509_san_dns is refused there until
//      `oid4vp.x509DnsName` names the host — which this job then sets.
//   1. For each prefix, a request started at /oid4vp/start with
//      `client_id_prefix`, fetched at its request_uri as a wallet does, and
//      checked with node's own crypto and nothing of the service's: the
//      `client_id` parameter is the Request Object's; the Request Object is
//      typed and signed by the key of the `x5c` leaf; the chain verifies link
//      by link to the service Root, fetched from the Intermediate's own
//      caIssuers address, and does not carry it; and the Client Identifier
//      is a dNSName of the leaf that is also the Response URI's host
//      (x509_san_dns), or the base64url SHA-256 of the leaf's DER
//      (x509_hash).
//   2. The same wallet check REFUSES a mismatch: a Client Identifier naming
//      another host, another hash, or the other prefix's value.
//   3. The realm's own setting: `oid4vp.clientIdPrefix` = x509_hash, with no
//      prefix named by the request.
//   4. The Verifier refuses what a wallet would: a name that is not the
//      Response URI's host builds no x509_san_dns request (and the
//      verifier-certificate document says so), while x509_hash still
//      answers.
//
// THE WALLET IS INDEPENDENT: every check is node's `crypto`
// (`X509Certificate`, `verify`), as `sts_oid4vp_wallet.js`'s are.
//
// OWNED HERE (local: true): this repository's Verifier.
// ---------------------------------------------------------------------------

const assert = require("assert");
const crypto = require("crypto");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const registry = require("./sts_applications.js");

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
var log = bunyan.createLogger({ name: "sts_oid4vp_x509",
                                level: appconfig.LOG_LEVEL ||
                                       process.env.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var root = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const REALM = ("x509-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                             .slice(0, 31);
const base = root + "/realm/" + REALM;
const api = base + "/admin-api";
// The Response URI's host, which the x509_san_dns name must be: read off the
// document the Verifier publishes, because a pinned global.publicBaseUrl
// makes it a different host from the one this job dials.
let HOST = new URL(base).hostname;

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function partOf(jwt, i) {
  log.debug("Entering partOf().");
  log.debug("Leaving partOf().");
  return JSON.parse(Buffer.from(String(jwt).split(".")[i], "base64url")
    .toString("utf8"));
}

function pemOf(b64) {
  log.debug("Entering pemOf().");
  log.debug("Leaving pemOf().");
  return "-----BEGIN CERTIFICATE-----\n" +
    String(b64).match(/.{1,64}/g).join("\n") +
    "\n-----END CERTIFICATE-----\n";
}

async function hop(method, url, json) {
  log.debug("Entering hop(). " + method + " " + url);
  const headers = {};
  let body;
  if (json !== undefined) {
    body = JSON.stringify(json);
    headers["content-type"] = "application/json";
  }
  const r = await fetch(url, { method: method, headers: headers, body: body,
                               redirect: "manual" });
  const buffer = Buffer.from(await r.arrayBuffer());
  const text = buffer.toString("utf8");
  let parsed = null;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in hop(): " + ((e && e.message) || e));
    parsed = null;
  }
  log.debug("Leaving hop(). " + r.status);
  return { status: r.status, text: text, json: parsed, buffer: buffer,
           type: r.headers.get("content-type") || "",
           cache: r.headers.get("cache-control") || "",
           location: r.headers.get("location") || "" };
}

async function set(key, value) {
  log.debug("Entering set(). " + key);
  const r = await hop("POST", api + "/config/set", { key: key,
                                                     value: value });
  assert.ok(r.status === 200 && r.json && r.json.ok !== false,
            "setting " + key + " was refused: " + r.status + " " +
            r.text.slice(0, 300));
  log.debug("Leaving set().");
}

// THE SERVICE ROOT, from the address the Intermediate itself names for its
// issuer (RFC 5280 section 4.2.2.1, caIssuers) — asked of this origin, since
// the address may be the plain-HTTP revocation listener.
async function rootFor(intermediate) {
  log.debug("Entering rootFor().");
  const access = String(intermediate.infoAccess || "");
  const found = /CA Issuers - URI:(\S+)/.exec(access);
  assert.ok(found, "the Intermediate names no caIssuers: " + access);
  const at = new URL(found[1]);
  const r = await hop("GET", root + at.pathname);
  assert.strictEqual(r.status, 200, "the Root could not be fetched from " +
                     at.pathname + ": " + r.status);
  log.debug("Leaving rootFor().");
  return new crypto.X509Certificate(r.buffer);
}

// A WALLET'S CHECK of one signed request (section 5.9.3). Answers what it
// found; `clientId` is the Client Identifier the wallet was handed.
async function walletCheck(jwt, clientId) {
  log.debug("Entering walletCheck().");
  const header = partOf(jwt, 0);
  const claims = partOf(jwt, 1);
  const certs = (header.x5c || []).map(function (one) {
    return new crypto.X509Certificate(pemOf(one));
  });
  const anchor = certs.length ? await rootFor(certs[certs.length - 1])
                              : null;
  const parts = String(jwt).split(".");
  const input = Buffer.from(parts[0] + "." + parts[1]);
  const signature = Buffer.from(parts[2], "base64url");
  const leafKey = certs.length ? certs[0].publicKey : null;
  const signed = !!leafKey && crypto.verify(
    leafKey.asymmetricKeyType === "ec" ? "sha" +
      String(header.alg).slice(2) : "sha256",
    input, leafKey.asymmetricKeyType === "ec"
      ? { key: leafKey, dsaEncoding: "ieee-p1363" } : leafKey, signature);
  let chained = certs.length >= 2 && !!anchor;
  for (let i = 0; chained && i < certs.length; i++) {
    const issuer = i + 1 < certs.length ? certs[i + 1] : anchor;
    chained = certs[i].checkIssued(issuer) &&
              certs[i].verify(issuer.publicKey) &&
              certs[i].fingerprint256 !== anchor.fingerprint256;
  }
  const dns = certs.length ? String(certs[0].subjectAltName || "")
    .split(/,\s*/).filter(function (one) {
      return one.indexOf("DNS:") === 0;
    }).map(function (one) {
      return one.slice(4);
    }) : [];
  const hash = certs.length ? crypto.createHash("sha256")
    .update(certs[0].raw).digest("base64url") : "";
  let matches = false;
  if (clientId.indexOf("x509_san_dns:") === 0) {
    const name = clientId.slice("x509_san_dns:".length);
    matches = dns.indexOf(name) >= 0 &&
              new URL(claims.response_uri).hostname === name;
  } else if (clientId.indexOf("x509_hash:") === 0) {
    matches = clientId.slice("x509_hash:".length) === hash;
  }
  log.debug("Leaving walletCheck().");
  return { header: header, claims: claims, signed: signed, chained: chained,
           matches: matches && claims.client_id === clientId, dns: dns,
           hash: hash, anchor: anchor, certs: certs };
}

// /oid4vp/start, followed as far as the wallet's address: the query the
// wallet is handed, and the Request Object at its request_uri.
async function start(query) {
  log.debug("Entering start().");
  const r = await hop("GET", base + "/oid4vp/start?" +
                      new URLSearchParams(query).toString());
  const out = { status: r.status, text: r.text, clientId: "", jwt: "",
                type: "" };
  if (r.status === 302 && r.location) {
    const handed = new URL(r.location, base).searchParams;
    out.clientId = handed.get("client_id") || "";
    const ro = await hop("GET", handed.get("request_uri"));
    out.jwt = ro.status === 200 ? ro.text : "";
    out.type = ro.type;
  }
  log.debug("Leaving start(). " + r.status);
  return out;
}

async function test() {
  log.debug("Entering test().");
  const product = await registry.isProduct(root);
  log.info("=== 0. a throwaway realm " + REALM + " (" +
           (product ? "product" : "development") + ") ===");
  const created = await hop("POST", root + "/admin-api/realms/create",
    { id: REALM, domain: REALM + ".example.net", name: "x509 " + STAMP });
  assert.ok(created.status === 200 && created.json &&
            created.json.ok !== false,
            "the realm was not created: " + created.status + " " +
            created.text.slice(0, 300));
  let doc = await hop("GET", base + "/oid4vp/verifier-certificate");
  assert.ok(doc.json && doc.json.response_uri, "no verifier-certificate " +
            "document: " + doc.status + " " + doc.text.slice(0, 300));
  HOST = new URL(doc.json.response_uri).hostname;
  const pinned = !!(doc.json.x509_san_dns &&
                    doc.json.x509_san_dns.dns_name === HOST);
  if (product && pinned) {
    log.info("  (product mode, and global.publicBaseUrl names " + HOST +
             ", so x509_san_dns is certified without oid4vp.x509DnsName)");
  } else if (product) {
    check("product mode: x509_san_dns is refused until a name is " +
          "configured — the Host header is never certified — while " +
          "x509_hash answers", function () {
      assert.strictEqual(doc.status, 200, doc.text.slice(0, 400));
      assert.strictEqual(doc.json.x509_san_dns, null, doc.text.slice(0, 400));
      assert.ok(/x509_san_dns/.test(JSON.stringify(doc.json.refused)),
                doc.text.slice(0, 400));
      assert.ok(doc.json.x509_hash && /^x509_hash:/.test(
        doc.json.x509_hash.client_id), doc.text.slice(0, 400));
    });
    await set("oid4vp.x509DnsName", HOST);
    doc = await hop("GET", base + "/oid4vp/verifier-certificate");
  }
  check("/oid4vp/verifier-certificate names both Client Identifiers, the " +
        "x5c and the anchor, no-store", function () {
    assert.strictEqual(doc.status, 200, doc.text.slice(0, 400));
    assert.ok(/no-store/.test(doc.cache), doc.cache);
    assert.strictEqual(doc.json.x509_san_dns.client_id,
                       "x509_san_dns:" + HOST);
    assert.strictEqual(doc.json.x509_san_dns.dns_name, HOST);
    assert.ok(/^x509_hash:[A-Za-z0-9_-]{43}$/.test(
      doc.json.x509_hash.client_id), doc.json.x509_hash.client_id);
    assert.strictEqual(doc.json.x509_san_dns.x5c.length, 3);
    assert.ok(/BEGIN CERTIFICATE/.test(
      doc.json.x509_san_dns.trust_anchor_pem));
    assert.strictEqual(doc.json.response_uri, base + "/oid4vp/response");
  });

  const seen = {};
  for (const prefix of ["x509_san_dns", "x509_hash"]) {
    log.info("=== 1. " + prefix + ", as a wallet checks it ===");
    const s = await start({ client_id_prefix: prefix,
                            format: "dc+sd-jwt" });
    check(prefix + ": /oid4vp/start hands the wallet a client_id and a " +
          "request_uri, and the Request Object is served typed", function () {
      assert.strictEqual(s.status, 302, s.text.slice(0, 400));
      assert.ok(s.clientId.indexOf(prefix + ":") === 0, s.clientId);
      assert.ok(s.jwt, "no Request Object");
      assert.ok(/application\/oauth-authz-req\+jwt/.test(s.type), s.type);
    });
    const w = await walletCheck(s.jwt, s.clientId);
    seen[prefix] = { clientId: s.clientId, jwt: s.jwt, check: w };
    check(prefix + ": signed by the x5c leaf's key, typed " +
          "oauth-authz-req+jwt, and the client_id parameter is the Request " +
          "Object's", function () {
      assert.strictEqual(w.header.typ, "oauth-authz-req+jwt");
      assert.strictEqual(w.header.alg, "ES256");
      assert.ok(w.signed, "the signature does not verify against the leaf");
      assert.strictEqual(w.claims.client_id, s.clientId);
      assert.strictEqual(w.claims.response_mode, "direct_post");
    });
    check(prefix + ": the chain verifies link by link to the service Root, " +
          "fetched from the Intermediate's caIssuers, and does not carry it",
          function () {
      assert.ok(w.chained, "the x5c chain does not verify to the Root");
      assert.strictEqual(w.certs.length, 3);
      assert.strictEqual(w.anchor.fingerprint256, new crypto.X509Certificate(
        doc.json.x509_hash.trust_anchor_pem).fingerprint256);
    });
    check(prefix + ": the Client Identifier matches the leaf" +
          (prefix === "x509_san_dns" ? " — a dNSName, and the Response " +
           "URI's host" : " — the SHA-256 of its DER"), function () {
      assert.ok(w.matches, JSON.stringify({ clientId: s.clientId,
                                            dns: w.dns, hash: w.hash }));
      assert.strictEqual(new URL(w.claims.response_uri).hostname, HOST);
    });
  }

  log.info("=== 2. the wallet refuses a mismatch ===");
  const san = seen.x509_san_dns;
  const hashed = seen.x509_hash;
  const otherHost = await walletCheck(san.jwt, "x509_san_dns:evil." + HOST);
  const otherHash = await walletCheck(hashed.jwt, "x509_hash:" +
    crypto.createHash("sha256").update("another certificate")
      .digest("base64url"));
  const swapped = await walletCheck(san.jwt, hashed.clientId);
  check("a Client Identifier naming another host, another hash, or the " +
        "other prefix's value does not match the request", function () {
    assert.ok(!otherHost.matches, "another host matched");
    assert.ok(!otherHash.matches, "another hash matched");
    assert.ok(!swapped.matches, "the other prefix's value matched");
  });
  check("both prefixes are one certificate for one name", function () {
    assert.strictEqual(san.check.hash, hashed.check.hash);
    assert.strictEqual(hashed.clientId, "x509_hash:" + san.check.hash);
  });

  log.info("=== 3. the realm's own setting ===");
  await set("oid4vp.clientIdPrefix", "x509_hash");
  const byRealm = await start({ by: "reference", format: "dc+sd-jwt" });
  check("with oid4vp.clientIdPrefix x509_hash, a signed request names no " +
        "prefix and carries the x509_hash Client Identifier", function () {
    assert.strictEqual(byRealm.status, 302, byRealm.text.slice(0, 400));
    assert.strictEqual(byRealm.clientId, hashed.clientId);
  });

  log.info("=== 4. the Verifier refuses what a wallet would ===");
  await set("oid4vp.x509DnsName", "elsewhere.example.net");
  const refused = await start({ client_id_prefix: "x509_san_dns" });
  const refusedDoc = await hop("GET", base + "/oid4vp/verifier-certificate");
  const stillHash = await start({ client_id_prefix: "x509_hash" });
  check("a name that is not the Response URI's host builds no x509_san_dns " +
        "request, and says so; x509_hash still answers", function () {
    assert.strictEqual(refused.status, 500, refused.text.slice(0, 300));
    assert.ok(/not the host of the Response URI/.test(refused.text),
              refused.text.slice(0, 300));
    assert.strictEqual(refusedDoc.json.x509_san_dns, null);
    assert.strictEqual(stillHash.status, 302, stillHash.text.slice(0, 300));
  });
  await set("oid4vp.x509DnsName", product && !pinned ? HOST : "");
  await set("oid4vp.clientIdPrefix", "pre-registered");

  assert.ok(checks >= 13, "only " + checks + " checks ran");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

new Command()
  .description("The OpenID4VP Verifier's x509_san_dns and x509_hash Client " +
    "Identifiers (#230), checked as a wallet checks them.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
