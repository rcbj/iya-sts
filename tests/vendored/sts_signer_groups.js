'use strict';
//
// File: sts_signer_groups.js
//
// ===========================================================================
// SIGNER GROUPS OVER HTTP, IN EVERY MODE (#68, 2026-09-26).
//
// `tests/signer_groups.js` and `tests/pki_hybrid.js` hold the keys, the
// hybrid certificates, the selection and the rotation to their promises in
// process. This job holds the RUNNING service to them through what a relying
// party actually reads, in a THROWAWAY REALM switched to
// `keys.signerModel = hybrid-groups` through `/admin-api/config/set`:
//
//   1. an access token the realm issues is signed by the TOKENS group's
//      RSA-3072 key, and verifies against the JWKS entry of that kid;
//   2. the JWKS keeps the per-algorithm RSA key FIRST, and publishes the
//      JOSE groups' keys after it — a classical key with its hybrid
//      certificate in x5c (whose key IS that key), an ML-DSA partner bare
//      (rcbj's D5);
//   3. /crypto/metadata lists one unit per group certificate, each classical
//      one naming its ML-DSA `alternativeKey`;
//   4. the SAML metadata publishes the XML group's hybrid certificate under
//      use="signing";
//   5. with `saml.signatureAlgorithm = ecdsa-sha256`, the SAML metadata is
//      signed ECDSA-SHA256 under an EC certificate (rcbj's D8).
//
// A protocol job because it is the only kind an AWS target and the product
// mode can run (tests/CLAUDE.md, rule 2).
// ===========================================================================

const assert = require("assert");
const nodeCrypto = require("crypto");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, for the reason wait_for.js (beside this file) gives.
  appconfigProblem = e;
  appconfig = {};
}

const bunyan = require("bunyan");
const log = bunyan.createLogger({ name: "sts_signer_groups",
                                  level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

const stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
const base = String(process.env.OID4VCI_ISSUER_URL ||
                    stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = Date.now().toString(36);
const REALM = "groups-" + STAMP;
const R = "/realm/" + REALM;

// The DER of the subjectAltPublicKeyInfo extension's OID, 2.5.29.72 — how
// this job tells a hybrid certificate from a classical one without a parser
// that knows ITU-T X.509 clause 9.8.
const ALT_KEY_OID_DER = Buffer.from("0603551d48", "hex");

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  ✓ " + what);
  log.debug("Leaving check().");
}

async function call(method, url, options) {
  log.debug("Entering call(). " + method + " " + url);
  const opts = Object.assign({ method: method, redirect: "manual" },
                             options || {});
  const r = await fetch(url, opts);
  const text = await r.text();
  let body = null;
  try {
    body = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in call(): " + ((e && e.message) || e));
    // Not JSON — a page, an XML document or an empty body. Kept as text.
    body = null;
  }
  log.debug("Leaving call(). status=" + r.status);
  return { status: r.status, body: body, text: text };
}

async function api(method, path, payload) {
  log.debug("Entering api(). " + method + " " + path);
  const options = payload === undefined ? {}
    : { headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload) };
  const reply = await call(method, base + path, options);
  log.debug("Leaving api().");
  return reply;
}

async function setting(key, value) {
  log.debug("Entering setting(). " + key + "=" + value);
  const r = await api("POST", R + "/admin-api/config/set",
                      { key: key, value: value });
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
            "precondition: setting " + key + " in " + REALM + " answered " +
            r.status + " " + r.text.slice(0, 300));
  log.debug("Leaving setting().");
}

async function until(what, fn, limitMs) {
  log.debug("Entering until(). " + what);
  const deadline = Date.now() + (limitMs || 180000);
  for (;;) {
    const got = await fn();
    if (got) {
      log.debug("Leaving until(). Met.");
      return got;
    }
    if (Date.now() > deadline) {
      log.debug("Leaving until(). Timed out.");
      assert.fail("timed out waiting for " + what);
    }
    await new Promise(function (resolve) { setTimeout(resolve, 1000); });
  }
}

async function realmToken() {
  log.debug("Entering realmToken().");
  const regenerated = await api("POST", R +
    "/admin-api/applications/regenerate-secret",
    { application: "sts-management-api" });
  const secret = regenerated.body && regenerated.body.clientSecret;
  assert.ok(secret, "precondition: regenerating the realm's " +
    "sts-management-api secret answered " + regenerated.status);
  const minted = await call("POST", base + R + "/oauth2/token", {
    headers: { "Content-Type": "application/x-www-form-urlencoded",
               Authorization: "Basic " +
                 Buffer.from("sts-management-api:" + secret)
                   .toString("base64") },
    body: new URLSearchParams({ grant_type: "client_credentials",
                                scope: "admin:read",
                                resource: base + R + "/admin-api" })
      .toString()
  });
  const token = minted.body && minted.body.access_token;
  assert.ok(token, "precondition: the realm's token endpoint answered " +
            minted.status + " " + minted.text.slice(0, 200));
  log.debug("Leaving realmToken().");
  return token;
}

function headerOf(token) {
  log.debug("Entering headerOf().");
  log.debug("Leaving headerOf().");
  return JSON.parse(Buffer.from(token.split(".")[0], "base64url")
    .toString("utf8"));
}

async function jwks() {
  log.debug("Entering jwks().");
  const r = await api("GET", R + "/oauth2/jwks");
  assert.strictEqual(r.status, 200, "GET " + R + "/oauth2/jwks answered " +
                     r.status);
  log.debug("Leaving jwks().");
  return r.body.keys || [];
}

function groupKeysOf(keys) {
  log.debug("Entering groupKeysOf().");
  log.debug("Leaving groupKeysOf().");
  return keys.filter(function (k) {
    return /^sts-g-/.test(String(k.kid || ""));
  });
}

async function main() {
  log.debug("Entering main().");
  const made = await api("POST", "/admin-api/realms/create",
                         { id: REALM, domain: REALM + ".example.net",
                           name: "Signer groups test " + STAMP });
  assert.ok(made.status === 200, "precondition: creating " + REALM +
            " answered " + made.status + " " + made.text.slice(0, 300));
  await setting("keys.signerModel", "hybrid-groups");

  // A realm switched at runtime makes its group keys on its first group
  // signature — this token — and signs with the per-algorithm keys until
  // they exist and are certified (the service says so once).
  await realmToken();
  const keys = await until("the JOSE groups' 28 keys, certified, in the " +
                           "JWKS", async function () {
    const all = await jwks();
    const grouped = groupKeysOf(all);
    const certified = grouped.filter(function (k) {
      return !!k.x5c;
    });
    // 4 JOSE groups x (3 classical + SLH-DSA) carry x5c once certified.
    return grouped.length === 28 && certified.length === 16 ? all : null;
  });

  // --- 1. an access token signs with the TOKENS group's key -----------------
  log.info("=== 1. an access token signs with the tokens group's key ===");
  const token = await until("an access token signed by the tokens group",
    async function () {
      const t = await realmToken();
      return /^sts-g-tokens-rs256-/.test(String(headerOf(t).kid)) ? t : null;
    });
  const kid = headerOf(token).kid;
  const jwk = keys.filter(function (k) { return k.kid === kid; })[0];
  check("the realm's access token is signed by the tokens group's RSA-3072 " +
        "key (" + kid + ")", function () {
    assert.ok(jwk, "the JWKS carries " + kid);
    assert.strictEqual(Buffer.from(jwk.n, "base64url").length * 8, 3072);
  });
  check("and it verifies against that JWKS entry", function () {
    const parts = token.split(".");
    const ok = nodeCrypto.verify("sha256",
      Buffer.from(parts[0] + "." + parts[1]),
      nodeCrypto.createPublicKey({ key: jwk, format: "jwk" }),
      Buffer.from(parts[2], "base64url"));
    assert.ok(ok, "the RS256 signature does not verify");
  });

  // --- 2. the JWKS, as D5 says ---------------------------------------------
  log.info("=== 2. the JWKS publishes the groups as D5 says ===");
  check("the per-algorithm RSA key is still FIRST", function () {
    assert.ok(!/^sts-g-/.test(String(keys[0].kid)), keys[0].kid);
  });
  const grouped = groupKeysOf(keys);
  check("a classical group key's x5c[0] holds THAT key, and is a HYBRID " +
        "certificate (subjectAltPublicKeyInfo present)", function () {
    grouped.filter(function (k) {
      return k.kty === "RSA" || k.kty === "EC";
    }).forEach(function (k) {
      assert.ok(k.x5c && k.x5c.length, k.kid + " has no x5c");
      const der = Buffer.from(k.x5c[0], "base64");
      const certKey = new nodeCrypto.X509Certificate(der).publicKey
        .export({ format: "jwk" });
      assert.strictEqual(certKey.n || certKey.x, k.n || k.x,
                         k.kid + ": x5c[0] holds another key");
      assert.ok(der.indexOf(ALT_KEY_OID_DER) >= 0,
                k.kid + ": x5c[0] is not a hybrid certificate");
    });
  });
  check("an ML-DSA group key is published WITHOUT x5c — its certificate " +
        "is its partner's, whose first key is not this one (RFC 7517 4.7)",
        function () {
    const mldsa = grouped.filter(function (k) {
      return /^ML-DSA-/.test(String(k.alg));
    });
    assert.strictEqual(mldsa.length, 12, "3 ML-DSA keys in each of 4 groups");
    mldsa.forEach(function (k) {
      assert.ok(!k.x5c, k.kid + " carries x5c");
    });
  });

  // --- 3. /crypto/metadata --------------------------------------------------
  log.info("=== 3. /crypto/metadata names the pairs ===");
  const meta = await api("GET", R + "/crypto/metadata.json");
  assert.strictEqual(meta.status, 200, "GET /crypto/metadata.json answered " +
                     meta.status);
  const units = (meta.body.units || []).filter(function (u) {
    return u.kind === "group";
  });
  check("one unit per group CERTIFICATE — 5 groups x 4", function () {
    assert.strictEqual(units.length, 20, units.map(function (u) {
      return u.unit;
    }).join(", "));
  });
  const tokensRsa = units.filter(function (u) {
    return u.unit === "jose:tokens/RS256";
  })[0];
  check("the tokens group's RSA certificate names its ML-DSA-65 " +
        "alternativeKey", function () {
    const current = tokensRsa.keys.filter(function (k) {
      return k.state === "current";
    })[0];
    assert.ok(current.alternativeKey, JSON.stringify(current).slice(0, 300));
    assert.strictEqual(current.alternativeKey.alg, "ML-DSA-65");
  });

  // --- 4. SAML metadata ---------------------------------------------------
  log.info("=== 4. the SAML metadata publishes the XML group ===");
  const samlMeta = await until("the SAML metadata to carry a hybrid signing " +
                               "certificate", async function () {
    const r = await api("GET", R + "/saml2/metadata");
    const signing = (r.text.match(/<md:KeyDescriptor use="signing">[\s\S]*?<\/md:KeyDescriptor>/g) || []);
    const hybrid = signing.some(function (d) {
      const b64 = (d.match(/<ds:X509Certificate>([^<]+)</) || [])[1] || "";
      return Buffer.from(b64, "base64").indexOf(ALT_KEY_OID_DER) >= 0;
    });
    return hybrid ? r.text : null;
  });
  check("a use=\"signing\" KeyDescriptor carries the XML group's hybrid " +
        "certificate", function () {
    assert.ok(samlMeta.length > 0);
  });

  // --- 5. ECDSA XML ------------------------------------------------------
  log.info("=== 5. saml.signatureAlgorithm = ecdsa-sha256 ===");
  await setting("saml.signatureAlgorithm", "ecdsa-sha256");
  const ecMeta = await api("GET", R + "/saml2/metadata");
  check("the SAML metadata is signed ECDSA-SHA256 under an EC certificate",
        function () {
    assert.ok(/SignatureMethod Algorithm="http:\/\/www\.w3\.org\/2001\/04\/xmldsig-more#ecdsa-sha256"/
                .test(ecMeta.text), ecMeta.text.slice(0, 400));
    const sigCert = ((ecMeta.text.match(/<ds:Signature[\s\S]*?<ds:X509Certificate>([^<]+)</) || [])[1]) || "";
    assert.ok(sigCert, "the signature carries a certificate");
    const certKey = new nodeCrypto.X509Certificate(
      Buffer.from(sigCert, "base64")).publicKey;
    assert.strictEqual(certKey.asymmetricKeyType, "ec");
  });
  await setting("saml.signatureAlgorithm", "rsa-sha256");

  log.info(checks + " check(s) passed.");
  log.debug("Leaving main().");
}

main().then(function () {
  process.exit(0);
}).catch(function (e) {
  log.error("sts_signer_groups FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
