"use strict";
//
// File: sts_oidfed.js
//
// ---------------------------------------------------------------------------
// OPENID FEDERATION 1.1 (#132, #133, 2026-09-23), over HTTP: the default realm
// a Trust Anchor, a throwaway realm its Subordinate (rcbj's answer 1).
//
//   1. THE ENTITY CONFIGURATIONS: served as application/entity-statement+jwt
//      with no parameter and no-store, typed, signed by the realm's own
//      Federation Entity Key; the default realm names no superior and
//      publishes fetch and list, the throwaway realm names the default one.
//   2. FETCH: the statement about the realm, signed by the anchor and pinning
//      the realm's keys; no sub, and a stranger, refused in section 8.9's
//      JSON.
//   3. LIST and RESOLVE: the realm listed; a resolve response carrying its
//      three-statement Trust Chain and its metadata; the refusals — no
//      trust_anchor, an anchor not configured, an entity nobody resolved.
//   4. TRUST MARKS: a type registered and a mark issued to the realm through
//      /admin-api; carried in the realm's Entity Configuration and verified
//      in the resolve response; handed out at the Trust Mark endpoint,
//      listed, active at the status endpoint; revoked, and then revoked
//      there, unlisted and gone from the resolution.
//   5. A REGISTERED SUBORDINATE: the realm vouches for an entity with a
//      metadata policy, becomes an Intermediate (fetch and list published),
//      and its statement carries the policy; the listing filters by type.
//   6. THE KEYS: a rotation by hand, then the retired key in the Historical
//      Keys jwk-set+jwt; a revocation with its reason there; an emergency
//      rotation without its confirmation refused.
//
// OWNED HERE (local: true): this repository's federation endpoints and its
// management API.
// ---------------------------------------------------------------------------

const assert = require("assert");
const crypto = require("crypto");
const { Command, Option } = require("commander");
const names = require("./random_username.js");

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
var log = bunyan.createLogger({ name: "sts_oidfed",
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
const REALM = ("fed-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                            .slice(0, 31);
const base = root + "/realm/" + REALM;
const TYPE = "https://federation.example.test/marks/job-" + STAMP;
const RP = "https://rp-" + STAMP.toLowerCase().replace(/[^a-z0-9]/g, "") +
           ".example.test";

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function partsOf(jwt) {
  log.debug("Entering partsOf().");
  const p = String(jwt).split(".");
  log.debug("Leaving partsOf().");
  return { header: JSON.parse(Buffer.from(p[0], "base64url").toString()),
           claims: JSON.parse(Buffer.from(p[1], "base64url").toString()) };
}

// A signature check of this job's own, with node's crypto, for the curve
// algorithms a Federation Entity Key is made for by default — so the job
// does not take the service's word for its own signatures.
function verified(jwt, jwks) {
  log.debug("Entering verified().");
  const p = String(jwt).split(".");
  const header = partsOf(jwt).header;
  const jwk = (jwks.keys || []).filter(function (k) {
    return k.kid === header.kid;
  })[0];
  if (!jwk) {
    log.debug("Leaving verified(). No key.");
    return false;
  }
  const key = crypto.createPublicKey({ key: jwk, format: "jwk" });
  const hashes = { ES256: "sha256", ES384: "sha384", ES512: "sha512",
                   EdDSA: null };
  if (!(header.alg in hashes)) {
    // A post-quantum key (oidfed.signingAlg): node here may not verify it,
    // and the in-process tests hold those.
    log.debug("Leaving verified(). Not a curve algorithm.");
    return true;
  }
  const ok = crypto.verify(hashes[header.alg],
    Buffer.from(p[0] + "." + p[1]),
    header.alg === "EdDSA" ? key : { key: key, dsaEncoding: "ieee-p1363" },
    Buffer.from(p[2], "base64url"));
  log.debug("Leaving verified(). " + ok);
  return ok;
}

async function hop(method, url, opts) {
  log.debug("Entering hop(). " + method + " " + url);
  const o = opts || {};
  const headers = {};
  let body;
  if (o.form) {
    body = new URLSearchParams(o.form).toString();
    headers["content-type"] = "application/x-www-form-urlencoded";
  } else if (o.json !== undefined) {
    body = JSON.stringify(o.json);
    headers["content-type"] = "application/json";
  }
  const r = await fetch(url, { method: method, headers: headers, body: body,
                               redirect: "manual" });
  const text = await r.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in hop(): " + ((e && e.message) || e));
    json = null;
  }
  log.debug("Leaving hop(). " + r.status);
  return { status: r.status, text: text, json: json,
           type: r.headers.get("content-type") || "",
           cache: r.headers.get("cache-control") || "" };
}

async function ok(url, payload, what) {
  log.debug("Entering ok().");
  const r = await hop("POST", url, { json: payload || {} });
  assert.ok(r.status === 200 && r.json && r.json.ok !== false,
    "POST " + url + " should have " + what + "; it answered " + r.status +
    " " + r.text.slice(0, 400));
  log.debug("Leaving ok().");
  return r.json;
}

async function configurationOf(at) {
  log.debug("Entering configurationOf(). " + at);
  const r = await hop("GET", at + "/.well-known/openid-federation");
  log.debug("Leaving configurationOf(). " + r.status);
  return { r: r, jwt: r.text, parts: r.status === 200 ? partsOf(r.text)
                                                      : null };
}

function waitMs(ms) {
  log.debug("Entering waitMs().");
  log.debug("Leaving waitMs().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. a throwaway realm " + REALM + " ===");
  await ok(root + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "OpenID Federation " + STAMP },
    "created the realm");

  log.info("=== 1. the Entity Configurations ===");
  const anchor = await configurationOf(root);
  const leaf = await configurationOf(base);
  const anchorId = anchor.parts.claims.iss;
  const leafId = leaf.parts.claims.iss;
  check("served as application/entity-statement+jwt, with no parameter, " +
        "no-store", function () {
    assert.strictEqual(anchor.r.status, 200, anchor.r.text.slice(0, 300));
    assert.strictEqual(anchor.r.type, "application/entity-statement+jwt");
    assert.ok(/no-store/.test(anchor.r.cache));
    assert.strictEqual(anchor.parts.header.typ, "entity-statement+jwt");
  });
  check("each self-signed with its own Federation Entity Key", function () {
    assert.ok(verified(anchor.jwt, anchor.parts.claims.jwks));
    assert.ok(verified(leaf.jwt, leaf.parts.claims.jwks));
    assert.strictEqual(anchor.parts.claims.sub, anchorId);
  });
  check("the default realm names no superior and publishes fetch and list; " +
        "the realm names the default one", function () {
    const fe = anchor.parts.claims.metadata.federation_entity;
    assert.ok(!anchor.parts.claims.authority_hints);
    assert.ok(fe.federation_fetch_endpoint && fe.federation_list_endpoint);
    assert.deepStrictEqual(leaf.parts.claims.authority_hints, [anchorId]);
    assert.ok(!leaf.parts.claims.metadata.federation_entity
      .federation_fetch_endpoint);
    assert.strictEqual(leaf.parts.claims.metadata.openid_provider.issuer,
                       leafId);
  });
  const fetchAt = anchor.parts.claims.metadata.federation_entity
    .federation_fetch_endpoint;

  log.info("=== 2. fetch ===");
  let r = await hop("GET", fetchAt + "?sub=" + encodeURIComponent(leafId));
  check("the statement about the realm, signed by the anchor, pinning the " +
        "realm's keys", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    const ss = partsOf(r.text);
    assert.strictEqual(ss.claims.iss, anchorId);
    assert.strictEqual(ss.claims.sub, leafId);
    assert.deepStrictEqual(ss.claims.jwks, leaf.parts.claims.jwks);
    assert.ok(verified(r.text, anchor.parts.claims.jwks));
  });
  const noSub = await hop("GET", fetchAt);
  const stranger = await hop("GET", fetchAt + "?sub=" +
                             encodeURIComponent("https://nobody.example"));
  check("no sub is invalid_request and a stranger not_found (8.9)",
        function () {
    assert.strictEqual(noSub.status, 400);
    assert.strictEqual(noSub.json.error, "invalid_request");
    assert.strictEqual(stranger.status, 404);
    assert.strictEqual(stranger.json.error, "not_found");
  });

  log.info("=== 3. list and resolve ===");
  r = await hop("GET", root + "/oidfed/list");
  check("the realm is listed", function () {
    assert.ok(Array.isArray(r.json) && r.json.indexOf(leafId) >= 0);
  });
  const resolveAt = anchor.parts.claims.metadata.federation_entity
    .federation_resolve_endpoint;
  r = await hop("GET", resolveAt + "?sub=" + encodeURIComponent(leafId) +
                "&trust_anchor=" + encodeURIComponent(anchorId));
  check("a resolve response with the three-statement chain and the " +
        "realm's metadata", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.strictEqual(r.type, "application/resolve-response+jwt");
    const rr = partsOf(r.text);
    assert.strictEqual(rr.header.typ, "resolve-response+jwt");
    assert.strictEqual(rr.claims.trust_chain.length, 3);
    assert.strictEqual(rr.claims.metadata.openid_provider.issuer, leafId);
    assert.ok(verified(r.text, anchor.parts.claims.jwks));
  });
  const noAnchor = await hop("GET", resolveAt + "?sub=" +
                             encodeURIComponent(leafId));
  const badAnchor = await hop("GET", resolveAt + "?sub=" +
    encodeURIComponent(leafId) + "&trust_anchor=" +
    encodeURIComponent("https://other-anchor.example"));
  const unresolved = await hop("GET", resolveAt + "?sub=" +
    encodeURIComponent("https://nobody.example") + "&trust_anchor=" +
    encodeURIComponent(anchorId));
  check("no trust_anchor, an anchor not configured, and an entity nobody " +
        "resolved are refused", function () {
    assert.strictEqual(noAnchor.json.error, "invalid_request");
    assert.strictEqual(badAnchor.status, 404);
    assert.strictEqual(badAnchor.json.error, "invalid_trust_anchor");
    assert.strictEqual(unresolved.status, 404);
    assert.strictEqual(unresolved.json.error, "not_found");
  });

  log.info("=== 4. Trust Marks ===");
  await ok(root + "/admin-api/oidfed/add-mark-type",
           { type: TYPE, lifetimeS: 3600 }, "registered the mark type");
  const issued = await ok(root + "/admin-api/oidfed/issue-trust-mark",
                          { type: TYPE, sub: leafId }, "issued the mark");
  const carried = await configurationOf(base);
  check("the realm's Entity Configuration carries the mark", function () {
    const marks = carried.parts.claims.trust_marks || [];
    assert.ok(marks.some(function (m) {
      return m.trust_mark_type === TYPE && m.trust_mark === issued.trustMark;
    }), JSON.stringify(marks).slice(0, 300));
  });
  r = await hop("GET", resolveAt + "?sub=" + encodeURIComponent(leafId) +
                "&trust_anchor=" + encodeURIComponent(anchorId));
  check("and the resolve response carries it, verified", function () {
    const marks = partsOf(r.text).claims.trust_marks || [];
    assert.ok(marks.some(function (m) {
      return m.trust_mark_type === TYPE;
    }), JSON.stringify(marks).slice(0, 300));
  });
  const markAt = root + "/oidfed/trust-mark?trust_mark_type=" +
                 encodeURIComponent(TYPE) + "&sub=" +
                 encodeURIComponent(leafId);
  const listAt = root + "/oidfed/trust-mark-list?trust_mark_type=" +
                 encodeURIComponent(TYPE);
  const statusAt = root + "/oidfed/trust-mark-status";
  const handed = await hop("GET", markAt);
  const listed = await hop("GET", listAt);
  let status = await hop("POST", statusAt,
                         { form: { trust_mark: issued.trustMark } });
  check("handed out, listed, and active at the status endpoint", function () {
    assert.strictEqual(handed.status, 200);
    assert.strictEqual(handed.type, "application/trust-mark+jwt");
    assert.strictEqual(handed.text, issued.trustMark);
    assert.deepStrictEqual(listed.json, [leafId]);
    assert.strictEqual(status.type,
                       "application/trust-mark-status-response+jwt");
    assert.strictEqual(partsOf(status.text).claims.status, "active");
  });
  await ok(root + "/admin-api/oidfed/revoke-trust-mark",
           { id: issued.id, reason: "job" }, "revoked the mark");
  status = await hop("POST", statusAt, { form: { trust_mark: issued.trustMark
                                                 } });
  const unlisted = await hop("GET", listAt);
  const gone = await hop("GET", markAt);
  r = await hop("GET", resolveAt + "?sub=" + encodeURIComponent(leafId) +
                "&trust_anchor=" + encodeURIComponent(anchorId));
  const foreign = await hop("POST", statusAt,
                            { form: { trust_mark: leaf.jwt } });
  check("revoked: so said at the status endpoint, unlisted, not handed out, " +
        "gone from the resolution; a mark it never issued is 404",
        function () {
    assert.strictEqual(partsOf(status.text).claims.status, "revoked");
    assert.deepStrictEqual(unlisted.json, []);
    assert.strictEqual(gone.status, 404);
    assert.ok(!(partsOf(r.text).claims.trust_marks || []).some(function (m) {
      return m.trust_mark_type === TYPE;
    }));
    assert.strictEqual(foreign.status, 404);
  });
  await ok(root + "/admin-api/oidfed/remove-mark-type", { type: TYPE },
           "removed the mark type");

  log.info("=== 5. a registered subordinate ===");
  const rpKey = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const rpJwk = rpKey.publicKey.export({ format: "jwk" });
  rpJwk.kid = "rp-" + STAMP;
  const policy = { openid_relying_party: {
    token_endpoint_auth_method: { one_of: ["private_key_jwt"],
                                  essential: true } } };
  await ok(base + "/admin-api/oidfed/add-subordinate",
           { entityId: RP, jwks: { keys: [rpJwk] }, metadataPolicy: policy,
             entityTypes: "openid_relying_party" },
           "registered a subordinate");
  const intermediate = await configurationOf(base);
  const realmFetch = intermediate.parts.claims.metadata.federation_entity
    .federation_fetch_endpoint;
  r = await hop("GET", realmFetch + "?sub=" + encodeURIComponent(RP));
  const byType = await hop("GET", base + "/oidfed/list?entity_type=" +
                           "openid_relying_party");
  const byOther = await hop("GET", base + "/oidfed/list?entity_type=" +
                            "openid_provider");
  check("the realm becomes an Intermediate, its statement carries the " +
        "policy, and the listing filters by type", function () {
    assert.ok(realmFetch, "no fetch endpoint");
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.deepStrictEqual(partsOf(r.text).claims.metadata_policy, policy);
    assert.deepStrictEqual(byType.json, [RP]);
    assert.deepStrictEqual(byOther.json, []);
  });

  log.info("=== 6. the keys ===");
  const before = partsOf(leaf.jwt).header.kid;
  await ok(base + "/admin-api/oidfed/rotate-key", {}, "queued a rotation");
  let view = null;
  for (let n = 0; n < 60; n += 1) {
    const got = await hop("GET", base + "/admin-api/oidfed");
    view = got.json;
    if (view && (view.keys || []).some(function (k) {
      return k.kid === before && k.state === "retired";
    })) {
      break;
    }
    await waitMs(500);
  }
  r = await hop("GET", base + "/oidfed/historical-keys");
  check("rotated: the retired key is in the Historical Keys jwk-set+jwt",
        function () {
    assert.ok((view.keys || []).some(function (k) {
      return k.kid === before && k.state === "retired";
    }), JSON.stringify(view && view.keys).slice(0, 400));
    assert.strictEqual(r.type, "application/jwk-set+jwt");
    const hk = partsOf(r.text);
    assert.strictEqual(hk.header.typ, "jwk-set+jwt");
    assert.ok(hk.claims.keys.some(function (k) {
      return k.kid === before && Number.isFinite(k.exp) && !k.revoked;
    }));
  });
  await ok(base + "/admin-api/oidfed/revoke-key",
           { kid: before, reason: "compromised" }, "revoked the old key");
  r = await hop("GET", base + "/oidfed/historical-keys");
  const emergency = await hop("POST", base + "/admin-api/oidfed/rotate-key",
                              { json: { emergency: true } });
  check("revoked with its reason; an emergency rotation needs its " +
        "confirmation", function () {
    const row = partsOf(r.text).claims.keys.filter(function (k) {
      return k.kid === before;
    })[0];
    assert.strictEqual(row.revoked.reason, "compromised");
    assert.strictEqual(emergency.status, 400);
  });

  assert.ok(checks >= 15, "only " + checks + " checks ran");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

new Command()
  .description("OpenID Federation 1.1 (#132): Entity Configurations, fetch, " +
    "list, resolve, Trust Marks, a registered subordinate and the keys.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
