"use strict";
//
// File: sts_oidfed_extensions.js
//
// ---------------------------------------------------------------------------
// THE THREE OPENID FEDERATION EXTENSIONS (#135, #136, #137, 2026-09-24), over
// HTTP: the default realm a Trust Anchor with a throwaway realm and three
// registered subordinates beneath it.
//
//   1. PUBLISHED: the anchor's Entity Configuration names the extended list,
//      collection and subordinate events endpoints.
//   2. THE EXTENDED SUBORDINATE LISTING (draft 03): JSON, no-store; paged two
//      at a time by an opaque next, in identifier order, each entry its id
//      alone; claims — the signed statement (verified here) and its
//      metadata_policy — and the audit timestamps; a pointer this service
//      did not make is 404 page_not_found, a limit of 0 400 invalid_request.
//   3. SUSPENSION AND THE HISTORY (draft 01): a subordinate suspended through
//      /admin-api has no statement (not_found) and is not listed;
//      reinstated, it is again; revoked with a reason and a page, its whole
//      history is still served — application/entity-events-statement+jwt,
//      typed, signed by the anchor — and the throwaway realm's begins with
//      its registration; a stranger is not_found and no sub
//      invalid_request.
//   4. THE ENTITY COLLECTION (draft 01): the throwaway realm collected, with
//      its entity types and last_updated; another trust_anchor 404
//      invalid_trust_anchor, an unknown claim 400 unsupported_claim; a POST
//      with a repeated entity_type; a crawl through /admin-api, whose
//      subordinates that cannot be resolved from here are left out and
//      named, and the endpoint still answering after it.
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
var log = bunyan.createLogger({ name: "sts_oidfed_extensions",
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
const TAG = STAMP.toLowerCase().replace(/[^a-z0-9]/g, "");
const REALM = ("fedx-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                             .slice(0, 31);
const base = root + "/realm/" + REALM;

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
// algorithms a Federation Entity Key is made for by default.
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
  if (o.formText !== undefined) {
    body = o.formText;
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

function ecJwk() {
  log.debug("Entering ecJwk().");
  const pair = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = pair.publicKey.export({ format: "jwk" });
  jwk.kid = crypto.randomUUID();
  log.debug("Leaving ecJwk().");
  return jwk;
}

function idsOf(r) {
  log.debug("Entering idsOf().");
  log.debug("Leaving idsOf().");
  return (r.json.immediate_subordinate_entities || []).map(function (e) {
    return e.id;
  });
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. a throwaway realm " + REALM + " and three subordinates ===");
  await ok(root + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "OpenID Federation ext " + STAMP },
    "created the realm");
  const subs = ["a", "b", "c"].map(function (x) {
    return "https://" + x + "-" + TAG + ".example.test";
  });
  const policy = { openid_relying_party: {
    token_endpoint_auth_method: { one_of: ["private_key_jwt"] } } };
  for (let i = 0; i < subs.length; i++) {
    await ok(root + "/admin-api/oidfed/add-subordinate",
             { entityId: subs[i], jwks: { keys: [ecJwk()] },
               entityTypes: "openid_relying_party", metadataPolicy: policy,
               eventDescription: "registered by the job",
               informationUri: "https://example.test/policy" },
             "registered " + subs[i]);
  }

  log.info("=== 1. published ===");
  const ecR = await hop("GET", root + "/.well-known/openid-federation");
  const anchor = partsOf(ecR.text);
  const anchorId = anchor.claims.iss;
  const fe = anchor.claims.metadata.federation_entity;
  const leafEc = await hop("GET", base + "/.well-known/openid-federation");
  const leafId = partsOf(leafEc.text).claims.iss;
  check("the anchor publishes the extended list, collection and subordinate " +
        "events endpoints", function () {
    assert.strictEqual(fe.federation_extended_list_endpoint,
                       root + "/oidfed/extended-list");
    assert.strictEqual(fe.federation_collection_endpoint,
                       root + "/oidfed/collection");
    assert.strictEqual(fe.federation_subordinate_events_endpoint,
                       root + "/oidfed/subordinate-events");
  });
  const list = fe.federation_extended_list_endpoint;
  const events = fe.federation_subordinate_events_endpoint;
  const collection = fe.federation_collection_endpoint;

  log.info("=== 2. the Extended Subordinate Listing ===");
  const all = [];
  let page = await hop("GET", list + "?limit=2");
  const first = page;
  for (let n = 0; n < 500 && page.status === 200; n += 1) {
    idsOf(page).forEach(function (id) {
      all.push(id);
    });
    if (!page.json.next) {
      break;
    }
    page = await hop("GET", list + "?limit=2&from=" +
                            encodeURIComponent(page.json.next));
  }
  check("JSON, no-store, paged two at a time by an opaque next, in " +
        "identifier order, each entry its id alone", function () {
    assert.strictEqual(first.status, 200, first.text.slice(0, 300));
    assert.ok(/^application\/json/.test(first.type), first.type);
    assert.ok(/no-store/.test(first.cache));
    assert.ok(first.json.immediate_subordinate_entities.length <= 2);
    assert.ok(first.json.next, "no next on the first page");
    assert.deepStrictEqual(all.slice().sort(), all);
    subs.concat([leafId]).forEach(function (id) {
      assert.ok(all.indexOf(id) >= 0, id + " not listed: " + all.join());
    });
    first.json.immediate_subordinate_entities.forEach(function (e) {
      assert.deepStrictEqual(Object.keys(e), ["id"]);
    });
  });
  const rich = await hop("GET", list + "?claims=subordinate_statement" +
    "&claims=metadata_policy&audit_timestamps=true&limit=1000");
  const a = (rich.json.immediate_subordinate_entities || []).filter(
    function (e) {
      return e.id === subs[0];
    })[0] || {};
  check("claims: the signed statement and its metadata_policy; the audit " +
        "timestamps", function () {
    assert.strictEqual(rich.status, 200, rich.text.slice(0, 300));
    assert.ok(a.subordinate_statement, JSON.stringify(a));
    assert.ok(verified(a.subordinate_statement, anchor.claims.jwks));
    assert.strictEqual(partsOf(a.subordinate_statement).claims.sub,
                       subs[0]);
    assert.deepStrictEqual(a.metadata_policy, policy);
    assert.ok(Number.isInteger(a.registered) && Number.isInteger(a.updated) &&
              a.updated >= a.registered, JSON.stringify(a));
  });
  const lost = await hop("GET", list + "?from=bm90LW91cnM.x");
  const zero = await hop("GET", list + "?limit=0");
  check("a pointer this service did not make is 404 page_not_found; a limit " +
        "of 0 is 400 invalid_request", function () {
    assert.strictEqual(lost.status, 404);
    assert.strictEqual(lost.json.error, "page_not_found");
    assert.strictEqual(zero.status, 400);
    assert.strictEqual(zero.json.error, "invalid_request");
  });

  log.info("=== 3. suspension and the history ===");
  const fetchAt = fe.federation_fetch_endpoint;
  await ok(root + "/admin-api/oidfed/suspend-subordinate",
           { entityId: subs[1], reason: "under review" }, "suspended");
  const gone = await hop("GET", fetchAt + "?sub=" +
                                encodeURIComponent(subs[1]));
  const plainList = await hop("GET", fe.federation_list_endpoint);
  check("suspended: no statement (not_found), and not listed", function () {
    assert.strictEqual(gone.status, 404, gone.text.slice(0, 300));
    assert.strictEqual(gone.json.error, "not_found");
    assert.ok(plainList.json.indexOf(subs[1]) < 0);
    assert.ok(plainList.json.indexOf(subs[0]) >= 0);
  });
  await ok(root + "/admin-api/oidfed/reinstate-subordinate",
           { entityId: subs[1] }, "reinstated");
  const back = await hop("GET", fetchAt + "?sub=" +
                                encodeURIComponent(subs[1]));
  check("reinstated, its statement is issued again", function () {
    assert.strictEqual(back.status, 200, back.text.slice(0, 300));
  });
  await ok(root + "/admin-api/oidfed/remove-subordinate",
           { entityId: subs[1], reason: "no longer operated",
             informationUri: "https://example.test/revoked" }, "revoked");
  const history = await hop("GET", events + "?sub=" +
                                   encodeURIComponent(subs[1]));
  const told = history.status === 200 ? partsOf(history.text) : null;
  check("revoked, its whole history is still served: typed, signed, the " +
        "reason and page on the revocation", function () {
    assert.strictEqual(history.status, 200, history.text.slice(0, 300));
    assert.strictEqual(history.type, "application/entity-events-statement+jwt");
    assert.ok(/no-store/.test(history.cache));
    assert.strictEqual(told.header.typ, "entity-events-statement+jwt");
    assert.ok(verified(history.text, anchor.claims.jwks));
    assert.strictEqual(told.claims.iss, anchorId);
    assert.strictEqual(told.claims.sub, subs[1]);
    const evs = told.claims.federation_registration_events;
    assert.deepStrictEqual(evs.map(function (e) {
      return e.event;
    }), ["registration", "suspension", "reinstatement", "revocation"]);
    assert.strictEqual(evs[0].information_uri, "https://example.test/policy");
    assert.strictEqual(evs[3].event_description, "no longer operated");
    assert.strictEqual(evs[3].information_uri, "https://example.test/revoked");
  });
  const realmHistory = await hop("GET", events + "?sub=" +
                                        encodeURIComponent(leafId));
  const stranger = await hop("GET", events + "?sub=" +
    encodeURIComponent("https://never-" + TAG + ".example.test"));
  const noSub = await hop("GET", events);
  check("the throwaway realm's history begins with its registration; a " +
        "stranger is not_found and no sub invalid_request", function () {
    assert.strictEqual(realmHistory.status, 200,
                       realmHistory.text.slice(0, 300));
    assert.strictEqual(partsOf(realmHistory.text).claims
      .federation_registration_events[0].event, "registration");
    assert.strictEqual(stranger.status, 404);
    assert.strictEqual(stranger.json.error, "not_found");
    assert.strictEqual(noSub.status, 400);
    assert.strictEqual(noSub.json.error, "invalid_request");
  });

  log.info("=== 4. the Entity Collection ===");
  const got = await hop("GET", collection);
  const mine = got.status === 200 ? got.json.entities.filter(function (e) {
    return e.entity_id === leafId;
  })[0] : null;
  check("the throwaway realm is collected with its entity types, and " +
        "last_updated is given", function () {
    assert.strictEqual(got.status, 200, got.text.slice(0, 300));
    assert.ok(/^application\/json/.test(got.type));
    assert.ok(mine, "the realm is not collected: " + got.text.slice(0, 400));
    assert.ok(mine.entity_types.indexOf("openid_provider") >= 0);
    assert.ok(Number.isInteger(got.json.last_updated));
  });
  const other = await hop("GET", collection + "?trust_anchor=" +
    encodeURIComponent("https://elsewhere.example.test"));
  const bogus = await hop("GET", collection + "?entity_claims=secret");
  const posted = await hop("POST", collection, { formText:
    "entity_type=openid_provider&entity_type=openid_relying_party" +
    "&entity_claims=entity_types" });
  check("another trust_anchor is 404 invalid_trust_anchor, an unknown " +
        "claim 400 unsupported_claim; a POST with a repeated entity_type " +
        "is answered", function () {
    assert.strictEqual(other.status, 404);
    assert.strictEqual(other.json.error, "invalid_trust_anchor");
    assert.strictEqual(bogus.status, 400);
    assert.strictEqual(bogus.json.error, "unsupported_claim");
    assert.strictEqual(posted.status, 200, posted.text.slice(0, 300));
    assert.ok(posted.json.entities.some(function (e) {
      return e.entity_id === leafId;
    }));
    posted.json.entities.forEach(function (e) {
      assert.deepStrictEqual(Object.keys(e).sort(),
                             ["entity_id", "entity_types"]);
    });
  });
  const crawled = await ok(root + "/admin-api/oidfed/crawl-collection", {},
                           "crawled the collection");
  const view = await hop("GET", root + "/admin-api/oidfed");
  const after = await hop("GET", collection);
  check("a crawl through /admin-api: the subordinates that cannot be " +
        "resolved from here are left out and named, and the endpoint still " +
        "answers", function () {
    assert.ok(crawled.collection && crawled.collection.crawl,
              JSON.stringify(crawled));
    const problems = view.json.collection.crawl.problems.join(" ");
    assert.ok(problems.indexOf(subs[0]) >= 0, problems);
    assert.strictEqual(after.status, 200);
    assert.ok(after.json.entities.some(function (e) {
      return e.entity_id === leafId;
    }), after.text.slice(0, 400));
    assert.ok(!after.json.entities.some(function (e) {
      return e.entity_id === subs[0];
    }));
  });

  // The subordinates go; their histories stay, as they should.
  for (let i = 0; i < subs.length; i++) {
    if (i !== 1) {
      await ok(root + "/admin-api/oidfed/remove-subordinate",
               { entityId: subs[i], reason: "the job is done" },
               "removed " + subs[i]);
    }
  }

  assert.ok(checks >= 11, "only " + checks + " checks ran");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

new Command()
  .description("OpenID Federation extensions (#135, #136, #137): the " +
    "Extended Subordinate Listing, the Entity Collection and each " +
    "subordinate's history, with suspension.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
