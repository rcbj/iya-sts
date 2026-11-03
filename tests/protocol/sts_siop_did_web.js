// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_siop_did_web.js
//
// ---------------------------------------------------------------------------
// A did:web PROVED, PINNED, ROTATED AND REFUSED, OVER HTTP (#693,
// 2026-11-03). `oid4vc/siop.ts` fetches a did:web document to enrol the DID
// by proof and to sign in with it, and a did:web must be https — so until
// the test peer could host one (`tests/peer/peer_did.js`, the `did` role)
// every claim below was held only in process (`tests/siop.js`), with a
// stubbed `fetchDocument`.
//
// The job is the person and holds the private keys; the peer publishes the
// DID document at `https://test-peer:9600/t/<tenant>/did/<name>/did.json`,
// trusted through the realm's `federation.outboundCaFile`, and records
// every fetch — so "dialled once", "not dialled" are asserted at the far
// end rather than inferred.
//
// In a DEVELOPMENT realm (product never dials a private address, and the
// peer is on one — section 6 is that refusal):
//
//   1. THE PERSON ENROLS A did:web BY PROOF: signed in with their password,
//      they answer `/authn/wallet?siop=1&enrol=1` with an ID Token whose
//      `kid` names the document's key. It lands on /portal/self-issued,
//      is listed as proved by the wallet with that key's RFC 7638
//      thumbprint pinned, and the peer saw ONE fetch.
//   2. A TOKEN THAT FAILS ITS OTHER CHECKS DIALS NOTHING: an enrolment
//      answered with another nonce is refused, and the peer saw no fetch.
//   3. THE SIGN-IN: the screen's self-issued link, the same key, and the
//      waiting authorization request completes for the person.
//   4. THE DOCUMENT ROTATED UNDER THE PIN: the peer now names a second key
//      only; an ID Token signed by it is refused (403, the pin), though the
//      document says the key is the DID's.
//   5. PROVED AGAIN: the person re-enrols by proof with the second key,
//      which re-pins it, and signs in with it.
//   6. A WITHDRAWN DOCUMENT: an enrolment of a did:web whose document
//      answers 404 is refused, and nothing is enrolled.
//   7. PRODUCT REFUSES THE ADDRESS: in a PRODUCT realm, the same enrolment
//      is refused and the peer saw no fetch — `fetchPublished()` refuses a
//      private address there (`mode.dialsInternalAddresses()`).
//
// `testPeer: true`: with no peer (an AWS target) the job is skipped and
// says so.
//
// OWNED HERE (local: true): the enrolment, the pin and the sign-in are this
// repository's own.
// ---------------------------------------------------------------------------

const assert = require("assert");
const crypto = require("crypto");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const registry = require("./sts_applications.js");
const consentScreen = require("./consent_screen.js");
const walletSignin = require("./wallet_signin.js");
const testPeer = require("./test_peer.js");

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
var log = bunyan.createLogger({ name: "sts_siop_did_web",
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
const DEV = ("didweb-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                             .slice(0, 31);
const PROD = ("didwebp-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                               .slice(0, 31);
const CLIENT_ID = "sts-siop-did-web";
const REDIRECT_URI = "https://rp.sts-siop-did-web.example.test/cb";
const HOLDER = names.usernameFor("didweb-holder");
const PASSWORD = "Didweb-holder-" + crypto.randomBytes(9)
  .toString("base64url") + "-Aa1!";

const FLOOR = 8;

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function payloadOf(jwt) {
  log.debug("Entering payloadOf().");
  log.debug("Leaving payloadOf().");
  return JSON.parse(Buffer.from(String(jwt).split(".")[1], "base64url")
    .toString("utf8"));
}

function realmBase(realm) {
  log.debug("Entering realmBase().");
  log.debug("Leaving realmBase().");
  return root + "/realm/" + realm;
}

// A P-256 key and its RFC 7638 thumbprint, as the pin records it.
function key() {
  log.debug("Entering key().");
  const pair = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const j = pair.publicKey.export({ format: "jwk" });
  const jwk = { kty: "EC", crv: "P-256", x: j.x, y: j.y };
  const thumbprint = crypto.createHash("sha256").update(JSON.stringify(
    { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y })).digest("base64url");
  log.debug("Leaving key().");
  return { privateKey: pair.privateKey, jwk: jwk, thumbprint: thumbprint };
}

// The DID document: one JsonWebKey2020 method per key, `#key-<n>`, each in
// `authentication`.
function documentOf(did, keys) {
  log.debug("Entering documentOf().");
  const methods = keys.map(function (k, i) {
    return { id: did + "#key-" + (i + 1), type: "JsonWebKey2020",
             controller: did, publicKeyJwk: k.jwk };
  });
  log.debug("Leaving documentOf().");
  return { "@context": ["https://www.w3.org/ns/did/v1"], id: did,
           verificationMethod: methods,
           authentication: methods.map(function (m) {
             return m.id;
           }) };
}

// A self-issued ID Token for the DID, signed by `k`, naming it as `kid`.
function selfIssued(did, kid, k, aud, nonce) {
  log.debug("Entering selfIssued().");
  const now = Math.floor(Date.now() / 1000);
  const input = Buffer.from(JSON.stringify({ alg: "ES256", typ: "JWT",
                                             kid: kid }))
    .toString("base64url") + "." +
    Buffer.from(JSON.stringify({ iss: did, sub: did, aud: aud, nonce: nonce,
                                 iat: now, exp: now + 300 }))
      .toString("base64url");
  const signature = crypto.sign("sha256", Buffer.from(input),
    { key: k.privateKey, dsaEncoding: "ieee-p1363" });
  log.debug("Leaving selfIssued().");
  return input + "." + signature.toString("base64url");
}

function jar(seed) {
  log.debug("Entering jar().");
  const cookies = {};
  String(seed || "").split(/;\s*/).forEach(function (pair) {
    const eq = pair.indexOf("=");
    if (eq > 0) {
      cookies[pair.slice(0, eq).trim()] = pair.slice(eq + 1).trim();
    }
  });
  log.debug("Leaving jar().");
  return {
    header: function header() {
      log.debug("Entering header().");
      log.debug("Leaving header().");
      return Object.keys(cookies).map(function (k) {
        return k + "=" + cookies[k];
      }).join("; ");
    },
    take: function take(response) {
      log.debug("Entering take().");
      const set = typeof response.headers.getSetCookie === "function"
        ? response.headers.getSetCookie() : [];
      set.forEach(function (line) {
        const pair = line.split(";")[0];
        const eq = pair.indexOf("=");
        const name = pair.slice(0, eq).trim();
        const value = pair.slice(eq + 1).trim();
        if (/Max-Age=0/i.test(line) || value === "") {
          delete cookies[name];
        } else {
          cookies[name] = value;
        }
      });
      log.debug("Leaving take().");
      return set;
    }
  };
}

async function hop(who, method, url, opts) {
  log.debug("Entering hop(). " + method + " " + url);
  const o = opts || {};
  const headers = Object.assign({}, o.headers || {});
  let body;
  if (o.form) {
    body = new URLSearchParams(o.form).toString();
    headers["content-type"] = "application/x-www-form-urlencoded";
  } else if (o.json !== undefined) {
    body = JSON.stringify(o.json);
    headers["content-type"] = "application/json";
  }
  if (who && who.header()) {
    headers.cookie = who.header();
  }
  const r = await fetch(url, { method: method, headers: headers, body: body,
                               redirect: "manual" });
  if (who) {
    who.take(r);
  }
  const text = await r.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in hop(): " + ((e && e.message) || e));
    json = null;
  }
  const location = r.headers.get("location") || "";
  log.debug("Leaving hop(). " + r.status);
  return { status: r.status, text: text, json: json,
           location: location ? new URL(location, url).toString() : "" };
}

async function ok(url, payload, what) {
  log.debug("Entering ok().");
  const r = await hop(null, "POST", url, { json: payload || {} });
  assert.ok(r.status === 200 && r.json && r.json.ok !== false,
    "POST " + url + " should have " + what + "; it answered " + r.status +
    " " + r.text.slice(0, 400));
  log.debug("Leaving ok().");
  return r.json;
}

async function setting(realm, key_, value) {
  log.debug("Entering setting(). " + realm + " " + key_);
  await ok(realmBase(realm) + "/admin-api/config/set",
           { key: key_, value: value }, realm + ": set " + key_);
  log.debug("Leaving setting().");
}

// Publishes (or replaces) the tenant's document `name` at the peer.
async function publish(view, name, doc) {
  log.debug("Entering publish(). " + name);
  const r = await hop(null, "PUT", testPeer.url() + "/t/" +
                      encodeURIComponent(view.tenant) + "/did/" + name +
                      "/did.json", { json: doc });
  assert.ok(r.status === 200 && r.json && r.json.ok, "the peer refused " +
            "the document: " + r.status + " " + r.text.slice(0, 300));
  log.debug("Leaving publish().");
}

async function withdraw(view, name) {
  log.debug("Entering withdraw(). " + name);
  await hop(null, "DELETE", testPeer.url() + "/t/" +
            encodeURIComponent(view.tenant) + "/did/" + name + "/did.json");
  log.debug("Leaving withdraw().");
}

// The `did` role's fetches of `name` after `since`.
async function fetchesOf(view, name, since) {
  log.debug("Entering fetchesOf(). " + name);
  const got = await testPeer.received(view.tenant, "did", since);
  log.debug("Leaving fetchesOf().");
  return got.events.filter(function (row) {
    return row.name === name;
  });
}

// The wallet's request for a transaction the wait page `waitUrl` names.
async function walletRequest(base, who, waitUrl) {
  log.debug("Entering walletRequest().");
  const state = walletSignin.fromWaitUrl(waitUrl).state;
  const waiting = await walletSignin.view(base, who, state);
  const view = (waiting.json && waiting.json.view) || {};
  const requestUri = view.sameDevice ?
    new URL(view.sameDevice).searchParams.get("request_uri") : "";
  assert.ok(requestUri, "no request_uri on the wait page: " +
            String(waiting.text).slice(0, 300));
  const ro = await hop(null, "GET", requestUri);
  log.debug("Leaving walletRequest().");
  return payloadOf(ro.text);
}

// Answers a wallet request with an ID Token, under its response mode
// (`direct_post.jwt`, encrypted, by default), and collects in `who` where
// the response endpoint sent the wallet back. Asserts nothing: a refusal
// may come from either step. Answers { answered, collected }.
async function answerAndCollect(base, who, request, idToken, waitUrl) {
  log.debug("Entering answerAndCollect().");
  const answered = await hop(null, "POST", request.response_uri, {
    form: walletSignin.answerForm(request, { state: request.state,
                                             id_token: idToken }) });
  const back = answered.json && answered.json.redirect_uri;
  const collected = await walletSignin.collect(base, who, back || waitUrl);
  log.debug("Leaving answerAndCollect(). " + answered.status + " " +
            collected.status);
  return { answered: answered, collected: collected };
}

// An enrolment by proof of `did`, answered by `make(request)`.
async function enrol(base, who, did, make) {
  log.debug("Entering enrol().");
  const door = (await walletSignin.start(base, who,
                                         { siop: "1", enrol: "1" })).door;
  assert.strictEqual(door.status, 303, "the enrolment did not start: " +
                     door.status + " " + String(door.text).slice(0, 300));
  const request = await walletRequest(base, who, door.location);
  const out = await answerAndCollect(base, who, request, make(request),
                                     door.location);
  log.debug("Leaving enrol().");
  return out;
}

function enrolledOk(out) {
  log.debug("Entering enrolledOk().");
  log.debug("Leaving enrolledOk().");
  return out.answered.status === 200 && out.collected.status === 303 &&
         /\/portal\/self-issued\?enrolled=1/.test(out.collected.location);
}

async function rowFor(base, did) {
  log.debug("Entering rowFor().");
  const r = await hop(null, "GET", base + "/admin-api/users/" +
                      "self-issued-subjects?user=" +
                      encodeURIComponent(HOLDER));
  assert.strictEqual(r.status, 200, r.text.slice(0, 300));
  log.debug("Leaving rowFor().");
  return (r.json.subjects || []).filter(function (one) {
    return one.subject === did;
  })[0] || null;
}

// A sign-in through the screen's self-issued link, answered by
// `make(request)`, the authorization request followed to the code and the
// code redeemed. Answers { collected, tokens }.
async function signIn(base, make) {
  log.debug("Entering signIn().");
  const who = jar();
  const verifier = crypto.randomBytes(32).toString("base64url");
  const authorized = await hop(who, "GET", base + "/oauth2/authorize?" +
    new URLSearchParams({ response_type: "code", client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI, scope: "openid", state: "s-" + STAMP,
      nonce: "n-" + STAMP,
      code_challenge: crypto.createHash("sha256").update(verifier)
        .digest("base64url"),
      code_challenge_method: "S256" }).toString());
  const authnId = new URL(authorized.location || base, base).searchParams
    .get("authn") || "";
  await hop(who, "GET", authorized.location);
  const started = await walletSignin.start(base, who,
                                           { authn: authnId, siop: "1" });
  assert.strictEqual(started.door.status, 303, "the sign-in did not " +
                     "start: " + String(started.door.text).slice(0, 300));
  const request = await walletRequest(base, who, started.door.location);
  const out = await answerAndCollect(base, who, request, make(request),
                                     started.door.location);
  let at = out.collected.status === 303 ? out.collected.location : "";
  for (let n = 0; n < 6 && at && at.indexOf(root) === 0 &&
                  !consentScreen.isConsentScreen(at); n += 1) {
    at = (await hop(who, "GET", at)).location;
  }
  if (at) {
    const settled = await consentScreen.settleAuthorization({
      base: base, location: at, cookie: who.header() });
    at = settled.location || at;
  }
  const code = at ? new URL(at).searchParams.get("code") : null;
  const tokens = code ? await hop(null, "POST", base + "/oauth2/token", {
    form: { grant_type: "authorization_code", code: code,
            redirect_uri: REDIRECT_URI, client_id: CLIENT_ID,
            code_verifier: verifier } }) : null;
  log.debug("Leaving signIn(). code=" + !!code);
  return { collected: out.collected, answered: out.answered,
           tokens: tokens };
}

async function setUpRealm(realm) {
  log.debug("Entering setUpRealm(). " + realm);
  const base = realmBase(realm);
  // RISK SCORING (#62) is off for sts_admin_client_policies.js's reason.
  await setting(realm, "risk.assessSignIns", false);
  await setting(realm, "oid4vp.signInSelfIssued", true);
  if (process.env.TEST_PEER_CA_FILE) {
    await setting(realm, "federation.outboundCaFile",
                  process.env.TEST_PEER_CA_FILE);
  } else if (realm === DEV) {
    log.info(DEV + ": no directory is shared with the service, so the " +
             "peer's certificate is NOT verified here " +
             "(federation.outboundSkipTlsVerification, development only).");
    await setting(realm, "federation.outboundSkipTlsVerification", true);
  }
  await registry.provision(base, {
    identifier: CLIENT_ID, name: "#693 did:web job",
    protocols: ["oauth2", "oidc"],
    fields: { oauthClientId: CLIENT_ID,
              oauthGrantType: ["authorization_code"],
              oauthTokenEndpointAuthMethod: "none",
              oauthConfidential: "FALSE",
              oauthRedirectUri: [REDIRECT_URI],
              oauthResponseType: ["code"],
              oauthScope: ["openid"] },
    why: "the relying party sts_siop_did_web.js signs its holder in for"
  });
  await registry.ensurePerson(base, HOLDER, PASSWORD);
  const signedIn = await registry.authorizationCode(base, {
    clientId: CLIENT_ID, redirectUri: REDIRECT_URI, username: HOLDER,
    password: PASSWORD, scope: "openid" });
  const view = await testPeer.tenant(testPeer.tenantId("did-" + realm),
                                     base, root);
  log.debug("Leaving setUpRealm().");
  return { base: base, browser: jar(signedIn.cookie), view: view };
}

async function development() {
  log.debug("Entering development().");
  const dev = await setUpRealm(DEV);
  const base = dev.base;
  const did = dev.view.did.prefix + "holder";
  const first = key();
  await publish(dev.view, "holder", documentOf(did, [first]));

  log.info("=== 1. enrolled by proof ===");
  let since = await testPeer.mark(dev.view.tenant);
  const enrolled = await enrol(base, dev.browser, did, function (request) {
    return selfIssued(did, did + "#key-1", first, request.client_id,
                      request.nonce);
  });
  let row = await rowFor(base, did);
  let fetched = await fetchesOf(dev.view, "holder", since);
  check("the person proves " + did + ": it is enrolled as proved by the " +
        "wallet, the key's thumbprint pinned, after ONE fetch over TLS",
        function () {
    assert.ok(enrolledOk(enrolled), enrolled.answered.status + " " +
              enrolled.answered.text.slice(0, 300) + " / " +
              enrolled.collected.status + " " +
              String(enrolled.collected.text).slice(0, 300));
    assert.ok(row, "not listed");
    assert.strictEqual(row.proof, "wallet", JSON.stringify(row));
    assert.ok([].concat(row.pinnedKeys || []).join(" ")
      .indexOf(first.thumbprint) >= 0, JSON.stringify(row));
    assert.strictEqual(fetched.length, 1, JSON.stringify(fetched));
    assert.strictEqual(fetched[0].tls, true);
  });

  log.info("=== 2. a token that fails its other checks dials nothing ===");
  since = await testPeer.mark(dev.view.tenant);
  const wrongNonce = await enrol(base, dev.browser, did, function (request) {
    return selfIssued(did, did + "#key-1", first, request.client_id,
                      "another-nonce");
  });
  fetched = await fetchesOf(dev.view, "holder", since);
  check("an enrolment answered for another nonce is refused, and the " +
        "document is not fetched", function () {
    assert.ok(!enrolledOk(wrongNonce), "it was enrolled");
    assert.strictEqual(fetched.length, 0, JSON.stringify(fetched));
  });

  log.info("=== 3. the sign-in ===");
  const signedIn = await signIn(base, function (request) {
    return selfIssued(did, did + "#key-1", first, request.client_id,
                      request.nonce);
  });
  check("the did:web signs the person in", function () {
    assert.ok(signedIn.tokens, "no code: " + signedIn.collected.status +
              " " + String(signedIn.collected.text).slice(0, 300));
    assert.strictEqual(signedIn.tokens.status, 200,
                       signedIn.tokens.text.slice(0, 300));
    assert.ok(/^urn:uuid:/.test(String(payloadOf(
      signedIn.tokens.json.id_token).sub)));
  });

  log.info("=== 4. the document rotated under the pin ===");
  const second = key();
  await publish(dev.view, "holder", documentOf(did, [second]));
  const rotated = await signIn(base, function (request) {
    return selfIssued(did, did + "#key-1", second, request.client_id,
                      request.nonce);
  });
  check("a key the document now names, and the pin does not, signs " +
        "nobody in", function () {
    assert.ok(!rotated.tokens, "it signed somebody in");
    // Refused where the token is judged: the response endpoint, or the
    // browser's collection (a 403 page), as a sign-in's refusals are.
    assert.ok(rotated.answered.status >= 400 ||
              rotated.collected.status === 403,
              rotated.answered.status + " " +
              rotated.answered.text.slice(0, 300) + " / " +
              rotated.collected.status + " " +
              String(rotated.collected.text).slice(0, 300));
  });

  log.info("=== 5. proved again ===");
  const again = await enrol(base, dev.browser, did, function (request) {
    return selfIssued(did, did + "#key-1", second, request.client_id,
                      request.nonce);
  });
  row = await rowFor(base, did);
  const afterRepin = await signIn(base, function (request) {
    return selfIssued(did, did + "#key-1", second, request.client_id,
                      request.nonce);
  });
  check("proving it again with the new key re-pins it, and that key signs " +
        "the person in", function () {
    assert.ok(enrolledOk(again), again.answered.status + " " +
              again.answered.text.slice(0, 300) + " / " +
              again.collected.status + " " +
              String(again.collected.text).slice(0, 300));
    assert.ok([].concat(row.pinnedKeys || []).join(" ")
      .indexOf(second.thumbprint) >= 0, JSON.stringify(row));
    assert.ok(afterRepin.tokens && afterRepin.tokens.status === 200,
              afterRepin.collected.status + " " +
              String(afterRepin.collected.text).slice(0, 300));
  });

  log.info("=== 6. a withdrawn document ===");
  const otherDid = dev.view.did.prefix + "withdrawn";
  const other = key();
  await publish(dev.view, "withdrawn", documentOf(otherDid, [other]));
  await withdraw(dev.view, "withdrawn");
  since = await testPeer.mark(dev.view.tenant);
  const missing = await enrol(base, dev.browser, otherDid,
                              function (request) {
    return selfIssued(otherDid, otherDid + "#key-1", other,
                      request.client_id, request.nonce);
  });
  fetched = await fetchesOf(dev.view, "withdrawn", since);
  check("a did:web whose document answers 404 is not enrolled, after one " +
        "attempt to fetch it", function () {
    assert.ok(!enrolledOk(missing), "it was enrolled");
    assert.strictEqual(fetched.length, 1, JSON.stringify(fetched));
    assert.strictEqual(fetched[0].found, false);
  });
  const missingRow = await rowFor(base, otherDid);
  check("and it is not listed", function () {
    assert.strictEqual(missingRow, null, JSON.stringify(missingRow));
  });
  log.debug("Leaving development().");
}

async function product() {
  log.debug("Entering product().");
  log.info("=== 7. product refuses the private address ===");
  const prod = await setUpRealm(PROD);
  const did = prod.view.did.prefix + "holder";
  const k = key();
  await publish(prod.view, "holder", documentOf(did, [k]));
  const since = await testPeer.mark(prod.view.tenant);
  const refused = await enrol(prod.base, prod.browser, did,
                              function (request) {
    return selfIssued(did, did + "#key-1", k, request.client_id,
                      request.nonce);
  });
  const fetched = await fetchesOf(prod.view, "holder", since);
  const row = await rowFor(prod.base, did);
  check("in a product realm the enrolment is refused, the peer on a " +
        "private address is never dialled, and nothing is enrolled",
        function () {
    assert.ok(!enrolledOk(refused), "it was enrolled");
    assert.strictEqual(fetched.length, 0, JSON.stringify(fetched));
    assert.strictEqual(row, null, JSON.stringify(row));
  });
  log.debug("Leaving product().");
}

async function test() {
  log.debug("Entering test().");
  if (!testPeer.available()) {
    log.info(testPeer.skipReason("the https host a did:web document is " +
                                 "published on"));
    log.info("Test completed successfully.");
    log.debug("Leaving test(). No peer.");
    return;
  }
  await ok(root + "/admin-api/realms/create",
           { id: DEV, domain: DEV + ".example.net",
             name: "#693 did:web development",
             overrides: { "global.mode": "development" } },
           "created the development realm");
  await ok(root + "/admin-api/realms/create",
           { id: PROD, domain: PROD + ".example.net",
             name: "#693 did:web product",
             overrides: { "global.mode": "product" } },
           "created the product realm");
  await development();
  await product();
  assert.ok(checks >= FLOOR, "only " + checks + " checks ran; a section has " +
            "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

new Command()
  .description("A did:web enrolled by proof (#693) at the test peer: " +
    "pinned, signed in with, rotated and refused, proved again, a " +
    "withdrawn document, and product refusing the private address.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
