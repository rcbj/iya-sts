// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//
// File: sts_person_did.js
//
// ===========================================================================
// A did:web THIS REALM PUBLISHES FOR A PERSON (#1291), OVER HTTP, in a
// throwaway realm in the stack's mode.
//
//   0. the realm, its settings, a relying party, a wallet client and the
//      holder's session;
//   1. the base: in product mode a DID is refused on an unpinned base, and
//      the realm then pins `global.publicBaseUrl` (both modes go on pinned);
//   2. `wallet` custody: the wallet's round trip with `did_act=publish`, the
//      document at /users/<rid>/did.json (did+json, no-store), the DID
//      listed by /admin-api, and a self-issued sign-in with the did:web;
//   3. the two-proof change: a new key with no authorization refused at the
//      start, an "authorization" by the new key refused, then the current
//      key's authorization and the new key — version 2, `?versionId=1`
//      still answering version 1, the old key no longer signing in;
//   4. holder binding: the metadata offering did:web, and `cnf.kid` naming
//      the VERSION;
//   5. `realm` custody from the portal, the account disabled (410) and
//      enabled again (200), and the person's deactivation (410);
//   6. the administrator's deactivation of the wallet DID (410), and a
//      second one refused.
//
// `local: true` (tests/protocol/MANIFEST.js): this repository's feature.
// ===========================================================================

"use strict";

const assert = require("assert");
const crypto = require("crypto");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const registry = require("./sts_applications.js");
const consentScreen = require("./consent_screen.js");
const portalSignin = require("./portal_signin.js");
const walletSignin = require("./wallet_signin.js");
const serviceFacts = require("./service_facts.js");

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
var log = bunyan.createLogger({ name: "sts_person_did",
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
const REALM = ("pdid-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                             .slice(0, 31);
const base = root + "/realm/" + REALM;
const api = base + "/admin-api";
const HOLDER = names.usernameFor("pdid-holder");
const PASSWORD = "Pdid-holder-" + crypto.randomBytes(9).toString("base64url") +
                 "-Aa1!";
const CLIENT_ID = "sts-person-did-rp";
const REDIRECT_URI = "https://rp.sts-person-did.example.test/cb";
const WALLET = "sts-person-did-wallet";
const WALLET_REDIRECT = "https://wallet.sts-person-did.example.test/cb";
const SD_JWT = "IdentityCredential";
const JWT_VC = "IdentityCredentialJwtVcJson";

const FLOOR = 16;

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

// A wallet key: P-256, its public JWK, its RFC 7638 thumbprint, and the
// did:jwk it is.
function walletKey() {
  log.debug("Entering walletKey().");
  const pair = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const j = pair.publicKey.export({ format: "jwk" });
  const jwk = { kty: "EC", crv: "P-256", x: j.x, y: j.y };
  const thumbprint = crypto.createHash("sha256")
    .update(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x,
                             y: jwk.y })).digest("base64url");
  const did = "did:jwk:" + Buffer.from(JSON.stringify(jwk))
    .toString("base64url");
  log.debug("Leaving walletKey().");
  return { privateKey: pair.privateKey, jwk: jwk, thumbprint: thumbprint,
           did: did, kid: did + "#0" };
}

// A compact ES256 JWS.
function es256(header, payload, key) {
  log.debug("Entering es256().");
  const input = Buffer.from(JSON.stringify(header)).toString("base64url") +
    "." + Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = crypto.sign("sha256", Buffer.from(input),
    { key: key.privateKey, dsaEncoding: "ieee-p1363" });
  log.debug("Leaving es256().");
  return input + "." + signature.toString("base64url");
}

// A self-issued ID Token naming `did` as iss and sub, signed by `key` under
// `kid`.
function selfIssued(did, kid, key, aud, nonce) {
  log.debug("Entering selfIssued().");
  const now = Math.floor(Date.now() / 1000);
  log.debug("Leaving selfIssued().");
  return es256({ alg: "ES256", typ: "JWT", kid: kid },
               { iss: did, sub: did, aud: aud, nonce: nonce, iat: now,
                 exp: now + 300 }, key);
}

// A browser: a cookie jar, seeded from a Cookie header when given.
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
  const absolute = new URL(url, base).toString();
  const r = await fetch(absolute,
                        { method: method, headers: headers, body: body,
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
           headers: { contentType: r.headers.get("content-type") || "",
                      cacheControl: r.headers.get("cache-control") || "" },
           location: location ? new URL(location, absolute).toString() :
                                "" };
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

async function setting(key, value) {
  log.debug("Entering setting(). " + key);
  await ok(api + "/config/set", { key: key, value: value },
           "set " + key + " in the realm");
  log.debug("Leaving setting().");
}

// The wallet's request object for the transaction a wait page names.
async function walletRequest(who, waitUrl) {
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

// Answers a wallet request with an ID Token and collects in `who` where the
// response endpoint sent the wallet back. Asserts nothing.
async function answerAndCollect(who, request, idToken, waitUrl) {
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

// A published DID's wallet act from the holder's browser: the start (which
// may refuse), then the wallet's answer by `make(request)`. Answers
// { door, collected }.
async function didAct(who, act, make) {
  log.debug("Entering didAct(). " + act.split(".")[0]);
  const door = (await walletSignin.start(base, who,
    { siop: "1", enrol: "1", did_act: act })).door;
  if (door.status !== 303) {
    log.debug("Leaving didAct(). The start refused.");
    return { door: door, collected: null };
  }
  const request = await walletRequest(who, door.location);
  const out = await answerAndCollect(who, request, make(request),
                                     door.location);
  log.debug("Leaving didAct(). " + out.collected.status);
  return { door: door, collected: out.collected };
}

function landed(out, step) {
  log.debug("Entering landed().");
  log.debug("Leaving landed().");
  return !!out.collected && out.collected.status === 303 &&
         new RegExp("/portal/self-issued\\?did=" + step).test(
           out.collected.location);
}

// A self-issued sign-in through the screen, answered by `make(request)`,
// followed to the code. Answers { collected, code }.
async function signIn(make) {
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
  const request = await walletRequest(who, started.door.location);
  const out = await answerAndCollect(who, request, make(request),
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
  log.debug("Leaving signIn(). code=" + !!code);
  return { collected: out.collected, code: code };
}

async function published() {
  log.debug("Entering published().");
  const r = await hop(null, "GET", api + "/users/published-dids?user=" +
                      encodeURIComponent(HOLDER));
  assert.strictEqual(r.status, 200, r.text.slice(0, 300));
  log.debug("Leaving published().");
  return r.json.dids || [];
}

function documentPath(rid, query) {
  log.debug("Entering documentPath().");
  log.debug("Leaving documentPath().");
  return base + "/users/" + rid + "/did.json" + (query ? "?" + query : "");
}

function keysOf(doc) {
  log.debug("Entering keysOf().");
  log.debug("Leaving keysOf().");
  return ((doc && doc.verificationMethod) || []).map(function (vm) {
    return String(vm.id).split("#")[1];
  }).join(",");
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. a throwaway realm " + REALM + " ===");
  await ok(root + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "#1291 person DID " + STAMP },
    "created the realm");
  const product = await serviceFacts.isProduct(api);
  // RISK SCORING (#62) is off for sts_admin_client_policies.js's reason.
  await setting("risk.assessSignIns", false);
  await setting("oid4vp.signInSelfIssued", true);
  await setting("did.personPublishing", true);
  await setting("oid4vci.didHolderBinding", SD_JWT + "," + JWT_VC);
  await registry.provision(base, {
    identifier: CLIENT_ID, name: "#1291 relying party",
    protocols: ["oauth2", "oidc"],
    fields: { oauthClientId: CLIENT_ID,
              oauthGrantType: ["authorization_code"],
              oauthTokenEndpointAuthMethod: "none",
              oauthConfidential: "FALSE",
              oauthRedirectUri: [REDIRECT_URI],
              oauthResponseType: ["code"],
              oauthScope: ["openid"], oauthAllowedScope: ["openid"] },
    why: "the relying party sts_person_did.js signs its holder in for"
  });
  const meta0 = await hop(null, "GET",
                          base + "/.well-known/openid-credential-issuer");
  const configs = (meta0.json && meta0.json
    .credential_configurations_supported) || {};
  const walletScopes = [SD_JWT, JWT_VC].map(function (id) {
    assert.ok(configs[id] && configs[id].scope, "the issuer offers no " + id);
    return configs[id].scope;
  });
  await registry.provision(base, {
    identifier: WALLET, name: "#1291 wallet",
    protocols: ["oauth2", "oid4vci"],
    fields: { oauthClientId: WALLET,
              oauthGrantType: ["authorization_code"],
              oauthTokenEndpointAuthMethod: "none",
              oauthConfidential: "FALSE",
              oauthRedirectUri: [WALLET_REDIRECT],
              oauthResponseType: ["code"],
              oauthScope: walletScopes, oauthAllowedScope: walletScopes },
    why: "the wallet sts_person_did.js collects DID-bound credentials with"
  });
  await registry.ensurePerson(base, HOLDER, PASSWORD);
  const signedIn = await registry.authorizationCode(base, {
    clientId: CLIENT_ID, redirectUri: REDIRECT_URI, username: HOLDER,
    password: PASSWORD, scope: "openid" });
  const browser = jar(signedIn.cookie);
  const portal = await portalSignin.signInToThePortal(base, HOLDER, null,
    { cookie: browser.header() });

  log.info("=== 1. the base a DID is minted on ===");
  // A stack that pins its public base already (STS_PUBLIC_BASE_URL) mints
  // on it in either mode; otherwise product refuses until the realm pins
  // one.
  const pinnedAlready = String(await serviceFacts.setting(api,
    "global.publicBaseUrl") || "").trim() !== "";
  const refuses = product && !pinnedAlready;
  await setting("did.personCustody", "realm");
  const unpinned = await portal.act("/portal/self-issued/dids",
                                    { action: "publish" });
  check(refuses
    ? "product mode refuses a DID on an unpinned base"
    : "a DID is minted on the base this realm has", function () {
    if (refuses) {
      assert.strictEqual(unpinned.status, 400,
                         String(unpinned.text).slice(0, 300));
    } else {
      assert.ok(unpinned.json && unpinned.json.ok,
                String(unpinned.text).slice(0, 300));
    }
  });
  if (!refuses) {
    // That DID is deactivated, so the cap and the steps below start from
    // none active.
    const first = (await published())[0];
    await portal.act("/portal/self-issued/dids",
                     { action: "deactivate", rid: first.rid });
  }
  if (!pinnedAlready) {
    await setting("global.publicBaseUrl", root);
  }
  await setting("did.personCustody", "wallet");

  log.info("=== 2. wallet custody ===");
  const k1 = walletKey();
  const made = await didAct(browser, "publish", function (request) {
    return selfIssued(k1.did, k1.kid, k1, request.client_id, request.nonce);
  });
  const mine = (await published()).filter(function (one) {
    return one.custody === "wallet";
  })[0] || {};
  check("the wallet's round trip publishes a DID whose version 1 names the " +
        "key it proved, and the portal is told so", function () {
    assert.ok(landed(made, "published"), JSON.stringify(made.collected));
    // 22 characters, and a cell's 12-character tag where deployed as cells.
    assert.ok(/^[A-Za-z0-9_-]{22}(?:[A-Za-z0-9_-]{12})?$/.test(mine.rid),
              JSON.stringify(mine));
    assert.strictEqual(mine.did, "did:web:" +
      new URL(root).host.replace(/:/g, "%3A") + ":realm:" + REALM +
      ":users:" + mine.rid);
    assert.strictEqual(mine.versions[0].keys[0].id, k1.thumbprint);
    assert.strictEqual(mine.proof, "wallet");
  });
  const doc = await hop(null, "GET", documentPath(mine.rid));
  check("its document is at /users/<rid>/did.json: did+json, no-store, " +
        "the key under authentication", function () {
    assert.strictEqual(doc.status, 200, doc.text.slice(0, 300));
    assert.ok(/application\/did\+json/.test(doc.headers.contentType));
    assert.ok(/no-store/.test(doc.headers.cacheControl));
    assert.strictEqual(doc.json.id, mine.did);
    assert.strictEqual(keysOf(doc.json), k1.thumbprint);
    assert.deepStrictEqual(doc.json.authentication,
                           [mine.did + "#" + k1.thumbprint]);
  });
  const viaDid = await signIn(function (request) {
    return selfIssued(mine.did, mine.did + "#" + k1.thumbprint, k1,
                      request.client_id, request.nonce);
  });
  check("the published did:web signs the holder in", function () {
    assert.ok(viaDid.code, "no code: " + JSON.stringify(viaDid.collected)
      .slice(0, 300));
  });

  log.info("=== 3. the two-proof change ===");
  const k2 = walletKey();
  const asNew = function (request) {
    return selfIssued(k2.did, k2.kid, k2, request.client_id, request.nonce);
  };
  const noAuthority = await didAct(browser, "key." + mine.rid, asNew);
  check("a new key with no authorization is refused before a wallet is " +
        "asked", function () {
    assert.ok(noAuthority.door.status >= 400, String(noAuthority.door.status));
  });
  const byNewOnly = await didAct(browser, "authorize-rotate." + mine.rid,
                                 asNew);
  check("an authorization signed by the new key alone is refused",
        function () {
    assert.ok(!landed(byNewOnly, "authorized"),
              JSON.stringify(byNewOnly.collected).slice(0, 300));
  });
  const authorized = await didAct(browser, "authorize-rotate." + mine.rid,
    function (request) {
      return selfIssued(mine.did, mine.did + "#" + k1.thumbprint, k1,
                        request.client_id, request.nonce);
    });
  check("signed as the DID with version 1's key, the rotation is " +
        "authorized", function () {
    assert.ok(landed(authorized, "authorized"),
              JSON.stringify(authorized.collected).slice(0, 300));
  });
  const changed = await didAct(browser, "key." + mine.rid, asNew);
  check("the new key's proof publishes version 2", function () {
    assert.ok(landed(changed, "changed"),
              JSON.stringify(changed.collected).slice(0, 300));
  });
  const now = await hop(null, "GET", documentPath(mine.rid));
  const v1 = await hop(null, "GET", documentPath(mine.rid, "versionId=1"));
  check("the document is version 2's, and ?versionId=1 still answers " +
        "version 1's", function () {
    assert.strictEqual(keysOf(now.json), k2.thumbprint, now.text);
    assert.strictEqual(keysOf(v1.json), k1.thumbprint, v1.text);
  });
  const row = (await published()).filter(function (one) {
    return one.rid === mine.rid;
  })[0];
  check("version 2 records both proofs as what authorized it", function () {
    const by = row.versions[1].authorizedBy;
    assert.strictEqual(by[0].keyThumbprint, k1.thumbprint);
    assert.strictEqual(by[1].keyThumbprint, k2.thumbprint);
  });
  const oldKey = await signIn(function (request) {
    return selfIssued(mine.did, mine.did + "#" + k1.thumbprint, k1,
                      request.client_id, request.nonce);
  });
  const newKey = await signIn(function (request) {
    return selfIssued(mine.did, mine.did + "#" + k2.thumbprint, k2,
                      request.client_id, request.nonce);
  });
  check("the rotated-out key signs nobody in; the new one does",
        function () {
    assert.ok(!oldKey.code);
    assert.ok(newKey.code, JSON.stringify(newKey.collected).slice(0, 300));
  });

  log.info("=== 4. holder binding names the version ===");
  const meta = (await hop(null, "GET",
                          base + "/.well-known/openid-credential-issuer"))
    .json;
  check("the DID-bound configurations offer did:web", function () {
    assert.ok(meta.credential_configurations_supported[SD_JWT]
      .cryptographic_binding_methods_supported.indexOf("did:web") >= 0);
  });
  const walletCode = await registry.authorizationCode(base, {
    clientId: WALLET, redirectUri: WALLET_REDIRECT, username: HOLDER,
    password: PASSWORD, scope: walletScopes.join(" "),
    cookie: browser.header() });
  const walletTokens = await hop(null, "POST", base + "/oauth2/token", {
    form: { grant_type: "authorization_code", code: walletCode.code,
            redirect_uri: WALLET_REDIRECT, client_id: WALLET,
            code_verifier: walletCode.verifier } });
  const vciToken = walletTokens.json && walletTokens.json.access_token;
  const nonce = await hop(null, "POST", meta.nonce_endpoint, { form: {} });
  const proof = es256({ alg: "ES256", typ: "openid4vci-proof+jwt",
                        kid: mine.did + "#" + k2.thumbprint },
                      { iss: WALLET, aud: meta.credential_issuer,
                        iat: Math.floor(Date.now() / 1000),
                        nonce: nonce.json && nonce.json.c_nonce }, k2);
  const issued = await hop(null, "POST", meta.credential_endpoint, {
    headers: { authorization: "Bearer " + vciToken },
    json: { credential_configuration_id: SD_JWT,
            proofs: { jwt: [proof] } } });
  check("a dc+sd-jwt bound to the published DID names its version in " +
        "cnf.kid", function () {
    assert.strictEqual(issued.status, 200, issued.text.slice(0, 400));
    const credential = issued.json.credentials[0].credential;
    assert.deepStrictEqual(payloadOf(String(credential).split("~")[0]).cnf,
      { kid: mine.did + "?versionId=2#" + k2.thumbprint });
  });

  log.info("=== 5. realm custody, the disabled account, the person's " +
           "deactivation ===");
  await setting("did.personCustody", "realm");
  const realmMade = await portal.act("/portal/self-issued/dids",
                                     { action: "publish" });
  const realmDid = (await published()).filter(function (one) {
    return one.custody === "realm" && one.state === "active";
  })[0] || {};
  check("a realm-custody DID is published from the portal, its key never " +
        "in the answer", function () {
    assert.ok(realmMade.json && realmMade.json.ok,
              String(realmMade.text).slice(0, 300));
    assert.ok(String(realmMade.text).indexOf("\"d\"") < 0);
    assert.strictEqual(realmDid.proof, "realm");
  });
  await ok(api + "/users/disable", { user: HOLDER }, "disabled the holder");
  const whileDisabled = await hop(null, "GET", documentPath(realmDid.rid));
  await ok(api + "/users/enable", { user: HOLDER }, "enabled the holder");
  const enabledAgain = await hop(null, "GET", documentPath(realmDid.rid));
  check("while the account is disabled the address answers 410 { id, " +
        "deactivated: true }, and enabling it restores the document",
        function () {
    assert.strictEqual(whileDisabled.status, 410, whileDisabled.text);
    assert.deepStrictEqual(whileDisabled.json,
                           { id: realmDid.did, deactivated: true });
    assert.strictEqual(enabledAgain.status, 200, enabledAgain.text);
  });
  const portal2 = await portalSignin.signInToThePortal(base, HOLDER, null,
    { password: PASSWORD });
  const personGone = await portal2.act("/portal/self-issued/dids",
    { action: "deactivate", rid: realmDid.rid });
  const goneDoc = await hop(null, "GET", documentPath(realmDid.rid));
  check("the person deactivates it: 410 for good", function () {
    assert.ok(personGone.json && personGone.json.ok,
              String(personGone.text).slice(0, 300));
    assert.strictEqual(goneDoc.status, 410);
  });

  log.info("=== 6. the administrator's deactivation ===");
  await ok(api + "/users/deactivate-published-did",
           { user: HOLDER, did: mine.did },
           "deactivated the wallet DID");
  const adminGone = await hop(null, "GET", documentPath(mine.rid));
  const twice = await hop(null, "POST", api +
                          "/users/deactivate-published-did",
                          { json: { user: HOLDER, did: mine.did } });
  const afterGone = await signIn(function (request) {
    return selfIssued(mine.did, mine.did + "#" + k2.thumbprint, k2,
                      request.client_id, request.nonce);
  });
  check("an administrator deactivates it: 410, a second deactivation " +
        "refused, and the DID signs nobody in", function () {
    assert.strictEqual(adminGone.status, 410, adminGone.text);
    assert.ok(twice.status >= 400 || (twice.json && twice.json.ok === false),
              twice.text.slice(0, 300));
    assert.ok(!afterGone.code);
  });

  assert.ok(checks >= FLOOR, "only " + checks + " checks ran; a section has " +
            "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

new Command()
  .description("A did:web this realm publishes for a person (#1291): " +
    "wallet custody end to end, the two-proof key change, versions, " +
    "holder binding naming the version, realm custody, the disabled " +
    "account and both deactivations.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
