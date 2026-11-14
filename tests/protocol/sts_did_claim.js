// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_did_claim.js
//
// ---------------------------------------------------------------------------
// A PERSON'S DID OVER HTTP (#693, 2026-11-03): the preferred DID, the `did`
// claim, and OpenID4VCI holder binding to the DID — the HTTP half of
// `tests/did_claim.js` and `tests/oid4vci_did_binding.js`, which hold all
// of it in process. A job here is the only kind a product-mode stack and an
// AWS target run, so until this file the claim and the binding were
// unchecked in both.
//
// In a throwaway realm, in whichever mode the service is in, with
// `oauth2.didClaim` on and `oid4vci.didHolderBinding` naming the dc+sd-jwt
// and jwt_vc_json identity configurations:
//
//   1. THE PERSON SIGNS IN with their password and PROVES a did:jwk with
//      their wallet (SIOPv2, `/authn/wallet?siop=1&enrol=1`): it is listed
//      as proved by the wallet. An administrator enrols a second did:jwk by
//      value: listed as by value. The issuer's metadata names did:jwk and
//      did:key as the binding methods of the two bound configurations only.
//   2. THE PREFERRED DID: the administrator's by-value DID cannot be
//      preferred, through `/admin-api` or the portal; the proved one is,
//      from `/portal/self-issued`.
//   3. THE CLAIM RELEASED: a client that declares the `did` scope asks for
//      it, the person answers the consent screen, and the ID Token and the
//      UserInfo response carry the proved DID. The access token and its
//      introspection response do NOT — the claim is the ID Token's and
//      UserInfo's alone (`oauth-oidc/did_claim.ts`).
//   4. THE CLAIM LEFT OUT, with no error: an OIDC Core 5.5 claims request
//      naming `did` without the scope; a PAIRWISE client, until its entry
//      opts in with `oauthDidClaimWithPairwise`; a client that does not
//      declare the scope (refused at the authorization endpoint in product,
//      granted and still left out in development); the preference cleared,
//      for a new token and at UserInfo for the old one.
//   5. HOLDER BINDING: a key proof naming the proved did:jwk by `kid` gets
//      a dc+sd-jwt whose `cnf.kid` is the DID URL and a jwt_vc_json whose
//      `sub` and `credentialSubject.id` are the DID; a `jwk` proof, a proof
//      carrying both, an unenrolled did:jwk and the administrator's by-value
//      did:jwk are refused `invalid_proof`; a configuration bound to a KEY
//      binds a `kid` proof to the key it names; and a DID the person
//      removed binds nothing.
//   6. A DISABLED ACCOUNT: UserInfo on the token section 3 issued carries
//      no `did` (or is refused outright).
//
// THE WALLET IS INDEPENDENT: its keys, JWS and did:jwk are node's own
// `crypto`, as `sts_siop.js`'s are. The `STS-*` codes are never sent, so
// this job asserts what a client sees; the in-process files assert codes.
//
// OWNED HERE (local: true): the claim, the binding and the enrolment are
// this repository's own.
// ---------------------------------------------------------------------------

const assert = require("assert");
const crypto = require("crypto");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const registry = require("./sts_applications.js");
const consentScreen = require("./consent_screen.js");
const portalSignin = require("./portal_signin.js");
const walletSignin = require("./wallet_signin.js");

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
var log = bunyan.createLogger({ name: "sts_did_claim",
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
const REALM = ("did-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                            .slice(0, 31);
const base = root + "/realm/" + REALM;
const api = base + "/admin-api";
const HOLDER = names.usernameFor("did-holder");
const PASSWORD = "Did-holder-" + crypto.randomBytes(9).toString("base64url") +
                 "-Aa1!";

// The relying parties. RP declares `did`, PAIRWISE declares it and uses
// pairwise subjects, PLAIN does not declare it. All three are confidential,
// so that RP can also ask the introspection endpoint about its own token.
const RP = "sts-did-claim-rp";
const PAIRWISE = "sts-did-claim-pairwise";
const PLAIN = "sts-did-claim-plain";
const RP_REDIRECT = "https://rp.sts-did-claim.example.test/cb";
const SECRET = "did-claim-" + crypto.randomBytes(18).toString("base64url");
// The wallet: public, PKCE, oauth2 and oid4vci only.
const WALLET = "sts-did-claim-wallet";
const WALLET_REDIRECT = "https://wallet.sts-did-claim.example.test/cb";

// The configurations bound to the person's DID, and one left bound to a key.
const SD_JWT = "IdentityCredential";
const JWT_VC = "IdentityCredentialJwtVcJson";
const KEY_BOUND = "IdentityCredentialDid";

// Enough checks that a section which stopped running is noticed.
const FLOOR = 18;

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function partOf(jwt, index) {
  log.debug("Entering partOf().");
  log.debug("Leaving partOf().");
  return JSON.parse(Buffer.from(String(jwt).split(".")[index], "base64url")
    .toString("utf8"));
}

function payloadOf(jwt) {
  log.debug("Entering payloadOf().");
  log.debug("Leaving payloadOf().");
  return partOf(jwt, 1);
}

// A wallet key: P-256, its public JWK, and the did:jwk it is (did:jwk's
// method: the base64url of the JWK's JSON), whose one method is `#0`.
function didJwkKey() {
  log.debug("Entering didJwkKey().");
  const pair = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const j = pair.publicKey.export({ format: "jwk" });
  const jwk = { kty: "EC", crv: "P-256", x: j.x, y: j.y };
  const did = "did:jwk:" + Buffer.from(JSON.stringify(jwk))
    .toString("base64url");
  log.debug("Leaving didJwkKey().");
  return { privateKey: pair.privateKey, jwk: jwk, did: did,
           kid: did + "#0" };
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

// A self-issued ID Token for a DID subject (SIOPv2 section 11): iss and sub
// the DID, the method named by `kid`, no sub_jwk.
function selfIssued(key, aud, nonce) {
  log.debug("Entering selfIssued().");
  const now = Math.floor(Date.now() / 1000);
  log.debug("Leaving selfIssued().");
  return es256({ alg: "ES256", typ: "JWT", kid: key.kid },
               { iss: key.did, sub: key.did, aud: aud, nonce: nonce,
                 iat: now, exp: now + 300 }, key);
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

function basic(clientId) {
  log.debug("Entering basic().");
  log.debug("Leaving basic().");
  return "Basic " + Buffer.from(encodeURIComponent(clientId) + ":" +
                                encodeURIComponent(SECRET)).toString("base64");
}

function pkce() {
  log.debug("Entering pkce().");
  const verifier = crypto.randomBytes(32).toString("base64url");
  log.debug("Leaving pkce().");
  return { verifier: verifier,
           challenge: crypto.createHash("sha256").update(verifier)
             .digest("base64url") };
}

// An authorization request for a confidential relying party on the session
// `cookie` holds, the consent screen answered Allow, and the code redeemed.
// Answers { landed, error, tokens, idClaims }.
async function signInTo(clientId, scope, cookie, extra) {
  log.debug("Entering signInTo(). " + clientId + " " + scope);
  const pair = pkce();
  const r = await hop(null, "GET", base + "/oauth2/authorize?" +
    new URLSearchParams(Object.assign({
      response_type: "code", client_id: clientId, redirect_uri: RP_REDIRECT,
      scope: scope, state: "s-" + crypto.randomBytes(6).toString("hex"),
      nonce: "n-" + crypto.randomBytes(6).toString("hex"),
      code_challenge: pair.challenge, code_challenge_method: "S256" },
                        extra || {})).toString(),
    { headers: { cookie: cookie } });
  const settled = await consentScreen.settleAuthorization({
    base: base, location: r.location, cookie: cookie });
  const landed = settled.location || r.location || "";
  const at = landed ? new URL(landed) : null;
  const code = at ? at.searchParams.get("code") : null;
  const error = at ? at.searchParams.get("error") : null;
  const tokens = code ? await hop(null, "POST", base + "/oauth2/token", {
    headers: { authorization: basic(clientId) },
    form: { grant_type: "authorization_code", code: code,
            redirect_uri: RP_REDIRECT, code_verifier: pair.verifier } })
    : null;
  const idToken = tokens && tokens.json && tokens.json.id_token;
  log.debug("Leaving signInTo(). code=" + !!code + " error=" + error);
  return { landed: landed, error: error, tokens: tokens,
           idClaims: idToken ? payloadOf(idToken) : null,
           accessToken: tokens && tokens.json && tokens.json.access_token };
}

async function userinfo(accessToken) {
  log.debug("Entering userinfo().");
  const r = await hop(null, "GET", base + "/oauth2/userinfo",
                      { headers: { authorization: "Bearer " +
                                                  accessToken } });
  log.debug("Leaving userinfo(). " + r.status);
  return r;
}

async function subjects() {
  log.debug("Entering subjects().");
  const r = await hop(null, "GET", api + "/users/self-issued-subjects?user=" +
                      encodeURIComponent(HOLDER));
  assert.strictEqual(r.status, 200, r.text.slice(0, 300));
  log.debug("Leaving subjects().");
  return r.json.subjects || [];
}

function rowOf(rows, subject) {
  log.debug("Entering rowOf().");
  log.debug("Leaving rowOf().");
  return rows.filter(function (one) {
    return one.subject === subject;
  })[0] || null;
}

// The person proves `key`'s did:jwk with their wallet, from the browser
// `who`, which holds their session (oid4vc/CLAUDE.md, 3ba).
async function enrolByProof(who, key) {
  log.debug("Entering enrolByProof().");
  const door = (await walletSignin.start(base, who,
                                         { siop: "1", enrol: "1" })).door;
  assert.strictEqual(door.status, 303, "the enrolment did not start: " +
                     door.status + " " + String(door.text).slice(0, 300));
  const state = walletSignin.fromWaitUrl(door.location).state;
  const waiting = await walletSignin.view(base, who, state);
  const view = (waiting.json && waiting.json.view) || {};
  const requestUri = view.sameDevice ?
    new URL(view.sameDevice).searchParams.get("request_uri") : "";
  assert.ok(requestUri, "no request_uri on the wait page: " +
            String(waiting.text).slice(0, 300));
  const ro = await hop(null, "GET", requestUri);
  const request = payloadOf(ro.text);
  const answered = await hop(null, "POST", request.response_uri, {
    form: walletSignin.answerForm(request, {
      state: request.state,
      id_token: selfIssued(key, request.client_id, request.nonce) }) });
  assert.strictEqual(answered.status, 200, "the wallet's answer: " +
                     answered.text.slice(0, 300));
  const collected = await walletSignin.collect(base, who,
                                               answered.json.redirect_uri);
  log.debug("Leaving enrolByProof(). " + collected.status);
  return collected;
}

async function issuerMetadata() {
  log.debug("Entering issuerMetadata().");
  const r = await hop(null, "GET",
                      base + "/.well-known/openid-credential-issuer");
  assert.strictEqual(r.status, 200, r.text.slice(0, 300));
  log.debug("Leaving issuerMetadata().");
  return r.json;
}

// A Credential Request with one `jwt` proof. `how` is { kid } or { jwk }
// or both: what the proof's header names its key by.
async function requestCredential(meta, configId, accessToken, key, how) {
  log.debug("Entering requestCredential(). " + configId);
  const nonce = await hop(null, "POST", meta.nonce_endpoint, { form: {} });
  const header = Object.assign({ alg: "ES256",
                                 typ: "openid4vci-proof+jwt" }, how);
  const proof = es256(header, { iss: WALLET, aud: meta.credential_issuer,
                                iat: Math.floor(Date.now() / 1000),
                                nonce: nonce.json && nonce.json.c_nonce },
                      key);
  const r = await hop(null, "POST", meta.credential_endpoint, {
    headers: { authorization: "Bearer " + accessToken },
    json: { credential_configuration_id: configId,
            proofs: { jwt: [proof] } } });
  const credential = r.json && r.json.credentials && r.json.credentials[0] &&
                     r.json.credentials[0].credential;
  log.debug("Leaving requestCredential(). " + r.status);
  return { status: r.status, json: r.json, text: r.text,
           credential: credential || null };
}

function refusedProof(r) {
  log.debug("Entering refusedProof().");
  log.debug("Leaving refusedProof().");
  return r.status === 400 && r.json && r.json.error === "invalid_proof" &&
         !r.credential;
}

async function setting(key, value) {
  log.debug("Entering setting(). " + key);
  await ok(api + "/config/set", { key: key, value: value },
           "set " + key + " in the realm");
  log.debug("Leaving setting().");
}

async function relyingParty(clientId, scopes, extraFields) {
  log.debug("Entering relyingParty(). " + clientId);
  await registry.provision(base, {
    identifier: clientId, name: "#693 " + clientId,
    protocols: ["oauth2", "oidc"],
    fields: Object.assign({ oauthClientId: clientId,
                            oauthGrantType: ["authorization_code"],
                            oauthClientSecret: SECRET,
                            oauthTokenEndpointAuthMethod:
                              "client_secret_basic",
                            oauthRedirectUri: [RP_REDIRECT],
                            oauthResponseType: ["code"],
                            oauthScope: scopes,
                            // What the client DECLARES, which is what the
                            // did claim reads (`scopePolicy.declares()`) —
                            // `oauthScope` alone is not a declaration.
                            oauthAllowedScope: scopes },
                          extraFields || {}),
    why: "a relying party sts_did_claim.js asks for the did claim as"
  });
  log.debug("Leaving relyingParty().");
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. a throwaway realm " + REALM + " ===");
  await ok(root + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "#693 DID " + STAMP },
    "created the realm");
  // RISK SCORING (#62) is off for sts_admin_client_policies.js's reason: a
  // script's sign-ins are not what this job is about.
  await setting("risk.assessSignIns", false);
  await setting("oid4vp.signInSelfIssued", true);
  await setting("oauth2.didClaim", true);
  await setting("oid4vci.didHolderBinding", SD_JWT + "," + JWT_VC);
  await relyingParty(RP, ["openid", "did"]);
  await relyingParty(PAIRWISE, ["openid", "did"],
                     { oauthSubjectType: "pairwise" });
  await relyingParty(PLAIN, ["openid"]);
  const meta = await issuerMetadata();
  const configs = meta.credential_configurations_supported || {};
  const walletScopes = [SD_JWT, JWT_VC, KEY_BOUND].map(function (id) {
    assert.ok(configs[id] && configs[id].scope, "the issuer offers no " +
              id + ": " + Object.keys(configs).join(", "));
    return configs[id].scope;
  });
  await registry.provision(base, {
    identifier: WALLET, name: "#693 wallet",
    protocols: ["oauth2", "oid4vci"],
    fields: { oauthClientId: WALLET,
              oauthGrantType: ["authorization_code"],
              oauthTokenEndpointAuthMethod: "none",
              oauthConfidential: "FALSE",
              oauthRedirectUri: [WALLET_REDIRECT],
              oauthResponseType: ["code"],
              oauthScope: walletScopes },
    why: "the wallet sts_did_claim.js collects DID-bound credentials with"
  });
  await registry.ensurePerson(base, HOLDER, PASSWORD);

  log.info("=== 1. the person proves a did:jwk; an administrator enrols " +
           "another ===");
  check("the issuer names did:jwk and did:key as the binding methods of " +
        "the two configurations bound to a DID, and of no other",
        function () {
    [SD_JWT, JWT_VC].forEach(function (id) {
      assert.deepStrictEqual(configs[id]
        .cryptographic_binding_methods_supported, ["did:jwk", "did:key"],
        id + ": " + JSON.stringify(configs[id]).slice(0, 300));
    });
    assert.ok([].concat(configs[KEY_BOUND]
      .cryptographic_binding_methods_supported || []).every(function (m) {
      return !/^did:/.test(m);
    }), JSON.stringify(configs[KEY_BOUND]).slice(0, 300));
  });
  const signedIn = await registry.authorizationCode(base, {
    clientId: WALLET, redirectUri: WALLET_REDIRECT, username: HOLDER,
    password: PASSWORD, scope: walletScopes.join(" ") });
  const browser = jar(signedIn.cookie);
  const proved = didJwkKey();
  const enrolled = await enrolByProof(browser, proved);
  const byValue = didJwkKey();
  await ok(api + "/users/enrol-self-issued-subject", { user: HOLDER,
    subject: byValue.did, label: "#693 by value" },
    "enrolled a did:jwk by value");
  let rows = await subjects();
  check("the proved did:jwk lands the person on /portal/self-issued and is " +
        "listed as proved by the wallet; the administrator's as by value",
        function () {
    assert.strictEqual(enrolled.status, 303, String(enrolled.text)
      .slice(0, 300));
    assert.ok(/\/portal\/self-issued\?enrolled=1/.test(enrolled.location),
              enrolled.location);
    assert.strictEqual((rowOf(rows, proved.did) || {}).proof, "wallet",
                       JSON.stringify(rows).slice(0, 600));
    assert.strictEqual((rowOf(rows, byValue.did) || {}).proof, "admin",
                       JSON.stringify(rows).slice(0, 600));
  });

  log.info("=== 2. the preferred DID ===");
  const adminPrefer = await hop(null, "POST", api +
    "/users/set-preferred-self-issued-subject",
    { json: { user: HOLDER, subject: byValue.did } });
  const portal = await portalSignin.signInToThePortal(base, HOLDER, null,
    { cookie: browser.header() });
  const portalPreferByValue = await portal.act("/portal/self-issued",
    { action: "prefer", subject: byValue.did });
  check("a DID enrolled by value cannot be preferred, by an administrator " +
        "or from the portal", function () {
    assert.ok(adminPrefer.status >= 400 ||
              (adminPrefer.json && adminPrefer.json.ok === false),
              adminPrefer.status + " " + adminPrefer.text.slice(0, 300));
    assert.ok(portalPreferByValue.status >= 400 ||
              !(portalPreferByValue.json && portalPreferByValue.json.ok),
              portalPreferByValue.status + " " +
              String(portalPreferByValue.text).slice(0, 300));
  });
  const preferred = await portal.act("/portal/self-issued",
                                     { action: "prefer",
                                       subject: proved.did });
  rows = await subjects();
  check("the person prefers the DID they proved, from the portal",
        function () {
    assert.ok(preferred.json && preferred.json.ok,
              String(preferred.text).slice(0, 300));
    assert.strictEqual((rowOf(rows, proved.did) || {}).preferred, true,
                       JSON.stringify(rows).slice(0, 600));
    assert.notStrictEqual((rowOf(rows, byValue.did) || {}).preferred, true);
  });

  log.info("=== 3. the claim released ===");
  const cookie = browser.header();
  const released = await signInTo(RP, "openid did", cookie);
  check("a client that declares the did scope, once the person consented, " +
        "gets the proved DID in the ID Token", function () {
    assert.ok(released.idClaims, "no ID Token: landed at " +
              released.landed + " " + (released.tokens ?
                released.tokens.text.slice(0, 300) : ""));
    assert.strictEqual(released.idClaims.did, proved.did,
                       JSON.stringify(released.idClaims));
  });
  const info = await userinfo(released.accessToken);
  check("and in the UserInfo response", function () {
    assert.strictEqual(info.status, 200, info.text.slice(0, 300));
    assert.strictEqual(info.json.did, proved.did, info.text.slice(0, 400));
  });
  const introspected = await hop(null, "POST", base + "/oauth2/introspect", {
    headers: { authorization: basic(RP) },
    form: { token: released.accessToken } });
  check("the access token and its introspection response carry no did",
        function () {
    if (String(released.accessToken).split(".").length === 3) {
      assert.strictEqual(payloadOf(released.accessToken).did, undefined,
                         JSON.stringify(payloadOf(released.accessToken)));
    }
    assert.strictEqual(introspected.status, 200,
                       introspected.text.slice(0, 300));
    assert.strictEqual(introspected.json.active, true,
                       introspected.text.slice(0, 300));
    assert.strictEqual(introspected.json.did, undefined,
                       introspected.text.slice(0, 400));
  });

  log.info("=== 4. the claim left out ===");
  const byClaims = await signInTo(RP, "openid", cookie, {
    claims: JSON.stringify({ id_token: { did: { essential: true } },
                             userinfo: { did: null } }) });
  const byClaimsInfo = byClaims.accessToken ?
    await userinfo(byClaims.accessToken) : null;
  check("a claims request naming did, without the scope, gets no did in " +
        "the ID Token or at UserInfo", function () {
    assert.ok(byClaims.idClaims, "no ID Token: " + byClaims.landed);
    assert.strictEqual(byClaims.idClaims.did, undefined,
                       JSON.stringify(byClaims.idClaims));
    assert.strictEqual(byClaimsInfo.status, 200,
                       byClaimsInfo.text.slice(0, 300));
    assert.strictEqual(byClaimsInfo.json.did, undefined,
                       byClaimsInfo.text.slice(0, 300));
  });
  const pairwise = await signInTo(PAIRWISE, "openid did", cookie);
  check("a pairwise client gets its own subject and no did", function () {
    assert.ok(pairwise.idClaims, "no ID Token: " + pairwise.landed + " " +
              (pairwise.tokens ? pairwise.tokens.text.slice(0, 300) : ""));
    assert.notStrictEqual(pairwise.idClaims.sub, released.idClaims.sub);
    assert.strictEqual(pairwise.idClaims.did, undefined,
                       JSON.stringify(pairwise.idClaims));
  });
  await relyingParty(PAIRWISE, ["openid", "did"],
                     { oauthSubjectType: "pairwise",
                       oauthDidClaimWithPairwise: "TRUE" });
  const optedIn = await signInTo(PAIRWISE, "openid did", cookie);
  check("once its entry opts in with oauthDidClaimWithPairwise, the " +
        "pairwise client is told the DID", function () {
    assert.ok(optedIn.idClaims, "no ID Token: " + optedIn.landed);
    assert.strictEqual(optedIn.idClaims.did, proved.did,
                       JSON.stringify(optedIn.idClaims));
  });
  const undeclared = await signInTo(PLAIN, "openid did", cookie);
  check("a client that does not declare the did scope gets no did: " +
        "refused at the authorization endpoint, or answered without it",
        function () {
    if (undeclared.idClaims) {
      assert.strictEqual(undeclared.idClaims.did, undefined,
                         JSON.stringify(undeclared.idClaims));
    } else {
      assert.ok(undeclared.error, "neither an ID Token nor an error: " +
                undeclared.landed);
    }
  });
  const unpreferred = await portal.act("/portal/self-issued",
                                       { action: "unprefer",
                                         subject: proved.did });
  const afterClear = await signInTo(RP, "openid did", cookie);
  const oldInfo = await userinfo(released.accessToken);
  check("with the preference cleared, a new ID Token and UserInfo on the " +
        "earlier token carry no did", function () {
    assert.ok(unpreferred.json && unpreferred.json.ok,
              String(unpreferred.text).slice(0, 300));
    assert.ok(afterClear.idClaims, "no ID Token: " + afterClear.landed);
    assert.strictEqual(afterClear.idClaims.did, undefined,
                       JSON.stringify(afterClear.idClaims));
    assert.strictEqual(oldInfo.status, 200, oldInfo.text.slice(0, 300));
    assert.strictEqual(oldInfo.json.did, undefined,
                       oldInfo.text.slice(0, 300));
  });
  await portal.act("/portal/self-issued", { action: "prefer",
                                            subject: proved.did });

  log.info("=== 5. holder binding to the proved DID ===");
  const walletCode = await registry.authorizationCode(base, {
    clientId: WALLET, redirectUri: WALLET_REDIRECT, username: HOLDER,
    password: PASSWORD, scope: walletScopes.join(" "), cookie: cookie });
  const walletTokens = await hop(null, "POST", base + "/oauth2/token", {
    form: { grant_type: "authorization_code", code: walletCode.code,
            redirect_uri: WALLET_REDIRECT, client_id: WALLET,
            code_verifier: walletCode.verifier } });
  const vciToken = walletTokens.json && walletTokens.json.access_token;
  assert.ok(vciToken, "no wallet access token: " +
            walletTokens.text.slice(0, 300));
  const sd = await requestCredential(meta, SD_JWT, vciToken, proved,
                                     { kid: proved.kid });
  check("a dc+sd-jwt for a proof naming the proved did:jwk by kid carries " +
        "cnf.kid, the DID URL", function () {
    assert.strictEqual(sd.status, 200, sd.text.slice(0, 400));
    const issued = payloadOf(String(sd.credential).split("~")[0]);
    assert.deepStrictEqual(issued.cnf, { kid: proved.kid },
                           JSON.stringify(issued.cnf));
  });
  const jv = await requestCredential(meta, JWT_VC, vciToken, proved,
                                     { kid: proved.kid });
  check("a jwt_vc_json for it names the DID as sub and " +
        "credentialSubject.id, with cnf.kid", function () {
    assert.strictEqual(jv.status, 200, jv.text.slice(0, 400));
    const issued = payloadOf(jv.credential);
    assert.strictEqual(issued.sub, proved.did, JSON.stringify(issued)
      .slice(0, 400));
    assert.strictEqual(issued.vc.credentialSubject.id, proved.did);
    assert.deepStrictEqual(issued.cnf, { kid: proved.kid });
  });
  const byJwk = await requestCredential(meta, SD_JWT, vciToken, proved,
                                        { jwk: proved.jwk });
  const both = await requestCredential(meta, SD_JWT, vciToken, proved,
                                       { jwk: proved.jwk, kid: proved.kid });
  const stranger = didJwkKey();
  const unenrolled = await requestCredential(meta, SD_JWT, vciToken,
                                             stranger,
                                             { kid: stranger.kid });
  const administrators = await requestCredential(meta, SD_JWT, vciToken,
                                                 byValue,
                                                 { kid: byValue.kid });
  check("a DID-bound configuration refuses invalid_proof: a jwk proof, a " +
        "proof with both jwk and kid, an unenrolled did:jwk, and the " +
        "administrator's by-value did:jwk", function () {
    assert.ok(refusedProof(byJwk), "jwk: " + byJwk.status + " " +
              byJwk.text.slice(0, 300));
    assert.ok(refusedProof(both), "both: " + both.status + " " +
              both.text.slice(0, 300));
    assert.ok(refusedProof(unenrolled), "unenrolled: " + unenrolled.status +
              " " + unenrolled.text.slice(0, 300));
    assert.ok(refusedProof(administrators), "by value: " +
              administrators.status + " " +
              administrators.text.slice(0, 300));
  });
  const keyBound = await requestCredential(meta, KEY_BOUND, vciToken,
                                           stranger, { kid: stranger.kid });
  check("a configuration bound to a key binds a kid proof to the key it " +
        "names, whoever's DID it is", function () {
    assert.strictEqual(keyBound.status, 200, keyBound.text.slice(0, 400));
    const issued = payloadOf(String(keyBound.credential).split("~")[0]);
    assert.ok(issued.cnf && issued.cnf.jwk &&
              issued.cnf.jwk.x === stranger.jwk.x,
              JSON.stringify(issued.cnf));
  });
  const removed = await portal.act("/portal/self-issued",
                                   { action: "remove",
                                     subject: proved.did });
  const afterRemoval = await requestCredential(meta, SD_JWT, vciToken,
                                               proved, { kid: proved.kid });
  check("a DID the person removed binds nothing", function () {
    assert.ok(removed.json && removed.json.ok,
              String(removed.text).slice(0, 300));
    assert.ok(refusedProof(afterRemoval), afterRemoval.status + " " +
              afterRemoval.text.slice(0, 300));
  });

  log.info("=== 6. a disabled account ===");
  // The DID is proved again first, and preferred, so that the only thing
  // standing between the token and the claim is the account's state.
  const reEnrolled = await enrolByProof(browser, proved);
  const portalAgain = await portalSignin.signInToThePortal(base, HOLDER,
    null, { cookie: browser.header() });
  await portalAgain.act("/portal/self-issued", { action: "prefer",
                                                 subject: proved.did });
  const fresh = await signInTo(RP, "openid did", browser.header());
  await ok(api + "/users/disable", { user: HOLDER },
           "disabled the person");
  const disabledInfo = fresh.accessToken ?
    await userinfo(fresh.accessToken) : null;
  check("UserInfo for a disabled account carries no did (or is refused)",
        function () {
    assert.strictEqual(reEnrolled.status, 303, String(reEnrolled.text)
      .slice(0, 300));
    assert.strictEqual(fresh.idClaims && fresh.idClaims.did, proved.did,
                       "the control: " + JSON.stringify(fresh.idClaims));
    assert.ok(disabledInfo.status !== 200 ||
              disabledInfo.json.did === undefined,
              disabledInfo.status + " " + disabledInfo.text.slice(0, 300));
  });

  assert.ok(checks >= FLOOR, "only " + checks + " checks ran; a section " +
            "has stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

new Command()
  .description("A person's DID (#693): the preferred DID, the did claim " +
    "released and left out, and OpenID4VCI holder binding to the DID.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
