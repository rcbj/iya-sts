// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_siop.js
//
// ---------------------------------------------------------------------------
// SELF-ISSUED OPENID PROVIDER v2, THIS SERVICE AS THE RELYING PARTY (#129,
// 2026-09-23), over HTTP, in a throwaway realm with
// `oid4vp.signInSelfIssued` turned on.
//
//   1. DISCOVERY: the realm's Entity Configuration at
//      /.well-known/openid-federation is a self-signed entity-statement+jwt
//      with openid_credential_verifier metadata.
//   2. AN ADMINISTRATOR ENROLS A KEY by value through /admin-api and it is
//      listed.
//   3. THE SIGN-IN: an authorization request reaches the sign-in screen, the
//      "self-issued ID" link starts a SIOPv2 request, the wallet fetches the
//      signed request object (response_type id_token, scope openid, the
//      section 8 client_metadata), answers with an ID Token it signs with
//      the enrolled key, and the browser collects: the waiting authorization
//      request completes with the person's `sub`.
//   4. THE REFUSALS: a key nobody enrolled verifies and signs nobody in (a
//      403 wait page); a token for another nonce is refused invalid_request.
//   5. A PERSON ENROLS THEIR OWN KEY by proving it: from the session section
//      3 left in the browser, /authn/wallet?siop=1&enrol=1, answered by a
//      NEW key, lands on /portal/self-issued — drawn since #568 by the static
//      portal from `/account-api`, signed in by single sign-on out of the same
//      browser's session — and a browser with no session is refused. Since
//      #693 the proved key is recorded as `proof: wallet` and the
//      administrator's as `admin`, the page says which, and the enrolment
//      writes a `portal.siop.enrol` audit row.
//   6. A REMOVED KEY signs nobody in.
//   7. THE VERIFIER, started at POST /admin-api/verifications/start
//      (#587): a by-value SIOPv2 request with response_mode form_post,
//      answered through the "browser", verified on GET
//      /admin-api/verifications?state=.
//
// THE WALLET IS INDEPENDENT: its keys and signatures are node's own
// `crypto`, as `sts_oid4vp_wallet.js`'s are.
//
// OWNED HERE (local: true): `/authn/wallet` and the enrolment are this
// repository's own.
// ---------------------------------------------------------------------------

const assert = require("assert");
const crypto = require("crypto");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const registry = require("./sts_applications.js");
const consentScreen = require("./consent_screen.js");
const portalSignin = require("./portal_signin.js");
// THE WALLET'S PAGES OVER `/authn-api/wallet` (#574): the start, the wait
// page's view and the collection, bound as the pages bind them.
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
var log = bunyan.createLogger({ name: "sts_siop",
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
const REALM = ("siop-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                             .slice(0, 31);
const base = root + "/realm/" + REALM;
const api = base + "/admin-api";
const CLIENT_ID = "sts-siop-job";
const REDIRECT_URI = "https://rp.sts-siop-job.example.test/cb";
const HOLDER = names.usernameFor("siop-holder");
const PASSWORD = "Siop-holder-" + crypto.randomBytes(9).toString("base64url") +
                 "-Aa1!";

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

function headerOf(jwt) {
  log.debug("Entering headerOf().");
  log.debug("Leaving headerOf().");
  return JSON.parse(Buffer.from(String(jwt).split(".")[0], "base64url")
    .toString("utf8"));
}

// A wallet key: P-256, its public JWK and its RFC 7638 thumbprint.
function walletKey() {
  log.debug("Entering walletKey().");
  const pair = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const j = pair.publicKey.export({ format: "jwk" });
  const jwk = { kty: "EC", crv: "P-256", x: j.x, y: j.y };
  const thumbprint = crypto.createHash("sha256").update(JSON.stringify(
    { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y })).digest("base64url");
  log.debug("Leaving walletKey().");
  return { privateKey: pair.privateKey, jwk: jwk, thumbprint: thumbprint };
}

// A self-issued ID Token (SIOPv2 section 11): iss and sub the thumbprint,
// the key in sub_jwk, ES256.
function selfIssued(key, aud, nonce) {
  log.debug("Entering selfIssued().");
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "ES256", typ: "JWT" };
  const payload = { iss: key.thumbprint, sub: key.thumbprint,
                    sub_jwk: key.jwk, aud: aud, nonce: nonce, iat: now,
                    exp: now + 300 };
  const input = Buffer.from(JSON.stringify(header)).toString("base64url") +
    "." + Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = crypto.sign("sha256", Buffer.from(input),
    { key: key.privateKey, dsaEncoding: "ieee-p1363" });
  log.debug("Leaving selfIssued().");
  return input + "." + signature.toString("base64url");
}

// A browser: a cookie jar.
function jar() {
  log.debug("Entering jar().");
  const cookies = {};
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

function unescapeHtml(text) {
  log.debug("Entering unescapeHtml().");
  log.debug("Leaving unescapeHtml().");
  return String(text).replace(/&quot;/g, "\"").replace(/&#39;/g, "'")
    .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
}

function pkce() {
  log.debug("Entering pkce().");
  const verifier = crypto.randomBytes(32).toString("base64url");
  log.debug("Leaving pkce().");
  return { verifier: verifier,
           challenge: crypto.createHash("sha256").update(verifier)
             .digest("base64url") };
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

// The wait page's wallet link, its request_uri, and the request object —
// from the wait page's view (#574), for the browser that started it.
async function walletRequest(who, waitUrl) {
  log.debug("Entering walletRequest().");
  const state = walletSignin.fromWaitUrl(waitUrl).state;
  const waiting = await walletSignin.view(base, who, state);
  const view = (waiting.json && waiting.json.view) || {};
  const walletUrl = view.sameDevice ? new URL(view.sameDevice) : null;
  const requestUri = walletUrl ? walletUrl.searchParams.get("request_uri") :
                                 "";
  const ro = requestUri ? await hop(null, "GET", requestUri) : null;
  log.debug("Leaving walletRequest().");
  return { waiting: waiting, jwt: ro ? ro.text : "",
           request: ro && ro.status === 200 ? payloadOf(ro.text) : null };
}

// An authorization request to the sign-in screen — a static surface (#571),
// whose view's `wallet.siop` is the self-issued link — and the start that
// link's page makes (#574), to the wait page.
async function startSignIn(who) {
  log.debug("Entering startSignIn().");
  const pair = pkce();
  const authorized = await hop(who, "GET", base + "/oauth2/authorize?" +
    new URLSearchParams({ response_type: "code", client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI, scope: "openid", state: "s-" + STAMP,
      nonce: "n-" + STAMP, code_challenge: pair.challenge,
      code_challenge_method: "S256" }).toString());
  const authnId = new URL(authorized.location || base, base).searchParams
    .get("authn") || "";
  const screen = await hop(who, "GET", authorized.location);
  const screenView = authnId ? await hop(who, "GET", base +
    "/authn-api/pending/" + encodeURIComponent(authnId)) : null;
  const wallet = screenView && screenView.json && screenView.json.view &&
                 screenView.json.view.wallet;
  const link = (wallet && wallet.siop) || "";
  const started = link ? await walletSignin.start(base, who,
    { authn: authnId, siop: "1" }) : null;
  const door = started ? started.door : null;
  const out = { pair: pair, screen: screen, screenView: screenView,
                link: link, door: door, started: started };
  if (door && door.status === 303) {
    out.waitUrl = door.location;
    Object.assign(out, await walletRequest(who, door.location));
  }
  log.debug("Leaving startSignIn().");
  return out;
}

// The wallet's answer, under the request's response mode: a sign-in asks
// for `direct_post.jwt` by default since 2026-10-12, so the ID Token is
// sent encrypted to the request's key (`wallet_signin.js`).
async function answer(request, idToken) {
  log.debug("Entering answer().");
  const r = await hop(null, "POST", request.response_uri, {
    form: walletSignin.answerForm(request, {
      state: request.state, id_token: idToken }) });
  log.debug("Leaving answer(). " + r.status);
  return r;
}

// Follows the browser from the wallet's redirect back to the client, and
// redeems the code.
async function finish(who, location, pair) {
  log.debug("Entering finish().");
  let at = location;
  // THE WALLET SENDS THE PERSON BACK TO THE WAIT PAGE, whose runtime
  // collects the sign-in (#574): the collection names where to go on.
  if (/\/authn\/wallet\/wait\?/.test(String(at || ""))) {
    at = (await walletSignin.collect(base, who, at)).location;
  }
  for (let n = 0; n < 6 && at && at.indexOf(root) === 0 &&
                  !consentScreen.isConsentScreen(at); n += 1) {
    const r = await hop(who, "GET", at);
    at = r.location;
  }
  const settled = await consentScreen.settleAuthorization({
    base: base, location: at, cookie: who.header() });
  at = settled.location || at;
  const code = at ? new URL(at).searchParams.get("code") : null;
  const tokens = code ? await hop(null, "POST", base + "/oauth2/token",
    { form: { grant_type: "authorization_code", code: code,
              redirect_uri: REDIRECT_URI, client_id: CLIENT_ID,
              code_verifier: pair.verifier } }) : null;
  log.debug("Leaving finish(). code=" + !!code);
  return { landed: at, code: code, tokens: tokens };
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. a throwaway realm " + REALM + " ===");
  await ok(root + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "SIOPv2 " + STAMP },
    "created the realm");
  await ok(api + "/config/set", { key: "oid4vp.signInSelfIssued",
                                  value: true },
           "turned self-issued sign-in on in the realm");
  await registry.provision(base, {
    identifier: CLIENT_ID, name: "SIOPv2 job",
    protocols: ["oauth2", "oidc"],
    fields: { oauthClientId: CLIENT_ID,
              oauthGrantType: ["authorization_code"],
              oauthTokenEndpointAuthMethod: "none",
              oauthConfidential: "FALSE",
              oauthRedirectUri: [REDIRECT_URI],
              oauthResponseType: ["code"],
              oauthScope: ["openid"] },
    why: "the relying party sts_siop.js signs its holder in for"
  });
  await registry.ensurePerson(base, HOLDER, PASSWORD);

  log.info("=== 1. the Entity Configuration ===");
  let r = await hop(null, "GET", base + "/.well-known/openid-federation");
  check("/.well-known/openid-federation is a self-signed " +
        "entity-statement+jwt naming the realm and its verifier metadata",
        function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    const ec = payloadOf(r.text);
    assert.strictEqual(headerOf(r.text).typ, "entity-statement+jwt");
    assert.strictEqual(ec.iss, base);
    assert.strictEqual(ec.sub, base);
    assert.ok(ec.metadata && ec.metadata.openid_credential_verifier &&
      ec.metadata.openid_credential_verifier.subject_syntax_types_supported
        .indexOf("did:jwk") >= 0, r.text.slice(0, 300));
  });

  log.info("=== 2. an administrator enrols a key ===");
  const key = walletKey();
  await ok(api + "/users/enrol-self-issued-subject", { user: HOLDER,
    subject: key.thumbprint, label: "job wallet" }, "enrolled a key");
  r = await hop(null, "GET", api + "/users/self-issued-subjects?user=" +
                encodeURIComponent(HOLDER));
  check("the enrolled key is listed as its RFC 9278 thumbprint URI",
        function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.deepStrictEqual(r.json.subjects.map(function (one) {
      return one.subject;
    }), ["urn:ietf:params:oauth:jwk-thumbprint:sha-256:" + key.thumbprint]);
    assert.strictEqual(r.json.signInEnabled, true);
  });
  const again = await hop(null, "POST", api +
    "/users/enrol-self-issued-subject", { json: { user: HOLDER,
      subject: key.thumbprint } });
  check("enrolling it twice is refused", function () {
    assert.strictEqual(again.status, 400, again.text.slice(0, 300));
  });

  log.info("=== 3. the sign-in ===");
  const browser = jar();
  const s = await startSignIn(browser);
  check("the sign-in screen offers a self-issued ID, and it starts a signed " +
        "SIOPv2 request: response_type id_token, scope openid, section 8 " +
        "client_metadata", function () {
    assert.ok(s.link, "no self-issued link in the screen's view: " +
              (s.screenView ? s.screenView.text.slice(0, 400) : ""));
    assert.ok(s.request, "no request object: " + (s.door && s.door.status));
    assert.strictEqual(headerOf(s.jwt).typ, "oauth-authz-req+jwt");
    assert.strictEqual(s.request.response_type, "id_token");
    assert.strictEqual(s.request.scope, "openid");
    // `direct_post.jwt`, a sign-in's default since 2026-10-12
    // (`oid4vp.signInResponseMode`): the ID Token goes back encrypted.
    assert.strictEqual(s.request.response_mode, "direct_post.jwt");
    assert.strictEqual(s.request.dcql_query, undefined);
    assert.ok(s.request.client_metadata.subject_syntax_types_supported
      .indexOf("urn:ietf:params:oauth:jwk-thumbprint") >= 0);
  });
  const answered = await answer(s.request, selfIssued(key,
    s.request.client_id, s.request.nonce));
  check("the wallet's ID Token is accepted and it is sent back with a " +
        "response_code", function () {
    assert.strictEqual(answered.status, 200, answered.text.slice(0, 400));
    assert.ok(/response_code=/.test(answered.json.redirect_uri),
              answered.text);
  });
  const done = await finish(browser, answered.json.redirect_uri, s.pair);
  const idToken = done.tokens && done.tokens.json &&
                  done.tokens.json.id_token;
  const claims = idToken ? payloadOf(idToken) : {};
  check("the waiting authorization request completes, for the person who " +
        "enrolled the key", function () {
    assert.ok(done.code, "no code: landed at " + done.landed);
    assert.strictEqual(done.tokens.status, 200, done.tokens.text);
    assert.ok(/^urn:uuid:/.test(String(claims.sub)), JSON.stringify(claims));
  });

  log.info("=== 4. the refusals ===");
  const stranger = jar();
  const t = await startSignIn(stranger);
  const unknownKey = walletKey();
  const unknown = await answer(t.request, selfIssued(unknownKey,
    t.request.client_id, t.request.nonce));
  const unknownPage = await walletSignin.collect(base, stranger,
    unknown.json && unknown.json.redirect_uri ? unknown.json.redirect_uri
                                              : t.waitUrl);
  check("a key nobody enrolled verifies and signs nobody in", function () {
    assert.strictEqual(unknown.status, 200, unknown.text.slice(0, 300));
    assert.strictEqual(unknownPage.status, 403,
                       unknownPage.text.replace(/\s+/g, " ").slice(0, 300));
    assert.ok(/not enrolled/.test(unknownPage.text),
              "the page says why");
  });
  const u = await startSignIn(jar());
  const replay = await answer(u.request, selfIssued(key, u.request.client_id,
                                                    "another-nonce"));
  check("an ID Token for another nonce is refused invalid_request",
        function () {
    assert.strictEqual(replay.status, 400, replay.text.slice(0, 300));
    assert.strictEqual(replay.json.error, "invalid_request");
  });

  log.info("=== 5. a person enrols their own key ===");
  const nobody = (await walletSignin.start(base, jar(),
                                          { siop: "1", enrol: "1" })).door;
  check("a browser with no session cannot start an enrolment", function () {
    assert.strictEqual(nobody.status, 403, nobody.text.slice(0, 300));
  });
  const door = (await walletSignin.start(base, browser,
                                         { siop: "1", enrol: "1" })).door;
  const enrolReq = door.status === 303 ?
    await walletRequest(browser, door.location) : {};
  const second = walletKey();
  const proved = enrolReq.request ? await answer(enrolReq.request,
    selfIssued(second, enrolReq.request.client_id,
               enrolReq.request.nonce)) : null;
  const collected = proved && proved.json ?
    await walletSignin.collect(base, browser, proved.json.redirect_uri) :
    null;
  r = await hop(null, "GET", api + "/users/self-issued-subjects?user=" +
                encodeURIComponent(HOLDER));
  check("the signed-in person proves a new key with their wallet, lands on " +
        "/portal/self-issued, and it is enrolled for them", function () {
    assert.strictEqual(door.status, 303, door.text.slice(0, 300));
    assert.ok(enrolReq.request, "no enrolment request");
    assert.strictEqual(proved.status, 200, proved.text.slice(0, 300));
    assert.strictEqual(collected.status, 303, collected.text.slice(0, 300));
    assert.ok(/\/portal\/self-issued\?enrolled=1/.test(collected.location),
              collected.location);
    assert.ok(r.json.subjects.some(function (one) {
      return one.subject === "urn:ietf:params:oauth:jwk-thumbprint:sha-256:" +
                             second.thumbprint;
    }), r.text.slice(0, 400));
  });
  // PROVENANCE (#693): the proved key says so, and the administrator's says
  // it was enrolled by value.
  check("the proved key is recorded as proved by the wallet, the " +
        "administrator's as by value", function () {
    const byProof = r.json.subjects.filter(function (one) {
      return one.subject === "urn:ietf:params:oauth:jwk-thumbprint:sha-256:" +
                             second.thumbprint;
    })[0];
    const byValue = r.json.subjects.filter(function (one) {
      return one.subject === "urn:ietf:params:oauth:jwk-thumbprint:sha-256:" +
                             key.thumbprint;
    })[0];
    assert.strictEqual(byProof.proof, "wallet", JSON.stringify(byProof));
    assert.strictEqual(byValue.proof, "admin", JSON.stringify(byValue));
  });
  // THE ENROLMENT IS AUDITED (#693), as the removal always was.
  let enrolRows = [];
  for (let i = 0; i < 20 && !enrolRows.length; i += 1) {
    const rows = await hop(null, "GET", api + "/audit?per=200&action=" +
                           "portal.siop.enrol");
    enrolRows = ((rows.json && (rows.json.rows || rows.json.events)) || [])
      .filter(function (row) {
        return row.actor === HOLDER && row.outcome === "success";
      });
    if (!enrolRows.length) {
      await new Promise(function (resolve) {
        setTimeout(resolve, 150);
      });
    }
  }
  check("the wallet enrolment wrote a portal.siop.enrol audit row",
        function () {
    assert.ok(enrolRows.length >= 1, "no portal.siop.enrol row for " +
              HOLDER);
  });

  // THE PORTAL PAGE ITSELF (#568): the static portal signs in as its public
  // client with PKCE and a DPoP-bound token, and single sign-on answers its
  // flow out of the same browser's sign-on session — so the page is its
  // `/account-api` operation's answer, drawn by the portal's own renderers,
  // and the Remove is that operation's POST.
  const portal = await portalSignin.signInToThePortal(base, HOLDER, null,
    { cookie: browser.header() });
  const enrolled = collected && collected.location
    ? new URL(collected.location, base).searchParams.get("enrolled") : null;
  const page = await portal.draw("/portal/self-issued",
                                 enrolled ? { enrolled: enrolled } : {});
  const secondUri = "urn:ietf:params:oauth:jwk-thumbprint:sha-256:" +
                    second.thumbprint;
  check("/portal/self-issued lists both keys, with a Remove each and the " +
        "Enrol a wallet link", function () {
    assert.strictEqual(page.status, 200, JSON.stringify(page.json)
      .slice(0, 300));
    assert.ok(page.html.indexOf(secondUri) >= 0, "the proved key is listed");
    assert.ok(page.html.indexOf(key.thumbprint) >= 0,
              "the administrator's key is listed");
    assert.ok(/id="siop-enrol"/.test(page.html), "no enrol link");
    // How each was enrolled (#693).
    assert.ok(page.html.indexOf("Proved with your wallet") >= 0 &&
              page.html.indexOf("Added by an administrator") >= 0,
              "the page does not say how each key was enrolled");
  });
  const gone = await portal.act("/portal/self-issued",
                                { action: "remove", subject: secondUri });
  r = await hop(null, "GET", api + "/users/self-issued-subjects?user=" +
                encodeURIComponent(HOLDER));
  check("the person removes their own key from the portal", function () {
    assert.strictEqual(gone.status, 200, gone.text.slice(0, 300));
    assert.ok(gone.json && gone.json.ok, gone.text.slice(0, 300));
    assert.ok(!r.json.subjects.some(function (one) {
      return one.subject === secondUri;
    }), r.text.slice(0, 300));
  });

  log.info("=== 6. a removed key ===");
  await ok(api + "/users/remove-self-issued-subject", { user: HOLDER,
    subject: key.thumbprint }, "removed the first key");
  const later = jar();
  const w = await startSignIn(later);
  const removed = await answer(w.request, selfIssued(key,
    w.request.client_id, w.request.nonce));
  // THE WAIT PAGE'S ANSWER OVER `/authn-api/wallet` (#574), as section 4
  // reads it: the page is a shell, and the refusal is its status act's.
  const removedPage = await walletSignin.collect(base, later,
    removed.json && removed.json.redirect_uri ? removed.json.redirect_uri
                                              : w.waitUrl);
  check("a removed key signs nobody in", function () {
    assert.strictEqual(removed.status, 200, removed.text.slice(0, 300));
    assert.strictEqual(removedPage.status, 403,
                       removedPage.text.replace(/\s+/g, " ").slice(0, 300));
    assert.ok(/not enrolled/.test(removedPage.text), "the page says why");
  });

  // STARTED THROUGH `/admin-api` (#587; the only door since #594), in the
  // process's mode, product in the single-node and cluster stacks. The
  // start names no page of its own, so the browser's form_post is answered
  // in place — 200 and plain text, sent nowhere (#594; it was a 303 to the
  // demonstration's /oid4vp/done until then).
  log.info("=== 7. the Verifier, started at /admin-api/verifications ===");
  const start = await hop(null, "POST", api + "/verifications/start",
    { json: { response_type: "id_token", response_mode: "form_post" } });
  const walletUrl = (start.json || {}).walletUrl || "";
  const q = walletUrl ? new URL(walletUrl).searchParams : null;
  const posted = q ? await hop(jar(), "POST", q.get("redirect_uri"),
    { form: { state: q.get("state"), id_token: selfIssued(walletKey(),
      q.get("client_id"), q.get("nonce")) } }) : null;
  const verdict = q ? await hop(null, "GET", api + "/verifications?state=" +
                                encodeURIComponent(q.get("state"))) : null;
  check("a by-value request (redirect_uri: client, form_post) is answered " +
        "through the browser and verified; it signs nobody in", function () {
    assert.strictEqual(start.status, 200, start.text.slice(0, 300));
    assert.ok(/^siopv2:\/\/\?/.test(start.json.requestUri),
              "an ID Token alone is offered as siopv2://: " +
              start.json.requestUri);
    assert.strictEqual(q.get("response_type"), "id_token");
    assert.ok(/^redirect_uri:/.test(q.get("client_id")));
    assert.strictEqual(q.get("response_mode"), "form_post");
    assert.strictEqual(posted.status, 200, posted.text.slice(0, 300));
    assert.ok(!posted.location, "sent nowhere: " + posted.location);
    assert.strictEqual(verdict.json.verdict.ok, true,
                       JSON.stringify(verdict.json.verdict).slice(0, 600));
  });

  assert.ok(checks >= 16, "only " + checks + " checks ran");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

new Command()
  .description("SIOPv2 as the relying party (#129): the Entity " +
    "Configuration, enrolment by an administrator and by proof, the " +
    "sign-in, its refusals, removal, and the Verifier's form_post.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
