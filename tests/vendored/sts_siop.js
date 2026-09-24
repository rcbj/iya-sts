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
//      NEW key, lands on /portal/self-issued — and a browser with no session
//      is refused.
//   6. A REMOVED KEY signs nobody in.
//   7. THE VERIFIER AT /oid4vp/start: a by-value SIOPv2 request with
//      response_mode form_post, answered through the "browser", verified on
//      /oid4vp/result.
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

// The wait page's wallet link, its request_uri, and the request object.
async function walletRequest(who, waitUrl) {
  log.debug("Entering walletRequest().");
  const waiting = await hop(who, "GET", waitUrl);
  const open = /id="wallet-open" href="([^"]+)"/.exec(waiting.text);
  const walletUrl = open ? new URL(unescapeHtml(open[1])) : null;
  const requestUri = walletUrl ? walletUrl.searchParams.get("request_uri") :
                                 "";
  const ro = requestUri ? await hop(null, "GET", requestUri) : null;
  log.debug("Leaving walletRequest().");
  return { waiting: waiting, jwt: ro ? ro.text : "",
           request: ro && ro.status === 200 ? payloadOf(ro.text) : null };
}

// An authorization request to the sign-in screen, and its self-issued link
// followed to the wait page.
async function startSignIn(who) {
  log.debug("Entering startSignIn().");
  const pair = pkce();
  const authorized = await hop(who, "GET", base + "/oauth2/authorize?" +
    new URLSearchParams({ response_type: "code", client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI, scope: "openid", state: "s-" + STAMP,
      nonce: "n-" + STAMP, code_challenge: pair.challenge,
      code_challenge_method: "S256" }).toString());
  const screen = await hop(who, "GET", authorized.location);
  const link = /id="siop-signin" href="([^"]+)"/.exec(screen.text);
  const door = link ? await hop(who, "GET", unescapeHtml(link[1])) : null;
  const out = { pair: pair, screen: screen, link: link ? link[1] : "",
                door: door };
  if (door && door.status === 303) {
    out.waitUrl = door.location;
    Object.assign(out, await walletRequest(who, door.location));
  }
  log.debug("Leaving startSignIn().");
  return out;
}

async function answer(request, idToken) {
  log.debug("Entering answer().");
  const r = await hop(null, "POST", request.response_uri, { form: {
    state: request.state, id_token: idToken } });
  log.debug("Leaving answer(). " + r.status);
  return r;
}

// Follows the browser from the wallet's redirect back to the client, and
// redeems the code.
async function finish(who, location, pair) {
  log.debug("Entering finish().");
  let at = location;
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
    protocols: ["oauth2"],
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
    assert.ok(s.link, "no siop-signin link: " +
              s.screen.text.replace(/\s+/g, " ").slice(0, 400));
    assert.ok(s.request, "no request object: " + (s.door && s.door.status));
    assert.strictEqual(headerOf(s.jwt).typ, "oauth-authz-req+jwt");
    assert.strictEqual(s.request.response_type, "id_token");
    assert.strictEqual(s.request.scope, "openid");
    assert.strictEqual(s.request.response_mode, "direct_post");
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
  const unknownPage = await hop(stranger, "GET", unknown.json &&
    unknown.json.redirect_uri ? unknown.json.redirect_uri : t.waitUrl);
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
  const nobody = await hop(jar(), "GET", base +
                           "/authn/wallet?siop=1&enrol=1");
  check("a browser with no session cannot start an enrolment", function () {
    assert.strictEqual(nobody.status, 403, nobody.text.slice(0, 300));
  });
  const door = await hop(browser, "GET", base +
                         "/authn/wallet?siop=1&enrol=1");
  const enrolReq = door.status === 303 ?
    await walletRequest(browser, door.location) : {};
  const second = walletKey();
  const proved = enrolReq.request ? await answer(enrolReq.request,
    selfIssued(second, enrolReq.request.client_id,
               enrolReq.request.nonce)) : null;
  const collected = proved && proved.json ?
    await hop(browser, "GET", proved.json.redirect_uri) : null;
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

  // The portal page itself, in the same browser: its own code flow rides
  // on the sign-on session, so it is followed hop by hop to a 200.
  let page = await hop(browser, "GET", collected.location);
  for (let n = 0; n < 12 && page.status !== 200 &&
                  (page.status === 302 || page.status === 303); n += 1) {
    page = await hop(browser, "GET", page.location);
  }
  const secondUri = "urn:ietf:params:oauth:jwk-thumbprint:sha-256:" +
                    second.thumbprint;
  check("/portal/self-issued lists both keys, with a Remove each and the " +
        "Enrol a wallet link", function () {
    assert.strictEqual(page.status, 200, page.text.slice(0, 300));
    assert.ok(page.text.indexOf(secondUri) >= 0, "the proved key is listed");
    assert.ok(page.text.indexOf(key.thumbprint) >= 0,
              "the administrator's key is listed");
    assert.ok(/id="siop-enrol"/.test(page.text), "no enrol link");
  });
  const csrf = (/name="csrf_token" value="([^"]+)"/.exec(page.text) ||
                [])[1] || "";
  const gone = await hop(browser, "POST", base + "/portal/self-issued",
    { form: { action: "remove", subject: secondUri, csrf_token: csrf } });
  r = await hop(null, "GET", api + "/users/self-issued-subjects?user=" +
                encodeURIComponent(HOLDER));
  check("the person removes their own key from the portal", function () {
    assert.strictEqual(gone.status, 303, gone.text.slice(0, 300));
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
  const removedPage = await hop(later, "GET", removed.json &&
                                removed.json.redirect_uri || w.waitUrl);
  check("a removed key signs nobody in", function () {
    assert.strictEqual(removed.status, 200, removed.text.slice(0, 300));
    assert.strictEqual(removedPage.status, 403,
                       removedPage.text.replace(/\s+/g, " ").slice(0, 300));
    assert.ok(/not enrolled/.test(removedPage.text), "the page says why");
  });

  log.info("=== 7. the Verifier at /oid4vp/start ===");
  const start = await hop(null, "GET", base + "/oid4vp/start?" +
    "response_type=id_token&response_mode=form_post");
  const q = start.location ? new URL(start.location).searchParams : null;
  const posted = q ? await hop(jar(), "POST", q.get("redirect_uri"),
    { form: { state: q.get("state"), id_token: selfIssued(walletKey(),
      q.get("client_id"), q.get("nonce")) } }) : null;
  const verdict = q ? await hop(null, "GET", base + "/oid4vp/result/" +
                                encodeURIComponent(q.get("state"))) : null;
  check("a by-value request (redirect_uri: client, form_post) is answered " +
        "through the browser and verified; it signs nobody in", function () {
    assert.strictEqual(start.status, 302, start.text.slice(0, 300));
    assert.strictEqual(q.get("response_type"), "id_token");
    assert.ok(/^redirect_uri:/.test(q.get("client_id")));
    assert.strictEqual(q.get("response_mode"), "form_post");
    assert.strictEqual(posted.status, 303, posted.text.slice(0, 300));
    assert.ok(/\/oid4vp\/done\?state=/.test(posted.location));
    assert.strictEqual(verdict.json.verdict.ok, true,
                       JSON.stringify(verdict.json.verdict).slice(0, 600));
  });

  assert.ok(checks >= 14, "only " + checks + " checks ran");
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
