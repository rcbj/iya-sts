"use strict";
//
// File: sts_oidc_core.js
//
// ---------------------------------------------------------------------------
// OPENID CONNECT CORE 1.0, READ AGAINST THE CODE, OVER THE WIRE (#118,
// 2026-09-22).
//
// What the #45 review found this authorization server getting wrong, held
// from where a relying party meets it — and runnable in `product` mode and
// against the AWS targets, which an in-process test is not. In a throwaway
// realm it leaves behind, with dynamic registration opened for the realm so
// that clients can register the metadata under test:
//
//   a. DISCOVERY: pairwise, every prompt value, display values, the address
//      and phone scopes and their claims.
//   b. at_hash AND c_hash WITH THE HASH OF THE ID TOKEN'S alg — RS256, RS384,
//      PS512, ES512, EdDSA and ML-DSA-44 — computed here independently.
//   c. ERRORS IN THE FRAGMENT for a hybrid request, in the query for code.
//   d. POST AT THE AUTHORIZATION ENDPOINT.
//   e. THE REQUEST RULES: openid for an ID Token, prompt=none alone, nonce for
//      the implicit flow.
//   f. id_token_hint: the signed-in person's own, another person's under
//      prompt=none, and one that does not verify; select_account.
//   g. SECTION 5.4: scope claims at UserInfo (address and phone included) and
//      in the ID Token only for response_type=id_token; no `typ` claim.
//   h. UserInfo's form-body access token, and the refusal of two.
//   i. THE CODE'S BINDINGS: another client, a missing redirect_uri; exact
//      redirect_uri matching for a registered client.
//   j. token_endpoint_auth_signing_alg.
//   k. PAIRWISE subjects.
//   l. offline_access, and an online refresh token ending with its session.
//   m. an essential acr claims request as a requirement.
//   p. OpenID Connect for Identity Assurance 1.0 (#127): discovery, a
//      verification recorded through /admin-api, verified_claims chosen by
//      trust framework and evidence type, omitted when nothing satisfies it,
//      and section 6's refusal of a request with no verification.
//
// OWNED HERE (local: true): this repository's own authorization server.
// ---------------------------------------------------------------------------

const assert = require("assert");
const nodeCrypto = require("crypto");
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
var log = bunyan.createLogger({ name: "sts_oidc_core",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const REALM = ("oidccore-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                                  .slice(0, 31);
const R = "/realm/" + REALM;
const realmApi = base + R + "/admin-api";
const REDIRECT = "https://rp.oidccore.example.test/cb";
const REDIRECT2 = "https://rp2.oidccore.example.test/cb";
const PASSWORD = "oidc-Core-Passw0rd!-" + String(Date.now()).slice(-6);
const ALICE = names.usernameFor("oc-alice");
const BOB = names.usernameFor("oc-bob");

// OIDC Core 3.1.3.6's table, and this service's choice where it is silent —
// written out here rather than read from the service, so the test is a
// second opinion rather than a copy.
const HASH_OF = { RS256: "sha256", RS384: "sha384", PS512: "sha512",
                  ES512: "sha512", EdDSA: "sha512", "ML-DSA-44": "sha256" };

// Whether RFC 9700 mode is on in the realm — product mode implies it — which
// refuses every response type that returns an access token from the
// authorization endpoint (section 2.1.2). Read in setUp().
let strict = false;

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function form(o) {
  log.debug("Entering form().");
  log.debug("Leaving form().");
  return new URLSearchParams(o).toString();
}

function absolute(location) {
  log.debug("Entering absolute().");
  log.debug("Leaving absolute().");
  return /^https?:\/\//i.test(String(location || ""))
    ? String(location) : base + String(location || "");
}

async function send(url, options) {
  log.debug("Entering send(). url=" + url);
  const r = await fetch(url, Object.assign({ redirect: "manual" },
                                           options || {}));
  const raw = await r.text();
  let body = null;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in send(): " + ((e && e.message) || e));
    // Not JSON — a page; the caller reads `raw`.
    body = null;
  }
  log.debug("Leaving send(). status=" + r.status);
  return { status: r.status, body: body, raw: raw,
           location: r.headers.get("location") || "" };
}

function postJson(url, payload) {
  log.debug("Entering postJson().");
  log.debug("Leaving postJson().");
  return send(url, { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {}) });
}

async function ok(url, payload, what) {
  log.debug("Entering ok().");
  const r = await postJson(url, payload);
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "POST " + url + " should have " + what + "; it answered " + r.status +
    " " + String(r.raw).slice(0, 400));
  log.debug("Leaving ok().");
  return r.body;
}

// One browser, with a cookie jar.
// RP-Initiated Logout asks the person to confirm a sign-out that carries no
// hint for this session (#124): GET the sign-out, and where the answer is that
// page, submit its own form — what the person would press.
async function signOut(b, url) {
  log.debug("Entering signOut().");
  const first = await b.go("GET", url);
  if (!/name="confirm_for"/.test(first.text || "")) {
    log.debug("Leaving signOut(). No confirmation asked.");
    return first;
  }
  const fields = {};
  (first.text.match(/<input type="hidden"[^>]*>/g) || []).forEach(
    function (tag) {
      const name = /name="([^"]+)"/.exec(tag);
      const value = /value="([^"]*)"/.exec(tag);
      if (name) {
        fields[name[1]] = value ? value[1].replace(/&amp;/g, "&") : "";
      }
    });
  fields.confirm = "yes";
  log.debug("Leaving signOut(). Confirmed.");
  return b.go("POST", String(url).split("?")[0],
              new URLSearchParams(fields).toString());
}

function browser(name) {
  log.debug("Entering browser(). " + name);
  const jar = {};
  const self = {
    async go(method, path, body) {
      log.debug("Entering go(). " + method + " " + path);
      const headers = {};
      const cookie = Object.keys(jar).map(function (k) {
        return k + "=" + jar[k];
      }).join("; ");
      if (cookie) {
        headers.cookie = cookie;
      }
      if (body !== undefined) {
        headers["Content-Type"] = "application/x-www-form-urlencoded";
      }
      const r = await fetch(absolute(path), { method: method,
        redirect: "manual", headers: headers, body: body });
      const set = r.headers.getSetCookie ? r.headers.getSetCookie() : [];
      set.forEach(function (one) {
        const pair = String(one).split(";")[0];
        const at = pair.indexOf("=");
        if (at <= 0) {
          return;
        }
        const value = pair.slice(at + 1);
        if (value === "" || /Expires=Thu, 01 Jan 1970/i.test(String(one))) {
          delete jar[pair.slice(0, at)];
        } else {
          jar[pair.slice(0, at)] = value;
        }
      });
      const text = await r.text();
      log.debug("Leaving go(). status=" + r.status);
      return { status: r.status, location: r.headers.get("location") || "",
               text: text };
    }
  };
  log.debug("Leaving browser().");
  return self;
}

function hiddenFields(html) {
  log.debug("Entering hiddenFields().");
  const out = {};
  (String(html).match(/<input type="hidden"[^>]*>/g) || [])
    .forEach(function (tag) {
      const name = /name="([^"]+)"/.exec(tag);
      const value = /value="([^"]*)"/.exec(tag);
      if (name) {
        out[name[1]] = value ? value[1].replace(/&amp;/g, "&") : "";
      }
    });
  log.debug("Leaving hiddenFields().");
  return out;
}

function decode(jwt) {
  log.debug("Entering decode().");
  const parts = String(jwt).split(".");
  log.debug("Leaving decode().");
  return { header: JSON.parse(Buffer.from(parts[0], "base64url")
                                .toString("utf8")),
           claims: JSON.parse(Buffer.from(parts[1], "base64url")
                                .toString("utf8")) };
}

function halfHash(value, hash) {
  log.debug("Entering halfHash().");
  const digest = nodeCrypto.createHash(hash).update(String(value), "ascii")
    .digest();
  log.debug("Leaving halfHash().");
  return digest.subarray(0, digest.length / 2).toString("base64url");
}

function pkce() {
  log.debug("Entering pkce().");
  const verifier = nodeCrypto.randomBytes(32).toString("base64url");
  log.debug("Leaving pkce().");
  return { verifier: verifier,
           challenge: nodeCrypto.createHash("sha256").update(verifier)
             .digest("base64url") };
}

// Where a redirect to REDIRECT put its parameters: `{ where, params }`, or
// null when it went anywhere else.
function atClient(r, redirect) {
  log.debug("Entering atClient().");
  const target = redirect || REDIRECT;
  if (!(r.status === 302 || r.status === 303) ||
      String(r.location).indexOf(target) !== 0) {
    log.debug("Leaving atClient(). Not at the client.");
    return null;
  }
  const url = new URL(r.location);
  const fragment = url.hash ? new URLSearchParams(url.hash.slice(1)) : null;
  log.debug("Leaving atClient().");
  return fragment && Array.from(fragment.keys()).length
    ? { where: "fragment", params: fragment }
    : { where: "query", params: url.searchParams };
}

async function signIn(b, location, who) {
  log.debug("Entering signIn(). who=" + who);
  const page = await b.go("GET", location);
  assert.strictEqual(page.status, 200, "the sign-in screen: " + page.status +
                     " " + page.text.slice(0, 300));
  const fields = hiddenFields(page.text);
  fields.username = who;
  fields.password = PASSWORD;
  fields.action = "login";
  const posted = await b.go("POST", R + "/authn/login", form(fields));
  log.debug("Leaving signIn().");
  return posted;
}

// An authorization request; follows a sign-in when there is no session.
async function authorize(b, params, who) {
  log.debug("Entering authorize().");
  let r = await b.go("GET", R + "/oauth2/authorize?" + form(params));
  if ((r.status === 302 || r.status === 303) &&
      /\/authn\/login\?authn=/.test(r.location) && who) {
    const signed = await signIn(b, r.location, who);
    r = await b.go("GET", signed.location);
  }
  log.debug("Leaving authorize(). " + r.status);
  return r;
}

function basicFor(client) {
  log.debug("Entering basicFor().");
  log.debug("Leaving basicFor().");
  return "Basic " + Buffer.from(encodeURIComponent(client.client_id) + ":" +
                                encodeURIComponent(client.client_secret))
    .toString("base64");
}

function token(client, body) {
  log.debug("Entering token().");
  log.debug("Leaving token().");
  return send(base + R + "/oauth2/token", { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded",
               Authorization: basicFor(client) },
    body: form(body) });
}

async function register(metadata) {
  log.debug("Entering register().");
  // `none` since #125 (Multiple Response Type Encoding Practices section 4),
  // registered because a registered list is enforced (#120).
  const types = ["code", "code id_token", "id_token", "none"].concat(strict ? []
    : ["id_token token", "code token", "code id_token token"]);
  const r = await postJson(base + R + "/oauth2/register", Object.assign({
    redirect_uris: [REDIRECT], token_endpoint_auth_method:
      "client_secret_basic",
    grant_types: ["authorization_code", "refresh_token"].concat(strict ? []
      : ["implicit"]),
    response_types: types
  }, metadata || {}));
  log.debug("Leaving register(). " + r.status);
  return r;
}

async function registered(metadata, scope) {
  log.debug("Entering registered().");
  const r = await register(metadata);
  assert.strictEqual(r.status, 201, "a registration: " + r.status + " " +
                     r.raw.slice(0, 400));
  // One scope per grant: the register holds (client, scope) pairs.
  for (const one of String(scope || "openid profile email address phone")
         .split(" ")) {
    await ok(realmApi + "/consent/grant-global-consent",
             { client: r.body.client_id, scope: one },
             "consented " + one + " for everybody on " + r.body.client_id);
  }
  log.debug("Leaving registered().");
  return r.body;
}

function codeRequest(client, extra) {
  log.debug("Entering codeRequest().");
  const p = pkce();
  const params = Object.assign({ response_type: "code",
    client_id: client.client_id, redirect_uri: REDIRECT,
    scope: "openid", state: "st-" + STAMP,
    nonce: "n-" + nodeCrypto.randomBytes(4).toString("hex"),
    code_challenge: p.challenge, code_challenge_method: "S256" },
    extra || {});
  log.debug("Leaving codeRequest().");
  return { params: params, verifier: p.verifier };
}

async function codeTokens(b, client, extra, who) {
  log.debug("Entering codeTokens().");
  const asked = codeRequest(client, extra);
  const r = await authorize(b, asked.params, who);
  const back = atClient(r);
  assert.ok(back && back.params.get("code"), "a code: " + r.status + " " +
            r.location + " " + r.text.slice(0, 300));
  const t = await token(client, { grant_type: "authorization_code",
    code: back.params.get("code"), redirect_uri: REDIRECT,
    code_verifier: asked.verifier });
  assert.strictEqual(t.status, 200, "the tokens: " + t.raw.slice(0, 400));
  log.debug("Leaving codeTokens().");
  return t.body;
}

async function setUp() {
  log.debug("Entering setUp().");
  log.info("=== 0. a throwaway realm " + REALM + " ===");
  await ok(base + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "OIDC Core " + STAMP },
    "created the realm");
  await ok(realmApi + "/config/set", { key: "oauth2.openRegistration",
                                       value: true },
           "opened dynamic registration in the realm");
  const mode = await send(base + R + "/oauth2/rfc9700");
  strict = !!(mode.body && mode.body.enabled);
  log.info("RFC 9700 mode in the realm: " + strict +
           (strict ? " — hybrid responses carry no access token here" : ""));
  for (const who of [ALICE, BOB]) {
    await ok(realmApi + "/users/create", {
      username: who, invent: false, credential: "password",
      password: PASSWORD,
      attributes: { cn: "OIDC " + who, givenName: "OIDC", sn: who,
                    mail: who + "@oidccore.test",
                    telephoneNumber: "+12065550100",
                    street: "1 Test Street", l: "Testville",
                    postalCode: "98101", c: "US" } },
      "created " + who);
  }
  log.debug("Leaving setUp().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving OIDC Core at " + base + R);
  await setUp();

  log.info("=== a. discovery ===");
  let r = await send(base + R + "/.well-known/openid-configuration");
  check("the provider publishes pairwise, the four prompt values, display " +
        "values, the address and phone scopes and their claims", function () {
    assert.strictEqual(r.status, 200, r.raw.slice(0, 200));
    assert.deepStrictEqual(r.body.subject_types_supported.slice().sort(),
                           ["pairwise", "public"]);
    ["none", "login", "consent", "select_account"].forEach(function (one) {
      assert.ok(r.body.prompt_values_supported.indexOf(one) >= 0, one);
    });
    assert.ok(Array.isArray(r.body.display_values_supported));
    ["address", "phone"].forEach(function (one) {
      assert.ok(r.body.scopes_supported.indexOf(one) >= 0, one);
    });
    // And the Identity Assurance Claims Registration's (#128).
    ["address", "phone_number", "birthdate", "acr", "nationalities",
     "place_of_birth", "title", "msisdn", "birth_family_name"]
      .forEach(function (one) {
        assert.ok(r.body.claims_supported.indexOf(one) >= 0, one);
      });
  });
  const issuer = r.body.issuer;

  log.info("=== b. at_hash and c_hash with the ID Token's own hash ===");
  const alice = browser("alice");
  const plain = await registered({});
  // The session, made on the first request.
  await codeTokens(alice, plain, {}, ALICE);
  for (const alg of Object.keys(HASH_OF)) {
    const client = await registered({ id_token_signed_response_alg: alg });
    const nonce = "n-" + nodeCrypto.randomBytes(4).toString("hex");
    r = await authorize(alice, { response_type: strict ? "code id_token"
      : "code id_token token", client_id: client.client_id,
      redirect_uri: REDIRECT, scope: "openid", nonce: nonce, state: "s" });
    const back = atClient(r);
    check("a hybrid response for an ID Token signed " + alg + " is in the " +
          "fragment and its c_hash" + (strict ? "" : " and at_hash") +
          " use " + HASH_OF[alg].toUpperCase(), function () {
      assert.ok(back && back.where === "fragment",
                r.status + " " + r.location);
      const idt = decode(back.params.get("id_token"));
      assert.strictEqual(idt.header.alg, alg);
      assert.strictEqual(idt.claims.c_hash,
                         halfHash(back.params.get("code"), HASH_OF[alg]));
      if (!strict) {
        assert.strictEqual(idt.claims.at_hash,
                           halfHash(back.params.get("access_token"),
                                    HASH_OF[alg]));
      }
      assert.strictEqual(idt.claims.nonce, nonce);
      assert.strictEqual(idt.claims.typ, undefined,
                         "an ID Token carries no typ claim");
    });
  }

  log.info("=== c. errors where the response would have gone ===");
  r = await authorize(alice, { response_type: "code id_token",
    client_id: plain.client_id, redirect_uri: REDIRECT, scope: "openid",
    nonce: "n", state: "s", prompt: "none login" });
  let back = atClient(r);
  check("A HYBRID REQUEST'S ERROR IS IN THE FRAGMENT, and prompt=none with " +
        "another value is invalid_request (OIDC Core 3.1.2.1, 3.3.2.6)",
        function () {
    assert.ok(back && back.where === "fragment", r.status + " " + r.location);
    assert.strictEqual(back.params.get("error"), "invalid_request");
  });
  r = await authorize(alice, codeRequest(plain, { prompt: "none login" })
    .params);
  back = atClient(r);
  check("the same refusal for response_type=code is in the query",
        function () {
    assert.ok(back && back.where === "query", r.status + " " + r.location);
    assert.strictEqual(back.params.get("error"), "invalid_request");
  });

  log.info("=== d. POST at the authorization endpoint ===");
  const posted = codeRequest(plain);
  r = await alice.go("POST", R + "/oauth2/authorize", form(posted.params));
  back = atClient(r);
  check("POST /oauth2/authorize with a form-serialized request is answered " +
        "like a GET (OIDC Core 3.1.2.1)", function () {
    assert.ok(back && back.params.get("code"), r.status + " " + r.location);
  });

  log.info("=== e. the request rules ===");
  r = await authorize(alice, { response_type: "id_token",
    client_id: plain.client_id, redirect_uri: REDIRECT, scope: "profile",
    nonce: "n", state: "s" });
  back = atClient(r);
  check("an ID Token without the openid scope is refused invalid_scope, in " +
        "the fragment", function () {
    assert.ok(back && back.where === "fragment", r.status + " " + r.location);
    assert.strictEqual(back.params.get("error"), "invalid_scope");
  });
  r = await authorize(alice, { response_type: "id_token",
    client_id: plain.client_id, redirect_uri: REDIRECT, scope: "openid",
    state: "s" });
  back = atClient(r);
  check("THE IMPLICIT FLOW WITHOUT A NONCE IS REFUSED in every mode " +
        "(OIDC Core 3.2.2.1)", function () {
    assert.ok(back && back.params.get("error") === "invalid_request",
              r.status + " " + r.location);
  });
  r = await authorize(alice, { response_type: "code id_token",
    client_id: plain.client_id, redirect_uri: REDIRECT, scope: "openid",
    state: "s" });
  back = atClient(r);
  check("AND SO IS THE HYBRID code id_token WITHOUT ONE (OIDC Core 3.3.2.1: " +
        "nonce is REQUIRED when an ID Token comes back from the " +
        "authorization endpoint; #187, the conformance suite's hybrid plan)",
        function () {
    assert.ok(back && back.where === "fragment" &&
              back.params.get("error") === "invalid_request",
              r.status + " " + r.location);
  });

  log.info("=== f. id_token_hint and select_account ===");
  const own = await codeTokens(alice, plain, {}, ALICE);
  r = await authorize(alice, codeRequest(plain, { prompt: "none",
    id_token_hint: own.id_token }).params);
  check("prompt=none with the signed-in person's own id_token_hint is " +
        "answered with a code", function () {
    back = atClient(r);
    assert.ok(back && back.params.get("code"), r.status + " " + r.location);
  });
  const bob = browser("bob");
  const bobs = await codeTokens(bob, plain, {}, BOB);
  r = await authorize(alice, codeRequest(plain, { prompt: "none",
    id_token_hint: bobs.id_token }).params);
  back = atClient(r);
  check("ANOTHER PERSON'S id_token_hint UNDER prompt=none IS login_required " +
        "(OIDC Core 3.1.2.1)", function () {
    assert.ok(back && back.params.get("error") === "login_required",
              r.status + " " + r.location);
  });
  const forged = own.id_token.split(".").slice(0, 2).join(".") + ".AAAA";
  r = await authorize(alice, codeRequest(plain, { id_token_hint: forged })
    .params);
  back = atClient(r);
  check("an id_token_hint that does not verify is invalid_request",
        function () {
    assert.ok(back && back.params.get("error") === "invalid_request",
              r.status + " " + r.location);
  });
  r = await alice.go("GET", R + "/oauth2/authorize?" +
                     form(codeRequest(plain, { prompt: "select_account" })
                       .params));
  check("prompt=select_account sends a signed-in person to the sign-in " +
        "screen to choose the account", function () {
    assert.ok((r.status === 302 || r.status === 303) &&
              /\/authn\/login\?authn=/.test(r.location),
              r.status + " " + r.location);
  });

  log.info("=== g. section 5.4 ===");
  const scoped = await codeTokens(alice, plain,
    { scope: "openid profile email address phone" });
  const scopedIdt = decode(scoped.id_token).claims;
  check("A CODE-FLOW ID TOKEN CARRIES NO PROFILE CLAIMS — they are " +
        "UserInfo's " +
        "(section 5.4)", function () {
    assert.strictEqual(scopedIdt.email, undefined, JSON.stringify(scopedIdt));
    assert.strictEqual(scopedIdt.name, undefined, JSON.stringify(scopedIdt));
  });
  r = await send(base + R + "/oauth2/userinfo",
                 { headers: { Authorization: "Bearer " +
                              scoped.access_token } });
  check("UserInfo answers profile, email, address and phone, with the ID " +
        "Token's sub", function () {
    assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
    assert.strictEqual(r.body.sub, scopedIdt.sub);
    // An address, not a particular one: development answers the address it
    // invents for everybody, product the entry's `mail`.
    assert.ok(/@/.test(String(r.body.email || "")), r.body.email);
    assert.strictEqual(r.body.phone_number, "+12065550100");
    assert.ok(r.body.address && r.body.address.locality === "Testville",
              JSON.stringify(r.body.address));
  });
  r = await authorize(alice, { response_type: "id_token",
    client_id: plain.client_id, redirect_uri: REDIRECT,
    scope: "openid email", nonce: "n-" + STAMP, state: "s" });
  back = atClient(r);
  check("while response_type=id_token, which issues no access token, puts " +
        "the scope claims in the ID Token", function () {
    assert.ok(back && back.params.get("id_token"),
              r.status + " " + r.location);
    const idt = decode(back.params.get("id_token")).claims;
    assert.ok(/@/.test(String(idt.email || "")), JSON.stringify(idt));
  });

  log.info("=== h. UserInfo's form-body access token ===");
  r = await send(base + R + "/oauth2/userinfo", { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form({ access_token: scoped.access_token }) });
  check("an access token in a form body is accepted (RFC 6750 2.2)",
        function () {
    assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
    assert.strictEqual(r.body.sub, scopedIdt.sub);
  });
  r = await send(base + R + "/oauth2/userinfo", { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded",
               Authorization: "Bearer " + scoped.access_token },
    body: form({ access_token: scoped.access_token }) });
  check("and one in the header AND the body is refused", function () {
    assert.strictEqual(r.status, 400, r.raw.slice(0, 300));
  });

  log.info("=== i. the code's bindings, and exact redirect matching ===");
  const other = await registered({});
  let asked = codeRequest(plain);
  r = await authorize(alice, asked.params);
  back = atClient(r);
  let t = await token(other, { grant_type: "authorization_code",
    code: back.params.get("code"), redirect_uri: REDIRECT,
    code_verifier: asked.verifier });
  check("A CODE REDEEMED BY ANOTHER CLIENT IS invalid_grant, in every mode",
        function () {
    assert.strictEqual(t.status, 400, t.raw.slice(0, 300));
    assert.strictEqual(t.body.error, "invalid_grant");
  });
  t = await token(plain, { grant_type: "authorization_code",
    code: back.params.get("code"), code_verifier: asked.verifier });
  check("and one redeemed without its redirect_uri is invalid_grant",
        function () {
    assert.strictEqual(t.status, 400, t.raw.slice(0, 300));
    assert.strictEqual(t.body.error, "invalid_grant");
  });
  r = await alice.go("GET", R + "/oauth2/authorize?" + form(
    codeRequest(plain, { redirect_uri: REDIRECT + "/elsewhere" }).params));
  check("A REGISTERED CLIENT'S redirect_uri IS MATCHED EXACTLY in every " +
        "mode, and a mismatch is answered here, never redirected",
        function () {
    assert.strictEqual(r.status, 400, r.status + " " + r.location);
  });

  log.info("=== j. token_endpoint_auth_signing_alg ===");
  const pinned = await registered({
    token_endpoint_auth_method: "client_secret_jwt",
    token_endpoint_auth_signing_alg: "HS512" });
  const assertion = function (alg) {
    log.debug("Entering assertion().");
    const head = Buffer.from(JSON.stringify({ alg: alg, typ: "JWT" }))
      .toString("base64url");
    const now = Math.floor(Date.now() / 1000);
    const body = Buffer.from(JSON.stringify({ iss: pinned.client_id,
      sub: pinned.client_id, aud: issuer + "/oauth2/token",
      jti: nodeCrypto.randomBytes(8).toString("hex"), iat: now,
      exp: now + 60 })).toString("base64url");
    const mac = nodeCrypto.createHmac(alg === "HS512" ? "sha512" : "sha256",
      pinned.client_secret).update(head + "." + body).digest("base64url");
    log.debug("Leaving assertion().");
    return head + "." + body + "." + mac;
  };
  asked = codeRequest(pinned);
  r = await authorize(alice, asked.params);
  back = atClient(r);
  t = await send(base + R + "/oauth2/token", { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form({ grant_type: "authorization_code",
      code: back.params.get("code"), redirect_uri: REDIRECT,
      code_verifier: asked.verifier, client_id: pinned.client_id,
      client_assertion_type:
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      client_assertion: assertion("HS256") }) });
  check("AN ASSERTION NOT SIGNED WITH THE REGISTERED " +
        "token_endpoint_auth_signing_alg IS invalid_client (OIDC Core 9)",
        function () {
    assert.strictEqual(t.status, 401, t.raw.slice(0, 300));
    assert.strictEqual(t.body.error, "invalid_client");
  });

  log.info("=== k. pairwise subjects ===");
  const pairwiseA = await registered({ subject_type: "pairwise" });
  const pairwiseB = await registered({ subject_type: "pairwise",
                                       redirect_uris: [REDIRECT2] });
  const publicSub = decode(own.id_token).claims.sub;
  const pa = await codeTokens(alice, pairwiseA);
  const paSub = decode(pa.id_token).claims.sub;
  asked = codeRequest(pairwiseB, { redirect_uri: REDIRECT2 });
  r = await authorize(alice, asked.params);
  back = atClient(r, REDIRECT2);
  t = await token(pairwiseB, { grant_type: "authorization_code",
    code: back.params.get("code"), redirect_uri: REDIRECT2,
    code_verifier: asked.verifier });
  const pbSub = decode(t.body.id_token).claims.sub;
  r = await send(base + R + "/oauth2/userinfo",
                 { headers: { Authorization: "Bearer " + pa.access_token } });
  check("A PAIRWISE CLIENT IS GIVEN A sub OF ITS OWN, another sector a " +
        "different one, and UserInfo names the same sub as its ID Token " +
        "(OIDC Core 8)", function () {
    assert.ok(paSub && paSub !== publicSub, paSub + " vs " + publicSub);
    assert.ok(pbSub && pbSub !== paSub && pbSub !== publicSub, pbSub);
    assert.strictEqual(r.body.sub, paSub);
  });
  r = await register({ subject_type: "pairwise",
                       redirect_uris: [REDIRECT, REDIRECT2] });
  check("a pairwise registration whose redirect URIs span two hosts with no " +
        "sector_identifier_uri is refused", function () {
    assert.strictEqual(r.status, 400, r.raw.slice(0, 300));
    assert.strictEqual(r.body.error, "invalid_client_metadata");
  });
  r = await register({ subject_type: "pairwise",
    sector_identifier_uri: "https://sector.invalid/uris.json" });
  check("and one whose sector_identifier_uri cannot be fetched is refused " +
        "(section 8.1: the OP MUST validate it)", function () {
    assert.strictEqual(r.status, 400, r.raw.slice(0, 300));
    assert.ok(/sector_identifier_uri/.test(r.body.error_description),
              r.raw.slice(0, 300));
  });

  log.info("=== l. offline_access ===");
  // With the consent screen on, asking for offline_access DRAWS it, and
  // agreeing records the consent section 11 accepts in place of
  // prompt=consent. The case section 11 removes the scope in is the one with
  // nothing to show that anybody agreed: the screen off and no prompt=consent.
  await ok(realmApi + "/config/set", { key: "oauth2.consentRequired",
                                       value: false },
           "turned the consent screen off in the realm");
  const stripped = await codeTokens(alice, plain,
    { scope: "openid offline_access" });
  check("offline_access with neither prompt=consent nor a recorded consent " +
        "is not granted (OIDC Core 11)", function () {
    assert.ok(String(stripped.scope || "").split(" ")
      .indexOf("offline_access") < 0, stripped.scope);
    assert.ok(stripped.refresh_token, "a refresh token is still issued");
  });
  await ok(realmApi + "/config/set", { key: "oauth2.consentRequired",
                                       value: true },
           "turned the consent screen back on");
  const offlineClient = await registered({}, "openid offline_access");
  const offline = await codeTokens(alice, offlineClient,
    { scope: "openid offline_access" });
  check("while a recorded consent to it grants it", function () {
    assert.ok(String(offline.scope || "").split(" ")
      .indexOf("offline_access") >= 0, offline.scope);
  });
  const online = await codeTokens(alice, plain, { scope: "openid" });
  t = await token(plain, { grant_type: "refresh_token",
                           refresh_token: online.refresh_token });
  check("an online refresh token works while the session lasts",
        function () {
    assert.strictEqual(t.status, 200, t.raw.slice(0, 300));
  });
  const onlineAgain = t.body.refresh_token || online.refresh_token;
  // RP-Initiated Logout's end_session_endpoint: the session ends. (The
  // global `/logout` would disown every token the person holds, offline ones
  // included, which is a different promise.)
  const out = await signOut(alice, R + "/oauth2/logout");
  assert.ok(out.status < 500, "sign-out: " + out.status);
  t = await token(plain, { grant_type: "refresh_token",
                           refresh_token: onlineAgain });
  check("AND IS REFUSED ONCE THE PERSON HAS SIGNED OUT — it was granted " +
        "without offline_access", function () {
    assert.strictEqual(t.status, 400, t.raw.slice(0, 300));
    assert.strictEqual(t.body.error, "invalid_grant");
  });
  t = await token(offlineClient, { grant_type: "refresh_token",
                                   refresh_token: offline.refresh_token });
  check("while the offline one outlives the session", function () {
    assert.strictEqual(t.status, 200, t.raw.slice(0, 300));
  });

  log.info("=== m. an essential acr claims request ===");
  const carol = browser("carol");
  await codeTokens(carol, plain, {}, BOB);
  r = await authorize(carol, codeRequest(plain, { prompt: "none",
    claims: JSON.stringify({ id_token: { acr: { essential: true,
      values: ["urn:example:oidccore:unmeetable"] } } }) }).params);
  back = atClient(r);
  check("AN ESSENTIAL acr THE SESSION CANNOT MEET IS A REFUSAL, not a " +
        "hint (section 5.5.1.1)", function () {
    assert.ok(back && ["login_required", "unmet_authentication_requirements"]
      .indexOf(back.params.get("error")) >= 0, r.status + " " + r.location);
  });

  log.info("=== n. response_type=none and an explicit query (#125) ===");
  // Signed in again: section l signed alice out.
  r = await authorize(alice, { response_type: "none",
    client_id: plain.client_id, redirect_uri: REDIRECT, scope: "openid",
    state: "s-none" }, ALICE);
  back = atClient(r);
  check("response_type=none issues nothing: state and iss alone, in the " +
        "query (section 4)", function () {
    assert.ok(back && back.where === "query", r.status + " " + r.location);
    assert.strictEqual(back.params.get("state"), "s-none");
    assert.ok(back.params.get("iss"), r.location);
    ["code", "access_token", "id_token", "error"].forEach(function (one) {
      assert.strictEqual(back.params.get(one), null, one + " in " +
                         r.location);
    });
  });
  r = await authorize(alice, { response_type: "none code",
    client_id: plain.client_id, redirect_uri: REDIRECT, scope: "openid",
    state: "s" });
  back = atClient(r);
  check("none combined with another type is unsupported_response_type",
        function () {
    assert.ok(back, r.status + " " + r.location);
    assert.strictEqual(back.params.get("error"), "unsupported_response_type");
  });
  r = await authorize(alice, { response_type: "id_token",
    response_mode: "query", client_id: plain.client_id,
    redirect_uri: REDIRECT, scope: "openid", nonce: "n", state: "s" });
  back = atClient(r);
  check("response_mode=query for an ID Token is REFUSED, and the refusal " +
        "is in the fragment (section 2.1's MUST NOT)", function () {
    assert.ok(back && back.where === "fragment", r.status + " " + r.location);
    assert.strictEqual(back.params.get("error"), "invalid_request");
  });

  log.info("=== o. form_post, a successful code response (#126) ===");
  const formPost = codeRequest(plain, { response_mode: "form_post" });
  r = await authorize(alice, formPost.params, ALICE);
  const hidden = function (name) {
    const m = new RegExp('name="' + name + '" value="([^"]*)"').exec(r.text);
    return m ? m[1].replace(/&amp;/g, "&") : null;
  };
  check("response_mode=form_post answers a form POSTing code, state and iss " +
        "to the redirect URI, with a real button (Form Post Response Mode " +
        "section 2)", function () {
    assert.strictEqual(r.status, 200, r.status + " " + r.location);
    assert.ok(new RegExp('<form[^>]+method="post"[^>]+action="' +
      REDIRECT.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + '"').test(r.text),
      r.text.slice(0, 400));
    assert.ok(hidden("code"), "no code field");
    assert.strictEqual(hidden("state"), formPost.params.state);
    assert.ok(hidden("iss"), "no iss field");
    assert.ok(/type="submit"/.test(r.text), "no button");
  });

  log.info("=== p. verified_claims (#127) ===");
  await ok(realmApi + "/config/set", { key: "oauth2.idaTrustFrameworks",
                                       value: "urn:example:oidccore,eidas" },
           "configured the realm's trust frameworks");
  r = await send(base + R + "/.well-known/openid-configuration");
  check("discovery publishes Identity Assurance's section 7 members",
        function () {
    assert.strictEqual(r.body.verified_claims_supported, true);
    assert.ok(r.body.trust_frameworks_supported.indexOf("eidas") >= 0,
              JSON.stringify(r.body.trust_frameworks_supported));
    assert.deepStrictEqual(r.body.evidence_supported.slice(0).sort(),
      ["document", "electronic_record", "electronic_signature", "vouch"]);
    assert.ok(r.body.documents_supported.indexOf("passport") >= 0);
    assert.ok(r.body.claims_supported.indexOf("verified_claims") >= 0);
    assert.ok(r.body.claims_in_verified_claims_supported
      .indexOf("given_name") >= 0);
  });
  const refusedRecord = await postJson(realmApi +
    "/users/record-verification", { user: ALICE,
      verification: { trust_framework: "eidas", evidence: [
        { type: "document", document_details: { type: "library" } }] },
      claims: ["given_name"] });
  check("a verification with a document type outside the vocabulary is " +
        "refused", function () {
    assert.strictEqual(refusedRecord.status, 400, refusedRecord.raw);
  });
  const recorded = await ok(realmApi + "/users/record-verification", {
    user: ALICE,
    verification: { trust_framework: "eidas", assurance_level: "high",
      evidence: [{ type: "document",
        check_details: [{ check_method: "vpip" }],
        document_details: { type: "passport", document_number: "P1" } }] },
    claims: ["given_name", "family_name"] }, "recorded a verification");
  r = await send(realmApi + "/users/verifications?user=" +
                 encodeURIComponent(ALICE));
  check("the verification is recorded with the entry's values, and listed",
        function () {
    assert.strictEqual(recorded.verification.claims.given_name, "OIDC");
    assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
    assert.ok(r.body.verifications.some(function (one) {
      return one.id === recorded.verification.id;
    }), r.raw.slice(0, 400));
  });
  const dave = browser("dave");
  const verified = await codeTokens(dave, plain, { claims: JSON.stringify({
    userinfo: { verified_claims: {
      verification: { trust_framework: { value: "eidas" },
        evidence: [{ type: { value: "document" },
                     document_details: { type: null } }] },
      claims: { given_name: null, family_name: null,
                birthdate: { purpose: "To check your age" } } } },
    id_token: { verified_claims: {
      verification: { trust_framework: { value: "de_aml" } },
      claims: { given_name: null } } } }) }, ALICE);
  r = await send(base + R + "/oauth2/userinfo",
                 { headers: { Authorization: "Bearer " +
                              verified.access_token } });
  check("UserInfo answers verified_claims from the eIDAS passport check, " +
        "with only the members asked for", function () {
    assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
    const vc = r.body.verified_claims;
    assert.ok(vc && !Array.isArray(vc), r.raw.slice(0, 400));
    assert.strictEqual(vc.verification.trust_framework, "eidas");
    assert.strictEqual(vc.verification.assurance_level, undefined);
    assert.strictEqual(vc.verification.evidence[0].type, "document");
    assert.strictEqual(vc.verification.evidence[0].document_details.type,
                       "passport");
    assert.strictEqual(
      vc.verification.evidence[0].document_details.document_number,
      undefined);
    assert.strictEqual(vc.claims.given_name, "OIDC");
    assert.strictEqual(vc.claims.family_name, ALICE);
    assert.strictEqual(vc.claims.birthdate, undefined);
  });
  check("an ID Token asking for a framework nothing was verified under " +
        "carries no verified_claims (section 6)", function () {
    assert.strictEqual(decode(verified.id_token).claims.verified_claims,
                       undefined);
  });
  r = await authorize(dave, codeRequest(plain, { claims: JSON.stringify({
    userinfo: { verified_claims: { claims: { given_name: null } } } })
  }).params);
  back = atClient(r);
  check("a verified_claims request with no verification is invalid_request",
        function () {
    assert.ok(back, r.status + " " + r.location);
    assert.strictEqual(back.params.get("error"), "invalid_request");
  });

  assert.ok(checks >= 34, "only " + checks + " checks ran; a section has " +
                                             "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_oidc_core")
  .description("OpenID Connect Core over the wire (#118): the ID Token's " +
    "hashes by alg, error encoding, POST, the request rules, id_token_hint, " +
    "section 5.4, the code's bindings, pairwise subjects and offline_access.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
