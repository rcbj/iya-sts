"use strict";
//
// File: sts_fapi_baseline.js
//
// ---------------------------------------------------------------------------
// FAPI 1.0 PART 1 BASELINE, OVER THE WIRE (#138, 2026-09-22).
//
// A throwaway realm (left behind) carrying `oauth2.fapi=1-baseline`, with
// dynamic registration opened so that clients can register what is under
// test:
//
//   a. GET /oauth2/fapi reports the profile, and RFC 9700 mode is implied.
//   b. DISCOVERY advertises S256 only and no client secret method.
//   c. REGISTRATION refuses a secret method, an http redirect URI and a
//      1024-bit RSA key, and takes a private_key_jwt client.
//   d. THE AUTHORIZATION REQUEST: no PKCE, plain PKCE, no nonce with openid,
//      no state without it, and no redirect_uri are refused.
//   e. CONSENT: an administrator's global consent is not the user's
//      approval; the screen is shown and the Allow is what issues the code.
//   f. THE TOKEN ENDPOINT: a private_key_jwt client is issued a token for at
//      most 600 s (item 21) with its scope (item 15); the code is spent once
//      (item 13); a client_secret_basic client is refused (item 4); a request
//      naming two clients is refused (item 19).
//   g. A NAMED AUTHORIZATION SERVER with `fapi=off` opts out of its realm's
//      profile.
//   h. THE HOSTED SURFACES: a portal sign-in in the realm asks the person's
//      own consent, and the portal's client authenticated by
//      private_key_jwt with a key this realm's CA issued it.
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
var log = bunyan.createLogger({ name: "sts_fapi_baseline",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const REALM = ("fapi-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                              .slice(0, 31);
const R = "/realm/" + REALM;
const realmApi = base + R + "/admin-api";
const REDIRECT = "https://rp.fapi.example.test/cb";
const PASSWORD = "fapi-Baseline-Passw0rd!-" + String(Date.now()).slice(-6);
const ALICE = names.usernameFor("fapi-alice");
const SCOPE = "openid profile email";

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

function pkce() {
  log.debug("Entering pkce().");
  const verifier = nodeCrypto.randomBytes(32).toString("base64url");
  log.debug("Leaving pkce().");
  return { verifier: verifier,
           challenge: nodeCrypto.createHash("sha256").update(verifier)
             .digest("base64url") };
}

// Where a redirect to REDIRECT put its parameters, or null.
function atClient(r) {
  log.debug("Entering atClient().");
  if (!(r.status === 302 || r.status === 303) ||
      String(r.location).indexOf(REDIRECT) !== 0) {
    log.debug("Leaving atClient(). Not at the client.");
    return null;
  }
  const url = new URL(r.location);
  log.debug("Leaving atClient().");
  return url.searchParams;
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

// Follows redirects inside this service, signing in when asked, until the
// answer leaves it or is a page. `onConsent` answers a consent screen.
async function follow(b, first, who, onConsent) {
  log.debug("Entering follow().");
  let r = first;
  for (let i = 0; i < 12; i++) {
    if (!(r.status === 302 || r.status === 303)) {
      break;
    }
    const where = absolute(r.location);
    if (where.indexOf(base) !== 0) {
      break;
    }
    if (/\/authn\/login\?authn=/.test(where) && who) {
      const signed = await signIn(b, where, who);
      r = signed;
      continue;
    }
    r = await b.go("GET", where);
    if (r.status === 200 && /id="consent-allow"/.test(r.text) && onConsent) {
      onConsent.shown += 1;
      const fields = hiddenFields(r.text);
      fields.action = "allow";
      r = await b.go("POST", R + "/oauth2/consent", form(fields));
    }
  }
  log.debug("Leaving follow(). " + r.status);
  return r;
}

// An EC P-256 key the client proves possession of, and its public JWK.
function clientKey(kid) {
  log.debug("Entering clientKey().");
  const pair = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = pair.publicKey.export({ format: "jwk" });
  jwk.kid = kid;
  jwk.use = "sig";
  jwk.alg = "ES256";
  log.debug("Leaving clientKey().");
  return { privateKey: pair.privateKey, jwk: jwk };
}

// RFC 7523 section 3's client assertion, signed ES256.
function assertion(clientId, key, aud) {
  log.debug("Entering assertion().");
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "ES256", typ: "JWT", kid: key.jwk.kid };
  const claims = { iss: clientId, sub: clientId, aud: aud,
                   jti: nodeCrypto.randomBytes(12).toString("base64url"),
                   iat: now, exp: now + 60 };
  const input = Buffer.from(JSON.stringify(header)).toString("base64url") +
                "." + Buffer.from(JSON.stringify(claims))
                  .toString("base64url");
  const sig = nodeCrypto.sign("sha256", Buffer.from(input),
    { key: key.privateKey, dsaEncoding: "ieee-p1363" });
  log.debug("Leaving assertion().");
  return input + "." + sig.toString("base64url");
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving FAPI 1.0 Baseline at " + base + R);

  log.info("=== 0. a throwaway realm " + REALM + " ===");
  await ok(base + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "FAPI " + STAMP },
    "created the realm");
  await ok(realmApi + "/config/set", { key: "oauth2.fapi",
                                       value: "1-baseline" },
           "put the realm in FAPI 1.0 Baseline");
  await ok(realmApi + "/config/set", { key: "oauth2.openRegistration",
                                       value: true },
           "opened dynamic registration in the realm");
  await ok(realmApi + "/users/create", {
    username: ALICE, invent: false, credential: "password",
    password: PASSWORD,
    attributes: { cn: "FAPI " + ALICE, givenName: "FAPI", sn: ALICE,
                  mail: ALICE + "@fapi.test" } }, "created " + ALICE);

  log.info("=== a. the report ===");
  let r = await send(base + R + "/oauth2/fapi");
  check("GET /oauth2/fapi reports FAPI 1.0 Baseline in force, row by row",
        function () {
    assert.strictEqual(r.status, 200, r.raw.slice(0, 200));
    assert.strictEqual(r.body.profile, "1-baseline");
    assert.strictEqual(r.body.enabled, true);
    const ids = r.body.requirements.map(function (row) {
      return row.id;
    });
    ["confidential-client-auth", "pkce-s256", "explicit-consent",
     "client-id-mismatch", "access-token-lifetime"].forEach(function (id) {
      assert.ok(ids.indexOf(id) >= 0, id);
    });
  });
  r = await send(base + R + "/oauth2/rfc9700");
  check("and RFC 9700 mode is on because of it", function () {
    assert.strictEqual(r.body.enabled, true, r.raw.slice(0, 300));
  });

  log.info("=== b. discovery ===");
  r = await send(base + R + "/.well-known/openid-configuration");
  const issuer = r.body.issuer;
  check("discovery advertises S256 alone and no client secret method",
        function () {
    assert.deepStrictEqual(r.body.code_challenge_methods_supported, ["S256"]);
    const methods = r.body.token_endpoint_auth_methods_supported;
    assert.ok(methods.indexOf("private_key_jwt") >= 0, methods.join(" "));
    assert.ok(methods.indexOf("client_secret_basic") < 0, methods.join(" "));
    assert.ok(methods.indexOf("client_secret_post") < 0, methods.join(" "));
  });

  log.info("=== c. registration ===");
  const key = clientKey("fapi-" + STAMP);
  const metadata = { redirect_uris: [REDIRECT],
    token_endpoint_auth_method: "private_key_jwt",
    token_endpoint_auth_signing_alg: "ES256",
    jwks: { keys: [key.jwk] },
    grant_types: ["authorization_code", "refresh_token",
                  "client_credentials"],
    response_types: ["code"], scope: SCOPE };
  r = await postJson(base + R + "/oauth2/register",
                     Object.assign({}, metadata,
                       { token_endpoint_auth_method: "client_secret_basic",
                         jwks: undefined,
                         token_endpoint_auth_signing_alg: undefined }));
  check("a client_secret_basic registration is refused (item 4)",
        function () {
    assert.strictEqual(r.status, 400, r.raw.slice(0, 300));
    assert.strictEqual(r.body.error, "invalid_client_metadata");
  });
  r = await postJson(base + R + "/oauth2/register", Object.assign({},
    metadata, { redirect_uris: ["http://rp.fapi.example.test/cb"] }));
  check("an http redirect URI is refused (item 20)", function () {
    assert.strictEqual(r.status, 400, r.raw.slice(0, 300));
    assert.ok(/invalid_redirect_uri|invalid_client_metadata/
      .test(r.body.error), r.raw.slice(0, 300));
  });
  const small = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 1024 })
    .publicKey.export({ format: "jwk" });
  r = await postJson(base + R + "/oauth2/register", Object.assign({},
    metadata, { token_endpoint_auth_signing_alg: "RS256",
                jwks: { keys: [small] } }));
  check("a 1024-bit RSA key is refused (item 5)", function () {
    assert.strictEqual(r.status, 400, r.raw.slice(0, 300));
    assert.strictEqual(r.body.error, "invalid_client_metadata");
  });
  r = await postJson(base + R + "/oauth2/register", metadata);
  check("a private_key_jwt client with a P-256 key is registered",
        function () {
    assert.strictEqual(r.status, 201, r.raw.slice(0, 400));
  });
  const client = r.body;
  const clientAuth = function () {
    return { client_id: client.client_id,
             client_assertion_type:
               "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
             client_assertion: assertion(client.client_id, key, issuer) };
  };
  const token = function (body) {
    return send(base + R + "/oauth2/token", { method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: form(Object.assign(clientAuth(), body)) });
  };

  log.info("=== d. the authorization request ===");
  const alice = browser("alice");
  const p = pkce();
  const good = { response_type: "code", client_id: client.client_id,
    redirect_uri: REDIRECT, scope: SCOPE, state: "st-" + STAMP,
    nonce: "n-" + STAMP, code_challenge: p.challenge,
    code_challenge_method: "S256" };
  const refusedWith = async function (overrides, what) {
    const params = Object.assign({}, good, overrides);
    Object.keys(params).forEach(function (k) {
      if (params[k] === undefined) {
        delete params[k];
      }
    });
    const answer = await alice.go("GET", R + "/oauth2/authorize?" +
                                         form(params));
    const back = atClient(answer);
    check(what, function () {
      assert.ok((back && back.get("error") === "invalid_request") ||
                answer.status === 400,
                answer.status + " " + answer.location + " " +
                answer.text.slice(0, 200));
    });
  };
  await refusedWith({ code_challenge: undefined,
                      code_challenge_method: undefined },
                    "an authorization request without PKCE is refused " +
                    "(item 7)");
  await refusedWith({ code_challenge_method: "plain",
                      code_challenge: p.verifier },
                    "and one with plain PKCE");
  await refusedWith({ nonce: undefined },
                    "openid without a nonce is refused (5.2.2.2)");
  await refusedWith({ scope: "profile", state: undefined, nonce: undefined },
                    "no openid and no state is refused (5.2.2.3)");
  r = await alice.go("GET", R + "/oauth2/authorize?" + form(Object.assign({},
    good, { redirect_uri: "" })));
  check("no redirect_uri is a 400 on this server, never a redirect " +
        "(item 9)", function () {
    assert.strictEqual(r.status, 400, r.status + " " + r.location);
  });

  log.info("=== e. consent ===");
  for (const one of SCOPE.split(" ")) {
    await ok(realmApi + "/consent/grant-global-consent",
             { client: client.client_id, scope: one },
             "consented " + one + " for everybody on " + client.client_id);
  }
  const consent = { shown: 0 };
  r = await follow(alice, await alice.go("GET", R + "/oauth2/authorize?" +
                                                form(good)), ALICE, consent);
  let back = atClient(r);
  check("AN ADMINISTRATOR'S GLOBAL CONSENT IS NOT THE USER'S APPROVAL: the " +
        "consent screen is shown, and its Allow issues the code (item 12)",
        function () {
    assert.strictEqual(consent.shown, 1, "consent screens: " +
                       consent.shown);
    assert.ok(back && back.get("code"), r.status + " " + r.location + " " +
              String(r.text).slice(0, 300));
    assert.strictEqual(back.get("iss"), issuer);
  });

  log.info("=== f. the token endpoint ===");
  const code = back.get("code");
  let t = await token({ grant_type: "authorization_code", code: code,
                        redirect_uri: REDIRECT, code_verifier: p.verifier });
  check("the code is redeemed by private_key_jwt; the unbound access token " +
        "lives 600 s at most (item 21) and the scope is returned (item 15)",
        function () {
    assert.strictEqual(t.status, 200, t.raw.slice(0, 400));
    assert.ok(t.body.expires_in <= 600, "expires_in " + t.body.expires_in);
    const at = decode(t.body.access_token).claims;
    assert.ok(at.exp - at.iat <= 600, "exp - iat = " + (at.exp - at.iat));
    assert.ok(typeof t.body.scope === "string" &&
              t.body.scope.indexOf("openid") >= 0, t.body.scope);
  });
  t = await token({ grant_type: "authorization_code", code: code,
                    redirect_uri: REDIRECT, code_verifier: p.verifier });
  check("the same code again is refused (item 13)", function () {
    assert.strictEqual(t.status, 400, t.raw.slice(0, 300));
    assert.strictEqual(t.body.error, "invalid_grant");
  });

  const SECRET_CLIENT = "fapi-secret-" + STAMP;
  const SECRET = "fapi-secret-" + nodeCrypto.randomBytes(12).toString("hex");
  await ok(realmApi + "/applications/create",
           { identifier: SECRET_CLIENT, protocols: ["oauth2"],
             fields: { oauthClientId: SECRET_CLIENT,
                       oauthClientSecret: SECRET,
                       oauthTokenEndpointAuthMethod: "client_secret_basic" } },
           "created a client_secret_basic application");
  const basic = "Basic " + Buffer.from(encodeURIComponent(SECRET_CLIENT) +
    ":" + encodeURIComponent(SECRET)).toString("base64");
  t = await send(base + R + "/oauth2/token", { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded",
               Authorization: basic },
    body: form({ grant_type: "client_credentials" }) });
  // 400 where the realm's advertised methods refuse it first (the metadata
  // FAPI narrowed is enforced), 401 where FAPI's own check does.
  check("a client authenticating with client_secret_basic is refused " +
        "invalid_client (item 4)", function () {
    assert.ok(t.status === 400 || t.status === 401, t.raw.slice(0, 300));
    assert.strictEqual(t.body.error, "invalid_client");
  });
  t = await send(base + R + "/oauth2/token", { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded",
               Authorization: basic },
    body: form(Object.assign(clientAuth(),
                             { grant_type: "client_credentials" })) });
  check("a request naming two clients — a Basic header for one, an " +
        "assertion for another — is refused invalid_client (item 19)",
        function () {
    assert.strictEqual(t.status, 401, t.raw.slice(0, 300));
    assert.strictEqual(t.body.error, "invalid_client");
  });
  t = await token({ grant_type: "client_credentials" });
  check("while the private_key_jwt client's client_credentials token is " +
        "issued, for 600 s at most", function () {
    assert.strictEqual(t.status, 200, t.raw.slice(0, 300));
    assert.ok(t.body.expires_in <= 600, "expires_in " + t.body.expires_in);
  });

  log.info("=== g. a named authorization server opting out ===");
  await ok(realmApi + "/authorization-servers/create",
           { id: "open", label: "Not FAPI" }, "created a named server");
  await ok(realmApi + "/authorization-servers/set",
           { id: "open", member: "fapi", value: "off" },
           "opted it out of the realm's profile");
  r = await send(base + R + "/open/oauth2/fapi");
  check("a named server with fapi=off reports no profile", function () {
    assert.strictEqual(r.status, 200, r.raw.slice(0, 200));
    assert.strictEqual(r.body.enabled, false, r.raw.slice(0, 300));
  });
  r = await send(base + R + "/.well-known/oauth-authorization-server/open");
  check("and advertises the secret methods FAPI would take away",
        function () {
    assert.strictEqual(r.status, 200, r.raw.slice(0, 200));
    assert.ok(r.body.token_endpoint_auth_methods_supported
      .indexOf("client_secret_basic") >= 0,
      JSON.stringify(r.body.token_endpoint_auth_methods_supported));
  });
  r = await postJson(realmApi + "/authorization-servers/set",
                     { id: "open", member: "fapi", value: "2" });
  check("a value that is not a profile or off is refused", function () {
    assert.ok(r.status >= 400 || (r.body && r.body.ok === false),
              r.status + " " + r.raw.slice(0, 200));
  });

  log.info("=== h. the hosted surfaces ===");
  const portal = browser("portal");
  const portalConsent = { shown: 0 };
  r = await follow(portal, await portal.go("GET", R + "/portal"), ALICE,
                   portalConsent);
  check("the portal signs its person in under FAPI, asking their own " +
        "consent rather than taking its seeded global one", function () {
    assert.strictEqual(portalConsent.shown, 1,
                       "consent screens: " + portalConsent.shown);
    assert.ok(r.status === 200 || (r.status === 302 &&
              /\/portal/.test(r.location)),
              r.status + " " + r.location + " " + r.text.slice(0, 300));
  });
  const view = await send(realmApi + "/applications?application=" +
                          "sts-user-portal");
  const entry = (view.body && (view.body.application || view.body)) || {};
  const fields = entry.fields || {};
  const first = function (v) {
    return String((Array.isArray(v) ? v[0] : v) || "");
  };
  check("the portal's client authenticates by private_key_jwt, holds no " +
        "secret, and was issued its key by this realm's CA", function () {
    assert.strictEqual(first(fields.oauthTokenEndpointAuthMethod),
                       "private_key_jwt", JSON.stringify(fields).slice(0, 400));
    assert.strictEqual(first(fields.oauthClientSecret), "");
    assert.ok(first(fields.oauthAssertionKid), "no kid on the entry");
    assert.strictEqual(first(fields.oauthAssertionKeySource), "issued");
  });

  assert.ok(checks >= 23, "only " + checks + " checks ran; a section has " +
                                             "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_fapi_baseline")
  .description("FAPI 1.0 Part 1 Baseline over the wire (#138): the report, " +
    "discovery, registration, the authorization request, consent, the " +
    "token endpoint, a named server opting out and the hosted surfaces.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
