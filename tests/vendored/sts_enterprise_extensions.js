"use strict";
//
// File: sts_enterprise_extensions.js
//
// ---------------------------------------------------------------------------
// OPENID CONNECT ENTERPRISE EXTENSIONS 1.0 (#148, 2026-09-26), over HTTP, in
// a throwaway realm.
//
//   1. DISCOVERY: session_expiry, tenant and aud_sub in claims_supported.
//   2. aud_sub: recorded by an administrator on /admin-api, a malformed one
//      refused.
//   3. THE ID TOKEN: tenant is the realm's id, session_expiry the session's
//      absolute end (after iat, and the same across two tokens of one
//      session), aud_sub the value recorded for this client.
//   4. tenant ON THE REQUEST: another realm's refused invalid_request at the
//      client's redirect URI; this realm's accepted.
//   5. domain_hint: a domain a federation relationship lists in
//      fedHomeRealmDomain sends the person to that relationship's login;
//      another domain goes to the sign-in screen.
//
// OWNED HERE (local: true): this repository's authorization server and API.
// ---------------------------------------------------------------------------

const assert = require("assert");
const crypto = require("crypto");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const registry = require("./sts_applications.js");

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
var log = bunyan.createLogger({ name: "sts_enterprise_extensions",
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
const TAG = STAMP.toLowerCase().replace(/[^a-z0-9]/g, "").slice(0, 12);
const REALM = "ee-" + TAG;
const base = root + "/realm/" + REALM;
const api = base + "/admin-api";
const PERSON = names.usernameFor("ee-person");
const PASSWORD = "Ee-" + crypto.randomBytes(9).toString("base64url") + "-Aa1!";
const RP_REDIRECT = "https://rp.enterprise.example/cb";
const HOME_DOMAIN = "home-" + TAG + ".example";

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

// A cookie jar that keeps each cookie's Path, as a browser does: the two
// realms are on one host, and their session cookies share names, so a jar
// keyed by name alone lets the provider realm's sign-in overwrite the OP
// realm's session.
function jar() {
  log.debug("Entering jar().");
  const cookies = {};
  log.debug("Leaving jar().");
  return {
    header: function header(url) {
      log.debug("Entering header().");
      const at = new URL(url).pathname;
      const out = Object.keys(cookies).map(function (k) {
        return cookies[k];
      }).filter(function (c) {
        return at === c.path || at.indexOf(c.path.replace(/\/?$/, "/")) ===
          0 || c.path === "/";
      }).sort(function (a, b) {
        return b.path.length - a.path.length;
      }).map(function (c) {
        return c.name + "=" + c.value;
      }).join("; ");
      log.debug("Leaving header().");
      return out;
    },
    take: function take(response, url) {
      log.debug("Entering take().");
      const set = typeof response.headers.getSetCookie === "function"
        ? response.headers.getSetCookie() : [];
      set.forEach(function (line) {
        const pair = line.split(";")[0];
        const eq = pair.indexOf("=");
        const name = pair.slice(0, eq).trim();
        const value = pair.slice(eq + 1).trim();
        const p = (/;\s*path=([^;]*)/i.exec(line) || [])[1];
        const cpath = p ? p.trim() :
          new URL(url).pathname.replace(/\/[^/]*$/, "") || "/";
        const key = name + " " + cpath;
        if (/Max-Age=0/i.test(line) || value === "") {
          delete cookies[key];
        } else {
          cookies[key] = { name: name, value: value, path: cpath };
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
  if (who && who.header(url)) {
    headers.cookie = who.header(url);
  }
  const r = await fetch(url, { method: method, headers: headers,
                               body: body, redirect: "manual" });
  if (who) {
    who.take(r, url);
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
  if (process.env.CA_TRACE) {
    log.info("HOP " + method + " " + url + " -> " + r.status + " " +
             (location || ""));
  }
  return { status: r.status, text: text, json: json,
           location: location ? new URL(location, url).toString() : "" };
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

function csrfOf(html) {
  log.debug("Entering csrfOf().");
  log.debug("Leaving csrfOf().");
  return (/name="csrf_token" value="([^"]+)"/.exec(html) || [])[1] || "";
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

// Follows redirects inside this service, signing the person in on the
// realm's screen and allowing a consent screen, until the answer leaves the
// service or is a page.
async function follow(who, first) {
  log.debug("Entering follow().");
  let r = first;
  for (let i = 0; i < 20; i++) {
    if (r.status === 200 && /name="authn_id"/.test(r.text)) {
      const fields = hiddenFields(r.text);
      fields.username = PERSON;
      fields.password = PASSWORD;
      fields.action = "login";
      r = await hop(who, "POST", base + "/authn/login", { form: fields });
      continue;
    }
    if (r.status === 200 && /id="consent-allow"/.test(r.text)) {
      const fields = hiddenFields(r.text);
      fields.action = "allow";
      r = await hop(who, "POST", base + "/oauth2/consent", { form: fields });
      continue;
    }
    if (!(r.status === 302 || r.status === 303) ||
        r.location.indexOf(root + "/") !== 0) {
      break;
    }
    r = await hop(who, "GET", r.location);
  }
  log.debug("Leaving follow(). " + r.status);
  return r;
}

function authorizeUrl(client, extra) {
  log.debug("Entering authorizeUrl().");
  const verifier = crypto.randomBytes(32).toString("base64url");
  const q = new URLSearchParams(Object.assign({
    response_type: "code", client_id: client.client_id,
    redirect_uri: RP_REDIRECT, scope: "openid", state: "s-" + TAG,
    nonce: "n-" + TAG, code_challenge: crypto.createHash("sha256")
      .update(verifier).digest("base64url"),
    code_challenge_method: "S256" }, extra || {}));
  log.debug("Leaving authorizeUrl().");
  return { url: base + "/oauth2/authorize?" + q.toString(),
           verifier: verifier };
}

async function idTokenFor(browser, client) {
  log.debug("Entering idTokenFor().");
  const asked = authorizeUrl(client);
  const landed = await follow(browser, await hop(browser, "GET", asked.url));
  assert.ok(/^https:\/\/rp\.enterprise\.example\/cb\?/.test(landed.location),
            "the authorization response: " + landed.status + " " +
            (landed.location || landed.text.slice(0, 300)));
  const code = new URL(landed.location).searchParams.get("code");
  const tokens = await hop(null, "POST", base + "/oauth2/token", { form: {
    grant_type: "authorization_code", code: code, redirect_uri: RP_REDIRECT,
    code_verifier: asked.verifier, client_id: client.client_id,
    client_secret: client.client_secret } });
  assert.strictEqual(tokens.status, 200, tokens.text.slice(0, 300));
  log.debug("Leaving idTokenFor().");
  return payloadOf(tokens.json.id_token);
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. a throwaway realm " + REALM + " ===");
  await ok(root + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "Enterprise Extensions " + TAG },
    "created the realm");
  await ok(api + "/config/set", { key: "oauth2.openRegistration",
                                  value: true }, "opened registration");
  await registry.ensurePerson(base, PERSON, PASSWORD);
  const reg = await hop(null, "POST", base + "/oauth2/register", { json: {
    redirect_uris: [RP_REDIRECT], token_endpoint_auth_method:
      "client_secret_post", grant_types: ["authorization_code"],
    response_types: ["code"], client_name: "RP " + TAG } });
  assert.strictEqual(reg.status, 201, reg.text.slice(0, 300));
  const client = reg.json;

  log.info("=== 1. discovery ===");
  const discovery = (await hop(null, "GET", base +
                               "/.well-known/openid-configuration")).json;
  check("claims_supported names session_expiry, tenant and aud_sub",
        function () {
    ["session_expiry", "tenant", "aud_sub"].forEach(function (c) {
      assert.ok(discovery.claims_supported.indexOf(c) >= 0, c);
    });
  });

  log.info("=== 2. aud_sub recorded by an administrator ===");
  const bad = await hop(null, "POST", api + "/users/set-aud-sub",
    { json: { user: PERSON, client: "has space", value: "x" } });
  await ok(api + "/users/set-aud-sub", { user: PERSON,
    client: client.client_id, value: "acct-" + TAG }, "recorded the aud_sub");
  check("a malformed aud_sub act is refused", function () {
    assert.strictEqual(bad.status, 400, bad.text.slice(0, 200));
  });

  log.info("=== 3. the ID Token ===");
  const browser = jar();
  const first = await idTokenFor(browser, client);
  const second = await idTokenFor(browser, client);
  check("tenant is the realm's id, aud_sub the recorded value, and " +
        "session_expiry the session's absolute end", function () {
    assert.strictEqual(first.tenant, REALM, JSON.stringify(first));
    assert.strictEqual(first.aud_sub, "acct-" + TAG);
    assert.ok(Number(first.session_expiry) > Number(first.iat),
              JSON.stringify(first));
    assert.strictEqual(second.session_expiry, first.session_expiry,
                       "a second token of the same session names the same " +
                       "end: sessions are absolute");
  });

  log.info("=== 4. tenant on the request ===");
  const other = await hop(jar(), "GET",
    authorizeUrl(client, { tenant: "some-other-realm" }).url);
  const same = await hop(jar(), "GET",
    authorizeUrl(client, { tenant: REALM }).url);
  check("another realm's tenant is refused invalid_request at the client; " +
        "this realm's is accepted", function () {
    assert.ok(/error=invalid_request/.test(other.location) &&
              other.location.indexOf(RP_REDIRECT) === 0,
              other.status + " " + other.location);
    assert.ok(same.status === 302 && same.location.indexOf(RP_REDIRECT) !==
              0, same.status + " " + same.location);
  });

  log.info("=== 5. domain_hint ===");
  const partnerKey = crypto.generateKeyPairSync("ec",
    { namedCurve: "P-256" }).publicKey.export({ format: "jwk" });
  const fed = "ee-home-" + TAG;
  await ok(api + "/federation/create", { id: fed,
    role: "service-provider", protocol: "oidc",
    peer: "https://" + HOME_DOMAIN }, "created the relationship");
  const fields = { fedAllowUnencrypted: "TRUE",
    fedSsoUrl: "https://" + HOME_DOMAIN + "/authorize",
    fedScope: "openid", fedUsernameSource: "preferred_username",
    fedClientId: "ee-" + TAG, fedResponseType: "id_token",
    fedJwks: JSON.stringify({ keys: [Object.assign(partnerKey,
      { kid: "p1", use: "sig", alg: "ES256" })] }) };
  for (const field of Object.keys(fields)) {
    await ok(api + "/federation/set", { id: fed, field: field,
      value: fields[field] }, "set " + field);
  }
  await ok(api + "/federation/add-value", { id: fed,
    field: "fedHomeRealmDomain", value: HOME_DOMAIN.toUpperCase() },
    "listed the home domain");
  await ok(api + "/federation/enable", { id: fed }, "enabled it");
  const hinted = await hop(jar(), "GET",
    authorizeUrl(client, { domain_hint: HOME_DOMAIN }).url);
  const elsewhere = await hop(jar(), "GET",
    authorizeUrl(client, { domain_hint: "nowhere-" + TAG + ".example" }).url);
  check("a listed domain goes to that relationship's login; another goes " +
        "to the sign-in screen", function () {
    assert.ok(hinted.location.indexOf(base + "/federation/login/" + fed) ===
              0 || hinted.location.indexOf("/federation/login/" + fed) >= 0,
              hinted.status + " " + hinted.location);
    assert.ok(/\/authn\/login/.test(elsewhere.location),
              elsewhere.status + " " + elsewhere.location);
  });

  assert.ok(checks >= 5, "only " + checks + " checks ran");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

new Command()
  .description("OpenID Connect Enterprise Extensions (#148): the three ID " +
    "Token claims, tenant and domain_hint on the request, over HTTP.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
