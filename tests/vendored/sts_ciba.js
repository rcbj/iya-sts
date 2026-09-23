"use strict";
//
// File: sts_ciba.js
//
// ---------------------------------------------------------------------------
// OPENID CONNECT CIBA CORE 1.0 (#131, 2026-09-23), over HTTP, in a throwaway
// realm with oauth2.ciba on.
//
//   1. DISCOVERY: the endpoint, the three modes, the grant.
//   2. THE ENDPOINT'S REFUSALS: no client authentication; a client with no
//      delivery mode; no openid; two hints; a name nobody holds
//      (unknown_user_id, in both modes).
//   3. POLL: the acknowledgement; authorization_pending, then slow_down;
//      the person approves on /portal/ciba, where the binding message is
//      shown; the tokens, once.
//   4. DENY on the portal: access_denied.
//   5. THE USER CODE: missing, wrong, then set by the person on the portal
//      and accepted.
//   6. PING AND PUSH (development only — product will not dial this job's
//      listener, an internal address): the ping names the request with the
//      client's Bearer and the token request answers; the push carries the
//      tokens, the ID Token naming the request.
//
// OWNED HERE (local: true): this repository's authorization server and
// portal.
// ---------------------------------------------------------------------------

const assert = require("assert");
const crypto = require("crypto");
const https = require("https");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const registry = require("./sts_applications.js");
const facts = require("./service_facts.js");
const testCa = require("./outbound_test_ca.js");

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
var log = bunyan.createLogger({ name: "sts_ciba",
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
const REALM = ("ciba-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                             .slice(0, 31);
const base = root + "/realm/" + REALM;
const api = base + "/admin-api";
const HOLDER = names.usernameFor("ciba-holder");
const PASSWORD = "Ciba-holder-" + crypto.randomBytes(9).toString("base64url") +
                 "-Aa1!";
const SECRET = "ciba-secret-" + crypto.randomBytes(12).toString("hex");
const GRANT = "urn:openid:params:grant-type:ciba";

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
  const r = await fetch(absolute, { method: method, headers: headers,
                                    body: body, redirect: "manual" });
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

async function ok(url, payload, what) {
  log.debug("Entering ok().");
  const r = await hop(null, "POST", url, { json: payload || {} });
  assert.ok(r.status === 200 && r.json && r.json.ok !== false,
    "POST " + url + " should have " + what + "; it answered " + r.status +
    " " + r.text.slice(0, 400));
  log.debug("Leaving ok().");
  return r.json;
}

// A portal page in a browser that signs in with the password on the way.
async function portal(who, path) {
  log.debug("Entering portal(). " + path);
  let r = await hop(who, "GET", base + path);
  for (let n = 0; n < 14 && r.status !== 200; n += 1) {
    if (r.status !== 302 && r.status !== 303) {
      break;
    }
    r = await hop(who, "GET", r.location);
    if (r.status === 200 && /name="authn_id"/.test(r.text)) {
      const fields = hiddenFields(r.text);
      fields.username = HOLDER;
      fields.password = PASSWORD;
      fields.action = "login";
      r = await hop(who, "POST", base + "/authn/login", { form: fields });
    }
  }
  log.debug("Leaving portal(). " + r.status);
  return r;
}

function csrfOf(html) {
  log.debug("Entering csrfOf().");
  log.debug("Leaving csrfOf().");
  return (/name="csrf_token" value="([^"]+)"/.exec(html) || [])[1] || "";
}

async function authorize(client, fields) {
  log.debug("Entering authorize(). " + client);
  const r = await hop(null, "POST", base + "/oauth2/bc-authorize", { form:
    Object.assign({ client_id: client, client_secret: SECRET,
                    scope: "openid" }, fields) });
  log.debug("Leaving authorize(). " + r.status);
  return r;
}

async function token(client, id) {
  log.debug("Entering token(). " + client);
  const r = await hop(null, "POST", base + "/oauth2/token", { form: {
    grant_type: GRANT, auth_req_id: id, client_id: client,
    client_secret: SECRET } });
  log.debug("Leaving token(). " + r.status);
  return r;
}

async function answerOnPortal(browser, id, action) {
  log.debug("Entering answerOnPortal(). " + action);
  const page = await portal(browser, "/portal/ciba");
  const r = await hop(browser, "POST", base + "/portal/ciba", { form: {
    action: action, id: id, csrf_token: csrfOf(page.text) } });
  log.debug("Leaving answerOnPortal(). " + r.status);
  return { page: page, answer: r };
}

async function provision(id, extra) {
  log.debug("Entering provision(). " + id);
  await registry.provision(base, {
    identifier: id, name: "CIBA job " + id, protocols: ["oauth2", "oidc"],
    fields: Object.assign({ oauthClientId: id, oauthClientSecret: SECRET,
      oauthTokenEndpointAuthMethod: "client_secret_post",
      oauthGrantType: [GRANT], oauthScope: ["openid"] }, extra || {}),
    why: "a CIBA client of sts_ciba.js"
  });
  log.debug("Leaving provision().");
}

async function test() {
  log.debug("Entering test().");
  const product = await facts.isProduct(root + "/admin-api");
  log.info("=== 0. a throwaway realm " + REALM + " (" +
           (product ? "product" : "development") + ") ===");
  await ok(root + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "CIBA " + STAMP },
    "created the realm");
  await ok(api + "/config/set", { key: "oauth2.ciba", value: true },
           "turned CIBA on in the realm");
  await provision("ciba-poll", { oauthBackchannelTokenDeliveryMode: "poll" });
  await provision("ciba-code", { oauthBackchannelTokenDeliveryMode: "poll",
                                 oauthBackchannelUserCodeParameter: "TRUE" });
  await provision("ciba-none", {});
  await registry.ensurePerson(base, HOLDER, PASSWORD);

  log.info("=== 1. discovery ===");
  let r = await hop(null, "GET", base + "/.well-known/openid-configuration");
  check("the endpoint, the three modes and the grant are published",
        function () {
    assert.strictEqual(r.json.backchannel_authentication_endpoint,
                       base + "/oauth2/bc-authorize");
    assert.deepStrictEqual(r.json.backchannel_token_delivery_modes_supported,
                           ["poll", "ping", "push"]);
    assert.ok(r.json.grant_types_supported.indexOf(GRANT) >= 0);
    assert.strictEqual(r.json.backchannel_user_code_parameter_supported, true);
  });

  log.info("=== 2. the endpoint's refusals ===");
  const refusals = [
    ["no client authentication", 401, "invalid_client",
     hop(null, "POST", base + "/oauth2/bc-authorize", { form: {
       client_id: "ciba-poll", scope: "openid", login_hint: HOLDER } })],
    ["a client with no delivery mode", 400, "unauthorized_client",
     authorize("ciba-none", { login_hint: HOLDER })],
    ["no openid in the scope", 400, "invalid_scope",
     authorize("ciba-poll", { scope: "profile", login_hint: HOLDER })],
    ["two hints", 400, "invalid_request",
     authorize("ciba-poll", { login_hint: HOLDER, id_token_hint: "x.y.z" })],
    ["a name nobody holds (unknown_user_id, in both modes)", 400,
     "unknown_user_id", authorize("ciba-poll", { login_hint:
       "nobody-" + STAMP })]
  ];
  for (const one of refusals) {
    const got = await one[3];
    check("refused: " + one[0], function () {
      assert.strictEqual(got.status, one[1], got.text.slice(0, 300));
      assert.strictEqual(got.json.error, one[2], got.text.slice(0, 300));
    });
  }

  log.info("=== 3. poll ===");
  const binding = "BIND-" + crypto.randomBytes(3).toString("hex");
  r = await authorize("ciba-poll", { login_hint: HOLDER,
                                     binding_message: binding });
  const id = r.json && r.json.auth_req_id;
  check("the acknowledgement: auth_req_id, expires_in and interval",
        function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.ok(/^[A-Za-z0-9_-]{43}$/.test(id));
    assert.ok(r.json.expires_in > 0 && r.json.interval > 0);
  });
  const pending = await token("ciba-poll", id);
  const fast = await token("ciba-poll", id);
  check("authorization_pending, then slow_down when asked again at once",
        function () {
    assert.strictEqual(pending.json.error, "authorization_pending",
                       pending.text);
    assert.strictEqual(fast.json.error, "slow_down", fast.text);
  });
  const browser = jar();
  const approved = await answerOnPortal(browser, id, "approve");
  check("the person sees the request with its binding message on " +
        "/portal/ciba, and approves it", function () {
    assert.strictEqual(approved.page.status, 200,
                       approved.page.text.slice(0, 300));
    assert.ok(approved.page.text.indexOf(binding) >= 0, "no binding message");
    assert.strictEqual(approved.answer.status, 303,
                       approved.answer.text.slice(0, 300));
  });
  await new Promise(function (resolve) { setTimeout(resolve, 11000); });
  const tokens = await token("ciba-poll", id);
  const again = await token("ciba-poll", id);
  check("the tokens, once: an ID Token for the person", function () {
    assert.strictEqual(tokens.status, 200, tokens.text.slice(0, 300));
    assert.ok(/^urn:uuid:/.test(payloadOf(tokens.json.id_token).sub));
    assert.strictEqual(again.json.error, "invalid_grant", again.text);
  });

  log.info("=== 4. deny ===");
  r = await authorize("ciba-poll", { login_hint: HOLDER });
  const deniedId = r.json.auth_req_id;
  await answerOnPortal(browser, deniedId, "deny");
  const denied = await token("ciba-poll", deniedId);
  check("a denied request is access_denied", function () {
    assert.strictEqual(denied.json.error, "access_denied", denied.text);
  });

  log.info("=== 5. the user code ===");
  const missing = await authorize("ciba-code", { login_hint: HOLDER });
  let page = await portal(browser, "/portal/ciba");
  const set = await hop(browser, "POST", base + "/portal/ciba", { form: {
    action: "set-code", code: "blue-horse-7", csrf_token: csrfOf(page.text) }
  });
  const wrong = await authorize("ciba-code", { login_hint: HOLDER,
                                               user_code: "red-horse-7" });
  const right = await authorize("ciba-code", { login_hint: HOLDER,
                                               user_code: "blue-horse-7" });
  check("missing_user_code, the person sets one, invalid_user_code for " +
        "another, and the right one is accepted", function () {
    assert.strictEqual(missing.json.error, "missing_user_code",
                       missing.text);
    assert.strictEqual(set.status, 303, set.text.slice(0, 300));
    assert.strictEqual(wrong.json.error, "invalid_user_code", wrong.text);
    assert.strictEqual(right.status, 200, right.text.slice(0, 300));
  });

  log.info("=== 6. ping and push ===");
  if (product) {
    log.info("[skip] section 6: product mode will not dial this job's " +
             "listener, which is an internal address.");
  } else {
    const host = process.env.CIBA_NOTIFY_HOST ||
                 process.env.GNAP_PUSH_HOST || "localhost";
    const credential = await testCa.selfSignedCertificate(host);
    const received = [];
    const listener = https.createServer({ key: credential.key,
                                          cert: credential.cert },
      function (req, res) {
        let text = "";
        req.on("data", function (c) { text += c; });
        req.on("end", function () {
          received.push({ path: req.url, auth: req.headers.authorization,
                          body: text ? JSON.parse(text) : {} });
          res.writeHead(204);
          res.end();
        });
      });
    await new Promise(function (resolve) {
      listener.listen(0, "0.0.0.0", resolve);
    });
    const at = "https://" + host + ":" + listener.address().port;
    await ok(api + "/config/set", { key:
      "federation.outboundSkipTlsVerification", value: true },
      "let the realm reach this job's self-signed listener");
    await provision("ciba-ping", { oauthBackchannelTokenDeliveryMode: "ping",
      oauthBackchannelClientNotificationEndpoint: at + "/ping" });
    await provision("ciba-push", { oauthBackchannelTokenDeliveryMode: "push",
      oauthBackchannelClientNotificationEndpoint: at + "/push" });
    r = await authorize("ciba-ping", { login_hint: HOLDER,
                                       client_notification_token: "nt-ping" });
    const pingId = r.json.auth_req_id;
    await answerOnPortal(browser, pingId, "approve");
    await new Promise(function (resolve) { setTimeout(resolve, 2000); });
    const pinged = received.filter(function (one) {
      return one.path === "/ping";
    })[0];
    const pingTokens = await token("ciba-ping", pingId);
    check("the ping names the request, with the client's Bearer, and the " +
          "token request answers", function () {
      assert.ok(pinged, JSON.stringify(received));
      assert.strictEqual(pinged.auth, "Bearer nt-ping");
      assert.strictEqual(pinged.body.auth_req_id, pingId);
      assert.strictEqual(pingTokens.status, 200, pingTokens.text);
    });
    r = await authorize("ciba-push", { login_hint: HOLDER,
                                       client_notification_token: "nt-push" });
    const pushId = r.json.auth_req_id;
    await answerOnPortal(browser, pushId, "approve");
    await new Promise(function (resolve) { setTimeout(resolve, 2000); });
    const pushed = received.filter(function (one) {
      return one.path === "/push";
    })[0];
    const pushToken = await token("ciba-push", pushId);
    check("the push carries the tokens, its ID Token naming the request, " +
          "and a push client may not poll", function () {
      assert.ok(pushed && pushed.body.access_token, JSON.stringify(received));
      assert.strictEqual(pushed.auth, "Bearer nt-push");
      assert.strictEqual(payloadOf(pushed.body.id_token)[
        "urn:openid:params:jwt:claim:auth_req_id"], pushId);
      assert.strictEqual(pushToken.json.error, "unauthorized_client");
    });
    listener.close();
  }

  assert.ok(checks >= 12, "only " + checks + " checks ran");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

new Command()
  .description("OpenID Connect CIBA (#131): discovery, the endpoint's " +
    "refusals, poll with an approval on /portal/ciba, deny, the user code, " +
    "and ping and push in development.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
