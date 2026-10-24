// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// ===========================================================================
// CONSUMER AND SOCIAL PROVIDERS, OVER THE NETWORK (#565).
//
// `tests/federation_consumer_providers.js` holds the profiles, the adapters,
// the risk work and the portal's connect in process, against provider-shaped
// servers. This job drives the same service a deployment runs, over HTTP, in
// whichever mode it is in, and asserts what an operator and a browser see of
// the CATEGORY — which is the part every mode and every stack must agree on:
//
//   1. The realm switch: with `federation.consumerProviders` off a provider
//      relationship cannot be created; on, `POST /admin-api/federation/create`
//      with `provider` makes one from its profile — created disabled,
//      `jit-namespaced`, auto-create ON in either mode, no encryption key.
//   2. The list: `?category=consumer` holds it and `?category=enterprise`
//      does not.
//   3. A newcomer signed in through it gets an entry of their own,
//      `<relationship>~sub-<uuid>`, and a LOCAL person with the same name and
//      the same address is left exactly as they were — an address is never a
//      matching key.
//   4. any-existing is refused on a consumer relationship in every mode.
//   5. The switch off again: the login endpoint refuses (403) and the
//      relationship's readiness names the setting.
//
// THE PROVIDER IS ANOTHER REALM OF THE SAME SERVICE, through the
// `generic-oidc` profile on the front-channel shape `sts_federation_realms.js`
// argues for (an ID Token by form_post against pasted keys), because a
// service cannot always dial itself. Every realm, person, application and
// relationship is CREATED by this run and left standing; nothing
// service-wide is changed.
// ===========================================================================

"use strict";

// The sign-in screen over `/authn-api` (#571).
const authnSignin = require("./authn_signin");
const assert = require("assert");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const facts = require("./service_facts.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, for the reason tests/vendored/wait_for.js gives.
  appconfigProblem = e;
  appconfig = {};
}

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_federation_consumer",
                                level: appconfig.LOG_LEVEL ||
                                       process.env.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");

const STAMP = names.runStamp();
const IDP = "ci-" + STAMP;
const SP = "cs-" + STAMP;
const REL = "consumer-oidc";
const CLIENT = "cs-consumer-" + STAMP;
const PASSWORD = "Consumer-Federation-Passw0rd!-" + String(Date.now()).slice(-6);
const IDP_MAIL = IDP + ".example.net";

let isProduct = false;
let checks = 0;
const failures = [];

async function check(what, fn) {
  log.debug("Entering check(). " + what);
  try {
    await fn();
    checks += 1;
    log.info("  ✓ " + what);
  } catch (e) {
    log.debug("Caught in check(): " + ((e && e.message) || e));
    failures.push(what + " — " + ((e && e.message) || e));
    log.error("  ✗ " + what + "  — " + ((e && e.message) || e));
  }
  log.debug("Leaving check().");
}

function must(condition, message) {
  log.debug("Entering must().");
  if (!condition) {
    log.debug("Leaving must(). Refused.");
    throw new Error("SETUP: " + message);
  }
  log.debug("Leaving must().");
}

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

function realmBase(realm) {
  log.debug("Entering realmBase().");
  log.debug("Leaving realmBase().");
  return base + "/realm/" + realm;
}

function squash(text) {
  log.debug("Entering squash().");
  log.debug("Leaving squash().");
  return String(text || "").replace(/<style[\s\S]*?<\/style>/g, " ")
    .replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim().slice(0, 300);
}

function htmlDecode(text) {
  log.debug("Entering htmlDecode().");
  log.debug("Leaving htmlDecode().");
  return String(text || "").replace(/&quot;/g, "\"").replace(/&#39;/g, "'")
    .replace(/&apos;/g, "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&");
}

// The management API in the realm named; the run's token is attached by
// tests/tools/attach-admin-token.js.
async function api(realm, method, path, payload) {
  log.debug("Entering api(). " + method + " " + path);
  const options = { method: method, redirect: "manual", headers: {} };
  if (payload !== undefined) {
    options.headers["content-type"] = "application/json";
    options.body = JSON.stringify(payload);
  }
  const prefix = realm ? realmBase(realm) : base;
  const r = await fetch(prefix + "/admin-api" + path, options);
  const text = await r.text();
  let body = null;
  try {
    body = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in api(): " + ((e && e.message) || e));
    // Not JSON; `text` carries the answer into every message quoting it.
    body = null;
  }
  log.debug("Leaving api(). status=" + r.status);
  return { status: r.status, body: body, text: text };
}

function jar() {
  log.debug("Entering jar().");
  const store = {};
  log.debug("Leaving jar().");
  return {
    header: function () {
      log.debug("Entering header().");
      log.debug("Leaving header().");
      return Object.keys(store).map(function (k) {
        return k + "=" + store[k];
      }).join("; ");
    },
    take: function (res) {
      log.debug("Entering take().");
      (res.headers.getSetCookie ? res.headers.getSetCookie() : []).forEach(
        function (line) {
          const pair = line.split(";")[0];
          const i = pair.indexOf("=");
          store[pair.slice(0, i).trim()] = pair.slice(i + 1).trim();
        });
      log.debug("Leaving take().");
    },
    has: function () {
      log.debug("Entering has().");
      log.debug("Leaving has().");
      return Object.keys(store).length > 0;
    }
  };
}

async function hop(cookies, url, options) {
  log.debug("Entering hop(). " + ((options && options.method) || "GET") +
            " " + url);
  const o = Object.assign({ redirect: "manual", headers: {} }, options || {});
  o.headers = Object.assign({}, o.headers);
  if (cookies && cookies.has()) {
    o.headers.cookie = cookies.header();
  }
  const r = await fetch(url, o);
  if (cookies) {
    cookies.take(r);
  }
  const body = r.status >= 300 && r.status < 400 ? "" : await r.text();
  log.debug("Leaving hop(). " + r.status);
  return { status: r.status, headers: r.headers, body: body, url: url,
           location: r.headers.get("location") || "" };
}

function postForm(cookies, url, fields) {
  log.debug("Entering postForm(). " + url);
  log.debug("Leaving postForm().");
  return hop(cookies, url, {
    method: "POST", body: new URLSearchParams(fields).toString(),
    headers: { "content-type": "application/x-www-form-urlencoded" } });
}

function formsIn(html) {
  log.debug("Entering formsIn().");
  const out = [];
  const re = /<form([^>]*)>([\s\S]*?)<\/form>/gi;
  let m = re.exec(String(html || ""));
  while (m) {
    const action = htmlDecode((/action="([^"]*)"/i.exec(m[1]) || [])[1] || "");
    const method = ((/method="([^"]*)"/i.exec(m[1]) || [])[1] || "get")
      .toLowerCase();
    const fields = {};
    [...m[2].matchAll(/<input[^>]*type="hidden"[^>]*>/gi)].forEach(
      function (one) {
        const n = /name="([^"]+)"/.exec(one[0]);
        const v = /value="([^"]*)"/.exec(one[0]);
        if (n) {
          fields[htmlDecode(n[1])] = v ? htmlDecode(v[1]) : "";
        }
      });
    out.push({ action: action, method: method, fields: fields,
               inner: m[2] });
    m = re.exec(String(html || ""));
  }
  log.debug("Leaving formsIn(). " + out.length);
  return out;
}

// ---------------------------------------------------------------------------
// ONE FEDERATED SIGN-IN, whole. Signs in at the partner as `idpUser`, posts
// the ID Token to the service provider's ACS, and then — where the service
// provider draws ITS OWN sign-in screen, which is the linking step — does
// what `link` says: 'stop' returns the screen, 'cancel' presses Cancel,
// anything else posts `password`. Answers the last response and a trail.
// ---------------------------------------------------------------------------
async function federatedSignIn(idpUser, opts) {
  log.debug("Entering federatedSignIn(). " + idpUser);
  const o = opts || {};
  const cookies = jar();
  const trail = { linkScreens: 0, linkScreen: null, linkScreenAt: "",
                  idpScreens: 0 };
  let r = await hop(cookies, realmBase(SP) + "/federation/login/" + REL);
  for (let step = 0; step < 24; step += 1) {
    if (r.status >= 300 && r.status < 400 && r.location) {
      const next = new URL(r.location, r.url).toString();
      // THE SIGN-IN SCREEN IS A STATIC PAGE OVER `/authn-api` SINCE #571:
      // its view is what it offers, and its acts are the API's.
      if (/\/authn\/login\?authn=/.test(next)) {
        const at = new URL(next);
        const screenBase = at.origin +
          at.pathname.replace(/\/authn\/login$/, "");
        const opened = await authnSignin.screen(screenBase, next,
          { cookie: cookies.header() });
        cookies.take({ headers: { getSetCookie: function () {
          return opened.setCookies;
        } } });
        const linking = at.pathname.indexOf("/realm/" + SP + "/") === 0;
        if (linking) {
          trail.linkScreens += 1;
          trail.linkScreen = opened.view || {};
          trail.linkScreenAt = next;
          if (o.link === "stop" || trail.linkScreens > (o.attempts || 1)) {
            r = { status: opened.status, headers: null, url: next,
                  body: JSON.stringify(opened.json), location: "" };
            break;
          }
        } else {
          trail.idpScreens += 1;
        }
        const answer = await authnSignin.submit(screenBase, next,
          linking
            ? { action: o.link === "cancel" ? "cancel" : "login",
                username: "not-the-person",
                password: o.password || PASSWORD }
            : { action: "login", username: idpUser, password: PASSWORD },
          { screen: opened });
        cookies.take({ headers: answer.headers });
        r = { status: authnSignin.responseLike(answer).status,
              headers: answer.headers, url: next,
              body: answer.text || JSON.stringify(answer.json),
              location: answer.location };
        // A REFUSED LINK is the screen drawn again with the sentence, as
        // the form was: counted, and the walk stops there.
        if (linking && answer.next === "refused") {
          trail.linkScreens += 1;
          break;
        }
        continue;
      }
      // THE CONSENT SCREEN, A PAGE OF THE SIGN-IN SURFACE SINCE #576:
      // answered over `/authn-api/consent` through the one helper.
      if (authnSignin.isConsent(next)) {
        const answer = await authnSignin.consentFor(next,
          cookies && cookies.has() ? cookies.header() : "");
        cookies.take({ headers: answer.headers });
        r = { status: authnSignin.responseLike(answer).status,
              headers: answer.headers, url: next,
              body: answer.text || JSON.stringify(answer.json),
              location: answer.location };
        continue;
      }
      r = await hop(cookies, next);
      continue;
    }
    if (r.status !== 200) {
      break;
    }
    const forms = formsIn(r.body);
    const onward = forms.find(function (f) {
      return f.method === "post" && ("id_token" in f.fields);
    });
    const consent = forms.find(function (f) {
      return /consent/.test(f.action) || "consent_id" in f.fields;
    });
    if (consent) {
      const to = new URL(consent.action || r.url, r.url).toString();
      r = await postForm(cookies, to, Object.assign({}, consent.fields, {
        action: "allow", decision: "allow" }));
      continue;
    }
    if (onward) {
      const to = new URL(onward.action, r.url).toString();
      r = await postForm(cookies, to, onward.fields);
      continue;
    }
    break;
  }
  log.debug("Leaving federatedSignIn(). " + r.status);
  return { r: r, trail: trail };
}

async function createPerson(realm, username, mail) {
  log.debug("Entering createPerson(). " + realm + " " + username);
  // The realm's attribute policy (#396) requires givenName, sn and mail of
  // every person in product mode.
  const r = await api(realm, "POST", "/users/create", {
    username: username, invent: false,
    attributes: { cn: "Consumer " + username, givenName: "Consumer",
                  sn: username, mail: mail },
    credential: "password", password: PASSWORD });
  must(r.status === 200 && r.body && r.body.ok,
       "creating " + username + " in " + realm + " answered " + r.status +
       " " + r.text.slice(0, 300));
  log.debug("Leaving createPerson().");
}

async function setSetting(realm, key, value) {
  log.debug("Entering setSetting(). " + key + "=" + value);
  const r = await api(realm, "POST", "/config/set",
                      { key: key, value: String(value) });
  must(r.status === 200 && r.body && r.body.ok !== false,
       "setting " + key + " answered " + r.status + " " +
       r.text.slice(0, 200));
  log.debug("Leaving setSetting().");
}

async function entryOf(username) {
  log.debug("Entering entryOf(). " + username);
  const r = await api(SP, "GET", "/users?user=" +
                                  encodeURIComponent(username));
  const ldap = (r.body && r.body.ldap) || {};
  log.debug("Leaving entryOf().");
  return ldap.found && ldap.entry ? ldap.entry.attributes || {} : null;
}

async function subjectAtPartner(username) {
  log.debug("Entering subjectAtPartner(). " + username);
  const r = await api(IDP, "GET", "/users?user=" +
                                   encodeURIComponent(username));
  must(r.status === 200 && r.body && r.body.subject,
       "the partner realm holds no subject for " + username + ": " +
       r.text.slice(0, 200));
  log.debug("Leaving subjectAtPartner().");
  return String(r.body.subject);
}

// One federated sign-in through the consumer relationship: the partner's
// screen, then the ID Token posted to the service provider's ACS.
async function federatedSignIn(idpUser) {
  log.debug("Entering federatedSignIn(). " + idpUser);
  const cookies = jar();
  let r = await hop(cookies, realmBase(SP) + "/federation/login/" + REL);
  for (let step = 0; step < 24; step += 1) {
    if (r.status >= 300 && r.status < 400 && r.location) {
      const next = new URL(r.location, r.url).toString();
      if (/\/authn\/login\?authn=/.test(next)) {
        const at = new URL(next);
        const screenBase = at.origin +
          at.pathname.replace(/\/authn\/login$/, "");
        const opened = await authnSignin.screen(screenBase, next,
          { cookie: cookies.header() });
        cookies.take({ headers: { getSetCookie: function () {
          return opened.setCookies;
        } } });
        const answer = await authnSignin.submit(screenBase, next,
          { action: "login", username: idpUser, password: PASSWORD },
          { screen: opened });
        cookies.take({ headers: answer.headers });
        r = { status: authnSignin.responseLike(answer).status,
              headers: answer.headers, url: next,
              body: answer.text || JSON.stringify(answer.json),
              location: answer.location };
        continue;
      }
      if (authnSignin.isConsent(next)) {
        const answer = await authnSignin.consentFor(next,
          cookies && cookies.has() ? cookies.header() : "");
        cookies.take({ headers: answer.headers });
        r = { status: authnSignin.responseLike(answer).status,
              headers: answer.headers, url: next,
              body: answer.text || JSON.stringify(answer.json),
              location: answer.location };
        continue;
      }
      r = await hop(cookies, next);
      continue;
    }
    if (r.status !== 200) {
      break;
    }
    const onward = formsIn(r.body).find(function (f) {
      return f.method === "post" && ("id_token" in f.fields);
    });
    if (onward) {
      r = await postForm(cookies, new URL(onward.action, r.url).toString(),
                         onward.fields);
      continue;
    }
    break;
  }
  log.debug("Leaving federatedSignIn(). " + r.status);
  return r;
}

async function setUp() {
  log.debug("Entering setUp().");
  isProduct = await facts.isProduct(base + "/admin-api");
  log.info("The service is in " + (isProduct ? "PRODUCT" : "DEVELOPMENT") +
           " mode. Partner realm " + IDP + ", service provider realm " + SP +
           ".");
  for (const id of [IDP, SP]) {
    const made = await api(null, "POST", "/realms/create",
                           { id: id, domain: id + ".example.net", name: id });
    must(made.status === 200 ||
         /already/i.test(JSON.stringify(made.body || made.text)),
         "creating the realm " + id + " answered " + made.status);
  }
  const d = await fetch(realmBase(IDP) + "/.well-known/openid-configuration");
  must(d.status === 200, "the partner's discovery answered " + d.status);
  const discovery = await d.json();
  const k = await fetch(discovery.jwks_uri);
  const jwks = await k.json();
  log.debug("Leaving setUp().");
  return { discovery: discovery, jwks: jwks };
}

// 1 and 2: the switch, the creation from a profile, the list.
async function theCategory(world) {
  log.debug("Entering theCategory().");
  const spec = { id: REL, role: "service-provider", protocol: "oidc",
                 provider: "generic-oidc", peer: world.discovery.issuer,
                 clientId: CLIENT };
  await check("1a. consumer providers off: a provider relationship cannot " +
              "be created", async function () {
    await setSetting(SP, "federation.consumerProviders", "false");
    const r = await api(SP, "POST", "/federation/create", spec);
    assert.ok(r.status >= 400 || (r.body && r.body.ok === false),
              "created anyway: " + r.status + " " + r.text.slice(0, 200));
  });
  let made = null;
  await check("1b. on: created from its profile, disabled, jit-namespaced, " +
              "auto-create on in either mode, no encryption key",
  async function () {
    await setSetting(SP, "federation.consumerProviders", "true");
    made = await api(SP, "POST", "/federation/create", spec);
    assert.ok(made.status === 200 && made.body && made.body.ok,
              "create answered " + made.status + " " +
              made.text.slice(0, 300));
    const rel = made.body.relationship || {};
    assert.strictEqual(rel.fedProvider, "generic-oidc");
    assert.strictEqual(rel.fedEnabled, "FALSE");
    assert.strictEqual(rel.fedSubjectPolicy, "jit-namespaced");
    assert.strictEqual(rel.fedAutocreateUsers, "TRUE");
    assert.strictEqual(rel.fedClientId, CLIENT);
    assert.ok(!rel.fedEncryptionKeyType,
              "an encryption key type was written: " +
              rel.fedEncryptionKeyType);
  });
  const settings = {
    fedSsoUrl: world.discovery.authorization_endpoint,
    fedResponseType: "id_token",
    fedJwks: JSON.stringify(world.jwks) };
  for (const field of Object.keys(settings)) {
    const set = await api(SP, "POST", "/federation/set",
                          { id: REL, field: field, value: settings[field] });
    must(set.status === 200 && set.body && set.body.ok,
         "setting " + field + " answered " + set.status + " " +
         set.text.slice(0, 200));
  }
  // A created person must satisfy the realm's attribute policy (#396) in
  // product mode, so the partner's names and address are mapped explicitly.
  for (const mapping of ["given_name=givenName", "family_name=sn",
                         "email=mail"]) {
    const mapped = await api(SP, "POST", "/federation/add-value",
                             { id: REL, field: "fedAttributeMap",
                               value: mapping });
    must(mapped.status === 200 && mapped.body && mapped.body.ok,
         "mapping " + mapping + " answered " + mapped.status);
  }
  const enabled = await api(SP, "POST", "/federation/enable", { id: REL });
  must(enabled.status === 200 && enabled.body && enabled.body.ok,
       "enabling answered " + enabled.status + " " +
       enabled.text.slice(0, 200));
  const view = await api(SP, "GET", "/federation?relationship=" + REL);
  const acs = ((view.body || {}).endpoints || {}).assertionConsumerService;
  const app = await api(IDP, "POST", "/applications/create", {
    identifier: CLIENT, name: "consumer provider " + CLIENT,
    protocols: ["oidc"],
    fields: { oauthClientId: [CLIENT], oauthRedirectUri: [acs],
              oauthTokenEndpointAuthMethod: "none",
              oauthGrantType: ["implicit"],
              oauthResponseType: ["id_token"] } });
  must(app.status === 200 && app.body && app.body.ok,
       "creating the partner's application answered " + app.status + " " +
       app.text.slice(0, 300));
  await check("2. the list: ?category=consumer holds it, ?category=" +
              "enterprise does not", async function () {
    const consumer = await api(SP, "GET", "/federation?category=consumer");
    const enterprise = await api(SP, "GET",
                                 "/federation?category=enterprise");
    const ids = function (r) {
      return ((r.body && r.body.relationships) || []).map(function (one) {
        return one.id + ":" + one.category;
      });
    };
    assert.ok(ids(consumer).indexOf(REL + ":consumer") >= 0,
              "consumer: " + ids(consumer).join(", "));
    assert.ok(ids(enterprise).every(function (one) {
      return one.indexOf(REL + ":") !== 0;
    }), "enterprise: " + ids(enterprise).join(", "));
  });
  log.debug("Leaving theCategory().");
}

// 3 and 4: a newcomer, a namesake left alone, any-existing refused.
async function theNewcomer() {
  log.debug("Entering theNewcomer().");
  const who = names.usernameFor("consumer");
  const mail = who + "@" + IDP_MAIL;
  await createPerson(IDP, who, mail);
  // The namesake: the same name and the same address, here.
  await createPerson(SP, who, mail);
  await check("3a. a newcomer through the consumer relationship gets an " +
              "entry of their own", async function () {
    const r = await federatedSignIn(who);
    assert.ok(r.status === 200, "the sign-in answered " + r.status + " " +
              squash(r.body));
    const subject = await subjectAtPartner(who);
    const uuid = subject.replace(/^urn:uuid:/i, "").toLowerCase();
    const created = await entryOf(REL + "~sub-" + uuid);
    assert.ok(created, "no entry " + REL + "~sub-" + uuid);
  });
  await check("3b. the local person with the same name and address is " +
              "left exactly as they were", async function () {
    const local = await entryOf(who);
    assert.ok(local, "the local person is gone");
    const linksOf = [].concat(local.federationLink ||
                              local.federationlink || []);
    assert.strictEqual(linksOf.length, 0,
                       "the local person was linked: " + linksOf.join(", "));
  });
  await check("4. any-existing is refused on a consumer relationship",
  async function () {
    const r = await api(SP, "POST", "/federation/set",
                        { id: REL, field: "fedSubjectPolicy",
                          value: "any-existing" });
    assert.ok(r.status >= 400 || (r.body && r.body.ok === false),
              "set anyway: " + r.status + " " + r.text.slice(0, 200));
  });
  log.debug("Leaving theNewcomer().");
}

// 5: the switch off again.
async function switchedOff() {
  log.debug("Entering switchedOff().");
  await check("5. consumer providers off: the login endpoint refuses, and " +
              "the relationship's readiness names the setting",
  async function () {
    await setSetting(SP, "federation.consumerProviders", "false");
    const r = await hop(null, realmBase(SP) + "/federation/login/" + REL);
    assert.strictEqual(r.status, 403);
    const view = await api(SP, "GET", "/federation?relationship=" + REL);
    const missing = [].concat((view.body || {}).missing || []);
    assert.ok(missing.some(function (one) {
      return /federation\.consumerProviders/.test(String(one));
    }), "readiness: " + JSON.stringify(missing));
  });
  log.debug("Leaving switchedOff().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Running the consumer provider checks against " + base);
  const world = await setUp();
  await theCategory(world);
  await theNewcomer();
  await switchedOff();
  log.info("The realms " + IDP + " and " + SP + " are left standing " +
           "(tests/CLAUDE.md, *No job removes a realm*).");
  if (failures.length) {
    log.error(checks + " check(s) passed, " + failures.length + " FAILED:");
    failures.forEach(function (f) {
      log.error("  ✗ " + f);
    });
    log.debug("Leaving test(). Failed.");
    return 1;
  }
  // A FLOOR ON THE COUNT: a section that stops being called takes its
  // assertions with it and the run would still say "passed".
  assert.ok(checks >= 7, "only " + checks + " checks ran; a section " +
                         "stopped being called");
  log.info(checks + " checks passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
  return 0;
}

const program = new Command();
program
  .name("sts_federation_consumer")
  .description("Consumer and social providers (#565), over HTTP between two " +
      "realms of one service: the realm switch at creation and at the login " +
      "endpoint, a relationship made from the generic-oidc profile, the " +
      "category in the list, a newcomer's own entry and a namesake left " +
      "alone, and any-existing refused.")
  .addOption(new Option("-u, --url <url>", "base url of the STS under test")
      .default(base))
  .parse(process.argv);
base = String(program.opts().url || base).replace(/\/+$/, "");

test().then(function (code) {
  process.exit(code);
}).catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
