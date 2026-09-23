// ===========================================================================
// WHICH PEOPLE A FEDERATION PARTNER MAY ASSERT, OVER THE NETWORK (#109).
//
// Until #109 a service-provider-side relationship signed in whichever local
// person had the NAME its partner asserted, and wrote the partner's
// attributes onto them before anything could refuse. A person now carries a
// `federationLink` — the relationship, the partner's issuer and its stable
// subject for them (OpenID Connect Core section 5.7's `iss` + `sub`) — and the
// relationship's `fedSubjectPolicy` says what happens to a subject nobody
// linked. `tests/federation_subject_policy.js` holds every policy in process;
// this job drives the same service a deployment runs, over HTTP, in whichever
// mode it is in, and asserts what a browser and an operator can see:
//
//   1. LINK AT FIRST SIGN-IN (the default): an unlinked subject naming an
//      existing person lands on the SERVICE PROVIDER's sign-in screen with the
//      name fixed; nothing is written on the entry; a wrong password links
//      nothing; Cancel is refused 403 and links nothing; the right password
//      links the partner's `iss` + `sub` and signs the person in, and only
//      then are the partner's attributes written.
//   2. PRE-LINKED: an unlinked person is refused 403, recorded as
//      STS-FED-0091 on the realm's audit (read back through /admin-api);
//      `POST /admin-api/users/federation-link` links them and they sign in.
//   3. A CONSOLE ADMINISTRATOR is refused (STS-FED-0093) with a valid link,
//      and signed in once the relationship sets fedMayAssertAdministrators.
//   4. ANY-EXISTING: development matches the name; product refuses to set it.
//   5. JIT-NAMESPACED: a new entry `<relationship>~<name>` in development and
//      a refusal in product, the existing person untouched either way.
//   6. A DOMAIN RULE refuses a linked person (STS-FED-0092).
//   7. `POST /admin-api/users/federation-unlink` ends the partner's sessions.
//   8. SCIM's iya-sts extension sets a link, and a pre-linked sign-in follows.
//   9. The relationship's view lists who is linked through it.
//
// THE PARTNER IS ANOTHER REALM OF THE SAME SERVICE, on the front-channel
// shape `sts_federation_realms.js` argues for (an ID Token by form_post
// against pasted keys), because a service cannot always dial itself. Every
// realm, person, application and relationship is CREATED by this run and
// left standing; nothing service-wide is changed.
// ===========================================================================

"use strict";

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
var log = bunyan.createLogger({ name: "sts_federation_subject_policy",
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
const IDP = "pi-" + STAMP;
const SP = "ps-" + STAMP;
const REL = "oidc-link";
const CLIENT = "ps-link-" + STAMP;
const PASSWORD = "Subject-Policy-Passw0rd!-" + String(Date.now()).slice(-6);
const IDP_MAIL = IDP + ".example.net";
const SP_MAIL = "sp-local.subject.test";
const EXT = "urn:ietf:params:scim:schemas:extension:iya-sts:2.0:User";

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
  const trail = { linkScreens: 0, linkScreen: "", idpScreens: 0 };
  let r = await hop(cookies, realmBase(SP) + "/federation/login/" + REL);
  for (let step = 0; step < 24; step += 1) {
    if (r.status >= 300 && r.status < 400 && r.location) {
      r = await hop(cookies, new URL(r.location, r.url).toString());
      continue;
    }
    if (r.status !== 200) {
      break;
    }
    const forms = formsIn(r.body);
    const signIn = forms.find(function (f) {
      return "authn_id" in f.fields;
    });
    const onward = forms.find(function (f) {
      return f.method === "post" && ("id_token" in f.fields);
    });
    const consent = forms.find(function (f) {
      return /consent/.test(f.action) || "consent_id" in f.fields;
    });
    const at = new URL(r.url).pathname;
    if (signIn && at.indexOf("/realm/" + SP + "/") === 0) {
      trail.linkScreens += 1;
      trail.linkScreen = r.body;
      if (o.link === "stop" || trail.linkScreens > (o.attempts || 1)) {
        break;
      }
      const to = new URL(signIn.action || r.url, r.url).toString();
      r = await postForm(cookies, to, Object.assign({}, signIn.fields, {
        username: "not-the-person", password: o.password || PASSWORD,
        action: o.link === "cancel" ? "cancel" : "login" }));
      continue;
    }
    if (signIn) {
      trail.idpScreens += 1;
      const to = new URL(signIn.action || r.url, r.url).toString();
      r = await postForm(cookies, to, Object.assign({}, signIn.fields, {
        username: idpUser, password: PASSWORD, action: "login" }));
      continue;
    }
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

// What the service provider realm holds about a person.
async function spView(username) {
  log.debug("Entering spView(). " + username);
  const r = await api(SP, "GET", "/users?user=" +
                                  encodeURIComponent(username));
  must(r.status === 200 && r.body,
       "GET /realm/" + SP + "/admin-api/users answered " + r.status + " " +
       r.text.slice(0, 200));
  const ldap = r.body.ldap || {};
  const entry = ldap.found && ldap.entry ? ldap.entry.attributes || {} : null;
  const sessions = Array.isArray(r.body.sessions) ? r.body.sessions : [];
  log.debug("Leaving spView().");
  return { entry: entry, links: r.body.federationLinks || [],
           federated: sessions.filter(function (s) {
             return /^federated\b/.test(String(s.amr || "")) && !s.expired;
           }).length };
}

async function subjectAtPartner(username) {
  log.debug("Entering subjectAtPartner(). " + username);
  const r = await api(IDP, "GET", "/users?user=" +
                                   encodeURIComponent(username));
  must(r.status === 200 && r.body && r.body.subject,
       "the partner realm holds no subject for " + username + ": " +
       r.text.slice(0, 200));
  log.debug("Leaving subjectAtPartner().");
  return r.body.subject;
}

async function codesInAudit(code) {
  log.debug("Entering codesInAudit(). " + code);
  const r = await api(SP, "GET", "/audit?code=" + encodeURIComponent(code));
  // `matched`, not the page: a realm's audit can hold more rows of one code
  // than a page shows.
  const matched = Number((r.body && r.body.matched) || 0);
  log.debug("Leaving codesInAudit(). " + matched);
  return matched;
}

async function setRel(field, value) {
  log.debug("Entering setRel(). " + field);
  const r = await api(SP, "POST", "/federation/set",
                      { id: REL, field: field, value: value });
  log.debug("Leaving setRel(). " + r.status);
  return r;
}

async function createPerson(realm, username, mailDomain) {
  log.debug("Entering createPerson(). " + realm + " " + username);
  const r = await api(realm, "POST", "/users/create", {
    username: username, invent: false,
    attributes: { cn: "Subject " + username, sn: username,
                  mail: username + "@" + mailDomain },
    credential: "password", password: PASSWORD });
  must(r.status === 200 && r.body && r.body.ok,
       "creating " + username + " in " + realm + " answered " + r.status +
       " " + r.text.slice(0, 300));
  log.debug("Leaving createPerson().");
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
  const made = await api(SP, "POST", "/federation/create",
    { id: REL, role: "service-provider", protocol: "oidc",
      peer: discovery.issuer });
  must(made.status === 200 && made.body && made.body.ok,
       "creating the relationship answered " + made.status + " " +
       made.text.slice(0, 300));
  const settings = {
    fedSsoUrl: discovery.authorization_endpoint,
    fedScope: "openid profile email",
    fedUsernameSource: "preferred_username",
    fedClientId: CLIENT, fedResponseType: "id_token",
    fedJwks: JSON.stringify(jwks) };
  for (const field of Object.keys(settings)) {
    const set = await setRel(field, settings[field]);
    must(set.status === 200 && set.body && set.body.ok,
         "setting " + field + " answered " + set.status + " " +
         set.text.slice(0, 200));
  }
  const enabled = await api(SP, "POST", "/federation/enable", { id: REL });
  must(enabled.status === 200 && enabled.body.ok, "enabling answered " +
                                                   enabled.status);
  const view = await api(SP, "GET", "/federation?relationship=" + REL);
  const acs = ((view.body || {}).endpoints || {}).assertionConsumerService;
  const app = await api(IDP, "POST", "/applications/create", {
    identifier: CLIENT, name: "subject policy " + CLIENT,
    protocols: ["oidc"],
    fields: { oauthClientId: [CLIENT], oauthRedirectUri: [acs],
              oauthTokenEndpointAuthMethod: "none",
              oauthGrantType: ["implicit"],
              oauthResponseType: ["id_token"] } });
  must(app.status === 200 && app.body && app.body.ok,
       "creating the partner's application answered " + app.status + " " +
       app.text.slice(0, 300));
  log.debug("Leaving setUp().");
  return { issuer: discovery.issuer };
}

// ---------------------------------------------------------------------------
// 1. LINK AT FIRST SIGN-IN
// ---------------------------------------------------------------------------
async function linkAtFirstSignIn(world) {
  log.debug("Entering linkAtFirstSignIn().");
  log.info("=== 1. link at first sign-in (the default) ===");
  const who = names.usernameFor("sp-link");
  await createPerson(IDP, who, IDP_MAIL);
  await createPerson(SP, who, SP_MAIL);

  let got = await federatedSignIn(who, { link: "stop" });
  let view = await spView(who);
  await check("an unlinked subject naming an existing person lands on the " +
              "SERVICE PROVIDER's sign-in screen, the name fixed",
              async function () {
    assert.strictEqual(got.trail.linkScreens, 1,
      "trail: " + JSON.stringify(got.trail) + " " + squash(got.r.body));
    assert.ok(/readonly/.test(got.trail.linkScreen) &&
              got.trail.linkScreen.indexOf("value=\"" + who + "\"") >= 0,
              squash(got.trail.linkScreen));
    assert.ok(!/id="webauthn_only"/.test(got.trail.linkScreen),
              "a passwordless box is offered on the linking screen");
  });
  await check("nothing is written onto the entry before the link",
              async function () {
    assert.deepStrictEqual(view.entry.mail, [who + "@" + SP_MAIL]);
    assert.strictEqual(view.links.length, 0, JSON.stringify(view.links));
    assert.ok(!(view.entry.federationRelationship || []).length,
              JSON.stringify(view.entry.federationRelationship));
  });

  // Development checks no password but refuses the reserved `invalid`
  // everywhere; product verifies, so a plausible wrong one is refused too.
  got = await federatedSignIn(who, { link: "password",
                                     password: isProduct
                                       ? "Wrong-Passw0rd!-" + STAMP
                                       : "invalid",
                                     attempts: 1 });
  view = await spView(who);
  await check("a WRONG password at the linking screen links nothing",
              async function () {
    assert.strictEqual(got.trail.linkScreens, 2, JSON.stringify(got.trail));
    assert.ok(/Authentication failed/.test(got.r.body), squash(got.r.body));
    assert.strictEqual(view.links.length, 0);
    assert.deepStrictEqual(view.entry.mail, [who + "@" + SP_MAIL]);
  });

  // THE LINKING SCREEN HANDED TO ANOTHER BROWSER: the step is bound to the
  // browser the partner's response arrived in (account-linking CSRF).
  got = await federatedSignIn(who, { link: "stop" });
  const screen = formsIn(got.trail.linkScreen).find(function (f) {
    return "authn_id" in f.fields;
  });
  const elsewhere = jar();
  let other = await postForm(elsewhere,
    new URL(screen.action, got.r.url).toString(),
    Object.assign({}, screen.fields, { username: who, password: PASSWORD,
                                       action: "login" }));
  for (let i = 0; i < 5 && other.status >= 300 && other.status < 400;
       i += 1) {
    other = await hop(elsewhere, new URL(other.location, other.url)
      .toString());
  }
  view = await spView(who);
  await check("the linking screen completed in ANOTHER browser is refused " +
              "403 (STS-FED-0111) and links nothing", async function () {
    assert.strictEqual(other.status, 403, squash(other.body));
    assert.ok(/different browser/.test(other.body), squash(other.body));
    assert.strictEqual(view.links.length, 0);
  });

  got = await federatedSignIn(who, { link: "cancel" });
  view = await spView(who);
  await check("Cancel at the linking screen is refused 403 and links " +
              "nothing", async function () {
    assert.strictEqual(got.r.status, 403, squash(got.r.body));
    assert.ok(/was not linked/.test(got.r.body), squash(got.r.body));
    assert.strictEqual(view.links.length, 0);
    assert.ok(await codesInAudit("STS-FED-0099") >= 1,
              "no STS-FED-0099 row on the service provider's audit");
  });

  got = await federatedSignIn(who, { link: "password" });
  view = await spView(who);
  const subject = await subjectAtPartner(who);
  await check("the right password links the partner's iss + sub and signs " +
              "the person in", async function () {
    assert.strictEqual(got.r.status, 200, squash(got.r.body));
    assert.ok(/Signed in through/.test(got.r.body), squash(got.r.body));
    assert.strictEqual(view.links.length, 1, JSON.stringify(view.links));
    assert.strictEqual(view.links[0].relationship, REL);
    assert.strictEqual(view.links[0].issuer, world.issuer);
    assert.strictEqual(view.links[0].subject, subject);
  });
  await check("and only then are the partner's attributes written",
              async function () {
    assert.deepStrictEqual(view.entry.mail, [who + "@" + IDP_MAIL]);
    assert.ok((view.entry.federationRelationship || []).indexOf(REL) >= 0);
  });
  got = await federatedSignIn(who, { link: "stop" });
  await check("the next sign-in finds the link and asks for nothing",
              async function () {
    assert.strictEqual(got.trail.linkScreens, 0);
    assert.strictEqual(got.r.status, 200, squash(got.r.body));
  });
  log.debug("Leaving linkAtFirstSignIn().");
  return { linked: who };
}

// ---------------------------------------------------------------------------
// 2. PRE-LINKED, AND LINKING THROUGH /admin-api
// ---------------------------------------------------------------------------
async function preLinked() {
  log.debug("Entering preLinked().");
  log.info("=== 2. pre-linked, and a link made through /admin-api ===");
  const who = names.usernameFor("sp-pre");
  await createPerson(IDP, who, IDP_MAIL);
  await createPerson(SP, who, SP_MAIL);
  const set = await setRel("fedSubjectPolicy", "pre-linked");
  must(set.status === 200 && set.body.ok, "setting pre-linked answered " +
                                          set.status);
  const before = await codesInAudit("STS-FED-0091");
  let got = await federatedSignIn(who, {});
  let view = await spView(who);
  await check("an unlinked person is refused 403 (STS-FED-0091) and " +
              "nothing is written", async function () {
    assert.strictEqual(got.r.status, 403, squash(got.r.body));
    assert.strictEqual(got.trail.linkScreens, 0);
    assert.ok(await codesInAudit("STS-FED-0091") > before,
              "no new STS-FED-0091 row");
    assert.deepStrictEqual(view.entry.mail, [who + "@" + SP_MAIL]);
  });
  const subject = await subjectAtPartner(who);
  const linked = await api(SP, "POST", "/users/federation-link",
    { user: who, relationship: REL, subject: subject });
  got = await federatedSignIn(who, {});
  view = await spView(who);
  await check("POST /admin-api/users/federation-link links them, and they " +
              "sign in", async function () {
    assert.strictEqual(linked.status, 200, linked.text.slice(0, 300));
    assert.ok(linked.body.ok && linked.body.changed, linked.text);
    assert.strictEqual(got.r.status, 200, squash(got.r.body));
    assert.strictEqual(view.links.length, 1);
  });
  const again = await api(SP, "POST", "/users/federation-link",
    { user: names.usernameFor("sp-nobody"), relationship: REL,
      subject: subject });
  await check("the same link on somebody else is refused", async function () {
    assert.strictEqual(again.status, 400, again.text.slice(0, 300));
  });
  log.debug("Leaving preLinked().");
  return { who: who };
}

// ---------------------------------------------------------------------------
// 3. A CONSOLE ADMINISTRATOR
// ---------------------------------------------------------------------------
async function administrators() {
  log.debug("Entering administrators().");
  log.info("=== 3. a partner may not sign in a console administrator ===");
  const who = names.usernameFor("sp-admin");
  await createPerson(IDP, who, IDP_MAIL);
  await createPerson(SP, who, SP_MAIL);
  const granted = await api(SP, "POST", "/rbac/grant",
                            { username: who, role: "read" });
  must(granted.status === 200, "granting the role answered " +
                               granted.status + " " + granted.text);
  const linked = await api(SP, "POST", "/users/federation-link",
    { user: who, relationship: REL, subject: await subjectAtPartner(who) });
  must(linked.status === 200, "linking answered " + linked.status);
  const before = await codesInAudit("STS-FED-0093");
  let got = await federatedSignIn(who, {});
  let view = await spView(who);
  await check("a LINKED console administrator is refused 403 " +
              "(STS-FED-0093), and their entry is not written",
              async function () {
    assert.strictEqual(got.r.status, 403, squash(got.r.body));
    assert.ok(/administrator/.test(got.r.body), squash(got.r.body));
    assert.ok(await codesInAudit("STS-FED-0093") > before);
    assert.deepStrictEqual(view.entry.mail, [who + "@" + SP_MAIL]);
  });
  await setRel("fedMayAssertAdministrators", "TRUE");
  got = await federatedSignIn(who, {});
  view = await spView(who);
  await check("with fedMayAssertAdministrators on, the same partner signs " +
              "them in", async function () {
    assert.strictEqual(got.r.status, 200, squash(got.r.body));
  });
  await setRel("fedMayAssertAdministrators", "FALSE");
  log.debug("Leaving administrators().");
}

// ---------------------------------------------------------------------------
// 4 AND 5. ANY-EXISTING AND JIT-NAMESPACED, AS THE MODE SAYS
// ---------------------------------------------------------------------------
async function theOtherPolicies() {
  log.debug("Entering theOtherPolicies().");
  log.info("=== 4, 5. any-existing and jit-namespaced ===");
  const who = names.usernameFor("sp-name");
  await createPerson(IDP, who, IDP_MAIL);
  await createPerson(SP, who, SP_MAIL);
  const any = await setRel("fedSubjectPolicy", "any-existing");
  if (isProduct) {
    await check("product refuses to set any-existing", async function () {
      assert.strictEqual(any.status, 400, any.text.slice(0, 300));
    });
  } else {
    const got = await federatedSignIn(who, {});
    const view = await spView(who);
    await check("development: any-existing matches the name and signs the " +
                "person in directly", async function () {
      assert.strictEqual(any.status, 200, any.text.slice(0, 300));
      assert.strictEqual(got.r.status, 200, squash(got.r.body));
      assert.strictEqual(got.trail.linkScreens, 0);
      assert.deepStrictEqual(view.entry.mail, [who + "@" + IDP_MAIL]);
    });
  }
  const jit = names.usernameFor("sp-jit");
  await createPerson(IDP, jit, IDP_MAIL);
  await createPerson(SP, jit, SP_MAIL);
  await setRel("fedSubjectPolicy", "jit-namespaced");
  const got = await federatedSignIn(jit, {});
  const own = await spView(jit);
  const spaced = await spView(REL + "~" + jit);
  await check("jit-namespaced never signs in the existing person of that " +
              "name" + (isProduct ? ", and product creates nobody"
                                  : ", and creates " + REL + "~" + jit),
              async function () {
    assert.deepStrictEqual(own.entry.mail, [jit + "@" + SP_MAIL]);
    assert.strictEqual(own.links.length, 0);
    if (isProduct) {
      assert.strictEqual(got.r.status, 403, squash(got.r.body));
      assert.strictEqual(spaced.entry, null);
    } else {
      assert.strictEqual(got.r.status, 200, squash(got.r.body));
      assert.ok(spaced.entry, "no namespaced entry");
      assert.strictEqual(spaced.links.length, 1);
    }
  });
  await setRel("fedSubjectPolicy", "");
  log.debug("Leaving theOtherPolicies().");
}

// ---------------------------------------------------------------------------
// 6. A RULE ON TOP. 7. UNLINKING.
// ---------------------------------------------------------------------------
async function ruleAndUnlink(linked) {
  log.debug("Entering ruleAndUnlink().");
  log.info("=== 6, 7. a domain rule, and unlinking ===");
  const ruled = await api(SP, "POST", "/federation/add-value",
                          { id: REL, field: "fedSubjectDomain",
                            value: "nowhere.example" });
  must(ruled.status === 200 && ruled.body && ruled.body.ok,
       "adding the domain rule answered " + ruled.status + " " +
       ruled.text.slice(0, 200));
  const before = await codesInAudit("STS-FED-0092");
  let got = await federatedSignIn(linked, {});
  await check("a domain rule refuses a LINKED person the partner sends " +
              "from elsewhere (STS-FED-0092)", async function () {
    assert.strictEqual(got.r.status, 403, squash(got.r.body));
    assert.ok(await codesInAudit("STS-FED-0092") > before);
  });
  await api(SP, "POST", "/federation/remove-value",
            { id: REL, field: "fedSubjectDomain", value: "nowhere.example" });
  got = await federatedSignIn(linked, {});
  let view = await spView(linked);
  must(got.r.status === 200 && view.federated >= 1,
       "the linked person should hold a federated session: " +
       got.r.status + " " + view.federated);
  const unlinked = await api(SP, "POST", "/users/federation-unlink",
                             { user: linked, link: view.links[0].link });
  let after = view.federated;
  for (let i = 0; i < 20 && after > 0; i += 1) {
    await sleep(500);
    after = (await spView(linked)).federated;
  }
  view = await spView(linked);
  await check("POST /admin-api/users/federation-unlink removes the link and " +
              "ends the sessions that partner made", async function () {
    assert.strictEqual(unlinked.status, 200, unlinked.text.slice(0, 300));
    assert.strictEqual(view.links.length, 0);
    assert.strictEqual(after, 0, "federated sessions left: " + after);
  });
  got = await federatedSignIn(linked, { link: "stop" });
  await check("and the next sign-in is unlinked again", async function () {
    assert.strictEqual(got.trail.linkScreens, 1, JSON.stringify(got.trail));
  });
  log.debug("Leaving ruleAndUnlink().");
}

// ---------------------------------------------------------------------------
// 8. SCIM. 9. THE RELATIONSHIP'S VIEW.
// ---------------------------------------------------------------------------
async function scimAndViews(pre) {
  log.debug("Entering scimAndViews().");
  log.info("=== 8, 9. SCIM's extension, and the relationship's view ===");
  const caller = names.usernameFor("sp-scim");
  await createPerson(SP, caller, SP_MAIL);
  const who = names.usernameFor("sp-scimmed");
  await createPerson(IDP, who, IDP_MAIL);
  const subject = await subjectAtPartner(who);
  const body = { schemas: ["urn:ietf:params:scim:schemas:core:2.0:User",
                           EXT],
                 userName: who };
  body[EXT] = { federationLinks: [{ relationship: REL, subject: subject }] };
  const r = await fetch(realmBase(SP) + "/scim/v2/Users", {
    method: "POST",
    headers: { "content-type": "application/scim+json",
               authorization: "Basic " + Buffer.from(caller + ":" + PASSWORD)
                 .toString("base64") },
    body: JSON.stringify(body) });
  const text = await r.text();
  let created = {};
  try {
    created = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in scimAndViews(): " + ((e && e.message) || e));
    // Not JSON; the assertion below quotes the text.
    created = {};
  }
  await check("a person created over SCIM with the iya-sts extension " +
              "carries the link, and the resource returns it",
              async function () {
    assert.strictEqual(r.status, 201, text.slice(0, 300));
    const links = (created[EXT] || {}).federationLinks || [];
    assert.strictEqual(links.length, 1, text.slice(0, 400));
    assert.strictEqual(links[0].subject, subject);
  });
  await setRel("fedSubjectPolicy", "pre-linked");
  const got = await federatedSignIn(who, {});
  await check("and a pre-linked relationship signs them in",
              async function () {
    assert.strictEqual(got.r.status, 200, squash(got.r.body));
  });
  await setRel("fedSubjectPolicy", "");
  const view = await api(SP, "GET", "/federation?relationship=" + REL +
                                    "&linksPage=1");
  await check("the relationship's view lists who is linked through it, " +
              "paged", async function () {
    assert.ok(view.body && Array.isArray(view.body.links), view.text);
    assert.ok(view.body.linksPaging, "no linksPaging");
    const users = view.body.links.map(function (one) {
      return one.username;
    });
    assert.ok(users.indexOf(pre) >= 0 && users.indexOf(who) >= 0,
              JSON.stringify(users));
  });
  log.debug("Leaving scimAndViews().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Running the federation subject-policy checks against " + base);
  const world = await setUp();
  const first = await linkAtFirstSignIn(world);
  const pre = await preLinked();
  await administrators();
  await theOtherPolicies();
  await ruleAndUnlink(first.linked);
  await scimAndViews(pre.who);
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
  assert.ok(checks >= 20, "only " + checks + " checks ran; a section " +
                          "stopped being called");
  log.info(checks + " checks passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
  return 0;
}

const program = new Command();
program
  .name("sts_federation_subject_policy")
  .description("Which people a federation partner may assert (#109), over " +
      "HTTP between two realms of one service: link at first sign-in with " +
      "a wrong password, a cancel and the right password; pre-linked and a " +
      "link through /admin-api; the administrator refusal and its override; " +
      "any-existing and jit-namespaced as the mode says; a domain rule; an " +
      "unlink ending the partner's sessions; SCIM's extension; the " +
      "relationship's list of linked people.")
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
