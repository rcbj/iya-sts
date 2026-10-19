// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// ===========================================================================
// ONE IDENTITY-PROVIDER-INITIATED SIGN-IN LINK PER APPLICATION, OVER THE
// WIRE, IN EVERY SUITE MODE (#715; the door is #426, #713).
//
// `GET /launch/{app}` chooses a protocol, checks the application's switch
// and hands the browser to that protocol's own endpoint — or, for OpenID
// Connect, signs the person in, records the launch on the session and sends
// them to the client's initiate_login_uri. `launch/CLAUDE.md` argues it.
// `tests/launch.js` holds the same door IN PROCESS, in development mode
// only; this job is its port to HTTP, so that it runs in `memory`
// (development) and in `single-node` and `cluster` (PRODUCT mode on
// postgres, `cluster` being several nodes behind one address). In
// `cluster` the launch record written on one node is read at
// /oauth2/authorize on whichever node answers, through the shared session
// store, and each switch set through `/admin-api` is read by whichever node
// answers the link — which is the whole reason this job exists.
//
// EVERYTHING IT NEEDS IT MAKES, in a throwaway realm of its own named for
// the run (*No job removes a realm*: it is left standing). The realm takes
// the stack's own mode, so the memory run is development and the other two
// are product. What product changes, and how this job meets it:
//
//   * PASSWORDS ARE CHECKED: the person is created through `/admin-api`
//     with a password this process made, carrying the attributes the
//     attribute policy asks (givenName, sn, mail — #396), and signs in
//     with it at the static sign-in screen (`authn_signin.js`).
//   * ADDRESSES MUST BE REGISTERED: every assertion consumer service, reply
//     URL, redirect URI and initiate_login_uri is written on the entry by
//     `/admin-api/applications/create`, which registers it; nothing is left
//     to be observed from a request.
//   * PKCE, A FRESH NONCE PER REQUEST and exact redirect URIs, which RFC
//     9700 mode (implied by product) holds a public client to.
//   * THE CONSENT SCREEN is on by default: each client is given a global
//     consent to `openid` through `/admin-api/consent` — a per-client
//     override, so no realm setting is changed for it — and a screen that
//     appears anyway is answered Allow and said so in the log.
//
// THE SECTIONS, labelled as `tests/launch.js` labels them:
//
//   a. an unknown application is 404 (STS-LAUNCH-0001); a protocol that is
//      not one of the four is 400 (0002), one the application is not
//      declared for 404 (0003);
//   b. the switch is off by default (403, 0005) and turned on through
//      `/admin-api/applications/set`; SAML 2.0 goes to
//      /saml2/unsolicited/{sp} with target as RelayState, SAML 1.1 to
//      /saml11/sso/{rp} with providerId and TARGET, WS-Federation to
//      /wsfed/initiate/{rp} with wctx — and each is followed ONE step,
//      where the endpoint sends a browser with no session to the sign-in
//      screen rather than refusing, while the endpoint of a switched-off
//      application refuses it (403) by itself;
//   c. nowhere registered to send it is 409 (0006);
//   d. two protocols on and no preference is 409 (0004); ?protocol= picks,
//      and appLaunchProtocol picks when the link does not;
//   e. OpenID Connect: no session goes to the sign-in screen and back to the
//      link; then 303 to initiate_login_uri with iss, login_hint, tenant and
//      target_link_uri. That the launch is ON THE SESSION (launch.js's e4)
//      cannot be read over HTTP: f1 is its effect;
//   s. with that session, each SAML and WS-Federation endpoint the door sent
//      the browser to answers the self-submitting form carrying the
//      response to the REGISTERED address;
//   f. /oauth2/authorize for a client whose own start is off is answered
//      right after a launch, refused unauthorized_client (STS-OAUTH-0959)
//      on the next request because the launch is spent, and refused after
//      `oauth2.launchWindowS` — set to its minimum, 10, through
//      `/admin-api/config/set` for this realm, waited out, and reset in a
//      `finally`; a client whose own start is on is not touched;
//   g. `/admin-api/applications?application=` carries `page.launchUrls`
//      (the URL, the switch, what is missing, the endpoint), and
//      `/account-api/applications`, asked as the static portal asks it
//      with its DPoP-bound token (`portal_signin.js`), offers `launches`
//      only where the switch is on.
//
// Every refusal's code is read back from the realm's `/admin-api/audit`,
// never from the response, which carries none (*Every failure has an error
// code, and no client ever sees one*). A refusal's row is held by the
// cluster barrier until it is committed, so the read through the load
// balancer finds it on whichever node answers.
//
// INVENTED FIXTURES: every identifier, address and the username below name
// nothing outside this run; the `.example` hosts are never dialled.
//
// `local: true`: the door, the switches, the management API's view and the
// portal's account API are all this repository's own.
// ===========================================================================

"use strict";

// The sign-in screen and the consent screen over `/authn-api` (#571, #576).
const authnSignin = require("./authn_signin");
// The static portal's sign-in and its `/account-api` calls (#568).
const portalSignin = require("./portal_signin");
const nodeCrypto = require("crypto");
const { Command, Option } = require("commander");
const names = require("./random_username.js");

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
var log = bunyan.createLogger({ name: "sts_idp_initiated_launch",
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
const REALM = "launch-" + STAMP;
// A password this process made: product checks it, and a fixed one would be
// a breached one sooner or later.
const PASSWORD = "Launch-" + nodeCrypto.randomBytes(9).toString("base64url") +
  "-9a!";
const USER = names.usernameFor("launch");

// The applications. URNs, as `tests/launch.js` uses: a URN carries no `/`,
// so its encoded path segment is the same on every hop through a proxy.
const SP2 = "urn:launch:" + STAMP + ":saml2";
const SP2_OFF = "urn:launch:" + STAMP + ":saml2-off";
const SP2_NOACS = "urn:launch:" + STAMP + ":saml2-no-acs";
const RP11 = "urn:launch:" + STAMP + ":saml11";
const RP_WS = "urn:launch:" + STAMP + ":wsfed";
const BOTH = "urn:launch:" + STAMP + ":both";
const PREFERS = "urn:launch:" + STAMP + ":prefers";
const RP_CLIENT = "launch-rp-" + STAMP;
const PLAIN_CLIENT = "launch-plain-" + STAMP;
const HOST = "https://rp-" + STAMP + ".launch.example";
const ACS = HOST + "/acs";
const ACS11 = HOST + "/saml11/acs";
const REPLY = HOST + "/wsfed";
const INITIATE = HOST + "/login";
const HOME = HOST + "/home";
const REDIRECT = HOST + "/cb";
const WINDOW_KEY = "oauth2.launchWindowS";

let checks = 0;
const failures = [];

// ---------------------------------------------------------------------------
// ONE CHECK. A failure is recorded and the run carries on; setup that later
// sections depend on uses `must()` instead, which throws.
// ---------------------------------------------------------------------------
async function check(what, fn) {
  log.debug("Entering check(). " + what);
  try {
    await fn();
    checks += 1;
    log.info("  [ok] " + what);
  } catch (e) {
    log.debug("Caught in check(): " + ((e && e.message) || e));
    failures.push(what + " — " + ((e && e.message) || e));
    log.error("  [FAILED] " + what + "  — " + ((e && e.message) || e));
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

function expect(condition, message) {
  log.debug("Entering expect().");
  if (!condition) {
    log.debug("Leaving expect(). Refused.");
    throw new Error(message);
  }
  log.debug("Leaving expect().");
}

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

function realmBase() {
  log.debug("Entering realmBase().");
  log.debug("Leaving realmBase().");
  return base + "/realm/" + REALM;
}

// The realm's path prefix, which every Location the service sends in the
// realm starts with (`realms.href()` in `common/app.js`).
function realmPath() {
  log.debug("Entering realmPath().");
  log.debug("Leaving realmPath().");
  return new URL(realmBase()).pathname.replace(/\/+$/, "");
}

// A Location's path and query, without the origin: behind the cluster's
// load balancer the origin a node builds from the request is not ours to
// predict, and what the door decides is the path.
function pathOf(location) {
  log.debug("Entering pathOf().");
  if (!location) {
    log.debug("Leaving pathOf(). None.");
    return "";
  }
  const u = new URL(String(location), realmBase() + "/");
  log.debug("Leaving pathOf().");
  return u.pathname + u.search;
}

// The door's link, as `LaunchLinks.launchUrl()` builds it, without the
// realm's prefix.
function link(identifier, query) {
  log.debug("Entering link().");
  const q = new URLSearchParams(query || {}).toString();
  log.debug("Leaving link().");
  return "/launch/" + encodeURIComponent(identifier) + (q ? "?" + q : "");
}

function htmlDecode(text) {
  log.debug("Entering htmlDecode().");
  log.debug("Leaving htmlDecode().");
  return String(text || "").replace(/&quot;/g, "\"").replace(/&#39;/g, "'")
    .replace(/&#x2F;/gi, "/").replace(/&apos;/g, "'").replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">").replace(/&amp;/g, "&");
}

// Every form on a page: its action and the names of its fields.
function formsIn(html) {
  log.debug("Entering formsIn().");
  const out = [];
  const re = /<form([^>]*)>([\s\S]*?)<\/form>/gi;
  let m = re.exec(String(html || ""));
  while (m) {
    const action = htmlDecode((/action="([^"]*)"/i.exec(m[1]) || [])[1] ||
                              "");
    const fields = [...m[2].matchAll(/name="([^"]+)"/gi)].map(
      function (one) {
        return htmlDecode(one[1]);
      });
    out.push({ action: action, fields: fields });
    m = re.exec(String(html || ""));
  }
  log.debug("Leaving formsIn(). " + out.length);
  return out;
}

function squash(text) {
  log.debug("Entering squash().");
  log.debug("Leaving squash().");
  return String(text || "").replace(/<style[\s\S]*?<\/style>/g, " ")
    .replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim().slice(0, 300);
}

// ===========================================================================
// THE MANAGEMENT API. The run's admin token is attached by the preload
// (`tools/attach-admin-token.js`) to every `/admin-api` call; the service
// administrator's token works under a realm's prefix.
// ===========================================================================

async function api(method, p, payload) {
  log.debug("Entering api(). " + method + " " + p);
  const options = { method: method, redirect: "manual", headers: {} };
  if (payload !== undefined) {
    options.headers["content-type"] = "application/json";
    options.body = JSON.stringify(payload);
  }
  const r = await fetch(realmBase() + "/admin-api" + p, options);
  const text = await r.text();
  let body = null;
  try {
    body = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in api(): " + ((e && e.message) || e));
    // Not JSON; `text` carries the answer into every message that quotes it.
    body = null;
  }
  log.debug("Leaving api(). status=" + r.status);
  return { status: r.status, body: body, text: text };
}

async function apiOk(p, payload, what) {
  log.debug("Entering apiOk(). " + p);
  const r = await api("POST", p, payload);
  must(r.status === 200 && r.body && r.body.ok !== false,
       what + " answered " + r.status + " " + r.text.slice(0, 300));
  log.debug("Leaving apiOk().");
  return r.body;
}

async function ensureRealm() {
  log.debug("Entering ensureRealm().");
  // NO `global.mode` OVERRIDE: the realm takes the stack's mode, so this
  // job is development in `memory` and product in the other two.
  const r = await fetch(base + "/admin-api/realms/create", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ id: REALM, domain: REALM + ".example.net",
                           name: "#715 identity-provider-initiated" }) });
  const text = await r.text();
  must(r.status === 200 || /already/i.test(text),
       "creating the realm " + REALM + " answered " + r.status + " " +
       text.slice(0, 300));
  log.debug("Leaving ensureRealm().");
}

async function createPerson(username) {
  log.debug("Entering createPerson(). " + username);
  await apiOk("/users/create", {
    username: username, invent: false,
    attributes: { cn: "Launch " + username, givenName: "Launch",
                  sn: username, displayName: "Launch " + username,
                  mail: username + "@" + REALM + ".example.net" },
    credential: "password", password: PASSWORD },
  "creating " + username);
  log.debug("Leaving createPerson().");
}

async function createApplication(identifier, protocols, fields, kind) {
  log.debug("Entering createApplication(). " + identifier);
  const body = { identifier: identifier, name: "launch " + identifier,
                 protocols: protocols, fields: fields };
  if (kind) {
    body.kind = kind;
  }
  await apiOk("/applications/create", body,
              "creating the application " + identifier);
  log.debug("Leaving createApplication().");
}

// How many of the realm's audit rows carry `code`.
async function codeCount(code) {
  log.debug("Entering codeCount(). " + code);
  const r = await api("GET", "/audit?per=500&code=" +
                      encodeURIComponent(code));
  const body = r.body && typeof r.body === "object" ? r.body : {};
  const rows = body.rows || body.events || [];
  log.debug("Leaving codeCount(). " + rows.length);
  return rows.length;
}

// Whether a new audit row with `code` arrived: the row is written as the
// response finishes, so the read after it may need a moment.
async function newRowWith(code, before) {
  log.debug("Entering newRowWith(). " + code);
  let after = await codeCount(code);
  for (let i = 0; i < 30 && after <= before; i += 1) {
    await sleep(200);
    after = await codeCount(code);
  }
  log.debug("Leaving newRowWith(). " + before + " -> " + after);
  return after > before;
}

// ===========================================================================
// THE BROWSER: a cookie jar (a plain object, which `authn_signin.js`'s
// `signInWithJar()` and `consentWithJar()` write back into) and redirects
// left to the caller, so every 303 is observed rather than followed.
// ===========================================================================

function browser() {
  log.debug("Entering browser().");
  const jar = {};
  const self = {
    jar: jar,
    cookie: function cookieOf() {
      log.debug("Entering cookieOf().");
      log.debug("Leaving cookieOf().");
      return Object.keys(jar).map(function (k) {
        return k + "=" + jar[k];
      }).join("; ");
    },
    go: async function go(method, url) {
      log.debug("Entering go(). " + method + " " + url);
      const headers = {};
      const cookie = self.cookie();
      if (cookie) {
        headers.cookie = cookie;
      }
      const absolute = /^https?:\/\//i.test(url) ? url : base + url;
      const r = await fetch(absolute, { method: method, redirect: "manual",
                                        headers: headers });
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
               text: text, url: absolute };
    }
  };
  log.debug("Leaving browser().");
  return self;
}

// The door, in this realm.
function launch(b, identifier, query) {
  log.debug("Entering launch(). " + identifier);
  log.debug("Leaving launch().");
  return b.go("GET", realmBase() + link(identifier, query));
}

function isRedirect(r) {
  log.debug("Entering isRedirect().");
  log.debug("Leaving isRedirect().");
  return r.status === 302 || r.status === 303;
}

function sentToSignIn(r) {
  log.debug("Entering sentToSignIn().");
  log.debug("Leaving sentToSignIn().");
  return isRedirect(r) && /\/authn\/login\?authn=/.test(r.location);
}

function shown(r) {
  log.debug("Entering shown().");
  log.debug("Leaving shown().");
  return r.status + " " + (r.location || squash(r.text));
}

// ===========================================================================
// THE WORLD
// ===========================================================================

async function makeWorld() {
  log.debug("Entering makeWorld().");
  log.info("=== 0. the realm " + REALM + ", " + USER + " and nine " +
           "applications ===");
  await ensureRealm();
  await createPerson(USER);
  // SP2 is created with NO switch: b1 asks the door before it is turned on
  // through `/admin-api/applications/set`, so the off-by-default answer and
  // the switch being read on whichever node answers are one application.
  await createApplication(SP2, ["saml2"], {
    samlEntityId: [SP2], samlAssertionConsumerService: [ACS] });
  await createApplication(SP2_OFF, ["saml2"], {
    samlEntityId: [SP2_OFF], samlAssertionConsumerService: [ACS] });
  await createApplication(SP2_NOACS, ["saml2"], {
    samlEntityId: [SP2_NOACS], saml2IdpInitiatedSso: "TRUE" });
  await createApplication(RP11, ["saml11"], {
    samlEntityId: [RP11], samlAssertionConsumerService: [ACS11],
    saml11IdpInitiatedSso: "TRUE" });
  await createApplication(RP_WS, ["wsfed"], {
    wsfedRealm: [RP_WS], wsfedReplyUrl: [REPLY],
    wsfedIdpInitiatedSso: "TRUE" });
  await createApplication(BOTH, ["saml2", "wsfed"], {
    samlEntityId: [BOTH], samlAssertionConsumerService: [ACS],
    wsfedRealm: [BOTH], wsfedReplyUrl: [REPLY],
    saml2IdpInitiatedSso: "TRUE", wsfedIdpInitiatedSso: "TRUE" });
  await createApplication(PREFERS, ["saml2", "wsfed"], {
    samlEntityId: [PREFERS], samlAssertionConsumerService: [ACS],
    wsfedRealm: [PREFERS], wsfedReplyUrl: [REPLY],
    saml2IdpInitiatedSso: "TRUE", wsfedIdpInitiatedSso: "TRUE",
    appLaunchProtocol: "wsfed" });
  // The client whose own start is OFF: answered at /oauth2/authorize only
  // after a launch of it (`oauthSpInitiatedSso` FALSE). A public client
  // with PKCE, as RFC 9700 mode allows.
  await createApplication(RP_CLIENT, ["oauth2", "oidc"], {
    oauthClientId: [RP_CLIENT], oauthRedirectUri: [REDIRECT],
    oauthGrantType: ["authorization_code"], oauthResponseType: ["code"],
    oauthAllowedScope: ["openid"], oauthTokenEndpointAuthMethod: "none",
    appHomePageUrl: HOME, oauthInitiateLoginUri: INITIATE,
    oauthThirdPartyInitiatedLogin: "TRUE", oauthSpInitiatedSso: "FALSE" },
  "oauth2-client");
  await createApplication(PLAIN_CLIENT, ["oauth2", "oidc"], {
    oauthClientId: [PLAIN_CLIENT], oauthRedirectUri: [REDIRECT],
    oauthGrantType: ["authorization_code"], oauthResponseType: ["code"],
    oauthAllowedScope: ["openid"], oauthTokenEndpointAuthMethod: "none" },
  "oauth2-client");
  // THE CONSENT SCREEN, ON BY DEFAULT: a global consent per client rather
  // than `oauth2.consentRequired` off, so no realm setting is changed.
  for (const client of [RP_CLIENT, PLAIN_CLIENT]) {
    await apiOk("/consent/grant-global-consent",
                { client: client, scope: "openid" },
                "consenting openid for everybody on " + client);
  }
  log.debug("Leaving makeWorld().");
}

// ===========================================================================
// a–d. THE DOOR'S CHOICES, with no session
// ===========================================================================

async function doorChoices(anon) {
  log.debug("Entering doorChoices().");
  log.info("=== a. what the link names ===");
  let before = await codeCount("STS-LAUNCH-0001");
  let r = await launch(anon, "urn:launch:" + STAMP + ":nobody");
  await check("a1. an application this realm does not have is 404 " +
              "(STS-LAUNCH-0001)", async function () {
    expect(r.status === 404, shown(r));
    expect(await newRowWith("STS-LAUNCH-0001", before),
           "no audit row carries STS-LAUNCH-0001");
  });
  before = await codeCount("STS-LAUNCH-0002");
  r = await launch(anon, RP11, { protocol: "kerberos" });
  await check("a2. a protocol that is not one of the four is 400 (0002)",
              async function () {
    expect(r.status === 400, shown(r));
    expect(await newRowWith("STS-LAUNCH-0002", before),
           "no audit row carries STS-LAUNCH-0002");
  });
  before = await codeCount("STS-LAUNCH-0003");
  r = await launch(anon, RP11, { protocol: "wsfed" });
  await check("a3. a protocol the application is not declared for is 404 " +
              "(0003)", async function () {
    expect(r.status === 404, shown(r));
    expect(await newRowWith("STS-LAUNCH-0003", before),
           "no audit row carries STS-LAUNCH-0003");
  });

  log.info("=== b. the switch, and where each protocol goes ===");
  before = await codeCount("STS-LAUNCH-0005");
  r = await launch(anon, SP2);
  await check("b1. an application with no override is refused 403: " +
              "identity-provider-initiated sign-in is off by default (0005)",
              async function () {
    expect(r.status === 403, shown(r));
    expect(await newRowWith("STS-LAUNCH-0005", before),
           "no audit row carries STS-LAUNCH-0005");
  });
  await apiOk("/applications/set", { application: SP2,
                                     attribute: "saml2IdpInitiatedSso",
                                     value: "TRUE" },
              "turning saml2IdpInitiatedSso on for " + SP2);
  r = await launch(anon, SP2, { target: "/after?x=1" });
  const toSaml2 = realmPath() + "/saml2/unsolicited/" +
    encodeURIComponent(SP2) + "?target=" + encodeURIComponent("/after?x=1");
  await check("b2. turned on through /admin-api/applications/set, SAML 2.0 " +
              "goes to /saml2/unsolicited/{sp} with the target as " +
              "RelayState", async function () {
    expect(r.status === 303 && pathOf(r.location) === toSaml2,
           shown(r) + " (wanted " + toSaml2 + ")");
  });
  const saml2Hop = r;
  r = await launch(anon, RP11, { target: "https://rp/t" });
  const toSaml11 = realmPath() + "/saml11/sso/" + encodeURIComponent(RP11) +
    "?providerId=" + encodeURIComponent(RP11) + "&TARGET=" +
    encodeURIComponent("https://rp/t");
  await check("b3. SAML 1.1 goes to /saml11/sso/{rp} with providerId and " +
              "TARGET", async function () {
    expect(r.status === 303 && pathOf(r.location) === toSaml11,
           shown(r) + " (wanted " + toSaml11 + ")");
  });
  const saml11Hop = r;
  r = await launch(anon, RP_WS, { target: "ctx" });
  const toWsfed = realmPath() + "/wsfed/initiate/" +
    encodeURIComponent(RP_WS) + "?wctx=ctx";
  await check("b4. WS-Federation goes to /wsfed/initiate/{rp} with the " +
              "target as wctx", async function () {
    expect(r.status === 303 && pathOf(r.location) === toWsfed,
           shown(r) + " (wanted " + toWsfed + ")");
  });
  const wsfedHop = r;

  // ONE STEP FURTHER: the endpoint the door chose reads the same switch on
  // whichever node answers, so with no session it begins a sign-in instead
  // of refusing — and the switched-off application's endpoint refuses by
  // itself, which is what makes going straight to it no way round the door.
  const hops = [["b5", "SAML 2.0", saml2Hop], ["b6", "SAML 1.1", saml11Hop],
                ["b7", "WS-Federation", wsfedHop]];
  for (const one of hops) {
    const next = one[2].location
      ? await anon.go("GET", new URL(one[2].location,
                                     realmBase() + "/").toString())
      : { status: 0, location: "", text: "the door sent nowhere" };
    await check(one[0] + ". followed one step, the " + one[1] + " endpoint " +
                "sends a browser with no session to the sign-in screen, " +
                "not a refusal", async function () {
      expect(sentToSignIn(next), shown(next));
    });
  }
  r = await anon.go("GET", realmBase() + "/saml2/unsolicited/" +
                    encodeURIComponent(SP2_OFF));
  await check("b8. and the endpoint itself refuses a switched-off service " +
              "provider (403), so it is no way round the door",
              async function () {
    expect(r.status === 403, shown(r));
  });

  log.info("=== c. nowhere to send it ===");
  before = await codeCount("STS-LAUNCH-0006");
  r = await launch(anon, SP2_NOACS);
  await check("c1. no registered assertion consumer service is 409 (0006)",
              async function () {
    expect(r.status === 409, shown(r));
    expect(await newRowWith("STS-LAUNCH-0006", before),
           "no audit row carries STS-LAUNCH-0006");
  });

  log.info("=== d. more than one protocol ===");
  before = await codeCount("STS-LAUNCH-0004");
  r = await launch(anon, BOTH);
  await check("d1. two protocols switched on and no preference is 409 " +
              "(0004)", async function () {
    expect(r.status === 409, shown(r));
    expect(await newRowWith("STS-LAUNCH-0004", before),
           "no audit row carries STS-LAUNCH-0004");
  });
  r = await launch(anon, BOTH, { protocol: "wsfed" });
  await check("d2. ?protocol= picks one", async function () {
    expect(r.status === 303 &&
           pathOf(r.location).indexOf(realmPath() + "/wsfed/initiate/") === 0,
           shown(r));
  });
  r = await launch(anon, PREFERS);
  await check("d3. appLaunchProtocol picks when the link does not",
              async function () {
    expect(r.status === 303 &&
           pathOf(r.location).indexOf(realmPath() + "/wsfed/initiate/") === 0,
           shown(r));
  });
  log.debug("Leaving doorChoices().");
}

// ===========================================================================
// e. OPENID CONNECT CORE SECTION 4
// ===========================================================================

// The section 4 redirect's checks, for e3 and the launch in f4.
function isSection4(r) {
  log.debug("Entering isSection4().");
  let to = null;
  try {
    to = new URL(String(r.location || ""));
  } catch (e) {
    log.debug("Caught in isSection4(): " + ((e && e.message) || e));
    // Not an absolute URL, so not the client's initiate_login_uri.
    to = null;
  }
  const ok = r.status === 303 && !!to &&
    to.origin + to.pathname === INITIATE &&
    !!to.searchParams.get("iss") &&
    to.searchParams.get("login_hint") === USER &&
    to.searchParams.get("tenant") === REALM &&
    to.searchParams.get("target_link_uri") === HOME;
  log.debug("Leaving isSection4(). " + ok);
  return ok;
}

async function openIdLaunch(alice) {
  log.debug("Entering openIdLaunch().");
  log.info("=== e. OpenID Connect Core section 4 ===");
  const first = await launch(alice, RP_CLIENT);
  await check("e1. with no session the OpenID Connect launch goes to the " +
              "sign-in screen", async function () {
    expect(sentToSignIn(first), shown(first));
  });
  must(sentToSignIn(first), "the launch did not reach the sign-in screen, " +
       "so nobody can be signed in for e and f: " + shown(first));
  const screen = new URL(first.location, realmBase() + "/").toString();
  const sent = await authnSignin.signInWithJar(realmBase(), screen,
    { action: "login", username: USER, password: PASSWORD }, alice.jar,
    { ignoreOffer: true });
  const back = pathOf(sent.location);
  await check("e2. signed in with the password, the sign-in returns to the " +
              "launch link", async function () {
    expect(sent.status === 303 && back === realmPath() + link(RP_CLIENT),
           sent.status + " " + (sent.location ||
                                String(sent.text || "").slice(0, 300)));
  });
  must(sent.status === 303 && back,
       "the sign-in did not complete, so e3 and f cannot run: " +
       sent.status + " " + String(sent.text || "").slice(0, 300));
  const r = await alice.go("GET", new URL(back, realmBase() + "/")
    .toString());
  await check("e3. then 303 to the client's initiate_login_uri with iss, " +
              "login_hint, tenant and the home page as target_link_uri",
              async function () {
    expect(isSection4(r), shown(r));
  });
  log.debug("Leaving openIdLaunch().");
}

// ===========================================================================
// s. THE SAML AND WS-FEDERATION ENDPOINTS, ON THE SESSION
// ===========================================================================

async function signedInEndpoints(alice) {
  log.debug("Entering signedInEndpoints().");
  log.info("=== s. each endpoint the door sends to, with the session ===");
  const cases = [
    ["s1", "SAML 2.0", SP2, { target: "/after" }, "SAMLResponse", ACS],
    ["s2", "SAML 1.1", RP11, { target: "https://rp/t" }, "SAMLResponse",
     ACS11],
    ["s3", "WS-Federation", RP_WS, { target: "ctx" }, "wresult", REPLY]
  ];
  for (const one of cases) {
    const door = await launch(alice, one[2], one[3]);
    const r = door.location
      ? await alice.go("GET", new URL(door.location,
                                      realmBase() + "/").toString())
      : door;
    const form = formsIn(r.text).filter(function (f) {
      return f.fields.indexOf(one[4]) >= 0;
    })[0] || null;
    await check(one[0] + ". " + one[1] + ": the link, followed with the " +
                "session, answers the self-submitting form carrying " +
                one[4] + " to the registered address", async function () {
      expect(door.status === 303, "the door: " + shown(door));
      expect(r.status === 200 && form && form.action === one[5],
             shown(r) + " — form " + JSON.stringify(form) + " (wanted " +
             one[5] + ")");
    });
  }
  log.debug("Leaving signedInEndpoints().");
}

// ===========================================================================
// f. THE CLIENT'S OWN START, AT THE AUTHORIZATION ENDPOINT
// ===========================================================================

// An authorization request for `client` on alice's session, with PKCE and a
// fresh nonce (product refuses a nonce a redeemed code used). A consent
// screen met anyway is answered Allow and its answer followed back.
async function authorize(alice, client) {
  log.debug("Entering authorize(). " + client);
  const verifier = nodeCrypto.randomBytes(32).toString("base64url");
  const challenge = nodeCrypto.createHash("sha256").update(verifier)
    .digest("base64url");
  let r = await alice.go("GET", realmBase() + "/oauth2/authorize?" +
    new URLSearchParams({
      client_id: client, response_type: "code", redirect_uri: REDIRECT,
      scope: "openid", state: "s-" + nodeCrypto.randomBytes(6)
        .toString("hex"),
      code_challenge: challenge, code_challenge_method: "S256",
      nonce: "n-" + nodeCrypto.randomBytes(9).toString("base64url")
    }).toString());
  if (isRedirect(r) && authnSignin.isConsent(r.location)) {
    log.info("  (a consent screen was met for " + client + " despite the " +
             "global consent, and was answered Allow)");
    const answered = await authnSignin.consentWithJar(
      new URL(r.location, realmBase() + "/").toString(), "allow", alice.jar);
    r = answered.location
      ? await alice.go("GET", new URL(answered.location,
                                      realmBase() + "/").toString())
      : { status: answered.status, location: "", text: answered.text };
  }
  log.debug("Leaving authorize(). " + r.status);
  return r;
}

function answeredWithCode(r) {
  log.debug("Entering answeredWithCode().");
  const ok = isRedirect(r) && r.location.indexOf(REDIRECT) === 0 &&
    /[?&]code=/.test(r.location) &&
    r.location.indexOf("error=") < 0;
  log.debug("Leaving answeredWithCode(). " + ok);
  return ok;
}

function refusedUnauthorized(r) {
  log.debug("Entering refusedUnauthorized().");
  const ok = isRedirect(r) && r.location.indexOf(REDIRECT) === 0 &&
    r.location.indexOf("error=unauthorized_client") > 0;
  log.debug("Leaving refusedUnauthorized(). " + ok);
  return ok;
}

async function clientsOwnStart(alice) {
  log.debug("Entering clientsOwnStart().");
  log.info("=== f. the client's own start, at /oauth2/authorize ===");
  let r = await authorize(alice, RP_CLIENT);
  await check("f1. within the window, the launched client's authorization " +
              "request is answered with a code — which is also how the " +
              "launch recorded on the session (launch.js's e4) is seen " +
              "over HTTP", async function () {
    expect(answeredWithCode(r), shown(r).slice(0, 300));
  });
  const before = await codeCount("STS-OAUTH-0959");
  r = await authorize(alice, RP_CLIENT);
  await check("f2. the launch is spent once the response went out: the " +
              "next request is refused unauthorized_client",
              async function () {
    expect(refusedUnauthorized(r), shown(r).slice(0, 300));
  });
  await check("f3. and the refusal is recorded as STS-OAUTH-0959",
              async function () {
    expect(await newRowWith("STS-OAUTH-0959", before),
           "no audit row carries STS-OAUTH-0959");
  });

  // THE WINDOW, at its minimum, waited out — and put back whatever happens.
  // Twelve seconds rather than eleven: a launch is recorded in whole
  // seconds, and in `cluster` the node that records it and the node that
  // checks it read two clocks.
  try {
    await apiOk("/config/set", { key: WINDOW_KEY, value: 10 },
                "setting " + WINDOW_KEY + " to 10 in " + REALM);
    const launched = await launch(alice, RP_CLIENT);
    await check("f4a. with the window at 10 s, a launch on the session " +
                "goes straight to initiate_login_uri", async function () {
      expect(isSection4(launched), shown(launched));
    });
    log.info("  (waiting 12 s for the 10 s launch window to pass)");
    await sleep(12000);
    r = await authorize(alice, RP_CLIENT);
    await check("f4. a launch older than oauth2.launchWindowS does not " +
                "count: refused unauthorized_client", async function () {
      expect(refusedUnauthorized(r), shown(r).slice(0, 300));
    });
  } finally {
    // `reset` RATHER THAN WRITING 300 BACK: a `set` leaves `source:
    // override` behind (tests/CLAUDE.md, *Restore a setting with `reset`*).
    const reset = await api("POST", "/config/reset", { key: WINDOW_KEY });
    if (!(reset.status === 200 && reset.body && reset.body.ok !== false)) {
      failures.push("resetting " + WINDOW_KEY + " in " + REALM +
                    " answered " + reset.status + " " +
                    reset.text.slice(0, 200));
      log.error("  [FAILED] resetting " + WINDOW_KEY + ": " + reset.status);
    }
  }

  r = await authorize(alice, PLAIN_CLIENT);
  await check("f5. a client whose own start is on (the default) is not " +
              "touched: answered with a code, no launch needed",
              async function () {
    expect(answeredWithCode(r), shown(r).slice(0, 300));
  });
  log.debug("Leaving clientsOwnStart().");
}

// ===========================================================================
// g. THE CONSOLE'S LINKS AND THE PORTAL'S
// ===========================================================================

async function launchUrlsOf(identifier) {
  log.debug("Entering launchUrlsOf(). " + identifier);
  const r = await api("GET", "/applications?application=" +
                      encodeURIComponent(identifier));
  const urls = r.body && r.body.page ? r.body.page.launchUrls : null;
  log.debug("Leaving launchUrlsOf().");
  return { status: r.status, urls: urls, text: r.text };
}

async function consoleLinks() {
  log.debug("Entering consoleLinks().");
  log.info("=== g. the management API's view and the portal's ===");
  let got = await launchUrlsOf(SP2_NOACS);
  await check("g1. /admin-api's application view carries launchUrls: the " +
              "URL, the switch and what is missing, for the protocols the " +
              "application has", async function () {
    const one = got.urls && got.urls.saml2;
    expect(got.status === 200 && one, got.status + " " +
           JSON.stringify(got.urls || got.text.slice(0, 300)));
    expect(pathOf(one.url) === realmPath() + link(SP2_NOACS,
                                                  { protocol: "saml2" }) &&
           one.enabled === true &&
           (one.missing || []).join() === "samlAssertionConsumerService" &&
           !got.urls.wsfed, JSON.stringify(got.urls));
  });
  got = await launchUrlsOf(SP2_OFF);
  await check("g2. a switched-off one is carried too, with the protocol's " +
              "own endpoint", async function () {
    const one = got.urls && got.urls.saml2;
    expect(one && one.enabled === false && !(one.missing || []).length &&
           pathOf(one.endpoint) === realmPath() + "/saml2/unsolicited/" +
             encodeURIComponent(SP2_OFF), JSON.stringify(got.urls));
  });
  got = await launchUrlsOf(RP_CLIENT);
  const plain = await launchUrlsOf(PLAIN_CLIENT);
  await check("g3. an OpenID Connect client's view carries its link with " +
              "initiate_login_uri as the endpoint, and one without an " +
              "initiate_login_uri says that is what is missing",
              async function () {
    const one = got.urls && got.urls.oidc;
    expect(one && one.enabled === true && !(one.missing || []).length &&
           one.endpoint === INITIATE &&
           pathOf(one.url) === realmPath() + link(RP_CLIENT,
                                                  { protocol: "oidc" }),
           JSON.stringify(got.urls));
    const other = plain.urls && plain.urls.oidc;
    expect(other && other.enabled === false &&
           (other.missing || []).join() === "oauthInitiateLoginUri",
           JSON.stringify(plain.urls));
  });
  log.debug("Leaving consoleLinks().");
}

// Every row of /account-api/applications, page by page.
async function portalRows(portal) {
  log.debug("Entering portalRows().");
  const rows = [];
  let pages = 1;
  let status = 0;
  for (let page = 1; page <= pages && page <= 20; page += 1) {
    const r = await portal.api("GET", "/account-api/applications?page=" +
                               page);
    status = r.status;
    const view = r.json && r.json.view ? r.json.view : r.json;
    if (r.status !== 200 || !view) {
      break;
    }
    (view.rows || []).forEach(function (row) {
      rows.push(row);
    });
    pages = Number(view.pages || 1);
  }
  log.debug("Leaving portalRows(). " + rows.length);
  return { status: status, rows: rows };
}

async function portalLinks() {
  log.debug("Entering portalLinks().");
  let portal = null;
  try {
    portal = await portalSignin.signInToThePortal(realmBase(), USER, log,
                                                  { password: PASSWORD });
  } catch (e) {
    log.debug("Caught in portalLinks(): " + ((e && e.message) || e));
    // Recorded as the section's failure; nothing below can run without it.
    portal = null;
    failures.push("g4. signing in to the portal — " +
                  ((e && e.message) || e));
    log.error("  [FAILED] signing in to the portal: " +
              ((e && e.message) || e));
  }
  if (!portal) {
    log.debug("Leaving portalLinks(). No portal session.");
    return;
  }
  const got = await portalRows(portal);
  const rowOf = function (id) {
    log.debug("Entering rowOf().");
    log.debug("Leaving rowOf().");
    return got.rows.filter(function (row) {
      return row.identifier === id;
    })[0] || null;
  };
  const offered = rowOf(SP2);
  const notOffered = rowOf(SP2_OFF);
  await check("g4. /account-api/applications offers a Sign in link where " +
              "the switch is on and none where it is off",
              async function () {
    expect(got.status === 200, "it answered " + got.status);
    expect(offered && offered.launches && offered.launches.length === 1 &&
           pathOf(offered.launches[0].url) === realmPath() +
             link(SP2, { protocol: "saml2" }) &&
           notOffered && notOffered.launches &&
           notOffered.launches.length === 0,
           JSON.stringify([offered, notOffered]).slice(0, 600));
  });
  const noAcs = rowOf(SP2_NOACS);
  await check("g5. and none for an application with nowhere registered to " +
              "send the sign-in, though its switch is on", async function () {
    expect(noAcs && noAcs.launches && noAcs.launches.length === 0,
           JSON.stringify(noAcs).slice(0, 400));
  });
  const client = rowOf(RP_CLIENT);
  await check("g6. the OpenID Connect link goes through the door, not " +
              "straight to initiate_login_uri", async function () {
    expect(client && client.launches && client.launches.length === 1 &&
           client.launches[0].protocol === "oidc" &&
           pathOf(client.launches[0].url) === realmPath() +
             link(RP_CLIENT, { protocol: "oidc" }),
           JSON.stringify(client).slice(0, 400));
  });
  log.debug("Leaving portalLinks().");
}

// ===========================================================================
// THE RUN
// ===========================================================================

async function test() {
  log.debug("Entering test().");
  log.info("Identity-provider-initiated sign-in against " + base +
           ", in the realm " + REALM);
  await makeWorld();
  await doorChoices(browser());
  const alice = browser();
  await openIdLaunch(alice);
  await signedInEndpoints(alice);
  await clientsOwnStart(alice);
  await consoleLinks();
  await portalLinks();
  log.info("The realm " + REALM + " is left standing (tests/CLAUDE.md, *No " +
           "job removes a realm*).");
  if (failures.length) {
    log.error(checks + " check(s) passed, " + failures.length + " FAILED:");
    failures.forEach(function (f) {
      log.error("  [FAILED] " + f.split("\n")[0]);
    });
    log.debug("Leaving test(). Failed.");
    return 1;
  }
  // A FLOOR ON THE COUNT: a section that stops being called takes its
  // checks with it, and the run would still say "passed".
  expect(checks >= 33, "only " + checks + " checks ran, so a SECTION " +
         "STOPPED BEING CALLED.");
  log.info(checks + " checks passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
  return 0;
}

const program = new Command();
program
  .name("sts_idp_initiated_launch")
  .description("Identity-provider-initiated sign-in over HTTP (#715): " +
      "/launch/{app} chooses the protocol, obeys the per-application " +
      "switch set through /admin-api, hands each protocol to its endpoint, " +
      "records an OpenID Connect launch /oauth2/authorize honours once and " +
      "within oauth2.launchWindowS, and is the link /admin-api and " +
      "/account-api carry.")
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
