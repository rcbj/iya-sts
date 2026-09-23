// ===========================================================================
// FEDERATION OVER THE NETWORK, BETWEEN TWO TRUST REALMS OF ONE SERVICE.
//
// federation/CLAUDE.md is emphatic that this is the one feature here that
// REFUSES BY DEFAULT, and that its inbound half — `/federation/acs/{id}` —
// cannot be made permissive: what arrives there is an unauthenticated request
// claiming to be a person, and the session it produces is the one every
// protocol in the process reads. A happy path proves close to nothing on such
// a surface ("an assertion that verifies against the key it was signed with
// is not evidence that anything would have been refused"), so most of what
// this file asserts is a REFUSAL, and every refusal is asserted to have
// started no session.
//
// Until this job, federation was covered in process only
// (tests/federation_provisioning.js, tests/federation_map_bands.js) and by the
// parent project's federation_sso.js, which does not run here. This one drives
// the real thing over HTTP against whatever service the launcher names —
// including a deployed PRODUCT-mode cluster (testidp), where the two realms
// are reached through the public load balancer exactly as a browser would.
//
// ---------------------------------------------------------------------------
// THE PARTIES, ALL CREATED BEFOREHAND AND ALL LEFT STANDING
//
//   /realm/fi-<stamp>   the IDENTITY PROVIDER: an OpenID Provider and a SAML
//                       2.0 identity provider. The only place a name and a
//                       password are ever typed. Its people, and one
//                       application per relationship that points at it, are
//                       created through its own /admin-api.
//   /realm/fs-<stamp>   the SERVICE PROVIDER: six relationships in its
//                       ou=federations, each pointing at the realm above, and
//                       the pre-provisioned person a federated sign-in lands
//                       on.
//
// Everything is CREATED — realms, people, applications, relationships — and
// nothing service-wide is changed. That is the owner's rule for this job, and
// it has two consequences worth knowing before reading the sections:
//
//   * THE OIDC RELATIONSHIP THAT CARRIES THE POSITIVE PATH IS THE FRONT-CHANNEL
//     SHAPE: `fedResponseType: id_token` with form_post and the partner's keys
//     PASTED into `fedJwks`. federation/CLAUDE.md names it "the only way to
//     federate with an OIDC partner from a deployment with no egress", and
//     that is exactly what testidp is to itself: its nodes leave the VPC from
//     their own public addresses, which the load balancer's security group
//     does not admit (deploy/aws/environment/security.tf admits allowed_cidrs
//     and the suite runner's NAT address only), so a node dialling
//     https://test-idp.iyasec.io times out. A local stack cannot dial itself
//     either — its certificate is issued under a Root generated at start that
//     the service's own outbound client does not trust, and
//     `federation.outboundAllowInsecure` is a setting this job may not turn
//     on.
//   * THE AUTHORIZATION CODE RELATIONSHIP IS STILL DRIVEN (section 5), because
//     everything up to the back channel is assertable anywhere — PKCE, the
//     state, the nonce, the code arriving at the ACS — and a back channel that
//     FAILS must still start no session. Where the service can reach its own
//     token endpoint the sign-in completes and is asserted as one; where it
//     cannot, the refusal is asserted instead and the log says which.
//
// ---------------------------------------------------------------------------
// WHAT IS ASSERTED
//
//   1. OIDC (front channel): the SP realm's login sends the browser to the IdP
//      realm's authorization endpoint with state and nonce; the IdP realm draws
//      ITS OWN sign-in screen; the ID Token that comes back names the IdP realm
//      as issuer and this relationship's client as audience; the SP realm
//      starts a session whose subject is ITS OWN entry for the person, with
//      `federated` first in the amr; the relationship counts it.
//   2. PROVISIONING, AS CONFIGURED: the relationship's `fedAutocreateUsers` is
//      READ, not set, and a person the SP realm has never heard of is either
//      created (the switch on and a service that creates entries; named
//      `<relationship>~<name>` and linked to the partner's subject since
//      #109) or refused
//      403 "has not been provisioned" with nothing created — product mode
//      never creates, `mode.autoCreates()`.
//   3. OIDC NEGATIVES: an ID Token signed by a key the relationship does not
//      name (a forgery carrying the partner's own kid); `alg: none`; HS256
//      nominated against the partner's RSA key; a genuine ID Token replayed
//      into a new sign-in (the nonce); a relationship whose pasted keys are
//      not the partner's, fed a GENUINE token; a relationship nobody
//      configured, in this realm and in the partner's.
//   4. SAML 2.0: the SP realm's signed AuthnRequest on a real form with a real
//      button (no script); the IdP realm's Response verified against the
//      relationship's certificate; the SAME captured Response refused at a
//      second relationship to the same partner because it is ADDRESSED TO A
//      DIFFERENT SERVICE PROVIDER, refused at a DISABLED relationship, refused
//      at an unconfigured id, and then accepted where it was addressed — which
//      is what shows each refusal was about the one thing that differed; a
//      replay of it refused; a forged Response signed by a key the
//      relationship does not name, carrying its own certificate in KeyInfo.
//   5. OIDC authorization code: see above, and an invented code refused.
//   6. ATTRIBUTE REFRESH, AS CONFIGURED: `fedUpdateUserAttributes` READ, and
//      the pre-provisioned person's entry asserted to carry the partner's
//      values (on) or its own (off), and the relationship it came through
//      recorded either way. LAST, because it is the section that fails on a
//      product-mode service today (see the note above that section).
//
// Every refusal is asserted three ways: the status and the page naming the
// check, no `sts_session` set on the response, and — wherever the refused
// document names a person — no new session for that person in the SP realm's
// own /admin-api.
// ===========================================================================

"use strict";

const assert = require("assert");
const nodeCrypto = require("crypto");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const facts = require("./service_facts.js");
const xmldsig = require("./saml_xmldsig.js");

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
var log = bunyan.createLogger({ name: "sts_federation_realms",
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

// ---------------------------------------------------------------------------
// NAMES. Every realm and person carries this run's stamp, so two runs against
// one long-lived service mint their own and never read each other's counters
// (tests/CLAUDE.md, *No job removes a realm* — these are left standing).
// ---------------------------------------------------------------------------
const STAMP = names.runStamp();
const IDP = "fi-" + STAMP;
const SP = "fs-" + STAMP;
// Pre-provisioned in BOTH realms: the person every positive path signs in.
const PERSON = names.usernameFor("fed-pre");
// In the identity provider's realm ONLY: the dynamic-provisioning case.
const STRANGER = names.usernameFor("fed-dyn");
const PASSWORD = "Federation-Passw0rd!-" + String(Date.now()).slice(-6);
const CLIENT_SECRET = "federation-realms-secret-" +
                      nodeCrypto.randomBytes(12).toString("hex");
// Two mail domains, so which realm a value came from is visible on the entry.
// THE IDENTITY PROVIDER'S IS ITS REALM'S OWN DOMAIN (ensureRealm() creates it
// as `<id>.example.net`), because that is the only address its ID Token can
// carry in BOTH modes: development asserts the persona helpers.userFor()
// invents — realms.inventedMailOf(), `<name>@<the ambient realm's domain>` —
// and never reads the entry's `mail`, while product reads the entry, which
// createPerson() writes with this same domain. `idp.federation.test`, until
// 2026-09-21, was an address the partner never sent in development, so the
// two checks comparing against it could not pass there.
const IDP_MAIL = IDP + ".example.net";
const SP_MAIL = "sp-local.federation.test";

// The relationships in the SP realm. One relationship is one direction and
// one partner configuration, so every shape that differs is its own entry.
const REL = {
  front: "oidc-front",      // OIDC, id_token + form_post, keys pasted
  code: "oidc-code",        // OIDC, authorization code, back channel
  wrongKey: "oidc-wrongkey", // OIDC, keys pasted that are NOT the partner's
  saml: "saml",             // SAML 2.0, signed AuthnRequest on HTTP-POST
  samlOther: "saml-other",  // the SAME partner, a different service provider
  samlOff: "saml-off"       // the same partner, never enabled
};
const NOBODY = "nobody-" + STAMP;

let isProduct = false;
let checks = 0;
const failures = [];

// ---------------------------------------------------------------------------
// ONE CHECK. A failure is recorded and the run carries on, so one broken
// property does not hide the forty behind it — the refusals are independent
// of each other and each is worth knowing about. Setup that later sections
// depend on uses `must()` instead, which throws.
// ---------------------------------------------------------------------------
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
    .replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim().slice(0, 400);
}

function htmlDecode(text) {
  log.debug("Entering htmlDecode().");
  log.debug("Leaving htmlDecode().");
  return String(text || "").replace(/&quot;/g, "\"").replace(/&#39;/g, "'")
    .replace(/&apos;/g, "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&");
}

// ---------------------------------------------------------------------------
// THE MANAGEMENT API, in the realm named. The run's token is attached by
// tests/tools/attach-admin-token.js to every /admin-api request, including
// /realm/<id>/admin-api.
// ---------------------------------------------------------------------------
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
    // Not JSON; `text` carries the answer into every message that quotes it.
    body = null;
  }
  log.debug("Leaving api(). status=" + r.status);
  return { status: r.status, body: body, text: text };
}

// ---------------------------------------------------------------------------
// A COOKIE JAR PER SIGN-IN. Both realms are one origin and the session cookie
// has one name at `Path=/`, so one jar is what a browser has — a session
// minted at the identity provider is PRESENTED to the service provider and
// must mean nothing there. A fresh jar per flow keeps each sign-in's evidence
// its own.
// ---------------------------------------------------------------------------
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

// One request, one body read, redirects NOT followed.
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
  const setCookies = r.headers.getSetCookie ? r.headers.getSetCookie() : [];
  log.debug("Leaving hop(). " + r.status);
  return { status: r.status, headers: r.headers, body: body, url: url,
           setCookies: setCookies,
           location: r.headers.get("location") || "" };
}

function postForm(cookies, url, fields) {
  log.debug("Entering postForm(). " + url);
  log.debug("Leaving postForm().");
  return hop(cookies, url, {
    method: "POST", body: new URLSearchParams(fields).toString(),
    headers: { "content-type": "application/x-www-form-urlencoded" } });
}

// Did this response START a session? A refusal must not — and the session
// cookie is the first place that would show, before any listing catches up.
function startsSession(r) {
  log.debug("Entering startsSession().");
  const started = (r.setCookies || []).some(function (line) {
    return /^sts_session=[^;]+/.test(line) &&
           !/^sts_session=;/.test(line) && !/Max-Age=0/i.test(line);
  });
  log.debug("Leaving startsSession(). " + started);
  return started;
}

// Every form on a page, with its action and its hidden fields decoded.
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

function isAcs(url) {
  log.debug("Entering isAcs().");
  log.debug("Leaving isAcs().");
  return /\/federation\/acs\//.test(String(url || ""));
}

// ---------------------------------------------------------------------------
// A BROWSER, UP TO THE SERVICE PROVIDER'S DOOR. Follows redirects, answers
// the identity provider's sign-in screen and consent screen, posts any form
// that leads onward — and STOPS at the first request addressed to a
// `/federation/acs/` path, returning it UNSENT. Stopping there is what lets a
// section send a genuine answer somewhere it was not addressed, or send it
// twice, which is where every interesting refusal in this file comes from.
//
// `trail` records every screen drawn and where, so a section can assert WHICH
// realm asked for the password.
// ---------------------------------------------------------------------------
async function toTheDoor(cookies, startUrl, username) {
  log.debug("Entering toTheDoor(). " + startUrl);
  const trail = { screens: [], hops: [], first: null };
  let r = await hop(cookies, startUrl);
  trail.first = r;
  for (let step = 0; step < 24; step += 1) {
    trail.hops.push(r.status + " " + r.url);
    if (r.status >= 300 && r.status < 400 && r.location) {
      const next = new URL(r.location, r.url).toString();
      if (isAcs(next)) {
        log.debug("Leaving toTheDoor(). A redirect to the ACS.");
        return { method: "GET", url: next, fields: null, trail: trail };
      }
      r = await hop(cookies, next);
      continue;
    }
    if (r.status !== 200) {
      break;
    }
    const forms = formsIn(r.body);
    const signIn = forms.find(function (f) {
      return "authn_id" in f.fields;
    });
    const consent = forms.find(function (f) {
      return /consent/.test(f.action) || "consent_id" in f.fields;
    });
    const onward = forms.find(function (f) {
      return f.method === "post" &&
             ("SAMLResponse" in f.fields || "SAMLRequest" in f.fields ||
              "id_token" in f.fields || "code" in f.fields);
    });
    if (signIn) {
      const to = new URL(signIn.action || r.url, r.url).toString();
      trail.screens.push({ kind: "sign-in", at: to });
      r = await postForm(cookies, to, Object.assign({}, signIn.fields, {
        username: username, password: PASSWORD, action: "login" }));
      continue;
    }
    if (consent) {
      const to = new URL(consent.action || r.url, r.url).toString();
      trail.screens.push({ kind: "consent", at: to });
      r = await postForm(cookies, to, Object.assign({}, consent.fields, {
        action: "allow", decision: "allow" }));
      continue;
    }
    if (onward) {
      const to = new URL(onward.action, r.url).toString();
      if (isAcs(to)) {
        log.debug("Leaving toTheDoor(). A form addressed to the ACS.");
        return { method: "POST", url: to, fields: onward.fields,
                 trail: trail, page: r };
      }
      trail.screens.push({ kind: "onward", at: to, page: r.body });
      r = await postForm(cookies, to, onward.fields);
      continue;
    }
    break;
  }
  log.debug("Leaving toTheDoor(). It never reached the ACS.");
  throw new Error("the browser never reached a /federation/acs/ door: the " +
    "last answer was HTTP " + r.status + " at " + r.url + " — " +
    squash(r.body) + " (trail: " + trail.hops.join(" → ") + ")");
}

// Deliver what toTheDoor() stopped at — to where it was addressed, or, for a
// negative, somewhere else.
function deliver(cookies, door, toUrl, fields) {
  log.debug("Entering deliver().");
  const url = toUrl || door.url;
  if (door.method === "GET" && !fields) {
    log.debug("Leaving deliver(). GET.");
    return hop(cookies, url);
  }
  log.debug("Leaving deliver(). POST.");
  return postForm(cookies, url, fields || door.fields);
}

// The first hop of a sign-in at the service provider, and nothing more: what
// a forgery needs to look like the answer to a request this service made.
async function beginAt(relationship) {
  log.debug("Entering beginAt(). " + relationship);
  const cookies = jar();
  const r = await hop(cookies, realmBase(SP) + "/federation/login/" +
                               relationship);
  log.debug("Leaving beginAt(). " + r.status);
  return { cookies: cookies, r: r };
}

// ---------------------------------------------------------------------------
// WHAT THE SERVICE PROVIDER REALM KNOWS ABOUT A PERSON: their entry and how
// many sign-on sessions they hold there. Asked of the SP realm's OWN
// /admin-api, because the session store and the directory are per realm.
// ---------------------------------------------------------------------------
async function spView(username) {
  log.debug("Entering spView(). " + username);
  const r = await api(SP, "GET", "/users?user=" +
                                  encodeURIComponent(username));
  must(r.status === 200 && r.body,
       "GET /realm/" + SP + "/admin-api/users answered " + r.status + " " +
       r.text.slice(0, 200));
  const ldap = r.body.ldap || {};
  const entry = ldap.found && ldap.entry ? ldap.entry.attributes || {} : null;
  const paging = r.body.sessionsPaging || {};
  const sessions = Array.isArray(r.body.sessions) ? r.body.sessions : [];
  log.debug("Leaving spView().");
  return { known: !!r.body.known, entry: entry,
           sessionCount: Number(paging.total || sessions.length || 0),
           sessions: sessions, subject: r.body.subject || "" };
}

// A session started on one node is listed by another once the change log
// reaches it, so a count that must RISE is waited for, briefly. One that must
// NOT rise is read after a pause of the same order — a refused sign-in makes
// no row for any node to catch up with.
async function sessionCountReaches(username, atLeast) {
  log.debug("Entering sessionCountReaches().");
  let view = await spView(username);
  const started = Date.now();
  while (view.sessionCount < atLeast && Date.now() - started < 10000) {
    await sleep(500);
    view = await spView(username);
  }
  log.debug("Leaving sessionCountReaches(). " + view.sessionCount);
  return view;
}

async function sessionCountAfterRefusal(username) {
  log.debug("Entering sessionCountAfterRefusal().");
  await sleep(1000);
  const view = await spView(username);
  log.debug("Leaving sessionCountAfterRefusal(). " + view.sessionCount);
  return view.sessionCount;
}

async function relationship(id) {
  log.debug("Entering relationship(). " + id);
  const r = await api(SP, "GET", "/federation?relationship=" +
                                 encodeURIComponent(id));
  must(r.status === 200 && r.body && r.body.found,
       "the relationship " + id + " should be registered in " + SP +
       "; GET answered " + r.status + " " + r.text.slice(0, 200));
  log.debug("Leaving relationship().");
  return r.body;
}

// ---------------------------------------------------------------------------
// ONE REFUSAL, asserted the three ways the header promises.
// ---------------------------------------------------------------------------
async function assertRefused(what, r, status, pattern, username, before) {
  log.debug("Entering assertRefused(). " + what);
  await check(what + ": refused " + status, async function () {
    assert.strictEqual(r.status, status,
      "expected HTTP " + status + " and got " + r.status + " — " +
      squash(r.body));
    if (pattern) {
      assert.ok(pattern.test(squash(r.body) + " " + r.body),
        "the refusal page should name the check (" + pattern + "); it " +
        "says: " + squash(r.body));
    }
  });
  await check(what + ": no session cookie on the refusal", async function () {
    assert.ok(!startsSession(r),
      "the refusal set a session cookie: " + JSON.stringify(r.setCookies));
  });
  if (username) {
    await check(what + ": no new session for " + username + " in the " +
                "service provider's realm", async function () {
      const after = await sessionCountAfterRefusal(username);
      assert.strictEqual(after, before,
        "the service provider realm held " + before + " session(s) for " +
        username + " before this refusal and holds " + after + " after it");
    });
  }
  log.debug("Leaving assertRefused().");
}

// ---------------------------------------------------------------------------
// JOSE, written here rather than imported from the service: a forgery built
// by the implementation under test proves only that it agrees with itself.
// ---------------------------------------------------------------------------
function b64uJson(value) {
  log.debug("Entering b64uJson().");
  log.debug("Leaving b64uJson().");
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

function jwtParts(token) {
  log.debug("Entering jwtParts().");
  const parts = String(token || "").split(".");
  let header = {};
  let payload = {};
  try {
    header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
    payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  } catch (e) {
    log.debug("Caught in jwtParts(): " + ((e && e.message) || e));
    // An unparseable token reads as empty; the assertion quoting it says so.
    header = {};
    payload = {};
  }
  log.debug("Leaving jwtParts().");
  return { header: header, payload: payload };
}

function signRs256(header, payload, privateKey) {
  log.debug("Entering signRs256().");
  const input = b64uJson(header) + "." + b64uJson(payload);
  const sig = nodeCrypto.sign("sha256", Buffer.from(input), privateKey)
    .toString("base64url");
  log.debug("Leaving signRs256().");
  return input + "." + sig;
}

function signHs256(header, payload, secret) {
  log.debug("Entering signHs256().");
  const input = b64uJson(header) + "." + b64uJson(payload);
  const sig = nodeCrypto.createHmac("sha256", secret).update(input)
    .digest("base64url");
  log.debug("Leaving signHs256().");
  return input + "." + sig;
}

// The claims a genuine ID Token for PERSON from the IdP realm would carry, for
// the sign-in that `begun` started — right issuer, right audience, the nonce
// that request sent. Only the SIGNATURE is wrong, which is the point.
function forgedClaims(begun, partner) {
  log.debug("Entering forgedClaims().");
  const asked = new URL(begun.r.location);
  const now = Math.floor(Date.now() / 1000);
  log.debug("Leaving forgedClaims().");
  return {
    iss: partner.issuer, aud: asked.searchParams.get("client_id"),
    sub: "urn:uuid:" + nodeCrypto.randomUUID(), iat: now, nbf: now,
    exp: now + 300, nonce: asked.searchParams.get("nonce"),
    preferred_username: PERSON, email: PERSON + "@" + IDP_MAIL
  };
}

// A self-signed certificate for the attacker's key, for the SAML forgery's
// KeyInfo — the one a naive verifier would believe.
function attackerCredential() {
  log.debug("Entering attackerCredential().");
  const forge = require("node-forge");
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = "01" + nodeCrypto.randomBytes(8).toString("hex");
  cert.validity.notBefore = new Date(Date.now() - 60000);
  cert.validity.notAfter = new Date(Date.now() + 3600 * 1000);
  const subject = [{ name: "commonName",
                     value: "not the partner " + STAMP }];
  cert.setSubject(subject);
  cert.setIssuer(subject);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  const privateKeyPem = forge.pki.privateKeyToPem(keys.privateKey);
  log.debug("Leaving attackerCredential().");
  return { certificatePem: forge.pki.certificateToPem(cert),
           privateKeyPem: privateKeyPem,
           privateKey: nodeCrypto.createPrivateKey(privateKeyPem),
           publicJwk: nodeCrypto.createPublicKey(privateKeyPem)
             .export({ format: "jwk" }) };
}

// ---------------------------------------------------------------------------
// SETTING THE WORLD UP. Nothing here changes a service-wide setting: every
// call creates something this run owns.
// ---------------------------------------------------------------------------
async function ensureRealm(id) {
  log.debug("Entering ensureRealm(). " + id);
  const made = await api(null, "POST", "/realms/create",
                         { id: id, domain: id + ".example.net", name: id });
  must(made.status === 200 ||
       /already/i.test(JSON.stringify(made.body || made.text)),
       "creating the realm " + id + " answered " + made.status + " " +
       made.text.slice(0, 300));
  log.debug("Leaving ensureRealm().");
}

async function createPerson(realm, username, mailDomain, withPassword) {
  log.debug("Entering createPerson(). " + realm + " " + username);
  const payload = {
    username: username, invent: false,
    attributes: { cn: "Federation " + username, givenName: "Federation",
                  sn: username, displayName: "Federation " + username,
                  mail: username + "@" + mailDomain },
    credential: withPassword ? "password" : "none" };
  if (withPassword) {
    payload.password = PASSWORD;
  }
  const r = await api(realm, "POST", "/users/create", payload);
  must(r.status === 200 && r.body && r.body.ok,
       "creating " + username + " in " + realm + " answered " + r.status +
       " " + r.text.slice(0, 300));
  log.debug("Leaving createPerson().");
}

async function createApplication(realm, identifier, protocols, fields) {
  log.debug("Entering createApplication(). " + identifier);
  const r = await api(realm, "POST", "/applications/create",
    { identifier: identifier, name: "federation " + identifier,
      protocols: protocols, fields: fields });
  must(r.status === 200 && r.body && r.body.ok,
       "creating the application " + identifier + " in " + realm +
       " answered " + r.status + " " + r.text.slice(0, 300));
  log.debug("Leaving createApplication().");
}

// Create a service-provider-side relationship, fill it in, and (unless told
// not to) enable it — the feature's own order: create (always DISABLED),
// configure, enable as a second act.
async function createRelationship(id, protocol, peer, settings, enable) {
  log.debug("Entering createRelationship(). " + id);
  const made = await api(SP, "POST", "/federation/create",
    { id: id, role: "service-provider", protocol: protocol, peer: peer });
  must(made.status === 200 && made.body && made.body.ok,
       "creating the relationship " + id + " answered " + made.status + " " +
       made.text.slice(0, 300));
  for (const field of Object.keys(settings)) {
    const set = await api(SP, "POST", "/federation/set",
                          { id: id, field: field, value: settings[field] });
    must(set.status === 200 && set.body && set.body.ok,
         "setting " + field + " on " + id + " answered " + set.status + " " +
         set.text.slice(0, 300));
  }
  let enabled = null;
  if (enable) {
    enabled = await api(SP, "POST", "/federation/enable", { id: id });
    must(enabled.status === 200 && enabled.body && enabled.body.ok,
         "enabling " + id + " answered " + enabled.status + " " +
         enabled.text.slice(0, 300));
  }
  log.debug("Leaving createRelationship().");
  return { created: made.body, enabled: enabled && enabled.body };
}

// Where the SP realm says a relationship answers — read from the register,
// never composed here, because a URL composed here and a URL the router serves
// can drift and the partner is configured with the second.
async function acsOf(id) {
  log.debug("Entering acsOf(). " + id);
  const view = await relationship(id);
  const acs = (view.endpoints || {}).assertionConsumerService || "";
  must(acs, "the relationship " + id + " reports no ACS URL");
  log.debug("Leaving acsOf(). " + acs);
  return { acs: acs, view: view };
}

// ---------------------------------------------------------------------------
// THE PARTNER: what the IdP realm publishes about itself, read from it.
// ---------------------------------------------------------------------------
async function partnerOidc() {
  log.debug("Entering partnerOidc().");
  const r = await fetch(realmBase(IDP) + "/.well-known/openid-configuration");
  must(r.status === 200, "the IdP realm's discovery document answered " +
                         r.status);
  const discovery = await r.json();
  const k = await fetch(discovery.jwks_uri);
  must(k.status === 200, "the IdP realm's JWKS answered " + k.status);
  const jwks = await k.json();
  log.debug("Leaving partnerOidc().");
  return { issuer: discovery.issuer, discovery: discovery, jwks: jwks };
}

// The IdP realm's SAML 2.0 metadata FOR one service provider: with
// `saml2.perApplicationEntityId` the entityID differs per service provider, so
// a document fetched without that name would name an issuer the assertions
// will not carry.
async function partnerSaml(spEntityId) {
  log.debug("Entering partnerSaml().");
  const url = realmBase(IDP) + "/saml2/metadata/" +
              encodeURIComponent(spEntityId);
  const r = await fetch(url);
  const xml = await r.text();
  must(r.status === 200, "the IdP realm's SAML metadata at " + url +
                         " answered " + r.status + " " + xml.slice(0, 200));
  const entityId = (/entityID="([^"]+)"/.exec(xml) || [])[1] || "";
  const keyDescriptor = (/<md:KeyDescriptor[^>]*use="signing"[\s\S]*?<\/md:KeyDescriptor>/
    .exec(xml) || [])[0] || xml;
  const certificate = ((/X509Certificate>([^<]+)</.exec(keyDescriptor) ||
                       [])[1] || "").replace(/\s+/g, "");
  const sso = (/SingleSignOnService[^>]*Binding="urn:oasis:names:tc:SAML:2\.0:bindings:HTTP-POST"[^>]*Location="([^"]+)"/
    .exec(xml) || [])[1] || "";
  must(entityId && certificate && sso,
       "the IdP realm's metadata lacks an entityID, a signing certificate " +
       "or an HTTP-POST SSO endpoint: " + xml.slice(0, 300));
  log.debug("Leaving partnerSaml().");
  return { entityId: entityId, certificate: certificate, sso: sso };
}

// What the SP realm publishes for one SAML relationship: the entityID the
// AuthnRequest's Issuer will carry and the certificate that signs it.
async function spSamlMetadata(view) {
  log.debug("Entering spSamlMetadata().");
  const url = (view.endpoints || {}).metadata;
  must(url, "the SAML relationship reports no metadata URL");
  const r = await fetch(new URL(url, base).toString());
  const xml = await r.text();
  must(r.status === 200, "the SP realm's metadata answered " + r.status);
  const entityId = (/entityID="([^"]+)"/.exec(xml) || [])[1] || "";
  const certificate = ((/X509Certificate>([^<]+)</.exec(xml) || [])[1] || "")
    .replace(/\s+/g, "");
  must(entityId && certificate,
       "the SP realm's metadata lacks an entityID or a certificate: " +
       xml.slice(0, 300));
  log.debug("Leaving spSamlMetadata().");
  return { entityId: entityId, certificate: certificate };
}

function pemOf(derBase64) {
  log.debug("Entering pemOf().");
  const lines = String(derBase64).match(/.{1,64}/g) || [];
  log.debug("Leaving pemOf().");
  return "-----BEGIN CERTIFICATE-----\n" + lines.join("\n") +
         "\n-----END CERTIFICATE-----\n";
}

async function setUp() {
  log.debug("Entering setUp().");
  const apiBase = base + "/admin-api";
  isProduct = await facts.isProduct(apiBase);
  log.info("The service is in " + (isProduct ? "PRODUCT" : "DEVELOPMENT") +
           " mode. Identity provider realm " + IDP + ", service provider " +
           "realm " + SP + ".");

  await ensureRealm(IDP);
  await ensureRealm(SP);
  await createPerson(IDP, PERSON, IDP_MAIL, true);
  await createPerson(IDP, STRANGER, IDP_MAIL, true);
  // PRE-PROVISIONED in the service provider's realm, with a mail of its own,
  // so whether the partner's value replaced it is visible (section 6).
  await createPerson(SP, PERSON, SP_MAIL, false);

  const partner = await partnerOidc();
  const kids = (partner.jwks.keys || []).map(function (key) {
    return key.kid;
  }).filter(Boolean);
  must(kids.length > 0, "the IdP realm publishes no key with a kid");
  const attacker = attackerCredential();

  // --- the three OIDC relationships and their clients at the partner -------
  const oidcCommon = {
    fedSsoUrl: partner.discovery.authorization_endpoint,
    fedScope: "openid profile email",
    fedUsernameSource: "preferred_username"
  };
  const front = await createRelationship(REL.front, "oidc", partner.issuer,
    Object.assign({}, oidcCommon, {
      fedClientId: "fs-front-" + STAMP, fedResponseType: "id_token",
      fedJwks: JSON.stringify(partner.jwks) }), true);
  const code = await createRelationship(REL.code, "oidc", partner.issuer,
    Object.assign({}, oidcCommon, {
      fedClientId: "fs-code-" + STAMP, fedResponseType: "code",
      fedTokenUrl: partner.discovery.token_endpoint,
      fedJwksUri: partner.discovery.jwks_uri,
      // OIDC Core section 5.4 (#118): a code-flow ID Token carries no
      // profile claims, so preferred_username is UserInfo's to give — which
      // is how a relying party of a conforming provider gets it.
      fedUserinfoUrl: partner.discovery.userinfo_endpoint,
      fedClientSecret: CLIENT_SECRET }), true);
  // THE ATTACKER'S KEY UNDER EVERY ONE OF THE PARTNER'S kids: selection by kid
  // succeeds, so what refuses the token can only be the signature. An
  // unverified value may SELECT, never ESTABLISH (federation/CLAUDE.md).
  const wrongJwks = { keys: kids.map(function (kid) {
    return Object.assign({}, attacker.publicJwk,
                         { kid: kid, alg: "RS256", use: "sig" });
  }) };
  await createRelationship(REL.wrongKey, "oidc", partner.issuer,
    Object.assign({}, oidcCommon, {
      fedClientId: "fs-wrongkey-" + STAMP, fedResponseType: "id_token",
      fedJwks: JSON.stringify(wrongJwks) }), true);

  for (const [rel, client, confidential] of [
    [REL.front, "fs-front-" + STAMP, false],
    [REL.code, "fs-code-" + STAMP, true],
    [REL.wrongKey, "fs-wrongkey-" + STAMP, false]]) {
    const where = await acsOf(rel);
    const fields = { oauthClientId: [client],
                     oauthRedirectUri: [where.acs] };
    if (confidential) {
      fields.oauthClientSecret = CLIENT_SECRET;
      fields.oauthTokenEndpointAuthMethod = "client_secret_basic";
      fields.oauthGrantType = ["authorization_code"];
      fields.oauthResponseType = ["code"];
    } else {
      // A browser-only relying party: an ID Token by form_post, no secret.
      fields.oauthTokenEndpointAuthMethod = "none";
      fields.oauthGrantType = ["implicit"];
      fields.oauthResponseType = ["id_token"];
    }
    await createApplication(IDP, client, ["oidc"], fields);
  }

  // --- the SAML relationships ---------------------------------------------
  // Created first with no partner fields, because the application at the
  // partner is keyed by OUR entityID, which the SP realm publishes, and the
  // partner's per-service-provider entityID is only knowable once that
  // application exists.
  const samlMade = await api(SP, "POST", "/federation/create",
    { id: REL.saml, role: "service-provider", protocol: "saml2" });
  must(samlMade.status === 200 && samlMade.body && samlMade.body.ok,
       "creating the SAML relationship answered " + samlMade.status + " " +
       samlMade.text.slice(0, 300));
  const samlWhere = await acsOf(REL.saml);
  const ours = await spSamlMetadata(samlWhere.view);
  // THE APPLICATION'S IDENTIFIER IS OUR entityID, because that is the key the
  // SAML 2.0 profile looks a service provider up by — its registered signing
  // certificate is what the partner verifies our signed AuthnRequest against.
  await createApplication(IDP, ours.entityId, ["saml2"], {
    samlEntityId: [ours.entityId],
    samlAssertionConsumerService: [samlWhere.acs],
    samlSigningCertificate: [pemOf(ours.certificate)] });
  const idpSaml = await partnerSaml(ours.entityId);
  const samlSettings = {
    fedPeer: idpSaml.entityId, fedSsoUrl: idpSaml.sso,
    fedSigningCertificate: idpSaml.certificate,
    // HTTP-POST so the request can be SIGNED: a product-mode identity
    // provider refuses an unsigned AuthnRequest
    // (saml2.requireSignedAuthnRequests), and this service signs only on the
    // POST binding.
    fedBinding: "HTTP-POST", fedSignRequest: "TRUE" };
  for (const field of Object.keys(samlSettings)) {
    const set = await api(SP, "POST", "/federation/set",
      { id: REL.saml, field: field, value: samlSettings[field] });
    must(set.status === 200 && set.body && set.body.ok,
         "setting " + field + " on " + REL.saml + " answered " + set.status +
         " " + set.text.slice(0, 300));
  }
  const samlEnabled = await api(SP, "POST", "/federation/enable",
                                { id: REL.saml });
  must(samlEnabled.status === 200 && samlEnabled.body.ok,
       "enabling " + REL.saml + " answered " + samlEnabled.status);
  // The same partner, the same key and issuer: only the service provider
  // differs. And the same again, never enabled.
  await createRelationship(REL.samlOther, "saml2", idpSaml.entityId,
    { fedSsoUrl: idpSaml.sso, fedSigningCertificate: idpSaml.certificate },
    true);
  const off = await createRelationship(REL.samlOff, "saml2",
    idpSaml.entityId,
    { fedSsoUrl: idpSaml.sso, fedSigningCertificate: idpSaml.certificate },
    false);

  // THE PRE-PROVISIONED PERSON IS LINKED TO THE PARTNER (#109). A partner
  // signs in only the person its subject is linked to, and PERSON has no
  // password in the service provider's realm to link at first sign-in with —
  // the pre-provisioned shape this job exercises is the one where an operator
  // links them, through the management API: the OpenID Connect relationships
  // by the partner's `sub`, the SAML one by the NameID it sends.
  const partnerView = await api(IDP, "GET", "/users?user=" +
                                              encodeURIComponent(PERSON));
  const partnerSub = (partnerView.body && partnerView.body.subject) || "";
  must(partnerSub, "the partner realm holds no subject for " + PERSON + ": " +
       partnerView.text.slice(0, 200));
  for (const [rel, subject] of [[REL.front, partnerSub],
                                [REL.code, partnerSub],
                                [REL.saml, PERSON]]) {
    const linked = await api(SP, "POST", "/users/federation-link",
                             { user: PERSON, relationship: rel,
                               subject: subject });
    must(linked.status === 200 && linked.body && linked.body.ok,
         "linking " + PERSON + " through " + rel + " answered " +
         linked.status + " " + linked.text.slice(0, 300));
  }

  log.debug("Leaving setUp().");
  return { partner: partner, attacker: attacker, idpSaml: idpSaml,
           ours: ours, samlAcs: samlWhere.acs, front: front, code: code,
           off: off };
}

// ---------------------------------------------------------------------------
// 0. THE REGISTER'S OWN PROMISES, before anything signs in.
// ---------------------------------------------------------------------------
async function theRegister(world) {
  log.debug("Entering theRegister().");
  log.info("=== 0. the register refuses by default ===");
  await check("a relationship is created DISABLED whatever the request " +
              "says, and names what it is missing", async function () {
    const made = world.front.created;
    assert.strictEqual(String(made.relationship.fedEnabled), "FALSE",
      "fedEnabled came back " + made.relationship.fedEnabled);
    const missing = (made.readiness && made.readiness.missing) || [];
    assert.ok(missing.indexOf("fedSsoUrl") >= 0 &&
              missing.indexOf("fedClientId") >= 0,
      "a bare OIDC relationship should be missing fedSsoUrl and " +
      "fedClientId; it reports " + JSON.stringify(missing));
  });
  await check("enabling is a second act, and a configured relationship is " +
              "then usable", async function () {
    const view = await relationship(REL.front);
    assert.ok(view.enabled && view.ready && view.usable,
      JSON.stringify({ enabled: view.enabled, ready: view.ready,
                       usable: view.usable, missing: view.missing }));
  });
  await check("a relationship never enabled stays unusable, though it is " +
              "fully configured", async function () {
    const view = await relationship(REL.samlOff);
    assert.ok(!view.enabled && view.ready && !view.usable,
      JSON.stringify({ enabled: view.enabled, ready: view.ready,
                       usable: view.usable }));
  });
  log.debug("Leaving theRegister().");
}

// ---------------------------------------------------------------------------
// 1. OPENID CONNECT, FRONT CHANNEL: the positive path.
// ---------------------------------------------------------------------------
async function oidcSignIn(world) {
  log.debug("Entering oidcSignIn().");
  log.info("=== 1. OpenID Connect: a federated sign-in, IdP realm → SP " +
           "realm ===");
  const before = (await spView(PERSON)).sessionCount;
  const cookies = jar();
  const door = await toTheDoor(cookies, realmBase(SP) +
                               "/federation/login/" + REL.front, PERSON);
  const asked = new URL(door.trail.first.location, base);
  const acs = (await acsOf(REL.front)).acs;

  await check("the SP realm's login sends the browser to the IdP realm's " +
              "authorization endpoint, asking for an ID Token by form_post " +
              "with a state and a nonce", async function () {
    assert.strictEqual(door.trail.first.status, 302);
    assert.strictEqual(asked.origin + asked.pathname,
      world.partner.discovery.authorization_endpoint);
    assert.strictEqual(asked.searchParams.get("response_type"), "id_token");
    assert.strictEqual(asked.searchParams.get("response_mode"), "form_post");
    assert.strictEqual(asked.searchParams.get("redirect_uri"), acs);
    assert.ok(asked.searchParams.get("state") &&
              asked.searchParams.get("nonce"),
      "state and nonce: " + asked.search);
  });
  await check("the IdP realm drew ITS OWN sign-in screen, and the SP realm " +
              "drew none", async function () {
    const screens = door.trail.screens.filter(function (s) {
      return s.kind === "sign-in";
    });
    assert.strictEqual(screens.length, 1, JSON.stringify(screens));
    assert.ok(new URL(screens[0].at).pathname.indexOf("/realm/" + IDP +
                                                      "/") === 0,
      "the password was asked for at " + screens[0].at);
  });
  const idToken = (door.fields || {}).id_token || "";
  const token = jwtParts(idToken);
  await check("the IdP realm answers with an ID Token for this person, " +
              "issued by it, audienced to this relationship's client, " +
              "carrying the nonce the SP realm sent", async function () {
    assert.strictEqual(door.method, "POST");
    assert.strictEqual(door.url, acs);
    assert.strictEqual(door.fields.state, asked.searchParams.get("state"));
    assert.strictEqual(token.payload.iss, world.partner.issuer);
    assert.strictEqual(token.payload.aud, "fs-front-" + STAMP);
    assert.strictEqual(token.payload.preferred_username, PERSON);
    assert.strictEqual(token.payload.nonce, asked.searchParams.get("nonce"));
  });
  const r = await deliver(cookies, door);
  await check("the SP realm verifies it against the pasted keys and signs " +
              "the person in", async function () {
    assert.strictEqual(r.status, 200, squash(r.body));
    assert.ok(/Signed in through/.test(r.body) &&
              r.body.indexOf(PERSON) >= 0, squash(r.body));
    assert.ok(startsSession(r), "no session cookie was set: " +
                                JSON.stringify(r.setCookies));
  });
  const view = await sessionCountReaches(PERSON, before + 1);
  await check("the session is the SP realm's own, on ITS entry for the " +
              "person — not the partner's subject — with `federated` first " +
              "in its amr", async function () {
    assert.ok(view.sessionCount >= before + 1,
      "sessions for " + PERSON + ": " + before + " before, " +
      view.sessionCount + " after");
    const uuid = ((view.entry || {}).entryUUID || [])[0] || "";
    assert.ok(uuid, "the SP realm has no entry for " + PERSON);
    assert.strictEqual(view.subject, "urn:uuid:" + uuid);
    assert.notStrictEqual(token.payload.sub, "urn:uuid:" + uuid,
      "the SP realm's subject should be its own, not the partner's");
    const federated = view.sessions.filter(function (s) {
      return /^federated\b/.test(String(s.amr || ""));
    });
    assert.ok(federated.length >= 1,
      "no session with amr beginning `federated`: " +
      JSON.stringify(view.sessions.map(function (s) {
        return s.amr;
      })));
  });
  await check("the relationship counted the sign-in and recorded no error",
              async function () {
    const rel = await relationship(REL.front);
    assert.ok(Number(rel.authentications) >= 1 && rel.lastUser === PERSON,
      JSON.stringify({ authentications: rel.authentications,
                       lastUser: rel.lastUser }));
    assert.strictEqual(rel.lastError, "");
  });
  log.debug("Leaving oidcSignIn().");
  return { idToken: idToken };
}

// ---------------------------------------------------------------------------
// 2. PROVISIONING, AS THE RELATIONSHIP SAYS — READ, NOT SET.
// ---------------------------------------------------------------------------
async function provisioning() {
  log.debug("Entering provisioning().");
  log.info("=== 2. a person the SP realm has never seen ===");
  const rel = await relationship(REL.front);
  const switchOn = String(rel.fields.fedAutocreateUsers) !== "FALSE";
  const ldapOn = String(await facts.setting(realmBase(SP) + "/admin-api",
                                            "ldap.autocreateUsers")) !==
                 "false";
  // mode.autoCreates(): a product-mode directory creates nobody because a
  // sign-in named them, whatever either switch says.
  const creates = switchOn && ldapOn && !isProduct;
  log.info("  fedAutocreateUsers=" + rel.fields.fedAutocreateUsers +
           ", ldap.autocreateUsers=" + ldapOn + ", mode=" +
           (isProduct ? "product" : "development") + " — so the SP realm " +
           (creates ? "SHOULD create" : "should NOT create") + " an entry.");
  // An entry a sign-in CREATES is namespaced to the relationship (#109).
  const CREATED = REL.front + "~" + STRANGER;
  const before = (await spView(STRANGER)).entry ||
                 (await spView(CREATED)).entry;
  await check("precondition: the SP realm has no entry for " + STRANGER,
              async function () {
    assert.strictEqual(before, null);
  });
  const cookies = jar();
  const door = await toTheDoor(cookies, realmBase(SP) +
                               "/federation/login/" + REL.front, STRANGER);
  const r = await deliver(cookies, door);
  if (creates) {
    await check("DYNAMIC PROVISIONING: the sign-in creates the person's " +
                "entry in the SP realm and signs them in", async function () {
      assert.strictEqual(r.status, 200, squash(r.body));
      assert.ok(startsSession(r), "no session cookie");
      const view = await sessionCountReaches(CREATED, 1);
      assert.ok(view.entry, "no entry was created at " + CREATED);
      assert.ok(view.sessionCount >= 1, "no session");
      assert.deepStrictEqual(view.entry.mail, [STRANGER + "@" + IDP_MAIL]);
      assert.ok((view.entry.federationRelationship || [])
                  .indexOf(REL.front) >= 0,
        "the entry does not record the relationship it came through: " +
        JSON.stringify(view.entry.federationRelationship));
    });
  } else {
    await assertRefused("an unprovisioned person, where the SP realm " +
                        "creates nobody", r, 403, /not been provisioned/,
                        STRANGER, 0);
    await check("and nothing was created for them", async function () {
      const view = await spView(CREATED);
      assert.strictEqual(view.entry, null,
        "an entry exists: " + JSON.stringify(view.entry));
    });
  }
  log.debug("Leaving provisioning().");
}

// ---------------------------------------------------------------------------
// 3. OPENID CONNECT: THE REFUSALS.
// ---------------------------------------------------------------------------
async function oidcRefusals(world, genuine) {
  log.debug("Entering oidcRefusals().");
  log.info("=== 3. OpenID Connect: what must be refused ===");
  const kid = (world.partner.jwks.keys[0] || {}).kid;
  const acs = (await acsOf(REL.front)).acs;

  // A FORGERY NAMING THE PARTNER'S OWN kid, signed by a key it never held.
  let before = (await spView(PERSON)).sessionCount;
  let begun = await beginAt(REL.front);
  let forged = signRs256({ alg: "RS256", typ: "JWT", kid: kid },
                         forgedClaims(begun, world.partner),
                         world.attacker.privateKey);
  let r = await postForm(begun.cookies, acs, {
    id_token: forged,
    state: new URL(begun.r.location).searchParams.get("state") });
  await assertRefused("an ID Token signed by a key the relationship does " +
                      "not name, carrying the partner's kid", r, 401,
                      /did not verify/i, PERSON, before);

  // alg: none — refused BY NAME.
  begun = await beginAt(REL.front);
  forged = b64uJson({ alg: "none", typ: "JWT" }) + "." +
           b64uJson(forgedClaims(begun, world.partner)) + ".";
  r = await postForm(begun.cookies, acs, {
    id_token: forged,
    state: new URL(begun.r.location).searchParams.get("state") });
  await assertRefused("an unsigned ID Token (alg: none)", r, 401,
                      /alg=none/i, PERSON, before);

  // HS256 nominated against the partner's RSA key, keyed with that key's
  // PUBLIC half — the classic forgery, which anybody can compute.
  begun = await beginAt(REL.front);
  const publicPem = nodeCrypto.createPublicKey({
    key: world.partner.jwks.keys[0], format: "jwk" })
    .export({ type: "spki", format: "pem" });
  forged = signHs256({ alg: "HS256", typ: "JWT", kid: kid },
                     forgedClaims(begun, world.partner), publicPem);
  r = await postForm(begun.cookies, acs, {
    id_token: forged,
    state: new URL(begun.r.location).searchParams.get("state") });
  await assertRefused("an ID Token nominating HS256 against the partner's " +
                      "RSA key", r, 401, /did not verify/i, PERSON, before);

  // A GENUINE ID Token, replayed into a sign-in that sent a different nonce.
  begun = await beginAt(REL.front);
  r = await postForm(begun.cookies, acs, {
    id_token: genuine.idToken,
    state: new URL(begun.r.location).searchParams.get("state") });
  await assertRefused("a genuine ID Token replayed into a new sign-in",
                      r, 401, /answers a different request/i, PERSON,
                      before);

  // A GENUINE ID Token, at a relationship whose pasted keys are not the
  // partner's: the relationship names the key, not the token.
  const cookies = jar();
  const door = await toTheDoor(cookies, realmBase(SP) +
                               "/federation/login/" + REL.wrongKey, PERSON);
  await check("precondition: the partner really issued an ID Token for the " +
              "wrong-key relationship", async function () {
    assert.strictEqual(jwtParts(door.fields.id_token).payload.aud,
                       "fs-wrongkey-" + STAMP);
  });
  r = await deliver(cookies, door);
  await assertRefused("a GENUINE ID Token at a relationship whose keys are " +
                      "not the partner's", r, 401, /did not verify/i,
                      PERSON, before);
  await check("and that relationship records the refusal and counts no " +
              "sign-in", async function () {
    const rel = await relationship(REL.wrongKey);
    assert.ok(rel.lastError, "no lastError recorded");
    assert.strictEqual(Number(rel.authentications), 0);
  });

  // NOBODY CONFIGURED: an unknown id here, and this relationship's id in the
  // PARTNER's realm, whose register is empty.
  r = await hop(jar(), realmBase(SP) + "/federation/login/" + NOBODY);
  await assertRefused("a login at a relationship nobody configured", r, 404,
                      /No such federation relationship/i, null, 0);
  begun = await beginAt(REL.front);
  r = await postForm(jar(), realmBase(SP) + "/federation/acs/" + NOBODY, {
    id_token: genuine.idToken,
    state: new URL(begun.r.location).searchParams.get("state") });
  await assertRefused("a genuine ID Token at an ACS nobody configured", r,
                      404, null, PERSON, before);
  r = await postForm(jar(), realmBase(IDP) + "/federation/acs/" + REL.front, {
    id_token: genuine.idToken,
    state: new URL(begun.r.location).searchParams.get("state") });
  await assertRefused("the same token at the same id in the partner's " +
                      "realm, which configured no such relationship", r,
                      404, null, PERSON, before);
  log.debug("Leaving oidcRefusals().");
}

// ---------------------------------------------------------------------------
// 4. SAML 2.0.
// ---------------------------------------------------------------------------
function samlXml(encoded) {
  log.debug("Entering samlXml().");
  log.debug("Leaving samlXml().");
  return Buffer.from(String(encoded || ""), "base64").toString("utf8");
}

function forgedResponse(world, requestId, acs) {
  log.debug("Entering forgedResponse().");
  const built = xmldsig.buildAssertion({
    issuer: world.idpSaml.entityId, subject: PERSON,
    audience: world.ours.entityId, recipient: acs, authnStatement: true,
    attributes: { mail: PERSON + "@" + IDP_MAIL } });
  // Signed by the attacker, WITH the attacker's certificate in KeyInfo — the
  // document brings the key that verifies it, which is the one thing a
  // verifier must never believe.
  const signed = xmldsig.sign(built, world.attacker.privateKeyPem,
                              world.attacker.certificatePem);
  const xml = "<samlp:Response " +
    "xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
    "Destination=\"" + acs + "\" ID=\"" + xmldsig.id() + "\" " +
    "InResponseTo=\"" + requestId + "\" IssueInstant=\"" + xmldsig.iso(0) +
    "\" Version=\"2.0\"><saml:Issuer " +
    "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">" +
    world.idpSaml.entityId + "</saml:Issuer><samlp:Status>" +
    "<samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:" +
    "Success\"></samlp:StatusCode></samlp:Status>" + signed +
    "</samlp:Response>";
  log.debug("Leaving forgedResponse().");
  return Buffer.from(xml, "utf8").toString("base64");
}

async function samlFederation(world) {
  log.debug("Entering samlFederation().");
  log.info("=== 4. SAML 2.0: a federated sign-in and what must be refused " +
           "===");
  const acs = world.samlAcs;
  const otherAcs = (await acsOf(REL.samlOther)).acs;
  const offAcs = (await acsOf(REL.samlOff)).acs;
  const before = (await spView(PERSON)).sessionCount;
  const cookies = jar();
  const door = await toTheDoor(cookies, realmBase(SP) +
                               "/federation/login/" + REL.saml, PERSON);

  const outbound = door.trail.screens.find(function (s) {
    return s.kind === "onward";
  });
  await check("the SP realm sends a SIGNED AuthnRequest on a real form with " +
              "a real button and no script", async function () {
    assert.ok(outbound, "no outbound form: " + door.trail.hops.join(" → "));
    assert.strictEqual(outbound.at, world.idpSaml.sso);
    assert.ok(/<button[^>]*type="submit"/.test(outbound.page) &&
              !/<script/i.test(outbound.page),
      "the page should carry a submit button and no script");
    const request = samlXml(formsIn(outbound.page)[0].fields.SAMLRequest);
    assert.ok(request.indexOf("<saml:Issuer>" + world.ours.entityId +
                              "</saml:Issuer>") >= 0, request.slice(0, 300));
    assert.ok(request.indexOf("AssertionConsumerServiceURL=\"" + acs +
                              "\"") >= 0, request.slice(0, 300));
    assert.ok(/<ds:Signature/.test(request), "the request is not signed");
  });
  await check("the IdP realm drew its own sign-in screen", async function () {
    const screens = door.trail.screens.filter(function (s) {
      return s.kind === "sign-in";
    });
    assert.strictEqual(screens.length, 1, JSON.stringify(screens));
    assert.ok(new URL(screens[0].at).pathname.indexOf("/realm/" + IDP +
                                                      "/") === 0,
      screens[0].at);
  });
  const response = samlXml(door.fields.SAMLResponse);
  await check("the IdP realm's Response names it as issuer, this " +
              "relationship as audience and the person as subject",
              async function () {
    assert.strictEqual(door.url, acs);
    assert.ok(response.indexOf(">" + world.idpSaml.entityId + "<") >= 0,
      "issuer: " + response.slice(0, 300));
    assert.ok(new RegExp("<(saml2?:)?Audience>" +
      world.ours.entityId.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") +
      "</(saml2?:)?Audience>").test(response),
      "audience: " + (/<[^>]*Audience>[^<]*</.exec(response) || [""])[0]);
    assert.ok(new RegExp(">" + PERSON + "</(saml2?:)?NameID>")
                .test(response), "NameID");
  });

  // THE SAME DOCUMENT, SENT WHERE IT WAS NOT ADDRESSED. saml-other has the
  // same partner, key and issuer, so the audience is the only difference.
  let r = await deliver(jar(), door, otherAcs);
  await assertRefused("the partner's genuine Response at a DIFFERENT " +
                      "service provider of the same partner", r, 401,
                      /issued for somebody else/i, PERSON, before);
  r = await deliver(jar(), door, offAcs);
  await assertRefused("the same Response at a relationship that is " +
                      "DISABLED", r, 403, /not usable|disabled/i, PERSON,
                      before);
  const offLogin = await hop(jar(), realmBase(SP) + "/federation/login/" +
                                    REL.samlOff);
  await assertRefused("a login at the disabled relationship", offLogin, 403,
                      /disabled/i, null, 0);
  r = await deliver(jar(), door, realmBase(SP) + "/federation/acs/" +
                                 NOBODY);
  await assertRefused("the same Response at an ACS nobody configured", r,
                      404, null, PERSON, before);

  // A FORGERY: right issuer, audience, recipient and InResponseTo, signed by
  // a key the relationship does not name, with that key's certificate inside.
  const begun = await beginAt(REL.saml);
  const pending = formsIn(begun.r.body)[0] || { fields: {} };
  const requestId = (/ ID="([^"]+)"/.exec(samlXml(pending.fields.SAMLRequest))
                     || [])[1] || "_unknown";
  r = await postForm(begun.cookies, acs, {
    SAMLResponse: forgedResponse(world, requestId, acs),
    RelayState: pending.fields.RelayState || "" });
  await assertRefused("a Response signed by a key the relationship does not " +
                      "name, carrying its own certificate in KeyInfo", r,
                      401, /signature did not verify/i, PERSON, before);

  // AND NOW WHERE IT WAS ADDRESSED: every refusal above was about the one
  // thing that differed.
  r = await deliver(cookies, door);
  await check("the genuine Response is accepted where it was addressed, " +
              "and signs the person in", async function () {
    assert.strictEqual(r.status, 200, squash(r.body));
    assert.ok(/Signed in through/.test(r.body) &&
              r.body.indexOf(PERSON) >= 0, squash(r.body));
    assert.ok(startsSession(r), "no session cookie");
    const view = await sessionCountReaches(PERSON, before + 1);
    assert.ok(view.sessionCount >= before + 1,
      "sessions: " + before + " before, " + view.sessionCount + " after");
  });
  const afterAccepted = (await spView(PERSON)).sessionCount;
  r = await deliver(jar(), door);
  await assertRefused("the same Response replayed", r, 401,
                      /did not ask for|did not start/i, PERSON,
                      afterAccepted);
  await check("the relationships' records: the sign-in counted where it was " +
              "addressed, the refusal recorded where it was not",
              async function () {
    const good = await relationship(REL.saml);
    const other = await relationship(REL.samlOther);
    assert.ok(Number(good.authentications) >= 1 && good.lastUser === PERSON,
      JSON.stringify({ authentications: good.authentications,
                       lastUser: good.lastUser }));
    assert.strictEqual(Number(other.authentications), 0);
    assert.ok(other.lastError, "saml-other recorded no error");
  });
  log.debug("Leaving samlFederation().");
}

// ---------------------------------------------------------------------------
// 5. OPENID CONNECT, AUTHORIZATION CODE: the back channel.
// ---------------------------------------------------------------------------
async function oidcCodeFlow(world) {
  log.debug("Entering oidcCodeFlow().");
  log.info("=== 5. OpenID Connect: the authorization code and the back " +
           "channel ===");
  const acs = (await acsOf(REL.code)).acs;
  const before = (await spView(PERSON)).sessionCount;
  const cookies = jar();
  const door = await toTheDoor(cookies, realmBase(SP) +
                               "/federation/login/" + REL.code, PERSON);
  const asked = new URL(door.trail.first.location, base);
  await check("the SP realm asks for a code with PKCE (S256), a state and " +
              "a nonce", async function () {
    assert.strictEqual(asked.searchParams.get("response_type"), "code");
    assert.strictEqual(asked.searchParams.get("code_challenge_method"),
                       "S256");
    assert.ok(asked.searchParams.get("code_challenge") &&
              asked.searchParams.get("state") &&
              asked.searchParams.get("nonce"), asked.search);
  });
  const answer = new URL(door.url);
  await check("the IdP realm returns a code to the SP realm's ACS, with the " +
              "state and its issuer (RFC 9207)", async function () {
    assert.strictEqual(answer.origin + answer.pathname, acs);
    assert.ok(answer.searchParams.get("code"), door.url);
    assert.strictEqual(answer.searchParams.get("state"),
                       asked.searchParams.get("state"));
    assert.strictEqual(answer.searchParams.get("iss"), world.partner.issuer);
  });
  const r = await deliver(cookies, door);
  if (r.status === 200) {
    log.info("  the back channel reached the IdP realm's token endpoint: " +
             "the code flow completed end to end.");
    await check("the code is redeemed over the back channel and the person " +
                "signed in", async function () {
      assert.ok(/Signed in through/.test(r.body), squash(r.body));
      assert.ok(startsSession(r), "no session cookie");
      const view = await sessionCountReaches(PERSON, before + 1);
      assert.ok(view.sessionCount >= before + 1, "no new session");
    });
  } else {
    // THE SERVICE CANNOT REACH ITS OWN TOKEN ENDPOINT FROM WHERE IT RUNS —
    // see the header: testidp's nodes are not admitted by their own load
    // balancer, and a local stack does not trust its own certificate. What
    // must hold regardless is that a failed back channel starts nothing.
    log.warn("  the back channel did NOT complete (HTTP " + r.status + "): " +
             squash(r.body).slice(0, 300) + ". The service cannot redeem a " +
             "code at its own public address from where it runs; asserting " +
             "the refusal instead.");
    await assertRefused("a code the service could not redeem", r, 502,
                        /could not be redeemed/i, PERSON, before);
    await check("and the relationship records why", async function () {
      const rel = await relationship(REL.code);
      assert.ok(/token/i.test(rel.lastError), "lastError: " + rel.lastError);
    });
  }
  // AN INVENTED CODE, with a genuine state: whatever the back channel's
  // reachability, the partner never issued it and nobody is signed in.
  const now = (await spView(PERSON)).sessionCount;
  const begun = await beginAt(REL.code);
  const invented = await hop(begun.cookies, acs + "?code=invented-" + STAMP +
    "&state=" + encodeURIComponent(new URL(begun.r.location)
                                     .searchParams.get("state")));
  await assertRefused("an authorization code the partner never issued",
                      invented, 502, /could not be redeemed/i, PERSON, now);
  log.debug("Leaving oidcCodeFlow().");
}

// ---------------------------------------------------------------------------
// 6. ATTRIBUTE REFRESH, AS THE RELATIONSHIP SAYS — READ, NOT SET.
//
// LAST, because on a PRODUCT-mode service it fails today, and a failure here
// should not be the reason nothing after it ran. ldap/ldap_server.js's
// `autoCreateUser()` returns before it looks the person up when
// `autocreateUsers()` is false — and that is `mode.autoCreates() &&
// ldap.autocreateUsers`, false in every product realm — so a PRE-PROVISIONED
// person's entry is never updated from the partner and never records the
// relationship, although the comment below that early return, the
// `fedUpdateUserAttributes` schema row ("Which relationship and issuer a
// person came through is recorded either way") and federation/CLAUDE.md all
// say it is.
// ---------------------------------------------------------------------------
async function attributeRefresh() {
  log.debug("Entering attributeRefresh().");
  log.info("=== 6. the partner's attributes on the pre-provisioned entry ===");
  const rel = await relationship(REL.front);
  const refresh = String(rel.fields.fedUpdateUserAttributes) !== "FALSE";
  log.info("  fedUpdateUserAttributes=" + rel.fields.fedUpdateUserAttributes +
           ", so " + PERSON + "'s mail should now be " +
           (refresh ? "the partner's" : "the SP realm's own") + ".");
  const view = await spView(PERSON);
  await check("the pre-provisioned entry records the relationships the " +
              "person came through", async function () {
    const came = (view.entry && view.entry.federationRelationship) || [];
    assert.ok(came.indexOf(REL.front) >= 0,
      "federationRelationship on " + PERSON + "'s SP entry is " +
      JSON.stringify(came) + " after a sign-in through " + REL.front +
      " (entry: " + JSON.stringify(view.entry) + ")");
  });
  await check("its mail is " + (refresh
    ? "the partner's (fedUpdateUserAttributes on)"
    : "still the SP realm's own (fedUpdateUserAttributes off)"),
  async function () {
    assert.deepStrictEqual((view.entry || {}).mail,
      [PERSON + "@" + (refresh ? IDP_MAIL : SP_MAIL)]);
  });
  log.debug("Leaving attributeRefresh().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Running the federation checks against " + base);
  const world = await setUp();
  await theRegister(world);
  const genuine = await oidcSignIn(world);
  await provisioning();
  await oidcRefusals(world, genuine);
  await samlFederation(world);
  await oidcCodeFlow(world);
  await attributeRefresh();

  log.info("The realms " + IDP + " and " + SP + " are left standing for " +
           "whoever reads this run (tests/CLAUDE.md, *No job removes a " +
           "realm*).");
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
  assert.ok(checks >= 60,
    "only " + checks + " checks ran. This file makes about seventy against " +
    "a healthy service, so a count this low means a SECTION STOPPED BEING " +
    "CALLED rather than that the feature got simpler.");
  log.info(checks + " checks passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
  return 0;
}

const program = new Command();
program
  .name("sts_federation_realms")
  .description("Federation over the network between two trust realms of " +
      "one service: an OpenID Connect and a SAML 2.0 federated sign-in from " +
      "an identity-provider realm into a service-provider realm, the " +
      "provisioning and attribute-refresh switches as configured, and the " +
      "refusals — a key the relationship does not name, alg none, HS256 " +
      "against RSA, a replay, a different service provider's assertion, a " +
      "disabled relationship and a partner nobody configured.")
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
