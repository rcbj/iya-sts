// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_idp_initiated_wsfed.js
//
// ---------------------------------------------------------------------------
// WHO MAY START A WS-FEDERATION SIGN-IN, OVER THE WIRE (#715, after #426 and
// #712).
//
// `tests/wsfed_initiation.js` holds the same rules in process, in a child
// that starts its own service in DEVELOPMENT mode. Nothing there reaches a
// product-mode service or a second node, and that is what this job is for:
// the suite runs it in `memory` (development), `single-node` and `cluster`
// (both PRODUCT mode on postgres; `cluster` is several nodes behind one
// address). So it is written for product throughout — every relying party
// and the person are created through `/admin-api` with names unique to the
// run, every relying party has a REGISTERED `wsfedReplyUrl`, and the person
// has a real password, which product checks. In `cluster` consecutive
// requests may land on different nodes: the pending sign-in made on one is
// finished on another, and the session one node wrote is read for the
// response and for `/logout` by another. Nothing pins a node; that is the
// point.
//
// Everything happens in a throwaway trust realm the job creates and leaves
// standing, like every job of this shape. The realm takes the process's mode
// (no `global.mode` override), and the realm setting section e turns on is
// the realm's own, so no other job running beside this one sees it.
//
//   a. `/wsfed/initiate/{rp}` is REFUSED 403 (STS-WSFED-0025) for a
//      registered relying party with no override — the realm setting is off
//      by default; a relying party nobody registered is 404
//      (STS-WSFED-0024); an entry's wsfedIdpInitiatedSso FALSE refuses it.
//   b. with the entry's override TRUE, a `wreply` on the link is refused 400
//      (STS-WSFED-0026) and an EMPTY one too; a relying party with no
//      registered reply address is refused (STS-WSFED-0027).
//   c. with no session the link goes to the sign-in screen (in product, a
//      wrong password is refused there first); the screen comes back to the
//      link; the response is a form POST to the REGISTERED wsfedReplyUrl
//      with `wctx` byte for byte; and the person's sign-out inventory —
//      `GET /logout` asking for JSON, the one model of a live session
//      (`logout/CLAUDE.md`) — then lists the relying party under
//      `wsfed-rp` with a cleanup address at the registered reply URL. That
//      replaces the in-process file's read of the session object.
//   d. the `?wtrealm=` form answers at once on the live session.
//   e. the REALM setting `wsfed.idpInitiatedSso`, turned on through
//      `/admin-api/config/set`, opens the link for an entry with no
//      override, and an entry's FALSE still closes it; the setting is RESET
//      in a `finally`, and the link is closed again afterwards.
//   f. a wsignin1.0 to an entry with wsfedSpInitiatedSso FALSE is refused
//      403 (STS-WSFED-0028), one to an entry without it is answered, and the
//      identity-provider-initiated link still signs in to the relying party
//      whose own start is off.
//
// NOT HERE, AND WHY: the in-process file's section g, the step-up on RISK.
// A session's risk comes from scoring against datasets the suite does not
// load, so it cannot be set up over HTTP; `tests/wsfed_initiation.js` puts
// it on the session object and runs that section a second time in product
// mode instead (#715's scope). Risk scoring is turned OFF in this job's realm
// (`risk.assessSignIns`) for `sts_admin_client_policies.js`'s reason: this
// job's HTTP client is an automated one on a TLS stack the realm has never
// seen, which product's issuance policy answers by asking for a security
// key, and what is asserted here is who may start a sign-in.
//
// The refusals' codes are read back from the realm's `/admin-api/audit`. A
// REFUSAL's audit row is one the cluster barrier holds the response for
// (`cluster/CLAUDE.md`, rule 6), so another node's read sees it; the read is
// still polled briefly rather than trusted to be instant.
//
// INVENTED FIXTURES: the relying-party identifiers, the reply addresses (in
// the reserved `.example.test` name space; nothing listens there, and each
// is read off the form, never followed) and the person's attributes name
// nothing outside this job.
//
// OWNED HERE (local: true).
// ---------------------------------------------------------------------------

const assert = require("assert");
const nodeCrypto = require("crypto");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const registry = require("./sts_applications.js");
// The sign-in screen over `/authn-api` (#571).
const authnSignin = require("./authn_signin");

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
var log = bunyan.createLogger({ name: "sts_idp_initiated_wsfed",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug('CONFIG_FILE could not be read, so the configuration is empty: ' +
            appconfigProblem.message);
}
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");

const STAMP = names.runStamp();
const TAG = STAMP.toLowerCase().replace(/[^a-z0-9]/g, "").slice(0, 12);
const REALM = "wsi-" + TAG;
const PERSON = names.usernameFor("wsi-person");
// At least twelve characters, every class, and random per run: product holds
// a password to the realm's policy and checks it at the screen.
const PASSWORD = "Wsi-" + nodeCrypto.randomBytes(9).toString("base64url") +
  "-Aa1!";

const RP_PLAIN = "urn:wsi:" + TAG + ":plain";
const RP_OPEN = "urn:wsi:" + TAG + ":open";
const RP_NOREPLY = "urn:wsi:" + TAG + ":no-reply";
const RP_CLOSED = "urn:wsi:" + TAG + ":closed";
const RP_IDP_ONLY = "urn:wsi:" + TAG + ":idp-only";
const REPLY_PLAIN = "https://plain-" + TAG + ".wsi.example.test/wsfed";
const REPLY_OPEN = "https://open-" + TAG + ".wsi.example.test/wsfed";
const REPLY_CLOSED = "https://closed-" + TAG + ".wsi.example.test/wsfed";
const REPLY_IDP_ONLY = "https://idp-only-" + TAG + ".wsi.example.test/wsfed";
// A wctx with bytes a careless pass would change: a space, an ampersand, an
// equals sign, a percent sign and a non-ASCII letter — the in-process file's.
const WCTX = "rm=0&id=passive ru=%2Fhome é";

// Eighteen checks in every mode (three each in a, b, e and f, five in c,
// one in d) — a FLOOR rather than an exact count, because product adds c0.
const FLOOR = 18;

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function realmBase() {
  log.debug("Entering realmBase().");
  log.debug("Leaving realmBase().");
  return base + "/realm/" + REALM;
}

function realmPath(p) {
  log.debug("Entering realmPath().");
  log.debug("Leaving realmPath().");
  return "/realm/" + REALM + p;
}

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

async function call(method, url, body, headers) {
  log.debug("Entering call(). " + method + " " + url);
  const r = await fetch(url, { method: method, redirect: "manual",
    headers: Object.assign({ "Content-Type": "application/json",
                             Accept: "application/json" }, headers || {}),
    body: body === undefined ? undefined :
          (typeof body === "string" ? body : JSON.stringify(body)) });
  const text = await r.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in call(): " + ((e && e.message) || e));
    // Not JSON; `text` carries it into the message.
    json = null;
  }
  log.debug("Leaving call(). status=" + r.status);
  return { status: r.status, json: json, text: text,
           location: r.headers.get("location") || "" };
}

async function ok(url, body, what) {
  log.debug("Entering ok().");
  const r = await call("POST", url, body);
  assert.ok(r.status === 200 && r.json && r.json.ok !== false,
            what + ": " + r.status + " " + r.text.slice(0, 400));
  log.debug("Leaving ok().");
  return r.json;
}

async function setting(key, value) {
  log.debug("Entering setting(). " + key);
  log.debug("Leaving setting().");
  return ok(realmBase() + "/admin-api/config/set",
            { key: key, value: value }, "set " + key + " in " + REALM);
}

// How many of the realm's audit rows carry `code`.
async function codeCount(code) {
  log.debug("Entering codeCount(). " + code);
  const r = await call("GET", realmBase() +
                       "/admin-api/audit?per=500&code=" +
                       encodeURIComponent(code));
  const body = r.json && typeof r.json === "object" ? r.json : {};
  const rows = body.rows || body.events || [];
  log.debug("Leaving codeCount(). " + rows.length);
  return rows.length;
}

// Whether a row carrying `code` was added since `before` rows were counted,
// asked for up to five seconds.
async function recorded(code, before) {
  log.debug("Entering recorded(). " + code);
  let now = await codeCount(code);
  for (let i = 0; i < 20 && now <= before; i += 1) {
    await sleep(250);
    now = await codeCount(code);
  }
  log.debug("Leaving recorded(). " + before + " -> " + now);
  return now > before;
}

// One browser: a cookie jar and redirects left to the caller.
function browser() {
  log.debug("Entering browser().");
  const jar = {};
  const self = {
    jar: jar,
    async go(method, url) {
      log.debug("Entering go(). " + method + " " + url);
      const headers = {};
      const cookie = Object.keys(jar).map(function (k) {
        return k + "=" + jar[k];
      }).join("; ");
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
               text: text };
    }
  };
  log.debug("Leaving browser().");
  return self;
}

// The link, under the realm's prefix.
function link(rp, query) {
  log.debug("Entering link().");
  const q = new URLSearchParams(query || {}).toString();
  log.debug("Leaving link().");
  return realmPath("/wsfed/initiate/" + encodeURIComponent(rp) +
                   (q ? "?" + q : ""));
}

// The relying party's own wsignin1.0, to a registered reply address.
function signInUrl(rp, reply) {
  log.debug("Entering signInUrl().");
  log.debug("Leaving signInUrl().");
  return realmPath("/wsfed?" + new URLSearchParams({ wa: "wsignin1.0",
    wtrealm: rp, wreply: reply, wctx: "sp" }).toString());
}

// The section 13.2.2 form's action and wctx, decoded.
function unescapeHtml(s) {
  log.debug("Entering unescapeHtml().");
  log.debug("Leaving unescapeHtml().");
  return String(s).replace(/&quot;/g, '"').replace(/&#39;/g, "'")
    .replace(/&lt;/g, "<").replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&");
}

function formOf(r) {
  log.debug("Entering formOf().");
  const action = /<form method="post" action="([^"]*)"/.exec(r.text || "");
  const wctx = /<input type="hidden" name="wctx" value="([^"]*)"/
    .exec(r.text || "");
  log.debug("Leaving formOf().");
  return { action: action ? unescapeHtml(action[1]) : null,
           wctx: wctx ? unescapeHtml(wctx[1]) : null,
           wresult: /name="wresult"/.test(r.text || "") };
}

function pathOf(url) {
  log.debug("Entering pathOf().");
  log.debug("Leaving pathOf().");
  return String(url || "").replace(/^https?:\/\/[^/]+/, "");
}

async function createRelyingParty(identifier, fields) {
  log.debug("Entering createRelyingParty(). " + identifier);
  await ok(realmBase() + "/admin-api/applications/create",
           { identifier: identifier, name: identifier, protocols: ["wsfed"],
             fields: Object.assign({ wsfedRealm: [identifier] }, fields) },
           "created the relying party " + identifier);
  log.debug("Leaving createRelyingParty().");
}

async function setUp() {
  log.debug("Entering setUp().");
  log.info("=== 0. the throwaway realm " + REALM + " ===");
  await ok(base + "/admin-api/realms/create",
           { id: REALM, domain: REALM + ".example.net",
             name: "#715 WS-Federation initiation" },
           "created the realm");
  await setting("risk.assessSignIns", false);
  await registry.ensurePerson(realmBase(), PERSON, PASSWORD);
  await createRelyingParty(RP_PLAIN, { wsfedReplyUrl: [REPLY_PLAIN] });
  await createRelyingParty(RP_OPEN, { wsfedReplyUrl: [REPLY_OPEN],
                                      wsfedIdpInitiatedSso: "TRUE" });
  await createRelyingParty(RP_NOREPLY, { wsfedIdpInitiatedSso: "TRUE" });
  await createRelyingParty(RP_CLOSED, { wsfedReplyUrl: [REPLY_CLOSED],
                                        wsfedIdpInitiatedSso: "FALSE" });
  await createRelyingParty(RP_IDP_ONLY, { wsfedReplyUrl: [REPLY_IDP_ONLY],
                                          wsfedIdpInitiatedSso: "TRUE",
                                          wsfedSpInitiatedSso: "FALSE" });
  const product = await registry.isProduct(realmBase());
  log.info(REALM + " is in " + (product ? "PRODUCT" : "DEVELOPMENT") +
           " mode.");
  log.debug("Leaving setUp().");
  return product;
}

// --- a. off by default, and registered only --------------------------------
async function sectionA() {
  log.debug("Entering sectionA().");
  log.info("=== a. off by default, and registered only ===");
  const anon = browser();
  let before = await codeCount("STS-WSFED-0025");
  let r = await anon.go("GET", link(RP_PLAIN));
  const offRecorded = await recorded("STS-WSFED-0025", before);
  check("a1. the link is REFUSED 403 for a registered relying party with no " +
        "override: wsfed.idpInitiatedSso is off by default (STS-WSFED-0025)",
        function () {
    assert.strictEqual(r.status, 403, r.text.slice(0, 300));
    assert.ok(offRecorded, "no audit row carries STS-WSFED-0025");
  });
  before = await codeCount("STS-WSFED-0024");
  r = await anon.go("GET", link("urn:wsi:" + TAG + ":nobody"));
  const unknownRecorded = await recorded("STS-WSFED-0024", before);
  check("a2. a relying party nobody registered is 404 (STS-WSFED-0024)",
        function () {
    assert.strictEqual(r.status, 404, r.text.slice(0, 300));
    assert.ok(unknownRecorded, "no audit row carries STS-WSFED-0024");
  });
  r = await anon.go("GET", link(RP_CLOSED));
  check("a3. an entry's wsfedIdpInitiatedSso FALSE refuses it too",
        function () {
    assert.strictEqual(r.status, 403, r.text.slice(0, 300));
  });
  log.debug("Leaving sectionA().");
}

// --- b. the wreply and the registered reply address ------------------------
async function sectionB() {
  log.debug("Entering sectionB().");
  log.info("=== b. the wreply and the registered reply address ===");
  const anon = browser();
  let before = await codeCount("STS-WSFED-0026");
  let r = await anon.go("GET", link(RP_OPEN,
    { wreply: "https://evil-" + TAG + ".example.test/wsfed" }));
  const wreplyRecorded = await recorded("STS-WSFED-0026", before);
  check("b1. with wsfedIdpInitiatedSso TRUE, a wreply on the link is " +
        "REFUSED 400 (STS-WSFED-0026), not followed", function () {
    assert.strictEqual(r.status, 400, r.text.slice(0, 300));
    assert.ok(r.text.indexOf("evil-" + TAG) < 0,
              "the refusal page names the address it was handed");
    assert.ok(!r.location, "a refusal redirected: " + r.location);
    assert.ok(wreplyRecorded, "no audit row carries STS-WSFED-0026");
  });
  r = await anon.go("GET", link(RP_OPEN, { wreply: "" }));
  check("b2. an EMPTY wreply is refused too — the parameter, not its value",
        function () {
    assert.strictEqual(r.status, 400, r.text.slice(0, 300));
  });
  before = await codeCount("STS-WSFED-0027");
  r = await anon.go("GET", link(RP_NOREPLY));
  const noReplyRecorded = await recorded("STS-WSFED-0027", before);
  check("b3. a relying party with no registered wsfedReplyUrl is refused " +
        "(STS-WSFED-0027)", function () {
    assert.strictEqual(r.status, 400, r.text.slice(0, 300));
    assert.ok(noReplyRecorded, "no audit row carries STS-WSFED-0027");
  });
  log.debug("Leaving sectionB().");
}

// --- c. the sign-in, the response, and the sign-out inventory --------------
async function sectionC(product) {
  log.debug("Entering sectionC().");
  log.info("=== c. the sign-in, and the response to the registered " +
           "address ===");
  if (product) {
    // PRODUCT CHECKS PASSWORDS: a wrong one at the screen the link sends a
    // person to is refused, and nobody is sent back to the link. In its own
    // browser, so the pending sign-in below is untouched by it.
    const wrong = browser();
    const started = await wrong.go("GET", link(RP_OPEN, { wctx: "wrong" }));
    const refused = await authnSignin.signInWithJar(realmBase(),
      new URL(started.location, base).toString(),
      { action: "login", username: PERSON, password: PASSWORD + "-not" },
      wrong.jar);
    check("c0. (product) a wrong password at the screen the link sends a " +
          "person to is refused, and nothing goes back to the link",
          function () {
      assert.strictEqual(started.status, 303, "the link answered " +
                         started.status);
      assert.notStrictEqual(refused.answer.next, "redirect",
                            JSON.stringify(refused.answer.json)
                              .slice(0, 300));
      assert.ok(pathOf(refused.location).indexOf("/wsfed/initiate/") < 0,
                "sent back to " + refused.location);
    });
  }
  const person = browser();
  const first = await person.go("GET", link(RP_OPEN, { wctx: WCTX }));
  check("c1. with no session the link goes to the sign-in screen (303)",
        function () {
    assert.strictEqual(first.status, 303, first.text.slice(0, 300));
    assert.ok(/\/authn\/login\?authn=/.test(first.location), first.location);
  });
  const signedIn = await authnSignin.signInWithJar(realmBase(),
    new URL(first.location, base).toString(),
    { action: "login", username: PERSON, password: PASSWORD }, person.jar,
    { ignoreOffer: true });
  const back = pathOf(signedIn.location);
  check("c2. the sign-in returns to the link itself", function () {
    assert.strictEqual(signedIn.status, 303,
                       signedIn.status + " " + signedIn.text.slice(0, 300));
    assert.strictEqual(back.indexOf(realmPath("/wsfed/initiate/" +
                                              encodeURIComponent(RP_OPEN))),
                       0, back);
  });
  const answered = await person.go("GET", back);
  const form = formOf(answered);
  check("c3. the sign-in response is a form POST to the REGISTERED " +
        "wsfedReplyUrl", function () {
    assert.strictEqual(answered.status, 200, answered.text.slice(0, 300));
    assert.ok(form.wresult, "no wresult on the form");
    assert.strictEqual(form.action, REPLY_OPEN);
  });
  check("c4. wctx comes back byte for byte", function () {
    assert.strictEqual(form.wctx, WCTX);
  });
  const inventory = await person.go("GET", realmPath("/logout?format=json"));
  let held = null;
  try {
    held = JSON.parse(inventory.text);
  } catch (e) {
    log.debug("Caught in sectionC(): " + ((e && e.message) || e));
    // Not JSON; the check below quotes what came instead.
    held = null;
  }
  const family = ((held && held.families) || []).filter(function (one) {
    return one.id === "wsfed-rp";
  })[0];
  const rows = (family && family.rows) || [];
  check("c5. the person's sign-out inventory (GET /logout, JSON) lists the " +
        "relying party, its cleanup going to the registered reply URL",
        function () {
    assert.strictEqual(inventory.status, 200, inventory.text.slice(0, 300));
    assert.ok(rows.some(function (row) {
      return row.label === RP_OPEN &&
        String(row.detail || "").indexOf(REPLY_OPEN) >= 0;
    }), JSON.stringify(family || held || inventory.text).slice(0, 600));
  });
  log.debug("Leaving sectionC().");
  return person;
}

// --- d. the ?wtrealm= form, on a session that exists -----------------------
async function sectionD(person) {
  log.debug("Entering sectionD().");
  log.info("=== d. the ?wtrealm= form ===");
  const r = await person.go("GET", realmPath("/wsfed/initiate?" +
    new URLSearchParams({ wtrealm: RP_OPEN, wctx: "second" }).toString()));
  const form = formOf(r);
  check("d1. /wsfed/initiate?wtrealm= answers at once on a live session, " +
        "to the same registered address", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.strictEqual(form.action, REPLY_OPEN);
    assert.strictEqual(form.wctx, "second");
  });
  log.debug("Leaving sectionD().");
}

// --- e. the realm switch, and an entry's override over it ------------------
async function sectionE(person) {
  log.debug("Entering sectionE().");
  log.info("=== e. the realm setting wsfed.idpInitiatedSso ===");
  try {
    await setting("wsfed.idpInitiatedSso", true);
    let r = await person.go("GET", link(RP_PLAIN));
    const form = formOf(r);
    check("e1. wsfed.idpInitiatedSso on opens the link for an entry with no " +
          "override", function () {
      assert.strictEqual(r.status, 200, r.text.slice(0, 300));
      assert.strictEqual(form.action, REPLY_PLAIN);
    });
    r = await person.go("GET", link(RP_CLOSED));
    check("e2. and an entry's wsfedIdpInitiatedSso FALSE still closes it",
          function () {
      assert.strictEqual(r.status, 403, r.text.slice(0, 300));
    });
  } finally {
    // RESTORED whatever happened above: the realm is left standing, and a
    // re-drive with RANDOM_USERNAME_STAMP meets it again.
    await ok(realmBase() + "/admin-api/config/reset",
             { key: "wsfed.idpInitiatedSso" },
             "reset wsfed.idpInitiatedSso in " + REALM);
  }
  const after = await person.go("GET", link(RP_PLAIN));
  check("e3. reset, the setting is off again and the link is refused",
        function () {
    assert.strictEqual(after.status, 403, after.text.slice(0, 300));
  });
  log.debug("Leaving sectionE().");
}

// --- f. the relying party's own wsignin1.0 ---------------------------------
async function sectionF(person) {
  log.debug("Entering sectionF().");
  log.info("=== f. the relying party's own wsignin1.0 ===");
  const before = await codeCount("STS-WSFED-0028");
  let r = await person.go("GET", signInUrl(RP_IDP_ONLY, REPLY_IDP_ONLY));
  const spOffRecorded = await recorded("STS-WSFED-0028", before);
  check("f1. a wsignin1.0 for an entry with wsfedSpInitiatedSso FALSE is " +
        "refused 403 (STS-WSFED-0028)", function () {
    assert.strictEqual(r.status, 403, r.text.slice(0, 300));
    assert.ok(spOffRecorded, "no audit row carries STS-WSFED-0028");
  });
  r = await person.go("GET", signInUrl(RP_PLAIN, REPLY_PLAIN));
  let form = formOf(r);
  check("f2. one for an entry without it is answered (on by default)",
        function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.strictEqual(form.action, REPLY_PLAIN);
  });
  r = await person.go("GET", link(RP_IDP_ONLY));
  form = formOf(r);
  check("f3. and the identity-provider-initiated link still signs in to " +
        "the relying party whose own start is off", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.strictEqual(form.action, REPLY_IDP_ONLY);
  });
  log.debug("Leaving sectionF().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving identity-provider-initiated WS-Federation at " + base);
  const product = await setUp();
  await sectionA();
  await sectionB();
  const person = await sectionC(product);
  await sectionD(person);
  await sectionE(person);
  await sectionF(person);
  // A FLOOR ON THE COUNT, for the reason sts_admin_console.js gives: a
  // section that stops being called takes its assertions with it.
  assert.ok(checks >= FLOOR, "only " + checks + " checks ran; a section has " +
            "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_idp_initiated_wsfed")
  .description("#715: identity-provider-initiated WS-Federation sign-in " +
    "(/wsfed/initiate) over the wire, in a throwaway realm in the run's " +
    "mode: off by default, registered relying parties only, no wreply, the " +
    "registered reply address with wctx intact, the sign-out inventory, " +
    "the realm setting and the entry overrides, and wsignin1.0 under " +
    "wsfedSpInitiatedSso.")
  .addOption(new Option("-u, --url <url>", "base url of the STS under test")
      .default(base))
  .parse(process.argv);
base = String(program.opts().url || base).replace(/\/+$/, "");

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
