// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: sts_language_chooser.js
//
// ---------------------------------------------------------------------------
// THE LANGUAGE CHOOSER, OVER HTTP, IN A REALM (#539, 2026-10-09).
//
// Written because a defect got past every in-process test: inside a realm the
// chooser's form posted to `/realm/X/realm/X/authn/language`, since
// `PageLocale.chooser()` put the realm prefix on its action and `app.js` puts
// it on every root-relative action again. Only the whole path — the page as a
// realm draws it, the action as the browser posts it — shows that. In a
// throwaway realm:
//
//   a. a sign-in screen asked for with `ui_locales=fr-CA` keeps it for the
//      page: since #571 the screen is a static page whose runtime draws it,
//      and its view answers the request's `ui_locales`, which the runtime
//      ranks first; its shell loads the surface's script with the realm's
//      prefix ONCE, and reflects no parameter the request merely added;
//   b. the runtime's chooser posts to the realm's `/authn/language` and
//      returns to the page's own address, each with the prefix once — what
//      the browser sends is posted here;
//   c. posting the chooser where the browser would answers a 303 to that
//      return path and sets `sts_lang`; the sign-in's shell then names the
//      chooser's Swedish to its runtime while its view still answers
//      `ui_locales` (fr-CA), which outranks it, and the realm's front door
//      reads Swedish;
//   d. a return path naming another host, or a scheme, comes back as `/` —
//      the realm's own, prefixed like every root-relative redirect;
//   e. a tag no catalog answers is refused with a 400, in English;
//   f. discovery's `ui_locales_supported` lists the offered locales.
// ---------------------------------------------------------------------------
"use strict";

// The sign-in screen over `/authn-api` (#571).
const authnSignin = require("./authn_signin");
const assert = require("assert");
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
var log = bunyan.createLogger({ name: "sts_language_chooser",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const REALM = ("lang-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                             .slice(0, 31);
const R = "/realm/" + REALM;
const realmApi = base + R + "/admin-api";
const REDIRECT = "https://rp.language.example/cb";

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
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
  return { status: r.status, body: body, raw: raw, headers: r.headers,
           location: r.headers.get("location") || "" };
}

async function ok(url, payload, what) {
  log.debug("Entering ok().");
  const r = await send(url, { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {}) });
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "POST " + url + " should have " + what + "; it answered " + r.status +
    " " + String(r.raw).slice(0, 400));
  log.debug("Leaving ok().");
  return r.body;
}

async function postChooser(action, lang, back, cookie) {
  log.debug("Entering postChooser().");
  const r = await send(base + action, { method: "POST",
    headers: Object.assign(
      { "Content-Type": "application/x-www-form-urlencoded" },
      cookie ? { Cookie: cookie } : {}),
    body: new URLSearchParams({ lang: lang, return: back }).toString() });
  log.debug("Leaving postChooser(). " + r.status);
  return r;
}

async function test() {
  log.debug("Entering test().");
  log.info("The language chooser at " + base + R);
  await ok(base + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "Language " + STAMP },
    "created the realm");
  // A REGISTERED client, so product mode — which refuses an unknown one
  // before any sign-in screen — draws the screen too.
  await ok(realmApi + "/config/set", { key: "oauth2.openRegistration",
                                       value: true },
           "opened dynamic registration in the realm");
  const registered = await send(base + R + "/oauth2/register", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ redirect_uris: [REDIRECT],
      grant_types: ["authorization_code"], response_types: ["code"],
      token_endpoint_auth_method: "client_secret_basic" }) });
  assert.strictEqual(registered.status, 201, registered.raw.slice(0, 300));
  const clientId = registered.body.client_id;

  log.info("=== a. ui_locales draws the sign-in screen in it ===");
  let r = await send(base + R + "/oauth2/authorize?" + new URLSearchParams({
    client_id: clientId, response_type: "code",
    redirect_uri: REDIRECT, scope: "openid", state: "s",
    ui_locales: "fr-CA" }).toString());
  assert.ok(r.status === 302 || r.status === 303,
            "the authorization request did not go to sign in: " + r.status);
  const login = new URL(r.location, base).toString();
  r = await send(login);
  const opened = await authnSignin.screen(base + R, login);
  check("the sign-in screen keeps fr-CA for its page: the view answers the " +
        "request's ui_locales, which the runtime ranks first (#571)",
        function () {
    assert.strictEqual(r.status, 200, String(r.raw).slice(0, 300));
    assert.ok(opened.json && opened.json.uiLocales === "fr-CA",
              JSON.stringify(opened.json).slice(0, 300));
  });
  check("and its shell loads the surface's script under the realm, prefixed " +
        "once", function () {
    assert.ok(r.raw.indexOf('<script src="' + R + '/authn/signin.js"') > 0 &&
              r.raw.indexOf(R + R) < 0, r.raw.slice(0, 600));
  });

  log.info("=== b. the chooser the runtime draws posts and returns once ===");
  // THE CHOOSER IS THE RUNTIME'S SINCE #571 (`common/web_i18n.ts`): its
  // action is `/authn/language` and its return the page's own address,
  // each put under the realm's prefix once by the runtime — what the
  // browser sends, posted here.
  const screenAt = new URL(login);
  const chooser = { action: R + "/authn/language",
                    back: screenAt.pathname + screenAt.search };
  check("the page's own address is the realm's, prefixed once", function () {
    assert.ok(chooser.back.indexOf(R + "/authn/login?") === 0 &&
              chooser.back.indexOf(R + R) < 0, chooser.back);
  });

  // NOTHING A REQUEST MERELY ADDS IS DRAWN BACK (the reflection the
  // integrator found on #539 phase 3): the shell a parameter of nobody's
  // choosing was added to does not carry it.
  r = await send(login + "&reflected=zz-" + STAMP);
  check("a parameter the request merely added is not drawn back",
        function () {
    assert.ok(r.status === 200 && r.raw.indexOf("zz-" + STAMP) < 0,
              r.raw.slice(0, 300));
  });

  log.info("=== c. choosing Swedish ===");
  r = await postChooser(chooser.action, "sv-SE", chooser.back);
  const cookie = String(r.headers.get("set-cookie") || "");
  check("the chooser answers 303 to the page and sets sts_lang", function () {
    assert.strictEqual(r.status, 303, r.status + " " + r.raw.slice(0, 200));
    assert.strictEqual(r.location, chooser.back);
    assert.ok(/(^|,\s*)sts_lang=sv-SE;/.test(cookie), cookie);
  });
  r = await send(base + r.location,
                 { headers: { Cookie: cookie.split(";")[0] } });
  const back = await authnSignin.screen(base + R, login,
                                        { cookie: cookie.split(";")[0] });
  check("the sign-in it returns to still honours its ui_locales, which " +
        "outranks the chooser", function () {
    assert.strictEqual(r.status, 200);
    // The shell names the chooser's Swedish to the runtime, and the view
    // still answers ui_locales, which ranks first for this sign-in: fr-CA.
    // A page reached without it — the front door, below — reads Swedish.
    assert.ok(/ data-sts-lang="sv-SE"/.test(r.raw), r.raw.slice(0, 300));
    assert.ok(back.json && back.json.uiLocales === "fr-CA",
              JSON.stringify(back.json).slice(0, 300));
  });
  r = await send(base + R + "/", { headers: { Cookie:
    cookie.split(";")[0] } });
  // The front door is a static surface since #579: its shell hands the
  // chooser's choice to the browser, which draws the page in it.
  check("a page with no ui_locales reads the chooser's Swedish", function () {
    assert.strictEqual(r.status, 200);
    assert.ok(/<html lang="en"[^>]* data-sts-lang="sv-SE"/.test(r.raw),
              r.raw.slice(0, 300));
  });

  log.info("=== d. the return is held to a local path ===");
  for (const bad of ["//evil.example/x", "https://evil.example/",
                     "/\\evil", "javascript:alert(1)"]) {
    r = await postChooser(chooser.action, "sv-SE", bad);
    // `/`, which `app.js` puts the realm's prefix on like every
    // root-relative redirect: the realm's own front door.
    check("a return of " + bad + " comes back as the realm's /", function () {
      assert.strictEqual(r.status, 303);
      assert.strictEqual(r.location, R + "/");
    });
  }

  log.info("=== e. an unanswered tag is refused ===");
  r = await postChooser(chooser.action, "de-CH", chooser.back);
  check("de-CH is refused with a 400, in English", function () {
    assert.strictEqual(r.status, 400);
    assert.ok(/not a language this service has a catalog for/
      .test(r.raw), r.raw.slice(0, 200));
  });

  log.info("=== f. discovery lists the offered locales ===");
  r = await send(base + R + "/.well-known/openid-configuration");
  check("ui_locales_supported lists fr-CA, zh-HK and sv-SE", function () {
    const listed = (r.body && r.body.ui_locales_supported) || [];
    ["en", "fr-CA", "zh-HK", "sv-SE"].forEach(function (tag) {
      assert.ok(listed.indexOf(tag) >= 0, JSON.stringify(listed));
    });
  });

  assert.ok(checks >= 13, "only " + checks + " checks ran; a section has " +
                                            "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_language_chooser")
  .description("The language chooser over HTTP, in a realm (#539).")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
