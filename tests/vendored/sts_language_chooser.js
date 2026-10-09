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
//   a. a sign-in screen asked for with `ui_locales=fr-CA` is drawn in it
//      (`lang="fr-CA"`), and carries the chooser;
//   b. the chooser's action is the realm's `/authn/language`, with the prefix
//      ONCE, and its return path is the page's own, with the prefix once;
//   c. posting the chooser where the browser would answers a 303 to that
//      return path and sets `sts_lang`; the sign-in, whose `ui_locales`
//      outranks the chooser, stays French, and the realm's front door then
//      reads Swedish;
//   d. a return path naming another host, or a scheme, comes back as `/` —
//      the realm's own, prefixed like every root-relative redirect;
//   e. a tag no catalog answers is refused with a 400, in English;
//   f. discovery's `ui_locales_supported` lists the offered locales.
// ---------------------------------------------------------------------------
"use strict";

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

// The chooser's form on a page: its action and its hidden return path.
function chooserOf(raw) {
  log.debug("Entering chooserOf().");
  const form = /<form class="language-chooser" method="post" action="([^"]*)">([\s\S]*?)<\/form>/
    .exec(raw);
  const back = form ? /name="return" value="([^"]*)"/.exec(form[2]) : null;
  log.debug("Leaving chooserOf().");
  return form ? { action: form[1].replace(/&amp;/g, "&"),
                  back: back ? back[1].replace(/&amp;/g, "&") : null }
              : null;
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
  const page = r.raw;
  check("the sign-in screen is drawn in fr-CA", function () {
    assert.strictEqual(r.status, 200, String(r.raw).slice(0, 300));
    assert.ok(/<html lang="fr-CA" dir="ltr">/.test(page),
              page.slice(0, 200));
  });
  const chooser = chooserOf(page);
  check("and it carries the language chooser", function () {
    assert.ok(chooser, "no chooser on the sign-in screen");
  });

  log.info("=== b. the action and the return carry the prefix ONCE ===");
  check("the chooser posts to the realm's /authn/language, prefixed once",
        function () {
    assert.strictEqual(chooser.action, R + "/authn/language",
                       "the action is " + chooser.action);
  });
  check("and returns to the page, prefixed once", function () {
    assert.ok(chooser.back.indexOf(R + "/authn/login?") === 0 &&
              chooser.back.indexOf(R + R) < 0, chooser.back);
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
  check("the sign-in it returns to still honours its ui_locales, which " +
        "outranks the chooser", function () {
    assert.strictEqual(r.status, 200);
    // ui_locales ranks first for this sign-in: fr-CA. A page reached without
    // it — the front door, below — reads the chooser's cookie.
    assert.ok(/<html lang="fr-CA"/.test(r.raw), r.raw.slice(0, 200));
  });
  r = await send(base + R + "/", { headers: { Cookie:
    cookie.split(";")[0] } });
  check("a page with no ui_locales reads the chooser's Swedish", function () {
    assert.strictEqual(r.status, 200);
    assert.ok(/<html lang="sv-SE"/.test(r.raw), r.raw.slice(0, 200));
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

  assert.ok(checks >= 12, "only " + checks + " checks ran; a section has " +
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
