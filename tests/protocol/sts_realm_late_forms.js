// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_realm_late_forms.js
//
// ===========================================================================
// FORMS DRAWN AFTER THE PAGE, IN A TRUST REALM, IN A BROWSER (#2098).
//
// `local: true`: this repository's console and portal, in Chrome, in a
// THROWAWAY REALM. A static surface drew a realm's prefix on its links and
// forms only when the page was drawn (`WebPage.realmLinks()`), so markup
// drawn later kept the default realm's path: in a realm the runtime did not
// claim the press, and the browser posted it natively to the DEFAULT realm,
// which refuses every non-GET. Since #2098 the safe renderer every draw goes
// through (`common/web_safe_dom.ts`) applies the prefix itself. This drives
// the two late draws the ticket names, where they are drawn:
//
//   1. the WS-Trust protection list (an application's Configuration ->
//      WS-Trust sub-tab, reached through the console's realm switcher): a
//      Message protection box ticked redraws its map's list
//      (`redrawList()`); every + and trash it draws posts into the realm,
//      the + pressed is claimed by the console (the list grows by a box, the
//      browser stays in the realm), and the map saved holds the ticked
//      expression, read back from the realm's /admin-api;
//   2. the delegate search (`/realm/<id>/portal/delegate`, signed in as a
//      person of the realm): its results' Choose forms post into the realm,
//      and Choose pressed names the delegate, read back from the page and
//      from the realm's /account-api answer the page draws.
//
// Each is also asked of the default realm's path: no form drawn in the realm
// names it.
//
// **A THROWAWAY REALM**, created here and removed by the runner once the job
// passes (`tests/CLAUDE.md`, *A passing job removes its realms*); the default
// realm's console account this job makes is deleted in a `finally`.
// ===========================================================================

const assert = require("assert");
const crypto = require("crypto");
const { Command, Option } = require("commander");
const { Builder, By } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const browserFlags = require("./browser_flags.js");
// What the console asks for after a Save — a recent sign-in (#2173), the
// write scope by a popup (#2189) — completed as an administrator would
// (#2196).
const consoleSteps = require("./console_steps.js");
// A password the person holds as their own (#2160).
const ownPassword = require("./own_password.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, the arrangement tests/vendored/wait_for.js has.
  appconfigProblem = e;
  appconfig = {};
}

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_realm_late_forms",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = Date.now().toString(36);
const REALM = "lateforms-" + STAMP;
const PREFIX = "/realm/" + REALM;
const USER = "late-forms-" + STAMP;
const PASSWORD = "Late-forms-Passw0rd!-" + STAMP;
const APP = "lf-" + STAMP;
const PERSON = "lfperson-" + STAMP;
const DELEGATE = "lfdelegate-" + STAMP;

const PRESSED_MS = 45000;
const PRESS_MARK = "__stsRealmLateFormsPress";

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

async function api(method, p, payload) {
  log.debug("Entering api(). " + method + " " + p);
  const reply = await fetch(base + p, {
    method: method,
    headers: payload === undefined ? {} :
      { "content-type": "application/json" },
    body: payload === undefined ? undefined : JSON.stringify(payload)
  });
  const raw = await reply.text();
  let json = null;
  try {
    json = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in api(): " + ((e && e.message) || e));
  }
  log.debug("Leaving api().");
  return { status: reply.status, raw: raw, json: json };
}

async function apiOk(method, p, payload) {
  log.debug("Entering apiOk(). " + method + " " + p);
  const r = await api(method, p, payload);
  assert.ok(r.status === 200 && !(r.json && r.json.ok === false),
            method + " " + p + " answered " + r.status + " " +
            r.raw.slice(0, 400));
  log.debug("Leaving apiOk().");
  return r;
}

// One member of an answer, wherever it sits in it.
function memberOf(node, name) {
  log.debug("Entering memberOf(). " + name);
  if (node && typeof node === "object") {
    if (!Array.isArray(node) &&
        Object.prototype.hasOwnProperty.call(node, name)) {
      log.debug("Leaving memberOf(). Found.");
      return node[name];
    }
    for (const key of Object.keys(node)) {
      const found = memberOf(node[key], name);
      if (found !== undefined) {
        log.debug("Leaving memberOf(). Found below.");
        return found;
      }
    }
  }
  log.debug("Leaving memberOf(). Absent.");
  return undefined;
}

async function evidence(driver) {
  log.debug("Entering evidence().");
  const shown = await driver.executeScript(`
    const strip = Array.from(document.querySelectorAll(
      '.flash, .err, .error, [role=alert]')).map(function (e) {
        return e.textContent.trim();
      }).filter(Boolean).join(' | ');
    return location.href + ' ' + strip.slice(0, 600) + ' BODY: ' +
           document.body.textContent.replace(/\\s+/g, ' ').slice(0, 600);
  `).catch(function (e) {
    log.debug("Caught in evidence(): " + ((e && e.message) || e));
    return "(the page could not be read)";
  });
  log.debug("Leaving evidence().");
  return String(shown);
}

// Waits until a script answers something truthy, and answers it.
async function until(driver, script, args, what, ms) {
  log.debug("Entering until(). " + what);
  let scriptError = "";
  const got = await driver.wait(async function () {
    const now = await driver.executeScript(script, ...(args || []))
      .catch(function (e) {
        // A document being replaced under the probe: asked again.
        log.debug("Caught in until(): " + ((e && e.message) || e));
        scriptError = String((e && e.message) || e).slice(0, 300);
        return null;
      });
    return now || false;
  }, ms || 20000, what).catch(async function (e) {
    log.debug("Caught in until(): " + ((e && e.message) || e));
    throw new Error(((e && e.message) || e) +
                    (scriptError ? ". The probe's last error: " +
                                   scriptError : "") +
                    ". The page: " + await evidence(driver));
  });
  log.debug("Leaving until().");
  return got;
}

async function waitForDrawn(driver) {
  log.debug("Entering waitForDrawn().");
  await until(driver, `
    if (document.readyState !== 'complete') { return ''; }
    const lede = document.querySelector('p.lede');
    if (lede && /^Signing in/.test(lede.textContent)) { return ''; }
    return document.querySelector('.pagehead') ? 'drawn' : '';
  `, [], "the console never drew the page");
  log.debug("Leaving waitForDrawn().");
}

// The sign-in screen: a username and a password, the authenticator-app
// offer passed over.
// Who the browser is signed in as, for a sign-in the console asks for again.
let signedInAs = "";

async function signInAt(driver, url, username) {
  log.debug("Entering signInAt(). " + url);
  signedInAs = username;
  await driver.get(url);
  await driver.wait(async function () {
    return (await driver.findElements(By.css("input[name='username']")))
      .length > 0;
  }, 15000, "the sign-in screen never drew its form at " + url);
  await (await driver.findElement(By.css("input[name='username']")))
    .sendKeys(username);
  await (await driver.findElement(By.css("input[name='password']")))
    .sendKeys(PASSWORD);
  await (await driver.findElement(By.id("kc-login"))).click();
  let clickedAt = 0;
  await driver.wait(async function () {
    const at = await driver.getCurrentUrl();
    if (at.indexOf("/authn/login") < 0 && at.indexOf("/authn/mfa-setup") < 0) {
      return true;
    }
    const ignore = await driver.findElements(By.id("mfa-setup-ignore"));
    if (ignore.length && Date.now() - clickedAt > 5000) {
      clickedAt = Date.now();
      await ignore[0].click().catch(function (e) {
        // A button the page redrew between the find and the click.
        log.debug("Caught in signInAt(): " + ((e && e.message) || e));
      });
    }
    return false;
  }, 20000, "signing in left the browser on the sign-in screen.");
  log.debug("Leaving signInAt().");
}

// THE STEPS AFTER A PRESS (#2196), completed by `console_steps.js`; set in
// test() once there is a driver.
let steps = null;

// Whether the press marked `arguments[1]` has been answered: a drawn frame
// that is not the marked one. Runs in the browser.
const FRAME_ANSWERED = `
  const frame = document.querySelector('.shell');
  if (document.readyState !== 'complete' || !frame) { return false; }
  if (frame[arguments[0]] === arguments[1]) { return false; }
  const lede = document.querySelector('p.lede');
  if (lede && /^Signing in/.test(lede.textContent)) { return false; }
  return !!document.querySelector('.pagehead');
`;

// THE PRESS IS SEEN TO BE ANSWERED: the console frame is marked, the button
// pressed in the same script, and the wait is for a drawn frame that is not
// the marked one (`sts_cert_sign_in_editors.js`'s arrangement).
//
// WHAT THE CONSOLE ASKS FOR FIRST (#2196) — a popup, a Continue, a sign-in
// again — is done in between as the person does it, and a page that left to
// sign in, which sent nothing, is pressed again.
async function pressAndWait(driver, find, args, what, pressedAgain) {
  log.debug("Entering pressAndWait(). " + what);
  const start = await steps.before();
  const token = STAMP + "-" + crypto.randomBytes(8).toString("hex");
  const pressed = await driver.executeScript(
    "const found = (function () { " + find + " }).apply(null, " +
    "arguments[2]);" +
    "if (!found || typeof found === 'string') {" +
    "  return found || 'nothing to press'; }" +
    "const frame = document.querySelector('.shell');" +
    "if (!frame) { return 'no console frame on ' + location.href; }" +
    "frame[arguments[0]] = arguments[1];" +
    "found.click(); return '';", PRESS_MARK, token, args || []);
  assert.strictEqual(pressed, "", what + ": " + pressed);
  const stepped = await steps.after(start, {
    settled: function () {
      return driver.executeScript(FRAME_ANSWERED, PRESS_MARK, token)
        .catch(function (e) {
          log.debug("Caught in pressAndWait(): " + ((e && e.message) || e));
          return false;
        });
    }
  });
  if (stepped.leftToSignIn && !pressedAgain) {
    await waitForDrawn(driver);
    log.info(what + " was not sent: the console signed in again on the " +
             "page. Pressed again.");
    await pressAndWait(driver, find, args, what, true);
    log.debug("Leaving pressAndWait(). Pressed again.");
    return;
  }
  await until(driver, FRAME_ANSWERED, [PRESS_MARK, token],
              what + " was pressed and its answer was never drawn",
              PRESSED_MS);
  log.debug("Leaving pressAndWait().");
}

// A page of the throwaway realm, through the shell's realm switcher, which
// draws it in place with the console's token.
async function openInRealm(driver, to) {
  log.debug("Entering openInRealm(). " + to);
  await driver.get(base + "/admin?realm=default");
  await waitForDrawn(driver);
  await pressAndWait(driver, `
    const f = document.querySelector('form.realmpick');
    if (!f) { return 'no realm switcher on ' + location.href; }
    const pick = f.querySelector('select[name=realm]');
    pick.value = arguments[0];
    if (pick.value !== arguments[0]) {
      return 'the switcher does not offer ' + arguments[0];
    }
    f.querySelector('input[name=to]').value = arguments[1];
    return f.querySelector('button');
  `, [REALM, to], "the switch to " + REALM + to);
  const at = await driver.getCurrentUrl();
  assert.ok(at.indexOf(PREFIX + "/admin") >= 0,
            "the switch to " + REALM + " left the browser at " + at);
  log.debug("Leaving openInRealm().");
}

// Every root-relative URL the forms and links under a selector name.
const URLS_UNDER = `
  const root = document.querySelector(arguments[0]);
  if (!root) { return null; }
  const out = [];
  root.querySelectorAll('[href], [action], [formaction]').forEach(
    function (el) {
      ['href', 'action', 'formaction'].forEach(function (name) {
        const v = el.getAttribute(name);
        if (v && v.charAt(0) === '/' && v.charAt(1) !== '/') {
          out.push(name + '=' + v);
        }
      });
    });
  return out;
`;

function allInRealm(urls) {
  log.debug("Entering allInRealm().");
  const outside = (urls || []).filter(function (one) {
    return one.split("=").slice(1).join("=").indexOf(PREFIX + "/") !== 0;
  });
  log.debug("Leaving allInRealm().");
  return outside;
}

// ---------------------------------------------------------------------------
// 1. THE WS-TRUST PROTECTION LIST.
// ---------------------------------------------------------------------------
async function theProtectionList(driver) {
  log.debug("Entering theProtectionList().");
  log.info("=== 1. the WS-Trust protection list, redrawn in " + REALM + " ===");
  await openInRealm(driver, "/admin/applications?application=" + APP);
  await driver.executeScript("location.hash = 'cfg-wstrust';");
  await until(driver,
              "return document.querySelectorAll('input.wsp-preset').length;",
              [], "the WS-Trust sub-tab never drew its protection boxes");
  await driver.executeScript(
    "const r = document.querySelector('#cfg-wstrust " +
    "input[name=\"view\"][value=\"advanced\"]'); if (r) { r.click(); }");
  // The first box not ticked, and its map's list before.
  const box = await driver.executeScript(`
    const b = Array.from(document.querySelectorAll('input.wsp-preset'))
      .filter(function (x) { return !x.checked; })[0];
    if (!b) { return null; }
    const map = b.getAttribute('data-wsp-map');
    return { map: map, part: b.getAttribute('data-wsp-part'),
             before: document.querySelectorAll('#fgc-' + map +
               ' .fg-item input').length };
  `);
  assert.ok(box && box.map, "no protection box to tick");
  const cell = "#fgc-" + box.map;
  const drawnUrls = await driver.executeScript(URLS_UNDER, cell);
  log.info("the page draw's URLs in " + cell + ": " +
           JSON.stringify(drawnUrls));
  await driver.executeScript(
    "document.querySelector('input.wsp-preset[data-wsp-map=\"' + " +
    "arguments[0] + '\"][data-wsp-part=\"' + arguments[1] + '\"]')" +
    ".click();", box.map, box.part);
  const after = await until(driver, `
    const n = document.querySelectorAll(arguments[0] + ' .fg-item input');
    return n.length > arguments[1] ? n.length : 0;
  `, [cell, box.before], "ticking " + box.map + "/" + box.part +
                         " never redrew its list");
  const redrawn = await driver.executeScript(URLS_UNDER, cell);
  check("1a. the list redrawn after the page draw: every + and trash " +
        "posts into " + PREFIX, function () {
          assert.ok(redrawn && redrawn.length >= 2, JSON.stringify(redrawn));
          assert.deepStrictEqual(allInRealm(redrawn), [],
                                 JSON.stringify(redrawn));
          assert.ok(redrawn.every(function (one) {
            return /^formaction=/.test(one);
          }), JSON.stringify(redrawn));
        });
  const ticked = await driver.executeScript(
    "return Array.from(document.querySelectorAll(arguments[0] + " +
    "' .fg-item input')).map(function (i) { return i.value; })", cell);
  // THE + PRESSED: claimed by the console, which posts it as an API call and
  // draws the list again with one more box; a native post would leave the
  // console for the default realm's refusal.
  await pressAndWait(driver, `
    return document.querySelector(arguments[0] + ' button.fg-grow') ||
           'no + in ' + arguments[0];
  `, [cell], "the redrawn list's +");
  const grown = await until(driver, `
    return document.querySelectorAll(arguments[0] + ' .fg-item input')
      .length;
  `, [cell], "the list was not drawn after the +");
  const at = await driver.getCurrentUrl();
  check("1b. the redrawn + pressed is claimed: the browser stays in " +
        PREFIX + " and the list grows by one box", function () {
          assert.ok(at.indexOf(PREFIX + "/admin/applications") >= 0, at);
          assert.strictEqual(grown, after + 1, String(grown) + " after " +
                             String(after));
        });
  const now = await driver.executeScript(URLS_UNDER, cell);
  check("1c. and the list it draws then is in the realm too", function () {
    assert.deepStrictEqual(allInRealm(now), [], JSON.stringify(now));
  });
  // The box the + added is filled (a save refuses an empty one).
  await driver.executeScript(`
    const boxes = document.querySelectorAll(arguments[0] + ' .fg-item input');
    const last = boxes[boxes.length - 1];
    last.value = arguments[1];
    last.dispatchEvent(new Event('input', { bubbles: true }));
  `, cell, "//wst:Lifetime");
  ticked.push("//wst:Lifetime");
  // SAVE (the grid's own button, as `sts_wstrust_xpath_builder.js` presses
  // it), and the realm's application holds what the box wrote.
  await pressAndWait(driver, `
    return document.querySelector('#cfg-wstrust form.appgrid ' +
      'button[type="submit"]:not(.default-submit):not([name])') ||
      'no Save in the WS-Trust form';
  `, [], "Save");
  const read = await apiOk("GET", PREFIX + "/admin-api/applications?" +
                           "application=" + encodeURIComponent(APP));
  const held = memberOf(read.json, box.map);
  const values = Array.isArray(held) ? held : (held ? [held] : []);
  check("1d. the realm's application holds the ticked expression in " +
        box.map, function () {
          ticked.filter(Boolean).forEach(function (one) {
            assert.ok(values.indexOf(one) >= 0, one + " not in " +
                      JSON.stringify(values));
          });
        });
  log.debug("Leaving theProtectionList().");
}

// ---------------------------------------------------------------------------
// 2. THE DELEGATE SEARCH.
// ---------------------------------------------------------------------------
async function theDelegateSearch(driver) {
  log.debug("Entering theDelegateSearch().");
  log.info("=== 2. the delegate search in " + REALM + "'s portal ===");
  await signInAt(driver, base + PREFIX + "/portal/delegate", PERSON);
  await until(driver,
              "return !!document.getElementById('delegate-search-q');", [],
              "the realm's delegate page never drew its search");
  const at = await driver.getCurrentUrl();
  check("2a. the portal is the realm's", function () {
    assert.ok(at.indexOf(PREFIX + "/portal/delegate") >= 0, at);
  });
  // Enter asks at once (`DelegateSearch.submitted()`).
  await driver.executeScript(`
    const box = document.getElementById('delegate-search-q');
    box.value = arguments[0];
    box.dispatchEvent(new Event('input', { bubbles: true }));
    const form = document.getElementById('delegate-search');
    form.requestSubmit ? form.requestSubmit()
      : form.dispatchEvent(new Event('submit', { cancelable: true }));
  `, DELEGATE);
  await until(driver, `
    const out = document.getElementById('delegate-search-results');
    return out && out.querySelector('form') ? true : false;
  `, [], "the search never drew a result to choose", 30000);
  const urls = await driver.executeScript(URLS_UNDER,
                                          "#delegate-search-results");
  check("2b. the search's results, drawn after the page: each Choose " +
        "posts to " + PREFIX + "/portal/delegate", function () {
          assert.ok(urls && urls.length >= 1, JSON.stringify(urls));
          assert.deepStrictEqual(allInRealm(urls), [], JSON.stringify(urls));
          assert.ok(urls.every(function (one) {
            return one === "action=" + PREFIX + "/portal/delegate";
          }), JSON.stringify(urls));
        });
  await driver.executeScript(`
    const out = document.getElementById('delegate-search-results');
    out.querySelector('form button[type=submit]').click();
  `);
  const named = await until(driver, `
    const text = document.body.textContent;
    return text.indexOf(arguments[0]) >= 0 &&
      !document.querySelector('#delegate-search-results form')
      ? location.href : '';
  `, [DELEGATE + ","], "Choose was pressed and the page never named " +
                        DELEGATE, 30000).catch(async function (e) {
    log.debug("Caught in theDelegateSearch(): " + ((e && e.message) || e));
    return "";
  });
  const view = await driver.executeScript(
    "return document.body.textContent.replace(/\\s+/g, ' ')");
  check("2c. Choose pressed is claimed by the portal and names the " +
        "delegate, in the realm", function () {
          assert.ok(named && named.indexOf(PREFIX + "/portal/delegate") >= 0,
                    "at " + named + "; the page: " + view.slice(0, 800));
          assert.ok(view.indexOf("uid=" + DELEGATE + ",") >= 0,
                    view.slice(0, 800));
        });
  log.debug("Leaving theDelegateSearch().");
}

async function setUp() {
  log.debug("Entering setUp().");
  await apiOk("POST", "/admin-api/realms/create", {
    id: REALM, domain: REALM + ".example.net",
    name: "Late-drawn forms test realm",
    description: "Created by tests/protocol/sts_realm_late_forms.js " +
                 "(#2098); the runner removes it once the job passes.",
    overrides: { "global.mode": "development" }
  });
  // THE PASSWORD IS THE PERSON'S OWN (#2160): typed by an administrator it
  // is temporary in product, so it is a temporary one, and the person
  // chooses PASSWORD (`own_password.js`). The realm's people are in a
  // development realm, where it is not temporary.
  const temporary = ownPassword.temporaryFor(PASSWORD);
  await apiOk("POST", "/admin-api/users/create", {
    username: USER, invent: false,
    attributes: { cn: USER, givenName: "Late", sn: "Forms",
                  mail: USER + "@late-forms.test" },
    credential: "password", password: temporary });
  await ownPassword.chooseOwn(base, USER, temporary, PASSWORD,
    function (who, value) {
      log.debug("Entering setPassword().");
      log.debug("Leaving setPassword().");
      return api("POST", "/admin-api/users/set-password",
                 { user: who, password: value });
    });
  await apiOk("POST", "/admin-api/rbac/grant",
              { username: USER, role: "write" });
  await apiOk("POST", PREFIX + "/admin-api/applications/create", {
    identifier: APP, protocols: ["wstrust"],
    fields: { wstrustAppliesTo: ["https://" + APP + ".example"] } });
  for (const who of [PERSON, DELEGATE]) {
    await apiOk("POST", PREFIX + "/admin-api/users/create", {
      username: who, invent: false,
      attributes: { cn: who, givenName: "Late", sn: "Forms",
                    mail: who + "@late-forms.test" },
      credential: "password", password: PASSWORD });
  }
  log.debug("Leaving setUp().");
}

async function test() {
  log.debug("Entering test().");
  log.info("forms drawn after the page, in a trust realm, at " + base +
           ", realm " + REALM);
  let failure = null;
  let driver = null;
  try {
    await setUp();
    const options = new chrome.Options();
    options.addArguments("--headless=new", "--no-sandbox",
        "--disable-dev-shm-usage", "--window-size=1400,1200");
    browserFlags.addBrowserAccessFlags(options, base);
    driver = await new Builder().forBrowser("chrome")
        .setChromeOptions(options).build();
    steps = consoleSteps.forDriver(driver, {
      credentials: function () {
        return { username: signedInAs, password: PASSWORD };
      },
      log: log
    });
    await signInAt(driver, base + "/admin?realm=default", USER);
    await waitForDrawn(driver);
    await theProtectionList(driver);
    await driver.manage().deleteAllCookies();
    await theDelegateSearch(driver);
  } catch (e) {
    log.debug("Caught in test(): " + ((e && e.message) || e));
    // Kept, and thrown once what this job added is taken away.
    failure = e;
  }
  if (driver) {
    await driver.quit().catch(function (e) {
      log.debug("Caught in test() quitting: " + ((e && e.message) || e));
    });
  }
  await api("POST", "/admin-api/users/delete", { user: USER });
  if (failure) {
    throw failure;
  }
  assert.ok(checks >= 7, "only " + checks + " checks ran; a section has " +
                                           "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_realm_late_forms")
  .description("Forms drawn after the page, in a trust realm (#2098).")
  .addOption(new Option("-u, --url <url>", "base url (this test reads it " +
                                           "from the environment)"))
  .parse(process.argv);

test().then(function () {
  process.exit(0);
}, function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
