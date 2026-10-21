// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: sts_multi_account_tabs.js
//
// ===========================================================================
// ONE ACCOUNT PER TAB IN THE USER PORTAL, IN A REAL BROWSER (#561).
//
// With `authn.multipleAccounts` on, one browser may hold several signed-in
// accounts, and the portal keeps ONE OF THEM PER TAB: the tab's `{ sub,
// username }` in sessionStorage, sent as `login_hint` on every sign-in the
// runtime starts (`portal/CLAUDE.md`, *Several accounts in one browser*).
// `tests/multi_account_tabs.js` holds the runtime's half in process with a
// stand-in for every browser object — two runtime instances with two
// sessionStorage stand-ins are two tabs — and nothing there asks a BROWSER
// whether sessionStorage really is per tab, whether a reload really keeps
// it, or whether the cookie both tabs share really carries two accounts.
// This file asks Chrome, with two real tabs in one window, one cookie jar:
//
//   1. A DIFFERENT ACCOUNT IN EACH TAB: alice signs in to the portal in the
//      first tab; the second tab opens the portal's Sign in with another
//      account (`/portal?accounts=another`, prompt=login) and bob signs in
//      there. The first tab is still alice's, the second bob's.
//   2. A RELOAD KEEPS EACH TAB'S ACCOUNT: both tabs reloaded, each is drawn
//      for the account it had — the sign-in a reload starts names it, so the
//      shared cookie's default (bob, the last to sign in) does not decide.
//   2a. SWITCH USER AND BACK (#751): the first tab's account menu offers
//      bob and says the account it leaves stays signed in; pressing bob
//      draws the tab for bob with nothing typed, and pressing alice in the
//      same menu draws it for alice again — she stayed signed in.
//   3. SIGNING ONE ACCOUNT OUT FROM ONE TAB: the first tab's Sign out goes to
//      `/logout` with alice as its hint, the account step preselects her,
//      and her own sign-out ends her session. The second tab, reloaded, is
//      still bob's and draws a page from `/account-api`; the first, reloaded,
//      is at the sign-in screen — never silently bob's.
//   4. THE BROWSER LOGGED NOTHING SEVERE.
//
// IN A THROWAWAY REALM that inherits the process's mode, so the setting is
// on for this job alone and the portal's relying party is in the mode the
// stack runs (`sts_portal_device_webauthn.js` says why a realm whose mode
// differs is another test). The people have passwords and type them, so
// nothing here depends on development. The realm and the people are left
// in place to be read.
//
// ONE BROWSER, SERIALLY (*do not saturate with browser tests*): two tabs of
// one Chrome, which is what the feature is about.
//
// OWNED HERE (local: true): the portal and the sign-out are this
// repository's surfaces.
// ===========================================================================

"use strict";

const assert = require("assert");
const nodeCrypto = require("crypto");
const { Command, Option } = require("commander");
const { Builder, By } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const browserFlags = require("./browser_flags.js");
const names = require("./random_username.js");

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
var log = bunyan.createLogger({ name: "sts_multi_account_tabs",
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
const REALM = "mat-" + TAG;
const ALICE = names.usernameFor("mat-alice");
const BOB = names.usernameFor("mat-bob");
// A PASSWORD THIS FILE CHOSE, because product mode verifies the one it is
// given. Long and mixed so that no password policy refuses it.
const PASSWORD = "Mat-" + nodeCrypto.randomBytes(9).toString("base64url") +
  "-Aa1!";
const WAIT_MS = 20000;
// The fewest checks a full run makes.
const FLOOR = 13;

var screenshotDir = "";
var checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  ✓ " + what);
  log.debug("Leaving check().");
}

function realmUrl(path) {
  log.debug("Entering realmUrl().");
  log.debug("Leaving realmUrl().");
  return base + "/realm/" + REALM + path;
}

// ---------------------------------------------------------------------------
// THE DOOR THAT IS NOT THE BROWSER: `/admin-api` makes the realm and the
// people, and never a change this file then credits to a page. The
// launcher's preload (`tools/attach-admin-token.js`) puts the run's access
// token on every one of these.
// ---------------------------------------------------------------------------
async function apiPost(url, payload, what) {
  log.debug("Entering apiPost(). " + what);
  const r = await fetch(url, { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {}) });
  const text = await r.text();
  let body = null;
  try {
    body = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in apiPost(): " + ((e && e.message) || e));
    // Not JSON: reported whole below.
    body = null;
  }
  assert.ok(r.status === 200 && body && body.ok !== false,
            what + ": " + r.status + " " + text.slice(0, 300));
  log.debug("Leaving apiPost().");
  return body;
}

async function setUp() {
  log.debug("Entering setUp().");
  await apiPost(base + "/admin-api/realms/create",
                { id: REALM, domain: REALM + ".example.net",
                  name: "#561 one account per tab " + TAG },
                "created the realm " + REALM);
  const set = function (key, value) {
    log.debug("Entering set(). " + key);
    log.debug("Leaving set().");
    return apiPost(realmUrl("/admin-api/config/set"),
                   { key: key, value: value }, "set " + key);
  };
  // RISK SCORING (#62) is off for sts_admin_client_policies.js's reason.
  await set("risk.assessSignIns", false);
  await set("authn.multipleAccounts", true);
  await set("logout.anyUser", false);
  for (const who of [ALICE, BOB]) {
    await apiPost(realmUrl("/admin-api/users/create"), {
      username: who, invent: false, credential: "password",
      password: PASSWORD,
      attributes: { cn: "Tabs " + who, givenName: "Tabs", sn: who,
                    displayName: "Tabs " + who,
                    mail: who + "@tabs.example.test" } },
      "created " + who);
  }
  log.debug("Leaving setUp().");
}

// ---------------------------------------------------------------------------
// THE BROWSER.
// ---------------------------------------------------------------------------
// Waits for a condition; on a timeout says where the browser is, read only
// then (`sts_portal_device_webauthn.js`'s reason).
async function waitFor(driver, condition, what) {
  log.debug("Entering waitFor().");
  try {
    await driver.wait(async function () {
      try {
        return await condition();
      } catch (e) {
        log.debug("Caught in waitFor(): " + ((e && e.message) || e));
        // A page mid-navigation; the next poll asks again.
        return false;
      }
    }, WAIT_MS);
  } catch (e) {
    log.debug("Caught in waitFor(): " + ((e && e.message) || e));
    let where = "";
    try {
      where = " The browser is at " + await driver.getCurrentUrl() +
        ", reading: " + (await bodyText(driver)).slice(0, 500);
    } catch (inner) {
      log.debug("Caught in waitFor(): " + ((inner && inner.message) ||
                                            inner));
      // The page cannot be read either; the condition's own words stand.
      where = "";
    }
    log.debug("Leaving waitFor(). Timed out.");
    throw new Error(what + where);
  }
  log.debug("Leaving waitFor().");
}

async function present(driver, css) {
  log.debug("Entering present().");
  const found = await driver.findElements(By.css(css));
  log.debug("Leaving present().");
  return found.length > 0;
}

async function bodyText(driver) {
  log.debug("Entering bodyText().");
  const text = await driver.findElement(By.css("body")).getText();
  log.debug("Leaving bodyText().");
  return String(text);
}

async function path(driver) {
  log.debug("Entering path().");
  const p = new URL(await driver.getCurrentUrl()).pathname;
  log.debug("Leaving path().");
  return p;
}

// Who the portal page in this tab is drawn for: the header's "Signed in as"
// name, '' where no portal page is drawn.
async function portalWho(driver) {
  log.debug("Entering portalWho().");
  const found = await driver.findElements(By.css("p.who strong"));
  const who = found.length ? String(await found[0].getText()).trim() : "";
  log.debug("Leaving portalWho(). " + who);
  return who;
}

// Waits for this tab's portal page to be drawn for `who`, its column with
// it (the frame is drawn from `/account-api`).
async function drawnFor(driver, who, what) {
  log.debug("Entering drawnFor(). " + who);
  await waitFor(driver, async function () {
    return (await path(driver)).indexOf("/portal") >= 0 &&
      await present(driver, ".side nav") &&
      (await portalWho(driver)) === who;
  }, what);
  log.debug("Leaving drawnFor().");
}

// Signs in at the screen this tab is on, as the screen's own script sends
// it (`sts_portal_device_webauthn.js`'s signIn(), with its settling).
async function signInHere(driver, who) {
  log.debug("Entering signInHere(). " + who);
  await waitFor(driver, async function () {
    return (await path(driver)).indexOf("/authn/login") >= 0 &&
      await present(driver, "#username");
  }, "the tab was never shown the sign-in screen for " + who + ".");
  // THE SCREEN SETTLES FIRST: with usernameless sign-in on it may arm a
  // conditional passkey request and draw itself again; typing into the
  // first drawing would type into a page being replaced.
  const settleBy = Date.now() + 2000;
  for (;;) {
    const marker = await driver.executeScript(
      "var u = document.getElementById('username');" +
      "if (!u) { return 'navigating'; }" +
      "return /webauthn/.test(u.getAttribute('autocomplete') || '')" +
      " ? 'armed' : '0';")
      .catch(function (e) {
        // The page was being replaced as the script ran: not settled yet.
        log.debug("Caught in signInHere(): " + ((e && e.message) || e));
        return "navigating";
      });
    if (marker === "0" || Date.now() > settleBy) {
      break;
    }
    await new Promise(function (resolve) {
      setTimeout(resolve, 100);
    });
  }
  const name = await driver.findElement(By.css("input[name='username']"));
  await name.clear();
  await name.sendKeys(who);
  const secret = await driver.findElement(By.css("input[name='password']"));
  await secret.clear();
  await secret.sendKeys(PASSWORD);
  // Sign In, clicked: the page sends the act to /authn-api (#571).
  await (await driver.findElement(By.id("kc-login"))).click();
  await waitFor(driver, async function () {
    const p = await path(driver);
    return (p.indexOf("/portal") >= 0 && p.indexOf("/authn") < 0) ||
      await present(driver, "#mfa-setup-ignore");
  }, "signing in as " + who + " showed neither the portal nor a set-up " +
     "step.");
  // An offered second factor is ignored, as the portal jobs do.
  if (await present(driver, "#mfa-setup-ignore")) {
    await driver.findElement(By.id("mfa-setup-ignore")).click();
  }
  log.debug("Leaving signInHere().");
}

async function reload(driver) {
  log.debug("Entering reload().");
  await driver.navigate().refresh();
  log.debug("Leaving reload().");
}

async function theBrowserLogIsClean(driver) {
  log.debug("Entering theBrowserLogIsClean().");
  const entries = await driver.manage()
                              .logs()
                              .get("browser")
                              .catch(function (e) {
    // Not every driver serves the log.
    log.debug("Caught in theBrowserLogIsClean(): " + ((e && e.message) || e));
    return [];
  });
  const severe = entries.filter(function (entry) {
    return entry.level && entry.level.name === "SEVERE";
  }).map(function (entry) {
    return entry.message;
  }).filter(function (message) {
    // The browser's own favicon request; this service serves none.
    return message.indexOf("/favicon.ico") < 0;
  }).filter(function (message) {
    // A conditional passkey request answered with nobody choosing is
    // refused as the API's 400 (`sts_portal_device_webauthn.js`).
    return !(/\/authn-api\/pending\/[^/]+\/passkey\b/.test(message) &&
             /status of 400/.test(message));
  });
  check("the browser logged nothing severe — no policy violation, no " +
        "failed load", function () {
    assert.deepStrictEqual(severe, [],
      "THE BROWSER LOGGED " + severe.length + " SEVERE MESSAGE(S): " +
      severe.join(" | "));
  });
  log.debug("Leaving theBrowserLogIsClean().");
}

async function keepAPicture(driver, what) {
  log.debug("Entering keepAPicture().");
  if (!screenshotDir) {
    log.debug("Leaving keepAPicture(). No directory.");
    return;
  }
  try {
    const png = await driver.takeScreenshot();
    const file = require("path").join(screenshotDir,
      "sts_multi_account_tabs-" + what + ".png");
    require("fs").writeFileSync(file, png, "base64");
    log.info("Kept a picture of the page at " + file);
  } catch (e) {
    log.debug("Caught in keepAPicture(): " + ((e && e.message) || e));
    // The picture is for a person reading a failure; failing to take one
    // must not replace the failure being reported.
  }
  log.debug("Leaving keepAPicture().");
}

// ---------------------------------------------------------------------------
// THE SECTIONS.
// ---------------------------------------------------------------------------
async function aDifferentAccountInEachTab(driver) {
  log.debug("Entering aDifferentAccountInEachTab().");
  await driver.get(realmUrl("/portal"));
  await signInHere(driver, ALICE);
  await drawnFor(driver, ALICE, "the first tab was never drawn for " +
                 ALICE + ".");
  const first = await driver.getWindowHandle();
  check("the first tab signs in to the portal as alice", function () {
    assert.ok(first);
  });
  await driver.switchTo().newWindow("tab");
  const second = await driver.getWindowHandle();
  // SIGN IN WITH ANOTHER ACCOUNT, as every page's control starts it: the
  // portal's own authorization request with prompt=login.
  await driver.get(realmUrl("/portal?accounts=another"));
  await signInHere(driver, BOB);
  await drawnFor(driver, BOB, "the second tab was never drawn for " + BOB +
                 ".");
  check("the second tab, through Sign in with another account, is bob's",
        function () {
    assert.notStrictEqual(first, second);
  });
  await driver.switchTo().window(first);
  const stillAlice = await portalWho(driver);
  check("the first tab, drawn before bob signed in, still names alice",
        function () {
    assert.strictEqual(stillAlice, ALICE);
  });
  log.debug("Leaving aDifferentAccountInEachTab().");
  return { first: first, second: second };
}

async function aReloadKeepsEachTabsAccount(driver, tabs) {
  log.debug("Entering aReloadKeepsEachTabsAccount().");
  await driver.switchTo().window(tabs.first);
  await reload(driver);
  await drawnFor(driver, ALICE, "the first tab, reloaded, was not drawn " +
                 "for " + ALICE + " — the shared cookie's default is bob.");
  check("the first tab, reloaded, is alice's although bob signed in last",
        function () {
    assert.ok(true);
  });
  await driver.switchTo().window(tabs.second);
  await reload(driver);
  await drawnFor(driver, BOB, "the second tab, reloaded, was not drawn " +
                 "for " + BOB + ".");
  check("the second tab, reloaded, is bob's", function () {
    assert.ok(true);
  });
  log.debug("Leaving aReloadKeepsEachTabsAccount().");
}

// Opens this tab's account menu and presses the Switch user button for
// the one other account it offers (#751).
async function switchFromTheMenu(driver, who) {
  log.debug("Entering switchFromTheMenu(). " + who);
  await waitFor(driver, async function () {
    return present(driver, "details.usermenu > summary");
  }, "the portal drew no account menu.");
  const open = await driver.executeScript(
    "return !!document.querySelector('details.usermenu[open]');");
  if (!open) {
    await (await driver.findElement(By.css("details.usermenu > summary")))
      .click();
  }
  await waitFor(driver, async function () {
    return present(driver, "button[data-account-action='switch']");
  }, "the account menu offered no account to switch to " + who + ".");
  const offered = await driver.executeScript(
    "var p = document.querySelector('details.usermenu .usermenupanel');" +
    "return { text: p ? p.textContent : '', " +
    "kept: !!(p && p.querySelector('p.usermenunote:not(" +
    "[data-account-none])')), " +
    "buttons: p ? p.querySelectorAll(" +
    "\"button[data-account-action='switch']\").length : 0 };");
  await (await driver.findElement(
    By.css("button[data-account-action='switch']"))).click();
  log.debug("Leaving switchFromTheMenu().");
  return offered;
}

async function switchUserAndBack(driver, tabs) {
  log.debug("Entering switchUserAndBack().");
  await driver.switchTo().window(tabs.first);
  await drawnFor(driver, ALICE, "the first tab was not alice's before the " +
                 "switch.");
  const toBob = await switchFromTheMenu(driver, BOB);
  check("alice's menu offers bob alone, and says the account left stays " +
        "signed in", function () {
    assert.strictEqual(toBob.buttons, 1, JSON.stringify(toBob));
    assert.ok(toBob.text.indexOf(BOB) >= 0, toBob.text);
    assert.ok(toBob.kept, JSON.stringify(toBob));
  });
  await drawnFor(driver, BOB, "Switch user to " + BOB + " never drew the " +
                 "tab for him.");
  check("Switch user draws the tab for bob, with nothing typed",
        function () {
    assert.ok(true);
  });
  const toAlice = await switchFromTheMenu(driver, ALICE);
  await drawnFor(driver, ALICE, "Switch user back to " + ALICE + " never " +
                 "drew the tab for her — she should have stayed signed in.");
  check("switching back draws the tab for alice, who stayed signed in",
        function () {
    assert.ok(toAlice.text.indexOf(ALICE) >= 0, toAlice.text);
  });
  log.debug("Leaving switchUserAndBack().");
}

async function signingOneAccountOut(driver, tabs) {
  log.debug("Entering signingOneAccountOut().");
  await driver.switchTo().window(tabs.first);
  // THE HEADER'S SIGN OUT: the runtime sends the tab to /logout with the
  // tab's account as `login_hint`.
  await (await driver.findElement(
    By.css("form[action$='/portal/signout'] button"))).click();
  await waitFor(driver, async function () {
    return (await path(driver)).indexOf("/logout") >= 0 &&
      await present(driver, "form[data-sts-step='accounts']");
  }, "the first tab's Sign out never drew the sign-out's account step.");
  const preselected = await driver.executeScript(
    "var c = document.querySelector(" +
    "\"form[data-sts-step='accounts'] input[name='account']:checked\");" +
    "if (!c) { return ''; }" +
    "var l = c.closest('label'); return l ? l.textContent : '';");
  check("the sign-out asks which account, with alice — this tab's — " +
        "preselected", function () {
    assert.ok(String(preselected).indexOf(ALICE) >= 0, preselected);
  });
  await (await driver.findElement(
    By.css("form[data-sts-step='accounts'] button[type='submit']")))
    .click();
  await waitFor(driver, async function () {
    return present(driver, "button.global");
  }, "choosing alice never drew her sign-out page.");
  await (await driver.findElement(By.css("button.global"))).click();
  await waitFor(driver, async function () {
    return !(await present(driver, "button.global")) &&
      !(await present(driver, "form[data-sts-step='accounts']"));
  }, "alice's sign-out never finished.");
  check("alice signed out from the first tab", function () {
    assert.ok(true);
  });
  await driver.switchTo().window(tabs.second);
  await reload(driver);
  await drawnFor(driver, BOB, "after alice signed out in the other tab, " +
                 "the second tab was not drawn for " + BOB + ".");
  await driver.get(realmUrl("/portal/sign-ins"));
  await drawnFor(driver, BOB, "bob's tab could not draw another page.");
  check("the second tab is still bob's, and draws its pages", function () {
    assert.ok(true);
  });
  await driver.switchTo().window(tabs.first);
  await driver.get(realmUrl("/portal"));
  await waitFor(driver, async function () {
    return (await path(driver)).indexOf("/authn/login") >= 0 ||
      (await portalWho(driver)) !== "";
  }, "the first tab, after its account signed out, drew nothing.");
  const firstNow = await portalWho(driver);
  const firstPath = await path(driver);
  check("the first tab is at the sign-in screen again — never silently " +
        "bob's", function () {
    assert.strictEqual(firstNow, "", "the first tab drew the portal for " +
                       firstNow);
    assert.ok(firstPath.indexOf("/authn/login") >= 0, firstPath);
  });
  log.debug("Leaving signingOneAccountOut().");
}

// ---------------------------------------------------------------------------
// THE RUN.
// ---------------------------------------------------------------------------
async function test() {
  log.debug("Entering test().");
  log.info("One account per tab in the portal at " + base + ", realm " +
           REALM + ", as " + ALICE + " and " + BOB);
  await setUp();
  const options = new chrome.Options();
  options.addArguments("--headless=new", "--no-sandbox",
      "--disable-dev-shm-usage", "--window-size=1400,1200");
  browserFlags.addBrowserAccessFlags(options, base);
  const driver = await new Builder().forBrowser("chrome")
      .setChromeOptions(options).build();
  try {
    const tabs = await aDifferentAccountInEachTab(driver);
    await aReloadKeepsEachTabsAccount(driver, tabs);
    await switchUserAndBack(driver, tabs);
    await signingOneAccountOut(driver, tabs);
    await theBrowserLogIsClean(driver);
    assert.ok(checks >= FLOOR, "only " + checks + " checks ran; a SECTION " +
              "STOPPED BEING CALLED.");
    log.info(checks + " checks passed. The realm " + REALM + " and its " +
             "people are left in place to be read.");
    log.info("Test completed successfully.");
  } catch (e) {
    await keepAPicture(driver, "failure");
    throw e;
  } finally {
    await driver.quit();
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_multi_account_tabs")
  .description("#561: one account per tab in the user portal, in two real " +
      "Chrome tabs sharing one cookie jar: a different account in each, a " +
      "reload keeping each, and one signed out leaving the other working.")
  .addOption(new Option("-u, --url <url>", "base url of the STS under test")
      .default(base))
  .addOption(new Option("--screenshot-dir <dir>",
      "write a PNG of the page here if the run fails"))
  .parse(process.argv);
base = String(program.opts().url || base).replace(/\/+$/, "");
screenshotDir = program.opts().screenshotDir || "";

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
