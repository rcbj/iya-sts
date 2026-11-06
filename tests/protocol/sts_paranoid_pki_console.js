// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_paranoid_pki_console.js
//
// ===========================================================================
// /admin/pki/trust, DRAWN BY THE CONSOLE'S OWN RUNTIME (#1360).
//
// `local: true`: this repository's console, in a browser. The four tabs; the
// signer truststore's Add through the page's form with a CA this job mints, its
// row drawn, a leaf refused by name, and Remove through the row's button; the
// inventory's empty state and Recheck; and `pki.pins.audit` run through
// `/admin-api/scheduler` and writing what the page draws.
//
// **THE DEFAULT REALM, WITH WHAT THIS JOB ADDS REMOVED IN A `finally`.** A realm's
// console is reached through the switcher, which is `sts_xacml_editor.js`'s
// business; the store is per realm, so nothing here reaches another job's realm,
// and only this job's own CA is asserted against.
// ===========================================================================

const assert = require("assert");
const { Command, Option } = require("commander");
const { Builder, By } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const browserFlags = require("./browser_flags.js");
const credentials = require("../tools/pep-credential.js");

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
var log = bunyan.createLogger({ name: "sts_paranoid_pki_console",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = Date.now().toString(36);
const USER = "paranoid-console-" + STAMP;
const PASSWORD = "Paranoid-console-Passw0rd!-" + STAMP;
const PAGE = "/admin/pki/trust";

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

async function api(method, path, payload) {
  log.debug("Entering api(). " + method + " " + path);
  const reply = await fetch(base + path, {
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

async function waitForDrawn(driver) {
  log.debug("Entering waitForDrawn().");
  await driver.wait(async function () {
    const now = await driver.executeScript(`
      if (document.readyState !== 'complete') { return ''; }
      const lede = document.querySelector('p.lede');
      if (lede && /^Signing in/.test(lede.textContent)) { return ''; }
      return document.querySelector('.pagehead') ? 'drawn' : '';
    `).catch(function (e) {
      // A document torn down under the probe: asked again.
      log.debug("Caught in waitForDrawn(): " + ((e && e.message) || e));
      return "";
    });
    return now || false;
  }, 20000, "the console never drew the page");
  log.debug("Leaving waitForDrawn().");
}

async function signIn(driver) {
  log.debug("Entering signIn().");
  await driver.get(base + "/admin?realm=default");
  await driver.wait(async function () {
    return (await driver.findElements(By.css("input[name='username']")))
      .length > 0;
  }, 15000, "the sign-in screen never drew its form.");
  await (await driver.findElement(By.css("input[name='username']")))
    .sendKeys(USER);
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
        log.debug("Caught in signIn(): " + ((e && e.message) || e));
      });
    }
    return false;
  }, 20000, "signing in left the browser on the sign-in screen.");
  await waitForDrawn(driver);
  log.debug("Leaving signIn().");
}

// The text of one tab, opened: a hidden panel is not in innerText.
async function tabText(driver, tab) {
  log.debug("Entering tabText(). " + tab);
  const url = base + PAGE + "#pki-trust-tab-" + tab;
  await driver.get("about:blank");
  await driver.get(url);
  await waitForDrawn(driver);
  const text = await driver.executeScript(
    "const panel = document.getElementById('pki-trust-tab-" + tab + "');" +
    "return panel ? panel.innerText : '';");
  log.debug("Leaving tabText().");
  return String(text);
}

// Submits the form on the open tab that holds this field.
async function submitFormHolding(driver, tab, selector, fields) {
  log.debug("Entering submitFormHolding(). " + selector);
  await driver.wait(async function () {
    return (await driver.findElements(
      By.css("#pki-trust-tab-" + tab + " " + selector))).length > 0;
  }, 15000, "no form holding " + selector);
  const field = await driver.findElement(
    By.css("#pki-trust-tab-" + tab + " " + selector));
  const form = await field.findElement(By.xpath("ancestor::form"));
  for (const name of Object.keys(fields || {})) {
    await driver.executeScript(
      "arguments[0].querySelector('[name=\"" + name + "\"]').value = " +
      "arguments[1];", form, fields[name]);
  }
  const before = await driver.getCurrentUrl();
  await (await form.findElement(By.css("button[type='submit']"))).click();
  await driver.sleep(1500);
  await waitForDrawn(driver);
  log.debug("Leaving submitFormHolding(). From " + before);
}

async function test() {
  log.debug("Entering test().");
  log.info("/admin/pki/trust at " + base);
  const created = await api("POST", "/admin-api/users/create", {
    username: USER, invent: false,
    attributes: { cn: USER, givenName: "Paranoid", sn: "Console",
                  mail: USER + "@paranoid.test" },
    credential: "password", password: PASSWORD });
  assert.ok(created.status === 200, created.raw.slice(0, 300));
  const granted = await api("POST", "/admin-api/rbac/grant",
                            { username: USER, role: "write" });
  assert.strictEqual(granted.status, 200, granted.raw.slice(0, 300));
  const minted = await credentials.mint({ crlBase: "",
    rootSubject: "CN=paranoid console " + STAMP + ",O=iya-sts tests",
    subject: "CN=paranoid-console-leaf-" + STAMP + ",O=iya-sts tests" });
  const commonName = "paranoid console " + STAMP;
  const leafName = "paranoid-console-leaf-" + STAMP;

  const options = new chrome.Options();
  options.addArguments("--headless=new", "--no-sandbox",
      "--disable-dev-shm-usage", "--window-size=1400,1200");
  browserFlags.addBrowserAccessFlags(options, base);
  const driver = await new Builder().forBrowser("chrome")
      .setChromeOptions(options).build();
  try {
    await signIn(driver);

    log.info("=== a. the four tabs ===");
    const paranoid = await tabText(driver, "paranoid");
    const signers = await tabText(driver, "signers");
    const pins = await tabText(driver, "pins");
    const client = await tabText(driver, "client");
    check("Paranoid PKI draws the master and every use case", function () {
      assert.ok(/auto/.test(paranoid), paranoid.slice(0, 300));
      ["tls-client", "saml-signer", "fido-mds"].forEach(function (id) {
        assert.ok(paranoid.indexOf(id) >= 0, id);
      });
    });
    check("the signer truststore tab draws its add form", function () {
      assert.ok(signers.length > 50, signers.slice(0, 200));
    });
    check("the inventory tab draws its table", function () {
      assert.ok(pins.length > 50, pins.slice(0, 200));
    });
    check("the client truststore tab says what it is", function () {
      assert.ok(client.length > 20, client);
    });
    const link = await driver.executeScript(
      "const a = document.querySelector(" +
      "'#pki-trust-tab-client a[href$=\"/admin/tls/trust\"]');" +
      "return a ? a.getAttribute('href') : '';");
    check("and the link is that page", function () {
      assert.ok(/\/admin\/tls\/trust$/.test(String(link)), String(link));
    });

    log.info("=== b. add and remove through the page ===");
    await tabText(driver, "signers");
    await submitFormHolding(driver, "signers", "textarea[name='certificates']",
                            { certificates: minted.anchorPem });
    const afterAdd = await tabText(driver, "signers");
    check("Add draws the CA in the table", function () {
      assert.ok(afterAdd.indexOf(commonName) >= 0, afterAdd.slice(0, 500));
    });
    const held = await api("GET", "/admin-api/pki/trust");
    const row = held.json.truststore.entries.filter(function (entry) {
      return entry.subject.indexOf(commonName) >= 0;
    })[0];
    check("and the API reads the same row, an anchor from this door",
          function () {
      assert.ok(row, held.raw.slice(0, 400));
      assert.strictEqual(row.kind, "anchor");
      assert.strictEqual(row.source, "runtime");
      assert.strictEqual(row.addedBy, USER);
    });
    await tabText(driver, "signers");
    await submitFormHolding(driver, "signers", "textarea[name='certificates']",
                            { certificates: minted.certPem });
    const leafRefused = await driver.executeScript(
      "return document.body.innerText;");
    check("a leaf is refused by name, and is not in the table", function () {
      assert.ok(/is a leaf/.test(String(leafRefused)),
                String(leafRefused).slice(0, 500));
    });
    const after = await api("GET", "/admin-api/pki/trust");
    check("the API agrees", function () {
      assert.ok(!after.json.truststore.entries.some(function (entry) {
        return entry.subject.indexOf(leafName) >= 0;
      }));
    });
    await tabText(driver, "signers");
    await submitFormHolding(driver, "signers",
      "input[name='fingerprint'][value='" + row.fingerprint256 + "']");
    const afterRemove = await api("GET", "/admin-api/pki/trust");
    check("Remove takes the row away", function () {
      assert.ok(!afterRemove.json.truststore.entries.some(function (entry) {
        return entry.fingerprint256 === row.fingerprint256;
      }));
    });

    log.info("=== c. the inventory and the job ===");
    await tabText(driver, "pins");
    await submitFormHolding(driver, "pins", "input[value='recheck']");
    const rechecked = await api("GET", "/admin-api/pki/trust");
    check("Recheck writes what the page draws", function () {
      assert.ok(rechecked.json.assessedAt > 0, rechecked.raw.slice(0, 300));
    });
    const queued = await api("POST", "/admin-api/scheduler/run",
                             { job: "pki.pins.audit", realm: "default" });
    check("pki.pins.audit is queued by hand", function () {
      assert.strictEqual(queued.status, 202, queued.raw.slice(0, 300));
      assert.ok(queued.json.runId, queued.raw.slice(0, 300));
    });
    let state = "";
    for (let i = 0; i < 60 && state !== "succeeded" && state !== "failed";
         i++) {
      const seen = await api("GET", "/admin-api/scheduler?run=" +
                                    encodeURIComponent(queued.json.runId));
      state = seen.json && seen.json.detail && seen.json.detail.state || "";
      if (state !== "succeeded" && state !== "failed") {
        await new Promise(function (resolve) {
          setTimeout(resolve, 1000);
        });
      }
    }
    const afterJob = await api("GET", "/admin-api/pki/trust");
    check("and it succeeds, and moves the audit's moment", function () {
      assert.strictEqual(state, "succeeded");
      assert.ok(afterJob.json.assessedAt >= rechecked.json.assessedAt);
    });
  } finally {
    await driver.quit();
    const held = await api("GET", "/admin-api/pki/trust");
    for (const entry of (held.json && held.json.truststore.entries) || []) {
      if (entry.subject.indexOf(STAMP) >= 0) {
        await api("POST", "/admin-api/pki/trust/remove",
                  { fingerprint: entry.fingerprint256 });
      }
    }
  }
  assert.ok(checks >= 10, "only " + checks + " checks ran; a section has " +
                                            "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_paranoid_pki_console")
  .description("/admin/pki/trust in a browser (#1360).")
  .addOption(new Option("-u, --url <url>", "base url (this test reads it " +
                                           "from the environment)"))
  .parse(process.argv);

test().then(function () {
  process.exit(0);
}, function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
