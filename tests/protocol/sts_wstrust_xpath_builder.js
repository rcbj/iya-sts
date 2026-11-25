// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_wstrust_xpath_builder.js
//
// ===========================================================================
// THE WS-TRUST XPATH BUILDER, DRIVEN IN A BROWSER (#2046, rcbj 2026-11-23):
// "build a set of tests to exercise the XPath Expression Builder to confirm
// that it is working correctly. Make sure the correct XPath expression ends
// up in the map field."
//
// `local: true`: this repository's console, in Chrome, on an application's
// Configuration -> WS-Trust sub-tab. For each of the five fields that hold
// XPath expressions, the builder is opened from that field's own card, a
// sample is parsed, elements are clicked, and what is asserted is EXACT:
//
//   a. the expression the builder writes for each element clicked — the
//      service's prefixes, never the sample's (s:, a:, trust:) — and the
//      number of the sample's elements it matches;
//   b. the dialog opens for that card's field alone, and closes once the
//      list is added;
//   c. the values in the field's card afterwards: the list appended, a value
//      already there kept, an expression already there not added twice, a
//      value taken off the list not added, and the recipient field's one
//      expression replacing what it held (a list of two refused);
//   d. the field's switch turned on;
//   e. and, after Save, the application as `/admin-api` answers it: each map
//      holding exactly those expressions, and each switch TRUE.
//
// A SOAP 1.1 sample (soap11:) and an element in a namespace the service has
// no prefix for (local-name() and namespace-uri()) are among the cases.
//
// **THE DEFAULT REALM, WITH WHAT THIS JOB ADDS REMOVED IN A `finally`**: an
// application and a console user of its own, by a stamp no other job uses.
//
// **IN PRODUCT (#2236)** the console user's password is made its own first
// (`own_password.js`, #2160: a typed one is temporary there, and the browser
// would land on the change step instead of the console), and the Save goes
// through `console_steps.js` (#2196): the console signs in with read scopes
// (#2168) and the write asks for `admin:write` in a popup before it is sent.
// ===========================================================================

const assert = require("assert");
const { Command, Option } = require("commander");
const { Builder, By } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const browserFlags = require("./browser_flags.js");
const consoleSteps = require("./console_steps.js");
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
var log = bunyan.createLogger({ name: "sts_wstrust_xpath_builder",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = Date.now().toString(36);
const USER = "xpath-builder-" + STAMP;
const PASSWORD = "Xpath-builder-Passw0rd!-" + STAMP;
const APP = "xpb-" + STAMP;
const APPLIES_TO = "https://xpb-" + STAMP + ".example";
// The Save's answer may wait behind a popup for the write scope (#2168).
const PRESSED_MS = 45000;
const PRESS_MARK = "__stsXpathBuilderPress";

// The expressions the builder must write for elements of its own sample (a
// SOAP 1.2 Issue request whose prefixes are s:, a:, wsse:, wsu:, trust:,
// wsp:), by the name the tree shows.
const ON_SAMPLE = {
  "s:Body": "/soap12:Envelope/soap12:Body",
  "a:To": "/soap12:Envelope/soap12:Header/wsa:To",
  "a:MessageID": "/soap12:Envelope/soap12:Header/wsa:MessageID",
  "wsu:Timestamp":
    "/soap12:Envelope/soap12:Header/wsse:Security/wsu:Timestamp",
  "trust:TokenType":
    "/soap12:Envelope/soap12:Body/wst:RequestSecurityToken/wst:TokenType",
  "wsp:AppliesTo":
    "/soap12:Envelope/soap12:Body/wst:RequestSecurityToken/wsp:AppliesTo",
  "a:Address": "/soap12:Envelope/soap12:Body/wst:RequestSecurityToken/" +
    "wsp:AppliesTo/wsa:EndpointReference/wsa:Address"
};

// A SOAP 1.1 sample, with an element in a namespace the service has no
// prefix for and a BinarySecurityToken for the recipient field.
const SOAP11_SAMPLE =
  '<e:Envelope xmlns:e="http://schemas.xmlsoap.org/soap/envelope/">' +
  '<e:Header><sec:Security xmlns:sec="http://docs.oasis-open.org/wss/2004/' +
  '01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><sec:BinarySecurityToken' +
  ' ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-' +
  'x509-token-profile-1.0#X509v3">MIIB</sec:BinarySecurityToken>' +
  '</sec:Security></e:Header><e:Body><x:Thing xmlns:x="urn:example:xpb">' +
  '<x:Part/></x:Thing></e:Body></e:Envelope>';
const ON_SOAP11 = {
  "e:Body": "/soap11:Envelope/soap11:Body",
  "x:Part": "/soap11:Envelope/soap11:Body/" +
    "*[local-name()='Thing' and namespace-uri()='urn:example:xpb']/" +
    "*[local-name()='Part' and namespace-uri()='urn:example:xpb']",
  "sec:BinarySecurityToken": "/soap11:Envelope/soap11:Header/" +
    "wsse:Security/wsse:BinarySecurityToken"
};

const SWITCHES = {
  wstrustEncryptRequestElements: "wstrustEncryptRequest",
  wstrustEncryptResponseElements: "wstrustEncryptResponse",
  wstrustSignRequestElements: "wstrustSignRequest",
  wstrustSignResponseElements: "wstrustSignResponse"
};

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

// One member of the application's answer, wherever it sits in it.
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

// What the page holds now: the builder's expression, its match line, the
// dialog's state and title, the list, the options the field select offers,
// and the values and switch of each map.
const STATE = `
  const q = function (s) { return document.querySelector(s); };
  const values = function (field) {
    return Array.from(document.querySelectorAll('#fgc-' + field +
      ' .fg-item input')).map(function (i) { return i.value; });
  };
  const switchOf = function (name) {
    const on = Array.from(document.querySelectorAll(
      'input[name="field.' + name + '"]')).filter(function (r) {
        return r.checked;
      })[0];
    return on ? on.value : null;
  };
  const dialog = q('#wsp-dialog');
  const recipient = q('#fg-wstrustResponseRecipientXPath');
  return {
    open: !!(dialog && dialog.open),
    modal: !!(dialog && dialog.open && dialog.matches(':modal')),
    title: dialog ? q('#wsp-dialog-title').textContent : '',
    expression: q('#wsp-expression') ? q('#wsp-expression').value : '',
    matches: q('#wsp-matches') ? q('#wsp-matches').textContent : '',
    list: Array.from(document.querySelectorAll('#wsp-list code'))
      .map(function (c) { return c.textContent; }),
    targets: q('#wsp-target') ? Array.from(q('#wsp-target').options)
      .map(function (o) { return o.value; }) : [],
    added: q('#wsp-added') ? q('#wsp-added').textContent : '',
    maps: {
      wstrustEncryptRequestElements: values('wstrustEncryptRequestElements'),
      wstrustEncryptResponseElements:
        values('wstrustEncryptResponseElements'),
      wstrustSignRequestElements: values('wstrustSignRequestElements'),
      wstrustSignResponseElements: values('wstrustSignResponseElements')
    },
    recipient: recipient ? recipient.value : null,
    switches: {
      wstrustEncryptRequest: switchOf('wstrustEncryptRequest'),
      wstrustEncryptResponse: switchOf('wstrustEncryptResponse'),
      wstrustSignRequest: switchOf('wstrustSignRequest'),
      wstrustSignResponse: switchOf('wstrustSignResponse')
    },
    status: Array.from(document.querySelectorAll('[data-wsp-added]'))
      .reduce(function (all, p) {
        all[p.getAttribute('data-wsp-added')] = p.textContent;
        return all;
      }, {})
  };
`;

async function state(driver) {
  log.debug("Entering state().");
  const got = await driver.executeScript(STATE);
  log.debug("Leaving state().");
  return got;
}

// Presses something by selector, through the page's own click.
async function press(driver, selector) {
  log.debug("Entering press(). " + selector);
  const done = await driver.executeScript(
    "const el = document.querySelector(arguments[0]);" +
    "if (!el) { return false; } el.click(); return true;", selector);
  assert.ok(done, "nothing on the page matches " + selector);
  log.debug("Leaving press().");
}

// Opens the builder from a field's card.
async function openFor(driver, field) {
  log.debug("Entering openFor(). " + field);
  await press(driver, '[data-wsp-open="' + field + '"]');
  log.debug("Leaving openFor().");
}

// Puts a sample in the box (or leaves the builder's own) and parses it.
async function parse(driver, sample) {
  log.debug("Entering parse().");
  if (sample) {
    await driver.executeScript(
      "document.getElementById('wsp-sample').value = arguments[0];", sample);
  }
  await press(driver, "[data-wsp-parse]");
  log.debug("Leaving parse().");
}

// Clicks an element of the parsed sample by the name the tree shows, and
// answers the expression and match line the builder then shows.
async function pick(driver, name) {
  log.debug("Entering pick(). " + name);
  const done = await driver.executeScript(
    "const wanted = arguments[0];" +
    "const b = Array.from(document.querySelectorAll(" +
    "'#wsp-tree button.wsp-el')).filter(function (x) {" +
    "  return x.textContent === wanted; })[0];" +
    "if (!b) { return false; } b.click(); return true;", name);
  assert.ok(done, "the tree has no element " + name);
  const now = await state(driver);
  log.debug("Leaving pick().");
  return now;
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

// THE SAVE, SEEN TO BE ANSWERED (`sts_realm_late_forms.js`'s arrangement):
// the console frame is marked and the button pressed in one script, what the
// console asks for first — the write scope's popup (#2168), a sign-in again
// (#2161) — is done as the person does it, a page that left to sign in,
// which sent nothing, is pressed again, and the wait is for a drawn frame
// that is not the marked one.
async function saveAndWait(driver, selector, pressedAgain) {
  log.debug("Entering saveAndWait(). " + selector);
  const start = await steps.before();
  const token = STAMP + "-" + Math.random().toString(36).slice(2);
  const pressed = await driver.executeScript(
    "const el = document.querySelector(arguments[2]);" +
    "if (!el) { return 'nothing matches ' + arguments[2]; }" +
    "const frame = document.querySelector('.shell');" +
    "if (!frame) { return 'no console frame on ' + location.href; }" +
    "frame[arguments[0]] = arguments[1];" +
    "el.click(); return '';", PRESS_MARK, token, selector);
  assert.strictEqual(pressed, "", "Save: " + pressed);
  const answered = function () {
    log.debug("Entering answered().");
    log.debug("Leaving answered().");
    return driver.executeScript(FRAME_ANSWERED, PRESS_MARK, token)
      .catch(function (e) {
        // A document torn down under the probe: not answered yet.
        log.debug("Caught in saveAndWait(): " + ((e && e.message) || e));
        return false;
      });
  };
  const stepped = await steps.after(start, { settled: answered });
  if (stepped.leftToSignIn && !pressedAgain) {
    await waitForDrawn(driver);
    log.info("the Save was not sent: the console signed in again on the " +
             "page. Pressed again.");
    await saveAndWait(driver, selector, true);
    log.debug("Leaving saveAndWait(). Pressed again.");
    return;
  }
  await driver.wait(answered, PRESSED_MS,
                    "the Save was pressed and its answer was never drawn");
  log.debug("Leaving saveAndWait().");
}

async function collect(driver) {
  log.debug("Entering collect().");
  await press(driver, "[data-wsp-collect]");
  log.debug("Leaving collect().");
}

async function addList(driver) {
  log.debug("Entering addList().");
  await press(driver, "[data-wsp-add]");
  const now = await state(driver);
  log.debug("Leaving addList().");
  return now;
}

async function test() {
  log.debug("Entering test().");
  log.info("the WS-Trust XPath builder at " + base);
  // THE PASSWORD IS THE PERSON'S OWN (#2160): one an administrator types is
  // temporary in product, so a temporary one is set and the person chooses
  // PASSWORD; in development it is set directly.
  const temporary = ownPassword.temporaryFor(PASSWORD);
  const created = await api("POST", "/admin-api/users/create", {
    username: USER, invent: false,
    attributes: { cn: USER, givenName: "Xpath", sn: "Builder",
                  mail: USER + "@xpath-builder.test" },
    credential: "password", password: temporary });
  assert.ok(created.status === 200, created.raw.slice(0, 300));
  await ownPassword.chooseOwn(base, USER, temporary, PASSWORD,
    function (who, value) {
      log.debug("Entering setPassword().");
      log.debug("Leaving setPassword().");
      return api("POST", "/admin-api/users/set-password",
                 { user: who, password: value });
    });
  const granted = await api("POST", "/admin-api/rbac/grant",
                            { username: USER, role: "write" });
  assert.strictEqual(granted.status, 200, granted.raw.slice(0, 300));
  // An application declared for WS-Trust, one map already holding a value
  // and one holding an expression the builder will write, so the append
  // and the no-duplicate rules have something to keep.
  const made = await api("POST", "/admin-api/applications/create", {
    identifier: APP, protocols: ["wstrust"],
    fields: { wstrustAppliesTo: [APPLIES_TO],
              wstrustSignResponseElements: ["//wst:Lifetime"],
              wstrustEncryptResponseElements: [ON_SAMPLE["s:Body"] + "/*"] }
  });
  assert.strictEqual(made.status, 200, made.raw.slice(0, 300));

  const options = new chrome.Options();
  options.addArguments("--headless=new", "--no-sandbox",
      "--disable-dev-shm-usage", "--window-size=1400,1200");
  browserFlags.addBrowserAccessFlags(options, base);
  const driver = await new Builder().forBrowser("chrome")
      .setChromeOptions(options).build();
  steps = consoleSteps.forDriver(driver, {
    credentials: function () {
      return { username: USER, password: PASSWORD };
    },
    log: log
  });
  try {
    await signIn(driver);
    await driver.get(base + "/admin/applications?application=" + APP +
                     "#cfg-wstrust");
    await waitForDrawn(driver);
    await driver.wait(async function () {
      return (await driver.findElements(By.css("[data-wsp-open]"))).length
        >= 5;
    }, 20000, "the WS-Trust sub-tab never drew the five builder buttons");
    await press(driver, '#cfg-wstrust input[name="view"][value="advanced"]');

    log.info("=== a, b. the builder on its own sample ===");
    await openFor(driver, "wstrustSignRequestElements");
    let now = await state(driver);
    check("the dialog opens, modal, for the card's field alone",
          function () {
            assert.ok(now.open && now.modal, JSON.stringify(now));
            assert.ok(/wstrustSignRequestElements/.test(now.title),
                      now.title);
            assert.deepStrictEqual(now.targets,
                                   ["wstrustSignRequestElements"]);
          });
    await parse(driver);
    for (const name of Object.keys(ON_SAMPLE)) {
      now = await pick(driver, name);
      check("clicking " + name + " writes " + ON_SAMPLE[name] +
            ", which matches it alone", function () {
              assert.strictEqual(now.expression, ON_SAMPLE[name]);
              assert.strictEqual(now.matches,
                                 "Elements of the sample it matches: 1.");
            });
    }

    log.info("=== c, d. each field, its card's values and its switch ===");
    // wstrustSignRequestElements: two expressions into an empty map.
    await pick(driver, "a:To");
    await collect(driver);
    await pick(driver, "trust:TokenType");
    await collect(driver);
    await pick(driver, "a:To");
    await collect(driver);
    now = await state(driver);
    check("an expression collected twice is on the list once", function () {
      assert.deepStrictEqual(now.list, [ON_SAMPLE["a:To"],
                                        ON_SAMPLE["trust:TokenType"]]);
    });
    now = await addList(driver);
    check("wstrustSignRequestElements: the list is in the card, exactly, " +
          "and the dialog closed", function () {
            assert.deepStrictEqual(now.maps.wstrustSignRequestElements,
              [ON_SAMPLE["a:To"], ON_SAMPLE["trust:TokenType"]]);
            assert.ok(!now.open);
            assert.ok(/Added 2 expression/.test(
              now.status.wstrustSignRequestElements),
                      JSON.stringify(now.status));
          });
    check("and its switch is on", function () {
      assert.strictEqual(now.switches.wstrustSignRequest, "TRUE");
    });

    // wstrustSignResponseElements: appended to a value already there.
    await openFor(driver, "wstrustSignResponseElements");
    now = await state(driver);
    check("opened from another card, the list starts empty and the field " +
          "is that card's", function () {
            assert.deepStrictEqual(now.list, []);
            assert.deepStrictEqual(now.targets,
                                   ["wstrustSignResponseElements"]);
          });
    await parse(driver);
    await pick(driver, "s:Body");
    await collect(driver);
    await pick(driver, "wsu:Timestamp");
    await collect(driver);
    // The second taken off the list again with its bin.
    await press(driver, '#wsp-list button[data-wsp-remove="1"]');
    now = await state(driver);
    check("a value taken off the list with its bin is gone from it",
          function () {
            assert.deepStrictEqual(now.list, [ON_SAMPLE["s:Body"]]);
          });
    now = await addList(driver);
    check("wstrustSignResponseElements: the list is appended to the value " +
          "the map held", function () {
            assert.deepStrictEqual(now.maps.wstrustSignResponseElements,
                                   ["//wst:Lifetime", ON_SAMPLE["s:Body"]]);
            assert.strictEqual(now.switches.wstrustSignResponse, "TRUE");
          });

    // wstrustEncryptResponseElements: an expression the map already holds
    // is not added twice; a new one is.
    await openFor(driver, "wstrustEncryptResponseElements");
    await parse(driver);
    await pick(driver, "wsp:AppliesTo");
    await collect(driver);
    now = await addList(driver);
    await openFor(driver, "wstrustEncryptResponseElements");
    await pick(driver, "wsp:AppliesTo");
    await collect(driver);
    now = await addList(driver);
    check("wstrustEncryptResponseElements: what it held, and the new " +
          "expression once, though added twice", function () {
            assert.deepStrictEqual(now.maps.wstrustEncryptResponseElements,
              [ON_SAMPLE["s:Body"] + "/*", ON_SAMPLE["wsp:AppliesTo"]]);
            assert.strictEqual(now.switches.wstrustEncryptResponse, "TRUE");
            assert.ok(/Added 0 expression/.test(
              now.status.wstrustEncryptResponseElements),
                      JSON.stringify(now.status));
          });

    // wstrustEncryptRequestElements: a SOAP 1.1 sample, an unknown
    // namespace.
    await openFor(driver, "wstrustEncryptRequestElements");
    await parse(driver, SOAP11_SAMPLE);
    for (const name of ["e:Body", "x:Part"]) {
      now = await pick(driver, name);
      check("SOAP 1.1: clicking " + name + " writes " + ON_SOAP11[name],
            function () {
              assert.strictEqual(now.expression, ON_SOAP11[name]);
              assert.strictEqual(now.matches,
                                 "Elements of the sample it matches: 1.");
            });
      await collect(driver);
    }
    now = await addList(driver);
    check("wstrustEncryptRequestElements: the SOAP 1.1 expressions are in " +
          "the card, exactly", function () {
            assert.deepStrictEqual(now.maps.wstrustEncryptRequestElements,
              [ON_SOAP11["e:Body"], ON_SOAP11["x:Part"]]);
            assert.strictEqual(now.switches.wstrustEncryptRequest, "TRUE");
          });

    // wstrustResponseRecipientXPath: one expression, which replaces.
    await openFor(driver, "wstrustResponseRecipientXPath");
    now = await state(driver);
    check("the recipient card's dialog is for that field alone",
          function () {
            assert.deepStrictEqual(now.targets,
                                   ["wstrustResponseRecipientXPath"]);
          });
    await parse(driver, SOAP11_SAMPLE);
    await pick(driver, "sec:BinarySecurityToken");
    await collect(driver);
    await pick(driver, "e:Body");
    await collect(driver);
    now = await addList(driver);
    check("the recipient field refuses a list of two, and stays open",
          function () {
            assert.ok(now.open);
            assert.ok(/holds one expression/.test(now.added), now.added);
            assert.strictEqual(now.recipient, "");
          });
    await press(driver, '#wsp-list button[data-wsp-remove="1"]');
    now = await addList(driver);
    check("a list of one is the recipient expression, exactly", function () {
      assert.strictEqual(now.recipient,
                         ON_SOAP11["sec:BinarySecurityToken"]);
      assert.ok(!now.open);
    });

    log.info("=== e. saved, and read back ===");
    await saveAndWait(driver, '#cfg-wstrust form.appgrid ' +
                      'button[type="submit"]:not(.default-submit):not([name])');
    const read = await api("GET", "/admin-api/applications?application=" +
                                  encodeURIComponent(APP));
    assert.strictEqual(read.status, 200, read.raw.slice(0, 300));
    const stored = function (name) {
      const value = memberOf(read.json, name);
      return value === undefined ? [] : [].concat(value);
    };
    check("each map holds exactly what the builder put in its card",
          function () {
            assert.deepStrictEqual(stored("wstrustSignRequestElements"),
              [ON_SAMPLE["a:To"], ON_SAMPLE["trust:TokenType"]]);
            assert.deepStrictEqual(stored("wstrustSignResponseElements"),
              ["//wst:Lifetime", ON_SAMPLE["s:Body"]]);
            assert.deepStrictEqual(stored("wstrustEncryptResponseElements"),
              [ON_SAMPLE["s:Body"] + "/*", ON_SAMPLE["wsp:AppliesTo"]]);
            assert.deepStrictEqual(stored("wstrustEncryptRequestElements"),
              [ON_SOAP11["e:Body"], ON_SOAP11["x:Part"]]);
            assert.deepStrictEqual(stored("wstrustResponseRecipientXPath"),
              [ON_SOAP11["sec:BinarySecurityToken"]]);
          });
    check("and each map's switch is TRUE", function () {
      Object.keys(SWITCHES).forEach(function (map) {
        assert.deepStrictEqual(stored(SWITCHES[map]).map(function (v) {
          return String(v).toUpperCase();
        }), ["TRUE"], SWITCHES[map]);
      });
    });
  } finally {
    await driver.quit();
    await api("POST", "/admin-api/applications/forget", { application: APP });
    await api("POST", "/admin-api/users/delete", { user: USER });
  }
  assert.ok(checks >= 20, "only " + checks + " checks ran; a section has " +
                                            "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_wstrust_xpath_builder")
  .description("The WS-Trust XPath builder in a browser (#2046).")
  .addOption(new Option("-u, --url <url>", "base url (this test reads it " +
                                           "from the environment)"))
  .parse(process.argv);

test().then(function () {
  process.exit(0);
}, function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
