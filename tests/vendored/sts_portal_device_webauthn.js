// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: sts_portal_device_webauthn.js
//
// ===========================================================================
// LINKING A WEBAUTHN PLATFORM CREDENTIAL TO A DEVICE ON /portal/devices, IN A
// REAL BROWSER (#258, the follow-up #164 left open).
//
// `/portal/devices` links a security key BUILT INTO a device to that device
// with a fresh assertion (`link-begin`, then `link-finish`), and it is the one
// step on that page that runs a script: `/authn/webauthn.js`, the resource the
// sign-in screen and `/portal/keys` run, sent only while a ceremony is armed
// (`portal/portal_devices.ts` argues it; the root CLAUDE.md lists the page).
// `tests/device_enrolment.js` drives the SERVER half of that path in process
// and `sts_devices.js` drives the JWK proof over HTTP — **and nothing drove
// the script.** A broken script, a policy that lost `script-src 'self'`, or a
// form the script cannot find would each have left every one of those green,
// because none of them ever asks a browser to run the ceremony.
//
// So this file asks one. The authenticators are WebDriver's VIRTUAL
// AUTHENTICATORS (the WebAuthn extension of the WebDriver spec, CDP's
// `WebAuthn` domain underneath): Chrome itself answers `navigator.credentials`
// for them, so the ceremony the page starts is the real one, verified by the
// real verifier, and nothing in this file builds a credential.
//
//   1. A ROAMING KEY IS REFUSED. A `usb` authenticator enrolled on
//      `/portal/keys` as "A security key I carry" is named on
//      `/portal/devices` as passed over and is not offered; a `link-begin`
//      the browser is made to post with its id is refused in the page's own
//      sentence.
//   2. A PLATFORM KEY, ENROLLED IN THE BROWSER. An `internal` authenticator,
//      enrolled as "Built into this device", stored with `attachment:
//      platform` — the one fact that makes it linkable.
//   3. THE SCRIPT BLOCKED (the root CLAUDE.md's submit-button rule). With
//      script execution off, the armed page still draws its real button, and
//      pressing it posts a `link-finish` that is answered with a sentence
//      saying the browser ran no ceremony — and links nothing.
//   4. THE LINK. The armed response carries `script-src 'self'` and keeps
//      `frame-ancestors`; pressing the button runs the script and the
//      platform authenticator signs. Development links the key; PRODUCT
//      REFUSES IT, and the refusal is what is asserted there — see
//      modeOfTheService() for why a virtual authenticator's key can never
//      be attested.
//   5. (development) THE DEVICE SHOWS THE KEY, on the page and through
//      `/admin-api`, recorded self-asserted.
//   6. (development) A LATER WEBAUTHN SIGN-IN RECOGNISES THE DEVICE. The
//      person signs in again — password, then the security key the sign-in
//      screen demands — and the device is linked to the portal's client and
//      its last use moves. Both are written to the directory, so they read
//      the same from whichever process or node answers.
//   7. THE BROWSER LOGGED NOTHING SEVERE: no CSP violation, no failed load.
//
// MUTATION-TESTED (2026-10-06), each against a copy of the compiled
// service: the armed page's `script-src 'self'` relaxation dropped (caught
// by section 4's policy check), the real submit button made inert (section
// 3), the script tag removed (section 4's ceremony leads nowhere), and
// recognition by a WebAuthn credential switched off (section 6).
//
// ---------------------------------------------------------------------------
// WHY IT IS HERE (`local: true`).
//
// Two of CLAUDE.md's three questions say so: the portal is this repository's
// own surface, and every assertion pairs what a browser did on it with what
// this repository's `/admin-api` then holds. A copy in the parent could not
// read the second half.
//
// IT RUNS IN THE DEFAULT REALM, with a person of its own, as the other
// portal jobs do. A throwaway realm would put the portal's relying party in
// a realm whose mode can differ from the process's, which is a different
// test (`email-mfa`'s lesson: a product-mode realm's portal cannot sign
// anybody in on a development-mode service). The person, their keys and
// their device are this run's alone — the username carries the run stamp —
// and are left in place, for the reason the console jobs leave their realms:
// they are what a person reads when the run went red.
//
// ONE BROWSER, SERIALLY (*do not saturate with browser tests*): the two
// authenticators are taken in turn, because WebDriver gives one session one
// virtual authenticator at a time, and that is also the order the sections
// need — the roaming key first, so the platform key's link form has
// something to pass over.
// ===========================================================================

"use strict";

const assert = require("assert");
const { Command, Option } = require("commander");
const { Builder, By } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const {
  VirtualAuthenticatorOptions, Transport, Protocol
} = require("selenium-webdriver/lib/virtual_authenticator");
const browserFlags = require("./browser_flags.js");
const { usernameFor } = require("./random_username.js");

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
var log = bunyan.createLogger({ name: "sts_portal_device_webauthn",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug('CONFIG_FILE could not be read, so the configuration is empty: ' +
            appconfigProblem.message);
}
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");

const PERSON = usernameFor("device-link");
// A PASSWORD THIS FILE CHOSE, because product mode verifies the one it is
// given and creates nobody for a typed name. Long and mixed so that no
// password policy a stack could be running refuses it.
const PASSWORD = "Device-Link-Passw0rd!-" + PERSON;
const ROAMING_LABEL = "keyring key";
const PLATFORM_LABEL = "built-in key";
const DEVICE_LABEL = "f258 laptop";
// The portal's own client — the relying party whose sign-in a recognition is
// recorded for (`common/applications.js` seeds it in every realm).
const PORTAL_CLIENT = "sts-user-portal";
const WAIT_MS = 20000;

var screenshotDir = "";
var checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  ✓ " + what);
  log.debug("Leaving check().");
}

function url(path) {
  log.debug("Entering url().");
  log.debug("Leaving url().");
  return base + path;
}

// ---------------------------------------------------------------------------
// THE DOOR THAT IS NOT THE BROWSER. `/admin-api` sets the person up and reads
// back what the browser did — never to make a change this file then credits
// to the page. The launcher's preload (`tools/attach-admin-token.js`) puts
// the run's access token on every one of these.
// ---------------------------------------------------------------------------
async function json(path, options) {
  log.debug("Entering json(). path=" + path);
  const r = await fetch(url(path), options || {});
  const text = await r.text();
  let body = null;
  try {
    body = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in json(): " + ((e && e.message) || e));
    // Not JSON — an HTML page from a door that answers JSON, which is worth
    // reporting whole rather than as a parse failure.
    body = null;
  }
  log.debug("Leaving json().");
  return { status: r.status, body: body, text: text };
}

function apiPost(path, payload) {
  log.debug("Entering apiPost().");
  log.debug("Leaving apiPost().");
  return json("/admin-api" + path, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {})
  });
}

async function keysOf(who) {
  log.debug("Entering keysOf().");
  const r = await json("/admin-api/users?user=" + encodeURIComponent(who));
  assert.strictEqual(r.status, 200,
    "GET /admin-api/users?user=" + who + " answered " + r.status + " " +
    String(r.text).slice(0, 300));
  const factors = (r.body && r.body.factors) || {};
  log.debug("Leaving keysOf().");
  return factors.keys || [];
}

async function devicesOf(who) {
  log.debug("Entering devicesOf().");
  const r = await json("/admin-api/devices?ownerKind=person&owner=" +
                       encodeURIComponent(who));
  assert.strictEqual(r.status, 200,
    "GET /admin-api/devices?owner=" + who + " answered " + r.status + " " +
    String(r.text).slice(0, 300));
  log.debug("Leaving devicesOf().");
  return (r.body && r.body.devices) || [];
}

function webauthnKeyOf(device, credentialId) {
  log.debug("Entering webauthnKeyOf().");
  const found = ((device && device.keys) || []).filter(function (k) {
    return k.kind === "webauthn" &&
      String((k.material || {}).credentialId || "") === String(credentialId);
  })[0] || null;
  log.debug("Leaving webauthnKeyOf().");
  return found;
}

async function createThePerson() {
  log.debug("Entering createThePerson().");
  const r = await apiPost("/users/create", {
    username: PERSON, invent: false,
    attributes: { cn: "Device Link " + PERSON, givenName: "Device",
                  sn: "Link", displayName: "Device Link Tester",
                  mail: PERSON + "@device-link.test" },
    credential: "password", password: PASSWORD
  });
  assert.ok(r.status === 200 && r.body && r.body.ok,
    "creating " + PERSON + " answered " + r.status + " " +
    String(r.text).slice(0, 300));
  log.info("Created " + PERSON + ".");
  log.debug("Leaving createThePerson().");
}

// THE MODE DECIDES HOW FAR THE LINK GOES, and it is asked rather than
// assumed. Product registers a device key only with an attestation that
// verified AND chained to a trusted root (`common/device_enrolment.ts`,
// `mode.acceptsUnattestedDeviceKeys()` — a mode predicate, not a setting),
// and a virtual authenticator's cannot: Chrome mints its self-signed batch
// certificate afresh at EVERY registration (same key, new validity), so no
// certificate can be pinned as an anchor in advance, and a fresh copy does
// not chain to a pinned one — the path builder refuses a second
// certificate with the same subject and key, as it should. That was found
// by trying (#258). So in product the same browser ceremony is driven to
// product's REFUSAL, which is itself what this page must do there, and the
// device and its recognition (sections 5 and 6) are asserted where a link
// can be made: development, the suite's `memory` mode.
async function modeOfTheService() {
  log.debug("Entering modeOfTheService().");
  const r = await json("/admin-api/mode");
  assert.strictEqual(r.status, 200,
    "GET /admin-api/mode answered " + r.status);
  log.debug("Leaving modeOfTheService().");
  return String((r.body && r.body.mode) || "");
}

// ---------------------------------------------------------------------------
// THE BROWSER.
// ---------------------------------------------------------------------------
// WAITS FOR A CONDITION, AND ON A TIMEOUT SAYS WHERE THE BROWSER IS. The
// page is read only THEN: a message built from the page before the wait
// reads a document mid-navigation, which throws a driver error that names
// no assertion — the first draft of this file did that, and a mutant was
// reported as "no such element: body".
async function waitFor(driver, condition, what) {
  log.debug("Entering waitFor().");
  try {
    await driver.wait(async function () {
      try {
        return await condition();
      } catch (e) {
        log.debug("Caught in waitFor(): " + ((e && e.message) || e));
        // A page mid-navigation answers a stale element or no document;
        // the next poll asks again.
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

// THE AUTHENTICATOR, one at a time — WebDriver keeps a single virtual
// authenticator per session. Both verify the user and consent without a
// person, which is what a test authenticator is for.
async function useAuthenticator(driver, transport) {
  log.debug("Entering useAuthenticator(). transport=" + transport);
  const options = new VirtualAuthenticatorOptions();
  options.setProtocol(Protocol.CTAP2);
  options.setTransport(transport);
  options.setHasResidentKey(true);
  options.setHasUserVerification(true);
  options.setIsUserVerified(true);
  options.setIsUserConsenting(true);
  await driver.addVirtualAuthenticator(options);
  log.debug("Leaving useAuthenticator().");
}

// Presses a form's submit button: the button inside the form that carries
// this hidden `action`, as a person would.
async function pressAction(driver, action) {
  log.debug("Entering pressAction(). action=" + action);
  const button = await driver.findElement(By.xpath(
    "//form[.//input[@type='hidden' and @name='action' and @value='" +
    action + "']]//button"));
  await button.click();
  log.debug("Leaving pressAction().");
}

// THE SIGN-IN, through the portal's relying party, as a browser makes it:
// `/portal` sends an unauthenticated browser to the authorization endpoint,
// which sends it to the sign-in screen. A person holding a security key is
// then asked for it — the real ceremony on the real page — and `withKey`
// says whether this sign-in expects that. An offer of a second factor
// (#246, administrators only) is ignored, as the console jobs do.
async function signIn(driver, withKey) {
  log.debug("Entering signIn(). withKey=" + withKey);
  await driver.manage().deleteAllCookies();
  // `?realm=default` past the realm chooser: a bare /portal draws it once
  // any trust realm exists (#32), which in a full run every earlier job has
  // made sure of — sts_portal_backup_codes' PORTAL_DOOR, for its reason.
  await driver.get(url("/portal?realm=default"));
  await waitFor(driver, async function () {
    return (await path(driver)).indexOf("/authn/login") >= 0;
  }, "an unauthenticated browser at /portal was never shown the sign-in " +
     "screen.");
  const name = await driver.findElement(By.css("input[name='username']"));
  await name.clear();
  await name.sendKeys(PERSON);
  const secret = await driver.findElement(By.css("input[name='password']"));
  await secret.clear();
  await secret.sendKeys(PASSWORD);
  await secret.submit();
  await waitFor(driver, async function () {
    const p = await path(driver);
    return (p.indexOf("/portal") === 0 && p.indexOf("/authn") < 0) ||
      await present(driver, "#wa-go") ||
      await present(driver, "#mfa-setup-ignore");
  }, "signing in as " + PERSON + " showed neither the portal nor a second " +
     "factor.");
  const keyAsked = await present(driver, "#wa-go");
  check("the sign-in screen " + (withKey ? "demands" : "does not demand") +
        " the security key", function () {
    assert.strictEqual(keyAsked, withKey,
      withKey ? "a person holding a second-factor key was let in on a " +
                "password alone"
              : "a person holding no key was asked for one");
  });
  if (keyAsked) {
    // THE SIGN-IN CEREMONY, by the same script: pressing the button is
    // `navigator.credentials.get()`, which the virtual authenticator answers.
    await driver.findElement(By.id("wa-go")).click();
  }
  if (await present(driver, "#mfa-setup-ignore")) {
    await driver.findElement(By.id("mfa-setup-ignore")).click();
  }
  // SIGNED IN, AND NOT MERELY UNDER /portal: the relying party's own error
  // page ("Signing in did not complete") is drawn at /portal/callback, and
  // the first draft of this file read it as a sign-in.
  await waitFor(driver, async function () {
    const p = await path(driver);
    return p.indexOf("/portal") === 0 && !(await present(driver, "#wa-go")) &&
      (await bodyText(driver)).indexOf("Signed in as " + PERSON) >= 0;
  }, "the sign-in did not end on the portal, signed in as " + PERSON + ".");
  log.debug("Leaving signIn().");
}

// ENROLMENT ON /portal/keys: name it, say where it lives, keep the default
// role (a second factor beside the password), and press Add — then the
// page's own button, which runs `navigator.credentials.create()`.
async function enrol(driver, kind, label) {
  log.debug("Entering enrol(). kind=" + kind);
  await driver.get(url("/portal/keys"));
  const box = await driver.findElement(By.id("key-label"));
  await box.clear();
  await box.sendKeys(label);
  const radios = await driver.findElements(
    By.css("input[name='kind'][value='" + kind + "']"));
  assert.ok(radios.length === 1,
    "/portal/keys offers no \"" + kind + "\" choice of where the key " +
    "lives, so a person cannot ask for one");
  await radios[0].click();
  await pressAction(driver, "begin");
  await waitFor(driver, function () {
    return present(driver, "#wa-go");
  }, "/portal/keys did not arm a ceremony for a " + kind + " key");
  await driver.findElement(By.id("wa-go")).click();
  await waitFor(driver, async function () {
    return !(await present(driver, "#wa-data"));
  }, "the " + kind + " key's ceremony never finished: the page still " +
     "holds the armed ceremony");
  const key = (await keysOf(PERSON)).filter(function (k) {
    return k.label === label;
  })[0];
  assert.ok(key && key.credentialId,
    "the " + kind + " key labelled \"" + label + "\" is not on " + PERSON +
    "'s entry after the ceremony; the page says: " +
    (await bodyText(driver)).slice(0, 400));
  log.debug("Leaving enrol().");
  return key;
}

// The armed `/portal/devices` page as a SERVER answers it, read with the
// browser's own session: the policy header is what WebDriver cannot show,
// and this is a GET, which changes nothing.
async function armedResponse(driver) {
  log.debug("Entering armedResponse().");
  const cookies = await driver.manage().getCookies();
  const agent = await driver.executeScript("return navigator.userAgent;");
  const r = await fetch(url("/portal/devices"), {
    redirect: "manual",
    headers: { cookie: cookies.map(function (c) {
      return c.name + "=" + c.value;
    }).join("; "), "user-agent": String(agent) }
  });
  const text = await r.text();
  log.debug("Leaving armedResponse().");
  return { status: r.status, csp: String(r.headers
    .get("content-security-policy") || ""), text: text };
}

// THE KIND /portal/keys DRAWS FOR ONE KEY — the third cell of its row,
// `credentials.keyKind()`'s text, from the attachment the browser reported
// at enrolment. It is read off the page because `/admin-api/users` does not
// carry the attachment, and the page is what a person decides by.
async function kindDrawnFor(driver, label) {
  log.debug("Entering kindDrawnFor().");
  await driver.get(url("/portal/keys"));
  const cells = await driver.findElements(By.xpath(
    "//tr[td[1][normalize-space()='" + label + "']]/td[3]"));
  const text = cells.length ? String(await cells[0].getText()) : "";
  log.debug("Leaving kindDrawnFor().");
  return text;
}

// ---------------------------------------------------------------------------
// 1. A ROAMING KEY IS REFUSED.
// ---------------------------------------------------------------------------
async function aRoamingKeyIsRefused(driver) {
  log.debug("Entering aRoamingKeyIsRefused().");
  log.info("=== 1. a roaming key is passed over, and refused if forced ===");
  await useAuthenticator(driver, Transport.USB);
  const roaming = await enrol(driver, "roaming", ROAMING_LABEL);
  const roamingKind = await kindDrawnFor(driver, ROAMING_LABEL);
  check("the browser reported the USB authenticator as cross-platform, and " +
        "/portal/keys draws the key as roaming", function () {
    assert.ok(/^roaming/i.test(roamingKind),
      "the roaming key is drawn as " + JSON.stringify(roamingKind));
  });

  await driver.get(url("/portal/devices"));
  const text = await bodyText(driver);
  const offered = await driver.findElements(By.css(
    "#dev-cred option[value='" + roaming.credentialId + "']"));
  check("/portal/devices names the roaming key as passed over and offers " +
        "it nowhere", function () {
    assert.ok(text.indexOf(ROAMING_LABEL) >= 0 &&
              /roaming key/i.test(text),
      "the page does not say the roaming key was passed over: " +
      text.slice(0, 500));
    assert.strictEqual(offered.length, 0,
      "the link form offers the roaming key");
  });

  // FORCED: the person holds nothing linkable yet, so there is no link form
  // to edit. The page arms nothing for a roaming key, and the platform key's
  // form in section 4 is where a forced post is made.
  await driver.removeVirtualAuthenticator();
  log.debug("Leaving aRoamingKeyIsRefused().");
  return roaming;
}

// ---------------------------------------------------------------------------
// 2. A PLATFORM KEY.
// ---------------------------------------------------------------------------
async function aPlatformKeyIsEnrolled(driver) {
  log.debug("Entering aPlatformKeyIsEnrolled().");
  log.info("=== 2. a platform key, enrolled in the browser ===");
  await useAuthenticator(driver, Transport.INTERNAL);
  // The roaming key is a second factor already, so the portal session the
  // first enrolment ran in is still the one in use; the sign-in below is a
  // fresh one that must ask for a key — and the only one present now is
  // the platform authenticator, which holds no credential yet. So this
  // enrolment happens in the session that already exists.
  const platform = await enrol(driver, "platform", PLATFORM_LABEL);
  const platformKind = await kindDrawnFor(driver, PLATFORM_LABEL);
  check("the browser reported the internal authenticator as platform, and " +
        "/portal/keys draws the key as built into a device", function () {
    assert.strictEqual(platformKind, "built into a device",
      "the platform key is drawn as " + JSON.stringify(platformKind));
  });
  log.debug("Leaving aPlatformKeyIsEnrolled().");
  return platform;
}

// A roaming key's id put into the link form and posted, as a hand-edited
// form would: the browser sends it, and the page must refuse it.
async function aForcedRoamingLinkIsRefused(driver, roaming) {
  log.debug("Entering aForcedRoamingLinkIsRefused().");
  await driver.get(url("/portal/devices"));
  await driver.executeScript(
    "var s = document.getElementById('dev-cred');" +
    "var o = document.createElement('option');" +
    "o.value = arguments[0]; o.textContent = 'forced';" +
    "s.appendChild(o); s.value = arguments[0];", roaming.credentialId);
  await pressAction(driver, "link-begin");
  await waitFor(driver, async function () {
    return /roaming authenticator/i.test(await bodyText(driver));
  }, "a link-begin naming the roaming key was not refused with the " +
     "page's sentence");
  const armed = await present(driver, "#wa-data");
  check("a link-begin the browser posts for the roaming key is refused, " +
        "in the page's sentence, and arms nothing", function () {
    assert.strictEqual(armed, false,
      "a ceremony was armed for a roaming key");
  });
  log.debug("Leaving aForcedRoamingLinkIsRefused().");
}

// Fills the link form for a NEW device and presses Link it.
async function beginTheLink(driver, platform) {
  log.debug("Entering beginTheLink().");
  await driver.get(url("/portal/devices"));
  const choice = await driver.findElements(By.css(
    "#dev-cred option[value='" + platform.credentialId + "']"));
  assert.strictEqual(choice.length, 1,
    "the link form does not offer the platform key: " +
    (await bodyText(driver)).slice(0, 500));
  await choice[0].click();
  const label = await driver.findElement(By.id("dev-label"));
  await label.clear();
  await label.sendKeys(DEVICE_LABEL);
  await pressAction(driver, "link-begin");
  await waitFor(driver, function () {
    return present(driver, "#wa-data");
  }, "pressing Link it armed no ceremony.");
  log.debug("Leaving beginTheLink().");
}

// ---------------------------------------------------------------------------
// 3. THE SCRIPT BLOCKED.
// ---------------------------------------------------------------------------
async function withTheScriptBlocked(driver, platform) {
  log.debug("Entering withTheScriptBlocked().");
  log.info("=== 3. with the script blocked, the button is the mechanism ===");
  await driver.sendDevToolsCommand("Emulation.setScriptExecutionDisabled",
                                   { value: true });
  try {
    await beginTheLink(driver, platform);
    const go = await driver.findElements(By.id("wa-go"));
    const real = await driver.findElements(By.css(
      "#wa-form button[type='submit']"));
    check("the armed page draws the ceremony's button AND a real submit " +
          "button under it", function () {
      assert.strictEqual(go.length, 1, "no #wa-go button");
      assert.strictEqual(real.length, 1,
        "no submit button in #wa-form: with the script blocked the page " +
        "would do nothing");
    });
    // Pressing the ceremony's own button does nothing with no script, which
    // is what a person with script blocked meets first.
    await go[0].click();
    await real[0].click();
    await waitFor(driver, async function () {
      return /did not run the ceremony/i.test(await bodyText(driver));
    }, "the real button's link-finish with no assertion was not answered " +
       "with the page's sentence");
  } finally {
    await driver.sendDevToolsCommand("Emulation.setScriptExecutionDisabled",
                                     { value: false });
  }
  const held = await devicesOf(PERSON);
  check("the page says the browser ran no ceremony, and nothing is " +
        "linked", function () {
    assert.ok(!held.some(function (d) {
      return webauthnKeyOf(d, platform.credentialId);
    }), "a device holds the platform key after a ceremony that never ran: " +
        JSON.stringify(held));
  });
  log.debug("Leaving withTheScriptBlocked().");
}

// ---------------------------------------------------------------------------
// 4. THE LINK.
// ---------------------------------------------------------------------------
async function theLink(driver, platform, product) {
  log.debug("Entering theLink().");
  log.info("=== 4. the link, by the script, against the platform key ===");
  await beginTheLink(driver, platform);
  const armed = await armedResponse(driver);
  check("the armed page is served script-src 'self' for its one script, " +
        "and keeps frame-ancestors", function () {
    assert.strictEqual(armed.status, 200,
      "GET /portal/devices with the browser's session answered " +
      armed.status);
    assert.ok(/data-mode="get"/.test(armed.text),
      "the page fetched with the browser's session is not the armed one");
    assert.ok(/frame-ancestors /.test(armed.csp),
      "the armed page's policy dropped frame-ancestors: " + armed.csp);
    // `script-src` alone: the portal's `style-src` allows inline styles,
    // which is a different exception and not this page's.
    const scriptSrc = (armed.csp.split(";").filter(function (d) {
      return /^\s*script-src\s/.test(d);
    })[0] || "").trim();
    assert.strictEqual(scriptSrc, "script-src 'self'",
      "the armed page's script-src is not exactly 'self': " + armed.csp);
  });
  await driver.findElement(By.id("wa-go")).click();
  await waitFor(driver, async function () {
    const text = await bodyText(driver);
    return /security key is linked/i.test(text) ||
      /only with an attestation/i.test(text) ||
      /refused|could not|not linked/i.test(text);
  }, "pressing the ceremony's button led nowhere.");
  const said = await bodyText(driver);
  if (product) {
    const held = await devicesOf(PERSON);
    check("the script ran the ceremony, and product refused the unattested " +
          "key in the page's sentence and linked nothing", function () {
      assert.ok(/only with an attestation that verified/i.test(said),
        "product did not refuse the virtual authenticator's key with the " +
        "attestation sentence: " + said.slice(0, 500));
      assert.ok(!held.some(function (d) {
        return webauthnKeyOf(d, platform.credentialId);
      }), "product linked an unattested key: " + JSON.stringify(held));
    });
    log.debug("Leaving theLink(). Refused, as product must.");
    return false;
  }
  check("the script ran the ceremony and the page says the key is linked",
    function () {
      assert.ok(/security key is linked/i.test(said),
        "the page did not say the key was linked: " + said.slice(0, 500));
    });
  log.debug("Leaving theLink(). Linked.");
  return true;
}
// ---------------------------------------------------------------------------
// 5. THE DEVICE SHOWS THE KEY.
// ---------------------------------------------------------------------------
async function theDeviceShowsTheKey(driver, platform) {
  log.debug("Entering theDeviceShowsTheKey().");
  log.info("=== 5. the device holds the key ===");
  const held = await devicesOf(PERSON);
  const device = held.filter(function (d) {
    return d.label === DEVICE_LABEL;
  })[0];
  check("/admin-api/devices holds one new device of " + PERSON + "'s, with " +
        "a webauthn key naming the credential the browser used", function () {
    assert.ok(device, "no device labelled " + DEVICE_LABEL + ": " +
      JSON.stringify(held));
    assert.ok(webauthnKeyOf(device, platform.credentialId),
      "the device holds no webauthn key with the platform credential's id: " +
      JSON.stringify(device.keys));
  });
  // SELF-ASSERTED: development's attestation policy verifies nothing, so
  // nothing about this key may be recorded as proven.
  check("the device is recorded self-asserted, claiming nothing its key " +
        "did not prove", function () {
    assert.strictEqual((device.attestation || {}).level, "self-asserted",
      "the device's attestation: " + JSON.stringify(device.attestation));
  });
  await driver.get(url("/portal/devices"));
  const rows = await driver.findElements(By.xpath(
    "//tr[td[1][normalize-space()='" + DEVICE_LABEL + "']]"));
  const row = rows.length ? await rows[0].getText() : "";
  check("/portal/devices draws the device with its webauthn key", function () {
    assert.strictEqual(rows.length, 1,
      "the device's row is not on the page");
    assert.ok(/webauthn/i.test(row),
      "the device's row does not show a webauthn key: " + row);
  });
  log.debug("Leaving theDeviceShowsTheKey().");
  return device;
}

// ---------------------------------------------------------------------------
// 6. A LATER SIGN-IN RECOGNISES THE DEVICE.
// ---------------------------------------------------------------------------
async function aLaterSignInRecognisesIt(driver, linked) {
  log.debug("Entering aLaterSignInRecognisesIt().");
  log.info("=== 6. a later webauthn sign-in recognises the device ===");
  const before = Date.parse(linked.lastUsed || "") || 0;
  // A clock tick between the link's write and the sign-in, so that a moved
  // last use is told apart from the one the link wrote.
  await new Promise(function (resolve) {
    setTimeout(resolve, 1500);
  });
  await signIn(driver, true);
  // THE DIRECTORY, NOT THE MONITOR'S COUNTERS: those are per process
  // (`sts_devices.js` section 9 argues it), and the device record is what
  // every process reads. Waited for, to cover replication between nodes.
  let device = null;
  for (let i = 0; i < 40; i++) {
    device = (await devicesOf(PERSON)).filter(function (d) {
      return d.id === linked.id;
    })[0] || null;
    const apps = ((device && device.applications) || []).join(" ")
      .toLowerCase();
    if (device && apps.indexOf(PORTAL_CLIENT) >= 0 &&
        (Date.parse(device.lastUsed || "") || 0) > before) {
      break;
    }
    await new Promise(function (resolve) {
      setTimeout(resolve, 500);
    });
  }
  check("the sign-in recognised the device by the key the browser used: " +
        "the portal's client is linked to it and its last use moved",
    function () {
      assert.ok(device, "the device is gone");
      assert.ok(((device.applications || []).join(" ").toLowerCase())
                  .indexOf(PORTAL_CLIENT) >= 0,
        "the portal's client is not linked to the device after a sign-in " +
        "its key proved: " + JSON.stringify(device.applications));
      assert.ok((Date.parse(device.lastUsed || "") || 0) > before,
        "the device's last use did not move: " + linked.lastUsed + " then " +
        device.lastUsed);
    });
  log.debug("Leaving aLaterSignInRecognisesIt().");
}

// ---------------------------------------------------------------------------
// 7. THE BROWSER'S OWN LOG.
// ---------------------------------------------------------------------------
async function theBrowserLogIsClean(driver) {
  log.debug("Entering theBrowserLogIsClean().");
  const entries = await driver.manage()
                              .logs()
                              .get("browser")
                              .catch(function (e) {
    // Not every driver serves the log; a job that failed here would be
    // reporting on the driver rather than on the portal.
    log.debug("Caught in theBrowserLogIsClean(): " + ((e && e.message) || e));
    return [];
  });
  const severe = entries.filter(function (entry) {
    return entry.level && entry.level.name === "SEVERE";
  }).map(function (entry) {
    return entry.message;
  }).filter(function (message) {
    // The browser asks for /favicon.ico on its own and this service serves
    // none; it is the browser's request rather than the page's.
    return message.indexOf("/favicon.ico") < 0;
  }).filter(function (message) {
    // THE REFUSALS THIS FILE PROVOKES: the forced roaming link and the
    // ceremony that never ran are each answered 400 on purpose.
    return !(/\/portal\/devices/.test(message) &&
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
      "sts_portal_device_webauthn-" + what + ".png");
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
// THE RUN.
// ---------------------------------------------------------------------------
async function test() {
  log.debug("Entering test().");
  log.info("Linking a WebAuthn platform credential on " + base +
           "/portal/devices in a real browser, as " + PERSON);

  const status = await json("/admin-api/status");
  assert.strictEqual(status.status, 200,
    "GET /admin-api/status answered " + status.status + " at " + base +
    ". This job needs the service and a browser, and a service that is not " +
    "there is a failure rather than a skip.");
  await createThePerson();

  const options = new chrome.Options();
  options.addArguments("--headless=new", "--no-sandbox",
      "--disable-dev-shm-usage", "--window-size=1400,1200");
  browserFlags.addBrowserAccessFlags(options, base);
  const driver = await new Builder().forBrowser("chrome")
      .setChromeOptions(options).build();

  const product = (await modeOfTheService()) === "product";
  log.info("The service is in " + (product ? "product" : "development") +
           " mode.");
  try {
    await signIn(driver, false);
    const roaming = await aRoamingKeyIsRefused(driver);
    const platform = await aPlatformKeyIsEnrolled(driver);
    await aForcedRoamingLinkIsRefused(driver, roaming);
    await withTheScriptBlocked(driver, platform);
    if (await theLink(driver, platform, product)) {
      const device = await theDeviceShowsTheKey(driver, platform);
      await aLaterSignInRecognisesIt(driver, device);
    } else {
      log.info("Sections 5 and 6 need a linked key, which product never " +
               "makes from a virtual authenticator; they run in " +
               "development (the suite's memory mode).");
    }
    await theBrowserLogIsClean(driver);

    // A FLOOR ON THE COUNT, for sts_admin_console.js's reason: a section
    // that stops being called takes its assertions with it and the run
    // still says "passed".
    const floor = product ? 10 : 15;
    assert.ok(checks >= floor,
      "only " + checks + " checks ran; this file makes " + floor + " in " +
      (product ? "product" : "development") + " mode, so a " +
      "SECTION STOPPED BEING CALLED.");
    log.info(checks + " checks passed. " + PERSON + ", their keys and their " +
             "device are left in place to be read.");
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
  .name("sts_portal_device_webauthn")
  .description("Link a WebAuthn platform credential to a device on " +
      "/portal/devices in a real browser with a virtual authenticator: the " +
      "roaming key refused, the page with its script blocked, the link, " +
      "the device holding the key, and a later sign-in recognising it.")
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
