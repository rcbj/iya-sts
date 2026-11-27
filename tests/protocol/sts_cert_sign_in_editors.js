// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_cert_sign_in_editors.js
//
// ===========================================================================
// CERTIFICATE SIGN-IN'S SETTINGS EDITORS, DRIVEN IN A BROWSER (#2096, rcbj
// 2026-11-24: "yes to a headless-browser test of #2080's editors").
//
// `admin-ui/web_cert_sign_in.ts` (#2080) draws six settings that hold a
// structure as text as form fields over the box that still carries the
// value. `tests/cert_sign_in_editor.js` holds its pure functions — the
// parse, the write-back, the changes — and NOTHING drove `wire()`: the
// events, the redraws, the truststore read, the server's inspection, and the
// Save posting the box. This job does, in Chrome, on the console's own
// runtime, in a THROWAWAY REALM (a development realm, reached through the
// realm switcher with the default realm's console account, which is how the
// console reaches a realm):
//
//   1. Protocols → PIV, `certSignIn.profiles`: a profile ADDED with the
//      editor — an issuer picked from the client truststore (a Root this job
//      mints, put there through the gated door and removed at the end),
//      keyUsage boxes, two EKU presets, the PIV Authentication policy
//      preset, high-affinity bindings; the low-affinity boxes DISABLED until
//      `lowAffinity` is ticked, and a name method taken out again when it is
//      unticked; a bad hash and a bad OID refused in the editor; a second
//      profile with a typed issuer, a custom OID and a name method; the two
//      REORDERED; saved. The stored text is asserted EXACTLY, through
//      `/admin-api/config`, and the page drawn again draws both, unchanged,
//      in order.
//   2. A hand-written value set through `/admin-api` (indented, members in
//      an order of its own, `"lowAffinity": false`, no `bindings`) drawn by
//      the editor, saved untouched and read back BYTE FOR BYTE; then a box
//      ticked and unticked again, saved, and read back as the same JSON.
//   3. `piv.attestationAnchors`' PEM list: a Root made here pasted in, its
//      subject and SHA-256 drawn from the server's inspection, saved and
//      read back, removed, saved and read back empty.
//   4. `listeners.applications` on Server configuration → Listeners: an
//      entry added, saved and read back exactly, drawn again, removed,
//      saved.
//   5. A person's Credentials → Certificate sign-in sub-tab: a certificate
//      issued by the truststore Root UPLOADED from a file, the three derived
//      values (spki-sha256, issuer-serial, issuer-ski — computed here
//      independently too) drawn with the issuer found in the truststore,
//      each added, the ones held drawn as held, all three on the person
//      through `/admin-api/users`, one removed.
//
// **THE DEFECT IT FOUND (#2090, fixed here).** The derived values' Add
// forms are drawn after the page, so `ConsoleRuntime.draw()`'s
// `realmLinks()` never put the realm's prefix on their action: in a trust
// realm the console did not claim the press, and the browser POSTed it,
// natively, to the DEFAULT realm's /admin/users. `wire()` now takes the
// runtime's prefix. Section 5 also makes that stray post on purpose
// (theStrayPost()) and holds what a running service does with it — 404
// text/plain, an `admin.change` refused STS-ADMIN-0843 row, and nothing
// written to the default realm's person of the same username — so the
// question "could it write across realms" is answered by every run.
//
// Every key and certificate is made when it runs. **Every setting it
// changes is reset in a `finally`**, the anchor is removed (`pep-credential.
// js`'s settleAnchors(), which fails a passing run that leaves one), the
// console account is deleted, and the realm is the runner's to remove once
// the job passes (`tests/CLAUDE.md`, *A passing job removes its realms*).
// ===========================================================================

const assert = require("assert");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { Command, Option } = require("commander");
const { Builder, By } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const browserFlags = require("./browser_flags.js");
const credentials = require("../tools/pep-credential.js");
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
var log = bunyan.createLogger({ name: "sts_cert_sign_in_editors",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = Date.now().toString(36);
const REALM = "csedit-" + STAMP;
const USER = "cert-editors-" + STAMP;
const PASSWORD = "Cert-editors-Passw0rd!-" + STAMP;
const PERSON = "card-holder-" + STAMP;

// The settings this job writes, and the groups their Save posts with them:
// every key of these groups that was not overridden in the realm before the
// job is reset at the end.
const GROUPS = ["Certificate sign-in", "PIV", "Custom listeners"];
const PROFILES = "certSignIn.profiles";
const ANCHORS = "piv.attestationAnchors";
const MAPPING = "listeners.applications";

const PEM_BLOCK =
  /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/;

// How long a pressed form or a switch has to be drawn. A press here is
// answered in about a second; `sts_xacml_editor.js`'s PRESSED_MS argues the
// bound (the first form a tab posts fetches the 7 MB OpenAPI document).
const PRESSED_MS = 45000;
const PRESS_MARK = "__stsCertSignInEditorsPress";

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function realmPath(p) {
  log.debug("Entering realmPath().");
  log.debug("Leaving realmPath().");
  return "/realm/" + REALM + p;
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

// Every described setting of the realm's configuration answer, by key.
function settingsOf(node, into) {
  log.debug("Entering settingsOf().");
  const out = into || {};
  if (node && typeof node === "object") {
    if (!Array.isArray(node) && typeof node.key === "string" &&
        Object.prototype.hasOwnProperty.call(node, "text")) {
      out[node.key] = node;
    }
    Object.keys(node).forEach(function (k) {
      settingsOf(node[k], out);
    });
  }
  log.debug("Leaving settingsOf().");
  return out;
}

async function realmSettings() {
  log.debug("Entering realmSettings().");
  const r = await apiOk("GET", realmPath("/admin-api/config"));
  log.debug("Leaving realmSettings().");
  return settingsOf(r.json);
}

async function storedText(key) {
  log.debug("Entering storedText(). " + key);
  const all = await realmSettings();
  assert.ok(all[key], "the realm's configuration describes no " + key);
  log.debug("Leaving storedText().");
  return String(all[key].text == null ? "" : all[key].text);
}

// ---------------------------------------------------------------------------
// WHAT A CERTIFICATE SAYS, COMPUTED HERE WITHOUT THE SERVICE: the SHA-256 of
// its SubjectPublicKeyInfo, its serial as `bindingValueOf()` writes it, and
// its subjectKeyIdentifier read out of the DER.
// ---------------------------------------------------------------------------
function spkiSha256(pem) {
  log.debug("Entering spkiSha256().");
  const der = new crypto.X509Certificate(pem).publicKey
    .export({ type: "spki", format: "der" });
  log.debug("Leaving spkiSha256().");
  return crypto.createHash("sha256").update(der).digest("hex");
}

function serialOf(pem) {
  log.debug("Entering serialOf().");
  log.debug("Leaving serialOf().");
  return new crypto.X509Certificate(pem).serialNumber.toLowerCase()
    .replace(/^0+(?=[0-9a-f])/, "");
}

// The subjectKeyIdentifier extension (2.5.29.14): its OID, an optional
// critical BOOLEAN, then an OCTET STRING holding the OCTET STRING that is
// the identifier.
function skiOf(pem) {
  log.debug("Entering skiOf().");
  const der = new crypto.X509Certificate(pem).raw;
  const oid = Buffer.from([0x06, 0x03, 0x55, 0x1d, 0x0e]);
  let at = der.indexOf(oid);
  assert.ok(at >= 0, "the certificate carries no subjectKeyIdentifier");
  at += oid.length;
  if (der[at] === 0x01) {
    at += 3;
  }
  assert.strictEqual(der[at], 0x04, "the extension value is an OCTET STRING");
  at += 2;
  assert.strictEqual(der[at], 0x04, "the identifier is an OCTET STRING");
  const len = der[at + 1];
  log.debug("Leaving skiOf().");
  return der.slice(at + 2, at + 2 + len).toString("hex");
}

function hexOnly(text) {
  log.debug("Entering hexOnly().");
  log.debug("Leaving hexOnly().");
  return String(text || "").toLowerCase().replace(/[^0-9a-f]/g, "");
}

// ---------------------------------------------------------------------------
// THE BROWSER.
// ---------------------------------------------------------------------------
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

// What the page shows when a press was never answered: the URL, the flash
// strip and any error box.
async function evidence(driver) {
  log.debug("Entering evidence().");
  const shown = await driver.executeScript(`
    const strip = Array.from(document.querySelectorAll(
      '.flash, .err, .error, [role=alert]')).map(function (e) {
        return e.textContent.trim();
      }).filter(Boolean).join(' | ');
    const editors = Array.from(document.querySelectorAll(
      '[data-structured-for], [data-cert-binding]')).map(function (e) {
        return (e.getAttribute('data-structured-for') ||
                e.getAttribute('data-cert-binding')) + ': ' +
               e.textContent.replace(/\s+/g, ' ').trim().slice(0, 400);
      }).join(' || ');
    return location.href + ' ' + strip.slice(0, 600) + ' EDITORS: ' +
           editors;
  `).catch(function (e) {
    log.debug("Caught in evidence(): " + ((e && e.message) || e));
    return "(the page could not be read)";
  });
  log.debug("Leaving evidence().");
  return String(shown);
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
// the marked one (`sts_xacml_editor.js`'s arrangement). `find` is a script
// body answering the element to press, or a string saying why there is none.
//
// WHAT THE CONSOLE ASKS FOR FIRST (#2196) — a popup, a Continue, a sign-in
// again — is done in between as the person does it, and a page that left to
// sign in, which sent nothing, is pressed again.
async function pressAndWait(driver, find, args, what, pressedAgain) {
  log.debug("Entering pressAndWait(). " + what);
  const start = await steps.before();
  const token = STAMP + "-" + crypto.randomBytes(6).toString("hex");
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
  await driver.wait(async function () {
    const done = await driver.executeScript(FRAME_ANSWERED, PRESS_MARK,
                                            token).catch(function (e) {
      // A document being replaced under the probe: asked again.
      log.debug("Caught in pressAndWait(): " + ((e && e.message) || e));
      return false;
    });
    return done;
  }, PRESSED_MS, what + " was pressed and its answer was never drawn")
    .catch(async function (e) {
      log.debug("Caught in pressAndWait(): " + ((e && e.message) || e));
      throw new Error(((e && e.message) || e) + ". The page: " +
                      await evidence(driver));
    });
  log.debug("Leaving pressAndWait().");
}

// A page of the throwaway realm, through the shell's realm switcher, which
// draws it in place with the console's token (a document loaded under the
// realm's prefix would sign in at that realm, where this account is not).
// Asked again for the same page, it is the page drawn afresh from its API.
async function openInRealm(driver, to) {
  log.debug("Entering openInRealm(). " + to);
  const offered = await driver.executeScript(`
    const wanted = arguments[0];
    const pick = document.querySelector('form.realmpick select[name=realm]');
    return !!pick && Array.from(pick.options).some(function (o) {
      return o.value === wanted;
    });
  `, REALM).catch(function (e) {
    log.debug("Caught in openInRealm(): " + ((e && e.message) || e));
    return false;
  });
  if (!offered) {
    // The switcher lists the realms the page was loaded with.
    await driver.get(base + "/admin?realm=default");
    await waitForDrawn(driver);
  }
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
  assert.ok(at.indexOf("/realm/" + REALM + "/admin") >= 0,
            "the switch to " + REALM + " left the browser at " + at);
  log.debug("Leaving openInRealm().");
}

// Waits until a script answers something truthy, and answers it.
async function until(driver, script, args, what, ms) {
  log.debug("Entering until(). " + what);
  let last = null;
  let scriptError = "";
  const got = await driver.wait(async function () {
    last = await driver.executeScript(script, ...(args || []))
      .catch(function (e) {
        // A document being replaced under the probe: asked again, and the
        // reason kept for the failure.
        log.debug("Caught in until(): " + ((e && e.message) || e));
        scriptError = String((e && e.message) || e).slice(0, 300);
        return null;
      });
    return last || false;
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

// Runs one action inside an editor's place (`[data-structured-for=<box>]`)
// and answers '' or why it could not. The actions, all through the page's
// own events: click a selector; type into a selector (value set, `input`
// fired, and `change` when asked); choose an option of a select.
const ACT = `
  const place = document.querySelector('[data-structured-for="' +
                                        arguments[0] + '"]');
  if (!place) { return 'no editor for ' + arguments[0]; }
  const how = arguments[1];
  const el = place.querySelector(arguments[2]);
  if (!el) { return 'the editor has no ' + arguments[2]; }
  if (how === 'click') {
    el.click();
  } else {
    el.value = arguments[3];
    el.dispatchEvent(new Event('input', { bubbles: true }));
    if (how === 'type-change' || el.tagName === 'SELECT') {
      el.dispatchEvent(new Event('change', { bubbles: true }));
    }
  }
  return '';
`;

async function act(driver, box, how, selector, value) {
  log.debug("Entering act(). " + how + " " + selector);
  const done = await driver.executeScript(ACT, box, how, selector,
                                          value === undefined ? "" : value);
  assert.strictEqual(done, "", done);
  log.debug("Leaving act().");
}

// The profiles editor as drawn: each card's legend, text fields, ticked and
// disabled boxes, listed values, and the box under "As JSON".
const PROFILES_STATE = `
  const box = document.getElementById(arguments[0]);
  const place = document.querySelector('[data-structured-for="' +
                                        arguments[0] + '"]');
  if (!box || !place) { return null; }
  const cards = Array.from(place.querySelectorAll('fieldset.cs-card'));
  const boxes = function (card, sel) {
    return Array.from(card.querySelectorAll(sel)).map(function (b) {
      return { value: b.getAttribute('data-cs-value') ||
                      b.getAttribute('data-cs-flag'),
               on: b.checked, disabled: b.disabled };
    });
  };
  return {
    box: box.value,
    error: Array.from(place.querySelectorAll('.err')).map(function (e) {
      return e.textContent.trim(); }).join(' | '),
    pickOptions: Array.from(place.querySelectorAll(
      'select[data-cs-pick] option')).map(function (o) {
        return { value: o.value, text: o.textContent };
      }),
    cards: cards.map(function (card) {
      const text = function (name) {
        const i = card.querySelector('input[data-cs-text="' + name + '"]');
        return i ? i.value : null;
      };
      return {
        legend: card.querySelector('legend').textContent,
        id: text('id'), description: text('description'),
        smartCard: boxes(card, 'input[data-cs-flag="smartCard"]')[0],
        lowAffinity: boxes(card, 'input[data-cs-flag="lowAffinity"]')[0],
        keyUsage: boxes(card, 'input[data-cs-toggle="keyUsage"]'),
        eku: boxes(card, 'input[data-cs-toggle="extendedKeyUsage"]'),
        policies: boxes(card, 'input[data-cs-toggle="policies"]'),
        bindings: boxes(card, 'input[data-cs-toggle="bindings"]'),
        listed: Array.from(card.querySelectorAll('ul.cs-values li'))
          .map(function (li) {
            const b = li.querySelector('button');
            return { list: b.getAttribute('data-cs-list'),
                     value: li.querySelector('code').textContent,
                     label: (li.querySelector('span.sub') || {}).textContent
                            || '' };
          }),
        defaultNote: /uses the default/.test(card.textContent),
        up: (card.querySelector('[data-cs-act="move"][data-cs-delta="-1"]')
             || {}).disabled,
        down: (card.querySelector('[data-cs-act="move"][data-cs-delta="1"]')
               || {}).disabled
      };
    })
  };
`;

async function profilesState(driver, box) {
  log.debug("Entering profilesState().");
  const got = await driver.executeScript(PROFILES_STATE, box);
  log.debug("Leaving profilesState().");
  return got;
}

function ticked(list) {
  log.debug("Entering ticked().");
  log.debug("Leaving ticked().");
  return list.filter(function (b) { return b.on; })
    .map(function (b) { return b.value; });
}

// The Save of the settings group whose form holds a box.
const SAVE_OF = `
  const box = document.getElementById(arguments[0]);
  if (!box || !box.form) { return 'no form holds ' + arguments[0]; }
  return Array.from(box.form.querySelectorAll('button')).filter(function (b) {
    return b.type === 'submit' && !b.hasAttribute('formaction');
  })[0] || 'the form holding ' + arguments[0] + ' has no Save';
`;

async function save(driver, box) {
  log.debug("Entering save(). " + box);
  await pressAndWait(driver, SAVE_OF, [box], "the Save of " + box);
  log.debug("Leaving save().");
}

// Waits for a structured setting's editor to be drawn (and, for the
// profiles, the truststore read).
async function editorReady(driver, box) {
  log.debug("Entering editorReady(). " + box);
  await until(driver, `
    const place = document.querySelector('[data-structured-for="' +
                                          arguments[0] + '"]');
    if (!place) { return false; }
    if (/Reading the client truststore/.test(place.textContent)) {
      return false;
    }
    return !!place.querySelector('[data-cs-act]') ||
           !!place.querySelector('.warn, .err');
  `, [box], "the editor of " + box + " was never drawn");
  log.debug("Leaving editorReady().");
}

// ---------------------------------------------------------------------------
// 1 AND 2. THE PROFILES.
// ---------------------------------------------------------------------------
const PROFILES_BOX = "cfg-certSignIn-profiles";
const CARD = function (i) {
  return '[data-cs-i="' + i + '"]';
};

async function theProfilesEditor(driver, root) {
  log.debug("Entering theProfilesEditor().");
  const rootSpki = spkiSha256(root.pem);
  log.info("=== 1. Protocols → PIV: a profile written with the editor ===");
  await openInRealm(driver, "/admin/piv");
  await editorReady(driver, PROFILES_BOX);
  let now = await profilesState(driver, PROFILES_BOX);
  check("the profiles editor is drawn over an empty box", function () {
    assert.ok(now, "no profiles editor on /admin/piv");
    assert.strictEqual(now.box, "");
    assert.deepStrictEqual(now.cards, []);
  });

  await act(driver, PROFILES_BOX, "click", '[data-cs-act="add"]');
  await until(driver, "return !!document.querySelector(" +
              "'[data-structured-for=\"" + PROFILES_BOX + "\"] " +
              "select[data-cs-pick] option');", [],
              "the truststore's CAs were never offered to pick");
  now = await profilesState(driver, PROFILES_BOX);
  check("Add draws one new card, profile-1, with the default bindings " +
        "ticked and nothing written yet but its id", function () {
          assert.strictEqual(now.cards.length, 1);
          assert.strictEqual(now.cards[0].id, "profile-1");
          assert.deepStrictEqual(ticked(now.cards[0].bindings),
                                 ["certificate-sha256", "issuer-serial"]);
          assert.strictEqual(now.box, '[{"id":"profile-1","issuers":[]}]');
          assert.ok(now.cards[0].up && now.cards[0].down,
                    "a single card moves neither way");
        });
  check("the truststore's Root this job added is offered to pick, by " +
        "subject and its SubjectPublicKeyInfo's SHA-256", function () {
          const mine = now.pickOptions.filter(function (o) {
            return o.value === rootSpki;
          });
          assert.strictEqual(mine.length, 1, JSON.stringify(now.pickOptions));
          assert.ok(mine[0].text.indexOf(STAMP) >= 0, mine[0].text);
        });

  await act(driver, PROFILES_BOX, "type",
            'input[data-cs-text="id"]' + CARD(0), "piv-cards");
  await act(driver, PROFILES_BOX, "type",
            'input[data-cs-text="description"]' + CARD(0),
            "PIV cards under the test root");
  await act(driver, PROFILES_BOX, "click",
            'input[data-cs-flag="smartCard"]' + CARD(0));
  await driver.executeScript(
    "document.querySelector('[data-structured-for=\"" + PROFILES_BOX +
    "\"] select[data-cs-pick]').value = arguments[0];", rootSpki);
  await act(driver, PROFILES_BOX, "click",
            '[data-cs-act="add-pick"]' + CARD(0));
  await act(driver, PROFILES_BOX, "click",
            'input[data-cs-toggle="keyUsage"][data-cs-value=' +
            '"digitalSignature"]' + CARD(0));
  for (const oid of ["1.3.6.1.5.5.7.3.2", "1.3.6.1.4.1.311.20.2.2"]) {
    await act(driver, PROFILES_BOX, "click",
              'input[data-cs-toggle="extendedKeyUsage"][data-cs-value="' +
              oid + '"]' + CARD(0));
  }
  await act(driver, PROFILES_BOX, "click",
            'input[data-cs-toggle="policies"][data-cs-value=' +
            '"2.16.840.1.101.3.2.1.3.13"]' + CARD(0));
  for (const m of ["issuer-ski", "spki-sha256"]) {
    await act(driver, PROFILES_BOX, "click",
              'input[data-cs-toggle="bindings"][data-cs-value="' + m +
              '"]' + CARD(0));
  }
  await act(driver, PROFILES_BOX, "click",
            'input[data-cs-toggle="bindings"][data-cs-value=' +
            '"certificate-sha256"]' + CARD(0));
  now = await profilesState(driver, PROFILES_BOX);
  const card = now.cards[0];
  check("the picked issuer is listed with the Root's subject beside it",
        function () {
          assert.deepStrictEqual(card.listed.filter(function (v) {
            return v.list === "issuers";
          }).map(function (v) { return v.value; }), [rootSpki]);
          assert.ok(card.listed[0].label.indexOf(STAMP) >= 0,
                    JSON.stringify(card.listed));
        });
  check("the boxes ticked are the ones drawn ticked", function () {
    assert.deepStrictEqual(ticked(card.keyUsage), ["digitalSignature"]);
    assert.deepStrictEqual(ticked(card.eku),
                           ["1.3.6.1.5.5.7.3.2", "1.3.6.1.4.1.311.20.2.2"]);
    assert.deepStrictEqual(ticked(card.policies),
                           ["2.16.840.1.101.3.2.1.3.13"]);
    assert.deepStrictEqual(ticked(card.bindings),
                           ["issuer-serial", "issuer-ski", "spki-sha256"]);
    assert.strictEqual(card.smartCard.on, true);
  });
  const lowOf = function (c) {
    return c.bindings.filter(function (b) {
      return ["upn", "email", "issuer-subject", "subject"]
        .indexOf(b.value) >= 0;
    });
  };
  check("the four low-affinity boxes are DISABLED while lowAffinity is " +
        "unticked", function () {
          assert.strictEqual(card.lowAffinity.on, false);
          assert.deepStrictEqual(lowOf(card).map(function (b) {
            return b.value + ":" + b.disabled;
          }), ["upn:true", "email:true", "issuer-subject:true",
               "subject:true"]);
        });
  const before = now.box;
  await act(driver, PROFILES_BOX, "click",
            'input[data-cs-toggle="bindings"][data-cs-value="upn"]' +
            CARD(0));
  now = await profilesState(driver, PROFILES_BOX);
  check("and a press on a disabled one changes nothing", function () {
    assert.strictEqual(now.box, before);
    assert.strictEqual(lowOf(now.cards[0])[0].on, false);
  });
  await act(driver, PROFILES_BOX, "click",
            'input[data-cs-flag="lowAffinity"]' + CARD(0));
  now = await profilesState(driver, PROFILES_BOX);
  check("ticking lowAffinity enables them", function () {
    assert.ok(lowOf(now.cards[0]).every(function (b) {
      return !b.disabled;
    }), JSON.stringify(lowOf(now.cards[0])));
  });
  await act(driver, PROFILES_BOX, "click",
            'input[data-cs-toggle="bindings"][data-cs-value="upn"]' +
            CARD(0));
  now = await profilesState(driver, PROFILES_BOX);
  check("upn is ticked under the opt-in", function () {
    assert.deepStrictEqual(ticked(now.cards[0].bindings),
      ["issuer-serial", "issuer-ski", "spki-sha256", "upn"]);
  });
  await act(driver, PROFILES_BOX, "click",
            'input[data-cs-flag="lowAffinity"]' + CARD(0));
  now = await profilesState(driver, PROFILES_BOX);
  check("unticking lowAffinity takes upn out again and disables the " +
        "boxes", function () {
          assert.deepStrictEqual(ticked(now.cards[0].bindings),
            ["issuer-serial", "issuer-ski", "spki-sha256"]);
          assert.ok(lowOf(now.cards[0]).every(function (b) {
            return b.disabled && !b.on;
          }));
        });

  // The second profile: a typed issuer, refusals first.
  await act(driver, PROFILES_BOX, "click", '[data-cs-act="add"]');
  await act(driver, PROFILES_BOX, "type",
            'input[data-cs-text="id"]' + CARD(1), "name-fallback");
  await act(driver, PROFILES_BOX, "type",
            'input[data-cs-new="issuers"]' + CARD(1), "not-a-hash");
  await act(driver, PROFILES_BOX, "click",
            '[data-cs-act="add-value"][data-cs-list="issuers"]' + CARD(1));
  now = await profilesState(driver, PROFILES_BOX);
  check("a typed issuer that is not 64 hexadecimal digits is refused in " +
        "the editor", function () {
          assert.ok(now.error, "no refusal drawn");
          assert.deepStrictEqual(now.cards[1].listed, []);
        });
  // As an operator copies it from a certificate dump: upper case, colons.
  const typed = "sha256:" + rootSpki.toUpperCase().match(/../g).join(":");
  await act(driver, PROFILES_BOX, "type",
            'input[data-cs-new="issuers"]' + CARD(1), typed);
  await act(driver, PROFILES_BOX, "click",
            '[data-cs-act="add-value"][data-cs-list="issuers"]' + CARD(1));
  await act(driver, PROFILES_BOX, "type",
            'input[data-cs-new="extendedKeyUsage"]' + CARD(1), "1.2.x");
  await act(driver, PROFILES_BOX, "click",
            '[data-cs-act="add-value"][data-cs-list="extendedKeyUsage"]' +
            CARD(1));
  now = await profilesState(driver, PROFILES_BOX);
  check("a typed issuer with sha256:, colons and capitals is listed as its " +
        "64 digits, and an OID that is not one is refused", function () {
          assert.deepStrictEqual(now.cards[1].listed.map(function (v) {
            return v.list + "=" + v.value;
          }), ["issuers=" + rootSpki]);
          assert.ok(now.error, "no refusal drawn for 1.2.x");
        });
  await act(driver, PROFILES_BOX, "type",
            'input[data-cs-new="extendedKeyUsage"]' + CARD(1), "1.2.3.4.5");
  await act(driver, PROFILES_BOX, "click",
            '[data-cs-act="add-value"][data-cs-list="extendedKeyUsage"]' +
            CARD(1));
  await act(driver, PROFILES_BOX, "click",
            'input[data-cs-flag="lowAffinity"]' + CARD(1));
  await act(driver, PROFILES_BOX, "click",
            'input[data-cs-toggle="bindings"][data-cs-value="email"]' +
            CARD(1));
  // Reordered: the second card up, above the first.
  await act(driver, PROFILES_BOX, "click",
            '[data-cs-act="move"][data-cs-delta="-1"]' + CARD(1));

  const expected = [
    { id: "name-fallback", issuers: [rootSpki],
      extendedKeyUsage: ["1.2.3.4.5"],
      bindings: ["certificate-sha256", "issuer-serial", "email"],
      lowAffinity: true },
    { id: "piv-cards", description: "PIV cards under the test root",
      issuers: [rootSpki], keyUsage: ["digitalSignature"],
      extendedKeyUsage: ["1.3.6.1.5.5.7.3.2", "1.3.6.1.4.1.311.20.2.2"],
      policies: ["2.16.840.1.101.3.2.1.3.13"],
      bindings: ["issuer-serial", "issuer-ski", "spki-sha256"],
      smartCard: true }
  ];
  const expectedText = JSON.stringify(expected);
  now = await profilesState(driver, PROFILES_BOX);
  check("reordered, the cards are drawn in the new order and the box " +
        "holds exactly the JSON the editor was told", function () {
          assert.deepStrictEqual(now.cards.map(function (c) {
            return c.id;
          }), ["name-fallback", "piv-cards"]);
          assert.ok(now.cards[0].up === true &&
                    now.cards[0].down === false &&
                    now.cards[1].up === false && now.cards[1].down === true,
                    "the first card moves down only, the last up only");
          assert.strictEqual(now.box, expectedText);
        });
  await save(driver, PROFILES_BOX);
  const stored = await storedText(PROFILES);
  check("saved, " + PROFILES + " is EXACTLY that JSON through " +
        "/admin-api/config", function () {
          assert.strictEqual(stored, expectedText);
          assert.deepStrictEqual(JSON.parse(stored), expected);
        });

  await openInRealm(driver, "/admin/piv");
  await editorReady(driver, PROFILES_BOX);
  now = await profilesState(driver, PROFILES_BOX);
  check("drawn again, both profiles are drawn unchanged, in order",
        function () {
          assert.strictEqual(now.box, expectedText);
          assert.deepStrictEqual(now.cards.map(function (c) {
            return [c.id, c.description, c.smartCard.on, c.lowAffinity.on,
                    ticked(c.keyUsage), ticked(c.eku), ticked(c.policies),
                    ticked(c.bindings), c.listed.map(function (v) {
                      return v.list + "=" + v.value;
                    })];
          }), [
            ["name-fallback", "", false, true, [], [], [],
             ["certificate-sha256", "issuer-serial", "email"],
             ["issuers=" + rootSpki, "extendedKeyUsage=1.2.3.4.5"]],
            ["piv-cards", "PIV cards under the test root", true, false,
             ["digitalSignature"],
             ["1.3.6.1.5.5.7.3.2", "1.3.6.1.4.1.311.20.2.2"],
             ["2.16.840.1.101.3.2.1.3.13"],
             ["issuer-serial", "issuer-ski", "spki-sha256"],
             ["issuers=" + rootSpki]]
          ]);
          assert.ok(now.cards[0].legend.indexOf("name-fallback") >= 0,
                    now.cards[0].legend);
        });

  log.info("=== 2. a hand-written value, through the editor unchanged ===");
  const hand = "[\n  {\n    \"description\": \"Written by hand\",\n" +
    "    \"id\": \"hand-written\",\n    \"lowAffinity\": false,\n" +
    "    \"issuers\": [\"" + rootSpki + "\"],\n    \"policies\": [],\n" +
    "    \"smartCard\": false\n  }\n]";
  await apiOk("POST", realmPath("/admin-api/config/set"),
              { key: PROFILES, value: hand });
  const handStored = await storedText(PROFILES);
  check("a hand-written value set through /admin-api is stored as written",
        function () {
          assert.strictEqual(handStored, hand);
        });
  await openInRealm(driver, "/admin/piv");
  await editorReady(driver, PROFILES_BOX);
  now = await profilesState(driver, PROFILES_BOX);
  check("the editor draws it: its id, lowAffinity unticked, the default " +
        "bindings ticked, the box untouched", function () {
          assert.strictEqual(now.box, hand);
          assert.strictEqual(now.cards.length, 1);
          assert.strictEqual(now.cards[0].id, "hand-written");
          assert.strictEqual(now.cards[0].description, "Written by hand");
          assert.strictEqual(now.cards[0].lowAffinity.on, false);
          assert.deepStrictEqual(ticked(now.cards[0].bindings),
                                 ["certificate-sha256", "issuer-serial"]);
          assert.ok(now.cards[0].defaultNote,
                    "no note that the default bindings apply");
          assert.strictEqual(now.error, "");
        });
  await save(driver, PROFILES_BOX);
  const handAgain = await storedText(PROFILES);
  check("saved without a change, it comes back BYTE FOR BYTE", function () {
    assert.strictEqual(handAgain, hand);
  });
  await openInRealm(driver, "/admin/piv");
  await editorReady(driver, PROFILES_BOX);
  await act(driver, PROFILES_BOX, "click",
            'input[data-cs-flag="smartCard"]' + CARD(0));
  await act(driver, PROFILES_BOX, "click",
            'input[data-cs-flag="smartCard"]' + CARD(0));
  now = await profilesState(driver, PROFILES_BOX);
  const canonical = JSON.stringify(JSON.parse(hand));
  check("a box ticked and unticked rewrites the box as the same JSON: " +
        "every member kept, in its order, an empty list and a false " +
        "flag included, no bindings added", function () {
          assert.strictEqual(now.box, canonical);
        });
  await save(driver, PROFILES_BOX);
  const handCanonical = await storedText(PROFILES);
  check("and saved, it is that JSON", function () {
    assert.strictEqual(handCanonical, canonical);
  });
  log.debug("Leaving theProfilesEditor().");
}

// ---------------------------------------------------------------------------
// 3. THE PEM LIST.
// ---------------------------------------------------------------------------
const ANCHORS_BOX = "cfg-piv-attestationAnchors";

async function thePemList(driver, anchor) {
  log.debug("Entering thePemList().");
  log.info("=== 3. " + ANCHORS + ": a CA pasted in, saved, removed ===");
  const block = anchor.pem.match(PEM_BLOCK)[0];
  const x = new crypto.X509Certificate(anchor.pem);
  await openInRealm(driver, "/admin/piv");
  await editorReady(driver, ANCHORS_BOX);
  await act(driver, ANCHORS_BOX, "type", "textarea[data-cs-pem]",
            anchor.pem);
  await act(driver, ANCHORS_BOX, "click", '[data-cs-act="add-pems"]');
  const rows = await until(driver, `
    // \`:scope\`: the editor sits in a row of the settings table, whose own
    // tbody would make the editor's header row match a bare 'tbody tr'.
    const place = document.querySelector('[data-structured-for="' +
                                          arguments[0] + '"]');
    const rows = Array.from(place.querySelectorAll(':scope tbody tr'));
    if (!rows.length || rows.some(function (r) {
      return !r.querySelector('code'); })) { return null; }
    return { box: document.getElementById(arguments[0]).value,
             rows: rows.map(function (r) {
               const td = r.querySelectorAll('td');
               return { subject: td[0].textContent,
                        fingerprint: td[1].textContent,
                        notAfter: td[2].textContent };
             }) };
  `, [ANCHORS_BOX], "the pasted CA's subject and SHA-256 were never drawn");
  check("the pasted CA is drawn with its subject and SHA-256, as the " +
        "server read it", function () {
          assert.strictEqual(rows.rows.length, 1);
          assert.ok(rows.rows[0].subject.indexOf(STAMP) >= 0,
                    rows.rows[0].subject);
          assert.strictEqual(hexOnly(rows.rows[0].fingerprint),
                             hexOnly(x.fingerprint256));
          assert.strictEqual(rows.rows[0].notAfter,
                             new Date(x.validTo).toISOString().slice(0, 10));
          assert.strictEqual(rows.box, block + "\n");
        });
  await save(driver, ANCHORS_BOX);
  const stored = await storedText(ANCHORS);
  check("saved, " + ANCHORS + " is that certificate", function () {
    assert.strictEqual(stored, block + "\n");
  });
  await openInRealm(driver, "/admin/piv");
  await editorReady(driver, ANCHORS_BOX);
  await until(driver, `
    const place = document.querySelector('[data-structured-for="' +
                                          arguments[0] + '"]');
    return !!place.querySelector(':scope tbody tr code');
  `, [ANCHORS_BOX], "the saved CA was not drawn again");
  await act(driver, ANCHORS_BOX, "click", '[data-cs-act="remove"]');
  const empty = await driver.executeScript(
    "return document.getElementById(arguments[0]).value;", ANCHORS_BOX);
  check("Remove empties the list and the box", function () {
    assert.strictEqual(empty, "");
  });
  await save(driver, ANCHORS_BOX);
  const after = await storedText(ANCHORS);
  check("saved, " + ANCHORS + " is empty again", function () {
    assert.strictEqual(after, "");
  });
  log.debug("Leaving thePemList().");
}

// ---------------------------------------------------------------------------
// 4. ONE LISTENER EDITOR: listeners.applications.
// ---------------------------------------------------------------------------
const MAPPING_BOX = "cfg-listeners-applications";

async function theMappingEditor(driver) {
  log.debug("Entering theMappingEditor().");
  log.info("=== 4. " + MAPPING + ": an entry added, saved, removed ===");
  await openInRealm(driver, "/admin/listeners#tab-applications");
  await editorReady(driver, MAPPING_BOX);
  const was = await storedText(MAPPING);
  check("the realm maps nothing of its own to begin with", function () {
    assert.strictEqual(was, "");
  });
  await act(driver, MAPPING_BOX, "click", '[data-cs-act="add"]');
  await act(driver, MAPPING_BOX, "type", 'input[data-cs-text="app"]',
            "scep");
  await act(driver, MAPPING_BOX, "type-change",
            'input[data-cs-text="listeners"]', "main");
  await act(driver, MAPPING_BOX, "type", 'select[data-cs-text="advertised"]',
            "main");
  const expected = JSON.stringify({ scep: { listeners: ["main"],
                                            advertised: "main" } });
  const drawn = await driver.executeScript(`
    const place = document.querySelector('[data-structured-for="' +
                                          arguments[0] + '"]');
    return { box: document.getElementById(arguments[0]).value,
             options: Array.from(place.querySelectorAll(
               'select[data-cs-text="advertised"] option')).map(
                 function (o) { return o.value; }) };
  `, MAPPING_BOX);
  check("the entry is in the box as JSON, and the advertised listener is " +
        "chosen from the listeners typed", function () {
          assert.strictEqual(drawn.box, expected);
          assert.deepStrictEqual(drawn.options, ["", "main"]);
        });
  await save(driver, MAPPING_BOX);
  const stored = await storedText(MAPPING);
  check("saved, " + MAPPING + " is exactly that JSON", function () {
    assert.strictEqual(stored, expected);
  });
  await openInRealm(driver, "/admin/listeners#tab-applications");
  await editorReady(driver, MAPPING_BOX);
  const again = await driver.executeScript(`
    const place = document.querySelector('[data-structured-for="' +
                                          arguments[0] + '"]');
    const v = function (s) { const e = place.querySelector(s);
                             return e ? e.value : null; };
    return { app: v('input[data-cs-text="app"]'),
             listeners: v('input[data-cs-text="listeners"]'),
             advertised: v('select[data-cs-text="advertised"]') };
  `, MAPPING_BOX);
  check("drawn again, the entry is drawn as it was saved", function () {
    assert.deepStrictEqual(again, { app: "scep", listeners: "main",
                                    advertised: "main" });
  });
  await act(driver, MAPPING_BOX, "click", '[data-cs-act="remove"]');
  await save(driver, MAPPING_BOX);
  const after = await storedText(MAPPING);
  check("removed and saved, " + MAPPING + " is empty again", function () {
    assert.strictEqual(after, "");
  });
  log.debug("Leaving theMappingEditor().");
}

// ---------------------------------------------------------------------------
// 5. A PERSON'S BINDINGS.
// ---------------------------------------------------------------------------
async function heldBindings(inDefault) {
  log.debug("Entering heldBindings().");
  const p = "/admin-api/users?user=" + encodeURIComponent(PERSON);
  const r = await apiOk("GET", inDefault ? p : realmPath(p));
  let found = [];
  const walk = function (node) {
    if (node && typeof node === "object") {
      if (!Array.isArray(node) && node.name === "stsCertificateBinding" &&
          Array.isArray(node.values)) {
        found = node.values.map(String);
      }
      Object.keys(node).forEach(function (k) {
        walk(node[k]);
      });
    }
  };
  walk(r.json);
  log.debug("Leaving heldBindings().");
  return found.slice(0).sort();
}

// The person's page on the sub-tab, the certificate UPLOADED through the
// file input, derived, and the derived table answered.
async function derive(driver, file) {
  log.debug("Entering derive().");
  await openInRealm(driver, "/admin/users?user=" +
                    encodeURIComponent(PERSON) + "#ucred-cert-binding");
  await until(driver, "return !!document.querySelector(" +
              "'[data-cert-binding] [data-cb-pem-file]');", [],
              "the person's certificate binding sub-tab was never drawn");
  const input = await driver.findElement(
    By.css("[data-cert-binding] input[data-cb-pem-file]"));
  await input.sendKeys(file);
  await until(driver, "const a = document.querySelector(" +
              "'[data-cert-binding] [data-cb-pem]');" +
              "return !!a && /BEGIN CERTIFICATE/.test(a.value);", [],
              "the uploaded file never reached the box");
  await driver.executeScript("document.querySelector(" +
                             "'[data-cert-binding] [data-cb-derive]')" +
                             ".click();");
  const got = await until(driver, `
    const result = document.querySelector('[data-cert-binding] ' +
                                          '[data-cb-result]');
    if (!result || !result.querySelector('tr td, .err')) { return null; }
    return { text: result.textContent,
             error: (result.querySelector('.err') || {}).textContent || '',
             rows: Array.from(result.querySelectorAll(':scope tbody tr'))
               .map(function (tr) {
                 const code = tr.querySelectorAll('code');
                 return { method: code[0].textContent,
                          value: code[1].textContent,
                          add: !!tr.querySelector('form button'),
                          held: !tr.querySelector('form') };
               }) };
  `, [], "the derived values were never drawn");
  log.debug("Leaving derive().");
  return got;
}

// ---------------------------------------------------------------------------
// THE STRAY POST (#2096). Until this job, the derived Add forms were drawn
// after the page and without the realm's prefix, so in a trust realm the
// console did not claim them and the BROWSER posted them, natively, to the
// DEFAULT realm's /admin/users. That post is made here on purpose, from the
// realm's sub-tab with the browser's own cookies — once through fetch(), to
// read what the server answers, and once as a native form submission, which
// is exactly what the unclaimed form did — and what it could have reached
// is read back: the default realm's person of the SAME username, and the
// default realm's audit log. The answer must be the static console's
// refusal (404, text/plain), and nothing may change anywhere.
// ---------------------------------------------------------------------------
async function auditNaming(since) {
  log.debug("Entering auditNaming().");
  const r = await apiOk("GET", "/admin-api/audit?per=300");
  const rows = [];
  const all = [];
  const walk = function (node) {
    if (Array.isArray(node)) {
      node.forEach(walk);
    } else if (node && typeof node === "object") {
      // `at` is milliseconds; a read through this API (`api.read`) and
      // the request log (`protocol.call`) name the person without being a
      // change, so only the directory's own rows are asked about.
      const when = typeof node.at === "number" ? node.at
        : Date.parse(node.time || node.timestamp || "");
      if (typeof node.action === "string" && node.category) {
        all.push(node);
        if (when >= since && node.category === "directory" &&
            JSON.stringify(node).indexOf(PERSON) >= 0) {
          rows.push(node);
        }
      } else {
        Object.keys(node).forEach(function (k) {
          walk(node[k]);
        });
      }
    }
  };
  walk(r.json);
  log.debug("Leaving auditNaming().");
  return {
    changes: rows,
    // The control: the twin's own creation, before `since`, is found by
    // the same reading, so an empty `changes` is not a reader seeing
    // nothing.
    created: all.filter(function (n) {
      return n.category === "directory" && n.action === "user.create" &&
             JSON.stringify(n).indexOf(PERSON) >= 0;
    }).length,
    // What the audit log recorded of the stray posts: the console's
    // refusal of a non-GET, as an `admin.change` row.
    posts: all.filter(function (n) {
      return n.action === "admin.change" && n.at >= since &&
             String(n.target) === "/admin/users";
    }).map(function (n) {
      return n.outcome + " " + n.errorCode + " " + n.summary;
    })
  };
}

async function theStrayPost(driver, value) {
  log.debug("Entering theStrayPost().");
  const since = Date.now() - 1000;
  const body = "action=add-attribute&user=" + encodeURIComponent(PERSON) +
    "&from=user&attribute=stsCertificateBinding&value=" +
    encodeURIComponent(value);
  const fetched = await driver.executeAsyncScript(`
    const done = arguments[arguments.length - 1];
    fetch('/admin/users', { method: 'POST', credentials: 'same-origin',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: arguments[0] }).then(function (r) {
        return r.text().then(function (text) {
          done({ status: r.status, type: r.headers.get('content-type'),
                 text: text.slice(0, 300) });
        });
      }, function (e) { done({ error: String(e) }); });
  `, body);
  check("a POST to the default realm's /admin/users, with the browser's " +
        "cookies, is answered 404 text/plain by the static console and " +
        "acts on nothing", function () {
          assert.strictEqual(fetched.status, 404, JSON.stringify(fetched));
          assert.ok(/^text\/plain/.test(String(fetched.type)),
                    JSON.stringify(fetched));
          assert.ok(/nothing is posted here/.test(fetched.text),
                    fetched.text);
        });
  // As the unclaimed form did: a native submission, which fires no submit
  // event the console could claim.
  await driver.executeScript(`
    const f = document.createElement('form');
    f.method = 'post';
    f.action = '/admin/users';
    new URLSearchParams(arguments[0]).forEach(function (v, k) {
      const i = document.createElement('input');
      i.type = 'hidden'; i.name = k; i.value = v;
      f.appendChild(i);
    });
    document.body.appendChild(f);
    HTMLFormElement.prototype.submit.call(f);
  `, body);
  const landed = await until(driver, `
    if (location.pathname !== '/admin/users' ||
        document.readyState !== 'complete') { return null; }
    return { url: location.href, text: document.body.innerText };
  `, [], "the native submission never landed on /admin/users");
  const twin = await heldBindings(true);
  const mine = await heldBindings(false);
  const audit = await auditNaming(since);
  check("submitted natively it lands on the same refusal, and neither the " +
        "default realm's " + PERSON + " nor the realm's holds the value, " +
        "and the default realm's audit log names neither", function () {
          assert.ok(/nothing is posted here/.test(landed.text),
                    JSON.stringify(landed));
          assert.deepStrictEqual(twin, []);
          assert.deepStrictEqual(mine, []);
          assert.deepStrictEqual(audit.changes, []);
          assert.ok(audit.created >= 1, "the audit reading found not even " +
                    "the twin's creation: " + JSON.stringify(audit));
        });
  check("and the default realm's audit log records both posts as the " +
        "static console's refusal (STS-ADMIN-0843, 404)", function () {
          assert.deepStrictEqual(audit.posts, [0, 1].map(function () {
            return "refused STS-ADMIN-0843 [STS-ADMIN-0843] POST " +
                   "/admin/users → 404 (add-attribute)";
          }), JSON.stringify(audit.posts));
        });
  log.debug("Leaving theStrayPost().");
}

async function thePersonsBindings(driver, root, leaf) {
  log.debug("Entering thePersonsBindings().");
  log.info("=== 5. a person's Credentials → Certificate sign-in ===");
  const rootSpki = spkiSha256(root.pem);
  const want = {
    "spki-sha256": "spki-sha256:" + spkiSha256(leaf.pem),
    "issuer-serial": "issuer-serial:" + rootSpki + ":" + serialOf(leaf.pem),
    "issuer-ski": "issuer-ski:" + rootSpki + ":" + skiOf(leaf.pem)
  };
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cert-editors-"));
  const file = path.join(dir, "card-holder.pem");
  fs.writeFileSync(file, leaf.pem);
  try {
    await theStrayPost(driver, want["spki-sha256"]);
    let got = await derive(driver, file);
    check("the uploaded certificate's issuer is found in the truststore " +
          "and its three values are drawn, each with an Add", function () {
            assert.strictEqual(got.error, "", got.text);
            assert.ok(/truststore/.test(got.text), got.text);
            assert.ok(got.text.indexOf(STAMP) >= 0, got.text);
            const drawn = {};
            got.rows.forEach(function (r) {
              drawn[r.method] = r.value;
            });
            assert.deepStrictEqual(drawn, want);
            assert.ok(got.rows.every(function (r) {
              return r.add;
            }), JSON.stringify(got.rows));
          });
    for (const method of ["spki-sha256", "issuer-serial", "issuer-ski"]) {
      await pressAndWait(driver, `
        const wanted = arguments[0];
        const rows = Array.from(document.querySelectorAll(
          '[data-cert-binding] [data-cb-result] tbody tr'));
        const row = rows.filter(function (tr) {
          return tr.querySelector('code').textContent === wanted;
        })[0];
        if (!row) { return 'no derived row for ' + wanted; }
        return row.querySelector('form button') ||
               wanted + ' is drawn as held already';
      `, [method], "the Add of " + method);
      if (method !== "issuer-ski") {
        got = await derive(driver, file);
        check("after adding " + method + ", it is drawn as held and the " +
              "others can still be added", function () {
                got.rows.forEach(function (r) {
                  const isHeld = r.method === method ||
                    (method === "issuer-serial" &&
                     r.method === "spki-sha256");
                  assert.strictEqual(r.held, isHeld, JSON.stringify(r));
                });
              });
      }
    }
    const held = await heldBindings();
    check("the person holds the three values, through /admin-api/users",
          function () {
            assert.deepStrictEqual(held, Object.keys(want).map(function (k) {
              return want[k];
            }).sort());
          });
    const table = await driver.executeScript(`
      return Array.from(document.querySelectorAll(
        'form input[name="attribute"][value="stsCertificateBinding"]'))
        .filter(function (i) {
          return !!i.form.querySelector(
            'input[name="action"][value="remove-attribute"]');
        })
        .map(function (i) {
          return i.form.querySelector('input[name="value"]').value;
        });
    `);
    check("the sub-tab's table draws the three, each with a Remove",
          function () {
            assert.deepStrictEqual(table.slice(0).sort(), held);
          });
    await pressAndWait(driver, `
      const wanted = arguments[0];
      const i = Array.from(document.querySelectorAll(
        'form input[name="attribute"][value="stsCertificateBinding"]'))
        .filter(function (i) {
          return !!i.form.querySelector(
            'input[name="action"][value="remove-attribute"]');
        })
        .filter(function (x) {
          return x.form.querySelector('input[name="value"]').value ===
                 wanted;
        })[0];
      return i ? i.form.querySelector('button') : 'no Remove for ' + wanted;
    `, [want["spki-sha256"]], "the Remove of spki-sha256");
    const left = await heldBindings();
    check("Remove takes that one value off the person and leaves the two",
          function () {
            assert.deepStrictEqual(left, [want["issuer-serial"],
                                          want["issuer-ski"]].sort());
          });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  log.debug("Leaving thePersonsBindings().");
}

// ---------------------------------------------------------------------------
// SETTING UP AND RESTORING.
// ---------------------------------------------------------------------------
async function setUp() {
  log.debug("Entering setUp().");
  await apiOk("POST", "/admin-api/realms/create", {
    id: REALM, domain: REALM + ".example.net",
    name: "Certificate sign-in editors test realm",
    description: "Created by tests/protocol/sts_cert_sign_in_editors.js " +
                 "(#2096); the runner removes it once the job passes.",
    overrides: { "global.mode": "development" }
  });
  // THE PASSWORD IS THE PERSON'S OWN (#2160): typed by an administrator it
  // is temporary in product, so it is a temporary one, and the person
  // chooses PASSWORD (`own_password.js`).
  const temporary = ownPassword.temporaryFor(PASSWORD);
  await apiOk("POST", "/admin-api/users/create", {
    username: USER, invent: false,
    attributes: { cn: USER, givenName: "Cert", sn: "Editors",
                  mail: USER + "@cert-editors.test" },
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
  await apiOk("POST", realmPath("/admin-api/users/create"), {
    username: PERSON, invent: false,
    attributes: { cn: "Card Holder " + STAMP, givenName: "Card",
                  sn: "Holder", mail: PERSON + "@cert-editors.test" } });
  // ITS TWIN IN THE DEFAULT REALM, the same username, which the stray post
  // (theStrayPost()) would have reached.
  await apiOk("POST", "/admin-api/users/create", {
    username: PERSON, invent: false,
    attributes: { cn: "Card Holder Twin " + STAMP, givenName: "Card",
                  sn: "Twin", mail: PERSON + "@twin.cert-editors.test" } });
  const before = await realmSettings();
  const overridden = Object.keys(before).filter(function (k) {
    return ["override", "realm"].indexOf(before[k].source) >= 0;
  });
  log.debug("Leaving setUp().");
  return { keys: Object.keys(before).filter(function (k) {
    return GROUPS.indexOf(before[k].group) >= 0 ||
           [PROFILES, ANCHORS, MAPPING].indexOf(k) >= 0;
  }), overridden: overridden };
}

// Every setting of the three groups the job's saves may have written, reset
// in the realm unless it was overridden before the job began.
async function restore(snapshot) {
  log.debug("Entering restore().");
  const problems = [];
  const now = await realmSettings().catch(function (e) {
    log.debug("Caught in restore(): " + ((e && e.message) || e));
    problems.push("the realm's settings could not be read: " + e.message);
    return {};
  });
  const keys = Object.keys(now).filter(function (k) {
    return ["override", "realm"].indexOf(now[k].source) >= 0 &&
           snapshot.overridden.indexOf(k) < 0 &&
           (snapshot.keys.indexOf(k) >= 0 || GROUPS.indexOf(now[k].group) >= 0);
  });
  for (const key of keys) {
    const r = await api("POST", realmPath("/admin-api/config/reset"),
                        { key: key });
    if (r.status !== 200) {
      problems.push(key + ": " + r.status + " " + r.raw.slice(0, 200));
    }
  }
  log.info("Reset " + keys.length + " setting(s) this job wrote in " +
           REALM + ": " + keys.join(", "));
  log.debug("Leaving restore().");
  return problems;
}

async function test() {
  log.debug("Entering test().");
  log.info("certificate sign-in's editors at " + base + ", realm " + REALM);
  // THE TRUSTSTORE'S ROOT, and the person's certificate it issued directly,
  // so the inspection finds the issuer in the truststore; and a second Root
  // for the attestation anchors. No distribution points: nothing here is
  // presented over TLS.
  const minted = await credentials.mint({
    crlBase: false,
    rootSubject: "CN=Cert editors test Root " + STAMP + ",O=iya-sts tests" });
  const root = minted.root;
  const leaf = (await credentials.reissue(
    { root: root, issuing: root, leaf: minted.leaf, issuingList: "" },
    { subject: "CN=Card Holder " + STAMP + ",O=iya-sts tests" })).leaf;
  const anchor = (await credentials.mint({
    crlBase: false,
    rootSubject: "CN=PIV attestation test Root " + STAMP +
                 ",O=iya-sts tests" })).root;

  let failure = null;
  let snapshot = null;
  let driver = null;
  // RECORDED BEFORE IT IS POSTED (#1307), so an add answered late is still
  // removed.
  const anchors = [];
  try {
    const added = await credentials.trustRecorded(base, root.pem, anchors);
    assert.ok(added.ok, added.why || ("POST /admin-api/tls/trust/add " +
                                      "answered " + added.status));
    snapshot = await setUp();
    const options = new chrome.Options();
    options.addArguments("--headless=new", "--no-sandbox",
        "--disable-dev-shm-usage", "--window-size=1400,1200");
    browserFlags.addBrowserAccessFlags(options, base);
    driver = await new Builder().forBrowser("chrome")
        .setChromeOptions(options).build();
    steps = consoleSteps.forDriver(driver, {
      credentials: function () {
        return { username: USER, password: PASSWORD };
      },
      log: log
    });
    await signIn(driver);
    await theProfilesEditor(driver, root);
    await thePemList(driver, anchor);
    await theMappingEditor(driver);
    await thePersonsBindings(driver, root, leaf);
  } catch (e) {
    log.debug("Caught in test(): " + ((e && e.message) || e));
    // Kept, and thrown once everything this job added is taken away.
    failure = e;
  }
  if (driver) {
    await driver.quit().catch(function (e) {
      log.debug("Caught in test() quitting: " + ((e && e.message) || e));
    });
  }
  const problems = snapshot ? await restore(snapshot) : [];
  await api("POST", "/admin-api/users/delete", { user: USER });
  await api("POST", "/admin-api/users/delete", { user: PERSON });
  if (problems.length && !failure) {
    failure = new Error("the settings this job wrote were not all reset: " +
                        problems.join("; "));
  }
  // Throws the job's own failure, or one for an anchor left behind.
  await credentials.settleAnchors(base, anchors, failure);
  assert.ok(checks >= 35, "only " + checks + " checks ran; a section has " +
                                            "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_cert_sign_in_editors")
  .description("Certificate sign-in's settings editors in a browser " +
               "(#2096).")
  .addOption(new Option("-u, --url <url>", "base url (this test reads it " +
                                           "from the environment)"))
  .parse(process.argv);

test().then(function () {
  process.exit(0);
}, function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
