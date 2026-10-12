// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: conformance_browser.js
//
// ---------------------------------------------------------------------------
// THE PERSON IN FRONT OF THE CONFORMANCE SUITE, IN A REAL BROWSER (#571,
// rcbj's decision, 2026-10-12).
//
// The OpenID Foundation's suite drives sign-in with a scripted browser of its
// own — HtmlUnit 4.17 on its Rhino fork at release-v5.3.1 — which runs no
// `class`, no `async function`, no array spread and has no `fetch`. Since
// #571 this service's sign-in screen is a static page drawn by its script,
// and that browser cannot draw it (measured: "identifier is a reserved word:
// class" on /authn/signin.js, the form never drawn). rcbj chose option 1 in
// its REAL-BROWSER form: the drivers stop handing the suite `browser`
// commands for this service's pages, so the suite does what it does for a
// human tester — it lists each address the person must visit on the module
// (`GET /api/runner/{id}` → `browser.urls`) — and this helper is that
// person: it opens each address in headless Chrome (the tests image's, as
// every browser job here), signs in on the real scripted screen, answers
// consent, lets the redirect return to the suite, and tells the suite the
// address was visited (`POST /api/runner/browser/{id}/visit?url=`).
//
// WHAT A HUMAN TESTER DOES, AND SO WHAT THIS DOES:
//
//   * Sign in, or the module's own action on the sign-in screen: Cancel for
//     user-rejects-authentication, only LOAD the screen for the first visit
//     of the reused-request_uri module, photograph it (prompt=login, max_age)
//     or only photograph it (the registration logo, policy and terms).
//   * Consent: Allow.
//   * An ERROR PAGE this service shows instead of redirecting (an
//     unregistered redirect_uri must not be redirected to), or the
//     end-session page: a screenshot UPLOADED to the module's image
//     placeholder through the suite's API (`POST /api/log/{id}/images/
//     {placeholder}`), which is how the suite asks a person for evidence —
//     a REVIEW outcome. The end-session confirmation is pressed where there
//     is one.
//   * A page of the suite's own (Session Management's check page) is opened
//     and given time for its script.
//
// THE PERSON'S BROWSER IS ONE BROWSER. Everything a module's person does —
// the authorization, the second authorization that finds the session, the
// end-session page — happens in this Chrome, because a session is a cookie
// and the suite's own browser would hold none of it. So the logout pages,
// although server-drawn, are visited here too.
//
// ONE CHROME PER JOB, ONE PAGE AT A TIME (no pooled fleets): visits are
// serialised by a lock, and since the suite gives every module a fresh
// browser of its own, the cookies are kept PER MODULE — saved after a visit
// and put back before the next one of the same module, the jar cleared in
// between — so modules of plans that run side by side never share a session.
//
// A LOCAL HELPER (MANIFEST.js's LOCAL_HELPERS): the conformance drivers share
// it; it owns no plan.
// ---------------------------------------------------------------------------

const fs = require("fs");
const nodeCrypto = require("crypto");
const bunyan = require("bunyan");
const { Builder, By } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const browserFlags = require("./browser_flags.js");

const log = bunyan.createLogger({ name: "conformance_browser",
                                  level: process.env.LOG_LEVEL || "info" });

// How long a page may take to move on before it is taken as where the flow
// stops.
const SETTLE_MS = Number(process.env.CONFORMANCE_BROWSER_SETTLE_MS) || 4000;

let shared = null;
let queue = Promise.resolve();

function waitMs(ms) {
  log.debug("Entering waitMs().");
  log.debug("Leaving waitMs().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

// The base64 SHA-256 of a certificate's SubjectPublicKeyInfo: what Chrome's
// --ignore-certificate-errors-spki-list wants (tests/tools/trust.js's
// spkiPin()).
function pinOf(file) {
  log.debug("Entering pinOf(). " + file);
  let pem = "";
  try {
    pem = fs.readFileSync(file, "utf8");
  } catch (e) {
    log.debug("Caught in pinOf(): " + ((e && e.message) || e));
    // No certificate there: nothing to pin.
    log.debug("Leaving pinOf(). None.");
    return "";
  }
  const der = new nodeCrypto.X509Certificate(pem).publicKey
    .export({ type: "spki", format: "der" });
  log.debug("Leaving pinOf().");
  return nodeCrypto.createHash("sha256").update(der).digest("base64");
}

// THE ONE CHROME, made when a module first needs it. The service's key and
// the suite's (conformance-tls's certificate) are trusted by pin, in ONE
// flag — Chrome keeps only the last occurrence of a switch
// (browser_flags.js says so at length).
async function browser(serviceBase) {
  log.debug("Entering browser().");
  if (shared) {
    log.debug("Leaving browser(). Shared.");
    return shared;
  }
  const options = new chrome.Options();
  options.addArguments("--headless=new", "--no-sandbox",
                       "--disable-dev-shm-usage", "--window-size=1100,900");
  browserFlags.addBrowserAccessFlags(options, serviceBase);
  const pins = [process.env.STS_SPKI_PIN, process.env.STACK_TLS_SPKI_PIN,
    pinOf(process.env.CONFORMANCE_SUITE_CA_FILE ||
          "/run/sts-test/conformance/server.crt")]
    .map(function (one) {
      return String(one || "").trim();
    }).filter(function (one, at, all) {
      return one && all.indexOf(one) === at;
    });
  if (pins.length) {
    options.addArguments("--ignore-certificate-errors-spki-list=" +
                         pins.join(","));
  }
  shared = await new Builder().forBrowser("chrome")
    .setChromeOptions(options).build();
  log.info("Opened the person's browser (headless Chrome) for the " +
           "conformance suite's sign-in steps.");
  log.debug("Leaving browser().");
  return shared;
}

// Closes the one Chrome, at the end of a job.
async function quit() {
  log.debug("Entering quit().");
  if (shared) {
    const was = shared;
    shared = null;
    try {
      await was.quit();
    } catch (e) {
      log.debug("Caught in quit(): " + ((e && e.message) || e));
      // Already gone: nothing to close.
    }
  }
  log.debug("Leaving quit().");
}

// One visit at a time, whatever plans run side by side.
function serially(work) {
  log.debug("Entering serially().");
  const run = queue.then(work, work);
  queue = run.then(function () {
    return null;
  }, function () {
    return null;
  });
  log.debug("Leaving serially().");
  return run;
}

/**
 * A person who answers the suite's browser steps for one set of plans.
 *
 * @param {object} o - `suite(method, path, body, contentType)` (the driver's
 *   client of the suite's API), `suiteBase` (its base URL), `serviceBase`
 *   (this service's root), `username`, `password` and `actions`: module
 *   name → `cancel`, `load-only`, `photograph` or `photograph-only`, a key
 *   ending in `*` matching by prefix and one beginning `*` by suffix
 * @returns {object} `{ visit(id, info) }`, a driver's `onWaiting`
 */
function person(o) {
  log.debug("Entering person().");
  const handled = {};
  const jars = {};
  const visits = {};
  const actionFor = function (moduleName) {
    log.debug("Entering actionFor().");
    const name = String(moduleName || "");
    const keys = Object.keys(o.actions || {});
    for (let i = 0; i < keys.length; i++) {
      const k = keys[i];
      const hit = k === name ||
        (k.slice(-1) === "*" && name.indexOf(k.slice(0, -1)) === 0) ||
        (k.charAt(0) === "*" && name.slice(-(k.length - 1)) === k.slice(1));
      if (hit) {
        log.debug("Leaving actionFor(). " + o.actions[k]);
        return o.actions[k];
      }
    }
    log.debug("Leaving actionFor(). Sign in.");
    return "sign-in";
  };
  log.debug("Leaving person().");
  return {
    visit: function (id, info) {
      log.debug("Entering visit(). " + id);
      log.debug("Leaving visit().");
      return visitWaiting(o, id, info, handled, jars, function (name) {
        log.debug("Entering the module's action.");
        visits[id] = (visits[id] || 0) + 1;
        const action = actionFor(name);
        log.debug("Leaving the module's action.");
        // `load-only` is the FIRST visit's: the reused-request_uri module
        // then asks for the same request again and expects a sign-in.
        return action === "load-only" && visits[id] > 1 ? "sign-in" : action;
      });
    }
  };
}

// The addresses the module asks a person to visit, not yet visited.
async function waitingUrls(o, id) {
  log.debug("Entering waitingUrls(). " + id);
  const r = await o.suite("GET", "api/runner/" + id);
  const browserState = (r.body && r.body.browser) || {};
  const out = (browserState.urlsWithMethod || []).map(function (u) {
    return { url: String(u.url), method: String(u.method || "GET") };
  });
  (browserState.urls || []).forEach(function (u) {
    if (!out.some(function (one) {
      return one.url === u;
    })) {
      out.push({ url: String(u), method: "GET" });
    }
  });
  log.debug("Leaving waitingUrls(). " + out.length);
  return out;
}

async function visitWaiting(o, id, info, handled, jars, actionFor) {
  log.debug("Entering visitWaiting(). " + id);
  if (!info || info.status !== "WAITING") {
    log.debug("Leaving visitWaiting(). Not waiting.");
    return;
  }
  const urls = await waitingUrls(o, id);
  for (let i = 0; i < urls.length; i++) {
    const key = id + " " + urls[i].url;
    if (handled[key]) {
      continue;
    }
    handled[key] = true;
    const one = urls[i];
    await serially(async function () {
      log.debug("Entering the visit.");
      await visitOne(o, id, info.testName, one, jars,
                     actionFor(info.testName));
      log.debug("Leaving the visit.");
    });
  }
  log.debug("Leaving visitWaiting().");
}

// The module's own cookies in the one browser: cleared, then put back.
async function useJar(driver, jars, id) {
  log.debug("Entering useJar(). " + id);
  await driver.sendDevToolsCommand("Network.clearBrowserCookies", {});
  if (jars[id] && jars[id].length) {
    await driver.sendDevToolsCommand("Network.setCookies",
                                     { cookies: jars[id] });
  }
  log.debug("Leaving useJar().");
}

async function keepJar(driver, jars, id) {
  log.debug("Entering keepJar(). " + id);
  const got = await driver.sendAndGetDevToolsCommand("Network.getAllCookies",
                                                     {});
  jars[id] = ((got && got.cookies) || []).map(function (c) {
    const out = { name: c.name, value: c.value, domain: c.domain,
                  path: c.path, secure: c.secure, httpOnly: c.httpOnly };
    if (c.sameSite) {
      out.sameSite = c.sameSite;
    }
    if (c.expires && c.expires > 0) {
      out.expires = c.expires;
    }
    return out;
  });
  log.debug("Leaving keepJar(). " + jars[id].length);
}

async function currentUrl(driver) {
  log.debug("Entering currentUrl().");
  let url = "";
  try {
    url = await driver.getCurrentUrl();
  } catch (e) {
    log.debug("Caught in currentUrl(): " + ((e && e.message) || e));
    // A navigation in flight; asked again.
    url = "";
  }
  log.debug("Leaving currentUrl().");
  return url;
}

// Waits for the address to change from `from`, or for `ms`.
async function moved(driver, from, ms) {
  log.debug("Entering moved().");
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const now = await currentUrl(driver);
    if (now && now !== from) {
      log.debug("Leaving moved(). Moved.");
      return now;
    }
    await waitMs(250);
  }
  log.debug("Leaving moved(). Stayed.");
  return "";
}

async function present(driver, cssId, ms) {
  log.debug("Entering present(). " + cssId);
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const found = await driver.findElements(By.id(cssId));
    if (found.length) {
      log.debug("Leaving present(). Yes.");
      return found[0];
    }
    await waitMs(250);
  }
  log.debug("Leaving present(). No.");
  return null;
}

// The page as the module's evidence, uploaded to its first unfilled
// placeholder — what a human tester's "upload an image" does.
async function photograph(o, driver, id, why) {
  log.debug("Entering photograph(). " + why);
  const images = await o.suite("GET", "api/log/" + id + "/images");
  const unfilled = (Array.isArray(images.body) ? images.body : [])
    .filter(function (entry) {
      return entry && entry.upload;
    });
  if (!unfilled.length) {
    log.debug("Leaving photograph(). No placeholder.");
    return false;
  }
  const png = await driver.takeScreenshot();
  const r = await o.suite("POST", "api/log/" + id + "/images/" +
                          encodeURIComponent(String(unfilled[0].upload)),
                          "data:image/png;base64," + png, "text/plain");
  log.info("  photographed " + why + " into the module's placeholder: " +
           r.status);
  log.debug("Leaving photograph().");
  return r.status === 200;
}

// Opens an address the module asked for: GET by navigating, POST as the
// suite's page posts it — a form of the address's query.
async function open(driver, one) {
  log.debug("Entering open(). " + one.method);
  if (String(one.method).toUpperCase() !== "POST") {
    await driver.get(one.url);
    log.debug("Leaving open(). GET.");
    return;
  }
  await driver.get("about:blank");
  await driver.executeScript(function (target) {
    const u = new URL(target);
    const form = document.createElement("form");
    form.method = "post";
    form.action = u.origin + u.pathname;
    u.searchParams.forEach(function (value, name) {
      const input = document.createElement("input");
      input.type = "hidden";
      input.name = name;
      input.value = value;
      form.appendChild(input);
    });
    document.body.appendChild(form);
    form.submit();
  }, one.url);
  log.debug("Leaving open(). POST.");
}

// ---------------------------------------------------------------------------
// ONE ADDRESS, followed as a person would until it reaches the suite or a
// page that stays.
// ---------------------------------------------------------------------------
async function visitOne(o, id, moduleName, one, jars, action) {
  log.debug("Entering visitOne(). " + moduleName + " " + action);
  const driver = await browser(o.serviceBase);
  await useJar(driver, jars, id);
  const suiteBase = String(o.suiteBase);
  let signedIn = false;
  let photographed = false;
  try {
    await open(driver, one);
    await o.suite("POST", "api/runner/browser/" + id + "/visit?url=" +
                  encodeURIComponent(one.url));
    for (let step = 0; step < 12; step++) {
      const here = await currentUrl(driver);
      let path = "";
      try {
        path = new URL(here).pathname;
      } catch (e) {
        log.debug("Caught in visitOne(): " + ((e && e.message) || e));
        // No address yet (a navigation in flight): taken as no page.
        path = "";
      }
      if (here.indexOf(suiteBase) === 0) {
        // THE SUITE'S OWN PAGE: its callback reports to the suite once its
        // script has run (`submission_complete`); a check page (Session
        // Management's) moves on by itself, to a result page of the suite.
        if (await present(driver, "submission_complete", 10000)) {
          break;
        }
        if (await moved(driver, here, 20000)) {
          continue;
        }
        break;
      }
      if (/\/authn\/login$/.test(path)) {
        const form = await present(driver, "kc-login", 15000);
        if (!form) {
          await photograph(o, driver, id, "a sign-in screen that never drew");
          break;
        }
        if (action === "load-only") {
          // Loaded, and left: the module's next request is the point.
          break;
        }
        if ((action === "photograph" || action === "photograph-only") &&
            !photographed) {
          photographed = true;
          await photograph(o, driver, id, "the sign-in screen");
          if (action === "photograph-only") {
            break;
          }
        }
        if (action === "cancel") {
          await (await driver.findElement(By.id("kc-cancel"))).click();
        } else if (!signedIn) {
          signedIn = true;
          const name = await driver.findElement(By.id("username"));
          await name.clear();
          await name.sendKeys(o.username);
          const pw = await driver.findElements(By.id("password"));
          if (pw.length) {
            await pw[0].sendKeys(o.password);
          }
          await (await driver.findElement(By.id("kc-login"))).click();
        } else {
          // Refused, and drawn again: the evidence, and where it stops.
          await photograph(o, driver, id, "a refused sign-in");
          break;
        }
        await moved(driver, here, 15000);
        continue;
      }
      // AN ADMINISTRATOR'S OFFERED SECOND FACTOR (#246), a page of the
      // sign-in surface since #572: Ignore, as a person who only wants to
      // sign in does. A REQUIRED set-up step has no Ignore, and is where
      // the flow stops (photographed below, as any page that stays).
      if (/\/authn\/mfa-setup$/.test(path)) {
        const ignore = await present(driver, "mfa-setup-ignore", 10000);
        if (ignore) {
          await ignore.click();
          await moved(driver, here, 15000);
          continue;
        }
      }
      if (/\/oauth2\/consent$/.test(path)) {
        const allow = await present(driver, "consent-allow", 10000);
        if (allow) {
          await allow.click();
          await moved(driver, here, 15000);
          continue;
        }
      }
      if (/\/oauth2\/logout$/.test(path)) {
        // THE END-SESSION PAGE: photographed as the module's evidence, the
        // confirmation pressed where there is one, and the return followed
        // (front-channel's notification page returns by a refresh). A page
        // that stays — a refusal, or a logout with nowhere to return to —
        // is where the flow ends, which is what those modules want.
        const yes = await driver.findElements(
          By.xpath("//button[@value='yes']"));
        if (yes.length) {
          await photograph(o, driver, id, "the end-session page");
          await yes[0].click();
          if (await moved(driver, here, 20000)) {
            continue;
          }
          break;
        }
        if (await moved(driver, here, 20000)) {
          continue;
        }
        await photograph(o, driver, id, "the page at " + path);
        break;
      }
      // ANY OTHER PAGE OF THIS SERVICE: one that moves on (an auto-posting
      // response, a redirect) is followed; one that stays is where the flow
      // ends — an error page this service shows rather than redirecting —
      // and is the module's evidence.
      if (await moved(driver, here, SETTLE_MS)) {
        continue;
      }
      await photograph(o, driver, id, "the page at " + path);
      break;
    }
  } catch (e) {
    log.warn("The person's visit to " + one.url + " for " + moduleName +
             " stopped: " + ((e && e.message) || e));
  }
  await keepJar(driver, jars, id);
  log.debug("Leaving visitOne().");
}

module.exports = {
  person: person,
  quit: quit
};
