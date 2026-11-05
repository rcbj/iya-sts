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
// AND IN THE RELYING-PARTY PLANS (#930), where the suite is the OpenID
// Provider and lists nothing to visit, the person STARTS at this service —
// `start()` opens a federation relationship's /federation/login/{id} and
// follows it through the suite and back — and `signOut()` signs out here and
// follows the partner's RP-Initiated Logout link the signed-out page offers.
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
const { Builder, By, logging } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const browserFlags = require("./browser_flags.js");

const log = bunyan.createLogger({ name: "conformance_browser",
                                  level: process.env.LOG_LEVEL || "info" });

// How long a page may take to move on before it is taken as where the flow
// stops.
const SETTLE_MS = Number(process.env.CONFORMANCE_BROWSER_SETTLE_MS) || 4000;

let shared = null;
// How many Chromes this process has opened with a network log (one file each).
let netlogCount = 0;
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
  // THE PAGES' CONSOLE, KEPT (#1293): a suite page whose own script never
  // moves on (Session Management's session_verify, whose RP iframe logs
  // every step) is otherwise a bare timeout. Read only by consoleOf().
  const prefs = new logging.Preferences();
  prefs.setLevel(logging.Type.BROWSER, logging.Level.ALL);
  options.setLoggingPrefs(prefs);
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
  // MORE FEATURES OFF, BY REQUEST (#1293): CONFORMANCE_BROWSER_DISABLE_FEATURES
  // is a comma list merged into the one --disable-features switch the access
  // flags already set (Chrome keeps only the last occurrence of a switch, so
  // a second one would undo theirs). For an experiment such as Session
  // Management's network-partitioning question; unset, nothing changes.
  const extra = String(process.env.CONFORMANCE_BROWSER_DISABLE_FEATURES ||
                       "").trim();
  if (extra) {
    const chromeOptions = options.get("goog:chromeOptions") || {};
    const args = chromeOptions.args || [];
    const at = args.findIndex(function (a) {
      return /^--disable-features=/.test(a);
    });
    if (at >= 0) {
      args[at] = args[at] + "," + extra;
    } else {
      args.push("--disable-features=" + extra);
    }
    log.info("Chrome features disabled on request: " + extra);
  }
  // CHROME'S OWN NETWORK LOG (#1293, rcbj 2026-11-04). Several modules on
  // the hosted suite stalled with test-idp never seeing the request; the
  // NetLog is written by Chrome itself, not through WebDriver, so it
  // survives a hung WebDriver call, and it records every request, the socket
  // and connection it rode, the TLS handshake and whether and when it ended.
  // CONFORMANCE_BROWSER_NETLOG names a directory; each Chrome this job opens
  // writes its own file there (a replaced browser starts a new one).
  const netlogDir = String(process.env.CONFORMANCE_BROWSER_NETLOG || "")
    .trim();
  if (netlogDir) {
    fs.mkdirSync(netlogDir, { recursive: true });
    netlogCount += 1;
    const file = require("path").join(netlogDir, "netlog-" + process.pid +
      "-" + netlogCount + "-" + Date.now() + ".json");
    options.addArguments("--log-net-log=" + file,
                         "--net-log-capture-mode=Default");
    log.info("Chrome's network log: " + file);
  }
  shared = await new Builder().forBrowser("chrome")
    .setChromeOptions(options).build();
  log.info("Opened the person's browser (headless Chrome) for the " +
           "conformance suite's sign-in steps.");
  await keepWarm(shared, serviceBase);
  log.debug("Leaving browser().");
  return shared;
}

// A WARM CONNECTION TO THE SERVICE (#1293, 2026-11-04): Session Management's
// second_session_verify loads our OP iframe and the suite's RP iframe side by
// side and posts its ONE message 500 ms after its own frame loads (#1297).
// From a distant browser, an OP iframe that needs a fresh TCP and TLS
// connection to the service spent 502 ms connecting before its request went
// out (the NetLog of the 11-04 run), and the message was gone before it
// listened; the same page over a reused connection answered in 294 ms. A
// background tab asks the service for its discovery document every
// CONFORMANCE_BROWSER_KEEP_WARM_MS, so a connection is always in the pool —
// the network a nearby browser would have, and nothing the service does
// differently. Off unless that variable is set (the certification tool sets
// it for a Session-only run, beside the partitioning switches).
async function keepWarm(driver, serviceBase) {
  log.debug("Entering keepWarm().");
  const every = Number(process.env.CONFORMANCE_BROWSER_KEEP_WARM_MS || 0);
  if (!(every > 0) || !serviceBase) {
    log.debug("Leaving keepWarm(). Off.");
    return;
  }
  try {
    const main = await driver.getWindowHandle();
    await driver.switchTo().newWindow("tab");
    await driver.get(String(serviceBase).replace(/\/+$/, "") +
                     "/.well-known/openid-configuration");
    // An <img> (the document's policy has img-src 'self'), not fetch()
    // (connect-src is 'none' there): the request is all that is wanted.
    await driver.executeScript(
      "var n = 0; setInterval(function () {" +
      "  var i = new Image(); i.src = location.pathname + '?warm=' + (n++);" +
      "}, arguments[0]);", every);
    await driver.switchTo().window(main);
    log.info("Keeping a connection to " + serviceBase + " warm every " +
             every + " ms from a background tab.");
  } catch (e) {
    log.debug("Caught in keepWarm(): " + ((e && e.message) || e));
    // Without it the run is what it was before, and goes on.
    log.info("Could not open the keep-warm tab: " +
             ((e && e.message) || e));
  }
  log.debug("Leaving keepWarm().");
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
// A VISIT HAS A DEADLINE (#1293, 2026-11-03). On the hosted suite one visit
// never returned — a WebDriver call that hung, with Chrome idle — and since
// visits hold one lock, every module after it timed out too: a 27-plan run
// lost to one stuck call. Past the deadline the visit is abandoned and its
// Chrome thrown away (closed in the background, never awaited, because the
// call that hung may hang the close as well); the next visit opens a fresh
// one. The module whose visit it was times out on its own and is re-run.
const VISIT_MS = Number(process.env.CONFORMANCE_BROWSER_VISIT_MS) || 180000;

function withDeadline(work) {
  log.debug("Entering withDeadline().");
  let timer = null;
  const deadline = new Promise(function (resolve) {
    timer = setTimeout(function () {
      log.warn("A browser visit ran past " + VISIT_MS + " ms; abandoning " +
               "it and replacing the browser.");
      const was = shared;
      shared = null;
      if (was) {
        was.quit().catch(function (e) {
          log.debug("Caught closing a stuck browser: " +
                    ((e && e.message) || e));
          // Gone or stuck: either way it is no longer the browser.
        });
      }
      resolve(null);
    }, VISIT_MS);
  });
  const done = Promise.resolve().then(work);
  log.debug("Leaving withDeadline().");
  return Promise.race([done, deadline]).finally(function () {
    clearTimeout(timer);
  });
}

function serially(work) {
  log.debug("Entering serially().");
  const guarded = function () {
    return withDeadline(work);
  };
  const run = queue.then(guarded, guarded);
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
 *   (this service's root), `username`, `password`, `markFirst` (report a
 *   listed address visited before opening it, #930) and `actions`: module
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
    },
    // THE PERSON STARTS AT THE RELYING PARTY (#930). In the suite's
    // relying-party plans the suite is the OpenID Provider and lists no
    // address: a person begins where an application sends them — this
    // service's /federation/login/{id} — and the browser carries them to
    // the suite's authorization endpoint and back. The address is not the
    // suite's, so it is not reported to the suite as visited.
    start: function (id, info, url) {
      log.debug("Entering start(). " + id);
      log.debug("Leaving start().");
      return serially(async function () {
        log.debug("Entering the start.");
        await visitOne(o, id, (info && info.testName) || "",
                       { url: String(url), method: "GET", noMark: true },
                       jars, "sign-in");
        log.debug("Leaving the start.");
      });
    },
    // AND SIGNS OUT THERE (#930): this service's /logout, the sign-out of
    // every session, and the partner's RP-Initiated Logout link the
    // signed-out page offers, followed as far as it goes.
    // `options.localOnly` ends the session here and follows no link to
    // the partner: for a module the suite has already finished, which a
    // visit would only disturb.
    signOut: function (id, info, base, options) {
      log.debug("Entering signOut(). " + id);
      log.debug("Leaving signOut().");
      return serially(async function () {
        log.debug("Entering the sign-out.");
        await signOutOne(o, id, (info && info.testName) || "", base, jars,
                         options || {});
        log.debug("Leaving the sign-out.");
      });
    }
  };
}

// The addresses the module asks a person to visit, not yet visited, and how
// many times the suite has recorded each address as visited.
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
  const seen = {};
  (browserState.visited || []).forEach(function (u) {
    seen[String(u)] = (seen[String(u)] || 0) + 1;
  });
  log.debug("Leaving waitingUrls(). " + out.length);
  return { urls: out, seen: seen };
}

// THE SAME ADDRESS ASKED FOR AGAIN IS ANOTHER VISIT. Two modules ask the
// person to open the very same authorization request twice: the
// reused-request_uri module (the first visit only loads the screen, the
// second signs in) and attempt-reuse-request_uri (the second must meet this
// service's refusal of a spent request_uri). The suite's BrowserControl keeps
// `urls` and `visited` as LISTS — a visit report removes one occurrence from
// the first and appends one to the second — so an address is asked for anew
// when it is pending while the suite has recorded every visit this person
// made to it. Until then a visit is queued or under way, and is not started
// twice. Keyed by the address alone, the second request was never answered
// and both modules waited out their time.
const MAX_VISITS_PER_ADDRESS = 4;

async function visitWaiting(o, id, info, handled, jars, actionFor) {
  log.debug("Entering visitWaiting(). " + id);
  if (!info || info.status !== "WAITING") {
    log.debug("Leaving visitWaiting(). Not waiting.");
    return;
  }
  const waiting = await waitingUrls(o, id);
  const urls = waiting.urls;
  for (let i = 0; i < urls.length; i++) {
    const key = id + " " + urls[i].url;
    const made = handled[key] || 0;
    if (made > (waiting.seen[urls[i].url] || 0) ||
        made >= MAX_VISITS_PER_ADDRESS) {
      continue;
    }
    handled[key] = made + 1;
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
// The browser console since the last read, every frame's, logged at info:
// for a suite page that never moved on.
async function consoleOf(driver, where) {
  log.debug("Entering consoleOf().");
  try {
    const entries = await driver.manage().logs().get(logging.Type.BROWSER);
    log.info("The browser console on " + where + " (" + entries.length +
             " entries):");
    entries.forEach(function (e) {
      log.info("  console " + e.level.name + ": " + e.message);
    });
  } catch (e) {
    log.debug("Caught in consoleOf(): " + ((e && e.message) || e));
    // A driver that keeps no log: nothing to add to the timeout.
  }
  log.debug("Leaving consoleOf().");
}

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
// THE PAGE'S PICTURES BEFORE ITS PHOTOGRAPH (#1293, 2026-11-04): the
// dynamic registration's logo module photographed the sign-in screen before
// the client's logo — fetched by the browser from the suite's own host, ~1 s
// away — had arrived, so the evidence showed the name and no logo. Every
// <img> on the page is waited for (loaded or failed) up to IMAGES_MS; one
// that failed is logged, since the screenshot would show it missing.
const IMAGES_MS = Number(process.env.CONFORMANCE_BROWSER_IMAGES_MS || 8000);
async function imagesSettled(driver, id) {
  log.debug("Entering imagesSettled().");
  try {
    const state = await driver.executeAsyncScript(
      "var done = arguments[arguments.length - 1];" +
      "var until = Date.now() + arguments[0];" +
      "(function poll() {" +
      "  var imgs = Array.prototype.slice.call(document.images || []);" +
      "  var pending = imgs.filter(function (i) { return !i.complete; });" +
      "  if (!pending.length || Date.now() > until) {" +
      "    done({ total: imgs.length, pending: pending.length," +
      "           broken: imgs.filter(function (i) {" +
      "             return i.complete && !i.naturalWidth; })" +
      "             .map(function (i) { return i.src; }) });" +
      "  } else { setTimeout(poll, 100); }" +
      "})();", IMAGES_MS);
    if (state && (state.pending || (state.broken || []).length)) {
      log.info("  images on the page for " + id + ": " + state.total +
               ", still loading " + state.pending + ", broken " +
               JSON.stringify(state.broken || []));
    }
  } catch (e) {
    log.debug("Caught in imagesSettled(): " + ((e && e.message) || e));
    // The script timed out or the page went: photograph what is there.
  }
  log.debug("Leaving imagesSettled().");
}

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
  const failed = await networkError(driver);
  if (failed) {
    log.warn("  " + id + ": not photographing Chrome's error page (" +
             failed + ") as " + why + "; the module's evidence is left " +
             "empty for its retry.");
    log.debug("Leaving photograph(). Chrome's error page.");
    return false;
  }
  await imagesSettled(driver, id);
  const png = await driver.takeScreenshot();
  // THE PAGE'S WORDS BESIDE ITS PICTURE (#1293, 2026-11-04): a reviewer
  // reads the screenshot, so its sentence is part of the certification; the
  // text is logged so a run can be checked for wording ("", "..", a code
  // path) without reading every image.
  try {
    const text = await driver.executeScript(
      "return document.body ? document.body.innerText : '';");
    log.info("  page text for " + id + ": " +
             String(text || "").replace(/\s+/g, " ").trim().slice(0, 1500));
  } catch (e) {
    log.debug("Caught in photograph(): " + ((e && e.message) || e));
    // No text: the picture is still the evidence.
  }
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
// A NAVIGATION THAT NEVER ARRIVES IS TRIED AGAIN (#1293, 2026-11-04). On
// the hosted suite a GET of test-idp's authorization endpoint once never
// reached the service (its per-minute request summary shows none), most
// likely a connection that had died between this machine and the load
// balancer, and WebDriver waits five minutes for a page load. The page load
// is held to PAGE_LOAD_MS; past it the browser stops, waits a moment and
// asks once more, on a fresh connection. A page the service is slow to draw
// still has 45 seconds, which is far more than any it serves.
const PAGE_LOAD_MS = Number(process.env.CONFORMANCE_BROWSER_PAGE_LOAD_MS) ||
                     45000;

async function getOnce(driver, url) {
  log.debug("Entering getOnce().");
  await driver.manage().setTimeouts({ pageLoad: PAGE_LOAD_MS });
  try {
    await driver.get(url);
  } catch (e) {
    // A NETWORK ERROR LEAVES THE BROWSER ON CHROME'S ERROR PAGE (2026-11-05)
    // rather than ending the visit: WebDriver throws `net::ERR_…` for some
    // failures (a refused connection) and not for others (a network change),
    // and in both cases the page to recover from is the same one, which
    // `follow()` loads again — see `networkError()`.
    if (/net::ERR_/.test(String((e && e.message) || ""))) {
      log.warn("  the browser could not load " + String(url).slice(0, 120) +
               " (" + String(e.message).split("\n")[0] + ")");
      log.debug("Leaving getOnce(). A network error.");
      return;
    }
    if (!/timeout/i.test(String((e && e.name) || "") + " " +
                         String((e && e.message) || ""))) {
      log.debug("Leaving getOnce(). Not a timeout.");
      throw e;
    }
    log.warn("  a page load passed " + PAGE_LOAD_MS + " ms; stopping it " +
             "and asking once more: " + String(url).slice(0, 120));
    try {
      await driver.executeScript("window.stop();");
    } catch (stopError) {
      log.debug("Caught in getOnce(): " +
                ((stopError && stopError.message) || stopError));
      // Nothing to stop: the retry below is the point.
    }
    await waitMs(1000);
    await driver.get(url);
  }
  log.debug("Leaving getOnce().");
}

async function open(driver, one) {
  log.debug("Entering open(). " + one.method);
  if (String(one.method).toUpperCase() !== "POST") {
    await getOnce(driver, one.url);
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
  try {
    // MARKED FIRST for a person who asks (#930): the third-party-initiated
    // login module refuses an authorization request that arrives before the
    // suite has recorded the visit to its initiate_login_uri, and opening
    // that address sends the browser straight on to the suite.
    if (!one.noMark && o.markFirst) {
      await o.suite("POST", "api/runner/browser/" + id + "/visit?url=" +
                    encodeURIComponent(one.url));
    }
    await open(driver, one);
    if (!one.noMark && !o.markFirst) {
      await o.suite("POST", "api/runner/browser/" + id + "/visit?url=" +
                    encodeURIComponent(one.url));
    }
    await follow(o, driver, id, action, suiteBase);
  } catch (e) {
    log.warn("The person's visit to " + one.url + " for " + moduleName +
             " stopped: " + ((e && e.message) || e));
  }
  await keepJar(driver, jars, id);
  log.debug("Leaving visitOne().");
}

// ---------------------------------------------------------------------------
// A PAGE CHROME COULD NOT LOAD IS LOADED AGAIN (2026-11-05). Another session
// on the same machine starting or stopping a Docker stack removes a bridge
// interface, the kernel announces an address change, and Chrome closes every
// connection and fails whatever was in flight with ERR_NETWORK_CHANGED — the
// link to test-idp never changed. The browser is left on its own error page
// at the address it was asked for, the suite's module goes on WAITING for a
// callback that never comes, and the run loses ten minutes to the module
// timeout before the retry does what a person would have done: load the
// page again. The OIDF re-run of 2026-11-05 lost twenty minutes this way
// (Form Post Hybrid's oidcc-claims-essential at 08:04:40, the NetLog's
// NETWORK_IP_ADDRESSES_CHANGED beside NetworkManager's bridge removal).
//
// `networkError()` names the error when the browser is on Chrome's error
// page (`chrome-error://chromewebdata/`), '' otherwise. `follow()` reloads a
// page of THIS SERVICE that failed this way, up to NETWORK_RETRIES times
// with a growing pause; the suite's module is still waiting, so the reload
// continues it exactly as the module retry would. A SUITE address is left
// alone: its callback may be a form POST, and loading it again as a GET is
// not the same request. And `photograph()` never uploads Chrome's error page
// as a module's evidence.
// ---------------------------------------------------------------------------
const NETWORK_RETRIES = 3;

async function networkError(driver) {
  log.debug("Entering networkError().");
  let out = "";
  try {
    out = String(await driver.executeScript(
      "if (document.documentURI !== 'chrome-error://chromewebdata/') " +
      "{ return ''; } var c = document.querySelector('.error-code'); " +
      "return (c && c.textContent.trim()) || 'a network error';") || "");
  } catch (e) {
    log.debug("Caught in networkError(): " + ((e && e.message) || e));
    // A page in the middle of loading: not an error page yet.
    out = "";
  }
  log.debug("Leaving networkError(). " + (out || "none"));
  return out;
}

// Where the browser goes from the page it is on, as a person would, until
// it reaches the suite's callback or a page that stays.
// THE PERSON'S AUTHENTICATOR APP (#1293). Where a driver gives the person a
// TOTP secret (`o.totpSecret`, base32, enrolled through the account API), a
// risk step-up to /authn/totp is answered with the current code (RFC 6238,
// the SHA-1 / 6-digit / 30 s defaults), so a sign-in the risk model scores
// MEDIUM completes as a person with an authenticator would complete it,
// instead of hanging the module. A code is never sent twice: the service
// refuses a replayed time step, so a second step-up inside the same 30 s
// waits for the next step.
let lastTotpStep = -1;

function base32Bytes(text) {
  log.debug("Entering base32Bytes().");
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const out = [];
  let bits = 0;
  let value = 0;
  String(text || "").toUpperCase().replace(/[^A-Z2-7]/g, "").split("")
    .forEach(function (ch) {
      value = (value << 5) | alphabet.indexOf(ch);
      bits += 5;
      if (bits >= 8) {
        out.push((value >>> (bits - 8)) & 255);
        bits -= 8;
      }
    });
  log.debug("Leaving base32Bytes().");
  return Buffer.from(out);
}

function totpAt(secret, step) {
  log.debug("Entering totpAt().");
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(step));
  const digest = nodeCrypto.createHmac("sha1", base32Bytes(secret))
    .update(message).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = ((digest[offset] & 0x7f) << 24) |
                 ((digest[offset + 1] & 0xff) << 16) |
                 ((digest[offset + 2] & 0xff) << 8) |
                 (digest[offset + 3] & 0xff);
  log.debug("Leaving totpAt().");
  return String(binary % 1000000).padStart(6, "0");
}

// The code for a time step not used before, waiting for the next step when
// this one was.
async function freshTotp(secret) {
  log.debug("Entering freshTotp().");
  let step = Math.floor(Date.now() / 30000);
  if (step <= lastTotpStep) {
    const wait = (lastTotpStep + 1) * 30000 - Date.now() + 500;
    log.info("  waiting " + Math.ceil(wait / 1000) + " s for a fresh " +
             "TOTP time step");
    await waitMs(Math.max(0, wait));
    step = Math.floor(Date.now() / 30000);
  }
  lastTotpStep = step;
  log.debug("Leaving freshTotp().");
  return totpAt(secret, step);
}

async function follow(o, driver, id, action, suiteBase) {
  log.debug("Entering follow(). " + action);
  let signedIn = false;
  let photographed = false;
  let reloads = 0;
  for (let step = 0; step < 12; step++) {
    const here = await currentUrl(driver);
    // CHROME'S OWN ERROR PAGE, for an address of this service: loaded again
    // (see `networkError()`), and the step counted against nothing.
    const failed = here && here.indexOf(suiteBase) !== 0
      ? await networkError(driver) : "";
    if (failed && reloads < NETWORK_RETRIES) {
      reloads += 1;
      log.warn("  " + id + ": the browser could not load " +
               here.slice(0, 120) + " (" + failed + "); loading it again (" +
               reloads + " of " + NETWORK_RETRIES + ")");
      await waitMs(2000 * Math.pow(2, reloads - 1));
      try {
        await getOnce(driver, here);
      } catch (e) {
        log.debug("Caught in follow(): " + ((e && e.message) || e));
        // Still failing: the next turn of the loop looks again.
      }
      step -= 1;
      continue;
    }
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
      // Stalled on the suite's own page: what its script said is the only
      // record of why (#1293).
      await consoleOf(driver, here);
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
    // A RISK STEP-UP (#1293): the person's authenticator answers it.
    if (/\/authn\/totp$/.test(path) && o.totpSecret) {
      const box = await present(driver, "code", 10000);
      if (box) {
        await box.sendKeys(await freshTotp(o.totpSecret));
        await (await driver.findElement(By.id("totp-submit"))).click();
        log.info("  answered a TOTP step-up for " + id);
        await moved(driver, here, 15000);
        continue;
      }
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
        // "confirm-then-photograph": the module asks for the page AFTER the
        // person is signed out (the suite's "upload a screenshot of the
        // successful logout page"), so the confirmation is pressed first and
        // the page it leads to is the evidence — where it moves on, the page
        // it settles on is photographed by the branches below.
        if (action !== "confirm-then-photograph") {
          await photograph(o, driver, id, "the end-session page");
        }
        await yes[0].click();
        if (await moved(driver, here, 20000)) {
          continue;
        }
        if (action === "confirm-then-photograph") {
          await photograph(o, driver, id, "the signed-out page");
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
  log.debug("Leaving follow().");
}

// ---------------------------------------------------------------------------
// A SIGN-OUT AT THIS SERVICE, carried to the partner (#930): /logout, the
// sign-out of every session (`button.global`), and on the signed-out page the
// link to the partner's end_session_endpoint (RP-Initiated Logout), which is
// clicked and followed: the partner's front-channel page, its return to this
// service's /federation/slo/{id}, or wherever it stops.
// ---------------------------------------------------------------------------
async function signOutOne(o, id, moduleName, base, jars, options) {
  log.debug("Entering signOutOne(). " + moduleName);
  const driver = await browser(o.serviceBase);
  await useJar(driver, jars, id);
  const suiteBase = String(o.suiteBase);
  try {
    await driver.get(String(base).replace(/\/+$/, "") + "/logout");
    const end = Date.now() + 15000;
    let global = null;
    while (!global && Date.now() < end) {
      const found = await driver.findElements(By.css("button.global"));
      global = found.length ? found[0] : null;
      if (!global) {
        await waitMs(250);
      }
    }
    if (!global) {
      log.warn("The sign-out page for " + moduleName + " drew no sign-out " +
               "button.");
    } else {
      await global.click();
      if (options && options.localOnly) {
        await waitMs(1000);
        log.debug("Leaving signOutOne(). Signed out here only.");
        await keepJar(driver, jars, id);
        return;
      }
      const until = Date.now() + 20000;
      let link = null;
      while (!link && Date.now() < until) {
        const links = await driver.findElements(
          By.css("a[href^=\"" + suiteBase + "\"]"));
        link = links.length ? links[0] : null;
        if (!link) {
          await waitMs(250);
        }
      }
      if (!link) {
        log.warn("The signed-out page for " + moduleName + " offered no " +
                 "sign-out at the partner.");
      } else {
        const here = await currentUrl(driver);
        await link.click();
        await moved(driver, here, 15000);
        await follow(o, driver, id, "sign-in", suiteBase);
      }
    }
  } catch (e) {
    log.warn("The person's sign-out for " + moduleName + " stopped: " +
             ((e && e.message) || e));
  }
  await keepJar(driver, jars, id);
  log.debug("Leaving signOutOne().");
}

// A time step a driver has spent elsewhere (the enrolment's confirming code),
// so the first step-up does not reuse it.
function usedTotpStep(step) {
  log.debug("Entering usedTotpStep().");
  lastTotpStep = Math.max(lastTotpStep, Number(step));
  log.debug("Leaving usedTotpStep().");
}

module.exports = {
  person: person,
  quit: quit,
  totpAt: totpAt,
  usedTotpStep: usedTotpStep
};
