'use strict';
// ===========================================================================
// tests/tools/browser-user-agent.js — A BROWSER'S USER-AGENT FOR EVERY
// PROTOCOL JOB'S CLIENTS (#62 P3, 2026-09-22).
//
// PRELOADED, never required: `run-report.js` puts `--require <this file>` on
// every protocol job's NODE_OPTIONS, in every mode and against every target.
//
// **WHY IT EXISTS.** Since #62 P3 the issuance policy decides on the RISK of
// an authentication, and product mode enforces it. One of the evaluators is
// an AUTOMATED CLIENT (`isbot` on the User-Agent, x10), and a person's first
// sign-in scores 1 before the evaluators — so a first sign-in from an
// automated client is 10, which is HIGH, and is refused. That is the policy
// rcbj chose on 2026-09-22 ("keep the policy, the suite looks like a
// browser"): an interactive sign-in by a script is refused in product, and a
// deployment's automation authenticates as a CLIENT, which is never scored.
// The suite's jobs sign people in through the browser flows with node's
// `fetch()`, which sends `User-Agent: node`, and with Selenium's headless
// Chrome, which sends `HeadlessChrome/…` — both of which `isbot` names.
//
// **A PRELOAD, BECAUSE THE CLIENTS ARE IN VENDORED FILES**, for
// `fresh-connections.js`'s reason: the jobs under tests/vendored/ and their
// helpers (`browser_flags.js`) are the parent project's copies and may not be
// edited here.
//
// WHAT IT CHANGES, and only where a job said nothing:
//
//   * `fetch()`: a request with no `user-agent` header of its own is sent
//     with a desktop Chrome's. A job that names one keeps it — the P0 context
//     jobs assert the fingerprint of their own.
//   * Selenium's Chrome: a `Builder` whose Chrome options carry no
//     `--user-agent` gets one, so the headless browser reads as the browser
//     it is. Nothing else about the options moves.
//
// WHAT IT LEAVES ALONE: `http.request()`/`https.request()`, which send no
// User-Agent at all unless asked — an empty header is not an automated client
// to `isbot`, so those requests are already scored as nothing in particular.
// The automated-client decision itself is tested where it is meant to be:
// `tests/risk_engine.js` and `tests/risk_decisions.js`, in process.
// ===========================================================================

const log = require('bunyan').createLogger({ name: 'browser-user-agent',
  level: process.env.LOG_LEVEL || 'info' });

const BROWSER = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 ' +
  '(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36';

function hasUserAgent(headers) {
  log.debug("Entering hasUserAgent().");
  let found = false;
  if (!headers) {
    found = false;
  } else if (typeof headers.has === 'function') {
    found = headers.has('user-agent');
  } else if (Array.isArray(headers)) {
    found = headers.some(function (pair) {
      return String(pair[0]).toLowerCase() === 'user-agent';
    });
  } else {
    found = Object.keys(headers).some(function (name) {
      return name.toLowerCase() === 'user-agent';
    });
  }
  log.debug("Leaving hasUserAgent(). " + found);
  return found;
}

function withUserAgent(headers) {
  log.debug("Entering withUserAgent().");
  if (!headers) {
    log.debug("Leaving withUserAgent(). New headers.");
    return { 'user-agent': BROWSER };
  }
  if (typeof headers.set === 'function') {
    const copy = new Headers(headers);
    copy.set('user-agent', BROWSER);
    log.debug("Leaving withUserAgent(). A Headers copy.");
    return copy;
  }
  if (Array.isArray(headers)) {
    log.debug("Leaving withUserAgent(). A list.");
    return headers.concat([['user-agent', BROWSER]]);
  }
  log.debug("Leaving withUserAgent(). An object.");
  return Object.assign({}, headers, { 'user-agent': BROWSER });
}

function wrapFetch() {
  log.debug("Entering wrapFetch().");
  if (typeof globalThis.fetch !== 'function') {
    log.debug("Leaving wrapFetch(). No fetch().");
    return;
  }
  const original = globalThis.fetch;
  globalThis.fetch = function (input, init) {
    log.debug("Entering fetch().");
    const own = (init && init.headers) ||
      (input && typeof input === 'object' && input.headers);
    if (hasUserAgent(own)) {
      log.debug("Leaving fetch(). The job named its own.");
      return original.call(this, input, init);
    }
    log.debug("Leaving fetch().");
    return original.call(this, input,
      Object.assign({}, init || {}, { headers: withUserAgent(own) }));
  };
  log.debug("Leaving wrapFetch().");
}

function wrapSelenium() {
  log.debug("Entering wrapSelenium().");
  let webdriver = null;
  try {
    webdriver = require('selenium-webdriver');
  } catch (e) {
    log.debug("Caught in wrapSelenium(): " + ((e && e.message) || e));
    // No Selenium where this job runs — a protocol job with no browser. Its
    // clients are covered by wrapFetch().
    log.debug("Leaving wrapSelenium(). No Selenium.");
    return;
  }
  const build = webdriver.Builder.prototype.build;
  webdriver.Builder.prototype.build = function () {
    log.debug("Entering build().");
    try {
      const options = typeof this.getChromeOptions === 'function'
        ? this.getChromeOptions() : null;
      const args = options && options.options_ && options.options_.args
        ? options.options_.args : [];
      if (options && !args.some(function (one) {
        return /^--user-agent=/.test(String(one));
      })) {
        options.addArguments('--user-agent=' + BROWSER);
      }
    } catch (e) {
      log.debug("Caught in build(): " + ((e && e.message) || e));
      // Options this shim cannot read are left as the job built them; the
      // job then signs in as the headless browser it is, and a product-mode
      // run says so in its own failure.
    }
    log.debug("Leaving build().");
    return build.apply(this, arguments);
  };
  log.debug("Leaving wrapSelenium().");
}

wrapFetch();
wrapSelenium();
