// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: url_match.js
//
// ---------------------------------------------------------------------------
// WHETHER A TEXT NAMES AN ADDRESS, BY PARSING IT (2026-11-20, CodeQL
// js/incomplete-url-substring-sanitization). The jobs asked
// `text.indexOf("https://rp.example/cb") < 0` of a page, an answer or a
// token, and a substring of a URL is not a URL: `https://rp.example/cb`
// is a substring of `https://rp.example/cbx` and of
// `https://rp.example/cb.evil.test/`, neither of which is that address.
//
// `namesAddress()` reads EVERY http(s) URL in the text — one starting at
// each `http://` or `https://`, so an address carried inside another URL's
// query is read too, as the substring test found it — parses each with
// `URL`, and answers whether one has the address's origin AND path. A
// query or fragment after the path does not change which address it is,
// which is what the jobs mean by "the page names the registered address":
// a `post_logout_redirect_uri` with `?state=` appended is still it.
//
// `namesOrigin()` is the same with the path left out, for a constant that
// is an origin. `sameOrigin()` and `hostOf()` are for a value that should
// BE a URL: the first compares `URL.origin`, the second reads `URL.host`,
// and neither answers anything but false or '' for text that does not
// parse.
// ---------------------------------------------------------------------------

const log = require("bunyan").createLogger({ name: "url_match",
  level: process.env.LOG_LEVEL || "info" });

// One candidate starts at every scheme; it ends at whitespace, a quote,
// an angle bracket, a backslash or an ampersand. None of the first four is
// in a URL a page, a JSON answer or an XML token carries unescaped, and
// the ampersand is where an escaped one starts (`&lt;`, `&quot;`): a SAML
// token in a form's hidden field is XML escaped into HTML, and reading
// `…/phishing-resistant&lt;/saml:…` as one path would miss the address.
// Stopping there costs only the rest of a query, which is not compared.
const CANDIDATE = /(?=(https?:\/\/[^\s"'<>\\&]+))/gi;

// Punctuation a sentence puts after a URL ("…registered: https://x/cb.")
// is not part of it.
const TRAILING = /[.,;:!?)\]]+$/;

/**
 * Every http(s) URL in a text, parsed; a candidate that does not parse is
 * left out.
 *
 * @param {string} text - the page, answer or token
 * @returns {URL[]} the URLs, in the order they start
 */
function urlsIn(text) {
  log.debug("Entering urlsIn().");
  const out = [];
  const s = String(text === undefined || text === null ? "" : text);
  CANDIDATE.lastIndex = 0;
  let m;
  while ((m = CANDIDATE.exec(s)) !== null) {
    // A zero-width match: step past it, or exec answers it again.
    CANDIDATE.lastIndex = m.index + 1;
    try {
      out.push(new URL(m[1].replace(TRAILING, "")));
    } catch (e) {
      log.debug("Caught in urlsIn(): " + ((e && e.message) || e));
    }
  }
  log.debug("Leaving urlsIn(). " + out.length);
  return out;
}

/**
 * Whether a text names an address: some URL in it with the address's
 * origin and path.
 *
 * @param {string} text - the page, answer or token
 * @param {string} address - an absolute http(s) URL
 * @returns {boolean} true when it is named
 */
function namesAddress(text, address) {
  log.debug("Entering namesAddress(). " + address);
  const want = new URL(String(address));
  const found = urlsIn(text).some(function (one) {
    return one.origin === want.origin && one.pathname === want.pathname;
  });
  log.debug("Leaving namesAddress(). " + found);
  return found;
}

/**
 * Whether a text names an origin: some URL in it at that origin, whatever
 * its path.
 *
 * @param {string} text - the page, answer or token
 * @param {string} origin - an absolute URL whose origin is compared
 * @returns {boolean} true when it is named
 */
function namesOrigin(text, origin) {
  log.debug("Entering namesOrigin(). " + origin);
  const want = new URL(String(origin)).origin;
  const found = urlsIn(text).some(function (one) {
    return one.origin === want;
  });
  log.debug("Leaving namesOrigin(). " + found);
  return found;
}

/**
 * Whether a value is a URL at an origin.
 *
 * @param {string} value - the value
 * @param {string} origin - an absolute URL whose origin is compared
 * @returns {boolean} true when both parse and the origins are equal
 */
function sameOrigin(value, origin) {
  log.debug("Entering sameOrigin().");
  let out = false;
  try {
    out = new URL(String(value)).origin === new URL(String(origin)).origin;
  } catch (e) {
    log.debug("Caught in sameOrigin(): " + ((e && e.message) || e));
    out = false;
  }
  log.debug("Leaving sameOrigin(). " + out);
  return out;
}

/**
 * A URL's host (with its port, when it has one), or '' when it does not
 * parse.
 *
 * @param {string} value - the value
 * @returns {string} the host
 */
function hostOf(value) {
  log.debug("Entering hostOf().");
  let out = "";
  try {
    out = new URL(String(value)).host;
  } catch (e) {
    log.debug("Caught in hostOf(): " + ((e && e.message) || e));
    out = "";
  }
  log.debug("Leaving hostOf(). " + out);
  return out;
}

module.exports = { urlsIn: urlsIn, namesAddress: namesAddress,
                   namesOrigin: namesOrigin, sameOrigin: sameOrigin,
                   hostOf: hostOf };
