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
//
// THE SAME FOR A VALUE THAT IS ONE ADDRESS, OR A LIST OF THEM (2026-11-20,
// the rest of the sweep). A redirect's `Location` was asked
// `loc.indexOf(REDIRECT) === 0`, which `https://rp.example/cbx?code=` and
// `https://rp.example/cb.evil.test/` both pass. `isAt()` parses the value
// and answers whether it is the address — origin and path equal, any query
// or fragment after them, which is where a code or a state goes.
// `isUnder()` is for a value that should be somewhere BELOW a base (the
// service's own base URL, a partner's `/oauth2/`): the same origin, and a
// path that is the base's or continues it at a `/`, so `/realm/acme` is
// not under `/realm/ac`. `holds()` is for a list of addresses (`aud`, a
// list of ACS URLs, the events a stream delivers): an element compared
// whole, and a single string taken as a list of one, so an `aud` that is
// a string is compared whole too rather than searched.
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

/**
 * A value parsed as an absolute URL, or null when it does not parse.
 *
 * @param {*} value - the value
 * @returns {URL|null} the URL
 */
function parsed(value) {
  log.debug("Entering parsed().");
  let out = null;
  try {
    out = new URL(String(value));
  } catch (e) {
    log.debug("Caught in parsed(): " + ((e && e.message) || e));
    out = null;
  }
  log.debug("Leaving parsed().");
  return out;
}

/**
 * Whether a value is an address: it parses, and its origin and path are
 * the address's. A query or a fragment after them is allowed.
 *
 * @param {*} value - the value, e.g. a `Location` header
 * @param {string} address - an absolute http(s) URL
 * @returns {boolean} true when it is that address
 */
function isAt(value, address) {
  log.debug("Entering isAt(). " + address);
  const one = parsed(value);
  const want = new URL(String(address));
  const out = !!one && one.origin === want.origin &&
    one.pathname === want.pathname;
  log.debug("Leaving isAt(). " + out);
  return out;
}

/**
 * Whether a value is at or below a base: it parses, its origin is the
 * base's, and its path is the base's or continues it at a `/`. A base
 * whose path ends in `/` asks for a path starting with it.
 *
 * @param {*} value - the value, e.g. a `Location` header
 * @param {string} base - an absolute http(s) URL
 * @returns {boolean} true when it is at or below the base
 */
function isUnder(value, base) {
  log.debug("Entering isUnder(). " + base);
  const one = parsed(value);
  const want = new URL(String(base));
  const p = want.pathname;
  let out = !!one && one.origin === want.origin;
  if (out && /\/$/.test(p)) {
    out = one.pathname.indexOf(p) === 0;
  } else if (out) {
    out = one.pathname === p || one.pathname.indexOf(p + "/") === 0;
  }
  log.debug("Leaving isUnder(). " + out);
  return out;
}

/**
 * Whether a list holds a value, compared whole. A value that is not an
 * array is taken as a list of one; undefined and null as an empty list.
 *
 * @param {*} list - the list, e.g. a token's `aud`
 * @param {*} value - the element looked for
 * @returns {boolean} true when an element is equal to it
 */
function holds(list, value) {
  log.debug("Entering holds().");
  const all = list === undefined || list === null ? [] : [].concat(list);
  const out = all.some(function (one) {
    return one === value;
  });
  log.debug("Leaving holds(). " + out);
  return out;
}

module.exports = { urlsIn: urlsIn, namesAddress: namesAddress,
                   namesOrigin: namesOrigin, sameOrigin: sameOrigin,
                   hostOf: hostOf, isAt: isAt, isUnder: isUnder,
                   holds: holds };
