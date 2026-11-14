// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: companion/krb5_error.js
//
// ===========================================================================
// A KRB-ERROR FOR THE PROTECTED SERVICE'S TCP SOCKET (#595), and nothing
// else of Kerberos.
//
// The companion's acceptor is MIT Kerberos's GSS-API (`demo_kerberos.js`
// argues why), and the binding it goes through hands back the reason a
// context was refused as TEXT — MIT's own message — and drops the error
// token MIT made. Over HTTP that is enough: RFC 4559 answers a refusal with
// a 401 and the page says why. Over the raw socket a client that gets
// silence learns nothing, so this writes the one message the socket answers
// a refusal with: a KRB-ERROR (RFC 4120 section 5.9.1), the same reply the
// service's own demonstration socket gave until #595.
//
// **The error code is read off MIT's message** (`codeFor()`), a table of
// the com_err strings an acceptor produces, and KRB_ERR_GENERIC (60) for
// anything not in it. The e-text is MIT's message itself, so nothing is
// lost by the table being short.
//
// **Its own DER, a dozen lines of it**, rather than the service's codec:
// the companion requires nothing of the service (`CLAUDE.md`), and a
// KRB-ERROR is one fixed SEQUENCE of integers, a time and strings.
// `tests/companion.js` decodes what this writes with the service's vendored
// codec, so the two are held to each other there.
// ===========================================================================

const util = require("./companion_util.js");

const log = util.logger("krb5_error");

// MIT's messages, as `gss_display_status()` renders the minor status of a
// refused AP-REQ, to the RFC 4120 section 7.5.9 code each one is. The first
// match wins.
const CODES = [
  [/clock skew too great/i, 37, "KRB_AP_ERR_SKEW"],
  [/request is a replay/i, 34, "KRB_AP_ERR_REPEAT"],
  [/ticket expired/i, 32, "KRB_AP_ERR_TKT_EXPIRED"],
  [/ticket not yet valid/i, 33, "KRB_AP_ERR_TKT_NYV"],
  [/version of key is not available|key version/i, 44,
   "KRB_AP_ERR_BADKEYVER"],
  [/no key table entry|not found in keytab|cannot find key/i, 45,
   "KRB_AP_ERR_NOKEY"],
  [/wrong principal/i, 35, "KRB_AP_ERR_NOT_US"],
  [/integrity check failed|decrypt/i, 31, "KRB_AP_ERR_BAD_INTEGRITY"],
  [/message stream modified/i, 41, "KRB_AP_ERR_MODIFIED"],
  [/inappropriate type of checksum/i, 50, "KRB_AP_ERR_INAPP_CKSUM"]
];

/**
 * The error code MIT's message names.
 *
 * @param {string} message - MIT's text for the refusal
 * @returns {object} `{ code, name }`
 */
function codeFor(message) {
  log.debug("Entering codeFor().");
  const text = String(message || "");
  for (const row of CODES) {
    if (row[0].test(text)) {
      log.debug("Leaving codeFor(). " + row[2]);
      return { code: row[1], name: row[2] };
    }
  }
  log.debug("Leaving codeFor(). Generic.");
  return { code: 60, name: "KRB_ERR_GENERIC" };
}

/**
 * A DER length.
 *
 * @param {number} n - the length
 * @returns {Buffer} its encoding
 */
function derLength(n) {
  log.debug("Entering derLength().");
  if (n < 0x80) {
    log.debug("Leaving derLength(). Short.");
    return Buffer.from([n]);
  }
  const bytes = [];
  let left = n;
  while (left > 0) {
    bytes.unshift(left & 0xff);
    left = Math.floor(left / 256);
  }
  log.debug("Leaving derLength(). Long.");
  return Buffer.from([0x80 | bytes.length].concat(bytes));
}

/**
 * A tag, its length and its contents.
 *
 * @param {number} tag - the identifier octet
 * @param {Buffer} body - the contents
 * @returns {Buffer} the TLV
 */
function tlv(tag, body) {
  log.debug("Entering tlv().");
  log.debug("Leaving tlv().");
  return Buffer.concat([Buffer.from([tag]), derLength(body.length), body]);
}

/**
 * A DER INTEGER, for the non-negative values a KRB-ERROR carries.
 *
 * @param {number} value - the value
 * @returns {Buffer} the INTEGER
 */
function integer(value) {
  log.debug("Entering integer().");
  const bytes = [];
  let left = Math.max(0, Math.floor(value));
  do {
    bytes.unshift(left & 0xff);
    left = Math.floor(left / 256);
  } while (left > 0);
  if (bytes[0] & 0x80) {
    bytes.unshift(0);
  }
  log.debug("Leaving integer().");
  return tlv(0x02, Buffer.from(bytes));
}

/**
 * A KerberosString (GeneralString, IA5 in practice).
 *
 * @param {string} text - the text
 * @returns {Buffer} the GeneralString
 */
function generalString(text) {
  log.debug("Entering generalString().");
  log.debug("Leaving generalString().");
  return tlv(0x1b, Buffer.from(String(text), "utf8"));
}

/**
 * A context-specific explicit tag.
 *
 * @param {number} n - the tag number
 * @param {Buffer} inner - what it wraps
 * @returns {Buffer} the tagged value
 */
function explicit(n, inner) {
  log.debug("Entering explicit(). [" + n + "]");
  log.debug("Leaving explicit().");
  return tlv(0xa0 | n, inner);
}

/**
 * A KRB-ERROR (RFC 4120 section 5.9.1) from this service.
 *
 * @param {object} opts - `code`, `realm`, `sname` (an array of components),
 *   `eText`, `now` (a Date, for a test)
 * @returns {Buffer} the DER
 */
function krbError(opts) {
  log.debug("Entering krbError(). code=" + opts.code);
  const now = opts.now || new Date();
  const stime = now.toISOString().replace(/[-:T]/g, "")
    .replace(/\.\d+Z$/, "Z");
  const sname = Buffer.concat([
    explicit(0, integer(opts.sname.length > 1 ? 2 : 1)),
    explicit(1, tlv(0x30, Buffer.concat(opts.sname.map(generalString))))
  ]);
  const fields = [
    explicit(0, integer(5)),
    explicit(1, integer(30)),
    explicit(4, tlv(0x18, Buffer.from(stime, "ascii"))),
    explicit(5, integer((now.getMilliseconds() * 1000) % 1000000)),
    explicit(6, integer(opts.code)),
    explicit(9, generalString(opts.realm || "")),
    explicit(10, tlv(0x30, sname))
  ];
  if (opts.eText) {
    fields.push(explicit(11, generalString(opts.eText)));
  }
  log.debug("Leaving krbError().");
  return tlv(0x7e, tlv(0x30, Buffer.concat(fields)));
}

module.exports = { codeFor: codeFor, krbError: krbError };
