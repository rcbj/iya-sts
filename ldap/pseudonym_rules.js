// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: ldap/pseudonym_rules.js
//
// The shape of one stsPseudonym value (#644). A leaf: ldap_server.js and
// persistence/bulk_import.js both ask it, and neither may require the other.
// Uniqueness against another person is not this file's question. That needs
// the username index and the mail index, which the writer holds.
//
// nameUsableInDn() in ldap_server.js uses the same reserved-character class.
// The two stay one class: DN_RESERVED there is this expression.

const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'sts-pseudonym-rules' });

// RFC 4514's reserved characters. A value that contains one cannot be the
// unescaped fast path in existingUserEntry() ('uid=' + name + ',' + base).
const DN_RESERVED = /[,=+<>#;"\\]/;

const DN_SHAPED = /^[A-Za-z][A-Za-z0-9-]*=/;
const DID_SHAPED = /^did:[a-z0-9]+:/i;
const SPIFFE_SHAPED = /^spiffe:\/\//i;
const UUID_SHAPED =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// Credentials.isLaneName(). '+' already fails DN_RESERVED; the check stays
// so a later widening of that class still refuses a passkey lane name.
const LANE_NAME = /\+(ml-dsa(-[0-9]+)?|pqc)$/i;

const CAP = 8;
const MAX_LENGTH = 254;
const RESERVED_NAME = 'invalid';

/**
 * What is wrong with one pseudonym, before any directory lookup.
 *
 * @param value - the trimmed string
 * @param options - ownNames (lower-cased uid and RDN), email (addressProblem
 *   returned ''), liveCount (how many live values the entry already holds)
 * @returns `{ ok: true, email }` or `{ ok: false, code, sentence }`
 */
function pseudonymProblem(value, options) {
  log.debug("Entering pseudonymProblem().");
  const opts = options || {};
  const text = String(value == null ? '' : value).trim();
  const fold = text.toLowerCase();
  const email = !!opts.email;
  // The code is named at each call, where tests/error_codes.js looks for it.
  const fail = function (code, sentence) {
    log.debug("Leaving pseudonymProblem(). Refused.");
    return { ok: false, code: code, sentence: sentence };
  };
  if (!text || text.length > MAX_LENGTH) {
    return fail('STS-LDAP-0199',
                'A pseudonym is one name of at most 254 characters.');
  }
  if (DN_RESERVED.test(text)) {
    return fail('STS-LDAP-0199',
                'A pseudonym cannot contain a character a distinguished ' +
                'name reserves.');
  }
  if (DN_SHAPED.test(text) || /^urn:uuid:/i.test(text) ||
      UUID_SHAPED.test(text) || DID_SHAPED.test(text) ||
      SPIFFE_SHAPED.test(text)) {
    return fail('STS-LDAP-0199',
                'A pseudonym cannot be a distinguished name, a subject, ' +
                'a DID, or a SPIFFE identity.');
  }
  if (fold === RESERVED_NAME || LANE_NAME.test(text)) {
    return fail('STS-LDAP-0199', 'That name is reserved.');
  }
  const own = opts.ownNames || [];
  if (own.indexOf(fold) !== -1) {
    log.debug("Leaving pseudonymProblem(). The person's own name.");
    return { ok: false, code: 'STS-LDAP-0201',
             sentence: 'That name is already this person\'s uid.' };
  }
  const count = Number(opts.liveCount);
  if (count >= CAP) {
    return fail('STS-LDAP-0199',
                'A person holds at most eight pseudonyms.');
  }
  log.debug("Leaving pseudonymProblem().");
  return { ok: true, email: email };
}

module.exports = {
  CAP: CAP,
  MAX_LENGTH: MAX_LENGTH,
  DN_RESERVED: DN_RESERVED,
  pseudonymProblem: pseudonymProblem
};
