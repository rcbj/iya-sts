'use strict';
//
// File: person_attributes.js
//
// ===========================================================================
// THE FOUR PERSONA FACTS AN ASSERTION CARRIES, AND WHERE THEY COME FROM IN EACH
// MODE (2026-09-12).
//
// SAML 2.0's attribute statement, SAML 1.1's, and WS-Federation's claims all
// write a given name, a surname, a mail address and a display name about the
// person, read off `session.user` — which is `helpers.userFor()`. In
// DEVELOPMENT that object invents all four (`Mock`, `<name>@sts.example`)
// and nothing here changes a byte of what it produces.
//
// **IN PRODUCT `userFor()` INVENTS NOTHING** (`mode.inventsClaimValues()`), so
// those fields are simply ABSENT on the session's user — and the three builders
// wrote `value: user.email` regardless, which put an <AttributeValue> of
// `undefined`, or an empty one, into a signed assertion. This module is where
// the absent facts are looked for in the one place that holds real ones: the
// person's own directory entry, read through `common/claim_attributes.js`'s
// catalogue so that `mail`, `givenName`, `sn` and `cn` are spelt and resolved
// exactly as a token's are. What the entry does not hold is OMITTED — an
// attribute a relying party can handle being missing, rather than one it
// cannot tell is false.
//
// A LIBRARY (rule 3). It registers no route. `claim_attributes.js` is required
// LAZILY, inside the one function that needs it and only in product mode: that
// module requires `admin_stats.js` and `oid4vc/vc_claims.js`, which `server.js`
// has already loaded at position 5 so the require is a cache hit there — but
// the in-process tests and the parent project's Kerberos jobs load `saml/`
// without them, and a development-mode process must not pay for a reader it
// never uses.
// ===========================================================================

const { log } = require('../common/helpers');
const mode = require('../common/mode');

// userFor()'s field -> the LDAP attribute the catalogue files the same fact
// under. `name` is cn (the full name) and not displayName, which the catalogue
// maps to OIDC's `nickname`.
const FROM_DIRECTORY = {
  given_name: 'givenname',
  family_name: 'sn',
  email: 'mail',
  name: 'cn'
};

function present(value) {
  return value !== undefined && value !== null && String(value) !== '';
}

// The person, with the four facts filled from the directory where the mode
// invents none. Always a NEW object — the session's own user is never written
// to, because it is shared by every protocol reading the session.
function personFor(user) {
  log.debug("Entering personFor(). user=" + ((user && user.username) || '(none)'));
  const out = Object.assign({}, user || {});
  if (mode.inventsClaimValues()) {
    log.debug("Leaving personFor(). This realm invents persona values; unchanged.");
    return out;
  }
  const missing = Object.keys(FROM_DIRECTORY).filter(function (field) {
    return !present(out[field]);
  });
  if (!missing.length || !out.username) {
    log.debug("Leaving personFor(). Nothing to look up.");
    return out;
  }
  let byLdap = {};
  try {
    byLdap = require('../common/claim_attributes').catalogueValuesFor(out.username).byLdap || {};
  } catch (e) {
    // No directory in this process (an in-process test, a parent-project job
    // loading saml/ alone). Omitting is exactly the product-mode answer for a
    // fact nobody holds, so this degrades to that rather than failing a
    // sign-in over bookkeeping.
    log.debug("personFor(): the directory could not be read (" + e.message +
              "); the missing facts are omitted.");
  }
  missing.forEach(function (field) {
    const item = byLdap[FROM_DIRECTORY[field]];
    if (item && present(item.value) && item.source === 'directory') {
      out[field] = String(item.value);
    }
  });
  log.debug("Leaving personFor(). " + missing.filter(function (f) {
    return present(out[f]);
  }).length + " of " + missing.length + " found on the entry.");
  return out;
}

// An attribute list with every row whose value is absent REMOVED. The builders
// write a row per fact whether or not there is one; an <AttributeValue> of
// "undefined" is a claim this service would be signing.
function withoutAbsent(attributes) {
  return (attributes || []).filter(function (a) {
    if (Array.isArray(a.values)) {
      return a.values.length > 0;
    }
    return present(a.value);
  });
}

module.exports = {
  personFor: personFor,
  withoutAbsent: withoutAbsent
};
