'use strict';
//
// File: person_attributes.ts
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
// person's own directory entry, read through `common/claim_attributes.ts`'s
// catalogue so that `mail`, `givenName`, `sn` and `cn` are spelt and resolved
// exactly as a token's are. What the entry does not hold is OMITTED — an
// attribute a relying party can handle being missing, rather than one it
// cannot tell is false.
//
// A LIBRARY (rule 3). It registers no route. `claim_attributes.js` is required
// LAZILY, inside the one function that needs it and only in product mode: that
// module requires `admin_stats.js` and `oid4vc/vc_claims.ts`, which
// `common/protocol_stack.ts` has already loaded at position 5 so the require
// is a cache hit there — but
// the in-process tests and the parent project's Kerberos jobs load `saml/`
// without them, and a development-mode process must not pay for a reader it
// never uses.
// ===========================================================================

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `PersonAttributes` takes the logger, `mode` and a LOADER for
// `claim_attributes.js` through its constructor (a loader and not the module,
// for the lazy require the header argues), and the module still exports
// `personFor()` and `withoutAbsent()` from a TRANSITIONAL instance for the
// unconverted modules that require it.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import mode = require('../common/mode');

// The person as `helpers.userFor()` draws them; only `username` and the four
// facts are read here.
interface Person {
  username?: string;
  given_name?: string;
  family_name?: string;
  email?: string;
  name?: string;
  [member: string]: unknown;
}

// One catalogue row, as `claim_attributes.js` answers it.
interface CatalogueItem {
  value?: unknown;
  source?: string;
}

interface ClaimAttributesReader {
  catalogueValuesFor(username: string): {
    byLdap?: Record<string, CatalogueItem>;
  };
}

// One row of an attribute list the builders write.
interface AttributeRow {
  value?: unknown;
  values?: unknown[];
  [member: string]: unknown;
}

interface PersonAttributesDeps {
  log: { debug(message: string): void };
  mode: { inventsClaimValues(): boolean };
  // `common/claim_attributes.ts`, required when first asked for. Never at
  // load: see the header.
  loadClaimAttributes(): ClaimAttributesReader;
}

class PersonAttributes {
  // userFor()'s field -> the LDAP attribute the catalogue files the same fact
  // under. `name` is cn (the full name) and not displayName, which the
  // catalogue maps to OIDC's `nickname`.
  static readonly FROM_DIRECTORY: Readonly<Record<string, string>> = {
    given_name: 'givenname',
    family_name: 'sn',
    email: 'mail',
    name: 'cn'
  };

  constructor(private readonly deps: PersonAttributesDeps) {
    deps.log.debug("Entering PersonAttributes.constructor().");
    deps.log.debug("Leaving PersonAttributes.constructor().");
  }

  private present(value: unknown): boolean {
    const { log } = this.deps;
    log.debug("Entering PersonAttributes.present().");
    log.debug("Leaving PersonAttributes.present().");
    return value !== undefined && value !== null && String(value) !== '';
  }

  // The person, with the four facts filled from the directory where the mode
  // invents none. Always a NEW object — the session's own user is never
  // written to, because it is shared by every protocol reading the session.
  personFor<T extends Person>(user?: T | null): T {
    const { log, mode, loadClaimAttributes } = this.deps;
    const FROM_DIRECTORY = PersonAttributes.FROM_DIRECTORY;
    log.debug("Entering PersonAttributes.personFor(). user=" +
              ((user && user.username) || '(none)'));
    const out = Object.assign({}, user || {}) as T;
    if (mode.inventsClaimValues()) {
      log.debug("Leaving PersonAttributes.personFor(). This realm invents " +
                "persona values; unchanged.");
      return out;
    }
    const missing = Object.keys(FROM_DIRECTORY).filter((field) => {
      return !this.present(out[field]);
    });
    if (!missing.length || !out.username) {
      log.debug("Leaving PersonAttributes.personFor(). Nothing to look up.");
      return out;
    }
    let byLdap: Record<string, CatalogueItem> = {};
    try {
      byLdap = loadClaimAttributes().catalogueValuesFor(
          out.username).byLdap || {};
    } catch (e) {
      // No directory in this process (an in-process test, a parent-project
      // job loading saml/ alone). Omitting is exactly the product-mode answer
      // for a fact nobody holds, so this degrades to that rather than failing
      // a sign-in over bookkeeping.
      log.debug("Caught in PersonAttributes.personFor(): the directory " +
                "could not be read (" + e.message + "); the missing facts " +
                "are omitted.");
    }
    missing.forEach((field) => {
      const item = byLdap[FROM_DIRECTORY[field]];
      if (item && this.present(item.value) && item.source === 'directory') {
        (out as Person)[field] = String(item.value);
      }
    });
    log.debug("Leaving PersonAttributes.personFor(). " +
              missing.filter((f) => {
                return this.present(out[f]);
              }).length + " of " + missing.length + " found on the entry.");
    return out;
  }

  // An attribute list with every row whose value is absent REMOVED. The
  // builders write a row per fact whether or not there is one; an
  // <AttributeValue> of "undefined" is a claim this service would be signing.
  withoutAbsent<T extends AttributeRow>(attributes?: T[] | null): T[] {
    const { log } = this.deps;
    log.debug("Entering PersonAttributes.withoutAbsent().");
    log.debug("Leaving PersonAttributes.withoutAbsent().");
    return (attributes || []).filter((a) => {
      if (Array.isArray(a.values)) {
        return a.values.length > 0;
      }
      return this.present(a.value);
    });
  }
}

// THE TRANSITIONAL INSTANCE — see the header above.
const personAttributes = new PersonAttributes({
  log: helpers.log,
  mode: mode,
  loadClaimAttributes: function (): ClaimAttributesReader {
    return require('../common/claim_attributes');
  }
});

export = {
  PersonAttributes: PersonAttributes,
  personFor: personAttributes.personFor.bind(personAttributes) as
    PersonAttributes['personFor'],
  withoutAbsent: personAttributes.withoutAbsent.bind(personAttributes) as
    PersonAttributes['withoutAbsent']
};
