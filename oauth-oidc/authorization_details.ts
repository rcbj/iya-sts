'use strict';
//
// File: authorization_details.ts
//
// ===========================================================================
// RFC 9396 — OAUTH 2.0 RICH AUTHORIZATION REQUESTS (2026-09-13).
//
// A client may say what it wants authorized as a JSON array rather than as
// scope strings:
//
//   authorization_details=[{"type":"payment_initiation",
//                           "locations":["https://pay.example/"],
//                           "actions":["initiate"],
//                           "instructedAmount":{"currency":"EUR","amount":"12"}}]
//
// at the authorization endpoint (section 3), inside a request object (RFC
// 9101) or a pushed request (RFC 9126), and at the token endpoint (section 6).
// The access token carries what was granted as its `authorization_details`
// claim (section 9.1), the token response echoes it (section 7), and
// introspection hands it to the resource server (section 9.2).
//
// A LIBRARY (rule 3): it registers nothing and requires `common/` modules,
// none of which requires it back. `oauth2.ts` asks it and answers; the consent
// screen draws what it describes.
//
// ---------------------------------------------------------------------------
// FOUR DECISIONS WERE ASKED OF rcbj, AND EACH TOOK THE RECOMMENDED ANSWER:
//
//   * WHERE A TYPE IS DEFINED — ON THE RESOURCE APPLICATION. An application
//     acting as a resource server declares the types it understands in
//     `oauthAuthorizationDetailsType`, each a bare name or a JSON object with a
//     description, the locations a detail may name and a JSON Schema. The
//     realm's `authorization_details_types_supported` is the union, beside the
//     one type this service understands itself: OpenID4VCI's
//     `openid_credential`, whose checks stay in `oauth2.ts` and are handed in
//     as `builtIn`. `common/applications.js` owns the definition's grammar and
//     reads it (`authorizationDetailsTypeOf()`); this file only uses it.
//   * AN UNKNOWN TYPE, OR ONE FAILING ITS SCHEMA, IS REFUSED IN EVERY MODE —
//     `invalid_authorization_details`, section 5's "MUST refuse to process any
//     unknown authorization details type or authorization details not
//     conforming to the respective type definition". A client whose detail was
//     quietly dropped holds a token that authorizes less than it asked for and
//     no way to learn why.
//   * THE AUDIENCE IS THE TYPE'S RESOURCE — `locations` where a detail names
//     them, which must be addresses that resource declares (the definition's
//     `locations`, its permission base URI and its `oauthAudience`), and its
//     primary identifier where it does not. RFC 9068's one-API rule still
//     holds: details of two resources in one request are refused, and so is a
//     `resource` or a scope naming a different one (`audienceFor()` feeds
//     `jwt_access_token.audiencePlan()`).
//   * THE CONSENT SCREEN DRAWS EVERY DETAIL AND ALWAYS ASKS. A detail is a
//     statement about ONE transaction — this payment, this amount — so it is
//     never remembered the way a scope is. Allow is recorded for exactly this
//     person, this client and this array (a SHA-256 of it), once, and spent
//     by the second pass of the authorization endpoint (`noteConsented()`,
//     `consumeConsented()`). `openid_credential` keeps the scope rules it
//     always had, which is what every OpenID4VCI wallet in the parent suite
//     already meets.
//
// ---------------------------------------------------------------------------
// WHAT ELSE THE RFC ASKS, AND WHERE IT IS:
//
//   * Section 2's common data fields — `locations`, `actions`, `datatypes`,
//     `identifier`, `privileges` — checked for shape in every type
//     (`commonFieldProblem()`), whatever the schema says.
//   * Section 6: a token request may carry `authorization_details` to ask for
//     LESS than was authorized, never more (`coveredProblem()`): every detail
//     it names must be covered by one granted detail of the same type — every
//     common array a subset, every other member identical.
//   * Section 10: a client may register `authorization_details_types`, and a
//     type outside that list is refused for it.
//   * Section 10 again: a named authorization server's profile may publish a
//     narrower `authorization_details_types_supported`, and a type outside it
//     is refused at that server (`authorization_servers.ts`, `enforces`).
//   * Section 11.2's caution about large requests: `oauth2.
//     authorizationDetailsMaxEntries`.
//
// NOT DONE, AND SAID: section 7's ENRICHED details are produced only for
// `openid_credential` (its `credential_identifiers`); for a declared type the
// token response echoes what was granted, because nothing here knows what a
// resource server would add. Which resource servers HERE read the claim: none
// but the OpenID4VCI credential endpoint — every other type is for an API this
// service issues tokens to and does not host.
//
// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `AuthorizationDetails` takes the application registry, the settings,
// the error-code table, the crypto module and the logger through its
// constructor. The definition cache and the consent store stay module-level,
// declared at load as before (a store becomes per realm at its declaration).
// The module still exports `COMMON_ARRAYS` and every function it exported,
// bound to a TRANSITIONAL instance built from the real modules, for
// `oauth2.ts`, `consent_screen.ts` and the rest that require it by those
// names.
// ===========================================================================

import crypto = require('crypto');
import applications = require('../common/applications');
import config = require('../common/config');
import errorCodes = require('../common/error_codes');
import helpers = require('../common/helpers');
import realms = require('../common/realms');

// A loose JSON-shaped object: a detail, a definition, a refusal.
type Json = any;

interface AuthorizationDetailsDeps {
  crypto: typeof crypto;
  applications: typeof applications;
  config: typeof config;
  errorCodes: typeof errorCodes;
  log: typeof helpers.log;
}

// Section 2.2's common data fields: four arrays of strings and one string.
const COMMON_ARRAYS = ['locations', 'actions', 'datatypes', 'privileges'];
const COMMON_STRINGS = ['identifier'];

// A parsed definition per distinct attribute value. The value is the key, so an
// edited definition is a different entry and nothing has to be invalidated; the
// bound only stops a process that has seen a great many from holding them all.
const definitionCache = new Map();
const MAX_CACHED_DEFINITIONS = 512;

// ALLOW, ONCE: `username client digest` → expiry. Persisted, because the
// consent POST and the authorization endpoint's second pass may be answered by
// two different request workers.
const consented = realms.map({ persist: 'authorization_details.consented' });

class AuthorizationDetails {
  static readonly COMMON_ARRAYS = COMMON_ARRAYS;

  constructor(private readonly deps: AuthorizationDetailsDeps) {
    deps.log.debug("Entering AuthorizationDetails.constructor().");
    deps.log.debug("Leaving AuthorizationDetails.constructor().");
  }

  private refusal(errorCode: string, description: string): Json {
    const { log, errorCodes } = this.deps;
    log.debug("Entering AuthorizationDetails.refusal(). " + errorCode);
    log.debug("Leaving AuthorizationDetails.refusal().");
    return errorCodes.mark({ ok: false, error: description }, errorCode);
  }

  private unique(list: Json[]): Json[] {
    const { log } = this.deps;
    log.debug("Entering AuthorizationDetails.unique().");
    const out = [];
    (list || []).forEach(function (one) {
      if (one !== undefined && one !== null && one !== '' &&
          out.indexOf(one) < 0) {
        out.push(one);
      }
    });
    log.debug("Leaving AuthorizationDetails.unique().");
    return out;
  }

  private definitionOf(value: unknown): Json {
    const { log, applications } = this.deps;
    log.debug("Entering AuthorizationDetails.definitionOf().");
    const key = String(value);
    if (definitionCache.has(key)) {
      log.debug("Leaving AuthorizationDetails.definitionOf(). Cached.");
      return definitionCache.get(key);
    }
    const parsed = applications.authorizationDetailsTypeOf(key);
    if (definitionCache.size >= MAX_CACHED_DEFINITIONS) {
      definitionCache.delete(definitionCache.keys().next().value);
    }
    definitionCache.set(key, parsed);
    log.debug("Leaving AuthorizationDetails.definitionOf().");
    return parsed;
  }

  private valuesOf(value: unknown): Json[] {
    const { log } = this.deps;
    log.debug("Entering AuthorizationDetails.valuesOf().");
    if (value === undefined || value === null) {
      log.debug("Leaving AuthorizationDetails.valuesOf(). None.");
      return [];
    }
    log.debug("Leaving AuthorizationDetails.valuesOf().");
    return Array.isArray(value) ? value : [value];
  }

  // THE TYPES THIS REALM'S APPLICATIONS DECLARE, as `type → definition`, each
  // definition carrying which application declared it and what that resource
  // answers to. An unusable value is skipped with a warning rather than
  // breaking every rich authorization request in the realm, because the write
  // doors refuse one and only an `ldapmodify` leaves one behind; the same type
  // declared by two applications is a configuration mistake answered by the
  // FIRST in identifier order, with a warning, so the answer does not depend on
  // the order the store happened to walk.
  declaredTypes(): Record<string, Json> {
    const { log, applications, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering AuthorizationDetails.declaredTypes().");
    const out: Record<string, Json> = {};
    const rows = applications.list().slice(0).sort(function (a, b) {
      return String(a.identifier) < String(b.identifier) ? -1 :
             String(a.identifier) > String(b.identifier) ? 1 : 0;
    });
    rows.forEach(function (row) {
      const fields = row.fields || {};
      self.valuesOf(fields.oauthAuthorizationDetailsType)
        .forEach(function (value) {
        const definition = self.definitionOf(value);
        if (definition.problem) {
          log.warn(errorCodes.tag('STS-OAUTH-0461') +
                   'authorization_details: ' +
                   'application "' + row.identifier + '" declares an ' +
                   'unusable authorization_details type, which is ignored: ' +
                   definition.problem + '.');
          return;
        }
        if (out[definition.type]) {
          log.warn(errorCodes.tag('STS-OAUTH-0462') +
                   'authorization_details: ' +
                   'the type "' + definition.type + '" is declared by both "' +
                   out[definition.type].identifier + '" and "' +
                   row.identifier + '"; "' + out[definition.type].identifier +
                   '" answers for it. A type names one resource server.');
          return;
        }
        out[definition.type] = self.resourceDefinition(definition, row);
      });
    });
    log.debug("Leaving AuthorizationDetails.declaredTypes(). " +
              Object.keys(out).length + " type(s).");
    return out;
  }

  // What a resource answers to. THE PRIMARY IDENTIFIER is the permission base
  // URI where the application has one — the audience a delegated permission
  // already gives a token for this API — then its first `oauthAudience`, then
  // its client_id, which is what a scope naming the application becomes. Every
  // identifier is a location a detail may name, beside the definition's own.
  private resourceDefinition(definition: Json, row: Json): Json {
    const { log, applications } = this.deps;
    log.debug("Entering AuthorizationDetails.resourceDefinition().");
    const fields = row.fields || {};
    const base = applications.permissionBaseOf(fields.oauthPermissionBaseUri);
    const audiences = this.unique([base].concat(
      this.valuesOf(fields.oauthAudience).map(String)));
    const clientId = String(this.valuesOf(fields.oauthClientId)[0] || '');
    const primary = audiences[0] || clientId || String(row.identifier);
    log.debug("Leaving AuthorizationDetails.resourceDefinition().");
    return {
      type: definition.type,
      description: definition.description,
      schema: definition.schema,
      validate: definition.validate,
      identifier: row.identifier,
      name: row.name || row.identifier,
      primary: primary,
      identifiers: this.unique([primary].concat(audiences,
                                                clientId ? [clientId] : [],
                                                definition.locations)),
      locations: definition.locations.slice(0)
    };
  }

  // The realm's `authorization_details_types_supported`: the built-in type and
  // every declared one, sorted so two processes publish the same document.
  typesSupported(): string[] {
    const { log, applications } = this.deps;
    log.debug("Entering AuthorizationDetails.typesSupported().");
    const out = this.unique(applications.AUTHORIZATION_DETAILS_BUILT_IN
      .concat(Object.keys(this.declaredTypes()))).sort();
    log.debug("Leaving AuthorizationDetails.typesSupported(). " + out.length +
              " type(s).");
    return out;
  }

  // Section 2.2: the common data fields have a shape whatever the type is.
  private commonFieldProblem(detail: Json, index: number): string {
    const { log, applications } = this.deps;
    log.debug("Entering AuthorizationDetails.commonFieldProblem().");
    const where = 'authorization_details[' + index + ']';
    for (let i = 0; i < COMMON_ARRAYS.length; i++) {
      const name = COMMON_ARRAYS[i];
      if (detail[name] === undefined) {
        continue;
      }
      const value = detail[name];
      if (!Array.isArray(value) || !value.length ||
          value.some(function (one) {
            return typeof one !== 'string' || !one;
          })) {
        log.debug("Leaving AuthorizationDetails.commonFieldProblem(). " +
                  name + ".");
        return where + '.' + name + ' must be a non-empty array of ' +
               'non-empty strings (RFC 9396 section 2.2).';
      }
      if (name === 'locations') {
        for (let j = 0; j < value.length; j++) {
          const problem = applications.authorizationDetailsLocationProblem(
            value[j]);
          if (problem) {
            log.debug("Leaving AuthorizationDetails.commonFieldProblem(). " +
                      "A location.");
            return where + '.locations: ' + problem + ' — a location is an ' +
                   'absolute URI with no fragment (RFC 9396 section 2.2).';
          }
        }
      }
    }
    for (let k = 0; k < COMMON_STRINGS.length; k++) {
      const member = COMMON_STRINGS[k];
      if (detail[member] !== undefined &&
          (typeof detail[member] !== 'string' || !detail[member])) {
        log.debug("Leaving AuthorizationDetails.commonFieldProblem(). " +
                  member + ".");
        return where + '.' + member + ' must be a non-empty string (RFC ' +
               '9396 section 2.2).';
      }
    }
    log.debug("Leaving AuthorizationDetails.commonFieldProblem().");
    return '';
  }

  // A JSON Schema failure as one sentence: the first error, where it is.
  private schemaProblem(validate: Json): string {
    const { log } = this.deps;
    log.debug("Entering AuthorizationDetails.schemaProblem().");
    const first = (validate.errors || [])[0] || {};
    log.debug("Leaving AuthorizationDetails.schemaProblem().");
    return (first.instancePath || '(the detail)') + ' ' +
           (first.message || 'does not match the type\'s schema') +
           (first.params && first.params.additionalProperty
             ? ' ("' + first.params.additionalProperty + '")' : '');
  }

  // -------------------------------------------------------------------------
  // PARSE AND CHECK ONE `authorization_details` VALUE.
  //
  //   raw        the parameter: JSON text (a query, a form body, a request
  //              object's claim as `request_object.ts` hands it on) or an
  //              array
  //   options    { clientTypes   the client's registered types, [] for any
  //                profileTypes  the selected authorization server's
  //                              published list, or null where it removed
  //                              the member
  //                builtIn       function (detail, index) → { entry } or a
  //                              refusal carrying its own code — the
  //                              `openid_credential` checks }
  //
  // Resolves `{ ok: true, details: null }` where nothing was sent (an empty
  // array included, which authorizes nothing), `{ ok: true, details,
  // resolved }` where every detail passed — `resolved[i]` is `{ detail,
  // definition }`, the definition null for the built-in type — or a refusal
  // whose `error` is the sentence for `invalid_authorization_details`. NEVER
  // throws.
  // -------------------------------------------------------------------------
  parse(raw: unknown, opts?: Json): Json {
    const { log, config, applications, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering AuthorizationDetails.parse().");
    const options = opts || {};
    if (raw === undefined || raw === null || raw === '') {
      log.debug("Leaving AuthorizationDetails.parse(). None were sent.");
      return { ok: true, details: null, resolved: [] };
    }
    let parsed: Json = raw;
    if (typeof raw === 'string') {
      try {
        parsed = JSON.parse(raw);
      } catch (e) {
        log.debug("Caught in AuthorizationDetails.parse(): " +
                  ((e && e.message) || e));
        log.debug("Leaving AuthorizationDetails.parse(). Not JSON.");
        return self.refusal('STS-OAUTH-0450', 'authorization_details is ' +
                            'not readable JSON: ' + e.message);
      }
    }
    if (!Array.isArray(parsed)) {
      log.debug("Leaving AuthorizationDetails.parse(). Not an array.");
      return self.refusal('STS-OAUTH-0450', 'authorization_details must be ' +
                          'a JSON array of objects (RFC 9396 section 2).');
    }
    if (!parsed.length) {
      log.debug("Leaving AuthorizationDetails.parse(). An empty array.");
      return { ok: true, details: null, resolved: [] };
    }
    const max = Number(config.value('oauth2.authorizationDetailsMaxEntries'));
    if (parsed.length > max) {
      log.debug("Leaving AuthorizationDetails.parse(). Too many.");
      return self.refusal('STS-OAUTH-0450', 'authorization_details carries ' +
                          parsed.length + ' entries, and this authorization ' +
                          'server accepts at most ' + max + ' in one ' +
                          'request (oauth2.authorizationDetailsMaxEntries).');
    }
    const clientTypes = (options.clientTypes || []).map(String);
    const profileTypes = Array.isArray(options.profileTypes)
      ? options.profileTypes.map(String) : null;
    const declared = self.declaredTypes();
    const details = [];
    const resolved = [];
    for (let i = 0; i < parsed.length; i++) {
      const detail = parsed[i];
      const where = 'authorization_details[' + i + ']';
      if (!detail || typeof detail !== 'object' || Array.isArray(detail)) {
        log.debug("Leaving AuthorizationDetails.parse(). Not an object.");
        return self.refusal('STS-OAUTH-0451', where +
                            ' is not a JSON object.');
      }
      if (typeof detail.type !== 'string' || !detail.type) {
        log.debug("Leaving AuthorizationDetails.parse(). No type.");
        return self.refusal('STS-OAUTH-0451', where + ' has no `type`, ' +
                            'which RFC 9396 section 2 makes REQUIRED: it is ' +
                            'what says how the rest of the object is read.');
      }
      const common = self.commonFieldProblem(detail, i);
      if (common) {
        log.debug("Leaving AuthorizationDetails.parse(). A common data " +
                  "field.");
        return self.refusal('STS-OAUTH-0452', common);
      }
      // WHETHER ANYTHING UNDERSTANDS THE TYPE comes first, so an unknown type
      // is named as unknown rather than as missing from a list that could
      // never have held it.
      const builtInType =
        applications.AUTHORIZATION_DETAILS_BUILT_IN.indexOf(detail.type) >= 0;
      const definition = builtInType ? null : declared[detail.type];
      if (!builtInType && !definition) {
        log.debug("Leaving AuthorizationDetails.parse(). An unknown type.");
        return self.refusal('STS-OAUTH-0453', where + ' is of type "' +
          detail.type + '", which no application in this realm declares ' +
          '(oauthAuthorizationDetailsType) and this service does not ' +
          'understand itself. RFC 9396 section 5 requires an unknown type ' +
          'to be refused. This authorization server supports ' +
          JSON.stringify(self.typesSupported()) + '.');
      }
      if (clientTypes.length && clientTypes.indexOf(detail.type) < 0) {
        log.debug("Leaving AuthorizationDetails.parse(). Not a type the " +
                  "client registered.");
        return self.refusal('STS-OAUTH-0454', where + ' is of type "' +
          detail.type + '", and this client registered ' +
          'authorization_details_types ' + JSON.stringify(clientTypes) +
          ' (RFC 9396 section 10).');
      }
      if (profileTypes && profileTypes.indexOf(detail.type) < 0) {
        log.debug("Leaving AuthorizationDetails.parse(). Not a type this " +
                  "server publishes.");
        return self.refusal('STS-OAUTH-0455', where + ' is of type "' +
          detail.type + '", and this authorization server publishes ' +
          'authorization_details_types_supported ' +
          JSON.stringify(profileTypes) + '.');
      }
      if (builtInType) {
        const built = typeof options.builtIn === 'function'
          ? options.builtIn(detail, i)
          : { entry: detail };
        if (!built || built.error) {
          log.debug("Leaving AuthorizationDetails.parse(). The built-in " +
                    "type refused it.");
          return errorCodes.mark({ ok: false,
            error: (built && built.error) || where + ' is not usable.' },
            errorCodes.codeOf(built) || 'STS-OAUTH-0153');
        }
        details.push(built.entry);
        resolved.push({ detail: built.entry, definition: null });
        continue;
      }
      if (definition.validate && !definition.validate(detail)) {
        log.debug("Leaving AuthorizationDetails.parse(). The type's schema " +
                  "refused it.");
        return self.refusal('STS-OAUTH-0456', where + ' does not conform to ' +
          'the definition of "' + detail.type + '" that "' +
          definition.identifier + '" declares: ' +
          self.schemaProblem(definition.validate) + ' (RFC 9396 ' +
          'section 5).');
      }
      const strangers = (detail.locations || []).filter(function (one) {
        return definition.identifiers.indexOf(one) < 0;
      });
      if (strangers.length) {
        log.debug("Leaving AuthorizationDetails.parse(). A location the " +
                  "resource does not declare.");
        return self.refusal('STS-OAUTH-0457', where + ' names the location' +
          (strangers.length === 1 ? ' ' : 's ') +
          strangers.map(function (one) {
            return '"' + one + '"';
          }).join(', ') + ', and "' + definition.identifier + '", which ' +
          'declares "' + detail.type + '", answers to ' +
          definition.identifiers.map(function (one) {
            return '"' + one + '"';
          }).join(', ') + '. A token is addressed to its locations, so a ' +
          'location nobody declared would be an audience nobody checks.');
      }
      details.push(detail);
      resolved.push({ detail: detail, definition: definition });
    }
    log.debug("Leaving AuthorizationDetails.parse(). " + details.length +
              " detail(s).");
    return { ok: true, details: details, resolved: resolved };
  }

  private deepEqual(a: unknown, b: unknown): boolean {
    const { log } = this.deps;
    log.debug("Entering AuthorizationDetails.deepEqual().");
    log.debug("Leaving AuthorizationDetails.deepEqual().");
    return JSON.stringify(this.canonical(a)) ===
      JSON.stringify(this.canonical(b));
  }

  // A value with every object's members in sorted order, so two JSON
  // documents that differ only in member order are one value — for the
  // comparison above and for the consent digest.
  private canonical(value: Json): Json {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering AuthorizationDetails.canonical().");
    if (Array.isArray(value)) {
      log.debug("Leaving AuthorizationDetails.canonical(). An array.");
      return value.map(self.canonical.bind(self));
    }
    if (value && typeof value === 'object') {
      const out: Json = {};
      Object.keys(value).sort().forEach(function (key) {
        out[key] = self.canonical(value[key]);
      });
      log.debug("Leaving AuthorizationDetails.canonical(). An object.");
      return out;
    }
    log.debug("Leaving AuthorizationDetails.canonical().");
    return value;
  }

  // Whether ONE granted detail covers ONE requested detail: the same type,
  // every common array of the request a subset of the grant's (and absent from
  // the request means "as granted"), every other member the request carries
  // equal to the grant's. Members only the grant carries are fine — that is
  // what an ENRICHED detail (section 7) looks like, and a token request is not
  // expected to repeat what the server added.
  covers(granted: Json, requested: Json): boolean {
    const { log } = this.deps;
    log.debug("Entering AuthorizationDetails.covers().");
    if (!granted || granted.type !== requested.type) {
      log.debug("Leaving AuthorizationDetails.covers(). Another type.");
      return false;
    }
    const keys = Object.keys(requested);
    for (let i = 0; i < keys.length; i++) {
      const key = keys[i];
      if (key === 'type') {
        continue;
      }
      if (COMMON_ARRAYS.indexOf(key) >= 0) {
        const allowed = Array.isArray(granted[key]) ? granted[key] : null;
        if (!allowed || !requested[key].every(function (one) {
          return allowed.indexOf(one) >= 0;
        })) {
          log.debug("Leaving AuthorizationDetails.covers(). " + key +
                    " widens.");
          return false;
        }
        continue;
      }
      if (!this.deepEqual(granted[key], requested[key])) {
        log.debug("Leaving AuthorizationDetails.covers(). " + key +
                  " differs.");
        return false;
      }
    }
    log.debug("Leaving AuthorizationDetails.covers().");
    return true;
  }

  // SECTION 6: a token request's details, against what the grant authorized.
  // As a sentence for `invalid_authorization_details`, or ''.
  coveredProblem(requested: Json[], granted: Json): string {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering AuthorizationDetails.coveredProblem().");
    const grant = Array.isArray(granted) ? granted : [];
    for (let i = 0; i < (requested || []).length; i++) {
      const one = requested[i];
      const found = grant.some(function (g) {
        return self.covers(g, one);
      });
      if (!found) {
        log.debug("Leaving AuthorizationDetails.coveredProblem(). Not " +
                  "covered.");
        return 'authorization_details[' + i + '] (type "' + one.type +
          '") is not covered by what this grant authorized — ' +
          (grant.length
            ? JSON.stringify(grant).slice(0, 400)
            : 'no authorization_details at all') +
          '. RFC 9396 section 6: a token request may ask for a subset of ' +
          'the authorized details and not for more.';
      }
    }
    log.debug("Leaving AuthorizationDetails.coveredProblem().");
    return '';
  }

  // What a token carries when a token request asked for a covered subset: the
  // requested details, except that a BUILT-IN detail is replaced by the
  // granted one covering it, which carries what the server added (OpenID4VCI's
  // `credential_identifiers`) and which the request is not expected to repeat.
  // Call it only after `coveredProblem()` answered ''.
  narrow(requested: Json[], granted: Json): Json[] {
    const { log, applications } = this.deps;
    const self = this;
    log.debug("Entering AuthorizationDetails.narrow().");
    const grant = Array.isArray(granted) ? granted : [];
    const out = (requested || []).map(function (one) {
      if (applications.AUTHORIZATION_DETAILS_BUILT_IN.indexOf(one.type) < 0) {
        return one;
      }
      return grant.filter(function (g) {
        return self.covers(g, one);
      })[0] || one;
    });
    log.debug("Leaving AuthorizationDetails.narrow(). " + out.length +
              " detail(s).");
    return out;
  }

  // -------------------------------------------------------------------------
  // WHICH RESOURCE A SET OF DETAILS ADDRESSES — the input
  // `jwt_access_token.audiencePlan()` takes as `details`.
  //
  // `{ resources, audiences, identifiers }`: the applications declaring the
  // types, the audiences a token for them carries (each detail's `locations`,
  // or its resource's primary identifier), and every identifier that resource
  // answers to — which is what a `resource` parameter or a scope may name
  // beside the details without naming a second API. The built-in type
  // addresses nothing: an OpenID4VCI token is for this service's own
  // credential endpoint. Details carried on a grant from before a definition
  // was removed resolve to nothing rather than throwing.
  // -------------------------------------------------------------------------
  audienceFor(details: Json[]): Json {
    const { log } = this.deps;
    log.debug("Entering AuthorizationDetails.audienceFor().");
    const declared = this.declaredTypes();
    const resources = [];
    const audiences = [];
    const identifiers = [];
    (details || []).forEach(function (detail) {
      const definition = detail && declared[detail.type];
      if (!definition) {
        return;
      }
      if (resources.indexOf(definition.identifier) < 0) {
        resources.push(definition.identifier);
      }
      (Array.isArray(detail.locations) && detail.locations.length
        ? detail.locations : [definition.primary]).forEach(function (one) {
        if (audiences.indexOf(one) < 0) {
          audiences.push(one);
        }
      });
      definition.identifiers.forEach(function (one) {
        if (identifiers.indexOf(one) < 0) {
          identifiers.push(one);
        }
      });
    });
    log.debug("Leaving AuthorizationDetails.audienceFor(). " +
              resources.length + " resource(s).");
    return { resources: resources, audiences: audiences,
             identifiers: identifiers };
  }

  // Whether a request's details need the consent screen: any detail of a type
  // an application declares. See the header for why `openid_credential` does
  // not.
  needsConsent(details: Json[]): boolean {
    const { log, applications } = this.deps;
    log.debug("Entering AuthorizationDetails.needsConsent().");
    const answer = (details || []).some(function (one) {
      return one && applications.AUTHORIZATION_DETAILS_BUILT_IN
        .indexOf(one.type) < 0;
    });
    log.debug("Leaving AuthorizationDetails.needsConsent(). " + answer);
    return answer;
  }

  // What the consent screen draws, one row per detail: the type, what the
  // resource said the type means, the resource, and every other member as it
  // was sent. Values are strings for the screen to escape.
  describe(details: Json[]): Json[] {
    const { log } = this.deps;
    log.debug("Entering AuthorizationDetails.describe().");
    const declared = this.declaredTypes();
    const rows = (details || []).map(function (detail) {
      const definition = declared[detail.type] || null;
      const members = Object.keys(detail).filter(function (key) {
        return key !== 'type';
      }).map(function (key) {
        const value = detail[key];
        return { name: key,
                 value: typeof value === 'string' ? value :
                        JSON.stringify(value) };
      });
      return {
        type: detail.type,
        description: definition ? definition.description : '',
        resource: definition ? definition.identifier : '',
        resourceName: definition ? definition.name : '',
        audience: definition
          ? (Array.isArray(detail.locations) && detail.locations.length
            ? detail.locations.join(', ') : definition.primary)
          : '',
        members: members
      };
    });
    log.debug("Leaving AuthorizationDetails.describe(). " + rows.length +
              " row(s).");
    return rows;
  }

  // A SHA-256 of the canonical array, base64url. What Allow is recorded
  // against, so an Allow for one amount is not an Allow for another.
  digestOf(details: Json[]): string {
    const { log, crypto } = this.deps;
    log.debug("Entering AuthorizationDetails.digestOf().");
    log.debug("Leaving AuthorizationDetails.digestOf().");
    return crypto.createHash('sha256')
      .update(JSON.stringify(this.canonical(details || [])))
      .digest('base64url');
  }

  private consentKey(username: unknown, clientId: unknown,
                     digest: unknown): string {
    const { log } = this.deps;
    log.debug("Entering AuthorizationDetails.consentKey().");
    log.debug("Leaving AuthorizationDetails.consentKey().");
    return String(username || '') + ' ' + String(clientId || '') + ' ' +
           String(digest || '');
  }

  private consentTtlMs(): number {
    const { log, config } = this.deps;
    log.debug("Entering AuthorizationDetails.consentTtlMs().");
    const seconds = Number(config.value('authn.pendingTtlS'));
    log.debug("Leaving AuthorizationDetails.consentTtlMs().");
    return (seconds > 0 ? seconds : 600) * 1000;
  }

  // The person pressed Allow on these details for this client.
  noteConsented(username: unknown, clientId: unknown, digest: unknown): void {
    const { log } = this.deps;
    log.debug("Entering AuthorizationDetails.noteConsented().");
    const now = Date.now();
    consented.forEach(function (expires, key) {
      if (expires < now) {
        consented.delete(key);
      }
    });
    consented.set(this.consentKey(username, clientId, digest),
                  now + this.consentTtlMs());
    log.debug("Leaving AuthorizationDetails.noteConsented().");
  }

  // Whether they did, SPENDING the answer: one Allow is one authorization
  // response. A second request carrying the same array asks again.
  consumeConsented(username: unknown, clientId: unknown,
                   digest: unknown): boolean {
    const { log } = this.deps;
    log.debug("Entering AuthorizationDetails.consumeConsented().");
    const key = this.consentKey(username, clientId, digest);
    const expires = consented.get(key);
    if (expires === undefined) {
      log.debug("Leaving AuthorizationDetails.consumeConsented(). Not " +
                "consented.");
      return false;
    }
    consented.delete(key);
    log.debug("Leaving AuthorizationDetails.consumeConsented(). " +
              (expires >= Date.now()));
    return expires >= Date.now();
  }
}

// THE TRANSITIONAL INSTANCE — see the header above. Built from the real
// modules, as the composition root will build one.
const details = new AuthorizationDetails({
  crypto: crypto,
  applications: applications,
  config: config,
  errorCodes: errorCodes,
  log: helpers.log
});

export = {
  AuthorizationDetails: AuthorizationDetails,
  COMMON_ARRAYS: AuthorizationDetails.COMMON_ARRAYS,
  declaredTypes: details.declaredTypes.bind(details) as
    AuthorizationDetails['declaredTypes'],
  typesSupported: details.typesSupported.bind(details) as
    AuthorizationDetails['typesSupported'],
  parse: details.parse.bind(details) as AuthorizationDetails['parse'],
  covers: details.covers.bind(details) as AuthorizationDetails['covers'],
  coveredProblem: details.coveredProblem.bind(details) as
    AuthorizationDetails['coveredProblem'],
  narrow: details.narrow.bind(details) as AuthorizationDetails['narrow'],
  audienceFor: details.audienceFor.bind(details) as
    AuthorizationDetails['audienceFor'],
  needsConsent: details.needsConsent.bind(details) as
    AuthorizationDetails['needsConsent'],
  describe: details.describe.bind(details) as AuthorizationDetails['describe'],
  digestOf: details.digestOf.bind(details) as AuthorizationDetails['digestOf'],
  noteConsented: details.noteConsented.bind(details) as
    AuthorizationDetails['noteConsented'],
  consumeConsented: details.consumeConsented.bind(details) as
    AuthorizationDetails['consumeConsented']
};
