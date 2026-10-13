// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

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
// for `oauth2.ts`, `consent_screen.ts` and the rest that require it by those
// names. Since R2 those functions are FACADES: the composition root builds
// the instance and installs it, and a process that loads this module without
// the root builds a default instance at load, as loading it always did.
// ===========================================================================

// `common/crypto.js`, the one place this service computes a digest (#453);
// the deps still call it `crypto`.
import stsCrypto = require('../common/crypto');
import applications = require('../common/applications');
import config = require('../common/config');
import errorCodes = require('../common/error_codes');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import realms = require('../common/realms');
import cacheRegistry = require('../common/cache_registry');
// The limits vocabulary (#432 phase 5): a static utility class, a leaf.
import AccessLimits = require('../common/access_limits');
// THE TWO AUTHORIZATION QUESTIONS ABOUT A DETAIL'S TYPE ARE THE ISSUANCE
// POLICY'S (#305, part D of #88): whether the client registered types and
// not this one (RFC 9396 section 10), and whether this authorization server
// publishes a list without it. The rest of `parse()` is RFC 9396
// WELL-FORMEDNESS — an unknown type, a schema, a location nobody declared —
// and stays here: it is not an authorization decision.
import gate = require('../common/issuance_gate');
import scopeVerdicts = require('../xacml/xacml_scope_verdicts');

// A loose JSON-shaped object: a detail, a definition, a refusal.
type Json = any;

interface AuthorizationDetailsDeps {
  crypto: typeof stsCrypto;
  applications: typeof applications;
  config: typeof config;
  errorCodes: typeof errorCodes;
  log: typeof helpers.log;
  gate: typeof gate;
  scopeVerdicts: typeof scopeVerdicts;
}

// A refusal of `conformance()`, by kind, as RFC 9396's codes: the schema's
// own (0456) for a definition, the location one (0457), and #432 phase 4's
// two about limits.
const CONFORMANCE_CODES: Record<string, string> = {
  definition: 'STS-OAUTH-0456',
  location: 'STS-OAUTH-0457',
  'limits-undeclared': 'STS-OAUTH-0876',
  limits: 'STS-OAUTH-0877',
  // #432 phase 5: a limit whose amount, count, receiver, interval or window
  // is not one `common/access_limits.ts` can read.
  'limits-value': 'STS-OAUTH-0916'
};

// Section 2.2's common data fields: four arrays of strings and one string.
const COMMON_ARRAYS = ['locations', 'actions', 'datatypes', 'privileges'];
const COMMON_STRINGS = ['identifier'];

// A parsed definition per distinct attribute value. The value is the key, so an
// edited definition is a different entry and nothing has to be invalidated; the
// bound only stops a process that has seen a great many from holding them all.
const definitionCache = new Map();
const MAX_CACHED_DEFINITIONS = 512;

// Described to `/admin/caches` (#74, rule 3ap). A row names the type and how
// long its definition is; the definition and its compiled schema stay here.
const definitionCount = cacheRegistry.register({
  name: 'oauth2.authorization-details-types',
  title: 'Parsed authorization_details types',
  description: 'RFC 9396 type definitions declared on resource ' +
    'applications, parsed and their JSON Schemas compiled once per distinct ' +
    'definition text. Shared by every realm, because the text is the key.',
  owner: 'oauth-oidc/authorization_details.ts',
  scope: 'process',
  maxEntries: function (): number {
    return MAX_CACHED_DEFINITIONS;
  },
  bound: 'Enforced: 512 parsed definitions, the oldest dropped and parsed ' +
    'again when next used.',
  lifetime: function (): string {
    return 'No expiry: keyed by the definition text, so an edited ' +
      'definition is a new entry. The oldest goes first when full.';
  },
  entries: function (): unknown[] {
    const out: unknown[] = [];
    definitionCache.forEach(function (parsed: Json, text: string): void {
      out.push({
        key: (parsed && parsed.type ? parsed.type : '(unusable)') +
          ' — ' + text.length + ' characters' +
          (parsed && parsed.problem ? ' — ' + parsed.problem : ''),
        validUntil: null,
        basis: 'content-keyed'
      });
    });
    return out;
  }
});

// ALLOW, ONCE: `username client digest` → expiry. Persisted, because the
// consent POST and the authorization endpoint's second pass may be answered by
// two different request workers.
const consented = realms.map({ persist: 'authorization_details.consented',
                               // #333: `expires`, in ms. Beside it (#432
                               // phase 5) the details as the person LOWERED
                               // their limits on the screen, or null.
                               expiresAt: realms.expiryField('expires', 1) });

/**
 * RFC 9396 rich authorization requests: the types applications declare, the
 * parsing and checking of `authorization_details`, section 6's subset rule, the
 * audience the details address, and the consent they need.
 */
class AuthorizationDetails {
  /**
   * Section 2.2's common data fields that are arrays of strings.
   */
  static readonly COMMON_ARRAYS = COMMON_ARRAYS;

  /**
   * Builds the module from its dependencies.
   *
   * @param deps - the crypto module, application registry, settings, error
   *   codes and logger
   */
  constructor(private readonly deps: AuthorizationDetailsDeps) {
    deps.log.debug("Entering AuthorizationDetails.constructor().");
    deps.log.debug("Leaving AuthorizationDetails.constructor().");
  }

  // What the composition root passes: the deps the module built its
  // own instance from before R2, from the same imports.
  /**
   * Returns the dependencies built from this module's own imports.
   *
   * @returns the default dependency set
   */
  static defaultDeps(): AuthorizationDetailsDeps {
    helpers.log.debug("Entering AuthorizationDetails.defaultDeps().");
    helpers.log.debug("Leaving AuthorizationDetails.defaultDeps().");
    return {
      crypto: stsCrypto,
      applications: applications,
      config: config,
      errorCodes: errorCodes,
      log: helpers.log,
      gate: gate,
      scopeVerdicts: scopeVerdicts
    };
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
      definitionCount.hit();
      log.debug("Leaving AuthorizationDetails.definitionOf(). Cached.");
      return definitionCache.get(key);
    }
    definitionCount.miss();
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
  /**
   * Returns the types this realm's applications declare, each with the
   * application that declared it; an unusable or duplicate declaration is
   * skipped with a warning.
   *
   * @returns type to definition
   */
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
    // A GNAP RESOURCE SERVER answers to its `gnapResourceServerUri` values
    // too (#432 phase 4): the catalogue is GNAP's as well, and an access
    // right names the resource server's address as its location.
    const gnapUris = this.valuesOf(fields.gnapResourceServerUri).map(String);
    log.debug("Leaving AuthorizationDetails.resourceDefinition().");
    return {
      type: definition.type,
      description: definition.description,
      schema: definition.schema,
      validate: definition.validate,
      identifier: row.identifier,
      name: row.name || row.identifier,
      clientId: clientId,
      primary: primary,
      identifiers: this.unique([primary].concat(audiences,
                                                clientId ? [clientId] : [],
                                                gnapUris,
                                                definition.locations)),
      locations: definition.locations.slice(0),
      // THE CATALOGUE'S DECLARATIONS (#432 phase 4), as
      // `applications.authorizationDetailsTypeOf()` read them.
      actions: definition.actions, datatypes: definition.datatypes,
      privileges: definition.privileges, required: definition.required,
      interaction: definition.interaction,
      consentActions: definition.consentActions, bearer: definition.bearer,
      maxLifetimeS: definition.maxLifetimeS, acr: definition.acr,
      derivableFrom: definition.derivableFrom,
      introspectionClaims: definition.introspectionClaims,
      limits: definition.limits, validateLimits: definition.validateLimits
    };
  }

  // -------------------------------------------------------------------------
  // ONE RIGHT AGAINST ITS CATALOGUE ENTRY (#432 phase 4) — the questions a
  // type's DEFINITION answers, asked identically of an RFC 9396 detail and
  // of a GNAP access right, which share the five common fields (RFC 9396
  // section 2.2 is RFC 9635 section 8's list). Well-formedness, not
  // authorization: whether the right is ISSUED is the issuance policy's
  // (rule 3bt for RAR's two type questions, `issue-gnap-right` for GNAP).
  //
  // `{ kind, problem }`, kind '' when it conforms, otherwise:
  //   definition          a value outside `actions` / `datatypes` /
  //                       `privileges`, a `required` member missing, or the
  //                       type's JSON Schema refusing it
  //   limits-undeclared   a `limits` member on a type that declares no limits
  //                       schema
  //   limits              a `limits` member its schema refuses
  //   limits-value        a `limits` member whose amount, count, receiver,
  //                       interval or window means nothing (#432 phase 5,
  //                       `common/access_limits.ts`)
  //   location            a location the owning resource does not answer to
  // -------------------------------------------------------------------------
  /**
   * Checks one right — an RFC 9396 detail or a GNAP access right — against
   * the catalogue entry of its type.
   *
   * @param right - the detail or right (an object carrying `type`)
   * @param definition - the type's entry from `declaredTypes()`
   * @param where - how a sentence names the right
   * @returns `{ kind, problem }`; `kind` is '' when the right conforms
   */
  conformance(right: Json, definition: Json, where: string): Json {
    const { log } = this.deps;
    log.debug("Entering AuthorizationDetails.conformance().");
    const ok = { kind: '', problem: '' };
    if (!right || typeof right !== 'object' || !definition) {
      log.debug("Leaving AuthorizationDetails.conformance(). Nothing to " +
                "compare.");
      return ok;
    }
    const lists = ['actions', 'datatypes', 'privileges'];
    for (let i = 0; i < lists.length; i++) {
      const name = lists[i];
      const allowed = definition[name];
      if (!Array.isArray(allowed) || !Array.isArray(right[name])) {
        continue;
      }
      const strangers = right[name].filter(function (one: Json): boolean {
        return allowed.indexOf(one) < 0;
      });
      if (strangers.length) {
        log.debug("Leaving AuthorizationDetails.conformance(). " + name +
                  ".");
        return { kind: 'definition', problem: where + '.' + name +
          ' names ' + JSON.stringify(strangers).slice(0, 200) + ', and the ' +
          'type "' + definition.type + '" (declared by "' +
          definition.identifier + '") allows only ' +
          JSON.stringify(allowed).slice(0, 300) };
      }
    }
    const missing = (definition.required || []).filter(function (one: string):
        boolean {
      return right[one] === undefined || right[one] === null;
    });
    if (missing.length) {
      log.debug("Leaving AuthorizationDetails.conformance(). required.");
      return { kind: 'definition', problem: where + ' carries no ' +
        missing.join(', ') + ', which the type "' + definition.type +
        '" (declared by "' + definition.identifier + '") requires' };
    }
    if (definition.validate && !definition.validate(right)) {
      log.debug("Leaving AuthorizationDetails.conformance(). The schema.");
      return { kind: 'definition', problem: where + ' does not conform to ' +
        'the definition of "' + definition.type + '" that "' +
        definition.identifier + '" declares: ' +
        this.schemaProblem(definition.validate) };
    }
    if (right.limits !== undefined) {
      if (!definition.validateLimits) {
        log.debug("Leaving AuthorizationDetails.conformance(). Limits on a " +
                  "type that declares none.");
        return { kind: 'limits-undeclared', problem: where + ' carries ' +
          'limits, and the type "' + definition.type + '" declares no ' +
          'limits schema, so no limit on it means anything this ' +
          'authorization server could show or check' };
      }
      if (!definition.validateLimits(right.limits)) {
        log.debug("Leaving AuthorizationDetails.conformance(). Limits " +
                  "refused.");
        return { kind: 'limits', problem: where + '.limits does not meet ' +
          'the limits schema of "' + definition.type + '": ' +
          this.schemaProblem(definition.validateLimits) };
      }
      // THE VOCABULARY (#432 phase 5): the schema says what SHAPE a limit
      // has; `common/access_limits.ts` says what its five members with a
      // meaning — amount, count, receiver, interval, window — must be for
      // the approval page to lower them and a resource server to count
      // against them. Asked of both protocols here, so a RAR detail and a
      // GNAP right of one type are held to one reading.
      const meaning = AccessLimits.problem(right.limits);
      if (meaning) {
        log.debug("Leaving AuthorizationDetails.conformance(). Limits " +
                  "vocabulary.");
        return { kind: 'limits-value', problem: where + '.limits is not a ' +
          'limit this service can read: ' + meaning };
      }
    }
    const strangers = (Array.isArray(right.locations) ? right.locations : [])
      .filter(function (one: Json): boolean {
        return definition.identifiers.indexOf(one) < 0;
      });
    if (strangers.length) {
      log.debug("Leaving AuthorizationDetails.conformance(). A location.");
      return { kind: 'location', problem: where + ' names the location' +
        (strangers.length === 1 ? ' ' : 's ') +
        strangers.map(function (one: Json): string {
          return '"' + one + '"';
        }).join(', ') + ', and "' + definition.identifier + '", which ' +
        'declares "' + right.type + '", answers to ' +
        definition.identifiers.map(function (one: Json): string {
          return '"' + one + '"';
        }).join(', ') + '. A token is addressed to its locations, so a ' +
        'location nobody declared would be an audience nobody checks' };
    }
    log.debug("Leaving AuthorizationDetails.conformance().");
    return ok;
  }

  // The catalogue entry of one type in this realm, or null (#432 phase 4).
  /**
   * Returns the catalogue entry of one type in this realm.
   *
   * @param type - the type name
   * @returns the entry, as `declaredTypes()` holds it, or null
   */
  typeOf(type: unknown): Json {
    const { log } = this.deps;
    log.debug("Entering AuthorizationDetails.typeOf().");
    const name = typeof type === 'string' ? type : '';
    const found = name ? this.declaredTypes()[name] || null : null;
    log.debug("Leaving AuthorizationDetails.typeOf(). " + !!found);
    return found;
  }

  // The shortest `maxLifetimeS` among a set of details' types, or null where
  // none declares one (#432 phase 4) — what `oauth2.ts` caps an access token
  // carrying them at. A GNAP token's cap is the issuance policy's obligation
  // instead (`issue-gnap-right`), which reads the same declaration.
  /**
   * Returns the shortest maximum lifetime the types of a set of details
   * declare.
   *
   * @param details - RFC 9396 details
   * @returns seconds, or null when no type declares one
   */
  maxLifetimeFor(details: Json[]): number | null {
    const { log } = this.deps;
    log.debug("Entering AuthorizationDetails.maxLifetimeFor().");
    const declared = this.declaredTypes();
    let out: number | null = null;
    (details || []).forEach(function (one: Json): void {
      const definition = one && declared[one.type];
      if (definition && typeof definition.maxLifetimeS === 'number' &&
          (out === null || definition.maxLifetimeS < out)) {
        out = definition.maxLifetimeS;
      }
    });
    log.debug("Leaving AuthorizationDetails.maxLifetimeFor(). " + out);
    return out;
  }

  // Whether any of a set of details carries `limits` (#432 phase 5): what
  // makes `oauth2.ts` put a grant identifier on the access token, so the
  // resource server has one stable key to keep its running totals under.
  /**
   * Says whether any detail of a set carries limits.
   *
   * @param details - RFC 9396 details
   * @returns true when one does
   */
  carriesLimits(details: Json[]): boolean {
    const { log } = this.deps;
    log.debug("Entering AuthorizationDetails.carriesLimits().");
    const out = (Array.isArray(details) ? details : []).some(
      function (one: Json): boolean {
        return !!one && typeof one === 'object' && one.limits !== undefined;
      });
    log.debug("Leaving AuthorizationDetails.carriesLimits(). " + out);
    return out;
  }

  // Whether `lowered` is the same details as `asked` with no limit raised
  // (#432 phase 5): the same number of details, each the same but for its
  // `limits`, and those no more than asked (`common/access_limits.ts`).
  // '' when it is, or the sentence naming the first that is not.
  /**
   * Says whether one list of details is another with limits lowered only.
   *
   * @param asked - the details the client sent
   * @param lowered - the details as the person lowered them
   * @returns '' when only limits were lowered, or the problem
   */
  limitsRaisedBy(asked: Json[], lowered: Json[]): string {
    const { log } = this.deps;
    log.debug("Entering AuthorizationDetails.limitsRaisedBy().");
    const a = Array.isArray(asked) ? asked : [];
    const b = Array.isArray(lowered) ? lowered : [];
    if (a.length !== b.length) {
      log.debug("Leaving AuthorizationDetails.limitsRaisedBy(). Count.");
      return 'the lowered authorization_details are not the details asked for';
    }
    for (let i = 0; i < a.length; i++) {
      const was = Object.assign({}, a[i]);
      const now = Object.assign({}, b[i]);
      delete was.limits;
      delete now.limits;
      if (JSON.stringify(this.sorted(was)) !==
          JSON.stringify(this.sorted(now))) {
        log.debug("Leaving AuthorizationDetails.limitsRaisedBy(). Changed.");
        return 'authorization_details[' + i + '] changed beyond its limits';
      }
      const why = AccessLimits.raised(a[i] && a[i].limits,
                                      b[i] && b[i].limits);
      if (why) {
        log.debug("Leaving AuthorizationDetails.limitsRaisedBy(). Raised.");
        return 'authorization_details[' + i + ']: ' + why;
      }
    }
    log.debug("Leaving AuthorizationDetails.limitsRaisedBy().");
    return '';
  }

  // A value with its object keys in order, for comparing.
  private sorted(value: Json): Json {
    const { log } = this.deps;
    log.debug("Entering AuthorizationDetails.sorted().");
    const self = this;
    let out: Json = value;
    if (Array.isArray(value)) {
      out = value.map(function (one: Json): Json {
        return self.sorted(one);
      });
    } else if (value && typeof value === 'object') {
      out = {};
      Object.keys(value).sort().forEach(function (k: string): void {
        out[k] = self.sorted(value[k]);
      });
    }
    log.debug("Leaving AuthorizationDetails.sorted().");
    return out;
  }

  // The first type among a set of details that declares `bearer: false`, or
  // '' (#432 phase 4): a token carrying it must be sender-constrained.
  /**
   * Returns the first type among a set of details that refuses a bearer
   * token.
   *
   * @param details - RFC 9396 details
   * @returns the type name, or ''
   */
  bearerRefusedBy(details: Json[]): string {
    const { log } = this.deps;
    log.debug("Entering AuthorizationDetails.bearerRefusedBy().");
    const declared = this.declaredTypes();
    const hit = (details || []).filter(function (one: Json): boolean {
      const definition = one && declared[one.type];
      return !!definition && definition.bearer === false;
    })[0];
    log.debug("Leaving AuthorizationDetails.bearerRefusedBy().");
    return hit ? String(hit.type) : '';
  }

  // -------------------------------------------------------------------------
  // THE AUTHENTICATION LEVELS A SET OF DETAILS NEEDS (#432 phase 6): every
  // `acr` the catalogue declares for a type among them, each REQUIRED — a
  // grant carrying two types is a grant of both, so it must meet both, which
  // is not `acr_values`' "any of". GNAP's approval holds a session to the
  // same declarations (`gnap/gnap_approval.ts`); the authorization endpoint
  // and the token endpoint's funnel ask this.
  // -------------------------------------------------------------------------
  /**
   * Returns every acr the catalogue declares for a type among some details.
   *
   * @param details - RFC 9396 details
   * @returns the distinct values, each required
   */
  requiredAcrsOf(details: Json[]): string[] {
    const { log } = this.deps;
    log.debug("Entering AuthorizationDetails.requiredAcrsOf().");
    const declared = this.declaredTypes();
    const out: string[] = [];
    (details || []).forEach(function (one: Json): void {
      const definition = one && declared[one.type];
      const acr = definition && definition.acr ? String(definition.acr) : '';
      if (acr && out.indexOf(acr) < 0) {
        out.push(acr);
      }
    });
    log.debug("Leaving AuthorizationDetails.requiredAcrsOf(). " +
              out.join(' '));
    return out;
  }

  // Whether a right of `type` may be DERIVED from a token carrying the types
  // `originalTypes` (RFC 9767 section 4; rcbj's decision 3 on #432): the
  // catalogue entry of `type` names one of them in `derivableFrom`.
  /**
   * Tells whether a right of one type may be derived from a token carrying
   * others, by the catalogue's `derivableFrom`.
   *
   * @param type - the derived right's type
   * @param originalTypes - the types the original token carries
   * @returns the original type it is derivable from, or ''
   */
  derivableFrom(type: unknown, originalTypes: string[]): string {
    const { log } = this.deps;
    log.debug("Entering AuthorizationDetails.derivableFrom().");
    const definition = this.typeOf(type);
    const from = definition ? (definition.derivableFrom || []).filter(
      function (one: string): boolean {
        return (originalTypes || []).indexOf(one) >= 0;
      })[0] || '' : '';
    log.debug("Leaving AuthorizationDetails.derivableFrom(). " +
              (from || 'No.'));
    return from;
  }

  // Whether an application is the OWNER of a catalogue entry: its identifier,
  // or (an OAuth caller is named by client_id) its client_id.
  /**
   * Tells whether a caller — an application identifier or a client_id — owns
   * a catalogue entry.
   *
   * @param definition - the entry
   * @param caller - the application identifier or client_id
   * @returns true when it is the owner
   */
  ownedBy(definition: Json, caller: unknown): boolean {
    const { log } = this.deps;
    log.debug("Entering AuthorizationDetails.ownedBy().");
    const name = String(caller || '');
    const answer = !!definition && !!name &&
      (definition.identifier === name ||
       (!!definition.clientId && definition.clientId === name));
    log.debug("Leaving AuthorizationDetails.ownedBy(). " + answer);
    return answer;
  }

  // -------------------------------------------------------------------------
  // WHAT A RESOURCE SERVER SEES AT INTROSPECTION (#432 phase 4), for RFC
  // 9396's `authorization_details` and GNAP's `access` alike: FILTERED PER
  // RESOURCE SERVER, which RFC 9767 section 3.3 permits ("the AS MAY ...
  // limit the access returned") and RFC 7662 section 2.2 leaves to the
  // server.
  //
  //   * A right of a catalogued type OWNED BY ANOTHER resource server is
  //     withheld: the caller may be in the token's audience for its own
  //     rights, and another API's rights say what the person granted
  //     somebody else.
  //   * The person's claims the caller's OWN types declare in
  //     `introspectionClaims` are added, read off the directory through
  //     `common/claim_attributes.ts`'s `requestedClaimsFor()` — the one
  //     reader of the attribute catalogue (OIDC Core section 5.5's door) —
  //     and only for a token about a person.
  //
  // `rights` is the token's list; `caller` the resource server's application
  // identifier or client_id; `username` the person, or ''. Answers `{ rights,
  // claims, owned }` — `owned` false when the caller owns none of the
  // token's types, which is when a caller that is not a resource server sees
  // the list unfiltered (the OAuth door's decision; GNAP's caller is always
  // a resource server).
  // -------------------------------------------------------------------------
  /**
   * Filters a token's rights for the resource server introspecting it, and
   * adds the person's claims its own types declare.
   *
   * @param rights - the token's details or access rights
   * @param caller - the resource server's application identifier or
   *   client_id
   * @param username - the person the token is about, or ''
   * @returns `{ rights, claims, owned }`
   */
  introspectionView(rights: Json[], caller: unknown, username: unknown): Json {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering AuthorizationDetails.introspectionView().");
    const declared = this.declaredTypes();
    const wanted: string[] = [];
    let owned = false;
    const kept = (rights || []).filter(function (one: Json): boolean {
      const definition = one && typeof one === 'object'
        ? declared[one.type] : null;
      if (!definition) {
        return true;
      }
      if (!self.ownedBy(definition, caller)) {
        return false;
      }
      owned = true;
      (definition.introspectionClaims || []).forEach(function (name: string):
          void {
        if (wanted.indexOf(name) < 0) {
          wanted.push(name);
        }
      });
      return true;
    });
    let claims: Json = {};
    if (wanted.length && username) {
      try {
        // LAZILY: the claim reader requires the credential module's claim
        // catalogue, and this library is required long before it.
        const claimAttributes = require('../common/claim_attributes');
        claims = claimAttributes.requestedClaimsFor(String(username),
                                                    wanted).claims || {};
      } catch (e) {
        log.debug("Caught in AuthorizationDetails.introspectionView(): " +
                  ((e && e.message) || e));
        // No directory in this process: no claims, which is what a person
        // with none of them on their entry gets too.
        claims = {};
      }
    }
    log.debug("Leaving AuthorizationDetails.introspectionView(). " +
              kept.length + " of " + (rights || []).length + " kept, " +
              Object.keys(claims).length + " claim(s).");
    return { rights: kept, claims: claims, owned: owned };
  }

  // The realm's `authorization_details_types_supported`: the built-in type and
  // every declared one, sorted so two processes publish the same document.
  /**
   * Returns the realm's `authorization_details_types_supported`: the built-in
   * type and every declared one, sorted.
   *
   * @returns the type names
   */
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
  /**
   * Parses and checks one `authorization_details` value. Never throws.
   *
   * @param raw - JSON text or an array
   * @param opts - `clientTypes` (the client's registered types, [] for any),
   *   `profileTypes` (the selected authorization server's list, or null) and
   *   `builtIn`, the `openid_credential` check
   * @returns `{ ok: true, details: null }` when nothing was sent, `{ ok: true,
   *   details, resolved }` when every detail passed, or a refusal whose `error`
   *   is the sentence for `invalid_authorization_details`
   */
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
      // THE POLICY DECIDES the two authorization questions (#305): the
      // facts, one question for this detail, and its verdict.
      const A = self.deps.scopeVerdicts.ATTRIBUTE;
      const asked = self.deps.gate.checkScopes({
        subject: { kind: 'application', name: String(options.clientId || ''),
                   authenticated: true },
        client: String(options.clientId || ''),
        protocol: 'OAuth 2.0',
        action: self.deps.scopeVerdicts.SCOPE.DETAIL_ACTION,
        requested: [String(detail.type)],
        facts: [{ scope: String(detail.type), attributes: [
          self.deps.scopeVerdicts.resourceFact(A.CLIENT_HAS_DETAIL_TYPES,
                                               clientTypes.length > 0),
          self.deps.scopeVerdicts.resourceFact(
            A.DETAIL_TYPE_REGISTERED, clientTypes.indexOf(detail.type) >= 0),
          self.deps.scopeVerdicts.resourceFact(A.SERVER_HAS_DETAIL_TYPES,
                                               !!profileTypes),
          self.deps.scopeVerdicts.resourceFact(
            A.DETAIL_TYPE_PUBLISHED,
            !!profileTypes && profileTypes.indexOf(detail.type) >= 0)] }]
      });
      const typeVerdict = (asked.verdicts || [])[0] ||
                          { verdict: 'keep', code: '' };
      if (typeVerdict.verdict !== 'keep' &&
          typeVerdict.code !== 'STS-OAUTH-0455') {
        log.debug("Leaving AuthorizationDetails.parse(). Not a type the " +
                  "client registered.");
        return self.refusal('STS-OAUTH-0454', where + ' is of type "' +
          detail.type + '", and this client registered ' +
          'authorization_details_types ' + JSON.stringify(clientTypes) +
          ' (RFC 9396 section 10).');
      }
      if (typeVerdict.verdict !== 'keep') {
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
      // THE TYPE'S DEFINITION — its schema, and since #432 phase 4 the
      // catalogue's values, required members, limits and locations — asked
      // through `conformance()`, the one reading GNAP shares.
      const conforms = self.conformance(detail, definition, where);
      if (conforms.kind) {
        log.debug("Leaving AuthorizationDetails.parse(). The type's " +
                  "definition refused it (" + conforms.kind + ").");
        return self.refusal(CONFORMANCE_CODES[conforms.kind] ||
                            'STS-OAUTH-0456', conforms.problem +
                            (conforms.kind === 'location' ? '.'
                              : ' (RFC 9396 section 5).'));
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
  /**
   * Tells whether one granted detail covers one requested detail: the same
   * type, each common array a subset, and every other requested member equal.
   *
   * @param granted - the granted detail
   * @param requested - the requested detail
   * @returns true when it is covered
   */
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
  /**
   * Checks a token request's details against what the grant authorized (section
   * 6).
   *
   * @param requested - the token request's details
   * @param granted - the grant's details
   * @returns a sentence for `invalid_authorization_details`, or ''
   */
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
  /**
   * Returns what a token carries for a covered subset: the requested details,
   * with a built-in detail replaced by the granted one covering it. Call only
   * after `coveredProblem()` answered ''.
   *
   * @param requested - the token request's details
   * @param granted - the grant's details
   * @returns the details for the token
   */
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
  /**
   * Tells which resource a set of details addresses, for
   * `jwt_access_token.audiencePlan()`.
   *
   * @param details - the details
   * @returns `{ resources, audiences, identifiers }`
   */
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
  /**
   * Tells whether a request's details need the consent screen: any detail of a
   * type an application declares.
   *
   * @param details - the details
   * @returns true when consent is needed
   */
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
  /**
   * Describes the details for the consent screen, one row per detail, with
   * values as strings for the screen to escape.
   *
   * @param details - the details
   * @returns the rows
   */
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
  /**
   * Returns a SHA-256 of the canonical details array, base64url, which Allow is
   * recorded against.
   *
   * @param details - the details
   * @returns the digest
   */
  digestOf(details: Json[]): string {
    const { log, crypto } = this.deps;
    log.debug("Entering AuthorizationDetails.digestOf().");
    log.debug("Leaving AuthorizationDetails.digestOf().");
    return crypto.digest('sha256',
      JSON.stringify(this.canonical(details || [])), 'base64url');
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
  /**
   * Records that a person pressed Allow on these details for this client.
   *
   * @param username - the person
   * @param clientId - the client
   * @param digest - `digestOf()` the details
   * @param lowered - the details with the limits the person lowered on the
   *   screen (#432 phase 5), or null when they lowered none
   */
  noteConsented(username: unknown, clientId: unknown, digest: unknown,
                lowered?: Json[] | null): void {
    const { log } = this.deps;
    log.debug("Entering AuthorizationDetails.noteConsented().");
    const now = Date.now();
    consented.forEach(function (held, key) {
      if (!(held && held.expires >= now)) {
        consented.delete(key);
      }
    });
    consented.set(this.consentKey(username, clientId, digest),
                  { expires: now + this.consentTtlMs(),
                    lowered: Array.isArray(lowered) ? lowered : null });
    log.debug("Leaving AuthorizationDetails.noteConsented().");
  }

  // Whether they did, SPENDING the answer: one Allow is one authorization
  // response. A second request carrying the same array asks again.
  /**
   * Tells whether the person allowed these details, spending the answer: one
   * Allow is one authorization response.
   *
   * @param username - the person
   * @param clientId - the client
   * @param digest - `digestOf()` the details
   * @returns true when an Allow was found and spent
   */
  consumeConsented(username: unknown, clientId: unknown,
                   digest: unknown): boolean {
    const { log } = this.deps;
    log.debug("Entering AuthorizationDetails.consumeConsented().");
    const answer = this.consumeConsent(username, clientId, digest);
    log.debug("Leaving AuthorizationDetails.consumeConsented().");
    return !!answer;
  }

  // The same, answering WHAT was allowed (#432 phase 5): `{ lowered }`, the
  // details with the limits the person lowered on the screen (null when
  // they lowered none), or null when nothing was allowed. Spent either way.
  /**
   * Spends a person's Allow on these details, answering the details as they
   * lowered them.
   *
   * @param username - the person
   * @param clientId - the client
   * @param digest - `digestOf()` the details as the client sent them
   * @returns `{ lowered }`, or null when nothing was allowed
   */
  consumeConsent(username: unknown, clientId: unknown, digest: unknown): Json {
    const { log } = this.deps;
    log.debug("Entering AuthorizationDetails.consumeConsent().");
    const key = this.consentKey(username, clientId, digest);
    const held = consented.get(key);
    if (held === undefined) {
      log.debug("Leaving AuthorizationDetails.consumeConsent(). Not " +
                "consented.");
      return null;
    }
    consented.delete(key);
    const live = !!held && held.expires >= Date.now();
    log.debug("Leaving AuthorizationDetails.consumeConsent(). " + live);
    return live ? { lowered: held.lowered || null } : null;
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds no
// instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` when this module loads (see
// `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<AuthorizationDetails>(
  'oauth-oidc/authorization_details',
  () => new AuthorizationDetails(AuthorizationDetails.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

/**
 * RFC 9396, OAuth 2.0 Rich Authorization Requests.
 *
 * A library that registers no route. The composition root builds the instance;
 * each function here forwards to it.
 *
 * @namespace
 */
export = {
  AuthorizationDetails: AuthorizationDetails,
  /**
   * Installs the instance the composition root built, and runs its wiring.
   * Refused once an instance is installed or a default built.
   *
   * @param instance - the instance every facade here forwards to
   */
  installInstance: (instance: AuthorizationDetails): void =>
    slot.install(instance),
  /**
   * Tells where the instance in use came from.
   *
   * @returns `root`, `default` or `none`
   */
  instanceOrigin: (): string => slot.origin(),
  COMMON_ARRAYS: AuthorizationDetails.COMMON_ARRAYS,
  declaredTypes: slot.forward('declaredTypes'),
  typesSupported: slot.forward('typesSupported'),
  parse: slot.forward('parse'),
  covers: slot.forward('covers'),
  conformance: slot.forward('conformance'),
  typeOf: slot.forward('typeOf'),
  maxLifetimeFor: slot.forward('maxLifetimeFor'),
  carriesLimits: slot.forward('carriesLimits'),
  limitsRaisedBy: slot.forward('limitsRaisedBy'),
  bearerRefusedBy: slot.forward('bearerRefusedBy'),
  requiredAcrsOf: slot.forward('requiredAcrsOf'),
  derivableFrom: slot.forward('derivableFrom'),
  ownedBy: slot.forward('ownedBy'),
  introspectionView: slot.forward('introspectionView'),
  coveredProblem: slot.forward('coveredProblem'),
  narrow: slot.forward('narrow'),
  audienceFor: slot.forward('audienceFor'),
  needsConsent: slot.forward('needsConsent'),
  describe: slot.forward('describe'),
  digestOf: slot.forward('digestOf'),
  noteConsented: slot.forward('noteConsented'),
  consumeConsent: slot.forward('consumeConsent'),
  consumeConsented: slot.forward('consumeConsented')
};
