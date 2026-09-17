'use strict';
//
// File: gnap_access.ts
//
// ===========================================================================
// RFC 9635 SECTION 8 ACCESS RIGHTS AS A TOKEN READS THEM, AND THE FOUR CHECKS
// EVERY STRUCTURED TOKEN FORMAT SHARES (2026-09-12).
//
// A route-free library. It registers nothing and requires only
// `common/helpers.js` (for the logger and the clock) and
// `common/error_codes.js` (a leaf), so it cannot join a cycle and its place in
// the require order is not a place.
//
// ---------------------------------------------------------------------------
// WHY THIS FILE EXISTS BESIDE `gnap_request.ts`'s `checkAccess()`.
//
// That function answers "is this a well-formed request" and refuses in the
// grant-endpoint range. This one answers "does a TOKEN cover what a request at
// a resource server needs", which is a different question with a different
// failure — a malformed request is the client's bug, an uncovered request is
// an ordinary refusal at the RS — and it is asked by three token formats
// (`token_macaroon.ts`, `token_biscuit.ts`, `token_zcap.ts`) that must answer
// it IDENTICALLY. Three matchers would be three readings of section 8's
// cross-product sentence, and the one that differs is the one an attacker
// presents a token in.
//
// ---------------------------------------------------------------------------
// THE MATCHER, AND THE ONE READING OF SECTION 8 IT COMMITS TO.
//
// Section 8: "The resulting access is the union of all elements within the
// array", and each object is "the cross-product of all fields of the object".
// So `accessCovers(granted, required)` is a question about POINTS:
//
//   * A REFERENCE STRING (section 8.1) is covered by an identical granted
//     string, compared by exact bytes, and by nothing else. A string never
//     covers an object and an object never covers a string — the section says
//     the AS "can define a clear mapping" between the two and this service has
//     not, so pretending one exists would be inventing it.
//
//   * A REQUIRED OBJECT is expanded into its cross-product — every combination
//     of one action, one location, one datatype and one privilege, over the
//     dimensions it LISTS — and each point must be covered by SOME granted
//     object of the same `type`. That is what makes the union real: a grant of
//     `{read @A}` and `{write @A}` covers a requirement of `{read,write @A}`,
//     which no single granted element does. A matcher that asked for one
//     granted element per required element would refuse that, and would be
//     reading "union" as "any".
//
//   * A DIMENSION THE GRANTED OBJECT DOES NOT LIST IS UNRESTRICTED. The
//     cross-product sentence makes an absent field a free variable — a grant of
//     `{type: photo-api, actions: [read]}` is "read, at any location, of any
//     datatype" — and the whole attenuation story depends on it: a resource
//     server narrowing a macaroon adds a caveat naming ONE dimension
//     (`locations: [A]`), and a matcher that read an absent dimension as
//     "nothing" would make that caveat refuse every request.
//
//   * A DIMENSION THE REQUIRED OBJECT DOES NOT LIST IS NOT ASKED ABOUT. The
//     resource server states the dimensions its decision depends on; one that
//     cares where a request lands must say so. This is the lenient half, and
//     it is lenient on the side the RESOURCE SERVER controls rather than the
//     side the token carries.
//
//   * `identifier` is a single string and is compared exactly. Every OTHER
//     member (section 8's `geolocation`, `currency`) is the API's own and is
//     opaque here: when the granted object carries it, the required value must
//     be deep-equal; when it does not, it is unrestricted, by the same rule as
//     a common dimension.
//
//   * `type` is compared by exact bytes, never normalised — section 8 says
//     MUST.
//
// An empty array in a REQUIRED object is read as not listing that dimension.
// Reading it as a cross-product with zero points would make
// `{type: x, actions: []}` covered by ANY token, including one with no right
// of type `x` at all — vacuous truth is the wrong answer for an authorization
// question, so the expansion always yields at least one point.
//
// The expansion is capped at `MAX_POINTS`. Past the cap the matcher falls back
// to asking for ONE granted object covering the whole required object, which
// can refuse something the union would allow and can never allow something it
// would refuse — a resource server that states a thousand-point requirement
// gets a conservative answer rather than a denial-of-service.
//
// ---------------------------------------------------------------------------
// THE FOUR SHARED CHECKS, AND WHY THEY ARE HERE RATHER THAN IN EACH FORMAT.
//
// `checkPresentation()` is time, audience, key binding and required access —
// RFC 9767 section 2.1.7, 2.1.3, 2.1.4 and 2.1.6 — asked of a token model a
// format has already authenticated. A format may hold MORE than one list for
// audience or access (a macaroon's attenuation caveats, each of which must be
// satisfied), so the checks take lists of lists and the model's own are the
// default. The codes are shared on purpose: "this token has expired" is one
// condition an operator filters on, whichever format the token was in, and the
// format is on the row beside it.
//
// `validateModel()` is the other shared half: what a model must be before any
// format mints it and after any format reconstructs it. Running it on the way
// OUT is what makes "every format's verify() returns the same shape" a checked
// claim rather than three promises.
//
// `libraryInfo()` / `packageDir()` are here for `describe()`, which the crypto
// metadata page reads, and for the biscuit loader: a package's version is read
// from its own package.json rather than written down, and one of the three
// packages hides that file behind an exports map.
// ===========================================================================

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `GnapAccess` takes the logger, the clock, the error-code table, `fs`,
// `path` and the directories `require` searches through its constructor. The
// module still exports its old names as FACADES forwarding to the instance the
// composition root builds (#50, R2), for the unconverted modules and the three
// token formats that require it. A process that loads this module without the
// root builds a default instance when the module loads.
// ---------------------------------------------------------------------------

import fs = require('fs');
import path = require('path');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import errorCodes = require('../common/error_codes');

interface GnapAccessDeps {
  log: { debug(message: string): void };
  nowSec(): number;
  errorCodes: { mark<T>(target: T, code: string): T };
  fs: {
    existsSync(p: string): boolean;
    readFileSync(p: string, encoding: 'utf8'): string;
  };
  path: { join(...parts: string[]): string };
  // The node_modules directories `require` searches from this file.
  modulePaths: string[];
}

// A refusal: `{ ok: false, errorCode, why }`, marked with its code.
interface Refusal {
  ok: false;
  errorCode: string;
  why: string;
}

// The common dimensions section 8 gives a JSON type to.
const ARRAY_DIMENSIONS = ['actions', 'locations', 'datatypes', 'privileges'];
const COMMON_FIELDS = ['type', 'identifier'].concat(ARRAY_DIMENSIONS);

// The two flags RFC 9635 section 3.2.1 defines. A token carrying a flag this
// service has never heard of is refused rather than carried: a flag changes
// how a token is processed, and an RS that ignores one it does not understand
// is processing the token wrongly by definition.
const TOKEN_FLAGS = ['bearer', 'durable'];

// The cross-product cap. Four dimensions of five values each is 625 points,
// which is already more than any requirement this service's RS states.
const MAX_POINTS = 1024;

// A base64url SHA-256 digest: what `jkt` (RFC 7638) and `x5t#S256` (RFC 8705)
// both are.
const THUMBPRINT_RE = /^[A-Za-z0-9_-]{43}$/;
const CONTROL_RE = /[\x00-\x1f\x7f]/;

class GnapAccess {
  static readonly TOKEN_FLAGS = TOKEN_FLAGS;
  static readonly ARRAY_DIMENSIONS = ARRAY_DIMENSIONS;
  static readonly COMMON_FIELDS = COMMON_FIELDS;
  static readonly MAX_POINTS = MAX_POINTS;

  constructor(private readonly deps: GnapAccessDeps) {
    deps.log.debug("Entering GnapAccess.constructor().");
    deps.log.debug("Leaving GnapAccess.constructor().");
  }

  refusal(code: string, why: string): Refusal {
    const { log, errorCodes } = this.deps;
    log.debug("Entering GnapAccess.refusal().");
    const out: Refusal = { ok: false, errorCode: code, why: why };
    log.debug("Leaving GnapAccess.refusal().");
    return errorCodes.mark(out, code);
  }

  private isObject(value: unknown): value is Record<string, any> {
    const { log } = this.deps;
    log.debug("Entering GnapAccess.isObject().");
    log.debug("Leaving GnapAccess.isObject().");
    return !!value && typeof value === 'object' && !Array.isArray(value);
  }

  private isStringArray(value: unknown): boolean {
    const { log } = this.deps;
    log.debug("Entering GnapAccess.isStringArray().");
    log.debug("Leaving GnapAccess.isStringArray().");
    return Array.isArray(value) && value.every(function (one) {
      return typeof one === 'string';
    });
  }

  // JSON with the keys of every object sorted, so two rights that differ only
  // in member order are one right. Used for dedupe and for deep equality.
  canonicalJson(value: unknown): string {
    const { log } = this.deps;
    log.debug("Entering GnapAccess.canonicalJson().");
    if (Array.isArray(value)) {
      log.debug("Leaving GnapAccess.canonicalJson().");
      return '[' + value.map((one) => {
        return this.canonicalJson(one);
      }).join(',') + ']';
    }
    if (this.isObject(value)) {
      log.debug("Leaving GnapAccess.canonicalJson().");
      return '{' + Object.keys(value).sort().map((k) => {
        return JSON.stringify(k) + ':' + this.canonicalJson(value[k]);
      }).join(',') + '}';
    }
    log.debug("Leaving GnapAccess.canonicalJson().");
    return JSON.stringify(value);
  }

  // -------------------------------------------------------------------------
  // normalise(access): the shape a token's access must have. A token's array
  // must be NON-EMPTY — an access token with no rights is a credential for
  // nothing, and a format that minted one would hand a resource server a
  // token every requirement fails against for a reason nobody could read off
  // it. Returns `{ ok:true, access }` (a deduplicated copy) or a refusal.
  // -------------------------------------------------------------------------
  normalise(access: unknown): any {
    const { log } = this.deps;
    log.debug("Entering GnapAccess.normalise().");
    if (!Array.isArray(access) || access.length === 0) {
      log.debug("Leaving GnapAccess.normalise(). Not a non-empty array.");
      return this.refusal('STS-GNAP-0300', 'access must be a non-empty ' +
                          'array of access rights (RFC 9635 section 8).');
    }
    for (let i = 0; i < access.length; i++) {
      const right = access[i];
      if (typeof right === 'string') {
        if (!right) {
          log.debug("Leaving GnapAccess.normalise(). Empty reference at " +
                    i + ".");
          return this.refusal('STS-GNAP-0301', 'access element ' + i +
                              ' is an empty reference string (RFC 9635 ' +
                              'section 8.1).');
        }
        continue;
      }
      if (!this.isObject(right) || typeof right.type !== 'string' ||
          !right.type) {
        log.debug("Leaving GnapAccess.normalise(). Element " + i +
                  " is neither a string nor a typed object.");
        return this.refusal('STS-GNAP-0301', 'access element ' + i +
                            ' must be a reference string or an object ' +
                            'with a non-empty string "type" (RFC 9635 ' +
                            'section 8).');
      }
      for (let j = 0; j < ARRAY_DIMENSIONS.length; j++) {
        const dim = ARRAY_DIMENSIONS[j];
        if (right[dim] !== undefined && !this.isStringArray(right[dim])) {
          log.debug("Leaving GnapAccess.normalise(). " + dim +
                    " malformed at " + i + ".");
          return this.refusal('STS-GNAP-0302', '"' + dim + '" in access ' +
                              'element ' + i + ' must be an array of ' +
                              'strings (RFC 9635 section 8).');
        }
      }
      if (right.identifier !== undefined &&
          typeof right.identifier !== 'string') {
        log.debug("Leaving GnapAccess.normalise(). identifier malformed at " +
                  i + ".");
        return this.refusal('STS-GNAP-0302', '"identifier" in access ' +
                            'element ' + i + ' must be a string (RFC 9635 ' +
                            'section 8).');
      }
    }
    const out = this.dedupe(access);
    log.debug("Leaving GnapAccess.normalise(). " + out.length +
              " right(s).");
    return { ok: true, access: out };
  }

  // Order-preserving: the first occurrence of each canonical right survives,
  // so a round trip through a format that deduplicates hands back the same
  // array.
  dedupe(access: any[]): any[] {
    const { log } = this.deps;
    log.debug("Entering GnapAccess.dedupe().");
    const seen = new Set();
    const out = [];
    (access || []).forEach((right) => {
      const key = this.canonicalJson(right);
      if (!seen.has(key)) {
        seen.add(key);
        out.push(right);
      }
    });
    log.debug("Leaving GnapAccess.dedupe().");
    return out;
  }

  union(a: any[], b: any[]): any[] {
    const { log } = this.deps;
    log.debug("Entering GnapAccess.union().");
    log.debug("Leaving GnapAccess.union().");
    return this.dedupe((a || []).concat(b || []));
  }

  // The elements of `requested` that `granted` covers, each kept WHOLE. It is
  // what an AS narrows a request with, and it deliberately does not split an
  // object into the covered part of its cross-product: a right handed back to
  // a client in a shape it never asked for is a right the client cannot
  // recognise.
  intersect(granted: any[], requested: any[]): any[] {
    const { log } = this.deps;
    log.debug("Entering GnapAccess.intersect().");
    log.debug("Leaving GnapAccess.intersect().");
    return this.dedupe((requested || []).filter((one) => {
      return this.accessCovers(granted, [one]);
    }));
  }

  // Does one granted OBJECT cover one required point (or, in the fallback,
  // one whole required object)? Values of an array dimension in `point` are
  // arrays; in a real point each holds one value.
  private objectCoversPoint(grantedObject: any, point: any): boolean {
    const { log } = this.deps;
    log.debug("Entering GnapAccess.objectCoversPoint().");
    if (!this.isObject(grantedObject) || grantedObject.type !== point.type) {
      log.debug("Leaving GnapAccess.objectCoversPoint(). Not an object of " +
                "this type.");
      return false;
    }
    const keys = Object.keys(point);
    for (let i = 0; i < keys.length; i++) {
      const key = keys[i];
      if (key === 'type' || grantedObject[key] === undefined) {
        // `type` was compared above; a dimension the grant does not list is
        // unrestricted (see the header).
        continue;
      }
      if (ARRAY_DIMENSIONS.indexOf(key) >= 0) {
        const allowed = grantedObject[key];
        if (!Array.isArray(allowed) ||
            !point[key].every(function (v) {
              return allowed.indexOf(v) >= 0;
            })) {
          log.debug("Leaving GnapAccess.objectCoversPoint(). " + key +
                    " not granted.");
          return false;
        }
      } else if (key === 'identifier') {
        if (grantedObject.identifier !== point.identifier) {
          log.debug("Leaving GnapAccess.objectCoversPoint(). identifier " +
                    "differs.");
          return false;
        }
      } else if (this.canonicalJson(grantedObject[key]) !==
                 this.canonicalJson(point[key])) {
        log.debug("Leaving GnapAccess.objectCoversPoint(). " + key +
                  " differs.");
        return false;
      }
    }
    log.debug("Leaving GnapAccess.objectCoversPoint(). Covered.");
    return true;
  }

  // Every combination of one value per listed array dimension, carrying the
  // object's scalar and API-specific members on each point. Returns null past
  // MAX_POINTS.
  private pointsOf(required: any): any[] | null {
    const { log } = this.deps;
    log.debug("Entering GnapAccess.pointsOf().");
    let points = [{}];
    Object.keys(required).forEach(function (key) {
      if (ARRAY_DIMENSIONS.indexOf(key) < 0) {
        points.forEach(function (p) {
          p[key] = required[key];
        });
      }
    });
    for (let i = 0; i < ARRAY_DIMENSIONS.length; i++) {
      const dim = ARRAY_DIMENSIONS[i];
      const values = required[dim];
      if (!Array.isArray(values) || values.length === 0) {
        continue;
      }
      if (points.length * values.length > MAX_POINTS) {
        log.debug("Leaving GnapAccess.pointsOf(). Past MAX_POINTS.");
        return null;
      }
      const next = [];
      points.forEach(function (p) {
        values.forEach(function (v) {
          const q = Object.assign({}, p);
          q[dim] = [v];
          next.push(q);
        });
      });
      points = next;
    }
    log.debug("Leaving GnapAccess.pointsOf(). " + points.length +
              " point(s).");
    return points;
  }

  // -------------------------------------------------------------------------
  // accessCovers(granted, required): true when every element of `required` is
  // covered by the union of `granted`. Malformed input on either side is
  // `false` — this is an authorization question and a shape it cannot read is
  // a no. An absent or empty `required` is covered: a resource server that
  // states no requirement has asked nothing of the access array.
  // -------------------------------------------------------------------------
  accessCovers(granted: unknown, required: unknown): boolean {
    const { log } = this.deps;
    log.debug("Entering GnapAccess.accessCovers().");
    if (required === undefined || required === null ||
        (Array.isArray(required) && required.length === 0)) {
      log.debug("Leaving GnapAccess.accessCovers(). Nothing required.");
      return true;
    }
    if (!Array.isArray(granted) || !Array.isArray(required)) {
      log.debug("Leaving GnapAccess.accessCovers(). Not arrays.");
      return false;
    }
    const strings =
        granted.filter(function (g) {
          return typeof g === 'string';
        });
    const objects = granted.filter((g) => {
      return this.isObject(g);
    });
    for (let i = 0; i < required.length; i++) {
      const need = required[i];
      if (typeof need === 'string') {
        if (strings.indexOf(need) < 0) {
          log.debug("Leaving GnapAccess.accessCovers(). Reference not " +
                    "granted.");
          return false;
        }
        continue;
      }
      if (!this.isObject(need) || typeof need.type !== 'string' ||
          !need.type) {
        log.debug("Leaving GnapAccess.accessCovers(). Malformed " +
                  "requirement.");
        return false;
      }
      const points = this.pointsOf(need);
      if (points === null) {
        // Past the cap: one granted object must cover the whole requirement.
        const whole = Object.assign({}, need);
        ARRAY_DIMENSIONS.forEach(function (dim) {
          if (Array.isArray(whole[dim]) && whole[dim].length === 0) {
            delete whole[dim];
          }
        });
        if (!objects.some((g) => {
          return this.objectCoversPoint(g, whole);
        })) {
          log.debug("Leaving GnapAccess.accessCovers(). Large requirement " +
                    "not covered by one grant.");
          return false;
        }
        continue;
      }
      for (let p = 0; p < points.length; p++) {
        const point = points[p];
        if (!objects.some((g) => {
          return this.objectCoversPoint(g, point);
        })) {
          log.debug("Leaving GnapAccess.accessCovers(). A point of element " +
              i + " is " +
              "not covered.");
          return false;
        }
      }
    }
    log.debug("Leaving GnapAccess.accessCovers(). Covered.");
    return true;
  }

  // -------------------------------------------------------------------------
  // THE KEY BINDING AS A STRING, shared by the macaroon caveat (`gnap:cnf=`)
  // and the ZCAP `gnapCnf` term so that the two formats spell a confirmation
  // one way.
  //   jkt:<thumbprint>   x5t:<thumbprint>   kid:<reference>   (null = bearer)
  // -------------------------------------------------------------------------
  cnfToString(cnf: any): string | null {
    const { log } = this.deps;
    log.debug("Entering GnapAccess.cnfToString().");
    if (!cnf) {
      log.debug("Leaving GnapAccess.cnfToString().");
      return null;
    }
    if (cnf.jkt !== undefined) {
      log.debug("Leaving GnapAccess.cnfToString().");
      return 'jkt:' + cnf.jkt;
    }
    if (cnf['x5t#S256'] !== undefined) {
      log.debug("Leaving GnapAccess.cnfToString().");
      return 'x5t:' + cnf['x5t#S256'];
    }
    log.debug("Leaving GnapAccess.cnfToString().");
    return 'kid:' + cnf.kid;
  }

  cnfFromString(text: unknown): Record<string, string> | undefined {
    const { log } = this.deps;
    log.debug("Entering GnapAccess.cnfFromString().");
    const m = typeof text === 'string' ?
      /^(jkt|x5t|kid):(.+)$/.exec(text) : null;
    if (!m) {
      log.debug("Leaving GnapAccess.cnfFromString(). Not a confirmation " +
                "string.");
      return undefined;
    }
    if (m[1] === 'kid') {
      log.debug("Leaving GnapAccess.cnfFromString(). Key reference.");
      return CONTROL_RE.test(m[2]) ? undefined : { kid: m[2] };
    }
    if (!THUMBPRINT_RE.test(m[2])) {
      log.debug("Leaving GnapAccess.cnfFromString(). Not a SHA-256 " +
                "thumbprint.");
      return undefined;
    }
    log.debug("Leaving GnapAccess.cnfFromString(). Thumbprint.");
    return m[1] === 'jkt' ? { jkt: m[2] } : { 'x5t#S256': m[2] };
  }

  private isInteger(value: unknown): boolean {
    const { log } = this.deps;
    log.debug("Entering GnapAccess.isInteger().");
    log.debug("Leaving GnapAccess.isInteger().");
    return typeof value === 'number' && Number.isSafeInteger(value) &&
      value >= 0;
  }

  private absoluteUri(value: unknown): boolean {
    const { log } = this.deps;
    log.debug("Entering GnapAccess.absoluteUri().");
    if (typeof value !== 'string' || !value) {
      log.debug("Leaving GnapAccess.absoluteUri().");
      return false;
    }
    try {
      new URL(value); // eslint-disable-line no-new
    } catch (e) {
      log.debug("Caught in GnapAccess.absoluteUri(): " +
                ((e && e.message) || e));
      log.debug("Leaving GnapAccess.absoluteUri().");
      // Not a URI; `false` is the whole of what the caller needs.
      return false;
    }
    log.debug("Leaving GnapAccess.absoluteUri().");
    return true;
  }

  private plainString(value: unknown): boolean {
    const { log } = this.deps;
    log.debug("Entering GnapAccess.plainString().");
    log.debug("Leaving GnapAccess.plainString().");
    return typeof value === 'string' && value.length > 0 &&
           !CONTROL_RE.test(value);
  }

  // -------------------------------------------------------------------------
  // validateModel(model): the token model of RFC 9767 section 2.1, as the
  // design contract spells it, before a format mints it and after a format
  // reconstructs it. Returns `{ ok:true, model }` — a copy with every optional
  // member present as `null` — or a refusal carrying STS-GNAP-0303 (or the
  // access codes).
  //
  // THE BEARER FLAG AND `cnf` MUST AGREE. RFC 9635 section 3.2.1 says the
  // `bearer` flag means the token is not bound to any key; a model with `cnf`
  // null and no `bearer` flag, or with both, is two answers to the one
  // question an RS asks before anything else.
  // -------------------------------------------------------------------------
  validateModel(model: any): any {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering GnapAccess.validateModel().");
    function bad(why: string) {
      log.debug("Entering bad().");
      log.debug("Leaving GnapAccess.validateModel(). " + why);
      return self.refusal('STS-GNAP-0303', 'the token model is not valid: ' +
                          why + ' (RFC 9767 section 2.1).');
    }
    const plainString = function (value: unknown) {
      return self.plainString(value);
    };
    if (!this.isObject(model)) {
      log.debug("Leaving GnapAccess.validateModel().");
      return bad('it is not an object');
    }
    if (!this.plainString(model.jti)) {
      log.debug("Leaving GnapAccess.validateModel().");
      return bad('"jti" must be a non-empty string');
    }
    if (!this.absoluteUri(model.iss) || CONTROL_RE.test(model.iss)) {
      log.debug("Leaving GnapAccess.validateModel().");
      return bad('"iss" must be an absolute URI');
    }
    if (model.sub !== undefined && model.sub !== null &&
        !this.plainString(model.sub)) {
      log.debug("Leaving GnapAccess.validateModel().");
      return bad('"sub" must be a non-empty string or null');
    }
    const aud = model.aud === undefined || model.aud === null ? [] :
      model.aud;
    if (!Array.isArray(aud) || !aud.every(plainString)) {
      log.debug("Leaving GnapAccess.validateModel().");
      return bad('"aud" must be an array of non-empty strings');
    }
    if (new Set(aud).size !== aud.length) {
      log.debug("Leaving GnapAccess.validateModel().");
      return bad('"aud" must not repeat an entry');
    }
    if (!this.plainString(model.instanceId)) {
      log.debug("Leaving GnapAccess.validateModel().");
      return bad('"instanceId" must be a non-empty string');
    }
    const access = this.normalise(model.access);
    if (!access.ok) {
      log.debug("Leaving GnapAccess.validateModel(). Access malformed.");
      return access;
    }
    const flags = model.flags === undefined || model.flags === null ? [] :
                  model.flags;
    if (!Array.isArray(flags) ||
        !flags.every(function (f) {
          return TOKEN_FLAGS.indexOf(f) >= 0;
        }) ||
        new Set(flags).size !== flags.length) {
      log.debug("Leaving GnapAccess.validateModel().");
      return bad('"flags" must be an array of distinct known flags (' +
                 TOKEN_FLAGS.join(', ') + ')');
    }
    let cnf = model.cnf === undefined ? null : model.cnf;
    if (cnf !== null) {
      const keys = this.isObject(cnf) ? Object.keys(cnf) : [];
      if (keys.length !== 1 ||
          ['jkt', 'x5t#S256', 'kid'].indexOf(keys[0]) < 0) {
        log.debug("Leaving GnapAccess.validateModel().");
        return bad('"cnf" must be null or an object with exactly one of ' +
                   'jkt, x5t#S256, kid');
      }
      if (keys[0] === 'kid' ? !this.plainString(cnf.kid) :
          !THUMBPRINT_RE.test(cnf[keys[0]])) {
        log.debug("Leaving GnapAccess.validateModel().");
        return bad('"cnf.' + keys[0] + '" is not a valid ' +
                   (keys[0] === 'kid' ? 'key reference' :
                     'SHA-256 thumbprint'));
      }
      cnf = { [keys[0]]: cnf[keys[0]] };
    }
    if ((cnf === null) !== (flags.indexOf('bearer') >= 0)) {
      log.debug("Leaving GnapAccess.validateModel().");
      return bad('the "bearer" flag and "cnf" disagree — a bearer token has ' +
                 'no cnf and a bound token has no bearer flag');
    }
    if (!this.isInteger(model.iat) || !this.isInteger(model.exp)) {
      log.debug("Leaving GnapAccess.validateModel().");
      return bad('"iat" and "exp" must be non-negative integer seconds');
    }
    const nbf = model.nbf === undefined ? null : model.nbf;
    if (nbf !== null && !this.isInteger(nbf)) {
      log.debug("Leaving GnapAccess.validateModel().");
      return bad('"nbf" must be integer seconds or null');
    }
    if (model.exp <= model.iat) {
      log.debug("Leaving GnapAccess.validateModel().");
      return bad('"exp" must be later than "iat"');
    }
    if (nbf !== null && nbf >= model.exp) {
      log.debug("Leaving GnapAccess.validateModel().");
      return bad('"nbf" must be earlier than "exp"');
    }
    // Year 9999 is where ISO 8601 and the biscuit date term both stop.
    if (model.exp > 253402300799) {
      log.debug("Leaving GnapAccess.validateModel().");
      return bad('"exp" is past the year 9999');
    }
    if (model.label !== undefined && model.label !== null &&
        !this.plainString(model.label)) {
      log.debug("Leaving GnapAccess.validateModel().");
      return bad('"label" must be a non-empty string or null');
    }
    const out = {
      jti: model.jti,
      iss: model.iss,
      sub: model.sub === undefined ? null : model.sub,
      aud: aud.slice(),
      instanceId: model.instanceId,
      access: access.access,
      flags: flags.slice(),
      cnf: cnf,
      iat: model.iat,
      nbf: nbf,
      exp: model.exp,
      label: model.label === undefined ? null : model.label
    };
    log.debug("Leaving GnapAccess.validateModel(). Valid.");
    return { ok: true, model: out };
  }

  // -------------------------------------------------------------------------
  // The four checks. Each returns null when satisfied or a refusal.
  // -------------------------------------------------------------------------

  // RFC 9767 section 2.1.7. `exp` is exclusive (the JWT reading: a token is
  // valid BEFORE exp) and `nbf` inclusive. No clock skew here: the caller
  // hands `now`, and a skew belongs to the caller's configuration, not to a
  // format.
  checkTime(exp: number, nbf: number | null | undefined,
            now: number): Refusal | null {
    const { log } = this.deps;
    log.debug("Entering GnapAccess.checkTime().");
    if (now >= exp) {
      log.debug("Leaving GnapAccess.checkTime().");
      return this.refusal('STS-GNAP-0304', 'the access token expired at ' +
                          exp + ' and it is now ' + now +
                          ' (RFC 9767 section 2.1.7).');
    }
    if (nbf !== null && nbf !== undefined && now < nbf) {
      log.debug("Leaving GnapAccess.checkTime().");
      return this.refusal('STS-GNAP-0305',
                          'the access token is not valid before ' + nbf +
                          ' and it is now ' + now +
                          ' (RFC 9767 section 2.1.7).');
    }
    log.debug("Leaving GnapAccess.checkTime().");
    return null;
  }

  // RFC 9767 section 2.1.3. Every list must name the verifying RS; an empty
  // list is no restriction. `audience` null means the verifier is not an RS
  // (the AS introspecting its own token) and asks nothing.
  checkAudience(audienceLists: any[], audience: unknown): Refusal | null {
    const { log } = this.deps;
    log.debug("Entering GnapAccess.checkAudience().");
    if (audience === null || audience === undefined) {
      log.debug("Leaving GnapAccess.checkAudience(). The verifier is not an " +
                "RS.");
      return null;
    }
    for (let i = 0; i < audienceLists.length; i++) {
      const list = audienceLists[i] || [];
      if (list.length > 0 && list.indexOf(audience) < 0) {
        log.debug("Leaving GnapAccess.checkAudience(). Not in list " + i +
                  ".");
        return this.refusal('STS-GNAP-0306',
                            'the access token is not intended for "' +
                            audience + '" (RFC 9767 section 2.1.3).');
      }
    }
    log.debug("Leaving GnapAccess.checkAudience(). Named.");
    return null;
  }

  // RFC 9767 section 2.1.4. A BEARER token presented alongside a key is
  // ACCEPTED: RFC 9635 section 7.2 presents a bearer token with no proof, and
  // a client that happens to sign every request it makes has not thereby used
  // the token "with a key in an undefined way" — the key simply confirms
  // nothing. A BOUND token must be presented with the key it names, compared
  // on the one member the confirmation carries.
  checkBinding(cnf: any, presentedKey: any): Refusal | null {
    const { log } = this.deps;
    log.debug("Entering GnapAccess.checkBinding().");
    if (!cnf) {
      log.debug("Leaving GnapAccess.checkBinding(). Bearer.");
      return null;
    }
    const member = Object.keys(cnf)[0];
    if (!presentedKey || typeof presentedKey[member] !== 'string' ||
        presentedKey[member] !== cnf[member]) {
      log.debug("Leaving GnapAccess.checkBinding(). Not the bound key.");
      return this.refusal('STS-GNAP-0307',
                          'the access token is bound to a key (' + member +
                          ') and was not presented with that key (RFC 9767 ' +
                          'section 2.1.4, RFC 9635 section 7.2).');
    }
    log.debug("Leaving GnapAccess.checkBinding(). Bound key presented.");
    return null;
  }

  // RFC 9767 section 2.1.6: every access list must cover the requirement.
  checkAccess(accessLists: any[], requiredAccess: unknown): Refusal | null {
    const { log } = this.deps;
    log.debug("Entering GnapAccess.checkAccess().");
    if (requiredAccess === undefined || requiredAccess === null) {
      log.debug("Leaving GnapAccess.checkAccess(). Nothing required.");
      return null;
    }
    for (let i = 0; i < accessLists.length; i++) {
      if (!this.accessCovers(accessLists[i], requiredAccess)) {
        log.debug("Leaving GnapAccess.checkAccess(). List " + i +
                  " does not cover.");
        return this.refusal('STS-GNAP-0308', 'the access token does not ' +
                            'grant the access this request ' +
                            'needs' +
                            (i > 0 ? ' (an attenuation narrowed it)' : '') +
                            ' (RFC 9635 section 8).');
      }
    }
    log.debug("Leaving GnapAccess.checkAccess(). Covered.");
    return null;
  }

  // -------------------------------------------------------------------------
  // checkPresentation(model, context, lists): all four, in the order a
  // refusal is most useful in. `lists` may carry `audience` and `access` lists
  // of lists (a format's attenuations) and an effective `exp` / `nbf`; the
  // model's own are the default.
  // -------------------------------------------------------------------------
  checkPresentation(model: any, context?: any, lists?: any): Refusal | null {
    const { log, nowSec } = this.deps;
    log.debug("Entering GnapAccess.checkPresentation().");
    const ctx = context || {};
    const extra = lists || {};
    const now = this.isInteger(ctx.now) ? ctx.now : nowSec();
    const exp = extra.exp !== undefined ? extra.exp : model.exp;
    const nbf = extra.nbf !== undefined ? extra.nbf : model.nbf;
    const failed = this.checkTime(exp, nbf, now) ||
      this.checkAudience(extra.audience || [model.aud], ctx.audience) ||
      this.checkBinding(model.cnf, ctx.presentedKey) ||
      this.checkAccess(extra.access || [model.access], ctx.requiredAccess);
    if (failed) {
      log.debug("Leaving GnapAccess.checkPresentation(). Refused " +
                failed.errorCode + ".");
      return failed;
    }
    log.debug("Leaving GnapAccess.checkPresentation(). Satisfied.");
    return null;
  }

  // -------------------------------------------------------------------------
  // Where an npm package lives, and what it says about itself.
  // `require.resolve` cannot be used for `@biscuit-auth/biscuit-wasm`: its
  // exports map exposes an `import` condition only, so both the package and
  // its package.json are unresolvable from CommonJS. So this walks the same
  // node_modules directories `require` would, in the same order.
  // -------------------------------------------------------------------------
  packageDir(name: string): string | null {
    const { log, fs, path, modulePaths } = this.deps;
    log.debug("Entering GnapAccess.packageDir().");
    const dirs = modulePaths || [];
    for (let i = 0; i < dirs.length; i++) {
      const candidate = path.join(dirs[i], name);
      if (fs.existsSync(path.join(candidate, 'package.json'))) {
        log.debug("Leaving GnapAccess.packageDir().");
        return candidate;
      }
    }
    log.debug("Leaving GnapAccess.packageDir().");
    return null;
  }

  libraryInfo(name: string) {
    const { log, fs, path } = this.deps;
    log.debug("Entering GnapAccess.libraryInfo(). name=" + name);
    const dir = this.packageDir(name);
    if (!dir) {
      log.debug("Leaving GnapAccess.libraryInfo(). Not installed.");
      return { name: name, version: null, license: null };
    }
    try {
      const pkg = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'),
                                             'utf8'));
      log.debug("Leaving GnapAccess.libraryInfo(). " + pkg.version);
      return { name: name, version: pkg.version || null,
               license: pkg.license || null };
    } catch (e) {
      log.debug("Caught in GnapAccess.libraryInfo(): " +
                ((e && e.message) || e));
      // An unreadable manifest is a metadata page with a blank cell, not a
      // reason for the page to fail; the name is still true.
      log.debug("Leaving GnapAccess.libraryInfo(). package.json unreadable: " +
                e.message);
      return { name: name, version: null, license: null };
    }
  }

  // What the composition root passes (#50, R2): the real modules, as the
  // module built its own instance from before. `modulePaths` is this file's
  // own `module.paths`, which is what the function read before; the clock is
  // read off `helpers` at each call, as it was.
  static defaultDeps(): GnapAccessDeps {
    helpers.log.debug("Entering GnapAccess.defaultDeps().");
    helpers.log.debug("Leaving GnapAccess.defaultDeps().");
    return {
      log: helpers.log,
      nowSec: function () {
        return helpers.nowSec();
      },
      errorCodes: errorCodes,
      fs: fs,
      path: path,
      modulePaths: (module as any).paths || []
    };
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds
// no instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` (see `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<GnapAccess>(
  'gnap/gnap_access',
  () => new GnapAccess(GnapAccess.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  GnapAccess: GnapAccess,
  installInstance: (instance: GnapAccess): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  TOKEN_FLAGS: GnapAccess.TOKEN_FLAGS,
  ARRAY_DIMENSIONS: GnapAccess.ARRAY_DIMENSIONS,
  COMMON_FIELDS: GnapAccess.COMMON_FIELDS,
  MAX_POINTS: GnapAccess.MAX_POINTS,
  refusal: slot.forward('refusal'),
  canonicalJson: slot.forward('canonicalJson'),
  normalise: slot.forward('normalise'),
  dedupe: slot.forward('dedupe'),
  union: slot.forward('union'),
  intersect: slot.forward('intersect'),
  accessCovers: slot.forward('accessCovers'),
  cnfToString: slot.forward('cnfToString'),
  cnfFromString: slot.forward('cnfFromString'),
  validateModel: slot.forward('validateModel'),
  checkTime: slot.forward('checkTime'),
  checkAudience: slot.forward('checkAudience'),
  checkBinding: slot.forward('checkBinding'),
  checkAccess: slot.forward('checkAccess'),
  checkPresentation: slot.forward('checkPresentation'),
  packageDir: slot.forward('packageDir'),
  libraryInfo: slot.forward('libraryInfo')
};
