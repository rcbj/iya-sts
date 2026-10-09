// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: scope_claims.ts
//
// ---------------------------------------------------------------------------
// WHICH CLAIMS A SCOPE COVERS, WHERE THEY MAY GO, AND HOW TWO SETS OF CLAIMS
// ARE COMBINED (#395, 2026-10-09).
//
// OpenID Connect Core 1.0 section 5.4 names four scopes that request a fixed
// set of claims: `profile`, `email`, `address` and `phone`. Section 5.4 says
// WHERE they are returned — the UserInfo endpoint, and the ID Token only when
// the response issues no access token — and `oauth-oidc/oauth2.ts` held that
// already (#118). What it did not hold is the other half of rcbj's ticket:
//
//   * **A SCOPE IS A REQUEST FOR ACCESS TO CLAIMS, NOT AN ACCESS-TOKEN CLAIM
//     SET.** RFC 9068 section 2.2.2 lets an access token carry identity
//     claims and says the authorization server decides which, from the
//     client, the scope and the resource; it gives a client no way to ask.
//     So a RESOURCE SERVER declares the claims of these four scopes it wants
//     on the access tokens addressed to it (`oauthAccessTokenClaim` on its
//     application entry), and `preferred_username`, which went into every
//     person's access token whatever was granted, is now one of them.
//
//   * **NOTHING THAT WAS NOT GRANTED IS RELEASED** (rcbj: "maximum
//     flexibility, but still only allowing information that has been
//     granted"). `gate()` removes a section 5.4 claim whose scope the grant
//     did not include, from EVERY layer of an access token, an ID Token and
//     a UserInfo response — the realm's configured set, an application's own,
//     a resource server's declaration. Two kinds of claim pass untouched,
//     because no scope covers them: a claim the client NAMED in section 5.5's
//     claims request (the request is its own grant, and those layers are
//     added after the gate), and a claim that is not one of the section 5.4
//     claims at all — groups, roles, an administrator's typed claim.
//
//   * **HOW TWO SETS ARE COMBINED IS A CHOICE PER APPLICATION** (rcbj: "a
//     configuration parameter per application to either use the union or
//     intersection of the two sets of claims for each token type"). There
//     are two pairs of sets, and each has its own choice:
//       - the REALM's claim set and an APPLICATION's own, per token type
//         (`COMBINE_ATTRIBUTES`, read by `admin_stats.effectiveClaimSet()`
//         for the rows and `claim_attributes.effectiveRows()` for the
//         ticked attributes): `application`, `union`, `intersection` or
//         `realm`. Unset is what #495 built — the rows ADDED and winning by
//         name, the selection REPLACING the realm's;
//       - the CLIENT's access-token claims and a RESOURCE SERVER's
//         declaration (`oauthAccessTokenClaimsCombine`, on the resource
//         server's entry): `union` (unset), `intersection`, `client` or
//         `resource`.
//     An application that holds no set of its own is the realm's whatever its
//     mode says, and a token whose audiences declare nothing has no resource
//     server layer: ABSENT IS NOT EMPTY, the rule #495 set for a selection.
//
// **A LIBRARY (rule 3)** that registers nothing and requires only
// `helpers.js`, so `admin_stats.js`, `applications.js`, `claim_attributes.ts`
// and `oauth2.ts` can all require it without joining a cycle.
// ---------------------------------------------------------------------------

import helpers = require('./helpers');

const log = helpers.log;

// A JSON-shaped value: a set of claims.
type Json = any;

// OIDC Core section 5.4, verbatim and in its order. `oauth2.ts`'s UserInfo
// and ID Token answer from this table, and the gate reads it backwards.
const SCOPE_CLAIMS: Record<string, string[]> = {
  profile: ['name', 'family_name', 'given_name', 'middle_name', 'nickname',
            'preferred_username', 'profile', 'picture', 'website', 'gender',
            'birthdate', 'zoneinfo', 'locale', 'updated_at'],
  email: ['email', 'email_verified'],
  address: ['address'],
  phone: ['phone_number', 'phone_number_verified']
};

// claim -> the scope that covers it.
const SCOPE_OF_CLAIM: Record<string, string> = {};
Object.keys(SCOPE_CLAIMS).forEach(function (scope) {
  SCOPE_CLAIMS[scope].forEach(function (claim) {
    SCOPE_OF_CLAIM[claim] = scope;
  });
});

// Every claim a resource server may declare: the section 5.4 claims and no
// other, because they are the ones a grant can be asked about. A resource
// server that wants a claim no scope covers asks an administrator for it on
// the client's Custom claims, where the realm's rules already decide.
const DECLARABLE_CLAIMS: string[] = Object.keys(SCOPE_OF_CLAIM);

// The realm's set against an application's own, per token type: the
// attribute on the application, by claim set id: the five sets #495 gave an
// application rows and a selection of. NOT the Kerberos PAC set (#493): a
// service ticket's claims are its TGT's with the application's rows over
// them, merged inside the KDC's `claimsForTicket()`, which is a vendored
// file this repository may not edit (`kerberos/CLAUDE.md`).
const COMBINE_ATTRIBUTES: Record<string, string> = {
  access_token: 'oauthClaimsCombineAccessToken',
  id_token: 'oauthClaimsCombineIdToken',
  userinfo: 'oauthClaimsCombineUserinfo',
  saml2: 'saml2ClaimsCombine',
  saml11: 'saml11ClaimsCombine'
};

const REALM_MODES: string[] = ['application', 'union', 'intersection',
                               'realm'];

// The client's access-token claims against a resource server's declaration.
const RESOURCE_MODES: string[] = ['union', 'intersection', 'client',
                                  'resource'];

/**
 * The OpenID Connect scope claims (OIDC Core section 5.4), the gate that
 * keeps a claim out of a token unless its scope was granted, and the two
 * ways two sets of claims are combined (#395).
 */
class ScopeClaims {
  /** OIDC Core section 5.4's claims, by scope. */
  static readonly SCOPE_CLAIMS = SCOPE_CLAIMS;

  /** The claims a resource server may declare for its access tokens. */
  static readonly DECLARABLE_CLAIMS = DECLARABLE_CLAIMS;

  /** The application attribute choosing realm-vs-application, by set. */
  static readonly COMBINE_ATTRIBUTES = COMBINE_ATTRIBUTES;

  /** The values of a realm-vs-application combine attribute. */
  static readonly REALM_MODES = REALM_MODES;

  /** The values of `oauthAccessTokenClaimsCombine`. */
  static readonly RESOURCE_MODES = RESOURCE_MODES;

  /**
   * Says which section 5.4 scope covers a claim.
   *
   * @param claim - the claim name
   * @returns the scope, or '' for a claim no scope covers
   */
  static scopeOf(claim: unknown): string {
    log.debug("Entering ScopeClaims.scopeOf().");
    const name = String(claim == null ? '' : claim);
    const out = Object.prototype.hasOwnProperty.call(SCOPE_OF_CLAIM, name)
      ? SCOPE_OF_CLAIM[name] : '';
    log.debug("Leaving ScopeClaims.scopeOf().");
    return out;
  }

  /**
   * Says whether a scope string includes a value.
   *
   * @param scope - the space-separated scope
   * @param value - the value
   * @returns whether it does
   */
  static grants(scope: unknown, value: string): boolean {
    log.debug("Entering ScopeClaims.grants().");
    const out = String(scope == null ? '' : scope).split(/\s+/)
      .indexOf(value) >= 0;
    log.debug("Leaving ScopeClaims.grants().");
    return out;
  }

  /**
   * Removes from a set of claims every section 5.4 claim whose scope the
   * grant does not include. A claim no scope covers is kept. The object is
   * changed in place and returned.
   *
   * @param claims - the claims about to be issued
   * @param grantedScope - the scope GRANTED (before RFC 9068's plan took the
   *   OpenID Connect scopes off an access token for an API)
   * @param where - what is being issued, for the log
   * @param alsoGranted - claim names granted another way: by a resource
   *   server's own permission that maps them, which is itself a grant
   * @returns the same object, without what was not granted
   */
  static gate(claims: Json, grantedScope: unknown, where: string,
              alsoGranted?: string[]): Json {
    log.debug("Entering ScopeClaims.gate(). " + where);
    if (!claims || typeof claims !== 'object') {
      log.debug("Leaving ScopeClaims.gate(). Nothing to gate.");
      return claims;
    }
    const removed: string[] = [];
    Object.keys(claims).forEach(function (name) {
      const scope = ScopeClaims.scopeOf(name);
      if (scope && !ScopeClaims.grants(grantedScope, scope) &&
          (alsoGranted || []).indexOf(name) < 0) {
        delete claims[name];
        removed.push(name);
      }
    });
    if (removed.length) {
      log.debug("ScopeClaims.gate(): " + where + ": " + removed.join(', ') +
                " left out, their scope not granted.");
    }
    log.debug("Leaving ScopeClaims.gate(). " + removed.length +
              " removed.");
    return claims;
  }

  /**
   * Reads a combine mode, answering the default for a value outside the
   * set (the write refuses one; a value stored past it is not honoured).
   *
   * @param value - the stored value
   * @param modes - the values allowed
   * @param fallback - the default
   * @returns the mode
   */
  static modeOf(value: unknown, modes: string[], fallback: string): string {
    log.debug("Entering ScopeClaims.modeOf().");
    const first = Array.isArray(value) ? value[0] : value;
    const text = String(first == null ? '' : first).trim();
    log.debug("Leaving ScopeClaims.modeOf().");
    return modes.indexOf(text) >= 0 ? text : fallback;
  }

  /**
   * Returns an application's realm-vs-application combine mode for a set,
   * or '' when it holds none (each half then keeps #495's rule).
   *
   * @param setId - the claim set id
   * @param application - the application's view, or null
   * @returns the mode, or ''
   */
  static realmModeOf(setId: unknown, application: any): string {
    log.debug("Entering ScopeClaims.realmModeOf().");
    const attribute = COMBINE_ATTRIBUTES[String(setId || '')];
    const raw = attribute && application && application.fields
      ? application.fields[attribute] : undefined;
    const out = ScopeClaims.modeOf(raw, REALM_MODES, '');
    log.debug("Leaving ScopeClaims.realmModeOf(). " + (out || 'unset'));
    return out;
  }

  /**
   * Combines two lists of names: the realm's and an application's, under a
   * realm-vs-application mode. `own` null is "the application holds none",
   * which is the realm's whatever the mode.
   *
   * @param realm - the realm's names, in order
   * @param own - the application's, or null
   * @param mode - `application`, `union`, `intersection` or `realm`
   * @returns the names in force: the realm's order, then the
   *   application's additions
   */
  static combineNames(realm: string[], own: string[] | null,
                      mode: string): string[] {
    log.debug("Entering ScopeClaims.combineNames(). mode=" + mode);
    if (!own || mode === 'realm') {
      log.debug("Leaving ScopeClaims.combineNames(). The realm's.");
      return realm.slice(0);
    }
    if (mode === 'union') {
      const out = realm.slice(0);
      own.forEach(function (name) {
        if (out.indexOf(name) < 0) {
          out.push(name);
        }
      });
      log.debug("Leaving ScopeClaims.combineNames(). Union.");
      return out;
    }
    if (mode === 'intersection') {
      log.debug("Leaving ScopeClaims.combineNames(). Intersection.");
      return realm.filter(function (name) { return own.indexOf(name) >= 0; });
    }
    log.debug("Leaving ScopeClaims.combineNames(). The application's.");
    return own.slice(0);
  }

  /**
   * Combines the client's access-token claims with the claims a resource
   * server declared. On a name both carry, the client's value is kept: it is
   * what an administrator configured for this client, and the declaration
   * says only which standard claim is wanted.
   *
   * @param client - the client's claims
   * @param resource - the resource server's, already resolved and gated
   * @param mode - `union`, `intersection`, `client` or `resource`
   * @returns a new object
   */
  static combineResource(client: Json, resource: Json, mode: string): Json {
    log.debug("Entering ScopeClaims.combineResource(). mode=" + mode);
    const out: Json = {};
    if (mode === 'resource') {
      Object.assign(out, resource);
    } else if (mode === 'client') {
      Object.assign(out, client);
    } else if (mode === 'intersection') {
      Object.keys(client).forEach(function (name) {
        if (Object.prototype.hasOwnProperty.call(resource, name)) {
          out[name] = client[name];
        }
      });
    } else {
      Object.assign(out, resource, client);
    }
    log.debug("Leaving ScopeClaims.combineResource(). " +
              Object.keys(out).length + " claim(s).");
    return out;
  }

  /**
   * The claims several resource servers declared, for one token addressed to
   * all of them: only what EVERY one declared (rcbj, 2026-10-09), so no
   * resource server is handed an attribute it did not ask for. An audience
   * that declared nothing contributes nothing, and so empties the result.
   *
   * @param declared - each audience's declared names
   * @returns the names every one declared
   */
  static intersectDeclared(declared: string[][]): string[] {
    log.debug("Entering ScopeClaims.intersectDeclared(). " +
              declared.length + " audience(s).");
    if (!declared.length) {
      log.debug("Leaving ScopeClaims.intersectDeclared(). None.");
      return [];
    }
    const out = declared[0].filter(function (name) {
      return declared.every(function (list) {
        return list.indexOf(name) >= 0;
      });
    });
    log.debug("Leaving ScopeClaims.intersectDeclared(). " + out.length +
              ".");
    return out;
  }

  /**
   * The one resource-server mode for a token addressed to several: theirs
   * when they agree, `intersection` — the most private — when they do not.
   *
   * @param modes - each declaring audience's mode
   * @returns the mode
   */
  static agreedResourceMode(modes: string[]): string {
    log.debug("Entering ScopeClaims.agreedResourceMode().");
    const first = modes.length ? modes[0] : 'union';
    const agreed = modes.every(function (one) { return one === first; });
    log.debug("Leaving ScopeClaims.agreedResourceMode().");
    return agreed ? first : 'intersection';
  }
}

export = ScopeClaims;
