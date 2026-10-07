// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: registered_targets.ts
//
// ---------------------------------------------------------------------------
// WHAT A TOKEN MAY BE ADDRESSED TO, IN PRODUCT: A REGISTERED TARGET (#505).
//
// #496 made product refuse an application nobody registered at every door
// that names one. Two doors name the party a token is FOR without naming an
// application by its client_id, and its audit left them open: an RFC 8707
// `resource` at the authorization, token and PAR endpoints (outside a token
// exchange, which RFC 8693's `resolveTarget()` already holds), and a GNAP
// access right's `locations`. In product the first became the token's `aud`
// whatever it said, and the second was silently left out of the token's
// audience. rcbj's rule on #505: in product either must name a REGISTERED
// TARGET, and this file is the one definition both doors ask.
//
// **A REGISTERED TARGET IS ONE OF TWO THINGS.**
//
//   1. ONE OF THIS SERVICE'S OWN RESOURCE SERVERS, read from the code that
//      checks a token's audience rather than listed here:
//        * the default resource indicator of an authorization server this
//          process publishes at the request's base — `<base>/resource`, or
//          a named authorization server's under it. It is what UserInfo,
//          SCIM, Shared Signals, the OpenID4VCI endpoints, Grant Management
//          and the VC-API test endpoints accept
//          (`jwt_access_token.ts`'s `isOwnResourceAudience()`, the one
//          reading they all share through `dpop.presentedAccessToken()`);
//        * the management API, `/admin-api` — what `mgmt-api/admin_api.ts`
//          accepts as a token's audience (`namesThisApi()`): the pinned
//          `adminApi.audience`, or while that is at its default the
//          configured base and `/admin-api` under this host, and a realm's
//          own `/admin-api`;
//        * the GNAP demonstration resource server, `/gnap/rs/resource`,
//          while `gnap.demoResourceServer` is on — the audience `gnap.ts`
//          judges a token against (`selfUri`), and the one `gnap_grants.ts`
//          gives a token for nobody in particular.
//      The embedded debugger's api is not in this list because it needs no
//      place in it: it is an APPLICATION, `sts-debugger-api`, seeded and
//      registered at startup (`appRegisteredBy: startup`) while the debugger
//      is embedded, under the permission base `urn:sts:debugger-api:` — so
//      it is found by the second rule, and is no target at all while the
//      debugger is not embedded.
//   2. A REGISTERED APPLICATION, found by any of the names an access token
//      addresses one by (`applications.audienceNamesEntry()`'s four, which
//      `accessTokenPlan()` and RFC 9701's "intended for" read): its
//      `oauthAudience`, its permission base URI (both sides normalised), its
//      client_id or its registry identifier — the lookups RFC 8693's
//      `resolveTarget()` makes, with the permission base beside them.
//      "Registered" is #494's word, `appRegisteredBy`: an entry a
//      development sighting filed is not one.
//
// **COMPARED WHOLE.** A resource indicator is an absolute URI (RFC 8707
// section 2) that becomes the token's `aud`, and an audience is compared
// whole at every resource server here (RFC 9068 section 4), so a target
// matches a name exactly; only the permission base is normalised, because
// `permissionBaseOf()` composed it. GNAP's own addressing — a location AT or
// UNDER a registered resource server's `gnapResourceServerUri` — is GNAP's
// rule and stays in `gnap_grants.ts`, which asks this file first.
//
// **DEVELOPMENT IS UNCHANGED**: `mode.issuesToUnregisteredApplications()`,
// #496's predicate, answers yes there and `unregistered()` returns nothing.
// The question is the same one — may a token be issued FOR something nobody
// registered — so it is the same predicate, with a row of its own in
// `mode.js`'s REQUIREMENTS (`unregistered-resource-targets`).
//
// A STATIC UTILITY CLASS (rule 3: a library, no route, no state), as
// `issuer_names.ts` is. `applications`, `oauth-oidc/jwt_access_token` and
// `mgmt-api/admin_api` are reached LAZILY and only at request time, and a
// converted module is ASKED, NEVER BUILT: before the composition root has
// installed its instance, a facade call would build a default one and the
// root's own install would then refuse (`issuer_names.ts` tells that story).
// ---------------------------------------------------------------------------

import config = require('./config');
import helpers = require('./helpers');
import mode = require('./mode');

const log = helpers.log;

type Json = any;

// The demonstration resource server's address under a realm's base
// (`gnap.ts`'s `/gnap/rs/resource`).
const GNAP_DEMO_RESOURCE_PATH = '/gnap/rs/resource';

/**
 * The one definition of a registered target for an RFC 8707 resource and a
 * GNAP access right's location (#505).
 */
export = class RegisteredTargets {
  /** The GNAP demonstration resource server's path under a base. */
  static readonly GNAP_DEMO_RESOURCE_PATH = GNAP_DEMO_RESOURCE_PATH;

  // A converted module, required lazily, or null while the composition root
  // has not installed its instance (ASKED, NEVER BUILT — the header).
  private static installed(what: string, load: () => Json): Json {
    log.debug("Entering RegisteredTargets.installed(). " + what);
    let mod: Json = null;
    try {
      mod = load();
    } catch (e) {
      // Not loadable here (a library tested on its own): it answers nothing.
      log.debug("Caught in RegisteredTargets.installed(): " +
                ((e && e.message) || e));
      mod = null;
    }
    if (mod && typeof mod.instanceOrigin === 'function' &&
        mod.instanceOrigin() === 'none') {
      log.debug("Leaving RegisteredTargets.installed(). Not installed yet.");
      return null;
    }
    log.debug("Leaving RegisteredTargets.installed().");
    return mod;
  }

  /**
   * Returns the REGISTERED application a target names — by `oauthAudience`,
   * client_id, registry identifier or permission base URI — or null, for an
   * entry nobody registered (no `appRegisteredBy`) as for none.
   *
   * @param target - a resource indicator or a location
   * @returns the application's view, or null
   */
  static application(target: string): Json {
    log.debug("Entering RegisteredTargets.application().");
    const wanted = String(target == null ? '' : target).trim();
    if (!wanted) {
      log.debug("Leaving RegisteredTargets.application(). Nothing asked.");
      return null;
    }
    let found: Json = null;
    try {
      const applications = require('./applications');
      found = applications.forAudience(wanted) ||
        applications.forClientId(wanted) || applications.get(wanted) ||
        applications.forPermissionBase(wanted) || null;
    } catch (e) {
      // No registry (a library tested on its own): nothing is registered.
      log.debug("Caught in RegisteredTargets.application(): " +
                ((e && e.message) || e));
      found = null;
    }
    if (found && !String(found.registeredBy || '')) {
      log.debug("Leaving RegisteredTargets.application(). " +
                found.identifier + " is not registered.");
      return null;
    }
    log.debug("Leaving RegisteredTargets.application(). " +
              (found ? found.identifier : 'None.'));
    return found;
  }

  /**
   * Names the resource server of this service's own a target is, or ''.
   *
   * @param target - a resource indicator or a location
   * @param req - the request, for the base it arrived on and its realm
   * @returns a label for the resource server, or ''
   */
  static ownResourceServer(target: string, req: Json): string {
    log.debug("Entering RegisteredTargets.ownResourceServer().");
    const wanted = String(target == null ? '' : target).trim();
    if (!wanted || !req) {
      log.debug("Leaving RegisteredTargets.ownResourceServer(). Nothing " +
                "asked.");
      return '';
    }
    const base = helpers.baseUrlOf(req);
    const jwtAccessToken = RegisteredTargets.installed('jwt_access_token',
      function loadJwtAccessToken(): Json {
        log.debug("Entering loadJwtAccessToken().");
        log.debug("Leaving loadJwtAccessToken().");
        return require('../oauth-oidc/jwt_access_token');
      });
    if (jwtAccessToken && jwtAccessToken.isOwnResourceAudience(wanted, base)) {
      log.debug("Leaving RegisteredTargets.ownResourceServer(). The default " +
                "resource indicator.");
      return 'this service\'s resource server (UserInfo, SCIM, Shared ' +
             'Signals, OpenID4VCI)';
    }
    const adminApi = RegisteredTargets.installed('admin_api',
      function loadAdminApi(): Json {
        log.debug("Entering loadAdminApi().");
        log.debug("Leaving loadAdminApi().");
        return require('../mgmt-api/admin_api');
      });
    if (adminApi && typeof adminApi.namesThisApi === 'function' &&
        adminApi.namesThisApi(wanted, req)) {
      log.debug("Leaving RegisteredTargets.ownResourceServer(). The " +
                "management API.");
      return 'the management API (/admin-api)';
    }
    if (config.value('gnap.demoResourceServer') !== false &&
        wanted === base + GNAP_DEMO_RESOURCE_PATH) {
      log.debug("Leaving RegisteredTargets.ownResourceServer(). The GNAP " +
                "demonstration resource server.");
      return 'the GNAP demonstration resource server';
    }
    log.debug("Leaving RegisteredTargets.ownResourceServer(). None.");
    return '';
  }

  /**
   * Says whether a target names a registered target: one of this service's
   * own resource servers, or a registered application.
   *
   * @param target - a resource indicator or a location
   * @param req - the request
   * @returns true when it does
   */
  static isRegistered(target: string, req: Json): boolean {
    log.debug("Entering RegisteredTargets.isRegistered().");
    const registered = !!RegisteredTargets.ownResourceServer(target, req) ||
      !!RegisteredTargets.application(target);
    log.debug("Leaving RegisteredTargets.isRegistered(). " + registered);
    return registered;
  }

  /**
   * Returns the targets a token may not be addressed to here: in product,
   * those naming no registered target; in development, none.
   *
   * @param targets - resource indicators or locations
   * @param req - the request
   * @returns the unregistered ones, in order
   */
  static unregistered(targets: unknown, req: Json): string[] {
    log.debug("Entering RegisteredTargets.unregistered().");
    if (mode.issuesToUnregisteredApplications()) {
      log.debug("Leaving RegisteredTargets.unregistered(). Development.");
      return [];
    }
    const asked = (Array.isArray(targets) ? targets : [targets])
      .filter(function (one: unknown): boolean {
        return one !== undefined && one !== null && String(one) !== '';
      }).map(String);
    const out = asked.filter(function (one: string): boolean {
      return !RegisteredTargets.isRegistered(one, req);
    });
    log.debug("Leaving RegisteredTargets.unregistered(). " + out.length +
              " of " + asked.length + ".");
    return out;
  }

  /**
   * The sentence a refusal names its targets in.
   *
   * @param targets - the unregistered targets
   * @returns the sentence
   */
  static describe(targets: string[]): string {
    log.debug("Entering RegisteredTargets.describe().");
    const named = (targets || []).map(function (one: string): string {
      return '"' + String(one).slice(0, 200) + '"';
    }).join(', ');
    log.debug("Leaving RegisteredTargets.describe().");
    return named + ((targets || []).length === 1 ? ' names' : ' name') +
      ' no registered target. In product mode a token is addressed only to ' +
      'one of this service\'s own resource servers or to an application ' +
      'registered ahead of time (the console, /admin-api, RFC 7591, an ' +
      'LDAP add under ou=applications or an OpenID Federation), found by ' +
      'its oauthAudience, permission base URI, client_id or identifier; ' +
      'one that was only seen is not registered.';
  }
};
