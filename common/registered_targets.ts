// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: registered_targets.ts
//
// ---------------------------------------------------------------------------
// WHAT A TOKEN MAY BE ADDRESSED TO: A REGISTERED TARGET (#505, #1140).
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
//   1. ONE OF THIS SERVICE'S OWN RESOURCE SERVERS, WHILE THE APPLICATION
//      OBJECT REPRESENTING IT EXISTS (#1139, #1140), matched by its path
//      under any name this process is reached by, as the code that checks a
//      token's audience reads it:
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
//        * the account API, `/account-api` (#568);
//        * the reports API, `/report-api` (#956);
//        * the AuthZEN API, `/access/v1` (#563).
//      The GNAP demonstration resource server, `/gnap/rs/resource`, was the
//      fourth until #593 deleted it.
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
// **EVERY MODE SINCE #1140** (2026-10-29). Development was unchanged by #505
// — `mode.issuesToUnregisteredApplications()` answered yes there and
// `unregistered()` returned nothing — until rcbj's rule that no access token
// is minted for an audience no application object holds, in both modes.
// And the rule is asked of EVERY audience a token is minted with, not only
// of the targets a request names: `oauth2.ts`'s `accessTokenPlan()` asks
// `unregistered()` of the plan's audiences (STS-OAUTH-0986), so the default
// audience, a client's own and one a scope or `authorization_details`
// derived are held to it as well.
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

const log = helpers.log;

type Json = any;

/**
 * The one definition of a registered target for an RFC 8707 resource and a
 * GNAP access right's location (#505).
 */
export = class RegisteredTargets {
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

  // ---------------------------------------------------------------------------
  // THIS SERVICE'S OWN RESOURCE SERVERS, EACH ONLY WHILE ITS OBJECT EXISTS
  // (#1140, 2026-10-29). Since #1139 each is an application object of kind
  // `oauth2-resource-server` seeded in every realm (`applications.js`'s
  // `apiResourceApplications()`), and rcbj's rule is that no access token is
  // minted for an audience no application object holds. An own API's
  // audience is matched by its PATH under any name this process is reached
  // by — the request's base, and the authorization server's — rather than
  // by the one URL the object stores (rcbj's decision on #1140: the test
  // launchers reach the service as `sts:8081`, the in-process suite as
  // `127.0.0.1` on a random port, and the default audience has always been
  // built from the request's own base). The OBJECT decides whether the API
  // is a target at all: an operator who deletes `sts-report-api` has turned
  // off every token for `/report-api`.
  // ---------------------------------------------------------------------------
  private static seeded(identifier: string): boolean {
    log.debug("Entering RegisteredTargets.seeded(). " + identifier);
    let found = false;
    try {
      const applications = require('./applications');
      found = !!applications.get(identifier);
    } catch (e) {
      // No registry (a library tested on its own): nothing is seeded.
      log.debug("Caught in RegisteredTargets.seeded(): " +
                ((e && e.message) || e));
      found = false;
    }
    log.debug("Leaving RegisteredTargets.seeded(). " + found);
    return found;
  }

  /**
   * Names the resource server of this service's own a target is, or '' —
   * only while the application object that represents it exists (#1140).
   *
   * @param target - a resource indicator, a location or an audience
   * @param req - the request, for the base it arrived on and its realm, or
   *   nothing where there was none (a CIBA push)
   * @param base - the authorization server's base, asked as well
   * @returns a label for the resource server, or ''
   */
  static ownResourceServer(target: string, req: Json, base?: string): string {
    log.debug("Entering RegisteredTargets.ownResourceServer().");
    const wanted = String(target == null ? '' : target).trim();
    const bases: string[] = [];
    [req ? helpers.baseUrlOf(req) : '', String(base || '')]
      .forEach(function (one: string): void {
        if (one && bases.indexOf(one) < 0) {
          bases.push(one);
        }
      });
    if (!wanted || !bases.length) {
      log.debug("Leaving RegisteredTargets.ownResourceServer(). Nothing " +
                "asked.");
      return '';
    }
    const jwtAccessToken = RegisteredTargets.installed('jwt_access_token',
      function loadJwtAccessToken(): Json {
        log.debug("Entering loadJwtAccessToken().");
        log.debug("Leaving loadJwtAccessToken().");
        return require('../oauth-oidc/jwt_access_token');
      });
    const underAny = function (path: string): boolean {
      return bases.some(function (one: string): boolean {
        return wanted === one + path;
      });
    };
    if (jwtAccessToken && bases.some(function (one: string): boolean {
      return jwtAccessToken.isOwnResourceAudience(wanted, one);
    })) {
      const on = RegisteredTargets.seeded('sts-resource');
      log.debug("Leaving RegisteredTargets.ownResourceServer(). The default " +
                "resource indicator; its object " +
                (on ? 'exists.' : 'is gone.'));
      return on ? 'this service\'s resource server (UserInfo, SCIM, ' +
                  'Shared Signals, OpenID4VCI)' : '';
    }
    if (RegisteredTargets.namesManagementApi(wanted, req, bases[0]) ||
        underAny('/admin-api')) {
      const on = RegisteredTargets.seeded('sts-management-api');
      log.debug("Leaving RegisteredTargets.ownResourceServer(). The " +
                "management API; its object " + (on ? 'exists.' : 'is gone.'));
      return on ? 'the management API (/admin-api)' : '';
    }
    // THE ACCOUNT API (#568), the user portal's only door: this realm's
    // `/account-api`, which is what the portal asks for as its `resource` and
    // what `account-api/account_api.ts` accepts as a token's audience.
    if (underAny('/account-api')) {
      const on = RegisteredTargets.seeded('sts-account-api');
      log.debug("Leaving RegisteredTargets.ownResourceServer(). The " +
                "account API; its object " + (on ? 'exists.' : 'is gone.'));
      return on ? 'the account API (/account-api)' : '';
    }
    // THE REPORTS API (#956), the reports application's only door: this
    // realm's `/report-api`, which is what `/report` asks for as its
    // `resource` and what `report/report_api.ts` accepts as a token's
    // audience. Compared whole, as the account API is.
    if (underAny('/report-api')) {
      const on = RegisteredTargets.seeded('sts-report-api');
      log.debug("Leaving RegisteredTargets.ownResourceServer(). The " +
                "reports API; its object " + (on ? 'exists.' : 'is gone.'));
      return on ? 'the reports API (/report-api)' : '';
    }
    // THE AUTHZEN API (#563): this realm's `/access/v1`, which a PEP asks
    // for as its `resource` on client_credentials and which
    // `authzen/authzen_caller.ts` accepts as a token's audience.
    if (underAny('/access/v1')) {
      const on = RegisteredTargets.seeded('sts-authzen-api');
      log.debug("Leaving RegisteredTargets.ownResourceServer(). The " +
                "AuthZEN API; its object " + (on ? 'exists.' : 'is gone.'));
      return on ? 'the AuthZEN API (/access/v1)' : '';
    }
    // THE UMA 2.0 PROTECTION API (#1168): this realm's `/uma`, which a
    // resource server asks for as its `resource` when it obtains a PAT and
    // which `uma/uma_pat.ts` accepts as a token's audience.
    if (underAny('/uma')) {
      const on = RegisteredTargets.seeded('sts-uma-protection-api');
      log.debug("Leaving RegisteredTargets.ownResourceServer(). The UMA " +
                "protection API; its object " + (on ? 'exists.' : 'is gone.'));
      return on ? 'the UMA 2.0 protection API (/uma)' : '';
    }
    log.debug("Leaving RegisteredTargets.ownResourceServer(). None.");
    return '';
  }

  // WHETHER A TOKEN ADDRESSED TO `target` WOULD BE ONE FOR THE MANAGEMENT API
  // (#1050), for the token funnel's certificate-binding rule. With a request
  // it is `admin_api.ts`'s own `namesThisApi()`, the check a token meets
  // there. WITHOUT ONE — a CIBA push, minted when the person approves and on
  // no connection — the request-relative audience cannot be computed, so the
  // two that can stand in: `<base>/admin-api` under the base the token is
  // minted at (a realm's own audience, and the default realm's under that
  // name), and `adminApi.audience` as configured. A token minted there is
  // unbound whatever it is for, so reading a little wide refuses nothing a
  // certificate could have saved.
  /**
   * Says whether a target names the management API (#1050).
   *
   * @param target - an audience the token will carry
   * @param req - the token request, or nothing where there was none
   * @param base - the base URL the token is minted at
   * @returns true when it does
   */
  static namesManagementApi(target: string, req: Json, base: string): boolean {
    log.debug("Entering RegisteredTargets.namesManagementApi().");
    const wanted = String(target == null ? '' : target).trim();
    if (!wanted) {
      log.debug("Leaving RegisteredTargets.namesManagementApi(). Nothing.");
      return false;
    }
    if (req) {
      const adminApi = RegisteredTargets.installed('admin_api',
        function loadAdminApi(): Json {
          log.debug("Entering loadAdminApi().");
          log.debug("Leaving loadAdminApi().");
          return require('../mgmt-api/admin_api');
        });
      if (adminApi && typeof adminApi.namesThisApi === 'function') {
        const named = !!adminApi.namesThisApi(wanted, req);
        log.debug("Leaving RegisteredTargets.namesManagementApi(). " + named);
        return named;
      }
    }
    const configured = String(config.value('adminApi.audience') || '').trim();
    const named = wanted === String(base || '') + '/admin-api' ||
      (!!configured && wanted === configured);
    log.debug("Leaving RegisteredTargets.namesManagementApi(). " + named +
              " (no request).");
    return named;
  }

  /**
   * Says whether a target names a registered target: one of this service's
   * own resource servers whose object exists, or a registered application.
   *
   * @param target - a resource indicator, a location or an audience
   * @param req - the request, or nothing where there was none
   * @param base - the authorization server's base, asked as well
   * @returns true when it does
   */
  static isRegistered(target: string, req: Json, base?: string): boolean {
    log.debug("Entering RegisteredTargets.isRegistered().");
    const registered =
      !!RegisteredTargets.ownResourceServer(target, req, base) ||
      !!RegisteredTargets.application(target);
    log.debug("Leaving RegisteredTargets.isRegistered(). " + registered);
    return registered;
  }

  // IN EVERY MODE SINCE #1140 (rcbj, 2026-10-29: "It shouldn't be possible
  // to mint an access token that doesn't have an application object with
  // that audience configured" — in both modes). Until then development
  // answered nothing here (`mode.issuesToUnregisteredApplications()`, #496's
  // predicate, and the `unregistered-resource-targets` row of `mode.js`), so
  // any absolute URI became a token's `aud`. The row is gone: there is no
  // difference between the modes left to describe.
  /**
   * Returns the targets a token may not be addressed to here, in every mode:
   * those naming no registered target.
   *
   * @param targets - resource indicators, locations or audiences
   * @param req - the request, or nothing where there was none
   * @param base - the authorization server's base, asked as well
   * @returns the unregistered ones, in order
   */
  static unregistered(targets: unknown, req: Json, base?: string): string[] {
    log.debug("Entering RegisteredTargets.unregistered().");
    const asked = (Array.isArray(targets) ? targets : [targets])
      .filter(function (one: unknown): boolean {
        return one !== undefined && one !== null && String(one) !== '';
      }).map(String);
    const out = asked.filter(function (one: string): boolean {
      return !RegisteredTargets.isRegistered(one, req, base);
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
      ' no registered target. A token is addressed only to ' +
      'one of this service\'s own resource servers or to an application ' +
      'registered ahead of time (the console, /admin-api, RFC 7591, an ' +
      'LDAP add under ou=applications or an OpenID Federation), found by ' +
      'its oauthAudience, permission base URI, client_id or identifier; ' +
      'one that was only seen is not registered.';
  }
};
