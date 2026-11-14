// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: issuer_names.ts
//
// ---------------------------------------------------------------------------
// THE ONE NAME THIS SERVICE ISSUES UNDER, IN EVERY PROTOCOL (#523).
//
// rcbj, 2026-10-08: "Shouldn't we have consistency between OAuth2 Token
// Exchange JWT Access Token iss claim and WS-Trust Issue RST OBO/ActAs
// Issuer elements?" Until #523 this file decided three names (#480, #494):
// `saml.issuer`, `wstrust.issuer` and `wsfed.entityId`, each defaulting to
// the SAML 2.0 entityID `saml2.entityId`, which with
// `saml2.perApplicationEntityId` was `urn:sts:idp:<sp>` per service provider
// — while every JWT carried the realm's OAuth issuer. One STS answering one
// request named itself two ways.
//
// **rcbj's decisions on #523: ONE ISSUER PER REALM, THE REALM'S OAUTH
// ISSUER URL, EVERYWHERE, WITH NO OVERRIDE.** The <saml:Issuer> of every SAML
// 2.0 and SAML 1.1 assertion (SAML SSO, WS-Federation, WS-Trust), the
// `entityID` of every identity provider metadata document (`/saml2/metadata`
// and `/saml2/metadata/{sp}`, SAML 1.1's, WS-Federation's), the WS-Trust STS's
// name and every JWT's `iss` are the one string
// `/.well-known/oauth-authorization-server` publishes. The four settings and
// the per-application names are retired. To change the name, change the
// public base URL (`global.publicBaseUrl`), which moves every protocol
// together.
//
// **IT IS THE REQUEST'S, AS THE OAUTH ISSUER IS.** The OAuth issuer is read
// at the base of the request that asked (`oauth2.issuerOf()`, moved to where
// `oauth-oidc` is advertised, #472), so in a deployment with no pinned base it
// follows the host a client used. The SAML name must be read the same way or
// the two disagree whenever the base is not pinned: `issuer(base)` takes the
// caller's base, else the AMBIENT request's (`audit.currentRequest()`, which
// every HTTP request runs inside), else the configured management base with
// the realm's prefix — the order `wstrust.ts`'s `oauthIssuer()` used, which
// now asks here.
//
// **WHAT IT IS NOT.** An application's own SAML entityID (`samlEntityId`, the
// SP side) is what an incoming AuthnRequest, LogoutRequest, ArtifactResolve or
// AttributeQuery is matched against, by its own <Issuer> or the `{sp}` path
// segment. That is untouched: this file names THIS service only.
//
// **"REGISTERED" IS `appRegisteredBy`** (`registeredApplication()`, #494's
// word, still asked by #496's refusals): an application an administrator,
// RFC 7591, an OpenID Federation or this service's own seeding put here, as
// opposed to an entry a protocol's `seen()` filed.
//
// A STATIC UTILITY CLASS (rule 3: a library, no route, no state). `audit`,
// `realms`, `applications` and `oauth-oidc/oauth2` are reached LAZILY: the
// SAML assertion builders require this file, and the authorization server
// loads later in the stack.
// ---------------------------------------------------------------------------

import config = require('./config');
import helpers = require('./helpers');

const log = helpers.log;

/**
 * The one name this service issues under (#523).
 */
export = class IssuerNames {
  /**
   * Returns this realm's issuer: its OAuth issuer at `base`, which is the
   * SAML Issuer, the identity provider metadata's entityID, the WS-Trust
   * STS's name and every JWT's `iss` (#523).
   *
   * @param base - the base URL of the request that asked, the realm prefix
   * included; omitted, the ambient request's, else the configured base
   * @returns the issuer
   */
  static issuer(base?: string): string {
    log.debug("Entering IssuerNames.issuer().");
    let at = String(base || '');
    if (!at) {
      let req: any = null;
      try {
        req = require('./audit').currentRequest();
      } catch (e) {
        // No audit module loaded (a library tested on its own): no request.
        log.debug("Caught in IssuerNames.issuer(): " +
                  ((e && e.message) || e));
        req = null;
      }
      at = req ? String(helpers.baseUrlOf(req) || '') : '';
    }
    if (!at) {
      at = String(config.managementApiBaseUrl() || '')
        .replace(/\/admin-api$/, '') +
        String(require('./realms').currentPrefix() || '');
    }
    // Where `oauth-oidc` is advertised (#472), whichever base asked.
    at = helpers.rebaseTo(at, 'oauth-oidc');
    let out = at;
    try {
      out = String(require('../oauth-oidc/oauth2').issuerOf(at) || at);
    } catch (e) {
      // No authorization server loaded (a library tested on its own): the
      // base is what it would have answered with no pinned issuer.
      log.debug("Caught in IssuerNames.issuer(): " + ((e && e.message) || e));
      out = at;
    }
    log.debug("Leaving IssuerNames.issuer(). " + out);
    return out;
  }

  /**
   * Returns the identifier of the REGISTERED application a protocol names,
   * or '' — for no identifier, for none in the registry, and for an entry
   * that merely turned up (no `appRegisteredBy`).
   *
   * @param identifier - the application's registry identifier
   * @returns the identifier, or ''
   */
  static registeredApplication(identifier?: string): string {
    log.debug("Entering IssuerNames.registeredApplication().");
    const wanted = String(identifier || '').trim();
    if (!wanted) {
      log.debug("Leaving IssuerNames.registeredApplication(). None named.");
      return '';
    }
    let found: any = null;
    try {
      found = require('./applications').get(wanted);
    } catch (e) {
      // No registry (a library tested on its own): nothing is registered.
      log.debug("Caught in IssuerNames.registeredApplication(): " +
                ((e && e.message) || e));
      found = null;
    }
    const registered = !!(found && String(found.registeredBy || ''));
    log.debug("Leaving IssuerNames.registeredApplication(). " +
              (registered ? wanted : 'Not registered.'));
    return registered ? wanted : '';
  }
};
