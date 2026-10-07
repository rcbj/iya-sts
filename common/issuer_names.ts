// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: issuer_names.ts
//
// ---------------------------------------------------------------------------
// THE NAMES THIS SERVICE SIGNS UNDER AS A SAML ISSUER, A WS-TRUST STS AND A
// WS-FEDERATION IDENTITY PROVIDER, DECIDED IN ONE PLACE (#480, #494).
//
// Three settings name this service outside the SAML 2.0 browser profile:
// `saml.issuer` (the <saml:Issuer> of an assertion WS-Trust or WS-Federation
// builds), `wstrust.issuer` (the STS's name on GET /sts) and `wsfed.entityId`
// (the FederationMetadata entityID). All three shipped `urn:wstrust:mock:sts`,
// a development placeholder, and a product deployment signed with it — beside
// `/saml2/metadata`, which publishes `saml2.entityId`. A relying party
// configured from that metadata saw an issuer it was never told about.
//
// **rcbj's decision on #480, extended to development on #494: ALIGN WITH THE
// SAML ENTITYID, IN BOTH MODES.** Each of the three, where nobody set it, is
// the realm's `saml2.entityId` — what `/saml2/metadata` publishes as this
// identity provider. #480 did that in product only, behind
// `mode.namesIssuersByEntityId()`, and kept the placeholder in development;
// #494 retired the predicate and the placeholder with it, so a development
// run exercises the rule a product deployment signs under. There is no mode
// question left here. A value somebody SET still wins:
//
//   * "set" means an operator's layer: a runtime override, the environment,
//     the operator's appconfig file. The shipped defaults (`env/defaults.js`
//     and the table's `dflt`, both empty since #494) are not a choice anybody
//     made;
//   * and a realm's SEEDED name is not one either. A realm is created with
//     `urn:<domain>:sts` on all three (`realms.js` NAMED_BY_REALM) so that two
//     realms never share a name; that seed is a default made distinct, and
//     reading it as an operator's choice would leave every realm misaligned.
//     A realm value equal to its seed is read as a default; any other realm
//     value is somebody's choice and wins.
//
// **ONE NAME PER APPLICATION (#494).** The SAML SSO profile names itself to
// each service provider by `<entityID>:<sp>` (`saml2_sso.idpEntityIdFor()`,
// governed by `saml2.perApplicationEntityId`), in the assertion's Issuer and
// in `/saml2/metadata/{sp}`. WS-Trust and WS-Federation take the same name
// for the same application, through that same function and nothing else:
// a WS-Trust assertion (SAML 2.0 or 1.1) for a registered AppliesTo, and a
// WS-Federation assertion and per-application metadata for a registered
// wtrealm, carry the application's own entityID. So an application declared
// for all three protocols sees one entityID in each — the key is its
// registry identifier, which is what SAML SSO's `{sp}` names too.
//
// **"REGISTERED" IS `appRegisteredBy`** (the view's `registeredBy`): an
// application an administrator, RFC 7591, an OpenID Federation or this
// service's own seeding put here. An entry that merely TURNED UP — every
// AppliesTo and wtrealm is filed by the protocol's `seen()` the first time a
// token is issued for it — is not one, or the second token for an address
// nobody registered would carry a different Issuer from the first. Such an
// address, and no application at all, gets the SHARED entityID.
//
// **A JWT's `iss` is not decided here**: it is the realm's OAuth issuer
// (rcbj's decision on #480, kept on #494), `wstrust.ts`'s `oauthIssuer()`.
//
// **NO NAME AT ALL** is possible only in product with `saml2.entityId`
// emptied and nothing set: the SSO profile invents no entityID there
// (`saml2_sso.idpEntityIdFor()`), and neither does this file. `problem()`
// says so, and WS-Trust and WS-Federation refuse to sign under an empty name
// (STS-WSTRUST-0029, STS-WSFED-0020) as SAML SSO does (STS-SAML-0004).
//
// A STATIC UTILITY CLASS (rule 3: a library, no route, no state). `realms`,
// `applications` and `saml/saml2_sso` are reached LAZILY: the SAML assertion
// builders require this file, and the SSO module loads later in the stack.
// ---------------------------------------------------------------------------

import config = require('./config');
import helpers = require('./helpers');

const log = helpers.log;

// The layers an operator writes. Everything else is a shipped default.
const SET_LAYERS = ['realm', 'override', 'env', 'env-legacy', 'appconfig'];

/**
 * The names this service signs under as a SAML issuer, a WS-Trust STS and a
 * WS-Federation identity provider (#480, #494).
 */
export = class IssuerNames {
  /**
   * Returns the value somebody SET for a naming setting, or '' where it holds
   * a default — the shipped one, or a realm's seeded `urn:<domain>:sts`.
   *
   * @param key - `saml.issuer`, `wstrust.issuer` or `wsfed.entityId`
   * @returns the configured value, or ''
   */
  static configured(key: string): string {
    log.debug("Entering IssuerNames.configured(). " + key);
    const source = String(config.sourceOf(key) || '');
    const value = String(config.value(key) || '').trim();
    if (SET_LAYERS.indexOf(source) < 0 || !value) {
      log.debug("Leaving IssuerNames.configured(). A default.");
      return '';
    }
    if (source === 'realm' && value === IssuerNames.realmSeed()) {
      log.debug("Leaving IssuerNames.configured(). The realm's seed.");
      return '';
    }
    log.debug("Leaving IssuerNames.configured(). Set (" + source + ").");
    return value;
  }

  /**
   * Returns the name a realm is seeded with for the three settings,
   * `urn:<domain>:sts`, or '' outside a realm.
   *
   * @returns the seeded name
   */
  static realmSeed(): string {
    log.debug("Entering IssuerNames.realmSeed().");
    let seed = '';
    try {
      const realms = require('./realms');
      const realm = realms.current();
      const domain = realm && !realms.isDefault(realm)
        ? String(realms.domainOf(realm) || '') : '';
      seed = domain ? 'urn:' + domain + ':sts' : '';
    } catch (e) {
      // No realm registry loaded (a module tested on its own): no seed.
      log.debug("Caught in IssuerNames.realmSeed(): " +
                ((e && e.message) || e));
      seed = '';
    }
    log.debug("Leaving IssuerNames.realmSeed().");
    return seed;
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

  /**
   * Returns this identity provider's SAML 2.0 entityID for an application,
   * as the SSO profile names itself to it: the per-SP entityID where
   * `saml2.perApplicationEntityId` is on and an application is named, else
   * the shared one. '' where none is configured in product.
   *
   * @param application - the application's identifier; '' for the shared one
   * @returns the entityID
   */
  static entityIdFor(application?: string): string {
    log.debug("Entering IssuerNames.entityIdFor().");
    let out = '';
    try {
      const sso = require('../saml/saml2_sso');
      // ASKED, NEVER BUILT. Before the composition root has installed the
      // SSO module's instance, a facade call would build a DEFAULT one, and
      // the root's own install would then refuse and stop the start — which
      // is what WS-Trust's startup warning did in product mode (fix on
      // develop, 4cc56ad0). Since #494 every mode reads the entityID here, so
      // development would reach it too. Until the root has installed it, the
      // shared setting is read directly, below.
      if (sso.instanceOrigin() === 'none') {
        throw new Error('the SAML 2.0 SSO module is not installed yet');
      }
      out = String(sso.idpEntityIdFor(String(application || '')) || '');
    } catch (e) {
      // The SSO module is not loaded (a library tested on its own) or not
      // installed yet (a startup read): the shared setting, read directly.
      log.debug("Caught in IssuerNames.entityIdFor(): " +
                ((e && e.message) || e));
      out = String(config.value('saml2.entityId') || '').trim();
    }
    log.debug("Leaving IssuerNames.entityIdFor(). " + out);
    return out;
  }

  // One of the three: set, or the SAML entityID — the application's own
  // where a REGISTERED one is named, else the shared one. '' only where
  // there is no entityID either (product, `saml2.entityId` empty).
  private static named(key: string, application?: string): string {
    log.debug("Entering IssuerNames.named(). " + key);
    const set = IssuerNames.configured(key);
    if (set) {
      log.debug("Leaving IssuerNames.named(). Set.");
      return set;
    }
    const out = IssuerNames.entityIdFor(
      IssuerNames.registeredApplication(application));
    log.debug("Leaving IssuerNames.named(). The SAML entityID: " + out);
    return out;
  }

  /**
   * Returns the <saml:Issuer> of an assertion WS-Trust or WS-Federation
   * builds (`saml.issuer`).
   *
   * @param application - the application the assertion is for, whose
   * per-application entityID applies when it is registered; none for the
   * shared one
   * @returns the issuer, or '' where there is no name to sign under
   */
  static samlIssuer(application?: string): string {
    log.debug("Entering IssuerNames.samlIssuer().");
    log.debug("Leaving IssuerNames.samlIssuer().");
    return IssuerNames.named('saml.issuer', application);
  }

  /**
   * Returns the WS-Trust STS's name, as GET /sts publishes it
   * (`wstrust.issuer`).
   *
   * @returns the name
   */
  static wstrustIssuer(): string {
    log.debug("Entering IssuerNames.wstrustIssuer().");
    log.debug("Leaving IssuerNames.wstrustIssuer().");
    return IssuerNames.named('wstrust.issuer');
  }

  /**
   * Returns the WS-Federation entityID (`wsfed.entityId`): the shared
   * FederationMetadata document's, or one registered relying party's.
   *
   * @param application - the relying party's registry identifier (its
   * wtrealm); none for the shared document
   * @returns the entityID, or '' where there is no name to publish
   */
  static wsfedEntityId(application?: string): string {
    log.debug("Entering IssuerNames.wsfedEntityId().");
    log.debug("Leaving IssuerNames.wsfedEntityId().");
    return IssuerNames.named('wsfed.entityId', application);
  }

  /**
   * Returns the sentence a refusal carries when this realm has no name to
   * sign or publish under — product, `saml2.entityId` empty and none of the
   * three set — or '' when it has one.
   *
   * @param key - the setting the refusing surface signs under
   * @returns the sentence, or ''
   */
  static problem(key: string): string {
    log.debug("Entering IssuerNames.problem(). " + key);
    if (IssuerNames.named(key)) {
      log.debug("Leaving IssuerNames.problem(). There is a name.");
      return '';
    }
    log.debug("Leaving IssuerNames.problem(). No name.");
    return key + ' is not set and saml2.entityId is empty, and this realm ' +
           'is in PRODUCT mode, where this service does not invent a name ' +
           'to sign under. Set saml2.entityId (the SAML 2.0 console page, ' +
           'POST /admin-api/config/set, or the appconfig file) to the ' +
           'entityID relying parties are configured with, or set ' + key +
           '.';
  }
};
