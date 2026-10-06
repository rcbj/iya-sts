// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: issuer_names.ts
//
// ---------------------------------------------------------------------------
// THE NAMES THIS SERVICE SIGNS UNDER AS A SAML ISSUER, A WS-TRUST STS AND A
// WS-FEDERATION IDENTITY PROVIDER, DECIDED IN ONE PLACE (#480, 2026-10-06).
//
// Three settings name this service outside the SAML 2.0 browser profile:
// `saml.issuer` (the <saml:Issuer> of an assertion WS-Trust or WS-Federation
// builds), `wstrust.issuer` (the STS's name on GET /sts) and `wsfed.entityId`
// (the FederationMetadata entityID). All three shipped `urn:wstrust:mock:sts`,
// a development placeholder, and a product deployment signed with it — beside
// `/saml2/metadata`, which publishes `saml2.entityId`. A relying party
// configured from that metadata saw an issuer it was never told about.
//
// **rcbj's decision on #480: ALIGN WITH THE SAML ENTITYID.** In product
// (`mode.namesIssuersByEntityId()`) each of the three, where nobody set it,
// is the realm's `saml2.entityId` — what `/saml2/metadata` publishes as this
// identity provider. Development keeps the mock value. A value somebody SET
// still wins, in either mode:
//
//   * "set" means an operator's layer: a runtime override, the environment,
//     the operator's appconfig file. The shipped defaults (`env/defaults.js`
//     and the table's `dflt`) are not a choice anybody made;
//   * and a realm's SEEDED name is not one either. A realm is created with
//     `urn:<domain>:sts` on all three (`realms.js` NAMED_BY_REALM) so that two
//     realms never share a name; that seed is a default made distinct, and
//     reading it as an operator's choice would leave every product realm
//     misaligned. A realm value equal to its seed is read as a default; any
//     other realm value is somebody's choice and wins.
//
// **A SERVICE PROVIDER'S OWN entityID (`saml2.perApplicationEntityId`).** The
// SAML SSO profile already names itself to each service provider by
// `<entityID>:<sp>` (`saml2_sso.idpEntityIdFor()`), in the assertion's Issuer
// and in `/saml2/metadata/{sp}`. So the SAML issuer here takes the
// application a token is for: a WS-Trust assertion for an AppliesTo whose
// application this registry holds carries that application's per-SP
// entityID, the one its own metadata names — and SSO's function decides it,
// so the two cannot differ. No application (WS-Federation's assertions,
// whose metadata is one document; an AppliesTo nobody registered) is the
// shared entityID.
//
// A STATIC UTILITY CLASS (rule 3: a library, no route, no state). `realms` and
// `saml/saml2_sso` are reached LAZILY: the SAML assertion builders require
// this file, and both of those load later in the stack.
// ---------------------------------------------------------------------------

import config = require('./config');
import mode = require('./mode');
import helpers = require('./helpers');

const log = helpers.log;

// The layers an operator writes. Everything else is a shipped default.
const SET_LAYERS = ['realm', 'override', 'env', 'env-legacy', 'appconfig'];

/**
 * The names this service signs under as a SAML issuer, a WS-Trust STS and a
 * WS-Federation identity provider (#480).
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
      // is what WS-Trust's startup warning did in product mode, the one
      // mode whose issuer is aligned with the entityID. Until the root has
      // installed it, the shared setting is read directly, below.
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

  // One of the three: set, aligned (product), or the default (development).
  private static named(key: string, application?: string): string {
    log.debug("Entering IssuerNames.named(). " + key);
    const set = IssuerNames.configured(key);
    if (set) {
      log.debug("Leaving IssuerNames.named(). Set.");
      return set;
    }
    if (mode.namesIssuersByEntityId()) {
      const entityId = IssuerNames.entityIdFor(application);
      if (entityId) {
        log.debug("Leaving IssuerNames.named(). The SAML entityID.");
        return entityId;
      }
    }
    log.debug("Leaving IssuerNames.named(). The default.");
    return String(config.value(key) || '');
  }

  /**
   * Returns the <saml:Issuer> of an assertion WS-Trust or WS-Federation
   * builds (`saml.issuer`).
   *
   * @param application - the application the assertion is for, whose
   * per-SP entityID applies; none for the shared one
   * @returns the issuer
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
   * Returns the FederationMetadata entityID (`wsfed.entityId`).
   *
   * @returns the entityID
   */
  static wsfedEntityId(): string {
    log.debug("Entering IssuerNames.wsfedEntityId().");
    log.debug("Leaving IssuerNames.wsfedEntityId().");
    return IssuerNames.named('wsfed.entityId');
  }
};
