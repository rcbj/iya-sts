// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: models/directory/application.overlay.ts
//
// ---------------------------------------------------------------------------
// THE APPLICATION ENRICHMENT THE GENERATOR DOES NOT TOUCH (#1390).
//
// `common/applications.js`'s SCHEMA says what each attribute holds. It does
// not say which attribute is the key, which relationship the entry owns,
// or that the subject's urn is derived. This file says those things. A
// name in `attributes` or in an application-side relationship has to be a
// name the SCHEMA already publishes. A derived name is not an attribute,
// and the check fails if the SCHEMA grows one under that name.
//
// Operation ids stay empty until a later iteration names the admin and
// account operations that project an application. Inventing that list
// here would point at operations the overlay had not been shown.
//
// The directory still enforces none of this.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');

const log = bunyan.createLogger({
  name: 'sts-application-overlay',
  level: process.env.LOG_LEVEL || process.env.STS_LOG_LEVEL || 'info'
});

/**
 * A relationship the overlay claims. `on: 'application'` is checked
 * against `applications.SCHEMA`. `incoming` is a link some other object
 * holds.
 */
interface OverlayRelationship {
  name: string;
  to: string;
  on: string;
  cardinality: string;
  owns: boolean;
  incoming?: boolean;
  what: string;
}

/**
 * The hand-written application model.
 */
class ApplicationOverlay {
  /**
   * The attribute the entry is keyed by. Case-sensitive.
   */
  static readonly key = 'appIdentifier';

  /**
   * Names that are not LDAP attributes.
   */
  static readonly derived = [{
    name: 'subject',
    what: 'urn:sts:application:<appIdentifier>. Derived, not stored.'
  }];

  /**
   * The RDN attribute. It may be a digest of the key.
   */
  static readonly naming = {
    attribute: 'cn',
    what: 'The identifier, or app- plus twelve hex digits when the ' +
      'identifier is longer than 64 characters.'
  };

  /**
   * Registration, as opposed to a development sighting of the entry.
   */
  static readonly registration = ['appRegistered', 'appRegisteredBy'];

  /**
   * Declared families, and families that have been seen.
   */
  static readonly declaration = 'appAllowedProtocol';

  /**
   * Families observed on the entry. Not the declaration.
   */
  static readonly observation = 'appProtocol';

  /**
   * Attributes the SCHEMA marks `sensitive` or `secret`, the two flags
   * the service treats alike. The test holds this list to them in both
   * directions.
   */
  static readonly withheld = [
    'oauthClientSecret',
    'oauthAssertionPrivateKey',
    'oauthSamlAssertionPrivateKey',
    'appRegistrationAccessToken',
    'didPrivateKeys',
    'gnapSymmetricKey',
    'gnapMacaroonKey',
    'krb5ServiceKeys',
    'appEnrolledPrivateKey',
    'appAcmeEabKey',
    'appScepChallenge',
    'secretDestCredential',
    'scimClientPassword',
    'scimClientOAuthClientSecret',
    'scimClientTlsPrivateKey'
  ];

  /**
   * Links. Devices point at the application; the application does not
   * own that link. `appFgaPolicy` names a policy entry this application
   * owns.
   */
  static readonly relationships: OverlayRelationship[] = [
    { name: 'appRequiredRole', to: 'role', on: 'application', cardinality: 'multi',
      owns: false,
      what: 'Roles whose holders may use this application.' },
    { name: 'appAuthnPolicy', to: 'policy.authn', on: 'application', cardinality: 'single',
      owns: false, what: 'The named authentication policy it signs in under.' },
    { name: 'appPasskeyPolicy', to: 'policy.passkey', on: 'application', cardinality: 'single',
      owns: false, what: 'The named passkey policy a sign-in is held to.' },
    { name: 'appLocalePolicy', to: 'policy.locale', on: 'application', cardinality: 'single',
      owns: false, what: 'The named locale policy it falls back to.' },
    { name: 'appPasswordPolicy', to: 'policy.password', on: 'application',
      cardinality: 'single', owns: false,
      what: 'The named password policy a password set here uses.' },
    { name: 'appPostLoginPolicy', to: 'policy.postLogin', on: 'application', cardinality: 'single',
      owns: false, what: 'The named post-login profile a sign-in follows.' },
    { name: 'appFgaPolicy', to: 'xacmlPolicy', on: 'application', cardinality: 'single',
      owns: true,
      what: 'The fine-grained policy entry in ou=policies that it owns.' },
    { name: 'appFederationRelationship', to: 'federationRelationship', on: 'application',
      cardinality: 'multi', owns: false,
      what: 'Federation relationships this application is tied to.' },
    { name: 'stsDeviceApplication', to: 'device', on: 'device', cardinality: 'multi',
      owns: false, incoming: true,
      what: 'Devices name the application. The application does not ' +
        'store the reverse link.' }
  ];

  /**
   * Admin and account operation ids that project an application.
   * Empty until those operations are named by hand.
   */
  static readonly operationIds: string[] = [];

  /**
   * Names the SCHEMA must already contain. Derived names are absent.
   *
   * @param attributeNames - `applications.SCHEMA` attribute names
   * @returns problems, empty when the overlay matches
   */
  static problems(attributeNames: string[]): string[] {
    log.debug("Entering ApplicationOverlay.problems().");
    const have = new Set(attributeNames);
    const problems: string[] = [];
    ApplicationOverlay.requireName(have, ApplicationOverlay.key, problems);
    ApplicationOverlay.requireName(have, ApplicationOverlay.naming.attribute,
      problems);
    ApplicationOverlay.registration.forEach(function (name) {
      ApplicationOverlay.requireName(have, name, problems);
    });
    ApplicationOverlay.requireName(have, ApplicationOverlay.declaration,
      problems);
    ApplicationOverlay.requireName(have, ApplicationOverlay.observation,
      problems);
    ApplicationOverlay.withheld.forEach(function (name) {
      ApplicationOverlay.requireName(have, name, problems);
    });
    ApplicationOverlay.relationships.forEach(function (link) {
      if (link.on === 'application') {
        ApplicationOverlay.requireName(have, link.name, problems);
      }
    });
    ApplicationOverlay.derived.forEach(function (field) {
      if (have.has(field.name)) {
        problems.push(field.name + ' is derived and is also an attribute');
      }
    });
    log.debug("Leaving ApplicationOverlay.problems().");
    return problems;
  }

  /**
   * Records one missing attribute name.
   *
   * @param have - the SCHEMA's names
   * @param name - the overlay's name
   * @param problems - the list being built
   */
  static requireName(have: Set<string>, name: string,
      problems: string[]): void {
    log.debug("Entering ApplicationOverlay.requireName().");
    if (!have.has(name)) {
      problems.push(name + ' is not an application attribute');
    }
    log.debug("Leaving ApplicationOverlay.requireName().");
  }
}

export = ApplicationOverlay;
