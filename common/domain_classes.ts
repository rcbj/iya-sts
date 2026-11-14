// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: domain_classes.ts
//
// GENERATED from models/domain/ (#1390). Do not edit: change the model and
// run tests/tools/regenerate-model-docs.sh. tests/model_domain.js fails
// when this differs.

import bunyan = require('bunyan');
import DomainMap = require('./domain_map');

const log = bunyan.createLogger({
  name: 'sts-domain-classes',
  level: process.env.LOG_LEVEL || process.env.STS_LOG_LEVEL || 'info'
});

/**
 * Something this service issues to or accepts from, in any protocol.
 */
class Application {
  /**
   * Makes one from what holds it.
   *
   * @param held - the attributes or the record
   * @param options - what it alone cannot say
   * @returns the concept
   */
  static fromEntry(held: any, options?: any):
      IyaDomain.Application {
    log.debug("Entering Application.fromEntry().");
    const made = DomainMap.fromEntry('Application', held, options);
    log.debug("Leaving Application.fromEntry().");
    return made;
  }
}

/**
 * What every person in a realm must hold.
 */
class AttributePolicy {
  /**
   * Makes one from what holds it.
   *
   * @param held - the attributes or the record
   * @param options - what it alone cannot say
   * @returns the concept
   */
  static fromEntry(held: any, options?: any):
      IyaDomain.AttributePolicy {
    log.debug("Entering AttributePolicy.fromEntry().");
    const made = DomainMap.fromEntry('AttributePolicy', held, options);
    log.debug("Leaving AttributePolicy.fromEntry().");
    return made;
  }
}

/**
 * An operator database a realm reads attributes from.
 */
class AttributeSource {
  /**
   * Makes one from what holds it.
   *
   * @param held - the attributes or the record
   * @param options - what it alone cannot say
   * @returns the concept
   */
  static fromEntry(held: any, options?: any):
      IyaDomain.AttributeSource {
    log.debug("Entering AttributeSource.fromEntry().");
    const made = DomainMap.fromEntry('AttributeSource', held, options);
    log.debug("Leaving AttributeSource.fromEntry().");
    return made;
  }
}

/**
 * One thing that happened, as the realm's audit log records it.
 */
class AuditEvent {
  /**
   * Makes one from what holds it.
   *
   * @param held - the attributes or the record
   * @param options - what it alone cannot say
   * @returns the concept
   */
  static fromRecord(held: any, options?: any):
      IyaDomain.AuditEvent {
    log.debug("Entering AuditEvent.fromRecord().");
    const made = DomainMap.fromRecord('AuditEvent', held, options);
    log.debug("Leaving AuditEvent.fromRecord().");
    return made;
  }
}

/**
 * One act of proving who somebody is, recorded on the session it happened in.
 */
class AuthenticationEvent {
  /**
   * Makes one from what holds it.
   *
   * @param held - the attributes or the record
   * @param options - what it alone cannot say
   * @returns the concept
   */
  static fromRecord(held: any, options?: any):
      IyaDomain.AuthenticationEvent {
    log.debug("Entering AuthenticationEvent.fromRecord().");
    const made = DomainMap.fromRecord('AuthenticationEvent', held, options);
    log.debug("Leaving AuthenticationEvent.fromRecord().");
    return made;
  }
}

/**
 * Which mechanisms a sign-in may use.
 */
class AuthenticationPolicy {
  /**
   * Makes one from what holds it.
   *
   * @param held - the attributes or the record
   * @param options - what it alone cannot say
   * @returns the concept
   */
  static fromEntry(held: any, options?: any):
      IyaDomain.AuthenticationPolicy {
    log.debug("Entering AuthenticationPolicy.fromEntry().");
    const made = DomainMap.fromEntry('AuthenticationPolicy', held, options);
    log.debug("Leaving AuthenticationPolicy.fromEntry().");
    return made;
  }
}

/**
 * Certificate enrollment by EST, ACME or SCEP.
 */
class CertificateEnrollment {
  /**
   * Makes one from what holds it.
   *
   * @param held - the attributes or the record
   * @param options - what it alone cannot say
   * @returns the concept
   */
  static fromEntry(held: any, options?: any):
      IyaDomain.CertificateEnrollment {
    log.debug("Entering CertificateEnrollment.fromEntry().");
    const made = DomainMap.fromEntry('CertificateEnrollment', held, options);
    log.debug("Leaving CertificateEnrollment.fromEntry().");
    return made;
  }
}

/**
 * An OpenID Connect claims provider.
 */
class ClaimProvider {
  /**
   * Makes one from what holds it.
   *
   * @param held - the attributes or the record
   * @param options - what it alone cannot say
   * @returns the concept
   */
  static fromEntry(held: any, options?: any):
      IyaDomain.ClaimProvider {
    log.debug("Entering ClaimProvider.fromEntry().");
    const made = DomainMap.fromEntry('ClaimProvider', held, options);
    log.debug("Leaving ClaimProvider.fromEntry().");
    return made;
  }
}

/**
 * Everything a person proves themselves with: the concept a User deliberately
 * is not.
 */
class Credential {
  /**
   * Makes one from what holds it.
   *
   * @param held - the attributes or the record
   * @param options - what it alone cannot say
   * @returns the concept
   */
  static fromEntry(held: any, options?: any):
      IyaDomain.Credential {
    log.debug("Entering Credential.fromEntry().");
    const made = DomainMap.fromEntry('Credential', held, options);
    log.debug("Leaving Credential.fromEntry().");
    return made;
  }
}

/**
 * A device registered in a realm, and what is known about its state.
 */
class Device {
  /**
   * Makes one from what holds it.
   *
   * @param held - the attributes or the record
   * @param options - what it alone cannot say
   * @returns the concept
   */
  static fromEntry(held: any, options?: any):
      IyaDomain.Device {
    log.debug("Entering Device.fromEntry().");
    const made = DomainMap.fromEntry('Device', held, options);
    log.debug("Leaving Device.fromEntry().");
    return made;
  }
}

/**
 * What the directory keeps about any entry.
 */
class DirectoryEntry {
  /**
   * Makes one from what holds it.
   *
   * @param held - the attributes or the record
   * @param options - what it alone cannot say
   * @returns the concept
   */
  static fromEntry(held: any, options?: any):
      IyaDomain.DirectoryEntry {
    log.debug("Entering DirectoryEntry.fromEntry().");
    const made = DomainMap.fromEntry('DirectoryEntry', held, options);
    log.debug("Leaving DirectoryEntry.fromEntry().");
    return made;
  }
}

/**
 * An agreement with one partner, in either direction and one protocol.
 */
class FederationRelationship {
  /**
   * Makes one from what holds it.
   *
   * @param held - the attributes or the record
   * @param options - what it alone cannot say
   * @returns the concept
   */
  static fromEntry(held: any, options?: any):
      IyaDomain.FederationRelationship {
    log.debug("Entering FederationRelationship.fromEntry().");
    const made = DomainMap.fromEntry('FederationRelationship', held, options);
    log.debug("Leaving FederationRelationship.fromEntry().");
    return made;
  }
}

/**
 * A GNAP client.
 */
class GnapClient {
  /**
   * Makes one from what holds it.
   *
   * @param held - the attributes or the record
   * @param options - what it alone cannot say
   * @returns the concept
   */
  static fromEntry(held: any, options?: any):
      IyaDomain.GnapClient {
    log.debug("Entering GnapClient.fromEntry().");
    const made = DomainMap.fromEntry('GnapClient', held, options);
    log.debug("Leaving GnapClient.fromEntry().");
    return made;
  }
}

/**
 * A set of people, and the policies that apply to its members. A group grants
 * nothing by being a group.
 */
class Group {
  /**
   * Makes one from what holds it.
   *
   * @param held - the attributes or the record
   * @param options - what it alone cannot say
   * @returns the concept
   */
  static fromEntry(held: any, options?: any):
      IyaDomain.Group {
    log.debug("Entering Group.fromEntry().");
    const made = DomainMap.fromEntry('Group', held, options);
    log.debug("Leaving Group.fromEntry().");
    return made;
  }
}

/**
 * A token this service issued, as its register remembers it. The signed value
 * is not kept.
 */
class IssuedToken {
  /**
   * Makes one from what holds it.
   *
   * @param held - the attributes or the record
   * @param options - what it alone cannot say
   * @returns the concept
   */
  static fromRecord(held: any, options?: any):
      IyaDomain.IssuedToken {
    log.debug("Entering IssuedToken.fromRecord().");
    const made = DomainMap.fromRecord('IssuedToken', held, options);
    log.debug("Leaving IssuedToken.fromRecord().");
    return made;
  }
}

/**
 * A Kerberos service principal.
 */
class KerberosService {
  /**
   * Makes one from what holds it.
   *
   * @param held - the attributes or the record
   * @param options - what it alone cannot say
   * @returns the concept
   */
  static fromEntry(held: any, options?: any):
      IyaDomain.KerberosService {
    log.debug("Entering KerberosService.fromEntry().");
    const made = DomainMap.fromEntry('KerberosService', held, options);
    log.debug("Leaving KerberosService.fromEntry().");
    return made;
  }
}

/**
 * A Kerberos trust with another realm.
 */
class KerberosTrust {
  /**
   * Makes one from what holds it.
   *
   * @param held - the attributes or the record
   * @param options - what it alone cannot say
   * @returns the concept
   */
  static fromEntry(held: any, options?: any):
      IyaDomain.KerberosTrust {
    log.debug("Entering KerberosTrust.fromEntry().");
    const made = DomainMap.fromEntry('KerberosTrust', held, options);
    log.debug("Leaving KerberosTrust.fromEntry().");
    return made;
  }
}

/**
 * Which languages a realm offers.
 */
class LocalePolicy {
  /**
   * Makes one from what holds it.
   *
   * @param held - the attributes or the record
   * @param options - what it alone cannot say
   * @returns the concept
   */
  static fromEntry(held: any, options?: any):
      IyaDomain.LocalePolicy {
    log.debug("Entering LocalePolicy.fromEntry().");
    const made = DomainMap.fromEntry('LocalePolicy', held, options);
    log.debug("Leaving LocalePolicy.fromEntry().");
    return made;
  }
}

/**
 * What an OAuth 2.0 client or OpenID Connect relying party is registered with.
 */
class OAuthClient {
  /**
   * Makes one from what holds it.
   *
   * @param held - the attributes or the record
   * @param options - what it alone cannot say
   * @returns the concept
   */
  static fromEntry(held: any, options?: any):
      IyaDomain.OAuthClient {
    log.debug("Entering OAuthClient.fromEntry().");
    const made = DomainMap.fromEntry('OAuthClient', held, options);
    log.debug("Leaving OAuthClient.fromEntry().");
    return made;
  }
}

/**
 * An OpenID Federation entity this realm holds.
 */
class OpenIdFederationEntity {
  /**
   * Makes one from what holds it.
   *
   * @param held - the attributes or the record
   * @param options - what it alone cannot say
   * @returns the concept
   */
  static fromEntry(held: any, options?: any):
      IyaDomain.OpenIdFederationEntity {
    log.debug("Entering OpenIdFederationEntity.fromEntry().");
    const made = DomainMap.fromEntry('OpenIdFederationEntity', held, options);
    log.debug("Leaving OpenIdFederationEntity.fromEntry().");
    return made;
  }
}

/**
 * What a passkey must be.
 */
class PasskeyPolicy {
  /**
   * Makes one from what holds it.
   *
   * @param held - the attributes or the record
   * @param options - what it alone cannot say
   * @returns the concept
   */
  static fromEntry(held: any, options?: any):
      IyaDomain.PasskeyPolicy {
    log.debug("Entering PasskeyPolicy.fromEntry().");
    const made = DomainMap.fromEntry('PasskeyPolicy', held, options);
    log.debug("Leaving PasskeyPolicy.fromEntry().");
    return made;
  }
}

/**
 * What a password must be.
 */
class PasswordPolicy {
  /**
   * Makes one from what holds it.
   *
   * @param held - the attributes or the record
   * @param options - what it alone cannot say
   * @returns the concept
   */
  static fromEntry(held: any, options?: any):
      IyaDomain.PasswordPolicy {
    log.debug("Entering PasswordPolicy.fromEntry().");
    const made = DomainMap.fromEntry('PasswordPolicy', held, options);
    log.debug("Leaving PasswordPolicy.fromEntry().");
    return made;
  }
}

/**
 * What this service keeps about a person beyond their profile and credentials:
 * federation links, delegation, consent and SPIFFE subjects.
 */
class PersonRecord {
  /**
   * Makes one from what holds it.
   *
   * @param held - the attributes or the record
   * @param options - what it alone cannot say
   * @returns the concept
   */
  static fromEntry(held: any, options?: any):
      IyaDomain.PersonRecord {
    log.debug("Entering PersonRecord.fromEntry().");
    const made = DomainMap.fromEntry('PersonRecord', held, options);
    log.debug("Leaving PersonRecord.fromEntry().");
    return made;
  }
}

/**
 * What is asked of a person after signing in.
 */
class PostLoginPolicy {
  /**
   * Makes one from what holds it.
   *
   * @param held - the attributes or the record
   * @param options - what it alone cannot say
   * @returns the concept
   */
  static fromEntry(held: any, options?: any):
      IyaDomain.PostLoginPolicy {
    log.debug("Entering PostLoginPolicy.fromEntry().");
    const made = DomainMap.fromEntry('PostLoginPolicy', held, options);
    log.debug("Leaving PostLoginPolicy.fromEntry().");
    return made;
  }
}

/**
 * A set of permissions and who holds it.
 */
class Role {
  /**
   * Makes one from what holds it.
   *
   * @param held - the attributes or the record
   * @param options - what it alone cannot say
   * @returns the concept
   */
  static fromEntry(held: any, options?: any):
      IyaDomain.Role {
    log.debug("Entering Role.fromEntry().");
    const made = DomainMap.fromEntry('Role', held, options);
    log.debug("Leaving Role.fromEntry().");
    return made;
  }
}

/**
 * What a SAML service provider is registered with.
 */
class SamlServiceProvider {
  /**
   * Makes one from what holds it.
   *
   * @param held - the attributes or the record
   * @param options - what it alone cannot say
   * @returns the concept
   */
  static fromEntry(held: any, options?: any):
      IyaDomain.SamlServiceProvider {
    log.debug("Entering SamlServiceProvider.fromEntry().");
    const made = DomainMap.fromEntry('SamlServiceProvider', held, options);
    log.debug("Leaving SamlServiceProvider.fromEntry().");
    return made;
  }
}

/**
 * Where people are provisioned by SCIM.
 */
class ScimProvisioningTarget {
  /**
   * Makes one from what holds it.
   *
   * @param held - the attributes or the record
   * @param options - what it alone cannot say
   * @returns the concept
   */
  static fromEntry(held: any, options?: any):
      IyaDomain.ScimProvisioningTarget {
    log.debug("Entering ScimProvisioningTarget.fromEntry().");
    const made = DomainMap.fromEntry('ScimProvisioningTarget', held, options);
    log.debug("Leaving ScimProvisioningTarget.fromEntry().");
    return made;
  }
}

/**
 * Where a rotated password is pushed.
 */
class SecretDestination {
  /**
   * Makes one from what holds it.
   *
   * @param held - the attributes or the record
   * @param options - what it alone cannot say
   * @returns the concept
   */
  static fromEntry(held: any, options?: any):
      IyaDomain.SecretDestination {
    log.debug("Entering SecretDestination.fromEntry().");
    const made = DomainMap.fromEntry('SecretDestination', held, options);
    log.debug("Leaving SecretDestination.fromEntry().");
    return made;
  }
}

/**
 * An account a program uses, rotated by this service and owned by a person.
 */
class ServiceAccount {
  /**
   * Makes one from what holds it.
   *
   * @param held - the attributes or the record
   * @param options - what it alone cannot say
   * @returns the concept
   */
  static fromEntry(held: any, options?: any):
      IyaDomain.ServiceAccount {
    log.debug("Entering ServiceAccount.fromEntry().");
    const made = DomainMap.fromEntry('ServiceAccount', held, options);
    log.debug("Leaving ServiceAccount.fromEntry().");
    return made;
  }
}

/**
 * What a service account may do.
 */
class ServiceAccountPolicy {
  /**
   * Makes one from what holds it.
   *
   * @param held - the attributes or the record
   * @param options - what it alone cannot say
   * @returns the concept
   */
  static fromEntry(held: any, options?: any):
      IyaDomain.ServiceAccountPolicy {
    log.debug("Entering ServiceAccountPolicy.fromEntry().");
    const made = DomainMap.fromEntry('ServiceAccountPolicy', held, options);
    log.debug("Leaving ServiceAccountPolicy.fromEntry().");
    return made;
  }
}

/**
 * An authenticated identity: the internal record every issued artifact is a
 * projection of.
 */
class Session {
  /**
   * Makes one from what holds it.
   *
   * @param held - the attributes or the record
   * @param options - what it alone cannot say
   * @returns the concept
   */
  static fromRecord(held: any, options?: any):
      IyaDomain.Session {
    log.debug("Entering Session.fromRecord().");
    const made = DomainMap.fromRecord('Session', held, options);
    log.debug("Leaving Session.fromRecord().");
    return made;
  }
}

/**
 * A Shared Signals receiver or transmitter partner.
 */
class SharedSignalsReceiver {
  /**
   * Makes one from what holds it.
   *
   * @param held - the attributes or the record
   * @param options - what it alone cannot say
   * @returns the concept
   */
  static fromEntry(held: any, options?: any):
      IyaDomain.SharedSignalsReceiver {
    log.debug("Entering SharedSignalsReceiver.fromEntry().");
    const made = DomainMap.fromEntry('SharedSignalsReceiver', held, options);
    log.debug("Leaving SharedSignalsReceiver.fromEntry().");
    return made;
  }
}

/**
 * A certificate authority a realm trusts to sign what it is sent.
 */
class SignerTrustAnchor {
  /**
   * Makes one from what holds it.
   *
   * @param held - the attributes or the record
   * @param options - what it alone cannot say
   * @returns the concept
   */
  static fromEntry(held: any, options?: any):
      IyaDomain.SignerTrustAnchor {
    log.debug("Entering SignerTrustAnchor.fromEntry().");
    const made = DomainMap.fromEntry('SignerTrustAnchor', held, options);
    log.debug("Leaving SignerTrustAnchor.fromEntry().");
    return made;
  }
}

/**
 * A SPIFFE registration entry.
 */
class SpiffeRegistration {
  /**
   * Makes one from what holds it.
   *
   * @param held - the attributes or the record
   * @param options - what it alone cannot say
   * @returns the concept
   */
  static fromEntry(held: any, options?: any):
      IyaDomain.SpiffeRegistration {
    log.debug("Entering SpiffeRegistration.fromEntry().");
    const made = DomainMap.fromEntry('SpiffeRegistration', held, options);
    log.debug("Leaving SpiffeRegistration.fromEntry().");
    return made;
  }
}

/**
 * A certificate authority a realm trusts for client certificates.
 */
class TrustAnchor {
  /**
   * Makes one from what holds it.
   *
   * @param held - the attributes or the record
   * @param options - what it alone cannot say
   * @returns the concept
   */
  static fromEntry(held: any, options?: any):
      IyaDomain.TrustAnchor {
    log.debug("Entering TrustAnchor.fromEntry().");
    const made = DomainMap.fromEntry('TrustAnchor', held, options);
    log.debug("Leaving TrustAnchor.fromEntry().");
    return made;
  }
}

/**
 * A person this service authenticates, as every protocol projects them.
 */
class User {
  /**
   * Makes one from what holds it.
   *
   * @param held - the attributes or the record
   * @param options - what it alone cannot say
   * @returns the concept
   */
  static fromEntry(held: any, options?: any):
      IyaDomain.User {
    log.debug("Entering User.fromEntry().");
    const made = DomainMap.fromEntry('User', held, options);
    log.debug("Leaving User.fromEntry().");
    return made;
  }
}

/**
 * Decentralized identifiers and verifiable credentials.
 */
class VerifiableCredentialPartner {
  /**
   * Makes one from what holds it.
   *
   * @param held - the attributes or the record
   * @param options - what it alone cannot say
   * @returns the concept
   */
  static fromEntry(held: any, options?: any):
      IyaDomain.VerifiableCredentialPartner {
    log.debug("Entering VerifiableCredentialPartner.fromEntry().");
    const made = DomainMap.fromEntry('VerifiableCredentialPartner', held, options);
    log.debug("Leaving VerifiableCredentialPartner.fromEntry().");
    return made;
  }
}

/**
 * What a WS-Federation relying party is registered with.
 */
class WsFederationRelyingParty {
  /**
   * Makes one from what holds it.
   *
   * @param held - the attributes or the record
   * @param options - what it alone cannot say
   * @returns the concept
   */
  static fromEntry(held: any, options?: any):
      IyaDomain.WsFederationRelyingParty {
    log.debug("Entering WsFederationRelyingParty.fromEntry().");
    const made = DomainMap.fromEntry('WsFederationRelyingParty', held, options);
    log.debug("Leaving WsFederationRelyingParty.fromEntry().");
    return made;
  }
}

/**
 * A WS-Trust relying party.
 */
class WsTrustRelyingParty {
  /**
   * Makes one from what holds it.
   *
   * @param held - the attributes or the record
   * @param options - what it alone cannot say
   * @returns the concept
   */
  static fromEntry(held: any, options?: any):
      IyaDomain.WsTrustRelyingParty {
    log.debug("Entering WsTrustRelyingParty.fromEntry().");
    const made = DomainMap.fromEntry('WsTrustRelyingParty', held, options);
    log.debug("Leaving WsTrustRelyingParty.fromEntry().");
    return made;
  }
}

/**
 * A remote policy enforcement point.
 */
class XacmlPep {
  /**
   * Makes one from what holds it.
   *
   * @param held - the attributes or the record
   * @param options - what it alone cannot say
   * @returns the concept
   */
  static fromEntry(held: any, options?: any):
      IyaDomain.XacmlPep {
    log.debug("Entering XacmlPep.fromEntry().");
    const made = DomainMap.fromEntry('XacmlPep', held, options);
    log.debug("Leaving XacmlPep.fromEntry().");
    return made;
  }
}

/**
 * An XACML 3.0 policy or policy set this realm evaluates.
 */
class XacmlPolicy {
  /**
   * Makes one from what holds it.
   *
   * @param held - the attributes or the record
   * @param options - what it alone cannot say
   * @returns the concept
   */
  static fromEntry(held: any, options?: any):
      IyaDomain.XacmlPolicy {
    log.debug("Entering XacmlPolicy.fromEntry().");
    const made = DomainMap.fromEntry('XacmlPolicy', held, options);
    log.debug("Leaving XacmlPolicy.fromEntry().");
    return made;
  }
}

export = {
  Application: Application,
  AttributePolicy: AttributePolicy,
  AttributeSource: AttributeSource,
  AuditEvent: AuditEvent,
  AuthenticationEvent: AuthenticationEvent,
  AuthenticationPolicy: AuthenticationPolicy,
  CertificateEnrollment: CertificateEnrollment,
  ClaimProvider: ClaimProvider,
  Credential: Credential,
  Device: Device,
  DirectoryEntry: DirectoryEntry,
  FederationRelationship: FederationRelationship,
  GnapClient: GnapClient,
  Group: Group,
  IssuedToken: IssuedToken,
  KerberosService: KerberosService,
  KerberosTrust: KerberosTrust,
  LocalePolicy: LocalePolicy,
  OAuthClient: OAuthClient,
  OpenIdFederationEntity: OpenIdFederationEntity,
  PasskeyPolicy: PasskeyPolicy,
  PasswordPolicy: PasswordPolicy,
  PersonRecord: PersonRecord,
  PostLoginPolicy: PostLoginPolicy,
  Role: Role,
  SamlServiceProvider: SamlServiceProvider,
  ScimProvisioningTarget: ScimProvisioningTarget,
  SecretDestination: SecretDestination,
  ServiceAccount: ServiceAccount,
  ServiceAccountPolicy: ServiceAccountPolicy,
  Session: Session,
  SharedSignalsReceiver: SharedSignalsReceiver,
  SignerTrustAnchor: SignerTrustAnchor,
  SpiffeRegistration: SpiffeRegistration,
  TrustAnchor: TrustAnchor,
  User: User,
  VerifiableCredentialPartner: VerifiableCredentialPartner,
  WsFederationRelyingParty: WsFederationRelyingParty,
  WsTrustRelyingParty: WsTrustRelyingParty,
  XacmlPep: XacmlPep,
  XacmlPolicy: XacmlPolicy
};
