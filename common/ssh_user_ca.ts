// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: ssh_user_ca.ts
//
// ---------------------------------------------------------------------------
// THE REALM'S OPENSSH USER CA (#1955 P3). The PKI row owns its key and its
// issued-serial register; this module owns the decision to issue: principals
// come only from the caller's directory entry and its groups, each is a
// separate XACML request, and only verified security-key or PIV evidence
// earns the longer lifetime. The hardware-token register's lost-token act
// calls back here through its validated retirer hook, which revokes every
// certificate for that key before the scheduler rebuilds the KRL.
//
// Security-key attestation signatures are checked over the authenticator
// data, whose RP ID hash and credential public key must match the submitted
// `sk-*` key. The attestation certificate must chain to an operator-configured
// `webauthn.attestationTrustAnchors` certificate; an untrusted statement is
// never hardware evidence.
// ---------------------------------------------------------------------------

import helpers = require('./helpers');
import InstanceSlot = require('./instance_slot');
import pki = require('./pki');
import stsCrypto = require('./crypto');
import accessGate = require('./access_gate');
import config = require('./config');
import hardwareTokens = require('./hardware_tokens');
import errorCodes = require('./error_codes');
import audit = require('./audit');

type Json = any;

const SOFTWARE_LIFETIME_S = 300;
const HARDWARE_LIFETIME_S = 3600;
const KRL_JOB = 'ssh-user-ca.krl';
const KRL_EVERY_MS = 5 * 60 * 1000;

interface SshUserCaDeps {
  log: typeof helpers.log;
  pki: typeof pki;
  crypto: typeof stsCrypto;
  accessGate: typeof accessGate;
  config: typeof config;
  hardwareTokens: typeof hardwareTokens;
  errorCodes: typeof errorCodes;
  audit: typeof audit;
  directory(): Json;
  webauthn(): Json;
}

/**
 * Issues certificates from a realm's OpenSSH user CA.
 */
class SshUserCa {
  /**
   * Builds the service over the dependencies it uses.
   *
   * @param deps - the PKI, policy and hardware-token services
   */
  constructor(private readonly deps: SshUserCaDeps) {
    deps.log.debug("Entering SshUserCa.constructor().");
    deps.log.debug("Leaving SshUserCa.constructor().");
  }

  /**
   * Returns the production dependency set.
   *
   * @returns the dependencies
   */
  static defaultDeps(): SshUserCaDeps {
    helpers.log.debug("Entering SshUserCa.defaultDeps().");
    helpers.log.debug("Leaving SshUserCa.defaultDeps().");
    return {
      log: helpers.log, pki: pki, crypto: stsCrypto,
      accessGate: accessGate, config: config,
      hardwareTokens: hardwareTokens, errorCodes: errorCodes, audit: audit,
      directory: function (): Json {
        return require('../ldap/ldap_server');
      },
      webauthn: function (): Json {
        return require('../authn/webauthn');
      }
    };
  }

  private refuse(code: string, why: string): Json {
    const { log, errorCodes: codes } = this.deps;
    log.debug("Entering SshUserCa.refuse(). " + code);
    const answer = codes.mark({ ok: false, errors: [why] }, code);
    log.debug("Leaving SshUserCa.refuse().");
    return answer;
  }

  private candidatesOf(username: string): Json {
    const { directory, log } = this.deps;
    log.debug("Entering SshUserCa.candidatesOf().");
    const ldap = directory();
    const entry = ldap.existingUserEntry(username);
    if (!entry || !entry.attributes) {
      log.debug("Leaving SshUserCa.candidatesOf(). No entry.");
      return null;
    }
    const attrs = entry.attributes;
    const uid = [].concat(attrs.uid || []).map(function (one: Json): string {
      return String(one || '').trim();
    }).filter(function (one: string): boolean {
      return !!one;
    });
    const groups = ldap.groupsOfUser(entry.dn);
    const groupCns = (groups && groups.entryFound ? groups.groups : [])
      .map(function (one: Json): string {
        return String((one && one.cn) || '').trim();
      }).filter(function (one: string): boolean {
        return !!one;
      });
    const names = Array.from(new Set(uid.concat(groupCns)));
    log.debug("Leaving SshUserCa.candidatesOf(). " + names.length + '.');
    return { entry: entry, uid: uid, names: names };
  }

  private async pivEvidenceFor(username: string, key: Json): Promise<Json> {
    const { directory, hardwareTokens: tokens, log, pki: certificate } =
      this.deps;
    log.debug("Entering SshUserCa.pivEvidenceFor().");
    const stored = directory().storedCertificatesOf('person', username);
    const certificates = (stored && stored.certificates) || [];
    for (let i = 0; i < certificates.length; i++) {
      const der = Buffer.from(certificates[i].der || []);
      const parsed = certificate.certificateFromDer(der);
      if (!parsed || !certificate.sshKeyMatches(key, parsed.x509.publicKey)) {
        continue;
      }
      const serial = certificate.certificateSerialHex(der);
      const evidence = tokens.evidenceFor('x509', serial);
      if (evidence.hardware === true &&
          evidence.source === 'piv-attestation' && evidence.token) {
        log.debug("Leaving SshUserCa.pivEvidenceFor(). PIV.");
        return { token: String(evidence.token), serial: serial };
      }
    }
    log.debug("Leaving SshUserCa.pivEvidenceFor(). None.");
    return null;
  }

  private async securityKeyEvidence(key: Json, encoded: string): Promise<Json> {
    const { log, pki: certificate, crypto, config: cfg, webauthn } =
      this.deps;
    log.debug("Entering SshUserCa.securityKeyEvidence().");
    if (!encoded || encoded.length > 87384 ||
        !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/
          .test(encoded)) {
      log.debug("Leaving SshUserCa.securityKeyEvidence(). Bad encoding.");
      return null;
    }
    let attestation: Json;
    let authData: Json;
    let cert: Json;
    try {
      const bytes = Buffer.from(encoded, 'base64');
      if (!bytes.length || bytes.length > 65536) {
        log.debug("Leaving SshUserCa.securityKeyEvidence(). Size.");
        return null;
      }
      attestation = certificate.parseSshSkAttestation(bytes);
      authData = webauthn().parseAuthenticatorData(attestation.authData);
      cert = certificate.certificateFromDer(attestation.certificate);
    } catch (e) {
      log.debug("Caught in SshUserCa.securityKeyEvidence(): " +
                ((e && e.message) || e));
      log.debug("Leaving SshUserCa.securityKeyEvidence(). Unreadable.");
      return null;
    }
    if (!cert || !authData.flags || !authData.flags.at ||
        !authData.flags.up || !authData.credentialPublicKey ||
        !key.application ||
        !Buffer.from(authData.rpIdHash).equals(
          crypto.digest('sha256', key.application)) ||
        !certificate.sshKeyMatches(key,
          crypto.publicKeyOf(webauthn().coseKeyToJwk(
            authData.credentialPublicKey).jwk))) {
      log.debug("Leaving SshUserCa.securityKeyEvidence(). Key mismatch.");
      return null;
    }
    const publicKey = cert.x509.publicKey;
    if (publicKey.asymmetricKeyType !== 'ec' ||
        String((publicKey.asymmetricKeyDetails || {}).namedCurve) !==
          'prime256v1' ||
        !(await crypto.verifyRawSignature({
          family: 'ecdsa', hash: 'sha256', encoding: 'der'
        }, publicKey, attestation.authData, attestation.signature))) {
      log.debug("Leaving SshUserCa.securityKeyEvidence(). Signature.");
      return null;
    }
    const configured = String(cfg.value('webauthn.attestationTrustAnchors') ||
                               '');
    const anchors = certificate.certificateBundle(configured).certificates
      .map(function (one: Json): Buffer {
        return Buffer.from(one.der);
      });
    const path = await certificate.verifyPathToAnchors(
      attestation.certificate, [], anchors);
    if (!path.ok) {
      log.debug("Leaving SshUserCa.securityKeyEvidence(). Untrusted.");
      return null;
    }
    log.debug("Leaving SshUserCa.securityKeyEvidence(). Verified.");
    return {
      vendor: 'fido',
      serial: crypto.digest('sha256', attestation.certificate, 'hex'),
      format: attestation.version
    };
  }

  private recordHardwareCredential(username: string, fingerprint: string,
                                   evidence: Json): Json {
    const { hardwareTokens: tokens, log } = this.deps;
    log.debug("Entering SshUserCa.recordHardwareCredential().");
    let record: Json;
    if (evidence.source === 'piv-attestation') {
      const slash = String(evidence.token).indexOf('/');
      record = tokens.recordAttested({
        username: username, vendor: String(evidence.token).slice(0, slash),
        serial: String(evidence.token).slice(slash + 1),
        credential: { kind: 'ssh', ref: fingerprint,
                      label: 'SSH user key' },
        evidence: { source: 'piv-attestation', smartCard: true,
                    format: 'yubico-piv' }
      });
    } else {
      record = tokens.recordAttested({
        username: username, vendor: evidence.vendor,
        serial: evidence.serial,
        credential: { kind: 'ssh', ref: fingerprint,
                      label: 'OpenSSH security key' },
        evidence: { source: 'ssh-security-key-attestation',
                    format: evidence.format }
      });
    }
    log.debug("Leaving SshUserCa.recordHardwareCredential(). " +
              (record && record.ok ? 'Recorded.' : 'Failed.'));
    return record;
  }

  /**
   * Issues a certificate for a caller's UID and permitted group principals.
   *
   * @param spec - `{ username, subject, publicKey, principals, lifetimeS,
   *   attestation }`
   * @returns the issued certificate or a marked refusal
   */
  async issue(spec: Json): Promise<Json> {
    const { log, pki: certificate, accessGate: gate, audit: eventLog } =
      this.deps;
    const s = spec || {};
    log.debug("Entering SshUserCa.issue().");
    const identity = this.candidatesOf(String(s.username || ''));
    if (!identity || !identity.uid.length) {
      log.debug("Leaving SshUserCa.issue(). No UID.");
      return this.refuse('STS-PKI-0294',
        'The caller has no directory UID for an SSH principal.');
    }
    const publicKey = String(s.publicKey || '').trim();
    const key = certificate.parseSshAuthorizedKey(publicKey);
    if (!key || key.certType || /[\r\n]/.test(publicKey) ||
        publicKey.split(/\s+/)[0] !== key.type) {
      log.debug("Leaving SshUserCa.issue(). Invalid public key.");
      return this.refuse('STS-PKI-0289',
        'Provide one supported OpenSSH public key, not a certificate.');
    }
    const principals = Array.isArray(s.principals) ? s.principals : [];
    if (!principals.length || principals.length > 32 ||
        principals.some(function (one: Json): boolean {
          return typeof one !== 'string' || one.length > 256 ||
            identity.names.indexOf(one) < 0;
        }) || new Set(principals).size !== principals.length) {
      log.debug("Leaving SshUserCa.issue(). Invalid principals.");
      return this.refuse('STS-PKI-0294',
        'Each principal must be the caller\'s UID or one of their group ' +
        'common names, with no duplicates.');
    }
    for (let i = 0; i < principals.length; i++) {
      const decision = gate.check({
        resource: gate.RESOURCE.SSH_USER_CA,
        action: gate.ACTION.ISSUE_SSH_PRINCIPAL,
        subject: { name: s.username, authenticated: true, sub: s.subject },
        owner: s.username, sshPrincipal: principals[i],
        context: { method: 'POST', path: '/account-api/ssh/certificates' }
      });
      if (!decision.allowed) {
        log.info('ssh-user-ca: policy refused principal ' +
                 JSON.stringify(principals[i]) + ' for ' + s.username +
                 ': ' + decision.why);
        log.debug("Leaving SshUserCa.issue(). Policy refused.");
        return this.refuse('STS-PKI-0294',
          'The access policy did not permit principal "' + principals[i] +
          '".');
      }
    }
    let hardwareEvidence: Json = null;
    if (key.sk) {
      hardwareEvidence = await this.securityKeyEvidence(
        key, String(s.attestation || ''));
      if (!hardwareEvidence) {
        log.debug("Leaving SshUserCa.issue(). Unverified security key.");
        return this.refuse('STS-PKI-0294',
          'The security-key attestation did not verify.');
      }
      hardwareEvidence.source = 'ssh-security-key-attestation';
    } else {
      const piv = await this.pivEvidenceFor(String(s.username), key);
      if (piv) {
        hardwareEvidence = Object.assign({ source: 'piv-attestation' }, piv);
      }
    }
    const lifetimeS = Number(s.lifetimeS || SOFTWARE_LIFETIME_S);
    const maximum = hardwareEvidence ? HARDWARE_LIFETIME_S
                                    : SOFTWARE_LIFETIME_S;
    if (!Number.isInteger(lifetimeS) || lifetimeS < 60 ||
        lifetimeS > maximum) {
      log.debug("Leaving SshUserCa.issue(). Lifetime.");
      return this.refuse('STS-PKI-0289',
        'The requested lifetime exceeds the limit for this key\'s evidence.');
    }
    const fingerprint = certificate.sshFingerprint(key);
    const issued = await certificate.issueSshUserCertificateAsync(s.realm, {
      subjectBlob: key.blob, principals: principals,
      ownerSubject: String(s.subject || ''), lifetimeS: lifetimeS,
      hardwareBound: !!hardwareEvidence
    });
    if (!issued || !issued.ok) {
      log.debug("Leaving SshUserCa.issue(). PKI refused.");
      return issued;
    }
    if (hardwareEvidence) {
      const recorded = this.recordHardwareCredential(
        String(s.username), fingerprint, hardwareEvidence);
      if (!recorded || !recorded.ok) {
        await certificate.revokeSshUserCertificateAsync(
          s.realm, issued.serialHex, String(s.subject || ''));
        log.debug("Leaving SshUserCa.issue(). Hardware registration failed.");
        return this.refuse('STS-PKI-0294',
          'The hardware evidence could not be recorded for lost-token ' +
          'revocation.');
      }
    }
    eventLog.record({
      category: 'authentication', action: 'ssh-user-ca.issue',
      actor: String(s.username), target: String(s.username),
      outcome: 'success',
      summary: String(s.username) + ' issued an SSH user certificate',
      detail: { serialHex: issued.serialHex, principals: principals,
                keyFingerprint: fingerprint,
                hardwareBound: !!hardwareEvidence,
                lifetimeS: lifetimeS }
    });
    log.debug("Leaving SshUserCa.issue(). Issued.");
    return { ok: true, certificate: issued.line,
             serialHex: issued.serialHex, validAfter: issued.validAfter,
             validBefore: issued.validBefore,
             hardwareBound: !!hardwareEvidence };
  }

  /**
   * Revokes a caller's SSH certificate by its serial.
   *
   * @param realm - the realm
   * @param subject - the token subject
   * @param serialHex - the certificate serial
   * @returns the revocation answer
   */
  async revoke(realm: string, subject: string,
               serialHex: string): Promise<Json> {
    const { log, pki: certificate } = this.deps;
    log.debug("Entering SshUserCa.revoke().");
    const answer = await certificate.revokeSshUserCertificateAsync(
      realm, serialHex, subject);
    log.debug("Leaving SshUserCa.revoke(). " +
              (answer && answer.ok ? 'Revoked.' : 'Refused.'));
    return answer;
  }

  /**
   * Revokes all certificates for a lost hardware credential.
   *
   * @param token - the lost token
   * @param credential - the SSH credential on it
   * @param context - the lost-token operation's context
   * @returns the KRL revocation result
   */
  async retireLost(token: Json, credential: Json,
                   context: Json): Promise<Json> {
    const { log, pki: certificate } = this.deps;
    log.debug("Entering SshUserCa.retireLost().");
    const answer = await certificate.revokeSshUserKeyAsync(
      String((context && context.realm) || ''),
      String((credential && credential.ref) || ''));
    log.debug("Leaving SshUserCa.retireLost(). " +
              (answer && answer.ok ? 'Retired.' : 'Failed.'));
    return answer && answer.ok ? { ok: true, revoked: answer.revoked }
                               : answer;
  }

  /**
   * Installs the lost-token retirer.
   *
   * @param tokens - the hardware-token register
   * @returns true if installed
   */
  installRetirer(tokens: Json): boolean {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering SshUserCa.installRetirer().");
    const installed = !!tokens && typeof tokens.registerRetirer === 'function' &&
      tokens.registerRetirer('ssh', {
        label: 'SSH user key',
        retire: function (token: Json, credential: Json,
                         context: Json): Promise<Json> {
          return self.retireLost(token, credential, context);
        }
      }) === true;
    log.debug("Leaving SshUserCa.installRetirer(). " + installed);
    return installed;
  }

  /**
   * Registers the periodic KRL refresh job.
   *
   * @param schedulerInstance - the cluster scheduler
   * @returns true if registered
   */
  static installScheduler(schedulerInstance?: Json): boolean {
    helpers.log.debug("Entering SshUserCa.installScheduler().");
    const scheduler = schedulerInstance || require('../cluster/scheduler');
    if (scheduler.job(KRL_JOB)) {
      helpers.log.debug("Leaving SshUserCa.installScheduler(). Already.");
      return false;
    }
    scheduler.register({
      id: KRL_JOB, title: 'SSH user CA revocation list',
      describe: 'Refreshes each realm\'s OpenSSH user CA KRL after issued ' +
        'certificate revocations and removes expired revocations.',
      owner: 'common/ssh_user_ca.ts', kind: 'cluster', scope: 'realm',
      everyMs: function (): number {
        return KRL_EVERY_MS;
      },
      manual: true, timeoutS: 120,
      run: async function (ctx: Json): Promise<Json> {
        const answer = await pki.buildSshUserKrlAsync(String(ctx.realm || ''));
        return answer === null ? { ok: true, skipped: true }
                               : (answer && answer.ok ? { ok: true } : answer);
      }
    });
    helpers.log.debug("Leaving SshUserCa.installScheduler().");
    return true;
  }
}

const slot = new InstanceSlot<SshUserCa>(
  'common/ssh_user_ca',
  () => new SshUserCa(SshUserCa.defaultDeps()),
  function (instance: SshUserCa): void {
    instance.installRetirer(hardwareTokens);
  },
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The realm's OpenSSH user CA issuance policy and hardware-token retirer.
 * @namespace
 */
export = {
  SshUserCa: SshUserCa,
  installInstance: (instance: SshUserCa): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  installScheduler: SshUserCa.installScheduler,
  issue: slot.forward('issue'),
  revoke: slot.forward('revoke')
};
