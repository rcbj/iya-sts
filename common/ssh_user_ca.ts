// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: ssh_user_ca.ts
//
// ---------------------------------------------------------------------------
// THE REALM'S OPENSSH USER CA (#1955 P3). The PKI row owns its key; the
// certificates it issued are a register of their own (`ssh_issued.ts`,
// since the #1955 review). This module owns the decision to issue:
// principals come only from the caller's directory entry, each is a
// separate XACML request, and only verified security-key or PIV evidence
// earns the longer lifetime. The hardware-token register's lost-token act
// calls back here through its validated retirer hook, which revokes every
// certificate for that key before the scheduler rebuilds the KRL.
//
// **WHAT THE #1955 REVIEW CHANGED**, each a gap it found:
//
//   * **A GROUP IS NOT A PRINCIPAL BY BEING A GROUP** (the *does not do*
//     row "Let a group grant anything BY BEING A GROUP"). Every group a
//     person was in used to be a principal they could ask for, and the
//     default policy permitted it. Now only the groups
//     `pki.sshGroupPrincipals` names (empty, none, by default) are offered,
//     each still decided by the policy, which is told the principal's kind
//     (`sshPrincipalKind`, `uid` or `group`). A group whose name is a
//     person's uid in the realm, or a system account (`RESERVED`), is never
//     a principal (STS-SSHCA-0002): an `sshd` mapping principals to
//     accounts would sign the member in as that person, or as root.
//   * **A SECURITY KEY'S ATTESTATION IS VERIFIED AS FIDO SIGNED IT**: over
//     `authenticatorData || clientDataHash`, where the client data hash is
//     SHA-256 of the challenge `ssh-keygen` was given (`-O challenge=`), or
//     the challenge itself for an older libfido2 that took it as the hash.
//     The signature over the authenticator data alone verified no real key.
//     It goes through the WebAuthn attestation verifier
//     (`authn/webauthn_attestation.ts`, `packed`), so the realm's anchors and
//     the FIDO Metadata Service decide trust exactly as they do for a
//     passkey. An attestation sent without its challenge is refused
//     (STS-SSHCA-0003). An `sk-` key with no attestation, or one that
//     verifies and is not trusted, is issued the SOFTWARE lifetime, as the
//     documentation always said, rather than refused.
//   * **A TOKEN IS RECORDED ONLY FROM A SERIAL THE ATTESTATION NAMES**: the
//     "serial" was the SHA-256 of the batch attestation certificate, one
//     value for every key of a model. A key whose attestation names no
//     device serial keeps its evidence on its issued row only.
//   * **THE LIFETIMES ARE SETTINGS** (`pki.sshSoftwareLifetimeSeconds`,
//     `pki.sshHardwareLifetimeSeconds`, the old constants as defaults), and
//     a certificate carries the realm's extensions
//     (`pki.sshUserCertificateExtensions`, `pki.js`).
//   * **THE ML-DSA CERTIFICATE `pki.sshUserCaPqcAlongsideClassical` ISSUES
//     IS RETURNED** beside the classical one, and revoked with it when the
//     hardware evidence cannot be recorded.
//   * **A PERSON'S CERTIFICATES CAN BE LISTED**, by them and by an
//     administrator, and an administrator can revoke one (rule 7) and,
//     since #2071, issue one (`adminIssue()`, through `issue()`).
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

// The defaults of the two lifetime settings: what the code held until the
// #1955 review.
const SOFTWARE_LIFETIME_S = 300;
const HARDWARE_LIFETIME_S = 3600;
const KRL_JOB = 'ssh-user-ca.krl';
const KRL_EVERY_MS = 5 * 60 * 1000;

// Names that are never a GROUP principal (header): the system accounts a
// Unix host has, whose certificate would be a root shell or a service's.
const RESERVED = ['root', 'toor', 'daemon', 'bin', 'sys', 'sync', 'adm',
                  'admin', 'administrator', 'wheel', 'sudo', 'sshd',
                  'nobody', 'operator', 'halt', 'shutdown', 'mail', 'lp',
                  'www-data', 'backup', 'man', 'games', 'news', 'uucp',
                  'proxy', 'list', 'irc', 'postgres', 'systemd-network'];

// The largest challenge accepted beside an attestation: `ssh-keygen`
// writes 32 random bytes unless given a file.
const MAX_CHALLENGE = 1024;

const BASE64 =
  /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

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
  // The WebAuthn attestation verifier, reached at the moment of use (it
  // loads the FIDO metadata lazily itself).
  attestation?(): Json;
  // A person's subject by name.
  subjectFor?(username: string): string;
}

/**
 * Issues certificates from a realm's OpenSSH user CA.
 */
class SshUserCa {
  static readonly RESERVED = RESERVED;

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
      },
      attestation: function (): Json {
        return require('../authn/webauthn_attestation');
      },
      subjectFor: function (username: string): string {
        return String(helpers.subjectForName(username) || '');
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

  // A setting, or its default where the configuration cannot be asked (a
  // test's stub).
  private setting(key: string, dflt: Json): Json {
    const { log, config: cfg } = this.deps;
    log.debug("Entering SshUserCa.setting(). " + key);
    let value: Json = dflt;
    try {
      const got = cfg && typeof cfg.value === 'function'
        ? cfg.value(key) : undefined;
      value = got === undefined || got === null ? dflt : got;
    } catch (e) {
      log.debug("Caught in SshUserCa.setting(): " + ((e && e.message) || e));
      value = dflt;
    }
    log.debug("Leaving SshUserCa.setting().");
    return value;
  }

  private listSetting(key: string): string[] {
    const { log } = this.deps;
    log.debug("Entering SshUserCa.listSetting(). " + key);
    const raw = this.setting(key, '');
    const out = (Array.isArray(raw) ? raw : String(raw || '').split(','))
      .map(function (one: unknown): string {
        return String(one).trim();
      }).filter(Boolean);
    log.debug("Leaving SshUserCa.listSetting(). " + out.length);
    return out;
  }

  /**
   * The two lifetimes, in seconds: without and with hardware evidence.
   *
   * @returns `{ software, hardware }`
   */
  lifetimes(): { software: number; hardware: number } {
    const { log } = this.deps;
    log.debug("Entering SshUserCa.lifetimes().");
    const bound = function (value: Json, dflt: number): number {
      const n = Math.floor(Number(value));
      return Number.isFinite(n) && n >= 60 && n <= HARDWARE_LIFETIME_S
        ? n : dflt;
    };
    const out = {
      software: bound(this.setting('pki.sshSoftwareLifetimeSeconds',
                                   SOFTWARE_LIFETIME_S), SOFTWARE_LIFETIME_S),
      hardware: bound(this.setting('pki.sshHardwareLifetimeSeconds',
                                   HARDWARE_LIFETIME_S), HARDWARE_LIFETIME_S)
    };
    log.debug("Leaving SshUserCa.lifetimes(). " + out.software + '/' +
              out.hardware);
    return out;
  }

  // THE PRINCIPALS A PERSON MAY ASK FOR (header): their uid, and the groups
  // `pki.sshGroupPrincipals` names that they are in, less any group whose
  // name is a person's uid or reserved.
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
    const offered = this.listSetting('pki.sshGroupPrincipals')
      .map(function (one: string): string {
        return one.toLowerCase();
      });
    const groups = offered.length ? ldap.groupsOfUser(entry.dn) : null;
    const groupCns = (groups && groups.entryFound ? groups.groups : [])
      .map(function (one: Json): string {
        return String((one && one.cn) || '').trim();
      }).filter(function (one: string): boolean {
        return !!one && offered.indexOf(one.toLowerCase()) >= 0;
      });
    const allowedGroups: string[] = [];
    const refusedGroups: string[] = [];
    groupCns.forEach(function (cn: string): void {
      let personsName = false;
      try {
        personsName = !!ldap.existingUserEntry(cn);
      } catch (e) {
        log.debug("Caught in SshUserCa.candidatesOf(): " +
                  ((e && e.message) || e));
        // A name that cannot be checked is not offered.
        personsName = true;
      }
      if (personsName || RESERVED.indexOf(cn.toLowerCase()) >= 0 ||
          uid.indexOf(cn) >= 0) {
        refusedGroups.push(cn);
      } else if (allowedGroups.indexOf(cn) < 0) {
        allowedGroups.push(cn);
      }
    });
    log.debug("Leaving SshUserCa.candidatesOf(). " + uid.length +
              " uid(s), " + allowedGroups.length + " group(s).");
    return { entry: entry, uid: uid, groups: allowedGroups,
             refusedGroups: refusedGroups,
             names: Array.from(new Set(uid.concat(allowedGroups))) };
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
      // By the certificate itself and for this person only (the #1955
      // review): a serial alone names a certificate of any issuer.
      const evidence = tokens.certificateEvidence({ der: der, serial: serial,
                                                    username: username });
      if (evidence.hardware === true &&
          evidence.source === 'piv-attestation' && evidence.token) {
        log.debug("Leaving SshUserCa.pivEvidenceFor(). PIV.");
        return { token: String(evidence.token), serial: serial };
      }
    }
    log.debug("Leaving SshUserCa.pivEvidenceFor(). None.");
    return null;
  }

  // The COSE algorithm a `packed` statement's x5c signs with, from the
  // attestation certificate's key: what the statement would have said.
  private static statementAlg(publicKey: Json): number {
    helpers.log.debug("Entering SshUserCa.statementAlg().");
    const type = String((publicKey && publicKey.asymmetricKeyType) || '');
    const curve = String(((publicKey && publicKey.asymmetricKeyDetails) ||
                          {}).namedCurve || '');
    const out = type === 'ed25519' ? -8
      : (type === 'ec' && curve === 'secp384r1' ? -35
        : (type === 'ec' && curve === 'secp521r1' ? -36
          : (type === 'rsa' ? -257 : -7)));
    helpers.log.debug("Leaving SshUserCa.statementAlg(). " + out);
    return out;
  }

  // The challenge sent beside an attestation, or an empty buffer.
  private static challengeOf(given: unknown): Buffer {
    helpers.log.debug("Entering SshUserCa.challengeOf().");
    const text = String(given || '');
    const out = text && text.length <= 2 * MAX_CHALLENGE && BASE64.test(text)
      ? Buffer.from(text, 'base64') : Buffer.alloc(0);
    helpers.log.debug("Leaving SshUserCa.challengeOf(). " + out.length);
    return out.length <= MAX_CHALLENGE ? out : Buffer.alloc(0);
  }

  // -------------------------------------------------------------------------
  // A SECURITY KEY'S ATTESTATION (header). Answers `{ state }`: `verified`
  // (trusted; `evidence` carries what it says), `untrusted` (it verified,
  // or the policy checks none, and nothing vouches for it: the software
  // lifetime), or `invalid` with a refusal.
  // -------------------------------------------------------------------------
  private async securityKeyEvidence(key: Json, encoded: string,
                                    challengeB64: string): Promise<Json> {
    const { log, pki: certificate, crypto, webauthn } = this.deps;
    log.debug("Entering SshUserCa.securityKeyEvidence().");
    const invalid = (code: string, why: string): Json => {
      log.debug("Leaving SshUserCa.securityKeyEvidence(). " + why);
      return { state: 'invalid', refusal: this.refuse(code, why) };
    };
    if (!encoded || encoded.length > 87384 || !BASE64.test(encoded)) {
      return invalid('STS-PKI-0294', 'The security-key attestation is not ' +
                     'base64 of an ssh-keygen attestation file.');
    }
    const challenge = SshUserCa.challengeOf(challengeB64);
    if (!challenge.length) {
      return invalid('STS-SSHCA-0003', 'A security-key attestation is ' +
        'checked against the challenge ssh-keygen was given (-O ' +
        'challenge=<file>), and none was sent: send the file\'s bytes, ' +
        'base64, as attestationChallenge.');
    }
    let attestation: Json;
    let authData: Json;
    let cert: Json;
    let cose: Json;
    try {
      const bytes = Buffer.from(encoded, 'base64');
      if (!bytes.length || bytes.length > 65536) {
        return invalid('STS-PKI-0294', 'The security-key attestation is ' +
                       'empty or too large.');
      }
      attestation = certificate.parseSshSkAttestation(bytes);
      authData = webauthn().parseAuthenticatorData(
        Buffer.from(attestation.authData));
      cert = certificate.certificateFromDer(attestation.certificate);
      cose = authData.credentialPublicKey;
    } catch (e) {
      log.debug("Caught in SshUserCa.securityKeyEvidence(): " +
                ((e && e.message) || e));
      return invalid('STS-PKI-0294', 'The security-key attestation could ' +
                     'not be read.');
    }
    let credentialJwk: Json = null;
    try {
      credentialJwk = cose ? webauthn().coseKeyToJwk(cose).jwk : null;
    } catch (e) {
      log.debug("Caught in SshUserCa.securityKeyEvidence(): " +
                ((e && e.message) || e));
      credentialJwk = null;
    }
    if (!cert || !authData.flags || !authData.flags.at ||
        !authData.flags.up || !credentialJwk || !key.application ||
        !Buffer.from(authData.rpIdHash).equals(
          crypto.digest('sha256', key.application)) ||
        !certificate.sshKeyMatches(key, crypto.publicKeyOf(credentialJwk))) {
      return invalid('STS-PKI-0294', 'The security-key attestation is not ' +
                     'of this key, or of this application.');
    }
    // THE CLIENT DATA HASH (header): SHA-256 of the challenge, as libfido2
    // 1.8 and later compute it, then the challenge itself where it is 32
    // bytes, as an older libfido2 took it.
    const hashes = [crypto.digest('sha256', challenge)];
    if (challenge.length === 32) {
      hashes.push(Buffer.from(challenge));
    }
    const verifier = this.deps.attestation ? this.deps.attestation() : null;
    let assessed: Json = null;
    for (const clientDataHash of hashes) {
      const verdict = {
        fmt: 'packed',
        attStmt: { alg: SshUserCa.statementAlg(cert.x509.publicKey),
                   sig: Buffer.from(attestation.signature),
                   x5c: [Buffer.from(attestation.certificate)] },
        authDataRaw: Buffer.from(attestation.authData),
        clientDataHash: clientDataHash,
        credentialPublicKeyCose: cose,
        coseAlg: Number(cose.get(3)),
        publicKeyJwk: credentialJwk,
        aaguid: Buffer.from(authData.aaguid || []).toString('hex'),
        credentialIdRaw: Buffer.from(authData.credentialId || []),
        rpIdHash: Buffer.from(authData.rpIdHash)
      };
      try {
        assessed = verifier ? await verifier.assess(verdict) : null;
      } catch (e) {
        log.debug("Caught in SshUserCa.securityKeyEvidence(): " +
                  ((e && e.message) || e));
        assessed = null;
      }
      if (assessed && assessed.ok) {
        break;
      }
    }
    if (!assessed || !assessed.ok) {
      return invalid('STS-PKI-0294', 'The security-key attestation did ' +
        'not verify' + (assessed && assessed.why
          ? ': ' + String(assessed.why) : '.'));
    }
    const facts = assessed.attestation || {};
    if (facts.verified !== true || facts.trusted !== true) {
      log.debug("Leaving SshUserCa.securityKeyEvidence(). Not trusted.");
      return { state: 'untrusted' };
    }
    // A DEVICE SERIAL ONLY WHERE THE TRUSTED CERTIFICATE NAMES ONE (header).
    let serial: Json = facts.deviceSerial
      ? { serial: String(facts.deviceSerial),
          source: String(facts.deviceSerialSource || '') } : null;
    if (!serial) {
      serial = certificate.attestationDeviceSerial(attestation.certificate);
    }
    log.debug("Leaving SshUserCa.securityKeyEvidence(). Verified" +
              (serial ? ', serial ' + serial.serial : ', no serial') + ".");
    return {
      state: 'verified',
      evidence: {
        source: 'ssh-security-key-attestation',
        vendor: hardwareTokens.HardwareTokens.fidoVendor({
          deviceSerialSource: serial ? serial.source : '',
          model: String(facts.model || ''),
          aaguid: String(facts.aaguid || '') }),
        serial: serial ? String(serial.serial) : '',
        model: String(facts.model || ''),
        format: String(attestation.version || '')
      }
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
        serial: evidence.serial, model: evidence.model,
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
   *   attestation, attestationChallenge }`, and from `adminIssue()` the
   *   `actor`, `via` and the policy's `contextPath`
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
    const refusedGroup = principals.filter(function (one: Json): boolean {
      return identity.refusedGroups.indexOf(one) >= 0;
    })[0];
    if (refusedGroup) {
      log.info('ssh-user-ca: group principal ' + JSON.stringify(refusedGroup) +
               ' was refused for ' + s.username + ': it is a person\'s uid ' +
               'or a reserved account name.');
      log.debug("Leaving SshUserCa.issue(). A reserved group name.");
      return this.refuse('STS-SSHCA-0002', 'The group "' + refusedGroup +
        '" cannot be an SSH principal: its name is a person\'s uid in this ' +
        'realm or a system account, which a server would sign you in as.');
    }
    if (!principals.length || principals.length > 32 ||
        principals.some(function (one: Json): boolean {
          return typeof one !== 'string' || one.length > 256 ||
            identity.names.indexOf(one) < 0;
        }) || new Set(principals).size !== principals.length) {
      log.debug("Leaving SshUserCa.issue(). Invalid principals.");
      return this.refuse('STS-PKI-0294',
        'Each principal must be the caller\'s UID, or a group of theirs ' +
        'this realm offers as a principal (pki.sshGroupPrincipals), with ' +
        'no duplicates.');
    }
    for (let i = 0; i < principals.length; i++) {
      const decision = gate.check({
        resource: gate.RESOURCE.SSH_USER_CA,
        action: gate.ACTION.ISSUE_SSH_PRINCIPAL,
        subject: { name: s.username, authenticated: true, sub: s.subject },
        owner: s.username, sshPrincipal: principals[i],
        sshPrincipalKind: identity.uid.indexOf(principals[i]) >= 0
          ? 'uid' : 'group',
        context: { method: 'POST',
                   path: String(s.contextPath ||
                                '/account-api/ssh/certificates') }
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
    if (key.sk && s.attestation) {
      const checked = await this.securityKeyEvidence(
        key, String(s.attestation || ''),
        String(s.attestationChallenge || ''));
      if (checked.state === 'invalid') {
        log.debug("Leaving SshUserCa.issue(). Unverified security key.");
        return checked.refusal;
      }
      hardwareEvidence = checked.state === 'verified' ? checked.evidence
                                                       : null;
    } else if (!key.sk) {
      const piv = await this.pivEvidenceFor(String(s.username), key);
      if (piv) {
        hardwareEvidence = Object.assign({ source: 'piv-attestation' }, piv);
      }
    }
    const limits = this.lifetimes();
    const lifetimeS = Number(s.lifetimeS || limits.software);
    const maximum = hardwareEvidence ? limits.hardware : limits.software;
    if (!Number.isInteger(lifetimeS) || lifetimeS < 60 ||
        lifetimeS > maximum) {
      log.debug("Leaving SshUserCa.issue(). Lifetime.");
      return this.refuse('STS-PKI-0289',
        'The requested lifetime exceeds the limit for this key\'s evidence (' +
        maximum + ' seconds).');
    }
    const fingerprint = certificate.sshFingerprint(key);
    const issued = await certificate.issueSshUserCertificateAsync(s.realm, {
      subjectBlob: key.blob, principals: principals,
      ownerSubject: String(s.subject || ''), lifetimeS: lifetimeS,
      hardwareBound: !!hardwareEvidence,
      evidence: hardwareEvidence ? String(hardwareEvidence.source) : ''
    });
    if (!issued || !issued.ok) {
      log.debug("Leaving SshUserCa.issue(). PKI refused.");
      return issued;
    }
    // A TOKEN ONLY WHERE THERE IS ONE (header): a PIV key's, which its
    // certificate's attestation recorded, or a security key's whose trusted
    // attestation named a device serial.
    const tokenOwed = !!hardwareEvidence &&
      (hardwareEvidence.source === 'piv-attestation' ||
       !!hardwareEvidence.serial);
    if (tokenOwed) {
      const recorded = this.recordHardwareCredential(
        String(s.username), fingerprint, hardwareEvidence);
      if (!recorded || !recorded.ok) {
        // EVERY CERTIFICATE THE ISSUANCE MADE GOES (the #1955 review): the
        // ML-DSA one beside the classical too, or a lost token would leave
        // it live.
        const serials = [issued.serialHex, issued.pqcSerialHex]
          .filter(function (one: Json, index: number,
                            all: Json[]): boolean {
            return !!one && all.indexOf(one) === index;
          });
        for (const serial of serials) {
          await certificate.revokeSshUserCertificateAsync(
            s.realm, serial, String(s.subject || ''));
        }
        log.debug("Leaving SshUserCa.issue(). Hardware registration failed.");
        return this.refuse('STS-PKI-0294',
          'The hardware evidence could not be recorded for lost-token ' +
          'revocation.');
      }
    }
    // WHO ISSUED IT: the person on their own door, or the administrator
    // `adminIssue()` names (#2071), whose row says so and by which door.
    const actor = String(s.actor || s.username);
    const byOther = actor !== String(s.username);
    eventLog.record({
      category: 'authentication', action: 'ssh-user-ca.issue',
      actor: actor, target: String(s.username),
      outcome: 'success',
      summary: byOther
        ? 'An administrator issued an SSH user certificate to ' +
          String(s.username)
        : String(s.username) + ' issued an SSH user certificate',
      detail: { serialHex: issued.serialHex,
                pqcSerialHex: issued.pqcSerialHex || undefined,
                principals: principals,
                keyFingerprint: fingerprint,
                hardwareBound: !!hardwareEvidence,
                lifetimeS: lifetimeS,
                via: s.via ? String(s.via) : undefined }
    });
    log.debug("Leaving SshUserCa.issue(). Issued.");
    const out: Json = { ok: true, certificate: issued.line,
                        serialHex: issued.serialHex,
                        validAfter: issued.validAfter,
                        validBefore: issued.validBefore,
                        hardwareBound: !!hardwareEvidence };
    // THE ML-DSA CERTIFICATE (the #1955 review), where the realm issues one
    // beside the classical one.
    if (issued.pqcLine && issued.pqcSerialHex &&
        issued.pqcSerialHex !== issued.serialHex) {
      out.pqcCertificate = String(issued.pqcLine);
      out.pqcSerialHex = String(issued.pqcSerialHex);
    }
    return out;
  }

  // -------------------------------------------------------------------------
  // AN ADMINISTRATOR ISSUES A PERSON'S CERTIFICATE (#2071, rule 7): the same
  // core the person's own door (`account-api/ssh_user_ca.ts`) calls, so the
  // principals still come only from the person's entry, each is still the
  // policy's question about THEM, the lifetime still follows the key's
  // evidence, and the certificate is written onto their entry
  // (`stsSshUserCertificate`, the master copy) through the register before
  // it is answered. What differs is who is named: the person by `username`,
  // their subject read here, and the actor the administrator — the caller's
  // own, or the ambient source's (`audit.currentActor()`, the API token's
  // subject) — never the person.
  // -------------------------------------------------------------------------
  /**
   * Issues an SSH user certificate to a named person for an administrator.
   *
   * @param spec - `{ realm, username, publicKey, principals?, lifetimeS?,
   *   attestation?, attestationChallenge?, actor?, via? }`; no principals
   *   is the person's uid
   * @returns a promise of the issued certificate, or a marked refusal
   */
  async adminIssue(spec: Json): Promise<Json> {
    const { log, audit: eventLog } = this.deps;
    log.debug("Entering SshUserCa.adminIssue().");
    const s = spec || {};
    const username = String(s.username || '').trim();
    const subject = username && this.deps.subjectFor
      ? this.deps.subjectFor(username) : '';
    let actor = String(s.actor || '');
    if (!actor) {
      try {
        actor = String((eventLog as Json).currentActor() || '');
      } catch (e) {
        log.debug("Caught in SshUserCa.adminIssue(): " +
                  ((e && e.message) || e));
        actor = '';
      }
    }
    if (!subject) {
      eventLog.record({
        category: 'authentication', action: 'ssh-user-ca.issue',
        actor: actor, target: username.slice(0, 64), outcome: 'refused',
        summary: 'An administrator could not issue an SSH user ' +
                 'certificate: nobody of that name',
        detail: { via: String(s.via || '') }, errorCode: 'STS-SSHCA-0004'
      });
      log.debug("Leaving SshUserCa.adminIssue(). Nobody.");
      return this.refuse('STS-SSHCA-0004', 'There is nobody called "' +
        username.slice(0, 64) + '" in this realm\'s directory.');
    }
    let principals: Json[] = Array.isArray(s.principals)
      ? s.principals.map(function (one: Json): string {
        return String(one).trim();
      }).filter(Boolean) : [];
    if (!principals.length) {
      const identity = this.candidatesOf(username);
      principals = identity && identity.uid.length ? [identity.uid[0]] : [];
    }
    const answer = await this.issue({
      realm: s.realm, username: username, subject: subject,
      publicKey: s.publicKey, principals: principals,
      lifetimeS: s.lifetimeS, attestation: s.attestation,
      attestationChallenge: s.attestationChallenge,
      actor: actor || 'unknown: an administrator\'s SSH issuance',
      via: String(s.via || 'api'),
      contextPath: '/admin-api/hardware-tokens/issue-ssh'
    });
    if (!answer || !answer.ok) {
      eventLog.record({
        category: 'authentication', action: 'ssh-user-ca.issue',
        actor: actor, target: username, outcome: 'refused',
        summary: 'An administrator could not issue an SSH user ' +
                 'certificate to ' + username,
        detail: { via: String(s.via || '') },
        errorCode: String(this.deps.errorCodes.codeOf(answer) ||
                          'STS-PKI-0290')
      });
    }
    log.debug("Leaving SshUserCa.adminIssue(). " +
              (answer && answer.ok ? 'Issued.' : 'Refused.'));
    return answer;
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

  // One issued row as a page or an API answer draws it: never a key.
  private static view(row: Json): Json {
    helpers.log.debug("Entering SshUserCa.view().");
    const r = row || {};
    helpers.log.debug("Leaving SshUserCa.view().");
    return {
      serialHex: String(r.serialHex || ''), keyType: String(r.keyType || ''),
      keyFingerprint: String(r.keyFingerprint || ''),
      principals: Array.isArray(r.principals) ? r.principals.map(String) : [],
      issuedAt: String(r.issuedAt || ''), notAfter: String(r.notAfter || ''),
      hardwareBound: r.hardwareBound === true,
      authority: r.caMember === 'sshUserCaPqc' ? 'ssh-mldsa-65'
                                               : 'classical',
      revoked: !!r.revokedAt, revokedAt: String(r.revokedAt || '')
    };
  }

  /**
   * The certificates of a token subject that have not expired, newest
   * first.
   *
   * @param realm - the realm
   * @param subject - the person's subject
   * @returns a promise of the rows as drawn
   */
  async certificatesOf(realm: string, subject: string): Promise<Json[]> {
    const { log, pki: certificate } = this.deps;
    log.debug("Entering SshUserCa.certificatesOf().");
    const rows = subject
      ? await certificate.sshUserCertificatesOfAsync(realm, subject) : [];
    log.debug("Leaving SshUserCa.certificatesOf(). " + rows.length);
    return rows.map(SshUserCa.view);
  }

  /**
   * A person's certificates by name, for an administrator (rule 7).
   *
   * @param realm - the realm
   * @param username - the person
   * @returns a promise of the rows as drawn, [] for nobody
   */
  async certificatesOfPerson(realm: string, username: string):
      Promise<Json[]> {
    const { log } = this.deps;
    log.debug("Entering SshUserCa.certificatesOfPerson().");
    const subject = username && this.deps.subjectFor
      ? this.deps.subjectFor(String(username)) : '';
    const out = subject ? await this.certificatesOf(realm, subject) : [];
    log.debug("Leaving SshUserCa.certificatesOfPerson(). " + out.length);
    return out;
  }

  /**
   * An administrator revokes a person's certificate (rule 7): the serial
   * must be that person's.
   *
   * @param spec - `{ realm, username, serialHex, actor, via }`
   * @returns a promise of `{ ok, serialHex }`, or a refusal
   */
  async adminRevoke(spec: Json): Promise<Json> {
    const { log, pki: certificate, audit: eventLog } = this.deps;
    log.debug("Entering SshUserCa.adminRevoke().");
    const s = spec || {};
    const username = String(s.username || '').trim();
    const subject = username && this.deps.subjectFor
      ? this.deps.subjectFor(username) : '';
    if (!subject) {
      log.debug("Leaving SshUserCa.adminRevoke(). Nobody.");
      return this.refuse('STS-SSHCA-0004', 'There is nobody called "' +
        username.slice(0, 64) + '" in this realm\'s directory.');
    }
    const answer = await certificate.revokeSshUserCertificateAsync(
      s.realm, String(s.serialHex || ''), subject);
    const ok = !!(answer && answer.ok);
    eventLog.record(Object.assign({
      category: 'authentication', action: 'ssh-user-ca.revoke',
      actor: String(s.actor || ''), target: username,
      outcome: ok ? 'success' : 'refused',
      summary: (ok ? 'An administrator revoked'
                   : 'An administrator could not revoke') +
               ' an SSH user certificate of ' + username,
      detail: { serialHex: String(s.serialHex || '').slice(0, 16),
                via: String(s.via || '') }
    }, ok ? {} : { errorCode: String(this.deps.errorCodes.codeOf(answer) ||
                                     'STS-PKI-0291') }));
    log.debug("Leaving SshUserCa.adminRevoke(). " +
              (ok ? 'Revoked.' : 'Refused.'));
    return ok
      ? { ok: true, serialHex: String(s.serialHex || '').toLowerCase()
            .replace(/^0+(?=.)/, '') }
      : answer;
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
  revoke: slot.forward('revoke'),
  lifetimes: slot.forward('lifetimes'),
  certificatesOf: slot.forward('certificatesOf'),
  certificatesOfPerson: slot.forward('certificatesOfPerson'),
  adminRevoke: slot.forward('adminRevoke'),
  adminIssue: slot.forward('adminIssue')
};
