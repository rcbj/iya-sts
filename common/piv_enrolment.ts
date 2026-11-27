// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: piv_enrolment.ts
//
// ===========================================================================
// THE PIV ENROLMENT FORM AND THE ESCROWED KEY-MANAGEMENT KEYS (#1955 P2,
// design S1's second carrier, and decision D7).
//
// **THE FORM** is the second way a PIV attestation reaches certificate
// enrolment (`common/piv_attestation.ts` argues the first, the request's own
// attribute). A person on the PIV tab of Tokens and keys
// (`/portal/tokens-and-keys`), or an
// administrator on Directory → Hardware tokens or `POST
// /admin-api/hardware-tokens/enrol-piv` (rule 7, parity), pastes three PEM
// texts: the certificate request from `ykman piv keys generate` + `ykman piv
// certificates request`, the slot's attestation certificate (`ykman piv keys
// attest`), and the f9 attestation certificate (`ykman piv certificates
// export f9`). `enrol()` reads the request as EST does (`parseCsr()`: the
// proof of possession, the key's size) and issues through the one core,
// `cert_enrollment.issue()`, over the EST family's Issuing CA, so the
// profile is held to `est.allowedProfiles` and the attestation to the
// realm's anchors and policy exactly as a request sent to `/.well-known/est`
// is. The certificate comes back to be written to the slot with `ykman piv
// certificates import`. **THE PERSON IS THE CALLER, OR THE ONE AN
// ADMINISTRATOR NAMED**; the identity rule (`authorizeTarget()`) is the
// core's, so a person can enrol only themselves.
//
// **D7, ESCROW** (rcbj's decision on #1955, off by default). A YubiKey's 9d
// key decrypts S/MIME mail; a 9d key generated ON the card is lost with the
// card, and with it every message encrypted to it. So a realm may turn on
// `piv.keyEscrow`, and then EST /serverkeygen for the `piv-key-management`
// profile generates the key here, hands it to the client to import into slot
// 9d, and KEEPS it — sealed under the key-encryption key in every mode,
// refused where no key-encryption key is held (`cert_enrollment.issue()`,
// STS-PIV-0020 and -0021). Such a key is NOT hardware-bound: this service
// had it in memory, so it is never PIV evidence, never on a token as
// `hardware`, and earns no `hwk`.
//
//   * **THE HOLDER** recovers their own escrowed key from the portal
//     (`recover-key`), behind the account API's fresh-sign-in requirement
//     (`recentAuth`), as every act that hands out a credential is.
//   * **AN ADMINISTRATOR** recovers a person's through `POST
//     /admin-api/hardware-tokens/recover-key` and the console. Admin Write is
//     not enough: recovering someone's decryption key reads their mail, so
//     the act asks the ACCESS-CONTROL POLICY (`common/access_gate.ts`,
//     resource `piv-key-escrow`, action `recover-key`, required role
//     PIV_KEY_RECOVERY) — the *authorization is XACML policy* rule — and
//     PIV_KEY_RECOVERY is a built-in role held through the group
//     `roles.pivKeyRecoveryGroup` names (default `piv-key-recovery`, empty
//     by default of members), argued in `common/roles.js` beside XACML_USER.
//     Only a Permit decided by a policy recovers (fail closed: an empty
//     decider, or XACML turned off, answers "allowed" with no decision,
//     which is right for a surface and wrong for somebody's mail). Every recovery, either door, is audited
//     (`piv-escrow.recover`), and the holder is told over CAEP.
//   * **A LOST CARD** (X2) revokes the certificate through the x509 retirer
//     and keeps the escrow: `revokeEnrolled()` rewrites the certificate row
//     and leaves the sealed key, which is what escrow is for. The holder
//     tells the register which token the key was loaded on (`attach-key`),
//     so reporting that token lost revokes the escrowed certificate too.
//
// A LIBRARY (rule 3): no route. It requires `helpers`, `audit`,
// `error_codes` and `access_gate`; enrolment, the register and the signals
// are reached at the moment of use.
// ===========================================================================

import helpers = require('./helpers');
import InstanceSlot = require('./instance_slot');
import audit = require('./audit');
import errorCodes = require('./error_codes');
import accessGate = require('./access_gate');

type Json = any;

const MAX_PEM = 32768;

interface PivEnrolmentDeps {
  log: typeof helpers.log;
  audit: typeof audit;
  errorCodes: typeof errorCodes;
  gate: typeof accessGate;
  // Reached at the moment of use (header).
  loadEnrollment: () => Json;
  loadTokens: () => Json;
  loadSignals: () => Json;
}

/**
 * The PIV enrolment form and the escrowed key-management keys (#1955 P2).
 */
class PivEnrolment {
  /**
   * Builds the module over its dependencies.
   *
   * @param deps - the modules it reads through
   */
  constructor(private readonly deps: PivEnrolmentDeps) {
    deps.log.debug("Entering PivEnrolment.constructor().");
    deps.log.debug("Leaving PivEnrolment.constructor().");
  }

  /**
   * The dependencies the service uses.
   *
   * @returns the dependencies
   */
  static defaultDeps(): PivEnrolmentDeps {
    helpers.log.debug("Entering PivEnrolment.defaultDeps().");
    helpers.log.debug("Leaving PivEnrolment.defaultDeps().");
    return {
      log: helpers.log, audit: audit, errorCodes: errorCodes,
      gate: accessGate,
      loadEnrollment: function (): Json {
        return require('./cert_enrollment');
      },
      loadTokens: function (): Json {
        return require('./hardware_tokens');
      },
      loadSignals: function (): Json {
        return require('../ssf/account_signals');
      }
    };
  }

  private refuse(code: string, status: number, why: string): Json {
    const { log, errorCodes: codes } = this.deps;
    log.debug("Entering PivEnrolment.refuse(). " + code);
    log.debug("Leaving PivEnrolment.refuse().");
    // error-code: none — the caller's code, passed in as `code`
    return codes.mark({ ok: false, status: status, error: why,
                        errors: [why], why: why }, code);
  }

  // A certificate request's DER from PEM, or from base64 DER.
  private static requestDer(text: unknown): Buffer | null {
    helpers.log.debug("Entering PivEnrolment.requestDer().");
    const raw = String(text || '').slice(0, MAX_PEM)
      .replace(/-----(BEGIN|END) (NEW )?CERTIFICATE REQUEST-----/g, '')
      .replace(/\s+/g, '');
    const der = /^[A-Za-z0-9+/=]+$/.test(raw) && raw.length > 16
      ? Buffer.from(raw, 'base64') : null;
    helpers.log.debug("Leaving PivEnrolment.requestDer().");
    return der && der.length ? der : null;
  }

  // -------------------------------------------------------------------------
  // THE FORM (header). `spec`: { username (whom it is for), actor, admin
  // (the console's door), profile, csr, slotPem, attestationPem, via }.
  // -------------------------------------------------------------------------
  /**
   * Issues a PIV slot certificate from the enrolment form: the request, the
   * slot's attestation certificate and the f9 certificate.
   *
   * @param spec - whom it is for, who acts, the profile and the three PEM
   *   texts
   * @returns `{ ok, certificatePem, chainPem, serialHex, attested, token }`,
   *   or a refusal
   */
  async enrol(spec: Json): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering PivEnrolment.enrol().");
    const s = spec || {};
    const enrollment = this.deps.loadEnrollment();
    const profile = String(s.profile || '');
    if (!require('./piv_attestation').isPivProfile(profile)) {
      log.debug("Leaving PivEnrolment.enrol(). Not a PIV profile.");
      return this.refuse('STS-PIV-0009', 400, 'The form issues one of the ' +
        'four PIV slot profiles (piv-auth, piv-sign, piv-key-management, ' +
        'piv-card-auth); "' + profile.slice(0, 64) + '" is not one.');
    }
    const der = PivEnrolment.requestDer(s.csr);
    if (!der) {
      log.debug("Leaving PivEnrolment.enrol(). No request.");
      return this.refuse('STS-PIV-0009', 400, 'Paste the certificate ' +
        'request (PEM) the YubiKey signed: ykman piv certificates request.');
    }
    const csr = await enrollment.parseCsr(der, {});
    if (!csr.ok) {
      log.debug("Leaving PivEnrolment.enrol(). The request was refused.");
      return csr;
    }
    const username = String(s.username || '');
    const principal = enrollment.sessionPrincipal(String(s.actor || ''),
      s.admin ? 'console' : 'portal', { admin: !!s.admin });
    const issued = await enrollment.issue({
      family: 'est', profile: profile, principal: principal,
      target: { kind: 'person', id: username },
      publicKeyPem: csr.publicKeyPem, keyAlg: csr.keyAlg,
      requested: csr.requested, keySource: 'client',
      attestations: csr.attestations,
      pivAttestation: String(s.slotPem || '').trim() ||
        String(s.attestationPem || '').trim()
        ? { slotPem: String(s.slotPem || '').slice(0, MAX_PEM),
            attestationPem: String(s.attestationPem || '').slice(0, MAX_PEM) }
        : null,
      via: String(s.via || (s.admin ? 'console:piv' : 'portal:piv'))
    });
    if (!issued.ok) {
      log.debug("Leaving PivEnrolment.enrol(). Refused.");
      return issued;
    }
    const record = issued.record || {};
    log.debug("Leaving PivEnrolment.enrol(). Issued " + record.serialHex);
    return { ok: true, serialHex: String(record.serialHex || ''),
             profile: profile,
             certificatePem: String(record.certificatePem || ''),
             chainPem: (record.chainPem || []).slice(),
             attested: record.keySource === 'attested-hardware',
             token: record.attestation
               ? 'yubico/' + String(record.attestation.serial) : '' };
  }

  // -------------------------------------------------------------------------
  // ESCROW (header).
  // -------------------------------------------------------------------------
  /**
   * A person's escrowed key-management certificates; never a key.
   *
   * @param username - the person
   * @returns the rows
   */
  escrowedOf(username: string): Json[] {
    const { log } = this.deps;
    log.debug("Entering PivEnrolment.escrowedOf().");
    let out: Json[] = [];
    try {
      out = this.deps.loadEnrollment().escrowedOf(username) || [];
    } catch (e) {
      log.debug("Caught in PivEnrolment.escrowedOf(): " +
                ((e && e.message) || e));
      out = [];
    }
    log.debug("Leaving PivEnrolment.escrowedOf(). " + out.length);
    return out;
  }

  /**
   * Recovers an escrowed key: the holder's own (the portal), or a person's
   * for an administrator the access-control policy lets (the console and
   * `/admin-api`).
   *
   * @param spec - `username` (whose), `serialHex`, `actor`, `door`
   *   ('portal' or 'admin-api'), `roles` (the administrator's, for the
   *   policy)
   * @returns `{ ok, privateKeyPem, certificatePem, chainPem, record }`, or a
   *   refusal
   */
  recover(spec: Json): Json {
    const { log, gate } = this.deps;
    log.debug("Entering PivEnrolment.recover().");
    const s = spec || {};
    const username = String(s.username || '');
    const actor = String(s.actor || '');
    const admin = s.door !== 'portal';
    if (!admin && actor !== username) {
      log.debug("Leaving PivEnrolment.recover(). Not the holder.");
      return this.refuse('STS-PIV-0022', 404, 'No escrowed key of yours is ' +
        'held for that certificate.');
    }
    if (admin) {
      // THE POLICY DECIDES (header), and a missing decider refuses.
      let allowed = false;
      let why = 'no access-control decider is installed in this process';
      if (gate.deciderInstalled()) {
        const answer: Json = gate.check({
          resource: gate.RESOURCE.PIV_KEY_ESCROW,
          action: gate.ACTION.RECOVER_KEY,
          requiredRoles: ['PIV_KEY_RECOVERY'],
          // The actor's GROUPS, looked up here: the access PEP resolves a
          // built-in group role only from the groups it is handed.
          subject: { name: actor, authenticated: true,
                     roles: Array.isArray(s.roles) ? s.roles : [],
                     groups: this.groupsOf(actor), sessionId: null },
          // NO `owner`: the built-in document gives a resource that names
          // one to its owner alone, and the owner here is the person whose
          // key it is, never the administrator asking. The holder rides in
          // the context, for a realm's own rule.
          context: { door: 'admin-api', holder: username }
        });
        // A PERMIT FROM A POLICY, and nothing less: the gate also answers
        // "allowed" with no decision where XACML is off, which is right for
        // a surface and wrong for somebody's mail.
        allowed = !!(answer && answer.allowed && answer.decision === 'Permit');
        why = String((answer && answer.why) || '');
      }
      if (!allowed) {
        this.recordAudit('failure', actor, username, s.serialHex,
                         String(s.door || 'admin-api'), 'STS-PIV-0023');
        log.debug("Leaving PivEnrolment.recover(). The policy refused it.");
        return this.refuse('STS-PIV-0023', 403, 'Recovering another ' +
          'person\'s escrowed key needs the PIV_KEY_RECOVERY role (the ' +
          'group roles.pivKeyRecoveryGroup names), which the access-control ' +
          'policy did not find: ' + why);
      }
    }
    const opened: Json = this.deps.loadEnrollment().escrowedKeyOf(username,
      String(s.serialHex || ''));
    if (!opened.ok) {
      this.recordAudit('failure', actor, username, s.serialHex,
                       String(s.door || ''),
                       this.deps.errorCodes.codeOf(opened) || 'STS-PIV-0022');
      log.debug("Leaving PivEnrolment.recover(). Not opened.");
      return opened;
    }
    this.recordAudit('success', actor, username, opened.record.serialHex,
                     String(s.door || ''), '');
    try {
      this.deps.loadSignals().credentialChanged({ username: username,
        credentialType: 'x509', friendlyName: 'escrowed key of certificate ' +
          opened.record.serialHex,
        changeType: 'update', initiatingEntity: admin ? 'admin' : 'user',
        via: admin ? 'Management API' : 'User portal',
        reasonAdmin: 'The escrowed key-management key of certificate ' +
          opened.record.serialHex + ' was recovered by ' + actor + '.',
        reasonUser: 'An escrowed encryption key of yours was recovered.' });
    } catch (e) {
      log.debug("Caught in PivEnrolment.recover(): " +
                ((e && e.message) || e));
      // The recovery stands and is audited; the signal is best effort, as
      // every door's is.
    }
    log.debug("Leaving PivEnrolment.recover(). Recovered.");
    return opened;
  }

  /**
   * Notes which hardware token an escrowed key was loaded on, so reporting
   * the token lost revokes its certificate (the escrow is kept).
   *
   * @param spec - `username`, `serialHex`, `key` (the token), `actor`
   * @returns `{ ok, token }`, or a refusal
   */
  attach(spec: Json): Json {
    const { log } = this.deps;
    log.debug("Entering PivEnrolment.attach().");
    const s = spec || {};
    const username = String(s.username || '');
    const serial = String(s.serialHex || '').toLowerCase();
    const escrowed = this.escrowedOf(username).filter(function (one: Json) {
      return String(one.serialHex).toLowerCase() === serial && !one.revoked;
    })[0];
    if (!escrowed) {
      log.debug("Leaving PivEnrolment.attach(). Not an escrowed one.");
      return this.refuse('STS-PIV-0025', 404, 'Certificate ' +
        serial.slice(0, 64) + ' is not an unrevoked escrowed certificate ' +
        'of yours.');
    }
    const out = this.deps.loadTokens().attachCredential({
      key: String(s.key || ''), username: username,
      credential: { kind: 'x509', ref: serial, family: 'est',
                    label: 'piv-key-management (slot 9d, escrowed)' },
      actor: String(s.actor || username) });
    log.debug("Leaving PivEnrolment.attach(). ok=" + !!(out && out.ok));
    return out;
  }

  // A person's groups for the policy (`common/roles.js`, reached lazily),
  // [] where they cannot be read: no group, no recovery role.
  private groupsOf(username: string): string[] {
    const { log } = this.deps;
    log.debug("Entering PivEnrolment.groupsOf().");
    let out: string[] = [];
    try {
      out = (require('./roles').groupsOf(username) || []).map(String);
    } catch (e) {
      log.debug("Caught in PivEnrolment.groupsOf(): " +
                ((e && e.message) || e));
      out = [];
    }
    log.debug("Leaving PivEnrolment.groupsOf(). " + out.length);
    return out;
  }

  private recordAudit(outcome: string, actor: string, target: string,
                      serialHex: unknown, door: string, code: string): void {
    const { log } = this.deps;
    log.debug("Entering PivEnrolment.recordAudit(). " + outcome);
    this.deps.audit.audit(Object.assign({
      action: 'piv-escrow.recover', actor: actor, target: target,
      outcome: outcome,
      summary: (outcome === 'success' ? 'The escrowed key of certificate '
        : 'A recovery of the escrowed key of certificate ') +
        String(serialHex || '').slice(0, 64) + ' of ' + target +
        (outcome === 'success' ? ' was recovered' : ' was refused') +
        ' (' + door + ')',
      detail: { serialHex: String(serialHex || '').slice(0, 64), door: door }
    }, code ? { errorCode: code } : {}));
    log.debug("Leaving PivEnrolment.recordAudit().");
  }
}

const slot = new InstanceSlot<PivEnrolment>(
  'common/piv_enrolment',
  () => new PivEnrolment(PivEnrolment.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The PIV enrolment form and escrowed key-management keys (#1955 P2). A
 * library (rule 3).
 * @namespace
 */
export = {
  PivEnrolment: PivEnrolment,
  installInstance: (instance: PivEnrolment): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  enrol: slot.forward('enrol'),
  escrowedOf: slot.forward('escrowedOf'),
  recover: slot.forward('recover'),
  attach: slot.forward('attach')
};
