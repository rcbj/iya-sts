'use strict';
//
// File: spiffe_attestor_tpm_devid.ts
//
// ---------------------------------------------------------------------------
// THE `tpm_devid` NODE ATTESTOR — A TPM-RESIDENT DevID (IEEE 802.1AR) (#40,
// 2026-09-21).
//
// SPIRE's `pkg/server/plugin/nodeattestor/tpmdevid`, whose client is a real
// `spire-agent` driving a real TPM:
//
//   1. The payload is SPIRE's `AttestationRequest` as Go marshals it:
//      `{"DevIDCert": [<DER>…], "DevIDPub", "EKCert", "EKPub", "AKPub",
//      "CertifiedDevID", "CertificationSignature"}`, every value base64.
//   2. The DevID certificate must chain to `spiffe.tpmDevidCaBundle`.
//   3. RESIDENCY: every field must be there; the EK certificate's RSA key
//      must be the EK public area's; the EK certificate must chain to
//      `spiffe.tpmEndorsementCaBundle` (a critical subjectAltName is not a
//      reason to refuse it — EK certificates carry one, in directoryName
//      form); and `CertifiedDevID` — a TPM2_Certify of the DevID key by
//      the AK — must be signed by the AK and must name the DevID public
//      area. That proves the DevID key and the AK are in ONE TPM.
//   4. THE CHALLENGE, two in one: 32 random bytes the DevID key must sign
//      (RSA PKCS#1 v1.5 or ECDSA, over SHA-256), and a credential only the
//      TPM holding the EK can activate for this AK
//      (`spiffe_tpm.ts`'s `makeCredential()`), whose secret — a nonce the
//      size of the EK's name hash — must come back. That proves the AK is in
//      the TPM the manufacturer certified.
//   5. The agent is `/tpm_devid/<SHA-1 of the DevID certificate>`, with
//      selectors `subject:cn:`, `issuer:cn:` and `ca:fingerprint:` for every
//      certificate above the DevID leaf. Re-attestable.
//
// Nothing is claimed: every proof answers a challenge this server chose.
// ---------------------------------------------------------------------------

import nodeCrypto = require('crypto');
import helpers = require('../common/helpers');
const { log } = helpers;
import config = require('../common/config');
import errorCodes = require('../common/error_codes');
import spiffeId = require('./spiffe_id');
import rpc = require('./spiffe_grpc');
import x509Path = require('./spiffe_x509_path');
import tpm = require('./spiffe_tpm');

type NodeAttestationContext =
  import('../types/spiffe-attestation').NodeAttestationContext;
type NodeAttestationResult =
  import('../types/spiffe-attestation').NodeAttestationResult;

const DEVID_NONCE_LENGTH = 32;

interface TpmDevidDeps {
  log: typeof log;
  crypto: typeof nodeCrypto;
  config: typeof config;
  errorCodes: typeof errorCodes;
  spiffeId: typeof spiffeId;
  rpc: typeof rpc;
  path: typeof x509Path;
  tpm: typeof tpm;
}

class TpmDevidAttestor {
  readonly type = 'tpm_devid';
  readonly verifies = 'A DevID certificate chaining to the realm\'s DevID ' +
    'anchors, whose key a TPM with a manufacturer-certified endorsement key ' +
    'holds — proved by a certification with the TPM\'s attestation key, a ' +
    'DevID signature and a credential activation.';

  constructor(private readonly deps: TpmDevidDeps) {
    deps.log.debug("Entering TpmDevidAttestor.constructor().");
    deps.log.debug("Leaving TpmDevidAttestor.constructor().");
  }

  static defaultDeps(): TpmDevidDeps {
    helpers.log.debug("Entering TpmDevidAttestor.defaultDeps().");
    helpers.log.debug("Leaving TpmDevidAttestor.defaultDeps().");
    return { log: log, crypto: nodeCrypto, config: config,
             errorCodes: errorCodes, spiffeId: spiffeId, rpc: rpc,
             path: x509Path, tpm: tpm };
  }

  json(bytes: Buffer): any {
    const { log } = this.deps;
    log.debug("Entering TpmDevidAttestor.json().");
    try {
      const parsed = JSON.parse(Buffer.from(bytes || []).toString('utf8'));
      log.debug("Leaving TpmDevidAttestor.json().");
      return parsed && typeof parsed === 'object' ? parsed : null;
    } catch (e) {
      log.debug("Caught in TpmDevidAttestor.json(): " +
                ((e && e.message) || e));
      log.debug("Leaving TpmDevidAttestor.json(). Not JSON.");
      return null;
    }
  }

  bytesOf(value: any): Buffer {
    const { log } = this.deps;
    log.debug("Entering TpmDevidAttestor.bytesOf().");
    log.debug("Leaving TpmDevidAttestor.bytesOf().");
    return typeof value === 'string' ? Buffer.from(value, 'base64')
                                     : Buffer.alloc(0);
  }

  // The CN of node's "K=V\n" name, or ''.
  commonName(text: string): string {
    const { log } = this.deps;
    log.debug("Entering TpmDevidAttestor.commonName().");
    const lines = String(text || '').split('\n').filter(function (line) {
      return line.indexOf('CN=') === 0;
    });
    log.debug("Leaving TpmDevidAttestor.commonName().");
    return lines.length ? lines[lines.length - 1].slice(3) : '';
  }

  // One refusal: mark the code, build the status.
  refuse(call: any, code: string, grpcCode: number, message: string): Error {
    const { log, errorCodes, rpc } = this.deps;
    log.debug("Entering TpmDevidAttestor.refuse(). " + code);
    errorCodes.mark(call, code);
    log.debug("Leaving TpmDevidAttestor.refuse().");
    // error-code: none — the helper's own internals: every caller passes
    // the code, and it is marked on the line above
    return rpc.statusError(grpcCode, message);
  }

  async attest(context: NodeAttestationContext):
      Promise<NodeAttestationResult> {
    const { log, crypto, config, spiffeId, rpc, path, tpm } = this.deps;
    const self = this;
    log.debug("Entering TpmDevidAttestor.attest().");
    const call = context.call;
    const status = rpc.grpc.status;
    const devidRoots = path.bundle(String(
      config.value('spiffe.tpmDevidCaBundle') || '')).certificates;
    const ekRoots = path.bundle(String(
      config.value('spiffe.tpmEndorsementCaBundle') || '')).certificates;
    if (!devidRoots.length || !ekRoots.length) {
      log.debug("Leaving TpmDevidAttestor.attest(). Not configured.");
      throw this.refuse(call, 'STS-SPIFFE-0085', status.FAILED_PRECONDITION,
        'tpm_devid is not configured in this realm: ' +
        (!devidRoots.length ? 'spiffe.tpmDevidCaBundle'
                            : 'spiffe.tpmEndorsementCaBundle') +
        ' holds no certificate.');
    }
    // 1. THE PAYLOAD.
    const data = this.json(context.payload);
    if (!data) {
      log.debug("Leaving TpmDevidAttestor.attest(). Unreadable.");
      throw this.refuse(call, 'STS-SPIFFE-0086', status.INVALID_ARGUMENT,
                        'unable to unmarshall attestation data');
    }
    const devidChain = Array.isArray(data.DevIDCert)
      ? data.DevIDCert.map(function (one) {
        return self.bytesOf(one);
      }) : [];
    if (!devidChain.length) {
      log.debug("Leaving TpmDevidAttestor.attest(). No DevID.");
      throw this.refuse(call, 'STS-SPIFFE-0086', status.INVALID_ARGUMENT,
                        'no DevID certificate to attest');
    }
    const devidLeaf = path.certificate(devidChain[0]);
    if (!devidLeaf) {
      log.debug("Leaving TpmDevidAttestor.attest(). Bad DevID.");
      throw this.refuse(call, 'STS-SPIFFE-0086', status.INVALID_ARGUMENT,
                        'unable to parse DevID certificate');
    }
    // 2. THE DevID PATH.
    const devidPath = await path.verify(devidChain[0], devidChain.slice(1),
                                        devidRoots);
    if (!devidPath.ok) {
      log.debug("Leaving TpmDevidAttestor.attest(). DevID path.");
      throw this.refuse(call, 'STS-SPIFFE-0089', status.INVALID_ARGUMENT,
        'unable to verify DevID signature: verification failed: ' +
        devidPath.reason);
    }
    // 3. RESIDENCY.
    const missing = !data.AKPub ? 'missing attestation key public blob'
      : !data.DevIDPub ? 'missing DevID key public blob'
        : !data.EKCert ? 'missing endorsement certificate'
          : !data.EKPub ? 'missing endorsement key public blob' : '';
    if (missing) {
      log.debug("Leaving TpmDevidAttestor.attest(). Incomplete.");
      throw this.refuse(call, 'STS-SPIFFE-0097', status.INVALID_ARGUMENT,
                        missing);
    }
    const ekCert = path.certificate(this.bytesOf(data.EKCert));
    if (!ekCert) {
      log.debug("Leaving TpmDevidAttestor.attest(). Bad EK certificate.");
      throw this.refuse(call, 'STS-SPIFFE-0086', status.INVALID_ARGUMENT,
                        'cannot parse endorsement certificate');
    }
    let devidPub = null;
    let akPub = null;
    let ekPub = null;
    try {
      devidPub = tpm.decodePublic(this.bytesOf(data.DevIDPub));
      akPub = tpm.decodePublic(this.bytesOf(data.AKPub));
      ekPub = tpm.decodePublic(this.bytesOf(data.EKPub));
    } catch (e) {
      log.debug("Caught in TpmDevidAttestor.attest(): " +
                ((e && e.message) || e));
      log.debug("Leaving TpmDevidAttestor.attest(). Bad public area.");
      throw this.refuse(call, 'STS-SPIFFE-0086', status.INVALID_ARGUMENT,
        'cannot decode ' + (!devidPub ? 'DevID key' : !akPub
          ? 'attestation key' : 'endorsement key') + ' public blob: ' +
        e.message);
    }
    // The EK certificate's key IS the EK.
    let ekMatches = false;
    try {
      const fromCert: any = ekCert.x509.publicKey.export({ format: 'jwk' });
      const fromTpm: any = tpm.keyOf(ekPub).export({ format: 'jwk' });
      ekMatches = fromCert.kty === 'RSA' && fromTpm.kty === 'RSA' &&
                  fromCert.n === fromTpm.n && fromCert.e === fromTpm.e;
    } catch (e) {
      log.debug("Caught in TpmDevidAttestor.attest(): " +
                ((e && e.message) || e));
    }
    if (!ekMatches) {
      log.debug("Leaving TpmDevidAttestor.attest(). EK mismatch.");
      throw this.refuse(call, 'STS-SPIFFE-0097', status.INVALID_ARGUMENT,
        'public key in EK certificate differs from public key created via ' +
        'EK template');
    }
    const ekPath = await path.verify(ekCert.der, [], ekRoots, undefined,
                                     ['subjectAltName']);
    if (!ekPath.ok) {
      log.debug("Leaving TpmDevidAttestor.attest(). EK path.");
      throw this.refuse(call, 'STS-SPIFFE-0089', status.INVALID_ARGUMENT,
        'cannot verify EK signature: endorsement certificate verification ' +
        'failed: ' + ekPath.reason);
    }
    // The AK certified the DevID key.
    const certified = this.bytesOf(data.CertifiedDevID);
    const signatureProblem = tpm.checkSignature(akPub, certified,
      this.bytesOf(data.CertificationSignature));
    let certifiedName = null;
    let certifyProblem = signatureProblem;
    if (!certifyProblem) {
      try {
        certifiedName = tpm.decodeCertifyName(certified);
        certifyProblem = tpm.nameMatches(certifiedName, devidPub)
          ? '' : 'certify failed';
      } catch (e) {
        log.debug("Caught in TpmDevidAttestor.attest(): " +
                  ((e && e.message) || e));
        certifyProblem = e.message;
      }
    }
    if (certifyProblem) {
      log.debug("Leaving TpmDevidAttestor.attest(). Not certified.");
      throw this.refuse(call, 'STS-SPIFFE-0097', status.INVALID_ARGUMENT,
        'cannot verify that DevID is in the same TPM than AK: ' +
        certifyProblem);
    }
    // 4. THE CHALLENGES.
    const devidNonce = crypto.randomBytes(DEVID_NONCE_LENGTH);
    let credential = null;
    let secret = null;
    try {
      // A nonce the size of the EK's name hash, as SPIRE sizes it.
      secret = crypto.randomBytes(crypto.createHash(
        tpm.hashName(ekPub.nameAlg)).digest().length);
      credential = tpm.makeCredential(tpm.name(akPub), ekPub, secret);
    } catch (e) {
      log.debug("Caught in TpmDevidAttestor.attest(): " +
                ((e && e.message) || e));
      log.debug("Leaving TpmDevidAttestor.attest(). No credential.");
      throw this.refuse(call, 'STS-SPIFFE-0097', status.INTERNAL,
        'cannot generate credential activation challenge: ' + e.message);
    }
    const answer = this.json(await context.challenge(Buffer.from(
      JSON.stringify({
        DevID: devidNonce.toString('base64'),
        CredActivation: {
          Credential: credential.credential.toString('base64'),
          Secret: credential.secret.toString('base64')
        }
      }), 'utf8')));
    if (!answer) {
      log.debug("Leaving TpmDevidAttestor.attest(). Unreadable response.");
      throw this.refuse(call, 'STS-SPIFFE-0086', status.INVALID_ARGUMENT,
                        'unable to unmarshall challenges response');
    }
    // SPIRE's `VerifyDevIDChallenge()`: CheckSignature with SHA-256.
    let devidSigned = false;
    try {
      const kind = String((devidLeaf.x509.publicKey as any)
        .asymmetricKeyType || '');
      // SHA256WithRSA (PKCS#1 v1.5), or ECDSAWithSHA256 (ASN.1 DER).
      if (kind === 'rsa') {
        devidSigned = crypto.verify('sha256', devidNonce, {
          key: devidLeaf.x509.publicKey,
          padding: crypto.constants.RSA_PKCS1_PADDING
        }, this.bytesOf(answer.DevID));
      } else if (kind === 'ec') {
        devidSigned = crypto.verify('sha256', devidNonce,
                                    devidLeaf.x509.publicKey,
                                    this.bytesOf(answer.DevID));
      }
    } catch (e) {
      log.debug("Caught in TpmDevidAttestor.attest(): " +
                ((e && e.message) || e));
    }
    if (!devidSigned) {
      log.debug("Leaving TpmDevidAttestor.attest(). DevID challenge.");
      throw this.refuse(call, 'STS-SPIFFE-0093', status.INVALID_ARGUMENT,
                        'devID challenge verification failed');
    }
    if (!this.bytesOf(answer.CredActivation).equals(secret)) {
      log.debug("Leaving TpmDevidAttestor.attest(). Activation.");
      throw this.refuse(call, 'STS-SPIFFE-0098', status.INVALID_ARGUMENT,
                        'credential activation failed: nonces are different');
    }
    // 5. THE AGENT.
    const agentId = spiffeId.make(context.trustDomain,
                                  '/spire/agent/' + this.type + '/' +
                                  devidLeaf.sha1);
    const selectors = [];
    const subjectCn = this.commonName(devidLeaf.x509.subject);
    const issuerCn = this.commonName(devidLeaf.x509.issuer);
    if (subjectCn) selectors.push('subject:cn:' + subjectCn);
    if (issuerCn) selectors.push('issuer:cn:' + issuerCn);
    devidPath.chain.slice(1).forEach(function (one) {
      selectors.push('ca:fingerprint:' + one.sha1);
    });
    log.debug("Leaving TpmDevidAttestor.attest(). " + agentId);
    return {
      agentId: agentId,
      selectors: selectors.map(function (value) {
        return { type: 'tpm_devid', value: value };
      }),
      canReattest: true,
      method: 'agent attestation (tpm_devid)',
      note: 'attested by a DevID key resident in a TPM whose endorsement ' +
            'key chains to spiffe.tpmEndorsementCaBundle',
      commit: function () {
        log.debug("Entering commit(). Nothing to spend.");
        log.debug("Leaving commit().");
      },
      release: function () {
        log.debug("Entering release(). Nothing to give back.");
        log.debug("Leaving release().");
      }
    };
  }
}

export = {
  TpmDevidAttestor: TpmDevidAttestor
};
