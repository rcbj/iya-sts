// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: passkey_evidence.ts
//
// RFC 4998 evidence records for verified passkey attestations (#947).
// A record is anchored by a configured RFC 3161 TSA; it contains the DER
// EvidenceRecord and the exact DER object whose existence was timestamped.
// Timestamp renewal extends the first ArchiveTimeStampChain by timestamping
// the prior TSA token, as RFC 4998 section 5.2 specifies.

import helpers = require('./helpers');
import config = require('./config');
import crypto = require('./crypto');
import pkijs = require('pkijs');
import asn1js = require('asn1js');

const { log } = helpers;
type Json = any;
const SHA256 = '2.16.840.1.101.3.4.2.1';
const DIGEST_OIDS: { [key: string]: string } = {
  sha256: SHA256, sha384: '2.16.840.1.101.3.4.2.2',
  sha512: '2.16.840.1.101.3.4.2.3'
};
const MAX_RESPONSE = 1024 * 1024;
const DAY_MS = 24 * 60 * 60 * 1000;

function bytes(value: Buffer): ArrayBuffer {
  const copy = Buffer.from(value);
  return copy.buffer.slice(copy.byteOffset, copy.byteOffset + copy.byteLength);
}

function der(node: any): Buffer {
  return Buffer.from(node.toBER(false));
}

function pemCertificates(text: string): any[] {
  const out: any[] = [];
  const re = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g;
  let m: RegExpExecArray;
  while ((m = re.exec(text))) {
    const raw = Buffer.from(m[1].replace(/\s/g, ''), 'base64');
    const parsed = asn1js.fromBER(bytes(raw));
    if (parsed.offset < 0) {
      throw new Error('A TSA trust anchor is not a DER certificate.');
    }
    out.push(new pkijs.Certificate({ schema: parsed.result }));
  }
  return out;
}

function timestampToken(token: any): Buffer {
  return der(token.toSchema());
}

class PasskeyEvidence {
  constructor(private readonly fetcher: typeof fetch = fetch) {}

  /** Creates an evidence record for the verified attestation object. */
  async create(object: Buffer): Promise<Json> {
    log.debug('Entering PasskeyEvidence.create().');
    const token = await this.timestamp(object);
    const archiveTimeStamp = new asn1js.Sequence({ value: [token.toSchema()] });
    const chain = new asn1js.Sequence({ value: [archiveTimeStamp] });
    const sequence = new asn1js.Sequence({ value: [chain] });
    const algorithm = new asn1js.Sequence({ value: [
      new asn1js.ObjectIdentifier({ value: SHA256 }), new asn1js.Null()
    ] });
    const algorithms = new asn1js.Sequence({ value: [algorithm] });
    const record = new asn1js.Sequence({ value: [
      new asn1js.Integer({ value: 1 }), algorithms, sequence
    ] });
    const at = token.genTime.getTime();
    const out = {
      syntax: 'RFC4998', version: 1,
      object: object.toString('base64'),
      objectDigest: crypto.digest('sha256', object, 'hex'),
      evidenceRecord: der(record).toString('base64'),
      timestamps: [timestampToken(token).toString('base64')],
      createdAt: at, renewedAt: at,
      renewAfter: token.renewAfter,
      hashAlgorithm: 'sha256',
      tsa: this.tsaLabel()
    };
    const target = String(config.value(
      'webauthn.attestationEvidenceHashAlgorithm') || 'sha256');
    if (target !== 'sha256' && DIGEST_OIDS[target]) {
      const migrated = await this.renewHashTree(out, target);
      log.debug('Leaving PasskeyEvidence.create() after hash-tree renewal.');
      return migrated;
    }
    log.debug('Leaving PasskeyEvidence.create().');
    return out;
  }

  /** Renews a record before its current timestamp is due for replacement. */
  async renew(record: Json, now?: number): Promise<Json> {
    log.debug('Entering PasskeyEvidence.renew().');
    if (!record || record.syntax !== 'RFC4998' ||
        !Array.isArray(record.timestamps) || !record.timestamps.length) {
      throw new Error('The passkey has no RFC 4998 evidence record.');
    }
    const instant = typeof now === 'number' ? now : Date.now();
    if (instant < Number(record.renewAfter || 0)) {
      return record;
    }
    const oldToken = Buffer.from(record.timestamps[
      record.timestamps.length - 1], 'base64');
    const token = await this.timestamp(oldToken);
    const previous = (Array.isArray(record.timestamps)
      ? record.timestamps : []).concat([timestampToken(token).toString('base64')]);
    // The sequence contains one chain. Its timestamps are chronological;
    // each renewal's imprint covers the previous timestamp token's DER.
    const parsed = asn1js.fromBER(bytes(Buffer.from(
      String(record.evidenceRecord), 'base64')));
    if (parsed.offset < 0) {
      throw new Error('The stored RFC 4998 evidence record is malformed.');
    }
    const evidence: any = parsed.result;
    const seqNode = evidence.valueBlock.value[2] as any;
    const chainNode = seqNode.valueBlock.value[0] as any;
    chainNode.valueBlock.value.push(
      new asn1js.Sequence({ value: [token.toSchema()] }));
    const out = Object.assign({}, record, {
      evidenceRecord: der(evidence).toString('base64'),
      timestamps: previous,
      renewedAt: token.genTime.getTime(),
      renewAfter: token.renewAfter,
      tsa: this.tsaLabel()
    });
    log.debug('Leaving PasskeyEvidence.renew().');
    return out;
  }

  /** Renews a weakened ERS hash tree into a new chain (RFC 4998 section 5.2). */
  async renewHashTree(record: Json, algorithm: string): Promise<Json> {
    log.debug('Entering PasskeyEvidence.renewHashTree().');
    const oid = DIGEST_OIDS[String(algorithm || '').toLowerCase()];
    if (!oid || oid === SHA256) {
      throw new Error('Hash-tree renewal requires SHA-384 or SHA-512.');
    }
    if (!record || record.syntax !== 'RFC4998' || !record.object ||
        !record.evidenceRecord) {
      throw new Error('The passkey has no complete RFC 4998 evidence record.');
    }
    const object = Buffer.from(record.object, 'base64');
    const oldDer = Buffer.from(record.evidenceRecord, 'base64');
    const parsed = asn1js.fromBER(bytes(oldDer));
    if (parsed.offset < 0) {
      throw new Error('The stored RFC 4998 evidence record is malformed.');
    }
    const priorSequence: any = (parsed.result as any).valueBlock.value[2];
    const digestAlgorithms: any = (parsed.result as any).valueBlock.value[1];
    if (!digestAlgorithms.valueBlock.value.some(function (one: any): boolean {
      return one.valueBlock.value[0].valueBlock.value === oid;
    })) {
      digestAlgorithms.valueBlock.value.push(new asn1js.Sequence({ value: [
        new asn1js.ObjectIdentifier({ value: oid }), new asn1js.Null()
      ] }));
    }
    const hashObject = crypto.digest(algorithm, object);
    const hashPrior = crypto.digest(algorithm, der(priorSequence));
    const leaf = crypto.digest(algorithm, Buffer.concat([hashObject, hashPrior]));
    const token = await this.timestamp(leaf, oid);
    const algorithmIdentifier = new asn1js.Sequence({ value: [
      new asn1js.ObjectIdentifier({ value: oid }), new asn1js.Null()
    ] });
    const taggedAlgorithm = new asn1js.Constructed({ idBlock: {
      tagClass: 3, tagNumber: 0
    }, value: algorithmIdentifier.valueBlock.value });
    const partialTree = new asn1js.Sequence({ value: [
      new asn1js.OctetString({ valueHex: bytes(leaf) })
    ] });
    const reducedTree = new asn1js.Constructed({ idBlock: {
      tagClass: 3, tagNumber: 2
    }, value: [partialTree] });
    const archiveTimestamp = new asn1js.Sequence({ value: [
      taggedAlgorithm, reducedTree, token.toSchema()
    ] });
    const newChain = new asn1js.Sequence({ value: [archiveTimestamp] });
    priorSequence.valueBlock.value.push(newChain);
    const out = Object.assign({}, record, {
      evidenceRecord: der(parsed.result).toString('base64'),
      timestamps: (record.timestamps || []).concat([
        timestampToken(token).toString('base64')
      ]),
      renewedAt: token.genTime.getTime(), renewAfter: token.renewAfter,
      hashAlgorithm: algorithm.toLowerCase(), tsa: this.tsaLabel()
    });
    log.debug('Leaving PasskeyEvidence.renewHashTree().');
    return out;
  }

  /** Requests and validates a SHA-256 RFC 3161 timestamp token. */
  private async timestamp(data: Buffer, algorithmOid: string = SHA256): Promise<any> {
    log.debug('Entering PasskeyEvidence.timestamp().');
    const endpoint = String(config.value('webauthn.attestationEvidenceTsaUrl') ||
                            '').trim();
    const anchors = String(config.value(
      'webauthn.attestationEvidenceTsaTrustAnchors') || '');
    if (!endpoint || !anchors.trim()) {
      throw new Error('A passkey evidence TSA URL and its trust anchors ' +
                      'must both be configured.');
    }
    const url = new URL(endpoint);
    if (url.protocol !== 'https:') {
      throw new Error('The passkey evidence TSA must use HTTPS.');
    }
    const algorithm = Object.keys(DIGEST_OIDS).filter(function (name) {
      return DIGEST_OIDS[name] === algorithmOid;
    })[0];
    if (!algorithm) { throw new Error('Unsupported timestamp digest.'); }
    const imprint = crypto.digest(algorithm, data);
    const request = new pkijs.TimeStampReq({
      version: 1,
      messageImprint: new pkijs.MessageImprint({
        hashAlgorithm: new pkijs.AlgorithmIdentifier({
          algorithmId: algorithmOid, algorithmParams: new asn1js.Null()
        }), hashedMessage: new asn1js.OctetString({
          valueHex: bytes(imprint)
        })
      }), certReq: true
    });
    const response = await this.fetcher(url.toString(), {
      method: 'POST',
      headers: { 'Content-Type': 'application/timestamp-query',
                 Accept: 'application/timestamp-reply' },
      body: Buffer.from(request.toSchema().toBER(false)),
      signal: AbortSignal.timeout(15000)
    });
    if (!response.ok) {
      throw new Error('The timestamp authority answered HTTP ' +
                      response.status + '.');
    }
    const reply = Buffer.from(await response.arrayBuffer());
    if (reply.length > MAX_RESPONSE) {
      throw new Error('The timestamp authority response is too large.');
    }
    const decoded = asn1js.fromBER(bytes(reply));
    if (decoded.offset < 0) {
      throw new Error('The timestamp authority returned malformed DER.');
    }
    const result = new pkijs.TimeStampResp({ schema: decoded.result });
    if (!result.timeStampToken || !result.status ||
        result.status.status !== 0 && result.status.status !== 1) {
      throw new Error('The timestamp authority did not grant the request.');
    }
    const content = result.timeStampToken;
    if (content.contentType !== pkijs.id_ContentType_SignedData) {
      throw new Error('The timestamp token is not CMS SignedData.');
    }
    const signed = new pkijs.SignedData({ schema: content.content });
    const econtent = signed.encapContentInfo.eContent;
    if (!econtent || !econtent.valueBlock ||
        !econtent.valueBlock.valueHexView) {
      throw new Error('The timestamp token carries no TSTInfo.');
    }
    const tstDer = Buffer.from(econtent.valueBlock.valueHexView);
    const tstAsn = asn1js.fromBER(bytes(tstDer));
    if (tstAsn.offset < 0) {
      throw new Error('The timestamp token TSTInfo is malformed.');
    }
    const info = new pkijs.TSTInfo({ schema: tstAsn.result });
    const actualHash = Buffer.from(info.messageImprint.hashedMessage
      .valueBlock.valueHexView);
    if (info.messageImprint.hashAlgorithm.algorithmId !== algorithmOid ||
        !actualHash.equals(imprint)) {
      throw new Error('The timestamp token does not cover the requested ' +
                      'evidence.');
    }
    const trust = pemCertificates(anchors);
    const verified = await signed.verify({ signer: 0, trustedCerts: trust,
                                           checkChain: true,
                                           checkDate: info.genTime });
    if (verified !== true) {
      throw new Error('The timestamp token signature or TSA chain did not ' +
                      'verify against the configured trust anchors.');
    }
    const signerCert = PasskeyEvidence.signerCertificate(signed);
    const eku = signerCert && (signerCert.extensions || []).filter(
      function (one: any): boolean {
        return one.extnID === '2.5.29.37';
      })[0];
    if (!eku || eku.critical !== true) {
      throw new Error('The timestamp signer certificate has no critical ' +
                      'extendedKeyUsage.');
    }
    const ekuAsn = asn1js.fromBER(bytes(Buffer.from(
      eku.extnValue.valueBlock.valueHexView)));
    const purposes = ekuAsn.offset >= 0
      ? new pkijs.ExtKeyUsage({ schema: ekuAsn.result }).keyPurposes : [];
    if (purposes.indexOf('1.3.6.1.5.5.7.3.8') < 0) {
      throw new Error('The timestamp signer certificate does not have the ' +
                      'id-kp-timeStamping purpose.');
    }
    const expiry = (signed.certificates || []).filter(function (one: any) {
      return one instanceof pkijs.Certificate && one.notAfter &&
             one.notAfter.value instanceof Date;
    }).map(function (one: any): number {
      return one.notAfter.value.getTime();
    }).reduce(function (a: number, b: number): number {
      return Math.min(a, b);
    }, Number.MAX_SAFE_INTEGER);
    if (expiry === Number.MAX_SAFE_INTEGER) {
      throw new Error('The timestamp token carries no certificate expiry.');
    }
    log.debug('Leaving PasskeyEvidence.timestamp().');
    return { genTime: info.genTime,
      renewAfter: Math.max(info.genTime.getTime() + DAY_MS,
                           expiry - 30 * DAY_MS),
      toSchema: () => content.toSchema() };
  }

  private static signerCertificate(signed: any): any {
    log.debug('Entering PasskeyEvidence.signerCertificate().');
    const signer = signed.signerInfos && signed.signerInfos[0];
    const sid = signer && signer.sid;
    const certs = Array.isArray(signed.certificates)
      ? signed.certificates.filter(function (one: any): boolean {
        return one instanceof pkijs.Certificate;
      }) : [];
    if (sid && sid.issuer && sid.serialNumber) {
      const found = certs.filter(function (one: any): boolean {
        return one.issuer.isEqual(sid.issuer) &&
               one.serialNumber.isEqual(sid.serialNumber);
      })[0];
      log.debug('Leaving PasskeyEvidence.signerCertificate().');
      return found || null;
    }
    if (sid && sid.valueBlock) {
      const keyId = sid.idBlock && sid.idBlock.isConstructed
        ? sid.valueBlock.value[0].valueBlock.valueHexView
        : sid.valueBlock.valueHexView;
      const found = certs.filter(function (one: any): boolean {
        const digest = crypto.sha1Digest('key-identifier', Buffer.from(
          one.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView));
        return digest.equals(Buffer.from(keyId));
      })[0];
      log.debug('Leaving PasskeyEvidence.signerCertificate().');
      return found || null;
    }
    log.debug('Leaving PasskeyEvidence.signerCertificate(). No signer.');
    return null;
  }

  private tsaLabel(): string {
    return new URL(String(config.value('webauthn.attestationEvidenceTsaUrl')))
      .origin;
  }
}

const instance = new PasskeyEvidence();
export = {
  PasskeyEvidence: PasskeyEvidence,
  create: instance.create.bind(instance),
  renew: instance.renew.bind(instance),
  renewHashTree: instance.renewHashTree.bind(instance),
  DAY_MS: DAY_MS
};
