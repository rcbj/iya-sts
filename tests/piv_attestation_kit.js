// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: piv_attestation_kit.js
//
// ===========================================================================
// A SOFTWARE YUBIKEY THAT ATTESTS ITS PIV KEYS (#1955 P2), for
// `tests/piv_attestation.js`. NOT A TEST: `run.js` lists it with the other
// kits.
//
// **EVERY KEY AND CERTIFICATE IS MADE HERE, AT RUN TIME, IN MEMORY**, as in
// `webauthn_attestation_kit.js`, whose certificate builder it uses. No key
// material is in this repository and no real YubiKey's output is either: a
// root standing for Yubico's PIV root, an "f9" attestation certificate under
// it (a CA, as a YubiKey's factory one is), and for each slot an attestation
// certificate over that slot's key with exactly the extensions Yubico's PIV
// attestation page defines (1.3.6.1.4.1.41482.3.3 firmware as three raw
// octets, .3.7 serial as a DER INTEGER, .3.8 PIN and touch policy as two
// octets, .3.9 form factor as one) and the subject a YubiKey writes,
// "YubiKey PIV Attestation <slot>". A certificate request is built over the
// slot's key, optionally carrying draft-ietf-lamps-csr-attestation's
// id-aa-attestation attribute with the statement this service reads
// (`crypto.js`'s YUBICO_PIV_STATEMENT): the slot certificate as `stmt`, the
// f9 certificate in `certs`.
//
// Written from Yubico's and the draft's text, not from the verifier. Each
// builder takes options that make the output wrong in exactly one way.
// ===========================================================================

const nodeCrypto = require('crypto');
const asn1js = require('asn1js');
const pkijs = require('pkijs');
const kit = require('./webauthn_attestation_kit');

const log = require('bunyan').createLogger({
  name: 'piv_attestation_kit', level: process.env.LOG_LEVEL || 'info' });

const YUBICO = '1.3.6.1.4.1.41482.3.';
const STATEMENT = '1.3.6.1.4.1.41482.3.2';
const ID_AA_ATTESTATION = '1.2.840.113549.1.9.16.2.59';
const PIN = { never: 1, once: 2, always: 3 };
const TOUCH = { never: 1, always: 2, cached: 3 };

function pem(der, label) {
  log.debug("Entering pem().");
  log.debug("Leaving pem().");
  return '-----BEGIN ' + label + '-----\n' +
    Buffer.from(der).toString('base64').replace(/(.{64})/g, '$1\n') +
    '\n-----END ' + label + '-----\n';
}

function rawExtension(suffix, bytes) {
  log.debug("Entering rawExtension(). " + suffix);
  log.debug("Leaving rawExtension().");
  return new pkijs.Extension({ extnID: YUBICO + suffix, critical: false,
    extnValue: new Uint8Array(Buffer.from(bytes)).buffer });
}

// The DER of an INTEGER holding `n`.
function derInteger(n) {
  log.debug("Entering derInteger().");
  let hex = Number(n).toString(16);
  if (hex.length % 2) {
    hex = '0' + hex;
  }
  let body = Buffer.from(hex, 'hex');
  if (body[0] & 0x80) {
    body = Buffer.concat([Buffer.from([0]), body]);
  }
  log.debug("Leaving derInteger().");
  return Buffer.concat([Buffer.from([0x02, body.length]), body]);
}

/**
 * A Yubico-shaped PIV attestation root and the f9 certificate under it.
 *
 * @param o - `name` (the root's), `fips` (the f9 carries .3.10)
 * @returns `{ root, f9, rootPem, f9Pem }`; root and f9 each `{ der, pem,
 *   pkijs, signingKey }`
 */
async function device(o) {
  log.debug("Entering device().");
  const opts = o || {};
  const root = await kit.root(opts.name || 'Test Yubico PIV', 'ec');
  const f9pair = await kit.keyPair('ec');
  const f9 = await kit.certificate({
    subject: [['2.5.4.3', 'Yubico PIV Attestation']],
    publicKey: f9pair.crypto.publicKey, issuer: root, ca: true,
    extensions: opts.fips ? [rawExtension('10', [1])] : [] });
  f9.signingKey = f9pair.crypto.privateKey;
  log.debug("Leaving device().");
  return { root: root, f9: f9, rootPem: root.pem, f9Pem: f9.pem };
}

/**
 * A key in a slot, its attestation certificate and a request over it.
 *
 * @param dev - `device()`'s answer
 * @param o - `slot` ('9a'), `serial`, `firmware` ([5,4,3]), `pin`
 *   ('once'), `touch` ('always'), `formFactor` (3), `noSerial`,
 *   `attestOther` (attest a different key than the request's),
 *   `inRequest` (carry the statement in the request), `subject`
 * @returns `{ csrDer, csrPem, slotPem, f9Pem, keyPair, serial }`
 */
async function slotKey(dev, o) {
  log.debug("Entering slotKey().");
  const opts = o || {};
  const slot = opts.slot || '9a';
  const serial = opts.serial || 10000000 + nodeCrypto.randomInt(8e7);
  const pair = await kit.keyPair('ec');
  const attested = opts.attestOther ? await kit.keyPair('ec') : pair;
  const fw = opts.firmware || [5, 4, 3];
  const ext = [rawExtension('3', fw),
               rawExtension('8', [PIN[opts.pin || 'once'],
                                  TOUCH[opts.touch || 'always']]),
               rawExtension('9', [opts.formFactor || 3])];
  if (!opts.noSerial) {
    ext.push(rawExtension('7', derInteger(serial)));
  }
  const slotCert = await kit.certificate({
    subject: [['2.5.4.3', 'YubiKey PIV Attestation ' + slot]],
    publicKey: attested.crypto.publicKey, issuer: dev.f9,
    extensions: ext });
  const csr = new pkijs.CertificationRequest();
  csr.version = 0;
  csr.subject.typesAndValues.push(new pkijs.AttributeTypeAndValue({
    type: '2.5.4.3',
    value: new asn1js.Utf8String({ value: opts.subject || 'piv test' }) }));
  await csr.subjectPublicKeyInfo.importKey(pair.crypto.publicKey);
  if (opts.inRequest) {
    const slotAsn1 = asn1js.fromBER(new Uint8Array(slotCert.der).buffer)
      .result;
    const f9Asn1 = asn1js.fromBER(new Uint8Array(dev.f9.der).buffer).result;
    const bundle = new asn1js.Sequence({ value: [
      new asn1js.Sequence({ value: [new asn1js.Sequence({ value: [
        new asn1js.ObjectIdentifier({ value: STATEMENT }), slotAsn1] })] }),
      new asn1js.Sequence({ value: [f9Asn1] })] });
    csr.attributes = [new pkijs.Attribute({ type: ID_AA_ATTESTATION,
                                            values: [bundle] })];
  }
  await csr.sign(pair.crypto.privateKey, 'SHA-256');
  const csrDer = Buffer.from(csr.toSchema().toBER(false));
  log.debug("Leaving slotKey().");
  return { csrDer: csrDer, csrPem: pem(csrDer, 'CERTIFICATE REQUEST'),
           slotPem: slotCert.pem, slotDer: slotCert.der, f9Pem: dev.f9.pem,
           f9Der: dev.f9.der, keyPair: pair, serial: String(serial),
           publicPem: pair.publicKey.export({ type: 'spki', format: 'pem' }) };
}

/**
 * An outside PIV card's certificate, from an issuing CA of its own, naming
 * its card by a urn:uuid subjectAltName and asserting certificate policies.
 *
 * @param o - `uuids` (the card UUIDs to name), `policies` (OIDs), `cn`
 * @returns `{ issuer, leaf, issuerPem, leafPem, leafDer }`
 */
async function outsideCard(o) {
  log.debug("Entering outsideCard().");
  const opts = o || {};
  const issuer = await kit.root(opts.issuerName || 'Test PIV Issuing CA',
                                'ec');
  const pair = await kit.keyPair('ec');
  const ext = [];
  const uuids = opts.uuids || [nodeCrypto.randomUUID()];
  if (uuids.length) {
    ext.push(new pkijs.Extension({ extnID: '2.5.29.17', critical: false,
      extnValue: new pkijs.AltName({ altNames: uuids.map(function (u) {
        return new pkijs.GeneralName({ type: 6, value: 'urn:uuid:' + u });
      }) }).toSchema().toBER(false) }));
  }
  if ((opts.policies || []).length) {
    ext.push(new pkijs.Extension({ extnID: '2.5.29.32', critical: false,
      extnValue: new pkijs.CertificatePolicies({ certificatePolicies:
        opts.policies.map(function (oid) {
          return new pkijs.PolicyInformation({ policyIdentifier: oid });
        }) }).toSchema().toBER(false) }));
  }
  // digitalSignature, as a PIV Authentication certificate has.
  ext.push(new pkijs.Extension({ extnID: '2.5.29.15', critical: true,
    extnValue: new asn1js.BitString({ valueHex: new Uint8Array([0x80]).buffer,
                                      unusedBits: 7 }).toBER(false) }));
  const leaf = await kit.certificate({
    subject: [['2.5.4.3', opts.cn || 'SOMEBODY.ELSE.1234567890']],
    publicKey: pair.crypto.publicKey, issuer: issuer, extensions: ext });
  log.debug("Leaving outsideCard().");
  return { issuer: issuer, leaf: leaf, issuerPem: issuer.pem,
           leafPem: leaf.pem, leafDer: leaf.der, uuids: uuids };
}

module.exports = {
  STATEMENT: STATEMENT,
  device: device,
  slotKey: slotKey,
  outsideCard: outsideCard
};
