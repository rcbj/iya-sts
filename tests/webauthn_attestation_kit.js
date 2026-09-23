'use strict';
//
// File: webauthn_attestation_kit.js
//
// ===========================================================================
// A SOFTWARE AUTHENTICATOR THAT ATTESTS IN ALL EIGHT FORMATS (#105), for
// `tests/webauthn_attestation.js`. NOT A TEST: `run.js` lists it with the
// other kits.
//
// **EVERY KEY AND CERTIFICATE IS MADE HERE, AT RUN TIME, IN MEMORY.** No key
// material is in this repository and no captured authenticator's output is
// either: a root per "vendor", an attestation certificate per format with
// exactly the fields WebAuthn Level 3 section 8 requires of it, and the
// structures a real authenticator would produce — a TPM's TPMT_PUBLIC,
// TPMS_ATTEST and TPMT_SIGNATURE, Android's KeyDescription, Apple's nonce
// extension, a SafetyNet JWS. The certificates are built with pkijs rather
// than the service's own `x509.issueCertificate()`, because a TPM AIK
// certificate has an EMPTY subject, which that builder refuses.
//
// It is written from the specification, not from the verifier: two readings
// of one document that agree is the result; one implementation agreeing with
// itself is none. Each builder takes a `spoil` argument that makes the output
// wrong in exactly one way, which is what the refusal tests use.
// ===========================================================================

const nodeCrypto = require('crypto');
const asn1js = require('asn1js');
const pkijs = require('pkijs');
const pqJose = require('../common/pq_jose');

const webcrypto = nodeCrypto.webcrypto;
pkijs.setEngine('webauthn-attestation-kit',
                new pkijs.CryptoEngine({ name: 'webauthn-attestation-kit',
                                         crypto: webcrypto }));

const log = require('bunyan').createLogger({
  name: 'webauthn_attestation_kit', level: process.env.LOG_LEVEL || 'info' });

// ----- CBOR, encode only -----------------------------------------------------

function cborHead(major, n) {
  log.debug("Entering cborHead().");
  let out;
  if (n < 24) {
    out = Buffer.from([(major << 5) | n]);
  } else if (n < 256) {
    out = Buffer.from([(major << 5) | 24, n]);
  } else if (n < 65536) {
    out = Buffer.alloc(3);
    out[0] = (major << 5) | 25;
    out.writeUInt16BE(n, 1);
  } else {
    out = Buffer.alloc(5);
    out[0] = (major << 5) | 26;
    out.writeUInt32BE(n, 1);
  }
  log.debug("Leaving cborHead().");
  return out;
}

function cbor(value) {
  log.debug("Entering cbor().");
  let out;
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    const b = Buffer.from(value);
    out = Buffer.concat([cborHead(2, b.length), b]);
  } else if (typeof value === 'string') {
    const b = Buffer.from(value, 'utf8');
    out = Buffer.concat([cborHead(3, b.length), b]);
  } else if (typeof value === 'number') {
    out = value >= 0 ? cborHead(0, value) : cborHead(1, -1 - value);
  } else if (typeof value === 'boolean') {
    out = Buffer.from([value ? 0xf5 : 0xf4]);
  } else if (value === null) {
    out = Buffer.from([0xf6]);
  } else if (Array.isArray(value)) {
    out = Buffer.concat([cborHead(4, value.length)]
      .concat(value.map(cbor)));
  } else {
    const entries = value instanceof Map ? Array.from(value.entries())
      : Object.keys(value).map(function (k) { return [k, value[k]]; });
    out = Buffer.concat([cborHead(5, entries.length)].concat(
      entries.map(function (kv) {
        return Buffer.concat([cbor(kv[0]), cbor(kv[1])]);
      })));
  }
  log.debug("Leaving cbor().");
  return out;
}

// ----- keys and certificates -------------------------------------------------

const EC = { name: 'ECDSA', namedCurve: 'P-256' };
const RSA = { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048,
              publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' };

async function keyPair(kind) {
  log.debug("Entering keyPair(). " + kind);
  const pair = await webcrypto.subtle.generateKey(kind === 'rsa' ? RSA : EC,
                                                  true, ['sign', 'verify']);
  log.debug("Leaving keyPair().");
  return { crypto: pair,
           privateKey: nodeCrypto.KeyObject.from(pair.privateKey),
           publicKey: nodeCrypto.KeyObject.from(pair.publicKey) };
}

function attribute(type, value, printable) {
  log.debug("Entering attribute().");
  log.debug("Leaving attribute().");
  return new pkijs.AttributeTypeAndValue({
    type: type,
    value: printable ? new asn1js.PrintableString({ value: value })
                     : new asn1js.Utf8String({ value: value }) });
}

// A DN from [[oid, value], ...]; `C` (2.5.4.6) as a PrintableString.
function dn(pairs) {
  log.debug("Entering dn().");
  const name = new pkijs.RelativeDistinguishedNames();
  (pairs || []).forEach(function (p) {
    name.typesAndValues.push(attribute(p[0], p[1], p[0] === '2.5.4.6'));
  });
  log.debug("Leaving dn().");
  return name;
}

function extension(oid, critical, der) {
  log.debug("Entering extension().");
  log.debug("Leaving extension().");
  return new pkijs.Extension({ extnID: oid, critical: !!critical,
    extnValue: der instanceof ArrayBuffer ? der
      : new Uint8Array(Buffer.from(der)).buffer });
}

// A certificate: `subject` pairs, the key it certifies (a webcrypto public
// key), the issuer (`{ cert, key }` or null for self-signed), `ca`, and any
// extra `extensions`. Answers `{ der, pem, pkijs }`.
async function certificate(o) {
  log.debug("Entering certificate().");
  const cert = new pkijs.Certificate();
  cert.version = 2;
  cert.serialNumber = new asn1js.Integer({
    valueHex: new Uint8Array(Buffer.concat([Buffer.from([1]),
                                            nodeCrypto.randomBytes(8)])) });
  cert.subject = dn(o.subject);
  cert.issuer = o.issuer ? o.issuer.pkijs.subject : cert.subject;
  cert.notBefore.value = new Date(Date.now() - 3600 * 1000);
  cert.notAfter.value = new Date(Date.now() + (o.expired ? -1800 * 1000
                                                         : 365 * 86400000));
  cert.extensions = [];
  if (o.ca !== undefined) {
    cert.extensions.push(extension('2.5.29.19', true,
      new pkijs.BasicConstraints({ cA: !!o.ca }).toSchema().toBER(false)));
  }
  if (o.ca) {
    cert.extensions.push(extension('2.5.29.15', true,
      new asn1js.BitString({ valueHex: new Uint8Array([0x06]).buffer,
                             unusedBits: 1 }).toBER(false)));
  }
  (o.extensions || []).forEach(function (e) {
    cert.extensions.push(e);
  });
  if (o.crl) {
    // A CRL distribution point, for the revocation tests.
    cert.extensions.push(extension('2.5.29.31', false,
      new pkijs.CRLDistributionPoints({ distributionPoints: [
        new pkijs.DistributionPoint({ distributionPoint: [
          new pkijs.GeneralName({ type: 6, value: o.crl })] })] })
        .toSchema().toBER(false)));
  }
  await cert.subjectPublicKeyInfo.importKey(o.publicKey);
  await cert.sign(o.issuer ? o.issuer.signingKey : o.signingKey, 'SHA-256');
  const der = Buffer.from(cert.toSchema(true).toBER(false));
  log.debug("Leaving certificate().");
  return { der: der, pkijs: cert,
           pem: '-----BEGIN CERTIFICATE-----\n' +
                der.toString('base64').replace(/(.{64})/g, '$1\n') +
                '\n-----END CERTIFICATE-----\n' };
}

// A root CA of its own name: `{ der, pem, pkijs, signingKey }`.
async function root(name, kind) {
  log.debug("Entering root(). " + name);
  const pair = await keyPair(kind || 'ec');
  const made = await certificate({ subject: [['2.5.4.3', name + ' Root']],
                                   publicKey: pair.crypto.publicKey,
                                   signingKey: pair.crypto.privateKey,
                                   ca: true });
  made.signingKey = pair.crypto.privateKey;
  log.debug("Leaving root().");
  return made;
}

// ----- the credential --------------------------------------------------------

// A credential key pair and its COSE key, for `alg` (a COSE identifier).
async function credential(alg) {
  log.debug("Entering credential(). alg=" + alg);
  const a = Number(alg || -7);
  let out;
  if (a === -7) {
    const pair = await keyPair('ec');
    const jwk = pair.publicKey.export({ format: 'jwk' });
    out = { pair: pair, sign: function (data) {
      return nodeCrypto.sign('sha256', data, pair.privateKey);
    }, cose: new Map([[1, 2], [3, -7], [-1, 1],
                      [-2, Buffer.from(jwk.x, 'base64url')],
                      [-3, Buffer.from(jwk.y, 'base64url')]]) };
  } else if (a === -257 || a === -37) {
    const pair = nodeCrypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const jwk = pair.publicKey.export({ format: 'jwk' });
    out = { pair: pair, sign: function (data) {
      return a === -257
        ? nodeCrypto.sign('sha256', data, pair.privateKey)
        : nodeCrypto.sign('sha256', data, { key: pair.privateKey,
            padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING,
            saltLength: 32 });
    }, cose: new Map([[1, 3], [3, a], [-1, Buffer.from(jwk.n, 'base64url')],
                      [-2, Buffer.from(jwk.e, 'base64url')]]) };
  } else if (a === -8) {
    const pair = nodeCrypto.generateKeyPairSync('ed25519');
    const jwk = pair.publicKey.export({ format: 'jwk' });
    out = { pair: pair, sign: function (data) {
      return nodeCrypto.sign(null, data, pair.privateKey);
    }, cose: new Map([[1, 1], [3, -8], [-1, 6],
                      [-2, Buffer.from(jwk.x, 'base64url')]]) };
  } else {
    const name = { '-48': 'ML-DSA-44', '-49': 'ML-DSA-65',
                   '-50': 'ML-DSA-87' }[String(a)];
    const pair = pqJose.generate(name);
    out = { pair: pair, sign: function (data) {
      return pqJose.sign(name, pair.priv, data);
    }, cose: new Map([[1, 7], [3, a], [-1, Buffer.from(pair.pub)]]) };
  }
  out.alg = a;
  out.id = nodeCrypto.randomBytes(32);
  log.debug("Leaving credential().");
  return out;
}

// ----- the ceremony ----------------------------------------------------------

function sha256(data) {
  log.debug("Entering sha256().");
  log.debug("Leaving sha256().");
  return nodeCrypto.createHash('sha256').update(data).digest();
}

// Authenticator data with attested credential data.
function authenticatorData(o) {
  log.debug("Entering authenticatorData().");
  const count = Buffer.alloc(4);
  count.writeUInt32BE(Number(o.signCount || 0), 0);
  const idLength = Buffer.alloc(2);
  idLength.writeUInt16BE(o.credentialId.length, 0);
  log.debug("Leaving authenticatorData().");
  return Buffer.concat([sha256(Buffer.from(o.rpId, 'utf8')),
                        Buffer.from([o.flags === undefined ? 0x45 : o.flags]),
                        count, o.aaguid || Buffer.alloc(16), idLength,
                        o.credentialId, cbor(o.cose)]);
}

// ----- the formats -----------------------------------------------------------

const AAGUID_EXT = '1.3.6.1.4.1.45724.1.1.4';

function aaguidExtension(aaguid, critical) {
  log.debug("Entering aaguidExtension().");
  log.debug("Leaving aaguidExtension().");
  return extension(AAGUID_EXT, critical, new asn1js.OctetString({
    valueHex: new Uint8Array(aaguid).buffer }).toBER(false));
}

// packed, Basic: an attestation certificate under `anchor` (section 8.2.1's
// subject, CA false, the AAGUID extension). spoil: 'signature', 'ou',
// 'aaguid-extension', 'ca'. `crl` names a distribution point.
async function packed(ctx, anchor, spoil, crl) {
  log.debug("Entering packed().");
  const att = await keyPair('ec');
  const leaf = await certificate({
    subject: [['2.5.4.6', 'US'], ['2.5.4.10', 'Synthetic Vendor'],
              ['2.5.4.11', spoil === 'ou' ? 'Something Else'
                                          : 'Authenticator Attestation'],
              ['2.5.4.3', 'Synthetic Attestation']],
    publicKey: att.crypto.publicKey, issuer: anchor, crl: crl,
    ca: spoil === 'ca' ? true : false,
    extensions: [aaguidExtension(spoil === 'aaguid-extension'
      ? Buffer.alloc(16, 0xee) : ctx.aaguid)] });
  const signed = Buffer.concat([ctx.authData, ctx.clientDataHash]);
  let sig = nodeCrypto.sign('sha256', signed, att.privateKey);
  if (spoil === 'signature') {
    sig = nodeCrypto.sign('sha256', Buffer.from('something else'),
                          att.privateKey);
  }
  log.debug("Leaving packed().");
  return { fmt: 'packed', attStmt: { alg: -7, sig: sig, x5c: [leaf.der] },
           leaf: leaf };
}

// packed, Self. spoil: 'alg', 'signature'.
function packedSelf(ctx, spoil) {
  log.debug("Entering packedSelf().");
  const signed = Buffer.concat([ctx.authData, ctx.clientDataHash]);
  const sig = ctx.credential.sign(spoil === 'signature'
    ? Buffer.concat([signed, Buffer.from([0])]) : signed);
  log.debug("Leaving packedSelf().");
  return { fmt: 'packed', attStmt: {
    alg: spoil === 'alg' ? (ctx.credential.alg === -7 ? -257 : -7)
                         : ctx.credential.alg, sig: sig } };
}

// A TPM2B: a 16-bit size and the bytes.
function tpm2b(bytes) {
  log.debug("Entering tpm2b().");
  const b = Buffer.from(bytes || []);
  const size = Buffer.alloc(2);
  size.writeUInt16BE(b.length, 0);
  log.debug("Leaving tpm2b().");
  return Buffer.concat([size, b]);
}

function u16(n) {
  log.debug("Entering u16().");
  const b = Buffer.alloc(2);
  b.writeUInt16BE(n, 0);
  log.debug("Leaving u16().");
  return b;
}

function u32(n) {
  log.debug("Entering u32().");
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n >>> 0, 0);
  log.debug("Leaving u32().");
  return b;
}

// tpm, AttCA: an ECC TPMT_PUBLIC for the (P-256) credential, a TPMS_ATTEST
// certifying it, an RSA AIK certificate under `anchor` (empty subject, the
// TPM's SAN, tcg-kp-AIKCertificate) and an RSASSA TPMT_SIGNATURE. spoil:
// 'extra-data', 'name', 'magic', 'signature', 'eku', 'subject', 'key',
// 'bare-signature' (valid: the signature without its TPMT_SIGNATURE).
async function tpm(ctx, anchor, spoil) {
  log.debug("Entering tpm().");
  const x = ctx.credential.cose.get(-2);
  const y = spoil === 'key' ? Buffer.alloc(32, 7) : ctx.credential.cose.get(-3);
  const pubArea = Buffer.concat([
    u16(0x0023), u16(0x000b), u32(0x00060472), tpm2b(Buffer.alloc(0)),
    u16(0x0010), u16(0x0010), u16(0x0003), u16(0x0010),
    tpm2b(x), tpm2b(y)]);
  const signed = Buffer.concat([ctx.authData, ctx.clientDataHash]);
  const name = Buffer.concat([u16(0x000b), sha256(pubArea)]);
  const certInfo = Buffer.concat([
    u32(spoil === 'magic' ? 0xff544348 : 0xff544347), u16(0x8017),
    tpm2b(Buffer.concat([u16(0x000b), nodeCrypto.randomBytes(32)])),
    tpm2b(spoil === 'extra-data' ? sha256(Buffer.from('another ceremony'))
                                 : sha256(signed)),
    Buffer.alloc(17), Buffer.alloc(8),
    tpm2b(spoil === 'name' ? Buffer.concat([u16(0x000b),
                                            nodeCrypto.randomBytes(32)])
                           : name),
    tpm2b(Buffer.concat([u16(0x000b), nodeCrypto.randomBytes(32)]))]);
  const aik = await keyPair('rsa');
  const san = new pkijs.GeneralNames({ names: [new pkijs.GeneralName({
    type: 4, value: dn([['2.23.133.2.1', 'id:53594E54'],
                        ['2.23.133.2.2', 'Synthetic TPM'],
                        ['2.23.133.2.3', 'id:00020000']]) })] });
  const leaf = await certificate({
    subject: spoil === 'subject' ? [['2.5.4.3', 'not empty']] : [],
    publicKey: aik.crypto.publicKey, issuer: anchor, ca: false,
    extensions: [
      extension('2.5.29.17', true, san.toSchema().toBER(false)),
      extension('2.5.29.37', false, new pkijs.ExtKeyUsage({
        keyPurposes: [spoil === 'eku' ? '1.3.6.1.5.5.7.3.2'
                                      : '2.23.133.8.3'] })
        .toSchema().toBER(false)),
      aaguidExtension(ctx.aaguid)] });
  let raw = nodeCrypto.sign('sha256', certInfo, aik.privateKey);
  if (spoil === 'signature') {
    raw = nodeCrypto.sign('sha256', Buffer.from('not certInfo'),
                          aik.privateKey);
  }
  const sig = spoil === 'bare-signature' ? raw
    : Buffer.concat([u16(0x0014), u16(0x000b), tpm2b(raw)]);
  log.debug("Leaving tpm().");
  return { fmt: 'tpm', attStmt: { ver: '2.0', alg: -257, x5c: [leaf.der],
                                  sig: sig, certInfo: certInfo,
                                  pubArea: pubArea },
           leaf: leaf };
}

// Android's KeyDescription. `lists` are `{ purpose, origin,
// allApplications }` for the software- and the hardware-enforced list.
function keyDescription(challenge, software, hardware) {
  log.debug("Entering keyDescription().");
  const list = function (l) {
    log.debug("Entering list().");
    const fields = [];
    if (l.purpose) {
      fields.push(new asn1js.Constructed({
        idBlock: { tagClass: 3, tagNumber: 1 },
        value: [new asn1js.Set({ value: l.purpose.map(function (p) {
          return new asn1js.Integer({ value: p });
        }) })] }));
    }
    if (l.allApplications) {
      fields.push(new asn1js.Constructed({
        idBlock: { tagClass: 3, tagNumber: 600 },
        value: [new asn1js.Null()] }));
    }
    if (l.origin !== undefined) {
      fields.push(new asn1js.Constructed({
        idBlock: { tagClass: 3, tagNumber: 702 },
        value: [new asn1js.Integer({ value: l.origin })] }));
    }
    log.debug("Leaving list().");
    return new asn1js.Sequence({ value: fields });
  };
  log.debug("Leaving keyDescription().");
  return new asn1js.Sequence({ value: [
    new asn1js.Integer({ value: 200 }), new asn1js.Enumerated({ value: 1 }),
    new asn1js.Integer({ value: 200 }), new asn1js.Enumerated({ value: 1 }),
    new asn1js.OctetString({ valueHex: new Uint8Array(challenge).buffer }),
    new asn1js.OctetString({ valueHex: new ArrayBuffer(0) }),
    list(software), list(hardware)] }).toBER(false);
}

// android-key, Basic: the credential key certified, KeyDescription beside
// it. spoil: 'challenge', 'all-applications', 'software-origin' (origin
// only in the software list), 'purpose', 'key'.
async function androidKey(ctx, anchor, spoil) {
  log.debug("Entering androidKey().");
  const software = spoil === 'software-origin'
    ? { origin: 0, purpose: [2] } : {};
  const hardware = spoil === 'software-origin' ? {}
    : { purpose: spoil === 'purpose' ? [2, 3] : [2], origin: 0,
        allApplications: spoil === 'all-applications' };
  const certified = spoil === 'key' ? (await keyPair('ec')).crypto.publicKey
                                    : ctx.credential.pair.crypto.publicKey;
  const leaf = await certificate({
    subject: [['2.5.4.3', 'Android Keystore Key']],
    publicKey: certified, issuer: anchor, ca: false,
    extensions: [extension('1.3.6.1.4.1.11129.2.1.17', false,
      keyDescription(spoil === 'challenge' ? sha256(Buffer.from('no'))
                                           : ctx.clientDataHash,
                     software, hardware))] });
  log.debug("Leaving androidKey().");
  return { fmt: 'android-key', leaf: leaf, attStmt: {
    alg: -7, x5c: [leaf.der],
    sig: ctx.credential.sign(Buffer.concat([ctx.authData,
                                            ctx.clientDataHash])) } };
}

// android-safetynet, Basic: a JWS from "attest.android.com". spoil:
// 'nonce', 'cts', 'stale', 'signature', 'host'.
async function safetynet(ctx, anchor, spoil) {
  log.debug("Entering safetynet().");
  const signer = await keyPair('rsa');
  const leaf = await certificate({
    subject: [['2.5.4.3', spoil === 'host' ? 'attest.example.com'
                                           : 'attest.android.com']],
    publicKey: signer.crypto.publicKey, issuer: anchor, ca: false });
  const header = Buffer.from(JSON.stringify({ alg: 'RS256',
    x5c: [leaf.der.toString('base64')] })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({
    nonce: spoil === 'nonce' ? sha256(Buffer.from('x')).toString('base64')
      : sha256(Buffer.concat([ctx.authData, ctx.clientDataHash]))
        .toString('base64'),
    timestampMs: Date.now() - (spoil === 'stale' ? 10 * 60 * 1000 : 0),
    apkPackageName: 'com.google.android.gms',
    ctsProfileMatch: spoil !== 'cts', basicIntegrity: true
  })).toString('base64url');
  let signature = nodeCrypto.sign('sha256',
    Buffer.from(header + '.' + payload), signer.privateKey);
  if (spoil === 'signature') {
    signature = Buffer.from(signature);
    signature[10] ^= 1;
  }
  log.debug("Leaving safetynet().");
  return { fmt: 'android-safetynet', leaf: leaf, attStmt: {
    ver: '214815028',
    response: Buffer.from(header + '.' + payload + '.' +
                          signature.toString('base64url')) } };
}

// fido-u2f: a P-256 attestation certificate and the U2F registration
// message's signature. spoil: 'signature', 'two-certificates'.
async function fidoU2f(ctx, anchor, spoil) {
  log.debug("Entering fidoU2f().");
  const att = await keyPair('ec');
  const leaf = await certificate({
    subject: [['2.5.4.3', 'Synthetic U2F Attestation']],
    publicKey: att.crypto.publicKey, issuer: anchor, ca: false });
  const message = Buffer.concat([
    Buffer.from([0x00]), sha256(Buffer.from(ctx.rpId, 'utf8')),
    ctx.clientDataHash, ctx.credential.id, Buffer.from([0x04]),
    ctx.credential.cose.get(-2), ctx.credential.cose.get(-3)]);
  const sig = nodeCrypto.sign('sha256', spoil === 'signature'
    ? Buffer.concat([message, Buffer.from([1])]) : message, att.privateKey);
  log.debug("Leaving fidoU2f().");
  return { fmt: 'fido-u2f', leaf: leaf, attStmt: {
    x5c: spoil === 'two-certificates' ? [leaf.der, anchor.der] : [leaf.der],
    sig: sig } };
}

// apple, AnonCA: a certificate for the credential key carrying the nonce.
// spoil: 'nonce', 'key'.
async function apple(ctx, anchor, spoil) {
  log.debug("Entering apple().");
  const nonce = spoil === 'nonce' ? sha256(Buffer.from('another'))
    : sha256(Buffer.concat([ctx.authData, ctx.clientDataHash]));
  const value = new asn1js.Sequence({ value: [new asn1js.Constructed({
    idBlock: { tagClass: 3, tagNumber: 1 },
    value: [new asn1js.OctetString({
      valueHex: new Uint8Array(nonce).buffer })] })] }).toBER(false);
  const certified = spoil === 'key' ? (await keyPair('ec')).crypto.publicKey
                                    : ctx.credential.pair.crypto.publicKey;
  const leaf = await certificate({
    subject: [['2.5.4.3', 'Synthetic Apple Anonymous']],
    publicKey: certified, issuer: anchor, ca: false,
    extensions: [extension('1.2.840.113635.100.8.2', false, value)] });
  log.debug("Leaving apple().");
  return { fmt: 'apple', leaf: leaf, attStmt: { x5c: [leaf.der] } };
}

// A ceremony: the credential, the authenticator data and client data it was
// made over, and — through `build(formatFn)` — an attestation object and the
// `verifyRegistration()` input for it.
async function ceremony(o) {
  log.debug("Entering ceremony().");
  const opts = o || {};
  const cred = await credential(opts.alg || -7);
  const rpId = opts.rpId || 'localhost';
  const origin = opts.origin || 'https://localhost:8081';
  const challenge = nodeCrypto.randomBytes(32).toString('base64url');
  const aaguid = opts.aaguid === undefined ? nodeCrypto.randomBytes(16)
                                           : opts.aaguid;
  const authData = authenticatorData({ rpId: rpId, credentialId: cred.id,
                                       cose: cred.cose, aaguid: aaguid,
                                       flags: opts.flags });
  const clientDataJSON = Buffer.from(JSON.stringify({
    type: 'webauthn.create', challenge: challenge, origin: origin,
    crossOrigin: false }));
  const ctx = { credential: cred, rpId: rpId, origin: origin,
                challenge: challenge, aaguid: aaguid, authData: authData,
                clientDataJSON: clientDataJSON,
                clientDataHash: sha256(clientDataJSON) };
  ctx.input = function (made) {
    log.debug("Entering input().");
    log.debug("Leaving input().");
    return {
      attestationObject: cbor(new Map([
        ['fmt', made.fmt], ['attStmt', made.attStmt],
        ['authData', authData]])).toString('base64url'),
      clientDataJSON: clientDataJSON.toString('base64url'),
      expectedChallenge: challenge, expectedOrigin: origin,
      expectedRpId: rpId, requireUserVerification: false
    };
  };
  log.debug("Leaving ceremony().");
  return ctx;
}

module.exports = {
  cbor: cbor,
  root: root,
  keyPair: keyPair,
  certificate: certificate,
  credential: credential,
  ceremony: ceremony,
  packed: packed,
  packedSelf: packedSelf,
  tpm: tpm,
  androidKey: androidKey,
  safetynet: safetynet,
  fidoU2f: fidoU2f,
  apple: apple,
  none: function () {
    log.debug("Entering none().");
    log.debug("Leaving none().");
    return { fmt: 'none', attStmt: {} };
  }
};
