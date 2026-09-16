// @ts-check
'use strict';
//
// File: scep_cms.js
//
// ===========================================================================
// THE CMS ENVELOPE SCEP SPEAKS (RFC 8894 section 3, over RFC 5652), READ AND
// WRITTEN — AND NOTHING ELSE.
//
// A SCEP message is a pkiMessage: a CMS SignedData whose signed attributes say
// what the message is (messageType, transactionID, senderNonce, and on a reply
// pkiStatus, failInfo and recipientNonce) and whose content is a CMS
// EnvelopedData encrypted to the RA — the pkcsPKIEnvelope — holding a PKCS#10
// request, an IssuerAndSubject or an IssuerAndSerialNumber. This file turns
// bytes into those facts and facts back into bytes. **It decides nothing**: who
// may have a certificate is `common/cert_enrollment.js`'s, what an operation
// means is `scep.js`'s, and which RA key opens an envelope is `scep_ra.js`'s.
//
// **IT IS A LIBRARY (rule 3)** — it registers no route and requires only npm
// packages, node's crypto and `helpers.js` (for its logger), so its place in
// the require order is not a place and it can join no cycle.
// `tests/scep_enrollment.js` drives it directly.
//
// ---------------------------------------------------------------------------
// WHY IT IS HERE AND NOT IN `common/crypto.js`, WHICH SAYS IT IS THE ONE PLACE
// THIS SERVICE ENCRYPTS AND DECRYPTS.
//
// That rule (3r) exists so a signature algorithm or a cipher has one policy.
// What this file adds is not a primitive but an ENVELOPE — the CMS structures
// SCEP alone in this service reads — and the primitives under it are node's
// own `sign`/`verify`/`publicEncrypt`/`privateDecrypt`/`createDecipheriv`, with
// every algorithm it accepts named in the tables below so that
// `admin-ui/crypto_metadata.js` reads them from here rather than from a
// paragraph. It is the arrangement `gnap/gnap_httpsig.js` has for RFC 9421.
//
// ---------------------------------------------------------------------------
// FOUR DECISIONS, EACH A REFUSAL SOMEBODY WILL MEET.
//
// 1. **THE DIGEST IS SHA-256, SHA-384 OR SHA-512.** RFC 8894 section 3.5.2
//    makes SHA-256 the one a server MUST support and `SCEPStandard` asserts it;
//    SHA-1 and MD5 are what old clients default to and what a collision can be
//    built for, and a signature over a request is the whole of SCEP's message
//    integrity. They are refused `badAlg` rather than quietly accepted, which
//    is the message a client can act on (`sscep -S sha256`).
//
// 2. **THE CONTENT CIPHER IS AES-CBC (128, 192 OR 256).** DES-EDE3-CBC is
//    what section 3.5.2 still permits and what an old client sends unless told
//    otherwise; it is a 64-bit block cipher (Sweet32) and it is refused
//    `badAlg` for the same reason (`sscep -E aes`). The reply is encrypted
//    with the cipher the request used, which is always an AES here.
//
// 3. **KEY TRANSPORT IS RSA — PKCS#1 v1.5 OR OAEP — AND THE v1.5 HALF IS
//    DECRYPTED WITH node-forge, NOT NODE.** Node 22 refuses
//    `privateDecrypt()` with `RSA_PKCS1_PADDING` outright ("no longer
//    supported for private decryption", CVE-2023-46809, the Marvin attack),
//    and PKCS#1 v1.5 is what every SCEP client in the field sends. So the
//    unwrap goes through forge's pure-javascript RSAES-PKCS1-v1_5, the same
//    one `crypto.js` uses for an XML Encryption `rsa-1_5` key. **A failed
//    unwrap is not reported as such**: it is replaced with random bytes of the
//    right length and decryption continues, so a padding error and a wrong
//    key both end as one "the content did not decrypt" — an answer that tells
//    a Bleichenbacher-style guesser nothing about the padding. RFC 3218
//    section 2.3.2's countermeasure, and the reason `openEnvelope()` has one
//    refusal where it could have had three.
//
// 4. **A SIGNED ATTRIBUTE SET IS VERIFIED OVER THE BYTES THAT ARRIVED**, with
//    the `[0] IMPLICIT` tag swapped for `SET OF` — never over a re-encoding. A
//    client that sorted its attributes differently from DER's rule signed the
//    bytes it sent; re-encoding them would check a signature over a document
//    the client never produced and refuse a correct request. The attributes
//    THIS file signs are DER-sorted, because some verifiers re-encode.
// ===========================================================================

const nodeCrypto = require('crypto');
const asn1js = require('asn1js');
const pkijs = require('pkijs');
const forge = require('node-forge');

const { log } = require('../common/helpers');

// ---------------------------------------------------------------------------
// THE VOCABULARY.
// ---------------------------------------------------------------------------
const OID = {
  data: '1.2.840.113549.1.7.1',
  signedData: '1.2.840.113549.1.7.2',
  envelopedData: '1.2.840.113549.1.7.3',
  contentType: '1.2.840.113549.1.9.3',
  messageDigest: '1.2.840.113549.1.9.4',
  signingTime: '1.2.840.113549.1.9.5',
  challengePassword: '1.2.840.113549.1.9.7',
  rsaEncryption: '1.2.840.113549.1.1.1',
  rsaesOaep: '1.2.840.113549.1.1.7',
  mgf1: '1.2.840.113549.1.1.8',
  subjectKeyIdentifier: '2.5.29.14',
  // RFC 8894 section 3.2.1, all under Verisign's arc.
  messageType: '2.16.840.1.113733.1.9.2',
  pkiStatus: '2.16.840.1.113733.1.9.3',
  failInfo: '2.16.840.1.113733.1.9.4',
  senderNonce: '2.16.840.1.113733.1.9.5',
  recipientNonce: '2.16.840.1.113733.1.9.6',
  transactionID: '2.16.840.1.113733.1.9.7'
};

// The digests a request may be signed over, by OID. Anything else is badAlg.
const DIGESTS = {
  '2.16.840.1.101.3.4.2.1': { id: 'sha256', label: 'SHA-256' },
  '2.16.840.1.101.3.4.2.2': { id: 'sha384', label: 'SHA-384' },
  '2.16.840.1.101.3.4.2.3': { id: 'sha512', label: 'SHA-512' }
};

// Two digests named only so a refusal can say what it refused.
const REFUSED_DIGESTS = {
  '1.3.14.3.2.26': 'SHA-1',
  '1.2.840.113549.2.5': 'MD5'
};

// The signature algorithms, by OID, and the digest each implies. The bare
// `rsaEncryption` OID is what most CMS signers put here and implies the digest
// named in `digestAlgorithm`.
const SIGNATURES = {
  '1.2.840.113549.1.1.1': { key: 'rsa', digest: null, label: 'RSA' },
  '1.2.840.113549.1.1.11': { key: 'rsa', digest: 'sha256',
                             label: 'sha256WithRSAEncryption' },
  '1.2.840.113549.1.1.12': { key: 'rsa', digest: 'sha384',
                             label: 'sha384WithRSAEncryption' },
  '1.2.840.113549.1.1.13': { key: 'rsa', digest: 'sha512',
                             label: 'sha512WithRSAEncryption' },
  '1.2.840.10045.4.3.2': { key: 'ec', digest: 'sha256',
                           label: 'ecdsa-with-SHA256' },
  '1.2.840.10045.4.3.3': { key: 'ec', digest: 'sha384',
                           label: 'ecdsa-with-SHA384' },
  '1.2.840.10045.4.3.4': { key: 'ec', digest: 'sha512',
                           label: 'ecdsa-with-SHA512' }
};

// The content ciphers, by OID.
const CIPHERS = {
  '2.16.840.1.101.3.4.1.2': { id: 'aes-128-cbc', keyBytes: 16,
                              label: 'AES-128-CBC' },
  '2.16.840.1.101.3.4.1.22': { id: 'aes-192-cbc', keyBytes: 24,
                               label: 'AES-192-CBC' },
  '2.16.840.1.101.3.4.1.42': { id: 'aes-256-cbc', keyBytes: 32,
                               label: 'AES-256-CBC' }
};

const REFUSED_CIPHERS = {
  '1.2.840.113549.3.7': 'DES-EDE3-CBC',
  '1.3.14.3.2.7': 'DES-CBC'
};

const OAEP_HASHES = {
  '1.3.14.3.2.26': 'sha1',
  '2.16.840.1.101.3.4.2.1': 'sha256',
  '2.16.840.1.101.3.4.2.2': 'sha384',
  '2.16.840.1.101.3.4.2.3': 'sha512'
};

const KEY_TRANSPORTS = ['RSAES-PKCS1-v1_5 (rsaEncryption)',
                       'RSAES-OAEP (SHA-1, SHA-256, SHA-384, SHA-512)'];

// RFC 8894 section 3.2.1.2 and 3.2.1.3.
const MESSAGE_TYPES = {
  3: 'CertRep', 17: 'RenewalReq', 19: 'PKCSReq', 20: 'CertPoll',
  21: 'GetCert', 22: 'GetCRL'
};

const PKI_STATUS = { SUCCESS: '0', FAILURE: '2', PENDING: '3' };

const FAIL_INFO = { badAlg: '0', badMessageCheck: '1', badRequest: '2',
                    badTime: '3', badCertId: '4' };

// RFC 8894 section 3.2.1.5: sixteen octets.
const NONCE_BYTES = 16;

// A transactionID is PrintableString and a client's own choice; a bound keeps
// it from being a way to grow a store.
const MAX_TRANSACTION_ID = 128;

// ---------------------------------------------------------------------------
// A REFUSAL. `stage` says which of the two answers the caller owes: 'http'
// when too little was read to build a CertRep, 'certrep' when the reply can
// be a signed FAILURE. `failInfo` is set for the second.
// ---------------------------------------------------------------------------
function refusal(code, why, failInfo, stage) {
  log.debug("Entering refusal(). code=" + code);
  log.debug("Leaving refusal().");
  return { ok: false, code: code, why: why,
           failInfo: failInfo || null, stage: stage || 'certrep' };
}

// ---------------------------------------------------------------------------
// BYTES.
// ---------------------------------------------------------------------------
function arrayBufferOf(bytes) {
  log.debug("Entering arrayBufferOf().");
  const buf = Buffer.from(bytes);
  log.debug("Leaving arrayBufferOf().");
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
}

function bufferOf(view) {
  log.debug("Entering bufferOf().");
  log.debug("Leaving bufferOf().");
  return Buffer.from(view || []);
}

// One complete BER value and nothing after it. A trailing byte is refused
// rather than ignored: bytes nobody signed riding along after a signed message
// are bytes two readers will disagree about.
function readOne(bytes) {
  log.debug("Entering readOne().");
  const buf = Buffer.from(bytes || []);
  if (!buf.length) {
    log.debug("Leaving readOne(). Empty.");
    return null;
  }
  let parsed = null;
  try {
    parsed = asn1js.fromBER(arrayBufferOf(buf));
  } catch (e) {
    log.debug("Caught in readOne(): " + ((e && e.message) || e));
    parsed = null;
  }
  if (!parsed || parsed.offset === -1 || parsed.offset !== buf.length ||
      parsed.result.error) {
    log.debug("Leaving readOne(). Not one value.");
    return null;
  }
  log.debug("Leaving readOne().");
  return parsed.result;
}

function children(node) {
  log.debug("Entering children().");
  const list = node && node.valueBlock && Array.isArray(node.valueBlock.value)
    ? node.valueBlock.value : [];
  log.debug("Leaving children().");
  return list;
}

function isUniversal(node, tagNumber) {
  log.debug("Entering isUniversal().");
  log.debug("Leaving isUniversal().");
  return !!(node && node.idBlock && node.idBlock.tagClass === 1 &&
            node.idBlock.tagNumber === tagNumber);
}

function isContext(node, tagNumber) {
  log.debug("Entering isContext().");
  log.debug("Leaving isContext().");
  return !!(node && node.idBlock && node.idBlock.tagClass === 3 &&
            node.idBlock.tagNumber === tagNumber);
}

function oidOf(node) {
  log.debug("Entering oidOf().");
  if (!isUniversal(node, 6)) {
    log.debug("Leaving oidOf(). Not an OID.");
    return '';
  }
  log.debug("Leaving oidOf().");
  return String(node.valueBlock.toString());
}

// The octets of an OCTET STRING, primitive or BER-constructed, or of an
// implicitly tagged one. OpenSSL streams a constructed, indefinite-length
// OCTET STRING for encapsulated content, so both shapes are ordinary.
function octetsOf(node) {
  log.debug("Entering octetsOf().");
  if (!node || !node.idBlock) {
    log.debug("Leaving octetsOf(). Nothing.");
    return null;
  }
  const constructed = node.idBlock.isConstructed ||
    (node.valueBlock && node.valueBlock.isConstructed);
  if (constructed) {
    const parts = [];
    const inner = children(node);
    for (let i = 0; i < inner.length; i++) {
      const one = octetsOf(inner[i]);
      if (one === null) {
        log.debug("Leaving octetsOf(). A malformed segment.");
        return null;
      }
      parts.push(one);
    }
    log.debug("Leaving octetsOf(). Constructed.");
    return Buffer.concat(parts);
  }
  const view = node.valueBlock && node.valueBlock.valueHexView;
  log.debug("Leaving octetsOf().");
  return view ? bufferOf(view) : null;
}

function rawOf(node) {
  log.debug("Entering rawOf().");
  log.debug("Leaving rawOf().");
  return bufferOf(node && node.valueBeforeDecodeView);
}

function stringOf(node) {
  log.debug("Entering stringOf().");
  if (!node || !node.valueBlock) {
    log.debug("Leaving stringOf().");
    return '';
  }
  const value = node.valueBlock.value;
  log.debug("Leaving stringOf().");
  return typeof value === 'string' ? value : '';
}

function derToPem(der, label) {
  log.debug("Entering derToPem().");
  log.debug("Leaving derToPem().");
  return '-----BEGIN ' + label + '-----\n' +
    Buffer.from(der).toString('base64').replace(/(.{64})/g, '$1\n')
      .replace(/\n$/, '') + '\n-----END ' + label + '-----\n';
}

function pemToDer(pem) {
  log.debug("Entering pemToDer().");
  log.debug("Leaving pemToDer().");
  return Buffer.from(String(pem || '').replace(/-----[^-]+-----/g, '')
    .replace(/\s+/g, ''), 'base64');
}

function hexOf(buf) {
  log.debug("Entering hexOf().");
  log.debug("Leaving hexOf().");
  return Buffer.from(buf || []).toString('hex');
}

// ---------------------------------------------------------------------------
// CERTIFICATES.
//
// The two things a CMS signer or recipient identifier is compared against —
// the issuer Name and the serial INTEGER — are read out of the certificate's
// own bytes, positionally, so the comparison is of bytes that were signed
// rather than of two re-encodings that happen to agree.
// ---------------------------------------------------------------------------
function describeCertificate(der) {
  log.debug("Entering describeCertificate().");
  const node = readOne(der);
  const tbs = children(node)[0];
  const parts = children(tbs);
  if (!isUniversal(node, 16) || !isUniversal(tbs, 16) || parts.length < 7) {
    log.debug("Leaving describeCertificate(). Not a certificate.");
    return null;
  }
  const offset = isContext(parts[0], 0) ? 1 : 0;
  let x509 = null;
  try {
    x509 = new nodeCrypto.X509Certificate(Buffer.from(der));
  } catch (e) {
    log.debug("Caught in describeCertificate(): " + ((e && e.message) || e));
    x509 = null;
  }
  if (!x509) {
    log.debug("Leaving describeCertificate(). Node could not read it.");
    return null;
  }
  let ski = null;
  try {
    const cert = pkijs.Certificate.fromBER(arrayBufferOf(der));
    (cert.extensions || []).forEach(function (ext) {
      if (ext.extnID === OID.subjectKeyIdentifier && !ski) {
        const inner = readOne(bufferOf(ext.extnValue.valueBlock.valueHexView));
        ski = inner ? octetsOf(inner) : null;
      }
    });
  } catch (e) {
    log.debug("Caught in describeCertificate(): " + ((e && e.message) || e));
    ski = null;
  }
  const spki = x509.publicKey.export({ type: 'spki', format: 'der' });
  log.debug("Leaving describeCertificate().");
  return {
    der: Buffer.from(der),
    pem: derToPem(der, 'CERTIFICATE'),
    x509: x509,
    serialRaw: octetsOf(parts[offset]),
    issuerRaw: rawOf(parts[offset + 2]),
    subjectRaw: rawOf(parts[offset + 4]),
    ski: ski,
    keyType: x509.publicKey.asymmetricKeyType,
    spkiSha256: nodeCrypto.createHash('sha256').update(spki).digest('hex'),
    selfIssued: rawOf(parts[offset + 2]).equals(rawOf(parts[offset + 4]))
  };
}

// Does an IssuerAndSerialNumber (or a [0] SubjectKeyIdentifier) name this
// certificate?
function identifies(sid, cert) {
  log.debug("Entering identifies().");
  if (!sid || !cert) {
    log.debug("Leaving identifies(). Nothing to compare.");
    return false;
  }
  if (isContext(sid, 0)) {
    const wanted = octetsOf(sid);
    log.debug("Leaving identifies(). By key identifier.");
    return !!(wanted && cert.ski && wanted.equals(cert.ski));
  }
  const parts = children(sid);
  if (!isUniversal(sid, 16) || parts.length !== 2) {
    log.debug("Leaving identifies(). Not an IssuerAndSerialNumber.");
    return false;
  }
  const serial = octetsOf(parts[1]);
  log.debug("Leaving identifies().");
  return rawOf(parts[0]).equals(cert.issuerRaw) &&
         !!serial && serial.equals(cert.serialRaw);
}

// ---------------------------------------------------------------------------
// READ A pkiMessage.
//
// Answers every fact `scep.js` needs, or a refusal whose `stage` is 'http'
// when not even a transactionID and a senderNonce could be read — without
// those a CertRep cannot be built, and RFC 8894 has no reply for a message it
// cannot name.
// ---------------------------------------------------------------------------
function attributeValues(attrs) {
  log.debug("Entering attributeValues().");
  const out = {};
  for (let i = 0; i < attrs.length; i++) {
    const parts = children(attrs[i]);
    const type = oidOf(parts[0]);
    if (!isUniversal(attrs[i], 16) || parts.length !== 2 || !type ||
        !isUniversal(parts[1], 17)) {
      log.debug("Leaving attributeValues(). A malformed attribute.");
      return null;
    }
    if (Object.prototype.hasOwnProperty.call(out, type)) {
      // A signed attribute given twice is refused rather than resolved:
      // which of two transactionIDs a reply echoes is not a choice to make.
      log.debug("Leaving attributeValues(). A repeated attribute.");
      return null;
    }
    const values = children(parts[1]);
    if (values.length !== 1) {
      log.debug("Leaving attributeValues(). Not single-valued.");
      return null;
    }
    out[type] = values[0];
  }
  log.debug("Leaving attributeValues().");
  return out;
}

function parsePkiMessage(bytes) {
  log.debug("Entering parsePkiMessage().");
  try {
    const parsed = readPkiMessage(bytes);
    log.debug("Leaving parsePkiMessage(). ok=" + parsed.ok);
    return parsed;
  } catch (e) {
    // Every structural check below is explicit, so a throw here is an input
    // shape asn1js or node rejected in a way nothing above anticipated. It is
    // a malformed message, never a 500.
    log.debug("Caught in parsePkiMessage(): " + ((e && e.message) || e));
    log.debug("Leaving parsePkiMessage(). Threw.");
    return refusal('STS-SCEP-0010', 'The message is not a readable CMS ' +
                   'SignedData.', null, 'http');
  }
}

function readPkiMessage(bytes) {
  log.debug("Entering readPkiMessage().");
  const outer = readOne(bytes);
  const outerParts = children(outer);
  if (!isUniversal(outer, 16) || outerParts.length !== 2 ||
      oidOf(outerParts[0]) !== OID.signedData || !isContext(outerParts[1], 0)) {
    log.debug("Leaving readPkiMessage(). Not a SignedData ContentInfo.");
    return refusal('STS-SCEP-0010', 'The message is not one complete CMS ' +
                   'ContentInfo carrying SignedData.', null, 'http');
  }
  const sd = children(outerParts[1])[0];
  const sdParts = children(sd);
  if (!isUniversal(sd, 16) || sdParts.length < 4) {
    log.debug("Leaving readPkiMessage(). Not a SignedData.");
    return refusal('STS-SCEP-0010', 'The SignedData is malformed.', null,
                   'http');
  }
  let at = 1;
  const digestSet = sdParts[at++];
  const encap = sdParts[at++];
  let certsNode = null;
  if (isContext(sdParts[at], 0)) {
    certsNode = sdParts[at++];
  }
  if (isContext(sdParts[at], 1)) {
    at++;
  }
  const signerSet = sdParts[at];
  if (!isUniversal(digestSet, 17) || !isUniversal(encap, 16) ||
      !isUniversal(signerSet, 17) || at !== sdParts.length - 1) {
    log.debug("Leaving readPkiMessage(). SignedData fields out of place.");
    return refusal('STS-SCEP-0010', 'The SignedData fields are not in the ' +
                   'order RFC 5652 section 5.1 defines.', null, 'http');
  }
  const encapParts = children(encap);
  const eContentType = oidOf(encapParts[0]);
  let content = null;
  if (encapParts.length === 2) {
    if (!isContext(encapParts[1], 0)) {
      log.debug("Leaving readPkiMessage(). eContent malformed.");
      return refusal('STS-SCEP-0010', 'The encapsulated content is ' +
                     'malformed.', null, 'http');
    }
    content = octetsOf(children(encapParts[1])[0]);
    if (content === null) {
      log.debug("Leaving readPkiMessage(). eContent is not an OCTET STRING.");
      return refusal('STS-SCEP-0010', 'The encapsulated content is not an ' +
                     'OCTET STRING.', null, 'http');
    }
  }
  const certificates = [];
  children(certsNode).forEach(function (one) {
    if (isUniversal(one, 16)) {
      const described = describeCertificate(rawOf(one));
      if (described) {
        certificates.push(described);
      }
    }
  });
  const signers = children(signerSet);
  if (signers.length !== 1) {
    log.debug("Leaving readPkiMessage(). " + signers.length + " signers.");
    return refusal('STS-SCEP-0011', 'A SCEP message has exactly one signer, ' +
                   'and this one has ' + signers.length + '.', null, 'http');
  }
  const si = children(signers[0]);
  if (!isUniversal(signers[0], 16) || si.length < 5) {
    log.debug("Leaving readPkiMessage(). SignerInfo malformed.");
    return refusal('STS-SCEP-0011', 'The SignerInfo is malformed.', null,
                   'http');
  }
  let s = 1;
  const sid = si[s++];
  const digestAlg = oidOf(children(si[s++])[0]);
  const signedAttrsNode = isContext(si[s], 0) ? si[s++] : null;
  const sigAlgNode = si[s++];
  const signatureNode = si[s++];
  if (!signedAttrsNode) {
    log.debug("Leaving readPkiMessage(). No signed attributes.");
    return refusal('STS-SCEP-0012', 'The signer carries no signed ' +
                   'attributes, so the message has no messageType, ' +
                   'transactionID or senderNonce (RFC 8894 section 3.2.1).',
                   null, 'http');
  }
  const attrs = attributeValues(children(signedAttrsNode));
  if (!attrs) {
    log.debug("Leaving readPkiMessage(). Signed attributes malformed.");
    return refusal('STS-SCEP-0012', 'The signed attributes are malformed or ' +
                   'repeat an attribute.', null, 'http');
  }
  const transactionID = stringOf(attrs[OID.transactionID]);
  const senderNonce = octetsOf(attrs[OID.senderNonce]);
  const messageTypeText = stringOf(attrs[OID.messageType]);
  if (!transactionID || transactionID.length > MAX_TRANSACTION_ID ||
      !/^[A-Za-z0-9 '()+,\-./:=?]+$/.test(transactionID)) {
    log.debug("Leaving readPkiMessage(). transactionID.");
    return refusal('STS-SCEP-0012', 'The transactionID is missing, is not a ' +
                   'PrintableString, or is longer than ' + MAX_TRANSACTION_ID +
                   ' characters.', null, 'http');
  }
  if (!senderNonce || senderNonce.length !== NONCE_BYTES) {
    log.debug("Leaving readPkiMessage(). senderNonce.");
    return refusal('STS-SCEP-0012', 'The senderNonce is missing or is not ' +
                   NONCE_BYTES + ' octets (RFC 8894 section 3.2.1.5).', null,
                   'http');
  }
  const signer = certificates.filter(function (one) {
    return identifies(sid, one);
  });
  log.debug("Leaving readPkiMessage(). transactionID=" + transactionID);
  return {
    ok: true,
    transactionID: transactionID,
    senderNonce: senderNonce,
    messageTypeText: messageTypeText,
    messageType: /^\d{1,3}$/.test(messageTypeText) ? Number(messageTypeText)
                                                    : null,
    pkiStatus: stringOf(attrs[OID.pkiStatus]),
    failInfo: stringOf(attrs[OID.failInfo]),
    recipientNonce: attrs[OID.recipientNonce]
      ? octetsOf(attrs[OID.recipientNonce]) : null,
    contentTypeAttr: oidOf(attrs[OID.contentType]),
    messageDigestAttr: attrs[OID.messageDigest]
      ? octetsOf(attrs[OID.messageDigest]) : null,
    eContentType: eContentType,
    content: content,
    certificates: certificates,
    signer: signer.length === 1 ? signer[0] : null,
    signerMatches: signer.length,
    digestAlg: digestAlg,
    signatureAlg: oidOf(children(sigAlgNode)[0]),
    signature: octetsOf(signatureNode),
    signedAttrsRaw: rawOf(signedAttrsNode)
  };
}

// ---------------------------------------------------------------------------
// VERIFY THE SIGNER. Every failure is a CertRep FAILURE with a failInfo.
// ---------------------------------------------------------------------------
function verifySigner(message) {
  log.debug("Entering verifySigner().");
  if (!message.signer) {
    log.debug("Leaving verifySigner(). No signer certificate.");
    return refusal('STS-SCEP-0011', 'The signer\'s certificate is not among ' +
                   'the certificates in the SignedData (' +
                   message.signerMatches + ' match), so the signature cannot ' +
                   'be checked.', FAIL_INFO.badMessageCheck);
  }
  const digest = DIGESTS[message.digestAlg];
  if (!digest) {
    log.debug("Leaving verifySigner(). Digest refused.");
    return refusal('STS-SCEP-0020', 'The message is signed over ' +
                   (REFUSED_DIGESTS[message.digestAlg] ||
                    'an unknown digest (' + message.digestAlg + ')') +
                   '. This server accepts SHA-256, SHA-384 and SHA-512.',
                   FAIL_INFO.badAlg);
  }
  const sig = SIGNATURES[message.signatureAlg];
  if (!sig || (sig.digest && sig.digest !== digest.id) ||
      sig.key !== message.signer.keyType) {
    log.debug("Leaving verifySigner(). Signature algorithm refused.");
    return refusal('STS-SCEP-0021', 'The signature algorithm (' +
                   message.signatureAlg + ') is not one this server ' +
                   'verifies, or does not agree with the digest algorithm ' +
                   'or the signer\'s key.', FAIL_INFO.badAlg);
  }
  if (message.contentTypeAttr !== message.eContentType ||
      message.eContentType !== OID.data) {
    log.debug("Leaving verifySigner(). contentType.");
    return refusal('STS-SCEP-0024', 'The contentType signed attribute does ' +
                   'not name id-data, or does not agree with the ' +
                   'encapsulated content.', FAIL_INFO.badMessageCheck);
  }
  const computed = nodeCrypto.createHash(digest.id)
    .update(message.content || Buffer.alloc(0)).digest();
  const claimed = message.messageDigestAttr;
  if (!claimed || claimed.length !== computed.length ||
      !nodeCrypto.timingSafeEqual(claimed, computed)) {
    log.debug("Leaving verifySigner(). messageDigest.");
    return refusal('STS-SCEP-0022', 'The messageDigest signed attribute is ' +
                   'not the digest of the encapsulated content.',
                   FAIL_INFO.badMessageCheck);
  }
  const signedBytes = Buffer.from(message.signedAttrsRaw);
  signedBytes[0] = 0x31;
  let verified = false;
  try {
    verified = nodeCrypto.verify(digest.id, signedBytes,
                                 message.signer.x509.publicKey,
                                 message.signature || Buffer.alloc(0));
  } catch (e) {
    log.debug("Caught in verifySigner(): " + ((e && e.message) || e));
    verified = false;
  }
  if (!verified) {
    log.debug("Leaving verifySigner(). The signature does not verify.");
    return refusal('STS-SCEP-0023', 'The signature over the signed ' +
                   'attributes does not verify with the signer\'s ' +
                   'certificate.', FAIL_INFO.badMessageCheck);
  }
  const nowMs = Date.now();
  if (new Date(message.signer.x509.validFrom).getTime() > nowMs + 300000 ||
      new Date(message.signer.x509.validTo).getTime() < nowMs) {
    log.debug("Leaving verifySigner(). Outside its validity.");
    return refusal('STS-SCEP-0046', 'The signer\'s certificate is not valid ' +
                   'now (' + message.signer.x509.validFrom + ' to ' +
                   message.signer.x509.validTo + ').', FAIL_INFO.badTime);
  }
  log.debug("Leaving verifySigner(). " + digest.label + ", " + sig.label);
  return { ok: true, digest: digest.id };
}

// ---------------------------------------------------------------------------
// OPEN THE pkcsPKIEnvelope with the RA's certificate and private key.
// ---------------------------------------------------------------------------
function unwrapKey(algorithmNode, encryptedKey, raPrivateKeyPem, keyBytes) {
  log.debug("Entering unwrapKey().");
  const algParts = children(algorithmNode);
  const algorithm = oidOf(algParts[0]);
  if (algorithm === OID.rsaEncryption) {
    let key = null;
    try {
      const forgeKey = forge.pki.privateKeyFromPem(raPrivateKeyPem);
      key = Buffer.from(forgeKey.decrypt(encryptedKey.toString('binary'),
                                         'RSAES-PKCS1-V1_5'), 'binary');
    } catch (e) {
      // THE IMPLICIT REJECTION — see the header, decision 3. The error is not
      // reported: random bytes of the right length take the key's place and
      // the content simply fails to decrypt, like a wrong key would.
      log.debug("Caught in unwrapKey(): " + ((e && e.message) || e));
      key = null;
    }
    if (!key || key.length !== keyBytes) {
      key = nodeCrypto.randomBytes(keyBytes);
    }
    log.debug("Leaving unwrapKey(). PKCS#1 v1.5.");
    return { ok: true, key: key, transport: 'rsaEncryption' };
  }
  if (algorithm === OID.rsaesOaep) {
    let hash = 'sha1';
    const params = children(algParts[1]);
    for (let i = 0; i < params.length; i++) {
      if (isContext(params[i], 0)) {
        const named = OAEP_HASHES[oidOf(children(children(params[i])[0])[0])];
        if (!named) {
          log.debug("Leaving unwrapKey(). OAEP hash refused.");
          return { ok: false, transport: 'rsaesOaep' };
        }
        hash = named;
      }
    }
    let key = null;
    try {
      key = nodeCrypto.privateDecrypt({
        key: raPrivateKeyPem,
        padding: nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: hash
      }, encryptedKey);
    } catch (e) {
      // OAEP has no padding oracle of v1.5's kind, and the same answer is
      // given anyway so that the two transports cannot be told apart.
      log.debug("Caught in unwrapKey(): " + ((e && e.message) || e));
      key = null;
    }
    if (!key || key.length !== keyBytes) {
      key = nodeCrypto.randomBytes(keyBytes);
    }
    log.debug("Leaving unwrapKey(). OAEP " + hash + ".");
    return { ok: true, key: key, transport: 'rsaesOaep-' + hash };
  }
  log.debug("Leaving unwrapKey(). Unknown transport " + algorithm);
  return { ok: false, transport: algorithm };
}

function openEnvelope(bytes, raCertificatePem, raPrivateKeyPem) {
  log.debug("Entering openEnvelope().");
  try {
    const opened = readEnvelope(bytes, raCertificatePem, raPrivateKeyPem);
    log.debug("Leaving openEnvelope(). ok=" + opened.ok);
    return opened;
  } catch (e) {
    log.debug("Caught in openEnvelope(): " + ((e && e.message) || e));
    log.debug("Leaving openEnvelope(). Threw.");
    return refusal('STS-SCEP-0026', 'The pkcsPKIEnvelope is not a readable ' +
                   'CMS EnvelopedData.', FAIL_INFO.badMessageCheck);
  }
}

function readEnvelope(bytes, raCertificatePem, raPrivateKeyPem) {
  log.debug("Entering readEnvelope().");
  const outer = readOne(bytes);
  const outerParts = children(outer);
  if (!isUniversal(outer, 16) || outerParts.length !== 2 ||
      oidOf(outerParts[0]) !== OID.envelopedData ||
      !isContext(outerParts[1], 0)) {
    log.debug("Leaving readEnvelope(). Not an EnvelopedData ContentInfo.");
    return refusal('STS-SCEP-0026', 'The content of the message is not a ' +
                   'CMS ContentInfo carrying EnvelopedData.',
                   FAIL_INFO.badMessageCheck);
  }
  const ed = children(outerParts[1])[0];
  const edParts = children(ed);
  let at = 1;
  if (isContext(edParts[at], 0)) {
    at++;
  }
  const recipientSet = edParts[at++];
  const eci = edParts[at];
  const eciParts = children(eci);
  if (!isUniversal(ed, 16) || !isUniversal(recipientSet, 17) ||
      !isUniversal(eci, 16) || eciParts.length !== 3 ||
      !isContext(eciParts[2], 0)) {
    log.debug("Leaving readEnvelope(). Fields out of place.");
    return refusal('STS-SCEP-0026', 'The EnvelopedData is malformed or has ' +
                   'no encrypted content.', FAIL_INFO.badMessageCheck);
  }
  const ra = describeCertificate(pemToDer(raCertificatePem));
  let mine = null;
  children(recipientSet).forEach(function (one) {
    const parts = children(one);
    // KeyTransRecipientInfo only: a version INTEGER, a rid, an AlgId and an
    // OCTET STRING. KeyAgree (an ECDH recipient) and the others are for keys
    // an RSA RA does not have.
    if (!mine && isUniversal(one, 16) && parts.length === 4 &&
        isUniversal(parts[0], 2) && identifies(parts[1], ra)) {
      mine = parts;
    }
  });
  if (!mine) {
    log.debug("Leaving readEnvelope(). Not encrypted to this RA.");
    return refusal('STS-SCEP-0027', 'The envelope is not encrypted to this ' +
                   'realm\'s current RA certificate. Fetch it again with ' +
                   'GetCACert.', FAIL_INFO.badMessageCheck);
  }
  const cipherAlg = oidOf(children(eciParts[1])[0]);
  const cipher = CIPHERS[cipherAlg];
  if (!cipher) {
    log.debug("Leaving readEnvelope(). Cipher refused.");
    return refusal('STS-SCEP-0029', 'The content is encrypted with ' +
                   (REFUSED_CIPHERS[cipherAlg] || 'an unknown cipher (' +
                    cipherAlg + ')') + '. This server accepts AES-128-CBC, ' +
                   'AES-192-CBC and AES-256-CBC.', FAIL_INFO.badAlg);
  }
  const iv = octetsOf(children(eciParts[1])[1]);
  const ciphertext = octetsOf(eciParts[2]);
  if (!iv || iv.length !== 16 || !ciphertext || !ciphertext.length ||
      ciphertext.length % 16 !== 0) {
    log.debug("Leaving readEnvelope(). IV or ciphertext malformed.");
    return refusal('STS-SCEP-0026', 'The content encryption parameters or ' +
                   'the ciphertext are malformed.', FAIL_INFO.badMessageCheck);
  }
  const unwrapped = unwrapKey(mine[2], octetsOf(mine[3]) || Buffer.alloc(0),
                              raPrivateKeyPem, cipher.keyBytes);
  if (!unwrapped.ok) {
    log.debug("Leaving readEnvelope(). Key transport refused.");
    return refusal('STS-SCEP-0028', 'The content key is transported with an ' +
                   'algorithm this server does not accept (' +
                   unwrapped.transport + '). It accepts RSAES-PKCS1-v1_5 and ' +
                   'RSAES-OAEP.', FAIL_INFO.badAlg);
  }
  let plain = null;
  try {
    const decipher = nodeCrypto.createDecipheriv(cipher.id, unwrapped.key, iv);
    plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch (e) {
    log.debug("Caught in readEnvelope(): " + ((e && e.message) || e));
    plain = null;
  }
  // AND THE PLAINTEXT MUST BE ONE DER VALUE. Every content a pkcsPKIEnvelope
  // holds is a SEQUENCE — a PKCS#10, an IssuerAndSubject, an
  // IssuerAndSerialNumber — and a wrong key (or the implicit rejection's
  // random one) passes AES-CBC's padding check about one time in 256. Without
  // this, that one time came back ok with garbage and the refusal arrived
  // later under a different code, so a padding failure and a wrong key were
  // two answers again (`tests/scep_enrollment.js` saw it as a flake).
  if (plain && !readOne(plain)) {
    log.debug("readEnvelope(): the content decrypted to no single DER value.");
    plain = null;
  }
  if (!plain) {
    log.debug("Leaving readEnvelope(). It did not decrypt.");
    return refusal('STS-SCEP-0030', 'The content did not decrypt with this ' +
                   'realm\'s RA key.', FAIL_INFO.badMessageCheck);
  }
  log.debug("Leaving readEnvelope(). " + plain.length + " bytes, " +
            cipher.label);
  return { ok: true, content: plain, cipher: cipherAlg,
           cipherLabel: cipher.label, transport: unwrapped.transport };
}

// ---------------------------------------------------------------------------
// THE TWO SMALL STRUCTURES A pkcsPKIEnvelope MAY HOLD INSTEAD OF A PKCS#10.
//
//   IssuerAndSubject      ::= SEQUENCE { issuer Name, subject Name }
//                             (CertPoll)
//   IssuerAndSerialNumber ::= SEQUENCE { issuer Name, serial INTEGER }
//                             (GetCert, GetCRL)
// ---------------------------------------------------------------------------
function readIssuerAndSomething(bytes, second) {
  log.debug("Entering readIssuerAndSomething().");
  const node = readOne(bytes);
  const parts = children(node);
  if (!isUniversal(node, 16) || parts.length !== 2 ||
      !isUniversal(parts[0], 16) || !isUniversal(parts[1], second)) {
    log.debug("Leaving readIssuerAndSomething(). Malformed.");
    return null;
  }
  log.debug("Leaving readIssuerAndSomething().");
  return { issuerRaw: rawOf(parts[0]),
           second: second === 2 ? octetsOf(parts[1]) : rawOf(parts[1]) };
}

function readIssuerAndSerial(bytes) {
  log.debug("Entering readIssuerAndSerial().");
  const read = readIssuerAndSomething(bytes, 2);
  log.debug("Leaving readIssuerAndSerial().");
  return read ? { issuerRaw: read.issuerRaw,
                  serialHex: hexOf(read.second) } : null;
}

function readIssuerAndSubject(bytes) {
  log.debug("Entering readIssuerAndSubject().");
  const read = readIssuerAndSomething(bytes, 16);
  log.debug("Leaving readIssuerAndSubject().");
  return read ? { issuerRaw: read.issuerRaw, subjectRaw: read.second } : null;
}

// ---------------------------------------------------------------------------
// WRITE.
// ---------------------------------------------------------------------------
function node(der) {
  log.debug("Entering node().");
  const parsed = readOne(der);
  if (!parsed) {
    log.debug("Leaving node(). Unreadable.");
    throw new Error('an internal structure did not re-read as DER');
  }
  log.debug("Leaving node().");
  return parsed;
}

function algorithmIdentifier(oid, withNull) {
  log.debug("Entering algorithmIdentifier().");
  log.debug("Leaving algorithmIdentifier().");
  return new asn1js.Sequence({ value: /** @type {any[]} */ ([
    new asn1js.ObjectIdentifier({ value: oid })])
    .concat(withNull ? [new asn1js.Null()] : []) });
}

function octetString(bytes) {
  log.debug("Entering octetString().");
  log.debug("Leaving octetString().");
  return new asn1js.OctetString({ valueHex: arrayBufferOf(bytes) });
}

function contentInfo(typeOid, inner) {
  log.debug("Entering contentInfo().");
  log.debug("Leaving contentInfo().");
  return Buffer.from(new asn1js.Sequence({ value: [
    new asn1js.ObjectIdentifier({ value: typeOid }),
    new asn1js.Constructed({ idBlock: { tagClass: 3, tagNumber: 0 },
                             value: [inner] })
  ] }).toBER(false));
}

function issuerAndSerialOf(cert) {
  log.debug("Entering issuerAndSerialOf().");
  log.debug("Leaving issuerAndSerialOf().");
  return new asn1js.Sequence({ value: [
    node(cert.issuerRaw),
    new asn1js.Integer({ valueHex: arrayBufferOf(cert.serialRaw) })
  ] });
}

// A degenerate, certificates-only SignedData (RFC 8894 section 3.4): what
// GetCACert answers, and what a successful CertRep's envelope holds.
function certsOnly(certificatePems, crlDers) {
  log.debug("Entering certsOnly().");
  const certs = (certificatePems || []).map(function (pem) {
    return node(pemToDer(pem));
  });
  const crls = (crlDers || []).map(function (der) {
    return node(der);
  });
  const value = [new asn1js.Integer({ value: 1 }),
                 new asn1js.Set({ value: [] }),
                 new asn1js.Sequence({ value: [
                   new asn1js.ObjectIdentifier({ value: OID.data })] })];
  if (certs.length) {
    value.push(new asn1js.Constructed({
      idBlock: { tagClass: 3, tagNumber: 0 }, value: certs }));
  }
  if (crls.length) {
    value.push(new asn1js.Constructed({
      idBlock: { tagClass: 3, tagNumber: 1 }, value: crls }));
  }
  value.push(new asn1js.Set({ value: [] }));
  log.debug("Leaving certsOnly(). " + certs.length + " certificate(s), " +
            crls.length + " CRL(s).");
  return contentInfo(OID.signedData, new asn1js.Sequence({ value: value }));
}

// An EnvelopedData to one RSA recipient, RSAES-PKCS1-v1_5 key transport —
// what every SCEP client decrypts, including forge and OpenSSL's PKCS7 — and
// an AES-CBC content cipher named by OID.
function envelope(content, recipientCertificatePem, cipherOid) {
  log.debug("Entering envelope().");
  const cipher = CIPHERS[cipherOid] || CIPHERS['2.16.840.1.101.3.4.1.42'];
  const cipherId = CIPHERS[cipherOid] ? cipherOid : '2.16.840.1.101.3.4.1.42';
  const recipient = describeCertificate(pemToDer(recipientCertificatePem));
  if (!recipient || recipient.keyType !== 'rsa') {
    log.debug("Leaving envelope(). Not an RSA recipient.");
    throw new Error('a reply can be encrypted only to an RSA certificate');
  }
  const key = nodeCrypto.randomBytes(cipher.keyBytes);
  const iv = nodeCrypto.randomBytes(16);
  const c = nodeCrypto.createCipheriv(cipher.id, key, iv);
  const ciphertext = Buffer.concat([c.update(content), c.final()]);
  const wrapped = nodeCrypto.publicEncrypt({
    key: recipient.x509.publicKey,
    padding: nodeCrypto.constants.RSA_PKCS1_PADDING
  }, key);
  const ed = new asn1js.Sequence({ value: [
    new asn1js.Integer({ value: 0 }),
    new asn1js.Set({ value: [new asn1js.Sequence({ value: [
      new asn1js.Integer({ value: 0 }),
      issuerAndSerialOf(recipient),
      algorithmIdentifier(OID.rsaEncryption, true),
      octetString(wrapped)
    ] })] }),
    new asn1js.Sequence({ value: [
      new asn1js.ObjectIdentifier({ value: OID.data }),
      new asn1js.Sequence({ value: [
        new asn1js.ObjectIdentifier({ value: cipherId }),
        octetString(iv)] }),
      new asn1js.Primitive({ idBlock: { tagClass: 3, tagNumber: 0 },
                             valueHex: arrayBufferOf(ciphertext) })
    ] })
  ] });
  log.debug("Leaving envelope(). " + cipher.label);
  return contentInfo(OID.envelopedData, ed);
}

function printable(text) {
  log.debug("Entering printable().");
  log.debug("Leaving printable().");
  return new asn1js.PrintableString({ value: String(text) });
}

function attribute(oid, value) {
  log.debug("Entering attribute().");
  log.debug("Leaving attribute().");
  return Buffer.from(new asn1js.Sequence({ value: [
    new asn1js.ObjectIdentifier({ value: oid }),
    new asn1js.Set({ value: [value] })] }).toBER(false));
}

// A CertRep (RFC 8894 section 3.3.2), signed by the RA.
//
//   spec.raCertificatePem, spec.raPrivateKeyPem  the RA
//   spec.transactionID                           echoed
//   spec.recipientNonce                          the request's senderNonce
//   spec.pkiStatus                               PKI_STATUS value
//   spec.failInfo                                FAIL_INFO value, on FAILURE
//   spec.content                                 the envelope's DER, SUCCESS
//   spec.digest                                  'sha256' (default) | …
function certRep(spec) {
  log.debug("Entering certRep(). status=" + spec.pkiStatus);
  const ra = describeCertificate(pemToDer(spec.raCertificatePem));
  const digestId = ['sha256', 'sha384', 'sha512'].indexOf(spec.digest) >= 0
    ? spec.digest : 'sha256';
  const digestOid = Object.keys(DIGESTS).filter(function (oid) {
    return DIGESTS[oid].id === digestId;
  })[0];
  const signatureOid = Object.keys(SIGNATURES).filter(function (oid) {
    return SIGNATURES[oid].key === 'rsa' && SIGNATURES[oid].digest === digestId;
  })[0];
  const content = spec.content ? Buffer.from(spec.content) : null;
  const attrs = [
    attribute(OID.contentType, new asn1js.ObjectIdentifier({
      value: OID.data })),
    attribute(OID.messageDigest, octetString(nodeCrypto.createHash(digestId)
      .update(content || Buffer.alloc(0)).digest())),
    attribute(OID.messageType, printable('3')),
    attribute(OID.pkiStatus, printable(spec.pkiStatus)),
    attribute(OID.transactionID, printable(spec.transactionID)),
    attribute(OID.senderNonce, octetString(nodeCrypto.randomBytes(
      NONCE_BYTES))),
    attribute(OID.recipientNonce, octetString(spec.recipientNonce))
  ];
  if (spec.pkiStatus === PKI_STATUS.FAILURE) {
    attrs.push(attribute(OID.failInfo, printable(spec.failInfo ||
                                                 FAIL_INFO.badRequest)));
  }
  // DER's SET OF rule: members in ascending order of their encodings.
  attrs.sort(Buffer.compare);
  const set = Buffer.from(new asn1js.Set({ value: attrs.map(node) })
    .toBER(false));
  const signature = nodeCrypto.sign(digestId, set, spec.raPrivateKeyPem);
  const implicit = Buffer.from(set);
  implicit[0] = 0xa0;
  const signerInfo = new asn1js.Sequence({ value: [
    new asn1js.Integer({ value: 1 }),
    issuerAndSerialOf(ra),
    algorithmIdentifier(digestOid, false),
    node(implicit),
    algorithmIdentifier(signatureOid, true),
    octetString(signature)
  ] });
  /** @type {any[]} */
  const encap = [new asn1js.ObjectIdentifier({ value: OID.data })];
  if (content) {
    encap.push(new asn1js.Constructed({ idBlock: { tagClass: 3,
                                                   tagNumber: 0 },
                                        value: [octetString(content)] }));
  }
  const sd = new asn1js.Sequence({ value: [
    new asn1js.Integer({ value: 1 }),
    new asn1js.Set({ value: [algorithmIdentifier(digestOid, false)] }),
    new asn1js.Sequence({ value: encap }),
    new asn1js.Constructed({ idBlock: { tagClass: 3, tagNumber: 0 },
                             value: [node(ra.der)] }),
    new asn1js.Set({ value: [signerInfo] })
  ] });
  log.debug("Leaving certRep().");
  return contentInfo(OID.signedData, sd);
}

// What the protocol pages and the crypto report print, read from the tables.
function algorithms() {
  log.debug("Entering algorithms().");
  const labels = function (table) {
    log.debug("Entering labels().");
    log.debug("Leaving labels().");
    return Object.keys(table).map(function (oid) {
      return table[oid].label;
    });
  };
  log.debug("Leaving algorithms().");
  return {
    digests: labels(DIGESTS),
    signatures: labels(SIGNATURES),
    ciphers: labels(CIPHERS),
    keyTransports: KEY_TRANSPORTS.slice(),
    refusedDigests: Object.keys(REFUSED_DIGESTS).map(function (oid) {
      return REFUSED_DIGESTS[oid];
    }),
    refusedCiphers: Object.keys(REFUSED_CIPHERS).map(function (oid) {
      return REFUSED_CIPHERS[oid];
    }),
    replySignature: 'sha256WithRSAEncryption (sha384/sha512 when the ' +
                    'request used them)',
    replyKeyTransport: 'RSAES-PKCS1-v1_5',
    replyCipher: 'the AES-CBC key size the request used'
  };
}

module.exports = {
  OID: OID,
  DIGESTS: DIGESTS,
  SIGNATURES: SIGNATURES,
  CIPHERS: CIPHERS,
  KEY_TRANSPORTS: KEY_TRANSPORTS,
  MESSAGE_TYPES: MESSAGE_TYPES,
  PKI_STATUS: PKI_STATUS,
  FAIL_INFO: FAIL_INFO,
  NONCE_BYTES: NONCE_BYTES,
  parsePkiMessage: parsePkiMessage,
  verifySigner: verifySigner,
  openEnvelope: openEnvelope,
  readIssuerAndSerial: readIssuerAndSerial,
  readIssuerAndSubject: readIssuerAndSubject,
  describeCertificate: describeCertificate,
  certsOnly: certsOnly,
  envelope: envelope,
  certRep: certRep,
  algorithms: algorithms,
  derToPem: derToPem,
  pemToDer: pemToDer
};
