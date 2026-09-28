// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: scep_cms.ts
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
// may have a certificate is `common/cert_enrollment.ts`'s, what an operation
// means is `scep.ts`'s, and which RA key opens an envelope is `scep_ra.ts`'s.
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
// `admin-ui/crypto_metadata.ts` reads them from here rather than from a
// paragraph. It is the arrangement `gnap/gnap_httpsig.ts` has for RFC 9421.
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
// 3. **KEY TRANSPORT IS RSA — PKCS#1 v1.5 OR OAEP — AND BOTH ARE NODE'S.**
//    PKCS#1 v1.5 is what every SCEP client in the field sends, and its
//    decryption is the Marvin attack's target (CVE-2023-46809). It was
//    node-forge's pure-javascript RSA until #65, because node 22 refused
//    `privateDecrypt()` with `RSA_PKCS1_PADDING` outright; that JavaScript
//    was not constant-time and drew its blinding from a generator of its
//    own. Node 24, which both images run, has OpenSSL's IMPLICIT REJECTION
//    and allows it: a padding that does not check unwraps to a deterministic
//    random value instead of throwing, in the same time. A runtime without
//    it still refuses, and that is logged once (`STS-SCEP-0066`) because it
//    fails every v1.5 request. **A failed unwrap is not reported as such**:
//    a value of the wrong length is replaced with random bytes of the right
//    length and decryption continues, so a padding error and a wrong key
//    both end as one "the content did not decrypt" — an answer that tells a
//    Bleichenbacher-style guesser nothing about the padding. RFC 3218
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

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `ScepCms` takes the modules it uses through its constructor
// (`ScepCmsDeps`). Since #50's R2 the composition root builds the instance
// (`ScepCms.defaultDeps()`) and installs it; the module's old export names are
// FACADES that forward to it, for the JavaScript callers, and a process without
// the root builds a default when the module finishes loading. `ScepCms` is
// exported beside them for the composition root.
// ---------------------------------------------------------------------------

import nodeCrypto = require('crypto');
import asn1js = require('asn1js');
import pkijs = require('pkijs');

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import errorCodes = require('../common/error_codes');
const { log } = helpers;

// ---------------------------------------------------------------------------
// THE VOCABULARY.
// ---------------------------------------------------------------------------
/**
 * The OIDs SCEP's CMS messages use: content types, SCEP's signed attributes,
 * algorithms and extensions.
 */
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
/**
 * The digests a request may be signed over, by OID; anything else is badAlg.
 */
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
/**
 * The signature algorithms accepted, by OID, with the key type and digest each
 * implies.
 */
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
/**
 * The content ciphers accepted, by OID: AES-128, AES-192 and AES-256 in CBC
 * mode.
 */
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

/**
 * The RSA key transports an envelope may use.
 */
const KEY_TRANSPORTS = ['RSAES-PKCS1-v1_5 (rsaEncryption)',
                       'RSAES-OAEP (SHA-1, SHA-256, SHA-384, SHA-512)'];

// RFC 8894 section 3.2.1.2 and 3.2.1.3.
/**
 * The SCEP messageType values (RFC 8894 sections 3.2.1.2 and 3.2.1.3).
 */
const MESSAGE_TYPES = {
  3: 'CertRep', 17: 'RenewalReq', 19: 'PKCSReq', 20: 'CertPoll',
  21: 'GetCert', 22: 'GetCRL'
};

/**
 * The pkiStatus values: SUCCESS, FAILURE and PENDING.
 */
const PKI_STATUS = { SUCCESS: '0', FAILURE: '2', PENDING: '3' };

/**
 * The failInfo values a FAILURE carries.
 */
const FAIL_INFO = { badAlg: '0', badMessageCheck: '1', badRequest: '2',
                    badTime: '3', badCertId: '4' };

// RFC 8894 section 3.2.1.5: sixteen octets.
/**
 * The length of a sender nonce: sixteen octets.
 */
const NONCE_BYTES = 16;

// A transactionID is PrintableString and a client's own choice; a bound keeps
// it from being a way to grow a store.
const MAX_TRANSACTION_ID = 128;

// What `ScepCms` needs from the rest of the service: the modules this file
// used to reach for itself, passed in so that the composition root can build
// one and a test can build one with stubs.
interface ScepCmsDeps {
  nodeCrypto: typeof nodeCrypto;
  asn1js: typeof asn1js;
  pkijs: typeof pkijs;
  log: typeof log;
}

/**
 * The CMS envelope SCEP speaks (RFC 8894 section 3, over RFC 5652), read and
 * written.
 *
 * It decides nothing: who may have a certificate, what an operation means and
 * which RA key opens an envelope are decided elsewhere.
 */
class ScepCms {
  // Set once the runtime has refused PKCS#1 v1.5 decryption (decision 3),
  // so the log says it once per process rather than per request.
  /**
   * Whether this process has already logged that its node runtime refuses
   * PKCS#1 v1.5 decryption (STS-SCEP-0066), which is said once.
   */
  static warnedNoImplicitRejection = false;

  /**
   * Builds the codec.
   *
   * @param deps - the logger, node's crypto, asn1js and pkijs
   */
  constructor(private readonly deps: ScepCmsDeps) {
    deps.log.debug("Entering ScepCms.constructor().");
    deps.log.debug("Leaving ScepCms.constructor().");
  }

  // What the composition root passes: the modules the load-time instance
  // was built from before R2.
  /**
   * Returns the dependencies the default instance is built from.
   *
   * @returns the modules the load-time instance is built from
   */
  static defaultDeps(): ScepCmsDeps {
    log.debug("Entering ScepCms.defaultDeps().");
    log.debug("Leaving ScepCms.defaultDeps().");
    return {
      nodeCrypto: nodeCrypto,
      asn1js: asn1js,
      pkijs: pkijs,
      log: log
    };
  }

  // ---------------------------------------------------------------------------
  // A REFUSAL. `stage` says which of the two answers the caller owes: 'http'
  // when too little was read to build a CertRep, 'certrep' when the reply can
  // be a signed FAILURE. `failInfo` is set for the second.
  // ---------------------------------------------------------------------------
  /**
   * Builds a refusal, saying whether the caller can still answer with a signed
   * CertRep FAILURE.
   *
   * @param code - the STS error code
   * @param why - the reason
   * @param failInfo - the failInfo, for a CertRep refusal
   * @param stage - `http` when too little was read to build a CertRep, else
   *   `certrep`
   * @returns `ok: false`, the code, the reason, the failInfo and the stage
   */
  refusal(code, why, failInfo, stage?) {
    const { log } = this.deps;
    log.debug("Entering ScepCms.refusal(). code=" + code);
    log.debug("Leaving ScepCms.refusal().");
    return { ok: false, code: code, why: why,
             failInfo: failInfo || null, stage: stage || 'certrep' };
  }

  // ---------------------------------------------------------------------------
  // BYTES.
  // ---------------------------------------------------------------------------
  /**
   * Returns bytes as an exactly sized ArrayBuffer.
   *
   * @param bytes - the bytes
   * @returns the ArrayBuffer
   */
  arrayBufferOf(bytes) {
    const { log } = this.deps;
    log.debug("Entering ScepCms.arrayBufferOf().");
    const buf = Buffer.from(bytes);
    log.debug("Leaving ScepCms.arrayBufferOf().");
    return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
  }

  /**
   * Copies a view into a Buffer.
   *
   * @param view - the view
   * @returns the Buffer
   */
  bufferOf(view) {
    const { log } = this.deps;
    log.debug("Entering ScepCms.bufferOf().");
    log.debug("Leaving ScepCms.bufferOf().");
    return Buffer.from(view || []);
  }

  // One complete BER value and nothing after it. A trailing byte is refused
  // rather than ignored: bytes nobody signed riding along after a signed
  // message are bytes two readers will disagree about.
  /**
   * Reads exactly one BER value; trailing bytes are refused.
   *
   * @param bytes - the bytes
   * @returns the parsed value, or null
   */
  readOne(bytes) {
    const { log, asn1js } = this.deps;
    log.debug("Entering ScepCms.readOne().");
    const buf = Buffer.from(bytes || []);
    if (!buf.length) {
      log.debug("Leaving ScepCms.readOne(). Empty.");
      return null;
    }
    let parsed = null;
    try {
      parsed = asn1js.fromBER(this.arrayBufferOf(buf));
    } catch (e) {
      log.debug("Caught in ScepCms.readOne(): " + ((e && e.message) || e));
      parsed = null;
    }
    if (!parsed || parsed.offset === -1 || parsed.offset !== buf.length ||
        parsed.result.error) {
      log.debug("Leaving ScepCms.readOne(). Not one value.");
      return null;
    }
    log.debug("Leaving ScepCms.readOne().");
    return parsed.result;
  }

  /**
   * Returns a constructed ASN.1 node's children.
   *
   * @param node - the node
   * @returns the children
   */
  children(node) {
    const { log } = this.deps;
    log.debug("Entering ScepCms.children().");
    const list = node && node.valueBlock && Array.isArray(node.valueBlock.value)
      ? node.valueBlock.value : [];
    log.debug("Leaving ScepCms.children().");
    return list;
  }

  /**
   * Says whether a node is a universal-class value with a tag number.
   *
   * @param node - the node
   * @param tagNumber - the tag number
   * @returns true when it is
   */
  isUniversal(node, tagNumber) {
    const { log } = this.deps;
    log.debug("Entering ScepCms.isUniversal().");
    log.debug("Leaving ScepCms.isUniversal().");
    return !!(node && node.idBlock && node.idBlock.tagClass === 1 &&
              node.idBlock.tagNumber === tagNumber);
  }

  /**
   * Says whether a node is a context-specific value with a tag number.
   *
   * @param node - the node
   * @param tagNumber - the tag number
   * @returns true when it is
   */
  isContext(node, tagNumber) {
    const { log } = this.deps;
    log.debug("Entering ScepCms.isContext().");
    log.debug("Leaving ScepCms.isContext().");
    return !!(node && node.idBlock && node.idBlock.tagClass === 3 &&
              node.idBlock.tagNumber === tagNumber);
  }

  /**
   * Returns an OBJECT IDENTIFIER node's dotted value.
   *
   * @param node - the node
   * @returns the OID, or ''
   */
  oidOf(node) {
    const { log } = this.deps;
    log.debug("Entering ScepCms.oidOf().");
    if (!this.isUniversal(node, 6)) {
      log.debug("Leaving ScepCms.oidOf(). Not an OID.");
      return '';
    }
    log.debug("Leaving ScepCms.oidOf().");
    return String(node.valueBlock.toString());
  }

  // The octets of an OCTET STRING, primitive or BER-constructed, or of an
  // implicitly tagged one. OpenSSL streams a constructed, indefinite-length
  // OCTET STRING for encapsulated content, so both shapes are ordinary.
  /**
   * Returns the octets of an OCTET STRING, primitive, BER-constructed or
   * implicitly tagged.
   *
   * @param node - the node
   * @returns the octets, or null
   */
  octetsOf(node) {
    const { log } = this.deps;
    log.debug("Entering ScepCms.octetsOf().");
    if (!node || !node.idBlock) {
      log.debug("Leaving ScepCms.octetsOf(). Nothing.");
      return null;
    }
    const constructed = node.idBlock.isConstructed ||
      (node.valueBlock && node.valueBlock.isConstructed);
    if (constructed) {
      const parts = [];
      const inner = this.children(node);
      for (let i = 0; i < inner.length; i++) {
        const one = this.octetsOf(inner[i]);
        if (one === null) {
          log.debug("Leaving ScepCms.octetsOf(). A malformed segment.");
          return null;
        }
        parts.push(one);
      }
      log.debug("Leaving ScepCms.octetsOf(). Constructed.");
      return Buffer.concat(parts);
    }
    const view = node.valueBlock && node.valueBlock.valueHexView;
    log.debug("Leaving ScepCms.octetsOf().");
    return view ? this.bufferOf(view) : null;
  }

  /**
   * Returns a node's encoding as it was read.
   *
   * @param node - the node
   * @returns the bytes
   */
  rawOf(node) {
    const { log } = this.deps;
    log.debug("Entering ScepCms.rawOf().");
    log.debug("Leaving ScepCms.rawOf().");
    return this.bufferOf(node && node.valueBeforeDecodeView);
  }

  /**
   * Returns a string node's value.
   *
   * @param node - the node
   * @returns the string, or ''
   */
  stringOf(node) {
    const { log } = this.deps;
    log.debug("Entering ScepCms.stringOf().");
    if (!node || !node.valueBlock) {
      log.debug("Leaving ScepCms.stringOf().");
      return '';
    }
    const value = node.valueBlock.value;
    log.debug("Leaving ScepCms.stringOf().");
    return typeof value === 'string' ? value : '';
  }

  /**
   * Wraps DER bytes as PEM.
   *
   * @param der - the bytes
   * @param label - the PEM label
   * @returns the PEM
   */
  derToPem(der, label) {
    const { log } = this.deps;
    log.debug("Entering ScepCms.derToPem().");
    log.debug("Leaving ScepCms.derToPem().");
    return '-----BEGIN ' + label + '-----\n' +
      Buffer.from(der).toString('base64').replace(/(.{64})/g, '$1\n')
        .replace(/\n$/, '') + '\n-----END ' + label + '-----\n';
  }

  /**
   * Unwraps PEM into DER bytes.
   *
   * @param pem - the PEM
   * @returns the bytes
   */
  pemToDer(pem) {
    const { log } = this.deps;
    log.debug("Entering ScepCms.pemToDer().");
    log.debug("Leaving ScepCms.pemToDer().");
    return Buffer.from(String(pem || '').replace(/-----[^-]+-----/g, '')
      .replace(/\s+/g, ''), 'base64');
  }

  /**
   * Returns bytes as lower-case hex.
   *
   * @param buf - the bytes
   * @returns the hex
   */
  hexOf(buf) {
    const { log } = this.deps;
    log.debug("Entering ScepCms.hexOf().");
    log.debug("Leaving ScepCms.hexOf().");
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
  /**
   * Reads the facts a CMS identifier is compared against out of a certificate's
   * own bytes: the serial, issuer and subject encodings, the key identifier and
   * the key.
   *
   * @param der - the certificate
   * @returns the certificate's DER, PEM, node X509Certificate and those facts;
   *   or null
   */
  describeCertificate(der) {
    const { log, nodeCrypto, pkijs } = this.deps;
    const self = this;
    log.debug("Entering ScepCms.describeCertificate().");
    const node = this.readOne(der);
    const tbs = this.children(node)[0];
    const parts = this.children(tbs);
    // A VERSION 1 CERTIFICATE HAS SIX TBS FIELDS, NOT SEVEN (#249): no [0]
    // version, and no extensions. certmonger signs every PKCSReq with such a
    // self-signed "mini certificate", and while this read demanded seven
    // fields the certificate was silently dropped from the SignedData's set,
    // so every certmonger request was refused STS-SCEP-0011 ("0 match").
    // RFC 8894 section 2.3 asks for a self-signed certificate over the
    // request's key and names no version; what is checked is that key.
    const offset = parts.length > 0 && this.isContext(parts[0], 0) ? 1 : 0;
    if (!this.isUniversal(node, 16) || !this.isUniversal(tbs, 16) ||
        parts.length < offset + 6) {
      log.debug("Leaving ScepCms.describeCertificate(). Not a certificate.");
      return null;
    }
    let x509 = null;
    try {
      x509 = new nodeCrypto.X509Certificate(Buffer.from(der));
    } catch (e) {
      log.debug("Caught in ScepCms.describeCertificate(): " +
                ((e && e.message) || e));
      x509 = null;
    }
    if (!x509) {
      log.debug("Leaving ScepCms.describeCertificate(). Node could not read " +
                "it.");
      return null;
    }
    let ski = null;
    try {
      const cert = pkijs.Certificate.fromBER(this.arrayBufferOf(der));
      (cert.extensions || []).forEach(function (ext) {
        if (ext.extnID === OID.subjectKeyIdentifier && !ski) {
          const inner =
            self.readOne(self.bufferOf(ext.extnValue.valueBlock.valueHexView));
          ski = inner ? self.octetsOf(inner) : null;
        }
      });
    } catch (e) {
      log.debug("Caught in ScepCms.describeCertificate(): " +
                ((e && e.message) || e));
      ski = null;
    }
    const spki = x509.publicKey.export({ type: 'spki', format: 'der' });
    log.debug("Leaving ScepCms.describeCertificate().");
    return {
      der: Buffer.from(der),
      pem: this.derToPem(der, 'CERTIFICATE'),
      x509: x509,
      serialRaw: this.octetsOf(parts[offset]),
      issuerRaw: this.rawOf(parts[offset + 2]),
      subjectRaw: this.rawOf(parts[offset + 4]),
      ski: ski,
      keyType: x509.publicKey.asymmetricKeyType,
      spkiSha256: nodeCrypto.createHash('sha256').update(spki).digest('hex'),
      selfIssued: this.rawOf(parts[offset + 2])
        .equals(this.rawOf(parts[offset + 4]))
    };
  }

  // Does an IssuerAndSerialNumber (or a [0] SubjectKeyIdentifier) name this
  // certificate?
  /**
   * Says whether a signer or recipient identifier (IssuerAndSerialNumber or
   * SubjectKeyIdentifier) names a certificate.
   *
   * @param sid - the identifier node
   * @param cert - a `describeCertificate()` answer
   * @returns true when it names it
   */
  identifies(sid, cert) {
    const { log } = this.deps;
    log.debug("Entering ScepCms.identifies().");
    if (!sid || !cert) {
      log.debug("Leaving ScepCms.identifies(). Nothing to compare.");
      return false;
    }
    if (this.isContext(sid, 0)) {
      const wanted = this.octetsOf(sid);
      log.debug("Leaving ScepCms.identifies(). By key identifier.");
      return !!(wanted && cert.ski && wanted.equals(cert.ski));
    }
    const parts = this.children(sid);
    if (!this.isUniversal(sid, 16) || parts.length !== 2) {
      log.debug("Leaving ScepCms.identifies(). Not an IssuerAndSerialNumber.");
      return false;
    }
    const serial = this.octetsOf(parts[1]);
    log.debug("Leaving ScepCms.identifies().");
    return this.rawOf(parts[0]).equals(cert.issuerRaw) &&
           !!serial && serial.equals(cert.serialRaw);
  }

  // ---------------------------------------------------------------------------
  // READ A pkiMessage.
  //
  // Answers every fact `scep.ts` needs, or a refusal whose `stage` is 'http'
  // when not even a transactionID and a senderNonce could be read — without
  // those a CertRep cannot be built, and RFC 8894 has no reply for a message it
  // cannot name.
  // ---------------------------------------------------------------------------
  /**
   * Reads a SET of CMS attributes into a map from OID to value.
   *
   * @param attrs - the attributes node
   * @returns the map, or null when malformed
   */
  attributeValues(attrs) {
    const { log } = this.deps;
    log.debug("Entering ScepCms.attributeValues().");
    const out = {};
    for (let i = 0; i < attrs.length; i++) {
      const parts = this.children(attrs[i]);
      const type = this.oidOf(parts[0]);
      if (!this.isUniversal(attrs[i], 16) || parts.length !== 2 || !type ||
          !this.isUniversal(parts[1], 17)) {
        log.debug("Leaving ScepCms.attributeValues(). A malformed attribute.");
        return null;
      }
      if (Object.prototype.hasOwnProperty.call(out, type)) {
        // A signed attribute given twice is refused rather than resolved:
        // which of two transactionIDs a reply echoes is not a choice to make.
        log.debug("Leaving ScepCms.attributeValues(). A repeated attribute.");
        return null;
      }
      const values = this.children(parts[1]);
      if (values.length !== 1) {
        log.debug("Leaving ScepCms.attributeValues(). Not single-valued.");
        return null;
      }
      out[type] = values[0];
    }
    log.debug("Leaving ScepCms.attributeValues().");
    return out;
  }

  /**
   * Reads a pkiMessage: its SCEP attributes, content and signer. Never throws.
   *
   * @param bytes - the message
   * @returns the facts `scep.ts` needs, or a refusal (stage `http` when not
   *   even a transactionID and senderNonce could be read)
   */
  parsePkiMessage(bytes): Record<string, any> {
    const { log } = this.deps;
    log.debug("Entering ScepCms.parsePkiMessage().");
    try {
      const parsed = this.readPkiMessage(bytes);
      log.debug("Leaving ScepCms.parsePkiMessage(). ok=" + parsed.ok);
      return parsed;
    } catch (e) {
      // Every structural check below is explicit, so a throw here is an input
      // shape asn1js or node rejected in a way nothing above anticipated. It is
      // a malformed message, never a 500.
      log.debug("Caught in ScepCms.parsePkiMessage(): " +
                ((e && e.message) || e));
      log.debug("Leaving ScepCms.parsePkiMessage(). Threw.");
      return this.refusal('STS-SCEP-0010',
                          'The message is not a readable CMS ' +
                          'SignedData.', null, 'http');
    }
  }

  /**
   * Reads a pkiMessage, throwing on a shape nothing anticipated;
   * `parsePkiMessage()` is the caller.
   *
   * @param bytes - the message
   * @returns the facts, or a refusal
   */
  readPkiMessage(bytes) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering ScepCms.readPkiMessage().");
    const outer = this.readOne(bytes);
    const outerParts = this.children(outer);
    if (!this.isUniversal(outer, 16) || outerParts.length !== 2 ||
        this.oidOf(outerParts[0]) !== OID.signedData ||
        !this.isContext(outerParts[1], 0)) {
      log.debug("Leaving ScepCms.readPkiMessage(). Not a SignedData " +
                "ContentInfo.");
      return this.refusal('STS-SCEP-0010',
                          'The message is not one complete CMS ' +
                          'ContentInfo carrying SignedData.', null, 'http');
    }
    const sd = this.children(outerParts[1])[0];
    const sdParts = this.children(sd);
    if (!this.isUniversal(sd, 16) || sdParts.length < 4) {
      log.debug("Leaving ScepCms.readPkiMessage(). Not a SignedData.");
      return this.refusal('STS-SCEP-0010', 'The SignedData is malformed.', null,
                          'http');
    }
    let at = 1;
    const digestSet = sdParts[at++];
    const encap = sdParts[at++];
    let certsNode = null;
    if (this.isContext(sdParts[at], 0)) {
      certsNode = sdParts[at++];
    }
    if (this.isContext(sdParts[at], 1)) {
      at++;
    }
    const signerSet = sdParts[at];
    if (!this.isUniversal(digestSet, 17) || !this.isUniversal(encap, 16) ||
        !this.isUniversal(signerSet, 17) || at !== sdParts.length - 1) {
      log.debug("Leaving ScepCms.readPkiMessage(). SignedData fields out of " +
                "place.");
      return this.refusal('STS-SCEP-0010',
                          'The SignedData fields are not in the ' +
                          'order RFC 5652 section 5.1 defines.', null, 'http');
    }
    const encapParts = this.children(encap);
    const eContentType = this.oidOf(encapParts[0]);
    let content = null;
    if (encapParts.length === 2) {
      if (!this.isContext(encapParts[1], 0)) {
        log.debug("Leaving ScepCms.readPkiMessage(). eContent malformed.");
        return this.refusal('STS-SCEP-0010', 'The encapsulated content is ' +
                            'malformed.', null, 'http');
      }
      content = this.octetsOf(this.children(encapParts[1])[0]);
      if (content === null) {
        log.debug("Leaving ScepCms.readPkiMessage(). eContent is not an " +
                  "OCTET STRING.");
        return this.refusal('STS-SCEP-0010',
                            'The encapsulated content is not an ' +
                            'OCTET STRING.', null, 'http');
      }
    }
    const certificates = [];
    this.children(certsNode).forEach(function (one) {
      if (self.isUniversal(one, 16)) {
        const described = self.describeCertificate(self.rawOf(one));
        if (described) {
          certificates.push(described);
        }
      }
    });
    const signers = this.children(signerSet);
    if (signers.length !== 1) {
      log.debug("Leaving ScepCms.readPkiMessage(). " + signers.length +
                " signers.");
      return this.refusal('STS-SCEP-0011',
                          'A SCEP message has exactly one signer, ' +
                          'and this one has ' + signers.length + '.', null,
                          'http');
    }
    const si = this.children(signers[0]);
    if (!this.isUniversal(signers[0], 16) || si.length < 5) {
      log.debug("Leaving ScepCms.readPkiMessage(). SignerInfo malformed.");
      return this.refusal('STS-SCEP-0011', 'The SignerInfo is malformed.', null,
                          'http');
    }
    let s = 1;
    const sid = si[s++];
    const digestAlg = this.oidOf(this.children(si[s++])[0]);
    const signedAttrsNode = this.isContext(si[s], 0) ? si[s++] : null;
    const sigAlgNode = si[s++];
    const signatureNode = si[s++];
    if (!signedAttrsNode) {
      log.debug("Leaving ScepCms.readPkiMessage(). No signed attributes.");
      return this.refusal('STS-SCEP-0012', 'The signer carries no signed ' +
                          'attributes, so the message has no messageType, ' +
                          'transactionID or senderNonce (RFC 8894 section ' +
                          '3.2.1).',
                          null, 'http');
    }
    const attrs = this.attributeValues(this.children(signedAttrsNode));
    if (!attrs) {
      log.debug("Leaving ScepCms.readPkiMessage(). Signed attributes " +
                "malformed.");
      return this.refusal('STS-SCEP-0012',
                          'The signed attributes are malformed or ' +
                          'repeat an attribute.', null, 'http');
    }
    const transactionID = this.stringOf(attrs[OID.transactionID]);
    const senderNonce = this.octetsOf(attrs[OID.senderNonce]);
    const messageTypeText = this.stringOf(attrs[OID.messageType]);
    if (!transactionID || transactionID.length > MAX_TRANSACTION_ID ||
        !/^[A-Za-z0-9 '()+,\-./:=?]+$/.test(transactionID)) {
      log.debug("Leaving ScepCms.readPkiMessage(). transactionID.");
      return this.refusal('STS-SCEP-0012',
                          'The transactionID is missing, is not a ' +
                          'PrintableString, or is longer than ' +
                          MAX_TRANSACTION_ID +
                          ' characters.', null, 'http');
    }
    if (!senderNonce || senderNonce.length !== NONCE_BYTES) {
      log.debug("Leaving ScepCms.readPkiMessage(). senderNonce.");
      return this.refusal('STS-SCEP-0012',
                          'The senderNonce is missing or is not ' +
                          NONCE_BYTES + ' octets (RFC 8894 section 3.2.1.5).',
                          null,
                          'http');
    }
    const signer = certificates.filter(function (one) {
      return self.identifies(sid, one);
    });
    log.debug("Leaving ScepCms.readPkiMessage(). transactionID=" +
              transactionID);
    return {
      ok: true,
      transactionID: transactionID,
      senderNonce: senderNonce,
      messageTypeText: messageTypeText,
      messageType: /^\d{1,3}$/.test(messageTypeText) ? Number(messageTypeText)
                                                      : null,
      pkiStatus: this.stringOf(attrs[OID.pkiStatus]),
      failInfo: this.stringOf(attrs[OID.failInfo]),
      recipientNonce: attrs[OID.recipientNonce]
        ? this.octetsOf(attrs[OID.recipientNonce]) : null,
      contentTypeAttr: this.oidOf(attrs[OID.contentType]),
      messageDigestAttr: attrs[OID.messageDigest]
        ? this.octetsOf(attrs[OID.messageDigest]) : null,
      eContentType: eContentType,
      content: content,
      certificates: certificates,
      signer: signer.length === 1 ? signer[0] : null,
      signerMatches: signer.length,
      digestAlg: digestAlg,
      signatureAlg: this.oidOf(this.children(sigAlgNode)[0]),
      signature: this.octetsOf(signatureNode),
      signedAttrsRaw: this.rawOf(signedAttrsNode)
    };
  }

  // ---------------------------------------------------------------------------
  // VERIFY THE SIGNER. Every failure is a CertRep FAILURE with a failInfo.
  // ---------------------------------------------------------------------------
  /**
   * Verifies a pkiMessage's signer: the digest and signature algorithms, the
   * signed attributes, the signature and the certificate's validity.
   *
   * @param message - a `parsePkiMessage()` answer
   * @returns `ok` and the digest, or a CertRep refusal with a failInfo
   */
  verifySigner(message): Record<string, any> {
    const { log, nodeCrypto } = this.deps;
    log.debug("Entering ScepCms.verifySigner().");
    if (!message.signer) {
      log.debug("Leaving ScepCms.verifySigner(). No signer certificate.");
      return this.refusal('STS-SCEP-0011',
                          'The signer\'s certificate is not among ' +
                          'the certificates in the SignedData (' +
                          message.signerMatches +
                          ' match), so the signature cannot ' +
                          'be checked.', FAIL_INFO.badMessageCheck);
    }
    const digest = DIGESTS[message.digestAlg];
    if (!digest) {
      log.debug("Leaving ScepCms.verifySigner(). Digest refused.");
      return this.refusal('STS-SCEP-0020', 'The message is signed over ' +
                          (REFUSED_DIGESTS[message.digestAlg] ||
                           'an unknown digest (' + message.digestAlg + ')') +
                          '. This server accepts SHA-256, SHA-384 and SHA-512.',
                          FAIL_INFO.badAlg);
    }
    const sig = SIGNATURES[message.signatureAlg];
    if (!sig || (sig.digest && sig.digest !== digest.id) ||
        sig.key !== message.signer.keyType) {
      log.debug("Leaving ScepCms.verifySigner(). Signature algorithm refused.");
      return this.refusal('STS-SCEP-0021', 'The signature algorithm (' +
                          message.signatureAlg + ') is not one this server ' +
                          'verifies, or does not agree with the digest ' +
                          'algorithm or the signer\'s key.', FAIL_INFO.badAlg);
    }
    if (message.contentTypeAttr !== message.eContentType ||
        message.eContentType !== OID.data) {
      log.debug("Leaving ScepCms.verifySigner(). contentType.");
      return this.refusal('STS-SCEP-0024',
                          'The contentType signed attribute does ' +
                          'not name id-data, or does not agree with the ' +
                          'encapsulated content.', FAIL_INFO.badMessageCheck);
    }
    const computed = nodeCrypto.createHash(digest.id)
      .update(message.content || Buffer.alloc(0)).digest();
    const claimed = message.messageDigestAttr;
    if (!claimed || claimed.length !== computed.length ||
        !nodeCrypto.timingSafeEqual(claimed, computed)) {
      log.debug("Leaving ScepCms.verifySigner(). messageDigest.");
      return this.refusal('STS-SCEP-0022',
                          'The messageDigest signed attribute is ' +
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
      log.debug("Caught in ScepCms.verifySigner(): " + ((e && e.message) || e));
      verified = false;
    }
    if (!verified) {
      log.debug("Leaving ScepCms.verifySigner(). The signature does not " +
                "verify.");
      return this.refusal('STS-SCEP-0023', 'The signature over the signed ' +
                          'attributes does not verify with the signer\'s ' +
                          'certificate.', FAIL_INFO.badMessageCheck);
    }
    const nowMs = Date.now();
    if (new Date(message.signer.x509.validFrom).getTime() > nowMs + 300000 ||
        new Date(message.signer.x509.validTo).getTime() < nowMs) {
      log.debug("Leaving ScepCms.verifySigner(). Outside its validity.");
      return this.refusal('STS-SCEP-0046',
                          'The signer\'s certificate is not valid ' +
                          'now (' + message.signer.x509.validFrom + ' to ' +
                          message.signer.x509.validTo + ').',
                          FAIL_INFO.badTime);
    }
    log.debug("Leaving ScepCms.verifySigner(). " + digest.label + ", " +
              sig.label);
    return { ok: true, digest: digest.id };
  }

  // ---------------------------------------------------------------------------
  // OPEN THE pkcsPKIEnvelope with the RA's certificate and private key.
  // ---------------------------------------------------------------------------
  /**
   * Unwraps an envelope's content key with the RA's private key, by
   * RSAES-PKCS1-v1_5 or RSAES-OAEP.
   *
   * @param algorithmNode - the key transport's AlgorithmIdentifier
   * @param encryptedKey - the encrypted key
   * @param raPrivateKeyPem - the RA's private key
   * @param keyBytes - the content cipher's key length
   * @returns `ok`, the key and the transport used
   */
  unwrapKey(algorithmNode, encryptedKey, raPrivateKeyPem, keyBytes) {
    const { log, nodeCrypto } = this.deps;
    log.debug("Entering ScepCms.unwrapKey().");
    const algParts = this.children(algorithmNode);
    const algorithm = this.oidOf(algParts[0]);
    if (algorithm === OID.rsaEncryption) {
      let key = null;
      try {
        key = nodeCrypto.privateDecrypt({
          key: raPrivateKeyPem,
          padding: nodeCrypto.constants.RSA_PKCS1_PADDING
        }, encryptedKey);
      } catch (e) {
        // THE IMPLICIT REJECTION — see the header, decision 3. The error is not
        // reported to the client: random bytes of the right length take the
        // key's place and the content simply fails to decrypt, like a wrong
        // key would. A runtime that refuses the padding altogether is said
        // once, because then no v1.5 request can ever succeed.
        log.debug("Caught in ScepCms.unwrapKey(): " + ((e && e.message) || e));
        if (e && e.code === 'ERR_INVALID_ARG_VALUE' &&
            !ScepCms.warnedNoImplicitRejection) {
          ScepCms.warnedNoImplicitRejection = true;
          log.error(errorCodes.tag('STS-SCEP-0066') + 'scep: this node ' +
                    'runtime refuses PKCS#1 v1.5 decryption (no OpenSSL ' +
                    'implicit rejection), so every SCEP request using ' +
                    'rsaEncryption will fail to decrypt. Run node 24 or ' +
                    'later.');
        }
        key = null;
      }
      if (!key || key.length !== keyBytes) {
        key = nodeCrypto.randomBytes(keyBytes);
      }
      log.debug("Leaving ScepCms.unwrapKey(). PKCS#1 v1.5.");
      return { ok: true, key: key, transport: 'rsaEncryption' };
    }
    if (algorithm === OID.rsaesOaep) {
      let hash = 'sha1';
      const params = this.children(algParts[1]);
      for (let i = 0; i < params.length; i++) {
        if (this.isContext(params[i], 0)) {
          const oaepHash = this.children(this.children(params[i])[0])[0];
          const named = OAEP_HASHES[this.oidOf(oaepHash)];
          if (!named) {
            log.debug("Leaving ScepCms.unwrapKey(). OAEP hash refused.");
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
        log.debug("Caught in ScepCms.unwrapKey(): " + ((e && e.message) || e));
        key = null;
      }
      if (!key || key.length !== keyBytes) {
        key = nodeCrypto.randomBytes(keyBytes);
      }
      log.debug("Leaving ScepCms.unwrapKey(). OAEP " + hash + ".");
      return { ok: true, key: key, transport: 'rsaesOaep-' + hash };
    }
    log.debug("Leaving ScepCms.unwrapKey(). Unknown transport " + algorithm);
    return { ok: false, transport: algorithm };
  }

  /**
   * Opens a pkcsPKIEnvelope with the RA's certificate and private key. Never
   * throws.
   *
   * @param bytes - the EnvelopedData
   * @param raCertificatePem - the RA's certificate
   * @param raPrivateKeyPem - the RA's private key
   * @returns `ok`, the plaintext content, the cipher and the transport; or a
   *   refusal
   */
  openEnvelope(bytes, raCertificatePem, raPrivateKeyPem): Record<string, any> {
    const { log } = this.deps;
    log.debug("Entering ScepCms.openEnvelope().");
    try {
      const opened = this.readEnvelope(bytes, raCertificatePem,
                                       raPrivateKeyPem);
      log.debug("Leaving ScepCms.openEnvelope(). ok=" + opened.ok);
      return opened;
    } catch (e) {
      log.debug("Caught in ScepCms.openEnvelope(): " + ((e && e.message) || e));
      log.debug("Leaving ScepCms.openEnvelope(). Threw.");
      return this.refusal('STS-SCEP-0026',
                          'The pkcsPKIEnvelope is not a readable ' +
                          'CMS EnvelopedData.', FAIL_INFO.badMessageCheck);
    }
  }

  /**
   * Opens a pkcsPKIEnvelope, throwing on a shape nothing anticipated;
   * `openEnvelope()` is the caller.
   *
   * @param bytes - the EnvelopedData
   * @param raCertificatePem - the RA's certificate
   * @param raPrivateKeyPem - the RA's private key
   * @returns what `openEnvelope()` answers
   */
  readEnvelope(bytes, raCertificatePem, raPrivateKeyPem) {
    const { log, nodeCrypto } = this.deps;
    const self = this;
    log.debug("Entering ScepCms.readEnvelope().");
    const outer = this.readOne(bytes);
    const outerParts = this.children(outer);
    if (!this.isUniversal(outer, 16) || outerParts.length !== 2 ||
        this.oidOf(outerParts[0]) !== OID.envelopedData ||
        !this.isContext(outerParts[1], 0)) {
      log.debug("Leaving ScepCms.readEnvelope(). Not an EnvelopedData " +
                "ContentInfo.");
      return this.refusal('STS-SCEP-0026',
                          'The content of the message is not a ' +
                          'CMS ContentInfo carrying EnvelopedData.',
                          FAIL_INFO.badMessageCheck);
    }
    const ed = this.children(outerParts[1])[0];
    const edParts = this.children(ed);
    let at = 1;
    if (this.isContext(edParts[at], 0)) {
      at++;
    }
    const recipientSet = edParts[at++];
    const eci = edParts[at];
    const eciParts = this.children(eci);
    if (!this.isUniversal(ed, 16) || !this.isUniversal(recipientSet, 17) ||
        !this.isUniversal(eci, 16) || eciParts.length !== 3 ||
        !this.isContext(eciParts[2], 0)) {
      log.debug("Leaving ScepCms.readEnvelope(). Fields out of place.");
      return this.refusal('STS-SCEP-0026',
                          'The EnvelopedData is malformed or has ' +
                          'no encrypted content.', FAIL_INFO.badMessageCheck);
    }
    const ra = this.describeCertificate(this.pemToDer(raCertificatePem));
    let mine = null;
    this.children(recipientSet).forEach(function (one) {
      const parts = self.children(one);
      // KeyTransRecipientInfo only: a version INTEGER, a rid, an AlgId and an
      // OCTET STRING. KeyAgree (an ECDH recipient) and the others are for keys
      // an RSA RA does not have.
      if (!mine && self.isUniversal(one, 16) && parts.length === 4 &&
          self.isUniversal(parts[0], 2) && self.identifies(parts[1], ra)) {
        mine = parts;
      }
    });
    if (!mine) {
      log.debug("Leaving ScepCms.readEnvelope(). Not encrypted to this RA.");
      return this.refusal('STS-SCEP-0027',
                          'The envelope is not encrypted to this ' +
                          'realm\'s current RA certificate. Fetch it again ' +
                          'with GetCACert.', FAIL_INFO.badMessageCheck);
    }
    const cipherAlg = this.oidOf(this.children(eciParts[1])[0]);
    const cipher = CIPHERS[cipherAlg];
    if (!cipher) {
      log.debug("Leaving ScepCms.readEnvelope(). Cipher refused.");
      return this.refusal('STS-SCEP-0029', 'The content is encrypted with ' +
                          (REFUSED_CIPHERS[cipherAlg] || 'an unknown cipher (' +
                           cipherAlg + ')') +
                           '. This server accepts AES-128-CBC, ' +
                          'AES-192-CBC and AES-256-CBC.', FAIL_INFO.badAlg);
    }
    const iv = this.octetsOf(this.children(eciParts[1])[1]);
    const ciphertext = this.octetsOf(eciParts[2]);
    if (!iv || iv.length !== 16 || !ciphertext || !ciphertext.length ||
        ciphertext.length % 16 !== 0) {
      log.debug("Leaving ScepCms.readEnvelope(). IV or ciphertext malformed.");
      return this.refusal('STS-SCEP-0026',
                          'The content encryption parameters or ' +
                          'the ciphertext are malformed.',
                          FAIL_INFO.badMessageCheck);
    }
    const unwrapped = this.unwrapKey(mine[2],
                                     this.octetsOf(mine[3]) || Buffer.alloc(0),
                                     raPrivateKeyPem, cipher.keyBytes);
    if (!unwrapped.ok) {
      log.debug("Leaving ScepCms.readEnvelope(). Key transport refused.");
      return this.refusal('STS-SCEP-0028',
                          'The content key is transported with an ' +
                          'algorithm this server does not accept (' +
                          unwrapped.transport +
                          '). It accepts RSAES-PKCS1-v1_5 and ' +
                          'RSAES-OAEP.', FAIL_INFO.badAlg);
    }
    let plain = null;
    try {
      const decipher = nodeCrypto.createDecipheriv(cipher.id, unwrapped.key,
                                                   iv);
      plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    } catch (e) {
      log.debug("Caught in ScepCms.readEnvelope(): " + ((e && e.message) || e));
      plain = null;
    }
    // AND THE PLAINTEXT MUST BE ONE DER VALUE. Every content a pkcsPKIEnvelope
    // holds is a SEQUENCE — a PKCS#10, an IssuerAndSubject, an
    // IssuerAndSerialNumber — and a wrong key (or the implicit rejection's
    // random one) passes AES-CBC's padding check about one time in 256. Without
    // this, that one time came back ok with garbage and the refusal arrived
    // later under a different code, so a padding failure and a wrong key were
    // two answers again (`tests/scep_enrollment.js` saw it as a flake).
    if (plain && !this.readOne(plain)) {
      log.debug("readEnvelope(): the content decrypted to no single DER " +
                "value.");
      plain = null;
    }
    if (!plain) {
      log.debug("Leaving ScepCms.readEnvelope(). It did not decrypt.");
      return this.refusal('STS-SCEP-0030',
                          'The content did not decrypt with this ' +
                          'realm\'s RA key.', FAIL_INFO.badMessageCheck);
    }
    log.debug("Leaving ScepCms.readEnvelope(). " + plain.length + " bytes, " +
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
  /**
   * Reads a SEQUENCE of an issuer Name and one more value.
   *
   * @param bytes - the DER
   * @param second - the universal tag of the second value: 2 for a serial
   *   INTEGER, 16 for a subject Name
   * @returns the issuer's encoding and the second value, or null
   */
  readIssuerAndSomething(bytes, second) {
    const { log } = this.deps;
    log.debug("Entering ScepCms.readIssuerAndSomething().");
    const node = this.readOne(bytes);
    const parts = this.children(node);
    if (!this.isUniversal(node, 16) || parts.length !== 2 ||
        !this.isUniversal(parts[0], 16) ||
        !this.isUniversal(parts[1], second)) {
      log.debug("Leaving ScepCms.readIssuerAndSomething(). Malformed.");
      return null;
    }
    log.debug("Leaving ScepCms.readIssuerAndSomething().");
    return { issuerRaw: this.rawOf(parts[0]),
             second: second === 2 ? this.octetsOf(parts[1]) :
                     this.rawOf(parts[1]) };
  }

  /**
   * Reads an IssuerAndSerialNumber, as GetCert and GetCRL carry.
   *
   * @param bytes - the DER
   * @returns the issuer's encoding and the serial, or null
   */
  readIssuerAndSerial(bytes) {
    const { log } = this.deps;
    log.debug("Entering ScepCms.readIssuerAndSerial().");
    const read = this.readIssuerAndSomething(bytes, 2);
    log.debug("Leaving ScepCms.readIssuerAndSerial().");
    return read ? { issuerRaw: read.issuerRaw,
                    serialHex: this.hexOf(read.second) } : null;
  }

  /**
   * Reads an IssuerAndSubject, as CertPoll carries.
   *
   * @param bytes - the DER
   * @returns the issuer's and subject's encodings, or null
   */
  readIssuerAndSubject(bytes) {
    const { log } = this.deps;
    log.debug("Entering ScepCms.readIssuerAndSubject().");
    const read = this.readIssuerAndSomething(bytes, 16);
    log.debug("Leaving ScepCms.readIssuerAndSubject().");
    return read ? { issuerRaw: read.issuerRaw, subjectRaw: read.second } : null;
  }

  // ---------------------------------------------------------------------------
  // WRITE.
  // ---------------------------------------------------------------------------
  /**
   * Parses DER into an asn1js node, for embedding in a structure being written.
   *
   * @param der - the bytes
   * @returns the node
   */
  node(der) {
    const { log } = this.deps;
    log.debug("Entering ScepCms.node().");
    const parsed = this.readOne(der);
    if (!parsed) {
      log.debug("Leaving ScepCms.node(). Unreadable.");
      throw new Error('an internal structure did not re-read as DER');
    }
    log.debug("Leaving ScepCms.node().");
    return parsed;
  }

  /**
   * Builds an AlgorithmIdentifier.
   *
   * @param oid - the algorithm's OID
   * @param withNull - whether to include NULL parameters
   * @returns the node
   */
  algorithmIdentifier(oid, withNull) {
    const { log, asn1js } = this.deps;
    log.debug("Entering ScepCms.algorithmIdentifier().");
    log.debug("Leaving ScepCms.algorithmIdentifier().");
    return new asn1js.Sequence({ value: ([
      new asn1js.ObjectIdentifier({ value: oid })] as any[])
      .concat(withNull ? [new asn1js.Null()] : []) });
  }

  /**
   * Builds an OCTET STRING.
   *
   * @param bytes - the content
   * @returns the node
   */
  octetString(bytes) {
    const { log, asn1js } = this.deps;
    log.debug("Entering ScepCms.octetString().");
    log.debug("Leaving ScepCms.octetString().");
    return new asn1js.OctetString({ valueHex: this.arrayBufferOf(bytes) });
  }

  /**
   * Wraps content in a CMS ContentInfo.
   *
   * @param typeOid - the content type
   * @param inner - the content node
   * @returns the DER
   */
  contentInfo(typeOid, inner) {
    const { log, asn1js } = this.deps;
    log.debug("Entering ScepCms.contentInfo().");
    log.debug("Leaving ScepCms.contentInfo().");
    return Buffer.from(new asn1js.Sequence({ value: [
      new asn1js.ObjectIdentifier({ value: typeOid }),
      new asn1js.Constructed({ idBlock: { tagClass: 3, tagNumber: 0 },
                               value: [inner] })
    ] }).toBER(false));
  }

  /**
   * Builds a certificate's IssuerAndSerialNumber.
   *
   * @param cert - a `describeCertificate()` answer
   * @returns the node
   */
  issuerAndSerialOf(cert) {
    const { log, asn1js } = this.deps;
    log.debug("Entering ScepCms.issuerAndSerialOf().");
    log.debug("Leaving ScepCms.issuerAndSerialOf().");
    return new asn1js.Sequence({ value: [
      this.node(cert.issuerRaw),
      new asn1js.Integer({ valueHex: this.arrayBufferOf(cert.serialRaw) })
    ] });
  }

  // A degenerate, certificates-only SignedData (RFC 8894 section 3.4): what
  // GetCACert answers, and what a successful CertRep's envelope holds.
  /**
   * Builds a degenerate, certificates-only SignedData (RFC 8894 section 3.4):
   * what GetCACert answers and a successful CertRep's envelope holds.
   *
   * @param certificatePems - the certificates
   * @param crlDers - CRLs to include
   * @returns the DER
   */
  certsOnly(certificatePems, crlDers?) {
    const { log, asn1js } = this.deps;
    const self = this;
    log.debug("Entering ScepCms.certsOnly().");
    const certs = (certificatePems || []).map(function (pem) {
      return self.node(self.pemToDer(pem));
    });
    const crls = (crlDers || []).map(function (der) {
      return self.node(der);
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
    log.debug("Leaving ScepCms.certsOnly(). " + certs.length +
              " certificate(s), " +
              crls.length + " CRL(s).");
    return this.contentInfo(OID.signedData,
                            new asn1js.Sequence({ value: value }));
  }

  // An EnvelopedData to one RSA recipient, RSAES-PKCS1-v1_5 key transport —
  // what every SCEP client decrypts, including forge and OpenSSL's PKCS7 — and
  // an AES-CBC content cipher named by OID.
  /**
   * Builds an EnvelopedData to one RSA recipient with RSAES-PKCS1-v1_5 key
   * transport and an AES-CBC content cipher.
   *
   * @param content - the plaintext
   * @param recipientCertificatePem - the recipient's certificate
   * @param cipherOid - the content cipher's OID
   * @returns the DER
   */
  envelope(content, recipientCertificatePem, cipherOid) {
    const { log, nodeCrypto, asn1js } = this.deps;
    log.debug("Entering ScepCms.envelope().");
    const cipher = CIPHERS[cipherOid] || CIPHERS['2.16.840.1.101.3.4.1.42'];
    const cipherId = CIPHERS[cipherOid] ? cipherOid : '2.16.840.1.101.3.4.1.42';
    const recipient =
      this.describeCertificate(this.pemToDer(recipientCertificatePem));
    if (!recipient || recipient.keyType !== 'rsa') {
      log.debug("Leaving ScepCms.envelope(). Not an RSA recipient.");
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
        this.issuerAndSerialOf(recipient),
        this.algorithmIdentifier(OID.rsaEncryption, true),
        this.octetString(wrapped)
      ] })] }),
      new asn1js.Sequence({ value: [
        new asn1js.ObjectIdentifier({ value: OID.data }),
        new asn1js.Sequence({ value: [
          new asn1js.ObjectIdentifier({ value: cipherId }),
          this.octetString(iv)] }),
        new asn1js.Primitive({ idBlock: { tagClass: 3, tagNumber: 0 },
                               valueHex: this.arrayBufferOf(ciphertext) })
      ] })
    ] });
    log.debug("Leaving ScepCms.envelope(). " + cipher.label);
    return this.contentInfo(OID.envelopedData, ed);
  }

  /**
   * Builds a PrintableString.
   *
   * @param text - the text
   * @returns the node
   */
  printable(text) {
    const { log, asn1js } = this.deps;
    log.debug("Entering ScepCms.printable().");
    log.debug("Leaving ScepCms.printable().");
    return new asn1js.PrintableString({ value: String(text) });
  }

  /**
   * Builds one CMS attribute.
   *
   * @param oid - the attribute's OID
   * @param value - its value node
   * @returns the DER
   */
  attribute(oid, value) {
    const { log, asn1js } = this.deps;
    log.debug("Entering ScepCms.attribute().");
    log.debug("Leaving ScepCms.attribute().");
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
  /**
   * Builds a CertRep (RFC 8894 section 3.3.2), signed by the RA.
   *
   * @param spec - `raCertificatePem`, `raPrivateKeyPem`, `transactionID`,
   *   `recipientNonce`, `pkiStatus`, `failInfo` (on FAILURE), `content` (the
   *   envelope, on SUCCESS) and `digest`
   * @returns the DER
   */
  certRep(spec) {
    const { log, asn1js, nodeCrypto } = this.deps;
    log.debug("Entering ScepCms.certRep(). status=" + spec.pkiStatus);
    const ra = this.describeCertificate(this.pemToDer(spec.raCertificatePem));
    const digestId = ['sha256', 'sha384', 'sha512'].indexOf(spec.digest) >= 0
      ? spec.digest : 'sha256';
    const digestOid = Object.keys(DIGESTS).filter(function (oid) {
      return DIGESTS[oid].id === digestId;
    })[0];
    const signatureOid = Object.keys(SIGNATURES).filter(function (oid) {
      return SIGNATURES[oid].key === 'rsa' &&
             SIGNATURES[oid].digest === digestId;
    })[0];
    const content = spec.content ? Buffer.from(spec.content) : null;
    const attrs = [
      this.attribute(OID.contentType, new asn1js.ObjectIdentifier({
        value: OID.data })),
      this.attribute(OID.messageDigest,
                     this.octetString(nodeCrypto.createHash(digestId)
        .update(content || Buffer.alloc(0)).digest())),
      this.attribute(OID.messageType, this.printable('3')),
      this.attribute(OID.pkiStatus, this.printable(spec.pkiStatus)),
      this.attribute(OID.transactionID, this.printable(spec.transactionID)),
      this.attribute(OID.senderNonce, this.octetString(nodeCrypto.randomBytes(
        NONCE_BYTES))),
      this.attribute(OID.recipientNonce, this.octetString(spec.recipientNonce))
    ];
    if (spec.pkiStatus === PKI_STATUS.FAILURE) {
      attrs.push(this.attribute(OID.failInfo,
                                this.printable(spec.failInfo ||
                                               FAIL_INFO.badRequest)));
    }
    // DER's SET OF rule: members in ascending order of their encodings.
    attrs.sort(Buffer.compare);
    const set =
      Buffer.from(new asn1js.Set({ value: attrs.map(this.node.bind(this)) })
      .toBER(false));
    const signature = nodeCrypto.sign(digestId, set, spec.raPrivateKeyPem);
    const implicit = Buffer.from(set);
    implicit[0] = 0xa0;
    const signerInfo = new asn1js.Sequence({ value: [
      new asn1js.Integer({ value: 1 }),
      this.issuerAndSerialOf(ra),
      this.algorithmIdentifier(digestOid, false),
      this.node(implicit),
      this.algorithmIdentifier(signatureOid, true),
      this.octetString(signature)
    ] });
    const encap: any[] = [new asn1js.ObjectIdentifier({ value: OID.data })];
    if (content) {
      encap.push(new asn1js.Constructed({ idBlock: { tagClass: 3,
                                                     tagNumber: 0 },
                                          value:
                                            [this.octetString(content)] }));
    }
    const sd = new asn1js.Sequence({ value: [
      new asn1js.Integer({ value: 1 }),
      new asn1js.Set({ value: [this.algorithmIdentifier(digestOid, false)] }),
      new asn1js.Sequence({ value: encap }),
      new asn1js.Constructed({ idBlock: { tagClass: 3, tagNumber: 0 },
                               value: [this.node(ra.der)] }),
      new asn1js.Set({ value: [signerInfo] })
    ] });
    log.debug("Leaving ScepCms.certRep().");
    return this.contentInfo(OID.signedData, sd);
  }

  // What the protocol pages and the crypto report print, read from the tables.
  /**
   * Lists the algorithms accepted and refused, for the protocol pages and the
   * crypto report.
   *
   * @returns the digests, signatures, ciphers, key transports, and the refused
   *   digests and ciphers
   */
  algorithms() {
    const { log } = this.deps;
    log.debug("Entering ScepCms.algorithms().");
    const labels = function (table) {
      log.debug("Entering labels().");
      log.debug("Leaving labels().");
      return Object.keys(table).map(function (oid) {
        return table[oid].label;
      });
    };
    log.debug("Leaving ScepCms.algorithms().");
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
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds no
// instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` when this module finishes loading (see
// `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<ScepCms>(
  'scep/scep_cms',
  () => new ScepCms(ScepCms.defaultDeps()),
  null,
  log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

/**
 * The CMS envelope SCEP speaks, read and written: a library that registers no
 * route and decides nothing.
 *
 * The exports forward to the instance the composition root installs.
 *
 * @namespace
 */
export = {
  ScepCms: ScepCms,
  /**
   * Installs the instance the module-level functions forward to.
   */
  installInstance: (instance: ScepCms): void => slot.install(instance),
  /**
   * Says where the installed instance came from.
   */
  instanceOrigin: (): string => slot.origin(),
  OID: OID,
  DIGESTS: DIGESTS,
  SIGNATURES: SIGNATURES,
  CIPHERS: CIPHERS,
  KEY_TRANSPORTS: KEY_TRANSPORTS,
  MESSAGE_TYPES: MESSAGE_TYPES,
  PKI_STATUS: PKI_STATUS,
  FAIL_INFO: FAIL_INFO,
  NONCE_BYTES: NONCE_BYTES,
  parsePkiMessage: slot.forward('parsePkiMessage'),
  verifySigner: slot.forward('verifySigner'),
  openEnvelope: slot.forward('openEnvelope'),
  readIssuerAndSerial: slot.forward('readIssuerAndSerial'),
  readIssuerAndSubject: slot.forward('readIssuerAndSubject'),
  describeCertificate: slot.forward('describeCertificate'),
  certsOnly: slot.forward('certsOnly'),
  envelope: slot.forward('envelope'),
  certRep: slot.forward('certRep'),
  algorithms: slot.forward('algorithms'),
  derToPem: slot.forward('derToPem'),
  pemToDer: slot.forward('pemToDer')
};
