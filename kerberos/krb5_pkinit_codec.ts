// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: krb5_pkinit_codec.ts
//
// ===========================================================================
// THE WIRE FORMAT OF PKINIT (RFC 4556, RFC 8070, RFC 8636, RFC 8062), FOR THE
// AS EXCHANGE (#179, 2026-10-05).
//
// What `krb5_pkinit.ts` reads out of a PA-PK-AS-REQ and writes into a
// PA-PK-AS-REP, and nothing else: structures to DER and back. The CMS
// SignedData inside each, the certificates and the key agreement are
// `common/crypto.js`'s (section 16) — this file hands their bytes over
// untouched, because a signature is checked over the bytes that ARRIVED.
// What a structure means is `krb5_pkinit.ts`'s.
//
// ---------------------------------------------------------------------------
// THE TAGS. RFC 4556's module is `DEFINITIONS EXPLICIT TAGS`, so every
// context tag is explicit unless the field says IMPLICIT — signedAuthPack,
// kdcPkId, dhSignedData, encKeyPack and the three fields of an
// ExternalPrincipalIdentifier. **ONE EXCEPTION THE WIRE MAKES AND THE TEXT
// DOES NOT**: PA-PK-AS-REP's `dhInfo [0] DHRepInfo` is written IMPLICIT by
// MIT Kerberos and by Windows — the [0] replaces DHRepInfo's SEQUENCE tag —
// and a reply tagged as the module says is one MIT's client does not read.
// This KDC writes it as the clients read it, and reads both.
//
// A STATIC UTILITY CLASS (#50's rule for helpers): no state, no dependencies
// but the codec and the logger. A LIBRARY (rule 3): it registers nothing and
// is reachable from none of `krb5_kdc.js`, `krb5_service.js` and `spnego.js`,
// so the parent project's COPY set does not grow (kerberos/CLAUDE.md).
// ===========================================================================

import helpers = require('../common/helpers');
import asn1 = require('./krb5_asn1');
import msgs = require('./krb5_messages');
import fastCodec = require('./krb5_fast_codec');

const log = helpers.log;

// A decoded structure: plain objects of the vendored codec's shapes.
type Json = any;

const OID_TAG = 0x06;
const BIT_STRING_TAG = 0x03;

/**
 * The wire format of PKINIT (RFC 4556 with RFC 8070's freshness token, RFC
 * 8636's KDF agility and RFC 8062's PA-PKINIT-KX): structures to DER and
 * back. It knows no key and no policy; a structure that does not decode
 * throws. A static utility class.
 */
class Krb5PkinitCodec {
  /**
   * The padata types: RFC 4556's request and reply, RFC 8062's PA-PKINIT-KX
   * and RFC 8070's PA-AS-FRESHNESS.
   */
  static readonly PA = {
    PK_AS_REQ: 16,
    PK_AS_REP: 17,
    PKINIT_KX: 147,
    AS_FRESHNESS: 150
  };

  /**
   * The error codes of RFC 4556 section 3.1.3 and RFC 8636 section 6.
   */
  static readonly ERROR = {
    CLIENT_NOT_TRUSTED: 62,
    INVALID_SIG: 64,
    DH_KEY_PARAMETERS_NOT_ACCEPTED: 65,
    CANT_VERIFY_CERTIFICATE: 70,
    INVALID_CERTIFICATE: 71,
    REVOKED_CERTIFICATE: 72,
    REVOCATION_STATUS_UNKNOWN: 73,
    CLIENT_NAME_MISMATCH: 75,
    INCONSISTENT_KEY_PURPOSE: 77,
    DIGEST_IN_CERT_NOT_ACCEPTED: 78,
    PA_CHECKSUM_MUST_BE_INCLUDED: 79,
    DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED: 80,
    PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED: 81,
    PREAUTH_EXPIRED: 90,
    NO_ACCEPTABLE_KDF: 100
  };

  /**
   * The typed-data types: RFC 4556's three and RFC 8636's two.
   */
  static readonly TD = {
    TRUSTED_CERTIFIERS: 104,
    INVALID_CERTIFICATES: 105,
    DH_PARAMETERS: 109,
    CMS_DIGEST_ALGORITHMS: 111,
    CERT_DIGEST_ALGORITHMS: 112
  };

  /**
   * The authorization data type AD-INITIAL-VERIFIED-CAS (RFC 4556).
   */
  static readonly AD_INITIAL_VERIFIED_CAS = 9;

  /**
   * RFC 8062 section 7's key usage for PA-PKINIT-KX.
   */
  static readonly KEY_USAGE_PA_PKINIT_KX = 44;

  // -------------------------------------------------------------------------
  // PRIMITIVES the vendored codec lacks: an OBJECT IDENTIFIER and a BIT
  // STRING of whole octets.
  // -------------------------------------------------------------------------
  /**
   * Encodes an OBJECT IDENTIFIER.
   *
   * @param dotted - the OID, dotted
   * @returns the DER
   */
  static encOid(dotted: string): Uint8Array {
    log.debug('Entering Krb5PkinitCodec.encOid(). ' + dotted);
    const arcs = String(dotted).split('.').map(function (one) {
      return BigInt(one);
    });
    const out: number[] = [];
    const writeArc = function (arc: bigint) {
      const septets = [Number(arc & 0x7fn)];
      let rest = arc >> 7n;
      while (rest > 0n) {
        septets.unshift(Number(rest & 0x7fn) | 0x80);
        rest >>= 7n;
      }
      out.push.apply(out, septets);
    };
    writeArc(arcs[0] * 40n + arcs[1]);
    arcs.slice(2).forEach(writeArc);
    log.debug('Leaving Krb5PkinitCodec.encOid().');
    return asn1.tlv(OID_TAG, new Uint8Array(out));
  }

  /**
   * Decodes an OBJECT IDENTIFIER.
   *
   * @param t - the TLV
   * @returns the OID, dotted
   * @throws Error when it is not one
   */
  static decOid(t: Json): string {
    log.debug('Entering Krb5PkinitCodec.decOid().');
    if (!t || t.tag !== OID_TAG || !t.value.length) {
      log.debug('Leaving Krb5PkinitCodec.decOid(). Not an OID.');
      // error-code: none — a decoder; the caller refuses what does not decode
      throw new Error('krb5-pkinit: expected an OBJECT IDENTIFIER');
    }
    const arcs: bigint[] = [];
    let value = 0n;
    for (const byte of t.value) {
      value = (value << 7n) | BigInt(byte & 0x7f);
      if (!(byte & 0x80)) {
        arcs.push(value);
        value = 0n;
      }
    }
    const first = arcs[0] < 80n ? arcs[0] / 40n : 2n;
    const second = arcs[0] - first * 40n;
    log.debug('Leaving Krb5PkinitCodec.decOid().');
    return [first, second].concat(arcs.slice(1)).map(String).join('.');
  }

  /**
   * Encodes a BIT STRING of whole octets (no unused bits).
   *
   * @param bytes - the octets
   * @returns the DER
   */
  static encBitString(bytes: Uint8Array): Uint8Array {
    log.debug('Entering Krb5PkinitCodec.encBitString().');
    log.debug('Leaving Krb5PkinitCodec.encBitString().');
    return asn1.tlv(BIT_STRING_TAG,
                    new Uint8Array(Buffer.concat([Buffer.from([0]),
                                                  Buffer.from(bytes)])));
  }

  /**
   * Decodes a BIT STRING of whole octets.
   *
   * @param t - the TLV
   * @returns the octets
   * @throws Error when it is not one, or has unused bits
   */
  static decBitString(t: Json): Uint8Array {
    log.debug('Entering Krb5PkinitCodec.decBitString().');
    if (!t || t.tag !== BIT_STRING_TAG || !t.value.length ||
        t.value[0] !== 0) {
      log.debug('Leaving Krb5PkinitCodec.decBitString(). Not one.');
      // error-code: none — a decoder; the caller refuses what does not decode
      throw new Error('krb5-pkinit: expected a BIT STRING of whole octets');
    }
    log.debug('Leaving Krb5PkinitCodec.decBitString().');
    return t.value.subarray(1);
  }

  // The bytes of an IMPLICIT [n] OCTET STRING field, primitive.
  private static implicitOctets(t: Json, what: string): Uint8Array {
    log.debug('Entering Krb5PkinitCodec.implicitOctets(). ' + what);
    if (!t || (t.tag & 0x20)) {
      log.debug('Leaving Krb5PkinitCodec.implicitOctets(). Constructed.');
      // error-code: none — a decoder; the caller refuses what does not decode
      throw new Error('krb5-pkinit: ' + what + ' is not a primitive ' +
                      'OCTET STRING');
    }
    log.debug('Leaving Krb5PkinitCodec.implicitOctets().');
    return t.value;
  }

  // -------------------------------------------------------------------------
  // RFC 4556 section 3.2.2: KRB5PrincipalName ::= SEQUENCE { realm [0]
  // Realm, principalName [1] PrincipalName }. What an id-pkinit-san carries,
  // and RFC 8636's partyUInfo and partyVInfo.
  // -------------------------------------------------------------------------
  /**
   * Encodes a KRB5PrincipalName.
   *
   * @param realm - the realm
   * @param name - the PrincipalName, `{ type, name }`
   * @returns the DER
   */
  static encKrb5PrincipalName(realm: string, name: Json): Uint8Array {
    log.debug('Entering Krb5PkinitCodec.encKrb5PrincipalName().');
    log.debug('Leaving Krb5PkinitCodec.encKrb5PrincipalName().');
    return asn1.encTaggedSequence([
      { tag: 0, value: asn1.encGeneralString(realm) },
      { tag: 1, value: msgs.encPrincipalName(name) }
    ]);
  }

  /**
   * Decodes a KRB5PrincipalName.
   *
   * @param bytes - the DER
   * @returns `{ realm, name }`
   * @throws Error when it does not decode
   */
  static readKrb5PrincipalName(bytes: Uint8Array): Json {
    log.debug('Entering Krb5PkinitCodec.readKrb5PrincipalName().');
    const f = fastCodec.fieldsOf(asn1.readTlv(bytes, 0), 'KRB5PrincipalName');
    const out = {
      realm: asn1.decGeneralString(fastCodec.required(f, 0,
                                                      'KRB5PrincipalName')),
      name: msgs.readPrincipalName(fastCodec.required(f, 1,
                                                      'KRB5PrincipalName'))
    };
    log.debug('Leaving Krb5PkinitCodec.readKrb5PrincipalName().');
    return out;
  }

  // -------------------------------------------------------------------------
  // RFC 4556 section 3.2.1: PA-PK-AS-REQ ::= SEQUENCE { signedAuthPack [0]
  // IMPLICIT OCTET STRING, trustedCertifiers [1] SEQUENCE OF
  // ExternalPrincipalIdentifier OPTIONAL, kdcPkId [2] IMPLICIT OCTET STRING
  // OPTIONAL, ... }.
  // -------------------------------------------------------------------------
  /**
   * Encodes a PA-PK-AS-REQ.
   *
   * @param req - `{ signedAuthPack, kdcPkId }`
   * @returns the DER
   */
  static encPaPkAsReq(req: Json): Uint8Array {
    log.debug('Entering Krb5PkinitCodec.encPaPkAsReq().');
    log.debug('Leaving Krb5PkinitCodec.encPaPkAsReq().');
    return fastCodec.implicitSequence([
      fastCodec.iOctets(0, req.signedAuthPack),
      req.kdcPkId ? fastCodec.iOctets(2, req.kdcPkId) : null
    ]);
  }

  /**
   * Decodes a PA-PK-AS-REQ. The trusted certifiers are kept as their DER,
   * since they are hints this KDC does not need: it has one chain.
   *
   * @param bytes - the padata value
   * @returns `{ signedAuthPack, trustedCertifiers, kdcPkId }`
   * @throws Error when it does not decode
   */
  static readPaPkAsReq(bytes: Uint8Array): Json {
    log.debug('Entering Krb5PkinitCodec.readPaPkAsReq().');
    const t = asn1.readTlv(bytes, 0);
    const f = fastCodec.implicitFields(t, 'PA-PK-AS-REQ');
    if (!f[0]) {
      log.debug('Leaving Krb5PkinitCodec.readPaPkAsReq(). No AuthPack.');
      // error-code: none — a decoder; the caller refuses what does not decode
      throw new Error('krb5-pkinit: PA-PK-AS-REQ has no signedAuthPack');
    }
    const out = {
      signedAuthPack: Krb5PkinitCodec.implicitOctets(f[0], 'signedAuthPack'),
      trustedCertifiers: f[1] ? f[1].raw : null,
      kdcPkId: f[2] ? Krb5PkinitCodec.implicitOctets(f[2], 'kdcPkId') : null
    };
    log.debug('Leaving Krb5PkinitCodec.readPaPkAsReq().');
    return out;
  }

  // -------------------------------------------------------------------------
  // AuthPack ::= SEQUENCE { pkAuthenticator [0] PKAuthenticator,
  // clientPublicValue [1] SubjectPublicKeyInfo OPTIONAL, supportedCMSTypes
  // [2] SEQUENCE OF AlgorithmIdentifier OPTIONAL, clientDHNonce [3] DHNonce
  // OPTIONAL, ..., supportedKDFs [4] SEQUENCE OF KDFAlgorithmId OPTIONAL
  // (RFC 8636) }, and PKAuthenticator ::= SEQUENCE { cusec [0] INTEGER, ctime
  // [1] KerberosTime, nonce [2] INTEGER (0..4294967295), paChecksum [3] OCTET
  // STRING OPTIONAL, ..., freshnessToken [4] OCTET STRING OPTIONAL (RFC
  // 8070) }. KDFAlgorithmId ::= SEQUENCE { kdf-id [0] OBJECT IDENTIFIER }.
  //
  // THE NONCE IS ECHOED AS IT WAS READ. MIT's client encodes it as a signed
  // 32-bit INTEGER, so a value with the top bit set arrives negative; the
  // KDCDHKeyInfo carries back the same number, which re-encodes to the same
  // bytes.
  // -------------------------------------------------------------------------
  /**
   * Encodes an AuthPack, for a client (the suite's own).
   *
   * @param pack - `{ cusec, ctime, nonce, paChecksum, freshnessToken,
   *   clientPublicValue, supportedKdfs, clientDhNonce }`
   * @returns the DER
   */
  static encAuthPack(pack: Json): Uint8Array {
    log.debug('Entering Krb5PkinitCodec.encAuthPack().');
    const authenticator = asn1.encTaggedSequence([
      { tag: 0, value: asn1.encInteger(pack.cusec) },
      { tag: 1, value: asn1.encKerberosTime(pack.ctime) },
      { tag: 2, value: asn1.encInteger(pack.nonce) },
      pack.paChecksum
        ? { tag: 3, value: asn1.encOctetString(pack.paChecksum) } : null,
      pack.freshnessToken
        ? { tag: 4, value: asn1.encOctetString(pack.freshnessToken) } : null
    ].filter(Boolean));
    const fields: Json[] = [{ tag: 0, value: authenticator }];
    if (pack.clientPublicValue) {
      fields.push({ tag: 1, value: pack.clientPublicValue });
    }
    if (pack.clientDhNonce) {
      fields.push({ tag: 3, value: asn1.encOctetString(pack.clientDhNonce) });
    }
    if (pack.supportedKdfs) {
      fields.push({ tag: 4, value: asn1.encSequenceOf(
        pack.supportedKdfs.map(Krb5PkinitCodec.encKdfAlgorithmId)) });
    }
    log.debug('Leaving Krb5PkinitCodec.encAuthPack().');
    return asn1.encTaggedSequence(fields);
  }

  /**
   * Decodes an AuthPack. The clientPublicValue is handed back as its DER.
   *
   * @param bytes - the SignedData's eContent
   * @returns `{ cusec, ctime, nonce, paChecksum, freshnessToken,
   *   clientPublicValue, supportedKdfs, clientDhNonce, supportedCmsTypes }`;
   *   `supportedKdfs` is null when the field is absent
   * @throws Error when it does not decode
   */
  static readAuthPack(bytes: Uint8Array): Json {
    log.debug('Entering Krb5PkinitCodec.readAuthPack().');
    const f = fastCodec.fieldsOf(asn1.readTlv(bytes, 0), 'AuthPack');
    const a = fastCodec.fieldsOf(fastCodec.required(f, 0, 'AuthPack'),
                                 'PKAuthenticator');
    const out = {
      cusec: asn1.decInteger(fastCodec.required(a, 0, 'PKAuthenticator')),
      ctime: asn1.decKerberosTime(fastCodec.required(a, 1,
                                                     'PKAuthenticator')),
      nonce: asn1.decInteger(fastCodec.required(a, 2, 'PKAuthenticator')),
      paChecksum: a[3] ? asn1.decOctetString(a[3]) : null,
      freshnessToken: a[4] ? asn1.decOctetString(a[4]) : null,
      clientPublicValue: f[1] ? f[1].raw : null,
      supportedCmsTypes: f[2] ? asn1.decSequenceOf(f[2]).length : 0,
      clientDhNonce: f[3] ? asn1.decOctetString(f[3]) : null,
      supportedKdfs: f[4]
        ? asn1.decSequenceOf(f[4]).map(Krb5PkinitCodec.readKdfAlgorithmId)
        : null
    };
    log.debug('Leaving Krb5PkinitCodec.readAuthPack().');
    return out;
  }

  /**
   * Encodes a KDFAlgorithmId.
   *
   * @param oid - the KDF's OID
   * @returns the DER
   */
  static encKdfAlgorithmId(oid: string): Uint8Array {
    log.debug('Entering Krb5PkinitCodec.encKdfAlgorithmId().');
    log.debug('Leaving Krb5PkinitCodec.encKdfAlgorithmId().');
    return asn1.encTaggedSequence([
      { tag: 0, value: Krb5PkinitCodec.encOid(oid) }]);
  }

  /**
   * Decodes a KDFAlgorithmId.
   *
   * @param t - the SEQUENCE's TLV
   * @returns the KDF's OID
   * @throws Error when it does not decode
   */
  static readKdfAlgorithmId(t: Json): string {
    log.debug('Entering Krb5PkinitCodec.readKdfAlgorithmId().');
    const f = fastCodec.fieldsOf(t, 'KDFAlgorithmId');
    log.debug('Leaving Krb5PkinitCodec.readKdfAlgorithmId().');
    return Krb5PkinitCodec.decOid(fastCodec.required(f, 0, 'KDFAlgorithmId'));
  }

  // -------------------------------------------------------------------------
  // RFC 4556 section 3.2.3: KDCDHKeyInfo ::= SEQUENCE { subjectPublicKey [0]
  // BIT STRING, nonce [1] INTEGER, dhKeyExpiration [2] KerberosTime OPTIONAL
  // }, and the reply: PA-PK-AS-REP ::= CHOICE { dhInfo [0] DHRepInfo, ... }
  // with DHRepInfo ::= SEQUENCE { dhSignedData [0] IMPLICIT OCTET STRING,
  // serverDHNonce [1] DHNonce OPTIONAL, ..., kdf [2] KDFAlgorithmId OPTIONAL
  // (RFC 8636) }. The [0] of the CHOICE is IMPLICIT on the wire — the
  // header says why.
  // -------------------------------------------------------------------------
  /**
   * Encodes a KDCDHKeyInfo.
   *
   * @param info - `{ subjectPublicKey, nonce }`
   * @returns the DER
   */
  static encKdcDhKeyInfo(info: Json): Uint8Array {
    log.debug('Entering Krb5PkinitCodec.encKdcDhKeyInfo().');
    log.debug('Leaving Krb5PkinitCodec.encKdcDhKeyInfo().');
    return asn1.encTaggedSequence([
      { tag: 0, value: Krb5PkinitCodec.encBitString(info.subjectPublicKey) },
      { tag: 1, value: asn1.encInteger(info.nonce) }
    ]);
  }

  /**
   * Decodes a KDCDHKeyInfo, for a client (the suite's own).
   *
   * @param bytes - the DER
   * @returns `{ subjectPublicKey, nonce }`
   * @throws Error when it does not decode
   */
  static readKdcDhKeyInfo(bytes: Uint8Array): Json {
    log.debug('Entering Krb5PkinitCodec.readKdcDhKeyInfo().');
    const f = fastCodec.fieldsOf(asn1.readTlv(bytes, 0), 'KDCDHKeyInfo');
    const out = {
      subjectPublicKey: Krb5PkinitCodec.decBitString(
        fastCodec.required(f, 0, 'KDCDHKeyInfo')),
      nonce: asn1.decInteger(fastCodec.required(f, 1, 'KDCDHKeyInfo'))
    };
    log.debug('Leaving Krb5PkinitCodec.readKdcDhKeyInfo().');
    return out;
  }

  /**
   * Encodes a PA-PK-AS-REP carrying a DHRepInfo, with the CHOICE's [0]
   * implicit as MIT and Windows write it.
   *
   * @param rep - `{ dhSignedData, kdf }`; `kdf` is an OID, or null for RFC
   *   4556's own derivation
   * @returns the DER
   */
  static encPaPkAsRep(rep: Json): Uint8Array {
    log.debug('Entering Krb5PkinitCodec.encPaPkAsRep().');
    const fields = [fastCodec.iOctets(0, rep.dhSignedData)];
    if (rep.kdf) {
      fields.push(asn1.encContext(2,
                                  Krb5PkinitCodec.encKdfAlgorithmId(rep.kdf)));
    }
    log.debug('Leaving Krb5PkinitCodec.encPaPkAsRep().');
    return fastCodec.implicit(0, fastCodec.implicitSequence(fields)) as
      Uint8Array;
  }

  /**
   * Decodes a PA-PK-AS-REP's DHRepInfo, IMPLICIT or EXPLICIT, for a client
   * (the suite's own).
   *
   * @param bytes - the padata value
   * @returns `{ dhSignedData, kdf }`
   * @throws Error when it does not decode
   */
  static readPaPkAsRep(bytes: Uint8Array): Json {
    log.debug('Entering Krb5PkinitCodec.readPaPkAsRep().');
    const outer = asn1.readTlv(bytes, 0);
    if (outer.tag !== asn1.contextTag(0)) {
      log.debug('Leaving Krb5PkinitCodec.readPaPkAsRep(). Not dhInfo.');
      // error-code: none — a decoder; the caller refuses what does not decode
      throw new Error('krb5-pkinit: PA-PK-AS-REP is not dhInfo');
    }
    const kids = asn1.readChildren(outer.value);
    const inner = kids.length === 1 && kids[0].tag === asn1.TAG.SEQUENCE
      ? asn1.readChildren(kids[0].value) : kids;
    const byTag: Json = {};
    inner.forEach(function (one: Json) {
      byTag[one.tag & 0x1f] = one;
    });
    if (!byTag[0]) {
      log.debug('Leaving Krb5PkinitCodec.readPaPkAsRep(). No signed data.');
      // error-code: none — a decoder; the caller refuses what does not decode
      throw new Error('krb5-pkinit: DHRepInfo has no dhSignedData');
    }
    const out = {
      dhSignedData: byTag[0].value,
      kdf: byTag[2]
        ? Krb5PkinitCodec.readKdfAlgorithmId(asn1.readChildren(
            byTag[2].value)[0])
        : null
    };
    log.debug('Leaving Krb5PkinitCodec.readPaPkAsRep().');
    return out;
  }

  // -------------------------------------------------------------------------
  // RFC 8636 section 6: OtherInfo ::= SEQUENCE { algorithmID
  // AlgorithmIdentifier, partyUInfo [0] OCTET STRING, partyVInfo [1] OCTET
  // STRING, suppPubInfo [2] OCTET STRING OPTIONAL, suppPrivInfo [3] ... },
  // with PkinitSuppPubInfo ::= SEQUENCE { enctype [0] Int32, as-REQ [1]
  // OCTET STRING, pk-as-rep [2] OCTET STRING }.
  //
  // The AlgorithmIdentifier carries NO parameters, and partyVInfo is the
  // TGS's name AS THE AS-REQ CARRIES IT: RFC 8636 section 8's vectors are
  // reproduced exactly that way (and with the name type of `krbtgt/SU.SE`
  // being NT-PRINCIPAL, which is what MIT's parser makes of the string the
  // vectors give), and by no other reading.
  // -------------------------------------------------------------------------
  /**
   * Encodes RFC 8636's OtherInfo, the KDF's context.
   *
   * @param opts - `kdf` (the OID), `client` and `server` (KRB5PrincipalName
   *   DER), `etype`, `asReq` (the AS-REQ as received) and `pkAsRep` (the
   *   PA-PK-AS-REP's DER)
   * @returns the DER
   */
  static encOtherInfo(opts: Json): Uint8Array {
    log.debug('Entering Krb5PkinitCodec.encOtherInfo().');
    const supp = asn1.encTaggedSequence([
      { tag: 0, value: asn1.encInteger(opts.etype) },
      { tag: 1, value: asn1.encOctetString(opts.asReq) },
      { tag: 2, value: asn1.encOctetString(opts.pkAsRep) }
    ]);
    log.debug('Leaving Krb5PkinitCodec.encOtherInfo().');
    return asn1.encSequence([
      asn1.encSequence([Krb5PkinitCodec.encOid(opts.kdf)]),
      asn1.encContext(0, asn1.encOctetString(opts.client)),
      asn1.encContext(1, asn1.encOctetString(opts.server)),
      asn1.encContext(2, asn1.encOctetString(supp))
    ]);
  }

  // -------------------------------------------------------------------------
  // TYPED-DATA (RFC 4120 section 5.9.1) ::= SEQUENCE SIZE (1..MAX) OF
  // SEQUENCE { data-type [0] Int32, data-value [1] OCTET STRING OPTIONAL } —
  // the e-data of every PKINIT error but the freshness ones, which are a
  // METHOD-DATA.
  // -------------------------------------------------------------------------
  /**
   * Encodes a TYPED-DATA.
   *
   * @param list - `{ type, value }` entries
   * @returns the DER
   */
  static encTypedData(list: Json[]): Uint8Array {
    log.debug('Entering Krb5PkinitCodec.encTypedData().');
    log.debug('Leaving Krb5PkinitCodec.encTypedData().');
    return asn1.encSequenceOf(list.map(function (one: Json) {
      return asn1.encTaggedSequence([
        { tag: 0, value: asn1.encInteger(one.type) },
        one.value ? { tag: 1, value: asn1.encOctetString(one.value) } : null
      ].filter(Boolean));
    }));
  }

  /**
   * Decodes a TYPED-DATA, for a client (the suite's own).
   *
   * @param bytes - the e-data
   * @returns `{ type, value }` entries
   * @throws Error when it does not decode
   */
  static readTypedData(bytes: Uint8Array): Json[] {
    log.debug('Entering Krb5PkinitCodec.readTypedData().');
    const out = asn1.decSequenceOf(asn1.readTlv(bytes, 0)).map(
      function (t: Json) {
        const f = fastCodec.fieldsOf(t, 'TYPED-DATA');
        return { type: asn1.decInteger(fastCodec.required(f, 0,
                                                          'TYPED-DATA')),
                 value: f[1] ? asn1.decOctetString(f[1]) : null };
      });
    log.debug('Leaving Krb5PkinitCodec.readTypedData().');
    return out;
  }

  /**
   * Encodes a SEQUENCE OF already-encoded elements — TD-DH-PARAMETERS,
   * TD-CMS-DIGEST-ALGORITHMS, TD-TRUSTED-CERTIFIERS.
   *
   * @param elements - the DER of each
   * @returns the DER
   */
  static encSequenceOfRaw(elements: Uint8Array[]): Uint8Array {
    log.debug('Entering Krb5PkinitCodec.encSequenceOfRaw().');
    log.debug('Leaving Krb5PkinitCodec.encSequenceOfRaw().');
    return asn1.encSequenceOf(elements.map(function (one) {
      return new Uint8Array(one);
    }));
  }

  // -------------------------------------------------------------------------
  // ExternalPrincipalIdentifier ::= SEQUENCE { subjectName [0] IMPLICIT
  // OCTET STRING OPTIONAL, issuerAndSerialNumber [1] IMPLICIT OCTET STRING
  // OPTIONAL, subjectKeyIdentifier [2] IMPLICIT OCTET STRING OPTIONAL }. What
  // TD-TRUSTED-CERTIFIERS lists and AD-INITIAL-VERIFIED-CAS carries.
  // -------------------------------------------------------------------------
  /**
   * Encodes an ExternalPrincipalIdentifier.
   *
   * @param epi - `{ subjectName, issuerAndSerialNumber, subjectKeyIdentifier
   *   }`, each the DER the field holds, or null
   * @returns the DER
   */
  static encExternalPrincipalIdentifier(epi: Json): Uint8Array {
    log.debug('Entering Krb5PkinitCodec.encExternalPrincipalIdentifier().');
    log.debug('Leaving Krb5PkinitCodec.encExternalPrincipalIdentifier().');
    return fastCodec.implicitSequence([
      epi.subjectName ? fastCodec.iOctets(0, epi.subjectName) : null,
      epi.issuerAndSerialNumber
        ? fastCodec.iOctets(1, epi.issuerAndSerialNumber) : null,
      epi.subjectKeyIdentifier
        ? fastCodec.iOctets(2, epi.subjectKeyIdentifier) : null
    ]);
  }

  /**
   * Encodes AD-INITIAL-VERIFIED-CAS as an authorization data element.
   *
   * @param epis - the ExternalPrincipalIdentifiers of the path's CAs
   * @returns `{ type, data }`
   */
  static initialVerifiedCas(epis: Json[]): Json {
    log.debug('Entering Krb5PkinitCodec.initialVerifiedCas().');
    log.debug('Leaving Krb5PkinitCodec.initialVerifiedCas().');
    return { type: Krb5PkinitCodec.AD_INITIAL_VERIFIED_CAS,
             data: asn1.encSequenceOf(
               epis.map(Krb5PkinitCodec.encExternalPrincipalIdentifier)) };
  }
}

export = Krb5PkinitCodec;
