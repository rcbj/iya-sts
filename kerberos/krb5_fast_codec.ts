'use strict';
//
// File: krb5_fast_codec.ts
//
// ===========================================================================
// THE WIRE FORMAT OF FAST, OTP PRE-AUTHENTICATION AND AUTHENTICATION
// INDICATORS (#173, 2026-09-22).
//
// Three specifications' ASN.1, which the vendored codec does not have:
//
//   * RFC 6113 (FAST) — PA-FX-FAST-REQUEST, KrbFastArmoredReq, KrbFastArmor,
//     KrbFastReq, PA-FX-FAST-REPLY, KrbFastArmoredRep, KrbFastResponse and
//     KrbFastFinished;
//   * RFC 6560 (OTP pre-authentication) — PA-OTP-CHALLENGE, OTP-TOKENINFO,
//     PA-OTP-REQUEST and PA-OTP-ENC-REQUEST;
//   * RFC 7751 and RFC 8129 — AD-CAMMAC, Verifier-MAC and
//     AD-AUTHENTICATION-INDICATOR.
//
// **A NEW FILE, AND NOT A CHANGE TO `krb5_messages.js`**, because that file
// and `krb5_asn1.js` are VENDORED (kerberos/CLAUDE.md): byte-identical copies
// of the parent project's codec that a sync overwrites. What is here is built
// on their primitives — `encTaggedSequence()`, `readTaggedSequence()`, the
// PA-DATA, EncryptedData, Checksum, PrincipalName, KDC-REQ-BODY and
// AuthorizationData codecs — so a KrbFastReq's req-body is the same reader the
// KDC uses for an ordinary AS-REQ, raw bytes included.
//
// **IT KNOWS NO KEY AND NO POLICY.** Encryption, checksums, KRB-FX-CF2 and
// every decision about what a FAST factor proves are `krb5_fast.ts`'s; this
// file turns structures into DER and back, and a structure that does not
// decode THROWS, which the caller turns into the refusal RFC 6113 names.
//
// A STATIC UTILITY CLASS (#50's rule for helpers): no state, no dependencies
// but the codec and the logger. A LIBRARY (rule 3): it registers nothing and
// is reachable from none of `krb5_kdc.js`, `krb5_service.js` and `spnego.js`,
// so the parent project's COPY set does not grow (kerberos/CLAUDE.md).
// ===========================================================================

import helpers = require('../common/helpers');
import asn1 = require('./krb5_asn1');
import msgs = require('./krb5_messages');

const log = helpers.log;

// A decoded structure: plain objects of the vendored codec's shapes.
type Json = any;

// UTF8String, universal tag 12. RFC 6560's otp-service, otp-vendor and
// otp-pin, and every element of an AD-AUTHENTICATION-INDICATOR.
const UTF8_STRING = 0x0c;

class Krb5FastCodec {
  // RFC 6113 section 6.4 and RFC 6560 section 5: the padata types.
  static readonly PA = {
    FX_COOKIE: 133,
    AUTHENTICATION_SET: 134,
    AUTH_SET_SELECTED: 135,
    FX_FAST: 136,
    FX_ERROR: 137,
    ENCRYPTED_CHALLENGE: 138,
    OTP_CHALLENGE: 141,
    OTP_REQUEST: 142,
    OTP_PIN_CHANGE: 144
  };

  // The key usages. 45 is RFC 6560's, 50 to 55 RFC 6113's, 64 RFC 7751's.
  // 513 is NOT a registered number: it is the private usage MIT's KDC seals
  // its PA-FX-COOKIE under (`KRB5_KEYUSAGE_PA_FX_COOKIE`), and a cookie's
  // content is "a local matter of the KDC" (RFC 6113 section 5.2). Reusing
  // MIT's number costs nothing and names no registered purpose.
  static readonly KEY_USAGE = {
    OTP_REQUEST: 45,
    FAST_REQ_CHKSUM: 50,
    FAST_ENC: 51,
    FAST_REP: 52,
    FAST_FINISHED: 53,
    ENC_CHALLENGE_CLIENT: 54,
    ENC_CHALLENGE_KDC: 55,
    CAMMAC: 64,
    FX_COOKIE: 513
  };

  // Authorization data types: RFC 4120's AD-IF-RELEVANT, RFC 6113's two FAST
  // markers, RFC 7751's container and RFC 8129's indicator.
  static readonly AD = {
    IF_RELEVANT: 1,
    FX_FAST_ARMOR: 71,
    FX_FAST_USED: 72,
    CAMMAC: 96,
    AUTHENTICATION_INDICATOR: 97
  };

  // RFC 6113 section 5.4.1: the one armor type defined.
  static readonly ARMOR_AP_REQUEST = 1;

  // FastOptions bits (RFC 6113 section 5.4.2). Bits 0 to 15 are CRITICAL.
  static readonly FAST_OPTION = {
    RESERVED: 0,
    HIDE_CLIENT_NAMES: 1,
    KDC_FOLLOW_REFERRALS: 16
  };

  // OTPFlags (RFC 6560 section 4.1), numbered from the most significant bit
  // as every KerberosFlags value is.
  static readonly OTP_FLAG = {
    NEXT_OTP: 1,
    COMBINE: 2,
    COLLECT_PIN: 3,
    DO_NOT_COLLECT_PIN: 4,
    MUST_ENCRYPT_NONCE: 5,
    SEPARATE_PIN_REQUIRED: 6,
    CHECK_DIGIT: 7
  };

  static readonly OTP_FORMAT = {
    DECIMAL: 0,
    HEXADECIMAL: 1,
    ALPHANUMERIC: 2,
    BINARY: 3,
    BASE64: 4
  };

  // RFC 6113 section 6.1 and RFC 6560 section 2.3: the error codes.
  static readonly ERROR = {
    PREAUTH_EXPIRED: 90,
    MORE_PREAUTH_DATA_REQUIRED: 91,
    PREAUTH_BAD_AUTHENTICATION_SET: 92,
    UNKNOWN_CRITICAL_FAST_OPTIONS: 93,
    INVALID_HASH_ALG: 94,
    INVALID_ITERATION_COUNT: 95,
    PIN_EXPIRED: 96,
    PIN_REQUIRED: 97
  };

  // -------------------------------------------------------------------------
  // PRIMITIVES the vendored codec lacks.
  // -------------------------------------------------------------------------
  static encUtf8(text: string): Uint8Array {
    log.debug('Entering Krb5FastCodec.encUtf8().');
    log.debug('Leaving Krb5FastCodec.encUtf8().');
    return asn1.tlv(UTF8_STRING, new Uint8Array(Buffer.from(String(text),
                                                            'utf8')));
  }

  static decUtf8(t: Json): string {
    log.debug('Entering Krb5FastCodec.decUtf8().');
    if (!t || t.tag !== UTF8_STRING) {
      log.debug('Leaving Krb5FastCodec.decUtf8(). Not a UTF8String.');
      // error-code: none — a decoder; the caller refuses what does not decode
      throw new Error('krb5-fast: expected a UTF8String, saw tag 0x' +
                      (t ? Number(t.tag).toString(16) : '??'));
    }
    log.debug('Leaving Krb5FastCodec.decUtf8().');
    return Buffer.from(t.value).toString('utf8');
  }

  // The one element inside an explicit context tag, which is how a CHOICE
  // alternative `[0] X` arrives. Throws unless it is exactly `[n]` round one
  // element.
  static explicit(bytes: Uint8Array, n: number): Json {
    log.debug('Entering Krb5FastCodec.explicit(). [' + n + ']');
    const outer = asn1.readTlv(bytes, 0);
    if (outer.tag !== asn1.contextTag(n)) {
      log.debug('Leaving Krb5FastCodec.explicit(). Wrong tag.');
      // error-code: none — a decoder; the caller refuses what does not decode
      throw new Error('krb5-fast: expected [' + n + '], saw tag 0x' +
                      Number(outer.tag).toString(16));
    }
    const inner = asn1.readChildren(outer.value);
    if (inner.length !== 1) {
      log.debug('Leaving Krb5FastCodec.explicit(). Not one element.');
      // error-code: none — a decoder; the caller refuses what does not decode
      throw new Error('krb5-fast: [' + n + '] wraps ' + inner.length +
                      ' elements, expected 1');
    }
    log.debug('Leaving Krb5FastCodec.explicit().');
    return inner[0];
  }

  // A SEQUENCE's context-tagged fields, from the SEQUENCE's own TLV.
  static fieldsOf(t: Json, what: string): Json {
    log.debug('Entering Krb5FastCodec.fieldsOf(). ' + what);
    if (!t || t.tag !== asn1.TAG.SEQUENCE) {
      log.debug('Leaving Krb5FastCodec.fieldsOf(). Not a SEQUENCE.');
      // error-code: none — a decoder; the caller refuses what does not decode
      throw new Error('krb5-fast: ' + what + ' is not a SEQUENCE');
    }
    log.debug('Leaving Krb5FastCodec.fieldsOf().');
    return asn1.readTaggedSequence(t.value);
  }

  static required(f: Json, n: number, what: string): Json {
    log.debug('Entering Krb5FastCodec.required(). ' + what);
    if (!f[n]) {
      log.debug('Leaving Krb5FastCodec.required(). Missing.');
      // error-code: none — a decoder; the caller refuses what does not decode
      throw new Error('krb5-fast: ' + what + ' has no field [' + n + ']');
    }
    log.debug('Leaving Krb5FastCodec.required().');
    return f[n];
  }

  static padataList(t: Json): Json[] {
    log.debug('Entering Krb5FastCodec.padataList().');
    log.debug('Leaving Krb5FastCodec.padataList().');
    return asn1.decSequenceOf(t).map(msgs.readPaData);
  }

  static encPadataList(list: Json[]): Uint8Array {
    log.debug('Entering Krb5FastCodec.encPadataList().');
    log.debug('Leaving Krb5FastCodec.encPadataList().');
    return asn1.encSequenceOf((list || []).map(msgs.encPaData));
  }

  // -------------------------------------------------------------------------
  // RFC 6113 section 5.4.1: KrbFastArmor ::= SEQUENCE { armor-type [0] Int32,
  // armor-value [1] OCTET STRING }.
  // -------------------------------------------------------------------------
  static encArmor(armor: Json): Uint8Array {
    log.debug('Entering Krb5FastCodec.encArmor().');
    log.debug('Leaving Krb5FastCodec.encArmor().');
    return asn1.encTaggedSequence([
      { tag: 0, value: asn1.encInteger(armor.type) },
      { tag: 1, value: asn1.encOctetString(armor.value) }
    ]);
  }

  static readArmor(t: Json): Json {
    log.debug('Entering Krb5FastCodec.readArmor().');
    const f = Krb5FastCodec.fieldsOf(t, 'KrbFastArmor');
    log.debug('Leaving Krb5FastCodec.readArmor().');
    return {
      type: asn1.decInteger(Krb5FastCodec.required(f, 0, 'KrbFastArmor')),
      value: asn1.decOctetString(Krb5FastCodec.required(f, 1,
                                                        'KrbFastArmor'))
    };
  }

  // -------------------------------------------------------------------------
  // RFC 6113 section 5.4.2: PA-FX-FAST-REQUEST ::= CHOICE { armored-data [0]
  // KrbFastArmoredReq }, KrbFastArmoredReq ::= SEQUENCE { armor [0]
  // KrbFastArmor OPTIONAL, req-checksum [1] Checksum, enc-fast-req [2]
  // EncryptedData }.
  // -------------------------------------------------------------------------
  static encFastRequest(req: Json): Uint8Array {
    log.debug('Entering Krb5FastCodec.encFastRequest().');
    log.debug('Leaving Krb5FastCodec.encFastRequest().');
    return asn1.encContext(0, asn1.encTaggedSequence([
      { tag: 0, value: req.armor ? Krb5FastCodec.encArmor(req.armor) : null },
      { tag: 1, value: msgs.encChecksum(req.reqChecksum) },
      { tag: 2, value: msgs.encEncryptedData(req.encFastReq) }
    ]));
  }

  static readFastRequest(bytes: Uint8Array): Json {
    log.debug('Entering Krb5FastCodec.readFastRequest().');
    const f = Krb5FastCodec.fieldsOf(Krb5FastCodec.explicit(bytes, 0),
                                     'KrbFastArmoredReq');
    log.debug('Leaving Krb5FastCodec.readFastRequest().');
    return {
      armor: f[0] ? Krb5FastCodec.readArmor(f[0]) : null,
      reqChecksum: msgs.readChecksum(Krb5FastCodec.required(
        f, 1, 'KrbFastArmoredReq')),
      encFastReq: msgs.readEncryptedData(Krb5FastCodec.required(
        f, 2, 'KrbFastArmoredReq'))
    };
  }

  // KrbFastReq ::= SEQUENCE { fast-options [0] FastOptions, padata [1]
  // SEQUENCE OF PA-DATA, req-body [2] KDC-REQ-BODY }. `reqBody` is the
  // vendored reader's, with `raw` kept.
  static encFastReq(req: Json): Uint8Array {
    log.debug('Entering Krb5FastCodec.encFastReq().');
    log.debug('Leaving Krb5FastCodec.encFastReq().');
    return asn1.encTaggedSequence([
      { tag: 0, value: asn1.encFlags(req.fastOptions || []) },
      { tag: 1, value: Krb5FastCodec.encPadataList(req.padata || []) },
      { tag: 2, value: req.reqBody.raw ? req.reqBody.raw
                                       : msgs.encKdcReqBody(req.reqBody) }
    ]);
  }

  static readFastReq(bytes: Uint8Array): Json {
    log.debug('Entering Krb5FastCodec.readFastReq().');
    const f = Krb5FastCodec.fieldsOf(asn1.readTlv(bytes, 0), 'KrbFastReq');
    log.debug('Leaving Krb5FastCodec.readFastReq().');
    return {
      fastOptions: asn1.bitsFromFlags(asn1.decFlags(
        Krb5FastCodec.required(f, 0, 'KrbFastReq'))),
      padata: Krb5FastCodec.padataList(Krb5FastCodec.required(f, 1,
                                                              'KrbFastReq')),
      reqBody: msgs.readKdcReqBody(Krb5FastCodec.required(f, 2,
                                                          'KrbFastReq'))
    };
  }

  // -------------------------------------------------------------------------
  // RFC 6113 section 5.4.3: PA-FX-FAST-REPLY ::= CHOICE { armored-data [0]
  // KrbFastArmoredRep }, KrbFastArmoredRep ::= SEQUENCE { enc-fast-rep [0]
  // EncryptedData }.
  // -------------------------------------------------------------------------
  static encFastReply(encFastRep: Json): Uint8Array {
    log.debug('Entering Krb5FastCodec.encFastReply().');
    log.debug('Leaving Krb5FastCodec.encFastReply().');
    return asn1.encContext(0, asn1.encTaggedSequence([
      { tag: 0, value: msgs.encEncryptedData(encFastRep) }
    ]));
  }

  static readFastReply(bytes: Uint8Array): Json {
    log.debug('Entering Krb5FastCodec.readFastReply().');
    const f = Krb5FastCodec.fieldsOf(Krb5FastCodec.explicit(bytes, 0),
                                     'KrbFastArmoredRep');
    log.debug('Leaving Krb5FastCodec.readFastReply().');
    return msgs.readEncryptedData(Krb5FastCodec.required(
      f, 0, 'KrbFastArmoredRep'));
  }

  // KrbFastResponse ::= SEQUENCE { padata [0] SEQUENCE OF PA-DATA,
  // strengthen-key [1] EncryptionKey OPTIONAL, finished [2] KrbFastFinished
  // OPTIONAL, nonce [3] UInt32 }.
  static encFastResponse(rep: Json): Uint8Array {
    log.debug('Entering Krb5FastCodec.encFastResponse().');
    log.debug('Leaving Krb5FastCodec.encFastResponse().');
    return asn1.encTaggedSequence([
      { tag: 0, value: Krb5FastCodec.encPadataList(rep.padata || []) },
      { tag: 1, value: rep.strengthenKey
          ? msgs.encEncryptionKey(rep.strengthenKey) : null },
      { tag: 2, value: rep.finished
          ? Krb5FastCodec.encFastFinished(rep.finished) : null },
      { tag: 3, value: asn1.encInteger(rep.nonce) }
    ]);
  }

  static readFastResponse(bytes: Uint8Array): Json {
    log.debug('Entering Krb5FastCodec.readFastResponse().');
    const f = Krb5FastCodec.fieldsOf(asn1.readTlv(bytes, 0),
                                     'KrbFastResponse');
    log.debug('Leaving Krb5FastCodec.readFastResponse().');
    return {
      padata: Krb5FastCodec.padataList(Krb5FastCodec.required(
        f, 0, 'KrbFastResponse')),
      strengthenKey: f[1] ? msgs.readEncryptionKey(f[1]) : null,
      finished: f[2] ? Krb5FastCodec.readFastFinished(f[2]) : null,
      nonce: asn1.decInteger(Krb5FastCodec.required(f, 3, 'KrbFastResponse'))
    };
  }

  // KrbFastFinished ::= SEQUENCE { timestamp [0] KerberosTime, usec [1]
  // Microseconds, crealm [2] Realm, cname [3] PrincipalName, ticket-checksum
  // [4] Checksum }.
  static encFastFinished(fin: Json): Uint8Array {
    log.debug('Entering Krb5FastCodec.encFastFinished().');
    log.debug('Leaving Krb5FastCodec.encFastFinished().');
    return asn1.encTaggedSequence([
      { tag: 0, value: asn1.encKerberosTime(fin.timestamp) },
      { tag: 1, value: asn1.encInteger(fin.usec || 0) },
      { tag: 2, value: asn1.encGeneralString(fin.crealm) },
      { tag: 3, value: msgs.encPrincipalName(fin.cname) },
      { tag: 4, value: msgs.encChecksum(fin.ticketChecksum) }
    ]);
  }

  static readFastFinished(t: Json): Json {
    log.debug('Entering Krb5FastCodec.readFastFinished().');
    const f = Krb5FastCodec.fieldsOf(t, 'KrbFastFinished');
    log.debug('Leaving Krb5FastCodec.readFastFinished().');
    return {
      timestamp: asn1.decKerberosTime(Krb5FastCodec.required(
        f, 0, 'KrbFastFinished')),
      usec: asn1.decInteger(Krb5FastCodec.required(f, 1, 'KrbFastFinished')),
      crealm: asn1.decGeneralString(Krb5FastCodec.required(
        f, 2, 'KrbFastFinished')),
      cname: msgs.readPrincipalName(Krb5FastCodec.required(
        f, 3, 'KrbFastFinished')),
      ticketChecksum: msgs.readChecksum(Krb5FastCodec.required(
        f, 4, 'KrbFastFinished'))
    };
  }

  // -------------------------------------------------------------------------
  // RFC 6560'S MODULE IS `DEFINITIONS IMPLICIT TAGS` (its Appendix A), and
  // RFC 6113's, 7751's and 8129's are EXPLICIT — so the OTP structures below
  // are the one place in Kerberos where a field's context tag REPLACES the
  // universal tag instead of wrapping it: `[0] OCTET STRING` is `80 len
  // bytes`, not `a0 len 04 len bytes`. It was written explicit first, and
  // both this codec and the suite's own client agreed with each other; MIT's
  // `kinit` refused the challenge with "ASN.1 structure is missing a required
  // field", which is what a real client is for. `implicit()` turns an encoded
  // universal TLV into its context-tagged form (the constructed bit kept, the
  // length unchanged), and `asUniversal()` the reverse for the readers.
  // -------------------------------------------------------------------------
  static implicit(n: number, encoded: Uint8Array | null): Uint8Array | null {
    log.debug('Entering Krb5FastCodec.implicit(). [' + n + ']');
    if (!encoded) {
      log.debug('Leaving Krb5FastCodec.implicit(). Absent.');
      return null;
    }
    const out = Buffer.from(encoded);
    out[0] = (out[0] & 0x20) ? (0xa0 | n) : (0x80 | n);
    log.debug('Leaving Krb5FastCodec.implicit().');
    return new Uint8Array(out);
  }

  static asUniversal(t: Json, tag: number): Json {
    log.debug('Entering Krb5FastCodec.asUniversal().');
    const raw = Buffer.from(t.raw);
    raw[0] = tag;
    log.debug('Leaving Krb5FastCodec.asUniversal().');
    return asn1.readTlv(new Uint8Array(raw), 0);
  }

  // The fields of an IMPLICITLY tagged SEQUENCE, by context tag number.
  static implicitFields(t: Json, what: string): Json {
    log.debug('Entering Krb5FastCodec.implicitFields(). ' + what);
    if (!t || t.tag !== asn1.TAG.SEQUENCE) {
      log.debug('Leaving Krb5FastCodec.implicitFields(). Not a SEQUENCE.');
      // error-code: none — a decoder; the caller refuses what does not decode
      throw new Error('krb5-fast: ' + what + ' is not a SEQUENCE');
    }
    const map = {};
    asn1.readChildren(t.value).forEach(function (child) {
      if ((child.tag & 0xc0) !== 0x80) {
        // error-code: none — a decoder; the caller refuses what does not decode
        throw new Error('krb5-fast: ' + what + ' has a field that is not ' +
                        'context-tagged');
      }
      map[child.tag & 0x1f] = child;
    });
    log.debug('Leaving Krb5FastCodec.implicitFields().');
    return map;
  }

  // The implicit-tag builders the OTP structures share: each takes the
  // field's value and answers its context-tagged TLV, or null when absent.
  static iOctets(n: number, value: Uint8Array | null): Uint8Array | null {
    log.debug('Entering Krb5FastCodec.iOctets().');
    log.debug('Leaving Krb5FastCodec.iOctets().');
    return value ? Krb5FastCodec.implicit(n, asn1.encOctetString(value))
                 : null;
  }

  static iUtf8(n: number, value: string | null): Uint8Array | null {
    log.debug('Entering Krb5FastCodec.iUtf8().');
    log.debug('Leaving Krb5FastCodec.iUtf8().');
    return (value === null || value === undefined) ? null
      : Krb5FastCodec.implicit(n, Krb5FastCodec.encUtf8(value));
  }

  static iInt(n: number, value: number | null): Uint8Array | null {
    log.debug('Entering Krb5FastCodec.iInt().');
    log.debug('Leaving Krb5FastCodec.iInt().');
    return (value === null || value === undefined) ? null
      : Krb5FastCodec.implicit(n, asn1.encInteger(value));
  }

  static implicitSequence(fields: Array<Uint8Array | null>): Uint8Array {
    log.debug('Entering Krb5FastCodec.implicitSequence().');
    log.debug('Leaving Krb5FastCodec.implicitSequence().');
    return asn1.encSequence(fields.filter(Boolean));
  }

  // -------------------------------------------------------------------------
  // RFC 6560 section 4.1: PA-OTP-CHALLENGE ::= SEQUENCE { nonce [0] OCTET
  // STRING, otp-service [1] UTF8String OPTIONAL, otp-tokenInfo [2] SEQUENCE
  // (SIZE(1..MAX)) OF OTP-TOKENINFO, salt [3] KerberosString OPTIONAL,
  // s2kparams [4] OCTET STRING OPTIONAL }, every tag IMPLICIT.
  // -------------------------------------------------------------------------
  static encOtpChallenge(chl: Json): Uint8Array {
    log.debug('Entering Krb5FastCodec.encOtpChallenge().');
    log.debug('Leaving Krb5FastCodec.encOtpChallenge().');
    return Krb5FastCodec.implicitSequence([
      Krb5FastCodec.iOctets(0, chl.nonce),
      Krb5FastCodec.iUtf8(1, chl.service || null),
      Krb5FastCodec.implicit(2, asn1.encSequenceOf((chl.tokenInfo || [])
        .map(Krb5FastCodec.encTokenInfo))),
      chl.salt ? Krb5FastCodec.implicit(3, asn1.encGeneralString(chl.salt))
               : null,
      Krb5FastCodec.iOctets(4, chl.s2kparams || null)
    ]);
  }

  static readOtpChallenge(bytes: Uint8Array): Json {
    log.debug('Entering Krb5FastCodec.readOtpChallenge().');
    const f = Krb5FastCodec.implicitFields(asn1.readTlv(bytes, 0),
                                           'PA-OTP-CHALLENGE');
    const nonce = Krb5FastCodec.required(f, 0, 'PA-OTP-CHALLENGE');
    const tokens = Krb5FastCodec.required(f, 2, 'PA-OTP-CHALLENGE');
    log.debug('Leaving Krb5FastCodec.readOtpChallenge().');
    return {
      nonce: nonce.value,
      service: f[1] ? Buffer.from(f[1].value).toString('utf8') : null,
      tokenInfo: asn1.readChildren(tokens.value)
        .map(Krb5FastCodec.readTokenInfo),
      salt: f[3] ? Buffer.from(f[3].value).toString('latin1') : null,
      s2kparams: f[4] ? f[4].value : null
    };
  }

  // OTP-TOKENINFO ::= SEQUENCE { flags [0] OTPFlags, otp-vendor [1]
  // UTF8String OPTIONAL, otp-challenge [2] OCTET STRING OPTIONAL, otp-length
  // [3] Int32 OPTIONAL, otp-format [4] OTPFormat OPTIONAL, otp-tokenID [5]
  // OCTET STRING OPTIONAL, otp-algID [6] AnyURI OPTIONAL, supportedHashAlg
  // [7] ..., iterationCount [8] Int32 OPTIONAL }. The two hashing fields are
  // never written: this KDC does not ask for hashed OTP values.
  static encTokenInfo(ti: Json): Uint8Array {
    log.debug('Entering Krb5FastCodec.encTokenInfo().');
    log.debug('Leaving Krb5FastCodec.encTokenInfo().');
    return Krb5FastCodec.implicitSequence([
      Krb5FastCodec.implicit(0, asn1.encFlags(ti.flags || [])),
      Krb5FastCodec.iUtf8(1, ti.vendor || null),
      Krb5FastCodec.iOctets(2, ti.challenge || null),
      Krb5FastCodec.iInt(3, ti.length),
      Krb5FastCodec.iInt(4, ti.format),
      Krb5FastCodec.iOctets(5, ti.tokenId || null),
      Krb5FastCodec.iUtf8(6, ti.algId || null)
    ]);
  }

  static readTokenInfo(t: Json): Json {
    log.debug('Entering Krb5FastCodec.readTokenInfo().');
    const f = Krb5FastCodec.implicitFields(t, 'OTP-TOKENINFO');
    const flags = Krb5FastCodec.asUniversal(Krb5FastCodec.required(
      f, 0, 'OTP-TOKENINFO'), asn1.TAG.BIT_STRING);
    log.debug('Leaving Krb5FastCodec.readTokenInfo().');
    return {
      flags: asn1.bitsFromFlags(asn1.decFlags(flags)),
      vendor: f[1] ? Buffer.from(f[1].value).toString('utf8') : null,
      challenge: f[2] ? f[2].value : null,
      length: f[3] ? asn1.decInteger(Krb5FastCodec.asUniversal(
        f[3], asn1.TAG.INTEGER)) : null,
      format: f[4] ? asn1.decInteger(Krb5FastCodec.asUniversal(
        f[4], asn1.TAG.INTEGER)) : null,
      tokenId: f[5] ? f[5].value : null,
      algId: f[6] ? Buffer.from(f[6].value).toString('utf8') : null,
      hashing: !!(f[7] || f[8])
    };
  }

  // -------------------------------------------------------------------------
  // RFC 6560 section 4.2: PA-OTP-REQUEST ::= SEQUENCE { flags [0] OTPFlags,
  // nonce [1] OCTET STRING OPTIONAL, encData [2] EncryptedData, hashAlg [3]
  // AlgorithmIdentifier OPTIONAL, iterationCount [4] Int32 OPTIONAL,
  // otp-value [5] OCTET STRING OPTIONAL, otp-pin [6] UTF8String OPTIONAL,
  // otp-challenge [7] ..., otp-time [8] KerberosTime OPTIONAL, otp-counter
  // [9] ..., otp-format [10] ..., otp-tokenID [11] ..., otp-algID [12] ...,
  // otp-vendor [13] UTF8String OPTIONAL }, every tag IMPLICIT — so encData is
  // EncryptedData's own fields under `a2`.
  // -------------------------------------------------------------------------
  static encOtpRequest(req: Json): Uint8Array {
    log.debug('Entering Krb5FastCodec.encOtpRequest().');
    log.debug('Leaving Krb5FastCodec.encOtpRequest().');
    return Krb5FastCodec.implicitSequence([
      Krb5FastCodec.implicit(0, asn1.encFlags(req.flags || [])),
      Krb5FastCodec.iOctets(1, req.nonce || null),
      Krb5FastCodec.implicit(2, msgs.encEncryptedData(req.encData)),
      (req.value === undefined || req.value === null) ? null
        : Krb5FastCodec.iOctets(5, new Uint8Array(Buffer.from(
            String(req.value)))),
      Krb5FastCodec.iUtf8(6, (req.pin === undefined) ? null : req.pin),
      req.time ? Krb5FastCodec.implicit(8, asn1.encKerberosTime(req.time))
               : null,
      Krb5FastCodec.iUtf8(13, req.vendor || null)
    ]);
  }

  static readOtpRequest(bytes: Uint8Array): Json {
    log.debug('Entering Krb5FastCodec.readOtpRequest().');
    const f = Krb5FastCodec.implicitFields(asn1.readTlv(bytes, 0),
                                           'PA-OTP-REQUEST');
    const flags = Krb5FastCodec.asUniversal(Krb5FastCodec.required(
      f, 0, 'PA-OTP-REQUEST'), asn1.TAG.BIT_STRING);
    const encData = Krb5FastCodec.asUniversal(Krb5FastCodec.required(
      f, 2, 'PA-OTP-REQUEST'), asn1.TAG.SEQUENCE);
    log.debug('Leaving Krb5FastCodec.readOtpRequest().');
    return {
      flags: asn1.bitsFromFlags(asn1.decFlags(flags)),
      nonce: f[1] ? f[1].value : null,
      encData: msgs.readEncryptedData(encData),
      // HASHED means a hashAlg, or an iterationCount above zero. MIT's client
      // sends `iterationCount 0` beside a plain otp-value (its request is
      // zero-filled and only -1 is left out), so a zero is not a hashed OTP —
      // read strictly, section 4.2's "MUST NOT be included" would refuse every
      // MIT kinit.
      hashing: !!f[3] || (!!f[4] && asn1.decInteger(
        Krb5FastCodec.asUniversal(f[4], asn1.TAG.INTEGER)) > 0),
      value: f[5] ? Buffer.from(f[5].value).toString('latin1') : null,
      pin: f[6] ? Buffer.from(f[6].value).toString('utf8') : null,
      time: f[8] ? asn1.decKerberosTime(Krb5FastCodec.asUniversal(
        f[8], asn1.TAG.GENERALIZED_TIME)) : null,
      vendor: f[13] ? Buffer.from(f[13].value).toString('utf8') : null
    };
  }

  // PA-OTP-ENC-REQUEST ::= SEQUENCE { nonce [0] OCTET STRING }, implicit.
  static encOtpEncRequest(nonce: Uint8Array): Uint8Array {
    log.debug('Entering Krb5FastCodec.encOtpEncRequest().');
    log.debug('Leaving Krb5FastCodec.encOtpEncRequest().');
    return Krb5FastCodec.implicitSequence([Krb5FastCodec.iOctets(0, nonce)]);
  }

  // What an OTP request's encData opened to: a PA-OTP-ENC-REQUEST (four-pass,
  // `{ nonce }`) or a PA-ENC-TS-ENC (two-pass, `{ timestamp }`). They differ
  // in field [0]'s TAG — RFC 6560's implicit `80` against RFC 4120's
  // explicit `a0` round a GeneralizedTime — which is how a KDC tells them
  // apart (RFC 6560 section 3.4).
  static readOtpEncData(bytes: Uint8Array): Json {
    log.debug('Entering Krb5FastCodec.readOtpEncData().');
    const t = asn1.readTlv(bytes, 0);
    if (!t || t.tag !== asn1.TAG.SEQUENCE) {
      log.debug('Leaving Krb5FastCodec.readOtpEncData(). Not a SEQUENCE.');
      // error-code: none — a decoder; the caller refuses what does not decode
      throw new Error('krb5-fast: the PA-OTP-REQUEST encData is not a ' +
                      'SEQUENCE');
    }
    const first = asn1.readChildren(t.value)[0];
    if (first && first.tag === asn1.contextTag(0)) {
      log.debug('Leaving Krb5FastCodec.readOtpEncData(). A timestamp.');
      return { timestamp: msgs.readPaEncTsEnc(bytes).patimestamp };
    }
    if (!first || first.tag !== 0x80) {
      log.debug('Leaving Krb5FastCodec.readOtpEncData(). Neither.');
      // error-code: none — a decoder; the caller refuses what does not decode
      throw new Error('krb5-fast: the PA-OTP-REQUEST encData is neither a ' +
                      'PA-OTP-ENC-REQUEST nor a PA-ENC-TS-ENC');
    }
    log.debug('Leaving Krb5FastCodec.readOtpEncData(). A nonce.');
    return { nonce: first.value };
  }

  // -------------------------------------------------------------------------
  // RFC 7751 section 4: AD-CAMMAC ::= SEQUENCE { elements [0]
  // AuthorizationData, kdc-verifier [1] Verifier-MAC OPTIONAL, svc-verifier
  // [2] Verifier-MAC OPTIONAL, other-verifiers [3] ... OPTIONAL },
  // Verifier-MAC ::= SEQUENCE { identifier [0] PrincipalName OPTIONAL, kvno
  // [1] UInt32 OPTIONAL, enctype [2] Int32 OPTIONAL, mac [3] Checksum }.
  // -------------------------------------------------------------------------
  static encVerifierMac(v: Json): Uint8Array {
    log.debug('Entering Krb5FastCodec.encVerifierMac().');
    log.debug('Leaving Krb5FastCodec.encVerifierMac().');
    return asn1.encTaggedSequence([
      { tag: 0, value: v.identifier ? msgs.encPrincipalName(v.identifier)
                                    : null },
      { tag: 1, value: (v.kvno === undefined || v.kvno === null)
          ? null : asn1.encInteger(v.kvno) },
      { tag: 2, value: (v.enctype === undefined || v.enctype === null)
          ? null : asn1.encInteger(v.enctype) },
      { tag: 3, value: msgs.encChecksum(v.mac) }
    ]);
  }

  static readVerifierMac(t: Json): Json {
    log.debug('Entering Krb5FastCodec.readVerifierMac().');
    const f = Krb5FastCodec.fieldsOf(t, 'Verifier-MAC');
    log.debug('Leaving Krb5FastCodec.readVerifierMac().');
    return {
      identifier: f[0] ? msgs.readPrincipalName(f[0]) : null,
      kvno: f[1] ? asn1.decInteger(f[1]) : null,
      enctype: f[2] ? asn1.decInteger(f[2]) : null,
      mac: msgs.readChecksum(Krb5FastCodec.required(f, 3, 'Verifier-MAC'))
    };
  }

  // `elementsBytes` is the DER of the AuthorizationData, which is what every
  // verifier's MAC covers — so it is encoded once and those bytes both
  // checksummed and placed.
  static encCammac(c: Json): Uint8Array {
    log.debug('Entering Krb5FastCodec.encCammac().');
    log.debug('Leaving Krb5FastCodec.encCammac().');
    return asn1.encTaggedSequence([
      { tag: 0, value: c.elementsBytes },
      { tag: 1, value: c.kdcVerifier
          ? Krb5FastCodec.encVerifierMac(c.kdcVerifier) : null },
      { tag: 2, value: c.svcVerifier
          ? Krb5FastCodec.encVerifierMac(c.svcVerifier) : null }
    ]);
  }

  static readCammac(bytes: Uint8Array): Json {
    log.debug('Entering Krb5FastCodec.readCammac().');
    const f = Krb5FastCodec.fieldsOf(asn1.readTlv(bytes, 0), 'AD-CAMMAC');
    const elements = Krb5FastCodec.required(f, 0, 'AD-CAMMAC');
    log.debug('Leaving Krb5FastCodec.readCammac().');
    return {
      elementsBytes: elements.raw,
      elements: msgs.readAuthorizationData(elements),
      kdcVerifier: f[1] ? Krb5FastCodec.readVerifierMac(f[1]) : null,
      svcVerifier: f[2] ? Krb5FastCodec.readVerifierMac(f[2]) : null
    };
  }

  // RFC 8129 section 3: AD-AUTHENTICATION-INDICATOR ::= SEQUENCE OF
  // UTF8String.
  static encIndicators(list: string[]): Uint8Array {
    log.debug('Entering Krb5FastCodec.encIndicators().');
    log.debug('Leaving Krb5FastCodec.encIndicators().');
    return asn1.encSequenceOf((list || []).map(Krb5FastCodec.encUtf8));
  }

  static readIndicators(bytes: Uint8Array): string[] {
    log.debug('Entering Krb5FastCodec.readIndicators().');
    log.debug('Leaving Krb5FastCodec.readIndicators().');
    return asn1.decSequenceOf(asn1.readTlv(bytes, 0))
      .map(Krb5FastCodec.decUtf8);
  }

  // The PA-DATA of a type in a list, or null.
  static find(list: Json[], type: number): Json {
    log.debug('Entering Krb5FastCodec.find(). type=' + type);
    log.debug('Leaving Krb5FastCodec.find().');
    return (list || []).filter(function (pa) {
      return pa && pa.type === type;
    })[0] || null;
  }
}

export = Krb5FastCodec;
