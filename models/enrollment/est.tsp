// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/enrollment/est.tsp
//
// Written by hand (#1579). THE SOURCE OF WHAT THE EST SERVER TAKES AND
// ANSWERS AS FACTS THE CODE READS: RFC 7030 with RFC 8951's clarifications
// and draft-ietf-lamps-attestation-freshness-08's `/nonce`. EST's bodies are
// ASN.1 — a PKCS#10 request, a certs-only CMS message, a CSR attributes
// document, a PKCS#8 key — and the DER work stays in `est/est_codec.ts`;
// what is here is what each operation takes and answers: its methods, the
// media type it reads and the one it writes, whether it is authenticated,
// the refusal statuses and which of them count against a caller, the names
// a CSR attributes answer asks a request for, and the one JSON exchange EST
// has, the nonce request and its answer. `common/enrollment_model.ts` reads
// each from `models/generated/enrollment.json`.
//
// A label is a certificate profile, and the labels are
// `common/enrollment_profiles.js`'s `EST_LABELS`, the leaf every reader of
// a profile's name shares (#251); they are not repeated here.

import "../lib/enrollment_lib.tsp";

using IyaSts.EnrollmentLib;

namespace IyaSts.Enrollment.Est;

/**
 * The operations at /.well-known/est/ and /.well-known/est/<label>/, the
 * methods each answers (the first its default; HEAD is answered for a GET
 * by Express itself) and what each reads and writes. Every answer that
 * carries DER is base64 with `Content-Transfer-Encoding: base64` (RFC 8951
 * section 3).
 */
@operations(#{ family: "est", cite: "RFC 7030 section 3.2.2" })
model EstOperations {
  @operation(#{ methods: #["GET"], answers: "certsOnly",
         authenticated: false, cite: "RFC 7030 section 4.1" })
  cacerts: string;

  @operation(#{ methods: #["POST"], accepts: "pkcs10", answers: "certsOnly",
         authenticated: true, cite: "RFC 7030 section 4.2.1" })
  simpleenroll: string;

  @operation(#{ methods: #["POST"], accepts: "pkcs10", answers: "certsOnly",
         authenticated: true, cite: "RFC 7030 section 4.2.2" })
  simplereenroll: string;

  @operation(#{ methods: #["POST"], accepts: "pkcs10", answers: "multipart",
         authenticated: true, cite: "RFC 7030 section 4.4" })
  serverkeygen: string;

  @operation(#{ methods: #["GET"], answers: "csrattrs", authenticated: false,
         cite: "RFC 7030 section 4.5" })
  csrattrs: string;

  @operation(#{ methods: #["POST"],
         refused: "Full CMC is not implemented: 501",
         cite: "RFC 7030 section 4.3" })
  fullcmc: string;

  @operation(#{ methods: #["GET", "POST"], accepts: "freshness",
         answers: "freshness", authenticated: true,
         cite: "draft-ietf-lamps-attestation-freshness-08 section 5.1" })
  nonce: string;
}

/** The media types EST reads and writes, by the name the code uses. */
@register(#{ id: "media", family: "est", cite: "RFC 7030 section 3.2.4" })
model EstMedia {
  @term(#{ value: "application/pkcs10", cite: "RFC 5967 section 3" })
  pkcs10: string;

  @term(#{ value: "application/pkcs7-mime; smime-type=certs-only",
           cite: "RFC 7030 section 4.1.3; RFC 8551 section 3.2.2" })
  certsOnly: string;

  @term(#{ value: "application/csrattrs", cite: "RFC 7030 section 4.5.2" })
  csrattrs: string;

  @term(#{ value: "application/pkcs8", cite: "RFC 7030 section 4.4.2" })
  pkcs8: string;

  @term(#{ value: "multipart/mixed", cite: "RFC 7030 section 4.4.2" })
  multipart: string;

  @term(#{ value: "application/est-attestation-freshness+json",
           cite: "draft-ietf-lamps-attestation-freshness-08 section 5.1" })
  freshness: string;
}

/**
 * The statuses an EST refusal is sent with, a plain-text sentence each (RFC
 * 7030 section 4.2.3). `counted` is a refusal a guessing client produces,
 * counted against its rate limit; a 404 label, a 405, a 501 and a 503 are
 * the server's own shape and are not.
 */
@register(#{ id: "refusal-statuses", family: "est",
             cite: "RFC 7030 section 4.2.3" })
model EstRefusalStatuses {
  @term(#{ code: 400, counted: true, cite: "RFC 9110 section 15.5.1" })
  badRequest: string;

  @term(#{ code: 401, counted: true, cite: "RFC 7030 section 3.2.3" })
  unauthorized: string;

  @term(#{ code: 403, counted: true, cite: "RFC 9110 section 15.5.4" })
  forbidden: string;

  @term(#{ code: 404, counted: false, cite: "RFC 7030 section 3.2.2" })
  notFound: string;

  @term(#{ code: 405, counted: false, cite: "RFC 9110 section 15.5.6" })
  methodNotAllowed: string;

  @term(#{ code: 409, counted: true, cite: "RFC 9110 section 15.5.10" })
  conflict: string;

  @term(#{ code: 413, counted: true, cite: "RFC 9110 section 15.5.14" })
  contentTooLarge: string;

  @term(#{ code: 415, counted: true, cite: "RFC 9110 section 15.5.16" })
  unsupportedMediaType: string;

  @term(#{ code: 501, counted: false, cite: "RFC 7030 section 4.3" })
  notImplemented: string;

  @term(#{ code: 503, counted: false, cite: "RFC 7030 section 4.2.3" })
  serviceUnavailable: string;
}

/**
 * The subjectAltName name types a CSR attributes answer asks a request for,
 * by profile (RFC 7030 section 4.5.2); a profile not named asks for none.
 */
@register(#{ id: "csrattrs-names", family: "est",
             cite: "RFC 7030 section 4.5.2" })
model EstCsrAttrsNames {
  @term(#{ values: #["dNSName", "iPAddress"],
           cite: "RFC 5280 section 4.2.1.6" })
  `tls-server`: string;

  @term(#{ values: #["dNSName", "iPAddress"],
           cite: "RFC 5280 section 4.2.1.6" })
  `tls-server-client`: string;

  @term(#{ values: #["rfc822Name"], cite: "RFC 8550 section 3" })
  email: string;

  @term(#{ values: #["otherName:1.3.6.1.4.1.311.20.2.3"],
           cite: "MS-WCCE section 2.2.2.7.7.4 (the user principal name)" })
  `smartcard-logon`: string;
}

/** No EST operation takes a query string. */
@body(#{ id: "query", family: "est", others: "strict", input: "query",
         cite: "RFC 7030 section 3.2.2" })
model EstQuery {}

/** A nonce request's type: a dotted-decimal OID and anything with it. */
@shape(#{ others: "strict",
          cite: "draft-ietf-lamps-attestation-freshness-08 section 3.2" })
model EstReqTypeInfo {
  @field(#{ maxLength: 200, pattern: "^[0-2](\\.(0|[1-9][0-9]*))+$",
            patternMessage: "must be a dotted-decimal OID",
            cite: "draft-ietf-lamps-attestation-freshness-08 section 3.2" })
  type: string;

  @field(#{ cite: "draft-ietf-lamps-attestation-freshness-08 section 3.2" })
  reqInfo?: unknown;
}

/**
 * The nonce request (the draft's CDDL): two optional members and no others —
 * a CDDL map is closed unless it says otherwise — `len` an unsigned integer
 * in 8..64. This service defines no `reqTypeInfo` type, so one that is well
 * formed is answered 503 by the code.
 */
@body(#{ id: "nonce-request", family: "est", others: "strict",
         input: "json",
         cite: "draft-ietf-lamps-attestation-freshness-08 section 3.2" })
model EstNonceRequest {
  @field(#{ minimum: 8, maximum: 64,
            cite: "draft-ietf-lamps-attestation-freshness-08 section 3.2" })
  len?: int32;

  @field(#{ cite: "draft-ietf-lamps-attestation-freshness-08 section 3.2" })
  reqTypeInfo?: EstReqTypeInfo;
}

/**
 * The nonce answer: the nonce and its lifetime, or an empty nonce and no
 * lifetime when the label issues nothing that reads an attestation.
 */
@answer(#{ id: "nonce", family: "est", members: "closed",
           cite: "draft-ietf-lamps-attestation-freshness-08 section 3.3" })
model EstNonceAnswer {
  @member(#{ cite: "draft-ietf-lamps-attestation-freshness-08 section 3.3" })
  nonce: string;

  @member(#{ cite: "draft-ietf-lamps-attestation-freshness-08 section 3.3" })
  expiry?: int32;
}
