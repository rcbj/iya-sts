// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/enrollment/scep.tsp
//
// Written by hand (#1579). THE SOURCE OF WHAT THE SCEP SERVER TAKES AND
// ANSWERS AS FACTS THE CODE READS (RFC 8894). SCEP's messages are CMS — a
// pkiMessage's SignedData around an EnvelopedData — and the DER work stays
// in `scep/scep_cms.ts`; what is here is the query every request carries,
// the operations with their methods and media types, the capabilities
// GetCACaps announces, and the values of the signed attributes a CertRep is
// built from: messageType, pkiStatus and failInfo.
// `common/enrollment_model.ts` reads each from
// `models/generated/enrollment.json`.

import "../lib/enrollment_lib.tsp";

using IyaSts.EnrollmentLib;

namespace IyaSts.Enrollment.Scep;

/**
 * The operations (RFC 8894 section 3.5 and 4), each named by the
 * `operation` query parameter at /enroll/scep. Only an operation that
 * answers POST may be POSTed; any other is 405 with `Allow` its methods.
 */
@operations(#{ family: "scep", cite: "RFC 8894 section 4" })
model ScepOperations {
  @operation(#{ methods: #["GET"], answers: "text/plain",
         cite: "RFC 8894 section 3.5.1" })
  GetCACaps: string;

  @operation(#{ methods: #["GET"], answers: "application/x-x509-ca-ra-cert",
         cite: "RFC 8894 section 4.2" })
  GetCACert: string;

  @operation(#{ methods: #["GET"],
         refused: "a CA rollover is not pre-announced: 501",
         cite: "RFC 8894 section 4.7" })
  GetNextCACert: string;

  @operation(#{ methods: #["GET", "POST"], accepts: "application/x-pki-message",
         answers: "application/x-pki-message",
         cite: "RFC 8894 section 4.3" })
  PKIOperation: string;
}

/**
 * The query every SCEP request carries. A parameter the model does not name
 * is dropped, not refused: clients send what RFC 8894's predecessors did.
 * The message parameter's cap is the base64 of the largest message
 * `scep.maxRequestBytes` allows at its maximum (4 MiB), a third larger and
 * rounded up; the precise bound is checked against the setting once the
 * length is known.
 */
@body(#{ id: "query", family: "scep", others: "strip", input: "query",
         cite: "RFC 8894 section 4.1" })
model ScepQuery {
  @field(#{ valuesFrom: "operations", cite: "RFC 8894 section 4.1" })
  operation: string;

  @field(#{ maxLength: 5592412, empty: true, cite: "RFC 8894 section 4.3" })
  message?: string;
}

/**
 * The capabilities GetCACaps announces, one a line, in this order (RFC 8894
 * section 3.5.2). `SCEPStandard` asserts AES, POSTPKIOperation and SHA-256;
 * each is still named, because older clients read the list rather than the
 * umbrella. `GetNextCACert` is deliberately absent: no rollover is
 * pre-announced.
 */
@register(#{ id: "capabilities", family: "scep",
             cite: "RFC 8894 section 3.5.2" })
model ScepCapabilities {
  @term(#{ cite: "RFC 8894 section 3.5.2" }) POSTPKIOperation: string;
  @term(#{ cite: "RFC 8894 section 3.5.2" }) `SHA-256`: string;
  @term(#{ cite: "RFC 8894 section 3.5.2" }) `SHA-512`: string;
  @term(#{ cite: "RFC 8894 section 3.5.2" }) AES: string;
  @term(#{ cite: "RFC 8894 section 3.5.2" }) SCEPStandard: string;
  @term(#{ cite: "RFC 8894 section 3.5.2" }) Renewal: string;
}

/** The messageType values (RFC 8894 sections 3.2.1.2 and 3.2.1.3). */
@register(#{ id: "message-types", family: "scep",
             cite: "RFC 8894 section 3.2.1.2" })
model ScepMessageTypes {
  @term(#{ code: 3, cite: "RFC 8894 section 3.2.1.2" }) CertRep: string;
  @term(#{ code: 17, cite: "RFC 8894 section 3.2.1.2" }) RenewalReq: string;
  @term(#{ code: 19, cite: "RFC 8894 section 3.2.1.2" }) PKCSReq: string;
  @term(#{ code: 20, cite: "RFC 8894 section 3.2.1.2" }) CertPoll: string;
  @term(#{ code: 21, cite: "RFC 8894 section 3.2.1.2" }) GetCert: string;
  @term(#{ code: 22, cite: "RFC 8894 section 3.2.1.2" }) GetCRL: string;
}

/** The pkiStatus values a CertRep carries (RFC 8894 section 3.2.1.3). */
@register(#{ id: "pki-status", family: "scep",
             cite: "RFC 8894 section 3.2.1.3" })
model ScepPkiStatus {
  @term(#{ value: "0", cite: "RFC 8894 section 3.2.1.3" }) SUCCESS: string;
  @term(#{ value: "2", cite: "RFC 8894 section 3.2.1.3" }) FAILURE: string;
  @term(#{ value: "3", cite: "RFC 8894 section 3.2.1.3" }) PENDING: string;
}

/** The failInfo values a FAILURE carries (RFC 8894 section 3.2.1.4). */
@register(#{ id: "fail-info", family: "scep",
             cite: "RFC 8894 section 3.2.1.4" })
model ScepFailInfo {
  @term(#{ value: "0", cite: "RFC 8894 section 3.2.1.4" }) badAlg: string;
  @term(#{ value: "1", cite: "RFC 8894 section 3.2.1.4" })
  badMessageCheck: string;
  @term(#{ value: "2", cite: "RFC 8894 section 3.2.1.4" }) badRequest: string;
  @term(#{ value: "3", cite: "RFC 8894 section 3.2.1.4" }) badTime: string;
  @term(#{ value: "4", cite: "RFC 8894 section 3.2.1.4" }) badCertId: string;
}
