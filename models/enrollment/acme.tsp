// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/enrollment/acme.tsp
//
// Written by hand (#1579). THE SOURCE OF WHAT THE ACME SERVER TAKES AND
// ANSWERS: RFC 8555 with RFC 9773 renewal information, RFC 8738's `ip` and
// RFC 8823's `email` identifiers, draft-ietf-acme-profiles and
// draft-ietf-acme-device-attest's `permanent-identifier`. Every JWS-protected
// request's members — the flattened JWS itself, its protected header, the
// External Account Binding's header and each resource's payload — every
// resource this service answers, the problem document, every error type
// with the document defining it, and the registers `acme/` branches on.
// `models/tools/generate.mjs` compiles it into
// `models/generated/enrollment.json` during the image build, and
// `common/enrollment_model.ts` builds each validator from it.
//
// THE MODEL DESCRIBES AND VALIDATES THE WIRE; IT DOES NOT RESHAPE IT. Every
// bound below is the one the hand-written zod schema in `acme/acme_jws.ts`
// had, in the order it had them, because the order decides which refusal a
// request with two bad members gets and the refusal's `detail` quotes it;
// `tests/enrollment_model_wire.js` holds every answer to what the
// hand-written version said. A change here is a change to what a client
// sees, and owes that snapshot.
//
// What needs the store, the key or the realm stays in `acme/`: the
// signature, the Replay-Nonce's MAC and its spending, the account key's
// shape against `alg`, a contact's scheme and address, an identifier's
// value against its type, ownership, the profile, the CSR. `acme/CLAUDE.md`,
// *THE REQUEST SHAPES ARE THE MODEL'S*, says where each is.

import "../lib/enrollment_lib.tsp";

using IyaSts.EnrollmentLib;

namespace IyaSts.Enrollment.Acme;

// ---------------------------------------------------------------------------
// THE RESOURCES. The paths under /enroll/acme and the methods each answers;
// any other method is 405 with `Allow` saying these (section 6.3).
// ---------------------------------------------------------------------------

@operations(#{ family: "acme", cite: "RFC 8555 section 7.1" })
model AcmeResources {
  @operation(#{ path: "/directory", methods: #["GET", "HEAD"],
         cite: "RFC 8555 section 7.1.1" })
  directory: string;

  @operation(#{ path: "/new-nonce", methods: #["GET", "HEAD"],
         cite: "RFC 8555 section 7.2" })
  newNonce: string;

  @operation(#{ path: "/renewal-info/:id", methods: #["GET", "HEAD"],
         cite: "RFC 9773 section 4" })
  renewalInfo: string;

  @operation(#{ path: "/new-account", methods: #["POST"],
         cite: "RFC 8555 section 7.3" })
  newAccount: string;

  @operation(#{ path: "/new-order", methods: #["POST"],
         cite: "RFC 8555 section 7.4" })
  newOrder: string;

  @operation(#{ path: "/revoke-cert", methods: #["POST"],
         cite: "RFC 8555 section 7.6" })
  revokeCert: string;

  @operation(#{ path: "/key-change", methods: #["POST"],
         cite: "RFC 8555 section 7.3.5" })
  keyChange: string;

  @operation(#{ path: "/account/:id", methods: #["POST"],
         cite: "RFC 8555 section 7.3.2" })
  account: string;

  @operation(#{ path: "/order/:id", methods: #["POST"],
         cite: "RFC 8555 section 7.1.3" })
  order: string;

  @operation(#{ path: "/authz/:id", methods: #["POST"],
         cite: "RFC 8555 section 7.5" })
  authz: string;

  @operation(#{ path: "/challenge/:id", methods: #["POST"],
         cite: "RFC 8555 section 7.5.1" })
  challenge: string;

  @operation(#{ path: "/cert/:id", methods: #["POST"],
         cite: "RFC 8555 section 7.4.2" })
  cert: string;

  @operation(#{ path: "/account/:id/orders", methods: #["POST"],
         cite: "RFC 8555 section 7.1.2.1" })
  orders: string;

  @operation(#{ path: "/order/:id/finalize", methods: #["POST"],
         cite: "RFC 8555 section 7.4" })
  finalize: string;
}

// ---------------------------------------------------------------------------
// THE ENVELOPE (section 6.2).
// ---------------------------------------------------------------------------

/**
 * The flattened JWS JSON object. Exactly three members: RFC 8555 section
 * 6.2 says the JWS MUST NOT have an unprotected header, and a `signatures`
 * array is the general serialization, which the section does not allow
 * either. A member is capped at 1 MiB before anything else looks at it; the
 * route's own size limit caps the whole body.
 */
@body(#{ id: "flattened", family: "acme", others: "strict", input: "json",
         cite: "RFC 8555 section 6.2; RFC 7515 section 7.2.2" })
model AcmeFlattenedJws {
  @field(#{ minLength: 1, maxLength: 1048576,
            cite: "RFC 7515 section 7.2.1" })
  protected: string;

  @field(#{ maxLength: 1048576, cite: "RFC 8555 section 6.3" })
  payload: string;

  @field(#{ minLength: 1, maxLength: 1048576,
            cite: "RFC 7515 section 7.2.1" })
  signature: string;
}

/** A JSON Web Key as a header carries it: its type, and members unread. */
@shape(#{ others: "loose", cite: "RFC 7517 section 4" })
model AcmeJwk {
  @field(#{ minLength: 1, maxLength: 8, cite: "RFC 7517 section 4.1" })
  kty: string;
}

/**
 * The protected header. Loose because RFC 7515 says an unknown member is
 * ignored unless named in `crit` — and `crit` is refused by name in
 * `acme/acme_jws.ts`, so nothing unknown can be made to matter. Exactly one
 * of `jwk` and `kid` is the code's to check: which one a resource takes is
 * the resource's.
 */
@body(#{ id: "protected-header", family: "acme", others: "loose",
         input: "json", cite: "RFC 8555 section 6.2" })
model AcmeProtectedHeader {
  @field(#{ minLength: 1, maxLength: 32, cite: "RFC 7515 section 4.1.1" })
  alg: string;

  @field(#{ minLength: 1, maxLength: 256, cite: "RFC 8555 section 6.5.2" })
  nonce?: string;

  @field(#{ minLength: 1, maxLength: 2048, cite: "RFC 8555 section 6.4.1" })
  url: string;

  @field(#{ cite: "RFC 7515 section 4.1.3" })
  jwk?: AcmeJwk;

  @field(#{ minLength: 1, maxLength: 2048, cite: "RFC 7515 section 4.1.4" })
  kid?: string;
}

/**
 * The External Account Binding's protected header: exactly `alg`, `kid` and
 * `url`, and no nonce (section 7.3.4).
 */
@body(#{ id: "eab-header", family: "acme", others: "strict", input: "json",
         cite: "RFC 8555 section 7.3.4" })
model AcmeEabHeader {
  @field(#{ minLength: 1, maxLength: 16, cite: "RFC 8555 section 7.3.4" })
  alg: string;

  @field(#{ minLength: 1, maxLength: 512, cite: "RFC 8555 section 7.3.4" })
  kid: string;

  @field(#{ minLength: 1, maxLength: 2048, cite: "RFC 8555 section 7.3.4" })
  url: string;
}

// ---------------------------------------------------------------------------
// THE PAYLOADS, one per resource (section 7). Loose where the RFC says
// unknown fields are ignored, strict where a member's presence would change
// what is asked for and this server does not offer it.
// ---------------------------------------------------------------------------

/** Any JSON object, its members unread here. */
@shape(#{ others: "loose", cite: "RFC 8555 section 7.3.4" })
model AcmeAnyObject {}

/** An account's contact URIs: ten at most, each a bounded string. */
model AcmeContacts {
  @field(#{ maxItems: 10, minLength: 1, maxLength: 320,
            cite: "RFC 8555 section 7.3" })
  contact?: string[];
}

/** newAccount's payload. */
@body(#{ id: "new-account", family: "acme", others: "loose", input: "json",
         cite: "RFC 8555 section 7.3" })
model AcmeNewAccount {
  ...AcmeContacts;

  @field(#{ cite: "RFC 8555 section 7.3" })
  termsOfServiceAgreed?: boolean;

  @field(#{ cite: "RFC 8555 section 7.3.1" })
  onlyReturnExisting?: boolean;

  @field(#{ cite: "RFC 8555 section 7.3.4" })
  externalAccountBinding?: AcmeAnyObject;
}

/** An account update's payload. */
@body(#{ id: "account-update", family: "acme", others: "loose",
         input: "json", cite: "RFC 8555 section 7.3.2" })
model AcmeAccountUpdate {
  ...AcmeContacts;

  @field(#{ maxLength: 32, cite: "RFC 8555 section 7.3.6" })
  status?: string;

  @field(#{ cite: "RFC 8555 section 7.3" })
  termsOfServiceAgreed?: boolean;
}

/** One identifier an order names. */
@shape(#{ others: "strict", cite: "RFC 8555 section 9.7.7" })
model AcmeIdentifierRequest {
  @field(#{ minLength: 1, maxLength: 64, cite: "RFC 8555 section 9.7.7" })
  type: string;

  @field(#{ minLength: 1, maxLength: 1024, cite: "RFC 8555 section 7.1.3" })
  value: string;
}

/**
 * newOrder's payload. `notBefore` and `notAfter` are read only to be
 * refused; `profile` is draft-ietf-acme-profiles', `replaces` RFC 9773's.
 */
@body(#{ id: "new-order", family: "acme", others: "loose", input: "json",
         cite: "RFC 8555 section 7.4" })
model AcmeNewOrder {
  @field(#{ minItems: 1, maxItems: 100, cite: "RFC 8555 section 7.4" })
  identifiers: AcmeIdentifierRequest[];

  @field(#{ maxLength: 64, cite: "RFC 8555 section 7.4" })
  notBefore?: string;

  @field(#{ maxLength: 64, cite: "RFC 8555 section 7.4" })
  notAfter?: string;

  @field(#{ minLength: 1, maxLength: 64,
            cite: "draft-ietf-acme-profiles section 4" })
  profile?: string;

  @field(#{ minLength: 1, maxLength: 1024, cite: "RFC 9773 section 5" })
  replaces?: string;
}

/** An order's finalize payload. */
@body(#{ id: "finalize", family: "acme", others: "loose", input: "json",
         cite: "RFC 8555 section 7.4" })
model AcmeFinalize {
  @field(#{ minLength: 1, maxLength: 1048576, cite: "RFC 8555 section 7.4" })
  csr: string;
}

/** revokeCert's payload. The reason's register is `revocation-reasons`. */
@body(#{ id: "revoke", family: "acme", others: "loose", input: "json",
         cite: "RFC 8555 section 7.6" })
model AcmeRevoke {
  @field(#{ minLength: 1, maxLength: 1048576, cite: "RFC 8555 section 7.6" })
  certificate: string;

  @field(#{ minimum: -1000, maximum: 1000, cite: "RFC 8555 section 7.6" })
  reason?: int32;
}

/** An authorization's deactivation. */
@body(#{ id: "authz-update", family: "acme", others: "loose",
         input: "json", cite: "RFC 8555 section 7.5.2" })
model AcmeAuthzUpdate {
  @field(#{ cite: "RFC 8555 section 7.5.2" })
  status: "deactivated";
}

/** keyChange's inner JWS's payload. */
@body(#{ id: "key-change-inner", family: "acme", others: "loose",
         input: "json", cite: "RFC 8555 section 7.3.5" })
model AcmeKeyChangeInner {
  @field(#{ minLength: 1, maxLength: 2048, cite: "RFC 8555 section 7.3.5" })
  account: string;

  @field(#{ cite: "RFC 8555 section 7.3.5" })
  oldKey: AcmeJwk;
}

/**
 * A challenge response is `{}` (section 7.5.1); a challenge type that needed
 * fields would define them, and `sts-entry-binding-01` needs none.
 */
@body(#{ id: "challenge-response", family: "acme", others: "loose",
         input: "json", cite: "RFC 8555 section 7.5.1" })
model AcmeChallengeResponse {}

/** The orders list's query (section 7.1.2.1's pagination). */
@body(#{ id: "orders-query", family: "acme", others: "loose",
         input: "query", cite: "RFC 8555 section 7.1.2.1" })
model AcmeOrdersQuery {
  @field(#{ minimum: 1, maximum: 100000, empty: true,
            cite: "RFC 8555 section 7.1.2.1" })
  page?: int32;
}

// ---------------------------------------------------------------------------
// THE RESOURCES THIS SERVICE ANSWERS (section 7.1), each closed: a member
// the model does not name is recorded under STS-ACME-0100 and sent.
// ---------------------------------------------------------------------------

/** The directory's `meta` (section 7.1.1). */
@answer(#{ id: "directory-meta", family: "acme", members: "closed",
           cite: "RFC 8555 section 7.1.1" })
model AcmeDirectoryMeta {
  @member(#{ cite: "RFC 8555 section 7.1.1" })
  externalAccountRequired: boolean;

  @member(#{ cite: "RFC 8555 section 7.1.1" })
  website: string;

  @member(#{ cite: "draft-ietf-acme-profiles section 3" })
  profiles: Record<string>;
}

/** The directory (section 7.1.1). */
@answer(#{ id: "directory", family: "acme", members: "closed",
           cite: "RFC 8555 section 7.1.1" })
model AcmeDirectory {
  @member(#{ cite: "RFC 8555 section 7.1.1" })
  newNonce: string;

  @member(#{ cite: "RFC 8555 section 7.1.1" })
  newAccount: string;

  @member(#{ cite: "RFC 8555 section 7.1.1" })
  newOrder: string;

  @member(#{ cite: "RFC 8555 section 7.1.1" })
  revokeCert: string;

  @member(#{ cite: "RFC 8555 section 7.1.1" })
  keyChange: string;

  @member(#{ cite: "RFC 9773 section 3" })
  renewalInfo: string;

  @member(#{ cite: "RFC 8555 section 7.1.1" })
  meta: AcmeDirectoryMeta;
}

/** An account (section 7.1.2). */
@answer(#{ id: "account", family: "acme", members: "closed",
           cite: "RFC 8555 section 7.1.2" })
model AcmeAccount {
  @member(#{ cite: "RFC 8555 section 7.1.2" })
  status: "valid" | "deactivated" | "revoked";

  @member(#{ cite: "RFC 8555 section 7.1.2" })
  contact: string[];

  @member(#{ cite: "RFC 8555 section 7.1.2" })
  termsOfServiceAgreed: boolean;

  @member(#{ cite: "RFC 8555 section 7.1.2" })
  orders: string;

  @member(#{ cite: "this service's own: when the account was created",
             own: true })
  createdAt: string;
}

/** An identifier, as a resource names it (section 7.1.3). */
@answer(#{ id: "identifier", family: "acme", members: "closed",
           cite: "RFC 8555 section 7.1.3" })
model AcmeIdentifier {
  @member(#{ cite: "RFC 8555 section 9.7.7" })
  type: string;

  @member(#{ cite: "RFC 8555 section 7.1.3" })
  value: string;
}

/** An order (section 7.1.3). */
@answer(#{ id: "order", family: "acme", members: "closed",
           cite: "RFC 8555 section 7.1.3" })
model AcmeOrder {
  @member(#{ cite: "RFC 8555 section 7.1.6" })
  status: "pending" | "ready" | "processing" | "valid" | "invalid";

  @member(#{ cite: "RFC 8555 section 7.1.3" })
  expires: string;

  @member(#{ cite: "RFC 8555 section 7.1.3" })
  identifiers: AcmeIdentifier[];

  @member(#{ cite: "draft-ietf-acme-profiles section 4" })
  profile: string;

  @member(#{ cite: "RFC 8555 section 7.1.3" })
  authorizations: string[];

  @member(#{ cite: "RFC 8555 section 7.1.3" })
  finalize: string;

  @member(#{ cite: "RFC 9773 section 5" })
  replaces?: string;

  @member(#{ cite: "RFC 8555 section 7.1.3" })
  certificate?: string;
}

/** A challenge (section 7.1.5). */
@answer(#{ id: "challenge", family: "acme", members: "closed",
           cite: "RFC 8555 section 7.1.5" })
model AcmeChallenge {
  @member(#{ cite: "RFC 8555 section 7.1.5" })
  type: string;

  @member(#{ cite: "RFC 8555 section 7.1.5" })
  url: string;

  @member(#{ cite: "RFC 8555 section 7.1.6" })
  status: "pending" | "processing" | "valid" | "invalid";

  @member(#{ cite: "RFC 8555 section 7.1.5" })
  validated?: string;

  @member(#{ cite: "RFC 8555 section 8.1" })
  token?: string;
}

/** An authorization (section 7.1.4). */
@answer(#{ id: "authorization", family: "acme", members: "closed",
           cite: "RFC 8555 section 7.1.4" })
model AcmeAuthorization {
  @member(#{ cite: "RFC 8555 section 7.1.4" })
  identifier: AcmeIdentifier;

  @member(#{ cite: "RFC 8555 section 7.1.6" })
  status: "pending" | "valid" | "invalid" | "deactivated" | "expired" |
          "revoked";

  @member(#{ cite: "RFC 8555 section 7.1.4" })
  expires: string;

  @member(#{ cite: "RFC 8555 section 7.1.4" })
  challenges: AcmeChallenge[];

  @member(#{ cite: "RFC 8555 section 7.1.4" })
  wildcard?: boolean;
}

/** An account's orders list (section 7.1.2.1). */
@answer(#{ id: "orders", family: "acme", members: "closed",
           cite: "RFC 8555 section 7.1.2.1" })
model AcmeOrders {
  @member(#{ cite: "RFC 8555 section 7.1.2.1" })
  orders: string[];
}

/** RFC 9773's suggested window. */
@answer(#{ id: "suggested-window", family: "acme", members: "closed",
           cite: "RFC 9773 section 4.2" })
model AcmeSuggestedWindow {
  @member(#{ cite: "RFC 9773 section 4.2" })
  start: string;

  @member(#{ cite: "RFC 9773 section 4.2" })
  end: string;
}

/** RFC 9773's renewal information. */
@answer(#{ id: "renewal-info", family: "acme", members: "closed",
           cite: "RFC 9773 section 4.2" })
model AcmeRenewalInfo {
  @member(#{ cite: "RFC 9773 section 4.2" })
  suggestedWindow: AcmeSuggestedWindow;

  @member(#{ cite: "RFC 9773 section 4.2" })
  explanationURL?: string;
}

/** A subproblem (section 6.7.1). */
@answer(#{ id: "subproblem", family: "acme", members: "closed",
           cite: "RFC 8555 section 6.7.1" })
model AcmeSubproblem {
  @member(#{ cite: "RFC 8555 section 6.7.1" })
  type: string;

  @member(#{ cite: "RFC 8555 section 6.7.1" })
  detail: string;

  @member(#{ cite: "RFC 8555 section 6.7.1" })
  identifier: AcmeIdentifier;
}

/**
 * The problem document every refusal is (section 6.7, RFC 7807). `type` is
 * `urn:ietf:params:acme:error:` and one of the `problems` register's rows.
 */
@answer(#{ id: "problem", family: "acme", members: "closed",
           cite: "RFC 8555 section 6.7; RFC 7807 section 3.1" })
model AcmeProblem {
  @member(#{ cite: "RFC 7807 section 3.1" })
  type: string;

  @member(#{ cite: "RFC 7807 section 3.1" })
  detail: string;

  @member(#{ cite: "RFC 7807 section 3.1" })
  status: int32;

  @member(#{ cite: "RFC 8555 section 6.2" })
  algorithms?: string[];

  @member(#{ cite: "RFC 8555 section 6.7.1" })
  subproblems?: AcmeSubproblem[];
}

// ---------------------------------------------------------------------------
// THE ERROR TYPES (section 6.7 and the extensions' registrations), each
// under `urn:ietf:params:acme:error:`. `counted: false` is a type a refusal
// of does not count against the caller's throttle: the ordinary course of a
// conforming client (a stale nonce) and the throttle itself.
// ---------------------------------------------------------------------------

@register(#{ id: "problems", family: "acme",
             cite: "RFC 8555 section 6.7; IANA ACME Error Types" })
model AcmeProblems {
  @term(#{ cite: "RFC 8555 section 6.7" }) accountDoesNotExist: string;
  @term(#{ cite: "RFC 8555 section 6.7" }) alreadyRevoked: string;
  @term(#{ cite: "RFC 8555 section 6.7" }) badCSR: string;
  @term(#{ cite: "RFC 8555 section 6.7", counted: false }) badNonce: string;
  @term(#{ cite: "RFC 8555 section 6.7" }) badPublicKey: string;
  @term(#{ cite: "RFC 8555 section 6.7" }) badRevocationReason: string;
  @term(#{ cite: "RFC 8555 section 6.7" }) badSignatureAlgorithm: string;
  @term(#{ cite: "RFC 8555 section 6.7" }) caa: string;
  @term(#{ cite: "RFC 8555 section 6.7" }) compound: string;
  @term(#{ cite: "RFC 8555 section 6.7" }) connection: string;
  @term(#{ cite: "RFC 8555 section 6.7" }) dns: string;
  @term(#{ cite: "RFC 8555 section 6.7" }) externalAccountRequired: string;
  @term(#{ cite: "RFC 8555 section 6.7" }) incorrectResponse: string;
  @term(#{ cite: "RFC 8555 section 6.7" }) invalidContact: string;
  @term(#{ cite: "RFC 8555 section 6.7" }) malformed: string;
  @term(#{ cite: "RFC 8555 section 6.7" }) orderNotReady: string;
  @term(#{ cite: "RFC 8555 section 6.7", counted: false }) rateLimited: string;
  @term(#{ cite: "RFC 8555 section 6.7" }) rejectedIdentifier: string;
  @term(#{ cite: "RFC 8555 section 6.7" }) serverInternal: string;
  @term(#{ cite: "RFC 8555 section 6.7" }) tls: string;
  @term(#{ cite: "RFC 8555 section 6.7" }) unauthorized: string;
  @term(#{ cite: "RFC 8555 section 6.7" }) unsupportedContact: string;
  @term(#{ cite: "RFC 8555 section 6.7" }) unsupportedIdentifier: string;
  @term(#{ cite: "RFC 8555 section 6.7" }) userActionRequired: string;
  @term(#{ cite: "RFC 9773 section 7.4" }) alreadyReplaced: string;
  @term(#{ cite: "draft-ietf-acme-profiles section 7.2" })
  invalidProfile: string;
}

// ---------------------------------------------------------------------------
// THE REGISTERS acme/ BRANCHES ON.
// ---------------------------------------------------------------------------

/**
 * The identifier types a newOrder may name; another is
 * `unsupportedIdentifier`. `permanent-identifier` names the bound entry
 * itself here (acme/CLAUDE.md).
 */
@register(#{ id: "identifier-types", family: "acme",
             cite: "IANA ACME Identifier Types" })
model AcmeIdentifierTypes {
  @term(#{ cite: "RFC 8555 section 9.7.7" }) dns: string;
  @term(#{ cite: "RFC 8738 section 3" }) ip: string;
  @term(#{ cite: "RFC 8823 section 3" }) email: string;
  @term(#{ cite: "draft-ietf-acme-device-attest section 4" })
  `permanent-identifier`: string;
}

/**
 * The one challenge type an authorization here carries, already valid: the
 * identifier was bound to the entry by the directory, not proven by a fetch
 * (no challenge dials out; acme/CLAUDE.md).
 */
@register(#{ id: "challenge-types", family: "acme",
             cite: "RFC 8555 section 8" })
model AcmeChallengeTypes {
  @term(#{ cite: "this service's own: an identifier the account's entry owns" })
  `sts-entry-binding-01`: string;
}

/**
 * The signature algorithms an account key may use: the asymmetric ones
 * `common/crypto.js` verifies whose key type has an RFC 7638 thumbprint,
 * since an account is its key's thumbprint. `none`, every HMAC, ES256K and
 * the post-quantum algorithms (whose `AKP` key has no thumbprint) are
 * `badSignatureAlgorithm` with this list, in this order.
 */
@register(#{ id: "account-algorithms", family: "acme",
             cite: "RFC 8555 section 6.2" })
model AcmeAccountAlgorithms {
  @term(#{ cite: "RFC 7518 section 3.3" }) RS256: string;
  @term(#{ cite: "RFC 7518 section 3.3" }) RS384: string;
  @term(#{ cite: "RFC 7518 section 3.3" }) RS512: string;
  @term(#{ cite: "RFC 7518 section 3.5" }) PS256: string;
  @term(#{ cite: "RFC 7518 section 3.5" }) PS384: string;
  @term(#{ cite: "RFC 7518 section 3.5" }) PS512: string;
  @term(#{ cite: "RFC 7518 section 3.4" }) ES256: string;
  @term(#{ cite: "RFC 7518 section 3.4" }) ES384: string;
  @term(#{ cite: "RFC 7518 section 3.4" }) ES512: string;
  @term(#{ cite: "RFC 8037 section 3.1" }) EdDSA: string;
}

/**
 * The MACs an External Account Binding may be made with: section 7.3.4
 * names HS256 as the one a CA MUST support, and the other two are the same
 * construction with a longer hash.
 */
@register(#{ id: "eab-algorithms", family: "acme",
             cite: "RFC 8555 section 7.3.4" })
model AcmeEabAlgorithms {
  @term(#{ cite: "RFC 7518 section 3.2" }) HS256: string;
  @term(#{ cite: "RFC 7518 section 3.2" }) HS384: string;
  @term(#{ cite: "RFC 7518 section 3.2" }) HS512: string;
}

/**
 * The RFC 5280 revocation reasons a SUBSCRIBER may give (section 7.6 lets a
 * server refuse any). `cACompromise` (2) and `aACompromise` (10) are about
 * an authority's key, `certificateHold` (6) is the one reversible reason and
 * nothing here un-holds, 7 is unassigned and `removeFromCRL` (8) exists only
 * inside a delta CRL: each is `badRevocationReason`.
 */
@register(#{ id: "revocation-reasons", family: "acme",
             cite: "RFC 8555 section 7.6; RFC 5280 section 5.3.1" })
model AcmeRevocationReasons {
  @term(#{ code: 0, cite: "RFC 5280 section 5.3.1" }) unspecified: string;
  @term(#{ code: 1, cite: "RFC 5280 section 5.3.1" }) keyCompromise: string;
  @term(#{ code: 3, cite: "RFC 5280 section 5.3.1" })
  affiliationChanged: string;
  @term(#{ code: 4, cite: "RFC 5280 section 5.3.1" }) superseded: string;
  @term(#{ code: 5, cite: "RFC 5280 section 5.3.1" })
  cessationOfOperation: string;
  @term(#{ code: 9, cite: "RFC 5280 section 5.3.1" })
  privilegeWithdrawn: string;
}
