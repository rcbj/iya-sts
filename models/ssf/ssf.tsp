// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/ssf/ssf.tsp
//
// Written by hand (#1579). THE SOURCE OF WHAT THE SHARED SIGNALS
// TRANSMITTER AND RECEIVERS SAY, OTHER THAN THE EVENT TYPES
// (`ssf_events.tsp`): the RFC 9493 subject identifier formats and SSF 1.0
// section 3's complex subject, the delivery methods, the stream statuses and
// the credential types, the members of every document the transmitter
// answers and the receivers send — the transmitter metadata (SSF 1.0 section
// 7.1), a stream configuration and who supplies each member (section 8.1.1),
// a status (section 8.1.2), a subject request (section 8.1.3), a
// verification request (section 8.1.4.2), a poll and its answer (RFC 8936),
// a refusal (RFC 8935 section 2.4) and the Security Event Token's own claims
// (RFC 8417 section 2.2) — and the `err` values this family sends.
// `models/tools/generate.mjs` compiles both files into
// `models/generated/ssf.json` during the image build, and `ssf/ssf_model.ts`
// reads it.
//
// THE MODEL DESCRIBES AND VALIDATES THE WIRE; IT DOES NOT RESHAPE IT. A
// subject format's members are CLOSED (RFC 9493 section 3: a receiver that
// met a member it did not know could not tell whether it narrows the
// subject), and `ssf/ssf_subjects.js` refuses by this table, word for word as
// it did. A document's members are what this service's answers are held to:
// a member the model does not name, or of a type it does not allow, is
// recorded under its error code and the answer is sent unchanged
// (`ssf/CLAUDE.md`, *THE SHAPES ARE THE MODEL'S*). A change here owes
// `tests/ssf_model_wire.snapshot.json`.
//
// The format names are the IANA "Security Event Identifier Formats"
// registry's, never the drafts' (#144).

import "../lib/ssf_lib.tsp";

using IyaSts.SsfLib;

namespace IyaSts.Ssf;

// ---------------------------------------------------------------------------
// THE SUBJECT IDENTIFIER FORMATS: RFC 9493 SECTION 3.2'S EIGHT AND SSF 1.0
// SECTION 3.5'S THREE. Every member of each is required — neither document
// defines an optional one — and `@subjectMember` names the check its value is
// held to (`ssf/ssf_subjects.js` holds the check and its sentence); a member
// with none is a non-empty string. `person` marks the eight a person can be
// named in.
// ---------------------------------------------------------------------------

@subjectFormat(#{
  format: "account",
  person: true,
  what: "An \"acct\" URI (RFC 7565) — a user at a service, the identifier form WebFinger uses.",
  example: "{\"format\":\"account\",\"uri\":\"acct:alice@example.com\"}",
  cite: "RFC 9493 section 3.2.1"
})
model AccountSubject {
  @subjectMember(#{ check: "acct" })
  uri: string;
}

@subjectFormat(#{
  format: "email",
  person: true,
  what: "An email address (RFC 5322 addr-spec). The commonest subject in practice and the one most likely to be RECYCLED, which is why RISC has an event type about exactly that.",
  example: "{\"format\":\"email\",\"email\":\"alice@example.com\"}",
  cite: "RFC 9493 section 3.2.2"
})
model EmailSubject {
  @subjectMember(#{ check: "addrSpec" })
  email: string;
}

@subjectFormat(#{
  format: "iss_sub",
  person: true,
  what: "The pair an OpenID Connect ID Token is identified by — the issuer and the subject within it. The only format that is globally unique by construction rather than by convention.",
  example: "{\"format\":\"iss_sub\",\"iss\":\"https://issuer.example.com/\",\"sub\":\"145234573\"}",
  cite: "RFC 9493 section 3.2.3"
})
model IssSubSubject {
  @subjectMember(#{ check: "issuer" })
  iss: string;

  `sub`: string;
}

@subjectFormat(#{
  format: "opaque",
  person: true,
  what: "A string meaningful only to the parties that agreed it. It says nothing about what kind of thing it names, which is the point: a transmitter that must not leak an email address uses this.",
  example: "{\"format\":\"opaque\",\"id\":\"11112222333344445555\"}",
  cite: "RFC 9493 section 3.2.4"
})
model OpaqueSubject {
  id: string;
}

@subjectFormat(#{
  format: "phone_number",
  person: true,
  what: "A phone number in E.164 form. RFC 9493 requires the leading \"+\" and digits only — no spaces, no punctuation, no extension.",
  example: "{\"format\":\"phone_number\",\"phone_number\":\"+12065550100\"}",
  cite: "RFC 9493 section 3.2.5"
})
model PhoneNumberSubject {
  @subjectMember(#{ check: "e164" })
  phone_number: string;
}

@subjectFormat(#{
  format: "did",
  person: true,
  what: "A DID or a DID URL (W3C DID Core). The identifier resolves to a document rather than to a record at the transmitter.",
  example: "{\"format\":\"did\",\"url\":\"did:example:123456789abcdefghi\"}",
  cite: "RFC 9493 section 3.2.6"
})
model DidSubject {
  @subjectMember(#{ check: "did" })
  url: string;
}

@subjectFormat(#{
  format: "uri",
  person: true,
  what: "Any URI. The escape hatch, and the one to reach for LAST — a receiver can do nothing with it but compare it, so a format that says what kind of thing this is is always better.",
  example: "{\"format\":\"uri\",\"uri\":\"https://example.com/users/1234\"}",
  cite: "RFC 9493 section 3.2.7"
})
model UriSubject {
  @subjectMember(#{ check: "absoluteUri" })
  uri: string;
}

@subjectFormat(#{
  format: "aliases",
  person: true,
  what: "SEVERAL identifiers for ONE subject, so a receiver that knows the person by any of them can act. It MUST NOT contain another aliases identifier — RFC 9493 section 3.2.8 forbids the nesting outright, and this service refuses it rather than flattening, because flattening would accept a document a conforming receiver rejects.",
  example: "{\"format\":\"aliases\",\"identifiers\":[{\"format\":\"email\",\"email\":\"alice@example.com\"},{\"format\":\"phone_number\",\"phone_number\":\"+12065550100\"}]}",
  cite: "RFC 9493 section 3.2.8"
})
model AliasesSubject {
  @subjectMember(#{ check: "identifiers" })
  identifiers: Record<unknown>[];
}

@subjectFormat(#{
  format: "jwt_id",
  person: false,
  what: "One JWT, by the issuer that minted it and its \"jti\" — which is how an event can be about a single token rather than about a person or a session.",
  example: "{\"format\":\"jwt_id\",\"iss\":\"https://idp.example.com/123456789/\",\"jti\":\"B70BA622-9515-4353-A866-823539EECBC8\"}",
  cite: "SSF 1.0 section 3.5.1"
})
model JwtIdSubject {
  @subjectMember(#{ check: "jwtIssuer" })
  iss: string;

  jti: string;
}

@subjectFormat(#{
  format: "saml_assertion_id",
  person: false,
  what: "One SAML 2.0 assertion, by its Issuer and its ID. The SAML counterpart of jwt_id; note the members are \"issuer\" and \"assertion_id\", not \"iss\" and \"id\".",
  example: "{\"format\":\"saml_assertion_id\",\"issuer\":\"https://idp.example.com/123456789/\",\"assertion_id\":\"_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6\"}",
  cite: "SSF 1.0 section 3.5.2"
})
model SamlAssertionIdSubject {
  issuer: string;

  assertion_id: string;
}

@subjectFormat(#{
  format: "ip-addresses",
  person: false,
  what: "The IP addresses the transmitter observed the subject at, as a non-empty array of RFC 4001 strings. The only format whose value is an array, and the only one whose name and member are the same hyphenated word.",
  example: "{\"format\":\"ip-addresses\",\"ip-addresses\":[\"10.29.37.75\",\"2001:0db8:0000:0000:0000:8a2e:0370:7334\"]}",
  cite: "SSF 1.0 section 3.5.3"
})
model IpAddressesSubject {
  @subjectMember(#{ check: "ipAddresses" })
  `ip-addresses`: string[];
}

@complexSubject(#{ format: "complex", memberName: "^[A-Za-z][A-Za-z0-9_.-]{0,63}$", cite: "SSF 1.0 section 3.3" })
model ComplexSubject {
  @complexMember(#{ what: "The person." })
  user?: Record<unknown>;

  @complexMember(#{ what: "The device they are on." })
  device?: Record<unknown>;

  @complexMember(#{ what: "The one session, of possibly many." })
  session?: Record<unknown>;

  @complexMember(#{ what: "The application the event concerns." })
  application?: Record<unknown>;

  @complexMember(#{ what: "The tenant, in a multi-tenant service." })
  tenant?: Record<unknown>;

  @complexMember(#{ what: "The organizational unit within the tenant." })
  org_unit?: Record<unknown>;

  @complexMember(#{ what: "The group membership the event is about." })
  group?: Record<unknown>;
}

// ---------------------------------------------------------------------------
// THE TWO DELIVERY METHODS (SSF 1.0 section 7.1.1), BY THEIR URNs.
// ---------------------------------------------------------------------------
@delivery(#{ method: "urn:ietf:rfc:8935", name: "Push (RFC 8935)", what: "The transmitter POSTs each SET to a URL the receiver gave it. The receiver has to be reachable, which is what makes this the hard one for a browser: a page cannot be an HTTP server, so the debugger hosts its receiver endpoint in its api layer.", cite: "RFC 8935" })
model PushDelivery {}

@delivery(#{ method: "urn:ietf:rfc:8936", name: "Poll (RFC 8936)", what: "The receiver POSTs to the transmitter and is handed whatever has queued up, acknowledging what it read. Nothing has to be reachable but the transmitter, which is why a browser can be a receiver over this method and not over the other one.", cite: "RFC 8936" })
model PollDelivery {}

// ---------------------------------------------------------------------------
// TWO LISTS THE SERVICE KEEPS BY ID. The credential types are ONE list for
// two specifications: RISC 1.0 section 2.7 defines credential-compromise's
// credential_type by reference to CAEP's credential-change, and the list is
// open in both ("or any other credential type supported mutually").
// ---------------------------------------------------------------------------
@valueList(#{ id: "credential-types", cite: "CAEP 1.0 section 3.3.1; RISC 1.0 section 2.7" })
union CredentialType { "password", "pin", "x509", "fido2-platform", "fido2-roaming", "fido-u2f", "verifiable-credential", "phone-voice", "phone-sms", "app", string }
@valueList(#{ id: "stream-statuses", cite: "SSF 1.0 section 8.1.2" })
union StreamStatus { "enabled", "paused", "disabled" }

// ---------------------------------------------------------------------------
// THE DOCUMENTS. Every member a document of this service's carries in any
// mode, with every switch on; a member the specification makes optional, or
// that appears only with its feature, is optional here.
// ---------------------------------------------------------------------------

/** One entry of `authorization_schemes` (SSF 1.0 section 7.1). */
model AuthorizationScheme {
  spec_urn: string;
}

@members(#{ id: "transmitter-metadata", cite: "SSF 1.0 section 7.1", members: "closed" })
model TransmitterMetadata {
  @member(#{ cite: "SSF 1.0 section 7.1" })
  spec_version?: string;

  @member(#{ cite: "SSF 1.0 section 7.1" })
  issuer: string;

  @member(#{ cite: "SSF 1.0 section 7.1" })
  jwks_uri?: string;

  @member(#{ cite: "SSF 1.0 section 7.1" })
  delivery_methods_supported?: string[];

  @member(#{ cite: "SSF 1.0 section 7.1" })
  configuration_endpoint?: string;

  @member(#{ cite: "SSF 1.0 section 7.1" })
  status_endpoint?: string;

  @member(#{ cite: "SSF 1.0 section 7.1" })
  add_subject_endpoint?: string;

  @member(#{ cite: "SSF 1.0 section 7.1" })
  remove_subject_endpoint?: string;

  @member(#{ cite: "SSF 1.0 section 7.1" })
  verification_endpoint?: string;

  @member(#{ cite: "SSF 1.0 section 7.1" })
  critical_subject_members?: string[];

  @member(#{ cite: "SSF 1.0 section 7.1" })
  default_subjects?: "ALL" | "NONE";

  @member(#{ cite: "SSF 1.0 section 7.1" })
  authorization_schemes?: AuthorizationScheme[];
}

/**
 * A stream configuration, as this transmitter answers it. `supplier` is
 * section 8.1.1's: a Transmitter-Supplied member an update may carry only
 * unchanged (sections 8.1.1.3 and 8.1.1.4), a Receiver-Supplied one is what
 * a creation and a replacement send. `stream_id` is Transmitter-Supplied and
 * is how an update names the stream.
 */
@members(#{ id: "stream-configuration", cite: "SSF 1.0 section 8.1.1", members: "closed" })
model StreamConfiguration {
  @member(#{ cite: "SSF 1.0 section 8.1.1", supplier: "transmitter" })
  stream_id: string;

  @member(#{ cite: "SSF 1.0 section 8.1.1", supplier: "transmitter" })
  iss: string;

  @member(#{ cite: "SSF 1.0 section 8.1.1", supplier: "transmitter" })
  aud: string | string[];

  @member(#{ cite: "SSF 1.0 section 8.1.1", supplier: "transmitter" })
  events_supported?: string[];

  @member(#{ cite: "SSF 1.0 section 8.1.1", supplier: "receiver" })
  events_requested?: string[];

  @member(#{ cite: "SSF 1.0 section 8.1.1", supplier: "transmitter" })
  events_delivered?: string[];

  @member(#{ cite: "SSF 1.0 section 8.1.1", supplier: "receiver" })
  delivery: StreamDelivery;

  @member(#{ cite: "SSF 1.0 section 8.1.1", supplier: "transmitter" })
  min_verification_interval?: int32;

  /**
   * The format a default subject is named in. In SSF's drafts; kept because
   * receivers under test send it.
   */
  @member(#{ cite: "this service's own (SSF's drafts' format)", own: true, supplier: "receiver" })
  format?: string;

  @member(#{ cite: "SSF 1.0 section 8.1.1", supplier: "receiver" })
  description?: string;

  @member(#{ cite: "SSF 1.0 section 8.1.1", supplier: "transmitter" })
  inactivity_timeout?: int32;
}

@members(#{ id: "stream-delivery", cite: "SSF 1.0 section 8.1.1; RFC 8935; RFC 8936", members: "closed" })
model StreamDelivery {
  @member(#{ cite: "SSF 1.0 section 8.1.1" })
  method: string;

  @member(#{ cite: "SSF 1.0 section 8.1.1" })
  endpoint_url?: string;

  @member(#{ cite: "SSF 1.0 section 8.1.1" })
  authorization_header?: string;
}

@members(#{ id: "stream-status", cite: "SSF 1.0 section 8.1.2", members: "closed" })
model StreamStatusDocument {
  @member(#{ cite: "SSF 1.0 section 8.1.2.1" })
  stream_id: string;

  @member(#{ cite: "SSF 1.0 section 8.1.2.1" })
  status: StreamStatus;

  @member(#{ cite: "SSF 1.0 section 8.1.2.2" })
  reason?: string;
}

@members(#{ id: "subject-request", cite: "SSF 1.0 section 8.1.3", members: "closed" })
model SubjectRequest {
  @member(#{ cite: "SSF 1.0 section 8.1.3.2" })
  stream_id: string;

  @member(#{ cite: "SSF 1.0 section 8.1.3.2" })
  subject: Record<unknown>;

  @member(#{ cite: "SSF 1.0 section 8.1.3.2" })
  verified?: boolean;
}

@members(#{ id: "verification-request", cite: "SSF 1.0 section 8.1.4.2", members: "closed" })
model VerificationRequest {
  @member(#{ cite: "SSF 1.0 section 8.1.4.2" })
  stream_id: string;

  @member(#{ cite: "SSF 1.0 section 8.1.4.2" })
  state?: string;
}

/**
 * A poll. RFC 8936's poll endpoint is per stream, and this transmitter
 * serves every stream at one path, so the stream may be named in the body.
 */
@members(#{ id: "poll-request", cite: "RFC 8936 section 2.1", members: "closed" })
model PollRequest {
  @member(#{ cite: "this service's own (one poll path for every stream)", own: true })
  stream_id?: string;

  @member(#{ cite: "RFC 8936 section 2.1" })
  maxEvents?: int32;

  @member(#{ cite: "RFC 8936 section 2.1" })
  returnImmediately?: boolean;

  @member(#{ cite: "RFC 8936 section 2.1" })
  ack?: string[];

  @member(#{ cite: "RFC 8936 section 2.1" })
  setErrs?: Record<SetError>;
}

@members(#{ id: "poll-response", cite: "RFC 8936 section 2.2", members: "closed" })
model PollResponse {
  @member(#{ cite: "RFC 8936 section 2.2" })
  sets: Record<string>;

  @member(#{ cite: "RFC 8936 section 2.2" })
  moreAvailable?: boolean;
}

/** A refusal on every endpoint of this family, and a poll's `setErrs`. */
@members(#{ id: "error-response", cite: "RFC 8935 section 2.4", members: "closed" })
model SetError {
  @member(#{ cite: "RFC 8935 section 2.4" })
  err: string;

  @member(#{ cite: "RFC 8935 section 2.4" })
  description: string;
}

/** The claims of a Security Event Token this service issues. */
@members(#{ id: "set-claims", cite: "RFC 8417 section 2.2", members: "closed" })
model SetClaims {
  @member(#{ cite: "RFC 8417 section 2.2" })
  iss: string;

  @member(#{ cite: "RFC 8417 section 2.2" })
  jti: string;

  @member(#{ cite: "RFC 8417 section 2.2" })
  iat: int64;

  @member(#{ cite: "RFC 8417 section 2.2" })
  aud?: string | string[];

  @member(#{ cite: "RFC 8417 section 2.2" })
  events: Record<Record<unknown>>;

  @member(#{ cite: "SSF 1.0 section 4.1.2; RFC 9493 section 4.1" })
  sub_id?: Record<unknown>;

  @member(#{ cite: "RFC 8417 section 2.2" })
  txn?: string;

  @member(#{ cite: "RFC 8417 section 2.2" })
  toe?: int64;

  /**
   * The deprecated claim beside `sub_id`, sent only while the development
   * defect `ssf.legacySubClaim` is on.
   */
  @member(#{ cite: "RFC 8417 section 2.2 (discouraged)" })
  `sub`?: string;
}

// ---------------------------------------------------------------------------
// THE `err` VALUES. The SET Error Codes registry's six (RFC 8935 section
// 7.1), which every refusal of this family uses, and the two a token gate
// answers with: RFC 6750's for a bearer token and GNAP's for a resource
// server.
// ---------------------------------------------------------------------------

@errorCodes
model ErrorCodes {
  @errorCode(#{ cite: "RFC 8935 section 2.4" })
  invalid_request: string;

  @errorCode(#{ cite: "RFC 8935 section 2.4" })
  invalid_key: string;

  @errorCode(#{ cite: "RFC 8935 section 2.4" })
  invalid_issuer: string;

  @errorCode(#{ cite: "RFC 8935 section 2.4" })
  invalid_audience: string;

  @errorCode(#{ cite: "RFC 8935 section 2.4" })
  authentication_failed: string;

  @errorCode(#{ cite: "RFC 8935 section 2.4" })
  access_denied: string;

  @errorCode(#{ cite: "RFC 6750 section 3.1" })
  invalid_token: string;

  @errorCode(#{ cite: "RFC 9635 section 3.6" })
  invalid_resource_server: string;
}
