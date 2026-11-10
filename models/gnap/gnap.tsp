// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/gnap/gnap.tsp
//
// Written by hand (#1579). THE GRANT NEGOTIATION AND AUTHORIZATION PROTOCOL
// (RFC 9635) AND ITS RESOURCE SERVER CONNECTIONS (RFC 9767), AS THIS SERVICE
// SPEAKS THEM.
//
// * THE REQUEST DOCUMENTS (`@document`): the grant request, a continuation,
//   a modification, a key rotation, an introspection and a resource
//   registration. Each is rendered as the JSON Schema 2020-12
//   `gnap/gnap_schemas.ts` compiles with ajv and holds every body to before
//   a handler reads a member: every member's JSON type, a bound on every
//   string, an item cap on every array and a member cap on every object, a
//   URI format where RFC 9635 says "absolute URI", and no control character
//   in any string (the model's pattern for a string that states none).
//   **`required` and enumerations are NOT in these schemas**: a request with
//   no client is section 2.3's `invalid_client` and a flag nobody defines is
//   section 2.1.1's `invalid_flag`, which `gnap/gnap_request.ts`'s walk
//   answers by name; a schema that enforced them would pre-empt the walk
//   with a generic `invalid_request`. The registries the walk reads are
//   below (`@registry`). **An object is OPEN where RFC 9635 has an extension
//   registry** — the grant request (section 10.3), the client (10.7), its
//   display (10.8), the subject request (10.5), a start mode object (10.9),
//   the hints (10.11), a proof object (10.16) and an access right (section
//   8's "API-specific fields") — because refusing a registered extension
//   this implementation does not know would refuse a conforming client. The
//   finish object (section 2.5.2) is CLOSED.
// * THE SHARED TYPES (`@definitions`): every document carries all of them
//   as its `$defs`, in this order.
// * A PATH'S PARAMETERS (`@pathParams`).
// * THE ANSWERS (`@members`): the grant response and what it nests, the
//   error response, both discovery documents, introspection, registration,
//   the verification material, the revoked biscuits, the ZCAP controller
//   document and `/gnap-api`'s answers. `gnap/gnap_model.ts` holds every
//   answer to its set and records a gap under STS-GNAP-0910 without
//   changing the answer: the model describes the wire, it does not reshape
//   it.
// * THE ERROR CODES (`@errorCodes`): RFC 9635 section 3.6's, and the two
//   this service adds. One sent that is not here is recorded under
//   STS-GNAP-0911.
// * THE ACCESS-TYPE CATALOGUE'S DEFINITION (rule 3bz): the members an
//   application's `oauthAuthorizationDetailsType` value may carry, shared by
//   GNAP's access rights and RFC 9396's authorization details.

import "../lib/gnap_lib.tsp";

using IyaSts.GnapLib;

namespace IyaSts.Gnap;

// ---------------------------------------------------------------------------
// THE SHARED TYPES.
// ---------------------------------------------------------------------------

/** RFC 9635's "absolute URI". */
@shape(#{ cap: "URI", format: "uri" })
scalar GnapUri extends string;

/** Section 2.3.2: a logo may be a `data:` image, which is legitimately long. */
@shape(#{ cap: "TEXT", pattern: "^(data:image/[A-Za-z0-9.+-]+;base64,[A-Za-z0-9+/=]*|[A-Za-z][A-Za-z0-9+.-]*:[^\\u0000-\\u001f\\u007f\\s]*)$" })
scalar LogoUri extends string;

/**
 * An access token value: RFC 9110 section 11.2's token68, which every
 * format this authorization server issues satisfies. A ZCAP is the long one.
 */
@shape(#{ cap: "TEXT", pattern: "^[A-Za-z0-9._~+/-]*=*$" })
scalar TokenValue extends string;

/** Section 8: an access right, by reference or as an object. */
union AccessRight {
  @shape(#{ cap: "URI" }) reference: string,
  right: AccessRightObject,
}

/** Section 8.1, with section 8's API-specific fields allowed. */
@shape(#{ maxProperties: 64, open: true, cite: "RFC 9635 section 8" })
model AccessRightObject {
  @shape(#{ cap: "URI" }) type?: string;
  @shape(#{ maxItems: 100, items: #{ cap: "NAME" } }) actions?: string[];
  @shape(#{ maxItems: 100, items: #{ cap: "URI" } }) locations?: string[];
  @shape(#{ maxItems: 100, items: #{ cap: "NAME" } }) datatypes?: string[];
  @shape(#{ maxItems: 100, items: #{ cap: "NAME" } }) privileges?: string[];
  @shape(#{ cap: "URI" }) identifier?: string;
}

/** Section 8: the access an access token asks for. */
@shape(#{ maxItems: 200 })
model Access is Array<AccessRight>;

/** Section 7.1: a proof method by name, or with its parameters. */
union Proof {
  @shape(#{ maxLength: 64 }) method: string,
  object: ProofObject,
}

@shape(#{ maxProperties: 16, open: true, cite: "RFC 9635 section 7.3" })
model ProofObject {
  @shape(#{ maxLength: 64 }) method?: string;
  @shape(#{ maxLength: 64 }) alg?: string;
  @shape(#{ maxLength: 64 }) `content-digest-alg`?: string;
}

/** RFC 7517. */
@shape(#{ maxProperties: 32, open: true, cite: "RFC 7517 section 4" })
model Jwk {
  @shape(#{ maxLength: 16 }) kty?: string;
  @shape(#{ maxLength: 64 }) alg?: string;
  @shape(#{ cap: "IDENTIFIER" }) kid?: string;
  @shape(#{ maxLength: 32 }) crv?: string;
  @shape(#{ maxLength: 16 }) use?: string;
  @shape(#{ maxLength: 512 }) x?: string;
  @shape(#{ maxLength: 512 }) y?: string;
  @shape(#{ maxLength: 4096 }) n?: string;
  @shape(#{ maxLength: 64 }) e?: string;
  @shape(#{ maxItems: 10, items: #{ cap: "TEXT" } }) x5c?: string[];
}

/** Section 7.1: a key by reference, or by value in one of its formats. */
union Key {
  @shape(#{ cap: "IDENTIFIER" }) reference: string,
  key: KeyObject,
}

@shape(#{ maxProperties: 16, open: true, cite: "RFC 9635 section 7.1" })
model KeyObject {
  proof?: Proof;
  jwk?: Jwk;
  @shape(#{ cap: "TEXT", pattern: "^[A-Za-z0-9+/=\\s-]*$" }) cert?: string;
  @shape(#{ maxLength: 128, pattern: "^[A-Za-z0-9_-]*$" }) `cert#S256`?: string;
}

/** RFC 9493's subject identifier, in any of its formats. */
@shape(#{ maxProperties: 16, open: true, cite: "RFC 9493 section 3" })
model SubId {
  @shape(#{ maxLength: 64 }) format?: string;
  @shape(#{ cap: "URI" }) uri?: string;
  @shape(#{ cap: "NAME" }) email?: string;
  @shape(#{ cap: "URI" }) iss?: string;
  @shape(#{ cap: "URI" }) sub?: string;
  @shape(#{ cap: "URI" }) id?: string;
  @shape(#{ maxLength: 32 }) phone_number?: string;
  @shape(#{ cap: "URI" }) url?: string;
  @shape(#{ maxItems: 20 }) identifiers?: SubIdAlias[];
}

/** RFC 9493 section 3.2.8: one identifier of an `aliases` subject. */
@shape(#{ maxProperties: 16 })
model SubIdAlias {}

@shape(#{ maxItems: 20 })
model SubIds is Array<SubId>;

/** Section 2.1: one access token asked for. */
@shape(#{ maxProperties: 32, open: true, cite: "RFC 9635 section 2.1" })
model TokenRequest {
  access?: Access;
  @shape(#{ cap: "NAME" }) label?: string;
  @shape(#{ maxItems: 16, items: #{ maxLength: 64 } }) flags?: string[];
}

/** Sections 2.1.1 and 2.1.2: one token, or several by label. */
union AccessTokenRequest {
  one: TokenRequest,
  @shape(#{ maxItems: 32 }) many: TokenRequest[],
}

/** Section 2.2. */
@shape(#{ maxProperties: 16, open: true, cite: "RFC 9635 section 2.2" })
model SubjectRequest {
  @shape(#{ maxItems: 20, items: #{ maxLength: 64 } }) sub_id_formats?: string[];
  @shape(#{ maxItems: 10, items: #{ maxLength: 64 } }) assertion_formats?: string[];
  sub_ids?: SubIds;
}

/** Section 2.3: an instance identifier, or the client by value. */
union Client {
  @shape(#{ cap: "IDENTIFIER" }) reference: string,
  client: ClientObject,
}

@shape(#{ maxProperties: 32, open: true, cite: "RFC 9635 section 2.3" })
model ClientObject {
  key?: Key;
  @shape(#{ cap: "IDENTIFIER" }) class_id?: string;
  display?: Display;
}

/** Section 2.3.2. */
@shape(#{ maxProperties: 16, open: true, cite: "RFC 9635 section 2.3.2" })
model Display {
  @shape(#{ cap: "NAME" }) name?: string;
  uri?: GnapUri;
  logo_uri?: LogoUri;
}

/** Section 2.4: a user reference, or the user by value. */
union User {
  @shape(#{ cap: "TOKEN" }) reference: string,
  user: UserObject,
}

@shape(#{ maxProperties: 16, open: true, cite: "RFC 9635 section 2.4" })
model UserObject {
  sub_ids?: SubIds;
  @shape(#{ maxItems: 10 }) assertions?: Assertion[];
}

/** Section 3.4.1. */
@shape(#{ maxProperties: 8, open: true, cite: "RFC 9635 section 3.4.1" })
model Assertion {
  @shape(#{ maxLength: 64 }) format?: string;
  @shape(#{ cap: "LARGE" }) value?: string;
}

/** Section 2.5. */
@shape(#{ maxProperties: 16, open: true, cite: "RFC 9635 section 2.5" })
model Interact {
  @shape(#{ maxItems: 16 }) start?: StartMode[];
  finish?: Finish;
  hints?: Hints;

  /**
   * #738. Not an RFC 9635 member: the short names `phr` and `phrh`, as a
   * string or an array. 256, so an EAP URI is a token the walk can decline,
   * not a schema refusal.
   */
  acr?: InteractAcr;
}

/** Section 2.5.1: a start mode by name, or with its parameters. */
union StartMode {
  @shape(#{ maxLength: 64 }) mode: string,
  object: StartModeObject,
}

@shape(#{ maxProperties: 16, open: true, cite: "RFC 9635 section 2.5.1" })
model StartModeObject {
  @shape(#{ maxLength: 64 }) mode?: string;
}

/** Section 2.5.2: a fixed document. */
@shape(#{ open: false, cite: "RFC 9635 section 2.5.2" })
model Finish {
  @shape(#{ maxLength: 64 }) method?: string;
  uri?: GnapUri;
  @shape(#{ maxLength: 256 }) nonce?: string;
  @shape(#{ maxLength: 64 }) hash_method?: string;
}

/** Section 2.5.3. */
@shape(#{ maxProperties: 16, open: true, cite: "RFC 9635 section 2.5.3" })
model Hints {
  @shape(#{ maxItems: 32, items: #{ maxLength: 64 } }) ui_locales?: string[];
}

union InteractAcr {
  @shape(#{ maxLength: 256 }) one: string,
  @shape(#{ maxItems: 16, items: #{ maxLength: 256 } }) many: string[],
}

/** RFC 9767 section 3.2: an instance identifier, or the server's key. */
union ResourceServer {
  @shape(#{ cap: "IDENTIFIER" }) reference: string,
  server: ResourceServerObject,
}

@shape(#{ maxProperties: 16, open: true, cite: "RFC 9767 section 3.2" })
model ResourceServerObject {
  key?: Key;
}

/** Every document's `$defs`, in this order. */
@definitions
model GnapDefinitions {
  uri: GnapUri;
  logoUri: LogoUri;
  accessRight: AccessRight;
  access: Access;
  proof: Proof;
  jwk: Jwk;
  key: Key;
  subId: SubId;
  subIds: SubIds;
  tokenRequest: TokenRequest;
  accessToken: AccessTokenRequest;
  subject: SubjectRequest;
  client: Client;
  user: User;
  interact: Interact;
  resourceServer: ResourceServer;
  tokenValue: TokenValue;
}

// ---------------------------------------------------------------------------
// THE REQUEST DOCUMENTS.
// ---------------------------------------------------------------------------

/** RFC 9635 section 2, plus RFC 9767 section 4's `existing_access_token`. */
@document(#{ name: "grantRequest", schemaId: "urn:iya-sts:gnap:grant-request", cite: "RFC 9635 section 2; RFC 9767 section 4" })
@shape(#{ maxProperties: 64, open: true })
model GrantRequest {
  access_token?: AccessTokenRequest;
  subject?: SubjectRequest;
  client?: Client;
  user?: User;
  interact?: Interact;
  @shape(#{ maxLength: 256 }) interact_ref?: string;
  existing_access_token?: TokenValue;
}

/** Section 5.1: nothing, or the interaction reference. */
@document(#{ name: "continuation", schemaId: "urn:iya-sts:gnap:continuation", cite: "RFC 9635 section 5.1" })
@shape(#{ open: true })
model Continuation {
  @shape(#{ maxLength: 256, pattern: "^[A-Za-z0-9._~-]*$" }) interact_ref?: string;
}

/** Section 5.3. */
@document(#{ name: "modification", schemaId: "urn:iya-sts:gnap:modification", cite: "RFC 9635 section 5.3" })
@shape(#{ maxProperties: 64, open: true })
model Modification {
  access_token?: AccessTokenRequest;
  subject?: SubjectRequest;
  user?: User;
  interact?: Interact;
}

/** Section 6.1.1. */
@document(#{ name: "rotation", schemaId: "urn:iya-sts:gnap:rotation", cite: "RFC 9635 section 6.1.1" })
@shape(#{ maxProperties: 4, open: true })
model Rotation {
  key?: Key;
}

/** RFC 9767 section 3.3. */
@document(#{ name: "introspection", schemaId: "urn:iya-sts:gnap:introspection", cite: "RFC 9767 section 3.3" })
@shape(#{ maxProperties: 32, open: true })
model Introspection {
  access_token?: TokenValue;
  @shape(#{ maxLength: 64 }) proof?: string;
  resource_server?: ResourceServer;
  access?: Access;
}

/** RFC 9767 section 3.4. */
@document(#{ name: "registration", schemaId: "urn:iya-sts:gnap:registration", cite: "RFC 9767 section 3.4" })
@shape(#{ maxProperties: 32, open: true })
model Registration {
  access?: Access;
  resource_server?: ResourceServer;
  @shape(#{ maxItems: 16, items: #{ maxLength: 64 } }) token_formats_supported?: string[];
  token_introspection_required?: boolean;

  /**
   * THIS SERVICE'S EXTENSION (#432 phase 5): the owner of each identifier
   * in the set, an identifier to the DN of a person or a group —
   * `gnap/gnap_ownership.ts`. `gnap/gnap_rs.ts`'s `register()` holds each
   * key to an identifier the set carries and each value to an entry.
   */
  @shape(#{ maxProperties: 256, propertyNames: #{ maxLength: 1024 }, values: #{ maxLength: 1024 } })
  resource_owners?: Record<string>;
}

// ---------------------------------------------------------------------------
// THE PATHS' PARAMETERS.
// ---------------------------------------------------------------------------

@pathParams(#{ id: "as", cite: "this service's named authorization servers (`common/authorization_servers.js`)" })
model AsPath {
  @pathParam(#{ kind: "identifier", empty: true, cite: "this service's own: a named authorization server" })
  as?: string;
}

@pathParams(#{ id: "continue", cite: "RFC 9635 section 3.1" })
model ContinuePath {
  @pathParam(#{ kind: "base64url", cite: "RFC 9635 section 3.1: the continuation URI this service mints" })
  grant: string;
}

@pathParams(#{ id: "manage", cite: "RFC 9635 section 3.2.1" })
model ManagePath {
  @pathParam(#{ kind: "base64url", cite: "RFC 9635 section 3.2.1: the management URI this service mints" })
  handle: string;
}

// ---------------------------------------------------------------------------
// THE REGISTRIES THE WALK READS.
// ---------------------------------------------------------------------------

/** Section 10.4: the flags a client may ask for. */
@registry(#{ id: "request-flags", cite: "RFC 9635 sections 2.1.1 and 10.4" })
union RequestFlags {
  bearer: "bearer",
}

/**
 * Section 10.4: a flag only a response carries, so a client asking for it
 * has a flag configuration that is not valid — `invalid_flag`.
 */
@registry(#{ id: "response-only-flags", cite: "RFC 9635 sections 3.2.1 and 10.4" })
union ResponseOnlyFlags {
  durable: "durable",
}

@registry(#{ id: "start-modes", cite: "RFC 9635 section 10.9" })
union StartModes {
  redirect: "redirect",
  app: "app",
  user_code: "user_code",
  user_code_uri: "user_code_uri",
}

@registry(#{ id: "finish-methods", cite: "RFC 9635 section 10.10" })
union FinishMethods {
  redirect: "redirect",
  push: "push",
}

@registry(#{ id: "assertion-formats", cite: "RFC 9635 section 10.6" })
union AssertionFormats {
  id_token: "id_token",
  saml2: "saml2",
}

@registry(#{ id: "proof-methods", cite: "RFC 9635 section 10.16" })
union ProofMethods {
  httpsig: "httpsig",
  mtls: "mtls",
  jwsd: "jwsd",
  jws: "jws",
}

@registry(#{ id: "key-formats", cite: "RFC 9635 section 10.17" })
union KeyFormats {
  jwk: "jwk",
  cert: "cert",
  `cert#S256`: "cert#S256",
}

/**
 * RFC 9493's subject identifier formats, in RFC 9493's spellings, each with
 * the members it must carry. GNAP section 2.2 names RFC 9493's registry and
 * nothing else, so SSF 1.0's own formats are not here.
 */
@registry(#{ id: "sub-id-formats", cite: "RFC 9493 section 3.2; RFC 9635 section 2.2" })
model SubIdFormats {
  account: ["uri"];
  email: ["email"];
  iss_sub: ["iss", "sub"];
  opaque: ["id"];
  phone_number: ["phone_number"];
  did: ["url"];
  uri: ["uri"];
  aliases: ["identifiers"];
}

// ---------------------------------------------------------------------------
// THE ANSWERS.
// ---------------------------------------------------------------------------

/** Section 3: what the grant endpoint, a continuation and a modification answer. */
@members(#{ id: "grant-response", cite: "RFC 9635 section 3", members: "closed" })
model GrantResponse {
  @member(#{ cite: "RFC 9635 section 3.1" })
  continue?: ContinueResponse;

  @member(#{ cite: "RFC 9635 sections 3.2.1 and 3.2.2" })
  access_token?: AccessTokenResponse | AccessTokenResponse[];

  @member(#{ cite: "RFC 9635 section 3.3" })
  interact?: InteractResponse;

  @member(#{ cite: "RFC 9635 section 3.4" })
  subject?: SubjectResponse;

  @member(#{ cite: "RFC 9635 section 3.5" })
  instance_id?: string;
}

/** Section 3.1. */
@members(#{ id: "continue", cite: "RFC 9635 section 3.1", members: "closed" })
model ContinueResponse {
  @member(#{ cite: "RFC 9635 section 3.1" })
  uri: string;

  @member(#{ cite: "RFC 9635 section 3.1" })
  wait?: integer;

  @member(#{ cite: "RFC 9635 section 3.1" })
  access_token: BoundToken;
}

/** Sections 3.1 and 3.2.1: a token bound to the client's key, value only. */
@members(#{ id: "bound-token", cite: "RFC 9635 sections 3.1 and 3.2.1", members: "closed" })
model BoundToken {
  @member(#{ cite: "RFC 9635 section 3.2.1" })
  value: string;
}

/** Section 3.2.1. */
@members(#{ id: "access-token", cite: "RFC 9635 section 3.2.1", members: "closed" })
model AccessTokenResponse {
  @member(#{ cite: "RFC 9635 section 3.2.1" })
  value: string;

  @member(#{ cite: "RFC 9635 section 3.2.1" })
  label?: string;

  @member(#{ cite: "RFC 9635 section 3.2.1" })
  manage?: ManageResponse;

  @member(#{ cite: "RFC 9635 section 3.2.1" })
  access: unknown[];

  @member(#{ cite: "RFC 9635 section 3.2.1" })
  expires_in?: integer;

  @member(#{ cite: "RFC 9635 section 3.2.1" })
  key?: string | Record<unknown>;

  @member(#{ cite: "RFC 9635 section 3.2.1" })
  flags?: string[];
}

/** Section 3.2.1's `manage`. */
@members(#{ id: "manage", cite: "RFC 9635 section 3.2.1", members: "closed" })
model ManageResponse {
  @member(#{ cite: "RFC 9635 section 3.2.1" })
  uri: string;

  @member(#{ cite: "RFC 9635 section 3.2.1" })
  access_token: BoundToken;
}

/** Section 3.3. */
@members(#{ id: "interact", cite: "RFC 9635 section 3.3", members: "closed" })
model InteractResponse {
  @member(#{ cite: "RFC 9635 section 3.3.1" })
  redirect?: string;

  @member(#{ cite: "RFC 9635 section 3.3.2" })
  app?: string;

  @member(#{ cite: "RFC 9635 section 3.3.3" })
  user_code?: string;

  @member(#{ cite: "RFC 9635 section 3.3.4" })
  user_code_uri?: UserCodeUri;

  @member(#{ cite: "RFC 9635 section 3.3.5" })
  finish?: string;

  @member(#{ cite: "RFC 9635 section 3.3.6" })
  expires_in?: integer;
}

/** Section 3.3.4. */
@members(#{ id: "user-code-uri", cite: "RFC 9635 section 3.3.4", members: "closed" })
model UserCodeUri {
  @member(#{ cite: "RFC 9635 section 3.3.4" })
  code: string;

  @member(#{ cite: "RFC 9635 section 3.3.4" })
  uri: string;
}

/** Section 3.4. */
@members(#{ id: "subject", cite: "RFC 9635 section 3.4", members: "closed" })
model SubjectResponse {
  @member(#{ cite: "RFC 9635 section 3.4" })
  sub_ids?: Record<unknown>[];

  @member(#{ cite: "RFC 9635 section 3.4" })
  assertions?: Record<unknown>[];

  @member(#{ cite: "RFC 9635 section 3.4" })
  updated_at?: string;
}

/** Section 3.6: a refusal, with a continuation where one is still offered. */
@members(#{ id: "error-response", cite: "RFC 9635 section 3.6", members: "closed" })
model ErrorResponse {
  @member(#{ cite: "RFC 9635 section 3.6" })
  error: ErrorObject;

  @member(#{ cite: "RFC 9635 section 3.6" })
  continue?: ContinueResponse;
}

@members(#{ id: "error", cite: "RFC 9635 section 3.6", members: "closed" })
model ErrorObject {
  @member(#{ cite: "RFC 9635 section 3.6" })
  code: string;

  @member(#{ cite: "RFC 9635 section 3.6" })
  description?: string;
}

/** Section 9, at OPTIONS on the grant endpoint, and RFC 9767's addition. */
@members(#{ id: "discovery", cite: "RFC 9635 section 9", members: "closed" })
model Discovery {
  @member(#{ cite: "RFC 9635 section 9" })
  grant_request_endpoint: string;

  @member(#{ cite: "RFC 9635 section 9" })
  interaction_start_modes_supported?: string[];

  @member(#{ cite: "RFC 9635 section 9" })
  interaction_finish_methods_supported?: string[];

  @member(#{ cite: "RFC 9635 section 9" })
  key_proofs_supported?: string[];

  @member(#{ cite: "RFC 9635 section 9" })
  sub_id_formats_supported?: string[];

  @member(#{ cite: "RFC 9635 section 9" })
  assertion_formats_supported?: string[];

  @member(#{ cite: "RFC 9635 section 9" })
  key_rotation_supported?: boolean;

  @member(#{ cite: "RFC 9767 section 10.1" })
  token_formats_supported?: string[];
}

/** RFC 9767 section 3.1, at /.well-known/gnap-as-rs. */
@members(#{ id: "rs-discovery", cite: "RFC 9767 section 3.1", members: "closed" })
model RsDiscovery {
  @member(#{ cite: "RFC 9767 section 3.1" })
  grant_request_endpoint: string;

  @member(#{ cite: "RFC 9767 section 3.1" })
  introspection_endpoint?: string;

  @member(#{ cite: "RFC 9767 section 3.1" })
  token_formats_supported?: string[];

  @member(#{ cite: "RFC 9767 section 3.1" })
  resource_registration_endpoint?: string;

  @member(#{ cite: "RFC 9767 section 3.1" })
  key_proofs_supported?: string[];

  @member(#{ cite: "this service's own (#432): draft-ietf-oauth-status-list section 9.1's name for the realm's one access-token list", own: true })
  status_list_aggregation_endpoint?: string;

  @member(#{ cite: "this service's own (#432): the revoked biscuits' identifiers", own: true })
  biscuit_revocation_endpoint?: string;
}

/**
 * RFC 9767 section 3.3. OPEN: the person's claims a resource server's
 * catalogued types declare (`introspectionClaims`, rule 3bz) are added as
 * top-level members.
 */
@members(#{ id: "introspection-response", cite: "RFC 9767 section 3.3", members: "open" })
model IntrospectionResponse {
  @member(#{ cite: "RFC 9767 section 3.3" })
  active: boolean;

  @member(#{ cite: "RFC 9767 section 3.3" })
  access?: unknown[];

  @member(#{ cite: "RFC 9767 section 3.3" })
  key?: string | Record<unknown>;

  @member(#{ cite: "RFC 9767 section 3.3" })
  flags?: string[];

  @member(#{ cite: "RFC 9767 section 3.3" })
  exp?: integer;

  @member(#{ cite: "RFC 9767 section 3.3" })
  iat?: integer;

  @member(#{ cite: "RFC 9767 section 3.3" })
  nbf?: integer;

  @member(#{ cite: "RFC 9767 section 3.3" })
  aud?: string | string[];

  @member(#{ cite: "RFC 9767 section 3.3" })
  sub?: string;

  @member(#{ cite: "RFC 9767 section 3.3" })
  iss?: string;

  @member(#{ cite: "RFC 9767 section 3.3" })
  instance_id?: string;

  @member(#{ cite: "RFC 9767 section 3.3" })
  label?: string;

  @member(#{ cite: "RFC 8693 section 4.1, on GNAP's token model (#432)", own: true })
  act?: Record<unknown>;

  @member(#{ cite: "this service's own (#432 phase 5): the grant a limit's totals are counted against", own: true })
  grant_id?: string;

  @member(#{ cite: "this service's own: the RFC 9767 format the token was minted in", own: true })
  format?: string;
}

/** RFC 9767 section 3.4. */
@members(#{ id: "registration-response", cite: "RFC 9767 section 3.4", members: "closed" })
model RegistrationResponse {
  @member(#{ cite: "RFC 9767 section 3.4" })
  resource_reference: string;

  @member(#{ cite: "RFC 9767 section 3.4" })
  instance_id?: string;

  @member(#{ cite: "RFC 9767 section 3.4" })
  introspection_endpoint?: string;
}

/** GET /gnap/keys: what verifies each self-contained format. */
@members(#{ id: "keys", cite: "this service's own: the verification material of RFC 9767's formats", members: "closed" })
model KeysDocument {
  @member(#{ cite: "RFC 9767 section 2.2 (jwt-signed)", own: true })
  jwt?: Record<unknown>;

  @member(#{ cite: "RFC 9767 section 2.5 (biscuit)", own: true })
  biscuit?: Record<unknown>;

  @member(#{ cite: "RFC 9767 section 2.6 (zcap)", own: true })
  zcap?: Record<unknown>;

  @member(#{ cite: "RFC 9767 section 2.4 (macaroon)", own: true })
  macaroon?: Record<unknown>;

  @member(#{ cite: "RFC 9767 section 2.3 (jwt-encrypted)", own: true })
  `jwt-encrypted`?: Record<unknown>;
}

/** GET /gnap/biscuit/revocations (#432). */
@members(#{ id: "biscuit-revocations", cite: "this service's own (#432): no document says where a biscuit revocation list is published", members: "closed" })
model BiscuitRevocations {
  @member(#{ cite: "this service's own", own: true })
  revocation_ids: string[];

  @member(#{ cite: "this service's own", own: true })
  ttl: integer;
}

/** GET /gnap/zcap/controller: a W3C Controlled Identifiers document. */
@members(#{ id: "zcap-controller", cite: "W3C Controlled Identifiers 1.0 section 2", members: "open" })
model ZcapController {
  @member(#{ cite: "W3C Controlled Identifiers 1.0 section 2" })
  `@context`: string[];

  @member(#{ cite: "W3C Controlled Identifiers 1.0 section 2.1.1" })
  id: string;

  @member(#{ cite: "W3C Controlled Identifiers 1.0 section 2.2" })
  verificationMethod: Record<unknown>[];

  @member(#{ cite: "W3C Controlled Identifiers 1.0 section 2.3.2" })
  assertionMethod?: unknown[];

  @member(#{ cite: "W3C Controlled Identifiers 1.0 section 2.3" })
  capabilityDelegation?: unknown[];

  @member(#{ cite: "W3C Controlled Identifiers 1.0 section 2.3" })
  capabilityInvocation?: unknown[];
}

/** GET /gnap-api (#578): the operations, each with what it mirrors. */
@members(#{ id: "gnap-api-index", cite: "this service's own (#578)", members: "closed" })
model GnapApiIndex {
  @member(#{ cite: "this service's own (#578)", own: true })
  api: string;

  @member(#{ cite: "this service's own (#578)", own: true })
  operations: Record<unknown>[];
}

/**
 * Every other answer of `/gnap-api` (#578): a view, an act's outcome, or a
 * refusal that leaves the page standing.
 */
@members(#{ id: "gnap-api-answer", cite: "this service's own (#578)", members: "closed" })
model GnapApiAnswer {
  @member(#{ cite: "this service's own (#578)", own: true })
  ok: boolean;

  @member(#{ cite: "this service's own (#578): the browser's next step", own: true })
  next?: "redirect" | "done" | "page";

  @member(#{ cite: "this service's own (#578): the finish URI or the page's address", own: true })
  location?: string;

  @member(#{ cite: "this service's own (#578): facts the browser draws", own: true })
  view?: Record<unknown>;

  @member(#{ cite: "this service's own (#578, #571)", own: true })
  csrf?: string;

  @member(#{ cite: "this service's own (#578): English sentences", own: true })
  errors?: string[];

  @member(#{ cite: "this service's own (#539)", own: true })
  preferredLanguage?: string;
}

// ---------------------------------------------------------------------------
// THE ACCESS-TYPE CATALOGUE (rule 3bz).
// ---------------------------------------------------------------------------

/**
 * One definition an application declares in `oauthAuthorizationDetailsType`:
 * an RFC 9396 type, extended for GNAP (#432 phase 4) and fine-grained
 * authorization (#564). `common/applications.js`'s
 * `authorizationDetailsTypeOf()` refuses any other member, in this order,
 * and checks each member's meaning; a bare string is a definition with only
 * `type`.
 */
@members(#{ id: "access-type-definition", cite: "RFC 9396 section 2; this service's catalogue (rule 3bz)", members: "closed" })
model AccessTypeDefinition {
  @member(#{ cite: "RFC 9396 section 2" })
  type: string;

  @member(#{ cite: "this service's catalogue", own: true })
  description?: string;

  @member(#{ cite: "RFC 9396 section 2.2" })
  locations?: string[];

  @member(#{ cite: "this service's catalogue: a JSON Schema every detail of the type meets", own: true })
  schema?: Record<unknown>;

  @member(#{ cite: "RFC 9396 section 2.2" })
  actions?: string[];

  @member(#{ cite: "RFC 9396 section 2.2" })
  datatypes?: string[];

  @member(#{ cite: "RFC 9396 section 2.2" })
  privileges?: string[];

  @member(#{ cite: "this service's catalogue (#432 phase 4)", own: true })
  required?: string[];

  @member(#{ cite: "this service's catalogue (#432 phase 6): who must be asked", own: true })
  interaction?: "always" | "default" | "never";

  @member(#{ cite: "this service's catalogue (#432 phase 6)", own: true })
  consentActions?: string[];

  @member(#{ cite: "this service's catalogue (#432 phase 4)", own: true })
  bearer?: boolean;

  @member(#{ cite: "this service's catalogue (#432 phase 4)", own: true })
  maxLifetimeS?: integer;

  @member(#{ cite: "this service's catalogue (#432 phase 6)", own: true })
  acr?: string;

  @member(#{ cite: "this service's catalogue (#432 phase 4)", own: true })
  derivableFrom?: string[];

  @member(#{ cite: "this service's catalogue (#432 phase 3)", own: true })
  introspectionClaims?: string[];

  @member(#{ cite: "this service's catalogue (#432 phase 5): a JSON Schema of the type's limits", own: true })
  limits?: Record<unknown>;

  @member(#{ cite: "this service's catalogue (#564): the type's XACML rows", own: true })
  xacml?: unknown[];

  @member(#{ cite: "this service's catalogue (#564)", own: true })
  notForPolicy?: string[];
}

// ---------------------------------------------------------------------------
// THE ERROR CODES.
// ---------------------------------------------------------------------------

@errorCodes
model GnapErrorCodes {
  @errorCode(#{ cite: "RFC 9635 section 3.6" })
  invalid_request: never;

  @errorCode(#{ cite: "RFC 9635 section 3.6" })
  invalid_client: never;

  @errorCode(#{ cite: "RFC 9635 section 3.6" })
  invalid_interaction: never;

  @errorCode(#{ cite: "RFC 9635 section 3.6" })
  invalid_flag: never;

  @errorCode(#{ cite: "RFC 9635 section 3.6" })
  invalid_rotation: never;

  @errorCode(#{ cite: "RFC 9635 section 3.6" })
  key_rotation_not_supported: never;

  @errorCode(#{ cite: "RFC 9635 section 3.6" })
  invalid_continuation: never;

  @errorCode(#{ cite: "RFC 9635 section 3.6" })
  user_denied: never;

  @errorCode(#{ cite: "RFC 9635 section 3.6" })
  request_denied: never;

  @errorCode(#{ cite: "RFC 9635 section 3.6" })
  unknown_user: never;

  @errorCode(#{ cite: "RFC 9635 section 3.6" })
  unknown_interaction: never;

  @errorCode(#{ cite: "RFC 9635 section 3.6" })
  too_fast: never;

  @errorCode(#{ cite: "RFC 9635 section 3.6" })
  too_many_attempts: never;

  @errorCode(#{ cite: "this service's own: RFC 9767 section 3.2's caller is a resource server, and section 3.6's invalid_client names a client instance", own: true })
  invalid_resource_server: never;

  @errorCode(#{ cite: "this service's own: a resource server registering access its entry does not allow (RFC 9767 section 3.4)", own: true })
  invalid_access: never;
}
