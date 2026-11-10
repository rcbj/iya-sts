// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/oauth/oauth_members.tsp
//
// Written by hand (#1579). THE MEMBERS OF WHAT THE AUTHORIZATION SERVER AND
// OPENID PROVIDER ANSWER, AND THE ERROR CODES IT SENDS: the two discovery
// documents, the token response, the error response, the introspection,
// registration, device authorization, backchannel authentication and pushed
// authorization responses, and the claim sets of the ID Token, the RFC 9068
// access token, the Logout Token and the RFC 9701 introspection response.
//
// A `closed` set is every member that may appear: `oauth-oidc/oauth2.ts`
// holds the discovery documents and the token response to it on every
// answer, and a member the model does not name is recorded under its error
// code (the answer is not changed: the model describes the wire, it does
// not reshape it). An `open` set is the members a specification names, each
// with the JSON type it must have; others may appear — a custom claim an
// administrator configured, a client's own registration metadata — and
// `tests/model_oauth.js` holds what the issuers produced to the named ones.
// The error codes are every `error` this service sends; the module's one
// error funnel records an undeclared one.

import "../lib/oauth_lib.tsp";

using IyaSts.OAuthLib;

namespace IyaSts.OAuth;

// ---------------------------------------------------------------------------
// THE DISCOVERY DOCUMENTS.
//
// Every member either document carries in any mode, with every switch on:
// conditional members (CIBA's, PAR's, RFC 8705's aliases) appear only when
// their feature does, which is why all but the two RFC 8414 requires are
// optional.
// ---------------------------------------------------------------------------

/** RFC 8414's document, at /.well-known/oauth-authorization-server. */
@members(#{ id: "authorization-server-metadata", cite: "RFC 8414 section 2", members: "closed" })
model AuthorizationServerMetadata {
  @member(#{ cite: "OpenID Connect Discovery 1.0 section 3" })
  acr_values_supported?: string[];

  @member(#{ cite: "this service's own (RFC 7523 encrypted assertions, #114)", own: true })
  assertion_encryption_alg_values_supported?: string[];

  @member(#{ cite: "this service's own (RFC 7523 encrypted assertions, #114)", own: true })
  assertion_encryption_enc_values_supported?: string[];

  @member(#{ cite: "this service's own (RFC 7523 and RFC 7522 assertion algorithms, #114)", own: true })
  assertion_signing_alg_values_supported?: string[];

  @member(#{ cite: "RFC 9396 section 10" })
  authorization_details_types_supported?: string[];

  @member(#{ cite: "JARM section 4" })
  authorization_encryption_alg_values_supported?: string[];

  @member(#{ cite: "JARM section 4" })
  authorization_encryption_enc_values_supported?: string[];

  @member(#{ cite: "RFC 8414 section 2" })
  authorization_endpoint?: string;

  @member(#{ cite: "RFC 9207 section 3" })
  authorization_response_iss_parameter_supported?: boolean;

  @member(#{ cite: "JARM section 4" })
  authorization_signing_alg_values_supported?: string[];

  @member(#{ cite: "RFC 8414 section 2" })
  code_challenge_methods_supported?: string[];

  @member(#{ cite: "this service's own (#42, D8)", own: true })
  crypto_metadata_uri?: string;

  @member(#{ cite: "RFC 8628 section 4" })
  device_authorization_endpoint?: string;

  @member(#{ cite: "RFC 9449 section 5.1" })
  dpop_signing_alg_values_supported?: string[];

  @member(#{ cite: "Grant Management for OAuth 2.0 section 7" })
  grant_management_actions_supported?: string[];

  @member(#{ cite: "Grant Management for OAuth 2.0 section 7" })
  grant_management_endpoint?: string;

  @member(#{ cite: "RFC 8414 section 2" })
  grant_types_supported?: string[];

  @member(#{ cite: "RFC 9701 section 7" })
  introspection_encryption_alg_values_supported?: string[];

  @member(#{ cite: "RFC 9701 section 7" })
  introspection_encryption_enc_values_supported?: string[];

  @member(#{ cite: "RFC 8414 section 2" })
  introspection_endpoint?: string;

  @member(#{ cite: "RFC 8414 section 2" })
  introspection_endpoint_auth_methods_supported?: string[];

  @member(#{ cite: "RFC 8414 section 2" })
  introspection_endpoint_auth_signing_alg_values_supported?: string[];

  @member(#{ cite: "RFC 9701 section 7" })
  introspection_signing_alg_values_supported?: string[];

  @member(#{ cite: "RFC 8414 section 2" })
  issuer: string;

  @member(#{ cite: "RFC 8414 section 2" })
  jwks_uri?: string;

  @member(#{ cite: "RFC 8705 section 5" })
  mtls_endpoint_aliases?: Record<string>;

  @member(#{ cite: "RFC 8414 section 2" })
  op_policy_uri?: string;

  @member(#{ cite: "RFC 8414 section 2" })
  op_tos_uri?: string;

  @member(#{ cite: "OpenID for Verifiable Credential Issuance 1.0 section 12.3" })
  `pre-authorized_grant_anonymous_access_supported`?: boolean;

  @member(#{ cite: "RFC 9126 section 5" })
  pushed_authorization_request_endpoint?: string;

  @member(#{ cite: "RFC 8414 section 2" })
  registration_endpoint?: string;

  @member(#{ cite: "OpenID Connect Discovery 1.0 section 3" })
  request_object_encryption_alg_values_supported?: string[];

  @member(#{ cite: "OpenID Connect Discovery 1.0 section 3" })
  request_object_encryption_enc_values_supported?: string[];

  @member(#{ cite: "OpenID Connect Discovery 1.0 section 3" })
  request_object_signing_alg_values_supported?: string[];

  @member(#{ cite: "OpenID Connect Discovery 1.0 section 3" })
  request_parameter_supported?: boolean;

  @member(#{ cite: "OpenID Connect Discovery 1.0 section 3" })
  request_uri_parameter_supported?: boolean;

  @member(#{ cite: "RFC 9126 section 5" })
  require_pushed_authorization_requests?: boolean;

  @member(#{ cite: "OpenID Connect Discovery 1.0 section 3" })
  require_request_uri_registration?: boolean;

  @member(#{ cite: "RFC 9101 section 10.5" })
  require_signed_request_object?: boolean;

  @member(#{ cite: "RFC 8414 section 2" })
  response_modes_supported?: string[];

  @member(#{ cite: "RFC 8414 section 2" })
  response_types_supported: string[];

  @member(#{ cite: "RFC 8414 section 2" })
  revocation_endpoint?: string;

  @member(#{ cite: "RFC 8414 section 2" })
  revocation_endpoint_auth_methods_supported?: string[];

  @member(#{ cite: "RFC 8414 section 2" })
  revocation_endpoint_auth_signing_alg_values_supported?: string[];

  @member(#{ cite: "RFC 8414 section 2" })
  scopes_supported?: string[];

  @member(#{ cite: "RFC 8414 section 2" })
  service_documentation?: string;

  @member(#{ cite: "RFC 8414 section 2.1" })
  signed_metadata?: string;

  @member(#{ cite: "Token Status List section 9.3" })
  status_list_aggregation_endpoint?: string;

  @member(#{ cite: "RFC 8705 section 3.3" })
  tls_client_certificate_bound_access_tokens?: boolean;

  @member(#{ cite: "RFC 8414 section 2" })
  token_endpoint?: string;

  @member(#{ cite: "RFC 8414 section 2" })
  token_endpoint_auth_methods_supported?: string[];

  @member(#{ cite: "RFC 8414 section 2" })
  token_endpoint_auth_signing_alg_values_supported?: string[];

  @member(#{ cite: "RFC 8414 section 2" })
  ui_locales_supported?: string[];

  @member(#{ cite: "this service's own (RFC 7521 section 4.1's type, as a member)", own: true })
  `urn:ietf:params:oauth:client-assertion-type:jwt-bearer_supported`?: boolean;

  @member(#{ cite: "this service's own (RFC 7522 section 2.2's type, as a member)", own: true })
  `urn:ietf:params:oauth:client-assertion-type:saml2-bearer_supported`?: boolean;
}

/**
 * OpenID Connect Discovery's document, at /.well-known/openid-configuration:
 * RFC 8414's members and the provider's own.
 */
@members(#{ id: "openid-provider-metadata", cite: "OpenID Connect Discovery 1.0 section 3", members: "closed" })
model OpenIdProviderMetadata {
  ...AuthorizationServerMetadata;

  @member(#{ cite: "OpenID Connect for Identity Assurance 1.0 section 8" })
  attachments_supported?: string[];

  @member(#{ cite: "OpenID Connect CIBA Core 1.0 section 4" })
  backchannel_authentication_endpoint?: string;

  @member(#{ cite: "OpenID Connect CIBA Core 1.0 section 4" })
  backchannel_authentication_request_signing_alg_values_supported?: string[];

  @member(#{ cite: "OpenID Connect Back-Channel Logout 1.0 section 2.1" })
  backchannel_logout_session_supported?: boolean;

  @member(#{ cite: "OpenID Connect Back-Channel Logout 1.0 section 2.1" })
  backchannel_logout_supported?: boolean;

  @member(#{ cite: "OpenID Connect CIBA Core 1.0 section 4" })
  backchannel_token_delivery_modes_supported?: string[];

  @member(#{ cite: "OpenID Connect CIBA Core 1.0 section 4" })
  backchannel_user_code_parameter_supported?: boolean;

  @member(#{ cite: "OpenID Connect Session Management 1.0 section 3.3" })
  check_session_iframe?: string;

  @member(#{ cite: "OpenID Connect Discovery 1.0 section 3" })
  claim_types_supported?: string[];

  @member(#{ cite: "OpenID Connect for Identity Assurance 1.0 section 8" })
  claims_in_verified_claims_supported?: string[];

  @member(#{ cite: "OpenID Connect Discovery 1.0 section 3" })
  claims_locales_supported?: string[];

  @member(#{ cite: "OpenID Connect Discovery 1.0 section 3" })
  claims_parameter_supported?: boolean;

  @member(#{ cite: "OpenID Connect Discovery 1.0 section 3" })
  claims_supported?: string[];

  @member(#{ cite: "OpenID Connect Discovery 1.0 section 3" })
  display_values_supported?: string[];

  @member(#{ cite: "OpenID Connect for Identity Assurance 1.0 section 8" })
  documents_check_methods_supported?: string[];

  @member(#{ cite: "OpenID Connect for Identity Assurance 1.0 section 8" })
  documents_supported?: string[];

  @member(#{ cite: "OpenID Connect for Identity Assurance 1.0 section 8" })
  electronic_records_supported?: string[];

  @member(#{ cite: "OpenID Connect RP-Initiated Logout 1.0 section 2.1" })
  end_session_endpoint?: string;

  @member(#{ cite: "OpenID Connect for Identity Assurance 1.0 section 8" })
  evidence_supported?: string[];

  @member(#{ cite: "OpenID Connect Front-Channel Logout 1.0 section 3" })
  frontchannel_logout_session_supported?: boolean;

  @member(#{ cite: "OpenID Connect Front-Channel Logout 1.0 section 3" })
  frontchannel_logout_supported?: boolean;

  @member(#{ cite: "OpenID Connect Discovery 1.0 section 3" })
  id_token_encryption_alg_values_supported?: string[];

  @member(#{ cite: "OpenID Connect Discovery 1.0 section 3" })
  id_token_encryption_enc_values_supported?: string[];

  @member(#{ cite: "OpenID Connect Discovery 1.0 section 3" })
  id_token_signing_alg_values_supported?: string[];

  @member(#{ cite: "OpenID Connect Native SSO for Mobile Apps 1.0 section 4" })
  native_sso_supported?: boolean;

  @member(#{ cite: "Initiating User Registration via OpenID Connect 1.0 section 4" })
  prompt_values_supported?: string[];

  @member(#{ cite: "OpenID Connect Discovery 1.0 section 3" })
  subject_types_supported?: string[];

  @member(#{ cite: "OpenID Connect for Identity Assurance 1.0 section 8" })
  trust_frameworks_supported?: string[];

  @member(#{ cite: "OpenID Connect Discovery 1.0 section 3" })
  userinfo_encryption_alg_values_supported?: string[];

  @member(#{ cite: "OpenID Connect Discovery 1.0 section 3" })
  userinfo_encryption_enc_values_supported?: string[];

  @member(#{ cite: "OpenID Connect Discovery 1.0 section 3" })
  userinfo_endpoint?: string;

  @member(#{ cite: "OpenID Connect Discovery 1.0 section 3" })
  userinfo_signing_alg_values_supported?: string[];

  @member(#{ cite: "OpenID Connect for Identity Assurance 1.0 section 8" })
  verified_claims_supported?: boolean;
}

// ---------------------------------------------------------------------------
// THE ANSWERS.
// ---------------------------------------------------------------------------

/** A successful token response, from every grant. */
@members(#{ id: "token-response", cite: "RFC 6749 section 5.1", members: "closed" })
model TokenResponse {
  @member(#{ cite: "RFC 6749 section 5.1" })
  access_token: string;

  /** `DPoP` for a bound token (RFC 9449 section 5), `N_A` for an exchange that issued no access token (RFC 8693 section 2.2.1). */
  @member(#{ cite: "RFC 6749 section 5.1" })
  token_type: string;

  @member(#{ cite: "RFC 6749 section 5.1" })
  expires_in?: int64;

  /** Left out when the token carries no scope (#156). */
  @member(#{ cite: "RFC 6749 section 5.1" })
  scope?: string;

  @member(#{ cite: "RFC 9396 section 7" })
  authorization_details?: unknown[];

  @member(#{ cite: "Grant Management for OAuth 2.0 section 4.2" })
  grant_id?: string;

  @member(#{ cite: "RFC 6749 section 5.1" })
  refresh_token?: string;

  @member(#{ cite: "OpenID Connect Native SSO for Mobile Apps 1.0 section 4.1" })
  device_secret?: string;

  @member(#{ cite: "OpenID Connect Core 1.0 section 3.1.3.3" })
  id_token?: string;

  @member(#{ cite: "RFC 8693 section 2.2.1" })
  issued_token_type?: string;
}

/** An error response: the token endpoint's, and every JSON refusal shaped like it. */
@members(#{ id: "error-response", cite: "RFC 6749 section 5.2", members: "open" })
model ErrorResponse {
  @member(#{ cite: "RFC 6749 section 5.2" })
  error: string;

  @member(#{ cite: "RFC 6749 section 5.2" })
  error_description?: string;

  @member(#{ cite: "RFC 6749 section 5.2" })
  error_uri?: string;
}

/** An introspection response; a token's own claims may ride along. */
@members(#{ id: "introspection-response", cite: "RFC 7662 section 2.2", members: "open" })
model IntrospectionResponse {
  @member(#{ cite: "RFC 7662 section 2.2" })
  active: boolean;

  @member(#{ cite: "RFC 7662 section 2.2" })
  scope?: string;

  @member(#{ cite: "RFC 7662 section 2.2" })
  client_id?: string;

  @member(#{ cite: "RFC 7662 section 2.2" })
  username?: string;

  @member(#{ cite: "RFC 7662 section 2.2" })
  token_type?: string;

  @member(#{ cite: "RFC 7662 section 2.2" })
  exp?: int64;

  @member(#{ cite: "RFC 7662 section 2.2" })
  iat?: int64;

  @member(#{ cite: "RFC 7662 section 2.2" })
  nbf?: int64;

  @member(#{ cite: "RFC 7662 section 2.2" })
  sub?: string;

  @member(#{ cite: "RFC 7662 section 2.2" })
  aud?: string | string[];

  @member(#{ cite: "RFC 7662 section 2.2" })
  iss?: string;

  @member(#{ cite: "RFC 7662 section 2.2" })
  jti?: string;

  @member(#{ cite: "RFC 7800 section 3.1; RFC 9449 section 6.2" })
  cnf?: Record<unknown>;

  @member(#{ cite: "RFC 9396 section 9.2" })
  authorization_details?: unknown[];
}

/** A registration, as RFC 7591 answers it and RFC 7592 reads it back. */
@members(#{ id: "registration-response", cite: "RFC 7591 section 3.2.1", members: "open" })
model RegistrationResponse {
  @member(#{ cite: "RFC 7591 section 3.2.1" })
  client_id: string;

  @member(#{ cite: "RFC 7591 section 3.2.1" })
  client_secret?: string;

  @member(#{ cite: "RFC 7591 section 3.2.1" })
  client_id_issued_at?: int64;

  @member(#{ cite: "RFC 7591 section 3.2.1" })
  client_secret_expires_at?: int64;

  @member(#{ cite: "RFC 7592 section 3" })
  registration_access_token?: string;

  @member(#{ cite: "RFC 7592 section 3" })
  registration_client_uri?: string;

  @member(#{ cite: "RFC 7591 section 2" })
  redirect_uris?: string[];

  @member(#{ cite: "RFC 7591 section 2" })
  token_endpoint_auth_method?: string;

  @member(#{ cite: "RFC 7591 section 2" })
  grant_types?: string[];

  @member(#{ cite: "RFC 7591 section 2" })
  response_types?: string[];

  @member(#{ cite: "RFC 7591 section 2" })
  client_name?: string;

  @member(#{ cite: "OpenID Connect Dynamic Client Registration 1.0 section 2" })
  application_type?: string;
}

/**
 * The client metadata a registration sends (RFC 7591 and RFC 7592) — every
 * member this service reads, from RFC 7591 section 2, OpenID Connect Dynamic
 * Client Registration section 2 and the extension specifications that add
 * one. Open: a member nobody defines is stored and echoed, as section 2 lets
 * a server do. The refusals in `common/applications.js` that test a member's
 * JSON type read it from here; `registerClient()` records the members whose
 * type nothing refuses today (STS-OAUTH-1005), and the answer is unchanged.
 */
@members(#{ id: "registration-request", cite: "RFC 7591 section 2", members: "open" })
model RegistrationRequest {
  @member(#{ cite: "RFC 7591 section 2" })
  redirect_uris?: string[];

  @member(#{ cite: "RFC 7591 section 2" })
  token_endpoint_auth_method?: string;

  @member(#{ cite: "RFC 7591 section 2" })
  grant_types?: string[];

  @member(#{ cite: "RFC 7591 section 2" })
  response_types?: string[];

  @member(#{ cite: "RFC 7591 section 2" })
  client_name?: string;

  @member(#{ cite: "RFC 7591 section 2" })
  client_uri?: string;

  @member(#{ cite: "RFC 7591 section 2" })
  logo_uri?: string;

  @member(#{ cite: "RFC 7591 section 2" })
  scope?: string;

  @member(#{ cite: "RFC 7591 section 2" })
  contacts?: string[];

  @member(#{ cite: "RFC 7591 section 2" })
  tos_uri?: string;

  @member(#{ cite: "RFC 7591 section 2" })
  policy_uri?: string;

  @member(#{ cite: "RFC 7591 section 2" })
  jwks_uri?: string;

  @member(#{ cite: "RFC 7591 section 2" })
  jwks?: Record<unknown>;

  @member(#{ cite: "RFC 7591 section 2" })
  software_id?: string;

  @member(#{ cite: "RFC 7591 section 2" })
  software_version?: string;

  @member(#{ cite: "RFC 7591 section 2.3" })
  software_statement?: string;

  @member(#{ cite: "OpenID Connect Dynamic Client Registration 1.0 section 2" })
  application_type?: string;

  @member(#{ cite: "OpenID Connect Dynamic Client Registration 1.0 section 2" })
  sector_identifier_uri?: string;

  @member(#{ cite: "OpenID Connect Dynamic Client Registration 1.0 section 2" })
  subject_type?: string;

  @member(#{ cite: "OpenID Connect Dynamic Client Registration 1.0 section 2" })
  id_token_signed_response_alg?: string;

  @member(#{ cite: "OpenID Connect Dynamic Client Registration 1.0 section 2" })
  id_token_encrypted_response_alg?: string;

  @member(#{ cite: "OpenID Connect Dynamic Client Registration 1.0 section 2" })
  id_token_encrypted_response_enc?: string;

  @member(#{ cite: "OpenID Connect Dynamic Client Registration 1.0 section 2" })
  userinfo_signed_response_alg?: string;

  @member(#{ cite: "OpenID Connect Dynamic Client Registration 1.0 section 2" })
  userinfo_encrypted_response_alg?: string;

  @member(#{ cite: "OpenID Connect Dynamic Client Registration 1.0 section 2" })
  userinfo_encrypted_response_enc?: string;

  @member(#{ cite: "OpenID Connect Dynamic Client Registration 1.0 section 2" })
  request_object_signing_alg?: string;

  @member(#{ cite: "OpenID Connect Dynamic Client Registration 1.0 section 2" })
  request_object_encryption_alg?: string;

  @member(#{ cite: "OpenID Connect Dynamic Client Registration 1.0 section 2" })
  request_object_encryption_enc?: string;

  @member(#{ cite: "OpenID Connect Dynamic Client Registration 1.0 section 2" })
  token_endpoint_auth_signing_alg?: string;

  @member(#{ cite: "OpenID Connect Dynamic Client Registration 1.0 section 2" })
  default_max_age?: int64;

  @member(#{ cite: "OpenID Connect Dynamic Client Registration 1.0 section 2" })
  require_auth_time?: boolean;

  @member(#{ cite: "OpenID Connect Dynamic Client Registration 1.0 section 2" })
  default_acr_values?: string[];

  @member(#{ cite: "OpenID Connect Dynamic Client Registration 1.0 section 2" })
  initiate_login_uri?: string;

  @member(#{ cite: "OpenID Connect Dynamic Client Registration 1.0 section 2" })
  request_uris?: string[];

  @member(#{ cite: "OpenID Connect RP-Initiated Logout 1.0 section 3.1" })
  post_logout_redirect_uris?: string[];

  @member(#{ cite: "OpenID Connect Front-Channel Logout 1.0 section 2" })
  frontchannel_logout_uri?: string;

  @member(#{ cite: "OpenID Connect Front-Channel Logout 1.0 section 2" })
  frontchannel_logout_session_required?: boolean;

  @member(#{ cite: "OpenID Connect Back-Channel Logout 1.0 section 2.2" })
  backchannel_logout_uri?: string;

  @member(#{ cite: "OpenID Connect Back-Channel Logout 1.0 section 2.2" })
  backchannel_logout_session_required?: boolean;

  @member(#{ cite: "RFC 9701 section 6" })
  introspection_signed_response_alg?: string;

  @member(#{ cite: "RFC 9701 section 6" })
  introspection_encrypted_response_alg?: string;

  @member(#{ cite: "RFC 9701 section 6" })
  introspection_encrypted_response_enc?: string;

  @member(#{ cite: "JARM section 3" })
  authorization_signed_response_alg?: string;

  @member(#{ cite: "JARM section 3" })
  authorization_encrypted_response_alg?: string;

  @member(#{ cite: "JARM section 3" })
  authorization_encrypted_response_enc?: string;

  @member(#{ cite: "RFC 9101 section 10.5" })
  require_signed_request_object?: boolean;

  @member(#{ cite: "RFC 9126 section 6" })
  require_pushed_authorization_requests?: boolean;

  @member(#{ cite: "RFC 8705 section 3.4" })
  tls_client_certificate_bound_access_tokens?: boolean;

  @member(#{ cite: "RFC 8705 section 2.1.2" })
  tls_client_auth_subject_dn?: string;

  @member(#{ cite: "RFC 8705 section 2.1.2" })
  tls_client_auth_san_dns?: string;

  @member(#{ cite: "RFC 8705 section 2.1.2" })
  tls_client_auth_san_uri?: string;

  @member(#{ cite: "RFC 8705 section 2.1.2" })
  tls_client_auth_san_ip?: string;

  @member(#{ cite: "RFC 8705 section 2.1.2" })
  tls_client_auth_san_email?: string;

  @member(#{ cite: "OpenID Connect CIBA Core 1.0 section 4" })
  backchannel_token_delivery_mode?: string;

  @member(#{ cite: "OpenID Connect CIBA Core 1.0 section 4" })
  backchannel_client_notification_endpoint?: string;

  @member(#{ cite: "OpenID Connect CIBA Core 1.0 section 4" })
  backchannel_authentication_request_signing_alg?: string;

  @member(#{ cite: "OpenID Connect CIBA Core 1.0 section 4" })
  backchannel_user_code_parameter?: boolean;

  @member(#{ cite: "RFC 9396 section 10" })
  authorization_details_types?: string[];

  @member(#{ cite: "OpenID Provider Commands 1.0 section 3" })
  command_endpoint?: string;
}

/** The device authorization response. */
@members(#{ id: "device-authorization-response", cite: "RFC 8628 section 3.2", members: "closed" })
model DeviceAuthorizationResponse {
  @member(#{ cite: "RFC 8628 section 3.2" })
  device_code: string;

  @member(#{ cite: "RFC 8628 section 3.2" })
  user_code: string;

  @member(#{ cite: "RFC 8628 section 3.2" })
  verification_uri: string;

  @member(#{ cite: "RFC 8628 section 3.2" })
  verification_uri_complete?: string;

  @member(#{ cite: "RFC 8628 section 3.2" })
  expires_in: int64;

  @member(#{ cite: "RFC 8628 section 3.2" })
  interval?: int64;
}

/** The backchannel authentication response. */
@members(#{ id: "backchannel-authentication-response", cite: "OpenID Connect CIBA Core 1.0 section 7.3", members: "closed" })
model BackchannelAuthenticationResponse {
  @member(#{ cite: "OpenID Connect CIBA Core 1.0 section 7.3" })
  auth_req_id: string;

  @member(#{ cite: "OpenID Connect CIBA Core 1.0 section 7.3" })
  expires_in: int64;

  @member(#{ cite: "OpenID Connect CIBA Core 1.0 section 7.3" })
  interval?: int64;
}

/** The pushed authorization response. */
@members(#{ id: "pushed-authorization-response", cite: "RFC 9126 section 2.2", members: "closed" })
model PushedAuthorizationResponse {
  @member(#{ cite: "RFC 9126 section 2.2" })
  request_uri: string;

  @member(#{ cite: "RFC 9126 section 2.2" })
  expires_in: int64;
}

// ---------------------------------------------------------------------------
// THE CLAIM SETS OF WHAT THIS SERVICE ISSUES.
// ---------------------------------------------------------------------------

/** The ID Token. Configured custom claims and the scopes' claims ride along. */
@members(#{ id: "id-token", cite: "OpenID Connect Core 1.0 section 2", members: "open" })
model IdTokenClaims {
  @member(#{ cite: "OpenID Connect Core 1.0 section 2" })
  iss: string;

  @member(#{ cite: "OpenID Connect Core 1.0 section 2" })
  sub: string;

  @member(#{ cite: "OpenID Connect Core 1.0 section 2" })
  aud: string | string[];

  @member(#{ cite: "OpenID Connect Core 1.0 section 2" })
  exp: int64;

  @member(#{ cite: "OpenID Connect Core 1.0 section 2" })
  iat: int64;

  @member(#{ cite: "OpenID Connect Core 1.0 section 2" })
  auth_time?: int64;

  @member(#{ cite: "OpenID Connect Core 1.0 section 2" })
  nonce?: string;

  @member(#{ cite: "OpenID Connect Core 1.0 section 2" })
  acr?: string;

  @member(#{ cite: "OpenID Connect Core 1.0 section 2" })
  amr?: string[];

  @member(#{ cite: "OpenID Connect Core 1.0 section 2" })
  azp?: string;

  @member(#{ cite: "OpenID Connect Core 1.0 section 3.1.3.6" })
  at_hash?: string;

  @member(#{ cite: "OpenID Connect Core 1.0 section 3.3.2.11" })
  c_hash?: string;

  @member(#{ cite: "FAPI 1.0 Part 2 section 5.1" })
  s_hash?: string;

  @member(#{ cite: "OpenID Connect Front-Channel Logout 1.0 section 3" })
  sid?: string;

  @member(#{ cite: "RFC 7519 section 4.1.7" })
  jti?: string;

  @member(#{ cite: "RFC 7519 section 4.1.5" })
  nbf?: int64;

  @member(#{ cite: "OpenID Connect Native SSO for Mobile Apps 1.0 section 4.1" })
  ds_hash?: string;
}

/** The JWT access token. Configured custom claims ride along. */
@members(#{ id: "access-token", cite: "RFC 9068 section 2.2", members: "open" })
model AccessTokenClaims {
  @member(#{ cite: "RFC 9068 section 2.2" })
  iss: string;

  @member(#{ cite: "RFC 9068 section 2.2" })
  exp: int64;

  @member(#{ cite: "RFC 9068 section 2.2" })
  aud: string | string[];

  @member(#{ cite: "RFC 9068 section 2.2" })
  sub: string;

  @member(#{ cite: "RFC 9068 section 2.2" })
  client_id: string;

  @member(#{ cite: "RFC 9068 section 2.2" })
  iat: int64;

  @member(#{ cite: "RFC 9068 section 2.2" })
  jti: string;

  @member(#{ cite: "RFC 7519 section 4.1.5" })
  nbf?: int64;

  @member(#{ cite: "RFC 9068 section 2.2.3" })
  scope?: string;

  @member(#{ cite: "RFC 9068 section 2.2.1" })
  auth_time?: int64;

  @member(#{ cite: "RFC 9068 section 2.2.1" })
  acr?: string;

  @member(#{ cite: "RFC 9068 section 2.2.1" })
  amr?: string[];

  @member(#{ cite: "RFC 7800 section 3.1; RFC 9449 section 6.1; RFC 8705 section 3.1" })
  cnf?: Record<unknown>;

  @member(#{ cite: "RFC 9396 section 9.1" })
  authorization_details?: unknown[];

  @member(#{ cite: "RFC 8693 section 4.1" })
  act?: Record<unknown>;

  @member(#{ cite: "RFC 8693 section 4.4" })
  may_act?: Record<unknown>;

  @member(#{ cite: "Token Status List section 6.1" })
  status?: Record<unknown>;

  @member(#{ cite: "OpenID Connect Front-Channel Logout 1.0 section 3" })
  sid?: string;
}

/** The back-channel Logout Token. */
@members(#{ id: "logout-token", cite: "OpenID Connect Back-Channel Logout 1.0 section 2.4", members: "closed" })
model LogoutTokenClaims {
  @member(#{ cite: "OpenID Connect Back-Channel Logout 1.0 section 2.4" })
  iss: string;

  @member(#{ cite: "OpenID Connect Back-Channel Logout 1.0 section 2.4" })
  sub?: string;

  @member(#{ cite: "OpenID Connect Back-Channel Logout 1.0 section 2.4" })
  aud: string | string[];

  @member(#{ cite: "OpenID Connect Back-Channel Logout 1.0 section 2.4" })
  iat: int64;

  @member(#{ cite: "OpenID Connect Back-Channel Logout 1.0 section 2.4" })
  exp: int64;

  @member(#{ cite: "OpenID Connect Back-Channel Logout 1.0 section 2.4" })
  jti: string;

  @member(#{ cite: "OpenID Connect Back-Channel Logout 1.0 section 2.4" })
  events: Record<unknown>;

  @member(#{ cite: "OpenID Connect Back-Channel Logout 1.0 section 2.4" })
  sid?: string;
}

/** The JWT introspection response's claims. */
@members(#{ id: "introspection-jwt", cite: "RFC 9701 section 5", members: "closed" })
model IntrospectionJwtClaims {
  @member(#{ cite: "RFC 9701 section 5" })
  iss: string;

  @member(#{ cite: "RFC 9701 section 5" })
  aud: string | string[];

  @member(#{ cite: "RFC 9701 section 5" })
  iat: int64;

  @member(#{ cite: "RFC 9701 section 5" })
  token_introspection: Record<unknown>;
}

// ---------------------------------------------------------------------------
// THE ERROR CODES: every `error` the authorization server and OpenID
// provider send, with the document that defines it.
// ---------------------------------------------------------------------------

@errorCodes
model ErrorCodes {
  @errorCode(#{ cite: "RFC 6749 section 5.2" }) invalid_request: string;
  @errorCode(#{ cite: "RFC 6749 section 5.2" }) invalid_client: string;
  @errorCode(#{ cite: "RFC 6749 section 5.2" }) invalid_grant: string;
  @errorCode(#{ cite: "RFC 6749 section 5.2" }) unauthorized_client: string;
  @errorCode(#{ cite: "RFC 6749 section 5.2" }) unsupported_grant_type: string;
  @errorCode(#{ cite: "RFC 6749 section 5.2" }) invalid_scope: string;
  @errorCode(#{ cite: "RFC 6749 section 4.1.2.1" }) access_denied: string;
  @errorCode(#{ cite: "RFC 6749 section 4.1.2.1" }) unsupported_response_type: string;
  @errorCode(#{ cite: "RFC 6749 section 4.1.2.1" }) server_error: string;
  @errorCode(#{ cite: "RFC 6749 section 4.1.2.1" }) temporarily_unavailable: string;
  @errorCode(#{ cite: "RFC 6750 section 3.1" }) invalid_token: string;
  @errorCode(#{ cite: "RFC 6750 section 3.1" }) insufficient_scope: string;
  @errorCode(#{ cite: "RFC 7009 section 2.2.1" }) unsupported_token_type: string;
  @errorCode(#{ cite: "RFC 7591 section 3.2.2" }) invalid_redirect_uri: string;
  @errorCode(#{ cite: "RFC 7591 section 3.2.2" }) invalid_client_metadata: string;
  @errorCode(#{ cite: "RFC 7591 section 3.2.2" }) invalid_software_statement: string;
  @errorCode(#{ cite: "RFC 7591 section 3.2.2" }) unapproved_software_statement: string;
  @errorCode(#{ cite: "RFC 8628 section 3.5" }) authorization_pending: string;
  @errorCode(#{ cite: "RFC 8628 section 3.5" }) slow_down: string;
  @errorCode(#{ cite: "RFC 8628 section 3.5" }) expired_token: string;
  @errorCode(#{ cite: "RFC 8707 section 2" }) invalid_target: string;
  @errorCode(#{ cite: "RFC 9101 section 6.3" }) invalid_request_object: string;
  @errorCode(#{ cite: "RFC 9101 section 6.3" }) invalid_request_uri: string;
  @errorCode(#{ cite: "OpenID Connect Core 1.0 section 3.1.2.6" }) request_not_supported: string;
  @errorCode(#{ cite: "OpenID Connect Core 1.0 section 3.1.2.6" }) request_uri_not_supported: string;
  @errorCode(#{ cite: "OpenID Connect Core 1.0 section 3.1.2.6" }) registration_not_supported: string;
  @errorCode(#{ cite: "OpenID Connect Core 1.0 section 3.1.2.6" }) interaction_required: string;
  @errorCode(#{ cite: "OpenID Connect Core 1.0 section 3.1.2.6" }) login_required: string;
  @errorCode(#{ cite: "OpenID Connect Core 1.0 section 3.1.2.6" }) account_selection_required: string;
  @errorCode(#{ cite: "OpenID Connect Core 1.0 section 3.1.2.6" }) consent_required: string;
  @errorCode(#{ cite: "RFC 9396 section 5" }) invalid_authorization_details: string;
  @errorCode(#{ cite: "RFC 9449 section 12.2" }) invalid_dpop_proof: string;
  @errorCode(#{ cite: "RFC 9449 section 8" }) use_dpop_nonce: string;
  @errorCode(#{ cite: "RFC 9470 section 3" }) insufficient_user_authentication: string;
  @errorCode(#{ cite: "OpenID Connect CIBA Core 1.0 section 13" }) expired_login_hint_token: string;
  @errorCode(#{ cite: "OpenID Connect CIBA Core 1.0 section 13" }) unknown_user_id: string;
  @errorCode(#{ cite: "OpenID Connect CIBA Core 1.0 section 13" }) missing_user_code: string;
  @errorCode(#{ cite: "OpenID Connect CIBA Core 1.0 section 13" }) invalid_user_code: string;
  @errorCode(#{ cite: "OpenID Connect CIBA Core 1.0 section 13" }) invalid_binding_message: string;
  @errorCode(#{ cite: "OpenID Connect CIBA Core 1.0 section 11" }) transaction_failed: string;
  @errorCode(#{ cite: "Grant Management for OAuth 2.0 section 5.4" }) invalid_grant_id: string;
  @errorCode(#{ cite: "Grant Management for OAuth 2.0 section 6 (a grant that does not exist is a 404)" }) not_found: string;
  @errorCode(#{ cite: "OAuth 2.0 Attestation-Based Client Authentication section 6.2" }) use_attestation_challenge: string;
  @errorCode(#{ cite: "OAuth 2.0 Attestation-Based Client Authentication section 6.2" }) use_fresh_attestation: string;
  @errorCode(#{ cite: "OpenID Connect Core Unmet Authentication Requirements 1.0 section 2" }) unmet_authentication_requirements: string;
}
