// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/oauth/oauth.tsp
//
// Written by hand (#1579). THE SOURCE OF WHAT THE OAUTH 2.0 AUTHORIZATION
// SERVER AND OPENID PROVIDER TAKE AND ANSWER: every endpoint's request
// parameters, the members of the two discovery documents and of every
// answer, the error codes, and the claim sets of what this service issues.
// `models/tools/generate.mjs` compiles it into `models/generated/oauth.json`
// during the image build. `oauth-oidc/oauth_model.ts` builds each
// endpoint's request validator from that file — the hand-written zod
// schemas in `oauth2.ts` and `consent_screen.ts` are gone — and holds what
// the endpoints answer to the member sets.
//
// THE MODEL DESCRIBES AND VALIDATES THE WIRE; IT DOES NOT RESHAPE IT. Every
// bound below is the one the hand-written schema had, in the order it had
// them, because the order decides which refusal a request with two bad
// parameters gets; `tests/oauth_model_wire.js` holds 412 answers to what the
// hand-written version said. A change here is a change to what a client
// sees, and owes that snapshot.
//
// A parameter's TypeSpec type says whether it is required (not optional),
// may repeat (an array) and is a number (an integer type); `@param` says the
// shared type of `common/validation.js` it is checked as, its bounds and
// whether an empty value counts as none (`empty`, which is
// `validation.types.opt()`). What needs the client's registration or the
// realm's mode — which parameters a client may send, what RFC 9700 mode,
// OAuth 2.1 mode or a FAPI profile requires — stays in the code, and
// `oauth-oidc/CLAUDE.md`, *THE REQUEST SHAPES ARE THE MODEL'S*, says where.

import "../lib/oauth_lib.tsp";

using IyaSts.OAuthLib;

namespace IyaSts.OAuth;

// ---------------------------------------------------------------------------
// THE REQUESTS.
// ---------------------------------------------------------------------------

/**
 * The authorization request. Undeclared parameters pass through: the
 * request is forwarded whole across the consent round trip
 * (`queryString()`) and into RFC 9700 mode's checks, so a parameter dropped
 * here would vanish from the request a person resumes. PAR's body is
 * checked against it too, as the authorization request it is.
 */
@endpoint(#{
  id: "authorize",
  paths: #["/oauth2/authorize", "/oauth2/par"],
  methods: #["GET", "POST"],
  input: "query",
  passThrough: true,
  cite: "RFC 6749 section 4.1.1; OpenID Connect Core 1.0 section 3.1.2.1"
})
model AuthorizationRequest {
  @param(#{ kind: "identifier", empty: true, cite: "RFC 6749 section 4.1.1" })
  client_id?: string;

  @param(#{ maxLength: 128, cite: "RFC 6749 section 3.1.1" })
  response_type?: string;

  @param(#{ kind: "redirectUri", empty: true,
            cite: "RFC 6749 section 3.1.2" })
  redirect_uri?: string;

  @param(#{ kind: "scope", empty: true, cite: "RFC 6749 section 3.3" })
  scope?: string;

  @param(#{ kind: "opaque", empty: true, cite: "RFC 6749 section 4.1.1" })
  state?: string;

  @param(#{ kind: "opaque", empty: true,
            cite: "OpenID Connect Core 1.0 section 3.1.2.1" })
  nonce?: string;

  @param(#{ maxLength: 64,
            cite: "OAuth 2.0 Multiple Response Type Encoding Practices section 2.1" })
  response_mode?: string;

  @param(#{ maxLength: 128,
            cite: "OpenID Connect Core 1.0 section 3.1.2.1" })
  prompt?: string;

  @param(#{ maxLength: 64, cite: "OpenID Connect Core 1.0 section 3.1.2.1" })
  display?: string;

  @param(#{ kind: "integer", minimum: 0, maximum: 315360000, empty: true,
            cite: "OpenID Connect Core 1.0 section 3.1.2.1" })
  max_age?: int32;

  @param(#{ maxLength: 256,
            cite: "OpenID Connect Core 1.0 section 3.1.2.1" })
  ui_locales?: string;

  /** Accepted and recorded (#118); see claims_locales_supported. */
  @param(#{ maxLength: 256, cite: "OpenID Connect Core 1.0 section 5.2" })
  claims_locales?: string;

  @param(#{ cap: "TOKEN", cite: "OpenID Connect Core 1.0 section 3.1.2.1" })
  id_token_hint?: string;

  @param(#{ kind: "name", empty: true,
            cite: "OpenID Connect Core 1.0 section 3.1.2.1" })
  login_hint?: string;

  /** A domain for home-realm discovery (#148). */
  @param(#{ maxLength: 253, pattern: "^[A-Za-z0-9.-]+$",
            cite: "OpenID Connect Enterprise Extensions 1.0 section 3" })
  domain_hint?: string;

  /** The tenant the client means: a trust realm's id here (#148). */
  @param(#{ maxLength: 64,
            cite: "OpenID Connect Enterprise Extensions 1.0 section 3" })
  tenant?: string;

  @param(#{ maxLength: 512,
            cite: "OpenID Connect Core 1.0 section 3.1.2.1" })
  acr_values?: string;

  /**
   * Bounded here rather than at the token endpoint too, because a challenge
   * stored now is compared much later.
   */
  @param(#{ minLength: 43, maxLength: 128, empty: true,
            cite: "RFC 7636 section 4.2" })
  code_challenge?: string;

  @param(#{ maxLength: 16, cite: "RFC 7636 section 4.3" })
  code_challenge_method?: string;

  @param(#{ cap: "TEXT", cite: "OpenID Connect Core 1.0 section 5.5" })
  claims?: string;

  /** This service's own per-claim spelling of a claims request. */
  @param(#{ maxLength: 256, cite: "this service's own (oauth2.ts, parseClaimsRequest())" })
  claim?: string[];

  /** MAY be repeated, which is what `repeatable` exists for. */
  @param(#{ kind: "uri", cite: "RFC 8707 section 2" })
  resource?: string[];

  @param(#{ kind: "base64url", empty: true, cite: "RFC 9449 section 10" })
  dpop_jkt?: string;

  @param(#{ cap: "TEXT", cite: "RFC 9396 section 2" })
  authorization_details?: string;

  @param(#{ maxLength: 128, cite: "Grant Management for OAuth 2.0 section 4.1" })
  grant_id?: string;

  @param(#{ maxLength: 16, cite: "Grant Management for OAuth 2.0 section 4.1" })
  grant_management_action?: string;

  @param(#{ kind: "opaque", empty: true,
            cite: "OpenID for Verifiable Credential Issuance 1.0 section 5.1.3" })
  issuer_state?: string;

  /**
   * This service's own round-trip fields, put in the URL by its own screens
   * and read back here; bounded like everything else, and trusted for
   * nothing.
   */
  @param(#{ maxLength: 256, cite: "this service's own (the sign-in screen)" })
  authn_error?: string;

  @param(#{ maxLength: 1024,
            cite: "this service's own (the sign-in screen)" })
  authn_error_description?: string;

  @param(#{ maxLength: 256,
            cite: "this service's own (the consent screen)" })
  consent_error?: string;

  @param(#{ maxLength: 1024,
            cite: "this service's own (the consent screen)" })
  consent_error_description?: string;

  /** The request object's `prompt` was honoured on the first pass. */
  @param(#{ maxLength: 8, cite: "this service's own (RFC 9101, authorizationReturnQuery())" })
  jar_prompt_honoured?: string;

  /** The sign-in a step-up sent this request to has happened. */
  @param(#{ maxLength: 8, cite: "this service's own (RFC 9470, step_up.ts)" })
  step_up_honoured?: string;

  @param(#{ cap: "TEXT", cite: "RFC 9101 section 4" })
  request?: string;

  @param(#{ maxLength: 2048, cite: "RFC 9101 section 4; RFC 9126 section 4" })
  request_uri?: string;
}

/**
 * A claims request sent to the UserInfo endpoint itself: this service's own
 * debugging aid, a union with the token's request and never a replacement.
 */
@endpoint(#{
  id: "userinfo-claims",
  paths: #["/oauth2/userinfo"],
  methods: #["GET", "POST"],
  input: "query",
  passThrough: true,
  cite: "this service's own (OpenID Connect Core 1.0 section 5.5's structure, at section 5.3)"
})
model UserInfoClaimsRequest {
  @param(#{ cap: "TEXT", cite: "OpenID Connect Core 1.0 section 5.5" })
  claims?: string;

  @param(#{ maxLength: 256, cite: "this service's own (oauth2.ts, parseClaimsRequest())" })
  claim?: string[];
}

/**
 * The token request, every grant's parameters in one form. Undeclared
 * parameters pass through into the libraries that read them (OpenID4VCI's
 * `pre-authorized_code`, RFC 8628's `device_code`). `resource` is single
 * here: a repeat is read off the raw body by `bodyValues()`.
 */
@endpoint(#{
  id: "token",
  paths: #["/oauth2/token"],
  methods: #["POST"],
  input: "body",
  passThrough: true,
  cite: "RFC 6749 section 3.2"
})
model TokenRequest {
  @param(#{ maxLength: 128, cite: "RFC 6749 section 4.1.3" })
  grant_type?: string;

  @param(#{ kind: "identifier", empty: true, cite: "RFC 6749 section 2.3.1" })
  client_id?: string;

  @param(#{ maxLength: 1024, cite: "RFC 6749 section 2.3.1" })
  client_secret?: string;

  @param(#{ kind: "opaque", empty: true, cite: "RFC 6749 section 4.1.3" })
  code?: string;

  @param(#{ minLength: 43, maxLength: 128, empty: true,
            cite: "RFC 7636 section 4.1" })
  code_verifier?: string;

  @param(#{ kind: "redirectUri", empty: true,
            cite: "RFC 6749 section 4.1.3" })
  redirect_uri?: string;

  @param(#{ kind: "opaque", empty: true, cite: "RFC 6749 section 6" })
  refresh_token?: string;

  @param(#{ kind: "scope", empty: true, cite: "RFC 6749 section 3.3" })
  scope?: string;

  @param(#{ kind: "name", empty: true, cite: "RFC 6749 section 4.3.2" })
  username?: string;

  @param(#{ maxLength: 1024, cite: "RFC 6749 section 4.3.2" })
  password?: string;

  @param(#{ cap: "TEXT", cite: "RFC 8693 section 2.1" })
  subject_token?: string;

  @param(#{ kind: "uri", empty: true, cite: "RFC 8693 section 2.1" })
  subject_token_type?: string;

  @param(#{ cap: "TEXT", cite: "RFC 8693 section 2.1" })
  actor_token?: string;

  @param(#{ kind: "uri", empty: true, cite: "RFC 8693 section 2.1" })
  actor_token_type?: string;

  @param(#{ kind: "uri", empty: true, cite: "RFC 8693 section 2.1" })
  requested_token_type?: string;

  @param(#{ cap: "URI", cite: "RFC 8693 section 2.1" })
  audience?: string;

  /**
   * This service's extension to RFC 8693 (#186): `delegation` or
   * `impersonation`, checked in the branch, where a refusal can say why.
   */
  @param(#{ maxLength: 32, cite: "this service's own (#186)" })
  exchange_semantics?: string;

  @param(#{ maxLength: 512, cite: "OpenID Connect Native SSO for Mobile Apps 1.0 section 3.3" })
  device_secret?: string;

  @param(#{ maxLength: 256, cite: "OpenID Connect CIBA Core 1.0 section 10.1" })
  auth_req_id?: string;

  @param(#{ cap: "URI", cite: "RFC 8707 section 2" })
  resource?: string;

  @param(#{ maxLength: 64,
            cite: "OpenID for Verifiable Credential Issuance 1.0 section 6.1" })
  tx_code?: string;

  @param(#{ cap: "TEXT", cite: "RFC 9396 section 6" })
  authorization_details?: string;

  @param(#{ cap: "TEXT", cite: "RFC 7521 section 4.2; RFC 7523 section 2.2" })
  client_assertion?: string;

  @param(#{ kind: "uri", empty: true, cite: "RFC 7521 section 4.2" })
  client_assertion_type?: string;

  /**
   * The assertion GRANT's own parameter: who the token is FOR, where
   * `client_assertion` says who is calling.
   */
  @param(#{ cap: "TEXT", cite: "RFC 7521 section 4.1" })
  assertion?: string;
}

/**
 * The introspection request. The hint is any short string: a server that
 * cannot locate the token by it searches every type (#1196).
 */
@endpoint(#{
  id: "introspect",
  paths: #["/oauth2/introspect"],
  methods: #["POST"],
  input: "body",
  passThrough: true,
  cite: "RFC 7662 section 2.1"
})
model IntrospectionRequest {
  @param(#{ cap: "TEXT", cite: "RFC 7662 section 2.1" })
  token?: string;

  @param(#{ maxLength: 256, cite: "RFC 7662 section 2.1" })
  token_type_hint?: string;

  @param(#{ kind: "identifier", empty: true, cite: "RFC 6749 section 2.3.1" })
  client_id?: string;

  @param(#{ maxLength: 1024, cite: "RFC 6749 section 2.3.1" })
  client_secret?: string;
}

/** What a device sends besides its client authentication. */
@endpoint(#{
  id: "device-authorization",
  paths: #["/oauth2/device_authorization"],
  methods: #["POST"],
  input: "body",
  passThrough: true,
  cite: "RFC 8628 section 3.1"
})
model DeviceAuthorizationRequest {
  @param(#{ kind: "scope", empty: true, cite: "RFC 8628 section 3.1" })
  scope?: string;
}

/**
 * The Backchannel Authentication Endpoint's form. A `request` carries every
 * other member signed instead.
 */
@endpoint(#{
  id: "bc-authorize",
  paths: #["/oauth2/bc-authorize"],
  methods: #["POST"],
  input: "body",
  passThrough: true,
  cite: "OpenID Connect CIBA Core 1.0 section 7.1"
})
model BackchannelAuthenticationRequest {
  @param(#{ kind: "scope", empty: true,
            cite: "OpenID Connect CIBA Core 1.0 section 7.1" })
  scope?: string;

  @param(#{ maxLength: 1024,
            cite: "OpenID Connect CIBA Core 1.0 section 7.1" })
  client_notification_token?: string;

  @param(#{ maxLength: 1024,
            cite: "OpenID Connect CIBA Core 1.0 section 7.1" })
  acr_values?: string;

  @param(#{ cap: "TEXT", cite: "OpenID Connect CIBA Core 1.0 section 7.1" })
  login_hint_token?: string;

  @param(#{ cap: "TEXT", cite: "OpenID Connect CIBA Core 1.0 section 7.1" })
  id_token_hint?: string;

  @param(#{ maxLength: 256,
            cite: "OpenID Connect CIBA Core 1.0 section 7.1" })
  login_hint?: string;

  @param(#{ maxLength: 1024,
            cite: "OpenID Connect CIBA Core 1.0 section 7.1" })
  binding_message?: string;

  @param(#{ maxLength: 256,
            cite: "OpenID Connect CIBA Core 1.0 section 7.1" })
  user_code?: string;

  @param(#{ maxLength: 16,
            cite: "OpenID Connect CIBA Core 1.0 section 7.1" })
  requested_expiry?: string;

  @param(#{ cap: "TEXT", cite: "OpenID Connect CIBA Core 1.0 section 7.1.1" })
  request?: string;

  /** A JSON object, as its text in a form (#142). */
  @param(#{ maxLength: 4096, cite: "FAPI-CIBA section 5.3" })
  request_context?: string;

  @param(#{ maxLength: 128, cite: "Grant Management for OAuth 2.0 section 4.1" })
  grant_id?: string;

  @param(#{ maxLength: 16, cite: "Grant Management for OAuth 2.0 section 4.1" })
  grant_management_action?: string;

  @param(#{ kind: "identifier", empty: true, cite: "RFC 6749 section 2.3.1" })
  client_id?: string;

  @param(#{ maxLength: 1024, cite: "RFC 6749 section 2.3.1" })
  client_secret?: string;
}

/**
 * The revocation request. `token` stays optional to the validator so that
 * its absence is answered by name (`STS-OAUTH-0608`), and an unknown hint
 * is ignored rather than refused (section 2.1, #102).
 */
@endpoint(#{
  id: "revoke",
  paths: #["/oauth2/revoke"],
  methods: #["POST"],
  input: "body",
  passThrough: true,
  cite: "RFC 7009 section 2.1"
})
model RevocationRequest {
  @param(#{ cap: "TEXT", cite: "RFC 7009 section 2.1" })
  token?: string;

  @param(#{ maxLength: 256, cite: "RFC 7009 section 2.1" })
  token_type_hint?: string;

  @param(#{ kind: "identifier", empty: true, cite: "RFC 6749 section 2.3.1" })
  client_id?: string;

  @param(#{ maxLength: 1024, cite: "RFC 6749 section 2.3.1" })
  client_secret?: string;
}

/**
 * RP-Initiated Logout. `post_logout_redirect_uri` is a `redirectUri`
 * because it is an address a BROWSER is sent to.
 */
@endpoint(#{
  id: "logout",
  paths: #["/oauth2/logout"],
  methods: #["GET", "POST"],
  input: "query",
  passThrough: true,
  cite: "OpenID Connect RP-Initiated Logout 1.0 section 2"
})
model LogoutRequest {
  @param(#{ kind: "redirectUri", empty: true,
            cite: "OpenID Connect RP-Initiated Logout 1.0 section 2" })
  post_logout_redirect_uri?: string;

  @param(#{ kind: "identifier", empty: true,
            cite: "OpenID Connect RP-Initiated Logout 1.0 section 2" })
  client_id?: string;

  @param(#{ cap: "TOKEN",
            cite: "OpenID Connect RP-Initiated Logout 1.0 section 2" })
  id_token_hint?: string;

  @param(#{ kind: "opaque", empty: true,
            cite: "OpenID Connect RP-Initiated Logout 1.0 section 2" })
  state?: string;

  @param(#{ maxLength: 256,
            cite: "OpenID Connect RP-Initiated Logout 1.0 section 2" })
  logout_hint?: string;

  @param(#{ maxLength: 256,
            cite: "OpenID Connect RP-Initiated Logout 1.0 section 2" })
  ui_locales?: string;
}

/**
 * What a push carries besides the authorization request, which is then
 * checked against `AuthorizationRequest`.
 */
@endpoint(#{
  id: "par",
  paths: #["/oauth2/par"],
  methods: #["POST"],
  input: "body",
  passThrough: true,
  cite: "RFC 9126 section 2.1"
})
model PushedAuthorizationRequest {
  @param(#{ kind: "identifier", empty: true, cite: "RFC 9126 section 2.1" })
  client_id?: string;

  @param(#{ maxLength: 1024, cite: "RFC 6749 section 2.3.1" })
  client_secret?: string;

  @param(#{ cap: "TEXT", cite: "RFC 7523 section 2.2" })
  client_assertion?: string;

  @param(#{ kind: "uri", empty: true, cite: "RFC 7521 section 4.2" })
  client_assertion_type?: string;

  /** A request object pushed by value. */
  @param(#{ cap: "TEXT", cite: "RFC 9126 section 3" })
  request?: string;

  /** "MUST NOT be provided": bounded so the refusal can quote it. */
  @param(#{ cap: "URI", cite: "RFC 9126 section 2.1" })
  request_uri?: string;
}

/** The client a registration access token manages. */
@endpoint(#{
  id: "registered-client",
  paths: #["/oauth2/register/{client_id}"],
  methods: #["GET", "PUT", "DELETE"],
  input: "params",
  passThrough: false,
  cite: "RFC 7592 section 2"
})
model RegisteredClientPath {
  @param(#{ kind: "identifier", cite: "RFC 7592 section 2" })
  client_id: string;
}

/** The path component that names an authorization server (`forProfile()`). */
@endpoint(#{
  id: "authorization-server",
  paths: #["/{as}/oauth2/token"],
  methods: #["GET", "POST"],
  input: "params",
  passThrough: false,
  cite: "RFC 8414 section 3.1"
})
model AuthorizationServerPath {
  @param(#{ kind: "identifier", empty: true, cite: "RFC 8414 section 3.1" })
  `as`?: string;
}

/** The consent screen's own round trip (`consent_screen.ts`). */
@endpoint(#{
  id: "consent",
  paths: #["/oauth2/consent"],
  methods: #["GET", "POST"],
  input: "query",
  passThrough: false,
  cite: "this service's own (the consent screen, #576)"
})
model ConsentQuery {
  @param(#{ kind: "base64url", empty: true,
            cite: "this service's own (the consent screen, #576)" })
  consent?: string;
}
