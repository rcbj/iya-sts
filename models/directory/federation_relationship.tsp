// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/directory/federation_relationship.tsp
//
// Written by hand (#1390). THIS IS THE SOURCE of this object's table:
// `models/tools/generate.mjs` compiles it during the image build and `federation/federation.js`
// reads the result. The comments are the ones that sat on these rows there.

import "../lib/model_lib.tsp";

using IyaSts.ModelLib;

namespace IyaSts.Directory;

@entry(#{
  id: "federationRelationship",
  lists: #{
    subjectPolicies: #["link-at-first-sign-in", "pre-linked", "jit-namespaced", "any-existing"],
    classicalKeyTypes: #["rsa-3072", "ec-p256"],
    joseOnlyKeyTypes: #["x-wing", "ml-kem-768"],
    xmlKeyManagement: #["rsa-oaep", "ecdh-es"],
    joseKeyManagement: #["RSA-OAEP-256", "RSA-OAEP", "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A256KW", "HPKE-10-KE", "ML-KEM-768"],
    xmlContentEncryption: #["aes256-gcm", "aes128-gcm"],
    joseContentEncryption: #["A256GCM", "A128GCM"],
    mechanisms: #["password", "password-mfa", "webauthn", "federation", "spnego", "wallet"]
  },
  source: "../federation/federation",
  container: "ou=federations",
  ownContainer: false,
  authored: true,
  objectClasses: #[
    #{
      name: "top",
      where: "RFC 4512",
      standard: true,
      what: "The abstract class every entry carries."
    },
    #{
      name: "applicationProcess",
      where: "RFC 4519 section 3.3",
      standard: true,
      what: "The same registered class ou=applications uses, and for the same reason: it is the one that fits a party in a protocol at all, and it brings cn, description, seeAlso, ou and l with it."
    },
    #{
      name: "stsFederation",
      where: "this service",
      standard: false,
      what: "INVENTED. No registered LDAP schema has a federation partner, because every product that stores one (AD FS, Shibboleth, Keycloak, Ping) keeps it in its own database. These are this service's own names in the way stsApplication's already are."
    }
  ]
})
model FederationRelationship {
  // --- identity ---------------------------------------------------------
  @attr(#{
    kind: "single",
    role: "both",
    from: "this register",
    what: "THE KEY: a short name an operator chose, unique across both roles. It is the RDN as well, unlike an application's, because this register is CONFIGURED rather than observed — nobody has to accept whatever a protocol presented, so the id can simply be required to be RDN-safe and short."
  })
  fedId?: string;
  @attr(#{
    kind: "single",
    role: "both",
    standard: true,
    from: "this register",
    what: "The RDN value, equal to fedId. Unlike an application entry there is no digest case here: an id that would not fit is refused at creation rather than hashed."
  })
  cn?: string;
  @attr(#{
    kind: "single",
    role: "both",
    from: "this register",
    what: "What to call the partner on a page. The id is the name when none is given, because inventing a friendly name would be inventing a fact."
  })
  fedName?: string;
  @attr(#{
    kind: "single",
    role: "both",
    from: "this register",
    what: "WHICH END THIS SERVICE IS: service-provider (it consumes) or identity-provider (it asserts). One relationship is one direction — see the header."
  })
  fedRole?: string;
  @attr(#{
    kind: "single",
    role: "both",
    from: "this register",
    what: "One of saml2, saml11, wsfed, oidc, oauth2 — the five sign-in protocols — or ssf, a partner that only sends Shared Signals and signs nobody in."
  })
  fedProtocol?: string;
  // A CONSUMER PROVIDER (#565): the profile this relationship was made
  // from, and so its category. See consumer_providers.ts.
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    what: "THE CONSUMER OR SOCIAL PROVIDER THIS RELATIONSHIP IS (google, discord, github, generic-oidc, generic-oauth2), or empty for an enterprise partner. Set when the relationship is created and never changed: the provider's profile wrote its endpoints onto this entry then, and supplies at every sign-in where the subject, the address and its verification come from. A relationship naming a provider is in the consumer category, which a realm turns on with federation.consumerProviders."
  })
  fedProvider?: string;
  @attr(#{
    kind: "single",
    role: "both",
    from: "this register",
    what: "THE PARTNER'S OWN IDENTIFIER, in whatever its protocol calls it: a SAML entityID, an OpenID Connect issuer, a WS-Federation wtrealm. On a service-provider-side relationship it is CHECKED — an assertion whose Issuer is not this string is refused — which is why it is not merely documentation, and since 2026-09-12 it is REQUIRED there: a relationship without it is not fully configured."
  })
  fedPeer?: string;
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    what: "WHAT THIS SERVICE IS CALLED TO THIS PARTNER, when that is not the name this service derives. Empty — the default — derives it from the base URL the browser reached this service at (<base>/federation/acs/<id>, which global.publicBaseUrl pins). Set it to the entityID the partner was configured with: it becomes the Issuer of the outbound AuthnRequest, the WS-Federation wtrealm, the SAML 1.1 providerId, this relationship's SP metadata entityID, and the audience an inbound assertion must name — which is a REFUSAL since 2026-09-12, so a partner that knows this service by another name needs this set. The assertion consumer URL stays derived, because it is an address a browser must be able to reach."
  })
  fedLocalEntityId?: string;
  @attr(#{
    kind: "single",
    role: "both",
    from: "this register",
    what: "TRUE/FALSE. A relationship is created DISABLED and nothing about it does anything until it is turned on: a half-configured partner that silently accepted assertions would be the failure this whole register exists to prevent."
  })
  fedEnabled?: string;
  @attr(#{
    kind: "multi",
    role: "both",
    standard: true,
    from: "this register",
    what: "One line per thing that has happened to this relationship."
  })
  description?: string[];
  // --- the service provider half: what this service CONSUMES ------------
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    what: "WHERE THE BROWSER IS SENT. The partner's SAML Single Sign-On service, its SAML 1.1 inter-site transfer service, its WS-Federation passive endpoint, or its OAuth 2.0 authorization endpoint. Required in every protocol, because a relationship with nowhere to send anybody cannot begin."
  })
  fedSsoUrl?: string;
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    what: "The partner's token endpoint, for the authorization code flow. THIS IS ONE OF THE TWO URLS THIS SERVICE WILL ACTUALLY DIAL — see federation_http.js, which is the only outbound request in this repository and argues why a configured URL is a different thing from a registered one."
  })
  fedTokenUrl?: string;
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    what: "The partner's UserInfo endpoint, or any endpoint that answers JSON about the bearer of an access token. OPTIONAL for OIDC, where the ID Token usually carries enough, and the ONLY source of attributes for a plain OAuth 2.0 partner whose access token is opaque. The second URL this service will dial."
  })
  fedUserinfoUrl?: string;
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    what: "The partner's JWKS. FETCHED — which is the exact opposite of what oauthJwksUri on an application entry does, and the difference is the whole argument in federation_http.js: that one is a URL an unauthenticated caller REGISTERED, this one is a URL an administrator CONFIGURED. Leave it empty and paste the keys into fedJwks instead if this service is not to make the call."
  })
  fedJwksUri?: string;
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    what: "A SECOND PROFILE ENDPOINT, for a provider that publishes a person's verified address apart from the rest (GitHub's /user/emails). Dialled with the same access token and under the same policy as fedUserinfoUrl, and only for a relationship whose provider profile reads it. Its failure costs the address, never the sign-in."
  })
  fedEmailsUrl?: string;
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    what: "The partner's public keys as a JWKS document, verbatim. Read BEFORE fedJwksUri and never refreshed, so a relationship carrying this makes no outbound request for keys at all."
  })
  fedJwks?: string;
  // OPENID FEDERATION (#134, 2026-09-23): an `oidc` relationship whose OP
  // is DISCOVERED through its Trust Chain rather than configured by hand.
  // See oidfed/oidfed_rp.ts, and federation/CLAUDE.md for why this is
  // still a relationship whose trust is a configured key.
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    what: "OPENID CONNECT ONLY. The Entity Identifier of one of this realm's Trust Anchors (/admin/oidfed). Set, the OP named by fedPeer is resolved through its Trust Chain to that anchor, its endpoints and keys are the openid_provider metadata the chain vouches for, and this service registers with it AUTOMATICALLY under its own Entity Identifier, signing its requests and token-endpoint authentication with its ES256 key — so fedSsoUrl, fedTokenUrl, fedJwks, fedJwksUri, fedClientId and fedClientSecret are not read. Empty, the relationship is configured by hand as always."
  })
  fedTrustAnchor?: string;
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    what: "THE PARTNER'S SIGNING CERTIFICATE, base64 DER — the same spelling a ds:X509Certificate carries and the same one samlSigningCertificate uses on an application entry, so one certificate has one spelling across this service. It is what every SAML and WS-Federation assertion is verified against, and it is the single attribute standing between this service and an endpoint anybody could assert anything at."
  })
  fedSigningCertificate?: string;
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    what: "THIS SERVICE'S client_id AT THE PARTNER. Ours, issued by them — not to be confused with an oauthClientId on an application entry, which is a client's id here."
  })
  fedClientId?: string;
  @attr(#{
    kind: "single",
    role: "service-provider",
    sensitive: true,
    from: "this register",
    what: "THIS SERVICE'S SECRET AT THE PARTNER, in the clear, in a directory where every bind succeeds. It is a REAL credential at a REAL foreign service, which is a stronger statement than anything else in this directory — see the header. Never written to the audit log and never printed on a page."
  })
  fedClientSecret?: string;
  // SIGN IN WITH APPLE (#565): a client secret that is a JWT this service
  // signs, and an authorization code returned by form_post.
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    allowed: #["query", "form_post", "fragment"],
    what: "HOW THE AUTHORIZATION RESPONSE COMES BACK. Empty, the default: query for code, and form_post (OAuth 2.0 Form Post Response Mode) for an OpenID Connect response type carrying an ID Token or an access token. form_post, which Sign in with Apple requires whenever a name or an address is asked for, arrives as a cross-site POST, so a browser sends it no SameSite=Lax cookie. fragment, OpenID Connect only, is the default of those response types in the specification: the answer is in the URL fragment, and a page with one script here posts it on. It puts the ID Token in the browser's history, which form_post does not: use it only for a partner that cannot post. query cannot carry an ID Token or an access token."
  })
  fedResponseMode?: string;
  @attr(#{
    kind: "multi",
    role: "service-provider",
    from: "this register",
    what: "MICROSOFT, ANY TENANT ONLY: the tenant ids whose people may sign in, one per value. fedPeer then holds {tenantid}, filled from each token's tid, and a token from a tenant not listed is refused. Empty refuses every tenant."
  })
  fedAllowedTenants?: string[];
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    what: "APPLE ONLY: the Apple Developer team id, the iss of the client secret this service signs for every token request."
  })
  fedTeamId?: string;
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    what: "APPLE ONLY: the id of the Sign in with Apple key, the kid of the client secret this service signs."
  })
  fedKeyId?: string;
  @attr(#{
    kind: "single",
    role: "service-provider",
    sensitive: true,
    from: "this register",
    what: "APPLE ONLY: THE PRIVATE KEY this service signs its client secret with (the .p8 file Apple issued, a P-256 key in PKCS #8 PEM). It is a credential at Apple. It is sealed under the key-encryption key wherever keys persist, never shown and never written to the audit log. A client secret signed with it lives five minutes and is minted per token request."
  })
  fedClientSigningKey?: string;
  @attr(#{
    kind: "multi",
    role: "service-provider",
    from: "this register",
    what: "EXTRA AUTHORIZATION REQUEST PARAMETERS, one per value, written `<name>=<value>`, for a provider that needs one (Twitch's `claims`, to be sent an address). OpenID Connect and OAuth 2.0 only. The parameters this service sets itself — response_type, client_id, redirect_uri, state, scope, nonce, code_challenge, code_challenge_method, response_mode, request and request_uri — are refused here, because one of them changed here would undo a check this service makes."
  })
  fedAuthorizeParams?: string[];
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    allowed: #["client_secret_basic", "client_secret_post"],
    what: "HOW THIS SERVICE AUTHENTICATES AT THE PARTNER'S TOKEN ENDPOINT: client_secret_basic (the default, which RFC 6749 section 2.3.1 says a server MUST support) or client_secret_post, for a partner that reads the secret only from the body. With no fedClientSecret this service is a public client and neither applies."
  })
  fedTokenAuth?: string;
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    what: "The scope asked of the partner. `openid profile email` is the default for an OIDC relationship and there is no default for an OAuth 2.0 one, because what an OAuth 2.0 authorization server will give you is entirely local to it."
  })
  fedScope?: string;
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    allowed: #["code", "id_token", "id_token token", "code id_token", "code token", "code id_token token"],
    what: "code (the default), id_token, or one of OpenID Connect's other four: id_token token (implicit), code id_token, code token and code id_token token (hybrid). `id_token` with form_post is the shape that needs NO back channel and therefore no token endpoint, no client secret and no outbound request — which is the only way to federate with an OIDC partner from a deployment that has no egress at all. An ID Token from the authorization endpoint must carry the nonce, and c_hash and at_hash wherever a code or an access token came with it."
  })
  fedResponseType?: string;
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    allowed: #["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"],
    what: "OPENID CONNECT ONLY. THE ONE ALGORITHM the partner signs this relationship's ID Tokens and Logout Tokens with — what was registered at the partner as id_token_signed_response_alg (OpenID Connect Core 1.0 section 3.1.3.7 step 7, Back-Channel Logout 1.0 section 2.6). A token signed with any other is refused, even one the partner's key verifies. Empty, the default: any algorithm of the verifying key's family that federation.jwtAlgorithms allows. Set it: an empty one accepts a token signed by another of the partner's keys under another algorithm."
  })
  fedIdTokenSignedResponseAlg?: string;
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    allowed: #["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"],
    what: "OPENID CONNECT ONLY. The algorithm a SIGNED UserInfo answer must be signed with — what was registered at the partner as userinfo_signed_response_alg (OpenID Connect Core 1.0 section 5.3.2). A signed answer is verified against the partner's keys whether or not this is set; set, one under another algorithm is not used. Empty, the default: a JSON answer, or a signed one under any algorithm of its key's family."
  })
  fedUserinfoSignedResponseAlg?: string;
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    what: "OPENID CONNECT ONLY. TRUE keeps the refresh token the partner issues at sign-in, sealed, with the session it started, and uses it to keep that session's identity current (OpenID Connect Core 1.0 section 12): every fedRefreshEverySeconds the session's tokens are refreshed, a new ID Token must name the same iss and sub, and UserInfo must still answer for that sub. A refresh the partner refuses, or an answer that fails those checks, ENDS the session. The token dies with the session. FALSE, the default: the partner's tokens are used once, at sign-in, and discarded — nothing here holds a credential at another service, and the partner's own sign-out and Shared Signals are what end the session early."
  })
  fedRefreshTokens?: string;
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    what: "With fedRefreshTokens on: how often, in seconds, a session's tokens are refreshed. Empty: when the access token expires (its expires_in), or hourly where the partner names no expiry. The scheduler job federation.partner-refresh looks every fifteen seconds."
  })
  fedRefreshEverySeconds?: string;
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    what: "OPENID CONNECT ONLY, with fedDiscovery. TRUE has this service REGISTER ITSELF at the partner (OpenID Connect Dynamic Client Registration 1.0, RFC 7591) at the registration_endpoint its discovery document names, whenever the relationship holds no fedClientId or holds one registered with another issuer — at the start of a sign-in, or by an administrator's register-partner. The client_id and secret the partner issues are written to fedClientId and fedClientSecret (sealed). What is registered is this relationship: its assertion consumer service, response type, client authentication, the algorithms set here and, for request objects, the public key that signs them. FALSE, the default: the client is registered at the partner by hand."
  })
  fedRegister?: string;
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    what: "The issuer fedClientId was registered with by fedRegister. Written by the registration; clear it, with fedClientId, to register again at the next sign-in."
  })
  fedRegisteredIssuer?: string;
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    allowed: #["request", "request_uri"],
    what: "OPENID CONNECT ONLY. Send the authorization request as a Request Object (OpenID Connect Core 1.0 section 6, RFC 9101): request (by value) or request_uri (by reference — the partner fetches it, once, from /federation/request/{id}/{handle}). Signed under fedRequestObjectSigningAlg with this realm's key. Empty, the default: a plain authorization request."
  })
  fedRequestObject?: string;
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    allowed: #["RS256", "PS256", "ES256", "none"],
    what: "The algorithm a Request Object is signed with: RS256 (the default), PS256 or ES256 under this realm's key, or none — an UNSIGNED one, which Core 6.2 allows only by reference over https; a warning: the partner then has only the TLS of the fetch to say this service wrote it."
  })
  fedRequestObjectSigningAlg?: string;
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    what: "OPENID CONNECT ONLY, with fedDiscovery. TRUE answers /federation/webfinger/{id}, where a PERSON types an identifier (acct:user@host or a URL) and this service asks that host who the person's OpenID Provider is (OpenID Connect Discovery 1.0 section 2, RFC 7033). A WARNING: the host dialled is one a caller chose — this service's one argued exception of that kind among the federation requests, under the outbound policy (no internal address in product mode, no redirect, the cap). The issuer found must begin with fedPeer, which bounds it to the partner an administrator configured; the person is shown the issuer and continues only by pressing a button. FALSE, the default, refuses."
  })
  fedWebFinger?: string;
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    what: "OPENID CONNECT ONLY. TRUE reads the partner's endpoints and its jwks_uri from its discovery document, {fedPeer}/.well-known/openid-configuration, at the start of every sign-in (OpenID Connect Discovery 1.0 section 4), whose issuer must be fedPeer exactly; fedSsoUrl, fedTokenUrl, fedUserinfoUrl and fedJwksUri are then not read. The address is derived from fedPeer, which an administrator configured, and never from a request. FALSE, the default: the endpoints are configured by hand."
  })
  fedDiscovery?: string;
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    what: "OPENID CONNECT ONLY. TRUE answers this relationship's login initiation endpoint, /federation/initiate-login/{id}, which the partner registers as initiate_login_uri (OpenID Connect Core 1.0 section 4): a sign-in the PARTNER starts, naming itself in iss, which must be fedPeer. A login_hint is passed on, and a target_link_uri is followed only to a path on this service. FALSE, the default, refuses it: a page anywhere could otherwise start a sign-in in a person's browser."
  })
  fedInitiateLogin?: string;
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    allowed: #["HTTP-Redirect", "HTTP-POST"],
    what: "Which binding the outbound SAML AuthnRequest goes on: HTTP-Redirect (the default, and what every identity provider supports) or HTTP-POST. It says nothing about the response, which arrives on whatever binding the partner sends it on and is accepted on all of them."
  })
  fedBinding?: string;
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    what: "Sign the outbound AuthnRequest with THIS service's key. OFF by default: most identity providers do not require it, and a partner that does will refuse the request in a way that names the problem. When it is on, the certificate to configure at the partner is the one on this service's own SAML metadata."
  })
  fedSignRequest?: string;
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    what: "WHICH INCOMING VALUE IS LOOKED UP AT LINK-AT-FIRST-SIGN-IN, and matched under any-existing — a claim name for OIDC/OAuth 2.0, a SAML Attribute Name for the others. Empty means the subject itself: the NameID, or `sub`. It does not name an entry this sign-in CREATES: that name is the relationship and the partner's stable subject (#358)."
  })
  fedUsernameSource?: string;
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    what: "PLAIN OAUTH 2.0 ONLY: the member of the profile endpoint's answer that is the partner's stable identifier for the person, as a dotted path (id, data.id). Empty keeps what this service has always done — sub, then id, then user_id. It is the SUBJECT, the half of a federation link that must never change, which is not the username (fedUsernameSource). An OpenID Connect partner's subject is the ID Token's sub, which OpenID Connect Core section 5.7 makes the only stable one, and a consumer provider's is its profile's."
  })
  fedSubjectClaim?: string;
  @attr(#{
    kind: "multi",
    role: "service-provider",
    from: "this register",
    what: "ONE VALUE PER MAPPING, written `<incoming name>=<LDAP attribute>`. What is NOT listed here still arrives — federation_map.js has a default table covering the ordinary OIDC claims, the SAML urn:oid: names and the WS-Federation claim URIs — so this is for the partner's own inventions rather than for the names everybody uses."
  })
  fedAttributeMap?: string[];
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    what: "DYNAMIC PROVISIONING: create a directory entry the first time this partner signs somebody in. Written TRUE when a relationship is created in development and FALSE in product (mode.defaultsFederatedAutocreate()); a relationship that stores neither reads the same way. OFF means the person must ALREADY have an entry here — provisioned ahead of time, by SCIM or by hand — and a sign-in for somebody who does not is refused, because a session needs an entry to be the subject of. (Until 2026-09-14 OFF gave a session and no entry; a stable subject made that state impossible.)"
  })
  fedAutocreateUsers?: string;
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    what: "Update the person's directory attributes on EVERY sign-in from the latest assertion or token. ON by default, which is what this service always did. OFF writes the partner's attributes only when this sign-in CREATED the entry, so a pre-provisioned person — or one somebody has since edited — keeps what the directory says. Which relationship and issuer a person came through is recorded either way."
  })
  fedUpdateUserAttributes?: string;
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    what: "BUILD GROUP MEMBERSHIPS FROM THE PARTNER'S TOKEN (#358). OFF by default, and a missing value is off. On, each group name the assertion carries becomes a membership of the person this sign-in provisioned, on every successful sign-in. A group created this way is marked with this relationship. A name that already exists and is not marked as this relationship's is ignored, audited (STS-FED-0161) and the sign-in continues. A group that grants something by being held — a console group, a role's member group, an owner group, a group a policy names — is never created or joined (STS-FED-0164). It does not satisfy fedSubjectGroup: that rule runs before anybody is added."
  })
  fedProvisionGroups?: string;
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    what: "HOW MANY PEOPLE THIS RELATIONSHIP MAY CREATE. 0 is unlimited. Empty is unlimited for an enterprise partner; a CONSUMER or social provider's relationship is never unlimited by default: it is created with federation.consumerProvisionCap (10000 unless the realm says otherwise) written here, and an empty value means that setting. At the cap a new subject is refused STS-FED-0090; a person already linked still signs in. ldap.maxEntries remains the realm ceiling. Not a count of sign-ins — fedUsers is that."
  })
  fedProvisionCap?: string;
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    what: "DISABLE A PERSON THIS RELATIONSHIP IS THE ONLY SIGN-IN PATH FOR, once federationLastSeen is older than this many minutes. Empty or 0 is off: nobody is disabled for being idle. The entry and the link are kept. A person with a local userPassword, or a link through another relationship, is left alone. A partner's account-disabled signal is separate (STS-FED-0156) and blocks only that partner's sign-ins."
  })
  fedProvisionIdleMinutes?: string;
  // --- WHICH PEOPLE THE PARTNER MAY ASSERT (#109, 2026-09-22) ----------
  // The gate used to be on the SIGNER only: any person a verified assertion
  // named was signed in, matched onto a local entry by NAME. These five say
  // which local person a partner's subject may become — see
  // federation/CLAUDE.md, *WHICH PEOPLE A PARTNER MAY ASSERT*.
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    allowedFrom: #["subjectPolicies"],
    what: "HOW THE PARTNER'S SUBJECT BECOMES A LOCAL PERSON. The subject is the partner's own stable identifier — iss + sub, a persistent NameID and the partner's entity ID — and a person carries it as a federationLink. link-at-first-sign-in (the default; empty means it): a linked subject signs in; an unlinked one naming an existing person must first sign in HERE as that person — password, and a second factor where one is held or required — and only then is the link recorded and the partner's attributes written; one naming nobody gets a new entry namespaced to this relationship where provisioning is on. pre-linked: only a link signs anybody in. jit-namespaced: an unlinked subject always gets a NEW entry, <relationship>~<subject>, never an existing person. The subject is the partner's stable identifier, with a urn:uuid: folded to sub-<uuid>; it is not the mapped username. any-existing: the name the partner sent is matched straight onto a local person, as this service did before #109 — DEVELOPMENT ONLY, refused in product, and it lets this partner sign in any account it can name."
  })
  fedSubjectPolicy?: string;
  @attr(#{
    kind: "multi",
    role: "service-provider",
    from: "this register",
    what: "A RULE ON TOP OF THE POLICY: the person must be a member of one of these groups, each a cn or a DN. An entry this sign-in would CREATE is in no group, so with this set nobody is created. Empty: no group rule."
  })
  fedSubjectGroup?: string[];
  @attr(#{
    kind: "multi",
    role: "service-provider",
    from: "this register",
    what: "A RULE ON TOP OF THE POLICY: the mail domain the partner SENT (the mapped mail, or the mapped username where it is an address) must be one of these, and so must the local entry's mail where it has one. Compared case-insensitively and exactly: example.com does not admit sub.example.com. Empty: no domain rule."
  })
  fedSubjectDomain?: string[];
  @attr(#{
    kind: "multi",
    role: "service-provider",
    from: "this register",
    what: "HOME-REALM DISCOVERY (#148): an authorization request whose OpenID Connect Enterprise Extensions `domain_hint` is one of these goes straight to this partner's sign-in, unless the application names a partner of its own. Compared case-insensitively and exactly. A routing hint only — who is ADMITTED is fedSubjectDomain's."
  })
  fedHomeRealmDomain?: string[];
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    what: "A RULE ON TOP OF THE POLICY: a regular expression the local entry's DN must match WHOLE (it is anchored for you), such as uid=[^,]+,ou=users,.* — for an entry this sign-in would create, the DN it would be created at. At most 256 characters, no backreference and no quantifier applied to a group that is itself quantified, and it is tested against at most 1024 characters, so a pattern cannot be made to backtrack for minutes. Empty: no pattern."
  })
  fedSubjectPattern?: string;
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    what: "LET THIS PARTNER SIGN IN A CONSOLE ADMINISTRATOR. OFF by default, and off means a person in the Admin Read or Admin Write roster — or holding REMOTE_PEPS — is refused whatever else is true, a valid link included (STS-FED-0093). Turning it on makes this partner's signing key a key to the console for every administrator linked to it."
  })
  fedMayAssertAdministrators?: string;
  // --- A PARTNER'S SHARED SIGNALS (#153) ----------------------------------
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    what: "LET THIS PARTNER'S SHARED SIGNALS NAME A PERSON BY MAIL. OFF by default: a Security Event Token from a transmitter with this partner's issuer names a person by `iss_sub`, through the person's federationLink. On, an `email` subject matches the one person with that mail address as well — an address is not an identifier (OpenID Connect Core section 5.7), so only for a partner whose addresses this realm trusts."
  })
  fedSignalEmailMatch?: string;
  // THE PARTNER AS A SHARED SIGNALS TRANSMITTER (#373, #374): the stream's
  // CONFIGURATION, on the relationship that says who the partner is. What
  // the stream IS at the far end — its id, audience, push secret digest,
  // verification — is minted, and lives in ssf/ssf_transmitters.ts's
  // store keyed by fedId. ssf/CLAUDE.md, *A PARTNER'S SHARED SIGNALS*.
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    what: "RECEIVE THIS PARTNER'S SHARED SIGNALS. OFF by default on a sign-in relationship, and the whole point of an `ssf` one, where it is written ON at creation. Off, no push is accepted for this relationship and the poll job skips it; fedEnabled must be on as well."
  })
  fedSignalsEnabled?: string;
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    what: "THE PARTNER'S SSF ISSUER, when it is not fedPeer. Empty — the default — uses fedPeer, which is right for an OpenID Connect partner whose transmitter shares its issuer. A SAML 2.0 or WS-Federation partner's entityID is usually NOT its SSF issuer URL, so set it there. The configuration document is fetched from /.well-known/ssf-configuration under it (SSF 1.0 section 7) and must name it, and every SET's iss must be it."
  })
  fedSignalsIssuer?: string;
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    allowed: #["poll", "push"],
    what: "HOW THE PARTNER'S EVENTS ARRIVE: poll (RFC 8936, the ssf.foreign-poll job, the default) or push (RFC 8935, to /federation/signals/{id} with an authorization header only this realm and the partner know). Read when the stream is created; delete and create it again to change it."
  })
  fedSignalsDelivery?: string;
  @attr(#{
    kind: "multi",
    role: "service-provider",
    from: "this register",
    what: "THE EVENT TYPE URIS THE STREAM ASKS FOR (events_requested). None asks for whatever the partner supports."
  })
  fedSignalsEvents?: string[];
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    what: "WHERE THIS REALM GETS AN ACCESS TOKEN FOR THE PARTNER'S STREAM MANAGEMENT, by client credentials. Empty uses fedTokenUrl — the same authorization server the sign-in relationship already dials."
  })
  fedSignalsTokenUrl?: string;
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    what: "THIS SERVICE'S client_id FOR THE PARTNER'S STREAM MANAGEMENT. Empty uses fedClientId."
  })
  fedSignalsClientId?: string;
  @attr(#{
    kind: "single",
    role: "service-provider",
    sensitive: true,
    from: "this register",
    what: "THE SECRET FOR fedSignalsClientId, SEALED under the key-encryption key wherever keys persist and never shown. Empty uses fedClientSecret, sealed the same way."
  })
  fedSignalsClientSecret?: string;
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    what: "The scope asked for with client credentials. Empty asks for `ssf.read ssf.manage`, the CAEP Interoperability Profile's two (section 2.7.3)."
  })
  fedSignalsScope?: string;
  @attr(#{
    kind: "single",
    role: "service-provider",
    sensitive: true,
    from: "this register",
    what: "A BEARER TOKEN THE PARTNER ISSUED, instead of client credentials. Sealed like fedSignalsClientSecret, and used whenever it is set."
  })
  fedSignalsBearer?: string;
  // --- A PARTNER'S SIGN-OUT (#167) ---------------------------------------
  // federation/federation_slo.ts is what reads these, in both directions:
  // the partner telling this service a session ended, and this service
  // telling the partner. federation/CLAUDE.md, *A PARTNER'S SIGN-OUT*.
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    what: "THE PARTNER'S SAML 2.0 SingleLogoutService — where this service sends a signed <LogoutRequest> when a person signs out HERE (/logout), and where the <LogoutResponse> to the partner's own LogoutRequest goes. From the partner's metadata. Empty: the partner is never told of a sign-out here, and a LogoutRequest from it is still honoured but answered with nothing, because there is nowhere to send the answer. SAML 2.0 only: SAML 1.1 defines no logout at all."
  })
  fedSloUrl?: string;
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    allowed: #["HTTP-Redirect", "HTTP-POST"],
    what: "Which binding a LogoutRequest or LogoutResponse this service sends the partner goes on: HTTP-Redirect (the default; the signature is over the query string) or HTTP-POST (an enveloped signature, on a real form with a real button — no script). A message FROM the partner is accepted on either."
  })
  fedSloBinding?: string;
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    what: "THE PARTNER'S OpenID Connect end_session_endpoint (RP-Initiated Logout 1.0), from its discovery document. When a person signs out HERE, the sign-out page offers to send them there with the partner's own ID Token as id_token_hint, this relationship's client_id, and this relationship's single logout endpoint as post_logout_redirect_uri — which the partner must have registered. The ID Token is kept on the session only while this is set. Empty: the partner is not told."
  })
  fedEndSessionUrl?: string;
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    what: "HONOUR THE PARTNER'S SIGN-OUT: a SAML LogoutRequest, an OpenID Connect Back-Channel or Front-Channel logout, a WS-Federation cleanup. ON by default — the partner is the authority on the person's sign-on, and when it ends a session or disables an account there, this is the only signal that reaches here. Off, every one of them is refused (STS-FED-0123) and the session here lives its whole lifetime."
  })
  fedAcceptSignout?: string;
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    what: "REQUIRE THE PARTNER'S SAML LogoutRequest AND LogoutResponse TO BE SIGNED, as saml-profiles-2.0-os section 4.4.4.1 says they MUST be. ON by default and ALWAYS on in product mode, where turning it off is refused (STS-FED-0132). Off — development only — accepts an UNSIGNED logout message, which lets anybody who can name a person's partner session end it: a partner under test that cannot sign yet is the only reason to. A signature that IS present is verified either way."
  })
  fedRequireSignedLogout?: string;
  // --- WHAT A PARTNER ENCRYPTS TO (#168) ------------------------------
  // federation/federation_encryption.ts issues, rotates, publishes and
  // decrypts with the key; federation/CLAUDE.md, *A PARTNER'S ENCRYPTED
  // ASSERTION*. SAML 2.0, WS-Federation and OpenID Connect only: SAML 1.1
  // has no encryption construct and a plain OAuth 2.0 relationship reads
  // no ID Token.
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    allowedFrom: #["classicalKeyTypes", "joseOnlyKeyTypes"],
    what: "THE KIND OF KEY A PARTNER ENCRYPTS TO: rsa-3072 (the default for SAML 2.0 and WS-Federation) or ec-p256 (the default for OpenID Connect) — or, for OpenID Connect only, a post-quantum one (#82): x-wing (HPKE-10-KE, ML-KEM-768 + X25519) or ml-kem-768 (ML-KEM-768), an AKP key published in the relationship's JWKS with no certificate, from Internet-Drafts few partners implement yet. Changing it issues a new key of that kind at once and keeps the old one for federation.encryptionKeyGraceS, as a rotation does."
  })
  fedEncryptionKeyType?: string;
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    allowedFrom: #["xmlKeyManagement", "joseKeyManagement"],
    what: "HOW THE PARTNER WRAPS OR AGREES THE CONTENT KEY, and the only one accepted. XML (SAML 2.0, WS-Federation): rsa-oaep — XML Encryption 1.1's RSA-OAEP with SHA-256 and MGF1-SHA-256 — for an RSA key, ecdh-es (ConcatKDF, kw-aes256) for an EC one. JOSE (an OpenID Connect ID Token): RSA-OAEP-256 or RSA-OAEP for an RSA key, ECDH-ES, ECDH-ES+A128KW or ECDH-ES+A256KW for an EC one. WARNING: RSA-OAEP is OAEP over SHA-1, offered for a partner that has nothing newer; RSA-OAEP-256 is the one to use. rsa-1_5 and RSA1_5 are refused in every mode (Bleichenbacher). Empty means the default for the key type."
  })
  fedKeyManagementAlgorithm?: string;
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    allowedFrom: #["xmlContentEncryption", "joseContentEncryption"],
    what: "THE CIPHER OVER THE ASSERTION OR THE ID TOKEN, and the only one accepted: aes256-gcm (the default) or aes128-gcm for XML, A256GCM (the default) or A128GCM for JOSE. AES-CBC — XML Encryption's aes*-cbc and JOSE's A*CBC-HS* — is refused in every mode: the XML form is the padding oracle of Jager and Somorovsky (2011), and a partner that can do GCM in one can in the other."
  })
  fedContentEncryptionAlgorithm?: string;
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    what: "ACCEPT A PLAINTEXT ASSERTION IN PRODUCT MODE. OFF by default, and off means a SAML 2.0 or WS-Federation assertion, or an OpenID Connect id_token by form_post, that is NOT encrypted to this relationship's key is refused (STS-FED-0140). WARNING: turning it on lets the partner send the person's NameID, mail, groups and every other attribute IN CLEAR through their browser — its history, its extensions and every TLS-terminating proxy on the way. Turn it on only for a partner that cannot encrypt, and prefer asking it to. Development mode accepts plaintext whatever this says."
  })
  fedAllowUnencrypted?: string;
  @attr(#{
    kind: "multi",
    role: "service-provider",
    from: "this register",
    sensitive: true,
    what: "THE KEY TABLE: one JSON row per key this relationship decrypts with — its kid, its key type, `current` or `previous`, its certificate and chain under this realm's Intermediate, and the private key, SEALED under the key-encryption key wherever keys persist. A `previous` row is kept until its retiresAt and then removed by the scheduler job federation.encryption-key-retire. Written only by create, rotate and that job; WITHHELD from every LDAP search in product and from every page and /admin-api reply, which publish the public half. The key type is a column so a hybrid post-quantum key can be a row beside the classical one once one is registered."
  })
  fedEncryptionKey?: string[];
  @attr(#{
    kind: "single",
    role: "service-provider",
    from: "this register",
    what: "Accept a response this service did not ask for — SAML 2.0's unsolicited Response, and SAML 1.1's ONLY mode of operation. OFF by default for SAML 2.0 and forced ON for SAML 1.1, because that profile has no request to be in response to. Turning it on for SAML 2.0 removes the InResponseTo check, which is worth knowing rather than worth hiding."
  })
  fedAllowUnsolicited?: string;
  // --- the identity provider half: what this service ASSERTS ------------
  @attr(#{
    kind: "single",
    role: "identity-provider",
    from: "this register",
    what: "THE POINTER, and the whole of what this side stores about the partner: the identifier of its entry in ou=applications. Its entityID, its assertion consumer service, its redirect URIs and its certificate live THERE, where every protocol module already reads them. Copying any of them here would be the two-stores failure this repository is arranged to avoid."
  })
  fedApplication?: string;
  @attr(#{
    kind: "single",
    role: "identity-provider",
    from: "this register",
    allowedFrom: #["mechanisms"],
    what: "HOW THIS SERVICE AUTHENTICATES THE PERSON when this partner asks it to: password, password-mfa, webauthn, spnego — a Kerberos ticket the browser already holds, with no screen at all — wallet — a credential this realm issued, presented from the person's wallet — or federation, which sends them on to another relationship and is what makes this service an identity BRIDGE between two protocols. EMPTY MEANS THIS RELATIONSHIP SAYS NOTHING, which is not the same as password: it falls through to appFederationRelationship on the application entry and then to the sign-in screen, which is exactly what every relationship did before this attribute existed."
  })
  fedAuthnMechanism?: string;
  @attr(#{
    kind: "single",
    role: "identity-provider",
    from: "this register",
    what: "WHICH RELATIONSHIP THE PERSON IS SENT TO, when the mechanism is `federation`. It names a SERVICE-PROVIDER-side relationship in THIS realm — the register is per realm, so an id from another one names nothing here — and it is checked when it is USED rather than when it is written, because the relationship it names can be disabled or deleted afterwards by somebody who never looked at this entry. Ignored by every other mechanism, and required by this one: readinessOf() names it."
  })
  fedAuthnRelationship?: string;
  @attr(#{
    kind: "multi",
    role: "identity-provider",
    from: "this register",
    what: "WHICH ATTRIBUTES ARE RELEASED TO THIS PARTNER, by claim or attribute name. It FILTERS what /admin/claims, /admin/saml-attributes and the groups claim would otherwise put in an artifact for this audience, and it can touch nothing else — not sub, not iss, not exp, not a NameID. NO VALUES HERE MEANS NO POLICY, not release nothing; see the header, where the difference is argued."
  })
  fedRelease?: string[];
  // --- what has happened ------------------------------------------------
  @attr(#{
    kind: "single",
    role: "both",
    from: "this register",
    what: "GeneralizedTime: when this relationship was first USED, which is not when it was created."
  })
  fedFirstSeen?: string;
  @attr(#{
    kind: "single",
    role: "both",
    from: "this register",
    what: "GeneralizedTime, the most recent use."
  })
  fedLastSeen?: string;
  @attr(#{
    kind: "single",
    role: "both",
    from: "this register",
    what: "How many credentials have crossed this relationship. ASSIGNED on every change — a counter that accumulated values would be nonsense — and it is a live number in a directory entry, which a real directory would not hold."
  })
  fedAuthentications?: string;
  @attr(#{
    kind: "single",
    role: "both",
    from: "this register",
    what: "How many distinct identities have crossed it. Counted against fedLastUser, so it counts a CHANGE of user rather than a set: right for the ordinary case and an undercount for somebody alternating between two partners. Stated here because it is a number on a page."
  })
  fedUsers?: string;
  @attr(#{
    kind: "single",
    role: "both",
    from: "this register",
    what: "The most recent identity. On the entry rather than in memory because the entry is the store."
  })
  fedLastUser?: string;
  @attr(#{
    kind: "multi",
    role: "service-provider",
    from: "this register",
    what: "THE SAME TWO COUNTS, SPLIT BY THE APPLICATION THE SIGN-IN WAS FOR — one value per application, packed as `application|authentications|users|lastUser|lastSeen`. It exists because fedAuthentications answers \"how much has crossed this relationship\" and the map at /admin/federation/map has to answer \"how much has crossed it FOR EACH of the applications configured to use it\", which is a different question the moment a second application names the same partner.\n\nIT IS SERVICE-PROVIDER SIDE ONLY, and that is not an omission. An identity-provider-side relationship names exactly ONE application (fedApplication), so its per-application count IS fedAuthentications and a second attribute holding the same number under another name is the copy that comes to disagree.\n\nA VALUE IS WRITTEN ONLY FOR A PAIR THIS SERVICE IS CONFIGURED FOR, checked against the live configuration at the moment of the write rather than trusted from the request — see applicationConfiguredFor(). Without that check this attribute would be an unbounded list of strings anybody who can reach /federation/login/{id} chose, on the one entry in this directory whose contents decide whether an assertion is refused.\n\n`|` IN EITHER FREE-TEXT FIELD IS REPLACED BY `~` ON THE WAY IN, which is the trade this format makes and it is stated rather than discovered: this is a packed counter drawn on a picture, not an identifier anything joins on. The application a row is FILED under is compared in the same packed spelling throughout, so a pair round-trips to itself whatever it is called."
  })
  fedApplicationUse?: string[];
  @attr(#{
    kind: "single",
    role: "both",
    from: "this register",
    what: "WHY THE LAST ATTEMPT FAILED, in this service's own words. It is the most useful attribute here and it is why refusals are recorded rather than only logged: a federation that does not work fails at somebody else's service, and \"the signature did not verify against the configured certificate\" is the sentence that ends the argument about whose end is broken."
  })
  fedLastError?: string;
  @attr(#{
    kind: "single",
    role: "both",
    from: "this register",
    what: "GeneralizedTime for the line above. Separate, so that an old error beside a recent success reads as history rather than as the current state."
  })
  fedLastErrorAt?: string;
}
