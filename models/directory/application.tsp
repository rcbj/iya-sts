// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/directory/application.tsp
//
// ---------------------------------------------------------------------------
// THE APPLICATION ENTRY, WRITTEN BY HAND (#1390). THIS IS THE SOURCE.
//
// `models/tools/generate.mjs` compiles this file during the image build and
// writes `models/generated/application.schema.json`, which is what
// `common/applications.js` reads as SCHEMA. A row added here is a row the
// service has. The generator never rewrites this file.
//
// The comments are the ones that sat on these rows in `common/applications.js`,
// and their reasoning still applies. What an RFC says about a name (OID,
// syntax, matching rules) is added by the collector from
// `rfc_schema.json`, so it is not repeated here.
// ---------------------------------------------------------------------------

import "../lib/model_lib.tsp";

using IyaSts.ModelLib;

namespace IyaSts.Directory;

@entry(#{
  id: "application",
  source: "./applications",
  container: "ou=applications",
  ownContainer: false,
  authored: true,
  key: "appIdentifier",
  naming: #{
    attribute: "cn",
    what: "The identifier, or app- plus twelve hex digits when the identifier is longer than 64 characters."
  },
  derived: #[#{
    name: "subject",
    what: "urn:sts:application:<appIdentifier>. Derived, not stored."
  }],
  registration: #["appRegistered", "appRegisteredBy"],
  declaration: "appAllowedProtocol",
  observation: "appProtocol",
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
      what: "The one REGISTERED object class that fits an application. It brings cn, description, seeAlso, ou and l — so the NAME of an application here is a standard attribute even though nothing else about it can be."
    },
    #{
      name: "stsApplication",
      where: "this service",
      standard: false,
      what: "INVENTED, because no registered LDAP schema has a client_id, a set of redirect URIs, an entityID or a service principal name. Every product that stores OAuth clients keeps them in its own database rather than in a directory, so there was nothing to borrow. These are this service's own names in the way x509subject and didSubject already are."
    }
  ]
})
model Application {
  // --- identity ---------------------------------------------------------
  @attr(#{
    kind: "single",
    from: "every protocol",
    what: "THE KEY: the identifier exactly as the protocol presented it. The entry's own cn may be a digest of it where it is too long to be a readable RDN, so this is the attribute to search on — the same arrangement didSubject has on a DID-named person."
  })
  appIdentifier?: string;
  @attr(#{
    kind: "single",
    from: "this registry",
    standard: true,
    what: "The RDN value: the identifier itself, or app-<12 hex> where that would be longer than 64 characters."
  })
  cn?: string;
  @attr(#{
    kind: "single",
    from: "RFC 7591 client_name, or the identifier",
    what: "What to call it on a page. A registration supplies one; otherwise the identifier is the name, because inventing a friendly name for an opaque id would be inventing a fact."
  })
  appName?: string;
  // ---------------------------------------------------------------------
  // WHERE THIS APPLICATION LIVES, added 2026-09-10 for /portal/applications.
  //
  // That page lists the applications a person may be signed in to, and until
  // this attribute existed it named them without being able to say where any
  // of them was. A name and a client_id are not somewhere you can go.
  //
  // **IT IS DECLARED AND IS NEVER DERIVED, WHICH IS THE WHOLE OF THE
  // DECISION.** The first attempt computed an address from the redirect URIs
  // already on the entry — take the ORIGIN of the first http(s) one — and it
  // was rejected because a redirect URI is a CALLBACK: a browser sent to one
  // carrying none of the parameters it exists to receive gets an error from
  // the application rather than its front door, and the origin above it is a
  // GUESS that is wrong for every application served under a path. A page
  // that guesses is a page whose links are right often enough that nobody
  // checks them. So this is a fact somebody states, and where it is absent
  // the portal draws the row with no link at all and says why.
  //
  // **RFC 7591 `client_uri` IS THE SAME FACT and register() writes it here**,
  // which is what stops this being an attribute only a hand-edited entry ever
  // carries: that member is defined as "URL string of a web page providing
  // information about the client", which is exactly the question this
  // answers. It is `set` rather than `multi` because an application has ONE
  // home page, and a list would be a question no page here has anywhere to
  // ask.
  //
  // `labeledURI` (RFC 2079) was the standards-purist alternative and was not
  // taken: its value is a URI followed by an optional label, so it would need
  // a grammar and a parser to hold one URL, and it is multi-valued by
  // definition. An attribute of this registry's own says one thing.
  //
  // THE VALUE IS CHECKED WHERE IT IS WRITTEN — http or https and nothing else
  // — because the one thing this service does with it is put it in an `href`
  // on a page. See homePageProblem(). `ldapmodify` reaches it like every
  // other attribute and is not checked, which is why homePageOf() checks
  // again when it reads.
  // ---------------------------------------------------------------------
  @attr(#{
    kind: "single",
    from: "RFC 7591 client_uri, the console, the management API, or by hand",
    what: "THE APPLICATION'S OWN HOME PAGE: where a person goes to reach it, and therefore where a sign-in to it starts. It is what /portal/applications links each row to, and an entry without one is drawn there with no link rather than with a guessed address. DECLARED and never derived — the redirect URIs beside it are callbacks and not front doors, so nothing computes this from them. http or https only, because it becomes an href."
  })
  appHomePageUrl?: string;
  // ---------------------------------------------------------------------
  // WHICH PROTOCOL /launch/{app} STARTS WHEN IT IS NOT TOLD (#426, #713).
  // An application declared for several browser protocols with
  // identity-provider-initiated sign-in on for more than one has more than
  // one way in, and the link has to pick; `?protocol=` still picks for
  // itself.
  // ---------------------------------------------------------------------
  @attr(#{
    kind: "single",
    from: "the console, the management API, or by hand",
    what: "WHICH PROTOCOL /launch/{app} uses for this application when the link names none and identity-provider-initiated sign-in is on for more than one: saml2, saml11, wsfed or oidc."
  })
  appLaunchProtocol?: string;
  // ---------------------------------------------------------------------
  // THE ORIGINS A BROWSER PAGE MAY CALL THIS SERVICE FROM ON THIS
  // APPLICATION'S BEHALF (2026-09-13).
  //
  // Until this date every response here carried `Access-Control-Allow-Origin:
  // *`, so a script on ANY origin could read any answer this service gave a
  // non-credentialed request. `common/cors.js` now echoes an origin only when
  // it is this service's own or is listed here — and WHICH entry's list is
  // asked is decided by the request: one that names a client (a `client_id`,
  // a Basic credential, a client assertion, an access token's `client_id`)
  // is judged against THAT entry's list alone, and one that names nobody
  // (discovery, a JWKS, a DID document, every preflight) against every entry
  // in the realm. That module's header argues both halves.
  //
  // **AN EMPTY LIST ALLOWS NO THIRD-PARTY ORIGIN, IN BOTH MODES.** That is
  // the rule as it was asked for and it is not mode-gated: a CORS header is
  // not a refusal a client under test learns anything from, it is what a
  // browser uses to decide whether a page may read an answer.
  //
  // It is an attribute of THIS REGISTRY rather than of the OAuth families
  // because every family's endpoints are behind the same decision — SCIM,
  // GNAP and the management API included — so it carries no `families`.
  // Values are normalised to the serialisation a browser sends when written
  // through this module (`validation.normaliseOrigin()`); `ldapmodify` is
  // not normalised, which is why the reader normalises again.
  // ---------------------------------------------------------------------
  @attr(#{
    kind: "multi",
    from: "the console, the management API, or by hand",
    what: "THE ORIGINS A BROWSER PAGE MAY CALL THIS SERVICE FROM FOR THIS APPLICATION — `https://app.example.com`, one exact origin per value, with no path and no wildcard. A request that names this application as its client (a client_id, a Basic credential, a client assertion, or an access token issued to it) is answered with Access-Control-Allow-Origin only when its Origin is listed here; a request that names no client at all — discovery, a JWKS, a DID document, a CORS preflight — is answered for an origin listed on ANY application in the realm. EMPTY ALLOWS NO THIRD-PARTY ORIGIN, in both modes. This service's own origins (its listeners, global.publicBaseUrl, the embedded debugger, and global.corsOrigins) never need listing. Normalised when written: scheme and host lower-cased, a default port dropped."
  })
  appCorsOrigin?: string[];
  @attr(#{
    kind: "multi",
    from: "every protocol",
    what: "What this application IS, one value per role it has been seen in. Several is the ordinary case and is the point: an OAuth client that asks for the openid scope is also a relying party."
  })
  appKind?: string[];
  @attr(#{
    kind: "multi",
    from: "every protocol",
    what: "The protocol families it has appeared in, accumulated."
  })
  appProtocol?: string[];
  @attr(#{
    kind: "multi",
    from: "the console, the management API, or by hand",
    what: "THE PROTOCOL FAMILIES THIS APPLICATION IS DECLARED FOR, one value per family, from the closed table PROTOCOLS publishes. It is the DECLARED twin of appProtocol above and the two must not be read as one thing: that attribute is what has happened and cannot be edited, this one is what somebody said the application is for and is ticked on /admin/applications/new before it has ever connected. It grants nothing. In PRODUCT mode the issuance policy refuses an issuance through a family it does not name — an application declared for SAML 2.0 alone is refused an access token (STS-XACML-0084); in development it refuses nothing. Declared for nothing, nothing is refused in either mode."
  })
  appAllowedProtocol?: string[];
  @attr(#{
    kind: "multi",
    from: "OAuth 2.0 / OIDC",
    what: "WHICH AUTHORIZATION SERVERS this client has used, by the name in their paths — one value per server it has been seen at. This process publishes several, each with its own capabilities and its own endpoints under /{id}/oauth2/…, and EVERY CLIENT MAY USE EVERY ONE of them: nothing here restricts a client to a server, so this records where it HAS been rather than where it may go. Accumulated, because a client that talks to two of them is one client with two values and not two clients."
  })
  appAuthorizationServer?: string[];
  // ONE VALUE, NOT A LIST (#456): what this application is, in a sentence,
  // edited as one box. The registry's own notes — how it first got here —
  // only ever fill an EMPTY one (noteDescription()), so they never add a
  // second value beside an administrator's or overwrite it. RFC 4519 lets
  // the attribute hold several; an entry an ldapmodify gave several is read
  // as its first, and the next save writes one.
  @attr(#{
    kind: "single",
    from: "this registry",
    standard: true,
    what: "What this application is, in a sentence. One value: until somebody writes one, it says how the application first got here."
  })
  description?: string;
  // --- what has happened ------------------------------------------------
  @attr(#{
    kind: "single",
    from: "this registry",
    what: "GeneralizedTime, when this identifier was first presented."
  })
  appFirstSeen?: string;
  @attr(#{
    kind: "single",
    from: "this registry",
    what: "GeneralizedTime, the most recent time."
  })
  appLastSeen?: string;
  @attr(#{
    kind: "single",
    from: "this registry",
    what: "How many credentials this service has accepted FOR this application. ASSIGNED on every change — a counter that accumulated values would be nonsense — and it is a live number in a directory entry, which is unusual enough to say out loud: a real directory would not hold one."
  })
  appAuthentications?: string;
  @attr(#{
    kind: "single",
    from: "this registry",
    what: "How many DISTINCT browser sign-on sessions have involved it. Counted from the session id that rides on the authentication funnel, so a direct grant with no browser session behind it adds nothing."
  })
  appSessions?: string;
  @attr(#{
    kind: "single",
    from: "this registry",
    what: "How many distinct identities have authenticated for it. The identities themselves are NOT listed here: an application used by two thousand people would otherwise put two thousand values on one entry."
  })
  appUsers?: string;
  @attr(#{
    kind: "single",
    from: "this registry",
    what: "The most recent sign-on session id. It is what appSessions is counted against — a different one increments the count — and it is on the entry rather than in memory because the entry is the store: without it a restart of nothing at all would recount the session already counted."
  })
  appLastSession?: string;
  @attr(#{
    kind: "single",
    from: "this registry",
    what: "The most recent identity, for the same reason and with the same limitation: it counts a CHANGE of user rather than a distinct set, which is right for the ordinary case and undercounts somebody alternating between two applications. Stated in seen() where the trade is made."
  })
  appLastUser?: string;
  // --- OAuth 2.0 / OpenID Connect ---------------------------------------
  @attr(#{
    kind: "single",
    from: "POST /oauth2/register",
    what: "TRUE when this application went through dynamic client registration here, FALSE when it is simply a client_id that turned up. It records HOW the application got here and not what counts: RFC 9700 mode judges a client against its own oauthRedirectUri whenever the entry holds one, however it got there, and against the oauth2.redirectUris setting only when it holds none — which OAuth 2.1 mode refuses instead. An omitted token_endpoint_auth_method means client_secret_basic for a registered client and nothing for one made by hand."
  })
  appRegistered?: string;
  // WHO PUT THIS APPLICATION HERE ON PURPOSE (2026-09-18). appRegistered
  // above cannot answer it: it means RFC 7591 and is what RFC 9700 mode's
  // rules and RFC 7592's endpoints turn on, so an application an operator
  // created on /admin/applications/new stays FALSE there — and the list
  // page, reading only that flag, said "Registered: no" about an entry
  // somebody had just finished registering. This is the answer the page
  // wanted, kept apart so that giving it changes no protocol's behaviour.
  @attr(#{
    kind: "single",
    from: "this registry",
    what: "How this application was registered, when it was: \"administrator\" (created on /admin/applications/new or through the management API), \"rfc7591\" (POST /oauth2/register), \"ldap:<bound DN>\" (an LDAP add under ou=applications, #504; \"ldap\" for an unbound one) or \"startup\" (one of this service's own seeded clients). Absent on an application that simply turned up. Written by this registry and by an LDAP add, which keeps a value its author gave; an LDAP modify never stamps it. IN PRODUCT IT IS WHAT MAKES AN APPLICATION SERVED (#496): an entry without it — one a development sighting filed — is answered as no application at every protocol door."
  })
  appRegisteredBy?: string;
  // REGISTERED THROUGH AN OPENID FEDERATION (#134, 2026-09-23): an
  // application that became a client because its Trust Chain ended at one
  // of this realm's Trust Anchors (OpenID Federation for OpenID Connect
  // 1.1, section 12), how, until when and through which anchor. Past
  // appFederationExpiresAt the client is UNKNOWN to every endpoint
  // (clientConfigOf()) — 12.3: a registration may not outlive the chain it
  // was made from — and the oidfed.registrations-expire job removes it.
  @attr(#{
    kind: "single",
    from: "OpenID Federation (#134)",
    what: "\"automatic\" (its first signed authentication request) or \"explicit\" (its Entity Configuration POSTed to /oidfed/register)."
  })
  appFederationRegistration?: string;
  @attr(#{
    kind: "single",
    from: "OpenID Federation (#134)",
    what: "When the registration ends, in SECONDS since the epoch: the Trust Chain's own expiry, or oidfed.registrationLifetimeS if that comes first."
  })
  appFederationExpiresAt?: string;
  @attr(#{
    kind: "single",
    from: "OpenID Federation (#134)",
    what: "The Trust Anchor its chain ended at."
  })
  appFederationTrustAnchor?: string;
  @attr(#{
    kind: "multi",
    from: "OAuth 2.0 / OIDC / OpenID4VCI",
    identifier: true,
    identifierName: "client_id",
    what: "THE CLIENT_ID, and the identifier attribute of three families: an OpenID Connect relying party IS an OAuth client, and a wallet collecting a credential at the OpenID4VCI issuer authenticates as one, so all three declare their name here rather than in three attributes that would be three spellings of one fact. Usually equal to appIdentifier, which is what a protocol sighting writes and what a create writes when this is left empty (#393); a SECOND value is a client_id this application also answers to — a per-environment id — and is why this accumulates rather than being assigned. A list typed on the create is the whole list. Absent on an entry no OAuth family has been declared for."
  })
  oauthClientId?: string[];
  @attr(#{
    kind: "multi",
    from: "the console, the management API, or by hand",
    what: "THE AUDIENCE THIS APPLICATION ANSWERS TO — the `aud` an access token addressed to it carries, and what a client puts in RFC 8693 section 2.1's `audience` (or `resource`) when it exchanges a token to reach this application. It is the OAuth spelling of a fact three other families here already record under their own names: `wstrustAppliesTo` is the same thing in a RequestSecurityToken and `samlEntityId` is the same thing in an assertion's AudienceRestriction, and one attribute holding all three would be one string that has to mean whichever protocol asked last.\n\nIt is DECLARED — nobody presents an audience as their own name, so nothing here writes it and it cannot be derived — and it is a URI rather than a client_id because that is what an audience is: the resource, not the client that calls it. Several values is the ordinary case (a per-environment hostname), which is why it accumulates.\n\n**IT IS READ, WHICH MAKES IT THE EXCEPTION** among the declaration attributes beside it. The token exchange looks an `audience` UP here — forAudience() — so that a delegation recorded for `https://esb1.example.com` names the application `esb1` on /admin/delegation and in its picture, instead of drawing a box for a URL that nothing else in the register mentions. It is a LOOKUP and not a permission: an audience nobody registered is exchanged for exactly as before and recorded verbatim, because a service that refused would remove a test case rather than add one."
  })
  oauthAudience?: string[];
  @attr(#{
    kind: "multi",
    from: "POST /oauth2/register",
    sensitive: true,
    what: "THE SECRETS THIS SERVICE MINTED OR WAS GIVEN. Each value is SEALED under the key-encryption key wherever the process holds a durable one (since 2026-10-01), so a directory read, a database row and a backup hold ciphertext; without one (development) it is in the clear. The console and /admin-api, behind a credential, show it opened. Never written to the audit log.\n\nSEVERAL SINCE 2026-10-01, EACH A RECORD: {\"id\",\"secret\",\"created\",\"expires\",\"description\"}, the two times in seconds since the epoch and `expires` 0 for never. Every unexpired secret authenticates; the NEWEST unexpired one is the one this service signs and encrypts with and the client_secret RFC 7591 and 7592 return. A bare value (an ldapmodify, a set) is a secret with no expiry; a set REPLACES every secret, and the Credentials section adds, removes and rotates them one at a time, at most oauth2.clientSecretsMax."
  })
  oauthClientSecret?: string[];
  @attr(#{
    kind: "multi",
    from: "OAuth 2.0 / OIDC",
    what: "Registered redirect URIs from a registration, and any redirect_uri this service has ACCEPTED for the application beside them. The two are not the same claim and the registry does not merge them silently — see appRedirectUriObserved."
  })
  oauthRedirectUri?: string[];
  // UMA 2.0 (#1168, #1194): where the claims interaction endpoint returns
  // the requesting party, the Grant specification's section 3.3.2. A list
  // of its own, exact-match, and never an RFC 6749 redirect_uri unless it
  // is listed here too.
  @attr(#{
    kind: "multi",
    from: "the console, the management API, or by hand",
    what: "Where /uma/claims may send the requesting party back to this client after gathering claims (UMA 2.0 Grant section 3.3.2, claims_redirect_uri). Matched exactly; a claims_redirect_uri not listed here is told to the person and never redirected to."
  })
  oauthClaimsRedirectUri?: string[];
  @attr(#{
    kind: "multi",
    from: "OAuth 2.0 / OIDC",
    what: "A redirect_uri seen on an authorization request that this service answered. Kept apart from oauthRedirectUri because \"registered\" and \"used\" are different facts, and RFC 9700 section 2.1 is entirely about not confusing them: an exact-match check reads the registered list, and this one is evidence of what a client actually does."
  })
  appRedirectUriObserved?: string[];
  // PROVENANCE, NOT A SECOND LIST OF ADDRESSES (2026-09-12). The attribute
  // above holds what a client USED and nothing ever trusts it. This one is a
  // MARK on a value that IS in a trusted list — a return address that got
  // onto `samlAssertionConsumerService`, `wsfedReplyUrl` or
  // `oauthRedirectUri` because a development-mode request named it rather
  // than because anybody registered it. ONE attribute carrying `<attribute>
  // <value>` rather than one per family: the families are
  // RETURN_ADDRESS_ATTRIBUTES, derived from the PROTOCOLS table, so a family
  // added tomorrow is marked the day it is added and the schema does not grow
  // a row per family for the privilege. The attribute name goes FIRST because
  // it has no space in it and the URL takes the remainder — `consent.js`'s
  // rule about which field is unconstrained. DERIVED, so it is in no EDITABLE
  // row: it is removed by confirming, discarding, or writing the address
  // explicitly.
  @attr(#{
    kind: "multi",
    from: "a development-mode sighting",
    what: "WHICH RETURN ADDRESSES ON THIS ENTRY WERE NEVER REGISTERED BY ANYBODY. Each value is `<attribute> <address>` — for example `samlAssertionConsumerService https://sp.example.com/acs` — and marks an address a DEVELOPMENT-mode request named, which development writes onto the entry because it believes every address. PRODUCT mode treats a marked address as NOT registered and refuses it exactly as it refuses one that is not on the entry at all, so a realm switched from development to product does not quietly trust what development learnt. An operator CONFIRMS one (the mark goes, the address stays), DISCARDS one (both go), or writes the address explicitly, which confirms it. Addresses recorded BEFORE this attribute existed carry no mark and cannot be told apart from registered ones — review those by hand."
  })
  appReturnAddressObserved?: string[];
  @attr(#{
    kind: "multi",
    from: "POST /oauth2/register",
    what: "Registered post_logout_redirect_uris, which RP-Initiated Logout matches against exactly, in every mode (#124)."
  })
  oauthPostLogoutRedirectUri?: string[];
  @attr(#{
    kind: "single",
    from: "POST /oauth2/register, the console, or by hand",
    what: "WHERE THIS CLIENT IS TOLD THAT THE USER SIGNED OUT — OpenID Connect Front-Channel Logout 1.0 section 2's frontchannel_logout_uri. The sign-out page loads it in a hidden iframe, with iss and sid on the query string when the client asked for them. It is SINGLE-valued because the specification defines one URI per client, unlike the redirect URIs beside it; a client with none registered is not notified at all and is listed on /logout as such rather than silently skipped."
  })
  oauthFrontchannelLogoutUri?: string;
  @attr(#{
    kind: "single",
    from: "POST /oauth2/register, the console, or by hand",
    what: "TRUE if this client requires `iss` and `sid` on the notification above — Front-Channel Logout 1.0 section 2's frontchannel_logout_session_required. It matters because an RP with several sessions in one browser cannot tell which one ended without the sid, and RFC 7591 section 2 makes an omitted boolean FALSE rather than unknown — so an absent value here means the client did not ask, which is a different fact from the client not having registered."
  })
  oauthFrontchannelLogoutSessionRequired?: string;
  @attr(#{
    kind: "single",
    from: "POST /oauth2/register, the console, or by hand",
    what: "WHERE THIS SERVICE POSTS A LOGOUT TOKEN WHEN THE USER SIGNS OUT — OpenID Connect Back-Channel Logout 1.0 section 2.2's backchannel_logout_uri. Every sign-out of a session this client was issued an authorization response on sends one, server-to-server, after the sign-out has answered, through the outbound policy (https with the certificate verified; no internal address in product mode). SINGLE-valued, like the front-channel URI: the specification defines one per client. https with no fragment; http only for a confidential client and only where the outbound policy sends over http (federation.outboundAllowHttp, development mode; section 2.2, #123)."
  })
  oauthBackchannelLogoutUri?: string;
  @attr(#{
    kind: "single",
    from: "POST /oauth2/register, the console, or by hand",
    what: "TRUE if this client requires `sid` in the Logout Token — Back-Channel Logout 1.0 section 2.2's backchannel_logout_session_required. This service puts `sid` AND `sub` in every Logout Token it sends, so the flag is always honoured; it is recorded because \"false\" and \"not stated\" are different facts about a client, as for the front-channel flag."
  })
  oauthBackchannelLogoutSessionRequired?: string;
  // DECLARED, AND ENFORCED (#289, 2026-10-07). Until then both lists were
  // also where a sighting wrote what a client USED, so they grew with use
  // and could restrict nothing, and only a registration document held a
  // client to its flows. The sightings moved to the two *Observed rows
  // below, as appRedirectUriObserved sits beside oauthRedirectUri.
  @attr(#{
    kind: "multi",
    from: "OAuth 2.0 / OIDC",
    what: "The grant types this client may use — RFC 7591 section 2's grant_types, from a registration or written by an administrator. The token endpoint refuses any other grant (unauthorized_client), in every mode; an empty list restricts nothing. What the client has actually used is oauthGrantTypeObserved."
  })
  oauthGrantType?: string[];
  @attr(#{
    kind: "multi",
    from: "OAuth 2.0 / OIDC",
    what: "The response_type values this client may ask for — RFC 7591 section 2's response_types, from a registration or written by an administrator, each value one response type (\"code\", \"code id_token\"). The authorization endpoint refuses any other (unauthorized_client), in every mode; an empty list restricts nothing. What the client has actually asked for is oauthResponseTypeObserved."
  })
  oauthResponseType?: string[];
  // ---------------------------------------------------------------------
  // THE TOKEN RESPONSE TYPES, ENABLED PER APPLICATION (#1296, rcbj's
  // decision, 2026-11-03: "a realm allowing the token response types must
  // not turn them on for every client. The realm setting makes them
  // POSSIBLE; each application still has to have the specific flow
  // ENABLED by an administrator or by its owner").
  //
  // A SEPARATE ATTRIBUTE FROM `oauthResponseType`, and not a reading of
  // it, for two reasons. `oauthResponseType` is what a client DECLARED it
  // would use, and an empty list there restricts nothing (#289) — so a
  // client that declares nothing would have every token response type the
  // moment a realm waived section 2.1.2, which is the exact outcome this
  // row exists to prevent. And a registration writes that one verbatim,
  // where it writes this one only within
  // `oauth2.dynamicRegistrationTokenResponseTypes`. So this list is a
  // PERMISSION whose empty value means NONE, read beside the declaration
  // rather than instead of it: the authorization endpoint asks both.
  //
  // READ ONLY WHERE RFC 9700 MODE IS IN FORCE (which product mode always
  // is), by `oauth2_bcp.js`'s checkAuthorizationRequest(): outside that
  // mode section 2.1.2 is not enforced and nothing here narrows it. Added
  // only while the realm allows the token response types
  // (`oauth2_bcp.js`'s tokenResponsesAllowed()), so the console and
  // `/admin-api` cannot record a permission the realm would refuse — the
  // registration endpoint's mirror rule (rule 3f) applied to an
  // administrator's write. Owners may write it: it is on the
  // access-control template's default `ownerApplicationAttributes` (rule
  // 3cn), rcbj's decision.
  @attr(#{
    kind: "multi",
    from: "OAuth 2.0 / OIDC",
    what: "The response types that issue an access token from the authorization endpoint — token, code token, id_token token, code id_token token — this client may use where RFC 9700 mode is in force (product mode always is). Honoured only while the realm waives RFC 9700 section 2.1.2 (oauth2.allowImplicitTokenResponses, never under OAuth 2.1 or FAPI); then a type not listed here is refused (unauthorized_client). EMPTY BY DEFAULT, and empty means none. Written by an administrator or the application's owner while the realm allows these types, or by a dynamic registration within oauth2.dynamicRegistrationTokenResponseTypes. RFC 9700 section 2.1.2 says clients SHOULD NOT use them."
  })
  oauthAllowedTokenResponseTypes?: string[];
  @attr(#{
    kind: "multi",
    from: "OAuth 2.0 / OIDC",
    what: "A grant type this client was seen using at the token endpoint. A record, not a permission: oauthGrantType is what it may use."
  })
  oauthGrantTypeObserved?: string[];
  @attr(#{
    kind: "multi",
    from: "OAuth 2.0 / OIDC",
    what: "A response_type this client was seen asking for at the authorization endpoint. A record, not a permission: oauthResponseType is what it may ask for."
  })
  oauthResponseTypeObserved?: string[];
  @attr(#{
    kind: "multi",
    from: "OAuth 2.0 / OIDC",
    what: "Scopes this application has ASKED FOR, accumulated as it asks. SIGHTED, never declared: nothing is allowed or refused by it. What the application may be issued is oauthAllowedScope."
  })
  oauthScope?: string[];
  // ---------------------------------------------------------------------
  // THE DECLARED TWIN OF `oauthScope` (#110, 2026-09-22), and the
  // `appProtocol` / `appAllowedProtocol` split again: one attribute is what
  // happened and the other is what somebody said. Until that day an RFC
  // 7591 registration's `scope` was written onto `oauthScope` beside every
  // scope the client had merely asked for, so what was declared and what was
  // observed could not be told apart — and nothing read either as a limit.
  //
  // IT IS READ, in three places. The authorization, pushed authorization and
  // token endpoints refuse a scope it does not list (`common/scope_policy.ts`
  // decides which, and in which mode); `tokenSet()` narrows a refresh or an
  // exchange to it; and the resource servers behind this service's own
  // protected scopes — /admin-api, /scim/v2, the Shared Signals endpoints —
  // ask it again on every call, so removing a value cuts off a token already
  // issued. GNAP reads it for the Shared Signals access rights.
  //
  // NOT FAMILY-SCOPED, deliberately. A SCIM or Shared Signals client is
  // declared for that family and still gets its token from /oauth2/token;
  // refusing the declaration on its entry would refuse the one thing it
  // needs.
  // ---------------------------------------------------------------------
  @attr(#{
    kind: "multi",
    from: "POST /oauth2/register (its `scope`), the console, the management API, or by hand",
    what: "THE SCOPES THIS CLIENT MAY BE ISSUED — RFC 7591 section 2's `scope`, \"the list that the client can use when requesting access tokens\". One scope token per value. Three kinds of scope read it differently.\n\n**This service's own protected scopes** — admin:read and admin:write (/admin-api), report:use and report:admin (/report-api), the SCIM scopes (scim.scopeRead, scim.scopeWrite), the Shared Signals scopes (ssf.authScopeRead, ssf.authScopeWrite, and always ssf.read and ssf.manage) and the debugger permission — are issued ONLY to a client that lists them, IN BOTH MODES. For Shared Signals, write includes read: listing a write scope authorizes the read scope too, and listing only a read scope does not authorize a write scope. The resource server behind each asks again on every call, so removing a value here cuts off tokens already issued. An RFC 7591 registration may not declare them; an administrator does, here.\n\n**Every other scope**, in product mode, is issued only when listed here — or, when nothing is listed, when it is in the default set: openid, profile, email, address, phone, offline_access and this realm's OpenID4VCI credential scopes. In development any scope is issued.\n\n**A scope naming an application or a delegated permission** keeps its own rules (the audience, and oauthDelegatedPermission) and need not be listed.\n\nA scope outside the list is refused invalid_scope at the authorization and token endpoints (RFC 6749 section 3.3), and taken off a refresh or a token exchange. Distinct from oauthScope, which is only what the client has asked for."
  })
  oauthAllowedScope?: string[];
  // --- delegated permissions: the RESOURCE half, then the CLIENT half -----
  //
  // THREE ATTRIBUTES THAT ARE ONE FEATURE, AND THEY ARE THE FIRST THING IN
  // THIS SCHEMA WHERE ONE ENTRY'S VALUE IS ONLY MEANINGFUL AGAINST ANOTHER
  // ENTRY'S. Everything above describes the application it is on. A GRANT
  // does not: `oauthDelegatedPermission` on webapp1 is a fact about webapp1
  // AND about the resource whose permission it names, and neither entry is
  // complete on its own. That is what makes this a RELATIONSHIP rather than
  // one more declaration, and it is why `common/app_permissions.ts` exists to
  // read the two halves together — see its header, which argues the model.
  //
  // The shape is Microsoft Entra ID's, deliberately and by name: a resource
  // application EXPOSES an API (`oauth2PermissionScopes` there) and a client
  // application is granted delegated permissions on it
  // (`requiredResourceAccess`). Two attributes on two entries, one value per
  // relationship, so one client granted three permissions is three values and
  // three clients granted one permission is three values on three entries —
  // which is how 1-to-many and many-to-1 both fall out of the same attribute
  // without a container of their own.
  @attr(#{
    kind: "single",
    from: "the console, the management API, or by hand",
    what: "THE BASE URI EVERY PERMISSION THIS APPLICATION DEFINES HANGS OFF, and the thing that makes a permission name globally unique here. A permission is identified by this value followed by its name — base `https://example.com/` and name `write` are the permission `https://example.com/write` — which is what a client puts in a `scope` and what the access token is then AUDIENCED to. Entra ID calls it the Application ID URI and spells it `api://<guid>`; the shape is the same and nothing here requires that scheme.\n\nIT IS NORMALISED TO END IN A SEPARATOR when it is written through this module — a trailing `/` is added where there is no `/`, `#` or `:` at the end — because base + name is a plain concatenation and `https://example.com` + `write` would otherwise produce `https://example.comwrite`. An `ldapmodify` reaches this attribute like every other and is not normalised, so a base written by hand means exactly what it says.\n\nSINGLE-VALUED, and it is the one attribute in this group that could not be widened without deciding something: two bases would mean every permission on the entry had two identifiers, and the lookup that turns a scope into an audience would have to pick one to put in `aud`."
  })
  oauthPermissionBaseUri?: string;
  @attr(#{
    kind: "multi",
    from: "the console, the management API, or by hand",
    what: "ONE PERMISSION THIS APPLICATION EXPOSES, one value each. The value is the permission's NAME — `read`, `write`, `Widgets.ReadWrite.All` — optionally followed by `|` and a description: `write|Change widgets on somebody's behalf`. The FIRST `|` is the delimiter and every later one belongs to the description, so a description may contain the character and a name may not.\n\nThe name must be a legal OAuth scope token (RFC 6749 section 3.3 — no space, no double quote, no backslash), because that is what a client will put in a `scope` parameter and what comes back on the token's `scope` claim. A name or a description containing an operator error code is refused too: both are returned on every page that lists the permission, and a code is recorded rather than sent. Nothing enforces either rule when an `ldapmodify` writes the value; this module and both consoles do.\n\nA PERMISSION MUST EXIST BEFORE ANYTHING CAN BE GRANTED IT, which is the one ordering rule this feature has and is checked in updateApplication() so that the console form and the management API cannot disagree about it. It is checked on the GRANT and not here: this attribute is the definition, and a definition nobody has used yet is the ordinary first step rather than a mistake."
  })
  oauthPermission?: string[];
  // WHICH OF THIS APPLICATION'S PERMISSIONS NEED A ROLE (#303, part B of
  // #88, 2026-09-27). rcbj's decision 1 on #88: a permission is gated by
  // role only where its RESOURCE application says so, so every existing
  // client keeps behaving as it did until an operator opts a permission
  // in. The role side is `rolePermission` on a role entry
  // (`common/roles.js`); the question is `common/role_permissions.ts`'s.
  @attr(#{
    kind: "multi",
    from: "the console, the management API, or by hand",
    what: "A PERMISSION THIS APPLICATION DEFINES THAT IS ISSUED ONLY TO A SUBJECT HOLDING A ROLE THAT AUTHORIZES IT. One value each, the permission's NAME as `oauthPermission` gives it (`write`, not the full identifier). A person or an application asking for a gated permission is issued it only while they hold a role whose `rolePermission` names the full identifier (base + name); otherwise it is left off the token (RFC 6749 section 3.3), and a request asking for nothing else is refused `invalid_scope`. A permission not listed here is issued as it always was, which is what keeps every existing client working until somebody opts in.\n\nThe name must be one of this entry's own permissions when it is written through this module; an `ldapmodify` is not checked, and a value naming no defined permission gates nothing, because no request can name it."
  })
  oauthRoleGatedPermission?: string[];
  // THE RFC 9728 DOCUMENT THIS APPLICATION WAS CREATED FROM (2026-09-13).
  // /admin/applications/new can be handed a protected resource's metadata
  // document and turn it into an entry; the members with an attribute of
  // their own are written to those attributes, and this keeps the whole
  // document beside them — `samlSpMetadata`'s arrangement, for its reason: a
  // setting with the document it came from missing is a value nobody can
  // check. DECLARATION ONLY: nothing in this service reads it back.
  @attr(#{
    kind: "single",
    from: "an RFC 9728 import, the console, the management API, or by hand",
    what: "THE PROTECTED RESOURCE METADATA DOCUMENT (RFC 9728) THIS APPLICATION WAS CONFIGURED FROM, as compact JSON. Its `resource` is the default name, `oauthPermissionBaseUri` and `oauthAudience` of an entry created from it, and its `scopes_supported` the permissions; every other member — `authorization_servers`, `jwks_uri`, `bearer_methods_supported`, the DPoP members — is recorded here and nowhere else.\n\nIt is DECLARATION ONLY: nothing reads it back, nothing re-fetches it, and changing it changes none of the attributes it filled in. A value written through this module must be a JSON object with a `resource`; an `ldapmodify` is not checked."
  })
  oauthResourceMetadata?: string;
  @attr(#{
    kind: "single",
    from: "an RFC 9728 import, the console, the management API, or by hand",
    what: "WHERE THE PROTECTED RESOURCE METADATA DOCUMENT WAS FETCHED FROM, when it was fetched rather than pasted or uploaded. Recorded and never dialled again: the fetch is an administrator's act on /admin/applications/new or POST /admin-api/applications/load-resource-metadata, and nothing refreshes it."
  })
  oauthResourceMetadataUrl?: string;
  @attr(#{
    kind: "multi",
    from: "the console, the management API, or by hand",
    what: "A PERMISSION THIS APPLICATION HAS BEEN GRANTED ON ANOTHER ONE — the whole permission identifier, base URI and name together: `https://example.com/write`. It is the DELEGATION RELATIONSHIP, and it is held on the CLIENT rather than on the resource for Entra's reason and one more: the client is the party that will name it in a `scope`, so the entry that answers \"may this request be honoured\" is the entry the request identifies.\n\n**IT IS READ, and it is read in the one place that decides what a token says.** A `scope` value matching a defined permission becomes the access token's `aud` (the base URI) and its `scope` (the name) — see oauth2.js's audienceScopes(). In PRODUCT MODE an ungranted permission is refused `invalid_scope` at the authorization and token endpoints, always. In development it is reported and REFUSES nothing unless `oauth2.delegatedPermissionsEnforced` is on, which is off by default: a client under test is exercised by both answers.\n\nA VALUE THAT RESOLVES TO NO DEFINED PERMISSION IS NOT AN ERROR AND IS NOT HIDDEN. The resource's entry may have been deleted, or the permission removed from under it; `/admin/delegation` shows such a grant as DANGLING, which is the same three-state honesty the rest of this console applies to a name it cannot resolve."
  })
  oauthDelegatedPermission?: string[];
  // --- consent: the OVERRIDE half ------------------------------------------
  //
  // THE SECOND ATTRIBUTE HERE WHOSE VALUE IS ABOUT SOMEBODY ELSE, and it is
  // about a different somebody else from the three above. A delegated
  // permission is a relationship between two APPLICATIONS; this is a
  // statement about every PERSON who will ever sign in to this one. That is
  // why it is a separate attribute from `oauthDelegatedPermission` rather
  // than a flag on it: a client may hold a permission nobody has consented
  // to, and a person may consent a scope the client was never granted, and
  // /admin/consent exists to show the difference.
  @attr(#{
    kind: "multi",
    from: "the console, the management API, or by hand",
    what: "A SCOPE NOBODY IS ASKED ABOUT WHEN THEY SIGN IN TO THIS APPLICATION. One value per scope, written exactly as a client puts it in a `scope` parameter — `openid`, `profile`, or a whole delegated permission identifier such as `https://example.com/write`.\n\n**It is an OVERRIDE and not a record.** With `oauth2.consentRequired` on (which is the default), the authorization endpoint draws /oauth2/consent for any scope this person has not agreed to for this application; a scope named here is skipped for EVERYBODY, and nothing is written to anybody's entry. So removing a value asks everybody again — including the people who would have said yes — where removing a person's own `oauthConsent` asks only them.\n\n**It is keyed on the pair and not on the scope alone.** Consenting `read` here consents it for THIS application; an application registered five minutes later that spells the same word is still asked.\n\nA value that names no permission any application defines is not an error and is not hidden — most scopes are not permissions. It must be a legal RFC 6749 section 3.3 scope token, because a value with a space in it could never match one scope; an `ldapmodify` reaches this attribute like every other and is not checked, and /admin/consent shows what it put there."
  })
  oauthGlobalConsent?: string[];
  // WHEN AN OVERRIDE ABOVE WAS WITHDRAWN (#172), one value per scope. NOT
  // editable, and that is the point of it: it is what stops a RE-ADDED
  // override reviving the refresh tokens issued under the one that was
  // taken away, so a form that could remove it would be a form that could
  // bring a withdrawn grant back. `common/consent.ts` writes it, through
  // `noteGlobalConsentWithdrawn()` below, and nothing else does.
  // WHO ANSWERS FOR THE APPLICATION (#604): people and groups of this
  // realm, by DN, the rule a group's and a role's owners follow. Written by
  // the application page's Owners tab alone (addOwner(), removeOwner()),
  // so it is in no EDITABLE row and the field grid never draws it.
  @attr(#{
    kind: "multi",
    from: "the application page's Owners tab",
    what: "A person or a group of this realm who answers for the application (#604), by DN, as a group's and a role's owners are. Multi-valued, at most 25. Since #607 an owner may ADMINISTER the application through /admin-api with owner:read and owner:write, within what the access-control policy's owner rule allows. The user portal lists what a person owns."
  })
  appOwner?: string[];
  // CLOSED TO ITS OWNERS (#607, rcbj's decision 4): an administrator's
  // mark, written by `setOwnerProtected()` alone, so it is in no EDITABLE
  // row either.
  @attr(#{
    kind: "single",
    from: "POST /admin-api/ownership/set-protected",
    what: "TRUE: the application's owners may not administer it through /admin-api (#607) — an administrator's mark, read by the access-control policy's owner rule as urn:sts:xacml:object-protected. Absent is FALSE."
  })
  stsOwnerProtected?: string;
  @attr(#{
    kind: "multi",
    from: "the consent register, when a global consent is withdrawn",
    what: "WHEN A GLOBAL CONSENT WAS WITHDRAWN, as `<when> <scope>` with the instant to the millisecond. The refresh grant refuses a refresh token granted before it that stood on that override, even after the override is added back — a withdrawn grant is not revived by the next one. One value per scope; a later withdrawal replaces the earlier. Written by the consent register and never by a form."
  })
  oauthGlobalConsentWithdrawn?: string[];
  // SEVERAL SINCE 2026-10-01 (rcbj): a client may hold a secret AND a key
  // pair and present either, so the entry lists every method it may use and
  // the token endpoint accepts the one a request presents
  // (`client_auth.methodFor()`). `none` stands alone — it is what makes a
  // client PUBLIC, and a client that is public and also authenticates is
  // two contradictory declarations (`authMethodsProblem()`). The FIRST
  // value is what RFC 7591's single-valued member reports.
  @attr(#{
    kind: "multi",
    from: "POST /oauth2/register",
    what: "How it authenticates — every method it may use at the token endpoint, any one of which a request may present. `none` (a public client) cannot be held with any other. RFC 7591 section 2 makes client_secret_basic the default when a registration omits it, which is why an omission means CONFIDENTIAL rather than unknown."
  })
  oauthTokenEndpointAuthMethod?: string[];
  // OPENID CONNECT NATIVE SSO FOR MOBILE APPS 1.0 (#130, 2026-09-23).
  @attr(#{
    kind: "single",
    from: "the console, the management API, or a TRUSTED software statement at POST /oauth2/register",
    families: #["oidc"],
    familyWhy: "Native SSO is an OpenID Connect profile: the device_sso scope, the ds_hash in an ID Token, and the exchange of one.",
    what: "TRUE lets this client ask for the device_sso scope — and so be handed a device_secret — and take part in a Native SSO token exchange, as the first app or the second. Anything else, the default, refuses both. Both apps of an exchange must hold it AND share oauthNativeSsoGroup. A registration may set it only through a trusted software statement, because the group is the boundary and a client may not choose its own."
  })
  oauthNativeSso?: string;
  @attr(#{
    kind: "single",
    from: "the console, the management API, or a TRUSTED software statement at POST /oauth2/register",
    families: #["oidc"],
    familyWhy: "The same profile as oauthNativeSso.",
    what: "The Native SSO group: the apps that may share one device session — in practice one vendor's. A token exchange is refused unless the app that received the ID Token and the app asking share it. 1 to 64 of letters, digits and . _ : -; an empty or malformed value takes the client out of Native SSO."
  })
  oauthNativeSsoGroup?: string;
  // OPENID CONNECT CIBA CORE 1.0 SECTION 4 (#131, 2026-09-23): the four
  // registration members, from a registration, the console or the API.
  @attr(#{
    kind: "single",
    from: "POST /oauth2/register, the console, the management API",
    families: #["oidc"],
    familyWhy: "CIBA is an OpenID Connect flow: it issues an ID Token.",
    what: "CIBA `backchannel_token_delivery_mode`: poll, ping or push. A client with none may not use the Backchannel Authentication Endpoint at all."
  })
  oauthBackchannelTokenDeliveryMode?: string;
  @attr(#{
    kind: "single",
    from: "POST /oauth2/register, the console, the management API",
    families: #["oidc"],
    familyWhy: "The same flow as oauthBackchannelTokenDeliveryMode.",
    what: "CIBA `backchannel_client_notification_endpoint`: the https URL a ping or a push is POSTed to, under the outbound policy. Required for ping and push."
  })
  oauthBackchannelClientNotificationEndpoint?: string;
  @attr(#{
    kind: "single",
    from: "POST /oauth2/register, the console, the management API",
    families: #["oidc"],
    familyWhy: "OpenID Provider Commands are sent to OpenID Connect relying parties.",
    what: "OpenID Provider Commands `command_endpoint` (#151): the https URL a Command Token is POSTed to, under the outbound policy. A client with none is sent no command."
  })
  oauthCommandEndpoint?: string;
  @attr(#{
    kind: "single",
    from: "POST /oauth2/register, the console, the management API",
    families: #["oidc"],
    familyWhy: "The same flow as oauthBackchannelTokenDeliveryMode.",
    what: "CIBA `backchannel_authentication_request_signing_alg`: when set, every authentication request from this client must be a signed request object with this algorithm (section 7.1.1)."
  })
  oauthBackchannelAuthenticationRequestSigningAlg?: string;
  @attr(#{
    kind: "single",
    from: "POST /oauth2/register, the console, the management API",
    families: #["oidc"],
    familyWhy: "The same flow as oauthBackchannelTokenDeliveryMode.",
    what: "TRUE: every authentication request from this client carries the person's `user_code` (CIBA section 7.1), a secret the person set on /portal/ciba, which stops a client that knows only a name from sending them requests."
  })
  oauthBackchannelUserCodeParameter?: string;
  // OPENID CONNECT CORE SECTION 8 AND SECTION 9 (#118, 2026-09-22).
  @attr(#{
    kind: "single",
    from: "POST /oauth2/register, the console, the management API, or by hand",
    families: #["oidc"],
    familyWhy: "It decides which `sub` an ID Token and a UserInfo response name this person by, which only an OpenID Connect client is given.",
    what: "OIDC Core section 8 `subject_type`: `public` (the default, and what an empty value means) gives every client the same `sub`; `pairwise` gives this client one of its own, derived from the person, the sector and a secret every node shares, so two clients of different sectors cannot correlate one person; `ephemeral` (#149) gives it a random one for each authentication, the same for everything that authentication issues and never again after."
  })
  oauthSubjectType?: string;
  @attr(#{
    kind: "single",
    from: "POST /oauth2/register, the console, the management API, or by hand",
    families: #["oidc"],
    familyWhy: "It is the sector a pairwise `sub` is computed for.",
    what: "OIDC Core section 8.1 `sector_identifier_uri`: an https URL whose HOST is the sector a pairwise `sub` is derived for, so several redirect hosts of one organisation see one subject. A REGISTRATION that names one has it FETCHED and must be listed in the JSON array it serves, every redirect URI of it; one written here by an administrator is the administrator's statement and is not fetched. Empty: the sector is the host of the redirect URIs, which must then all share one."
  })
  oauthSectorIdentifierUri?: string;
  // THE `did` CLAIM AGAINST A PAIRWISE SUBJECT (#693, phase 2).
  @attr(#{
    kind: "single",
    from: "the console, the management API, or by hand",
    families: #["oidc"],
    familyWhy: "It decides whether an ID Token and a UserInfo response may carry the did claim, which only an OpenID Connect client is given.",
    what: "TRUE: this client may be told the person's preferred DID (the `did` claim, oauth2.didClaim) although it uses pairwise or ephemeral subject identifiers. Anything else, and for a public-subject client it does not matter: never. A pairwise or ephemeral `sub` exists so that this client cannot correlate the person with other clients, and a DID is the same value at every client that is told it, which defeats that — set it only where this client is meant to know the person by their DID anyway. Not settable by a registration."
  })
  oauthDidClaimWithPairwise?: string;
  @attr(#{
    kind: "single",
    from: "POST /oauth2/register, the console, the management API, or by hand",
    families: #["oauth2", "oidc"],
    familyWhy: "It decides which signature a private_key_jwt or client_secret_jwt assertion at the token endpoint must carry.",
    what: "OIDC Core section 9 / RFC 7591 `token_endpoint_auth_signing_alg`: the ONE JWS algorithm this client's authentication assertion must be signed with. An assertion signed with any other is refused, in every mode. Empty: any algorithm the method allows."
  })
  oauthTokenEndpointAuthSigningAlg?: string;
  @attr(#{
    kind: "single",
    from: "POST /oauth2/register, or by hand",
    what: "THE CLIENT'S PUBLIC KEYS, as a JWKS document — what private_key_jwt is verified against (RFC 7591 `jwks`). This is the asymmetric credential RFC 9700 section 2.5 RECOMMENDS, and it is the one credential attribute here that is NOT a secret: it is public key material, worth nothing to anybody who reads it, which is the whole point of preferring it to a shared secret."
  })
  oauthJwks?: string;
  @attr(#{
    kind: "single",
    from: "POST /oauth2/register",
    what: "RFC 7591 `jwks_uri`, https. FETCHED since #120, when a key is needed, under federation/federation_http.ts's outbound policy (https, no redirect, a size cap, internal addresses refused in product mode), cached for oauth2.clientJwksCacheS and fetched again for an unknown kid at most every oauth2.clientJwksRefetchS. Never beside `oauthJwks`: RFC 7591 section 2 allows one or the other."
  })
  oauthJwksUri?: string;
  // -------------------------------------------------------------------
  // RFC 9701 (2026-09-13). THE THREE CLIENT METADATA MEMBERS OF SECTION 6,
  // each an attribute of its own, and they are READ: `/oauth2/introspect`
  // signs — and where asked, encrypts — the JWT response it gives THIS
  // client as a resource server with what they say.
  //
  // `single`, for the override attributes' reason: an algorithm has one
  // answer and a list has no rule for which one signs. Family-scoped like
  // `oauthTokenExchangeRefreshToken`, because what they change is what an
  // OAuth endpoint sends one client_id, and on an entry no introspection
  // request can name they would read like a registration in force. The
  // VALUES are checked on every write door by introspectionResponseProblem()
  // below — the list is `common/crypto.js`'s own, so a value this service
  // cannot sign or encrypt with cannot be stored.
  @attr(#{
    kind: "single",
    from: "POST /oauth2/register, the console, the management API, or by hand",
    families: #["oauth2", "oidc"],
    familyWhy: "It decides how /oauth2/introspect signs the JWT response it gives this client, so on an entry declared for neither OAuth family it would sit there reading like a registration in force.",
    what: "RFC 9701 section 6 `introspection_signed_response_alg`: the JWS algorithm of the JWT introspection response this application receives when it asks /oauth2/introspect with `Accept: application/token-introspection+jwt`. EMPTY MEANS RS256, the section's default. Any algorithm in `introspection_signing_alg_values_supported` — every asymmetric one this service holds a key for, and HS256/384/512 keyed with this application's own client_secret. `none` is refused: section 5 says the response MUST be cryptographically secured."
  })
  oauthIntrospectionSignedResponseAlg?: string;
  @attr(#{
    kind: "single",
    from: "POST /oauth2/register, the console, the management API, or by hand",
    families: #["oauth2", "oidc"],
    familyWhy: "It decides whether /oauth2/introspect encrypts the JWT response it gives this client, so on an entry declared for neither OAuth family it would sit there reading like a registration in force.",
    what: "RFC 9701 section 6 `introspection_encrypted_response_alg`: the JWE key management algorithm the signed introspection response is ENCRYPTED to this application with, making it a Nested JWT. EMPTY MEANS NOT ENCRYPTED. One of the asymmetric algorithms (RSA-OAEP, RSA-OAEP-256, ECDH-ES and its key-wrap variants), and the key is taken from this entry's `oauthJwks`, or the set its `oauthJwksUri` answers (#120). The symmetric families are refused: they are for a document encrypted TO this service."
  })
  oauthIntrospectionEncryptedResponseAlg?: string;
  @attr(#{
    kind: "single",
    from: "POST /oauth2/register, the console, the management API, or by hand",
    families: #["oauth2", "oidc"],
    familyWhy: "It decides how /oauth2/introspect encrypts the JWT response it gives this client, so on an entry declared for neither OAuth family it would sit there reading like a registration in force.",
    what: "RFC 9701 section 6 `introspection_encrypted_response_enc`: the JWE content encryption algorithm. EMPTY MEANS A128CBC-HS256 once `oauthIntrospectionEncryptedResponseAlg` is set. It MUST NOT be set without that attribute, and a write that tries is refused; an entry left holding one alone (by `ldapmodify`, or by clearing the algorithm) makes the JWT introspection response fail with the reason rather than go out unencrypted."
  })
  oauthIntrospectionEncryptedResponseEnc?: string;
  // -------------------------------------------------------------------
  // RFC 9101 AND OPENID CONNECT DYNAMIC CLIENT REGISTRATION (2026-09-13).
  // FIVE MEMBERS a client registers about the REQUEST OBJECTS it sends to
  // the authorization endpoint, each an attribute, and all five READ by
  // `oauth-oidc/request_object.ts`. Family-scoped for the introspection
  // attributes' reason.
  //
  // `oauthRequestUri` IS THE ONE THAT MATTERS MOST, because it is the whole
  // of what makes fetching a request_uri defensible: this service dials a
  // request_uri ONLY when it is one of these values, exactly, so the URL a
  // request names was declared on the client's entry beforehand rather than
  // chosen by whoever sent the request. `multi`, because a client serving
  // request objects from several places is one client.
  @attr(#{
    kind: "multi",
    from: "POST /oauth2/register, the console, the management API, or by hand",
    families: #["oauth2", "oidc"],
    familyWhy: "It is the list of request_uri values /oauth2/authorize will fetch for this client, so on an entry declared for neither OAuth family it would sit there reading like a permission to dial those URLs.",
    what: "OpenID Connect Registration `request_uris`: the request_uri values (RFC 9101 section 5.2) this client may send, one per line. THE AUTHORIZATION ENDPOINT FETCHES A request_uri ONLY WHEN IT IS ONE OF THESE, compared exactly once any #fragment is removed — a request_uri nobody registered is refused invalid_request_uri and never dialled, which is what keeps the fetch from being a server-side request forgery. https, or http in development mode only."
  })
  oauthRequestUri?: string[];
  @attr(#{
    kind: "single",
    from: "POST /oauth2/register, the console, the management API, or by hand",
    families: #["oauth2", "oidc"],
    familyWhy: "It decides which request objects /oauth2/authorize accepts from this client, so on an entry declared for neither OAuth family it would read like a restriction in force.",
    what: "OpenID Connect Registration `request_object_signing_alg`: the ONLY JWS algorithm a request object from this client is accepted in. EMPTY MEANS ANY algorithm in request_object_signing_alg_values_supported. `none` may be registered only where an unsigned request object is accepted at all — development mode, with no signed one required."
  })
  oauthRequestObjectSigningAlg?: string;
  @attr(#{
    kind: "single",
    from: "POST /oauth2/register, the console, the management API, or by hand",
    families: #["oauth2", "oidc"],
    familyWhy: "It decides which request objects /oauth2/authorize accepts from this client, so on an entry declared for neither OAuth family it would read like a restriction in force.",
    what: "OpenID Connect Registration `request_object_encryption_alg`: when set, a request object from this client MUST be encrypted (RFC 9101 section 6.1) with this JWE key management algorithm — to this realm's request object key published in /oauth2/jwks (use: enc) for RSA-OAEP and ECDH-ES, or to this client's own client_secret for the symmetric families. EMPTY MEANS encryption is optional."
  })
  oauthRequestObjectEncryptionAlg?: string;
  @attr(#{
    kind: "single",
    from: "POST /oauth2/register, the console, the management API, or by hand",
    families: #["oauth2", "oidc"],
    familyWhy: "It decides which request objects /oauth2/authorize accepts from this client, so on an entry declared for neither OAuth family it would read like a restriction in force.",
    what: "OpenID Connect Registration `request_object_encryption_enc`: the JWE content encryption a request object from this client must use. EMPTY MEANS A128CBC-HS256 once `oauthRequestObjectEncryptionAlg` is set; it may not be set without that attribute."
  })
  oauthRequestObjectEncryptionEnc?: string;
  @attr(#{
    kind: "single",
    from: "POST /oauth2/register, the console, the management API, or by hand",
    families: #["oauth2", "oidc"],
    familyWhy: "It decides whether /oauth2/authorize refuses a plain request from this client, so on an entry declared for neither OAuth family it would read like a requirement in force.",
    what: "RFC 9101 section 10.5 `require_signed_request_object`, for this client alone: TRUE refuses an authorization request from it that carries no `request` or `request_uri`, and a request object signed with `none`, with invalid_request. FALSE or empty defers to oauth2.requireSignedRequestObject."
  })
  oauthRequireSignedRequestObject?: string;
  // RFC 9126 SECTION 6 (2026-09-13). ONE MEMBER a client registers about
  // HOW it sends an authorization request: pushed, or not at all. READ by
  // `oauth-oidc/oauth2.ts`'s `pushedRequestPolicyRefusal()`. Family-scoped for
  // the introspection attributes' reason.
  @attr(#{
    kind: "single",
    from: "POST /oauth2/register, the console, the management API, or by hand",
    families: #["oauth2", "oidc"],
    familyWhy: "It decides whether /oauth2/authorize refuses a request from this client that was not pushed, so on an entry declared for neither OAuth family it would read like a requirement in force.",
    what: "RFC 9126 section 6 `require_pushed_authorization_requests`, for this client alone: TRUE refuses an authorization request from it that does not carry a request_uri issued at /oauth2/par, with invalid_request. FALSE or empty defers to oauth2.requirePushedAuthorizationRequests."
  })
  oauthRequirePushedAuthorizationRequests?: string;
  // FAPI 2.0 HTTP SIGNATURES (#178, 2026-10-05). ONE MEMBER, and no
  // registration metadata name: the draft of 26 June 2026 defines none, and
  // this service does not invent one for RFC 7591. So it is written through
  // the console, the management API or by hand, never by a client. READ by
  // `oauth-oidc/http_signatures.ts` through `httpSignaturesOf()`.
  @attr(#{
    kind: "single",
    from: "the console, the management API, or by hand",
    families: #["oauth2", "oidc"],
    familyWhy: "It decides whether the OAuth resource servers refuse an unsigned request carrying this client's access token, so on an entry declared for neither OAuth family it would read like a requirement in force.",
    what: "FAPI 2.0 HTTP Signatures, for this client alone: TRUE refuses, with 401, a request to a resource server with this client's access token that does not carry a valid \"fapi-2-request\" signature (RFC 9421) by a key in its jwks or jwks_uri. FALSE or empty defers to oauth2.httpSignatures."
  })
  oauthHttpSignedRequests?: string;
  // -------------------------------------------------------------------
  // RFC 9396, RICH AUTHORIZATION REQUESTS (2026-09-13). TWO ATTRIBUTES, and
  // they sit on DIFFERENT KINDS OF ENTRY, which is the design rcbj chose:
  // a RESOURCE declares the authorization_details types it understands (a
  // type selects its resource server the way a delegated permission does),
  // and a CLIENT may register the types it will use (RFC 9396 section 10's
  // `authorization_details_types`). READ by
  // `oauth-oidc/authorization_details.ts`. Family-scoped for the
  // introspection attributes' reason.
  // SINCE #432 PHASE 4 (2026-10-03) IT IS THE ACCESS-TYPE CATALOGUE that
  // RFC 9396 and GNAP share — see `authorizationDetailsTypeOf()`'s block —
  // so a GNAP resource server declares its types here too.
  @attr(#{
    kind: "multi",
    from: "the console (the Access types tab), the management API, the RFC 9728 import, or by hand",
    families: #["oauth2", "oidc", "gnap"],
    familyWhy: "It is a type /oauth2/authorize, /oauth2/token and /gnap accept and address tokens to this application for, so on an entry declared for no OAuth family and not for GNAP it would read like an API in service.",
    what: "An ACCESS TYPE this application, as a resource server, owns — one per value, read by RFC 9396 authorization_details and by GNAP access rights alike. A bare type name, or a JSON object {\"type\", \"description\", \"locations\", \"schema\", \"actions\", \"datatypes\", \"privileges\", \"required\", \"interaction\", \"consentActions\", \"bearer\", \"maxLifetimeS\", \"acr\", \"derivableFrom\", \"introspectionClaims\", \"limits\"}: `locations` are the addresses a right of this type may name (the permission base URI and oauthAudience always count), `schema` a JSON Schema every right of it must satisfy, `actions`, `datatypes` and `privileges` the values it may name, `required` the members it must carry, `bearer: false` that a token carrying it is sender-constrained, `maxLifetimeS` the longest such a token lives, `derivableFrom` the types it may be derived from (RFC 9767 section 4), `introspectionClaims` what this resource server is told about the person at introspection, and `limits` the JSON Schema (a subset) a right's limits must meet. `interaction` (always, default, never), `consentActions` and `acr` decide, for GNAP, whether the resource owner is asked and how strongly signed in (#432 phase 6). An undeclared type is refused invalid_authorization_details by RFC 9396 in every mode, and by GNAP in product mode."
  })
  oauthAuthorizationDetailsType?: string[];
  @attr(#{
    kind: "multi",
    from: "POST /oauth2/register, the console, the management API, or by hand",
    families: #["oauth2", "oidc"],
    familyWhy: "It narrows what /oauth2/authorize and /oauth2/token accept from this client, so on an entry declared for neither OAuth family it would read like a restriction in force.",
    what: "RFC 9396 section 10 `authorization_details_types`: the ONLY authorization_details types this client may use, one per value. EMPTY MEANS any type this authorization server supports."
  })
  oauthAuthorizationDetailsTypes?: string[];
  // -------------------------------------------------------------------
  // AUTHZEN (#563): TWO ATTRIBUTES, on DIFFERENT KINDS OF ENTRY, as RFC
  // 9396's two are. The CATALOGUE is the API's — one row per value on the
  // realm's `sts-authzen-api` resource object, read by `authzen/` on every
  // request — and the APPLICATION SCOPE is a caller's: the applications an
  // OAuth client calling `/access/v1` may ask about. A person or a service
  // account carries the second as `stsAuthzenApplication` on its directory
  // entry instead. Both are written by an administrator only: what a
  // caller may ask about is never something the caller says.
  @attr(#{
    kind: "multi",
    from: "the console (the AuthZEN page), the management API, or by hand",
    families: #["oauth2", "oidc"],
    familyWhy: "It is the vocabulary /access/v1 accepts, and that API is an OAuth 2.0 resource; on an entry declared for no OAuth family it would read like an API in service.",
    what: "ONE ROW OF THE AUTHZEN ATTRIBUTE CATALOGUE (#563), on the sts-authzen-api resource object: a JSON object {\"object\", \"property\", \"attributeId\", \"category\", \"dataType\", \"multiplicity\", \"description\"}. `object` is subject, resource, action or context; `property` the member's name, or a dotted path into a nested object; `attributeId` the XACML attribute it is sent as; `category` (default the object's own), `dataType` (default string) and `multiplicity` (single or bag). A property no row names is refused in every mode, and a row may not name this service's own urn:sts:xacml: identifiers, subject-id, resource-id or action-id, nor a bare directory attribute name in a subject category."
  })
  authzenAttribute?: string[];
  @attr(#{
    kind: "multi",
    from: "the console, the management API, or by hand",
    families: #["oauth2", "oidc"],
    familyWhy: "It scopes what this client may ask /access/v1 about with an OAuth 2.0 access token, so on an entry declared for no OAuth family it would read like a permission in force.",
    what: "AUTHZEN APPLICATION SCOPE (#563): the applications this client, calling /access/v1 with its own client_credentials token, may name in context.application — one identifier per value. The client's own identifier is always in scope. Set by an administrator, never by the caller."
  })
  appAuthzenApplication?: string[];
  // THE ACCESS REQUEST CALLBACK URLS (#1180): where this service may tell
  // this client, as an AuthZEN PEP, that an access request it submitted
  // finished — the CALLBACK companion's endpoint, held to these exactly,
  // so a request names one of them or none. Written by an administrator
  // (the AuthZEN tab's set-callbacks); `federation/CLAUDE.md` carries the
  // URL-dialling argument.
  @attr(#{
    kind: "multi",
    from: "the console (the AuthZEN tab), the management API, or by hand",
    families: #["oauth2", "oidc"],
    familyWhy: "It is where /access/v1 tells this client an access request finished, and that API is an OAuth 2.0 resource; on an entry declared for no OAuth family it would read like a delivery in service.",
    what: "AUTHZEN ACCESS REQUEST CALLBACK (#1180): an https URL this client, as an AuthZEN PEP, may name as an access request's callback.endpoint — one per value, matched exactly. A request naming any other is refused; this service never dials a callback URL taken from a request alone. Set by an administrator, never by the caller."
  })
  appAuthzenCallbackUri?: string[];
  // -------------------------------------------------------------------
  // RFC 9470, STEP-UP AUTHENTICATION (2026-09-13). TWO ATTRIBUTES ON A
  // RESOURCE: what it requires of the authentication behind an access token
  // addressed to it. RFC 9470 defines no registration or metadata member for
  // either — section 3 is a challenge a resource server sends — so they are
  // written by an operator, never by a registration. ENFORCED by the
  // resource server the application is — somebody else's process (the
  // stand-in resource that answered for it here went with #593); drawn on
  // the monitor, and READ through `stepUpRequirementOf()` below, whose
  // grammar is
  // `oauth-oidc/step_up.ts`'s header's. Family-scoped for the introspection
  // attributes' reason.
  @attr(#{
    kind: "single",
    from: "the console, the management API, or by hand",
    families: #["oauth2", "oidc"],
    familyWhy: "It is a requirement on OAuth access tokens addressed to this application, so on an entry declared for neither OAuth family it would read like a requirement in force.",
    what: "RFC 9470 section 3: the acr values this application, as a resource server, requires of the authentication behind an access token — space-separated, most preferred first. A token whose acr meets none is challenged 401 insufficient_user_authentication with these as acr_values. The levels 0 < 1 < mfa are ordered; hwk is met by a password with a security key; phr and phrh only by the phishing-resistant authentication they name (#723); any other value only by that exact acr. EMPTY requires nothing."
  })
  oauthStepUpAcrValues?: string;
  @attr(#{
    kind: "single",
    from: "the console, the management API, or by hand",
    families: #["oauth2", "oidc"],
    familyWhy: "It is a requirement on OAuth access tokens addressed to this application, so on an entry declared for neither OAuth family it would read like a requirement in force.",
    what: "RFC 9470 section 3's max_age: the oldest authentication, in whole seconds, this application accepts behind an access token. A token whose auth_time is older, or absent, is challenged 401 insufficient_user_authentication with max_age. 0 means an authentication this second. EMPTY requires nothing."
  })
  oauthStepUpMaxAge?: string;
  // -------------------------------------------------------------------
  // HOW THIS SERVICE SIGNS AND ENCRYPTS WHAT IT SENDS THIS CLIENT, AND THE
  // CLIENT'S REQUEST DEFAULTS (#290, 2026-10-08). ELEVEN members of OpenID
  // Connect Registration section 2 and JARM section 3 that lived only in
  // `appRegistrationJson`, so a client created on the console could not hold
  // them and had to register again through RFC 7591 for an ES256 ID Token
  // or a signed UserInfo response. Each is now an attribute, written by a
  // registration (REPLACED, as RFC 7592 replaces it), the console and the
  // management API alike, checked at every door by the registration's own
  // grammar (`clientResponseAttributeProblem()`), and READ through
  // `clientConfigOf()` by the ID Token, the UserInfo response, JARM, the
  // Logout and Command Tokens and step-up.
  //
  // `single`, for the introspection attributes' reason. The acr values are
  // ONE space-separated value in preference order, for
  // `oauthStepUpAcrValues`' reason: a multi-valued attribute has no order.
  @attr(#{
    kind: "single",
    from: "POST /oauth2/register, the console, the management API, or by hand",
    families: #["oidc"],
    familyWhy: "It decides how this client's ID Tokens are signed, and only an OpenID Connect client is given one.",
    what: "OpenID Connect Registration `id_token_signed_response_alg`: the JWS algorithm this client's ID Tokens are signed with — and its back-channel Logout Tokens and Command Tokens. EMPTY MEANS RS256 (PS256 under FAPI 1.0 Advanced). Any algorithm in id_token_signing_alg_values_supported; an HMAC one is keyed with the client secret. `none` is refused."
  })
  oauthIdTokenSignedResponseAlg?: string;
  @attr(#{
    kind: "single",
    from: "POST /oauth2/register, the console, the management API, or by hand",
    families: #["oidc"],
    familyWhy: "It decides whether this client's ID Tokens are encrypted, and only an OpenID Connect client is given one.",
    what: "OpenID Connect Registration `id_token_encrypted_response_alg`: the JWE key management algorithm its ID Tokens (and Logout Tokens) are encrypted to it with, after signing. EMPTY MEANS NOT ENCRYPTED. An asymmetric algorithm, and the key is taken from `oauthJwks` or `oauthJwksUri`."
  })
  oauthIdTokenEncryptedResponseAlg?: string;
  @attr(#{
    kind: "single",
    from: "POST /oauth2/register, the console, the management API, or by hand",
    families: #["oidc"],
    familyWhy: "The same as oauthIdTokenEncryptedResponseAlg.",
    what: "OpenID Connect Registration `id_token_encrypted_response_enc`: the JWE content encryption. EMPTY MEANS A128CBC-HS256 once `oauthIdTokenEncryptedResponseAlg` is set; it may not be set without that attribute."
  })
  oauthIdTokenEncryptedResponseEnc?: string;
  @attr(#{
    kind: "single",
    from: "POST /oauth2/register, the console, the management API, or by hand",
    families: #["oidc"],
    familyWhy: "It decides what the UserInfo endpoint answers this client, which only an OpenID Connect client calls.",
    what: "OpenID Connect Registration `userinfo_signed_response_alg`: the JWS algorithm the UserInfo response to this client is signed with, making it `application/jwt` carrying `iss` and `aud`. EMPTY (or `none`) MEANS plain JSON, unless it is encrypted."
  })
  oauthUserinfoSignedResponseAlg?: string;
  @attr(#{
    kind: "single",
    from: "POST /oauth2/register, the console, the management API, or by hand",
    families: #["oidc"],
    familyWhy: "The same as oauthUserinfoSignedResponseAlg.",
    what: "OpenID Connect Registration `userinfo_encrypted_response_alg`: the JWE key management algorithm the UserInfo response is encrypted to this client with (after signing, where it is signed). EMPTY MEANS NOT ENCRYPTED. An asymmetric algorithm, to `oauthJwks` or `oauthJwksUri`."
  })
  oauthUserinfoEncryptedResponseAlg?: string;
  @attr(#{
    kind: "single",
    from: "POST /oauth2/register, the console, the management API, or by hand",
    families: #["oidc"],
    familyWhy: "The same as oauthUserinfoSignedResponseAlg.",
    what: "OpenID Connect Registration `userinfo_encrypted_response_enc`: the JWE content encryption. EMPTY MEANS A128CBC-HS256 once `oauthUserinfoEncryptedResponseAlg` is set; it may not be set without that attribute."
  })
  oauthUserinfoEncryptedResponseEnc?: string;
  @attr(#{
    kind: "single",
    from: "POST /oauth2/register, the console, the management API, or by hand",
    families: #["oauth2", "oidc"],
    familyWhy: "It decides how /oauth2/authorize signs a JWT-secured response to this client, so on an entry declared for neither OAuth family it would read like a registration in force.",
    what: "JARM section 3 `authorization_signed_response_alg`: the JWS algorithm of this client's JWT-secured authorization responses (`response_mode` `jwt`, `query.jwt` and the rest). EMPTY MEANS RS256 (PS256 under FAPI 1.0 Advanced). `none` is refused (JARM section 3)."
  })
  oauthAuthorizationSignedResponseAlg?: string;
  @attr(#{
    kind: "single",
    from: "POST /oauth2/register, the console, the management API, or by hand",
    families: #["oauth2", "oidc"],
    familyWhy: "The same as oauthAuthorizationSignedResponseAlg.",
    what: "JARM section 3 `authorization_encrypted_response_alg`: the JWE key management algorithm a JWT-secured authorization response is encrypted to this client with. EMPTY MEANS NOT ENCRYPTED. An asymmetric algorithm, to `oauthJwks` or `oauthJwksUri`."
  })
  oauthAuthorizationEncryptedResponseAlg?: string;
  @attr(#{
    kind: "single",
    from: "POST /oauth2/register, the console, the management API, or by hand",
    families: #["oauth2", "oidc"],
    familyWhy: "The same as oauthAuthorizationSignedResponseAlg.",
    what: "JARM section 3 `authorization_encrypted_response_enc`: the JWE content encryption. EMPTY MEANS A128CBC-HS256 once `oauthAuthorizationEncryptedResponseAlg` is set; it may not be set without that attribute."
  })
  oauthAuthorizationEncryptedResponseEnc?: string;
  @attr(#{
    kind: "single",
    from: "POST /oauth2/register, the console, the management API, or by hand",
    families: #["oidc"],
    familyWhy: "It is what /oauth2/authorize requires of a sign-in for this client's OpenID Connect requests.",
    what: "OpenID Connect Registration `default_acr_values`: the acr values requested for this client when a request names neither `acr_values` nor an essential acr claim — space-separated, most preferred first. EMPTY requests nothing."
  })
  oauthDefaultAcrValues?: string;
  @attr(#{
    kind: "single",
    from: "POST /oauth2/register, the console, the management API, or by hand",
    families: #["oidc"],
    familyWhy: "The same as oauthDefaultAcrValues.",
    what: "OpenID Connect Registration `default_max_age`: the oldest sign-in, in whole seconds, this client accepts when a request names no `max_age` — an older one signs the person in again. 0 means a sign-in this second. EMPTY requires nothing."
  })
  oauthDefaultMaxAge?: string;
  // -------------------------------------------------------------------
  // RFC 7521 / RFC 7523 (2026-09-10). SEVEN ATTRIBUTES (eight since the key
  // source joined them on 2026-09-13), and the split between them is the
  // split between what an OPERATOR says and what this service ISSUED.
  //
  // The first is a DECLARATION and is the whole trust decision: this
  // application may present assertions under these `iss` values. There is no
  // permissive reading of it — see `oauth-oidc/assertion_grant.js`, where the
  // argument is federation's.
  //
  // The other six are what a build on /admin/pki wrote here, and they are on
  // the APPLICATION ENTRY rather than in a store of the PKI module's own for
  // the reason `applications.js` gives about everything else in this table:
  // a second store would be a second answer to "what is that client's signing
  // key", and the second answer would be the one an `ldapsearch` could not
  // see.
  // -------------------------------------------------------------------
  @attr(#{
    kind: "multi",
    from: "by hand",
    identifier: true,
    identifierName: "assertion iss",
    what: "THE `iss` VALUES THIS APPLICATION MAY PRESENT IN AN RFC 7523 SECTION 2.1 AUTHORIZATION GRANT, and it is one of the few DECLARED attributes here that is READ. A JWT bearer assertion IS the whole authorization — there is no browser, no password and no consent step in that grant — so accepting one from anybody would mean anybody who can reach this port getting an access token as anybody. This is therefore the second feature in this service with no permissive answer available, beside federation, and `oauth2.jwtBearerRequireRegisteredIssuer` is on by default.\n\nAn assertion a client issues ABOUT ITSELF names its own client_id as `iss` and needs no value here: that lookup already succeeds through oauthClientId, and asking an operator to write the client_id down twice would be a configuration step with no decision in it. It accumulates, because one application legitimately asserts under a per-environment issuer name."
  })
  oauthAssertionIssuer?: string[];
  @attr(#{
    kind: "single",
    from: "/admin/pki",
    what: "THE PUBLIC KEYS THIS SERVICE ISSUED THIS APPLICATION, as a JWKS document, each key carrying `x5c` (its certificate chain) and `x5t#S256`. Written by the Issue control on /admin/pki and by POST /admin-api/pki/issue.\n\nIt is a SECOND attribute beside `oauthJwks` and never overwrites it. A client that registered its own keys and was later issued a pair by an operator has two ways to sign, both of which somebody deliberately arranged — and writing over the first would silently end it the moment somebody pressed a button about the second. Both are read, ORed, by client_auth.js and by assertion_grant.js. Public key material, so like oauthJwks it is worth nothing to whoever reads this directory."
  })
  oauthAssertionJwks?: string;
  @attr(#{
    kind: "single",
    from: "/admin/pki",
    what: "The leaf certificate, PEM, whose subject is this application and whose issuer is the realm's Issuing CA. The same bytes as the first `x5c` member above, in the form a person can paste into `openssl x509 -text`."
  })
  oauthAssertionCertificate?: string;
  @attr(#{
    kind: "single",
    from: "/admin/pki",
    what: "The Issuing CA and the Intermediate CA, PEM, in that order — what a leaf travels with. The ROOT is deliberately not in it: a root is a trust anchor, and a relying party that accepted one because it arrived in the chain would be accepting a certificate that vouched for itself."
  })
  oauthAssertionCertificateChain?: string;
  @attr(#{
    kind: "single",
    from: "/admin/pki",
    sensitive: true,
    what: "THE PRIVATE KEY, PEM. **SEALED AT REST WHEREVER THE KEY-ENCRYPTION KEY OUTLIVES THE PROCESS** — AES-256-GCM through common/keystore.js, the same mechanism and the same key that seal this service's own signing keys, common/pki.js's three CA key pairs and an authenticator's shared secret. So an ldapsearch on TCP 389 where every bind succeeds, an ldif file, a database row and a backup of either hold `$aesgcm$…` and not a usable key. The surfaces that come through this module — /admin/applications and GET /admin-api/applications, both behind a credential — are handed the PEM, because the seal protects the STORE rather than the console an operator collects an issued credential from; SEALED_FIELDS argues the split. In DEVELOPMENT mode it is written in the clear, which is the rule the authenticator secret beside it follows and for its reason: the key-encryption key there is ephemeral, so sealing an entry that survives a restart under a key that does not would make the private half permanent garbage while the certificate came back. It is never written to the audit log, and this service keeps NO SECOND COPY of it — common/pki.js hands it over once, at issuance, and forgets it."
  })
  oauthAssertionPrivateKey?: string;
  @attr(#{
    kind: "single",
    from: "/admin/pki",
    what: "The `kid` of the issued key, derived from the key material as every kid in this service is (RFC 7638). An assertion naming it in its JWS header narrows the verification to that key; one naming nothing is tried against every key registered for this application, which is correct rather than lax."
  })
  oauthAssertionKid?: string;
  @attr(#{
    kind: "single",
    from: "/admin/pki",
    what: "When the issued certificate expires, as a GeneralizedTime. It is a fact about the CERTIFICATE and not a policy: nothing here refuses an assertion because this date has passed — what refuses one is the certificate failing to build a path, which is checked where the chain is checked. Drawn on /admin/pki so that an operator can see what is about to stop working."
  })
  oauthAssertionExpiresAt?: string;
  @attr(#{
    kind: "single",
    from: "/admin/pki, or the application's own page",
    what: "WHERE THE RFC 7523 KEY PAIR ABOVE CAME FROM, and therefore who holds its private half. `issued` — generated here and signed by this realm's Issuing CA, the private key on `oauthAssertionPrivateKey`. `uploaded-realm-ca` — a certificate this realm's own certificate authority issued, uploaded in place of a generated pair. `uploaded-external-ca` — a certificate from another authority, uploaded with its whole chain up to a self-signed root, every link verified. For both uploaded values the APPLICATION holds the private key and this service never has.\n\nA fact about what was done and not a policy: no verifier reads it, and an entry written before it existed carries none — the console reads a sealed private key as `issued` there, which is the only thing that could have put one on the entry."
  })
  oauthAssertionKeySource?: string;
  // -------------------------------------------------------------------
  // RFC 7522 — THE SAML 2.0 PROFILE OF THE SAME FRAMEWORK (2026-09-11).
  // SEVEN MORE ATTRIBUTES (eight with the key source), AND THE WHOLE POINT
  // OF THEM IS THAT THEY ARE NOT THE ONES ABOVE.
  //
  // An application may hold TWO key pairs issued by this realm's
  // certificate authority — one for RFC 7523 and one for RFC 7522 — and no
  // code path crosses between the two sets:
  // `oauth-oidc/saml_assertion_grant.js` never reads an `oauthAssertion*`
  // attribute and `oauth-oidc/assertion_grant.js` never reads an
  // `oauthSamlAssertion*` one. So a key pair issued for one profile cannot
  // sign for the other, and taking one off leaves the other working.
  //
  // **THAT SEPARATION IS A DESIGN DECISION RATHER THAN AN ACCIDENT OF
  // NAMING**, and the reason is that the two profiles verify differently:
  // a JWT is verified against a JWKS or an x5c chain that reaches this
  // realm's Root, and a SAML assertion is verified ONLY against a
  // certificate registered here. One attribute set holding both would make
  // the second rule unenforceable — the chain path would reach the SAML
  // certificate too. `oauth-oidc/saml_assertion_grant.js`'s header argues
  // it at length.
  //
  // The first TWO are DECLARED and are what a party registers; the other
  // five are what an Issue on /admin/pki wrote, and they are the same five
  // the JWT profile writes with a different spelling of the key handle —
  // an X.509 key is named by its THUMBPRINT here where a JWS key is named
  // by its `kid`, because those are the handles the two formats actually
  // carry.
  // -------------------------------------------------------------------
  @attr(#{
    kind: "multi",
    from: "by hand",
    identifier: true,
    identifierName: "SAML assertion Issuer",
    what: "THE `<Issuer>` VALUES THIS APPLICATION MAY PRESENT IN AN RFC 7522 SECTION 2.1 AUTHORIZATION GRANT. It is `oauthAssertionIssuer`'s sibling for the SAML 2.0 profile and it is READ for the same reason: a bearer assertion IS the whole authorization — no browser, no password, no consent step — so accepting one from anybody would mean anybody who can reach this port getting an access token as anybody. `oauth2.saml2BearerRequireRegisteredIssuer` is on by default.\n\nIt is a SEPARATE attribute from the JWT one and not a shared list: a party trusted to assert in one format has not thereby been trusted to assert in the other, and an operator who declared an issuer for RFC 7523 must not silently have declared it for RFC 7522. Compared by Simple String Comparison (RFC 3986 section 6.2.1), which RFC 7522 section 3 item 1 asks for — no case folding and no trailing-slash tolerance. It accumulates, for the reason the JWT one does."
  })
  oauthSamlAssertionIssuer?: string[];
  @attr(#{
    kind: "single",
    from: "by hand",
    what: "THE CERTIFICATE THIS PARTY SIGNS ITS RFC 7522 ASSERTIONS WITH, PEM, registered by value. The analogue of `oauthJwks` for a profile whose signatures are XML Signature rather than JWS — there is no JWKS in SAML, the thing a party registers IS a certificate.\n\nSeveral PEM blocks may be in one value, because a party rotating a certificate holds two for as long as assertions signed by the old one are still in flight. Public key material, so like `oauthJwks` it is worth nothing to whoever reads this directory.\n\n**A CERTIFICATE ARRIVING IN THE ASSERTION'S OWN `<ds:KeyInfo>` IS NOT A SUBSTITUTE FOR THIS.** It is used to choose among what is registered here and never as a key in its own right, which is where this profile is stricter than RFC 7523: a chain to this realm's Root proves the REALM issued a key and says nothing about WHICH application holds it, so accepting one would let an application's RFC 7523 leaf sign a SAML assertion."
  })
  oauthSamlAssertionSigningCertificate?: string;
  @attr(#{
    kind: "single",
    from: "/admin/pki",
    what: "The leaf certificate this service ISSUED this application for RFC 7522, PEM, whose subject is the application and whose issuer is the realm's Issuing CA. Written by the Issue control on /admin/pki with the SAML 2.0 purpose chosen, and by POST /admin-api/pki/issue with `purpose: \"saml\"`. It is a DIFFERENT certificate over a DIFFERENT key pair from `oauthAssertionCertificate` beside it, and its subjectAltName carries the RFC 7522 profile URI so that a certificate read out of context says which profile it was issued for."
  })
  oauthSamlAssertionCertificate?: string;
  @attr(#{
    kind: "single",
    from: "/admin/pki",
    what: "The Issuing CA and the Intermediate CA, PEM, in that order — what the leaf above travels with. The ROOT is deliberately not in it, for the reason the JWT chain row gives: a relying party that accepted one because it arrived in the chain would be accepting a certificate that vouched for itself."
  })
  oauthSamlAssertionCertificateChain?: string;
  @attr(#{
    kind: "single",
    from: "/admin/pki",
    sensitive: true,
    what: "THE PRIVATE KEY of the RFC 7522 pair, PEM. **SEALED AT REST WHEREVER THE KEY-ENCRYPTION KEY OUTLIVES THE PROCESS**, by the same mechanism and under the same key as `oauthAssertionPrivateKey` beside it — see that row, which argues the whole of it. This service keeps NO SECOND COPY: common/pki.js hands it over once, at issuance, and forgets it."
  })
  oauthSamlAssertionPrivateKey?: string;
  @attr(#{
    kind: "single",
    from: "/admin/pki",
    what: "The SHA-256 thumbprint of the issued certificate, base64url. It is what `oauthAssertionKid` is for the JWT profile and it is spelt differently because the two formats carry different handles: a JWS header names a `kid` and an XML Signature carries the certificate itself, so what matches a presented <ds:KeyInfo> against what is registered is a thumbprint."
  })
  oauthSamlAssertionThumbprint?: string;
  @attr(#{
    kind: "single",
    from: "/admin/pki",
    what: "When the issued RFC 7522 certificate expires, as a GeneralizedTime. A fact about the CERTIFICATE and not a policy, exactly as `oauthAssertionExpiresAt` is: nothing here refuses an assertion because this date has passed. Drawn on /admin/pki so that an operator can see what is about to stop working."
  })
  oauthSamlAssertionExpiresAt?: string;
  @attr(#{
    kind: "single",
    from: "/admin/pki, or the application's own page",
    what: "Where the RFC 7522 key pair above came from, in the vocabulary `oauthAssertionKeySource` uses and for its reason: `issued`, `uploaded-realm-ca` or `uploaded-external-ca`. It is a SEPARATE attribute from the JWT one because the two key pairs are separate — one may be issued here while the other is somebody else's certificate."
  })
  oauthSamlAssertionKeySource?: string;
  // -------------------------------------------------------------------
  // RFC 7591 SECTION 2.3 — SOFTWARE STATEMENTS (2026-09-13). Two kinds of
  // row, and `oauth-oidc/software_statement.ts` argues both: on a PUBLISHER,
  // the declaration and the statement this realm issued it; on a client that
  // REGISTERED with a statement, three facts about how it got in. The keys a
  // declared publisher signs with are the ones above — `oauthJwks` and the
  // RFC 7523 key pair — because a key is the party's and the declaration is
  // the decision.
  // -------------------------------------------------------------------
  @attr(#{
    kind: "multi",
    from: "by hand",
    identifier: true,
    identifierName: "software statement iss",
    what: "THE `iss` VALUES WHOSE SOFTWARE STATEMENTS THIS APPLICATION VOUCHES FOR at POST /oauth2/register (RFC 7591 section 2.3) — the application is the software PUBLISHER, and a statement naming one of these issuers is verified against its `jwks` or its RFC 7523 key pair from /admin/pki, or an x5c this realm issued to it. It is READ: a statement from an issuer nobody declares is refused unapproved_software_statement while `oauth2.softwareStatementRequireTrustedIssuer` is on, and a trusted one fixes the registered metadata and may open a closed registration endpoint.\n\nA SEPARATE attribute from `oauthAssertionIssuer`: a party trusted to say who a person is has not thereby been trusted to say what software may register as. A statement this realm issued itself needs no declaration. It accumulates, for the reason the assertion issuers do."
  })
  oauthSoftwareStatementIssuer?: string[];
  @attr(#{
    kind: "single",
    from: "the application's own page, or POST /admin-api/applications/issue-software-statement",
    what: "THE SOFTWARE STATEMENT THIS REALM LAST ISSUED FOR THIS APPLICATION, as the compact JWS, typed `software-statement+jwt`, with `sub` naming this application. A client presenting it at POST /oauth2/register is registered with the members it fixes. NOT A SECRET — RFC 7591 section 2.3 expects a statement to ship with every copy of the software — and not a record of every statement issued: issuing again replaces this value, and the earlier statement still verifies until it expires or the realm's signing key changes."
  })
  oauthIssuedSoftwareStatement?: string;
  @attr(#{
    kind: "single",
    from: "POST /oauth2/register",
    what: "The `iss` of the software statement this client REGISTERED with, or absent when it presented none. Cleared by an RFC 7592 update that carries none, and by the registration being deleted."
  })
  appSoftwareStatementIssuer?: string;
  @attr(#{
    kind: "single",
    from: "POST /oauth2/register",
    what: "TRUE when that statement was verified against an issuer this realm trusts, FALSE when it was accepted unverified because `oauth2.softwareStatementRequireTrustedIssuer` was off. A client registered on a TRUE statement at an endpoint otherwise closed must present a trusted statement from the same issuer with every update."
  })
  appSoftwareStatementTrusted?: string;
  @attr(#{
    kind: "single",
    from: "POST /oauth2/register",
    what: "The application the trust came through: the one declaring the issuer, or — for a statement this realm issued — the application it was issued for."
  })
  appSoftwareStatementPublisher?: string;
  @attr(#{
    kind: "single",
    from: "by hand",
    identifier: true,
    identifierName: "subject DN",
    what: "RFC 8705 section 2.1.2 `tls_client_auth_subject_dn`: the subject DN of the PKI certificate this client authenticates with, in RFC 4514 form. Compared as a NAME since 2026-09-13 (common/certificate_subject.js: attribute types folded, values caseIgnoreMatch, the AVAs of a multi-valued RDN in any order) and only against a certificate whose chain VERIFIED. One of the FIVE subject parameters, and a client registers at most one — a second is refused (STS-REG-0131, STS-REG-0135). With none, tls_client_auth still authenticates a certificate this realm issued to THIS application. IT IS ALSO THE IDENTIFIER ATTRIBUTE OF THE `mtls` FAMILY, and it is SINGLE-VALUED while every other identifier here accumulates, because RFC 8705 says the certificate matches \"the single expected subject\"."
  })
  oauthTlsClientAuthSubjectDn?: string;
  @attr(#{
    kind: "single",
    from: "by hand / POST /oauth2/register",
    what: "RFC 8705 section 2.1.2 `tls_client_auth_san_dns`: a dNSName the certificate this client authenticates with must carry, compared without regard to case or a trailing dot, never as a wildcard. One of the five subject parameters; see oauthTlsClientAuthSubjectDn."
  })
  oauthTlsClientAuthSanDns?: string;
  @attr(#{
    kind: "single",
    from: "by hand / POST /oauth2/register",
    what: "RFC 8705 section 2.1.2 `tls_client_auth_san_uri`: a uniformResourceIdentifier the certificate must carry, compared exactly. One of the five subject parameters."
  })
  oauthTlsClientAuthSanUri?: string;
  @attr(#{
    kind: "single",
    from: "by hand / POST /oauth2/register",
    what: "RFC 8705 section 2.1.2 `tls_client_auth_san_ip`: an iPAddress the certificate must carry, IPv4 or IPv6, compared as the address rather than its spelling. One of the five subject parameters."
  })
  oauthTlsClientAuthSanIp?: string;
  @attr(#{
    kind: "single",
    from: "by hand / POST /oauth2/register",
    what: "RFC 8705 section 2.1.2 `tls_client_auth_san_email`: an rfc822Name the certificate must carry, the domain compared without regard to case and the local part exactly (RFC 5280 section 7.5). One of the five subject parameters."
  })
  oauthTlsClientAuthSanEmail?: string;
  @attr(#{
    kind: "single",
    from: "by hand / POST /oauth2/register",
    what: "RFC 8705 section 3.4 `tls_client_certificate_bound_access_tokens`, TRUE or FALSE. TRUE is this client DECLARING that its tokens are certificate-bound, and it is held to that in EVERY mode: a token request from it over a connection with no client certificate is refused (STS-OAUTH-0487) rather than answered with an unbound token, which section 3.4 leaves to the authorization server. FALSE or absent changes nothing — a client presenting a certificate still gets a bound token."
  })
  oauthTlsClientCertificateBoundAccessTokens?: string;
  @attr(#{
    kind: "single",
    from: "by hand",
    what: "For RFC 8705 section 2.2 self_signed_tls_client_auth: the base64url SHA-256 of the DER of the certificate this client authenticates with. THIS SERVICE'S OWN NAME, kept beside what the RFC names: since 2026-09-13 a certificate also authenticates the client when it is the x5c[0] of a key in the jwks it registered (section 2.2.2). Fetch a certificate's thumbprint with GET /tls/sign-in, or compute it: openssl x509 -outform DER | openssl dgst -sha256 -binary | base64url."
  })
  oauthTlsClientCertificateThumbprint?: string;
  // THE METHOD IS THE DECLARATION (#466). RFC 9700 reads
  // oauthTokenEndpointAuthMethod (oauth2_bcp.js isConfidential()). This
  // attribute is the registry's record of that answer, so it can be read
  // without inferring it, and it is not edited on its own.
  @attr(#{
    kind: "single",
    from: "this registry",
    what: "TRUE or FALSE, the determination the token endpoint authentication method makes, written by this registry so the answer can be read. `none`, or no method on an application created by hand, is FALSE; any other method is TRUE. RFC 9700 reads `oauthTokenEndpointAuthMethod` (`isConfidential()` in `oauth2_bcp.js`), so this attribute is not edited. A create may state it only when the value agrees, and a disagreement is refused (`STS-REG-0363`). An OAuth or OpenID Connect application created with no method and no credential is still recorded as `none`."
  })
  oauthConfidential?: string;
  // --- SAML, WS-Federation, WS-Trust ------------------------------------
  @attr(#{
    kind: "multi",
    from: "SAML 2.0 / SAML 1.1",
    identifier: true,
    identifierName: "entityID",
    what: "THE SERVICE PROVIDER'S ENTITYID — the assertion audience, and the identifier attribute of BOTH SAML families. SAML 1.1 has no entityID of its own in the protocol (there is no request message for one to travel in) and what stands in for it — Shibboleth's providerId, the path segment, or the TARGET's origin — names the same party, so one attribute holds it rather than two that would disagree the first time an application was declared for both. Accumulates: an application answering to two entityIDs is one application.\n\nIT IS READ, as the SECOND half of forAppliesTo(): a WS-Trust AppliesTo and the AudienceRestriction of the assertion issued for it are one string, so an application that registered it here rather than on `wstrustAppliesTo` still gets its own box on the delegation map. The same lookup, and since #496 the AppliesTo it resolves is refused in product when the application it names is not registered (appRegisteredBy)."
  })
  samlEntityId?: string[];
  @attr(#{
    kind: "multi",
    from: "SAML 2.0 / SAML 1.1",
    what: "THE ASSERTION CONSUMER SERVICE URL — where a SAML response is posted back to, and the redirect URI of both SAML families. It held WS-Federation's `wreply` as well until 2026-08-25; that moved to wsfedReplyUrl, because the SAML pages read this attribute for the Single Logout fallback and a wreply arriving in it made a WS-Federation application look as though it had named a SAML ACS. CHECKED IN PRODUCT MODE ONLY: development sends a response wherever the request asked and records the address here; product delivers only to an address already on this list, and a sighting there never adds one. What development RECORDS here is marked on appReturnAddressObserved, and product refuses a marked address until an operator confirms it — so a realm switched from development to product does not trust what development learnt. Values recorded before that mark existed carry none and still need reviewing."
  })
  samlAssertionConsumerService?: string[];
  @attr(#{
    kind: "multi",
    from: "consumed metadata, or by hand",
    what: "WHERE A <samlp:LogoutResponse> IS SENT for this service provider, and where a LogoutRequest goes when this identity provider starts the logout. DECLARED, not observed: a LogoutRequest carries no return address, so only SP METADATA or an operator can say. Consuming the metadata writes its SingleLogoutService locations here (and each endpoint's binding and ResponseLocation on samlSloEndpoint, which is read first). With none recorded the fallback is saml2.defaultSingleLogoutService and then the assertion consumer service URL above, which is a guess this service makes out loud rather than quietly."
  })
  samlSingleLogoutService?: string[];
  @attr(#{
    kind: "multi",
    from: "SAML 2.0",
    what: "Every NameID Format this service provider has asked for in a NameIDPolicy, accumulated. It is evidence rather than configuration: this identity provider answers with whatever was asked for, including a format nobody has ever heard of, so a value here does not restrict the next request."
  })
  samlNameIdFormat?: string[];
  @attr(#{
    kind: "multi",
    from: "SAML 2.0",
    what: "The ProtocolBinding values it has asked its responses back on — HTTP-POST, HTTP-Redirect or HTTP-Artifact. Several is the ordinary case for a service provider being exercised, which is what makes this a list."
  })
  samlResponseBinding?: string[];
  // THE TRUST ANCHOR FOR A SERVICE PROVIDER'S SIGNATURES (2026-09-17,
  // #37). It was single-valued and written straight off the ds:KeyInfo of
  // every signed AuthnRequest while nothing verified a request signature;
  // now that something does, a certificate a REQUEST carries cannot be
  // what the request is checked against, so a sighting writes
  // `samlObservedSigningCertificate` below instead and this attribute holds
  // only what an operator or consumed metadata registered. MULTI, because
  // metadata publishes the old and new key side by side during a rollover
  // and both must verify. `saml/request_signature.ts` argues the rest.
  @attr(#{
    kind: "multi",
    from: "consumed metadata, the SAML 2.0 page, or by hand",
    what: "THE SERVICE PROVIDER'S REGISTERED SIGNING CERTIFICATES, base64 DER, one per value. A signed AuthnRequest, LogoutRequest or LogoutResponse from this service provider is VERIFIED against these — in every mode — and refused when it verifies against none. Written by consuming its metadata (every KeyDescriptor use=\"signing\" or with no use), by the SAML 2.0 console page, by POST /admin-api/saml2/set-signing-certificate, by confirming the observed certificate below, or by hand. Its key must make an XML signature this service verifies — RSA, EC, EdDSA, DSA, ML-DSA or SLH-DSA (STS-REG-0160). It is NEVER written from a request: the certificate a request carries in its ds:KeyInfo goes on samlObservedSigningCertificate. Values written before 2026-09-17 were captured off requests and carry no provenance — review them before trusting them. Public key material, so unlike oauthClientSecret it is worth nothing to whoever reads this directory."
  })
  samlSigningCertificate?: string[];
  @attr(#{
    kind: "single",
    from: "a signed SAML 2.0 request",
    what: "THE CERTIFICATE THE LAST SIGNED REQUEST CARRIED IN ITS ds:KeyInfo, base64 DER, when it is not one of the registered samlSigningCertificate values. OBSERVED, NOT TRUSTED: a key a request brings with it proves nothing about who sent the request, so it verifies nothing in either mode. Development still encrypts an assertion to it when the entry holds no other certificate; product does not. An operator CONFIRMS it (it moves onto samlSigningCertificate) or DISCARDS it, on the SAML 2.0 page or with POST /admin-api/saml2/confirm-signing-certificate and /discard-signing-certificate. ONE value — the last — so a stream of requests carrying made-up keys cannot grow the entry."
  })
  samlObservedSigningCertificate?: string;
  @attr(#{
    kind: "single",
    from: "SAML 2.0",
    what: "WHAT CHECKING THE LAST REQUEST'S SIGNATURE FOUND: `verified`, `failed`, `unsigned` or `no-certificate` (signed, and nothing registered to check it against), then the binding and the algorithm. Assigned, like samlAuthnRequestSigned beside it."
  })
  samlAuthnRequestVerification?: string;
  // ---------------------------------------------------------------------
  // SAML 2.0 ENCRYPTION, added 2026-08-27. Three attributes that are NOT
  // setting overrides — they are where the recipient's key comes from — and
  // four that are.
  //
  // THE CERTIFICATE IS RESOLVED IN THREE PLACES, MOST SPECIFIC FIRST:
  // `samlEncryptionCertificate` (extracted from metadata, or typed), then a
  // REGISTERED `samlSigningCertificate`, then — in development mode only
  // since 2026-09-17 (#37) — the OBSERVED `samlObservedSigningCertificate`
  // off a signed AuthnRequest's ds:KeyInfo. That last one is what makes
  // this work with no configuration at all in development; product does not
  // encrypt to a key anybody could have put in a request. Using a SIGNING
  // key to encrypt to is not what a careful deployment does — real metadata
  // carries a separate `use="encryption"` KeyDescriptor — and it is the
  // right default for a mock, where the alternative is refusing to
  // demonstrate the feature.
  @attr(#{
    kind: "single",
    from: "by hand",
    what: "WHERE THIS SERVICE PROVIDER'S METADATA IS PUBLISHED. It is fetched by the \"refresh metadata\" action on the application page and by POST /admin-api/applications/refresh-metadata, and NEVER while a flow is running — an assertion that had to wait on somebody else's web server to be issued would make every sign-in as reliable as that server. What the fetch writes is everything consuming the document writes — see samlSpMetadata below.\n\nThis is the SECOND outbound-request surface in this service; federation was the first and is the only other. It follows the same refusals — the URL must be one this entry carries, the scheme must be http or https, and the request times out."
  })
  samlSpMetadataUrl?: string;
  @attr(#{
    kind: "single",
    from: "a metadata fetch, or by hand",
    what: "THE SERVICE PROVIDER'S METADATA DOCUMENT, cached verbatim. It is what the refresh action stores, and what uploading one on the SAML 2.0 page (or POST /admin-api/saml2/upload-metadata) stores for a service provider whose metadata this service cannot reach. CONSUMING it (2026-09-17) writes its AssertionConsumerService and SingleLogoutService endpoints as REGISTERED return addresses (samlAssertionConsumerService, samlAcsEndpoint, samlSingleLogoutService, samlSloEndpoint), its signing certificates (samlSigningCertificate), its encryption certificate (samlEncryptionCertificate), its NameIDFormats, AuthnRequestsSigned and WantAssertionsSigned, and its validUntil and cacheDuration. Setting this attribute by hand stores the document and consumes NOTHING — use the upload.\n\nIT IS KEPT AS WELL AS THE EXTRACT so that a reader can see what was actually consumed. A certificate with no document behind it is a value nobody can check."
  })
  samlSpMetadata?: string;
  @attr(#{
    kind: "single",
    from: "metadata, or by hand",
    what: "THE CERTIFICATE AN ASSERTION IS ENCRYPTED TO, base64 DER or PEM. Written by the metadata fetch from the <md:KeyDescriptor use=\"encryption\"> — falling back to an unqualified KeyDescriptor, which the specification says serves both uses — and settable by hand for a service provider with no metadata at all.\n\nIt decides what goes out. With none here a registered samlSigningCertificate is used, then — in development only — the observed one, and with none of them the assertion is sent in clear (development) or refused (product), and the page says so."
  })
  samlEncryptionCertificate?: string;
  // ---------------------------------------------------------------------
  // WHAT CONSUMING THE METADATA FOUND (2026-09-17, #37). DERIVED — each is
  // rewritten whole by every consumption and by nothing else, which is
  // `applications.replaceSamlMetadataFields()`'s job — except the
  // metadata's own signing certificate, which is what an operator
  // DECLARES the document must be signed with.
  //
  // THE TWO ENDPOINT ATTRIBUTES CARRY ONE ENDPOINT PER VALUE, space
  // separated with the URL LAST — `appReturnAddressObserved`'s arrangement,
  // for its reason: a URL has no raw space in it, so it can take the
  // remainder. The plain locations are ALSO written to
  // samlAssertionConsumerService and samlSingleLogoutService, because those
  // are what the return-address rules and every older reader already ask.
  // ---------------------------------------------------------------------
  @attr(#{
    kind: "multi",
    from: "consumed metadata",
    what: "An <md:AssertionConsumerService> from the consumed metadata, as `<index> <isDefault> <binding> <location>` — isDefault is `true`, `false` or `-` for unstated. A SAML 2.0 AuthnRequest naming an AssertionConsumerServiceIndex is answered at that endpoint and on its binding; one naming an AssertionConsumerServiceURL must name one of these (in EVERY mode, once metadata has been consumed); one naming neither goes to the default endpoint (saml-metadata-2.0-os section 2.2.3). SAML 1.1 uses the registered binding and location to select Browser/POST or Browser/Artifact when no profile is explicitly requested."
  })
  samlAcsEndpoint?: string[];
  @attr(#{
    kind: "multi",
    from: "consumed metadata",
    what: "An <md:SingleLogoutService> from the consumed metadata, as `<binding> <location>` or `<binding> <location> <responseLocation>`. A LogoutResponse goes to the ResponseLocation where there is one, on the binding the LogoutRequest arrived on where the service provider publishes it."
  })
  samlSloEndpoint?: string[];
  @attr(#{
    kind: "multi",
    from: "consumed metadata",
    what: "The <md:NameIDFormat> values the service provider's metadata declares. Unlike samlNameIdFormat (what it has ASKED for), these RESTRICT: a NameIDPolicy naming another format is answered InvalidNameIDPolicy (saml-core-2.0-os section 3.4.1.1), and the default format is chosen from them."
  })
  samlSpNameIdFormat?: string[];
  @attr(#{
    kind: "single",
    from: "consumed metadata",
    what: "TRUE when the metadata says AuthnRequestsSigned=\"true\": an unsigned request from this service provider is then refused whatever saml2.requireSignedAuthnRequests says, and the metadata this identity provider serves it says WantAuthnRequestsSigned=\"true\"."
  })
  samlSpAuthnRequestsSigned?: string;
  @attr(#{
    kind: "single",
    from: "consumed metadata",
    what: "TRUE when the metadata says WantAssertionsSigned=\"true\": the assertion is signed even where saml2.signAssertion (or saml2SignAssertion) is off — in product mode; development honours the setting, which is a test case, and logs that the service provider asked otherwise."
  })
  samlSpWantAssertionsSigned?: string;
  @attr(#{
    kind: "single",
    from: "consumed metadata",
    what: "TRUE when the consumed metadata publishes a KeyDescriptor marked use=\"encryption\" — the service provider saying it has a key for encrypted assertions, which SAML 2.0 metadata has no attribute of its own for (the interoperability profiles read the key as the request). The assertion is then ENCRYPTED to that key in every mode, whatever saml2.encryptAssertion says."
  })
  samlSpWantAssertionsEncrypted?: string;
  @attr(#{
    kind: "single",
    from: "consumed metadata",
    what: "The EFFECTIVE validUntil of the consumed document — the earliest on any enclosing EntitiesDescriptor, the EntityDescriptor and its SPSSODescriptor. A document already expired is refused when consumed; once this passes, every request from the service provider is REFUSED (STS-SAML-0074) until a newer document is consumed."
  })
  samlSpMetadataValidUntil?: string;
  @attr(#{
    kind: "single",
    from: "consumed metadata",
    what: "The EFFECTIVE cacheDuration of the consumed document (the shortest in its chain), as the xs:duration it carried. Once it has elapsed since the document was consumed, the document is STALE: the background refresher fetches it again where it can (saml2.spMetadataRefresh), and it keeps working until its validUntil."
  })
  samlSpMetadataCacheDuration?: string;
  @attr(#{
    kind: "single",
    from: "consumed metadata",
    what: "When the document was last consumed, and how: `<ISO instant> <refresh|upload|mdq>` — `mdq` for one fetched from the Metadata Query responder, which the background refresher can fetch again."
  })
  samlSpMetadataConsumedAt?: string;
  @attr(#{
    kind: "single",
    from: "consumed metadata",
    what: "What checking the consumed document's own signature found: `verified`, `unsigned`, or `signed-not-verified` (signed, and no samlSpMetadataSigningCertificate to check it against)."
  })
  samlSpMetadataSignature?: string;
  @attr(#{
    kind: "single",
    from: "by hand",
    what: "THE CERTIFICATE THIS SERVICE PROVIDER'S METADATA MUST BE SIGNED WITH, base64 DER. With it set, a document that is unsigned, or whose signature does not verify against it, is REFUSED and nothing on the entry changes. Without it a signed document is consumed and recorded as signed-not-verified: the trust act is then the operator's choice of URL (or document), which is what an explicit refresh or upload is."
  })
  samlSpMetadataSigningCertificate?: string;
  @attr(#{
    kind: "single",
    from: "by hand",
    overrides: "saml2.encryptAssertion",
    what: "TRUE or FALSE: encrypt the assertion issued to THIS service provider, overriding saml2.encryptAssertion. This is the one of the four most worth having per application — an estate where one service provider requires encryption and the others cannot read it is the ordinary case, and a service-wide switch could not express it."
  })
  saml2EncryptAssertion?: string;
  @attr(#{
    kind: "single",
    from: "by hand",
    overrides: "saml2.encryptionAlgorithm",
    what: "The block cipher used for this service provider — aes256-gcm, aes128-gcm, aes256-cbc or aes128-cbc — overriding saml2.encryptionAlgorithm. A value that is not one of those four is IGNORED with a warning and the service-wide choice is used, exactly as an unparseable number would be."
  })
  saml2EncryptionAlgorithm?: string;
  @attr(#{
    kind: "single",
    from: "by hand",
    overrides: "saml2.keyTransportAlgorithm",
    what: "How the content key is wrapped for this service provider — rsa-oaep-mgf1p, rsa-oaep (SHA-256, MGF1-SHA-256; #168) or rsa-1_5 — overriding saml2.keyTransportAlgorithm. An appliance that accepts only rsa-1_5 is the reason this is per application rather than a decision made once for the whole service."
  })
  saml2KeyTransportAlgorithm?: string;
  @attr(#{
    kind: "single",
    from: "by hand",
    overrides: "saml2.encryptLogoutNameId",
    what: "TRUE or FALSE: send <saml:EncryptedID> rather than <saml:NameID> in the LogoutRequest sent to this service provider, overriding saml2.encryptLogoutNameId. Separate from the assertion switch above because they are separate capabilities in every service provider library that has them: one that decrypts assertions may still expect a plain NameID in a logout message."
  })
  saml2EncryptLogoutNameId?: string;
  // ---------------------------------------------------------------------
  // THE OAUTH 2.0 / OIDC PER-CLIENT OVERRIDES, added 2026-08-27 in the same
  // change that generalised the SAML ten below.
  //
  // Five settings a real authorization server varies per client and this one
  // could not: how long each of the three tokens lives, how long a quiet
  // refresh chain survives, and whether signing out kills the refresh token.
  // Every one is a DEFAULT on /admin/token-lifetimes and an exception here.
  //
  // WHAT IS DELIBERATELY NOT HERE is as much of the point as what is.
  // `oauth2.issuer` and `oauth2.rfc9700` describe the authorization SERVER —
  // one answer per realm, and a per-client issuer would produce tokens that
  // fail discovery. `oauth2.clockSkewS` and `oauth2.clientAssertionSkewS` are
  // clock tolerances, which the SAML block below argues are a fact about the
  // estate rather than about one relying party. And `oauth2.redirectUris` is
  // the SERVICE-WIDE default list; the per-application half of that has
  // existed since this file was written and is `oauthRedirectUri` above.
  @attr(#{
    kind: "single",
    from: "by hand",
    overrides: "oauth2.accessTokenTtlS",
    what: "HOW LONG AN ACCESS TOKEN ISSUED TO THIS CLIENT LIVES, in seconds, overriding oauth2.accessTokenTtlS for it alone. It becomes the token's `exp`, so it is stamped in at signing time and nothing here can shorten a token already issued. Set it to 30 on one client to watch that client refresh while every other client carries on."
  })
  oauthAccessTokenTtlS?: string;
  @attr(#{
    kind: "single",
    from: "by hand",
    overrides: "oauth2.idTokenTtlS",
    what: "The same for the OIDC ID Token, overriding oauth2.idTokenTtlS. Separate from the access token's because the two go to different readers: an ID Token is consumed once at sign-in and an access token is presented for as long as it lasts."
  })
  oauthIdTokenTtlS?: string;
  @attr(#{
    kind: "single",
    from: "by hand",
    overrides: "oauth2.refreshTokenTtlS",
    what: "The same for the refresh token, overriding oauth2.refreshTokenTtlS. A value at or below oauthAccessTokenTtlS is legal and is a grant that can never usefully be renewed — /admin/token-lifetimes reports that combination for the service-wide pair, and it is just as reachable here."
  })
  oauthRefreshTokenTtlS?: string;
  @attr(#{
    kind: "single",
    from: "by hand",
    overrides: "oauth2.refreshIdleSeconds",
    what: "RFC 9700 MODE ONLY: how long a refresh chain may sit unused before it is cut off, overriding oauth2.refreshIdleSeconds for this client. It is measured from the last time any token in the CHAIN was redeemed rather than from issuance, so a busy client keeps its grant and a quiet one does not. Outside RFC 9700 mode nothing reads it, which is a property of the setting rather than of this attribute."
  })
  oauthRefreshIdleSeconds?: string;
  // AN APPLICATION'S OWN CUSTOM CLAIMS (rcbj, 2026-10-01), one JSON array
  // of rows per claim set, each row the realm's shape (`name` and `value`,
  // or `name`, `attribute`, `multi` and `type`). Added to the realm's set
  // at issuance and winning by name (admin_stats.effectiveClaimSet()).
  // Written by the configuration tab's Custom claims section, through the
  // `set-custom-claim` and `remove-custom-claim` actions; kept off the
  // field grid, which would show a JSON array as one text box.
  @attr(#{
    kind: "single",
    from: "the console's Custom claims section",
    what: "THIS APPLICATION'S OWN ACCESS TOKEN CLAIMS, as a JSON array of rows like the realm's Custom claims page. Added to the realm's access token claims for tokens issued to this client, and an application row replaces the realm row of the same name."
  })
  oauthClaimsAccessToken?: string;
  @attr(#{
    kind: "single",
    from: "the console's Custom claims section",
    what: "THIS APPLICATION'S OWN ID TOKEN CLAIMS, as a JSON array of rows like the realm's Custom claims page. Added to the realm's ID Token claims for this client, winning by name."
  })
  oauthClaimsIdToken?: string;
  @attr(#{
    kind: "single",
    from: "the console's Custom claims section",
    what: "THIS APPLICATION'S OWN USERINFO CLAIMS, as a JSON array of rows like the realm's UserInfo claims page. Added to the realm's UserInfo claims answered to this client, winning by name."
  })
  oauthClaimsUserinfo?: string;
  // AN APPLICATION'S OWN DIRECTORY-ATTRIBUTE SELECTIONS (#495), one JSON
  // array of catalogue attribute names per claim set: the ticked
  // catalogue of the realm's Custom claims and UserInfo claims pages, for
  // this client. HELD, IT REPLACES THE REALM'S SELECTION for the set;
  // absent, the realm's is in force (claim_attributes.ts). Written by the
  // configuration tab's sections through `set-claim-attributes` and
  // `inherit-claim-attributes`; kept off the field grid for the reason the
  // rows above are.
  @attr(#{
    kind: "single",
    from: "the console's Custom claims section",
    what: "THIS APPLICATION'S OWN SELECTION of directory attributes for its access tokens, as a JSON array of attribute names from the realm's Custom claims catalogue. When present it REPLACES the realm's selection for tokens issued to this client; absent, the realm's is used."
  })
  oauthClaimAttributesAccessToken?: string;
  @attr(#{
    kind: "single",
    from: "the console's Custom claims section",
    what: "THIS APPLICATION'S OWN SELECTION of directory attributes for its ID Tokens, a JSON array of catalogue attribute names, replacing the realm's selection when present."
  })
  oauthClaimAttributesIdToken?: string;
  @attr(#{
    kind: "single",
    from: "the console's UserInfo claims section",
    what: "THIS APPLICATION'S OWN SELECTION of directory attributes for the UserInfo response answered to it, a JSON array of catalogue attribute names, replacing the realm's selection when present."
  })
  oauthClaimAttributesUserinfo?: string;
  // HOW THE REALM'S SET AND THE APPLICATION'S OWN ARE COMBINED, PER TOKEN
  // TYPE (#395; `common/scope_claims.ts`). On the field grid, under the
  // OAuth sub-tab's Claims in tokens section.
  @attr(#{
    kind: "single",
    from: "the console, the management API, or by hand",
    what: "HOW THE REALM'S ACCESS-TOKEN CLAIMS AND THIS APPLICATION'S OWN ARE COMBINED (#395), the typed rows and the ticked directory attributes alike: application (only this application's own), union (the realm's and its own), intersection (only what both hold) or realm (only the realm's). Unset, its rows are added to the realm's and win by name, and its selection replaces the realm's. An application holding nothing of its own gets the realm's whatever this says."
  })
  oauthClaimsCombineAccessToken?: string;
  @attr(#{
    kind: "single",
    from: "the console, the management API, or by hand",
    what: "HOW THE REALM'S ID TOKEN CLAIMS AND THIS APPLICATION'S OWN ARE COMBINED (#395), the typed rows and the ticked directory attributes alike: application (only this application's own), union (the realm's and its own), intersection (only what both hold) or realm (only the realm's). Unset, its rows are added to the realm's and win by name, and its selection replaces the realm's. An application holding nothing of its own gets the realm's whatever this says."
  })
  oauthClaimsCombineIdToken?: string;
  @attr(#{
    kind: "single",
    from: "the console, the management API, or by hand",
    what: "HOW THE REALM'S USERINFO CLAIMS AND THIS APPLICATION'S OWN ARE COMBINED (#395), the typed rows and the ticked directory attributes alike: application (only this application's own), union (the realm's and its own), intersection (only what both hold) or realm (only the realm's). Unset, its rows are added to the realm's and win by name, and its selection replaces the realm's. An application holding nothing of its own gets the realm's whatever this says."
  })
  oauthClaimsCombineUserinfo?: string;
  // WHAT A RESOURCE SERVER WANTS ON THE ACCESS TOKENS ADDRESSED TO IT
  // (#395; RFC 9068 section 2.2.2). Read by `oauth2.ts`'s accessToken()
  // for each audience the token names.
  @attr(#{
    kind: "multi",
    from: "the console, the management API, or by hand",
    what: "THE IDENTITY CLAIMS THIS RESOURCE SERVER WANTS on the access tokens addressed to it (one of its oauthAudience values, or its client_id named as a scope), from OpenID Connect Core section 5.4's profile, email, address and phone claims. Each is released only when the scope that covers it was GRANTED, and on a token for several resource servers only a claim every one of them declared goes in. Absent, the token carries none of these claims from this layer — preferred_username included."
  })
  oauthAccessTokenClaim?: string[];
  // CLAIMS MAPPED TO THIS RESOURCE SERVER'S OWN SCOPES (2026-10-09): drawn
  // and written by the application's Scope claims tab, so kept off the
  // field grid for the reason the selections above are.
  @attr(#{
    kind: "single",
    from: "the console's Scope claims tab",
    what: "THE CLAIMS EACH OF THIS RESOURCE SERVER'S PERMISSIONS CARRIES, as a JSON object from a permission name (one of its oauthPermission values) to a list of attribute names from the realm's claim catalogue. An access token addressed to this application on which a permission was GRANTED carries the person's values of that permission's attributes, under the catalogue's claim names; granting the permission is the grant of those claims, a standard OpenID Connect one included. Combined with the client's claims as oauthAccessTokenClaimsCombine says."
  })
  oauthPermissionClaims?: string;
  @attr(#{
    kind: "single",
    from: "the console, the management API, or by hand",
    what: "HOW THE CLIENT'S ACCESS-TOKEN CLAIMS AND THIS RESOURCE SERVER'S DECLARED CLAIMS (oauthAccessTokenClaim) ARE COMBINED on a token addressed to it: 'union' (the default), 'intersection' (only claims both carry), 'client' (only the client's) or 'resource' (only the declared ones). Several resource servers that disagree are combined by intersection. Nothing a grant did not cover is released, whichever is chosen."
  })
  oauthAccessTokenClaimsCombine?: string;
  @attr(#{
    kind: "single",
    from: "by hand",
    overrides: "oauth2.revokeRefreshOnLogout",
    what: "TRUE or FALSE: does signing out revoke this client's refresh tokens, overriding oauth2.revokeRefreshOnLogout. FALSE is the interesting case and it is why this is worth having per client — a client that can refresh its way back after a sign-out is a real defect in real deployments, and this makes it reproducible for ONE client while the rest behave."
  })
  oauthRevokeRefreshOnLogout?: string;
  // WHO MAY START A SIGN-IN, PER CLIENT (#426, #710). OpenID Connect's
  // identity-provider-initiated sign-in is Core section 4 (rcbj on #426):
  // /launch/{app} sends the person to `oauthInitiateLoginUri` and the client
  // starts an ordinary authorization request from there.
  @attr(#{
    kind: "single",
    from: "the console, the management API, or by hand",
    overrides: "oauth2.thirdPartyInitiatedLogin",
    families: #["oauth2", "oidc"],
    what: "TRUE or FALSE: may /launch/{app} — and the user portal's Sign in link — send a person to this client's oauthInitiateLoginUri (OpenID Connect Core section 4), overriding oauth2.thirdPartyInitiatedLogin."
  })
  oauthThirdPartyInitiatedLogin?: string;
  @attr(#{
    kind: "single",
    from: "the console, the management API, or by hand",
    overrides: "oauth2.spInitiatedSso",
    families: #["oauth2", "oidc"],
    what: "TRUE or FALSE: does /oauth2/authorize answer this client when it was not just launched, overriding oauth2.spInitiatedSso. FALSE answers only an authorization request that follows a /launch of this client on the same session within oauth2.launchWindowS, once per launch, and refuses any other with unauthorized_client."
  })
  oauthSpInitiatedSso?: string;
  // ---------------------------------------------------------------------
  // OPENID CONNECT CORE SECTION 4's `initiate_login_uri`, AS AN ATTRIBUTE OF
  // ITS OWN (#426, #710). It lived only inside appRegistrationJson until
  // then — written by RFC 7591 registration and RFC 7592 update and by
  // nothing else — so a client an administrator created could not have one
  // and nothing could launch it. Registration writes this now, and the
  // console and the management API edit it. https only, no fragment
  // (STS-REG-0188), and initiateLoginUriOf() checks again on the read,
  // because `ldapmodify` reaches it unchecked.
  // ---------------------------------------------------------------------
  @attr(#{
    kind: "single",
    from: "RFC 7591 initiate_login_uri, the console, the management API, or by hand",
    families: #["oauth2", "oidc"],
    what: "WHERE A SIGN-IN TO THIS CLIENT IS STARTED BY A THIRD PARTY: OpenID Connect Core section 4's initiate_login_uri, which /launch/{app} and the user portal send a person to with iss, login_hint and target_link_uri. https only, with no fragment."
  })
  oauthInitiateLoginUri?: string;
  // ---------------------------------------------------------------------
  // WHAT A PERSON IS SHOWN ABOUT THIS CLIENT WHILE SIGNING IN TO IT
  // (#1300). OpenID Connect Registration section 2's `logo_uri` ("the
  // server SHOULD display this image to the End-User during approval"),
  // `policy_uri` and `tos_uri` (the OP SHOULD display them). They lived
  // only inside appRegistrationJson until #1300, so nothing drew them and
  // a client an administrator made could not have them; registration and
  // RFC 7592 update write them now, and the console and the management
  // API edit them, as `oauthInitiateLoginUri` above. (`client_uri` is
  // already kept, as `appHomePageUrl`.)
  //
  // **THE BROWSER LOADS THE LOGO; THIS SERVICE NEVER DIALS IT.** The
  // sign-in and consent screens draw an `<img>` whose `src` is this value
  // and add exactly its origin to that page's `img-src`
  // (`clientDisplayOf()`, `ShellDocument`'s `images`) — the rule that this
  // service dials no URL a caller supplied is untouched. https only
  // (STS-REG-0365): an http image on an https page is mixed content a
  // browser blocks, and an http policy link is a document a network can
  // rewrite. clientDisplayOf() checks again on the read, because
  // `ldapmodify` reaches the attributes unchecked.
  // ---------------------------------------------------------------------
  @attr(#{
    kind: "single",
    from: "RFC 7591 logo_uri, the console, the management API, or by hand",
    families: #["oauth2", "oidc"],
    what: "THE CLIENT'S LOGO: OpenID Connect Registration section 2's logo_uri, drawn on the sign-in and consent screens beside the client's name. The person's browser loads it from this address; this service never fetches it. An absolute https URL."
  })
  oauthLogoUri?: string;
  @attr(#{
    kind: "single",
    from: "RFC 7591 policy_uri, the console, the management API, or by hand",
    families: #["oauth2", "oidc"],
    what: "THE CLIENT'S PRIVACY POLICY: OpenID Connect Registration section 2's policy_uri, linked from the sign-in and consent screens. An absolute https URL."
  })
  oauthPolicyUri?: string;
  @attr(#{
    kind: "single",
    from: "RFC 7591 tos_uri, the console, the management API, or by hand",
    families: #["oauth2", "oidc"],
    what: "THE CLIENT'S TERMS OF SERVICE: OpenID Connect Registration section 2's tos_uri, linked from the sign-in and consent screens. An absolute https URL."
  })
  oauthTosUri?: string;
  // ---------------------------------------------------------------------
  // THE SIXTH OAUTH OVERRIDE, ADDED 2026-09-01, AND THE FIRST ATTRIBUTE IN
  // THIS SCHEMA THAT IS SCOPED TO A PROTOCOL FAMILY.
  //
  // Every other row here is offered on every entry. Most of them are named
  // for the family they belong to and that has been enough: writing
  // `saml2SignAssertion` onto an OAuth client is inert rather than wrong, and
  // refusing it would be this registry having an opinion about an attribute
  // nothing reads. This one is different in a way worth spelling out, because
  // the mechanism it introduces will be reached for again.
  //
  // It decides what the TOKEN ENDPOINT does for one client_id. So an entry
  // that is not an OAuth client at all cannot be the entry it decides
  // anything for — there is no request that would ever arrive naming it — and
  // a value written there is not merely inert, it is a POLICY somebody
  // believes is in force. That is the state `families` exists to refuse: the
  // attribute applies to the OAuth 2.0 and OpenID Connect families, and
  // updateApplication() and createApplication() both turn away a write onto
  // an entry declared for neither, naming what to tick first. The console
  // does not offer it there either, which is the same "a form cannot offer a
  // field the action would refuse" rule EDITABLE's own header states.
  //
  // `ldapmodify` still reaches it, as it reaches everything here. The refusal
  // is the difference between offering an operation and merely not preventing
  // it, which is the line the derived attributes are already on.
  @attr(#{
    kind: "single",
    from: "the console, the management API, or by hand",
    overrides: "oauth2.tokenExchangeRefreshToken",
    families: #["oauth2", "oidc"],
    what: "WHETHER AN RFC 8693 TOKEN EXCHANGE PERFORMED BY THIS CLIENT GETS A `refresh_token` BESIDE THE EXCHANGED ACCESS TOKEN, overriding oauth2.tokenExchangeRefreshToken for it alone. One of three words: `never`, `when-requested` (the service-wide default — the client asks with RFC 8693 section 2.1's `requested_token_type` and gets one only if it did) or `always`.\n\nIT IS READ ON THE CLIENT PERFORMING THE EXCHANGE and not on the audience, because the refresh token is handed to the client: it is that party's credential to hold, revoke and eventually redeem. The subject the exchange is ABOUT has no entry in this registry at all in the interesting case, since the whole point of an exchange is a subject_token from somewhere else.\n\n**IT APPLIES TO THE OAUTH 2.0 AND OPENID CONNECT FAMILIES AND TO NO OTHER, and unlike every other attribute here that is ENFORCED.** An entry declared for neither is turned away by both console doors and by the management API, naming the family to tick first — because a value here is a policy about the token endpoint, and an entry no token request can ever name would carry it looking as though it were in force. The block above this row argues it. `ldapmodify` reaches this attribute like every other and is not checked.\n\nA VALUE THAT IS NOT ONE OF THE THREE WORDS IS NOT AN ERROR AT WRITE TIME AND IS NOT SILENT: settingFor() warns naming the entry, the attribute and what it holds, and the service-wide setting decides — the same three-state honesty every other override on this entry gets."
  })
  oauthTokenExchangeRefreshToken?: string;
  // ---------------------------------------------------------------------
  // THE GROUP CLAIM, PER APPLICATION, added 2026-08-27.
  //
  // The one override group here that is NOT a protocol's: these four reach an
  // OAuth 2.0 access token, an OIDC ID Token, a UserInfo response, a SAML 2.0
  // assertion and a SAML 1.1 one at once, because `group_claims.js` answers
  // all five claim sets from one place. So an application that carries them
  // gets its own group claim in whichever of those it actually uses, and an
  // application declared for two protocols gets the same answer in both —
  // which is the behaviour a claim mapping should have and the reason these
  // are four attributes rather than eight.
  // ---------------------------------------------------------------------
  // THE ROLES THIS APPLICATION REQUIRES, added 2026-09-05 with the role
  // register.
  //
  // IT IS THE OPPOSITE RELATION FROM `roleMemberApplication` ON A ROLE
  // ENTRY, and the two are one keystroke apart in a listing, so it is worth
  // being exact: `roleMemberApplication` says this application HOLDS a role
  // — what a client_credentials grant is decided on, where there is no
  // person — and this attribute says what this application DEMANDS of
  // whoever is being authenticated before anything is issued for it.
  //
  // ABSENT MEANS `EVERYBODY`, and that is what makes the whole feature off
  // by default without being switched off. Everybody holds EVERYBODY, so an
  // application nobody has configured admits exactly who it admitted before
  // roles existed — while the decision is still a real XACML decision,
  // visible on /admin/xacml/decide and in the audit log. Narrowing this list
  // is how enforcement is turned on for one application, and it is the only
  // way it is turned on.
  @attr(#{
    kind: "multi",
    from: "by hand",
    what: "A role somebody must hold before this application is issued anything — a token, an assertion, a WS-Federation response, a session. Multi-valued and ANY of them is enough. ABSENT MEANS EVERYBODY, the built-in role everybody holds, which is why an unconfigured application refuses nobody. The decision is made by the XACML PDP against the policy named by xacml.issuancePolicy, not by an if in an issuance site, so the reason for a refusal is a policy somebody can read."
  })
  @link(#{to: "role", cardinality: "multi", owns: false, what: "Roles whose holders may use this application."})
  appRequiredRole?: string[];
  // ---------------------------------------------------------------------
  // THE DELEGATION POLICY (#108, 2026-09-23): WHO MAY ACT FOR WHOM AT THE
  // TWO DOORS THAT HAD NO POLICY — WS-Trust `OnBehalfOf` / `ActAs` and the
  // RFC 8693 token exchange.
  //
  // KERBEROS'S MODEL, DELIBERATELY AND BY NAME, and on the same kind of
  // entry: a KDC decides S4U2Proxy from `msDS-AllowedToDelegateTo` on the
  // front end and `msDS-AllowedToActOnBehalfOfOtherIdentity` on the back
  // end, protocol transition from TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION,
  // and nothing at all for an account flagged NOT_DELEGATED. These four are
  // those, on `ou=applications`, so there is no new store and no new object
  // class — an `ldapmodify` IS a policy change, exactly as it is for a
  // redirect URI. `common/delegation_policy.ts` reads them; the person's
  // half (`stsNotDelegated`, `stsMayAct`) is on the person's own entry.
  //
  // A TARGET IS AN APPLICATION IDENTIFIER. An RFC 8693 `audience` or
  // `resource` and a WS-Trust `AppliesTo` are resolved to the application
  // that registered them first (forAudience(), forAppliesTo()), and a value
  // here may also be the raw string, so an unregistered audience can be
  // allowed without inventing an entry for it.
  // ---------------------------------------------------------------------
  @attr(#{
    kind: "multi",
    from: "by hand",
    what: "THE TARGETS THIS APPLICATION MAY OBTAIN A TOKEN FOR ON SOMEBODY ELSE'S BEHALF, when it is the INTERMEDIARY of a WS-Trust OnBehalfOf / ActAs request or an RFC 8693 token exchange — the analogue of Kerberos's msDS-AllowedToDelegateTo, on the front end. One application identifier (or the literal audience / AppliesTo) per value. Enforced in product mode; development records what would have been refused on /admin/delegation. appAllowedToActOnBehalfOf on the TARGET is the other way to allow the same pair."
  })
  appAllowedToDelegateTo?: string[];
  @attr(#{
    kind: "multi",
    from: "by hand",
    what: "THE INTERMEDIARIES THIS APPLICATION ACCEPTS as acting for somebody else when it is the TARGET of a delegation — the resource-based analogue of Kerberos's msDS-AllowedToActOnBehalfOfOtherIdentity, set on the back end. One intermediary application identifier per value."
  })
  appAllowedToActOnBehalfOf?: string[];
  @attr(#{
    kind: "multi",
    from: "by hand",
    what: "THE PEOPLE THIS INTERMEDIARY MAY ACT FOR, as group DNs: a subject must be a member of one of them. EMPTY MEANS ANYBODY who is not protected — a person carrying stsNotDelegated, or a member of the console's Admin Read or Admin Write roster, is never delegated whatever this says."
  })
  appDelegationSubjectGroup?: string[];
  // #186: THE SEMANTICS this application may use or be used with — one set
  // for the three protocols, read as a fact by the exchange policy. It
  // replaced appTrustedToImpersonate: impersonation in the set is that
  // flag (and, at Kerberos, a forwardable S4U2Self ticket).
  @attr(#{
    kind: "multi",
    from: "by hand",
    what: "THE SEMANTICS this application allows: `delegation`, `impersonation`, or both. As the ACTOR — the client of a token exchange, the requester of a WS-Trust OnBehalfOf / ActAs, the service of a Kerberos S4U request — it says what this application may DO; empty is delegation only, so impersonating somebody needs `impersonation` here (Kerberos's TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION). As the SUBJECT it says what may be done AS it; empty is both. The issuance policy decides; this is one of its facts."
  })
  appDelegationSemantics?: string[];
  @attr(#{
    kind: "single",
    from: "by hand",
    what: "`delegation` or `impersonation`: what an act this application is part of is when the request does not say — the actor's default first, then the subject's, then delegation.defaultSemantics."
  })
  appDefaultDelegationSemantics?: string;
  @attr(#{
    kind: "single",
    from: "by hand",
    what: "TRUE or FALSE, default FALSE: nobody may act for this application, in any protocol — NOT_DELEGATED, the application's counterpart of a person's stsNotDelegated."
  })
  appNotDelegated?: string;
  @attr(#{
    kind: "single",
    from: "by hand",
    what: "The DN of ONE party — a person or another application — this application names as its delegate: a token about it carries RFC 8693 section 4.4's may_act naming that party, as the issuance policy assigns it, and an exchange of that token by anybody else is refused. A person's counterpart is stsMayAct."
  })
  appMayAct?: string;
  @attr(#{
    kind: "single",
    from: "by hand",
    overrides: "groups.claim",
    what: "TRUE or FALSE: does anything issued to this application carry a groups claim at all, overriding groups.claim. FALSE on one application is how a client that breaks on an unexpected claim is exercised without taking the claim away from everything else."
  })
  appGroupsClaim?: string;
  @attr(#{
    kind: "single",
    from: "by hand",
    overrides: "groups.claimName",
    what: "What the groups claim is CALLED for this application, overriding groups.claimName. This is the attribute that earns the group its place here: `groups`, `roles`, `memberOf` and a URI-shaped claim name are all ordinary, they differ per relying party in every real deployment, and a single service-wide name meant only one of them could be tested at a time."
  })
  appGroupsClaimName?: string;
  @attr(#{
    kind: "single",
    from: "by hand",
    overrides: "groups.claimValue",
    what: "Whether the claim carries each group's name or its whole DN, overriding groups.claimValue. Relying parties genuinely differ: one matches on `cn` and the next was written against an LDAP DN."
  })
  appGroupsClaimValue?: string;
  @attr(#{
    kind: "single",
    from: "by hand",
    overrides: "groups.claimFromMemberOf",
    what: "Where the groups are read from for this application, overriding groups.claimFromMemberOf — the person's memberOf attribute, or a search of the groups container. The two agree in this directory; they are worth telling apart because a real directory's memberOf can lag."
  })
  appGroupsClaimFromMemberOf?: string;
  // ---------------------------------------------------------------------
  // THE WS-FEDERATION ASSERTION LIFETIME, added 2026-08-27 together with the
  // setting it overrides — which did not exist either, because wsfed.js
  // carried a module-level `const lifetimeMin = 60`. A group of one, for the
  // reason config.js's row gives.
  @attr(#{
    kind: "single",
    from: "by hand",
    overrides: "wsfed.assertionLifetimeMin",
    what: "How long the SAML 1.1 assertion inside a WS-Federation sign-in response for THIS relying party is valid, in minutes, overriding wsfed.assertionLifetimeMin. It sets the assertion's Conditions and the wsu:Lifetime of the RequestSecurityTokenResponse around it, so the envelope and the document inside it cannot disagree. It is separate from saml11AssertionLifetimeMin: one application may speak both, and a WS-Federation session and a Browser/POST assertion are not consumed the same way."
  })
  wsfedAssertionLifetimeMin?: string;
  // ---------------------------------------------------------------------
  // THE TEN PER-APPLICATION OVERRIDES, added 2026-08-27.
  //
  // Each one names a `config.js` setting and, where it is set, WINS over it
  // for this application alone. Absent — which is every application until
  // somebody types one — the setting decides, exactly as it always did.
  // `overrides` is the setting's key, and it is on the row rather than in
  // prose because `/admin/saml-assertions` reads it to name the attribute
  // beside each default, and saml2_sso.js and saml11_sso.js read it to
  // resolve a value. Three readers, one table.
  //
  // ALL TEN ARE `single`, and that is a decision rather than an oversight.
  // Every identifier attribute here is `multi` because an application
  // answering to two client_ids is one application; a SETTING is the
  // opposite case — an application has one answer to "sign the assertion?",
  // and a list would be a question with no page to ask it and no rule for
  // which value won.
  //
  // DECLARED, never observed. Nothing in this service writes them: they are
  // configuration in exactly the way `samlSingleLogoutService` is, and for
  // the same reason — there is nothing to observe. An application does not
  // tell this service how long its assertions should live.
  //
  // A VALUE THAT WILL NOT PARSE IS IGNORED, not refused, and the resolver
  // says so in the log. That is this service's rule everywhere a directory
  // value is read back: an `ldapmodify` can put any string on any attribute,
  // and an identity provider that refused to issue because somebody typed
  // "yes" instead of "true" would be a service that stopped answering.
  @attr(#{
    kind: "single",
    from: "the console's Custom SAML attributes section",
    what: "THIS SERVICE PROVIDER'S OWN SAML 2.0 ATTRIBUTES, as a JSON array of rows like the realm's Custom SAML attributes page (a nameFormat allowed). Added to the realm's SAML 2.0 attributes in assertions for this audience, winning by name."
  })
  saml2CustomAttributes?: string;
  @attr(#{
    kind: "single",
    from: "the console's Custom SAML attributes section",
    what: "THIS RELYING PARTY'S OWN SAML 1.1 ATTRIBUTES, as a JSON array of rows like the realm's Custom SAML attributes page (a namespace allowed). Added to the realm's SAML 1.1 attributes in assertions for this audience (SAML 1.1, WS-Federation, WS-Trust), winning by name."
  })
  saml11CustomAttributes?: string;
  // The SAML halves of #495's selections, as the OAuth ones above.
  @attr(#{
    kind: "single",
    from: "the console's Custom SAML attributes section",
    what: "THIS SERVICE PROVIDER'S OWN SELECTION of directory attributes for its SAML 2.0 assertions, a JSON array of catalogue attribute names, replacing the realm's selection when present."
  })
  saml2ClaimAttributes?: string;
  @attr(#{
    kind: "single",
    from: "the console's Custom SAML attributes section",
    what: "THIS RELYING PARTY'S OWN SELECTION of directory attributes for its SAML 1.1 assertions (SAML 1.1, WS-Federation, WS-Trust), a JSON array of catalogue attribute names, replacing the realm's selection when present."
  })
  saml11ClaimAttributes?: string;
  // The SAML halves of #395's combine modes, as the OAuth ones.
  @attr(#{
    kind: "single",
    from: "the console, the management API, or by hand",
    what: "HOW THE REALM'S SAML 2.0 ATTRIBUTES AND THIS APPLICATION'S OWN ARE COMBINED (#395), the typed rows and the ticked directory attributes alike: application (only this application's own), union (the realm's and its own), intersection (only what both hold) or realm (only the realm's). Unset, its rows are added to the realm's and win by name, and its selection replaces the realm's. An application holding nothing of its own gets the realm's whatever this says."
  })
  saml2ClaimsCombine?: string;
  @attr(#{
    kind: "single",
    from: "the console, the management API, or by hand",
    what: "HOW THE REALM'S SAML 1.1 ATTRIBUTES AND THIS APPLICATION'S OWN ARE COMBINED (#395), the typed rows and the ticked directory attributes alike: application (only this application's own), union (the realm's and its own), intersection (only what both hold) or realm (only the realm's). Unset, its rows are added to the realm's and win by name, and its selection replaces the realm's. An application holding nothing of its own gets the realm's whatever this says."
  })
  saml11ClaimsCombine?: string;
  // AN OPENID4VCI CLIENT'S OWN CREDENTIAL CLAIMS (#495): the realm's
  // Verifiable Credentials → Credential claims selection, for credentials
  // issued on an access token issued to this client (vc_claims.ts).
  @attr(#{
    kind: "single",
    families: #["oid4vci"],
    from: "the console's Credential claims section",
    what: "THIS CLIENT'S OWN SELECTION of the directory attributes a Verifiable Credential carries, a JSON array of catalogue attribute names. When present it REPLACES the realm's Credential claims selection for credentials issued on this client's access tokens; the issuer metadata still advertises the realm's."
  })
  vcCredentialClaimAttributes?: string;
  @attr(#{
    kind: "single",
    from: "by hand",
    overrides: "saml2.assertionLifetimeMin",
    what: "HOW LONG THIS SERVICE PROVIDER'S ASSERTIONS ARE VALID, in minutes, overriding saml2.assertionLifetimeMin for it alone. What it becomes is Conditions/NotOnOrAfter and the bearer SubjectConfirmationData/NotOnOrAfter alike, widened at both ends by saml.clockSkewS — which is NOT per application, because it is a fact about the clocks in this estate rather than about one relying party."
  })
  saml2AssertionLifetimeMin?: string;
  @attr(#{
    kind: "single",
    from: "by hand",
    overrides: "saml2.signAssertion",
    what: "TRUE or FALSE: sign the <saml:Assertion> issued to this service provider, overriding saml2.signAssertion for it alone. FALSE is a test case rather than a mistake — a service provider that accepts an unsigned assertion has a hole in it, and this is how one is found without turning signing off for every other application at the same time. That is the whole reason this is per application."
  })
  saml2SignAssertion?: string;
  @attr(#{
    kind: "single",
    from: "by hand",
    overrides: "saml2.signResponse",
    what: "TRUE or FALSE: sign the <samlp:Response> around the assertion for this service provider, overriding saml2.signResponse. On the HTTP Redirect binding it also controls the query-string signature of section 3.4.4.1, which is the one a redirect response is really verified by."
  })
  saml2SignResponse?: string;
  @attr(#{
    kind: "single",
    from: "by hand",
    overrides: "saml2.nameIdFormat",
    what: "The NameID Format used for this service provider when its AuthnRequest's NameIDPolicy asks for none, overriding saml2.nameIdFormat. A request that DOES name a format is still answered with the one it named — this is the default, not a restriction, and it is deliberately NOT checked against samlNameIdFormat beside it, which is the list of formats this service provider has ASKED for."
  })
  saml2NameIdFormat?: string;
  @attr(#{
    kind: "single",
    from: "by hand",
    overrides: "saml2.artifactTtlS",
    what: "How long an artifact minted for this service provider can be resolved for, in seconds, overriding saml2.artifactTtlS. An artifact is ALSO one-shot however long this is — resolving it destroys it, which section 3.6.4.1 requires and no lifetime can express."
  })
  saml2ArtifactTtlS?: string;
  @attr(#{
    kind: "single",
    from: "by hand",
    overrides: "saml11.assertionLifetimeMin",
    what: "The SAML 1.1 equivalent of saml2AssertionLifetimeMin, overriding saml11.assertionLifetimeMin for this relying party. Separate from the 2.0 attribute for the reason the two SETTINGS are separate: the profiles are separate implementations consumed differently, and an application declared for both legitimately wants two answers."
  })
  saml11AssertionLifetimeMin?: string;
  @attr(#{
    kind: "single",
    from: "by hand",
    overrides: "saml11.signAssertion",
    what: "TRUE or FALSE: sign the SAML 1.1 <saml:Assertion> for this relying party, overriding saml11.signAssertion. The Browser/POST profile REQUIRES a signed assertion (saml-profile-1.1 section 4.2.1.4), so FALSE here is exactly the test case: a relying party that accepts it anyway has a hole."
  })
  saml11SignAssertion?: string;
  @attr(#{
    kind: "single",
    from: "by hand",
    overrides: "saml11.signResponse",
    what: "TRUE or FALSE: sign the SAML 1.1 <samlp:Response> for this relying party, overriding saml11.signResponse, with the reference naming ResponseID."
  })
  saml11SignResponse?: string;
  @attr(#{
    kind: "single",
    from: "by hand",
    overrides: "saml11.nameIdFormat",
    what: "The NameIdentifier Format used for this relying party, overriding saml11.nameIdFormat. SAML 1.1 has no request message, so nothing can ask for a format and this is the only thing that decides it — which makes it the more useful of the two per-application format attributes."
  })
  saml11NameIdFormat?: string;
  @attr(#{
    kind: "single",
    from: "by hand",
    overrides: "saml11.artifactTtlS",
    what: "How long a SAML 1.1 artifact minted for this relying party can be resolved for, in seconds, overriding saml11.artifactTtlS. The Browser/Artifact profile's SOAP responder is what redeems it, once."
  })
  saml11ArtifactTtlS?: string;
  // WHO MAY START A SIGN-IN, PER SERVICE PROVIDER (#426, #710). Each is a
  // realm default's override, read through settingFor() like the ten
  // above; IDENTITY-PROVIDER-INITIATED IS OFF until an application opts in
  // (rcbj on #426), so `saml2IdpInitiatedSso` is the one an operator sets.
  @attr(#{
    kind: "single",
    from: "the console, the management API, or by hand",
    overrides: "saml2.idpInitiatedSso",
    what: "TRUE or FALSE: may this identity provider START a sign-in to this service provider — an unsolicited Response (saml-profiles-2.0-os section 4.1.5) from /saml2/unsolicited or /launch/{app} — overriding saml2.idpInitiatedSso. TRUE only for a service provider that expects one: the Response carries no InResponseTo, so it cannot tell one it was sent from one pushed into its browser."
  })
  saml2IdpInitiatedSso?: string;
  @attr(#{
    kind: "single",
    from: "the console, the management API, or by hand",
    overrides: "saml2.ssoConsent",
    what: "TRUE or FALSE: is a person asked, once, before SAML 2.0 signs them in to this application from a session they already have, overriding saml2.ssoConsent (ASVS 5.0.0 7.6.2). FALSE suits an application everybody in the realm is expected to use; a global consent on the entry answers for everyone and keeps the record of who agreed."
  })
  saml2SsoConsent?: string;
  @attr(#{
    kind: "single",
    from: "the console, the management API, or by hand",
    overrides: "saml2.spInitiatedSso",
    what: "TRUE or FALSE: is this service provider's own <samlp:AuthnRequest> answered, overriding saml2.spInitiatedSso. FALSE answers it RequestDenied, leaving identity-provider-initiated sign-in as the only way in."
  })
  saml2SpInitiatedSso?: string;
  @attr(#{
    kind: "single",
    from: "the console, the management API, or by hand",
    overrides: "saml11.idpInitiatedSso",
    what: "TRUE or FALSE: may a SAML 1.1 sign-in to this relying party START here — /saml11/sso/{rp} with a TARGET and no shire, or /launch/{app} — overriding saml11.idpInitiatedSso."
  })
  saml11IdpInitiatedSso?: string;
  @attr(#{
    kind: "single",
    from: "the console, the management API, or by hand",
    overrides: "saml11.ssoConsent",
    what: "TRUE or FALSE: is a person asked, once, before SAML 1.1 signs them in to this application from a session they already have, overriding saml11.ssoConsent (ASVS 5.0.0 7.6.2). FALSE suits an application everybody in the realm is expected to use; a global consent on the entry answers for everyone and keeps the record of who agreed."
  })
  saml11SsoConsent?: string;
  @attr(#{
    kind: "single",
    from: "the console, the management API, or by hand",
    overrides: "saml11.spInitiatedSso",
    what: "TRUE or FALSE: is a SAML 1.1 sign-in this relying party started — the Shibboleth 1.3 AuthnRequest profile, a request carrying shire — answered, overriding saml11.spInitiatedSso. The request is an unsigned URL, so FALSE closes the door rather than proving who opened it."
  })
  saml11SpInitiatedSso?: string;
  @attr(#{
    kind: "single",
    from: "SAML 2.0",
    what: "TRUE when the last AuthnRequest from this service provider carried a signature — an enveloped ds:Signature on the POST binding, or the Signature parameter of section 3.4.4.1 on the Redirect binding. ASSIGNED rather than accumulated, because it is a fact about the last request and a history of booleans would say nothing."
  })
  samlAuthnRequestSigned?: string;
  @attr(#{
    kind: "multi",
    from: "WS-Federation",
    identifier: true,
    identifierName: "wtrealm",
    what: "THE WTREALM from a wsignin1.0 request (section 13.2.1) — WS-Federation's identifier attribute. Accumulates, for the reason every identifier here does."
  })
  wsfedRealm?: string[];
  @attr(#{
    kind: "multi",
    from: "WS-Federation, the console, or by hand",
    what: "WHERE A SIGN-IN RESPONSE IS POSTED BACK TO for this application: the `wreply` of section 13.2.1, WS-Federation's redirect URI. It was written into samlAssertionConsumerService until 2026-08-25, which put a wreply in the attribute the SAML pages read for an assertion consumer service and for the Single Logout fallback — one attribute holding two protocols' return addresses, so a WS-Federation application appeared to have a SAML ACS it had never named. Two facts, two attributes. Like the SAML one beside it this is CHECKED IN PRODUCT MODE ONLY: development refuses no wreply, because a service that refused would remove a test case rather than add one; product posts only to an address on this list and a sighting never adds one. A wreply development recorded is marked on appReturnAddressObserved and product refuses it until it is confirmed; values recorded before that mark existed carry none and still need reviewing before a realm is switched to product."
  })
  wsfedReplyUrl?: string[];
  // WHO MAY START A SIGN-IN, PER RELYING PARTY (#426, #710).
  @attr(#{
    kind: "single",
    from: "the console, the management API, or by hand",
    overrides: "wsfed.idpInitiatedSso",
    what: "TRUE or FALSE: may this identity provider START a sign-in to this relying party — /wsfed/initiate/{rp} or /launch/{app}, posting to its registered wsfedReplyUrl — overriding wsfed.idpInitiatedSso."
  })
  wsfedIdpInitiatedSso?: string;
  @attr(#{
    kind: "single",
    from: "the console, the management API, or by hand",
    overrides: "wsfed.spInitiatedSso",
    what: "TRUE or FALSE: is this relying party's own wsignin1.0 answered, overriding wsfed.spInitiatedSso. A wsignin1.0 is an unsigned URL, so FALSE closes the door rather than proving who opened it."
  })
  wsfedSpInitiatedSso?: string;
  @attr(#{
    kind: "single",
    from: "the console, the management API, or by hand",
    overrides: "wsfed.ssoConsent",
    what: "TRUE or FALSE: is a person asked, once, before WS-Federation signs them in to this application from a session they already have, overriding wsfed.ssoConsent (ASVS 5.0.0 7.6.2). FALSE suits an application everybody in the realm is expected to use; a global consent on the entry answers for everyone and keeps the record of who agreed."
  })
  wsfedSsoConsent?: string;
  @attr(#{
    kind: "multi",
    from: "by hand",
    what: "WHERE A wsignoutcleanup1.0 PING IS SENT for this application — WS-Federation's logout URI, and the one this table did not have until 2026-08-30. DECLARED, not observed, which makes it the sibling of samlSingleLogoutService rather than of wsfedReplyUrl: a cleanup is sent when a SESSION ends, and by then the request that would have carried a wreply is long over.\n\n**A DECLARED ADDRESS OUTRANKS AN OBSERVED ONE** (#747). `cleanupTargetsFor()` pings every value here for a realm the session signed into, and the wreply the sign-in response went to, which `session.wsfedRealms` records, only where this is empty."
  })
  wsfedSignOutUri?: string[];
  @attr(#{
    kind: "multi",
    from: "WS-Trust",
    identifier: true,
    identifierName: "AppliesTo",
    what: "THE APPLIESTO ADDRESS from a RequestSecurityToken — the service the token is issued FOR, and WS-Trust's identifier attribute. Accumulates.\n\n**IT IS READ**, which it was not before 2026-08-27, and it is `oauthAudience`'s exception arriving through a second protocol: an OnBehalfOf or ActAs asking for a token to reach `https://esb.example.com` is recorded on /admin/delegation against the APPLICATION that registered that address, so a chain of delegated hops draws as one picture rather than as boxes named after URLs that nothing else in it mentions. In development a LOOKUP and not a permission — an AppliesTo nobody registered is issued for and recorded verbatim; in product it is refused (#496). See forAppliesTo(), which asks this attribute first and `samlEntityId` behind it."
  })
  wstrustAppliesTo?: string[];
  // #485: the OAuth 2.0 scopes a WS-Trust JWT for this application
  // carries, judged as an access token's are.
  @attr(#{
    kind: "multi",
    from: "by hand",
    families: #["wstrust"],
    what: "THE OAUTH 2.0 SCOPES A WS-TRUST JWT FOR THIS APPLICATION CARRIES, one scope value each (#485). A JWT WS-Trust issues with this application as the AppliesTo (wst:TokenType urn:ietf:params:oauth:token-type:jwt) carries them in its `scope` claim, space-delimited (RFC 9068 section 2.2.3); with none set it carries no `scope`. A SAML token is unaffected.\n\n**EACH IS JUDGED AS AN OAUTH ACCESS TOKEN'S IS**, with this application as the client: `oauthAllowedScope` declares what it may be issued (in product; this service's protected scopes in every mode), and the issuance policy's per-scope question decides. A value the policy drops is LEFT OFF the token and audited (STS-OAUTH-0579), never issued. A write naming an undeclared scope is accepted here, because the declaration may change and development grants undeclared scopes: declare it on oauthAllowedScope too. A value the policy will drop is WARNED about where it is set (#488): beside this field, in the Save reply, and as `warnings` on the /admin-api write replies and the application's view."
  })
  wstrustJwtScope?: string[];
  // --- Kerberos and OID4VP ----------------------------------------------
  @attr(#{
    kind: "multi",
    from: "Kerberos v5",
    identifier: true,
    identifierName: "SPN",
    what: "THE SPN, e.g. HTTP/sts@EXAMPLE.COM — Kerberos v5's identifier attribute. A Kerberos service is an application like the others here, and it is the one whose identifier this service may have created on demand (KRB5_SERVICE_DOMAINS). It accumulates, and here that is the ordinary case rather than the unusual one: one service commonly answers to several SPNs — HTTP/host and HTTP/host.example.com — and a real KDC holds them all against one account."
  })
  krb5ServicePrincipalName?: string[];
  // #493: THIS SERVICE'S OWN PAC CLAIMS, one JSON array of rows of the
  // realm's Kerberos PAC claims shape (`name`, `type` and `value`, or
  // `name`, `type`, `attribute` and `multi`). Added to a SERVICE TICKET for
  // one of this application's SPNs, winning by name over what the TGT
  // carried (admin_stats.kerberosApplicationPacClaims(), the KDC's
  // claimsForTicket()). The 2026-10-01 pattern of the five sets above, and
  // kept off the field grid for their reason.
  @attr(#{
    kind: "single",
    from: "the console's Kerberos PAC claims section",
    what: "THIS SERVICE'S OWN PAC CLAIMS, as a JSON array of rows like the realm's Kerberos PAC claims page. Added to the claims a service ticket for one of this application's SPNs carries (those of the TGT it was issued from), an application row replacing the claim of the same name. Only while krb5.pacClaims is on."
  })
  krb5ClaimsPac?: string;
  // #1250: THIS CLIENT'S OWN GNAP ACCESS-TOKEN JWT CLAIMS, one JSON array
  // of rows of the realm's shape (`name` and `value`, or `name`,
  // `attribute`, `multi` and `type`). Added to a jwt-signed token, and to
  // the JWT inside a jwt-encrypted token, for this client instance; an
  // application row wins by name. The protocol's own claims win over both.
  // Macaroon, biscuit and zcap do not carry them. Kept off the field grid
  // for the rows above's reason: the GNAP tab's Custom claims section
  // writes them.
  @attr(#{
    kind: "single",
    from: "the console's Custom claims section",
    what: "THIS CLIENT'S OWN GNAP ACCESS-TOKEN JWT CLAIMS, as a JSON array of rows like the other custom-claim sets. Added to a jwt-signed token and to the JWT inside a jwt-encrypted token issued to this client, an application row replacing the realm row of the same name. The token's own claims (access, flags, label, grant_id and the JWT names) cannot be overridden. Macaroon, biscuit and zcap tokens do not carry these rows."
  })
  gnapClaimsAccessToken?: string;
  // #186: UNCONSTRAINED DELEGATION is Kerberos's alone, and OFF unless set.
  @attr(#{
    kind: "single",
    from: "by hand",
    what: "TRUE or FALSE, default FALSE: this Kerberos service is TRUSTED FOR DELEGATION — unconstrained (Active Directory's TRUSTED_FOR_DELEGATION). Its service tickets carry ok-as-delegate, which tells a client it may forward its TGT here; whoever holds a forwarded TGT can act as that person anywhere. A protected person's TGT is never forwardable, so it is never forwarded however this is set. Constrained delegation (appAllowedToDelegateTo, appAllowedToActOnBehalfOf) is the safer alternative."
  })
  krb5TrustedForDelegation?: string;
  // #430 Phase 3: DELEGATION ACROSS A KERBEROS TRUST, the service's two
  // words on it. Read by the issuance policy as facts; the trusts
  // themselves are records under ou=kerberosTrusts.
  @attr(#{
    kind: "multi",
    from: "by hand",
    families: #["krb5"],
    familyWhy: "S4U2Self is a Kerberos request ([MS-SFU]).",
    what: "THE KERBEROS REALMS WHOSE USERS THIS SERVICE MAY OBTAIN S4U2SELF TICKETS FOR, beside its own. EMPTY MEANS ITS OWN REALM ONLY. A value must be a realm this realm's trusts accept tickets from — a trust holding an incoming key, or a realm a transitive one routes — and is checked at the write."
  })
  krb5S4uSelfRealm?: string[];
  @attr(#{
    kind: "single",
    from: "by hand",
    families: #["krb5"],
    familyWhy: "ok-as-delegate and forwarded TGTs are Kerberos's.",
    what: "`inherit` (the default) or `deny`: what this service says of a TGT delegated to it ACROSS A TRUST — ok-as-delegate on its tickets for a user of another realm. `inherit` follows the trust's attributes ([MS-KILE] 3.3.5.7.5); `deny` refuses it whatever they say. It only narrows: nothing here enables what the trust does not."
  })
  krb5ForeignTgtDelegation?: string;
  // THE STORED SERVICE KEY (2026-09-12). Two rows, and the split between
  // them is the design: one is SECRET and one is not, so that every page
  // listing service principals can say what is held without opening a key.
  // Both are DERIVED in `EDITABLE`'s sense — neither is a form field — and
  // written by `kerberos/krb5_person_keys.ts` through the directory slot,
  // NOT through updateApplication(), whose audit summary and reply quote
  // the value written. They are rows here for one reason that is not
  // optional: writeApplication() REPLACES an entry from its record, and an
  // attribute the schema does not list would be erased by the next
  // sighting — which for a Kerberos service is the next ticket issued for it.
  // (Since #1230 the store keeps an attribute the schema does not list;
  // these stay rows because the pages and the record describe them.)
  @attr(#{
    kind: "single",
    from: "/admin/kerberos/principals",
    secret: true,
    what: "A SERVICE PRINCIPAL'S RANDOM LONG-TERM KEYS, one per enctype, in ONE value: a JSON document naming the SPN, the realm and the kvno beside the keys, SEALED under the key-encryption key wherever that key outlives the process. One value rather than one per enctype so that a key cannot be moved onto another entry or another kvno without the seal failing. Password-equivalent: it is WITHHELD from every page and every /admin-api reply, and the one time it leaves this service is as the keytab a create or a rotate hands over."
  })
  krb5ServiceKeys?: string;
  @attr(#{
    kind: "single",
    from: "/admin/kerberos/principals",
    what: "What `krb5ServiceKeys` holds, without the keys: the kvno, the enctypes, when the keys were made and whether they are sealed. Written in the same act as the keys, so the two cannot describe different generations."
  })
  krb5ServiceKeyInfo?: string;
  // CERTIFICATE ENROLLMENT (2026-09-13): what ACME, EST and SCEP issued to
  // this application, the credentials that let it ask, and the host names
  // an administrator registered for it. `common/cert_enrollment.ts` is the
  // one reader and writer; the attributes are schema rows so that a sighting
  // rewriting this entry from its record does not erase them.
  @attr(#{
    kind: "multi",
    from: "/enroll/acme, /.well-known/est, /enroll/scep",
    what: "One JSON record per certificate issued to this application over an enrollment protocol: serial, protocol, profile, subject, names, validity, who asked, whether the key was generated here, the certificate and its issuing chain, and a revocation mark. Public material. Written by common/cert_enrollment.ts only."
  })
  appEnrolledCertificate?: string[];
  @attr(#{
    kind: "multi",
    from: "/.well-known/est/serverkeygen",
    secret: true,
    what: "A private key THIS SERVICE generated for one of the certificates above (EST server-side key generation, or the console's server-generated key pair), as `<serial>:<PEM>`, sealed wherever the key-encryption key outlives the process. WITHHELD from every page and /admin-api reply; it is handed over once, at issuance."
  })
  appEnrolledPrivateKey?: string[];
  @attr(#{
    kind: "multi",
    from: "/admin/acme",
    secret: true,
    what: "ACME External Account Binding keys issued for this application, one JSON record each: the key id, the sealed HMAC key, its expiry and the account it bound. A working credential, WITHHELD from every page and /admin-api reply."
  })
  appAcmeEabKey?: string[];
  @attr(#{
    kind: "multi",
    from: "/admin/scep",
    secret: true,
    what: "SCEP challenge passwords issued for this application, one JSON record each: the id, a SHA-256 digest of the secret, the profile, the expiry and when it was redeemed. WITHHELD from every page and /admin-api reply."
  })
  appScepChallenge?: string[];
  @attr(#{
    kind: "multi",
    from: "/admin/acme, /admin/est, /admin/scep",
    what: "A DNS name or IP address this application may be issued a certificate for over ACME, EST or SCEP. Registering one is the whole proof of control: this service never dials a name to validate it. Set by an administrator; read by common/cert_enrollment.ts."
  })
  appCertificateHostName?: string[];
  @attr(#{
    kind: "single",
    from: "POST /oauth2/register",
    what: "THE RFC 7591 REGISTRATION VERBATIM, as JSON on one attribute. It is here because RFC 7591 lets a client register arbitrary metadata and RFC 7592's read has to hand back what was registered — which no fixed set of LDAP attributes can represent. It is the STARTING POINT when the record is reconstructed and not the last word: every member that also has an attribute above is then overwritten FROM that attribute, so an ldapmodify of oauthRedirectUri is what RFC 9700 mode enforces. Edit this only to change a member that has no attribute of its own."
  })
  appRegistrationJson?: string;
  @attr(#{
    kind: "single",
    from: "POST /oauth2/register",
    sensitive: true,
    what: "The RFC 7592 registration access token, which is what guards the read, update and delete operations on this client. Sealed like oauthClientSecret wherever the process holds a durable key-encryption key (since 2026-10-01), and never written to the audit log."
  })
  appRegistrationAccessToken?: string;
  @attr(#{
    kind: "multi",
    from: "OpenID4VP",
    identifier: true,
    identifierName: "client_id",
    what: "THE VERIFIER'S CLIENT_ID in an Authorization Request asking for a presentation — OpenID4VP's identifier attribute. This service's own Verifier takes its from configuration (oid4vp.clientId) rather than from a caller, so that record appears the first time a presentation is verified; a value declared here is a FOREIGN verifier somebody is configuring."
  })
  oid4vpClientId?: string[];
  // --- THE FOUR FAMILIES THAT ONLY EVER DECLARE ------------------------
  // Nothing in this service writes any of these four. That is the whole
  // point of them rather than a gap: LDAP, SCIM, SPIFFE and Federation
  // either authenticate the CALLER rather than an application (the first
  // two), file the identity in a container of its own (the third), or keep
  // the arrangement under ou=federations (the fourth) — so the registry had
  // nowhere to put "what is this application called when it talks to us that
  // way", which is a fact an operator has before anything connects. They are
  // declaration and only ever declaration, exactly as appAllowedProtocol is,
  // and like it they grant and refuse nothing.
  @attr(#{
    kind: "multi",
    from: "the console, or by hand",
    identifier: true,
    identifierName: "partner id",
    what: "WHAT A FEDERATION PARTNER CALLS ITSELF — a foreign identity provider's entityID, or its issuer identifier where the relationship speaks OpenID Connect. THE RELATIONSHIP IS NOT HERE: the endpoints, the certificate and the attribute mapping live under ou=federations and are what /federation/acs/{id} actually verifies against (see federation/CLAUDE.md). This entry is the partner as a PARTY, and this attribute is the name it goes by — so a value here federates with nobody, which is the one place in this service where that sentence has teeth."
  })
  federationPartnerId?: string[];
  // Both modes' truth (#543 round 2): "EVERY BIND HERE SUCCEEDS" was
  // unqualified, and in product only a person binds.
  @attr(#{
    kind: "multi",
    from: "the console, or by hand",
    identifier: true,
    identifierName: "bind DN",
    what: "THE DN A DIRECTORY CLIENT BINDS AS on 389 or LDAPS 636. Nothing will ever write this and nothing will ever read it: in development mode EVERY BIND SUCCEEDS — any DN, any password, anonymous — and in product mode only a person binds, so an application reads the directory through SCIM instead. It is where an operator records which credential an application is expected to use, beside the rest of what that application is."
  })
  ldapBindDn?: string[];
  @attr(#{
    kind: "multi",
    from: "the console, or by hand",
    identifier: true,
    identifierName: "client_id",
    what: "WHAT A PROVISIONING CLIENT AT /scim/v2 IS CALLED — the OAuth client_id it presents a token from, or the username it sends in Basic. That surface authenticates its CALLER in any of the six schemes RFC 7644 section 2 names rather than an application identifier, so it writes nothing here; the value is a declaration, and the SCIM gate is what decides whether a credential is demanded at all."
  })
  scimClientId?: string[];
  @attr(#{
    kind: "multi",
    from: "the console, or by hand",
    what: "THE ACME PROFILES THIS APPLICATION MAY BE ISSUED. Where it lists something it OVERRIDES acme.allowedProfiles for this application, wider or narrower; empty leaves the realm's list. The five CA, OCSP and KDC profiles are never issued."
  })
  acmeAllowedProfiles?: string[];
  @attr(#{
    kind: "single",
    from: "the console, or by hand",
    what: "THE PROFILE THIS APPLICATION IS ISSUED OVER ACME WHEN A REQUEST NAMES NONE, overriding acme.defaultProfile. Used only while the list in force for it allows it."
  })
  acmeDefaultProfile?: string;
  @attr(#{
    kind: "single",
    from: "by hand",
    overrides: "acme.certificateLifetimeDays",
    what: "How long a certificate this application is issued over ACME is valid, in days, overriding acme.certificateLifetimeDays (longer or shorter). No certificate outlives its Issuing CA."
  })
  acmeCertificateLifetimeDays?: string;
  @attr(#{
    kind: "multi",
    from: "the console, or by hand",
    what: "THE EST PROFILES THIS APPLICATION MAY BE ISSUED. Where it lists something it OVERRIDES est.allowedProfiles for this application, wider or narrower; empty leaves the realm's list. The five CA, OCSP and KDC profiles are never issued."
  })
  estAllowedProfiles?: string[];
  @attr(#{
    kind: "single",
    from: "the console, or by hand",
    what: "THE PROFILE THIS APPLICATION IS ISSUED OVER EST WHEN A REQUEST NAMES NONE, overriding est.defaultProfile. Used only while the list in force for it allows it."
  })
  estDefaultProfile?: string;
  @attr(#{
    kind: "single",
    from: "by hand",
    overrides: "est.certificateLifetimeDays",
    what: "How long a certificate this application is issued over EST is valid, in days, overriding est.certificateLifetimeDays (longer or shorter). No certificate outlives its Issuing CA."
  })
  estCertificateLifetimeDays?: string;
  @attr(#{
    kind: "multi",
    from: "the console, or by hand",
    what: "THE SCEP PROFILES THIS APPLICATION MAY BE ISSUED. Where it lists something it OVERRIDES scep.allowedProfiles for this application, wider or narrower; empty leaves the realm's list. The five CA, OCSP and KDC profiles are never issued."
  })
  scepAllowedProfiles?: string[];
  @attr(#{
    kind: "single",
    from: "the console, or by hand",
    what: "THE PROFILE THIS APPLICATION IS ISSUED OVER SCEP WHEN A REQUEST NAMES NONE, overriding scep.defaultProfile. Used only while the list in force for it allows it."
  })
  scepDefaultProfile?: string;
  @attr(#{
    kind: "single",
    from: "by hand",
    overrides: "scep.certificateLifetimeDays",
    what: "How long a certificate this application is issued over SCEP is valid, in days, overriding scep.certificateLifetimeDays (longer or shorter). No certificate outlives its Issuing CA."
  })
  scepCertificateLifetimeDays?: string;
  @attr(#{
    kind: "single",
    from: "by hand",
    overrides: "est.basicAuthentication",
    what: "Whether EST accepts this application's client id and secret (HTTP Basic, RFC 7030 section 3.2.3), overriding est.basicAuthentication: TRUE accepts it and FALSE refuses it whatever the realm says; unset leaves the realm to decide."
  })
  estBasicAuthentication?: string;
  @attr(#{
    kind: "single",
    from: "by hand",
    overrides: "est.certificateAuthentication",
    what: "Whether EST accepts a certificate this realm issued this application (TLS client authentication, RFC 7030 section 3.3.2), overriding est.certificateAuthentication: TRUE accepts it and FALSE refuses it; unset leaves the realm to decide."
  })
  estCertificateAuthentication?: string;
  @attr(#{
    kind: "single",
    from: "by hand",
    overrides: "est.serverKeyGeneration",
    what: "Whether EST /serverkeygen (RFC 7030 section 4.4) may generate this application's key, overriding est.serverKeyGeneration: TRUE allows it and FALSE refuses it; unset leaves the realm to decide."
  })
  estServerKeyGeneration?: string;
  @attr(#{
    kind: "single",
    from: "by hand",
    overrides: "pki.enrollmentMaxCertificatesPerEntry",
    what: "How many unexpired enrolled certificates (ACME, EST and SCEP together) this application may hold, overriding pki.enrollmentMaxCertificatesPerEntry (higher or lower)."
  })
  enrollMaxCertificates?: string;
  // THE DID DOCUMENT'S CONTENTS (2026-10-01): what this service publishes
  // at <base>/applications/<identifier>/did.json for an application
  // declared for `did`. See the `did` row of PROTOCOLS.
  @attr(#{
    kind: "multi",
    from: "the console's Generate a key pair, or by hand",
    what: "A PUBLIC KEY THE APPLICATION'S DID DOCUMENT PUBLISHES, one JWK per value, each a JsonWebKey2020 verification method named by its kid (its RFC 7638 thumbprint where it carries none) and listed under authentication and assertionMethod. Public members only: a value carrying d, p, q, dp, dq, qi, oth, k or priv is refused. Generate a key pair on the application's page and the private half is handed out once and not kept here."
  })
  didPublicKeyJwk?: string[];
  @attr(#{
    kind: "single",
    sensitive: true,
    from: "the console's Generate a key pair",
    what: "THE PRIVATE HALVES OF THE DID KEYS THIS SERVICE GENERATED, as a JSON array of private JWKs, SEALED at rest under the key-encryption key like an application's RFC 7523 key pair. Kept so this service can sign the application's Domain Linkage Credentials (the DIF Well-Known DID Configuration) on request; a key pasted into didPublicKeyJwk by hand has no private half here and cannot sign one. Written by Generate a key pair only."
  })
  didPrivateKeys?: string;
  @attr(#{
    kind: "multi",
    from: "the console, or by hand",
    what: "A SERVICE THE DID DOCUMENT NAMES, as <type>|<serviceEndpoint>: for example LinkedDomains|https://app.example.com. The type is one token; the endpoint an absolute http or https URL. Each becomes a service entry with the id <did>#service-<n>."
  })
  didService?: string[];
  @attr(#{
    kind: "multi",
    from: "the console, or by hand",
    what: "ANOTHER IDENTIFIER FOR THE SAME APPLICATION, published as the DID document's alsoKnownAs: an absolute URI such as the application's web origin or its client_id URL. DID Core makes it a claim, not a proof; a relying party checks it."
  })
  didAlsoKnownAs?: string[];
  // A SECRET PUSH DESTINATION (#221 P3, 2026-10-06): where a service
  // account's rotated password is written, and with what. See the
  // `secret-destination` row of PROTOCOLS and
  // `common/secret_destinations.ts`, which reads these; every address here
  // is the operator's, and no request can name one.
  @attr(#{
    kind: "single",
    from: "Directory → Secret destinations, the console, or by hand",
    families: #["secret-destination"],
    what: "WHICH SECRETS MANAGER THIS DESTINATION IS: aws (Secrets Manager, PutSecretValue), gcp (Secret Manager, AddSecretVersion), azure (Key Vault, setSecret), vault (a HashiCorp Vault or OpenBao KV version 2 engine, a write with check-and-set) or file (development mode only). A key management service is not a destination: it stores keys, not secrets."
  })
  secretDestProvider?: string;
  @attr(#{
    kind: "single",
    from: "Directory → Secret destinations, the console, or by hand",
    families: #["secret-destination"],
    what: "WHAT A PUSH WRITES: password (the bare password, the default) or json — {\"username\", \"password\", \"realm\", \"rotatedAt\"}, the object a reader takes the password out of by its field, as this service's own secret reads do (keys.kekField and the like). In Vault, whose versions are maps, password writes the one field secretDestField names."
  })
  secretDestPayload?: string;
  @attr(#{
    kind: "single",
    from: "Directory → Secret destinations, the console, or by hand",
    families: #["secret-destination"],
    what: "aws: the AWS region the secrets are in (us-east-1)."
  })
  secretDestRegion?: string;
  @attr(#{
    kind: "single",
    from: "Directory → Secret destinations, the console, or by hand",
    families: #["secret-destination"],
    what: "gcp: the project a short secret name is in, so that a service account names its secret as sts-svc-backup rather than projects/<project>/secrets/sts-svc-backup. A full resource name is taken as it is."
  })
  secretDestProject?: string;
  @attr(#{
    kind: "single",
    from: "Directory → Secret destinations, the console, or by hand",
    families: #["secret-destination"],
    what: "azure: the vault URL (https://<name>.vault.azure.net). vault: the Vault or OpenBao address (https://vault.example.com:8200). https only — the write credential and a password cross it."
  })
  secretDestEndpoint?: string;
  @attr(#{
    kind: "single",
    from: "Directory → Secret destinations, the console, or by hand",
    families: #["secret-destination"],
    what: "vault: where the KV version 2 engine is mounted; secret when empty."
  })
  secretDestMount?: string;
  @attr(#{
    kind: "single",
    from: "Directory → Secret destinations, the console, or by hand",
    families: #["secret-destination"],
    what: "vault, with the password payload: the field of the version the password is written to; value when empty, which is the field this service's own Vault reads default to."
  })
  secretDestField?: string;
  @attr(#{
    kind: "single",
    from: "Directory → Secret destinations, the console, or by hand",
    families: #["secret-destination"],
    what: "file (DEVELOPMENT MODE ONLY): the absolute directory a secret name is a file in. The file must already exist; a name that leaves the directory is refused."
  })
  secretDestDirectory?: string;
  @attr(#{
    kind: "single",
    from: "Directory → Secret destinations, the console, or by hand",
    families: #["secret-destination"],
    what: "vault: the PEM certificates of the CA the Vault listener chains to, trusted beside the public roots. Certificates are public; the certificate is always verified."
  })
  secretDestCaCertificates?: string;
  @attr(#{
    kind: "single",
    from: "Directory → Secret destinations, the console, or by hand",
    families: #["secret-destination"],
    secret: true,
    what: "THE DESTINATION'S WRITE CREDENTIAL, which may write versions of named secrets and should be able to do nothing else: aws, a JSON {\"accessKeyId\", \"secretAccessKey\"[, \"sessionToken\"]}; gcp, a service account key file's JSON; azure, a JSON {\"tenantId\", \"clientId\", \"clientSecret\"}; vault, a token. Separate from the read-only credentials this service reads its own key-encryption key and database password with. Sealed with the key-encryption key when keys persist, WITHHELD from every page, /admin-api reply and directory read, and never logged."
  })
  secretDestCredential?: string;
  // AN OUTBOUND SCIM CLIENT (#552): the remote service provider this
  // entry pushes to, how it authenticates there, and what it pushes. See
  // the `scim-client` row of PROTOCOLS and `scim/scim_client.ts`, which
  // reads these; every address here is the operator's.
  @attr(#{
    kind: "single",
    from: "Protocols → SCIM → Clients, or by hand",
    families: #["scim-client"],
    what: "THE REMOTE SCIM BASE URI (RFC 7644 section 1.3), the /v2 segment included where the service provider uses one: https://idp.example.com/scim/v2. https only (section 7.2); no query, fragment or user information (section 7.1)."
  })
  scimClientBaseUrl?: string;
  @attr(#{
    kind: "single",
    from: "Protocols → SCIM → Clients, or by hand",
    families: #["scim-client"],
    what: "TRUE to push changes and reconcile; FALSE (the default) keeps the configuration and sends nothing."
  })
  scimClientEnabled?: string;
  @attr(#{
    kind: "single",
    from: "Protocols → SCIM → Clients, or by hand",
    families: #["scim-client"],
    what: "HOW A REQUEST IS AUTHENTICATED (RFC 7644 section 2): basic (HTTP Basic with scimClientUsername and scimClientPassword), oauth2 (a client_credentials token from scimClientTokenEndpoint, sent as a Bearer token), or none (only the TLS client certificate, when one is configured)."
  })
  scimClientAuthMethod?: string;
  @attr(#{
    kind: "single",
    from: "Protocols → SCIM → Clients, or by hand",
    families: #["scim-client"],
    what: "basic: the user name the service provider knows this client by."
  })
  scimClientUsername?: string;
  @attr(#{
    kind: "single",
    from: "Protocols → SCIM → Clients, or by hand",
    families: #["scim-client"],
    secret: true,
    what: "basic: the password. Sealed with the key-encryption key when keys persist, WITHHELD from every page, /admin-api reply and directory read, and never logged."
  })
  scimClientPassword?: string;
  @attr(#{
    kind: "single",
    from: "Protocols → SCIM → Clients, or by hand",
    families: #["scim-client"],
    what: "oauth2: the token endpoint of the authorization server the service provider trusts. https only."
  })
  scimClientTokenEndpoint?: string;
  @attr(#{
    kind: "single",
    from: "Protocols → SCIM → Clients, or by hand",
    families: #["scim-client"],
    what: "oauth2: the client_id this client is registered under there."
  })
  scimClientOAuthClientId?: string;
  @attr(#{
    kind: "single",
    from: "Protocols → SCIM → Clients, or by hand",
    families: #["scim-client"],
    secret: true,
    what: "oauth2: the client secret. Sealed, withheld and never logged."
  })
  scimClientOAuthClientSecret?: string;
  @attr(#{
    kind: "single",
    from: "Protocols → SCIM → Clients, or by hand",
    families: #["scim-client"],
    what: "oauth2: how the client authenticates at the token endpoint — client_secret_basic (the default) or client_secret_post (RFC 6749 section 2.3.1)."
  })
  scimClientOAuthClientAuth?: string;
  @attr(#{
    kind: "single",
    from: "Protocols → SCIM → Clients, or by hand",
    families: #["scim-client"],
    what: "oauth2: the scope asked for, space-separated (scim:write, for this service's own /scim/v2). Empty asks for none."
  })
  scimClientOAuthScope?: string;
  @attr(#{
    kind: "single",
    from: "Protocols → SCIM → Clients, or by hand",
    families: #["scim-client"],
    what: "oauth2: an RFC 8707 resource indicator sent with the token request, where the authorization server wants one."
  })
  scimClientOAuthResource?: string;
  @attr(#{
    kind: "single",
    from: "Protocols → SCIM → Clients, or by hand",
    families: #["scim-client"],
    what: "THE TLS CLIENT CERTIFICATE presented to the service provider: none (the default), issued (by this realm's CA, from its tls-client Issuing CA, revocable on /admin/pki) or uploaded (scimClientTlsCertificate and scimClientTlsPrivateKey). It is presented whatever scimClientAuthMethod says."
  })
  scimClientTlsSource?: string;
  @attr(#{
    kind: "single",
    from: "Protocols → SCIM → Clients, or by hand",
    families: #["scim-client"],
    what: "The client certificate, PEM, its chain after it. Public."
  })
  scimClientTlsCertificate?: string;
  @attr(#{
    kind: "single",
    from: "Protocols → SCIM → Clients, or by hand",
    families: #["scim-client"],
    secret: true,
    what: "The client certificate's private key, PEM. Sealed, withheld and never logged."
  })
  scimClientTlsPrivateKey?: string;
  @attr(#{
    kind: "single",
    from: "Protocols → SCIM → Clients, or by hand",
    families: #["scim-client"],
    what: "PEM certificates of a CA the service provider's TLS certificate chains to, trusted beside the public roots. The certificate and its host name are always verified."
  })
  scimClientCaCertificates?: string;
  @attr(#{
    kind: "single",
    from: "Protocols → SCIM → Clients, or by hand",
    families: #["scim-client"],
    what: "WHO IS PUSHED: all (every person in the realm), groups (the members of scimClientScopeGroups) or filter (the people scimClientScopeFilter matches). Somebody who leaves the scope is deprovisioned there."
  })
  scimClientScopeMode?: string;
  @attr(#{
    kind: "multi",
    from: "Protocols → SCIM → Clients, or by hand",
    families: #["scim-client"],
    what: "groups scope: the groups whose members are pushed, each a group's cn or DN."
  })
  scimClientScopeGroups?: string[];
  @attr(#{
    kind: "single",
    from: "Protocols → SCIM → Clients, or by hand",
    families: #["scim-client"],
    what: "filter scope: an RFC 4515 LDAP filter a person's entry must match, such as (department=Sales)."
  })
  scimClientScopeFilter?: string;
  @attr(#{
    kind: "single",
    from: "Protocols → SCIM → Clients, or by hand",
    families: #["scim-client"],
    what: "WHICH GROUPS ARE PUSHED, each with its in-scope members only: none, selected (scimClientGroups), member-groups (every group an in-scope person is in) or all."
  })
  scimClientGroupMode?: string;
  @attr(#{
    kind: "multi",
    from: "Protocols → SCIM → Clients, or by hand",
    families: #["scim-client"],
    what: "selected groups: each a group's cn or DN."
  })
  scimClientGroups?: string[];
  @attr(#{
    kind: "single",
    from: "Protocols → SCIM → Clients, or by hand",
    families: #["scim-client"],
    what: "WHAT HAPPENS THERE when a person is deleted here or leaves the scope: deactivate (active false, the default) or delete. A disabled account here is always active false there."
  })
  scimClientDeprovision?: string;
  @attr(#{
    kind: "single",
    from: "Protocols → SCIM → Clients, or by hand",
    families: #["scim-client"],
    what: "HOW OFTEN THE WHOLE SCOPE IS RECONCILED, in minutes, by the cluster scheduler: every person and group in scope is pushed, and what the service provider holds under an externalId of this realm's and no longer in scope is deprovisioned. 0 (the default) reconciles only when an administrator asks."
  })
  scimClientReconcileMinutes?: string;
  // A SERVICE DEPLOYED AS CELLS (#553): where the service provider is,
  // which the home cell puts to the issuance policy before it pushes a
  // person (`cell_transfer.ts`, purpose `scim-provision`), and which cells
  // push to it at all. Read only when the service is deployed as cells.
  @attr(#{
    kind: "single",
    from: "Protocols → SCIM → Clients, or by hand",
    families: #["scim-client"],
    what: "WHERE THE SERVICE PROVIDER IS, as a jurisdiction code of the cell map (us, eu, ca, …). In a service deployed as cells, each person's home cell asks the issuance policy whether that person's data may go there (release-attributes, purpose scim-provision) before it pushes them; a refusal leaves them out of scope — not pushed, and deprovisioned if they were. Empty is an unknown jurisdiction, which the strict default never releases to. Ignored when the service is one cell."
  })
  scimClientJurisdiction?: string;
  @attr(#{
    kind: "multi",
    from: "Protocols → SCIM → Clients, or by hand",
    families: #["scim-client"],
    what: "WHICH CELLS PUSH TO THE SERVICE PROVIDER, each a cell id; none (the default) means every cell. A cell not listed sends nothing for this client, so the people homed there are not pushed. Ignored when the service is one cell."
  })
  scimClientCells?: string[];
  @attr(#{
    kind: "single",
    from: "Protocols → SCIM → Clients, or by hand",
    families: #["scim-client"],
    what: "HOW MANY REQUESTS A SECOND the service provider is sent, at most: every delivery, lookup, discovery read and reconciliation page waits for its turn rather than failing. Empty or 0 (the default) is no limit. In a service deployed as cells each cell that pushes may send this divided by the number of such cells, rounded up."
  })
  scimClientMaxRequestsPerSecond?: string;
  @attr(#{
    kind: "multi",
    from: "SSF, the console, or by hand",
    identifier: true,
    identifierName: "receiver id",
    what: "WHAT A SHARED SIGNALS RECEIVER IS CALLED — whatever it authenticated as when it created a stream at /ssf/stream, which is also the `aud` of every Security Event Token that stream carries. Unlike the four declaration-only identifiers above it, this one IS written by the protocol: creating a stream records a sighting, because a receiver authenticating and being agreed a stream is exactly the kind of event this registry exists to hold. It still grants nothing — a stream is what decides what a receiver gets, and it carries its own audience."
  })
  ssfReceiverId?: string[];
  @attr(#{
    kind: "multi",
    from: "the console, or by hand",
    what: "WHERE THIS RECEIVER EXPECTS ITS EVENTS PUSHED — an RFC 8935 delivery endpoint. It is a DECLARATION and nothing reads it: a push goes to the endpoint on the STREAM, which the receiver named when it created one, and this service will not take a URL to dial from an application entry: a URL recorded here is a note about what a receiver is, and a URL on a stream is a URL this service opens a connection to. The two are deliberately not the same store."
  })
  ssfDeliveryEndpoint?: string[];
  // ---------------------------------------------------------------------
  // THE ONE ATTRIBUTE ON THIS ENTRY THAT LIMITS SHARED SIGNALS (2026-09-12).
  //
  // Every other SSF attribute here is a declaration nothing reads. This one
  // is READ, by `ssf/ssf_streams.ts`'s allowedEventsFor(), at two moments:
  // when a stream owned by this application is agreed (its `events_delivered`
  // is narrowed) and at every delivery (so tightening it takes effect on
  // streams that already exist). Empty means unrestricted, which is what
  // every entry was before it existed. Family-scoped like
  // `oauthTokenExchangeRefreshToken` and for the same reason: on an entry
  // nobody declared for Shared Signals it would read like a policy in force
  // over streams that cannot be its.
  @attr(#{
    kind: "multi",
    from: "the console, the management API, or by hand",
    families: #["ssf"],
    familyWhy: "It limits which Security Event Tokens a stream owned by this application is sent, so on an entry declared for no Shared Signals family it would sit there reading like a limit that was in force.",
    what: "WHICH SHARED SIGNALS EVENT TYPES A STREAM OWNED BY THIS APPLICATION MAY BE SENT. One value per line, each either a whole profile — `caep` (the eight session events) or `risc` (the fourteen account events) — or one event type URI, such as https://schemas.openid.net/secevent/caep/event-type/session-revoked. EMPTY MEANS UNRESTRICTED. SSF's own verification and stream-updated events are always allowed. It is ENFORCED twice: a stream this application creates or updates is agreed only the types allowed here (anything else it asked for is absent from `events_delivered`, and the stream's log says why), and every delivery checks it again, so removing a value stops existing streams receiving that type. The owner is whoever authenticated to /ssf/stream, matched against this entry's identifier or its ssfReceiverId values."
  })
  ssfAllowedEvents?: string[];
  // ---------------------------------------------------------------------
  // PER-RECEIVER SHARED SIGNALS SETTINGS (2026-10-01). Each overrides one
  // caep.*, risc.* or ssf.* setting for the streams this application owns,
  // read through ssfSettingFor(). They are the ones that stay inside SSF
  // 1.0, CAEP 1.0 and RISC 1.0 when two receivers differ: optional members
  // of a SET, transmitter-supplied stream members, and the transmitter's
  // own limits. Left service-wide on purpose: what the metadata document
  // publishes (default_subjects, the delivery methods), what describes the
  // SUBJECT rather than the delivery (a risk level, an assurance
  // namespace), what the stream's own `format` already chooses, and the
  // account holder's RISC opt-out. Empty means the setting decides, and
  // the console shows its value. `strictOverride` refuses a value that
  // does not parse at the write, where the older overrides warn on read.
  // ---------------------------------------------------------------------
  @attr(#{
    kind: "single",
    from: "the console, the management API, or by hand",
    overrides: "caep.includeReasons",
    families: #["ssf"],
    strictOverride: true,
    familyWhy: "It changes what this application's Shared Signals streams are sent, so on an entry declared for no Shared Signals family it would read like a setting in force.",
    what: "TRUE or FALSE: send reason_admin and reason_user on the CAEP events this receiver's streams carry. Both are OPTIONAL members (CAEP 1.0 section 2), so either answer conforms."
  })
  ssfCaepIncludeReasons?: string;
  @attr(#{
    kind: "single",
    from: "the console, the management API, or by hand",
    overrides: "caep.reasonLanguage",
    families: #["ssf"],
    strictOverride: true,
    familyWhy: "It changes what this application's Shared Signals streams are sent, so on an entry declared for no Shared Signals family it would read like a setting in force.",
    what: "The BCP 47 language tag the CAEP reason members are keyed under on this receiver's streams. They stay objects keyed by a tag either way."
  })
  ssfCaepReasonLanguage?: string;
  @attr(#{
    kind: "single",
    from: "the console, the management API, or by hand",
    overrides: "caep.omitEventTimestamp",
    families: #["ssf"],
    strictOverride: true,
    familyWhy: "It changes what this application's Shared Signals streams are sent, so on an entry declared for no Shared Signals family it would read like a setting in force.",
    what: "TRUE or FALSE: leave event_timestamp (OPTIONAL, CAEP 1.0 section 2) off the CAEP events this receiver's streams carry."
  })
  ssfCaepOmitEventTimestamp?: string;
  @attr(#{
    kind: "single",
    from: "the console, the management API, or by hand",
    overrides: "risc.includeReasons",
    families: #["ssf"],
    strictOverride: true,
    familyWhy: "It changes what this application's Shared Signals streams are sent, so on an entry declared for no Shared Signals family it would read like a setting in force.",
    what: "TRUE or FALSE: send reason_admin and reason_user on the RISC events that define them, on this receiver's streams."
  })
  ssfRiscIncludeReasons?: string;
  @attr(#{
    kind: "single",
    from: "the console, the management API, or by hand",
    overrides: "risc.reasonLanguage",
    families: #["ssf"],
    strictOverride: true,
    familyWhy: "It changes what this application's Shared Signals streams are sent, so on an entry declared for no Shared Signals family it would read like a setting in force.",
    what: "The BCP 47 language tag the RISC reason members are keyed under on this receiver's streams."
  })
  ssfRiscReasonLanguage?: string;
  @attr(#{
    kind: "single",
    from: "the console, the management API, or by hand",
    overrides: "risc.omitEventTimestamp",
    families: #["ssf"],
    strictOverride: true,
    familyWhy: "It changes what this application's Shared Signals streams are sent, so on an entry declared for no Shared Signals family it would read like a setting in force.",
    what: "TRUE or FALSE: leave event_timestamp off the RISC events that define it, on this receiver's streams."
  })
  ssfRiscOmitEventTimestamp?: string;
  @attr(#{
    kind: "single",
    from: "the console, the management API, or by hand",
    overrides: "ssf.signingAlgorithm",
    families: #["ssf"],
    strictOverride: true,
    familyWhy: "It changes what this application's Shared Signals streams are sent, so on an entry declared for no Shared Signals family it would read like a setting in force.",
    what: "The JWS algorithm this receiver's Security Event Tokens are signed with. Each is one this transmitter publishes a key for in its JWKS, so the receiver can always verify."
  })
  ssfSigningAlgorithm?: string;
  @attr(#{
    kind: "single",
    from: "the console, the management API, or by hand",
    overrides: "ssf.minVerificationInterval",
    families: #["ssf"],
    strictOverride: true,
    familyWhy: "It changes what this application's Shared Signals streams are sent, so on an entry declared for no Shared Signals family it would read like a setting in force.",
    what: "Seconds: min_verification_interval (SSF 1.0 section 8.1.1, transmitter-supplied) on this receiver's streams. A receiver asking for a shorter one is refused."
  })
  ssfMinVerificationInterval?: string;
  @attr(#{
    kind: "single",
    from: "the console, the management API, or by hand",
    overrides: "ssf.inactivityTimeoutS",
    families: #["ssf"],
    strictOverride: true,
    familyWhy: "It changes what this application's Shared Signals streams are sent, so on an entry declared for no Shared Signals family it would read like a setting in force.",
    what: "Seconds: inactivity_timeout (SSF 1.0 section 8.1.1, transmitter-supplied) on this receiver's streams; 0 means none."
  })
  ssfInactivityTimeoutS?: string;
  @attr(#{
    kind: "single",
    from: "the console, the management API, or by hand",
    overrides: "ssf.inactivityAction",
    families: #["ssf"],
    strictOverride: true,
    familyWhy: "It changes what this application's Shared Signals streams are sent, so on an entry declared for no Shared Signals family it would read like a setting in force.",
    what: "What happens to one of this receiver's streams when its inactivity timeout passes."
  })
  ssfInactivityAction?: string;
  @attr(#{
    kind: "single",
    from: "the console, the management API, or by hand",
    overrides: "ssf.verificationEveryS",
    families: #["ssf"],
    strictOverride: true,
    familyWhy: "It changes what this application's Shared Signals streams are sent, so on an entry declared for no Shared Signals family it would read like a setting in force.",
    what: "Seconds between the verification events this transmitter sends on this receiver's streams by itself; 0 means none."
  })
  ssfVerificationEveryS?: string;
  @attr(#{
    kind: "single",
    from: "the console, the management API, or by hand",
    overrides: "ssf.streamStatusOnCreate",
    families: #["ssf"],
    strictOverride: true,
    familyWhy: "It changes what this application's Shared Signals streams are sent, so on an entry declared for no Shared Signals family it would read like a setting in force.",
    what: "The status a stream this receiver creates starts in."
  })
  ssfStreamStatusOnCreate?: string;
  @attr(#{
    kind: "single",
    from: "the console, the management API, or by hand",
    overrides: "ssf.maxStreams",
    families: #["ssf"],
    strictOverride: true,
    familyWhy: "It changes what this application's Shared Signals streams are sent, so on an entry declared for no Shared Signals family it would read like a setting in force.",
    what: "How many streams this receiver may hold at once."
  })
  ssfMaxStreams?: string;
  @attr(#{
    kind: "single",
    from: "the console, the management API, or by hand",
    overrides: "ssf.maxSubjectsPerStream",
    families: #["ssf"],
    strictOverride: true,
    familyWhy: "It changes what this application's Shared Signals streams are sent, so on an entry declared for no Shared Signals family it would read like a setting in force.",
    what: "How many subjects one of this receiver's streams may name."
  })
  ssfMaxSubjectsPerStream?: string;
  @attr(#{
    kind: "single",
    from: "the console, the management API, or by hand",
    overrides: "ssf.maxQueuedEvents",
    families: #["ssf"],
    strictOverride: true,
    familyWhy: "It changes what this application's Shared Signals streams are sent, so on an entry declared for no Shared Signals family it would read like a setting in force.",
    what: "How many undelivered events one of this receiver's streams holds."
  })
  ssfMaxQueuedEvents?: string;
  @attr(#{
    kind: "single",
    from: "the console, the management API, or by hand",
    overrides: "ssf.pollMaxEvents",
    families: #["ssf"],
    strictOverride: true,
    familyWhy: "It changes what this application's Shared Signals streams are sent, so on an entry declared for no Shared Signals family it would read like a setting in force.",
    what: "The most events one poll of this receiver's stream returns (RFC 8936 lets a transmitter return fewer than maxEvents)."
  })
  ssfPollMaxEvents?: string;
  @attr(#{
    kind: "single",
    from: "the console, the management API, or by hand",
    overrides: "ssf.deadLetterMaxPerStream",
    families: #["ssf"],
    strictOverride: true,
    familyWhy: "It changes what this application's Shared Signals streams are sent, so on an entry declared for no Shared Signals family it would read like a setting in force.",
    what: "How many dead letters one of this receiver's streams keeps."
  })
  ssfDeadLetterMaxPerStream?: string;
  @attr(#{
    kind: "single",
    from: "the console, the management API, or by hand",
    overrides: "ssf.pushTimeoutMs",
    families: #["ssf"],
    strictOverride: true,
    familyWhy: "It changes what this application's Shared Signals streams are sent, so on an entry declared for no Shared Signals family it would read like a setting in force.",
    what: "Milliseconds to wait for this receiver's push endpoint to answer."
  })
  ssfPushTimeoutMs?: string;
  @attr(#{
    kind: "single",
    from: "the console, the management API, or by hand",
    overrides: "ssf.pushRetries",
    families: #["ssf"],
    strictOverride: true,
    familyWhy: "It changes what this application's Shared Signals streams are sent, so on an entry declared for no Shared Signals family it would read like a setting in force.",
    what: "How many times a failed push to this receiver is tried again before it becomes a dead letter."
  })
  ssfPushRetries?: string;
  @attr(#{
    kind: "single",
    from: "the console, the management API, or by hand",
    overrides: "ssf.pushRetryDelayMs",
    families: #["ssf"],
    strictOverride: true,
    familyWhy: "It changes what this application's Shared Signals streams are sent, so on an entry declared for no Shared Signals family it would read like a setting in force.",
    what: "Milliseconds between push attempts to this receiver."
  })
  ssfPushRetryDelayMs?: string;
  // ---------------------------------------------------------------------
  // GNAP (RFC 9635 + RFC 9767), 2026-09-12. See gnap/CLAUDE.md.
  // ---------------------------------------------------------------------
  @attr(#{
    kind: "single",
    from: "the console, or by hand",
    identifier: true,
    identifierName: "GNAP instance identifier",
    what: "A STATIC instance identifier (RFC 9635 section 2.3.1): the string a client sends as `client` in place of its key. The key it must then prove is gnapKey or gnapKeyReference on this entry. Dynamic identifiers the authorization server hands out (section 3.5) are not written here."
  })
  gnapInstanceId?: string;
  @attr(#{
    kind: "single",
    from: "GNAP (on first sight, development), the console, or by hand",
    what: "The client instance's or resource server's PUBLIC key, as the JSON key object of RFC 9635 section 7.1: a proof method and exactly one of jwk, cert or cert#S256. It is how a request by value is matched to this entry, by the key's thumbprint."
  })
  gnapKey?: string;
  @attr(#{
    kind: "single",
    from: "GNAP",
    what: "The thumbprint identity of gnapKey (jkt:... for a JWK, x5t:... for a certificate), written when GNAP creates the entry so the key can be found without re-reading it."
  })
  gnapKeyIdentity?: string;
  @attr(#{
    kind: "single",
    from: "the console, or by hand",
    what: "A KEY REFERENCE (RFC 9635 section 7.1.1): the opaque string a client sends as `key`. It resolves to gnapSymmetricKey when that is set, and to gnapKey otherwise."
  })
  gnapKeyReference?: string;
  @attr(#{
    kind: "single",
    from: "the console, or by hand",
    what: "The proofing method a key reference is bound to (section 7.1.1: \"MUST be bound to a single proofing mechanism\"): httpsig, jwsd or jws. Default httpsig."
  })
  gnapKeyProof?: string;
  @attr(#{
    kind: "single",
    from: "the console, or by hand",
    what: "How a key this client proves by mutual TLS is trusted, for this client alone (#107): `pki` or `pinned`, as the realm's gnap.mtlsTrust. It can only make the realm STRICTER — `pki` where the realm is pinned — and `pinned` is refused where the realm is pki (STS-REG-0196) and ignored if the realm is made pki afterwards. Empty follows the realm. Under pki the certificate must chain to the client truststore and be issued to this entry by this realm, or carry the one RFC 8705 subject parameter it registers (oauthTlsClientAuthSubjectDn or an oauthTlsClientAuthSan* attribute)."
  })
  gnapMtlsTrust?: string;
  @attr(#{
    kind: "single",
    from: "the console, or by hand",
    sensitive: true,
    what: "A SHARED SECRET for a key reference, base64url, at least 32 bytes — the one case GNAP allows a symmetric key, because it never crosses the wire (section 7.1.2). Sealed with the key-encryption key when keys persist, withheld from LDAP readers in product mode."
  })
  gnapSymmetricKey?: string;
  @attr(#{
    kind: "single",
    from: "the console, or by hand",
    what: "The algorithm a shared secret signs with: HS256 (default), HS384 or HS512 for jwsd and jws; hmac-sha256 for httpsig."
  })
  gnapSymmetricAlg?: string;
  @attr(#{
    kind: "single",
    from: "GNAP, the console, or by hand",
    what: "The client software's class_id (section 2.3). A registered value takes precedence over the one a request carries."
  })
  gnapClassId?: string;
  @attr(#{
    kind: "single",
    from: "GNAP, the console, or by hand",
    what: "The client's display.uri, shown on the approval page (section 2.3.2)."
  })
  gnapDisplayUri?: string;
  @attr(#{
    kind: "single",
    from: "GNAP, the console, or by hand",
    what: "The client's display.logo_uri. Only a data: image is drawn; any other URI is shown as a link (section 11.16)."
  })
  gnapLogoUri?: string;
  @attr(#{
    kind: "multi",
    from: "GNAP (observed, development), the console, or by hand",
    what: "An INTERACTION FINISH URI (section 2.5.2) this client may be sent back to or pushed to. A return address: in product mode a finish URI not listed here is refused."
  })
  gnapFinishUri?: string[];
  @attr(#{
    kind: "multi",
    from: "the console, or by hand",
    what: "The interaction start modes this client may use (redirect, app, user_code, user_code_uri). Empty means every mode the authorization server offers."
  })
  gnapInteractionStartModes?: string[];
  @attr(#{
    kind: "multi",
    from: "the console, or by hand",
    what: "The access types and reference strings this client may request, or this resource server may register. Empty means any."
  })
  gnapAllowedAccess?: string[];
  @attr(#{
    kind: "single",
    from: "the console, or by hand",
    what: "FALSE refuses the bearer flag for this client with invalid_flag."
  })
  gnapBearerTokens?: string;
  @attr(#{
    kind: "single",
    from: "the console, or by hand",
    what: "TRUE makes this a TRUSTED client instance (section 2.3.3): a grant that asks for no subject information is approved with no resource owner and no interaction, and one carrying a verified user assertion is approved for that person. Honoured only for a registered entry, never one GNAP created on sight."
  })
  gnapSkipInteraction?: string;
  @attr(#{
    kind: "single",
    from: "the console, or by hand",
    what: "The RFC 9767 token format for tokens issued to this client, or for this resource server: jwt-signed, jwt-encrypted, macaroon, biscuit or zcap."
  })
  gnapAccessTokenFormat?: string;
  @attr(#{
    kind: "single",
    from: "the console, or by hand",
    overrides: "gnap.accessTokenLifetimeS",
    what: "The lifetime in seconds of access tokens issued to this client."
  })
  gnapAccessTokenLifetimeS?: string;
  @attr(#{
    kind: "multi",
    from: "the console, or by hand",
    what: "The locations this resource server answers for. An access right whose locations start with one of these is audienced to this entry, and a token for it is minted with this resource server's format, JWE key and macaroon key."
  })
  gnapResourceServerUri?: string[];
  @attr(#{
    kind: "single",
    from: "the console, or by hand",
    what: "Where this resource server answers who owns a resource (#432 phase 5): an https URL template holding {identifier} once, in its path, e.g. https://rs.example.com/owners/{identifier}. The authorization server fetches it with the identifier percent-encoded into that segment and reads {\"owner\": \"<DN>\"} (404: nobody owns it); the person approving a right naming the identifier must be that person or a member of that group."
  })
  gnapOwnerLookupUri?: string;
  @attr(#{
    kind: "single",
    from: "the console, or by hand",
    what: "This resource server's PUBLIC encryption key (a JWK) for jwt-encrypted tokens, so only this resource server can read them."
  })
  gnapJweKey?: string;
  @attr(#{
    kind: "single",
    from: "GNAP",
    sensitive: true,
    what: "The macaroon ROOT KEY this resource server verifies its macaroon tokens with, base64url. Written by the authorization server when the resource server first registers a resource set; sealed with the key-encryption key when keys persist."
  })
  gnapMacaroonKey?: string;
  @attr(#{
    kind: "single",
    from: "the console, or by hand",
    what: "FALSE opts this web application out of Shared Signals scoping: a stream it owns then carries events about everybody, like any other receiver's."
  })
  gnapScopedSignals?: string;
  @attr(#{
    kind: "multi",
    from: "the console, or by hand",
    identifier: true,
    identifierName: "SPIFFE ID",
    what: "A SPIFFE ID this application is expected to hold — spiffe://<trust domain>/<path>. A SPIFFE identity gets an entry of its OWN under ou=spiffe (see spiffe/CLAUDE.md) and the registry there is what an SVID is actually issued against, so this writes nothing and reads nothing: it is the link between an application in this registry and an identity in that one, said by hand because no protocol says it."
  })
  spiffeWorkloadId?: string[];
  // --- AND THE ONE PAIR HERE THAT DOES DECIDE SOMETHING ----------------
  //
  // When this block was written, every attribute above this line either
  // recorded what happened or declared something nothing reads —
  // `appAllowedProtocol` says so in capitals, and the four declaration-only
  // identifiers above are still that. (Several rows above are READ by now:
  // the setting overrides, `ssfAllowedEvents`, and the RFC 9701, 9101, 9126,
  // 9396 and 9470 attributes — each says so on its own row.) These two are
  // read, by `authn.js`, on the way to the sign-in screen.
  //
  // WHAT THEY ANSWER is a question this registry could not answer before:
  // WHERE ARE THIS APPLICATION'S USERS AUTHENTICATED? A relationship under
  // `ou=federations` says how to talk to a foreign identity provider and says
  // nothing about who should be sent there, and an application entry said
  // what the application is and nothing about how its people sign in. So a
  // federated sign-in was something a PERSON chose, on a button at the foot
  // of the sign-in screen, once per sign-in — which is the discovery step a
  // real deployment does not make its users perform.
  //
  // THEY ARE NOT A PERMISSION, and that is the same posture the rest of this
  // registry takes: nothing here refuses a local sign-in for an application
  // that names a relationship, nothing refuses a person who reaches the
  // screen by another route, and clearing them takes the shortcut away
  // rather than locking anybody out. What they change is the DEFAULT ROUTE
  // to the screen — see authn.js's federationFor().
  //
  // AND THE FIRST OF THEM HOLDS A LIST, since 2026-08-26. The discovery step
  // this pair removed was a person choosing from EVERY relationship this
  // service has; naming several here narrows that list to this
  // application's own partners without pretending the choice does not
  // exist. A deployment with one federated identity provider still gets the
  // redirect it always got — the list is one value long — and one with two
  // gets a page listing exactly two. See authn.js's federationFor(), which
  // resolves every value and reports the ones that would not work.
  @attr(#{
    kind: "multi",
    from: "the console, the management API, or by hand",
    what: "THE FEDERATION RELATIONSHIPS THIS APPLICATION'S USERS ARE AUTHENTICATED THROUGH — each value the `fedId` of an entry under ou=federations, in THIS trust realm, whose `fedRole` is service-provider. Both halves of that are checked when it is read rather than when it is written: an identity-provider-side relationship goes the other way (this service asserts to that partner, so there is nothing to sign in to), and the register is per realm, so an id that names a relationship in another realm names nothing here.\n\nIT HOLDS A LIST, and that is what makes an application able to offer more than one identity provider. ONE usable value with the auto-redirect on is the case this attribute was added for and it is unchanged: the browser goes straight to that partner. SEVERAL usable values draw /authn/select-idp, where the person chooses which one — home realm discovery narrowed to this application's partners rather than performed against every relationship this service has. They need not share a protocol: a SAML 2.0 partner and an OpenID Connect one are two values here and two buttons there, because what the list names is where a person can be authenticated and not how.\n\nA value that names a relationship this service cannot use is REPORTED on the screen rather than dropped, one line per value: a list of three whose middle entry is disabled must not look like a list of two.\n\nIt is WRITTEN BY NOBODY. No protocol presents it and no sighting derives it — an application's home identity provider is an arrangement somebody made, not something this service can observe — so it is editable and it starts empty."
  })
  @link(#{to: "federationRelationship", cardinality: "multi", owns: false, what: "Federation relationships this application is tied to."})
  appFederationRelationship?: string[];
  @attr(#{
    kind: "single",
    from: "the console, the management API, or by hand",
    what: "TRUE if a person signing in to this application should be sent STRAIGHT to the partner named above, without the sign-in screen in between. This is home realm discovery done by configuration instead of by asking, which is what a deployment with one federated identity provider actually does.\n\nIt is TRUE BY DEFAULT once a relationship is named, because naming one and then having to click a button is the state nobody wants; set it FALSE to keep the screen, where the partners are then the only buttons offered. An absent value therefore means \"yes\" here and not \"unknown\", which is the opposite of what RFC 7591 section 2 makes an omitted boolean mean — said out loud because the two rules meet on one entry.\n\nWITH SEVERAL RELATIONSHIPS NAMED IT MEANS EXACTLY WHAT IT ALWAYS MEANT — \"without the sign-in screen\" — and what changes is what that leaves. With one it is a redirect straight to the partner. With several it is the chooser at /authn/select-idp: one button per partner and no password field, which is the sign-in screen's job done without the sign-in screen. What it never means is \"pick one for them\"; there is no value of a boolean that can say which identity provider somebody's employer is.\n\nFALSE with several named is therefore the SCREEN, with one button per partner under the password box — the same thing FALSE has always done, with the partners plural.\n\nWith no relationship named it does nothing at all, rather than being an error: the two are edited separately and a value left behind by a relationship that was cleared should not refuse the next write."
  })
  appFederationAutoRedirect?: string;
  // ---------------------------------------------------------------------
  // AND THE THIRD, WHICH GENERALISES THE PAIR ABOVE IT — AND SINCE #1148
  // NAMES A POLICY RATHER THAN HOLDING THE LISTS.
  //
  // `appAuthnMechanism` (#457, 2026-08-26) was the list of the mechanisms an
  // application's people may sign in with, in `federation.MECHANISM_IDS`'s
  // vocabulary (`password`, `password-mfa`, `webauthn`, `spnego`, `wallet`,
  // `federation`), and `appMfaMechanism` (#475) its second factors'
  // companion. rcbj, 2026-10-29: "replace the appAuthnMechanism and
  // appMfaMechanism fields with scoped authentication policy reference ...
  // one field that points at a named, scoped authentication policy." Both
  // are GONE (no migration is owed); `appAuthnPolicy` names a NAMED
  // AUTHENTICATION POLICY (`common/authn_policy.ts`, Directory > Policies),
  // which holds the two lists. Everything the two attributes did, the
  // policy's lists do, read through `authn_mechanisms.ts`'s and
  // `mfa_mechanisms.ts`'s `allowedOf()`:
  //
  //   * **None listed allows every mechanism** (and leaves the realm's
  //     second factors as they are); one listed routes the sign-in
  //     (/authn/spnego, /authn/wallet, the partner, or the screen in the
  //     shape named); several draw the screen with only those on it.
  //   * **Every BROWSER issuance is put to the issuance policy** — its
  //     `authn-mechanism` and `mfa-mechanism` rules re-prompt a session
  //     standing on a mechanism the policy does not allow — in both modes.
  //     Non-browser doors (the password grant, WS-Trust, an LDAP bind) are
  //     not covered.
  //
  // CHECKED AT THE WRITE (CHOICES_CHECKED_HERE): the value must be
  // `default` or a named policy this realm holds (ATTRIBUTE_CHOICES reads
  // them lazily). A name an `ldapmodify` wrote that no policy holds allows
  // NOTHING (`authn_policy.ts`'s `mechanismsFor()`, STS-AUTHN-0536): a
  // reference fails closed, as a misspelt list did.
  // ---------------------------------------------------------------------
  @attr(#{
    kind: "single",
    from: "the console, the management API, or by hand",
    what: "THE AUTHENTICATION POLICY THIS APPLICATION'S PEOPLE SIGN IN UNDER: `default` (or empty), or the name of a named authentication policy of this realm (Directory > Policies). A named policy holds the first-factor mechanisms allowed (password, password-mfa, webauthn, spnego, wallet, federation; none allows every one) and the second factors allowed (password, securityKey, totp, recoveryCode, emailCode, emailLink, wallet; none leaves the realm's as it is). `default` allows every mechanism the realm's authentication policy allows.\n\nENFORCED at every browser sign-in to the application, in both modes: a person whose session stands on a mechanism the policy does not allow is sent to sign in again with one it does. One first-factor mechanism listed is also where the sign-in goes (`spnego` to /authn/spnego, `wallet` to /authn/wallet, `federation` to appFederationRelationship). The second factors only NARROW the realm's policy: one it has switched off stays off here.\n\nA name no policy of this realm holds — written past the console — allows NO mechanism until the policy exists (STS-AUTHN-0536).\n\nIt is WRITTEN BY NOBODY: no protocol presents it, so it is editable and starts empty."
  })
  @link(#{to: "policy.authn", cardinality: "single", owns: false, what: "The named authentication policy it signs in under."})
  appAuthnPolicy?: string;
  // ---------------------------------------------------------------------
  // THE PASSKEY POLICY THIS APPLICATION NAMES (#1235, rcbj on #1234,
  // 2026-10-30: "a unique application or user attribute ... that points at
  // each type of named policy"). It replaced the named passkey policy's
  // own list of applications (`stsPasskeySelectApplication`, #535, #609),
  // and no migration is owed; a group names one in `stsPasskeyPolicy`. `appAuthnPolicy`'s arrangement: one value,
  // CHECKED AT THE WRITE (CHOICES_CHECKED_HERE) against `default` and this
  // realm's named passkey policies, and listed in POLICY_REFERENCES so the
  // policy can ask which applications name it.
  // ---------------------------------------------------------------------
  @attr(#{
    kind: "single",
    from: "the console, the management API, or by hand",
    what: "THE PASSKEY POLICY A SIGN-IN TO THIS APPLICATION IS HELD TO: `default` (or empty), or the name of a named passkey policy of this realm (Directory > Policies). It competes on precedence with the passkey policy each of the person's groups names (stsPasskeyPolicy): the lowest precedence applies, ties by name, and `default` where nothing names one.\n\nA name no policy of this realm holds — written past the console — names nothing and is logged (STS-AUTHN-0537). A named passkey policy this attribute names cannot be deleted (STS-AUTHN-0538).\n\nIt is WRITTEN BY NOBODY: no protocol presents it, so it is editable and starts empty."
  })
  @link(#{to: "policy.passkey", cardinality: "single", owns: false, what: "The named passkey policy a sign-in is held to."})
  appPasskeyPolicy?: string;
  // ---------------------------------------------------------------------
  // THE LOCALE POLICY THIS APPLICATION NAMES (#1238, rcbj on #1234). It
  // replaced the named locale policy's own list of applications
  // (`stsLocaleSelectApplication`, #539) and its one-profile-per-
  // application refusal (STS-I18N-0007, retired); no migration is owed. A
  // group names one in `stsLocalePolicy`. `appPasskeyPolicy`'s
  // arrangement: one value, CHECKED AT THE WRITE, in POLICY_REFERENCES.
  // ---------------------------------------------------------------------
  @attr(#{
    kind: "single",
    from: "the console, the management API, or by hand",
    what: "THE LOCALE POLICY A PAGE OR A MAIL FOR THIS APPLICATION FALLS BACK TO: `default` (or empty), or the name of a named locale policy of this realm (Directory > Policies). It decides the language a page is drawn in when the request, the person and the browser name none a catalog answers, and the preferredLanguage a person this application causes to be created is given. Where the person is known it competes on precedence with the locale policy each of the person's groups names (stsLocalePolicy): the lowest precedence applies, ties by name, and `default` where nothing names one.\n\nA name no policy of this realm holds — written past the console — names nothing and is logged (STS-I18N-0013): `default` applies, as a language is all it decides. A named locale policy this attribute names cannot be deleted (STS-I18N-0014).\n\nIt is WRITTEN BY NOBODY: no protocol presents it, so it is editable and starts empty."
  })
  @link(#{to: "policy.locale", cardinality: "single", owns: false, what: "The named locale policy it falls back to."})
  appLocalePolicy?: string;
  // THE PASSWORD POLICY THIS APPLICATION NAMES (#1236), `appPasskeyPolicy`'s
  // arrangement: one value, checked at the write against `default` and
  // this realm's named password policies. Read where a password is set
  // with the application in hand — the sign-in's forced password change.
  @attr(#{
    kind: "single",
    from: "the console, the management API, or by hand",
    what: "THE PASSWORD POLICY A PASSWORD SET WHILE SIGNING IN TO THIS APPLICATION IS HELD TO: `default` (or empty), or the name of a named password policy of this realm (Directory > Policies). It competes on precedence with the password policy each of the person's groups names (stsPasswordPolicy): the lowest precedence applies, ties by name, and `default` where nothing names one. A door with no application in hand (the portal, the console, LDAP) ranks the groups' alone.\n\nA name no policy of this realm holds — written past the console — names nothing, the group references still rank, and it is logged (STS-AUTHN-0539). A named password policy this attribute names cannot be deleted (STS-AUTHN-0540).\n\nIt is WRITTEN BY NOBODY: no protocol presents it, so it is editable and starts empty."
  })
  @link(#{to: "policy.password", cardinality: "single", owns: false, what: "The named password policy a password set here uses."})
  appPasswordPolicy?: string;
  // ---------------------------------------------------------------------
  // THE POST-LOGIN ACTIVITY POLICY THIS APPLICATION NAMES (#1239, rcbj on
  // #1234): `appPasskeyPolicy`'s arrangement. A sign-in to the application
  // ranks it with the profiles the person's groups name; a question asked
  // of a person outside a sign-in (a started activity's mail, the
  // progress report) has no application and does not read it.
  // ---------------------------------------------------------------------
  @attr(#{
    kind: "single",
    from: "the console, the management API, or by hand",
    what: "THE POST-LOGIN ACTIVITY POLICY A SIGN-IN TO THIS APPLICATION FOLLOWS: `default` (or empty), or the name of a named post-login policy of this realm (Directory > Policies). It competes on precedence with the post-login policy each of the person's groups names (stsPostLoginPolicy): the lowest precedence applies, ties by name, and `default` where nothing names one. A named policy with its activity off EXCLUDES a sign-in to this application where it wins.\n\nIt is read at the sign-in only: a started activity's reminder mail and the progress report know no application, and select by the person's groups alone.\n\nA name no policy of this realm holds — written past the console — names nothing and is logged (STS-AUTHN-0542). A named post-login policy this attribute names cannot be deleted (STS-AUTHN-0543).\n\nIt is WRITTEN BY NOBODY: no protocol presents it, so it is editable and starts empty."
  })
  @link(#{to: "policy.postLogin", cardinality: "single", owns: false, what: "The named post-login profile a sign-in follows."})
  appPostLoginPolicy?: string;
  // -------------------------------------------------------------------
  // APPLICATION-SCOPED FINE-GRAINED AUTHORIZATION (#564). The RESOURCE
  // application that declares an authorization_details type owns the
  // policy that decides details of that type (rcbj's decision 1). The
  // policy is an entry in ou=policies carrying xacmlApplication; these
  // are the application's half. BOTH ARE DERIVED in this registry's
  // sense and in no EDITABLE row: `xacml/fga_policies.ts` writes them,
  // through `setFgaState()` below, because switching enforcement on
  // creates the policy first and an ordinary field write would skip
  // that. An LDIF export leaves them out and an import refuses them, so
  // an imported application gets a policy of its own.
  @attr(#{
    kind: "single",
    from: "this registry, when the application is created",
    what: "The entry name in ou=policies of the fine-grained authorization policy this application owns, which decides each authorization detail of the types it declares once appFgaEnforced is TRUE."
  })
  @link(#{to: "xacmlPolicy", cardinality: "single", owns: true, what: "The fine-grained policy entry in ou=policies that it owns."})
  appFgaPolicy?: string;
  @attr(#{
    kind: "single",
    from: "this registry, when fine-grained authorization is switched",
    what: "TRUE when this application's fine-grained policy is enforced. Absent or FALSE means it is not, which is the default."
  })
  appFgaEnforced?: string;
  // -------------------------------------------------------------------
  // USER-MANAGED ACCESS 2.0 (#1168). A resource server's one attribute:
  // whether the APPLICATION may be a resource owner itself, through a
  // client_credentials protection API token (rcbj's decision 5). Off, a
  // PAT issued to the client as itself is refused at /uma, and every
  // resource it registers belongs to the person whose code-flow PAT it
  // presents. DECLARED, so editable, and family-scoped by its prefix.
  // -------------------------------------------------------------------
  @attr(#{
    kind: "single",
    from: "the console, the management API, or by hand",
    what: "TRUE when this UMA 2.0 resource server may register resources it OWNS ITSELF, through a protection API token obtained with client_credentials. Absent or FALSE, the default, means a PAT must be a person's (the code flow) and that person owns what it registers."
  })
  umaOwnsResources?: string;
}
